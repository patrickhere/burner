//! which route the mac would send a connection out on, asked from the routing
//! socket (RTM_GET, what route get does, no root needed). on linux VM traffic
//! has a routing table of its own holding only the default route; macnet can't
//! have that, so it refuses whatever the mac would route any other way: a vpn,
//! a tailnet, a lan on public addresses. anything it can't read is refused too

use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Gateway {
    Inet(Ipv4Addr),
    /// on-link: a link-layer address or none
    Link,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Route {
    pub dst: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Gateway,
    pub index: u16,
}

impl Route {
    fn is_default(&self) -> bool {
        self.dst == Ipv4Addr::UNSPECIFIED && self.prefix == 0
    }
}

/// the interface dst goes out on, when that's the way the default route goes.
/// the connection is then bound to it, so a route that shows up after this
/// check (a vpn coming up) can't carry it
pub fn check(dst: Ipv4Addr) -> Result<u16, &'static str> {
    let unreadable = "can't read the route to it";
    let r = lookup(dst, false).map_err(|_| unreadable)?;
    if r.is_default() {
        return Ok(r.index);
    }
    let d = lookup(Ipv4Addr::UNSPECIFIED, true).map_err(|_| "no default route")?;
    if allowed(&r, &d) {
        Ok(d.index)
    } else {
        Err("not routed through the default route")
    }
}

/// the default route itself, or one through the same gateway on the same
/// interface: host routes the mac clones off the default for every
/// destination it talks to, and the routes dhcp adds for its dns servers.
/// the same exception linux makes
pub fn allowed(r: &Route, default: &Route) -> bool {
    if !default.is_default() {
        return false;
    }
    if r.is_default() {
        return r == default;
    }
    matches!(default.gateway, Gateway::Inet(_))
        && r.gateway == default.gateway
        && r.index == default.index
}

const HDR: usize = size_of::<libc::rt_msghdr>();
const SIN: usize = size_of::<libc::sockaddr_in>();

fn sin(ip: Ipv4Addr) -> [u8; SIN] {
    let mut b = [0u8; SIN];
    b[0] = SIN as u8;
    b[1] = libc::AF_INET as u8;
    b[4..8].copy_from_slice(&ip.octets());
    b
}

/// the kernel's route for dst: the best match, or with exact the route for
/// exactly dst/0, which is how the default route is asked for
pub fn lookup(dst: Ipv4Addr, exact: bool) -> io::Result<Route> {
    static SEQ: AtomicI32 = AtomicI32::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    // SAFETY: a fresh socket, owned right away
    let fd = unsafe {
        let fd = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: setsockopt reads a timeval from a live local
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut msg = vec![0u8; HDR];
    msg.extend_from_slice(&sin(dst));
    let mut addrs = libc::RTA_DST;
    if exact {
        // a netmask of /0: sa_len 0 is how route(8) sends it too
        msg.extend_from_slice(&[0u8; 4]);
        addrs |= libc::RTA_NETMASK;
    }
    // SAFETY: zeroed is a valid rt_msghdr, written over the start of msg
    let mut h: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    h.rtm_msglen = msg.len() as u16;
    h.rtm_version = libc::RTM_VERSION as u8;
    h.rtm_type = libc::RTM_GET as u8;
    h.rtm_addrs = addrs;
    h.rtm_seq = seq;
    // SAFETY: msg is at least HDR bytes; unaligned write of a plain struct
    unsafe { std::ptr::write_unaligned(msg.as_mut_ptr().cast(), h) };
    // SAFETY: write from and read into buffers we own
    let n = unsafe { libc::write(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getpid can't fail
    let me = unsafe { libc::getpid() };
    let mut buf = vec![0u8; 2048];
    // the socket sees every routing message on the system: wait for our answer
    for _ in 0..64 {
        // SAFETY: read into a buffer we own
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < HDR {
            continue;
        }
        // SAFETY: n >= HDR bytes were read into buf
        let r: libc::rt_msghdr = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        if r.rtm_pid != me || r.rtm_seq != seq || r.rtm_type != libc::RTM_GET as u8 {
            continue;
        }
        if r.rtm_errno != 0 {
            return Err(io::Error::from_raw_os_error(r.rtm_errno));
        }
        let end = (r.rtm_msglen as usize).min(n);
        return parse(&r, &buf[HDR..end]).ok_or_else(|| io::Error::other("odd route reply"));
    }
    Err(io::Error::other("no route reply"))
}

/// the sockaddrs after the header: one per bit of rtm_addrs, each padded to 4 bytes
fn parse(h: &libc::rt_msghdr, mut b: &[u8]) -> Option<Route> {
    let mut dst = None;
    let mut gateway = Gateway::Link;
    let mut prefix = 32;
    for bit in 0..libc::RTAX_MAX {
        if h.rtm_addrs & (1 << bit) == 0 {
            continue;
        }
        let len = *b.first()? as usize;
        let sa = b.get(..len.max(1))?;
        match 1 << bit {
            libc::RTA_DST => dst = Some(inet(sa)?),
            libc::RTA_GATEWAY => {
                if sa.get(1) == Some(&(libc::AF_INET as u8)) {
                    gateway = Gateway::Inet(inet(sa)?);
                }
            }
            // netmasks come cut short after their last nonzero byte
            libc::RTA_NETMASK => {
                let mut m = [0u8; 4];
                for (i, x) in sa.iter().skip(4).take(4).enumerate() {
                    m[i] = *x;
                }
                prefix = u32::from_be_bytes(m).leading_ones() as u8;
            }
            _ => {}
        }
        let step = if len == 0 { 4 } else { (len + 3) & !3 };
        b = b.get(step.min(b.len())..)?;
    }
    if h.rtm_flags & libc::RTF_HOST != 0 {
        prefix = 32;
    }
    Some(Route {
        dst: dst?,
        prefix,
        gateway,
        index: h.rtm_index,
    })
}

fn inet(sa: &[u8]) -> Option<Ipv4Addr> {
    if sa.len() < 8 || sa[1] != libc::AF_INET as u8 {
        return None;
    }
    Some(Ipv4Addr::new(sa[4], sa[5], sa[6], sa[7]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(dst: &str, prefix: u8, gw: Option<&str>, index: u16) -> Route {
        Route {
            dst: dst.parse().unwrap(),
            prefix,
            gateway: gw.map_or(Gateway::Link, |g| Gateway::Inet(g.parse().unwrap())),
            index,
        }
    }

    #[test]
    fn only_the_default_way_out() {
        let d = r("0.0.0.0", 0, Some("192.168.1.1"), 11);
        assert!(allowed(&d, &d));
        // cloned off the default, or dhcp's route to its dns server
        assert!(allowed(&r("1.1.1.1", 32, Some("192.168.1.1"), 11), &d));
        // a vpn or tailnet route
        assert!(!allowed(&r("100.64.0.0", 10, Some("100.100.1.1"), 23), &d));
        assert!(!allowed(&r("44.0.0.0", 8, None, 23), &d));
        // a lan on public addresses, on-link
        assert!(!allowed(&r("203.0.113.7", 32, None, 11), &d));
        assert!(!allowed(&r("198.51.100.0", 24, None, 11), &d));
        // same gateway, other interface
        assert!(!allowed(&r("8.8.8.0", 24, Some("192.168.1.1"), 12), &d));
        // a full tunnel vpn's halves
        assert!(!allowed(&r("0.0.0.0", 1, Some("10.8.0.1"), 23), &d));
        assert!(!allowed(&r("128.0.0.0", 1, Some("10.8.0.1"), 23), &d));
    }

    #[test]
    fn a_default_route_with_no_gateway_lets_only_itself_through() {
        let d = r("0.0.0.0", 0, None, 23);
        assert!(allowed(&d, &d));
        assert!(!allowed(&r("1.1.1.1", 32, None, 23), &d));
        assert!(!allowed(
            &r("1.1.1.1", 32, None, 11),
            &r("1.0.0.0", 8, None, 11)
        ));
    }

    #[test]
    fn live_table() {
        let Ok(d) = lookup(Ipv4Addr::UNSPECIFIED, true) else {
            return;
        };
        assert!(d.is_default(), "{d:?}");
        // the mac's own lan is on-link, never the default route
        for (ip, p) in super::super::policy::host_nets().unwrap() {
            if p < 32 && !ip.is_loopback() && !ip.is_link_local() {
                assert!(check(ip).is_err(), "{ip}");
                let next = Ipv4Addr::from(u32::from(ip) ^ 1);
                assert!(check(next).is_err(), "{next}");
            }
        }
        assert!(check(Ipv4Addr::new(127, 0, 0, 1)).is_err());
    }
}
