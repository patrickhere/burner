//! what a guest may reach. the same policy as the linux nft table in
//! burner/src/net.rs: the special ranges and everything on the host are never
//! reachable, dns only goes to the configured resolvers, and the mode decides
//! which other ports are open

use std::net::Ipv4Addr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Web,
    Open,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "web" => Some(Mode::Web),
            "open" => Some(Mode::Open),
            _ => None,
        }
    }
}

/// smtp, smtps and submission stay shut in open mode, as on linux
const MAIL: [u16; 3] = [25, 465, 587];

/// always blocked, kept in step with SPECIAL in burner/src/net.rs
const SPECIAL: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

pub fn inside(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    u32::from(ip) & mask(prefix) == u32::from(net) & mask(prefix)
}

pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, p) = match s.split_once('/') {
        Some((ip, p)) => (ip, p.parse().ok()?),
        None => (s, 32),
    };
    let ip: Ipv4Addr = ip.parse().ok()?;
    (p <= 32).then_some((ip, p))
}

pub struct Policy {
    pub mode: Mode,
    pub resolvers: Vec<Ipv4Addr>,
    blocked: Vec<(Ipv4Addr, u8)>,
    route: fn(Ipv4Addr) -> Result<(), &'static str>,
}

impl Policy {
    /// extra: --block entries. guest_net: the guest's own network, never a destination
    pub fn new(
        mode: Mode,
        resolvers: Vec<Ipv4Addr>,
        extra: &[(Ipv4Addr, u8)],
        guest_net: (Ipv4Addr, u8),
    ) -> Policy {
        let mut blocked: Vec<_> = SPECIAL.to_vec();
        blocked.extend_from_slice(extra);
        blocked.push(guest_net);
        Policy {
            mode,
            resolvers,
            blocked,
            route: super::route::check,
        }
    }

    /// Ok when a guest tcp connection to dst:port may go out, else why not
    pub fn tcp(&self, dst: Ipv4Addr, port: u16) -> Result<(), &'static str> {
        self.reachable(dst)?;
        if port == 53 {
            return self.resolver(dst);
        }
        match self.mode {
            Mode::Web if port == 80 || port == 443 => Ok(()),
            Mode::Web => Err("port closed in web mode"),
            Mode::Open if MAIL.contains(&port) => Err("mail port closed in open mode"),
            Mode::Open => Ok(()),
        }
    }

    /// Ok when a guest udp datagram to dst:53 may go out
    pub fn dns(&self, dst: Ipv4Addr) -> Result<(), &'static str> {
        self.reachable(dst)?;
        self.resolver(dst)
    }

    fn resolver(&self, dst: Ipv4Addr) -> Result<(), &'static str> {
        if self.resolvers.contains(&dst) {
            Ok(())
        } else {
            Err("not a configured resolver")
        }
    }

    fn reachable(&self, dst: Ipv4Addr) -> Result<(), &'static str> {
        // read fresh every time: interfaces come and go (wifi, vpn, docker)
        let host = host_nets().ok_or("can't read the host's addresses")?;
        if host.iter().any(|&(n, p)| inside(dst, n, p)) {
            return Err("the host's own address or network");
        }
        if self.blocked.iter().any(|&(n, p)| inside(dst, n, p)) {
            return Err("blocked range");
        }
        (self.route)(dst)
    }
}

/// every ipv4 address on the host as a /32, the network it sits on, and the far
/// end of point to point links (vpns). None if the list can't be read, which
/// the caller treats as blocked
pub fn host_nets() -> Option<Vec<(Ipv4Addr, u8)>> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        let Some(ip) = sockaddr_v4(ifa.ifa_addr) else {
            continue;
        };
        out.push((ip, 32));
        if let Some(m) = sockaddr_v4(ifa.ifa_netmask) {
            out.push((ip, u32::from(m).leading_ones() as u8));
        }
        if ifa.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0
            && let Some(d) = sockaddr_v4(ifa.ifa_dstaddr)
        {
            out.push((d, 32));
        }
    }
    unsafe { libc::freeifaddrs(head) };
    Some(out)
}

fn sockaddr_v4(sa: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if sa.is_null() || unsafe { (*sa).sa_family } as i32 != libc::AF_INET {
        return None;
    }
    let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// the ranges alone, whatever the routes of the machine running the tests
    fn any_route(mut p: Policy) -> Policy {
        p.route = |_| Ok(());
        p
    }

    fn web() -> Policy {
        any_route(Policy::new(
            Mode::Web,
            vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)],
            &[(Ipv4Addr::new(140, 82, 121, 0), 24)],
            (Ipv4Addr::new(172, 29, 217, 0), 30),
        ))
    }

    #[test]
    fn web_ports() {
        let p = web();
        let gh = Ipv4Addr::new(140, 82, 112, 3);
        assert!(p.tcp(gh, 443).is_ok());
        assert!(p.tcp(gh, 80).is_ok());
        for port in [22, 25, 53, 8080, 0] {
            assert!(p.tcp(gh, port).is_err(), "{port}");
        }
    }

    #[test]
    fn open_ports() {
        let p = any_route(Policy::new(
            Mode::Open,
            vec![Ipv4Addr::new(9, 9, 9, 9)],
            &[],
            (Ipv4Addr::new(172, 29, 217, 0), 30),
        ));
        let gh = Ipv4Addr::new(140, 82, 112, 3);
        for port in [22, 80, 443, 8080, 1] {
            assert!(p.tcp(gh, port).is_ok(), "{port}");
        }
        for port in [25, 465, 587, 53] {
            assert!(p.tcp(gh, port).is_err(), "{port}");
        }
        assert!(p.tcp(Ipv4Addr::new(9, 9, 9, 9), 53).is_ok());
        assert!(p.tcp(Ipv4Addr::new(10, 1, 0, 63), 22).is_err());
    }

    #[test]
    fn dns_only_to_resolvers() {
        let p = web();
        assert!(p.dns(Ipv4Addr::new(9, 9, 9, 9)).is_ok());
        assert!(p.tcp(Ipv4Addr::new(1, 1, 1, 1), 53).is_ok());
        assert!(p.dns(Ipv4Addr::new(8, 8, 8, 8)).is_err());
        assert!(p.tcp(Ipv4Addr::new(8, 8, 8, 8), 53).is_err());
    }

    #[test]
    fn special_and_extra_ranges() {
        let p = web();
        for ip in [
            "10.1.0.63",
            "10.1.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "172.29.217.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "140.82.121.4",
        ] {
            assert!(p.tcp(ip.parse().unwrap(), 443).is_err(), "{ip}");
        }
    }

    #[test]
    fn a_blocked_resolver_stays_blocked() {
        let p = Policy::new(
            Mode::Web,
            vec![Ipv4Addr::new(192, 168, 1, 1)],
            &[],
            (Ipv4Addr::new(172, 29, 217, 0), 30),
        );
        assert!(p.dns(Ipv4Addr::new(192, 168, 1, 1)).is_err());
    }

    #[test]
    fn host_addresses_blocked() {
        let p = web();
        for (ip, _) in host_nets().unwrap() {
            assert!(p.tcp(ip, 443).is_err(), "{ip}");
        }
    }

    #[test]
    fn a_route_that_isnt_the_default_is_refused() {
        let mut p = web();
        p.route = |_| Err("not routed through the default route");
        assert!(p.tcp(Ipv4Addr::new(140, 82, 112, 3), 443).is_err());
        assert!(p.dns(Ipv4Addr::new(9, 9, 9, 9)).is_err());
    }

    #[test]
    fn cidrs() {
        assert_eq!(
            parse_cidr("10.0.0.0/8"),
            Some((Ipv4Addr::new(10, 0, 0, 0), 8))
        );
        assert_eq!(parse_cidr("1.2.3.4"), Some((Ipv4Addr::new(1, 2, 3, 4), 32)));
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert!(inside(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
        assert_eq!(mask(0), 0);
        assert_eq!(mask(32), u32::MAX);
    }
}
