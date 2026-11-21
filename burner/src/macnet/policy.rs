//! what a guest may reach. the same policy as the linux nft table in
//! burner/src/net.rs: the special ranges and everything on the host are never
//! reachable, dns only goes to the configured resolvers, and the mode decides
//! which other ports are open

use std::net::Ipv4Addr;

use crate::netmodel::Reason;

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

/// why the policy said no. reason() is the connection log's word for it,
/// as_str() the words macnet -v has always used
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// the host's addresses couldn't be read, so nothing goes
    HostUnreadable,
    /// one of the host's own addresses
    Host,
    /// a network the host is on
    HostNet,
    Special,
    Config,
    PublicIp,
    VmNet,
    /// not the default way out, in route::check's words
    Route(&'static str),
    NotResolver,
    Port,
    Mail,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::HostUnreadable => "can't read the host's addresses",
            Refused::Host | Refused::HostNet => "the host's own address or network",
            Refused::Special | Refused::Config | Refused::PublicIp | Refused::VmNet => {
                "blocked range"
            }
            Refused::Route(why) => why,
            Refused::NotResolver => "not a configured resolver",
            Refused::Port => "port closed in web mode",
            Refused::Mail => "mail port closed in open mode",
        }
    }

    // the connection log's, next
    #[allow(dead_code)]
    pub fn reason(self) -> Reason {
        match self {
            Refused::HostUnreadable | Refused::Host => Reason::Host,
            Refused::Special => Reason::Special,
            Refused::Config => Reason::Config,
            Refused::PublicIp => Reason::PublicIp,
            Refused::VmNet => Reason::VmSubnet,
            Refused::Route(_) | Refused::HostNet => Reason::Route,
            Refused::NotResolver => Reason::NotResolver,
            Refused::Port => Reason::Port,
            Refused::Mail => Reason::Mail,
        }
    }
}

pub struct Policy {
    pub mode: Mode,
    pub resolvers: Vec<Ipv4Addr>,
    /// (range, what it is), checked in order
    blocked: Vec<(Ipv4Addr, u8, Refused)>,
    route: fn(Ipv4Addr) -> Result<u16, &'static str>,
}

impl Policy {
    /// extra: --block entries, public: the address net.block_public_ip found,
    /// guest_net: the guest's own network, never a destination
    pub fn new(
        mode: Mode,
        resolvers: Vec<Ipv4Addr>,
        extra: &[(Ipv4Addr, u8)],
        public: Option<Ipv4Addr>,
        guest_net: (Ipv4Addr, u8),
    ) -> Policy {
        let mut blocked = vec![(guest_net.0, guest_net.1, Refused::VmNet)];
        blocked.extend(public.map(|ip| (ip, 32, Refused::PublicIp)));
        blocked.extend(extra.iter().map(|&(n, p)| (n, p, Refused::Config)));
        // the same list the linux filter is built from
        blocked.extend(
            crate::net::SPECIAL
                .iter()
                .map(|s| (s.net, s.prefix, Refused::Special)),
        );
        Policy {
            mode,
            resolvers,
            blocked,
            route: super::route::check,
        }
    }

    /// the interface a guest tcp connection to dst:port goes out on, if it may
    /// go out at all, else why not
    pub fn tcp(&self, dst: Ipv4Addr, port: u16) -> Result<u16, Refused> {
        let index = self.reachable(dst)?;
        if port == 53 {
            return self.resolver(dst).map(|()| index);
        }
        match self.mode {
            Mode::Web if port == 80 || port == 443 => Ok(index),
            Mode::Web => Err(Refused::Port),
            Mode::Open if MAIL.contains(&port) => Err(Refused::Mail),
            Mode::Open => Ok(index),
        }
    }

    /// the interface a guest udp datagram to dst:53 goes out on, if it may
    pub fn dns(&self, dst: Ipv4Addr) -> Result<u16, Refused> {
        let index = self.reachable(dst)?;
        self.resolver(dst).map(|()| index)
    }

    fn resolver(&self, dst: Ipv4Addr) -> Result<(), Refused> {
        if self.resolvers.contains(&dst) {
            Ok(())
        } else {
            Err(Refused::NotResolver)
        }
    }

    fn reachable(&self, dst: Ipv4Addr) -> Result<u16, Refused> {
        // read fresh every time: interfaces come and go (wifi, vpn, docker)
        let host = host_nets().ok_or(Refused::HostUnreadable)?;
        if host.iter().any(|&(n, p)| p == 32 && n == dst) {
            return Err(Refused::Host);
        }
        if host.iter().any(|&(n, p)| inside(dst, n, p)) {
            return Err(Refused::HostNet);
        }
        if let Some(&(_, _, why)) = self.blocked.iter().find(|&&(n, p, _)| inside(dst, n, p)) {
            return Err(why);
        }
        (self.route)(dst).map_err(Refused::Route)
    }
}

/// every ipv4 address on the host as a /32, the network it sits on, and the far
/// end of point to point links (vpns). None if the list can't be read, which
/// the caller treats as blocked
pub fn host_nets() -> Option<Vec<(Ipv4Addr, u8)>> {
    let mut out = Vec::new();
    for a in host_addrs()? {
        out.push((a.ip, 32));
        if let Some(p) = a.prefix {
            out.push((a.ip, p));
        }
        if let Some(d) = a.peer {
            out.push((d, 32));
        }
    }
    Some(out)
}

/// one ipv4 address of the host
pub struct HostAddr {
    pub dev: String,
    pub ip: Ipv4Addr,
    pub prefix: Option<u8>,
    /// the far end of a point to point link
    pub peer: Option<Ipv4Addr>,
}

pub fn host_addrs() -> Option<Vec<HostAddr>> {
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
        let dev = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let prefix = sockaddr_v4(ifa.ifa_netmask).map(|m| u32::from(m).leading_ones() as u8);
        let peer = (ifa.ifa_flags & libc::IFF_POINTOPOINT as u32 != 0)
            .then(|| sockaddr_v4(ifa.ifa_dstaddr))
            .flatten();
        out.push(HostAddr {
            dev,
            ip,
            prefix,
            peer,
        });
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
        p.route = |_| Ok(1);
        p
    }

    fn web() -> Policy {
        any_route(Policy::new(
            Mode::Web,
            vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)],
            &[(Ipv4Addr::new(140, 82, 121, 0), 24)],
            Some(Ipv4Addr::new(81, 2, 3, 4)),
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
            None,
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
            None,
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
    fn reasons_and_the_old_words() {
        let p = web();
        let r = |ip: &str, port| p.tcp(ip.parse().unwrap(), port).unwrap_err();
        assert_eq!(r("169.254.169.254", 80), Refused::Special);
        assert_eq!(r("140.82.121.4", 443), Refused::Config);
        assert_eq!(r("81.2.3.4", 443), Refused::PublicIp);
        assert_eq!(r("172.29.217.1", 443), Refused::VmNet);
        assert_eq!(r("140.82.112.3", 22), Refused::Port);
        assert_eq!(r("8.8.8.8", 53), Refused::NotResolver);
        // what -v says, as before
        assert_eq!(Refused::Special.as_str(), "blocked range");
        assert_eq!(Refused::Config.as_str(), "blocked range");
        assert_eq!(Refused::Host.as_str(), "the host's own address or network");
        assert_eq!(Refused::Port.as_str(), "port closed in web mode");
        assert_eq!(Refused::Mail.as_str(), "mail port closed in open mode");
        assert_eq!(Refused::NotResolver.as_str(), "not a configured resolver");
        assert_eq!(
            Refused::Route("not routed through the default route").as_str(),
            "not routed through the default route"
        );
        assert_eq!(Refused::VmNet.reason(), Reason::VmSubnet);
    }

    /// the model explain and the log use says the same as the policy that
    /// decides, case by case
    #[test]
    fn the_model_agrees() {
        use crate::netmodel::{Model, Platform, Proto, Verdict};
        let p = web();
        let cfg = crate::config::Config {
            net: crate::config::Net {
                block: vec!["140.82.121.0/24".into()],
                ..crate::config::Config::default().net
            },
            ..crate::config::Config::default()
        };
        let mut blocked = Vec::new();
        for s in crate::net::SPECIAL {
            blocked.push(crate::net::Blocked {
                net: s.net,
                prefix: s.prefix,
                why: crate::net::Why::Special { label: s.label },
            });
        }
        let b = |n: [u8; 4], prefix, why| crate::net::Blocked {
            net: Ipv4Addr::from(n),
            prefix,
            why,
        };
        blocked.push(b([140, 82, 121, 0], 24, crate::net::Why::Config));
        blocked.push(b([81, 2, 3, 4], 32, crate::net::Why::PublicIp));
        blocked.push(b([172, 29, 217, 0], 24, crate::net::Why::Subnet));
        // and this mac's own, which the policy reads live
        for a in host_addrs().unwrap() {
            let dev = a.dev.clone();
            blocked.push(b(
                a.ip.octets(),
                32,
                crate::net::Why::HostAddr { dev: dev.clone() },
            ));
            if let Some(p) = a.prefix {
                let net = Ipv4Addr::from(u32::from(a.ip) & mask(p));
                blocked.push(b(net.octets(), p, crate::net::Why::HostNet { dev }));
            }
        }
        let mut m = Model::new(&cfg, crate::net::Mode::Web, Platform::Mac, blocked);
        m.resolvers = p.resolvers.clone();
        for (ip, port) in [
            ("140.82.112.3", 443),
            ("140.82.112.3", 80),
            ("140.82.112.3", 22),
            ("140.82.112.3", 25),
            ("9.9.9.9", 53),
            ("8.8.8.8", 53),
            ("169.254.169.254", 80),
            ("140.82.121.4", 443),
            ("81.2.3.4", 443),
            ("10.1.0.63", 22),
            ("100.100.100.100", 53),
        ]
        .into_iter()
        .chain(
            host_addrs()
                .unwrap()
                .into_iter()
                .filter(|a| !a.ip.is_loopback())
                .map(|a| (Box::leak(a.ip.to_string().into_boxed_str()) as &str, 443)),
        ) {
            let dst: Ipv4Addr = ip.parse().unwrap();
            let e = m.expect(dst, Proto::Tcp, port);
            match p.tcp(dst, port) {
                Ok(_) => assert_eq!(e.verdict, Verdict::Allowed, "{ip}:{port}"),
                Err(why) => {
                    assert_eq!(e.verdict, Verdict::Blocked, "{ip}:{port}");
                    // the policy's vm network is the guest's /30, the
                    // model's the whole subnet: both block it
                    if why != Refused::VmNet {
                        assert_eq!(e.reason, Some(why.reason()), "{ip}:{port}");
                    }
                }
            }
        }
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
