//! what a VM may reach, as a function. the policy in rust terms, for explain,
//! the connection log's reasons and the probe's expectations. it only ever
//! explains and predicts: nft (linux) and macnet's policy (macOS) are the
//! only things that decide what a packet does

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::config::{self, Config};
use crate::net::{Blocked, Mode, Why};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    /// anything else ip carries (gre, sctp, ...)
    Other,
}

impl Proto {
    pub fn from_ip(n: u8) -> Proto {
        match n {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            1 => Proto::Icmp,
            _ => Proto::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Other => "other",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Blocked,
}

/// why something was blocked. an open list: readers skip values they don't know
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// this host itself: one of its addresses, or the VM's own gateway
    Host,
    /// a network the host is on, or anything behind a route that isn't the default one
    Route,
    /// one of the ranges never reachable on any network
    Special,
    /// net.block
    Config,
    /// net.block_public_ip
    PublicIp,
    /// another VM
    VmSubnet,
    /// a port this mode doesn't open
    Port,
    /// smtp, smtps or submission
    Mail,
    /// dns to a server that isn't one of net.resolvers
    NotResolver,
    /// past one of the filter's meters (new connections, dns, ping)
    Rate,
    /// macOS: too many open connections
    Flows,
    /// a protocol this mode doesn't carry
    Proto,
    /// --net none
    NoNetwork,
    /// the filter blocked it and the model can't say why
    Unknown,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Reason::Host => "host",
            Reason::Route => "route",
            Reason::Special => "special",
            Reason::Config => "config",
            Reason::PublicIp => "public_ip",
            Reason::VmSubnet => "vm_subnet",
            Reason::Port => "port",
            Reason::Mail => "mail",
            Reason::NotResolver => "not_resolver",
            Reason::Rate => "rate",
            Reason::Flows => "flows",
            Reason::Proto => "proto",
            Reason::NoNetwork => "no_network",
            Reason::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Platform {
    Linux,
    Mac,
}

/// what a VM is up against on this host: its mode, the resolvers, and every
/// blocked range with where it comes from
pub struct Model {
    pub mode: Mode,
    pub platform: Platform,
    pub resolvers: Vec<Ipv4Addr>,
    pub blocked: Vec<Blocked>,
    pub subnet: (Ipv4Addr, u8),
}

/// what the model says happens to one packet
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expect {
    pub verdict: Verdict,
    pub reason: Option<Reason>,
    /// which range, interface or rule, in words
    pub detail: Option<String>,
}

impl Expect {
    fn allowed() -> Expect {
        Expect {
            verdict: Verdict::Allowed,
            reason: None,
            detail: None,
        }
    }

    fn blocked(reason: Reason, detail: impl Into<String>) -> Expect {
        Expect {
            verdict: Verdict::Blocked,
            reason: Some(reason),
            detail: Some(detail.into()).filter(|d: &String| !d.is_empty()),
        }
    }
}

/// smtp, smtps and submission stay shut in open mode
pub const MAIL: [u16; 3] = [25, 465, 587];

/// what an interface is, by its name, only for display
pub fn iface_label(dev: &str) -> Option<&'static str> {
    if dev.starts_with("tailscale") {
        Some("tailnet")
    } else if dev.starts_with("wg") {
        Some("wireguard")
    } else if dev == "docker0" || dev.starts_with("br-") {
        Some("docker")
    } else if dev.starts_with("tun") || dev.starts_with("utun") {
        Some("vpn")
    } else {
        None
    }
}

fn inside(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    u32::from(ip) & config::mask(prefix) == u32::from(net) & config::mask(prefix)
}

/// on a tie between ranges of the same size, the more telling one wins
fn rank(w: &Why) -> u8 {
    match w {
        Why::HostAddr { .. } => 0,
        Why::PublicIp => 1,
        Why::Subnet => 2,
        Why::HostNet { .. } => 3,
        Why::Route { .. } => 4,
        Why::Config => 5,
        Why::Special { .. } => 6,
    }
}

/// a blocked range in words, and the reason it maps to
pub fn describe(b: &Blocked) -> (Reason, String) {
    let cidr = format!("{}/{}", b.net, b.prefix);
    match &b.why {
        Why::HostAddr { dev } => (Reason::Host, format!("this host, {} on {dev}", b.net)),
        Why::PublicIp => (
            Reason::PublicIp,
            format!("your public address {} (net.block_public_ip)", b.net),
        ),
        Why::Subnet => (Reason::VmSubnet, format!("other VMs ({cidr})")),
        Why::HostNet { dev } => {
            let what = iface_label(dev).unwrap_or("your lan");
            (Reason::Route, format!("{what} ({cidr} on {dev})"))
        }
        Why::Route { dev, via, table } => {
            let what = iface_label(dev).unwrap_or("a route");
            let via = via.map_or_else(String::new, |v| format!(" via {v}"));
            let table = match table.as_str() {
                "main" => String::new(),
                t => format!(", table {t}"),
            };
            (
                Reason::Route,
                format!("{what} ({cidr}{via} on {dev}{table})"),
            )
        }
        Why::Config => (Reason::Config, format!("net.block {cidr}")),
        Why::Special { label } => (Reason::Special, format!("{label} ({cidr})")),
    }
}

impl Model {
    /// the model for this host now. linux reads its addresses and routes, so
    /// that can fail; a mac's model comes from macnet's own view (explain)
    pub fn new(cfg: &Config, mode: Mode, platform: Platform, blocked: Vec<Blocked>) -> Model {
        Model {
            mode,
            platform,
            resolvers: cfg.net.resolvers.clone(),
            blocked,
            subnet: cfg.subnet().unwrap_or((Ipv4Addr::new(172, 29, 217, 0), 24)),
        }
    }

    /// the blocked range dst is in, the most specific one first
    pub fn range(&self, dst: Ipv4Addr) -> Option<&Blocked> {
        self.blocked
            .iter()
            .filter(|b| inside(dst, b.net, b.prefix))
            .min_by_key(|b| (std::cmp::Reverse(b.prefix), rank(&b.why)))
    }

    /// what happens to a new connection or datagram from a VM to dst:port.
    /// port is ignored for icmp and other protocols
    pub fn expect(&self, dst: Ipv4Addr, proto: Proto, port: u16) -> Expect {
        if self.mode == Mode::None {
            return Expect::blocked(Reason::NoNetwork, "--net none");
        }
        // the host side of a VM's /30 is the VM's gateway, which is this host
        let (sub, sp) = self.subnet;
        if inside(dst, sub, sp) && u32::from(dst) & 3 == 1 {
            return Expect::blocked(Reason::Host, format!("this host, the VM's gateway {dst}"));
        }
        if let Some(b) = self.range(dst) {
            let (reason, detail) = describe(b);
            return Expect::blocked(reason, detail);
        }
        let dns = matches!(proto, Proto::Tcp | Proto::Udp) && port == 53;
        if dns {
            return if self.resolvers.contains(&dst) {
                Expect::allowed()
            } else {
                Expect::blocked(Reason::NotResolver, "not one of net.resolvers")
            };
        }
        match (self.platform, self.mode, proto) {
            (_, Mode::Web, Proto::Tcp) if port == 80 || port == 443 => Expect::allowed(),
            (_, Mode::Web, Proto::Tcp) => {
                Expect::blocked(Reason::Port, format!("tcp {port} is closed in web mode"))
            }
            (_, Mode::Open, Proto::Tcp) if MAIL.contains(&port) => {
                Expect::blocked(Reason::Mail, format!("mail port {port}"))
            }
            (_, Mode::Open, Proto::Tcp) => Expect::allowed(),
            (Platform::Linux, _, Proto::Icmp) => Expect::allowed(),
            (Platform::Linux, Mode::Open, _) => Expect::allowed(),
            (Platform::Linux, _, p) => {
                Expect::blocked(Reason::Proto, format!("{} is closed in web mode", p.name()))
            }
            (Platform::Mac, _, p) => Expect::blocked(
                Reason::Proto,
                format!("{} doesn't go out on macOS, only tcp and dns", p.name()),
            ),
        }
    }

    /// the kernel blocked what the model would let through: one of the meters,
    /// when this kind of packet has one
    pub fn over_meter(&self, proto: Proto, port: u16) -> Reason {
        let metered = match proto {
            Proto::Tcp | Proto::Udp if port == 53 => true,
            Proto::Icmp => self.platform == Platform::Linux,
            Proto::Tcp => true,
            _ => self.mode == Mode::Open && self.platform == Platform::Linux,
        };
        if metered {
            Reason::Rate
        } else {
            Reason::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{self, parse_addrs, parse_routes};

    fn homelab(mode: Mode) -> Model {
        let mut cfg = Config::default();
        cfg.net.block = vec!["140.82.121.0/24".into()];
        let b = net::sources_from(
            &cfg,
            Some(Ipv4Addr::new(81, 2, 3, 4)),
            &parse_addrs(net::tests::HOMELAB_ADDRS.as_bytes()).unwrap(),
            &parse_routes(net::tests::HOMELAB_ROUTES.as_bytes(), "eth0").unwrap(),
        )
        .unwrap();
        Model::new(&cfg, mode, Platform::Linux, b)
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn blocked_ranges_say_why() {
        let m = homelab(Mode::Web);
        let r = |dst: &str| m.expect(ip(dst), Proto::Tcp, 443).reason.unwrap();
        assert_eq!(r("192.168.1.20"), Reason::Host);
        assert_eq!(r("172.29.217.1"), Reason::Host);
        assert_eq!(r("172.29.217.5"), Reason::Host);
        assert_eq!(r("172.29.217.6"), Reason::VmSubnet);
        assert_eq!(r("192.168.1.1"), Reason::Route);
        assert_eq!(r("172.16.98.1"), Reason::Route);
        assert_eq!(r("203.0.114.9"), Reason::Route);
        assert_eq!(r("169.254.169.254"), Reason::Special);
        assert_eq!(r("100.100.100.100"), Reason::Route);
        assert_eq!(r("140.82.121.4"), Reason::Config);
        assert_eq!(r("81.2.3.4"), Reason::PublicIp);
        let d = m.expect(ip("192.168.1.1"), Proto::Tcp, 22).detail.unwrap();
        assert_eq!(d, "your lan (192.168.1.0/24 on eth0)");
        let d = m.expect(ip("10.1.0.1"), Proto::Tcp, 22).detail.unwrap();
        assert_eq!(d, "wireguard (10.1.0.0/16 on wg0)");
        let d = m
            .expect(ip("169.254.169.254"), Proto::Tcp, 80)
            .detail
            .unwrap();
        assert_eq!(d, "cloud metadata and link-local (169.254.0.0/16)");
    }

    #[test]
    fn web_mode() {
        let m = homelab(Mode::Web);
        let gh = ip("140.82.112.3");
        let v = |p, port| m.expect(gh, p, port);
        assert_eq!(v(Proto::Tcp, 443).verdict, Verdict::Allowed);
        assert_eq!(v(Proto::Tcp, 80).verdict, Verdict::Allowed);
        assert_eq!(v(Proto::Tcp, 22).reason, Some(Reason::Port));
        assert_eq!(v(Proto::Tcp, 25).reason, Some(Reason::Port));
        assert_eq!(v(Proto::Udp, 443).reason, Some(Reason::Proto));
        assert_eq!(v(Proto::Icmp, 0).verdict, Verdict::Allowed);
        assert_eq!(v(Proto::Tcp, 53).reason, Some(Reason::NotResolver));
        assert_eq!(
            m.expect(ip("9.9.9.9"), Proto::Udp, 53).verdict,
            Verdict::Allowed
        );
        assert_eq!(
            m.expect(ip("8.8.8.8"), Proto::Udp, 53).reason,
            Some(Reason::NotResolver)
        );
    }

    #[test]
    fn open_mode() {
        let m = homelab(Mode::Open);
        let gh = ip("140.82.112.3");
        for port in [22, 80, 443, 8080, 1] {
            assert_eq!(m.expect(gh, Proto::Tcp, port).verdict, Verdict::Allowed);
        }
        for port in MAIL {
            assert_eq!(m.expect(gh, Proto::Tcp, port).reason, Some(Reason::Mail));
        }
        assert_eq!(m.expect(gh, Proto::Udp, 443).verdict, Verdict::Allowed);
        assert_eq!(
            m.expect(gh, Proto::Udp, 53).reason,
            Some(Reason::NotResolver)
        );
        assert_eq!(
            m.expect(ip("10.1.0.63"), Proto::Tcp, 22).reason,
            Some(Reason::Route)
        );
    }

    #[test]
    fn mac_carries_tcp_and_dns_only() {
        let mut m = homelab(Mode::Open);
        m.platform = Platform::Mac;
        let gh = ip("140.82.112.3");
        assert_eq!(m.expect(gh, Proto::Tcp, 22).verdict, Verdict::Allowed);
        assert_eq!(m.expect(gh, Proto::Icmp, 0).reason, Some(Reason::Proto));
        assert_eq!(m.expect(gh, Proto::Udp, 443).reason, Some(Reason::Proto));
        assert_eq!(
            m.expect(ip("1.1.1.1"), Proto::Udp, 53).verdict,
            Verdict::Allowed
        );
    }

    #[test]
    fn none_blocks_everything() {
        let m = homelab(Mode::None);
        assert_eq!(
            m.expect(ip("140.82.112.3"), Proto::Tcp, 443).reason,
            Some(Reason::NoNetwork)
        );
    }

    #[test]
    fn a_blocked_resolver_stays_blocked() {
        let mut m = homelab(Mode::Web);
        m.resolvers = vec![ip("192.168.1.1")];
        assert_eq!(
            m.expect(ip("192.168.1.1"), Proto::Udp, 53).verdict,
            Verdict::Blocked
        );
    }

    #[test]
    fn meters() {
        let m = homelab(Mode::Web);
        assert_eq!(m.over_meter(Proto::Tcp, 443), Reason::Rate);
        assert_eq!(m.over_meter(Proto::Udp, 53), Reason::Rate);
        assert_eq!(m.over_meter(Proto::Icmp, 0), Reason::Rate);
        assert_eq!(m.over_meter(Proto::Udp, 9), Reason::Unknown);
    }
}
