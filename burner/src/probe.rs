//! `burner doctor --probe`: a real VM tries the places a VM must not reach
//! on this host (the gateway, the host, the lan, other routes, the tailnet,
//! cloud metadata, other VMs) and a few it may, and the host says what
//! happened, not the guest. on linux the connection log and a witness table
//! of counters after burner's filter decide; on macOS macnet's own log and a
//! loopback canary. the guest's own OPEN/BLOCKED lines only show disagreement

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use clap::Args;
use serde::Serialize;

use crate::config::Config;
use crate::net::{Mode, Why};
use crate::netlog::{Event, Kind, NetLog, Outcome};
use crate::netmodel::{self, Model, Platform, Proto, Verdict};

const MAX_LINES: usize = 40;
const MAX_TARGETS: usize = 8;
const PER_KIND: usize = 8;

#[derive(Args, Clone, Default)]
pub struct ProbeArgs {
    /// boot a VM that tries what a VM must not reach here, and check what the host saw
    #[arg(long)]
    pub probe: bool,
    /// the mode to probe, web or open. default web, and open too when the config allows it
    #[arg(long, requires = "probe")]
    pub net: Option<String>,
    /// one more address to try, IP:PORT, repeatable (up to 8)
    #[arg(long, requires = "probe", value_name = "IP:PORT")]
    pub target: Vec<String>,
    /// the internet host tried on 443 (allowed), 22 and 25
    #[arg(
        long,
        requires = "probe",
        default_value = "burnervm.dev",
        value_name = "HOST"
    )]
    pub internet: String,
    /// the image the probe VM boots. default alpine, or the only image there is
    #[arg(long, requires = "probe", value_name = "IMAGE")]
    pub img: Option<String>,
}

/// alpine when it's installed, else the first image there is: a box with
/// only debian can still probe
fn probe_image(cfg: &Config, a: &ProbeArgs) -> Result<String, String> {
    if let Some(i) = &a.img {
        return Ok(i.clone());
    }
    let have = crate::run::images(cfg);
    if have.iter().any(|i| i == "alpine") {
        return Ok("alpine".into());
    }
    have.into_iter()
        .next()
        .ok_or_else(|| "no image here to probe with (burner images)".to_string())
}

#[derive(Clone, Debug, PartialEq)]
enum Dst {
    Ip(Ipv4Addr),
    Name(String),
    /// the probe VM's own gateway, the host side of its tap
    TapGateway,
    /// the address another VM would have
    OtherVm,
}

#[derive(Clone, Debug, PartialEq)]
enum How {
    Tcp(Dst, u16),
    Ping(Ipv4Addr),
    Dns(Dst, String),
    V6,
    /// macOS: send the token to the canary listening on ip:port
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Canary(Ipv4Addr, u16, String),
}

#[derive(Clone, Debug)]
struct Target {
    /// the guest script's name for it, [a-z0-9-]
    name: String,
    label: String,
    kind: &'static str,
    how: How,
    expect: Verdict,
}

/// what a witness counter says about one target
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Witnessed {
    /// the target has no counter (macOS, or not blocked in every mode)
    NoRule,
    Count(u64),
    /// it should have one and it couldn't be read: no evidence either way
    Unreadable,
}

/// the witness table's counters per target, from what it put up and what
/// came back. every counter it put up must come back. linux only, there's
/// no witness table on a mac
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn witnessed(
    rules: &[usize],
    counts: Option<&std::collections::HashMap<String, u64>>,
    i: usize,
) -> Witnessed {
    if !rules.contains(&i) {
        return Witnessed::NoRule;
    }
    match counts.and_then(|c| c.get(&format!("w{i}"))) {
        Some(&n) => Witnessed::Count(n),
        None => Witnessed::Unreadable,
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Row {
    pub target: String,
    pub kind: &'static str,
    pub dst: Option<String>,
    pub port: Option<u16>,
    pub proto: &'static str,
    pub expect: Verdict,
    /// blocked, answered, allowed_no_answer, leaked, not_tried, inconclusive
    pub host_saw: &'static str,
    /// what the guest said, open or blocked, null if it said nothing
    pub guest_said: Option<&'static str>,
    /// linux: packets the witness counters saw get past burner's filter
    pub leaked_packets: Option<u64>,
    pub ok: bool,
}

#[derive(Serialize, Debug)]
pub struct ProbeRun {
    pub mode: &'static str,
    pub id: Option<String>,
    pub secs: f64,
    pub rows: Vec<Row>,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct Probe {
    pub platform: &'static str,
    pub internet: String,
    pub runs: Vec<ProbeRun>,
    /// every row as expected
    pub ok: bool,
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// a hostname that may go in the guest's script: letters, digits, dots, dashes
pub fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !h.starts_with('-')
}

fn first_host(net: Ipv4Addr, prefix: u8, not: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        return (!not.contains(&net)).then_some(net);
    }
    let base = u32::from(net);
    (1..4)
        .map(|i| Ipv4Addr::from(base + i))
        .find(|ip| !not.contains(ip))
}

/// what a probe in `mode` tries, from the same model explain uses
fn targets(
    m: &Model,
    cfg: &Config,
    gateway: Option<Ipv4Addr>,
    a: &ProbeArgs,
) -> Result<Vec<Target>, String> {
    let mut out: Vec<Target> = Vec::new();
    let mut add = |name: String, label: String, kind: &'static str, how: How, expect: Verdict| {
        if !out.iter().any(|t| t.how == how) {
            out.push(Target {
                name: slug(&name),
                label,
                kind,
                how,
                expect,
            });
        }
    };
    let tcp_expect = |dst: Ipv4Addr, port| m.expect(dst, Proto::Tcp, port).verdict;
    if let Some(gw) = gateway {
        for port in [53, 80, 443] {
            add(
                format!("gateway-{port}"),
                format!("gateway {gw} tcp/{port}"),
                "gateway",
                How::Tcp(Dst::Ip(gw), port),
                tcp_expect(gw, port),
            );
        }
        add(
            "gateway-ping".into(),
            format!("gateway {gw} ping"),
            "gateway",
            How::Ping(gw),
            m.expect(gw, Proto::Icmp, 0).verdict,
        );
    }
    let usable = |dev: &str| !crate::net::is_tap(dev) && dev != "lo" && dev != "lo0";
    let host: Vec<Ipv4Addr> = m
        .blocked
        .iter()
        .filter_map(|b| match &b.why {
            Why::HostAddr { dev } if usable(dev) && !b.net.is_loopback() => Some(b.net),
            _ => None,
        })
        .take(PER_KIND)
        .collect();
    for (i, ip) in host.iter().enumerate() {
        for port in [22, 80, 443] {
            add(
                format!("host{i}-{port}"),
                format!("this host {ip} tcp/{port}"),
                "host",
                How::Tcp(Dst::Ip(*ip), port),
                Verdict::Blocked,
            );
        }
    }
    for port in [22, 53] {
        let how = match port {
            53 => How::Dns(Dst::TapGateway, a.internet.clone()),
            p => How::Tcp(Dst::TapGateway, p),
        };
        let what = if port == 53 { "udp/53" } else { "tcp/22" };
        add(
            format!("tap-{port}"),
            format!("tap gateway (this host) {what}"),
            "tap",
            how,
            Verdict::Blocked,
        );
    }
    let mut lans = 0;
    for b in &m.blocked {
        let Why::HostNet { dev } = &b.why else {
            continue;
        };
        if !usable(dev) || b.prefix == 32 || b.net.is_loopback() || lans >= PER_KIND {
            continue;
        }
        let Some(ip) = first_host(b.net, b.prefix, &host) else {
            continue;
        };
        lans += 1;
        // a docker or vpn network the host is on, by its name
        let what = format!(
            "{} {}/{} on {dev}",
            netmodel::iface_label(dev).unwrap_or("lan"),
            b.net,
            b.prefix
        );
        add(
            format!("lan{lans}-22"),
            format!("{what} ({ip}) tcp/22"),
            "lan",
            How::Tcp(Dst::Ip(ip), 22),
            Verdict::Blocked,
        );
        add(
            format!("lan{lans}-ping"),
            format!("{what} ({ip}) ping"),
            "lan",
            How::Ping(ip),
            Verdict::Blocked,
        );
    }
    let mut routes = 0;
    for b in &m.blocked {
        let Why::Route { dev, .. } = &b.why else {
            continue;
        };
        if !usable(dev) || routes >= PER_KIND {
            continue;
        }
        // a route inside a network the host is on is that network's, and one
        // inside link-local, multicast or broadcast is the special range's
        if m.range(b.net)
            .is_some_and(|r| !matches!(r.why, Why::Route { .. }))
            || crate::net::special(b.net)
                .is_some_and(|sp| sp.label != "private range" && sp.prefix <= b.prefix)
        {
            continue;
        }
        let Some(ip) = first_host(b.net, b.prefix, &host) else {
            continue;
        };
        routes += 1;
        let what = format!("{}/{} on {dev}", b.net, b.prefix);
        for port in [22, 443] {
            add(
                format!("route{routes}-{port}"),
                format!("route {what} ({ip}) tcp/{port}"),
                "route",
                How::Tcp(Dst::Ip(ip), port),
                Verdict::Blocked,
            );
        }
    }
    if m.blocked.iter().any(|b| matches!(&b.why, Why::HostAddr { dev } | Why::HostNet { dev } | Why::Route { dev, .. } if netmodel::iface_label(dev) == Some("tailnet"))) {
        let ts = Ipv4Addr::new(100, 100, 100, 100);
        for port in [53, 80] {
            add(format!("tailnet-{port}"), format!("tailnet {ts} tcp/{port}"), "tailnet", How::Tcp(Dst::Ip(ts), port), Verdict::Blocked);
        }
    }
    let md = Ipv4Addr::new(169, 254, 169, 254);
    add(
        "metadata-80".into(),
        format!("cloud metadata {md} tcp/80"),
        "metadata",
        How::Tcp(Dst::Ip(md), 80),
        Verdict::Blocked,
    );
    add(
        "other-vm-22".into(),
        "other VM tcp/22".into(),
        "vm",
        How::Tcp(Dst::OtherVm, 22),
        Verdict::Blocked,
    );
    if let Some(b) = m.blocked.iter().find(|b| b.why == Why::PublicIp) {
        for port in [80, 443] {
            add(
                format!("public-{port}"),
                format!("public ip {} tcp/{port}", b.net),
                "public_ip",
                How::Tcp(Dst::Ip(b.net), port),
                Verdict::Blocked,
            );
        }
    }
    if let Some(r) = cfg.net.resolvers.first() {
        add(
            "resolver".into(),
            format!("dns {r} (resolver)"),
            "resolver",
            How::Dns(Dst::Ip(*r), a.internet.clone()),
            Verdict::Allowed,
        );
    }
    let other = if cfg.net.resolvers.contains(&Ipv4Addr::new(8, 8, 8, 8)) {
        Ipv4Addr::new(9, 9, 9, 9)
    } else {
        Ipv4Addr::new(8, 8, 8, 8)
    };
    if !cfg.net.resolvers.contains(&other) {
        add(
            "other-resolver".into(),
            format!("dns {other} (not a resolver)"),
            "other_resolver",
            How::Dns(Dst::Ip(other), a.internet.clone()),
            Verdict::Blocked,
        );
    }
    let inet = &a.internet;
    let open22 = if m.mode == Mode::Open {
        Verdict::Allowed
    } else {
        Verdict::Blocked
    };
    add(
        "internet-443".into(),
        format!("internet {inet} tcp/443"),
        "internet",
        How::Tcp(Dst::Name(inet.clone()), 443),
        Verdict::Allowed,
    );
    add(
        "internet-22".into(),
        format!("internet {inet} tcp/22"),
        "internet",
        How::Tcp(Dst::Name(inet.clone()), 22),
        open22,
    );
    add(
        "mail-25".into(),
        format!("mail {inet} tcp/25"),
        "mail",
        How::Tcp(Dst::Name(inet.clone()), 25),
        Verdict::Blocked,
    );
    // dns rebinding: a name that resolves to this host is refused all the same
    if let Some(ip) = host.first() {
        let name = format!("{}.sslip.io", ip.to_string().replace('.', "-"));
        add(
            "rebind".into(),
            format!("rebinding {name} -> {ip} tcp/81"),
            "rebind",
            // a port of its own, so its row is its own
            How::Tcp(Dst::Name(name), 81),
            Verdict::Blocked,
        );
    }
    add(
        "ipv6".into(),
        "ipv6 out of the VM (ff02::1)".into(),
        "ipv6",
        How::V6,
        Verdict::Blocked,
    );
    for (i, t) in a.target.iter().enumerate().take(MAX_TARGETS) {
        let (ip, port) = t
            .rsplit_once(':')
            .and_then(|(ip, p)| Some((ip.parse::<Ipv4Addr>().ok()?, p.parse::<u16>().ok()?)))
            .ok_or_else(|| format!("--target {t:?}: IP:PORT"))?;
        add(
            format!("extra{i}"),
            format!("--target {ip} tcp/{port}"),
            "extra",
            How::Tcp(Dst::Ip(ip), port),
            tcp_expect(ip, port),
        );
    }
    if a.target.len() > MAX_TARGETS {
        return Err(format!("at most {MAX_TARGETS} --target"));
    }
    // over the cap, the many-of-a-kind rows go first, from their ends
    for kind in ["route", "lan", "host", "gateway"] {
        while out.len() > MAX_LINES {
            let Some(i) = out.iter().rposition(|t| t.kind == kind) else {
                break;
            };
            out.remove(i);
        }
    }
    out.truncate(MAX_LINES);
    Ok(out)
}

/// the guest's half: one line per target, all at once, each OPEN or BLOCKED
fn script(ts: &[Target]) -> String {
    let mut s = String::from(
        "GW=$(ip route | awk '/^default/ {print $3}')\n\
         ME=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, \"/\"); print a[1]}')\n\
         case $ME in *.2) OTHER=${ME%.*}.6 ;; *) OTHER=${ME%.*}.2 ;; esac\n\
         p() { ( if timeout 8 sh -c \"$2\" >/dev/null 2>&1; then echo \"OPEN $1\"; else echo \"BLOCKED $1\"; fi ) & }\n",
    );
    let dst = |d: &Dst| match d {
        Dst::Ip(ip) => ip.to_string(),
        Dst::Name(n) => n.clone(),
        Dst::TapGateway => "$GW".into(),
        Dst::OtherVm => "$OTHER".into(),
    };
    let mut last = String::new();
    for t in ts {
        // the canary goes after everything else: it takes the guest's own
        // loopback route away to send 127.0.0.1 out eth0
        if let How::Canary(ip, port, token) = &t.how {
            last += &format!(
                "sysctl -qw net.ipv4.conf.all.route_localnet=1 net.ipv4.conf.eth0.route_localnet=1 2>/dev/null\n\
                 ip route del local 127.0.0.0/8 table local 2>/dev/null; ip route del local {ip} table local 2>/dev/null\n\
                 ip route add {ip}/32 via $GW dev eth0 2>/dev/null\n\
                 if echo {token} | timeout 8 nc -w 3 {ip} {port} >/dev/null 2>&1; then echo \"OPEN {n}\"; else echo \"BLOCKED {n}\"; fi\n",
                n = t.name
            );
            continue;
        }
        let cmd = match &t.how {
            How::Tcp(d, port) => format!("nc -z -w 3 {} {port}", dst(d)),
            How::Ping(ip) => format!("ping -c 1 -W 3 {ip}"),
            How::Dns(d, name) => format!("nslookup {name} {}", dst(d)),
            // the guest hears its own echo: only a reply from anyone else counts
            How::V6 => "ping -6 -c 2 -W 2 -I eth0 ff02::1 2>&1 | grep \\\"bytes from\\\" | grep -v \\\"from $(ip -6 addr show dev eth0 scope link | grep -oE fe80[0-9a-f:]+):\\\" | grep -q .".into(),
            How::Canary(..) => unreachable!("written last"),
        };
        s += &format!("p {} \"{cmd}\"\n", t.name);
    }
    s + "wait\n" + &last
}

/// the guest's lines, strictly: OPEN or BLOCKED and a name it was given
fn guest_said(out: &str, ts: &[Target]) -> Vec<(String, &'static str)> {
    out.lines()
        .filter_map(|l| {
            let (w, name) = l.trim_end().split_once(' ')?;
            let w = match w {
                "OPEN" => "open",
                "BLOCKED" => "blocked",
                _ => return None,
            };
            ts.iter()
                .any(|t| t.name == name)
                .then(|| (name.to_string(), w))
        })
        .collect()
}

fn in_subnet(m: &Model, ip: Ipv4Addr) -> bool {
    let (n, p) = m.subnet;
    u32::from(ip) & crate::config::mask(p) == u32::from(n)
}

/// what the host saw for one target, from the connection log
fn host_saw(t: &Target, log: &NetLog, m: &Model) -> &'static str {
    let conn = |e: &&Event| e.kind == Kind::Conn;
    let rows: Vec<&Event> = match &t.how {
        How::Canary(ip, port, _) => log
            .events
            .iter()
            .filter(conn)
            .filter(|e| e.proto == Proto::Tcp && e.port == Some(*port) && e.dst == *ip)
            .collect(),
        How::Tcp(d, port) => log
            .events
            .iter()
            .filter(conn)
            .filter(|e| e.proto == Proto::Tcp && e.port == Some(*port))
            .filter(|e| match d {
                Dst::Ip(ip) => e.dst == *ip,
                Dst::Name(n) => e.names.contains(n),
                Dst::TapGateway => in_subnet(m, e.dst) && u32::from(e.dst) & 3 == 1,
                Dst::OtherVm => in_subnet(m, e.dst) && u32::from(e.dst) & 3 == 2,
            })
            .collect(),
        How::Ping(ip) => log
            .events
            .iter()
            .filter(conn)
            .filter(|e| e.proto == Proto::Icmp && e.dst == *ip)
            .collect(),
        How::Dns(d, name) => log
            .events
            .iter()
            .filter(|e| e.kind == Kind::Dns && e.name.as_deref() == Some(name.as_str()))
            .filter(|e| match d {
                Dst::Ip(ip) => e.dst == *ip,
                _ => in_subnet(m, e.dst) && u32::from(e.dst) & 3 == 1,
            })
            .collect(),
        How::V6 => Vec::new(),
    };
    if rows.is_empty() {
        // with messages lost, nothing seen proves nothing was sent
        return if log.complete {
            "not_tried"
        } else {
            "inconclusive"
        };
    }
    let allowed: Vec<&&Event> = rows
        .iter()
        .filter(|e| e.verdict == Verdict::Allowed)
        .collect();
    if allowed.is_empty() {
        // blocked only when the host's record says so for every attempt
        return if rows.iter().all(|e| e.verdict == Verdict::Blocked) {
            "blocked"
        } else {
            "inconclusive"
        };
    }
    let answered = allowed.iter().any(|e| match e.kind {
        Kind::Dns => e.rcode.is_some(),
        Kind::Conn => e.outcome == Some(Outcome::Answered),
    });
    if answered {
        "answered"
    } else {
        "allowed_no_answer"
    }
}

/// one row's verdict, all sources together
fn judge(t: &Target, saw: &'static str, w: Witnessed, guest: Option<&'static str>) -> Row {
    let saw = match w {
        Witnessed::Count(n) if n > 0 => "leaked",
        // a blocked row needs the counter that would have caught a leak
        Witnessed::Unreadable if saw != "leaked" => "inconclusive",
        _ => saw,
    };
    let leaked = match w {
        Witnessed::Count(n) => Some(n),
        _ => None,
    };
    let ok = match (t.expect, saw) {
        (_, "leaked") => false,
        (Verdict::Blocked, "blocked") => true,
        (Verdict::Allowed, "answered" | "allowed_no_answer") => true,
        // the guest never sent it: inconclusive, a warning
        (_, "not_tried") => true,
        _ => false,
    };
    let (dst, port, proto) = match &t.how {
        How::Tcp(Dst::Ip(ip), p) => (Some(ip.to_string()), Some(*p), "tcp"),
        How::Tcp(Dst::Name(n), p) => (Some(n.clone()), Some(*p), "tcp"),
        How::Tcp(_, p) => (None, Some(*p), "tcp"),
        How::Ping(ip) => (Some(ip.to_string()), None, "icmp"),
        How::Dns(Dst::Ip(ip), _) => (Some(ip.to_string()), Some(53), "dns"),
        How::Dns(_, _) => (None, Some(53), "dns"),
        How::V6 => (None, None, "ipv6"),
        How::Canary(ip, p, _) => (Some(ip.to_string()), Some(*p), "tcp"),
    };
    Row {
        target: t.label.clone(),
        kind: t.kind,
        dst,
        port,
        proto,
        expect: t.expect,
        host_saw: saw,
        guest_said: guest,
        leaked_packets: leaked,
        ok,
    }
}

fn shown(saw: &str) -> &str {
    match saw {
        "allowed_no_answer" => "allowed, no answer",
        "not_tried" => "not tried",
        "leaked" => "LEAKED",
        "inconclusive" => "INCONCLUSIVE",
        s => s,
    }
}

pub fn render(p: &Probe) -> String {
    let mut s = String::new();
    for r in &p.runs {
        s += &format!(
            "probing with a VM, --net {} ({}, {:.1}s)\n\n",
            r.mode,
            r.id.as_deref().unwrap_or("no VM"),
            r.secs
        );
        let w = r
            .rows
            .iter()
            .map(|x| x.target.len())
            .max()
            .unwrap_or(6)
            .max(6);
        s += &format!("  {:<w$}  expect    host saw\n", "target");
        for x in &r.rows {
            let e = match x.expect {
                Verdict::Allowed => "allowed",
                Verdict::Blocked => "blocked",
                Verdict::Unknown => "unknown",
            };
            let mut line = format!("  {:<w$}  {e:<8}  {}", x.target, shown(x.host_saw));
            if !x.ok {
                line += "   <- not as expected";
            }
            s += &line;
            s.push('\n');
        }
        for wn in &r.warnings {
            s += &format!("  warn: {wn}\n");
        }
        let bad = r.rows.iter().filter(|x| !x.ok).count();
        let leaks = r.rows.iter().filter(|x| x.host_saw == "leaked").count();
        s += &match (bad, leaks) {
            (0, _) => format!(
                "\nall {} as expected, nothing got past the filter\n\n",
                r.rows.len()
            ),
            (b, 0) => format!("\n{b} of {} not as expected\n\n", r.rows.len()),
            (b, l) => format!(
                "\n{b} of {} not as expected, {l} LEAKED past the filter\n\n",
                r.rows.len()
            ),
        };
    }
    s
}

/// the rows of one run, warnings for what's inconclusive
fn rows(
    ts: &[Target],
    log: &NetLog,
    m: &Model,
    out: &str,
    leaked: &dyn Fn(usize) -> Witnessed,
    v6: Option<&'static str>,
) -> (Vec<Row>, Vec<String>) {
    let said = guest_said(out, ts);
    let mut rows = Vec::new();
    let mut warns = Vec::new();
    for (i, t) in ts.iter().enumerate() {
        let guest = said.iter().find(|(n, _)| *n == t.name).map(|(_, w)| *w);
        let saw = match t.how {
            How::V6 => match v6 {
                Some(saw) => saw,
                // no witness here (macOS): macnet takes ipv4 only, the guest's
                // word is all there is: did anything but itself answer
                None => match guest {
                    Some("blocked") => "blocked",
                    Some(_) => "leaked",
                    None => "not_tried",
                },
            },
            _ => host_saw(t, log, m),
        };
        let r = judge(t, saw, leaked(i), guest);
        if r.host_saw == "inconclusive" {
            warns.push(format!(
                "{}: the host's evidence for it is missing (a lost log message or an unreadable counter)",
                r.target
            ));
        }
        if r.host_saw == "not_tried" {
            warns.push(format!(
                "{}: the host saw nothing from the VM for it",
                r.target
            ));
        }
        if r.host_saw == "allowed_no_answer" {
            warns.push(format!("{}: let through, but nothing answered", r.target));
        }
        if r.host_saw == "blocked" && guest == Some("open") && t.kind != "ipv6" {
            warns.push(format!(
                "{}: the guest says open, the host saw it blocked",
                r.target
            ));
        }
        rows.push(r);
    }
    (rows, warns)
}

/// run the probe VM: burner run itself, with --json, so it's a normal run in
/// every way. (exit, the envelope's result, the guest's output)
fn run_vm(
    config: &Path,
    img: &str,
    mode: Mode,
    script: &str,
) -> Result<(u8, serde_json::Value, String), String> {
    let mut cmd = std::process::Command::new(crate::sys::self_exe());
    cmd.arg("--config").arg(config).args([
        "run",
        "--img",
        img,
        "--json",
        "--net",
        mode.name(),
        "--log",
        "none",
        "--tag",
        "probe",
        "--ttl",
        "2m",
        "--",
        script,
    ]);
    let out = crate::sys::run_timeout(&mut cmd, None, Duration::from_secs(240))
        .map_err(|e| format!("couldn't start the probe VM: {e}"))?;
    let env: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|_| "the probe run wrote no json".to_string())?;
    let code = env["exit"].as_u64().unwrap_or(125) as u8;
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    Ok((code, env, err))
}

/// one mode: targets, witness (linux), the VM, the verdicts
fn probe_mode(
    cfg: &Config,
    config: &Path,
    mode: Mode,
    a: &ProbeArgs,
) -> Result<ProbeRun, (u8, String)> {
    let t0 = Instant::now();
    #[cfg(target_os = "linux")]
    let (blocked, gateway, platform) = (
        crate::net::blocked_sources(cfg).map_err(|e| (125, format!("{e:#}")))?,
        cfg.uplink()
            .ok()
            .and_then(|u| crate::net::default_gateway(&u)),
        Platform::Linux,
    );
    #[cfg(target_os = "macos")]
    let (blocked, gateway, platform) = (
        crate::explain::mac_sources(cfg).map_err(|e| (125, format!("{e:#}")))?,
        mac::gateway(),
        Platform::Mac,
    );
    let m = Model::new(cfg, mode, platform, blocked.clone());
    let mut ts = targets(&m, cfg, gateway, a).map_err(|e| (2, e))?;
    #[cfg(target_os = "macos")]
    let canary = mac::Canary::open().map_err(|e| (125, format!("the loopback canary: {e}")))?;
    #[cfg(target_os = "macos")]
    canary.targets(&mut ts);
    #[cfg(target_os = "linux")]
    let witness =
        linux::Witness::up(cfg, &ts).map_err(|e| (125, format!("the witness table: {e}")))?;
    let img = probe_image(cfg, a).map_err(|e| (125, e))?;
    let res = run_vm(config, &img, mode, &script(&ts));
    #[cfg(target_os = "linux")]
    let (counts, witness_rules) = (witness.read(), witness.rules.clone());
    #[cfg(target_os = "linux")]
    drop(witness);
    let (code, env, err) = res.map_err(|e| (125, e))?;
    let r = &env["result"];
    let id = r["id"].as_str().map(str::to_string);
    let log: Option<NetLog> = serde_json::from_value(r["network"].clone()).ok();
    let Some(log) = log else {
        let why = env["errors"][0]["message"]
            .as_str()
            .unwrap_or("no log came back")
            .to_string();
        return Err((125, format!("the probe VM couldn't run: {why}")));
    };
    if code == crate::exit::EXIT_SANDBOX || code == crate::exit::EXIT_INTERRUPTED {
        let why = env["errors"][0]["message"]
            .as_str()
            .unwrap_or("")
            .to_string();
        return Err((125, format!("the probe VM didn't finish ({code}): {why}")));
    }
    #[cfg(target_os = "linux")]
    let (leaked, v6) = {
        let (c, rules) = (counts.clone(), witness_rules.clone());
        let v6 = Some(linux::v6_saw(c.as_ref()));
        let f = move |i: usize| witnessed(&rules, c.as_ref(), i);
        (f, v6)
    };
    #[cfg(target_os = "macos")]
    let (leaked, v6) = (|_: usize| Witnessed::NoRule, None::<&'static str>);
    let (mut rows, mut warnings) = rows(&ts, &log, &m, &err, &leaked, v6);
    // two rows that are the witness alone: anything from a VM into this
    // host past burner's input chain, or out an interface that isn't the uplink
    #[cfg(target_os = "linux")]
    {
        if counts.is_none() {
            warnings.push(
                "the witness counters couldn't be read back: nothing it covers is confirmed".into(),
            );
        }
        for (target, key) in [
            ("anything from a VM into this host (witness)", "in"),
            (
                "anything from a VM out a way that isn't the uplink (witness)",
                "post",
            ),
        ] {
            let n = counts.as_ref().and_then(|c| c.get(key).copied());
            let saw = match n {
                Some(0) => "blocked",
                Some(_) => "leaked",
                None => "inconclusive",
            };
            rows.push(Row {
                target: target.into(),
                kind: "witness",
                dst: None,
                port: None,
                proto: "any",
                expect: Verdict::Blocked,
                host_saw: saw,
                guest_said: None,
                leaked_packets: n,
                ok: n == Some(0),
            });
        }
    }
    #[cfg(target_os = "macos")]
    {
        let hits = canary.hits();
        if hits > 0 {
            warnings.push(format!(
                "the loopback canary took {hits} connections: a LEAK"
            ));
            for r in rows.iter_mut().filter(|r| r.kind == "canary") {
                r.host_saw = "leaked";
                r.ok = false;
            }
        }
    }
    if !log.complete {
        warnings.push("the connection log is incomplete, rows may be missing".into());
    }
    if rows
        .iter()
        .filter(|r| r.kind != "witness")
        .all(|r| r.host_saw == "not_tried")
    {
        warnings
            .push("the host saw nothing from the probe VM: the network log isn't receiving".into());
        for r in &mut rows {
            r.ok = false;
        }
    }
    let _ = &mut ts;
    Ok(ProbeRun {
        mode: mode.name(),
        id,
        secs: (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        rows,
        warnings,
    })
}

/// doctor --probe: exit 0 all as expected, 1 not, 125 no VM could run
pub fn main(cfg: &Config, config: &Path, a: &ProbeArgs) -> (u8, Option<Probe>, Option<String>) {
    #[cfg(target_os = "linux")]
    if !crate::sys::is_root() {
        return (
            2,
            None,
            Some("doctor --probe boots a VM: it needs root (sudo burner doctor --probe)".into()),
        );
    }
    if !host_ok(&a.internet) {
        return (
            2,
            None,
            Some(format!(
                "--internet {:?}: a hostname or address",
                a.internet
            )),
        );
    }
    let ceiling = Mode::parse(&cfg.limits.net).unwrap_or(Mode::None);
    let modes = match a.net.as_deref() {
        Some(n) => match Mode::parse(n) {
            Some(m @ (Mode::Web | Mode::Open)) if m <= ceiling => vec![m],
            Some(Mode::Web | Mode::Open) => {
                return (
                    2,
                    None,
                    Some(format!(
                        "--net {n} is more than this machine allows (limits.net = {})",
                        cfg.limits.net
                    )),
                );
            }
            _ => return (2, None, Some(format!("--net {n:?}: web or open"))),
        },
        None if ceiling == Mode::Open => vec![Mode::Web, Mode::Open],
        None if ceiling == Mode::Web => vec![Mode::Web],
        None => {
            return (
                2,
                None,
                Some("limits.net is none here, there's no network to probe".into()),
            );
        }
    };
    let mut runs = Vec::new();
    for mode in modes {
        match probe_mode(cfg, config, mode, a) {
            Ok(r) => runs.push(r),
            Err((code, msg)) => {
                let p = Probe {
                    platform: platform(),
                    internet: a.internet.clone(),
                    ok: false,
                    runs,
                };
                return (code, Some(p), Some(msg));
            }
        }
    }
    let ok = runs.iter().all(|r| r.rows.iter().all(|x| x.ok));
    let p = Probe {
        platform: platform(),
        internet: a.internet.clone(),
        runs,
        ok,
    };
    (
        if ok { 0 } else { 1 },
        Some(p),
        (!ok).then(|| "the probe found something not as expected".into()),
    )
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashMap;
    use std::process::Command;

    /// a table of counters after burner's chains, for the probe only: any
    /// packet counted here got past burner's filter. passive, policy accept,
    /// counters only, so it can't change what happens to a packet
    pub struct Witness {
        name: String,
        /// the targets with a counter of their own
        pub rules: Vec<usize>,
    }

    fn nft(args: &[&str], input: Option<&[u8]>) -> std::io::Result<std::process::Output> {
        crate::sys::run_timeout(
            Command::new("nft").args(args),
            input,
            Duration::from_secs(30),
        )
    }

    /// which targets get a counter: only what every mode blocks. a leak there
    /// is a leak whichever VM sent it, so other VMs running now can't make it
    /// look like one
    pub fn rule(t: &Target) -> Option<String> {
        match &t.how {
            How::Tcp(Dst::Ip(ip), port) if t.expect == Verdict::Blocked && t.kind != "extra" => {
                Some(format!("ip daddr {ip} tcp dport {port}"))
            }
            How::Ping(ip) if t.expect == Verdict::Blocked => {
                Some(format!("ip daddr {ip} icmp type echo-request"))
            }
            _ => None,
        }
    }

    pub fn rule_targets(ts: &[Target]) -> Vec<usize> {
        (0..ts.len()).filter(|&i| rule(&ts[i]).is_some()).collect()
    }

    pub fn table_text(name: &str, subnet: &str, uplink: &str, ts: &[Target]) -> String {
        let mut fwd = String::new();
        for (i, t) in ts.iter().enumerate() {
            let Some(rule) = rule(t) else { continue };
            fwd += &format!("        ip saddr {subnet} {rule} counter comment \"w{i}\"\n");
        }
        format!(
            "table inet {name} {{\n\
             \x20   chain w_fwd {{\n        type filter hook forward priority filter - 5; policy accept;\n{fwd}    }}\n\
             \x20   chain w_in {{\n        type filter hook input priority filter + 50; policy accept;\n        iifname \"bn*\" counter comment \"in\"\n    }}\n\
             \x20   chain w_post {{\n        type filter hook postrouting priority filter; policy accept;\n        ip saddr {subnet} oifname != \"{uplink}\" oifname != \"bn*\" counter comment \"post\"\n    }}\n\
             \x20   chain w_v6sent {{\n        type filter hook prerouting priority -451; policy accept;\n        iifname \"bn*\" meta nfproto ipv6 counter comment \"v6sent\"\n    }}\n\
             \x20   chain w_v6past {{\n        type filter hook prerouting priority -449; policy accept;\n        iifname \"bn*\" meta nfproto ipv6 counter comment \"v6past\"\n    }}\n\
             }}\n"
        )
    }

    impl Witness {
        pub fn up(cfg: &Config, ts: &[Target]) -> Result<Witness, String> {
            let name = format!("{PROBE_TABLE}{}", std::process::id());
            let uplink = cfg.uplink().map_err(|e| format!("{e:#}"))?;
            let text = table_text(&name, &cfg.net.subnet, &uplink, ts);
            let out = nft(&["-f", "-"], Some(text.as_bytes())).map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
            }
            Ok(Witness {
                name,
                rules: rule_targets(ts),
            })
        }

        /// comment -> packets, None if it can't be read
        pub fn read(&self) -> Option<HashMap<String, u64>> {
            let out = nft(&["-j", "list", "table", "inet", &self.name], None).ok()?;
            out.status.success().then_some(())?;
            parse_counts(&out.stdout)
        }
    }

    impl Drop for Witness {
        fn drop(&mut self) {
            let _ = nft(&["delete", "table", "inet", &self.name], None);
        }
    }

    pub fn parse_counts(json: &[u8]) -> Option<HashMap<String, u64>> {
        let v: serde_json::Value = serde_json::from_slice(json).ok()?;
        let mut out = HashMap::new();
        for o in v["nftables"].as_array()? {
            let Some(rule) = o.get("rule") else { continue };
            let Some(c) = rule["comment"].as_str() else {
                continue;
            };
            let n = rule["expr"]
                .as_array()?
                .iter()
                .find_map(|e| e.get("counter"))
                .and_then(|c| c["packets"].as_u64())?;
            out.insert(c.to_string(), n);
        }
        Some(out)
    }

    /// what the witness says about ipv6: sent and stopped, never sent, past
    /// the drop, or no evidence when either counter didn't come back
    pub fn v6_saw(c: Option<&HashMap<String, u64>>) -> &'static str {
        let get = |k: &str| c.and_then(|c| c.get(k).copied());
        match (get("v6sent"), get("v6past")) {
            (_, Some(p)) if p > 0 => "leaked",
            (Some(_), None) | (None, _) => "inconclusive",
            (Some(0), Some(_)) => "not_tried",
            _ => "blocked",
        }
    }

    pub const PROBE_TABLE: &str = "burner_probe_";

    /// from the reaper: a witness table whose probe is gone
    pub fn reap_tables() {
        let Ok(out) = nft(&["-j", "list", "tables"], None) else {
            return;
        };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
            return;
        };
        for o in v["nftables"].as_array().into_iter().flatten() {
            let Some(name) = o["table"]["name"].as_str() else {
                continue;
            };
            let Some(pid) = name
                .strip_prefix(PROBE_TABLE)
                .and_then(|p| p.parse::<u32>().ok())
            else {
                continue;
            };
            if !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = nft(&["delete", "table", "inet", name], None);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::reap_tables;

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use crate::macnet::route::{Gateway, lookup};

    pub fn gateway() -> Option<Ipv4Addr> {
        match lookup(Ipv4Addr::UNSPECIFIED, true).ok()?.gateway {
            Gateway::Inet(g) => Some(g),
            Gateway::Link => None,
        }
    }

    /// a listener on loopback, a port and a token only this probe knows. on
    /// a mac nothing outside macnet can carry guest traffic, so anything
    /// that reaches it with the token came through macnet: a leak, seen on
    /// the host. loopback only, so no firewall prompt and nothing on the lan
    pub struct Canary {
        port: u16,
        token: String,
        hits: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Canary {
        pub fn open() -> std::io::Result<Canary> {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            l.set_nonblocking(true)?;
            let port = l.local_addr()?.port();
            let token = crate::sys::random_hex(8)?;
            let hits = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let (hits, stop, token) = (hits.clone(), stop.clone(), token.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match l.accept() {
                            Ok((mut c, _)) => {
                                let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
                                let mut b = [0u8; 64];
                                let n = c.read(&mut b).unwrap_or(0);
                                if String::from_utf8_lossy(&b[..n]).contains(&token) {
                                    hits.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(50)),
                        }
                    }
                })
            };
            Ok(Canary {
                port,
                token,
                hits,
                stop,
                thread: Some(thread),
            })
        }

        /// the canary: the guest sends 127.0.0.1 out its eth0, which macnet
        /// must refuse. if it didn't, the connection lands here
        pub fn targets(&self, ts: &mut Vec<Target>) {
            let ip = Ipv4Addr::LOCALHOST;
            ts.push(Target {
                name: "canary".into(),
                label: format!("this mac's loopback {ip}:{} (canary)", self.port),
                kind: "canary",
                how: How::Canary(ip, self.port, self.token.clone()),
                expect: Verdict::Blocked,
            });
        }

        pub fn hits(&self) -> u64 {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for Canary {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{parse_addrs, parse_routes, sources_from};

    fn model(mode: Mode) -> (Model, Config) {
        let cfg = Config::default();
        let b = sources_from(
            &cfg,
            Some(Ipv4Addr::new(81, 2, 3, 4)),
            &parse_addrs(crate::net::tests::HOMELAB_ADDRS.as_bytes()).unwrap(),
            &parse_routes(crate::net::tests::HOMELAB_ROUTES.as_bytes(), "eth0").unwrap(),
        )
        .unwrap();
        (Model::new(&cfg, mode, Platform::Linux, b), cfg)
    }

    fn args() -> ProbeArgs {
        ProbeArgs {
            probe: true,
            internet: "burnervm.dev".into(),
            ..ProbeArgs::default()
        }
    }

    #[test]
    fn targets_from_the_model() {
        let (m, cfg) = model(Mode::Web);
        let ts = targets(&m, &cfg, Some(Ipv4Addr::new(192, 168, 1, 1)), &args()).unwrap();
        let names: Vec<&str> = ts.iter().map(|t| t.name.as_str()).collect();
        for want in [
            "gateway-53",
            "gateway-ping",
            "host0-22",
            "tap-22",
            "tap-53",
            "lan1-22",
            "route1-22",
            "tailnet-53",
            "metadata-80",
            "other-vm-22",
            "public-80",
            "resolver",
            "other-resolver",
            "internet-443",
            "internet-22",
            "mail-25",
            "rebind",
            "ipv6",
        ] {
            assert!(names.contains(&want), "{want} in {names:?}");
        }
        assert!(ts.len() <= MAX_LINES);
        let get = |n: &str| ts.iter().find(|t| t.name == n).unwrap();
        assert_eq!(get("internet-443").expect, Verdict::Allowed);
        assert_eq!(get("internet-22").expect, Verdict::Blocked);
        assert_eq!(get("resolver").expect, Verdict::Allowed);
        // the lan's first address that isn't this host
        assert!(
            get("lan1-22")
                .label
                .contains("192.168.1.0/24 on eth0 (192.168.1.1)"),
            "{}",
            get("lan1-22").label
        );
        for t in &ts {
            assert!(
                t.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}",
                t.name
            );
        }
        let (m, cfg) = model(Mode::Open);
        let ts = targets(&m, &cfg, None, &args()).unwrap();
        assert_eq!(
            ts.iter().find(|t| t.name == "internet-22").unwrap().expect,
            Verdict::Allowed
        );
        let mut a = args();
        a.target = vec!["10.9.9.9:8080".into(), "nope".into()];
        assert!(targets(&m, &cfg, None, &a).is_err());
    }

    #[test]
    fn the_guest_script() {
        let (m, cfg) = model(Mode::Web);
        let ts = targets(&m, &cfg, Some(Ipv4Addr::new(192, 168, 1, 1)), &args()).unwrap();
        let s = script(&ts);
        assert!(
            s.contains("p gateway-80 \"nc -z -w 3 192.168.1.1 80\"\n"),
            "{s}"
        );
        assert!(
            s.contains("p tap-53 \"nslookup burnervm.dev $GW\"\n"),
            "{s}"
        );
        assert!(
            s.contains("p rebind \"nc -z -w 3 192-168-1-20.sslip.io 81\"\n"),
            "{s}"
        );
        assert!(s.ends_with("wait\n"));
        assert!(
            !host_ok("a;rm -rf /") && !host_ok("$(x)") && !host_ok("-x") && host_ok("burnervm.dev")
        );
    }

    fn ev(kind: Kind, proto: Proto, dst: &str, port: Option<u16>, verdict: Verdict) -> Event {
        Event {
            t: 0.0,
            last: 0.0,
            count: 1,
            dir: "out".into(),
            kind,
            proto,
            dst: dst.parse().unwrap(),
            port,
            verdict,
            reason: None,
            detail: None,
            outcome: None,
            names: Vec::new(),
            bytes_up: None,
            bytes_down: None,
            name: None,
            qtype: None,
            rcode: None,
            answers: Vec::new(),
            malformed: false,
        }
    }

    #[test]
    fn verdicts() {
        let (m, cfg) = model(Mode::Web);
        let ts = targets(&m, &cfg, Some(Ipv4Addr::new(192, 168, 1, 1)), &args()).unwrap();
        let mut ok443 = ev(
            Kind::Conn,
            Proto::Tcp,
            "198.51.100.9",
            Some(443),
            Verdict::Allowed,
        );
        ok443.names = vec!["burnervm.dev".into()];
        ok443.outcome = Some(Outcome::Answered);
        let mut resolver = ev(Kind::Dns, Proto::Udp, "9.9.9.9", Some(53), Verdict::Allowed);
        resolver.name = Some("burnervm.dev".into());
        resolver.rcode = Some("NOERROR".into());
        let log = NetLog {
            id: "burner-000000000001".into(),
            net: "web".into(),
            platform: "linux".into(),
            owner: None,
            started_unix: 0,
            secs: 1.0,
            complete: true,
            lost: 0,
            not_itemized: 0,
            invalid: 0,
            summary: Default::default(),
            events: vec![
                ev(
                    Kind::Conn,
                    Proto::Tcp,
                    "192.168.1.1",
                    Some(80),
                    Verdict::Blocked,
                ),
                // a leak: allowed to the gateway
                ev(
                    Kind::Conn,
                    Proto::Tcp,
                    "192.168.1.1",
                    Some(443),
                    Verdict::Allowed,
                ),
                ok443,
                resolver,
                ev(
                    Kind::Conn,
                    Proto::Tcp,
                    "172.29.217.1",
                    Some(22),
                    Verdict::Blocked,
                ),
                ev(
                    Kind::Conn,
                    Proto::Tcp,
                    "172.29.217.6",
                    Some(22),
                    Verdict::Blocked,
                ),
            ],
        };
        let get = |n: &str| ts.iter().find(|t| t.name == n).unwrap();
        assert_eq!(host_saw(get("gateway-80"), &log, &m), "blocked");
        assert_eq!(host_saw(get("gateway-443"), &log, &m), "allowed_no_answer");
        assert_eq!(host_saw(get("internet-443"), &log, &m), "answered");
        assert_eq!(host_saw(get("resolver"), &log, &m), "answered");
        assert_eq!(host_saw(get("tap-22"), &log, &m), "blocked");
        assert_eq!(host_saw(get("other-vm-22"), &log, &m), "blocked");
        assert_eq!(host_saw(get("metadata-80"), &log, &m), "not_tried");
        assert!(
            !judge(
                get("gateway-443"),
                "allowed_no_answer",
                Witnessed::NoRule,
                None
            )
            .ok
        );
        assert!(
            judge(
                get("gateway-80"),
                "blocked",
                Witnessed::Count(0),
                Some("blocked")
            )
            .ok
        );
        // a witness count beats what the log says
        let r = judge(get("gateway-80"), "blocked", Witnessed::Count(3), None);
        assert_eq!((r.host_saw, r.ok), ("leaked", false));
        assert!(
            judge(get("metadata-80"), "not_tried", Witnessed::NoRule, None).ok,
            "inconclusive, a warning"
        );
        let out = "OPEN gateway-80\nBLOCKED tap-22\nOPEN made-up\nGARBAGE x\n";
        let said = guest_said(out, &ts);
        assert_eq!(
            said,
            vec![
                ("gateway-80".to_string(), "open"),
                ("tap-22".to_string(), "blocked")
            ]
        );
        let (rows, warns) = rows(&ts, &log, &m, out, &|_| Witnessed::NoRule, Some("blocked"));
        assert!(warns.iter().any(|w| w.contains("the guest says open")));
        assert!(rows.iter().any(|r| !r.ok));
        let text = render(&Probe {
            platform: "linux",
            internet: "burnervm.dev".into(),
            ok: false,
            runs: vec![ProbeRun {
                mode: "web",
                id: Some("burner-000000000001".into()),
                secs: 1.0,
                rows,
                warnings: warns,
            }],
        });
        assert!(text.contains("not as expected"), "{text}");
    }

    /// evidence that's missing never reads as blocked: an unreadable or
    /// absent witness counter, an attempt whose verdict the log lost, a row
    /// the guest never seemed to send in a log that's incomplete
    #[test]
    fn missing_evidence_is_inconclusive() {
        let (m, cfg) = model(Mode::Web);
        let ts = targets(&m, &cfg, Some(Ipv4Addr::new(192, 168, 1, 1)), &args()).unwrap();
        let get = |n: &str| ts.iter().find(|t| t.name == n).unwrap();
        let mut c = std::collections::HashMap::new();
        c.insert("w0".to_string(), 0u64);
        assert_eq!(witnessed(&[0, 1], Some(&c), 0), Witnessed::Count(0));
        assert_eq!(witnessed(&[0, 1], Some(&c), 1), Witnessed::Unreadable);
        assert_eq!(witnessed(&[0, 1], None, 0), Witnessed::Unreadable);
        assert_eq!(witnessed(&[0, 1], Some(&c), 2), Witnessed::NoRule);
        let r = judge(get("gateway-80"), "blocked", Witnessed::Unreadable, None);
        assert_eq!((r.host_saw, r.ok), ("inconclusive", false));
        // a leak still shows as one
        let r = judge(get("gateway-80"), "leaked", Witnessed::Unreadable, None);
        assert_eq!(r.host_saw, "leaked");
        let mut log = NetLog {
            id: "burner-000000000001".into(),
            net: "web".into(),
            platform: "linux".into(),
            owner: None,
            started_unix: 0,
            secs: 1.0,
            complete: false,
            lost: 1,
            not_itemized: 0,
            invalid: 0,
            summary: Default::default(),
            events: vec![ev(
                Kind::Conn,
                Proto::Tcp,
                "192.168.1.1",
                Some(80),
                Verdict::Unknown,
            )],
        };
        assert_eq!(host_saw(get("gateway-80"), &log, &m), "inconclusive");
        assert_eq!(host_saw(get("gateway-443"), &log, &m), "inconclusive");
        log.complete = true;
        log.events.clear();
        assert_eq!(host_saw(get("gateway-443"), &log, &m), "not_tried");
        let r = judge(get("gateway-443"), "inconclusive", Witnessed::NoRule, None);
        assert!(!r.ok);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn witness_table() {
        let (m, cfg) = model(Mode::Web);
        let ts = targets(&m, &cfg, Some(Ipv4Addr::new(192, 168, 1, 1)), &args()).unwrap();
        let t = linux::table_text("burner_probe_1", "172.29.217.0/24", "eth0", &ts);
        assert!(t.contains("policy accept;"));
        for v in [" drop", " reject", " queue", " jump", " goto", " accept\n"] {
            assert!(!t.contains(v), "{v} in {t}");
        }
        assert!(t.contains(
            "ip saddr 172.29.217.0/24 ip daddr 192.168.1.1 tcp dport 80 counter comment"
        ));
        assert!(!t.contains("198.51"), "names aren't witnessed");
        let mut c = std::collections::HashMap::new();
        assert_eq!(linux::v6_saw(None), "inconclusive");
        c.insert("v6sent".to_string(), 4u64);
        assert_eq!(linux::v6_saw(Some(&c)), "inconclusive", "no v6past");
        c.insert("v6past".to_string(), 0);
        assert_eq!(linux::v6_saw(Some(&c)), "blocked");
        c.insert("v6past".to_string(), 1);
        assert_eq!(linux::v6_saw(Some(&c)), "leaked");
        assert_eq!(
            linux::rule_targets(&ts).len(),
            t.matches("comment \"w").count()
        );
        let j = br#"{"nftables":[{"rule":{"family":"inet","table":"t","chain":"fwd","handle":3,"comment":"w0","expr":[{"match":{}},{"counter":{"packets":2,"bytes":120}}]}}]}"#;
        assert_eq!(linux::parse_counts(j).unwrap().get("w0"), Some(&2));
    }
}
