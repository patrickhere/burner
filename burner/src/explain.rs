//! `burner explain`: what a VM could reach on this host, in words, and with
//! --rules the rules behind it. read-only: it never changes the filter

use std::net::Ipv4Addr;

use clap::Args;
use serde::Serialize;

use crate::config::Config;
use crate::net::{self, Blocked, Mode, Why};
use crate::netmodel::{self, Platform};

#[derive(Args, Clone)]
pub struct ExplainArgs {
    /// the mode to explain: none, web or open. default web, or less if the
    /// config says so
    #[arg(long)]
    net: Option<String>,
    /// the firewall rules too: the loaded ones as root, else what would load
    #[arg(long)]
    rules: bool,
}

impl ExplainArgs {
    /// explain's argv for burner -H, rebuilt from what was parsed
    pub fn remote_argv(&self) -> Result<Vec<String>, String> {
        let mut v = vec!["explain".to_string()];
        if let Some(n) = &self.net {
            if net::Mode::parse(n).is_none() {
                return Err(format!("--net {n:?}: use none, web or open"));
            }
            v.extend(["--net".to_string(), n.clone()]);
        }
        if self.rules {
            v.push("--rules".into());
        }
        Ok(v)
    }

    /// -H runs explain --rules as the ssh user there, since sudo refuses it
    pub fn wants_rules(&self) -> bool {
        self.rules
    }

    /// --rules through sudo, for anyone but root: refused. the rule
    /// install.sh --allow writes lets a restricted user run explain, and the
    /// loaded rules (the tap entries, the public address) stay root's
    pub fn refused(&self) -> Option<String> {
        self.refused_for(std::env::var("SUDO_UID").ok().as_deref())
    }

    fn refused_for(&self, sudo_uid: Option<&str>) -> Option<String> {
        let caller = sudo_uid?;
        if !self.rules || !cfg!(target_os = "linux") || caller.trim() == "0" {
            return None;
        }
        Some(
            "burner explain --rules isn't allowed through sudo, the loaded rules are root's: \
             burner explain --rules without sudo shows what would load (as root: nft list table inet burner)"
                .into(),
        )
    }
}

#[derive(Serialize, Debug)]
pub struct Uplink {
    pub dev: String,
    pub gateway: Option<Ipv4Addr>,
    pub addrs: Vec<Ipv4Addr>,
}

#[derive(Serialize, Debug)]
pub struct Allowed {
    /// internet, dns, ping, rate
    pub what: &'static str,
    pub detail: String,
}

#[derive(Serialize, Debug)]
pub struct BlockedRow {
    pub net: String,
    /// the section it's listed under: host, lan, routes, tailnet, metadata,
    /// private, vms, config, public_ip, special
    pub group: &'static str,
    /// the reason the connection log gives for it
    pub why: &'static str,
    pub detail: String,
    /// how its section lists it
    #[serde(skip)]
    pub item: String,
}

#[derive(Serialize, Debug, Default)]
pub struct Rules {
    /// the filter is in the kernel. null when that couldn't be checked (not root, macOS)
    pub loaded: Option<bool>,
    /// the loaded blocked set differs from what this config and host give now
    pub stale: Option<bool>,
    /// ranges that should be blocked and aren't, and the other way round
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    /// the VM routing table is in place
    pub routing: Option<bool>,
    /// since the reaper last refreshed the filter
    pub refreshed_secs: Option<u64>,
    /// with --rules: the rules themselves
    pub text: Option<String>,
    /// true when text is what would load, not what's loaded
    pub would_load: bool,
}

#[derive(Serialize, Debug)]
pub struct Explain {
    pub mode: &'static str,
    pub platform: &'static str,
    /// limits.net, the most a run may ask for here
    pub ceiling: &'static str,
    /// burner run would refuse this mode on this host
    pub refused: bool,
    pub uplink: Option<Uplink>,
    pub allowed: Vec<Allowed>,
    pub blocked: Vec<BlockedRow>,
    pub notes: Vec<String>,
    pub rules: Rules,
}

impl Explain {
    /// exit 1 when the filter is known to be missing or stale
    pub fn healthy(&self) -> bool {
        self.rules.loaded != Some(false)
            && self.rules.stale != Some(true)
            && self.rules.routing != Some(false)
    }
}

/// the mode explain talks about: --net, else web lowered to limits.net
pub fn pick_mode(cfg: &Config, net: Option<&str>) -> Result<(Mode, Mode), String> {
    let ceiling = Mode::parse(&cfg.limits.net).unwrap_or(Mode::None);
    let mode = match net {
        Some(n) => Mode::parse(n).ok_or_else(|| format!("--net {n:?}: none, web or open"))?,
        None => Mode::Web.min(ceiling),
    };
    Ok((mode, ceiling))
}

fn mbs(rate: u64) -> String {
    let m = rate as f64 / 1e6;
    if m >= 10.0 {
        format!("{m:.0}")
    } else {
        format!("{m:.1}")
    }
}

/// what a VM may use, in words, the same on both platforms but for what
/// macnet doesn't carry
pub fn allowed(cfg: &Config, mode: Mode, platform: Platform, way: &str) -> Vec<Allowed> {
    let mut out = Vec::new();
    if mode == Mode::None {
        return out;
    }
    let (ports, rate) = match mode {
        Mode::Open => (
            "any tcp port but mail (25, 465, 587)".to_string(),
            "50 new connections a second",
        ),
        _ => ("tcp 80 and 443".to_string(), "20 new connections a second"),
    };
    let udp = match (mode, platform) {
        (Mode::Open, Platform::Linux) => ", udp and other protocols too",
        _ => "",
    };
    out.push(Allowed {
        what: "internet",
        detail: format!("the internet {way}, {ports}{udp}, {rate}"),
    });
    let dns: Vec<String> = cfg.net.resolvers.iter().map(|r| r.to_string()).collect();
    let dns = match dns.len() {
        0 => "no resolvers configured (net.resolvers), so no dns".to_string(),
        _ => format!(
            "dns at {} (udp and tcp 53), 20 queries a second",
            and_list(&dns)
        ),
    };
    out.push(Allowed {
        what: "dns",
        detail: dns,
    });
    match platform {
        Platform::Linux => out.push(Allowed {
            what: "ping",
            detail: "ping to the internet, 5 a second".into(),
        }),
        Platform::Mac => out.push(Allowed {
            what: "ping",
            detail: "no ping, and no udp but dns (macnet carries tcp and dns only)".into(),
        }),
    }
    let rate = match cfg.net.rate {
        0 => "no bandwidth cap (net.rate = 0)".to_string(),
        r => format!("each way at most {} MB/s (net.rate)", mbs(r)),
    };
    out.push(Allowed {
        what: "rate",
        detail: rate,
    });
    out
}

/// a line for each full-tunnel vpn. a default route on a vpn only matters
/// when VM traffic leaves by that interface: on linux the uplink, on a mac
/// (uplink None) whatever the default route is
pub fn tunnel_notes(tunnels: &[net::Tunnel], uplink: Option<&str>) -> Vec<String> {
    tunnels
        .iter()
        .filter(|t| match t {
            net::Tunnel::Default { dev } => uplink.is_none_or(|u| u == dev),
            _ => true,
        })
        .map(|t| net::tunnel_words(t, uplink))
        .collect()
}

/// a line for each of net.resolvers that VMs can't reach
pub fn resolver_notes(cfg: &Config, blocked: &[Blocked], platform: Platform) -> Vec<String> {
    net::blocked_resolvers(cfg, blocked, platform)
        .into_iter()
        .map(|(ip, why)| {
            format!(
                "net.resolvers has {ip}, and VMs can't reach it: {why}. they get no dns from it"
            )
        })
        .collect()
}

fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn cidr(b: &Blocked) -> String {
    format!("{}/{}", b.net, b.prefix)
}

fn is_tailnet(b: &Blocked) -> bool {
    match &b.why {
        Why::HostNet { dev } | Why::HostAddr { dev } | Why::Route { dev, .. } => {
            netmodel::iface_label(dev) == Some("tailnet")
        }
        Why::Special { label } => *label == "cgnat and tailscale",
        _ => false,
    }
}

/// the blocked set sorted into explain's sections. taps and loopback are left
/// out: the VM subnet and the special ranges already say it
pub fn rows(blocked: &[Blocked]) -> Vec<BlockedRow> {
    let mut out: Vec<BlockedRow> = Vec::new();
    for b in blocked {
        let dev = match &b.why {
            Why::HostNet { dev } | Why::HostAddr { dev } | Why::Route { dev, .. } => Some(dev),
            _ => None,
        };
        if dev.is_some_and(|d| net::is_tap(d) || d == "lo" || d == "lo0") {
            continue;
        }
        // a route to a network or address the host is on says nothing new
        let covered = |b: &Blocked| {
            blocked.iter().any(|o| {
                matches!(
                    o.why,
                    Why::HostNet { .. } | Why::HostAddr { .. } | Why::Subnet
                ) && o.prefix <= b.prefix
                    && u32::from(b.net) & crate::config::mask(o.prefix) == u32::from(o.net)
            })
        };
        // nor one inside link-local, multicast or broadcast: the special
        // ranges' lines say those
        let odd = |b: &Blocked| {
            net::special(b.net).is_some_and(|s| s.label != "private range" && s.prefix <= b.prefix)
        };
        if matches!(b.why, Why::Route { .. }) && (covered(b) || odd(b)) {
            continue;
        }
        let label = dev.and_then(|d| netmodel::iface_label(d));
        let with_label = |s: String| match label {
            Some(l) => format!("{s} ({l})"),
            None => s,
        };
        let (group, item) = match &b.why {
            _ if is_tailnet(b) => (
                "tailnet",
                match &b.why {
                    Why::Special { label } => format!("{} ({label})", cidr(b)),
                    Why::HostAddr { dev } => format!("{} ({dev})", b.net),
                    Why::Route { dev, table, .. } if table != "main" => {
                        format!("{} on {dev}, table {table}", cidr(b))
                    }
                    _ => format!("{} on {}", cidr(b), dev.map_or("?", |d| d.as_str())),
                },
            ),
            Why::HostAddr { dev } => ("host", format!("{} ({dev})", b.net)),
            Why::HostNet { dev } if label.is_none() => ("lan", format!("{} on {dev}", cidr(b))),
            Why::HostNet { dev } => ("routes", with_label(format!("{} on {dev}", cidr(b)))),
            Why::Route { dev, via, table } => {
                let via = via.map_or_else(String::new, |v| format!(" via {v}"));
                let table = match table.as_str() {
                    "main" => String::new(),
                    t => format!(", table {t}"),
                };
                (
                    "routes",
                    with_label(format!("{}{via} on {dev}{table}", cidr(b))),
                )
            }
            Why::Subnet => ("vms", cidr(b)),
            Why::Config => ("config", cidr(b)),
            Why::PublicIp => ("public_ip", b.net.to_string()),
            Why::Special { label } if label.starts_with("cloud metadata") => {
                ("metadata", format!("169.254.169.254 (in {})", cidr(b)))
            }
            Why::Special { label } if *label == "private range" => ("private", cidr(b)),
            Why::Special { .. } => ("special", cidr(b)),
        };
        let (reason, detail) = netmodel::describe(b);
        let row = BlockedRow {
            net: cidr(b),
            group,
            why: reason.name(),
            detail,
            item,
        };
        // the same range from two places (an address that's also a /32 route)
        if !out.iter().any(|r| r.net == row.net && r.group == row.group) {
            out.push(row);
        }
    }
    out
}

const SECTIONS: &[(&str, &str)] = &[
    ("host", "this host"),
    ("lan", "lan"),
    ("routes", "routes"),
    ("tailnet", "tailnet"),
    ("metadata", "cloud metadata"),
    ("private", "private ranges"),
    ("vms", "other VMs"),
    ("config", "net.block"),
    ("public_ip", "your public ip"),
    ("ipv6", "ipv6"),
    ("special", "special ranges"),
];

fn section_items(e: &Explain, group: &str) -> Vec<String> {
    e.blocked
        .iter()
        .filter(|r| r.group == group)
        .map(|r| r.item.clone())
        .collect()
}

/// the words, as printed
pub fn render(e: &Explain) -> String {
    let mut s = String::new();
    if e.mode == "none" {
        s += &format!(
            "a VM with --net none on this host ({}) has no network interface at all, only lo\n",
            e.platform
        );
        return s;
    }
    s += &format!(
        "a VM with --net {} on this host ({}) can reach:\n",
        e.mode, e.platform
    );
    for a in &e.allowed {
        s += &format!("  {}\n", a.detail);
    }
    if e.refused {
        s += &format!(
            "  (burner run refuses --net {} here, limits.net is {})\n",
            e.mode, e.ceiling
        );
    }
    s += "\nit can't reach:\n";
    for (group, title) in SECTIONS {
        let items = match *group {
            "ipv6" => vec!["nothing, no ipv6 at all".to_string()],
            "public_ip" if !e.blocked.iter().any(|r| r.group == "public_ip") => {
                match e.notes.iter().find(|n| n.starts_with("your public ip")) {
                    Some(n) => vec![n.trim_start_matches("your public ip ").to_string()],
                    None => continue,
                }
            }
            "config" if !e.blocked.iter().any(|r| r.group == "config") => {
                vec!["(empty)".into()]
            }
            g => section_items(e, g),
        };
        if items.is_empty() {
            continue;
        }
        s += &format!("  {title:<18} {}\n", items.join(", "));
    }
    for n in e.notes.iter().filter(|n| !n.starts_with("your public ip")) {
        s += &format!("\n{n}\n");
    }
    s += "\n";
    match (e.rules.loaded, e.rules.stale) {
        (Some(false), _) => s += "filter: not loaded, run burner net up\n",
        (Some(true), Some(true)) => {
            s += "filter: loaded but stale, the reaper's refresh isn't keeping up (journalctl -t burner)\n";
            if !e.rules.missing.is_empty() {
                s += &format!("  not blocked yet: {}\n", e.rules.missing.join(", "));
            }
            if !e.rules.extra.is_empty() {
                s += &format!(
                    "  blocked, no longer needed: {}\n",
                    e.rules.extra.join(", ")
                );
            }
        }
        (Some(true), _) => {
            let age = e
                .rules
                .refreshed_secs
                .map_or_else(String::new, |a| format!(", refreshed {a}s ago"));
            s += &format!("filter: loaded, matches this config{age}\n");
        }
        (None, _) if e.platform == "linux" => {
            s += "filter: not checked without root, this is what burner net up would load\n"
        }
        (None, _) => {}
    }
    let rules_title = if e.platform == "macos" {
        "macnet's policy"
    } else if e.rules.would_load {
        "rules (what would load)"
    } else {
        "rules (loaded)"
    };
    if e.rules.routing == Some(false) {
        s += "routing: the VM routing table is missing, run burner net up\n";
    }
    match &e.rules.text {
        Some(t) => {
            if !s.ends_with("\n\n") {
                s.push('\n');
            }
            s += &format!("{rules_title}:\n{t}");
            if !t.ends_with('\n') {
                s.push('\n');
            }
        }
        None => s += "rules: burner explain --rules\n",
    }
    s
}

/// an ipv4 interval set, for comparing the loaded set with a fresh one
fn intervals(cidrs: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut v = cidrs.to_vec();
    v.sort();
    let mut out: Vec<(u32, u32)> = Vec::new();
    for (a, b) in v {
        match out.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

fn cidr_range(s: &str) -> Option<(u32, u32)> {
    let (ip, p) = match s.split_once('/') {
        Some((ip, p)) => (ip.parse::<Ipv4Addr>().ok()?, p.parse::<u8>().ok()?),
        None => (s.parse().ok()?, 32),
    };
    if p > 32 {
        return None;
    }
    let m = crate::config::mask(p);
    let n = u32::from(ip) & m;
    Some((n, n | !m))
}

/// the elements of `nft -j list set`, as ranges. None if it can't be read
pub fn parse_nft_set(json: &[u8]) -> Option<Vec<(u32, u32)>> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let set = v["nftables"]
        .as_array()?
        .iter()
        .find_map(|o| o.get("set"))?;
    let mut out = Vec::new();
    for e in set["elem"].as_array().into_iter().flatten() {
        let e = e.get("elem").and_then(|x| x.get("val")).unwrap_or(e);
        let r = if let Some(s) = e.as_str() {
            cidr_range(s)?
        } else if let Some(p) = e.get("prefix") {
            cidr_range(&format!("{}/{}", p["addr"].as_str()?, p["len"].as_u64()?))?
        } else {
            let r = e.get("range")?.as_array()?;
            let a: Ipv4Addr = r.first()?.as_str()?.parse().ok()?;
            let b: Ipv4Addr = r.get(1)?.as_str()?.parse().ok()?;
            (u32::from(a), u32::from(b))
        };
        out.push(r);
    }
    Some(intervals(&out))
}

fn show_range((a, b): (u32, u32)) -> String {
    // a range that is one cidr reads as one
    let size = u64::from(b) - u64::from(a) + 1;
    if size.is_power_of_two() && u64::from(a) % size == 0 {
        let p = 32 - size.trailing_zeros();
        return format!("{}/{p}", Ipv4Addr::from(a));
    }
    format!("{}-{}", Ipv4Addr::from(a), Ipv4Addr::from(b))
}

/// the parts of `want` not covered by `have`
fn uncovered(want: &[(u32, u32)], have: &[(u32, u32)]) -> Vec<String> {
    let mut out = Vec::new();
    for &(a, b) in want {
        let mut cur = u64::from(a);
        let end = u64::from(b);
        for &(ha, hb) in have {
            let (ha, hb) = (u64::from(ha), u64::from(hb));
            if hb < cur || ha > end {
                continue;
            }
            if ha > cur {
                out.push(show_range((cur as u32, (ha - 1) as u32)));
            }
            cur = hb + 1;
            if cur > end {
                break;
            }
        }
        if cur <= end {
            out.push(show_range((cur as u32, end as u32)));
        }
    }
    out
}

/// compare the loaded blocked set with what the config and host give now
pub fn compare(loaded: &[(u32, u32)], fresh: &[String]) -> (Vec<String>, Vec<String>) {
    let fresh: Vec<(u32, u32)> = intervals(
        &fresh
            .iter()
            .filter_map(|c| cidr_range(c))
            .collect::<Vec<_>>(),
    );
    (uncovered(&fresh, loaded), uncovered(loaded, &fresh))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;
    use std::time::Duration;

    fn nft(args: &[&str]) -> Option<Vec<u8>> {
        let out = crate::sys::run_timeout(
            Command::new("nft").args(args),
            None,
            Duration::from_secs(30),
        )
        .ok()?;
        out.status.success().then_some(out.stdout)
    }

    fn uplink(cfg: &Config) -> Option<Uplink> {
        let dev = cfg.uplink().ok()?;
        let addrs = crate::config::iface_addrs(&dev).unwrap_or_default();
        let gateway = net::default_gateway(&dev);
        Some(Uplink {
            dev,
            gateway,
            addrs,
        })
    }

    pub fn build(cfg: &Config, a: &ExplainArgs) -> anyhow::Result<Explain> {
        let (mode, ceiling) = pick_mode(cfg, a.net.as_deref()).map_err(anyhow::Error::msg)?;
        let up = uplink(cfg);
        let way = match &up {
            Some(Uplink {
                dev,
                gateway: Some(g),
                ..
            }) => format!("through {dev} (default route via {g})"),
            Some(u) => format!("through {}", u.dev),
            None => "through the default route".into(),
        };
        let sources = net::blocked_sources(cfg)?;
        let mut notes = Vec::new();
        if !sources.iter().any(|b| b.why == Why::PublicIp) {
            let public_uplink = up.as_ref().is_some_and(|u| {
                !u.addrs.is_empty() && u.addrs.iter().all(|ip| net::plausible_public(*ip))
            });
            notes.push(if public_uplink {
                "your public ip not blocked: this host has a public address of its own, and that's blocked as a host address".into()
            } else if cfg.net.block_public_ip && !crate::sys::is_root() {
                "your public ip blocked by net.block_public_ip, the address it found is only readable as root (sudo burner explain)".into()
            } else if cfg.net.block_public_ip {
                "your public ip not looked up yet, so runs with a network are refused until the reaper finds it".into()
            } else {
                "your public ip NOT blocked: this host looks NATed, and VMs can reach your router's public address (often its admin page or your port forwards). set net.block_public_ip = true".into()
            });
        }
        notes.push(
            "VM packets use their own routing table (29217) holding only the default route,\nso a VPN or tailnet that comes up later never applies to them."
                .into(),
        );
        let dev = up.as_ref().map(|u| u.dev.as_str());
        notes.extend(tunnel_notes(&net::tunnels_here(), dev));
        notes.extend(resolver_notes(cfg, &sources, Platform::Linux));
        let mut rules = Rules::default();
        if crate::sys::is_root() {
            let loaded = net::table_exists();
            rules.loaded = Some(loaded);
            rules.routing = Some(net::routing_ok(cfg));
            if loaded {
                let fresh = net::blocked(cfg)?;
                match nft(&["-j", "list", "set", "inet", net::TABLE, "blocked4"])
                    .as_deref()
                    .and_then(parse_nft_set)
                {
                    Some(have) => {
                        let (missing, extra) = compare(&have, &fresh);
                        rules.stale = Some(!missing.is_empty() || !extra.is_empty());
                        rules.missing = missing;
                        rules.extra = extra;
                    }
                    None => rules.stale = Some(true),
                }
                rules.refreshed_secs = crate::run::reaper_age(cfg).map(|d| d.as_secs());
                if let Some((was, now)) = net::uplink_moved(cfg) {
                    rules.stale = Some(true);
                    notes.push(format!(
                        "the loaded filter sends VM traffic out {was}, and the default route is on {now} now:\nVMs have no way out until the reaper reloads it (within 30s) or burner net up does"
                    ));
                }
            }
            if a.rules && loaded {
                let mut t = String::new();
                for (fam, table) in [("inet", net::TABLE), ("ip", net::NAT_TABLE)] {
                    if let Some(out) = nft(&["list", "table", fam, table]) {
                        t += &String::from_utf8_lossy(&out);
                    }
                }
                rules.text = Some(t);
            }
        }
        if a.rules && rules.text.is_none() {
            rules.text = Some(net::ruleset(cfg)?);
            rules.would_load = true;
        }
        Ok(Explain {
            mode: mode.name(),
            platform: "linux",
            ceiling: ceiling.name(),
            refused: mode > ceiling,
            uplink: up,
            allowed: allowed(cfg, mode, Platform::Linux, &way),
            blocked: rows(&sources),
            notes,
            rules,
        })
    }
}

#[cfg(target_os = "linux")]
pub use linux::build;

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use crate::macnet::policy::host_addrs;
    use crate::macnet::route::{self, Gateway};

    /// what macnet refuses, from the same places it reads: the mac's
    /// addresses, the special ranges, net.block, the public address and every
    /// route that isn't the default way out
    pub fn sources(cfg: &Config) -> anyhow::Result<Vec<Blocked>> {
        let mut out = Vec::new();
        let mut add = |net: Ipv4Addr, prefix: u8, why: Why| {
            let net = Ipv4Addr::from(u32::from(net) & crate::config::mask(prefix));
            out.push(Blocked { net, prefix, why });
        };
        for s in net::SPECIAL {
            add(s.net, s.prefix, Why::Special { label: s.label });
        }
        for b in &cfg.net.block {
            let (n, p) = crate::config::parse_cidr(b)?;
            add(n, p, Why::Config);
        }
        let (sub, sp) = cfg.subnet()?;
        add(sub, sp, Why::Subnet);
        if let Some((ip, _)) = net::public_ip(cfg) {
            add(ip, 32, Why::PublicIp);
        }
        let addrs =
            host_addrs().ok_or_else(|| anyhow::anyhow!("can't read the mac's addresses"))?;
        for a in addrs {
            add(a.ip, 32, Why::HostAddr { dev: a.dev.clone() });
            if let Some(p) = a.prefix {
                add(a.ip, p, Why::HostNet { dev: a.dev.clone() });
            }
            if let Some(peer) = a.peer {
                add(peer, 32, Why::HostAddr { dev: a.dev.clone() });
            }
        }
        for (r, dev) in route::dump()? {
            let via = match r.gateway {
                Gateway::Inet(g) => Some(g),
                Gateway::Link => None,
            };
            add(
                r.dst,
                r.prefix,
                Why::Route {
                    dev,
                    via,
                    table: "main".into(),
                },
            );
        }
        Ok(out)
    }

    /// the default route's interface, its gateway and its addresses
    pub fn uplink() -> Option<Uplink> {
        let d = route::lookup(Ipv4Addr::UNSPECIFIED, true).ok()?;
        let addrs = host_addrs()?;
        let mut name = None;
        let mut ips = Vec::new();
        for a in addrs {
            // SAFETY: if_nametoindex reads a NUL-terminated name we made
            let c = std::ffi::CString::new(a.dev.clone()).ok()?;
            if unsafe { libc::if_nametoindex(c.as_ptr()) } == u32::from(d.index) {
                ips.push(a.ip);
                name = Some(a.dev);
            }
        }
        Some(Uplink {
            dev: name?,
            gateway: match d.gateway {
                Gateway::Inet(g) => Some(g),
                Gateway::Link => None,
            },
            addrs: ips,
        })
    }

    /// macnet's checks in the order it makes them, with this config's values
    pub fn policy_words(cfg: &Config, mode: Mode) -> String {
        let resolvers: Vec<String> = cfg.net.resolvers.iter().map(|r| r.to_string()).collect();
        let (ports, meter) = match mode {
            Mode::Open => ("any tcp port but 25, 465 and 587", "50 a second, burst 100"),
            _ => ("tcp 80 and 443", "20 a second, burst 40"),
        };
        let rate = match cfg.net.rate {
            0 => "no cap".to_string(),
            r => format!("{r} bytes a second each way"),
        };
        format!(
            "burner macnet, one process per VM, checks each guest packet in this order:\n\
             1. dropped: anything not from the guest's own address, ipv6, fragments, icmp, udp that isn't to port 53\n\
             2. refused: one of this mac's addresses or the networks it's on, read fresh for every connection\n\
             3. refused: the special ranges, net.block, net.block_public_ip, the VM's own network\n\
             4. refused: anything the mac doesn't route through its default route (a vpn, a tailnet, a lan route).\n\
             \x20  what's left is connected bound to the default route's interface\n\
             5. port 53 (udp and tcp): only to {}\n\
             6. {ports}\n\
             7. meters: new connections {meter}, dns 20 a second burst 50, at most 256 connections\n\
             \x20  and 64 dns flows open, bandwidth {rate} (net.rate)\n",
            and_list(&resolvers)
        )
    }

    pub fn build(cfg: &Config, a: &ExplainArgs) -> anyhow::Result<Explain> {
        let (mode, ceiling) = pick_mode(cfg, a.net.as_deref()).map_err(anyhow::Error::msg)?;
        let up = uplink();
        let way = match &up {
            Some(Uplink {
                dev,
                gateway: Some(g),
                ..
            }) => format!("through {dev} (default route via {g})"),
            Some(u) => format!("through {}", u.dev),
            None => "through the default route (there's none right now)".into(),
        };
        let sources = sources(cfg)?;
        let mut notes = Vec::new();
        if !sources.iter().any(|b| b.why == Why::PublicIp) {
            notes.push(if cfg.net.block_public_ip {
                "your public ip not looked up for this network yet: burner run looks it up first".into()
            } else {
                "your public ip NOT blocked: VMs can reach your router's public address (often its admin page or your port forwards). set net.block_public_ip = true".into()
            });
        }
        notes.push(
            "each VM's network is its own macnet process. it reads the mac's addresses and routes\nfor every connection, so a vpn that comes up later is refused too."
                .into(),
        );
        notes.extend(tunnel_notes(&route::tunnels_here(), None));
        notes.extend(resolver_notes(cfg, &sources, Platform::Mac));
        let rules = Rules {
            text: a.rules.then(|| policy_words(cfg, mode)),
            ..Rules::default()
        };
        Ok(Explain {
            mode: mode.name(),
            platform: "macos",
            ceiling: ceiling.name(),
            refused: mode > ceiling,
            uplink: up,
            allowed: allowed(cfg, mode, Platform::Mac, &way),
            blocked: rows(&sources),
            notes,
            rules,
        })
    }
}

#[cfg(target_os = "macos")]
pub use mac::{build, sources as mac_sources, uplink as mac_uplink};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{parse_addrs, parse_routes, sources_from};

    fn homelab() -> Explain {
        let mut cfg = Config::default();
        cfg.net.block = vec!["140.82.121.0/24".into()];
        let b = sources_from(
            &cfg,
            None,
            &parse_addrs(net::tests::HOMELAB_ADDRS.as_bytes()).unwrap(),
            &parse_routes(net::tests::HOMELAB_ROUTES.as_bytes(), "eth0").unwrap(),
        )
        .unwrap();
        Explain {
            mode: "web",
            platform: "linux",
            ceiling: "web",
            refused: false,
            uplink: None,
            allowed: allowed(
                &cfg,
                Mode::Web,
                Platform::Linux,
                "through eth0 (default route via 192.168.1.1)",
            ),
            blocked: rows(&b),
            notes: vec!["your public ip NOT blocked: this host looks NATed".into()],
            rules: Rules {
                loaded: Some(true),
                stale: Some(false),
                refreshed_secs: Some(12),
                ..Rules::default()
            },
        }
    }

    #[test]
    fn words() {
        let t = render(&homelab());
        for want in [
            "a VM with --net web on this host (linux) can reach:",
            "  the internet through eth0 (default route via 192.168.1.1), tcp 80 and 443, 20 new connections a second\n",
            "  dns at 9.9.9.9 and 1.1.1.1 (udp and tcp 53), 20 queries a second\n",
            "  this host          192.168.1.20 (eth0), 10.1.0.5 (wg0), 172.17.0.1 (docker0)\n",
            "  lan                192.168.1.0/24 on eth0\n",
            "  tailnet            100.64.0.0/10 (cgnat and tailscale), 100.101.102.103 (tailscale0), 203.0.114.0/24 on tailscale0, table 52\n",
            "  routes             10.1.0.0/16 on wg0 (wireguard), 172.17.0.0/16 on docker0 (docker), 172.16.98.0/30 via 10.1.0.1 on wg0 (wireguard)\n",
            "  cloud metadata     169.254.169.254 (in 169.254.0.0/16)\n",
            "  other VMs          172.29.217.0/24\n",
            "  net.block          140.82.121.0/24\n",
            "  your public ip     NOT blocked: this host looks NATed\n",
            "  ipv6               nothing, no ipv6 at all\n",
            "filter: loaded, matches this config, refreshed 12s ago\n",
        ] {
            assert!(t.contains(want), "missing {want:?} in\n{t}");
        }
        assert!(t.contains("10.1.0.0/16 on wg0 (wireguard)"), "{t}");
        assert!(
            t.contains("172.16.98.0/30 via 10.1.0.1 on wg0 (wireguard)"),
            "{t}"
        );
        assert!(t.contains("172.17.0.0/16 on docker0 (docker)"), "{t}");
        assert!(!t.contains("bn0"), "taps are the VM subnet's line: {t}");
    }

    #[test]
    fn stale_and_missing() {
        let mut e = homelab();
        e.rules.stale = Some(true);
        e.rules.missing = vec!["10.9.0.0/16".into()];
        assert!(!e.healthy());
        assert!(render(&e).contains("not blocked yet: 10.9.0.0/16"));
        e.rules = Rules {
            loaded: Some(false),
            ..Rules::default()
        };
        assert!(!e.healthy());
        assert!(render(&e).contains("filter: not loaded, run burner net up"));
        e.rules = Rules::default();
        assert!(e.healthy(), "not checked isn't a failure");
    }

    #[test]
    fn set_comparison() {
        let set = br#"{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"blocked4","table":"burner",
            "type":"ipv4_addr","flags":["interval"],"elem":[{"prefix":{"addr":"10.0.0.0","len":8}},
            "74.208.113.109",{"range":["172.16.0.0","172.31.255.255"]}]}}]}"#;
        let have = parse_nft_set(set).unwrap();
        let (missing, extra) = compare(
            &have,
            &[
                "10.0.0.0/8".into(),
                "74.208.113.109/32".into(),
                "172.16.0.0/12".into(),
            ],
        );
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{missing:?} {extra:?}"
        );
        let (missing, extra) = compare(&have, &["10.0.0.0/8".into(), "192.168.0.0/16".into()]);
        assert_eq!(missing, vec!["192.168.0.0/16"]);
        assert_eq!(extra, vec!["74.208.113.109/32", "172.16.0.0/12"]);
        assert!(parse_nft_set(b"{}").is_none());
        // adjacent ranges auto-merge in the kernel, and still compare equal
        let (m, x) = compare(
            &intervals(&[(0x0a000000, 0x0bffffff)]),
            &["10.0.0.0/8".into(), "11.0.0.0/8".into()],
        );
        assert!(m.is_empty() && x.is_empty());
    }

    #[test]
    fn modes() {
        let mut cfg = Config::default();
        cfg.limits.net = "web".into();
        assert_eq!(pick_mode(&cfg, None).unwrap(), (Mode::Web, Mode::Web));
        assert_eq!(pick_mode(&cfg, Some("open")).unwrap().0, Mode::Open);
        cfg.limits.net = "none".into();
        assert_eq!(pick_mode(&cfg, None).unwrap().0, Mode::None);
        assert!(pick_mode(&cfg, Some("lan")).is_err());
        let a = allowed(&cfg, Mode::Open, Platform::Linux, "out");
        assert!(a[0].detail.contains("any tcp port but mail"));
        let a = allowed(&cfg, Mode::Web, Platform::Mac, "out");
        assert!(a.iter().any(|x| x.detail.starts_with("no ping")));
    }

    #[test]
    fn rules_through_sudo() {
        let a = |net: Option<&str>, rules: bool| ExplainArgs {
            net: net.map(str::to_string),
            rules,
        };
        let linux = cfg!(target_os = "linux");
        assert_eq!(a(None, true).refused_for(Some("1000")).is_some(), linux);
        assert_eq!(
            a(Some("open"), true).refused_for(Some("")).is_some(),
            linux,
            "a SUDO_UID that isn't a number isn't root"
        );
        assert!(
            a(None, true).refused_for(Some("0")).is_none(),
            "root's own sudo"
        );
        assert!(
            a(None, true).refused_for(None).is_none(),
            "not through sudo"
        );
        assert!(a(None, false).refused_for(Some("1000")).is_none());
        assert!(a(Some("web"), false).refused_for(Some("1000")).is_none());
    }

    #[test]
    fn vpn_and_resolver_notes() {
        use crate::net::Tunnel;
        let t = vec![
            Tunnel::Default { dev: "tun0".into() },
            Tunnel::Policy {
                dev: "wg0".into(),
                table: "51820".into(),
            },
        ];
        // linux: a default route on a vpn that isn't the uplink says nothing
        let n = tunnel_notes(&t, Some("eth0"));
        assert_eq!(n.len(), 1);
        assert!(
            n[0].contains("VM traffic leaves outside the vpn, through eth0"),
            "{n:?}"
        );
        assert_eq!(tunnel_notes(&t, Some("tun0")).len(), 2);
        // a mac: the default route is the way out, whatever it's on
        assert_eq!(tunnel_notes(&t, None).len(), 2);
        let mut cfg = Config::default();
        cfg.net.resolvers = vec![Ipv4Addr::new(192, 168, 1, 53)];
        let b = sources_from(
            &cfg,
            None,
            &parse_addrs(net::tests::HOMELAB_ADDRS.as_bytes()).unwrap(),
            &parse_routes(net::tests::HOMELAB_ROUTES.as_bytes(), "eth0").unwrap(),
        )
        .unwrap();
        let n = resolver_notes(&cfg, &b, Platform::Linux);
        assert_eq!(n.len(), 1);
        assert!(
            n[0].starts_with("net.resolvers has 192.168.1.53, and VMs can't reach it: your lan"),
            "{n:?}"
        );
    }
}
