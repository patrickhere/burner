//! the VM network: every VM gets a tap and its own /30 out of net.subnet, and
//! one nft table lets those taps reach the internet through the uplink and
//! nothing else (not the LAN, not the host, not each other).
//! on macOS only the modes, slots and public address lookup are used here: the
//! filter itself is burner macnet, one process per VM (src/macnet)
#![cfg_attr(target_os = "macos", allow(dead_code))]

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::cgroup;
use crate::config::{self, Config};
use crate::ledger::Ledger;
use crate::sys;

pub const TABLE: &str = "burner";
pub const NAT_TABLE: &str = "burner_nat";
const TAP_PREFIX: &str = "bn";
const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const FORWARD_MARK: &str = "forwarding-turned-on";
const PUBLIC_IP: &str = "public-ip";
const PUBLIC_IP_EVERY: Duration = Duration::from_secs(600);
const PUBLIC_IP_URLS: [&str; 2] = ["https://ipv4.icanhazip.com", "https://api.ipify.org"];

fn helper(prog: &str, args: &[&str], input: Option<&[u8]>) -> Result<std::process::Output> {
    sys::run_timeout(Command::new(prog).args(args), input, HELPER_TIMEOUT)
        .with_context(|| format!("running {prog}"))
}

/// ordered from least to most reach, so a config ceiling can compare them
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Mode {
    None,
    Web,
    Open,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "none" => Some(Mode::None),
            "web" => Some(Mode::Web),
            "open" => Some(Mode::Open),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::None => "none",
            Mode::Web => "web",
            Mode::Open => "open",
        }
    }
}

pub struct Slot {
    pub tap: String,
    pub host: Ipv4Addr,
    pub guest: Ipv4Addr,
}

pub fn slot(cfg: &Config, i: u32) -> Result<Slot> {
    let (base, _) = cfg.subnet()?;
    if i >= cfg.net_slots()? {
        bail!("network slot {i} is outside net.subnet");
    }
    let b = u32::from(base) + 4 * i;
    Ok(Slot {
        tap: format!("{TAP_PREFIX}{i}"),
        host: (b + 1).into(),
        guest: (b + 2).into(),
    })
}

/// a range that's never reachable, on any network, and what it is
pub struct Special {
    pub net: Ipv4Addr,
    pub prefix: u8,
    pub label: &'static str,
}

const fn sp(a: u8, b: u8, prefix: u8, label: &'static str) -> Special {
    Special {
        net: Ipv4Addr::new(a, b, 0, 0),
        prefix,
        label,
    }
}

/// always blocked, on any network. the linux filter and macnet's policy both
/// read this one list
pub const SPECIAL: &[Special] = &[
    sp(0, 0, 8, "this network (0/8)"),
    sp(10, 0, 8, "private range"),
    sp(100, 64, 10, "cgnat and tailscale"),
    sp(127, 0, 8, "loopback"),
    sp(169, 254, 16, "cloud metadata and link-local"),
    sp(172, 16, 12, "private range"),
    Special {
        net: Ipv4Addr::new(192, 0, 0, 0),
        prefix: 24,
        label: "ietf protocol assignments",
    },
    Special {
        net: Ipv4Addr::new(192, 0, 2, 0),
        prefix: 24,
        label: "documentation",
    },
    sp(192, 168, 16, "private range"),
    sp(198, 18, 15, "benchmarking"),
    Special {
        net: Ipv4Addr::new(198, 51, 100, 0),
        prefix: 24,
        label: "documentation",
    },
    Special {
        net: Ipv4Addr::new(203, 0, 113, 0),
        prefix: 24,
        label: "documentation",
    },
    sp(224, 0, 4, "multicast"),
    sp(240, 0, 4, "reserved and broadcast"),
];

/// the special range dst is in, if any
pub fn special(dst: Ipv4Addr) -> Option<&'static Special> {
    SPECIAL
        .iter()
        .find(|s| u32::from(dst) & config::mask(s.prefix) == u32::from(s.net))
}

/// why a range is in the blocked set, for explain and the connection log
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum Why {
    /// one of the ranges that are never reachable on any network
    Special { label: &'static str },
    /// net.block
    Config,
    /// the VMs' own subnet
    Subnet,
    /// net.block_public_ip
    PublicIp,
    /// an address of this host, on dev
    HostAddr { dev: String },
    /// a network this host is attached to, on dev
    HostNet { dev: String },
    /// a route that isn't the default one
    Route {
        dev: String,
        via: Option<Ipv4Addr>,
        table: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Blocked {
    pub net: Ipv4Addr,
    pub prefix: u8,
    #[serde(flatten)]
    pub why: Why,
}

/// an address on one of the host's interfaces
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub dev: String,
}

/// a route from `ip route show table all`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub dst: Ipv4Addr,
    pub prefix: u8,
    pub dev: String,
    pub via: Option<Ipv4Addr>,
    /// main, local, or a number
    pub table: String,
}

/// everything a VM must never reach: the special ranges, every address and
/// attached network on the host, every route that isn't the default one (a LAN
/// on public addresses, a vpn, a docker network), the VM subnet and net.block.
/// what's left is the internet through the default route
pub fn blocked(cfg: &Config) -> Result<Vec<String>> {
    Ok(collapse(
        blocked_sources(cfg)?
            .iter()
            .map(|b| (u32::from(b.net) & config::mask(b.prefix), b.prefix))
            .collect(),
    ))
}

/// blocked(), with where each range comes from
pub fn blocked_sources(cfg: &Config) -> Result<Vec<Blocked>> {
    let public = public_ip(cfg).map(|(ip, _)| ip);
    sources_from(cfg, public, &local_addrs()?, &route_dsts(&cfg.uplink()?)?)
}

/// the pure half of blocked_sources, for tests on fixtures
pub fn sources_from(
    cfg: &Config,
    public: Option<Ipv4Addr>,
    addrs: &[Addr],
    routes: &[Route],
) -> Result<Vec<Blocked>> {
    let mut out = Vec::new();
    let mut add = |(net, prefix): (Ipv4Addr, u8), why: Why| {
        let net = Ipv4Addr::from(u32::from(net) & config::mask(prefix));
        out.push(Blocked { net, prefix, why });
    };
    for s in SPECIAL {
        add((s.net, s.prefix), Why::Special { label: s.label });
    }
    for s in &cfg.net.block {
        add(
            config::parse_cidr(s).with_context(|| format!("net.block {s:?}"))?,
            Why::Config,
        );
    }
    add(cfg.subnet()?, Why::Subnet);
    if let Some(ip) = public {
        add((ip, 32), Why::PublicIp);
    }
    for a in addrs {
        let dev = a.dev.clone();
        add((a.ip, 32), Why::HostAddr { dev: dev.clone() });
        add((a.ip, a.prefix), Why::HostNet { dev });
    }
    for r in routes.iter().filter(|r| r.prefix > 0) {
        add(
            (r.dst, r.prefix),
            Why::Route {
                dev: r.dev.clone(),
                via: r.via,
                table: r.table.clone(),
            },
        );
    }
    Ok(out)
}

/// drop entries covered by a wider one, so nft gets no overlapping intervals
fn collapse(mut nets: Vec<(u32, u8)>) -> Vec<String> {
    nets.sort_by_key(|&(n, p)| (p, n));
    nets.dedup();
    let mut out: Vec<(u32, u8)> = Vec::new();
    for (n, p) in nets {
        if !out
            .iter()
            .any(|&(on, op)| op <= p && n & config::mask(op) == on)
        {
            out.push((n, p));
        }
    }
    out.sort();
    out.iter()
        .map(|&(n, p)| format!("{}/{p}", Ipv4Addr::from(n)))
        .collect()
}

fn local_addrs() -> Result<Vec<Addr>> {
    let out = helper("ip", &["-j", "-4", "addr", "show"], None)?;
    if !out.status.success() {
        bail!("ip addr show failed");
    }
    parse_addrs(&out.stdout)
}

/// `ip -j -4 addr show`: every address with its prefix and interface
pub fn parse_addrs(json: &[u8]) -> Result<Vec<Addr>> {
    let v: serde_json::Value = serde_json::from_slice(json)?;
    let mut addrs = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        let dev = link["ifname"].as_str().unwrap_or("?").to_string();
        for a in link["addr_info"].as_array().into_iter().flatten() {
            let ip = a["local"].as_str().and_then(|s| s.parse().ok());
            let prefix = a["prefixlen"].as_u64().map(|p| p.min(32) as u8);
            if let (Some(ip), Some(prefix)) = (ip, prefix) {
                addrs.push(Addr {
                    ip,
                    prefix,
                    dev: dev.clone(),
                });
            }
        }
    }
    Ok(addrs)
}

/// destinations of every route except the default ones, and except routes that
/// go out the uplink through the default gateway: those reach the same place
/// the default route does. dhcp clients add such routes for the dns servers
/// they hand out (systemd-networkd does by default), and blocking them would
/// block public resolvers like 1.1.1.1
fn route_dsts(uplink: &str) -> Result<Vec<Route>> {
    let out = helper("ip", &["-j", "-4", "route", "show", "table", "all"], None)?;
    if !out.status.success() {
        bail!("ip route show failed");
    }
    parse_routes(&out.stdout, uplink)
}

/// the pure half of route_dsts. a route list we can't read must not shrink
/// the blocked set, so that's an error
pub fn parse_routes(json: &[u8], uplink: &str) -> Result<Vec<Route>> {
    let v: serde_json::Value = serde_json::from_slice(json).context("reading ip route")?;
    let routes = v.as_array().cloned().unwrap_or_default();
    let gateways: Vec<&str> = routes
        .iter()
        .filter(|r| r["dst"] == "default" && r["dev"] == uplink)
        .filter_map(|r| r["gateway"].as_str())
        .collect();
    Ok(routes
        .iter()
        .filter(|r| {
            !(r["dev"] == uplink && r["gateway"].as_str().is_some_and(|g| gateways.contains(&g)))
        })
        .filter_map(|r| {
            let dst = r["dst"].as_str()?;
            let (ip, p) = match dst.split_once('/') {
                Some((ip, p)) => (ip.parse().ok()?, p.parse().ok().filter(|&p: &u8| p <= 32)?),
                None if dst == "default" => return None,
                None => (dst.parse().ok()?, 32),
            };
            Some(Route {
                dst: ip,
                prefix: p,
                dev: r["dev"].as_str().unwrap_or("?").to_string(),
                via: r["gateway"].as_str().and_then(|g| g.parse().ok()),
                table: match &r["table"] {
                    serde_json::Value::String(t) => t.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => "main".into(),
                },
            })
        })
        .collect())
}

#[derive(serde::Serialize)]
pub struct ShowResult {
    pub table: String,
    pub ruleset: String,
}

#[derive(serde::Serialize)]
pub struct UpResult {
    pub notes: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct DownResult {
    pub stopped_vms: usize,
}

/// the full nft ruleset for this config
pub fn ruleset(cfg: &Config) -> Result<String> {
    Ok(ruleset_for(cfg, &cfg.uplink()?, &blocked(cfg)?))
}

/// the pure half of ruleset
fn ruleset_for(cfg: &Config, uplink: &str, blocked: &[String]) -> String {
    let blocked = blocked.join(", ");
    let resolvers = cfg
        .net
        .resolvers
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let subnet = &cfg.net.subnet;
    let t = TAP_PREFIX;
    format!(
        r#"table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
    set blocked4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {blocked} }} }}
    set resolvers {{ type ipv4_addr; elements = {{ {resolvers} }} }}
    set mode_web {{ type ifname; }}
    set mode_open {{ type ifname; }}
    set tap_ip {{ type ifname . ipv4_addr; }}

    # the connection log: per tap, a jump into chains that only log and
    # return. a tap with no element here just isn't logged
    map log_try {{ type ifname : verdict; }}
    map log_up {{ type ifname : verdict; }}
    map log_down {{ type ifname : verdict; }}

    # before defrag and conntrack (-400): spoofed, fragmented or flooding guest
    # packets never reach shared state on the host
    chain ingress {{
        type filter hook prerouting priority -450; policy accept;
        iifname "{t}*" meta nfproto ipv6 drop
        iifname "{t}*" iifname . ip saddr != @tap_ip drop
        iifname "{t}*" ip frag-off & 0x3fff != 0 drop
        iifname "{t}*" meter {TABLE}_pps {{ iifname limit rate over 3000/second burst 6000 packets }} drop
    }}

    chain input {{
        type filter hook input priority filter - 10; policy accept;
        iifname "{t}*" ct state new iifname vmap @log_try
        iifname "{t}*" drop
    }}

    chain forward {{
        type filter hook forward priority filter - 10; policy accept;
        iifname "{t}*" ct state new iifname vmap @log_try
        iifname "{t}*" meta nfproto ipv6 drop
        oifname "{t}*" meta nfproto ipv6 drop
        iifname "{t}*" iifname . ip saddr != @tap_ip drop
        iifname "{t}*" oifname != "{uplink}" drop
        iifname "{t}*" ip daddr @blocked4 drop
        iifname "{t}*" ct state established,related accept
        iifname @mode_web meta l4proto {{ tcp, udp }} th dport 53 ip daddr @resolvers meter {TABLE}_dns_web {{ iifname limit rate 20/second burst 50 packets }} accept
        iifname @mode_open meta l4proto {{ tcp, udp }} th dport 53 ip daddr @resolvers meter {TABLE}_dns_open {{ iifname limit rate 20/second burst 50 packets }} accept
        iifname "{t}*" meta l4proto {{ tcp, udp }} th dport 53 drop
        iifname @mode_web icmp type echo-request meter {TABLE}_ping_web {{ iifname limit rate 5/second burst 10 packets }} accept
        iifname @mode_open icmp type echo-request meter {TABLE}_ping_open {{ iifname limit rate 5/second burst 10 packets }} accept
        iifname @mode_web tcp dport {{ 80, 443 }} ct state new meter {TABLE}_web {{ iifname limit rate 20/second burst 40 packets }} accept
        iifname @mode_open tcp dport {{ 25, 465, 587 }} drop
        iifname @mode_open ct state new meter {TABLE}_open {{ iifname limit rate 50/second burst 100 packets }} accept
        iifname "{t}*" drop
        oifname "{t}*" ct state established,related accept
        oifname "{t}*" drop
    }}

    # after forward: an accept there doesn't stop this chain, a drop does, so
    # it only ever sees what burner let through. it logs and never decides:
    # its returns end it like its accept policy would
    chain log_after {{
        type filter hook forward priority filter - 9; policy accept;
        iifname "{t}*" udp dport 53 iifname vmap @log_up
        iifname "{t}*" udp dport 53 return
        iifname "{t}*" ct state new iifname vmap @log_up
        oifname "{t}*" udp sport 53 oifname vmap @log_down
        oifname "{t}*" udp sport 53 return
        oifname "{t}*" ct direction reply ct status & assured == 0 oifname vmap @log_down
    }}
}}

table ip {NAT_TABLE}
delete table ip {NAT_TABLE}
table ip {NAT_TABLE} {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {subnet} oifname "{uplink}" masquerade
    }}
}}
"#
    )
}

fn nft(script: &str, check: bool) -> Result<()> {
    let args: &[&str] = if check {
        &["-c", "-f", "-"]
    } else {
        &["-f", "-"]
    };
    let out = helper("nft", args, Some(script.as_bytes()))?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let out = helper(prog, args, None)?;
    if !out.status.success() {
        bail!(
            "{prog} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// VM traffic gets its own routing table holding nothing but the uplink's
/// default route, picked by source address. routes added later (a VPN, a new
/// LAN, docker) land in the main table and never apply to a VM
const RT_TABLE: &str = "29217";
const RULE_PRIO: &str = "29217";

fn egress_route(uplink: &str) -> Result<Vec<String>> {
    let out = helper(
        "ip",
        &["-j", "-4", "route", "show", "default", "dev", uplink],
        None,
    )?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("reading ip route")?;
    let r = v
        .as_array()
        .and_then(|a| a.first())
        .with_context(|| format!("no default route on {uplink}, VMs would have no way out"))?;
    let mut route = vec!["default".to_string()];
    if let Some(gw) = r["gateway"].as_str() {
        gw.parse::<Ipv4Addr>().context("odd gateway in ip route")?;
        route.extend(["via".into(), gw.into()]);
    }
    route.extend(["dev".into(), uplink.into()]);
    Ok(route)
}

/// the uplink's default gateway, if it has one
pub fn default_gateway(uplink: &str) -> Option<Ipv4Addr> {
    let r = egress_route(uplink).ok()?;
    let i = r.iter().position(|w| w == "via")?;
    r.get(i + 1)?.parse().ok()
}

/// point the VM table at the uplink's current default route. safe to repeat
fn routing_up(cfg: &Config) -> Result<()> {
    let route = egress_route(&cfg.uplink()?)?;
    let mut args: Vec<&str> = vec!["-4", "route", "replace"];
    args.extend(route.iter().map(String::as_str));
    args.extend(["table", RT_TABLE]);
    run("ip", &args)?;
    let want = format!("from {} lookup {RT_TABLE}", cfg.net.subnet);
    let have = helper("ip", &["-4", "rule", "show", "priority", RULE_PRIO], None)?;
    let have = String::from_utf8_lossy(&have.stdout);
    if have.lines().count() == 1 && have.contains(&want) {
        return Ok(());
    }
    while run("ip", &["-4", "rule", "del", "priority", RULE_PRIO]).is_ok() {}
    run(
        "ip",
        &[
            "-4",
            "rule",
            "add",
            "from",
            &cfg.net.subnet,
            "lookup",
            RT_TABLE,
            "priority",
            RULE_PRIO,
        ],
    )
}

fn routing_down() {
    while run("ip", &["-4", "rule", "del", "priority", RULE_PRIO]).is_ok() {}
    let _ = run("ip", &["-4", "route", "flush", "table", RT_TABLE]);
}

pub fn routing_ok(cfg: &Config) -> bool {
    helper("ip", &["-4", "rule", "show", "priority", RULE_PRIO], None).is_ok_and(|o| {
        String::from_utf8_lossy(&o.stdout)
            .contains(&format!("from {} lookup {RT_TABLE}", cfg.net.subnet))
    })
}

/// stop new VM connections when the filter can't be kept current
/// empties the sets that let a tap's traffic through. tap_ip too: without it the
/// ingress chain drops every packet from a VM, so connections that were already
/// open stop as well, not only new ones
fn fail_closed_script() -> String {
    ["tap_ip", "mode_web", "mode_open"]
        .iter()
        .map(|s| format!("flush set inet {TABLE} {s}\n"))
        .collect()
}

/// the filter couldn't be refreshed: VMs lose their network until it can. the
/// next good pass puts their entries back (readd_running). if nft itself is what
/// fails, the sets can't be emptied, so the VMs with a network are stopped
fn fail_closed(cfg: &Config, why: &str) {
    sys::syslog(&format!(
        "burner net: {why}, VMs lose their network until it works again"
    ));
    if nft(&fail_closed_script(), false).is_ok() {
        return;
    }
    let Ok(led) = Ledger::open(&cfg.paths.state) else {
        sys::syslog("burner net: can't read the ledger either, stopping every VM");
        cgroup::kill_all();
        return;
    };
    for v in led.all().into_iter().filter(|v| v.net_slot.is_some()) {
        let _ = led.update(&v.id, |x| x.cancel = true);
        cgroup::kill(&v.id);
        sys::syslog(&format!(
            "burner net: couldn't empty the filter sets, stopped {}",
            v.id
        ));
    }
}

fn net_lock(cfg: &Config) -> Result<sys::Lock> {
    sys::private_dir(&cfg.paths.state)?;
    Ok(sys::Lock::exclusive(&cfg.paths.state.join("net.lock"))?)
}

pub fn table_exists() -> bool {
    run("nft", &["list", "table", "inet", TABLE]).is_ok()
}

/// the table has the connection log's maps: one loaded by an older burner
/// doesn't, and a tap can't come up in it
fn log_maps_ok() -> bool {
    run("nft", &["list", "map", "inet", TABLE, "log_try"]).is_ok()
}

/// load the ruleset and turn on forwarding. safe to run again: the reload is
/// one nft transaction, and running VMs get their tap entries back right after
pub fn up(cfg: &Config) -> Result<Vec<String>> {
    let _lock = net_lock(cfg)?;
    let rules = ruleset(cfg)?;
    // routing first: without the nft table no tap can come up, so a failure
    // here leaves VMs with no network instead of the host's routes
    routing_up(cfg).context("setting up the VM routing table")?;
    nft(&rules, true)?;
    nft(&rules, false)?;
    readd_running(cfg)?;
    let mut notes = Vec::new();
    if std::fs::read_to_string(IP_FORWARD).is_ok_and(|v| v.trim() != "1") {
        std::fs::write(IP_FORWARD, "1")?;
        // remembered, so net down only turns it off again if burner turned it on
        std::fs::write(cfg.paths.state.join(FORWARD_MARK), b"")?;
        notes.push("turned on ipv4 forwarding".into());
    }
    if let Some(cmd) = ufw_rule_missing(cfg)? {
        notes.push(format!(
            "ufw drops forwarded traffic and has no rule for burner. add it with:\n  {cmd}"
        ));
    }
    Ok(notes)
}

/// the nflog group a slot's log goes to: one each, since a group has one reader
pub fn log_group(i: u32) -> u32 {
    LOG_GROUP_BASE + i
}

pub const LOG_GROUP_BASE: u32 = 29217;
/// new attempts a VM gets itemized before the rest are only counted
const LOG_TRY_LIMIT: &str = "100/second burst 500 packets";
const LOG_DOWN_LIMIT: &str = "200/second burst 400 packets";

/// a tap's log chains and the elements that let its traffic through, as one
/// nft transaction: the log is never missing while the tap passes traffic.
/// safe to repeat, the chains are flushed before their rules go in. the
/// chains only log, count and return
fn slot_script(s: &Slot, i: u32, mode: Mode) -> String {
    let tap = &s.tap;
    let g = log_group(i);
    let mut o = String::new();
    for c in COUNTERS {
        o += &format!("add counter inet {TABLE} {c}_{tap}\n");
    }
    for (c, rules) in [
        (
            "lt",
            vec![
                format!("counter name n_{tap}"),
                format!("limit rate over {LOG_TRY_LIMIT} counter name over_{tap} return"),
                format!("udp dport 53 log prefix \"t\" group {g} snaplen 320 return"),
                format!("log prefix \"t\" group {g} snaplen 80"),
            ],
        ),
        (
            "lu",
            vec![
                // every packet here gets one message: the count of them says
                // whether any went missing, the last one included
                format!("counter name up_{tap}"),
                format!("udp dport 53 log prefix \"q\" group {g} snaplen 320 return"),
                format!("log prefix \"o\" group {g} snaplen 80"),
            ],
        ),
        (
            "ld",
            vec![
                format!("limit rate over {LOG_DOWN_LIMIT} return"),
                format!("counter name down_{tap}"),
                format!("udp sport 53 log prefix \"r\" group {g} snaplen 600 return"),
                format!("log prefix \"a\" group {g} snaplen 80"),
            ],
        ),
    ] {
        o += &format!("add chain inet {TABLE} {c}_{tap}\nflush chain inet {TABLE} {c}_{tap}\n");
        for r in rules {
            o += &format!("add rule inet {TABLE} {c}_{tap} {r}\n");
        }
    }
    for (map, c) in [("log_try", "lt"), ("log_up", "lu"), ("log_down", "ld")] {
        o += &format!("add element inet {TABLE} {map} {{ \"{tap}\" : jump {c}_{tap} }}\n");
    }
    o += &format!(
        "add element inet {TABLE} tap_ip {{ {tap} . {} }}\nadd element inet {TABLE} mode_{} {{ {tap} }}\n",
        s.guest,
        mode.name()
    );
    o
}

/// what removes a slot's log pieces: the elements pointing at the chains
/// first, then the chains, then the counters their rules name
fn slot_teardown(tap: &str) -> Vec<String> {
    let mut o = Vec::new();
    for map in ["log_try", "log_up", "log_down"] {
        o.push(format!("delete element inet {TABLE} {map} {{ \"{tap}\" }}"));
    }
    for c in ["lt", "lu", "ld"] {
        o.push(format!("delete chain inet {TABLE} {c}_{tap}"));
    }
    for c in COUNTERS {
        o.push(format!("delete counter inet {TABLE} {c}_{tap}"));
    }
    o
}

/// a slot's log counters: every new attempt, those past the itemization
/// limit, what was let out and the replies logged. None if any can't be read
pub fn log_counts(tap: &str) -> Option<crate::netlog::NetCounts> {
    let get = |c: &str| -> Option<u64> {
        let name = format!("{c}_{tap}");
        let out = helper(
            "nft",
            &["-j", "list", "counter", "inet", TABLE, &name],
            None,
        )
        .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_counter(&out.stdout)
    };
    Some(crate::netlog::NetCounts {
        tries: get("n")?,
        over: get("over")?,
        up: get("up")?,
        down: get("down")?,
    })
}

/// the log's named counters per slot, as prefixes of their names
const COUNTERS: [&str; 4] = ["n", "over", "up", "down"];

fn parse_counter(json: &[u8]) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    v["nftables"]
        .as_array()?
        .iter()
        .find_map(|o| o.get("counter"))?["packets"]
        .as_u64()
}

/// put running VMs' taps back in the sets, after a reload or a fail-closed flush
fn readd_running(cfg: &Config) -> Result<()> {
    let mut readd = String::new();
    for v in Ledger::open(&cfg.paths.state)?.all() {
        let (Some(i), Some(mode)) = (v.net_slot, Mode::parse(&v.net)) else {
            continue;
        };
        let s = slot(cfg, i)?;
        if mode != Mode::None && std::path::Path::new("/sys/class/net").join(&s.tap).exists() {
            readd += &slot_script(&s, i, mode);
        }
    }
    if !readd.is_empty() {
        nft(&readd, false)?;
    }
    Ok(())
}

/// take the network away. VMs that have one are killed and their taps removed
/// first, so no tap is ever up without the filter in front of it
pub fn down(cfg: &Config) -> Result<usize> {
    let _lock = net_lock(cfg)?;
    let mut killed = 0;
    let led = Ledger::open(&cfg.paths.state)?;
    for v in led.all() {
        if v.net_slot.is_some() {
            // cancel too: a VM still setting up stops before it launches
            let _ = led.update(&v.id, |x| x.cancel = true);
            cgroup::kill(&v.id);
            killed += 1;
        }
    }
    drop(led);
    for i in taps_present(cfg) {
        tap_down_locked(cfg, i);
    }
    if !taps_present(cfg).is_empty() {
        bail!("some taps couldn't be removed, leaving the filter in place");
    }
    let _ = run("nft", &["delete", "table", "inet", TABLE]);
    let _ = run("nft", &["delete", "table", "ip", NAT_TABLE]);
    routing_down();
    if std::fs::remove_file(cfg.paths.state.join(FORWARD_MARK)).is_ok() {
        let _ = std::fs::write(IP_FORWARD, "0");
    }
    Ok(killed)
}

/// the last public address found for net.block_public_ip and how old that
/// answer is. a stale one stays blocked: the old address is more likely still
/// the router's than not
pub fn public_ip(cfg: &Config) -> Option<(Ipv4Addr, Duration)> {
    if !cfg.net.block_public_ip {
        return None;
    }
    let path = cfg.paths.state.join(PUBLIC_IP);
    let text = std::fs::read_to_string(&path).ok()?;
    #[cfg(target_os = "macos")]
    let text = same_uplink(&text)?;
    let ip = text.trim().parse().ok()?;
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or_default();
    #[cfg(target_os = "macos")]
    if age > PUBLIC_IP_MAX_AGE {
        return None;
    }
    Some((ip, age))
}

/// a public address worth blocking. anything else an outside service says is ignored
pub fn plausible_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
}

/// on macOS, the network an address was looked up on: the default route's
/// gateway, its ethernet address, the mac's own address there and the
/// interface. a mac moves between networks, and the address found behind the
/// last router says nothing about the one it's behind now. most home routers
/// are 192.168.1.1, so that alone can't tell them apart. macOS shows the
/// router's ethernet address only to processes it lets onto the local network
/// (arp sees no entry otherwise), so the mac's own dhcp address is in the key
/// too. anything that changes only costs a lookup
#[cfg(target_os = "macos")]
fn uplink() -> Option<String> {
    use crate::macnet::route::{Gateway, lookup};
    let r = lookup(Ipv4Addr::UNSPECIFIED, true).ok()?;
    let me = own_addr(r.index).map_or_else(|| "-".into(), |a| a.to_string());
    Some(match r.gateway {
        Gateway::Inet(gw) => {
            let mac = router_mac(gw).unwrap_or_else(|| "-".into());
            format!("{gw} {mac} {me} {}", r.index)
        }
        Gateway::Link => format!("link {me} {}", r.index),
    })
}

/// the first ipv4 address on interface index
#[cfg(target_os = "macos")]
fn own_addr(index: u16) -> Option<Ipv4Addr> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list freed below; each entry is only read while
    // the list lives, and if_nametoindex reads a NUL-terminated name from it
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return None;
        }
        let mut found = None;
        let mut cur = head;
        while !cur.is_null() && found.is_none() {
            let ifa = &*cur;
            cur = ifa.ifa_next;
            let sa = ifa.ifa_addr;
            if sa.is_null()
                || i32::from((*sa).sa_family) != libc::AF_INET
                || libc::if_nametoindex(ifa.ifa_name) != u32::from(index)
            {
                continue;
            }
            let sin = &*(sa as *const libc::sockaddr_in);
            found = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
        }
        libc::freeifaddrs(head);
        found
    }
}

/// the router's ethernet address, from arp(8): the routing socket and the
/// sysctl table only hand a process that isn't part of macOS a placeholder
#[cfg(target_os = "macos")]
fn router_mac(gw: Ipv4Addr) -> Option<String> {
    let out = sys::run_timeout(
        Command::new("/usr/sbin/arp").args(["-n", &gw.to_string()]),
        None,
        Duration::from_secs(5),
    )
    .ok()?;
    arp_mac(&String::from_utf8_lossy(&out.stdout))
}

/// "? (192.168.1.1) at 58:d6:1f:4c:f:e7 on en0 ifscope [ethernet]", with the
/// leading zeros arp leaves out put back
#[cfg(target_os = "macos")]
fn arp_mac(line: &str) -> Option<String> {
    let mac = line.split(" at ").nth(1)?.split_whitespace().next()?;
    let parts: Vec<u8> = mac
        .split(':')
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<_>>()?;
    (parts.len() == 6 && parts != [2, 0, 0, 0, 0, 0]).then(|| {
        parts
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// on macOS a cached address older than this doesn't count: a failed lookup
/// there more likely means another network than the same router
#[cfg(target_os = "macos")]
const PUBLIC_IP_MAX_AGE: Duration = Duration::from_secs(3600);

/// the address line, if the file was written on the network the mac is on now
#[cfg(target_os = "macos")]
fn same_uplink(text: &str) -> Option<&str> {
    let mut lines = text.lines();
    let ip = lines.next()?;
    (lines.next().map(str::trim) == Some(uplink()?.as_str())).then_some(ip)
}

/// from the reaper, before check(): ask again when the last answer is 10 min
/// old. the worst a lying service can do is get one more address blocked
pub fn refresh_public_ip(cfg: &Config) {
    if !cfg.net.block_public_ip || public_ip(cfg).is_some_and(|(_, age)| age < PUBLIC_IP_EVERY) {
        return;
    }
    // no default route, no way out to ask
    #[cfg(target_os = "macos")]
    let Some(net) = uplink() else {
        return;
    };
    for url in PUBLIC_IP_URLS {
        let Ok(out) = sys::run_timeout(
            Command::new("curl").args(["-4", "-sSf", "-m", "5", "--max-filesize", "64", url]),
            None,
            Duration::from_secs(8),
        ) else {
            continue;
        };
        let Some(ip) = std::str::from_utf8(&out.stdout)
            .ok()
            .and_then(|s| s.trim().parse::<Ipv4Addr>().ok())
            .filter(|ip| out.status.success() && plausible_public(*ip))
        else {
            continue;
        };
        let path = cfg.paths.state.join(PUBLIC_IP);
        let tmp = path.with_extension("new");
        let text = format!("{ip}\n");
        #[cfg(target_os = "macos")]
        let text = format!("{text}{net}\n");
        if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
            return;
        }
    }
    sys::syslog(
        "couldn't look up the public address for net.block_public_ip, keeping the last one",
    );
}

/// from the reaper: keep the blocked set current as routes and addresses change,
/// and if something wiped the table while taps are up, put it back or kill them
pub fn check(cfg: &Config) {
    let has_taps = !taps_present(cfg).is_empty();
    let exists = table_exists();
    if !exists || !log_maps_ok() {
        // a table an older burner loaded: the same filter, without the log.
        // reload it, the same as net up after an upgrade
        if exists && !has_taps {
            if up(cfg).is_err() {
                sys::syslog("burner net: reloading the filter for the network log failed");
            }
            return;
        }
        if !has_taps {
            return;
        }
        sys::syslog("nft table missing with taps up, reloading");
        if up(cfg).is_err() {
            sys::syslog("reload failed, stopping VMs that have a network");
            let _ = down(cfg);
        }
        return;
    }
    let Ok(_lock) = net_lock(cfg) else {
        sys::syslog("burner net: net.lock stayed busy, filter refresh skipped this pass");
        return;
    };
    let res = routing_up(cfg).context("VM routing").and_then(|()| {
        let b = blocked(cfg)?;
        nft(
            &format!(
                "flush set inet {TABLE} blocked4\nadd element inet {TABLE} blocked4 {{ {} }}\n",
                b.join(", ")
            ),
            false,
        )?;
        readd_running(cfg)
    });
    if let Err(e) = res {
        fail_closed(cfg, &format!("{e:#}"));
    }
}

/// the ufw command still needed, if ufw is active and lacks it
pub fn ufw_rule_missing(cfg: &Config) -> Result<Option<String>> {
    let Ok(out) = helper("ufw", &["status"], None) else {
        return Ok(None);
    };
    let status = String::from_utf8_lossy(&out.stdout);
    if !status.contains("Status: active") {
        return Ok(None);
    }
    let uplink = cfg.uplink()?;
    let have = status
        .lines()
        .any(|l| l.contains(&cfg.net.subnet) && l.contains("ALLOW FWD") && l.contains(&uplink));
    Ok((!have).then(|| {
        format!(
            "ufw route allow out on {uplink} from {} comment 'burner VMs'",
            cfg.net.subnet
        )
    }))
}

/// a tap only the VM's own uid and gid (the same number) can open
pub fn tap_up(cfg: &Config, i: u32, mode: Mode, uid: u32) -> Result<Slot> {
    let _lock = net_lock_for(cfg, std::time::Duration::from_secs(60))?;
    if !table_exists() || !routing_ok(cfg) {
        bail!("the VM network isn't set up, run burner net up first (or use --net none)");
    }
    if !log_maps_ok() {
        bail!("the VM network was set up by an older burner, run burner net up again");
    }
    let s = slot(cfg, i)?;
    if !sys::which("conntrack") {
        bail!(
            "conntrack not found (package conntrack). burner needs it to clear old connections when a network slot is reused"
        );
    }
    // teardown and the reaper remove a tap before its slot is free, so one that
    // still exists here belongs to something else
    if std::path::Path::new("/sys/class/net").join(&s.tap).exists() {
        bail!(
            "{} already exists, not touching it (burner reap cleans up its own)",
            s.tap
        );
    }
    clear_conntrack(s.guest)?;
    // a mode left from the slot's last VM must never carry over
    drop_elements(&s);
    run(
        "ip",
        &[
            "tuntap",
            "add",
            "dev",
            &s.tap,
            "mode",
            "tap",
            "user",
            &uid.to_string(),
            "group",
            &uid.to_string(),
        ],
    )?;
    // by default linux answers arp on any interface for every address it has,
    // which would let a VM map the host's LAN, vpn and docker addresses
    std::fs::write(format!("/proc/sys/net/ipv4/conf/{}/arp_ignore", s.tap), "1")
        .with_context(|| format!("setting arp_ignore on {}", s.tap))?;
    run(
        "ip",
        &["addr", "add", &format!("{}/30", s.host), "dev", &s.tap],
    )?;
    // the log chains and the pass-through elements in one go
    nft(&slot_script(&s, i, mode), false)?;
    run("ip", &["link", "set", &s.tap, "up"])?;
    Ok(s)
}

/// remove a VM's tap, its filter entries and any connections it left. false when
/// it couldn't be confirmed. takes the network lock, so the reaper can't put
/// the entries back halfway through
pub fn tap_down(cfg: &Config, i: u32) -> bool {
    let Ok(_lock) = net_lock_for(cfg, std::time::Duration::from_secs(60)) else {
        return false;
    };
    tap_down_locked(cfg, i)
}

/// tap_down for a VM's own teardown: its log counters are read first, before
/// they go with the tap, and kept in state/netcount/<id> for the run to read
pub fn tap_down_for(cfg: &Config, i: u32, id: &str) -> bool {
    let Ok(_lock) = net_lock_for(cfg, std::time::Duration::from_secs(60)) else {
        return false;
    };
    if let Ok(s) = slot(cfg, i)
        && let Some(c) = log_counts(&s.tap)
    {
        let dir = cfg.paths.state.join("netcount");
        if sys::private_dir(&dir).is_ok() {
            let _ = std::fs::write(
                dir.join(id),
                serde_json::json!({"tries": c.tries, "over": c.over, "up": c.up, "down": c.down})
                    .to_string(),
            );
        }
    }
    tap_down_locked(cfg, i)
}

/// with the network lock held: drop burner's taps that no ledger entry owns.
/// the ledger is read under the lock, and taps only come up under it, so a VM
/// starting right now can't have its tap taken for an orphan
pub fn reap_orphan_taps(cfg: &Config) -> Vec<u32> {
    let Ok(_lock) = net_lock_for(cfg, std::time::Duration::from_secs(60)) else {
        return Vec::new();
    };
    let Ok(led) = Ledger::open(&cfg.paths.state) else {
        return Vec::new();
    };
    let used: Vec<u32> = led.all().iter().filter_map(|v| v.net_slot).collect();
    drop(led);
    let gone: Vec<u32> = taps_present(cfg)
        .into_iter()
        .filter(|i| !used.contains(i))
        .collect();
    for &i in &gone {
        tap_down_locked(cfg, i);
    }
    gone
}

fn net_lock_for(cfg: &Config, wait: std::time::Duration) -> Result<sys::Lock> {
    sys::private_dir(&cfg.paths.state)?;
    sys::Lock::exclusive_until(
        &cfg.paths.state.join("net.lock"),
        std::time::Instant::now() + wait,
    )
    .context("the network lock stayed busy")
}

fn drop_elements(s: &Slot) {
    // one at a time: a piece that's already gone mustn't keep the others
    for cmd in slot_teardown(&s.tap) {
        let args: Vec<&str> = cmd.split(' ').collect();
        let _ = run("nft", &args);
    }
    let _ = run(
        "nft",
        &[
            "delete",
            "element",
            "inet",
            TABLE,
            "tap_ip",
            &format!("{{ {} . {} }}", s.tap, s.guest),
        ],
    );
    for m in ["web", "open"] {
        let _ = run(
            "nft",
            &[
                "delete",
                "element",
                "inet",
                TABLE,
                &format!("mode_{m}"),
                &format!("{{ {} }}", s.tap),
            ],
        );
    }
}

fn tap_down_locked(cfg: &Config, i: u32) -> bool {
    let Ok(s) = slot(cfg, i) else { return false };
    drop_elements(&s);
    let dev = std::path::Path::new("/sys/class/net").join(&s.tap);
    if dev.exists() && ours(cfg, &s.tap) {
        let _ = run("ip", &["link", "delete", &s.tap]);
    }
    let cleared = clear_conntrack(s.guest).is_ok();
    !dev.exists() && cleared
}

/// drop every tracked connection from a VM address, so whoever gets the slot
/// next can't receive replies meant for the last VM
fn clear_conntrack(ip: Ipv4Addr) -> Result<()> {
    let out = helper("conntrack", &["-D", "-s", &ip.to_string()], None)?;
    // exit 1 with "0 flow entries" just means there was nothing to delete
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || err.contains(" 0 flow entries") {
        return Ok(());
    }
    bail!("conntrack -D -s {ip}: {}", err.trim())
}

/// before each VM had its own uid, every tap belonged to this user
const OLD_USER: &str = "burner";

/// a bnN burner made: a tap owned by a VM uid, or by the old shared user so
/// taps from VMs started before an upgrade still get cleaned up. an unrelated
/// interface that happens to have the same name is left alone
fn ours(cfg: &Config, tap: &str) -> bool {
    let dir = std::path::Path::new("/sys/class/net").join(tap);
    let old = sys::user_ids(OLD_USER).map(|(u, _)| u);
    dir.join("tun_flags").exists()
        && std::fs::read_to_string(dir.join("owner"))
            .ok()
            .and_then(|o| o.trim().parse::<u32>().ok())
            .is_some_and(|o| owned_by_vm(cfg, o, old))
}

fn owned_by_vm(cfg: &Config, owner: u32, old: Option<u32>) -> bool {
    cfg.vm_uids().contains(&owner) || old == Some(owner)
}

pub fn is_tap(dev: &str) -> bool {
    dev.strip_prefix(TAP_PREFIX)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// indexes of burner's own taps that exist on the host right now
pub fn taps_present(cfg: &Config) -> Vec<u32> {
    std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            let i: u32 = name.strip_prefix(TAP_PREFIX)?.parse().ok()?;
            (name == format!("{TAP_PREFIX}{i}") && ours(cfg, &name)).then_some(i)
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn fail_closed_empties_every_pass_set() {
        let s = fail_closed_script();
        for set in ["tap_ip", "mode_web", "mode_open"] {
            assert!(
                s.contains(&format!("flush set inet {TABLE} {set}\n")),
                "{set}"
            );
        }
        assert!(!s.contains("blocked4"), "the blocked set stays as it was");
    }

    #[test]
    fn log_chains_never_decide() {
        let cfg = Config::default();
        let s = slot(&cfg, 3).unwrap();
        let script = slot_script(&s, 3, Mode::Web);
        for line in script.lines().filter(|l| l.starts_with("add rule")) {
            for verdict in [
                " accept",
                " drop",
                " reject",
                " queue",
                " jump",
                " goto",
                " continue",
            ] {
                assert!(!line.contains(verdict), "{verdict} in {line}");
            }
        }
        // chains exist before the elements that point at them, and the
        // elements that let traffic through come last, with them
        let chain = script.find("add chain inet burner lt_bn3").unwrap();
        let elem = script.find("add element inet burner log_try").unwrap();
        let pass = script.find("add element inet burner tap_ip").unwrap();
        assert!(chain < elem && elem < pass);
        assert!(script.contains("group 29220 "));
        assert!(script.contains("add element inet burner mode_web { bn3 }"));
        assert!(
            script.contains("flush chain inet burner lt_bn3"),
            "safe to repeat"
        );
        // removal: elements, then chains, then counters
        let down = slot_teardown("bn3").join("\n");
        let e = down.find("delete element inet burner log_try").unwrap();
        let c = down.find("delete chain inet burner lt_bn3").unwrap();
        let n = down.find("delete counter inet burner n_bn3").unwrap();
        for c in ["n_bn3", "over_bn3", "up_bn3", "down_bn3"] {
            assert!(
                script.contains(&format!("add counter inet burner {c}\n")),
                "{c}"
            );
            assert!(
                down.contains(&format!("delete counter inet burner {c}")),
                "{c}"
            );
        }
        // up counts every packet the up chain sees, before its log rules
        let up = script
            .find("add rule inet burner lu_bn3 counter name up_bn3")
            .unwrap();
        assert!(up < script.find("prefix \"o\"").unwrap());
        assert!(e < c && c < n);
        assert_eq!(log_group(1023), 30240);
    }

    /// the rules of one chain in a ruleset, trimmed
    fn chain<'a>(rules: &'a str, name: &str) -> Vec<&'a str> {
        let start = rules.find(&format!("chain {name} {{")).unwrap();
        rules[start..]
            .lines()
            .skip(2)
            .take_while(|l| l.trim() != "}")
            .map(str::trim)
            .collect()
    }

    #[test]
    fn the_filter_itself_is_unchanged() {
        let cfg = Config::default();
        let r = ruleset_for(&cfg, "eth0", &["10.0.0.0/8".into()]);
        // forward: the one new line at the top, then every rule as before
        let fwd = chain(&r, "forward");
        assert_eq!(fwd[0], "iifname \"bn*\" ct state new iifname vmap @log_try");
        let before = [
            "iifname \"bn*\" meta nfproto ipv6 drop",
            "oifname \"bn*\" meta nfproto ipv6 drop",
            "iifname \"bn*\" iifname . ip saddr != @tap_ip drop",
            "iifname \"bn*\" oifname != \"eth0\" drop",
            "iifname \"bn*\" ip daddr @blocked4 drop",
            "iifname \"bn*\" ct state established,related accept",
            "iifname @mode_web meta l4proto { tcp, udp } th dport 53 ip daddr @resolvers meter burner_dns_web { iifname limit rate 20/second burst 50 packets } accept",
            "iifname @mode_open meta l4proto { tcp, udp } th dport 53 ip daddr @resolvers meter burner_dns_open { iifname limit rate 20/second burst 50 packets } accept",
            "iifname \"bn*\" meta l4proto { tcp, udp } th dport 53 drop",
            "iifname @mode_web icmp type echo-request meter burner_ping_web { iifname limit rate 5/second burst 10 packets } accept",
            "iifname @mode_open icmp type echo-request meter burner_ping_open { iifname limit rate 5/second burst 10 packets } accept",
            "iifname @mode_web tcp dport { 80, 443 } ct state new meter burner_web { iifname limit rate 20/second burst 40 packets } accept",
            "iifname @mode_open tcp dport { 25, 465, 587 } drop",
            "iifname @mode_open ct state new meter burner_open { iifname limit rate 50/second burst 100 packets } accept",
            "iifname \"bn*\" drop",
            "oifname \"bn*\" ct state established,related accept",
            "oifname \"bn*\" drop",
        ];
        assert_eq!(&fwd[1..], &before[..]);
        let input = chain(&r, "input");
        assert_eq!(
            input,
            [
                "iifname \"bn*\" ct state new iifname vmap @log_try",
                "iifname \"bn*\" drop"
            ]
        );
        // the log chain after it decides nothing: vmap jumps into chains that
        // only return, and returns, which end it as its accept policy would
        let after = chain(&r, "log_after");
        assert!(r.contains("type filter hook forward priority filter - 9; policy accept;"));
        for l in &after {
            assert!(l.contains(" vmap @log_") || l.ends_with(" return"), "{l}");
            for v in [" accept", " drop", " reject", " queue", " goto"] {
                assert!(!l.contains(v), "{l}");
            }
        }
        assert_eq!(after.len(), 6);
    }

    #[test]
    fn counters() {
        let j = br#"{"nftables":[{"metainfo":{}},{"counter":{"family":"inet","name":"lt_bn3_n","table":"burner","handle":7,"packets":42,"bytes":2520}}]}"#;
        assert_eq!(parse_counter(j), Some(42));
        assert_eq!(parse_counter(b"{}"), None);
    }

    #[test]
    fn public_ip_answers() {
        for ok in ["8.8.8.8", "1.1.1.1"] {
            assert!(plausible_public(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "10.1.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.1",
        ] {
            assert!(!plausible_public(bad.parse().unwrap()), "{bad}");
        }
    }

    /// a homelab box: lan on eth0, a wireguard tunnel, docker, tailscale's
    /// own table (52) and the VM table burner made
    pub(crate) const HOMELAB_ADDRS: &str = r#"[
 {"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
 {"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24}]},
 {"ifindex":3,"ifname":"wg0","addr_info":[{"family":"inet","local":"10.1.0.5","prefixlen":16}]},
 {"ifindex":4,"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]},
 {"ifindex":5,"ifname":"tailscale0","addr_info":[{"family":"inet","local":"100.101.102.103","prefixlen":32}]},
 {"ifindex":9,"ifname":"bn0","addr_info":[{"family":"inet","local":"172.29.217.1","prefixlen":30}]}]"#;
    pub(crate) const HOMELAB_ROUTES: &str = r#"[
 {"dst":"default","gateway":"192.168.1.1","dev":"eth0","table":"29217","flags":[]},
 {"dst":"default","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp","flags":[]},
 {"dst":"9.9.9.9","gateway":"192.168.1.1","dev":"eth0","protocol":"dhcp","flags":[]},
 {"dst":"10.1.0.0/16","dev":"wg0","protocol":"kernel","scope":"link","prefsrc":"10.1.0.5","flags":[]},
 {"dst":"172.16.98.0/30","gateway":"10.1.0.1","dev":"wg0","flags":[]},
 {"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]},
 {"dst":"172.29.217.0/30","dev":"bn0","protocol":"kernel","scope":"link","prefsrc":"172.29.217.1","flags":[]},
 {"dst":"192.168.1.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"192.168.1.20","flags":[]},
 {"dst":"100.100.100.100","dev":"tailscale0","table":"52","flags":[]},
 {"dst":"100.64.0.0/10","dev":"tailscale0","table":"52","flags":[]},
 {"dst":"203.0.114.0/24","dev":"tailscale0","table":"52","flags":[]},
 {"type":"local","dst":"192.168.1.20","dev":"eth0","table":"local","protocol":"kernel","scope":"host","prefsrc":"192.168.1.20","flags":[]},
 {"type":"broadcast","dst":"192.168.1.255","dev":"eth0","table":"local","protocol":"kernel","scope":"link","prefsrc":"192.168.1.20","flags":[]},
 {"type":"local","dst":"127.0.0.0/8","dev":"lo","table":"local","protocol":"kernel","scope":"host","prefsrc":"127.0.0.1","flags":[]}]"#;
    /// a vps: one public address, nothing else
    pub(crate) const VPS_ADDRS: &str = r#"[
 {"ifindex":1,"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
 {"ifindex":2,"ifname":"ens6","addr_info":[{"local":"74.208.113.109","prefixlen":32}]}]"#;
    pub(crate) const VPS_ROUTES: &str = r#"[
 {"dst":"default","gateway":"74.208.113.1","dev":"ens6","protocol":"dhcp","flags":[]},
 {"dst":"74.208.113.1","dev":"ens6","protocol":"dhcp","scope":"link","flags":[]},
 {"type":"local","dst":"74.208.113.109","dev":"ens6","table":"local","protocol":"kernel","scope":"host","flags":[]}]"#;

    /// blocked() before it knew why: the same adds, straight into collapse
    fn old_blocked(
        cfg: &Config,
        public: Option<Ipv4Addr>,
        addrs: &str,
        routes: &str,
        up: &str,
    ) -> Vec<String> {
        let mut nets: Vec<(u32, u8)> = Vec::new();
        let mut add = |c: (Ipv4Addr, u8)| nets.push((u32::from(c.0) & config::mask(c.1), c.1));
        // the list as it was before it had labels
        let old_special = [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
        ];
        for s in old_special
            .iter()
            .map(|s| s.to_string())
            .chain(cfg.net.block.iter().cloned())
        {
            add(config::parse_cidr(&s).unwrap());
        }
        add(cfg.subnet().unwrap());
        if let Some(ip) = public {
            add((ip, 32));
        }
        for a in parse_addrs(addrs.as_bytes()).unwrap() {
            add((a.ip, 32));
            add((a.ip, a.prefix));
        }
        for r in parse_routes(routes.as_bytes(), up).unwrap() {
            if r.prefix > 0 {
                add((r.dst, r.prefix));
            }
        }
        collapse(nets)
    }

    fn fixture(public: Option<Ipv4Addr>, addrs: &str, routes: &str, up: &str) -> Vec<Blocked> {
        let mut cfg = Config::default();
        cfg.net.block = vec!["140.82.121.0/24".into()];
        sources_from(
            &cfg,
            public,
            &parse_addrs(addrs.as_bytes()).unwrap(),
            &parse_routes(routes.as_bytes(), up).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn sources_collapse_to_the_old_set() {
        let mut cfg = Config::default();
        cfg.net.block = vec!["140.82.121.0/24".into()];
        for (public, addrs, routes, up) in [
            (None, HOMELAB_ADDRS, HOMELAB_ROUTES, "eth0"),
            (
                Some(Ipv4Addr::new(81, 2, 3, 4)),
                HOMELAB_ADDRS,
                HOMELAB_ROUTES,
                "eth0",
            ),
            (None, VPS_ADDRS, VPS_ROUTES, "ens6"),
        ] {
            let new: Vec<(u32, u8)> = fixture(public, addrs, routes, up)
                .iter()
                .map(|b| (u32::from(b.net), b.prefix))
                .collect();
            assert_eq!(collapse(new), old_blocked(&cfg, public, addrs, routes, up));
        }
    }

    #[test]
    fn sources_say_why() {
        let b = fixture(
            Some(Ipv4Addr::new(81, 2, 3, 4)),
            HOMELAB_ADDRS,
            HOMELAB_ROUTES,
            "eth0",
        );
        let has = |net: &str, prefix: u8, why: Why| {
            let net: Ipv4Addr = net.parse().unwrap();
            assert!(
                b.iter()
                    .any(|x| x.net == net && x.prefix == prefix && x.why == why),
                "{net}/{prefix} {why:?} in {b:#?}"
            );
        };
        has("192.168.1.20", 32, Why::HostAddr { dev: "eth0".into() });
        has("192.168.1.0", 24, Why::HostNet { dev: "eth0".into() });
        has(
            "172.17.0.0",
            16,
            Why::HostNet {
                dev: "docker0".into(),
            },
        );
        has(
            "172.16.98.0",
            30,
            Why::Route {
                dev: "wg0".into(),
                via: Some(Ipv4Addr::new(10, 1, 0, 1)),
                table: "main".into(),
            },
        );
        has(
            "203.0.114.0",
            24,
            Why::Route {
                dev: "tailscale0".into(),
                via: None,
                table: "52".into(),
            },
        );
        has("81.2.3.4", 32, Why::PublicIp);
        has("140.82.121.0", 24, Why::Config);
        has("172.29.217.0", 24, Why::Subnet);
        has(
            "169.254.0.0",
            16,
            Why::Special {
                label: "cloud metadata and link-local",
            },
        );
        // the dhcp route to the resolver goes the default way, so it stays open
        assert!(!b.iter().any(|x| x.net == Ipv4Addr::new(9, 9, 9, 9)));
        // and the VM table's default route is no destination
        assert!(!b.iter().any(|x| x.prefix == 0));
    }

    #[test]
    fn special_ranges() {
        for s in SPECIAL {
            assert_eq!(u32::from(s.net) & !config::mask(s.prefix), 0, "{}", s.net);
        }
        let label = |ip: [u8; 4]| special(Ipv4Addr::from(ip)).map(|s| s.label);
        assert_eq!(
            label([169, 254, 169, 254]),
            Some("cloud metadata and link-local")
        );
        assert_eq!(label([100, 100, 100, 100]), Some("cgnat and tailscale"));
        assert_eq!(label([255, 255, 255, 255]), Some("reserved and broadcast"));
        assert_eq!(label([140, 82, 112, 3]), None);
    }

    #[test]
    fn unreadable_routes_are_an_error() {
        assert!(parse_routes(b"not json", "eth0").is_err());
        assert!(parse_addrs(b"{").is_err());
        let odd = parse_routes(br#"[{"dst":"10.0.0.0/40","dev":"x"}]"#, "eth0").unwrap();
        assert!(odd.is_empty(), "a prefix over 32 is no route");
    }

    #[test]
    fn collapsing() {
        let v = collapse(vec![
            (0x0a000000, 8),
            (0x0a010000, 16),
            (0x0a010203, 32),
            (0xc0a80000, 16),
            (0x0a000000, 8),
        ]);
        assert_eq!(
            v,
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
    }

    #[test]
    fn slots() {
        let cfg = Config::default();
        let s = slot(&cfg, 0).unwrap();
        assert_eq!(
            (s.tap.as_str(), s.host, s.guest),
            (
                "bn0",
                Ipv4Addr::new(172, 29, 217, 1),
                Ipv4Addr::new(172, 29, 217, 2)
            )
        );
        let s = slot(&cfg, 63).unwrap();
        assert_eq!(s.guest, Ipv4Addr::new(172, 29, 217, 254));
        assert!(slot(&cfg, 64).is_err());
    }

    #[test]
    fn tap_owners() {
        let cfg = Config::default();
        let base = cfg.jail.uid_base;
        assert!(owned_by_vm(&cfg, base, None));
        assert!(owned_by_vm(&cfg, base + 1023, None));
        assert!(!owned_by_vm(&cfg, base + 1024, None));
        assert!(!owned_by_vm(&cfg, base - 1, None));
        assert!(!owned_by_vm(&cfg, 0, None));
        assert!(!owned_by_vm(&cfg, 1000, None));
        assert!(owned_by_vm(&cfg, 998, Some(998)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn public_ip_is_per_network() {
        let Some(here) = uplink() else {
            return;
        };
        assert_eq!(
            same_uplink(&format!("203.0.113.9\n{here}\n")),
            Some("203.0.113.9")
        );
        assert_eq!(same_uplink("203.0.113.9\n192.0.2.1 99\n"), None);
        assert_eq!(same_uplink("203.0.113.9\n"), None, "written before");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn router_macs() {
        assert_eq!(
            arp_mac("? (10.1.0.1) at 58:d6:1f:4c:f:e7 on en0 ifscope [ethernet]").as_deref(),
            Some("58:d6:1f:4c:0f:e7")
        );
        assert_eq!(
            arp_mac("? (10.1.0.1) at (incomplete) on en0 ifscope [ethernet]"),
            None
        );
        assert_eq!(arp_mac("10.1.0.1 (10.1.0.1) -- no entry"), None);
        assert_eq!(arp_mac("? (10.1.0.1) at 2:0:0:0:0:0 on en0"), None);
    }
}
