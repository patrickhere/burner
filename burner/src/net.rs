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

/// always blocked, on any network
const SPECIAL: &[&str] = &[
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

/// everything a VM must never reach: the special ranges, every address and
/// attached network on the host, every route that isn't the default one (a LAN
/// on public addresses, a vpn, a docker network), the VM subnet and net.block.
/// what's left is the internet through the default route
pub fn blocked(cfg: &Config) -> Result<Vec<String>> {
    let mut nets: Vec<(u32, u8)> = Vec::new();
    let mut add = |c: (Ipv4Addr, u8)| nets.push((u32::from(c.0) & config::mask(c.1), c.1));
    for s in SPECIAL
        .iter()
        .map(|s| s.to_string())
        .chain(cfg.net.block.iter().cloned())
    {
        add(config::parse_cidr(&s).with_context(|| format!("net.block {s:?}"))?);
    }
    add(cfg.subnet()?);
    if let Some((ip, _)) = public_ip(cfg) {
        add((ip, 32));
    }
    for (addr, prefix) in local_addrs()? {
        add((addr, 32));
        add((addr, prefix));
    }
    for dst in route_dsts(&cfg.uplink()?)? {
        if dst.1 > 0 {
            add(dst);
        }
    }
    Ok(collapse(nets))
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

fn local_addrs() -> Result<Vec<(Ipv4Addr, u8)>> {
    let out = helper("ip", &["-j", "-4", "addr", "show"], None)?;
    if !out.status.success() {
        bail!("ip addr show failed");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let mut addrs = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        for a in link["addr_info"].as_array().into_iter().flatten() {
            let ip = a["local"].as_str().and_then(|s| s.parse().ok());
            let prefix = a["prefixlen"].as_u64().map(|p| p.min(32) as u8);
            if let (Some(ip), Some(p)) = (ip, prefix) {
                addrs.push((ip, p));
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
fn route_dsts(uplink: &str) -> Result<Vec<(Ipv4Addr, u8)>> {
    let out = helper("ip", &["-j", "-4", "route", "show", "table", "all"], None)?;
    if !out.status.success() {
        bail!("ip route show failed");
    }
    // a route list we can't read must not shrink the blocked set
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("reading ip route")?;
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
                Some((ip, p)) => (ip.parse().ok()?, p.parse().ok()?),
                None if dst == "default" => return None,
                None => (dst.parse().ok()?, 32),
            };
            Some((ip, p))
        })
        .collect())
}

/// the full nft ruleset for this config
pub fn ruleset(cfg: &Config) -> Result<String> {
    let uplink = cfg.uplink()?;
    let blocked = blocked(cfg)?.join(", ");
    let resolvers = cfg
        .net
        .resolvers
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let subnet = &cfg.net.subnet;
    let t = TAP_PREFIX;
    Ok(format!(
        r#"table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
    set blocked4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {blocked} }} }}
    set resolvers {{ type ipv4_addr; elements = {{ {resolvers} }} }}
    set mode_web {{ type ifname; }}
    set mode_open {{ type ifname; }}
    set tap_ip {{ type ifname . ipv4_addr; }}

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
        iifname "{t}*" drop
    }}

    chain forward {{
        type filter hook forward priority filter - 10; policy accept;
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
    ))
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

/// put running VMs' taps back in the sets, after a reload or a fail-closed flush
fn readd_running(cfg: &Config) -> Result<()> {
    let mut readd = String::new();
    for v in Ledger::open(&cfg.paths.state)?.all() {
        let (Some(i), Some(mode)) = (v.net_slot, Mode::parse(&v.net)) else {
            continue;
        };
        let s = slot(cfg, i)?;
        if mode != Mode::None && std::path::Path::new("/sys/class/net").join(&s.tap).exists() {
            readd += &format!(
                "add element inet {TABLE} tap_ip {{ {} . {} }}\nadd element inet {TABLE} mode_{} {{ {} }}\n",
                s.tap,
                s.guest,
                mode.name(),
                s.tap
            );
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
    let ip = std::fs::read_to_string(&path).ok()?.trim().parse().ok()?;
    let age = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .unwrap_or_default();
    Some((ip, age))
}

/// a public address worth blocking. anything else an outside service says is ignored
fn plausible_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64)
}

/// from the reaper, before check(): ask again when the last answer is 10 min
/// old. the worst a lying service can do is get one more address blocked
pub fn refresh_public_ip(cfg: &Config) {
    if !cfg.net.block_public_ip || public_ip(cfg).is_some_and(|(_, age)| age < PUBLIC_IP_EVERY) {
        return;
    }
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
        if std::fs::write(&tmp, format!("{ip}\n")).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
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
    if !table_exists() {
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
    run(
        "nft",
        &[
            "add",
            "element",
            "inet",
            TABLE,
            "tap_ip",
            &format!("{{ {} . {} }}", s.tap, s.guest),
        ],
    )?;
    run(
        "nft",
        &[
            "add",
            "element",
            "inet",
            TABLE,
            &format!("mode_{}", mode.name()),
            &format!("{{ {} }}", s.tap),
        ],
    )?;
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
mod tests {
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
}
