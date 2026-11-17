//! the VM network: every VM gets a tap and its own /30 out of net.subnet, and
//! one nft table lets those taps reach the internet through the uplink and
//! nothing else (not the LAN, not the host, not each other).

use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::{self, Config};

pub const TABLE: &str = "burner";
pub const NAT_TABLE: &str = "burner_nat";
const TAP_PREFIX: &str = "bn";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// the full nft ruleset for this config
pub fn ruleset(cfg: &Config) -> Result<String> {
    let uplink = cfg.uplink()?;
    let mut own: Vec<String> = config::iface_addrs(&uplink)?
        .iter()
        .map(|a| a.to_string())
        .collect();
    own.sort();
    own.dedup();
    let blocked = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(own)
    .chain(std::iter::once(cfg.net.subnet.clone()))
    .collect::<Vec<_>>()
    .join(", ");
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
        iifname "{t}*" meta l4proto {{ tcp, udp }} th dport 53 ip daddr @resolvers accept
        iifname "{t}*" meta l4proto {{ tcp, udp }} th dport 53 drop
        iifname "{t}*" icmp type echo-request limit rate 5/second accept
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
    let mut c = Command::new("nft");
    if check {
        c.arg("-c");
    }
    let mut child = c
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn run(prog: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(prog)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        bail!(
            "{prog} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// load the ruleset and turn on forwarding. safe to run again
pub fn up(cfg: &Config) -> Result<Vec<String>> {
    let rules = ruleset(cfg)?;
    nft(&rules, true)?;
    nft(&rules, false)?;
    let mut notes = Vec::new();
    if std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|v| v.trim() != "1") {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
        notes.push("turned on ipv4 forwarding".into());
    }
    if let Some(cmd) = ufw_rule_missing(cfg)? {
        notes.push(format!(
            "ufw drops forwarded traffic and has no rule for burner. add it with:\n  {cmd}"
        ));
    }
    Ok(notes)
}

pub fn down() {
    let _ = run("nft", &["delete", "table", "inet", TABLE]);
    let _ = run("nft", &["delete", "table", "ip", NAT_TABLE]);
}

/// the ufw command still needed, if ufw is active and lacks it
pub fn ufw_rule_missing(cfg: &Config) -> Result<Option<String>> {
    let Ok(out) = Command::new("ufw").arg("status").output() else {
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

pub fn tap_up(cfg: &Config, i: u32, mode: Mode, uid: u32, gid: u32) -> Result<Slot> {
    if run("nft", &["list", "table", "inet", TABLE]).is_err() {
        bail!("the VM network isn't set up, run burner net up first (or use --net none)");
    }
    let s = slot(cfg, i)?;
    tap_down(cfg, i);
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
            &gid.to_string(),
        ],
    )?;
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

pub fn tap_down(cfg: &Config, i: u32) {
    let Ok(s) = slot(cfg, i) else { return };
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
    if std::path::Path::new("/sys/class/net").join(&s.tap).exists() {
        let _ = run("ip", &["link", "delete", &s.tap]);
    }
}

pub fn is_tap(dev: &str) -> bool {
    dev.strip_prefix(TAP_PREFIX)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// tap indexes that exist on the host right now
pub fn taps_present() -> Vec<u32> {
    std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .filter_map(|e| {
            e.ok()?
                .file_name()
                .to_str()?
                .strip_prefix(TAP_PREFIX)?
                .parse()
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
