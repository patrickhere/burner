use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/burner/config.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub paths: Paths,
    pub net: Net,
    pub limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    /// firecracker, jailer, kernel, images and per-run jails live under here
    pub root: PathBuf,
    /// run state, cleared on reboot
    pub state: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Net {
    /// carved into one /30 per VM
    pub subnet: String,
    /// the interface VMs reach the internet through. empty = the default route's
    pub uplink: String,
    pub resolvers: Vec<Ipv4Addr>,
    /// bytes per second, each direction, per VM
    pub rate: u64,
    /// extra destinations VMs may never reach, on top of private ranges and
    /// everything the host itself has a route to
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub vcpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
    pub ttl_secs: u32,
    pub ttl_shell_secs: u32,
    pub max_vms: u32,
    pub total_mem_mib: u32,
    /// the most network any run may ask for: none, web or open. default web
    pub net: String,
    /// how long --in stdin and --in tar wait for the next byte before giving up
    pub stdin_idle_secs: u32,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            root: "/var/lib/burner".into(),
            state: "/run/burner".into(),
        }
    }
}

impl Default for Net {
    fn default() -> Self {
        Net {
            subnet: "172.29.217.0/24".into(),
            uplink: String::new(),
            resolvers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)],
            rate: 2_500_000,
            block: Vec::new(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            vcpus: 2,
            mem_mib: 3072,
            disk_gib: 8,
            ttl_secs: 1800,
            ttl_shell_secs: 3600,
            max_vms: 2,
            total_mem_mib: 3072,
            // open (any port but mail) is something you opt into
            net: "web".into(),
            stdin_idle_secs: 60,
        }
    }
}

impl Config {
    /// a missing file means defaults; a broken one is an error, never silently ignored
    pub fn load(path: &Path) -> Result<Config> {
        // as root, a config decides what burner runs as root (paths.root holds
        // the jailer). only one that nobody but root could have written counts
        let via_sudo = std::env::var_os("SUDO_UID").is_some();
        if crate::sys::is_root() {
            trusted(path, via_sudo)?;
        }
        let cfg = match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| {
                // someone running burner through sudo doesn't get to read root's
                // files through parse errors: position only, never the text
                let line = e.span().map_or(0, |s| {
                    text[..s.start.min(text.len())].matches('\n').count() + 1
                });
                if via_sudo {
                    anyhow::anyhow!("{} is not a valid config (line {line})", path.display())
                } else {
                    anyhow::anyhow!("{} is not a valid config: {e}", path.display())
                }
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        cfg.check()?;
        Ok(cfg)
    }

    fn check(&self) -> Result<()> {
        let (_, prefix) = self.subnet()?;
        if prefix > 28 {
            bail!("net.subnet /{prefix} is too small, it needs room for at least four /30s");
        }
        let l = &self.limits;
        if crate::net::Mode::parse(&l.net).is_none() {
            bail!("limits.net must be none, web or open");
        }
        if l.vcpus == 0
            || l.mem_mib < 128
            || l.disk_gib == 0
            || l.ttl_secs < 10
            || l.max_vms == 0
            || l.stdin_idle_secs < 5
        {
            bail!("limits are too low to start a VM");
        }
        if l.total_mem_mib < l.mem_mib {
            bail!(
                "limits.total_mem_mib is below limits.mem_mib, no VM at the max size could ever start"
            );
        }
        Ok(())
    }

    pub fn subnet(&self) -> Result<(Ipv4Addr, u8)> {
        parse_cidr(&self.net.subnet).with_context(|| format!("net.subnet {:?}", self.net.subnet))
    }

    /// how many /30 slots the subnet holds
    pub fn net_slots(&self) -> Result<u32> {
        let (_, prefix) = self.subnet()?;
        Ok(1u32 << (30 - prefix))
    }

    pub fn uplink(&self) -> Result<String> {
        if !self.net.uplink.is_empty() {
            return Ok(self.net.uplink.clone());
        }
        default_route_iface().context("no default route; set net.uplink in the config")
    }
}

pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = s.split_once('/').context("expected a.b.c.d/nn")?;
    let addr: Ipv4Addr = addr.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        bail!("prefix over 32");
    }
    let mask = mask(prefix);
    if u32::from(addr) & !mask != 0 {
        bail!(
            "host bits set, did you mean {}/{prefix}",
            Ipv4Addr::from(u32::from(addr) & mask)
        );
    }
    Ok((addr, prefix))
}

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

pub fn overlaps(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
    let m = mask(a.1.min(b.1));
    u32::from(a.0) & m == u32::from(b.0) & m
}

fn default_route_iface() -> Option<String> {
    // /proc/net/route: iface, destination (hex, 0 = default), ...
    let routes = fs::read_to_string("/proc/net/route").ok()?;
    routes
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .find(|f| f.len() > 2 && f[1] == "00000000")
        .map(|f| f[0].to_string())
}

/// the config file and every directory above it: owned by root and writable by
/// nobody else. a path other than the default has to exist, and through sudo it
/// has to be in /etc/burner, so a sudo rule for burner can't be used to load
/// some other root-owned file as a config
fn trusted(path: &Path, via_sudo: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let real = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && path == Path::new(DEFAULT_PATH) => {
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("config {}", path.display())),
    };
    if via_sudo && !real.starts_with("/etc/burner/") {
        bail!("through sudo, --config has to be a file in /etc/burner");
    }
    for p in real.ancestors() {
        let m = fs::metadata(p).with_context(|| format!("checking {}", p.display()))?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!(
                "{} is owned or writable by someone other than root, so burner won't take a config from it",
                p.display()
            );
        }
    }
    Ok(())
}

/// ipv4 addresses on an interface, from `ip -j`
pub fn iface_addrs(iface: &str) -> Result<Vec<Ipv4Addr>> {
    let out = crate::sys::run_timeout(
        Command::new("ip").args(["-j", "-4", "addr", "show", "dev", iface]),
        None,
        std::time::Duration::from_secs(30),
    )?;
    if !out.status.success() {
        bail!("ip addr show {iface} failed");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let mut addrs = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        for a in link["addr_info"].as_array().into_iter().flatten() {
            if let Some(ip) = a["local"].as_str().and_then(|s| s.parse().ok()) {
                addrs.push(ip);
            }
        }
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert_eq!(
            parse_cidr("10.1.0.0/16").unwrap(),
            (Ipv4Addr::new(10, 1, 0, 0), 16)
        );
        assert!(parse_cidr("10.1.0.5/16").is_err());
        assert!(parse_cidr("10.1.0.0/33").is_err());
        assert!(parse_cidr("nope").is_err());
    }

    #[test]
    fn overlap() {
        let lan = parse_cidr("10.1.0.0/16").unwrap();
        assert!(overlaps(lan, parse_cidr("10.1.4.0/24").unwrap()));
        assert!(!overlaps(lan, parse_cidr("172.29.217.0/24").unwrap()));
        assert!(overlaps(parse_cidr("0.0.0.0/0").unwrap(), lan));
    }

    #[test]
    fn defaults_are_valid() {
        let c = Config::default();
        c.check().unwrap();
        assert_eq!(c.net_slots().unwrap(), 64);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_limits() {
        assert!(toml::from_str::<Config>("[net]\nsubnett = \"10.0.0.0/24\"\n").is_err());
        let c: Config = toml::from_str("[limits]\nmem_mib = 4096\ntotal_mem_mib = 2048\n").unwrap();
        assert!(c.check().is_err());
    }
}
