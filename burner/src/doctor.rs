//! `burner doctor`: can this machine run burner, and if not, what to fix.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Serialize;

use crate::config::{self, Config};
use crate::json;
use crate::net;
use crate::sys;

pub const GUEST_INIT: &[u8] = include_bytes!("../guest-init");

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    /// for people, may change in any release
    pub detail: String,
}

#[derive(Serialize)]
pub struct Report {
    pub root: bool,
    pub worst: Level,
    pub checks: Vec<Check>,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, detail: impl AsRef<str>) {
        let tag = match level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        if !json::on() {
            println!("{tag}  {what:<12} {}", detail.as_ref());
        }
        self.worst = self.worst.max(level);
        self.checks.push(Check {
            name: what.into(),
            level,
            detail: detail.as_ref().into(),
        });
    }

    pub fn failed(&self) -> bool {
        self.worst == Level::Fail
    }
}

pub fn run(cfg: &Config) -> Report {
    let mut r = Report {
        root: false,
        worst: Level::Ok,
        checks: Vec::new(),
    };
    let root = is_root();
    if !root {
        r.line(
            Level::Warn,
            "user",
            "not root, some checks are skipped (run with sudo for all of them)",
        );
    }

    container(&mut r);
    kvm(&mut r);
    cgroups(&mut r);
    tools(&mut r);
    network(&mut r, cfg);
    memory(&mut r, cfg);
    disk(&mut r, cfg);
    install(&mut r, cfg);
    if root {
        services(&mut r, cfg);
    }

    if !json::on() {
        println!();
        match r.worst {
            Level::Ok => println!("all good"),
            Level::Warn => println!("works, see the warnings above"),
            Level::Fail => println!("not ready, fix the FAIL lines first"),
        }
    }
    r.root = root;
    r
}

fn is_root() -> bool {
    fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

fn kvm(r: &mut Report) {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => r.line(Level::Ok, "kvm", "/dev/kvm usable"),
        Err(e) if Path::new("/dev/kvm").exists() => r.line(
            Level::Fail,
            "kvm",
            format!("/dev/kvm exists but can't be opened ({e}), run as root"),
        ),
        Err(_) => {
            let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
            r.line(
                Level::Fail,
                "kvm",
                no_kvm(&cpuinfo, cfg!(target_arch = "x86_64")),
            )
        }
    }
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    if cpu_flag(&cpuinfo, "hypervisor") {
        r.line(
            Level::Warn,
            "nested",
            "this machine is itself a VM: VMs run nested, slower and at the host's mercy",
        );
    }
}

/// whether /proc/cpuinfo's first flags line has this flag
fn cpu_flag(cpuinfo: &str, flag: &str) -> bool {
    cpuinfo
        .lines()
        .find(|l| l.starts_with("flags"))
        .is_some_and(|l| l.split_whitespace().any(|f| f == flag))
}

/// why there's no /dev/kvm, from the cpu: a VM whose cpu type hides
/// virtualization (proxmox's default does), a module that isn't loaded, or
/// a bios that has it off. x86 only, an arm cpu doesn't list it
fn no_kvm(cpuinfo: &str, x86: bool) -> String {
    let model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, m)| m.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let virt = ["vmx", "svm"].into_iter().find(|f| cpu_flag(cpuinfo, f));
    match (x86, virt, cpu_flag(cpuinfo, "hypervisor")) {
        (false, _, _) => {
            "no /dev/kvm. enable virtualization in the firmware, or nested virt if this is a VM"
                .into()
        }
        (true, Some(f), _) => format!(
            "no /dev/kvm, though the cpu has {f}: the kvm module isn't loaded (modprobe {})",
            if f == "vmx" { "kvm_intel" } else { "kvm_amd" }
        ),
        (true, None, true) => format!(
            "no /dev/kvm: this VM's cpu type ({model}) hides virtualization. on proxmox: cpu type host \
             (qm set ID --cpu host), and nested on in the proxmox host"
        ),
        (true, None, false) => format!(
            "no /dev/kvm, and the cpu ({model}) shows no vmx or svm: turn virtualization on in the bios (VT-x or AMD-V)"
        ),
    }
}

/// inside a container: lxc, docker, podman, systemd-nspawn. burner needs a
/// machine or a VM of its own: its nft table, routing table, taps and uid
/// range would land on the container's host
fn container(r: &mut Report) {
    let environ = fs::read("/proc/1/environ").unwrap_or_default();
    let what = in_container(
        fs::read_to_string("/run/systemd/container").ok().as_deref(),
        &environ,
        Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists(),
    )
    .or_else(|| {
        run_ok("systemd-detect-virt", &["-c"])
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty() && o != "none")
    });
    if let Some(what) = what {
        r.line(
            Level::Fail,
            "container",
            format!(
                "burner is inside a container ({}). it needs a machine or a VM of its own: in a \
                 container its firewall, routes and VM users would be the host's",
                printable(&what)
            ),
        );
    }
}

/// the container kind, from /run/systemd/container, pid 1's environment or
/// docker's and podman's marker files
fn in_container(systemd: Option<&str>, environ: &[u8], marker: bool) -> Option<String> {
    if let Some(s) = systemd.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(s.to_string());
    }
    let env = environ
        .split(|&b| b == 0)
        .find_map(|v| v.strip_prefix(b"container="))
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .filter(|v| !v.is_empty());
    env.or_else(|| marker.then(|| "docker or podman".to_string()))
}

fn printable(s: &str) -> String {
    s.chars()
        .take(40)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

fn cgroups(r: &mut Report) {
    let Ok(ctrls) = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") else {
        r.line(
            Level::Fail,
            "cgroups",
            "cgroup v2 is not mounted at /sys/fs/cgroup (v1-only systems aren't supported)",
        );
        return;
    };
    let missing: Vec<_> = ["cpu", "memory", "pids"]
        .into_iter()
        .filter(|c| !ctrls.split_whitespace().any(|x| x == *c))
        .collect();
    if missing.is_empty() {
        r.line(Level::Ok, "cgroups", "v2 with cpu, memory and pids");
    } else {
        r.line(
            Level::Fail,
            "cgroups",
            format!("v2 is missing controllers: {}", missing.join(", ")),
        );
    }
}

fn tools(r: &mut Report) {
    for t in ["ip", "nft", "mkfs.ext4", "conntrack"] {
        if sys::which(t) {
            r.line(Level::Ok, t, "found");
        } else {
            let pkg = match t {
                "ip" => "iproute2",
                "nft" => "nftables",
                "conntrack" => "conntrack",
                _ => "e2fsprogs",
            };
            r.line(Level::Fail, t, format!("not found, install {pkg}"));
        }
    }
    if sys::which("firewall-cmd")
        && run_ok("firewall-cmd", &["--state"]).is_some_and(|o| o.trim() == "running")
    {
        r.line(
            Level::Warn,
            "firewall",
            "firewalld is running: VM traffic needs its zone set up (not automated yet)",
        );
    }
}

fn network(r: &mut Report, cfg: &Config) {
    let uplink = match cfg.uplink() {
        Ok(u) => u,
        Err(e) => {
            r.line(Level::Fail, "uplink", format!("{e:#}"));
            return;
        }
    };
    match config::iface_addrs(&uplink) {
        Ok(a) if !a.is_empty() => {
            let list: Vec<_> = a.iter().map(|x| x.to_string()).collect();
            r.line(
                Level::Ok,
                "uplink",
                format!("{uplink} ({})", list.join(", ")),
            );
            // behind NAT the router's public address is just "internet" to the
            // filter, and from inside it usually answers with its own admin and
            // ssh, or loops back into port forwards. burner can't know that
            // address without asking an outside service, so it asks you
            let natted = a
                .iter()
                .all(|ip| ip.is_private() || ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64);
            let public_block = cfg.net.block.iter().any(|b| {
                config::parse_cidr(b).is_ok_and(|(ip, _)| !ip.is_private() && !ip.is_loopback())
            });
            if cfg.net.block_public_ip {
                match crate::net::public_ip(cfg) {
                    Some((ip, age)) if age.as_secs() < 3600 => r.line(
                        Level::Ok,
                        "public ip",
                        format!("{ip} is blocked, looked up {} min ago", age.as_secs() / 60),
                    ),
                    Some((ip, age)) => r.line(
                        Level::Warn,
                        "public ip",
                        format!(
                            "{ip} is blocked, but the last lookup that worked was {} min ago (journalctl -t burner)",
                            age.as_secs() / 60
                        ),
                    ),
                    None => r.line(
                        Level::Fail,
                        "public ip",
                        "net.block_public_ip is on but no address was found yet, so runs with a network are \
                         refused. the reaper looks it up (journalctl -t burner)",
                    ),
                }
            } else if natted && !public_block {
                r.line(
                    Level::Warn,
                    "router",
                    "this host is behind NAT. VMs can reach your router's public address, and from the inside \
                     that's often its admin page, its ssh or your port forwards. set net.block_public_ip = true \
                     to have burner look it up and block it, or put it in net.block yourself",
                );
            }
        }
        Ok(_) => r.line(
            Level::Fail,
            "uplink",
            format!("{uplink} has no ipv4 address"),
        ),
        Err(e) => r.line(Level::Fail, "uplink", format!("{uplink}: {e:#}")),
    }

    let Ok(subnet) = cfg.subnet() else { return };
    let clashes = routes()
        .into_iter()
        .filter(|(dst, dev)| dst.1 > 0 && !net::is_tap(dev) && config::overlaps(subnet, *dst))
        .map(|(dst, dev)| format!("{}/{} on {dev}", dst.0, dst.1))
        .collect::<Vec<_>>();
    if clashes.is_empty() {
        r.line(Level::Ok, "subnet", format!("{} is free", cfg.net.subnet));
    } else {
        r.line(
            Level::Fail,
            "subnet",
            format!(
                "{} overlaps {}, pick another net.subnet",
                cfg.net.subnet,
                clashes.join(", ")
            ),
        );
    }

    // a full-tunnel vpn: VMs either reach nothing or leave outside it
    let up = cfg.uplink().ok();
    for t in crate::explain::tunnel_notes(&net::tunnels_here(), up.as_deref()) {
        r.line(Level::Warn, "vpn", t);
    }
    let blocked = net::blocked_sources(cfg).ok();
    for (sev, msg) in
        net::resolver_checks(cfg, blocked.as_deref(), crate::netmodel::Platform::Linux)
    {
        r.line(level(sev), "dns", msg);
    }

    // ufw's forward policy drops VM traffic unless it has a rule for the subnet
    if is_root() {
        match net::ufw_rule_missing(cfg) {
            Ok(Some(cmd)) => r.line(
                Level::Warn,
                "firewall",
                format!("ufw is active and has no rule for burner: {cmd}"),
            ),
            Ok(None) if sys::which("ufw") => {
                r.line(Level::Ok, "firewall", "ufw allows the VM subnet out")
            }
            _ => {}
        }
    }

    if fs::read_to_string("/proc/sys/net/ipv4/ip_forward").is_ok_and(|v| v.trim() == "1") {
        r.line(Level::Ok, "forwarding", "ipv4 forwarding on");
    } else {
        r.line(
            Level::Warn,
            "forwarding",
            "ipv4 forwarding off, burner turns it on when it sets up the network",
        );
    }
}

fn level(s: net::Severity) -> Level {
    match s {
        net::Severity::Ok => Level::Ok,
        net::Severity::Warn => Level::Warn,
        net::Severity::Fail => Level::Fail,
    }
}

/// (destination, device) for every ipv4 route
fn routes() -> Vec<((std::net::Ipv4Addr, u8), String)> {
    let Some(out) = run_ok("ip", &["-j", "-4", "route", "show", "table", "all"]) else {
        return Vec::new();
    };
    let v: serde_json::Value = serde_json::from_str(&out).unwrap_or_default();
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|rt| {
            let dst = rt["dst"].as_str()?;
            let dev = rt["dev"].as_str().unwrap_or("-").to_string();
            let cidr = if dst.contains('/') {
                dst.to_string()
            } else {
                format!("{dst}/32")
            };
            config::parse_cidr(&cidr).ok().map(|c| (c, dev))
        })
        .collect()
}

fn memory(r: &mut Report, cfg: &Config) {
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let field = |name: &str| {
        meminfo
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
            .map(|kb| kb / 1024)
    };
    let (Some(total), Some(avail)) = (field("MemTotal:"), field("MemAvailable:")) else {
        r.line(Level::Warn, "memory", "couldn't read /proc/meminfo");
        return;
    };
    // guest RAM plus what each firecracker process may use on top
    let want = u64::from(cfg.limits.total_mem_mib)
        + u64::from(cfg.limits.max_vms) * crate::run::VMM_OVERHEAD_MIB;
    let level = if avail >= want + 512 {
        Level::Ok
    } else {
        Level::Warn
    };
    r.line(
        level,
        "memory",
        format!("{avail} MiB free of {total}, VMs may use up to {want} (limits.total_mem_mib + {} per VM)", crate::run::VMM_OVERHEAD_MIB),
    );
}

fn disk(r: &mut Report, cfg: &Config) {
    let dir = existing_parent(&cfg.paths.root);
    let Some(out) = run_ok("df", &["-Pm", &dir]) else {
        return;
    };
    let free = out
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok());
    // images + one full-size scratch disk per possible VM
    let want = 2048 + u64::from(cfg.limits.disk_gib) * 1024 * u64::from(cfg.limits.max_vms);
    match free {
        Some(f) if f >= want => r.line(Level::Ok, "disk", format!("{f} MiB free on {dir}")),
        Some(f) => r.line(
            Level::Warn,
            "disk",
            format!("{f} MiB free on {dir}, full-size VMs may need {want}"),
        ),
        None => r.line(
            Level::Warn,
            "disk",
            format!("couldn't read free space on {dir}"),
        ),
    }
}

fn install(r: &mut Report, cfg: &Config) {
    let root = &cfg.paths.root;
    for (what, rel) in [
        ("firecracker", "bin/firecracker"),
        ("jailer", "bin/jailer"),
        ("kernel", "kernel/vmlinux"),
    ] {
        let p = root.join(rel);
        if p.exists() {
            let ver = if rel.starts_with("bin/") {
                run_ok(&p.to_string_lossy(), &["--version"])
            } else {
                None
            };
            let detail = ver
                .and_then(|v| v.lines().next().map(str::to_string))
                .unwrap_or_else(|| p.display().to_string());
            r.line(Level::Ok, what, detail);
        } else {
            r.line(
                Level::Warn,
                what,
                format!("{} not installed yet", p.display()),
            );
        }
    }
    vm_uids(r, cfg);
    // the result parser's user: unprivileged, and never sharing an id with a VM
    let vms = cfg.vm_uids();
    match sys::user_ids(crate::result::PARSE_USER) {
        Some((u, g)) if u != 0 && g != 0 && !vms.contains(&u) && !vms.contains(&g) => {
            r.line(Level::Ok, "users", format!("burner-parse ({u})"))
        }
        Some(_) => r.line(
            Level::Fail,
            "users",
            "burner-parse must be a non-root user with a uid and gid outside the VM range",
        ),
        None => r.line(
            Level::Warn,
            "users",
            "burner-parse missing, install.sh creates it",
        ),
    }
    // images carry a copy of the guest init they were built with; one from an
    // older burner still runs the old init inside every VM
    let mut images = 0;
    for e in fs::read_dir(root.join("images"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if !e.path().join("rootfs.ext4").exists() {
            continue;
        }
        images += 1;
        let name = e.file_name().to_string_lossy().into_owned();
        if fs::read(e.path().join("init")).ok().as_deref() != Some(GUEST_INIT) {
            r.line(
                Level::Warn,
                "images",
                format!("{name} was built with a different guest init, rebuild it: tools/build-image {name}"),
            );
        }
    }
    if images > 0 {
        r.line(Level::Ok, "images", format!("{images} installed"));
    } else {
        r.line(Level::Warn, "images", "none installed yet");
    }
}

/// the uids and gids VMs run as must belong to nobody else: an account, a group
/// or a container's mapped uid with the same number could signal a VM's
/// firecracker or open its disks
fn vm_uids(r: &mut Report, cfg: &Config) {
    let ids = cfg.vm_uids();
    let mut clash = Vec::new();
    for db in ["passwd", "group"] {
        let keys: Vec<String> = ids.clone().map(|i| i.to_string()).collect();
        // by key, so accounts from ldap and the like count too. exit 2 means
        // some keys weren't found, the normal answer here
        let text = sys::run_timeout(
            Command::new("getent").arg(db).args(&keys),
            None,
            Duration::from_secs(30),
        )
        .ok()
        .filter(|o| matches!(o.status.code(), Some(0 | 2)))
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|| fs::read_to_string(format!("/etc/{db}")).unwrap_or_default());
        clash.extend(ids_in(&text, &ids).into_iter().map(|n| format!("{db} {n}")));
    }
    for f in ["/etc/subuid", "/etc/subgid"] {
        let text = fs::read_to_string(f).unwrap_or_default();
        clash.extend(
            sub_ranges_in(&text, &ids)
                .into_iter()
                .map(|n| format!("{n} in {f}")),
        );
    }
    let range = format!("{}-{}", ids.start, ids.end - 1);
    if clash.is_empty() {
        r.line(
            Level::Ok,
            "vm uids",
            format!("{range}, nothing else uses them"),
        );
    } else {
        clash.truncate(5);
        r.line(
            Level::Fail,
            "vm uids",
            format!(
                "{range} is partly taken ({}), pick another jail.uid_base",
                clash.join(", ")
            ),
        );
    }
}

/// "name id" for each passwd or group line whose id is in `ids`
fn ids_in(text: &str, ids: &std::ops::Range<u32>) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let id: u32 = f.get(2)?.parse().ok()?;
            ids.contains(&id).then(|| format!("{} {id}", f[0]))
        })
        .collect()
}

/// names in a subuid or subgid file whose range overlaps `ids`
fn sub_ranges_in(text: &str, ids: &std::ops::Range<u32>) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let start: u64 = f.get(1)?.trim().parse().ok()?;
            let count: u64 = f.get(2)?.trim().parse().ok()?;
            (start < u64::from(ids.end) && start + count > u64::from(ids.start))
                .then(|| f[0].to_string())
        })
        .collect()
}

/// the parts that only exist once burner is installed and running: the reaper,
/// the VM network, and a forward policy that lets VM traffic out at all
fn services(r: &mut Report, cfg: &Config) {
    let timer = run_ok("systemctl", &["is-active", "burner-reap.timer"]).is_some();
    match (timer, crate::run::reaper_age(cfg)) {
        (true, Some(a)) if a.as_secs() <= 120 => r.line(
            Level::Ok,
            "reaper",
            format!("last ran {}s ago", a.as_secs()),
        ),
        (true, _) => r.line(
            Level::Fail,
            "reaper",
            "timer is on but hasn't finished a pass in 2 min, see journalctl -u burner-reap",
        ),
        (false, _) => r.line(
            Level::Fail,
            "reaper",
            "burner-reap.timer isn't running; VMs with a network are refused until it is",
        ),
    }
    if net::table_exists() && net::routing_ok(cfg) {
        r.line(Level::Ok, "vm network", "filter and routing table loaded");
    } else {
        r.line(
            Level::Warn,
            "vm network",
            "not set up, see systemctl status burner-net (or run burner net up)",
        );
    }
    // docker and some firewalls set the forward policy to drop; then VM traffic
    // needs its own accept rule, which ufw's route rule provides
    let drops = run_ok("nft", &["list", "chain", "ip", "filter", "FORWARD"])
        .is_some_and(|c| c.contains("policy drop"));
    let ufw_ok = matches!(net::ufw_rule_missing(cfg), Ok(None))
        && run_ok("ufw", &["status"]).is_some_and(|s| s.contains("Status: active"));
    // or someone already added accept rules for the subnet (docker's DOCKER-USER chain)
    let own_rule = run_ok("nft", &["list", "table", "ip", "filter"]).is_some_and(|t| {
        t.contains(&format!("ip saddr {}", cfg.net.subnet)) && t.contains("accept")
    });
    if drops && !ufw_ok && !own_rule {
        let up = cfg.uplink().unwrap_or_else(|_| "UPLINK".into());
        r.line(
            Level::Warn,
            "forwarding",
            format!(
                "the FORWARD policy is drop (docker sets this), VM traffic may never leave. allow it with:\n  iptables -I DOCKER-USER -s {s} -o {up} -j ACCEPT\n  iptables -I DOCKER-USER -d {s} -i {up} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                s = cfg.net.subnet
            ),
        );
    }
}

fn existing_parent(p: &Path) -> String {
    p.ancestors()
        .find(|a| a.exists())
        .unwrap_or(Path::new("/"))
        .display()
        .to_string()
}

fn run_ok(cmd: &str, args: &[&str]) -> Option<String> {
    let out = sys::run_timeout(Command::new(cmd).args(args), None, Duration::from_secs(30)).ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taken_ids() {
        let ids = 400_000..401_024;
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      odd:x:400005:100::/:/bin/sh\n\
                      past:x:401024:100::/:/bin/sh\n\
                      broken line\n";
        assert_eq!(ids_in(passwd, &ids), vec!["odd 400005"]);
        let group = "kvm:x:992:\nfirst:x:400000:\n";
        assert_eq!(ids_in(group, &ids), vec!["first 400000"]);
        // useradd's fifth subuid range runs 362144-427679
        let subuid = "alice:100000:65536\nbob:362144:65536\nend:399000:1000\nafter:401024:65536\n";
        assert_eq!(sub_ranges_in(subuid, &ids), vec!["bob"]);
        assert!(sub_ranges_in("", &ids).is_empty());
    }

    const PROXMOX_DEFAULT: &str = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: QEMU Virtual CPU version 2.5+\n\
        flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep hypervisor lahf_lm\n\nprocessor\t: 1\n";
    const HOST_TYPE: &str = "model name\t: Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz\n\
        flags\t\t: fpu vme de vmx ssse3 hypervisor\n";
    const BARE_AMD: &str =
        "model name\t: AMD Ryzen 7 5800X 8-Core Processor\nflags\t\t: fpu svm sse4a\n";
    const BIOS_OFF: &str = "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4\nflags\t\t: fpu sse4_2\n";

    #[test]
    fn why_no_kvm() {
        let m = no_kvm(PROXMOX_DEFAULT, true);
        assert!(
            m.contains("this VM's cpu type (QEMU Virtual CPU version 2.5+) hides virtualization"),
            "{m}"
        );
        assert!(m.contains("qm set ID --cpu host"), "{m}");
        assert!(
            no_kvm(HOST_TYPE, true)
                .contains("cpu has vmx: the kvm module isn't loaded (modprobe kvm_intel)")
        );
        assert!(no_kvm(BARE_AMD, true).contains("modprobe kvm_amd"));
        let m = no_kvm(BIOS_OFF, true);
        assert!(
            m.contains("(Intel(R) Xeon(R) CPU E5-2680 v4) shows no vmx or svm"),
            "{m}"
        );
        assert!(no_kvm("", false).contains("firmware"));
        assert!(no_kvm("", true).contains("(unknown)"));
        assert!(cpu_flag(HOST_TYPE, "hypervisor") && !cpu_flag(BIOS_OFF, "hypervisor"));
    }

    #[test]
    fn containers() {
        assert_eq!(in_container(Some("lxc\n"), b"", false), Some("lxc".into()));
        assert_eq!(
            in_container(None, b"PATH=/bin\0container=podman\0TERM=xterm\0", false),
            Some("podman".into())
        );
        assert_eq!(
            in_container(None, b"", true),
            Some("docker or podman".into())
        );
        assert_eq!(in_container(Some(""), b"HOME=/\0container=\0", false), None);
        assert_eq!(in_container(None, b"PATH=/bin\0", false), None);
    }
}
