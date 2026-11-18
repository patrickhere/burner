//! `burner doctor`: can this machine run burner, and if not, what to fix.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::config::{self, Config};
use crate::net;
use crate::sys;

const GUEST_INIT: &[u8] = include_bytes!("../../guest/init");

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum Level {
    Ok,
    Warn,
    Fail,
}

struct Report {
    worst: Level,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, detail: impl AsRef<str>) {
        let tag = match level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        println!("{tag}  {what:<12} {}", detail.as_ref());
        self.worst = self.worst.max(level);
    }
}

/// returns true when nothing failed
pub fn run(cfg: &Config) -> bool {
    let mut r = Report { worst: Level::Ok };
    let root = is_root();
    if !root {
        r.line(
            Level::Warn,
            "user",
            "not root, some checks are skipped (run with sudo for all of them)",
        );
    }

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

    println!();
    match r.worst {
        Level::Ok => println!("all good"),
        Level::Warn => println!("works, see the warnings above"),
        Level::Fail => println!("not ready, fix the FAIL lines first"),
    }
    r.worst != Level::Fail
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
        Err(_) => r.line(
            Level::Fail,
            "kvm",
            "no /dev/kvm. enable virtualization in the bios, or nested virt if this is a VM",
        ),
    }
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    if cpuinfo
        .lines()
        .any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor"))
    {
        r.line(
            Level::Warn,
            "nested",
            "this machine is itself a VM: VMs run nested, slower and at the host's mercy",
        );
    }
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
            if natted && !public_block {
                r.line(
                    Level::Warn,
                    "router",
                    "this host is behind NAT. VMs can reach your router's public address, and from the inside \
                     that's often its admin page, its ssh or your port forwards. put that address in net.block \
                     (curl ifconfig.me shows it; update it if it changes)",
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
    // the VM user and the result parser's user: both unprivileged, never the same
    let vm = sys::user_ids(crate::run::USER);
    let parse = sys::user_ids(crate::result::PARSE_USER);
    match (vm, parse) {
        (Some((a, _)), Some((b, _))) if a != 0 && b != 0 && a != b => r.line(
            Level::Ok,
            "users",
            format!("burner ({a}), burner-parse ({b})"),
        ),
        (Some(_), Some(_)) => r.line(
            Level::Fail,
            "users",
            "burner and burner-parse must be two different non-root users",
        ),
        _ => r.line(
            Level::Warn,
            "users",
            "burner or burner-parse missing, install.sh creates them",
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
