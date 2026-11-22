//! `burner doctor` on macOS: can this mac run burner, and if not, what to fix.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Serialize;

use crate::config::{self, Config};
use crate::json;
use crate::sys;

/// the guest init this burner speaks to, what burner setup records next to an
/// image from its own release
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

pub fn run(cfg: &Config, config_path: &Path) -> Report {
    let mut r = Report {
        root: false,
        worst: Level::Ok,
        checks: Vec::new(),
    };
    if sys::is_root() {
        r.line(Level::Fail, "user", "on macOS burner runs as you, not root");
    }
    if cfg!(not(target_arch = "aarch64")) {
        r.line(Level::Fail, "cpu", "burner on macOS needs apple silicon");
    }
    hypervisor(&mut r);
    match crate::krun::probe() {
        Ok(path) => match crate::krun::version(&path) {
            Some(v) if v >= crate::krun::MIN_VERSION => {
                r.line(Level::Ok, "libkrun", format!("{}, {path}", dotted(v)))
            }
            Some(v) => r.line(
                Level::Warn,
                "libkrun",
                format!(
                    "{} is older than {}, the oldest burner was tested with: brew upgrade libkrun ({path})",
                    dotted(v),
                    dotted(crate::krun::MIN_VERSION)
                ),
            ),
            None => r.line(
                Level::Warn,
                "libkrun",
                format!("{path}, can't tell its version"),
            ),
        },
        Err(e) => r.line(
            Level::Fail,
            "libkrun",
            format!("{e}, brew reinstall libkrun"),
        ),
    }
    let mkfs = crate::run::mkfs_bin();
    if mkfs.is_file() {
        r.line(Level::Ok, "mkfs.ext4", mkfs.display().to_string());
    } else {
        r.line(
            Level::Fail,
            "mkfs.ext4",
            "not found, brew install e2fsprogs",
        );
    }

    // Config::load already refused a config anyone else could have written
    if config_path.exists() {
        r.line(
            Level::Ok,
            "config",
            format!("{}, only you can change it", config_path.display()),
        );
    } else {
        r.line(
            Level::Ok,
            "config",
            format!("none at {}, defaults", config_path.display()),
        );
    }
    let root = &cfg.paths.root;
    match config::trusted_file(root) {
        Ok(()) => r.line(Level::Ok, "root", root.display().to_string()),
        Err(e) => r.line(
            Level::Fail,
            "root",
            format!("{e:#}, chmod go-w it or set paths.root"),
        ),
    }
    kernel(&mut r, &root.join("kernel/vmlinux"));
    images(&mut r, cfg);

    match sys::free_bytes(root) {
        Ok(f) => {
            let (f, want) = (
                f >> 20,
                2048 + u64::from(cfg.limits.disk_gib) * 1024 * u64::from(cfg.limits.max_vms),
            );
            if f >= want {
                r.line(Level::Ok, "disk", format!("{f} MiB free"));
            } else {
                r.line(
                    Level::Warn,
                    "disk",
                    format!("{f} MiB free, full-size VMs may need {want}"),
                );
            }
        }
        Err(e) => r.line(
            Level::Warn,
            "disk",
            format!("couldn't read free space ({e})"),
        ),
    }
    match crate::macnet::probe() {
        Ok(()) => r.line(
            Level::Ok,
            "network",
            "burner macnet starts in its sandbox (no ping or non-dns udp on macOS)",
        ),
        Err(e) => r.line(
            Level::Fail,
            "network",
            format!("burner macnet won't start: {e}. --net none still works"),
        ),
    }
    network(&mut r, cfg);
    headless(&mut r);

    if !json::on() {
        println!();
        match r.worst {
            Level::Ok => println!("all good"),
            Level::Warn => println!("works, see the warnings above"),
            Level::Fail => println!("not ready, fix the FAIL lines first"),
        }
    }
    r.root = sys::is_root();
    r
}

/// the way out: NAT and the router, a full-tunnel vpn, and resolvers VMs
/// can use. the same lines linux doctor has
fn network(r: &mut Report, cfg: &Config) {
    use crate::net;
    let Some(up) = crate::explain::mac_uplink() else {
        r.line(
            Level::Warn,
            "uplink",
            "no default route right now, so VMs with a network can't reach anything",
        );
        return;
    };
    let list: Vec<String> = up.addrs.iter().map(|a| a.to_string()).collect();
    let gw = up
        .gateway
        .map_or_else(String::new, |g| format!(", default route via {g}"));
    r.line(
        Level::Ok,
        "uplink",
        format!("{} ({}){gw}", up.dev, list.join(", ")),
    );
    // behind NAT the router's public address is just "internet" to macnet,
    // and from inside it's often the router's admin page or a port forward
    let natted = up
        .addrs
        .iter()
        .all(|ip| ip.is_private() || ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64);
    let public_block =
        cfg.net.block.iter().any(|b| {
            config::parse_cidr(b).is_ok_and(|(ip, _)| !ip.is_private() && !ip.is_loopback())
        });
    if cfg.net.block_public_ip {
        match net::public_ip(cfg) {
            Some((ip, age)) => r.line(
                Level::Ok,
                "public ip",
                format!("{ip} is blocked, looked up {} min ago on this network", age.as_secs() / 60),
            ),
            None => r.line(
                Level::Ok,
                "public ip",
                "net.block_public_ip is on, not looked up on this network yet: burner run looks it up first",
            ),
        }
    } else if natted && !public_block && !up.addrs.is_empty() {
        r.line(
            Level::Warn,
            "router",
            "this mac is behind NAT. VMs can reach your router's public address, and from the inside \
             that's often its admin page, its ssh or your port forwards. set net.block_public_ip = true \
             to have burner look it up and block it, or put it in net.block yourself",
        );
    }
    for t in crate::explain::tunnel_notes(&crate::macnet::route::tunnels_here(), None) {
        r.line(Level::Warn, "vpn", t);
    }
    let blocked = crate::explain::mac_sources(cfg).ok();
    for (sev, msg) in net::resolver_checks(cfg, blocked.as_deref(), crate::netmodel::Platform::Mac)
    {
        let level = match sev {
            net::Severity::Ok => Level::Ok,
            net::Severity::Warn => Level::Warn,
            net::Severity::Fail => Level::Fail,
        };
        r.line(level, "dns", msg);
    }
}

/// what matters for a mac nobody sits at: who's at the console, sleep,
/// FileVault after a reboot, and a quarantined burner
fn headless(r: &mut Report) {
    match console_user() {
        Some(u) if u == "root" => r.line(
            Level::Ok,
            "session",
            "nobody logged in at the mac. VMs run over ssh and from a LaunchDaemon anyway",
        ),
        Some(u) => r.line(Level::Ok, "session", format!("{u} at the console")),
        None => {}
    }

    let pmset = output(Command::new("/usr/bin/pmset").arg("-g"));
    match pmset.as_deref().and_then(idle_sleep) {
        Some(0) => r.line(Level::Ok, "sleep", "idle sleep off"),
        Some(m) => r.line(
            Level::Warn,
            "sleep",
            format!(
                "the mac sleeps after {m} min idle, and VMs freeze while it sleeps. \
                 burner keeps it awake while its VMs run, but ssh can't wake it: \
                 sudo pmset -a sleep 0 for a mac you reach over -H"
            ),
        ),
        None => r.line(Level::Warn, "sleep", "couldn't read pmset -g"),
    }

    let fv = output(Command::new("/usr/bin/fdesetup").arg("status"));
    let major = crate::sys::macos_version().as_deref().and_then(major);
    match (fv.as_deref().and_then(filevault_on), major) {
        (Some(true), Some(v)) if v < 26 => r.line(
            Level::Warn,
            "filevault",
            "on: after a reboot ssh and burner only come back once someone types \
             the FileVault password at the mac (macOS 26 takes it over ssh). \
             planned reboots: sudo fdesetup authrestart",
        ),
        (Some(true), _) => r.line(
            Level::Ok,
            "filevault",
            "on, macOS 26 and later take its password over ssh after a reboot",
        ),
        (Some(false), _) => r.line(Level::Ok, "filevault", "off"),
        (None, _) => {}
    }

    let mut files = vec![sys::self_exe()];
    if let Ok(k) = crate::krun::probe() {
        files.push(k.into());
    }
    let marked: Vec<String> = files
        .iter()
        .filter(|f| quarantined(f))
        .map(|f| f.display().to_string())
        .collect();
    if marked.is_empty() {
        r.line(Level::Ok, "quarantine", "not on burner or libkrun");
    } else {
        r.line(
            Level::Warn,
            "quarantine",
            format!(
                "{} has com.apple.quarantine (a browser download). it ran anyway over ssh \
                 on macOS 27, other versions may refuse it: xattr -d com.apple.quarantine {}",
                marked.join(", "),
                marked.join(" ")
            ),
        );
    }
}

/// stdout of a short command that worked
fn output(cmd: &mut Command) -> Option<String> {
    let o = sys::run_timeout(cmd, None, Duration::from_secs(10)).ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// who owns /dev/console: root while the mac sits at the login window
fn console_user() -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/dev/console").ok()?.uid();
    // SAFETY: getpwuid's result is read before anything else calls it
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return Some(uid.to_string());
        }
        Some(
            std::ffi::CStr::from_ptr((*pw).pw_name)
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// pmset -g's idle sleep timer in minutes, 0 when it never sleeps
fn idle_sleep(pmset: &str) -> Option<u32> {
    pmset.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next() == Some("sleep"))
            .then(|| w.next()?.parse().ok())
            .flatten()
    })
}

/// fdesetup status: "FileVault is On." or "FileVault is Off."
fn filevault_on(status: &str) -> Option<bool> {
    let l = status.lines().next()?;
    if l.starts_with("FileVault is On") {
        Some(true)
    } else if l.starts_with("FileVault is Off") {
        Some(false)
    } else {
        None
    }
}

fn major(version: &str) -> Option<u32> {
    version.split('.').next()?.parse().ok()
}

fn quarantined(f: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(p) = std::ffi::CString::new(f.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: a size-only getxattr on a NUL-terminated path
    unsafe {
        libc::getxattr(
            p.as_ptr(),
            c"com.apple.quarantine".as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            0,
        ) >= 0
    }
}

fn dotted(v: [u32; 3]) -> String {
    format!("{}.{}.{}", v[0], v[1], v[2])
}

fn hypervisor(r: &mut Report) {
    let mut hv = [0u8; 4];
    let mut len = hv.len();
    // SAFETY: valid name, a 4-byte buffer for an int, no new value
    let ok = unsafe {
        libc::sysctlbyname(
            c"kern.hv_support".as_ptr(),
            hv.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;
    if ok && i32::from_ne_bytes(hv) == 1 {
        r.line(Level::Ok, "hypervisor", "hypervisor.framework available");
    } else {
        r.line(
            Level::Fail,
            "hypervisor",
            "no hypervisor.framework (kern.hv_support), burner can't start VMs here",
        );
        return;
    }
    // without the entitlement hypervisor.framework refuses to make a VM
    let exe = sys::self_exe();
    let out = sys::run_timeout(
        Command::new("codesign")
            .args(["-d", "--entitlements", "-", "--xml"])
            .arg(&exe),
        None,
        Duration::from_secs(30),
    );
    match out {
        Ok(o)
            if o.status.success()
                && String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor") =>
        {
            r.line(Level::Ok, "entitlement", "signed for hypervisor.framework")
        }
        Ok(_) => r.line(
            Level::Fail,
            "entitlement",
            format!(
                "{} isn't signed with com.apple.security.hypervisor, brew reinstall burner (or codesign it with that entitlement)",
                exe.display()
            ),
        ),
        Err(e) => r.line(
            Level::Warn,
            "entitlement",
            format!("couldn't run codesign to check ({e})"),
        ),
    }
}

fn kernel(r: &mut Report, link: &Path) {
    let k = match std::fs::canonicalize(link) {
        Ok(k) => k,
        Err(_) => {
            return r.line(
                Level::Fail,
                "kernel",
                format!("none at {}, run burner setup", link.display()),
            );
        }
    };
    if let Err(e) = config::trusted_file(&k) {
        return r.line(Level::Fail, "kernel", format!("{e:#}"));
    }
    // an arm64 Image has "ARM\x64" at byte 56
    let mut head = [0u8; 64];
    match File::open(&k).and_then(|mut f| f.read_exact(&mut head)) {
        Ok(()) if head[56..60] == *b"ARM\x64" => {
            r.line(Level::Ok, "kernel", k.display().to_string())
        }
        Ok(()) => r.line(
            Level::Fail,
            "kernel",
            format!(
                "{} isn't an arm64 kernel image, run burner setup",
                k.display()
            ),
        ),
        Err(e) => r.line(
            Level::Fail,
            "kernel",
            format!("can't read {} ({e}), run burner setup", k.display()),
        ),
    }
}

fn images(r: &mut Report, cfg: &Config) {
    let names = crate::run::images(cfg);
    if names.is_empty() {
        return r.line(Level::Fail, "images", "none installed, run burner setup");
    }
    let mut good = Vec::new();
    for n in names {
        let f = cfg.paths.root.join("images").join(&n).join("rootfs.ext4");
        let checked = std::fs::canonicalize(&f)
            .map_err(anyhow::Error::from)
            .and_then(|real| {
                config::trusted_file(&real)?;
                // the ext4 superblock magic, 0xef53 at byte 1080
                let mut magic = [0u8; 2];
                File::open(&real)?.read_exact_at(&mut magic, 1080)?;
                anyhow::ensure!(magic == [0x53, 0xef], "{} isn't ext4", real.display());
                Ok(())
            });
        match checked {
            Ok(()) => good.push(n),
            Err(e) => r.line(Level::Fail, "images", format!("{n}: {e:#}")),
        }
    }
    if !good.is_empty() {
        r.line(Level::Ok, "images", good.join(", "));
    }
    // burner shell still works with these, but sends keys typed during boot
    // before the guest is ready for them
    let other: Vec<String> = crate::run::images(cfg)
        .into_iter()
        .filter(|n| {
            std::fs::read(cfg.paths.root.join("images").join(n).join("init"))
                .ok()
                .as_deref()
                != Some(GUEST_INIT)
        })
        .collect();
    if !other.is_empty() {
        r.line(
            Level::Warn,
            "images",
            format!(
                "{} not from this burner's guest init, {}",
                other.join(", "),
                crate::setup::fix_hint(&other)
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pmset() {
        let out = "System-wide power settings:\nCurrently in use:\n standby              0\n \
                   Sleep On Power Button 1\n SleepServices        0\n disksleep            10\n \
                   sleep                0 (sleep prevented by powerd, mds)\n displaysleep         10\n";
        assert_eq!(idle_sleep(out), Some(0));
        assert_eq!(idle_sleep(" displaysleep 10\n sleep 1\n"), Some(1));
        assert_eq!(idle_sleep(" displaysleep 10\n"), None);
    }

    #[test]
    fn reads_fdesetup_and_versions() {
        assert_eq!(filevault_on("FileVault is On.\n"), Some(true));
        assert_eq!(filevault_on("FileVault is Off.\n"), Some(false));
        assert_eq!(filevault_on("Error: something\n"), None);
        assert_eq!(major("27.0.1"), Some(27));
        assert_eq!(major("15.7"), Some(15));
        assert_eq!(major(""), None);
    }
}
