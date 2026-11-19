//! `burner doctor` on macOS: can this mac run burner, and if not, what to fix.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::config::{self, Config};
use crate::sys;

/// the guest init this burner speaks to, what burner setup records next to an
/// image from its own release
pub const GUEST_INIT: &[u8] = include_bytes!("../guest-init");

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
pub fn run(cfg: &Config, config_path: &Path) -> bool {
    let mut r = Report { worst: Level::Ok };
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

    println!();
    match r.worst {
        Level::Ok => println!("all good"),
        Level::Warn => println!("works, see the warnings above"),
        Level::Fail => println!("not ready, fix the FAIL lines first"),
    }
    r.worst != Level::Fail
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
                "{} not from this burner's guest init, burner setup fetches one that is",
                other.join(", ")
            ),
        );
    }
}
