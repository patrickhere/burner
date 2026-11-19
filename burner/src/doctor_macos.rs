//! `burner doctor` on macOS: can this mac run burner, and if not, what to fix.

use crate::config::{self, Config};
use crate::sys;

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
    if sys::is_root() {
        r.line(Level::Fail, "user", "on macOS burner runs as you, not root");
    }
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
    let kernel = cfg.paths.root.join("kernel/vmlinux");
    match std::fs::canonicalize(&kernel) {
        Ok(k) => match config::trusted_file(&k) {
            Ok(()) => r.line(Level::Ok, "kernel", k.display().to_string()),
            Err(e) => r.line(Level::Fail, "kernel", format!("{e:#}")),
        },
        Err(_) => r.line(
            Level::Fail,
            "kernel",
            format!("no kernel at {}", kernel.display()),
        ),
    }
    let images = crate::run::images(cfg);
    if images.is_empty() {
        r.line(Level::Fail, "images", "none installed yet");
    } else {
        r.line(Level::Ok, "images", images.join(", "));
    }
    match sys::free_bytes(&cfg.paths.root) {
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
    r.line(
        Level::Warn,
        "network",
        "VMs on macOS have no network yet, only --net none",
    );

    println!();
    match r.worst {
        Level::Ok => println!("all good"),
        Level::Warn => println!("works, see the warnings above"),
        Level::Fail => println!("not ready, fix the FAIL lines first"),
    }
    r.worst != Level::Fail
}
