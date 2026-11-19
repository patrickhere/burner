//! `burner run`: boot a VM, run one command in it, hand back the output and
//! exit code, delete the VM. the VM's console, disks and result are hostile;
//! the caller is trusted but may be sloppy (stdin that never closes, a reader
//! that stops reading).

// lock order, all flocks under paths.state: reap.lock (held for a whole reaper
// pass), then net.lock, then ledger.lock. disk.lock and parse.lock are only
// taken with no other lock held

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::sys;

mod admin;
mod console;
mod launch;
mod plan;

#[cfg(target_os = "linux")]
pub use admin::reaper_age;
pub use admin::{kill, ls, reap};
#[cfg(target_os = "linux")]
pub use launch::VMM_OVERHEAD_MIB;
pub use launch::main;
#[cfg(target_os = "macos")]
pub use launch::mkfs_bin;
pub use plan::{RunArgs, ShellArgs, images, shell_main};

pub const EXIT_USAGE: u8 = 2;
pub const EXIT_TIMEOUT: u8 = 124;
pub const EXIT_SANDBOX: u8 = 125;
pub const EXIT_INTERRUPTED: u8 = 130;

/// an error with the exit code it should end the run with
#[derive(Debug)]
struct Exit(u8, String);

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for Exit {}

fn usage(msg: impl Into<String>) -> anyhow::Error {
    Exit(EXIT_USAGE, msg.into()).into()
}

fn interrupted() -> &'static Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| {
        let f = Arc::new(AtomicBool::new(false));
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ] {
            let _ = signal_hook::flag::register(sig, f.clone());
        }
        f
    })
}

fn is_interrupted() -> bool {
    interrupted().load(Ordering::Relaxed)
}

/// a point in boot time (CLOCK_BOOTTIME, keeps counting through suspend). the
/// same value goes in the ledger, so burner and the reaper agree on when a VM ends
#[derive(Clone, Copy)]
struct Deadline(f64);

impl Deadline {
    fn in_secs(secs: u32) -> Deadline {
        Deadline(sys::boottime() + f64::from(secs))
    }
    fn passed(self) -> bool {
        sys::boottime() >= self.0
    }
    fn left(self) -> Duration {
        Duration::from_secs_f64((self.0 - sys::boottime()).max(0.0))
    }
}

enum Outcome {
    /// the caller typed ~. in burner shell
    Detached,
    Done,
    Failed,
    Timeout,
    Cancelled,
    Interrupted,
}
