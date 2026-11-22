//! `burner run`: boot a VM, run one command in it, hand back the output and
//! exit code, delete the VM. the VM's console, disks and result are hostile;
//! the caller is trusted but may be sloppy (stdin that never closes, a reader
//! that stops reading).

// lock order, all flocks under paths.state: reap.lock (held for a whole reaper
// pass), then net.lock, then ledger.lock. disk.lock and parse.lock are only
// taken with no other lock held

use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::json::Kind;
use crate::sys;

mod admin;
mod console;
mod launch;
mod netwire;
mod plan;
pub mod record;

#[cfg(target_os = "linux")]
pub use admin::reaper_age;
pub use admin::{kill, log, ls, reap};
pub(crate) use console::Escape;
#[cfg(target_os = "linux")]
pub use launch::VMM_OVERHEAD_MIB;
#[cfg(target_os = "macos")]
pub use launch::mkfs_bin;
pub use launch::{GUEST_PROTO, VMM, check_fds, config_failed, finished, json_target, main, refuse};

/// the line the network log's reader writes first
pub fn netlog_ready() -> &'static str {
    netwire::READY
}
pub use plan::{RunArgs, ShellArgs, images, images_result, shell_main, shell_run_args, valid_name};

pub use crate::exit::{EXIT_INTERRUPTED, EXIT_SANDBOX, EXIT_TIMEOUT, EXIT_USAGE};

/// an error with the exit code it should end the run with, and its kind
#[derive(Debug)]
struct Exit(u8, Kind, String);

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.2)
    }
}

impl std::error::Error for Exit {}

fn exit(code: u8, kind: Kind, msg: impl Into<String>) -> anyhow::Error {
    Exit(code, kind, msg.into()).into()
}

fn usage(msg: impl Into<String>) -> anyhow::Error {
    exit(EXIT_USAGE, Kind::Usage, msg)
}

/// SIGINT, SIGTERM and SIGHUP so far. a count, not a flag: a wait that starts
/// late can still tell a signal that came after it from one before
static SIGNALS: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn interrupted() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ] {
            // SAFETY: the handler only does an atomic add, which is async-signal-safe
            let _ = unsafe {
                signal_hook::low_level::register(sig, || {
                    SIGNALS.fetch_add(1, Ordering::Relaxed);
                })
            };
        }
    });
}

fn signals() -> usize {
    SIGNALS.load(Ordering::Relaxed)
}

/// burner -H on the far end: when sshd loses the client it closes the
/// session's pipes but sends the command no signal (a shell has a pty, whose
/// hangup does). so a stdout or stderr that hung up counts as a SIGHUP, and
/// the run stops as it would on ctrl-c
pub(crate) fn watch_peer() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::thread::spawn(|| {
            loop {
                if sys::hung_up(&[1, 2]) {
                    SIGNALS.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        });
    });
}

/// SIGINT, SIGTERM and SIGHUP count from here on instead of ending burner
pub fn catch_signals() {
    interrupted()
}

pub fn is_interrupted() -> bool {
    signals() > 0
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
