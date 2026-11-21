//! one run's connection log while it's being recorded: the producer (the
//! nflog reader on linux, macnet on macOS), the thread that folds its lines,
//! and what happens at the end. the log never decides anything about the
//! run but this: on linux, a reader that dies while the VM runs stops the
//! VM, so nothing goes unrecorded

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::net::Mode;
use crate::netlog::{Collector, LINE_CAP, NetLog};
#[cfg(target_os = "linux")]
use crate::netmodel::Model;
use crate::netmodel::Platform;

/// what the run says when the reader went away under a running VM
pub const READER_DIED: &str =
    "the network log reader stopped, VM stopped so nothing goes unrecorded";

struct Live {
    id: String,
    mode: Mode,
    platform: Platform,
    started_unix: u64,
    coll: Arc<Mutex<Option<Collector>>>,
    last: Arc<Mutex<Instant>>,
    stopping: Arc<AtomicBool>,
    died: Arc<AtomicBool>,
    child: Option<Child>,
    thread: Option<JoinHandle<()>>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

fn live<T>(f: impl FnOnce(&mut Option<Live>) -> T) -> T {
    let mut g = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

// macnet's events come in through here too, later
#[cfg_attr(target_os = "macos", allow(dead_code))]
/// read a producer's lines into the collector until it closes. lines past
/// the cap are skipped to their end and counted
fn pump(
    src: impl Read,
    coll: Arc<Mutex<Option<Collector>>>,
    last: Arc<Mutex<Instant>>,
    on_eof: impl FnOnce(),
) {
    let mut r = BufReader::with_capacity(64 << 10, src);
    let mut buf = Vec::with_capacity(LINE_CAP + 1);
    loop {
        buf.clear();
        match (&mut r)
            .take(LINE_CAP as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let now = Instant::now();
        *last.lock().unwrap_or_else(|e| e.into_inner()) = now;
        let mut g = coll.lock().unwrap_or_else(|e| e.into_inner());
        let Some(c) = g.as_mut() else { continue };
        if buf.last() != Some(&b'\n') {
            c.invalid += 1;
            drop(g);
            // the rest of an overlong line
            let mut skip = Vec::new();
            loop {
                skip.clear();
                match (&mut r).take(64 << 10).read_until(b'\n', &mut skip) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if skip.last() == Some(&b'\n') => break,
                    Ok(_) => {}
                }
            }
            continue;
        }
        match std::str::from_utf8(&buf[..buf.len() - 1]) {
            Ok(s) => c.take(s, now),
            Err(_) => c.invalid += 1,
        }
    }
    on_eof();
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// linux, as root, before the slot's tap exists: bind the slot's nflog group,
/// start the reader as burner-parse, and fold what it says. any failure is
/// the run's: no network without a log
#[cfg(target_os = "linux")]
pub(super) fn start_linux(cfg: &Config, id: &str, i: u32, mode: Mode) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use anyhow::Context;

    let s = crate::net::slot(cfg, i)?;
    let model = Model::new(
        cfg,
        mode,
        Platform::Linux,
        crate::net::blocked_sources(cfg).context("the network log's view of this host")?,
    );
    let (pu, pg) = crate::sys::user_ids(crate::result::PARSE_USER)
        .with_context(|| format!("no {} user, see burner doctor", crate::result::PARSE_USER))?;
    let sock = crate::nflog::bind(crate::net::log_group(i)).context("the network log")?;
    let parent = std::process::id() as libc::pid_t;
    let mut cmd = Command::new(crate::sys::self_exe());
    cmd.arg(crate::nflog::READ_ARG)
        .stdin(Stdio::from(sock))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .current_dir("/")
        .uid(pu)
        .gid(pg);
    // SAFETY: setrlimit, prctl and getppid only, all async-signal-safe
    unsafe {
        cmd.pre_exec(move || {
            crate::sys::limit_child(&[
                (libc::RLIMIT_AS, 64 << 20),
                (libc::RLIMIT_NOFILE, 8),
                (libc::RLIMIT_NPROC, 0),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 0),
            ])?;
            // never outlives the run, even one killed with SIGKILL
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent
            {
                return Err(std::io::Error::other("parent gone"));
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("starting the network log reader")?;
    let out = child.stdout.take().context("the reader's pipe")?;
    let coll = Arc::new(Mutex::new(Some(Collector::new(
        model,
        s.guest,
        Instant::now(),
    ))));
    let last = Arc::new(Mutex::new(Instant::now()));
    let stopping = Arc::new(AtomicBool::new(false));
    let died = Arc::new(AtomicBool::new(false));
    let thread = {
        let (coll, last, stopping, died, id) = (
            coll.clone(),
            last.clone(),
            stopping.clone(),
            died.clone(),
            id.to_string(),
        );
        std::thread::spawn(move || {
            pump(out, coll, last, || {
                if !stopping.load(Ordering::SeqCst) {
                    died.store(true, Ordering::SeqCst);
                    crate::cgroup::kill(&id);
                    super::admin::log_line(&format!("{id}: {READER_DIED}"));
                }
            })
        })
    };
    live(|l| {
        *l = Some(Live {
            id: id.into(),
            mode,
            platform: Platform::Linux,
            started_unix: unix_now(),
            coll,
            last,
            stopping,
            died,
            child: Some(child),
            thread: Some(thread),
        })
    });
    Ok(())
}

/// the VM is gone: let the last messages in (the reader flushes every 10 ms),
/// then stop the reader, so it never overlaps the result parser
pub(super) fn stop() {
    let Some((last, stopping)) = live(|l| l.as_ref().map(|l| (l.last.clone(), l.stopping.clone())))
    else {
        return;
    };
    stopping.store(true, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        let quiet = last
            .lock()
            .map(|t| t.elapsed() > Duration::from_millis(50))
            .unwrap_or(true);
        if quiet {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    live(|l| {
        if let Some(c) = l.as_mut().and_then(|l| l.child.as_mut()) {
            let _ = c.kill();
            let _ = c.wait();
        }
    });
}

/// whether the reader died under a running VM
pub(super) fn died() -> bool {
    live(|l| l.as_ref().is_some_and(|l| l.died.load(Ordering::SeqCst)))
}

/// the netcount file teardown wrote: (every attempt, those past the limit)
fn counts(cfg: &Config, id: &str) -> Option<(u64, u64)> {
    let path = cfg.paths.state.join("netcount").join(id);
    let text = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    let v: serde_json::Value = serde_json::from_str(&text?).ok()?;
    Some((v["tries"].as_u64()?, v["over"].as_u64()?))
}

/// after teardown: the run's log, whole. None for a run without a network
pub(super) fn finish(cfg: &Config) -> Option<NetLog> {
    stop();
    let mut l = live(|l| l.take())?;
    if let Some(t) = l.thread.take() {
        let _ = t.join();
    }
    let mut c = l.coll.lock().unwrap_or_else(|e| e.into_inner()).take()?;
    let counts_ok = match l.platform {
        Platform::Linux => match counts(cfg, &l.id) {
            // every attempt went through the try chain's counter: those not
            // past its limit should all have come through as lines
            Some((tries, over)) if c.tries_seen <= tries => {
                let listed = tries - over;
                c.lost += listed.saturating_sub(c.tries_seen);
                c.unlisted(over.saturating_sub(c.allowed_without_try.min(over)));
                true
            }
            _ => false,
        },
        Platform::Mac => c.saw_counts,
    };
    let owner = super::admin::caller_uid().parse().ok();
    let platform = match l.platform {
        Platform::Linux => "linux",
        Platform::Mac => "macos",
    };
    Some(c.finish(
        &l.id,
        l.mode.name(),
        platform,
        owner,
        l.started_unix,
        Instant::now(),
        counts_ok,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netmodel::Model;
    use std::net::Ipv4Addr;

    #[test]
    fn long_lines_are_skipped_whole() {
        let cfg = Config::default();
        let model = Model::new(&cfg, Mode::Web, Platform::Linux, Vec::new());
        let coll = Arc::new(Mutex::new(Some(Collector::new(
            model,
            Ipv4Addr::new(172, 29, 217, 2),
            Instant::now(),
        ))));
        let mut input = format!("{}\n", "x".repeat(LINE_CAP * 3)).into_bytes();
        input.extend(b"{\"k\":\"lost\",\"n\":4}\n\xff\xfe\n{\"k\":\"lost\",\"n\":1}");
        let eof = Arc::new(AtomicBool::new(false));
        let e = eof.clone();
        pump(
            &input[..],
            coll.clone(),
            Arc::new(Mutex::new(Instant::now())),
            move || e.store(true, Ordering::SeqCst),
        );
        assert!(eof.load(Ordering::SeqCst));
        let c = coll.lock().unwrap().take().unwrap();
        // the long one and the bad utf-8; the last line had no newline but
        // the producer closed, so it's cut off too
        assert_eq!(c.invalid, 3);
        assert_eq!(c.lost, 4);
    }
}
