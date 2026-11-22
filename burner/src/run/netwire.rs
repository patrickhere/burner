//! one run's connection log while it's being recorded: the producer (the
//! nflog reader on linux, macnet on macOS), the thread that folds its lines,
//! and what happens at the end. the log never decides anything about the
//! run but this: on linux, a reader that dies or stalls while the VM runs
//! stops the VM, so nothing goes unrecorded

use std::io::{BufRead, BufReader, Read};
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::net::Mode;
use crate::netlog::{Collector, LINE_CAP, NetLog};
use crate::netmodel::{Model, Platform};

/// the reader's first line, once its limits are on and it's reading
pub const READY: &str = "{\"k\":\"ready\"}\n";

/// how long a reader gets to say it's ready
#[cfg(target_os = "linux")]
const READY_WAIT: Duration = Duration::from_secs(10);

/// what the run says when the reader went away under a running VM
pub const READER_DIED: &str =
    "the network log reader stopped, VM stopped so nothing goes unrecorded";

/// and when it was there but stopped reading
pub const READER_STALLED: &str =
    "the network log reader stalled, VM stopped so nothing goes unrecorded";

/// how often the watchdog reads the slot's counters
#[cfg(target_os = "linux")]
const WATCH_EVERY: Duration = Duration::from_secs(3);

/// how long the reader may say nothing while the counters say the kernel
/// sent it messages
#[cfg(any(target_os = "linux", test))]
const STALL_AFTER: Duration = Duration::from_secs(5);

struct Live {
    id: String,
    mode: Mode,
    platform: Platform,
    started_unix: u64,
    coll: Arc<Mutex<Option<Collector>>>,
    last: Arc<Mutex<Instant>>,
    stopping: Arc<AtomicBool>,
    died: Arc<AtomicBool>,
    stalled: Arc<AtomicBool>,
    child: Option<Child>,
    thread: Option<JoinHandle<()>>,
    /// linux: the stall watchdog
    watch: Option<JoinHandle<()>>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);

fn live<T>(f: impl FnOnce(&mut Option<Live>) -> T) -> T {
    let mut g = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

/// read a producer's lines into the collector until it closes. lines past
/// the cap are skipped to their end and counted
fn pump(
    src: impl Read,
    coll: Arc<Mutex<Option<Collector>>>,
    last: Arc<Mutex<Instant>>,
    ready: Arc<AtomicBool>,
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
        // the reader says it's in its sandbox and reading, once, first
        if buf == READY.as_bytes() && !ready.swap(true, Ordering::SeqCst) {
            continue;
        }
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

/// the stall watchdog's view between two reads of the counters
#[cfg(any(target_os = "linux", test))]
struct Watch {
    /// messages the kernel had sent the reader at the last read
    sent: Option<u64>,
    /// just before that read
    at: Instant,
    /// more were sent after a read the reader has said nothing since:
    /// (that read, when it was seen)
    owed: Option<(Instant, Instant)>,
}

#[cfg(any(target_os = "linux", test))]
impl Watch {
    fn new(now: Instant) -> Watch {
        Watch {
            sent: None,
            at: now,
            owed: None,
        }
    }

    /// one read at `now` (taken before the counters were): `sent` by the
    /// counters, None when they can't be read, and the reader's last line.
    /// true when the reader is stalled. a live reader passes each message
    /// on within milliseconds, so it has always spoken since a read that
    /// came before messages it was sent. a filter reload sets the counters
    /// back, which only lowers `sent`
    fn tick(&mut self, now: Instant, sent: Option<u64>, last: Instant) -> bool {
        if self.owed.is_some_and(|(since, _)| last > since) {
            self.owed = None;
        }
        if self.owed.is_none()
            && let (Some(before), Some(n)) = (self.sent, sent)
            && n > before
            && last <= self.at
        {
            self.owed = Some((self.at, now));
        }
        self.sent = sent;
        self.at = now;
        self.owed
            .is_some_and(|(_, seen)| now.duration_since(seen) >= STALL_AFTER)
    }
}

/// linux: every few seconds, the messages the slot's counters say the
/// kernel sent the reader (attempts but the ones over the limit, let-outs
/// and replies). if more came and the reader says nothing for STALL_AFTER,
/// it's stopped (SIGSTOP) or stuck: the VM is stopped as for a dead one
#[cfg(target_os = "linux")]
fn watchdog(
    tap: &str,
    id: &str,
    last: &Mutex<Instant>,
    stopping: &AtomicBool,
    stalled: &AtomicBool,
) {
    let mut w = Watch::new(Instant::now());
    loop {
        let until = Instant::now() + WATCH_EVERY;
        while Instant::now() < until {
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let now = Instant::now();
        let sent = crate::net::log_counts(tap).map(|c| {
            c.tries
                .saturating_sub(c.over)
                .saturating_add(c.up)
                .saturating_add(c.down)
        });
        let heard = *last.lock().unwrap_or_else(|e| e.into_inner());
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        if w.tick(now, sent, heard) {
            stalled.store(true, Ordering::SeqCst);
            crate::cgroup::kill(id);
            super::admin::log_line(&format!("{id}: {READER_STALLED}"));
            return;
        }
    }
}

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
    let ready = Arc::new(AtomicBool::new(false));
    let thread = {
        let (coll, last, stopping, died, ready, id) = (
            coll.clone(),
            last.clone(),
            stopping.clone(),
            died.clone(),
            ready.clone(),
            id.to_string(),
        );
        std::thread::spawn(move || {
            pump(out, coll, last, ready, || {
                if !stopping.load(Ordering::SeqCst) {
                    died.store(true, Ordering::SeqCst);
                    crate::cgroup::kill(&id);
                    super::admin::log_line(&format!("{id}: {READER_DIED}"));
                }
            })
        })
    };
    // no tap until the reader is in its sandbox and reading. one that dies
    // or never says so ends the run here
    let until = Instant::now() + READY_WAIT;
    while !ready.load(Ordering::SeqCst) && !died.load(Ordering::SeqCst) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !ready.load(Ordering::SeqCst) || died.load(Ordering::SeqCst) {
        stopping.store(true, Ordering::SeqCst);
        let _ = child.kill();
        let _ = child.wait();
        let _ = thread.join();
        return Err(super::exit(
            crate::exit::EXIT_SANDBOX,
            crate::json::Kind::Net,
            "the network log reader didn't start, no network without it",
        ));
    }
    let stalled = Arc::new(AtomicBool::new(false));
    let watch = {
        let (last, stopping, stalled, id, tap) = (
            last.clone(),
            stopping.clone(),
            stalled.clone(),
            id.to_string(),
            s.tap,
        );
        std::thread::spawn(move || watchdog(&tap, &id, &last, &stopping, &stalled))
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
            stalled,
            child: Some(child),
            thread: Some(thread),
            watch: Some(watch),
        })
    });
    Ok(())
}

/// macOS: macnet writes to the other end of `events`. its going away isn't
/// the run's business, the network goes with it
#[cfg(target_os = "macos")]
pub(super) fn start_mac(
    cfg: &Config,
    id: &str,
    mode: Mode,
    guest: Ipv4Addr,
    events: std::os::fd::OwnedFd,
    blocked: Vec<crate::net::Blocked>,
) {
    let model = Model::new(cfg, mode, Platform::Mac, blocked);
    let coll = Arc::new(Mutex::new(Some(Collector::new(
        model,
        guest,
        Instant::now(),
    ))));
    let last = Arc::new(Mutex::new(Instant::now()));
    let thread = {
        let (coll, last) = (coll.clone(), last.clone());
        let f = std::fs::File::from(events);
        let ready = Arc::new(AtomicBool::new(false));
        std::thread::spawn(move || pump(f, coll, last, ready, || {}))
    };
    live(|l| {
        *l = Some(Live {
            id: id.into(),
            mode,
            platform: Platform::Mac,
            started_unix: unix_now(),
            coll,
            last,
            stopping: Arc::new(AtomicBool::new(true)),
            died: Arc::new(AtomicBool::new(false)),
            stalled: Arc::new(AtomicBool::new(false)),
            child: None,
            thread: Some(thread),
            watch: None,
        })
    });
}

/// macOS: wait until macnet has closed its end of the log's pipe, which it
/// does right after its last line, or until `until`
#[cfg(target_os = "macos")]
pub(super) fn net_closed(until: Instant) {
    let open = || {
        live(|l| {
            l.as_ref()
                .and_then(|l| l.thread.as_ref())
                .is_some_and(|t| !t.is_finished())
        })
    };
    while open() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(2));
    }
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

#[cfg(target_os = "linux")]
/// linux, at each step of starting the VM: a reader that's gone by now
/// cancels the launch. after the VMM is in its cgroup, a death kills it there
pub(super) fn alive() -> anyhow::Result<()> {
    if let Some(why) = died() {
        return Err(super::exit(
            crate::exit::EXIT_SANDBOX,
            crate::json::Kind::Net,
            why,
        ));
    }
    Ok(())
}

/// whether the reader died or stalled under a running VM, and what the
/// run says about it
pub(super) fn died() -> Option<&'static str> {
    live(|l| {
        let l = l.as_ref()?;
        if l.died.load(Ordering::SeqCst) {
            Some(READER_DIED)
        } else if l.stalled.load(Ordering::SeqCst) {
            Some(READER_STALLED)
        } else {
            None
        }
    })
}

/// what --log prints after a run, each line to go after "burner: "
pub(super) fn words(log: &NetLog, mode: super::plan::LogMode) -> Vec<String> {
    use super::plan::LogMode;
    match mode {
        LogMode::None => Vec::new(),
        LogMode::Summary => crate::netlog::summary_lines(log),
        LogMode::Full => {
            let t = crate::netlog::table(log);
            let mut lines = t.lines();
            let head = lines.next().unwrap_or_default().to_string();
            std::iter::once(format!("{head} (burner log {})", log.id))
                .chain(lines.map(str::to_string))
                .collect()
        }
    }
}

/// the netcount file teardown wrote
fn counts(cfg: &Config, id: &str) -> Option<crate::netlog::NetCounts> {
    let path = cfg.paths.state.join("netcount").join(id);
    let text = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    let v: serde_json::Value = serde_json::from_str(&text?).ok()?;
    Some(crate::netlog::NetCounts {
        tries: v["tries"].as_u64()?,
        over: v["over"].as_u64()?,
        up: v["up"].as_u64()?,
        down: v["down"].as_u64()?,
    })
}

/// after teardown: the run's log, whole. None for a run without a network
pub(super) fn finish(cfg: &Config) -> Option<NetLog> {
    stop();
    let mut l = live(|l| l.take())?;
    for t in [l.thread.take(), l.watch.take()].into_iter().flatten() {
        let _ = t.join();
    }
    let c = l.coll.lock().unwrap_or_else(|e| e.into_inner()).take()?;
    let check = match l.platform {
        Platform::Linux => crate::netlog::Check::Linux(counts(cfg, &l.id)),
        Platform::Mac => crate::netlog::Check::Mac(c.saw_counts),
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
        check,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn stalls() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        // quiet VM, quiet reader: never
        let mut w = Watch::new(t0);
        assert!((1..20).all(|i| !w.tick(at(3 * i), Some(7), t0)));
        // a live reader speaks right after each message
        let mut w = Watch::new(t0);
        assert!((1..20).all(|i| !w.tick(at(3 * i), Some(i), at(3 * i - 1))));
        // messages after the first read, then nothing from the reader: owed
        // at 6, stalled once 5s have passed since
        let mut w = Watch::new(t0);
        assert!(!w.tick(at(3), Some(10), t0));
        assert!(!w.tick(at(6), Some(12), at(2)));
        assert!(!w.tick(at(9), Some(14), at(2)));
        assert!(w.tick(at(12), Some(16), at(2)));
        // the reader catching up in time clears it
        let mut w = Watch::new(t0);
        w.tick(at(3), Some(10), t0);
        w.tick(at(6), Some(12), at(2));
        assert!(!w.tick(at(9), Some(12), at(8)));
        assert!(!w.tick(at(15), Some(12), at(8)));
        // a line that came between the counters' read and the tick isn't
        // owed: it was sent after `at`, and so was the reader's answer
        let mut w = Watch::new(t0);
        w.tick(at(3), Some(10), t0);
        let r = at(3) + Duration::from_millis(20);
        assert!((2..10).all(|i| !w.tick(at(3 * i), Some(11), r)));
        // counters that can't be read, or set back by a reload, owe nothing
        let mut w = Watch::new(t0);
        w.tick(at(3), Some(50), t0);
        assert!(!w.tick(at(6), None, t0));
        assert!(!w.tick(at(9), Some(3), t0));
        assert!((4..10).all(|i| !w.tick(at(3 * i), Some(3), t0)));
        // nflog's own loss leaves a gap in the counts that never closes, but
        // nothing more is sent after it, so nothing is owed
        let mut w = Watch::new(t0);
        w.tick(at(3), Some(100), at(2));
        assert!((2..10).all(|i| !w.tick(at(3 * i), Some(140), at(4))));
    }

    #[test]
    fn long_lines_are_skipped_whole() {
        let cfg = Config::default();
        let model = Model::new(&cfg, Mode::Web, Platform::Linux, Vec::new());
        let coll = Arc::new(Mutex::new(Some(Collector::new(
            model,
            Ipv4Addr::new(172, 29, 217, 2),
            Instant::now(),
        ))));
        // the ready line counts once, a second one is just an invalid line
        let mut input = format!("{READY}{READY}{}\n", "x".repeat(LINE_CAP * 3)).into_bytes();
        input.extend(b"{\"k\":\"lost\",\"n\":4}\n\xff\xfe\n{\"k\":\"lost\",\"n\":1}");
        let eof = Arc::new(AtomicBool::new(false));
        let e = eof.clone();
        let ready = Arc::new(AtomicBool::new(false));
        pump(
            &input[..],
            coll.clone(),
            Arc::new(Mutex::new(Instant::now())),
            ready.clone(),
            move || e.store(true, Ordering::SeqCst),
        );
        assert!(ready.load(Ordering::SeqCst));
        assert!(eof.load(Ordering::SeqCst));
        let c = coll.lock().unwrap().take().unwrap();
        // the long one and the bad utf-8; the last line had no newline but
        // the producer closed, so it's cut off too
        assert_eq!(c.invalid, 4);
        assert_eq!(c.lost, 4);
    }
}
