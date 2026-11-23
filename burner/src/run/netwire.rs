//! one run's connection log while it's being recorded: the producer (the
//! nflog reader on linux, macnet on macOS), the thread that folds its lines,
//! and what happens at the end. the log never decides anything about the
//! run but this: on linux, a reader that dies or stalls while the VM runs
//! stops the VM, so nothing goes unrecorded

use std::io::{BufRead, BufReader, Read};
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// and when it was there but stopped passing messages on
#[cfg(target_os = "linux")]
const READER_STALLED: &str =
    "the network log reader stalled, VM stopped so nothing goes unrecorded";

/// and when the watchdog couldn't tell, with the counters unreadable
#[cfg(target_os = "linux")]
const COUNTS_UNREAD: &str =
    "the network log's counters couldn't be read, VM stopped so nothing goes unrecorded";

/// how often the watchdog reads the slot's counters
#[cfg(target_os = "linux")]
const WATCH_EVERY: Duration = Duration::from_secs(3);

/// one counter read, at most
#[cfg(target_os = "linux")]
const COUNTER_TIMEOUT: Duration = Duration::from_secs(5);

/// how long the reader may pass nothing on while the counters say the
/// kernel sent it messages
#[cfg(any(target_os = "linux", test))]
const STALL_AFTER: Duration = Duration::from_secs(5);

/// how long the counters may stay unreadable before the watchdog gives up
/// on telling, and stops the VM
#[cfg(any(target_os = "linux", test))]
const BLIND_AFTER: Duration = Duration::from_secs(30);

struct Live {
    id: String,
    mode: Mode,
    platform: Platform,
    started_unix: u64,
    coll: Arc<Mutex<Option<Collector>>>,
    /// what the producer itself said was lost, in the collector's lost.
    /// the linux watchdog's
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    said: Arc<AtomicU64>,
    last: Arc<Mutex<Instant>>,
    stopping: Arc<AtomicBool>,
    died: Arc<AtomicBool>,
    /// the watchdog stopped the VM, and why
    stalled: Arc<Mutex<Option<&'static str>>>,
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
    said: Arc<AtomicU64>,
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
            Ok(s) => {
                let lost = c.lost;
                c.take(s, now);
                // what the producer says itself was lost, kept apart from
                // the gaps in nflog's numbering, under the collector's lock
                if s.starts_with(LOST_LINE) {
                    said.fetch_add(c.lost.saturating_sub(lost), Ordering::SeqCst);
                }
            }
            Err(_) => c.invalid += 1,
        }
    }
    on_eof();
}

/// how a producer's own word on lost messages starts
const LOST_LINE: &str = "{\"k\":\"lost\"";

/// what the reader has passed on: the messages the counters count. other
/// lines (ready, junk, a packet from the wrong address, what it says was
/// lost) don't count as keeping up. when nflog drops messages the reader
/// still reads the ones that filled its socket, so it passes those on
#[cfg(any(target_os = "linux", test))]
fn passed_on(c: &Collector) -> u64 {
    c.tries_seen
        .saturating_add(c.up_seen)
        .saturating_add(c.down_seen)
}

/// linux: whether a process is stopped (SIGSTOP, or held by a tracer). a
/// stopped reader passes nothing on, whether or not the VM sends anything
#[cfg(target_os = "linux")]
fn stopped(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .is_some_and(|s| stat_stopped(&s))
}

/// the state in a /proc/PID/stat line, after the name in parens (which
/// can hold anything, parens and spaces too)
#[cfg(any(target_os = "linux", test))]
fn stat_stopped(stat: &str) -> bool {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|st| st == "T" || st == "t")
}

/// what the reader had done at one moment
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Default)]
struct Seen {
    /// messages passed on
    passed: u64,
    /// messages lost by the gaps in nflog's numbering: exact, and only
    /// ever messages sent before the one that showed the gap
    gaps: u64,
    /// everything said lost, its own overflow notes too, which say one
    /// whatever was dropped and can be the same message as a gap
    lost: u64,
}

#[cfg(target_os = "linux")]
fn seen(c: &Collector, said: &AtomicU64) -> Seen {
    Seen {
        passed: passed_on(c),
        gaps: c.lost.saturating_sub(said.load(Ordering::SeqCst)),
        lost: c.lost,
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq)]
enum Health {
    Fine,
    Stalled,
    Blind,
}

/// a slot's log counters, read in this order
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Default)]
struct Counts {
    /// attempts past the itemization limit, which get no message
    over: u64,
    /// every new attempt
    tries: u64,
    /// let-out messages
    up: u64,
    /// reply messages
    down: u64,
}

#[cfg(any(target_os = "linux", test))]
impl Counts {
    /// the messages the kernel sent the reader
    fn sent(self) -> i128 {
        i128::from(self.tries) - i128::from(self.over) + i128::from(self.up) + i128::from(self.down)
    }

    /// a filter reload made them again from zero
    fn reset_since(self, before: Counts) -> bool {
        self.tries < before.tries
            || self.over < before.over
            || self.up < before.up
            || self.down < before.down
    }
}

/// the stall watchdog's view between two reads of the counters
#[cfg(any(target_os = "linux", test))]
struct Watch {
    /// the counters at the last good read
    counts: Counts,
    /// what the reader had done just before that read started
    before: Seen,
    /// and once it was done
    after: Seen,
    /// messages sent that the reader hadn't passed on by then
    owed: i128,
    /// when that read started
    at: Instant,
    /// since when messages have been owed with nothing passed on
    quiet_since: Option<Instant>,
}

#[cfg(any(target_os = "linux", test))]
impl Watch {
    /// from a read before the VM started, so every message after it is
    /// the VM's
    fn new(now: Instant, counts: Counts, seen: Seen) -> Watch {
        Watch {
            counts,
            before: seen,
            after: seen,
            owed: 0,
            at: now,
            quiet_since: None,
        }
    }

    /// one read that started at `now`, with what the reader had done
    /// `before` it, the counters (None when they couldn't be read), and
    /// what it had done `after`.
    ///
    /// what's owed is what the counters say was sent less what was passed
    /// on or lost in a numbering gap before they were read, so it's never
    /// more than was really outstanding. a live reader passes each message
    /// on within milliseconds: owed with nothing at all passed on or said
    /// lost between two reads is a stall once it lasts STALL_AFTER.
    /// overflow notes don't come off what's owed, since they don't say how
    /// many, and an overflow with the last messages gone and nothing after
    /// looks just like a reader stuck right after one. that's stopped on
    /// purpose: its socket holds 4M, and the log rules' limits let a VM
    /// fill that in no less than tens of seconds, so a reader that overflows
    /// wasn't reading, and messages did go unrecorded. a filter
    /// reload makes the counters again from zero: what they say then was
    /// all sent since the last read, and what was sent between the last
    /// read and the reload is only in the counters the reload threw away
    fn tick(&mut self, now: Instant, before: Seen, counts: Option<Counts>, after: Seen) -> Health {
        let Some(c) = counts else {
            if now.duration_since(self.at) >= BLIND_AFTER {
                return Health::Blind;
            }
            return self.health(now);
        };
        let sent = if c.reset_since(self.counts) {
            c.sent()
        } else {
            c.sent() - self.counts.sent()
        };
        let done = i128::from(before.passed.saturating_sub(self.before.passed))
            + i128::from(before.gaps.saturating_sub(self.before.gaps));
        self.owed = (self.owed + sent - done).max(0);
        let moved = after.passed > self.after.passed || after.lost > self.after.lost;
        if self.owed > 0 && !moved {
            self.quiet_since.get_or_insert(now);
        } else {
            self.quiet_since = None;
        }
        (self.counts, self.before, self.after, self.at) = (c, before, after, now);
        self.health(now)
    }

    fn health(&self, now: Instant) -> Health {
        match self.quiet_since {
            Some(t) if now.duration_since(t) >= STALL_AFTER => Health::Stalled,
            _ => Health::Fine,
        }
    }
}

/// linux: the slot's log counters, None when they can't be read in
/// COUNTER_TIMEOUT. the over-limit count comes from one list and the rest
/// from the next, so it's read before the attempts and traffic between can
/// only make what was sent look more, never fewer (the next read takes it
/// back). each list is one ruleset generation, nft starts over when the
/// ruleset changes under it, and a filter reload between the two shows as a
/// count that went down: then it reads again, so a sample never mixes an old
/// count with a new one
#[cfg(target_os = "linux")]
fn live_counts(tap: &str) -> Option<Counts> {
    let mut first = list_counts(tap)?;
    for _ in 0..3 {
        let next = list_counts(tap)?;
        if let Some(c) = combine(first, next) {
            return Some(c);
        }
        first = next;
    }
    None
}

/// over from the first list, the rest from the second. None when a count
/// went down between them, a reload
#[cfg(any(target_os = "linux", test))]
fn combine(first: Counts, next: Counts) -> Option<Counts> {
    (!next.reset_since(first)).then_some(Counts {
        over: first.over,
        ..next
    })
}

/// linux: one `nft list` of the slot's four counters
#[cfg(target_os = "linux")]
fn list_counts(tap: &str) -> Option<Counts> {
    let out = crate::sys::run_timeout(
        std::process::Command::new("nft").args([
            "-j",
            "list",
            "counters",
            "table",
            "inet",
            crate::net::TABLE,
        ]),
        None,
        COUNTER_TIMEOUT,
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    slot_counts(&out.stdout, tap)
}

/// the four counters named for `tap` in an `nft -j list counters`
#[cfg(any(target_os = "linux", test))]
fn slot_counts(json: &[u8], tap: &str) -> Option<Counts> {
    let v: serde_json::Value = serde_json::from_slice(json).ok()?;
    let all = v["nftables"].as_array()?;
    let get = |c: &str| -> Option<u64> {
        let name = format!("{c}_{tap}");
        all.iter()
            .filter_map(|o| o.get("counter"))
            .find(|c| c["name"] == name.as_str() && c["table"] == crate::net::TABLE)?["packets"]
            .as_u64()
    };
    Some(Counts {
        over: get("over")?,
        tries: get("n")?,
        up: get("up")?,
        down: get("down")?,
    })
}

/// linux: every few seconds, the messages the slot's counters say the
/// kernel sent the reader. if more came and the reader passes nothing on
/// for STALL_AFTER, it's stopped (SIGSTOP) or stuck; if the counters can't
/// be read for BLIND_AFTER, nobody can tell. either way the VM is stopped,
/// as for a dead reader
#[cfg(target_os = "linux")]
fn watchdog(tap: &str, id: &str, mut w: Watch, l: &Watched) {
    let passed = || {
        l.coll
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|c| seen(c, &l.said))
    };
    loop {
        let until = Instant::now() + WATCH_EVERY;
        while Instant::now() < until {
            if l.stopping.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let now = Instant::now();
        let Some(before) = passed() else { return };
        let c = live_counts(tap);
        let Some(after) = passed() else { return };
        if l.stopping.load(Ordering::SeqCst) {
            return;
        }
        let why = match w.tick(now, before, c, after) {
            _ if stopped(l.pid) => READER_STALLED,
            Health::Fine => continue,
            Health::Stalled => READER_STALLED,
            Health::Blind => COUNTS_UNREAD,
        };
        *l.stalled.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
        crate::cgroup::kill(id);
        super::admin::log_line(&format!("{id}: {why}"));
        return;
    }
}

/// what the watchdog shares with the run
#[cfg(target_os = "linux")]
struct Watched {
    /// the reader's
    pid: u32,
    coll: Arc<Mutex<Option<Collector>>>,
    said: Arc<AtomicU64>,
    stopping: Arc<AtomicBool>,
    stalled: Arc<Mutex<Option<&'static str>>>,
}

/// linux, with the slot's tap just up and the VM not started yet: read its
/// counters for a starting point and start the watchdog. counters that
/// can't be read end the run here, no network without the watch
#[cfg(target_os = "linux")]
pub(super) fn watch_linux(tap: &str) -> anyhow::Result<()> {
    let Some((id, l)) = live(|l| {
        let l = l.as_ref()?;
        Some((
            l.id.clone(),
            Watched {
                pid: l.child.as_ref()?.id(),
                coll: l.coll.clone(),
                said: l.said.clone(),
                stopping: l.stopping.clone(),
                stalled: l.stalled.clone(),
            },
        ))
    }) else {
        return Ok(());
    };
    let now = Instant::now();
    let got = l
        .coll
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or(Seen::default(), |c| seen(c, &l.said));
    let Some(start) = live_counts(tap) else {
        return Err(super::exit(
            crate::exit::EXIT_SANDBOX,
            crate::json::Kind::Net,
            "the network log's counters can't be read, no network without them",
        ));
    };
    let w = Watch::new(now, start, got);
    let tap = tap.to_string();
    let t = std::thread::spawn(move || watchdog(&tap, &id, w, &l));
    live(|l| {
        if let Some(l) = l.as_mut() {
            l.watch = Some(t);
        }
    });
    Ok(())
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
    let said = Arc::new(AtomicU64::new(0));
    let thread = {
        let (coll, said, last, stopping, died, ready, id) = (
            coll.clone(),
            said.clone(),
            last.clone(),
            stopping.clone(),
            died.clone(),
            ready.clone(),
            id.to_string(),
        );
        std::thread::spawn(move || {
            pump(out, coll, said, last, ready, || {
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
    live(|l| {
        *l = Some(Live {
            id: id.into(),
            mode,
            platform: Platform::Linux,
            started_unix: unix_now(),
            coll,
            said,
            last,
            stopping,
            died,
            stalled: Arc::new(Mutex::new(None)),
            child: Some(child),
            thread: Some(thread),
            watch: None,
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
    let said = Arc::new(AtomicU64::new(0));
    let thread = {
        let (coll, said, last) = (coll.clone(), said.clone(), last.clone());
        let f = std::fs::File::from(events);
        let ready = Arc::new(AtomicBool::new(false));
        std::thread::spawn(move || pump(f, coll, said, last, ready, || {}))
    };
    live(|l| {
        *l = Some(Live {
            id: id.into(),
            mode,
            platform: Platform::Mac,
            started_unix: unix_now(),
            coll,
            said,
            last,
            stopping: Arc::new(AtomicBool::new(true)),
            died: Arc::new(AtomicBool::new(false)),
            stalled: Arc::new(Mutex::new(None)),
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
        } else {
            *l.stalled.lock().unwrap_or_else(|e| e.into_inner())
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
    fn slot_counts_from_one_list() {
        let c = |name: &str, table: &str, n: u64| {
            format!(
                r#"{{"counter": {{"family": "inet", "name": "{name}", "table": "{table}", "handle": 9, "packets": {n}, "bytes": 0}}}}"#
            )
        };
        let list = |rows: Vec<String>| {
            format!(
                r#"{{"nftables": [{{"metainfo": {{"version": "1.1.3", "json_schema_version": 1}}}}, {}]}}"#,
                rows.join(", ")
            )
        };
        let all = list(vec![
            c("n_bn1", "burner", 99),
            c("n_bn3", "other", 98),
            c("n_bn3", "burner", 7),
            c("over_bn3", "burner", 2),
            c("up_bn3", "burner", 3),
            c("down_bn3", "burner", 4),
        ]);
        let got = slot_counts(all.as_bytes(), "bn3").unwrap();
        assert_eq!((got.tries, got.over, got.up, got.down), (7, 2, 3, 4));
        // a slot with a counter missing, or nothing that parses: unread
        let part = list(vec![c("n_bn3", "burner", 7), c("over_bn3", "burner", 2)]);
        assert!(slot_counts(part.as_bytes(), "bn3").is_none());
        assert!(slot_counts(b"not json", "bn3").is_none());
    }

    #[test]
    fn over_first_then_the_rest() {
        let c = |tries: u64, over: u64, up: u64| Counts {
            tries,
            over,
            up,
            down: 0,
        };
        // 100 over-limit attempts between the two lists: over from the
        // first, so the sample says 100 more sent, never fewer
        let got = combine(c(100, 0, 5), c(200, 100, 5)).unwrap();
        assert_eq!((got.tries, got.over, got.up), (200, 0, 5));
        // a reload between them: counts went down, read again
        assert!(combine(c(100, 0, 5), c(3, 0, 0)).is_none());
        assert!(combine(c(100, 0, 5), c(150, 0, 2)).is_none());
        // the watchdog on such a sample: owed for one read, then the next
        // read takes it back, and a quiet VM is never stopped
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let p = |passed: u64| Seen {
            passed,
            gaps: 0,
            lost: 0,
        };
        let mut w = Watch::new(t0, c(100, 0, 5), p(105));
        assert_eq!(w.tick(at(3), p(105), Some(got), p(105)), Health::Fine);
        assert!(
            (2..10)
                .all(|i| w.tick(at(3 * i), p(105), Some(c(200, 100, 5)), p(105)) == Health::Fine)
        );
    }

    #[test]
    fn stalls() {
        use Health::*;
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        // counters with `n` messages sent: attempts only, none over the limit
        let c = |n: u64| {
            Some(Counts {
                tries: n,
                ..Counts::default()
            })
        };
        // passed on, lost in numbering gaps, all said lost
        let s = |passed: u64, gaps: u64, lost: u64| Seen { passed, gaps, lost };
        let p = |passed: u64| s(passed, 0, 0);
        let new = |n: u64, passed: u64| {
            Watch::new(
                t0,
                Counts {
                    tries: n,
                    ..Counts::default()
                },
                p(passed),
            )
        };
        // a quiet VM: never
        let mut w = new(4, 4);
        assert!((1..20).all(|i| w.tick(at(3 * i), p(4), c(4), p(4)) == Fine));
        // a reader that keeps up, one message a read, each passed on just
        // after the counters were read
        let mut w = new(0, 0);
        assert!((1..20).all(|i| w.tick(at(3 * i), p(i - 1), c(i), p(i)) == Fine));
        // one attempt before the first read and nothing passed on: the
        // starting point came before the VM, so it's owed at 3, a stall at 9
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(1), p(0)), Fine);
        assert_eq!(w.tick(at(6), p(0), c(1), p(0)), Fine);
        assert_eq!(w.tick(at(9), p(0), c(1), p(0)), Stalled);
        // two sent, one passed on, then it's stuck: owed from 6, stalled at 12
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(2), p(1)), Fine);
        assert_eq!(w.tick(at(6), p(1), c(2), p(1)), Fine);
        assert_eq!(w.tick(at(9), p(1), c(2), p(1)), Fine);
        assert_eq!(w.tick(at(12), p(1), c(2), p(1)), Stalled);
        // one passed on a few ms after its read: owed for one read, not more
        let mut w = new(5, 5);
        assert_eq!(w.tick(at(3), p(5), c(6), p(5)), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), p(6), c(6), p(6)) == Fine));
        // passed on between the counters' read and the end of it: before
        // didn't have it, after does, so nothing is owed after
        let mut w = new(5, 5);
        assert_eq!(w.tick(at(3), p(5), c(6), p(6)), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), p(6), c(6), p(6)) == Fine));
        // lines that aren't messages don't count: passed_on stays put
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(10), p(0)), Fine);
        assert_eq!(w.tick(at(6), p(0), c(20), p(0)), Fine);
        assert_eq!(w.tick(at(9), p(0), c(30), p(0)), Stalled);
        // nflog dropped 20, the numbering shows which: not owed
        let mut w = new(100, 100);
        assert_eq!(w.tick(at(3), p(100), c(140), s(120, 20, 21)), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), s(120, 20, 21), c(140), s(120, 20, 21)) == Fine));
        // an overflow note and a gap for the same message, then stuck with
        // the last unread: the note doesn't come off, so the last is owed
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(4), s(2, 1, 2)), Fine);
        assert_eq!(w.tick(at(6), s(2, 1, 2), c(4), s(2, 1, 2)), Fine);
        assert_eq!(w.tick(at(9), s(2, 1, 2), c(4), s(2, 1, 2)), Fine);
        assert_eq!(w.tick(at(12), s(2, 1, 2), c(4), s(2, 1, 2)), Stalled);
        // nflog dropped the last one, the reader said it overflowed, and
        // nothing came after to show the gap: a reader that fell that far
        // behind is stopped like a stuck one, on purpose
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(2), s(1, 0, 1)), Fine);
        assert_eq!(w.tick(at(6), s(1, 0, 1), c(2), s(1, 0, 1)), Fine);
        assert_eq!(w.tick(at(9), s(1, 0, 1), c(2), s(1, 0, 1)), Fine);
        assert_eq!(w.tick(at(12), s(1, 0, 1), c(2), s(1, 0, 1)), Stalled);
        // a loss shown after the counters' read, of a message they didn't
        // have yet: it comes off at the next read, which has both
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), p(0), c(0), s(1, 1, 1)), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), s(1, 1, 1), c(2), s(1, 1, 1)) == Fine));
        // a reload: the counters start over. the 3 since were passed on
        let mut w = new(50, 50);
        assert_eq!(w.tick(at(3), p(50), c(3), p(53)), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), p(53), c(3), p(53)) == Fine));
        // and when they weren't, that's owed like any other
        let mut w = new(50, 50);
        w.tick(at(3), p(50), c(3), p(50));
        w.tick(at(6), p(50), c(3), p(50));
        assert_eq!(w.tick(at(9), p(50), c(3), p(50)), Stalled);
        // a flood past the limit while the counters were read: over was read
        // first, so the sum came out high, with the reader busy. the next
        // read, with the flood over, takes it back
        let mut w = new(0, 0);
        let busy = Counts {
            tries: 1000,
            over: 400,
            ..Counts::default()
        };
        assert_eq!(w.tick(at(3), p(0), Some(busy), p(590)), Fine);
        let done = Counts {
            tries: 1000,
            over: 410,
            ..Counts::default()
        };
        assert!((2..10).all(|i| w.tick(at(3 * i), p(590), Some(done), p(590)) == Fine));
        // counters that can't be read: fine for a while, then nobody can tell
        let mut w = new(0, 0);
        assert!((1..10).all(|i| w.tick(at(3 * i), p(0), None, p(0)) == Fine));
        assert_eq!(w.tick(at(30), p(0), None, p(0)), Blind);
        // and a stall seen before they went unreadable still counts
        let mut w = new(0, 0);
        w.tick(at(3), p(0), c(1), p(0));
        assert_eq!(w.tick(at(6), p(0), None, p(0)), Fine);
        assert_eq!(w.tick(at(9), p(0), None, p(0)), Stalled);
    }

    #[test]
    fn passed_on_counts_messages_only() {
        let cfg = Config::default();
        let model = Model::new(&cfg, Mode::Web, Platform::Linux, Vec::new());
        let mut c = Collector::new(model, Ipv4Addr::new(172, 29, 217, 2), Instant::now());
        c.take("not a line", Instant::now());
        c.take("{\"k\":\"lost\",\"n\":3}", Instant::now());
        assert_eq!((passed_on(&c), c.lost, c.invalid), (0, 3, 1));
    }

    #[test]
    fn stopped_states() {
        let line = |name: &str, st: &str| format!("4242 ({name}) {st} 1 4242 4242 0 -1 4194560");
        assert!(stat_stopped(&line("burner", "T")));
        assert!(stat_stopped(&line("burner", "t")));
        assert!(!stat_stopped(&line("burner", "S")));
        assert!(!stat_stopped(&line("burner", "R")));
        // a name that looks like a stopped state doesn't fool it
        assert!(!stat_stopped(&line("x) T (y", "S")));
        assert!(!stat_stopped(""));
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
        let said = Arc::new(AtomicU64::new(0));
        pump(
            &input[..],
            coll.clone(),
            said.clone(),
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
        // the producer's own word, kept apart from numbering gaps
        assert_eq!(said.load(Ordering::SeqCst), 4);
    }
}
