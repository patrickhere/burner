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
    /// what the reader had passed on just before that read started
    before: u64,
    /// and once it was done
    after: u64,
    /// what the reader had said was lost then
    lost: u64,
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
    fn new(now: Instant, counts: Counts, passed: u64, lost: u64) -> Watch {
        Watch {
            counts,
            before: passed,
            after: passed,
            lost,
            owed: 0,
            at: now,
            quiet_since: None,
        }
    }

    /// one read that started at `now`, with `before` passed on then, the
    /// counters (None when they couldn't be read), and `after` passed on
    /// and `lost` said lost once it was done.
    ///
    /// what's owed is what the counters say was sent less what was passed
    /// on before they were read, so it's never more than was really
    /// outstanding. a live reader passes each message on within
    /// milliseconds: owed with nothing at all passed on between two reads
    /// is a stall once it lasts STALL_AFTER. what the reader says nflog
    /// dropped is taken off what's owed, by its count: its socket holds 4M,
    /// far more than the log rules' limits let a VM send, so a reader that
    /// keeps up doesn't drop any. a filter reload makes the counters again
    /// from zero: what they say then was all sent since the last read, and
    /// what was sent between the last read and the reload is only in the
    /// counters the reload threw away
    fn tick(
        &mut self,
        now: Instant,
        before: u64,
        counts: Option<Counts>,
        after: u64,
        lost: u64,
    ) -> Health {
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
        let passed = i128::from(before.saturating_sub(self.before));
        let said_lost = i128::from(lost.saturating_sub(self.lost));
        self.owed = (self.owed + sent - passed - said_lost).max(0);
        let moved = after > self.after || said_lost > 0;
        if self.owed > 0 && !moved {
            self.quiet_since.get_or_insert(now);
        } else {
            self.quiet_since = None;
        }
        (self.counts, self.before, self.after, self.lost, self.at) = (c, before, after, lost, now);
        self.health(now)
    }

    fn health(&self, now: Instant) -> Health {
        match self.quiet_since {
            Some(t) if now.duration_since(t) >= STALL_AFTER => Health::Stalled,
            _ => Health::Fine,
        }
    }
}

/// linux: what one nft counter of the slot's says, None when it can't be
/// read in COUNTER_TIMEOUT
#[cfg(target_os = "linux")]
fn counter(name: &str) -> Option<u64> {
    let out = crate::sys::run_timeout(
        std::process::Command::new("nft").args([
            "-j",
            "list",
            "counter",
            "inet",
            crate::net::TABLE,
            name,
        ]),
        None,
        COUNTER_TIMEOUT,
    )
    .ok()?;
    if !out.status.success() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v["nftables"]
        .as_array()?
        .iter()
        .find_map(|o| o.get("counter"))?["packets"]
        .as_u64()
}

/// linux: the slot's log counters. the over-limit count is read before
/// the attempts, so traffic between the two reads can only make what was
/// sent look more, never fewer
#[cfg(target_os = "linux")]
fn live_counts(tap: &str) -> Option<Counts> {
    let over = counter(&format!("over_{tap}"))?;
    let tries = counter(&format!("n_{tap}"))?;
    let up = counter(&format!("up_{tap}"))?;
    let down = counter(&format!("down_{tap}"))?;
    Some(Counts {
        over,
        tries,
        up,
        down,
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
            .map(|c| (passed_on(c), c.lost))
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
        let Some((before, _)) = passed() else { return };
        let c = live_counts(tap);
        let Some((after, lost)) = passed() else {
            return;
        };
        if l.stopping.load(Ordering::SeqCst) {
            return;
        }
        let why = match w.tick(now, before, c, after, lost) {
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
                stopping: l.stopping.clone(),
                stalled: l.stalled.clone(),
            },
        ))
    }) else {
        return Ok(());
    };
    let now = Instant::now();
    let (got, lost) = l
        .coll
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or((0, 0), |c| (passed_on(c), c.lost));
    let Some(start) = live_counts(tap) else {
        return Err(super::exit(
            crate::exit::EXIT_SANDBOX,
            crate::json::Kind::Net,
            "the network log's counters can't be read, no network without them",
        ));
    };
    let w = Watch::new(now, start, got, lost);
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
        let new = |n: u64, passed: u64| {
            Watch::new(
                t0,
                Counts {
                    tries: n,
                    ..Counts::default()
                },
                passed,
                0,
            )
        };
        // a quiet VM: never
        let mut w = new(4, 4);
        assert!((1..20).all(|i| w.tick(at(3 * i), 4, c(4), 4, 0) == Fine));
        // a reader that keeps up, one message a read, each passed on just
        // after the counters were read
        let mut w = new(0, 0);
        assert!((1..20).all(|i| w.tick(at(3 * i), i - 1, c(i), i, 0) == Fine));
        // one attempt before the first read and nothing passed on: the
        // starting point came before the VM, so it's owed at 3, a stall at 9
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), 0, c(1), 0, 0), Fine);
        assert_eq!(w.tick(at(6), 0, c(1), 0, 0), Fine);
        assert_eq!(w.tick(at(9), 0, c(1), 0, 0), Stalled);
        // two sent, one passed on, then it's stuck: owed from 6, stalled at 12
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), 0, c(2), 1, 0), Fine);
        assert_eq!(w.tick(at(6), 1, c(2), 1, 0), Fine);
        assert_eq!(w.tick(at(9), 1, c(2), 1, 0), Fine);
        assert_eq!(w.tick(at(12), 1, c(2), 1, 0), Stalled);
        // one passed on a few ms after its read: owed for one read, not more
        let mut w = new(5, 5);
        assert_eq!(w.tick(at(3), 5, c(6), 5, 0), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), 6, c(6), 6, 0) == Fine));
        // passed on between the counters' read and the end of it: before
        // didn't have it, after does, so nothing is owed after
        let mut w = new(5, 5);
        assert_eq!(w.tick(at(3), 5, c(6), 6, 0), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), 6, c(6), 6, 0) == Fine));
        // lines that aren't messages don't count: passed_on stays put
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), 0, c(10), 0, 0), Fine);
        assert_eq!(w.tick(at(6), 0, c(20), 0, 0), Fine);
        assert_eq!(w.tick(at(9), 0, c(30), 0, 0), Stalled);
        // nflog dropped some and the reader said how many: not owed
        let mut w = new(100, 100);
        assert_eq!(w.tick(at(3), 100, c(140), 120, 20), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), 120, c(140), 120, 20) == Fine));
        // one lost, said so, and then stuck with the other unread: owed
        let mut w = new(0, 0);
        assert_eq!(w.tick(at(3), 0, c(2), 0, 1), Fine);
        assert_eq!(w.tick(at(6), 0, c(2), 0, 1), Fine);
        assert_eq!(w.tick(at(9), 0, c(2), 0, 1), Fine);
        assert_eq!(w.tick(at(12), 0, c(2), 0, 1), Stalled);
        // a reload: the counters start over. the 3 since were passed on
        let mut w = new(50, 50);
        assert_eq!(w.tick(at(3), 50, c(3), 53, 0), Fine);
        assert!((2..10).all(|i| w.tick(at(3 * i), 53, c(3), 53, 0) == Fine));
        // and when they weren't, that's owed like any other
        let mut w = new(50, 50);
        w.tick(at(3), 50, c(3), 50, 0);
        w.tick(at(6), 50, c(3), 50, 0);
        assert_eq!(w.tick(at(9), 50, c(3), 50, 0), Stalled);
        // a flood past the limit while the counters were read: over was read
        // first, so the sum came out high, with the reader busy. the next
        // read, with the flood over, takes it back
        let mut w = new(0, 0);
        let busy = Counts {
            tries: 1000,
            over: 400,
            ..Counts::default()
        };
        assert_eq!(w.tick(at(3), 0, Some(busy), 590, 0), Fine);
        let done = Counts {
            tries: 1000,
            over: 410,
            ..Counts::default()
        };
        assert!((2..10).all(|i| w.tick(at(3 * i), 590, Some(done), 590, 0) == Fine));
        // counters that can't be read: fine for a while, then nobody can tell
        let mut w = new(0, 0);
        assert!((1..10).all(|i| w.tick(at(3 * i), 0, None, 0, 0) == Fine));
        assert_eq!(w.tick(at(30), 0, None, 0, 0), Blind);
        // and a stall seen before they went unreadable still counts
        let mut w = new(0, 0);
        w.tick(at(3), 0, c(1), 0, 0);
        assert_eq!(w.tick(at(6), 0, None, 0, 0), Fine);
        assert_eq!(w.tick(at(9), 0, None, 0, 0), Stalled);
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
