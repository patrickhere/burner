use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, ChildStdout};
use std::time::{Duration, Instant};

use super::record::{self, Mark};
use super::{Deadline, Outcome, is_interrupted, signals};
use crate::cgroup;
use crate::config::Config;
use crate::json::{self, Kind};
use crate::ledger;
use crate::output::{Out, escape_controls};
use crate::result;
use crate::sys;

const SERIAL_CAP: u64 = 1 << 20;
const LIVE_BYTES: u64 = 65536;
/// input the shell holds for a VM that isn't taking it; past this it's dropped
const TO_VM_CAP: usize = 16 << 20;
/// how long after guest init's end marker the VM gets to stop on its own
const END_GRACE: Duration = Duration::from_secs(5);
/// an image whose init should say it's ready but hasn't by then gets the
/// caller's keys anyway
const READY_WAIT: Duration = Duration::from_secs(60);
/// how long the vCPUs must all sit asleep, never scheduled, behind the
/// kernel's halt line. an idle guest's timers wake them every half second
const HALT_CHECK: Duration = Duration::from_millis(1500);
/// a halt line the vCPUs don't stop behind by then was the guest's own text
const HALT_GIVE_UP: Duration = Duration::from_secs(10);

/// copy the console between the BEGIN/END markers to `out`, byte for byte.
/// the markers are only presentation: the guest knows the token and can end its
/// own live output early, which hides nothing but its own output
#[allow(clippy::too_many_arguments)]
pub(super) fn stream(
    stdout: &mut ChildStdout,
    child: &mut Child,
    token: &str,
    deadline: Deadline,
    out: &Out,
    diag: &Out,
    cfg: &Config,
    id: &str,
) -> Outcome {
    let begin = format!("BURNER-{token}-BEGIN\n").into_bytes();
    let end = format!("BURNER-{token}-END").into_bytes();
    let end_n = [end.as_slice(), b"N"].concat();
    let fd = stdout.as_raw_fd();
    let _ = sys::set_nonblocking(fd);
    #[derive(PartialEq)]
    enum St {
        Pre,
        Body,
        Capped,
        Done,
    }
    let mut st = St::Pre;
    // pre_line: whether pre[0] starts a line, kept across trims
    let (mut pre, mut pre_line, mut pending) = (Vec::new(), true, Vec::new());
    let (mut held_nl, mut at_line_start, mut raw_total) = (false, true, 0u64);
    let mut next_check = Instant::now();
    let mut chunk = vec![0u8; 65536];
    let flush_held = |held: &mut bool| {
        if *held {
            out.put(b"\n", None);
            *held = false;
        }
    };
    loop {
        if deadline.passed() {
            return Outcome::Timeout;
        }
        if is_interrupted() {
            return Outcome::Interrupted;
        }
        if Instant::now() >= next_check {
            next_check = Instant::now() + Duration::from_secs(1);
            if cancelled(cfg, id) {
                return Outcome::Cancelled;
            }
        }
        // a newline is held back in case the guest's own one before ENDN comes
        // next. the guest prints that newline and the marker in one printf, so
        // 200ms of quiet means it's real: let it out, or a line reader waits on it
        let wait = if held_nl {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(1)
        };
        if !sys::readable(fd, deadline.left().min(wait)) {
            if held_nl && st == St::Body {
                flush_held(&mut held_nl);
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            continue;
        }
        let n = match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(_) => break,
        };
        // the part of this read still under the console cap
        let take = n.min(SERIAL_CAP.saturating_sub(raw_total) as usize);
        raw_total += n as u64;
        let data = &chunk[..take];
        match st {
            St::Pre => {
                pre.extend_from_slice(data);
                if let Some(i) = find_at_line_start(&pre, &begin, pre_line) {
                    record::mark(Mark::Begun);
                    st = St::Body;
                    pending = pre.split_off(i + begin.len());
                    pre.truncate(i);
                } else {
                    let keep = 8192 + begin.len();
                    if pre.len() > keep {
                        let cut = pre.len() - keep;
                        pre_line = pre[cut - 1] == b'\n';
                        pre.drain(..cut);
                    }
                }
            }
            St::Body => pending.extend_from_slice(data),
            _ => {}
        }
        if st == St::Body {
            // scan with an offset and compact once, instead of draining per line
            let mut start = 0;
            loop {
                let Some(off) = pending[start..].iter().position(|&b| b == b'\n') else {
                    let rest = &pending[start..];
                    if !rest.is_empty() && !(at_line_start && end_n.starts_with(rest)) {
                        flush_held(&mut held_nl);
                        out.put(rest, None);
                        at_line_start = false;
                        start = pending.len();
                    }
                    break;
                };
                let line = &pending[start..start + off];
                start += off + 1;
                if at_line_start && line == end.as_slice() {
                    flush_held(&mut held_nl);
                    st = St::Done;
                    break;
                }
                if at_line_start && line == end_n.as_slice() {
                    held_nl = false; // that newline was added by the guest init
                    st = St::Done;
                    break;
                }
                flush_held(&mut held_nl);
                out.put(line, None);
                held_nl = true;
                at_line_start = true;
            }
            pending.drain(..start);
        }
        if raw_total >= SERIAL_CAP && st == St::Body {
            flush_held(&mut held_nl);
            out.put(&pending, None);
            pending.clear();
            let msg = "console over 1M, live output stopped";
            json::note_warning(Kind::Output, msg, false);
            diag.put(format!("burner: {msg}\n").as_bytes(), None);
            st = St::Capped;
        }
    }
    if st == St::Body {
        flush_held(&mut held_nl);
        out.put(&pending, None);
    }
    // a kill during boot ends the VM before the job, that's not worth the console tail
    if st == St::Pre && !kill_requested(cfg, id) {
        // the console lines are the guest's, they stay out of the json
        json::note_warning(Kind::Vmm, "VM ended before the job started", false);
        diag.put(
            b"burner: VM ended before the job started; last console lines:\n",
            None,
        );
        let tail = &pre[pre.len().saturating_sub(2000)..];
        diag.put(&escape_controls(tail), None);
        diag.put(b"\n", None);
    }
    Outcome::Done
}

/// first `needle` that starts a line. `first_is_line` says whether hay[0] does
fn find_at_line_start(hay: &[u8], needle: &[u8], first_is_line: bool) -> Option<usize> {
    let mut from = 0;
    while let Some(off) = hay
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let i = from + off;
        if (i == 0 && first_is_line) || (i > 0 && hay[i - 1] == b'\n') {
            return Some(i);
        }
        from = i + 1;
    }
    None
}

/// what relay gets besides the VM itself
pub(super) struct ShellIo {
    /// an image whose guest init doesn't say when the shell is ready
    pub(super) legacy: bool,
    /// the job disk with the terminal size on it, see write_size
    pub(super) tty_rec: Option<File>,
    /// the size written there before the VM started
    pub(super) size: (u16, u16),
    /// ~. leaves. off for burner -H, where the client handles it
    pub(super) escape: bool,
}

/// how a shell session went
pub(super) struct Shell {
    pub(super) outcome: Outcome,
    /// what guest init said about the shell's end. None when it said nothing:
    /// the VM crashed or was reset under the shell
    pub(super) end: Option<Ended>,
    /// the terminal reset is queued last on it, to wait on before printing
    pub(super) screen: Out,
    /// when guest init said the shell was ready
    pub(super) ready: Option<Instant>,
    /// the signal count when the session was over: any signal past it stops
    /// every wait on the caller's terminal from there on
    pub(super) seen: usize,
}

/// `burner shell`: the caller's terminal goes raw and burner copies bytes both
/// ways. keystrokes go to the VM as they are; what the VM prints goes through a
/// filter so it can't set titles, the clipboard or anything else on the terminal.
///
/// keys typed while the VM boots wait: bytes sent before the guest has set up
/// its serial port are lost, and before the shell runs nothing in the guest
/// would act on ctrl-c. the terminal stays in the boot mode burner set (ctrl-c
/// still interrupts burner) until guest init says the shell is starting, and
/// the held keys go once the shell has drawn its prompt. an image whose init
/// doesn't say so (legacy) gets keys right away, as it used to
pub(super) fn relay(
    child: &mut Child,
    token: &str,
    deadline: Deadline,
    cfg: &Config,
    id: &str,
    io: ShellIo,
) -> Shell {
    let ShellIo {
        legacy,
        tty_rec,
        size: sent,
        escape: escapes,
    } = io;
    let screen = Out::new_screen();
    let failed = |screen: Out| {
        let seen = signals();
        screen.finish_reset();
        Shell {
            outcome: Outcome::Failed,
            end: None,
            screen,
            ready: None,
            seen,
        }
    };
    let (Some(vin), Some(mut vout)) = (child.stdin.take(), child.stdout.take()) else {
        return failed(screen);
    };
    let (vin_fd, vout_fd) = (vin.as_raw_fd(), vout.as_raw_fd());
    // blocking pipes would let a stuck VM freeze the loop that enforces the ttl
    if sys::set_nonblocking(vin_fd).is_err() || sys::set_nonblocking(vout_fd).is_err() {
        return failed(screen);
    }
    let mut vin = Some(vin);
    let started = Instant::now();
    // raw: keys reach the VM as bytes, ctrl-c too. open: held keys may go
    let (mut raw, mut open) = (legacy, legacy);
    if raw {
        let _ = sys::set_raw(0);
    }
    // when guest init said the shell starts, and when the guest last printed since
    let (mut ready_at, mut quiet_from): (Option<Instant>, Option<Instant>) = (None, None);
    let mut filter = crate::output::TermFilter::new(!crate::output::term_utf8());
    let mut escape = Escape::default();
    let mut end = Markers::new(token);
    let mut halt = HaltLine::default();
    // the vCPUs' run count while they've all been asleep, and since when
    let mut still: Option<(u64, Instant)> = None;
    let mut halted = false;
    // a resize goes to the guest through the job disk, see write_size. it
    // starts out set, for a resize between writing the disk and getting here
    let winch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGWINCH, winch.clone());
    let (mut size, mut size_seq) = (sent, 0u64);
    let mut held_since: Option<Instant> = None;
    // when guest init's end marker came: the VM stops right after it
    let mut ended_at: Option<Instant> = None;
    let mut to_vm: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut next_check = Instant::now();
    let (mut stdin_open, mut console_open) = (true, true);
    let outcome = loop {
        if deadline.passed() {
            break Outcome::Timeout;
        }
        if is_interrupted() {
            break Outcome::Interrupted;
        }
        if Instant::now() >= next_check {
            next_check = Instant::now() + Duration::from_secs(1);
            if cancelled(cfg, id) {
                break Outcome::Cancelled;
            }
        }
        // the guest can print the marker itself (the token is on its kernel
        // command line). the session ends either way, rather than going on
        // with nothing shown
        if ended_at.is_some_and(|t| t.elapsed() >= END_GRACE) {
            break Outcome::Done;
        }
        // a guest kernel that stops without a reset (poweroff -f where the
        // shell has no pid namespace of its own) leaves firecracker running,
        // and firecracker has no way to tell: on x86 the guest can't power
        // off. its last line can be printed by anyone, so it's held back and
        // only counts once the vCPUs have stopped too. when that can't be
        // read, the line shows after HALT_GIVE_UP and the ttl ends the VM
        if let Some(t) = halt.whole_since {
            match (vcpus_asleep(child.id()), still) {
                (Some(r), Some((s, _))) if r == s => {}
                (Some(r), _) => still = Some((r, Instant::now())),
                (None, _) => still = None,
            }
            if still.is_some_and(|(_, at)| at.elapsed() >= HALT_CHECK) {
                halted = true;
                break Outcome::Done;
            }
            if t.elapsed() >= HALT_GIVE_UP {
                screen.put(&filter.feed(&halt.release()), None);
            }
        } else {
            still = None;
        }
        if winch.swap(false, std::sync::atomic::Ordering::Relaxed)
            && let Some(f) = &tty_rec
            && let Some(now) = sys::term_size(1)
            && size != now
        {
            // a failed write is tried again with the next look
            if write_size(f, size_seq + 1, now).is_ok() {
                size = now;
                size_seq += 1;
            } else {
                winch.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if !raw && started.elapsed() >= READY_WAIT {
            let _ = sys::set_raw(0);
            (raw, open) = (true, true);
        }
        // the shell's prompt is out once the guest printed after ready and then
        // went quiet a moment. keys sent before the shell reads them are echoed
        // by the guest tty, and again by the shell
        if !open
            && ready_at.is_some_and(|t| match quiet_from {
                Some(q) => q.elapsed() >= Duration::from_millis(100),
                None => t.elapsed() >= Duration::from_millis(300),
            } || t.elapsed() >= Duration::from_secs(2))
        {
            open = true;
        }
        // stdin is always read, so ~. works even when the VM stops taking input
        let mut fds = Vec::new();
        if stdin_open {
            fds.push(0);
        }
        if console_open {
            fds.push(vout_fd);
        }
        let wait = if held_since.is_some() || halt.since.is_some() || (raw && !open) {
            30
        } else {
            200
        };
        let ready = sys::poll_read(&fds, deadline.left().min(Duration::from_millis(wait)));
        if ready.contains(&0) {
            match io::stdin().lock().read(&mut buf) {
                Ok(0) | Err(_) => stdin_open = false,
                Ok(n) => {
                    let mut keys = Vec::new();
                    escape.bracketed = screen.screen().is_some_and(|s| s.paste());
                    if !escapes {
                        keys.extend_from_slice(&buf[..n]);
                    } else if escape.feed(&buf[..n], &mut keys) {
                        break Outcome::Detached;
                    }
                    if console_open && ended_at.is_none() {
                        let room = TO_VM_CAP.saturating_sub(to_vm.len());
                        to_vm.extend_from_slice(&keys[..keys.len().min(room)]);
                    }
                }
            }
        }
        if let Some(w) = vin.as_mut()
            && open
            && !to_vm.is_empty()
        {
            match w.write(&to_vm) {
                Ok(n) => {
                    to_vm.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => to_vm.clear(),
            }
        }
        // caller's input ended and everything is sent: the VM sees eof too
        if !stdin_open && to_vm.is_empty() {
            vin = None;
        }
        if ready.contains(&vout_fd) {
            match vout.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let show = end.feed(&buf[..n]);
                    screen.put(&filter.feed(&halt.feed(&show)), None);
                    if end.ready && !raw {
                        let _ = sys::set_raw(0);
                        raw = true;
                    }
                    if end.ready {
                        if ready_at.is_some() && !show.is_empty() {
                            quiet_from = Some(Instant::now());
                        }
                        ready_at.get_or_insert_with(Instant::now);
                    }
                    held_since = end
                        .unshown()
                        .then(|| held_since.unwrap_or_else(Instant::now));
                    if end.ended.is_some() && ended_at.is_none() {
                        ended_at = Some(Instant::now());
                        to_vm.clear();
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                // console gone: keep watching the deadline and kills until firecracker exits
                _ => console_open = false,
            }
        } else if matches!(child.try_wait(), Ok(Some(_))) {
            break child_outcome(child);
        }
        if held_since.is_some_and(|t| t.elapsed() >= end.hold()) {
            screen.put(&filter.feed(&halt.feed(&end.flush())), None);
            held_since = None;
        }
        if halt.whole_since.is_none() && halt.since.is_some_and(|t| t.elapsed() >= HALT_HOLD) {
            screen.put(&filter.feed(&halt.release()), None);
        }
    };
    // shutting down from here on
    let seen = signals();
    // what the guest printed is shown, unless it was the halt line of a guest
    // that did halt
    if !halted {
        screen.put(&filter.feed(&halt.release()), None);
    }
    // a kill that landed as the VM was exiting still counts as a kill
    let outcome = match outcome {
        Outcome::Done | Outcome::Failed if cancelled(cfg, id) => Outcome::Cancelled,
        o => o,
    };
    // output still queued goes out if the terminal takes it soon; a terminal
    // that has stopped reading would leave the reset stuck behind it
    screen.drain_or(Instant::now() + Duration::from_secs(2), || signals() > seen);
    screen.finish_reset();
    let end = if halted {
        Some(Ended::PowerOff)
    } else {
        end.ended
    };
    Shell {
        outcome,
        end,
        screen,
        ready: ready_at,
        seen,
    }
}

/// the caller's terminal size as the first line of a shell's job disk:
/// `burner-tty SEQ ROWS COLS SEQ`. guest init reads it every half second and
/// sets it on the console, which sends the shell's foreground job SIGWINCH.
/// SEQ twice: a line read while it was being written doesn't match itself
pub(super) fn write_size(f: &File, seq: u64, (rows, cols): (u16, u16)) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(
        format!("burner-tty {seq} {rows} {cols} {seq}\n").as_bytes(),
        0,
    )
}

/// how long the start of what could be a halt line waits for the rest
const HALT_HOLD: Duration = Duration::from_millis(30);

/// keeps the line the guest kernel prints when it stops for good off the
/// screen while it's the last thing on the console:
/// `[    1.389719] reboot: System halted` or `... reboot: Power down`.
/// the kernel doesn't know where the tty's cursor is, so it can come after
/// anything on a line (a full-screen app's last draw). it goes out as soon as
/// more comes after it, or by release
#[derive(Default)]
struct HaltLine {
    /// from the line's [ on
    held: Vec<u8>,
    /// what went out last was an ESC, so a [ now starts a CSI
    esc: bool,
    /// since when bytes are held, and since when they're a whole halt line
    since: Option<Instant>,
    whole_since: Option<Instant>,
}

#[derive(PartialEq, Debug)]
enum Halt {
    No,
    Start,
    Whole,
}

/// what bytes from a [ on, \r\n included, are of a halt line
fn halt_match(l: &[u8]) -> Halt {
    let Some(rest) = l.strip_prefix(b"[") else {
        return Halt::No;
    };
    let ts = rest
        .iter()
        .take_while(|b| b.is_ascii_digit() || b" .".contains(b))
        .count();
    let rest = &rest[ts..];
    if rest.is_empty() {
        return Halt::Start;
    }
    if ts == 0 {
        return Halt::No;
    }
    for m in [&b"] reboot: System halted"[..], b"] reboot: Power down"] {
        if rest.len() < m.len() && m.starts_with(rest) {
            return Halt::Start;
        }
        if let Some(after) = rest.strip_prefix(m) {
            return match after {
                b"" | b"\r" | b"\r\n" | b"\n" => Halt::Whole,
                _ => Halt::No,
            };
        }
    }
    Halt::No
}

impl HaltLine {
    /// what can go to the screen now
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        if b.is_empty() {
            return Vec::new();
        }
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        // the last [ on the last line, its line break aside
        let body = buf.strip_suffix(b"\n").unwrap_or(&buf);
        let line = body.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);
        let from = body[line..]
            .iter()
            .rposition(|&c| c == b'[')
            .map(|i| line + i)
            .filter(|&i| {
                if i == 0 {
                    !self.esc
                } else {
                    buf[i - 1] != 0x1b
                }
            });
        let m = from.map_or(Halt::No, |i| halt_match(&buf[i..]));
        let Some(from) = from.filter(|_| m != Halt::No) else {
            (self.since, self.whole_since) = (None, None);
            self.esc = buf.last() == Some(&0x1b);
            return buf;
        };
        let now = Instant::now();
        if from > 0 || self.since.is_none() {
            self.since = Some(now);
        }
        self.whole_since = match m {
            Halt::Whole => Some(self.whole_since.filter(|_| from == 0).unwrap_or(now)),
            _ => None,
        };
        self.held = buf.split_off(from);
        if !buf.is_empty() {
            self.esc = buf.last() == Some(&0x1b);
        }
        buf
    }

    /// what's held goes out after all
    fn release(&mut self) -> Vec<u8> {
        (self.since, self.whole_since) = (None, None);
        let held = std::mem::take(&mut self.held);
        if !held.is_empty() {
            self.esc = false;
        }
        held
    }
}

/// how many times firecracker's vCPU threads have been scheduled, from
/// /proc/PID/task/*/schedstat, while every one of them is asleep. None when
/// one is running or waiting to (a busy host can leave a live vCPU
/// unscheduled), or when there's nothing to read. a halted guest's vCPUs
/// sleep and never run again
fn vcpus_asleep(pid: u32) -> Option<u64> {
    let mut total = None;
    for t in std::fs::read_dir(format!("/proc/{pid}/task"))
        .ok()?
        .flatten()
    {
        let p = t.path();
        if !std::fs::read_to_string(p.join("comm")).is_ok_and(|c| c.starts_with("fc_vcpu")) {
            continue;
        }
        // the state comes after the name, which can hold spaces and parens
        let stat = std::fs::read_to_string(p.join("stat")).ok()?;
        if stat.rsplit_once(')')?.1.split_whitespace().next()? != "S" {
            return None;
        }
        let runs = sched_runs(&std::fs::read_to_string(p.join("schedstat")).ok()?)?;
        total = Some(total.unwrap_or(0) + runs);
    }
    total
}

/// the run count from a schedstat line, `ns-on-cpu ns-waiting runs`. a
/// kernel with scheduler accounting off gives 0 0 0 for every thread, and a
/// count that never moves would look like a halt, so that's no count at all
fn sched_runs(line: &str) -> Option<u64> {
    let v: Vec<u64> = line
        .split_whitespace()
        .map(|n| n.parse().ok())
        .collect::<Option<_>>()?;
    match v.as_slice() {
        [0, 0, 0] => None,
        [_, _, runs] => Some(*runs),
        _ => None,
    }
}

/// watches the shell's console for guest init's markers and keeps them off the
/// caller's terminal: `BURNER-<token>-SHELL2;` first, the version of the
/// records that follow, `BURNER-<token>-READY` right before the shell starts,
/// and the end record `BURNER-<token>-END<status>;` after it, where status is
/// the shell's exit code, or p (powered off), r (rebooted), f (the shell
/// couldn't start) or l (it ended without an exit code). the end record only
/// counts once it's whole. images from before the version say so by sending
/// READY without it (version 1, `END<exit code>[p|r];`) or nothing at all (a
/// bare `END`). what comes after the end (the guest kernel's reboot line)
/// never shows either.
///
/// bytes that could be the start of a marker are held until it's clear. once
/// they have the whole `BURNER-<token>-`, they're held for as long as it takes
/// (only the guest knows the token, so it can only hide its own output). a
/// shorter start goes out after a moment, but is still matched: a record that
/// comes in with a gap inside it still counts
struct Markers {
    prefix: Vec<u8>,
    held: Vec<u8>,
    /// how many of the held bytes went out already
    shown: usize,
    /// the guest's record version: from SHELL, 1 for a READY without it,
    /// None for an image that says neither
    proto: Option<u32>,
    ready: bool,
    ended: Option<Ended>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Ended {
    Exit(u8),
    PowerOff,
    Reboot,
    /// the shell couldn't be started
    NoStart,
    /// the shell went away without an exit code
    Lost,
    /// an image built before the end record had a status
    Legacy,
}

/// a record so far
enum Record<T> {
    Done(T),
    Partial,
    Bad,
}

impl<T> Record<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> Record<U> {
        match self {
            Record::Done(t) => Record::Done(f(t)),
            Record::Partial => Record::Partial,
            Record::Bad => Record::Bad,
        }
    }
}

/// up to three digits, as a number up to 255, and the bytes after them
fn status_digits(p: &[u8]) -> Record<(u8, &[u8])> {
    let n = p.iter().take_while(|b| b.is_ascii_digit()).count();
    match (n, p.get(n)) {
        (0, None) => Record::Partial,
        (0, _) | (4.., _) => Record::Bad,
        // digits can go on up to three
        (_, None) => Record::Partial,
        _ => match std::str::from_utf8(&p[..n])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(rc) => Record::Done((rc, &p[n..])),
            None => Record::Bad,
        },
    }
}

/// what's after `SHELL`: the version and the bytes it took, `;` included
fn shell_record(p: &[u8]) -> Record<(u32, usize)> {
    match status_digits(p) {
        Record::Done((2, [b';', ..])) => Record::Done((2, 2)),
        Record::Done(_) | Record::Bad => Record::Bad,
        Record::Partial => Record::Partial,
    }
}

/// what's after `END`, read as the guest's version has it
fn end_record(proto: Option<u32>, p: &[u8]) -> Record<Ended> {
    let Some(proto) = proto else {
        return Record::Done(Ended::Legacy);
    };
    let (status, rest) = match (proto, p.first()) {
        (_, None) => return Record::Partial,
        (2, Some(b'p')) => (Ended::PowerOff, &p[1..]),
        (2, Some(b'r')) => (Ended::Reboot, &p[1..]),
        (2, Some(b'f')) => (Ended::NoStart, &p[1..]),
        (2, Some(b'l')) => (Ended::Lost, &p[1..]),
        _ => match status_digits(p) {
            Record::Done((rc, rest)) => match (proto, rest) {
                // version 1 put p or r after an exit code of 0
                (1, [b'p', rest @ ..]) => (Ended::PowerOff, rest),
                (1, [b'r', rest @ ..]) => (Ended::Reboot, rest),
                _ => (Ended::Exit(rc), rest),
            },
            Record::Partial => return Record::Partial,
            Record::Bad => return Record::Bad,
        },
    };
    match rest.first() {
        Some(b';') => Record::Done(status),
        None => Record::Partial,
        Some(_) => Record::Bad,
    }
}

impl Markers {
    fn new(token: &str) -> Markers {
        Markers {
            prefix: format!("BURNER-{token}-").into_bytes(),
            held: Vec::new(),
            shown: 0,
            proto: None,
            ready: false,
            ended: None,
        }
    }

    /// what can go to the screen now
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        if self.ended.is_some() {
            return Vec::new();
        }
        let shown = std::mem::take(&mut self.shown);
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        let mut out = Vec::with_capacity(buf.len());
        let emit = |out: &mut Vec<u8>, from: usize, to: usize| {
            if to > shown {
                out.extend_from_slice(&buf[from.max(shown)..to]);
            }
        };
        let mut at = 0;
        loop {
            let Some(i) = buf[at..]
                .windows(self.prefix.len())
                .position(|w| w == self.prefix)
                .map(|i| at + i)
            else {
                // a cut-off start of the prefix waits
                let tail = &buf[at..];
                let keep = (1..self.prefix.len().min(tail.len() + 1))
                    .rev()
                    .find(|&k| tail.ends_with(&self.prefix[..k]))
                    .unwrap_or(0);
                let from = buf.len() - keep;
                emit(&mut out, at, from);
                self.held = buf[from..].to_vec();
                self.shown = shown.saturating_sub(from);
                return out;
            };
            emit(&mut out, at, i);
            let rest = &buf[i + self.prefix.len()..];
            if let Some(after) = rest.strip_prefix(b"READY") {
                self.ready = true;
                // an image from before SHELL2 says nothing else first
                self.proto.get_or_insert(1);
                at = buf.len() - after.len();
                continue;
            }
            let record = if let Some(p) = rest.strip_prefix(b"SHELL") {
                match shell_record(p) {
                    Record::Done((v, n)) => {
                        self.proto = Some(v);
                        at = i + self.prefix.len() + 5 + n;
                        continue;
                    }
                    r => r.map(|_| ()),
                }
            } else if let Some(p) = rest.strip_prefix(b"END") {
                match end_record(self.proto, p) {
                    Record::Done(e) => {
                        self.ended = Some(e);
                        return out;
                    }
                    r => r.map(|_| ()),
                }
            } else if [&b"READY"[..], b"END", b"SHELL"]
                .iter()
                .any(|m| m.starts_with(rest))
            {
                Record::Partial
            } else {
                Record::Bad
            };
            if matches!(record, Record::Partial) {
                self.held = buf[i..].to_vec();
                self.shown = shown.saturating_sub(i);
                return out;
            }
            // not a marker after all: the guest's own text
            emit(&mut out, i, i + 1);
            at = i + 1;
        }
    }

    /// how long held bytes wait for the rest of a marker. a short start ("B",
    /// "BURNER-") goes out after 30ms, so typing never lags
    fn hold(&self) -> Duration {
        if self.held.len() >= self.prefix.len() {
            Duration::MAX
        } else {
            Duration::from_millis(30)
        }
    }

    /// held bytes not shown yet
    fn unshown(&self) -> bool {
        self.held.len() > self.shown
    }

    /// nothing more came for a while: what's held goes out, and stays held
    /// in case the rest of a marker still comes
    fn flush(&mut self) -> Vec<u8> {
        let out = self.held[self.shown..].to_vec();
        self.shown = self.held.len();
        out
    }
}

/// ssh-style escape for burner shell: `~` right after enter (or at the start)
/// is held, `~.` leaves, `~~` sends one `~`, anything else goes through as is.
/// a way out when the guest hangs and ctrl-c only reaches the VM. a bracketed
/// paste (ESC[200~ .. ESC[201~, only while the guest has bracketed paste on at
/// the terminal) is pasted text, not keys, and goes through untouched
#[derive(Default)]
struct Escape {
    mid_line: bool,
    tilde: bool,
    /// the guest has bracketed paste on, as far as the terminal knows
    bracketed: bool,
    paste: bool,
    /// the last few bytes, to spot the paste brackets across reads
    recent: Vec<u8>,
    last: Option<Instant>,
}

/// a paste whose end bracket hasn't come after this long never will: a
/// terminal sends a paste in one go. the escape works again after it
const PASTE_IDLE: Duration = Duration::from_secs(1);

impl Escape {
    /// true when the caller asked to leave
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        self.feed_at(input, out, Instant::now())
    }

    fn feed_at(&mut self, input: &[u8], out: &mut Vec<u8>, now: Instant) -> bool {
        if self.paste
            && self
                .last
                .is_some_and(|t| now.duration_since(t) >= PASTE_IDLE)
        {
            self.paste = false;
            self.mid_line = true;
        }
        self.last = Some(now);
        for &b in input {
            if self.recent.len() == 6 {
                self.recent.remove(0);
            }
            self.recent.push(b);
            if self.paste {
                out.push(b);
                if self.recent.ends_with(b"\x1b[201~") {
                    self.paste = false;
                    self.mid_line = true;
                }
                continue;
            }
            if self.tilde {
                self.tilde = false;
                match b {
                    b'.' => return true,
                    b'~' => {
                        out.push(b'~');
                        self.mid_line = true;
                        continue;
                    }
                    _ => out.push(b'~'),
                }
            } else if b == b'~' && !self.mid_line {
                self.tilde = true;
                continue;
            }
            out.push(b);
            self.mid_line = !matches!(b, b'\r' | b'\n');
            self.paste = self.bracketed && self.recent.ends_with(b"\x1b[200~");
        }
        false
    }
}

fn child_outcome(child: &mut Child) -> Outcome {
    match child.wait() {
        Ok(s) if s.success() => Outcome::Done,
        _ => Outcome::Failed,
    }
}

fn cancelled(cfg: &Config, id: &str) -> bool {
    // unreadable counts as cancelled: nothing keeps running on a record nobody can read
    ledger::peek_strict(&cfg.paths.state, id).map_or(true, |v| v.is_none_or(|v| v.cancel))
}

/// only an entry that says so: an unreadable one doesn't turn a finished run into a kill
fn kill_requested(cfg: &Config, id: &str) -> bool {
    matches!(ledger::peek_strict(&cfg.paths.state, id), Ok(Some(v)) if v.cancel)
}

/// after the console closed: the VM must be gone before its result disk is read
pub(super) fn supervise(child: &mut Child, deadline: Deadline, cfg: &Config, id: &str) -> Outcome {
    let mut next_check = Instant::now();
    let status = loop {
        if let Ok(Some(st)) = child.try_wait() {
            break st;
        }
        let now = Instant::now();
        if deadline.passed() {
            return Outcome::Timeout;
        }
        if is_interrupted() {
            return Outcome::Interrupted;
        }
        if now >= next_check {
            next_check = now + Duration::from_secs(1);
            if cancelled(cfg, id) {
                return Outcome::Cancelled;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // burner kill sets cancel before it kills the cgroup, so a VM that died of a
    // kill always finds it here, even when the once a second check above missed it
    if kill_requested(cfg, id) {
        return Outcome::Cancelled;
    }
    let end = Instant::now() + Duration::from_secs(5);
    while cgroup::populated(id) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    if cgroup::populated(id) {
        cgroup::kill(id);
        return Outcome::Timeout;
    }
    if status.success() {
        Outcome::Done
    } else {
        Outcome::Failed
    }
}

/// what the guest didn't stream live: log bytes past the first LIVE_BYTES
pub(super) fn print_rest(meta: &result::Meta, log: &Path, out: &Out, diag: &Out, until: Instant) {
    let Ok(mut f) = File::open(log) else { return };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = match meta.skipped {
        0 => LIVE_BYTES,
        s if s <= LIVE_BYTES => LIVE_BYTES - s,
        s => {
            let msg = format!(
                "output was {} bytes; the {} bytes after the first 64K are not kept, showing the last 16M",
                s + size,
                s - LIVE_BYTES
            );
            json::note_warning(Kind::Output, &msg, false);
            diag.put(format!("burner: {msg}\n").as_bytes(), None);
            0
        }
    };
    if size <= start || f.seek(SeekFrom::Start(start)).is_err() {
        return;
    }
    deliver_from(&mut f, out, until);
}

/// false when the file couldn't be read in full before the deadline
pub(super) fn deliver(path: &Path, out: &Out, until: Instant) -> bool {
    File::open(path).is_ok_and(|mut f| deliver_from(&mut f, out, until))
}

fn deliver_from(f: &mut File, out: &Out, until: Instant) -> bool {
    let want = f.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
    let pos = f.stream_position().unwrap_or(0);
    let (mut sent, mut buf) = (0u64, vec![0u8; 1 << 20]);
    loop {
        if Instant::now() >= until || is_interrupted() {
            return false;
        }
        match f.read(&mut buf) {
            Ok(0) => return pos + sent == want,
            Ok(n) => {
                out.put(&buf[..n], Some(until));
                sent += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// what a current image's init has said before the shell starts
    fn v2(token: &str) -> Markers {
        let mut e = Markers::new(token);
        let shell = format!("BURNER-{token}-SHELL2;");
        assert_eq!(e.feed(shell.as_bytes()), b"".to_vec());
        assert_eq!(e.proto, Some(2));
        e
    }

    #[test]
    fn shell_end_marker() {
        // the bare marker an image built before the end record sends
        let all = b"burner:~# exit\r\nBURNER-abc-END[ 10.66] reboot: Restarting system\r\n";
        let want = b"burner:~# exit\r\n".to_vec();
        for i in 0..=all.len() {
            let mut e = Markers::new("abc");
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, want, "split at {i}");
            assert_eq!(e.ended, Some(Ended::Legacy));
        }
        // a held "BUR" that turns out not to be the marker still shows
        let mut e = v2("abc");
        assert_eq!(e.feed(b"echo BUR"), b"echo ".to_vec());
        assert_eq!(e.hold(), Duration::from_millis(30));
        assert_eq!(e.flush(), b"BUR".to_vec());
        assert_eq!(e.feed(b"NING\r\n"), b"NING\r\n".to_vec());
        // another token's marker is just output
        let mut e = v2("abc");
        assert_eq!(
            e.feed(b"BURNER-xyz-END\r\n"),
            b"BURNER-xyz-END\r\n".to_vec()
        );
        assert!(e.ended.is_none());
    }

    #[test]
    fn size_record() {
        let path = std::env::temp_dir().join(format!("burner-tty-{}", std::process::id()));
        let f = File::create(&path).unwrap();
        write_size(&f, 0, (30, 100)).unwrap();
        write_size(&f, 12, (9, 7)).unwrap();
        let got = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(got.lines().next(), Some("burner-tty 12 9 7 12"));
    }

    #[test]
    fn schedstat_lines() {
        assert_eq!(sched_runs("2187231 30210 42\n"), Some(42));
        // accounting off
        assert_eq!(sched_runs("0 0 0\n"), None);
        assert_eq!(sched_runs("12 0\n"), None);
    }

    #[test]
    fn halt_lines() {
        assert_eq!(
            halt_match(b"[    1.389719] reboot: System halted\r\n"),
            Halt::Whole
        );
        assert_eq!(halt_match(b"[ 12.5] reboot: Power down"), Halt::Whole);
        assert_eq!(halt_match(b"[ 12.5] reboot: Pow"), Halt::Start);
        assert_eq!(halt_match(b"[    1"), Halt::Start);
        assert_eq!(halt_match(b"[1]+  Done"), Halt::No);
        assert_eq!(halt_match(b"[] reboot: Power down"), Halt::No);
        assert_eq!(halt_match(b"reboot: System halted\r\n"), Halt::No);
        assert_eq!(halt_match(b"[1;1H"), Halt::No);
        assert_eq!(
            halt_match(b"[    1.0] reboot: Restarting system\r\n"),
            Halt::No
        );
        assert_eq!(halt_match(b"[    1.0] reboot: Power down\r\nx"), Halt::No);
    }

    #[test]
    fn halt_line_held_while_last() {
        let line = b"[    1.389719] reboot: System halted\r\n";
        let all = [&b"# poweroff -f\r\n"[..], line].concat();
        for i in 0..=all.len() {
            let mut h = HaltLine::default();
            let mut got = h.feed(&all[..i]);
            got.extend(h.feed(&all[i..]));
            assert_eq!(got, b"# poweroff -f\r\n".to_vec(), "split at {i}");
            assert!(h.whole_since.is_some(), "split at {i}");
            // more output: it wasn't the end, and it all shows
            got.extend(h.feed(b"# "));
            assert_eq!(got, [&all[..], b"# "].concat(), "split at {i}");
            assert!(h.since.is_none() && h.whole_since.is_none());
        }
        // after what a full-screen app drew last, with no line break
        let mut h = HaltLine::default();
        assert_eq!(
            h.feed(b"\x1b[24;1H- f 1/1\x1b[1;1H"),
            b"\x1b[24;1H- f 1/1\x1b[1;1H"
        );
        assert_eq!(h.feed(line), b"".to_vec());
        assert!(h.whole_since.is_some());
        // but never the [ of a CSI, even when the ESC came in an earlier read
        let mut h = HaltLine::default();
        assert_eq!(h.feed(b"x\x1b"), b"x\x1b".to_vec());
        assert_eq!(h.feed(b"[1"), b"[1".to_vec());
        assert_eq!(h.feed(b"\x1b[1"), b"\x1b[1".to_vec());
        assert!(h.since.is_none());
        // a start that goes nowhere is let out by release
        let mut h = HaltLine::default();
        assert_eq!(h.feed(b"x\n[ 1"), b"x\n".to_vec());
        assert!(h.since.is_some() && h.whole_since.is_none());
        assert_eq!(h.release(), b"[ 1".to_vec());
        assert_eq!(h.feed(b".0]"), b".0]".to_vec());
    }

    #[test]
    fn shell_ready_marker() {
        let all = b"\r\nburner: fresh VM.\r\n\r\nBURNER-abc-READYburner:~# ";
        for i in 0..=all.len() {
            let mut e = v2("abc");
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            got.extend(e.flush());
            assert_eq!(
                got,
                b"\r\nburner: fresh VM.\r\n\r\nburner:~# ".to_vec(),
                "split at {i}"
            );
            assert!(e.ready && e.ended.is_none(), "split at {i}");
        }
        let mut e = v2("abc");
        assert_eq!(
            e.feed(b"BURNER-abc-READYx\r\nBURNER-abc-END0;"),
            b"x\r\n".to_vec()
        );
        assert!(e.ready && e.ended == Some(Ended::Exit(0)));
        let mut e = v2("abc");
        assert_eq!(e.feed(b"BURNER-abc-REA"), b"".to_vec());
        assert_eq!(e.feed(b"L"), b"BURNER-abc-REAL".to_vec());
        assert!(!e.ready);
    }

    #[test]
    fn shell_end_record_held_across_gaps() {
        // a gap of any length in the middle of the record: it's held, not let
        // out, once it has the whole token
        let mut e = v2("f72b08526ecfa370");
        assert_eq!(e.feed(b"$ BURNER-f72b08526ecfa370-E"), b"$ ".to_vec());
        assert_eq!(e.hold(), Duration::MAX);
        assert_eq!(e.feed(b"ND"), b"".to_vec());
        assert_eq!(e.feed(b"0"), b"".to_vec());
        assert_eq!(e.hold(), Duration::MAX);
        assert_eq!(e.feed(b";[ 3.05] reboot: Restarting system"), b"".to_vec());
        assert_eq!(e.ended, Some(Ended::Exit(0)));
        // before the token is whole it's let out after a moment, and still
        // counts when the rest comes
        let mut e = v2("f72b08526ecfa370");
        assert_eq!(e.feed(b"$ BURNER-f72b"), b"$ ".to_vec());
        assert_eq!(e.hold(), Duration::from_millis(30));
        assert_eq!(e.flush(), b"BURNER-f72b".to_vec());
        assert!(!e.unshown());
        assert_eq!(e.flush(), b"".to_vec());
        assert_eq!(e.feed(b"08526ecfa"), b"".to_vec());
        assert_eq!(e.flush(), b"08526ecfa".to_vec());
        assert_eq!(e.feed(b"370-END3;\r\n[ 1.0] reboot"), b"".to_vec());
        assert_eq!(e.ended, Some(Ended::Exit(3)));
        // and when it doesn't, nothing shows twice
        let mut e = v2("f72b08526ecfa370");
        assert_eq!(e.feed(b"BURNER-f72"), b"".to_vec());
        assert_eq!(e.flush(), b"BURNER-f72".to_vec());
        assert_eq!(e.feed(b"x BURNER-f"), b"x ".to_vec());
        assert_eq!(e.flush(), b"BURNER-f".to_vec());
        assert_eq!(e.feed(b"oo"), b"oo".to_vec());
        assert!(e.ended.is_none() && !e.unshown());
    }

    #[test]
    fn shell_end_record() {
        let all = b"exit 3\r\nBURNER-abc-END3;[ 1.0] reboot: Restarting system\r\n";
        for i in 0..=all.len() {
            let mut e = v2("abc");
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, b"exit 3\r\n".to_vec(), "split at {i}");
            assert_eq!(e.ended, Some(Ended::Exit(3)), "split at {i}");
        }
        let end = |s: &[u8]| {
            let mut e = v2("abc");
            let shown = e.feed(s);
            (e.ended, shown)
        };
        assert_eq!(end(b"BURNER-abc-END0;").0, Some(Ended::Exit(0)));
        assert_eq!(end(b"BURNER-abc-END255;").0, Some(Ended::Exit(255)));
        assert_eq!(end(b"BURNER-abc-ENDp;").0, Some(Ended::PowerOff));
        assert_eq!(end(b"BURNER-abc-ENDr;").0, Some(Ended::Reboot));
        assert_eq!(end(b"BURNER-abc-ENDf;").0, Some(Ended::NoStart));
        assert_eq!(end(b"BURNER-abc-ENDl;").0, Some(Ended::Lost));
        // only a whole, well formed record counts; anything else is text
        for bad in [
            &b"BURNER-abc-END[ 1.0] reboot\r\n"[..],
            b"BURNER-abc-END256;x",
            b"BURNER-abc-END1234;",
            b"BURNER-abc-END0p;",
            b"BURNER-abc-ENDx;",
            b"BURNER-abc-END;",
        ] {
            assert_eq!(end(bad), (None, bad.to_vec()), "{bad:?}");
        }
        // a record still coming in is held
        assert_eq!(end(b"BURNER-abc-END12"), (None, b"".to_vec()));
    }

    #[test]
    fn shell_record_versions() {
        let end = |e: &mut Markers, s: &[u8]| {
            let shown = e.feed(s);
            (e.ended, shown)
        };
        // the version comes in pieces like anything else
        let mut e = Markers::new("abc");
        assert_eq!(end(&mut e, b"hi BURNER-abc-SHE"), (None, b"hi ".to_vec()));
        assert_eq!(end(&mut e, b"LL2;x"), (None, b"x".to_vec()));
        assert_eq!(e.proto, Some(2));
        // one this burner doesn't know is just text
        let mut e = Markers::new("abc");
        assert_eq!(
            e.feed(b"BURNER-abc-SHELL3;"),
            b"BURNER-abc-SHELL3;".to_vec()
        );
        assert_eq!(e.proto, None);
        // version 1: READY with no version before it, the exit code and p or r
        for (rec, want) in [
            (&b"BURNER-abc-END3;"[..], Ended::Exit(3)),
            (b"BURNER-abc-END0p;", Ended::PowerOff),
            (b"BURNER-abc-END0r;", Ended::Reboot),
        ] {
            let mut e = Markers::new("abc");
            assert_eq!(e.feed(b"BURNER-abc-READY"), b"".to_vec());
            assert_eq!(e.proto, Some(1));
            assert_eq!(end(&mut e, rec), (Some(want), b"".to_vec()), "{rec:?}");
        }
        let mut e = Markers::new("abc");
        e.feed(b"BURNER-abc-READY");
        assert_eq!(end(&mut e, b"BURNER-abc-END0"), (None, b"".to_vec()));
        assert_eq!(end(&mut e, b"p"), (None, b"".to_vec()));
        assert_eq!(end(&mut e, b";"), (Some(Ended::PowerOff), b"".to_vec()));
        let mut e = Markers::new("abc");
        e.feed(b"BURNER-abc-READY");
        assert_eq!(end(&mut e, b"BURNER-abc-ENDf;").0, None);
        // the bare marker only from an image that said neither
        let mut e = v2("abc");
        assert_eq!(end(&mut e, b"BURNER-abc-END\r\n").0, None);
    }

    #[test]
    fn shell_escape() {
        let run = |chunks: &[&[u8]]| {
            let (mut e, mut out) = (Escape::default(), Vec::new());
            let left = chunks.iter().any(|c| e.feed(c, &mut out));
            (left, out)
        };
        assert_eq!(run(&[b"~."]), (true, vec![]));
        assert!(run(&[b"ls\r", b"~", b"."]).0);
        assert_eq!(run(&[b"a~."]), (false, b"a~.".to_vec()));
        assert_eq!(run(&[b"~~x"]), (false, b"~x".to_vec()));
        assert_eq!(run(&[b"~x"]), (false, b"~x".to_vec()));
        assert_eq!(run(&[b"\r~."]), (true, b"\r".to_vec()));
    }

    #[test]
    fn shell_escape_skips_bracketed_paste() {
        let run = |chunks: &[&[u8]]| {
            let mut e = Escape {
                bracketed: true,
                ..Escape::default()
            };
            let mut out = Vec::new();
            let left = chunks.iter().any(|c| e.feed(c, &mut out));
            (left, out)
        };
        let paste = b"\x1b[200~before\r~.after\r~~tilde\r\x1b[201~";
        assert_eq!(run(&[paste]), (false, paste.to_vec()));
        // brackets split across reads
        let (a, b) = paste.split_at(4);
        let (b, c) = b.split_at(b.len() - 3);
        assert_eq!(run(&[a, b, c]), (false, paste.to_vec()));
        // typed keys after the paste still get the escape, after enter
        assert!(run(&[paste, b"\r", b"~."]).0);
        assert!(!run(&[paste, b"~."]).0);
    }

    #[test]
    fn shell_escape_paste_brackets_only_when_on() {
        // the terminal wasn't asked for bracketed paste, so these are typed keys
        let (mut e, mut out) = (Escape::default(), Vec::new());
        assert!(e.feed(b"\x1b[200~\r~.", &mut out));
    }

    #[test]
    fn shell_escape_after_a_paste_that_never_ends() {
        let t = Instant::now();
        let mut e = Escape {
            bracketed: true,
            ..Escape::default()
        };
        let mut out = Vec::new();
        assert!(!e.feed_at(b"\x1b[200~half a paste\r", &mut out, t));
        assert!(!e.feed_at(b"~.", &mut out, t + Duration::from_millis(500)));
        assert!(!e.feed_at(b"\r~.", &mut out, t + Duration::from_millis(900)));
        // quiet for PASTE_IDLE: the paste is over, enter and ~. leave
        let later = t + Duration::from_millis(900) + PASTE_IDLE;
        assert!(!e.feed_at(b"~.", &mut out, later));
        assert!(e.feed_at(b"\r~.", &mut out, later));
    }

    #[test]
    fn markers() {
        assert_eq!(
            find_at_line_start(b"xBEGIN\nBEGIN\n", b"BEGIN\n", true),
            Some(7)
        );
        assert_eq!(find_at_line_start(b"BEGIN\n", b"BEGIN\n", true), Some(0));
        assert_eq!(find_at_line_start(b"noise BEGIN\n", b"BEGIN\n", true), None);
        // after a trim, the buffer's first byte may sit mid-line
        assert_eq!(find_at_line_start(b"BEGIN\n", b"BEGIN\n", false), None);
        assert_eq!(
            find_at_line_start(b"BEGIN\nBEGIN\n", b"BEGIN\n", false),
            Some(6)
        );
    }
}
