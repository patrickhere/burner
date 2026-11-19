use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Child, ChildStdout};
use std::time::{Duration, Instant};

use super::{Deadline, Outcome, is_interrupted};
use crate::cgroup;
use crate::config::Config;
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
/// how long the vCPUs must sit still after the kernel's halt line
const HALT_CHECK: Duration = Duration::from_millis(1500);

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
            diag.put(b"burner: console over 1M, live output stopped\n", None);
            st = St::Capped;
        }
    }
    if st == St::Body {
        flush_held(&mut held_nl);
        out.put(&pending, None);
    }
    // a kill during boot ends the VM before the job, that's not worth the console tail
    if st == St::Pre && !kill_requested(cfg, id) {
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
}

/// how a shell session went
pub(super) struct Shell {
    pub(super) outcome: Outcome,
    /// what guest init said about the shell's end. None when it said nothing:
    /// the VM crashed or was reset under the shell
    pub(super) end: Option<Ended>,
    /// the terminal reset is queued last on it, to wait on before printing
    pub(super) screen: Out,
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
    } = io;
    let screen = Out::new_screen();
    let (Some(vin), Some(mut vout)) = (child.stdin.take(), child.stdout.take()) else {
        return Shell {
            outcome: Outcome::Failed,
            end: None,
            screen,
        };
    };
    let (vin_fd, vout_fd) = (vin.as_raw_fd(), vout.as_raw_fd());
    // blocking pipes would let a stuck VM freeze the loop that enforces the ttl
    if sys::set_nonblocking(vin_fd).is_err() || sys::set_nonblocking(vout_fd).is_err() {
        return Shell {
            outcome: Outcome::Failed,
            end: None,
            screen,
        };
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
    let mut end = Markers::new(token, legacy);
    // the last of the console, and when it ended in the kernel's halt line,
    // with the vCPUs' run count then
    let (mut tail, mut halt_seen): (Vec<u8>, Option<(Instant, Option<u64>)>) = (Vec::new(), None);
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
        // shell has no pid namespace of its own, sysrq o) leaves firecracker
        // running. its last line can be printed by anyone, so it only counts
        // once the vCPUs have stopped running too
        if let Some((t, runs)) = halt_seen
            && t.elapsed() >= HALT_CHECK
        {
            let now = vcpu_runs(child.id());
            if runs.is_some() && now == runs {
                halted = true;
                break Outcome::Done;
            }
            // still running: it can take a moment after the line to stop
            halt_seen = Some((Instant::now(), now));
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
        let wait = if held_since.is_some() || (raw && !open) {
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
                    if escape.feed(&buf[..n], &mut keys) {
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
                    screen.put(&filter.feed(&show), None);
                    if !show.is_empty() {
                        tail.extend_from_slice(&show);
                        tail.drain(..tail.len().saturating_sub(128));
                        halt_seen =
                            halt_line(&tail).then(|| (Instant::now(), vcpu_runs(child.id())));
                    }
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
                    held_since =
                        (!end.held.is_empty()).then(|| held_since.unwrap_or_else(Instant::now));
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
            screen.put(&filter.feed(&end.flush()), None);
            held_since = None;
        }
    };
    // a kill that landed as the VM was exiting still counts as a kill
    let outcome = match outcome {
        Outcome::Done | Outcome::Failed if cancelled(cfg, id) => Outcome::Cancelled,
        o => o,
    };
    // output still queued goes out if the terminal takes it soon; a terminal
    // that has stopped reading would leave the reset stuck behind it
    screen.drain(Instant::now() + Duration::from_secs(2));
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

/// whether the console ends in the line the guest kernel prints when it stops
/// for good: `[    1.389719] reboot: System halted` or `... reboot: Power down`
fn halt_line(tail: &[u8]) -> bool {
    let t = tail.strip_suffix(b"\n").unwrap_or(tail);
    let t = t.strip_suffix(b"\r").unwrap_or(t);
    let Some(t) = [&b"] reboot: System halted"[..], b"] reboot: Power down"]
        .iter()
        .find_map(|m| t.strip_suffix(*m))
    else {
        return false;
    };
    let line = t.rsplit(|&b| b == b'\n').next().unwrap_or(t);
    let line = line.strip_prefix(b"\r").unwrap_or(line);
    line.strip_prefix(b"[").is_some_and(|ts| {
        !ts.is_empty() && ts.iter().all(|b| b.is_ascii_digit() || b" .".contains(b))
    })
}

/// how many times firecracker's vCPU threads have been scheduled, from
/// /proc/PID/task/*/schedstat. a halted guest's vCPUs never run again; an idle
/// one still wakes for its timers
fn vcpu_runs(pid: u32) -> Option<u64> {
    let mut total = None;
    for t in std::fs::read_dir(format!("/proc/{pid}/task"))
        .ok()?
        .flatten()
    {
        let p = t.path();
        if !std::fs::read_to_string(p.join("comm")).is_ok_and(|c| c.starts_with("fc_vcpu")) {
            continue;
        }
        let stat = std::fs::read_to_string(p.join("schedstat")).ok()?;
        let runs: u64 = stat.split_whitespace().nth(2)?.parse().ok()?;
        total = Some(total.unwrap_or(0) + runs);
    }
    total
}

/// watches the shell's console for guest init's markers and keeps them off the
/// caller's terminal: `BURNER-<token>-READY` right before the shell starts, and
/// the end record `BURNER-<token>-END<status>;` after it, where status is the
/// shell's exit code, or p (powered off), r (rebooted), f (the shell couldn't
/// start) or l (it ended without an exit code). the end record only counts
/// once it's whole; an image built before that sends a bare `END`, which
/// counts for one (legacy) only. what comes after the end (the guest kernel's
/// reboot line) never shows either.
///
/// bytes that could be the start of a marker are held until it's clear. once
/// they have the whole `BURNER-<token>-`, they're held for as long as it takes
/// (only the guest knows the token, so it can only hide its own output)
struct Markers {
    prefix: Vec<u8>,
    legacy: bool,
    held: Vec<u8>,
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

/// what's after `END` so far
enum Record {
    Done(Ended),
    Partial,
    Bad,
}

fn end_record(p: &[u8]) -> Record {
    let digits = p.iter().take_while(|b| b.is_ascii_digit()).count();
    let (status, rest) = match (digits, p.first()) {
        (0, None) => return Record::Partial,
        (0, Some(b'p')) => (Some(Ended::PowerOff), &p[1..]),
        (0, Some(b'r')) => (Some(Ended::Reboot), &p[1..]),
        (0, Some(b'f')) => (Some(Ended::NoStart), &p[1..]),
        (0, Some(b'l')) => (Some(Ended::Lost), &p[1..]),
        (0, Some(_)) => return Record::Bad,
        (n, _) if n > 3 => return Record::Bad,
        (n, _) => (
            std::str::from_utf8(&p[..n])
                .ok()
                .and_then(|s| s.parse().ok())
                .map(Ended::Exit),
            &p[n..],
        ),
    };
    match (status, rest.first()) {
        (None, _) => Record::Bad,
        (Some(e), Some(b';')) => Record::Done(e),
        // digits can go on up to three
        (Some(_), None) => Record::Partial,
        (Some(_), Some(_)) => Record::Bad,
    }
}

impl Markers {
    fn new(token: &str, legacy: bool) -> Markers {
        Markers {
            prefix: format!("BURNER-{token}-").into_bytes(),
            legacy,
            held: Vec::new(),
            ready: false,
            ended: None,
        }
    }

    /// what can go to the screen now
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        if self.ended.is_some() {
            return Vec::new();
        }
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        let mut out = Vec::with_capacity(buf.len());
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
                out.extend_from_slice(&tail[..tail.len() - keep]);
                self.held = tail[tail.len() - keep..].to_vec();
                return out;
            };
            out.extend_from_slice(&buf[at..i]);
            let rest = &buf[i + self.prefix.len()..];
            if let Some(after) = rest.strip_prefix(b"READY") {
                self.ready = true;
                at = buf.len() - after.len();
                continue;
            }
            if let Some(p) = rest.strip_prefix(b"END") {
                if self.legacy {
                    self.ended = Some(Ended::Legacy);
                    return out;
                }
                match end_record(p) {
                    Record::Done(e) => {
                        self.ended = Some(e);
                        return out;
                    }
                    Record::Partial => {
                        self.held = buf[i..].to_vec();
                        return out;
                    }
                    Record::Bad => {}
                }
            } else if b"READY".starts_with(rest) || b"END".starts_with(rest) {
                self.held = buf[i..].to_vec();
                return out;
            }
            // not a marker after all: the guest's own text
            out.push(buf[i]);
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

    /// nothing more came, so what was held back wasn't a marker
    fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// ssh-style escape for burner shell: `~` right after enter (or at the start)
/// is held, `~.` leaves, `~~` sends one `~`, anything else goes through as is.
/// a way out when the guest hangs and ctrl-c only reaches the VM. a bracketed
/// paste (ESC[200~ .. ESC[201~, when the guest asked for them) is pasted text,
/// not keys, and goes through untouched
#[derive(Default)]
struct Escape {
    mid_line: bool,
    tilde: bool,
    paste: bool,
    /// the last few bytes, to spot the paste brackets across reads
    recent: Vec<u8>,
}

impl Escape {
    /// true when the caller asked to leave
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
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
            self.paste = self.recent.ends_with(b"\x1b[200~");
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
            diag.put(
                format!(
                    "burner: output was {} bytes; the {} bytes after the first 64K are not kept, showing the last 16M\n",
                    s + size,
                    s - LIVE_BYTES
                )
                .as_bytes(),
                None,
            );
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

    #[test]
    fn shell_end_marker() {
        // the bare marker an image built before the end record sends
        let all = b"burner:~# exit\r\nBURNER-abc-END[ 10.66] reboot: Restarting system\r\n";
        let want = b"burner:~# exit\r\n".to_vec();
        for i in 0..=all.len() {
            let mut e = Markers::new("abc", true);
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, want, "split at {i}");
            assert_eq!(e.ended, Some(Ended::Legacy));
        }
        // a held "BUR" that turns out not to be the marker still shows
        let mut e = Markers::new("abc", false);
        assert_eq!(e.feed(b"echo BUR"), b"echo ".to_vec());
        assert_eq!(e.hold(), Duration::from_millis(30));
        assert_eq!(e.flush(), b"BUR".to_vec());
        assert_eq!(e.feed(b"NING\r\n"), b"NING\r\n".to_vec());
        // another token's marker is just output
        let mut e = Markers::new("abc", false);
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
    fn halt_lines() {
        assert!(halt_line(
            b"# poweroff -f\r\n[    1.389719] reboot: System halted\r\n"
        ));
        assert!(halt_line(b"[ 12.5] reboot: Power down\r\n"));
        assert!(halt_line(b"[    1.0] reboot: Power down"));
        assert!(!halt_line(
            b"[    1.389719] reboot: System halted\r\nburner:~# "
        ));
        assert!(!halt_line(b"echo [ 1.0] reboot: System halted\r\n"));
        assert!(!halt_line(b"reboot: System halted\r\n"));
        assert!(!halt_line(b"[    1.0] reboot: Restarting system\r\n"));
    }

    #[test]
    fn shell_ready_marker() {
        let all = b"\r\nburner: fresh VM.\r\n\r\nBURNER-abc-READYburner:~# ";
        for i in 0..=all.len() {
            let mut e = Markers::new("abc", false);
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
        let mut e = Markers::new("abc", false);
        assert_eq!(
            e.feed(b"BURNER-abc-READYx\r\nBURNER-abc-END0;"),
            b"x\r\n".to_vec()
        );
        assert!(e.ready && e.ended == Some(Ended::Exit(0)));
        let mut e = Markers::new("abc", false);
        assert_eq!(e.feed(b"BURNER-abc-REA"), b"".to_vec());
        assert_eq!(e.feed(b"L"), b"BURNER-abc-REAL".to_vec());
        assert!(!e.ready);
    }

    #[test]
    fn shell_end_record_held_across_gaps() {
        // a gap of any length in the middle of the record: it's held, not let
        // out, once it has the whole token
        let mut e = Markers::new("f72b08526ecfa370", false);
        assert_eq!(e.feed(b"$ BURNER-f72b08526ecfa370-E"), b"$ ".to_vec());
        assert_eq!(e.hold(), Duration::MAX);
        assert_eq!(e.feed(b"ND"), b"".to_vec());
        assert_eq!(e.feed(b"0"), b"".to_vec());
        assert_eq!(e.hold(), Duration::MAX);
        assert_eq!(e.feed(b";[ 3.05] reboot: Restarting system"), b"".to_vec());
        assert_eq!(e.ended, Some(Ended::Exit(0)));
        // before the token is whole it's let out after a moment
        let mut e = Markers::new("f72b08526ecfa370", false);
        assert_eq!(e.feed(b"BURNER-f72b"), b"".to_vec());
        assert_eq!(e.hold(), Duration::from_millis(30));
    }

    #[test]
    fn shell_end_record() {
        let all = b"exit 3\r\nBURNER-abc-END3;[ 1.0] reboot: Restarting system\r\n";
        for i in 0..=all.len() {
            let mut e = Markers::new("abc", false);
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, b"exit 3\r\n".to_vec(), "split at {i}");
            assert_eq!(e.ended, Some(Ended::Exit(3)), "split at {i}");
        }
        let end = |s: &[u8]| {
            let mut e = Markers::new("abc", false);
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
            let (mut e, mut out) = (Escape::default(), Vec::new());
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
