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
use crate::output::{Dest, Out, escape_controls};
use crate::result;
use crate::sys;

const SERIAL_CAP: u64 = 1 << 20;
const LIVE_BYTES: u64 = 65536;
/// input the shell holds for a VM that isn't taking it; past this it's dropped
const TO_VM_CAP: usize = 16 << 20;

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

/// how a shell session went
pub(super) struct Shell {
    pub(super) outcome: Outcome,
    /// what guest init said about the shell's end. None when it said nothing:
    /// the VM crashed or was reset under the shell
    pub(super) end: Option<Ended>,
    /// the terminal reset is queued last on it, to wait on before printing
    pub(super) screen: Out,
}

pub(super) struct Ended {
    pub(super) rc: u8,
}

/// `burner shell`: the caller's terminal goes raw and burner copies bytes both
/// ways. keystrokes go to the VM as they are; what the VM prints goes through a
/// filter so it can't set titles, the clipboard or anything else on the terminal
pub(super) fn relay(
    child: &mut Child,
    token: &str,
    deadline: Deadline,
    cfg: &Config,
    id: &str,
) -> Shell {
    let screen = Out::new_unescaped(Dest::Stdout);
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
    sys::restore_tty_on_panic(crate::output::TERM_RESET); // saves the tty before it goes raw
    let _ = sys::set_raw(0);
    let mut filter = crate::output::TermFilter::new(!crate::output::term_utf8());
    let mut escape = Escape::default();
    let mut end = ShellEnd::new(token);
    let mut held_since: Option<Instant> = None;
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
        // stdin is always read, so ~. works even when the VM stops taking input
        let mut fds = Vec::new();
        if stdin_open {
            fds.push(0);
        }
        if console_open {
            fds.push(vout_fd);
        }
        // a held possible marker start waits at most 30ms, so typing never lags
        let wait = if held_since.is_some() { 30 } else { 200 };
        let ready = sys::poll_read(&fds, deadline.left().min(Duration::from_millis(wait)));
        if ready.contains(&0) {
            match io::stdin().lock().read(&mut buf) {
                Ok(0) | Err(_) => stdin_open = false,
                Ok(n) => {
                    let mut keys = Vec::new();
                    if escape.feed(&buf[..n], &mut keys) {
                        break Outcome::Detached;
                    }
                    if console_open {
                        let room = TO_VM_CAP.saturating_sub(to_vm.len());
                        to_vm.extend_from_slice(&keys[..keys.len().min(room)]);
                    }
                }
            }
        }
        if let Some(w) = vin.as_mut()
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
                    held_since =
                        (!end.held.is_empty()).then(|| held_since.unwrap_or_else(Instant::now));
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
        if held_since.is_some_and(|t| t.elapsed() >= Duration::from_millis(30)) {
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
    screen.finish(&filter.reset());
    Shell {
        outcome,
        end: end.ended.then(|| Ended {
            rc: end.rc().unwrap_or(0),
        }),
        screen,
    }
}

/// watches the shell's console for guest init's end marker, `BURNER-<token>-END`
/// followed by the shell's exit code and `;` (an image built before that sends
/// none). what comes after it (the guest kernel's reboot line) never reaches
/// the caller's terminal. bytes that could be the start of the marker wait
/// until it's clear they aren't
struct ShellEnd {
    marker: Vec<u8>,
    held: Vec<u8>,
    ended: bool,
    /// what came after the marker, up to the `;`
    tail: Vec<u8>,
}

impl ShellEnd {
    fn new(token: &str) -> ShellEnd {
        ShellEnd {
            marker: format!("BURNER-{token}-END").into_bytes(),
            held: Vec::new(),
            ended: false,
            tail: Vec::new(),
        }
    }

    /// what can go to the screen now
    fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        if self.ended {
            self.keep_tail(b);
            return Vec::new();
        }
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        if let Some(i) = buf
            .windows(self.marker.len())
            .position(|w| w == self.marker)
        {
            self.ended = true;
            self.keep_tail(&buf[i + self.marker.len()..]);
            buf.truncate(i);
            return buf;
        }
        let keep = (1..self.marker.len().min(buf.len() + 1))
            .rev()
            .find(|&k| buf.ends_with(&self.marker[..k]))
            .unwrap_or(0);
        self.held = buf.split_off(buf.len() - keep);
        buf
    }

    /// nothing more came, so what was held back wasn't the marker
    fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    fn keep_tail(&mut self, b: &[u8]) {
        if !self.tail.contains(&b';') {
            let room = 8usize.saturating_sub(self.tail.len());
            self.tail.extend(b.iter().take(room));
        }
    }

    /// the shell's exit code from after the marker, if it sent one
    fn rc(&self) -> Option<u8> {
        let n = self.tail.iter().take_while(|b| b.is_ascii_digit()).count();
        if n == 0 || self.tail.get(n) != Some(&b';') {
            return None;
        }
        std::str::from_utf8(&self.tail[..n]).ok()?.parse().ok()
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
        let all = b"burner:~# exit\r\nBURNER-abc-END[ 10.66] reboot: Restarting system\r\n";
        let want = b"burner:~# exit\r\n".to_vec();
        for i in 0..=all.len() {
            let mut e = ShellEnd::new("abc");
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, want, "split at {i}");
            assert!(e.ended);
        }
        // a held "BUR" that turns out not to be the marker still shows
        let mut e = ShellEnd::new("abc");
        assert_eq!(e.feed(b"echo BUR"), b"echo ".to_vec());
        assert_eq!(e.flush(), b"BUR".to_vec());
        assert_eq!(e.feed(b"NING\r\n"), b"NING\r\n".to_vec());
        // another token's marker is just output
        let mut e = ShellEnd::new("abc");
        assert_eq!(
            e.feed(b"BURNER-xyz-END\r\n"),
            b"BURNER-xyz-END\r\n".to_vec()
        );
        assert!(!e.ended);
    }

    #[test]
    fn shell_end_exit_code() {
        let all = b"exit 3\r\nBURNER-abc-END3;[ 1.0] reboot: Restarting system\r\n";
        for i in 0..=all.len() {
            let mut e = ShellEnd::new("abc");
            let mut got = e.feed(&all[..i]);
            got.extend(e.feed(&all[i..]));
            assert_eq!(got, b"exit 3\r\n".to_vec(), "split at {i}");
            assert_eq!(e.rc(), Some(3), "split at {i}");
        }
        let rc = |s: &[u8]| {
            let mut e = ShellEnd::new("abc");
            e.feed(s);
            (e.ended, e.rc())
        };
        assert_eq!(rc(b"BURNER-abc-END0;"), (true, Some(0)));
        assert_eq!(rc(b"BURNER-abc-END255;"), (true, Some(255)));
        // an older guest init sends no code
        assert_eq!(rc(b"BURNER-abc-END[ 1.0] reboot"), (true, None));
        assert_eq!(rc(b"BURNER-abc-END256;"), (true, None));
        assert_eq!(rc(b"BURNER-abc-END12"), (true, None));
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
