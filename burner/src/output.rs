//! output to the caller goes through a writer thread with a bounded queue, so a
//! reader that stops reading can't stall the main loop (and with it the ttl).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 8 << 20;
/// what one queued chunk costs beyond its bytes (the Vec and the channel slot),
/// so a flood of tiny writes can't hold far more memory than the cap says
const CHUNK_COST: usize = 128;

pub struct Out {
    tx: mpsc::Sender<Chunk>,
    queued: Arc<AtomicUsize>,
    broken: Arc<AtomicBool>,
    /// set by finish: what's still queued is dropped, only the last chunk goes out
    skip: Arc<AtomicBool>,
    last_done: Arc<AtomicBool>,
    dropped: AtomicBool,
    tty: bool,
    esc: Mutex<TtyEscape>,
}

enum Chunk {
    Data(Vec<u8>),
    Last(Vec<u8>),
}

pub enum Dest {
    Stdout,
    Stderr,
}

impl Out {
    /// bytes go out as they are; for the shell relay, which filters on its own
    pub fn new_unescaped(dest: Dest) -> Out {
        let mut o = Out::new(dest);
        o.tty = false;
        o
    }

    pub fn new(dest: Dest) -> Out {
        let (fd, w): (i32, Box<dyn Write + Send>) = match dest {
            Dest::Stdout => (1, Box::new(std::io::stdout())),
            Dest::Stderr => (2, Box::new(std::io::stderr())),
        };
        Out::to(w, crate::sys::is_tty(fd))
    }

    fn to(mut w: Box<dyn Write + Send>, tty: bool) -> Out {
        let (tx, rx) = mpsc::channel::<Chunk>();
        let queued = Arc::new(AtomicUsize::new(0));
        let broken = Arc::new(AtomicBool::new(false));
        let skip = Arc::new(AtomicBool::new(false));
        let last_done = Arc::new(AtomicBool::new(false));
        let (q, b, sk, done) = (
            queued.clone(),
            broken.clone(),
            skip.clone(),
            last_done.clone(),
        );
        std::thread::spawn(move || {
            for c in rx {
                let (chunk, last) = match c {
                    Chunk::Data(v) => (v, false),
                    Chunk::Last(v) => (v, true),
                };
                if !b.load(Ordering::Relaxed)
                    && (last || !sk.load(Ordering::Relaxed))
                    && (w.write_all(&chunk).is_err() || w.flush().is_err())
                {
                    b.store(true, Ordering::Relaxed);
                }
                if last {
                    done.store(true, Ordering::Relaxed);
                } else {
                    q.fetch_sub(chunk.len() + CHUNK_COST, Ordering::Relaxed);
                }
            }
        });
        Out {
            tx,
            queued,
            broken,
            skip,
            last_done,
            dropped: AtomicBool::new(false),
            tty,
            esc: Mutex::new(TtyEscape::default()),
        }
    }

    /// queue bytes. without `wait_until` they're dropped when the queue is full
    pub fn put(&self, b: &[u8], wait_until: Option<Instant>) {
        if b.is_empty() || self.broken.load(Ordering::Relaxed) {
            return;
        }
        if !self.tty {
            return self.send(b.to_vec(), wait_until);
        }
        // held through the send so chunks queue in the order they were escaped
        let mut esc = self.esc.lock().unwrap_or_else(|e| e.into_inner());
        self.send(esc.feed(b), wait_until);
    }

    fn send(&self, b: Vec<u8>, wait_until: Option<Instant>) {
        if b.is_empty() {
            return;
        }
        loop {
            let q = self.queued.load(Ordering::Relaxed);
            if q + b.len() + CHUNK_COST <= QUEUE_CAP {
                self.queued
                    .fetch_add(b.len() + CHUNK_COST, Ordering::Relaxed);
                let _ = self.tx.send(Chunk::Data(b));
                return;
            }
            if wait_until.is_none_or(|t| Instant::now() > t) || self.broken.load(Ordering::Relaxed)
            {
                self.dropped.store(true, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn dropped(&self) -> bool {
        self.dropped.load(Ordering::Relaxed)
    }

    /// waits until everything queued is written. false if anything was dropped,
    /// the writer broke, or the deadline came first
    pub fn complete(&self, until: Instant) -> bool {
        self.drain(until);
        self.queued.load(Ordering::Relaxed) == 0
            && !self.broken.load(Ordering::Relaxed)
            && !self.dropped()
    }

    pub fn drain(&self, until: Instant) {
        if self.tty && !self.broken.load(Ordering::Relaxed) {
            let mut esc = self.esc.lock().unwrap_or_else(|e| e.into_inner());
            self.send(esc.finish(), Some(until));
        }
        while Instant::now() < until {
            if self.queued.load(Ordering::Relaxed) == 0 || self.broken.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// drops whatever is still queued and writes `last` next, past the queue
    /// cap. for the shell's terminal reset: a reader that stalled behind a
    /// pile of guest output still gets it, and gets it last
    pub fn finish(&self, last: &[u8]) {
        self.skip.store(true, Ordering::Relaxed);
        let _ = self.tx.send(Chunk::Last(last.to_vec()));
    }

    /// waits until finish's chunk is written, the writer broke, or `give_up`
    pub fn wait_last(&self, give_up: impl Fn() -> bool) {
        while !self.last_done.load(Ordering::Relaxed)
            && !self.broken.load(Ordering::Relaxed)
            && !give_up()
        {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// whether the caller's terminal takes utf-8, going by the locale. with no
/// locale set at all it's assumed to. on a terminal that doesn't, the second
/// byte of a utf-8 char can be a C1 control (0x9b is CSI), so non-ascii text
/// is escaped or shown as ? there
pub fn term_utf8() -> bool {
    let var = ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()));
    var.is_none_or(|v| locale_utf8(&v))
}

fn locale_utf8(v: &str) -> bool {
    let v = v.to_ascii_lowercase();
    v.contains("utf-8") || v.contains("utf8")
}

/// guest bytes must not drive the caller's terminal: control characters become
/// \xNN. tab and newline stay; a carriage return only when it starts a \r\n.
/// C1 controls count too when they come as utf-8 code points, and on a terminal
/// that isn't utf-8 so does everything else past ascii
pub fn escape_controls(b: &[u8]) -> Vec<u8> {
    static ASCII: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    escape_for(b, *ASCII.get_or_init(|| !term_utf8()))
}

fn escape_for(b: &[u8], ascii: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let esc = |out: &mut Vec<u8>, c: u8| out.extend_from_slice(format!("\\x{c:02x}").as_bytes());
    for chunk in b.utf8_chunks() {
        let valid = chunk.valid();
        let bytes = valid.as_bytes();
        for (i, ch) in valid.char_indices() {
            let c = ch as u32;
            match ch {
                '\t' | '\n' => out.push(c as u8),
                '\r' if bytes.get(i + 1) == Some(&b'\n') => out.push(b'\r'),
                _ if c < 0x20 || c == 0x7f => esc(&mut out, c as u8),
                _ if (0x80..=0x9f).contains(&c) || (ascii && c >= 0x80) => {
                    out.extend_from_slice(format!("\\u{{{c:x}}}").as_bytes())
                }
                _ => out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes()),
            }
        }
        for &c in chunk.invalid() {
            esc(&mut out, c);
        }
    }
    out
}

/// escape_controls over a stream. a trailing \r and a cut-off utf-8 char wait
/// for the next chunk, so where the reads split doesn't change what's shown
#[derive(Default)]
pub struct TtyEscape {
    held: Vec<u8>,
}

impl TtyEscape {
    pub fn feed(&mut self, b: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        let keep = unfinished_tail(&buf);
        self.held = buf.split_off(buf.len() - keep);
        escape_controls(&buf)
    }

    /// whatever is still held, escaped as it stands
    pub fn finish(&mut self) -> Vec<u8> {
        escape_controls(&std::mem::take(&mut self.held))
    }
}

/// how many bytes at the end could still change meaning: the start of a utf-8
/// char, or a \r that a \n may follow
fn unfinished_tail(b: &[u8]) -> usize {
    let from = b.len().saturating_sub(3);
    if let Some(i) = (from..b.len()).rev().find(|&i| b[i] & 0xc0 != 0x80)
        && std::str::from_utf8(&b[i..]).is_err_and(|e| e.error_len().is_none())
    {
        return b.len() - i;
    }
    usize::from(b.last() == Some(&b'\r'))
}

/// an allowlist for what the VM may send to the caller's terminal in `burner
/// shell`: text, colors, cursor movement, erasing and a few screen modes. it
/// drops every query (the terminal would type the answer into the VM), mouse
/// reporting, OSC/DCS/APC/PM/SOS strings (titles, clipboard, hyperlinks), C1
/// controls and anything it doesn't know. keeps its state across reads, and
/// tracks what it let through that has to be undone when the shell ends
pub struct TermFilter {
    st: FState,
    seq: Vec<u8>,
    utf8: Vec<u8>,
    str_len: usize,
    /// the terminal isn't utf-8: non-ascii chars go out as ?
    ascii: bool,
    /// the cursor is known to be at the start of a line, and that line is
    /// known to be empty: what reset needs to tell whether to add a newline
    col0: bool,
    clean: bool,
    /// the alternate screen mode that's on, and the main screen's two flags
    alt: Option<u32>,
    main_col0: bool,
    main_clean: bool,
    /// the guest turned cursor blinking on or off
    blink: bool,
}

impl Default for TermFilter {
    fn default() -> TermFilter {
        TermFilter::new(false)
    }
}

#[derive(Default, PartialEq)]
enum FState {
    #[default]
    Text,
    Esc,
    /// ESC with intermediate bytes: dropped up to its final byte
    EscInter,
    Charset,
    Csi,
    /// a CSI over SEQ_MAX: dropped up to its final byte
    CsiSkip,
    Str,
    StrEsc,
}

const SEQ_MAX: usize = 64;
/// an OSC/DCS/APC/PM/SOS string longer than this is given up on, so one that
/// never ends doesn't hide the rest of the session
const STR_MAX: usize = 16 << 10;

/// undoes every mode the filter lets through. the panic hook sends this one;
/// a shell that ends normally gets TermFilter::reset, which knows whether the
/// alt screen is on. leaving the alt screen and resetting the scroll region
/// both move the cursor home, so it's saved before them and restored after:
/// the caller's prompt comes back below the session, not over its first line
pub const TERM_RESET: &[u8] = b"\x1b7\x1b[?1049l\x1b[r\x1b8\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l\x1b[?12l";

/// the mode resets after the alt screen and scroll region, same as TERM_RESET
const MODES_RESET: &[u8] = b"\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l";

/// private modes (CSI ? n h/l) a shell or editor needs that make the terminal
/// send nothing back: cursor keys, autowrap, blink, cursor shown, alt screen,
/// bracketed paste
const PRIVATE_MODES: &[u32] = &[1, 7, 12, 25, 47, 1047, 1048, 1049, 2004];

/// CSI finals that only move the cursor, erase, scroll or set colors. not g
/// (tab clear): the guest could clear the caller's tab stops for good
const CSI_FINALS: &[u8] = b"@ABCDEFGHIJKLMPSTXZ`adefmr";

impl TermFilter {
    pub fn new(ascii: bool) -> TermFilter {
        TermFilter {
            st: FState::Text,
            seq: Vec::new(),
            utf8: Vec::new(),
            str_len: 0,
            ascii,
            // the caller pressed enter to start the shell
            col0: true,
            clean: true,
            alt: None,
            main_col0: true,
            main_clean: true,
            blink: false,
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            self.byte(b, &mut out);
        }
        out
    }

    /// what puts the caller's terminal back when the shell ends. leaving the
    /// alt screen comes first: it puts the cursor back where it was on the
    /// main screen, and a terminal with one saved cursor for both screens
    /// (tmux) would otherwise restore the alt screen's spot after it. off the
    /// alt screen, ?1049l would restore a stale saved cursor, so it isn't sent.
    /// it ends on a fresh line, so what comes next doesn't start mid-line or
    /// on top of the guest's last line
    pub fn reset(&self) -> Vec<u8> {
        let mut r = Vec::new();
        let mut fresh = self.col0 && self.clean;
        match self.alt {
            Some(1049) => {
                r.extend_from_slice(b"\x1b[?1049l");
                fresh = self.main_col0 && self.main_clean;
            }
            // these never saved the main screen's cursor, it stays where it was
            Some(m) => {
                r.extend_from_slice(format!("\x1b[?{m}l").as_bytes());
                fresh = false;
            }
            None => {}
        }
        r.extend_from_slice(b"\x1b7\x1b[r\x1b8");
        r.extend_from_slice(MODES_RESET);
        // only when the guest touched it: some terminals blink by default
        if self.blink {
            r.extend_from_slice(b"\x1b[?12l");
        }
        if !fresh {
            r.extend_from_slice(b"\r\n");
        }
        r
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        match self.st {
            FState::Text => self.text(b, out),
            FState::Esc => {
                if b < 0x20 && b != 0x1b {
                    // a control inside a sequence: drop the sequence, act on the control
                    self.st = FState::Text;
                    return self.text(b, out);
                }
                self.seq.push(b);
                match b {
                    b'[' => self.st = FState::Csi,
                    b']' | b'P' | b'_' | b'^' | b'X' => {
                        self.str_len = 0;
                        self.st = FState::Str;
                    }
                    b'(' | b')' => self.st = FState::Charset,
                    0x1b => self.start_esc(),
                    // save/restore cursor, reverse index, keypad modes
                    b'7' | b'8' | b'M' | b'=' | b'>' => {
                        out.extend_from_slice(&self.seq);
                        if b == b'8' || b == b'M' {
                            self.col0 &= b == b'M';
                            self.clean = false;
                        }
                        self.st = FState::Text;
                    }
                    0x20..=0x2f => self.st = FState::EscInter,
                    _ => self.st = FState::Text,
                }
            }
            FState::EscInter | FState::CsiSkip => match b {
                0x1b => self.start_esc(),
                0x00..=0x1f => {
                    self.st = FState::Text;
                    self.text(b, out);
                }
                0x30..=0x7e if self.st == FState::EscInter => self.st = FState::Text,
                0x40..=0x7e => self.st = FState::Text,
                _ => {}
            },
            FState::Charset => {
                if b < 0x20 && b != 0x1b {
                    self.st = FState::Text;
                    return self.text(b, out);
                }
                self.seq.push(b);
                match b {
                    0x1b => self.start_esc(),
                    0x20..=0x2f => self.st = FState::EscInter,
                    // only ascii and line drawing
                    b'B' | b'0' => {
                        out.extend_from_slice(&self.seq);
                        self.st = FState::Text;
                    }
                    _ => self.st = FState::Text,
                }
            }
            FState::Csi => {
                if b == 0x1b {
                    return self.start_esc();
                }
                if b < 0x20 {
                    // a control inside a sequence: drop the sequence, act on the control
                    self.st = FState::Text;
                    return self.text(b, out);
                }
                self.seq.push(b);
                if (0x40..=0x7e).contains(&b) {
                    if csi_allowed(&self.seq[2..]) {
                        out.extend_from_slice(&self.seq);
                        let body = self.seq[2..].to_vec();
                        self.track_csi(&body);
                    }
                    self.st = FState::Text;
                } else if self.seq.len() > SEQ_MAX {
                    self.st = FState::CsiSkip;
                }
            }
            // a terminal ends a string on BEL, ST, CAN, SUB or any other ESC
            FState::Str => match b {
                0x07 | 0x18 | 0x1a => self.st = FState::Text,
                0x1b => self.st = FState::StrEsc,
                _ => {
                    self.str_len += 1;
                    if self.str_len > STR_MAX {
                        self.st = FState::Text;
                    }
                }
            },
            FState::StrEsc => {
                if b == b'\\' {
                    self.st = FState::Text;
                } else {
                    self.start_esc();
                    self.byte(b, out);
                }
            }
        }
    }

    /// keeps the state reset() needs in step with a CSI that went out. where
    /// the column isn't clear it counts as mid-line: an extra blank line beats
    /// a message drawn over the guest's last line
    fn track_csi(&mut self, body: &[u8]) {
        let (&fin, rest) = body.split_last().expect("csi has a final byte");
        let Some(modes) = rest.strip_prefix(b"?") else {
            let num = |i: usize| -> u32 {
                std::str::from_utf8(rest)
                    .ok()
                    .and_then(|p| p.split(';').nth(i))
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0)
            };
            // a move to another line lands on one that may have text on it
            match fin {
                b'H' | b'f' => (self.col0, self.clean) = (num(1) <= 1, false),
                b'G' | b'`' => self.col0 = num(0) <= 1,
                b'E' | b'F' | b'r' => (self.col0, self.clean) = (true, false),
                b'A' | b'B' | b'd' | b'e' => self.clean = false,
                // erasing, scrolling, colors and insert mode
                b'J' | b'K' | b'X' | b'P' | b'@' | b'S' | b'T' | b'm' | b'h' | b'l' => {}
                _ => self.col0 = false,
            }
            return;
        };
        let on = fin == b'h';
        for m in std::str::from_utf8(modes).unwrap_or("").split(';') {
            match m.parse::<u32>() {
                Ok(12) => self.blink = true,
                Ok(1048) if !on => (self.col0, self.clean) = (false, false),
                Ok(n @ (47 | 1047 | 1049)) if on && self.alt.is_none() => {
                    (self.main_col0, self.main_clean) = (self.col0, self.clean);
                    self.alt = Some(n);
                }
                // any of them going off is back on the main screen; only
                // 1049 brings its cursor back
                Ok(n @ (47 | 1047 | 1049)) if !on && self.alt.is_some() => {
                    let back = n == 1049 && self.alt == Some(1049);
                    self.col0 = back && self.main_col0;
                    self.clean = back && self.main_clean;
                    self.alt = None;
                }
                _ => {}
            }
        }
    }

    fn start_esc(&mut self) {
        self.utf8.clear();
        self.seq.clear();
        self.seq.push(0x1b);
        self.st = FState::Esc;
    }

    fn text(&mut self, b: u8, out: &mut Vec<u8>) {
        if b < 0x80 {
            self.utf8.clear(); // a cut-off multibyte char is dropped
            match b {
                0x1b => self.start_esc(),
                b'\r' => {
                    out.push(b);
                    self.col0 = true;
                }
                // vertical tab and form feed move down a line, like line feed
                b'\n' | 0x0b | 0x0c => {
                    out.push(b);
                    self.clean = true;
                }
                0x07 => out.push(b),
                b'\t' | 0x08 | 0x20..=0x7e => {
                    out.push(b);
                    (self.col0, self.clean) = (false, false);
                }
                _ => {}
            }
            return;
        }
        self.utf8.push(b);
        match std::str::from_utf8(&self.utf8) {
            Ok(s) => {
                // C1 controls (U+0080..U+009F) act like ESC sequences on some terminals
                if !s.chars().all(|c| ('\u{80}'..='\u{9f}').contains(&c)) {
                    if self.ascii {
                        out.push(b'?');
                    } else {
                        out.extend_from_slice(&self.utf8);
                    }
                    (self.col0, self.clean) = (false, false);
                }
                self.utf8.clear();
            }
            Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => {} // needs more bytes
            Err(_) => self.utf8.clear(),
        }
    }
}

/// `body` is everything after ESC [, final byte included
fn csi_allowed(body: &[u8]) -> bool {
    let (&fin, rest) = body.split_last().expect("csi has a final byte");
    if rest.iter().any(|b| (0x20..=0x2f).contains(b)) {
        return false; // intermediates: cursor style, soft reset, and so on
    }
    match rest.first() {
        Some(b'?') => {
            matches!(fin, b'h' | b'l')
                && std::str::from_utf8(&rest[1..]).is_ok_and(|p| {
                    p.split(';')
                        .all(|m| m.parse().is_ok_and(|n| PRIVATE_MODES.contains(&n)))
                })
        }
        Some(b'>' | b'<' | b'=') => false,
        _ => {
            let digits = rest
                .iter()
                .all(|b| b.is_ascii_digit() || *b == b';' || *b == b':');
            match fin {
                b'h' | b'l' => rest == b"4", // insert mode, used by line editors
                // ED 3 erases the caller's scrollback, outside the session
                b'J' => matches!(rest, b"" | b"0" | b"1" | b"2"),
                _ => digits && CSI_FINALS.contains(&fin),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a reader that stalls: each write waits until the test lets it through
    struct Stalled(mpsc::Receiver<()>, Arc<Mutex<Vec<u8>>>);

    impl Write for Stalled {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let _ = self.0.recv();
            self.1.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn finish_goes_out_past_a_stalled_backlog() {
        let (go, wait) = mpsc::channel();
        let got = Arc::new(Mutex::new(Vec::new()));
        let o = Out::to(Box::new(Stalled(wait, got.clone())), false);
        o.put(b"first", None);
        // the writer is stuck on "first"; the rest piles up behind it
        std::thread::sleep(Duration::from_millis(50));
        for _ in 0..100 {
            o.put(b"guest", None);
        }
        o.finish(b"RESET");
        for _ in 0..3 {
            go.send(()).unwrap();
        }
        o.wait_last(|| false);
        assert_eq!(*got.lock().unwrap(), b"firstRESET".to_vec());
    }

    #[test]
    fn term_reset_keeps_the_cursor() {
        let r = TERM_RESET;
        assert!(r.starts_with(b"\x1b7"), "cursor saved first");
        let at = |pat: &[u8]| r.windows(pat.len()).position(|w| w == pat).unwrap();
        assert!(
            at(b"\x1b8") > at(b"\x1b[r"),
            "restored after the scroll region reset"
        );
        assert!(
            at(b"\x1b8") > at(b"\x1b[?1049l"),
            "and after leaving the alt screen"
        );
    }

    #[test]
    fn reset_leaves_the_alt_screen_first() {
        let mut f = TermFilter::default();
        let r = f.reset();
        assert!(
            r.starts_with(b"\x1b7\x1b[r\x1b8"),
            "no ?1049l off the alt screen"
        );
        assert!(r.ends_with(MODES_RESET));
        f.feed(b"\x1b[?1049h\x1b[3;1Hx");
        assert!(f.reset().starts_with(b"\x1b[?1049l\x1b7\x1b[r\x1b8"));
        f.feed(b"\x1b[?1049l");
        assert_eq!(f.reset(), r);
        f.feed(b"\x1b[?47h");
        assert!(f.reset().starts_with(b"\x1b[?47l\x1b7"));
        f.feed(b"\x1b[?1049h\x1b[?1047l");
        assert!(f.reset().starts_with(b"\x1b7\x1b[r\x1b8"));
    }

    #[test]
    fn reset_ends_on_a_fresh_line() {
        let fresh = |out: &[u8]| {
            let mut f = TermFilter::default();
            f.feed(out);
            f.reset().ends_with(b"\r\n")
        };
        assert!(!fresh(b""));
        assert!(!fresh(b"burner:~# exit\r\n"));
        assert!(fresh(b"burner:~# "));
        assert!(fresh(b"partial"));
        assert!(fresh("\u{2713}".as_bytes()));
        // a line the cursor moved to may have text on it, top's last one say
        assert!(fresh(b"x\x1b[1;1H"));
        assert!(fresh(b"top\r\n\x1b[H row 1\r\n row 2\r"));
        assert!(fresh(b"\x1b[5;7H"));
        assert!(fresh(b"\r\x1b[3C"));
        assert!(!fresh(b"\r\n\x1b[G\x1b[K\x1b[0m"));
        assert!(fresh(b"\x1b8"));
        // the alt screen: what counts is the main screen under it
        assert!(!fresh(b"vi f\r\n\x1b[?1049h\x1b[12;12Htext"));
        assert!(fresh(b"$ \x1b[?1049h\x1b[H"));
        assert!(!fresh(b"x\r\n\x1b[?1049h\x1b[2;2Hy\x1b[?1049l"));
        assert!(fresh(b"\r\x1b[?47hx\x1b[?47l"));
    }

    #[test]
    fn reset_undoes_blinking() {
        let mut f = TermFilter::default();
        assert!(!f.reset().windows(6).any(|w| w == b"\x1b[?12l"));
        assert_eq!(f.feed(b"\x1b[?12;25h"), b"\x1b[?12;25h".to_vec());
        assert!(f.reset().ends_with(b"\x1b[?12l"));
        assert!(TERM_RESET.ends_with(b"\x1b[?12l"));
    }

    #[test]
    fn filter() {
        let mut f = TermFilter::default();
        assert_eq!(
            f.feed(b"\x1b[1;31mred\x1b[0m"),
            b"\x1b[1;31mred\x1b[0m".to_vec()
        );
        assert_eq!(f.feed(b"a\x1b]52;c;aGk=\x07b"), b"ab".to_vec());
        assert_eq!(f.feed(b"\x1b]0;tit"), b"".to_vec());
        assert_eq!(f.feed(b"le\x1b\\x"), b"x".to_vec());
        assert_eq!(f.feed(b"\x1b[8;100;100t!"), b"!".to_vec());
        assert_eq!(f.feed(b"\x1bPq#0;2;0;0;0\x1b\\ok"), b"ok".to_vec());
        assert_eq!(f.feed(b"\x1b(Bz"), b"\x1b(Bz".to_vec());
    }

    #[test]
    fn filter_queries_and_modes() {
        let mut f = TermFilter::default();
        // queries: the terminal would type the answer into the VM
        for q in [
            &b"\x1b[6n"[..],
            b"\x1b[c",
            b"\x1b[>c",
            b"\x1b[?6n",
            b"\x1b[>0q",
            b"\x1b[18t",
            b"\x1b[?u",
        ] {
            assert_eq!(f.feed(q), b"".to_vec(), "{q:?}");
        }
        // mouse reporting and other modes outside the list
        assert_eq!(f.feed(b"\x1b[?1000h\x1b[?1006h\x1b[?9h"), b"".to_vec());
        assert_eq!(
            f.feed(b"\x1b[?1049h\x1b[?25l\x1b[?2004h"),
            b"\x1b[?1049h\x1b[?25l\x1b[?2004h".to_vec()
        );
        assert_eq!(f.feed(b"\x1b[?1049;1000h"), b"".to_vec());
        assert_eq!(f.feed(b"\x1b[2 q\x1b[!p\x1b[5b"), b"".to_vec());
        assert_eq!(
            f.feed(b"\x1b[2J\x1b[1;1H\x1b[K"),
            b"\x1b[2J\x1b[1;1H\x1b[K".to_vec()
        );
        // unknown escapes and a second ESC mid-sequence
        assert_eq!(f.feed(b"\x1bc\x1b#8x"), b"x".to_vec());
        assert_eq!(f.feed(b"\x1b[1\x1b[31mr"), b"\x1b[31mr".to_vec());
        // a control inside a CSI ends it
        assert_eq!(f.feed(b"\x1b[1\nz"), b"\nz".to_vec());
    }

    #[test]
    fn filter_strings_that_never_end() {
        let mut f = TermFilter::default();
        // another escape ends the string and starts on its own
        assert_eq!(f.feed(b"\x1b]0;x\x1b[1mbold"), b"\x1b[1mbold".to_vec());
        assert_eq!(f.feed(b"\x1b_apc\x1b]0;t\x07ok"), b"ok".to_vec());
        // CAN and SUB end it too
        for end in *b"\x18\x1a" {
            assert_eq!(
                f.feed(&[&b"\x1bPq"[..], &[end], b"seen"].concat()),
                b"seen".to_vec()
            );
        }
        // ESC \\ still ends it, split across reads
        assert_eq!(f.feed(b"\x1b]2;t\x1b"), b"".to_vec());
        assert_eq!(f.feed(b"\\after"), b"after".to_vec());
        // and one that runs on is given up on
        let long = [&b"\x1b]"[..], &vec![b'a'; STR_MAX], b"bcd"].concat();
        assert_eq!(f.feed(&long), b"cd".to_vec());
    }

    #[test]
    fn filter_drops_long_sequences_whole() {
        let mut f = TermFilter::default();
        let params = (1..=40)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(";");
        let csi = format!("L1\x1b[{params}mL2");
        assert_eq!(f.feed(csi.as_bytes()), b"L1L2".to_vec());
        let long = format!("Q1\x1b[{}1CQ2", "0".repeat(99));
        assert_eq!(f.feed(long.as_bytes()), b"Q1Q2".to_vec());
        // one byte under the cap still goes out
        let fits = format!("\x1b[{}1C", "0".repeat(SEQ_MAX - 4));
        assert_eq!(f.feed(fits.as_bytes()), fits.as_bytes().to_vec());
        // ESC with intermediates: DECALN, charset designations it doesn't allow
        assert_eq!(f.feed(b"P1\x1b#8P2\x1b%GP3\x1b(%6P4"), b"P1P2P3P4".to_vec());
        assert_eq!(f.feed(b"\x1b(0q\x1b(B"), b"\x1b(0q\x1b(B".to_vec());
        // a control inside one ends it and still acts
        assert_eq!(f.feed(b"\x1b#\r\x1b\nz"), b"\r\nz".to_vec());
    }

    #[test]
    fn filter_keeps_scrollback() {
        let mut f = TermFilter::default();
        for ok in [&b"\x1b[J"[..], b"\x1b[0J", b"\x1b[1J", b"\x1b[2J"] {
            assert_eq!(f.feed(ok), ok.to_vec());
        }
        for bad in [&b"\x1b[3J"[..], b"\x1b[2;3J", b"\x1b[03J"] {
            assert_eq!(f.feed(bad), b"".to_vec(), "{bad:?}");
        }
    }

    #[test]
    fn filter_keeps_tab_stops() {
        let mut f = TermFilter::default();
        assert_eq!(f.feed(b"a\x1b[3gb\x1b[0gc\x1b[gd"), b"abcd".to_vec());
    }

    #[test]
    fn filter_utf8_and_c1() {
        let mut f = TermFilter::default();
        assert_eq!(
            f.feed("h\u{e9}llo \u{2713}".as_bytes()),
            "h\u{e9}llo \u{2713}".as_bytes().to_vec()
        );
        // 8-bit OSC and CSI, raw and utf-8 encoded
        assert_eq!(f.feed(b"a\x9d0;x\x9cb"), b"a0;xb".to_vec());
        assert_eq!(f.feed("a\u{9b}6nb".as_bytes()), b"a6nb".to_vec());
        // a char split across reads
        let v = "\u{2713}".as_bytes();
        assert_eq!(f.feed(&v[..1]), b"".to_vec());
        assert_eq!(f.feed(&v[1..]), v.to_vec());
        assert_eq!(f.feed(b"\xff\xfeok"), b"ok".to_vec());
        assert_eq!(f.feed(b"\x00\x0e\x7fok"), b"ok".to_vec());
        assert_eq!(f.feed(b"v\x0bw\x0cx"), b"v\x0bw\x0cx".to_vec());
    }

    #[test]
    fn filter_on_a_terminal_that_isnt_utf8() {
        // U+011B is c4 9b: on a latin-1 terminal 0x9b is CSI, and 6n a query
        let mut f = TermFilter::new(true);
        assert_eq!(
            f.feed("a\u{11b}6n \u{2713}b".as_bytes()),
            b"a?6n ?b".to_vec()
        );
        assert_eq!(f.feed("\u{9d}x".as_bytes()), b"x".to_vec());
        assert_eq!(
            escape_for("a\u{11b}b".as_bytes(), true),
            b"a\\u{11b}b".to_vec()
        );
        assert_eq!(
            escape_for("a\u{11b}b".as_bytes(), false),
            "a\u{11b}b".as_bytes().to_vec()
        );
        for (v, utf8) in [
            ("C.UTF-8", true),
            ("en_US.utf8", true),
            ("C", false),
            ("POSIX", false),
            ("de_DE.ISO-8859-1", false),
        ] {
            assert_eq!(locale_utf8(v), utf8, "{v}");
        }
    }

    #[test]
    fn escapes() {
        assert_eq!(
            escape_controls(b"a\x1b]52;c;x\x07\n"),
            b"a\\x1b]52;c;x\\x07\n".to_vec()
        );
        assert_eq!(escape_controls(b"tab\there\r\n"), b"tab\there\r\n".to_vec());
        assert_eq!(
            escape_controls(b"fake\rprompt"),
            b"fake\\x0dprompt".to_vec()
        );
        assert_eq!(
            escape_controls("x\u{9b}31m".as_bytes()),
            b"x\\u{9b}31m".to_vec()
        );
        assert_eq!(escape_controls(b"bad\xffbyte"), b"bad\\xffbyte".to_vec());
    }

    fn stream(chunks: &[&[u8]]) -> Vec<u8> {
        let mut e = TtyEscape::default();
        let mut out: Vec<u8> = chunks.iter().flat_map(|c| e.feed(c)).collect();
        out.extend(e.finish());
        out
    }

    #[test]
    fn tty_escape_any_split() {
        for s in [&b"a\r\nb\n"[..], "caf\u{e9} \u{20ac}\n".as_bytes()] {
            let whole = stream(&[s]);
            assert_eq!(whole, escape_controls(s));
            for i in 0..=s.len() {
                assert_eq!(stream(&[&s[..i], &s[i..]]), whole, "split at {i}");
            }
        }
    }

    #[test]
    fn tty_escape_bare_cr() {
        assert_eq!(stream(&[b"fake\r", b"prompt"]), b"fake\\x0dprompt".to_vec());
        assert_eq!(stream(&[b"a\r", b"\r\n"]), b"a\\x0d\r\n".to_vec());
    }

    #[test]
    fn tty_escape_invalid() {
        assert_eq!(stream(&[b"bad\xff", b"byte"]), b"bad\\xffbyte".to_vec());
        // a lead byte whose char never finishes
        assert_eq!(stream(&[b"x\xc3", b"y"]), b"x\\xc3y".to_vec());
        assert_eq!(stream(&[b"\xe2\x82", b"\n"]), b"\\xe2\\x82\n".to_vec());
    }

    #[test]
    fn tty_escape_finish() {
        let mut e = TtyEscape::default();
        assert_eq!(e.feed(b"ok\r"), b"ok".to_vec());
        assert_eq!(e.finish(), b"\\x0d".to_vec());
        assert_eq!(e.feed(&"\u{2713}".as_bytes()[..2]), b"".to_vec());
        assert_eq!(e.finish(), b"\\xe2\\x9c".to_vec());
        assert_eq!(e.finish(), b"".to_vec());
    }
}
