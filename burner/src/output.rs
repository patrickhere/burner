//! output to the caller goes through a writer thread with a bounded queue, so a
//! reader that stops reading can't stall the main loop (and with it the ttl).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 8 << 20;
/// what one queued chunk costs beyond its bytes (the Vec and the channel slot),
/// so a flood of tiny writes can't hold far more memory than the cap says
const CHUNK_COST: usize = 128;

pub struct Out {
    tx: mpsc::Sender<Chunk>,
    screen: Option<Arc<Mutex<Screen>>>,
    queued: Arc<AtomicUsize>,
    broken: Arc<AtomicBool>,
    /// set by finish: what's still queued is dropped, only the last chunk goes out
    skip: Arc<AtomicBool>,
    last_done: Arc<AtomicBool>,
    dropped: AtomicBool,
    /// bytes handed to put, before any escaping
    taken: AtomicU64,
    tty: bool,
    esc: Mutex<TtyEscape>,
}

enum Chunk {
    Data(Vec<u8>),
    /// the screen's reset, made when the writer gets to it
    Reset,
}

pub enum Dest {
    Stdout,
    Stderr,
    /// nowhere: burner's own lines with --json, which are in the json instead
    Null,
}

impl Out {
    pub fn new(dest: Dest) -> Out {
        let (fd, w): (i32, Box<dyn Write + Send>) = match dest {
            Dest::Stdout => (1, Box::new(std::io::stdout())),
            Dest::Stderr => (2, Box::new(std::io::stderr())),
            Dest::Null => (-1, Box::new(std::io::sink())),
        };
        Out::to(w, crate::sys::is_tty(fd), None)
    }

    /// stdout for the shell relay: bytes go out as they are (TermFilter has
    /// done its part), and the writer keeps a Screen of what it really wrote
    pub fn new_screen() -> Out {
        Out::to(
            Box::new(std::io::stdout()),
            false,
            Some(Arc::new(Mutex::new(Screen::default()))),
        )
    }

    fn to(mut w: Box<dyn Write + Send>, tty: bool, screen: Option<Arc<Mutex<Screen>>>) -> Out {
        let (tx, rx) = mpsc::channel::<Chunk>();
        let queued = Arc::new(AtomicUsize::new(0));
        let broken = Arc::new(AtomicBool::new(false));
        let skip = Arc::new(AtomicBool::new(false));
        let last_done = Arc::new(AtomicBool::new(false));
        let (q, b, sk, done, scr) = (
            queued.clone(),
            broken.clone(),
            skip.clone(),
            last_done.clone(),
            screen.clone(),
        );
        let lock = |s: &Arc<Mutex<Screen>>| s.lock().unwrap_or_else(|e| e.into_inner()).clone();
        std::thread::spawn(move || {
            for c in rx {
                let (chunk, last) = match c {
                    Chunk::Data(v) => (v, false),
                    Chunk::Reset => (
                        scr.as_ref().map(|s| lock(s).reset()).unwrap_or_default(),
                        true,
                    ),
                };
                if !b.load(Ordering::Relaxed) && (last || !sk.load(Ordering::Relaxed)) {
                    if w.write_all(&chunk).is_err() || w.flush().is_err() {
                        b.store(true, Ordering::Relaxed);
                    } else if let Some(s) = &scr {
                        s.lock().unwrap_or_else(|e| e.into_inner()).feed(&chunk);
                    }
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
            screen,
            queued,
            broken,
            skip,
            last_done,
            dropped: AtomicBool::new(false),
            taken: AtomicU64::new(0),
            tty,
            esc: Mutex::new(TtyEscape::default()),
        }
    }

    /// queue bytes. without `wait_until` they're dropped when the queue is full
    pub fn put(&self, b: &[u8], wait_until: Option<Instant>) {
        if b.is_empty() || self.broken.load(Ordering::Relaxed) {
            return;
        }
        self.taken.fetch_add(b.len() as u64, Ordering::Relaxed);
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

    pub fn bytes(&self) -> u64 {
        self.taken.load(Ordering::Relaxed)
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
        self.drain_or(until, || false)
    }

    /// drain, cut short by `give_up`
    pub fn drain_or(&self, until: Instant, give_up: impl Fn() -> bool) {
        if self.tty && !self.broken.load(Ordering::Relaxed) {
            let mut esc = self.esc.lock().unwrap_or_else(|e| e.into_inner());
            self.send(esc.finish(), Some(until));
        }
        while Instant::now() < until && !give_up() {
            if self.queued.load(Ordering::Relaxed) == 0 || self.broken.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// drops whatever is still queued and writes the screen's reset next, past
    /// the queue cap: a reader that stalled behind a pile of guest output still
    /// gets it, and gets it last. it's made from what was really written, so
    /// an alt screen whose way back was dropped still gets left
    pub fn finish_reset(&self) {
        self.skip.store(true, Ordering::Relaxed);
        let _ = self.tx.send(Chunk::Reset);
    }

    /// the screen as the bytes written so far left it
    pub fn screen(&self) -> Option<Screen> {
        let s = self.screen.as_ref()?;
        Some(s.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    /// waits until everything queued is written, the writer broke, or `give_up`
    pub fn settle(&self, give_up: impl Fn() -> bool) {
        if self.tty && !self.broken.load(Ordering::Relaxed) {
            let mut esc = self.esc.lock().unwrap_or_else(|e| e.into_inner());
            self.send(esc.finish(), None);
        }
        while self.queued.load(Ordering::Relaxed) > 0
            && !self.broken.load(Ordering::Relaxed)
            && !give_up()
        {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// waits until finish_reset's chunk is written, the writer broke, or `give_up`
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
/// controls and anything it doesn't know. keeps its state across reads. the
/// alt screen modes 47 and 1047 go out as 1049, so there's one way back
#[derive(Default)]
pub struct TermFilter {
    st: FState,
    seq: Vec<u8>,
    utf8: Vec<u8>,
    str_len: usize,
    /// when the last read that left a string open came
    str_at: Option<Instant>,
    /// the terminal isn't utf-8: non-ascii chars go out as ?
    ascii: bool,
}

/// the caller's terminal as the shell left it, kept from the bytes that were
/// really written to it (TermFilter's output, so only what that lets through):
/// what reset has to undo, and whether bracketed paste is on
#[derive(Clone)]
pub struct Screen {
    st: SState,
    seq: Vec<u8>,
    /// the cursor is known to be at the start of a line, and that line is
    /// known to be empty: whether reset has to add a newline
    col0: bool,
    clean: bool,
    /// the alt screen is on, and the main screen's two flags under it
    alt: bool,
    main_col0: bool,
    main_clean: bool,
    /// the guest turned cursor blinking on or off
    blink: bool,
    /// bracketed paste is on, so the terminal brackets what's pasted
    paste: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum SState {
    Text,
    Esc,
    Charset,
    Csi,
}

impl Default for Screen {
    fn default() -> Screen {
        Screen {
            st: SState::Text,
            seq: Vec::new(),
            // the caller pressed enter to start the shell
            col0: true,
            clean: true,
            alt: false,
            main_col0: true,
            main_clean: true,
            blink: false,
            paste: false,
        }
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
/// an OSC/DCS/APC/PM/SOS string longer than this, or one with nothing more for
/// STR_IDLE, is given up on, so one that never ends doesn't hide the rest of
/// the session. a real one comes in one go
const STR_MAX: usize = 16 << 10;
const STR_IDLE: Duration = Duration::from_secs(1);

/// undoes every mode the filter lets through. the panic hook sends this one;
/// a shell that ends normally gets Screen::reset, which knows whether the
/// alt screen is on. this doesn't, so it goes onto the alt screen and back:
/// that leaves the guest's with the cursor where it was on the main screen,
/// and off it puts the cursor back where it is, where a bare ?1049l would
/// restore a stale one. resetting the scroll region moves the cursor home, so
/// it's saved around that, once on the main screen: a cursor saved on the alt
/// screen would land on the main one in tmux, which keeps one for both
pub const TERM_RESET: &[u8] = b"\x1b[?1049h\x1b[?1049l\x1b7\x1b[r\x1b8\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l\x1b[?12l";

/// the mode resets after the alt screen and scroll region, same as TERM_RESET
const MODES_RESET: &[u8] = b"\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l";

/// private modes (CSI ? n h/l) a shell or editor needs that make the terminal
/// send nothing back: cursor keys, autowrap, blink, cursor shown, alt screen,
/// bracketed paste
const PRIVATE_MODES: &[u32] = &[1, 7, 12, 25, 47, 1047, 1048, 1049, 2004];

/// CSI finals that only move the cursor, erase, scroll or set colors. not g
/// (tab clear): the guest could clear the caller's tab stops for good
const CSI_FINALS: &[u8] = b"@ABCDEFGHIJKLMPSTXZ`adefmr";

impl Screen {
    pub fn feed(&mut self, b: &[u8]) {
        for &b in b {
            self.byte(b);
        }
    }

    pub fn paste(&self) -> bool {
        self.paste
    }

    fn byte(&mut self, b: u8) {
        match self.st {
            SState::Text => match b {
                0x1b => {
                    self.seq.clear();
                    self.st = SState::Esc;
                }
                b'\r' => self.col0 = true,
                // line feed, vertical tab and form feed only move down
                b'\n' | 0x0b | 0x0c => self.clean = true,
                0x00..=0x1f | 0x7f => {}
                _ => (self.col0, self.clean) = (false, false),
            },
            SState::Esc => {
                self.st = match b {
                    b'[' => SState::Csi,
                    b'(' | b')' => SState::Charset,
                    _ => {
                        if b == b'8' || b == b'M' {
                            self.col0 &= b == b'M';
                            self.clean = false;
                        }
                        SState::Text
                    }
                }
            }
            SState::Charset => self.st = SState::Text,
            SState::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    let rest = std::mem::take(&mut self.seq);
                    self.csi(b, &rest);
                    self.st = SState::Text;
                } else if self.seq.len() < SEQ_MAX {
                    self.seq.push(b);
                }
            }
        }
    }

    /// where the column isn't clear it counts as mid-line: an extra blank line
    /// beats a message drawn over the guest's last line
    fn csi(&mut self, fin: u8, rest: &[u8]) {
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
                Ok(2004) => self.paste = on,
                Ok(1048) if !on => (self.col0, self.clean) = (false, false),
                Ok(1049) if on && !self.alt => {
                    (self.main_col0, self.main_clean) = (self.col0, self.clean);
                    self.alt = true;
                }
                Ok(1049) if !on && self.alt => {
                    (self.col0, self.clean) = (self.main_col0, self.main_clean);
                    self.alt = false;
                }
                _ => {}
            }
        }
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
        if self.alt {
            r.extend_from_slice(b"\x1b[?1049l");
            fresh = self.main_col0 && self.main_clean;
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
}

impl TermFilter {
    pub fn new(ascii: bool) -> TermFilter {
        TermFilter {
            ascii,
            ..TermFilter::default()
        }
    }

    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.feed_at(input, Instant::now())
    }

    fn feed_at(&mut self, input: &[u8], now: Instant) -> Vec<u8> {
        let open = matches!(self.st, FState::Str | FState::StrEsc);
        if open
            && self
                .str_at
                .is_some_and(|t| now.duration_since(t) >= STR_IDLE)
        {
            self.st = FState::Text;
        }
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            self.byte(b, &mut out);
        }
        self.str_at = matches!(self.st, FState::Str | FState::StrEsc).then_some(now);
        out
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
                        if self.seq[2] == b'?' {
                            out.extend_from_slice(&alt_as_1049(&self.seq));
                        } else if b == b'm' {
                            let params = &self.seq[2..self.seq.len() - 1];
                            out.extend_from_slice(&sgr(params).unwrap_or_default());
                        } else {
                            out.extend_from_slice(&self.seq);
                        }
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
                // vertical tab and form feed move down a line, like line feed
                b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0x08 | 0x07 => out.push(b),
                0x20..=0x7e => out.push(b),
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
                }
                self.utf8.clear();
            }
            Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => {} // needs more bytes
            Err(_) => self.utf8.clear(),
        }
    }
}

/// a private mode sequence with 47 and 1047 (alt screens that don't save the
/// cursor) as 1049: one alt screen mode, so the reset has one way back. the
/// modes go out as plain numbers, so 0047 is 47 too and Screen sees them all
fn alt_as_1049(seq: &[u8]) -> Vec<u8> {
    let (&fin, body) = seq.split_last().expect("csi has a final byte");
    let mut modes: Vec<String> = Vec::new();
    for m in std::str::from_utf8(&body[3..]).unwrap_or("").split(';') {
        let Ok(n) = m.parse::<u32>() else { continue };
        let m = if n == 47 || n == 1047 { 1049 } else { n }.to_string();
        if !modes.contains(&m) {
            modes.push(m);
        }
    }
    format!("\x1b[?{}{}", modes.join(";"), fin as char).into_bytes()
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
                b'm' => sgr(rest).is_some(),
                _ => digits && CSI_FINALS.contains(&fin),
            }
        }
    }
}

/// the linux console keeps 16 SGR parameters and runs the digits of any
/// past that into the last one
const SGR_MAX: usize = 16;

/// what goes out for an SGR with these parameters, or None to drop it. only
/// attributes and colors: not 10 to 20 (font selection), since on the linux
/// console 11 and 12 switch the charset and make it print control bytes, and
/// SGR 0 doesn't switch them back. extended colors only as whole groups, and
/// never 58 (underline color) or 59: the linux console doesn't know them and
/// reads 58's operands as attributes of their own (58;5;11 is font 11). a
/// long one goes out as several SGRs of at most SGR_MAX parameters, split
/// between groups, so the console can't cut a group into attributes
fn sgr(params: &[u8]) -> Option<Vec<u8>> {
    let p = std::str::from_utf8(params).ok()?;
    fn byte(s: Option<&str>) -> Option<&str> {
        s.filter(|s| s.parse::<u8>().is_ok())
    }
    let mut groups: Vec<Vec<&str>> = Vec::new();
    let mut it = p.split(';');
    while let Some(x) = it.next() {
        if x.contains(':') {
            // 4:N underline styles, 38:5:N and 38:2:[space]:R:G:B colors
            let sub: Vec<&str> = x.split(':').collect();
            let keep = match sub.as_slice() {
                ["4", n] if n.parse::<u8>().is_ok_and(|n| n <= 5) => true,
                [c @ ("38" | "48" | "58"), "5", n] if byte(Some(n)).is_some() => *c != "58",
                [c @ ("38" | "48" | "58"), "2", rgb @ ..]
                    if (rgb.len() == 3 || rgb.len() == 4)
                        && rgb[rgb.len() - 3..].iter().all(|v| byte(Some(v)).is_some()) =>
                {
                    *c != "58"
                }
                _ => return None,
            };
            if keep {
                groups.push(vec![x]);
            }
            continue;
        }
        let n: u32 = if x.is_empty() { 0 } else { x.parse().ok()? };
        match n {
            0..=9 | 21..=25 | 27..=37 | 39..=47 | 49 | 90..=97 | 100..=107 => groups.push(vec![x]),
            59 => {}
            38 | 48 | 58 => {
                let mut g = vec![x];
                match it.next() {
                    Some("5") => g.extend(["5", byte(it.next())?]),
                    Some("2") => {
                        g.push("2");
                        for _ in 0..3 {
                            g.push(byte(it.next())?);
                        }
                    }
                    _ => return None,
                }
                if n != 58 {
                    groups.push(g);
                }
            }
            _ => return None,
        }
    }
    let mut out = Vec::new();
    let mut seq: Vec<&str> = Vec::new();
    for g in groups {
        if seq.len() + g.len() > SGR_MAX {
            out.extend_from_slice(format!("\x1b[{}m", seq.join(";")).as_bytes());
            seq.clear();
        }
        seq.extend(g);
    }
    // nothing left is nothing sent: an empty SGR would reset everything
    if !seq.is_empty() {
        out.extend_from_slice(format!("\x1b[{}m", seq.join(";")).as_bytes());
    }
    Some(out)
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
        let o = Out::to(
            Box::new(Stalled(wait, got.clone())),
            false,
            Some(Arc::new(Mutex::new(Screen::default()))),
        );
        o.put(b"first\r\n", None);
        // the writer is stuck on "first"; the rest piles up behind it, the alt
        // screen's way back included
        std::thread::sleep(Duration::from_millis(50));
        o.put(b"\x1b[?1049h", None);
        for _ in 0..100 {
            o.put(b"guest", None);
        }
        o.put(b"\x1b[?1049l", None);
        o.finish_reset();
        for _ in 0..3 {
            go.send(()).unwrap();
        }
        o.wait_last(|| false);
        let want = [&b"first\r\n"[..], &Screen::default().reset()].concat();
        assert_eq!(*got.lock().unwrap(), want);
    }

    #[test]
    fn reset_follows_what_was_written() {
        // the alt screen went on, and the guest's way back never got written
        let (go, wait) = mpsc::channel();
        let got = Arc::new(Mutex::new(Vec::new()));
        let o = Out::to(
            Box::new(Stalled(wait, got.clone())),
            false,
            Some(Arc::new(Mutex::new(Screen::default()))),
        );
        o.put(b"\x1b[?1049h", None);
        std::thread::sleep(Duration::from_millis(50));
        o.finish_reset();
        for _ in 0..2 {
            go.send(()).unwrap();
        }
        o.wait_last(|| false);
        let want = [&b"\x1b[?1049h"[..], &shown(b"\x1b[?1049h").reset()].concat();
        assert_eq!(*got.lock().unwrap(), want);
        assert!(want.ends_with(&[&b"\x1b[?1049l"[..], &Screen::default().reset()].concat()));
    }

    #[test]
    fn term_reset_keeps_the_cursor() {
        let r = TERM_RESET;
        assert!(
            r.starts_with(b"\x1b[?1049h\x1b[?1049l"),
            "off the alt screen first"
        );
        let at = |pat: &[u8]| r.windows(pat.len()).position(|w| w == pat).unwrap();
        assert!(
            at(b"\x1b7") > at(b"\x1b[?1049l"),
            "cursor saved on the main screen"
        );
        assert!(
            at(b"\x1b8") > at(b"\x1b[r"),
            "restored after the scroll region reset"
        );
    }

    /// the guest's output through the filter and onto a Screen
    fn shown(out: &[u8]) -> Screen {
        let mut s = Screen::default();
        s.feed(&TermFilter::default().feed(out));
        s
    }

    #[test]
    fn reset_leaves_the_alt_screen_first() {
        let r = Screen::default().reset();
        assert!(
            r.starts_with(b"\x1b7\x1b[r\x1b8"),
            "no ?1049l off the alt screen"
        );
        assert!(r.ends_with(MODES_RESET));
        assert!(
            shown(b"\x1b[?1049h\x1b[3;1Hx")
                .reset()
                .starts_with(b"\x1b[?1049l\x1b7\x1b[r\x1b8")
        );
        assert_eq!(shown(b"\x1b[?1049h\x1b[?1049l").reset(), r);
        // 47 and 1047 are 1049 by the time they reach the terminal, in any mix
        assert!(shown(b"\x1b[?47h").reset().starts_with(b"\x1b[?1049l\x1b7"));
        assert_eq!(shown(b"\x1b[?1049h\x1b[?1047l").reset(), r);
        assert_eq!(shown(b"\x1b[?47h\x1b[?1049l").reset(), r);
    }

    #[test]
    fn filter_normalizes_alt_screens() {
        let mut f = TermFilter::default();
        assert_eq!(f.feed(b"\x1b[?47h"), b"\x1b[?1049h".to_vec());
        assert_eq!(f.feed(b"\x1b[?1047l"), b"\x1b[?1049l".to_vec());
        assert_eq!(f.feed(b"\x1b[?1047;1049;25h"), b"\x1b[?1049;25h".to_vec());
        // a number is a number, however it's written
        assert_eq!(f.feed(b"\x1b[?0047h"), b"\x1b[?1049h".to_vec());
        assert_eq!(f.feed(b"\x1b[?01047;025l"), b"\x1b[?1049;25l".to_vec());
        assert!(shown(b"\x1b[?0047h").reset().starts_with(b"\x1b[?1049l"));
        assert_eq!(f.feed(b"\x1b[?1;25l"), b"\x1b[?1;25l".to_vec());
    }

    #[test]
    fn reset_ends_on_a_fresh_line() {
        let fresh = |out: &[u8]| shown(out).reset().ends_with(b"\r\n");
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
        assert!(!fresh(b"\r\n\x1b[?47hx\x1b[?47l"));
    }

    #[test]
    fn screen_knows_bracketed_paste() {
        assert!(shown(b"\x1b[?2004h").paste());
        assert!(!shown(b"\x1b[?2004h\x1b[?2004l").paste());
        assert!(!shown(b"").paste());
    }

    #[test]
    fn reset_undoes_blinking() {
        assert!(
            !Screen::default()
                .reset()
                .windows(6)
                .any(|w| w == b"\x1b[?12l")
        );
        assert_eq!(
            TermFilter::default().feed(b"\x1b[?12;25h"),
            b"\x1b[?12;25h".to_vec()
        );
        assert!(shown(b"\x1b[?12;25h").reset().ends_with(b"\x1b[?12l"));
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
        // as is one that's still open after a second with nothing more for it
        let t = Instant::now();
        assert_eq!(f.feed_at(b"\x1b]0;x", t), b"".to_vec());
        assert_eq!(
            f.feed_at(b"still in it", t + Duration::from_millis(500)),
            b"".to_vec()
        );
        let later = t + Duration::from_millis(500) + STR_IDLE;
        assert_eq!(f.feed_at(b"burner:~# ", later), b"burner:~# ".to_vec());
        // a string that comes in pieces without such a gap still ends normally
        assert_eq!(f.feed_at(b"\x1b]0;ti", later), b"".to_vec());
        assert_eq!(
            f.feed_at(b"tle\x07ok", later + Duration::from_millis(900)),
            b"ok".to_vec()
        );
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
    fn filter_sgr() {
        let mut f = TermFilter::default();
        for ok in [
            &b"\x1b[m"[..],
            b"\x1b[0;1;4;7;31;42m",
            b"\x1b[38;5;208;48;2;10;20;30m",
            b"\x1b[38:2::1:2:3m\x1b[4:3m\x1b[48:5:9m",
            b"\x1b[22;23;24;27;39;49;97;107m",
        ] {
            assert_eq!(f.feed(ok), ok.to_vec(), "{ok:?}");
        }
        // fonts (the linux console's 11 and 12 most of all), unknowns, and
        // extended colors cut short or with a value out of range
        for bad in [
            &b"\x1b[10m"[..],
            b"\x1b[1;11m",
            b"\x1b[12m",
            b"\x1b[26m",
            b"\x1b[60m",
            b"\x1b[38;5m",
            b"\x1b[38;5;256m",
            b"\x1b[48;2;1;2m",
            b"\x1b[38;3;1m",
            b"\x1b[4:9m",
            b"\x1b[11:1m",
        ] {
            assert_eq!(f.feed(bad), b"".to_vec(), "{bad:?}");
        }
    }

    #[test]
    fn filter_sgr_for_the_linux_console() {
        let mut f = TermFilter::default();
        // underline color is dropped, with its operands, the rest stays
        assert_eq!(f.feed(b"\x1b[1;58;5;11;31m"), b"\x1b[1;31m".to_vec());
        assert_eq!(f.feed(b"\x1b[58;2;1;11;12;4m"), b"\x1b[4m".to_vec());
        assert_eq!(f.feed(b"\x1b[58:5:11;59;7m"), b"\x1b[7m".to_vec());
        // and an SGR that was nothing else sends nothing, not a reset
        assert_eq!(f.feed(b"\x1b[58;5;11m\x1b[59m"), b"".to_vec());
        // past 16 parameters it's split between groups, never inside one
        let long = b"\x1b[1;2;3;4;5;7;8;9;21;22;23;24;25;27;38;5;11;48;2;1;2;3m";
        assert_eq!(
            f.feed(long),
            b"\x1b[1;2;3;4;5;7;8;9;21;22;23;24;25;27m\x1b[38;5;11;48;2;1;2;3m".to_vec()
        );
        let groups = b"\x1b[0;1;38;2;1;2;3;48;2;4;5;6;38;5;9;48;5;10m";
        assert_eq!(
            f.feed(groups),
            b"\x1b[0;1;38;2;1;2;3;48;2;4;5;6;38;5;9m\x1b[48;5;10m".to_vec()
        );
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
