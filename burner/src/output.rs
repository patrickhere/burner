//! output to the caller goes through a writer thread with a bounded queue, so a
//! reader that stops reading can't stall the main loop (and with it the ttl).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 8 << 20;
/// what one queued chunk costs beyond its bytes (the Vec and the channel slot),
/// so a flood of tiny writes can't hold far more memory than the cap says
const CHUNK_COST: usize = 128;

pub struct Out {
    tx: mpsc::Sender<Vec<u8>>,
    queued: Arc<AtomicUsize>,
    broken: Arc<AtomicBool>,
    dropped: AtomicBool,
    tty: bool,
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
        let fd = match dest {
            Dest::Stdout => 1,
            Dest::Stderr => 2,
        };
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let queued = Arc::new(AtomicUsize::new(0));
        let broken = Arc::new(AtomicBool::new(false));
        let (q, b) = (queued.clone(), broken.clone());
        std::thread::spawn(move || {
            let mut w: Box<dyn Write> = match dest {
                Dest::Stdout => Box::new(std::io::stdout()),
                Dest::Stderr => Box::new(std::io::stderr()),
            };
            for chunk in rx {
                if !b.load(Ordering::Relaxed)
                    && (w.write_all(&chunk).is_err() || w.flush().is_err())
                {
                    b.store(true, Ordering::Relaxed);
                }
                q.fetch_sub(chunk.len() + CHUNK_COST, Ordering::Relaxed);
            }
        });
        Out {
            tx,
            queued,
            broken,
            dropped: AtomicBool::new(false),
            tty: crate::sys::is_tty(fd),
        }
    }

    /// queue bytes. without `wait_until` they're dropped when the queue is full
    pub fn put(&self, b: &[u8], wait_until: Option<Instant>) {
        if b.is_empty() || self.broken.load(Ordering::Relaxed) {
            return;
        }
        let b = if self.tty {
            escape_controls(b)
        } else {
            b.to_vec()
        };
        loop {
            let q = self.queued.load(Ordering::Relaxed);
            if q + b.len() + CHUNK_COST <= QUEUE_CAP {
                self.queued
                    .fetch_add(b.len() + CHUNK_COST, Ordering::Relaxed);
                let _ = self.tx.send(b);
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
        while Instant::now() < until {
            if self.queued.load(Ordering::Relaxed) == 0 || self.broken.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// guest bytes must not drive the caller's terminal: control characters become
/// \xNN. tab and newline stay; a carriage return only when it starts a \r\n.
/// C1 controls count too when they come as utf-8 code points
pub fn escape_controls(b: &[u8]) -> Vec<u8> {
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
                _ if (0x80..=0x9f).contains(&c) => {
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

/// an allowlist for what the VM may send to the caller's terminal in `burner
/// shell`: text, colors, cursor movement, erasing and a few screen modes. it
/// drops every query (the terminal would type the answer into the VM), mouse
/// reporting, OSC/DCS/APC/PM/SOS strings (titles, clipboard, hyperlinks), C1
/// controls and anything it doesn't know. keeps its state across reads
#[derive(Default)]
pub struct TermFilter {
    st: FState,
    seq: Vec<u8>,
    utf8: Vec<u8>,
}

#[derive(Default, PartialEq)]
enum FState {
    #[default]
    Text,
    Esc,
    Charset,
    Csi,
    Str,
    StrEsc,
}

const SEQ_MAX: usize = 64;

/// undoes every mode the filter lets through, sent when the shell ends
pub const TERM_RESET: &[u8] =
    b"\x1b[?1049l\x1b[r\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l";

/// private modes (CSI ? n h/l) a shell or editor needs that make the terminal
/// send nothing back: cursor keys, autowrap, blink, cursor shown, alt screen,
/// bracketed paste
const PRIVATE_MODES: &[u32] = &[1, 7, 12, 25, 47, 1047, 1048, 1049, 2004];

/// CSI finals that only move the cursor, erase, scroll or set colors
const CSI_FINALS: &[u8] = b"@ABCDEFGHIJKLMPSTXZ`adefgmr";

impl TermFilter {
    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            self.byte(b, &mut out);
        }
        out
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        match self.st {
            FState::Text => self.text(b, out),
            FState::Esc => {
                self.seq.push(b);
                match b {
                    b'[' => self.st = FState::Csi,
                    b']' | b'P' | b'_' | b'^' | b'X' => self.st = FState::Str,
                    b'(' | b')' => self.st = FState::Charset,
                    0x1b => self.start_esc(),
                    // save/restore cursor, reverse index, keypad modes
                    b'7' | b'8' | b'M' | b'=' | b'>' => {
                        out.extend_from_slice(&self.seq);
                        self.st = FState::Text;
                    }
                    _ => self.st = FState::Text,
                }
            }
            FState::Charset => {
                self.seq.push(b);
                // only ascii and line drawing
                if b == b'B' || b == b'0' {
                    out.extend_from_slice(&self.seq);
                }
                self.st = FState::Text;
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
                    }
                    self.st = FState::Text;
                } else if self.seq.len() > SEQ_MAX {
                    self.st = FState::Text;
                }
            }
            FState::Str => match b {
                0x07 => self.st = FState::Text,
                0x1b => self.st = FState::StrEsc,
                _ => {}
            },
            FState::StrEsc => {
                self.st = if b == b'\\' {
                    FState::Text
                } else {
                    FState::Str
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
                b'\t' | b'\n' | b'\r' | 0x08 | 0x07 => out.push(b),
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
                    out.extend_from_slice(&self.utf8);
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
                _ => digits && CSI_FINALS.contains(&fin),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(f.feed(b"\x1bc\x1b#8x"), b"8x".to_vec());
        assert_eq!(f.feed(b"\x1b[1\x1b[31mr"), b"\x1b[31mr".to_vec());
        // a control inside a CSI ends it
        assert_eq!(f.feed(b"\x1b[1\nz"), b"\nz".to_vec());
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
}
