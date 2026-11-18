//! output to the caller goes through a writer thread with a bounded queue, so a
//! reader that stops reading can't stall the main loop (and with it the ttl).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAP: usize = 8 << 20;

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
                q.fetch_sub(chunk.len(), Ordering::Relaxed);
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
            if q + b.len() <= QUEUE_CAP {
                self.queued.fetch_add(b.len(), Ordering::Relaxed);
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

/// passes what a shell needs to draw (text, colors, cursor movement) and drops
/// what a hostile guest could use against the terminal or the person at it:
/// OSC (titles, clipboard, hyperlinks), DCS/APC/PM/SOS strings, and window ops.
/// keeps its state across reads
#[derive(Default)]
pub struct TermFilter {
    st: FState,
    seq: Vec<u8>,
}

#[derive(Default, PartialEq)]
enum FState {
    #[default]
    Text,
    Esc,
    EscInter,
    Csi,
    Str,
    StrEsc,
}

const SEQ_MAX: usize = 64;

impl TermFilter {
    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            match self.st {
                FState::Text => {
                    if b == 0x1b {
                        self.st = FState::Esc;
                        self.seq.clear();
                        self.seq.push(b);
                    } else {
                        out.push(b);
                    }
                }
                FState::Esc => {
                    self.seq.push(b);
                    match b {
                        b'[' => self.st = FState::Csi,
                        b']' | b'P' | b'_' | b'^' | b'X' => self.st = FState::Str,
                        b'(' | b')' | b'*' | b'+' | b'#' | b'%' => self.st = FState::EscInter,
                        _ => {
                            out.extend_from_slice(&self.seq);
                            self.st = FState::Text;
                        }
                    }
                }
                FState::EscInter => {
                    self.seq.push(b);
                    out.extend_from_slice(&self.seq);
                    self.st = FState::Text;
                }
                FState::Csi => {
                    self.seq.push(b);
                    if (0x40..=0x7e).contains(&b) {
                        // CSI ... t is window manipulation (resize, move, report title)
                        if b != b't' {
                            out.extend_from_slice(&self.seq);
                        }
                        self.st = FState::Text;
                    } else if self.seq.len() > SEQ_MAX {
                        self.st = FState::Text; // runaway sequence, drop it
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
        out
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
