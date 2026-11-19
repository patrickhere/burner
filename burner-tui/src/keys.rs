//! keys from the tty's bytes. burner-tui reads the tty itself instead of
//! through crossterm's event queue, so one poll sees keys, resizes and a
//! hangup, and nothing typed before a handover is left in a queue it can't see

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// a sequence longer than this isn't a key
const SEQ_MAX: usize = 32;
/// how long the start of a sequence waits for the rest. a terminal sends a
/// key's sequence in one write, but a read can still end inside it
const ESC_WAIT: Duration = Duration::from_millis(100);

#[derive(Default)]
pub struct Keys {
    held: Vec<u8>,
    /// when the held bytes started waiting
    since: Option<Instant>,
}

impl Keys {
    /// the keys in one read. the start of a sequence or utf-8 char, a lone
    /// ESC included, waits for the next read, until ESC_WAIT has passed
    pub fn feed(&mut self, b: &[u8], now: Instant) -> Vec<KeyEvent> {
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(b);
        let mut out = Vec::new();
        let mut at = 0;
        while at < buf.len() {
            match key(&buf[at..]) {
                Parsed::Key(n, k) => {
                    out.extend(k);
                    at += n;
                }
                Parsed::More if buf.len() - at < SEQ_MAX => {
                    self.held = buf[at..].to_vec();
                    break;
                }
                Parsed::More => at = buf.len(),
            }
        }
        self.since = if self.held.is_empty() {
            None
        } else {
            Some(self.since.unwrap_or(now))
        };
        out
    }

    /// when what's held stops waiting, if anything is
    pub fn deadline(&self) -> Option<Instant> {
        self.since.map(|t| t + ESC_WAIT)
    }

    /// past the deadline a lone ESC is the escape key, and the start of
    /// anything else is dropped
    pub fn expire(&mut self, now: Instant) -> Vec<KeyEvent> {
        if self.deadline().is_none_or(|d| now < d) {
            return Vec::new();
        }
        let esc = self.held == [0x1b];
        self.clear();
        if esc {
            vec![KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)]
        } else {
            Vec::new()
        }
    }

    pub fn clear(&mut self) {
        self.held.clear();
        self.since = None;
    }
}

enum Parsed {
    /// bytes used, and the key if they were one
    Key(usize, Option<KeyEvent>),
    More,
}

fn press(code: KeyCode, m: KeyModifiers) -> Parsed {
    Parsed::Key(0, Some(KeyEvent::new(code, m)))
}

fn used(n: usize, p: Parsed) -> Parsed {
    match p {
        Parsed::Key(_, k) => Parsed::Key(n, k),
        p => p,
    }
}

/// the same keys crossterm makes of these bytes
fn key(b: &[u8]) -> Parsed {
    let none = KeyModifiers::NONE;
    let ctrl = KeyModifiers::CONTROL;
    match b[0] {
        0x1b => match b.get(1) {
            None => Parsed::More,
            Some(0x1b) => used(1, press(KeyCode::Esc, none)),
            Some(b'[') => csi(b),
            Some(b'O') => match b.get(2) {
                None => Parsed::More,
                Some(&f @ 0x40..=0x7e) => used(3, Parsed::Key(0, arrow(f, none))),
                // not SS3 after all: alt-O, then whatever this is
                Some(_) => used(2, press(KeyCode::Char('O'), KeyModifiers::ALT)),
            },
            // alt with a key
            Some(_) => match key(&b[1..]) {
                Parsed::Key(n, k) => Parsed::Key(
                    n + 1,
                    k.map(|mut k| {
                        k.modifiers |= KeyModifiers::ALT;
                        k
                    }),
                ),
                p => p,
            },
        },
        b'\r' => used(1, press(KeyCode::Enter, none)),
        b'\t' => used(1, press(KeyCode::Tab, none)),
        0x7f => used(1, press(KeyCode::Backspace, none)),
        0 => used(1, press(KeyCode::Char(' '), ctrl)),
        c @ 0x01..=0x1a => used(1, press(KeyCode::Char((c - 1 + b'a') as char), ctrl)),
        c @ 0x1c..=0x1f => used(1, press(KeyCode::Char((c - 0x1c + b'4') as char), ctrl)),
        _ => utf8(b),
    }
}

fn utf8(b: &[u8]) -> Parsed {
    let n = match b[0] {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => return Parsed::Key(1, None),
    };
    if b.len() < n {
        return Parsed::More;
    }
    match std::str::from_utf8(&b[..n])
        .ok()
        .and_then(|s| s.chars().next())
    {
        Some(c) => {
            let m = if c.is_uppercase() {
                KeyModifiers::SHIFT
            } else {
                KeyModifiers::NONE
            };
            used(n, press(KeyCode::Char(c), m))
        }
        None => Parsed::Key(1, None),
    }
}

/// ESC [ params final. arrows can carry modifiers (1;5A is ctrl-up). one
/// nothing here uses is still taken whole, so none of it acts as keys; a
/// byte that can't be in one ends it there
fn csi(b: &[u8]) -> Parsed {
    let Some(end) = b[2..].iter().position(|c| !(0x20..=0x3f).contains(c)) else {
        return Parsed::More;
    };
    let (params, fin) = (&b[2..2 + end], b[2 + end]);
    if !(0x40..=0x7e).contains(&fin) {
        return Parsed::Key(end + 2, None);
    }
    let n = end + 3;
    let m = std::str::from_utf8(params)
        .ok()
        .and_then(|p| p.split(';').nth(1))
        .and_then(|m| m.parse::<u8>().ok())
        .map_or(KeyModifiers::NONE, |m| {
            let bits = m.saturating_sub(1);
            let mut k = KeyModifiers::NONE;
            for (bit, km) in [
                (1, KeyModifiers::SHIFT),
                (2, KeyModifiers::ALT),
                (4, KeyModifiers::CONTROL),
            ] {
                if bits & bit != 0 {
                    k |= km;
                }
            }
            k
        });
    if fin == b'Z' {
        return used(n, press(KeyCode::BackTab, KeyModifiers::SHIFT));
    }
    Parsed::Key(n, arrow(fin, m))
}

fn arrow(fin: u8, m: KeyModifiers) -> Option<KeyEvent> {
    let code = match fin {
        b'A' => KeyCode::Up,
        b'B' => KeyCode::Down,
        b'C' => KeyCode::Right,
        b'D' => KeyCode::Left,
        b'H' => KeyCode::Home,
        b'F' => KeyCode::End,
        _ => return None,
    };
    Some(KeyEvent::new(code, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(chunks: &[&[u8]]) -> Vec<(KeyCode, KeyModifiers)> {
        let mut k = Keys::default();
        let now = Instant::now();
        chunks
            .iter()
            .flat_map(|c| k.feed(c, now))
            .map(|e| (e.code, e.modifiers))
            .collect()
    }

    #[test]
    fn plain_keys() {
        let n = KeyModifiers::NONE;
        assert_eq!(
            codes(&[b"q\r\t\x7f"]),
            [
                (KeyCode::Char('q'), n),
                (KeyCode::Enter, n),
                (KeyCode::Tab, n),
                (KeyCode::Backspace, n)
            ]
        );
        assert_eq!(
            codes(&[b"\x03\x15Y"]),
            [
                (KeyCode::Char('c'), KeyModifiers::CONTROL),
                (KeyCode::Char('u'), KeyModifiers::CONTROL),
                (KeyCode::Char('Y'), KeyModifiers::SHIFT)
            ]
        );
        assert_eq!(codes(&["é".as_bytes()]), [(KeyCode::Char('é'), n)]);
    }

    #[test]
    fn sequences() {
        let n = KeyModifiers::NONE;
        assert_eq!(
            codes(&[b"\x1b[A\x1bOB\x1b[1;5C\x1b[Z"]),
            [
                (KeyCode::Up, n),
                (KeyCode::Down, n),
                (KeyCode::Right, KeyModifiers::CONTROL),
                (KeyCode::BackTab, KeyModifiers::SHIFT)
            ]
        );
        // keys nothing here uses are skipped whole
        assert_eq!(codes(&[b"\x1b[3~\x1b[15~q"]), [(KeyCode::Char('q'), n)]);
        assert_eq!(
            codes(&[b"\x1bq"]),
            [(KeyCode::Char('q'), KeyModifiers::ALT)]
        );
    }

    #[test]
    fn split_reads() {
        let n = KeyModifiers::NONE;
        // an arrow cut after its ESC is still the arrow
        assert_eq!(codes(&[b"\x1b", b"[A"]), [(KeyCode::Up, n)]);
        assert_eq!(codes(&[b"\x1b[", b"D"]), [(KeyCode::Left, n)]);
        assert_eq!(codes(&[b"\x1bO", b"A"]), [(KeyCode::Up, n)]);
        let e = "é".as_bytes();
        assert_eq!(codes(&[&e[..1], &e[1..]]), [(KeyCode::Char('é'), n)]);
    }

    #[test]
    fn a_lone_esc_is_the_key_after_a_moment() {
        let t = Instant::now();
        let mut k = Keys::default();
        assert!(k.feed(b"\x1b", t).is_empty());
        assert_eq!(k.deadline(), Some(t + ESC_WAIT));
        assert!(k.expire(t + ESC_WAIT / 2).is_empty());
        assert_eq!(k.expire(t + ESC_WAIT)[0].code, KeyCode::Esc);
        assert_eq!(k.deadline(), None);
        // the start of anything else is dropped then
        assert!(k.feed(b"\x1b[1;", t).is_empty());
        assert!(k.expire(t + ESC_WAIT).is_empty());
        assert_eq!(k.feed(b"5A", t)[0].code, KeyCode::Char('5'));
    }

    #[test]
    fn unknown_sequences_are_taken_whole() {
        let n = KeyModifiers::NONE;
        // a mouse report and a focus event: none of their bytes are keys
        assert_eq!(
            codes(&[b"\x1b[<0;12;5Mq", b"\x1b[Iq"]),
            [(KeyCode::Char('q'), n); 2]
        );
        // a byte no sequence can hold ends it, and acts
        assert_eq!(codes(&[b"\x1b[1\r"]), [(KeyCode::Enter, n)]);
        assert_eq!(
            codes(&[b"\x1bO\r"]),
            [(KeyCode::Char('O'), KeyModifiers::ALT), (KeyCode::Enter, n)]
        );
    }

    #[test]
    fn clear_drops_a_held_start() {
        let t = Instant::now();
        let mut k = Keys::default();
        assert!(k.feed(b"\x1b[", t).is_empty());
        k.clear();
        assert_eq!(k.feed(b"A", t)[0].code, KeyCode::Char('A'));
    }

    #[test]
    fn a_runaway_sequence_is_dropped() {
        let mut long = b"\x1b[".to_vec();
        long.extend(std::iter::repeat_n(b'1', SEQ_MAX));
        assert!(codes(&[&long, b"q"]) == [(KeyCode::Char('q'), KeyModifiers::NONE)]);
    }
}
