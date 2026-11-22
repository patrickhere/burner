//! the lines the far end marks for the client, found and taken out of its
//! stderr (or a shell's terminal stream). each is `burner-NONCE KIND ...`
//! up to a newline. only wrap.sh and the remote burner know the nonce, the
//! guest never sees it, so a guest printing a lookalike line only prints text.
//!
//! a marker can start anywhere, not only at a line start: the remote doesn't
//! know whether the guest's output ended with a newline. bytes that could
//! still be the start of one are held until it's clear, everything else goes
//! through at once and unchanged

use serde_json::Value;

/// past this a record is broken, and with it the run
pub const LINE_MAX: usize = 64 << 10;

#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// wrap.sh found burner: the far end's OS, the ssh user's uid, whether
    /// burner goes through sudo, and its --version line
    Wrap {
        os: String,
        uid: u32,
        sudo: bool,
        version: String,
    },
    /// no burner at that path
    NoBin(String),
    /// the sudo rule doesn't let this command run without a password
    NoSudo,
    /// doctor: whether the sudo rule covers a command
    Sudo { cmd: String, ok: bool },
    /// burner there has a VM id for the run
    Start { id: String },
    /// how it ended: the json document a --json-fd would get, as it came
    /// (an object, checked)
    Status(String),
}

pub struct Frames {
    marker: Vec<u8>,
    /// bytes that could be the start of a marker
    held: Vec<u8>,
    /// inside a record, its bytes so far
    rec: Option<Vec<u8>>,
    started: bool,
    ended: bool,
    /// a shell's stream: a marker only counts at the start of a line, so a
    /// typed `b` isn't held back waiting for what comes after it
    lines: bool,
    /// the next byte out starts a line
    at_line: bool,
    /// why the stream can't be trusted any more. bytes after it go through
    /// as text
    pub broken: Option<String>,
}

impl Frames {
    pub fn new(nonce: &str) -> Frames {
        Frames {
            marker: format!("burner-{nonce} ").into_bytes(),
            held: Vec::new(),
            rec: None,
            started: false,
            ended: false,
            lines: false,
            at_line: true,
            broken: None,
        }
    }

    /// for a shell: records only at the start of a line, where the far end's
    /// burner puts them there. bytes are held only while they can still be
    /// a marker, never on a timer, and let out the moment they can't
    pub fn lines(nonce: &str) -> Frames {
        Frames {
            lines: true,
            ..Frames::new(nonce)
        }
    }

    fn emit(&mut self, out: &mut Vec<u8>, b: &[u8]) {
        if let Some(&last) = b.last() {
            self.at_line = last == b'\n';
        }
        out.extend_from_slice(b);
    }

    /// where in `b` a marker could start next
    fn next_start(&self, b: &[u8]) -> usize {
        let m = self.marker[0];
        if !self.lines {
            return b.iter().position(|&c| c == m).unwrap_or(b.len());
        }
        (0..b.len())
            .find(|&i| {
                b[i] == m
                    && if i == 0 {
                        self.at_line
                    } else {
                        b[i - 1] == b'\n'
                    }
            })
            .unwrap_or(b.len())
    }

    /// what isn't a record goes to `out`, records to `recs`
    pub fn feed(&mut self, mut b: &[u8], out: &mut Vec<u8>, recs: &mut Vec<Record>) {
        while !b.is_empty() {
            if self.broken.is_some() {
                let held = std::mem::take(&mut self.held);
                self.emit(out, &held);
                self.emit(out, b);
                return;
            }
            if let Some(rec) = &mut self.rec {
                match b.iter().position(|&c| c == b'\n') {
                    Some(i) => {
                        rec.extend_from_slice(&b[..i]);
                        b = &b[i + 1..];
                        self.at_line = true;
                        let mut line = self.rec.take().unwrap_or_default();
                        if line.last() == Some(&b'\r') {
                            line.pop();
                        }
                        if line.len() > LINE_MAX {
                            self.broken = Some("a record from the far end is too long".into());
                            continue;
                        }
                        match self.parse(&line) {
                            Ok(r) => recs.push(r),
                            Err(e) => self.broken = Some(e),
                        }
                    }
                    None => {
                        rec.extend_from_slice(b);
                        if rec.len() > LINE_MAX + 1 {
                            self.rec = None;
                            self.broken = Some("a record from the far end is too long".into());
                        }
                        return;
                    }
                }
                continue;
            }
            if self.held.is_empty() {
                // nothing can start before the next b (at a line start)
                let next = self.next_start(b);
                self.emit(out, &b[..next]);
                b = &b[next..];
                if b.is_empty() {
                    return;
                }
            }
            self.held.push(b[0]);
            b = &b[1..];
            if self.held.len() == self.marker.len() && self.held == self.marker {
                self.held.clear();
                self.rec = Some(Vec::new());
                continue;
            }
            if !self.marker.starts_with(&self.held) {
                // let out what can't start a marker any more: everything up
                // to the next place one still could
                let h = &self.held;
                let keep = (1..h.len())
                    .find(|&i| {
                        self.marker.starts_with(&h[i..]) && (!self.lines || h[i - 1] == b'\n')
                    })
                    .unwrap_or(h.len());
                let gone: Vec<u8> = self.held.drain(..keep).collect();
                self.emit(out, &gone);
            }
        }
    }

    /// the stream ended. what was held is text after all; a record that
    /// never got its newline breaks it
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.held);
        if self.rec.take().is_some() && self.broken.is_none() {
            self.broken = Some("the far end stopped in the middle of a record".into());
        }
    }

    fn parse(&mut self, line: &[u8]) -> Result<Record, String> {
        let bad = |what: &str| format!("a bad {what} record from the far end");
        let line = std::str::from_utf8(line).map_err(|_| bad("non-utf-8"))?;
        let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
        let r = match kind {
            "wrap" => {
                let mut f = rest.splitn(4, ' ');
                let os = f.next().unwrap_or("");
                let uid = f.next().and_then(|u| u.parse().ok());
                let mode = f.next();
                let version = f.next().unwrap_or("");
                let os_ok = !os.is_empty()
                    && os.len() <= 32
                    && os
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                match (os_ok, uid, mode) {
                    (true, Some(uid), Some(m @ ("sudo" | "direct"))) => Record::Wrap {
                        os: os.into(),
                        uid,
                        sudo: m == "sudo",
                        version: printable(version, 200),
                    },
                    _ => return Err(bad("wrap")),
                }
            }
            "nobin" => Record::NoBin(printable(rest, 1024)),
            "nosudo" if rest.is_empty() => Record::NoSudo,
            "sudo" => match rest.split_once(' ') {
                Some((cmd, ok @ ("yes" | "no")))
                    if !cmd.is_empty()
                        && cmd.len() <= 16
                        && cmd.bytes().all(|b| b.is_ascii_lowercase()) =>
                {
                    Record::Sudo {
                        cmd: cmd.into(),
                        ok: ok == "yes",
                    }
                }
                _ => return Err(bad("sudo")),
            },
            "start" => {
                let v: Value = serde_json::from_str(rest).map_err(|_| bad("start"))?;
                let id = v.get("id").and_then(Value::as_str).unwrap_or("");
                if !crate::ledger::valid_id(id) || self.started || self.ended {
                    return Err(bad("start"));
                }
                self.started = true;
                Record::Start { id: id.into() }
            }
            "status" => {
                let v: Value = serde_json::from_str(rest).map_err(|_| bad("status"))?;
                if !v.is_object() || self.ended {
                    return Err(bad("status"));
                }
                self.ended = true;
                Record::Status(rest.to_string())
            }
            _ => return Err("a record of a kind this burner doesn't know".into()),
        };
        Ok(r)
    }
}

/// text from the far end that ends up in burner's own messages: printable
/// ascii only, cut to `max`
pub fn printable(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "0123456789abcdef0123456789abcdef";

    fn all(input: &[u8]) -> (Vec<u8>, Vec<Record>, Option<String>) {
        let mut f = Frames::new(N);
        let (mut out, mut recs) = (Vec::new(), Vec::new());
        f.feed(input, &mut out, &mut recs);
        f.finish(&mut out);
        (out, recs, f.broken)
    }

    /// the same stream fed in pieces cut at `cuts`
    fn pieces(input: &[u8], cuts: &[usize]) -> (Vec<u8>, Vec<Record>, Option<String>) {
        let mut f = Frames::new(N);
        let (mut out, mut recs) = (Vec::new(), Vec::new());
        let mut at = 0;
        for &c in cuts {
            let c = c.clamp(at, input.len());
            f.feed(&input[at..c], &mut out, &mut recs);
            at = c;
        }
        f.feed(&input[at..], &mut out, &mut recs);
        f.finish(&mut out);
        (out, recs, f.broken)
    }

    fn rec(kind: &str) -> String {
        format!("burner-{N} {kind}\n")
    }

    #[test]
    fn records_come_out() {
        let s = format!(
            "hello\n{}out{}{}tail",
            rec("wrap Linux 1000 sudo burnervm 0.3.0"),
            rec("start {\"id\":\"burner-4f1c09ab22e1\"}"),
            rec("status {\"exit\":3}"),
        );
        let (out, recs, broken) = all(s.as_bytes());
        assert_eq!(out, b"hello\nouttail");
        assert_eq!(broken, None);
        assert_eq!(
            recs,
            [
                Record::Wrap {
                    os: "Linux".into(),
                    uid: 1000,
                    sudo: true,
                    version: "burnervm 0.3.0".into()
                },
                Record::Start {
                    id: "burner-4f1c09ab22e1".into()
                },
                Record::Status("{\"exit\":3}".into()),
            ]
        );
    }

    #[test]
    fn every_split_gives_the_same() {
        let s = format!(
            "burner: waiting\nburner-4f1c09ab22e1 is an id, burner-0123 isn't a marker\r\n{}x{}",
            rec("wrap Darwin 501 direct burnervm 0.3.0"),
            "burner-0123456789abcdef0123456789abcdef status {\"exit\":0,\"ok\":true}\r\n"
        );
        let whole = all(s.as_bytes());
        assert_eq!(whole.1.len(), 2);
        assert_eq!(whole.2, None);
        for i in 0..=s.len() {
            assert_eq!(pieces(s.as_bytes(), &[i]), whole, "cut at {i}");
            for j in (i..=s.len()).step_by(7) {
                assert_eq!(pieces(s.as_bytes(), &[i, j]), whole, "cut at {i}, {j}");
            }
        }
        // one byte at a time
        let ones: Vec<usize> = (0..s.len()).collect();
        assert_eq!(pieces(s.as_bytes(), &ones), whole);
    }

    fn lines_all(input: &[u8], cuts: &[usize]) -> (Vec<u8>, Vec<Record>, Option<String>) {
        let mut f = Frames::lines(N);
        let (mut out, mut recs) = (Vec::new(), Vec::new());
        let mut at = 0;
        for &c in cuts {
            let c = c.clamp(at, input.len());
            f.feed(&input[at..c], &mut out, &mut recs);
            at = c;
        }
        f.feed(&input[at..], &mut out, &mut recs);
        f.finish(&mut out);
        (out, recs, f.broken)
    }

    #[test]
    fn shell_streams_only_hold_at_a_line_start() {
        let mut f = Frames::lines(N);
        let (mut out, mut recs) = (Vec::new(), Vec::new());
        // a typed b echoed after the prompt shows at once
        f.feed(b"burner:~# b", &mut out, &mut recs);
        assert_eq!(out, b"burner:~# b");
        // one at a line start waits for what decides it, however long
        f.feed(b"\r\nbu", &mut out, &mut recs);
        assert_eq!(out, b"burner:~# b\r\n");
        f.feed(b"s\n", &mut out, &mut recs);
        assert_eq!(out, b"burner:~# b\r\nbus\n");
        // a marker in the middle of a line is text in a shell
        let mid = format!("x{}", rec("status {}"));
        assert_eq!(lines_all(mid.as_bytes(), &[]).0, mid.as_bytes());
        // a record after a newline, cut anywhere, comes out whole
        let s = format!(
            "bye\r\nbu\r\n{}{}",
            rec("start {\"id\":\"burner-4f1c09ab22e1\"}"),
            "\r\nburner: x\n\r\n".to_string() + &rec("status {\"exit\":3}")
        );
        let whole = lines_all(s.as_bytes(), &[]);
        assert_eq!(whole.1.len(), 2, "{whole:?}");
        assert_eq!(whole.0, b"bye\r\nbu\r\n\r\nburner: x\n\r\n");
        for i in 0..=s.len() {
            for j in (i..=s.len()).step_by(5) {
                assert_eq!(lines_all(s.as_bytes(), &[i, j]), whole, "cut at {i}, {j}");
            }
        }
        // the stream starts a line
        assert_eq!(
            lines_all(rec("nosudo").as_bytes(), &[3]).1,
            [Record::NoSudo]
        );
    }

    #[test]
    fn lookalikes_are_text() {
        // a guest doesn't know the nonce
        let fake = "burner-00000000000000000000000000000000 status {\"exit\":0}\n";
        assert_eq!(
            all(fake.as_bytes()),
            (fake.as_bytes().to_vec(), vec![], None)
        );
        // a marker without its trailing space, and one cut off at the end
        let near = format!("burner-{N}status\nburner-{}", &N[..10]);
        assert_eq!(all(near.as_bytes()).0, near.as_bytes());
        assert!(all(near.as_bytes()).2.is_none());
        // a marker that starts inside a near miss
        let s = format!("burner-burner-{N} nosudo\n!");
        assert_eq!(
            all(s.as_bytes()),
            (b"burner-!".to_vec(), vec![Record::NoSudo], None)
        );
    }

    #[test]
    fn broken_streams() {
        let broken = |s: String| all(s.as_bytes()).2.is_some();
        assert!(broken(rec("status not json")));
        assert!(broken(rec("status [1]")));
        assert!(broken(rec("teleport now")));
        assert!(broken(rec("wrap Linux x sudo v")));
        assert!(broken(rec("wrap Li\u{1b}nux 1 sudo v")));
        assert!(broken(rec("nosudo please")));
        assert!(broken(rec("start {\"id\":\"../../etc\"}")));
        assert!(broken(rec("sudo run maybe")));
        // two ends, or a start after the end
        assert!(broken(rec("status {}") + &rec("status {}")));
        assert!(broken(
            rec("status {}") + &rec("start {\"id\":\"burner-4f1c09ab22e1\"}")
        ));
        // never ends
        assert!(broken(format!("burner-{N} status {{\"exit\":0}}")));
        // over the cap, ended or not
        let long = format!("status {{\"x\":\"{}\"}}", "a".repeat(LINE_MAX));
        assert!(broken(rec(&long)));
        assert!(broken(format!("burner-{N} {long}")));
        assert!(broken(format!("burner-{N} status \u{ff}\n")));
        // just under the cap is fine
        let fits = format!("status {{\"x\":\"{}\"}}", "a".repeat(LINE_MAX - 20));
        assert!(!broken(rec(&fits)));
        // after a break bytes go through as they are
        let s = rec("bogus") + &rec("status {}") + "after";
        let (out, recs, b) = all(s.as_bytes());
        assert!(b.is_some() && recs.is_empty());
        assert_eq!(out, (rec("status {}") + "after").as_bytes());
    }

    #[test]
    fn wrap_version_is_made_printable() {
        let (_, recs, _) = all(rec("wrap Linux 0 direct burnervm \u{1b}]0;x\u{7} 1").as_bytes());
        assert_eq!(
            recs,
            [Record::Wrap {
                os: "Linux".into(),
                uid: 0,
                sudo: false,
                version: "burnervm ?]0;x? 1".into()
            }]
        );
    }

    #[test]
    fn fuzz_style() {
        // a small xorshift, the same cases every run
        let mut x: u64 = 0x2545f4914f6cdd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let marker = format!("burner-{N} ");
        let parts: Vec<Vec<u8>> = vec![
            b"burner-".to_vec(),
            marker.clone().into_bytes(),
            b"status {\"exit\":1}\n".to_vec(),
            b"start {\"id\":\"burner-4f1c09ab22e1\"}\n".to_vec(),
            b"wrap Linux 0 direct v\n".to_vec(),
            b"\n".to_vec(),
            b"\r".to_vec(),
            b"b".to_vec(),
            N.as_bytes().to_vec(),
            vec![0xff, 0x00, 0x1b],
            b"plain text ".to_vec(),
        ];
        for round in 0..3000 {
            let mut s = Vec::new();
            for _ in 0..(next() % 20) {
                s.extend_from_slice(&parts[(next() % parts.len() as u64) as usize]);
            }
            if round % 5 == 0 {
                for _ in 0..(next() % 64) {
                    s.push((next() % 256) as u8);
                }
            }
            let whole = all(&s);
            let cuts: Vec<usize> = (0..(next() % 6))
                .map(|_| (next() % (s.len() as u64 + 1)) as usize)
                .collect();
            let mut cuts = cuts;
            cuts.sort();
            assert_eq!(pieces(&s, &cuts), whole, "{s:?} cut at {cuts:?}");
            // nothing comes out that wasn't in, and a clean stream keeps every
            // byte that wasn't a record
            assert!(whole.0.len() <= s.len());
            if whole.1.is_empty() && whole.2.is_none() {
                assert_eq!(whole.0, s);
            }
        }
    }
}
