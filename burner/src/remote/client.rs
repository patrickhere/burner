//! the laptop's side of -H. it picks an address, starts ssh with the fixed
//! options and the wrapper, and reads back what comes: the far end's output
//! goes through the same escaping a local run's does, its records are taken
//! out and checked, and the exit code is decided here from them, never from
//! ssh's own 255

use std::io::Read;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::Value;

use super::frame::{Frames, Record, printable};
use super::hosts::{self, Host};
use super::probe::{self, Pick};
use super::quote;
use super::ssh::{self, Mode, Opts};
use crate::exit::{EXIT_SANDBOX, EXIT_USAGE};
use crate::json::{self, Kind};
use crate::output::{Dest, Out};
use crate::sys;

/// what's kept of ssh's own words before the far end answered
const PRE_CAP: usize = 8 << 10;
/// the most a --json reply from the far end can be
const JSON_CAP: u64 = 16 << 20;

/// the tui's background calls: ssh must never ask for anything over it
fn batch() -> bool {
    std::env::var("BURNER_BATCH").is_ok_and(|v| v == "1")
}

/// a connection's parts: the host, the address picked for it, and the
/// nonce that marks this call's records
pub(super) struct Conn {
    pub(super) host: Host,
    pub(super) pick: Pick,
    pub(super) nonce: String,
}

/// why a -H call failed before or instead of a real answer
pub(super) struct Failed {
    pub(super) kind: Kind,
    pub(super) msg: String,
}

impl Failed {
    fn new(kind: Kind, msg: impl Into<String>) -> Failed {
        Failed {
            kind,
            msg: msg.into(),
        }
    }
}

impl Conn {
    pub(super) fn open(host: &Host) -> Result<Conn, Failed> {
        let pick = probe::pick(host).map_err(|n| {
            let parts: Vec<String> = n.0.iter().map(|(a, why)| format!("{a}: {why}")).collect();
            let msg = match (host.addrs.len(), n.0.first()) {
                (1, Some((a, why))) => format!("{}: ssh failed on {a}: {why}", host.name),
                _ => format!("{}: no address answered ({})", host.name, parts.join(", ")),
            };
            Failed::new(Kind::Unreachable, msg)
        })?;
        let nonce = sys::random_hex(16)
            .map_err(|e| Failed::new(Kind::Io, format!("no random bytes for a nonce: {e}")))?;
        Ok(Conn {
            host: host.clone(),
            pick,
            nonce,
        })
    }

    /// ssh with the fixed options and the wrapped burner command line
    pub(super) fn command(&self, o: Opts, mode: Mode, args: &[String]) -> Result<Command, Failed> {
        let line = ssh::remote_line(&self.nonce, self.host.burner.as_deref(), mode, args);
        if line.len() > quote::LINE_MAX {
            return Err(Failed::new(
                Kind::Usage,
                format!(
                    "the command is {}K once quoted for ssh, the most is {}K. put it in a file and use --in tar",
                    line.len() >> 10,
                    quote::LINE_MAX >> 10
                ),
            ));
        }
        let o = Opts {
            alive: !self.pick.conf.alive_set,
            batch: o.batch || batch(),
            ..o
        };
        let mut cmd = Command::new(ssh::program());
        cmd.args(ssh::argv(
            &self.host,
            &self.pick.addr,
            self.host.timeout.as_secs().max(1),
            o,
            &line,
        ));
        Ok(cmd)
    }

    /// what ssh's stderr before the far end answered says about why it
    /// didn't, as burner's own words
    pub(super) fn ssh_failed(&self, pre: &[u8], code: Option<i32>) -> Failed {
        let text = String::from_utf8_lossy(pre);
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('@'))
            .collect();
        let has = |s: &str| text.contains(s);
        let first = lines
            .iter()
            .rev()
            .find(|l| !l.starts_with("Please contact") && !l.contains("Offending"))
            .map(|l| printable(l, 300))
            .unwrap_or_else(|| "no answer".into());
        let (name, addr) = (&self.host.name, &self.pick.addr);
        let other = self
            .host
            .addrs
            .iter()
            .find(|a| *a != addr)
            .map(|a| format!(", or use -H {a}"))
            .unwrap_or_default();
        // the login shell got the line but didn't run it: not sh-like
        if code.is_some_and(|c| c != 255) {
            let user = if self.pick.conf.user.is_empty() {
                "you".to_string()
            } else {
                self.pick.conf.user.clone()
            };
            return Failed::new(
                Kind::RemoteError,
                format!(
                    "{name}: the login shell for {user} on {name} didn't run burner's command ({first}). -H needs sh, bash, zsh or fish there"
                ),
            );
        }
        let msg = if has("IDENTIFICATION HAS CHANGED") || has("has changed and you have requested")
        {
            format!(
                "{name}: ssh refused {addr}'s host key. burner never accepts host keys itself: check it with ssh {addr}{other}"
            )
        } else if has("Host key verification failed") || has("host key is known") {
            format!(
                "{name}: the host key of {addr} isn't known yet. connect once with ssh {addr} and check the fingerprint"
            )
        } else if !self.host.configured && has("Could not resolve hostname") {
            let path = hosts::shown(&hosts::path());
            let known = if self.host.known.is_empty() {
                String::new()
            } else {
                format!(" ({})", self.host.known.join(", "))
            };
            format!("{name} isn't in {path}{known}, and ssh says: {first}")
        } else if has("Connection timed out")
            || has("Connection refused")
            || has("No route to host")
            || has("Operation timed out")
            || has("Could not resolve hostname")
        {
            format!("{name}: no address answered ({addr}: {first})")
        } else {
            format!("{name}: ssh failed on {addr}: {first}")
        };
        Failed::new(Kind::Unreachable, msg)
    }
}

/// what came back on the far end's stderr besides its own text
#[derive(Default)]
pub(super) struct Seen {
    pub(super) wrap: Option<(String, u32, bool, String)>,
    pub(super) nobin: Option<String>,
    pub(super) nosudo: bool,
    pub(super) sudo: Vec<(String, bool)>,
    pub(super) start: Option<String>,
    pub(super) status: Option<String>,
    pub(super) broken: Option<String>,
    /// ssh's own stderr, until the wrapper answered
    pub(super) pre: Vec<u8>,
    /// the first line the far end wrote after the wrapper, for the version message
    pub(super) first_line: Option<String>,
    line_buf: Vec<u8>,
}

impl Seen {
    fn take(&mut self, r: Record) {
        match r {
            Record::Wrap {
                os,
                uid,
                sudo,
                version,
            } => self.wrap = Some((os, uid, sudo, version)),
            Record::NoBin(p) => self.nobin = Some(p),
            Record::NoSudo => self.nosudo = true,
            Record::Sudo { cmd, ok } => self.sudo.push((cmd, ok)),
            Record::Start { id } => self.start = Some(id),
            Record::Status(v) => self.status = Some(v),
        }
    }

    /// text from the far end: held while nothing has answered (it's ssh's
    /// own, and goes in burner's message), shown once the wrapper did
    fn text(&mut self, b: &[u8], out: &Out) {
        if self.wrap.is_none() && self.nobin.is_none() {
            let room = PRE_CAP.saturating_sub(self.pre.len());
            self.pre.extend_from_slice(&b[..b.len().min(room)]);
            return;
        }
        if self.first_line.is_none() && self.line_buf.len() < 4096 {
            self.line_buf.extend_from_slice(b);
            if let Some(l) = String::from_utf8_lossy(&self.line_buf)
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .filter(|_| self.line_buf.contains(&b'\n'))
            {
                self.first_line = Some(printable(l, 300));
            }
        }
        out.put(b, None);
    }

    /// what was held as ssh's goes out after all: the wrapper did answer
    fn release(&mut self, out: &Out) {
        if !self.pre.is_empty() && (self.wrap.is_some() || self.nobin.is_some()) {
            out.put(&std::mem::take(&mut self.pre), None);
        }
    }
}

/// reads `r` through the record parser until it ends. text goes to `out`
pub(super) fn read_records(
    mut r: impl Read + Send + 'static,
    nonce: &str,
    seen: Arc<Mutex<Seen>>,
    out: Arc<Out>,
) -> std::thread::JoinHandle<()> {
    let nonce = nonce.to_string();
    std::thread::spawn(move || {
        let mut f = Frames::new(&nonce);
        let mut buf = vec![0u8; 65536];
        let (mut text, mut recs) = (Vec::new(), Vec::new());
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) | Err(_) => 0,
                Ok(n) => n,
            };
            if n == 0 {
                f.finish(&mut text);
            } else {
                f.feed(&buf[..n], &mut text, &mut recs);
            }
            let mut s = seen.lock().unwrap_or_else(|e| e.into_inner());
            // a record ends the text before it: hand that over first
            for r in recs.drain(..) {
                s.take(r);
                s.release(&out);
            }
            if !text.is_empty() {
                s.text(&std::mem::take(&mut text), &out);
            }
            if s.broken.is_none() {
                s.broken = f.broken.clone();
            }
            if n == 0 {
                return;
            }
        }
    })
}

/// what's still a bad reply after the far end answered: no burner, no sudo
/// rule, a broken record stream
pub(super) fn remote_failed(c: &Conn, s: &Seen, what: &str) -> Option<Failed> {
    let name = &c.host.name;
    if let Some(p) = &s.nobin {
        return Some(Failed::new(
            Kind::RemoteError,
            format!(
                "{name}: no burner at {p} (install it there, or set burner = \"...\" for {name} in hosts.toml)"
            ),
        ));
    }
    if s.nosudo {
        return Some(Failed::new(
            Kind::RemoteError,
            format!(
                "{name}: sudo wants a password for burner {what}. -H needs a NOPASSWD rule for burner there, see dist/sudoers.example (burner -H {name} doctor checks it)"
            ),
        ));
    }
    if let Some(b) = &s.broken {
        return Some(Failed::new(
            Kind::RemoteError,
            format!("{name}: {b}, so nothing it said counts"),
        ));
    }
    None
}

/// a failure as text or json, exit 125 unless it's a usage error
pub(super) fn fail(command: &str, f: Failed) -> ExitCode {
    let code = if f.kind == Kind::Usage {
        EXIT_USAGE
    } else {
        EXIT_SANDBOX
    };
    json::fail(command, code, f.kind, f.msg)
}

pub(super) fn exit_of(st: &ExitStatus) -> Option<i32> {
    st.code()
}

/// a json document from the far end as it came, one line, with DEL and C1
/// controls made ? (serde escapes C0 ones, these it would pass on raw to your
/// terminal) and the host filled in. None when it isn't a json object
pub(super) fn forward_json(reply: &str, host: &str) -> Option<String> {
    let clean: String = reply
        .trim()
        .chars()
        .map(|c| {
            if c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
                '?'
            } else {
                c
            }
        })
        .collect();
    let mut v: Value = serde_json::from_str(&clean).ok()?;
    if !v.is_object() {
        return None;
    }
    let h = Value::String(host.into());
    // burner writes "host":null before anything that could hold another
    // one, so the first is the envelope's. checked, and else rebuilt
    let named = clean.replacen("\"host\":null", &format!("\"host\":{h}"), 1);
    if !named.contains('\n')
        && serde_json::from_str::<Value>(&named)
            .ok()
            .is_some_and(|n| n.get("host") == Some(&h))
    {
        return Some(named + "\n");
    }
    v["host"] = h;
    Some(v.to_string() + "\n")
}

fn spawn(cmd: &mut Command) -> Result<Child, Failed> {
    cmd.spawn()
        .map_err(|e| Failed::new(Kind::Io, format!("can't run ssh: {e}")))
}

/// -H is refused here: run as root (root has other keys and another
/// known_hosts, and sudo drops your agent), or inside the lima VM of a
/// burner 0.1 install, where your ssh keys aren't
pub fn refuse_here() -> Option<String> {
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string("/etc/hostname").is_ok_and(|h| h.trim() == "lima-burnervm") {
        return Some(
            "burner -H needs the native burner on your mac (brew install burnervm/tap/burner)"
                .into(),
        );
    }
    // SAFETY: geteuid can't fail
    if unsafe { libc::geteuid() } == 0 || std::env::var_os("SUDO_UID").is_some() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        return Some(format!(
            "-H runs ssh as you, not as root: drop the sudo (burner {})",
            printable(&args.join(" "), 200)
        ));
    }
    None
}

/// ls, kill, images, config and version: one call, the far end's output
/// shown escaped on a terminal, its exit code passed on. `args` start with
/// the command word
pub fn oneshot(host: &Host, command: &'static str, mut args: Vec<String>, mode: Mode) -> ExitCode {
    json::set_host(&host.name);
    let c = match Conn::open(host) {
        Ok(c) => c,
        Err(f) => return fail(command, f),
    };
    if json::on() {
        args.push("--json".into());
    }
    let o = Opts {
        no_stdin: true,
        ..Default::default()
    };
    let mut cmd = match c.command(o, mode, &args) {
        Ok(cmd) => cmd,
        Err(f) => return fail(command, f),
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match spawn(&mut cmd) {
        Ok(ch) => ch,
        Err(f) => return fail(command, f),
    };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let err_out = Arc::new(Out::new(Dest::Stderr));
    let errs = child
        .stderr
        .take()
        .map(|e| read_records(e, &c.nonce, seen.clone(), err_out.clone()));
    let out = Out::new(Dest::Stdout);
    let mut reply = Vec::new();
    if let Some(mut so) = child.stdout.take() {
        if json::on() {
            let _ = so.by_ref().take(JSON_CAP + 1).read_to_end(&mut reply);
            // whatever is past the cap isn't read: ssh's pipe would fill
            let _ = std::io::copy(&mut so, &mut std::io::sink());
        } else {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = so.read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.put(
                    &buf[..n],
                    Some(Instant::now() + std::time::Duration::from_secs(300)),
                );
            }
        }
    }
    let st = child.wait();
    if let Some(h) = errs {
        let _ = h.join();
    }
    let until = Instant::now() + std::time::Duration::from_secs(30);
    out.drain(until);
    err_out.drain(until);
    let code = st.as_ref().ok().and_then(exit_of);
    let s = seen.lock().unwrap_or_else(|e| e.into_inner());
    if s.wrap.is_none() && s.nobin.is_none() {
        return fail(command, c.ssh_failed(&s.pre, code));
    }
    if let Some(f) = remote_failed(&c, &s, command) {
        return fail(command, f);
    }
    // the far end's burner exits 0, 1 or 2 for these. 255 is ssh's: the
    // connection went after the wrapper answered
    let code = match code {
        Some(255) | None => {
            return fail(
                command,
                Failed::new(Kind::Lost, format!("lost the connection to {}", host.name)),
            );
        }
        Some(c) => c.clamp(0, 255) as u8,
    };
    if json::on() {
        let text = String::from_utf8_lossy(&reply);
        let line = match forward_json(&text, &host.name) {
            Some(l) if reply.len() as u64 <= JSON_CAP => l,
            _ => {
                let version = s.wrap.as_ref().map(|w| w.3.clone()).unwrap_or_default();
                return fail(
                    command,
                    Failed::new(
                        Kind::RemoteError,
                        format!(
                            "{}: burner there ({version}) didn't answer with json (exit {code})",
                            host.name
                        ),
                    ),
                );
            }
        };
        json::write_fd(1, &line);
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn conn(addrs: &[&str], configured: bool) -> Conn {
        Conn {
            host: Host {
                name: "mini".into(),
                addrs: addrs.iter().map(|a| a.to_string()).collect(),
                user: None,
                port: None,
                timeout: Duration::from_secs(3),
                burner: None,
                configured,
                known: vec!["mini".into(), "vps".into()],
            },
            pick: Pick {
                addr: addrs[0].into(),
                conf: probe::SshConf {
                    user: "patrick".into(),
                    ..Default::default()
                },
                skipped: vec![],
            },
            nonce: "0".repeat(32),
        }
    }

    #[test]
    fn ssh_messages() {
        let c = conn(&["10.1.0.81", "mini.tail1234.ts.net"], true);
        let changed = b"@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n\
            @@@@@@@@\nIT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n\
            Host key verification failed.\n";
        let f = c.ssh_failed(changed, Some(255));
        assert_eq!(f.kind, Kind::Unreachable);
        assert_eq!(
            f.msg,
            "mini: ssh refused 10.1.0.81's host key. burner never accepts host keys itself: check it with ssh 10.1.0.81, or use -H mini.tail1234.ts.net"
        );
        let f = c.ssh_failed(
            b"No ED25519 host key is known for 10.1.0.81 and you have requested strict checking.\nHost key verification failed.\n",
            Some(255),
        );
        assert!(
            f.msg
                .contains("isn't known yet. connect once with ssh 10.1.0.81")
        );
        let f = c.ssh_failed(
            b"patrick@10.1.0.81: Permission denied (publickey).\n",
            Some(255),
        );
        assert_eq!(
            f.msg,
            "mini: ssh failed on 10.1.0.81: patrick@10.1.0.81: Permission denied (publickey)."
        );
        let f = c.ssh_failed(b"Unmatched '.\n", Some(1));
        assert_eq!(f.kind, Kind::RemoteError);
        assert!(f.msg.contains("the login shell for patrick on mini"));
        let mut typo = conn(&["mnii"], false);
        typo.host.name = "mnii".into();
        let f = typo.ssh_failed(
            b"ssh: Could not resolve hostname mnii: nodename nor servname provided, or not known\n",
            Some(255),
        );
        assert!(f.msg.starts_with("mnii isn't in "), "{}", f.msg);
        assert!(f.msg.ends_with(
            "(mini, vps), and ssh says: ssh: Could not resolve hostname mnii: nodename nor servname provided, or not known"
        ));
        // a hostile ssh config or banner can't put controls in burner's message
        let f = c.ssh_failed(b"x\x1b]0;pwned\x07\n", Some(255));
        assert_eq!(f.msg, "mini: ssh failed on 10.1.0.81: x?]0;pwned?");
    }

    #[test]
    fn json_from_the_far_end_is_cleaned() {
        let raw = "{\"schema\":1,\"host\":null,\"a\u{85}\":[\"x\u{9b}31m\",\"\u{7f}\",1],\"b\":{\"c\":\"ok\\n\"}}\n";
        assert_eq!(
            forward_json(raw, "vps").unwrap(),
            "{\"schema\":1,\"host\":\"vps\",\"a?\":[\"x?31m\",\"?\",1],\"b\":{\"c\":\"ok\\n\"}}\n"
        );
        // a nested host first: rebuilt, sorted, with the real one set
        let odd = r#"{"r":{"host":null},"host":null}"#;
        assert_eq!(
            forward_json(odd, "vps").unwrap(),
            r#"{"host":"vps","r":{"host":null}}"#.to_string() + "\n"
        );
        // pretty printed comes out on one line
        assert_eq!(
            forward_json("{\n\"host\": null\n}", "x").unwrap(),
            "{\"host\":\"x\"}\n"
        );
        assert!(forward_json("[1]", "x").is_none());
        assert!(forward_json("nope", "x").is_none());
    }
}
