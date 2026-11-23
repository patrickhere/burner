//! the laptop's side of -H. it picks an address, starts ssh with the fixed
//! options and the wrapper, and reads back what comes: the far end's output
//! goes through the same escaping a local run's does, its records are taken
//! out and checked, and the exit code is decided here from them, never from
//! ssh's own 255

use std::io::Read;
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::frame::{Frames, Record, printable};
use super::hosts::{self, Host};
use super::probe::{self, Pick};
use super::quote;
use super::ssh::{self, Mode, Opts};
use crate::exit::{EXIT_INTERRUPTED, EXIT_SANDBOX, EXIT_USAGE};
use crate::json::{self, Kind};
use crate::output::{Dest, Out};
use crate::run::RunArgs;
use crate::run::record::{self, RunOutcome};
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
    pub(super) fn take_record(&mut self, r: Record) {
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
                s.take_record(r);
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

/// a json document from the far end on one line, with DEL and C1 controls
/// made ? (serde escapes C0 ones, these it would pass on raw to your
/// terminal) and the host filled in. it's written from what was parsed, not
/// patched as text: a far end that sends a key twice can't have readers that
/// take the first one see something else than burner did. None when it
/// isn't a json object
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
    // and once parsed: a \u009b escape is a C1 control only then
    crate::runlog::clean(&mut v);
    v["host"] = Value::String(host.into());
    Some(v.to_string() + "\n")
}

/// a run's or shell's argv for the far end with --config in it, right
/// after the command word and --remote: after the `--` it would be part of
/// the command
pub(super) fn with_config(mut args: Vec<String>, config: &[String]) -> Vec<String> {
    let at = 3.min(args.len());
    args.splice(at..at, config.iter().cloned());
    args
}

/// waits for a reader thread, but not forever: whatever ssh left running (a
/// ProxyCommand, a connection master) can hold its pipes open after it exited
pub(super) fn join_until<T>(h: std::thread::JoinHandle<T>, until: Instant) -> Option<T> {
    while !h.is_finished() {
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    h.join().ok()
}

/// how long readers get once ssh has exited
pub(super) const READERS_GRACE: Duration = Duration::from_secs(10);

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
    let out = Arc::new(Out::new(Dest::Stdout));
    let json_on = json::on();
    let outs = child.stdout.take().map(|mut so| {
        let out = out.clone();
        std::thread::spawn(move || {
            let mut reply = Vec::new();
            if json_on {
                let _ = so.by_ref().take(JSON_CAP + 1).read_to_end(&mut reply);
                // whatever is past the cap is read and dropped: ssh's pipe would fill
                let _ = std::io::copy(&mut so, &mut std::io::sink());
            } else {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = so.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    out.put(&buf[..n], Some(Instant::now() + Duration::from_secs(300)));
                }
            }
            reply
        })
    });
    let st = child.wait();
    let grace = Instant::now() + READERS_GRACE;
    let reply = outs.map(|h| join_until(h, grace));
    let errs_done = errs.map(|h| join_until(h, grace).is_some());
    if matches!(reply, Some(None)) || errs_done == Some(false) {
        return fail(command, still_open(&host.name));
    }
    let reply = reply.flatten().unwrap_or_default();
    let until = Instant::now() + Duration::from_secs(30);
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

/// how a run or a shell over -H ended, from what came back
pub(super) struct End {
    pub(super) code: u8,
    /// the far end's json, when it said how the run ended
    pub(super) env: Option<Value>,
    pub(super) raw: Option<String>,
    /// why the client decides it instead
    pub(super) failed: Option<(RunOutcome, Failed)>,
}

/// waits for ssh, and on a signal here passes SIGTERM on to it: a ctrl-c
/// reached it already, a kill aimed at burner didn't. ssh going is what
/// stops the VM on the far end
pub(super) fn wait_ssh(child: &mut Child) -> Option<ExitStatus> {
    let mut sent: Option<Instant> = None;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        if crate::run::is_interrupted() {
            match sent {
                None => {
                    // SAFETY: kill(2) on our own child, which we haven't reaped
                    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
                    sent = Some(Instant::now());
                }
                Some(t) if t.elapsed() > Duration::from_secs(3) => {
                    let _ = child.kill();
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// what a run's records and ssh's exit say, as an exit code and outcome
pub(super) fn decide(c: &Conn, s: &Seen, ssh: Option<i32>, what: &str) -> End {
    let name = &c.host.name;
    let failed = |o: RunOutcome, f: Failed| End {
        code: EXIT_SANDBOX,
        env: None,
        raw: None,
        failed: Some((o, f)),
    };
    // a ctrl-c while ssh connects is an interruption, not a host that's down
    if s.wrap.is_none() && s.nobin.is_none() && !crate::run::is_interrupted() {
        let f = c.ssh_failed(&s.pre, ssh);
        let o = if f.kind == Kind::RemoteError {
            RunOutcome::RemoteError
        } else {
            RunOutcome::Unreachable
        };
        return failed(o, f);
    }
    if let Some(f) = remote_failed(c, s, what) {
        return failed(RunOutcome::RemoteError, f);
    }
    if let Some(raw) = &s.status {
        let env: Option<Value> = serde_json::from_str(raw).ok();
        let code = env
            .as_ref()
            .and_then(|e| e.get("exit"))
            .and_then(Value::as_u64)
            .filter(|c| *c <= 255);
        if let (Some(env), Some(code)) = (env, code) {
            if let Err(why) = adds_up(&env, code as u8) {
                return failed(
                    RunOutcome::RemoteError,
                    Failed::new(
                        Kind::RemoteError,
                        format!(
                            "{name}: burner there ended with json that doesn't add up ({why}), so nothing it said counts"
                        ),
                    ),
                );
            }
            return End {
                code: code as u8,
                env: Some(env),
                raw: Some(raw.clone()),
                failed: None,
            };
        }
        return failed(
            RunOutcome::RemoteError,
            Failed::new(
                Kind::RemoteError,
                format!("{name}: a run's end without an exit code"),
            ),
        );
    }
    let id = s.start.as_deref();
    if crate::run::is_interrupted() {
        let msg = match id {
            Some(id) => format!("interrupted, {id} on {name} stops when burner there sees ssh go"),
            None => format!("interrupted, nothing started on {name}"),
        };
        return End {
            code: EXIT_INTERRUPTED,
            env: None,
            raw: None,
            failed: Some((RunOutcome::Interrupted, Failed::new(Kind::Interrupted, msg))),
        };
    }
    let version = s.wrap.as_ref().map(|w| w.3.clone()).unwrap_or_default();
    match (id, ssh) {
        // the far end refused the arguments before anything started: clap,
        // or a protocol it doesn't speak
        (None, Some(2)) => failed(
            RunOutcome::RemoteError,
            Failed::new(
                Kind::RemoteError,
                format!(
                    "{name} runs {} and this is burnervm {}, and it didn't take the arguments ({}). update burner on {name}",
                    if version.is_empty() {
                        "another burner"
                    } else {
                        &version
                    },
                    env!("CARGO_PKG_VERSION"),
                    s.first_line.as_deref().unwrap_or("no reason given")
                ),
            ),
        ),
        (Some(id), _) => failed(
            RunOutcome::Lost,
            Failed::new(
                Kind::Lost,
                format!(
                    "lost the connection to {name} while {id} was running. burner there stops it once it notices, burner -H {name} ls shows it"
                ),
            ),
        ),
        (None, Some(255) | None) => failed(
            RunOutcome::Lost,
            Failed::new(
                Kind::Lost,
                format!("lost the connection to {name} before the run started"),
            ),
        ),
        (None, Some(rc)) => failed(
            RunOutcome::RemoteError,
            Failed::new(
                Kind::RemoteError,
                format!(
                    "{name}: burner there ({version}) ended with {rc} without saying how the run went"
                ),
            ),
        ),
    }
}

/// the far end's end of a run, checked against itself: schema 1, and an
/// exit code that goes with the outcome the way exit.rs has it. this can't
/// tell a true answer from a lie told well, the host ran the VM and holds
/// the nonce, but a careless or garbled one doesn't pass
pub(super) fn adds_up(env: &Value, code: u8) -> Result<(), String> {
    if env.get("schema").and_then(Value::as_u64) != Some(u64::from(crate::json::SCHEMA)) {
        return Err("not schema 1".into());
    }
    let result = env.get("result").unwrap_or(&Value::Null);
    if result.is_null() {
        // a usage error, a config that didn't load, a signal before the run had an id
        return match code {
            2 | 125 | 130 => Ok(()),
            _ => Err(format!("exit {code} without a result")),
        };
    }
    let Some(outcome) = result.get("outcome").and_then(Value::as_str) else {
        return Err("a result without an outcome".into());
    };
    let rc = result.get("rc").and_then(Value::as_i64);
    let fits = match serde_json::from_value::<RunOutcome>(Value::String(outcome.into())) {
        Ok(RunOutcome::Exited) => match rc {
            Some(rc) => rc == i64::from(code),
            // a shell whose VM was powered off: no rc, exit 0
            None => code == 0,
        },
        Ok(RunOutcome::Detached) => code == 0,
        Ok(RunOutcome::Timeout) => code == crate::exit::EXIT_TIMEOUT,
        Ok(RunOutcome::Killed | RunOutcome::Interrupted) => code == EXIT_INTERRUPTED,
        Ok(
            RunOutcome::Busy
            | RunOutcome::SandboxError
            | RunOutcome::InputError
            | RunOutcome::Poweroff
            | RunOutcome::Reboot,
        ) => code == EXIT_SANDBOX,
        // only a client says these
        Ok(RunOutcome::Unreachable | RunOutcome::RemoteError | RunOutcome::Lost) => false,
        // one from a newer burner: fine as long as it isn't a success
        Err(_) => code != 0,
    };
    if !fits {
        return Err(format!(
            "outcome {} with exit {code}",
            printable(outcome, 32)
        ));
    }
    let ok = matches!(outcome, "exited" | "detached");
    if env
        .get("ok")
        .and_then(Value::as_bool)
        .is_some_and(|o| o != ok)
    {
        return Err(format!("ok doesn't match outcome {outcome}"));
    }
    Ok(())
}

/// the end of a run or shell over -H, here: the far end's own json with the
/// host filled in, or the client's when the far end never said. the status
/// line is made here either way, from parsed fields
pub(super) fn finish_run_with_id(
    a: &RunArgs,
    t0: Instant,
    end: End,
    host: &str,
    id: Option<&str>,
) -> ExitCode {
    let code = end.code;
    let kept = crate::runlog::keep(crate::runlog::Ended::Remote {
        host,
        args: a,
        t0,
        code,
        env: end.env.as_ref(),
        raw: end.raw.as_deref(),
        id,
        outcome: end.failed.as_ref().map(|(o, _)| *o),
    });
    // the far end's summary named its own log: this one is kept here too
    let logged = end
        .env
        .as_ref()
        .and_then(|e| e.get("result"))
        .and_then(|r| r.get("id").and_then(Value::as_str).zip(r.get("network")))
        .filter(|(i, n)| crate::ledger::valid_id(i) && n.is_object())
        .map(|(i, _)| i.to_string());
    if kept
        && !json::on()
        && let Some(i) = logged
        && !log_none(a)
    {
        let local = if std::env::var("BURNER_HOST").is_ok_and(|h| !h.is_empty()) {
            "burner -H local log"
        } else {
            "burner log"
        };
        eprintln!("burner: kept here too, {local} {i}");
    }
    match (end.failed, end.env, end.raw) {
        (Some((outcome, f)), _, _) => {
            if !json::on() {
                eprintln!("burner: {}", f.msg);
            }
            let why = json::Problem {
                kind: f.kind,
                message: f.msg,
            };
            let fin = record::client_end(t0, code, outcome, id, why);
            crate::run::finished(a, fin)
        }
        (None, Some(env), Some(raw)) => {
            if let Some(fd) = a.status_fd() {
                json::write_fd(
                    fd,
                    &record::status_line_of(&env, code, t0.elapsed().as_secs_f64()),
                );
            }
            if let Some(fd) = crate::run::json_target(a)
                && let Some(line) = forward_json(&raw, host)
            {
                json::write_fd(fd, &crate::run::json_line(a, &line));
            }
            ExitCode::from(code)
        }
        _ => ExitCode::from(EXIT_SANDBOX),
    }
}

/// the run was asked for with --log none: then nothing of the log is said
/// here either. RunArgs keeps its log mode to itself, what goes to the far
/// end says it
fn log_none(a: &RunArgs) -> bool {
    a.remote_argv("", false)
        .windows(2)
        .any(|w| w[0] == "--log" && w[1] == "none")
}

/// `burner -H HOST run`: stdin goes to ssh as it is, the command's output
/// comes back escaped on a terminal and raw into a pipe, and the far end's
/// records say how it ended
pub fn run(host: &Host, a: &RunArgs, config: &[String]) -> ExitCode {
    json::set_host(&host.name);
    crate::run::catch_signals();
    let t0 = Instant::now();
    if let Some(code) = crate::run::check_fds(a, t0) {
        return code;
    }
    if let Err(msg) = a.check_local() {
        return crate::run::refuse(a, Kind::Usage, msg);
    }
    let ended = |end: End| finish_run_with_id(a, t0, end, &host.name, None);
    let failed = |o: RunOutcome, f: Failed| End {
        code: if f.kind == Kind::Usage {
            EXIT_USAGE
        } else {
            EXIT_SANDBOX
        },
        env: None,
        raw: None,
        failed: Some((o, f)),
    };
    let c = match Conn::open(host) {
        Ok(c) => c,
        Err(f) => return ended(failed(RunOutcome::Unreachable, f)),
    };
    let args = with_config(a.remote_argv(&c.nonce, json::on()), config);
    let o = Opts {
        no_stdin: !a.reads_stdin(),
        ..Default::default()
    };
    let mut cmd = match c.command(o, Mode::Auto, &args) {
        Ok(cmd) => cmd,
        Err(f) if f.kind == Kind::Usage => return crate::run::refuse(a, Kind::Usage, f.msg),
        Err(f) => return ended(failed(RunOutcome::Unreachable, f)),
    };
    cmd.stdin(if a.reads_stdin() {
        Stdio::inherit()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = match spawn(&mut cmd) {
        Ok(ch) => ch,
        Err(f) => return ended(failed(RunOutcome::Unreachable, f)),
    };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let err_out = Arc::new(Out::new(Dest::Stderr));
    let errs = child
        .stderr
        .take()
        .map(|e| read_records(e, &c.nonce, seen.clone(), err_out.clone()));
    // with --json stdout is the json's, and the command's output goes to stderr
    let live = Arc::new(Out::new(if json::on() {
        Dest::Stderr
    } else {
        Dest::Stdout
    }));
    // --result tar: stdout is the far end's tar, spooled to be checked here
    // before any of it reaches yours
    let (spool, sink) = match a.result_tar().then(Spool::new).transpose() {
        Ok(Some((sp, f))) => (Some(sp), Sink::Spool(f)),
        Ok(None) => (None, Sink::Live(live.clone())),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            let f = Failed::new(
                Kind::Io,
                format!("no private place for the result tar: {e}"),
            );
            return ended(failed(RunOutcome::SandboxError, f));
        }
    };
    let over = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outs = child.stdout.take().map(|mut so| {
        let over = over.clone();
        let mut sink = sink;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut n_total = 0u64;
            while let Ok(n) = so.read(&mut buf) {
                if n == 0 {
                    break;
                }
                match &mut sink {
                    // past the cap the rest is read and dropped, so ssh never blocks
                    Sink::Spool(f) => {
                        n_total += n as u64;
                        if n_total > crate::result::CLEAN_SIZE
                            || std::io::Write::write_all(f, &buf[..n]).is_err()
                        {
                            over.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Sink::Live(live) => {
                        live.put(&buf[..n], Some(Instant::now() + Duration::from_secs(300)))
                    }
                }
            }
        })
    });
    let st = wait_ssh(&mut child);
    let grace = Instant::now() + READERS_GRACE;
    let mut stuck = false;
    for h in [errs, outs].into_iter().flatten() {
        stuck |= join_until(h, grace).is_none();
    }
    let until = Instant::now() + Duration::from_secs(30);
    live.drain(until);
    err_out.drain(until);
    let s = seen.lock().unwrap_or_else(|e| e.into_inner());
    let mut end = decide(&c, &s, st.as_ref().and_then(exit_of), "run");
    let id = s.start.clone();
    drop(s);
    // a reader still going could still bring a second end line or more of
    // the tar: nothing it read so far counts
    if stuck {
        end = End {
            code: EXIT_SANDBOX,
            env: None,
            raw: None,
            failed: Some((RunOutcome::RemoteError, still_open(&host.name))),
        };
    }
    if let (Some(sp), Some(env)) = (&spool, end.env.as_mut()) {
        let over = over.load(std::sync::atomic::Ordering::Relaxed);
        if let Err(why) = sp.deliver(env, over, &host.name) {
            if !json::on() {
                eprintln!("burner: {why}");
            }
            result_lost(env, &why);
            end.code = EXIT_SANDBOX;
            end.raw = Some(env.to_string());
        }
    }
    finish_run_with_id(a, t0, end, &host.name, id.as_deref())
}

/// the far end's json for a run whose result tar didn't check out here: a
/// sandbox error now, with why first in the errors
fn result_lost(env: &mut Value, why: &str) {
    env["exit"] = EXIT_SANDBOX.into();
    env["ok"] = false.into();
    if let Some(r) = env.get_mut("result").filter(|r| r.is_object()) {
        r["outcome"] = "sandbox_error".into();
        r["rc"] = Value::Null;
        if let Some(t) = r.get_mut("result_tar").filter(|t| t.is_object()) {
            t["delivered"] = false.into();
        }
    }
    let p = serde_json::json!({"kind": "result_lost", "message": why});
    match env.get_mut("errors").and_then(Value::as_array_mut) {
        Some(e) => e.insert(0, p),
        None => env["errors"] = Value::Array(vec![p]),
    }
}

/// where a run's stdout from the far end goes: your stdout, or the spool
/// that gets checked first. never one when the other was asked for
enum Sink {
    Live(Arc<Out>),
    Spool(std::fs::File),
}

/// ssh exited, but its output didn't close in time: something it started
/// holds it open
pub(super) fn still_open(host: &str) -> Failed {
    Failed::new(
        Kind::RemoteError,
        format!(
            "{host}: ssh's output didn't close after it exited (something it started holds it), so nothing that came back counts"
        ),
    )
}

/// a place for files only you can read: $XDG_RUNTIME_DIR/burner, or
/// burner-UID in the temp dir (your own one on a mac). one that already
/// exists has to be yours and private, or it isn't used
pub(super) fn private_dir() -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    // SAFETY: getuid can't fail
    let me = unsafe { libc::getuid() };
    #[cfg(target_os = "macos")]
    let base = crate::config::user_temp().join(format!("burner-{me}"));
    #[cfg(target_os = "linux")]
    let base = match std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from) {
        Some(d) if d.is_absolute() => d.join("burner"),
        _ => std::env::temp_dir().join(format!("burner-{me}")),
    };
    // made 0700 or found, never chmod'ed: in a shared /tmp it could be a
    // link someone planted, and that's refused below without touching it
    match std::fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = std::fs::symlink_metadata(&base)?;
    if !m.is_dir() || m.uid() != me || m.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} isn't a directory only you can use",
            base.display()
        )));
    }
    Ok(base)
}

/// the files go however the run ended: delivered, refused, or never
/// looked at because the far end didn't say how it went
impl Drop for Spool {
    fn drop(&mut self) {
        for ext in ["tar", "clean", "log"] {
            let _ = std::fs::remove_file(self.path.with_extension(ext));
        }
    }
}

/// the result tar as it came from the far end, in a private file
struct Spool {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
    file: std::fs::File,
}

impl Spool {
    /// the spool and a second handle to write it with. without that second
    /// handle there's no run with --result tar: nothing goes to stdout unchecked
    fn new() -> std::io::Result<(Spool, std::fs::File)> {
        let sp = Spool::create()?;
        let w = sp.file.try_clone()?;
        Ok((sp, w))
    }

    fn create() -> std::io::Result<Spool> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = private_dir()?;
        let path = dir.join(format!("result-{}.tar", sys::random_hex(8)?));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        Ok(Spool { dir, path, file })
    }

    /// parse it again here and write the clean tar that comes out to stdout.
    /// Err says why nothing (or not all of it) was written
    fn deliver(&self, env: &Value, over: bool, host: &str) -> Result<(), String> {
        let clean = self.path.with_extension("clean");
        let log = self.path.with_extension("log");
        self.deliver_inner(env, over, host, &clean, &log)
    }

    fn deliver_inner(
        &self,
        env: &Value,
        over: bool,
        host: &str,
        clean: &std::path::Path,
        log: &std::path::Path,
    ) -> Result<(), String> {
        if over {
            return Err(format!(
                "the result tar from {host} is over the size cap, nothing written"
            ));
        }
        let len = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        let said = env
            .pointer("/result/result_tar/delivered")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if len == 0 {
            return match said {
                true => Err(format!("the result tar from {host} didn't arrive")),
                false => Ok(()),
            };
        }
        let f = std::fs::File::open(&self.path).map_err(|e| e.to_string())?;
        let meta = crate::result::recheck(f, log, clean, &self.dir);
        if meta.fatal {
            return Err(format!(
                "the result tar from {host} didn't check out here ({}), nothing written",
                meta.problem.as_deref().unwrap_or("no reason")
            ));
        }
        let mut c = std::fs::File::open(clean).map_err(|e| e.to_string())?;
        let mut out = std::io::stdout().lock();
        std::io::copy(&mut c, &mut out)
            .and_then(|_| std::io::Write::flush(&mut out))
            .map_err(|e| format!("result tar not fully delivered ({e})"))?;
        Ok(())
    }
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
    fn ends_that_add_up() {
        let e = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        let run = |o: &str, rc: &str| {
            e(&format!(
                r#"{{"schema":1,"ok":{},"result":{{"outcome":"{o}","rc":{rc}}}}}"#,
                o == "exited" || o == "detached"
            ))
        };
        assert!(adds_up(&run("exited", "7"), 7).is_ok());
        assert!(adds_up(&run("exited", "255"), 255).is_ok());
        assert!(adds_up(&run("exited", "null"), 0).is_ok());
        assert!(adds_up(&run("timeout", "null"), 124).is_ok());
        assert!(adds_up(&run("killed", "null"), 130).is_ok());
        assert!(adds_up(&run("busy", "null"), 125).is_ok());
        assert!(adds_up(&run("detached", "null"), 0).is_ok());
        assert!(adds_up(&run("teleported", "null"), 125).is_ok());
        assert!(adds_up(&e(r#"{"schema":1,"result":null}"#), 2).is_ok());
        // what doesn't
        assert!(adds_up(&run("exited", "7"), 0).is_err());
        assert!(adds_up(&run("timeout", "null"), 0).is_err());
        assert!(adds_up(&run("sandbox_error", "null"), 0).is_err());
        assert!(adds_up(&run("lost", "null"), 125).is_err());
        assert!(adds_up(&run("teleported", "null"), 0).is_err());
        assert!(adds_up(&e(r#"{"schema":2,"result":null}"#), 2).is_err());
        assert!(adds_up(&e(r#"{"result":null}"#), 2).is_err());
        assert!(adds_up(&e(r#"{"schema":1,"result":null}"#), 0).is_err());
        assert!(
            adds_up(
                &e(r#"{"schema":1,"ok":false,"result":{"outcome":"exited","rc":0}}"#),
                0
            )
            .is_err()
        );
        assert!(adds_up(&e(r#"{"schema":1,"result":{"rc":0}}"#), 0).is_err());
    }

    #[test]
    fn config_goes_before_the_command() {
        let a: Vec<String> = ["run", "--remote", "1:x", "--net", "none", "--", "ls"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            with_config(a, &["--config=/etc/burner/b.toml".into()]),
            [
                "run",
                "--remote",
                "1:x",
                "--config=/etc/burner/b.toml",
                "--net",
                "none",
                "--",
                "ls"
            ]
        );
    }

    #[test]
    fn json_from_the_far_end_is_cleaned() {
        let raw =
            "{\"host\":null,\"a\u{85}\":[\"x\u{9b}31m\",\"\u{7f}\",1],\"b\":{\"c\":\"ok\\n\"}}\n";
        assert_eq!(
            forward_json(raw, "vps").unwrap(),
            "{\"a?\":[\"x?31m\",\"?\",1],\"b\":{\"c\":\"ok\\n\"},\"host\":\"vps\"}\n"
        );
        // escaped in the json, raw once parsed
        assert_eq!(
            forward_json(r#"{"a":"x\u009b31m\u007f\u0085"}"#, "vps").unwrap(),
            "{\"a\":\"x?31m??\",\"host\":\"vps\"}\n"
        );
        // a host the far end sends twice is one, ours
        let twice = r#"{"host":"evil","exit":0,"host":null}"#;
        assert_eq!(
            forward_json(twice, "vps").unwrap(),
            r#"{"exit":0,"host":"vps"}"#.to_string() + "\n"
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
