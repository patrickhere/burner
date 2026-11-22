//! `burner -H HOST doctor` checks the way there: the addresses, ssh, burner
//! and the sudo rule on the far end, then shows that host's own doctor.
//! `burner hosts` lists hosts.toml, and with --check tries every address

use std::io::Read;
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::client::{self, Conn, Seen};
use super::frame::printable;
use super::hosts::{self, Host};
use super::probe::{self, Answer};
use super::ssh::{Mode, Opts};
use crate::exit::{EXIT_FAILED, EXIT_USAGE};
use crate::json::{self, Kind};
use crate::output::{Dest, Out, escape_controls};

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
}

#[derive(Serialize)]
pub struct Report {
    pub host: String,
    pub worst: Level,
    pub checks: Vec<Check>,
    /// the far end's own doctor, its json result with --json
    pub remote: Option<Value>,
}

impl Report {
    fn line(&mut self, level: Level, what: &str, detail: impl Into<String>) {
        let detail = detail.into();
        let tag = match level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        if !json::on() {
            println!("{tag}  {what:<12} {detail}");
        }
        self.worst = self.worst.max(level);
        self.checks.push(Check {
            name: what.into(),
            level,
            detail,
        });
    }
}

fn ms(d: Duration) -> String {
    format!("{} ms", d.as_millis())
}

/// every address of a host tried at once: what ssh -G says and whether it
/// answers
fn knock_all(host: &Host) -> Vec<(String, Result<probe::SshConf, String>, Option<Answer>)> {
    let handles: Vec<_> = host
        .addrs
        .iter()
        .map(|a| {
            let (host, a) = (host.clone(), a.clone());
            std::thread::spawn(move || {
                let conf = probe::ssh_conf(&host, &a);
                let answer = match &conf {
                    Ok(c) if !c.proxied => Some(probe::knock(&c.hostname, c.port, host.timeout)),
                    _ => None,
                };
                (a, conf, answer)
            })
        })
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}

pub fn doctor(host: &Host, config: &[String]) -> ExitCode {
    json::set_host(&host.name);
    let mut r = Report {
        host: host.name.clone(),
        worst: Level::Ok,
        checks: Vec::new(),
        remote: None,
    };
    let name = &host.name;
    let n = host.addrs.len();
    r.line(
        Level::Ok,
        "hosts",
        if host.configured {
            format!("{name}, {n} address{}", if n == 1 { "" } else { "es" })
        } else {
            format!(
                "{name} isn't in {}, it's used as an ssh host",
                hosts::shown(&hosts::path())
            )
        },
    );
    let knocks = knock_all(host);
    let any_up = knocks
        .iter()
        .any(|(_, c, a)| matches!(a, Some(Answer::Up(_))) || c.as_ref().is_ok_and(|c| c.proxied));
    for (i, (addr, conf, answer)) in knocks.iter().enumerate() {
        let later = if i > 0 {
            ", used when the ones before it don't"
        } else {
            ""
        };
        match (conf, answer) {
            (Err(e), _) => r.line(Level::Fail, "address", format!("{addr}: ssh -G says: {e}")),
            (Ok(c), _) if c.proxied => {
                r.line(
                    Level::Ok,
                    "address",
                    format!("{addr} goes through a ProxyJump or ProxyCommand, not probed{later}"),
                );
            }
            (Ok(c), Some(Answer::Up(t))) => {
                r.line(
                    Level::Ok,
                    "address",
                    format!("{} answers ({}){later}", probe::label(addr, c), ms(*t)),
                );
            }
            (Ok(c), Some(Answer::Down(why))) => r.line(
                if any_up { Level::Warn } else { Level::Fail },
                "address",
                format!("{}: {why}", probe::label(addr, c)),
            ),
            (Ok(_), None) => {}
        }
    }
    if !any_up {
        return done(r);
    }
    let c = match Conn::open(host) {
        Ok(c) => c,
        Err(f) => {
            r.line(Level::Fail, "ssh", f.msg);
            return done(r);
        }
    };
    let mut args = vec!["doctor".to_string()];
    if json::on() {
        args.push("--json".into());
    }
    args.extend(config.iter().cloned());
    let o = Opts {
        no_stdin: true,
        batch: true,
        ..Default::default()
    };
    let mut cmd = match c.command(o, Mode::Doctor, &args) {
        Ok(cmd) => cmd,
        Err(f) => {
            r.line(Level::Fail, "ssh", f.msg);
            return done(r);
        }
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            r.line(Level::Fail, "ssh", format!("can't run ssh: {e}"));
            return done(r);
        }
    };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = Arc::new(Out::new(Dest::Null));
    let errs = child
        .stderr
        .take()
        .map(|e| client::read_records(e, &c.nonce, seen.clone(), sink.clone()));
    let outs = child.stdout.take().map(|mut so| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = so.by_ref().take(4 << 20).read_to_end(&mut out);
            // the rest is read and dropped, or ssh would block on a full pipe
            let _ = std::io::copy(&mut so, &mut std::io::sink());
            out
        })
    });
    let st = child.wait().ok();
    let grace = std::time::Instant::now() + client::READERS_GRACE;
    let out = outs.map(|h| client::join_until(h, grace));
    let errs_done = errs.map(|h| client::join_until(h, grace).is_some());
    if matches!(out, Some(None)) || errs_done == Some(false) {
        r.line(Level::Fail, "ssh", client::still_open(&host.name).msg);
        return done(r);
    }
    let out = out.flatten().unwrap_or_default();
    let code = st.as_ref().and_then(client::exit_of);
    let s = seen.lock().unwrap_or_else(|e| e.into_inner());
    let Some((os, uid, sudo, version)) = s.wrap.clone() else {
        if let Some(p) = &s.nobin {
            r.line(
                Level::Ok,
                "ssh",
                format!("as {}, host key known", c.pick.conf.user),
            );
            r.line(
                Level::Fail,
                "burner",
                format!("no burner at {p} there (install it, or set burner = \"...\" for {name} in hosts.toml)"),
            );
        } else {
            r.line(Level::Fail, "ssh", c.ssh_failed(&s.pre, code).msg);
        }
        return done(r);
    };
    let user = if c.pick.conf.user.is_empty() {
        "you".to_string()
    } else {
        c.pick.conf.user.clone()
    };
    r.line(
        Level::Ok,
        "ssh",
        format!(
            "as {user} on {}, host key known, agent forwarding off",
            c.pick.addr
        ),
    );
    if c.pick.conf.forward_agent {
        r.line(
            Level::Warn,
            "ssh",
            format!("your ssh config forwards the agent to {}: burner turns that off, plain ssh doesn't", c.pick.addr),
        );
    }
    let here = format!("burnervm {}", env!("CARGO_PKG_VERSION"));
    if version == here {
        r.line(
            Level::Ok,
            "burner",
            format!("{version} there, same as here"),
        );
    } else if version.is_empty() {
        r.line(
            Level::Fail,
            "burner",
            "burner there doesn't say its version",
        );
    } else {
        r.line(
            Level::Warn,
            "burner",
            format!("{version} there and {here} here. runs work while they speak the same protocol; update the older one"),
        );
    }
    if os == "Darwin" {
        r.line(Level::Ok, "user", format!("macOS, runs as {user}"));
    } else if !sudo {
        r.line(
            Level::Ok,
            "sudo",
            format!("ssh'd in as uid {uid}, burner runs without sudo"),
        );
    } else {
        let no: Vec<&str> = s
            .sudo
            .iter()
            .filter(|(c, ok)| c != "doctor" && !ok)
            .map(|(c, _)| c.as_str())
            .collect();
        if s.sudo.is_empty() {
            r.line(
                Level::Fail,
                "sudo",
                "burner there didn't say what sudo allows",
            );
        } else if no.is_empty() {
            r.line(
                Level::Ok,
                "sudo",
                "run, shell, ls, kill and images allowed without a password",
            );
        } else {
            r.line(
                Level::Fail,
                "sudo",
                format!(
                    "no NOPASSWD rule there for burner {}: -H needs one, see dist/sudoers.example",
                    no.join(", ")
                ),
            );
        }
        if s.sudo.iter().any(|(c, ok)| c == "doctor" && !ok) {
            r.line(
                Level::Warn,
                "doctor",
                format!("burner doctor needs root there and the sudo rule doesn't cover it: ssh -t {} sudo burner doctor", c.pick.addr),
            );
        }
    }
    if let Some(b) = &s.broken {
        r.line(
            Level::Fail,
            "records",
            format!("{b}, so nothing it said counts"),
        );
        return done(r);
    }
    drop(s);
    match code {
        Some(255) | None => r.line(Level::Fail, "ssh", format!("lost the connection to {name}")),
        Some(rc) => {
            if json::on() {
                let v: Option<Value> = client::forward_json(&String::from_utf8_lossy(&out), name)
                    .and_then(|l| serde_json::from_str::<Value>(&l).ok());
                r.remote = v.and_then(|v| v.get("result").cloned());
            } else {
                println!("{name}'s own doctor:");
                let text = escape_controls(&out);
                for l in String::from_utf8_lossy(&text).lines() {
                    println!("  | {l}");
                }
            }
            if rc != 0 {
                r.line(
                    Level::Fail,
                    "doctor",
                    format!("{name}'s own doctor found something to fix, above"),
                );
            }
        }
    }
    done(r)
}

fn done(r: Report) -> ExitCode {
    if !json::on() {
        match r.worst {
            Level::Ok => println!("works"),
            Level::Warn => println!("works, see the warnings above"),
            Level::Fail => println!("not ready, fix the FAIL lines first"),
        }
    }
    if r.worst == Level::Fail {
        json::note_error(
            Kind::DoctorFailed,
            "not ready, fix the FAIL lines first",
            false,
        );
        return json::reply("doctor", EXIT_FAILED, Some(r));
    }
    json::reply("doctor", 0, Some(r))
}

#[derive(Serialize)]
pub struct HostsResult {
    pub path: String,
    pub hosts: Vec<HostLine>,
}

#[derive(Serialize)]
pub struct HostLine {
    pub name: String,
    pub addrs: Vec<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub connect_timeout_secs: f64,
    pub burner: Option<String>,
    /// with --check, per address
    pub checks: Option<Vec<AddrCheck>>,
}

#[derive(Serialize)]
pub struct AddrCheck {
    pub addr: String,
    /// answered a tcp connect, or goes through a proxy and wasn't tried
    pub up: bool,
    pub proxied: bool,
    pub connect_ms: Option<u64>,
    pub why: Option<String>,
}

/// `burner hosts [--check]`: what hosts.toml has, and with --check whether
/// each address answers right now
pub fn hosts(check: bool) -> ExitCode {
    let path = hosts::path();
    let entries = match hosts::load(&path) {
        Ok(h) => h,
        Err(e) => return json::fail("hosts", EXIT_USAGE, Kind::Config, format!("{e:#}")),
    };
    let mut lines = Vec::new();
    for name in entries.keys() {
        let Ok(h) = hosts::lookup(name, &entries) else {
            continue;
        };
        let checks = check.then(|| {
            knock_all(&h)
                .into_iter()
                .map(|(addr, conf, answer)| match (conf, answer) {
                    (Err(e), _) => AddrCheck {
                        addr,
                        up: false,
                        proxied: false,
                        connect_ms: None,
                        why: Some(e),
                    },
                    (Ok(c), _) if c.proxied => AddrCheck {
                        addr,
                        up: true,
                        proxied: true,
                        connect_ms: None,
                        why: None,
                    },
                    (Ok(_), Some(Answer::Up(t))) => AddrCheck {
                        addr,
                        up: true,
                        proxied: false,
                        connect_ms: Some(t.as_millis() as u64),
                        why: None,
                    },
                    (Ok(_), Some(Answer::Down(w))) => AddrCheck {
                        addr,
                        up: false,
                        proxied: false,
                        connect_ms: None,
                        why: Some(w),
                    },
                    (Ok(_), None) => AddrCheck {
                        addr,
                        up: false,
                        proxied: false,
                        connect_ms: None,
                        why: None,
                    },
                })
                .collect::<Vec<_>>()
        });
        lines.push(HostLine {
            name: h.name.clone(),
            addrs: h.addrs.clone(),
            user: h.user.clone(),
            port: h.port,
            connect_timeout_secs: h.timeout.as_secs_f64(),
            burner: h.burner.clone(),
            checks,
        });
    }
    if !json::on() {
        if lines.is_empty() {
            println!("no hosts in {}", hosts::shown(&path));
        }
        let w = lines.iter().map(|l| l.name.len()).max().unwrap_or(0);
        for l in &lines {
            let parts: Vec<String> = match &l.checks {
                None => l.addrs.clone(),
                Some(cs) => cs
                    .iter()
                    .map(|c| match (c.proxied, c.connect_ms, &c.why) {
                        (true, _, _) => format!("{} (via a proxy, not probed)", c.addr),
                        (_, Some(t), _) => format!("{} ({t} ms)", c.addr),
                        (_, _, Some(w)) => format!("{} ({})", c.addr, printable(w, 100)),
                        _ => format!("{} (no answer)", c.addr),
                    })
                    .collect(),
            };
            println!("{:<w$}  {}", l.name, parts.join("   "));
        }
    }
    json::reply(
        "hosts",
        0,
        Some(HostsResult {
            path: path.display().to_string(),
            hosts: lines,
        }),
    )
}
