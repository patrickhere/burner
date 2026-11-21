//! which of a host's addresses to hand ssh. they're all tried at once with a
//! plain TCP connect to the host and port ssh would use; the first one in list
//! order that answers wins, but once any has answered the earlier ones get at
//! most GRACE more. at home the LAN address answers in a few ms, away it hangs
//! and the tailnet name wins a moment after it answers. nothing is kept
//! between runs. the probe only picks an address: ssh's host key check is what
//! says it's the right machine

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::hosts::Host;
use super::ssh;

pub const GRACE: Duration = Duration::from_millis(300);

/// what `ssh -G` says it would do for an address
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshConf {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// a ProxyJump or ProxyCommand: the address can't be probed directly
    pub proxied: bool,
    /// ServerAliveInterval is set, burner leaves it alone
    pub alive_set: bool,
    pub forward_agent: bool,
}

pub fn parse_g(text: &str) -> SshConf {
    let mut c = SshConf {
        port: 22,
        ..Default::default()
    };
    for l in text.lines() {
        let Some((k, v)) = l.split_once(' ') else {
            continue;
        };
        let v = v.trim();
        let set = !v.is_empty() && v != "none";
        match k {
            "hostname" => c.hostname = v.into(),
            "port" => c.port = v.parse().unwrap_or(22),
            "user" => c.user = v.into(),
            "proxyjump" | "proxycommand" if set => c.proxied = true,
            "serveraliveinterval" => c.alive_set = v != "0",
            "forwardagent" => c.forward_agent = v != "no",
            _ => {}
        }
    }
    c
}

/// `ssh -G` for one address, or why it failed
pub fn ssh_conf(host: &Host, addr: &str) -> Result<SshConf, String> {
    let mut cmd = Command::new(ssh::program());
    cmd.args(ssh::config_argv(host, addr))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = crate::sys::run_timeout(&mut cmd, None, Duration::from_secs(10))
        .map_err(|e| format!("can't run ssh: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err.lines().map(str::trim).find(|l| !l.is_empty());
        return Err(super::frame::printable(
            line.unwrap_or("ssh -G failed"),
            300,
        ));
    }
    Ok(parse_g(&String::from_utf8_lossy(&out.stdout)))
}

/// how one address did
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Up(Duration),
    Down(String),
}

/// the choice so far, from what each address said and when the first
/// answer came. `proxied` addresses aren't probed: one counts as answering
/// once everything before it failed, and nothing after it is ever used
pub fn decide(
    answers: &[Option<Answer>],
    proxied: &[bool],
    first_up: Option<Instant>,
    now: Instant,
) -> Option<Result<usize, ()>> {
    let usable = proxied
        .iter()
        .position(|&p| p)
        .map_or(answers.len(), |p| p + 1);
    let answers = &answers[..usable];
    let up = |a: &Option<Answer>| matches!(a, Some(Answer::Up(_)));
    let down = |a: &Option<Answer>| matches!(a, Some(Answer::Down(_)));
    for (i, a) in answers.iter().enumerate() {
        let earlier_down = answers[..i].iter().all(down);
        if (up(a) || proxied[i]) && earlier_down {
            return Some(Ok(i));
        }
    }
    if let Some(t) = first_up
        && now >= t + GRACE
        && let Some(i) = answers.iter().position(up)
    {
        return Some(Ok(i));
    }
    if answers.iter().all(down) {
        return Some(Err(()));
    }
    None
}

/// a TCP connect to every address `name:port` resolves to, within `limit`
fn knock(name: &str, port: u16, limit: Duration) -> Answer {
    let t0 = Instant::now();
    let (tx, rx) = mpsc::channel();
    let target = (name.to_string(), port);
    // a lookup that hangs (a tailnet name with MagicDNS off) can't stall the race
    std::thread::spawn(move || {
        let _ = tx.send(
            target
                .to_socket_addrs()
                .map(|a| a.collect::<Vec<SocketAddr>>()),
        );
    });
    let addrs = match rx.recv_timeout(limit) {
        Ok(Ok(a)) if !a.is_empty() => a,
        Ok(_) => return Answer::Down("no such host".into()),
        Err(_) => return Answer::Down(format!("no answer from dns in {}s", limit.as_secs())),
    };
    let mut why = String::new();
    for a in addrs {
        let left = limit.saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&a, left) {
            Ok(_) => return Answer::Up(t0.elapsed()),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => why = short_err(&e),
        }
    }
    if why.is_empty() {
        why = format!("timed out after {}s", limit.as_secs_f64().round());
    }
    Answer::Down(why)
}

fn short_err(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "refused".into(),
        _ => match e.raw_os_error() {
            Some(libc::EHOSTUNREACH) => "no route".into(),
            Some(libc::ENETUNREACH) => "network unreachable".into(),
            _ => e.to_string(),
        },
    }
}

/// the address ssh gets, with what ssh -G said about it
#[derive(Debug, Clone)]
pub struct Pick {
    pub addr: String,
    pub conf: SshConf,
    /// earlier addresses that didn't answer, and why
    pub skipped: Vec<(String, String)>,
}

/// each address and how it did, for the message when none answered
pub struct NoneAnswered(pub Vec<(String, String)>);

/// the shown name of an address: `name:port` when ssh would connect
/// somewhere it doesn't say
fn label(addr: &str, c: &SshConf) -> String {
    if c.port == 22 && (c.hostname.is_empty() || c.hostname == addr) {
        addr.to_string()
    } else if c.hostname.is_empty() || c.hostname == addr {
        format!("{addr}:{}", c.port)
    } else {
        format!("{addr} ({}:{})", c.hostname, c.port)
    }
}

/// pick an address. with just one there's no probe: ssh's own timeout does
pub fn pick(host: &Host) -> Result<Pick, NoneAnswered> {
    let confs: Vec<Result<SshConf, String>> =
        host.addrs.iter().map(|a| ssh_conf(host, a)).collect();
    if host.addrs.len() == 1 {
        return match confs.into_iter().next() {
            Some(Ok(conf)) => Ok(Pick {
                addr: host.addrs[0].clone(),
                conf,
                skipped: vec![],
            }),
            Some(Err(e)) => Err(NoneAnswered(vec![(host.addrs[0].clone(), e)])),
            None => Err(NoneAnswered(vec![])),
        };
    }
    let n = host.addrs.len();
    let mut answers: Vec<Option<Answer>> = vec![None; n];
    let proxied: Vec<bool> = confs
        .iter()
        .map(|c| c.as_ref().is_ok_and(|c| c.proxied))
        .collect();
    let (tx, rx) = mpsc::channel();
    let last = proxied
        .iter()
        .position(|&p| p)
        .unwrap_or(n.saturating_sub(1));
    for (i, c) in confs.iter().enumerate().take(last + 1) {
        match c {
            Err(e) => answers[i] = Some(Answer::Down(e.clone())),
            Ok(c) if c.proxied => {}
            Ok(c) => {
                let (tx, name, port, limit) =
                    (tx.clone(), c.hostname.clone(), c.port, host.timeout);
                std::thread::spawn(move || {
                    let _ = tx.send((i, knock(&name, port, limit)));
                });
            }
        }
    }
    drop(tx);
    let deadline = Instant::now() + host.timeout + Duration::from_secs(1);
    let mut first_up = None;
    let chosen = loop {
        if let Some(d) = decide(&answers, &proxied, first_up, Instant::now()) {
            break d;
        }
        let wait = match first_up {
            Some(t) => (t + GRACE).saturating_duration_since(Instant::now()),
            None => deadline.saturating_duration_since(Instant::now()),
        };
        match rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok((i, a)) => {
                if matches!(a, Answer::Up(_)) {
                    first_up.get_or_insert_with(Instant::now);
                }
                answers[i] = Some(a);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if Instant::now() >= deadline => {
                for a in answers.iter_mut().filter(|a| a.is_none()) {
                    *a = Some(Answer::Down("timed out".into()));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                for a in answers.iter_mut().filter(|a| a.is_none()) {
                    *a = Some(Answer::Down("timed out".into()));
                }
            }
        }
    };
    let why = |i: usize| -> String {
        match &answers[i] {
            Some(Answer::Down(w)) => w.clone(),
            Some(Answer::Up(_)) => "answered later".into(),
            None => "didn't answer in time".into(),
        }
    };
    let shown = |i: usize| match &confs[i] {
        Ok(c) => label(&host.addrs[i], c),
        Err(_) => host.addrs[i].clone(),
    };
    match chosen {
        Ok(i) => Ok(Pick {
            addr: host.addrs[i].clone(),
            conf: confs[i].clone().unwrap_or_default(),
            skipped: (0..i).map(|j| (shown(j), why(j))).collect(),
        }),
        Err(()) => Err(NoneAnswered(
            (0..=last.min(n - 1)).map(|j| (shown(j), why(j))).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: &str = "user patrick\nhostname 10.1.0.81\nport 22\nserveraliveinterval 0\n\
                     forwardagent no\nproxycommand none\nstricthostkeychecking ask\n";

    #[test]
    fn ssh_g() {
        let c = parse_g(G);
        assert_eq!(
            c,
            SshConf {
                hostname: "10.1.0.81".into(),
                port: 22,
                user: "patrick".into(),
                proxied: false,
                alive_set: false,
                forward_agent: false,
            }
        );
        let j = parse_g(
            "hostname vps\nport 2222\nproxyjump bastion\nserveraliveinterval 30\nforwardagent yes\n",
        );
        assert!(j.proxied && j.alive_set && j.forward_agent);
        assert_eq!(j.port, 2222);
    }

    fn up(ms: u64) -> Option<Answer> {
        Some(Answer::Up(Duration::from_millis(ms)))
    }

    fn down() -> Option<Answer> {
        Some(Answer::Down("timed out".into()))
    }

    #[test]
    fn races() {
        let t = Instant::now();
        let ms = |n| t + Duration::from_millis(n);
        let no = [false; 3];
        // the LAN answers first: it wins at once
        assert_eq!(decide(&[up(3), None, None], &no, Some(t), t), Some(Ok(0)));
        // the tailnet answered, the LAN hasn't yet: wait out the grace
        assert_eq!(decide(&[None, up(40), None], &no, Some(t), ms(100)), None);
        assert_eq!(
            decide(&[None, up(40), None], &no, Some(t), ms(300)),
            Some(Ok(1))
        );
        // the LAN answered within the grace: it wins over the later one
        assert_eq!(
            decide(&[up(250), up(40), None], &no, Some(t), ms(250)),
            Some(Ok(0))
        );
        // everything before it failed: no need to wait
        assert_eq!(
            decide(&[down(), up(40), None], &no, Some(t), t),
            Some(Ok(1))
        );
        // after the grace the earliest that answered, not the fastest
        assert_eq!(
            decide(&[None, up(90), up(10)], &no, Some(t), ms(301)),
            Some(Ok(1))
        );
        assert_eq!(
            decide(&[down(), down(), down()], &no, None, t),
            Some(Err(()))
        );
        assert_eq!(decide(&[down(), None, down()], &no, None, ms(5000)), None);
    }

    #[test]
    fn proxied_counts_when_its_turn_comes() {
        let t = Instant::now();
        let p = [false, true, false];
        // the first one is still trying: wait for it
        assert_eq!(
            decide(&[None, None, up(1)], &p, Some(t), t + GRACE * 5),
            None
        );
        // it failed: the proxied one is used, never the one after it
        assert_eq!(decide(&[down(), None, up(1)], &p, Some(t), t), Some(Ok(1)));
        assert_eq!(decide(&[up(5), None, None], &p, Some(t), t), Some(Ok(0)));
        assert_eq!(decide(&[None], &[true], None, t), Some(Ok(0)));
    }

    #[test]
    fn knocks() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(matches!(
            knock("127.0.0.1", port, Duration::from_secs(1)),
            Answer::Up(_)
        ));
        drop(l);
        assert_eq!(
            knock("127.0.0.1", port, Duration::from_secs(1)),
            Answer::Down("refused".into())
        );
        assert_eq!(
            knock("no-such-host.invalid", 22, Duration::from_secs(2)),
            Answer::Down("no such host".into())
        );
    }

    #[test]
    fn labels() {
        let c = |h: &str, p| SshConf {
            hostname: h.into(),
            port: p,
            ..Default::default()
        };
        assert_eq!(label("10.1.0.81", &c("10.1.0.81", 22)), "10.1.0.81");
        assert_eq!(label("10.1.0.81", &c("10.1.0.81", 2222)), "10.1.0.81:2222");
        assert_eq!(label("vps", &c("172.16.98.2", 22)), "vps (172.16.98.2:22)");
    }
}
