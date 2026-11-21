//! the ssh command line. the same fixed options every time: no forwarding of
//! any kind, ssh's own ~ escape off, and host keys checked strictly and never
//! written. everything else (keys, agent, ProxyJump, user, port) is your ssh
//! config's

use std::ffi::OsString;

use super::hosts::Host;
use super::quote;

/// the wrapper that runs on the far end, see wrap.sh
pub const WRAP: &str = include_str!("wrap.sh");

/// BURNER_SSH picks another ssh program (a wrapper with -F, for tests). the
/// default is the ssh on your PATH, like any ssh wrapper
pub fn program() -> OsString {
    std::env::var_os("BURNER_SSH")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh".into())
}

/// how burner should be started there
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// through sudo -n on linux unless ssh'd as root, as you on a mac
    Auto,
    /// never through sudo (config needs no root)
    User,
    /// Auto, and say what the sudo rule allows
    Doctor,
}

impl Mode {
    fn word(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::User => "user",
            Mode::Doctor => "doctor",
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Opts {
    /// -tt: a shell, whose stdin is a terminal here
    pub tty: bool,
    /// -n: ssh doesn't read stdin, so a loop reading lines keeps them
    pub no_stdin: bool,
    /// BatchMode: never prompt (the tui's background calls, doctor's probe)
    pub batch: bool,
    /// add ServerAlive*, when the ssh config has none
    pub alive: bool,
}

/// burner's argv on the far end, wrapped: `sh -c WRAP burner-remote NONCE
/// BURNER MODE ARG...`, every word quoted for any login shell
pub fn remote_line(nonce: &str, burner: Option<&str>, mode: Mode, args: &[String]) -> String {
    let mut words: Vec<&str> = vec![
        "sh",
        "-c",
        WRAP,
        "burner-remote",
        nonce,
        burner.unwrap_or(""),
        mode.word(),
    ];
    words.extend(args.iter().map(String::as_str));
    quote::line(&words)
}

/// ssh's argv after the program name
pub fn argv(host: &Host, addr: &str, connect_secs: u64, o: Opts, line: &str) -> Vec<String> {
    let mut a: Vec<String> = ["-a", "-x", "-e", "none"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut opt = |s: String| {
        a.push("-o".into());
        a.push(s);
    };
    // ClearAllForwardings also drops what -L/-R/-D lines in ssh config ask for
    opt("ClearAllForwardings=yes".into());
    opt("RemoteCommand=none".into());
    opt("PermitLocalCommand=no".into());
    // a host key ssh doesn't know, or one that changed, is a refusal. never a
    // prompt to accept it, never a line added to known_hosts
    opt("StrictHostKeyChecking=yes".into());
    opt("UpdateHostKeys=no".into());
    opt(format!("ConnectTimeout={}", connect_secs.max(1)));
    // no "Connection to x closed." in a run's stderr
    opt("LogLevel=ERROR".into());
    if o.alive {
        opt("ServerAliveInterval=15".into());
        opt("ServerAliveCountMax=4".into());
    }
    if o.batch {
        opt("BatchMode=yes".into());
    }
    if let Some(u) = &host.user {
        a.push("-l".into());
        a.push(u.clone());
    }
    if let Some(p) = host.port {
        a.push("-p".into());
        a.push(p.to_string());
    }
    a.push(if o.tty { "-tt" } else { "-T" }.into());
    if o.no_stdin {
        a.push("-n".into());
    }
    // ssh uses getopt: nothing after -- is an option, whatever it looks like
    a.push("--".into());
    a.push(addr.into());
    a.push(line.into());
    a
}

/// `ssh -G`: what ssh would use for an address, without connecting
pub fn config_argv(host: &Host, addr: &str) -> Vec<String> {
    let mut a = vec!["-G".to_string()];
    if let Some(u) = &host.user {
        a.push("-l".into());
        a.push(u.clone());
    }
    if let Some(p) = host.port {
        a.push("-p".into());
        a.push(p.to_string());
    }
    a.push("--".into());
    a.push(addr.into());
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn host(user: Option<&str>, port: Option<u16>) -> Host {
        Host {
            name: "vps".into(),
            addrs: vec!["vps".into()],
            user: user.map(str::to_string),
            port,
            timeout: Duration::from_secs(3),
            burner: None,
            configured: true,
            known: vec![],
        }
    }

    const FIXED: &str = "-a -x -e none -o ClearAllForwardings=yes -o RemoteCommand=none \
        -o PermitLocalCommand=no -o StrictHostKeyChecking=yes -o UpdateHostKeys=no \
        -o ConnectTimeout=3 -o LogLevel=ERROR";

    #[test]
    fn golden_argv() {
        let run = argv(
            &host(None, None),
            "vps",
            3,
            Opts {
                alive: true,
                ..Default::default()
            },
            "L",
        );
        assert_eq!(
            run.join(" "),
            format!("{FIXED} -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -T -- vps L")
        );
        let shell = argv(
            &host(Some("patrick"), Some(2222)),
            "10.1.0.81",
            2,
            Opts {
                tty: true,
                ..Default::default()
            },
            "L",
        );
        assert_eq!(
            shell.join(" "),
            FIXED.replace("ConnectTimeout=3", "ConnectTimeout=2")
                + " -l patrick -p 2222 -tt -- 10.1.0.81 L"
        );
        let ls = argv(
            &host(None, None),
            "vps",
            3,
            Opts {
                no_stdin: true,
                batch: true,
                ..Default::default()
            },
            "L",
        );
        assert_eq!(
            ls.join(" "),
            format!("{FIXED} -o BatchMode=yes -T -n -- vps L")
        );
        // the line stays one argument whatever is in it
        let l = argv(&host(None, None), "vps", 3, Opts::default(), "a b; c");
        assert_eq!(l.last().map(String::as_str), Some("a b; c"));
        assert_eq!(
            config_argv(&host(Some("p"), Some(22)), "x").join(" "),
            "-G -l p -p 22 -- x"
        );
    }

    #[test]
    fn wrapper_travels_in_single_quotes() {
        assert!(!WRAP.contains('\'') && !WRAP.contains('\\'));
        let l = remote_line(&"a".repeat(32), None, Mode::Auto, &["ls".into()]);
        assert!(l.starts_with("sh -c '# shellcheck shell=sh\n# burner -H"));
        assert!(l.ends_with(&format!("' burner-remote {} '' auto ls", "a".repeat(32))));
    }

    /// the wrapper, run here by sh with a stand-in burner
    fn wrap(burner: &std::path::Path, mode: &str, args: &[&str]) -> (String, String, i32) {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(WRAP)
            .arg("burner-remote")
            .arg("f".repeat(32))
            .arg(burner)
            .arg(mode)
            .args(args)
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    #[test]
    fn wrapper_runs() {
        let d = std::env::temp_dir().join(format!(
            "burner-wrap-{}",
            crate::sys::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&d).unwrap();
        let fake = d.join("burner");
        std::fs::write(
            &fake,
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo burnervm 9.9.9; exit 0; fi\nprintf '%s|' \"$@\"\nexit 7\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let n = "f".repeat(32);
        let (out, err, code) = wrap(&fake, "user", &["ls", "a b", "--json"]);
        assert_eq!((out.as_str(), code), ("ls|a b|--json|", 7));
        let os = if cfg!(target_os = "macos") {
            "Darwin"
        } else {
            "Linux"
        };
        // SAFETY: getuid can't fail
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            err,
            format!("burner-{n} wrap {os} {uid} direct burnervm 9.9.9\n")
        );
        let (_, err, code) = wrap(&d.join("nope"), "auto", &["ls"]);
        assert_eq!(
            (err, code),
            (
                format!("burner-{n} nobin {}\n", d.join("nope").display()),
                125
            )
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}
