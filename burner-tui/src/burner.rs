//! everything that runs the burner binary or reads what it prints

use std::collections::HashMap;
use std::process::{Command, Stdio};

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq)]
pub struct Burner {
    pub bin: String,
    pub root: bool,
}

impl Burner {
    pub fn from_env() -> Burner {
        let bin = std::env::var("BURNER")
            .ok()
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| "burner".into());
        // SAFETY: geteuid has no preconditions and can't fail
        let root = unsafe { libc::geteuid() } == 0;
        Burner { bin, root }
    }

    fn with(&self, sudo: &[&str], args: &[String]) -> Vec<String> {
        let mut argv: Vec<String> = Vec::new();
        if !self.root {
            argv.extend(sudo.iter().map(|s| s.to_string()));
        }
        argv.push(self.bin.clone());
        argv.extend(args.iter().cloned());
        argv
    }

    /// for commands run behind the TUI, where sudo has no terminal to ask a password on
    pub fn quiet(&self, args: &[&str]) -> Vec<String> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        self.with(&["sudo", "-n"], &args)
    }

    /// for shell and run, which get the terminal, so sudo can ask
    pub fn interactive(&self, args: &[String]) -> Vec<String> {
        self.with(&["sudo"], args)
    }
}

/// runs argv with no stdin and returns stdout, or the first line of stderr
pub fn output(argv: &[String]) -> Result<String, String> {
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("can't run {}: {e}", argv[0]))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(match err.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(line) => line.to_string(),
        None => envelope_error(&out.stdout)
            .unwrap_or_else(|| format!("{} exited with {}", join(argv), out.status)),
    })
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Vm {
    pub id: String,
    pub tag: String,
    pub img: String,
    pub vcpus: u32,
    pub mem: u32,
    pub net: String,
    pub status: String,
    pub owner: Option<u32>,
    pub age: u64,
    pub ttl: u64,
    pub ttl_left: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Ls {
    pub vms: Vec<Vm>,
    pub max_vms: u32,
    pub total_mem: u32,
    pub used_mem: u32,
}

/// the envelope burner 0.3 and up prints, with ls's result inside
#[derive(Deserialize)]
struct Envelope<T> {
    result: Option<T>,
    #[serde(default)]
    errors: Vec<Problem>,
}

#[derive(Deserialize)]
struct Problem {
    message: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LsResult {
    vms: Vec<VmResult>,
    max_vms: u32,
    total_mem_mib: u32,
    used_mem_mib: u32,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VmResult {
    id: String,
    tag: Option<String>,
    img: String,
    vcpus: u32,
    mem_mib: u32,
    net: String,
    status: String,
    owner: Option<u32>,
    age_secs: u64,
    ttl_secs: u64,
    ttl_left_secs: Option<u64>,
}

/// both shapes: the envelope from burner 0.3 and up, the bare object before
pub fn parse_ls(s: &str) -> Result<Ls, String> {
    let bad = |e: serde_json::Error| format!("can't read burner ls --json: {e}");
    let v: serde_json::Value = serde_json::from_str(s.trim()).map_err(bad)?;
    if v.get("schema").is_none() {
        return serde_json::from_value(v).map_err(bad);
    }
    let env: Envelope<LsResult> = serde_json::from_value(v).map_err(bad)?;
    let Some(r) = env.result else {
        return Err(env
            .errors
            .into_iter()
            .next()
            .map_or("burner ls --json gave no result".into(), |p| p.message));
    };
    Ok(Ls {
        vms: r
            .vms
            .into_iter()
            .map(|v| Vm {
                id: v.id,
                tag: v.tag.unwrap_or_else(|| "-".into()),
                img: v.img,
                vcpus: v.vcpus,
                mem: v.mem_mib,
                net: v.net,
                status: v.status,
                owner: v.owner,
                age: v.age_secs,
                ttl: v.ttl_secs,
                ttl_left: v.ttl_left_secs,
            })
            .collect(),
        max_vms: r.max_vms,
        total_mem: r.total_mem_mib,
        used_mem: r.used_mem_mib,
    })
}

/// the first error in an envelope on stdout, for a burner that failed with --json
fn envelope_error(stdout: &[u8]) -> Option<String> {
    let env: Envelope<serde_json::Value> = serde_json::from_slice(stdout).ok()?;
    env.errors.into_iter().next().map(|p| p.message)
}

/// one name per line, same rule burner uses for image names
pub fn parse_images(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 32
                && n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .map(String::from)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Shell,
    Run,
}

/// what the launcher has filled in. empty fields leave the flag out so
/// burner's own defaults apply
#[derive(Debug, Clone, PartialEq)]
pub struct Launch {
    pub image: String,
    pub net: Option<String>,
    pub cpus: String,
    pub mem: String,
    pub ttl: String,
    pub mode: Mode,
    pub cmd: String,
}

impl Launch {
    /// the arguments after the burner binary
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        a.push(
            match self.mode {
                Mode::Shell => "shell",
                Mode::Run => "run",
            }
            .into(),
        );
        if self.mode == Mode::Run {
            a.extend(["--img".into(), self.image.clone()]);
        }
        let flags = [
            ("--net", self.net.as_deref().unwrap_or("")),
            ("--cpus", self.cpus.as_str()),
            ("--mem", self.mem.as_str()),
            ("--ttl", self.ttl.as_str()),
        ];
        for (flag, v) in flags {
            if !v.is_empty() {
                a.extend([flag.into(), v.to_string()]);
            }
        }
        match self.mode {
            Mode::Shell => a.push(self.image.clone()),
            Mode::Run => a.extend(["--".into(), self.cmd.clone()]),
        }
        a
    }

    /// what's wrong with it before burner gets to say so
    pub fn problem(&self) -> Option<String> {
        for (name, v) in [("cpus", &self.cpus), ("memory", &self.mem)] {
            if !v.is_empty() && v.parse::<u32>().map_or(true, |n| n == 0) {
                return Some(format!("{name} has to be a number above 0"));
            }
        }
        if !self.ttl.is_empty() && !valid_ttl(&self.ttl) {
            return Some("ttl looks like 90s, 10m or 1h".into());
        }
        if self.mode == Mode::Run && self.cmd.trim().is_empty() {
            return Some("type a command to run".into());
        }
        None
    }
}

fn valid_ttl(s: &str) -> bool {
    let num = s.strip_suffix(['s', 'm', 'h']).unwrap_or(s);
    !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit())
}

/// quotes like burner does, so the preview pastes back into a shell as the same argv
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-_./=:,@%".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub fn join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// 45s, 3m05s, 2h10m
pub fn dur(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, secs % 3600 / 60),
    }
}

/// what an exit code from burner means, for the status line
pub fn describe_exit(code: Option<i32>) -> String {
    match code {
        None => "ended by a signal".into(),
        Some(124) => "exit 124, hit the time limit".into(),
        Some(125) => "exit 125, the sandbox failed".into(),
        Some(130) => "exit 130, interrupted".into(),
        Some(c) => format!("exit {c}"),
    }
}

/// uid -> name from /etc/passwd, for the owner column
pub fn users(passwd: &str) -> HashMap<u32, String> {
    passwd
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch() -> Launch {
        Launch {
            image: "alpine".into(),
            net: None,
            cpus: String::new(),
            mem: String::new(),
            ttl: String::new(),
            mode: Mode::Shell,
            cmd: String::new(),
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn ls_parses_what_burner_prints() {
        let out = r#"{"max_vms":2,"total_mem":3072,"used_mem":1024,"vms":[
            {"id":"burner-0123456789ab","tag":"ci","img":"alpine","vcpus":2,"mem":512,"disk":2,
             "net":"web","status":"running","owner":1000,"age":75,"ttl":600,"ttl_left":525},
            {"id":"burner-ba9876543210","tag":"","img":"node","vcpus":1,"mem":512,"disk":2,
             "net":"none","status":"preparing","owner":null,"age":1,"ttl":600,"ttl_left":null}]}
"#;
        let ls = parse_ls(out).unwrap();
        assert_eq!((ls.max_vms, ls.total_mem, ls.used_mem), (2, 3072, 1024));
        assert_eq!(ls.vms.len(), 2);
        assert_eq!(ls.vms[0].id, "burner-0123456789ab");
        assert_eq!(ls.vms[0].owner, Some(1000));
        assert_eq!(ls.vms[0].ttl_left, Some(525));
        assert_eq!(ls.vms[1].owner, None);
        assert_eq!(ls.vms[1].ttl_left, None);
        assert_eq!(ls.vms[1].status, "preparing");
    }

    #[test]
    fn ls_empty_and_missing_fields() {
        let ls = parse_ls(r#"{"max_vms":2,"total_mem":3072,"used_mem":0,"vms":[]}"#).unwrap();
        assert!(ls.vms.is_empty());
        // an older or newer burner may leave fields out or add some
        let ls = parse_ls(r#"{"vms":[{"id":"burner-0123456789ab","new":1}]}"#).unwrap();
        assert_eq!(ls.vms[0].img, "");
        assert_eq!(ls.max_vms, 0);
    }

    #[test]
    fn ls_reads_the_envelope() {
        let out = r#"{"schema":1,"burner":"0.3.0","command":"ls","host":null,"exit":0,"ok":true,
            "result":{"vms":[{"id":"burner-0123456789ab","tag":null,"img":"alpine","vcpus":1,"mem_mib":512,
             "disk_gib":2,"net":"web","status":"running","owner":1000,"started_unix":1795000000,"age_secs":42,
             "ttl_secs":600,"ttl_left_secs":558}],"max_vms":2,"total_mem_mib":3072,"used_mem_mib":512},
            "errors":[],"warnings":[]}"#;
        let ls = parse_ls(out).unwrap();
        assert_eq!((ls.max_vms, ls.total_mem, ls.used_mem), (2, 3072, 512));
        let v = &ls.vms[0];
        assert_eq!((v.tag.as_str(), v.mem, v.age, v.ttl), ("-", 512, 42, 600));
        assert_eq!((v.owner, v.ttl_left), (Some(1000), Some(558)));
        let failed = r#"{"schema":1,"burner":"0.3.0","command":"ls","host":null,"exit":1,"ok":false,
            "result":null,"errors":[{"kind":"io","message":"ledger unreadable"}],"warnings":[]}"#;
        assert_eq!(parse_ls(failed).unwrap_err(), "ledger unreadable");
        assert_eq!(
            envelope_error(failed.as_bytes()).as_deref(),
            Some("ledger unreadable")
        );
    }

    #[test]
    fn ls_garbage_is_an_error() {
        assert!(parse_ls("").is_err());
        assert!(parse_ls("no VMs running").is_err());
        assert!(parse_ls(r#"{"vms":3}"#).is_err());
    }

    #[test]
    fn images_skip_junk() {
        assert_eq!(
            parse_images("alpine\n\n  node-22 \nBad\n../x\n"),
            s(&["alpine", "node-22"])
        );
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("alpine"), "alpine");
        assert_eq!(sh_quote("--mem"), "--mem");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("uname -a"), "'uname -a'");
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
        assert_eq!(sh_quote("$HOME"), "'$HOME'");
        assert_eq!(sh_quote("a;b"), "'a;b'");
    }

    #[test]
    fn shell_with_defaults_only_names_the_image() {
        let b = Burner {
            bin: "burner".into(),
            root: false,
        };
        assert_eq!(
            join(&b.interactive(&launch().args())),
            "sudo burner shell alpine"
        );
    }

    #[test]
    fn shell_with_everything() {
        let l = Launch {
            image: "node".into(),
            net: Some("open".into()),
            cpus: "2".into(),
            mem: "1024".into(),
            ttl: "30m".into(),
            ..launch()
        };
        assert_eq!(
            l.args(),
            s(&[
                "shell", "--net", "open", "--cpus", "2", "--mem", "1024", "--ttl", "30m", "node"
            ])
        );
        assert_eq!(l.problem(), None);
    }

    #[test]
    fn run_keeps_the_command_as_one_argument() {
        let l = Launch {
            mode: Mode::Run,
            net: Some("web".into()),
            cmd: "echo 'hi there'; exit 3".into(),
            ..launch()
        };
        let b = Burner {
            bin: "/opt/burner/bin/burner".into(),
            root: false,
        };
        let argv = b.interactive(&l.args());
        assert_eq!(argv.last().unwrap(), "echo 'hi there'; exit 3");
        assert_eq!(
            join(&argv),
            r"sudo /opt/burner/bin/burner run --img alpine --net web -- 'echo '\''hi there'\''; exit 3'"
        );
    }

    #[test]
    fn root_skips_sudo() {
        let b = Burner {
            bin: "burner".into(),
            root: true,
        };
        assert_eq!(b.quiet(&["ls", "--json"]), s(&["burner", "ls", "--json"]));
        assert_eq!(b.interactive(&s(&["shell"])), s(&["burner", "shell"]));
        let b = Burner { root: false, ..b };
        assert_eq!(
            b.quiet(&["kill", "burner-0123456789ab"]),
            s(&["sudo", "-n", "burner", "kill", "burner-0123456789ab"])
        );
    }

    #[test]
    fn problems() {
        let bad = |f: fn(&mut Launch)| {
            let mut l = launch();
            f(&mut l);
            l.problem()
        };
        assert!(bad(|l| l.cpus = "0".into()).is_some());
        assert!(bad(|l| l.mem = "lots".into()).is_some());
        assert!(bad(|l| l.ttl = "10x".into()).is_some());
        assert!(bad(|l| l.ttl = "m".into()).is_some());
        assert!(bad(|l| l.mode = Mode::Run).is_some());
        assert!(bad(|l| l.ttl = "90s".into()).is_none());
        assert!(bad(|l| l.ttl = "600".into()).is_none());
    }

    #[test]
    fn durations() {
        assert_eq!(dur(0), "0s");
        assert_eq!(dur(59), "59s");
        assert_eq!(dur(65), "1m05s");
        assert_eq!(dur(3600), "1h00m");
        assert_eq!(dur(7830), "2h10m");
    }

    #[test]
    fn passwd() {
        let u = users(
            "root:x:0:0:root:/root:/bin/bash\n# comment\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        );
        assert_eq!(u.get(&0).map(String::as_str), Some("root"));
        assert_eq!(u.get(&1000).map(String::as_str), Some("alice"));
        assert_eq!(u.len(), 2);
    }
}
