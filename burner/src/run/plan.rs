use std::fs;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, ValueEnum};
use serde::Deserialize;

#[cfg(target_os = "linux")]
use super::admin::reaper_alive;
use super::launch::main;
use super::{EXIT_SANDBOX, EXIT_USAGE, Exit, usage};
use crate::config::Config;
use crate::net;
use crate::sys;

const CMD_CAP: usize = 64 << 10;

#[derive(Args)]
pub struct RunArgs {
    /// image to boot (burner images lists them)
    #[arg(long, default_value = "alpine")]
    img: String,
    #[arg(long)]
    cpus: Option<u32>,
    /// memory in MiB
    #[arg(long)]
    mem: Option<u32>,
    /// scratch disk in GiB
    #[arg(long)]
    disk: Option<u32>,
    /// time limit: 90s, 10m, 1h
    #[arg(long)]
    ttl: Option<String>,
    /// what to do with stdin: ignore it, feed it to the command, or unpack it as a tar into /work
    #[arg(long = "in", value_enum, default_value_t = Input::None)]
    pub(super) input: Input,
    /// stdout becomes a tar of the VM's /out, rc and log.txt; the command's output goes to stderr
    #[arg(long, value_enum)]
    pub(super) result: Option<ResultMode>,
    /// a label for burner ls
    #[arg(long)]
    tag: Option<String>,
    /// network: none, web (http/https, dns, ping) or open (any port but mail). never the LAN
    #[arg(long, default_value = "none")]
    net: String,
    /// write one JSON line to this fd when done: how the run ended, the guest's
    /// exit code if it has one, the VM id. for wrappers that need to tell a
    /// timeout from a command that exited 124 itself. sudo closes fds above 2,
    /// so through sudo use 2: the line is then the last thing on stderr
    #[arg(long, value_name = "FD")]
    pub(super) status_fd: Option<i32>,
    /// fail right away instead of queueing when every slot is taken
    #[arg(long)]
    no_wait: bool,
    /// one argument runs as a shell string; several are quoted as they are
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
    #[arg(skip)]
    pub(super) shell: bool,
    /// --net wasn't given: lower it to limits.net instead of refusing
    #[arg(skip)]
    net_default: bool,
}

#[derive(Args)]
pub struct ShellArgs {
    /// image to boot (burner images lists them), default alpine
    spec: Option<String>,
    #[arg(long)]
    cpus: Option<u32>,
    /// memory in MiB
    #[arg(long)]
    mem: Option<u32>,
    /// scratch disk in GiB
    #[arg(long)]
    disk: Option<u32>,
    /// time limit: 30m, 1h
    #[arg(long)]
    ttl: Option<String>,
    /// network: none, web or open (default web, or less if the config says so)
    #[arg(long)]
    net: Option<String>,
    #[arg(long)]
    tag: Option<String>,
}

pub fn shell_main(cfg: &Config, a: ShellArgs) -> ExitCode {
    if !(sys::is_tty(0) && sys::is_tty(1)) {
        eprintln!("burner: burner shell needs a terminal (over ssh: ssh -t)");
        return ExitCode::from(EXIT_USAGE);
    }
    let img = a.spec.unwrap_or_else(|| "alpine".into());
    let ra = RunArgs {
        img,
        cpus: a.cpus,
        mem: a.mem,
        disk: a.disk,
        ttl: a.ttl,
        input: Input::None,
        result: None,
        tag: a.tag,
        net_default: a.net.is_none(),
        status_fd: None,
        no_wait: false,
        net: a.net.unwrap_or_else(|| "web".into()),
        cmd: vec!["true".into()],
        shell: true,
    };
    main(cfg, ra)
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(super) enum Input {
    None,
    Stdin,
    Tar,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(super) enum ResultMode {
    Tar,
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ImageDefaults {
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_gib: Option<u32>,
    ttl_secs: Option<u32>,
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn images(cfg: &Config) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(cfg.paths.root.join("images"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            valid_name(n)
                && cfg
                    .paths
                    .root
                    .join("images")
                    .join(n)
                    .join("rootfs.ext4")
                    .is_file()
        })
        .collect();
    names.sort();
    names
}

/// an image without a defaults.toml uses the config's. one that doesn't parse
/// is an error, like the config: a typo shouldn't quietly mean other limits
fn image_defaults(cfg: &Config, img: &str) -> Result<ImageDefaults> {
    let path = cfg
        .paths
        .root
        .join("images")
        .join(img)
        .join("defaults.toml");
    match fs::read_to_string(&path) {
        Ok(t) => toml::from_str(&t)
            .map_err(|e| Exit(EXIT_SANDBOX, format!("{}: {}", path.display(), e.message())).into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImageDefaults::default()),
        Err(e) => Err(Exit(EXIT_SANDBOX, format!("{}: {e}", path.display())).into()),
    }
}

pub fn parse_ttl(s: &str, max: u32) -> Result<u32> {
    let (num, mult) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let n: u32 = num
        .parse()
        .map_err(|_| usage(format!("bad --ttl {s:?} (use 90s, 10m, 1h)")))?;
    let secs = n.saturating_mul(mult);
    if !(10..=max).contains(&secs) {
        return Err(usage(format!(
            "--ttl must be between 10s and {}m",
            max / 60
        )));
    }
    Ok(secs)
}

/// the command as one sh string: one arg as-is, several quoted
fn command_string(args: &[String]) -> String {
    if args.len() == 1 {
        return args[0].clone();
    }
    args.iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-_./=:,@%".contains(&b))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub(super) struct Plan {
    pub(super) img: String,
    pub(super) vcpus: u32,
    pub(super) mem_mib: u32,
    pub(super) disk_gib: u32,
    pub(super) ttl: u32,
    pub(super) tag: String,
    pub(super) cmd: String,
    pub(super) net: net::Mode,
    pub(super) shell: bool,
    pub(super) no_wait: bool,
}

pub(super) fn plan(cfg: &Config, a: &RunArgs) -> Result<Plan> {
    if !valid_name(&a.img) || !images(cfg).contains(&a.img) {
        return Err(usage(format!("unknown image {:?} (burner images)", a.img)));
    }
    let d = image_defaults(cfg, &a.img)?;
    let l = &cfg.limits;
    let pick = |flag: &str,
                given: Option<u32>,
                def: Option<u32>,
                fallback: u32,
                lo: u32,
                hi: u32|
     -> Result<u32> {
        let v = given.or(def).unwrap_or(fallback);
        if given.is_some() && !(lo..=hi).contains(&v) {
            return Err(usage(format!("--{flag} must be between {lo} and {hi}")));
        }
        Ok(v.clamp(lo, hi))
    };
    let vcpus = pick("cpus", a.cpus, d.vcpus, 1, 1, l.vcpus)?;
    let mem_mib = pick("mem", a.mem, d.mem_mib, 512, 128, l.mem_mib)?;
    let disk_gib = pick("disk", a.disk, d.disk_gib, 2, 1, l.disk_gib)?;
    let max_ttl = if a.shell {
        l.ttl_shell_secs
    } else {
        l.ttl_secs
    };
    let ttl = match &a.ttl {
        Some(t) => parse_ttl(t, max_ttl)?,
        None if a.shell => 3600.min(max_ttl),
        None => d.ttl_secs.unwrap_or(600).clamp(10, max_ttl),
    };
    let mut net = net::Mode::parse(&a.net)
        .ok_or_else(|| usage(format!("--net {:?}: use none, web or open", a.net)))?;
    let ceiling = net::Mode::parse(&cfg.limits.net).unwrap_or(net::Mode::None);
    if net > ceiling {
        if !a.net_default {
            return Err(usage(format!(
                "--net {} is more than this machine allows (limits.net = {})",
                a.net, cfg.limits.net
            )));
        }
        net = ceiling;
    }
    if net != net::Mode::None {
        // no filter to keep current on macOS: macnet reads the host's
        // addresses and routes for every connection itself
        #[cfg(target_os = "linux")]
        reaper_alive(cfg)?;
        #[cfg(target_os = "linux")]
        let logs = "journalctl -t burner";
        #[cfg(target_os = "macos")]
        let logs = "log show --predicate 'process == \"burner\"'";
        if cfg.net.block_public_ip && net::public_ip(cfg).is_none() {
            return Err(Exit(
                EXIT_SANDBOX,
                format!(
                    "net.block_public_ip is on but no public address has been found yet \
                     ({logs}), refusing a VM with a network. --net none still works"
                ),
            )
            .into());
        }
    }
    let tag = a.tag.clone().unwrap_or_else(|| "-".into());
    if tag != "-" && !valid_name(&tag) {
        return Err(usage(
            "--tag must be lowercase letters, digits and dashes, max 32",
        ));
    }
    let cmd = command_string(&a.cmd);
    if cmd.trim().is_empty() {
        return Err(usage("no command given (burner run [opts] -- COMMAND)"));
    }
    if cmd.len() > CMD_CAP || cmd.contains('\0') {
        return Err(usage("command too long or contains NUL"));
    }
    if a.input != Input::None && sys::is_tty(0) {
        return Err(usage("--in stdin and --in tar need piped input"));
    }
    if a.result.is_some() && sys::is_tty(1) {
        return Err(usage(
            "--result tar writes a tar to stdout, redirect it to a file",
        ));
    }
    Ok(Plan {
        img: a.img.clone(),
        vcpus,
        mem_mib,
        disk_gib,
        ttl,
        tag,
        cmd,
        net,
        shell: a.shell,
        no_wait: a.no_wait,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl() {
        assert_eq!(parse_ttl("90s", 1800).unwrap(), 90);
        assert_eq!(parse_ttl("10m", 1800).unwrap(), 600);
        assert_eq!(parse_ttl("45", 1800).unwrap(), 45);
        assert!(parse_ttl("1h", 1800).is_err());
        assert!(parse_ttl("5s", 1800).is_err());
        assert!(parse_ttl("x", 1800).is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(
            command_string(&["make && make test".into()]),
            "make && make test"
        );
        assert_eq!(
            command_string(&["printf".into(), "%s\n".into(), "a b".into()]),
            "printf '%s\n' 'a b'"
        );
        assert_eq!(sh_quote("it's"), r"'it'\''s'");
    }
}
