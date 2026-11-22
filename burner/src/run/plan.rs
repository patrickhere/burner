use std::fs;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use super::admin::reaper_alive;
use super::launch::{main, refuse};
use super::{EXIT_SANDBOX, EXIT_USAGE, exit, usage};
use crate::config::Config;
use crate::json::{self, Kind};
use crate::net;
use crate::sys;

const CMD_CAP: usize = 64 << 10;

#[derive(Args, Clone)]
pub struct RunArgs {
    /// image to boot (burner images lists them)
    #[arg(long, default_value = "alpine")]
    img: String,
    /// virtual CPUs (default the image's, else 1; at most limits.vcpus)
    #[arg(long)]
    cpus: Option<u32>,
    /// memory: 512M, 2G, or a number of MiB
    #[arg(long, value_name = "SIZE", value_parser = mem_size)]
    mem: Option<u32>,
    /// scratch disk: 4G, or a number of GiB
    #[arg(long, value_name = "SIZE", value_parser = disk_size)]
    disk: Option<u32>,
    /// time limit: 90s, 10m, 1h. the command is stopped a little before it (a
    /// quarter of it, 5s to 30s), so its output and /out still get saved
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
    /// network: none (the default), web (http/https, dns, ping) or open (any
    /// port but mail). never the LAN
    #[arg(long)]
    net: Option<String>,
    /// the older one-line form of --json-fd: outcome, rc, exit, id and secs
    #[arg(long, value_name = "FD")]
    pub(super) status_fd: Option<i32>,
    /// write the json result (docs/json.md) to this fd when done, and leave
    /// stdout and stderr as they are. sudo closes fds above 2, so through sudo
    /// use 2: the json is then the last line on stderr
    #[arg(long, value_name = "FD")]
    pub(super) json_fd: Option<i32>,
    /// mark the json with this nonce, so a line the guest wrote can't pass
    /// for it
    #[arg(long, value_name = "NONCE")]
    json_mark: Option<String>,
    /// the connection log after a run with a network, on stderr: a summary,
    /// the full table, or nothing. it's kept either way (burner log)
    #[arg(long, value_enum, default_value_t = LogMode::Summary)]
    pub(super) log: LogMode,
    /// fail right away instead of queueing when every slot is taken
    #[arg(long)]
    no_wait: bool,
    /// how long to queue for a slot: 30s, 5m [default: 10m]
    #[arg(long, value_name = "TIME", conflicts_with = "no_wait")]
    wait: Option<String>,
    /// burner -H on the far end of ssh: how it ended goes to stderr as a
    /// marked line, and a closed stdout or stderr stops the run
    #[arg(long, hide = true, value_name = "PROTO:NONCE", value_parser = remote_nonce)]
    pub(super) remote: Option<String>,
    /// one argument runs as a shell string; several are quoted as they are
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
    #[arg(skip)]
    pub(super) shell: bool,
}

#[derive(Args)]
pub struct ShellArgs {
    /// image to boot (burner images lists them), default alpine
    spec: Option<String>,
    /// the image, as run takes it
    #[arg(long, conflicts_with = "spec")]
    img: Option<String>,
    /// virtual CPUs (default the image's, else 1; at most limits.vcpus)
    #[arg(long)]
    cpus: Option<u32>,
    /// memory: 512M, 2G, or a number of MiB
    #[arg(long, value_name = "SIZE", value_parser = mem_size)]
    mem: Option<u32>,
    /// scratch disk: 4G, or a number of GiB
    #[arg(long, value_name = "SIZE", value_parser = disk_size)]
    disk: Option<u32>,
    /// time limit: 30m, 1h. a shell isn't stopped early like a run, it closes
    /// at the limit
    #[arg(long)]
    ttl: Option<String>,
    /// network: none, web or open (default web, or less if the config says so)
    #[arg(long)]
    net: Option<String>,
    /// a label for burner ls
    #[arg(long)]
    tag: Option<String>,
    /// write the json result (docs/json.md) to this fd when the shell ends.
    /// through sudo use 2
    #[arg(long, value_name = "FD")]
    json_fd: Option<i32>,
    /// mark the json with this nonce, see run
    #[arg(long, value_name = "NONCE")]
    json_mark: Option<String>,
    /// how long to queue for a slot: 30s, 5m [default: 10m]
    #[arg(long, value_name = "TIME")]
    wait: Option<String>,
    /// the connection log when the shell ends: a summary, the full table, or nothing
    #[arg(long, value_enum, default_value_t = LogMode::Summary)]
    log: LogMode,
    /// burner -H on the far end of ssh, see run. the ~ escape is the client's
    #[arg(long, hide = true, value_name = "PROTO:NONCE", value_parser = remote_nonce)]
    remote: Option<String>,
}

/// the remote protocol this burner speaks
pub const REMOTE_PROTO: u32 = 1;

/// `1:` and 32 lowercase hex digits. a client asking for a protocol this
/// burner doesn't know is refused before anything starts
fn remote_nonce(s: &str) -> Result<String, String> {
    let (proto, nonce) = s.split_once(':').unwrap_or(("", s));
    if proto != REMOTE_PROTO.to_string() {
        return Err(format!(
            "this burner ({}) speaks remote protocol {REMOTE_PROTO}, the caller asked for {}",
            env!("CARGO_PKG_VERSION"),
            if proto.is_empty() { "none" } else { proto }
        ));
    }
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("the nonce is 32 lowercase hex digits".into());
    }
    Ok(nonce.into())
}

impl RunArgs {
    /// started by burner -H on the far end of ssh
    pub fn is_remote(&self) -> bool {
        self.remote.is_some()
    }

    pub fn is_shell(&self) -> bool {
        self.shell
    }

    /// stdin is the run's (--in stdin or tar)
    pub fn reads_stdin(&self) -> bool {
        self.input != Input::None
    }

    pub fn result_tar(&self) -> bool {
        self.result.is_some()
    }

    pub fn status_fd(&self) -> Option<i32> {
        self.status_fd
    }

    pub fn img(&self) -> &str {
        &self.img
    }

    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// --net as given, before limits.net lowers a default
    pub fn net(&self) -> &str {
        self.net
            .as_deref()
            .unwrap_or(if self.shell { "web" } else { "none" })
    }

    /// --net wasn't given: a shell's default is lowered to limits.net
    /// instead of refused, and a run that fails says it had no network
    pub(super) fn net_default(&self) -> bool {
        self.net.is_none()
    }

    /// the command as the VM's sh gets it, empty for a shell
    pub fn command(&self) -> String {
        if self.shell {
            return String::new();
        }
        command_string(&self.cmd)
    }

    /// a flag that parses but isn't built yet
    pub(super) fn unbuilt(&self) -> Option<&'static str> {
        if self.json_mark.is_some() {
            Some("--json-mark")
        } else if self.wait.is_some() {
            Some("--wait")
        } else {
            None
        }
    }

    /// what burner -H checks here before it connects: everything that needs
    /// no config. the image, the limits and limits.net are the far end's call
    pub fn check_local(&self) -> std::result::Result<(), String> {
        if let Some(t) = &self.ttl {
            parse_ttl(t, u32::MAX).map_err(|e| e.to_string())?;
        }
        if net::Mode::parse(self.net()).is_none() {
            return Err(format!("--net {:?}: use none, web or open", self.net()));
        }
        if !valid_name(&self.img) {
            return Err(format!("unknown image {:?} (burner images)", self.img));
        }
        if let Some(t) = &self.tag
            && !valid_name(t)
        {
            return Err("--tag must be lowercase letters, digits and dashes, max 32".into());
        }
        let cmd = command_string(&self.cmd);
        if cmd.trim().is_empty() {
            return Err("no command given (burner run [opts] -- COMMAND)".into());
        }
        if cmd.len() > CMD_CAP || cmd.contains('\0') {
            return Err("command too long or contains NUL".into());
        }
        if self.input != Input::None && sys::is_tty(0) {
            return Err("--in stdin and --in tar need piped input".into());
        }
        if self.result.is_some() && sys::is_tty(1) {
            return Err("--result tar writes a tar to stdout, redirect it to a file".into());
        }
        Ok(())
    }

    /// burner's argv on the far end, rebuilt from what was parsed: only flags
    /// burner knows, each value one argument, the command after --. never
    /// -H, --status-fd or --json-fd, those are the client's
    pub fn remote_argv(&self, nonce: &str, json: bool) -> Vec<String> {
        let mut v: Vec<String> = vec![
            if self.shell { "shell" } else { "run" }.into(),
            "--remote".into(),
            format!("{REMOTE_PROTO}:{nonce}"),
        ];
        let mut opt = |k: &str, val: Option<String>| {
            if let Some(val) = val {
                v.push(format!("--{k}"));
                v.push(val);
            }
        };
        opt("cpus", self.cpus.map(|n| n.to_string()));
        opt("mem", self.mem.map(|n| n.to_string()));
        opt("disk", self.disk.map(|n| n.to_string()));
        opt("ttl", self.ttl.clone());
        opt("tag", self.tag.clone());
        // only when given: the far end's default is the same
        opt("net", self.net.clone());
        // the summary is printed there, on the stderr that comes back here
        opt(
            "log",
            match self.log {
                LogMode::Summary => None,
                LogMode::None => Some("none".into()),
                LogMode::Full => Some("full".into()),
            },
        );
        if self.shell {
            v.push(self.img.clone());
            return v;
        }
        opt("img", Some(self.img.clone()));
        opt(
            "in",
            match self.input {
                Input::None => None,
                Input::Stdin => Some("stdin".into()),
                Input::Tar => Some("tar".into()),
            },
        );
        opt("result", self.result.map(|_| "tar".into()));
        if self.no_wait {
            v.push("--no-wait".into());
        }
        if json {
            v.push("--json".into());
        }
        v.push("--".into());
        v.extend(self.cmd.iter().cloned());
        v
    }
}

impl ShellArgs {
    pub fn is_remote(&self) -> bool {
        self.remote.is_some()
    }
}

/// a shell is a run with the caller's terminal and no command
pub fn shell_run_args(a: &ShellArgs) -> RunArgs {
    RunArgs {
        img: a
            .img
            .clone()
            .or_else(|| a.spec.clone())
            .unwrap_or_else(|| "alpine".into()),
        cpus: a.cpus,
        mem: a.mem,
        disk: a.disk,
        ttl: a.ttl.clone(),
        input: Input::None,
        result: None,
        tag: a.tag.clone(),
        status_fd: None,
        json_fd: a.json_fd,
        log: a.log,
        no_wait: false,
        json_mark: a.json_mark.clone(),
        wait: a.wait.clone(),
        remote: a.remote.clone(),
        net: a.net.clone(),
        cmd: vec!["true".into()],
        shell: true,
    }
}

pub fn shell_main(cfg: &Config, a: &RunArgs) -> ExitCode {
    if !(sys::is_tty(0) && sys::is_tty(1)) {
        return refuse(
            a,
            Kind::NoTty,
            "burner shell needs a terminal (over ssh: ssh -t)".into(),
        );
    }
    main(cfg, a)
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(super) enum Input {
    None,
    Stdin,
    Tar,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(super) enum LogMode {
    None,
    Summary,
    Full,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub(super) enum ResultMode {
    Tar,
}

#[derive(Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ImageDefaults {
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

#[derive(Serialize)]
pub struct ImagesResult {
    pub images: Vec<Image>,
}

#[derive(Serialize)]
pub struct Image {
    pub name: String,
    pub rootfs_bytes: u64,
    /// built with the guest init this burner has
    pub init_matches: bool,
    /// from its defaults.toml, null when that doesn't parse
    pub defaults: Option<ImageDefaults>,
}

pub fn images_result(cfg: &Config) -> ImagesResult {
    let dir = cfg.paths.root.join("images");
    let images = images(cfg)
        .into_iter()
        .map(|name| {
            let d = dir.join(&name);
            let defaults = match image_defaults(cfg, &name) {
                Ok(d) => Some(d),
                Err(e) => {
                    json::warn(Kind::Image, format!("{e:#}"));
                    None
                }
            };
            Image {
                rootfs_bytes: fs::metadata(d.join("rootfs.ext4")).map_or(0, |m| m.len()),
                init_matches: fs::read(d.join("init")).ok().as_deref()
                    == Some(crate::doctor::GUEST_INIT),
                defaults,
                name,
            }
        })
        .collect();
    ImagesResult { images }
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
        Ok(t) => toml::from_str(&t).map_err(|e| {
            exit(
                EXIT_SANDBOX,
                Kind::Config,
                format!("{}: {}", path.display(), e.message()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImageDefaults::default()),
        Err(e) => Err(exit(
            EXIT_SANDBOX,
            Kind::Config,
            format!("{}: {e}", path.display()),
        )),
    }
}

/// a size: a number, then M or G (MB, MiB, GB and GiB too, any case). None
/// for the number's own unit
fn size_unit(s: &str) -> Result<(u64, Option<u64>), String> {
    let at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(at);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{s:?}: use a size like 512M or 2G"))?;
    let mib = match unit.to_ascii_lowercase().as_str() {
        "" => None,
        "m" | "mb" | "mib" => Some(1),
        "g" | "gb" | "gib" => Some(1024),
        _ => return Err(format!("{s:?}: use a size like 512M or 2G")),
    };
    Ok((n, mib))
}

/// --mem in MiB: 512, 512M, 2G
fn mem_size(s: &str) -> Result<u32, String> {
    let (n, mib) = size_unit(s)?;
    u32::try_from(n.saturating_mul(mib.unwrap_or(1))).map_err(|_| format!("{s:?} is too big"))
}

/// --disk in GiB: 4, 4G, 4096M
fn disk_size(s: &str) -> Result<u32, String> {
    let (n, mib) = size_unit(s)?;
    let mib = n.saturating_mul(mib.unwrap_or(1024));
    if !mib.is_multiple_of(1024) {
        return Err(format!("{s:?}: the disk is whole GiB (4G)"));
    }
    u32::try_from(mib / 1024).map_err(|_| format!("{s:?} is too big"))
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

/// what to say for an image that isn't here: how to get one of the stock
/// images, or where to look for the rest
fn missing_image(img: &str) -> String {
    if !["alpine", "debian"].contains(&img) {
        return format!("unknown image {img:?} (burner images)");
    }
    #[cfg(target_os = "linux")]
    let how = match img {
        "debian" => "tools/build-image debian from burner's source builds it (it needs mmdebstrap)",
        _ => "tools/build-image alpine from burner's source builds it",
    };
    #[cfg(target_os = "macos")]
    let how = format!("burner setup {img} fetches it");
    format!("no {img} image here (burner images): {how}")
}

pub(super) fn plan(cfg: &Config, a: &RunArgs) -> Result<Plan> {
    if !valid_name(&a.img) || !images(cfg).contains(&a.img) {
        return Err(exit(EXIT_USAGE, Kind::UnknownImage, missing_image(&a.img)));
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
    let mut net = net::Mode::parse(a.net())
        .ok_or_else(|| usage(format!("--net {:?}: use none, web or open", a.net())))?;
    let ceiling = net::Mode::parse(&cfg.limits.net).unwrap_or(net::Mode::None);
    if net > ceiling {
        if !a.net_default() {
            return Err(usage(format!(
                "--net {} is more than this machine allows (limits.net = {})",
                a.net(),
                cfg.limits.net
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
            return Err(exit(
                EXIT_SANDBOX,
                Kind::NoPublicIp,
                format!(
                    "net.block_public_ip is on but no public address has been found yet \
                     ({logs}), refusing a VM with a network. --net none still works"
                ),
            ));
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
    fn missing_images_say_how_to_get_them() {
        let d = missing_image("debian");
        #[cfg(target_os = "linux")]
        assert!(d.contains("tools/build-image debian") && d.contains("mmdebstrap"));
        #[cfg(target_os = "macos")]
        assert!(d.contains("burner setup debian"));
        assert!(missing_image("alpine").contains("alpine"));
        assert_eq!(
            missing_image("node"),
            "unknown image \"node\" (burner images)"
        );
    }

    #[test]
    fn images_json() {
        let r = ImagesResult {
            images: vec![Image {
                name: "alpine".into(),
                rootfs_bytes: 268435456,
                init_matches: true,
                defaults: Some(ImageDefaults {
                    mem_mib: Some(512),
                    ..Default::default()
                }),
            }],
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"images":[{"name":"alpine","rootfs_bytes":268435456,"init_matches":true,"defaults":{"vcpus":null,"mem_mib":512,"disk_gib":null,"ttl_secs":null}}]}"#
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(mem_size("512"), Ok(512));
        assert_eq!(mem_size("512M"), Ok(512));
        assert_eq!(mem_size("512mib"), Ok(512));
        assert_eq!(mem_size("2G"), Ok(2048));
        assert_eq!(mem_size("2gb"), Ok(2048));
        assert_eq!(disk_size("4"), Ok(4));
        assert_eq!(disk_size("4G"), Ok(4));
        assert_eq!(disk_size("4096M"), Ok(4));
        assert!(disk_size("500M").is_err(), "not whole GiB");
        for bad in ["", "G", "2T", "1.5G", "-1", " 2G", "2 G", "99999999999G"] {
            assert!(mem_size(bad).is_err() && disk_size(bad).is_err(), "{bad:?}");
        }
        // the far end gets plain MiB and GiB, which 0.3.0 takes too
        let n = "0123456789abcdef0123456789abcdef";
        let a = parse(&["--mem", "2G", "--disk", "4G", "--", "x"]).remote_argv(n, false);
        assert_eq!(a[3..7], ["--mem", "2048", "--disk", "4"]);
    }

    #[test]
    fn shell_takes_img() {
        #[derive(clap::Parser)]
        struct S {
            #[command(flatten)]
            a: ShellArgs,
        }
        let sh = |args: &[&str]| {
            <S as clap::Parser>::try_parse_from(
                std::iter::once("shell").chain(args.iter().copied()),
            )
            .map(|s| shell_run_args(&s.a).img)
        };
        assert_eq!(sh(&[]).unwrap(), "alpine");
        assert_eq!(sh(&["debian"]).unwrap(), "debian");
        assert_eq!(sh(&["--img", "debian"]).unwrap(), "debian");
        assert!(
            sh(&["--img", "debian", "alpine"]).is_err(),
            "one or the other"
        );
    }

    #[test]
    fn ttl() {
        assert_eq!(parse_ttl("90s", 1800).unwrap(), 90);
        assert_eq!(parse_ttl("10m", 1800).unwrap(), 600);
        assert_eq!(parse_ttl("45", 1800).unwrap(), 45);
        assert!(parse_ttl("1h", 1800).is_err());
        assert!(parse_ttl("5s", 1800).is_err());
        assert!(parse_ttl("x", 1800).is_err());
    }

    fn parse(args: &[&str]) -> RunArgs {
        #[derive(clap::Parser)]
        struct T {
            #[command(flatten)]
            a: RunArgs,
        }
        <T as clap::Parser>::try_parse_from(std::iter::once("run").chain(args.iter().copied()))
            .unwrap()
            .a
    }

    #[test]
    fn remote_argv_round_trips() {
        let n = "0123456789abcdef0123456789abcdef";
        let a = parse(&[
            "--img",
            "alpine --net open",
            "--mem",
            "1024",
            "--ttl",
            "90s",
            "--net",
            "web",
            "--status-fd",
            "3",
            "--json-fd",
            "4",
            "--no-wait",
            "--",
            "echo",
            "--net open",
            "a b",
        ]);
        let argv = a.remote_argv(n, false);
        assert_eq!(
            argv,
            [
                "run",
                "--remote",
                &format!("1:{n}"),
                "--mem",
                "1024",
                "--ttl",
                "90s",
                "--net",
                "web",
                "--img",
                "alpine --net open",
                "--no-wait",
                "--",
                "echo",
                "--net open",
                "a b"
            ]
        );
        // the far end parses it back to the same run, the hostile --img still
        // one value, and never the client's fds
        let back = parse(&argv[1..].iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(back.img, "alpine --net open");
        assert_eq!((back.status_fd, back.json_fd), (None, None));
        assert_eq!(back.cmd, ["echo", "--net open", "a b"]);
        assert_eq!(back.remote.as_deref(), Some(n));
        assert!(a.check_local().is_err(), "a bad image name is caught here");
        let j = parse(&["--in", "tar", "--result", "tar", "--", "x"]).remote_argv(n, true);
        assert_eq!(
            j[3..],
            [
                "--img", "alpine", "--in", "tar", "--result", "tar", "--json", "--", "x"
            ]
        );
    }

    #[test]
    fn remote_argv_takes_the_log_mode() {
        let n = "0123456789abcdef0123456789abcdef";
        for (mode, want) in [
            ("none", Some("none")),
            ("full", Some("full")),
            ("summary", None),
        ] {
            let argv = parse(&["--log", mode, "--", "x"]).remote_argv(n, false);
            let at = argv.iter().position(|w| w == "--log");
            assert_eq!(at.map(|i| argv[i + 1].as_str()), want, "{mode}");
            let back = parse(&argv[1..].iter().map(String::as_str).collect::<Vec<_>>());
            assert!(back.log == parse(&["--log", mode, "--", "x"]).log);
        }
        #[derive(clap::Parser)]
        struct S {
            #[command(flatten)]
            a: ShellArgs,
        }
        let s = <S as clap::Parser>::try_parse_from(["shell", "--log", "none", "debian"]).unwrap();
        let sh = shell_run_args(&s.a).remote_argv(n, false);
        assert_eq!(sh[3..], ["--log", "none", "debian"]);
    }

    #[test]
    fn remote_flag() {
        let n = "0123456789abcdef0123456789abcdef";
        assert_eq!(remote_nonce(&format!("1:{n}")).as_deref(), Ok(n));
        let two = remote_nonce(&format!("2:{n}")).unwrap_err();
        assert!(two.contains("speaks remote protocol 1, the caller asked for 2"));
        for bad in [
            n.to_string(),
            format!("1:{}", &n[1..]),
            format!("1:{}", n.to_uppercase()),
            format!("1:{n}0"),
        ] {
            assert!(remote_nonce(&bad).is_err(), "{bad}");
        }
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
