//! `burner run`: boot a VM, run one command in it, hand back the output and
//! exit code, delete the VM. the VM's console, disks and result are hostile;
//! the caller is trusted but may be sloppy (stdin that never closes, a reader
//! that stops reading).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, chown};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;
use serde_json::json;

use crate::cgroup;
use crate::config::Config;
use crate::ledger::{self, Ident, Ledger, Status, Vm, valid_id};
use crate::net;
use crate::output::{Dest, Out, escape_controls};
use crate::result;
use crate::sys;

pub const USER: &str = "burner";
const SERIAL_CAP: u64 = 1 << 20;
const LIVE_BYTES: u64 = 65536;
const STDIN_CAP: u64 = 512 << 20;
const STDIN_IDLE: Duration = Duration::from_secs(60);
const STDIN_TOTAL: Duration = Duration::from_secs(600);
const CMD_CAP: usize = 64 << 10;
const QUEUE_WAIT: Duration = Duration::from_secs(600);
const DELIVER_TIMEOUT: Duration = Duration::from_secs(300);
/// what the VM's cgroup may use on top of guest RAM: firecracker itself, plus
/// host page cache from writes to its disks, which is charged to the same cgroup
pub const VMM_OVERHEAD_MIB: u64 = 256;
/// past this much over guest RAM the kernel starts flushing and throttling the
/// VM's writes, long before the hard limit would kill firecracker
const VMM_SOFT_MIB: u64 = 64;
/// setup (disks, tap) has this long before the reaper stops the wrapper
const PREP_SECS: u32 = 180;

pub const EXIT_USAGE: u8 = 2;
pub const EXIT_TIMEOUT: u8 = 124;
pub const EXIT_SANDBOX: u8 = 125;
pub const EXIT_INTERRUPTED: u8 = 130;

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
    input: Input,
    /// stdout becomes a tar of the VM's /out, rc and log.txt; the command's output goes to stderr
    #[arg(long, value_enum)]
    result: Option<ResultMode>,
    /// a label for burner ls
    #[arg(long)]
    tag: Option<String>,
    /// network: none, web (http/https, dns, ping) or open (any port but mail). never the LAN
    #[arg(long, default_value = "none")]
    net: String,
    /// one argument runs as a shell string; several are quoted as they are
    /// write one JSON line to this fd when done: how the run ended, the guest's
    /// exit code if it has one, the VM id. for wrappers that need to tell a
    /// timeout from a command that exited 124 itself. sudo closes fds above 2,
    /// so through sudo use 2: the line is then the last thing on stderr
    #[arg(long, value_name = "FD")]
    status_fd: Option<i32>,
    /// fail right away instead of queueing when every slot is taken
    #[arg(long)]
    no_wait: bool,
    #[arg(trailing_var_arg = true, required = true)]
    cmd: Vec<String>,
    #[arg(skip)]
    shell: bool,
    /// --net wasn't given: lower it to limits.net instead of refusing
    #[arg(skip)]
    net_default: bool,
}

#[derive(Args)]
pub struct ShellArgs {
    /// image to boot, default ubuntu if it's installed, else alpine
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
    let img = a.spec.unwrap_or_else(|| {
        if images(cfg).iter().any(|i| i == "ubuntu") {
            "ubuntu".into()
        } else {
            "alpine".into()
        }
    });
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
enum Input {
    None,
    Stdin,
    Tar,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum ResultMode {
    Tar,
}

/// an error with the exit code it should end the run with
#[derive(Debug)]
struct Exit(u8, String);

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.1)
    }
}

impl std::error::Error for Exit {}

fn usage(msg: impl Into<String>) -> anyhow::Error {
    Exit(EXIT_USAGE, msg.into()).into()
}

fn interrupted() -> &'static Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| {
        let f = Arc::new(AtomicBool::new(false));
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGHUP,
        ] {
            let _ = signal_hook::flag::register(sig, f.clone());
        }
        f
    })
}

fn is_interrupted() -> bool {
    interrupted().load(Ordering::Relaxed)
}

#[derive(Deserialize, Default)]
#[serde(default)]
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

fn image_defaults(cfg: &Config, img: &str) -> ImageDefaults {
    fs::read_to_string(
        cfg.paths
            .root
            .join("images")
            .join(img)
            .join("defaults.toml"),
    )
    .ok()
    .and_then(|t| toml::from_str(&t).ok())
    .unwrap_or_default()
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

struct Plan {
    img: String,
    vcpus: u32,
    mem_mib: u32,
    disk_gib: u32,
    ttl: u32,
    tag: String,
    cmd: String,
    net: net::Mode,
    shell: bool,
    no_wait: bool,
}

fn plan(cfg: &Config, a: &RunArgs) -> Result<Plan> {
    if !valid_name(&a.img) || !images(cfg).contains(&a.img) {
        return Err(usage(format!("unknown image {:?} (burner images)", a.img)));
    }
    let d = image_defaults(cfg, &a.img);
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
        reaper_alive(cfg)?;
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

/// how the run ended, for --status-fd. set where burner decides it
static STATUS: Mutex<Option<(&str, Option<i32>)>> = Mutex::new(None);
static RUN_ID: OnceLock<String> = OnceLock::new();

fn set_status(outcome: &'static str, rc: Option<i32>) {
    if let Ok(mut s) = STATUS.lock() {
        *s = Some((outcome, rc));
    }
}

pub fn main(cfg: &Config, a: RunArgs) -> ExitCode {
    interrupted();
    if let Some(fd) = a.status_fd {
        // SAFETY: fcntl only inspects and flags the fd; close-on-exec keeps a
        // caller's fd out of the VM's processes (stderr is passed explicitly anyway)
        let ok =
            fd == 2 || (fd > 2 && unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0);
        if !ok {
            eprintln!("burner: --status-fd {fd} isn't an open file descriptor (2, or above 2)");
            return ExitCode::from(EXIT_USAGE);
        }
    }
    let t0 = Instant::now();
    let code = match run(cfg, &a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("burner: {e:#}");
            match e.downcast_ref::<Exit>() {
                Some(Exit(code, _)) => *code,
                None => EXIT_SANDBOX,
            }
        }
    };
    if let Some(fd) = a.status_fd {
        let (outcome, rc) = STATUS.lock().ok().and_then(|s| *s).unwrap_or(match code {
            EXIT_USAGE => ("usage", None),
            EXIT_INTERRUPTED => ("interrupted", None),
            _ => ("sandbox_error", None),
        });
        let line = json!({"outcome": outcome, "rc": rc, "exit": code, "id": RUN_ID.get(),
                          "secs": (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0})
        .to_string()
            + "\n";
        let mut b = line.as_bytes();
        while !b.is_empty() {
            // SAFETY: write(2) of a live buffer to an fd checked at start
            let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
            if n <= 0 {
                break;
            }
            b = &b[n as usize..];
        }
    }
    ExitCode::from(code)
}

/// a point in boot time (CLOCK_BOOTTIME, keeps counting through suspend). the
/// same value goes in the ledger, so burner and the reaper agree on when a VM ends
#[derive(Clone, Copy)]
struct Deadline(f64);

impl Deadline {
    fn in_secs(secs: u32) -> Deadline {
        Deadline(sys::boottime() + f64::from(secs))
    }
    fn passed(self) -> bool {
        sys::boottime() >= self.0
    }
    fn left(self) -> Duration {
        Duration::from_secs_f64((self.0 - sys::boottime()).max(0.0))
    }
}

enum Outcome {
    /// the caller typed ~. in burner shell
    Detached,
    Done,
    Failed,
    Timeout,
    Cancelled,
    Interrupted,
}

fn run(cfg: &Config, a: &RunArgs) -> Result<u8> {
    if !sys::is_root() {
        return Err(usage("burner run needs root (sudo burner run ...)"));
    }
    let p = plan(cfg, a)?;
    let (uid, gid) =
        sys::user_ids(USER).with_context(|| format!("no {USER} user, see burner doctor"))?;
    let runs = cfg.paths.root.join("run");
    fs::create_dir_all(&runs)?;
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700))?;
    let (id, run_dir) = alloc_id(&runs)?;
    let _ = RUN_ID.set(id.clone());
    let mut vm = None;
    let res = run_vm(cfg, a, &p, &id, &run_dir, uid, gid, &mut vm);
    if vm.is_some() {
        teardown(cfg, &id, None);
    }
    remove_tree(&run_dir);
    res
}

fn alloc_id(runs: &Path) -> Result<(String, PathBuf)> {
    for _ in 0..5 {
        let id = format!("burner-{}", sys::random_hex(6)?);
        let dir = runs.join(&id);
        match fs::create_dir(&dir) {
            Ok(()) => {
                fs::write(dir.join("owner"), serde_json::to_vec(&Ident::me())?)?;
                return Ok((id, dir));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("could not allocate a run id")
}

#[allow(clippy::too_many_arguments)]
fn run_vm(
    cfg: &Config,
    a: &RunArgs,
    p: &Plan,
    id: &str,
    run_dir: &Path,
    uid: u32,
    gid: u32,
    held: &mut Option<()>,
) -> Result<u8> {
    let live = Out::new(if a.result.is_some() {
        Dest::Stderr
    } else {
        Dest::Stdout
    });
    let tar_out = a.result.map(|_| Out::new(Dest::Stdout));
    let diag = Out::new(Dest::Stderr);
    let t0 = Instant::now();

    if a.input != Input::None && !disk_left(run_dir, 0) {
        return Err(Exit(EXIT_SANDBOX, "not enough disk to hold the input".into()).into());
    }
    let spool = spool_input(&run_dir.join("stdin"), a.input)?;
    let job = run_dir.join("job.tar");
    // the job disk copies the spool before the spool goes away
    if let Some(sp) = &spool
        && !disk_left(run_dir, fs::metadata(sp)?.len())
    {
        return Err(Exit(EXIT_SANDBOX, "not enough disk to build the job disk".into()).into());
    }
    build_job(&job, &p.cmd, a.input, spool.as_deref())?;

    let net_slot = take_slot(cfg, p, id, &diag)?;
    *held = Some(());

    let jail = cfg.paths.root.join("jail").join("firecracker").join(id);
    let root = jail.join("root");
    fs::create_dir_all(jail.parent().context("jail path")?)?;
    // fresh dirs only: a jail left over from anything else is never reused
    fs::create_dir(&jail).context("creating the jail (left over from an earlier run?)")?;
    fs::create_dir(&root)?;
    for d in [&jail, &root] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o755))?;
    }
    fs::hard_link(
        fs::canonicalize(cfg.paths.root.join("kernel/vmlinux"))?,
        root.join("vmlinux"),
    )?;
    fs::hard_link(
        cfg.paths
            .root
            .join("images")
            .join(&p.img)
            .join("rootfs.ext4"),
        root.join("rootfs.ext4"),
    )?;
    fs::rename(&job, root.join("job.tar"))?;
    let scratch = root.join("scratch.ext4");
    reserve(cfg, &scratch, u64::from(p.disk_gib) << 30)?;
    prep_ok(cfg, id)?;
    mkfs(&scratch, cfg, id)?;
    let raw = root.join("result.raw");
    reserve(cfg, &raw, result::RESULT_SIZE)?;
    // opened now, before anything runs as the VM's user, and read through this fd
    // later: the path inside the jail can't be swapped for something else
    let raw_fd = File::open(&raw)?;
    for f in [&scratch, &raw] {
        chown(f, Some(uid), Some(gid))?;
        fs::set_permissions(f, fs::Permissions::from_mode(0o600))?;
    }

    prep_ok(cfg, id)?;
    let token = sys::random_hex(8)?;
    let mut boot = format!(
        "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=1 init=/sbin/burner-init burner.token={token}"
    );
    let mut ifaces = Vec::new();
    if let Some(i) = net_slot {
        let s = net::tap_up(cfg, i, p.net, uid, gid)?;
        let rate = json!({"bandwidth": {"size": cfg.net.rate, "refill_time": 1000}});
        ifaces.push(json!({"iface_id": "eth0", "host_dev_name": s.tap, "guest_mac": format!("06:00:ac:1d:{:02x}:{:02x}", i >> 8, i & 0xff),
                           "rx_rate_limiter": rate, "tx_rate_limiter": rate}));
        let dns: Vec<String> = cfg.net.resolvers.iter().map(|r| r.to_string()).collect();
        boot += &format!(
            " ip={}::{}:255.255.255.252:burner:eth0:off burner.dns={}",
            s.guest,
            s.host,
            dns.join(",")
        );
    }
    let saved_tty = p.shell.then(sys::save_tty).flatten();
    if p.shell {
        let (rows, cols) = sys::term_size(1).unwrap_or((24, 80));
        let term = std::env::var("TERM").ok().filter(|t| {
            !t.is_empty()
                && t.len() <= 32
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        });
        boot += &format!(
            " burner.shell=1 burner.tty={}x{} burner.term={}",
            rows.min(500),
            cols.min(1000),
            term.as_deref().unwrap_or("xterm")
        );
    }
    let drive = |id: &str, path: &str, ro: bool, mbps: u64, ops: u64| {
        json!({"drive_id": id, "path_on_host": path, "is_root_device": id == "rootfs", "is_read_only": ro,
               "rate_limiter": {"bandwidth": {"size": mbps << 20, "refill_time": 1000},
                                "ops": {"size": ops, "refill_time": 1000}}})
    };
    let vmcfg = json!({
        "boot-source": {"kernel_image_path": "vmlinux", "boot_args": boot},
        "drives": [drive("rootfs", "rootfs.ext4", true, 200, 5000), drive("scratch", "scratch.ext4", false, 100, 3000),
                   drive("job", "job.tar", true, 200, 3000), drive("result", "result.raw", false, 100, 3000)],
        "machine-config": {"vcpu_count": p.vcpus, "mem_size_mib": p.mem_mib},
        "network-interfaces": ifaces,
    });
    fs::write(root.join("vm.json"), serde_json::to_vec(&vmcfg)?)?;
    fs::set_permissions(root.join("vm.json"), fs::Permissions::from_mode(0o644))?;

    let deadline = Deadline::in_secs(p.ttl);
    let procs = cgroup::prepare(id).context("creating the VM's cgroup")?;
    {
        let led = Ledger::open(&cfg.paths.state)?;
        let cur = led.get(id).context("ledger entry vanished")?;
        if cur.cancel {
            return Err(Exit(EXIT_INTERRUPTED, "cancelled before start".into()).into());
        }
        if cur.deadline_boot.is_some_and(|d| sys::boottime() > d) {
            return Err(Exit(EXIT_SANDBOX, format!("setup took longer than {PREP_SECS}s")).into());
        }
        led.update(id, |v| {
            v.status = Status::Running;
            v.deadline_boot = Some(deadline.0);
        })?;
    }
    if is_interrupted() {
        return Err(Exit(EXIT_INTERRUPTED, "interrupted, sandbox stopped".into()).into());
    }
    let fclog = File::create(jail.join("firecracker.log"))?;
    // bin is a symlink the installer switches in one rename; resolve it once so
    // this launch uses a jailer and a firecracker from the same release
    let bin = fs::canonicalize(cfg.paths.root.join("bin")).context("no firecracker installed")?;
    let mut jailer = Command::new(bin.join("jailer"));
    // own process group so a ctrl-c meant for burner doesn't hit the VM first.
    // firecracker never sees the caller's terminal, even for a shell: burner relays it
    jailer.process_group(0);
    let me = std::process::id() as libc::pid_t;
    // SAFETY: join_from_child only makes plain syscalls (prctl, getppid, open, write, close)
    unsafe {
        jailer.pre_exec(move || cgroup::join_from_child(&procs, me));
    }
    let mut child = jailer
        .args(["--id", id, "--exec-file"])
        .arg(bin.join("firecracker"))
        .args([
            "--uid",
            &uid.to_string(),
            "--gid",
            &gid.to_string(),
            "--chroot-base-dir",
        ])
        .arg(cfg.paths.root.join("jail"))
        .args(["--cgroup-version", "2", "--parent-cgroup", cgroup::PARENT])
        .args([
            "--cgroup",
            &format!("cpu.max={} 100000", u64::from(p.vcpus) * 100_000),
        ])
        .args([
            "--cgroup",
            &format!(
                "memory.high={}",
                (u64::from(p.mem_mib) + VMM_SOFT_MIB) << 20
            ),
        ])
        .args([
            "--cgroup",
            &format!(
                "memory.max={}",
                (u64::from(p.mem_mib) + VMM_OVERHEAD_MIB) << 20
            ),
        ])
        .args(["--cgroup", "pids.max=128"])
        .args([
            "--",
            "--no-api",
            "--config-file",
            "vm.json",
            "--level",
            "Error",
        ])
        .stdin(if p.shell {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(fclog)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .spawn()
        .context("starting the jailer")?;
    if p.shell {
        let outcome = relay(&mut child, deadline, cfg, id);
        sys::restore_tty(saved_tty.as_ref());
        if matches!(outcome, Outcome::Failed) {
            // the jail and its firecracker.log are gone after teardown
            let tail = tail_of(&jail.join("firecracker.log"), 1500);
            log_line(&format!(
                "{id}: firecracker failed: {}",
                String::from_utf8_lossy(&escape_controls(&tail)).trim()
            ));
        }
        teardown(cfg, id, Some(&mut child));
        *held = None;
        log_line(&format!(
            "end {id} tag={} secs={:.1} shell",
            p.tag,
            t0.elapsed().as_secs_f64()
        ));
        return Ok(match outcome {
            Outcome::Done => {
                set_status("exited", None);
                0
            }
            Outcome::Detached => {
                set_status("detached", None);
                eprintln!("burner: left the shell, VM stopped");
                0
            }
            Outcome::Failed => {
                set_status("sandbox_error", None);
                eprintln!("burner: the VM stopped with an error, see the system log");
                EXIT_SANDBOX
            }
            Outcome::Timeout => {
                set_status("timeout", None);
                eprintln!("burner: shell closed at the {} min limit", p.ttl / 60);
                EXIT_TIMEOUT
            }
            Outcome::Cancelled => {
                set_status("killed", None);
                eprintln!("burner: killed by burner kill");
                EXIT_INTERRUPTED
            }
            Outcome::Interrupted => {
                set_status("interrupted", None);
                EXIT_INTERRUPTED
            }
        });
    }
    let mut stdout = child.stdout.take().context("no console pipe")?;

    let mut outcome = stream(
        &mut stdout,
        &mut child,
        &token,
        deadline,
        &live,
        &diag,
        cfg,
        id,
    );
    if matches!(outcome, Outcome::Done) {
        outcome = supervise(&mut child, deadline, cfg, id);
    }
    let code = match outcome {
        Outcome::Timeout | Outcome::Cancelled | Outcome::Interrupted | Outcome::Detached => {
            teardown(cfg, id, Some(&mut child));
            *held = None;
            match outcome {
                Outcome::Timeout => {
                    set_status("timeout", None);
                    diag.put(
                        format!("burner: killed at the {}s time limit\n", p.ttl).as_bytes(),
                        None,
                    );
                    EXIT_TIMEOUT
                }
                Outcome::Cancelled => {
                    set_status("killed", None);
                    diag.put(b"burner: killed by burner kill\n", None);
                    EXIT_INTERRUPTED
                }
                _ => {
                    set_status("interrupted", None);
                    diag.put(b"burner: interrupted, sandbox stopped\n", None);
                    EXIT_INTERRUPTED
                }
            }
        }
        // a firecracker error after the job still has a result disk worth reading;
        // without an exit code from the guest it ends up as a sandbox failure anyway
        Outcome::Done | Outcome::Failed => {
            let log = run_dir.join("log.bin");
            let tar_path = run_dir.join("result.tar");
            let meta = result::parse(
                raw_fd,
                &log,
                a.result.map(|_| tar_path.as_path()),
                &cfg.paths.state,
            );
            let fc_tail = if meta.rc.is_none() {
                tail_of(&jail.join("firecracker.log"), 1500)
            } else {
                Vec::new()
            };
            if meta.rc.is_none() && cgroup::oom_kills(id) > 0 {
                diag.put(
                    b"burner: the VM's cgroup ran out of memory and the kernel killed firecracker\n",
                    None,
                );
            }
            teardown(cfg, id, Some(&mut child));
            *held = None;
            let until = Instant::now() + DELIVER_TIMEOUT;
            print_rest(&meta, &log, &live, &diag, until);
            if let Some(pr) = &meta.problem {
                diag.put(format!("burner: {pr}\n").as_bytes(), None);
            }
            if !fc_tail.iter().all(u8::is_ascii_whitespace) {
                diag.put(b"burner: firecracker: ", None);
                diag.put(&escape_controls(&fc_tail), None);
                diag.put(b"\n", None);
            }
            let mut code = meta.rc.map(|rc| rc as u8).unwrap_or(EXIT_SANDBOX);
            if meta.guest_error {
                code = EXIT_SANDBOX;
            }
            match meta.rc {
                Some(rc) if !meta.guest_error => set_status("exited", Some(rc)),
                _ => set_status("sandbox_error", None),
            }
            if let (Some(out), false) = (&tar_out, meta.fatal) {
                // a tar that didn't arrive whole is a failed run, whatever the guest said
                if !deliver(&tar_path, out, until) || !out.complete(until) {
                    diag.put(
                        b"burner: result tar not fully delivered, failing the run\n",
                        None,
                    );
                    code = EXIT_SANDBOX;
                    set_status("sandbox_error", None);
                }
            }
            code
        }
    };
    let until = Instant::now() + Duration::from_secs(30);
    if !live.complete(until) {
        diag.put(
            b"burner: some live output was dropped (reader too slow)\n",
            None,
        );
    }
    diag.drain(until);
    log_line(&format!(
        "end {id} tag={} secs={:.1} code={code}",
        p.tag,
        t0.elapsed().as_secs_f64()
    ));
    Ok(code)
}

/// read the caller's stdin before taking a slot, with idle and total deadlines
fn spool_input(path: &Path, mode: Input) -> Result<Option<PathBuf>> {
    if mode == Input::None {
        return Ok(None);
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let mut stdin = io::stdin().lock();
    let (start, mut last, mut n) = (Instant::now(), Instant::now(), 0u64);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        if is_interrupted() {
            return Err(Exit(EXIT_INTERRUPTED, "interrupted".into()).into());
        }
        if start.elapsed() > STDIN_TOTAL {
            return Err(usage("input took longer than 10 min"));
        }
        if last.elapsed() > STDIN_IDLE {
            return Err(usage("no input for 60s (does the pipe ever close?)"));
        }
        if !sys::readable(0, Duration::from_secs(1)) {
            continue;
        }
        let got = stdin.read(&mut buf)?;
        if got == 0 {
            break;
        }
        last = Instant::now();
        n += got as u64;
        if n > STDIN_CAP {
            return Err(usage("input over the 512M cap"));
        }
        // spooled input counts against the same 1 GiB the VM disks keep free
        if n % (16 << 20) < got as u64 && !disk_left(path, 0) {
            return Err(Exit(EXIT_SANDBOX, "not enough disk to hold the input".into()).into());
        }
        f.write_all(&buf[..got])?;
    }
    Ok(Some(path.to_path_buf()))
}

fn build_job(job: &Path, cmd: &str, mode: Input, spool: Option<&Path>) -> Result<()> {
    let f = File::create(job)?;
    let mut b = tar::Builder::new(f);
    let mut h = tar::Header::new_ustar();
    h.set_size(cmd.len() as u64 + 1);
    h.set_mode(0o644);
    b.append_data(&mut h, "run.sh", format!("{cmd}\n").as_bytes())?;
    if let Some(sp) = spool {
        let mut f = File::open(sp)?;
        let mut h = tar::Header::new_ustar();
        h.set_size(f.metadata()?.len());
        h.set_mode(0o644);
        b.append_data(
            &mut h,
            if mode == Input::Tar {
                "input.tar"
            } else {
                "stdin"
            },
            &mut f,
        )?;
        fs::remove_file(sp)?;
    }
    let f = b.into_inner()?;
    let len = f.metadata()?.len();
    f.set_len(((len >> 20) + 1) << 20)?;
    fs::set_permissions(job, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn take_slot(cfg: &Config, p: &Plan, id: &str, diag: &Out) -> Result<Option<u32>> {
    let l = &cfg.limits;
    let vm = Vm {
        id: id.into(),
        tag: p.tag.clone(),
        img: p.img.clone(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        disk_gib: p.disk_gib,
        net: p.net.name().into(),
        ttl_secs: p.ttl,
        wrapper: Some(Ident::me()),
        status: Status::Preparing,
        version: ledger::VERSION,
        owner: caller_uid().parse().ok(),
        cancel: false,
        started: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        deadline_boot: None,
        net_slot: None,
    };
    let start = Instant::now();
    let mut waited = false;
    loop {
        if is_interrupted() {
            return Err(Exit(EXIT_INTERRUPTED, "interrupted".into()).into());
        }
        {
            let led = Ledger::open(&cfg.paths.state)?;
            if let Some(bad) = led.unreadable().first() {
                anyhow::bail!(
                    "ledger entry {bad} is unreadable. if no VM is running for it, delete it"
                );
            }
            let busy = led.all();
            let used: u32 = busy.iter().map(|v| v.mem_mib).sum();
            if (busy.len() as u32) < l.max_vms && used + p.mem_mib <= l.total_mem_mib {
                let mut vm = vm.clone();
                vm.deadline_boot = Some(sys::boottime() + f64::from(PREP_SECS));
                if p.net != net::Mode::None {
                    let taken: Vec<u32> = led.all().iter().filter_map(|v| v.net_slot).collect();
                    vm.net_slot = Some(
                        (0..cfg.net_slots()?)
                            .find(|i| !taken.contains(i))
                            .context("no free network slot")?,
                    );
                }
                if !led.create(&vm)? {
                    anyhow::bail!("run id collision");
                }
                log_line(&format!(
                    "start {id} by uid {} tag={} img={} vcpus={} mem={} disk={} ttl={} net={} shell={}",
                    caller_uid(),
                    p.tag,
                    p.img,
                    p.vcpus,
                    p.mem_mib,
                    p.disk_gib,
                    p.ttl,
                    p.net.name(),
                    p.shell
                ));
                return Ok(vm.net_slot);
            }
            if p.no_wait {
                set_status("busy", None);
                return Err(Exit(
                    EXIT_SANDBOX,
                    format!("no free slot ({} running) and --no-wait", busy.len()),
                )
                .into());
            }
            if !waited {
                // queued, never written while the ledger lock is held
                diag.put(
                    format!(
                        "burner: waiting for a slot ({} running, {used} of {} MiB in use)\n",
                        busy.len(),
                        l.total_mem_mib
                    )
                    .as_bytes(),
                    None,
                );
                waited = true;
            }
        }
        if start.elapsed() > QUEUE_WAIT {
            anyhow::bail!("no free slot after 10 min");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// the reaper refreshes the network filter and stops orphaned VMs. without it,
/// a VM with a network could outlive its wrapper or sit behind a stale filter,
/// so networked runs wait for it to be running
const REAPED: &str = "reaped";
const REAPER_MAX_AGE: Duration = Duration::from_secs(120);

fn reaper_alive(cfg: &Config) -> Result<()> {
    match reaper_age(cfg) {
        Some(a) if a <= REAPER_MAX_AGE => Ok(()),
        _ => Err(Exit(
            EXIT_SANDBOX,
            "the reaper hasn't run in the last 2 min (systemctl status burner-reap.timer), \
             refusing a VM with a network. --net none still works"
                .into(),
        )
        .into()),
    }
}

/// when the reaper last finished a pass, for doctor
pub fn reaper_age(cfg: &Config) -> Option<Duration> {
    fs::metadata(cfg.paths.state.join(REAPED))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
}

/// whether `need` bytes fit on `dir`'s filesystem with 1 GiB to spare
fn disk_left(dir: &Path, need: u64) -> bool {
    sys::free_bytes(dir).is_ok_and(|f| f >= need + (1 << 30))
}

/// a disk file with all its blocks reserved up front, so a guest filling it
/// can never fill the host. keeps 1 GiB free for everything else
fn reserve(cfg: &Config, path: &Path, size: u64) -> Result<()> {
    // check and allocate under one lock, so two runs can't both count the same free space
    let _disk = sys::Lock::exclusive_until(
        &cfg.paths.state.join("disk.lock"),
        Instant::now() + Duration::from_secs(60),
    )
    .context("the disk lock stayed busy")?;
    let free = sys::free_bytes(path.parent().unwrap_or(Path::new("/")))?;
    if free < size + (1 << 30) {
        return Err(Exit(
            EXIT_SANDBOX,
            format!(
                "not enough disk: this VM needs {} MiB, {} MiB free",
                size >> 20,
                free >> 20
            ),
        )
        .into());
    }
    let f = File::create(path)?;
    sys::preallocate(&f, size).context("reserving disk space")?;
    Ok(())
}

/// between setup steps: stop if burner kill, a signal or the setup deadline
/// (set at admission) says so
fn prep_ok(cfg: &Config, id: &str) -> Result<()> {
    if is_interrupted() {
        return Err(Exit(EXIT_INTERRUPTED, "interrupted, sandbox stopped".into()).into());
    }
    let v = ledger::peek(&cfg.paths.state, id);
    if v.as_ref().is_none_or(|v| v.cancel) {
        set_status("killed", None);
        return Err(Exit(EXIT_INTERRUPTED, "killed by burner kill".into()).into());
    }
    if v.is_some_and(|v| {
        v.status == Status::Preparing && v.deadline_boot.is_some_and(|d| sys::boottime() > d)
    }) {
        return Err(Exit(EXIT_SANDBOX, format!("setup took longer than {PREP_SECS}s")).into());
    }
    Ok(())
}

fn mkfs(path: &Path, cfg: &Config, id: &str) -> Result<()> {
    let mut c = Command::new("mkfs.ext4")
        .args([
            "-q",
            "-F",
            "-E",
            "lazy_itable_init=1,lazy_journal_init=1,nodiscard",
        ])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("mkfs.ext4")?;
    let start = Instant::now();
    loop {
        if let Some(s) = c.try_wait()? {
            anyhow::ensure!(s.success(), "mkfs.ext4 failed");
            return Ok(());
        }
        let stop = if start.elapsed() > Duration::from_secs(60) {
            Some(anyhow::anyhow!("mkfs.ext4 hung"))
        } else {
            prep_ok(cfg, id).err()
        };
        if let Some(e) = stop {
            let _ = c.kill();
            let _ = c.wait();
            return Err(e);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// copy the console between the BEGIN/END markers to `out`, byte for byte.
/// the markers are only presentation: the guest knows the token and can end its
/// own live output early, which hides nothing but its own output
#[allow(clippy::too_many_arguments)]
fn stream(
    stdout: &mut ChildStdout,
    child: &mut Child,
    token: &str,
    deadline: Deadline,
    out: &Out,
    diag: &Out,
    cfg: &Config,
    id: &str,
) -> Outcome {
    let begin = format!("BURNER-{token}-BEGIN\n").into_bytes();
    let end = format!("BURNER-{token}-END").into_bytes();
    let end_n = [end.as_slice(), b"N"].concat();
    let fd = stdout.as_raw_fd();
    let _ = sys::set_nonblocking(fd);
    #[derive(PartialEq)]
    enum St {
        Pre,
        Body,
        Capped,
        Done,
    }
    let mut st = St::Pre;
    // pre_line: whether pre[0] starts a line, kept across trims
    let (mut pre, mut pre_line, mut pending) = (Vec::new(), true, Vec::new());
    let (mut held_nl, mut at_line_start, mut raw_total) = (false, true, 0u64);
    let mut next_check = Instant::now();
    let mut chunk = vec![0u8; 65536];
    let flush_held = |held: &mut bool| {
        if *held {
            out.put(b"\n", None);
            *held = false;
        }
    };
    loop {
        if deadline.passed() {
            return Outcome::Timeout;
        }
        if is_interrupted() {
            return Outcome::Interrupted;
        }
        if Instant::now() >= next_check {
            next_check = Instant::now() + Duration::from_secs(1);
            if cancelled(cfg, id) {
                return Outcome::Cancelled;
            }
        }
        // a newline is held back in case the guest's own one before ENDN comes
        // next. the guest prints that newline and the marker in one printf, so
        // 200ms of quiet means it's real: let it out, or a line reader waits on it
        let wait = if held_nl {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(1)
        };
        if !sys::readable(fd, deadline.left().min(wait)) {
            if held_nl && st == St::Body {
                flush_held(&mut held_nl);
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            continue;
        }
        let n = match stdout.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(_) => break,
        };
        // the part of this read still under the console cap
        let take = n.min(SERIAL_CAP.saturating_sub(raw_total) as usize);
        raw_total += n as u64;
        let data = &chunk[..take];
        match st {
            St::Pre => {
                pre.extend_from_slice(data);
                if let Some(i) = find_at_line_start(&pre, &begin, pre_line) {
                    st = St::Body;
                    pending = pre.split_off(i + begin.len());
                    pre.truncate(i);
                } else {
                    let keep = 8192 + begin.len();
                    if pre.len() > keep {
                        let cut = pre.len() - keep;
                        pre_line = pre[cut - 1] == b'\n';
                        pre.drain(..cut);
                    }
                }
            }
            St::Body => pending.extend_from_slice(data),
            _ => {}
        }
        if st == St::Body {
            // scan with an offset and compact once, instead of draining per line
            let mut start = 0;
            loop {
                let Some(off) = pending[start..].iter().position(|&b| b == b'\n') else {
                    let rest = &pending[start..];
                    if !rest.is_empty() && !(at_line_start && end_n.starts_with(rest)) {
                        flush_held(&mut held_nl);
                        out.put(rest, None);
                        at_line_start = false;
                        start = pending.len();
                    }
                    break;
                };
                let line = &pending[start..start + off];
                start += off + 1;
                if at_line_start && line == end.as_slice() {
                    flush_held(&mut held_nl);
                    st = St::Done;
                    break;
                }
                if at_line_start && line == end_n.as_slice() {
                    held_nl = false; // that newline was added by the guest init
                    st = St::Done;
                    break;
                }
                flush_held(&mut held_nl);
                out.put(line, None);
                held_nl = true;
                at_line_start = true;
            }
            pending.drain(..start);
        }
        if raw_total >= SERIAL_CAP && st == St::Body {
            flush_held(&mut held_nl);
            out.put(&pending, None);
            pending.clear();
            diag.put(b"burner: console over 1M, live output stopped\n", None);
            st = St::Capped;
        }
    }
    if st == St::Body {
        flush_held(&mut held_nl);
        out.put(&pending, None);
    }
    if st == St::Pre {
        diag.put(
            b"burner: VM ended before the job started; last console lines:\n",
            None,
        );
        let tail = &pre[pre.len().saturating_sub(2000)..];
        diag.put(&escape_controls(tail), None);
        diag.put(b"\n", None);
    }
    Outcome::Done
}

/// first `needle` that starts a line. `first_is_line` says whether hay[0] does
fn find_at_line_start(hay: &[u8], needle: &[u8], first_is_line: bool) -> Option<usize> {
    let mut from = 0;
    while let Some(off) = hay
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
    {
        let i = from + off;
        if (i == 0 && first_is_line) || (i > 0 && hay[i - 1] == b'\n') {
            return Some(i);
        }
        from = i + 1;
    }
    None
}

/// `burner shell`: the caller's terminal goes raw and burner copies bytes both
/// ways. keystrokes go to the VM as they are; what the VM prints goes through a
/// filter so it can't set titles, the clipboard or anything else on the terminal
fn relay(child: &mut Child, deadline: Deadline, cfg: &Config, id: &str) -> Outcome {
    let (Some(vin), Some(mut vout)) = (child.stdin.take(), child.stdout.take()) else {
        return Outcome::Failed;
    };
    let (vin_fd, vout_fd) = (vin.as_raw_fd(), vout.as_raw_fd());
    // blocking pipes would let a stuck VM freeze the loop that enforces the ttl
    if sys::set_nonblocking(vin_fd).is_err() || sys::set_nonblocking(vout_fd).is_err() {
        return Outcome::Failed;
    }
    let mut vin = Some(vin);
    sys::restore_tty_on_panic(crate::output::TERM_RESET); // saves the tty before it goes raw
    let _ = sys::set_raw(0);
    let screen = Out::new_unescaped(Dest::Stdout);
    let mut filter = crate::output::TermFilter::default();
    let mut escape = Escape::default();
    let mut to_vm: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut next_check = Instant::now();
    let (mut stdin_open, mut console_open) = (true, true);
    let outcome = loop {
        if deadline.passed() {
            break Outcome::Timeout;
        }
        if is_interrupted() {
            break Outcome::Interrupted;
        }
        if Instant::now() >= next_check {
            next_check = Instant::now() + Duration::from_secs(1);
            if cancelled(cfg, id) {
                break Outcome::Cancelled;
            }
        }
        let mut fds = Vec::new();
        if stdin_open && console_open && to_vm.len() < 65536 {
            fds.push(0);
        }
        if console_open {
            fds.push(vout_fd);
        }
        let ready = sys::poll_read(&fds, deadline.left().min(Duration::from_millis(200)));
        if ready.contains(&0) {
            match io::stdin().lock().read(&mut buf) {
                Ok(0) | Err(_) => stdin_open = false,
                Ok(n) => {
                    if escape.feed(&buf[..n], &mut to_vm) {
                        break Outcome::Detached;
                    }
                }
            }
        }
        if let Some(w) = vin.as_mut()
            && !to_vm.is_empty()
        {
            match w.write(&to_vm) {
                Ok(n) => {
                    to_vm.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => to_vm.clear(),
            }
        }
        // caller's input ended and everything is sent: the VM sees eof too
        if !stdin_open && to_vm.is_empty() {
            vin = None;
        }
        if ready.contains(&vout_fd) {
            match vout.read(&mut buf) {
                Ok(n) if n > 0 => screen.put(&filter.feed(&buf[..n]), None),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                // console gone: keep watching the deadline and kills until firecracker exits
                _ => console_open = false,
            }
        } else if matches!(child.try_wait(), Ok(Some(_))) {
            break child_outcome(child);
        }
    };
    // a kill that landed as the VM was exiting still counts as a kill
    let outcome = match outcome {
        Outcome::Done | Outcome::Failed if cancelled(cfg, id) => Outcome::Cancelled,
        o => o,
    };
    screen.put(crate::output::TERM_RESET, None);
    screen.drain(Instant::now() + Duration::from_secs(2));
    outcome
}

/// ssh-style escape for burner shell: `~` right after enter (or at the start)
/// is held, `~.` leaves, `~~` sends one `~`, anything else goes through as is.
/// a way out when the guest hangs and ctrl-c only reaches the VM
#[derive(Default)]
struct Escape {
    mid_line: bool,
    tilde: bool,
}

impl Escape {
    /// true when the caller asked to leave
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> bool {
        for &b in input {
            if self.tilde {
                self.tilde = false;
                match b {
                    b'.' => return true,
                    b'~' => {
                        out.push(b'~');
                        self.mid_line = true;
                        continue;
                    }
                    _ => out.push(b'~'),
                }
            } else if b == b'~' && !self.mid_line {
                self.tilde = true;
                continue;
            }
            out.push(b);
            self.mid_line = !matches!(b, b'\r' | b'\n');
        }
        false
    }
}

fn child_outcome(child: &mut Child) -> Outcome {
    match child.wait() {
        Ok(s) if s.success() => Outcome::Done,
        _ => Outcome::Failed,
    }
}

fn cancelled(cfg: &Config, id: &str) -> bool {
    // unreadable counts as cancelled: nothing keeps running on a record nobody can read
    ledger::peek_strict(&cfg.paths.state, id).map_or(true, |v| v.is_none_or(|v| v.cancel))
}

/// after the console closed: the VM must be gone before its result disk is read
fn supervise(child: &mut Child, deadline: Deadline, cfg: &Config, id: &str) -> Outcome {
    let mut next_check = Instant::now();
    let status = loop {
        if let Ok(Some(st)) = child.try_wait() {
            break st;
        }
        let now = Instant::now();
        if deadline.passed() {
            return Outcome::Timeout;
        }
        if is_interrupted() {
            return Outcome::Interrupted;
        }
        if now >= next_check {
            next_check = now + Duration::from_secs(1);
            if cancelled(cfg, id) {
                return Outcome::Cancelled;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let end = Instant::now() + Duration::from_secs(5);
    while cgroup::populated(id) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    if cgroup::populated(id) {
        cgroup::kill(id);
        return Outcome::Timeout;
    }
    if status.success() {
        Outcome::Done
    } else {
        Outcome::Failed
    }
}

/// delete a jail or run dir. stops at anything mounted inside it, so a bind
/// mount someone left there never gets its contents deleted
fn remove_tree(path: &Path) -> bool {
    let ok = sys::remove_tree_at(path);
    if !ok && path.exists() {
        log_line(&format!(
            "couldn't fully remove {}, keeping it for the reaper",
            path.display()
        ));
    }
    ok
}

/// stop the VM and only then free its disks and its slot. false when it couldn't be confirmed dead
pub fn teardown(cfg: &Config, id: &str, child: Option<&mut Child>) -> bool {
    let mut child = child;
    if let Some(c) = child.as_deref_mut() {
        let _ = c.kill();
    }
    cgroup::kill(id);
    let end = Instant::now() + Duration::from_secs(15);
    let done = |c: &mut Option<&mut Child>| {
        c.as_deref_mut()
            .is_none_or(|c| matches!(c.try_wait(), Ok(Some(_))))
    };
    while Instant::now() < end && !(done(&mut child) && !cgroup::populated(id)) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let stopped = done(&mut child) && !cgroup::populated(id);
    if !stopped {
        if let Ok(led) = Ledger::open(&cfg.paths.state) {
            let _ = led.update(id, |v| v.status = Status::CleanupFailed);
        }
        log_line(&format!(
            "teardown {id}: VM did not stop, slot kept for the reaper"
        ));
        return false;
    }
    // the slow parts (subprocesses, deleting files) happen without the ledger lock
    let cg_gone = cgroup::remove(id);
    let tap_gone = match ledger::peek_strict(&cfg.paths.state, id) {
        Ok(v) => v
            .and_then(|v| v.net_slot)
            .is_none_or(|i| net::tap_down(cfg, i)),
        Err(_) => false, // can't tell which tap: leave it all for the reaper
    };
    let jail = cfg.paths.root.join("jail").join("firecracker").join(id);
    let jail_gone = remove_tree(&jail) && tap_gone && cg_gone;
    let Ok(led) = Ledger::open(&cfg.paths.state) else {
        return false;
    };
    if !jail_gone {
        let _ = led.update(id, |v| {
            v.status = Status::CleanupFailed;
            v.wrapper = None;
        });
        return false;
    }
    led.delete(id);
    true
}

/// what the guest didn't stream live: log bytes past the first LIVE_BYTES
fn print_rest(meta: &result::Meta, log: &Path, out: &Out, diag: &Out, until: Instant) {
    let Ok(mut f) = File::open(log) else { return };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = match meta.skipped {
        0 => LIVE_BYTES,
        s if s <= LIVE_BYTES => LIVE_BYTES - s,
        s => {
            diag.put(
                format!(
                    "burner: output was {} bytes; the {} bytes after the first 64K are not kept, showing the last 16M\n",
                    s + size,
                    s - LIVE_BYTES
                )
                .as_bytes(),
                None,
            );
            0
        }
    };
    if size <= start || f.seek(SeekFrom::Start(start)).is_err() {
        return;
    }
    deliver_from(&mut f, out, until);
}

/// false when the file couldn't be read in full before the deadline
fn deliver(path: &Path, out: &Out, until: Instant) -> bool {
    File::open(path).is_ok_and(|mut f| deliver_from(&mut f, out, until))
}

fn deliver_from(f: &mut File, out: &Out, until: Instant) -> bool {
    let want = f.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
    let pos = f.stream_position().unwrap_or(0);
    let (mut sent, mut buf) = (0u64, vec![0u8; 1 << 20]);
    loop {
        if Instant::now() >= until || is_interrupted() {
            return false;
        }
        match f.read(&mut buf) {
            Ok(0) => return pos + sent == want,
            Ok(n) => {
                out.put(&buf[..n], Some(until));
                sent += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
}

fn tail_of(path: &Path, n: u64) -> Vec<u8> {
    let Ok(mut f) = File::open(path) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(n)));
    let mut v = Vec::new();
    let _ = f.read_to_end(&mut v);
    v
}

/// who asked for the run: the sudo caller when there is one, else our own uid
fn caller_uid() -> String {
    std::env::var("SUDO_UID")
        .ok()
        .filter(|u| u.bytes().all(|b| b.is_ascii_digit()) && !u.is_empty())
        // SAFETY: getuid can't fail
        .unwrap_or_else(|| unsafe { libc::getuid() }.to_string())
}

pub fn log_line(msg: &str) {
    sys::syslog(msg);
}

// ---- ls, kill, reap ----

pub fn ls(cfg: &Config, json_out: bool) -> Result<ExitCode> {
    let now = sys::boottime();
    let mut vms = Ledger::open(&cfg.paths.state)?.all();
    vms.sort_by_key(|v| v.started);
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if json_out {
        let items: Vec<_> = vms
            .iter()
            .map(|v| {
                json!({"id": v.id, "tag": v.tag, "img": v.img, "vcpus": v.vcpus, "mem": v.mem_mib, "disk": v.disk_gib,
                       "net": v.net, "status": v.status.name(), "owner": v.owner, "age": unix.saturating_sub(v.started), "ttl": v.ttl_secs,
                       "ttl_left": v.deadline_boot.map(|d| (d - now).max(0.0) as u64)})
            })
            .collect();
        let used: u32 = vms.iter().map(|v| v.mem_mib).sum();
        println!(
            "{}",
            json!({"vms": items, "max_vms": cfg.limits.max_vms, "total_mem": cfg.limits.total_mem_mib, "used_mem": used})
        );
        return Ok(ExitCode::SUCCESS);
    }
    if vms.is_empty() {
        println!("no VMs running");
    }
    for v in vms {
        let left = v
            .deadline_boot
            .map(|d| format!("{}s", (d - now).max(0.0) as u64))
            .unwrap_or("-".into());
        println!(
            "{}  {:<12} {:<10} {}cpu {}M  net={}  {}  age={}s  ttl_left={left}",
            v.id,
            v.tag,
            v.img,
            v.vcpus,
            v.mem_mib,
            v.net,
            v.status.name(),
            unix.saturating_sub(v.started)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn kill(cfg: &Config, id: &str) -> Result<ExitCode> {
    if !valid_id(id) {
        eprintln!("burner: usage: burner kill burner-xxxxxxxxxxxx");
        return Ok(ExitCode::from(EXIT_USAGE));
    }
    // through sudo you can only kill what you started. real root can kill anything
    let caller: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
    // nothing is printed while the ledger is locked: a stalled stderr would hold it
    let refused = {
        let led = Ledger::open(&cfg.paths.state)?;
        match led.get(id) {
            None => Some("no VM with that id"),
            Some(v) if caller.is_some_and(|c| v.owner != Some(c)) => {
                Some("not yours, another user started it")
            }
            Some(_) => match led.update(id, |v| v.cancel = true)? {
                Some(_) => None,
                None => Some("no VM with that id"),
            },
        }
    };
    if let Some(why) = refused {
        eprintln!("burner: {id}: {why}");
        return Ok(ExitCode::from(1));
    }
    cgroup::kill(id);
    log_line(&format!("kill {id}"));
    // only say it's gone once its wrapper (or the reaper) has cleaned it up
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        if matches!(ledger::peek_strict(&cfg.paths.state, id), Ok(None)) {
            println!("killed {id}");
            return Ok(ExitCode::SUCCESS);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("burner: kill requested for {id}, still stopping (burner ls shows it)");
    Ok(ExitCode::from(1))
}

/// run every 30s from a timer: stop VMs past their deadline, clean up after
/// wrappers that died, keep the network filter current. the ledger lock is only
/// held for reads and the final deletes, never across subprocesses or file removal
pub fn reap(cfg: &Config) -> Result<ExitCode> {
    // one reaper at a time; a second one just leaves it to the first
    sys::private_dir(&cfg.paths.state)?;
    let Ok(_reaping) =
        sys::Lock::exclusive_until(&cfg.paths.state.join("reap.lock"), Instant::now())
    else {
        return Ok(ExitCode::SUCCESS);
    };
    let now = sys::boottime();
    let vms = Ledger::open(&cfg.paths.state)?.all();
    let known: Vec<String> = vms.iter().map(|v| v.id.clone()).collect();
    let mut done = Vec::new();
    for v in &vms {
        if !valid_id(&v.id) {
            continue;
        }
        if v.deadline_boot.is_some_and(|d| now > d + 5.0) {
            cgroup::kill(&v.id);
            // still setting up long past its time: something it ran is stuck
            // read again: the snapshot may be stale and the VM running by now
            let now_v = ledger::peek(&cfg.paths.state, &v.id);
            if v.status == Status::Preparing
                && now_v
                    .as_ref()
                    .is_some_and(|n| n.status == Status::Preparing)
                && let Some(w) = v.wrapper.as_ref()
                && sys::signal_ident(w, libc::SIGTERM)
            {
                log_line(&format!("reap {}: setup stuck, stopping its wrapper", v.id));
            }
        }
        if v.wrapper.as_ref().is_some_and(Ident::alive) {
            continue;
        }
        cgroup::kill(&v.id);
        let until = Instant::now() + Duration::from_secs(3);
        while cgroup::populated(&v.id) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        if cgroup::populated(&v.id) {
            continue;
        }
        // something that joined late makes the remove fail: then nothing is freed
        if !cgroup::remove(&v.id) {
            continue;
        }
        let tap_gone = v.net_slot.is_none_or(|i| net::tap_down(cfg, i));
        let jail = cfg.paths.root.join("jail/firecracker").join(&v.id);
        let run_gone = remove_tree(&cfg.paths.root.join("run").join(&v.id));
        done.push((v.id.clone(), remove_tree(&jail) && run_gone && tap_gone));
    }
    {
        let led = Ledger::open(&cfg.paths.state)?;
        for v in &vms {
            if !v.wrapper.as_ref().is_some_and(Ident::alive) && cgroup::populated(&v.id) {
                let _ = led.update(&v.id, |x| x.status = Status::CleanupFailed);
            }
        }
        for (id, clean) in &done {
            // only if nobody revived it meanwhile
            if led
                .get(id)
                .is_some_and(|v| !v.wrapper.as_ref().is_some_and(Ident::alive))
            {
                if *clean {
                    led.delete(id);
                    log_line(&format!("reap {id} (wrapper gone)"));
                } else {
                    let _ = led.update(id, |x| x.status = Status::CleanupFailed);
                }
            }
        }
    }
    let unix_now = SystemTime::now();
    let old = |p: &Path, secs: u64| {
        fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| unix_now.duration_since(t).ok())
            .is_some_and(|d| d.as_secs() > secs)
    };
    // an entry nobody can read would block admission forever. stop whatever runs
    // under its id, then move it aside as .bad; the orphan sweeps below take
    // care of its tap and jail
    let unreadable = Ledger::open(&cfg.paths.state)?.unreadable();
    for path in unreadable {
        let p = PathBuf::from(&path);
        let Some(id) = p
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| valid_id(s))
        else {
            continue;
        };
        cgroup::kill(id);
        let until = Instant::now() + Duration::from_secs(3);
        while cgroup::populated(id) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        if !cgroup::populated(id)
            && cgroup::remove(id)
            && fs::rename(&p, p.with_extension("bad")).is_ok()
        {
            log_line(&format!(
                "reap {id}: ledger entry unreadable, VM stopped, entry kept as {id}.bad"
            ));
        }
    }
    for i in net::reap_orphan_taps(cfg) {
        log_line(&format!("reap orphan tap {i}"));
    }
    for base in [
        cfg.paths.root.join("jail/firecracker"),
        PathBuf::from("/sys/fs/cgroup").join(cgroup::PARENT),
    ] {
        for e in fs::read_dir(&base)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
        {
            let name = e.file_name().to_string_lossy().into_owned();
            if !valid_id(&name) || known.contains(&name) || !old(&e.path(), 120) {
                continue;
            }
            cgroup::kill(&name);
            if !cgroup::populated(&name)
                && cgroup::remove(&name)
                && remove_tree(&cfg.paths.root.join("jail/firecracker").join(&name))
            {
                log_line(&format!("reap orphan {name}"));
            }
        }
    }
    for e in fs::read_dir(cfg.paths.root.join("run"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
    {
        // run dirs hold spooled input (up to 512M); drop them once their wrapper is gone
        let name = e.file_name().to_string_lossy().into_owned();
        if !valid_id(&name) || known.contains(&name) {
            continue;
        }
        let owner: Option<Ident> = fs::read(e.path().join("owner"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        if owner.as_ref().is_some_and(|o| !o.alive()) || (owner.is_none() && old(&e.path(), 600)) {
            remove_tree(&e.path());
        }
    }
    net::check(cfg);
    let _ = fs::write(
        cfg.paths.state.join(REAPED),
        format!("{}\n", sys::boottime()),
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_escape() {
        let run = |chunks: &[&[u8]]| {
            let (mut e, mut out) = (Escape::default(), Vec::new());
            let left = chunks.iter().any(|c| e.feed(c, &mut out));
            (left, out)
        };
        assert_eq!(run(&[b"~."]), (true, vec![]));
        assert!(run(&[b"ls\r", b"~", b"."]).0);
        assert_eq!(run(&[b"a~."]), (false, b"a~.".to_vec()));
        assert_eq!(run(&[b"~~x"]), (false, b"~x".to_vec()));
        assert_eq!(run(&[b"~x"]), (false, b"~x".to_vec()));
        assert_eq!(run(&[b"\r~."]), (true, b"\r".to_vec()));
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

    #[test]
    fn markers() {
        assert_eq!(
            find_at_line_start(b"xBEGIN\nBEGIN\n", b"BEGIN\n", true),
            Some(7)
        );
        assert_eq!(find_at_line_start(b"BEGIN\n", b"BEGIN\n", true), Some(0));
        assert_eq!(find_at_line_start(b"noise BEGIN\n", b"BEGIN\n", true), None);
        // after a trim, the buffer's first byte may sit mid-line
        assert_eq!(find_at_line_start(b"BEGIN\n", b"BEGIN\n", false), None);
        assert_eq!(
            find_at_line_start(b"BEGIN\nBEGIN\n", b"BEGIN\n", false),
            Some(6)
        );
    }
}
