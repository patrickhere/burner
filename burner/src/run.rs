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
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;
use serde_json::json;

use crate::cgroup;
use crate::config::Config;
use crate::ledger::{Ident, Ledger, Vm, valid_id};
use crate::output::{Dest, Out, escape_controls};
use crate::result;
use crate::sys;

const USER: &str = "burner";
const SERIAL_CAP: u64 = 1 << 20;
const LIVE_BYTES: u64 = 65536;
const STDIN_CAP: u64 = 512 << 20;
const STDIN_IDLE: Duration = Duration::from_secs(60);
const STDIN_TOTAL: Duration = Duration::from_secs(600);
const CMD_CAP: usize = 64 << 10;
const QUEUE_WAIT: Duration = Duration::from_secs(600);
const DELIVER_TIMEOUT: Duration = Duration::from_secs(300);
const VMM_OVERHEAD_MIB: u64 = 128;

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
    /// one argument runs as a shell string; several are quoted as they are
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    cmd: Vec<String>,
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
    let ttl = match &a.ttl {
        Some(t) => parse_ttl(t, l.ttl_secs)?,
        None => d.ttl_secs.unwrap_or(600).clamp(10, l.ttl_secs),
    };
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
    Ok(Plan {
        img: a.img.clone(),
        vcpus,
        mem_mib,
        disk_gib,
        ttl,
        tag,
        cmd,
    })
}

pub fn main(cfg: &Config, a: RunArgs) -> ExitCode {
    interrupted();
    match run(cfg, &a) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("burner: {e:#}");
            match e.downcast_ref::<Exit>() {
                Some(Exit(code, _)) => ExitCode::from(*code),
                None => ExitCode::from(EXIT_SANDBOX),
            }
        }
    }
}

enum Outcome {
    Done,
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
    let mut vm = None;
    let res = run_vm(cfg, a, &p, &id, &run_dir, uid, gid, &mut vm);
    if vm.is_some() {
        teardown(cfg, &id, None);
    }
    let _ = fs::remove_dir_all(&run_dir);
    res
}

fn alloc_id(runs: &Path) -> Result<(String, PathBuf)> {
    for _ in 0..5 {
        let id = format!("burner-{}", sys::random_hex(6)?);
        let dir = runs.join(&id);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok((id, dir)),
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

    let spool = spool_input(&run_dir.join("stdin"), a.input)?;
    let job = run_dir.join("job.tar");
    build_job(&job, &p.cmd, a.input, spool.as_deref())?;

    take_slot(cfg, p, id)?;
    *held = Some(());

    let jail = cfg.paths.root.join("jail").join("firecracker").join(id);
    let root = jail.join("root");
    fs::create_dir_all(&root)?;
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
    sparse(&scratch, u64::from(p.disk_gib) << 30)?;
    mkfs(&scratch)?;
    let raw = root.join("result.raw");
    sparse(&raw, result::RESULT_SIZE)?;
    for f in [&scratch, &raw] {
        chown(f, Some(uid), Some(gid))?;
        fs::set_permissions(f, fs::Permissions::from_mode(0o600))?;
    }

    let token = sys::random_hex(8)?;
    let drive = |id: &str, path: &str, ro: bool, mbps: u64, ops: u64| {
        json!({"drive_id": id, "path_on_host": path, "is_root_device": id == "rootfs", "is_read_only": ro,
               "rate_limiter": {"bandwidth": {"size": mbps << 20, "refill_time": 1000},
                                "ops": {"size": ops, "refill_time": 1000}}})
    };
    let vmcfg = json!({
        "boot-source": {"kernel_image_path": "vmlinux",
            "boot_args": format!("console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=1 init=/sbin/burner-init burner.token={token}")},
        "drives": [drive("rootfs", "rootfs.ext4", true, 200, 5000), drive("scratch", "scratch.ext4", false, 100, 3000),
                   drive("job", "job.tar", true, 200, 3000), drive("result", "result.raw", false, 100, 3000)],
        "machine-config": {"vcpu_count": p.vcpus, "mem_size_mib": p.mem_mib},
    });
    fs::write(root.join("vm.json"), serde_json::to_vec(&vmcfg)?)?;
    fs::set_permissions(root.join("vm.json"), fs::Permissions::from_mode(0o644))?;

    let deadline = Instant::now() + Duration::from_secs(u64::from(p.ttl));
    {
        let led = Ledger::open(&cfg.paths.state)?;
        let cur = led.get(id).context("ledger entry vanished")?;
        if cur.cancel {
            return Err(Exit(EXIT_INTERRUPTED, "cancelled before start".into()).into());
        }
        led.update(id, |v| {
            v.status = "running".into();
            v.deadline_boot = Some(sys::boottime() + f64::from(p.ttl));
        })?;
    }
    if is_interrupted() {
        return Err(Exit(EXIT_INTERRUPTED, "interrupted, sandbox stopped".into()).into());
    }
    let fclog = File::create(jail.join("firecracker.log"))?;
    let mut child = Command::new(cfg.paths.root.join("bin/jailer"))
        .args(["--id", id, "--exec-file"])
        .arg(cfg.paths.root.join("bin/firecracker"))
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(fclog)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .process_group(0)
        .spawn()
        .context("starting the jailer")?;
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
        Outcome::Timeout | Outcome::Cancelled | Outcome::Interrupted => {
            teardown(cfg, id, Some(&mut child));
            *held = None;
            match outcome {
                Outcome::Timeout => {
                    diag.put(
                        format!("burner: killed at the {}s time limit\n", p.ttl).as_bytes(),
                        None,
                    );
                    EXIT_TIMEOUT
                }
                Outcome::Cancelled => {
                    diag.put(b"burner: killed by burner kill\n", None);
                    EXIT_INTERRUPTED
                }
                _ => {
                    diag.put(b"burner: interrupted, sandbox stopped\n", None);
                    EXIT_INTERRUPTED
                }
            }
        }
        Outcome::Done => {
            let log = run_dir.join("log.bin");
            let tar_path = run_dir.join("result.tar");
            let meta = result::parse(&raw, &log, a.result.map(|_| tar_path.as_path()), uid, gid);
            let fc_tail = if meta.rc.is_none() {
                tail_of(&jail.join("firecracker.log"), 1500)
            } else {
                Vec::new()
            };
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
            if let (Some(out), false) = (&tar_out, meta.fatal) {
                deliver(&tar_path, out, until);
                if out.dropped() {
                    diag.put(
                        b"burner: result tar not fully delivered (reader too slow)\n",
                        None,
                    );
                }
            }
            meta.rc.map(|rc| rc as u8).unwrap_or(EXIT_SANDBOX)
        }
    };
    let until = Instant::now() + Duration::from_secs(30);
    live.drain(until);
    diag.drain(until);
    if let Some(o) = &tar_out {
        o.drain(until);
    }
    if live.dropped() {
        eprintln!("burner: some live output was dropped (reader too slow)");
    }
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

fn take_slot(cfg: &Config, p: &Plan, id: &str) -> Result<()> {
    let l = &cfg.limits;
    let vm = Vm {
        id: id.into(),
        tag: p.tag.clone(),
        img: p.img.clone(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        disk_gib: p.disk_gib,
        net: "none".into(),
        ttl_secs: p.ttl,
        wrapper: Some(Ident::me()),
        status: "preparing".into(),
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
            let busy: Vec<_> = led.all().into_iter().filter(Vm::holds_slot).collect();
            let used: u32 = busy.iter().map(|v| v.mem_mib).sum();
            if (busy.len() as u32) < l.max_vms && used + p.mem_mib <= l.total_mem_mib {
                if !led.create(&vm)? {
                    anyhow::bail!("run id collision");
                }
                log_line(&format!(
                    "start {id} tag={} img={} vcpus={} mem={} disk={} ttl={}",
                    p.tag, p.img, p.vcpus, p.mem_mib, p.disk_gib, p.ttl
                ));
                return Ok(());
            }
            if !waited {
                eprintln!(
                    "burner: waiting for a slot ({} running, {used} of {} MiB in use)",
                    busy.len(),
                    l.total_mem_mib
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

fn sparse(path: &Path, size: u64) -> Result<()> {
    File::create(path)?.set_len(size)?;
    Ok(())
}

fn mkfs(path: &Path) -> Result<()> {
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
        if start.elapsed() > Duration::from_secs(60) {
            let _ = c.kill();
            anyhow::bail!("mkfs.ext4 hung");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// copy the console between the BEGIN/END markers to `out`, byte for byte
#[allow(clippy::too_many_arguments)]
fn stream(
    stdout: &mut ChildStdout,
    child: &mut Child,
    token: &str,
    deadline: Instant,
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
    let (mut buf, mut pending) = (Vec::new(), Vec::new());
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
        let now = Instant::now();
        if now >= deadline {
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
        if !sys::readable(fd, (deadline - now).min(Duration::from_secs(1))) {
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
        raw_total += n as u64;
        if raw_total > SERIAL_CAP {
            if st == St::Body {
                flush_held(&mut held_nl);
                diag.put(b"burner: console over 1M, live output stopped\n", None);
                st = St::Capped;
            }
            continue;
        }
        match st {
            St::Pre => {
                buf.extend_from_slice(&chunk[..n]);
                let found = find_at_line_start(&buf, &begin);
                let Some(i) = found else {
                    let keep = 8192 + begin.len();
                    if buf.len() > keep {
                        buf.drain(..buf.len() - keep);
                    }
                    continue;
                };
                st = St::Body;
                pending = buf.split_off(i + begin.len());
                buf.truncate(i);
            }
            St::Body => pending.extend_from_slice(&chunk[..n]),
            _ => continue,
        }
        while st == St::Body {
            let Some(nl) = pending.iter().position(|&b| b == b'\n') else {
                if !pending.is_empty() && !(at_line_start && end_n.starts_with(&pending)) {
                    flush_held(&mut held_nl);
                    out.put(&pending, None);
                    at_line_start = false;
                    pending.clear();
                }
                break;
            };
            let line: Vec<u8> = pending.drain(..=nl).collect();
            let line = &line[..line.len() - 1];
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
        let tail = &buf[buf.len().saturating_sub(2000)..];
        diag.put(&escape_controls(tail), None);
        diag.put(b"\n", None);
    }
    Outcome::Done
}

fn find_at_line_start(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(off) = hay[from..].windows(needle.len()).position(|w| w == needle) {
        let i = from + off;
        if i == 0 || hay[i - 1] == b'\n' {
            return Some(i);
        }
        from = i + 1;
    }
    None
}

fn cancelled(cfg: &Config, id: &str) -> bool {
    Ledger::open(&cfg.paths.state)
        .ok()
        .and_then(|l| l.get(id))
        .is_none_or(|v| v.cancel)
}

/// after the console closed: the VM must be gone before its result disk is read
fn supervise(child: &mut Child, deadline: Instant, cfg: &Config, id: &str) -> Outcome {
    let mut next_check = Instant::now();
    while !matches!(child.try_wait(), Ok(Some(_))) {
        let now = Instant::now();
        if now >= deadline {
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
    }
    let end = Instant::now() + Duration::from_secs(5);
    while cgroup::populated(id) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    if cgroup::populated(id) {
        cgroup::kill(id);
        return Outcome::Timeout;
    }
    Outcome::Done
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
    let Ok(led) = Ledger::open(&cfg.paths.state) else {
        return false;
    };
    if !stopped {
        let _ = led.update(id, |v| v.status = "cleanup-failed".into());
        log_line(&format!(
            "teardown {id}: VM did not stop, slot kept for the reaper"
        ));
        return false;
    }
    cgroup::remove(id);
    let jail = cfg.paths.root.join("jail").join("firecracker").join(id);
    if jail.exists() && fs::remove_dir_all(&jail).is_err() {
        let _ = led.update(id, |v| {
            v.status = "cleanup-failed".into();
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
        s if s < LIVE_BYTES => LIVE_BYTES - s,
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

fn deliver(path: &Path, out: &Out, until: Instant) {
    if let Ok(mut f) = File::open(path) {
        deliver_from(&mut f, out, until);
    }
}

fn deliver_from(f: &mut File, out: &Out, until: Instant) {
    let mut buf = vec![0u8; 1 << 20];
    while let Ok(n) = f.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.put(&buf[..n], Some(until));
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

pub fn log_line(msg: &str) {
    // journald picks this up via the logger tool; a missing logger isn't worth failing over
    let _ = Command::new("logger")
        .args(["-t", "burner", msg])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

// ---- ls, kill, reap ----

pub fn ls(cfg: &Config, json_out: bool) -> Result<ExitCode> {
    let now = sys::boottime();
    let mut vms: Vec<_> = Ledger::open(&cfg.paths.state)?
        .all()
        .into_iter()
        .filter(Vm::holds_slot)
        .collect();
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
                       "net": v.net, "status": v.status, "age": unix.saturating_sub(v.started), "ttl": v.ttl_secs,
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
            v.status,
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
    let led = Ledger::open(&cfg.paths.state)?;
    if led.update(id, |v| v.cancel = true)?.is_none() {
        eprintln!("burner: no VM {id}");
        return Ok(ExitCode::from(1));
    }
    cgroup::kill(id);
    log_line(&format!("kill {id}"));
    println!("killed {id}");
    Ok(ExitCode::SUCCESS)
}

/// run every minute from a timer: stop VMs past their deadline, clean up after wrappers that died
pub fn reap(cfg: &Config) -> Result<ExitCode> {
    let now = sys::boottime();
    let led = Ledger::open(&cfg.paths.state)?;
    let known: Vec<String> = led.all().iter().map(|v| v.id.clone()).collect();
    for v in led.all() {
        if !valid_id(&v.id) {
            continue;
        }
        if v.deadline_boot.is_some_and(|d| now > d + 60.0) {
            cgroup::kill(&v.id);
        }
        if !v.wrapper.as_ref().is_some_and(Ident::alive) {
            cgroup::kill(&v.id);
            if cgroup::populated(&v.id) {
                let _ = led.update(&v.id, |x| x.status = "cleanup-failed".into());
                continue;
            }
            cgroup::remove(&v.id);
            let jail = cfg.paths.root.join("jail/firecracker").join(&v.id);
            if !jail.exists() || fs::remove_dir_all(&jail).is_ok() {
                led.delete(&v.id);
                log_line(&format!("reap {} (wrapper gone)", v.id));
            } else {
                let _ = led.update(&v.id, |x| x.status = "cleanup-failed".into());
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
            if !cgroup::populated(&name) {
                cgroup::remove(&name);
                let _ = fs::remove_dir_all(cfg.paths.root.join("jail/firecracker").join(&name));
                log_line(&format!("reap orphan {name}"));
            }
        }
    }
    for e in fs::read_dir(cfg.paths.root.join("run"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if valid_id(&name) && !known.contains(&name) && old(&e.path(), 86400) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
    Ok(ExitCode::SUCCESS)
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

    #[test]
    fn markers() {
        assert_eq!(find_at_line_start(b"xBEGIN\nBEGIN\n", b"BEGIN\n"), Some(7));
        assert_eq!(find_at_line_start(b"BEGIN\n", b"BEGIN\n"), Some(0));
        assert_eq!(find_at_line_start(b"noise BEGIN\n", b"BEGIN\n"), None);
    }
}
