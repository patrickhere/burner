use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::chown;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::json;

#[cfg(target_os = "macos")]
use super::admin::VM_DIRS;
use super::admin::{caller_uid, log_line, remove_tree, teardown};
use super::console::{Ended, ShellIo, deliver, print_rest, relay, stream, supervise};
use super::plan::{Input, Plan, RunArgs, plan};
use super::{
    Deadline, EXIT_INTERRUPTED, EXIT_SANDBOX, EXIT_TIMEOUT, EXIT_USAGE, Exit, Outcome, interrupted,
    is_interrupted, signals, usage,
};
use crate::cgroup;
use crate::config::{self, Config};
use crate::ledger::{self, Ident, Ledger, Status, Vm};
use crate::net;
use crate::output::{Dest, Out, escape_controls};
use crate::result;
use crate::sys;

const STDIN_CAP: u64 = 512 << 20;
const STDIN_TOTAL: Duration = Duration::from_secs(600);
const QUEUE_WAIT: Duration = Duration::from_secs(600);
const DELIVER_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(target_os = "linux")]
const VMM: &str = "firecracker";
#[cfg(target_os = "macos")]
const VMM: &str = "libkrun";
/// the guest init protocol this burner speaks (guest/init has the same number)
const GUEST_PROTO: u32 = 1;

/// how long the guest lets the job run: a little under the VM's limit, so a job
/// that runs long still gets its log and /out written before the host kills it
fn guest_limit(ttl: u32) -> u32 {
    ttl.saturating_sub((ttl / 4).clamp(5, 30)).max(1)
}

/// what the VM's cgroup may use on top of guest RAM: firecracker itself, plus
/// host page cache from writes to its disks, which is charged to the same cgroup
#[cfg(target_os = "linux")]
pub const VMM_OVERHEAD_MIB: u64 = 256;
/// past this much over guest RAM the kernel starts flushing and throttling the
/// VM's writes, long before the hard limit would kill firecracker
#[cfg(target_os = "linux")]
const VMM_SOFT_MIB: u64 = 64;
/// setup (disks, tap) has this long before the reaper stops the wrapper
const PREP_SECS: u32 = 180;

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
    // boot mode from the start: keys typed during setup wait for the VM and
    // ctrl-c works. the terminal comes back however main returns
    let _tty = a
        .shell
        .then(|| sys::ShellTty::take(crate::output::TERM_RESET));
    let t0 = Instant::now();
    let code = match run(cfg, &a) {
        Ok(code) => code,
        Err(e) => {
            if a.shell {
                sys::restore_saved_tty();
            }
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

fn run(cfg: &Config, a: &RunArgs) -> Result<u8> {
    #[cfg(target_os = "linux")]
    if !sys::is_root() {
        return Err(usage("burner run needs root (sudo burner run ...)"));
    }
    #[cfg(target_os = "macos")]
    if sys::is_root() {
        return Err(usage("on macOS burner runs as you, without sudo"));
    }
    // no reaper timer on macOS: each run first cleans up after dead ones, and
    // looks up the public address for net.block_public_ip before plan wants it
    #[cfg(target_os = "macos")]
    let _ = super::admin::reap(cfg);
    let p = plan(cfg, a)?;
    // the parser reads what a VM wrote, so it must never share an id with one
    #[cfg(target_os = "linux")]
    {
        let (pu, pg) = sys::user_ids(result::PARSE_USER)
            .with_context(|| format!("no {} user, see burner doctor", result::PARSE_USER))?;
        if cfg.vm_uids().contains(&pu) || cfg.vm_uids().contains(&pg) {
            anyhow::bail!(
                "{} has a uid or gid in the VM range (jail.uid_base), see burner doctor",
                result::PARSE_USER
            );
        }
    }
    let runs = cfg.paths.root.join("run");
    fs::create_dir_all(&runs)?;
    fs::set_permissions(&runs, fs::Permissions::from_mode(0o700))?;
    let (id, run_dir) = alloc_id(&runs)?;
    let _ = RUN_ID.set(id.clone());
    let mut vm = None;
    let res = run_vm(cfg, a, &p, &id, &run_dir, &mut vm);
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

fn run_vm(
    cfg: &Config,
    a: &RunArgs,
    p: &Plan,
    id: &str,
    run_dir: &Path,
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
    let idle = Duration::from_secs(u64::from(cfg.limits.stdin_idle_secs));
    let spool = spool_input(&run_dir.join("stdin"), a.input, idle)?;
    let job = run_dir.join("job.tar");
    // the job disk copies the spool before the spool goes away
    if let Some(sp) = &spool
        && !disk_left(run_dir, fs::metadata(sp)?.len())
    {
        return Err(Exit(EXIT_SANDBOX, "not enough disk to build the job disk".into()).into());
    }
    // a shell has no job: its job disk carries the caller's terminal size
    let size = sys::term_size(1).unwrap_or((24, 80));
    if p.shell {
        tty_disk(&job, size)?;
    } else {
        build_job(&job, &p.cmd, a.input, spool.as_deref())?;
    }

    let (net_slot, uid) = take_slot(cfg, p, id, &diag)?;
    *held = Some(());

    let Vmm {
        mut child,
        log: vmm_log,
        raw: raw_fd,
        token,
        deadline,
        tty_rec,
        // macnet goes with the VMM's group; this only waits for it at the end
        #[cfg(target_os = "macos")]
            net: _net,
    } = launch(cfg, p, id, &job, net_slot, uid, size)?;
    if p.shell {
        // an image built with another guest init doesn't say when its shell
        // is ready for keys
        let legacy = fs::read(cfg.paths.root.join("images").join(&p.img).join("init"))
            .ok()
            .as_deref()
            != Some(crate::doctor::GUEST_INIT);
        if legacy {
            diag.put(
                format!(
                    "burner: image {} was built with a different guest init, rebuild it: tools/build-image {}\n",
                    p.img, p.img
                )
                .as_bytes(),
                None,
            );
        }
        let io = ShellIo {
            legacy,
            tty_rec,
            size,
        };
        let sh = relay(&mut child, &token, deadline, cfg, id, io);
        // a signal since the relay stopped stops any wait on the caller's
        // terminal, the relay's own drain included
        let seen = sh.seen;
        sys::restore_saved_tty();
        let outcome = sh.outcome;
        if matches!(outcome, Outcome::Failed) {
            // the VM's dir and its log are gone after teardown
            let tail = tail_of(&vmm_log, 1500);
            log_line(&format!(
                "{id}: {VMM} failed: {}",
                String::from_utf8_lossy(&escape_controls(&tail)).trim()
            ));
        }
        teardown(cfg, id, Some(&mut child));
        *held = None;
        let (code, msg) = match outcome {
            // guest init passes on the shell's exit code. a VM that stopped
            // without saying so crashed or was reset under the shell
            Outcome::Done => match sh.end {
                Some(Ended::Exit(rc)) => {
                    set_status("exited", Some(i32::from(rc)));
                    (rc, None)
                }
                Some(Ended::Legacy) => {
                    set_status("exited", Some(0));
                    (0, None)
                }
                Some(Ended::PowerOff) => {
                    set_status("exited", Some(0));
                    (0, Some("the VM was powered off".into()))
                }
                Some(Ended::Reboot) => {
                    set_status("exited", Some(0));
                    (0, Some("the VM was rebooted, which ends it".into()))
                }
                Some(Ended::NoStart) => {
                    set_status("sandbox_error", None);
                    (EXIT_SANDBOX, Some("the guest shell couldn't start".into()))
                }
                Some(Ended::Lost) => {
                    set_status("sandbox_error", None);
                    (
                        EXIT_SANDBOX,
                        Some("the guest shell ended without an exit code".into()),
                    )
                }
                None => {
                    set_status("sandbox_error", None);
                    (
                        EXIT_SANDBOX,
                        Some("the VM stopped without the shell ending (a crash or a reset)".into()),
                    )
                }
            },
            Outcome::Detached => {
                set_status("detached", None);
                (0, Some("left the shell, VM stopped".into()))
            }
            Outcome::Failed => {
                set_status("sandbox_error", None);
                (
                    EXIT_SANDBOX,
                    Some("the VM stopped with an error, see the system log".into()),
                )
            }
            Outcome::Timeout => {
                set_status("timeout", None);
                let limit = if p.ttl.is_multiple_of(60) {
                    format!("{} min", p.ttl / 60)
                } else {
                    format!("{}s", p.ttl)
                };
                (
                    EXIT_TIMEOUT,
                    Some(format!("shell closed at the {limit} limit")),
                )
            }
            Outcome::Cancelled => {
                set_status("killed", None);
                (EXIT_INTERRUPTED, Some("killed by burner kill".into()))
            }
            Outcome::Interrupted => {
                set_status("interrupted", None);
                (EXIT_INTERRUPTED, Some("interrupted, VM stopped".into()))
            }
        };
        log_line(&format!(
            "end {id} tag={} secs={:.1} shell code={code}",
            p.tag,
            t0.elapsed().as_secs_f64()
        ));
        // the terminal reset goes out before any message. a caller's terminal
        // that stalled gets it once it reads again, the VM is gone by then. a
        // signal stops the wait, and then nothing more is written to it
        let give_up = || signals() > seen;
        sh.screen.wait_last(give_up);
        if let Some(m) = msg
            && !give_up()
        {
            diag.put(format!("burner: {m}\n").as_bytes(), None);
            diag.settle(give_up);
        }
        return Ok(code);
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
                tail_of(&vmm_log, 1500)
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
                diag.put(format!("burner: {VMM}: ").as_bytes(), None);
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
            if meta.timed_out {
                diag.put(
                    format!(
                        "burner: stopped at the {}s time limit, the output and /out up to then are above\n",
                        p.ttl
                    )
                    .as_bytes(),
                    None,
                );
                code = EXIT_TIMEOUT;
                set_status("timeout", None);
            }
            // an image built from another burner's guest init: its results can't be trusted
            if meta.rc.is_some() && meta.proto != Some(GUEST_PROTO) {
                diag.put(
                    format!(
                        "burner: image {} runs a guest init from another burner version, rebuild it: tools/build-image {}\n",
                        p.img, p.img
                    )
                    .as_bytes(),
                    None,
                );
                code = EXIT_SANDBOX;
                set_status("sandbox_error", None);
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

/// a started VM: its VMM process, that VMM's log, the result disk (opened
/// before the VM could touch it) and what the console markers are keyed on
struct Vmm {
    child: Child,
    log: PathBuf,
    raw: File,
    token: String,
    deadline: Deadline,
    /// a shell's job disk, opened for writing before the VM could touch it:
    /// relay writes the terminal size there
    tty_rec: Option<File>,
    #[cfg(target_os = "macos")]
    net: Option<crate::macnet::Proc>,
}

/// set up the jail and start firecracker under the jailer
#[cfg(target_os = "linux")]
fn launch(
    cfg: &Config,
    p: &Plan,
    id: &str,
    job: &Path,
    net_slot: Option<u32>,
    uid: u32,
    size: (u16, u16),
) -> Result<Vmm> {
    let jail = cfg.paths.root.join("jail").join("firecracker").join(id);
    let root = jail.join("root");
    fs::create_dir_all(jail.parent().context("jail path")?)?;
    // only root walks these: firecracker sees nothing above its chroot. the job
    // tar and the VM config sit in here before the jailer locks the root down,
    // and other users on the host must not read them meanwhile
    for d in [
        cfg.paths.root.join("jail"),
        cfg.paths.root.join("jail/firecracker"),
    ] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    // fresh dirs only: a jail left over from anything else is never reused
    fs::create_dir(&jail).context("creating the jail (left over from an earlier run?)")?;
    fs::create_dir(&root)?;
    for d in [&jail, &root] {
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    // hard links, not copies: instant, and the jailer can't follow a symlink out.
    // that needs the kernel, images and jail on one filesystem under paths.root
    let same_fs = "the kernel, images and jail dirs have to be on one filesystem (paths.root)";
    fs::hard_link(
        fs::canonicalize(cfg.paths.root.join("kernel/vmlinux"))?,
        root.join("vmlinux"),
    )
    .context(same_fs)?;
    fs::hard_link(
        cfg.paths
            .root
            .join("images")
            .join(&p.img)
            .join("rootfs.ext4"),
        root.join("rootfs.ext4"),
    )
    .context(same_fs)?;
    fs::rename(job, root.join("job.tar"))?;
    // opened before anything runs as the VM's uid, like the result disk
    let tty_rec = if p.shell {
        Some(OpenOptions::new().write(true).open(root.join("job.tar"))?)
    } else {
        None
    };
    chown(root.join("job.tar"), Some(uid), Some(uid))?;
    let scratch = root.join("scratch.ext4");
    reserve(cfg, &scratch, u64::from(p.disk_gib) << 30)?;
    prep_ok(cfg, id)?;
    mkfs(&scratch, cfg, id)?;
    let raw = root.join("result.raw");
    reserve(cfg, &raw, result::RESULT_SIZE)?;
    // opened now, before anything runs as the VM's uid, and read through this fd
    // later: the path inside the jail can't be swapped for something else
    let raw_fd = File::open(&raw)?;
    for f in [&scratch, &raw] {
        chown(f, Some(uid), Some(uid))?;
        fs::set_permissions(f, fs::Permissions::from_mode(0o600))?;
    }

    prep_ok(cfg, id)?;
    let token = sys::random_hex(8)?;
    let mut boot = format!(
        "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=1 init=/sbin/burner-init burner.token={token} burner.proto={GUEST_PROTO}"
    );
    if !p.shell {
        boot += &format!(" burner.limit={}", guest_limit(p.ttl));
    }
    let mut ifaces = Vec::new();
    if let Some(i) = net_slot {
        let s = net::tap_up(cfg, i, p.net, uid)?;
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
    if p.shell {
        boot += &shell_args(size);
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
    fs::set_permissions(root.join("vm.json"), fs::Permissions::from_mode(0o600))?;
    chown(root.join("vm.json"), Some(uid), Some(uid))?;

    let deadline = Deadline::in_secs(p.ttl);
    let procs = cgroup::prepare(id).context("creating the VM's cgroup")?;
    go_live(cfg, id, deadline)?;
    let fclog = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(jail.join("firecracker.log"))?;
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
    // no --new-pid-ns: with it the jailer exits right after cloning firecracker,
    // and burner watches this child's exit and status as the VM's
    let child = jailer
        .args(["--id", id, "--exec-file"])
        .arg(bin.join("firecracker"))
        .args([
            "--uid",
            &uid.to_string(),
            "--gid",
            &uid.to_string(),
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
    Ok(Vmm {
        child,
        log: jail.join("firecracker.log"),
        raw: raw_fd,
        token,
        deadline,
        tty_rec,
    })
}

/// macOS: no jailer, no chroot, no uid of its own. the VM's dir holds its
/// disks, libkrun opens the kernel and image where they are, and the VMM is
/// this binary again (vmm-krun) in its own process group
#[cfg(target_os = "macos")]
fn launch(
    cfg: &Config,
    p: &Plan,
    id: &str,
    job: &Path,
    net_slot: Option<u32>,
    _uid: u32,
    size: (u16, u16),
) -> Result<Vmm> {
    let vms = cfg.paths.root.join(VM_DIRS);
    let dir = vms.join(id);
    sys::private_dir(&vms)?;
    // fresh dirs only: a VM dir left over from anything else is never reused
    fs::create_dir(&dir).context("creating the VM's dir (left over from an earlier run?)")?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let kernel = fs::canonicalize(cfg.paths.root.join("kernel/vmlinux")).with_context(|| {
        format!(
            "no kernel at {}",
            cfg.paths.root.join("kernel/vmlinux").display()
        )
    })?;
    let rootfs = fs::canonicalize(
        cfg.paths
            .root
            .join("images")
            .join(&p.img)
            .join("rootfs.ext4"),
    )?;
    for f in [&kernel, &rootfs] {
        config::trusted_file(f)?;
    }
    let job_disk = dir.join("job.tar");
    fs::rename(job, &job_disk)?;
    let tty_rec = if p.shell {
        Some(OpenOptions::new().write(true).open(&job_disk)?)
    } else {
        None
    };
    let scratch = dir.join("scratch.ext4");
    reserve(cfg, &scratch, u64::from(p.disk_gib) << 30)?;
    prep_ok(cfg, id)?;
    mkfs(&scratch, cfg, id)?;
    let raw = dir.join("result.raw");
    reserve(cfg, &raw, result::RESULT_SIZE)?;
    let raw_fd = File::open(&raw)?;
    for f in [&scratch, &raw] {
        fs::set_permissions(f, fs::Permissions::from_mode(0o600))?;
    }

    prep_ok(cfg, id)?;
    let token = sys::random_hex(8)?;
    // hvc0 is libkrun's virtio console, guest init puts the shell on it too
    let mut boot = format!(
        "console=hvc0 reboot=k panic=1 pci=off quiet loglevel=1 root=/dev/vda ro init=/sbin/burner-init burner.token={token} burner.proto={GUEST_PROTO}"
    );
    if !p.shell {
        boot += &format!(" burner.limit={}", guest_limit(p.ttl));
    }
    // the same addresses as on linux, though each VM is alone on its wire
    let net = match net_slot {
        Some(i) => {
            let s = net::slot(cfg, i)?;
            let dns: Vec<String> = cfg.net.resolvers.iter().map(|r| r.to_string()).collect();
            boot += &format!(
                " ip={}::{}:255.255.255.252:burner:eth0:off burner.dns={}",
                s.guest,
                s.host,
                dns.join(",")
            );
            let (vm_end, net_end) = crate::macnet::pair().context("the VM's network socket")?;
            Some((s, vm_end, net_end))
        }
        None => None,
    };
    if p.shell {
        boot += &shell_args(size);
    }

    let deadline = Deadline::in_secs(p.ttl);
    let procs = cgroup::prepare(id).context("creating the VM's record dir")?;
    go_live(cfg, id, deadline)?;
    let log = dir.join("vmm.log");
    let vlog = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&log)?;
    let mut vmm = Command::new(sys::self_exe());
    // own process group so a ctrl-c meant for burner doesn't hit the VM first,
    // and so kill takes the group
    vmm.process_group(0);
    let me = std::process::id() as libc::pid_t;
    let vm_fd = net.as_ref().map(|(_, v, _)| v.as_raw_fd());
    let fds = sys::open_fds().context("listing open fds")?;
    // SAFETY: join_from_child only calls getppid, close_strays and inherit
    // only fcntl and close
    unsafe {
        vmm.pre_exec(move || {
            cgroup::join_from_child(&procs, me)?;
            sys::close_strays(&fds, vm_fd.as_slice());
            vm_fd.map_or(Ok(()), crate::macnet::inherit)
        });
    }
    let net_log = vlog.try_clone()?;
    let mut child = vmm
        .arg("vmm-krun")
        .arg("--kernel")
        .arg(&kernel)
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--scratch")
        .arg(&scratch)
        .arg("--job")
        .arg(&job_disk)
        .arg("--result")
        .arg(&raw)
        .args(["--cpus", &p.vcpus.min(255).to_string()])
        .args(["--mem", &p.mem_mib.to_string()])
        .args(["--cmdline", &boot])
        // the VMM's own backstop, when the reaper would have stopped it on linux
        .args(["--until", &format!("{:.1}", deadline.0 + 5.0)])
        .args(p.shell.then_some("--stdin"))
        .args(
            vm_fd
                .iter()
                .flat_map(|fd| ["--net-fd".to_string(), fd.to_string()]),
        )
        .stdin(if p.shell {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(vlog)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir("/")
        .spawn()
        .context("starting the VMM")?;
    if let Err(e) = cgroup::record(id, child.id()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e).context("recording the VMM");
    }
    let net = match net {
        Some((s, vm_end, net_end)) => {
            // the VMM holds its end now. ours has to go, or macnet would never
            // see it close when the VM stops
            drop(vm_end);
            let started = crate::macnet::spawn(cfg, p.net, &s, net_end, child.id(), net_log)
                .and_then(|n| cgroup::record_net(id, n.id()).map(|()| n));
            match started {
                Ok(n) => Some(n),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e).context("starting the VM's network");
                }
            }
        }
        None => None,
    };
    Ok(Vmm {
        child,
        log,
        raw: raw_fd,
        token,
        deadline,
        tty_rec,
        net,
    })
}

/// what guest init needs to run a shell on the caller's terminal
fn shell_args((rows, cols): (u16, u16)) -> String {
    let term = std::env::var("TERM").ok().filter(|t| {
        !t.is_empty()
            && t.len() <= 32
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
    });
    format!(
        " burner.shell=1 burner.tty={rows}x{cols} burner.term={}",
        term.as_deref().unwrap_or("xterm")
    )
}

/// the last check before the VM starts, and the switch to running with its deadline
fn go_live(cfg: &Config, id: &str, deadline: Deadline) -> Result<()> {
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
    Ok(())
}

/// read the caller's stdin before taking a slot, with idle and total deadlines
fn spool_input(path: &Path, mode: Input, idle: Duration) -> Result<Option<PathBuf>> {
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
        if last.elapsed() > idle {
            return Err(usage(format!(
                "no input for {}s (does the pipe ever close?)",
                idle.as_secs()
            )));
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

/// a shell's job disk: its first line is the caller's terminal size, which
/// relay rewrites when the terminal is resized and guest init polls
fn tty_disk(path: &Path, size: (u16, u16)) -> Result<()> {
    let f = File::create(path)?;
    f.set_len(1 << 20)?;
    super::console::write_size(&f, 0, size)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
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
    fs::set_permissions(job, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// the lowest of 0..n not in `taken`
fn first_free(taken: &[u32], n: u32) -> Option<u32> {
    (0..n).find(|i| !taken.contains(i))
}

/// a uid no VM in the ledger holds. entries from before VMs had their own uid
/// hold none
fn free_uid(cfg: &Config, vms: &[Vm]) -> Option<u32> {
    let base = cfg.jail.uid_base;
    let taken: Vec<u32> = vms
        .iter()
        .filter_map(|v| v.uid?.checked_sub(base))
        .collect();
    first_free(&taken, config::VM_UIDS).map(|i| base + i)
}

/// wait for room, then write the VM's ledger entry with its network slot (if
/// it has a network) and its uid
fn take_slot(cfg: &Config, p: &Plan, id: &str, diag: &Out) -> Result<(Option<u32>, u32)> {
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
        uid: None,
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
                    let taken: Vec<u32> = busy.iter().filter_map(|v| v.net_slot).collect();
                    vm.net_slot =
                        Some(first_free(&taken, cfg.net_slots()?).context("no free network slot")?);
                }
                let uid = free_uid(cfg, &busy).context("no free VM uid")?;
                vm.uid = Some(uid);
                if !led.create(&vm)? {
                    anyhow::bail!("run id collision");
                }
                log_line(&format!(
                    "start {id} by uid {} as uid {uid} tag={} img={} vcpus={} mem={} disk={} ttl={} net={} shell={}",
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
                return Ok((vm.net_slot, uid));
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
    // its own process group: a ctrl-c is burner's to handle (prep_ok stops
    // mkfs), not a mkfs failure
    let mut c = Command::new(mkfs_bin())
        .process_group(0)
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

#[cfg(target_os = "linux")]
fn mkfs_bin() -> PathBuf {
    "mkfs.ext4".into()
}

/// homebrew's e2fsprogs is keg-only, so mkfs.ext4 is usually not on PATH
#[cfg(target_os = "macos")]
pub fn mkfs_bin() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(
            [
                "/opt/homebrew/opt/e2fsprogs/sbin",
                "/usr/local/opt/e2fsprogs/sbin",
            ]
            .map(PathBuf::from),
        )
        .map(|d| d.join("mkfs.ext4"))
        .find(|p| p.is_file())
        .unwrap_or_else(|| "mkfs.ext4".into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_limits() {
        assert_eq!(guest_limit(10), 5);
        assert_eq!(guest_limit(60), 45);
        assert_eq!(guest_limit(3600), 3570);
        assert_eq!(guest_limit(3), 1);
    }

    #[test]
    fn free_slots() {
        assert_eq!(first_free(&[], 4), Some(0));
        assert_eq!(first_free(&[0, 2], 4), Some(1));
        assert_eq!(first_free(&[1, 0, 2], 4), Some(3));
        assert_eq!(first_free(&[0, 1, 2, 3], 4), None);
    }

    #[test]
    fn vm_uids() {
        let cfg = Config::default();
        let base = cfg.jail.uid_base;
        let vm = |uid: Option<u32>| Vm {
            uid,
            ..Vm::default()
        };
        assert_eq!(free_uid(&cfg, &[]), Some(base));
        // a VM without a network still takes a uid, and an old entry with none
        // or one from another uid_base doesn't block one
        assert_eq!(
            free_uid(&cfg, &[vm(Some(base)), vm(None), vm(Some(5000))]),
            Some(base + 1)
        );
        assert_eq!(
            free_uid(&cfg, &[vm(Some(base + 1)), vm(Some(base))]),
            Some(base + 2)
        );
        assert_eq!(
            free_uid(&cfg, &[vm(Some(base)), vm(Some(base + 2))]),
            Some(base + 1)
        );
        let full: Vec<Vm> = cfg.vm_uids().map(|u| vm(Some(u))).collect();
        assert_eq!(free_uid(&cfg, &full), None);
    }
}
