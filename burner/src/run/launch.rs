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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use serde_json::json;

#[cfg(target_os = "macos")]
use super::admin::VM_DIRS;
use super::admin::{caller_uid, log_line, remove_tree, teardown};
use super::console::{Ended, ShellIo, deliver, print_rest, relay, stream, supervise};
use super::plan::{Input, Plan, RunArgs, plan};
use super::record::{self, Mark, OutputInfo, RunOutcome, ShellEnd, TarInfo, VmInfo};
use super::{
    Deadline, EXIT_INTERRUPTED, EXIT_SANDBOX, EXIT_TIMEOUT, EXIT_USAGE, Exit, Outcome, exit,
    interrupted, is_interrupted, signals, usage,
};
use crate::cgroup;
use crate::config::{self, Config};
use crate::json::{self, Kind, Problem};
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
pub const VMM: &str = "firecracker";
#[cfg(target_os = "macos")]
pub const VMM: &str = "libkrun";
/// the guest init protocol this burner speaks (guest/init has the same number)
pub const GUEST_PROTO: u32 = 1;

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

/// with --json stdout is the json's, and burner's own lines are only in it
fn quiet() -> bool {
    json::on()
}

/// where the json goes, if anywhere
fn json_target(a: &RunArgs) -> Option<i32> {
    if quiet() { Some(1) } else { a.json_fd }
}

/// open for writing, so the line at the end isn't lost after the VM ran
fn writable(fd: i32) -> bool {
    // SAFETY: F_GETFL only reads the fd's flags, a bad fd gives -1
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    fl != -1 && matches!(fl & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
}

/// 2, or a writable fd above 2, now close-on-exec so it never reaches the
/// VM's processes (stderr is passed explicitly anyway)
fn fd_ok(fd: i32) -> bool {
    // SAFETY: fcntl only inspects and flags the fd
    fd >= 2
        && writable(fd)
        && (fd == 2 || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0)
}

/// the fds and the flags that write to stdout, checked before the config
/// loads so a run that fails that early still writes its status line and json.
/// Some(exit) when the run can't go ahead
pub fn check_fds(a: &RunArgs, t0: Instant) -> Option<ExitCode> {
    let status_ok = a.status_fd.is_none_or(fd_ok);
    let json_ok = match json_target(a) {
        Some(1) => writable(1),
        Some(fd) => fd_ok(fd),
        None => true,
    };
    let tar_out = "--result tar writes the tar to stdout, use --json-fd 2 for the json";
    let msg = match (a.status_fd, a.json_fd) {
        _ if a.shell && quiet() => {
            "burner shell has the terminal, use --json-fd N for the json".into()
        }
        (Some(fd), _) if !status_ok => {
            format!("--status-fd {fd} isn't open for writing (2, or above 2)")
        }
        (_, Some(fd)) if !json_ok => {
            format!("--json-fd {fd} isn't open for writing (1, 2, or above 2)")
        }
        (_, None) if !json_ok => "--json needs stdout open for writing".into(),
        (_, Some(_)) if quiet() => {
            "--json writes to stdout, --json-fd to another fd: pick one".into()
        }
        _ if a.result.is_some() && json_target(a) == Some(1) => tar_out.into(),
        _ => return None,
    };
    // with nowhere to put the json, stderr is all that's left
    if !quiet() || !json_ok {
        eprintln!("burner: {msg}");
    }
    let why = Problem {
        kind: Kind::Usage,
        message: msg,
    };
    let f = record::finish(t0, EXIT_USAGE, Some(why));
    if let (true, Some(fd)) = (status_ok, a.status_fd) {
        json::write_fd(fd, &f.status_line());
    }
    if let (true, Some(fd)) = (json_ok, json_target(a)) {
        json::write_fd(fd, &envelope(a, f));
    }
    Some(ExitCode::from(EXIT_USAGE))
}

/// a usage error found after the fds were checked, before anything started
pub(super) fn refuse(a: &RunArgs, kind: Kind, msg: String) -> ExitCode {
    if !quiet() {
        eprintln!("burner: {msg}");
    }
    let why = Problem { kind, message: msg };
    finished(a, record::finish(Instant::now(), EXIT_USAGE, Some(why)))
}

/// a run whose config didn't load: no result, so 125 like any other sandbox failure
pub fn config_failed(a: &RunArgs, e: &anyhow::Error, t0: Instant) -> ExitCode {
    let msg = format!("{e:#}");
    if !quiet() {
        eprintln!("burner: {msg}");
    }
    let why = Problem {
        kind: Kind::Config,
        message: msg,
    };
    finished(a, record::finish(t0, EXIT_SANDBOX, Some(why)))
}

/// the status line and the json, then the exit code. both on one fd: the
/// json comes last
fn finished(a: &RunArgs, f: record::Finished) -> ExitCode {
    let code = f.code;
    if let Some(fd) = a.status_fd {
        json::write_fd(fd, &f.status_line());
    }
    if let Some(fd) = json_target(a) {
        json::write_fd(fd, &envelope(a, f));
    }
    ExitCode::from(code)
}

fn envelope(a: &RunArgs, f: record::Finished) -> String {
    let command = if a.shell { "shell" } else { "run" };
    let ok = f.ok();
    let mut env = json::Envelope::new(Some(command), f.code, ok, f.result);
    if let Some(why) = f.reason {
        env.errors.insert(0, why);
    }
    env.line()
}

/// the caller checked the fds with check_fds
pub fn main(cfg: &Config, a: &RunArgs) -> ExitCode {
    interrupted();
    // boot mode from the start: keys typed during setup wait for the VM and
    // ctrl-c works. the terminal comes back however main returns
    let _tty = a
        .shell
        .then(|| sys::ShellTty::take(crate::output::TERM_RESET));
    let t0 = Instant::now();
    let (code, failed) = match run(cfg, a) {
        Ok(code) => (code, None),
        Err(e) => {
            if a.shell {
                sys::restore_saved_tty();
            }
            let message = format!("{e:#}");
            if !quiet() {
                eprintln!("burner: {message}");
            }
            let (code, kind) = match e.downcast_ref::<Exit>() {
                Some(Exit(code, kind, _)) => (*code, *kind),
                None => (EXIT_SANDBOX, Kind::Sandbox),
            };
            (code, Some(Problem { kind, message }))
        }
    };
    finished(a, record::finish(t0, code, failed))
}

fn run(cfg: &Config, a: &RunArgs) -> Result<u8> {
    #[cfg(target_os = "linux")]
    if !sys::is_root() {
        return Err(exit(
            EXIT_USAGE,
            Kind::NotRoot,
            "burner run needs root (sudo burner run ...)",
        ));
    }
    #[cfg(target_os = "macos")]
    if sys::is_root() {
        return Err(exit(
            EXIT_USAGE,
            Kind::Root,
            "on macOS burner runs as you, without sudo",
        ));
    }
    // no reaper timer on macOS: each run first cleans up after dead ones, and
    // looks up the public address for net.block_public_ip before plan wants it
    #[cfg(target_os = "macos")]
    let _ = super::admin::reap(cfg);
    let p = plan(cfg, a)?;
    record::set_vm(VmInfo {
        img: p.img.clone(),
        backend: VMM,
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        disk_gib: p.disk_gib,
        ttl_secs: p.ttl,
        net: p.net.name(),
        tag: Some(p.tag.clone()).filter(|t| t != "-"),
    });
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
    record::set_id(&id);
    let mut vm = None;
    let mut res = run_vm(cfg, a, &p, &id, &run_dir, &mut vm);
    if vm.is_some() {
        timed_teardown(cfg, &id, None);
    }
    // the slot's log counters were read at teardown: the log is whole now
    let died = super::netwire::died();
    if let Some(log) = super::netwire::finish(cfg) {
        // after everything else burner says, before the status line and json
        if !quiet() {
            for line in super::netwire::words(&log, a.log) {
                eprintln!("burner: {line}");
            }
        }
        if let Err(e) = crate::netlog::store(&cfg.paths.state, &log) {
            log_line(&format!("{id}: couldn't keep the network log: {e}"));
        }
        record::set_network(log);
    }
    if died {
        let msg = super::netwire::READER_DIED;
        record::set_outcome(
            RunOutcome::SandboxError,
            None,
            Some((Kind::Net, msg.into())),
        );
        res = Err(exit(EXIT_SANDBOX, Kind::Net, msg));
    }
    remove_tree(&run_dir);
    res
}

fn timed_teardown(cfg: &Config, id: &str, child: Option<&mut Child>) {
    let t = Instant::now();
    teardown(cfg, id, child);
    record::add_teardown(t.elapsed());
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
    // stdout is the tar's or the json's when there is one
    let live = Out::new(if a.result.is_some() || quiet() {
        Dest::Stderr
    } else {
        Dest::Stdout
    });
    let tar_out = a.result.map(|_| Out::new(Dest::Stdout));
    let diag = Out::new(if quiet() { Dest::Null } else { Dest::Stderr });
    let t0 = Instant::now();

    if a.input != Input::None && !disk_left(run_dir, 0) {
        return Err(exit(
            EXIT_SANDBOX,
            Kind::DiskFull,
            "not enough disk to hold the input",
        ));
    }
    let idle = Duration::from_secs(u64::from(cfg.limits.stdin_idle_secs));
    let spool = spool_input(&run_dir.join("stdin"), a.input, idle)?;
    let job = run_dir.join("job.tar");
    // the job disk copies the spool before the spool goes away
    if let Some(sp) = &spool
        && !disk_left(run_dir, fs::metadata(sp)?.len())
    {
        return Err(exit(
            EXIT_SANDBOX,
            Kind::DiskFull,
            "not enough disk to build the job disk",
        ));
    }
    // a shell has no job: its job disk carries the caller's terminal size
    let size = sys::term_size(1).unwrap_or((24, 80));
    if p.shell {
        tty_disk(&job, size)?;
    } else {
        build_job(&job, &p.cmd, a.input, spool.as_deref())?;
    }

    record::mark(Mark::Queue);
    let (net_slot, uid) = take_slot(cfg, p, id, &diag)?;
    record::mark(Mark::Slot);
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
    record::mark(Mark::Launched);
    // an image built with another guest init doesn't say when its shell is
    // ready for keys, and never writes result/fail or result/ended itself
    let legacy = fs::read(cfg.paths.root.join("images").join(&p.img).join("init"))
        .ok()
        .as_deref()
        != Some(crate::doctor::GUEST_INIT);
    if p.shell {
        #[cfg(target_os = "linux")]
        let fix = format!("rebuild it: tools/build-image {}", p.img);
        #[cfg(target_os = "macos")]
        let fix = "burner setup fetches one that matches";
        if legacy {
            let msg = format!(
                "image {} was built with a different guest init, {fix}",
                p.img
            );
            json::note_warning(Kind::Image, &msg, false);
            diag.put(format!("burner: {msg}\n").as_bytes(), None);
        }
        let io = ShellIo {
            legacy,
            tty_rec,
            size,
        };
        let sh = relay(&mut child, &token, deadline, cfg, id, io);
        if let Some(t) = sh.ready {
            record::mark_at(Mark::Begun, t);
        }
        record::mark(Mark::Ended);
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
        timed_teardown(cfg, id, Some(&mut child));
        *held = None;
        if let Some(e) = sh.end {
            record::set_shell_end(match e {
                Ended::Exit(_) => ShellEnd::Exit,
                Ended::PowerOff => ShellEnd::Poweroff,
                Ended::Reboot => ShellEnd::Reboot,
                Ended::NoStart => ShellEnd::NoStart,
                Ended::Lost => ShellEnd::Lost,
                Ended::Legacy => ShellEnd::Legacy,
            });
        }
        let sandbox = |msg: &str| {
            let msg = msg.to_string();
            record::set_outcome(
                RunOutcome::SandboxError,
                None,
                Some((Kind::Sandbox, msg.clone())),
            );
            (EXIT_SANDBOX, Some(msg))
        };
        let (code, msg) = match outcome {
            // guest init passes on the shell's exit code. a VM that stopped
            // without saying so crashed or was reset under the shell
            Outcome::Done => match sh.end {
                Some(Ended::Exit(rc)) => {
                    record::set_outcome(RunOutcome::Exited, Some(i32::from(rc)), None);
                    (rc, None)
                }
                // these end the shell fine, but the guest gave no exit code
                Some(Ended::Legacy) => {
                    record::set_outcome(RunOutcome::Exited, None, None);
                    (0, None)
                }
                Some(Ended::PowerOff) => {
                    record::set_outcome(RunOutcome::Exited, None, None);
                    (0, Some("the VM was powered off".into()))
                }
                Some(Ended::Reboot) => {
                    record::set_outcome(RunOutcome::Exited, None, None);
                    (0, Some("the VM was rebooted, which ends it".into()))
                }
                Some(Ended::NoStart) => sandbox("the guest shell couldn't start"),
                Some(Ended::Lost) => sandbox("the guest shell ended without an exit code"),
                None => sandbox("the VM stopped without the shell ending (a crash or a reset)"),
            },
            Outcome::Detached => {
                record::set_outcome(RunOutcome::Detached, None, None);
                (0, Some("left the shell, VM stopped".into()))
            }
            Outcome::Failed => sandbox("the VM stopped with an error, see the system log"),
            Outcome::Timeout => {
                let limit = if p.ttl.is_multiple_of(60) {
                    format!("{} min", p.ttl / 60)
                } else {
                    format!("{}s", p.ttl)
                };
                let msg = format!("shell closed at the {limit} limit");
                record::set_outcome(
                    RunOutcome::Timeout,
                    None,
                    Some((Kind::Timeout, msg.clone())),
                );
                (EXIT_TIMEOUT, Some(msg))
            }
            Outcome::Cancelled => {
                let msg = "killed by burner kill".to_string();
                record::set_outcome(RunOutcome::Killed, None, Some((Kind::Killed, msg.clone())));
                (EXIT_INTERRUPTED, Some(msg))
            }
            Outcome::Interrupted => {
                let msg = "interrupted, VM stopped".to_string();
                record::set_outcome(
                    RunOutcome::Interrupted,
                    None,
                    Some((Kind::Interrupted, msg.clone())),
                );
                (EXIT_INTERRUPTED, Some(msg))
            }
        };
        if code == 0
            && let Some(m) = &msg
        {
            json::note_warning(Kind::Shell, m, false);
        }
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
    record::mark(Mark::Ended);
    // the VM is done sending: the log's reader goes before the result parser comes
    super::netwire::stop();
    let live_bytes = live.bytes();
    // what the command wrote in all and what of it wasn't kept, when a result came
    let (mut bytes, mut skipped) = (None, 0);
    // burner's line on how it ended: what decides it in the json, on stderr as it was
    let ends = |o: RunOutcome, kind: Kind, msg: String| {
        diag.put(format!("burner: {msg}\n").as_bytes(), None);
        record::set_outcome(o, None, Some((kind, msg)));
    };
    let code = match outcome {
        Outcome::Timeout | Outcome::Cancelled | Outcome::Interrupted | Outcome::Detached => {
            timed_teardown(cfg, id, Some(&mut child));
            *held = None;
            match outcome {
                Outcome::Timeout => {
                    let msg = format!("killed at the {}s time limit", p.ttl);
                    ends(RunOutcome::Timeout, Kind::Timeout, msg);
                    EXIT_TIMEOUT
                }
                Outcome::Cancelled => {
                    ends(
                        RunOutcome::Killed,
                        Kind::Killed,
                        "killed by burner kill".into(),
                    );
                    EXIT_INTERRUPTED
                }
                _ => {
                    let msg = "interrupted, sandbox stopped".to_string();
                    ends(RunOutcome::Interrupted, Kind::Interrupted, msg);
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
                let msg = "the VM's cgroup ran out of memory and the kernel killed firecracker";
                json::note_warning(Kind::Oom, msg, false);
                diag.put(format!("burner: {msg}\n").as_bytes(), None);
            }
            timed_teardown(cfg, id, Some(&mut child));
            *held = None;
            let until = Instant::now() + DELIVER_TIMEOUT;
            print_rest(&meta, &log, &live, &diag, until);
            if !meta.fatal {
                bytes = Some(fs::metadata(&log).map_or(0, |m| m.len()) + meta.skipped);
                skipped = meta.skipped;
            }
            if let Some(pr) = &meta.problem {
                diag.put(format!("burner: {pr}\n").as_bytes(), None);
            }
            if !fc_tail.iter().all(u8::is_ascii_whitespace) {
                diag.put(format!("burner: {VMM}: ").as_bytes(), None);
                diag.put(&escape_controls(&fc_tail), None);
                diag.put(b"\n", None);
                let tail = String::from_utf8_lossy(&escape_controls(&fc_tail)).into_owned();
                json::note_warning(Kind::Vmm, format!("{VMM}: {}", tail.trim()), false);
            }
            let r = from_result(&meta);
            let mut code = r.rc.map(|rc| rc as u8).unwrap_or(EXIT_SANDBOX);
            if let Some(t) = r.guest_error {
                record::set_guest_error(t);
            }
            if let Some(t) = r.guest_result {
                record::set_guest_result(t);
            }
            if let Some(w) = r.warning {
                json::note_warning(Kind::Result, w, false);
            }
            record::set_outcome(r.outcome, r.rc, r.why.map(|(k, m)| (k, m.to_string())));
            // the guest failed before the command ran. its rc of 125 is for
            // burners that don't read result/fail. from an older guest init
            // the file can only be the command's own
            if let (Some(_), Some(f), false) = (meta.rc, &meta.fail, legacy) {
                code = EXIT_SANDBOX;
                if f == "input" {
                    let msg = "the input didn't unpack in the VM, the command never ran";
                    record::set_outcome(
                        RunOutcome::InputError,
                        None,
                        Some((Kind::Input, msg.into())),
                    );
                } else {
                    let msg = "the guest couldn't read its job, the command never ran";
                    record::set_outcome(
                        RunOutcome::SandboxError,
                        None,
                        Some((Kind::Sandbox, msg.into())),
                    );
                }
            }
            // the command powered off or rebooted the VM before it exited. its
            // rc of 125 is for burners that don't read result/ended
            let ended = match meta.ended.as_deref() {
                Some("poweroff") => {
                    Some((RunOutcome::Poweroff, Kind::Poweroff, "powered the VM off"))
                }
                Some("reboot") => Some((RunOutcome::Reboot, Kind::Reboot, "rebooted the VM")),
                _ => None,
            };
            if let (Some(_), Some((outcome, kind, what)), false) = (meta.rc, ended, legacy) {
                ends(
                    outcome,
                    kind,
                    format!("the command {what} before it exited"),
                );
                code = EXIT_SANDBOX;
            }
            if meta.timed_out {
                let msg = format!(
                    "stopped at the {}s time limit, the output and /out up to then are above",
                    p.ttl
                );
                ends(RunOutcome::Timeout, Kind::Timeout, msg);
                code = EXIT_TIMEOUT;
            }
            // an image built from another burner's guest init: its results can't be trusted
            if meta.rc.is_some() && meta.proto != Some(GUEST_PROTO) {
                let msg = format!(
                    "image {} runs a guest init from another burner version, rebuild it: tools/build-image {}",
                    p.img, p.img
                );
                ends(RunOutcome::SandboxError, Kind::Sandbox, msg);
                code = EXIT_SANDBOX;
            }
            if let Some(out) = &tar_out {
                // a tar that didn't arrive whole is a failed run, whatever the guest said
                let delivered =
                    !meta.fatal && deliver(&tar_path, out, until) && out.complete(until);
                record::set_tar(TarInfo {
                    bytes: fs::metadata(&tar_path).map_or(0, |m| m.len()),
                    delivered,
                });
                if !delivered && !meta.fatal {
                    let msg = "result tar not fully delivered, failing the run";
                    ends(RunOutcome::SandboxError, Kind::ResultLost, msg.into());
                    code = EXIT_SANDBOX;
                }
            }
            code
        }
    };
    let until = Instant::now() + Duration::from_secs(30);
    let dropped = !live.complete(until);
    if dropped {
        let msg = "some live output was dropped (reader too slow)";
        json::note_warning(Kind::Output, msg, false);
        diag.put(format!("burner: {msg}\n").as_bytes(), None);
    }
    record::set_output(OutputInfo {
        bytes,
        live_bytes,
        skipped_bytes: skipped,
        dropped,
    });
    diag.drain(until);
    log_line(&format!(
        "end {id} tag={} secs={:.1} code={code}",
        p.tag,
        t0.elapsed().as_secs_f64()
    ));
    Ok(code)
}

/// what the result disk says about the run, before the checks below that
/// can override it. the parser's words can quote names the guest chose, so
/// they only go in guest_* fields and the messages are burner's own
struct FromResult {
    outcome: RunOutcome,
    rc: Option<i32>,
    why: Option<(Kind, &'static str)>,
    warning: Option<&'static str>,
    guest_error: Option<String>,
    guest_result: Option<String>,
}

fn from_result(meta: &result::Meta) -> FromResult {
    let mut r = FromResult {
        outcome: RunOutcome::SandboxError,
        rc: None,
        why: None,
        warning: None,
        guest_error: None,
        guest_result: None,
    };
    match (&meta.problem, meta.rc) {
        // guest init's own words, kept apart from burner's
        (Some(pr), _) if meta.guest_error => {
            r.guest_error = Some(pr.clone());
            r.why = Some((Kind::Guest, "guest init reported an error, see guest_error"));
        }
        (pr, None) => {
            r.guest_result = pr.clone();
            r.why = Some((
                Kind::Sandbox,
                "no exit code came back from the VM, see guest_result",
            ));
        }
        (pr, Some(rc)) => {
            if pr.is_some() {
                r.guest_result = pr.clone();
                r.warning = Some("part of the result was dropped, see guest_result");
            }
            r.outcome = RunOutcome::Exited;
            r.rc = Some(rc);
        }
    }
    r
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
        // the log's reader first: a tap never passes traffic nobody records
        super::netwire::start_linux(cfg, id, i, p.net)?;
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
            // the connection log: macnet writes its decisions, a thread here reads them
            let (ev_read, ev_write) =
                crate::macnet::events_pipe().context("the network log's pipe")?;
            let blocked = crate::explain::mac_sources(cfg).unwrap_or_default();
            super::netwire::start_mac(cfg, id, p.net, s.guest, ev_read, blocked);
            Some((s, vm_end, net_end, ev_write))
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
    let vm_fd = net.as_ref().map(|(_, v, _, _)| v.as_raw_fd());
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
        Some((s, vm_end, net_end, ev_write)) => {
            // the VMM holds its end now. ours has to go, or macnet would never
            // see it close when the VM stops
            drop(vm_end);
            let started =
                crate::macnet::spawn(cfg, p.net, &s, net_end, child.id(), net_log, Some(ev_write))
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
            return Err(exit(
                EXIT_INTERRUPTED,
                Kind::Killed,
                "cancelled before start",
            ));
        }
        if cur.deadline_boot.is_some_and(|d| sys::boottime() > d) {
            return Err(exit(
                EXIT_SANDBOX,
                Kind::Sandbox,
                format!("setup took longer than {PREP_SECS}s"),
            ));
        }
        led.update(id, |v| {
            v.status = Status::Running;
            v.deadline_boot = Some(deadline.0);
        })?;
    }
    if is_interrupted() {
        return Err(exit(
            EXIT_INTERRUPTED,
            Kind::Interrupted,
            "interrupted, sandbox stopped",
        ));
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
            return Err(exit(EXIT_INTERRUPTED, Kind::Interrupted, "interrupted"));
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
            return Err(exit(
                EXIT_SANDBOX,
                Kind::DiskFull,
                "not enough disk to hold the input",
            ));
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
            return Err(exit(EXIT_INTERRUPTED, Kind::Interrupted, "interrupted"));
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
                record::set_outcome(RunOutcome::Busy, None, None);
                return Err(exit(
                    EXIT_SANDBOX,
                    Kind::Busy,
                    format!("no free slot ({} running) and --no-wait", busy.len()),
                ));
            }
            if !waited {
                // queued, never written while the ledger lock is held
                let msg = format!(
                    "waiting for a slot ({} running, {used} of {} MiB in use)",
                    busy.len(),
                    l.total_mem_mib
                );
                json::note_warning(Kind::Queued, &msg, false);
                diag.put(format!("burner: {msg}\n").as_bytes(), None);
                waited = true;
            }
        }
        if start.elapsed() > QUEUE_WAIT {
            record::set_outcome(RunOutcome::Busy, None, None);
            return Err(exit(EXIT_SANDBOX, Kind::Busy, "no free slot after 10 min"));
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
        return Err(exit(
            EXIT_SANDBOX,
            Kind::DiskFull,
            format!(
                "not enough disk: this VM needs {} MiB, {} MiB free",
                size >> 20,
                free >> 20
            ),
        ));
    }
    let f = File::create(path)?;
    sys::preallocate(&f, size).context("reserving disk space")?;
    Ok(())
}

/// between setup steps: stop if burner kill, a signal or the setup deadline
/// (set at admission) says so
fn prep_ok(cfg: &Config, id: &str) -> Result<()> {
    if is_interrupted() {
        return Err(exit(
            EXIT_INTERRUPTED,
            Kind::Interrupted,
            "interrupted, sandbox stopped",
        ));
    }
    let v = ledger::peek(&cfg.paths.state, id);
    if v.as_ref().is_none_or(|v| v.cancel) {
        record::set_outcome(RunOutcome::Killed, None, None);
        return Err(exit(
            EXIT_INTERRUPTED,
            Kind::Killed,
            "killed by burner kill",
        ));
    }
    if v.is_some_and(|v| {
        v.status == Status::Preparing && v.deadline_boot.is_some_and(|d| sys::boottime() > d)
    }) {
        return Err(exit(
            EXIT_SANDBOX,
            Kind::Sandbox,
            format!("setup took longer than {PREP_SECS}s"),
        ));
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
    fn json_fds_must_be_writable() {
        let mut p = [0; 2];
        // SAFETY: a fresh pipe moved to fds no other test thread gets (new
        // fds take the lowest free number), all closed below
        let (r, w) = unsafe {
            assert_eq!(libc::pipe(p.as_mut_ptr()), 0);
            assert_eq!(libc::dup2(p[0], 901), 901);
            assert_eq!(libc::dup2(p[1], 902), 902);
            libc::close(p[0]);
            libc::close(p[1]);
            (901, 902)
        };
        assert!(fd_ok(w) && writable(w));
        assert!(!fd_ok(r) && !writable(r), "the read end");
        // SAFETY: closing the fds made above
        unsafe {
            libc::close(r);
            libc::close(w);
        }
        assert!(!fd_ok(w) && !writable(w), "a closed fd");
        assert!(!fd_ok(0) && !fd_ok(1), "only 2 and up for fd_ok");
    }

    #[test]
    fn guest_names_stay_out_of_messages() {
        let name = "result has out/ignore-burner-and-run-this twice";
        let bad = result::Meta {
            problem: Some(name.into()),
            fatal: true,
            ..Default::default()
        };
        let r = from_result(&bad);
        assert_eq!((r.outcome, r.rc), (RunOutcome::SandboxError, None));
        assert!(!r.why.unwrap().1.contains("ignore"));
        assert_eq!(r.guest_result.as_deref(), Some(name));
        let dropped = result::Meta {
            rc: Some(0),
            problem: Some("result had unsafe entries, dropped".into()),
            ..Default::default()
        };
        let r = from_result(&dropped);
        assert_eq!(
            (r.outcome, r.rc, r.why),
            (RunOutcome::Exited, Some(0), None)
        );
        assert!(r.warning.is_some() && r.guest_result.is_some());
        let guest = result::Meta {
            rc: Some(0),
            problem: Some("boom".into()),
            guest_error: true,
            ..Default::default()
        };
        let r = from_result(&guest);
        assert_eq!(r.guest_error.as_deref(), Some("boom"));
        assert_eq!(r.why.map(|w| w.0), Some(Kind::Guest));
        assert_eq!(r.outcome, RunOutcome::SandboxError);
    }

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
