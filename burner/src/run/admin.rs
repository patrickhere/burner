use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde_json::json;

use super::EXIT_USAGE;
#[cfg(target_os = "linux")]
use super::{EXIT_SANDBOX, Exit};
use crate::cgroup;
use crate::config::Config;
use crate::ledger::{self, Ident, Ledger, Status, valid_id};
#[cfg(target_os = "linux")]
use crate::net;
use crate::sys;

/// the reaper refreshes the network filter and stops orphaned VMs. without it,
/// a VM with a network could outlive its wrapper or sit behind a stale filter,
/// so networked runs wait for it to be running
const REAPED: &str = "reaped";
#[cfg(target_os = "linux")]
const REAPER_MAX_AGE: Duration = Duration::from_secs(120);

/// each VM's own dir under paths.root: its disks, its VMM's log
#[cfg(target_os = "linux")]
pub(super) const VM_DIRS: &str = "jail/firecracker";
#[cfg(target_os = "macos")]
pub(super) const VM_DIRS: &str = "vm";

#[cfg(target_os = "linux")]
fn cgroup_dir() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup").join(cgroup::PARENT)
}

#[cfg(target_os = "macos")]
fn cgroup_dir() -> PathBuf {
    cgroup::dir()
}

#[cfg(target_os = "linux")]
pub(super) fn reaper_alive(cfg: &Config) -> Result<()> {
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
#[cfg(target_os = "linux")]
pub fn reaper_age(cfg: &Config) -> Option<Duration> {
    fs::metadata(cfg.paths.state.join(REAPED))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
}

/// delete a jail or run dir. stops at anything mounted inside it, so a bind
/// mount someone left there never gets its contents deleted
pub(super) fn remove_tree(path: &Path) -> bool {
    let ok = sys::remove_tree_at(path);
    if !ok && path.exists() {
        log_line(&format!(
            "couldn't fully remove {}, keeping it for the reaper",
            path.display()
        ));
    }
    ok
}

/// what's known about a VM's tap when it gets released
pub(super) enum Slot {
    /// it never had one
    None,
    Tap(#[cfg_attr(target_os = "macos", allow(dead_code))] u32),
    /// its ledger entry can't be read: leave the tap and report it unfinished
    Unknown,
    /// the orphan tap sweep frees it
    Swept,
}

#[derive(PartialEq)]
pub(super) enum Released {
    /// still running, or its cgroup is still there: nothing was freed
    Running,
    /// stopped, but its tap or jail is still around
    Partly,
    Done,
}

/// the one place a VM's resources get freed, for teardown, the reaper and the
/// orphan sweeps: kill what's in its cgroup, wait up to `wait`, and only once the
/// cgroup is empty and removed take down its tap and delete its jail. the run
/// dir is left to the caller, the wrapper still reads the result from it
pub(super) fn release(cfg: &Config, id: &str, slot: Slot, wait: Duration) -> Released {
    cgroup::kill(id);
    let end = Instant::now() + wait;
    while cgroup::populated(id) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    // something that joined late makes the remove fail: then nothing is freed
    if cgroup::populated(id) || !cgroup::remove(id) {
        return Released::Running;
    }
    // the slow parts (subprocesses, deleting files) happen without the ledger lock
    let tap_gone = match slot {
        Slot::None | Slot::Swept => true,
        #[cfg(target_os = "linux")]
        Slot::Tap(i) => net::tap_down(cfg, i),
        // no tap on macOS: the network is macnet, and it went with the VMM's group
        #[cfg(target_os = "macos")]
        Slot::Tap(_) => true,
        Slot::Unknown => false,
    };
    let jail_gone = remove_tree(&cfg.paths.root.join(VM_DIRS).join(id));
    if tap_gone && jail_gone {
        Released::Done
    } else {
        Released::Partly
    }
}

/// stop the VM and only then free its disks and its slot. false when it couldn't be confirmed dead
pub fn teardown(cfg: &Config, id: &str, child: Option<&mut Child>) -> bool {
    let mut child = child;
    if let Some(c) = child.as_deref_mut() {
        let _ = c.kill();
    }
    cgroup::kill(id);
    let end = Instant::now() + Duration::from_secs(15);
    let exited = |c: &mut Option<&mut Child>| {
        c.as_deref_mut()
            .is_none_or(|c| matches!(c.try_wait(), Ok(Some(_))))
    };
    while Instant::now() < end && !exited(&mut child) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let slot = match ledger::peek_strict(&cfg.paths.state, id) {
        Ok(v) => v.and_then(|v| v.net_slot).map_or(Slot::None, Slot::Tap),
        Err(_) => Slot::Unknown, // can't tell which tap: leave it for the reaper
    };
    // the jailer can be killed before it moved itself into the cgroup
    let released = if exited(&mut child) {
        release(cfg, id, slot, end.saturating_duration_since(Instant::now()))
    } else {
        Released::Running
    };
    let Ok(led) = Ledger::open(&cfg.paths.state) else {
        return false;
    };
    match released {
        Released::Done => {
            led.delete(id);
            true
        }
        Released::Partly => {
            let _ = led.update(id, |v| {
                v.status = Status::CleanupFailed;
                v.wrapper = None;
            });
            false
        }
        Released::Running => {
            let _ = led.update(id, |v| v.status = Status::CleanupFailed);
            log_line(&format!(
                "teardown {id}: VM did not stop, slot kept for the reaper"
            ));
            false
        }
    }
}

/// who asked for the run: the sudo caller when there is one, else our own uid
pub(super) fn caller_uid() -> String {
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
    // no reaper timer on macOS: don't list VMs whose wrapper is long gone
    #[cfg(target_os = "macos")]
    let _ = reap(cfg);
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

/// a wrapper that's still alive a minute past its VM's deadline without having
/// torn it down is stopped (ctrl-z) or stuck: a healthy one has deleted or
/// re-marked the entry within 15s of the VM ending
fn wrapper_stuck(v: &ledger::Vm, now: f64) -> bool {
    matches!(v.status, Status::Running | Status::Preparing)
        && v.deadline_boot.is_some_and(|d| now > d + 60.0)
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
            // its slot, tap and jail stay taken while the wrapper lives, so a
            // stopped one would hold them forever. the next pass cleans up
            if let Some(n) = now_v.filter(|n| wrapper_stuck(n, now))
                && let Some(w) = n.wrapper.as_ref()
                && w.alive()
                && sys::signal_ident(w, libc::SIGKILL)
            {
                log_line(&format!(
                    "reap {}: wrapper still there a minute past the deadline, killed it",
                    v.id
                ));
            }
        }
        if v.wrapper.as_ref().is_some_and(Ident::alive) {
            continue;
        }
        let slot = v.net_slot.map_or(Slot::None, Slot::Tap);
        let released = release(cfg, &v.id, slot, Duration::from_secs(3));
        if released == Released::Running {
            continue;
        }
        let run_gone = remove_tree(&cfg.paths.root.join("run").join(&v.id));
        done.push((v.id.clone(), released == Released::Done && run_gone));
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
    // under its id, then move it aside as .bad; the orphan tap sweep below takes
    // care of its tap
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
        if release(cfg, id, Slot::Swept, Duration::from_secs(3)) != Released::Running
            && fs::rename(&p, p.with_extension("bad")).is_ok()
        {
            log_line(&format!(
                "reap {id}: ledger entry unreadable, VM stopped, entry kept as {id}.bad"
            ));
        }
    }
    // read again: a pass can take minutes, and a VM admitted since the first
    // read is not an orphan
    let known: Vec<String> = Ledger::open(&cfg.paths.state)?
        .all()
        .into_iter()
        .map(|v| v.id)
        .collect();
    #[cfg(target_os = "linux")]
    for i in net::reap_orphan_taps(cfg) {
        log_line(&format!("reap orphan tap {i}"));
    }
    for base in [cfg.paths.root.join(VM_DIRS), cgroup_dir()] {
        for e in fs::read_dir(&base)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
        {
            let name = e.file_name().to_string_lossy().into_owned();
            if !valid_id(&name) || known.contains(&name) || !old(&e.path(), 120) {
                continue;
            }
            if release(cfg, &name, Slot::Swept, Duration::ZERO) == Released::Done {
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
    #[cfg(target_os = "linux")]
    {
        net::refresh_public_ip(cfg);
        net::check(cfg);
    }
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
    fn stuck_wrappers() {
        let vm = |status, deadline| ledger::Vm {
            status,
            deadline_boot: deadline,
            ..Default::default()
        };
        assert!(wrapper_stuck(&vm(Status::Running, Some(100.0)), 161.0));
        assert!(wrapper_stuck(&vm(Status::Preparing, Some(100.0)), 161.0));
        assert!(
            !wrapper_stuck(&vm(Status::Running, Some(100.0)), 159.0),
            "still in its grace minute"
        );
        assert!(
            !wrapper_stuck(&vm(Status::CleanupFailed, Some(100.0)), 500.0),
            "teardown already ran"
        );
        assert!(
            !wrapper_stuck(&vm(Status::Running, None), 500.0),
            "no deadline yet"
        );
    }
}
