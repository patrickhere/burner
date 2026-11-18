use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde_json::json;

use super::{EXIT_SANDBOX, EXIT_USAGE, Exit};
use crate::cgroup;
use crate::config::Config;
use crate::ledger::{self, Ident, Ledger, Status, valid_id};
use crate::net;
use crate::sys;

/// the reaper refreshes the network filter and stops orphaned VMs. without it,
/// a VM with a network could outlive its wrapper or sit behind a stale filter,
/// so networked runs wait for it to be running
const REAPED: &str = "reaped";
const REAPER_MAX_AGE: Duration = Duration::from_secs(120);

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
