use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use super::EXIT_USAGE;
#[cfg(target_os = "linux")]
use super::{EXIT_SANDBOX, exit};
use crate::cgroup;
use crate::config::Config;
use crate::exit::EXIT_FAILED;
use crate::json::{self, Kind};
use crate::ledger::{self, Ident, Ledger, Status, valid_id};
use crate::net;
use crate::sys;

/// the reaper refreshes the network filter and stops orphaned VMs. without it,
/// a VM with a network could outlive its wrapper or sit behind a stale filter,
/// so networked runs wait for it to be running
const REAPED: &str = "reaped";
#[cfg(target_os = "linux")]
const REAPER_MAX_AGE: Duration = Duration::from_secs(120);

/// how long teardown gives the VMM to go and then macnet to write its
/// counts, before the group is killed either way
#[cfg(target_os = "macos")]
const NET_LAST_LINE: Duration = Duration::from_millis(500);

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
        _ => Err(exit(
            EXIT_SANDBOX,
            Kind::NoReaper,
            "the reaper hasn't run in the last 2 min (systemctl status burner-reap.timer), \
             refusing a VM with a network. --net none still works",
        )),
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
        Slot::Tap(i) => net::tap_down_for(cfg, i, id),
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

/// macOS, with the VMM just killed: macnet's last line has the counts that
/// make the connection log complete, and it writes it when it sees the VM's
/// end of the socket gone. a poll() already asleep on that socket isn't woken
/// when the VMM exits, so macnet is told with SIGTERM once the VMM is down
#[cfg(target_os = "macos")]
fn net_last_line(id: &str, vmm: u32) {
    let until = Instant::now() + NET_LAST_LINE;
    while !sys::exited(vmm) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(2));
    }
    cgroup::stop_net(id);
    super::netwire::net_closed(until);
}

/// stop the VM and only then free its disks and its slot. false when it couldn't be confirmed dead
pub fn teardown(cfg: &Config, id: &str, child: Option<&mut Child>) -> bool {
    let mut child = child;
    if let Some(c) = child.as_deref_mut() {
        let _ = c.kill();
        #[cfg(target_os = "macos")]
        net_last_line(id, c.id());
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

#[derive(Serialize)]
pub struct LsResult {
    pub vms: Vec<LsVm>,
    pub max_vms: u32,
    pub total_mem_mib: u32,
    pub used_mem_mib: u32,
}

#[derive(Serialize)]
pub struct LsVm {
    pub id: String,
    pub tag: Option<String>,
    pub img: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
    pub net: String,
    pub status: &'static str,
    pub owner: Option<u32>,
    pub started_unix: u64,
    pub age_secs: u64,
    pub ttl_secs: u32,
    pub ttl_left_secs: Option<u64>,
}

impl LsVm {
    fn of(v: &ledger::Vm, now: f64, unix: u64) -> LsVm {
        LsVm {
            id: v.id.clone(),
            tag: Some(v.tag.clone()).filter(|t| t != "-"),
            img: v.img.clone(),
            vcpus: v.vcpus,
            mem_mib: v.mem_mib,
            disk_gib: v.disk_gib,
            net: v.net.clone(),
            status: v.status.name(),
            owner: v.owner,
            started_unix: v.started,
            age_secs: unix.saturating_sub(v.started),
            ttl_secs: v.ttl_secs,
            ttl_left_secs: v.deadline_boot.map(|d| (d - now).max(0.0) as u64),
        }
    }
}

/// through sudo, the caller. None for root itself, which sees every VM
fn sudo_caller() -> Option<u32> {
    std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok())
}

/// ls and kill read and change the ledger, which is root's on linux
#[cfg(target_os = "linux")]
fn needs_root(cmd: &str, what: &str) -> Option<ExitCode> {
    (!sys::is_root()).then(|| {
        json::fail(
            cmd,
            EXIT_USAGE,
            Kind::NotRoot,
            format!("burner {cmd} needs root, like the VMs it {what} (sudo burner {cmd})"),
        )
    })
}

#[cfg(target_os = "macos")]
fn needs_root(_cmd: &str, _what: &str) -> Option<ExitCode> {
    None
}

/// an age or a time left: 42s, 4m12s, 1h03m, 2d05h
fn short_secs(s: u64) -> String {
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m{:02}s", s / 60, s % 60),
        3600..86400 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d{:02}h", s / 86400, s % 86400 / 3600),
    }
}

/// 512M, or 2G when it's whole GiB
fn short_mib(m: u32) -> String {
    if m >= 1024 && m.is_multiple_of(1024) {
        format!("{}G", m / 1024)
    } else {
        format!("{m}M")
    }
}

/// the text table: a header, then one row per VM, columns as wide as
/// their widest cell
fn ls_table(vms: &[LsVm]) -> String {
    let mut rows = vec![
        [
            "ID", "TAG", "IMG", "CPU", "MEM", "DISK", "NET", "STATUS", "AGE", "LEFT",
        ]
        .map(String::from),
    ];
    for v in vms {
        rows.push([
            v.id.clone(),
            v.tag.clone().unwrap_or_default(),
            v.img.clone(),
            v.vcpus.to_string(),
            short_mib(v.mem_mib),
            format!("{}G", v.disk_gib),
            v.net.clone(),
            v.status.into(),
            short_secs(v.age_secs),
            v.ttl_left_secs.map_or("-".into(), short_secs),
        ]);
    }
    let mut width = [0; 10];
    for r in &rows {
        for (w, c) in width.iter_mut().zip(r) {
            *w = (*w).max(c.len());
        }
    }
    let mut out = String::new();
    for r in &rows {
        let line: Vec<String> = r
            .iter()
            .zip(width)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        out += line.join("  ").trim_end();
        out += "\n";
    }
    out
}

pub fn ls(cfg: &Config) -> Result<ExitCode> {
    if let Some(code) = needs_root("ls", "lists") {
        return Ok(code);
    }
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
    // the room left is the machine's, every user's VMs count
    let used_mem_mib = vms.iter().map(|v| v.mem_mib).sum();
    // through sudo it's the caller's VMs, like kill and log; root sees all
    let caller = sudo_caller();
    let mine: Vec<LsVm> = vms
        .iter()
        .filter(|v| caller.is_none_or(|c| v.owner == Some(c)))
        .map(|v| LsVm::of(v, now, unix))
        .collect();
    if json::on() {
        let res = LsResult {
            vms: mine,
            max_vms: cfg.limits.max_vms,
            total_mem_mib: cfg.limits.total_mem_mib,
            used_mem_mib,
        };
        return Ok(json::reply("ls", 0, Some(res)));
    }
    match (mine.is_empty(), caller) {
        (true, Some(_)) => println!("no VMs of yours running"),
        (true, None) => println!("no VMs running"),
        (false, _) => print!("{}", ls_table(&mine)),
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Serialize)]
pub struct KillResult {
    pub id: String,
    /// gone, or stopping when it hadn't stopped 20s later
    pub state: &'static str,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct KillArgs {
    /// the VM's id, from burner ls
    id: Option<String>,
    /// every VM of yours with this tag
    #[arg(long)]
    tag: Option<String>,
    /// every VM of yours
    #[arg(long)]
    mine: bool,
}

/// with --tag or --mine: every VM it asked to stop
#[derive(Serialize)]
pub struct KillManyResult {
    pub vms: Vec<KillResult>,
}

const KILL_USAGE: &str = "usage: burner kill burner-xxxxxxxxxxxx, --tag TAG or --mine";
const TAG_USAGE: &str = "--tag must be lowercase letters, digits and dashes, max 32";

/// which VMs a kill is for
enum Pick<'a> {
    Id(&'a str),
    /// the caller's, with this tag or all of them
    Mine(Option<&'a str>),
}

impl KillArgs {
    fn pick(&self) -> std::result::Result<Pick<'_>, &'static str> {
        match (&self.id, &self.tag, self.mine) {
            (Some(id), None, false) if valid_id(id) => Ok(Pick::Id(id)),
            (None, Some(t), false) if super::plan::valid_name(t) => Ok(Pick::Mine(Some(t))),
            (None, Some(_), false) => Err(TAG_USAGE),
            (None, None, true) => Ok(Pick::Mine(None)),
            _ => Err(KILL_USAGE),
        }
    }

    /// burner's argv on the far end of -H. checked here: an id like
    /// -Hother would be a flag there. --tag and --mine need a 0.3.1 there
    pub fn remote_argv(&self) -> std::result::Result<Vec<String>, String> {
        let mut v = vec!["kill".to_string()];
        match self.pick()? {
            Pick::Id(id) => v.push(id.into()),
            Pick::Mine(Some(t)) => v.extend(["--tag".into(), t.into()]),
            Pick::Mine(None) => v.push("--mine".into()),
        }
        Ok(v)
    }
}

pub fn kill(cfg: &Config, a: &KillArgs) -> Result<ExitCode> {
    let pick = match a.pick() {
        Ok(p) => p,
        Err(why) => return Ok(json::fail("kill", EXIT_USAGE, Kind::Usage, why)),
    };
    if let Some(code) = needs_root("kill", "stops") {
        return Ok(code);
    }
    let id = match pick {
        Pick::Id(id) => id,
        Pick::Mine(tag) => return kill_mine(cfg, tag),
    };
    // through sudo you can only kill what you started. real root can kill anything
    let caller = sudo_caller();
    // nothing is printed while the ledger is locked: a stalled stderr would hold it
    let refused = {
        let led = Ledger::open(&cfg.paths.state)?;
        match led.get(id) {
            None => Some((Kind::NotFound, "no VM with that id")),
            Some(v) if caller.is_some_and(|c| v.owner != Some(c)) => {
                Some((Kind::NotOwner, "not yours, another user started it"))
            }
            Some(_) => match led.update(id, |v| v.cancel = true)? {
                Some(_) => None,
                None => Some((Kind::NotFound, "no VM with that id")),
            },
        }
    };
    if let Some((kind, why)) = refused {
        return Ok(json::fail(
            "kill",
            EXIT_FAILED,
            kind,
            format!("{id}: {why}"),
        ));
    }
    let ids = [id.to_string()];
    let gone = stop_and_wait(cfg, &ids);
    let done = |state| {
        Some(KillResult {
            id: id.into(),
            state,
        })
    };
    if gone[0] {
        if !json::on() {
            println!("killed {id}");
        }
        return Ok(json::reply("kill", 0, done("gone")));
    }
    json::error(
        Kind::StillStopping,
        format!("kill requested for {id}, still stopping (burner ls shows it)"),
    );
    Ok(json::reply("kill", EXIT_FAILED, done("stopping")))
}

/// kill --tag and --mine: the caller's VMs (the sudo caller's, else the
/// uid burner runs as, which is what a VM's owner was set from). none is
/// fine, there's nothing left to stop
fn kill_mine(cfg: &Config, tag: Option<&str>) -> Result<ExitCode> {
    let me: Option<u32> = caller_uid().parse().ok();
    let ids: Vec<String> = {
        let led = Ledger::open(&cfg.paths.state)?;
        let mut ids = Vec::new();
        for v in led.all() {
            if v.owner.is_some()
                && v.owner == me
                && tag.is_none_or(|t| v.tag == t)
                && led.update(&v.id, |v| v.cancel = true)?.is_some()
            {
                ids.push(v.id);
            }
        }
        ids
    };
    let gone = stop_and_wait(cfg, &ids);
    let vms: Vec<KillResult> = ids
        .iter()
        .zip(&gone)
        .map(|(id, &g)| KillResult {
            id: id.clone(),
            state: if g { "gone" } else { "stopping" },
        })
        .collect();
    if !json::on() {
        for v in vms.iter().filter(|v| v.state == "gone") {
            println!("killed {}", v.id);
        }
        if vms.is_empty() {
            match tag {
                Some(t) => println!("no VMs of yours tagged {t}"),
                None => println!("no VMs of yours running"),
            }
        }
    }
    let left: Vec<&str> = vms
        .iter()
        .filter(|v| v.state == "stopping")
        .map(|v| v.id.as_str())
        .collect();
    if left.is_empty() {
        return Ok(json::reply("kill", 0, Some(KillManyResult { vms })));
    }
    json::error(
        Kind::StillStopping,
        format!(
            "kill requested for {}, still stopping (burner ls shows it)",
            left.join(", ")
        ),
    );
    Ok(json::reply(
        "kill",
        EXIT_FAILED,
        Some(KillManyResult { vms }),
    ))
}

/// stop VMs whose cancel is set, and wait up to 20s for each to be gone.
/// only gone once its wrapper (or the reaper) has cleaned it up
fn stop_and_wait(cfg: &Config, ids: &[String]) -> Vec<bool> {
    for id in ids {
        cgroup::kill(id);
        log_line(&format!("kill {id}"));
    }
    let mut gone = vec![false; ids.len()];
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end && !gone.iter().all(|&g| g) {
        // no reaper timer on macOS: a VM whose wrapper is gone is cleaned up here
        #[cfg(target_os = "macos")]
        let _ = reap(cfg);
        for (id, g) in ids.iter().zip(gone.iter_mut()) {
            *g = *g || matches!(ledger::peek_strict(&cfg.paths.state, id), Ok(None));
        }
        if !gone.iter().all(|&g| g) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    gone
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
        // a probe that died left its witness table behind
        crate::probe::reap_tables();
    }
    // nothing to check on macOS: macnet reads addresses and routes itself
    #[cfg(target_os = "macos")]
    net::refresh_public_ip(cfg);
    crate::runlog::prune(cfg);
    // counters teardown kept for a run that never came back for them
    for e in fs::read_dir(cfg.paths.state.join("netcount"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
    {
        if old(&e.path(), 600) {
            let _ = fs::remove_file(e.path());
        }
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
    fn ls_json() {
        let v = ledger::Vm {
            id: "burner-3f9a1c2b7d10".into(),
            tag: "-".into(),
            img: "alpine".into(),
            vcpus: 1,
            mem_mib: 512,
            disk_gib: 2,
            net: "web".into(),
            ttl_secs: 600,
            status: Status::Running,
            owner: Some(1000),
            started: 1_795_000_000,
            deadline_boot: Some(658.4),
            ..Default::default()
        };
        let r = LsResult {
            vms: vec![LsVm::of(&v, 100.0, 1_795_000_042)],
            max_vms: 2,
            total_mem_mib: 3072,
            used_mem_mib: 512,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"vms":[{"id":"burner-3f9a1c2b7d10","tag":null,"img":"alpine","vcpus":1,"mem_mib":512,"disk_gib":2,"net":"web","status":"running","owner":1000,"started_unix":1795000000,"age_secs":42,"ttl_secs":600,"ttl_left_secs":558}],"max_vms":2,"total_mem_mib":3072,"used_mem_mib":512}"#
        );
    }

    #[test]
    fn ls_text() {
        assert_eq!(
            [0, 42, 60, 252, 3599, 3600, 3780, 86399, 86400, 183600].map(short_secs),
            [
                "0s", "42s", "1m00s", "4m12s", "59m59s", "1h00m", "1h03m", "23h59m", "1d00h",
                "2d03h"
            ]
        );
        assert_eq!(
            [512, 1024, 1536, 3072].map(short_mib),
            ["512M", "1G", "1536M", "3G"]
        );
        let vm = |id: &str, tag: Option<&str>, left: Option<u64>| LsVm {
            id: id.into(),
            tag: tag.map(String::from),
            img: "alpine".into(),
            vcpus: 1,
            mem_mib: 512,
            disk_gib: 2,
            net: "none".into(),
            status: "running",
            owner: Some(1000),
            started_unix: 0,
            age_secs: 252,
            ttl_secs: 600,
            ttl_left_secs: left,
        };
        let t = ls_table(&[
            vm("burner-3f9a1c2b7d10", Some("tests"), Some(348)),
            vm("burner-0123456789ab", None, None),
        ]);
        assert_eq!(
            t,
            "ID                   TAG    IMG     CPU  MEM   DISK  NET   STATUS   AGE    LEFT\n\
             burner-3f9a1c2b7d10  tests  alpine  1    512M  2G    none  running  4m12s  5m48s\n\
             burner-0123456789ab         alpine  1    512M  2G    none  running  4m12s  -\n"
        );
        // what the suites match on: the id first, the tag as its own word
        let row = t.lines().nth(1).unwrap();
        assert!(row.starts_with("burner-") && row.contains(" tests "));
        assert_eq!(row.split_whitespace().nth(1), Some("tests"));
    }

    #[test]
    fn kill_picks() {
        #[derive(clap::Parser)]
        struct K {
            #[command(flatten)]
            a: KillArgs,
        }
        let argv = |args: &[&str]| {
            <K as clap::Parser>::try_parse_from(std::iter::once("kill").chain(args.iter().copied()))
                .map_err(|e| e.to_string())
                .and_then(|k| k.a.remote_argv())
        };
        assert_eq!(
            argv(&["burner-3f9a1c2b7d10"]).unwrap(),
            ["kill", "burner-3f9a1c2b7d10"]
        );
        assert_eq!(
            argv(&["--tag", "tests"]).unwrap(),
            ["kill", "--tag", "tests"]
        );
        assert_eq!(argv(&["--mine"]).unwrap(), ["kill", "--mine"]);
        assert_eq!(argv(&["--tag", "Tests_1"]).unwrap_err(), TAG_USAGE);
        assert_eq!(argv(&["--tag=-Hx"]).unwrap_err(), TAG_USAGE);
        assert_eq!(argv(&["../../etc"]).unwrap_err(), KILL_USAGE);
        assert!(argv(&["--mine", "--tag", "x"]).is_err(), "one of them");
        assert!(argv(&[]).is_err());
    }

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
