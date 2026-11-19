//! macOS has no cgroups. a VM is its VMM process and that process's group,
//! which macnet joins: burner records the VMM's pid and start time in
//! state/vmm/ID when it spawns it, and macnet's once that's up. the VM is gone
//! once neither is left and nothing else runs in the group. libkrun runs the
//! whole VM inside the VMM, nothing forks from it or from macnet

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::ledger::Ident;
use crate::sys;

static DIR: OnceLock<PathBuf> = OnceLock::new();

/// where the records live, under the state dir. set once the config is loaded
pub fn set_dir(state: &Path) {
    let _ = DIR.set(state.join("vmm"));
}

pub fn dir() -> PathBuf {
    DIR.get().cloned().unwrap_or_default()
}

fn path(id: &str) -> PathBuf {
    dir().join(id)
}

fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
    // SAFETY: zeroed proc_bsdinfo is a valid out-parameter of the size passed
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (n == size).then_some(info)
}

/// the start time of pid, zombies included: a VMM that exited but wasn't
/// waited for yet still holds its pid, and with it its group
fn started(pid: u32) -> Option<u64> {
    bsdinfo(pid).map(|i| i.pbi_start_tvsec * 1_000_000 + i.pbi_start_tvusec)
}

/// whether anything in process group pgid still runs. zombies don't count:
/// macnet that exited but wasn't waited for yet holds nothing anymore
fn group_runs(pgid: libc::pid_t) -> bool {
    const SZOMB: u32 = 5;
    let mut pids = [0 as libc::pid_t; 64];
    // SAFETY: a buffer of exactly the size passed; unused slots stay 0
    let n = unsafe {
        libc::proc_listpgrppids(
            pgid,
            pids.as_mut_ptr().cast(),
            std::mem::size_of_val(&pids) as libc::c_int,
        )
    };
    // can't tell: count it as running, so its slot stays taken
    if n < 0 {
        return true;
    }
    pids.iter().filter(|&&p| p > 0).any(|&p| {
        bsdinfo(p as u32).is_some_and(|i| i.pbi_status != SZOMB && i.pbi_pgid == pgid as u32)
    })
}

#[derive(Serialize, Deserialize)]
struct Record {
    #[serde(flatten)]
    vmm: Ident,
    /// macnet, for a VM with a network. records from before it was kept have none
    #[serde(default, skip_serializing_if = "Option::is_none")]
    net: Option<Ident>,
}

fn read(id: &str) -> io::Result<Record> {
    serde_json::from_slice(&fs::read(path(id))?).map_err(io::Error::other)
}

fn write(id: &str, r: &Record) -> io::Result<()> {
    let tmp = dir().join(format!("{id}.tmp"));
    fs::write(&tmp, serde_json::to_vec(r)?)?;
    fs::rename(tmp, path(id))
}

enum Group {
    /// the recorded VMM is still there, maybe as a zombie
    Leader,
    /// the VMM is gone and reaped, but something in its group still runs
    Orphans,
    Empty,
    /// the pid belongs to another process now, and so may the group id
    Reused,
}

/// what's left of the VMM's process group. its id is the VMM's pid, and macOS
/// hands out no pid that is still in use as a group id: with no process at
/// that pid, a group by that id is still this VM's
fn group(r: &Record) -> Group {
    if r.vmm.boot != sys::boot_id() {
        return Group::Empty;
    }
    let pid = r.vmm.pid as libc::pid_t;
    match started(r.vmm.pid) {
        Some(start) if start == r.vmm.start => return Group::Leader,
        Some(_) => return Group::Reused,
        None => {}
    }
    // SAFETY: signal 0 only checks, kill(2) is a plain syscall
    if unsafe { libc::kill(pid, 0) } == 0
        || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Group::Reused;
    }
    if group_runs(pid) {
        Group::Orphans
    } else {
        Group::Empty
    }
}

/// the recorded macnet, if it's still that same process
fn net(r: &Record) -> Option<&Ident> {
    r.net.as_ref().filter(|n| n.alive())
}

/// write down the VMM burner just spawned
pub fn record(id: &str, pid: u32) -> io::Result<()> {
    let start = started(pid).ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
    let vmm = Ident {
        pid,
        start,
        boot: sys::boot_id(),
    };
    write(id, &Record { vmm, net: None })
}

/// add macnet to the VM's record once it runs
pub fn record_net(id: &str, pid: u32) -> io::Result<()> {
    let mut r = read(id)?;
    let start = sys::proc_start(pid).ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))?;
    r.net = Some(Ident {
        pid,
        start,
        boot: sys::boot_id(),
    });
    write(id, &r)
}

/// a VM has no OOM killer of its own on macOS: hypervisor.framework memory is
/// the VMM's memory, and the host swaps before it kills
pub fn oom_kills(_id: &str) -> u64 {
    0
}

/// true while the VMM, macnet or anything else in the VMM's group is left. a
/// record that can't be read counts as busy, so its slot stays taken
pub fn populated(id: &str) -> bool {
    match read(id) {
        Ok(r) => matches!(group(&r), Group::Leader | Group::Orphans) || net(&r).is_some(),
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}

pub fn kill(id: &str) {
    let Ok(r) = read(id) else { return };
    // SAFETY: plain kill(2). group() and the start time checks are what keep a
    // reused pid out of it; without pidfds that's as close as macOS gets
    unsafe {
        if matches!(group(&r), Group::Leader | Group::Orphans) {
            libc::killpg(r.vmm.pid as libc::pid_t, libc::SIGKILL);
        }
        if let Some(n) = net(&r) {
            libc::kill(n.pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

/// only net down takes every VM down at once, and on macOS VMs have no network yet
#[allow(dead_code)]
pub fn kill_all() {
    for e in fs::read_dir(dir()).into_iter().flatten().flatten() {
        if let Some(id) = e.file_name().to_str()
            && crate::ledger::valid_id(id)
        {
            kill(id);
        }
    }
}

/// true when the record is gone. only dropped once its process is
pub fn remove(id: &str) -> bool {
    if populated(id) {
        return false;
    }
    match fs::remove_file(path(id)) {
        Ok(()) => true,
        Err(e) => e.kind() == io::ErrorKind::NotFound,
    }
}

/// make sure the record dir is there before the VMM starts. what comes back is
/// only for join_from_child's signature, which matches the linux one
pub fn prepare(id: &str) -> io::Result<CString> {
    sys::private_dir(&dir())?;
    CString::new(path(id).into_os_string().into_encoded_bytes())
        .map_err(|_| io::Error::other("bad record path"))
}

/// runs between fork and exec. no PDEATHSIG on macOS: the VMM watches its
/// parent itself once it runs. this only refuses to start one when burner
/// already died, so it can't come up with nobody left to stop it
pub fn join_from_child(_procs: &CStr, parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: getppid is a plain syscall, fine between fork and exec
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}
