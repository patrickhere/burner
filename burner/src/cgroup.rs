//! each VM runs in its own cgroup under /sys/fs/cgroup/burner. killing and
//! checking the cgroup is how burner knows a VM is really gone.

use std::fs;
use std::path::PathBuf;

pub const PARENT: &str = "burner";

fn path(id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup").join(PARENT).join(id)
}

/// how many times the kernel's OOM killer fired inside the VM's cgroup
pub fn oom_kills(id: &str) -> u64 {
    fs::read_to_string(path(id).join("memory.events"))
        .ok()
        .and_then(|e| {
            e.lines()
                .find_map(|l| l.strip_prefix("oom_kill "))
                .and_then(|n| n.trim().parse().ok())
        })
        .unwrap_or(0)
}

/// true unless the cgroup is gone or confirmed empty: a read that fails for any
/// other reason counts as busy, so its slot stays taken
pub fn populated(id: &str) -> bool {
    match fs::read_to_string(path(id).join("cgroup.events")) {
        Ok(e) => e.contains("populated 1"),
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

pub fn kill(id: &str) {
    let _ = fs::write(path(id).join("cgroup.kill"), "1");
}

/// every VM at once, for when there's no telling which ones have a network
pub fn kill_all() {
    let _ = fs::write(
        PathBuf::from("/sys/fs/cgroup")
            .join(PARENT)
            .join("cgroup.kill"),
        "1",
    );
}

/// true when the cgroup no longer exists
pub fn remove(id: &str) -> bool {
    match fs::remove_dir(path(id)) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// create the VM's cgroup before anything runs, so the jailer can join it
/// between fork and exec. a wrapper that dies at any point after that leaves a
/// populated cgroup the reaper can kill, never an untracked VM
pub fn prepare(id: &str) -> std::io::Result<std::ffi::CString> {
    let root = PathBuf::from("/sys/fs/cgroup");
    let parent = root.join(PARENT);
    fs::create_dir_all(&parent)?;
    for dir in [&root, &parent] {
        // already enabled is fine; a missing controller shows up as a jailer error later
        let _ = fs::write(dir.join("cgroup.subtree_control"), "+cpu +memory +pids");
    }
    fs::create_dir_all(path(id))?;
    let procs = path(id).join("cgroup.procs");
    std::ffi::CString::new(procs.into_os_string().into_encoded_bytes())
        .map_err(|_| std::io::Error::other("bad cgroup path"))
}

/// in a forked child: move this process into the cgroup. only open and write,
/// which are async-signal-safe
/// runs between fork and exec. the child dies with burner from here on, and
/// refuses to go on if burner already died, so a jailer can never start outside
/// the cgroup with nobody left to account for it
pub fn join_from_child(procs: &std::ffi::CStr, parent: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: valid NUL-terminated path; prctl, getppid, open, write and close
    // are plain syscalls, fine between fork and exec
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::getppid() != parent {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ok = libc::write(fd, b"0".as_ptr().cast(), 1) == 1;
        libc::close(fd);
        if !ok {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
