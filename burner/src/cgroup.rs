//! each VM runs in its own cgroup under /sys/fs/cgroup/burner. killing and
//! checking the cgroup is how burner knows a VM is really gone.

use std::fs;
use std::path::PathBuf;

pub const PARENT: &str = "burner";

fn path(id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup").join(PARENT).join(id)
}

pub fn populated(id: &str) -> bool {
    fs::read_to_string(path(id).join("cgroup.events")).is_ok_and(|e| e.contains("populated 1"))
}

pub fn kill(id: &str) {
    let _ = fs::write(path(id).join("cgroup.kill"), "1");
}

pub fn remove(id: &str) {
    let _ = fs::remove_dir(path(id));
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
pub fn join_from_child(procs: &std::ffi::CStr) -> std::io::Result<()> {
    // SAFETY: valid NUL-terminated path; plain syscalls between fork and exec
    unsafe {
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
