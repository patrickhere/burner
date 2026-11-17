//! the few raw linux calls burner needs, wrapped once.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions
    unsafe { libc::geteuid() == 0 }
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// seconds since boot, including suspend. survives wall clock changes
pub fn boottime() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// a process's start time in clock ticks since boot, field 22 of /proc/pid/stat.
/// with the boot id it tells a process apart from a later one that reused its pid
pub fn proc_start(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 2..];
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

pub fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    io::Read::read_exact(&mut File::open("/dev/urandom")?, &mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// an exclusive flock held until the guard drops
pub struct Lock(File);

impl Lock {
    pub fn exclusive(path: &std::path::Path) -> io::Result<Lock> {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        // SAFETY: valid fd for the life of the call
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(f))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: valid fd
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: fcntl on an fd we own
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// true when fd has data (or eof) within the timeout
pub fn readable(fd: i32, timeout: Duration) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one valid pollfd
    let n = unsafe { libc::poll(&mut p, 1, ms) };
    n > 0
}

pub fn is_tty(fd: i32) -> bool {
    // SAFETY: isatty only reads the fd
    unsafe { libc::isatty(fd) == 1 }
}

/// hard resource limits, run in a forked child before exec. std's Command has
/// already dropped supplementary groups and switched uid by then
pub fn limit_child(limits: &[(libc::__rlimit_resource_t, u64)]) -> io::Result<()> {
    // SAFETY: called between fork and exec; setrlimit is async-signal-safe
    unsafe {
        for &(res, v) in limits {
            let r = libc::rlimit {
                rlim_cur: v,
                rlim_max: v,
            };
            if libc::setrlimit(res, &r) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// move fd to `to` in a forked child (dup2 clears close-on-exec on the copy)
pub fn dup_to(fd: i32, to: i32) -> io::Result<()> {
    // SAFETY: plain dup2 between fork and exec
    if unsafe { libc::dup2(fd, to) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn user_ids(name: &str) -> Option<(u32, u32)> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<_> = l.split(':').collect();
        (f.len() > 3 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
    })
}
