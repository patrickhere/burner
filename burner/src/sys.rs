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

impl Lock {
    /// like exclusive, but gives up at the deadline instead of waiting forever
    pub fn exclusive_until(path: &std::path::Path, until: std::time::Instant) -> io::Result<Lock> {
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)?;
        loop {
            // SAFETY: valid fd for the life of the call
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Lock(f));
            }
            if std::time::Instant::now() > until {
                return Err(io::Error::other(format!(
                    "timed out waiting for {}",
                    path.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
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

pub fn term_size(fd: i32) -> Option<(u16, u16)> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ fills a winsize
    let ok = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0;
    (ok && ws.ws_row > 0 && ws.ws_col > 0).then_some((ws.ws_row, ws.ws_col))
}

pub fn save_tty() -> Option<libc::termios> {
    // SAFETY: zeroed termios is a valid out-parameter
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 and a valid termios pointer
    (unsafe { libc::tcgetattr(0, &mut t) } == 0).then_some(t)
}

/// firecracker puts the terminal in raw mode; put it back even when it was killed
pub fn restore_tty(t: Option<&libc::termios>) {
    if let Some(t) = t {
        // SAFETY: fd 0 and a termios we read earlier
        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, t) };
    }
}

/// fire-and-forget to the system log. never blocks, so it's safe under a lock
pub fn syslog(msg: &str) {
    use std::os::unix::net::UnixDatagram;
    if let Ok(s) = UnixDatagram::unbound() {
        let _ = s.set_nonblocking(true);
        // facility daemon (3), severity info (6)
        let _ = s.send_to(format!("<30>burner: {msg}").as_bytes(), "/dev/log");
    }
}

/// bytes free for root on the filesystem holding `path`
pub fn free_bytes(path: &std::path::Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: zeroed statvfs is a valid out-parameter, c is NUL-terminated
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

/// reserve the full size on disk now, so a guest filling its disk can't fill the host's
pub fn preallocate(f: &File, size: u64) -> io::Result<()> {
    // SAFETY: valid fd, offset 0, mode 0 allocates blocks and extends the file
    if unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size as libc::off_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// a close-on-exec copy of fd numbered at least `min`
pub fn dup_above(fd: i32, min: i32) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: F_DUPFD_CLOEXEC on an fd we own returns a new fd we then own
    let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: n is a fresh fd nobody else owns
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(n) })
}
