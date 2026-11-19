//! the few raw linux calls burner needs, wrapped once.

use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

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
    let mut f = after_comm.split_whitespace();
    // a zombie has exited, it only waits for its parent to notice. a parent
    // that is stopped itself (sudo, after ctrl-z) may never do that
    if matches!(f.next(), Some("Z" | "X")) {
        return None;
    }
    f.nth(18)?.parse().ok()
}

pub fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    io::Read::read_exact(&mut File::open("/dev/urandom")?, &mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// an exclusive flock held until the guard drops
pub struct Lock(File);

impl Lock {
    /// waits up to a minute: a lock held longer than that means something is
    /// stuck, and failing beats hanging forever
    pub fn exclusive(path: &std::path::Path) -> io::Result<Lock> {
        Lock::exclusive_until(path, std::time::Instant::now() + Duration::from_secs(60))
    }
}

impl Lock {
    /// like exclusive, but gives up at the deadline instead of waiting forever
    pub fn exclusive_until(path: &std::path::Path, until: std::time::Instant) -> io::Result<Lock> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path)?;
        // root-only, so nobody else can open it and sit on the lock
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
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

/// setrlimit's resource type: its own typedef on glibc, a plain int on musl
#[cfg(target_env = "gnu")]
pub type Resource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
pub type Resource = libc::c_int;

/// hard resource limits, run in a forked child before exec. std's Command has
/// already dropped supplementary groups and switched uid by then
pub fn limit_child(limits: &[(Resource, u64)]) -> io::Result<()> {
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

/// raw mode on fd 0 so keystrokes, ctrl-c included, go to the VM as bytes
pub fn set_raw(fd: i32) -> io::Result<()> {
    // SAFETY: zeroed termios is a valid out-parameter
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and termios pointer
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: cfmakeraw only edits the struct
    unsafe { libc::cfmakeraw(&mut t) };
    // SAFETY: valid fd and termios pointer
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// fd 0 while a shell's VM boots: no echo and no line editing, so keys typed
/// early are read as they come and wait for the guest, but ctrl-c still
/// interrupts burner and burner's own messages still get \r\n. ctrl-\ and
/// ctrl-z are off, they'd kill or stop burner
pub fn set_boot_mode(fd: i32) -> io::Result<()> {
    // SAFETY: zeroed termios is a valid out-parameter
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and termios pointer
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL | libc::IEXTEN);
    t.c_lflag |= libc::ISIG;
    // 0 is _POSIX_VDISABLE on linux
    t.c_cc[libc::VQUIT] = 0;
    t.c_cc[libc::VSUSP] = 0;
    t.c_cc[libc::VMIN] = 1;
    t.c_cc[libc::VTIME] = 0;
    // SAFETY: valid fd and termios pointer
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// put the terminal back right away, without waiting on output a dead VM left queued
pub fn restore_tty(t: Option<&libc::termios>) {
    if let Some(t) = t {
        // SAFETY: fd 0 and a termios we read earlier
        unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
    }
}

/// which of `fds` are readable (or at eof/error) within the timeout
pub fn poll_read(fds: &[i32], timeout: Duration) -> Vec<i32> {
    let mut p: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: p is a valid array of p.len() pollfds
    let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, ms) };
    if n <= 0 {
        return Vec::new();
    }
    p.iter().filter(|x| x.revents != 0).map(|x| x.fd).collect()
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

/// run a helper (ip, nft, conntrack) with one time limit covering the process,
/// anything it forks and its output pipes. on timeout its whole process group is
/// killed and reaped. `input` goes to its stdin
pub fn run_timeout(cmd: &mut Command, input: Option<&[u8]>, limit: Duration) -> io::Result<Output> {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;
    const CAP: u64 = 16 << 20;
    let end = Instant::now() + limit;
    let mut child = cmd
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pgid = child.id() as libc::pid_t;
    let kill_all = |child: &mut std::process::Child| {
        // SAFETY: plain kill(2) on the helper's own process group
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.wait();
    };
    if let (Some(mut w), Some(data)) = (child.stdin.take(), input.map(<[u8]>::to_vec)) {
        std::thread::spawn(move || {
            let _ = w.write_all(&data);
        });
    }
    let (tx, rx) = mpsc::channel();
    for (n, r) in [
        child
            .stdout
            .take()
            .map(|r| Box::new(r) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|r| Box::new(r) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .enumerate()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let res = match r {
                Some(r) => r.take(CAP + 1).read_to_end(&mut buf).map(|_| buf),
                None => Ok(buf),
            };
            let _ = tx.send((n, res));
        });
    }
    drop(tx);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                kill_all(&mut child);
                return Err(io::Error::new(io::ErrorKind::TimedOut, "helper timed out"));
            }
            Err(e) => {
                kill_all(&mut child);
                return Err(e);
            }
        }
    };
    // the helper exited; whatever it forked may still hold the pipes open
    let (mut stdout, mut stderr) = (None, None);
    for _ in 0..2 {
        let left = end
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(100));
        match rx.recv_timeout(left) {
            Ok((0, r)) => stdout = Some(r?),
            Ok((_, r)) => stderr = Some(r?),
            Err(_) => {
                // SAFETY: plain kill(2) on the helper's own process group
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper left its output open",
                ));
            }
        }
    }
    let (stdout, stderr) = (stdout.unwrap_or_default(), stderr.unwrap_or_default());
    if stdout.len() as u64 > CAP || stderr.len() as u64 > CAP {
        return Err(io::Error::other("helper output over 16M"));
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// a program on PATH or in the sbin dirs root's PATH sometimes lacks
pub fn which(cmd: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(cmd).is_file()))
        .unwrap_or(false)
        || ["/usr/sbin", "/sbin"]
            .iter()
            .any(|d| std::path::Path::new(d).join(cmd).is_file())
}

static SAVED_TTY: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();

/// the terminal as restore_tty_on_panic found it
pub fn restore_saved_tty() {
    restore_tty(SAVED_TTY.get());
}

/// burner shell's hold on fd 0: saved (for the panic hook too) and in boot
/// mode while it lives, put back when it drops
pub struct ShellTty;

impl ShellTty {
    pub fn take(reset: &'static [u8]) -> ShellTty {
        restore_tty_on_panic(reset);
        let _ = set_boot_mode(0);
        ShellTty
    }
}

impl Drop for ShellTty {
    fn drop(&mut self) {
        restore_saved_tty();
    }
}

/// release builds abort on panic, which skips every cleanup path. the hook
/// still runs first: put the terminal back and undo any screen modes
pub fn restore_tty_on_panic(reset: &'static [u8]) {
    if let Some(t) = save_tty() {
        let _ = SAVED_TTY.set(t);
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // SAFETY: plain write(2) of a static buffer to stdout
        unsafe { libc::write(1, reset.as_ptr().cast(), reset.len()) };
        restore_tty(SAVED_TTY.get());
        prev(info);
    }));
}

/// signal a process only if it's still the one `who` names. the pidfd pins the
/// process, so a pid reused after the check can't get the signal
pub fn signal_ident(who: &crate::ledger::Ident, sig: libc::c_int) -> bool {
    // SAFETY: pidfd_open and pidfd_send_signal are plain syscalls; the fd is
    // closed on every path
    unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, who.pid as libc::pid_t, 0) as libc::c_int;
        if fd < 0 {
            return false;
        }
        let ok = who.alive()
            && libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0;
        libc::close(fd);
        ok
    }
}

/// the mount a file descriptor lives on, from /proc/self/fdinfo
fn mnt_id(fd: libc::c_int) -> Option<u64> {
    fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))?
        .trim()
        .parse()
        .ok()
}

/// delete a tree without following symlinks or leaving the mount it starts on.
/// every directory is opened relative to its parent's fd with O_NOFOLLOW, so a
/// path swapped mid-walk can't redirect it, and a directory on another mount
/// (a bind mount included) stops the delete. true only when it's all gone
pub fn remove_tree_at(path: &std::path::Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let (Ok(parent), Ok(name)) = (
        CString::new(parent.as_os_str().as_bytes()),
        CString::new(name.as_bytes()),
    ) else {
        return false;
    };
    // SAFETY: plain open(2) of a NUL-terminated path
    let pfd = unsafe {
        libc::open(
            parent.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if pfd < 0 {
        return false;
    }
    let ok = match mnt_id(pfd) {
        Some(mnt) => remove_at(pfd, &name, mnt),
        None => false,
    };
    // SAFETY: closing the fd opened above
    unsafe { libc::close(pfd) };
    ok
}

fn remove_at(dirfd: libc::c_int, name: &std::ffi::CStr, mnt: u64) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: openat(2) relative to a dir fd we hold, never following a symlink
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error().raw_os_error();
        return match err {
            // a file or a symlink: unlink the name itself
            // SAFETY: unlinkat(2) of a name in a dir fd we hold
            Some(libc::ENOTDIR) | Some(libc::ELOOP) => unsafe {
                libc::unlinkat(dirfd, name.as_ptr(), 0) == 0
            },
            Some(libc::ENOENT) => true,
            _ => false,
        };
    }
    let mut ok = mnt_id(fd) == Some(mnt);
    if ok {
        // listing through the fd's /proc entry keeps it anchored to this directory
        let names: Vec<CString> = fs::read_dir(format!("/proc/self/fd/{fd}"))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| CString::new(e.file_name().as_bytes()).ok())
                    .collect()
            })
            .unwrap_or_else(|_| {
                ok = false;
                Vec::new()
            });
        for n in names {
            ok &= remove_at(fd, &n, mnt);
        }
    }
    // SAFETY: closing the fd opened above
    unsafe { libc::close(fd) };
    // SAFETY: unlinkat(2) of a name in a dir fd we hold
    ok && unsafe { libc::unlinkat(dirfd, name.as_ptr(), libc::AT_REMOVEDIR) == 0 }
}

/// a directory only root can enter: burner's state dir and the ledger in it
pub fn private_dir(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_tree_stays_inside() {
        let base = std::env::temp_dir().join(format!("burner-rm-{}", random_hex(6).unwrap()));
        let keep = base.join("keep");
        let tree = base.join("tree");
        fs::create_dir_all(tree.join("a/b/c")).unwrap();
        fs::create_dir_all(&keep).unwrap();
        fs::write(keep.join("precious"), "x").unwrap();
        fs::write(tree.join("a/b/c/f"), "y").unwrap();
        std::os::unix::fs::symlink(&keep, tree.join("a/link")).unwrap();
        std::os::unix::fs::symlink(keep.join("precious"), tree.join("flink")).unwrap();
        assert!(remove_tree_at(&tree));
        assert!(!tree.exists());
        assert!(keep.join("precious").exists());
        assert!(remove_tree_at(&tree), "already gone counts as removed");
        fs::remove_dir_all(&base).unwrap();
    }
}
