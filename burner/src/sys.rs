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

#[cfg(target_os = "linux")]
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// changes on every boot, so a pid recorded before a reboot never matches
#[cfg(target_os = "macos")]
pub fn boot_id() -> String {
    sysctl_string(c"kern.bootsessionuuid").unwrap_or_default()
}

/// a child of ours has exited, waited for or not. a zombie isn't reaped here,
/// so its pid and group stay its own
#[cfg(target_os = "macos")]
pub fn exited(pid: u32) -> bool {
    // SAFETY: waitid fills a zeroed siginfo_t; WNOWAIT leaves the child as it is
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        // ECHILD: it was reaped already
        r != 0 || info.si_pid != 0
    }
}

/// "27.0.1"
#[cfg(target_os = "macos")]
pub fn macos_version() -> Option<String> {
    sysctl_string(c"kern.osproductversion")
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &std::ffi::CStr) -> Option<String> {
    let mut buf = [0u8; 128];
    let mut len = buf.len();
    // SAFETY: valid name, a buffer of len bytes, no new value
    let r = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    let s = &buf[..len.min(buf.len())];
    Some(
        String::from_utf8_lossy(s)
            .trim_end_matches('\0')
            .trim()
            .to_string(),
    )
}

/// seconds since boot, including suspend. survives wall clock changes
#[cfg(target_os = "linux")]
pub fn boottime() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// on macOS CLOCK_MONOTONIC keeps counting while the machine sleeps, like
/// CLOCK_BOOTTIME on linux
#[cfg(target_os = "macos")]
pub fn boottime() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// a process's start time in clock ticks since boot, field 22 of /proc/pid/stat.
/// with the boot id it tells a process apart from a later one that reused its pid
#[cfg(target_os = "linux")]
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

/// a process's start time in microseconds since the epoch, None for a zombie
#[cfg(target_os = "macos")]
pub fn proc_start(pid: u32) -> Option<u64> {
    const SZOMB: u32 = 5;
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
    if n != size || info.pbi_status == SZOMB {
        return None;
    }
    Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
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

/// a control char set to this does nothing. 0 on linux; on macOS 0 is the
/// NUL key (ctrl-space), which would then quit or stop burner
#[cfg(target_os = "linux")]
const VDISABLE: libc::cc_t = libc::_POSIX_VDISABLE;
#[cfg(target_os = "macos")]
const VDISABLE: libc::cc_t = 0xff;

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
    t.c_cc[libc::VQUIT] = VDISABLE;
    t.c_cc[libc::VSUSP] = VDISABLE;
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

/// a new pseudo terminal pair of the given size: (master, slave), both
/// close-on-exec
pub fn openpty(
    (rows, cols): (u16, u16),
) -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let (mut m, mut s) = (-1, -1);
    let mut ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills two fds; no name buffer, default termios
    let r = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut ws,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both were just opened and are ours
    let (m, s) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(m),
            std::os::fd::OwnedFd::from_raw_fd(s),
        )
    };
    for fd in [&m, &s] {
        use std::os::fd::AsRawFd;
        // SAFETY: fcntl only flags the fd
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok((m, s))
}

/// a terminal's size, which sends its foreground job SIGWINCH
pub fn set_term_size(fd: i32, (rows, cols): (u16, u16)) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads a winsize
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// whether any of `fds` hung up: a pipe or socket whose other end is gone,
/// a terminal that was hung up. macOS only says so when asked about writing
pub fn hung_up(fds: &[i32]) -> bool {
    let mut p: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        })
        .collect();
    // SAFETY: p is a valid array of p.len() pollfds
    let n = unsafe { libc::poll(p.as_mut_ptr(), p.len() as libc::nfds_t, 0) };
    n > 0
        && p.iter()
            .any(|x| x.revents & (libc::POLLERR | libc::POLLHUP) != 0)
}

/// fire-and-forget to the system log. never blocks, so it's safe under a lock
#[cfg(target_os = "linux")]
pub fn syslog(msg: &str) {
    use std::os::unix::net::UnixDatagram;
    if let Ok(s) = UnixDatagram::unbound() {
        let _ = s.set_nonblocking(true);
        // facility daemon (3), severity info (6)
        let _ = s.send_to(format!("<30>burner: {msg}").as_bytes(), "/dev/log");
    }
}

/// syslog(3) on macOS goes to the unified log (log show --predicate
/// 'process == "burner"'). notice, since info isn't kept on disk there
#[cfg(target_os = "macos")]
pub fn syslog(msg: &str) {
    let Ok(m) = std::ffi::CString::new(msg.replace('\0', "?")) else {
        return;
    };
    // SAFETY: a constant format string and one NUL-terminated argument
    unsafe {
        libc::syslog(
            libc::LOG_NOTICE | libc::LOG_DAEMON,
            c"%s".as_ptr(),
            m.as_ptr(),
        )
    };
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
#[cfg(target_os = "linux")]
pub fn preallocate(f: &File, size: u64) -> io::Result<()> {
    // SAFETY: valid fd, offset 0, mode 0 allocates blocks and extends the file
    if unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size as libc::off_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn preallocate(f: &File, size: u64) -> io::Result<()> {
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: size as libc::off_t,
        fst_bytesalloc: 0,
    };
    // SAFETY: valid fd and a valid fstore_t
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &mut store) } != 0 {
        return Err(io::Error::last_os_error());
    }
    f.set_len(size)
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
    run_until(cmd, input, limit, &|| false)
}

/// run_timeout that also gives up, the same way, as soon as `stop` says so.
/// the helper has its own process group, so a ctrl-c only reaches burner
pub fn run_until(
    cmd: &mut Command,
    input: Option<&[u8]>,
    limit: Duration,
    stop: &dyn Fn() -> bool,
) -> io::Result<Output> {
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
            Ok(None) if stop() => {
                kill_all(&mut child);
                return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
            }
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

/// this burner binary, for the helpers it runs as itself. on linux the running
/// file itself: an upgrade while VMs run replaces the path, never that
#[cfg(target_os = "linux")]
pub fn self_exe() -> std::path::PathBuf {
    "/proc/self/exe".into()
}

/// macOS has no /proc/self/exe. resolved on first use (main does that right
/// away), so a homebrew upgrade that moves the link later doesn't switch binaries
#[cfg(target_os = "macos")]
pub fn self_exe() -> std::path::PathBuf {
    static EXE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    EXE.get_or_init(|| {
        std::env::current_exe()
            .and_then(fs::canonicalize)
            .unwrap_or_default()
    })
    .clone()
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
#[cfg(target_os = "linux")]
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

/// macOS has no pidfd: the start time check and the signal are two steps, so a
/// pid reused in between could get it. pids wrap slowly enough that this is
/// the same tradeoff every mac process manager makes
#[cfg(target_os = "macos")]
pub fn signal_ident(who: &crate::ledger::Ident, sig: libc::c_int) -> bool {
    // SAFETY: kill is a plain syscall
    who.alive() && unsafe { libc::kill(who.pid as libc::pid_t, sig) } == 0
}

/// the fds open in this process, for a child to close between fork and exec,
/// where it can't list them itself. an error, never an empty list, when they
/// can't be read: the child would close nothing
#[cfg(target_os = "macos")]
pub fn open_fds() -> io::Result<Vec<libc::c_int>> {
    let mut fds = Vec::new();
    for e in fs::read_dir("/dev/fd")? {
        let name = e?.file_name();
        let fd = name
            .to_str()
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| io::Error::other("odd name in /dev/fd"))?;
        fds.push(fd);
    }
    Ok(fds)
}

/// in a forked child: close what of `fds` would survive exec, except stdio and
/// `keep`. no jailer on macOS to close what the caller left open without
/// close-on-exec, and a sandbox only limits what gets opened later
#[cfg(target_os = "macos")]
pub fn close_strays(fds: &[libc::c_int], keep: &[libc::c_int]) {
    for &fd in fds {
        if fd <= 2 || keep.contains(&fd) {
            continue;
        }
        // SAFETY: fcntl and close are async-signal-safe and only touch the
        // child's fd table
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFD);
            if fl >= 0 && fl & libc::FD_CLOEXEC == 0 {
                libc::close(fd);
            }
        }
    }
}

/// the mount a file descriptor lives on, from /proc/self/fdinfo
#[cfg(target_os = "linux")]
fn mnt_id(fd: libc::c_int) -> Option<u64> {
    fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))?
        .trim()
        .parse()
        .ok()
}

/// macOS has no bind mounts, so the filesystem a fd lives on is enough
#[cfg(target_os = "macos")]
fn mnt_id(fd: libc::c_int) -> Option<u64> {
    // SAFETY: zeroed stat is a valid out-parameter for fstat on a fd we hold
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_dev as u64)
}

/// the names in a directory, read through the fd we hold
#[cfg(target_os = "linux")]
fn dir_names(fd: libc::c_int) -> io::Result<Vec<std::ffi::CString>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    // listing through the fd's /proc entry keeps it anchored to this directory
    Ok(fs::read_dir(format!("/proc/self/fd/{fd}"))?
        .filter_map(|e| e.ok())
        .filter_map(|e| CString::new(e.file_name().as_bytes()).ok())
        .collect())
}

#[cfg(target_os = "macos")]
fn dir_names(fd: libc::c_int) -> io::Result<Vec<std::ffi::CString>> {
    // SAFETY: fdopendir takes over a dup of our fd and closedir releases it;
    // readdir's entries are copied out before the next call
    unsafe {
        let dup = libc::dup(fd);
        if dup < 0 {
            return Err(io::Error::last_os_error());
        }
        let d = libc::fdopendir(dup);
        if d.is_null() {
            libc::close(dup);
            return Err(io::Error::last_os_error());
        }
        let mut names = Vec::new();
        loop {
            let e = libc::readdir(d);
            if e.is_null() {
                break;
            }
            let n = std::ffi::CStr::from_ptr((*e).d_name.as_ptr());
            if n != c"." && n != c".." {
                names.push(n.to_owned());
            }
        }
        libc::closedir(d);
        Ok(names)
    }
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
        let names = dir_names(fd).unwrap_or_else(|_| {
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

#[cfg(target_os = "macos")]
mod iokit {
    use std::ffi::{c_char, c_void};

    pub type CFStringRef = *const c_void;
    pub const UTF8: u32 = 0x0800_0100;
    pub const LEVEL_ON: u32 = 255;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        pub fn CFStringCreateWithCString(
            alloc: *const c_void,
            s: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        pub fn CFRelease(cf: *const c_void);
    }

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        pub fn IOPMAssertionCreateWithName(
            kind: CFStringRef,
            level: u32,
            name: CFStringRef,
            id: *mut u32,
        ) -> i32;
        pub fn IOPMAssertionRelease(id: u32) -> i32;
    }
}

/// a sleeping mac freezes its VMs, so a run keeps it from idle sleep while
/// its VM is up, like caffeinate -i. lid close and a forced sleep still win.
/// released on drop, and by macOS when the process goes
#[cfg(target_os = "macos")]
pub struct Awake(Option<u32>);

#[cfg(target_os = "macos")]
impl Awake {
    pub fn hold(name: &str) -> Awake {
        use iokit::*;
        let Ok(name) = std::ffi::CString::new(name) else {
            return Awake(None);
        };
        // SAFETY: two CFStrings made from NUL-terminated strings, each
        // released once; the id is only read when the call says it worked
        unsafe {
            let kind = CFStringCreateWithCString(
                std::ptr::null(),
                c"PreventUserIdleSystemSleep".as_ptr(),
                UTF8,
            );
            let label = CFStringCreateWithCString(std::ptr::null(), name.as_ptr(), UTF8);
            let mut id = 0u32;
            let ok = !kind.is_null()
                && !label.is_null()
                && IOPMAssertionCreateWithName(kind, LEVEL_ON, label, &mut id) == 0;
            for s in [kind, label] {
                if !s.is_null() {
                    CFRelease(s);
                }
            }
            Awake(ok.then_some(id))
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for Awake {
    fn drop(&mut self) {
        if let Some(id) = self.0.take() {
            // SAFETY: an id IOPMAssertionCreateWithName gave us, released once
            unsafe { iokit::IOPMAssertionRelease(id) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hang_ups() {
        let mut fds = [0; 2];
        // SAFETY: pipe(2) fills two fds. close-on-exec, or a child another
        // test spawns meanwhile keeps the read end open
        unsafe {
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            for fd in fds {
                assert_eq!(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            }
        }
        assert!(!hung_up(&[fds[1]]));
        // SAFETY: closing the read end we just made
        unsafe { libc::close(fds[0]) };
        assert!(hung_up(&[fds[1]]));
        // SAFETY: and the write end
        unsafe { libc::close(fds[1]) };
    }

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
