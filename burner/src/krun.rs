//! `burner vmm-krun`: the VMM on macOS. one process per VM, spawned by burner
//! run like the jailer on linux. libkrun takes the process over and exits it
//! when the guest stops. to burner it looks like firecracker: the guest's
//! console on stdout, and for a shell, stdin into the console.

use std::ffi::{CString, c_char, c_int};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use clap::Args;

use crate::sys;

const KERNEL_FORMAT_RAW: u32 = 0;
const DISK_FORMAT_RAW: u32 = 0;
const LOG_LEVEL_ERROR: u32 = 1;
// NET_FEATURE_CSUM | GUEST_CSUM | GUEST_TSO4 | GUEST_UFO | HOST_TSO4 | HOST_UFO
const COMPAT_NET_FEATURES: u32 = 1 | 1 << 1 | 1 << 7 | 1 << 10 | 1 << 11 | 1 << 14;

// linked by build.rs
unsafe extern "C" {
    fn krun_set_log_level(level: u32) -> i32;
    fn krun_create_ctx() -> i32;
    fn krun_set_vm_config(ctx: u32, vcpus: u8, ram_mib: u32) -> i32;
    fn krun_disable_implicit_vsock(ctx: u32) -> i32;
    fn krun_disable_implicit_console(ctx: u32) -> i32;
    fn krun_add_virtio_console_default(ctx: u32, input: c_int, output: c_int, err: c_int) -> i32;
    fn krun_set_kernel(
        ctx: u32,
        path: *const c_char,
        format: u32,
        initramfs: *const c_char,
        cmdline: *const c_char,
    ) -> i32;
    fn krun_add_disk2(
        ctx: u32,
        id: *const c_char,
        path: *const c_char,
        format: u32,
        read_only: bool,
    ) -> i32;
    fn krun_add_net_unixgram(
        ctx: u32,
        path: *const c_char,
        fd: c_int,
        mac: *const u8,
        features: u32,
        flags: u32,
    ) -> i32;
    fn krun_start_enter(ctx: u32) -> i32;
}

#[derive(Args)]
pub struct VmmArgs {
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    rootfs: PathBuf,
    #[arg(long)]
    scratch: PathBuf,
    #[arg(long)]
    job: PathBuf,
    #[arg(long)]
    result: PathBuf,
    #[arg(long)]
    cpus: u8,
    /// MiB
    #[arg(long)]
    mem: u32,
    #[arg(long)]
    cmdline: String,
    /// a unixgram socket to the network proxy, already connected
    #[arg(long)]
    net_fd: Option<i32>,
    /// copy stdin into the console (burner shell)
    #[arg(long)]
    stdin: bool,
    /// boot time (sys::boottime) past which the VMM stops itself
    #[arg(long)]
    until: Option<f64>,
}

pub fn main(a: VmmArgs) -> ExitCode {
    // SAFETY: getppid has no preconditions
    let parent = unsafe { libc::getppid() };
    // launchd took us over: burner died before we got here
    if parent == 1 {
        return ExitCode::from(1);
    }
    watch(parent, a.until);
    let Err(e) = start(&a);
    eprintln!("burner vmm-krun: {e}");
    ExitCode::from(1)
}

/// no PDEATHSIG and no reaper timer on macOS, so the VMM keeps its own watch:
/// it ends when burner does, and a while after its time limit whatever burner
/// is doing. _exit, so nothing waits on a console nobody reads anymore
fn watch(parent: libc::pid_t, until: Option<f64>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(200));
            // SAFETY: getppid and _exit have no preconditions
            unsafe {
                if libc::getppid() != parent {
                    libc::_exit(1);
                }
                if until.is_some_and(|u| sys::boottime() > u) {
                    libc::_exit(1);
                }
            }
        }
    });
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("path with a NUL"))
}

fn check(what: &str, r: i32) -> io::Result<u32> {
    if r < 0 {
        return Err(io::Error::other(format!(
            "{what}: {}",
            io::Error::from_raw_os_error(-r)
        )));
    }
    Ok(r as u32)
}

fn start(a: &VmmArgs) -> io::Result<std::convert::Infallible> {
    let kernel = cstr(&a.kernel)?;
    let cmdline = CString::new(a.cmdline.as_bytes()).map_err(io::Error::other)?;
    let disks = [
        (c"rootfs", &a.rootfs, true),
        (c"scratch", &a.scratch, false),
        (c"job", &a.job, true),
        (c"result", &a.result, false),
    ];
    // SAFETY: plain calls into libkrun with a context it handed out and
    // NUL-terminated strings that outlive them
    unsafe {
        check("log level", krun_set_log_level(LOG_LEVEL_ERROR))?;
        let ctx = check("context", krun_create_ctx())?;
        check("vm config", krun_set_vm_config(ctx, a.cpus, a.mem))?;
        // no TSI: without it the guest has no way out but the disks and the console
        check("vsock", krun_disable_implicit_vsock(ctx))?;
        check("console", krun_disable_implicit_console(ctx))?;
        let slave = console(a.stdin)?;
        check(
            "console",
            krun_add_virtio_console_default(ctx, slave, slave, slave),
        )?;
        check(
            "kernel",
            krun_set_kernel(
                ctx,
                kernel.as_ptr(),
                KERNEL_FORMAT_RAW,
                std::ptr::null(),
                cmdline.as_ptr(),
            ),
        )?;
        // added in this order they're vda..vdd, what guest init expects
        for (id, path, ro) in disks {
            let p = cstr(path)?;
            check(
                "disk",
                krun_add_disk2(ctx, id.as_ptr(), p.as_ptr(), DISK_FORMAT_RAW, ro),
            )?;
        }
        if let Some(fd) = a.net_fd {
            // TODO: the proxy decides the mac, features and flags it wants
            let mac = [0x06, 0x00, 0xac, 0x1d, 0x00, 0x02];
            check(
                "net",
                krun_add_net_unixgram(
                    ctx,
                    std::ptr::null(),
                    fd,
                    mac.as_ptr(),
                    COMPAT_NET_FEATURES,
                    0,
                ),
            )?;
        }
        let r = krun_start_enter(ctx);
        Err(io::Error::other(format!(
            "start: {}",
            io::Error::from_raw_os_error(-r)
        )))
    }
}

static MASTER: AtomicI32 = AtomicI32::new(-1);
static PUMP: Mutex<()> = Mutex::new(());

/// the guest's console is a pty in raw mode: plain pipes make libkrun send the
/// output to its logger instead. returns the slave for libkrun; a thread copies
/// the master to stdout, and another one stdin to the master for a shell
fn console(stdin: bool) -> io::Result<c_int> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty fills two fds; cfmakeraw and tcsetattr work on a
    // zeroed-then-read termios of the slave we just got
    unsafe {
        if libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(slave, &mut t) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::cfmakeraw(&mut t);
        if libc::tcsetattr(slave, libc::TCSANOW, &t) != 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in [master, slave] {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    sys::set_nonblocking(master)?;
    MASTER.store(master, Ordering::SeqCst);
    // libkrun ends the process with exit(): this copies out what the guest
    // wrote last, which the pump thread may not have picked up yet
    // SAFETY: registering a plain extern "C" fn
    unsafe { libc::atexit(drain) };
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            if !sys::readable(master, Duration::from_millis(100)) {
                continue;
            }
            let _g = PUMP.lock().unwrap_or_else(|e| e.into_inner());
            if !copy_out(master, &mut buf) {
                break;
            }
        }
    });
    if stdin {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 16384];
            loop {
                // SAFETY: read into a buffer we own
                let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
                if n == 0
                    || (n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted)
                {
                    break;
                }
                if n > 0 && !write_all(master, &buf[..n as usize]) {
                    break;
                }
            }
        });
    }
    Ok(slave)
}

/// one read from the master to stdout. false once the console is gone
fn copy_out(master: c_int, buf: &mut [u8]) -> bool {
    // SAFETY: read into a buffer we own
    let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
    if n > 0 {
        if !write_all(1, &buf[..n as usize]) {
            // burner stopped reading the console: it's gone or tearing down
            // SAFETY: _exit has no preconditions
            unsafe { libc::_exit(1) };
        }
        return true;
    }
    n < 0
        && matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        )
}

/// write all of buf, waiting out a full nonblocking fd
fn write_all(fd: c_int, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: write from a live buffer
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
            continue;
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(5)),
            _ => return false,
        }
    }
    true
}

extern "C" fn drain() {
    let master = MASTER.load(Ordering::SeqCst);
    if master < 0 {
        return;
    }
    let _g = PUMP.lock().unwrap_or_else(|e| e.into_inner());
    let mut buf = vec![0u8; 65536];
    while sys::readable(master, Duration::ZERO) {
        // SAFETY: read into a buffer we own
        let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 || !write_all(1, &buf[..n as usize]) {
            break;
        }
    }
}
