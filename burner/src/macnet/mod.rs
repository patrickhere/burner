//! `burner macnet`: the network for one VM on macOS. libkrun hands the guest's
//! virtio-net frames to one end of a unixgram socketpair, this process holds
//! the other end, acts as the guest's gateway and opens real host connections
//! only for what the policy allows. no root, no packet filter. burner run
//! starts it in the VMM's process group, so it goes when the VM does, and it
//! exits on its own once the VM's end of the socket closes.

mod net;
pub(crate) mod policy;
pub(crate) mod route;
pub(crate) mod sandbox;

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitCode, Stdio};

use clap::Args;

use crate::config::Config;
use crate::sys;
use policy::{Mode, Policy};

/// macos sizes a unix datagram socket's buffers for a few frames and caps a
/// datagram at 2k. both ends get room for bursts and for 64k datagrams
pub const SOCK_RCVBUF: libc::c_int = 4 << 20;
pub const SOCK_SNDBUF: libc::c_int = 64 << 10;

#[derive(Args)]
pub struct MacnetArgs {
    /// this process's end of a unixgram socketpair, one ethernet frame per datagram
    #[arg(long)]
    fd: i32,
    /// web: tcp 80 and 443. open: any tcp port but mail. dns to the resolvers in both
    #[arg(long)]
    mode: String,
    /// a dns server the guest may use (udp and tcp 53), repeatable
    #[arg(long)]
    resolver: Vec<Ipv4Addr>,
    /// an extra range the guest must never reach, repeatable
    #[arg(long)]
    block: Vec<String>,
    /// the public address net.block_public_ip found, blocked too
    #[arg(long)]
    public_ip: Option<Ipv4Addr>,
    /// the guest's address and prefix (what burner's ip= hands it)
    #[arg(long, default_value = "172.29.217.2/30")]
    guest: String,
    /// this process's address on the guest's network
    #[arg(long, default_value = "172.29.217.1")]
    gateway: Ipv4Addr,
    /// bytes a second each way, 0 for no limit
    #[arg(long, default_value_t = 0)]
    rate: u64,
    /// log every connection and refusal to stderr
    #[arg(short)]
    v: bool,
    /// write the connection log's events here, one JSON line each, never
    /// blocking: what doesn't fit is counted as lost
    #[arg(long)]
    events: Option<i32>,
}

pub struct Link {
    pub fd: i32,
    pub guest: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub rate: u64,
    pub verbose: bool,
    pub events: Option<i32>,
}

pub fn main(a: MacnetArgs) -> ExitCode {
    match start(a) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("burner net: {e}");
            ExitCode::from(1)
        }
    }
}

fn start(a: MacnetArgs) -> io::Result<()> {
    // 256 open files by default: fewer than the flows and dns sockets allowed
    nofile(1024);
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
    let mode = Mode::parse(&a.mode).ok_or_else(|| bad("--mode must be web or open"))?;
    let mut block = Vec::new();
    for b in &a.block {
        block.push(policy::parse_cidr(b).ok_or_else(|| bad("bad --block"))?);
    }
    let (ip, prefix) = policy::parse_cidr(&a.guest).ok_or_else(|| bad("bad --guest"))?;
    if !(1..=30).contains(&prefix) || !policy::inside(a.gateway, ip, prefix) || a.gateway == ip {
        return Err(bad(
            "--gateway must be another address on the --guest network",
        ));
    }
    let pol = Policy::new(mode, a.resolver, &block, a.public_ip, (ip, prefix));
    sandbox::enter()?;
    let args = Link {
        fd: a.fd,
        guest: ip,
        prefix,
        gateway: a.gateway,
        rate: a.rate,
        verbose: a.v,
        events: a.events,
    };
    net::run(&args, pol)
}

fn nofile(want: libc::rlim_t) {
    let mut r = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit on a live local
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 && r.rlim_cur < want {
            r.rlim_cur = want.min(r.rlim_max);
            libc::setrlimit(libc::RLIMIT_NOFILE, &r);
        }
    }
}

/// a running macnet. dropping it stops it and waits for it
pub struct Proc(Child);

impl Proc {
    pub fn id(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// start macnet on its end of the pair, in the VMM's process group: whatever
/// stops the VM (teardown, burner kill, the reaper) signals that group. what it
/// says goes to `log`, the VM's log, never the caller's terminal
pub fn spawn(
    cfg: &Config,
    mode: crate::net::Mode,
    s: &crate::net::Slot,
    fd: OwnedFd,
    group: u32,
    log: std::fs::File,
    events: Option<OwnedFd>,
) -> io::Result<Proc> {
    let raw = fd.as_raw_fd();
    let ev = events.as_ref().map(|e| e.as_raw_fd());
    let mut cmd = Command::new(sys::self_exe());
    cmd.arg("macnet")
        .args(["--fd", &raw.to_string(), "--mode", mode.name()])
        .args(["--guest", &format!("{}/30", s.guest)])
        .args(["--gateway", &s.host.to_string()])
        .args(["--rate", &cfg.net.rate.to_string()]);
    for r in &cfg.net.resolvers {
        cmd.args(["--resolver", &r.to_string()]);
    }
    if let Some(e) = ev {
        cmd.args(["--events", &e.to_string()]);
    }
    for b in &cfg.net.block {
        cmd.args(["--block", b]);
    }
    // a stale answer from this same network still counts for an hour, as on
    // linux: the old address is more likely still the router's than not
    if cfg.net.block_public_ip {
        let (ip, _) = crate::net::public_ip(cfg).ok_or_else(|| {
            io::Error::other(
                "net.block_public_ip is on but there's no public address for this network",
            )
        })?;
        cmd.args(["--public-ip", &ip.to_string()]);
    }
    cmd.process_group(group as libc::pid_t);
    let fds = sys::open_fds()?;
    // SAFETY: close_strays and inherit only call fcntl and close
    unsafe {
        cmd.pre_exec(move || {
            let keep: Vec<RawFd> = std::iter::once(raw).chain(ev).collect();
            sys::close_strays(&fds, &keep);
            inherit(raw)?;
            ev.map_or(Ok(()), inherit)
        });
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir("/")
        .spawn()?;
    drop(fd);
    // macnet holds the write end now: the reader sees it close when macnet goes
    drop(events);
    Ok(Proc(child))
}

/// for doctor: start macnet the way burner run does, on a socket whose other
/// end is already closed. it has to get into its sandbox and its loop, see the
/// VM gone and exit cleanly
pub fn probe() -> Result<(), String> {
    let (vm_end, net_end) = pair().map_err(|e| e.to_string())?;
    drop(vm_end);
    let raw = net_end.as_raw_fd();
    let mut cmd = Command::new(sys::self_exe());
    cmd.args(["macnet", "-v", "--fd", &raw.to_string(), "--mode", "web"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir("/");
    let fds = sys::open_fds().map_err(|e| e.to_string())?;
    // SAFETY: close_strays and inherit only call fcntl and close
    unsafe {
        cmd.pre_exec(move || {
            sys::close_strays(&fds, &[raw]);
            inherit(raw)
        });
    }
    let out = sys::run_timeout(&mut cmd, None, std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    drop(net_end);
    let err = String::from_utf8_lossy(&out.stderr);
    if out.status.success() && err.contains("socket closed, exiting") {
        return Ok(());
    }
    Err(err
        .lines()
        .last()
        .map_or_else(|| format!("exited with {}", out.status), str::to_string))
}

/// the two ends of a VM's network, close-on-exec and with big enough buffers:
/// (the VMM's, macnet's)
pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut sv = [-1; 2];
    // SAFETY: socketpair fills two fds, owned right after
    let (a, b) = unsafe {
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1]))
    };
    for fd in [&a, &b] {
        let fd = fd.as_raw_fd();
        // SAFETY: fcntl on an fd we own
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        setopt(fd, libc::SO_RCVBUF, SOCK_RCVBUF)?;
        setopt(fd, libc::SO_SNDBUF, SOCK_SNDBUF)?;
    }
    Ok((a, b))
}

/// the connection log's pipe: (burner run's read end, macnet's write end),
/// close-on-exec, and the write end never raises SIGPIPE
pub fn events_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut p = [-1; 2];
    // SAFETY: pipe fills two fds, owned right after
    let (r, w) = unsafe {
        if libc::pipe(p.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1]))
    };
    for fd in [r.as_raw_fd(), w.as_raw_fd()] {
        // SAFETY: fcntl on fds we own
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: fcntl on an fd we own
    unsafe { libc::fcntl(w.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) };
    Ok((r, w))
}

/// for pre_exec: let exactly this fd through to the exec'd child
pub fn inherit(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl is async-signal-safe and only touches the child's fd table
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn setopt(fd: RawFd, opt: libc::c_int, val: libc::c_int) -> io::Result<()> {
    // SAFETY: setsockopt reads one int from a live local
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&val as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
