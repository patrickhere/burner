//! the gateway. smoltcp terminates the guest's tcp and dns, and every flow the
//! policy allows is spliced onto a real host socket. a guest syn is held until
//! the host connection is up, so the guest sees the real outcome: a syn-ack
//! when the far end answered, a reset when it refused or timed out, and nothing
//! at all when the policy says no

use std::collections::{HashMap, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration as StdDuration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, IpAddress, IpCidr,
    IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket,
};
use socket2::{Domain, Protocol, Socket, Type};

use crate::Args;
use crate::policy::Policy;

/// ethernet header plus a 1500 mtu. libkrun gets no offload features, so the
/// guest never sends more than this
const FRAME: usize = 1514;
const GATEWAY_MAC: [u8; 6] = [0x02, 0x00, 0xac, 0x1d, 0xd9, 0x01];
const TCP_BUF: usize = 64 * 1024;
const MAX_FLOWS: usize = 256;
const MAX_DNS: usize = 64;
const CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(15);
const DNS_IDLE: StdDuration = StdDuration::from_secs(10);
/// guest connections are aborted when the guest stops acking for this long
const GUEST_TIMEOUT: Duration = Duration::from_secs(120);
const TX_QUEUE: usize = 1024;
const RX_BATCH: usize = 256;
/// macos sizes a unix datagram socket's buffers tiny by default: a few frames
const SOCK_RCVBUF: libc::c_int = 4 << 20;
const SOCK_SNDBUF: libc::c_int = 64 << 10;

/// guest port, destination, destination port
type Key = (u16, Ipv4Addr, u16);

struct Dev {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _: Instant) -> Option<(RxTok, TxTok<'_>)> {
        let f = self.rx.pop_front()?;
        Some((RxTok(f), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<TxTok<'_>> {
        (self.tx.len() < TX_QUEUE).then_some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        c.max_transmission_unit = FRAME;
        c
    }
}

struct Conn {
    handle: SocketHandle,
    host: TcpStream,
    to_host: Vec<u8>,
    host_eof: bool,
    shut: bool,
    readable: bool,
}

struct Pending {
    sock: Socket,
    syn: Vec<u8>,
    deadline: StdInstant,
    ready: bool,
}

struct Dns {
    host: UdpSocket,
    guest_port: u16,
    resolver: Ipv4Addr,
    last: StdInstant,
}

struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: StdInstant,
}

impl Bucket {
    fn new(rate: f64, burst: f64) -> Bucket {
        Bucket {
            tokens: burst,
            rate,
            burst,
            last: StdInstant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = StdInstant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

enum Verdict {
    Pass,
    Drop,
    Syn(Key),
}

enum Who {
    Vm,
    // dns_in tries every resolver socket, this only wakes the loop
    Dns,
    Pending(Key),
    Conn(Key),
}

struct Gw<'a> {
    args: &'a Args,
    pol: Policy,
    vm: RawFd,
    iface: Interface,
    dev: Dev,
    sockets: SocketSet<'static>,
    udp53: SocketHandle,
    conns: HashMap<Key, Conn>,
    pending: HashMap<Key, Pending>,
    dns: Vec<Dns>,
    // the linux table's meters: 20 new web connections a second, burst 40,
    // and 20 dns packets a second, burst 50
    new_conns: Bucket,
    dns_rate: Bucket,
    tx_blocked: bool,
}

pub fn run(args: &Args, pol: Policy) -> io::Result<()> {
    let vm = args.fd;
    let mut ty: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            vm,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut ty as *mut _ as *mut _,
            &mut len,
        )
    };
    if r != 0 || ty != libc::SOCK_DGRAM {
        return Err(io::Error::other(format!(
            "--fd {vm} is not a datagram socket"
        )));
    }
    setopt(vm, libc::SO_RCVBUF, SOCK_RCVBUF)?;
    setopt(vm, libc::SO_SNDBUF, SOCK_SNDBUF)?;
    #[cfg(target_os = "macos")]
    setopt(vm, libc::SO_NOSIGPIPE, 1)?;
    unsafe {
        let fl = libc::fcntl(vm, libc::F_GETFL);
        if fl < 0 || libc::fcntl(vm, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let ppid = unsafe { libc::getppid() };

    let mut dev = Dev {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(GATEWAY_MAC)));
    cfg.random_seed = seed();
    let mut iface = Interface::new(cfg, &mut dev, Instant::now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::Ipv4(args.gateway), args.prefix));
    });
    // every destination the guest names is answered here, the policy decides
    // which of them get a real connection behind them
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let udp_buf =
        || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 64 << 10]);
    let mut u = udp::Socket::new(udp_buf(), udp_buf());
    u.bind(53).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let udp53 = sockets.add(u);

    let mut gw = Gw {
        args,
        pol,
        vm,
        iface,
        dev,
        sockets,
        udp53,
        conns: HashMap::new(),
        pending: HashMap::new(),
        dns: Vec::new(),
        new_conns: Bucket::new(20.0, 40.0),
        dns_rate: Bucket::new(20.0, 50.0),
        tx_blocked: false,
    };
    let mut buf = vec![0u8; 65536];
    loop {
        let (mut fds, who) = gw.pollfds();
        let timeout = gw.timeout();
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        for (f, w) in fds.iter().zip(&who) {
            if f.revents == 0 {
                continue;
            }
            match w {
                Who::Vm | Who::Dns => {}
                Who::Pending(k) => {
                    if let Some(p) = gw.pending.get_mut(k) {
                        p.ready = true;
                    }
                }
                Who::Conn(k) => {
                    if let Some(c) = gw.conns.get_mut(k) {
                        c.readable = true;
                    }
                }
            }
        }
        if fds[0].revents & libc::POLLNVAL != 0 {
            return Err(io::Error::other("the VM socket was closed under us"));
        }
        if fds[0].revents != 0 && !gw.read_vm(&mut buf)? {
            gw.log(format_args!("the VM's end of the socket closed, exiting"));
            return Ok(());
        }
        gw.poll();
        gw.resolve_pending();
        gw.pump();
        gw.dns_out();
        gw.dns_in();
        gw.poll();
        gw.reap();
        if !gw.flush()? {
            gw.log(format_args!("the VM's end of the socket closed, exiting"));
            return Ok(());
        }
        // backstop for a launcher that dies without its VM end ever closing
        if unsafe { libc::getppid() } != ppid {
            gw.log(format_args!("parent exited, exiting"));
            return Ok(());
        }
    }
}

impl Gw<'_> {
    fn log(&self, msg: std::fmt::Arguments) {
        if self.args.verbose {
            eprintln!("burner-macnet: {msg}");
        }
    }

    fn poll(&mut self) {
        self.iface
            .poll(Instant::now(), &mut self.dev, &mut self.sockets);
    }

    fn pollfds(&self) -> (Vec<libc::pollfd>, Vec<Who>) {
        let pfd = |fd, events| libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let mut ev = libc::POLLIN;
        if !self.dev.tx.is_empty() && !self.tx_blocked {
            ev |= libc::POLLOUT;
        }
        let mut fds = vec![pfd(self.vm, ev)];
        let mut who = vec![Who::Vm];
        for (k, p) in &self.pending {
            fds.push(pfd(p.sock.as_raw_fd(), libc::POLLOUT));
            who.push(Who::Pending(*k));
        }
        for (k, c) in &self.conns {
            let s = self.sockets.get::<tcp::Socket>(c.handle);
            let mut ev = 0;
            if !c.host_eof && s.may_send() && s.send_queue() < s.send_capacity() {
                ev |= libc::POLLIN;
            }
            if !c.to_host.is_empty() {
                ev |= libc::POLLOUT;
            }
            // a socket polled for nothing still reports hangups, and would spin
            if ev != 0 {
                fds.push(pfd(c.host.as_raw_fd(), ev));
                who.push(Who::Conn(*k));
            }
        }
        for d in &self.dns {
            fds.push(pfd(d.host.as_raw_fd(), libc::POLLIN));
            who.push(Who::Dns);
        }
        (fds, who)
    }

    fn timeout(&mut self) -> libc::c_int {
        if !self.dev.rx.is_empty() {
            return 0;
        }
        let now = StdInstant::now();
        let mut ms = self
            .iface
            .poll_delay(Instant::now(), &self.sockets)
            .map_or(1000, |d| d.total_millis())
            .min(1000);
        if self.tx_blocked {
            ms = ms.min(1);
        }
        for p in self.pending.values() {
            ms = ms.min(p.deadline.saturating_duration_since(now).as_millis() as u64);
        }
        ms as libc::c_int
    }

    /// false when the VM's end is gone
    fn read_vm(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        for _ in 0..RX_BATCH {
            let n = unsafe { libc::recv(self.vm, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n > 0 {
                self.ingress(&buf[..n as usize]);
                continue;
            }
            // libkrun never sends an empty frame, so 0 is the peer closing
            if n == 0 {
                return Ok(false);
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EAGAIN) => break,
                Some(libc::EINTR) => continue,
                Some(libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE) => return Ok(false),
                _ => return Err(e),
            }
        }
        Ok(true)
    }

    /// false when the VM's end is gone
    fn flush(&mut self) -> io::Result<bool> {
        while let Some(f) = self.dev.tx.front() {
            let r = unsafe { libc::send(self.vm, f.as_ptr() as *const _, f.len(), 0) };
            if r >= 0 {
                self.dev.tx.pop_front();
                continue;
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                // the VM's receive buffer is full: retry shortly, poll can't say when
                Some(libc::EAGAIN | libc::ENOBUFS) => {
                    self.tx_blocked = true;
                    return Ok(true);
                }
                Some(libc::EINTR) => continue,
                Some(libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE | libc::ECONNREFUSED) => {
                    return Ok(false);
                }
                _ => return Err(e),
            }
        }
        self.tx_blocked = false;
        Ok(true)
    }

    fn ingress(&mut self, frame: &[u8]) {
        match self.classify(frame) {
            Verdict::Pass => self.dev.rx.push_back(frame.to_vec()),
            Verdict::Drop => {}
            Verdict::Syn(key) => self.syn(key, frame),
        }
    }

    /// what reaches smoltcp at all: arp, tcp of connections already let through,
    /// new syns (which go through the policy first) and udp to port 53. ipv6,
    /// fragments, icmp, other udp and anything not from the guest's own address
    /// are dropped here
    fn classify(&self, frame: &[u8]) -> Verdict {
        let Ok(eth) = EthernetFrame::new_checked(frame) else {
            return Verdict::Drop;
        };
        match eth.ethertype() {
            EthernetProtocol::Arp => return Verdict::Pass,
            EthernetProtocol::Ipv4 => {}
            _ => return Verdict::Drop,
        }
        let Ok(ip) = Ipv4Packet::new_checked(eth.payload()) else {
            return Verdict::Drop;
        };
        if ip.src_addr() != self.args.guest || ip.more_frags() || ip.frag_offset() != 0 {
            return Verdict::Drop;
        }
        match ip.next_header() {
            IpProtocol::Tcp => {
                let Ok(t) = TcpPacket::new_checked(ip.payload()) else {
                    return Verdict::Drop;
                };
                let key = (t.src_port(), ip.dst_addr(), t.dst_port());
                if self.conns.contains_key(&key) {
                    Verdict::Pass
                } else if t.syn() && !t.ack() && !t.rst() && !t.fin() {
                    Verdict::Syn(key)
                } else {
                    Verdict::Drop
                }
            }
            IpProtocol::Udp => match UdpPacket::new_checked(ip.payload()) {
                Ok(u) if u.dst_port() == 53 => Verdict::Pass,
                _ => Verdict::Drop,
            },
            _ => Verdict::Drop,
        }
    }

    fn syn(&mut self, key: Key, frame: &[u8]) {
        // a retransmit while the host connection is still being made
        if self.pending.contains_key(&key) {
            return;
        }
        let (_, dst, port) = key;
        if let Err(why) = self.pol.tcp(dst, port) {
            self.log(format_args!("tcp {dst}:{port} refused: {why}"));
            return;
        }
        if self.conns.len() + self.pending.len() >= MAX_FLOWS {
            self.log(format_args!(
                "tcp {dst}:{port} refused: too many connections"
            ));
            return;
        }
        if !self.new_conns.take() {
            self.log(format_args!("tcp {dst}:{port} refused: rate limit"));
            return;
        }
        match connect(dst, port) {
            Ok(sock) => {
                self.log(format_args!("tcp {dst}:{port} connecting"));
                self.pending.insert(
                    key,
                    Pending {
                        sock,
                        syn: frame.to_vec(),
                        deadline: StdInstant::now() + CONNECT_TIMEOUT,
                        ready: false,
                    },
                );
            }
            Err(e) => {
                self.log(format_args!("tcp {dst}:{port} failed: {e}"));
                self.reset(frame.to_vec());
            }
        }
    }

    /// no socket takes the syn, so smoltcp answers it with a reset
    fn reset(&mut self, syn: Vec<u8>) {
        self.dev.rx.push_back(syn);
        self.poll();
    }

    fn resolve_pending(&mut self) {
        let now = StdInstant::now();
        let keys: Vec<Key> = self
            .pending
            .iter()
            .filter(|(_, p)| p.ready || now >= p.deadline)
            .map(|(k, _)| *k)
            .collect();
        for key in keys {
            let p = self.pending.get_mut(&key).unwrap();
            p.ready = false;
            let (_, dst, port) = key;
            let res = match connected(&p.sock) {
                None if now < p.deadline => continue,
                None => Err(io::Error::from(ErrorKind::TimedOut)),
                Some(r) => r,
            };
            let p = self.pending.remove(&key).unwrap();
            match res {
                Ok(()) => self.accept(key, p),
                Err(e) => {
                    self.log(format_args!("tcp {dst}:{port} failed: {e}"));
                    self.reset(p.syn);
                }
            }
        }
    }

    /// the host side is up: give smoltcp a listener for exactly this
    /// destination and replay the guest's syn into it
    fn accept(&mut self, key: Key, p: Pending) {
        let (gport, dst, port) = key;
        let host: TcpStream = p.sock.into();
        let _ = host.set_nodelay(true);
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0; TCP_BUF]),
        );
        s.set_nagle_enabled(false);
        s.set_timeout(Some(GUEST_TIMEOUT));
        let ep = IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(dst)),
            port,
        };
        if s.listen(ep).is_err() {
            return;
        }
        let h = self.sockets.add(s);
        self.dev.rx.push_back(p.syn);
        self.poll();
        // the listener must have taken this guest's syn and no other
        let s = self.sockets.get_mut::<tcp::Socket>(h);
        let want = IpEndpoint::new(IpAddress::Ipv4(self.args.guest), gport);
        if s.remote_endpoint() != Some(want) {
            s.abort();
            self.poll();
            self.sockets.remove(h);
            self.log(format_args!("tcp {dst}:{port} dropped: syn not taken"));
            return;
        }
        self.log(format_args!("tcp {dst}:{port} open"));
        self.conns.insert(
            key,
            Conn {
                handle: h,
                host,
                to_host: Vec::new(),
                host_eof: false,
                shut: false,
                readable: false,
            },
        );
    }

    fn pump(&mut self) {
        for c in self.conns.values_mut() {
            let s = self.sockets.get_mut::<tcp::Socket>(c.handle);
            pump(c, s);
        }
    }

    /// forget connections smoltcp has finished with. runs after a poll, so a
    /// reset or fin queued by the pump has gone out
    fn reap(&mut self) {
        let Gw {
            conns,
            sockets,
            args,
            ..
        } = self;
        conns.retain(|k, c| {
            let s = sockets.get::<tcp::Socket>(c.handle);
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                if args.verbose {
                    eprintln!("burner-macnet: tcp {}:{} closed", k.1, k.2);
                }
                sockets.remove(c.handle);
                false
            } else {
                true
            }
        });
        let now = StdInstant::now();
        self.dns.retain(|d| now.duration_since(d.last) < DNS_IDLE);
    }

    /// guest dns queries out to the resolvers
    fn dns_out(&mut self) {
        loop {
            let s = self.sockets.get_mut::<udp::Socket>(self.udp53);
            let Ok((data, meta)) = s.recv() else { break };
            let data = data.to_vec();
            let Some(IpAddress::Ipv4(dst)) = meta.local_address else {
                continue;
            };
            let gport = meta.endpoint.port;
            if let Err(why) = self.pol.dns(dst) {
                self.log(format_args!("dns {dst} refused: {why}"));
                continue;
            }
            if !self.dns_rate.take() {
                self.log(format_args!("dns {dst} refused: rate limit"));
                continue;
            }
            let now = StdInstant::now();
            let i = match self
                .dns
                .iter()
                .position(|d| d.guest_port == gport && d.resolver == dst)
            {
                Some(i) => i,
                None => {
                    if self.dns.len() >= MAX_DNS
                        && let Some(old) = (0..self.dns.len()).min_by_key(|&i| self.dns[i].last)
                    {
                        self.dns.swap_remove(old);
                    }
                    match dns_socket(dst) {
                        Ok(host) => {
                            self.dns.push(Dns {
                                host,
                                guest_port: gport,
                                resolver: dst,
                                last: now,
                            });
                            self.dns.len() - 1
                        }
                        Err(e) => {
                            self.log(format_args!("dns {dst} failed: {e}"));
                            continue;
                        }
                    }
                }
            };
            let d = &mut self.dns[i];
            d.last = now;
            let _ = d.host.send(&data);
            self.log(format_args!("dns {dst} query"));
        }
    }

    /// resolver answers back to the guest, from the resolver's address
    fn dns_in(&mut self) {
        let mut buf = [0u8; 4096];
        let s = self.sockets.get_mut::<udp::Socket>(self.udp53);
        let now = StdInstant::now();
        for d in &mut self.dns {
            while let Ok(n) = d.host.recv(&mut buf) {
                d.last = now;
                let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                    IpAddress::Ipv4(self.args.guest),
                    d.guest_port,
                ));
                meta.local_address = Some(IpAddress::Ipv4(d.resolver));
                let _ = s.send_slice(&buf[..n], meta);
            }
        }
    }
}

fn guest_closed(st: tcp::State) -> bool {
    use tcp::State::*;
    matches!(st, CloseWait | LastAck | Closing | TimeWait | Closed)
}

fn pump(c: &mut Conn, s: &mut tcp::Socket) {
    // guest to host. at most one chunk held here, the rest waits in smoltcp,
    // which shrinks the guest's window
    loop {
        if c.to_host.is_empty() {
            let _ = s.recv(|b| {
                c.to_host.extend_from_slice(b);
                (b.len(), ())
            });
        }
        if c.to_host.is_empty() {
            break;
        }
        match c.host.write(&c.to_host) {
            Ok(n) if n > 0 => {
                c.to_host.drain(..n);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            _ => {
                s.abort();
                return;
            }
        }
    }
    if !c.shut && c.to_host.is_empty() && !s.can_recv() && guest_closed(s.state()) {
        let _ = c.host.shutdown(Shutdown::Write);
        c.shut = true;
    }
    // host to guest, only as much as smoltcp has room for
    let readable = std::mem::take(&mut c.readable);
    while readable && !c.host_eof && s.may_send() && s.send_queue() < s.send_capacity() {
        let r = s.send(|b| {
            if b.is_empty() {
                return (0, Err(ErrorKind::WouldBlock.into()));
            }
            match c.host.read(b) {
                Ok(n) => (n, Ok(n)),
                Err(e) => (0, Err(e)),
            }
        });
        match r {
            Ok(Ok(0)) => {
                c.host_eof = true;
                s.close();
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => {}
            _ => {
                s.abort();
                break;
            }
        }
    }
}

fn connect(dst: Ipv4Addr, port: u16) -> io::Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    s.set_nonblocking(true)?;
    #[cfg(target_os = "macos")]
    setopt(s.as_raw_fd(), libc::SO_NOSIGPIPE, 1)?;
    match s.connect(&SocketAddrV4::new(dst, port).into()) {
        Ok(()) => Ok(s),
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => Ok(s),
        Err(e) => Err(e),
    }
}

/// None while the connect is still in flight
fn connected(s: &Socket) -> Option<io::Result<()>> {
    match s.take_error() {
        Ok(Some(e)) | Err(e) => return Some(Err(e)),
        Ok(None) => {}
    }
    match s.peer_addr() {
        Ok(_) => Some(Ok(())),
        Err(e) if e.kind() == ErrorKind::NotConnected => None,
        Err(e) => Some(Err(e)),
    }
}

fn dns_socket(dst: Ipv4Addr) -> io::Result<UdpSocket> {
    let u = UdpSocket::bind("0.0.0.0:0")?;
    u.connect(SocketAddrV4::new(dst, 53))?;
    u.set_nonblocking(true)?;
    Ok(u)
}

fn setopt(fd: RawFd, opt: libc::c_int, val: libc::c_int) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &val as *const _ as *const _,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn seed() -> u64 {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        return t.as_nanos() as u64 ^ std::process::id() as u64;
    }
    u64::from_ne_bytes(b)
}
