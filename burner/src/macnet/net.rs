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

use super::policy::{Mode, Policy};
use super::{Link, SOCK_RCVBUF, SOCK_SNDBUF, setopt};
use crate::netlog::{DnsInfo, Line, Outcome};
use crate::netmodel::{Proto, Reason};

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
/// replies to what the guest sent may run past TX_QUEUE by one read's worth
/// and no further: past TX_QUEUE nothing more is read from the VM, and past
/// this smoltcp gets no more of what was
const TX_HARD: usize = TX_QUEUE + RX_BATCH;

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
        if self.tx.len() >= TX_HARD {
            return None;
        }
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
    /// payload bytes guest to host and back, for the log
    up: u64,
    down: u64,
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
    /// the interface host is bound to
    index: u16,
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

    fn refill(&mut self) {
        let now = StdInstant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
    }

    fn take(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// never less than a segment at a time, unless the rate itself is lower
const RATE_CHUNK: f64 = 1460.0;

/// net.rate, bytes a second one way, like firecracker's limiter on linux: the
/// bucket holds a second's worth, so a short burst goes at full speed. counts
/// tcp payload, not headers or dns. None is no limit
struct Rate(Option<Bucket>);

impl Rate {
    fn new(bytes: u64) -> Rate {
        Rate((bytes > 0).then(|| Bucket::new(bytes as f64, bytes as f64)))
    }

    fn chunk(b: &Bucket) -> f64 {
        RATE_CHUNK.min(b.burst)
    }

    /// bytes that may go now: nothing until a chunk's worth has built up
    fn allow(&mut self) -> usize {
        let Some(b) = &mut self.0 else {
            return usize::MAX;
        };
        b.refill();
        if b.tokens < Self::chunk(b) {
            0
        } else {
            b.tokens as usize
        }
    }

    fn spend(&mut self, n: usize) {
        if let Some(b) = &mut self.0 {
            b.tokens -= n as f64;
        }
    }

    /// ms until allow gives something again, None while it does
    fn wait(&self) -> Option<u64> {
        let b = self.0.as_ref()?;
        let have = b.tokens + b.last.elapsed().as_secs_f64() * b.rate;
        let need = Self::chunk(b) - have;
        (need > 0.0).then(|| (need / b.rate * 1000.0).ceil() as u64)
    }
}

/// the connection log's end of things: one JSON line per decision, written
/// without ever blocking the loop. what doesn't fit is dropped and counted,
/// and the count goes out with the next line that fits
struct Events {
    fd: Option<RawFd>,
    out: Vec<u8>,
    lost: u64,
    /// blocked attempts decided, and those past the itemization bucket
    blocked: u64,
    not_itemized: u64,
    bucket: Bucket,
}

/// what's held back for a slow reader before lines are dropped
const EVENTS_HELD: usize = 256 << 10;

impl Events {
    fn new(fd: Option<RawFd>) -> Events {
        let fd = fd.filter(|&fd| {
            // SAFETY: fcntl on an fd we were handed
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                fl >= 0 && libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) >= 0
            }
        });
        Events {
            fd,
            out: Vec::new(),
            lost: 0,
            blocked: 0,
            not_itemized: 0,
            // the linux try chain's limit: 100 a second, burst 500
            bucket: Bucket::new(100.0, 500.0),
        }
    }

    fn send(&mut self, l: &Line) {
        if self.fd.is_none() {
            return;
        }
        let Ok(mut s) = serde_json::to_string(l) else {
            return;
        };
        s.push('\n');
        if self.lost > 0 {
            let lost = format!("{{\"k\":\"lost\",\"n\":{}}}\n", self.lost);
            if self.out.len() + lost.len() + s.len() <= EVENTS_HELD {
                self.out.extend_from_slice(lost.as_bytes());
                self.lost = 0;
            }
        }
        if self.out.len() + s.len() > EVENTS_HELD || self.lost > 0 {
            self.lost += 1;
            return;
        }
        self.out.extend_from_slice(s.as_bytes());
        self.flush();
    }

    /// a refusal: always counted, itemized while the bucket lasts
    fn blocked(&mut self, l: Line) {
        self.blocked += 1;
        if self.bucket.take() {
            self.send(&l);
        } else {
            self.not_itemized += 1;
        }
    }

    fn flush(&mut self) {
        let Some(fd) = self.fd else { return };
        while !self.out.is_empty() {
            // SAFETY: write from a buffer we own
            let n = unsafe { libc::write(fd, self.out.as_ptr().cast(), self.out.len()) };
            if n > 0 {
                self.out.drain(..n as usize);
                continue;
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => return,
                // the reader is gone: nobody to tell
                _ => {
                    self.fd = None;
                    self.out.clear();
                    return;
                }
            }
        }
    }

    /// the last line, with the exact counts: a short wait for room, then gone
    fn finish(&mut self) {
        let counts = Line::Counts {
            blocked: self.blocked,
            not_itemized: self.not_itemized,
        };
        self.send(&counts);
        let end = StdInstant::now() + StdDuration::from_millis(500);
        while let Some(fd) = self.fd
            && !self.out.is_empty()
            && StdInstant::now() < end
        {
            let mut p = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll on one pollfd we own
            unsafe { libc::poll(&mut p, 1, 50) };
            self.flush();
        }
    }
}

fn outcome_of(e: &io::Error) -> Outcome {
    match e.kind() {
        ErrorKind::TimedOut => Outcome::Timeout,
        ErrorKind::ConnectionRefused => Outcome::Refused,
        _ => Outcome::NoAnswer,
    }
}

enum Verdict {
    Pass,
    Arp,
    Drop,
    /// dropped, and worth a line in the log: icmp or udp that isn't dns
    Refuse(Proto, Ipv4Addr, u16, u16),
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
    args: &'a Link,
    pol: Policy,
    vm: RawFd,
    iface: Interface,
    dev: Dev,
    sockets: SocketSet<'static>,
    udp53: SocketHandle,
    conns: HashMap<Key, Conn>,
    pending: HashMap<Key, Pending>,
    dns: Vec<Dns>,
    // the linux table's meters: new connections at 20 a second, burst 40 in
    // web mode and 50, burst 100 in open mode, and 20 dns packets a second, burst 50
    new_conns: Bucket,
    dns_rate: Bucket,
    // the guest only needs the gateway's address, now and then
    arp_rate: Bucket,
    // guest to host and host to guest
    up: Rate,
    down: Rate,
    tx_blocked: bool,
    events: Events,
}

pub fn run(args: &Link, pol: Policy) -> io::Result<()> {
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
    // which of them get a real connection behind them. smoltcp 0.12 only takes
    // a packet for an address that isn't its own when a route to it points at one
    // that is, hence the default route through ourselves
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(args.gateway)
        .map_err(|_| io::Error::other("smoltcp's route table is full"))?;
    let mut sockets = SocketSet::new(Vec::new());
    let udp_buf =
        || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; 64 << 10]);
    let mut u = udp::Socket::new(udp_buf(), udp_buf());
    u.bind(53).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let udp53 = sockets.add(u);

    let new_conns = match pol.mode {
        Mode::Web => Bucket::new(20.0, 40.0),
        Mode::Open => Bucket::new(50.0, 100.0),
    };
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
        new_conns,
        dns_rate: Bucket::new(20.0, 50.0),
        arp_rate: Bucket::new(20.0, 50.0),
        up: Rate::new(args.rate),
        down: Rate::new(args.rate),
        tx_blocked: false,
        events: Events::new(args.events),
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
            gw.events.finish();
            return Ok(());
        }
        gw.poll();
        gw.resolve_pending();
        gw.pump();
        gw.dns_out();
        gw.dns_in();
        gw.poll();
        gw.reap();
        gw.events.flush();
        if !gw.flush()? {
            gw.log(format_args!("the VM's end of the socket closed, exiting"));
            gw.events.finish();
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
            eprintln!("burner net: {msg}");
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
        // a guest that doesn't read what it gets is heard again once it does
        let mut ev = if self.dev.tx.len() < TX_QUEUE {
            libc::POLLIN
        } else {
            0
        };
        if !self.dev.tx.is_empty() && !self.tx_blocked {
            ev |= libc::POLLOUT;
        }
        let mut fds = vec![pfd(self.vm, ev)];
        let mut who = vec![Who::Vm];
        // past the rate, host sockets wait for the timer instead
        let down = self.down.wait().is_none();
        for (k, p) in &self.pending {
            fds.push(pfd(p.sock.as_raw_fd(), libc::POLLOUT));
            who.push(Who::Pending(*k));
        }
        for (k, c) in &self.conns {
            let s = self.sockets.get::<tcp::Socket>(c.handle);
            let mut ev = 0;
            if down && !c.host_eof && s.may_send() && s.send_queue() < s.send_capacity() {
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
        if !self.dev.rx.is_empty() && self.dev.tx.len() < TX_HARD {
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
        for w in [self.up.wait(), self.down.wait()].into_iter().flatten() {
            ms = ms.min(w.max(1));
        }
        ms as libc::c_int
    }

    /// false when the VM's end is gone
    fn read_vm(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        if self.dev.tx.len() >= TX_QUEUE {
            return Ok(true);
        }
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
            Verdict::Arp if self.arp_rate.take() => self.dev.rx.push_back(frame.to_vec()),
            Verdict::Arp | Verdict::Drop => {}
            Verdict::Refuse(proto, dst, sport, port) => self.events.blocked(Line::Conn {
                proto,
                sport,
                dst,
                port,
                verdict: crate::netmodel::Verdict::Blocked,
                reason: Some(Reason::Proto),
            }),
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
            EthernetProtocol::Arp => return Verdict::Arp,
            EthernetProtocol::Ipv4 => {}
            _ => return Verdict::Drop,
        }
        let Ok(ip) = Ipv4Packet::new_checked(eth.payload()) else {
            return Verdict::Drop;
        };
        // smoltcp 0.12 doesn't refuse a header length under 20 itself
        if ip.header_len() < 20
            || ip.src_addr() != self.args.guest
            || ip.more_frags()
            || ip.frag_offset() != 0
        {
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
                Ok(u) => Verdict::Refuse(Proto::Udp, ip.dst_addr(), u.src_port(), u.dst_port()),
                _ => Verdict::Drop,
            },
            // ping included: macnet carries tcp and dns only
            IpProtocol::Icmp => Verdict::Refuse(Proto::Icmp, ip.dst_addr(), 0, 0),
            _ => Verdict::Drop,
        }
    }

    fn syn(&mut self, key: Key, frame: &[u8]) {
        // a retransmit while the host connection is still being made
        if self.pending.contains_key(&key) {
            return;
        }
        let (sport, dst, port) = key;
        let conn = |verdict, reason| Line::Conn {
            proto: Proto::Tcp,
            sport,
            dst,
            port,
            verdict,
            reason,
        };
        let index = match self.pol.tcp(dst, port) {
            Ok(i) => i,
            Err(why) => {
                self.log(format_args!("tcp {dst}:{port} refused: {}", why.as_str()));
                self.events
                    .blocked(conn(crate::netmodel::Verdict::Blocked, Some(why.reason())));
                return;
            }
        };
        if self.conns.len() + self.pending.len() >= MAX_FLOWS {
            self.log(format_args!(
                "tcp {dst}:{port} refused: too many connections"
            ));
            self.events
                .blocked(conn(crate::netmodel::Verdict::Blocked, Some(Reason::Flows)));
            return;
        }
        if !self.new_conns.take() {
            self.log(format_args!("tcp {dst}:{port} refused: rate limit"));
            self.events
                .blocked(conn(crate::netmodel::Verdict::Blocked, Some(Reason::Rate)));
            return;
        }
        self.events
            .send(&conn(crate::netmodel::Verdict::Allowed, None));
        match connect(dst, port, index) {
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
                self.events.send(&Line::Outcome {
                    sport,
                    dst,
                    port,
                    outcome: outcome_of(&e),
                });
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
            let outcome = match &res {
                Ok(()) => Outcome::Answered,
                Err(e) => outcome_of(e),
            };
            self.events.send(&Line::Outcome {
                sport: key.0,
                dst,
                port,
                outcome,
            });
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
                up: 0,
                down: 0,
            },
        );
    }

    fn pump(&mut self) {
        let Gw {
            conns,
            sockets,
            up,
            down,
            ..
        } = self;
        for c in conns.values_mut() {
            let s = sockets.get_mut::<tcp::Socket>(c.handle);
            pump(c, s, up, down);
        }
    }

    /// forget connections smoltcp has finished with. runs after a poll, so a
    /// reset or fin queued by the pump has gone out
    fn reap(&mut self) {
        let Gw {
            conns,
            sockets,
            args,
            events,
            ..
        } = self;
        conns.retain(|k, c| {
            let s = sockets.get::<tcp::Socket>(c.handle);
            if matches!(s.state(), tcp::State::Closed | tcp::State::TimeWait) {
                if args.verbose {
                    eprintln!("burner net: tcp {}:{} closed", k.1, k.2);
                }
                events.send(&Line::Bytes {
                    sport: k.0,
                    dst: k.1,
                    port: k.2,
                    up: c.up,
                    down: c.down,
                });
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
            let ev = |verdict, reason| Line::Dns {
                dst,
                sport: gport,
                verdict,
                reason,
                dns: DnsInfo::query(&data, 0),
            };
            let index = match self.pol.dns(dst) {
                Ok(i) => i,
                Err(why) => {
                    self.log(format_args!("dns {dst} refused: {}", why.as_str()));
                    self.events
                        .blocked(ev(crate::netmodel::Verdict::Blocked, Some(why.reason())));
                    continue;
                }
            };
            if !self.dns_rate.take() {
                self.log(format_args!("dns {dst} refused: rate limit"));
                self.events
                    .blocked(ev(crate::netmodel::Verdict::Blocked, Some(Reason::Rate)));
                continue;
            }
            self.events
                .send(&ev(crate::netmodel::Verdict::Allowed, None));
            let now = StdInstant::now();
            let mut found = self
                .dns
                .iter()
                .position(|d| d.guest_port == gport && d.resolver == dst);
            // the default route moved: this query goes out the new way
            if let Some(i) = found
                && self.dns[i].index != index
            {
                self.dns.swap_remove(i);
                found = None;
            }
            let i = match found {
                Some(i) => i,
                None => {
                    if self.dns.len() >= MAX_DNS
                        && let Some(old) = (0..self.dns.len()).min_by_key(|&i| self.dns[i].last)
                    {
                        self.dns.swap_remove(old);
                    }
                    match dns_socket(dst, index) {
                        Ok(host) => {
                            self.dns.push(Dns {
                                host,
                                guest_port: gport,
                                resolver: dst,
                                index,
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
                self.events.send(&Line::Answer {
                    dst: d.resolver,
                    sport: d.guest_port,
                    dns: DnsInfo::response(&buf[..n]),
                });
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

fn pump(c: &mut Conn, s: &mut tcp::Socket, up: &mut Rate, down: &mut Rate) {
    // guest to host. at most one chunk held here, the rest waits in smoltcp,
    // which shrinks the guest's window
    loop {
        if c.to_host.is_empty() {
            let lim = up.allow();
            let n = s
                .recv(|b| {
                    let n = b.len().min(lim);
                    c.to_host.extend_from_slice(&b[..n]);
                    (n, n)
                })
                .unwrap_or(0);
            up.spend(n);
            c.up += n as u64;
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
    // host to guest, only as much as smoltcp has room for and the rate allows
    let readable = std::mem::take(&mut c.readable);
    while readable && !c.host_eof && s.may_send() && s.send_queue() < s.send_capacity() {
        let lim = down.allow();
        if lim == 0 {
            // still readable: the timer brings it back
            c.readable = true;
            break;
        }
        let r = s.send(|b| {
            if b.is_empty() {
                return (0, Err(ErrorKind::WouldBlock.into()));
            }
            let n = b.len().min(lim);
            match c.host.read(&mut b[..n]) {
                Ok(n) => (n, Ok(n)),
                Err(e) => (0, Err(e)),
            }
        });
        match r {
            Ok(Ok(0)) => {
                c.host_eof = true;
                s.close();
            }
            Ok(Ok(n)) => {
                down.spend(n);
                c.down += n as u64;
            }
            Ok(Err(e)) if e.kind() == ErrorKind::WouldBlock => break,
            Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => {}
            _ => {
                s.abort();
                break;
            }
        }
    }
}

/// out the interface the policy checked, whatever the routes say by the time
/// the syn leaves
fn bind_to(s: &Socket, index: u16) -> io::Result<()> {
    if index == 0 {
        return Err(io::Error::other("no interface to bind to"));
    }
    let i = libc::c_int::from(index);
    // SAFETY: setsockopt reads one int from a live local
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_BOUND_IF,
            (&i as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect(dst: Ipv4Addr, port: u16, index: u16) -> io::Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    s.set_nonblocking(true)?;
    setopt(s.as_raw_fd(), libc::SO_NOSIGPIPE, 1)?;
    bind_to(&s, index)?;
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

/// connected without a bind first: the sandbox allows no binds, and connect
/// picks the local port anyway
pub fn dns_socket(dst: Ipv4Addr, index: u16) -> io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    bind_to(&s, index)?;
    s.connect(&SocketAddrV4::new(dst, 53).into())?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// getentropy, not /dev/urandom: the sandbox has no files
fn seed() -> u64 {
    let mut b = [0u8; 8];
    // SAFETY: getentropy fills at most 256 bytes of a buffer we own
    if unsafe { libc::getentropy(b.as_mut_ptr().cast(), b.len()) } != 0 {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        return t.as_nanos() as u64 ^ std::process::id() as u64;
    }
    u64::from_ne_bytes(b)
}
