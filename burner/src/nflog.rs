//! linux: the connection log's reader. burner run (root) binds the slot's
//! nflog group and hands the socket to `burner __read-netlog`, which runs as
//! burner-parse under hard limits and turns each message into one JSON line
//! (netlog::Line). the packets in those messages are the guest's, so this is
//! the one place on linux where they're parsed: bounded, never panicking,
//! writing nothing it didn't build itself

use std::net::Ipv4Addr;

use crate::netlog::{DnsInfo, Line};

const NLMSG_HDR: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_PACKET_HDR: u16 = 1;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_SEQ: u16 = 12;

fn u16_ne(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_ne(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// the netlink messages in one read, each turned into a line, or skipped
/// when it isn't a packet message that parses. never more lines than messages
pub fn parse_batch(mut b: &[u8], out: &mut Vec<Line>) {
    while b.len() >= NLMSG_HDR {
        let Some(len) = u32_ne(b, 0).map(|l| l as usize) else {
            return;
        };
        if len < NLMSG_HDR || len > b.len() {
            return;
        }
        let ty = u16_ne(b, 4).unwrap_or(0);
        if ty == (NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET)
            && let Some(l) = parse_packet(&b[NLMSG_HDR..len])
        {
            out.push(l);
        }
        // netlink pads each message to 4 bytes
        let step = (len + 3) & !3;
        b = b.get(step..).unwrap_or(&[]);
    }
}

/// nfgenmsg, then attributes
fn parse_packet(b: &[u8]) -> Option<Line> {
    let mut a = b.get(4..)?;
    let (mut prefix, mut hook, mut payload, mut seq) = (None, None, None, None);
    while a.len() >= 4 {
        let len = u16_ne(a, 0)? as usize;
        let ty = u16_ne(a, 2)? & 0x3fff;
        if len < 4 || len > a.len() {
            return None;
        }
        let v = &a[4..len];
        match ty {
            NFULA_PACKET_HDR => hook = v.get(2).copied(),
            NFULA_PAYLOAD => payload = Some(v),
            NFULA_PREFIX => {
                prefix = Some(v.split(|&c| c == 0).next().unwrap_or(&[]));
            }
            NFULA_SEQ => seq = Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?)),
            _ => {}
        }
        a = a.get((len + 3) & !3..).unwrap_or(&[]);
    }
    let p = match prefix? {
        b"t" => "t",
        b"o" => "o",
        b"q" => "q",
        b"a" => "a",
        b"r" => "r",
        _ => return None,
    };
    packet_line(p, hook?, payload?, seq)
}

/// the ip header and what follows it, as far as the snaplen let it come
pub fn packet_line(p: &str, hook: u8, ip: &[u8], seq: Option<u32>) -> Option<Line> {
    let first = *ip.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0xf) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let total = usize::from(be16(ip, 2)?).clamp(ihl, ip.len().max(ihl));
    let l4 = ip.get(ihl..total.max(ihl))?;
    let (mut sport, mut dport, mut flags, mut dns) = (0, 0, 0, None);
    match proto {
        6 => {
            sport = be16(l4, 0)?;
            dport = be16(l4, 2)?;
            flags = *l4.get(13)?;
        }
        17 => {
            sport = be16(l4, 0)?;
            dport = be16(l4, 2)?;
            let body = l4.get(8..).unwrap_or(&[]);
            dns = match p {
                "t" | "q" if dport == 53 => Some(DnsInfo::query(body, 0)),
                "r" if sport == 53 => Some(DnsInfo::response(body)),
                _ => None,
            };
        }
        1 => {
            flags = *l4.first()?;
            // an echo's id stands in for a port: the request's on the
            // guest's side, the reply's mirrored, so the two meet as one flow
            let id = be16(l4, 4).unwrap_or(0);
            match flags {
                8 => sport = id,
                0 => dport = id,
                _ => {}
            }
        }
        _ => {}
    }
    Some(Line::Pkt {
        p: p.into(),
        hook,
        proto,
        src,
        dst,
        sport,
        dport,
        flags,
        dns,
        seq,
    })
}

/// one config message for the nflog instance of group
fn config_msg(group: u16, seq: u32, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut m = vec![0u8; NLMSG_HDR];
    // nfgenmsg: family unspec, version 0, the group big endian
    m.extend_from_slice(&[0, 0]);
    m.extend_from_slice(&group.to_be_bytes());
    for (ty, v) in attrs {
        let len = 4 + v.len();
        m.extend_from_slice(&(len as u16).to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(v);
        while !m.len().is_multiple_of(4) {
            m.push(0);
        }
    }
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    m[4..6].copy_from_slice(&(NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_CONFIG).to_ne_bytes());
    // request, ack
    m[6..8].copy_from_slice(&(1u16 | 4).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    m
}

/// the messages that bind a group and set it up: bind, copy whole packets
/// (the rules' snaplen cuts them), flush every 10 ms, number each message
pub fn setup_msgs(group: u16) -> Vec<Vec<u8>> {
    const CMD: u16 = 1;
    const MODE: u16 = 2;
    const TIMEOUT: u16 = 4;
    const QTHRESH: u16 = 5;
    const FLAGS: u16 = 6;
    let mut mode = 0xffffu32.to_be_bytes().to_vec();
    // NFULNL_COPY_PACKET, pad
    mode.extend_from_slice(&[2, 0]);
    vec![
        config_msg(group, 1, &[(CMD, vec![1])]),
        config_msg(group, 2, &[(MODE, mode)]),
        config_msg(group, 3, &[(TIMEOUT, 1u32.to_be_bytes().to_vec())]),
        config_msg(group, 4, &[(QTHRESH, 32u32.to_be_bytes().to_vec())]),
        // NFULNL_CFG_F_SEQ
        config_msg(group, 5, &[(FLAGS, 1u16.to_be_bytes().to_vec())]),
    ]
}

/// the kernel's answer to a request: Ok for an ack, the errno otherwise
pub fn ack(b: &[u8], seq: u32) -> Option<Result<(), i32>> {
    let mut b = b;
    while b.len() >= NLMSG_HDR {
        let len = u32_ne(b, 0)? as usize;
        if len < NLMSG_HDR || len > b.len() {
            return None;
        }
        let ty = u16_ne(b, 4)?;
        if ty == NLMSG_ERROR && u32_ne(b, 8)? == seq {
            let err = i32::from_ne_bytes(b.get(NLMSG_HDR..NLMSG_HDR + 4)?.try_into().ok()?);
            return Some(if err == 0 { Ok(()) } else { Err(-err) });
        }
        if ty == NLMSG_DONE {
            return None;
        }
        b = b.get((len + 3) & !3..).unwrap_or(&[]);
    }
    None
}

#[cfg(target_os = "linux")]
pub use sock::{bind, child_main};

#[cfg(target_os = "linux")]
mod sock {
    use super::*;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::ExitCode;

    pub const READ_ARG: &str = "__read-netlog";

    /// root: a netlink socket bound to group, set up, with a big receive
    /// buffer. a group some other program holds (ulogd) is an error: no
    /// network without a log
    pub fn bind(group: u32) -> io::Result<OwnedFd> {
        let group =
            u16::try_from(group).map_err(|_| io::Error::other("nflog group out of range"))?;
        // SAFETY: a fresh socket, owned right away
        let fd = unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };
        let raw = fd.as_raw_fd();
        // SAFETY: zeroed is a valid sockaddr_nl, bind reads it
        unsafe {
            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;
            if libc::bind(
                raw,
                (&sa as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let size: libc::c_int = 4 << 20;
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&size as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as u32,
            );
            let tv = libc::timeval {
                tv_sec: 5,
                tv_usec: 0,
            };
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as u32,
            );
        }
        let mut buf = vec![0u8; 8192];
        for (i, m) in setup_msgs(group).iter().enumerate() {
            // SAFETY: send from and recv into buffers we own
            let n = unsafe { libc::send(raw, m.as_ptr().cast(), m.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = unsafe { libc::recv(raw, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            match ack(&buf[..n as usize], i as u32 + 1) {
                Some(Ok(())) => {}
                Some(Err(libc::EBUSY)) => {
                    return Err(io::Error::other(format!(
                        "nflog group {group} is taken by another program (ulogd?), burner needs it for the network log"
                    )));
                }
                Some(Err(e)) => return Err(io::Error::from_raw_os_error(e)),
                None => return Err(io::Error::other("no answer from nfnetlink_log")),
            }
        }
        // the reader blocks until messages come, forever
        // SAFETY: setsockopt reads a timeval from a live local
        unsafe {
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as u32,
            );
        }
        Ok(fd)
    }

    /// no ptrace, no signals to others, no new programs, files or sockets.
    /// a reader the guest found a bug in can then only stop, which stops
    /// its VM, and can't reach another run's parser under the same user
    fn deny_list() -> io::Result<()> {
        #[cfg(target_arch = "x86_64")]
        const ARCH: u32 = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        const ARCH: u32 = 0xc000_00b7;
        #[allow(unused_mut)]
        let mut deny: Vec<libc::c_long> = vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_open,
            libc::SYS_pidfd_send_signal,
            libc::SYS_pidfd_getfd,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_openat,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_sendmsg,
        ];
        #[cfg(target_arch = "x86_64")]
        deny.push(libc::SYS_open);
        let stmt = |code: u16, k: u32| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        let ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        let ret = (libc::BPF_RET | libc::BPF_K) as u16;
        let mut prog = vec![
            // seccomp_data.arch: another architecture's numbers mean nothing here
            stmt(ld, 4),
            jeq(ARCH, 1, 0),
            stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
            // seccomp_data.nr
            stmt(ld, 0),
        ];
        // x32 calls carry the same arch with a high bit set in the number
        #[cfg(target_arch = "x86_64")]
        {
            prog.push(libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: 0x4000_0000,
            });
            prog.push(stmt(ret, libc::SECCOMP_RET_KILL_PROCESS));
        }
        for &nr in &deny {
            prog.push(jeq(nr as u32, 0, 1));
            prog.push(stmt(ret, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32));
        }
        prog.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };
        // SAFETY: prctl with a filter that lives through the call
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &fprog as *const libc::sock_fprog,
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// child side: fd 0 is the bound socket, fd 1 a pipe to the run. refuses
    /// to run as root or on anything that isn't a netlink socket
    pub fn child_main() -> ExitCode {
        // SAFETY: geteuid has no preconditions
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("burner: {READ_ARG} is internal and never runs as root");
            return ExitCode::from(2);
        }
        let mut dom: libc::c_int = 0;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes one int into a live local
        let r = unsafe {
            libc::getsockopt(
                0,
                libc::SOL_SOCKET,
                libc::SO_DOMAIN,
                (&mut dom as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        if r != 0 || dom != libc::AF_NETLINK {
            eprintln!("burner: {READ_ARG} is internal, run by burner run");
            return ExitCode::from(2);
        }
        // exec made it dumpable again: no other burner-parse process may
        // attach to it or read its memory
        // SAFETY: prctl with plain integer arguments
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if deny_list().is_err() {
            return ExitCode::from(2);
        }
        let mut buf = vec![0u8; 256 << 10];
        let mut lines = Vec::new();
        let mut out = io::stdout().lock();
        loop {
            // SAFETY: recv into a buffer we own
            let n = unsafe { libc::recv(0, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                match io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    // the socket overflowed: the kernel dropped messages
                    Some(libc::ENOBUFS) => {
                        if writeln!(out, r#"{{"k":"lost","n":1}}"#).is_err() {
                            return ExitCode::SUCCESS;
                        }
                        continue;
                    }
                    _ => return ExitCode::from(1),
                }
            }
            if n == 0 {
                return ExitCode::SUCCESS;
            }
            lines.clear();
            parse_batch(&buf[..n as usize], &mut lines);
            for l in &lines {
                let Ok(s) = serde_json::to_string(l) else {
                    continue;
                };
                if writeln!(out, "{s}").is_err() {
                    return ExitCode::SUCCESS;
                }
            }
            if out.flush().is_err() {
                return ExitCode::SUCCESS;
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use sock::READ_ARG;

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
        let total = (20 + l4.len()) as u16;
        let mut v = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            1,
            0x40,
            0,
            64,
            proto,
            0,
            0,
        ];
        v.extend(src);
        v.extend(dst);
        v.extend(l4);
        v
    }

    fn nfmsg(prefix: &str, hook: u8, payload: &[u8], seq: u32) -> Vec<u8> {
        let mut attrs: Vec<(u16, Vec<u8>)> = vec![
            (NFULA_PACKET_HDR, vec![0x08, 0x00, hook, 0]),
            (NFULA_PREFIX, format!("{prefix}\0").into_bytes()),
            (NFULA_SEQ, seq.to_be_bytes().to_vec()),
        ];
        attrs.push((NFULA_PAYLOAD, payload.to_vec()));
        let mut m = config_msg(29217, 0, &attrs);
        m[4..6].copy_from_slice(&(NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_PACKET).to_ne_bytes());
        m
    }

    const G: [u8; 4] = [172, 29, 217, 2];

    #[test]
    fn messages_to_lines() {
        let syn = [
            0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ];
        let q = crate::dns::tests::query(0x77, "github.com", 1);
        let mut udp = vec![0x10, 0x00, 0x00, 53, 0, (8 + q.len()) as u8, 0, 0];
        udp.extend(&q);
        let mut batch = nfmsg("t", 2, &ipv4(6, G, [140, 82, 112, 3], &syn), 1);
        batch.extend(nfmsg("q", 2, &ipv4(17, G, [9, 9, 9, 9], &udp), 2));
        // echo request, id 0x1234
        batch.extend(nfmsg(
            "t",
            1,
            &ipv4(1, G, [172, 29, 217, 1], &[8, 0, 0, 0, 0x12, 0x34, 0, 1]),
            3,
        ));
        // garbage between: a message with an unknown prefix, a short one
        batch.extend(nfmsg("z", 2, &ipv4(6, G, [1, 1, 1, 1], &syn), 4));
        let mut out = Vec::new();
        parse_batch(&batch, &mut out);
        assert_eq!(out.len(), 3);
        match &out[0] {
            Line::Pkt {
                p,
                hook,
                proto,
                dst,
                sport,
                dport,
                flags,
                seq,
                ..
            } => {
                assert_eq!((p.as_str(), *hook, *proto), ("t", 2, 6));
                assert_eq!(
                    (*dst, *sport, *dport, *flags, *seq),
                    (Ipv4Addr::new(140, 82, 112, 3), 40000, 443, 2, Some(1))
                );
            }
            l => panic!("{l:?}"),
        }
        match &out[1] {
            Line::Pkt {
                p,
                dns: Some(d),
                dport,
                ..
            } => {
                assert_eq!((p.as_str(), *dport), ("q", 53));
                assert_eq!(d.name.as_deref(), Some("github.com"));
                assert_eq!(d.id, 0x77);
            }
            l => panic!("{l:?}"),
        }
        match &out[2] {
            Line::Pkt {
                hook, proto, sport, ..
            } => assert_eq!((*hook, *proto, *sport), (1, 1, 0x1234)),
            l => panic!("{l:?}"),
        }
        // every line is one the parent accepts
        for l in &out {
            let s = serde_json::to_string(l).unwrap();
            assert!(crate::netlog::accept_line(&s).is_some(), "{s}");
        }
    }

    #[test]
    fn cut_and_broken_messages() {
        let syn = [
            0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff,
        ];
        let m = nfmsg("t", 2, &ipv4(6, G, [1, 1, 1, 1], &syn), 9);
        for n in 0..m.len() {
            let mut out = Vec::new();
            parse_batch(&m[..n], &mut out);
            assert!(out.is_empty(), "{n}");
        }
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..5000 {
            let mut b = m.clone();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = x as usize % b.len();
                b[i] = (x >> 32) as u8;
            }
            let mut out = Vec::new();
            parse_batch(&b, &mut out);
            assert!(out.len() <= 1);
        }
        // not ipv4
        assert!(packet_line("t", 2, &[0x60; 40], None).is_none());
        assert!(
            packet_line("t", 2, &[0x41; 40], None).is_none(),
            "ihl under 5"
        );
    }

    #[test]
    fn acks() {
        let mut m = vec![0u8; 36];
        m[0..4].copy_from_slice(&36u32.to_ne_bytes());
        m[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        m[8..12].copy_from_slice(&3u32.to_ne_bytes());
        assert_eq!(ack(&m, 3), Some(Ok(())));
        m[16..20].copy_from_slice(&(-16i32).to_ne_bytes());
        assert_eq!(ack(&m, 3), Some(Err(16)));
        assert_eq!(ack(&m, 4), None);
        let s = setup_msgs(29220);
        assert_eq!(s.len(), 5);
        assert_eq!(&s[0][18..20], &29220u16.to_be_bytes());
        assert!(s.iter().all(|m| m.len().is_multiple_of(4)));
    }
}
