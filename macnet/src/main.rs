//! burner-macnet: the network for one burner VM on macos. libkrun hands the
//! guest's virtio-net frames to one end of a unixgram socketpair, this process
//! holds the other end, acts as the guest's gateway and opens real host
//! connections only for what the policy allows. no root, no packet filter. it
//! exits when the VM's end of the socket goes away.

mod net;
mod policy;

use std::net::Ipv4Addr;
use std::process::exit;

use policy::{Mode, Policy};

const USAGE: &str = "usage: burner-macnet --fd N --mode web [--resolver IP]... [--block CIDR]...
                     [--guest IP/PREFIX] [--gateway IP] [-v]
  --fd        the process's end of a unixgram socketpair, one ethernet frame per datagram
  --mode      web: tcp 80 and 443 to public addresses, plus dns to the resolvers
  --resolver  a dns server the guest may use (udp and tcp 53), repeatable
  --block     an extra range the guest must never reach, repeatable
  --guest     the guest's address, default 172.29.217.2/30 (what burner's ip= hands it)
  --gateway   this process's address on the guest's network, default 172.29.217.1
  -v          log every connection and refusal to stderr";

pub struct Args {
    pub fd: i32,
    pub guest: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub verbose: bool,
}

fn die(msg: &str) -> ! {
    eprintln!("burner-macnet: {msg}");
    exit(2)
}

fn main() {
    let mut fd = None;
    let mut mode = None;
    let mut resolvers = Vec::new();
    let mut block = Vec::new();
    let mut guest = (Ipv4Addr::new(172, 29, 217, 2), 30);
    let mut gateway = Ipv4Addr::new(172, 29, 217, 1);
    let mut verbose = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == "-v" {
            verbose = true;
            continue;
        }
        if a == "-h" || a == "--help" {
            println!("{USAGE}");
            return;
        }
        let Some(v) = it.next() else {
            die(&format!("{a} needs a value\n{USAGE}"))
        };
        match a.as_str() {
            "--fd" => fd = Some(v.parse::<i32>().unwrap_or_else(|_| die("bad --fd"))),
            "--mode" => {
                mode = Some(Mode::parse(&v).unwrap_or_else(|| die("--mode must be web for now")))
            }
            "--resolver" => resolvers.push(
                v.parse::<Ipv4Addr>()
                    .unwrap_or_else(|_| die("bad --resolver")),
            ),
            "--block" => block.push(policy::parse_cidr(&v).unwrap_or_else(|| die("bad --block"))),
            "--guest" => guest = policy::parse_cidr(&v).unwrap_or_else(|| die("bad --guest")),
            "--gateway" => gateway = v.parse().unwrap_or_else(|_| die("bad --gateway")),
            _ => die(&format!("unknown argument {a}\n{USAGE}")),
        }
    }
    let (Some(fd), Some(mode)) = (fd, mode) else {
        die(USAGE)
    };
    let (ip, prefix) = guest;
    if !(1..=30).contains(&prefix) || !policy::inside(gateway, ip, prefix) || gateway == ip {
        die("--gateway must be another address on the --guest network");
    }
    let pol = Policy::new(mode, resolvers, &block, guest);
    let args = Args {
        fd,
        guest: ip,
        prefix,
        gateway,
        verbose,
    };
    if let Err(e) = net::run(&args, pol) {
        eprintln!("burner-macnet: {e}");
        exit(1);
    }
}
