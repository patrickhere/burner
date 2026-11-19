//! macnet is the one part of burner on macOS that parses what the guest sends
//! and holds real sockets, so it runs under a seatbelt profile of its own:
//! outbound connections and the routing socket, nothing else. no files, no
//! processes, no mach services (so no resolving names either). a bug in the
//! frame parsing or tcp stack then gets the guest no files and no processes,
//! but still any address the mac can reach: the policy that keeps loopback,
//! the lan and vpns out runs in this same process

use std::ffi::{CStr, CString, c_char, c_int};
use std::io;

// in libSystem. deprecated, but still what the system's own daemons and
// sandbox-exec use
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

const PROFILE: &str = r#"
(version 1)
(deny default)
; tcp and udp out, the policy picked where to already
; seatbelt can't take ranges, and a deny for localhost after this allow
; doesn't take, so loopback and the lan are the policy's job alone
(allow network-outbound (remote ip))
; route lookups
(allow system-socket (socket-domain AF_ROUTE))
; getifaddrs reads the interface list through sysctl
(allow sysctl-read (sysctl-name-prefix "net.routetable"))
"#;

/// from here on this process can only do what PROFILE allows. there's no way back
pub fn enter() -> io::Result<()> {
    let p = CString::new(PROFILE).map_err(io::Error::other)?;
    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: a NUL-terminated profile and an out pointer for the error,
    // freed with the function that goes with it
    let r = unsafe { sandbox_init(p.as_ptr(), 0, &mut err) };
    if r == 0 {
        return Ok(());
    }
    let msg = if err.is_null() {
        "unknown error".to_string()
    } else {
        // SAFETY: sandbox_init set err to a C string it allocated
        let m = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        unsafe { sandbox_free_error(err) };
        m
    };
    Err(io::Error::other(format!("sandbox: {msg}")))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpStream};
    use std::process::Command;

    const CHILD: &str = "BURNER_SANDBOX_CHILD";

    fn attempt(out: &mut impl Write, what: &str, r: std::io::Result<()>) {
        let _ = writeln!(
            out,
            "{what}: {}",
            match r {
                Ok(()) => "allowed".to_string(),
                Err(e) => format!("denied ({e})"),
            }
        );
    }

    /// runs again as a child, sandboxed, and tries what a compromised macnet would
    #[test]
    fn sandbox_holds() {
        if std::env::var_os(CHILD).is_some() {
            let home = std::env::var("HOME").unwrap();
            let mut o = std::io::stdout();
            // home is read before entering, the way macnet has its config by then
            super::enter().unwrap();
            attempt(
                &mut o,
                "list ~/.ssh",
                std::fs::read_dir(format!("{home}/.ssh")).map(drop),
            );
            attempt(
                &mut o,
                "read ~/.ssh/known_hosts",
                std::fs::read(format!("{home}/.ssh/known_hosts")).map(drop),
            );
            attempt(
                &mut o,
                "read /etc/passwd",
                std::fs::read("/etc/passwd").map(drop),
            );
            attempt(
                &mut o,
                "write /tmp",
                std::fs::write("/tmp/burner-sandbox-test", b"x"),
            );
            attempt(
                &mut o,
                "spawn /bin/sh",
                Command::new("/bin/sh")
                    .arg("-c")
                    .arg("true")
                    .status()
                    .map(drop),
            );
            attempt(
                &mut o,
                "unix socket to mDNSResponder",
                std::os::unix::net::UnixStream::connect("/var/run/mDNSResponder").map(drop),
            );
            attempt(
                &mut o,
                "route lookup",
                super::super::route::lookup(Ipv4Addr::UNSPECIFIED, true).map(drop),
            );
            attempt(
                &mut o,
                "interface list",
                super::super::policy::host_nets()
                    .map(drop)
                    .ok_or_else(|| std::io::Error::other("getifaddrs")),
            );
            let tcp = |ip: Ipv4Addr, port| {
                TcpStream::connect_timeout(&(ip, port).into(), std::time::Duration::from_secs(5))
                    .map(drop)
            };
            attempt(
                &mut o,
                "tcp to 1.1.1.1:443",
                tcp(Ipv4Addr::new(1, 1, 1, 1), 443),
            );
            let quad9 = Ipv4Addr::new(9, 9, 9, 9);
            attempt(
                &mut o,
                "udp to 9.9.9.9:53",
                super::super::route::check(quad9)
                    .map_err(std::io::Error::other)
                    .and_then(|i| super::super::net::dns_socket(quad9, i))
                    .and_then(|u| u.send(b"x"))
                    .map(drop),
            );
            attempt(
                &mut o,
                "a listening socket",
                std::net::TcpListener::bind("0.0.0.0:0").map(drop),
            );
            return;
        }
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macnet::sandbox::tests::sandbox_holds",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        eprintln!("{text}");
        for denied in [
            "list ~/.ssh",
            "read ~/.ssh/known_hosts",
            "read /etc/passwd",
            "write /tmp",
            "spawn /bin/sh",
            "unix socket to mDNSResponder",
            "a listening socket",
        ] {
            assert!(text.contains(&format!("{denied}: denied")), "{denied}");
        }
        for allowed in ["route lookup", "interface list", "udp to 9.9.9.9:53"] {
            assert!(text.contains(&format!("{allowed}: allowed")), "{allowed}");
        }
        assert!(!text.contains("tcp to 1.1.1.1:443: denied (Operation not permitted"));
    }
}
