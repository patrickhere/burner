use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub const DEFAULT_PATH: &str = "/etc/burner/config.toml";

#[cfg(target_os = "linux")]
pub fn default_path() -> PathBuf {
    DEFAULT_PATH.into()
}

/// on macOS burner runs as you, so everything it keeps is yours: the config,
/// kernel and images in ~/Library/Application Support/burner
#[cfg(target_os = "macos")]
pub fn default_path() -> PathBuf {
    support_dir().join("config.toml")
}

#[cfg(target_os = "macos")]
fn support_dir() -> PathBuf {
    home().join("Library/Application Support/burner")
}

/// from the user database, not $HOME, so it's the same dir however burner is started
#[cfg(target_os = "macos")]
fn home() -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getpwuid_r fills a passwd whose strings point into buf, which
    // outlives the read of pw_dir
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        if libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        ) == 0
            && !out.is_null()
            && !pw.pw_dir.is_null()
        {
            let dir = std::ffi::CStr::from_ptr(pw.pw_dir);
            return PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// the per-user temp dir launchd hands out (what $TMPDIR is set to), only
/// you can enter it. it doesn't depend on the environment burner got
#[cfg(target_os = "macos")]
pub fn user_temp() -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most buf.len() bytes, NUL included
    let n = unsafe {
        libc::confstr(
            libc::_CS_DARWIN_USER_TEMP_DIR,
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n == 0 || n > buf.len() {
        return std::env::temp_dir();
    }
    buf.truncate(n - 1);
    PathBuf::from(std::ffi::OsStr::from_bytes(&buf))
}
/// how many uids from jail.uid_base belong to VMs. also the most VMs at once
pub const VM_UIDS: u32 = 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub paths: Paths,
    pub net: Net,
    pub limits: Limits,
    pub jail: Jail,
    pub log: Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    /// firecracker, jailer, kernel, images and per-run jails live under here
    pub root: PathBuf,
    /// run state, cleared on reboot
    pub state: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Net {
    /// carved into one /30 per VM
    pub subnet: String,
    /// the interface VMs reach the internet through. empty = the default route's
    pub uplink: String,
    pub resolvers: Vec<Ipv4Addr>,
    /// bytes per second, each direction, per VM
    pub rate: u64,
    /// extra destinations VMs may never reach, on top of private ranges and
    /// everything the host itself has a route to
    pub block: Vec<String>,
    /// look up this host's public IPv4 every 10 min (behind NAT, the router's)
    /// and block it too. asks icanhazip.com, ipify.org as a fallback
    pub block_public_ip: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub vcpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
    pub ttl_secs: u32,
    pub ttl_shell_secs: u32,
    pub max_vms: u32,
    pub total_mem_mib: u32,
    /// the most network any run may ask for: none, web or open. default web
    pub net: String,
    /// how long --in stdin and --in tar wait for the next byte before giving up
    pub stdin_idle_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Jail {
    /// each VM's firecracker runs as its own uid and gid out of
    /// uid_base .. uid_base + 1023, with no account behind them
    pub uid_base: u32,
}

/// the run log: what's kept of each run and shell, per owner
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// the newest this many of each owner's runs. 0 keeps none
    pub keep_runs: u32,
    /// and none older than this. 0 keeps none
    pub keep_days: u32,
}

impl Default for Log {
    fn default() -> Self {
        Log {
            keep_runs: 200,
            keep_days: 30,
        }
    }
}

/// past these a typo is more likely than a wish
pub const KEEP_RUNS_MAX: u32 = 100_000;
pub const KEEP_DAYS_MAX: u32 = 36_500;

impl Default for Jail {
    fn default() -> Self {
        // past useradd's subuid ranges and systemd-nspawn's container range
        // (up to 1879048191), below 2^31 where signedness bugs live
        Jail {
            uid_base: 1_900_000_000,
        }
    }
}

#[cfg(target_os = "linux")]
impl Default for Paths {
    fn default() -> Self {
        Paths {
            root: "/var/lib/burner".into(),
            state: "/run/burner".into(),
        }
    }
}

#[cfg(target_os = "macos")]
impl Default for Paths {
    fn default() -> Self {
        Paths {
            root: support_dir(),
            state: user_temp().join("burner"),
        }
    }
}

impl Default for Net {
    fn default() -> Self {
        Net {
            subnet: "172.29.217.0/24".into(),
            uplink: String::new(),
            resolvers: vec![Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 1, 1, 1)],
            rate: 2_500_000,
            block: Vec::new(),
            block_public_ip: false,
        }
    }
}

// open (any port but mail) is something you opt into
const DEFAULT_NET: &str = "web";

impl Default for Limits {
    fn default() -> Self {
        Limits {
            vcpus: 2,
            mem_mib: 3072,
            disk_gib: 8,
            ttl_secs: 1800,
            ttl_shell_secs: 3600,
            max_vms: 2,
            total_mem_mib: 3072,
            net: DEFAULT_NET.into(),
            stdin_idle_secs: 60,
        }
    }
}

impl Config {
    /// a missing file means defaults; a broken one is an error, never silently ignored
    pub fn load(path: &Path) -> Result<Config> {
        // as root, a config decides what burner runs as root (paths.root holds
        // the jailer). only one that nobody but root could have written counts
        let via_sudo = std::env::var_os("SUDO_UID").is_some();
        #[cfg(target_os = "linux")]
        if crate::sys::is_root() {
            trusted(path, via_sudo)?;
        }
        #[cfg(target_os = "macos")]
        trusted_mac(path)?;
        let cfg = match fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| {
                // someone running burner through sudo doesn't get to read root's
                // files through parse errors: position only, never the text
                let line = e.span().map_or(0, |s| {
                    text[..s.start.min(text.len())].matches('\n').count() + 1
                });
                if via_sudo {
                    anyhow::anyhow!("{} is not a valid config (line {line})", path.display())
                } else {
                    anyhow::anyhow!("{} is not a valid config: {e}", path.display())
                }
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        cfg.check()?;
        Ok(cfg)
    }

    fn check(&self) -> Result<()> {
        let (_, prefix) = self.subnet()?;
        if prefix > 28 {
            bail!("net.subnet /{prefix} is too small, it needs room for at least four /30s");
        }
        let l = &self.limits;
        if crate::net::Mode::parse(&l.net).is_none() {
            bail!("limits.net must be none, web or open");
        }
        if l.vcpus == 0
            || l.mem_mib < 128
            || l.disk_gib == 0
            || l.ttl_secs < 10
            || l.max_vms == 0
            || l.stdin_idle_secs < 5
        {
            bail!("limits are too low to start a VM");
        }
        if l.total_mem_mib < l.mem_mib {
            bail!(
                "limits.total_mem_mib is below limits.mem_mib, no VM at the max size could ever start"
            );
        }
        if l.max_vms > VM_UIDS {
            bail!("limits.max_vms is over {VM_UIDS}, the most VM uids there are");
        }
        if self.log.keep_runs > KEEP_RUNS_MAX || self.log.keep_days > KEEP_DAYS_MAX {
            bail!(
                "log.keep_runs goes up to {KEEP_RUNS_MAX} and log.keep_days up to {KEEP_DAYS_MAX}"
            );
        }
        let base = self.jail.uid_base;
        if !(65536..=(1 << 31) - VM_UIDS).contains(&base) {
            bail!(
                "jail.uid_base has to be between 65536 (below that live real accounts) and {}",
                (1u32 << 31) - VM_UIDS
            );
        }
        Ok(())
    }

    /// the uids (and gids, same numbers) VMs run as
    pub fn vm_uids(&self) -> std::ops::Range<u32> {
        self.jail.uid_base..self.jail.uid_base + VM_UIDS
    }

    pub fn subnet(&self) -> Result<(Ipv4Addr, u8)> {
        parse_cidr(&self.net.subnet).with_context(|| format!("net.subnet {:?}", self.net.subnet))
    }

    /// how many /30 slots the subnet holds
    pub fn net_slots(&self) -> Result<u32> {
        let (_, prefix) = self.subnet()?;
        Ok(1u32 << (30 - prefix))
    }

    pub fn uplink(&self) -> Result<String> {
        if !self.net.uplink.is_empty() {
            return Ok(self.net.uplink.clone());
        }
        default_route_iface().context("no default route; set net.uplink in the config")
    }
}

pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = s.split_once('/').context("expected a.b.c.d/nn")?;
    let addr: Ipv4Addr = addr.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        bail!("prefix over 32");
    }
    let mask = mask(prefix);
    if u32::from(addr) & !mask != 0 {
        bail!(
            "host bits set, did you mean {}/{prefix}",
            Ipv4Addr::from(u32::from(addr) & mask)
        );
    }
    Ok((addr, prefix))
}

pub fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn overlaps(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
    let m = mask(a.1.min(b.1));
    u32::from(a.0) & m == u32::from(b.0) & m
}

fn default_route_iface() -> Option<String> {
    // /proc/net/route: iface, destination (hex, 0 = default), ..., metric,
    // mask. a full-tunnel vpn's 0.0.0.0/1 has destination 0 too, its mask
    // isn't. of two defaults the kernel takes the lower metric, the first
    // one listed on a tie
    let routes = fs::read_to_string("/proc/net/route").ok()?;
    routes
        .lines()
        .skip(1)
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.len() > 7 && f[1] == "00000000" && f[7] == "00000000")
        .min_by_key(|f| f[6].parse::<u32>().unwrap_or(u32::MAX))
        .map(|f| f[0].to_string())
}

/// the config file and every directory above it: owned by root and writable by
/// nobody else. a path other than the default has to exist, and through sudo it
/// has to be in /etc/burner, so a sudo rule for burner can't be used to load
/// some other root-owned file as a config
#[cfg(target_os = "linux")]
fn trusted(path: &Path, via_sudo: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let real = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && path == Path::new(DEFAULT_PATH) => {
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("config {}", path.display())),
    };
    if via_sudo && !real.starts_with("/etc/burner/") {
        bail!("through sudo, --config has to be a file in /etc/burner");
    }
    for p in real.ancestors() {
        let m = fs::metadata(p).with_context(|| format!("checking {}", p.display()))?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            bail!(
                "{} is owned or writable by someone other than root, so burner won't take a config from it",
                p.display()
            );
        }
    }
    Ok(())
}

/// on macOS burner runs as you and only spends your own resources, so a config
/// you could have written yourself is fine. one someone else could have written
/// or swapped isn't: it picks the kernel and image your VMs boot, and with them
/// what happens to anything you pipe in
#[cfg(target_os = "macos")]
fn trusted_mac(path: &Path) -> Result<()> {
    match fs::canonicalize(path) {
        Ok(real) => trusted_file(&real),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && path == default_path() => Ok(()),
        Err(e) => Err(e).with_context(|| format!("config {}", path.display())),
    }
}

/// the admin group on macOS. its members can already become root, so a
/// directory they can write is no weaker than one only root can. homebrew
/// makes its prefix and Cellar group admin and group writable
#[cfg(target_os = "macos")]
const ADMIN_GID: u32 = 80;

/// whether a mode lets anyone but the owner, root or the admin group write
#[cfg(target_os = "macos")]
fn mode_lets_others_write(mode: u32, gid: u32) -> bool {
    mode & 0o002 != 0 || (mode & 0o020 != 0 && gid != ADMIN_GID)
}

/// a file and every directory above it owned by you or root and writable by
/// nobody else: on macOS the admin group aside, by its mode or by an ACL, on
/// linux by its mode
pub fn trusted_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid can't fail
    let me = unsafe { libc::getuid() };
    // the directories above the real file, not above a symlink to it: a
    // trusted path can point into a tree someone else can write
    let real = fs::canonicalize(path).with_context(|| format!("checking {}", path.display()))?;
    for p in real.ancestors() {
        let m = fs::metadata(p).with_context(|| format!("checking {}", p.display()))?;
        if (m.uid() != me && m.uid() != 0) || others_write(p, &m, me)? {
            bail!(
                "{} is owned or writable by someone other than you or root, so burner won't use it",
                p.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn others_write(p: &Path, m: &fs::Metadata, me: u32) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(mode_lets_others_write(m.mode(), m.gid())
        || acl::lets_others_write(p, me)
            .with_context(|| format!("reading the ACL of {}", p.display()))?)
}

/// world writable, or group writable by a group with anyone in it but you.
/// debian and ubuntu give each user a group of their own and often umask
/// 002, so ~/.config can be group writable by just you. ssh makes the same
/// exception for ~/.ssh/config
#[cfg(target_os = "linux")]
fn others_write(_: &Path, m: &fs::Metadata, me: u32) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    if m.mode() & 0o002 != 0 {
        return Ok(true);
    }
    if m.mode() & 0o020 == 0 {
        return Ok(false);
    }
    let passwd = fs::read_to_string("/etc/passwd").unwrap_or_default();
    let group = fs::read_to_string("/etc/group").unwrap_or_default();
    Ok(!group_of_one(m.gid(), me, &passwd, &group))
}

/// whether `me` is the only user in group `gid`, as the primary group of
/// accounts and as a listed member. a group with nobody in it doesn't count:
/// those belong to setgid programs
#[cfg(target_os = "linux")]
fn group_of_one(gid: u32, me: u32, passwd: &str, group: &str) -> bool {
    let users: Vec<(&str, u32, u32)> = passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some((
                *f.first()?,
                f.get(2)?.parse().ok()?,
                f.get(3)?.parse().ok()?,
            ))
        })
        .collect();
    let Some(my_name) = users.iter().find(|u| u.1 == me).map(|u| u.0) else {
        return false;
    };
    let primary: Vec<u32> = users.iter().filter(|u| u.2 == gid).map(|u| u.1).collect();
    let listed: Vec<&str> = group
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.get(2)?.parse::<u32>().ok()? == gid).then(|| f.get(3).copied().unwrap_or(""))
        })
        .flat_map(|m| m.split(',').filter(|s| !s.is_empty()))
        .collect();
    (!primary.is_empty() || !listed.is_empty())
        && primary.iter().all(|&u| u == me)
        && listed.iter().all(|&n| n == my_name)
}

/// macOS ACLs: an entry can let others write where the mode bits say nobody can
#[cfg(target_os = "macos")]
mod acl {
    use std::ffi::{CString, c_int, c_void};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const ACL_TYPE_EXTENDED: c_int = 0x100;
    const ACL_FIRST_ENTRY: c_int = 0;
    const ACL_NEXT_ENTRY: c_int = -1;
    const ACL_EXTENDED_ALLOW: c_int = 1;
    const ID_TYPE_UID: c_int = 0;
    const ID_TYPE_GID: c_int = 1;
    /// write and append data (add file and subdirectory on a dir), delete,
    /// delete child, write attributes, extended attributes and the ACL, chown
    const WRITES: u64 = 1 << 2 | 1 << 4 | 1 << 5 | 1 << 6 | 1 << 8 | 1 << 10 | 1 << 12 | 1 << 13;

    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, ty: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
        fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
        fn acl_free(obj: *mut c_void) -> c_int;
        fn mbr_uuid_to_id(uu: *const u8, id: *mut libc::id_t, ty: *mut c_int) -> c_int;
    }

    /// true when an allow entry gives anyone but `me`, root or the admin group
    /// any kind of write
    pub fn lets_others_write(path: &Path, me: u32) -> io::Result<bool> {
        let p = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: a NUL-terminated path; the ACL and each qualifier are freed
        // with acl_free, entries belong to the ACL and aren't freed themselves
        unsafe {
            let acl = acl_get_file(p.as_ptr(), ACL_TYPE_EXTENDED);
            if acl.is_null() {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::ENOENT) => Ok(false),
                    _ => Err(e),
                };
            }
            let mut found = false;
            let mut entry = std::ptr::null_mut();
            let mut id = ACL_FIRST_ENTRY;
            while !found && acl_get_entry(acl, id, &mut entry) == 0 {
                id = ACL_NEXT_ENTRY;
                let (mut tag, mut mask) = (0, 0u64);
                if acl_get_tag_type(entry, &mut tag) != 0
                    || acl_get_permset_mask_np(entry, &mut mask) != 0
                {
                    found = true;
                    break;
                }
                if tag != ACL_EXTENDED_ALLOW || mask & WRITES == 0 {
                    continue;
                }
                let q = acl_get_qualifier(entry);
                let (mut who, mut ty) = (0, -1);
                let ok = !q.is_null() && mbr_uuid_to_id(q.cast(), &mut who, &mut ty) == 0;
                if !q.is_null() {
                    acl_free(q);
                }
                // a group can hold others, so only a user entry for you or root
                // is fine, and the admin group, whose members can become root
                let fine = (ty == ID_TYPE_UID && (who == me || who == 0))
                    || (ty == ID_TYPE_GID && who == super::ADMIN_GID);
                found = !(ok && fine);
            }
            acl_free(acl);
            Ok(found)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::process::Command;

        fn with_acl(rule: &str) -> bool {
            let f = std::env::temp_dir()
                .join(format!("burner-acl-{}", crate::sys::random_hex(6).unwrap()));
            std::fs::write(&f, b"x").unwrap();
            if !rule.is_empty() {
                let st = Command::new("chmod").arg("+a").arg(rule).arg(&f).status();
                assert!(st.unwrap().success(), "{rule}");
            }
            // SAFETY: getuid can't fail
            let r = super::lets_others_write(&f, unsafe { libc::getuid() }).unwrap();
            // "deny delete" holds against its owner too
            Command::new("chmod").arg("-N").arg(&f).status().unwrap();
            std::fs::remove_file(&f).unwrap();
            r
        }

        #[test]
        fn write_entries_for_others() {
            let me = std::env::var("USER").unwrap();
            assert!(!with_acl(""));
            assert!(!with_acl("everyone deny delete"));
            assert!(!with_acl("everyone allow read"));
            assert!(!with_acl(&format!("user:{me} allow write")));
            assert!(with_acl("everyone allow write"));
            assert!(with_acl("everyone allow append"));
            assert!(with_acl("group:staff allow writeattr"));
            assert!(with_acl("user:nobody allow delete"));
            assert!(!with_acl("group:admin allow write"));
            assert!(with_acl("group:everyone allow write"));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    #[test]
    fn trusted_by_mode() {
        use std::os::unix::fs::PermissionsExt;
        // /tmp is world writable, so the test tree lives in the checkout
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target")
            .join(format!(
                "burner-trust-{}",
                crate::sys::random_hex(6).unwrap()
            ));
        let f = d.join("f");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(&f, b"x").unwrap();
        let set = |p: &std::path::Path, m| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let mut seen = Vec::new();
        for (dir, file) in [
            (0o700, 0o600),
            (0o755, 0o644),
            (0o757, 0o644),
            (0o755, 0o666),
        ] {
            set(&d, dir);
            set(&f, file);
            seen.push(super::trusted_file(&f).is_ok());
        }
        set(&d, 0o700);
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(seen, [true, true, false, false]);
        assert!(super::trusted_file(&d.join("gone")).is_err());
    }

    #[test]
    fn groups_of_one() {
        let passwd = "root:x:0:0::/root:/bin/sh\npat:x:1000:1000::/home/pat:/bin/bash\n\
                      sam:x:1001:1001::/home/sam:/bin/bash\nweb:x:33:1000::/:/bin/false\n";
        let group = "pat:x:1000:\nsam:x:1001:\nstaff:x:50:pat,sam\nmine:x:51:pat\nempty:x:52:\n";
        let one = |gid, me| super::group_of_one(gid, me, passwd, group);
        assert!(one(1001, 1001));
        assert!(!one(50, 1001));
        assert!(!one(52, 1001), "a group with nobody in it");
        assert!(one(51, 1000));
        // another account has pat's group as its primary one
        assert!(!one(1000, 1000));
        assert!(!one(1001, 4242));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod mac_tests {
    #[test]
    fn group_admin_may_write() {
        use super::mode_lets_others_write as w;
        // homebrew's Cellar: drwxrwxr-x you:admin
        assert!(!w(0o40775, super::ADMIN_GID));
        assert!(!w(0o40755, 20));
        assert!(w(0o40775, 20));
        assert!(w(0o40757, super::ADMIN_GID));
        assert!(w(0o40777, super::ADMIN_GID));
        assert!(w(0o100664, 0));
    }

    #[test]
    fn trusted_under_group_admin() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "burner-trust-{}",
            crate::sys::random_hex(6).unwrap()
        ));
        let f = d.join("f");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(&f, b"x").unwrap();
        let mode = |m| std::fs::set_permissions(&d, std::fs::Permissions::from_mode(m)).unwrap();
        // only where the test runs as a member of admin, as on a mac's first user
        let admin = std::process::Command::new("chgrp")
            .arg("admin")
            .arg(&d)
            .status()
            .is_ok_and(|s| s.success());
        mode(0o775);
        let in_admin = super::trusted_file(&f);
        mode(0o777);
        let world = super::trusted_file(&f);
        mode(0o700);
        std::fs::remove_dir_all(&d).unwrap();
        if admin {
            assert!(in_admin.is_ok(), "{in_admin:?}");
        }
        assert!(world.is_err());
    }

    #[test]
    fn trusted_follows_symlinks_to_the_real_tree() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "burner-link-{}",
            crate::sys::random_hex(6).unwrap()
        ));
        let open = base.join("open");
        let inner = open.join("inner");
        let safe = base.join("safe");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::create_dir(&safe).unwrap();
        std::fs::write(inner.join("f"), b"x").unwrap();
        for (d, m) in [
            (&base, 0o700),
            (&safe, 0o700),
            (&inner, 0o700),
            (&open, 0o777),
        ] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(m)).unwrap();
        }
        std::os::unix::fs::symlink(&inner, safe.join("link")).unwrap();
        // the link sits in a safe dir and its target dir is private, but the
        // dir above the target is world writable
        let r = super::trusted_file(&safe.join("link").join("f"));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
        assert!(r.is_err(), "{r:?}");
    }
}

/// ipv4 addresses on an interface, from `ip -j`
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn iface_addrs(iface: &str) -> Result<Vec<Ipv4Addr>> {
    let out = crate::sys::run_timeout(
        Command::new("ip").args(["-j", "-4", "addr", "show", "dev", iface]),
        None,
        std::time::Duration::from_secs(30),
    )?;
    if !out.status.success() {
        bail!("ip addr show {iface} failed");
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let mut addrs = Vec::new();
    for link in v.as_array().into_iter().flatten() {
        for a in link["addr_info"].as_array().into_iter().flatten() {
            if let Some(ip) = a["local"].as_str().and_then(|s| s.parse().ok()) {
                addrs.push(ip);
            }
        }
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert_eq!(
            parse_cidr("10.1.0.0/16").unwrap(),
            (Ipv4Addr::new(10, 1, 0, 0), 16)
        );
        assert!(parse_cidr("10.1.0.5/16").is_err());
        assert!(parse_cidr("10.1.0.0/33").is_err());
        assert!(parse_cidr("nope").is_err());
    }

    #[test]
    fn overlap() {
        let lan = parse_cidr("10.1.0.0/16").unwrap();
        assert!(overlaps(lan, parse_cidr("10.1.4.0/24").unwrap()));
        assert!(!overlaps(lan, parse_cidr("172.29.217.0/24").unwrap()));
        assert!(overlaps(parse_cidr("0.0.0.0/0").unwrap(), lan));
    }

    #[test]
    fn defaults_are_valid() {
        let c = Config::default();
        c.check().unwrap();
        assert_eq!(c.net_slots().unwrap(), 64);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_limits() {
        assert!(toml::from_str::<Config>("[net]\nsubnett = \"10.0.0.0/24\"\n").is_err());
        let c: Config = toml::from_str("[limits]\nmem_mib = 4096\ntotal_mem_mib = 2048\n").unwrap();
        assert!(c.check().is_err());
    }

    #[test]
    fn vm_uid_range() {
        let c = Config::default();
        assert_eq!(c.vm_uids(), 1_900_000_000..1_900_001_024);
        for bad in [
            "[jail]\nuid_base = 0\n",
            "[jail]\nuid_base = 1000\n",
            "[jail]\nuid_base = 2147483000\n",
            "[limits]\nmax_vms = 2000\ntotal_mem_mib = 9999999\n",
        ] {
            assert!(
                toml::from_str::<Config>(bad).unwrap().check().is_err(),
                "{bad}"
            );
        }
        let c: Config = toml::from_str("[jail]\nuid_base = 400000\n").unwrap();
        c.check().unwrap();
        assert!(c.vm_uids().contains(&401_023) && !c.vm_uids().contains(&401_024));
    }

    #[test]
    fn log_keys() {
        let c = Config::default();
        assert_eq!((c.log.keep_runs, c.log.keep_days), (200, 30));
        let c: Config = toml::from_str("[log]\nkeep_runs = 0\nkeep_days = 7\n").unwrap();
        c.check().unwrap();
        assert_eq!((c.log.keep_runs, c.log.keep_days), (0, 7));
        assert!(toml::from_str::<Config>("[log]\nkeep = 3\n").is_err());
        let c: Config = toml::from_str("[log]\nkeep_runs = 100001\n").unwrap();
        assert!(c.check().is_err());
        let c: Config = toml::from_str("[log]\nkeep_days = 40000\n").unwrap();
        assert!(c.check().is_err());
    }
}
