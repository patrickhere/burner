//! ~/.config/burner/hosts.toml, and which host a command goes to: -H, then
//! BURNER_HOST, then this machine. the file decides where your commands and
//! what you pipe in end up, so it's checked the way ssh checks its config

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const ADDRS_MAX: usize = 8;
const ADDR_MAX: usize = 253;
pub const TIMEOUT_DEFAULT: Duration = Duration::from_secs(3);

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// tried in this order: ips, dns names or Host aliases from ssh config
    pub addrs: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    /// per address, 1s to 30s
    #[serde(default)]
    pub connect_timeout: Option<String>,
    /// burner's path there, when it isn't where install.sh or homebrew put it
    #[serde(default)]
    pub burner: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsFile {
    #[serde(default)]
    hosts: BTreeMap<String, Entry>,
}

/// where a command goes over ssh
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    /// the name in hosts.toml, or the -H value used as an ssh destination
    pub name: String,
    pub addrs: Vec<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub timeout: Duration,
    pub burner: Option<String>,
    /// it came from hosts.toml, not straight from -H
    pub configured: bool,
    /// the names hosts.toml has, for the message about a typo
    pub known: Vec<String>,
}

/// $XDG_CONFIG_HOME/burner/hosts.toml, else ~/.config/burner/hosts.toml, on
/// macOS too: it's the file you'd keep in dotfiles for every machine
pub fn path() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|x| {
        let p = std::path::Path::new(x);
        p.is_absolute()
    }) {
        return PathBuf::from(x).join("burner/hosts.toml");
    }
    home().join(".config/burner/hosts.toml")
}

fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return h.into();
    }
    // SAFETY: getuid can't fail
    let me = unsafe { libc::getuid() }.to_string();
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 5 && f[2] == me).then(|| PathBuf::from(f[5]))
            })
        })
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// the path as you'd type it, ~ for your home
pub fn shown(p: &std::path::Path) -> String {
    match p.strip_prefix(home()) {
        Ok(rest) if home() != std::path::Path::new("/") => format!("~/{}", rest.display()),
        _ => p.display().to_string(),
    }
}

/// a missing file is no hosts. one that someone else could have written, or
/// that doesn't parse, is an error
pub fn load(path: &std::path::Path) -> Result<BTreeMap<String, Entry>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).with_context(|| shown(path)),
        Ok(_) => {}
    }
    crate::config::trusted_file(path)?;
    let text = fs::read_to_string(path).with_context(|| shown(path))?;
    parse(&text).with_context(|| shown(path))
}

pub fn parse(text: &str) -> Result<BTreeMap<String, Entry>> {
    let f: HostsFile = toml::from_str(text).map_err(|e| anyhow::anyhow!("{}", e.message()))?;
    for (name, e) in &f.hosts {
        check(name, e).with_context(|| format!("[hosts.{name}]"))?;
    }
    Ok(f.hosts)
}

fn check(name: &str, e: &Entry) -> Result<()> {
    if !crate::run::valid_name(name) {
        bail!("a host name is lowercase letters, digits and dashes, max 32");
    }
    if name == "local" {
        bail!("local is taken: -H local means this machine");
    }
    if e.addrs.is_empty() || e.addrs.len() > ADDRS_MAX {
        bail!("addrs needs 1 to {ADDRS_MAX} addresses");
    }
    for a in &e.addrs {
        if !valid_addr(a) {
            bail!(
                "address {:?}: letters, digits and ._:- only, not starting with -",
                a.escape_debug().to_string()
            );
        }
    }
    if let Some(u) = &e.user
        && !valid_user(u)
    {
        bail!("user {:?} isn't a user name", u.escape_debug().to_string());
    }
    if e.port == Some(0) {
        bail!("port must be 1 to 65535");
    }
    if let Some(t) = &e.connect_timeout {
        timeout(t)?;
    }
    if let Some(b) = &e.burner
        && !valid_path(b)
    {
        bail!("burner must be an absolute path of letters, digits and ._/+- only");
    }
    Ok(())
}

/// an ip, a dns name or an ssh config alias. it's ssh's destination
/// argument, so it can never look like an option
pub fn valid_addr(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= ADDR_MAX
        && !a.starts_with('-')
        && a.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
}

pub fn valid_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c))
}

fn valid_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 1024
        && !p.split('/').any(|s| s == "..")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/+-".contains(&b))
}

/// 2s, 2 or 1500ms, between 1s and 30s
pub fn timeout(s: &str) -> Result<Duration> {
    let (num, ms) = if let Some(n) = s.strip_suffix("ms") {
        (n, true)
    } else {
        (s.strip_suffix('s').unwrap_or(s), false)
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("connect_timeout {s:?}: use 2s or 1500ms"))?;
    let d = if ms {
        Duration::from_millis(n)
    } else {
        Duration::from_secs(n)
    };
    if !(Duration::from_secs(1)..=Duration::from_secs(30)).contains(&d) {
        bail!("connect_timeout must be between 1s and 30s");
    }
    Ok(d)
}

/// the -H value, or BURNER_HOST when there's no -H. None means here
pub fn pick(flag: Option<&str>, env: Option<&str>) -> Option<String> {
    let v = match flag {
        Some(f) => f,
        None => env.filter(|e| !e.is_empty())?,
    };
    (v != "local").then(|| v.to_string())
}

/// what a -H value names: a host in hosts.toml, or else an ssh destination,
/// `user@` allowed, so a plain Host alias in ~/.ssh/config works with no
/// burner config at all
pub fn lookup(value: &str, hosts: &BTreeMap<String, Entry>) -> Result<Host> {
    let known: Vec<String> = hosts.keys().cloned().collect();
    if let Some(e) = hosts.get(value) {
        return Ok(Host {
            name: value.to_string(),
            addrs: e.addrs.clone(),
            user: e.user.clone(),
            port: e.port,
            timeout: match &e.connect_timeout {
                Some(t) => timeout(t)?,
                None => TIMEOUT_DEFAULT,
            },
            burner: e.burner.clone(),
            configured: true,
            known,
        });
    }
    let (user, addr) = match value.split_once('@') {
        Some((u, a)) => (Some(u), a),
        None => (None, value),
    };
    if !valid_addr(addr) || user.is_some_and(|u| !valid_user(u)) {
        bail!(
            "-H {:?}: a name from hosts.toml, an ssh host or user@host",
            value.escape_debug().to_string()
        );
    }
    Ok(Host {
        name: value.to_string(),
        addrs: vec![addr.to_string()],
        user: user.map(str::to_string),
        port: None,
        timeout: TIMEOUT_DEFAULT,
        burner: None,
        configured: false,
        known,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[hosts.mini]
addrs = ["10.1.0.81", "mini.tail1234.ts.net"]

[hosts.vps]
addrs = ["vps"]

[hosts.gaming]
addrs = ["10.1.10.139", "gaming.tail1234.ts.net"]
user = "patrick"
port = 2222
connect_timeout = "2s"
burner = "/usr/local/bin/burner"
"#;

    #[test]
    fn parses() {
        let h = parse(GOOD).unwrap();
        assert_eq!(h.len(), 3);
        let g = lookup("gaming", &h).unwrap();
        assert_eq!(g.user.as_deref(), Some("patrick"));
        assert_eq!((g.port, g.timeout), (Some(2222), Duration::from_secs(2)));
        assert!(g.configured);
        assert_eq!(g.known, ["gaming", "mini", "vps"]);
        let m = lookup("mini", &h).unwrap();
        assert_eq!(m.timeout, TIMEOUT_DEFAULT);
        assert_eq!(m.addrs.len(), 2);
        assert!(parse("").unwrap().is_empty());
    }

    #[test]
    fn refuses() {
        for bad in [
            // no place for a secret
            "[hosts.a]\naddrs = [\"x\"]\npassword = \"hunter2\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nidentity = \"~/.ssh/id\"\n",
            "[other]\nx = 1\n",
            "[hosts.A]\naddrs = [\"x\"]\n",
            "[hosts.local]\naddrs = [\"x\"]\n",
            "[hosts.a]\naddrs = []\n",
            "[hosts.a]\naddrs = [\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"]\n",
            "[hosts.a]\naddrs = [\"-oProxyCommand=x\"]\n",
            "[hosts.a]\naddrs = [\"a b\"]\n",
            "[hosts.a]\naddrs = [\"a;b\"]\n",
            "[hosts.a]\naddrs = [\"x\"]\nuser = \"-l\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nuser = \"Root\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nport = 0\n",
            "[hosts.a]\naddrs = [\"x\"]\nport = 70000\n",
            "[hosts.a]\naddrs = [\"x\"]\nconnect_timeout = \"0s\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nconnect_timeout = \"1m\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nburner = \"burner\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nburner = \"/x/../y\"\n",
            "[hosts.a]\naddrs = [\"x\"]\nburner = \"/x y\"\n",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn timeouts() {
        assert_eq!(timeout("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(timeout("5").unwrap(), Duration::from_secs(5));
        assert_eq!(timeout("1500ms").unwrap(), Duration::from_millis(1500));
        assert!(timeout("999ms").is_err());
        assert!(timeout("31s").is_err());
        assert!(timeout("fast").is_err());
    }

    #[test]
    fn which_host() {
        assert_eq!(pick(None, None), None);
        assert_eq!(pick(None, Some("")), None);
        assert_eq!(pick(None, Some("vps")).as_deref(), Some("vps"));
        // -H beats BURNER_HOST, and -H local beats both
        assert_eq!(pick(Some("mini"), Some("vps")).as_deref(), Some("mini"));
        assert_eq!(pick(Some("local"), Some("vps")), None);
        assert_eq!(pick(None, Some("local")), None);
    }

    #[test]
    fn ssh_destinations() {
        let h = parse(GOOD).unwrap();
        let a = lookup("box", &h).unwrap();
        assert_eq!(
            (a.addrs.as_slice(), a.configured),
            (&["box".to_string()][..], false)
        );
        let u = lookup("pat@10.1.0.5", &h).unwrap();
        assert_eq!(u.user.as_deref(), Some("pat"));
        assert_eq!(u.addrs, ["10.1.0.5"]);
        assert_eq!(u.known, ["gaming", "mini", "vps"]);
        for bad in [
            "-oProxyCommand=x",
            "a b",
            "a@b@c",
            "@x",
            "x@",
            "Root@x",
            "a;b",
            "",
        ] {
            assert!(lookup(bad, &h).is_err(), "{bad}");
        }
    }

    #[test]
    fn untrusted_file_refused() {
        use std::os::unix::fs::PermissionsExt;
        #[cfg(target_os = "macos")]
        let base = std::env::temp_dir().canonicalize().unwrap();
        #[cfg(target_os = "linux")]
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../target");
        let d = base.join(format!(
            "burner-hosts-{}",
            crate::sys::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        let f = d.join("hosts.toml");
        assert!(load(&f).unwrap().is_empty(), "a missing file is no hosts");
        fs::write(&f, GOOD).unwrap();
        let set = |m| fs::set_permissions(&f, fs::Permissions::from_mode(m)).unwrap();
        set(0o644);
        let ok = load(&f).map(|h| h.len());
        set(0o666);
        let world = load(&f).map(|h| h.len());
        set(0o600);
        fs::write(&f, "[hosts.a]\naddrs = [\"x\"]\nkey = 1\n").unwrap();
        let broken = load(&f).map(|h| h.len());
        fs::remove_dir_all(&d).unwrap();
        assert_eq!(ok.unwrap(), 3);
        assert!(format!("{:#}", world.unwrap_err()).contains("someone other than you"));
        assert!(broken.is_err());
    }
}
