//! the run log: one record for every run and shell, kept under paths.root
//! so it outlives a reboot, plus the client's copy of each -H run.
//!
//! a record is a file of two lines: a small head (what `burner log --list`
//! shows: host, command, image, exit, counts) and the run's `result` as its
//! --json had it. this machine's runs are `logs/UID/ID.json` under
//! paths.root, root's on linux. a -H copy is `ID@HOST.json`: on a mac in the
//! same place, on linux in the caller's own ~/.local/state/burner/logs.
//! a copy holds what a far end said, so it's read with the lenient types,
//! cleaned and capped, and only from a file its owner wrote

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{Config, Log};
use crate::ledger::valid_id;
use crate::netlog::NetLog;
use crate::run::RunArgs;
use crate::run::record::{Finished, RunOutcome, RunResult};

/// the head's version: it goes up when a field changes or goes away
pub const RECORD: u32 = 1;
/// the command line kept, in characters, after escaping
pub const COMMAND_CAP: usize = 300;
/// a head is never longer than this
const HEAD_CAP: usize = 16 << 10;
/// a whole record: the head and a result with a log of up to FILE_CAP, a
/// far end's as frame.rs lets it through included
pub const RECORD_CAP: usize = 2 * crate::netlog::FILE_CAP;
/// a -H host as it's kept in a file name
const SLUG_CAP: usize = 64;

/// how a run or shell ended, as it's handed to keep
pub enum Ended<'a> {
    /// a run or shell on this machine, the far end of -H included
    Here {
        cfg: &'a Config,
        args: &'a RunArgs,
        fin: &'a Finished,
    },
    /// the client of -H. `env` and `raw` are the far end's json, parsed and
    /// as it came, when it said how the run ended; None when the client
    /// decided it (unreachable, lost, interrupted, a shell left with ~.)
    Remote {
        host: &'a str,
        args: &'a RunArgs,
        /// when the client started on the run
        t0: Instant,
        code: u8,
        env: Option<&'a Value>,
        raw: Option<&'a str>,
        /// the id the far end said it started, if it did
        id: Option<&'a str>,
        /// the client's own word for how it ended, when it decided it
        outcome: Option<RunOutcome>,
    },
}

/// the first line of a record
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub record: u32,
    /// the burner that kept it
    pub burner: String,
    pub id: String,
    /// the -H host it ran on, as it was named; null for this machine
    pub host: Option<String>,
    pub shell: bool,
    /// the command as the VM's sh got it, controls escaped, cut to 300
    /// characters. empty for a shell
    pub command: String,
    pub img: String,
    pub net: String,
    pub tag: Option<String>,
    /// who ran it: the sudo caller on linux
    pub owner: u32,
    pub started_unix: u64,
    pub secs: f64,
    /// what burner exited with
    pub exit: u8,
    pub outcome: String,
    pub rc: Option<i64>,
    /// the connection log's allowed connections and blocked destinations,
    /// null without one
    pub allowed: Option<u64>,
    pub blocked: Option<u64>,
}

/// called once at the end of every run and shell, just before the json goes
/// out. it never fails the run, prints, or notes json errors: a record that
/// can't be kept goes to syslog. true when one was kept
pub fn keep(e: Ended) -> bool {
    match e {
        Ended::Here { cfg, args, fin } => {
            let Some(r) = &fin.result else { return false };
            match keep_here(cfg, args, fin) {
                Ok(kept) => kept,
                Err(err) => {
                    crate::sys::syslog(&format!("{}: couldn't keep the run log: {err}", r.id));
                    false
                }
            }
        }
        Ended::Remote {
            host,
            args,
            t0,
            code,
            env,
            raw: _,
            id,
            outcome,
        } => keep_remote(host, args, t0, code, env, id, outcome).unwrap_or(false),
    }
}

/// the reaper's pass over the kept runs: every owner's, on top of what each
/// store does after a run
pub fn prune(cfg: &Config) {
    let logs = machine_dir(cfg);
    for e in fs::read_dir(&logs).into_iter().flatten().flatten() {
        let numeric = e
            .file_name()
            .to_str()
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if numeric && e.file_type().is_ok_and(|t| t.is_dir()) {
            prune_dir(&e.path(), &cfg.log);
        }
    }
    crate::netlog::clear_old(&cfg.paths.state);
}

// ---- keeping ----

fn keep_here(cfg: &Config, args: &RunArgs, fin: &Finished) -> io::Result<bool> {
    let Some(r) = &fin.result else {
        return Ok(false);
    };
    if !valid_id(&r.id) {
        return Ok(false);
    }
    let owner = caller_uid();
    let vm = r.vm.as_ref();
    let summary = r.network.as_ref().map(|n| &n.summary);
    let head = Head {
        record: RECORD,
        burner: env!("CARGO_PKG_VERSION").into(),
        id: r.id.clone(),
        host: None,
        shell: args.is_shell(),
        command: command_of(&args.command()),
        img: vm.map_or_else(|| args.img().to_string(), |v| v.img.clone()),
        net: vm.map_or_else(|| args.net().to_string(), |v| v.net.to_string()),
        tag: match vm {
            Some(v) => v.tag.clone(),
            None => args.tag().map(String::from),
        },
        owner,
        started_unix: now_unix().saturating_sub(fin.secs.max(0.0) as u64),
        secs: round3(fin.secs),
        exit: fin.code,
        outcome: outcome_name(fin.outcome),
        rc: fin.rc.map(i64::from),
        allowed: summary.map(|s| s.allowed),
        blocked: summary.map(|s| s.blocked),
    };
    let result = serde_json::to_value(r)?;
    let logs = machine_dir(cfg);
    private_dir(&logs)?;
    let dir = logs.join(owner.to_string());
    private_dir(&dir)?;
    store(&dir, &format!("{}.json", r.id), &head, &result, &cfg.log)?;
    Ok(cfg.log.keep_runs > 0 && cfg.log.keep_days > 0)
}

/// the client's copy of a -H run: the far end's result, cleaned, with this
/// side's own head. nothing for a run that never had an id
fn keep_remote(
    host: &str,
    args: &RunArgs,
    t0: Instant,
    code: u8,
    env: Option<&Value>,
    id: Option<&str>,
    outcome: Option<RunOutcome>,
) -> io::Result<bool> {
    let mut result = env
        .and_then(|e| e.get("result"))
        .filter(|r| r.is_object())
        .cloned()
        .unwrap_or(Value::Null);
    clean(&mut result);
    let str_at = |v: &Value, path: &[&str]| -> Option<String> {
        let mut v = v;
        for p in path {
            v = v.get(p)?;
        }
        v.as_str().map(String::from)
    };
    let Some(rid) = str_at(&result, &["id"])
        .filter(|i| valid_id(i))
        .or_else(|| id.filter(|i| valid_id(i)).map(String::from))
    else {
        return Ok(false);
    };
    // a result that isn't this run's isn't kept with it
    if str_at(&result, &["id"]).as_deref() != Some(rid.as_str()) {
        result = Value::Null;
    }
    let said = str_at(&result, &["outcome"]).map(|o| text(&o, 32));
    let outcome = match (outcome, said) {
        (Some(o), _) => outcome_name(o),
        (None, Some(o)) => o,
        (None, None) => "remote_error".into(),
    };
    let rc = result
        .get("rc")
        .and_then(Value::as_i64)
        .filter(|_| outcome == "exited");
    let log = result.get("network").and_then(NetLog::lenient);
    if log.is_none() && result.is_object() {
        // a log this burner can't read is no log
        result["network"] = Value::Null;
    }
    let elapsed = t0.elapsed().as_secs_f64();
    let head = Head {
        record: RECORD,
        burner: env!("CARGO_PKG_VERSION").into(),
        id: rid.clone(),
        host: Some(text(host, 255)),
        shell: args.is_shell(),
        command: command_of(&args.command()),
        img: str_at(&result, &["vm", "img"])
            .map(|i| text(&i, 64))
            .unwrap_or_else(|| args.img().into()),
        net: str_at(&result, &["vm", "net"])
            .map(|n| text(&n, 16))
            .unwrap_or_else(|| args.net().into()),
        tag: match result.get("vm").filter(|v| v.is_object()) {
            Some(vm) => str_at(vm, &["tag"]).map(|t| text(&t, 64)),
            None => args.tag().map(String::from),
        },
        // SAFETY: getuid can't fail. the client never runs as root
        owner: unsafe { libc::getuid() },
        started_unix: now_unix().saturating_sub(elapsed as u64),
        secs: round3(elapsed),
        exit: code,
        outcome,
        rc,
        allowed: log.as_ref().map(|l| l.summary.allowed),
        blocked: log.as_ref().map(|l| l.summary.blocked),
    };
    // the far end's line was capped on the way in; this is the cap on disk
    if serde_json::to_vec(&result)?.len() > RECORD_CAP - HEAD_CAP {
        result["network"] = Value::Null;
    }
    let dir = copies_dir().ok_or_else(|| io::Error::other("no home to keep -H runs in"))?;
    make_dirs(&dir)?;
    let cfg = client_config();
    store(
        &dir,
        &format!("{rid}@{}.json", slug(host)),
        &head,
        &result,
        &cfg.log,
    )?;
    Ok(cfg.log.keep_runs > 0 && cfg.log.keep_days > 0)
}

/// a record goes in whole or not at all: written aside, then renamed. then
/// the oldest of that owner's go
fn store(dir: &Path, name: &str, head: &Head, result: &Value, keep: &Log) -> io::Result<()> {
    if keep.keep_runs > 0 && keep.keep_days > 0 {
        let mut b = serde_json::to_vec(head)?;
        if b.len() >= HEAD_CAP {
            return Err(io::Error::other("the record's head is too long"));
        }
        b.push(b'\n');
        serde_json::to_writer(&mut b, result)?;
        b.push(b'\n');
        let path = dir.join(name);
        let tmp = dir.join(format!("{name}.new"));
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        let wrote = f.write_all(&b).and_then(|()| f.sync_all());
        if let Err(e) = wrote.and_then(|()| fs::rename(&tmp, &path)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    }
    prune_dir(dir, keep);
    Ok(())
}

/// one owner's records: the newest keep_runs, none older than keep_days,
/// and no leftovers of a write that didn't finish
fn prune_dir(dir: &Path, keep: &Log) {
    let max_age = Duration::from_secs(u64::from(keep.keep_days) * 86_400);
    let mut records = Vec::new();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let Some(t) = e.metadata().and_then(|m| m.modified()).ok() else {
            continue;
        };
        let name = e.file_name();
        let name = name.to_string_lossy();
        if record_name(&name).is_some() {
            records.push((t, e.path()));
        } else if name
            .strip_suffix(".new")
            .is_some_and(|n| record_name(n).is_some())
            && t.elapsed().is_ok_and(|d| d > Duration::from_secs(600))
        {
            let _ = fs::remove_file(e.path());
        }
    }
    newest_first(&mut records);
    for (i, (t, p)) in records.into_iter().enumerate() {
        let old = t.elapsed().is_ok_and(|a| a > max_age);
        if i >= keep.keep_runs as usize || old {
            let _ = fs::remove_file(p);
        }
    }
}

fn newest_first(v: &mut [(SystemTime, PathBuf)]) {
    v.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
}

/// a record's file name: its id, and for a -H copy the host's slug
fn record_name(name: &str) -> Option<(&str, Option<&str>)> {
    let stem = name.strip_suffix(".json")?;
    let (id, host) = match stem.split_once('@') {
        Some((id, h)) => (id, Some(h)),
        None => (stem, None),
    };
    if !valid_id(id) {
        return None;
    }
    if let Some(h) = host
        && (h.is_empty() || h.len() > SLUG_CAP || h.bytes().any(|b| !slug_byte(b)))
    {
        return None;
    }
    Some((id, host))
}

fn slug_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
}

/// a -H host's name as a file name can have it, one name to one slug: a
/// byte past letters, digits, . and - is _xx. a long one is its start and
/// a hash of all of it
fn slug(host: &str) -> String {
    let tok = |b: u8| {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
            (b as char).to_string()
        } else {
            format!("_{b:02x}")
        }
    };
    let full: String = host.bytes().map(tok).collect();
    if !full.is_empty() && full.len() <= SLUG_CAP {
        return full;
    }
    let mut s = String::new();
    for t in host.bytes().map(tok) {
        if s.len() + t.len() > SLUG_CAP - 18 {
            break;
        }
        s += &t;
    }
    // fnv-1a: no crate for it, and it only has to tell long names apart
    let h = host.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("{s}_h{h:016x}")
}

/// the records in a dir, newest first
fn records_in(dir: &Path) -> Vec<(SystemTime, PathBuf)> {
    let mut v: Vec<_> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            record_name(&name)?;
            Some((e.metadata().ok()?.modified().ok()?, e.path()))
        })
        .collect();
    newest_first(&mut v);
    v
}

// ---- where ----

fn machine_dir(cfg: &Config) -> PathBuf {
    cfg.paths.root.join("logs")
}

/// a dir only its owner can enter
fn private_dir(path: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() {
        return Err(io::Error::other(format!(
            "{} isn't a directory",
            path.display()
        )));
    }
    if m.mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// the -H copies' dir and the ones above it, made private where they're new
fn make_dirs(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    private_dir(dir)
}

/// the config the -H client goes by for retention and, on a mac, where the
/// store is: the default one, or burner's defaults when that doesn't load
fn client_config() -> Config {
    Config::load(&crate::config::default_path()).unwrap_or_default()
}

/// where this user's -H copies go
fn copies_dir() -> Option<PathBuf> {
    // SAFETY: getuid can't fail
    let me = unsafe { libc::getuid() };
    #[cfg(target_os = "macos")]
    return Some(machine_dir(&client_config()).join(me.to_string()));
    #[cfg(target_os = "linux")]
    return state_home(me, true).map(|d| d.join("burner/logs"));
}

/// a user's XDG state dir: $XDG_STATE_HOME when it's absolute, else
/// ~/.local/state with the home from the user database. through sudo the
/// environment is the caller's only when `env` says it may be
#[cfg(target_os = "linux")]
fn state_home(uid: u32, env: bool) -> Option<PathBuf> {
    if env
        && let Some(d) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        && d.is_absolute()
    {
        return Some(d);
    }
    home_of(uid).map(|h| h.join(".local/state"))
}

#[cfg(target_os = "linux")]
fn home_of(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getpwuid_r fills a passwd whose strings point into buf, which
    // outlives the read of pw_dir
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 4096];
        if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) == 0
            && !out.is_null()
            && !pw.pw_dir.is_null()
        {
            let dir = std::ffi::CStr::from_ptr(pw.pw_dir);
            let p = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
            return p.is_absolute().then_some(p);
        }
    }
    None
}

/// who asked for the run: the sudo caller when there is one, else our own
/// uid. the same rule as run/admin.rs caller_uid
fn caller_uid() -> u32 {
    std::env::var("SUDO_UID")
        .ok()
        .filter(|u| u.bytes().all(|b| b.is_ascii_digit()) && !u.is_empty())
        .and_then(|u| u.parse().ok())
        // SAFETY: getuid can't fail
        .unwrap_or_else(|| unsafe { libc::getuid() })
}

// ---- reading ----

/// a dir records are read from: whose files they must be, and whether only
/// -H copies count there
struct Source {
    dir: PathBuf,
    uid: u32,
    copies_only: bool,
    /// the owner every record in it must have
    owner: Option<u32>,
}

/// a record as it was read
pub struct Kept {
    pub head: Head,
    /// the run's result, a -H copy's cleaned. null when there was none
    pub result: Value,
    pub copy: bool,
}

impl Kept {
    /// the connection log: this machine's read with the strict types, a
    /// copy's with the lenient ones
    pub fn network(&self) -> Option<NetLog> {
        let n = self.result.get("network").filter(|n| !n.is_null())?;
        if self.copy {
            NetLog::lenient(n)
        } else {
            serde_json::from_value(n.clone()).ok()
        }
    }

    /// `run` in burner log --json: the head, and the result without the
    /// network, which is the top level there
    pub fn run_json(&self) -> Value {
        let mut v = serde_json::to_value(&self.head).unwrap_or(Value::Null);
        let mut r = self.result.clone();
        if let Some(o) = r.as_object_mut() {
            o.remove("network");
        }
        if v.is_object() {
            v["result"] = r;
        }
        v
    }
}

/// the runs the caller may see
pub struct Store {
    sources: Vec<Source>,
    /// this machine's own runs are in it (on linux they need root)
    pub this_machine: bool,
}

impl Store {
    pub fn open(cfg: &Config) -> Store {
        let mut sources = Vec::new();
        #[cfg(target_os = "linux")]
        let this_machine = crate::sys::is_root();
        #[cfg(target_os = "linux")]
        if this_machine {
            // through sudo it's the caller's runs; root itself sees every one
            let caller: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
            let logs = machine_dir(cfg);
            let dirs: Vec<(PathBuf, u32)> = match caller {
                Some(u) => vec![(logs.join(u.to_string()), u)],
                None => fs::read_dir(&logs)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter_map(|e| {
                        let u = e.file_name().to_str()?.parse().ok()?;
                        Some((e.path(), u))
                    })
                    .collect(),
            };
            for (dir, u) in dirs {
                sources.push(Source {
                    dir,
                    uid: 0,
                    copies_only: false,
                    owner: Some(u),
                });
            }
            // the caller's -H copies, read as root: only files they own
            if let Some(u) = caller
                && let Some(d) = state_home(u, true)
            {
                sources.push(Source {
                    dir: d.join("burner/logs"),
                    uid: u,
                    copies_only: true,
                    owner: Some(u),
                });
            }
        } else {
            // SAFETY: getuid can't fail
            let me = unsafe { libc::getuid() };
            if let Some(d) = copies_dir() {
                sources.push(Source {
                    dir: d,
                    uid: me,
                    copies_only: true,
                    owner: Some(me),
                });
            }
        }
        #[cfg(target_os = "macos")]
        let this_machine = {
            // SAFETY: getuid can't fail
            let me = unsafe { libc::getuid() };
            let here = machine_dir(cfg).join(me.to_string());
            sources.push(Source {
                dir: here.clone(),
                uid: me,
                copies_only: false,
                owner: Some(me),
            });
            if let Some(d) = copies_dir().filter(|d| *d != here) {
                sources.push(Source {
                    dir: d,
                    uid: me,
                    copies_only: false,
                    owner: Some(me),
                });
            }
            true
        };
        Store {
            sources,
            this_machine,
        }
    }

    #[cfg(test)]
    fn at(dirs: &[(&Path, bool)]) -> Store {
        // SAFETY: getuid can't fail
        let me = unsafe { libc::getuid() };
        Store {
            sources: dirs
                .iter()
                .map(|(d, copies_only)| Source {
                    dir: d.to_path_buf(),
                    uid: me,
                    copies_only: *copies_only,
                    owner: Some(me),
                })
                .collect(),
            this_machine: true,
        }
    }

    /// every record's file, newest first
    fn files(&self) -> Vec<(SystemTime, PathBuf, &Source)> {
        let mut v: Vec<_> = self
            .sources
            .iter()
            .flat_map(|s| records_in(&s.dir).into_iter().map(move |(t, p)| (t, p, s)))
            .collect();
        v.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
        v
    }

    /// the heads that pass `keep`, newest first, at most `limit`
    pub fn list(&self, keep: impl Fn(&Head) -> bool, limit: usize) -> Vec<Head> {
        self.files()
            .into_iter()
            .filter_map(|(_, p, s)| read(&p, s))
            .map(|k| k.head)
            .filter(|h| keep(h))
            .take(limit)
            .collect()
    }

    /// a run by id, this machine's before a -H copy with the same id; the
    /// newest one without an id
    pub fn find(&self, id: Option<&str>) -> Option<Kept> {
        if let Some(id) = id
            && !valid_id(id)
        {
            return None;
        }
        let mut hits: Vec<Kept> = Vec::new();
        for (_, p, s) in self.files() {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let matches = match (id, record_name(name)) {
                (Some(id), Some((i, _))) => i == id,
                (None, Some(_)) => true,
                (_, None) => false,
            };
            if !matches {
                continue;
            }
            if let Some(k) = read(&p, s) {
                if id.is_none() || !k.copy {
                    return Some(k);
                }
                hits.push(k);
            }
        }
        hits.into_iter().next()
    }
}

/// a record file: opened without following a link or blocking on a fifo,
/// a regular file `uid` owns, no bigger than a record gets
fn open_checked(path: &Path, uid: u32) -> Option<fs::File> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let m = f.metadata().ok()?;
    (m.is_file() && m.uid() == uid && m.len() <= RECORD_CAP as u64).then_some(f)
}

/// a record, checked whole: None for anything that isn't one. the wrong
/// owner, a head that doesn't fit its file name, a copy where only this
/// machine's runs are, a result that doesn't parse or is another run's
fn read(path: &Path, s: &Source) -> Option<Kept> {
    let (id, slug) = record_name(path.file_name()?.to_str()?)?;
    let copy = slug.is_some();
    if s.copies_only && !copy {
        return None;
    }
    let f = open_checked(path, s.uid)?;
    let mut b = Vec::new();
    f.take(RECORD_CAP as u64 + 1).read_to_end(&mut b).ok()?;
    if b.len() > RECORD_CAP {
        return None;
    }
    let nl = b
        .iter()
        .position(|&c| c == b'\n')
        .filter(|n| *n < HEAD_CAP)?;
    let hv: Value = serde_json::from_slice(&b[..nl]).ok()?;
    let head: Head = if copy {
        lenient_head(hv)?
    } else {
        serde_json::from_value(hv).ok()?
    };
    if head.id != id || head.host.is_some() != copy || s.owner.is_some_and(|o| head.owner != o) {
        return None;
    }
    let mut result: Value = serde_json::from_slice(&b[nl + 1..]).ok()?;
    if copy {
        // a far end's result, or none when the client decided how it ended
        clean(&mut result);
        let same = result.get("id").and_then(Value::as_str) == Some(id);
        if !(result.is_null() || result.is_object() && same) {
            return None;
        }
    } else {
        // burner's own: read with the types it was written from
        let r: RunResult = serde_json::from_value(result.clone()).ok()?;
        if r.id != id {
            return None;
        }
    }
    Some(Kept { head, result, copy })
}

/// a -H copy's head: written by a burner on this machine, maybe a newer
/// one, so the fields this one knows, cleaned and cut
fn lenient_head(mut v: Value) -> Option<Head> {
    clean(&mut v);
    let o = v.as_object_mut()?;
    let known = [
        "record",
        "burner",
        "id",
        "host",
        "shell",
        "command",
        "img",
        "net",
        "tag",
        "owner",
        "started_unix",
        "secs",
        "exit",
        "outcome",
        "rc",
        "allowed",
        "blocked",
    ];
    o.retain(|k, _| known.contains(&k.as_str()));
    let mut h: Head = serde_json::from_value(v).ok()?;
    h.burner = text(&h.burner, 32);
    h.host = h.host.map(|x| text(&x, 255));
    h.img = text(&h.img, 64);
    h.net = text(&h.net, 16);
    h.tag = h.tag.map(|x| text(&x, 64));
    h.outcome = text(&h.outcome, 32);
    h.command = command_of(&h.command);
    Some(h)
}

// ---- words ----

/// DEL and the C1 controls become ?, in every string and key: json escapes
/// the C0 ones, these it would pass on raw to a terminal
pub fn clean(v: &mut Value) {
    fn s(x: &str) -> String {
        x.chars()
            .map(|c| {
                if c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) {
                    '?'
                } else {
                    c
                }
            })
            .collect()
    }
    match v {
        Value::String(x) => *x = s(x),
        Value::Array(a) => a.iter_mut().for_each(clean),
        Value::Object(o) => {
            let old = std::mem::take(o);
            for (k, mut x) in old {
                clean(&mut x);
                o.insert(s(&k), x);
            }
        }
        _ => {}
    }
}

/// text for a head: control characters escaped, cut to `max` characters
fn text(s: &str, max: usize) -> String {
    let e = crate::output::escape_controls(s.as_bytes());
    String::from_utf8_lossy(&e).chars().take(max).collect()
}

/// the command line as it's kept: escaped (a newline too), then cut
fn command_of(cmd: &str) -> String {
    let one = cmd.replace('\n', "\\n");
    text(&one, COMMAND_CAP)
}

fn outcome_name(o: RunOutcome) -> String {
    match serde_json::to_value(o) {
        Ok(Value::String(s)) => s,
        _ => "sandbox_error".into(),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn round3(s: f64) -> f64 {
    if s.is_finite() {
        (s.max(0.0) * 1000.0).round() / 1000.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::record::{Timing, VmInfo};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("burner-runlog-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        make_dirs(&d).unwrap();
        d
    }

    fn head(id: &str, host: Option<&str>) -> Head {
        Head {
            record: RECORD,
            burner: "0.3.1".into(),
            id: id.into(),
            host: host.map(String::from),
            shell: false,
            command: "echo hi".into(),
            img: "alpine".into(),
            net: "none".into(),
            tag: None,
            // SAFETY: getuid can't fail
            owner: unsafe { libc::getuid() },
            started_unix: 1_795_000_000,
            secs: 1.5,
            exit: 0,
            outcome: "exited".into(),
            rc: Some(0),
            allowed: None,
            blocked: None,
        }
    }

    /// a result the way a run of this burner writes one
    fn result(id: &str, network: Option<Value>) -> Value {
        let r = RunResult {
            id: id.into(),
            outcome: RunOutcome::Exited,
            rc: Some(0),
            shell_end: None,
            guest_error: None,
            guest_result: None,
            secs: 1.5,
            timing_secs: Timing::default(),
            vm: Some(VmInfo {
                img: "alpine".into(),
                backend: "libkrun",
                vcpus: 1,
                mem_mib: 512,
                disk_gib: 2,
                ttl_secs: 600,
                net: "web",
                tag: None,
            }),
            output: None,
            result_tar: None,
            network: network.map(|n| serde_json::from_value(n).unwrap()),
            files: None,
            processes: None,
        };
        serde_json::to_value(r).unwrap()
    }

    fn log(id: &str) -> Value {
        serde_json::json!({
            "id": id, "net": "web", "platform": "linux", "owner": 1000, "started_unix": 1,
            "secs": 1.0, "complete": true, "lost": 0, "not_itemized": 0, "invalid": 0,
            "summary": {"allowed": 1, "blocked": 0, "blocked_attempts": 0, "dns": 0, "unknown": 0},
            "events": []
        })
    }

    fn id(i: usize) -> String {
        format!("burner-{i:012x}")
    }

    fn age(p: &Path, secs: u64) {
        let f = fs::File::options().write(true).open(p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(secs))
            .unwrap();
    }

    fn line(h: &Head, r: &Value) -> String {
        format!("{}\n{r}\n", serde_json::to_value(h).unwrap())
    }

    #[test]
    fn names() {
        assert_eq!(
            record_name("burner-0123456789ab.json"),
            Some(("burner-0123456789ab", None))
        );
        assert_eq!(
            record_name("burner-0123456789ab@mini.json"),
            Some(("burner-0123456789ab", Some("mini")))
        );
        for bad in [
            "burner-0123456789ab",
            "../../etc/passwd.json",
            "burner-0123456789ab@.json",
            "burner-0123456789ab@a/b.json",
            "burner-0123456789ab@a@b.json",
            "burner-0123456789ab.json.new",
        ] {
            assert!(record_name(bad).is_none(), "{bad}");
        }
        assert_eq!(slug("mini.tail1234.ts.net"), "mini.tail1234.ts.net");
        assert_eq!(slug("pat@mini"), "pat_40mini");
        // one name, one slug: these used to be the same file
        assert_ne!(slug("a@b"), slug("a_b"));
        let long = "x".repeat(200);
        let other = "x".repeat(199) + "y";
        assert!(slug(&long).len() <= SLUG_CAP && slug(&long) != slug(&other));
        assert!(slug("").starts_with("_h"));
        for h in ["pat@mini", "a b/c", "", &long, "é"] {
            let name = format!("burner-0123456789ab@{}.json", slug(h));
            assert!(record_name(&name).is_some(), "{name}");
        }
    }

    #[test]
    fn command_line_is_escaped_and_cut() {
        assert_eq!(command_of("a\nb\x1b[31m"), "a\\nb\\x1b[31m");
        let long = "é".repeat(400);
        assert_eq!(command_of(&long).chars().count(), COMMAND_CAP);
        assert_eq!(command_of("echo \u{9b}x"), "echo \\u{9b}x");
    }

    #[test]
    fn keeps_and_prunes_per_owner() {
        let d = tmp("prune");
        let keep = Log {
            keep_runs: 3,
            keep_days: 30,
        };
        for i in 0..5 {
            let r = result(&id(i), None);
            store(
                &d,
                &format!("{}.json", id(i)),
                &head(&id(i), None),
                &r,
                &keep,
            )
            .unwrap();
            age(&d.join(format!("{}.json", id(i))), 1000 - i as u64);
        }
        // a write that didn't finish, from long ago
        fs::write(d.join(format!("{}.json.new", id(9))), b"x").unwrap();
        age(&d.join(format!("{}.json.new", id(9))), 4000);
        prune_dir(&d, &keep);
        let left: Vec<String> = records_in(&d)
            .iter()
            .map(|(_, p)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, [id(4), id(3), id(2)].map(|i| format!("{i}.json")));
        assert!(!d.join(format!("{}.json.new", id(9))).exists());
        let mode = fs::metadata(d.join(format!("{}.json", id(4))))
            .unwrap()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // past keep_days goes, however few there are
        age(&d.join(format!("{}.json", id(2))), 31 * 86_400);
        prune_dir(&d, &keep);
        assert_eq!(records_in(&d).len(), 2);
        // 0 keeps none, and stores nothing
        let none = Log {
            keep_runs: 0,
            keep_days: 30,
        };
        let r = result(&id(7), None);
        store(
            &d,
            &format!("{}.json", id(7)),
            &head(&id(7), None),
            &r,
            &none,
        )
        .unwrap();
        assert!(records_in(&d).is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn reads_back_strict_and_lenient() {
        let d = tmp("read");
        let keep = Log::default();
        let mut l = log(&id(1));
        let r = result(&id(1), Some(l.clone()));
        store(
            &d,
            &format!("{}.json", id(1)),
            &head(&id(1), None),
            &r,
            &keep,
        )
        .unwrap();
        age(&d.join(format!("{}.json", id(1))), 100);
        // a copy from a newer far end: a field more in the log and the head
        l["report"] = "x".into();
        let copy = serde_json::json!({"id": id(1), "outcome": "exited", "rc": 0,
            "guest_error": "a\u{9b}b", "network": l});
        let mut h = head(&id(1), Some("mini"));
        h.exit = 3;
        store(&d, &format!("{}@mini.json", id(1)), &h, &copy, &keep).unwrap();
        let mut hv = serde_json::to_value(head(&id(2), Some("pi"))).unwrap();
        hv["newer"] = true.into();
        hv["img"] = "evil\u{9b}31m".into();
        fs::write(
            d.join(format!("{}@pi.json", id(2))),
            format!("{hv}\nnull\n"),
        )
        .unwrap();
        let s = Store::at(&[(&d, false)]);
        let all = s.list(|_| true, 10);
        assert_eq!(all.len(), 3, "{all:?}");
        assert_eq!(all[0].id, id(2));
        assert_eq!(all[0].img, "evil?31m");
        // by id: this machine's first
        let k = s.find(Some(&id(1))).unwrap();
        assert!(!k.copy && k.network().is_some());
        assert!(k.run_json()["result"].get("network").is_none());
        // a copy's log is read leniently and cleaned
        let s2 = Store::at(&[(&d, true)]);
        assert!(s2.list(|h| h.host.is_none(), 10).is_empty(), "copies only");
        let k = s2.find(Some(&id(1))).unwrap();
        assert!(k.copy && k.head.exit == 3);
        assert_eq!(k.network().unwrap().summary.allowed, 1);
        assert_eq!(k.result["guest_error"], "a?b");
        assert!(s.find(Some("../../etc/passwd")).is_none());
        // the newest without an id
        assert_eq!(s.find(None).unwrap().head.id, id(2));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_what_isnt_a_record() {
        let d = tmp("refuse");
        let keep = Log::default();
        let good = |i: usize| line(&head(&id(i), None), &result(&id(i), None));
        // a link to a record is never followed
        let target = d.join("target");
        fs::write(&target, good(1)).unwrap();
        std::os::unix::fs::symlink(&target, d.join(format!("{}.json", id(1)))).unwrap();
        // a head that names another run than its file, or claims to be from
        // here in a copy's name, or is strict and has a field too many
        fs::write(d.join(format!("{}.json", id(2))), good(1)).unwrap();
        fs::write(d.join(format!("{}@x.json", id(1))), good(1)).unwrap();
        let mut extra = serde_json::to_value(head(&id(3), None)).unwrap();
        extra["x"] = 1.into();
        let r3 = result(&id(3), None);
        fs::write(
            d.join(format!("{}.json", id(3))),
            format!("{extra}\n{r3}\n"),
        )
        .unwrap();
        // a fifo would hang a reader that blocks
        let fifo = std::ffi::CString::new(
            d.join(format!("{}.json", id(4)))
                .as_os_str()
                .as_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: mkfifo on a path we made
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // too big
        let mut big = good(5).into_bytes();
        big.resize(RECORD_CAP + 10, b' ');
        fs::write(d.join(format!("{}.json", id(5))), big).unwrap();
        // a result cut short, one that's another run's, one this burner
        // didn't write (a field too many, a backend it doesn't have)
        let g = good(6);
        fs::write(d.join(format!("{}.json", id(6))), &g[..g.len() - 20]).unwrap();
        let other = line(&head(&id(7), None), &result(&id(8), None));
        fs::write(d.join(format!("{}.json", id(7))), other).unwrap();
        let mut odd = result(&id(8), None);
        odd["report"] = 1.into();
        fs::write(
            d.join(format!("{}.json", id(8))),
            line(&head(&id(8), None), &odd),
        )
        .unwrap();
        let mut vmm = result(&id(9), None);
        vmm["vm"]["backend"] = "qemu".into();
        fs::write(
            d.join(format!("{}.json", id(9))),
            line(&head(&id(9), None), &vmm),
        )
        .unwrap();
        // a copy whose result is another run's
        let wrong = line(&head(&id(10), Some("x")), &result(&id(11), None));
        fs::write(d.join(format!("{}@x.json", id(10))), wrong).unwrap();
        let s = Store::at(&[(&d, false)]);
        assert!(
            s.list(|_| true, 20).is_empty(),
            "{:?}",
            s.list(|_| true, 20)
        );
        assert!(s.find(None).is_none());
        // and the same written by store is fine
        let r = result(&id(12), None);
        store(
            &d,
            &format!("{}.json", id(12)),
            &head(&id(12), None),
            &r,
            &keep,
        )
        .unwrap();
        assert_eq!(s.list(|_| true, 20).len(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cleans_every_string() {
        let mut v = serde_json::json!({"a\u{85}": ["x\u{7f}", {"b": "\u{9b}"}], "n": 1});
        clean(&mut v);
        assert_eq!(v, serde_json::json!({"a?": ["x?", {"b": "?"}], "n": 1}));
    }
}
