//! the result disk is a raw tar written by the guest, so it's hostile input.
//! it's read by a separate burner process running as its own unprivileged user
//! with hard rlimits, one at a time, and only regular files and directories
//! come back. any cap hit or missing exit code makes the whole result invalid.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::sys;

pub const RESULT_SIZE: u64 = 256 << 20;
pub const LOG_CAP: u64 = 16 << 20;
const MEMBERS: u32 = 20_000;
const PARSE_TIMEOUT: Duration = Duration::from_secs(120);
pub const PARSE_ARG: &str = "__parse-result";
/// the parser's own account, so a parser bug can't touch what the VM's user owns
pub const PARSE_USER: &str = "burner-parse";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    pub rc: Option<i32>,
    pub problem: Option<String>,
    pub skipped: u64,
    pub fatal: bool,
}

/// parent side: parse the already-open result disk in a limited child, write the
/// log and (optionally) a clean tar
pub fn parse(raw: File, log: &Path, tar_out: Option<&Path>, state: &Path) -> Meta {
    match parse_inner(raw, log, tar_out, state) {
        Ok(m) => m,
        Err(e) => Meta {
            problem: Some(format!("result unreadable ({e})")),
            fatal: true,
            ..Meta::default()
        },
    }
}

fn parse_inner(raw: File, log: &Path, tar_out: Option<&Path>, state: &Path) -> io::Result<Meta> {
    let (uid, gid) = sys::user_ids(PARSE_USER)
        .ok_or_else(|| io::Error::other(format!("no {PARSE_USER} user, rerun install.sh")))?;
    if raw.metadata()?.len() > RESULT_SIZE {
        return Err(io::Error::other("result disk larger than expected"));
    }
    // one parser at a time keeps the host-side memory budget to one rlimit
    let deadline = Instant::now() + PARSE_TIMEOUT;
    let _lock = sys::Lock::exclusive_until(&state.join("parse.lock"), deadline)?;
    let new = || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .clone()
    };
    let logf = new().open(log)?;
    let tarf = match tar_out {
        Some(p) => new().open(p)?,
        None => OpenOptions::new().write(true).open("/dev/null")?,
    };
    // staged above 10 so moving them to 3 and 4 in the child can't clobber each other
    let log_fd = sys::dup_above(logf.as_raw_fd(), 10)?;
    let tar_fd = sys::dup_above(tarf.as_raw_fd(), 10)?;
    let (l, t) = (log_fd.as_raw_fd(), tar_fd.as_raw_fd());
    // the running binary itself, not its path: an upgrade while VMs run replaces
    // the file, and the old path would then point at nothing
    let mut cmd = Command::new("/proc/self/exe");
    cmd.arg(PARSE_ARG)
        .arg(if tar_out.is_some() { "1" } else { "0" })
        .stdin(Stdio::from(raw))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .current_dir("/")
        .uid(uid)
        .gid(gid);
    // SAFETY: dup2 and setrlimit only, both async-signal-safe on linux
    unsafe {
        cmd.pre_exec(move || {
            sys::dup_to(l, 3)?;
            sys::dup_to(t, 4)?;
            sys::limit_child(&[
                (libc::RLIMIT_AS, 512 << 20),
                (libc::RLIMIT_CPU, 30),
                (libc::RLIMIT_FSIZE, RESULT_SIZE + (8 << 20)),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_NOFILE, 16),
                (libc::RLIMIT_NPROC, 0),
            ])
        });
    }
    let mut child = cmd.spawn()?;
    drop((logf, tarf, log_fd, tar_fd));
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("parser timed out"));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        so.by_ref().take(64 << 10).read_to_string(&mut out)?;
    }
    if !status.success() {
        return Err(io::Error::other("parser failed"));
    }
    let mut meta: Meta =
        serde_json::from_str(&out).map_err(|_| io::Error::other("parser gave no answer"))?;
    meta.rc = meta.rc.filter(|rc| (0..=255).contains(rc));
    meta.problem = meta.problem.map(|p| {
        p.chars()
            .take(300)
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    });
    if meta.rc.is_none() && !meta.fatal {
        meta.fatal = true;
        meta.problem
            .get_or_insert_with(|| "the VM gave no exit code".into());
    }
    if meta.fatal {
        meta.rc = None;
    }
    Ok(meta)
}

/// child side: fd 0 the raw tar, fd 3 the log, fd 4 the clean tar. refuses to
/// run as root or with anything else wired to those fds
pub fn child_main(emit: bool) -> ExitCode {
    // SAFETY: geteuid has no preconditions
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("burner: {PARSE_ARG} is internal and never runs as root");
        return ExitCode::from(2);
    }
    let fd_ok = |fd: i32, devnull_ok: bool| -> bool {
        // SAFETY: zeroed stat is a valid out-parameter; fstat on any int is safe
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return false;
        }
        let kind = st.st_mode & libc::S_IFMT;
        kind == libc::S_IFREG || (devnull_ok && kind == libc::S_IFCHR)
    };
    if !(fd_ok(0, false) && fd_ok(3, false) && fd_ok(4, true)) {
        eprintln!("burner: {PARSE_ARG} is internal, run by burner run");
        return ExitCode::from(2);
    }
    // SAFETY: checked above that these are open files we were handed
    let (src, logf, tarf) = unsafe {
        (
            File::from_raw_fd(0),
            File::from_raw_fd(3),
            OwnedFd::from_raw_fd(4),
        )
    };
    let tarf = File::from(tarf);
    if tarf
        .metadata()
        .is_ok_and(|m| m.file_type().is_char_device())
        && emit
    {
        return ExitCode::from(2);
    }
    let mut meta = Meta::default();
    let mut out = emit.then(|| {
        tar::Builder::new(Capped {
            f: tarf,
            cap: RESULT_SIZE + (4 << 20),
            n: 0,
        })
    });
    if let Err(e) = walk(src, logf, out.as_mut(), &mut meta) {
        meta.problem = Some(e.to_string());
        meta.fatal = true;
    }
    if let Some(b) = out
        && b.into_inner().is_err()
    {
        meta.problem
            .get_or_insert_with(|| "result too large to return".into());
        meta.fatal = true;
    }
    println!("{}", serde_json::to_string(&meta).unwrap_or_default());
    ExitCode::SUCCESS
}

fn fatal(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

fn walk(
    src: File,
    mut logf: File,
    mut out: Option<&mut tar::Builder<Capped>>,
    meta: &mut Meta,
) -> io::Result<()> {
    let mut ar = tar::Archive::new(BufReader::with_capacity(1 << 16, src));
    let (mut count, mut total, mut logged) = (0u32, 0u64, 0u64);
    let mut seen = HashSet::new();
    for e in ar
        .entries()
        .map_err(|e| fatal(&format!("result unreadable ({e})")))?
    {
        let mut e = e.map_err(|e| fatal(&format!("result unreadable ({e})")))?;
        count += 1;
        if count > MEMBERS {
            return Err(fatal("result has too many entries"));
        }
        let kind = e.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            continue;
        }
        let Some(name) = clean_name(&e.path()?) else {
            meta.problem = Some("result had unsafe entries, dropped".into());
            continue;
        };
        if !seen.insert(name.clone()) {
            meta.problem = Some(format!("result had {name} twice, kept the first"));
            continue;
        }
        let mtime = e.header().mtime().unwrap_or(0).min(1 << 33);
        if kind.is_dir() {
            if let Some(b) = out.as_deref_mut()
                && (name == "out" || name.starts_with("out/"))
            {
                let mut h = header(tar::EntryType::Directory, 0o755, 0, mtime);
                b.append_data(&mut h, &name, io::empty())?;
            }
            continue;
        }
        let size = e.size();
        total = total
            .checked_add(size)
            .filter(|t| *t <= RESULT_SIZE)
            .ok_or_else(|| fatal("result over the size cap"))?;
        match name.as_str() {
            "result/rc" if size <= 8 => meta.rc = read_small(&mut e)?.trim().parse().ok(),
            "result/log_skipped" if size <= 20 => {
                meta.skipped = read_small(&mut e)?.trim().parse().unwrap_or(0)
            }
            "result/error" if size <= 1000 => {
                meta.problem = Some(read_small(&mut e)?.trim().to_string())
            }
            "result/log.txt" => {
                logged = logged
                    .checked_add(size)
                    .filter(|l| *l <= LOG_CAP)
                    .ok_or_else(|| fatal("log over the cap"))?;
                let mut buf = Vec::with_capacity(size as usize);
                e.read_to_end(&mut buf)?;
                logf.write_all(&buf)?;
                if let Some(b) = out.as_deref_mut() {
                    let mut h = header(tar::EntryType::Regular, 0o644, size, mtime);
                    b.append_data(&mut h, "log.txt", buf.as_slice())?;
                }
            }
            n if n.starts_with("out/") => {
                if let Some(b) = out.as_deref_mut() {
                    let mode = if e.header().mode().unwrap_or(0) & 0o111 != 0 {
                        0o755
                    } else {
                        0o644
                    };
                    let mut h = header(tar::EntryType::Regular, mode, size, mtime);
                    b.append_data(&mut h, n, &mut e)?;
                }
            }
            _ => {}
        }
        if name == "result/rc"
            && let (Some(b), Some(rc)) = (out.as_deref_mut(), meta.rc)
        {
            let body = format!("{rc}\n");
            let mut h = header(tar::EntryType::Regular, 0o644, body.len() as u64, mtime);
            b.append_data(&mut h, "rc", body.as_bytes())?;
        }
    }
    logf.flush()
}

fn read_small(e: &mut impl Read) -> io::Result<String> {
    let mut s = String::new();
    e.take(1024).read_to_string(&mut s)?;
    Ok(s)
}

fn header(kind: tar::EntryType, mode: u32, size: u64, mtime: u64) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(kind);
    h.set_mode(mode);
    h.set_size(size);
    h.set_mtime(mtime);
    h
}

/// a relative path made only of normal parts, or None
fn clean_name(p: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str()?),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let name = parts.join("/");
    (!name.is_empty() && name.len() <= 1024).then_some(name)
}

struct Capped {
    f: File,
    cap: u64,
    n: u64,
}

impl Write for Capped {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.n += b.len() as u64;
        if self.n > self.cap {
            return Err(io::Error::other("output cap"));
        }
        self.f.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.f.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            clean_name(Path::new("out/a/b.txt")).as_deref(),
            Some("out/a/b.txt")
        );
        assert_eq!(
            clean_name(Path::new("./result/rc")).as_deref(),
            Some("result/rc")
        );
        assert_eq!(clean_name(Path::new("../x")), None);
        assert_eq!(clean_name(Path::new("out/../../x")), None);
        assert_eq!(clean_name(Path::new("/etc/passwd")), None);
        assert_eq!(clean_name(Path::new(".")), None);
    }
}
