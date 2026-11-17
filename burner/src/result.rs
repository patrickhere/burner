//! the result disk is a raw tar written by the guest, so it's hostile input.
//! it's read by a separate burner process running as the unprivileged burner
//! user with hard rlimits, and only regular files and directories come back.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Meta {
    pub rc: Option<i32>,
    pub problem: Option<String>,
    pub skipped: u64,
    pub fatal: bool,
}

/// parent side: parse `raw` in a limited child, write the log and (optionally) a clean tar
pub fn parse(raw: &Path, log: &Path, tar_out: Option<&Path>, uid: u32, gid: u32) -> Meta {
    match parse_inner(raw, log, tar_out, uid, gid) {
        Ok(m) => m,
        Err(e) => Meta {
            problem: Some(format!("result unreadable ({e})")),
            fatal: true,
            ..Meta::default()
        },
    }
}

fn parse_inner(
    raw: &Path,
    log: &Path,
    tar_out: Option<&Path>,
    uid: u32,
    gid: u32,
) -> io::Result<Meta> {
    let raw = File::open(raw)?;
    if raw.metadata()?.len() > RESULT_SIZE {
        return Err(io::Error::other("result disk larger than expected"));
    }
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
    let (log_fd, tar_fd) = (logf.as_raw_fd(), tarf.as_raw_fd());
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg(PARSE_ARG)
        .arg(if tar_out.is_some() { "1" } else { "0" })
        .stdin(Stdio::from(raw))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .current_dir("/")
        .uid(uid)
        .gid(gid);
    // SAFETY: only async-signal-safe calls between fork and exec
    unsafe {
        cmd.pre_exec(move || {
            sys::dup_to(log_fd, 3)?;
            sys::dup_to(tar_fd, 4)?;
            sys::limit_child(&[
                (libc::RLIMIT_AS, 768 << 20),
                (libc::RLIMIT_CPU, 60),
                (libc::RLIMIT_FSIZE, RESULT_SIZE + (8 << 20)),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_NOFILE, 32),
            ])
        });
    }
    let mut child = cmd.spawn()?;
    drop((logf, tarf));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() > PARSE_TIMEOUT {
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
    if meta.fatal {
        meta.rc = None;
    }
    Ok(meta)
}

/// child side, as user burner: fd 0 the raw tar, fd 3 the log, fd 4 the clean tar
pub fn child_main(emit: bool) -> ExitCode {
    let mut meta = Meta::default();
    // SAFETY: the parent set up exactly these fds before exec
    let (src, logf, tarf) = unsafe {
        (
            File::from_raw_fd(0),
            File::from_raw_fd(3),
            File::from_raw_fd(4),
        )
    };
    let mut out = emit.then(|| {
        tar::Builder::new(Capped {
            f: tarf,
            cap: RESULT_SIZE + (4 << 20),
            n: 0,
        })
    });
    if let Err(e) = walk(src, logf, out.as_mut(), &mut meta) {
        meta.problem = Some(format!("result unreadable ({e})"));
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

fn walk(
    src: File,
    mut logf: File,
    mut out: Option<&mut tar::Builder<Capped>>,
    meta: &mut Meta,
) -> io::Result<()> {
    let mut ar = tar::Archive::new(BufReader::with_capacity(1 << 16, src));
    let (mut count, mut total, mut logged) = (0u32, 0u64, 0u64);
    let mut seen = HashSet::new();
    for e in ar.entries()? {
        let mut e = e?;
        count += 1;
        if count > MEMBERS {
            meta.problem = Some("result has too many entries, rest dropped".into());
            break;
        }
        let kind = e.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            continue;
        }
        let Some(name) = clean_name(&e.path()?) else {
            meta.problem = Some("result had unsafe entries, dropped".into());
            continue;
        };
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
        if name.starts_with("result/") && !seen.insert(name.clone()) {
            continue; // one of each result field, the first wins
        }
        let size = e.size();
        total += size;
        if total > RESULT_SIZE {
            meta.problem = Some("result over the size cap, rest dropped".into());
            break;
        }
        match name.as_str() {
            "result/rc" if size <= 8 => meta.rc = read_small(&mut e)?.trim().parse().ok(),
            "result/log_skipped" if size <= 20 => {
                meta.skipped = read_small(&mut e)?.trim().parse().unwrap_or(0)
            }
            "result/error" if size <= 1000 => {
                meta.problem = Some(read_small(&mut e)?.trim().to_string())
            }
            "result/log.txt" if logged + size <= LOG_CAP => {
                let mut buf = Vec::with_capacity(size as usize);
                e.read_to_end(&mut buf)?;
                logf.write_all(&buf)?;
                logged += size;
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
