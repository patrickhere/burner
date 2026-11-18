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
    /// the guest reported a failure of its own (log capture, result write):
    /// the run fails even if the command succeeded
    #[serde(default)]
    pub guest_error: bool,
    /// the guest init's protocol number, from result/proto
    #[serde(default)]
    pub proto: Option<u32>,
    /// the guest stopped the job at its time limit and still wrote results
    #[serde(default)]
    pub timed_out: bool,
}

/// reads exactly `left` bytes or fails: a member whose body runs past the end
/// of the disk would otherwise come out short and padded
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Ok(0);
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(fatal("result cut off inside a file"));
        }
        self.left -= n as u64;
        Ok(n)
    }
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
    let mut src = src;
    if let Err(e) = prescan(&mut src).and_then(|()| walk(src, logf, out.as_mut(), &mut meta)) {
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

/// a first pass over the raw headers before the tar crate sees them: only the
/// entry types busybox tar writes, small long-name and pax records, a bounded
/// number of headers, and every size in range. the crate would otherwise load
/// extension records and sparse maps before any of burner's limits apply
fn prescan(src: &mut File) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let len = src.metadata()?.len().min(RESULT_SIZE);
    let (mut off, mut headers) = (0u64, 0u32);
    let mut h = [0u8; 512];
    while off + 512 <= len {
        src.seek(SeekFrom::Start(off))?;
        src.read_exact(&mut h)?;
        if h.iter().all(|&b| b == 0) {
            break; // end of archive
        }
        headers += 1;
        if headers > MEMBERS * 3 {
            return Err(fatal("result has too many headers"));
        }
        let size = octal(&h[124..136]).ok_or_else(|| fatal("result header has a bad size"))?;
        let max = match h[156] {
            b'0' | 0 | b'7' => RESULT_SIZE,
            b'1' | b'2' | b'3' | b'4' | b'5' | b'6' => 0,
            b'L' | b'K' => 4096,
            b'x' => 64 << 10,
            t => {
                return Err(fatal(&format!(
                    "result has a tar entry of type {:?}",
                    t as char
                )));
            }
        };
        if size > max {
            return Err(fatal("result has an oversized tar header"));
        }
        // a pax record can override the next member's size, which would make this
        // pass and the tar crate disagree about where members start
        if h[156] == b'x' {
            let mut rec = vec![0u8; size as usize];
            src.read_exact(&mut rec)?;
            if rec
                .split(|&b| b == b'\n')
                .any(|l| l.windows(6).any(|w| w == b" size="))
            {
                return Err(fatal("result has a pax size override"));
            }
        }
        off = size
            .div_ceil(512)
            .checked_mul(512)
            .and_then(|b| off.checked_add(512 + b))
            .filter(|o| *o <= len)
            .ok_or_else(|| fatal("result tar runs past the end of the disk"))?;
    }
    src.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// a tar size field: octal digits, padded with spaces or NULs. base-256 sizes
/// are only needed past 8G and get refused
fn octal(f: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(f)
        .ok()?
        .trim_matches(|c| c == ' ' || c == '\0');
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

fn walk(
    src: File,
    mut logf: File,
    mut out: Option<&mut tar::Builder<Capped>>,
    meta: &mut Meta,
) -> io::Result<()> {
    let mut ar = tar::Archive::new(BufReader::with_capacity(1 << 16, src));
    let (mut count, mut total, mut logged) = (0u32, 0u64, 0u64);
    let (mut seen, mut files, mut dirs) = (HashSet::new(), HashSet::new(), HashSet::new());
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
        // twice the same path, or a file where another entry needs a directory,
        // can't be unpacked as one tree: not a result burner hands back
        if !seen.insert(name.clone()) {
            return Err(fatal(&format!("result has {name} twice")));
        }
        let parents: Vec<String> = name
            .match_indices('/')
            .map(|(i, _)| name[..i].to_string())
            .collect();
        if parents.iter().any(|p| files.contains(p)) || (kind.is_file() && dirs.contains(&name)) {
            return Err(fatal(&format!(
                "result has {name} both as a file and a directory"
            )));
        }
        dirs.extend(parents);
        if kind.is_file() {
            files.insert(name.clone());
        } else {
            dirs.insert(name.clone());
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
            "result/proto" if size <= 8 => meta.proto = read_small(&mut e)?.trim().parse().ok(),
            "result/timed_out" => meta.timed_out = true,
            "result/log_skipped" if size <= 20 => {
                meta.skipped = read_small(&mut e)?.trim().parse().unwrap_or(0)
            }
            "result/error" if size <= 1000 => {
                meta.problem = Some(read_small(&mut e)?.trim().to_string());
                meta.guest_error = true;
            }
            "result/log.txt" => {
                logged = logged
                    .checked_add(size)
                    .filter(|l| *l <= LOG_CAP)
                    .ok_or_else(|| fatal("log over the cap"))?;
                let mut buf = Vec::with_capacity(size as usize);
                Exact {
                    inner: &mut e,
                    left: size,
                }
                .read_to_end(&mut buf)?;
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
                    b.append_data(
                        &mut h,
                        n,
                        Exact {
                            inner: &mut e,
                            left: size,
                        },
                    )?;
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
    use std::fs;

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

    fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, body) in entries {
            let mut h = tar::Header::new_ustar();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, name, *body).unwrap();
        }
        b.into_inner().unwrap()
    }

    fn walk_bytes(bytes: &[u8]) -> io::Result<Meta> {
        let dir = std::env::temp_dir().join(format!("burner-walk-{}", sys::random_hex(6)?));
        fs::create_dir(&dir)?;
        fs::write(dir.join("raw"), bytes)?;
        let mut meta = Meta::default();
        let mut src = File::open(dir.join("raw"))?;
        let res = prescan(&mut src)
            .and_then(|()| walk(src, File::create(dir.join("log"))?, None, &mut meta));
        let _ = fs::remove_dir_all(&dir);
        res.map(|()| meta)
    }

    #[test]
    fn result_trees() {
        let ok = walk_bytes(&tar_of(&[("result/rc", b"3\n"), ("out/a/b", b"x")])).unwrap();
        assert_eq!(ok.rc, Some(3));
        assert!(walk_bytes(&tar_of(&[("out/a", b"x"), ("out/a/b", b"y")])).is_err());
        assert!(walk_bytes(&tar_of(&[("out/a/b", b"y"), ("out/a", b"x")])).is_err());
        assert!(walk_bytes(&tar_of(&[("out/a", b"x"), ("out/a", b"y")])).is_err());
        let err = walk_bytes(&tar_of(&[("result/rc", b"0\n"), ("result/error", b"boom")])).unwrap();
        assert!(err.guest_error);
    }

    fn with_type(t: tar::EntryType, size: u64) -> Vec<u8> {
        let mut h = tar::Header::new_gnu();
        h.set_path("out/x").unwrap();
        h.set_entry_type(t);
        h.set_size(size);
        h.set_cksum();
        let mut v = h.as_bytes().to_vec();
        v.resize(512 + size.div_ceil(512) as usize * 512 + 1024, 0);
        v
    }

    #[test]
    fn prescan_types() {
        assert!(walk_bytes(&with_type(tar::EntryType::GNUSparse, 0)).is_err());
        assert!(walk_bytes(&with_type(tar::EntryType::XGlobalHeader, 10)).is_err());
        assert!(walk_bytes(&with_type(tar::EntryType::GNULongName, 100_000)).is_err());
        assert!(walk_bytes(&with_type(tar::EntryType::Regular, 10)).is_ok());
        // a long name, as busybox tar writes it
        let long = format!("out/{}", "d/".repeat(80) + "f");
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        b.append_data(&mut h, &long, &b"z"[..]).unwrap();
        assert!(walk_bytes(&b.into_inner().unwrap()).is_ok());
    }

    #[test]
    fn pax_size_override() {
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("size", &b"5"[..])]).unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(1);
        b.append_data(&mut h, "out/x", &b"z"[..]).unwrap();
        assert!(walk_bytes(&b.into_inner().unwrap()).is_err());
        // a pax record without a size (long names, mtimes) still passes
        let mut b = tar::Builder::new(Vec::new());
        b.append_pax_extensions([("mtime", &b"1700000000.5"[..])])
            .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_size(1);
        b.append_data(&mut h, "out/x", &b"z"[..]).unwrap();
        assert!(walk_bytes(&b.into_inner().unwrap()).is_ok());
    }

    #[test]
    fn cut_off_body() {
        let full = tar_of(&[("result/log.txt", &[b'a'; 4000])]);
        // header plus part of the body: the member claims more than the disk has
        assert!(walk_bytes(&full[..512 + 1000]).is_err());
    }
}
