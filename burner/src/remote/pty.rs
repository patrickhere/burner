//! `burner -H HOST shell`: the laptop keeps the terminal. ssh runs on a pty
//! of burner's own, so its prompts, raw mode and window size work as they do
//! on a terminal, and every byte passes burner both ways. keys go through the
//! ~ escape here: `~.` leaves however stuck or hostile the far end is. what
//! comes back goes through the record parser and the same terminal filter a
//! local shell uses, and the terminal is reset at the end from what was
//! really written to it

use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::client::{self, Conn, End, Failed, Seen};
use super::frame::Frames;
use super::hosts::Host;
use super::ssh::{Mode, Opts};
use crate::exit::{EXIT_INTERRUPTED, EXIT_SANDBOX};
use crate::json::{self, Kind, Problem};
use crate::output::{Out, TERM_RESET, TermFilter, term_utf8};
use crate::run::record::{self, RunOutcome};
use crate::run::{Escape, RunArgs};
use crate::sys;

/// keys for a far end that isn't taking them; past this they're dropped
const TO_PTY_CAP: usize = 1 << 20;
/// bytes held as a possible record marker go out after this much quiet. a
/// marker split over a slow link comes together well within it; text that
/// only looks like the start of one waits that long to show
const HELD_QUIET: Duration = Duration::from_secs(1);

enum Ended {
    /// ssh went: the far end ended the session, or the connection did
    Closed,
    /// ~. here
    Detached,
    /// a signal here
    Interrupted,
}

fn read_some(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: read(2) into a live buffer
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn write_some(fd: i32, b: &[u8]) -> io::Result<usize> {
    // SAFETY: write(2) of a live buffer
    let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

fn would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// ssh on the slave side of a new pty, as its controlling terminal
fn start(c: &Conn, args: &[String]) -> Result<(Child, OwnedFd), Failed> {
    let mut cmd = c.command(
        Opts {
            tty: true,
            ..Default::default()
        },
        Mode::Auto,
        args,
    )?;
    let size = sys::term_size(1).unwrap_or((24, 80));
    let io_err = |e: io::Error| Failed {
        kind: Kind::Io,
        msg: format!("no pty for ssh: {e}"),
    };
    let (master, slave) = sys::openpty(size).map_err(io_err)?;
    let (s_in, s_out) = (
        slave.try_clone().map_err(io_err)?,
        slave.try_clone().map_err(io_err)?,
    );
    cmd.stdin(Stdio::from(s_in))
        .stdout(Stdio::from(s_out))
        .stderr(Stdio::piped());
    // SAFETY: setsid and ioctl only, both async-signal-safe
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            #[allow(clippy::useless_conversion)]
            if libc::ioctl(0, libc::TIOCSCTTY.into(), 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| Failed {
        kind: Kind::Io,
        msg: format!("can't run ssh: {e}"),
    })?;
    drop(slave);
    Ok((child, master))
}

pub fn shell(host: &Host, a: &RunArgs, config: &[String]) -> ExitCode {
    json::set_host(&host.name);
    crate::run::catch_signals();
    let t0 = Instant::now();
    if let Some(code) = crate::run::check_fds(a, t0) {
        return code;
    }
    if !(sys::is_tty(0) && sys::is_tty(1)) {
        return crate::run::refuse(
            a,
            Kind::NoTty,
            "burner shell needs a terminal (over ssh: ssh -t)".into(),
        );
    }
    if let Err(msg) = a.check_local() {
        return crate::run::refuse(a, Kind::Usage, msg);
    }
    let gone = |o: RunOutcome, f: Failed| {
        client::finish_run_with_id(
            a,
            t0,
            End {
                code: EXIT_SANDBOX,
                env: None,
                raw: None,
                failed: Some((o, f)),
            },
            &host.name,
            None,
        )
    };
    let c = match Conn::open(host) {
        Ok(c) => c,
        Err(f) => return gone(RunOutcome::Unreachable, f),
    };
    let skipped: Vec<String> = c
        .pick
        .skipped
        .iter()
        .map(|(a, why)| format!("{a} {why}"))
        .collect();
    if skipped.is_empty() {
        eprintln!("burner: {} via {}", host.name, c.pick.addr);
    } else {
        eprintln!(
            "burner: {} via {} ({})",
            host.name,
            c.pick.addr,
            skipped.join(", ")
        );
    }
    let args = client::with_config(a.remote_argv(&c.nonce, false), config);
    let (mut child, master) = match start(&c, &args) {
        Ok(x) => x,
        Err(f) if f.kind == Kind::Usage => return crate::run::refuse(a, Kind::Usage, f.msg),
        Err(f) => return gone(RunOutcome::Unreachable, f),
    };
    sys::restore_tty_on_panic(TERM_RESET);
    let _ = sys::set_raw(0);
    let seen = Arc::new(Mutex::new(Seen::default()));
    // ssh's own words: they go in burner's message, or out after the session
    let errs = child.stderr.take().map(|mut e| {
        let seen = seen.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = e.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut s = seen.lock().unwrap_or_else(|e| e.into_inner());
                let room = (8usize << 10).saturating_sub(s.pre.len());
                s.pre.extend_from_slice(&buf[..n.min(room)]);
            }
        })
    });
    let screen = Out::new_screen();
    let ended = relay(&mut child, master, &c.nonce, &seen, &screen);
    // whatever the far end left on the screen is undone from what was really
    // written, and the terminal comes back before any message
    screen.finish_reset();
    let quick = Instant::now() + Duration::from_secs(2);
    screen.wait_last(|| Instant::now() > quick);
    sys::restore_saved_tty();
    let st = stop_ssh(&mut child, matches!(ended, Ended::Closed));
    if let Some(h) = errs {
        client::join_until(h, Instant::now() + client::READERS_GRACE);
    }
    let s = seen.lock().unwrap_or_else(|e| e.into_inner());
    let id = s.start.clone();
    let name = &host.name;
    let end = match ended {
        Ended::Detached => {
            let msg = format!("left the shell, the VM on {name} stops with it");
            eprintln!("burner: {msg}");
            let fin = record::client_end(
                t0,
                0,
                RunOutcome::Detached,
                id.as_deref(),
                Problem {
                    kind: Kind::Shell,
                    message: msg,
                },
            );
            return detached(a, fin);
        }
        Ended::Interrupted => End {
            code: EXIT_INTERRUPTED,
            env: None,
            raw: None,
            failed: Some((
                RunOutcome::Interrupted,
                Failed {
                    kind: Kind::Interrupted,
                    msg: match &id {
                        Some(id) => format!("interrupted, {id} on {name} stops with the session"),
                        None => format!("interrupted, nothing started on {name}"),
                    },
                },
            )),
        },
        Ended::Closed => {
            let code = st.as_ref().and_then(client::exit_of);
            let end = client::decide(&c, &s, code, "shell");
            // ssh's own last words (connection closed, broken pipe) are worth
            // seeing when the session didn't end the normal way
            if end.failed.is_some() && (s.wrap.is_some() || s.nobin.is_some()) && !s.pre.is_empty()
            {
                let t = crate::output::escape_controls(&s.pre);
                eprint!("{}", String::from_utf8_lossy(&t));
            }
            end
        }
    };
    drop(s);
    client::finish_run_with_id(a, t0, end, name, id.as_deref())
}

/// a shell left with ~.: exit 0, the json says detached
fn detached(a: &RunArgs, mut fin: record::Finished) -> ExitCode {
    // leaving is how a shell ends fine: the reason is a warning, not an error
    if let Some(p) = fin.reason.take() {
        json::note_warning(p.kind, p.message, false);
    }
    crate::run::finished(a, fin)
}

/// ssh after the session: gone already when it ended the session itself.
/// after ~. or a signal the pty is closed, which hangs it up, and it gets
/// a few seconds before it's killed
fn stop_ssh(child: &mut Child, closed: bool) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + Duration::from_secs(if closed { 10 } else { 3 });
    let mut termed = false;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) => {}
            Err(_) => return None,
        }
        if Instant::now() > until {
            if termed {
                let _ = child.kill();
                return child.wait().ok();
            }
            // SAFETY: kill(2) on our own child, not reaped yet
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            termed = true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// whether burner's wrapper on the far end has said anything yet
fn answered(seen: &Arc<Mutex<Seen>>) -> bool {
    let s = seen.lock().unwrap_or_else(|e| e.into_inner());
    s.wrap.is_some() || s.nobin.is_some()
}

/// copies bytes both ways until ssh goes, ~. is typed or a signal comes.
/// the master is dropped on the way out, which hangs ssh up
fn relay(
    child: &mut Child,
    master: OwnedFd,
    nonce: &str,
    seen: &Arc<Mutex<Seen>>,
    screen: &Out,
) -> Ended {
    let m = master.as_raw_fd();
    let _ = sys::set_nonblocking(m);
    let mut filter = TermFilter::new(!term_utf8());
    let mut escape = Escape::default();
    let mut frames = Frames::new(nonce);
    let winch = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register(signal_hook::consts::SIGWINCH, winch.clone());
    let mut size = sys::term_size(1);
    let mut to_pty: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 16384];
    let mut stdin_open = true;
    let mut last_out = Instant::now();
    // a ctrl-c typed before burner there answered went to ssh, still
    // connecting on a cooked pty: when ssh then goes, that was you
    let mut early_ctrl_c = false;
    let show =
        |frames: &mut Frames, filter: &mut TermFilter, data: &[u8], seen: &Arc<Mutex<Seen>>| {
            let (mut text, mut recs) = (Vec::new(), Vec::new());
            frames.feed(data, &mut text, &mut recs);
            if !recs.is_empty() {
                let mut s = seen.lock().unwrap_or_else(|e| e.into_inner());
                for r in recs {
                    s.take_record(r);
                }
            }
            screen.put(&filter.feed(&text), None);
        };
    let ended = loop {
        if crate::run::is_interrupted() {
            break Ended::Interrupted;
        }
        if winch.swap(false, Ordering::Relaxed)
            && let Some(now) = sys::term_size(1)
            && Some(now) != size
        {
            let _ = sys::set_term_size(m, now);
            size = Some(now);
        }
        let mut fds = vec![m];
        if stdin_open {
            fds.push(0);
        }
        let ready = sys::poll_read(&fds, Duration::from_millis(100));
        if ready.contains(&0) {
            match io::stdin().lock().read(&mut buf) {
                Ok(0) | Err(_) => stdin_open = false,
                Ok(n) => {
                    let mut keys = Vec::new();
                    escape.bracketed = screen.screen().is_some_and(|s| s.paste());
                    if escape.feed(&buf[..n], &mut keys) {
                        break Ended::Detached;
                    }
                    if keys.contains(&0x03) && !answered(seen) {
                        early_ctrl_c = true;
                    }
                    let room = TO_PTY_CAP.saturating_sub(to_pty.len());
                    to_pty.extend_from_slice(&keys[..keys.len().min(room)]);
                }
            }
        }
        if !to_pty.is_empty() {
            match write_some(m, &to_pty) {
                Ok(n) => {
                    to_pty.drain(..n);
                }
                Err(e) if would_block(&e) => {}
                Err(_) => to_pty.clear(),
            }
        }
        if ready.contains(&m) {
            match read_some(m, &mut buf) {
                Ok(0) => break Ended::Closed,
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    show(&mut frames, &mut filter, &data, seen);
                    last_out = Instant::now();
                }
                Err(e) if would_block(&e) => {}
                // EIO: every slave fd is closed, ssh is gone
                Err(_) => break Ended::Closed,
            }
        } else if frames.held() && last_out.elapsed() >= HELD_QUIET {
            let mut text = Vec::new();
            frames.flush_held(&mut text);
            screen.put(&filter.feed(&text), None);
        }
        if ready.is_empty() && matches!(child.try_wait(), Ok(Some(_))) {
            // ssh exited, but its pty may still hold the last bytes
            while let Ok(n) = read_some(m, &mut buf) {
                if n == 0 {
                    break;
                }
                let data = buf[..n].to_vec();
                show(&mut frames, &mut filter, &data, seen);
            }
            break Ended::Closed;
        }
    };
    let ended = match ended {
        Ended::Closed if early_ctrl_c && !answered(seen) => Ended::Interrupted,
        e => e,
    };
    let mut text = Vec::new();
    frames.finish(&mut text);
    screen.put(&filter.feed(&text), None);
    if let Some(b) = frames.broken.clone() {
        let mut s = seen.lock().unwrap_or_else(|e| e.into_inner());
        s.broken.get_or_insert(b);
    }
    drop(master);
    ended
}
