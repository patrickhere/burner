//! a terminal UI for burner. it only ever runs the burner binary ($BURNER, or
//! burner on PATH), through sudo when not root

mod app;
mod burner;
mod keys;
mod ui;

use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::KeyEvent;
use crossterm::{cursor, execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use app::{Action, App, Screen};
use burner::{Burner, Mode};
use keys::Keys;

const REFRESH: Duration = Duration::from_secs(2);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// the terminal is gone, there's nothing left to restore. leaving it to the
/// main loop isn't enough: crossterm can spin on the tty's EOF and never return
extern "C" fn on_hup(_: libc::c_int) {
    // SAFETY: _exit is async-signal-safe
    unsafe { libc::_exit(129) };
}

extern "C" fn ignore(_: libc::c_int) {}

/// the write end of the pipe a resize wakes the input poll through
static WINCH: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_winch(_: libc::c_int) {
    let fd = WINCH.load(Ordering::Relaxed);
    // SAFETY: write is async-signal-safe; a full pipe already has a wakeup in it
    unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
}

fn handle(sig: libc::c_int, f: extern "C" fn(libc::c_int)) {
    // SAFETY: the handlers only touch an atomic, write to a pipe, call _exit or
    // do nothing
    unsafe { libc::signal(sig, f as libc::sighandler_t) };
}

fn default(sig: libc::c_int) {
    // SAFETY: putting back the default disposition
    unsafe { libc::signal(sig, libc::SIG_DFL) };
}

/// the tty's input and resizes, through one poll: a key, a resize and a
/// hangup all end the same wait, and no key waits in a queue the poll can't see
struct Input {
    keys: Keys,
    winch: i32,
}

enum Tty {
    Keys(Vec<KeyEvent>),
    /// nothing to read, or the size changed: the next draw picks that up
    Quiet,
    Gone,
}

impl Input {
    fn new() -> io::Result<Input> {
        let mut p = [0; 2];
        // SAFETY: a valid array for the two fds
        if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        WINCH.store(p[1], Ordering::Relaxed);
        handle(libc::SIGWINCH, on_winch);
        Ok(Input {
            keys: Keys::default(),
            winch: p[0],
        })
    }

    fn wait(&mut self, ms: i32) -> Tty {
        let mut p = [0, self.winch].map(|fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        });
        // SAFETY: two valid pollfds
        let n = unsafe { libc::poll(p.as_mut_ptr(), 2, ms) };
        if n < 0 {
            return match io::Error::last_os_error().kind() {
                io::ErrorKind::Interrupted => Tty::Quiet,
                _ => Tty::Gone,
            };
        }
        if p[1].revents & libc::POLLIN != 0 {
            let mut sink = [0u8; 64];
            // SAFETY: reads into a local buffer from our own nonblocking pipe
            while unsafe { libc::read(self.winch, sink.as_mut_ptr().cast(), sink.len()) } > 0 {}
        }
        if p[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Tty::Gone;
        }
        if p[0].revents & libc::POLLIN == 0 {
            return Tty::Quiet;
        }
        let mut buf = [0u8; 1024];
        match tty().read(&mut buf) {
            Ok(0) => Tty::Gone,
            Ok(n) => Tty::Keys(self.keys.feed(&buf[..n])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Tty::Quiet,
            Err(_) => Tty::Gone,
        }
    }

    /// everything typed so far is dropped, half a key sequence included
    fn flush(&mut self) {
        self.keys.clear();
        // SAFETY: tcflush on fd 0 only discards its pending input
        unsafe { libc::tcflush(0, libc::TCIFLUSH) };
    }
}

/// fd 0 without std's stdin buffer, which would keep what it read ahead
fn tty() -> std::mem::ManuallyDrop<std::fs::File> {
    // SAFETY: fd 0 is open (main checked it's a tty) and is never closed here
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) })
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

static ENTERED: AtomicBool = AtomicBool::new(false);

fn enter() -> io::Result<()> {
    ENTERED.store(true, Ordering::SeqCst);
    terminal::enable_raw_mode()?;
    execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide)
}

/// safe to call more than once, and from the panic hook. only the first call
/// does anything: leaving the alternate screen twice moves the cursor back up
/// over whatever was printed in between
fn leave() {
    if ENTERED.swap(false, Ordering::SeqCst) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen, cursor::Show);
    }
}

/// puts the terminal back however main ends
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        leave();
    }
}

enum Msg {
    Ls(Result<burner::Ls, String>),
    Killed(String, Result<String, String>),
}

fn main() -> ExitCode {
    if let Some(a) = std::env::args().nth(1) {
        match a.as_str() {
            "-V" | "--version" => println!("burner-tui {}", env!("CARGO_PKG_VERSION")),
            "-h" | "--help" => println!(
                "burner-tui: pick an image and settings, start a burner shell or run, watch and kill running VMs\n\
                 runs $BURNER (default: burner on PATH), through sudo when not root. ? inside shows the keys"
            ),
            _ => {
                eprintln!("burner-tui: takes no arguments, try --help");
                return ExitCode::from(2);
            }
        }
        return ExitCode::SUCCESS;
    }
    // SAFETY: isatty only looks at the fd
    if unsafe { libc::isatty(0) == 0 || libc::isatty(1) == 0 } {
        eprintln!("burner-tui: needs a terminal");
        return ExitCode::from(2);
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("burner-tui: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> io::Result<()> {
    let b = Burner::from_env();
    let (images, images_err) = match burner::output(&b.quiet(&["images"])) {
        Ok(out) => (burner::parse_images(&out), None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let mut app = App::new(b, images);
    if let Some(e) = images_err {
        app.status = format!("burner images: {e}");
    }
    app.users = burner::users(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        leave();
        prev(info);
    }));
    handle(libc::SIGTERM, on_stop);
    handle(libc::SIGHUP, on_hup);

    let mut input = Input::new()?;
    let _restore = Restore;
    enter()?;
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    term.clear()?;

    let (tx, rx) = mpsc::channel();
    let mut asking = false;
    let mut last_ls: Option<Instant> = None;
    'main: while !STOP.load(Ordering::Relaxed) {
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Ls(r) => {
                    asking = false;
                    app.set_ls(r);
                }
                Msg::Killed(id, r) => {
                    app.killing = None;
                    app.status = match r {
                        Ok(_) => format!("{id} is gone"),
                        Err(e) => e,
                    };
                    last_ls = None;
                }
            }
        }
        // only poll while the list is on screen, every call is a sudo log line
        if app.screen == Screen::Running
            && !asking
            && last_ls.is_none_or(|t| t.elapsed() >= REFRESH)
        {
            asking = true;
            last_ls = Some(Instant::now());
            let (tx, argv) = (tx.clone(), app.burner.quiet(&["ls", "--json"]));
            thread::spawn(move || {
                let r = burner::output(&argv).and_then(|o| burner::parse_ls(&o));
                let _ = tx.send(Msg::Ls(r));
            });
        }
        term.draw(|f| ui::draw(f, &app))?;
        let keys = match input.wait(200) {
            Tty::Gone => break,
            Tty::Quiet => continue,
            Tty::Keys(k) => k,
        };
        for k in keys {
            match app.key(k) {
                Action::Nothing => {}
                Action::Quit => break 'main,
                Action::Refresh => last_ls = None,
                Action::Kill(id) => {
                    let (tx, argv) = (tx.clone(), app.burner.quiet(&["kill", &id]));
                    thread::spawn(move || {
                        let _ = tx.send(Msg::Killed(id, burner::output(&argv)));
                    });
                }
                Action::Launch(argv, mode) => {
                    app.status = hand_over(&mut term, &mut input, &argv, mode)?;
                    last_ls = None;
                    continue 'main;
                }
            }
        }
    }
    Ok(())
}

/// the screen modes a guest can leave on through burner shell, off again, for
/// a burner that died before it could do that itself: burner's TERM_RESET.
/// burner shell sends every alt screen as 1049, so ?1049l leaves the guest's
/// before the pause is printed; the cursor is saved around it because off the
/// alt screen ?1049l restores a stale one
const MODES_RESET: &[u8] = b"\x1b7\x1b[?1049l\x1b[r\x1b8\x1b[0m\x1b[?25h\x1b[?1l\x1b>\x1b(B\x1b)B\x1b[?2004l\x1b[?7h\x1b[4l\x1b[?12l\r\n";

/// gives the real terminal to burner shell or run and takes it back after
fn hand_over(
    term: &mut Term,
    input: &mut Input,
    argv: &[String],
    mode: Mode,
) -> io::Result<String> {
    leave();
    // burner puts the terminal back when it ends, unless it's killed outright
    // SAFETY: zeroed termios is a valid out-parameter for tcgetattr on fd 0
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd 0 and a valid termios pointer
    let have_tty = unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    println!("$ {}", burner::join(argv));
    // ctrl-c and ctrl-\ are for burner now. a handler instead of SIG_IGN, so
    // the child starts with the default again
    handle(libc::SIGINT, ignore);
    handle(libc::SIGQUIT, ignore);
    let res = Command::new(&argv[0]).args(&argv[1..]).status();
    let msg = match &res {
        Ok(st) => burner::describe_exit(st.code()),
        Err(e) => format!("can't run {}: {e}", argv[0]),
    };
    if have_tty {
        // SAFETY: fd 0 and the termios read above
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    }
    if res.as_ref().is_ok_and(|s| s.code().is_none()) {
        let mut out = io::stdout();
        out.write_all(MODES_RESET)?;
        out.flush()?;
    }
    // run's output and a failed shell's error stay up until enter
    if mode == Mode::Run || !res.as_ref().is_ok_and(|s| s.success()) {
        print!("\n[{msg}, enter goes back to burner-tui] ");
        io::stdout().flush()?;
        // the tty is canonical again, so one read is one line
        let mut line = [0u8; 4096];
        let n = loop {
            match tty().read(&mut line) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => break r?,
            }
        };
        // ctrl-d ends the line without echoing a newline
        if !line[..n].ends_with(b"\n") {
            println!();
        }
    }
    default(libc::SIGINT);
    default(libc::SIGQUIT);
    enter()?;
    // keys typed while burner had the terminal, and any that came in the same
    // read as the launching enter, would act on the TUI: they're dropped
    input.flush();
    term.clear()?;
    let what = match mode {
        Mode::Shell => "shell",
        Mode::Run => "run",
    };
    Ok(format!("{what} ended: {msg}"))
}
