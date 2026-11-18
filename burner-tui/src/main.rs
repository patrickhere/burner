//! a terminal UI for burner. it only ever runs the burner binary ($BURNER, or
//! burner on PATH), through sudo when not root

mod app;
mod burner;
mod ui;

use std::io::{self, Write};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind};
use crossterm::{cursor, execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use app::{Action, App, Screen};
use burner::{Burner, Mode};

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

fn handle(sig: libc::c_int, f: extern "C" fn(libc::c_int)) {
    // SAFETY: the handlers only touch an atomic, call _exit or do nothing
    unsafe { libc::signal(sig, f as libc::sighandler_t) };
}

fn default(sig: libc::c_int) {
    // SAFETY: putting back the default disposition
    unsafe { libc::signal(sig, libc::SIG_DFL) };
}

enum Tty {
    Input,
    Quiet,
    Gone,
}

/// waits for keys on the tty. crossterm is only asked once there's something
/// to read, because its own poll spins forever if the tty hangs up meanwhile
fn wait_tty(ms: i32) -> Tty {
    let mut p = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd
    let n = unsafe { libc::poll(&mut p, 1, ms) };
    if n < 0 {
        return match io::Error::last_os_error().kind() {
            io::ErrorKind::Interrupted => Tty::Quiet,
            _ => Tty::Gone,
        };
    }
    if p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        Tty::Gone
    } else if p.revents & libc::POLLIN != 0 {
        Tty::Input
    } else {
        Tty::Quiet
    }
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
        match wait_tty(200) {
            Tty::Gone => break,
            Tty::Quiet => continue,
            Tty::Input => {}
        }
        // one read can hold several keys, crossterm keeps the rest buffered
        while event::poll(Duration::ZERO)? {
            let Event::Key(k) = event::read()? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
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
                    app.status = hand_over(&mut term, &argv, mode)?;
                    last_ls = None;
                    continue 'main;
                }
            }
        }
    }
    Ok(())
}

/// gives the real terminal to burner shell or run and takes it back after
fn hand_over(term: &mut Term, argv: &[String], mode: Mode) -> io::Result<String> {
    leave();
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
    // run's output and a failed shell's error stay up until enter
    if mode == Mode::Run || !res.as_ref().is_ok_and(|s| s.success()) {
        print!("\n[{msg}, enter goes back to burner-tui] ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
    }
    default(libc::SIGINT);
    default(libc::SIGQUIT);
    enter()?;
    term.clear()?;
    let what = match mode {
        Mode::Shell => "shell",
        Mode::Run => "run",
    };
    Ok(format!("{what} ended: {msg}"))
}
