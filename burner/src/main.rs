use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use burnervm::config::{self, Config};
use burnervm::json::{self, Kind};
#[cfg(target_os = "linux")]
use burnervm::net;
#[cfg(target_os = "macos")]
use burnervm::{cgroup, krun, macnet, setup, sys};
use burnervm::{doctor, exit, result, run};

/// throwaway firecracker VMs on your own hardware
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// config file
    #[arg(long, global = true, default_value_os_t = config::default_path())]
    config: PathBuf,
    /// write one JSON document (docs/json.md) instead of text
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// print the config burner would use, defaults filled in
    Config,
    /// check that this machine can run burner, and say what to fix
    Doctor,
    /// run one command in a fresh VM and hand back its output and exit code
    #[command(after_long_help = exit::help())]
    Run(run::RunArgs),
    /// a root shell in a fresh VM, gone when you exit
    #[command(after_long_help = exit::help())]
    Shell(run::ShellArgs),
    /// set up or remove the VM network (nft table, forwarding)
    Net {
        #[arg(value_parser = ["up", "down", "show"])]
        action: String,
    },
    /// list running VMs
    Ls,
    /// stop a running VM
    Kill { id: String },
    /// list installed images
    Images,
    /// fetch the guest kernel and alpine image from a release and install them
    #[cfg(target_os = "macos")]
    Setup(setup::SetupArgs),
    /// clean up after dead runs (run by the burner-reap timer)
    #[command(hide = true)]
    Reap,
    #[command(name = "__parse-result", hide = true)]
    ParseResult { emit: String },
    /// the VMM for one VM, started by burner run
    #[cfg(target_os = "macos")]
    #[command(name = "vmm-krun", hide = true)]
    VmmKrun(krun::VmmArgs),
    /// the network for one VM, started by burner run
    #[cfg(target_os = "macos")]
    #[command(hide = true)]
    Macnet(macnet::MacnetArgs),
}

fn main() -> ExitCode {
    #[cfg(target_os = "macos")]
    sys::self_exe();
    // as root, helpers (ip, nft, mkfs.ext4, curl) never come from the caller's
    // PATH: sudo doesn't always reset it
    // SAFETY: first thing in main, before any thread exists
    if unsafe { libc::geteuid() } == 0 {
        unsafe { std::env::set_var("PATH", "/usr/sbin:/usr/bin:/sbin:/bin") };
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return parse_failed(e),
    };
    json::set_on(cli.json);
    if let Cmd::ParseResult { emit } = &cli.cmd {
        return result::child_main(emit == "1");
    }
    #[cfg(target_os = "macos")]
    match cli.cmd {
        Cmd::VmmKrun(a) => return krun::main(a),
        Cmd::Macnet(a) => return macnet::main(a),
        _ => {}
    }
    let name = cli.cmd.name();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let kind = if name.starts_with("net ") {
                Kind::Net
            } else {
                Kind::Io
            };
            json::fail(name, exit::EXIT_FAILED, kind, format!("{e:#}"))
        }
    }
}

fn doctor_done(r: doctor::Report) -> ExitCode {
    if !r.failed() {
        return json::reply("doctor", 0, Some(r));
    }
    // the human text already said so, as its last line
    json::note_error(
        Kind::DoctorFailed,
        "not ready, fix the FAIL lines first",
        false,
    );
    json::reply("doctor", exit::EXIT_FAILED, Some(r))
}

impl Cmd {
    /// the command's name in the envelope
    fn name(&self) -> &'static str {
        match self {
            Cmd::Config => "config",
            Cmd::Doctor => "doctor",
            Cmd::Run(_) => "run",
            Cmd::Shell(_) => "shell",
            Cmd::Net { action } => match action.as_str() {
                "up" => "net up",
                "down" => "net down",
                _ => "net show",
            },
            Cmd::Ls => "ls",
            Cmd::Kill { .. } => "kill",
            Cmd::Images => "images",
            #[cfg(target_os = "macos")]
            Cmd::Setup(_) => "setup",
            Cmd::Reap => "reap",
            Cmd::ParseResult { .. } => "__parse-result",
            #[cfg(target_os = "macos")]
            Cmd::VmmKrun(_) => "vmm-krun",
            #[cfg(target_os = "macos")]
            Cmd::Macnet(_) => "macnet",
        }
    }
}

/// a command line clap refused. with --json before any -- that's an
/// envelope too; help and --version stay text
fn parse_failed(e: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .take_while(|a| a != "--")
        .collect();
    if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion)
        || !args.iter().any(|a| a == "--json")
    {
        e.exit();
    }
    json::set_on(true);
    // clap's text up to its usage line, on one line
    let text = e.render().to_string();
    let msg: Vec<&str> = text
        .lines()
        .map(str::trim)
        .take_while(|l| !l.is_empty() && !l.starts_with("Usage:"))
        .collect();
    let msg = msg.join(" ");
    json::error(Kind::Usage, msg.strip_prefix("error: ").unwrap_or(&msg));
    let command = command_word(&args);
    print!(
        "{}",
        json::Envelope::<()>::new(command, exit::EXIT_USAGE, false, None).line()
    );
    ExitCode::from(exit::EXIT_USAGE)
}

/// the subcommand a command line was for, when it names a real one
fn command_word(args: &[String]) -> Option<&'static str> {
    let mut words = args.iter().scan(false, |skip, a| {
        let this = !*skip && !a.starts_with('-');
        *skip = a == "--config";
        Some((this, a.as_str()))
    });
    let first = words.find(|(w, _)| *w)?.1;
    let cmd = Cli::command()
        .get_subcommands()
        .find(|c| !c.is_hide_set() && c.get_name() == first)?
        .get_name()
        .to_string();
    let full = match cmd.as_str() {
        "net" => match words.find(|(w, _)| *w).map(|(_, a)| a) {
            Some(a @ ("up" | "down" | "show")) => format!("net {a}"),
            _ => return None,
        },
        _ => cmd,
    };
    [
        "config", "doctor", "run", "shell", "net up", "net down", "net show", "ls", "kill",
        "images", "setup",
    ]
    .into_iter()
    .find(|c| *c == full)
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let t0 = Instant::now();
    if let Cmd::Run(a) = &cli.cmd
        && !run::status_fd_ok(a)
    {
        return Ok(ExitCode::from(run::EXIT_USAGE));
    }
    // run and shell end with 125 when they have no result, a config that
    // doesn't load included, and run still writes its status line
    let cfg = match Config::load(&cli.config) {
        Ok(cfg) => cfg,
        Err(e) => match &cli.cmd {
            Cmd::Run(a) => return Ok(run::config_failed(a, &e, t0)),
            Cmd::Shell(_) => {
                eprintln!("burner: {e:#}");
                return Ok(ExitCode::from(run::EXIT_SANDBOX));
            }
            c => {
                return Ok(json::fail(
                    c.name(),
                    exit::EXIT_FAILED,
                    Kind::Config,
                    format!("{e:#}"),
                ));
            }
        },
    };
    #[cfg(target_os = "macos")]
    cgroup::set_dir(&cfg.paths.state);
    let name = cli.cmd.name();
    match cli.cmd {
        Cmd::Config => {
            if !cli.json {
                print!("{}", toml::to_string_pretty(&cfg)?);
            }
            Ok(json::reply("config", 0, Some(&cfg)))
        }
        #[cfg(target_os = "linux")]
        Cmd::Doctor => Ok(doctor_done(doctor::run(&cfg))),
        #[cfg(target_os = "macos")]
        Cmd::Doctor => Ok(doctor_done(doctor::run(&cfg, &cli.config))),
        Cmd::Run(a) => Ok(run::main(&cfg, a)),
        Cmd::Shell(a) => Ok(run::shell_main(&cfg, a)),
        // not there on this OS rather than failed, like a wrong flag
        #[cfg(target_os = "macos")]
        Cmd::Net { .. } => Ok(json::fail(
            name,
            run::EXIT_USAGE,
            Kind::Unsupported,
            "on macOS each VM's network is a process of its own, there's nothing to set up",
        )),
        #[cfg(target_os = "linux")]
        Cmd::Net { action } => match action.as_str() {
            "show" => {
                let ruleset = net::ruleset(&cfg)?;
                if !cli.json {
                    print!("{ruleset}");
                }
                let table = format!("inet {}", net::TABLE);
                Ok(json::reply(
                    name,
                    0,
                    Some(net::ShowResult { table, ruleset }),
                ))
            }
            "down" => {
                let n = net::down(&cfg)?;
                if n > 0 && !cli.json {
                    eprintln!("burner: stopped {n} VMs that had a network");
                }
                Ok(json::reply(
                    name,
                    0,
                    Some(net::DownResult { stopped_vms: n }),
                ))
            }
            _ => {
                let notes = net::up(&cfg)?;
                if !cli.json {
                    for note in &notes {
                        eprintln!("burner: {note}");
                    }
                }
                Ok(json::reply(name, 0, Some(net::UpResult { notes })))
            }
        },
        Cmd::Ls => run::ls(&cfg),
        Cmd::Kill { id } => run::kill(&cfg, &id),
        Cmd::Images if cli.json => Ok(json::reply("images", 0, Some(run::images_result(&cfg)))),
        Cmd::Images => {
            for i in run::images(&cfg) {
                println!("{i}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Reap => run::reap(&cfg),
        #[cfg(target_os = "macos")]
        Cmd::Setup(a) => setup::main(&cfg, a),
        Cmd::ParseResult { .. } => unreachable!("handled before the config loads"),
        #[cfg(target_os = "macos")]
        Cmd::VmmKrun(_) | Cmd::Macnet(_) => unreachable!("handled before the config loads"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_is_sound() {
        Cli::command().debug_assert();
    }

    #[test]
    fn command_words() {
        let w = |a: &[&str]| command_word(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(w(&["--json", "ls"]), Some("ls"));
        assert_eq!(w(&["--config", "ls", "kill", "--json"]), Some("kill"));
        assert_eq!(w(&["net", "--json", "up"]), Some("net up"));
        assert_eq!(w(&["net", "sideways"]), None);
        assert_eq!(w(&["reap", "--json"]), None);
        assert_eq!(w(&["--json"]), None);
    }
}
