use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{CommandFactory, Parser, Subcommand};

use burnervm::config::{self, Config};
use burnervm::json::{self, Kind};
#[cfg(target_os = "linux")]
use burnervm::net;
#[cfg(target_os = "macos")]
use burnervm::{cgroup, krun, macnet, sys};
use burnervm::{completions, doctor, exit, explain, probe, remote, result, run, setup};

#[derive(Parser)]
#[command(version)]
#[cfg_attr(
    target_os = "linux",
    command(about = "throwaway firecracker VMs on your own hardware")
)]
#[cfg_attr(
    target_os = "macos",
    command(about = "throwaway linux VMs on your mac, through libkrun")
)]
struct Cli {
    /// config file [default: /etc/burner/config.toml, on macOS in
    /// ~/Library/Application Support/burner]
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// write one JSON document (docs/json.md) instead of text
    #[arg(long, global = true)]
    json: bool,
    /// run it on this host over ssh: a name from ~/.config/burner/hosts.toml
    /// or an ssh host. local means here. default: $BURNER_HOST
    #[arg(short = 'H', long = "host", global = true, value_name = "HOST")]
    host: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// print the config burner would use, defaults filled in
    Config,
    /// check that this machine can run burner, and say what to fix. --probe
    /// also boots a VM that tries what a VM must not reach here
    Doctor(probe::ProbeArgs),
    /// run one command in a fresh VM and hand back its output and exit code
    #[command(after_long_help = exit::help())]
    Run(run::RunArgs),
    /// a root shell in a fresh VM, gone when you exit
    #[command(after_long_help = exit::help())]
    Shell(run::ShellArgs),
    /// what a VM could reach on this host, and with --rules the rules behind it
    Explain(explain::ExplainArgs),
    /// set up or remove the VM network (nft table, forwarding)
    Net {
        #[arg(value_parser = ["up", "down", "show"])]
        action: String,
    },
    /// list running VMs
    Ls,
    /// every connection a run's VM tried, allowed or blocked: yours, the newest without an ID
    Log(run::LogArgs),
    /// stop a running VM
    Kill(run::KillArgs),
    /// list installed images
    Images,
    /// this burner's version, backend and the json and guest protocol it speaks
    Version,
    /// the hosts -H knows, from ~/.config/burner/hosts.toml
    Hosts {
        /// try every address now
        #[arg(long)]
        check: bool,
    },
    #[cfg_attr(
        target_os = "linux",
        command(about = "fetch this version's images from its release and install them")
    )]
    #[cfg_attr(
        target_os = "macos",
        command(
            about = "install the guest kernel and images: the copy homebrew installed, or a release"
        )
    )]
    Setup(setup::SetupArgs),
    /// print completions for a shell
    Completions(completions::CompletionsArgs),
    /// the man pages, for packaging
    #[command(name = "__man", hide = true)]
    Man(completions::ManArgs),
    /// clean up after dead runs (run by the burner-reap timer)
    #[command(hide = true)]
    Reap,
    #[command(name = "__parse-result", hide = true)]
    ParseResult { emit: String },
    /// the connection log's reader, started by burner run
    #[cfg(target_os = "linux")]
    #[command(name = "__read-netlog", hide = true)]
    ReadNetlog,
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
        return result::child_main(emit);
    }
    #[cfg(target_os = "linux")]
    if let Cmd::ReadNetlog = &cli.cmd {
        return burnervm::nflog::child_main();
    }
    #[cfg(target_os = "macos")]
    match cli.cmd {
        Cmd::VmmKrun(a) => return krun::main(a),
        Cmd::Macnet(a) => return macnet::main(a),
        _ => {}
    }
    let name = cli.cmd.name();
    if let Some(code) = remote(&cli) {
        return code;
    }
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

fn probe_done(cfg: &Config, config: &std::path::Path, a: &probe::ProbeArgs) -> ExitCode {
    let (code, p, msg) = probe::main(cfg, config, a);
    if let Some(p) = &p
        && !json::on()
    {
        print!("{}", probe::render(p));
    }
    if let Some(m) = msg {
        let kind = match code {
            exit::EXIT_USAGE => Kind::Usage,
            exit::EXIT_FAILED => Kind::DoctorFailed,
            _ => Kind::Sandbox,
        };
        if code != exit::EXIT_FAILED && !json::on() {
            eprintln!("burner: {m}");
        }
        json::note_error(kind, m, false);
    }
    json::reply("doctor", code, p)
}

fn explain_main(cfg: &Config, a: &explain::ExplainArgs, json_on: bool) -> anyhow::Result<ExitCode> {
    {
        let e = match explain::build(cfg, a) {
            Ok(e) => e,
            Err(e) if e.to_string().starts_with("--net ") => {
                return Ok(json::fail(
                    "explain",
                    exit::EXIT_USAGE,
                    Kind::Usage,
                    e.to_string(),
                ));
            }
            Err(e) => return Err(e),
        };
        if !json_on {
            print!("{}", explain::render(&e));
        }
        if e.healthy() {
            return Ok(json::reply("explain", 0, Some(e)));
        }
        json::note_error(
            Kind::Net,
            "the filter isn't loaded, or isn't what this config and host give now",
            false,
        );
        Ok(json::reply("explain", exit::EXIT_FAILED, Some(e)))
    }
}

impl Cmd {
    /// the command's name in the envelope
    fn name(&self) -> &'static str {
        match self {
            Cmd::Config => "config",
            Cmd::Doctor(_) => "doctor",
            Cmd::Run(_) => "run",
            Cmd::Shell(_) => "shell",
            Cmd::Explain(_) => "explain",
            Cmd::Net { action } => match action.as_str() {
                "up" => "net up",
                "down" => "net down",
                _ => "net show",
            },
            Cmd::Ls => "ls",
            Cmd::Log(_) => "log",
            Cmd::Kill(_) => "kill",
            Cmd::Images => "images",
            Cmd::Version => "version",
            Cmd::Hosts { .. } => "hosts",
            Cmd::Setup(_) => "setup",
            Cmd::Completions(_) => "completions",
            Cmd::Man(_) => "__man",
            Cmd::Reap => "reap",
            Cmd::ParseResult { .. } => "__parse-result",
            #[cfg(target_os = "linux")]
            Cmd::ReadNetlog => "__read-netlog",
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
        *skip = matches!(a.as_str(), "--config" | "-H" | "--host");
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
        "config",
        "doctor",
        "run",
        "shell",
        "explain",
        "net up",
        "net down",
        "net show",
        "ls",
        "log",
        "kill",
        "images",
        "setup",
        "version",
        "hosts",
        "completions",
    ]
    .into_iter()
    .find(|c| *c == full)
}

/// -H or BURNER_HOST: the command goes to that host over ssh, and nothing
/// here is loaded. None when it runs here
fn remote(cli: &Cli) -> Option<ExitCode> {
    use remote::hosts;
    use remote::ssh::Mode;
    let name = cli.cmd.name();
    // the far end of -H always runs here. the wrapper drops BURNER_HOST, and
    // a run or shell started for a client never looks
    match &cli.cmd {
        Cmd::Run(a) if a.is_remote() => return None,
        Cmd::Shell(a) if a.is_remote() => return None,
        Cmd::ParseResult { .. } | Cmd::Hosts { .. } => return None,
        // about this burner's own command line, nothing to ask a host
        Cmd::Completions(_) | Cmd::Man(_) => return None,
        _ => {}
    }
    let env = std::env::var("BURNER_HOST").ok();
    let value = hosts::pick(cli.host.as_deref(), env.as_deref())?;
    let usage = |msg: String| Some(json::fail(name, exit::EXIT_USAGE, Kind::Usage, msg));
    // before hosts.toml is read: as root it would be someone else's file
    if let Some(why) = remote::client::refuse_here() {
        return usage(why);
    }
    let host = match hosts::load(&hosts::path()).and_then(|h| hosts::lookup(&value, &h)) {
        Ok(h) => h,
        Err(e) => {
            return Some(json::fail(
                name,
                exit::EXIT_USAGE,
                Kind::Config,
                format!("{e:#}"),
            ));
        }
    };
    let config = cli
        .config
        .as_ref()
        // one word, so a path that looks like a flag stays the value
        .map(|c| vec![format!("--config={}", c.to_string_lossy())])
        .unwrap_or_default();
    let words = |w: &[&str]| -> Vec<String> {
        w.iter()
            .map(|s| s.to_string())
            .chain(config.clone())
            .collect()
    };
    let h = &host.name;
    Some(match &cli.cmd {
        Cmd::Ls => remote::client::oneshot(&host, "ls", words(&["ls"]), Mode::Auto),
        Cmd::Kill(a) => match a.remote_argv() {
            Ok(argv) => {
                let w: Vec<&str> = argv.iter().map(String::as_str).collect();
                remote::client::oneshot(&host, "kill", words(&w), Mode::Auto)
            }
            Err(e) => return usage(e),
        },
        // the sudo rule names `burner images` exactly, so no --config for it
        Cmd::Images => {
            remote::client::oneshot(&host, "images", vec!["images".to_string()], Mode::Auto)
        }
        // config needs no root there, and isn't in the sudo rule
        Cmd::Config => remote::client::oneshot(&host, "config", words(&["config"]), Mode::User),
        Cmd::Version => remote::client::oneshot(&host, "version", words(&["version"]), Mode::User),
        Cmd::Run(a) => remote::client::run(&host, a, &config),
        Cmd::Shell(a) => remote::pty::shell(&host, &run::shell_run_args(a), &config),
        Cmd::Doctor(a) if !a.probe => remote::doctor::doctor(&host, &config),
        Cmd::Doctor(_) => {
            return usage(format!(
                "burner doctor --probe runs on the machine itself, not over -H (ssh -t {h} sudo burner doctor --probe)"
            ));
        }
        // the summary after a run over -H names a log that's kept there
        Cmd::Log(a) => match a.remote_argv() {
            Ok(argv) => {
                let w: Vec<&str> = argv.iter().map(String::as_str).collect();
                remote::client::oneshot(&host, "log", words(&w), Mode::Auto)
            }
            Err(e) => return usage(e),
        },
        Cmd::Explain(a) => match a.remote_argv() {
            Ok(argv) => {
                let w: Vec<&str> = argv.iter().map(String::as_str).collect();
                remote::client::oneshot(&host, "explain", words(&w), Mode::Auto)
            }
            Err(e) => return usage(e),
        },
        _ => {
            let what = name.split(' ').next().unwrap_or(name);
            return usage(format!(
                "burner {what} runs on the machine itself, not over -H (ssh {h} sudo burner {name}, or -H local here)"
            ));
        }
    })
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    // needs no config: what a remote burner asks first
    if let Cmd::Version = cli.cmd {
        let v = json::Version::this();
        if !cli.json {
            println!(
                "burner {} ({}, {} {}, json schema {}, guest protocol {})",
                v.version, v.backend, v.os, v.arch, v.schema, v.guest_proto
            );
        }
        return Ok(json::reply("version", 0, Some(v)));
    }
    if let Cmd::Hosts { check } = cli.cmd {
        return Ok(remote::doctor::hosts(check));
    }
    match &cli.cmd {
        Cmd::Completions(a) => return Ok(completions::main(Cli::command(), a)),
        Cmd::Man(a) => return Ok(completions::man(Cli::command(), a)),
        _ => {}
    }
    let t0 = Instant::now();
    // a shell is a run with the caller's terminal from here on
    let run_args = match &cli.cmd {
        Cmd::Run(a) => Some(a.clone()),
        Cmd::Shell(a) => Some(run::shell_run_args(a)),
        _ => None,
    };
    if let Some(a) = &run_args
        && let Some(code) = run::check_fds(a, t0)
    {
        return Ok(code);
    }
    // run and shell end with 125 when they have no result, a config that
    // doesn't load included, and run still writes its status line
    let config_path = cli.config.clone().unwrap_or_else(config::default_path);
    let cfg = match Config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            if let Some(a) = &run_args {
                return Ok(run::config_failed(a, &e, t0));
            }
            let msg = format!("{e:#}");
            return Ok(json::fail(
                cli.cmd.name(),
                exit::EXIT_FAILED,
                Kind::Config,
                msg,
            ));
        }
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
        Cmd::Doctor(a) if a.probe => Ok(probe_done(&cfg, &config_path, &a)),
        #[cfg(target_os = "linux")]
        Cmd::Doctor(_) => Ok(doctor_done(doctor::run(&cfg))),
        #[cfg(target_os = "macos")]
        Cmd::Doctor(_) => Ok(doctor_done(doctor::run(&cfg, &config_path))),
        Cmd::Run(_) => Ok(run::main(&cfg, &run_args.expect("set for run"))),
        Cmd::Shell(_) => Ok(run::shell_main(&cfg, &run_args.expect("set for shell"))),
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
        Cmd::Explain(a) => explain_main(&cfg, &a, cli.json),
        Cmd::Ls => run::ls(&cfg),
        Cmd::Log(a) => run::log(&cfg, &a),
        Cmd::Kill(a) => run::kill(&cfg, &a),
        Cmd::Images if cli.json => Ok(json::reply("images", 0, Some(run::images_result(&cfg)))),
        Cmd::Images => {
            for i in run::images(&cfg) {
                println!("{i}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Reap => run::reap(&cfg),
        Cmd::Version | Cmd::Hosts { .. } | Cmd::Completions(_) | Cmd::Man(_) => {
            unreachable!("handled before the config loads")
        }
        Cmd::Setup(a) => setup::main(&cfg, a),
        Cmd::ParseResult { .. } => unreachable!("handled before the config loads"),
        #[cfg(target_os = "linux")]
        Cmd::ReadNetlog => unreachable!("handled before the config loads"),
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
        assert_eq!(w(&["-H", "ls", "images", "--json"]), Some("images"));
        assert_eq!(w(&["--host", "kill", "ls"]), Some("ls"));
        assert_eq!(w(&["net", "--json", "up"]), Some("net up"));
        assert_eq!(w(&["net", "sideways"]), None);
        assert_eq!(w(&["reap", "--json"]), None);
        assert_eq!(w(&["--json"]), None);
    }
}
