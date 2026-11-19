#[cfg_attr(target_os = "macos", path = "cgroup_macos.rs")]
mod cgroup;
mod config;
#[cfg_attr(target_os = "macos", path = "doctor_macos.rs")]
mod doctor;
#[cfg(target_os = "macos")]
mod krun;
mod ledger;
#[cfg(target_os = "macos")]
mod macnet;
mod net;
mod output;
mod result;
mod run;
#[cfg(target_os = "macos")]
mod setup;
mod sys;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use config::Config;

/// throwaway firecracker VMs on your own hardware
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// config file
    #[arg(long, global = true, default_value_os_t = config::default_path())]
    config: PathBuf,
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
    Run(run::RunArgs),
    /// a root shell in a fresh VM, gone when you exit
    Shell(run::ShellArgs),
    /// set up or remove the VM network (nft table, forwarding)
    Net {
        #[arg(value_parser = ["up", "down", "show"])]
        action: String,
    },
    /// list running VMs
    Ls {
        #[arg(long)]
        json: bool,
    },
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
    let cli = Cli::parse();
    if let Cmd::ParseResult { emit } = &cli.cmd {
        return result::child_main(emit == "1");
    }
    #[cfg(target_os = "macos")]
    match cli.cmd {
        Cmd::VmmKrun(a) => return krun::main(a),
        Cmd::Macnet(a) => return macnet::main(a),
        _ => {}
    }
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("burner: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let cfg = Config::load(&cli.config)?;
    #[cfg(target_os = "macos")]
    cgroup::set_dir(&cfg.paths.state);
    match cli.cmd {
        Cmd::Config => {
            print!("{}", toml::to_string_pretty(&cfg)?);
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(target_os = "linux")]
        Cmd::Doctor => Ok(if doctor::run(&cfg) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }),
        #[cfg(target_os = "macos")]
        Cmd::Doctor => Ok(if doctor::run(&cfg, &cli.config) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }),
        Cmd::Run(a) => Ok(run::main(&cfg, a)),
        Cmd::Shell(a) => Ok(run::shell_main(&cfg, a)),
        #[cfg(target_os = "macos")]
        Cmd::Net { .. } => {
            anyhow::bail!(
                "on macOS each VM's network is a process of its own, there's nothing to set up"
            )
        }
        #[cfg(target_os = "linux")]
        Cmd::Net { action } => match action.as_str() {
            "show" => {
                print!("{}", net::ruleset(&cfg)?);
                Ok(ExitCode::SUCCESS)
            }
            "down" => {
                let n = net::down(&cfg)?;
                if n > 0 {
                    eprintln!("burner: stopped {n} VMs that had a network");
                }
                Ok(ExitCode::SUCCESS)
            }
            _ => {
                for note in net::up(&cfg)? {
                    eprintln!("burner: {note}");
                }
                Ok(ExitCode::SUCCESS)
            }
        },
        Cmd::Ls { json } => run::ls(&cfg, json),
        Cmd::Kill { id } => run::kill(&cfg, &id),
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
