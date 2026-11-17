mod cgroup;
mod config;
mod doctor;
mod ledger;
mod output;
mod result;
mod run;
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
    #[arg(long, global = true, default_value = config::DEFAULT_PATH)]
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
    /// list running VMs
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// stop a running VM
    Kill { id: String },
    /// list installed images
    Images,
    /// clean up after dead runs (run by the burner-reap timer)
    #[command(hide = true)]
    Reap,
    #[command(name = "__parse-result", hide = true)]
    ParseResult { emit: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Cmd::ParseResult { emit } = &cli.cmd {
        return result::child_main(emit == "1");
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
    match cli.cmd {
        Cmd::Config => {
            print!("{}", toml::to_string_pretty(&cfg)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor => Ok(if doctor::run(&cfg) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        }),
        Cmd::Run(a) => Ok(run::main(&cfg, a)),
        Cmd::Ls { json } => run::ls(&cfg, json),
        Cmd::Kill { id } => run::kill(&cfg, &id),
        Cmd::Images => {
            for i in run::images(&cfg) {
                println!("{i}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Reap => run::reap(&cfg),
        Cmd::ParseResult { .. } => unreachable!("handled before the config loads"),
    }
}
