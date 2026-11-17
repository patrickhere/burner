mod config;
mod doctor;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
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
    }
}
