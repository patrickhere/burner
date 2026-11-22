use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use super::EXIT_USAGE;
use crate::config::Config;
use crate::exit::EXIT_FAILED;
use crate::json::{self, Kind};
use crate::ledger::valid_id;
#[cfg(target_os = "linux")]
use crate::sys;

#[derive(Args)]
pub struct LogArgs {
    /// the run's id, the newest of yours without one
    #[arg(conflicts_with = "list")]
    id: Option<String>,
    /// the runs kept, newest first
    #[arg(long)]
    list: bool,
    /// only runs on this -H host (-H itself asks that host)
    #[arg(long, value_name = "HOST", requires = "list")]
    from: Option<String>,
    /// at most this many
    #[arg(long, value_name = "N", requires = "list")]
    limit: Option<usize>,
}

const LOG_USAGE: &str = "usage: burner log [burner-xxxxxxxxxxxx]";

impl LogArgs {
    /// a flag that parses but isn't built yet
    fn unbuilt(&self) -> Option<&'static str> {
        self.list.then_some("burner log --list: not yet")
    }

    /// burner's argv on the far end of -H. checked here: an id like
    /// -Hother would be a flag there
    pub fn remote_argv(&self) -> std::result::Result<Vec<String>, String> {
        if let Some(why) = self.unbuilt() {
            return Err(why.into());
        }
        match &self.id {
            Some(id) if !valid_id(id) => Err(LOG_USAGE.into()),
            id => Ok(std::iter::once("log".to_string())
                .chain(id.clone())
                .collect()),
        }
    }
}

/// burner log: a run's connection log, the newest of yours without an id
pub fn log(cfg: &Config, a: &LogArgs) -> Result<ExitCode> {
    if let Some(why) = a.unbuilt() {
        return Ok(json::fail("log", EXIT_USAGE, Kind::Usage, why));
    }
    let id = a.id.as_deref();
    #[cfg(target_os = "linux")]
    if !sys::is_root() {
        return Ok(json::fail(
            "log",
            EXIT_USAGE,
            Kind::NotRoot,
            "burner log needs root, like the runs it reads (sudo burner log)",
        ));
    }
    // through sudo it's the caller's runs; root itself sees every one
    let owner = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok());
    let Some(l) = crate::netlog::load(&cfg.paths.state, id, owner) else {
        let msg = match id {
            Some(id) => format!(
                "{id}: no network log for that run (only the last {} are kept)",
                crate::netlog::KEEP
            ),
            None => "no network log yet: run something with --net web or open".into(),
        };
        return Ok(json::fail("log", EXIT_FAILED, Kind::NotFound, msg));
    };
    if !json::on() {
        print!("{}: {}", l.id, crate::netlog::table(&l));
    }
    Ok(json::reply("log", 0, Some(l)))
}
