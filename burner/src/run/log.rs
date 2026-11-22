use std::process::ExitCode;

use anyhow::Result;

#[cfg(target_os = "linux")]
use super::EXIT_USAGE;
use crate::config::Config;
use crate::exit::EXIT_FAILED;
use crate::json::{self, Kind};
#[cfg(target_os = "linux")]
use crate::sys;

/// burner log: a run's connection log, the newest of yours without an id
pub fn log(cfg: &Config, id: Option<&str>) -> Result<ExitCode> {
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
