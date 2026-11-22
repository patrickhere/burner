//! `burner setup` on linux: this version's images from its release, checked
//! against the SHA256SUMS get.sh kept. not built yet

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::config::Config;
use crate::json::{self, Kind};

const IMAGES: [&str; 2] = ["alpine", "debian"];

#[derive(Args)]
pub struct SetupArgs {
    /// the images to install, alpine when none are named
    #[arg(value_name = "IMAGE", value_parser = IMAGES)]
    images: Vec<String>,
}

pub fn main(_cfg: &Config, _a: SetupArgs) -> Result<ExitCode> {
    Ok(json::fail(
        "setup",
        crate::run::EXIT_USAGE,
        Kind::Usage,
        "burner setup on linux: not yet",
    ))
}
