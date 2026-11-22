//! `burner completions` and the man pages, both made from burner's own clap
//! definition. not built yet

use std::process::ExitCode;

use clap::{Args, Command};

use crate::exit::EXIT_USAGE;
use crate::json::{self, Kind};

const SHELLS: [&str; 5] = ["bash", "zsh", "fish", "elvish", "powershell"];

#[derive(Args)]
pub struct CompletionsArgs {
    /// the shell to print completions for
    #[arg(value_name = "SHELL", value_parser = SHELLS)]
    shell: String,
}

#[derive(Args)]
pub struct ManArgs {}

/// `cli` is burner's whole command line, from the binary
pub fn main(_cli: Command, _a: &CompletionsArgs) -> ExitCode {
    json::fail(
        "completions",
        EXIT_USAGE,
        Kind::Usage,
        "burner completions: not yet",
    )
}

pub fn man(_cli: Command, _a: &ManArgs) -> ExitCode {
    json::fail("__man", EXIT_USAGE, Kind::Usage, "burner __man: not yet")
}
