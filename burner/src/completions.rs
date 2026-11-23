//! `burner completions SHELL` and the man pages (`burner __man DIR`), both
//! made from burner's own clap definition, so they know every flag the
//! binary they come from has. install.sh and the homebrew formula put them
//! where the shells and man look

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Command};
use clap_complete::Shell;

use crate::exit::EXIT_FAILED;
use crate::json::{self, Kind};

#[derive(Args)]
pub struct CompletionsArgs {
    /// the shell to print completions for
    #[arg(value_name = "SHELL", value_enum)]
    shell: Shell,
}

#[derive(Args)]
pub struct ManArgs {
    /// the dir to write burner.1 and a page per command into, made if it
    /// isn't there
    #[arg(value_name = "DIR")]
    dir: PathBuf,
}

#[derive(serde::Serialize)]
pub struct CompletionsResult {
    pub shell: String,
    /// what it prints without --json
    pub script: String,
}

#[derive(serde::Serialize)]
pub struct ManResult {
    pub dir: String,
    /// burner's pages in dir, burner.1 first
    pub pages: Vec<String>,
}

/// the command line as people type it: the crate is burnervm, the command
/// burner
fn named(cli: Command) -> Command {
    cli.name("burner").bin_name("burner")
}

/// `cli` is burner's whole command line, from the binary
pub fn main(cli: Command, a: &CompletionsArgs) -> ExitCode {
    let script = script(cli, a.shell);
    if !json::on() {
        print!("{script}");
    }
    json::reply(
        "completions",
        0,
        Some(CompletionsResult {
            shell: a.shell.to_string(),
            script,
        }),
    )
}

fn script(cli: Command, shell: Shell) -> String {
    // clap_complete offers hidden commands too (reap, __man, the helpers
    // burner starts itself), so they don't go in
    let shown: Vec<Command> = cli
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .cloned()
        .collect();
    let mut cmd = Command::new("burner")
        .args(cli.get_arguments().cloned())
        .subcommands(shown);
    if cli.get_version().is_some() {
        cmd = cmd.version(env!("CARGO_PKG_VERSION"));
    }
    let mut cmd = named(cmd);
    let mut out = Vec::new();
    clap_complete::generate(shell, &mut cmd, "burner", &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

pub fn man(cli: Command, a: &ManArgs) -> ExitCode {
    match pages(cli, a) {
        Ok(pages) => {
            if !json::on() {
                for p in &pages {
                    println!("{}", a.dir.join(p).display());
                }
            }
            json::reply(
                "__man",
                0,
                Some(ManResult {
                    dir: a.dir.display().to_string(),
                    pages,
                }),
            )
        }
        Err(e) => json::fail(
            "__man",
            EXIT_FAILED,
            Kind::Io,
            format!("writing the man pages to {}: {e}", a.dir.display()),
        ),
    }
}

fn pages(cli: Command, a: &ManArgs) -> std::io::Result<Vec<String>> {
    fs::create_dir_all(&a.dir)?;
    clap_mangen::generate_to(named(cli), &a.dir)?;
    let mut pages: Vec<String> = list(&a.dir)?
        .into_iter()
        .filter(|p| p == "burner.1" || (p.starts_with("burner-") && p.ends_with(".1")))
        .collect();
    pages.sort_by_key(|p| (p != "burner.1", p.clone()));
    Ok(pages)
}

fn list(dir: &std::path::Path) -> std::io::Result<Vec<String>> {
    Ok(fs::read_dir(dir)?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli() -> Command {
        // a stand-in for main.rs's Cli: the crate's name, a hidden command
        Command::new("burnervm")
            .subcommand(Command::new("run").arg(clap::Arg::new("img").long("img")))
            .subcommand(Command::new("ls"))
            .subcommand(Command::new("__man").hide(true))
    }

    #[test]
    fn completions_say_burner() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let s = script(cli(), shell);
            assert!(s.contains("burner"), "{shell}");
            // fish has it as -l img
            assert!(s.contains("img"), "{shell}");
            assert!(!s.contains("burnervm"), "{shell}");
            assert!(!s.contains("__man"), "{shell}");
        }
    }

    #[test]
    fn man_pages_per_command() {
        let dir = std::env::temp_dir().join(format!("burner-man-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let a = ManArgs { dir: dir.clone() };
        let p = pages(cli(), &a).unwrap();
        assert_eq!(p, ["burner.1", "burner-ls.1", "burner-run.1"]);
        let top = fs::read_to_string(dir.join("burner.1")).unwrap();
        assert!(top.contains("burner"));
        assert!(!top.contains("burnervm"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
