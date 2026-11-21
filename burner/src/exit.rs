//! what burner exits with. README.md has the same table, a test keeps them equal

pub const EXIT_FAILED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_TIMEOUT: u8 = 124;
pub const EXIT_SANDBOX: u8 = 125;
pub const EXIT_INTERRUPTED: u8 = 130;

pub const TABLE: &[(&str, &str)] = &[
    (
        "0",
        "success. for run and shell: the command exited 0, the shell was left with `~.`, or the shell's VM was powered off",
    ),
    (
        "1",
        "the command didn't do its job: doctor found a FAIL, kill was refused or the VM is still stopping, net up failed, the config didn't load. never from run or shell",
    ),
    (
        "2",
        "usage: bad flags or arguments, needs root (or must not be root), no terminal for shell, not on this OS. nothing was started",
    ),
    ("124", "run and shell: the time limit stopped it"),
    (
        "125",
        "run and shell: no result. the sandbox or the VM failed, no free slot, the config or an image's defaults didn't load, the input didn't unpack, the command powered off or rebooted the VM, the result tar wasn't delivered",
    ),
    (
        "130",
        "a signal (ctrl-c, SIGTERM, SIGHUP) stopped burner, or burner kill stopped the VM",
    ),
    ("other", "run and shell: the command's own exit code"),
];

/// the table for run --help and shell --help
pub fn help() -> String {
    let mut s = String::from("Exit codes:\n");
    for (code, what) in TABLE {
        s += &format!("  {code:<6} {}\n", what.replace('`', ""));
    }
    s + "a command can exit 2, 124, 125 or 130 itself: --json-fd tells them apart"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readme_has_the_table() {
        let readme = include_str!("../../README.md");
        for (code, what) in TABLE {
            let row = format!("| {code} | {what} |");
            assert!(readme.contains(&row), "README.md is missing: {row}");
        }
    }
}
