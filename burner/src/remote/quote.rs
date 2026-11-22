//! the remote command line. ssh hands one string to the login shell of the
//! user on the far end, which can be sh, dash, bash, zsh, ksh or fish. inside
//! single quotes fish reads \' and \\ as escapes and the others don't, so
//! those two never go inside quotes: `it's a\b` becomes `'it'\''s a'\\'b'`,
//! which every one of them reads back as the same bytes. = and % are never
//! left bare: zsh expands =cmd at the start of a word, and fish %self

/// the most a remote line can be. linux takes one argument of at most 128K
/// (MAX_ARG_STRLEN), and the line is one argument to the remote's shell
pub const LINE_MAX: usize = 100 << 10;

fn safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"+_./:,@-".contains(&b)
}

/// one argument, quoted for any of those shells
pub fn remote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(safe) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' || c == '\\' {
            out.push_str("'\\");
            out.push(c);
            out.push('\'');
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// the whole line: every argument quoted, joined by spaces
pub fn line<S: AsRef<str>>(args: &[S]) -> String {
    args.iter()
        .map(|a| remote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn golden() {
        assert_eq!(remote("plain-1.0/x,y:z@w"), "plain-1.0/x,y:z@w");
        assert_eq!(remote(""), "''");
        assert_eq!(remote("it's a\\b"), r"'it'\''s a'\\'b'");
        assert_eq!(remote("=ls"), "'=ls'");
        assert_eq!(remote("%self"), "'%self'");
        assert_eq!(remote("$(id)"), "'$(id)'");
        assert_eq!(remote("'"), r"''\'''");
        assert_eq!(remote("\\\\"), r"''\\''\\''");
        assert_eq!(remote("--net open"), "'--net open'");
        assert_eq!(remote("é"), "'é'");
        assert_eq!(line(&["a", "b c", ""]), "a 'b c' ''");
    }

    /// arguments that have broken shell quoting somewhere
    fn nasty() -> Vec<String> {
        let mut v: Vec<String> = [
            "",
            " ",
            "'",
            "''",
            "\"",
            "\\",
            "\\'",
            "'\\",
            "\\\\'\\",
            "$(id)",
            "`id`",
            "${HOME}",
            "$HOME",
            "a;b",
            "a&&b",
            "a|b",
            "!",
            "!!",
            "*",
            "?",
            "[a]",
            "{a,b}",
            "~",
            "~root",
            "-n",
            "-e",
            "--",
            "--net open",
            "a\nb",
            "\n",
            "line one\nline 'two'\n\\three",
            "tab\there",
            "\r",
            "#comment",
            "a#b",
            "x=y z",
            "%s\\0",
            "é ü 漢字 🔥",
            "\u{1b}[31mred",
            "(a)",
            "<in",
            ">out",
            "a\\nb",
            "\\x41",
            "\\u0041",
            "@@",
            "^",
            "=",
            "%",
            "=ls",
            "%self",
            "a=b",
            "=",
            "==",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // every byte from 1 to 127 on its own and next to a quote
        for b in 1u8..128 {
            let c = (b as char).to_string();
            v.push(c.clone());
            v.push(format!("'{c}\\"));
        }
        v
    }

    /// what `shell -c LINE` gives a program as its argv, with the program
    /// being sh's printf, each argument followed by a NUL
    fn through(shell: &str, args: &[String]) -> Option<Vec<u8>> {
        let mut words = vec![
            "/bin/sh".to_string(),
            "-c".into(),
            "printf '%s\\0' \"$@\"".into(),
            "x".into(),
        ];
        words.extend(args.iter().cloned());
        let out = Command::new(shell)
            .arg("-c")
            .arg(line(&words))
            .env("HOME", "/nonexistent")
            .output()
            .ok()?;
        assert!(
            out.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Some(out.stdout)
    }

    fn want(args: &[String]) -> Vec<u8> {
        let mut w = Vec::new();
        for a in args {
            w.extend_from_slice(a.as_bytes());
            w.push(0);
        }
        w
    }

    /// shells the far end's login shell can be. the ones not installed are
    /// skipped here; the remote ci job installs them all
    const SHELLS: &[&str] = &["sh", "dash", "bash", "zsh", "ksh", "fish"];

    #[test]
    fn round_trips_through_every_shell() {
        let args = nasty();
        let mut tried = Vec::new();
        for sh in SHELLS {
            if !crate::sys::which(sh) {
                continue;
            }
            // one at a time, so a failure names the argument
            for a in &args {
                let one = vec![a.clone()];
                assert_eq!(
                    through(sh, &one),
                    Some(want(&one)),
                    "{sh} with {a:?} quoted as {}",
                    remote(a)
                );
            }
            assert_eq!(through(sh, &args), Some(want(&args)), "{sh}, all at once");
            tried.push(*sh);
        }
        assert!(tried.contains(&"sh"), "no sh found");
    }

    #[test]
    fn random_argv_round_trips() {
        // a small xorshift: the same cases every run
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let alphabet: Vec<char> = "ab '\"\\$`!*?;&|<>(){}[]~#\n\t=%-.é漢".chars().collect();
        let mut args = Vec::new();
        for _ in 0..200 {
            let len = (next() % 12) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            args.push(s);
        }
        for sh in SHELLS {
            if crate::sys::which(sh) {
                assert_eq!(through(sh, &args), Some(want(&args)), "{sh}");
            }
        }
    }
}
