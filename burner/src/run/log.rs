use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use serde_json::Value;

use super::EXIT_USAGE;
use crate::config::Config;
use crate::exit::EXIT_FAILED;
use crate::json::{self, Kind};
use crate::ledger::valid_id;
use crate::netlog::{NetLog, Summary};
use crate::runlog::{Head, Kept, Store};

#[derive(Args)]
pub struct LogArgs {
    /// the run's id, the newest of yours without one
    #[arg(conflicts_with = "list")]
    id: Option<String>,
    /// the runs kept, newest first
    #[arg(long)]
    list: bool,
    /// only runs on this -H host, or `local` for this machine's (-H itself
    /// asks that host)
    #[arg(long, value_name = "HOST", requires = "list")]
    from: Option<String>,
    /// at most this many [default: 50]
    #[arg(long, value_name = "N", requires = "list")]
    limit: Option<usize>,
}

const LOG_USAGE: &str = "usage: burner log [burner-xxxxxxxxxxxx] or burner log --list";
/// rows --list shows without --limit
const LIST_DEFAULT: usize = 50;
/// the command in a --list row
const LIST_COMMAND: usize = 60;

impl LogArgs {
    /// burner's argv on the far end of -H. checked here: an id like
    /// -Hother would be a flag there
    pub fn remote_argv(&self) -> std::result::Result<Vec<String>, String> {
        let mut v = vec!["log".to_string()];
        if self.list {
            v.push("--list".into());
            if let Some(f) = &self.from {
                // one word, so a host that looks like a flag stays the value
                v.push(format!("--from={f}"));
            }
            if let Some(n) = self.limit {
                v.push(format!("--limit={n}"));
            }
            return Ok(v);
        }
        match &self.id {
            Some(id) if !valid_id(id) => Err(LOG_USAGE.into()),
            id => Ok(v.into_iter().chain(id.clone()).collect()),
        }
    }
}

/// burner log: a run's record and connection log, the newest of yours
/// without an id, or with --list the runs kept
pub fn log(cfg: &Config, a: &LogArgs) -> Result<ExitCode> {
    if let Some(id) = a.id.as_deref()
        && !valid_id(id)
    {
        return Ok(json::fail("log", EXIT_USAGE, Kind::Usage, LOG_USAGE));
    }
    let store = Store::open(cfg);
    if a.list {
        return Ok(list(&store, a));
    }
    let id = a.id.as_deref();
    let Some(k) = store.find(id) else {
        let sudo = match id {
            Some(id) => format!("sudo burner log {id}"),
            None => "sudo burner log".into(),
        };
        let msg = match (id, store.this_machine) {
            (Some(id), true) => format!(
                "{id}: no such run kept (the newest {} of each owner's, for {} days)",
                cfg.log.keep_runs, cfg.log.keep_days
            ),
            (None, true) => "no runs kept yet".into(),
            (Some(id), false) => format!(
                "{id}: not one of your -H runs kept here. this machine's own runs need root ({sudo})"
            ),
            (None, false) => format!(
                "none of your -H runs are kept here yet. this machine's own runs need root ({sudo})"
            ),
        };
        return Ok(json::fail("log", EXIT_FAILED, Kind::NotFound, msg));
    };
    let net = k.network();
    if !json::on() {
        let mut out = head_line(&k.head) + "\n";
        match &net {
            Some(l) => out += &format!("{}: {}", k.head.id, crate::netlog::table(l)),
            None if k.head.net == "none" => {
                out += &format!("{}: no network (--net none)\n", k.head.id)
            }
            None => out += &format!("{}: no connection log was kept for it\n", k.head.id),
        }
        print!("{out}");
    }
    Ok(json::reply("log", 0, Some(log_json(&k, net))))
}

/// burner log --json: the connection log's fields as 0.3.0 had them, an
/// empty one for a run without, and the record in `run`
fn log_json(k: &Kept, net: Option<NetLog>) -> Value {
    let h = &k.head;
    let log = net.unwrap_or_else(|| NetLog {
        id: h.id.clone(),
        net: h.net.clone(),
        platform: platform_of(k),
        owner: Some(h.owner),
        started_unix: h.started_unix,
        secs: 0.0,
        // nothing can be missing from a run that had no network
        complete: h.net == "none",
        lost: 0,
        not_itemized: 0,
        invalid: 0,
        summary: Summary::default(),
        events: Vec::new(),
    });
    let mut v = serde_json::to_value(&log).unwrap_or(Value::Null);
    if v.is_object() {
        v["run"] = k.run_json();
    }
    v
}

/// where a run without a log ran, from the VMM it says it had
fn platform_of(k: &Kept) -> String {
    if !k.copy {
        return std::env::consts::OS.into();
    }
    match k.result.pointer("/vm/backend").and_then(Value::as_str) {
        Some("firecracker") => "linux".into(),
        Some("libkrun") => "macos".into(),
        _ => "unknown".into(),
    }
}

fn list(store: &Store, a: &LogArgs) -> ExitCode {
    let from = a.from.as_deref();
    let keep = |h: &Head| match from {
        None => true,
        Some("local") => h.host.is_none(),
        Some(f) => h.host.as_deref() == Some(f),
    };
    let runs = store.list(keep, a.limit.unwrap_or(LIST_DEFAULT));
    if !json::on() {
        print!("{}", list_text(&runs));
        if !store.this_machine {
            eprintln!(
                "burner: these are your -H runs; this machine's own need root (sudo burner log --list)"
            );
        }
    }
    json::reply(
        "log",
        0,
        Some(serde_json::json!({ "runs": runs, "this_machine": store.this_machine })),
    )
}

fn list_text(runs: &[Head]) -> String {
    if runs.is_empty() {
        return "no runs kept\n".into();
    }
    let count = |n: Option<u64>| n.map_or_else(|| "-".into(), |n| n.to_string());
    let mut rows: Vec<[String; 10]> = vec![
        [
            "id", "when", "host", "img", "net", "tag", "exit", "out", "blocked", "command",
        ]
        .map(String::from),
    ];
    for h in runs {
        rows.push([
            h.id.clone(),
            when(h.started_unix),
            h.host.clone().unwrap_or_else(|| "local".into()),
            h.img.clone(),
            h.net.clone(),
            h.tag.clone().unwrap_or_else(|| "-".into()),
            exit_word(h),
            count(h.allowed),
            count(h.blocked),
            command_word(h, LIST_COMMAND),
        ]);
    }
    let mut w = [0usize; 10];
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count()).min(32);
        }
    }
    let mut s = String::new();
    for r in &rows {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            if i + 1 == r.len() {
                line += c;
            } else {
                line += &format!("{:<width$}  ", c, width = w[i]);
            }
        }
        s += &sanitize(line.trim_end());
        s.push('\n');
    }
    s
}

/// the line burner log opens with: date, host, image, exit, command
fn head_line(h: &Head) -> String {
    let exit = match (h.outcome.as_str(), h.rc) {
        ("exited", Some(rc)) => format!("exit {rc}"),
        (o, _) => format!("{o}, exit {}", h.exit),
    };
    sanitize(&format!(
        "{}  {}  {}  {exit}  {}",
        when(h.started_unix),
        h.host.as_deref().unwrap_or("local"),
        h.img,
        command_word(h, crate::runlog::COMMAND_CAP)
    ))
}

/// the exit column: the command's code, or how it ended when it didn't
fn exit_word(h: &Head) -> String {
    match (h.outcome.as_str(), h.rc) {
        ("exited", Some(rc)) => rc.to_string(),
        (o, _) => o.to_string(),
    }
}

fn command_word(h: &Head, max: usize) -> String {
    if h.shell {
        return "(shell)".into();
    }
    let n = h.command.chars().count();
    if n > max {
        h.command
            .chars()
            .take(max.saturating_sub(3))
            .collect::<String>()
            + "..."
    } else {
        h.command.clone()
    }
}

/// local time, to the minute
fn when(unix: u64) -> String {
    let t = libc::time_t::try_from(unix).unwrap_or(0);
    // SAFETY: localtime_r writes only the tm it's given
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return "-".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    )
}

/// what's printed passes the terminal filter: a copy's text came from
/// another machine
fn sanitize(s: &str) -> String {
    String::from_utf8_lossy(&crate::output::escape_controls(s.as_bytes())).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> Head {
        Head {
            record: 1,
            burner: "0.3.1".into(),
            id: "burner-0123456789ab".into(),
            host: Some("mini".into()),
            shell: false,
            command: format!("curl -fsSL https://example.com/{} | sh", "x".repeat(80)),
            img: "alpine".into(),
            net: "web".into(),
            tag: None,
            owner: 1000,
            started_unix: 1_795_000_000,
            secs: 2.0,
            exit: 3,
            outcome: "exited".into(),
            rc: Some(3),
            allowed: Some(6),
            blocked: Some(2),
        }
    }

    #[test]
    fn list_rows() {
        let mut shell = head();
        shell.shell = true;
        shell.host = None;
        shell.outcome = "detached".into();
        shell.rc = None;
        shell.allowed = None;
        shell.blocked = None;
        let t = list_text(&[head(), shell]);
        let lines: Vec<&str> = t.lines().collect();
        assert!(lines[0].starts_with("id  "), "{t}");
        assert!(lines[0].ends_with("exit      out  blocked  command"), "{t}");
        assert!(
            lines[1].contains("  mini   alpine  web  -    3         6    2        curl -fsSL"),
            "{t}"
        );
        assert!(lines[1].ends_with("..."), "{t}");
        assert!(
            lines[2].contains("  local  ") && lines[2].contains("detached  -    -        (shell)"),
            "{t}"
        );
        assert_eq!(list_text(&[]), "no runs kept\n");
    }

    #[test]
    fn opening_line() {
        let mut h = head();
        let l = head_line(&h);
        assert!(l.contains("  mini  alpine  exit 3  curl -fsSL"), "{l}");
        assert!(!l.ends_with("..."), "the whole kept command: {l}");
        h.outcome = "timeout".into();
        h.rc = None;
        h.exit = 124;
        h.host = Some("evil\x1b]0;x\x07".into());
        let l = head_line(&h);
        assert!(
            l.contains("timeout, exit 124") && !l.contains('\x1b'),
            "{l}"
        );
    }

    #[test]
    fn far_end_argv() {
        let a = |list, from: Option<&str>, limit, id: Option<&str>| LogArgs {
            id: id.map(String::from),
            list,
            from: from.map(String::from),
            limit,
        };
        assert_eq!(
            a(true, Some("-x"), Some(5), None).remote_argv().unwrap(),
            ["log", "--list", "--from=-x", "--limit=5"]
        );
        assert_eq!(
            a(false, None, None, Some("burner-0123456789ab"))
                .remote_argv()
                .unwrap(),
            ["log", "burner-0123456789ab"]
        );
        assert!(a(false, None, None, Some("-Hx")).remote_argv().is_err());
    }
}
