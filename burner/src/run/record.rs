//! how a run went, noted where burner decides it. the --status-fd line and
//! the json result are both made from this

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;

use super::{EXIT_INTERRUPTED, EXIT_USAGE};
use crate::json::{Kind, Problem};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Exited,
    Timeout,
    Killed,
    Interrupted,
    Busy,
    SandboxError,
    InputError,
    Poweroff,
    Reboot,
    /// the shell was left with ~.
    Detached,
    // reserved for -H, not written yet
    Unreachable,
    RemoteError,
    Lost,
}

impl RunOutcome {
    /// for --status-fd, whose readers only know the outcomes it had before
    /// remote hosts
    fn legacy(self) -> &'static str {
        match self {
            RunOutcome::Exited => "exited",
            RunOutcome::Timeout => "timeout",
            RunOutcome::Killed => "killed",
            RunOutcome::Interrupted => "interrupted",
            RunOutcome::Busy => "busy",
            RunOutcome::InputError => "input_error",
            RunOutcome::Poweroff => "poweroff",
            RunOutcome::Reboot => "reboot",
            RunOutcome::Detached => "detached",
            RunOutcome::SandboxError
            | RunOutcome::Unreachable
            | RunOutcome::RemoteError
            | RunOutcome::Lost => "sandbox_error",
        }
    }

    fn kind(self) -> Kind {
        match self {
            RunOutcome::Exited | RunOutcome::Detached | RunOutcome::SandboxError => Kind::Sandbox,
            RunOutcome::Timeout => Kind::Timeout,
            RunOutcome::Killed => Kind::Killed,
            RunOutcome::Interrupted => Kind::Interrupted,
            RunOutcome::Busy => Kind::Busy,
            RunOutcome::InputError => Kind::Input,
            RunOutcome::Poweroff => Kind::Poweroff,
            RunOutcome::Reboot => Kind::Reboot,
            RunOutcome::Unreachable => Kind::Unreachable,
            RunOutcome::RemoteError => Kind::RemoteError,
            RunOutcome::Lost => Kind::Lost,
        }
    }
}

/// how guest init said a shell ended
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShellEnd {
    Exit,
    Poweroff,
    Reboot,
    NoStart,
    Lost,
    /// an image whose guest init doesn't say
    Legacy,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct VmInfo {
    pub img: String,
    pub backend: &'static str,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
    pub ttl_secs: u32,
    pub net: &'static str,
    pub tag: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Timing {
    pub queue: Option<f64>,
    pub prepare: Option<f64>,
    pub boot: Option<f64>,
    pub command: Option<f64>,
    pub collect: Option<f64>,
    pub teardown: Option<f64>,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct OutputInfo {
    /// what the command wrote in all, null when the result never came
    pub bytes: Option<u64>,
    /// written to the caller while it ran
    pub live_bytes: u64,
    /// past the log's cap, not kept
    pub skipped_bytes: u64,
    /// a reader too slow for the live output lost some
    pub dropped: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct TarInfo {
    pub bytes: u64,
    pub delivered: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct RunResult {
    pub id: String,
    pub outcome: RunOutcome,
    /// the command's exit code, only when outcome is exited
    pub rc: Option<i32>,
    pub shell_end: Option<ShellEnd>,
    /// what guest init wrote to result/error: the guest's words, not burner's
    pub guest_error: Option<String>,
    pub secs: f64,
    pub timing_secs: Timing,
    pub vm: Option<VmInfo>,
    pub output: Option<OutputInfo>,
    pub result_tar: Option<TarInfo>,
    /// the connection log's place, null until it's recorded
    pub network: Option<()>,
    /// reserved for the report, null in schema 1 so far
    pub files: Option<()>,
    pub processes: Option<()>,
}

#[derive(Clone, Copy)]
pub(super) enum Mark {
    Queue,
    Slot,
    Launched,
    Begun,
    Ended,
}

#[derive(Default)]
struct Rec {
    id: Option<String>,
    outcome: Option<(RunOutcome, Option<i32>)>,
    /// why the outcome is what it is: errors[0]
    reason: Option<Problem>,
    shell_end: Option<ShellEnd>,
    guest_error: Option<String>,
    vm: Option<VmInfo>,
    marks: [Option<Instant>; 5],
    teardown: Option<Duration>,
    output: Option<OutputInfo>,
    result_tar: Option<TarInfo>,
}

static REC: Mutex<Option<Rec>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut Rec) -> T) -> T {
    let mut g = REC.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Rec::default))
}

/// how the run ended so far, and why when it's not a plain exit. a later
/// call wins, the reason it replaces stays in the errors
pub(super) fn set_outcome(o: RunOutcome, rc: Option<i32>, why: Option<(Kind, String)>) {
    with(|r| {
        r.outcome = Some((o, rc));
        if let Some(old) = r.reason.take() {
            crate::json::note_error(old.kind, old.message, false);
        }
        r.reason = why.map(|(kind, message)| Problem { kind, message });
    })
}

pub(super) fn set_id(id: &str) {
    with(|r| r.id = Some(id.into()))
}

pub(super) fn set_vm(vm: VmInfo) {
    with(|r| r.vm = Some(vm))
}

pub(super) fn set_shell_end(e: ShellEnd) {
    with(|r| r.shell_end = Some(e))
}

pub(super) fn set_guest_error(text: String) {
    with(|r| r.guest_error = Some(text))
}

pub(super) fn set_output(o: OutputInfo) {
    with(|r| r.output = Some(o))
}

pub(super) fn set_tar(t: TarInfo) {
    with(|r| r.result_tar = Some(t))
}

pub(super) fn mark(m: Mark) {
    mark_at(m, Instant::now())
}

pub(super) fn mark_at(m: Mark, t: Instant) {
    with(|r| {
        r.marks[m as usize].get_or_insert(t);
    })
}

pub(super) fn add_teardown(d: Duration) {
    with(|r| *r.teardown.get_or_insert_default() += d)
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0).round() / 1000.0
}

/// what a run ended with, for both the status line and the json
pub struct Finished {
    pub code: u8,
    /// failed on its arguments, before there was an outcome
    pub usage: bool,
    pub outcome: RunOutcome,
    pub rc: Option<i32>,
    pub id: Option<String>,
    /// unrounded, the status line rounds it its own way
    pub secs: f64,
    /// null for a usage error and for a run that failed before it had an id
    pub result: Option<RunResult>,
    /// why it ended the way it did, errors[0] in the json
    pub reason: Option<Problem>,
}

/// `start` is when burner started on the run, `failed` the error it ended
/// with, if it did
pub(super) fn finish(start: Instant, code: u8, failed: Option<Problem>) -> Finished {
    with(|r| r.finish(start, Instant::now(), code, failed))
}

impl Rec {
    fn finish(
        &mut self,
        start: Instant,
        now: Instant,
        code: u8,
        failed: Option<Problem>,
    ) -> Finished {
        let r = self;
        // a usage error never gets as far as an outcome, a command's own exit 2 does
        let usage = r.outcome.is_none() && code == EXIT_USAGE;
        let (outcome, rc) = r.outcome.unwrap_or(match code {
            EXIT_INTERRUPTED => (RunOutcome::Interrupted, None),
            _ => (RunOutcome::SandboxError, None),
        });
        let rc = rc.filter(|_| outcome == RunOutcome::Exited);
        // the error a run ended with is the last word on it
        let mut reason = match failed {
            Some(p) => {
                if let Some(old) = r.reason.take() {
                    crate::json::note_error(old.kind, old.message, false);
                }
                Some(p)
            }
            None => r.reason.take(),
        };
        if reason.is_none()
            && !matches!(outcome, RunOutcome::Exited | RunOutcome::Detached)
            && !usage
        {
            reason = Some(Problem {
                kind: outcome.kind(),
                message: format!("the run ended as {}", outcome.legacy()),
            });
        }
        let m = |i: Mark| r.marks[i as usize];
        let span = |a: Mark, b: Mark| Some(m(b)?.saturating_duration_since(m(a)?));
        let teardown = r.teardown.unwrap_or_default();
        let timing = Timing {
            queue: span(Mark::Queue, Mark::Slot).map(secs),
            prepare: m(Mark::Queue)
                .map(|q| q.saturating_duration_since(start))
                .zip(span(Mark::Slot, Mark::Launched))
                .map(|(a, b)| secs(a + b)),
            boot: span(Mark::Launched, Mark::Begun).map(secs),
            command: span(Mark::Begun, Mark::Ended).map(secs),
            collect: m(Mark::Ended)
                .map(|e| secs(now.saturating_duration_since(e).saturating_sub(teardown))),
            teardown: r.teardown.map(secs),
        };
        let total = secs(now.saturating_duration_since(start));
        let result = r.id.clone().filter(|_| !usage).map(|id| RunResult {
            id,
            outcome,
            rc,
            shell_end: r.shell_end,
            guest_error: r.guest_error.clone(),
            secs: total,
            timing_secs: timing,
            vm: r.vm.clone(),
            output: r.output.clone(),
            result_tar: r.result_tar.clone(),
            network: None,
            files: None,
            processes: None,
        });
        Finished {
            code,
            usage,
            outcome,
            rc,
            id: r.id.clone(),
            secs: now.saturating_duration_since(start).as_secs_f64(),
            result,
            reason,
        }
    }
}

impl Finished {
    /// the --status-fd line, byte for byte what burner wrote before the json:
    /// sorted keys, secs to a tenth, usage when the run never got going
    pub fn status_line(&self) -> String {
        let outcome = match self.usage {
            true => "usage",
            false => self.outcome.legacy(),
        };
        json!({"outcome": outcome, "rc": self.rc, "exit": self.code, "id": self.id,
               "secs": (self.secs * 10.0).round() / 10.0})
        .to_string()
            + "\n"
    }

    pub fn ok(&self) -> bool {
        self.result.is_some() && matches!(self.outcome, RunOutcome::Exited | RunOutcome::Detached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(o: Option<(RunOutcome, Option<i32>)>) -> Rec {
        Rec {
            id: Some("burner-3f9a1c2b7d10".into()),
            outcome: o,
            ..Default::default()
        }
    }

    fn line(o: Option<(RunOutcome, Option<i32>)>, code: u8) -> String {
        let t = Instant::now();
        rec(o)
            .finish(t, t + Duration::from_millis(10_449), code, None)
            .status_line()
    }

    #[test]
    fn status_line_as_before() {
        let id = "burner-3f9a1c2b7d10";
        let want = |o: &str, rc: &str, code: u8| {
            format!(r#"{{"exit":{code},"id":"{id}","outcome":"{o}","rc":{rc},"secs":10.4}}"#) + "\n"
        };
        assert_eq!(
            line(Some((RunOutcome::Exited, Some(3))), 3),
            want("exited", "3", 3)
        );
        // a command's own exit 2 isn't a usage error
        assert_eq!(
            line(Some((RunOutcome::Exited, Some(2))), 2),
            want("exited", "2", 2)
        );
        assert_eq!(
            line(Some((RunOutcome::Timeout, None)), 124),
            want("timeout", "null", 124)
        );
        assert_eq!(
            line(Some((RunOutcome::InputError, None)), 125),
            want("input_error", "null", 125)
        );
        assert_eq!(
            line(Some((RunOutcome::Poweroff, None)), 125),
            want("poweroff", "null", 125)
        );
        assert_eq!(
            line(Some((RunOutcome::Busy, None)), 125),
            want("busy", "null", 125)
        );
        // outcomes newer than the line map down to ones a wrapper knows
        for o in [
            RunOutcome::Unreachable,
            RunOutcome::RemoteError,
            RunOutcome::Lost,
        ] {
            assert_eq!(
                line(Some((o, None)), 125),
                want("sandbox_error", "null", 125)
            );
        }
        assert_eq!(line(None, 2), want("usage", "null", 2));
        assert_eq!(line(None, 130), want("interrupted", "null", 130));
        assert_eq!(line(None, 125), want("sandbox_error", "null", 125));
        let t = Instant::now();
        let none = Rec::default().finish(t, t, 125, None).status_line();
        assert_eq!(
            none,
            r#"{"exit":125,"id":null,"outcome":"sandbox_error","rc":null,"secs":0.0}"#.to_string()
                + "\n"
        );
    }

    #[test]
    fn run_result_json() {
        let t = Instant::now();
        let ms = |n| t + Duration::from_millis(n);
        let mut r = rec(Some((RunOutcome::Exited, Some(3))));
        r.vm = Some(VmInfo {
            img: "alpine".into(),
            backend: "firecracker",
            vcpus: 1,
            mem_mib: 512,
            disk_gib: 2,
            ttl_secs: 600,
            net: "web",
            tag: None,
        });
        r.marks = [
            Some(ms(100)),
            Some(ms(100)),
            Some(ms(500)),
            Some(ms(2100)),
            Some(ms(2600)),
        ];
        r.teardown = Some(Duration::from_millis(300));
        r.output = Some(OutputInfo {
            bytes: Some(1834),
            live_bytes: 1834,
            skipped_bytes: 0,
            dropped: false,
        });
        let f = r.finish(t, ms(3000), 3, None);
        assert!(f.ok() && f.reason.is_none());
        assert_eq!(
            serde_json::to_string(&f.result).unwrap(),
            r#"{"id":"burner-3f9a1c2b7d10","outcome":"exited","rc":3,"shell_end":null,"guest_error":null,"secs":3.0,"timing_secs":{"queue":0.0,"prepare":0.5,"boot":1.6,"command":0.5,"collect":0.1,"teardown":0.3},"vm":{"img":"alpine","backend":"firecracker","vcpus":1,"mem_mib":512,"disk_gib":2,"ttl_secs":600,"net":"web","tag":null},"output":{"bytes":1834,"live_bytes":1834,"skipped_bytes":0,"dropped":false},"result_tar":null,"network":null,"files":null,"processes":null}"#
        );
    }

    #[test]
    fn reasons() {
        let t = Instant::now();
        // a usage error has no result, whatever id it got
        let f = rec(None).finish(t, t, EXIT_USAGE, None);
        assert!(f.result.is_none() && f.usage && !f.ok());
        // the error a run ended with wins over what it noted before
        let mut r = rec(None);
        r.reason = Some(Problem {
            kind: Kind::Timeout,
            message: "a".into(),
        });
        let failed = Problem {
            kind: Kind::Busy,
            message: "b".into(),
        };
        let f = r.finish(t, t, 125, Some(failed.clone()));
        assert_eq!(f.reason, Some(failed));
        // a failure always says why, even where nothing did
        let f = rec(Some((RunOutcome::SandboxError, None))).finish(t, t, 125, None);
        assert_eq!(f.reason.map(|p| p.kind), Some(Kind::Sandbox));
        assert!(
            rec(Some((RunOutcome::Detached, None)))
                .finish(t, t, 0, None)
                .ok()
        );
    }
}
