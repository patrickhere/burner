//! --json: every command writes one document, the envelope, with its own
//! result inside. the structs are the schema (docs/json.md): typed, so field
//! order is fixed, and nullable fields are always there

use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

/// bumped only when a field changes type or goes away. new fields and new
/// enum values don't bump it
pub const SCHEMA: u32 = 1;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Usage,
    NotRoot,
    Root,
    NoTty,
    UnknownImage,
    Config,
    Unsupported,
    Busy,
    NoReaper,
    NoPublicIp,
    DiskFull,
    Sandbox,
    Guest,
    Input,
    Timeout,
    Interrupted,
    Killed,
    Poweroff,
    Reboot,
    ResultLost,
    NotFound,
    NotOwner,
    StillStopping,
    DoctorFailed,
    Net,
    Io,
    // warnings
    Queued,
    Output,
    Vmm,
    Oom,
    Image,
    Result,
    Shell,
    Unverified,
    NoNet,
    // reserved for -H, not written yet
    Unreachable,
    RemoteError,
    Lost,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Problem {
    pub kind: Kind,
    /// burner's own words, never text from a guest
    pub message: String,
}

#[derive(Serialize)]
pub struct Envelope<'a, T: Serialize> {
    pub schema: u32,
    pub burner: &'static str,
    /// null only when the command line didn't parse far enough to say
    pub command: Option<&'a str>,
    /// the -H host, null when local
    pub host: Option<&'a str>,
    pub exit: u8,
    pub ok: bool,
    pub result: Option<T>,
    pub errors: Vec<Problem>,
    pub warnings: Vec<Problem>,
}

impl<'a, T: Serialize> Envelope<'a, T> {
    /// with the problems noted so far
    pub fn new(command: Option<&'a str>, exit: u8, ok: bool, result: Option<T>) -> Self {
        let (errors, warnings) = take();
        Envelope {
            schema: SCHEMA,
            burner: env!("CARGO_PKG_VERSION"),
            command,
            host: HOST.get().map(String::as_str),
            exit,
            ok,
            result,
            errors,
            warnings,
        }
    }

    pub fn line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default() + "\n"
    }
}

/// what another burner needs to know about this one before it sends it work
#[derive(Serialize)]
pub struct Version {
    pub version: &'static str,
    pub schema: u32,
    pub guest_proto: u32,
    pub backend: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
}

impl Version {
    pub fn this() -> Version {
        Version {
            version: env!("CARGO_PKG_VERSION"),
            schema: SCHEMA,
            guest_proto: crate::run::GUEST_PROTO,
            backend: crate::run::VMM,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        }
    }
}

static ON: OnceLock<bool> = OnceLock::new();
static HOST: OnceLock<String> = OnceLock::new();

/// set once by burner -H: the host every envelope from here on is about
pub fn set_host(name: &str) {
    let _ = HOST.set(name.to_string());
}
static NOTED: Mutex<(Vec<Problem>, Vec<Problem>)> = Mutex::new((Vec::new(), Vec::new()));

/// set once from main: --json was given
pub fn set_on(on: bool) {
    let _ = ON.set(on);
}

/// stdout is the envelope's, and burner's own lines go into it instead of stderr
pub fn on() -> bool {
    ON.get().copied().unwrap_or(false)
}

fn note(error: bool, kind: Kind, msg: String, print: bool) {
    if print {
        eprintln!("burner: {msg}");
    }
    let mut n = NOTED.lock().unwrap_or_else(|e| e.into_inner());
    let p = Problem { kind, message: msg };
    if error { n.0.push(p) } else { n.1.push(p) }
}

/// a burner line that doesn't fail the command: stderr, or a warning with --json
pub fn warn(kind: Kind, msg: impl Into<String>) {
    note(false, kind, msg.into(), !on());
}

/// why the command failed: stderr, or an error with --json
pub fn error(kind: Kind, msg: impl Into<String>) {
    note(true, kind, msg.into(), !on());
}

/// noted for the envelope only, `print` says whether it goes on stderr too
pub fn note_error(kind: Kind, msg: impl Into<String>, print: bool) {
    note(true, kind, msg.into(), print);
}

pub fn note_warning(kind: Kind, msg: impl Into<String>, print: bool) {
    note(false, kind, msg.into(), print);
}

pub fn has_errors() -> bool {
    !NOTED.lock().unwrap_or_else(|e| e.into_inner()).0.is_empty()
}

fn take() -> (Vec<Problem>, Vec<Problem>) {
    std::mem::take(&mut *NOTED.lock().unwrap_or_else(|e| e.into_inner()))
}

/// a whole line to an fd, with write(2) so it works on any fd number
pub fn write_fd(fd: i32, line: &str) {
    let mut b = line.as_bytes();
    while !b.is_empty() {
        // SAFETY: write(2) of a live buffer; a bad fd only gets EBADF
        let n = unsafe { libc::write(fd, b.as_ptr().cast(), b.len()) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            break;
        }
        b = &b[n as usize..];
    }
}

/// how a command other than run and shell ends: with --json its envelope on
/// stdout. ok unless it exits non-zero or noted an error
pub fn reply<T: Serialize>(command: &str, exit: u8, result: Option<T>) -> ExitCode {
    if on() {
        let ok = exit == 0 && !has_errors();
        write_fd(1, &Envelope::new(Some(command), exit, ok, result).line());
    }
    ExitCode::from(exit)
}

/// a command that failed before it had a result
pub fn fail(command: &str, exit: u8, kind: Kind, msg: impl Into<String>) -> ExitCode {
    error(kind, msg);
    reply::<()>(command, exit, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_fields_in_order() {
        let e = Envelope {
            schema: SCHEMA,
            burner: "0.3.0",
            command: Some("kill"),
            host: None,
            exit: 1,
            ok: false,
            result: None::<()>,
            errors: vec![Problem {
                kind: Kind::NotFound,
                message: "no VM with that id".into(),
            }],
            warnings: vec![],
        };
        assert_eq!(
            e.line(),
            r#"{"schema":1,"burner":"0.3.0","command":"kill","host":null,"exit":1,"ok":false,"result":null,"errors":[{"kind":"not_found","message":"no VM with that id"}],"warnings":[]}"#.to_string() + "\n"
        );
    }

    #[test]
    fn version_json() {
        let v = serde_json::to_value(Version::this()).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            ["arch", "backend", "guest_proto", "os", "schema", "version"]
        );
        assert_eq!(v["schema"], SCHEMA);
    }

    #[test]
    fn kinds_are_snake_case() {
        let k = |k: Kind| serde_json::to_string(&k).unwrap();
        assert_eq!(k(Kind::NotRoot), r#""not_root""#);
        assert_eq!(k(Kind::NoNet), r#""no_net""#);
        assert_eq!(k(Kind::DoctorFailed), r#""doctor_failed""#);
        assert_eq!(k(Kind::RemoteError), r#""remote_error""#);
    }
}
