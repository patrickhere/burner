//! the run log: one record for every run and shell, kept under paths.root,
//! plus the client's copy of each -H run. not built yet: keep stores
//! nothing, and prune is the connection logs' as before

use std::time::Instant;

use serde_json::Value;

use crate::config::Config;
use crate::run::RunArgs;
use crate::run::record::Finished;

/// how a run or shell ended, as it's handed to keep
pub enum Ended<'a> {
    /// a run or shell on this machine, the far end of -H included
    Here {
        cfg: &'a Config,
        args: &'a RunArgs,
        fin: &'a Finished,
    },
    /// the client of -H. `env` and `raw` are the far end's json, parsed and
    /// as it came, when it said how the run ended; None when the client
    /// decided it (unreachable, lost, interrupted)
    Remote {
        host: &'a str,
        args: &'a RunArgs,
        /// when the client started on the run
        t0: Instant,
        code: u8,
        env: Option<&'a Value>,
        raw: Option<&'a str>,
    },
}

/// called once at the end of every run and shell, just before the json goes
/// out. it must not fail the run or print anything the json would miss
pub fn keep(_e: Ended) {}

/// the reaper's pass over the kept logs
pub fn prune(cfg: &Config) {
    crate::netlog::prune(&cfg.paths.state, crate::netlog::KEEP);
}
