//! who holds which VM slot. one json file per VM under the state dir, all
//! changes under one flock so admission, updates and cleanup never interleave.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cgroup;
use crate::sys;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ident {
    pub pid: u32,
    pub start: u64,
    pub boot: String,
}

impl Ident {
    pub fn me() -> Ident {
        let pid = std::process::id();
        Ident {
            pid,
            start: sys::proc_start(pid).unwrap_or(0),
            boot: sys::boot_id(),
        }
    }

    pub fn alive(&self) -> bool {
        self.boot == sys::boot_id() && sys::proc_start(self.pid) == Some(self.start)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vm {
    pub id: String,
    pub tag: String,
    pub img: String,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub disk_gib: u32,
    pub net: String,
    pub ttl_secs: u32,
    pub wrapper: Option<Ident>,
    pub status: String,
    pub cancel: bool,
    pub started: u64,
    pub deadline_boot: Option<f64>,
    pub net_slot: Option<u32>,
}

impl Vm {
    pub fn holds_slot(&self) -> bool {
        self.wrapper.as_ref().is_some_and(Ident::alive)
            || cgroup::populated(&self.id)
            || self.status == "cleanup-failed"
    }
}

pub struct Ledger {
    dir: PathBuf,
    _lock: sys::Lock,
}

impl Ledger {
    pub fn open(state: &Path) -> Result<Ledger> {
        let dir = state.join("vms");
        fs::create_dir_all(&dir)?;
        let lock = sys::Lock::exclusive(&state.join("ledger.lock"))?;
        Ok(Ledger { dir, _lock: lock })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn all(&self) -> Vec<Vm> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| serde_json::from_slice(&fs::read(e.path()).ok()?).ok())
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<Vm> {
        serde_json::from_slice(&fs::read(self.path(id)).ok()?).ok()
    }

    /// false when the id is already taken
    pub fn create(&self, vm: &Vm) -> Result<bool> {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path(&vm.id))
        {
            Ok(mut f) => {
                f.write_all(&serde_json::to_vec(vm)?)?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// changes an existing entry; a deleted one stays deleted
    pub fn update(&self, id: &str, f: impl FnOnce(&mut Vm)) -> Result<Option<Vm>> {
        let Some(mut vm) = self.get(id) else {
            return Ok(None);
        };
        f(&mut vm);
        let tmp = self.dir.join(format!("{id}.json.tmp"));
        fs::write(&tmp, serde_json::to_vec(&vm)?)?;
        fs::rename(tmp, self.path(id))?;
        Ok(Some(vm))
    }

    pub fn delete(&self, id: &str) {
        let _ = fs::remove_file(self.path(id));
    }
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 19
        && id.starts_with("burner-")
        && id[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("burner-0123456789ab"));
        assert!(!valid_id("burner-0123456789AB"));
        assert!(!valid_id("burner-../../etc/x"));
        assert!(!valid_id("sbx-0123456789ab"));
    }

    #[test]
    fn dead_ident() {
        let me = Ident::me();
        assert!(me.alive());
        assert!(
            !Ident {
                boot: "other-boot".into(),
                ..me.clone()
            }
            .alive()
        );
        assert!(
            !Ident {
                start: me.start + 1,
                ..me
            }
            .alive()
        );
    }
}
