//! each VM runs in its own cgroup under /sys/fs/cgroup/burner. killing and
//! checking the cgroup is how burner knows a VM is really gone.

use std::fs;
use std::path::PathBuf;

pub const PARENT: &str = "burner";

fn path(id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup").join(PARENT).join(id)
}

pub fn populated(id: &str) -> bool {
    fs::read_to_string(path(id).join("cgroup.events")).is_ok_and(|e| e.contains("populated 1"))
}

pub fn kill(id: &str) {
    let _ = fs::write(path(id).join("cgroup.kill"), "1");
}

pub fn remove(id: &str) {
    let _ = fs::remove_dir(path(id));
}
