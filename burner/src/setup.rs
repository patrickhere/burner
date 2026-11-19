//! `burner setup` on macOS: the guest kernel and the alpine image from a
//! release, checked against its SHA256SUMS and put where burner looks for them.
//! curl, shasum and gzip all come with macOS, so no http or archive crates

use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::config::{self, Config};
use crate::ledger::Ledger;
use crate::sys;

const REPO: &str = "https://github.com/patrickhere/burner";
const KERNEL: &str = "vmlinux-aarch64";
const IMAGE: &str = "alpine-aarch64.ext4.gz";
const SUMS: &str = "SHA256SUMS";
// what tools/build-image puts next to the image
const ALPINE_DEFAULTS: &str = include_str!("../alpine-defaults.toml");

#[derive(Args)]
pub struct SetupArgs {
    /// a release tag (like v0.2.0) instead of this burner's own version. with no
    /// tag, the latest release
    #[arg(long, value_name = "TAG", num_args = 0..=1, default_missing_value = "latest")]
    version: Option<String>,
    /// fetch from this directory instead of a github release (https:// or file://).
    /// it has to hold SHA256SUMS and the release's files
    #[arg(long, value_name = "URL", conflicts_with = "version")]
    from: Option<String>,
}

pub fn main(cfg: &Config, a: SetupArgs) -> Result<ExitCode> {
    if sys::is_root() {
        bail!("on macOS burner runs as you, run setup without sudo");
    }
    if cfg!(not(target_arch = "aarch64")) {
        bail!("burner on macOS needs apple silicon");
    }
    let (base, proto) = source(&a)?;
    // checked again before the swap, this only saves a pointless download
    drop(idle(cfg)?);
    eprintln!("burner: fetching the guest kernel and the alpine image from {base}");

    let root = &cfg.paths.root;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .with_context(|| format!("creating {}", root.display()))?;
    config::trusted_file(root)?;
    let stage = Stage::new(root)?;

    fetch(&format!("{base}/{SUMS}"), proto, &stage.0.join(SUMS))?;
    let sums = fs::read_to_string(stage.0.join(SUMS)).context("reading SHA256SUMS")?;
    for name in [KERNEL, IMAGE] {
        let Some(want) = sum_for(&sums, name) else {
            bail!(
                "{name} isn't in the release's SHA256SUMS (releases before the macOS port don't have it)"
            );
        };
        let f = stage.0.join(name);
        fetch(&format!("{base}/{name}"), proto, &f)?;
        let got = sha256(&f)?;
        if got != want {
            bail!("checksum mismatch for {name}: SHA256SUMS says {want}, the download is {got}");
        }
        eprintln!("burner: {name} ok");
    }

    let rootfs = stage.0.join("rootfs.ext4");
    let out = File::create(&rootfs)?;
    let st = Command::new("gzip")
        .arg("-dc")
        .arg(stage.0.join(IMAGE))
        .stdin(Stdio::null())
        .stdout(out)
        .status()
        .context("running gzip")?;
    if !st.success() {
        bail!("gzip couldn't unpack {IMAGE}");
    }
    let defaults = stage.0.join("defaults.toml");
    fs::write(&defaults, ALPINE_DEFAULTS)?;
    let kernel = stage.0.join(KERNEL);
    for f in [&kernel, &rootfs, &defaults] {
        fs::set_permissions(f, fs::Permissions::from_mode(0o644))?;
    }

    // a VM opens the kernel and image by path while it starts, and holding the
    // ledger lock keeps new ones from starting while they're swapped
    let ledger = idle(cfg)?;
    let kdir = root.join("kernel");
    let idir = root.join("images/alpine");
    for d in [&kdir, &idir] {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(d)?;
    }
    fs::rename(&kernel, kdir.join("vmlinux"))?;
    fs::rename(&rootfs, idir.join("rootfs.ext4"))?;
    fs::rename(&defaults, idir.join("defaults.toml"))?;
    drop(ledger);

    println!("kernel  {}", kdir.join("vmlinux").display());
    println!("image   {}", idir.join("rootfs.ext4").display());
    println!("burner doctor checks the rest");
    Ok(ExitCode::SUCCESS)
}

/// the ledger, locked, when no VM is in it
fn idle(cfg: &Config) -> Result<Ledger> {
    let _ = crate::run::reap(cfg);
    let ledger = Ledger::open(&cfg.paths.state)?;
    if !ledger.all().is_empty() || !ledger.unreadable().is_empty() {
        bail!(
            "VMs are running (burner ls), stop them first so setup doesn't swap their kernel and image"
        );
    }
    Ok(ledger)
}

/// the base url of the release files, and the one protocol curl may use for them
fn source(a: &SetupArgs) -> Result<(String, &'static str)> {
    if let Some(from) = &a.from {
        let from = from.trim_end_matches('/').to_string();
        return if from.starts_with("https://") {
            Ok((from, "=https"))
        } else if from.starts_with("file://") {
            Ok((from, "=file"))
        } else {
            bail!("--from takes an https:// or file:// url")
        };
    }
    let tag = match a.version.as_deref() {
        None => format!("v{}", env!("CARGO_PKG_VERSION")),
        Some("latest") => latest()?,
        Some(t) => t.to_string(),
    };
    if !valid_tag(&tag) {
        bail!("{tag:?} doesn't look like a release tag");
    }
    Ok((format!("{REPO}/releases/download/{tag}"), "=https"))
}

/// github redirects releases/latest to releases/tag/TAG
fn latest() -> Result<String> {
    let out = sys::run_timeout(
        Command::new("curl")
            .args(["-fsSIL", "--proto", "=https", "--proto-redir", "=https"])
            .args(["--retry", "3", "--connect-timeout", "30"])
            .args(["-o", "/dev/null", "-w", "%{url_effective}"])
            .arg(format!("{REPO}/releases/latest")),
        None,
        Duration::from_secs(120),
    )
    .context("running curl")?;
    if !out.status.success() {
        bail!(
            "couldn't look up the latest release: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let url = String::from_utf8_lossy(&out.stdout);
    url.rsplit_once("/releases/tag/")
        .map(|(_, t)| t.to_string())
        .filter(|t| valid_tag(t))
        .context("couldn't tell the latest release from github's answer")
}

fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn fetch(url: &str, proto: &str, dest: &Path) -> Result<()> {
    let out = sys::run_timeout(
        Command::new("curl")
            .args(["-fsSL", "--proto", proto, "--proto-redir", proto])
            .args(["--retry", "3", "--connect-timeout", "30"])
            .arg("-o")
            .arg(dest)
            .arg(url),
        None,
        Duration::from_secs(30 * 60),
    )
    .context("running curl")?;
    if !out.status.success() {
        bail!(
            "download failed: {url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn sha256(f: &Path) -> Result<String> {
    let out = sys::run_timeout(
        Command::new("shasum").args(["-a", "256"]).arg(f),
        None,
        Duration::from_secs(5 * 60),
    )
    .context("running shasum")?;
    let text = String::from_utf8_lossy(&out.stdout);
    match text.split_whitespace().next() {
        Some(h) if out.status.success() && is_sha256(h) => Ok(h.to_ascii_lowercase()),
        _ => bail!("shasum couldn't hash {}", f.display()),
    }
}

/// the hash a sha256sum-style list has for one file name
fn sum_for(list: &str, name: &str) -> Option<String> {
    list.lines().find_map(|l| {
        let (hash, file) = l.split_once(char::is_whitespace)?;
        let file = file.trim_start();
        let file = file.strip_prefix('*').unwrap_or(file);
        (file == name && is_sha256(hash)).then(|| hash.to_ascii_lowercase())
    })
}

fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// a private dir under paths.root, on the same disk so renames out of it are
/// atomic, gone when setup ends either way
struct Stage(PathBuf);

impl Stage {
    fn new(root: &Path) -> Result<Stage> {
        let p = root.join(format!(".setup-{}", sys::random_hex(4)?));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .with_context(|| format!("creating {}", p.display()))?;
        Ok(Stage(p))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums() {
        let h = "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4";
        let list = format!(
            "{h}  burner-v1-x86_64-linux.tar.gz\n{}  vmlinux-aarch64\n{h} *alpine-aarch64.ext4.gz\nnope  vmlinux\n",
            h.to_uppercase()
        );
        assert_eq!(sum_for(&list, KERNEL).as_deref(), Some(h));
        assert_eq!(sum_for(&list, IMAGE).as_deref(), Some(h));
        assert_eq!(sum_for(&list, "vmlinux"), None);
        assert_eq!(sum_for(&list, "aarch64"), None);
    }

    #[test]
    fn tags() {
        assert!(valid_tag("v0.2.0"));
        assert!(valid_tag("v1.0.0-rc.1"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("v1/../x"));
        assert!(!valid_tag("v1?x=1"));
    }
}
