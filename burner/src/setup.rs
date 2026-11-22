//! `burner setup`: the images (alpine, debian), checked and put where burner
//! looks for them, and on macOS the guest kernel too. on macOS they come from
//! the copy homebrew installed next to burner when there is one (the formula
//! pins the kernel and alpine and fetches them, and pins debian without
//! fetching it), else from a release. the kernel always has to match the
//! sha256 install.sh pins, built into burner, except with --from. on linux
//! see setup_linux.rs. curl, a sha256 tool and gzip come with both, so no
//! http or archive crates

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
#[cfg(target_os = "macos")]
use std::time::Instant;

use anyhow::{Context, Result, bail};
#[cfg(target_os = "macos")]
use clap::Args;

#[cfg(target_os = "macos")]
use crate::config;
use crate::config::Config;
use crate::json::{self, Kind};
use crate::ledger::Ledger;
use crate::sys;

#[cfg(target_os = "linux")]
#[path = "setup_linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
use linux::setup;
#[cfg(target_os = "linux")]
pub use linux::{SetupArgs, SetupResult};

const REPO: &str = "https://github.com/patrickhere/burner";
#[cfg(target_os = "macos")]
const KERNEL: &str = "vmlinux-aarch64";
const SUMS: &str = "SHA256SUMS";
/// what the formula writes next to the files it fetched: a sha256 for each
/// release file it pins but doesn't fetch, debian's image
#[cfg(target_os = "macos")]
const PINS: &str = "pins";
/// far over what a release carries (the kernel is ~20M, the images ~100M and
/// ~250M unpacked), low enough that a bad source can't fill the disk
const MAX_DOWNLOAD: u64 = 1 << 30;
const MAX_UNPACKED: u64 = 4 << 30;
const STAGE_PREFIX: &str = ".setup-";
/// the images burner's own release publishes, for each arch
const IMAGES: [&str; 2] = ["alpine", "debian"];
// what tools/build-image puts next to each image
const ALPINE_DEFAULTS: &str = include_str!("../alpine-defaults.toml");
const DEBIAN_DEFAULTS: &str = include_str!("../debian-defaults.toml");
/// the kernel install.sh pins for aarch64, read from it by build.rs
#[cfg(target_os = "macos")]
const KERNEL_SHA256: &str = env!("BURNER_KERNEL_SHA256");
/// a release's SHA256SUMS is a few lines, one per file
const MAX_SUMS: u64 = 64 << 10;
/// where an image the release doesn't have comes from instead
#[cfg(target_os = "macos")]
const NOT_IN_RELEASE: &str =
    "releases before the macOS port have no images, and before 0.3.0 no debian";
#[cfg(target_os = "linux")]
const NOT_IN_RELEASE: &str = "releases before 0.3.1 have no alpine image and no linux setup. \
     tools/build-image builds it here instead";

#[cfg(target_os = "macos")]
#[derive(Args)]
pub struct SetupArgs {
    /// the images to install, alpine when none are named
    #[arg(value_name = "IMAGE", value_parser = IMAGES)]
    images: Vec<String>,
    /// fetch from a github release (like v0.2.0) instead of the copy homebrew
    /// installed or this burner's own release. with no tag, the latest release
    #[arg(long, value_name = "TAG", num_args = 0..=1, default_missing_value = "latest")]
    version: Option<String>,
    /// fetch from this directory instead (https:// or file://). it has to hold
    /// SHA256SUMS and the release's files, and the files are checked only
    /// against that: the kernel's pinned checksum is skipped
    #[arg(long, value_name = "URL", conflicts_with = "version")]
    from: Option<String>,
    /// remove what setup installed
    #[arg(long, conflicts_with_all = ["images", "version", "from"])]
    remove: bool,
}

/// where the kernel and images come from
#[cfg(target_os = "macos")]
enum Source {
    /// the copy the homebrew formula installed, checked by brew against the
    /// formula's sha256s. a file it pins but didn't fetch comes from this
    /// burner's own release and has to match the formula's pin too
    Brew(PathBuf),
    /// a release: SHA256SUMS from the same place, and the kernel pin. true
    /// when it's this burner's own
    Release(String, bool),
    /// --from: only that dir's SHA256SUMS
    From(String, &'static str),
}

/// what fixes images that are missing or from another guest init, for the
/// hints in doctor and burner shell
#[cfg(target_os = "macos")]
pub(crate) fn fix_hint(imgs: &[String]) -> String {
    if imgs.iter().all(|i| IMAGES.contains(&i.as_str())) {
        format!("run burner setup {}", imgs.join(" "))
    } else {
        "rebuild it with this burner's guest init".into()
    }
}

/// the same on linux, where setup needs root and other images are built here.
/// nothing on linux points to it yet, the hints there still name build-image
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn fix_hint(imgs: &[String]) -> String {
    match imgs {
        _ if imgs.iter().all(|i| IMAGES.contains(&i.as_str())) => {
            format!("run sudo burner setup {}", imgs.join(" "))
        }
        [one] => format!("rebuild it: tools/build-image {one}"),
        _ => "rebuild them with tools/build-image".into(),
    }
}

/// the release file for an image, built for this cpu
fn asset(img: &str) -> String {
    format!("{img}-{}.ext4.gz", std::env::consts::ARCH)
}

/// the list of packages in it, next to it in the release
#[cfg(target_os = "linux")]
fn package_list(img: &str) -> String {
    format!("{img}-{}.packages", std::env::consts::ARCH)
}

/// the images named, each once, alpine when none are
fn wanted(images: &[String]) -> Vec<String> {
    let mut imgs: Vec<String> = Vec::new();
    for i in images {
        if !imgs.contains(i) {
            imgs.push(i.clone());
        }
    }
    if imgs.is_empty() {
        imgs.push("alpine".into());
    }
    imgs
}

fn defaults(img: &str) -> &'static str {
    match img {
        "debian" => DEBIAN_DEFAULTS,
        _ => ALPINE_DEFAULTS,
    }
}

/// "alpine", "alpine and debian"
#[cfg(target_os = "macos")]
fn and_list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

pub fn main(cfg: &Config, a: SetupArgs) -> Result<ExitCode> {
    // ctrl-c sets a flag instead of killing burner, so the stage dir goes and
    // curl or gzip with it
    crate::run::interrupted();
    #[cfg(target_os = "macos")]
    if a.remove {
        return remove(cfg);
    }
    match setup(cfg, a) {
        Err(e) if SWAPPING.load(Ordering::SeqCst) => Err(e.context(
            "setup stopped while it swapped in the new files, the kernel and image may not \
             match now: run it again",
        )),
        Err(_) if crate::run::is_interrupted() => Ok(json::fail(
            "setup",
            crate::run::EXIT_INTERRUPTED,
            Kind::Interrupted,
            "setup interrupted, nothing was changed",
        )),
        r => r,
    }
}

/// set once the first installed file is replaced: past that, a failure has
/// changed something
static SWAPPING: AtomicBool = AtomicBool::new(false);

/// between the slow steps: ctrl-c only sets a flag, nothing stops on its own
fn go_on() -> Result<()> {
    if crate::run::is_interrupted() {
        bail!("interrupted");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn setup(cfg: &Config, a: SetupArgs) -> Result<ExitCode> {
    if sys::is_root() {
        bail!("on macOS burner runs as you, run setup without sudo");
    }
    if cfg!(not(target_arch = "aarch64")) {
        bail!("burner on macOS needs apple silicon");
    }
    let imgs = wanted(&a.images);
    let src = source(&a)?;
    // checked again before the swap, this only saves a pointless download
    drop(idle(cfg, "swap their kernel and image")?);
    go_on()?;

    let root = &cfg.paths.root;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .with_context(|| format!("creating {}", root.display()))?;
    config::trusted_file(root)?;
    sys::private_dir(&cfg.paths.state)?;
    let _setup = sys::Lock::exclusive_until(&cfg.paths.state.join("setup.lock"), Instant::now())
        .map_err(|_| anyhow::anyhow!("another burner setup is running"))?;
    sweep(root);
    {
        let _no_vms = idle(cfg, "swap their kernel and image")?;
        recover_all(root)?;
    }
    let stage = Stage::new(root)?;
    let files: Vec<String> = std::iter::once(KERNEL.to_string())
        .chain(imgs.iter().map(|i| asset(i)))
        .collect();
    match &src {
        Source::Brew(dir) => {
            // what the formula fetched, and the rest from this burner's release
            let (have, fetch): (Vec<String>, Vec<String>) =
                files.iter().cloned().partition(|f| dir.join(f).is_file());
            let what: Vec<String> = have.iter().map(|f| describe(f)).collect();
            say(&format!(
                "{} homebrew installed with burner, from {}",
                and_list(&what),
                dir.display()
            ));
            for name in &have {
                let from = dir.join(name);
                config::trusted_file(&from)?;
                go_on()?;
                fs::copy(&from, stage.0.join(name))
                    .with_context(|| format!("copying {}", from.display()))?;
            }
            if !fetch.is_empty() {
                let pins = dir.join(PINS);
                let pins = if pins.exists() {
                    config::trusted_file(&pins)?;
                    fs::read_to_string(&pins)
                        .with_context(|| format!("reading {}", pins.display()))?
                } else {
                    String::new()
                };
                let v = env!("CARGO_PKG_VERSION");
                let pinned = fetch
                    .iter()
                    .map(|f| match sum_for(&pins, f) {
                        Some(h) if placeholder(&h) => Err(anyhow::anyhow!(
                            "the homebrew formula's sha256 for {f} is still the all-zero \
                             placeholder, so it pins nothing. brew update && brew upgrade \
                             burner gets the real one, or burner setup --version v{v} fetches \
                             it checked only against the release's SHA256SUMS"
                        )),
                        Some(h) => Ok((f.clone(), h)),
                        None => Err(anyhow::anyhow!(
                            "the homebrew formula pins no sha256 for {f}. burner setup \
                             --version v{v} fetches it checked only against the release's \
                             SHA256SUMS"
                        )),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let base = own_release();
                say(&format!("fetching {} from {base}", fetch.join(", ")));
                download(&base, "=https", &stage.0, &fetch)?;
                for (f, want) in pinned {
                    let got = sha256(&stage.0.join(&f))?;
                    if got != want {
                        bail!(
                            "{f} is {got}, not the {want} the homebrew formula pins. \
                             nothing was changed"
                        );
                    }
                    say(&format!(
                        "{f} matches SHA256SUMS and the sha256 homebrew pinned"
                    ));
                }
            }
        }
        Source::Release(base, _) => {
            say(&format!("fetching {} from {base}", files.join(", ")));
            download(base, "=https", &stage.0, &files)?;
        }
        Source::From(base, proto) => {
            json::warn(
                Kind::Unverified,
                format!(
                    "fetching from {base}. --from skips the kernel checksum built into \
                     burner, the files are checked only against the SHA256SUMS there"
                ),
            );
            download(base, proto, &stage.0, &files)?;
        }
    }
    if !matches!(src, Source::From(..)) {
        let got = sha256(&stage.0.join(KERNEL))?;
        if got != KERNEL_SHA256 {
            bail!(
                "the kernel is {got}, not the {KERNEL_SHA256} this burner pins. \
                 if you meant to use another kernel, --from skips the pin"
            );
        }
        say(&format!("{KERNEL} matches the pinned sha256"));
    }
    if matches!(src, Source::Release(..)) {
        json::warn(
            Kind::Unverified,
            "the images are checked only against the release's own SHA256SUMS, \
             which comes from the same place. gh attestation verify checks where they were built",
        );
    }

    // the guest init an image was built with, what burner shell checks to
    // know the image tells it when the shell is ready. only known for an image
    // from this burner's own release; any other one counts as built with
    // another init, and the shell falls back to how older images worked
    let own = matches!(src, Source::Brew(_) | Source::Release(_, true));
    let kernel = stage.0.join(KERNEL);
    fs::set_permissions(&kernel, fs::Permissions::from_mode(0o644))?;
    for img in &imgs {
        let d = stage.0.join(img);
        fs::DirBuilder::new().mode(0o755).create(&d)?;
        let rootfs = d.join("rootfs.ext4");
        gunzip(&stage.0.join(asset(img)), &rootfs)?;
        fs::write(d.join("defaults.toml"), defaults(img))?;
        if own {
            fs::write(d.join("init"), crate::doctor::GUEST_INIT)?;
        }
        for f in ["rootfs.ext4", "defaults.toml"]
            .into_iter()
            .chain(own.then_some("init"))
        {
            fs::set_permissions(d.join(f), fs::Permissions::from_mode(0o644))?;
        }
    }

    go_on()?;
    // a VM opens the kernel and image by path while it starts, and holding the
    // ledger lock keeps new ones from starting while they're swapped
    let ledger = idle(cfg, "swap their kernel and image")?;
    go_on()?;
    let kdir = root.join("kernel");
    let idirs: Vec<PathBuf> = imgs.iter().map(|i| root.join("images").join(i)).collect();
    for d in [&kdir, &root.join("images")] {
        real_dir(d)?;
    }
    // before anything is swapped, so a refusal changes nothing
    for d in &idirs {
        recover(d)?;
        replaceable(d)?;
    }
    SWAPPING.store(true, Ordering::SeqCst);
    fs::rename(&kernel, kdir.join("vmlinux"))?;
    // each image dir whole, with its defaults and init, in one step
    for (img, idir) in imgs.iter().zip(&idirs) {
        swap_dir(&stage.0.join(img), idir)?;
    }
    drop(ledger);

    let res = SetupResult {
        source: match &src {
            Source::Brew(_) => "brew",
            Source::Release(..) => "release",
            Source::From(..) => "from",
        },
        from: match &src {
            Source::Brew(dir) => dir.display().to_string(),
            Source::Release(base, _) | Source::From(base, _) => base.clone(),
        },
        kernel_pinned: !matches!(src, Source::From(..)),
        kernel: kdir.join("vmlinux").display().to_string(),
        images: idirs
            .iter()
            .map(|d| d.join("rootfs.ext4").display().to_string())
            .collect(),
    };
    if !json::on() {
        println!("kernel  {}", res.kernel);
        for i in &res.images {
            println!("image   {i}");
        }
        println!("burner doctor checks the rest");
    }
    Ok(json::reply("setup", 0, Some(res)))
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
pub struct SetupResult {
    /// brew, release or from
    pub source: &'static str,
    /// the dir homebrew installed, or the url the files came from
    pub from: String,
    /// the kernel matched the sha256 built into burner (not with --from)
    pub kernel_pinned: bool,
    pub kernel: String,
    /// each image's rootfs, in the order they were named
    pub images: Vec<String>,
}

/// burner setup --remove: the kernel and the images setup installs, and the
/// stage dirs a setup that was killed left. the rest of the dir (the config,
/// the run log, images from somewhere else) stays, and it says what's left
#[cfg(target_os = "macos")]
fn remove(cfg: &Config) -> Result<ExitCode> {
    if sys::is_root() {
        bail!("on macOS burner runs as you, run setup --remove without sudo");
    }
    let root = &cfg.paths.root;
    let mut removed: Vec<PathBuf> = Vec::new();
    if root.exists() {
        config::trusted_file(root)?;
        sys::private_dir(&cfg.paths.state)?;
        let _setup =
            sys::Lock::exclusive_until(&cfg.paths.state.join("setup.lock"), Instant::now())
                .map_err(|_| anyhow::anyhow!("another burner setup is running"))?;
        // no VM may be using the kernel or an image, and none starts meanwhile
        let ledger = idle(cfg, "remove their kernel and image")?;
        sweep(root);
        recover_all(root)?;
        let kernel = root.join("kernel").join("vmlinux");
        let imgs = IMAGES.iter().map(|i| root.join("images").join(i));
        for p in std::iter::once(kernel).chain(imgs) {
            // a symlink goes, what it points to stays
            let Ok(m) = p.symlink_metadata() else {
                continue;
            };
            if m.is_dir() {
                if !sys::remove_tree_at(&p) {
                    bail!("couldn't remove all of {}", p.display());
                }
            } else {
                fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
            }
            removed.push(p);
        }
        // only once they're empty
        let _ = fs::remove_dir(root.join("kernel"));
        let _ = fs::remove_dir(root.join("images"));
        drop(ledger);
    }
    let res = RemoveResult {
        dir: root.display().to_string(),
        removed: removed.iter().map(|p| p.display().to_string()).collect(),
        left: left_in(root),
    };
    if !json::on() {
        if res.removed.is_empty() {
            println!("nothing of setup's was in {}", res.dir);
        }
        for p in &res.removed {
            println!("removed {p}");
        }
        if !res.left.is_empty() {
            println!(
                "left in {}: {}. delete that dir to remove them too",
                res.dir,
                res.left.join(", ")
            );
        }
        println!("brew uninstall burner removes burner itself");
    }
    Ok(json::reply("setup", 0, Some(res)))
}

/// what's in the dir that setup didn't put there, images/NAME for each image
#[cfg(target_os = "macos")]
fn left_in(root: &Path) -> Vec<String> {
    let names = |d: &Path| -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    };
    names(root)
        .into_iter()
        .flat_map(|n| match n.as_str() {
            "images" => names(&root.join("images"))
                .into_iter()
                .map(|i| format!("images/{i}"))
                .collect(),
            _ => vec![n],
        })
        .collect()
}

#[cfg(target_os = "macos")]
#[derive(serde::Serialize)]
pub struct RemoveResult {
    /// paths.root
    pub dir: String,
    pub removed: Vec<String>,
    /// what's still in dir, images/NAME for each image left
    pub left: Vec<String>,
}

/// a dir setup writes into, made when it isn't there: never a symlink, and
/// nobody but its owner and root may write it
fn real_dir(d: &Path) -> Result<()> {
    match d.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o755)
                .create(d)
                .with_context(|| format!("creating {}", d.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("checking {}", d.display())),
        Ok(m) if !m.is_dir() => bail!(
            "{} isn't a directory, so setup won't write there",
            d.display()
        ),
        Ok(_) => {}
    }
    crate::config::trusted_file(d)
}

/// put the dir `new`, complete, at `dest` in one step: a rename when dest
/// isn't there, else an exchange, after which the old dir is at `new`, in the
/// stage dir that goes when setup ends. where the filesystem can't exchange,
/// two renames: the old dir to .NAME.old next to it, then the new one in. a
/// setup killed in between leaves the old one there, and the next setup puts
/// it back (`recover`)
fn swap_dir(new: &Path, dest: &Path) -> Result<()> {
    if !replaceable(dest)? {
        return fs::rename(new, dest).with_context(|| format!("moving in {}", dest.display()));
    }
    if exchange(new, dest).with_context(|| format!("swapping in {}", dest.display()))? {
        return Ok(());
    }
    let old = kept_old(dest);
    fs::rename(dest, &old).with_context(|| format!("moving {} aside", dest.display()))?;
    if let Err(e) = fs::rename(new, dest) {
        let _ = fs::rename(&old, dest);
        return Err(e).with_context(|| format!("moving in {}", dest.display()));
    }
    // one left behind goes at the next setup
    sys::remove_tree_at(&old);
    Ok(())
}

/// where swap_dir keeps the old image dir between its two renames
fn kept_old(dest: &Path) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    dest.with_file_name(format!(".{name}.old"))
}

/// what a setup killed mid-swap left, for every image setup installs, right
/// after the setup lock and before anything is fetched, so a setup that then
/// fails (offline, say) has still put the old image back. with the ledger
/// locked, so no VM starts meanwhile
fn recover_all(root: &Path) -> Result<()> {
    real_dir(&root.join("images"))?;
    for img in IMAGES {
        recover(&root.join("images").join(img))?;
    }
    Ok(())
}

/// an image dir a setup killed between swap_dir's two renames left aside:
/// back in its place when that's empty, else gone
fn recover(dest: &Path) -> Result<()> {
    let old = kept_old(dest);
    match old.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("checking {}", old.display())),
        Ok(m) if !m.is_dir() => bail!("{} isn't a directory", old.display()),
        Ok(_) => {}
    }
    match dest.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // only a dir nobody else could have put there goes back
            crate::config::trusted_file(&old)?;
            fs::rename(&old, dest).with_context(|| format!("putting back {}", dest.display()))
        }
        _ if sys::remove_tree_at(&old) => Ok(()),
        _ => bail!("couldn't remove {}", old.display()),
    }
}

/// whether there's an image dir at dest to replace. anything but a dir
/// there, a symlink included, or one someone else can write, is an error
fn replaceable(dest: &Path) -> Result<bool> {
    match dest.symlink_metadata() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("checking {}", dest.display())),
        Ok(m) if !m.is_dir() => bail!(
            "{} isn't a directory, so setup won't replace it",
            dest.display()
        ),
        Ok(_) => crate::config::trusted_file(dest).map(|()| true),
    }
}

/// swap two paths in one rename. false when the filesystem can't
fn exchange(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let bad = |_| std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let a = CString::new(a.as_os_str().as_bytes()).map_err(bad)?;
    let b = CString::new(b.as_os_str().as_bytes()).map_err(bad)?;
    // SAFETY: renameat2(2) with two nul-terminated paths that outlive the call
    #[cfg(target_os = "linux")]
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    // SAFETY: renamex_np(2) with two nul-terminated paths that outlive the call
    #[cfg(target_os = "macos")]
    let r = unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) } as libc::c_long;
    if r == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => Ok(false),
        _ => Err(e),
    }
}

/// progress, on stderr and not in the json
fn say(msg: &str) {
    if !json::on() {
        eprintln!("burner: {msg}");
    }
}

/// the ledger, locked, when no VM is in it. `what` setup would do to theirs
fn idle(cfg: &Config, what: &str) -> Result<Ledger> {
    let _ = crate::run::reap(cfg);
    go_on()?;
    let ledger = Ledger::open(&cfg.paths.state)?;
    if !ledger.all().is_empty() || !ledger.unreadable().is_empty() {
        bail!("VMs are running (burner ls), stop them first so setup doesn't {what}");
    }
    Ok(ledger)
}

#[cfg(target_os = "macos")]
fn source(a: &SetupArgs) -> Result<Source> {
    if let Some(from) = &a.from {
        let from = from.trim_end_matches('/').to_string();
        return if from.starts_with("https://") {
            Ok(Source::From(from, "=https"))
        } else if from.starts_with("file://") {
            Ok(Source::From(from, "=file"))
        } else {
            bail!("--from takes an https:// or file:// url")
        };
    }
    if a.version.is_none()
        && let Some(dir) = brew_copy()
    {
        return Ok(Source::Brew(dir));
    }
    let tag = match a.version.as_deref() {
        None => format!("v{}", env!("CARGO_PKG_VERSION")),
        Some("latest") => latest()?,
        Some(t) => t.to_string(),
    };
    if !valid_tag(&tag) {
        bail!("{tag:?} doesn't look like a release tag");
    }
    let own = tag == format!("v{}", env!("CARGO_PKG_VERSION"));
    Ok(Source::Release(
        format!("{REPO}/releases/download/{tag}"),
        own,
    ))
}

/// this burner's own release
fn own_release() -> String {
    format!("{REPO}/releases/download/v{}", env!("CARGO_PKG_VERSION"))
}

/// the guest kernel, the alpine image
#[cfg(target_os = "macos")]
fn describe(file: &str) -> String {
    match file.strip_suffix("-aarch64.ext4.gz") {
        Some(img) => format!("the {img} image"),
        None => "the guest kernel".into(),
    }
}

/// share/burner next to the bin dir this burner runs from, where the formula
/// puts the kernel and image it fetched
#[cfg(target_os = "macos")]
fn brew_copy() -> Option<PathBuf> {
    let dir = sys::self_exe().parent()?.parent()?.join("share/burner");
    [KERNEL.to_string(), asset("alpine")]
        .iter()
        .all(|f| dir.join(f).is_file())
        .then_some(dir)
}

/// SHA256SUMS and the files from base into dir, each checked against it
#[cfg(target_os = "macos")]
fn download(base: &str, proto: &str, dir: &Path, files: &[String]) -> Result<()> {
    let sums = fetch_sums(base, proto, dir)?;
    download_listed(base, proto, dir, files, &sums)
}

/// base's SHA256SUMS, fetched into dir
fn fetch_sums(base: &str, proto: &str, dir: &Path) -> Result<String> {
    fetch(&format!("{base}/{SUMS}"), proto, &dir.join(SUMS), MAX_SUMS)?;
    fs::read_to_string(dir.join(SUMS)).context("reading SHA256SUMS")
}

/// the files from base into dir, each checked against sums
fn download_listed(
    base: &str,
    proto: &str,
    dir: &Path,
    files: &[String],
    sums: &str,
) -> Result<()> {
    for name in files {
        let Some(want) = sum_for(sums, name) else {
            bail!("{name} isn't in the release's SHA256SUMS ({NOT_IN_RELEASE})");
        };
        let f = dir.join(name);
        fetch(&format!("{base}/{name}"), proto, &f, MAX_DOWNLOAD)?;
        let got = sha256(&f)?;
        if got != want {
            bail!("checksum mismatch for {name}: SHA256SUMS says {want}, the download is {got}");
        }
        say(&format!("{name} matches SHA256SUMS"));
    }
    Ok(())
}

/// github redirects releases/latest to releases/tag/TAG
#[cfg(target_os = "macos")]
fn latest() -> Result<String> {
    let out = sys::run_until(
        Command::new("curl")
            .args(["-fsSIL", "--proto", "=https", "--proto-redir", "=https"])
            .args(["--retry", "3", "--connect-timeout", "30"])
            .args(["-o", "/dev/null", "-w", "%{url_effective}"])
            .arg(format!("{REPO}/releases/latest")),
        None,
        Duration::from_secs(120),
        &crate::run::is_interrupted,
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

#[cfg(target_os = "macos")]
fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn fetch(url: &str, proto: &str, dest: &Path, max: u64) -> Result<()> {
    let out = sys::run_until(
        Command::new("curl")
            .args(["-fsSL", "--proto", proto, "--proto-redir", proto])
            .args(["--retry", "3", "--connect-timeout", "30"])
            .args(["--max-filesize", &max.to_string()])
            .arg("-o")
            .arg(dest)
            .arg(url),
        None,
        Duration::from_secs(30 * 60),
        &crate::run::is_interrupted,
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

/// gzip -dc src into dest, no bigger than MAX_UNPACKED
fn gunzip(src: &Path, dest: &Path) -> Result<()> {
    let mut child = Command::new("gzip")
        .arg("-dc")
        .arg(src)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("running gzip")?;
    let mut from = child.stdout.take().context("gzip's output")?;
    let copied = (|| -> Result<()> {
        let mut to = File::create(dest)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut n = 0u64;
        loop {
            if crate::run::is_interrupted() {
                bail!("interrupted");
            }
            let got = from.read(&mut buf)?;
            if got == 0 {
                return Ok(());
            }
            n += got as u64;
            if n > MAX_UNPACKED {
                bail!(
                    "{} unpacks to more than {} GiB",
                    src.display(),
                    MAX_UNPACKED >> 30
                );
            }
            to.write_all(&buf[..got])?;
        }
    })();
    if copied.is_err() {
        // SAFETY: plain kill(2) on gzip's own process group
        unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) };
    }
    drop(from);
    let st = child.wait().context("waiting for gzip")?;
    copied?;
    if !st.success() {
        bail!("gzip couldn't unpack {}", src.display());
    }
    Ok(())
}

fn sha256(f: &Path) -> Result<String> {
    // shasum is perl, not on every linux; sha256sum isn't on a mac
    #[cfg(target_os = "macos")]
    let (tool, args) = ("shasum", &["-a", "256"][..]);
    #[cfg(target_os = "linux")]
    let (tool, args): (&str, &[&str]) = ("sha256sum", &[]);
    let out = sys::run_until(
        Command::new(tool).args(args).arg(f),
        None,
        Duration::from_secs(5 * 60),
        &crate::run::is_interrupted,
    )
    .with_context(|| format!("running {tool}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match text.split_whitespace().next() {
        Some(h) if out.status.success() && is_sha256(h) => Ok(h.to_ascii_lowercase()),
        _ => bail!("{tool} couldn't hash {}", f.display()),
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

/// the formula's pin before a release fills it in
#[cfg(target_os = "macos")]
fn placeholder(h: &str) -> bool {
    h.bytes().all(|b| b == b'0')
}

fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// stage dirs a setup that was killed outright left behind. only called with
/// the setup lock held, so none of them is in use
fn sweep(root: &Path) {
    for e in fs::read_dir(root).into_iter().flatten().flatten() {
        let name = e.file_name();
        let stale = name
            .to_str()
            .and_then(|n| n.strip_prefix(STAGE_PREFIX))
            .is_some_and(|h| h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit()));
        if stale && e.file_type().is_ok_and(|t| t.is_dir()) {
            sys::remove_tree_at(&e.path());
        }
    }
}

/// a private dir under paths.root, on the same disk so renames out of it are
/// atomic, gone when setup ends either way
struct Stage(PathBuf);

impl Stage {
    fn new(root: &Path) -> Result<Stage> {
        let p = root.join(format!("{STAGE_PREFIX}{}", sys::random_hex(4)?));
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
        assert_eq!(sum_for(&list, "vmlinux-aarch64").as_deref(), Some(h));
        assert_eq!(sum_for(&list, "alpine-aarch64.ext4.gz").as_deref(), Some(h));
        assert_eq!(sum_for(&list, "debian-aarch64.ext4.gz"), None);
        assert_eq!(
            sum_for(&list, "burner-v1-x86_64-linux.tar.gz").as_deref(),
            Some(h)
        );
        assert_eq!(sum_for(&list, "vmlinux"), None);
        assert_eq!(sum_for(&list, "aarch64"), None);
    }

    #[test]
    fn images() {
        let arch = std::env::consts::ARCH;
        assert!(["x86_64", "aarch64"].contains(&arch));
        assert_eq!(asset("alpine"), format!("alpine-{arch}.ext4.gz"));
        assert_eq!(asset("debian"), format!("debian-{arch}.ext4.gz"));
        #[cfg(target_os = "macos")]
        {
            assert_eq!(asset("debian"), "debian-aarch64.ext4.gz");
            assert_eq!(describe(KERNEL), "the guest kernel");
            assert_eq!(describe(&asset("debian")), "the debian image");
            assert_eq!(
                fix_hint(&["alpine".into(), "debian".into()]),
                "run burner setup alpine debian"
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(package_list("debian"), format!("debian-{arch}.packages"));
            assert_eq!(
                fix_hint(&["alpine".into(), "debian".into()]),
                "run sudo burner setup alpine debian"
            );
            assert_eq!(
                fix_hint(&["mine".into()]),
                "rebuild it: tools/build-image mine"
            );
        }
        assert!(fix_hint(&["debian".into(), "mine".into()]).starts_with("rebuild"));
        assert_eq!(wanted(&[]), ["alpine"]);
        assert_eq!(
            wanted(&["debian".into(), "alpine".into(), "debian".into()]),
            ["debian", "alpine"]
        );
        #[cfg(target_os = "macos")]
        {
            assert_eq!(and_list(&["a".into()]), "a");
            assert_eq!(
                and_list(&["a".into(), "b".into(), "c".into()]),
                "a, b and c"
            );
        }
        // the keys run reads from an image's defaults.toml
        for img in IMAGES {
            let t: toml::Table = toml::from_str(defaults(img)).unwrap();
            assert!(!t.is_empty(), "{img}");
            for (k, v) in &t {
                assert!(
                    ["vcpus", "mem_mib", "disk_gib", "ttl_secs"].contains(&k.as_str()),
                    "{img} {k}"
                );
                assert!(v.as_integer().is_some_and(|n| n > 0), "{img} {k}");
            }
        }
    }

    #[test]
    fn image_dirs_swap_whole() {
        let t = std::env::temp_dir().join(format!("burner-swap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        let (new, dest) = (t.join("stage-alpine"), t.join("alpine"));
        let put = |d: &Path, what: &str| {
            fs::create_dir_all(d).unwrap();
            fs::write(d.join("rootfs.ext4"), what).unwrap();
        };
        let has = |d: &Path| fs::read_to_string(d.join("rootfs.ext4")).ok();
        // nothing there yet: moved in
        put(&new, "one");
        swap_dir(&new, &dest).unwrap();
        assert_eq!(has(&dest).as_deref(), Some("one"));
        // there: the new one in, the old one out where the new one was
        put(&new, "two");
        fs::write(dest.join("base"), "from build-image").unwrap();
        swap_dir(&new, &dest).unwrap();
        assert_eq!(has(&dest).as_deref(), Some("two"));
        assert!(!dest.join("base").exists());
        assert!(!new.exists() || has(&new).as_deref() == Some("one"));
        // a symlink there is refused, before and during
        let link = t.join("linked");
        std::os::unix::fs::symlink(&dest, &link).unwrap();
        assert!(replaceable(&link).is_err());
        put(&new, "three");
        assert!(swap_dir(&new, &link).is_err());
        assert_eq!(has(&dest).as_deref(), Some("two"));
        // a setup killed between the two renames: the old one comes back
        fs::rename(&dest, kept_old(&dest)).unwrap();
        recover(&dest).unwrap();
        assert_eq!(has(&dest).as_deref(), Some("two"));
        // killed after them: the old one goes
        put(&kept_old(&dest), "old");
        recover(&dest).unwrap();
        assert!(!kept_old(&dest).exists());
        assert_eq!(has(&dest).as_deref(), Some("two"));
        assert_eq!(kept_old(&dest), t.join(".alpine.old"));
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn image_names() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            a: SetupArgs,
        }
        let a = Cli::try_parse_from(["setup"]).unwrap().a;
        assert!(a.images.is_empty());
        let a = Cli::try_parse_from(["setup", "alpine", "debian"])
            .unwrap()
            .a;
        assert_eq!(a.images, ["alpine", "debian"]);
        for bad in ["ubuntu", "../alpine", "Debian"] {
            let e = Cli::try_parse_from(["setup", bad]).err().unwrap();
            assert_eq!(e.exit_code(), 2, "{bad}");
        }
        #[cfg(target_os = "macos")]
        {
            assert!(Cli::try_parse_from(["setup", "--remove"]).unwrap().a.remove);
            assert!(Cli::try_parse_from(["setup", "--remove", "debian"]).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pins() {
        let h = "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4";
        let pins = format!("# the formula's pins\n{h}  debian-aarch64.ext4.gz\n");
        assert_eq!(sum_for(&pins, &asset("debian")).as_deref(), Some(h));
        assert_eq!(sum_for(&pins, &asset("alpine")), None);
        assert_eq!(sum_for("", &asset("debian")), None);
        assert!(!placeholder(h));
        let zeros = format!("{}  debian-aarch64.ext4.gz\n", "0".repeat(64));
        assert!(sum_for(&zeros, &asset("debian")).is_some_and(|h| placeholder(&h)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn pinned_kernel() {
        assert!(is_sha256(KERNEL_SHA256));
        assert_eq!(KERNEL_SHA256, KERNEL_SHA256.to_ascii_lowercase());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn tags() {
        assert!(valid_tag("v0.2.0"));
        assert!(valid_tag("v1.0.0-rc.1"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("v1/../x"));
        assert!(!valid_tag("v1?x=1"));
    }
}
