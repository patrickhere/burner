//! `burner setup` on linux: this version's alpine and debian images from its
//! own release, for this cpu. they're checked against the SHA256SUMS get.sh
//! checked the release against and install.sh kept in paths.root, so an
//! image swapped on the release after the install doesn't get in. without one
//! (a crates.io install, a build from source) against the release's own
//! SHA256SUMS, which comes from the same place, and setup says so. the kernel
//! stays install.sh's. the fetch and check code is setup.rs's, the mac's

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::Args;

use super::{
    IMAGES, MAX_SUMS, SUMS, SWAPPING, Stage, asset, defaults, download_listed, fetch_sums, go_on,
    gunzip, idle, own_release, package_list, say, sum_for, sweep, wanted,
};
use crate::config::{self, Config};
use crate::json::{self, Kind};
use crate::sys;

#[derive(Args)]
pub struct SetupArgs {
    /// the images to install, alpine when none are named
    #[arg(value_name = "IMAGE", value_parser = IMAGES)]
    pub(super) images: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct SetupResult {
    /// release: on linux the images only come from this burner's own
    pub source: &'static str,
    /// the url they came from
    pub from: String,
    /// which SHA256SUMS they were checked against: install, the one kept
    /// when burner was installed, or release, the release's own
    pub sums: &'static str,
    /// each image's rootfs, in the order they were named
    pub images: Vec<String>,
}

/// the release tarball this burner came in, the line a kept SHA256SUMS has
/// to have to be this version's
fn tarball() -> String {
    format!(
        "burner-v{}-{}-linux.tar.gz",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    )
}

pub(super) fn setup(cfg: &Config, a: SetupArgs) -> Result<ExitCode> {
    let imgs = wanted(&a.images);
    let root = &cfg.paths.root;
    if !sys::is_root() {
        return Ok(json::fail(
            "setup",
            crate::run::EXIT_USAGE,
            Kind::NotRoot,
            format!(
                "burner setup needs root, it installs into {} (sudo burner setup {})",
                root.join("images").display(),
                imgs.join(" ")
            ),
        ));
    }
    if !root.is_dir() {
        bail!(
            "no {}, so burner isn't installed here yet. install.sh sets it up",
            root.display()
        );
    }
    // as root, a dir anyone else can write would hand them the images
    config::trusted_file(root)?;
    let base = own_release();
    let kept = kept_sums(root)?;
    // checked again before the swap, this only saves a pointless download
    drop(idle(cfg, "swap their image")?);
    go_on()?;

    sys::private_dir(&cfg.paths.state)?;
    let _setup = sys::Lock::exclusive_until(&cfg.paths.state.join("setup.lock"), Instant::now())
        .map_err(|_| anyhow::anyhow!("another burner setup is running"))?;
    sweep(root);
    let stage = Stage::new(root)?;
    let sums = match &kept {
        Some((path, text)) => {
            say(&format!(
                "checking against the SHA256SUMS kept from the install, {}",
                path.display()
            ));
            text.clone()
        }
        None => {
            json::warn(
                Kind::Unverified,
                format!(
                    "no SHA256SUMS was kept here from installing {} (get.sh keeps it), so the \
                     images are checked only against the release's own, which comes from the \
                     same place. gh attestation verify checks where they were built",
                    tarball()
                ),
            );
            fetch_sums(&base, "=https", &stage.0)?
        }
    };
    // the package list next to each image, when the release has one
    let files: Vec<String> = imgs
        .iter()
        .flat_map(|i| [asset(i), package_list(i)])
        .filter(|f| f.ends_with(".ext4.gz") || sum_for(&sums, f).is_some())
        .collect();
    say(&format!("fetching {} from {base}", files.join(", ")));
    download_listed(&base, "=https", &stage.0, &files, &sums)?;

    // the release's images are built with the guest init of the same tag,
    // the one built into this burner
    for img in &imgs {
        let d = stage.0.join(img);
        fs::DirBuilder::new().mode(0o755).create(&d)?;
        gunzip(&stage.0.join(asset(img)), &d.join("rootfs.ext4"))?;
        fs::write(d.join("defaults.toml"), defaults(img))?;
        fs::write(d.join("init"), crate::doctor::GUEST_INIT)?;
        let list = stage.0.join(package_list(img));
        if list.exists() {
            fs::rename(&list, d.join("packages"))?;
        }
        for f in ["rootfs.ext4", "defaults.toml", "init", "packages"] {
            if d.join(f).exists() {
                fs::set_permissions(d.join(f), fs::Permissions::from_mode(0o644))?;
            }
        }
    }

    go_on()?;
    // a VM opens its image by path while it starts, and holding the ledger
    // lock keeps new ones from starting while they're swapped
    let ledger = idle(cfg, "swap their image")?;
    go_on()?;
    let idirs: Vec<PathBuf> = imgs.iter().map(|i| root.join("images").join(i)).collect();
    for d in &idirs {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(d)
            .with_context(|| format!("creating {}", d.display()))?;
    }
    SWAPPING.store(true, Ordering::SeqCst);
    for (img, idir) in imgs.iter().zip(&idirs) {
        let d = stage.0.join(img);
        for f in ["rootfs.ext4", "defaults.toml", "init"] {
            fs::rename(d.join(f), idir.join(f))?;
        }
        // what tools/build-image wrote about an image this one replaces
        if d.join("packages").exists() {
            fs::rename(d.join("packages"), idir.join("packages"))?;
        } else {
            remove_if_there(&idir.join("packages"))?;
        }
        remove_if_there(&idir.join("base"))?;
    }
    drop(ledger);

    let res = SetupResult {
        source: "release",
        from: base,
        sums: if kept.is_some() { "install" } else { "release" },
        images: idirs
            .iter()
            .map(|d| d.join("rootfs.ext4").display().to_string())
            .collect(),
    };
    if !json::on() {
        for i in &res.images {
            println!("image   {i}");
        }
        println!("sudo burner doctor checks the rest");
    }
    Ok(json::reply("setup", 0, Some(res)))
}

fn remove_if_there(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", p.display()))
        }
        _ => Ok(()),
    }
}

/// the SHA256SUMS install.sh kept, when it's this version's. one from
/// another version (burner upgraded some other way) doesn't count, one that
/// isn't root's alone is an error
fn kept_sums(root: &Path) -> Result<Option<(PathBuf, String)>> {
    let path = root.join(SUMS);
    let Ok(m) = path.symlink_metadata() else {
        return Ok(None);
    };
    if !m.is_file() || m.len() > MAX_SUMS {
        bail!("{} isn't a SHA256SUMS file", path.display());
    }
    config::trusted_file(&path)?;
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(is_for_this(&text).then_some((path, text)))
}

fn is_for_this(sums: &str) -> bool {
    sum_for(sums, &tarball()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_sums_are_this_versions() {
        let h = "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4";
        let arch = std::env::consts::ARCH;
        let v = env!("CARGO_PKG_VERSION");
        assert!(is_for_this(&format!(
            "{h}  alpine-{arch}.ext4.gz\n{h}  burner-v{v}-{arch}-linux.tar.gz\n"
        )));
        assert!(!is_for_this(&format!(
            "{h}  burner-v0.0.1-{arch}-linux.tar.gz\n"
        )));
        assert!(!is_for_this(&format!(
            "nope  burner-v{v}-{arch}-linux.tar.gz\n"
        )));
        assert!(!is_for_this(""));
    }

    #[test]
    fn kept_sums_on_disk() {
        let d = std::env::temp_dir().join(format!("burner-sums-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        assert!(kept_sums(&d).unwrap().is_none());
        let h = "7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4";
        fs::write(d.join(SUMS), format!("{h}  {}\n", tarball())).unwrap();
        // the temp dir is everyone's, so the file isn't trusted there
        let r = kept_sums(&d);
        assert!(r.is_err() || r.unwrap().is_some());
        fs::remove_file(d.join(SUMS)).unwrap();
        fs::create_dir(d.join(SUMS)).unwrap();
        assert!(kept_sums(&d).is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
