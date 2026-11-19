// macOS runs VMs on libkrun, linked from homebrew. LIBKRUN_LIB_DIR overrides
// where it's found. nothing to link anywhere else
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LIBKRUN_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HOMEBREW_PREFIX");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-changed=install.sh");
    println!("cargo:rustc-env=BURNER_KERNEL_SHA256={}", kernel_sha256());
    // homebrew's own places only, never a brew found on PATH: what's linked
    // here is the VM boundary
    let dir = std::env::var_os("LIBKRUN_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOMEBREW_PREFIX")
                .map(PathBuf::from)
                .into_iter()
                .chain([PathBuf::from("/opt/homebrew")])
                .map(|p| p.join("opt/libkrun/lib"))
                .find(|d| d.is_dir())
                .unwrap_or_else(|| PathBuf::from("/opt/homebrew/opt/libkrun/lib"))
        });
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=dylib=krun");
}

/// the aarch64 guest kernel's sha256, read from where install.sh pins it, so
/// burner setup and install.sh can't disagree about which kernel is the one
fn kernel_sha256() -> String {
    let path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("install.sh");
    let text = std::fs::read_to_string(&path).expect("reading install.sh");
    let mut arm = false;
    for line in text.lines().map(str::trim) {
        arm = arm || line == "aarch64)";
        if let Some(rest) = line.split("KERNEL_SHA=").nth(1).filter(|_| arm) {
            let sha: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            assert_eq!(
                sha.len(),
                64,
                "install.sh's aarch64 KERNEL_SHA isn't a sha256"
            );
            return sha.to_ascii_lowercase();
        }
    }
    panic!("no aarch64 KERNEL_SHA in install.sh");
}
