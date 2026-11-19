// macOS runs VMs on libkrun, linked from homebrew. LIBKRUN_LIB_DIR overrides
// where it's found. nothing to link anywhere else
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LIBKRUN_LIB_DIR");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let dir = std::env::var_os("LIBKRUN_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Command::new("brew")
                .args(["--prefix", "libkrun"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| PathBuf::from(s.trim()))
                .or_else(|| {
                    std::env::var_os("HOMEBREW_PREFIX")
                        .map(|p| PathBuf::from(p).join("opt/libkrun"))
                })
                .unwrap_or_else(|| PathBuf::from("/opt/homebrew/opt/libkrun"))
                .join("lib")
        });
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=dylib=krun");
}
