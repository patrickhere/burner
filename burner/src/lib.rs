//! burner's insides, a library so its binary and the fuzz targets can share
//! them. not an api: anything here can change in any release

#[doc(hidden)]
#[cfg_attr(target_os = "macos", path = "cgroup_macos.rs")]
pub mod cgroup;
#[doc(hidden)]
pub mod completions;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod dns;
#[doc(hidden)]
#[cfg_attr(target_os = "macos", path = "doctor_macos.rs")]
pub mod doctor;
#[doc(hidden)]
pub mod exit;
#[doc(hidden)]
pub mod explain;
#[doc(hidden)]
pub mod json;
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub mod krun;
#[doc(hidden)]
pub mod ledger;
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub mod macnet;
#[doc(hidden)]
pub mod net;
#[doc(hidden)]
pub mod netlog;
#[doc(hidden)]
pub mod netmodel;
#[doc(hidden)]
pub mod nflog;
#[doc(hidden)]
pub mod output;
#[doc(hidden)]
pub mod probe;
#[doc(hidden)]
pub mod remote;
#[doc(hidden)]
pub mod result;
#[doc(hidden)]
pub mod run;
#[doc(hidden)]
pub mod runlog;
#[doc(hidden)]
#[cfg_attr(target_os = "linux", path = "setup_linux.rs")]
pub mod setup;
#[doc(hidden)]
pub mod sys;
