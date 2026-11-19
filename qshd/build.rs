// Build script for `qshd`: emits QSHD_BUILD -- a MONOTONIC build stamp used
// by `state::build_label()` for version negotiation. We take the HEAD commit
// time (UNIX seconds) rather than wall-clock compile time: cargo caches the
// build script, and a wall-clock stamp did NOT advance when only a dependency
// crate (crates/transport) changed but the `qshd` package didn't -- two
// byte-different binaries then carried the SAME stamp. The commit time
// advances on every commit, including dependency edits.

#[path = "../build-support/git_metadata.rs"]
mod git_metadata;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // The build script runs on the host; the adapter belongs to the target.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=src/handover/darwin_listener.c");
        cc::Build::new()
            .file("src/handover/darwin_listener.c")
            .flag_if_supported("-std=c11")
            .warnings(true)
            .extra_warnings(true)
            .compile("qsh_handover_darwin");
        println!("cargo:rerun-if-changed=src/darwin_process_scope/native.c");
        println!("cargo:rerun-if-changed=src/darwin_process_scope/native.h");
        cc::Build::new()
            .file("src/darwin_process_scope/native.c")
            .flag_if_supported("-std=c11")
            .warnings(true)
            .extra_warnings(true)
            .compile("qsh_darwin_process_scope");
        println!("cargo:rustc-link-lib=proc");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../build-support/git_metadata.rs");
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let stamp = git_metadata::watch_git_metadata(root.parent().unwrap())
        .and_then(|metadata| metadata.commit_epoch())
        .unwrap_or_else(wallclock_epoch);
    println!("cargo:rustc-env=QSHD_BUILD={stamp}");
}

fn wallclock_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
