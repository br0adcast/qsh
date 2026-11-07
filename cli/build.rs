// Build script for the `qsh` client: emits QSH_BUILD, the same build stamp
// `qshd/build.rs` gives the daemon -- UNIX seconds of the HEAD commit, or the
// wall clock outside a repository -- so the client's log names the build it
// came from the way the daemon's does (`crate::log::start_marker`).

#[path = "../build-support/git_metadata.rs"]
mod git_metadata;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=QSH_OFFICIAL_RELEASE");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    let official = std::env::var("QSH_OFFICIAL_RELEASE").as_deref() == Ok("1");
    let source = if official {
        let source = std::env::var("GITHUB_SHA").expect("official release requires GITHUB_SHA");
        assert!(
            source.len() == 40 && source.bytes().all(|b| b.is_ascii_hexdigit()),
            "official release requires a full source commit"
        );
        source
    } else {
        String::new()
    };
    println!(
        "cargo:rustc-env=QSH_CLIENT_OFFICIAL={}",
        if official { "1" } else { "0" }
    );
    println!("cargo:rustc-env=QSH_CLIENT_SOURCE={source}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../build-support/git_metadata.rs");
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let stamp = git_metadata::watch_git_metadata(root.parent().unwrap())
        .and_then(|metadata| metadata.commit_epoch())
        .unwrap_or_else(wallclock_epoch);
    println!("cargo:rustc-env=QSH_BUILD={stamp}");
}

fn wallclock_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
