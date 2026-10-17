// Build script for the `qsh` client: emits QSH_BUILD, the same build stamp
// `qshd/build.rs` gives the daemon -- UNIX seconds of the HEAD commit, or the
// wall clock outside a repository -- so the client's log names the build it
// came from the way the daemon's does (`crate::log::start_marker`).

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Rebuild when HEAD (or a ref it points at) moves. The git directory is
    // asked for rather than assumed: in a submodule `.git` is a file.
    let git_dir = git(&["rev-parse", "--absolute-git-dir"]).unwrap_or_else(|| "../.git".into());
    for name in ["HEAD", "refs", "packed-refs"] {
        println!("cargo:rerun-if-changed={git_dir}/{name}");
    }
    let stamp = git(&["log", "-1", "--format=%ct"])
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(wallclock_epoch);
    println!("cargo:rustc-env=QSH_BUILD={stamp}");
}

/// What `git args` prints, trimmed; None when git is missing or fails.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

fn wallclock_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
