// Build script for `qshd`: emits QSHD_BUILD -- a MONOTONIC build stamp used
// by `state::build_label()` for version negotiation. We take the HEAD commit
// time (UNIX seconds) rather than wall-clock compile time: cargo caches the
// build script, and a wall-clock stamp did NOT advance when only a dependency
// crate (crates/transport) changed but the `qshd` package didn't -- two
// byte-different binaries then carried the SAME stamp. The commit time
// advances on every commit, including dependency edits.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Rebuild when HEAD (or a ref it points at) moves, so the stamp tracks
    // commits. Best-effort: even if a rerun is missed, `git log` yields the
    // right value whenever the script does run, and reconcile's `>=` branch
    // (see version.rs) backstops a stale-equal stamp.
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
    println!("cargo:rerun-if-changed=../.git/packed-refs");
    let stamp = git_commit_epoch().unwrap_or_else(wallclock_epoch);
    println!("cargo:rustc-env=QSHD_BUILD={stamp}");
}

/// UNIX seconds of the HEAD commit, or None if git is unavailable (build
/// outside a repo) -- then we fall back to wall-clock so the build never fails.
fn git_commit_epoch() -> Option<u64> {
    let out = Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

fn wallclock_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
