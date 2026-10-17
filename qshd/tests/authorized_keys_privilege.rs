//! The full privilege-switching path of `authorized::read_for`, exercised
//! for real under root -- two things nothing in this crate's own
//! (always-unprivileged) unit tests can prove:
//!
//! 1. That switching only the effective user id is not enough (the defect
//!    fix round 1 of this task found): a `root:root`, `0640` file is
//!    unreadable to an account sharing none of root's groups, but a
//!    helper that moved only its uid keeps root's leftover effective gid
//!    (0) throughout the switch -- and that gid matches the file's group,
//!    letting the read through on root's authority rather than the
//!    account's. This test fails against a uid-only version of
//!    `EffectiveIdentity` and passes against the uid+gid+groups version;
//!    the fix report records both runs.
//! 2. That the effective identity -- user, group, AND the supplementary
//!    group list -- is fully restored after a read that fails under a
//!    genuinely different identity. Unprivileged, "restored" and "never
//!    moved" look identical, because the account under test would have to
//!    be the caller's own; only a real cross-account switch, which needs
//!    root, can tell them apart.
//!
//! `#![cfg(feature = "system")]` on the whole file: without the feature,
//! `authorized::read_for` does not exist to call, so there is nothing here
//! worth compiling under the crate's default (non-system) build -- see
//! `qshd/tests/serve_system_split.rs` for the same reasoning applied
//! elsewhere in this test suite.
//!
//! This test changes the process's EFFECTIVE identity -- user, group, and
//! the supplementary group list -- for the whole process, for the duration
//! of `read_for`'s internal `seteuid`/`setegid`/`setgroups` calls (glibc
//! synchronizes these across every thread in the process, not just the
//! calling one; only `seteuid`/`setegid` are used, never `setuid` or
//! `setresuid`, so the REAL and SAVED ids never move at all -- see
//! `authorized.rs`'s own module docs for why that is what makes restoring
//! them afterward possible without needing any capability back). That is
//! exactly why this test lives in its own integration test binary, run by
//! this project's required gate with `--test-threads=1`, rather than
//! inside the crate's own `#[cfg(test)]` unit tests, which run without
//! that flag and would let a concurrently-running, unrelated test observe
//! -- or be affected by -- the temporary switch to `nobody`.
//!
//! Do not add a second test to this file. This file is safe to run under a
//! plain `sudo` invocation (no `--test-threads=1` needed by hand) only
//! because it is the single test in its binary; a second test that also
//! switches identity would bring back exactly the race described above,
//! just between two tests in the same binary instead of two tests in the
//! shared lib binary. A new identity-switching root-only test belongs in
//! its OWN new integration file, not here.

#![cfg(feature = "system")]

use std::os::unix::fs::PermissionsExt;

use nix::unistd::{Gid, Uid};
use qshd::helper::account;
use qshd::helper::authorized::{read_for, AuthorizedError};

#[test]
fn the_effective_account_is_restored_even_when_the_read_fails() {
    if !Uid::effective().is_root() {
        eprintln!(
            "SKIPPED the_effective_account_is_restored_even_when_the_read_fails: the system \
             mode needs root to set up a root-only file and to become an unprivileged account."
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    // `tempfile` leaves the directory's mode to the umask; pin it
    // explicitly so the file's own 0640 is what actually decides this
    // test, not an accidentally-restrictive (or permissive) parent
    // directory inherited from whatever umask happens to be set.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the tempdir to 0755");

    let path = dir.path().join("root-only-keys");
    std::fs::write(&path, "ssh-ed25519 AAAA root-only\n").expect("write");
    // 0640, not 0600: a mode with zero group bits cannot tell a helper
    // that switched the effective GROUP apart from one that did not --
    // both would correctly be refused, for different reasons. Group-read
    // bits on a file owned root:root (this test process's own identity,
    // since it is running as root) are what actually exercise the
    // group-permission path the uid-only version got wrong: root's own
    // group (0) satisfies them, `nobody`'s does not.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
        .expect("restrict to owner and group (root:root)");

    let nobody = account::lookup("nobody").expect("the nobody account exists");
    assert_ne!(
        nobody.uid,
        Uid::effective(),
        "the test needs a genuinely different uid to prove anything"
    );
    assert!(
        !nobody.groups.contains(&Gid::from_raw(0)),
        "the test needs an account that does NOT share root's group, or the file would be \
         readable for the right reason and prove nothing about the fix"
    );

    let before_uid = Uid::effective();
    let before_gid = Gid::effective();
    let mut before_groups: Vec<u32> = nix::unistd::getgroups()
        .expect("read this process's own groups")
        .iter()
        .map(|g| g.as_raw())
        .collect();
    before_groups.sort_unstable();

    let err = read_for(&nobody, &path.display().to_string()).expect_err(
        "an account sharing none of root's groups must be refused this 0640 root:root file, \
         not served on root's authority",
    );
    assert!(matches!(err, AuthorizedError::Read { .. }), "got: {err}");

    assert_eq!(
        Uid::effective(),
        before_uid,
        "the effective user must be restored after a failed read under another identity"
    );
    assert_eq!(
        Gid::effective(),
        before_gid,
        "the effective group must be restored after a failed read under another identity"
    );
    let mut after_groups: Vec<u32> = nix::unistd::getgroups()
        .expect("read this process's own groups")
        .iter()
        .map(|g| g.as_raw())
        .collect();
    after_groups.sort_unstable();
    assert_eq!(
        after_groups, before_groups,
        "the supplementary group list must be restored after a failed read under another \
         identity"
    );
}
