//! Real credential and authorization-object checks. Run this single sequential
//! test only in a disposable root container with QSHD_TEST_DISPOSABLE_HOST=1.
//! Never run it with host sudo: effective identity changes affect every thread.

#![cfg(feature = "system")]

use std::os::unix::fs::{chown, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, Uid};
use qshd::helper::account::Account;
use qshd::helper::authorized::{read_for, AuthorizedError};

fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}

fn identity() -> (Uid, Gid, Vec<Gid>) {
    let mut groups = nix::unistd::getgroups().unwrap();
    groups.sort_unstable_by_key(|group| group.as_raw());
    (Uid::effective(), Gid::effective(), groups)
}

fn checked_read(account: &Account, path: &Path) -> Result<String, AuthorizedError> {
    let before = identity();
    let result = read_for(account, path.to_str().unwrap());
    assert_eq!(
        identity(),
        before,
        "restore uid, gid and supplementary groups"
    );
    result
}

fn refused(account: &Account, path: &Path, reason: &str) {
    let err = checked_read(account, path).expect_err("unsafe authorization must be refused");
    assert!(matches!(err, AuthorizedError::Read { .. }), "{err}");
    assert!(err.to_string().contains(reason), "expected {reason}: {err}");
}

#[test]
fn the_effective_account_is_restored_even_when_the_read_fails() {
    if !Uid::effective().is_root()
        || std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() != Ok("1")
    {
        eprintln!("SKIPPED the_effective_account_is_restored_even_when_the_read_fails: requires root and QSHD_TEST_DISPOSABLE_HOST=1 in a disposable container");
        return;
    }
    // /var/lib is root-owned and not writable by other principals. A private
    // child of /tmp would conceal leaf checks behind an unsafe ancestor.
    let dir = tempfile::Builder::new()
        .prefix("qshd-keys-")
        .tempdir_in("/var/lib")
        .unwrap();
    mode(dir.path(), 0o755);
    let account = Account {
        uid: Uid::from_raw(61001),
        gid: Gid::from_raw(61001),
        groups: vec![Gid::from_raw(61001), Gid::from_raw(61003)],
        name: "qshd-fixture-alice".into(),
        home: dir.path().into(),
        shell: "/bin/sh".into(),
    };
    let path = dir.path().join("keys");
    std::fs::write(&path, "safe keys").unwrap();
    mode(&path, 0o644);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "root-owned readable store"
    );
    mode(dir.path(), 0o711);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "search-only parent"
    );
    mode(dir.path(), 0o755);

    // This must reach the leaf's kernel permission check, not an ancestor policy
    // refusal. Retaining root's effective gid would incorrectly allow this read.
    mode(&path, 0o640);
    refused(&account, &path, "Permission denied");
    chown(&path, Some(0), Some(61003)).unwrap();
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "supplementary group grants read"
    );
    chown(&path, Some(61001), Some(61001)).unwrap();
    mode(&path, 0o600);
    assert_eq!(
        checked_read(&account, &path).unwrap(),
        "safe keys",
        "account-private keys"
    );

    for bits in [0o620, 0o602] {
        mode(&path, bits);
        refused(&account, &path, "writable by group or others");
        mode(&path, 0o600);
        assert_eq!(checked_read(&account, &path).unwrap(), "safe keys");
    }
    chown(&path, Some(61002), Some(61002)).unwrap();
    mode(&path, 0o644);
    refused(&account, &path, "untrusted owner");
    chown(&path, Some(61001), Some(61001)).unwrap();

    let parent = dir.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    mode(&parent, 0o755);
    let nested = parent.join("keys");
    std::fs::write(&nested, "nested keys").unwrap();
    mode(&nested, 0o644);
    assert_eq!(checked_read(&account, &nested).unwrap(), "nested keys");
    chown(&parent, Some(61002), Some(61002)).unwrap();
    refused(&account, &nested, "untrusted owner");
    chown(&parent, Some(61001), Some(61001)).unwrap();
    for bits in [0o775, 0o757] {
        mode(&parent, bits);
        refused(&account, &nested, "writable by group or others");
        mode(&parent, 0o755);
        assert_eq!(checked_read(&account, &nested).unwrap(), "nested keys");
    }
    mode(dir.path(), 0o777);
    refused(&account, &nested, "writable by group or others");
    mode(dir.path(), 0o755);

    assert_eq!(
        checked_read(&account, &dir.path().join("missing")).unwrap(),
        ""
    );
    refused(&account, &parent, "not a regular file");
    refused(&account, Path::new("/dev/zero"), "not a regular file");
    let link = dir.path().join("linked-keys");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(checked_read(&account, &link).is_err());
    std::fs::write(&path, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    refused(&account, &path, "larger than");
    std::fs::write(&path, [0xff]).unwrap();
    refused(&account, &path, "invalid utf-8");
    mode(&path, 0o000);
    refused(&account, &path, "Permission denied");
    let unsafe_dir = tempfile::tempdir().unwrap();
    mode(unsafe_dir.path(), 0o755);
    let unsafe_path = unsafe_dir.path().join("keys");
    std::fs::write(&unsafe_path, "keys").unwrap();
    refused(&account, &unsafe_path, "writable by group or others");
}
