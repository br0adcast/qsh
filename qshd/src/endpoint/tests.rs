use super::path::EndpointAuthority;
use super::{bind_prepared_mode, EndpointLock};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

fn private_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn entries(path: &Path) -> BTreeSet<OsString> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

#[test]
fn private_parent_policy_is_opt_in_and_rechecked() {
    let root = private_dir();
    for mode in [0o700, 0o755, 0o711] {
        let parent = root.path().join(format!("mode{mode:o}"));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        let socket = parent.join("host-v1.sock");
        let ordinary = EndpointAuthority::open(&socket, false).unwrap();
        ordinary.validate_route().unwrap();
        let private = EndpointAuthority::open_private(&socket);
        assert_eq!(private.is_ok(), mode == 0o700, "private parent {mode:o}");
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, mode);
        assert!(entries(&parent).is_empty());
    }
    let parent = root.path().join("mode700");
    let private = EndpointAuthority::open_private(&parent.join("host-v1.sock")).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(private.validate_route().is_err());
    assert!(EndpointLock::acquire(private, Duration::ZERO).is_err());
    assert!(!parent.join("host-v1.sock.lock").exists());
    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o755);
    assert!(entries(&parent).is_empty());
}

#[test]
fn private_open_does_not_create_or_repair() {
    let root = private_dir();
    let valid = root.path().join("private");
    fs::create_dir(&valid).unwrap();
    fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(valid.join("sentinel"), b"owned sentinel").unwrap();
    let alias = root.path().join("alias");
    symlink(&valid, &alias).unwrap();
    let opened = EndpointAuthority::open_private(&alias.join("host-v1.sock")).unwrap();
    assert_eq!(opened.route, alias.join("host-v1.sock"));
    opened.validate_route().unwrap();
    let file = root.path().join("file");
    fs::write(&file, b"parent sentinel").unwrap();
    let dangling = root.path().join("dangling");
    symlink(root.path().join("missing"), &dangling).unwrap();
    let loop_a = root.path().join("loop-a");
    let loop_b = root.path().join("loop-b");
    symlink(&loop_b, &loop_a).unwrap();
    symlink(&loop_a, &loop_b).unwrap();
    let before = entries(root.path());
    for parent in [root.path().join("missing"), file.clone(), dangling, loop_a] {
        assert!(EndpointAuthority::open_private(&parent.join("host-v1.sock")).is_err());
        assert_eq!(entries(root.path()), before);
    }
    for mode in [0o755, 0o711, 0o770, 0o777, 0o1700] {
        fs::set_permissions(&valid, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            EndpointAuthority::open_private(&valid.join("host-v1.sock")).is_err(),
            "unsafe private mode {mode:o}"
        );
        assert_eq!(fs::metadata(&valid).unwrap().mode() & 0o7777, mode);
        assert_eq!(fs::read(valid.join("sentinel")).unwrap(), b"owned sentinel");
        assert_eq!(
            entries(&valid),
            BTreeSet::from([OsString::from("sentinel")])
        );
    }
    assert_eq!(fs::read(&file).unwrap(), b"parent sentinel");
    assert_eq!(entries(root.path()), before);
}

#[cfg(target_os = "linux")]
#[test]
fn private_parent_foreign_owner_refused() {
    use nix::unistd::{chown, geteuid, Gid, Uid};
    use std::io::Read;

    assert_eq!(geteuid().as_raw(), 0, "disposable root fixture only");
    let root = private_dir();
    let parent = root.path().join("foreign-owned");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let sentinel = parent.join("sentinel");
    fs::write(&sentinel, b"owned sentinel").unwrap();
    let mut retained = fs::File::open(&sentinel).unwrap();
    let identity = retained.metadata().unwrap();
    let before = entries(&parent);
    chown(
        &parent,
        Some(Uid::from_raw(65534)),
        Some(Gid::from_raw(65534)),
    )
    .unwrap();
    let result = EndpointAuthority::open_private(&parent.join("host-v1.sock"));
    let after = fs::metadata(&parent).unwrap();
    let retained_after = retained.metadata().unwrap();
    // Restore only fixture ownership for teardown after observing the refusal.
    chown(&parent, Some(geteuid()), Some(nix::unistd::getegid())).unwrap();
    assert!(result.is_err());
    assert_eq!(after.uid(), 65534);
    assert_eq!(after.mode() & 0o7777, 0o700);
    assert_eq!(
        (identity.dev(), identity.ino()),
        (retained_after.dev(), retained_after.ino())
    );
    assert_eq!(entries(&parent), before);
    let mut bytes = Vec::new();
    retained.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"owned sentinel");
}

#[test]
fn private_lock_substitution_preserves_replacement() {
    use std::os::fd::AsRawFd;

    let root = private_dir();
    let socket = root.path().join("host-v1.sock");
    let lock = root.path().join("host-v1.sock.lock");
    let retired = root.path().join("retained-lock");
    let authority = EndpointAuthority::open_private(&socket).unwrap();
    let mut replacement = None;
    let result = EndpointLock::acquire_prepared(authority, Duration::ZERO, || {
        fs::rename(&lock, &retired).unwrap();
        fs::write(&lock, b"replacement lock sentinel").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
        replacement = Some(fs::metadata(&lock).unwrap());
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&lock).unwrap(), b"replacement lock sentinel");
    let current = fs::metadata(&lock).unwrap();
    let replacement = replacement.unwrap();
    assert_eq!(
        (current.dev(), current.ino()),
        (replacement.dev(), replacement.ino())
    );
    assert_eq!(current.mode() & 0o7777, 0o600);
    for path in [&lock, &retired] {
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        // SAFETY: this fixture owns and retains the descriptor for the call.
        assert_eq!(
            unsafe { nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB) },
            0
        );
    }
}

#[test]
fn private_bind_policy_change_cannot_publish() {
    for before_publish in [false, true] {
        let root = private_dir();
        let parent = root.path().join("private");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel = root.path().join("outside-sentinel");
        fs::write(&sentinel, b"outside sentinel").unwrap();
        let socket = parent.join("host-v1.sock");
        let authority = EndpointAuthority::open_private(&socket).unwrap();
        let lock = EndpointLock::acquire(authority, Duration::ZERO).unwrap();
        let changed = parent.clone();
        let result = bind_prepared_mode(
            lock.authority(),
            |stage| {
                let change: Box<dyn FnOnce()> = Box::new(move || {
                    fs::set_permissions(changed, fs::Permissions::from_mode(0o755)).unwrap();
                });
                if before_publish {
                    stage.before_publish = Some(change);
                } else {
                    stage.before_chmod = Some(change);
                }
            },
            false,
        );
        assert!(result.is_err());
        assert!(!socket.exists());
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside sentinel");
        assert_eq!(
            entries(&parent),
            BTreeSet::from([OsString::from("host-v1.sock.lock")])
        );
        // The operation has settled; repair only this fixture during teardown.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn private_no_replace_failure_preserves_competitor() {
    use std::cell::RefCell;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::rc::Rc;

    for unsupported in [false, true] {
        let root = private_dir();
        let socket = root.path().join("host-v1.sock");
        let authority = EndpointAuthority::open_private(&socket).unwrap();
        let lock = EndpointLock::acquire(authority, Duration::ZERO).unwrap();
        let competitor = Rc::new(RefCell::new(None));
        let retained = Rc::clone(&competitor);
        let route = socket.clone();
        let result = bind_prepared_mode(
            lock.authority(),
            |stage| {
                stage.before_publish = Some(Box::new(move || {
                    let listener = UnixListener::bind(&route).unwrap();
                    fs::set_permissions(&route, fs::Permissions::from_mode(0o600)).unwrap();
                    let identity = fs::metadata(&route).unwrap();
                    *retained.borrow_mut() = Some((listener, identity));
                }));
                if unsupported {
                    stage.no_replace_error = Some(nix::libc::ENOTSUP);
                }
            },
            false,
        );
        let error = result.err().unwrap();
        if unsupported {
            assert_eq!(error.raw_os_error(), Some(nix::libc::ENOTSUP));
        } else {
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        }
        let held = competitor.borrow();
        let (_, identity) = held.as_ref().unwrap();
        let current = fs::metadata(&socket).unwrap();
        assert_eq!(
            (current.dev(), current.ino()),
            (identity.dev(), identity.ino())
        );
        assert!(UnixStream::connect(&socket).is_ok());
        assert_eq!(
            entries(root.path()),
            BTreeSet::from([
                OsString::from("host-v1.sock"),
                OsString::from("host-v1.sock.lock"),
            ])
        );
    }
}
