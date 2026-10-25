// Synthetic public pins and disposable paths; no real account/host credentials.
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
fn pin_fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn pin_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
#[test]
fn pin_authority_unsafe_sources_never_become_unknown() {
    let root = pin_fixture();
    let mut failures = Vec::new();
    for kind in ["writable-file", "writable-parent", "dangling"] {
        let parent = root.path().join(kind);
        fs::create_dir(&parent).unwrap();
        pin_mode(&parent, 0o700);
        let path = parent.join("known_hosts");
        if kind == "dangling" {
            symlink("missing-target", &path).unwrap();
        } else {
            fs::write(
                &path,
                format!("fixture.invalid 22 {}\n", base64_key(&[1; 32])),
            )
            .unwrap();
            pin_mode(
                &path,
                if kind == "writable-file" {
                    0o666
                } else {
                    0o644
                },
            );
        }
        if kind == "writable-parent" {
            pin_mode(&parent, 0o777);
        }
        let before = fs::symlink_metadata(&path).unwrap();
        let bytes = fs::read(&path).ok();
        let hosts = KnownHosts::open(path.clone());
        if !matches!(
            hosts.check("fixture.invalid", 22, &[1; 32]),
            Err(AuthError::Backend(_))
        ) {
            failures.push(format!("{kind} granted a verdict"));
        }
        if !matches!(
            hosts.pin("new.invalid", 22, &[2; 32]),
            Err(AuthError::Backend(_))
        ) {
            failures.push(format!("{kind} pin accepted"));
        }
        if !matches!(
            hosts.pin_if_absent("new.invalid", 22, &[2; 32]),
            Err(AuthError::Backend(_))
        ) {
            failures.push(format!("{kind} first pin accepted"));
        }
        let after = fs::symlink_metadata(&path).unwrap();
        if bytes != fs::read(&path).ok()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
        {
            failures.push(format!("{kind} evidence changed"));
        }
    }
    let missing = root.path().join("missing/known_hosts");
    assert_eq!(
        KnownHosts::open(missing.clone())
            .check("fixture.invalid", 22, &[1; 32])
            .unwrap(),
        HostVerdict::Unknown
    );
    assert!(!missing.parent().unwrap().exists());
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn pin_authority_trusted_aliases_and_public_hardlinks_preserve_read_and_entry_write_semantics() {
    let root = pin_fixture();
    let data = root.path().join("data");
    fs::create_dir(&data).unwrap();
    pin_mode(&data, 0o755);
    let target = data.join("public-pins");
    let text = format!(
        "# preserved\r\nfixture.invalid 22 {}\r\n",
        base64_key(&[1; 32])
    );
    fs::write(&target, &text).unwrap();
    pin_mode(&target, 0o644);
    let hard = data.join("hard");
    fs::hard_link(&target, &hard).unwrap();
    symlink("data", root.path().join("parent")).unwrap();
    let path = root.path().join("parent/known_hosts");
    symlink("public-pins", &path).unwrap();
    let original = fs::symlink_metadata(&path).unwrap();
    let held = PinLock::acquire(&path).unwrap();
    let lock = data.join(".known_hosts.lock");
    let identity = fs::metadata(&lock).unwrap();
    drop(held);
    let hosts = KnownHosts::open(path.clone());
    assert_eq!(
        hosts.check("fixture.invalid", 22, &[1; 32]).unwrap(),
        HostVerdict::Known
    );
    hosts.pin("fixture.invalid", 22, &[1; 32]).unwrap();
    assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), original.ino());
    assert_eq!(fs::read(&target).unwrap(), text.as_bytes());
    assert!(fs::metadata(&target).unwrap().nlink() > 1);
    hosts.pin("new.invalid", 22, &[2; 32]).unwrap();
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&target).unwrap(), text.as_bytes());
    assert_eq!(fs::read(&hard).unwrap(), text.as_bytes());
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
    assert_eq!(fs::metadata(lock).unwrap().ino(), identity.ino());
    assert!(!data.join(".public-pins.lock").exists());
    assert_eq!(
        hosts.check("new.invalid", 22, &[2; 32]).unwrap(),
        HostVerdict::Known
    );
}

fn relative_pin_child(directory: &Path) -> std::io::Result<()> {
    use std::io::{Read, Seek};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct OwnedChild {
        child: Child,
        terminal: bool,
        lost_identity: bool,
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.terminal {
                return;
            }
            if !self.lost_identity {
                let _ = self.child.kill();
            }
            let mut reported = false;
            loop {
                match self.child.wait() {
                    Ok(_) => break,
                    Err(error) => {
                        if !reported {
                            eprintln!("relative pin fixture retains child/TempDir after wait error: {error}");
                            reported = true;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
    }
    let mut output = tempfile::tempfile()?;
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "known_hosts::tests::pin_authority_raw_routes_and_alias_limits_are_checked",
            "--nocapture",
        ])
        .env("QSH_PIN_RELATIVE_CHILD", "1")
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?)
        .spawn()?;
    let mut owned = OwnedChild {
        child,
        terminal: false,
        lost_identity: false,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match owned.child.try_wait() {
            Ok(Some(status)) => {
                owned.terminal = true;
                break status;
            }
            Ok(None) => {}
            Err(error) => {
                owned.lost_identity = error.raw_os_error() == Some(libc::ECHILD);
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "relative pin child did not finish",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    output.rewind()?;
    let mut bytes = Vec::new();
    output.take(4096).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    assert!(status.success(), "relative pin child: {text}");
    assert!(
        text.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "{text}"
    );
    Ok(())
}

#[test]
fn pin_authority_raw_routes_and_alias_limits_are_checked() {
    fn assert_lookup_matches_metadata(path: &Path) {
        let expected = fs::symlink_metadata(path).unwrap_err();
        if expected.kind() == std::io::ErrorKind::NotFound {
            let (text, binding) = storage::read(path).unwrap().into_parts();
            assert!(text.is_empty());
            binding.validate().unwrap();
            assert_eq!(
                KnownHosts::open(path.to_owned())
                    .check("fixture.invalid", 22, &[1; 32])
                    .unwrap(),
                HostVerdict::Unknown
            );
            assert_eq!(
                fs::symlink_metadata(path).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        } else {
            assert_eq!(
                storage::read(path).err().unwrap().raw_os_error(),
                expected.raw_os_error()
            );
        }
    }
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    if std::env::var_os("QSH_PIN_RELATIVE_CHILD").is_some() {
        let hosts = KnownHosts::open("relative-pins".into());
        assert_eq!(
            hosts.check("fixture.invalid", 22, &[1; 32]).unwrap(),
            HostVerdict::Known
        );
        let loaded = hosts.read_entries().unwrap();
        let mut tx = storage::Transaction::acquire(Path::new("relative-pins")).unwrap();
        let (text, binding) = tx.read().unwrap().into_parts();
        std::env::set_current_dir("/").unwrap();
        loaded.validate().unwrap(); // The in-flight lookup captured its original cwd.
        tx.replace(
            &binding,
            format!("{text}# captured transaction\n").as_bytes(),
        )
        .unwrap();
        return;
    }
    let root = pin_fixture();
    // Exercise genuine absent-lookup semantics even on filesystems that accept raw bytes.
    assert_lookup_matches_metadata(&root.path().join("missing-raw-lookup"));
    let path = root.path().join("relative-pins");
    let text = format!("fixture.invalid 22 {}\n", base64_key(&[1; 32]));
    fs::write(&path, &text).unwrap();
    pin_mode(&path, 0o644);
    relative_pin_child(root.path()).unwrap();
    let physical = fs::canonicalize(root.path()).unwrap();
    for i in 0..41 {
        symlink(
            if i == 0 {
                "relative-pins".to_string()
            } else {
                format!("a{}", i - 1)
            },
            physical.join(format!("a{i}")),
        )
        .unwrap();
    }
    assert!(storage::read(&physical.join("a39")).is_ok());
    assert!(storage::read(&physical.join("a40")).is_err());
    for suffix in ["relative-pins/", "relative-pins/.", "relative-pins/.."] {
        assert!(
            storage::read(&root.path().join(suffix)).is_err(),
            "{suffix}"
        );
    }
    let sub = root.path().join("search");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("pins"), &text).unwrap();
    pin_mode(&sub.join("pins"), 0o644);
    pin_mode(&sub, 0o111);
    assert!(storage::read(&sub.join("pins")).is_ok());
    assert_eq!(fs::metadata(&sub).unwrap().mode() & 0o777, 0o111);
    pin_mode(&sub, 0o1777);
    assert!(storage::read(&sub.join("pins")).is_ok());
    pin_mode(&sub, 0o700);
    symlink("search/../relative-pins", root.path().join("dotdot")).unwrap();
    assert!(storage::read(&root.path().join("dotdot")).is_ok());
    let raw = OsString::from_vec(b"pins-\xff".to_vec());
    assert_eq!(
        storage::parts(raw.as_bytes(), false).pop_front().unwrap().0,
        raw
    );
    let raw = root.path().join(raw);
    match fs::write(&raw, &text) {
        Ok(()) => {
            pin_mode(&raw, 0o644);
            assert!(storage::read(&raw).is_ok());
            assert_eq!(lock_path_for(&raw), root.path().join(".known_hosts.lock"));
            let hosts = KnownHosts::open(raw.clone());
            hosts.pin("other.invalid", 22, &[2; 32]).unwrap();
            assert_eq!(
                hosts.check("other.invalid", 22, &[2; 32]).unwrap(),
                HostVerdict::Known
            );
            assert!(root.path().join(".known_hosts.lock").is_file());
        }
        Err(error) => {
            assert_eq!(error.raw_os_error(), Some(libc::EILSEQ));
            assert_lookup_matches_metadata(&raw);
        }
    }
}

#[test]
fn pin_authority_read_errors_never_accept_a_valid_prefix() {
    use std::io::Read;
    let root = pin_fixture();
    let path = root.path().join("pins");
    let text = format!("fixture.invalid 22 {}\n", base64_key(&[1; 32]));
    assert_eq!(parse_line(&text).unwrap().key, [1; 32]);
    fs::write(&path, &text).unwrap();
    pin_mode(&path, 0o644);
    let error = storage::read_with(&path, |file| {
        let mut prefix = vec![0; text.len()];
        file.read_exact(&mut prefix)?;
        assert_eq!(prefix, text.as_bytes());
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    })
    .err()
    .unwrap();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(fs::read(&path).unwrap(), text.as_bytes());
    let result = storage::read_with(&path, |file| {
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        fs::rename(&path, root.path().join("held"))?;
        fs::write(&path, &text)?;
        pin_mode(&path, 0o644);
        Ok(text)
    });
    assert!(
        result.is_err(),
        "a displaced named source cannot return its old trust snapshot"
    );
    let mut damaged = text.into_bytes();
    damaged.push(0xff);
    fs::write(&path, &damaged).unwrap();
    let before = fs::metadata(&path).unwrap();
    let hosts = KnownHosts::open(path.clone());
    for operation in 0..3 {
        let result = match operation {
            0 => hosts.check("fixture.invalid", 22, &[1; 32]),
            1 => hosts
                .pin("fixture.invalid", 22, &[1; 32])
                .map(|()| HostVerdict::Known),
            _ => hosts.pin_if_absent("fixture.invalid", 22, &[1; 32]),
        };
        assert!(matches!(result, Err(AuthError::Backend(_))));
        assert_eq!(fs::read(&path).unwrap(), damaged);
        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
    }
    let fifo = root.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(storage::read(&fifo).is_err());
    assert!(storage::read(Path::new("/dev/zero")).is_err());
    assert!(storage::read(root.path()).is_err());
}

fn pin_transaction(path: &Path) -> (storage::Transaction, storage::ReadBinding) {
    let tx = storage::Transaction::acquire(path).unwrap();
    let (_, binding) = tx.read().unwrap().into_parts();
    (tx, binding)
}

#[test]
fn pin_authority_lock_metadata_and_name_cannot_change_the_transaction() {
    let root = pin_fixture();
    for kind in ["mode", "hardlink", "fifo", "symlink"] {
        let path = root.path().join(kind);
        let lock = lock_path_for(&path);
        match kind {
            "fifo" => nix::unistd::mkfifo(
                &lock,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
            "symlink" => symlink("missing", &lock).unwrap(),
            _ => {
                fs::write(&lock, b"lock sentinel").unwrap();
                pin_mode(&lock, if kind == "mode" { 0o644 } else { 0o600 });
                if kind == "hardlink" {
                    fs::hard_link(&lock, root.path().join("lock-alias")).unwrap();
                }
            }
        }
        let before = fs::symlink_metadata(&lock).unwrap();
        assert!(
            PinLock::acquire(&path).is_err(),
            "invalid {kind} lock accepted"
        );
        let after = fs::symlink_metadata(&lock).unwrap();
        assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
        if matches!(kind, "mode" | "hardlink") {
            assert_eq!(fs::read(&lock).unwrap(), b"lock sentinel");
        }
    }
    let path = root.path().join("replaced");
    let (tx, binding) = pin_transaction(&path);
    let old = root.path().join("held-lock");
    fs::rename(lock_path_for(&path), &old).unwrap();
    fs::write(lock_path_for(&path), b"replacement").unwrap();
    pin_mode(&lock_path_for(&path), 0o600);
    assert!(tx.validate(&binding).is_err());
    assert!(tx.read().is_err());
    let contender = File::open(&old).unwrap();
    assert_eq!(
        rustix::fs::flock(
            &contender,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        ),
        Err(rustix::io::Errno::WOULDBLOCK)
    );
    drop(tx);
    rustix::fs::flock(
        &contender,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}

#[test]
fn pin_authority_collision_cleanup_never_deletes_an_unowned_name() {
    let root = pin_fixture();
    let path = root.path().join("pins");
    let tmp = root.path().join(".collision");
    fs::write(&tmp, b"collision sentinel").unwrap();
    pin_mode(&tmp, 0o644);
    let before = fs::metadata(&tmp).unwrap();
    let (mut tx, binding) = pin_transaction(&path);
    assert!(tx
        .replace_with(&binding, b"new", ".collision".into(), |_| panic!(
            "collision cannot enter owned phase"
        ))
        .is_err());
    assert_eq!(fs::read(&tmp).unwrap(), b"collision sentinel");
    let after = fs::metadata(&tmp).unwrap();
    assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
    assert!(!path.exists());
}

#[test]
fn pin_authority_error_cleanup_removes_only_its_created_inode() {
    let root = pin_fixture();
    let path = root.path().join("pins");
    fs::write(&path, b"original").unwrap();
    pin_mode(&path, 0o644);
    let (mut tx, binding) = pin_transaction(&path);
    let tmp = root.path().join(".owned-temp");
    for failure in [
        storage::Phase::Created,
        storage::Phase::Written,
        storage::Phase::Synced,
    ] {
        assert!(tx
            .replace_with(&binding, b"new", ".owned-temp".into(), |phase| {
                if phase == failure {
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(!tmp.exists());
        assert_eq!(fs::read(&path).unwrap(), b"original");
    }
    let moved = root.path().join("moved-temp");
    assert!(tx
        .replace_with(&binding, b"new", ".owned-temp".into(), |phase| {
            if phase == storage::Phase::Synced {
                fs::rename(&tmp, &moved)?;
                fs::write(&tmp, b"replacement sentinel")?;
                pin_mode(&tmp, 0o644);
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(&tmp).unwrap(), b"replacement sentinel");
    assert_eq!(fs::read(&moved).unwrap(), b"new");
    assert_eq!(fs::read(&path).unwrap(), b"original");
    fs::remove_file(&tmp).unwrap();
    fs::remove_file(&moved).unwrap();
    // A successful callback cannot smuggle a substituted temp into rename.
    assert!(tx
        .replace_with(&binding, b"new", ".owned-temp".into(), |phase| {
            if phase == storage::Phase::Synced {
                fs::rename(&tmp, &moved)?;
                fs::write(&tmp, b"replacement sentinel")?;
                pin_mode(&tmp, 0o644);
            }
            Ok(())
        })
        .is_err());
    assert_eq!(fs::read(&tmp).unwrap(), b"replacement sentinel");
    assert_eq!(fs::read(&moved).unwrap(), b"new");
    assert_eq!(fs::read(&path).unwrap(), b"original");
    fs::remove_file(&tmp).unwrap();
    fs::remove_file(&moved).unwrap();
    tx.replace_with(&binding, b"complete", ".owned-temp".into(), |_| Ok(()))
        .unwrap();
    assert!(!tmp.exists());
    assert_eq!(fs::read(&path).unwrap(), b"complete");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn pin_authority_replaced_parent_or_source_refuses_before_publication() {
    let root = pin_fixture();
    for kind in ["parent", "source", "alias", "lock"] {
        let parent = root.path().join(kind);
        fs::create_dir(&parent).unwrap();
        pin_mode(&parent, 0o700);
        let path = parent.join("pins");
        let target = parent.join("target");
        if kind == "alias" {
            fs::write(&target, b"original").unwrap();
            pin_mode(&target, 0o644);
            symlink("target", &path).unwrap();
        } else {
            fs::write(&path, b"original").unwrap();
            pin_mode(&path, 0o644);
        }
        let (mut tx, binding) = pin_transaction(&path);
        let displaced = root.path().join(format!("displaced-{kind}"));
        let result = tx.replace_with(&binding, b"new", ".temp".into(), |phase| {
            if phase != storage::Phase::Synced {
                return Ok(());
            }
            match kind {
                "parent" => {
                    fs::rename(&parent, &displaced)?;
                    fs::create_dir(&parent)?;
                    pin_mode(&parent, 0o700);
                    fs::write(&path, b"outside sentinel")?;
                    pin_mode(&path, 0o644);
                }
                "source" | "alias" => {
                    fs::rename(&path, &displaced)?;
                    fs::write(&path, b"outside sentinel")?;
                    pin_mode(&path, 0o644);
                }
                _ => {
                    fs::rename(lock_path_for(&path), &displaced)?;
                    fs::write(lock_path_for(&path), b"replacement lock")?;
                    pin_mode(&lock_path_for(&path), 0o600);
                }
            }
            Ok(())
        });
        assert!(result.is_err(), "{kind} publication accepted");
        let expected = if kind == "lock" {
            b"original".as_slice()
        } else {
            b"outside sentinel".as_slice()
        };
        assert_eq!(
            fs::read(&path).unwrap(),
            expected,
            "{kind} destination changed"
        );
        if matches!(kind, "parent" | "lock") {
            assert!(tx.read().is_err(), "observed {kind} cannot be reanchored");
        }
        assert!(
            tx.validate(&binding).is_err(),
            "observed {kind} cannot be a no-op"
        );
        if kind == "alias" {
            assert_eq!(fs::read(&target).unwrap(), b"original");
        }
        if kind == "parent" {
            assert_eq!(fs::read(displaced.join("pins")).unwrap(), b"original");
            assert!(!displaced.join(".temp").exists());
        } else {
            assert!(!parent.join(".temp").exists());
        }
    }
}
