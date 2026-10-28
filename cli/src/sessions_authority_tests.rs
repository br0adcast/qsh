// All tokens/paths below are disposable fixtures; none names a real service.
fn slot139_fixture() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}
fn slot139_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
#[test]
fn slot139_planted_leaves_cannot_change_outside_objects() {
    let dir = slot139_fixture();
    let mut failures = Vec::new();
    for hard in [false, true] {
        let store = dir
            .path()
            .join(if hard { "hard-store" } else { "symbolic-store" });
        std::fs::create_dir(&store).unwrap();
        slot139_mode(&store, 0o700);
        let outside = dir.path().join(if hard {
            "hard-outside"
        } else {
            "symbolic-outside"
        });
        std::fs::write(&outside, b"owned outside sentinel").unwrap();
        slot139_mode(&outside, 0o644);
        for i in 0..MAX_SLOTS {
            let path = store.join(slot_name("alice", "example.invalid", 60000, i));
            if hard {
                std::fs::hard_link(&outside, path).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, path).unwrap();
            }
        }
        let before = std::fs::read(&outside).unwrap();
        let mode = std::fs::metadata(&outside).unwrap().permissions().mode();
        let owner = claim(&store, "alice", "example.invalid", 60000);
        if owner._lock.is_some() {
            failures.push(format!("planted {hard} acquired"));
        }
        drop(owner);
        if std::fs::read(&outside).unwrap() != before
            || std::fs::metadata(&outside).unwrap().permissions().mode() != mode
        {
            failures.push(format!("outside {hard} changed"));
        }
        assert_eq!(std::fs::read_dir(&store).unwrap().count(), MAX_SLOTS);
    }
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn slot139_directory_repair_requires_explicit_intent() {
    let dir = slot139_fixture();
    let store = dir.path().join("generic");
    std::fs::create_dir(&store).unwrap();
    slot139_mode(&store, 0o755);
    let owner = claim(&store, "alice", "example.invalid", 60000);
    assert!(owner._lock.is_some());
    assert_eq!(
        std::fs::metadata(&store).unwrap().permissions().mode() & 0o7777,
        0o755,
        "generic store must not chmod parent"
    );
    drop(owner);
    let path = store.join(slot_name("alice", "example.invalid", 60000, 0));
    slot139_mode(&path, 0o644);
    let before = std::fs::read(&path).unwrap();
    let dedicated = claim_in_private_dir(&store, "alice", "example.invalid", 60000);
    assert!(dedicated._lock.is_some());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&store).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(dedicated);
    let occupied = claim(&store, "alice", "example.invalid", 60000);
    slot139_mode(&path, 0o644);
    let another = claim(&store, "alice", "example.invalid", 60000);
    assert_ne!(occupied.token, another.token);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644,
        "occupied file must not be repaired"
    );
    drop((another, occupied));
    let sticky = dir.path().join("sticky");
    std::fs::create_dir(&sticky).unwrap();
    slot139_mode(&sticky, 0o1777);
    let generic = claim(&sticky, "alice", "example.invalid", 60000);
    assert!(generic._lock.is_some());
    drop(generic);
    let entries = std::fs::read_dir(&sticky).unwrap().count();
    let refused = claim_in_private_dir(&sticky, "alice", "example.invalid", 60000);
    assert!(refused._lock.is_none());
    assert_eq!(
        std::fs::metadata(&sticky).unwrap().permissions().mode() & 0o7777,
        0o1777
    );
    assert_eq!(std::fs::read_dir(&sticky).unwrap().count(), entries);
    slot139_mode(&sticky, 0o700);
}

fn slot139_locked(store: &Store, name: &str) -> SlotLock {
    let file = store.open_candidate(name).unwrap();
    let (parent, binding) = store.binding(name).unwrap();
    assert!(lock_exclusive(&file));
    let slot = SlotLock::new(file, parent, binding);
    store
        .prepare_locked(&slot.parent, &slot.file, &slot.binding)
        .unwrap();
    slot
}
#[test]
fn slot139_bounded_trim_and_read_failures_have_distinct_results() {
    let dir = slot139_fixture();
    let name = slot_name("alice", "example.invalid", 60000, 0);
    let path = dir.path().join(&name);
    let expected = [0xab; 16];
    let mut failures = Vec::new();
    let mut text = format!("\u{2003}{}\r\n", hex(&expected).to_uppercase()).into_bytes();
    text.resize(4096, b' ');
    std::fs::write(&path, &text).unwrap();
    slot139_mode(&path, 0o600);
    let owner = claim(dir.path(), "alice", "example.invalid", 60000);
    assert_eq!(owner.token, expected, "trim/uppercase at exact cap");
    drop(owner);
    text.push(b' ');
    std::fs::write(&path, &text).unwrap();
    let owner = claim(dir.path(), "alice", "example.invalid", 60000);
    if owner.token == expected {
        failures.push("over-cap prefix accepted");
    }
    drop(owner);
    if std::fs::metadata(&path).unwrap().len() != 33 {
        failures.push("over-cap not reinitialized");
    }
    std::fs::write(&path, b"owned read error sentinel").unwrap();
    let store = Store::open(dir.path(), DirectoryIntent::Generic).unwrap();
    let slot = slot139_locked(&store, &name);
    let result = claim_locked(slot, |file| {
        let mut prefix = [0u8; 5];
        file.read_exact(&mut prefix)?;
        assert_eq!(&prefix, b"owned");
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    });
    if result.is_ok() {
        failures.push("read IO error treated as damaged");
    }
    drop(result);
    if std::fs::read(&path).unwrap() != b"owned read error sentinel" {
        failures.push("read IO error truncated input");
    }
    assert_lock_from_subprocess(&path, true);
    std::fs::write(&path, format!("{}\n", hex(&expected))).unwrap();
    let slot = slot139_locked(&store, &name);
    let mut append = OpenOptions::new().append(true).open(&path).unwrap();
    let owner = claim_locked(slot, |file| {
        append.write_all(&vec![b' '; 4096])?;
        read_token_bytes(file)
    })
    .unwrap();
    if owner.token == expected {
        failures.push("growth after open exceeded cap");
    }
    drop(owner);
    for damaged in [Vec::new(), vec![0xff], b"not a token".to_vec()] {
        std::fs::write(&path, damaged).unwrap();
        let owner = claim(dir.path(), "alice", "example.invalid", 60000);
        assert!(owner._lock.is_some());
        drop(owner);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 33);
    }
    // A valid readonly binding reaches real write I/O, not an authority error.
    std::fs::write(&path, b"readonly damaged contents").unwrap();
    let file = OpenOptions::new().read(true).open(&path).unwrap();
    let (parent, binding) = store.binding(&name).unwrap();
    binding.validate_private_current(&parent, &file).unwrap();
    assert!(lock_exclusive(&file));
    let owner = claim_locked(SlotLock::new(file, parent, binding), read_token_bytes).unwrap();
    assert!(owner._lock.is_some());
    assert_eq!(std::fs::read(&path).unwrap(), b"readonly damaged contents");
    assert_lock_from_subprocess(&path, false);
    drop(owner);
    assert_lock_from_subprocess(&path, true);
    std::fs::write(&path, b"invalid-but-private").unwrap();
    let slot = slot139_locked(&store, &name);
    let result = claim_locked(slot, |_| {
        slot139_mode(&path, 0o644);
        Ok(b"invalid-but-private".to_vec())
    });
    assert!(
        result.is_err(),
        "unsafe mode observed before damaged write is refusal"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"invalid-but-private");
    slot139_mode(&path, 0o600);
    assert!(failures.is_empty(), "{failures:?}");
}
#[test]
fn slot139_replacement_refuses_displaced_routes_and_keeps_lock() {
    let dir = slot139_fixture();
    let mut failures = Vec::new();
    for kind in ["leaf", "parent", "mode", "hardlink"] {
        let store = dir.path().join(kind);
        std::fs::create_dir(&store).unwrap();
        slot139_mode(&store, 0o700);
        let mut owner = claim(&store, "alice", "example.invalid", 60000);
        assert!(owner._lock.is_some());
        let token = owner.token;
        let name = slot_name("alice", "example.invalid", 60000, 0);
        let original = store.join(&name);
        let held = match kind {
            "leaf" => {
                let held = store.join("held");
                std::fs::rename(&original, &held).unwrap();
                std::fs::write(&original, b"replacement sentinel").unwrap();
                slot139_mode(&original, 0o600);
                held
            }
            "parent" => {
                let moved = dir.path().join("moved-parent");
                std::fs::rename(&store, &moved).unwrap();
                std::fs::create_dir(&store).unwrap();
                slot139_mode(&store, 0o700);
                std::fs::write(&original, b"replacement sentinel").unwrap();
                slot139_mode(&original, 0o600);
                moved.join(&name)
            }
            "mode" => {
                slot139_mode(&original, 0o644);
                original.clone()
            }
            "hardlink" => {
                std::fs::hard_link(&original, store.join("alias")).unwrap();
                original.clone()
            }
            _ => unreachable!(),
        };
        let before = std::fs::read(&held).unwrap();
        let current = std::fs::read(&original).unwrap();
        if owner.replace_token().is_ok() {
            failures.push(format!("{kind} replacement accepted"));
        }
        if owner.token != token || std::fs::read(&held).unwrap() != before {
            failures.push(format!("{kind} held state changed"));
        }
        if std::fs::read(&original).unwrap() != current {
            failures.push(format!("{kind} named state changed"));
        }
        assert_lock_from_subprocess(&held, false);
        drop(owner);
        assert_lock_from_subprocess(&held, true);
    }
    assert!(failures.is_empty(), "{failures:?}");
}

#[test]
fn path_diagnostics_unavailable_store_warns_once_and_keeps_usable_token() {
    let d = slot139_fixture();
    let parent = d.path().join("unsafe\nparent");
    std::fs::create_dir(&parent).unwrap();
    slot139_mode(&parent, 0o777);
    let mut owner = claim(&parent.join("sessions"), "alice", "example.invalid", 60000);
    let token = owner.token;
    let warning = owner.take_warning().expect("visible persistence warning");
    assert!(warning.contains("future recovery") && warning.contains("unsafe\\nparent"), "{warning}");
    assert!(!warning.contains(&hex(&token)));
    assert!(owner.take_warning().is_none());
    assert!(owner._lock.is_none());
    assert_ne!(token, [0; 16]);
    assert_eq!(std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777, 0o777);
}

#[test]
fn path_diagnostics_failed_initial_write_retains_token_and_lock_with_warning() {
    let d = slot139_fixture();
    let name = slot_name("alice", "example.invalid", 60000, 0);
    let path = d.path().join(&name);
    std::fs::write(&path, b"not a token").unwrap();
    slot139_mode(&path, 0o600);
    let store = Store::open(d.path(), DirectoryIntent::Generic).unwrap();
    let file = OpenOptions::new().read(true).open(&path).unwrap();
    let (parent, binding) = store.binding(&name).unwrap();
    assert!(lock_exclusive(&file));
    let mut owner = claim_locked(SlotLock::new(file, parent, binding), read_token_bytes).unwrap();
    let token = owner.token;
    let warning = owner.take_warning().expect("failed write is visible");
    assert!(warning.contains("future recovery"));
    assert!(!warning.contains(&hex(&token)));
    assert_eq!(owner.token, token);
    assert!(owner._lock.is_some());
    assert_lock_from_subprocess(&path, false);
    assert_eq!(std::fs::read(&path).unwrap(), b"not a token");
}

#[test]
fn group_writable_session_authority_is_refused_without_repair() {
    for final_parent in [false, true] {
        let root = slot139_fixture();
        let unsafe_dir = root.path().join("group-writable");
        std::fs::create_dir(&unsafe_dir).unwrap();
        slot139_mode(&unsafe_dir, 0o775);
        let store = if final_parent {
            unsafe_dir.clone()
        } else {
            let store = unsafe_dir.join("sessions");
            std::fs::create_dir(&store).unwrap();
            slot139_mode(&store, 0o700);
            store
        };
        let mut owner = claim_in_private_dir(&store, "alice", "example.invalid", 60000);
        assert!(owner._lock.is_none());
        assert!(owner.take_warning().is_some());
        assert_eq!(
            std::fs::metadata(&unsafe_dir).unwrap().permissions().mode() & 0o7777,
            0o775
        );
        assert_eq!(std::fs::read_dir(&store).unwrap().count(), 0);
    }
}
