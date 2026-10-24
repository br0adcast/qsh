use crate::FileSink;
use std::fs;
use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

#[test]
fn authority_leaf_aliases_never_modify_outside_sentinels() {
    for hard in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let sentinel = dir.path().join("outside");
        let parent = dir.path().join("logs");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&sentinel, b"owned outside sentinel\n").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o644)).unwrap();
        let path = parent.join("log");
        if hard {
            fs::hard_link(&sentinel, &path).unwrap();
        } else {
            symlink(&sentinel, &path).unwrap();
        }
        let before = (fs::read(&sentinel).unwrap(), mode(&sentinel), mode(&parent));
        let sink = FileSink::open_in_private_dir(&path, 100);
        if let Some(sink) = &sink {
            sink.write_lines(&["must not append".into()]);
        }
        assert_eq!(
            (fs::read(&sentinel).unwrap(), mode(&sentinel), mode(&parent)),
            before,
            "hard={hard}"
        );
        assert!(sink.is_none());
    }
}

#[test]
fn authority_generic_parent_is_never_repaired() {
    let dir = crate::private_test_dir().unwrap();
    for permissions in [0o755, 0o1777] {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(permissions)).unwrap();
        let sink = FileSink::open(&dir.path().join("log"), 100).unwrap();
        sink.write_lines(&["allowed".into()]);
        assert_eq!(mode(dir.path()), permissions);
    }
}

#[test]
fn authority_declared_parent_and_file_are_repaired() {
    let dir = crate::private_test_dir().unwrap();
    let parent = dir.path().join("logs");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    let path = parent.join("log");
    fs::write(&path, b"retained\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let sink = FileSink::open_in_private_dir(&path, 100).unwrap();
    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&path), 0o600);
    sink.write_lines(&["appended".into()]);
    assert_eq!(fs::read(&path).unwrap(), b"retained\nappended\n");
}

#[test]
fn authority_unsafe_ancestor_is_refused_before_mutation() {
    for final_parent in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let unsafe_dir = dir.path().join("unsafe");
        fs::create_dir(&unsafe_dir).unwrap();
        fs::set_permissions(&unsafe_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let parent = if final_parent {
            unsafe_dir.clone()
        } else {
            let p = unsafe_dir.join("logs");
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let before = (mode(&unsafe_dir), mode(&parent));
        let path = parent.join("log");
        assert!(FileSink::open_in_private_dir(&path, 100).is_none());
        assert_eq!((mode(&unsafe_dir), mode(&parent)), before);
        assert!(!path.exists());
    }
}

#[test]
fn authority_declared_sticky_parent_is_not_repaired() {
    let dir = crate::private_test_dir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o1777)).unwrap();
    let path = dir.path().join("log");
    assert!(FileSink::open_in_private_dir(&path, 100).is_none());
    assert_eq!(mode(dir.path()), 0o1777);
    assert!(!path.exists());
}

#[test]
fn authority_directory_leaf_is_refused_without_parent_repair() {
    let dir = crate::private_test_dir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("log");
    fs::create_dir(&path).unwrap();
    assert!(FileSink::open_in_private_dir(&path, 100).is_none());
    assert_eq!(mode(dir.path()), 0o755);
}

#[test]
fn authority_fifo_leaf_is_refused_without_blocking_or_parent_repair() {
    let dir = crate::private_test_dir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("log");
    assert!(std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap()
        .success());
    // A nonblocking reader keeps even the old WRONLY opener from hanging this
    // negative control. The sink must reject the FIFO, not append to it.
    let _reader = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let before = (mode(&path), mode(dir.path()));
    assert!(FileSink::open_in_private_dir(&path, 100).is_none());
    assert_eq!((mode(&path), mode(dir.path())), before);
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_fifo());
}

#[test]
fn authority_trusted_absolute_and_relative_directory_aliases_work() {
    for absolute in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = dir.path().join("alias");
        if absolute {
            symlink(&target, &alias).unwrap();
        } else {
            symlink("target", &alias).unwrap();
        }
        let sink = FileSink::open_in_private_dir(&alias.join("log"), 100).unwrap();
        sink.write_lines(&["alias".into()]);
        assert_eq!(fs::read(target.join("log")).unwrap(), b"alias\n");
        assert_eq!(mode(&target), 0o700);
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn authority_search_only_ancestor_needs_no_directory_read_permission() {
    let dir = crate::private_test_dir().unwrap();
    let search = dir.path().join("search");
    let parent = search.join("logs");
    fs::create_dir(&search).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&search, fs::Permissions::from_mode(0o111)).unwrap();
    let sink = FileSink::open_in_private_dir(&parent.join("log"), 100);
    if let Some(sink) = &sink {
        sink.write_lines(&["search".into()]);
    }
    let unchanged = mode(&search);
    // Restore before assertions or fixture teardown, including failed opens.
    fs::set_permissions(&search, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(sink.is_some());
    assert_eq!(unchanged, 0o111);
    assert_eq!(fs::read(parent.join("log")).unwrap(), b"search\n");
}

#[test]
fn authority_only_declared_final_directory_is_repaired() {
    let dir = crate::private_test_dir().unwrap();
    let shared = dir.path().join("shared");
    let parent = shared.join("qsh");
    fs::create_dir(&shared).unwrap();
    fs::create_dir(&parent).unwrap();
    for p in [&shared, &parent] {
        fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sink = FileSink::open_in_private_dir(&parent.join("log"), 100).unwrap();
    sink.write_lines(&["private".into()]);
    assert_eq!(mode(&shared), 0o755);
    assert_eq!(mode(&parent), 0o700);
}

#[test]
fn authority_failed_or_unestablished_repair_never_authorizes_a_write() {
    use crate::file_path::{Intent, ParentAuthority};
    for noop in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let parent = dir.path().join("logs");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let path = parent.join("log");
        fs::write(&path, b"before\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let authority = ParentAuthority::resolve(&path, Intent::DeclaredPrivate, false).unwrap();
        let before = (fs::read(&path).unwrap(), mode(&path), mode(&parent));
        let opened = authority.open_append_with_repair(|_, _| {
            if noop {
                Ok(())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        });
        assert!(opened.is_err());
        assert_eq!(
            (fs::read(&path).unwrap(), mode(&path), mode(&parent)),
            before
        );
    }
}

#[test]
fn authority_owner_and_sticky_policy_is_explicit_without_privilege() {
    use crate::file_path::{declared_parent, trusted_directory, trusted_leaf};
    for (owner, mode, allowed) in [
        (0, 0o755, true),
        (1000, 0o700, true),
        (1000, 0o775, false),
        (1000, 0o777, false),
        (1000, 0o1777, true),
        (0, 0o777, false),
        (0, 0o1777, true),
        (2000, 0o1777, false),
        (1000, 0o111, true),
    ] {
        assert_eq!(
            trusted_directory(owner, mode, 1000),
            allowed,
            "owner={owner}, mode={mode:o}"
        );
    }
    assert!(trusted_leaf(0, 1, 0));
    assert!(!trusted_leaf(1000, 1, 0));
    assert!(!trusted_leaf(0, 1, 1000));
    assert!(!trusted_leaf(2000, 1, 1000));
    assert!(!trusted_leaf(1000, 2, 1000));
    assert!(trusted_leaf(1000, 1, 1000));
    assert!(!declared_parent(0, 0o755, 1000, false));
    assert!(!declared_parent(0, 0o755, 0, true));
    assert!(!declared_parent(1000, 0o1777, 1000, false));
    assert!(declared_parent(1000, 0o755, 1000, false));
}

#[test]
fn authority_directory_alias_count_is_bounded() {
    for count in [40, 41] {
        let dir = crate::private_test_dir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        for index in (0..count).rev() {
            let next = if index + 1 == count {
                "target".into()
            } else {
                format!("alias{}", index + 1)
            };
            symlink(next, dir.path().join(format!("alias{index}"))).unwrap();
        }
        let opened = FileSink::open_in_private_dir(&dir.path().join("alias0/log"), 100);
        assert_eq!(opened.is_some(), count == 40);
    }
}

#[test]
fn route_held_file_metadata_changes_are_refused_and_recover() {
    for hard in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let path = dir.path().join("log");
        let outside = dir.path().join("outside");
        let sink = FileSink::open(&path, 100).unwrap();
        sink.write_lines(&["initial".into()]);
        let held = sink.try_clone_file().unwrap();
        if hard {
            fs::hard_link(&path, &outside).unwrap();
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        sink.write_lines(&["refused".into()]);
        let after = held.metadata().unwrap().len();
        if hard {
            assert_eq!(fs::read(&outside).unwrap(), b"initial\n");
            fs::remove_file(&outside).unwrap();
        } else {
            assert_eq!(mode(&path), 0o644);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        sink.write_lines(&["recovered".into()]);
        assert_eq!(after, 8, "observed in-place metadata change hard={hard}");
        assert_eq!(fs::read(&path).unwrap(), b"initial\nrecovered\n");
    }
}

#[test]
fn route_unsafe_parent_change_is_refused_without_extending_held_file() {
    let dir = crate::private_test_dir().unwrap();
    let parent = dir.path().join("logs");
    let path = parent.join("log");
    let sink = FileSink::open(&path, 100).unwrap();
    sink.write_lines(&["initial".into()]);
    let held = sink.try_clone_file().unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
    sink.write_lines(&["refused".into()]);
    let after = held.metadata().unwrap().len();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    sink.write_lines(&["recovered".into()]);
    assert_eq!(after, 8);
    assert_eq!(fs::read(path).unwrap(), b"initial\nrecovered\n");
}

#[test]
fn route_rotation_refuses_aliases_and_preserves_outside_metadata() {
    for hard in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let path = dir.path().join("log");
        let rotated = dir.path().join("log.1");
        let outside = dir.path().join("outside");
        fs::write(&outside, b"outside\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
        let sink = FileSink::open(&path, 6).unwrap();
        sink.write_lines(&["first".into()]);
        let held = sink.try_clone_file().unwrap();
        if hard {
            fs::hard_link(&outside, &rotated).unwrap();
        } else {
            symlink(&outside, &rotated).unwrap();
        }
        let before = (
            fs::read(&outside).unwrap(),
            mode(&outside),
            fs::metadata(&outside).unwrap().nlink(),
        );
        let original = fs::symlink_metadata(&rotated).unwrap();
        sink.write_lines(&["next".into()]);
        assert_eq!(held.metadata().unwrap().len(), 6);
        assert_eq!(
            (
                fs::read(&outside).unwrap(),
                mode(&outside),
                fs::metadata(&outside).unwrap().nlink()
            ),
            before
        );
        let after = fs::symlink_metadata(&rotated).unwrap();
        assert_eq!((after.dev(), after.ino()), (original.dev(), original.ino()));
        fs::remove_file(&rotated).unwrap();
        sink.write_lines(&["next".into()]);
        assert_eq!(fs::read(path).unwrap(), b"next\n");
        assert_eq!(fs::read(rotated).unwrap(), b"first\n");
    }
}

#[test]
fn route_active_substitution_refuses_outside_aliases_and_recovers() {
    for hard in [false, true] {
        let dir = crate::private_test_dir().unwrap();
        let path = dir.path().join("log");
        let moved = dir.path().join("held");
        let outside = dir.path().join("outside");
        let sink = FileSink::open(&path, 100).unwrap();
        sink.write_lines(&["initial".into()]);
        let held = sink.try_clone_file().unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::write(&outside, b"outside\n").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o644)).unwrap();
        if hard {
            fs::hard_link(&outside, &path).unwrap();
        } else {
            symlink(&outside, &path).unwrap();
        }
        let before = (
            fs::read(&outside).unwrap(),
            mode(&outside),
            fs::metadata(&outside).unwrap().nlink(),
        );
        sink.write_lines(&["refused".into()]);
        assert_eq!(held.metadata().unwrap().len(), 8);
        assert_eq!(
            (
                fs::read(&outside).unwrap(),
                mode(&outside),
                fs::metadata(&outside).unwrap().nlink()
            ),
            before
        );
        fs::remove_file(&path).unwrap();
        sink.write_lines(&["recovered".into()]);
        assert_eq!(fs::read(path).unwrap(), b"recovered\n");
        assert_eq!(held.metadata().unwrap().len(), 8);
    }
}

#[test]
fn route_declared_alias_replacement_revalidates_ancestors_even_for_same_inode() {
    let dir = crate::private_test_dir().unwrap();
    let target = dir.path().join("target");
    let outside = dir.path().join("outside");
    let alias = dir.path().join("alias");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o777)).unwrap();
    symlink(&target, &alias).unwrap();
    let sink = FileSink::open_in_private_dir(&alias.join("log"), 100).unwrap();
    sink.write_lines(&["initial".into()]);
    let held = sink.try_clone_file().unwrap();
    fs::hard_link(target.join("log"), outside.join("log")).unwrap();
    fs::remove_file(&alias).unwrap();
    symlink(&outside, &alias).unwrap();
    sink.write_lines(&["refused".into()]);
    let after = held.metadata().unwrap().len();
    let outside_bytes = fs::read(outside.join("log")).unwrap();
    fs::remove_file(outside.join("log")).unwrap();
    fs::remove_file(&alias).unwrap();
    symlink(&target, &alias).unwrap();
    sink.write_lines(&["recovered".into()]);
    assert_eq!(after, 8);
    assert_eq!(outside_bytes, b"initial\n");
    assert_eq!(mode(&outside), 0o777);
    assert_eq!(
        fs::read(target.join("log")).unwrap(),
        b"initial\nrecovered\n"
    );
}

#[test]
fn route_valid_replacement_parent_is_reanchored_without_old_inode_growth() {
    let dir = crate::private_test_dir().unwrap();
    let parent = dir.path().join("logs");
    let moved = dir.path().join("old-logs");
    let path = parent.join("log");
    let sink = FileSink::open_in_private_dir(&path, 100).unwrap();
    sink.write_lines(&["initial".into()]);
    let held = sink.try_clone_file().unwrap();
    fs::rename(&parent, &moved).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    sink.write_lines(&["new route".into()]);
    assert_eq!(held.metadata().unwrap().len(), 8);
    assert_eq!(fs::read(&path).unwrap(), b"new route\n");
    assert_eq!(mode(&parent), 0o700);
}

#[test]
fn route_observed_metadata_change_after_refresh_prevents_append() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = crate::private_test_dir().unwrap();
    let path = dir.path().join("log");
    let sink = FileSink::open(&path, 100).unwrap();
    sink.write_lines(&["initial".into()]);
    let observed = Arc::new(AtomicBool::new(false));
    let observed_phase = observed.clone();
    let changed = path.clone();
    sink.before_active_check_once(move || {
        fs::set_permissions(changed, fs::Permissions::from_mode(0o644)).unwrap();
        observed_phase.store(true, Ordering::SeqCst);
    });
    sink.write_lines(&["refused".into()]);
    assert!(observed.load(Ordering::SeqCst));
    assert_eq!(mode(&path), 0o644);
    let after = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    sink.write_lines(&["recovered".into()]);
    assert_eq!(after, b"initial\n");
    assert_eq!(fs::read(path).unwrap(), b"initial\nrecovered\n");
}

#[test]
fn route_relative_path_is_captured_before_later_cwd_changes() {
    const CHILD_ROOT: &str = "QSH_TEST_LOG_ROUTE_CHILD_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = std::path::PathBuf::from(root);
        std::env::set_current_dir(root.join("first")).unwrap();
        let sink = FileSink::open(std::path::Path::new("logs/log"), 6).unwrap();
        sink.write_lines(&["first".into()]);
        std::env::set_current_dir(root.join("second")).unwrap();
        sink.write_lines(&["next".into()]);
        assert_eq!(fs::read(root.join("first/logs/log.1")).unwrap(), b"first\n");
        assert_eq!(fs::read(root.join("first/logs/log")).unwrap(), b"next\n");
        assert!(!root.join("second/logs").exists());
        return;
    }
    let dir = crate::private_test_dir().unwrap();
    for name in ["first", "second"] {
        let path = dir.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Only this exact owned self-exec changes cwd; parallel test callers do not.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "file_path_tests::route_relative_path_is_captured_before_later_cwd_changes",
            "--test-threads=1",
        ])
        .env(CHILD_ROOT, dir.path())
        .env("HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("HISTFILE", "/dev/null")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "owned relative-route control: {status}");
                break;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1))
            }
            result => {
                let _ = child.kill();
                let mut reported = false;
                loop {
                    match child.wait() {
                        Ok(_) => break,
                        Err(error) => {
                            if !reported {
                                eprintln!("retaining owned relative-route child/fixture while cleanup wait fails: {error}");
                                reported = true;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }
                panic!("owned relative-route result deadline/wait failed: {result:?}");
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn authority_darwin_var_alias_is_traversed_natively() {
    assert!(
        fs::symlink_metadata("/var")
            .unwrap()
            .file_type()
            .is_symlink(),
        "this control must exercise the native /var alias"
    );
    let dir = tempfile::Builder::new()
        .prefix("qsh-log-authority-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in("/var/tmp")
        .unwrap();
    let path = dir.path().join("qsh/log");
    let sink = FileSink::open_in_private_dir(&path, 100).unwrap();
    sink.write_lines(&["native var alias".into()]);
    assert_eq!(fs::read(path).unwrap(), b"native var alias\n");
}
