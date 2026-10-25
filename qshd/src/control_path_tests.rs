use super::*;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[test]
fn directory_untrusted_parent_refuses_lock_without_mutation() {
    for intermediate in [false, true] {
        let dir = root();
        let parent = dir.path().join("shared");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let endpoint = if intermediate {
            parent.join("missing/control.sock")
        } else {
            parent.join("control.sock")
        };
        assert!(EnsureLock::acquire(&endpoint, Duration::ZERO).is_err());
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o777);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
}

#[test]
fn directory_trust_failure_is_not_no_daemon() {
    let dir = root();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let result = client_request_with_timeout(
        &dir.path().join("control.sock"),
        &ControlRequest::Status,
        Duration::from_millis(10),
    );
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_err(),
        "unsafe absence is not a trusted first start"
    );
}

#[test]
fn directory_safe_modes_and_aliases_are_not_repaired() {
    let dir = root();
    for mode in [0o755, 0o711] {
        let parent = dir.path().join(format!("safe{mode:o}"));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        let alias = dir.path().join(format!("alias{mode:o}"));
        symlink(&parent, &alias).unwrap();
        drop(EnsureLock::acquire(&alias.join("control.sock"), Duration::ZERO).unwrap());
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, mode);
    }
}

#[test]
fn directory_trusted_missing_endpoint_does_not_create_parents() {
    let dir = root();
    assert_eq!(
        client_request(
            &dir.path().join("missing/control.sock"),
            &ControlRequest::Status
        )
        .unwrap(),
        ControlReply::NoDaemon
    );
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn directory_transaction_refuses_replacement_for_every_request_and_reuse() {
    let dir = root();
    let parent = dir.path().join("cache");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = EnsureLock::acquire(&parent.join("control.sock"), Duration::ZERO).unwrap();
    let moved = dir.path().join("old-cache");
    fs::rename(&parent, &moved).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    for request in [
        ControlRequest::Status,
        ControlRequest::AddClient([8; 32]),
        ControlRequest::Stop,
    ] {
        assert!(lock.request(&request).is_err());
    }
    assert!(lock.endpoint_exists().is_err());
    assert!(
        lock.validate_route().is_err(),
        "reused READY cannot follow a new route"
    );
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    assert!(moved.join("control.sock.lock").is_file());
    fs::remove_dir(&parent).unwrap();
    fs::rename(&moved, &parent).unwrap();
    lock.validate_route().unwrap();
    assert_eq!(
        lock.request(&ControlRequest::Status).unwrap(),
        ControlReply::NoDaemon
    );
}

#[test]
fn directory_existing_stage_alias_never_unlinks_outside_sentinel() {
    let dir = root();
    let outside = root();
    let sentinel = outside.path().join("s");
    fs::write(&sentinel, b"outside stage sentinel").unwrap();
    let before = fs::metadata(&sentinel).unwrap();
    let stage = dir.path().join(format!(".c{}", std::process::id()));
    symlink(outside.path(), &stage).unwrap();
    assert!(bind_private(&dir.path().join("control.sock")).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside stage sentinel");
    let after = fs::metadata(&sentinel).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert!(fs::symlink_metadata(&stage)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn directory_unrelated_final_entries_are_not_replaced() {
    for alias in [false, true] {
        let dir = root();
        let outside = root();
        let sentinel = outside.path().join("sentinel");
        fs::write(&sentinel, b"unrelated final sentinel").unwrap();
        let endpoint = dir.path().join("control.sock");
        if alias {
            symlink(&sentinel, &endpoint).unwrap();
        } else {
            fs::write(&endpoint, b"unrelated final record").unwrap();
        }
        let before = fs::symlink_metadata(&endpoint).unwrap();
        assert!(bind_private(&endpoint).is_err());
        let after = fs::symlink_metadata(&endpoint).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"unrelated final sentinel");
        if !alias {
            assert_eq!(fs::read(&endpoint).unwrap(), b"unrelated final record");
        }
    }
}

#[test]
fn directory_existing_same_pid_stage_is_not_cleaned_speculatively() {
    let dir = root();
    let stage = dir.path().join(format!(".c{}", std::process::id()));
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stage.join("s"), b"existing staged sentinel").unwrap();
    assert!(bind_private(&dir.path().join("control.sock")).is_err());
    assert_eq!(
        fs::read(stage.join("s")).unwrap(),
        b"existing staged sentinel"
    );
}

#[test]
fn directory_search_only_ancestor_is_supported_without_chmod() {
    let dir = root();
    let ancestor = dir.path().join("search");
    let parent = ancestor.join("cache");
    fs::create_dir(&ancestor).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111)).unwrap();
    let result = EnsureLock::acquire(&parent.join("control.sock"), Duration::ZERO);
    let mode = fs::metadata(&ancestor).unwrap().mode() & 0o777;
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
    drop(result.unwrap());
    assert_eq!(mode, 0o111);
}

#[test]
fn directory_cleanup_uses_owned_parent_not_replacement_route() {
    let dir = root();
    let parent = dir.path().join("cache");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let (listener, cleanup) = bind_private_owned(&parent.join("control.sock")).unwrap();
    let old = dir.path().join("old-cache");
    fs::rename(&parent, &old).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = UnixListener::bind(parent.join("control.sock")).unwrap();
    let before = fs::metadata(parent.join("control.sock")).unwrap();
    drop(cleanup);
    assert!(!old.join("control.sock").exists());
    let after = fs::metadata(parent.join("control.sock")).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    drop((listener, replacement));
}

#[test]
fn directory_stage_boundaries_refuse_replacement_without_outside_mutation() {
    for bound in [false, true] {
        let dir = root();
        let outside = root();
        fs::write(outside.path().join("s"), b"outside socket-name sentinel").unwrap();
        let parent = dir.path().join("cache");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = path::EndpointAuthority::open(&parent.join("control.sock"), false).unwrap();
        let mut stage = path::Stage::create(&authority).unwrap();
        let listener = bound.then(|| stage.bind(&authority).unwrap());
        let old = dir.path().join("old-cache");
        fs::rename(&parent, &old).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let name = format!(".c{}", std::process::id());
        symlink(outside.path(), parent.join(&name)).unwrap();
        if bound {
            assert!(stage.publish(&authority).is_err());
        } else {
            assert!(stage.bind(&authority).is_err());
        }
        drop(stage);
        assert!(!old.join(&name).exists());
        assert!(fs::symlink_metadata(parent.join(&name))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(outside.path().join("s")).unwrap(),
            b"outside socket-name sentinel"
        );
        assert!(!parent.join("control.sock").exists());
        drop(listener);
    }
}

#[test]
fn directory_publication_failure_cleans_stage_and_preserves_unrelated_entry() {
    let dir = root();
    let endpoint = dir.path().join("control.sock");
    let authority = path::EndpointAuthority::open(&endpoint, false).unwrap();
    let mut stage = path::Stage::create(&authority).unwrap();
    let listener = stage.bind(&authority).unwrap();
    fs::write(&endpoint, b"new unrelated entry").unwrap();
    assert!(stage.publish(&authority).is_err());
    drop((stage, listener));
    assert_eq!(fs::read(&endpoint).unwrap(), b"new unrelated entry");
    assert!(!dir
        .path()
        .join(format!(".c{}", std::process::id()))
        .exists());
}

#[test]
fn directory_changed_staged_socket_permissions_are_not_published() {
    let dir = root();
    let endpoint = dir.path().join("control.sock");
    let authority = path::EndpointAuthority::open(&endpoint, false).unwrap();
    let mut stage = path::Stage::create(&authority).unwrap();
    let listener = stage.bind(&authority).unwrap();
    let private_socket = dir.path().join(format!(".c{}/s", std::process::id()));
    fs::set_permissions(&private_socket, fs::Permissions::from_mode(0o644)).unwrap();
    let result = stage.publish(&authority);
    drop((stage, listener));
    assert!(
        result.is_err(),
        "observed socket disclosure must not be published"
    );
    assert!(!endpoint.exists());
}

#[test]
fn directory_lock_wait_never_adopts_a_replacement_parent() {
    let dir = root();
    let parent = dir.path().join("cache");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let old = dir.path().join("old-cache");
    let result = EnsureLock::acquire_prepared(&parent.join("control.sock"), Duration::ZERO, || {
        fs::rename(&parent, &old).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    assert!(old.join("control.sock.lock").is_file());
}

#[test]
fn directory_observed_stage_alias_before_chmod_cannot_touch_sentinel() {
    let dir = root();
    let outside = root();
    let sentinel = outside.path().join("s");
    fs::write(&sentinel, b"before chmod sentinel").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o666)).unwrap();
    let before = fs::metadata(&sentinel).unwrap();
    let authority = path::EndpointAuthority::open(&dir.path().join("control.sock"), false).unwrap();
    let mut stage = path::Stage::create(&authority).unwrap();
    let staged = dir.path().join(format!(".c{}", std::process::id()));
    let moved = dir.path().join("moved-stage");
    let alias = staged.clone();
    let target = outside.path().to_owned();
    stage.before_chmod = Some(Box::new(move || {
        fs::rename(&alias, &moved).unwrap();
        symlink(target, alias).unwrap();
    }));
    assert!(stage.bind(&authority).is_err());
    drop(stage);
    let after = fs::metadata(&sentinel).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"before chmod sentinel");
    assert!(fs::symlink_metadata(&staged)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(!dir.path().join("moved-stage/s").exists());
    // The renamed stage has no longer-known parent name; only this owned
    // fixture removes it. Production never guesses an alternate cleanup name.
    assert!(dir.path().join("moved-stage").is_dir());
}

#[test]
fn directory_sweep_refuses_a_replaced_candidate_name() {
    use std::os::fd::AsRawFd;
    let dir = root();
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let pid = child.id().try_into().unwrap();
    let waited = child.wait();
    if let Err(error) = &waited {
        eprintln!("owned sweep-fixture wait failed; retaining child and directory until terminal wait: {error}");
        if let Err(error) = child.kill() {
            eprintln!("owned sweep-fixture termination failed; retaining custody: {error}");
        }
        loop {
            match child.wait() {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
    // Propagate the original error only after this exact child is reaped.
    assert!(waited.unwrap().success());
    let name = format!(".c{pid}");
    let candidate = dir.path().join(&name);
    fs::create_dir(&candidate).unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let old = std::time::SystemTime::now() - STALE_STAGING_AFTER - Duration::from_secs(1);
    fs::File::open(&candidate)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let authority = path::EndpointAuthority::open(&dir.path().join("control.sock"), false).unwrap();
    let result = remove_if_stale_prepared(
        authority.parent.as_raw_fd(),
        &name,
        pid,
        std::time::SystemTime::now(),
        || {
            fs::rename(&candidate, dir.path().join("old-stage")).unwrap();
            fs::create_dir(&candidate).unwrap();
        },
    );
    assert!(!result);
    assert!(candidate.is_dir());
    assert!(dir.path().join("old-stage").is_dir());
}

#[test]
fn directory_connect_infrastructure_error_is_not_no_daemon() {
    let dir = root();
    let short = dir.path().join("short");
    let listener = UnixListener::bind(&short).unwrap();
    let long = dir.path().join("x".repeat(128));
    fs::create_dir(&long).unwrap();
    fs::set_permissions(&long, fs::Permissions::from_mode(0o700)).unwrap();
    let endpoint = long.join("control.sock");
    fs::rename(&short, &endpoint).unwrap();
    let error = client_request(&endpoint, &ControlRequest::Status).unwrap_err();
    assert_eq!(
        error.to_string(),
        "connecting to the trusted control endpoint"
    );
    assert!(endpoint.exists());
    drop(listener);
}

#[test]
fn directory_post_publication_failure_cleans_only_its_owned_socket() {
    let dir = root();
    let parent = dir.path().join("cache");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let transaction = EnsureLock::acquire(&parent.join("control.sock"), Duration::ZERO).unwrap();
    let replacement_path = dir.path().join("replacement.sock");
    let replacement = UnixListener::bind(&replacement_path).unwrap();
    let before = fs::metadata(&replacement_path).unwrap();
    let old = dir.path().join("old-cache");
    let changed_parent = parent.clone();
    let result = bind_prepared(&transaction.authority, |stage| {
        stage.after_publish = Some(Box::new(move || {
            fs::rename(&changed_parent, &old).unwrap();
            fs::create_dir(&changed_parent).unwrap();
            fs::set_permissions(&changed_parent, fs::Permissions::from_mode(0o700)).unwrap();
            fs::rename(&replacement_path, changed_parent.join("control.sock")).unwrap();
        }));
    });
    assert!(result.is_err());
    assert!(!dir.path().join("old-cache/control.sock").exists());
    assert!(!dir
        .path()
        .join(format!("old-cache/.c{}", std::process::id()))
        .exists());
    assert!(dir.path().join("old-cache/control.sock.lock").is_file());
    let after = fs::metadata(parent.join("control.sock")).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert!(UnixStream::connect(parent.join("control.sock")).is_ok());
    assert!(!parent.join("control.sock.lock").exists());
    drop(replacement);
}

#[test]
fn directory_relative_socket_spelling_survives_a_long_owned_cwd() {
    const CASE: &str = "QSH_TEST_CONTROL_RELATIVE_CASE";
    const NAME: &str =
        "control::path_tests::directory_relative_socket_spelling_survives_a_long_owned_cwd";
    if std::env::var(CASE).as_deref() == Ok("owned") {
        use std::io::{BufRead, Write};
        let cwd = std::env::current_dir().unwrap();
        assert!(cwd.as_os_str().len() > 107);
        // Establish the original short-relative Unix API behavior first.
        let plain = UnixListener::bind("plain.sock").unwrap();
        let plain_client = UnixStream::connect("plain.sock").unwrap();
        drop((plain, plain_client));
        fs::remove_file("plain.sock").unwrap();
        println!("owned short-relative bind/connect work beyond the absolute sun_path limit");

        let relative = std::path::Path::new("./control.sock");
        let transaction = EnsureLock::acquire(relative, Duration::ZERO).unwrap();
        let (listener, cleanup) = transaction.bind_private_owned().unwrap();
        let address = listener.local_addr().unwrap();
        let bound = address.as_pathname().unwrap();
        assert!(!bound.is_absolute());
        assert_eq!(bound.file_name().unwrap(), "s");
        assert_eq!(
            bound.parent().unwrap().file_name().unwrap(),
            format!(".c{}", std::process::id()).as_str()
        );

        let success_listener = listener.try_clone().unwrap();
        let (ready, configured) = std::sync::mpsc::channel();
        let observer = std::thread::spawn(move || {
            let mut stream = peer_fixture::accept(
                &success_listener,
                std::time::Instant::now() + Duration::from_secs(2),
            );
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            ready.send(()).unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            stream.write_all(b"relative response\n").unwrap();
            request
        });
        let reply = client_request_with_peer_check(
            relative,
            &ControlRequest::Status,
            Duration::from_secs(2),
            |stream| {
                configured
                    .recv_timeout(Duration::from_secs(2))
                    .context("owned relative observer readiness")?;
                check_control_peer(stream)
            },
        );
        let request = observer.join().unwrap();
        assert_eq!(
            reply.unwrap(),
            ControlReply::Answered("relative response".into())
        );
        assert_eq!(request, "STATUS\n");

        let different = root();
        let next_cwd = different.path().to_owned();
        let (ready, configured) = std::sync::mpsc::channel();
        let observer = std::thread::spawn(move || {
            let mut stream = peer_fixture::accept(
                &listener,
                std::time::Instant::now() + Duration::from_secs(2),
            );
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            ready.send(()).unwrap();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut stream, &mut bytes).unwrap();
            bytes
        });
        let reply = client_request_with_peer_check(
            relative,
            &ControlRequest::Status,
            Duration::from_secs(2),
            |stream| {
                configured
                    .recv_timeout(Duration::from_secs(2))
                    .context("owned relative observer readiness")?;
                check_control_peer(stream)?;
                // This is the owned self-exec child, never the shared test runner.
                std::env::set_current_dir(next_cwd)?;
                Ok(())
            },
        );
        let bytes = observer.join().unwrap();
        assert_eq!(
            reply.unwrap_err().to_string(),
            "the control endpoint working directory changed"
        );
        assert!(
            bytes.is_empty(),
            "cwd change must be rejected before request bytes"
        );
        assert!(transaction.request(&ControlRequest::Status).is_err());
        assert!(transaction.endpoint_exists().is_err());
        assert!(transaction.bind_private_owned().is_err());
        drop(cleanup);
        assert!(
            !cwd.join("control.sock").exists(),
            "cleanup remains pinned after cwd change"
        );
        assert!(!different.path().join("control.sock").exists());
        std::env::set_current_dir(cwd).unwrap();
        println!("owned relative cwd rejection preserved zero request bytes and pinned cleanup");
        return;
    }

    let dir = root();
    let long = dir.path().join("x".repeat(128));
    fs::create_dir(&long).unwrap();
    fs::set_permissions(&long, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
        .current_dir(long)
        .env(CASE, "owned")
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path())
        .env("HISTFILE", "/dev/null")
        .env("RUST_BACKTRACE", "0")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let observed = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Ok(None) => {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned relative child result deadline",
                ))
            }
            Err(error) => break Err(error),
        }
    };
    if observed.is_err() {
        if let Err(error) = child.kill() {
            eprintln!("owned relative child termination failed; retaining custody: {error}");
        }
        let mut reported = false;
        loop {
            match child.wait() {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    if !reported {
                        eprintln!("owned relative child wait failed; retaining child and directory: {error}");
                        reported = true;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    // Every path above established a terminal wait before collecting pipes
    // or allowing this owned directory to be removed.
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        observed.is_ok() && output.status.success(),
        "owned relative control failed: {observed:?}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout
        .contains("owned short-relative bind/connect work beyond the absolute sun_path limit"));
    assert!(stdout
        .contains("owned relative cwd rejection preserved zero request bytes and pinned cleanup"));
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored;"));
}
