#[path = "support/releases.rs"]
mod support;
use bringup::{ImageError, ImageSource, InstallTiming};
use qsh::releases::{release_urls, GitHubImages};
use std::{
    fs,
    sync::{atomic::AtomicUsize, Arc},
};
use support::*;
fn cache_test_dir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn load(root: &std::path::Path, transport: Arc<Fake>) -> Result<bringup::DaemonImage, ImageError> {
    GitHubImages::with_transport(root.into(), transport).load(
        &request(),
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    )
}
fn object(root: &std::path::Path, archive: &[u8]) -> std::path::PathBuf {
    root.join("releases/0.4.0/x86_64-unknown-linux-musl/objects")
        .join(digest(archive))
}

#[test]
fn optional_cache_open_failure_still_returns_verified_download() {
    let root = cache_test_dir().unwrap();
    let blocked = root.path().join("cache");
    fs::write(&blocked, b"keep this file").unwrap();
    let online = Fake::new(archive());
    let image = load(&blocked, online.clone()).expect("cache storage is optional");
    assert_eq!(&*image.bytes, IMAGE);
    assert_eq!(
        online.calls(),
        2,
        "fetch current sums and verify a fresh archive"
    );
    assert_eq!(fs::read(blocked).unwrap(), b"keep this file");
}

#[test]
fn optional_cache_lock_failure_still_returns_verified_download() {
    let root = cache_test_dir().unwrap();
    let lock = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/.lock");
    fs::create_dir_all(&lock).unwrap();
    let online = Fake::new(archive());
    let image = load(root.path(), online.clone()).expect("unusable lock skips cache");
    assert_eq!(&*image.bytes, IMAGE);
    assert_eq!(online.calls(), 2);
    assert!(lock.is_dir());
}

#[test]
fn optional_cache_publication_failure_keeps_verified_image() {
    let root = cache_test_dir().unwrap();
    let pointer = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/current.json");
    fs::create_dir_all(&pointer).unwrap();
    let online = Fake::new(archive());
    let image = load(root.path(), online.clone()).expect("publication follows verification");
    assert_eq!(&*image.bytes, IMAGE);
    assert_eq!(online.calls(), 2);
    assert!(pointer.is_dir());
}

#[test]
fn optional_cache_repair_failure_keeps_reverified_offline_image() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let cached_image = object(root.path(), &bytes).join("image");
    fs::remove_file(&cached_image).unwrap();
    fs::create_dir(&cached_image).unwrap();
    let offline = Fake::offline();
    let image = load(root.path(), offline.clone()).expect("verified archive does not need repair");
    assert_eq!(&*image.bytes, IMAGE);
    assert_eq!(offline.calls(), 1, "still check GitHub before offline use");
    assert!(cached_image.is_dir());
}

#[test]
fn optional_cache_archive_read_failure_downloads_and_verifies_fresh_image() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let cached_archive = object(root.path(), &bytes).join("archive");
    fs::remove_file(&cached_archive).unwrap();
    fs::create_dir(&cached_archive).unwrap();
    let online = Fake::new(bytes);
    let image = load(root.path(), online.clone()).expect("unreadable cache is a miss");
    assert_eq!(&*image.bytes, IMAGE);
    assert_eq!(online.calls(), 2);
    assert!(cached_archive.is_dir());
}

#[test]
fn optional_cache_failure_never_bypasses_metadata_or_archive_verification() {
    let root = cache_test_dir().unwrap();
    let blocked = root.path().join("cache");
    fs::write(&blocked, b"storage unavailable").unwrap();
    for metadata in [
        b"invalid metadata".to_vec(),
        format!("{}  {STEM}.tar.gz\n", "00".repeat(32)).into_bytes(),
    ] {
        let online = Arc::new(Fake {
            sums: metadata,
            archive: archive(),
            calls: AtomicUsize::new(0),
            offline: false,
        });
        assert!(matches!(load(&blocked, online), Err(ImageError::Checksum)));
    }
}

#[test]
fn offline_cache_never_uses_a_different_release_version() {
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    let mut other = request();
    other.version = "0.4.1".into();
    let offline = Fake::offline();
    let result = GitHubImages::with_transport(root.path().into(), offline.clone()).load(
        &other,
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(matches!(result, Err(ImageError::Download(_))));
    assert_eq!(offline.calls(), 1);
}

#[test]
fn optional_cache_does_not_follow_unsafe_descendants() {
    use std::os::unix::fs::symlink;
    let root = cache_test_dir().unwrap();
    let outside = cache_test_dir().unwrap();
    let sentinel = outside.path().join("keep");
    fs::write(&sentinel, b"unchanged").unwrap();
    symlink(outside.path(), root.path().join("releases")).unwrap();
    let online = Fake::new(archive());
    assert_eq!(&*load(root.path(), online.clone()).unwrap().bytes, IMAGE);
    assert_eq!(online.calls(), 2);
    assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    assert!(matches!(
        load(root.path(), Fake::offline()),
        Err(ImageError::Download(_))
    ));
}

#[test]
fn optional_cache_cannot_hide_publication_deadline() {
    let root = cache_test_dir().unwrap();
    let blocked = root.path().join("cache");
    fs::write(&blocked, b"storage unavailable").unwrap();
    let online = Fake::new(archive());
    let result = GitHubImages::with_transport(blocked, online.clone()).load(
        &request(),
        &InstallTiming {
            publish: std::time::Duration::ZERO,
            ..InstallTiming::default()
        },
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(matches!(result, Err(ImageError::Invalid(_))));
    assert_eq!(
        online.calls(),
        2,
        "deadline applies after verified download"
    );
}

#[test]
fn optional_cache_cannot_hide_cancellation_after_metadata() {
    use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
    struct CancelAfterMetadata;
    impl ReleaseTransport for CancelAfterMetadata {
        fn fetch(
            &self,
            url: &str,
            _: FetchLimits,
            cancel: &knock::Cancel,
            _: &dyn bringup::BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            assert!(
                url.ends_with("SHA256SUMS"),
                "cancellation must stop archive download"
            );
            cancel.cancel();
            Ok(sums(&archive()))
        }
    }
    let root = cache_test_dir().unwrap();
    let blocked = root.path().join("cache");
    fs::write(&blocked, b"storage unavailable").unwrap();
    let result = GitHubImages::with_transport(blocked, Arc::new(CancelAfterMetadata)).load(
        &request(),
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(matches!(result, Err(ImageError::Cancelled)));
}
#[test]
fn release_cache_path_uses_xdg_then_home_independently_of_host_os() {
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
    };
    assert_eq!(
        qsh::releases::release_cache_root(
            Some(OsStr::new("/private/xdg")),
            Path::new("/private/home")
        ),
        PathBuf::from("/private/xdg/qsh")
    );
    assert_eq!(
        qsh::releases::release_cache_root(None, Path::new("/private/home")),
        PathBuf::from("/private/home/.cache/qsh")
    );
}

#[test]
fn selected_release_cache_loads_complete_generation_when_github_is_unreachable() {
    let home = cache_test_dir().unwrap();
    let xdg = cache_test_dir().unwrap();
    for configured in [Some(xdg.path().as_os_str()), None] {
        let root = qsh::releases::release_cache_root(configured, home.path());
        let expected = if configured.is_some() {
            xdg.path().join("qsh")
        } else {
            home.path().join(".cache/qsh")
        };
        assert_eq!(root, expected);
        load(&expected, Fake::new(archive())).unwrap();
        let offline = Fake::offline();
        assert_eq!(&*load(&root, offline.clone()).unwrap().bytes, IMAGE);
        assert_eq!(offline.calls(), 1);
    }
}

#[test]
fn exact_release_urls_and_invalid_literal_requests() {
    let mut req = request();
    req.platform = bringup::Platform::from_uname("Darwin", "arm64").unwrap();
    let (sums, archive) = release_urls(&req).unwrap();
    assert_eq!(
        sums,
        "https://github.com/br0adcast/qsh/releases/download/v0.4.0/SHA256SUMS"
    );
    assert!(archive.ends_with("/v0.4.0/qsh-0.4.0-aarch64-apple-darwin.tar.gz"));
    req.version = "../escape".into();
    let root = cache_test_dir().unwrap();
    let fake = Fake::new(support::archive());
    assert!(matches!(release_urls(&req), Err(ImageError::Invalid(_))));
    assert!(matches!(
        GitHubImages::with_transport(root.path().into(), fake.clone()).load(
            &req,
            &InstallTiming::default(),
            &knock::Cancel::new(),
            &Silent
        ),
        Err(ImageError::Invalid(_))
    ));
    assert_eq!(fake.calls(), 0);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
#[test]
fn valid_cache_is_offline_and_repairs_image_from_verified_archive() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    assert_eq!(
        &*load(root.path(), Fake::new(bytes.clone())).unwrap().bytes,
        IMAGE
    );
    let offline = Fake::offline();
    assert_eq!(&*load(root.path(), offline.clone()).unwrap().bytes, IMAGE);
    fs::write(object(root.path(), &bytes).join("image"), b"corrupt").unwrap();
    assert_eq!(&*load(root.path(), offline.clone()).unwrap().bytes, IMAGE);
    assert_eq!(
        fs::read(object(root.path(), &bytes).join("image")).unwrap(),
        IMAGE
    );
    assert_eq!(offline.calls(), 2);
}
#[test]
fn corrupt_archive_is_redownloaded_and_generation_repaired() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    fs::write(object(root.path(), &bytes).join("archive"), b"broken").unwrap();
    assert!(load(root.path(), Fake::offline()).is_err());
    let online = Fake::new(bytes.clone());
    load(root.path(), online.clone()).unwrap();
    assert_eq!(online.calls(), 2);
    assert_eq!(
        fs::read(object(root.path(), &bytes).join("archive")).unwrap(),
        bytes
    );
}
#[test]
fn missing_duplicate_and_malformed_sums_or_wrong_digest_fail() {
    for sums in [
        vec![],
        b"bad checksum".to_vec(),
        [sums(&archive()), sums(&archive())].concat(),
        format!("{}  {STEM}.tar.gz\n", "00".repeat(32)).into_bytes(),
    ] {
        let fake = Arc::new(Fake {
            sums,
            archive: archive(),
            calls: AtomicUsize::new(0),
            offline: false,
        });
        let root = cache_test_dir().unwrap();
        assert!(matches!(load(root.path(), fake), Err(ImageError::Checksum)));
    }
}
#[test]
fn traversal_links_special_entries_duplicates_and_missing_image_fail() {
    let name = format!("{STEM}/qshd");
    for entries in [
        vec![("../escape", b'0', &b""[..]), (&name, b'0', IMAGE)],
        vec![(&name, b'2', &b""[..])],
        vec![(&name, b'1', &b""[..])],
        vec![(&name, b'6', &b""[..])],
        vec![(&name, b'0', IMAGE), (&name, b'0', IMAGE)],
        vec![("/absolute", b'0', IMAGE)],
        vec![("other", b'0', IMAGE)],
    ] {
        let root = cache_test_dir().unwrap();
        assert!(matches!(
            load(root.path(), Fake::new(gzip(&tar(&entries)))),
            Err(ImageError::Archive(_))
        ));
    }
}
#[test]
fn entry_image_stream_and_download_limits_are_enforced() {
    let name = format!("{STEM}/qshd");
    let large = vec![0; 32 * 1024 * 1024 + 1];
    let ignored = format!("{STEM}/ignored");
    let mut many = vec![(ignored.as_str(), b'0', &b""[..]); 128];
    many.push((&name, b'0', IMAGE));
    let mut trailing = tar(&[(&name, b'0', IMAGE)]);
    trailing.resize(128 * 1024 * 1024 + 1, 0);
    let skipped = vec![0; 128 * 1024 * 1024 + 1];
    for bytes in [
        gzip(&tar(&many)),
        gzip(&tar(&[(&name, b'0', &large)])),
        gzip(&trailing),
        gzip(&tar(&[
            (ignored.as_str(), b'0', &skipped),
            (&name, b'0', IMAGE),
        ])),
    ] {
        let root = cache_test_dir().unwrap();
        assert!(matches!(
            load(root.path(), Fake::new(bytes)),
            Err(ImageError::Archive(_))
        ));
    }
    for (metadata, bytes) in [
        (true, vec![0; 1024 * 1024 + 1]),
        (false, vec![0; 64 * 1024 * 1024 + 1]),
    ] {
        let fake = Arc::new(Fake {
            sums: if metadata {
                bytes.clone()
            } else {
                sums(&bytes)
            },
            archive: bytes,
            calls: AtomicUsize::new(0),
            offline: false,
        });
        let root = cache_test_dir().unwrap();
        assert!(matches!(
            load(root.path(), fake),
            Err(ImageError::Download(_))
        ));
    }
}
#[test]
fn cancellation_prevents_cache_or_network_work() {
    let root = cache_test_dir().unwrap();
    let fake = Fake::new(archive());
    let cancel = knock::Cancel::new();
    cancel.cancel();
    assert!(matches!(
        GitHubImages::with_transport(root.path().into(), fake.clone()).load(
            &request(),
            &InstallTiming::default(),
            &cancel,
            &Silent
        ),
        Err(ImageError::Cancelled)
    ));
    assert_eq!(fake.calls(), 0);
}
#[test]
fn unsafe_receipts_and_symlinks_are_never_used() {
    use std::os::unix::fs::symlink;
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let outside = cache_test_dir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    fs::remove_file(object(root.path(), &bytes).join("image")).unwrap();
    symlink(&victim, object(root.path(), &bytes).join("image")).unwrap();
    let _ = load(root.path(), Fake::offline());
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    fs::write(
        target.join("current.json"),
        br#"{"archive_sha256":"../../../../escape"}"#,
    )
    .unwrap();
    assert!(load(root.path(), Fake::offline()).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
}
#[test]
fn corrupt_receipt_cannot_bless_a_modified_image() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let path = object(root.path(), &bytes);
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("receipt.json")).unwrap()).unwrap();
    receipt["image_sha256"] = digest(b"modified").into();
    receipt["image_size"] = 8.into();
    fs::write(
        path.join("receipt.json"),
        serde_json::to_vec(&receipt).unwrap(),
    )
    .unwrap();
    fs::write(path.join("image"), b"modified").unwrap();
    assert_eq!(&*load(root.path(), Fake::offline()).unwrap().bytes, IMAGE);
}
#[test]
fn concurrent_processes_publish_a_complete_generation() {
    let root = cache_test_dir().unwrap();
    let exe = std::env::current_exe().unwrap();
    struct Workers<'a> {
        children: Vec<std::process::Child>,
        _root: &'a tempfile::TempDir,
    }
    impl Drop for Workers<'_> {
        fn drop(&mut self) {
            for child in &mut self.children {
                match child.try_wait() {
                    Ok(Some(_)) => continue,
                    Ok(None) => {
                        let _ = child.kill();
                    }
                    Err(error) => eprintln!(
                        "owned cache worker observation failed; retaining custody: {error}"
                    ),
                }
                let mut reported = false;
                loop {
                    match child.wait() {
                        Ok(_) => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            if !reported {
                                eprintln!(
                                    "owned cache worker wait failed; retaining custody: {error}"
                                );
                                reported = true;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                }
            }
        }
    }
    let mut workers = Workers {
        children: Vec::new(),
        _root: &root,
    };
    for _ in 0..2 {
        workers.children.push(
            std::process::Command::new(&exe)
                .args(["--exact", "cache_process_worker", "--nocapture"])
                .env("QSH_TEST_RELEASE_CACHE", root.path())
                .env("HOME", root.path())
                .env("XDG_CACHE_HOME", root.path())
                .env("XDG_CONFIG_HOME", root.path())
                .env("HISTFILE", "/dev/null")
                .spawn()
                .unwrap(),
        );
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fs::read_dir(root.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
        .count()
        < 2
    {
        assert!(
            std::time::Instant::now() < deadline,
            "workers failed to reach barrier"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    fs::write(root.path().join("go"), b"").unwrap();
    for child in &mut workers.children {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "owned cache worker exceeded its result deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let offline = Fake::offline();
    assert_eq!(&*load(root.path(), offline.clone()).unwrap().bytes, IMAGE);
    assert_eq!(offline.calls(), 1);
    assert_eq!(
        fs::read_dir(
            root.path()
                .join("releases/0.4.0/x86_64-unknown-linux-musl/objects")
        )
        .unwrap()
        .count(),
        1
    );
}
#[test]
fn cache_process_worker() {
    let Some(root) = std::env::var_os("QSH_TEST_RELEASE_CACHE") else {
        return;
    };
    let root = std::path::Path::new(&root);
    fs::write(root.join(format!("ready-{}", std::process::id())), b"").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !root.join("go").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(&*load(root, Fake::new(archive())).unwrap().bytes, IMAGE);
}
#[test]
fn cancelled_lock_wait_returns_promptly() {
    use std::os::fd::AsRawFd;
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    let lock = fs::File::open(
        root.path()
            .join("releases/0.4.0/x86_64-unknown-linux-musl/.lock"),
    )
    .unwrap();
    // SAFETY: lock owns a valid descriptor until this test returns.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let cancel = knock::Cancel::new();
    let copy = cancel.clone();
    let thread = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        copy.cancel();
    });
    let start = std::time::Instant::now();
    let result = GitHubImages::with_transport(root.path().into(), Fake::offline()).load(
        &request(),
        &InstallTiming::default(),
        &cancel,
        &Silent,
    );
    assert!(matches!(result, Err(ImageError::Cancelled)));
    assert!(start.elapsed() < std::time::Duration::from_millis(300));
    thread.join().unwrap();
}
#[test]
fn truncated_gzip_and_hidden_special_entries_cannot_be_published() {
    let name = format!("{STEM}/qshd");
    let link = format!("{STEM}/link");
    let traversal = format!("{STEM}/../outside");
    let mut truncated = archive();
    truncated.truncate(truncated.len() - 3);
    for bytes in [
        truncated,
        gzip(&tar(&[(&name, b'0', IMAGE), (&link, b'2', b"")])),
        gzip(&tar(&[(&name, b'0', IMAGE), (&traversal, b'0', b"")])),
    ] {
        let root = cache_test_dir().unwrap();
        assert!(matches!(
            load(root.path(), Fake::new(bytes)),
            Err(ImageError::Archive(_))
        ));
        assert!(!root
            .path()
            .join("releases/0.4.0/x86_64-unknown-linux-musl/current.json")
            .exists());
    }
}
#[test]
fn failed_download_preserves_prior_generation_and_pointer() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let receipt_path = object(root.path(), &bytes).join("receipt.json");
    let saved_receipt = fs::read(&receipt_path).unwrap();
    // Make the selected receipt invalid, but keep its bytes for the failure check.
    fs::write(&receipt_path, b"bad receipt").unwrap();
    let current = fs::read(target.join("current.json")).unwrap();
    assert!(load(root.path(), Fake::offline()).is_err());
    assert_eq!(fs::read(target.join("current.json")).unwrap(), current);
    assert_eq!(
        fs::read(object(root.path(), &bytes).join("archive")).unwrap(),
        bytes
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), b"bad receipt");
    fs::write(&receipt_path, saved_receipt).unwrap();
    assert_eq!(&*load(root.path(), Fake::offline()).unwrap().bytes, IMAGE);
}
#[test]
fn offline_image_repair_honors_publication_budget() {
    let root = cache_test_dir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let image_path = object(root.path(), &bytes).join("image");
    fs::write(&image_path, b"broken image").unwrap();
    let timing = InstallTiming {
        publish: std::time::Duration::ZERO,
        ..InstallTiming::default()
    };
    let result = GitHubImages::with_transport(root.path().into(), Fake::offline()).load(
        &request(),
        &timing,
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(result.is_err());
    assert_eq!(fs::read(image_path).unwrap(), b"broken image");
}
#[test]
fn another_download_does_not_hold_the_cache_lock() {
    use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
    use std::sync::{mpsc, Mutex};
    struct Paused {
        started: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        fake: Arc<Fake>,
    }
    impl ReleaseTransport for Paused {
        fn fetch(
            &self,
            url: &str,
            limits: FetchLimits,
            cancel: &knock::Cancel,
            observer: &dyn bringup::BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            if url.ends_with("SHA256SUMS") {
                self.started.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
            self.fake.fetch(url, limits, cancel, observer)
        }
    }
    let root = cache_test_dir().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let source = GitHubImages::with_transport(
        root.path().into(),
        Arc::new(Paused {
            started: started_tx,
            release: Mutex::new(release_rx),
            fake: Fake::new(archive()),
        }),
    );
    let worker = std::thread::spawn(move || {
        source.load(
            &request(),
            &InstallTiming::default(),
            &knock::Cancel::new(),
            &Silent,
        )
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let timing = InstallTiming {
        verify: std::time::Duration::from_millis(100),
        ..InstallTiming::default()
    };
    let second = GitHubImages::with_transport(root.path().into(), Fake::new(archive())).load(
        &request(),
        &timing,
        &knock::Cancel::new(),
        &Silent,
    );
    release_tx.send(()).unwrap();
    let first = worker.join().unwrap();
    assert_eq!(&*first.unwrap().bytes, IMAGE);
    assert_eq!(&*second.unwrap().bytes, IMAGE);
}

#[test]
fn a_cache_hit_checks_current_metadata_without_downloading_the_archive() {
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    let online = Fake::new(archive());
    assert_eq!(&*load(root.path(), online.clone()).unwrap().bytes, IMAGE);
    assert_eq!(online.calls(), 1, "fetch SHA256SUMS even on a cache hit");
}

#[test]
fn changed_published_checksum_replaces_the_cached_generation() {
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    let replacement = b"a replacement verified daemon";
    let updated = Fake::new(gzip(&tar(&[(&format!("{STEM}/qshd"), b'0', replacement)])));
    assert_eq!(
        &*load(root.path(), updated.clone()).unwrap().bytes,
        replacement
    );
    assert_eq!(updated.calls(), 2);
}

#[test]
fn invalid_metadata_never_falls_back_to_a_valid_cache() {
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    for sums in [
        vec![],
        b"invalid checksum metadata".to_vec(),
        [sums(&archive()), sums(&archive())].concat(),
        format!("{}  {STEM}.tar.gz\n", "00".repeat(32)).into_bytes(),
    ] {
        let online = Arc::new(Fake {
            sums,
            archive: archive(),
            calls: AtomicUsize::new(0),
            offline: false,
        });
        assert!(matches!(
            load(root.path(), online),
            Err(ImageError::Checksum)
        ));
    }
}

#[test]
fn rejected_metadata_and_cancel_never_use_a_cached_image() {
    use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
    struct Rejected(ImageError);
    impl ReleaseTransport for Rejected {
        fn fetch(
            &self,
            _: &str,
            _: FetchLimits,
            _: &knock::Cancel,
            _: &dyn bringup::BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            Err(FetchError::Rejected(self.0.clone()))
        }
    }
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    for error in [
        ImageError::Unavailable("HTTP 404".into()),
        ImageError::Download("untrusted certificate".into()),
        ImageError::Download("unsafe redirect".into()),
        ImageError::Cancelled,
    ] {
        let result =
            GitHubImages::with_transport(root.path().into(), Arc::new(Rejected(error.clone())))
                .load(
                    &request(),
                    &InstallTiming::default(),
                    &knock::Cancel::new(),
                    &Silent,
                );
        assert_eq!(format!("{:?}", result.unwrap_err()), format!("{error:?}"));
    }
}

#[test]
fn archive_outage_after_a_new_checksum_does_not_fall_back_to_old_data() {
    use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
    struct MetadataOnly(Vec<u8>);
    impl ReleaseTransport for MetadataOnly {
        fn fetch(
            &self,
            url: &str,
            _: FetchLimits,
            _: &knock::Cancel,
            _: &dyn bringup::BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            if url.ends_with("SHA256SUMS") {
                Ok(self.0.clone())
            } else {
                Err(FetchError::TemporarilyUnavailable("offline".into()))
            }
        }
    }
    let root = cache_test_dir().unwrap();
    load(root.path(), Fake::new(archive())).unwrap();
    let updated = gzip(&tar(&[(&format!("{STEM}/qshd"), b'0', b"updated image")]));
    let result =
        GitHubImages::with_transport(root.path().into(), Arc::new(MetadataOnly(sums(&updated))))
            .load(
                &request(),
                &InstallTiming::default(),
                &knock::Cancel::new(),
                &Silent,
            );
    assert!(matches!(result, Err(ImageError::Download(_))));
}

#[test]
fn metadata_phase_precedes_fetch_and_only_archive_bytes_reach_download_progress() {
    use bringup::{BringUpObserver, BringUpProgress, BringUpStage};
    use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
    use std::sync::Mutex;
    #[derive(Default)]
    struct Recorder(Mutex<Vec<BringUpProgress>>);
    impl BringUpObserver for Recorder {
        fn on_progress(&self, event: BringUpProgress) {
            self.0.lock().unwrap().push(event);
        }
    }
    struct Transfer {
        inner: Arc<Fake>,
        observed: Arc<Recorder>,
    }
    impl ReleaseTransport for Transfer {
        fn fetch(
            &self,
            url: &str,
            limits: FetchLimits,
            cancel: &knock::Cancel,
            observer: &dyn BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            assert_eq!(
                self.observed
                    .0
                    .lock()
                    .unwrap()
                    .first()
                    .map(|event| event.stage),
                Some(BringUpStage::CheckingMetadata),
                "metadata phase must be visible before fetch blocks"
            );
            let metadata = url.ends_with("SHA256SUMS");
            assert_eq!(
                limits.total,
                if metadata {
                    InstallTiming::default().metadata
                } else {
                    InstallTiming::default().download
                }
            );
            // Distinguish checksum bytes from actual archive transfer bytes.
            let completed = if metadata { 99 } else { 123 };
            observer.on_progress(BringUpProgress {
                stage: BringUpStage::Downloading,
                completed,
                total: Some(completed),
                finished: true,
            });
            self.inner.fetch(url, limits, cancel, observer)
        }
    }
    for cached in [false, true] {
        let root = cache_test_dir().unwrap();
        if cached {
            load(root.path(), Fake::new(archive())).unwrap();
        }
        let observed = Arc::new(Recorder::default());
        let inner = Fake::new(archive());
        let source = GitHubImages::with_transport(
            root.path().into(),
            Arc::new(Transfer {
                inner: inner.clone(),
                observed: observed.clone(),
            }),
        );
        assert_eq!(
            &*source
                .load(
                    &request(),
                    &InstallTiming::default(),
                    &knock::Cancel::new(),
                    observed.as_ref()
                )
                .unwrap()
                .bytes,
            IMAGE
        );
        assert_eq!(inner.calls(), if cached { 1 } else { 2 });
        let events = observed.0.lock().unwrap();
        assert_eq!(events.len(), if cached { 2 } else { 3 });
        assert_eq!(events[0].stage, BringUpStage::CheckingMetadata);
        assert!(!events[0].finished);
        assert_eq!(events[1].stage, BringUpStage::CheckingMetadata);
        assert!(events[1].finished);
        if !cached {
            assert_eq!(events[2].stage, BringUpStage::Downloading);
            assert_eq!(events[2].completed, 123);
            assert!(events[2].finished);
        }
    }
}

#[test]
fn cache_authority_rejects_writable_cache_but_keeps_verified_online_install() {
    use std::os::unix::fs::PermissionsExt;
    let root = cache_test_dir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let pointer = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/current.json");
    let before = fs::read(&pointer).unwrap();
    let lock = pointer.parent().unwrap().join(".lock");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        matches!(
            load(root.path(), Fake::offline()),
            Err(ImageError::Download(_))
        ),
        "a publicly readable lock is not cache authority"
    );
    assert_eq!(
        fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o644
    );
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        matches!(
            load(root.path(), Fake::offline()),
            Err(ImageError::Download(_))
        ),
        "writable cache is not offline evidence"
    );
    let online = Fake::new(bytes);
    assert_eq!(&*load(root.path(), online.clone()).unwrap().bytes, IMAGE);
    assert_eq!(
        online.calls(),
        2,
        "refused cache requires a fresh verified archive"
    );
    assert_eq!(fs::read(&pointer).unwrap(), before);
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o777
    );
}

#[test]
fn cache_authority_preserves_safe_public_modes_and_root_aliases() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    let owner = cache_test_dir().unwrap();
    fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = owner.path().join("cache");
    let bytes = archive();
    load(&root, Fake::new(bytes.clone())).unwrap();
    fn public_modes(path: &std::path::Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                public_modes(&entry.path());
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o755)).unwrap();
            } else if entry.file_name() != ".lock" {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
    }
    public_modes(&root);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let archive_path = object(&root, &bytes).join("archive");
    let hardlink = owner.path().join("archive-hardlink");
    fs::hard_link(&archive_path, &hardlink).unwrap();
    assert!(fs::metadata(&archive_path).unwrap().nlink() > 1);
    let alias = owner.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert_eq!(&*load(&alias, Fake::offline()).unwrap().bytes, IMAGE);
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&archive_path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let objects = root.join("releases/0.4.0/x86_64-unknown-linux-musl/objects");
    let moved = owner.path().join("objects");
    fs::rename(&objects, &moved).unwrap();
    symlink(&moved, &objects).unwrap();
    assert!(matches!(
        load(&alias, Fake::offline()),
        Err(ImageError::Download(_))
    ));
    assert_eq!(fs::read(&hardlink).unwrap(), bytes);
}
