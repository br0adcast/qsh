#[path = "support/releases.rs"]
mod support;
use bringup::{ImageError, ImageSource, InstallTiming};
use qsh::releases::{release_urls, GitHubImages};
use std::{
    fs,
    sync::{atomic::AtomicUsize, Arc},
};
use support::*;
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
fn selected_release_cache_loads_complete_generation_without_http() {
    let home = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
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
        assert_eq!(offline.calls(), 0);
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    assert_eq!(offline.calls(), 0);
}
#[test]
fn corrupt_archive_is_redownloaded_and_generation_repaired() {
    let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(root.path(), fake),
            Err(ImageError::Download(_))
        ));
    }
}
#[test]
fn cancellation_prevents_cache_or_network_work() {
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
    let bytes = archive();
    load(root.path(), Fake::new(bytes.clone())).unwrap();
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let outside = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
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
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let offline = Fake::offline();
    assert_eq!(&*load(root.path(), offline.clone()).unwrap().bytes, IMAGE);
    assert_eq!(offline.calls(), 0);
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
    let root = tempfile::tempdir().unwrap();
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
        let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    use qsh::releases::{FetchLimits, ReleaseTransport};
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
        ) -> Result<Vec<u8>, ImageError> {
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
    let root = tempfile::tempdir().unwrap();
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
