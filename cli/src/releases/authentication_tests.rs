// Signed evidence orchestration controls. Real cryptography is tested by release-auth.
use super::{test_support::*, *};
use std::sync::Mutex;

#[derive(Default)]
struct Events(Mutex<Vec<bringup::BringUpProgress>>);
impl BringUpObserver for Events {
    fn on_progress(&self, event: bringup::BringUpProgress) {
        self.0.lock().unwrap().push(event);
    }
}
struct Script {
    manifest: Result<Vec<u8>, FetchError>,
    bundle: Result<Vec<u8>, FetchError>,
    archive: Result<Vec<u8>, FetchError>,
    calls: Mutex<Vec<(String, FetchLimits)>>,
    manifest_delay: Duration,
}
impl Script {
    fn good() -> Self {
        let bytes = archive();
        let manifest = sums(&bytes);
        Self {
            bundle: Ok(fixture_bundle("0.4.0", &manifest)),
            manifest: Ok(manifest),
            archive: Ok(bytes),
            calls: Mutex::new(vec![]),
            manifest_delay: Duration::ZERO,
        }
    }
    fn archives(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(url, _)| url.ends_with(".tar.gz"))
            .count()
    }
}
impl ReleaseTransport for Script {
    fn fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        _: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, FetchError> {
        self.calls.lock().unwrap().push((url.to_owned(), limits));
        // Metadata progress from either response must remain suppressed.
        observer.on_progress(bringup::BringUpProgress {
            stage: bringup::BringUpStage::Downloading,
            completed: 99,
            total: Some(99),
            finished: true,
        });
        if url.ends_with("SHA256SUMS") {
            std::thread::sleep(self.manifest_delay);
            self.manifest.clone()
        } else if url.ends_with("SHA256SUMS.sigstore.json") {
            self.bundle.clone()
        } else {
            self.archive.clone()
        }
    }
}
fn load(
    root: &std::path::Path,
    script: Arc<Script>,
    events: &Events,
) -> Result<DaemonImage, ImageError> {
    GitHubImages::fixture(root.into(), script).load(
        &request(),
        &InstallTiming::default(),
        &Cancel::new(),
        events,
    )
}
fn prime(root: &std::path::Path) {
    load(root, Arc::new(Script::good()), &Events::default()).unwrap();
}
fn generation(root: &std::path::Path) -> PathBuf {
    root.join("releases/0.4.0/x86_64-unknown-linux-musl/objects")
        .join(digest(&archive()))
}
fn no_finished_metadata(events: &Events) {
    assert!(!events
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.stage == bringup::BringUpStage::CheckingMetadata && e.finished));
}

#[test]
fn exact_network_outage_table_with_a_good_authenticated_cache() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    for partial in [false, true] {
        for bundle_phase in [false, true] {
            for matching in [false, true] {
                let mut script = Script::good();
                if !matching {
                    // A complete, valid but different canonical manifest.
                    script.manifest = Ok(fixture_manifest(&request(), &[42; 32]));
                }
                let error = if partial {
                    FetchError::InterruptedResponse("bounded outage".into())
                } else {
                    FetchError::TemporarilyUnavailable("bounded outage".into())
                };
                if bundle_phase {
                    script.bundle = Err(error);
                } else {
                    script.manifest = Err(error);
                }
                let script = Arc::new(script);
                let events = Events::default();
                let result = load(root.path(), script.clone(), &events);
                let permitted = if bundle_phase { matching } else { !partial };
                assert_eq!(
                    result.is_ok(),
                    permitted,
                    "partial={partial} bundle={bundle_phase} matching={matching}"
                );
                assert_eq!(script.archives(), 0);
                assert_eq!(
                    script.calls.lock().unwrap().len(),
                    if bundle_phase { 2 } else { 1 }
                );
                if permitted {
                    assert_eq!(&*result.unwrap().bytes, IMAGE);
                } else {
                    no_finished_metadata(&events);
                }
            }
        }
    }
}

#[test]
fn bundle_outage_requires_original_manifest_bytes_even_with_the_same_archive_hash() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    let original = sums(&archive());
    let target = format!("  {STEM}.tar.gz");
    let mut changed = String::from_utf8(original.clone()).unwrap();
    let index = changed
        .lines()
        .scan(0, |offset, line| {
            let index = *offset;
            *offset += line.len() + 1;
            Some((index, line.ends_with(&target)))
        })
        .find(|(_, is_target)| !is_target)
        .unwrap()
        .0;
    changed.replace_range(index..index + 1, "1");
    let target_line = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
            .unwrap()
            .lines()
            .find(|line| line.ends_with(&target))
            .unwrap()
            .to_owned()
    };
    assert_eq!(target_line(&original), target_line(changed.as_bytes()));
    assert_ne!(original, changed.as_bytes());
    for error in [
        FetchError::TemporarilyUnavailable("outage".into()),
        FetchError::InterruptedResponse("partial bundle".into()),
    ] {
        let mut script = Script::good();
        script.manifest = Ok(changed.as_bytes().to_vec());
        script.bundle = Err(error);
        let script = Arc::new(script);
        let events = Events::default();
        assert!(load(root.path(), script.clone(), &events).is_err());
        assert_eq!(script.archives(), 0);
        no_finished_metadata(&events);
    }
}

#[test]
fn hard_metadata_failures_never_hide_behind_a_good_cache() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    let pointer = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/current.json");
    let before = std::fs::read(&pointer).unwrap();
    for bundle_phase in [false, true] {
        for response in [
            Err(FetchError::Rejected(ImageError::Unavailable(
                "HTTP 404".into(),
            ))),
            Err(FetchError::Rejected(ImageError::Download(
                "TLS rejected".into(),
            ))),
            Err(FetchError::Rejected(ImageError::Download(
                "over limit".into(),
            ))),
            Ok(b"malformed evidence".to_vec()),
            Ok(vec![]),
            Ok(vec![
                0;
                if bundle_phase {
                    BUNDLE_LIMIT + 1
                } else {
                    SUMS_LIMIT + 1
                }
            ]),
        ] {
            let mut script = Script::good();
            if bundle_phase {
                script.bundle = response;
            } else {
                script.manifest = response;
            }
            let script = Arc::new(script);
            let events = Events::default();
            assert!(load(root.path(), script.clone(), &events).is_err());
            no_finished_metadata(&events);
            assert_eq!(script.archives(), 0);
            assert_eq!(std::fs::read(&pointer).unwrap(), before);
        }
    }
}

#[test]
fn metadata_requests_consume_one_absolute_end() {
    let root = tempfile::tempdir().unwrap();
    let mut script = Script::good();
    script.manifest_delay = Duration::from_millis(30);
    let script = Arc::new(script);
    let timing = InstallTiming {
        metadata: Duration::from_secs(1),
        ..InstallTiming::default()
    };
    let events = Events::default();
    GitHubImages::fixture(root.path().into(), script.clone())
        .load(&request(), &timing, &Cancel::new(), &events)
        .unwrap();
    let calls = script.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls[0].1.total <= timing.metadata);
    assert!(calls[1].1.total + Duration::from_millis(25) < calls[0].1.total);
    assert_eq!(calls[0].1.max_bytes, SUMS_LIMIT);
    assert_eq!(calls[1].1.max_bytes, BUNDLE_LIMIT);
    let events = events.0.lock().unwrap();
    assert_eq!(events.len(), 3);
    assert!(!events[0].finished);
    assert!(events[1].finished);
    assert_eq!(events[1].stage, bringup::BringUpStage::CheckingMetadata);
    assert_eq!(events[2].completed, 99);
}

#[test]
fn archive_outages_and_wrong_hashes_cannot_use_a_different_generation() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    for response in [
        Err(FetchError::TemporarilyUnavailable("outage".into())),
        Err(FetchError::InterruptedResponse("partial".into())),
        Ok(archive()),
    ] {
        let mut script = Script::good();
        let manifest = fixture_manifest(&request(), &[42; 32]);
        script.manifest = Ok(manifest.clone());
        script.bundle = Ok(fixture_bundle("0.4.0", &manifest));
        script.archive = response;
        let script = Arc::new(script);
        assert!(load(root.path(), script.clone(), &Events::default()).is_err());
        assert_eq!(script.archives(), 1);
    }
}

#[test]
fn offline_load_reverifies_both_original_evidence_files_each_time() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn verify(r: &ImageRequest, m: &[u8], b: &[u8]) -> Result<Evidence, ImageError> {
        CALLS.fetch_add(1, Ordering::SeqCst);
        super::test_support::verify(r, m, b)
    }
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    let mut source = GitHubImages::fixture(root.path().into(), Fake::offline());
    source.authentication = Authentication::Test(verify);
    for n in 1..=2 {
        source
            .load(
                &request(),
                &InstallTiming::default(),
                &Cancel::new(),
                &Silent,
            )
            .unwrap();
        assert_eq!(CALLS.load(Ordering::SeqCst), n);
    }
    std::fs::write(
        generation(root.path()).join("SHA256SUMS.sigstore.json"),
        b"invalid",
    )
    .unwrap();
    assert!(source
        .load(
            &request(),
            &InstallTiming::default(),
            &Cancel::new(),
            &Silent
        )
        .is_err());
    assert_eq!(CALLS.load(Ordering::SeqCst), 3);
}

#[test]
fn absent_altered_mixed_or_unsafe_evidence_is_never_an_offline_image() {
    use std::os::unix::fs::symlink;
    for file in ["SHA256SUMS", "SHA256SUMS.sigstore.json"] {
        for mutation in 0..6 {
            let root = tempfile::tempdir().unwrap();
            prime(root.path());
            let path = generation(root.path()).join(file);
            let original = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            match mutation {
                0 => {}
                1 => std::fs::write(&path, b"altered evidence").unwrap(),
                2 => {
                    let mut other = request();
                    other.version = "0.4.1".into();
                    let evidence = evidence(&other, &[42; 32]);
                    std::fs::write(
                        &path,
                        if file == "SHA256SUMS" {
                            evidence.manifest_bytes()
                        } else {
                            evidence.bundle_bytes()
                        },
                    )
                    .unwrap();
                }
                3 => {
                    let outside = root.path().join("outside");
                    std::fs::write(&outside, &original).unwrap();
                    symlink(&outside, &path).unwrap();
                }
                4 => std::fs::create_dir(&path).unwrap(),
                5 => nix::unistd::mkfifo(
                    &path,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )
                .unwrap(),
                _ => unreachable!(),
            }
            assert!(
                GitHubImages::fixture(root.path().into(), Fake::offline())
                    .load(
                        &request(),
                        &InstallTiming::default(),
                        &Cancel::new(),
                        &Silent
                    )
                    .is_err(),
                "{file} mutation {mutation}"
            );
        }
    }
}

#[test]
fn fresh_authenticated_metadata_can_upgrade_a_matching_unsigned_archive() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    for file in ["SHA256SUMS", "SHA256SUMS.sigstore.json", "receipt.json"] {
        std::fs::remove_file(generation(root.path()).join(file)).unwrap();
    }
    assert!(GitHubImages::fixture(root.path().into(), Fake::offline())
        .load(
            &request(),
            &InstallTiming::default(),
            &Cancel::new(),
            &Silent
        )
        .is_err());
    let script = Arc::new(Script::good());
    assert_eq!(
        &*load(root.path(), script.clone(), &Events::default())
            .unwrap()
            .bytes,
        IMAGE
    );
    assert_eq!(
        script.archives(),
        0,
        "actual stored archive is rehashed against authenticated metadata"
    );
    assert_eq!(script.calls.lock().unwrap().len(), 2);
    assert_eq!(
        &*GitHubImages::fixture(root.path().into(), Fake::offline())
            .load(
                &request(),
                &InstallTiming::default(),
                &Cancel::new(),
                &Silent
            )
            .unwrap()
            .bytes,
        IMAGE
    );
}

#[test]
fn partial_evidence_repair_cannot_make_an_offline_generation_acceptable() {
    let root = tempfile::tempdir().unwrap();
    prime(root.path());
    let bundle = generation(root.path()).join("SHA256SUMS.sigstore.json");
    std::fs::remove_file(&bundle).unwrap();
    std::fs::create_dir(&bundle).unwrap();
    let pointer = root
        .path()
        .join("releases/0.4.0/x86_64-unknown-linux-musl/current.json");
    let before = std::fs::read(&pointer).unwrap();
    // A fresh authenticated download may still return an image if optional
    // storage cannot replace a directory; incomplete local evidence stays bad.
    load(root.path(), Arc::new(Script::good()), &Events::default()).unwrap();
    assert_eq!(std::fs::read(&pointer).unwrap(), before);
    assert!(GitHubImages::fixture(root.path().into(), Fake::offline())
        .load(
            &request(),
            &InstallTiming::default(),
            &Cancel::new(),
            &Silent
        )
        .is_err());
}

#[test]
fn cancellation_and_expiry_immediately_after_bounded_verification_win() {
    thread_local! { static CANCEL: std::cell::RefCell<Option<Cancel>> = const { std::cell::RefCell::new(None) }; }
    fn cancelling(r: &ImageRequest, m: &[u8], b: &[u8]) -> Result<Evidence, ImageError> {
        let result = super::test_support::verify(r, m, b);
        CANCEL.with(|cancel| cancel.borrow().as_ref().unwrap().cancel());
        result
    }
    fn expired(r: &ImageRequest, m: &[u8], b: &[u8]) -> Result<Evidence, ImageError> {
        let result = super::test_support::verify(r, m, b);
        std::thread::sleep(Duration::from_millis(10));
        result
    }
    for cancel_after in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let script = Arc::new(Script::good());
        let cancel = Cancel::new();
        CANCEL.with(|slot| *slot.borrow_mut() = Some(cancel.clone()));
        let mut source = GitHubImages::fixture(root.path().into(), script.clone());
        source.authentication =
            Authentication::Test(if cancel_after { cancelling } else { expired });
        let timing = InstallTiming {
            verify: if cancel_after {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(1)
            },
            ..InstallTiming::default()
        };
        let events = Events::default();
        let result = source.load(&request(), &timing, &cancel, &events);
        CANCEL.with(|slot| slot.borrow_mut().take());
        if cancel_after {
            assert!(matches!(result, Err(ImageError::Cancelled)));
        } else {
            assert!(matches!(result, Err(ImageError::Invalid(_))));
        }
        assert_eq!(script.archives(), 0);
        no_finished_metadata(&events);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_before_verification_never_enters_the_verifier() {
    struct Cancelling(Arc<Script>);
    impl ReleaseTransport for Cancelling {
        fn fetch(
            &self,
            url: &str,
            limits: FetchLimits,
            cancel: &Cancel,
            observer: &dyn BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            let result = self.0.fetch(url, limits, cancel, observer);
            if url.ends_with(".sigstore.json") {
                cancel.cancel();
            }
            result
        }
    }
    fn unreachable_verifier(_: &ImageRequest, _: &[u8], _: &[u8]) -> Result<Evidence, ImageError> {
        panic!("verification after cancellation");
    }
    let root = tempfile::tempdir().unwrap();
    let script = Arc::new(Script::good());
    let mut source =
        GitHubImages::fixture(root.path().into(), Arc::new(Cancelling(script.clone())));
    source.authentication = Authentication::Test(unreachable_verifier);
    let events = Events::default();
    assert!(matches!(
        source.load(
            &request(),
            &InstallTiming::default(),
            &Cancel::new(),
            &events
        ),
        Err(ImageError::Cancelled)
    ));
    assert_eq!(script.archives(), 0);
    no_finished_metadata(&events);
}
