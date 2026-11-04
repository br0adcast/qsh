#[allow(dead_code)]
#[path = "support/releases.rs"]
mod support;
use bringup::{ImageError, ImageSource, InstallTiming};
use qsh::releases::{FetchError, FetchLimits, GitHubImages, ReleaseTransport};
use std::sync::{Arc, Mutex};
use support::*;

struct Unsigned(Mutex<Vec<String>>);
impl ReleaseTransport for Unsigned {
    fn fetch(
        &self,
        url: &str,
        _: FetchLimits,
        _: &knock::Cancel,
        _: &dyn bringup::BringUpObserver,
    ) -> Result<Vec<u8>, FetchError> {
        self.0.lock().unwrap().push(url.to_owned());
        Ok(if url.ends_with("SHA256SUMS") {
            sums(&archive())
        } else if url.ends_with(".sigstore.json") {
            b"{}".to_vec()
        } else {
            archive()
        })
    }
}
#[test]
fn unsigned_metadata_is_refused_before_any_archive_fetch() {
    let transport = Arc::new(Unsigned(Mutex::new(vec![])));
    let result = GitHubImages::uncached(transport.clone()).load(
        &request(),
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(
        result.is_err(),
        "checksum-only metadata cannot authorize a download"
    );
    let calls = transport.0.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls[1].ends_with("SHA256SUMS.sigstore.json"));
    assert!(!calls.iter().any(|u| u.ends_with(".tar.gz")));
}
#[test]
fn unsigned_preexisting_cache_is_an_offline_miss() {
    let root = tempfile::tempdir().unwrap();
    let bytes = archive();
    let sha = digest(&bytes);
    let target = root.path().join("releases/0.4.0/x86_64-unknown-linux-musl");
    let object = target.join("objects").join(&sha);
    std::fs::create_dir_all(&object).unwrap();
    std::fs::write(object.join("archive"), &bytes).unwrap();
    std::fs::write(object.join("image"), IMAGE).unwrap();
    std::fs::write(object.join("receipt.json"), serde_json::to_vec(&serde_json::json!({"version":"0.4.0","target":"x86_64-unknown-linux-musl","archive_sha256":sha,"image_sha256":digest(IMAGE),"image_size":IMAGE.len()})).unwrap()).unwrap();
    std::fs::write(
        target.join("current.json"),
        serde_json::to_vec(&serde_json::json!({"archive_sha256":sha})).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        GitHubImages::with_transport(root.path().into(), Fake::offline()).load(
            &request(),
            &InstallTiming::default(),
            &knock::Cancel::new(),
            &Silent
        ),
        Err(ImageError::Download(_))
    ));
}

#[test]
fn a_public_upstream_signature_cannot_authorize_qsh_metadata() {
    struct Upstream;
    impl ReleaseTransport for Upstream {
        fn fetch(
            &self,
            url: &str,
            _: FetchLimits,
            _: &knock::Cancel,
            _: &dyn bringup::BringUpObserver,
        ) -> Result<Vec<u8>, FetchError> {
            if url.ends_with("SHA256SUMS") {
                Ok(sums(&archive()))
            } else {
                assert!(url.ends_with("SHA256SUMS.sigstore.json"));
                Ok(include_bytes!(
                    "../../crates/release-auth/tests/data/conda-attestation.sigstore.json"
                )
                .to_vec())
            }
        }
    }
    let result = GitHubImages::uncached(Arc::new(Upstream)).load(
        &request(),
        &InstallTiming::default(),
        &knock::Cancel::new(),
        &Silent,
    );
    assert!(
        matches!(result, Err(ImageError::Invalid(reason)) if reason.contains("authentication"))
    );
}
