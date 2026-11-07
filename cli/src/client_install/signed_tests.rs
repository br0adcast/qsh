//! Optional offline acceptance against externally supplied, production-signed assets.
//! No release artifacts or alternate trust roots are embedded in the test binary.
use super::*;
use crate::releases::{FetchError, FetchLimits, GitHubImages, ReleaseTransport};
use bringup::{BringUpObserver, ImageError, ImageRequest, InstallTiming};
use knock::Cancel;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Assets {
    directory: PathBuf,
    archive: String,
    requests: AtomicUsize,
}
impl ReleaseTransport for Assets {
    fn fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        _: &Cancel,
        _: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, FetchError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let name = url.rsplit('/').next().unwrap();
        let file = match name {
            "SHA256SUMS" | "SHA256SUMS.sigstore.json" => name,
            _ if name == self.archive => &self.archive,
            _ => return Err(ImageError::Unavailable("fixture asset unavailable".into()).into()),
        };
        let bytes = std::fs::read(self.directory.join(file)).unwrap();
        assert!(bytes.len() <= limits.max_bytes);
        Ok(bytes)
    }
}

#[test]
#[ignore = "requires QSH_TEST_SIGNED_RELEASE_DIR and QSH_TEST_SIGNED_RELEASE_VERSION"]
fn production_signed_install_and_explicit_update_policy() {
    let directory = PathBuf::from(
        std::env::var_os("QSH_TEST_SIGNED_RELEASE_DIR").expect("signed fixture directory"),
    );
    let version = std::env::var("QSH_TEST_SIGNED_RELEASE_VERSION").expect("signed fixture version");
    let platform = native_platform().unwrap();
    let assets = Arc::new(Assets {
        directory,
        archive: format!("qsh-{version}-{}.tar.gz", platform.target()),
        requests: AtomicUsize::new(0),
    });
    let images = GitHubImages::uncached(assets.clone());
    let image = images
        .load_client(
            &ImageRequest::new(platform, &version).unwrap(),
            &InstallTiming::default(),
            &Cancel::new(),
            &Quiet,
        )
        .unwrap();
    let identity = BuildIdentity {
        official: true,
        version: &version,
        source: image.manifest().source_commit(),
    };
    let home = tempfile::tempdir().unwrap();
    let bootstrap = home.path().join("bootstrap-qsh");
    std::fs::write(&bootstrap, image.bytes()).unwrap();
    let mut command = Command {
        update: false,
        version: Some(version.clone()),
        prefix: None,
        help: false,
    };
    execute(&command, identity, home.path(), &bootstrap, None, &images).unwrap();
    let active = home.path().join(".local/bin/qsh");
    assert_eq!(std::fs::read(&active).unwrap(), image.bytes());
    let executable = std::fs::canonicalize(&active).unwrap();
    let installation = store::validate_running(
        home.path(),
        &executable,
        &version,
        platform.target(),
        identity.source,
    )
    .unwrap();
    assert_eq!(installation.version, version);
    // A matching raw link is insufficient if its bin directory was redirected.
    let bin = home.path().join(".local/bin");
    let moved_bin = home.path().join("redirected-bin");
    std::fs::rename(&bin, &moved_bin).unwrap();
    std::os::unix::fs::symlink(&moved_bin, &bin).unwrap();
    assert!(store::validate_running(
        home.path(),
        &executable,
        &version,
        platform.target(),
        identity.source
    )
    .is_err());
    std::fs::remove_file(&bin).unwrap();
    std::fs::rename(moved_bin, &bin).unwrap();
    let before = std::fs::read_link(&active).unwrap();
    let fetched = assets.requests.load(Ordering::Relaxed);
    command.update = true;
    let wrong_build = BuildIdentity {
        official: true,
        version: &version,
        source: "unrelated build",
    };
    assert!(execute(
        &command,
        wrong_build,
        home.path(),
        &executable,
        None,
        &images
    )
    .is_err());
    assert_eq!(assets.requests.load(Ordering::Relaxed), fetched);
    let unchanged = execute(&command, identity, home.path(), &executable, None, &images).unwrap();
    assert!(unchanged.contains("already"));
    assert_eq!(assets.requests.load(Ordering::Relaxed), fetched);
    command.version = Some("0.0.1".into());
    let error = execute(&command, identity, home.path(), &executable, None, &images).unwrap_err();
    assert!(error.contains("downgrade"));
    assert_eq!(assets.requests.load(Ordering::Relaxed), fetched);
    // A newer requested version cannot reuse this release's signed evidence.
    command.version = Some("999.0.0".into());
    assert!(execute(&command, identity, home.path(), &executable, None, &images).is_err());
    assert!(assets.requests.load(Ordering::Relaxed) > fetched);
    assert_eq!(std::fs::read_link(&active).unwrap(), before);
    assert_eq!(std::fs::read(&active).unwrap(), image.bytes());
    let fetched = assets.requests.load(Ordering::Relaxed);
    let receipt = executable.parent().unwrap().join("receipt.json");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&receipt, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&receipt, b"invalid receipt").unwrap();
    assert!(execute(&command, identity, home.path(), &executable, None, &images).is_err());
    assert_eq!(assets.requests.load(Ordering::Relaxed), fetched);
    assert_eq!(std::fs::read_link(&active).unwrap(), before);
}
