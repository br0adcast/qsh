//! Verified console release loading, separate from the daemon cache.

use super::{
    archive, Budget, FetchLimits, GitHubImages, MetadataTransfer, ARCHIVE_LIMIT, BUNDLE_LIMIT,
    SUMS_LIMIT,
};
use bringup::{BringUpObserver, ImageError, ImageRequest, InstallTiming, Platform};
use knock::Cancel;

const LATEST_URL: &str = "https://api.github.com/repos/br0adcast/qsh/releases/latest";
const LATEST_LIMIT: usize = 1024 * 1024;

/// Client bytes whose archive and release authority have both been verified.
/// Only this loader can construct the value; receipts alone are never authority.
#[derive(Debug)]
pub struct ClientImage {
    request: ImageRequest,
    bytes: Vec<u8>,
    sha256: [u8; 32],
    archive_sha256: [u8; 32],
    manifest: release_auth::VerifiedManifest,
}
impl ClientImage {
    pub fn request(&self) -> &ImageRequest {
        &self.request
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn archive_sha256(&self) -> &[u8; 32] {
        &self.archive_sha256
    }
    pub fn manifest(&self) -> &release_auth::VerifiedManifest {
        &self.manifest
    }
}

#[derive(serde::Deserialize)]
struct LatestRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

fn valid_version(version: &str) -> Result<(), ImageError> {
    if version.len() > 128 {
        return Err(ImageError::Invalid("invalid client release version".into()));
    }
    ImageRequest::new(
        Platform::from_uname("Linux", "x86_64").expect("supported platform"),
        version,
    )
    .map(|_| ())
    .map_err(|_| ImageError::Invalid("invalid client release version".into()))
}

impl GitHubImages {
    /// Resolve discovery metadata only. Release signatures establish authority
    /// later; neither the API nor a signature proves that a version is newest.
    pub fn select_client_version(
        &self,
        explicit: Option<&str>,
        timing: &InstallTiming,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<String, ImageError> {
        let budget = Budget::new(timing.metadata, cancel);
        budget.check()?;
        if let Some(version) = explicit {
            valid_version(version)?;
            budget.check()?;
            return Ok(version.to_owned());
        }
        let response = self.transport.fetch(
            LATEST_URL,
            FetchLimits {
                total: budget.remaining()?,
                idle: timing.download_idle.min(timing.metadata),
                max_bytes: LATEST_LIMIT,
            },
            cancel,
            observer,
        );
        budget.check()?;
        let bytes = response?;
        if bytes.len() > LATEST_LIMIT {
            return Err(ImageError::Invalid(
                "latest release metadata exceeds size limit".into(),
            ));
        }
        let latest: LatestRelease = serde_json::from_slice(&bytes)
            .map_err(|_| ImageError::Invalid("invalid latest release metadata".into()))?;
        let version = latest
            .tag_name
            .strip_prefix('v')
            .ok_or_else(|| ImageError::Invalid("latest release tag must start with v".into()))?;
        valid_version(version)?;
        if latest.draft || latest.prerelease || version.contains('-') {
            return Err(ImageError::Invalid(
                "latest release is not stable; select an explicit version".into(),
            ));
        }
        budget.check()?;
        Ok(version.to_owned())
    }

    /// Load a console image using the compiled release policy. This never
    /// touches the daemon cache and never obtains executable URLs from a peer.
    pub fn load_client(
        &self,
        request: &ImageRequest,
        timing: &InstallTiming,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<ClientImage, ImageError> {
        let metadata = Budget::new(timing.metadata, cancel);
        metadata.check()?;
        valid_version(&request.version)?;
        let (manifest_url, archive_url) = super::release_urls(request)?;
        let fetch = |url: &str, limit| -> Result<Vec<u8>, ImageError> {
            let remaining = metadata.remaining()?;
            let response = self.transport.fetch(
                url,
                FetchLimits {
                    total: remaining,
                    idle: remaining.min(timing.download_idle),
                    max_bytes: limit,
                },
                cancel,
                &MetadataTransfer,
            );
            metadata.check()?;
            let bytes = response?;
            if bytes.len() > limit {
                return Err(ImageError::Invalid(
                    "client release metadata exceeds size limit".into(),
                ));
            }
            Ok(bytes)
        };
        let manifest_bytes = fetch(&manifest_url, SUMS_LIMIT)?;
        let bundle_bytes = fetch(&format!("{manifest_url}.sigstore.json"), BUNDLE_LIMIT)?;
        let verification = Budget::new(timing.verify, cancel);
        verification.check()?;
        let result =
            release_auth::verify_manifest(&request.version, &manifest_bytes, &bundle_bytes);
        verification.check()?;
        let manifest = result
            .map_err(|error| ImageError::Invalid(format!("release authentication: {error}")))?;
        let archive_sha256 = *manifest
            .asset_hash(&format!("{}.tar.gz", super::stem(request)))
            .ok_or_else(|| {
                ImageError::Invalid("release authentication: missing client target".into())
            })?;
        let download = Budget::new(timing.download, cancel);
        download.check()?;
        let response = self.transport.fetch(
            &archive_url,
            FetchLimits {
                total: download.remaining()?,
                idle: timing.download_idle.min(timing.download),
                max_bytes: ARCHIVE_LIMIT,
            },
            cancel,
            observer,
        );
        download.check()?;
        let archive = response?;
        if archive.len() > ARCHIVE_LIMIT {
            return Err(ImageError::Invalid("client archive exceeds 64 MiB".into()));
        }
        let verification = Budget::new(timing.verify, cancel);
        let bytes = client_bytes(request, &archive, &archive_sha256, &verification)?;
        let sha256 = archive::hash(&bytes, &verification)?;
        verification.check()?;
        Ok(ClientImage {
            request: request.clone(),
            bytes,
            sha256,
            archive_sha256,
            manifest,
        })
    }
}

fn client_bytes(
    request: &ImageRequest,
    bytes: &[u8],
    expected: &[u8; 32],
    budget: &Budget<'_>,
) -> Result<Vec<u8>, ImageError> {
    if &archive::hash(bytes, budget)? != expected {
        return Err(ImageError::Checksum);
    }
    let result = archive::extract_member(request, bytes, budget, "qsh");
    budget.check()?;
    let bytes = result?;
    if bytes.is_empty() {
        return Err(ImageError::Archive("empty client image".into()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::releases::test_support::{gzip, tar, Silent};
    use bringup::Platform;
    use std::sync::Arc;

    fn request(os: &str, arch: &str) -> ImageRequest {
        ImageRequest::new(Platform::from_uname(os, arch).unwrap(), "0.6.0").unwrap()
    }
    #[test]
    fn exact_client_member_on_every_target() {
        for (os, arch) in [
            ("Linux", "x86_64"),
            ("Linux", "aarch64"),
            ("Darwin", "x86_64"),
            ("Darwin", "arm64"),
        ] {
            let request = request(os, arch);
            let root = super::super::stem(&request);
            let bytes = gzip(&tar(&[
                (&format!("{root}/qsh"), b'0', b"client"),
                (&format!("{root}/qshd"), b'0', b"daemon"),
            ]));
            let cancel = Cancel::new();
            let budget = Budget::new(std::time::Duration::from_secs(10), &cancel);
            let hash = archive::hash(&bytes, &budget).unwrap();
            assert_eq!(
                client_bytes(&request, &bytes, &hash, &budget).unwrap(),
                b"client"
            );
        }
    }
    #[test]
    fn rejects_wrong_hash_and_unsafe_or_missing_members() {
        let request = request("Linux", "x86_64");
        let root = super::super::stem(&request);
        let client = format!("{root}/qsh");
        for entries in [
            vec![
                (client.as_str(), b'0', b"client".as_slice()),
                (client.as_str(), b'0', b"twice".as_slice()),
            ],
            vec![(client.as_str(), b'2', b"".as_slice())],
            vec![("../qsh", b'0', b"bad".as_slice())],
            vec![(
                "qsh-0.6.0-x86_64-unknown-linux-musl/qshd",
                b'0',
                b"daemon".as_slice(),
            )],
            vec![(client.as_str(), b'0', b"".as_slice())],
        ] {
            let bytes = gzip(&tar(&entries));
            let cancel = Cancel::new();
            let budget = Budget::new(std::time::Duration::from_secs(10), &cancel);
            let hash = archive::hash(&bytes, &budget).unwrap();
            assert!(client_bytes(&request, &bytes, &hash, &budget).is_err());
        }
        let bytes = gzip(&tar(&[(client.as_str(), b'0', b"client")]));
        let cancel = Cancel::new();
        let budget = Budget::new(std::time::Duration::from_secs(10), &cancel);
        assert!(client_bytes(&request, &bytes, &[0; 32], &budget).is_err());
    }
    struct Metadata(Vec<u8>);
    impl super::super::ReleaseTransport for Metadata {
        fn fetch(
            &self,
            url: &str,
            _: FetchLimits,
            _: &Cancel,
            _: &dyn BringUpObserver,
        ) -> Result<Vec<u8>, super::super::FetchError> {
            assert_eq!(url, LATEST_URL);
            Ok(self.0.clone())
        }
    }
    #[test]
    fn latest_requires_exact_stable_release_metadata() {
        for body in [
            r#"{"tag_name":"v0.6.0-rc.1","draft":false,"prerelease":false}"#,
            r#"{"tag_name":"v0.6.0","draft":true,"prerelease":false}"#,
            r#"{"tag_name":"v0.6.0","draft":false,"prerelease":true}"#,
            r#"{"tag_name":"v0.6.0","draft":false}"#,
            r#"{"tag_name":"v../escape","draft":false,"prerelease":false}"#,
        ] {
            let images = GitHubImages::uncached(Arc::new(Metadata(body.as_bytes().to_vec())));
            assert!(images
                .select_client_version(None, &InstallTiming::default(), &Cancel::new(), &Silent)
                .is_err());
        }
        let images = GitHubImages::uncached(Arc::new(Metadata(
            br#"{"tag_name":"v0.6.0","draft":false,"prerelease":false}"#.to_vec(),
        )));
        assert_eq!(
            images
                .select_client_version(None, &InstallTiming::default(), &Cancel::new(), &Silent)
                .unwrap(),
            "0.6.0"
        );
        assert_eq!(
            images
                .select_client_version(
                    Some("0.6.0-rc.1"),
                    &InstallTiming::default(),
                    &Cancel::new(),
                    &Silent
                )
                .unwrap(),
            "0.6.0-rc.1"
        );
        assert!(images
            .select_client_version(
                Some("0.6.0+build"),
                &InstallTiming::default(),
                &Cancel::new(),
                &Silent
            )
            .is_err());
    }
    #[test]
    fn client_loader_rejects_unsigned_metadata() {
        let images = GitHubImages::uncached(super::super::test_support::Fake::new(
            super::super::test_support::archive(),
        ));
        assert!(images
            .load_client(
                &request("Linux", "x86_64"),
                &InstallTiming::default(),
                &Cancel::new(),
                &Silent
            )
            .is_err());
    }
    #[test]
    fn cancellation_and_metadata_limits_prevent_selection() {
        let images = GitHubImages::uncached(Arc::new(Metadata(vec![b' '; 1024 * 1024 + 1])));
        let cancel = Cancel::new();
        assert!(images
            .select_client_version(None, &InstallTiming::default(), &cancel, &Silent)
            .is_err());
        cancel.cancel();
        assert!(matches!(
            images.select_client_version(
                Some("0.6.0"),
                &InstallTiming::default(),
                &cancel,
                &Silent
            ),
            Err(ImageError::Cancelled)
        ));
        assert!(matches!(
            images.load_client(
                &request("Linux", "x86_64"),
                &InstallTiming::default(),
                &cancel,
                &Silent
            ),
            Err(ImageError::Cancelled)
        ));
    }
    #[test]
    fn bounded_client_archive_rejects_entry_count_size_and_broken_trailer() {
        let request = request("Linux", "x86_64");
        let root = super::super::stem(&request);
        let path = format!("{root}/qsh");
        let directory = format!("{root}/");
        let mut many = vec![(directory.as_str(), b'5', b"".as_slice()); 128];
        many.push((path.as_str(), b'0', b"client"));
        let too_many = gzip(&tar(&many));
        let mut oversized = tar(&[(path.as_str(), b'0', b"client")]);
        {
            let header = tar::Header::from_byte_slice(&oversized[..512]);
            let mut header = header.clone();
            header.set_size(super::super::IMAGE_LIMIT as u64 + 1);
            header.set_cksum();
            oversized[..512].copy_from_slice(header.as_bytes());
        }
        let oversized = gzip(&oversized);
        let mut broken = gzip(&tar(&[(path.as_str(), b'0', b"client")]));
        let trailer = broken.len() - 8;
        broken[trailer] ^= 1;
        for bytes in [too_many, oversized, broken] {
            let cancel = Cancel::new();
            let budget = Budget::new(std::time::Duration::from_secs(10), &cancel);
            let hash = archive::hash(&bytes, &budget).unwrap();
            assert!(client_bytes(&request, &bytes, &hash, &budget).is_err());
        }
    }

    struct Cancelling;
    impl super::super::ReleaseTransport for Cancelling {
        fn fetch(
            &self,
            _: &str,
            _: FetchLimits,
            cancel: &Cancel,
            _: &dyn BringUpObserver,
        ) -> Result<Vec<u8>, super::super::FetchError> {
            cancel.cancel();
            Err(super::super::FetchError::TemporarilyUnavailable(
                "offline".into(),
            ))
        }
    }
    #[test]
    fn cancellation_wins_over_transport_failure() {
        let images = GitHubImages::uncached(Arc::new(Cancelling));
        let timing = InstallTiming::default();
        assert!(matches!(
            images.select_client_version(None, &timing, &Cancel::new(), &Silent),
            Err(ImageError::Cancelled)
        ));
        assert!(matches!(
            images.load_client(
                &request("Linux", "x86_64"),
                &timing,
                &Cancel::new(),
                &Silent
            ),
            Err(ImageError::Cancelled)
        ));
    }
}
