//! Official release images with bounded HTTPS downloads and a verified local cache.

mod archive;
mod cache;
mod http;

use bringup::{BringUpObserver, DaemonImage, ImageError, ImageRequest, ImageSource, InstallTiming};
use knock::Cancel;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

const SUMS_LIMIT: usize = release_auth::SUMS_LIMIT;
const BUNDLE_LIMIT: usize = release_auth::BUNDLE_LIMIT;
const ARCHIVE_LIMIT: usize = 64 * 1024 * 1024;
const IMAGE_LIMIT: usize = 32 * 1024 * 1024;
const STREAM_LIMIT: usize = 128 * 1024 * 1024;
const ENTRY_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct FetchLimits {
    pub total: Duration,
    pub idle: Duration,
    pub max_bytes: usize,
}

/// Only temporary network/service failures permit a verified offline cache.
#[derive(Debug, Clone)]
pub enum FetchError {
    /// A temporary failure before receiving any asset body bytes.
    TemporarilyUnavailable(String),
    /// A temporary failure after receiving at least one asset body byte.
    InterruptedResponse(String),
    Rejected(ImageError),
}

impl From<ImageError> for FetchError {
    fn from(error: ImageError) -> Self {
        Self::Rejected(error)
    }
}
impl From<FetchError> for ImageError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::TemporarilyUnavailable(reason)
            | FetchError::InterruptedResponse(reason) => Self::Download(reason),
            FetchError::Rejected(error) => error,
        }
    }
}

/// A bounded download seam; production uses certificate-verified HTTPS only.
pub trait ReleaseTransport: Send + Sync {
    fn fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, FetchError>;
}

pub struct GitHubImages {
    /// The client's cache directory, normally [`crate::paths::cache_dir`];
    /// releases are kept under its `releases`. Without one, every image is
    /// downloaded and verified and none is kept.
    cache_root: Option<PathBuf>,
    transport: Arc<dyn ReleaseTransport>,
    authentication: Authentication,
}

impl GitHubImages {
    pub fn new(cache_root: Option<PathBuf>) -> Self {
        Self {
            cache_root,
            transport: Arc::new(http::HttpsTransport),
            authentication: Authentication::Production,
        }
    }

    pub fn with_transport(cache_root: PathBuf, transport: Arc<dyn ReleaseTransport>) -> Self {
        Self {
            cache_root: Some(cache_root),
            transport,
            authentication: Authentication::Production,
        }
    }

    pub fn uncached(transport: Arc<dyn ReleaseTransport>) -> Self {
        Self {
            cache_root: None,
            transport,
            authentication: Authentication::Production,
        }
    }

    #[cfg(test)]
    fn fixture(cache_root: PathBuf, transport: Arc<dyn ReleaseTransport>) -> Self {
        let mut source = Self::with_transport(cache_root, transport);
        source.authentication = Authentication::Test(test_support::verify);
        source
    }

    /// The cache, when there is a directory for it and it can be used.
    fn cache(
        &self,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Option<cache::Cache>, ImageError> {
        match &self.cache_root {
            Some(root) => cache::optional(
                cache::Cache::open(root, request, budget).map(|mut cache| {
                    cache.authentication = self.authentication;
                    cache
                }),
                budget,
            ),
            None => budget.check().map(|()| None),
        }
    }
}

// Only the product verifier can construct production evidence. The synthetic
// branch is private and absent from every deliverable, including debug builds.
enum Evidence {
    Production(release_auth::VerifiedManifest),
    #[cfg(test)]
    Fixture {
        manifest: Vec<u8>,
        bundle: Vec<u8>,
        assets: std::collections::BTreeMap<String, [u8; 32]>,
    },
}
impl Evidence {
    fn asset_hash(&self, name: &str) -> Option<&[u8; 32]> {
        match self {
            Self::Production(evidence) => evidence.asset_hash(name),
            #[cfg(test)]
            Self::Fixture { assets, .. } => assets.get(name),
        }
    }
    fn manifest_bytes(&self) -> &[u8] {
        match self {
            Self::Production(evidence) => evidence.manifest_bytes(),
            #[cfg(test)]
            Self::Fixture { manifest, .. } => manifest,
        }
    }
    fn bundle_bytes(&self) -> &[u8] {
        match self {
            Self::Production(evidence) => evidence.bundle_bytes(),
            #[cfg(test)]
            Self::Fixture { bundle, .. } => bundle,
        }
    }
    fn archive_hash(&self, request: &ImageRequest) -> Result<&[u8; 32], ImageError> {
        self.asset_hash(&format!("{}.tar.gz", stem(request)))
            .ok_or_else(|| {
                ImageError::Invalid("release authentication: missing target asset".into())
            })
    }
}
#[cfg(test)]
type TestVerifier = fn(&ImageRequest, &[u8], &[u8]) -> Result<Evidence, ImageError>;

#[derive(Clone, Copy)]
enum Authentication {
    Production,
    #[cfg(test)]
    Test(TestVerifier),
}
impl Authentication {
    fn verify(
        self,
        request: &ImageRequest,
        manifest: &[u8],
        bundle: &[u8],
        budget: &Budget<'_>,
    ) -> Result<Evidence, ImageError> {
        budget.check()?;
        let result = match self {
            Self::Production => release_auth::verify_manifest(&request.version, manifest, bundle)
                .map(Evidence::Production)
                .map_err(|error| ImageError::Invalid(format!("release authentication: {error}"))),
            #[cfg(test)]
            Self::Test(verify) => verify(request, manifest, bundle),
        };
        // Synchronous crypto is bounded, but cannot be preempted. Cancellation
        // and expiry must win over its result before evidence can be used.
        budget.check()?;
        result
    }
}

fn bundle_url(request: &ImageRequest) -> Result<String, ImageError> {
    release_urls(request).map(|(manifest, _)| format!("{manifest}.sigstore.json"))
}

pub fn release_urls(request: &ImageRequest) -> Result<(String, String), ImageError> {
    validate(request)?;
    let base = format!(
        "https://github.com/br0adcast/qsh/releases/download/v{}",
        request.version
    );
    Ok((
        format!("{base}/SHA256SUMS"),
        format!("{base}/{}.tar.gz", stem(request)),
    ))
}

fn validate(request: &ImageRequest) -> Result<(), ImageError> {
    request
        .validate()
        .map_err(|error| ImageError::Invalid(error.to_string()))
}

fn stem(request: &ImageRequest) -> String {
    format!("qsh-{}-{}", request.version, request.platform.target())
}

// SHA256SUMS bytes are not daemon-image transfer progress. The source owns
// the explicit metadata phase, including its initial event before network I/O.
struct MetadataTransfer;
impl BringUpObserver for MetadataTransfer {
    fn on_progress(&self, _: bringup::BringUpProgress) {}
}

impl ImageSource for GitHubImages {
    fn load(
        &self,
        request: &ImageRequest,
        timing: &InstallTiming,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<DaemonImage, ImageError> {
        // Public struct literals bypass ImageRequest::new.
        validate(request)?;
        let check = Budget::new(timing.verify, cancel);
        check.check()?;
        // Contact GitHub before consulting the cache, without holding its lock.
        let (sums_url, archive_url) = release_urls(request)?;
        let metadata_progress = |finished| {
            observer.on_progress(bringup::BringUpProgress {
                stage: bringup::BringUpStage::CheckingMetadata,
                completed: 0,
                total: None,
                finished,
            })
        };
        metadata_progress(false);
        let metadata = Budget::new(timing.metadata, cancel);
        let fetch_metadata = |url: &str, limit| {
            let total = metadata.remaining().map_err(FetchError::Rejected)?;
            let result = self.transport.fetch(
                url,
                FetchLimits {
                    total,
                    idle: total.min(timing.download_idle),
                    max_bytes: limit,
                },
                cancel,
                &MetadataTransfer,
            );
            if cancel.is_cancelled() {
                Err(FetchError::Rejected(ImageError::Cancelled))
            } else {
                result
            }
        };
        let offline = |manifest: Option<&[u8]>| {
            let check = Budget::new(timing.verify, cancel);
            let unavailable = || {
                ImageError::Download("signed release metadata temporarily unavailable; no matching authenticated cache".into())
            };
            let Some(cache) = self.cache(request, &check)? else {
                return Err(unavailable());
            };
            let image = cache
                .load(request, None, manifest, &check, timing.publish)?
                .ok_or_else(unavailable)?;
            check.check()?;
            metadata_progress(true);
            check.check()?;
            Ok(image)
        };
        let sums = match fetch_metadata(&sums_url, SUMS_LIMIT) {
            Ok(sums) => sums,
            Err(FetchError::TemporarilyUnavailable(_)) => return offline(None),
            Err(error) => return Err(metadata_error(error)),
        };
        metadata.check()?;
        if sums.len() > SUMS_LIMIT {
            return Err(ImageError::Download(
                "signed release manifest exceeds 1 MiB".into(),
            ));
        }
        let bundle = match fetch_metadata(&bundle_url(request)?, BUNDLE_LIMIT) {
            Ok(bundle) => bundle,
            Err(FetchError::TemporarilyUnavailable(_) | FetchError::InterruptedResponse(_)) => {
                return offline(Some(&sums))
            }
            Err(error) => return Err(metadata_error(error)),
        };
        metadata.check()?;
        if bundle.len() > BUNDLE_LIMIT {
            return Err(ImageError::Download(
                "signed release bundle exceeds 256 KiB".into(),
            ));
        }
        let check = Budget::new(timing.verify, cancel);
        let evidence = self
            .authentication
            .verify(request, &sums, &bundle, &check)?;
        let archive_sha = *evidence.archive_hash(request)?;
        check.check()?;
        metadata_progress(true);
        check.check()?;
        if let Some(cache) = self.cache(request, &check)? {
            if let Some(image) =
                cache.load(request, Some(&evidence), None, &check, timing.publish)?
            {
                return Ok(image);
            }
        }
        // Once GitHub names a hash, a failed download must not use older data.
        Budget::new(timing.download, cancel).check()?;
        let bytes = self.transport.fetch(
            &archive_url,
            FetchLimits {
                total: timing.download,
                idle: timing.download_idle,
                max_bytes: ARCHIVE_LIMIT,
            },
            cancel,
            observer,
        )?;
        if bytes.len() > ARCHIVE_LIMIT {
            return Err(ImageError::Download(
                "release archive exceeds 64 MiB".into(),
            ));
        }
        let check = Budget::new(timing.verify, cancel);
        let image = archive::verified_image(request, &bytes, &archive_sha, &check)?;
        let publication = Budget::new(timing.publish, cancel);
        if let Some(cache) = self.cache(request, &publication)? {
            cache::optional(
                cache.publish(request, &bytes, &evidence, &image, &publication),
                &publication,
            )?;
        }
        publication.check()?;
        Ok(image)
    }
}

fn metadata_error(error: FetchError) -> ImageError {
    match error {
        FetchError::Rejected(ImageError::Cancelled) => ImageError::Cancelled,
        FetchError::Rejected(ImageError::Unavailable(_)) => {
            ImageError::Unavailable("signed release metadata is missing (HTTP 404)".into())
        }
        FetchError::Rejected(_) => {
            ImageError::Download("signed release metadata transport rejected".into())
        }
        FetchError::InterruptedResponse(_) => ImageError::Download(
            "signed release manifest transfer interrupted after body bytes".into(),
        ),
        FetchError::TemporarilyUnavailable(_) => {
            ImageError::Download("signed release metadata temporarily unavailable".into())
        }
    }
}

struct Budget<'a> {
    started: Instant,
    total: Duration,
    cancel: &'a Cancel,
}
impl<'a> Budget<'a> {
    fn new(total: Duration, cancel: &'a Cancel) -> Self {
        Self {
            started: Instant::now(),
            total,
            cancel,
        }
    }
    fn remaining(&self) -> Result<Duration, ImageError> {
        self.check()?;
        Ok(self.total.saturating_sub(self.started.elapsed()))
    }
    fn check(&self) -> Result<(), ImageError> {
        if self.cancel.is_cancelled() {
            Err(ImageError::Cancelled)
        } else if self.started.elapsed() >= self.total {
            Err(ImageError::Invalid(
                "local release operation timed out".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod authentication_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
