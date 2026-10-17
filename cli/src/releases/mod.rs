//! Official release images with bounded HTTPS downloads and a verified local cache.

mod archive;
mod cache;
mod http;

use bringup::{BringUpObserver, DaemonImage, ImageError, ImageRequest, ImageSource, InstallTiming};
use knock::Cancel;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

/// Release cache location follows XDG on every supported client OS.
pub fn release_cache_root(xdg_cache_home: Option<&OsStr>, home: &Path) -> PathBuf {
    crate::paths::unix_root(home, xdg_cache_home, ".cache")
}

const SUMS_LIMIT: usize = 1024 * 1024;
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

/// A bounded download seam; production uses certificate-verified HTTPS only.
pub trait ReleaseTransport: Send + Sync {
    fn fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, ImageError>;
}

pub struct GitHubImages {
    cache_root: PathBuf,
    transport: Arc<dyn ReleaseTransport>,
}

impl GitHubImages {
    pub fn new(cache_root: PathBuf) -> Self {
        Self::with_transport(cache_root, Arc::new(http::HttpsTransport))
    }

    pub fn with_transport(cache_root: PathBuf, transport: Arc<dyn ReleaseTransport>) -> Self {
        Self {
            cache_root,
            transport,
        }
    }
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
        let cache = cache::Cache::open(&self.cache_root, request, &check)?;
        if let Some(image) = cache.load(request, &check, timing.publish)? {
            return Ok(image);
        }
        // Network I/O must not monopolize the cache lock: another process can
        // finish its own download or use a complete generation while we wait.
        drop(cache);
        let (sums_url, archive_url) = release_urls(request)?;
        let sums = self.transport.fetch(
            &sums_url,
            FetchLimits {
                total: timing.metadata,
                idle: timing.metadata.min(timing.download_idle),
                max_bytes: SUMS_LIMIT,
            },
            cancel,
            observer,
        )?;
        if sums.len() > SUMS_LIMIT {
            return Err(ImageError::Download(
                "release metadata exceeds 1 MiB".into(),
            ));
        }
        let archive_sha = archive::expected_hash(&sums, &format!("{}.tar.gz", stem(request)))?;
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
        let cache = cache::Cache::open(&self.cache_root, request, &publication)?;
        cache.publish(request, &bytes, &archive_sha, &image, &publication)?;
        Ok(image)
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
