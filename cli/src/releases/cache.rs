use super::{archive, Budget, ImageError, ARCHIVE_LIMIT, IMAGE_LIMIT};
use bringup::{DaemonImage, ImageRequest};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    archive_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: String,
    target: String,
    archive_sha256: String,
    image_sha256: String,
    image_size: u64,
}

pub(super) struct Cache {
    path: PathBuf,
    _lock: File,
}
struct Cached {
    image: DaemonImage,
    sha: [u8; 32],
    object: PathBuf,
    repair: bool,
}

/// Storage is optional; cancellation, deadlines and verification are not.
pub(super) enum CacheError {
    Unavailable,
    Required(ImageError),
}
impl From<ImageError> for CacheError {
    fn from(error: ImageError) -> Self {
        Self::Required(error)
    }
}
fn unavailable(_: std::io::Error) -> CacheError {
    CacheError::Unavailable
}

pub(super) fn optional<T>(
    result: Result<T, CacheError>,
    budget: &Budget<'_>,
) -> Result<Option<T>, ImageError> {
    // An I/O error must not hide cancellation or an expired local deadline.
    budget.check()?;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(CacheError::Unavailable) => Ok(None),
        Err(CacheError::Required(error)) => Err(error),
    }
}
fn failure(error: impl std::fmt::Display) -> ImageError {
    ImageError::Invalid(format!("release cache: {error}"))
}

fn directory(path: &Path) -> Result<(), CacheError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(unavailable(error)),
    }
    if !fs::symlink_metadata(path).map_err(unavailable)?.is_dir() {
        return Err(CacheError::Unavailable);
    }
    Ok(())
}

fn read(path: &Path, limit: usize, budget: &Budget<'_>) -> Result<Vec<u8>, ImageError> {
    budget.check()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(failure)?;
    let metadata = file.metadata().map_err(failure)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(failure("invalid cache file type or size"));
    }
    let mut data = Vec::new();
    let mut chunk = [0; 64 * 1024];
    loop {
        budget.check()?;
        let count = file.read(&mut chunk).map_err(failure)?;
        if count == 0 {
            break;
        }
        if data.len() + count > limit {
            return Err(failure("cache file exceeds its limit"));
        }
        data.extend_from_slice(&chunk[..count]);
    }
    Ok(data)
}

/// All readers participate in the per-target lock. Each published object and
/// pointer is atomic; the lock also serializes repair of a damaged generation.
impl Cache {
    pub(super) fn open(
        root: &Path,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Self, CacheError> {
        budget.check()?;
        // The caller owns the root (which may itself be an XDG symlink). Every
        // untrusted descendant is checked before it is used as a directory.
        fs::create_dir_all(root).map_err(unavailable)?;
        let mut path = root.to_owned();
        for part in ["releases", &request.version, request.platform.target()] {
            path.push(part);
            directory(&path)?;
        }
        directory(&path.join("objects"))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path.join(".lock"))
            .map_err(unavailable)?;
        if !lock.metadata().map_err(unavailable)?.is_file() {
            return Err(CacheError::Unavailable);
        }
        loop {
            budget.check()?;
            // SAFETY: lock owns a live file descriptor until Cache is dropped.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(unavailable(error));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(Self { path, _lock: lock })
    }

    pub(super) fn load(
        &self,
        request: &ImageRequest,
        expected_sha: Option<&[u8; 32]>,
        budget: &Budget<'_>,
        publication: Duration,
    ) -> Result<Option<DaemonImage>, ImageError> {
        let result = self.load_checked(request, budget);
        budget.check()?;
        // Corrupt and incomplete local data are cache misses, never images.
        let cached = match result {
            Ok(cached) => cached,
            Err(ImageError::Cancelled) => return Err(ImageError::Cancelled),
            Err(_) => return Ok(None),
        };
        if expected_sha.is_some_and(|expected| expected != &cached.sha) {
            return Ok(None);
        }
        if cached.repair {
            let publication = Budget::new(publication, budget.cancel);
            let repair = (|| {
                atomic_file(&cached.object, "image", &cached.image.bytes, &publication)?;
                atomic_file(
                    &cached.object,
                    "receipt.json",
                    &receipt_bytes(request, &cached.sha, &cached.image)?,
                    &publication,
                )
            })();
            optional(repair, &publication)?;
        }
        Ok(Some(cached.image))
    }

    fn load_checked(
        &self,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Cached, ImageError> {
        let current: Current =
            serde_json::from_slice(&read(&self.path.join("current.json"), 4096, budget)?)
                .map_err(failure)?;
        let sha = archive::parse_hash(&current.archive_sha256)
            .ok_or_else(|| failure("invalid archive hash"))?;
        if current.archive_sha256 != archive::hex(&sha) {
            return Err(failure("noncanonical archive hash"));
        }
        let object = self.path.join("objects").join(&current.archive_sha256);
        if !fs::symlink_metadata(&object).map_err(failure)?.is_dir() {
            return Err(failure("invalid object directory"));
        }
        let receipt: Receipt =
            serde_json::from_slice(&read(&object.join("receipt.json"), 4096, budget)?)
                .map_err(failure)?;
        if receipt.version != request.version
            || receipt.target != request.platform.target()
            || receipt.archive_sha256 != current.archive_sha256
            || receipt.image_size > IMAGE_LIMIT as u64
            || archive::parse_hash(&receipt.image_sha256).is_none()
        {
            return Err(failure("invalid receipt"));
        }
        let bytes = read(&object.join("archive"), ARCHIVE_LIMIT, budget)?;
        // Re-extraction binds the image to the verified archive, even if both
        // the cached image and its receipt were changed together.
        let image = archive::verified_image(request, &bytes, &sha, budget)?;
        let image_sha = archive::hex(&image.sha256);
        let cached = read(&object.join("image"), IMAGE_LIMIT, budget);
        let repair = receipt.image_sha256 != image_sha
            || receipt.image_size != image.size
            || cached.as_deref().ok() != Some(image.bytes.as_ref());
        Ok(Cached {
            image,
            sha,
            object,
            repair,
        })
    }

    pub(super) fn publish(
        &self,
        request: &ImageRequest,
        bytes: &[u8],
        sha: &[u8; 32],
        image: &DaemonImage,
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        budget.check()?;
        let objects = self.path.join("objects");
        let name = archive::hex(sha);
        let target = objects.join(&name);
        let staging = tempfile::Builder::new()
            .prefix(".release-")
            .tempdir_in(&objects)
            .map_err(unavailable)?;
        atomic_file(staging.path(), "archive", bytes, budget)?;
        atomic_file(staging.path(), "image", &image.bytes, budget)?;
        let receipt = receipt_bytes(request, sha, image)?;
        atomic_file(staging.path(), "receipt.json", &receipt, budget)?;
        budget.check()?;
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::rename(staging.path(), &target).map_err(unavailable)?;
            }
            Ok(metadata) if metadata.is_dir() => {
                // The same content-addressed generation may have been damaged.
                // Readers hold the lock, so repair is coherent across processes.
                for file in ["archive", "image", "receipt.json"] {
                    budget.check()?;
                    fs::rename(staging.path().join(file), target.join(file))
                        .map_err(unavailable)?;
                }
            }
            Ok(_) => return Err(CacheError::Unavailable),
            Err(error) => return Err(unavailable(error)),
        }
        File::open(&objects)
            .and_then(|file| file.sync_all())
            .map_err(unavailable)?;
        let current = serde_json::to_vec(&Current {
            archive_sha256: name,
        })
        .map_err(failure)?;
        atomic_file(&self.path, "current.json", &current, budget)
    }
}

fn receipt_bytes(
    request: &ImageRequest,
    sha: &[u8; 32],
    image: &DaemonImage,
) -> Result<Vec<u8>, ImageError> {
    serde_json::to_vec(&Receipt {
        version: request.version.clone(),
        target: request.platform.target().into(),
        archive_sha256: archive::hex(sha),
        image_sha256: archive::hex(&image.sha256),
        image_size: image.size,
    })
    .map_err(failure)
}

fn atomic_file(
    parent: &Path,
    name: &str,
    bytes: &[u8],
    budget: &Budget<'_>,
) -> Result<(), CacheError> {
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(unavailable)?;
    for chunk in bytes.chunks(64 * 1024) {
        budget.check()?;
        file.write_all(chunk).map_err(unavailable)?;
    }
    file.as_file().sync_all().map_err(unavailable)?;
    budget.check()?;
    file.persist(parent.join(name))
        .map_err(|error| unavailable(error.error))?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(unavailable)?;
    Ok(())
}
