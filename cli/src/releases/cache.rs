mod storage;

use super::{
    archive, Authentication, Budget, Evidence, ImageError, ARCHIVE_LIMIT, BUNDLE_LIMIT,
    IMAGE_LIMIT, SUMS_LIMIT,
};
use bringup::{DaemonImage, ImageRequest};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

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
    authority: storage::Authority,
    pub(super) authentication: Authentication,
    #[cfg(test)]
    hook: std::cell::RefCell<Option<PhaseHook>>,
}

#[cfg(test)]
type PhaseHook = Box<dyn FnMut(Phase)>;

#[cfg(test)]
#[derive(Clone, Debug)]
enum Phase {
    AfterImageRead,
    BeforeRepair,
    BeforeGenerationRename(std::ffi::OsString),
    AfterGenerationCommit,
    BeforePointerRename,
}
struct Cached {
    image: DaemonImage,
    sha: [u8; 32],
    repair: bool,
    generation: std::sync::Arc<storage::Directory>,
    receipt: storage::CheckedRead,
    manifest: Vec<u8>,
    required: Vec<storage::CheckedRead>,
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

fn storage_error(error: CacheError) -> ImageError {
    match error {
        CacheError::Required(error) => error,
        CacheError::Unavailable => failure("unavailable filesystem authority"),
    }
}

/// All readers participate in the per-target lock. Each published object and
/// pointer is atomic; the lock also serializes repair of a damaged generation.
impl Cache {
    pub(super) fn open(
        root: &Path,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Self, CacheError> {
        let authority = storage::Authority::open(root, request, budget)?;
        Ok(Self {
            authority,
            authentication: Authentication::Production,
            #[cfg(test)]
            hook: std::cell::RefCell::new(None),
        })
    }

    #[cfg(test)]
    fn open_test(
        root: &Path,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Self, CacheError> {
        let mut cache = Self::open(root, request, budget)?;
        cache.authentication = Authentication::Test(super::test_support::verify);
        Ok(cache)
    }
    #[cfg(test)]
    fn publish_test(
        &self,
        request: &ImageRequest,
        bytes: &[u8],
        sha: &[u8; 32],
        image: &DaemonImage,
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        let evidence = super::test_support::evidence(request, sha);
        self.publish(request, bytes, &evidence, image, budget)
    }
    #[cfg(test)]
    fn load_test(
        &self,
        request: &ImageRequest,
        budget: &Budget<'_>,
        publication: Duration,
    ) -> Result<Option<DaemonImage>, ImageError> {
        self.load(request, None, None, budget, publication)
    }

    #[cfg(test)]
    fn phase(&self, phase: Phase) {
        if let Some(hook) = self.hook.borrow_mut().as_mut() {
            hook(phase);
        }
    }

    pub(super) fn load(
        &self,
        request: &ImageRequest,
        evidence: Option<&Evidence>,
        required_manifest: Option<&[u8]>,
        budget: &Budget<'_>,
        publication: Duration,
    ) -> Result<Option<DaemonImage>, ImageError> {
        let result = self.load_checked(request, budget);
        let expected_sha = evidence.map(|e| e.archive_hash(request)).transpose()?;
        // A fresh authenticated hash may qualify an existing unsigned archive;
        // never derive authority from its old receipt. Publish all five objects
        // through the same stage, then reopen/reverify the complete generation.
        let result = match (result, evidence) {
            (Err(_), Some(evidence)) => {
                self.authenticate_archive(request, evidence, budget, publication)
            }
            (result, _) => result,
        };
        budget.check()?;
        // Corrupt and incomplete local data are cache misses, never images.
        let mut cached = match result {
            Ok(cached) => cached,
            Err(ImageError::Cancelled) => return Err(ImageError::Cancelled),
            Err(_) => return Ok(None),
        };
        if required_manifest.is_some_and(|manifest| cached.manifest != manifest) {
            return Ok(None);
        }
        if expected_sha.is_some_and(|expected| expected != &cached.sha) {
            return Ok(None);
        }
        if optional(self.validate_cached(&cached, budget), budget)?.is_none() {
            return Ok(None);
        }
        if cached.repair {
            let publication = Budget::new(publication, budget.cancel);
            #[cfg(test)]
            self.phase(Phase::BeforeRepair);
            let repair = (|| {
                self.validate_cached(&cached, &publication)?;
                self.authority.atomic_file(
                    cached.generation.clone(),
                    "image",
                    &cached.image.bytes,
                    &publication,
                )?;
                self.authority.sync(&cached.generation, &publication)?;
                let receipt = receipt_bytes(request, &cached.sha, &cached.image)?;
                let mut owned_receipt = self.authority.atomic_file(
                    cached.generation.clone(),
                    "receipt.json",
                    &receipt,
                    &publication,
                )?;
                owned_receipt.bytes = receipt;
                // Retain the exact token before any fallible post-publication sync.
                cached.receipt = owned_receipt;
                self.authority.sync(&cached.generation, &publication)
            })();
            optional(repair, &publication)?;
        }
        if optional(self.validate_cached(&cached, budget), budget)?.is_none() {
            return Ok(None);
        }
        Ok(Some(cached.image))
    }

    fn validate_cached(&self, cached: &Cached, budget: &Budget<'_>) -> Result<(), CacheError> {
        self.authority.validate(budget)?;
        cached.generation.validate().map_err(unavailable)?;
        cached.receipt.validate().map_err(unavailable)?;
        for read in &cached.required {
            read.validate().map_err(unavailable)?;
        }
        budget.check()?;
        Ok(())
    }

    fn load_checked(
        &self,
        request: &ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Cached, ImageError> {
        self.authority.validate(budget).map_err(storage_error)?;
        let pointer = self
            .authority
            .target
            .read("current.json", 4096, budget)
            .map_err(storage_error)?;
        let current: Current = serde_json::from_slice(&pointer.bytes).map_err(failure)?;
        let sha = archive::parse_hash(&current.archive_sha256)
            .ok_or_else(|| failure("invalid archive hash"))?;
        if current.archive_sha256 != archive::hex(&sha) {
            return Err(failure("noncanonical archive hash"));
        }
        let generation = self
            .authority
            .objects
            .child(std::ffi::OsStr::new(&current.archive_sha256), false, budget)
            .map_err(storage_error)?;
        let manifest = generation
            .read("SHA256SUMS", SUMS_LIMIT, budget)
            .map_err(storage_error)?;
        let bundle = generation
            .read("SHA256SUMS.sigstore.json", BUNDLE_LIMIT, budget)
            .map_err(storage_error)?;
        let evidence =
            self.authentication
                .verify(request, &manifest.bytes, &bundle.bytes, budget)?;
        if evidence.archive_hash(request)? != &sha {
            return Err(failure("authenticated archive hash differs from pointer"));
        }
        let receipt_read = generation
            .read("receipt.json", 4096, budget)
            .map_err(storage_error)?;
        let receipt: Receipt = serde_json::from_slice(&receipt_read.bytes).map_err(failure)?;
        if receipt.version != request.version
            || receipt.target != request.platform.target()
            || receipt.archive_sha256 != current.archive_sha256
            || receipt.image_size > IMAGE_LIMIT as u64
            || archive::parse_hash(&receipt.image_sha256).is_none()
        {
            return Err(failure("invalid receipt"));
        }
        let archive_read = generation
            .read("archive", ARCHIVE_LIMIT, budget)
            .map_err(storage_error)?;
        let image = archive::verified_image(request, &archive_read.bytes, &sha, budget)?;
        let image_sha = archive::hex(&image.sha256);
        let cached = generation.read("image", IMAGE_LIMIT, budget);
        #[cfg(test)]
        self.phase(Phase::AfterImageRead);
        budget.check()?;
        let repair = receipt.image_sha256 != image_sha
            || receipt.image_size != image.size
            || cached.as_ref().ok().map(|r| r.bytes.as_slice()) != Some(image.bytes.as_ref());
        self.authority.validate(budget).map_err(storage_error)?;
        generation.validate().map_err(failure)?;
        receipt_read.validate().map_err(failure)?;
        let manifest_bytes = manifest.bytes.clone();
        let required = vec![pointer, manifest, bundle, archive_read];
        for read in &required {
            read.validate().map_err(failure)?;
        }
        Ok(Cached {
            image,
            sha,
            repair,
            generation,
            receipt: receipt_read,
            manifest: manifest_bytes,
            required,
        })
    }

    fn authenticate_archive(
        &self,
        request: &ImageRequest,
        evidence: &Evidence,
        budget: &Budget<'_>,
        publication: Duration,
    ) -> Result<Cached, ImageError> {
        self.authority.validate(budget).map_err(storage_error)?;
        let pointer = self
            .authority
            .target
            .read("current.json", 4096, budget)
            .map_err(storage_error)?;
        let current: Current = serde_json::from_slice(&pointer.bytes).map_err(failure)?;
        let sha = evidence.archive_hash(request)?;
        if current.archive_sha256 != archive::hex(sha) {
            return Err(failure("different archive generation"));
        }
        let generation = self
            .authority
            .objects
            .child(std::ffi::OsStr::new(&current.archive_sha256), false, budget)
            .map_err(storage_error)?;
        let archive = generation
            .read("archive", ARCHIVE_LIMIT, budget)
            .map_err(storage_error)?;
        let image = archive::verified_image(request, &archive.bytes, sha, budget)?;
        self.authority.validate(budget).map_err(storage_error)?;
        pointer.validate().map_err(failure)?;
        archive.validate().map_err(failure)?;
        generation.validate().map_err(failure)?;
        let publication = Budget::new(publication, budget.cancel);
        self.publish(request, &archive.bytes, evidence, &image, &publication)
            .map_err(storage_error)?;
        // Our publication deliberately replaces names. Retain the old read FDs
        // until the fully published replacement is opened and authenticated.
        let cached = self.load_checked(request, budget)?;
        drop((pointer, archive, generation));
        Ok(cached)
    }

    pub(super) fn publish(
        &self,
        request: &ImageRequest,
        bytes: &[u8],
        evidence: &Evidence,
        image: &DaemonImage,
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        self.authority.validate(budget)?;
        let sha = evidence.archive_hash(request)?;
        let name = archive::hex(sha);
        // Capture an existing generation before staging; never adopt a replacement.
        let existing = self.authority.generation(&name, budget)?;
        let mut staging = storage::Stage::new(&self.authority, budget)?;
        staging.write(&self.authority, "archive", bytes, budget)?;
        staging.write(&self.authority, "image", &image.bytes, budget)?;
        staging.write(
            &self.authority,
            "SHA256SUMS",
            evidence.manifest_bytes(),
            budget,
        )?;
        staging.write(
            &self.authority,
            "SHA256SUMS.sigstore.json",
            evidence.bundle_bytes(),
            budget,
        )?;
        staging.write(
            &self.authority,
            "receipt.json",
            &receipt_bytes(request, sha, image)?,
            budget,
        )?;
        #[cfg(test)]
        self.phase(Phase::BeforeGenerationRename(staging.name().to_owned()));
        let generation = match existing {
            Some(target) => {
                staging.repair(&self.authority, target.clone(), budget)?;
                target
            }
            None => staging.commit(&self.authority, &name, budget)?,
        };
        #[cfg(test)]
        self.phase(Phase::AfterGenerationCommit);
        generation.validate().map_err(unavailable)?;
        self.authority.sync(&self.authority.objects, budget)?;
        let current = serde_json::to_vec(&Current {
            archive_sha256: name,
        })
        .map_err(failure)?;
        #[cfg(test)]
        self.phase(Phase::BeforePointerRename);
        self.authority.validate(budget)?;
        generation.validate().map_err(unavailable)?;
        let pointer = self.authority.atomic_file(
            self.authority.target.clone(),
            "current.json",
            &current,
            budget,
        )?;
        self.authority.sync(&self.authority.target, budget)?;
        pointer.validate().map_err(unavailable)?;
        generation.validate().map_err(unavailable)?;
        self.authority.validate(budget)
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

#[cfg(all(test, target_os = "linux"))]
mod privilege_tests;
