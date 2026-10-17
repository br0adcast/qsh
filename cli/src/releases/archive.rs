use super::{stem, Budget, ENTRY_LIMIT, IMAGE_LIMIT, STREAM_LIMIT};
use bringup::{DaemonImage, ImageError, ImageRequest};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    sync::Arc,
};

pub(super) fn hash(bytes: &[u8], budget: &Budget<'_>) -> Result<[u8; 32], ImageError> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(64 * 1024) {
        budget.check()?;
        hash.update(chunk);
    }
    budget.check()?;
    Ok(hash.finalize().into())
}

pub(super) fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn parse_hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut hash = [0; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(hash)
}

pub(super) fn expected_hash(sums: &[u8], name: &str) -> Result<[u8; 32], ImageError> {
    let text = std::str::from_utf8(sums).map_err(|_| ImageError::Checksum)?;
    let mut result = None;
    for line in text.lines() {
        let Some((hash, file)) = line.split_once(' ') else {
            continue;
        };
        let Some(file) = file.strip_prefix(' ').or_else(|| file.strip_prefix('*')) else {
            continue;
        };
        if file == name {
            if result.is_some() {
                return Err(ImageError::Checksum);
            }
            result = Some(parse_hash(hash).ok_or(ImageError::Checksum)?);
        }
    }
    result.ok_or(ImageError::Checksum)
}

pub(super) fn verified_image(
    request: &ImageRequest,
    bytes: &[u8],
    expected: &[u8; 32],
    budget: &Budget<'_>,
) -> Result<DaemonImage, ImageError> {
    if &hash(bytes, budget)? != expected {
        return Err(ImageError::Checksum);
    }
    let extracted = extract(request, bytes, budget);
    // Preserve cancellation/deadline errors even when Read has wrapped them.
    budget.check()?;
    let bytes: Arc<[u8]> = extracted?.into();
    if bytes.is_empty() {
        return Err(ImageError::Archive("empty daemon image".into()));
    }
    Ok(DaemonImage {
        request: request.clone(),
        size: bytes.len() as u64,
        sha256: hash(&bytes, budget)?,
        bytes,
    })
}

fn archive_error(error: impl std::fmt::Display) -> ImageError {
    ImageError::Archive(error.to_string())
}

/// Bounds the *reader*, including skipped tar members and bytes after tar EOF.
struct Bounded<'a, R> {
    inner: R,
    consumed: usize,
    budget: &'a Budget<'a>,
}
impl<R: Read> Read for Bounded<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.budget.check().map_err(io::Error::other)?;
        let size = out
            .len()
            .min(STREAM_LIMIT.saturating_sub(self.consumed) + 1)
            .min(64 * 1024);
        let count = self.inner.read(&mut out[..size])?;
        self.consumed += count;
        if self.consumed > STREAM_LIMIT {
            return Err(io::Error::other("unpacked release exceeds 128 MiB"));
        }
        Ok(count)
    }
}

fn extract(
    request: &ImageRequest,
    bytes: &[u8],
    budget: &Budget<'_>,
) -> Result<Vec<u8>, ImageError> {
    let reader = Bounded {
        inner: flate2::read::MultiGzDecoder::new(bytes),
        consumed: 0,
        budget,
    };
    let mut archive = tar::Archive::new(reader);
    let root = stem(request);
    let expected = format!("{root}/qshd");
    let mut image = None;
    // Raw iteration counts and rejects extension headers instead of letting tar
    // hide GNU/PAX entries or their allocations behind a single logical member.
    for (index, entry) in archive
        .entries()
        .map_err(archive_error)?
        .raw(true)
        .enumerate()
    {
        budget.check()?;
        if index >= ENTRY_LIMIT {
            return Err(archive_error("release has more than 128 entries"));
        }
        let mut entry = entry.map_err(archive_error)?;
        let path = entry.path_bytes();
        let path = std::str::from_utf8(&path).map_err(archive_error)?;
        if path.starts_with('/')
            || path.contains('\\')
            || path.split('/').any(|part| part == "..")
            || !(path == root || path.starts_with(&format!("{root}/")))
        {
            return Err(archive_error("unsafe release entry path"));
        }
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(archive_error("release contains a link or special entry"));
        }
        if path == expected {
            if !kind.is_file() || image.is_some() {
                return Err(archive_error(
                    "daemon entry is duplicated or not a regular file",
                ));
            }
            if entry.size() > IMAGE_LIMIT as u64 {
                return Err(archive_error("daemon image exceeds 32 MiB"));
            }
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(IMAGE_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(archive_error)?;
            if bytes.len() > IMAGE_LIMIT {
                return Err(archive_error("daemon image exceeds 32 MiB"));
            }
            image = Some(bytes);
        }
    }
    // tar stops at its zero header; gzip must still validate its trailer and
    // every concatenated member, and all remaining output consumes the limit.
    io::copy(&mut archive.into_inner(), &mut io::sink()).map_err(archive_error)?;
    image.ok_or_else(|| archive_error("daemon image is missing"))
}
