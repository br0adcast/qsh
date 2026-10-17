use bringup::{BringUpObserver, BringUpProgress, ImageRequest, Platform};
use qsh::releases::{FetchError, FetchLimits, ReleaseTransport};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
pub const STEM: &str = "qsh-0.4.0-x86_64-unknown-linux-musl";
pub const IMAGE: &[u8] = b"a verified daemon image";
pub struct Silent;
impl BringUpObserver for Silent {
    fn on_progress(&self, _: BringUpProgress) {}
}
pub fn request() -> ImageRequest {
    ImageRequest::new(Platform::from_uname("Linux", "x86_64").unwrap(), "0.4.0").unwrap()
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn sums(bytes: &[u8]) -> Vec<u8> {
    format!("{}  {STEM}.tar.gz\n", digest(bytes)).into_bytes()
}
pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
pub fn tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    // Write raw headers so malformed paths survive fixture construction.
    let mut data = Vec::new();
    for (path, kind, body) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::new(*kind));
        header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        if *kind == b'1' || *kind == b'2' {
            header.set_link_name("victim").unwrap();
        }
        header.set_cksum();
        data.extend_from_slice(header.as_bytes());
        data.extend_from_slice(body);
        data.resize(data.len().div_ceil(512) * 512, 0);
    }
    data.resize(data.len() + 1024, 0);
    data
}
pub fn archive() -> Vec<u8> {
    gzip(&tar(&[
        (&format!("{STEM}/"), b'5', b""),
        (&format!("{STEM}/qshd"), b'0', IMAGE),
    ]))
}
pub struct Fake {
    pub sums: Vec<u8>,
    pub archive: Vec<u8>,
    pub calls: AtomicUsize,
    pub offline: bool,
}
impl Fake {
    pub fn new(archive: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            sums: sums(&archive),
            archive,
            calls: AtomicUsize::new(0),
            offline: false,
        })
    }
    pub fn offline() -> Arc<Self> {
        Arc::new(Self {
            sums: vec![],
            archive: vec![],
            calls: AtomicUsize::new(0),
            offline: true,
        })
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl ReleaseTransport for Fake {
    fn fetch(
        &self,
        url: &str,
        _: FetchLimits,
        _: &knock::Cancel,
        _: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.offline {
            return Err(FetchError::TemporarilyUnavailable("offline".into()));
        }
        Ok(if url.ends_with("SHA256SUMS") {
            self.sums.clone()
        } else {
            self.archive.clone()
        })
    }
}

/// Seeds the production cache with a real daemon, without contacting a release server.
#[allow(dead_code)] // Shared with release-only targets that do not install a real daemon.
pub fn seed_release_cache(
    root: &std::path::Path,
    request: &ImageRequest,
    qshd_path: &std::path::Path,
) {
    request.validate().unwrap();
    let staging = tempfile::tempdir().unwrap();
    let image = staging.path().join("qshd");
    std::fs::copy(qshd_path, &image).unwrap();
    assert!(std::process::Command::new("strip")
        .arg(&image)
        .status()
        .unwrap()
        .success());
    let bytes = std::fs::read(image).unwrap();
    let stem = format!("qsh-{}-{}", request.version, request.platform.target());
    let archive = gzip(&tar(&[(&format!("{stem}/qshd"), b'0', &bytes)]));
    let archive_sha = digest(&archive);
    let cache = root
        .join("releases")
        .join(&request.version)
        .join(request.platform.target());
    let object = cache.join("objects").join(&archive_sha);
    std::fs::create_dir_all(&object).unwrap();
    std::fs::write(object.join("archive"), archive).unwrap();
    std::fs::write(object.join("image"), &bytes).unwrap();
    std::fs::write(
        object.join("receipt.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": request.version, "target": request.platform.target(),
            "archive_sha256": archive_sha, "image_sha256": digest(&bytes), "image_size": bytes.len()
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        cache.join("current.json"),
        serde_json::to_vec(&serde_json::json!({"archive_sha256": archive_sha})).unwrap(),
    )
    .unwrap();
}
