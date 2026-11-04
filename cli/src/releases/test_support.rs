use super::{FetchError, FetchLimits, ReleaseTransport};
use bringup::{BringUpObserver, BringUpProgress, ImageRequest, Platform};
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
    fixture_manifest(
        &request(),
        &super::archive::parse_hash(&digest(bytes)).unwrap(),
    )
}
pub fn fixture_manifest(request: &ImageRequest, sha: &[u8; 32]) -> Vec<u8> {
    let v = &request.version;
    let mut names = Vec::new();
    for target in [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        names.push(format!("qsh-{v}-{target}.tar.gz"));
    }
    let deb = v.replacen('-', "~", 1);
    for tool in ["qsh", "qshd"] {
        for arch in ["amd64", "arm64"] {
            names.push(format!("{tool}_{deb}-1_{arch}.deb"));
        }
        for arch in ["x86_64", "aarch64"] {
            names.push(format!("{tool}-{v}-1.{arch}.rpm"));
        }
    }
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let hash = if name == format!("{}.tar.gz", super::stem(request)) {
                super::archive::hex(sha)
            } else {
                "00".repeat(32)
            };
            format!("{hash}  {name}\n")
        })
        .collect::<String>()
        .into_bytes()
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
        Ok(if url.ends_with("SHA256SUMS.sigstore.json") {
            fixture_bundle("0.4.0", &self.sums)
        } else if url.ends_with("SHA256SUMS") {
            self.sums.clone()
        } else {
            self.archive.clone()
        })
    }
}

// Deliberately synthetic evidence for private orchestration tests only.
// Real signature, historical-time and root-rotation controls live in release-auth.
pub fn fixture_bundle(version: &str, manifest: &[u8]) -> Vec<u8> {
    format!("fixture:{version}:{}", digest(manifest)).into_bytes()
}

pub(super) fn verify(
    request: &ImageRequest,
    manifest: &[u8],
    bundle: &[u8],
) -> Result<super::Evidence, bringup::ImageError> {
    if bundle != fixture_bundle(&request.version, manifest) {
        return Err(bringup::ImageError::Invalid(
            "fixture authentication failed".into(),
        ));
    }
    let text = std::str::from_utf8(manifest).map_err(|_| bringup::ImageError::Checksum)?;
    let name = format!("{}.tar.gz", super::stem(request));
    let hash = text
        .lines()
        .find_map(|line| {
            line.split_once("  ")
                .filter(|(_, asset)| *asset == name)
                .map(|(hash, _)| hash)
        })
        .ok_or(bringup::ImageError::Checksum)?;
    let sha = super::archive::parse_hash(hash).ok_or(bringup::ImageError::Checksum)?;
    if manifest != fixture_manifest(request, &sha) {
        return Err(bringup::ImageError::Checksum);
    }
    let assets = text
        .lines()
        .map(|line| {
            let (hash, name) = line.split_once("  ").unwrap();
            (name.to_owned(), super::archive::parse_hash(hash).unwrap())
        })
        .collect();
    Ok(super::Evidence::Fixture {
        manifest: manifest.to_vec(),
        bundle: bundle.to_vec(),
        assets,
    })
}
pub(super) fn evidence(request: &ImageRequest, sha: &[u8; 32]) -> super::Evidence {
    let manifest = fixture_manifest(request, sha);
    let bundle = fixture_bundle(&request.version, &manifest);
    verify(request, &manifest, &bundle).unwrap()
}
