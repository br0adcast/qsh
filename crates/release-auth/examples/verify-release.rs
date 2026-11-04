//! Noninteractive CI verifier. It never downloads evidence or invokes qsh.
use std::{
    collections::BTreeMap, error::Error, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt,
    path::Path,
};
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open metadata input")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect metadata input")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("metadata input must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read metadata input")?;
    if bytes.len() > limit {
        return Err("metadata input exceeds size limit".into());
    }
    Ok(bytes)
}
fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let mut values = BTreeMap::new();
    while let Some(name) = args.next() {
        if ![
            "--version",
            "--manifest",
            "--bundle",
            "--expected-source-commit",
        ]
        .iter()
        .any(|key| name == *key)
        {
            return Err("unknown argument".into());
        }
        let value = args.next().ok_or("missing argument value")?;
        if values.insert(name, value).is_some() {
            return Err("duplicate argument".into());
        }
    }
    let get = |name: &str| {
        values
            .get(std::ffi::OsStr::new(name))
            .ok_or("missing required argument")
    };
    let version = get("--version")?
        .to_str()
        .ok_or("invalid version encoding")?;
    let manifest = read_bounded(Path::new(get("--manifest")?), release_auth::SUMS_LIMIT)?;
    let bundle = read_bounded(Path::new(get("--bundle")?), release_auth::BUNDLE_LIMIT)?;
    let verified = release_auth::verify_manifest(version, &manifest, &bundle)?;
    if let Some(expected) = values.get(std::ffi::OsStr::new("--expected-source-commit")) {
        if expected.to_str() != Some(verified.source_commit()) {
            return Err("verified source commit differs from checkout".into());
        }
    }
    println!(
        "verified release {} source {}",
        verified.version(),
        verified.source_commit()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("release metadata: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_regular_file_and_rejects_symlink_fifo_and_oversize() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("regular");
        std::fs::write(&file, b"exact bytes").unwrap();
        assert_eq!(read_bounded(&file, 11).unwrap(), b"exact bytes");
        assert!(read_bounded(&file, 10).is_err());
        assert!(read_bounded(directory.path(), 100).is_err());
        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&file, &symlink).unwrap();
        assert!(read_bounded(&symlink, 100).is_err());
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_bounded(&fifo, 100).is_err());
    }
}
