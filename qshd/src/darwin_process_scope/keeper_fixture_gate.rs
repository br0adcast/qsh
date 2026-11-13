//! Private file gates shared by the native keeper fixtures and host regressions.
use super::fixture_diagnostics::GateRead;
use nix::libc;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

pub(super) fn monotonic() -> u128 {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) },
        0
    );
    value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128
}
pub(super) fn exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    exclusive_at_prepare(path, bytes, || {})
}

fn exclusive_at_prepare(path: &Path, bytes: &[u8], prepared: impl FnOnce()) -> io::Result<()> {
    if bytes.len() > 256 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let mut file =
        tempfile::Builder::new()
            .prefix(".keeper-gate-")
            .make_in(parent, |temporary| {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(temporary)
            })?;
    prepared();
    file.write_all(bytes)?;
    // link(2) publishes a complete inode and refuses every existing destination,
    // including symlinks. The temp guard removes only its own private name.
    std::fs::hard_link(file.path(), path)
}

pub(super) fn read_gate(path: &Path) -> io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !valid_metadata(&meta, unsafe { libc::geteuid() }) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    file.take(257).read_to_end(&mut bytes)?;
    if bytes.len() > 256 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
fn valid_metadata(meta: &std::fs::Metadata, owner: u32) -> bool {
    meta.is_file() && meta.uid() == owner && meta.mode() & 0o777 == 0o600 && meta.len() <= 256
}

pub(super) fn wait_release(path: &Path, nonce: &str, end: u128) {
    wait_release_observed(path, nonce, end, |_| {})
}

pub(super) fn wait_release_observed(
    path: &Path,
    nonce: &str,
    end: u128,
    mut observe: impl FnMut(GateRead),
) {
    loop {
        assert!(
            monotonic() < end,
            "fixture release exceeded original deadline"
        );
        match read_release_observed(path, nonce, &mut observe) {
            Ok(()) => return,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => panic!("fixture release gate refused"),
        }
    }
}

fn read_release(path: &Path, nonce: &str) -> io::Result<()> {
    read_release_observed(path, nonce, &mut |_| {})
}

fn read_release_observed(
    path: &Path,
    nonce: &str,
    observe: &mut impl FnMut(GateRead),
) -> io::Result<()> {
    let result = read_gate(path);
    observe(match &result {
        Ok(bytes) if bytes == nonce.as_bytes() => GateRead::Valid,
        Ok(_) => GateRead::Mismatch,
        Err(error) if error.kind() == io::ErrorKind::NotFound => GateRead::Missing,
        Err(_) => GateRead::Refused,
    });
    let bytes = result?;
    assert_eq!(bytes, nonce.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn publication_is_absent_until_complete_for_strict_consumer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release");
        let (prepared, ready) = mpsc::sync_channel(0);
        let (release, proceed) = mpsc::sync_channel(0);
        let destination = path.clone();
        let writer = std::thread::spawn(move || {
            exclusive_at_prepare(&destination, b"fixture-payload", || {
                prepared.send(()).unwrap();
                proceed.recv_timeout(Duration::from_secs(5)).unwrap();
            })
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let before = std::panic::catch_unwind(|| read_release(&path, "fixture-payload"));
        release.send(()).unwrap();
        writer.join().unwrap().unwrap();
        assert!(matches!(before, Ok(Err(ref error)) if error.kind() == io::ErrorKind::NotFound));
        wait_release(&path, "fixture-payload", monotonic() + 1_000_000_000);
    }

    #[test]
    fn destination_collision_preserves_contents_and_links() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release");
        exclusive(&path, b"original").unwrap();
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        assert_eq!(
            exclusive(&path, b"replacement").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(read_gate(&path).unwrap(), b"original");
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert_eq!(
            exclusive(&link, b"replacement").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), path);
        assert!(read_gate(&link).is_err());
        assert_eq!(read_gate(&path).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn strict_consumer_rejects_empty_partial_and_wrong_payloads() {
        let directory = tempfile::tempdir().unwrap();
        for (index, bytes) in [b"".as_slice(), b"fixture-", b"wrong-payload"]
            .into_iter()
            .enumerate()
        {
            let path = directory.path().join(index.to_string());
            exclusive(&path, bytes).unwrap();
            assert!(std::panic::catch_unwind(|| wait_release(
                &path,
                "fixture-payload",
                monotonic() + 1_000_000_000
            ))
            .is_err());
        }
    }

    #[test]
    fn reader_refuses_wrong_mode_oversize_and_directory() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release");
        exclusive(&path, b"payload").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_gate(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, [0; 257]).unwrap();
        assert_eq!(
            read_gate(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_gate(directory.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn publisher_rejects_payload_beyond_reader_bound_without_a_destination() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release");
        assert_eq!(
            exclusive(&path, &[0; 257]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn metadata_predicate_rejects_foreign_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release");
        exclusive(&path, b"payload").unwrap();
        let meta = std::fs::metadata(path).unwrap();
        assert!(valid_metadata(&meta, meta.uid()));
        assert!(!valid_metadata(&meta, meta.uid() ^ 1));
    }
}
