use super::*;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn winner(parent: &File, leaf: &OsStr, bytes: &[u8]) -> io::Result<()> {
    let fd = nix::fcntl::openat(
        Some(parent.as_raw_fd()),
        leaf,
        nix::fcntl::OFlag::O_CREAT | nix::fcntl::OFlag::O_EXCL | nix::fcntl::OFlag::O_WRONLY,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    // SAFETY: openat returned a new, uniquely owned descriptor.
    unsafe { File::from_raw_fd(fd) }.write_all(bytes)
}

#[test]
fn parent_replacement_before_staging_stays_in_verified_directory() {
    struct Swap {
        original: std::path::PathBuf,
        pinned: std::path::PathBuf,
    }
    impl KeyFileIo for Swap {
        fn stage(&mut self, parent: &File) -> io::Result<publication::Stage> {
            std::fs::rename(&self.original, &self.pinned)?;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.original)?;
            FileIo.stage(parent)
        }
    }
    let dir = private_dir();
    let original = dir.path().join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&original)
        .unwrap();
    let pinned = dir.path().join("pinned");
    let key = load_or_create_with(
        &original.join("host.key"),
        &mut Swap {
            original: original.clone(),
            pinned: pinned.clone(),
        },
    )
    .unwrap();
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&pinned).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(pinned.join("host.key")).unwrap()[..32],
        key.private
    );
    assert_eq!(
        std::fs::metadata(pinned.join("host.key")).unwrap().nlink(),
        1
    );
}

#[test]
fn losing_creator_loads_pinned_winner_after_parent_replacement() {
    struct Lose {
        original: std::path::PathBuf,
        pinned: std::path::PathBuf,
    }
    impl KeyFileIo for Lose {
        fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
            winner(parent, leaf, &[41; 64])?;
            std::fs::rename(&self.original, &self.pinned)?;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.original)?;
            std::fs::write(self.original.join(leaf), [99; 64])?;
            FileIo.publish(parent, stage, leaf)
        }
    }
    let dir = private_dir();
    let original = dir.path().join("parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&original)
        .unwrap();
    let pinned = dir.path().join("pinned");
    let key = load_or_create_with(
        &original.join("host.key"),
        &mut Lose {
            original: original.clone(),
            pinned: pinned.clone(),
        },
    )
    .unwrap();
    assert_eq!(key.private, [41; 32]);
    assert_eq!(key.public, [41; 32]);
    assert_eq!(std::fs::read(original.join("host.key")).unwrap(), [99; 64]);
    assert_eq!(
        std::fs::metadata(pinned.join("host.key")).unwrap().nlink(),
        1
    );
    assert_eq!(std::fs::read_dir(&pinned).unwrap().count(), 1);
}

#[test]
fn unsupported_exclusive_rename_never_falls_back_to_link_publication() {
    struct Unsupported(i32);
    impl KeyFileIo for Unsupported {
        fn publish(&mut self, _: &File, _: &CStr, _: &OsStr) -> io::Result<()> {
            Err(io::Error::from_raw_os_error(self.0))
        }
    }
    for code in [nix::libc::EINVAL, nix::libc::ENOSYS, nix::libc::ENOTSUP] {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        let error = load_or_create_with(&path, &mut Unsupported(code))
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("requires atomic exclusive rename support"));
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(code)
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        // Existing valid keys need no exclusive-rename support.
        let key = load_or_create_transport_key(&path).unwrap();
        assert_eq!(
            load_or_create_with(&path, &mut Unsupported(code))
                .unwrap()
                .public,
            key.public
        );
    }
}

#[test]
fn owned_cleanup_failure_is_reported_for_write_and_losing_publication() {
    struct CleanupFailure {
        lose: bool,
    }
    impl KeyFileIo for CleanupFailure {
        fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
            if self.lose {
                return FileIo.write(file, bytes);
            }
            file.write_all(&bytes[..17])?;
            Err(io::Error::other("injected partial write"))
        }
        fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
            winner(parent, leaf, &[42; 64])?;
            FileIo.publish(parent, stage, leaf)
        }
        fn cleanup(&mut self, _: &File, _: &CStr) -> io::Result<()> {
            Err(io::Error::other("injected owned unlink failure"))
        }
    }
    for lose in [false, true] {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        std::fs::write(dir.path().join(".qshd-host-key-unrelated"), b"sentinel").unwrap();
        let error = load_or_create_with(&path, &mut CleanupFailure { lose })
            .err()
            .unwrap();
        let message = format!("{error:#}");
        assert!(message.contains("injected owned unlink failure"));
        assert!(message.contains(if lose {
            "publishing key"
        } else {
            "injected partial write"
        }));
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            if lose { 3 } else { 2 }
        );
        assert_eq!(
            std::fs::read(dir.path().join(".qshd-host-key-unrelated")).unwrap(),
            b"sentinel"
        );
        if lose {
            assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
            assert_eq!(std::fs::read(&path).unwrap(), [42; 64]);
        } else {
            assert!(!path.exists());
        }
    }
}

#[test]
fn hardlinked_winner_is_rejected_without_replacement() {
    struct HardlinkedWinner {
        directory: std::path::PathBuf,
    }
    impl KeyFileIo for HardlinkedWinner {
        fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
            winner(parent, leaf, &[43; 64])?;
            std::fs::hard_link(self.directory.join(leaf), self.directory.join("other-link"))?;
            FileIo.publish(parent, stage, leaf)
        }
    }
    let dir = private_dir();
    let path = dir.path().join("host.key");
    let error = load_or_create_with(
        &path,
        &mut HardlinkedWinner {
            directory: dir.path().to_owned(),
        },
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("exactly one link"));
    assert_eq!(std::fs::read(&path).unwrap(), [43; 64]);
    assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}
