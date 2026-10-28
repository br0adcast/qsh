//! Small authority primitives shared by the log file path and the console's
//! session store: the same trust predicates, the same verified alias read
//! and the same repair handle. Each caller keeps its own resolver -- lookup
//! order, alias limit, error text and context, repair sequence and final
//! revalidation -- and maps every refusal here into its own words.

use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{self, AtFlags, Mode, OFlags, Stat};

/// The longest symlink target followed.
pub const MAX_ALIAS_BYTES: usize = 4096;

pub fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// An ancestor directory: owned by root or `uid`, with no group/other write
/// unless sticky.
pub fn trusted_directory(owner: u32, mode: u32, uid: u32) -> bool {
    (owner == 0 || owner == uid) && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}

/// A dedicated private directory: owned by `uid`, and either private already
/// or one whose group/other bits may be repaired -- never `/` (`is_root`)
/// and never a shared sticky directory.
pub fn declared_parent(owner: u32, mode: u32, uid: u32, is_root: bool) -> bool {
    owner == uid && (mode & 0o077 == 0 || (!is_root && mode & 0o1000 == 0))
}

/// A private leaf: owned by `uid`, with exactly one link.
pub fn trusted_leaf(owner: u32, links: u64, uid: u32) -> bool {
    owner == uid && links == 1
}

/// Why [`read_alias`] refused, for each caller to report in its own words.
#[derive(Debug)]
pub enum AliasError {
    /// `readlinkat` failed.
    Read(io::Error),
    /// The target is longer than [`MAX_ALIAS_BYTES`].
    TooLong,
    /// The repeated `lstat` failed.
    Restat(io::Error),
    /// The name no longer has the identity or owner observed before.
    Changed,
}

/// The target of the symlink `name` in `parent`, whose `lstat` the caller
/// already took and checked as `before`. The target is at most
/// [`MAX_ALIAS_BYTES`], and the name must still have `before`'s identity
/// and owner after it was read.
pub fn read_alias(parent: &impl AsFd, name: &OsStr, before: &Stat) -> Result<Vec<u8>, AliasError> {
    let mut buffer = [0u8; MAX_ALIAS_BYTES + 1];
    let count = fs::readlinkat_raw(parent, name, &mut buffer[..])
        .map_err(|error| AliasError::Read(error.into()))?;
    if count > MAX_ALIAS_BYTES {
        return Err(AliasError::TooLong);
    }
    let after = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| AliasError::Restat(error.into()))?;
    if !same(before, &after) || before.st_uid != after.st_uid {
        return Err(AliasError::Changed);
    }
    Ok(buffer[..count].to_vec())
}

/// A descriptor through which `directory` itself can be `fchmod`ed. Search
/// access does not imply that right, so this opens the pinned directory's
/// own `.` entry for reading. `check` validates the new descriptor in the
/// caller's terms and returns its metadata; `None` means it is not the
/// `expected` directory, which the caller refuses in its own words.
pub fn repair_handle(
    directory: &impl AsFd,
    expected: &Stat,
    check: impl FnOnce(&OwnedFd) -> io::Result<Stat>,
) -> io::Result<Option<(OwnedFd, Stat)>> {
    let fd = fs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let current = check(&fd)?;
    Ok(same(expected, &current).then_some((fd, current)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const SEARCH: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn lstat(parent: &OwnedFd, name: &str) -> Stat {
        fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).unwrap()
    }

    #[test]
    fn declared_parent_is_the_negation_of_the_session_refusal() {
        // The session store wrote this rule as a refusal: not owned by the
        // account, or open to group/other while being `/` or sticky.
        for owner in [0, 1000, 2000] {
            for mode in [0o700, 0o750, 0o755, 0o775, 0o777, 0o1700, 0o1777, 0o2770] {
                for is_root in [false, true] {
                    let sticky = mode & 0o1000 != 0;
                    let refused = owner != 1000 || (mode & 0o077 != 0 && (is_root || sticky));
                    assert_eq!(
                        declared_parent(owner, mode, 1000, is_root),
                        !refused,
                        "owner={owner} mode={mode:o} is_root={is_root}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_verified_alias_is_read_whole_and_rechecked() {
        let dir = private_dir();
        let parent = fs::open(dir.path(), SEARCH, Mode::empty()).unwrap();
        let long = "t/".repeat(500);
        symlink(&long, dir.path().join("long")).unwrap();
        let before = lstat(&parent, "long");
        assert_eq!(
            read_alias(&parent, OsStr::new("long"), &before).unwrap(),
            long.as_bytes()
        );

        // An identity that is no longer the name's is refused, whatever the
        // target: here, another symlink's observation.
        symlink(&long, dir.path().join("other")).unwrap();
        let other = lstat(&parent, "other");
        assert!(matches!(
            read_alias(&parent, OsStr::new("long"), &other),
            Err(AliasError::Changed)
        ));
        // So is an owner that differs from the one observed.
        let mut owner = before;
        owner.st_uid = owner.st_uid.wrapping_add(1);
        assert!(matches!(
            read_alias(&parent, OsStr::new("long"), &owner),
            Err(AliasError::Changed)
        ));
        // Not a symlink, and gone: the read itself fails.
        std::fs::write(dir.path().join("file"), "").unwrap();
        let file = lstat(&parent, "file");
        match read_alias(&parent, OsStr::new("file"), &file) {
            Err(AliasError::Read(error)) => {
                assert_eq!(
                    error.raw_os_error(),
                    Some(rustix::io::Errno::INVAL.raw_os_error())
                )
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            read_alias(&parent, OsStr::new("missing"), &file),
            Err(AliasError::Read(_))
        ));
    }

    #[test]
    fn a_repair_handle_is_the_pinned_directory_itself() {
        let dir = private_dir();
        let search = fs::open(dir.path(), SEARCH, Mode::empty()).unwrap();
        let expected = fs::fstat(&search).unwrap();
        let (fd, current) =
            repair_handle(&search, &expected, |fd| fs::fstat(fd).map_err(Into::into))
                .unwrap()
                .expect("the same directory");
        assert!(same(&current, &expected));
        // Opened for reading, so it can change the directory's mode.
        fs::fchmod(&fd, Mode::from_raw_mode(0o711)).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o711
        );

        // Another directory's metadata is not the expected identity.
        let elsewhere = private_dir();
        let other = fs::stat(elsewhere.path()).unwrap();
        assert!(
            repair_handle(&search, &other, |fd| fs::fstat(fd).map_err(Into::into))
                .unwrap()
                .is_none()
        );
        // The caller's own check decides first, and its error is kept.
        let error = repair_handle(&search, &expected, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "caller refusal",
            ))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "caller refusal");
    }
}
