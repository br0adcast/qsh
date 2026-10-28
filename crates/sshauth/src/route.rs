//! Observed descriptor routes shared by the QSH pin store and the console's
//! SSH `known_hosts` reader.
//!
//! Both stores apply one read-authority policy: root or the current eUID owns
//! every ancestor, symlink and file; ancestors have no group/other write
//! unless sticky; a file has no group/other write. A walk records each name
//! it crosses -- the pinned parent, the name, the observed identity, and a
//! symlink's target bytes -- in a [`Route`], and [`Binding::validate`]
//! repeats every observation later. The walks themselves stay with each
//! store: creation, append rights and error codes are store policy.
//!
//! These checks detect observed substitutions; root or the same UID can still
//! change an inode between observations.

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStringExt;

#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as _);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH: OFlags = OFlags::RDONLY;
/// Search-only, non-following access to one directory.
pub const DIRECTORY: OFlags = SEARCH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// A store file opened for reading: not through a symlink, without blocking
/// on a FIFO, and never as a controlling terminal.
pub const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);
/// The longest symlink target followed.
pub const MAX_ALIAS_BYTES: usize = 4096;

/// How one store reports a refusal: a failed observation, and a symlink
/// target longer than [`MAX_ALIAS_BYTES`].
#[derive(Clone, Copy)]
pub struct Refusals {
    pub untrusted: fn() -> io::Error,
    pub alias_too_long: fn() -> io::Error,
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}
pub fn owner(stat: &Stat) -> bool {
    stat.st_uid == 0 || stat.st_uid == euid()
}
pub fn kind(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}
/// An ancestor: trusted owner, no group/other write unless sticky.
pub fn directory(stat: &Stat) -> bool {
    kind(stat) == FileType::Directory
        && owner(stat)
        && (stat.st_mode & 0o022 == 0 || stat.st_mode & 0o1000 != 0)
}
/// A directory this account may create in: its own, with no sticky
/// exception for group/other write.
pub fn mutation_parent(stat: &Stat) -> bool {
    kind(stat) == FileType::Directory && stat.st_uid == euid() && stat.st_mode & 0o022 == 0
}
/// A store file: regular, trusted owner, no group/other write.
pub fn public(stat: &Stat) -> bool {
    kind(stat) == FileType::RegularFile && owner(stat) && stat.st_mode & 0o022 == 0
}
pub fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// The components of `bytes` in the kernel's raw traversal order, each
/// tagged with `alias`. `Path::components` would erase `regular-file/.` and
/// `symlink/..`; a trailing slash becomes a final `.`, so `regular-file/`
/// still requires a directory.
pub fn parts(bytes: &[u8], alias: bool) -> VecDeque<(OsString, bool)> {
    let mut result: VecDeque<_> = bytes
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| (OsString::from_vec(p.to_vec()), alias))
        .collect();
    if bytes.ends_with(b"/") {
        result.push_back((".".into(), alias));
    }
    result
}

/// The target of the symlink `name` in `parent`, at most
/// [`MAX_ALIAS_BYTES`].
pub fn alias_target(parent: &File, name: &OsStr, refusals: &Refusals) -> io::Result<Vec<u8>> {
    let mut bytes = [0u8; MAX_ALIAS_BYTES + 1];
    let length = fs::readlinkat_raw(parent, name, &mut bytes[..])?;
    if length > MAX_ALIAS_BYTES {
        return Err((refusals.alias_too_long)());
    }
    Ok(bytes[..length].to_vec())
}

/// One name a walk crossed, held by its parent's descriptor.
pub struct Entry {
    parent: File,
    name: OsString,
    observed: Option<Stat>,
    alias: Option<Vec<u8>>,
}
impl Entry {
    /// A name that did not exist; it must still be absent.
    pub fn absent(parent: &File, name: OsString) -> io::Result<Self> {
        Self::new(parent, name, None, None)
    }
    /// A directory or file, by its identity.
    pub fn object(parent: &File, name: OsString, observed: Stat) -> io::Result<Self> {
        Self::new(parent, name, Some(observed), None)
    }
    /// A symlink, by its identity and its target.
    pub fn alias(
        parent: &File,
        name: OsString,
        observed: Stat,
        target: Vec<u8>,
    ) -> io::Result<Self> {
        Self::new(parent, name, Some(observed), Some(target))
    }
    fn new(
        parent: &File,
        name: OsString,
        observed: Option<Stat>,
        alias: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        Ok(Self {
            parent: parent.try_clone()?,
            name,
            observed,
            alias,
        })
    }
    fn validate(&self, refusals: &Refusals) -> io::Result<()> {
        if !directory(&fs::fstat(&self.parent)?) {
            return Err((refusals.untrusted)());
        }
        let named = fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW);
        let Some(observed) = &self.observed else {
            return match named {
                Err(rustix::io::Errno::NOENT) => Ok(()),
                _ => Err((refusals.untrusted)()),
            };
        };
        let named = named?;
        if !same(observed, &named) || kind(observed) != kind(&named) {
            return Err((refusals.untrusted)());
        }
        let valid = match kind(&named) {
            FileType::Directory => directory(&named),
            FileType::RegularFile => public(&named),
            FileType::Symlink => {
                owner(&named)
                    && self.alias.as_deref()
                        == Some(alias_target(&self.parent, &self.name, refusals)?.as_slice())
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err((refusals.untrusted)())
        }
    }
}

/// The pinned root and every entry crossed from it, in order.
pub struct Route {
    root: File,
    entries: Vec<Entry>,
    refusals: Refusals,
}
impl Route {
    /// Opens `/`, which must itself be a trusted directory.
    pub fn open(refusals: Refusals) -> io::Result<Self> {
        let root = File::from(fs::open("/", DIRECTORY, Mode::empty())?);
        if !directory(&fs::fstat(&root)?) {
            return Err((refusals.untrusted)());
        }
        Ok(Self {
            root,
            entries: Vec::new(),
            refusals,
        })
    }
    pub fn root(&self) -> &File {
        &self.root
    }
    pub fn refusals(&self) -> &Refusals {
        &self.refusals
    }
    pub fn push(&mut self, entry: Entry) {
        self.entries.push(entry);
    }
    /// Repeats every observation: the root and each ancestor are still
    /// trusted directories and each name still has its observed identity,
    /// type, policy and symlink target, or is still absent.
    pub fn validate(&self) -> io::Result<()> {
        if !directory(&fs::fstat(&self.root)?) {
            return Err((self.refusals.untrusted)());
        }
        for entry in &self.entries {
            entry.validate(&self.refusals)?;
        }
        Ok(())
    }
}

/// A route ending in an opened store file, or in an absent name.
pub struct Binding {
    route: Route,
    source: Option<File>,
}
impl Binding {
    pub fn new(route: Route, source: Option<File>) -> Self {
        Self { route, source }
    }
    pub fn source(&self) -> Option<&File> {
        self.source.as_ref()
    }
    pub fn source_mut(&mut self) -> Option<&mut File> {
        self.source.as_mut()
    }
    /// [`Route::validate`], and the held file is still a store file with the
    /// identity last observed under its name.
    pub fn validate(&self) -> io::Result<()> {
        self.route.validate()?;
        if let Some(file) = &self.source {
            let held = fs::fstat(file)?;
            if !public(&held)
                || !self
                    .route
                    .entries
                    .last()
                    .and_then(|e| e.observed.as_ref())
                    .is_some_and(|named| same(&held, named))
            {
                return Err((self.route.refusals.untrusted)());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn refused() -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, "test refusal")
    }
    fn too_long() -> io::Error {
        io::Error::from_raw_os_error(libc::ENAMETOOLONG)
    }
    const REFUSALS: Refusals = Refusals {
        untrusted: refused,
        alias_too_long: too_long,
    };
    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn lstat(parent: &File, name: &str) -> Stat {
        fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).unwrap()
    }
    fn open_dir(path: &std::path::Path) -> File {
        File::from(fs::open(path, DIRECTORY, Mode::empty()).unwrap())
    }

    #[test]
    fn raw_parts_keep_dots_and_turn_a_trailing_slash_into_a_final_dot() {
        let names = |bytes: &[u8]| -> Vec<String> {
            parts(bytes, false)
                .into_iter()
                .map(|(name, _)| name.into_string().unwrap())
                .collect()
        };
        assert_eq!(names(b"/a//b/./c"), ["a", "b", ".", "c"]);
        assert_eq!(names(b"a/../b"), ["a", "..", "b"]);
        assert_eq!(names(b"/a/b/"), ["a", "b", "."]);
        assert_eq!(names(b"/a/b//"), ["a", "b", "."]);
        assert_eq!(names(b"/"), ["."]);
        assert!(names(b"").is_empty());
        assert!(parts(b"x/y", true).iter().all(|(_, alias)| *alias));
    }

    #[test]
    fn alias_targets_are_read_raw_and_bounded() {
        let dir = private_dir();
        let parent = open_dir(dir.path());
        // Long targets are read whole; the bound itself is above what
        // symlink(2) accepts on supported systems.
        let long = "t/".repeat(500);
        symlink(&long, dir.path().join("long")).unwrap();
        assert_eq!(
            alias_target(&parent, OsStr::new("long"), &REFUSALS).unwrap(),
            long.as_bytes()
        );
        symlink("../x/", dir.path().join("short")).unwrap();
        assert_eq!(
            alias_target(&parent, OsStr::new("short"), &REFUSALS).unwrap(),
            b"../x/"
        );
        let regular = dir.path().join("regular");
        std::fs::write(&regular, "").unwrap();
        assert_eq!(
            alias_target(&parent, OsStr::new("regular"), &REFUSALS)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn a_route_repeats_each_observation() {
        let dir = private_dir();
        let parent = open_dir(dir.path());
        std::fs::write(dir.path().join("file"), "x").unwrap();
        std::fs::set_permissions(
            dir.path().join("file"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        symlink("file", dir.path().join("alias")).unwrap();
        let mut route = Route::open(REFUSALS).unwrap();
        route.push(Entry::absent(&parent, "missing".into()).unwrap());
        route.push(
            Entry::alias(
                &parent,
                "alias".into(),
                lstat(&parent, "alias"),
                b"file".to_vec(),
            )
            .unwrap(),
        );
        route.push(Entry::object(&parent, "file".into(), lstat(&parent, "file")).unwrap());
        let source = File::open(dir.path().join("file")).unwrap();
        let binding = Binding::new(route, Some(source));
        binding.validate().unwrap();

        // Each observation is repeated: an absent name that appears, a
        // retargeted alias, a replaced file and a loosened mode all refuse.
        let refuses = |change: &dyn Fn()| {
            change();
            let error = binding.validate().unwrap_err();
            assert_eq!(error.to_string(), "test refusal");
        };
        refuses(&|| std::fs::write(dir.path().join("missing"), "").unwrap());
        std::fs::remove_file(dir.path().join("missing")).unwrap();
        binding.validate().unwrap();
        refuses(&|| {
            std::fs::remove_file(dir.path().join("alias")).unwrap();
            symlink("other", dir.path().join("alias")).unwrap();
        });
        let mut route = Route::open(REFUSALS).unwrap();
        route.push(Entry::object(&parent, "file".into(), lstat(&parent, "file")).unwrap());
        let binding = Binding::new(route, Some(File::open(dir.path().join("file")).unwrap()));
        binding.validate().unwrap();
        std::fs::set_permissions(
            dir.path().join("file"),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert_eq!(binding.validate().unwrap_err().to_string(), "test refusal");
    }
}
