//! QSH pin read authority. Trusted owners may still edit held files in place;
//! these observations are not an atomic snapshot against root/the same UID.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as _);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH: OFlags = OFlags::RDONLY;
const DIR: OFlags = SEARCH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted QSH pin-store authority",
    )
}
fn owner(stat: &Stat) -> bool {
    stat.st_uid == 0 || stat.st_uid == rustix::process::geteuid().as_raw()
}
fn kind(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}
fn directory(stat: &Stat) -> bool {
    kind(stat) == FileType::Directory
        && owner(stat)
        && (stat.st_mode & 0o022 == 0 || stat.st_mode & 0o1000 != 0)
}
fn public(stat: &Stat) -> bool {
    kind(stat) == FileType::RegularFile && owner(stat) && stat.st_mode & 0o022 == 0
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

// Preserve raw slash/dot syntax: regular-file/ and regular-file/. must still
// require a directory, and symlink/.. traverses the symlink before its parent.
pub(super) fn parts(bytes: &[u8], alias: bool) -> VecDeque<(OsString, bool)> {
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
fn target(parent: &File, name: &OsString) -> io::Result<Vec<u8>> {
    let mut bytes = [0u8; 4097];
    let length = fs::readlinkat_raw(parent, name, &mut bytes[..])?;
    if length > 4096 {
        return Err(refused());
    }
    Ok(bytes[..length].to_vec())
}

struct Entry {
    parent: File,
    name: OsString,
    observed: Option<Stat>,
    alias: Option<Vec<u8>>,
}
impl Entry {
    fn validate(&self) -> io::Result<()> {
        if !directory(&fs::fstat(&self.parent)?) {
            return Err(refused());
        }
        let named = fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW);
        let Some(observed) = &self.observed else {
            return match named {
                Err(rustix::io::Errno::NOENT) => Ok(()),
                _ => Err(refused()),
            };
        };
        let named = named?;
        if !same(observed, &named) || kind(observed) != kind(&named) {
            return Err(refused());
        }
        let valid = match kind(&named) {
            FileType::Directory => directory(&named),
            FileType::RegularFile => public(&named),
            FileType::Symlink => {
                owner(&named)
                    && self.alias.as_deref() == Some(target(&self.parent, &self.name)?.as_slice())
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(refused())
        }
    }
}
pub(super) struct ReadBinding {
    root: File,
    entries: Vec<Entry>,
    source: Option<File>,
}
impl ReadBinding {
    pub(super) fn validate(&self) -> io::Result<()> {
        if !directory(&fs::fstat(&self.root)?) {
            return Err(refused());
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        if let Some(file) = &self.source {
            let held = fs::fstat(file)?;
            if !public(&held)
                || !self
                    .entries
                    .last()
                    .and_then(|e| e.observed.as_ref())
                    .is_some_and(|named| same(&held, named))
            {
                return Err(refused());
            }
        }
        Ok(())
    }
}
pub(super) struct ReadSnapshot {
    text: String,
    binding: ReadBinding,
}
impl ReadSnapshot {
    pub(super) fn into_parts(self) -> (String, ReadBinding) {
        (self.text, self.binding)
    }
}

enum Walk {
    Read(ReadBinding),
    Parent {
        route: ReadBinding,
        parent: File,
        name: OsString,
    },
}

fn walk(path: &Path, parent_only: bool, create: bool) -> io::Result<Walk> {
    if path.as_os_str().is_empty() {
        return Err(refused());
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = File::from(fs::open("/", DIR, Mode::empty())?);
    if !directory(&fs::fstat(&root)?) {
        return Err(refused());
    }
    let mut stack = vec![root.try_clone()?];
    let mut pending = parts(absolute.as_os_str().as_bytes(), false);
    let mut entries = Vec::new();
    let mut aliases = 0;
    while let Some((name, from_alias)) = pending.pop_front() {
        if name == "." || name == ".." {
            if name == ".." && stack.len() > 1 {
                stack.pop();
            }
            if pending.is_empty() {
                return Err(refused());
            }
            continue;
        }
        let parent = stack.last().expect("root remains pinned");
        if !directory(&fs::fstat(parent)?) {
            return Err(refused());
        }
        if parent_only && pending.is_empty() {
            let parent = parent.try_clone()?;
            let route = ReadBinding {
                root,
                entries,
                source: None,
            };
            route.validate()?;
            return Ok(Walk::Parent {
                route,
                parent,
                name,
            });
        }
        let observed = match fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) if !from_alias && create && !pending.is_empty() => {
                if !mutation_parent(&fs::fstat(parent)?) {
                    return Err(refused());
                }
                // Another cooperating writer may create this directory first.
                // It still passes the ordinary named/held authority checks.
                match fs::mkdirat(parent, &name, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW)?
            }
            Err(rustix::io::Errno::NOENT) if !from_alias => {
                entries.push(Entry {
                    parent: parent.try_clone()?,
                    name,
                    observed: None,
                    alias: None,
                });
                let binding = ReadBinding {
                    root,
                    entries,
                    source: None,
                };
                binding.validate()?;
                return Ok(Walk::Read(binding));
            }
            Err(error) => return Err(error.into()),
        };
        if kind(&observed) == FileType::Symlink {
            if !owner(&observed) {
                return Err(refused());
            }
            aliases += 1;
            if aliases > 40 {
                return Err(refused());
            }
            let bytes = target(parent, &name)?;
            entries.push(Entry {
                parent: parent.try_clone()?,
                name,
                observed: Some(observed),
                alias: Some(bytes.clone()),
            });
            if bytes.starts_with(b"/") {
                stack.truncate(1);
            }
            let mut next = parts(&bytes, true);
            next.append(&mut pending);
            pending = next;
            continue;
        }
        if pending.is_empty() {
            // Refuse special files before opening; NONBLOCK alone is not a
            // reason to open a device or FIFO as trust evidence.
            if !public(&observed) {
                return Err(refused());
            }
            let source = File::from(fs::openat(parent, &name, READ, Mode::empty())?);
            if !same(&observed, &fs::fstat(&source)?) {
                return Err(refused());
            }
            entries.push(Entry {
                parent: parent.try_clone()?,
                name,
                observed: Some(observed),
                alias: None,
            });
            let binding = ReadBinding {
                root,
                entries,
                source: Some(source),
            };
            binding.validate()?;
            return Ok(Walk::Read(binding));
        }
        if !directory(&observed) {
            return Err(refused());
        }
        let child = File::from(fs::openat(parent, &name, DIR, Mode::empty())?);
        if !same(&observed, &fs::fstat(&child)?) {
            return Err(refused());
        }
        entries.push(Entry {
            parent: parent.try_clone()?,
            name,
            observed: Some(observed),
            alias: None,
        });
        stack.push(child);
    }
    Err(refused())
}

pub(super) fn read(path: &Path) -> io::Result<ReadSnapshot> {
    read_with(path, |file| {
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    })
}
pub(super) fn read_with(
    path: &Path,
    reader: impl FnOnce(&mut File) -> io::Result<String>,
) -> io::Result<ReadSnapshot> {
    let Walk::Read(mut binding) = walk(path, false, false)? else {
        unreachable!()
    };
    let text = match &mut binding.source {
        Some(file) => reader(file)?,
        None => String::new(),
    };
    binding.validate()?;
    Ok(ReadSnapshot { text, binding })
}

fn mutation_parent(stat: &Stat) -> bool {
    kind(stat) == FileType::Directory
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o022 == 0
}
fn private_lock(stat: &Stat) -> bool {
    kind(stat) == FileType::RegularFile
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode & 0o7777 == 0o600
}

/// A single actual flock and the original configured-entry publication route.
/// No canonicalized leaf name or alias-target sibling lock is substituted.
pub(super) struct Transaction {
    absolute: PathBuf,
    route: ReadBinding,
    parent: File,
    name: OsString,
    lock_name: OsString,
    lock: File,
}
impl Transaction {
    pub(super) fn acquire(path: &Path) -> io::Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(refused());
        }
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let Walk::Parent {
            route,
            parent,
            name,
        } = walk(&absolute, true, true)?
        else {
            return Err(refused());
        };
        let lock_name = super::lock_path_for(Path::new(&name)).into_os_string();
        let mut before = match fs::statat(&parent, &lock_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if private_lock(&stat) => Some(stat),
            Ok(_) => return Err(refused()),
            Err(rustix::io::Errno::NOENT) if mutation_parent(&fs::fstat(&parent)?) => None,
            Err(error) => return Err(error.into()),
        };
        let flags =
            OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let lock = if before.is_none() {
            match fs::openat(
                &parent,
                &lock_name,
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::EXIST) => {
                    let named = fs::statat(&parent, &lock_name, AtFlags::SYMLINK_NOFOLLOW)?;
                    if !private_lock(&named) {
                        return Err(refused());
                    }
                    before = Some(named);
                    fs::openat(&parent, &lock_name, flags, Mode::empty())?
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            fs::openat(&parent, &lock_name, flags, Mode::empty())?
        };
        let lock = File::from(lock);
        let held = fs::fstat(&lock)?;
        if !private_lock(&held) || before.as_ref().is_some_and(|before| !same(before, &held)) {
            return Err(refused());
        }
        loop {
            match fs::flock(&lock, fs::FlockOperation::LockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let tx = Self {
            absolute,
            route,
            parent,
            name,
            lock_name,
            lock,
        };
        tx.validate_route()?;
        Ok(tx)
    }
    fn validate_route(&self) -> io::Result<()> {
        self.route.validate()?;
        if !directory(&fs::fstat(&self.parent)?) {
            return Err(refused());
        }
        let held = fs::fstat(&self.lock)?;
        let named = fs::statat(&self.parent, &self.lock_name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !private_lock(&held) || !private_lock(&named) || !same(&held, &named) {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn read(&self) -> io::Result<ReadSnapshot> {
        self.validate_route()?;
        let snapshot = read(&self.absolute)?;
        self.validate(&snapshot.binding)?;
        Ok(snapshot)
    }
    pub(super) fn validate(&self, source: &ReadBinding) -> io::Result<()> {
        self.validate_route()?;
        source.validate()
    }
    pub(super) fn replace(&mut self, source: &ReadBinding, contents: &[u8]) -> io::Result<()> {
        let name = super::temp_path_for(Path::new(&self.name)).into_os_string();
        self.replace_with(source, contents, name, |_| Ok(()))
    }
    pub(super) fn replace_with(
        &mut self,
        source: &ReadBinding,
        contents: &[u8],
        name: OsString,
        mut phase: impl FnMut(Phase) -> io::Result<()>,
    ) -> io::Result<()> {
        self.validate(source)?;
        if !mutation_parent(&fs::fstat(&self.parent)?) {
            return Err(refused());
        }
        let mut temp = OwnedTemp::create(&self.parent, name)?;
        phase(Phase::Created)?;
        temp.file.write_all(contents)?;
        phase(Phase::Written)?;
        temp.file.sync_all()?;
        phase(Phase::Synced)?;
        self.validate(source)?;
        if !mutation_parent(&fs::fstat(&self.parent)?) {
            return Err(refused());
        }
        temp.validate()?;
        fs::renameat(&self.parent, &temp.name, &self.parent, &self.name)?;
        temp.armed = false;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    Created,
    Written,
    Synced,
}

/// Ownership starts only after exclusive creation. A failed operation may
/// remove only the exact inode still held and named here; moved/unknown names
/// and substitutions are retained. Same-owner namespace edits remain cooperative.
struct OwnedTemp<'a> {
    parent: &'a File,
    name: OsString,
    file: File,
    armed: bool,
}
impl<'a> OwnedTemp<'a> {
    fn create(parent: &'a File, name: OsString) -> io::Result<Self> {
        // Name allocation precedes creation; immediately retain the returned FD.
        let file = File::from(fs::openat(
            parent,
            &name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY
                | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        let temp = Self {
            parent,
            name,
            file,
            armed: true,
        };
        temp.validate()?;
        Ok(temp)
    }
    fn validate(&self) -> io::Result<()> {
        let held = fs::fstat(&self.file)?;
        let named = fs::statat(self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !private_lock(&held) || !private_lock(&named) || !same(&held, &named) {
            return Err(refused());
        }
        Ok(())
    }
}
impl Drop for OwnedTemp<'_> {
    fn drop(&mut self) {
        if self.armed && self.validate().is_ok() {
            let _ = fs::unlinkat(self.parent, &self.name, AtFlags::empty());
        }
    }
}
