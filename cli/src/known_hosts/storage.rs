//! SSH trust-store read authority. These checks detect observed substitutions;
//! trusted root/the same UID can still change an inode between observations.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as _);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH: OFlags = OFlags::RDONLY;
const DIRECTORY: OFlags = SEARCH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted SSH known-hosts authority",
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
fn mutation_parent(stat: &Stat) -> bool {
    kind(stat) == FileType::Directory
        && stat.st_uid == rustix::process::geteuid().as_raw()
        && stat.st_mode & 0o022 == 0
}
fn writable(stat: &Stat) -> bool {
    public(stat) && stat.st_uid == rustix::process::geteuid().as_raw()
}
fn public(stat: &Stat) -> bool {
    kind(stat) == FileType::RegularFile && owner(stat) && stat.st_mode & 0o022 == 0
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

// Path::components would erase regular-file/. and symlink/.. requirements.
// Preserve the kernel's raw traversal order, including a trailing slash.
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
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
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
        validate_entries(&self.root, &self.entries)?;
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
    bytes: Vec<u8>,
    binding: ReadBinding,
}
impl ReadSnapshot {
    pub(super) fn into_parts(self) -> (Vec<u8>, ReadBinding) {
        (self.bytes, self.binding)
    }
}

fn validate_entries(root: &File, entries: &[Entry]) -> io::Result<()> {
    if !directory(&fs::fstat(root)?) {
        return Err(refused());
    }
    for entry in entries {
        entry.validate()?;
    }
    Ok(())
}

fn bind(
    path: &Path,
    append: bool,
    mut before_create: impl FnMut() -> io::Result<()>,
) -> io::Result<ReadBinding> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let root = File::from(fs::open("/", DIRECTORY, Mode::empty())?);
    if !directory(&fs::fstat(&root)?) {
        return Err(refused());
    }
    let mut stack = vec![root.try_clone()?];
    let mut entries = Vec::new();
    let mut pending = parts(absolute.as_os_str().as_bytes(), false);
    let mut aliases = 0;
    while let Some((name, from_alias)) = pending.pop_front() {
        if name == "." || name == ".." {
            if name == ".." && stack.len() > 1 {
                stack.pop();
            }
            if pending.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::EISDIR));
            }
            continue;
        }
        let parent = stack.last().expect("root remains pinned");
        if !directory(&fs::fstat(parent)?) {
            return Err(refused());
        }
        let observed = match fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) if append && !from_alias => {
                validate_entries(&root, &entries)?;
                if !mutation_parent(&fs::fstat(parent)?) {
                    return Err(refused());
                }
                if !pending.is_empty() {
                    fs::mkdirat(parent, &name, Mode::from_raw_mode(0o700))?;
                    fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW)?
                } else {
                    before_create()?;
                    // Recheck the captured route/parent, then let EXCL refuse
                    // an entry that appeared after the observed absence.
                    validate_entries(&root, &entries)?;
                    if !mutation_parent(&fs::fstat(parent)?) {
                        return Err(refused());
                    }
                    let flags = READ
                        .difference(OFlags::RDONLY)
                        .union(OFlags::RDWR)
                        .union(OFlags::APPEND)
                        .union(OFlags::CREATE)
                        .union(OFlags::EXCL);
                    let source = File::from(fs::openat(
                        parent,
                        &name,
                        flags,
                        Mode::from_raw_mode(0o600),
                    )?);
                    let created = fs::fstat(&source)?;
                    if !writable(&created) {
                        return Err(refused());
                    }
                    entries.push(Entry {
                        parent: parent.try_clone()?,
                        name,
                        observed: Some(created),
                        alias: None,
                    });
                    let binding = ReadBinding {
                        root,
                        entries,
                        source: Some(source),
                    };
                    binding.validate()?;
                    return Ok(binding);
                }
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
                return Ok(binding);
            }
            Err(error) => return Err(error.into()),
        };
        if kind(&observed) == FileType::Symlink {
            if !owner(&observed) {
                return Err(refused());
            }
            aliases += 1;
            if aliases > 40 {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
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
            if kind(&observed) == FileType::Directory {
                return Err(io::Error::from_raw_os_error(libc::EISDIR));
            }
            // Inspect the named type before open; never open a device or FIFO
            // as trust evidence even though NONBLOCK is also requested.
            if !public(&observed) {
                return Err(refused());
            }
            if append && !writable(&observed) {
                return Err(refused());
            }
            let flags = if append {
                READ.difference(OFlags::RDONLY)
                    .union(OFlags::RDWR)
                    .union(OFlags::APPEND)
            } else {
                READ
            };
            let source = File::from(fs::openat(parent, &name, flags, Mode::empty())?);
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
            return Ok(binding);
        }
        if kind(&observed) != FileType::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        if !directory(&observed) {
            return Err(refused());
        }
        let child = File::from(fs::openat(parent, &name, DIRECTORY, Mode::empty())?);
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
    Err(io::Error::from_raw_os_error(libc::EISDIR))
}

pub(super) fn read(path: &Path) -> io::Result<ReadSnapshot> {
    read_with(path, |file| {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}
pub(super) fn read_with(
    path: &Path,
    reader: impl FnOnce(&mut File) -> io::Result<Vec<u8>>,
) -> io::Result<ReadSnapshot> {
    let mut binding = bind(path, false, || Ok(()))?;
    let bytes = match &mut binding.source {
        Some(file) => reader(file)?,
        None => Vec::new(),
    };
    binding.validate()?;
    Ok(ReadSnapshot { bytes, binding })
}

// Complete byte scan, with no whole-file allocation or new total-file cap.
pub(super) fn read_tail(file: &mut File) -> io::Result<Option<u8>> {
    let mut buffer = [0u8; 8192];
    let mut last = None;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Ok(last),
            Ok(length) => last = Some(buffer[length - 1]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// An append owns exactly the same descriptor that supplies its tail byte.
/// Safe aliases select their actual target; no name is reopened for writing.
pub(super) struct AppendFile {
    binding: ReadBinding,
}
impl AppendFile {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        Self::open_with(path, || Ok(()))
    }
    pub(super) fn open_with(
        path: &Path,
        before_create: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        let writer = Self {
            binding: bind(path, true, before_create)?,
        };
        writer.validate()?;
        Ok(writer)
    }
    fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        let source = self.binding.source.as_ref().expect("append pins a file");
        if !writable(&fs::fstat(source)?) {
            return Err(refused());
        }
        Ok(())
    }
    pub(super) fn append_with(
        &mut self,
        record: &[u8],
        read_tail: impl FnOnce(&mut File) -> io::Result<Option<u8>>,
        after_tail: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        self.validate()?;
        let file = self.binding.source.as_mut().expect("append pins a file");
        file.rewind()?;
        let last = read_tail(file)?;
        after_tail()?;
        let mut text = Vec::with_capacity(record.len() + 1);
        if last.is_some_and(|byte| byte != b'\n') {
            text.push(b'\n');
        }
        text.extend_from_slice(record);
        self.validate()?;
        // O_APPEND is unchanged: no serialization, whole-record atomicity or
        // rollback is promised if write_all fails after a partial write.
        self.binding
            .source
            .as_mut()
            .expect("append pins a file")
            .write_all(&text)?;
        self.validate()
    }
}
