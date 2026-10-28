//! SSH trust-store read authority. These checks detect observed substitutions;
//! trusted root/the same UID can still change an inode between observations.
//! The observed route is `sshauth::route`'s, the policy the QSH pin store
//! shares; append rights, creation and error codes are this store's.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use sshauth::route::{
    self, directory, kind, mutation_parent, public, same, Entry, Refusals, Route,
};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const READ: OFlags = route::READ;
const DIRECTORY: OFlags = route::DIRECTORY;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted SSH known-hosts authority",
    )
}
fn alias_too_long() -> io::Error {
    io::Error::from_raw_os_error(libc::ENAMETOOLONG)
}
const REFUSALS: Refusals = Refusals {
    untrusted: refused,
    alias_too_long,
};
fn writable(stat: &Stat) -> bool {
    public(stat) && stat.st_uid == rustix::process::geteuid().as_raw()
}

pub(super) use route::parts;
pub(super) type ReadBinding = route::Binding;
pub(super) struct ReadSnapshot {
    bytes: Vec<u8>,
    binding: ReadBinding,
}
impl ReadSnapshot {
    pub(super) fn into_parts(self) -> (Vec<u8>, ReadBinding) {
        (self.bytes, self.binding)
    }
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
    let mut route = Route::open(REFUSALS)?;
    let mut stack = vec![route.root().try_clone()?];
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
                route.validate()?;
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
                    route.validate()?;
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
                    route.push(Entry::object(parent, name, created)?);
                    let binding = ReadBinding::new(route, Some(source));
                    binding.validate()?;
                    return Ok(binding);
                }
            }
            Err(rustix::io::Errno::NOENT) if !from_alias => {
                route.push(Entry::absent(parent, name)?);
                let binding = ReadBinding::new(route, None);
                binding.validate()?;
                return Ok(binding);
            }
            Err(error) => return Err(error.into()),
        };
        if kind(&observed) == FileType::Symlink {
            if !route::owner(&observed) {
                return Err(refused());
            }
            aliases += 1;
            if aliases > 40 {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let bytes = route::alias_target(parent, &name, &REFUSALS)?;
            route.push(Entry::alias(parent, name, observed, bytes.clone())?);
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
            route.push(Entry::object(parent, name, observed)?);
            let binding = ReadBinding::new(route, Some(source));
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
        route.push(Entry::object(parent, name, observed)?);
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
    let bytes = match binding.source_mut() {
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
        let source = self.binding.source().expect("append pins a file");
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
        let file = self.binding.source_mut().expect("append pins a file");
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
            .source_mut()
            .expect("append pins a file")
            .write_all(&text)?;
        self.validate()
    }
}
