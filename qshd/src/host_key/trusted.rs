//! Host-key-specific descriptor validation; publication is a separate phase.
use std::collections::VecDeque;
use std::ffi::{CString, OsString};
use std::fs::{File, Metadata, Permissions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use nix::fcntl::{self, AtFlags, OFlag};
use nix::sys::stat::{self, Mode, SFlag};
use nix::unistd::Uid;

const MAX_ALIASES: usize = 40;
const MAX_ALIAS_BYTES: usize = 4096;

#[cfg(any(target_os = "linux", target_os = "android"))]
const DIRECTORY_ACCESS: OFlag = OFlag::O_PATH;
#[cfg(target_vendor = "apple")]
// nix 0.28 omits Apple's search-only flag; retain libc's exact bits.
const DIRECTORY_ACCESS: OFlag = OFlag::from_bits_retain(nix::libc::O_SEARCH);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const DIRECTORY_ACCESS: OFlag = OFlag::O_RDONLY;
const DIRECTORY_FLAGS: OFlag = DIRECTORY_ACCESS
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const LEAF_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_NOCTTY)
    .union(OFlag::O_CLOEXEC);

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Only root and this daemon account may control parent names. Sticky writable
/// directories are allowed only with that trusted owner; each next object is
/// still independently checked before use. Filesystem authority remains trusted.
fn directory(file: File, uid: Uid) -> io::Result<File> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(refused("host key parent is not a directory"));
    }
    if metadata.uid() != 0 && metadata.uid() != uid.as_raw() {
        return Err(refused("host key parent has an untrusted owner"));
    }
    if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
        return Err(refused("host key parent is writable by group or others"));
    }
    Ok(file)
}

fn owned(fd: std::os::fd::RawFd) -> File {
    // SAFETY: callers pass a newly opened, uniquely owned descriptor.
    unsafe { File::from_raw_fd(fd) }
}

fn parts(path: &Path) -> VecDeque<OsString> {
    path.components()
        .map(|part| match part {
            Component::RootDir => OsString::from("/"),
            Component::CurDir => OsString::from("."),
            Component::ParentDir => OsString::from(".."),
            Component::Normal(name) => name.to_owned(),
            Component::Prefix(_) => unreachable!("Unix path has no prefix"),
        })
        .collect()
}

fn alias_target(parent: &File, name: &std::ffi::OsStr, uid: Uid) -> io::Result<OsString> {
    let metadata = stat::fstatat(Some(parent.as_raw_fd()), name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    if metadata.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFLNK.bits() {
        return Err(refused(
            "host key parent is not a directory or trusted alias",
        ));
    }
    if metadata.st_uid != 0 && metadata.st_uid != uid.as_raw() {
        return Err(refused("host key parent alias has an untrusted owner"));
    }
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in host key parent"))?;
    let mut bytes = [0u8; MAX_ALIAS_BYTES + 1];
    // SAFETY: parent remains owned; both buffers are valid for this call.
    let count = unsafe {
        nix::libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize > MAX_ALIAS_BYTES {
        return Err(refused("host key parent alias target is too long"));
    }
    Ok(OsString::from_vec(bytes[..count as usize].to_vec()))
}

/// Each subsequent lookup stays relative to an owned, verified directory.
/// Parent aliases use this same traversal for their targets; canonicalize then
/// reopen would not pin the object. Root/current UID may still change their data.
fn resolve_parent(path: &Path, uid: Uid, create: bool) -> io::Result<(File, OsString)> {
    let leaf = path
        .file_name()
        .ok_or_else(|| refused("host key path has no file name"))?
        .to_owned();
    let ancestors = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let absolute = if ancestors.is_absolute() {
        ancestors.to_owned()
    } else {
        std::env::current_dir()?.join(ancestors)
    };
    let root = directory(
        owned(fcntl::open(Path::new("/"), DIRECTORY_FLAGS, Mode::empty())?),
        uid,
    )?;
    let mut stack = vec![root];
    let mut pending = parts(&absolute);
    let mut aliases = 0;
    while let Some(name) = pending.pop_front() {
        if name == "/" {
            stack.truncate(1);
            continue;
        }
        if name == "." {
            continue;
        }
        if name == ".." {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        let current = stack.last().expect("root stays pinned");
        match fcntl::openat(
            Some(current.as_raw_fd()),
            name.as_os_str(),
            DIRECTORY_FLAGS,
            Mode::empty(),
        ) {
            Ok(fd) => stack.push(directory(owned(fd), uid)?),
            Err(nix::errno::Errno::ENOENT) if create => {
                match stat::mkdirat(Some(current.as_raw_fd()), name.as_os_str(), Mode::S_IRWXU) {
                    Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
                    Err(error) => return Err(error.into()),
                }
                let fd = fcntl::openat(
                    Some(current.as_raw_fd()),
                    name.as_os_str(),
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                )?;
                stack.push(directory(owned(fd), uid)?);
            }
            Err(nix::errno::Errno::ELOOP | nix::errno::Errno::ENOTDIR) => {
                aliases += 1;
                if aliases > MAX_ALIASES {
                    return Err(refused("host key parent alias limit exceeded"));
                }
                let target = alias_target(current, &name, uid)?;
                let mut target = parts(Path::new(&target));
                target.append(&mut pending);
                pending = target;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((stack.pop().expect("root stays pinned"), leaf))
}

fn parent(path: &Path, uid: Uid) -> io::Result<(File, OsString)> {
    resolve_parent(path, uid, false)
}

pub(super) fn prepare_parent(path: &Path, uid: Uid) -> io::Result<(File, OsString)> {
    resolve_parent(path, uid, true)
}

pub(super) trait ReadIo {
    fn repair(&mut self, file: &File) -> io::Result<()> {
        file.set_permissions(Permissions::from_mode(0o600))
    }
    fn read(&mut self, file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        file.read(buffer)
    }
}
pub(super) struct FileIo;
impl ReadIo for FileIo {}

pub(super) struct Loaded {
    pub bytes: [u8; 64],
    pub repaired_mode: Option<u32>,
}

fn validate(file: &File, uid: Uid) -> io::Result<Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(refused("host key is not a regular file"));
    }
    if metadata.uid() != uid.as_raw() {
        return Err(refused("host key has an untrusted owner"));
    }
    if metadata.nlink() != 1 {
        return Err(refused("host key must have exactly one link"));
    }
    if metadata.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host key must contain exactly 64 bytes",
        ));
    }
    Ok(metadata)
}

fn read_opened(mut file: File, uid: Uid, io: &mut impl ReadIo) -> io::Result<Loaded> {
    let metadata = validate(&file, uid)?;
    let mode = metadata.mode() & 0o777;
    let repaired_mode = if mode & 0o077 != 0 {
        io.repair(&file).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("repairing verified host key permissions: {error}"),
            )
        })?;
        if validate(&file, uid)?.mode() & 0o077 != 0 {
            return Err(refused(
                "host key permission repair did not remove group/other access",
            ));
        }
        Some(mode)
    } else {
        None
    };
    // Metadata never authorizes an unbounded allocation, even if the trusted
    // owner changes file size after validation. No byte is read before repair.
    let mut buffer = [0u8; 65];
    let mut length = 0;
    while length < buffer.len() {
        match io.read(&mut file, &mut buffer[length..]) {
            Ok(0) => break,
            Ok(count) => length += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if length != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "host key must contain exactly 64 bytes",
        ));
    }
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&buffer[..64]);
    Ok(Loaded {
        bytes,
        repaired_mode,
    })
}

pub(super) fn read(path: &Path, uid: Uid, io: &mut impl ReadIo) -> io::Result<Loaded> {
    let (parent, leaf) = parent(path, uid)?;
    read_at(&parent, &leaf, uid, io)
}

pub(super) fn read_at(
    parent: &File,
    leaf: &std::ffi::OsStr,
    uid: Uid,
    io: &mut impl ReadIo,
) -> io::Result<Loaded> {
    let file = owned(fcntl::openat(
        Some(parent.as_raw_fd()),
        leaf,
        LEAF_FLAGS,
        Mode::empty(),
    )?);
    read_opened(file, uid, io)
}

#[cfg(test)]
#[path = "trusted_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "trusted_owned_tests.rs"]
mod owned_tests;
