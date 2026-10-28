//! Logging-specific directory authority. Names are resolved relative to owned
//! descriptors; trusted filesystem owners may still change their namespace.
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};

pub(super) use crate::authority::{declared_parent, trusted_directory, trusted_leaf};
use crate::authority::{same, AliasError};

const MAX_ALIASES: usize = 40;
#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as u32);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH: OFlags = OFlags::RDONLY;
const DIRECTORY: OFlags = SEARCH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const APPEND: OFlags = OFlags::WRONLY
    .union(OFlags::APPEND)
    .union(OFlags::CREATE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Copy)]
pub(crate) enum Intent {
    Generic,
    DeclaredPrivate,
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn directory(fd: &impl AsFd, uid: u32) -> io::Result<Stat> {
    let stat = fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || !trusted_directory(stat.st_uid, stat.st_mode as u32, uid)
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
            "log parent must be a trusted directory: uid={} mode={:04o}; expected root or uid={uid}, no group/other write unless sticky",
            stat.st_uid, stat.st_mode & 0o7777)));
    }
    Ok(stat)
}

fn leaf(stat: &Stat, uid: u32) -> io::Result<()> {
    // nlink_t is narrower on Darwin; keep the policy input platform-neutral.
    #[allow(clippy::unnecessary_cast)]
    let links = stat.st_nlink as u64;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || !trusted_leaf(stat.st_uid, links, uid)
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
            "log leaf must be a single-linked account-owned regular file: uid={} mode={:04o} links={links}; expected uid={uid}",
            stat.st_uid, stat.st_mode & 0o7777)));
    }
    Ok(())
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

fn alias(parent: &OwnedFd, name: &OsStr, uid: u32) -> io::Result<OsString> {
    let before = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Symlink
        || (before.st_uid != 0 && before.st_uid != uid)
    {
        return Err(refused("log parent alias is not trusted"));
    }
    match crate::authority::read_alias(parent, name, &before) {
        Ok(target) => Ok(OsString::from_vec(target)),
        Err(AliasError::Read(error) | AliasError::Restat(error)) => Err(error),
        Err(AliasError::TooLong) => Err(refused("log parent alias target is too long")),
        Err(AliasError::Changed) => Err(refused("log parent alias changed during resolution")),
    }
}

pub(crate) struct ParentAuthority {
    route: PathBuf,
    intent: Intent,
    directory: OwnedFd,
    name: OsString,
    rotated: OsString,
    uid: u32,
    is_root: bool,
}

impl ParentAuthority {
    pub(crate) fn resolve(path: &Path, intent: Intent, create: bool) -> io::Result<Self> {
        let route = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let name = route
            .file_name()
            .ok_or_else(|| refused("log path has no file name"))?
            .to_owned();
        let parent = route
            .parent()
            .ok_or_else(|| refused("log path has no parent"))?;
        let uid = rustix::process::geteuid().as_raw();
        let root = fs::open("/", DIRECTORY, Mode::empty())?;
        let root_stat = directory(&root, uid)
            .map_err(|e| crate::path_error(Path::new("/"), "checking log ancestor", e))?;
        let mut resolved = PathBuf::from("/");
        let mut stack = vec![root];
        let mut pending = parts(parent);
        let mut aliases = 0;
        while let Some(name) = pending.pop_front() {
            if name == "/" {
                stack.truncate(1);
                resolved = PathBuf::from("/");
                continue;
            }
            if name == "." {
                continue;
            }
            if name == ".." {
                if stack.len() > 1 {
                    stack.pop();
                    resolved.pop();
                }
                continue;
            }
            let component = resolved.join(&name);
            let current = stack.last().expect("root stays pinned");
            // Recheck authority before any lookup that may create a component.
            directory(current, uid)
                .map_err(|e| crate::path_error(&resolved, "checking log ancestor", e))?;
            match fs::openat(current, &name, DIRECTORY, Mode::empty()) {
                Ok(fd) => {
                    directory(&fd, uid)
                        .map_err(|e| crate::path_error(&component, "checking log ancestor", e))?;
                    stack.push(fd);
                    resolved = component;
                }
                Err(rustix::io::Errno::NOENT) if create => {
                    match fs::mkdirat(current, &name, Mode::RWXU) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => {
                            return Err(crate::path_error(
                                &component,
                                "resolving log ancestor",
                                error.into(),
                            ))
                        }
                    }
                    let fd = fs::openat(current, &name, DIRECTORY, Mode::empty()).map_err(|e| {
                        crate::path_error(&component, "opening log ancestor", e.into())
                    })?;
                    directory(&fd, uid)
                        .map_err(|e| crate::path_error(&component, "checking log ancestor", e))?;
                    stack.push(fd);
                    resolved = component;
                }
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                    aliases += 1;
                    if aliases > MAX_ALIASES {
                        return Err(crate::path_error(
                            &component,
                            "checking log alias",
                            refused("log parent alias limit exceeded"),
                        ));
                    }
                    let target = alias(current, &name, uid)
                        .map_err(|e| crate::path_error(&component, "checking log alias", e))?;
                    let mut expanded = parts(Path::new(&target));
                    expanded.append(&mut pending);
                    pending = expanded;
                }
                Err(error) => {
                    return Err(crate::path_error(
                        &component,
                        "resolving log ancestor",
                        error.into(),
                    ))
                }
            }
        }
        let directory = stack.pop().expect("root stays pinned");
        let final_stat = self::directory(&directory, uid)?;
        let mut rotated = name.clone();
        rotated.push(".1");
        let authority = Self {
            route,
            intent,
            directory,
            name,
            rotated,
            uid,
            is_root: same(&root_stat, &final_stat),
        };
        authority.validate_parent().map_err(|error| {
            crate::path_error(
                authority.route.parent().unwrap_or(Path::new("/")),
                "checking dedicated log directory",
                error,
            )
        })?;
        Ok(authority)
    }

    fn validate_parent(&self) -> io::Result<Stat> {
        let stat = directory(&self.directory, self.uid)?;
        if matches!(self.intent, Intent::DeclaredPrivate)
            && !declared_parent(stat.st_uid, stat.st_mode as u32, self.uid, self.is_root)
        {
            return Err(refused("dedicated log directory cannot be safely repaired"));
        }
        Ok(stat)
    }

    pub(crate) fn open_append_checked(&self) -> io::Result<File> {
        self.open_append_with_repair(|fd, mode| fs::fchmod(fd, mode).map_err(Into::into))
    }

    pub(super) fn open_append_with_repair(
        &self,
        mut repair: impl FnMut(&OwnedFd, Mode) -> io::Result<()>,
    ) -> io::Result<File> {
        let parent = self.validate_parent()?;
        match fs::statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => leaf(&stat, self.uid)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        let file = fs::openat(&self.directory, &self.name, APPEND, Mode::RUSR | Mode::WUSR)?;
        let stat = fs::fstat(&file)?;
        leaf(&stat, self.uid)?;
        // O_PATH/search authority does not imply chmod capability. Reopen only
        // the pinned directory's own dot entry and check exact identity first.
        let parent_repair =
            if matches!(self.intent, Intent::DeclaredPrivate) && parent.st_mode & 0o077 != 0 {
                let handle = crate::authority::repair_handle(&self.directory, &parent, |fd| {
                    directory(fd, self.uid)
                })?;
                let Some((fd, _)) = handle.filter(|(_, current)| current.st_uid == self.uid) else {
                    return Err(refused("log directory changed before repair"));
                };
                self.validate_parent()?;
                Some(fd)
            } else {
                None
            };
        if stat.st_mode & 0o077 != 0 {
            repair(&file, Mode::RUSR | Mode::WUSR)?;
            let after = fs::fstat(&file)?;
            leaf(&after, self.uid)?;
            if !same(&stat, &after) || after.st_mode & 0o077 != 0 {
                return Err(refused("log file repair was not established"));
            }
        }
        if let Some(fd) = parent_repair {
            repair(&fd, Mode::RWXU)?;
            let after = directory(&fd, self.uid)?;
            if !same(&parent, &after) || after.st_uid != self.uid || after.st_mode & 0o077 != 0 {
                return Err(refused("log directory repair was not established"));
            }
        }
        Ok(file.into())
    }

    /// Re-resolve the captured route without creating missing ancestors. An
    /// old descriptor is never fallback authority for a vanished route.
    pub(crate) fn refresh_route(&mut self) -> io::Result<bool> {
        let next = self.reopen_route()?;
        let changed = !same(&fs::fstat(&self.directory)?, &fs::fstat(&next.directory)?);
        *self = next;
        Ok(changed)
    }

    fn mutation_parent(&self) -> io::Result<()> {
        let stat = self.validate_parent()?;
        if matches!(self.intent, Intent::DeclaredPrivate) && stat.st_mode & 0o077 != 0 {
            return Err(refused("dedicated log directory permissions changed"));
        }
        Ok(())
    }

    /// Check the name without following aliases. A stale held inode may be
    /// unlinked after another sink rotates; reopen the current valid name.
    /// An inode still named active must retain all of its validated metadata.
    pub(crate) fn owns_active(&self, file: &File) -> io::Result<bool> {
        self.mutation_parent()?;
        let named = match fs::statat(&self.directory, &self.name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        leaf(&named, self.uid)?;
        let held = fs::fstat(file)?;
        if !same(&named, &held) {
            return Ok(false);
        }
        leaf(&held, self.uid)?;
        if named.st_mode & 0o077 != 0 || held.st_mode & 0o077 != 0 {
            return Err(refused("active log permissions changed"));
        }
        Ok(true)
    }

    pub(crate) fn rotate_checked(&self, file: &File) -> io::Result<()> {
        if !self.owns_active(file)? {
            return Ok(());
        }
        // A fitting append does not inspect .1: only replacement needs this
        // authority. POSIX rename is not inode-conditional against trusted
        // owners changing these names after validation.
        match fs::statat(&self.directory, &self.rotated, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => leaf(&stat, self.uid)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        self.mutation_parent()?;
        fs::renameat(&self.directory, &self.name, &self.directory, &self.rotated)?;
        Ok(())
    }

    pub(crate) fn reopen_route(&self) -> io::Result<Self> {
        Self::resolve(&self.route, self.intent, false)
    }
}
