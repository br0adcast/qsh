//! Release-cache authority. Public bytes and private lock have distinct policies.
use super::{unavailable, Budget, CacheError};
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
const SEARCH: OFlags = OFlags::PATH;
#[cfg(target_vendor = "apple")]
const SEARCH: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as u32);
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
const SEARCH: OFlags = OFlags::RDONLY;
const DIR: OFlags = SEARCH
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
        "untrusted release cache authority",
    )
}
fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}
fn trusted_owner(owner: u32, current: u32) -> bool {
    owner == 0 || owner == current
}
fn owner(owner: u32) -> bool {
    trusted_owner(owner, uid())
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
// rustix Stat field widths vary between Linux backends and Darwin.
#[allow(clippy::unnecessary_cast)]
fn stat_mode(stat: &fs::Stat) -> u32 {
    stat.st_mode as u32
}
#[allow(clippy::unnecessary_cast)]
fn stat_type(stat: &fs::Stat, kind: libc::mode_t) -> bool {
    stat.st_mode as libc::mode_t & libc::S_IFMT == kind
}
#[allow(clippy::unnecessary_cast)]
fn same_stat(held: &Metadata, named: &fs::Stat) -> bool {
    held.dev() == named.st_dev as u64 && held.ino() == named.st_ino as u64
}
fn directory_policy(m: &Metadata, strict: bool) -> bool {
    m.is_dir() && owner(m.uid()) && (m.mode() & 0o022 == 0 || (!strict && m.mode() & 0o1000 != 0))
}
fn public_policy(m: &Metadata) -> bool {
    m.is_file() && owner(m.uid()) && m.mode() & 0o022 == 0
}
fn lock_policy(m: &Metadata) -> bool {
    m.is_file() && m.uid() == uid() && m.nlink() == 1 && m.mode() & 0o7777 == 0o600
}

pub(super) struct Directory {
    pub(super) file: File,
    parent: Option<Arc<Directory>>,
    name: OsString,
    strict: bool,
}
impl Directory {
    fn opened(
        file: File,
        parent: Option<Arc<Self>>,
        name: OsString,
        strict: bool,
    ) -> io::Result<Arc<Self>> {
        if !directory_policy(&file.metadata()?, strict) {
            return Err(refused());
        }
        Ok(Arc::new(Self {
            file,
            parent,
            name,
            strict,
        }))
    }
    pub(super) fn validate(&self) -> io::Result<()> {
        let m = self.file.metadata()?;
        if !directory_policy(&m, self.strict) {
            return Err(refused());
        }
        if let Some(parent) = &self.parent {
            parent.validate()?;
            let named: File = fs::openat(&parent.file, &self.name, DIR, Mode::empty())?.into();
            if !same(&m, &named.metadata()?) {
                return Err(refused());
            }
        }
        Ok(())
    }
    pub(super) fn child(
        self: &Arc<Self>,
        name: &OsStr,
        create: bool,
        budget: &Budget<'_>,
    ) -> Result<Arc<Self>, CacheError> {
        budget.check()?;
        self.validate().map_err(unavailable)?;
        let fd = match fs::openat(&self.file, name, DIR, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if create => {
                budget.check()?;
                // Creation changes this parent, so require current-account ownership.
                if self.file.metadata().map_err(unavailable)?.uid() != uid() {
                    return Err(CacheError::Unavailable);
                }
                match fs::mkdirat(&self.file, name, Mode::RWXU) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(unavailable(e.into())),
                }
                fs::openat(&self.file, name, DIR, Mode::empty())
                    .map_err(|e| unavailable(e.into()))?
            }
            Err(e) => return Err(unavailable(e.into())),
        };
        Self::opened(fd.into(), Some(self.clone()), name.to_owned(), true).map_err(unavailable)
    }
    pub(super) fn read(
        self: &Arc<Self>,
        name: &str,
        limit: usize,
        budget: &Budget<'_>,
    ) -> Result<CheckedRead, CacheError> {
        budget.check()?;
        self.validate().map_err(unavailable)?;
        let named = fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| unavailable(e.into()))?;
        if !stat_type(&named, libc::S_IFREG)
            || !owner(named.st_uid)
            || stat_mode(&named) & 0o022 != 0
        {
            return Err(CacheError::Unavailable);
        }
        let mut file: File = fs::openat(&self.file, name, READ, Mode::empty())
            .map_err(|e| unavailable(e.into()))?
            .into();
        let metadata = file.metadata().map_err(unavailable)?;
        if !same_stat(&metadata, &named)
            || !public_policy(&metadata)
            || metadata.len() > limit as u64
        {
            return Err(CacheError::Unavailable);
        }
        let bytes = complete_read(&mut file, limit, budget)?;
        let read = CheckedRead {
            file,
            parent: self.clone(),
            name: name.into(),
            bytes,
        };
        read.validate().map_err(unavailable)?;
        budget.check()?;
        Ok(read)
    }
}

fn complete_read(
    reader: &mut impl Read,
    limit: usize,
    budget: &Budget<'_>,
) -> Result<Vec<u8>, CacheError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        budget.check()?;
        let remaining = limit.saturating_sub(bytes.len()).saturating_add(1);
        let request = remaining.min(chunk.len());
        let count = reader.read(&mut chunk[..request]).map_err(unavailable)?;
        if count == 0 {
            break;
        }
        if count > limit.saturating_sub(bytes.len()) {
            return Err(CacheError::Unavailable);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

pub(super) struct CheckedRead {
    file: File,
    parent: Arc<Directory>,
    name: String,
    pub(super) bytes: Vec<u8>,
}
impl CheckedRead {
    pub(super) fn validate(&self) -> io::Result<()> {
        self.parent.validate()?;
        let held = self.file.metadata()?;
        if !public_policy(&held) {
            return Err(refused());
        }
        let named: File =
            fs::openat(&self.parent.file, self.name.as_str(), READ, Mode::empty())?.into();
        let m = named.metadata()?;
        if !public_policy(&m) || !same(&held, &m) {
            return Err(refused());
        }
        Ok(())
    }
}

fn parts(path: &Path) -> VecDeque<OsString> {
    path.components()
        .map(|c| match c {
            Component::RootDir => OsString::from("/"),
            Component::CurDir => OsString::from("."),
            Component::ParentDir => OsString::from(".."),
            Component::Normal(n) => n.to_owned(),
            Component::Prefix(_) => unreachable!("Unix path"),
        })
        .collect()
}
fn walk(route: &Path, create: bool, budget: &Budget<'_>) -> Result<Arc<Directory>, CacheError> {
    budget.check()?;
    let root: File = fs::open("/", DIR, Mode::empty())
        .map_err(|e| unavailable(e.into()))?
        .into();
    let mut stack = vec![Directory::opened(root, None, "/".into(), false).map_err(unavailable)?];
    let mut pending = parts(route);
    let mut aliases = 0;
    while let Some(name) = pending.pop_front() {
        budget.check()?;
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
        let parent = stack.last().expect("root pinned");
        match fs::openat(&parent.file, &name, DIR, Mode::empty()) {
            Ok(fd) => stack.push(
                Directory::opened(fd.into(), Some(parent.clone()), name, false)
                    .map_err(unavailable)?,
            ),
            Err(rustix::io::Errno::NOENT) if create => {
                match fs::mkdirat(&parent.file, &name, Mode::RWXU) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(unavailable(e.into())),
                }
                let fd = fs::openat(&parent.file, &name, DIR, Mode::empty())
                    .map_err(|e| unavailable(e.into()))?;
                stack.push(
                    Directory::opened(fd.into(), Some(parent.clone()), name, false)
                        .map_err(unavailable)?,
                );
            }
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                aliases += 1;
                if aliases > 40 {
                    return Err(CacheError::Unavailable);
                }
                let m = fs::statat(&parent.file, &name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|e| unavailable(e.into()))?;
                if !owner(m.st_uid) || !stat_type(&m, libc::S_IFLNK) {
                    return Err(CacheError::Unavailable);
                }
                let mut bytes = [0u8; 4097];
                let read = fs::readlinkat_raw(&parent.file, &name, &mut bytes)
                    .map_err(|e| unavailable(e.into()))?;
                if read > 4096 {
                    return Err(CacheError::Unavailable);
                }
                let target = OsString::from_vec(bytes[..read].to_vec());
                let mut target = parts(Path::new(&target));
                target.append(&mut pending);
                pending = target;
            }
            Err(e) => return Err(unavailable(e.into())),
        }
    }
    let final_dir = stack.pop().expect("root pinned");
    // Only ordinary ancestors receive the trusted sticky exception.
    if !directory_policy(&final_dir.file.metadata().map_err(unavailable)?, true) {
        return Err(CacheError::Unavailable);
    }
    Ok(final_dir)
}

pub(super) struct Authority {
    route: PathBuf,
    root: Arc<Directory>,
    pub(super) target: Arc<Directory>,
    pub(super) objects: Arc<Directory>,
    lock: File,
}
impl Authority {
    pub(super) fn open(
        root: &Path,
        request: &bringup::ImageRequest,
        budget: &Budget<'_>,
    ) -> Result<Self, CacheError> {
        budget.check()?;
        let route = if root.is_absolute() {
            root.to_owned()
        } else {
            std::env::current_dir().map_err(unavailable)?.join(root)
        };
        let root = walk(&route, true, budget)?;
        let releases = root.child(OsStr::new("releases"), true, budget)?;
        let version = releases.child(OsStr::new(&request.version), true, budget)?;
        let target = version.child(OsStr::new(request.platform.target()), true, budget)?;
        let objects = target.child(OsStr::new("objects"), true, budget)?;
        budget.check()?;
        match fs::statat(&target.file, ".lock", AtFlags::SYMLINK_NOFOLLOW) {
            Ok(m)
                if stat_type(&m, libc::S_IFREG)
                    && m.st_uid == uid()
                    && m.st_nlink == 1
                    && stat_mode(&m) & 0o7777 == 0o600 => {}
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(CacheError::Unavailable),
        }
        let flags =
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        let fd = match fs::openat(&target.file, ".lock", flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => {
                if target.file.metadata().map_err(unavailable)?.uid() != uid() {
                    return Err(CacheError::Unavailable);
                }
                fs::openat(
                    &target.file,
                    ".lock",
                    flags | OFlags::CREATE | OFlags::EXCL,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|e| unavailable(e.into()))?
            }
            Err(e) => return Err(unavailable(e.into())),
        };
        let lock: File = fd.into();
        if !lock_policy(&lock.metadata().map_err(unavailable)?) {
            return Err(CacheError::Unavailable);
        }
        loop {
            budget.check()?;
            match fs::flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(rustix::io::Errno::WOULDBLOCK) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(unavailable(e.into())),
            }
        }
        let authority = Self {
            route,
            root,
            target,
            objects,
            lock,
        };
        authority.validate(budget)?;
        Ok(authority)
    }
    pub(super) fn validate(&self, budget: &Budget<'_>) -> Result<(), CacheError> {
        budget.check()?;
        let current = walk(&self.route, false, budget)?;
        if !same(
            &current.file.metadata().map_err(unavailable)?,
            &self.root.file.metadata().map_err(unavailable)?,
        ) {
            return Err(CacheError::Unavailable);
        }
        self.objects.validate().map_err(unavailable)?;
        let held = self.lock.metadata().map_err(unavailable)?;
        let named: File = fs::openat(&self.target.file, ".lock", READ, Mode::empty())
            .map_err(|e| unavailable(e.into()))?
            .into();
        let m = named.metadata().map_err(unavailable)?;
        if !lock_policy(&held) || !lock_policy(&m) || !same(&held, &m) {
            return Err(CacheError::Unavailable);
        }
        budget.check()?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;

impl Directory {
    fn writable(&self) -> io::Result<()> {
        self.validate()?;
        let m = self.file.metadata()?;
        if m.uid() != uid() || m.mode() & 0o022 != 0 {
            return Err(refused());
        }
        Ok(())
    }
    fn destination(&self, name: &OsStr) -> io::Result<()> {
        self.writable()?;
        match fs::statat(&self.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(m)
                if stat_type(&m, libc::S_IFREG)
                    && owner(m.st_uid)
                    && stat_mode(&m) & 0o022 == 0 =>
            {
                Ok(())
            }
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Ok(_) => Err(refused()),
            Err(error) => Err(error.into()),
        }
    }
}

fn cleanup(parent: &Directory, name: &OsStr, held: &File, flags: AtFlags) {
    // Cleanup deliberately uses the original descriptor even when its route was
    // replaced. Never recurse, guess an unknown name, or remove a replacement.
    let Ok(metadata) = held.metadata() else {
        return;
    };
    let Ok(named) = fs::statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if same_stat(&metadata, &named) {
        let _ = fs::unlinkat(&parent.file, name, flags);
    }
}

struct OwnedFile {
    parent: Arc<Directory>,
    name: OsString,
    file: File,
    active: bool,
}
impl Drop for OwnedFile {
    fn drop(&mut self) {
        if self.active {
            cleanup(&self.parent, &self.name, &self.file, AtFlags::empty());
        }
    }
}
impl OwnedFile {
    fn new(
        authority: &Authority,
        parent: Arc<Directory>,
        budget: &Budget<'_>,
    ) -> Result<Self, CacheError> {
        loop {
            authority.validate(budget)?;
            parent.writable().map_err(unavailable)?;
            let name = OsString::from(format!(".release-file-{:032x}", rand::random::<u128>()));
            match fs::openat(
                &parent.file,
                &name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::EXCL
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        parent,
                        name,
                        file: fd.into(),
                        active: true,
                    })
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(unavailable(e.into())),
            }
        }
    }
    fn validate(&self) -> io::Result<()> {
        self.parent.writable()?;
        let m = self.file.metadata()?;
        let named = fs::statat(&self.parent.file, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if !public_policy(&m) || m.uid() != uid() || !same_stat(&m, &named) {
            return Err(refused());
        }
        Ok(())
    }
    fn write(
        &mut self,
        authority: &Authority,
        bytes: &[u8],
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        use std::io::Write;
        for chunk in bytes.chunks(64 * 1024) {
            authority.validate(budget)?;
            self.validate().map_err(unavailable)?;
            self.file.write_all(chunk).map_err(unavailable)?;
        }
        authority.validate(budget)?;
        self.validate().map_err(unavailable)?;
        self.file.sync_all().map_err(unavailable)?;
        budget.check()?;
        Ok(())
    }
    fn publish(
        mut self,
        authority: &Authority,
        parent: Arc<Directory>,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<CheckedRead, CacheError> {
        // Allocate the destination name and duplicate the retained token before
        // rename: no fallible ownership handoff follows publication.
        let token = CheckedRead {
            file: self.file.try_clone().map_err(unavailable)?,
            parent,
            name: name.into(),
            bytes: Vec::new(),
        };
        authority.validate(budget)?;
        self.validate().map_err(unavailable)?;
        token
            .parent
            .destination(OsStr::new(name))
            .map_err(unavailable)?;
        fs::renameat(&self.parent.file, &self.name, &token.parent.file, name)
            .map_err(|e| unavailable(e.into()))?;
        self.active = false;
        Ok(token)
    }
}

pub(super) struct Stage {
    pub(super) directory: Arc<Directory>,
    known: Vec<OwnedFile>,
    active: bool,
}
impl Drop for Stage {
    fn drop(&mut self) {
        self.known.clear();
        if self.active {
            if let Some(parent) = &self.directory.parent {
                cleanup(
                    parent,
                    &self.directory.name,
                    &self.directory.file,
                    AtFlags::REMOVEDIR,
                );
            }
        }
    }
}
impl Stage {
    #[cfg(test)]
    pub(super) fn name(&self) -> &OsStr {
        &self.directory.name
    }
    pub(super) fn new(authority: &Authority, budget: &Budget<'_>) -> Result<Self, CacheError> {
        loop {
            authority.validate(budget)?;
            authority.objects.writable().map_err(unavailable)?;
            let name = OsString::from(format!(".release-{:032x}", rand::random::<u128>()));
            match fs::mkdirat(&authority.objects.file, &name, Mode::RWXU) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => continue,
                Err(e) => return Err(unavailable(e.into())),
            }
            let file: File = fs::openat(&authority.objects.file, &name, DIR, Mode::empty())
                .map_err(|e| unavailable(e.into()))?
                .into();
            let directory = Directory::opened(file, Some(authority.objects.clone()), name, true)
                .map_err(unavailable)?;
            let stage = Self {
                directory,
                known: Vec::with_capacity(3),
                active: true,
            };
            let metadata = stage.directory.file.metadata().map_err(unavailable)?;
            if metadata.uid() != uid() || metadata.mode() & 0o7777 != 0o700 {
                return Err(CacheError::Unavailable);
            }
            stage.directory.validate().map_err(unavailable)?;
            return Ok(stage);
        }
    }
    pub(super) fn write(
        &mut self,
        authority: &Authority,
        name: &str,
        bytes: &[u8],
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        let token = authority.atomic_file(self.directory.clone(), name, bytes, budget)?;
        self.known.push(OwnedFile {
            parent: token.parent,
            name: token.name.into(),
            file: token.file,
            active: true,
        });
        authority.sync(&self.directory, budget)
    }
    pub(super) fn commit(
        mut self,
        authority: &Authority,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<Arc<Directory>, CacheError> {
        authority.validate(budget)?;
        self.directory.validate().map_err(unavailable)?;
        authority.objects.writable().map_err(unavailable)?;
        let committed = Directory::opened(
            self.directory.file.try_clone().map_err(unavailable)?,
            Some(authority.objects.clone()),
            name.into(),
            true,
        )
        .map_err(unavailable)?;
        match fs::statat(&authority.objects.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(CacheError::Unavailable),
        }
        fs::renameat(
            &authority.objects.file,
            &self.directory.name,
            &authority.objects.file,
            name,
        )
        .map_err(|e| unavailable(e.into()))?;
        // A completed generation is intentionally retained even if a later
        // pointer publication or sync fails.
        self.active = false;
        for file in &mut self.known {
            file.active = false;
        }
        authority.validate(budget)?;
        committed.validate().map_err(unavailable)?;
        Ok(committed)
    }
    pub(super) fn repair(
        &mut self,
        authority: &Authority,
        target: Arc<Directory>,
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        for file in &mut self.known {
            authority.validate(budget)?;
            self.directory.validate().map_err(unavailable)?;
            file.validate().map_err(unavailable)?;
            target.destination(&file.name).map_err(unavailable)?;
            fs::renameat(&file.parent.file, &file.name, &target.file, &file.name)
                .map_err(|e| unavailable(e.into()))?;
            file.active = false;
            target.validate().map_err(unavailable)?;
        }
        Ok(())
    }
}

impl Authority {
    pub(super) fn generation(
        &self,
        name: &str,
        budget: &Budget<'_>,
    ) -> Result<Option<Arc<Directory>>, CacheError> {
        self.validate(budget)?;
        match fs::statat(&self.objects.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Ok(_) => self
                .objects
                .child(OsStr::new(name), false, budget)
                .map(Some),
            Err(e) => Err(unavailable(e.into())),
        }
    }
    pub(super) fn atomic_file(
        &self,
        parent: Arc<Directory>,
        name: &str,
        bytes: &[u8],
        budget: &Budget<'_>,
    ) -> Result<CheckedRead, CacheError> {
        self.validate(budget)?;
        parent.destination(OsStr::new(name)).map_err(unavailable)?;
        let mut file = OwnedFile::new(self, parent.clone(), budget)?;
        file.write(self, bytes, budget)?;
        file.publish(self, parent, name, budget)
    }
    pub(super) fn sync(
        &self,
        directory: &Directory,
        budget: &Budget<'_>,
    ) -> Result<(), CacheError> {
        self.validate(budget)?;
        directory.validate().map_err(unavailable)?;
        // O_PATH/O_SEARCH handles are not assumed to support fsync.
        let sync: File = fs::openat(
            &directory.file,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| unavailable(e.into()))?
        .into();
        if !same(
            &sync.metadata().map_err(unavailable)?,
            &directory.file.metadata().map_err(unavailable)?,
        ) {
            return Err(CacheError::Unavailable);
        }
        sync.sync_all().map_err(unavailable)?;
        directory.validate().map_err(unavailable)?;
        self.validate(budget)
    }
}
