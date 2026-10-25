//! Session-slot-specific descriptor authority; no path mutation after acquisition.
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const MAX_ALIASES: usize = 40;
const MAX_ALIAS_BYTES: usize = 4096;
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
const CANDIDATE: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);
#[derive(Clone, Copy)]
pub(crate) enum DirectoryIntent {
    Generic,
    DeclaredPrivate,
}
fn refused(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, text)
}
fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}
fn trusted_directory(owner: u32, mode: u32, uid: u32) -> bool {
    (owner == 0 || owner == uid) && (mode & 0o022 == 0 || mode & 0o1000 != 0)
}
fn trusted_leaf(owner: u32, links: u64, uid: u32) -> bool {
    owner == uid && links == 1
}
fn directory(file: &File, uid: u32) -> io::Result<Stat> {
    let m = fs::fstat(file)?;
    if FileType::from_raw_mode(m.st_mode) != FileType::Directory
        || !trusted_directory(m.st_uid, m.st_mode as u32, uid)
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
            "session ancestor must be a trusted directory: uid={} mode={:04o}; expected root or uid={uid}, no group/other write unless sticky",
            m.st_uid, m.st_mode & 0o7777)));
    }
    Ok(m)
}
fn leaf(m: &Stat, uid: u32) -> io::Result<()> {
    // Darwin nlink_t is narrower; policy inputs have one portable width.
    #[allow(clippy::unnecessary_cast)]
    let links = m.st_nlink as u64;
    if FileType::from_raw_mode(m.st_mode) != FileType::RegularFile
        || !trusted_leaf(m.st_uid, links, uid)
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!(
            "session slot must be a single-linked account-owned regular file: uid={} mode={:04o} links={links}; expected uid={uid}",
            m.st_uid, m.st_mode & 0o7777)));
    }
    Ok(())
}
fn alias_length(length: usize) -> io::Result<()> {
    if length > MAX_ALIAS_BYTES {
        Err(refused("session directory alias target is too long"))
    } else {
        Ok(())
    }
}
fn parts(bytes: &[u8]) -> VecDeque<OsString> {
    // Preserve raw bytes and directory syntax, including regular-file/.. errors.
    bytes
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| OsString::from_vec(p.to_vec()))
        .collect()
}
fn resolve(route: &Path, intent: DirectoryIntent, create: bool) -> io::Result<File> {
    let uid = rustix::process::geteuid().as_raw();
    let root = File::from(fs::open("/", DIRECTORY, Mode::empty())?);
    let root_stat = directory(&root, uid)?;
    let mut stack = vec![root];
    let mut resolved = PathBuf::from("/");
    let mut pending = parts(route.as_os_str().as_bytes());
    let mut aliases = 0;
    while let Some(name) = pending.pop_front() {
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
        let parent = stack.last().expect("root stays pinned");
        match fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(m) if FileType::from_raw_mode(m.st_mode) == FileType::Symlink => {
                if m.st_uid != 0 && m.st_uid != uid {
                    return Err(logging::path_error(&component, "checking session alias", io::Error::new(io::ErrorKind::PermissionDenied, format!("session directory alias has untrusted uid={}; expected root or uid={uid}", m.st_uid))));
                }
                aliases += 1;
                if aliases > MAX_ALIASES {
                    return Err(logging::path_error(
                        &component,
                        "checking session alias",
                        refused("session directory alias limit exceeded"),
                    ));
                }
                let mut buffer = [0u8; MAX_ALIAS_BYTES + 1];
                let count =
                    fs::readlinkat_raw(parent, &name, &mut buffer[..]).map_err(|error| {
                        logging::path_error(&component, "reading session alias", error.into())
                    })?;
                alias_length(count)?;
                let after = fs::statat(parent, &name, AtFlags::SYMLINK_NOFOLLOW)?;
                if !same(&m, &after) || m.st_uid != after.st_uid {
                    return Err(refused("session alias changed during resolution"));
                }
                let target = &buffer[..count];
                if target.starts_with(b"/") {
                    stack.truncate(1);
                    resolved = PathBuf::from("/");
                }
                let mut target = parts(target);
                target.append(&mut pending);
                pending = target;
                continue;
            }
            Ok(_) => {}
            Err(rustix::io::Errno::NOENT) if create => {
                match fs::mkdirat(parent, &name, Mode::RWXU) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => {
                        return Err(logging::path_error(
                            &component,
                            "resolving session ancestor",
                            e.into(),
                        ))
                    }
                }
            }
            Err(e) => {
                return Err(logging::path_error(
                    &component,
                    "resolving session ancestor",
                    e.into(),
                ))
            }
        }
        let file = File::from(
            fs::openat(parent, &name, DIRECTORY, Mode::empty()).map_err(|e| {
                logging::path_error(&component, "opening session ancestor", e.into())
            })?,
        );
        directory(&file, uid)
            .map_err(|e| logging::path_error(&component, "checking session ancestor", e))?;
        stack.push(file);
        resolved = component;
    }
    let file = stack.pop().expect("root stays pinned");
    let m = directory(&file, uid)?;
    if matches!(intent, DirectoryIntent::DeclaredPrivate)
        && (m.st_uid != uid
            || (m.st_mode & 0o077 != 0 && (same(&m, &root_stat) || m.st_mode & 0o1000 != 0)))
    {
        return Err(logging::path_error(&resolved, "checking dedicated session directory",
            io::Error::new(io::ErrorKind::PermissionDenied, format!(
                "dedicated session directory cannot be safely repaired: uid={} mode={:04o}; expected private directory owned by uid={uid}",
                m.st_uid, m.st_mode & 0o7777))));
    }
    Ok(file)
}
fn basename(name: &str) -> io::Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        Err(refused("session slot name is not a basename"))
    } else {
        Ok(())
    }
}

pub(crate) struct Store {
    directory: File,
    route: PathBuf,
    intent: DirectoryIntent,
}
// Heap-only metadata. No descriptors/Arc/callbacks: SlotLock deliberately omits
// this destructor in a fork-copy while its separate File fields still close.
pub(crate) struct SlotBinding {
    route: PathBuf,
    name: OsString,
    intent: DirectoryIntent,
}
impl Store {
    pub(crate) fn open(path: &Path, intent: DirectoryIntent) -> io::Result<Self> {
        let route = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let directory = resolve(&route, intent, true)?;
        Ok(Self {
            directory,
            route,
            intent,
        })
    }
    pub(crate) fn open_candidate(&self, name: &str) -> io::Result<File> {
        basename(name)?;
        let uid = rustix::process::geteuid().as_raw();
        directory(&self.directory, uid)?;
        match fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(m) => leaf(&m, uid)?,
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(e.into()),
        }
        let file = File::from(fs::openat(
            &self.directory,
            name,
            CANDIDATE,
            Mode::RUSR | Mode::WUSR,
        )?);
        leaf(&fs::fstat(&file)?, uid)?;
        Ok(file)
    }
    // Complete fallible descriptor duplication/metadata allocation BEFORE flock.
    pub(crate) fn binding(&self, name: &str) -> io::Result<(File, SlotBinding)> {
        basename(name)?;
        Ok((
            self.directory.try_clone()?,
            SlotBinding {
                route: self.route.clone(),
                name: name.into(),
                intent: self.intent,
            },
        ))
    }
    pub(crate) fn prepare_locked(
        &self,
        parent: &File,
        slot: &File,
        binding: &SlotBinding,
    ) -> io::Result<()> {
        self.prepare_locked_with(parent, slot, binding, |fd, mode| {
            fs::fchmod(fd, mode).map_err(Into::into)
        })
    }
    fn prepare_locked_with(
        &self,
        parent: &File,
        slot: &File,
        binding: &SlotBinding,
        mut repair: impl FnMut(&File, Mode) -> io::Result<()>,
    ) -> io::Result<()> {
        binding.validate_current(parent, slot)?;
        let uid = rustix::process::geteuid().as_raw();
        let p = directory(parent, uid)?;
        let f = fs::fstat(slot)?;
        let parent_repair = if matches!(binding.intent, DirectoryIntent::DeclaredPrivate)
            && p.st_mode & 0o077 != 0
        {
            // Search-only authority does not imply fchmod rights. Open only its
            // pinned dot entry, compare identity, and fail closed on denial.
            let fd = File::from(fs::openat(
                parent,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if !same(&p, &directory(&fd, uid)?) {
                return Err(refused("session parent changed before repair"));
            }
            Some(fd)
        } else {
            None
        };
        if f.st_mode & 0o077 != 0 {
            repair(slot, Mode::RUSR | Mode::WUSR)?;
        }
        if let Some(fd) = parent_repair {
            repair(&fd, Mode::RWXU)?;
        }
        binding.validate_private_current(parent, slot)
    }
}
impl SlotBinding {
    pub(crate) fn diagnostic_path(&self) -> PathBuf {
        self.route.join(&self.name)
    }

    fn validate_current(&self, parent: &File, slot: &File) -> io::Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        let current = resolve(&self.route, self.intent, false)?;
        if !same(&directory(&current, uid)?, &directory(parent, uid)?) {
            return Err(refused("configured session directory changed"));
        }
        let opened = fs::fstat(slot)?;
        leaf(&opened, uid)?;
        let named = fs::statat(&current, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        leaf(&named, uid)?;
        if !same(&opened, &named) {
            return Err(refused("configured session slot changed"));
        }
        Ok(())
    }
    // After initial preparation, observations can only authorize private I/O or
    // refuse it. Replacement never repairs/reopens/retargets the held claim.
    pub(crate) fn validate_private_current(&self, parent: &File, slot: &File) -> io::Result<()> {
        self.validate_current(parent, slot)?;
        if fs::fstat(slot)?.st_mode & 0o077 != 0 {
            return Err(refused("session slot is no longer private"));
        }
        if matches!(self.intent, DirectoryIntent::DeclaredPrivate)
            && fs::fstat(parent)?.st_mode & 0o077 != 0
        {
            return Err(refused("dedicated session directory is no longer private"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }
    fn mode(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }
    fn file(path: &Path) {
        std::fs::write(path, b"owned sentinel").unwrap();
        mode(path, 0o600);
    }
    // Self-exec provides a trusted owned cwd without changing libtest's global
    // cwd. The shared checkout itself may legitimately be group-writable.
    fn relative_child(directory: &Path) -> io::Result<std::process::ExitStatus> {
        struct OwnedChild {
            child: std::process::Child,
            terminal: bool,
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if self.terminal {
                    return;
                }
                if let Err(error) = self.child.kill() {
                    eprintln!("relative slot child termination failed; retaining custody: {error}");
                }
                let mut reported = false;
                loop {
                    match self.child.wait() {
                        Ok(_) => break,
                        Err(error) => {
                            if !reported {
                                eprintln!("relative slot child wait failed; retaining child/fixture and retrying: {error}");
                                reported = true;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                    }
                }
            }
        }
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "sessions_store::tests::slot139_traversal_preserves_aliases_and_raw_paths",
                "--nocapture",
            ])
            .env("QSH_TEST_SLOT139_RELATIVE", "1")
            .current_dir(directory)
            .stdout(std::process::Stdio::null())
            .spawn()?;
        let mut child = OwnedChild {
            child,
            terminal: false,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.child.try_wait()? {
                child.terminal = true;
                return Ok(status);
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relative slot child did not finish",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[test]
    fn slot139_traversal_preserves_aliases_and_raw_paths() {
        if std::env::var_os("QSH_TEST_SLOT139_RELATIVE").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            assert!(Store::open(Path::new("store"), DirectoryIntent::Generic).is_ok());
            return;
        }
        let d = fixture();
        let directory = d.path().join("store");
        std::fs::create_dir(&directory).unwrap();
        mode(&directory, 0o700);
        symlink("store", d.path().join("alias")).unwrap();
        symlink(d.path(), d.path().join("parent")).unwrap();
        for p in [
            directory.clone(),
            d.path().join("alias"),
            d.path().join("parent/store"),
        ] {
            let s = Store::open(&p, DirectoryIntent::Generic).unwrap();
            assert!(s.open_candidate("slot").is_ok());
        }
        assert!(relative_child(d.path()).unwrap().success());
        let search = d.path().join("search");
        std::fs::create_dir(&search).unwrap();
        let nested = search.join("nested");
        std::fs::create_dir(&nested).unwrap();
        mode(&nested, 0o700);
        mode(&search, 0o111);
        let result = Store::open(&nested, DirectoryIntent::Generic);
        mode(&search, 0o700);
        assert!(result.is_ok());
        mode(&search, 0o1777);
        assert!(Store::open(&nested, DirectoryIntent::Generic).is_ok());
        mode(&search, 0o700);
        let raw = OsString::from_vec(b"raw-\xff".to_vec());
        assert_eq!(parts(raw.as_bytes()), VecDeque::from([raw.clone()]));
        let path = d.path().join(raw);
        match std::fs::create_dir(&path) {
            Ok(()) => {
                mode(&path, 0o700);
                assert!(Store::open(&path, DirectoryIntent::Generic).is_ok());
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EILSEQ));
                // Store::open creates missing directories, so compare its refusal
                // with the same creation operation, not a metadata lookup.
                let actual = Store::open(&path, DirectoryIntent::Generic)
                    .err()
                    .expect("same raw path refused");
                assert_eq!(actual.kind(), e.kind());
                assert!(actual.to_string().contains("os error"));
            }
        }
    }
    #[test]
    fn slot139_nonregular_owner_and_alias_bounds_are_checked() {
        let d = fixture();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir(base.join("directory")).unwrap();
        mode(&base.join("directory"), 0o700);
        for i in 0..41 {
            symlink(
                if i == 0 {
                    "directory".into()
                } else {
                    format!("alias{}", i - 1)
                },
                base.join(format!("alias{i}")),
            )
            .unwrap();
        }
        assert!(Store::open(&base.join("alias39"), DirectoryIntent::Generic).is_ok());
        assert!(Store::open(&base.join("alias40"), DirectoryIntent::Generic).is_err());
        symlink("loop", base.join("loop")).unwrap();
        assert!(Store::open(&base.join("loop"), DirectoryIntent::Generic).is_err());
        assert!(alias_length(4096).is_ok());
        assert!(alias_length(4097).is_err());
        assert!(trusted_directory(0, 0o755, 123));
        assert!(trusted_directory(123, 0o1777, 123));
        assert!(!trusted_directory(124, 0o755, 123));
        assert!(!trusted_directory(123, 0o775, 123));
        assert!(trusted_leaf(123, 1, 123));
        assert!(!trusted_leaf(0, 1, 123));
        assert!(!trusted_leaf(123, 2, 123));
        let store = Store::open(&base.join("directory"), DirectoryIntent::Generic).unwrap();
        let fifo = base.join("directory/fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(store.open_candidate("fifo").is_err());
        std::fs::create_dir(base.join("directory/child")).unwrap();
        assert!(store.open_candidate("child").is_err());
        assert!(Store::open(Path::new("/dev"), DirectoryIntent::Generic)
            .unwrap()
            .open_candidate("zero")
            .is_err());
        assert!(store.open_candidate("../outside").is_err());
    }
    #[test]
    fn slot139_substitution_and_failed_repairs_preserve_sentinels() {
        let d = fixture();
        let path = d.path().join("store");
        std::fs::create_dir(&path).unwrap();
        mode(&path, 0o755);
        let store = Store::open(&path, DirectoryIntent::DeclaredPrivate).unwrap();
        file(&path.join("slot"));
        mode(&path.join("slot"), 0o644);
        let opened = store.open_candidate("slot").unwrap();
        let (parent, binding) = store.binding("slot").unwrap();
        rustix::fs::flock(
            &opened,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        let mut calls = 0;
        assert!(store
            .prepare_locked_with(&parent, &opened, &binding, |_, _| {
                calls += 1;
                Err(io::Error::from_raw_os_error(libc::EIO))
            })
            .is_err());
        assert_eq!(calls, 1);
        assert_eq!(
            std::fs::metadata(path.join("slot"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        let outside = d.path().join("outside");
        file(&outside);
        std::fs::rename(path.join("slot"), path.join("old")).unwrap();
        symlink(&outside, path.join("slot")).unwrap();
        calls = 0;
        assert!(store
            .prepare_locked_with(&parent, &opened, &binding, |_, _| {
                calls += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(calls, 0);
        assert_eq!(std::fs::read(&outside).unwrap(), b"owned sentinel");
        assert_eq!(
            std::fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::rename(&path, d.path().join("moved")).unwrap();
        std::fs::create_dir(&path).unwrap();
        mode(&path, 0o700);
        file(&path.join("slot"));
        assert!(binding.validate_private_current(&parent, &opened).is_err());
    }
}
