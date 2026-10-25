use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::fcntl::{self, AtFlags, OFlag};
use nix::sys::stat::{self, Mode, SFlag};

pub(super) fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(super) struct EndpointAuthority {
    pub parent: File,
    pub leaf: OsString,
    pub route: PathBuf,
    pub syscall_path: PathBuf,
    cwd: Option<File>,
    pub lock: OsString,
}

impl EndpointAuthority {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        let current_dir = if path.is_absolute() {
            None
        } else {
            Some(std::env::current_dir()?)
        };
        let route = current_dir
            .as_ref()
            .map_or_else(|| path.to_owned(), |cwd| cwd.join(path));
        // The traversal opens only the parent, never this marker leaf. Retain
        // search-only access instead of requiring read permission on cwd.
        let cwd = current_dir
            .as_ref()
            .map(|cwd| {
                crate::host_key::trusted_parent(&cwd.join(".qsh-control-cwd"), false)
                    .map(|(directory, _)| directory)
            })
            .transpose()?;
        let (parent, leaf) = crate::host_key::trusted_parent(&route, create)?;
        let mut lock = leaf.clone();
        lock.push(".lock");
        let authority = Self {
            parent,
            leaf,
            route,
            syscall_path: path.to_owned(),
            cwd,
            lock,
        };
        authority.validate_route()?;
        Ok(authority)
    }

    pub fn validate_route(&self) -> io::Result<()> {
        if let Some(captured) = &self.cwd {
            let (current, _) =
                crate::host_key::trusted_parent(Path::new(".qsh-control-cwd"), false)?;
            let old = captured.metadata()?;
            let new = current.metadata()?;
            if old.dev() != new.dev() || old.ino() != new.ino() {
                return Err(refused("the control endpoint working directory changed"));
            }
        }
        let (current, _) = crate::host_key::trusted_parent(&self.route, false)?;
        let old = self.parent.metadata()?;
        let new = current.metadata()?;
        if old.dev() != new.dev() || old.ino() != new.ino() {
            return Err(refused("the control endpoint parent changed"));
        }
        Ok(())
    }

    pub fn entry(&self) -> io::Result<Option<nix::libc::stat>> {
        match stat::fstatat(
            Some(self.parent.as_raw_fd()),
            self.leaf.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            Ok(st) => {
                if st.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFSOCK.bits()
                    || st.st_uid != nix::unistd::geteuid().as_raw()
                {
                    return Err(refused(
                        "the control endpoint must be a socket owned by this account",
                    ));
                }
                Ok(Some(st))
            }
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn open_lock(&self) -> io::Result<File> {
        let fd = fcntl::openat(
            Some(self.parent.as_raw_fd()),
            self.lock.as_os_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?;
        // SAFETY: openat returned a newly owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(super) fn same(a: &nix::libc::stat, b: &nix::libc::stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

pub(super) struct Stage {
    parent: File,
    pub directory: File,
    name: OsString,
    identity: nix::libc::stat,
    socket: Option<nix::libc::stat>,
    #[cfg(test)]
    pub before_chmod: Option<Box<dyn FnOnce()>>,
    #[cfg(test)]
    pub after_publish: Option<Box<dyn FnOnce()>>,
}

impl Stage {
    pub fn create(authority: &EndpointAuthority) -> io::Result<Self> {
        authority.validate_route()?;
        let parent = authority.parent.try_clone()?;
        let name = OsString::from(format!(".c{}", std::process::id()));
        stat::mkdirat(
            Some(authority.parent.as_raw_fd()),
            name.as_os_str(),
            Mode::S_IRWXU,
        )?;
        let fd = fcntl::openat(
            Some(authority.parent.as_raw_fd()),
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        // SAFETY: openat returned a new uniquely owned descriptor.
        let directory = unsafe { File::from_raw_fd(fd) };
        let identity = stat::fstat(directory.as_raw_fd())?;
        if identity.st_uid != nix::unistd::geteuid().as_raw() || identity.st_mode & 0o7777 != 0o700
        {
            return Err(refused(
                "the new control stage is not private and owned by this account",
            ));
        }
        let stage = Self {
            parent,
            directory,
            name,
            identity,
            socket: None,
            #[cfg(test)]
            before_chmod: None,
            #[cfg(test)]
            after_publish: None,
        };
        stage.validate(authority)?;
        Ok(stage)
    }

    pub fn validate(&self, authority: &EndpointAuthority) -> io::Result<()> {
        authority.validate_route()?;
        let current = stat::fstatat(
            Some(self.parent.as_raw_fd()),
            self.name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        let held = stat::fstat(self.directory.as_raw_fd())?;
        if !same(&current, &self.identity)
            || !same(&held, &self.identity)
            || held.st_uid != nix::unistd::geteuid().as_raw()
            || held.st_mode & 0o7777 != 0o700
        {
            return Err(refused("the private control stage changed"));
        }
        Ok(())
    }

    pub fn bind(
        &mut self,
        authority: &EndpointAuthority,
    ) -> io::Result<std::os::unix::net::UnixListener> {
        self.validate(authority)?;
        let parent = authority
            .syscall_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        // No portable bindat exists. Only trusted namespace owners can change
        // this checked private route between these checks and pathname bind.
        // Keep the original spelling: an absolute cwd may exceed sun_path even
        // when this supported relative syscall path fits. Cwd identity checks
        // detect observed changes; they do not make process-wide chdir atomic.
        let listener = std::os::unix::net::UnixListener::bind(
            parent.join(&self.name).join(super::STAGED_NAME),
        )?;
        let socket = stat::fstatat(
            Some(self.directory.as_raw_fd()),
            super::STAGED_NAME,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if socket.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFSOCK.bits()
            || socket.st_uid != nix::unistd::geteuid().as_raw()
        {
            return Err(refused("the bound control stage entry is not our socket"));
        }
        self.socket = Some(socket);
        #[cfg(test)]
        if let Some(before) = self.before_chmod.take() {
            before();
        }
        self.validate(authority)?;
        // Explicit flags0 preserves older GNU/musl support. Untrusted users
        // cannot replace this leaf inside the exclusive 0700 stage; this is not
        // atomic conditional chmod against a malicious same-account owner.
        stat::fchmodat(
            Some(self.directory.as_raw_fd()),
            super::STAGED_NAME,
            Mode::S_IRUSR | Mode::S_IWUSR,
            stat::FchmodatFlags::FollowSymlink,
        )?;
        let checked = stat::fstatat(
            Some(self.directory.as_raw_fd()),
            super::STAGED_NAME,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if !same(&socket, &checked) || checked.st_mode & 0o7777 != 0o600 {
            return Err(refused(
                "the bound control socket changed during permission setup",
            ));
        }
        self.validate(authority)?;
        Ok(listener)
    }

    pub fn socket(&self) -> &nix::libc::stat {
        self.socket.as_ref().expect("bound before publication")
    }

    pub fn publish(&mut self, authority: &EndpointAuthority) -> io::Result<()> {
        self.validate(authority)?;
        authority.entry()?;
        let current = stat::fstatat(
            Some(self.directory.as_raw_fd()),
            super::STAGED_NAME,
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if !same(&current, self.socket())
            || current.st_uid != nix::unistd::geteuid().as_raw()
            || current.st_mode & 0o7777 != 0o600
        {
            return Err(refused("the staged control socket changed"));
        }
        fcntl::renameat(
            Some(self.directory.as_raw_fd()),
            super::STAGED_NAME,
            Some(authority.parent.as_raw_fd()),
            authority.leaf.as_os_str(),
        )?;
        self.socket = None;
        #[cfg(test)]
        if let Some(after) = self.after_publish.take() {
            after();
        }
        authority.validate_route()?;
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if let Some(owned) = &self.socket {
            if let Ok(current) = stat::fstatat(
                Some(self.directory.as_raw_fd()),
                super::STAGED_NAME,
                AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                if same(&current, owned) {
                    let _ = nix::unistd::unlinkat(
                        Some(self.directory.as_raw_fd()),
                        super::STAGED_NAME,
                        nix::unistd::UnlinkatFlags::NoRemoveDir,
                    );
                }
            }
        }
        if let Ok(current) = stat::fstatat(
            Some(self.parent.as_raw_fd()),
            self.name.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            if same(&current, &self.identity) {
                let _ = nix::unistd::unlinkat(
                    Some(self.parent.as_raw_fd()),
                    self.name.as_os_str(),
                    nix::unistd::UnlinkatFlags::RemoveDir,
                );
            }
        }
    }
}
