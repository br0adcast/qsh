//! Retained filesystem and socket authority shared by local endpoints.

pub(crate) mod path;

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

/// Owns the exact acquired flock description until its final descriptor closes.
pub(crate) struct EndpointLock {
    authority: path::EndpointAuthority,
    _file: std::fs::File,
}

impl EndpointLock {
    /// Attempt immediately, even for a zero budget, then bound contention by
    /// `patience`. This does not bound filesystem operations or the transaction
    /// performed after acquisition. A timeout never removes or unlocks the file.
    pub(crate) fn acquire_prepared(
        authority: path::EndpointAuthority,
        patience: Duration,
        opened: impl FnOnce(),
    ) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        authority.validate_route()?;
        authority.entry()?;
        let file = authority.open_lock()?;
        let metadata = file.metadata()?;
        let identity = nix::sys::stat::fstat(&file)?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the ensure lock must be a private, singly linked regular file owned by this user",
            ));
        }
        opened();
        let deadline = std::time::Instant::now()
            .checked_add(patience)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ensure lock wait budget is too large",
                )
            })?;
        let mut attempted = false;
        loop {
            // There is one immediate attempt, including with zero patience.
            // Neither contention nor EINTR grants another attempt after expiry.
            if attempted && std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out after {patience:?} waiting for another transport ensure transaction"),
                ));
            }
            attempted = true;
            // SAFETY: the descriptor remains owned by file throughout the call.
            if unsafe {
                nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB)
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => std::thread::sleep(
                    Duration::from_millis(25)
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                ),
                _ => return Err(error),
            }
        }
        authority.validate_route()?;
        let current = nix::sys::stat::fstatat(
            &authority.parent,
            authority.lock.as_os_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if !path::same(&current, &identity) {
            return Err(path::refused("the ensure lock changed while waiting"));
        }
        Ok(Self {
            authority,
            _file: file,
        })
    }

    pub(crate) fn authority(&self) -> &path::EndpointAuthority {
        &self.authority
    }

    pub(crate) fn validate_route(&self) -> std::io::Result<()> {
        self.authority.validate_route()
    }

    #[cfg(test)]
    pub(crate) fn file_for_test(&self) -> &std::fs::File {
        &self._file
    }
}

/// Owns removal of one published socket, including startup errors. Keeping a
/// listener reference until removal prevents another ensure from observing a
/// refused endpoint between the serving future's drop and this cleanup.
/// The duplicate is close-on-exec; only the original listener crosses update
/// handover, whose resumed owner creates its own guard before serving.
pub struct SocketCleanup {
    parent: std::fs::File,
    leaf: std::ffi::OsString,
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    remove_on_drop: bool,
    _listener: UnixListener,
}

impl SocketCleanup {
    #[cfg(test)]
    pub(crate) fn listener_for_test(&self) -> &UnixListener {
        &self._listener
    }

    /// A daemonization parent cannot infer child death from a wait error.
    /// Leave publication to the child's inherited guard (or stale recovery).
    pub fn leave_to_child(&mut self) {
        self.remove_on_drop = false;
    }

    /// The caller must know that this path names this listener: an owned
    /// private staging path, or a cooperatively inherited update listener.
    /// A live inherited listener prevents another ensure from replacing it;
    /// arbitrary external same-UID pathname mutation is outside this contract.
    pub fn capture(listener: &UnixListener, path: &Path) -> std::io::Result<Self> {
        let authority = path::EndpointAuthority::open(path, false)?;
        authority.validate_route()?;
        let metadata = authority.entry()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the control publication is missing",
            )
        })?;
        if metadata.st_mode & 0o7777 != 0o600 {
            return Err(path::refused(
                "the inherited control publication must be private",
            ));
        }
        Self::from_authority(listener, &authority, &metadata)
    }

    fn from_authority(
        listener: &UnixListener,
        authority: &path::EndpointAuthority,
        metadata: &nix::libc::stat,
    ) -> std::io::Result<Self> {
        let parent = authority.parent.try_clone()?;
        Ok(Self {
            parent,
            leaf: authority.leaf.clone(),
            device: metadata.st_dev,
            inode: metadata.st_ino,
            remove_on_drop: true,
            _listener: listener.try_clone()?,
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if !self.remove_on_drop {
            return;
        }
        use nix::fcntl::AtFlags;
        use nix::sys::stat::{fstatat, SFlag};
        if let Ok(current) = fstatat(
            &self.parent,
            self.leaf.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            if current.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFSOCK.bits()
                && current.st_dev == self.device
                && current.st_ino == self.inode
            {
                let _ = nix::unistd::unlinkat(
                    &self.parent,
                    self.leaf.as_os_str(),
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                );
            }
        }
    }
}

/// Name of the staged socket inside the staging directory. One byte, kept
/// short for the same reason the directory name is (see [`crate::control::bind_private`]'s
/// doc, Minor 1 of the task 6 review): a long staging path could refuse to
/// bind at a length a plain bind at the final name would have accepted.
pub(crate) const STAGED_NAME: &str = "s";

pub(crate) fn bind_with_authority(
    authority: &path::EndpointAuthority,
) -> std::io::Result<(UnixListener, SocketCleanup)> {
    bind_prepared(authority, |_| {})
}

pub(crate) fn bind_prepared(
    authority: &path::EndpointAuthority,
    configure: impl FnOnce(&mut path::Stage),
) -> std::io::Result<(UnixListener, SocketCleanup)> {
    bind_prepared_mode(authority, configure, true)
}
pub(crate) fn bind_prepared_mode(
    authority: &path::EndpointAuthority,
    configure: impl FnOnce(&mut path::Stage),
    replace: bool,
) -> std::io::Result<(UnixListener, SocketCleanup)> {
    authority.validate_route()?;
    authority.entry()?;
    sweep_stale_staging_at(&authority.parent, std::time::SystemTime::now());
    let mut stage = path::Stage::create(authority)?;
    configure(&mut stage);
    let listener = stage.bind(authority)?;
    // Allocate every cleanup descriptor before publication. On a later error,
    // this guard owns only this socket in this pinned parent, never a new route.
    let cleanup = SocketCleanup::from_authority(&listener, authority, stage.socket())?;
    if replace {
        stage.publish(authority)?;
    } else {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        stage.publish_absent(authority)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no-replace restart publication is unavailable",
        ));
    }
    Ok((listener, cleanup))
}

/// Minimum staging age for conservative crash recovery. Age is a heuristic;
/// the separate PID check also preserves every process visible to this caller.
/// Neither check proves that an inaccessible PID namespace has no live owner.
pub(crate) const STALE_STAGING_AFTER: Duration = Duration::from_secs(60);

/// The pid in a staging directory's name, if the name is exactly what
/// [`crate::control::bind_private`] writes: `.c` and a positive pid in decimal, no leading
/// zero, nothing after it.
fn staging_pid(name: &str) -> Option<i32> {
    let digits = name.strip_prefix(".c")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i32>().ok().filter(|&pid| pid > 0)
}

/// Whether a process with this pid exists (a zombie counts), as far as
/// this process can tell: only `ESRCH` says it does not.
fn process_exists(pid: i32) -> bool {
    !matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

/// Remove the staging directories that daemons of this user left in
/// `parent` when they died between [`crate::control::bind_private`]'s `mkdir` and its
/// cleanup (final review of slice 5, M4): only the next run with the same
/// pid would otherwise remove one. Best effort, and conservative: a
/// directory is removed only if every one of these holds --
///
/// - its name is `.c<pid>` exactly (see [`staging_pid`]);
/// - it is a directory, not a symlink to one: it is opened with
///   `O_NOFOLLOW`, and what that descriptor shows is what gets emptied;
/// - it belongs to this process's effective uid and its mode is `0700`, as
///   `bind_private` makes it;
/// - it has gone unchanged for [`STALE_STAGING_AFTER`] as of `now`;
/// - no process with its pid exists (a pid in use by anyone is left alone,
///   whatever that process is);
/// - it is empty, or holds only the staged socket (`s`, a socket, this
///   uid's) -- which is dead then: its pid is gone.
///
/// The socket is unlinked through the directory's descriptor, the
/// directory by name with `AT_REMOVEDIR`, which removes only an empty
/// directory and never follows a symlink. Anything else in `parent` is
/// never touched. Returns how many directories were removed.
#[cfg(test)]
pub(crate) fn sweep_stale_staging(parent: &Path, now: std::time::SystemTime) -> usize {
    let Ok(authority) = path::EndpointAuthority::open(&parent.join("control.sock"), false) else {
        return 0;
    };
    sweep_stale_staging_at(&authority.parent, now)
}

fn sweep_stale_staging_at(parent: &std::fs::File, now: std::time::SystemTime) -> usize {
    use nix::dir::Dir;
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    let Ok(mut entries) = Dir::openat(
        parent,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.iter().flatten() {
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        let Some(pid) = staging_pid(name) else {
            continue;
        };
        if remove_if_stale(parent, name, pid, now) {
            removed += 1;
        }
    }
    removed
}

/// One directory of [`sweep_stale_staging`]: whether it was removed.
fn remove_if_stale(
    parent: &std::fs::File,
    name: &str,
    pid: i32,
    now: std::time::SystemTime,
) -> bool {
    remove_if_stale_prepared(parent, name, pid, now, || {})
}

pub(crate) fn remove_if_stale_prepared(
    parent: &std::fs::File,
    name: &str,
    pid: i32,
    now: std::time::SystemTime,
    before_remove: impl FnOnce(),
) -> bool {
    use nix::dir::Dir;
    use nix::fcntl::{AtFlags, OFlag};
    use nix::sys::stat::{fstat, fstatat, Mode, SFlag};
    use nix::unistd::{geteuid, unlinkat, UnlinkatFlags};
    use std::os::fd::{AsRawFd, BorrowedFd};

    let Ok(mut dir) = Dir::openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    // SAFETY: dir retains sole ownership throughout iteration and all calls below;
    // readdir/rewinddir mutate its cursor without closing its descriptor.
    let fd = unsafe { BorrowedFd::borrow_raw(dir.as_raw_fd()) };
    let uid = geteuid().as_raw();
    let Ok(st) = fstat(fd) else {
        return false;
    };
    if st.st_uid != uid || st.st_mode & 0o7777 != 0o700 {
        return false;
    }
    let (Ok(secs), Ok(nanos)) = (u64::try_from(st.st_mtime), u32::try_from(st.st_mtime_nsec))
    else {
        return false;
    };
    let changed = std::time::UNIX_EPOCH + Duration::new(secs, nanos);
    if now
        .duration_since(changed)
        .map_or(true, |age| age < STALE_STAGING_AFTER)
    {
        return false;
    }
    if process_exists(pid) {
        return false;
    }
    let mut socket = false;
    for entry in dir.iter() {
        let Ok(entry) = entry else {
            return false;
        };
        let entry_name = entry.file_name().to_bytes();
        if entry_name == b"." || entry_name == b".." {
            continue;
        }
        if entry_name != STAGED_NAME.as_bytes() {
            return false;
        }
        let Ok(staged) = fstatat(fd, STAGED_NAME, AtFlags::AT_SYMLINK_NOFOLLOW) else {
            return false;
        };
        let kind = SFlag::from_bits_truncate(staged.st_mode) & SFlag::S_IFMT;
        if kind != SFlag::S_IFSOCK || staged.st_uid != uid {
            return false;
        }
        socket = true;
    }
    if socket && unlinkat(fd, STAGED_NAME, UnlinkatFlags::NoRemoveDir).is_err() {
        return false;
    }
    before_remove();
    let Ok(current) = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) else {
        return false;
    };
    if !path::same(&current, &st) {
        return false;
    }
    unlinkat(parent, name, UnlinkatFlags::RemoveDir).is_ok()
}
