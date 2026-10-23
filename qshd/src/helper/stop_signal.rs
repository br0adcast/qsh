//! Private Linux service-stop notification; descriptors never certify cleanup.

use nix::libc;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

/// Value-only copy: child descriptor sweeps cannot leave a stale FD owner here.
#[derive(Clone, Copy)]
pub(super) struct ChildMask(libc::sigset_t);
impl ChildMask {
    pub(super) fn restore(self) -> io::Result<()> {
        // SAFETY: this complete set was initialized by successful sigprocmask.
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Prepared only immediately before the owned fork. Pre-child errors explicitly
/// call checked rollback; the parent retains its blocker through process exit.
/// There is deliberately no implicit mask restoration on descriptor Drop.
#[must_use = "retain through helper drain, explicitly roll back, or hand off to the child"]
pub(super) struct StopOwner {
    fd: OwnedFd,
    saved: ChildMask,
}
impl StopOwner {
    pub(super) fn prepare() -> io::Result<Self> {
        Self::prepare_with(|set| {
            // SAFETY: initialized set is live for the syscall; returned FD has one owner.
            let fd = unsafe { libc::signalfd(-1, set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        })
    }
    pub(super) fn prepare_with(
        create: impl FnOnce(&libc::sigset_t) -> io::Result<OwnedFd>,
    ) -> io::Result<Self> {
        let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: every pointer names a live initialized stack set.
        if unsafe { libc::sigemptyset(&mut set) } < 0
            || unsafe { libc::sigaddset(&mut set, libc::SIGTERM) } < 0
            || unsafe { libc::sigaddset(&mut set, libc::SIGINT) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &set, &mut previous) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = ChildMask(previous);
        match create(&set) {
            Ok(fd) => Ok(Self { fd, saved }),
            Err(error) => {
                saved.restore().map_err(|restore| {
                    io::Error::other(format!(
                        "stop descriptor preparation failed ({error}); original mask restoration failed ({restore})"
                    ))
                })?;
                Err(error)
            }
        }
    }
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub(super) fn child_mask(&self) -> ChildMask {
        self.saved
    }
    pub(super) fn into_child_mask_close_fd(self) -> ChildMask {
        let Self { fd, saved } = self;
        drop(fd); // before any child sweep or descriptor reuse
        saved
    }
    pub(super) fn rollback(self) -> io::Result<()> {
        self.saved.restore()
    }
    pub(super) fn receive_requested(&self) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut info = unsafe { std::mem::zeroed::<libc::signalfd_siginfo>() };
        let count = loop {
            let count = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    &mut info as *mut _ as *mut libc::c_void,
                    std::mem::size_of_val(&info),
                )
            };
            if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break count;
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            return match error.kind() {
                io::ErrorKind::WouldBlock => Ok(false),
                _ => Err(error),
            };
        }
        if count as usize != std::mem::size_of_val(&info)
            || ![libc::SIGTERM as u32, libc::SIGINT as u32].contains(&info.ssi_signo)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid stop signal record",
            ));
        }
        Ok(true)
    }
}
