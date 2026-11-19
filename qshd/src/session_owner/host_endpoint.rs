//! Dormant private host listener; no production route constructs it.

use crate::endpoint::path::EndpointAuthority;
use crate::endpoint::{EndpointLock, SocketCleanup};
use std::io;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

pub(crate) struct HostEndpoint {
    // Cleanup retains its listener duplicate and finishes while the lock is held.
    _cleanup: SocketCleanup,
    listener: UnixListener,
    lock: EndpointLock,
}

impl HostEndpoint {
    pub(crate) fn publish(directory: &Path, patience: Duration) -> io::Result<Self> {
        let authority = EndpointAuthority::open_private(&directory.join("host-v1.sock"))?;
        let lock = EndpointLock::acquire(authority, patience)?;
        let (listener, cleanup) = lock.bind_private_absent_owned()?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            _cleanup: cleanup,
            listener,
            lock,
        })
    }

    pub(crate) fn refuse_unprovisioned(&self) -> io::Result<bool> {
        self.lock.validate_route()?;
        // These wrappers make one syscall and return EINTR without retrying.
        #[cfg(target_os = "linux")]
        let accepted =
            nix::sys::socket::accept4(&self.listener, nix::sys::socket::SockFlag::SOCK_CLOEXEC);
        #[cfg(not(target_os = "linux"))]
        let accepted = nix::sys::socket::accept(&self.listener);
        match accepted.map_err(io::Error::from) {
            Ok(fd) => {
                // Drop the newly owned descriptor once, without granting authority.
                drop(fd);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
}
