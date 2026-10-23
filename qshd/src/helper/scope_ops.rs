//! Bounded diagnostic projection for exact native monitor operations.

use crate::process_scope::{scope::ScopeOperations, Failure, Native, Operations, ProcOperations};
use nix::libc;
use std::os::fd::OwnedFd;

pub(super) struct MonitorOps {
    signal: fn(&OwnedFd, i32) -> Result<(), Failure>,
    first_failure: Option<(i32, i32)>,
}
impl MonitorOps {
    pub(super) fn new() -> Self {
        Self {
            signal: |fd, signal| Native.signal(fd, signal),
            first_failure: None,
        }
    }
    pub(super) fn take_failure(&mut self) -> Option<(i32, i32)> {
        self.first_failure.take()
    }
}
impl Operations for MonitorOps {
    fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        Native.stat(fd)
    }
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        Native.status(fd)
    }
    fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        let result = (self.signal)(fd, signal);
        if signal != 0 {
            match result {
                Err(Failure::Errno(errno)) if errno != libc::ESRCH => {
                    self.first_failure.get_or_insert((signal, errno));
                }
                Err(Failure::Malformed) => {
                    self.first_failure.get_or_insert((signal, libc::EIO));
                }
                _ => {}
            }
        }
        // Diagnostics never turn an error into successful signalling/cleanup.
        result
    }
}
impl ProcOperations for MonitorOps {
    fn open_self(&mut self, root: &OwnedFd) -> Result<OwnedFd, Failure> {
        Native.open_self(root)
    }
    fn self_identity(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        Native.self_identity(fd)
    }
    fn open_numeric(&mut self, root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
        Native.open_numeric(root, pid)
    }
}
impl ScopeOperations for MonitorOps {
    fn census(
        &mut self,
        root: &OwnedFd,
        visit: &mut dyn FnMut(&mut Self, u32),
    ) -> Result<(), Failure> {
        // Native is stateless; the visitor's operations retain this diagnostic
        // projection while the fresh native directory iterator stays owned.
        Native.census(root, &mut |_, pid| visit(self, pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_real_signal_error_is_bounded_and_preserves_the_error() {
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        let mut ops = MonitorOps {
            signal: |_, _| Err(Failure::Errno(libc::EPERM)),
            first_failure: None,
        };
        assert!(matches!(
            ops.signal(&fd, 0),
            Err(Failure::Errno(libc::EPERM))
        ));
        assert_eq!(ops.take_failure(), None);
        assert!(matches!(
            ops.signal(&fd, libc::SIGHUP),
            Err(Failure::Errno(libc::EPERM))
        ));
        assert!(matches!(
            ops.signal(&fd, libc::SIGKILL),
            Err(Failure::Errno(libc::EPERM))
        ));
        assert_eq!(ops.take_failure(), Some((libc::SIGHUP, libc::EPERM)));
        assert_eq!(ops.take_failure(), None);
        ops.signal = |_, _| Err(Failure::Errno(libc::ESRCH));
        assert!(matches!(
            ops.signal(&fd, libc::SIGKILL),
            Err(Failure::Errno(libc::ESRCH))
        ));
        assert_eq!(ops.take_failure(), None);
    }
}
