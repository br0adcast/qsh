//! Linux operations for a dedicated single-threaded owned helper only.
use super::*;
use crate::process_scope::{Native, ProcOperations, QualifiedProc};
use nix::libc;
use std::{
    ffi::{CStr, CString},
    os::fd::{AsRawFd, FromRawFd},
};

pub(crate) struct NativeOps {
    view: QualifiedProc,
    pid: u32,
    stage: &'static str,
}
impl NativeOps {
    /// Mutates only the dedicated owned helper's process attribute. Call before
    /// child creation, never on an application's/libtest's shared parent.
    pub(crate) fn prepare() -> Result<(Adoption, Self), String> {
        let view = crate::process_scope::prepare()?;
        let mut ops = Self {
            view,
            pid: std::process::id(),
            stage: "identity",
        };
        let proof = qualify(&mut ops)
            .map_err(|failure| format!("helper adoption {} unavailable: {failure:?}", ops.stage))?;
        Ok((Adoption::new(proof), ops))
    }
    fn role(&mut self) -> Result<(), Failure> {
        if std::process::id() != self.pid
            || unsafe { libc::syscall(libc::SYS_gettid) } != i64::from(self.pid)
        {
            return Err(Failure::Malformed);
        }
        if !self.get_subreaper()? {
            return Err(Failure::Malformed);
        }
        Ok(())
    }
    fn open(&self, name: &CStr, flags: i32) -> Result<OwnedFd, Failure> {
        let fd = unsafe {
            libc::openat(
                self.view.root.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(super::super::last_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
    fn children(&self) -> Result<std::fs::File, Failure> {
        let path = CString::new(format!("self/task/{}/children", self.pid)).unwrap();
        Ok(self.open(&path, libc::O_RDONLY)?.into())
    }
    fn empty_wait(&self) -> Result<Empty, Failure> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        if rc == 0 {
            return Ok(Empty::No);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ECHILD) => Ok(Empty::Yes),
            Some(libc::EINTR) => Ok(Empty::Yielded),
            _ => Err(super::super::last_error()),
        }
    }
}
impl QualificationOps for NativeOps {
    fn ids(&mut self) -> Result<(u32, u32), Failure> {
        self.stage = "single-thread identity";
        Ok((
            std::process::id(),
            u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
                .map_err(|_| Failure::Malformed)?,
        ))
    }
    fn single_thread(&mut self) -> Result<bool, Failure> {
        self.stage = "single-thread proc view";
        use std::os::fd::IntoRawFd;
        let raw = self
            .open(c"self/task", libc::O_RDONLY | libc::O_DIRECTORY)?
            .into_raw_fd();
        let ptr = unsafe { libc::fdopendir(raw) };
        if ptr.is_null() {
            let error = super::super::last_error();
            unsafe {
                libc::close(raw);
            }
            return Err(error);
        }
        struct Dir(*mut libc::DIR);
        impl Drop for Dir {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let dir = Dir(ptr);
        let mut found = false;
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(dir.0) };
            if entry.is_null() {
                return if unsafe { *libc::__errno_location() } == 0 {
                    Ok(found)
                } else {
                    Err(super::super::last_error())
                };
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if found || super::super::positive_number(name)? != u64::from(self.pid) {
                return Ok(false);
            }
            found = true;
        }
    }
    fn children_empty(&mut self) -> Result<bool, Failure> {
        self.stage = "proc children interface";
        let mut byte = [0];
        self.children()?
            .read(&mut byte)
            .map(|n| n == 0)
            .map_err(|e| Failure::Errno(e.raw_os_error().unwrap_or(libc::EIO)))
    }
    fn no_children(&mut self) -> Result<Empty, Failure> {
        self.stage = "exclusive all-child wait";
        self.empty_wait()
    }
    fn set_subreaper(&mut self) -> Result<(), Failure> {
        self.stage = "PR_SET_CHILD_SUBREAPER";
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            Err(super::super::last_error())
        } else {
            Ok(())
        }
    }
    fn get_subreaper(&mut self) -> Result<bool, Failure> {
        self.stage = "PR_GET_CHILD_SUBREAPER";
        let mut flag = 0;
        if unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut flag, 0, 0, 0) } < 0 {
            Err(super::super::last_error())
        } else {
            Ok(flag == 1)
        }
    }
}
impl Operations for NativeOps {
    fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        self.role()?;
        Native.stat(fd)
    }
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        self.role()?;
        Native.status(fd)
    }
    fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        self.role()?;
        Native.signal(fd, signal)
    }
}
impl AdoptionOps for NativeOps {
    fn census(&mut self) -> Result<Box<dyn Read>, Failure> {
        self.role()?;
        Ok(Box::new(self.children()?))
    }
    fn open_child(&mut self, pid: u32) -> Result<OwnedFd, Failure> {
        self.role()?;
        Native.open_numeric(&self.view.root, pid)
    }
    fn observe_child(&mut self, pid: u32) -> Result<Observation, Failure> {
        self.role()?;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        if rc < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                Ok(Observation::Yielded)
            } else {
                Err(super::super::last_error())
            };
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(Observation::Running);
        }
        if unsafe { info.si_pid() } as u32 != pid {
            return Err(Failure::Malformed);
        }
        let status = unsafe { info.si_status() };
        match info.si_code {
            libc::CLD_EXITED => Ok(Observation::Exited(status)),
            libc::CLD_KILLED | libc::CLD_DUMPED => Ok(Observation::Exited(128 + status)),
            _ => Err(Failure::Malformed),
        }
    }
    fn reap_child(&mut self, pid: u32) -> Result<Reaped, Failure> {
        self.role()?;
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG | libc::__WALL) };
        if rc == 0 {
            return Ok(Reaped::Yielded);
        }
        if rc < 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                Ok(Reaped::Yielded)
            } else {
                Err(super::super::last_error())
            };
        }
        if rc as u32 != pid {
            return Err(Failure::Malformed);
        }
        if libc::WIFEXITED(status) {
            Ok(Reaped::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Ok(Reaped::Exited(128 + libc::WTERMSIG(status)))
        } else {
            Err(Failure::Malformed)
        }
    }
    fn no_children(&mut self) -> Result<Empty, Failure> {
        self.role()?;
        if !self.single_thread()? {
            return Err(Failure::Malformed);
        }
        self.empty_wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adoption40_shared_test_thread_is_rejected_before_changing_process_attribute() {
        let mut before = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut before, 0, 0, 0) },
            0
        );
        assert_ne!(
            unsafe { libc::syscall(libc::SYS_gettid) },
            i64::from(std::process::id())
        );
        assert!(NativeOps::prepare().is_err());
        let mut after = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut after, 0, 0, 0) },
            0
        );
        assert_eq!(
            before, after,
            "the ordinary libtest parent must not become a subreaper"
        );
    }
}
