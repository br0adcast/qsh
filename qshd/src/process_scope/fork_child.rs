//! Exclusive wait ownership of the direct child returned by fork.

use super::{scope::ChildCustody, Failure};
use nix::libc;
use std::num::NonZeroU32;

pub(crate) struct ForkChild {
    pid: NonZeroU32,
}
impl ForkChild {
    /// The successful fork parent constructs this before fallible setup.
    /// No other waiter may consume this child; automatic reaping is forbidden.
    pub(crate) fn new(pid: NonZeroU32) -> Self {
        Self { pid }
    }
    pub(crate) fn pid(&self) -> NonZeroU32 {
        self.pid
    }
    pub(crate) fn observe(&mut self) -> Result<Option<i32>, Failure> {
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid.get(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                let error = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if error == libc::EINTR {
                    continue;
                }
                return Err(Failure::Errno(error));
            }
            if unsafe { info.si_pid() } == 0 {
                return Ok(None);
            }
            if unsafe { info.si_pid() } as u32 != self.pid.get() {
                return Err(Failure::Malformed);
            }
            let status = unsafe { info.si_status() };
            return Ok(Some(if info.si_code == libc::CLD_EXITED {
                status
            } else {
                128 + status
            }));
        }
    }
    pub(crate) fn reap(&mut self) -> Result<i32, Failure> {
        loop {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(self.pid.get() as i32, &mut status, 0) };
            if rc < 0 {
                let error = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                if error == libc::EINTR {
                    continue;
                }
                return Err(Failure::Errno(error));
            }
            if rc as u32 != self.pid.get() {
                return Err(Failure::Malformed);
            }
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            return Err(Failure::Malformed);
        }
    }
}

impl ChildCustody for ForkChild {
    fn leader_id(&self) -> NonZeroU32 {
        self.pid()
    }
    fn observe(&mut self) -> Result<Option<i32>, crate::process_scope::Failure> {
        self.observe()
    }
    fn reap(&mut self) -> Result<i32, crate::process_scope::Failure> {
        self.reap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    struct OwnedChild {
        child: Child,
        reaped: bool,
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                Err(error) => panic!("fixture wait failed: {error}"),
                Ok(None) => {}
            }
            let _ = self.child.kill();
            loop {
                match self.child.wait() {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => {
                        result.unwrap();
                        break;
                    }
                }
            }
        }
    }
    #[test]
    fn actual_running_and_repeated_wnowait_preserve_exact_final_wait() {
        let mut fixture = OwnedChild {
            child: Command::new("/bin/sh")
                .args(["-c", "printf ready; read release; exit 7"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            reaped: false,
        };
        let mut owner = ForkChild::new(NonZeroU32::new(fixture.child.id()).unwrap());
        assert_eq!(owner.pid().get(), fixture.child.id());
        let mut ready = [0; 5];
        fixture
            .child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(owner.observe().unwrap(), None);
        drop(fixture.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(2);
        let code = loop {
            if let Some(code) = owner.observe().unwrap() {
                break code;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        };
        let second = owner.observe().unwrap();
        let result = owner.reap().unwrap();
        fixture.reaped = true;
        let after = owner.observe();
        drop(fixture); // no signalling after the actual final wait
        assert_eq!(&ready, b"ready");
        assert_eq!(code, 7);
        assert_eq!(second, Some(7));
        assert_eq!(result, 7);
        assert!(matches!(after, Err(Failure::Errno(libc::ECHILD))));
    }
}
