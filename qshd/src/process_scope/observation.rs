//! Retained process observation, with no signalling or child ownership API.
use super::{
    validate_tgid, Evidence, Failure, Native, Operations, ProcOperations, QualifiedProc,
    RetainedProcess,
};

#[derive(Debug)]
pub(crate) enum Unavailable {
    InvalidPid,
    Open(Failure),
    Identity,
    Initial(Evidence),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPid => f.write_str("invalid PID"),
            Self::Identity => f.write_str("retained Pid/Tgid mismatch"),
            Self::Open(error) => write!(f, "retained proc open failed: {error:?}"),
            Self::Initial(evidence) => write!(f, "initial retained evidence was {evidence:?}"),
        }
    }
}

/// Deliberately has no Deref/conversion to RetainedProcess and no stop/reap API.
pub(crate) struct ObservedProcess {
    retained: RetainedProcess,
}
impl ObservedProcess {
    pub(crate) fn acquire(
        view: &QualifiedProc,
        pid: u32,
        ops: &mut impl ProcOperations,
    ) -> Result<Self, Unavailable> {
        if pid == 0 {
            return Err(Unavailable::InvalidPid);
        }
        let fd = ops
            .open_numeric(&view.root, pid)
            .map_err(Unavailable::Open)?;
        if !ops
            .status(&fd)
            .and_then(|bytes| validate_tgid(&bytes, pid))
            .unwrap_or(false)
        {
            return Err(Unavailable::Identity);
        }
        let mut retained = RetainedProcess { fd, exited: false };
        let initial = retained.observe(ops);
        if initial != Evidence::Pending {
            return Err(Unavailable::Initial(initial));
        }
        Ok(Self { retained })
    }
    pub(crate) fn acquire_native(pid: u32) -> Result<Self, String> {
        let view = super::qualify_native_proc()
            .map_err(|e| format!("process observation unavailable: {e:?}"))?;
        Self::acquire(&view, pid, &mut Native)
            .map_err(|e| format!("daemon observation unavailable: {e}"))
    }
    pub(crate) fn observe(&mut self, ops: &mut impl Operations) -> Evidence {
        self.retained.observe(ops)
    }
    pub(crate) fn observe_native(&mut self) -> Evidence {
        self.observe(&mut Native)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_scope::{Evidence, Failure, Operations, ProcOperations, QualifiedProc};
    use std::collections::VecDeque;
    use std::os::fd::OwnedFd;
    fn fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }
    fn running() -> Vec<u8> {
        b"42 (fixture) R 1 42 999 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 123\n".to_vec()
    }
    struct Ops {
        status: Vec<u8>,
        stats: VecDeque<Result<Vec<u8>, Failure>>,
        zero_signals: usize,
        opens: usize,
    }
    impl Operations for Ops {
        fn stat(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.stats.pop_front().unwrap()
        }
        fn status(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            Ok(self.status.clone())
        }
        fn signal(&mut self, _: &OwnedFd, signal: i32) -> Result<(), Failure> {
            assert_eq!(signal, 0);
            self.zero_signals += 1;
            Err(Failure::Errno(nix::libc::ESRCH))
        }
    }
    impl ProcOperations for Ops {
        fn open_self(&mut self, _: &OwnedFd) -> Result<OwnedFd, Failure> {
            unreachable!()
        }
        fn self_identity(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            unreachable!()
        }
        fn open_numeric(&mut self, _: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
            assert_eq!(pid, 42);
            self.opens += 1;
            Ok(fd())
        }
    }
    fn ops() -> Ops {
        Ops {
            status: b"Pid:\t42\nTgid:\t42\n".to_vec(),
            stats: VecDeque::from([Ok(running())]),
            zero_signals: 0,
            opens: 0,
        }
    }
    #[test]
    fn observation_does_not_require_pty_session_or_child_custody() {
        let view = QualifiedProc { root: fd() };
        let mut ops = ops();
        let observer = ObservedProcess::acquire(&view, 42, &mut ops).unwrap();
        assert_eq!(ops.opens, 1);
        drop(observer);
        assert_eq!(ops.zero_signals, 0);
    }
    #[test]
    fn malformed_target_and_initial_unknown_or_exited_are_unavailable() {
        let view = QualifiedProc { root: fd() };
        for status in [
            b"Pid:42\nTgid:43\n".to_vec(),
            b"Pid:42\nTgid:42".to_vec(),
            b"Pid:42\n".to_vec(),
        ] {
            let mut ops = ops();
            ops.status = status;
            assert!(ObservedProcess::acquire(&view, 42, &mut ops).is_err());
            assert_eq!(ops.zero_signals, 0);
        }
        for stat in [
            Err(Failure::Malformed),
            Ok(String::from_utf8(running())
                .unwrap()
                .replace(" R ", " Z ")
                .into_bytes()),
        ] {
            let mut ops = ops();
            ops.stats = VecDeque::from([stat]);
            assert!(ObservedProcess::acquire(&view, 42, &mut ops).is_err());
        }
        let mut ops = ops();
        assert!(ObservedProcess::acquire(&view, 0, &mut ops).is_err());
        assert_eq!(ops.opens, 0);
    }
    #[test]
    fn retained_observation_separates_unknown_from_positive_exit() {
        let view = QualifiedProc { root: fd() };
        let mut ops = ops();
        let mut observer = ObservedProcess::acquire(&view, 42, &mut ops).unwrap();
        ops.stats.push_back(Err(Failure::Malformed));
        assert_eq!(observer.observe(&mut ops), Evidence::Unknown);
        ops.stats.push_back(Err(Failure::Errno(nix::libc::ENOENT)));
        assert_eq!(observer.observe(&mut ops), Evidence::Exited);
        assert_eq!(ops.zero_signals, 1);
        assert_eq!(observer.observe(&mut ops), Evidence::Exited);
    }
    #[test]
    fn native_observer_retains_unrelated_process_in_another_session() {
        use std::os::unix::process::CommandExt;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        struct Owned(Option<Child>);
        impl Drop for Owned {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    if matches!(child.try_wait(), Ok(None)) {
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                }
            }
        }
        let home = tempfile::tempdir().unwrap();
        let mut target = Command::new("/bin/sleep");
        target
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            target.pre_exec(|| {
                if nix::libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut target = Owned(Some(target.spawn().unwrap()));
        let marker = home.path().join("observed");
        let mut helper = Command::new(std::env::current_exe().unwrap());
        helper
            .args([
                "--exact",
                "process_scope::observation::tests::native_observer_process",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "QSH_TEST_OBSERVED_PID",
                target.0.as_ref().unwrap().id().to_string(),
            )
            .env("QSH_TEST_OBSERVER_MARKER", &marker)
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("XDG_CACHE_HOME", home.path())
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            helper.pre_exec(|| {
                if nix::libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut helper = Owned(Some(helper.spawn().unwrap()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                helper.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "observer refused qualified owned sibling"
            );
            assert!(Instant::now() < deadline, "observer acquisition deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            target.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "dropping a prior observer cannot kill or reap the target"
        );
        let mut child = target.0.take().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        loop {
            if let Some(status) = helper.0.as_mut().unwrap().try_wait().unwrap() {
                helper.0.take();
                assert!(
                    status.success(),
                    "retained observation did not prove the exact exit"
                );
                break;
            }
            assert!(Instant::now() < deadline, "exact observer exit deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    #[ignore = "owned isolated observer process, invoked by native observer fixture"]
    fn native_observer_process() {
        use std::time::{Duration, Instant};
        let pid: u32 = std::env::var("QSH_TEST_OBSERVED_PID")
            .expect("owned observer role")
            .parse()
            .unwrap();
        assert_ne!(unsafe { nix::libc::getsid(pid as i32) }, unsafe {
            nix::libc::getsid(0)
        });
        drop(ObservedProcess::acquire_native(pid).unwrap());
        let mut observer = ObservedProcess::acquire_native(pid).unwrap();
        std::fs::write(
            std::env::var_os("QSH_TEST_OBSERVER_MARKER").unwrap(),
            b"ready",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match observer.observe_native() {
                Evidence::Exited => break,
                Evidence::Pending => {}
                Evidence::Unknown => panic!("qualified retained exit became unknown"),
            }
            assert!(Instant::now() < deadline, "exit witness deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
