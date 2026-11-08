//! Exit-only custody. No signal token, PTY membership or child/reap API.
use super::{Class, Classified, ExitEvent, Failure, Identity, Registration};
pub(super) struct QualifiedObservation {
    pub(super) contract: &'static str,
}
pub(super) trait ObservationOps {
    type Watch;
    fn classify(&mut self, pid: i32) -> Result<Classified, Failure>;
    fn bind(
        &mut self,
        process: Classified,
        cookie: u64,
    ) -> Result<Registration<Self::Watch>, Failure>;
    fn identity(&mut self, pid: i32) -> Result<Identity, Failure>;
    fn event(&mut self, watch: &mut Self::Watch) -> Result<Option<ExitEvent>, Failure>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Evidence {
    Pending,
    Exited,
    Unknown,
}
pub(super) struct Observed<W> {
    identity: Identity,
    cookie: u64,
    watch: W,
    evidence: Evidence,
}
impl<W> Observed<W> {
    pub(super) fn acquire(
        qualified: &QualifiedObservation,
        pid: i32,
        cookie: u64,
        ops: &mut impl ObservationOps<Watch = W>,
    ) -> Result<Self, Failure> {
        if qualified.contract.is_empty() || pid <= 0 || cookie == 0 {
            return Err(Failure::Invalid);
        }
        let process = ops.classify(pid)?;
        if process.identity.pid != pid
            || !process.identity.valid()
            || !matches!(process.class,Class::Session(sid) if sid>0)
        {
            return Err(Failure::Invalid);
        }
        let registration = ops.bind(process, cookie)?;
        if registration.identity != process.identity
            || registration.cookie != cookie
            || ops.identity(pid)? != process.identity
        {
            return Err(Failure::LostBinding);
        }
        Ok(Self {
            identity: process.identity,
            cookie,
            watch: registration.handle,
            evidence: Evidence::Pending,
        })
    }
    pub(super) fn observe(&mut self, ops: &mut impl ObservationOps<Watch = W>) -> Evidence {
        if self.evidence != Evidence::Pending {
            return self.evidence;
        }
        self.evidence = match ops.event(&mut self.watch) {
            Ok(Some(event))
                if event.pid == self.identity.pid
                    && event.cookie == self.cookie
                    && event.process_filter
                    && event.note_exit
                    && !event.error =>
            {
                Evidence::Exited
            }
            Ok(None) if ops.identity(self.identity.pid) == Ok(self.identity) => Evidence::Pending,
            _ => Evidence::Unknown,
        };
        self.evidence
    }
}
#[cfg(target_os = "macos")]
pub(crate) struct NativeObserved {
    value: Observed<super::native::Watch>,
    ops: super::native::NativeOps,
}
#[cfg(target_os = "macos")]
impl NativeObserved {
    pub(crate) fn acquire(pid: u32) -> Result<Self, super::native::AdmissionError> {
        use rand_core::RngCore;
        let qualified = super::native::prepare_observation()?;
        let pid = i32::try_from(pid)
            .map_err(|_| super::native::AdmissionError::Native(Failure::Invalid))?;
        let mut bytes = [0; 8];
        rand_core::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| super::native::AdmissionError::Native(Failure::Invalid))?;
        let mut ops = super::native::NativeOps;
        let value = Observed::acquire(&qualified, pid, u64::from_ne_bytes(bytes), &mut ops)
            .map_err(super::native::AdmissionError::Native)?;
        Ok(Self { value, ops })
    }
    pub(crate) fn observe(&mut self) -> Evidence {
        self.value.observe(&mut self.ops)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        identity: Identity,
        bound: Identity,
        after: Identity,
        event: Option<ExitEvent>,
        denied: bool,
    }
    impl Fake {
        fn new() -> Self {
            let identity = Identity {
                pid: 42,
                unique: 7,
                version: 1,
            };
            Self {
                identity,
                bound: identity,
                after: identity,
                event: None,
                denied: false,
            }
        }
    }
    impl ObservationOps for Fake {
        type Watch = ();
        fn classify(&mut self, _: i32) -> Result<Classified, Failure> {
            if self.denied {
                return Err(Failure::Errno(1));
            }
            Ok(Classified {
                identity: self.identity,
                class: Class::Session(999),
            })
        }
        fn bind(&mut self, _: Classified, cookie: u64) -> Result<Registration<()>, Failure> {
            Ok(Registration {
                identity: self.bound,
                cookie,
                handle: (),
            })
        }
        fn identity(&mut self, _: i32) -> Result<Identity, Failure> {
            Ok(self.after)
        }
        fn event(&mut self, _: &mut ()) -> Result<Option<ExitEvent>, Failure> {
            Ok(self.event.take())
        }
    }
    fn qualification() -> QualifiedObservation {
        QualifiedObservation {
            contract: "reviewed-fixture",
        }
    }
    #[test]
    fn full_image_identity_must_survive_bind_and_recheck() {
        for field in 0..6 {
            let mut ops = Fake::new();
            match field {
                0 => ops.bound.version += 1,
                1 => ops.bound.unique += 1,
                2 => ops.bound.pid += 1,
                3 => ops.after.version += 1,
                4 => ops.after.unique += 1,
                _ => ops.after.pid += 1,
            }
            assert!(Observed::acquire(&qualification(), 42, 3, &mut ops).is_err());
        }
        let mut ops = Fake::new();
        ops.denied = true;
        assert!(Observed::acquire(&qualification(), 42, 3, &mut ops).is_err());
        assert!(Observed::acquire(
            &QualifiedObservation { contract: "" },
            42,
            3,
            &mut Fake::new()
        )
        .is_err());
    }
    #[test]
    fn only_exact_cookie_bound_exit_event_is_positive_exit() {
        for bad in 0..5 {
            let mut ops = Fake::new();
            let mut observed = Observed::acquire(&qualification(), 42, 3, &mut ops).unwrap();
            let mut event = ExitEvent {
                pid: 42,
                cookie: 3,
                process_filter: true,
                note_exit: true,
                error: false,
            };
            match bad {
                0 => event.pid += 1,
                1 => event.cookie += 1,
                2 => event.process_filter = false,
                3 => event.note_exit = false,
                _ => event.error = true,
            }
            ops.event = Some(event);
            assert_eq!(observed.observe(&mut ops), Evidence::Unknown);
        }
        let mut ops = Fake::new();
        let mut observed = Observed::acquire(&qualification(), 42, 3, &mut ops).unwrap();
        assert_eq!(observed.observe(&mut ops), Evidence::Pending);
        ops.after.version += 1;
        assert_eq!(observed.observe(&mut ops), Evidence::Unknown);
        // A lost image binding is sticky; a later event cannot repair it.
        ops.event = Some(ExitEvent {
            pid: 42,
            cookie: 3,
            process_filter: true,
            note_exit: true,
            error: false,
        });
        assert_eq!(observed.observe(&mut ops), Evidence::Unknown);
        let mut ops = Fake::new();
        let mut observed = Observed::acquire(&qualification(), 42, 3, &mut ops).unwrap();
        ops.event = Some(ExitEvent {
            pid: 42,
            cookie: 3,
            process_filter: true,
            note_exit: true,
            error: false,
        });
        assert_eq!(observed.observe(&mut ops), Evidence::Exited);
        assert_eq!(observed.observe(&mut ops), Evidence::Exited);
    }
    #[cfg(target_os = "macos")]
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
                "darwin_process_scope::observation::tests::native_observer_process",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "QSH_TEST_DARWIN_OBSERVED_PID",
                target.0.as_ref().unwrap().id().to_string(),
            )
            .env("QSH_TEST_DARWIN_OBSERVER_MARKER", &marker)
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
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "owned isolated observer process, invoked by native observer fixture"]
    fn native_observer_process() {
        use std::time::{Duration, Instant};
        let pid: u32 = std::env::var("QSH_TEST_DARWIN_OBSERVED_PID")
            .expect("owned observer role")
            .parse()
            .unwrap();
        assert_ne!(unsafe { nix::libc::getsid(pid as i32) }, unsafe {
            nix::libc::getsid(0)
        });
        drop(NativeObserved::acquire(pid).unwrap());
        let mut observer = NativeObserved::acquire(pid).unwrap();
        std::fs::write(
            std::env::var_os("QSH_TEST_DARWIN_OBSERVER_MARKER").unwrap(),
            b"ready",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match observer.observe() {
                Evidence::Exited => break,
                Evidence::Pending => {}
                Evidence::Unknown => panic!("qualified retained exit became unknown"),
            }
            assert!(Instant::now() < deadline, "exit witness deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
