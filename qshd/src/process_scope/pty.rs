//! Portable-PTY custody over the Linux exact-instance scope.

use super::{scope, Failure, Native, QualifiedProc, Unavailable};
use nix::libc;
use portable_pty::Child;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use transport::channel_open::{CleanupAuthority, CleanupStatus};
use transport::channel_server::{ChannelWait, ChildStatus, LeaderStatus};

// A grace interval chooses signal escalation; elapsed time never proves exit.
const HUP_GRACE: Duration = Duration::from_secs(1);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn prepare() -> Result<QualifiedProc, String> {
    // Custody requires exclusive waiting for these direct children. A handler
    // may notify its runtime, but must not reap children owned by this scope.
    // Automatic reaping would release the leader PID before our final wait.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } < 0 {
        return Err(format!(
            "child wait disposition unavailable: {:?}",
            super::last_error()
        ));
    }
    if action.sa_sigaction == libc::SIG_IGN || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err("process ownership requires a non-auto-reaping SIGCHLD disposition".into());
    }
    super::qualify_native_proc().map_err(|error| match error {
        Unavailable::SelfOpen(error) => {
            format!("process ownership self lookup unavailable: {error:?}")
        }
        Unavailable::Identity(error) => {
            format!("process ownership identity unavailable: {error:?}")
        }
        Unavailable::Mismatch => "process ownership namespace does not match procfs".to_string(),
        Unavailable::Capability(error) => {
            format!("exact process signalling unavailable: {error:?}")
        }
    })
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> Result<T, Failure>) -> Result<T, Failure> {
    loop {
        match operation() {
            Err(Failure::Errno(libc::EINTR)) => continue,
            result => return result,
        }
    }
}

struct PtyChild {
    child: Box<dyn Child + Send + Sync>,
    pid: NonZeroU32,
}
impl scope::ChildCustody for PtyChild {
    fn leader_id(&self) -> NonZeroU32 {
        self.pid
    }
    fn observe(&mut self) -> Result<Option<i32>, Failure> {
        retry_interrupted(|| {
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
                return Err(super::last_error());
            }
            if unsafe { info.si_pid() } == 0 {
                return Ok(None);
            }
            let status = unsafe { info.si_status() };
            Ok(Some(if info.si_code == libc::CLD_EXITED {
                status
            } else {
                128 + status
            }))
        })
    }
    fn reap(&mut self) -> Result<i32, Failure> {
        retry_interrupted(|| {
            self.child
                .wait()
                .map(|status| status.exit_code() as i32)
                .map_err(|error| Failure::Errno(error.raw_os_error().unwrap_or(libc::EIO)))
        })
    }
}

struct NativeWait {
    scope: Option<scope::Scope<PtyChild>>,
    // A backend without an exact PID is retained as Unknown, never downgraded
    // to a numeric kill or treated as a refusal before child creation.
    _unproved_child: Option<Box<dyn Child + Send + Sync>>,
    stop_started: Option<Instant>,
}
pub(crate) fn own_child(
    child: Box<dyn Child + Send + Sync>,
    view: QualifiedProc,
) -> Box<dyn ChannelWait> {
    let pid = child
        .process_id()
        .filter(|pid| *pid <= i32::MAX as u32)
        .and_then(NonZeroU32::new);
    let (scope, unproved_child) = match pid {
        Some(pid) => (Some(scope::Scope::new(PtyChild { child, pid }, view)), None),
        None => (None, Some(child)),
    };
    Box::new(NativeWait {
        scope,
        _unproved_child: unproved_child,
        stop_started: None,
    })
}
impl NativeWait {
    fn start_grace(&mut self) {
        self.stop_started.get_or_insert_with(Instant::now);
    }
    fn progress(&mut self) -> ChildStatus {
        let Some(scope) = self.scope.as_mut() else {
            return ChildStatus::Unknown("the created child has no exact process identity".into());
        };
        if self
            .stop_started
            .is_some_and(|started| started.elapsed() >= HUP_GRACE)
        {
            scope.escalate();
        }
        match scope.step(&mut Native) {
            scope::Progress::Pending => ChildStatus::Running,
            scope::Progress::Unknown => {
                ChildStatus::Unknown("native process scope cleanup is unconfirmed".into())
            }
            scope::Progress::Complete(code) => ChildStatus::Reaped { code: Some(code) },
        }
    }
}
impl ChannelWait for NativeWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let status = match self.scope.as_mut() {
            Some(scope) => scope.poll_leader(),
            None => scope::LeaderStatus::Unknown,
        };
        Some(match status {
            scope::LeaderStatus::Running => LeaderStatus::Running,
            scope::LeaderStatus::Exited(code) => {
                self.start_grace();
                LeaderStatus::Exited { code: Some(code) }
            }
            scope::LeaderStatus::Unknown => {
                LeaderStatus::Unknown("native leader custody is unconfirmed".into())
            }
        })
    }
    fn poll_exit(&mut self) -> ChildStatus {
        // Legacy callers may begin at cleanup without a separate leader poll.
        if matches!(self.poll_leader_status(), Some(LeaderStatus::Unknown(_))) {
            return ChildStatus::Unknown("native leader custody is unconfirmed".into());
        }
        self.progress()
    }
    fn kill(&mut self) {
        if let Some(scope) = self.scope.as_mut() {
            scope.request_stop();
            self.start_grace();
        }
    }
    fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
        self.kill();
        loop {
            match self.poll_exit() {
                ChildStatus::Reaped { .. } => return authority.reaped(),
                ChildStatus::Unknown(_) => return CleanupStatus::Unknown,
                ChildStatus::Running | ChildStatus::WaitingForWorkers => {
                    std::thread::sleep(OBSERVE_INTERVAL)
                }
            }
        }
    }
    fn wait(mut self: Box<Self>) -> i32 {
        loop {
            if let ChildStatus::Reaped { code: Some(code) } = self.poll_exit() {
                return code;
            }
            std::thread::sleep(OBSERVE_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scope::ChildCustody;
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    #[derive(Debug, Clone)]
    struct ControlledChild {
        pid: Option<u32>,
        waits: Arc<AtomicUsize>,
        kills: Arc<AtomicUsize>,
    }
    impl portable_pty::ChildKiller for ControlledChild {
        fn kill(&mut self) -> std::io::Result<()> {
            self.kills.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(self.clone())
        }
    }
    impl portable_pty::Child for ControlledChild {
        fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
            panic!("must use non-reaping observation")
        }
        fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
            if self.waits.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(std::io::Error::from_raw_os_error(libc::EINTR))
            } else {
                Ok(portable_pty::ExitStatus::with_exit_code(7))
            }
        }
        fn process_id(&self) -> Option<u32> {
            self.pid
        }
    }
    #[test]
    fn interrupt39_pty_final_wait_retries_before_custody_is_revoked() {
        let waits = Arc::new(AtomicUsize::new(0));
        let child = ControlledChild {
            pid: Some(42),
            waits: waits.clone(),
            kills: Arc::default(),
        };
        let mut child = PtyChild {
            child: Box::new(child),
            pid: NonZeroU32::new(42).unwrap(),
        };
        assert!(
            matches!(scope::ChildCustody::reap(&mut child), Ok(7)),
            "an interrupted actual child wait escaped as permanent custody loss"
        );
        assert_eq!(waits.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn custody39_missing_child_pid_retains_unknown_without_legacy_kill_or_wait() {
        let waits = Arc::new(AtomicUsize::new(0));
        let kills = Arc::new(AtomicUsize::new(0));
        let child = ControlledChild {
            pid: None,
            waits: waits.clone(),
            kills: kills.clone(),
        };
        let view = QualifiedProc {
            root: std::fs::File::open("/dev/null").unwrap().into(),
        };
        let mut wait = own_child(Box::new(child), view);
        assert!(matches!(wait.poll_exit(), ChildStatus::Unknown(_)));
        wait.kill();
        assert!(matches!(wait.poll_exit(), ChildStatus::Unknown(_)));
        assert_eq!(waits.load(Ordering::SeqCst), 0);
        assert_eq!(kills.load(Ordering::SeqCst), 0);
    }
    extern "C" fn notify_only(_: libc::c_int) {}

    struct ProbeChild(Option<PtyChild>);
    impl Drop for ProbeChild {
        fn drop(&mut self) {
            let Some(mut child) = self.0.take() else {
                return;
            };
            // Only an exact, still-unreaped direct child may be signalled.
            if child.observe().is_ok() {
                let _ = child.child.kill();
                let _ = child.child.wait();
            }
        }
    }
    #[test]
    fn sigchld39_preflight_rejects_autoreap_and_supports_notification_only() {
        use std::process::{Command, Stdio};
        const MODE: &str = "QSH_TEST_SCOPE_SIGCHLD";
        const TEST: &str = "process_scope::pty::tests::sigchld39_preflight_rejects_autoreap_and_supports_notification_only";
        if let Ok(mode) = std::env::var(MODE) {
            // This branch runs only in our exact owned self-reexec process.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            action.sa_sigaction = match mode.as_str() {
                "ignore" => libc::SIG_IGN,
                "no-wait" => {
                    action.sa_flags = libc::SA_NOCLDWAIT;
                    libc::SIG_DFL
                }
                "notify" => notify_only as *const () as usize,
                _ => panic!("unknown owned probe mode"),
            };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
                0
            );
            if mode != "notify" {
                assert!(
                    prepare().is_err(),
                    "auto-reaping disposition was accepted before child creation"
                );
                return;
            }
            let _view = prepare().expect("notification-only handler retains wait ownership");
            let child = Command::new("/bin/true").spawn().unwrap();
            let pid = NonZeroU32::new(child.id()).unwrap();
            let mut child = ProbeChild(Some(PtyChild {
                child: Box::new(child),
                pid,
            }));
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.0.as_mut().unwrap().observe().unwrap() {
                    Some(code) => {
                        assert_eq!(code, 0);
                        break;
                    }
                    None => {
                        assert!(Instant::now() < deadline, "owned true child did not exit");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            assert_eq!(
                child.0.as_mut().unwrap().observe().unwrap(),
                Some(0),
                "WNOWAIT did not retain the exited leader"
            );
            assert_eq!(child.0.as_mut().unwrap().reap().unwrap(), 0);
            child.0.take(); // Successful reap: never observe/signal this PID again.
            return;
        }
        let mut results = Vec::new();
        for mode in ["ignore", "no-wait", "notify"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let success = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status.success();
                }
                if Instant::now() >= deadline {
                    // Parent retains this exact unreaped helper; no group or
                    // unrelated PID is signalled. Probe descendants run /bin/true.
                    child.kill().unwrap();
                    child.wait().unwrap();
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            results.push((mode, success));
        }
        assert_eq!(
            results,
            vec![("ignore", true), ("no-wait", true), ("notify", true)]
        );
    }
    #[test]
    fn interrupt39_observation_retries_before_returning_authority_error() {
        let mut calls = 0;
        let result = retry_interrupted(|| {
            calls += 1;
            if calls == 1 {
                Err(Failure::Errno(libc::EINTR))
            } else {
                Ok(Some(7))
            }
        });
        assert!(
            matches!(result, Ok(Some(7))),
            "EINTR escaped as an authority error"
        );
        assert_eq!(calls, 2);
    }
    #[test]
    fn interrupt39_final_wait_does_not_retry_irrecoverable_failure() {
        let mut calls = 0;
        let result: Result<i32, _> = retry_interrupted(|| {
            calls += 1;
            Err(Failure::Errno(libc::ECHILD))
        });
        assert!(matches!(result, Err(Failure::Errno(libc::ECHILD))));
        assert_eq!(calls, 1);
    }
}
