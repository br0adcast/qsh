//! Monitor-local direct-child to authenticated-session custody transfer.

use super::scope_ops::MonitorOps;
use super::startup::SessionEstablished;
use crate::process_scope::{
    fork::ChildOnly,
    fork_child::ForkChild,
    scope::{LeaderStatus, Progress, Scope},
    QualifiedProc,
};
use std::num::NonZeroU32;

enum State {
    ChildOnly(ChildOnly<ForkChild>),
    Session(Scope<ForkChild>),
    Complete(i32),
}
#[must_use = "the monitor must retain and drain this exact shell owner"]
pub(super) struct ShellOwner {
    // Taken only during a synchronous, infallible custody transfer. No await,
    // callback, native operation, or publication can see the temporary None.
    state: Option<State>,
    signal_failure: Option<(i32, i32)>,
}
impl ShellOwner {
    pub(super) fn reserved_root(&self) -> crate::process_scope::scope::ReservedRoot {
        match self.state.as_ref().unwrap() {
            State::ChildOnly(owner) => owner.reserved_root(),
            State::Session(scope) => scope.reserved_root(),
            State::Complete(_) => crate::process_scope::scope::ReservedRoot::Released,
        }
    }
    pub(super) fn new(pid: NonZeroU32, view: QualifiedProc) -> Self {
        Self {
            state: Some(State::ChildOnly(ChildOnly::new(ForkChild::new(pid), view))),
            signal_failure: None,
        }
    }
    pub(super) fn establish(&mut self, proof: SessionEstablished) -> bool {
        self.establish_sid(proof.sid())
    }
    pub(super) fn establish_monitor(&mut self, proof: super::monitor_owner::Established) -> bool {
        self.establish_sid(proof.sid())
    }
    pub(super) fn establish_worker(&mut self, proof: super::worker_owner::Established) -> bool {
        self.establish_sid(proof.sid())
    }
    fn establish_sid(&mut self, sid: u32) -> bool {
        let state = self.state.take().unwrap();
        let (state, established) = match state {
            State::ChildOnly(owner) => match owner.establish_session(sid) {
                Ok(scope) => (State::Session(scope), true),
                Err(owner) => (State::ChildOnly(owner), false),
            },
            // The parser publishes a stage only once. An unexpected stage
            // cannot renew completed or otherwise incompatible authority.
            state => (state, false),
        };
        self.state = Some(state);
        established
    }
    pub(super) fn request_stop(&mut self) {
        match self.state.as_mut().unwrap() {
            State::ChildOnly(owner) => owner.request_stop(),
            State::Session(scope) => scope.request_stop(),
            State::Complete(_) => {}
        }
    }
    pub(super) fn escalate(&mut self) {
        match self.state.as_mut().unwrap() {
            State::ChildOnly(owner) => owner.escalate(),
            State::Session(scope) => scope.escalate(),
            State::Complete(_) => {}
        }
    }
    pub(super) fn leader(&mut self) -> LeaderStatus {
        match self.state.as_mut().unwrap() {
            State::ChildOnly(owner) => owner.poll_leader(),
            State::Session(scope) => scope.poll_leader(),
            State::Complete(code) => LeaderStatus::Exited(*code),
        }
    }
    pub(super) fn take_signal_failure(&mut self) -> Option<(i32, i32)> {
        self.signal_failure.take()
    }
    #[cfg(test)]
    pub(super) fn inject_signal_failure(&mut self, failure: (i32, i32)) {
        self.signal_failure = Some(failure);
    }
    pub(super) fn progress(&mut self, pre_session_terminal: bool) -> Progress {
        self.progress_inner(pre_session_terminal, true)
    }
    pub(super) fn progress_without_reap(&mut self) -> Progress {
        self.progress_inner(false, false)
    }
    fn progress_inner(&mut self, pre_session_terminal: bool, allow_reap: bool) -> Progress {
        let mut ops = MonitorOps::new();
        let result = match self.state.as_mut().unwrap() {
            State::ChildOnly(owner) => owner.step(&mut ops, pre_session_terminal),
            State::Session(scope) if allow_reap => scope.step(&mut ops),
            State::Session(scope) => scope.step_without_reap(&mut ops),
            State::Complete(code) => Progress::Complete(*code),
        };
        if self.signal_failure.is_none() {
            self.signal_failure = ops.take_failure();
        }
        if let Progress::Complete(code) = result {
            self.state = Some(State::Complete(code));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::super::startup::{Failure, Outcome, StartupReader};
    use super::*;
    use nix::libc;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::{net::UnixStream, process::CommandExt};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct Fixture {
        child: Child,
        product_reaped: bool,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.product_reaped {
                return;
            }
            loop {
                match self.child.try_wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Some(_)) => return,
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                    Err(error) => panic!("owned fixture wait failed: {error}"),
                    Ok(None) => break,
                }
            }
            let _ = self.child.kill();
            loop {
                match self.child.wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => {
                        result.unwrap();
                        break;
                    }
                }
            }
        }
    }
    fn command() -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "read release"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
    fn fixture(command: &mut Command) -> Fixture {
        Fixture {
            child: command.spawn().unwrap(),
            product_reaped: false,
        }
    }
    #[test]
    fn helper39_actual_pre_stage_stop_preserves_parent_session_and_other_child() {
        let view = crate::process_scope::prepare().unwrap();
        let mut child = fixture(&mut command());
        let mut owner = ShellOwner::new(NonZeroU32::new(child.child.id()).unwrap(), view);
        let mut outsider = fixture(&mut command());
        let sid = unsafe { libc::getsid(0) };
        assert_eq!(unsafe { libc::getsid(child.child.id() as i32) }, sid);
        owner.request_stop();
        let deadline = Instant::now() + Duration::from_secs(2);
        let complete = loop {
            match owner.progress(true) {
                Progress::Complete(_) => break true,
                _ if Instant::now() >= deadline => break false,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        };
        child.product_reaped = complete;
        let outsider_running = outsider.child.try_wait().unwrap().is_none();
        drop(child);
        drop(outsider); // fixture-owned cleanup precedes every acceptance assertion
        assert!(complete, "deadline is failure, never product cleanup proof");
        assert_eq!(unsafe { libc::getsid(0) }, sid);
        assert!(
            outsider_running,
            "pre-stage stop must not signal the shared SID"
        );
    }
    #[test]
    fn helper39_actual_queued_stage_after_leader_exit_upgrades_before_final_reap() {
        let view = crate::process_scope::prepare().unwrap();
        let (mut input, output) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let mut command = Command::new("/bin/true");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                let sid = libc::setsid();
                if sid < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut frame = [0u8; 5];
                frame[0] = 1;
                frame[1..].copy_from_slice(&(sid as u32).to_ne_bytes());
                loop {
                    let count = libc::write(output.as_raw_fd(), frame.as_ptr().cast(), frame.len());
                    if count == 5 {
                        break;
                    }
                    if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    libc::_exit(127);
                }
                Ok(())
            });
        }
        let mut child = fixture(&mut command);
        let pid = child.child.id();
        let mut owner = ShellOwner::new(NonZeroU32::new(pid).unwrap(), view);
        drop(command);
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.leader() != LeaderStatus::Exited(0) {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let now = Instant::now();
        let mut reader = StartupReader::new(pid, now + Duration::from_secs(1));
        reader.cancel();
        owner.request_stop();
        let update = reader.poll(&mut input, now);
        let established = update
            .established
            .map(|proof| owner.establish(proof))
            .unwrap_or(false);
        let complete = loop {
            match owner.progress(reader.pre_session_terminal()) {
                Progress::Complete(0) => break true,
                _ if Instant::now() >= deadline => break false,
                _ => std::thread::sleep(Duration::from_millis(1)),
            }
        };
        child.product_reaped = complete;
        drop(child);
        assert!(
            established,
            "queued private child stage survives cancellation and leader exit"
        );
        assert_eq!(update.outcome, Some(Outcome::Failed(Failure::Cancelled)));
        assert!(!reader.pre_session_terminal());
        assert!(
            complete,
            "scope must produce actual final receipt before release"
        );
        assert_eq!(owner.leader(), LeaderStatus::Exited(0));
        owner.escalate(); // completed custody never signals again
        assert_eq!(owner.progress(false), Progress::Complete(0));
    }
}
