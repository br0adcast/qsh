//! Reserved direct-child custody before authenticated session establishment.

use super::scope::{ChildCustody, LeaderStatus, Progress, Scope};
use super::{Acquisition, CaptureFailure, ProcOperations, QualifiedProc, RetainedProcess};
use nix::libc;
use std::os::fd::OwnedFd;

#[must_use = "retain exact child custody until completion or explicit transfer"]
pub(crate) struct ChildOnly<C> {
    child: C,
    view: QualifiedProc,
    process: Option<RetainedProcess>,
    unproved: Option<OwnedFd>,
    stop: bool,
    kill: bool,
    lost: bool,
    completed: Option<i32>,
}
impl<C: ChildCustody> ChildOnly<C> {
    /// Construct immediately after fork, before any fallible capture/setup.
    /// The proc view was qualified before fork in the same active PID namespace.
    pub(crate) fn new(child: C, view: QualifiedProc) -> Self {
        Self {
            child,
            view,
            process: None,
            unproved: None,
            stop: false,
            kill: false,
            lost: false,
            completed: None,
        }
    }
    pub(crate) fn request_stop(&mut self) {
        self.stop = true;
    }
    pub(crate) fn escalate(&mut self) {
        self.stop = true;
        self.kill = true;
    }
    pub(crate) fn poll_leader(&mut self) -> LeaderStatus {
        if let Some(code) = self.completed {
            return LeaderStatus::Exited(code);
        }
        if self.lost {
            return LeaderStatus::Unknown;
        }
        self.lost = true;
        match self.child.observe() {
            Ok(code) => {
                self.lost = false;
                code.map_or(LeaderStatus::Running, LeaderStatus::Exited)
            }
            Err(_) => LeaderStatus::Unknown,
        }
    }
    /// The monitor must consume queued stage frames before calling this. True
    /// means positive terminal private-report proof, not timeout/cancellation.
    pub(crate) fn step(
        &mut self,
        ops: &mut impl ProcOperations,
        pre_session_terminal: bool,
    ) -> Progress {
        if let Some(code) = self.completed {
            return Progress::Complete(code);
        }
        match self.poll_leader() {
            LeaderStatus::Unknown => return Progress::Unknown,
            LeaderStatus::Exited(_) if pre_session_terminal => {
                self.lost = true;
                return match self.child.reap() {
                    Ok(code) => {
                        self.completed = Some(code);
                        self.lost = false;
                        Progress::Complete(code)
                    }
                    Err(_) => Progress::Unknown,
                };
            }
            _ => {}
        }
        if !self.stop {
            return Progress::Pending;
        }
        if self.process.is_none() {
            let capture = if let Some(fd) = self.unproved.take() {
                RetainedProcess::acquire_reserved_child(fd, self.child.leader_id().get(), ops)
                    .map_err(CaptureFailure::Unproved)
            } else {
                self.view
                    .capture_reserved_child(self.child.leader_id().get(), ops)
            };
            match capture {
                Ok(process) => self.process = Some(process),
                Err(CaptureFailure::Unproved(Acquisition::Unknown(fd))) => {
                    self.unproved = Some(fd);
                    return Progress::Unknown;
                }
                Err(_) => return Progress::Unknown,
            }
        }
        match self.process.as_mut().unwrap().stop(
            ops,
            if self.kill {
                libc::SIGKILL
            } else {
                libc::SIGHUP
            },
        ) {
            super::Evidence::Unknown => Progress::Unknown,
            _ => Progress::Pending,
        }
    }
    /// `sid` comes only from this child's complete private stage frame.
    /// Failure returns the original owner, including poison and retained fds.
    pub(crate) fn establish_session(self, sid: u32) -> Result<Scope<C>, Self> {
        if self.lost || self.completed.is_some() || sid != self.child.leader_id().get() {
            return Err(self);
        }
        let mut scope = Scope::from_reserved(self.child, self.view, self.process, self.unproved);
        if self.stop {
            scope.request_stop();
        }
        if self.kill {
            scope.escalate();
        }
        Ok(scope)
    }
}

#[cfg(test)]
mod tests {
    use super::super::scope::ScopeOperations;
    use super::super::{Failure, Operations};
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::num::NonZeroU32;
    use std::rc::Rc;

    #[derive(Default)]
    struct Calls {
        observes: usize,
        reaps: usize,
    }
    struct Child {
        calls: Rc<RefCell<Calls>>,
        observe: VecDeque<Result<Option<i32>, Failure>>,
        reap: Result<i32, Failure>,
    }
    impl ChildCustody for Child {
        fn leader_id(&self) -> NonZeroU32 {
            NonZeroU32::new(42).unwrap()
        }
        fn observe(&mut self) -> Result<Option<i32>, Failure> {
            self.calls.borrow_mut().observes += 1;
            self.observe.pop_front().unwrap_or(Ok(None))
        }
        fn reap(&mut self) -> Result<i32, Failure> {
            self.calls.borrow_mut().reaps += 1;
            self.reap
        }
    }
    #[derive(Default)]
    struct Ops {
        opens: usize,
        signals: Vec<i32>,
        census: usize,
        denied: bool,
    }
    fn fd() -> OwnedFd {
        File::open("/dev/null").unwrap().into()
    }
    impl Operations for Ops {
        fn status(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            if self.denied {
                return Err(Failure::Errno(libc::EPERM));
            }
            Ok(b"Pid:\t42\nTgid:\t42\n".to_vec())
        }
        fn stat(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            Ok(b"42 (owned) S 1 42 1000 0 0 0 0 0 0 0 0 0 0 0 0 0 1\n".to_vec())
        }
        fn signal(&mut self, _: &OwnedFd, signal: i32) -> Result<(), Failure> {
            self.signals.push(signal);
            Ok(())
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
    impl ScopeOperations for Ops {
        fn census(
            &mut self,
            _: &OwnedFd,
            _: &mut dyn FnMut(&mut Self, u32),
        ) -> Result<(), Failure> {
            self.census += 1;
            Ok(())
        }
    }
    fn owner(
        observe: Vec<Result<Option<i32>, Failure>>,
        reap: Result<i32, Failure>,
    ) -> (ChildOnly<Child>, Rc<RefCell<Calls>>) {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let child = Child {
            calls: calls.clone(),
            observe: observe.into(),
            reap,
        };
        // A controlled qualified view: these tests inspect transitions, not
        // actual proc availability or membership proof.
        (ChildOnly::new(child, QualifiedProc { root: fd() }), calls)
    }

    #[test]
    fn helper39_child_only_stop_never_censuses_parent_session() {
        let (mut owner, calls) = owner(vec![], Ok(0));
        let mut ops = Ops::default();
        owner.request_stop();
        assert_eq!(owner.step(&mut ops, false), Progress::Pending);
        owner.escalate();
        assert_eq!(owner.step(&mut ops, false), Progress::Pending);
        assert_eq!(ops.signals, [libc::SIGHUP, libc::SIGKILL]);
        assert_eq!(ops.opens, 1);
        assert_eq!(ops.census, 0);
        assert_eq!(calls.borrow().reaps, 0);
    }
    #[test]
    fn helper39_child_exit_without_terminal_report_never_reaps() {
        let (mut owner, calls) = owner(vec![Ok(Some(7)), Ok(Some(7))], Ok(7));
        let mut ops = Ops::default();
        assert_eq!(owner.step(&mut ops, false), Progress::Pending);
        assert_eq!(calls.borrow().reaps, 0);
        assert_eq!(owner.step(&mut ops, true), Progress::Complete(7));
        assert_eq!(owner.step(&mut ops, true), Progress::Complete(7));
        assert_eq!(calls.borrow().reaps, 1);
        assert!(ops.signals.is_empty());
    }
    #[test]
    fn helper39_handoff_retains_exact_capture_and_stop() {
        let (mut owner, _) = owner(vec![], Ok(0));
        let mut ops = Ops::default();
        owner.request_stop();
        assert_eq!(owner.step(&mut ops, false), Progress::Pending);
        let mut scope = match owner.establish_session(42) {
            Ok(scope) => scope,
            Err(_) => panic!("valid stage"),
        };
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert_eq!(ops.opens, 1, "handoff retained the exact child fd");
        assert_eq!(
            ops.census, 1,
            "session census begins only after matching stage"
        );
    }
    #[test]
    fn helper39_wait_loss_permanently_blocks_signal_reap_and_upgrade() {
        for final_reap in [false, true] {
            let observe = if final_reap {
                vec![Ok(Some(7))]
            } else {
                vec![Err(Failure::Errno(libc::ECHILD))]
            };
            let (mut owner, calls) = owner(observe, Err(Failure::Errno(libc::ECHILD)));
            let mut ops = Ops::default();
            owner.request_stop();
            assert_eq!(owner.step(&mut ops, final_reap), Progress::Unknown);
            let mut owner = match owner.establish_session(42) {
                Err(owner) => owner,
                Ok(_) => panic!("lost custody upgraded"),
            };
            assert_eq!(owner.poll_leader(), LeaderStatus::Unknown);
            assert_eq!(owner.step(&mut ops, true), Progress::Unknown);
            assert_eq!(calls.borrow().observes, 1);
            assert_eq!(calls.borrow().reaps, usize::from(final_reap));
            assert_eq!(ops.opens, 0);
            assert!(ops.signals.is_empty());
        }
    }
    #[test]
    fn helper39_failed_capture_and_wrong_stage_keep_original_owner() {
        let (mut owner, _) = owner(vec![], Ok(0));
        let mut ops = Ops {
            denied: true,
            ..Ops::default()
        };
        owner.request_stop();
        assert_eq!(owner.step(&mut ops, false), Progress::Unknown);
        let mut owner = match owner.establish_session(43) {
            Err(owner) => owner,
            Ok(_) => panic!("wrong stage"),
        };
        ops.denied = false;
        assert_eq!(owner.step(&mut ops, false), Progress::Pending);
        assert_eq!(ops.opens, 1, "unproved exact fd survives failed upgrade");
        assert_eq!(ops.signals, [libc::SIGHUP]);
    }
}
