use crate::process_scope::{
    parse_stat, Acquisition, CaptureFailure, Evidence, Failure, ProcOperations, QualifiedProc,
    RetainedProcess,
};
use nix::libc;

pub trait ChildCustody {
    fn leader_id(&self) -> std::num::NonZeroU32;
    /// Observe with WNOWAIT; never consume the reserved leader identity.
    /// Retry EINTR internally; returned errors permanently invalidate authority.
    fn observe(&mut self) -> Result<Option<i32>, Failure>;
    fn reap(&mut self) -> Result<i32, Failure>;
}
pub trait ScopeOperations: ProcOperations {
    fn census(
        &mut self,
        root: &std::os::fd::OwnedFd,
        visit: &mut dyn FnMut(&mut Self, u32),
    ) -> Result<(), Failure>
    where
        Self: Sized;
}
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    Pending,
    Unknown,
    Complete(i32),
}
#[derive(Debug, PartialEq, Eq)]
pub enum LeaderStatus {
    Running,
    Exited(i32),
    Unknown,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    Hup,
    Kill,
}
struct Member {
    pid: u32,
    process: RetainedProcess,
    hup: bool,
    killed: bool,
}
#[must_use = "retain process custody until completion or explicit transfer"]
pub struct Scope<C> {
    child: C,
    view: QualifiedProc,
    sid: u32,
    phase: Phase,
    members: Vec<Member>,
    unproved: Vec<(u32, std::os::fd::OwnedFd)>,
    completed: Option<i32>,
    custody_lost: bool,
}
impl<C: ChildCustody> Scope<C> {
    /// Caller owns this exact unreaped child and has authenticated setsid success.
    pub fn new(child: C, view: QualifiedProc) -> Self {
        let sid = child.leader_id();
        Self {
            child,
            view,
            sid: sid.get(),
            phase: Phase::Running,
            members: vec![],
            unproved: vec![],
            completed: None,
            custody_lost: false,
        }
    }
    pub fn poll_leader(&mut self) -> LeaderStatus {
        if let Some(code) = self.completed {
            return LeaderStatus::Exited(code);
        }
        if self.custody_lost {
            return LeaderStatus::Unknown;
        }
        // Errors/unwind cannot renew authority over a possibly released PID.
        // Native adapters retry EINTR at their syscall boundary.
        self.custody_lost = true;
        match self.child.observe() {
            Ok(status) => {
                self.custody_lost = false;
                match status {
                    Some(code) => {
                        self.request_stop();
                        LeaderStatus::Exited(code)
                    }
                    None => LeaderStatus::Running,
                }
            }
            Err(_) => LeaderStatus::Unknown,
        }
    }
    pub fn request_stop(&mut self) {
        if self.phase == Phase::Running {
            self.phase = Phase::Hup;
        }
    }
    pub fn escalate(&mut self) {
        self.phase = Phase::Kill;
    }
    pub fn step(&mut self, ops: &mut impl ScopeOperations) -> Progress {
        if let Some(code) = self.completed {
            return Progress::Complete(code);
        }
        let leader_exited = match self.poll_leader() {
            LeaderStatus::Exited(_) => true,
            LeaderStatus::Running if self.phase == Phase::Running => return Progress::Pending,
            LeaderStatus::Running => false,
            LeaderStatus::Unknown => return Progress::Unknown,
        };
        let mut unknown = false;
        let mut all_previously_exited = leader_exited && self.unproved.is_empty();
        for member in &mut self.members {
            match member.process.observe(ops) {
                Evidence::Exited => {}
                Evidence::Pending => all_previously_exited = false,
                Evidence::Unknown => {
                    all_previously_exited = false;
                    unknown = true;
                }
            }
        }
        let mut new_owner = false;
        let mut vanished = false;
        for (pid, fd) in std::mem::take(&mut self.unproved) {
            match RetainedProcess::acquire_member(fd, pid, self.sid, ops) {
                Ok(process) => new_owner |= Self::retain(&mut self.members, pid, process, ops),
                Err(Acquisition::OutsideSession) => {}
                Err(Acquisition::Unknown(fd)) => {
                    if candidate_vanished(&fd, ops) {
                        vanished = true;
                    } else {
                        self.unproved.push((pid, fd));
                        unknown = true;
                    }
                }
            }
        }
        // This census begins AFTER the above exact exit observations. A census
        // started while a previously captured parent was alive cannot certify
        // final closure even if that parent exits later in this step.
        if !unknown && self.unproved.is_empty() {
            let view = &self.view;
            let members = &mut self.members;
            let unproved = &mut self.unproved;
            let sid = self.sid;
            let mut visit = |ops: &mut _, pid| match view.capture(pid, sid, ops) {
                Ok(process) => new_owner |= Self::retain(members, pid, process, ops),
                Err(CaptureFailure::Open(Failure::Errno(libc::ENOENT | libc::ESRCH))) => {
                    vanished = true
                }
                Err(CaptureFailure::Open(_)) => unknown = true,
                Err(CaptureFailure::Unproved(Acquisition::OutsideSession)) => {}
                Err(CaptureFailure::Unproved(Acquisition::Unknown(fd))) => {
                    if candidate_vanished(&fd, ops) {
                        vanished = true;
                    } else {
                        unproved.push((pid, fd));
                        unknown = true;
                    }
                }
            };
            if ops.census(&view.root, &mut visit).is_err() {
                unknown = true;
            }
        } else {
            unknown = true;
        }
        let mut all_exited = true;
        for member in &mut self.members {
            let observation = member.process.observe(ops);
            if observation == Evidence::Exited {
                continue;
            }
            all_exited = false;
            if observation == Evidence::Unknown {
                unknown = true;
            }
            let signal = match self.phase {
                Phase::Hup if !member.hup => Some(libc::SIGHUP),
                Phase::Kill if !member.killed => Some(libc::SIGKILL),
                _ => None,
            };
            if let Some(signal) = signal {
                match member.process.stop(ops, signal) {
                    Evidence::Unknown => unknown = true,
                    _ => {
                        if signal == libc::SIGHUP {
                            member.hup = true;
                        } else {
                            member.killed = true;
                        }
                    }
                }
            }
        }
        if unknown {
            return Progress::Unknown;
        }
        if !all_previously_exited
            || !all_exited
            || new_owner
            || vanished
            || !self.unproved.is_empty()
        {
            return Progress::Pending;
        }
        // A failed/unwinding final wait may already have released the SID.
        // Only a successful receipt below permits completed-state publication.
        self.custody_lost = true;
        match self.child.reap() {
            Ok(code) => {
                self.completed = Some(code);
                Progress::Complete(code)
            }
            Err(_) => Progress::Unknown,
        }
    }
    fn retain(
        members: &mut Vec<Member>,
        pid: u32,
        process: RetainedProcess,
        ops: &mut impl ScopeOperations,
    ) -> bool {
        // Fresh exact capture precedes this old-instance presence proof. A
        // successful new read through old procfd means its PID was still held,
        // so that numeric PID could not have been reused before fresh capture.
        // This also handles persistent Z/1 zombies without signalling them.
        for old in members.iter_mut().filter(|old| old.pid == pid) {
            if ops
                .stat(&old.process.fd)
                .and_then(|bytes| parse_stat(&bytes))
                .is_ok()
            {
                return false;
            }
        }
        members.push(Member {
            pid,
            process,
            hup: false,
            killed: false,
        });
        true
    }
}

fn candidate_vanished(fd: &std::os::fd::OwnedFd, ops: &mut impl ScopeOperations) -> bool {
    matches!(
        ops.status(fd),
        Err(Failure::Errno(libc::ENOENT | libc::ESRCH))
    ) && matches!(ops.signal(fd, 0), Err(Failure::Errno(libc::ESRCH)))
}

impl ScopeOperations for crate::process_scope::Native {
    fn census(
        &mut self,
        root: &std::os::fd::OwnedFd,
        visit: &mut dyn FnMut(&mut Self, u32),
    ) -> Result<(), Failure> {
        use std::os::fd::AsRawFd;
        let raw = unsafe {
            libc::openat(
                root.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(crate::process_scope::last_error());
        }
        let dir = unsafe { libc::fdopendir(raw) };
        if dir.is_null() {
            let error = crate::process_scope::last_error();
            unsafe { libc::close(raw) };
            return Err(error);
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let directory = Directory(dir);
        // A fresh openat(".") gives an independent directory offset per census.
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                let errno = unsafe { *libc::__errno_location() };
                if errno != 0 {
                    return Err(Failure::Errno(errno));
                }
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if !name.iter().all(u8::is_ascii_digit) {
                continue;
            }
            let pid = u32::try_from(crate::process_scope::positive_number(name)?)
                .map_err(|_| Failure::Malformed)?;
            visit(self, pid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_scope::Operations;
    use std::{
        collections::VecDeque,
        fs::File,
        os::fd::OwnedFd,
        sync::{Arc, Mutex},
    };
    struct Child {
        events: Arc<Mutex<Vec<&'static str>>>,
        exited: bool,
    }
    impl ChildCustody for Child {
        fn leader_id(&self) -> std::num::NonZeroU32 {
            std::num::NonZeroU32::new(42).unwrap()
        }
        fn observe(&mut self) -> Result<Option<i32>, Failure> {
            self.events.lock().unwrap().push("observe");
            Ok(self.exited.then_some(0))
        }
        fn reap(&mut self) -> Result<i32, Failure> {
            self.events.lock().unwrap().push("reap");
            Ok(0)
        }
    }
    struct Ops {
        censuses: VecDeque<Result<Vec<u32>, Failure>>,
        calls: Vec<&'static str>,
    }
    impl Operations for Ops {
        fn stat(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            Err(Failure::Errno(libc::EACCES))
        }
        fn status(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            Err(Failure::Errno(libc::EACCES))
        }
        fn signal(&mut self, _fd: &OwnedFd, _sig: i32) -> Result<(), Failure> {
            self.calls.push("signal");
            Ok(())
        }
    }
    impl ProcOperations for Ops {
        fn open_self(&mut self, _root: &OwnedFd) -> Result<OwnedFd, Failure> {
            unreachable!()
        }
        fn self_identity(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            unreachable!()
        }
        fn open_numeric(&mut self, _root: &OwnedFd, _pid: u32) -> Result<OwnedFd, Failure> {
            self.calls.push("capture");
            Err(Failure::Errno(libc::ENOENT))
        }
    }
    impl ScopeOperations for Ops {
        fn census(
            &mut self,
            _root: &OwnedFd,
            visit: &mut dyn FnMut(&mut Self, u32),
        ) -> Result<(), Failure> {
            self.calls.push("census");
            for pid in self.censuses.pop_front().unwrap()? {
                visit(self, pid);
            }
            Ok(())
        }
    }
    fn fixture(
        exited: bool,
        censuses: Vec<Result<Vec<u32>, Failure>>,
    ) -> (Scope<Child>, Ops, Arc<Mutex<Vec<&'static str>>>) {
        let events = Arc::new(Mutex::new(vec![]));
        let child = Child {
            events: events.clone(),
            exited,
        };
        let view = QualifiedProc {
            root: File::open("/dev/null").unwrap().into(),
        };
        (
            Scope::new(child, view),
            Ops {
                censuses: censuses.into(),
                calls: vec![],
            },
            events,
        )
    }
    #[test]
    fn empty_sticky_drain_reaps_once_and_never_signals_after_reap() {
        let (mut scope, mut ops, events) = fixture(true, vec![Ok(vec![])]);
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        let count = ops.calls.len();
        scope.request_stop();
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        assert_eq!(ops.calls.len(), count);
        assert_eq!(*events.lock().unwrap(), vec!["observe", "reap"]);
    }
    #[test]
    fn vanished_before_capture_requires_a_new_census_not_unknown_or_completion() {
        let (mut scope, mut ops, events) = fixture(true, vec![Ok(vec![77]), Ok(vec![])]);
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert!(!events.lock().unwrap().contains(&"reap"));
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        assert_eq!(ops.calls, vec!["census", "capture", "census"]);
    }
    #[test]
    fn discovery_failure_retains_owner_and_can_retry() {
        let (mut scope, mut ops, events) =
            fixture(true, vec![Err(Failure::Errno(libc::EACCES)), Ok(vec![])]);
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert!(!events.lock().unwrap().contains(&"reap"));
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn lost_leader_custody_never_censuses_signals_or_reaps() {
        struct Lost;
        impl ChildCustody for Lost {
            fn leader_id(&self) -> std::num::NonZeroU32 {
                std::num::NonZeroU32::new(42).unwrap()
            }
            fn observe(&mut self) -> Result<Option<i32>, Failure> {
                Err(Failure::Errno(libc::ECHILD))
            }
            fn reap(&mut self) -> Result<i32, Failure> {
                panic!("lost custody is not reaped proof")
            }
        }
        let view = QualifiedProc {
            root: File::open("/dev/null").unwrap().into(),
        };
        let mut scope = Scope::new(Lost, view);
        let mut ops = Ops {
            censuses: VecDeque::new(),
            calls: vec![],
        };
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert!(ops.calls.is_empty());
    }
    #[test]
    fn running_leader_status_does_not_wait_for_cleanup_or_reap() {
        let (mut scope, mut ops, events) =
            fixture(true, vec![Err(Failure::Errno(libc::EACCES)), Ok(vec![])]);
        assert_eq!(scope.poll_leader(), LeaderStatus::Exited(0));
        assert_eq!(*events.lock().unwrap(), vec!["observe"]);
        assert!(ops.calls.is_empty());
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert!(!events.lock().unwrap().contains(&"reap"));
        assert_eq!(scope.poll_leader(), LeaderStatus::Exited(0));
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn natural_exit_starts_drain_without_external_close() {
        let (mut scope, mut ops, _) = fixture(true, vec![Ok(vec![])]);
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        assert_eq!(scope.poll_leader(), LeaderStatus::Exited(0));
    }
    struct FailedChild {
        events: Arc<Mutex<Vec<&'static str>>>,
        observation_error: bool,
        reap_error: bool,
    }
    impl ChildCustody for FailedChild {
        fn leader_id(&self) -> std::num::NonZeroU32 {
            std::num::NonZeroU32::new(42).unwrap()
        }
        fn observe(&mut self) -> Result<Option<i32>, Failure> {
            self.events.lock().unwrap().push("observe");
            if std::mem::take(&mut self.observation_error) {
                Err(Failure::Errno(libc::ECHILD))
            } else {
                // A later numeric lookup could now identify a different child.
                Ok(Some(91))
            }
        }
        fn reap(&mut self) -> Result<i32, Failure> {
            self.events.lock().unwrap().push("reap");
            if self.reap_error {
                Err(Failure::Errno(libc::ECHILD))
            } else {
                Ok(91)
            }
        }
    }
    #[test]
    fn custody39_echild_never_renews_numeric_authority_after_pid_reuse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let child = FailedChild {
            events: events.clone(),
            observation_error: true,
            reap_error: false,
        };
        let mut scope = Scope::new(
            child,
            QualifiedProc {
                root: File::open("/dev/null").unwrap().into(),
            },
        );
        let mut ops = Ops {
            censuses: vec![Ok(vec![])].into(),
            calls: Vec::new(),
        };
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        scope.escalate();
        assert_eq!(
            scope.step(&mut ops),
            Progress::Unknown,
            "a reused numeric child was accepted after ECHILD"
        );
        assert_eq!(*events.lock().unwrap(), vec!["observe"]);
        assert!(
            ops.calls.is_empty(),
            "lost custody must never census/capture/signal"
        );
    }
    #[test]
    fn custody39_failed_final_wait_never_restarts_session_discovery() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let child = FailedChild {
            events: events.clone(),
            observation_error: false,
            reap_error: true,
        };
        let mut scope = Scope::new(
            child,
            QualifiedProc {
                root: File::open("/dev/null").unwrap().into(),
            },
        );
        let mut ops = Ops {
            censuses: vec![Ok(vec![]), Ok(vec![77])].into(),
            calls: Vec::new(),
        };
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        scope.escalate();
        assert_eq!(
            scope.step(&mut ops),
            Progress::Unknown,
            "failed final wait resumed discovery under a potentially reused SID"
        );
        assert_eq!(*events.lock().unwrap(), vec!["observe", "reap"]);
        assert_eq!(ops.calls, vec!["census"]);
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;
    use crate::process_scope::{Operations, ProcOperations};
    use std::{
        collections::{HashMap, VecDeque},
        fs::File,
        os::fd::{AsRawFd, OwnedFd},
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Process {
        pid: u32,
        sid: u32,
        state: u8,
        present: bool,
        denied: bool,
    }
    #[derive(Default)]
    struct Model {
        processes: HashMap<u32, Process>,
        current: HashMap<u32, u32>,
        fds: HashMap<i32, u32>,
        events: Vec<String>,
        censuses: VecDeque<Vec<u32>>,
        fork_on_census: bool,
        census_denied: bool,
        late_census_error: bool,
    }
    struct ModelOps(Arc<Mutex<Model>>);
    fn fd() -> OwnedFd {
        File::open("/dev/null").unwrap().into()
    }
    fn stat(process: &Process) -> Vec<u8> {
        format!(
            "{} (test) {} 1 {} {} 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 123\n",
            process.pid, process.state as char, process.pid, process.sid
        )
        .into_bytes()
    }
    impl Operations for ModelOps {
        fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            let mut m = self.0.lock().unwrap();
            let token = m.fds[&fd.as_raw_fd()];
            m.events.push(format!("stat{token}"));
            let p = &m.processes[&token];
            if p.present {
                Ok(stat(p))
            } else {
                Err(Failure::Errno(libc::ESRCH))
            }
        }
        fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            let m = self.0.lock().unwrap();
            let p = &m.processes[&m.fds[&fd.as_raw_fd()]];
            if !p.present {
                Err(Failure::Errno(libc::ESRCH))
            } else if p.denied {
                Err(Failure::Errno(libc::EACCES))
            } else {
                Ok(format!("Pid: {}\nTgid: {}\n", p.pid, p.pid).into_bytes())
            }
        }
        fn signal(&mut self, fd: &OwnedFd, sig: i32) -> Result<(), Failure> {
            let mut m = self.0.lock().unwrap();
            let token = m.fds[&fd.as_raw_fd()];
            m.events.push(format!("signal{token}:{sig}"));
            let p = m.processes.get_mut(&token).unwrap();
            if !p.present {
                return Err(Failure::Errno(libc::ESRCH));
            }
            if sig == libc::SIGKILL {
                p.state = b'Z';
            }
            Ok(())
        }
    }
    impl ProcOperations for ModelOps {
        fn open_self(&mut self, _root: &OwnedFd) -> Result<OwnedFd, Failure> {
            unreachable!()
        }
        fn self_identity(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            unreachable!()
        }
        fn open_numeric(&mut self, _root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
            let mut m = self.0.lock().unwrap();
            let token = *m.current.get(&pid).ok_or(Failure::Errno(libc::ENOENT))?;
            m.events.push(format!("capture{pid}:{token}"));
            let result = fd();
            m.fds.insert(result.as_raw_fd(), token);
            Ok(result)
        }
    }
    impl ScopeOperations for ModelOps {
        fn census(
            &mut self,
            _root: &OwnedFd,
            visit: &mut dyn FnMut(&mut Self, u32),
        ) -> Result<(), Failure> {
            let pids = {
                let mut m = self.0.lock().unwrap();
                m.events.push("census".into());
                if m.census_denied {
                    return Err(Failure::Errno(libc::EACCES));
                }
                if let Some(pids) = m.censuses.pop_front() {
                    pids
                } else {
                    m.current.keys().copied().collect()
                }
            };
            for pid in pids {
                visit(self, pid);
            }
            let mut m = self.0.lock().unwrap();
            if m.fork_on_census {
                m.fork_on_census = false;
                m.processes.get_mut(&1).unwrap().state = b'Z';
                insert(&mut m, 2, 76, b'S');
                m.events.push("latefork".into());
            }
            if m.late_census_error {
                return Err(Failure::Errno(libc::EIO));
            }
            Ok(())
        }
    }

    struct Child(Arc<Mutex<Model>>);
    impl ChildCustody for Child {
        fn leader_id(&self) -> std::num::NonZeroU32 {
            std::num::NonZeroU32::new(42).unwrap()
        }
        fn observe(&mut self) -> Result<Option<i32>, Failure> {
            self.0.lock().unwrap().events.push("leader_wnowait".into());
            Ok(Some(0))
        }
        fn reap(&mut self) -> Result<i32, Failure> {
            self.0.lock().unwrap().events.push("leader_reap".into());
            Ok(0)
        }
    }
    fn insert(m: &mut Model, token: u32, pid: u32, state: u8) {
        m.processes.insert(
            token,
            Process {
                pid,
                sid: 42,
                state,
                present: true,
                denied: false,
            },
        );
        m.current.insert(pid, token);
    }
    fn fixture() -> (Scope<Child>, ModelOps, Arc<Mutex<Model>>) {
        let m = Arc::new(Mutex::new(Model::default()));
        let scope = Scope::new(Child(m.clone()), QualifiedProc { root: fd() });
        (scope, ModelOps(m.clone()), m)
    }
    #[test]
    fn final_census_begins_after_old_exit_and_finds_last_moment_child() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        model.lock().unwrap().fork_on_census = true;
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert!(!model.lock().unwrap().events.contains(&"leader_reap".into()));
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert!(model.lock().unwrap().events.contains(&"capture76:2".into()));
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn zombie_identity_dedups_only_after_fresh_capture_and_without_signal() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'Z');
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        let m = model.lock().unwrap();
        assert_eq!(scope.members.len(), 1);
        assert_eq!(
            m.events.iter().filter(|s| s.starts_with("capture")).count(),
            2
        );
        assert!(!m.events.iter().any(|s| s.starts_with("signal")));
    }
    #[test]
    fn stale_fd_and_reused_numeric_pid_cannot_hide_new_owned_instance() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        {
            let mut m = model.lock().unwrap();
            m.processes.get_mut(&1).unwrap().present = false;
            insert(&mut m, 2, 77, b'S');
        }
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert_eq!(scope.members.len(), 2);
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        let calls = model.lock().unwrap().events.len();
        scope.request_stop();
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        assert_eq!(calls, model.lock().unwrap().events.len());
        let m = model.lock().unwrap();
        assert!(m.events.contains(&format!("signal2:{}", libc::SIGKILL)));
        assert!(!m.events.contains(&format!("signal1:{}", libc::SIGKILL)));
    }
    #[test]
    fn denied_capture_retains_descriptor_and_discovery_error_still_drains_owners() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        model.lock().unwrap().processes.get_mut(&1).unwrap().denied = true;
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert_eq!(scope.unproved.len(), 1);
        assert!(unsafe { libc::fcntl(scope.unproved[0].1.as_raw_fd(), libc::F_GETFD) } >= 0);
        model.lock().unwrap().processes.get_mut(&1).unwrap().denied = false;
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        model.lock().unwrap().census_denied = true;
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert!(model
            .lock()
            .unwrap()
            .events
            .contains(&format!("signal1:{}", libc::SIGKILL)));
        assert!(!model.lock().unwrap().events.contains(&"leader_reap".into()));
        model.lock().unwrap().census_denied = false;
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn kill_phase_is_sticky_and_vanished_unproved_candidate_requires_fresh_census() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        scope.escalate();
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert!(model
            .lock()
            .unwrap()
            .events
            .contains(&format!("signal1:{}", libc::SIGKILL)));
        assert!(!model
            .lock()
            .unwrap()
            .events
            .contains(&format!("signal1:{}", libc::SIGHUP)));
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        model.lock().unwrap().processes.get_mut(&1).unwrap().present = false;
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Pending);
        assert!(scope.unproved.is_empty());
        model.lock().unwrap().current.remove(&77);
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn streaming_capture_is_owned_before_late_census_error() {
        let (mut scope, mut ops, model) = fixture();
        insert(&mut model.lock().unwrap(), 1, 77, b'S');
        model.lock().unwrap().late_census_error = true;
        scope.escalate();
        assert_eq!(scope.step(&mut ops), Progress::Unknown);
        assert_eq!(scope.members.len(), 1);
        let m = model.lock().unwrap();
        assert!(m.events.contains(&format!("signal1:{}", libc::SIGKILL)));
        assert!(!m.events.contains(&"leader_reap".into()));
        drop(m);
        model.lock().unwrap().late_census_error = false;
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
    }
    #[test]
    fn streaming_foreign_population_has_no_global_pid_cap() {
        struct Foreign {
            pid: u32,
            count: usize,
        }
        impl Operations for Foreign {
            fn status(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
                Ok(format!("Pid: {}\nTgid: {}\n", self.pid, self.pid).into_bytes())
            }
            fn stat(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
                Ok(format!(
                    "{} (foreign) S 1 99 99 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 123\n",
                    self.pid
                )
                .into_bytes())
            }
            fn signal(&mut self, _fd: &OwnedFd, _sig: i32) -> Result<(), Failure> {
                panic!("foreign task signalled")
            }
        }
        impl ProcOperations for Foreign {
            fn open_self(&mut self, _root: &OwnedFd) -> Result<OwnedFd, Failure> {
                unreachable!()
            }
            fn self_identity(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
                unreachable!()
            }
            fn open_numeric(&mut self, root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
                self.pid = pid;
                self.count += 1;
                Ok(root.try_clone().unwrap())
            }
        }
        impl ScopeOperations for Foreign {
            fn census(
                &mut self,
                _root: &OwnedFd,
                visit: &mut dyn FnMut(&mut Self, u32),
            ) -> Result<(), Failure> {
                for pid in 100000..170000 {
                    visit(self, pid);
                }
                Ok(())
            }
        }
        let (mut scope, _, _) = fixture();
        let mut ops = Foreign { pid: 0, count: 0 };
        scope.request_stop();
        assert_eq!(scope.step(&mut ops), Progress::Complete(0));
        assert_eq!(ops.count, 70000);
        assert!(scope.members.is_empty());
        assert!(scope.unproved.is_empty());
    }
}
