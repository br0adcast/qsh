use super::*;
use std::{collections::VecDeque, io::Cursor};

struct RootModel {
    live: bool,
    unknown: bool,
}
impl Roots for RootModel {
    fn classify(&mut self, pid: u32) -> Reservation {
        if self.unknown {
            Reservation::Unknown
        } else if self.live && pid == 7 {
            Reservation::Reserved
        } else {
            Reservation::Other
        }
    }
    fn state(&self) -> RootState {
        if self.unknown {
            RootState::Unknown
        } else if self.live {
            RootState::Active
        } else {
            RootState::Settled
        }
    }
}
struct Model {
    census: VecDeque<Vec<u8>>,
    observations: VecDeque<Result<Observation, Failure>>,
    signals: usize,
    reaps: usize,
    opens: usize,
    empty: usize,
    empties: VecDeque<Result<Empty, Failure>>,
    reaped: VecDeque<Result<Reaped, Failure>>,
    status: Option<Result<Vec<u8>, i32>>,
    signal_error: Option<i32>,
    open_error: Option<i32>,
    last_pid: u32,
}
impl Model {
    fn new(lists: &[&[u8]]) -> Self {
        Self {
            census: lists.iter().map(|s| s.to_vec()).collect(),
            observations: VecDeque::new(),
            signals: 0,
            reaps: 0,
            opens: 0,
            empty: 0,
            empties: VecDeque::new(),
            reaped: VecDeque::new(),
            status: None,
            signal_error: None,
            open_error: None,
            last_pid: 7,
        }
    }
}
impl Operations for Model {
    fn stat(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
        Ok(b"7 (owned) S 42 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n".to_vec())
    }
    fn status(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
        match &self.status {
            Some(Ok(bytes)) => Ok(bytes.clone()),
            Some(Err(errno)) => Err(Failure::Errno(*errno)),
            None => Ok(format!(
                "Pid: {}\nTgid: {}\nPPid: 42\n",
                self.last_pid, self.last_pid
            )
            .into_bytes()),
        }
    }
    fn signal(&mut self, _: &OwnedFd, _: i32) -> Result<(), Failure> {
        self.signals += 1;
        self.signal_error.map_or(Ok(()), |e| Err(Failure::Errno(e)))
    }
}
impl AdoptionOps for Model {
    fn census(&mut self) -> Result<Box<dyn Read>, Failure> {
        Ok(Box::new(Cursor::new(
            self.census.pop_front().expect("fresh census required"),
        )))
    }
    fn open_child(&mut self, pid: u32) -> Result<OwnedFd, Failure> {
        self.opens += 1;
        self.last_pid = pid;
        if let Some(e) = self.open_error {
            return Err(Failure::Errno(e));
        }
        Ok(std::fs::File::open("/dev/null").unwrap().into())
    }
    fn observe_child(&mut self, _: u32) -> Result<Observation, Failure> {
        self.observations
            .pop_front()
            .unwrap_or(Ok(Observation::Running))
    }
    fn reap_child(&mut self, _: u32) -> Result<Reaped, Failure> {
        self.reaps += 1;
        self.reaped.pop_front().unwrap_or(Ok(Reaped::Exited(9)))
    }
    fn no_children(&mut self) -> Result<Empty, Failure> {
        self.empty += 1;
        self.empties.pop_front().unwrap_or(Ok(Empty::Yes))
    }
}
#[test]
fn adoption40_empty_fence_requires_actual_new_census_and_echild() {
    let mut ops = Model::new(&[b""]);
    let mut roots = RootModel {
        live: false,
        unknown: false,
    };
    let mut owner = Adoption::new(QualifiedHelper { pid: 42 });
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
    assert_eq!(ops.empty, 1);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
    assert_eq!(
        ops.empty, 1,
        "completed owner cannot observe a recycled child"
    );
}
#[test]
fn adoption40_old_root_number_does_not_hide_a_new_adopted_child() {
    let mut ops = Model::new(&[b"7 ", b"7 ", b""]);
    let mut roots = RootModel {
        live: true,
        unknown: false,
    };
    let mut owner = Adoption::new(QualifiedHelper { pid: 42 });
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(
        ops.opens, 0,
        "reserved live root must not be acquired twice"
    );
    roots.live = false;
    // Finish the old census, then begin a NEW one after root settlement.
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(
        ops.opens, 1,
        "fresh custody lookup must consider numeric reuse"
    );
    ops.observations.push_back(Ok(Observation::Exited(9)));
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(ops.reaps, 1);
    assert_eq!(ops.empty, 0, "exit must force a later fresh census");
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
}

#[test]
fn adoption40_lost_root_is_unknown_even_when_children_file_is_empty() {
    let mut ops = Model::new(&[b""]);
    let mut roots = RootModel {
        live: false,
        unknown: true,
    };
    let mut owner = Adoption::new(QualifiedHelper { pid: 42 });
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Unknown);
    roots.unknown = false;
    assert_eq!(
        owner.step(&mut ops, &mut roots),
        Progress::Unknown,
        "lost authority must never recover from empty bookkeeping"
    );
    assert_eq!(ops.empty, 0);
}

struct Qualifier {
    fail: Option<&'static str>,
    steps: Vec<&'static str>,
}
impl Qualifier {
    fn result<T>(&mut self, name: &'static str, value: T) -> Result<T, Failure> {
        self.steps.push(name);
        if self.fail == Some(name) {
            Err(Failure::Errno(nix::libc::EPERM))
        } else {
            Ok(value)
        }
    }
}
impl QualificationOps for Qualifier {
    fn ids(&mut self) -> Result<(u32, u32), Failure> {
        self.result("ids", (42, 42))
    }
    fn single_thread(&mut self) -> Result<bool, Failure> {
        self.result("thread", true)
    }
    fn children_empty(&mut self) -> Result<bool, Failure> {
        self.result("proc", true)
    }
    fn no_children(&mut self) -> Result<Empty, Failure> {
        self.result("wait", Empty::Yes)
    }
    fn set_subreaper(&mut self) -> Result<(), Failure> {
        self.result("set", ())
    }
    fn get_subreaper(&mut self) -> Result<bool, Failure> {
        self.result("get", true)
    }
}
#[test]
fn adoption40_qualifies_all_preconditions_before_child_creation() {
    let mut ops = Qualifier {
        fail: None,
        steps: vec![],
    };
    assert!(qualify(&mut ops).is_ok());
    assert_eq!(ops.steps, ["ids", "thread", "proc", "wait", "set", "get"]);
}

fn ready_roots() -> RootModel {
    RootModel {
        live: false,
        unknown: false,
    }
}
fn owner() -> Adoption {
    Adoption::new(QualifiedHelper { pid: 42 })
}
#[test]
fn adoption40_denied_malformed_and_nonleader_identity_never_signal() {
    let statuses = [
        Err(nix::libc::EACCES),
        Ok(b"Pid: 7\nTgid: 8\nPPid: 42\n".to_vec()),
        Ok(b"Pid: 7\nTgid: 7\nPPid: 99\n".to_vec()),
        Ok(b"Pid: 7\nTgid: 7\nPPid: 42".to_vec()),
        Ok(b"Pid: 7\nTgid: 7\nPPid: 42\nPPid: 42\n".to_vec()),
    ];
    for status in statuses {
        let rejected = matches!(&status, Ok(bytes) if matches!(direct_child(bytes,7,42),Ok(false)));
        let mut ops = Model::new(&[b"7 ", b"7 "]);
        ops.status = Some(status);
        let mut owner = owner();
        let mut roots = ready_roots();
        let expected = if rejected {
            Progress::Pending
        } else {
            Progress::Unknown
        };
        assert_eq!(owner.step(&mut ops, &mut roots), expected);
        assert_eq!(owner.step(&mut ops, &mut roots), expected);
        assert_eq!(owner.failed(), !rejected);
        assert_eq!(
            (ops.opens, ops.signals, ops.reaps, ops.empty),
            (if rejected { 2 } else { 1 }, 0, 0, 0)
        );
    }
}
#[test]
fn adoption40_binary_name_and_long_groups_do_not_hide_parent_fields() {
    let mut ops = Model::new(&[b"7 "]);
    let mut bytes = b"Name: \xff\nPid: 7\nTgid: 7\nPPid: 42\nGroups: ".to_vec();
    bytes.resize(8192, b'1');
    ops.status = Some(Ok(bytes));
    assert_eq!(
        owner().step(&mut ops, &mut ready_roots()),
        Progress::Pending
    );
}
#[test]
fn adoption40_lost_child_wait_cannot_be_repaired_or_signal_reuse() {
    for final_wait in [false, true] {
        let mut ops = Model::new(&[b"7 "]);
        let mut owner = owner();
        let mut roots = ready_roots();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        if final_wait {
            ops.observations.push_back(Ok(Observation::Exited(9)));
            ops.reaped.push_back(Err(Failure::Errno(nix::libc::ECHILD)));
        } else {
            ops.observations
                .push_back(Err(Failure::Errno(nix::libc::ECHILD)));
        }
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Unknown);
        let counts = (ops.opens, ops.signals, ops.reaps, ops.empty);
        ops.observations.push_back(Ok(Observation::Exited(9)));
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Unknown);
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), counts);
    }
}
#[test]
fn adoption40_interruptions_do_not_release_candidate_or_prove_empty() {
    let mut ops = Model::new(&[b"7 ", b"", b""]);
    ops.observations.extend([
        Ok(Observation::Yielded),
        Ok(Observation::Running),
        Ok(Observation::Yielded),
        Ok(Observation::Exited(9)),
        Ok(Observation::Exited(9)),
    ]);
    ops.reaped.push_back(Ok(Reaped::Yielded));
    ops.empties.push_back(Ok(Empty::Yielded));
    let mut owner = owner();
    let mut roots = ready_roots();
    for _ in 0..6 {
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    }
    assert_eq!((ops.opens, ops.reaps, ops.empty), (1, 2, 1));
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
}
#[test]
fn adoption40_child_appearing_after_previous_exit_forces_new_census() {
    let mut ops = Model::new(&[b"7 ", b"8 ", b""]);
    let mut owner = owner();
    let mut roots = ready_roots();
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    ops.observations.push_back(Ok(Observation::Exited(9)));
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!((ops.opens, ops.reaps, ops.empty), (2, 1, 0));
    ops.observations.push_back(Ok(Observation::Exited(9)));
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
}
#[test]
fn adoption40_signal_errors_are_unknown_and_never_exit_receipts() {
    for errno in [nix::libc::EPERM, nix::libc::ENOSYS, nix::libc::ESRCH] {
        let mut ops = Model::new(&[b"7 ", b""]);
        ops.signal_error = Some(errno);
        let mut owner = owner();
        let mut roots = ready_roots();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Unknown);
        assert_eq!(ops.reaps, 0);
        assert!(owner.failed());
        ops.observations.push_back(Ok(Observation::Exited(9)));
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
        assert!(
            owner.failed(),
            "physical proof does not erase earlier fault"
        );
    }
}
#[test]
fn adoption40_unowned_missing_candidate_refreshes_without_cleanup_failure() {
    for errno in [nix::libc::ENOENT, nix::libc::ESRCH] {
        let mut ops = Model::new(&[b"7 ", b"", b""]);
        ops.open_error = Some(errno);
        ops.empties.extend([Ok(Empty::No), Ok(Empty::Yes)]);
        let mut owner = owner();
        let mut roots = ready_roots();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!((ops.signals, ops.reaps, ops.empty), (0, 0, 0));
        assert_eq!(
            owner.step(&mut ops, &mut roots),
            Progress::Pending,
            "a fresh empty proc list without ECHILD does not prove completion"
        );
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
        assert!(
            !owner.failed(),
            "stale unowned number is ordinary census churn"
        );
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (1, 0, 0, 2));
    }
}
#[test]
fn adoption40_buffered_registered_root_may_settle_before_unowned_capture() {
    for disappeared in [true, false] {
        let mut ops = Model::new(&[b"7 7 ", b""]);
        let mut roots = RootModel {
            live: true,
            unknown: false,
        };
        let mut owner = owner();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!(ops.opens, 0, "registered root keeps exclusive wait custody");
        roots.live = false; // Actual root owner has completed and reaped it.
        if disappeared {
            ops.open_error = Some(nix::libc::ENOENT);
        } else {
            ops.status = Some(Ok(b"Pid: 7\nTgid: 7\nPPid: 99\n".to_vec()));
        }
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
        assert!(!owner.failed());
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (1, 0, 0, 1));
    }
}
#[test]
fn adoption40_unproved_status_disappearance_refreshes_without_custody() {
    for errno in [nix::libc::ENOENT, nix::libc::ESRCH] {
        let mut ops = Model::new(&[b"7 ", b"", b""]);
        ops.status = Some(Err(errno));
        ops.empties.extend([Ok(Empty::No), Ok(Empty::Yes)]);
        let mut owner = owner();
        let mut roots = ready_roots();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!((ops.signals, ops.reaps, ops.empty), (0, 0, 0));
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
        assert!(!owner.failed());
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (1, 0, 0, 2));
    }
}
#[test]
fn adoption40_denied_unowned_capture_stays_failed_even_after_fresh_physical_proof() {
    for errno in [nix::libc::EACCES, nix::libc::EPERM, nix::libc::ENOSYS] {
        let mut ops = Model::new(&[b"7 ", b""]);
        ops.open_error = Some(errno);
        let mut owner = owner();
        let mut roots = ready_roots();
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Unknown);
        assert!(owner.failed());
        assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
        assert!(owner.failed());
        assert_eq!((ops.signals, ops.reaps, ops.empty), (0, 0, 1));
    }
}
#[test]
fn adoption40_qualification_failures_stop_before_child_creation() {
    for stage in ["ids", "thread", "proc", "wait", "set", "get"] {
        let mut ops = Qualifier {
            fail: Some(stage),
            steps: vec![],
        };
        assert!(qualify(&mut ops).is_err());
        assert_eq!(ops.steps.last(), Some(&stage));
    }
}

#[test]
fn adoption40_parser_is_bounded_streaming_and_interrupt_preserves_partial_token() {
    struct Interrupted {
        data: Cursor<Vec<u8>>,
        interrupt: bool,
    }
    impl Read for Interrupted {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupt {
                self.interrupt = false;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            self.interrupt = true;
            self.data.read(&mut bytes[..1])
        }
    }
    let mut list = Census {
        reader: Box::new(Interrupted {
            data: Cursor::new(b"123 ".to_vec()),
            interrupt: false,
        }),
        bytes: [0; 4096],
        pos: 0,
        end: 0,
        token: 0,
        digits: 0,
        roots_settled: true,
    };
    assert!(matches!(list.next(), Ok(Token::Yielded)));
    assert!(matches!(list.next(), Ok(Token::Yielded)));
    assert!(matches!(list.next(), Ok(Token::Yielded)));
    assert!(matches!(list.next(), Ok(Token::Pid(123))));
    let mut bytes = vec![b' '; 8192];
    bytes.extend_from_slice(b"7 ");
    list.reader = Box::new(Cursor::new(bytes));
    list.pos = 0;
    list.end = 0;
    assert!(matches!(list.next(), Ok(Token::Yielded)));
    assert!(matches!(list.next(), Ok(Token::Yielded)));
    assert!(matches!(list.next(), Ok(Token::Pid(7))));
}
#[test]
fn adoption40_malformed_census_and_final_wait_denial_never_complete() {
    for bytes in [
        b"0 ".as_slice(),
        b"4294967296 ",
        b"2147483648 ",
        b"7x ",
        b"-7 ",
    ] {
        let mut ops = Model::new(&[bytes]);
        assert_eq!(
            owner().step(&mut ops, &mut ready_roots()),
            Progress::Unknown
        );
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (0, 0, 0, 0));
    }
    let mut ops = Model::new(&[b"", b""]);
    ops.empties.push_back(Err(Failure::Errno(nix::libc::EPERM)));
    let mut owner = owner();
    assert_eq!(owner.step(&mut ops, &mut ready_roots()), Progress::Unknown);
    assert_eq!(owner.step(&mut ops, &mut ready_roots()), Progress::Complete);
    assert!(owner.failed());
}
#[test]
fn adoption40_racy_empty_list_is_not_no_child_proof() {
    let mut ops = Model::new(&[b"", b"7 ", b""]);
    ops.empties.push_back(Ok(Empty::No));
    let mut owner = owner();
    let mut roots = ready_roots();
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    ops.observations.push_back(Ok(Observation::Exited(9)));
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Complete);
}

#[test]
fn adoption40_positive_outside_identity_retries_fresh_census_without_owning_foreign_process() {
    let mut ops = Model::new(&[b"7 ", b""]);
    ops.status = Some(Ok(b"Pid: 7\nTgid: 7\nPPid: 99\n".to_vec()));
    let mut owner = owner();
    let mut roots = ready_roots();
    assert_eq!(owner.step(&mut ops, &mut roots), Progress::Pending);
    assert_eq!(
        owner.step(&mut ops, &mut roots),
        Progress::Complete,
        "fresh ECHILD proves our tree empty; outside identity is not our child owner"
    );
    assert_eq!((ops.signals, ops.reaps, ops.empty), (0, 0, 1));
    assert!(
        !owner.failed(),
        "positive foreign identity grants no custody or cleanup fault"
    );
}

#[test]
fn adoption40_contradictory_qualification_never_produces_a_token() {
    struct Invalid(&'static str);
    impl QualificationOps for Invalid {
        fn ids(&mut self) -> Result<(u32, u32), Failure> {
            Ok(if self.0 == "identity" {
                (42, 43)
            } else {
                (42, 42)
            })
        }
        fn single_thread(&mut self) -> Result<bool, Failure> {
            Ok(self.0 != "thread")
        }
        fn children_empty(&mut self) -> Result<bool, Failure> {
            Ok(self.0 != "proc")
        }
        fn no_children(&mut self) -> Result<Empty, Failure> {
            Ok(if self.0 == "wait" {
                Empty::No
            } else if self.0 == "interrupted" {
                Empty::Yielded
            } else {
                Empty::Yes
            })
        }
        fn set_subreaper(&mut self) -> Result<(), Failure> {
            Ok(())
        }
        fn get_subreaper(&mut self) -> Result<bool, Failure> {
            Ok(self.0 != "get")
        }
    }
    for stage in ["identity", "thread", "proc", "wait", "interrupted", "get"] {
        assert!(qualify(&mut Invalid(stage)).is_err());
    }
}
