#[cfg(target_os = "linux")]
mod adoption_parent {
    use super::*;
    use crate::process_scope::{
        adoption::{self, Adoption, AdoptionOps, Empty, Observation, QualificationOps, Reaped},
        scope::ReservedRoot,
        Failure, Operations,
    };
    use std::{
        collections::VecDeque,
        io::{Cursor, Read},
        num::NonZeroU32,
    };
    struct Ops {
        lists: VecDeque<Vec<u8>>,
        opens: usize,
        signals: usize,
        reaps: usize,
        empty: usize,
        killed: bool,
    }
    impl QualificationOps for Ops {
        fn ids(&mut self) -> Result<(u32, u32), Failure> {
            Ok((42, 42))
        }
        fn single_thread(&mut self) -> Result<bool, Failure> {
            Ok(true)
        }
        fn children_empty(&mut self) -> Result<bool, Failure> {
            Ok(true)
        }
        fn no_children(&mut self) -> Result<Empty, Failure> {
            Ok(Empty::Yes)
        }
        fn set_subreaper(&mut self) -> Result<(), Failure> {
            Ok(())
        }
        fn get_subreaper(&mut self) -> Result<bool, Failure> {
            Ok(true)
        }
    }
    impl Operations for Ops {
        fn stat(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            unreachable!()
        }
        fn status(&mut self, _: &OwnedFd) -> Result<Vec<u8>, Failure> {
            Ok(b"Pid: 7\nTgid: 7\nPPid: 42\n".to_vec())
        }
        fn signal(&mut self, _: &OwnedFd, signal: i32) -> Result<(), Failure> {
            assert_eq!(signal, nix::libc::SIGKILL);
            self.signals += 1;
            self.killed = true;
            Ok(())
        }
    }
    impl AdoptionOps for Ops {
        fn census(&mut self) -> Result<Box<dyn Read>, Failure> {
            Ok(Box::new(Cursor::new(
                self.lists.pop_front().expect("fresh census"),
            )))
        }
        fn open_child(&mut self, pid: u32) -> Result<OwnedFd, Failure> {
            assert_eq!(pid, 7, "the protected worker root must never be acquired");
            self.opens += 1;
            Ok(std::fs::File::open("/dev/null").unwrap().into())
        }
        fn observe_child(&mut self, pid: u32) -> Result<Observation, Failure> {
            assert_eq!(pid, 7);
            Ok(if self.killed {
                Observation::Exited(9)
            } else {
                Observation::Running
            })
        }
        fn reap_child(&mut self, pid: u32) -> Result<Reaped, Failure> {
            assert_eq!(pid, 7);
            self.reaps += 1;
            Ok(Reaped::Exited(9))
        }
        fn no_children(&mut self) -> Result<Empty, Failure> {
            self.empty += 1;
            Ok(Empty::Yes)
        }
    }
    fn model(lists: &[&[u8]]) -> (Adoption, Ops) {
        let mut ops = Ops {
            lists: lists.iter().map(|x| x.to_vec()).collect(),
            opens: 0,
            signals: 0,
            reaps: 0,
            empty: 0,
            killed: false,
        };
        let owner = Adoption::new(adoption::qualify(&mut ops).unwrap());
        (owner, ops)
    }
    fn state() -> LoopState {
        let mut state = state_with_login(&my_account(), [40; 16]);
        state.stopping = true;
        state
    }
    #[test]
    fn adoption40_parent_protects_live_worker_and_requires_new_post_release_census() {
        let (mut owner, mut ops) = model(&[b"42 7 ", b"", b""]);
        let state = state();
        let root = ReservedRoot::Owned(NonZeroU32::new(42).unwrap());
        for _ in 0..5 {
            assert_eq!(
                advance_adoption(&state, root, &mut owner, &mut ops),
                adoption::Progress::Pending
            );
        }
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (1, 1, 1, 0));
        assert_eq!(
            advance_adoption(&state, ReservedRoot::Released, &mut owner, &mut ops),
            adoption::Progress::Complete
        );
        assert_eq!(ops.empty, 1);
    }
    #[test]
    fn adoption40_parent_lost_worker_never_becomes_released_from_later_projection() {
        let (mut owner, mut ops) = model(&[b""]);
        let state = state();
        assert_eq!(
            advance_adoption(&state, ReservedRoot::Lost, &mut owner, &mut ops),
            adoption::Progress::Unknown
        );
        assert_eq!(
            advance_adoption(&state, ReservedRoot::Released, &mut owner, &mut ops),
            adoption::Progress::Unknown
        );
        assert_eq!((ops.opens, ops.signals, ops.reaps, ops.empty), (0, 0, 0, 0));
    }
    #[test]
    fn adoption40_parent_never_scans_before_stopping_or_with_missing_monitor_owner() {
        let (mut owner, mut ops) = model(&[b""]);
        let mut state = state();
        state.stopping = false;
        assert_eq!(
            advance_adoption(&state, ReservedRoot::Released, &mut owner, &mut ops),
            adoption::Progress::Pending
        );
        state.stopping = true;
        state.retired.insert(owner_for(&state, [40; 16]));
        assert_eq!(
            advance_adoption(&state, ReservedRoot::Released, &mut owner, &mut ops),
            adoption::Progress::Pending
        );
        assert_eq!(ops.lists.len(), 1);
        assert_eq!(ops.empty, 0);
    }
    #[test]
    fn adoption40_reaped_running_owes_exit_outcome_but_has_real_cleanup() {
        let mut state = state();
        let owner = owner_for(&state, [40; 16]);
        state.live.insert(1, ChannelSlot::ReapedRunning(owner));
        assert_eq!(
            ChannelReceiptDebt::from_state(&state),
            ChannelReceiptDebt {
                cleanup: 0,
                exit: 1
            }
        );
    }
    #[test]
    fn adoption40_unreceived_channel_cleanup_and_exit_are_separate_debts() {
        let mut state = state();
        let owner = owner_for(&state, [40; 16]);
        state.live.insert(1, ChannelSlot::Starting(owner));
        state.live.insert(2, ChannelSlot::Running(owner));
        state.live.insert(3, ChannelSlot::Cleaning(owner));
        assert_eq!(
            ChannelReceiptDebt::from_state(&state),
            ChannelReceiptDebt {
                cleanup: 3,
                exit: 1
            }
        );
    }
}
