//! Fixed private helper/worker records; a record never proves native cleanup.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StopReason {
    Requested,
    ChannelLost,
    AuthLost,
    NoncePoolLost,
    RequiredTellLost,
    Protocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Settled {
    Joined,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkerCompletion {
    pub manager: Settled,
    /// Qualified producer fence, independently of the physical joined mask.
    /// A failed manager cannot certify all required tell producers settled.
    pub producers: Settled,
    pub runtime: Settled,
    pub started: u8,
    pub joined: u8,
    pub failed: u8,
    pub panicked: u8,
}
impl WorkerCompletion {
    pub(super) fn encode(self) -> Result<[u8; 8], Fault> {
        let status = |value| match value {
            Settled::Joined => 0,
            Settled::Failed => 1,
        };
        let bytes = [
            4,
            status(self.manager),
            status(self.producers),
            status(self.runtime),
            self.started,
            self.joined,
            self.failed,
            self.panicked,
        ];
        match decode(&bytes) {
            Ok(Frame::Drained(decoded)) if decoded == self => Ok(bytes),
            _ => Err(Fault::Protocol),
        }
    }
    /// Only reported worker domains; native cleanup/wait remains independent.
    pub(super) fn successful(self) -> bool {
        self.manager == Settled::Joined
            && self.producers == Settled::Joined
            && self.runtime == Settled::Joined
            && self.started == 15
            && self.joined == 15
            && self.failed == 0
            && self.panicked == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Frame {
    Stop(StopReason),
    SessionEstablished(u32),
    InitFailed(i32),
    Drained(WorkerCompletion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    Protocol,
    Os(i32),
    Truncated,
    Ancillary,
}

pub(super) fn decode(bytes: &[u8]) -> Result<Frame, Fault> {
    let settled = |value| match value {
        0 => Ok(Settled::Joined),
        1 => Ok(Settled::Failed),
        _ => Err(Fault::Protocol),
    };
    match bytes {
        [1, reason] => Ok(Frame::Stop(match reason {
            0 => StopReason::Requested,
            1 => StopReason::ChannelLost,
            2 => StopReason::AuthLost,
            3 => StopReason::NoncePoolLost,
            4 => StopReason::RequiredTellLost,
            5 => StopReason::Protocol,
            _ => return Err(Fault::Protocol),
        })),
        [kind @ (2 | 3), a, b, c, d] => {
            let value = i32::from_be_bytes([*a, *b, *c, *d]);
            if value <= 0 {
                return Err(Fault::Protocol);
            }
            Ok(if *kind == 2 {
                Frame::SessionEstablished(value as u32)
            } else {
                Frame::InitFailed(value)
            })
        }
        [4, manager, producers, runtime, started, joined, failed, panicked]
            if *started == 15
                && joined == started
                && (failed | panicked) & !started == 0
                && (*producers != 0 || (*manager == 0 && *failed == 0 && *panicked == 0)) =>
        {
            Ok(Frame::Drained(WorkerCompletion {
                manager: settled(*manager)?,
                producers: settled(*producers)?,
                runtime: settled(*runtime)?,
                started: *started,
                joined: *joined,
                failed: *failed,
                panicked: *panicked,
            }))
        }
        _ => Err(Fault::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker40_completion_encoder_checks_masks_and_preserves_failed_joined_domains() {
        let completion = WorkerCompletion {
            manager: Settled::Failed,
            producers: Settled::Failed,
            runtime: Settled::Joined,
            started: 15,
            joined: 15,
            failed: 2,
            panicked: 4,
        };
        assert_eq!(completion.encode(), Ok([4, 1, 1, 0, 15, 15, 2, 4]));
        for invalid in [
            WorkerCompletion {
                started: 7,
                ..completion
            },
            WorkerCompletion {
                joined: 7,
                ..completion
            },
            WorkerCompletion {
                failed: 16,
                ..completion
            },
            WorkerCompletion {
                panicked: 16,
                ..completion
            },
        ] {
            assert_eq!(invalid.encode(), Err(Fault::Protocol));
        }
    }

    #[test]
    fn worker40_completion_cannot_claim_a_clean_producer_fence_after_failure() {
        for bytes in [
            [4, 1, 0, 0, 15, 15, 0, 0],
            [4, 0, 0, 0, 15, 15, 2, 0],
            [4, 0, 0, 0, 15, 15, 0, 4],
        ] {
            assert_eq!(decode(&bytes), Err(Fault::Protocol));
        }
    }

    #[test]
    fn worker40_fixed_frames_decode_exact_bounded_values() {
        assert_eq!(decode(&[1, 0]), Ok(Frame::Stop(StopReason::Requested)));
        assert_eq!(decode(&[2, 0, 0, 1, 7]), Ok(Frame::SessionEstablished(263)));
        assert_eq!(decode(&[3, 0, 0, 0, 13]), Ok(Frame::InitFailed(13)));
        assert_eq!(
            decode(&[4, 0, 0, 0, 15, 15, 0, 0]),
            Ok(Frame::Drained(WorkerCompletion {
                manager: Settled::Joined,
                producers: Settled::Joined,
                runtime: Settled::Joined,
                started: 15,
                joined: 15,
                failed: 0,
                panicked: 0,
            }))
        );
    }

    #[test]
    fn worker40_frames_reject_unknown_status_or_impossible_role_custody() {
        for frame in [
            vec![],
            vec![1],
            vec![1, 6],
            vec![1, 0, 0],
            vec![2, 0, 0, 0, 0],
            vec![2, 128, 0, 0, 0],
            vec![3, 0, 0, 0, 0],
            vec![3, 255, 255, 255, 255],
            vec![4, 2, 0, 0, 15, 15, 0, 0],
            vec![4, 0, 2, 0, 15, 15, 0, 0],
            vec![4, 0, 0, 2, 15, 15, 0, 0],
            vec![4, 0, 0, 0, 15, 7, 0, 0],
            vec![4, 0, 0, 0, 31, 31, 0, 0],
            vec![4, 0, 0, 0, 15, 15, 16, 0],
            vec![4, 0, 0, 0, 15, 15, 0, 16],
            vec![4, 0, 0, 0, 3, 3, 4, 0],
            vec![4, 0, 0, 0, 3, 3, 0, 4],
        ] {
            assert_eq!(decode(&frame), Err(Fault::Protocol), "{frame:?}");
        }
    }
}
