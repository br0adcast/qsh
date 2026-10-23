//! Exact verification-child custody, independent of its authentication verdict.

use std::io::{self, Read};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Instant;

use super::shell_owner::ShellOwner as SessionChildOwner;
use super::startup::{Failure, VerificationReader};
use crate::process_scope::{scope::Progress, QualifiedProc};

struct Report<'a>(&'a OwnedFd);
impl Read for Report<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        nix::unistd::read(self.0.as_raw_fd(), bytes).map_err(io::Error::from)
    }
}

#[must_use = "retain verification custody until actual scope completion and wait"]
pub(super) struct VerificationChild {
    owner: SessionChildOwner,
    reader: VerificationReader,
    stopping_since: Option<Instant>,
    authority_failed: bool,
    first_signal_failure: Option<(i32, i32)>,
}

pub(super) struct VerificationProgress {
    pub result: Option<Result<Vec<u8>, Failure>>,
    pub cleanup: Progress,
    pub signal_failure: Option<(i32, i32)>,
}

impl VerificationChild {
    /// Construct immediately in the successful fork parent. The proc view and
    /// nonblocking report descriptor must have been prepared before the fork.
    pub(super) fn new(pid: NonZeroU32, view: QualifiedProc, deadline: Instant) -> Self {
        let owner = SessionChildOwner::new(pid, view);
        Self {
            owner,
            reader: VerificationReader::new(pid.get(), deadline, super::protocol::MAX_MESSAGE_LEN),
            stopping_since: None,
            authority_failed: false,
            first_signal_failure: None,
        }
    }

    pub(super) fn readable(&self) -> bool {
        !self.reader.finished()
    }

    pub(super) fn poll(
        &mut self,
        report: &OwnedFd,
        stopping: bool,
        now: Instant,
    ) -> VerificationProgress {
        if stopping {
            self.reader.cancel();
        }
        // Queued stage must be processed even after cancel/deadline and before
        // observing/reaping the direct child or progressing any native scope.
        let update = self.reader.poll(&mut Report(report), now);
        if let Some(proof) = update.established {
            self.authority_failed |= !self.owner.establish(proof);
        }
        let result = if self.authority_failed {
            Some(Err(Failure::Protocol))
        } else {
            update.result
        };
        if stopping || result.is_some() {
            self.stopping_since.get_or_insert(now);
            self.owner.request_stop();
            if stopping || matches!(result, Some(Err(Failure::TimedOut | Failure::Cancelled))) {
                // Preserve forceful cancellation/timeout of this helper-owned
                // computation, after consuming any queued session stage.
                self.owner.escalate();
            }
        }
        if self.stopping_since.is_some_and(|started| {
            now.saturating_duration_since(started) >= super::server::CLOSE_GRACE_PERIOD
        }) {
            // Elapsed time chooses escalation; it never proves completion.
            self.owner.escalate();
        }
        let cleanup = self.owner.progress(self.reader.pre_session_terminal());
        let signal_failure = self
            .owner
            .take_signal_failure()
            .filter(|_| self.first_signal_failure.is_none());
        if let Some(failure) = signal_failure {
            self.first_signal_failure = Some(failure);
        }
        VerificationProgress {
            result,
            cleanup,
            signal_failure,
        }
    }
}
