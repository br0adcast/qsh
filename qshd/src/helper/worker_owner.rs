//! Reserved worker child and private records; no manager/service completion claim.

use super::shell_owner::ShellOwner;
use super::worker_control::{self, Received};
use super::worker_protocol::{Fault, Frame, WorkerCompletion};
use crate::process_scope::{
    scope::{LeaderStatus, Progress},
    QualifiedProc,
};
use std::{num::NonZeroU32, os::unix::net::UnixStream, time::Instant};

/// Only the retained child's complete private matching record creates this.
pub(super) struct Established(u32);
impl Established {
    pub(super) fn sid(&self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkerFailure {
    Protocol(Fault),
    TimedOut,
    Init(i32),
    MissingReceipt,
    LostAuthority,
    Signal { signal: i32, errno: i32 },
    DrainFailed,
}

pub(super) struct WorkerProgress {
    pub native: Progress,
    pub receipt: Option<WorkerCompletion>,
    pub failure: Option<WorkerFailure>,
    pub signal_failure: Option<(i32, i32)>,
}

#[must_use = "retain worker child and private record custody until qualified settlement"]
pub(super) struct WorkerOwner {
    child: ShellOwner,
    pid: NonZeroU32,
    seam: UnixStream,
    deadline: Instant,
    established: bool,
    ambiguous: bool,
    eof: bool,
    receipt: Option<WorkerCompletion>,
    init_failed: bool,
    failure: Option<WorkerFailure>,
    signal_failure: Option<(i32, i32)>,
}

impl WorkerOwner {
    /// Infallible immediate custody in the successful fork parent; qualified
    /// proc view and both credential-enabled private ends precede that fork.
    pub(super) fn new(
        pid: NonZeroU32,
        view: QualifiedProc,
        seam: UnixStream,
        deadline: Instant,
    ) -> Self {
        let child = ShellOwner::new(pid, view);
        Self {
            child,
            pid,
            seam,
            deadline,
            established: false,
            ambiguous: false,
            eof: false,
            receipt: None,
            init_failed: false,
            failure: None,
            signal_failure: None,
        }
    }
    pub(super) fn reserved_root(&self) -> crate::process_scope::scope::ReservedRoot {
        self.child.reserved_root()
    }
    pub(super) fn control_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.seam.as_fd()
    }
    pub(super) fn control_closed(&self) -> bool {
        self.eof
    }
    pub(super) fn terminal_received(&self) -> bool {
        self.receipt.is_some() || self.init_failed
    }
    pub(super) fn send_stop(
        &self,
        pending: &mut worker_control::PendingFrame,
    ) -> Result<worker_control::Sent, Fault> {
        pending.send(&self.seam)
    }
    pub(super) fn leader(&mut self) -> LeaderStatus {
        self.child.leader()
    }
    pub(super) fn cancel(&mut self) {
        self.child.request_stop();
    }
    /// Failed global drain only: this is physical cancellation, never a
    /// cooperative manager/auxiliary join receipt or a normal-stop timer.
    pub(super) fn force_failed_cleanup(&mut self) {
        self.child.request_stop();
        self.child.escalate();
    }
    pub(super) fn poll(&mut self, now: Instant) -> WorkerProgress {
        self.poll_with(now, worker_control::receive)
    }
    fn fail(&mut self, failure: WorkerFailure) {
        self.failure.get_or_insert(failure);
    }
    fn poll_with(
        &mut self,
        now: Instant,
        read: impl FnOnce(&UnixStream) -> Result<Received, Fault>,
    ) -> WorkerProgress {
        let before = self.child.leader();
        if before == LeaderStatus::Unknown {
            self.fail(WorkerFailure::LostAuthority);
        }
        if !self.established && now >= self.deadline {
            self.fail(WorkerFailure::TimedOut);
            self.cancel();
        }
        let received = read(&self.seam);
        // A read which STARTS after non-reaping exit observation can prove all
        // records from that terminated producer were consumed. A frame, EINTR,
        // or read error supplies no such proof, even after leader exit.
        let queue_drained = matches!(before, LeaderStatus::Exited(_));
        let queue_drained =
            queue_drained && matches!(&received, Ok(Received::Empty | Received::Eof));
        match received {
            Ok(Received::Frame { sender, frame }) if sender == self.pid.get() => match frame {
                Frame::SessionEstablished(sid)
                    if sid == self.pid.get()
                        && !self.established
                        && !self.ambiguous
                        && !self.init_failed =>
                {
                    if self.child.establish_worker(Established(sid)) {
                        self.established = true;
                    } else {
                        self.fail(WorkerFailure::LostAuthority);
                    }
                }
                Frame::Drained(receipt)
                    if self.established && self.receipt.is_none() && !self.init_failed =>
                {
                    if !receipt.successful() {
                        self.fail(WorkerFailure::DrainFailed);
                    }
                    self.receipt = Some(receipt)
                }
                Frame::InitFailed(errno) if !self.init_failed && self.receipt.is_none() => {
                    self.init_failed = true;
                    self.fail(WorkerFailure::Init(errno));
                }
                _ => {
                    self.ambiguous = true;
                    self.fail(WorkerFailure::Protocol(Fault::Protocol));
                }
            },
            Ok(Received::Eof) => {
                self.eof = true;
                if self.receipt.is_none() {
                    self.fail(WorkerFailure::MissingReceipt);
                }
            }
            Ok(Received::Empty | Received::Yielded) => {}
            Ok(Received::Frame { .. }) => {
                self.ambiguous = true;
                self.fail(WorkerFailure::Protocol(Fault::Protocol));
            }
            Err(failure) => {
                self.ambiguous = true;
                self.fail(WorkerFailure::Protocol(failure));
            }
        }
        let native = if queue_drained {
            self.child.progress(self.eof && !self.ambiguous)
        } else {
            self.child.progress_without_reap()
        };
        if let Some((signal, errno)) = self.child.take_signal_failure() {
            self.signal_failure.get_or_insert((signal, errno));
            self.fail(WorkerFailure::Signal { signal, errno });
        }
        let native = if self.ambiguous && !self.established {
            Progress::Unknown
        } else {
            native
        };
        WorkerProgress {
            native,
            receipt: self.receipt,
            failure: self.failure,
            signal_failure: self.signal_failure,
        }
    }
}

#[cfg(test)]
mod tests {
    include!("worker_owner_tests.rs");
}
