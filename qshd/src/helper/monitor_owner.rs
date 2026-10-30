//! Exact monitor child custody and one private record per bounded pass.

use super::{protocol::MonitorEvent, shell_owner::ShellOwner, worker_control};
use crate::process_scope::{
    scope::{LeaderStatus, Progress},
    QualifiedProc,
};
use std::{io, num::NonZeroU32, os::unix::net::UnixStream, time::Instant};

pub(super) struct Established(u32);
impl Established {
    pub(super) fn sid(&self) -> u32 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Protocol,
    Request(super::protocol::RequestDrainFailure),
    Stream(i32),
    LostAuthority,
    Signal(i32, i32),
}
pub(super) struct Advance {
    pub leader: LeaderStatus,
    pub event: Option<MonitorEvent>,
    pub native: Progress,
    pub failure: Option<Failure>,
    pub signal_failure: Option<(i32, i32)>,
}
#[must_use = "retain exact monitor custody until actual native settlement"]
pub(super) struct NativeMonitor {
    child: ShellOwner,
    pid: NonZeroU32,
    seam: UnixStream,
    established: bool,
    ambiguous: bool,
    closed: bool,
    failure: Option<Failure>,
    signal_failure: Option<(i32, i32)>,
    stop_at: Option<Instant>,
    completed: Option<i32>,
    leader_exited: bool,
    producer_drained: bool,
}
impl NativeMonitor {
    /// Infallible first successful-fork parent action. Qualified proc and the
    /// private credential-enabled socket pair must be prepared before fork.
    pub(super) fn new(pid: NonZeroU32, view: QualifiedProc, seam: UnixStream) -> Self {
        Self {
            child: ShellOwner::new(pid, view),
            pid,
            seam,
            established: false,
            ambiguous: false,
            closed: false,
            failure: None,
            signal_failure: None,
            stop_at: None,
            completed: None,
            leader_exited: false,
            producer_drained: false,
        }
    }
    pub(super) fn seam(&self) -> &UnixStream {
        &self.seam
    }
    pub(super) fn closed(&self) -> bool {
        self.closed
    }
    /// An empty receive begun after original-producer exit. Inherited socket
    /// writers need not reach EOF before its queued outcomes are exhausted.
    pub(super) fn producer_drained(&self) -> bool {
        self.producer_drained
    }
    pub(super) fn leader(&mut self) -> LeaderStatus {
        let status = self.child.leader();
        self.leader_exited |= matches!(status, LeaderStatus::Exited(_));
        status
    }
    pub(super) fn leader_exited(&self) -> bool {
        self.leader_exited
    }
    /// Explicit force is distinct from cooperative SHUT_WR on the seam.
    pub(super) fn force(&mut self, now: Instant) {
        self.stop_at.get_or_insert(now);
        self.child.request_stop();
        self.child.escalate();
    }
    pub(super) fn advance(&mut self, now: Instant) -> Advance {
        self.advance_with(now, worker_control::read_packet::<8192>)
    }
    fn advance_with(
        &mut self,
        now: Instant,
        read: impl FnOnce(&UnixStream) -> io::Result<worker_control::Packet<8192>>,
    ) -> Advance {
        if let Some(code) = self.completed {
            return Advance {
                leader: LeaderStatus::Exited(code),
                event: None,
                native: Progress::Complete(code),
                failure: self.failure,
                signal_failure: self.signal_failure,
            };
        }
        let leader = self.leader();
        if matches!(leader, LeaderStatus::Exited(_)) {
            // The leader is already gone; ordinary retained members now drain.
            // This does not turn a cooperative stop into force while PAM runs.
            self.child.request_stop();
            self.stop_at.get_or_insert(now);
        }
        if self.stop_at.is_some_and(|at| {
            now.saturating_duration_since(at) >= super::server::CLOSE_GRACE_PERIOD
        }) {
            self.child.escalate();
        }
        if leader == LeaderStatus::Unknown {
            self.failure.get_or_insert(Failure::LostAuthority);
        }
        let mut event = None;
        let mut empty = false;
        match read(&self.seam) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => empty = true,
            Err(error) => {
                self.ambiguous = true;
                self.failure.get_or_insert(Failure::Stream(
                    error.raw_os_error().unwrap_or(nix::libc::EIO),
                ));
            }
            Ok(packet) if packet.truncated || packet.ancillary => {
                self.ambiguous = true;
                self.failure.get_or_insert(Failure::Protocol);
            }
            Ok(packet) if packet.len == 0 && packet.sender.is_none() => {
                self.closed = true;
                empty = true;
            }
            Ok(packet) if packet.sender == Some(self.pid.get() as i32) => {
                match super::protocol::decode::<MonitorEvent>(&packet.bytes[..packet.len]) {
                    Ok(MonitorEvent::SessionEstablished { sid })
                        if sid == self.pid.get() && !self.established && !self.ambiguous =>
                    {
                        if self.child.establish_monitor(Established(sid)) {
                            self.established = true;
                        } else {
                            self.ambiguous = true;
                            self.failure.get_or_insert(Failure::LostAuthority);
                        }
                    }
                    Ok(MonitorEvent::SessionEstablished { .. }) => {
                        self.ambiguous = true;
                        self.failure.get_or_insert(Failure::Protocol);
                    }
                    Ok(record) if self.established => {
                        if let MonitorEvent::SessionClosed {
                            request_failure: Some(failure),
                            ..
                        } = &record
                        {
                            self.failure.get_or_insert(Failure::Request(*failure));
                        }
                        event = Some(record);
                    }
                    _ => {
                        self.ambiguous = true;
                        self.failure.get_or_insert(Failure::Protocol);
                    }
                }
            }
            Ok(_) => {
                self.ambiguous = true;
                self.failure.get_or_insert(Failure::Protocol);
            }
        }
        // Only a receive begun after nonreaping exit observation can discharge
        // the queue fence. An event, error, or EINTR is never an empty proof.
        self.producer_drained |= matches!(leader, LeaderStatus::Exited(_)) && empty;
        let native = if matches!(leader, LeaderStatus::Exited(_)) && empty {
            self.child.progress(self.closed && !self.ambiguous)
        } else {
            self.child.progress_without_reap()
        };
        if let Some((signal, errno)) = self.child.take_signal_failure() {
            self.signal_failure.get_or_insert((signal, errno));
            self.failure.get_or_insert(Failure::Signal(signal, errno));
        }
        let native = if !self.established && self.ambiguous {
            Progress::Unknown
        } else {
            native
        };
        if let Progress::Complete(code) = native {
            self.completed = Some(code);
        }
        Advance {
            leader,
            event,
            native,
            failure: self.failure,
            signal_failure: self.signal_failure,
        }
    }
}
#[cfg(test)]
mod tests {
    include!("monitor_owner_tests.rs");
}
