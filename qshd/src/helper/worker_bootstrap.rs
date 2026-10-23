//! Linux owned split preparation and explicit private publication.

use super::worker_control::{self, PendingFrame, Sent};
use super::worker_owner::WorkerOwner;
use super::worker_protocol::Fault;
use crate::process_scope::QualifiedProc;
use std::{
    io,
    num::NonZeroU32,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

pub(super) struct Prepared {
    view: QualifiedProc,
    parent: UnixStream,
    child: UnixStream,
    deadline: Instant,
}
impl Prepared {
    pub(super) fn new(timeout: Duration) -> anyhow::Result<Self> {
        let view = crate::process_scope::prepare().map_err(anyhow::Error::msg)?;
        let (parent, child) = worker_control::pair()?;
        Ok(Self {
            view,
            parent,
            child,
            deadline: Instant::now() + timeout,
        })
    }
    pub(super) fn parent(self, pid: NonZeroU32) -> WorkerOwner {
        let owner = WorkerOwner::new(pid, self.view, self.parent, self.deadline);
        drop(self.child);
        owner
    }
    pub(super) fn child(self) -> Publisher {
        drop(self.view);
        drop(self.parent);
        Publisher::new(self.child)
    }
}

pub(super) struct Publisher {
    socket: UnixStream,
    final_started: bool,
    stage_attempted: bool,
    failure: Option<Fault>,
}
impl Publisher {
    pub(super) fn new(socket: UnixStream) -> Self {
        Self {
            socket,
            final_started: false,
            stage_attempted: false,
            failure: None,
        }
    }
    pub(super) fn establish(&mut self) -> anyhow::Result<()> {
        if self.stage_attempted || self.final_started {
            anyhow::bail!("worker session stage already attempted");
        }
        self.stage_attempted = true;
        // This must precede privilege-drop/NSS and every descendant-producing
        // action. A failed stage never permits initialization to continue.
        let sid = nix::unistd::setsid()?;
        let mut bytes = [2, 0, 0, 0, 0];
        bytes[1..].copy_from_slice(&sid.as_raw().to_be_bytes());
        self.publish(&bytes)
            .map_err(|error| anyhow::anyhow!("worker session stage publication failed: {error:?}"))
    }
    pub(super) fn reader(&self) -> io::Result<UnixStream> {
        self.socket.try_clone()
    }
    fn publish(&mut self, bytes: &[u8]) -> Result<(), Fault> {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        use std::os::fd::AsFd;
        if let Some(error) = self.failure {
            return Err(error);
        }
        let mut pending = match PendingFrame::new(bytes) {
            Ok(pending) => pending,
            Err(error) => {
                self.failure = Some(error);
                return Err(error);
            }
        };
        loop {
            match pending.send(&self.socket) {
                Ok(Sent::Complete) => return Ok(()),
                Ok(Sent::Blocked | Sent::Yielded) => {}
                Err(error) => {
                    self.failure = Some(error);
                    return Err(error);
                }
            }
            // One owned fixed frame, one send attempt per pass. A poll timeout
            // only permits another attempt; it never proves delivery/cleanup.
            let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLOUT)];
            match poll(&mut descriptor, PollTimeout::from(20u16)) {
                Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                Err(error) => {
                    let error = Fault::Os(error as i32);
                    self.failure = Some(error);
                    return Err(error);
                }
            }
        }
    }
    pub(super) fn init_failed(&mut self, errno: i32) -> anyhow::Result<()> {
        if self.final_started {
            anyhow::bail!("a final worker record was already attempted");
        }
        self.final_started = true;
        let mut bytes = [3, 0, 0, 0, 0];
        bytes[1..].copy_from_slice(&errno.to_be_bytes());
        self.publish(&bytes)
            .map_err(|error| anyhow::anyhow!("worker initialization publication failed: {error:?}"))
    }
    pub(super) fn finish(
        &mut self,
        mut outcome: super::worker_drain::WorkerDrainOutcome,
    ) -> anyhow::Result<()> {
        if self.final_started {
            anyhow::bail!("a final worker record was already attempted");
        }
        self.final_started = true;
        let completion = outcome
            .completion()
            .ok_or_else(|| anyhow::anyhow!("worker local completion is unqualified"))?;
        let bytes = completion
            .encode()
            .map_err(|error| anyhow::anyhow!("invalid worker completion: {error:?}"))?;
        self.publish(&bytes)
            .map_err(|error| anyhow::anyhow!("worker completion publication failed: {error:?}"))?;
        outcome.into_result()
    }
}

#[cfg(test)]
#[path = "worker_bootstrap_tests.rs"]
mod tests;
