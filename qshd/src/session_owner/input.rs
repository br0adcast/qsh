//! Retained synchronous single-writer input. This component owns pending bytes
//! and their quota; it makes no attachment, authentication or process decision.
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Write};
use transport::session_resume::{checked_end, InputEpoch, InputPosition, MAX_RESUME_DATA};
use transport::{ChannelInputBudget, InputChunk, InputLimit, InputOrigin};

/// Metadata-only errors: never retain a backend message or input payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputError {
    WrongEpoch,
    Gap,
    PendingMismatch,
    Overflow,
    TooLarge,
    Quota(InputLimit),
    WriterFailed(io::ErrorKind),
}
impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for InputError {}
impl From<InputLimit> for InputError {
    fn from(error: InputLimit) -> Self {
        Self::Quota(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteProgress {
    Idle,
    Progress {
        origin: InputOrigin,
        written: usize,
        position: InputPosition,
    },
    Interrupted,
    WouldBlock,
}
struct Pending {
    chunk: InputChunk,
    consumed: usize,
    /// Network offset of the original charged chunk; unused for local replies.
    user_start: u64,
}
/// The engine's one writer worker must retain this ledger through detach/fence.
/// A partial write keeps the entire original chunk/permit until completion.
/// Dropping a failed ledger is cleanup, not an invitation to retry its writer.
pub struct InputLedger {
    budget: ChannelInputBudget,
    position: InputPosition,
    queue: VecDeque<Pending>,
    failed: Option<io::ErrorKind>,
}
impl fmt::Debug for InputLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputLedger")
            .field("position", &self.position)
            .field("queued_chunks", &self.queue.len())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl InputLedger {
    pub fn new(epoch: InputEpoch, budget: ChannelInputBudget) -> Self {
        Self {
            budget,
            position: InputPosition {
                epoch,
                accepted: 0,
                committed: 0,
            },
            queue: VecDeque::new(),
            failed: None,
        }
    }
    pub fn position(&self) -> InputPosition {
        self.position
    }
    fn writable(&self) -> Result<(), InputError> {
        self.failed
            .map_or(Ok(()), |kind| Err(InputError::WriterFailed(kind)))
    }
    /// Validate the entire span, including all retained overlap, before quota
    /// admission or copying only the previously unaccepted suffix.
    pub fn accept(
        &mut self,
        epoch: InputEpoch,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InputPosition, InputError> {
        if epoch != self.position.epoch {
            return Err(InputError::WrongEpoch);
        }
        let end = checked_end(offset, bytes.len()).map_err(|_| InputError::Overflow)?;
        if bytes.len() > MAX_RESUME_DATA {
            return Err(InputError::TooLarge);
        }
        self.writable()?;
        if offset > self.position.accepted {
            return Err(InputError::Gap);
        }
        if end <= self.position.committed {
            return Ok(self.position);
        }
        let overlap_start = offset.max(self.position.committed);
        let overlap_end = end.min(self.position.accepted);
        let mut compared = 0u64;
        if overlap_start < overlap_end {
            for pending in &self.queue {
                if pending.chunk.origin() != InputOrigin::Network {
                    continue;
                }
                let start = checked_end(pending.user_start, pending.consumed)
                    .map_err(|_| InputError::Overflow)?;
                let finish = checked_end(pending.user_start, pending.chunk.bytes().len())
                    .map_err(|_| InputError::Overflow)?;
                let from = overlap_start.max(start);
                let to = overlap_end.min(finish);
                if from >= to {
                    continue;
                }
                let incoming_from =
                    usize::try_from(from - offset).map_err(|_| InputError::Overflow)?;
                let incoming_to = usize::try_from(to - offset).map_err(|_| InputError::Overflow)?;
                let retained_from =
                    usize::try_from(from - pending.user_start).map_err(|_| InputError::Overflow)?;
                let retained_to =
                    usize::try_from(to - pending.user_start).map_err(|_| InputError::Overflow)?;
                if bytes[incoming_from..incoming_to]
                    != pending.chunk.bytes()[retained_from..retained_to]
                {
                    return Err(InputError::PendingMismatch);
                }
                compared = compared
                    .checked_add(to - from)
                    .ok_or(InputError::Overflow)?;
            }
            if compared != overlap_end - overlap_start {
                return Err(InputError::PendingMismatch);
            }
        }
        if end <= self.position.accepted {
            return Ok(self.position);
        }
        let suffix =
            usize::try_from(self.position.accepted - offset).map_err(|_| InputError::Overflow)?;
        if let Some(chunk) = self.budget.try_network_slice(&bytes[suffix..])? {
            self.queue.push_back(Pending {
                chunk,
                consumed: 0,
                user_start: self.position.accepted,
            });
            self.position.accepted = end;
        }
        Ok(self.position)
    }
    /// Internal replies obey the existing local64KiB quota, not a network record
    /// cap. They share FIFO order but have no user-input byte offsets.
    pub fn queue_reply(&mut self, bytes: &[u8]) -> Result<(), InputError> {
        self.writable()?;
        if bytes.is_empty() {
            return Ok(());
        }
        if let Some(chunk) = self.budget.try_local_reply_slice(bytes)? {
            self.queue.push_back(Pending {
                chunk,
                consumed: 0,
                user_start: 0,
            });
        }
        Ok(())
    }
    /// Attempt at most one concrete write. No quota or engine mutex spans I/O.
    /// A permanent error retains all debt and permanently refuses further writes.
    pub fn write_step(&mut self, writer: &mut dyn Write) -> Result<WriteProgress, InputError> {
        self.writable()?;
        let Some(pending) = self.queue.front_mut() else {
            return Ok(WriteProgress::Idle);
        };
        let remaining = &pending.chunk.bytes()[pending.consumed..];
        let origin = pending.chunk.origin();
        if origin == InputOrigin::Network {
            let start = checked_end(pending.user_start, pending.consumed)
                .map_err(|_| InputError::Overflow)?;
            let end = checked_end(self.position.committed, remaining.len())
                .map_err(|_| InputError::Overflow)?;
            if start != self.position.committed || end > self.position.accepted {
                return Err(InputError::Overflow);
            }
        }
        let result = writer.write(remaining);
        let written = match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                return Ok(WriteProgress::Interrupted)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(WriteProgress::WouldBlock)
            }
            Err(error) => {
                self.failed = Some(error.kind());
                return Err(InputError::WriterFailed(error.kind()));
            }
            Ok(0) => {
                self.failed = Some(io::ErrorKind::WriteZero);
                return Err(InputError::WriterFailed(io::ErrorKind::WriteZero));
            }
            Ok(n) if n > remaining.len() => {
                self.failed = Some(io::ErrorKind::InvalidData);
                return Err(InputError::WriterFailed(io::ErrorKind::InvalidData));
            }
            Ok(n) => n,
        };
        pending.consumed += written;
        if origin == InputOrigin::Network {
            // The complete remaining span was checked before calling the sink.
            self.position.committed =
                checked_end(self.position.committed, written).map_err(|_| InputError::Overflow)?;
        }
        if pending.consumed == pending.chunk.bytes().len() {
            self.queue.pop_front();
        }
        Ok(WriteProgress::Progress {
            origin,
            written,
            position: self.position,
        })
    }
}
#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
