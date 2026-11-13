//! One channel ordering for authoritative parsing, raw history and replies.
use super::{
    engine::InputSubmission,
    screen_control::{ControlChannel, ControlPoll, ControlWake},
    writer::{WriterError, WriterShared},
};
use crate::screen_budget::ScreenEnvelope;
use std::{
    io::Read,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};
use transport::{
    channel_geometry::GeometryRecord,
    shell_server::{ResizeHandle, SessionScreen},
};
pub(super) struct OutputModel {
    pub screen: Box<dyn SessionScreen>,
    pub resize: Box<dyn ResizeHandle>,
    pub envelope: Option<ScreenEnvelope>,
}
enum PendingReply {
    Batch(Vec<u8>),
    Submitted(InputSubmission),
}
pub(super) struct OutputState {
    pub bytes: Vec<u8>,
    pub start: u64,
    pub closed: bool,
    pub eof: bool,
    pub failed: bool,
    pub model: Option<OutputModel>,
    pub has_screen: bool,
    pub busy: bool,
    pub geometry: GeometryRecord,
    pub geometry_start: u64,
    pending: Option<PendingReply>,
}
impl OutputState {
    pub(super) fn new(bytes: Vec<u8>, geometry: GeometryRecord) -> Self {
        Self {
            bytes,
            start: 0,
            closed: false,
            eof: false,
            failed: false,
            model: None,
            has_screen: false,
            busy: false,
            geometry,
            geometry_start: 0,
            pending: None,
        }
    }
    pub(super) fn replies_pending(&self) -> bool {
        self.pending.is_some()
    }
    fn retain_replies(&mut self, replies: Vec<u8>) {
        assert!(self.pending.is_none());
        if replies.len() > 65536 || replies.capacity() > 65536 {
            self.failed = true;
            return;
        }
        if !replies.is_empty() {
            self.pending = Some(PendingReply::Batch(replies));
        }
    }
}
pub(super) struct SharedOutput {
    pub state: Mutex<OutputState>,
    pub changed: Condvar,
    pub capacity: usize,
    pub writer: Option<Arc<WriterShared>>,
    pub wake: ControlWake,
}
impl SharedOutput {
    /// One bounded transition, never wait for a mailbox while holding this lock.
    pub(super) fn drain_reply(&self, state: &mut OutputState) -> Result<bool, WriterError> {
        if state.failed || state.closed {
            return Err(WriterError::Closed);
        }
        let Some(pending) = state.pending.take() else {
            return Ok(false);
        };
        let Some(writer) = &self.writer else {
            state.failed = true;
            return Err(WriterError::Closed);
        };
        match pending {
            PendingReply::Batch(bytes) => match writer.reply(&bytes) {
                Ok(submission) => {
                    drop(bytes);
                    state.pending = Some(PendingReply::Submitted(submission));
                }
                Err(WriterError::Busy) => {
                    state.pending = Some(PendingReply::Batch(bytes));
                }
                Err(e) => {
                    state.pending = Some(PendingReply::Batch(bytes));
                    state.failed = true;
                    return Err(e);
                }
            },
            PendingReply::Submitted(submission) => match submission.try_accepted() {
                None => state.pending = Some(PendingReply::Submitted(submission)),
                Some(Ok(_)) => {
                    self.changed.notify_all();
                }
                Some(Err(e)) => {
                    state.pending = Some(PendingReply::Submitted(submission));
                    state.failed = true;
                    return Err(e);
                }
            },
        }
        Ok(state.pending.is_some())
    }
    pub(super) fn retain_replies(&self, state: &mut OutputState, replies: Vec<u8>) {
        state.retain_replies(replies);
        self.wake.wake();
    }
}
impl ControlChannel for SharedOutput {
    fn service(&self, now: Instant) -> ControlPoll {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.failed || state.busy {
            return ControlPoll::default();
        }
        if state.pending.is_some() {
            let busy = self.drain_reply(&mut state).unwrap_or(false);
            return ControlPoll {
                deadline: None,
                busy,
            };
        }
        if let Some(model) = state.model.as_mut() {
            if model.screen.sync_deadline().is_some_and(|d| d <= now) {
                match model.screen.flush_due_output(now) {
                    Ok(replies) => state.retain_replies(replies),
                    Err(_) => state.failed = true,
                }
            }
        }
        ControlPoll {
            deadline: state.model.as_ref().and_then(|m| m.screen.sync_deadline()),
            busy: state.pending.is_some(),
        }
    }
}
pub(super) fn read_output(
    mut reader: Box<dyn Read + Send>,
    output: Arc<SharedOutput>,
    mut buffer: Vec<u8>,
) {
    loop {
        let allowance = {
            let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if state.closed || state.failed || !output.wake.healthy() {
                    if !output.wake.healthy() {
                        state.failed = true;
                    }
                    return;
                }
                let pending = output.drain_reply(&mut state).unwrap_or(true);
                if !state.busy
                    && !pending
                    && (state.has_screen || state.bytes.len() < output.capacity)
                {
                    break;
                }
                if pending {
                    output.wake.wake();
                    state = output
                        .changed
                        .wait_timeout(state, Duration::from_millis(10))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                } else {
                    state = output
                        .changed
                        .wait(state)
                        .unwrap_or_else(|e| e.into_inner());
                }
            }
            if state.has_screen {
                buffer.len()
            } else {
                buffer.len().min(output.capacity - state.bytes.len())
            }
        };
        // Only blocking native Read, always outside all model/control/custody locks.
        match reader.read(&mut buffer[..allowance]) {
            Ok(0) => {
                output.state.lock().unwrap_or_else(|e| e.into_inner()).eof = true;
                return;
            }
            Ok(n) => {
                let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
                while !state.closed && !state.failed && (state.busy || state.pending.is_some()) {
                    output.wake.wake();
                    state = output
                        .changed
                        .wait_timeout(state, Duration::from_millis(10))
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                    let _ = output.drain_reply(&mut state);
                }
                if state.closed || state.failed {
                    return;
                }
                if state
                    .start
                    .checked_add(state.bytes.len() as u64)
                    .and_then(|v| v.checked_add(n as u64))
                    .is_none()
                {
                    state.failed = true;
                    return;
                }
                if let Some(model) = state.model.as_mut() {
                    match model.screen.absorb(&buffer[..n]) {
                        Ok(replies) => state.retain_replies(replies),
                        Err(_) => {
                            state.failed = true;
                            output.wake.wake();
                            return;
                        }
                    }
                }
                if state.has_screen {
                    let skip = n.saturating_sub(output.capacity);
                    let remove = (state.bytes.len() + n - skip).saturating_sub(output.capacity);
                    state.bytes.drain(..remove);
                    state.start += (remove + skip) as u64;
                    state.bytes.extend_from_slice(&buffer[skip..n]);
                } else {
                    state.bytes.extend_from_slice(&buffer[..n]);
                }
                output.wake.wake();
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                output
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .failed = true;
                return;
            }
        }
    }
}
/// Moves the actual model out while preserving a parked ordering slot. Host
/// admission/native resize/serialization then run without a model mutex guard.
pub(super) struct ModelOperation {
    pub model: Option<OutputModel>,
    pub effect: Option<(GeometryRecord, u64, bool)>,
    output: Arc<SharedOutput>,
}
impl ModelOperation {
    pub(super) fn take(output: &Arc<SharedOutput>) -> Result<Self, WriterError> {
        let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.failed || state.busy || output.drain_reply(&mut state)? {
            return Err(WriterError::Busy);
        }
        let model = state.model.take().ok_or(WriterError::Busy)?;
        state.busy = true;
        Ok(Self {
            model: Some(model),
            effect: None,
            output: output.clone(),
        })
    }
}
impl Drop for ModelOperation {
    fn drop(&mut self) {
        let mut state = self.output.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((geometry, start, completed)) = self.effect {
            state.geometry = geometry;
            state.geometry_start = start;
            if !completed {
                state.failed = true;
            }
        }
        state.model = self.model.take();
        state.busy = false;
        drop(state);
        self.output.changed.notify_all();
        self.output.wake.wake();
    }
}
