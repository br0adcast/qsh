//! One retained writer, one precharged payload slot and independent control state.
use super::input::{InputError, InputLedger, WriteProgress};
use super::resources::StorageCharge;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::{Attachment, InputEpoch, InputPosition, MAX_RESUME_DATA};
use transport::{ChannelInputBudget, InputOrigin};
const PAYLOAD_BYTES: usize = 65536;
pub(super) const CONTROL_METADATA: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterError {
    Busy,
    Closed,
    Stale,
    WrongChannel,
    WrongEpoch,
    TooLarge,
    Exhausted,
    ResponseExpired,
    Input(InputError),
}
#[derive(Clone, Copy)]
struct Payload {
    ticket: u64,
    origin: InputOrigin,
    epoch: InputEpoch,
    offset: u64,
    len: usize,
}
#[derive(Clone, Copy)]
struct Barrier {
    ticket: u64,
    attachment: Attachment,
}
struct State {
    buffer: Vec<u8>,
    payload: Option<Payload>,
    response: Option<(u64, Result<InputPosition, WriterError>)>,
    next: u64,
    position: InputPosition,
    lease: Option<Attachment>,
    running: bool,
    closed: bool,
    barrier: Option<Barrier>,
    fenced: Option<(u64, Attachment, InputPosition)>,
    inflight: bool,
    failure: Option<InputError>,
    exhausted: bool,
}
pub(super) struct WriterShared {
    state: Mutex<State>,
    changed: Condvar,
    notify: tokio::sync::Notify,
    channel: ChannelInstance,
    // Last field: the backing above disappears before its allocation charge.
    charge: Arc<StorageCharge>,
}
pub struct InputSubmission {
    writer: Arc<WriterShared>,
    ticket: u64,
}
impl InputSubmission {
    /// Only ledger acceptance is an ACK. A lost receiver never cancels bytes.
    pub async fn accepted(self) -> Result<InputPosition, WriterError> {
        loop {
            let notification = self.writer.notify.notified();
            tokio::pin!(notification);
            notification.as_mut().enable();
            {
                let state = self.writer.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((ticket, result)) = state.response {
                    if ticket == self.ticket {
                        return result;
                    }
                    if ticket > self.ticket {
                        return Err(WriterError::ResponseExpired);
                    }
                }
                if state.closed && state.payload.is_none() {
                    return Err(WriterError::Closed);
                }
            }
            notification.await;
        }
    }
}
pub(super) struct WriterWorker {
    shared: Arc<WriterShared>,
    ledger: InputLedger,
}
impl WriterShared {
    pub(super) fn new(
        channel: ChannelInstance,
        epoch: InputEpoch,
        budget: ChannelInputBudget,
        charge: Arc<StorageCharge>,
    ) -> Result<(Arc<Self>, WriterWorker), WriterError> {
        if charge.bytes() < (PAYLOAD_BYTES + CONTROL_METADATA) as u64
            || std::mem::size_of::<Self>() > CONTROL_METADATA
        {
            return Err(WriterError::TooLarge);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(PAYLOAD_BYTES)
            .map_err(|_| WriterError::TooLarge)?;
        if buffer.capacity() > PAYLOAD_BYTES {
            return Err(WriterError::TooLarge);
        }
        buffer.resize(PAYLOAD_BYTES, 0);
        let ledger = InputLedger::new(epoch, budget);
        let position = ledger.position();
        let shared = Arc::new(Self {
            state: Mutex::new(State {
                buffer,
                payload: None,
                response: None,
                next: 0,
                position,
                lease: None,
                running: false,
                closed: false,
                barrier: None,
                fenced: None,
                inflight: false,
                failure: None,
                exhausted: false,
            }),
            changed: Condvar::new(),
            notify: tokio::sync::Notify::new(),
            channel,
            charge,
        });
        Ok((shared.clone(), WriterWorker { shared, ledger }))
    }
    fn ticket(state: &mut State) -> Result<u64, WriterError> {
        state.next = state.next.checked_add(1).ok_or(WriterError::Exhausted)?;
        Ok(state.next)
    }
    pub(super) fn submit(
        self: &Arc<Self>,
        attachment: Attachment,
        channel: ChannelInstance,
        epoch: InputEpoch,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InputSubmission, WriterError> {
        if channel != self.channel {
            return Err(WriterError::WrongChannel);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(WriterError::Closed);
        }
        if state.exhausted {
            return Err(WriterError::Exhausted);
        }
        if state.lease != Some(attachment) || !state.running {
            return Err(WriterError::Stale);
        }
        if state.position.epoch != epoch {
            return Err(WriterError::WrongEpoch);
        }
        self.enqueue(&mut state, InputOrigin::Network, epoch, offset, bytes)
    }
    pub(super) fn reply(self: &Arc<Self>, bytes: &[u8]) -> Result<InputSubmission, WriterError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(WriterError::Closed);
        }
        if state.exhausted {
            return Err(WriterError::Exhausted);
        }
        let epoch = state.position.epoch;
        self.enqueue(&mut state, InputOrigin::LocalReply, epoch, 0, bytes)
    }
    fn enqueue(
        self: &Arc<Self>,
        state: &mut State,
        origin: InputOrigin,
        epoch: InputEpoch,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InputSubmission, WriterError> {
        if let Some(failure) = state.failure {
            return Err(WriterError::Input(failure));
        }
        if state.payload.is_some() {
            return Err(WriterError::Busy);
        }
        if bytes.len()
            > if origin == InputOrigin::Network {
                MAX_RESUME_DATA
            } else {
                PAYLOAD_BYTES
            }
        {
            return Err(WriterError::TooLarge);
        }
        let ticket = Self::ticket(state)?;
        state.buffer[..bytes.len()].copy_from_slice(bytes);
        state.payload = Some(Payload {
            ticket,
            origin,
            epoch,
            offset,
            len: bytes.len(),
        });
        self.changed.notify_all();
        Ok(InputSubmission {
            writer: self.clone(),
            ticket,
        })
    }
    pub(super) fn channel(&self) -> ChannelInstance {
        self.channel
    }
    pub(super) fn assign(&self, attachment: Attachment) -> Result<(), WriterError> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.closed {
            return Err(WriterError::Closed);
        }
        if s.exhausted {
            return Err(WriterError::Exhausted);
        }
        if s.barrier.is_some() || s.inflight {
            return Err(WriterError::Busy);
        }
        s.lease = Some(attachment);
        s.running = false;
        Ok(())
    }
    pub(super) async fn wait_fence(
        &self,
        ticket: u64,
        attachment: Attachment,
    ) -> Result<InputPosition, WriterError> {
        loop {
            let notification = self.notify.notified();
            tokio::pin!(notification);
            notification.as_mut().enable();
            if let Some(position) = self.fence_result(ticket, attachment)? {
                return Ok(position);
            }
            notification.await;
        }
    }
    pub(super) fn resume(&self, attachment: Attachment) -> Result<(), WriterError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(WriterError::Closed);
        }
        if state.exhausted {
            return Err(WriterError::Exhausted);
        }
        if state.barrier.is_some()
            || (state.inflight && (state.lease != Some(attachment) || !state.running))
        {
            return Err(WriterError::Busy);
        }
        state.lease = Some(attachment);
        state.running = true;
        self.changed.notify_all();
        Ok(())
    }
    pub(super) fn request_fence(&self, attachment: Attachment) -> Result<u64, WriterError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed {
            return Err(WriterError::Closed);
        }
        if state.exhausted {
            return Err(WriterError::Exhausted);
        }
        if state.lease != Some(attachment) {
            return Err(WriterError::Stale);
        }
        if let Some(b) = state.barrier {
            return if b.attachment == attachment {
                Ok(b.ticket)
            } else {
                Err(WriterError::Busy)
            };
        }
        let ticket = match Self::ticket(&mut state) {
            Ok(t) => t,
            Err(error) => {
                state.running = false;
                state.exhausted = true;
                self.changed.notify_all();
                return Err(error);
            }
        };
        state.running = false;
        state.barrier = Some(Barrier { ticket, attachment });
        self.changed.notify_all();
        Ok(ticket)
    }
    pub(super) fn can_catalog(&self) -> bool {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !s.closed && !s.exhausted && s.failure.is_none()
    }
    pub(super) fn settled(&self) -> bool {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.barrier.is_none() && !s.inflight && !s.exhausted
    }
    pub(super) fn fence_result(
        &self,
        ticket: u64,
        attachment: Attachment,
    ) -> Result<Option<InputPosition>, WriterError> {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, a, p)) = s.fenced {
            if t == ticket && a == attachment {
                return Ok(Some(p));
            }
            if t > ticket {
                return Err(WriterError::ResponseExpired);
            }
        }
        if s.closed {
            return Err(WriterError::Closed);
        }
        if s.exhausted {
            return Err(WriterError::Exhausted);
        }
        Ok(None)
    }
    pub(super) fn position(&self) -> InputPosition {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .position
    }
    pub(super) fn close(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.closed = true;
        s.running = false;
        self.changed.notify_all();
        self.notify.notify_waiters();
    }
    pub(super) fn allow_release(&self) {
        self.charge.allow_release();
    }
}
impl WriterWorker {
    pub(super) fn run(mut self, mut writer: Box<dyn Write + Send>) {
        let mut pending = false;
        loop {
            let mut s = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            if s.closed {
                s.payload = None;
                s.buffer = Vec::new();
                self.shared.notify.notify_waiters();
                return;
            }
            if let Some(barrier) = s.barrier {
                if s.payload.is_none_or(|p| p.ticket > barrier.ticket) {
                    s.fenced = Some((barrier.ticket, barrier.attachment, self.ledger.position()));
                    s.barrier = None;
                    self.shared.notify.notify_waiters();
                    continue;
                }
            }
            if let Some(payload) = s.payload.take() {
                let bytes = &s.buffer[..payload.len];
                let result = match payload.origin {
                    InputOrigin::Network => {
                        self.ledger.accept(payload.epoch, payload.offset, bytes)
                    }
                    InputOrigin::LocalReply => self
                        .ledger
                        .queue_reply(bytes)
                        .map(|()| self.ledger.position()),
                }
                .map_err(WriterError::Input);
                s.position = self.ledger.position();
                s.response = Some((payload.ticket, result));
                pending = true;
                self.shared.notify.notify_waiters();
            }
            if let Some(barrier) = s.barrier.take() {
                s.fenced = Some((barrier.ticket, barrier.attachment, self.ledger.position()));
                self.shared.notify.notify_waiters();
                continue;
            }
            if !s.running || !pending || s.failure.is_some() {
                drop(
                    self.shared
                        .changed
                        .wait(s)
                        .unwrap_or_else(|e| e.into_inner()),
                );
                continue;
            }
            s.inflight = true;
            drop(s);
            let progress = self.ledger.write_step(writer.as_mut());
            let mut s = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            s.inflight = false;
            s.position = self.ledger.position();
            match progress {
                Ok(WriteProgress::Idle) => pending = false,
                Err(error) => s.failure = Some(error),
                _ => {}
            }
            self.shared.notify.notify_waiters();
            if matches!(progress, Ok(WriteProgress::WouldBlock)) {
                drop(
                    self.shared
                        .changed
                        .wait_timeout(s, std::time::Duration::from_millis(10))
                        .unwrap_or_else(|e| e.into_inner()),
                );
            }
        }
    }
}
#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
