//! Local typed NoScreen replay and independently retained byte-consumer proof.
//! This is not a wire endpoint, terminal parser, or authentication adapter.
use super::protocol::OwnerProtocolError;
use super::resource_contract::{Reservation, ReservationKind};
use super::resources::{OwnerResourceClient, StorageCharge};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use transport::{
    channel_geometry::{ChannelInstance, GeometryRecord},
    session_resume::*,
};
const CHUNK_BYTES: usize = 16384;
const METADATA_BYTES: usize = 65536;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    Invalid,
    Unavailable,
    Busy,
    Resource(OwnerProtocolError),
    Protocol(ResumeError),
}
impl From<ResumeError> for RecoveryError {
    fn from(e: ResumeError) -> Self {
        Self::Protocol(e)
    }
}
/// A caller-supplied host charge, not an allocation limit chosen by this module.
pub struct TransferAllowance {
    pub(super) client: OwnerResourceClient,
    pub(super) reservation: Reservation,
    pub(super) retained: usize,
    pub(super) charge: Arc<StorageCharge>,
}
impl TransferAllowance {
    pub fn admit(
        client: OwnerResourceClient,
        reservation: Reservation,
        cleanup: RequestId,
        retained_bytes: usize,
    ) -> Result<Self, RecoveryError> {
        let required = retained_bytes
            .max(1)
            .checked_add(CHUNK_BYTES)
            .and_then(|n| n.checked_add(METADATA_BYTES))
            .ok_or(RecoveryError::Unavailable)?;
        if reservation.kind != ReservationKind::SnapshotTransfer
            || reservation.principal != client.principal()
            || reservation.bytes
                < u64::try_from(required).map_err(|_| RecoveryError::Unavailable)?
        {
            return Err(RecoveryError::Unavailable);
        }
        let token = client
            .reserve(reservation, cleanup)
            .map_err(RecoveryError::Resource)?;
        let charge = StorageCharge::new(client.clone(), token, cleanup);
        charge.allow_release();
        Ok(Self {
            client,
            reservation,
            retained: retained_bytes,
            charge,
        })
    }
    pub(super) fn admit_peak(
        client: OwnerResourceClient,
        reservation: Reservation,
        cleanup: RequestId,
        retained: usize,
        peak: usize,
    ) -> Result<Self, RecoveryError> {
        if reservation.kind != ReservationKind::SnapshotTransfer
            || reservation.principal != client.principal()
            || reservation.bytes < u64::try_from(peak).map_err(|_| RecoveryError::Unavailable)?
        {
            return Err(RecoveryError::Unavailable);
        }
        let token = client
            .reserve(reservation, cleanup)
            .map_err(RecoveryError::Resource)?;
        let charge = StorageCharge::new(client.clone(), token, cleanup);
        charge.allow_release();
        Ok(Self {
            client,
            reservation,
            retained,
            charge,
        })
    }
    pub(super) fn matches(&self, attachment: Attachment, channel: ChannelInstance) -> bool {
        self.reservation.locator == attachment.locator && self.reservation.channel == channel
    }
    pub(super) fn same_host(&self, client: &OwnerResourceClient) -> bool {
        self.client.same_host(client)
    }
    pub(super) fn matches_locator(&self, attachment: Attachment) -> bool {
        self.reservation.locator == attachment.locator
    }
    pub(super) fn buffer(&self, capacity: usize) -> Result<Vec<u8>, RecoveryError> {
        if capacity > self.retained {
            return Err(RecoveryError::Unavailable);
        }
        let mut v = Vec::new();
        v.try_reserve_exact(capacity)
            .map_err(|_| RecoveryError::Unavailable)?;
        if v.capacity() > self.retained {
            return Err(RecoveryError::Unavailable);
        }
        Ok(v)
    }
}
pub struct RecoveryProducer {
    bytes: Vec<u8>,
    start: RecoveryStart,
    request_id: RequestId,
    offset: usize,
    chunk_live: Arc<AtomicBool>,
    allowance: TransferAllowance,
    _scratch: Option<Arc<StorageCharge>>,
}
pub struct ChargedRecoveryChunk {
    record: Option<RecoveryChunk>,
    live: Arc<AtomicBool>,
    _charge: Arc<StorageCharge>,
}
impl ChargedRecoveryChunk {
    pub fn record(&self) -> &RecoveryChunk {
        self.record.as_ref().unwrap()
    }
}
impl Drop for ChargedRecoveryChunk {
    fn drop(&mut self) {
        drop(self.record.take());
        self.live.store(false, Ordering::Release);
    }
}
impl RecoveryProducer {
    pub(super) fn new(
        request: RecoveryRequest,
        recovery_id: RecoveryId,
        request_id: RequestId,
        geometry: GeometryRecord,
        boundary: OutputCursor,
        source: &[u8],
        allowance: TransferAllowance,
    ) -> Result<Self, RecoveryError> {
        let ParserContinuity::DataCursor { cursor } = request.parser else {
            return Err(RecoveryError::Invalid);
        };
        if !allowance.matches(request.attachment, request.channel)
            || cursor.channel != request.channel
            || checked_end(cursor.offset, source.len())? != boundary.offset
        {
            return Err(RecoveryError::Invalid);
        }
        let start = RecoveryStart {
            attachment: request.attachment,
            channel: request.channel,
            recovery_id,
            mode: RecoveryMode::Replay,
            boundary,
            gap: false,
            geometry,
            total_bytes: source.len() as u64,
            snapshot_version: 0,
        };
        start.validate()?;
        let mut bytes = allowance.buffer(source.len())?;
        bytes.extend_from_slice(source);
        Ok(Self {
            bytes,
            start,
            request_id,
            offset: 0,
            chunk_live: Arc::new(AtomicBool::new(false)),
            allowance,
            _scratch: None,
        })
    }
    pub(super) fn from_owned(
        start: RecoveryStart,
        request_id: RequestId,
        bytes: Vec<u8>,
        allowance: TransferAllowance,
        scratch: Option<Arc<StorageCharge>>,
    ) -> Result<Self, RecoveryError> {
        start.validate()?;
        if bytes.len() as u64 != start.total_bytes
            || bytes.capacity() > allowance.retained
            || !allowance.matches(start.attachment, start.channel)
        {
            return Err(RecoveryError::Unavailable);
        }
        Ok(Self {
            bytes,
            start,
            request_id,
            offset: 0,
            chunk_live: Arc::new(AtomicBool::new(false)),
            allowance,
            _scratch: scratch,
        })
    }
    pub fn start(&self) -> RecoveryStart {
        self.start
    }
    pub fn next_chunk(&mut self) -> Result<Option<ChargedRecoveryChunk>, RecoveryError> {
        if self.chunk_live.load(Ordering::Acquire) {
            return Err(RecoveryError::Busy);
        }
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let n = CHUNK_BYTES.min(self.bytes.len() - self.offset);
        let mut data = Vec::new();
        data.try_reserve_exact(n)
            .map_err(|_| RecoveryError::Unavailable)?;
        if data.capacity() > CHUNK_BYTES {
            return Err(RecoveryError::Unavailable);
        }
        data.extend_from_slice(&self.bytes[self.offset..self.offset + n]);
        let record = RecoveryChunk {
            attachment: self.start.attachment,
            channel: self.start.channel,
            recovery_id: self.start.recovery_id,
            offset: self.offset as u64,
            data,
        };
        self.offset += n;
        self.chunk_live.store(true, Ordering::Release);
        Ok(Some(ChargedRecoveryChunk {
            record: Some(record),
            live: self.chunk_live.clone(),
            _charge: self.allowance.charge.clone(),
        }))
    }
    pub fn end(&self) -> Result<(RecoveryEnd, ResumeControl), RecoveryError> {
        if self.offset != self.bytes.len() || self.chunk_live.load(Ordering::Acquire) {
            return Err(RecoveryError::Busy);
        }
        Ok((
            RecoveryEnd {
                attachment: self.start.attachment,
                channel: self.start.channel,
                recovery_id: self.start.recovery_id,
                total_bytes: self.start.total_bytes,
                boundary: self.start.boundary,
            },
            ResumeControl::RecoveryReady {
                request_id: self.request_id,
                attachment: self.start.attachment,
            },
        ))
    }
}
struct Receiving {
    receiver: RecoveryReceiver,
    start: RecoveryStart,
    request_id: RequestId,
}
/// The cursor derives only from actual retained bytes consumed by this object.
pub struct NoScreenConsumer {
    bytes: Vec<u8>,
    channel: ChannelInstance,
    receiving: Option<Receiving>,
    allowance: TransferAllowance,
}
pub struct ConsumedRecovery {
    pub(super) host: OwnerResourceClient,
    pub(super) completion: RecoveryCompletion,
    pub(super) request_id: RequestId,
    pub(super) recovery_id: RecoveryId,
    pub(super) attachment: Attachment,
    pub(super) channel: ChannelInstance,
}
impl ConsumedRecovery {
    pub(super) fn take(
        self,
    ) -> (
        RecoveryCompletion,
        RequestId,
        RecoveryId,
        Attachment,
        ChannelInstance,
        OwnerResourceClient,
    ) {
        (
            self.completion,
            self.request_id,
            self.recovery_id,
            self.attachment,
            self.channel,
            self.host,
        )
    }
}
impl NoScreenConsumer {
    pub fn new(
        channel: ChannelInstance,
        allowance: TransferAllowance,
    ) -> Result<Self, RecoveryError> {
        if allowance.reservation.channel != channel {
            return Err(RecoveryError::Invalid);
        }
        let bytes = allowance.buffer(allowance.retained)?;
        Ok(Self {
            bytes,
            channel,
            receiving: None,
            allowance,
        })
    }
    pub fn cursor(&self) -> OutputCursor {
        OutputCursor {
            channel: self.channel,
            offset: self.bytes.len() as u64,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn begin(
        &mut self,
        request_id: RequestId,
        request: RecoveryRequest,
        start: RecoveryStart,
    ) -> Result<(), RecoveryError> {
        if self.receiving.is_some() || !self.allowance.matches(request.attachment, self.channel) {
            return Err(RecoveryError::Invalid);
        }
        let receiver = RecoveryReceiver::new(
            request,
            start,
            false,
            RecoveryEvidence::DataCursor(self.cursor()),
            self.allowance.retained as u64,
        )?;
        self.receiving = Some(Receiving {
            receiver,
            start,
            request_id,
        });
        Ok(())
    }
    pub fn consume(&mut self, chunk: &ChargedRecoveryChunk) -> Result<(), RecoveryError> {
        let record = chunk.record();
        let receiving = self.receiving.as_mut().ok_or(RecoveryError::Invalid)?;
        let absolute = receiving
            .start
            .boundary
            .offset
            .checked_sub(receiving.start.total_bytes)
            .and_then(|n| n.checked_add(record.offset))
            .ok_or(RecoveryError::Invalid)?;
        if absolute != self.bytes.len() as u64
            || self
                .bytes
                .len()
                .checked_add(record.data.len())
                .is_none_or(|n| n > self.bytes.capacity())
        {
            return Err(RecoveryError::Unavailable);
        }
        receiving.receiver.chunk(record)?;
        self.bytes.extend_from_slice(&record.data);
        Ok(())
    }
    pub fn finish(
        &mut self,
        end: RecoveryEnd,
        ready: ResumeControl,
    ) -> Result<ConsumedRecovery, RecoveryError> {
        let receiving = self.receiving.as_mut().ok_or(RecoveryError::Invalid)?;
        if ready
            != (ResumeControl::RecoveryReady {
                request_id: receiving.request_id,
                attachment: receiving.start.attachment,
            })
            || self.bytes.len() as u64 != end.boundary.offset
        {
            return Err(RecoveryError::Invalid);
        }
        let completion = receiving.receiver.end(end)?;
        let receiving = self.receiving.take().unwrap();
        Ok(ConsumedRecovery {
            host: self.allowance.client.clone(),
            completion,
            request_id: receiving.request_id,
            recovery_id: receiving.start.recovery_id,
            attachment: receiving.start.attachment,
            channel: self.channel,
        })
    }
    pub fn abandon_transaction(&mut self) {
        self.receiving = None;
    }
    pub fn consume_live(&mut self, offset: u64, bytes: &[u8]) -> Result<(), RecoveryError> {
        if self.receiving.is_some()
            || offset != self.bytes.len() as u64
            || self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.bytes.capacity())
        {
            return Err(RecoveryError::Unavailable);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}
#[cfg(test)]
#[path = "recovery_runtime_tests.rs"]
mod tests;
