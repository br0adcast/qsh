//! Canonical Screen transfer with independent passive parser evidence.
use super::{
    recovery_runtime::{ChargedRecoveryChunk, ConsumedRecovery, RecoveryError, TransferAllowance},
    resource_contract::{Reservation, ReservationKind, ScreenCharge},
    resources::{OwnerResourceClient, StorageCharge},
};
use crate::screen_budget::{ScreenBudget, ScreenEnvelope, ScreenLease};
use std::sync::{Arc, Mutex, Weak};
use terminal::{TerminalCore, TerminalOptions};
use terminal_size::TerminalSize;
use transport::{
    channel_geometry::{ChannelInstance, GeometryRecord},
    session_resume::*,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenRecoveryRequirements {
    pub max_bytes: usize,
    pub transfer_bytes: usize,
    pub scratch: ScreenCharge,
}
impl ScreenRecoveryRequirements {
    pub(super) fn new(envelope: ScreenEnvelope, size: TerminalSize) -> Result<Self, RecoveryError> {
        let max_bytes =
            terminal::replay_allocation_bound(size).ok_or(RecoveryError::Unavailable)?;
        let transfer_bytes = max_bytes
            .checked_mul(4)
            .and_then(|n| n.checked_add(2 * 1_052_672 + 1_048_576 + 16384 + 65536))
            .ok_or(RecoveryError::Unavailable)?;
        let slots = envelope.charge().map_err(|_| RecoveryError::Unavailable)?;
        Ok(Self {
            max_bytes,
            transfer_bytes,
            scratch: ScreenCharge {
                cells: slots.cells as u64,
                rows: slots.rows as u64,
                models: 0,
            },
        })
    }
}
pub struct ScreenRecoveryAllowance {
    pub(super) transfer: TransferAllowance,
    pub(super) scratch: Arc<StorageCharge>,
    requirements: ScreenRecoveryRequirements,
}
impl ScreenRecoveryAllowance {
    pub fn admit(
        client: OwnerResourceClient,
        bytes: Reservation,
        scratch: Reservation,
        cleanup: RequestId,
        requirements: ScreenRecoveryRequirements,
    ) -> Result<Self, RecoveryError> {
        if scratch.kind != ReservationKind::ScreenModel
            || scratch.screen_charge != Some(requirements.scratch)
            || scratch.principal != client.principal()
            || scratch.locator != bytes.locator
            || scratch.channel != bytes.channel
            || requirements.scratch.models != 0
            || requirements.max_bytes.checked_mul(2).is_none()
        {
            return Err(RecoveryError::Invalid);
        }
        let transfer = TransferAllowance::admit_peak(
            client.clone(),
            bytes,
            cleanup,
            2 * requirements.max_bytes,
            requirements.transfer_bytes,
        )?;
        let token = client
            .reserve(scratch, cleanup)
            .map_err(RecoveryError::Resource)?;
        let scratch = StorageCharge::new(client, token, cleanup);
        scratch.allow_release();
        Ok(Self {
            transfer,
            scratch,
            requirements,
        })
    }
    pub(super) fn matches(
        &self,
        client: &OwnerResourceClient,
        request: RecoveryRequest,
        quote: ScreenRecoveryRequirements,
    ) -> bool {
        self.requirements == quote
            && self.transfer.same_host(client)
            && self.transfer.matches(request.attachment, request.channel)
    }
}
#[derive(Clone, Copy)]
struct ParserState {
    instance: [u8; 16],
    cursor: OutputCursor,
    geometry: Option<GeometryRecord>,
    retained: bool,
}
/// Carries a weak identity for the actual receiver object and its charged
/// metadata lifetime. A request's claimed fields cannot construct this evidence.
pub struct ScreenEvidence {
    state: Weak<Mutex<ParserState>>,
    host: OwnerResourceClient,
    _charge: Arc<StorageCharge>,
}
impl ScreenEvidence {
    pub(super) fn matches(
        &self,
        client: &OwnerResourceClient,
        request: RecoveryRequest,
        geometry: GeometryRecord,
        geometry_start: u64,
    ) -> bool {
        if !self.host.same_host(client) {
            return false;
        }
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained
            && state.geometry == Some(geometry)
            && state.cursor.offset >= geometry_start
            && request.channel == state.cursor.channel
            && request.parser
                == (ParserContinuity::Retained {
                    parser_instance: state.instance,
                    cursor: state.cursor,
                })
    }
}
struct Receiving {
    receiver: RecoveryReceiver,
    start: RecoveryStart,
    request_id: RequestId,
}
pub struct ScreenConsumer {
    term: TerminalCore,
    lease: ScreenLease,
    state: Arc<Mutex<ParserState>>,
    receiving: Option<Receiving>,
    allowance: TransferAllowance,
}
impl ScreenConsumer {
    pub fn new(
        channel: ChannelInstance,
        instance: [u8; 16],
        size: TerminalSize,
        uid: u32,
        budget: Arc<ScreenBudget>,
        allowance: TransferAllowance,
    ) -> Result<Self, RecoveryError> {
        if instance == [0; 16] || allowance.reservation.channel != channel {
            return Err(RecoveryError::Invalid);
        }
        let lease = budget
            .reserve(uid, size)
            .map_err(|_| RecoveryError::Unavailable)?;
        let term = TerminalCore::with_options(
            size,
            TerminalOptions {
                history_lines: 0,
                replay: true,
            },
        );
        Ok(Self {
            term,
            lease,
            state: Arc::new(Mutex::new(ParserState {
                instance,
                cursor: OutputCursor { channel, offset: 0 },
                geometry: None,
                retained: false,
            })),
            receiving: None,
            allowance,
        })
    }
    pub fn request(&self, attachment: Attachment) -> (RecoveryRequest, ScreenEvidence) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let parser = if state.retained {
            ParserContinuity::Retained {
                parser_instance: state.instance,
                cursor: state.cursor,
            }
        } else {
            ParserContinuity::Recreated
        };
        (
            RecoveryRequest {
                attachment,
                channel: state.cursor.channel,
                parser,
            },
            ScreenEvidence {
                state: Arc::downgrade(&self.state),
                host: self.allowance.client.clone(),
                _charge: self.allowance.charge.clone(),
            },
        )
    }
    pub fn cursor(&self) -> OutputCursor {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).cursor
    }
    pub fn begin(
        &mut self,
        request_id: RequestId,
        request: RecoveryRequest,
        start: RecoveryStart,
    ) -> Result<(), RecoveryError> {
        if self.receiving.is_some() || !self.allowance.matches(request.attachment, request.channel)
        {
            return Err(RecoveryError::Invalid);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.cursor.channel != request.channel {
            return Err(RecoveryError::Invalid);
        }
        let evidence = if state.retained {
            RecoveryEvidence::ScreenParser {
                parser_instance: state.instance,
                cursor: state.cursor,
            }
        } else {
            RecoveryEvidence::None
        };
        if start.mode == RecoveryMode::Replay && state.geometry != Some(start.geometry) {
            return Err(RecoveryError::Invalid);
        }
        let receiver = RecoveryReceiver::new(
            request,
            start,
            true,
            evidence,
            self.allowance.retained as u64,
        )?;
        let size = TerminalSize::new(start.geometry.cols, start.geometry.rows)
            .map_err(|_| RecoveryError::Invalid)?;
        let prepared = self
            .lease
            .prepare(size)
            .map_err(|_| RecoveryError::Unavailable)?;
        self.term.resize_to(size);
        prepared.commit();
        state.retained = false;
        state.geometry = Some(start.geometry);
        drop(state);
        self.receiving = Some(Receiving {
            receiver,
            start,
            request_id,
        });
        Ok(())
    }
    pub fn consume(&mut self, chunk: &ChargedRecoveryChunk) -> Result<(), RecoveryError> {
        let receiving = self.receiving.as_mut().ok_or(RecoveryError::Invalid)?;
        receiving.receiver.chunk(chunk.record())?;
        // Passive replica: never generate application-input answers here.
        self.term.feed(&chunk.record().data);
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
        {
            return Err(RecoveryError::Invalid);
        }
        let completion = receiving.receiver.end(end)?;
        self.term.flush_pending_output();
        let receiving = self.receiving.take().unwrap();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.cursor = end.boundary;
        state.retained = true;
        Ok(ConsumedRecovery {
            host: self.allowance.client.clone(),
            completion,
            request_id: receiving.request_id,
            recovery_id: receiving.start.recovery_id,
            attachment: receiving.start.attachment,
            channel: end.channel,
        })
    }
    pub fn consume_live(&mut self, offset: u64, bytes: &[u8]) -> Result<(), RecoveryError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.receiving.is_some() || !state.retained || state.cursor.offset != offset {
            return Err(RecoveryError::Invalid);
        }
        let end = checked_end(offset, bytes.len())?;
        self.term.feed(bytes);
        state.cursor.offset = end;
        Ok(())
    }
    pub fn abandon_transaction(&mut self) {
        self.receiving = None;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retained = false;
    }
    #[cfg(test)]
    pub fn snapshot(&mut self) -> terminal::StateSnapshot {
        self.term.snapshot().unwrap()
    }
}
