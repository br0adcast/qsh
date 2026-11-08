//! Inactive retained-session wire contracts. These pure codecs do not provide
//! authentication, preserve processes, or advertise runtime support.

use crate::channel_geometry::ChannelInstance;
use crate::Features;
use std::num::NonZeroU64;

mod codec;
pub use codec::{
    decode_control, decode_control_payload, decode_data, decode_data_payload, encode_control,
    encode_data,
};
#[cfg(test)]
mod tests;

pub const MAX_RESUME_PAYLOAD: usize = 64 * 1024;
pub const MAX_RESUME_DATA: usize = 16 * 1024;

macro_rules! identity {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 16]);
        impl $name {
            pub fn new(bytes: [u8; 16]) -> Option<Self> {
                bytes.iter().any(|b| *b != 0).then_some(Self(bytes))
            }
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}
identity!(RetainedSessionId);
identity!(OwnerInstance);
identity!(HostInstance);
identity!(FrontendGeneration);
identity!(InputEpoch);

macro_rules! counter {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroU64);
        impl $name {
            pub const fn new(value: u64) -> Option<Self> {
                match NonZeroU64::new(value) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }
            pub const fn get(self) -> u64 {
                self.0.get()
            }
            pub fn checked_next(self) -> Option<Self> {
                Self::new(self.get().checked_add(1)?)
            }
        }
    };
}
counter!(AttachEpoch);
counter!(RequestId);
mod catalog;
pub use catalog::*;
mod recovery;
pub use recovery::*;

/// A public locator is never an authorization capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionLocator {
    pub session: RetainedSessionId,
    pub owner: OwnerInstance,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Attachment {
    pub locator: SessionLocator,
    pub frontend: FrontendGeneration,
    pub epoch: AttachEpoch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputPosition {
    pub epoch: InputEpoch,
    pub accepted: u64,
    pub committed: u64,
}
impl InputPosition {
    pub fn validate(self) -> Result<(), ResumeError> {
        if self.committed > self.accepted {
            Err(ResumeError::Malformed)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCursor {
    pub channel: ChannelInstance,
    pub offset: u64,
}

pub fn checked_end(offset: u64, len: usize) -> Result<u64, ResumeError> {
    offset
        .checked_add(u64::try_from(len).map_err(|_| ResumeError::Overflow)?)
        .ok_or(ResumeError::Overflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachReason {
    TransportLost,
    FrontendReplacement,
    ClientUpdate,
}
impl DetachReason {
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::TransportLost => 1,
            Self::FrontendReplacement => 2,
            Self::ClientUpdate => 3,
        }
    }
    pub const fn from_wire(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TransportLost),
            2 => Some(Self::FrontendReplacement),
            3 => Some(Self::ClientUpdate),
            _ => None,
        }
    }
}
/// Destructive close is a separate operation, never inferred from detach/EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    ExplicitClient,
    Administrator,
    OwnerFailure,
}
impl CloseReason {
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::ExplicitClient => 1,
            Self::Administrator => 2,
            Self::OwnerFailure => 3,
        }
    }
    pub const fn from_wire(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ExplicitClient),
            2 => Some(Self::Administrator),
            3 => Some(Self::OwnerFailure),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachRefusal {
    Missing,
    Unsupported,
    AlreadyAttached,
    Unauthorized,
    StaleOwner,
}
impl AttachRefusal {
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Missing => 1,
            Self::Unsupported => 2,
            Self::AlreadyAttached => 3,
            Self::Unauthorized => 4,
            Self::StaleOwner => 5,
        }
    }
    pub const fn from_wire(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Missing),
            2 => Some(Self::Unsupported),
            3 => Some(Self::AlreadyAttached),
            4 => Some(Self::Unauthorized),
            5 => Some(Self::StaleOwner),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeControl {
    CatalogRequest {
        request_id: RequestId,
        attachment: Attachment,
    },
    Catalog {
        request_id: RequestId,
        catalog: RetainedCatalog,
    },
    RecoveryRequest {
        request_id: RequestId,
        request: RecoveryRequest,
    },
    RecoveryReady {
        request_id: RequestId,
        attachment: Attachment,
    },
    CloseChannel {
        request_id: RequestId,
        close: OwnerCloseChannel,
    },
    CloseSession {
        request_id: RequestId,
        close: OwnerCloseSession,
    },
    CloseAccepted {
        request_id: RequestId,
        accepted: CloseAccepted,
    },
    ExitReceipt(ExitReceipt),
    Attach {
        request_id: RequestId,
        locator: SessionLocator,
        frontend: FrontendGeneration,
        last_epoch: u64,
    },
    Attached {
        request_id: RequestId,
        attachment: Attachment,
    },
    AttachRefused {
        request_id: RequestId,
        reason: AttachRefusal,
    },
    Detach {
        attachment: Attachment,
        reason: DetachReason,
    },
    Fence {
        request_id: RequestId,
        attachment: Attachment,
    },
    Fenced {
        request_id: RequestId,
        attachment: Attachment,
    },
}
impl ResumeControl {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::CatalogRequest { .. } => 0x36,
            Self::Catalog { .. } => 0x37,
            Self::RecoveryRequest { .. } => 0x38,
            Self::RecoveryReady { .. } => 0x39,
            Self::CloseChannel { .. } => 0x3a,
            Self::CloseSession { .. } => 0x3b,
            Self::CloseAccepted { .. } => 0x3c,
            Self::ExitReceipt(_) => 0x3d,
            Self::Attach { .. } => 0x30,
            Self::Attached { .. } => 0x31,
            Self::AttachRefused { .. } => 0x32,
            Self::Detach { .. } => 0x33,
            Self::Fence { .. } => 0x34,
            Self::Fenced { .. } => 0x35,
        }
    }
    pub const fn request_id(&self) -> Option<RequestId> {
        match self {
            Self::Attach { request_id, .. }
            | Self::Attached { request_id, .. }
            | Self::AttachRefused { request_id, .. }
            | Self::Fence { request_id, .. }
            | Self::Fenced { request_id, .. } => Some(*request_id),
            Self::CatalogRequest { request_id, .. }
            | Self::Catalog { request_id, .. }
            | Self::RecoveryRequest { request_id, .. }
            | Self::RecoveryReady { request_id, .. }
            | Self::CloseChannel { request_id, .. }
            | Self::CloseSession { request_id, .. }
            | Self::CloseAccepted { request_id, .. } => Some(*request_id),
            Self::Detach { .. } | Self::ExitReceipt(_) => None,
        }
    }
    pub const fn locator(&self) -> Option<SessionLocator> {
        match self {
            Self::Attach { locator, .. } => Some(*locator),
            Self::Attached { attachment, .. }
            | Self::Detach { attachment, .. }
            | Self::Fence { attachment, .. }
            | Self::Fenced { attachment, .. } => Some(attachment.locator),
            Self::CatalogRequest { attachment, .. } | Self::RecoveryReady { attachment, .. } => {
                Some(attachment.locator)
            }
            Self::Catalog { catalog, .. } => Some(catalog.attachment().locator),
            Self::RecoveryRequest { request, .. } => Some(request.attachment.locator),
            Self::CloseChannel { close, .. } => Some(close.attachment.locator),
            Self::CloseSession { close, .. } => Some(close.attachment.locator),
            Self::CloseAccepted { accepted, .. } => Some(accepted.attachment.locator),
            Self::ExitReceipt(receipt) => Some(receipt.attachment.locator),
            Self::AttachRefused { .. } => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeData {
    RecoveryStart(RecoveryStart),
    RecoveryChunk(RecoveryChunk),
    RecoveryEnd(RecoveryEnd),
    RecoveryBlocked(RecoveryBlocked),
    Input {
        attachment: Attachment,
        channel: ChannelInstance,
        epoch: InputEpoch,
        offset: u64,
        data: Vec<u8>,
    },
    InputAck {
        attachment: Attachment,
        channel: ChannelInstance,
        position: InputPosition,
    },
    Output {
        attachment: Attachment,
        channel: ChannelInstance,
        offset: u64,
        data: Vec<u8>,
    },
    OutputAck {
        attachment: Attachment,
        cursor: OutputCursor,
    },
}
impl ResumeData {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::RecoveryStart(_) => 0x44,
            Self::RecoveryChunk(_) => 0x45,
            Self::RecoveryEnd(_) => 0x46,
            Self::RecoveryBlocked(_) => 0x47,
            Self::Input { .. } => 0x40,
            Self::InputAck { .. } => 0x41,
            Self::Output { .. } => 0x42,
            Self::OutputAck { .. } => 0x43,
        }
    }
    pub const fn attachment(&self) -> Attachment {
        match self {
            Self::RecoveryStart(r) => r.attachment,
            Self::RecoveryChunk(r) => r.attachment,
            Self::RecoveryEnd(r) => r.attachment,
            Self::RecoveryBlocked(r) => r.attachment,
            Self::Input { attachment, .. }
            | Self::InputAck { attachment, .. }
            | Self::Output { attachment, .. }
            | Self::OutputAck { attachment, .. } => *attachment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    FeatureRequired,
    UnknownKind(u8),
    Malformed,
    TooLarge,
    Overflow,
    StaleAttachment,
    InvalidState,
    RequestLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentPhase {
    Detached,
    Attaching,
    Attached,
    Fencing,
    Fenced,
}

/// A pure lease validator, not a grant verifier or authority issuer. The caller
/// must establish authentication and complete channel recovery independently.
#[derive(Debug, Clone)]
pub struct AttachmentState {
    phase: AttachmentPhase,
    current: Option<Attachment>,
    revoked: u64,
    recovered: bool,
}
impl Default for AttachmentState {
    fn default() -> Self {
        Self::new()
    }
}
impl AttachmentState {
    pub const fn new() -> Self {
        Self {
            phase: AttachmentPhase::Detached,
            current: None,
            revoked: 0,
            recovered: false,
        }
    }
    pub const fn phase(&self) -> AttachmentPhase {
        self.phase
    }
    pub fn begin_attach(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        if !matches!(
            self.phase,
            AttachmentPhase::Detached | AttachmentPhase::Fenced
        ) {
            return Err(ResumeError::InvalidState);
        }
        if attachment.epoch.get() <= self.revoked
            || self
                .current
                .is_some_and(|old| old.locator != attachment.locator)
        {
            return Err(ResumeError::StaleAttachment);
        }
        self.current = Some(attachment);
        self.phase = AttachmentPhase::Attaching;
        self.recovered = false;
        Ok(())
    }
    fn require(&self, attachment: Attachment, phase: AttachmentPhase) -> Result<(), ResumeError> {
        if self.current.is_some_and(|current| current != attachment) {
            return Err(ResumeError::StaleAttachment);
        }
        if self.current.is_none() || self.phase != phase {
            return Err(ResumeError::InvalidState);
        }
        Ok(())
    }
    pub fn attached(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Attaching)?;
        self.phase = AttachmentPhase::Attached;
        Ok(())
    }
    pub fn mark_recovery_complete(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Attached)?;
        if self.recovered {
            return Err(ResumeError::InvalidState);
        }
        self.recovered = true;
        Ok(())
    }
    pub fn validate_input(&self, attachment: Attachment) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Attached)?;
        if !self.recovered {
            return Err(ResumeError::InvalidState);
        }
        Ok(())
    }
    pub fn validate_resize(&self, attachment: Attachment) -> Result<(), ResumeError> {
        self.validate_input(attachment)
    }
    pub fn validate_close(&self, attachment: Attachment) -> Result<(), ResumeError> {
        self.validate_input(attachment)
    }
    pub fn begin_fence(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Attached)?;
        self.phase = AttachmentPhase::Fencing;
        self.recovered = false;
        Ok(())
    }
    pub fn fenced(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Fencing)?;
        self.revoked = attachment.epoch.get();
        self.phase = AttachmentPhase::Fenced;
        Ok(())
    }
    /// Locally abandon a lost peer or a cancelled/refused attachment attempt.
    /// This revokes the lease only: it asserts no remote acknowledgement or
    /// completed PTY write barrier. Repeated abandonment of a detached/fenced
    /// attachment is rejected, and later attachment requires a greater epoch.
    pub fn abandon(&mut self, attachment: Attachment) -> Result<(), ResumeError> {
        match self.current {
            Some(current) if current != attachment => return Err(ResumeError::StaleAttachment),
            None => return Err(ResumeError::InvalidState),
            Some(_) => {}
        }
        if !matches!(
            self.phase,
            AttachmentPhase::Attaching | AttachmentPhase::Attached | AttachmentPhase::Fencing
        ) {
            return Err(ResumeError::InvalidState);
        }
        self.revoked = self.revoked.max(attachment.epoch.get());
        self.phase = AttachmentPhase::Detached;
        self.recovered = false;
        Ok(())
    }
    pub fn detach(
        &mut self,
        attachment: Attachment,
        _reason: DetachReason,
    ) -> Result<(), ResumeError> {
        self.require(attachment, AttachmentPhase::Attached)?;
        self.revoked = attachment.epoch.get();
        self.phase = AttachmentPhase::Detached;
        self.recovered = false;
        Ok(())
    }
}

#[cfg(test)]
mod extension_tests;

mod extension_codec;
