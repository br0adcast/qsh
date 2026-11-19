//! Atomic bounded retained-channel metadata. This contains no bearer grants.
use super::*;
use crate::channel::{
    ChannelKind, ChannelSnapshot, OpenRequest, CHANNEL_IDENTITIES, CHANNEL_SNAPSHOT_MAX,
    FIRST_CHANNEL_STREAM, MAX_COMMAND_LEN,
};
use crate::channel_geometry::{GeometryRecord, ResizeRequestId};

pub const MAX_CATALOG_BODY: usize = 56 + 4 + CHANNEL_SNAPSHOT_MAX + 2 + CHANNEL_IDENTITIES * 79;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOpen {
    pub attachment: Attachment,
    pub request: OpenRequest,
}
impl OwnerOpen {
    pub fn decode_payload(attachment: Attachment, payload: &[u8]) -> Result<Self, ResumeError> {
        Ok(Self {
            attachment,
            request: crate::channel::decode_checked_open(payload)
                .map_err(|_| ResumeError::Malformed)?,
        })
    }
    pub fn validate(&self) -> Result<(), ResumeError> {
        validate_open(&self.request)
    }
}
pub fn validate_open(r: &OpenRequest) -> Result<(), ResumeError> {
    if r.stream < FIRST_CHANNEL_STREAM
        || r.command.len() > MAX_COMMAND_LEN
        || (r.kind == ChannelKind::Shell && !r.command.is_empty())
    {
        return Err(ResumeError::Malformed);
    }
    if r.cols != 0 && r.rows != 0 {
        terminal_size::TerminalSize::new(r.cols, r.rows).map_err(|_| ResumeError::Malformed)?;
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerResize {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub request_id: ResizeRequestId,
    pub cols: u16,
    pub rows: u16,
}
impl OwnerResize {
    pub fn validate(self) -> Result<(), ResumeError> {
        terminal_size::TerminalSize::new(self.cols, self.rows)
            .map(|_| ())
            .map_err(|_| ResumeError::Malformed)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerCloseChannel {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub reason: CloseReason,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerCloseSession {
    pub attachment: Attachment,
    pub reason: CloseReason,
}
impl OwnerCloseChannel {
    pub fn validate_lease(self, state: &AttachmentState) -> Result<(), ResumeError> {
        state.validate_close(self.attachment)
    }
}
impl OwnerCloseSession {
    pub fn validate_lease(self, state: &AttachmentState) -> Result<(), ResumeError> {
        state.validate_close(self.attachment)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseTarget {
    Channel(ChannelInstance),
    Session,
}
/// Acceptance only requests cleanup. It is not an exit or reservation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAccepted {
    pub attachment: Attachment,
    pub target: CloseTarget,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitFact {
    Reaped { status: i32 },
    NoChild,
    StatusUnavailable,
}
/// Runtime producers may issue this only after the exact child's actual cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitReceipt {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub receipt_id: RequestId,
    pub fact: ExitFact,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLifecycle {
    Active,
    Draining,
    Exited,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelPosition {
    pub channel: ChannelInstance,
    pub input: InputPosition,
    pub output: OutputCursor,
    pub geometry: GeometryRecord,
    pub lifecycle: ChannelLifecycle,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedCatalog {
    attachment: Attachment,
    channels: ChannelSnapshot,
    positions: Box<[ChannelPosition]>,
}
impl RetainedCatalog {
    pub fn new(
        attachment: Attachment,
        channels: ChannelSnapshot,
        positions: Vec<ChannelPosition>,
    ) -> Result<Self, ResumeError> {
        Self::validate_parts(&channels, &positions)?;
        Ok(Self {
            attachment,
            channels,
            positions: positions.into_boxed_slice(),
        })
    }
    fn validate_parts(
        channels: &ChannelSnapshot,
        positions: &[ChannelPosition],
    ) -> Result<(), ResumeError> {
        if positions.len() > CHANNEL_IDENTITIES
            || positions.len() != channels.active().len() + channels.draining().len()
        {
            return Err(ResumeError::Malformed);
        }
        for (i, p) in positions.iter().enumerate() {
            p.input.validate()?;
            if p.channel != p.output.channel
                || p.channel != p.geometry.instance
                || positions[..i].iter().any(|old| old.channel == p.channel)
            {
                return Err(ResumeError::Malformed);
            }
            let active = channels.active().iter().find(|e| e.instance == p.channel);
            let draining = channels.draining().iter().find(|e| e.instance == p.channel);
            // ChannelSnapshot bounds stream IDs; retained catalog also bounds lifetime IDs.
            if active.is_some() && draining.is_some() {
                return Err(ResumeError::Malformed);
            }
            let (cols, rows) = if let Some(e) = active {
                if p.lifecycle != ChannelLifecycle::Active {
                    return Err(ResumeError::Malformed);
                }
                (e.request.cols, e.request.rows)
            } else if let Some(e) = draining {
                if p.lifecycle == ChannelLifecycle::Active {
                    return Err(ResumeError::Malformed);
                }
                (e.open.cols, e.open.rows)
            } else {
                return Err(ResumeError::Malformed);
            };
            p.geometry
                .validate_for_open(cols, rows)
                .map_err(|_| ResumeError::Malformed)?;
        }
        // Two snapshot entries with the same lifetime cannot share a single position.
        for e in channels.active() {
            if channels
                .active()
                .iter()
                .filter(|x| x.instance == e.instance)
                .count()
                != 1
            {
                return Err(ResumeError::Malformed);
            }
        }
        for e in channels.draining() {
            if channels
                .draining()
                .iter()
                .filter(|x| x.instance == e.instance)
                .count()
                != 1
            {
                return Err(ResumeError::Malformed);
            }
        }
        Ok(())
    }
    pub const fn attachment(&self) -> Attachment {
        self.attachment
    }
    pub fn channels(&self) -> &ChannelSnapshot {
        &self.channels
    }
    pub fn positions(&self) -> &[ChannelPosition] {
        &self.positions
    }
}
/// Tracks exact cleanup facts for a session close; EOF never completes it.
#[derive(Debug)]
pub struct SessionCleanup {
    attachment: Attachment,
    remaining: Vec<ChannelInstance>,
}
impl SessionCleanup {
    pub fn new(catalog: &RetainedCatalog) -> Self {
        Self {
            attachment: catalog.attachment,
            remaining: catalog.positions.iter().map(|p| p.channel).collect(),
        }
    }
    pub fn receipt(&mut self, receipt: ExitReceipt) -> Result<(), ResumeError> {
        if receipt.attachment != self.attachment {
            return Err(ResumeError::StaleAttachment);
        }
        let i = self
            .remaining
            .iter()
            .position(|c| *c == receipt.channel)
            .ok_or(ResumeError::InvalidState)?;
        self.remaining.swap_remove(i);
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.remaining.is_empty()
    }
}
