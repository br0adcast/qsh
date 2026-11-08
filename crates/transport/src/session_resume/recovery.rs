//! Bounded recovery transactions. No screen serializer or storage allocation.
use super::*;
use crate::channel_geometry::GeometryRecord;
identity!(RecoveryId);
/// Analytic existing replay bound at maximum geometry and parser tail; see
/// docs/terminal-resources.md. Snapshot backing/copies are separately charged.
pub const MAX_REPLAY_SNAPSHOT_PAYLOAD: u64 = 41_457_964;
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ParserContinuity {
    /// A retained byte-consumer position, never a screen parser identity.
    DataCursor { cursor: OutputCursor },
    #[default]
    Recreated,
    Retained {
        parser_instance: [u8; 16],
        cursor: OutputCursor,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRequest {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub parser: ParserContinuity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMode {
    Replay,
    ScreenReset,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryStart {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub recovery_id: RecoveryId,
    pub mode: RecoveryMode,
    pub boundary: OutputCursor,
    pub gap: bool,
    pub geometry: GeometryRecord,
    pub total_bytes: u64,
    pub snapshot_version: u16,
}
impl RecoveryStart {
    pub fn validate(self) -> Result<(), ResumeError> {
        if self.channel != self.boundary.channel || self.channel != self.geometry.instance {
            return Err(ResumeError::Malformed);
        }
        self.geometry
            .validate()
            .map_err(|_| ResumeError::Malformed)?;
        if matches!(self.mode, RecoveryMode::Replay) {
            if self.snapshot_version != 0 || self.gap || self.total_bytes > self.boundary.offset {
                return Err(ResumeError::Malformed);
            }
        } else {
            if self.snapshot_version != 1 {
                return Err(ResumeError::Malformed);
            }
            if self.total_bytes > MAX_REPLAY_SNAPSHOT_PAYLOAD {
                return Err(ResumeError::TooLarge);
            }
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryChunk {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub recovery_id: RecoveryId,
    pub offset: u64,
    pub data: Vec<u8>,
}
impl std::fmt::Debug for RecoveryChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryChunk")
            .field("channel", &self.channel)
            .field("offset", &self.offset)
            .field("bytes", &self.data.len())
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEnd {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub recovery_id: RecoveryId,
    pub total_bytes: u64,
    pub boundary: OutputCursor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBlocked {
    pub attachment: Attachment,
    pub channel: ChannelInstance,
    pub boundary: OutputCursor,
}
/// Independently accepted local recovery evidence, supplied by the receiver.
/// The runtime must verify the actual retained parser or available data bytes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryEvidence {
    #[default]
    None,
    ScreenParser {
        parser_instance: [u8; 16],
        cursor: OutputCursor,
    },
    DataCursor(OutputCursor),
}
/// Produced only after an exact transaction ends; not constructible by a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCompletion {
    attachment: Attachment,
    channel: ChannelInstance,
    boundary: OutputCursor,
    geometry: GeometryRecord,
}
#[derive(Debug)]
pub struct RecoveryReceiver {
    start: RecoveryStart,
    received: u64,
    ended: bool,
}
impl RecoveryReceiver {
    /// `charged_max` is a receiver-owned existing reservation, not a peer limit.
    /// Evidence identifies independently verified retained parser/data continuity.
    pub fn new(
        request: RecoveryRequest,
        start: RecoveryStart,
        has_screen: bool,
        evidence: RecoveryEvidence,
        charged_max: u64,
    ) -> Result<Self, ResumeError> {
        start.validate()?;
        if request.attachment != start.attachment {
            return Err(ResumeError::StaleAttachment);
        }
        if request.channel != start.channel || start.total_bytes > charged_max {
            return Err(ResumeError::TooLarge);
        }
        if has_screen && matches!(request.parser, ParserContinuity::DataCursor { .. })
            || !has_screen && matches!(request.parser, ParserContinuity::Retained { .. })
        {
            return Err(ResumeError::InvalidState);
        }
        match start.mode {
            RecoveryMode::ScreenReset if !has_screen => return Err(ResumeError::InvalidState),
            RecoveryMode::Replay => {
                let cursor = match (has_screen, request.parser, evidence) {
                    (
                        true,
                        ParserContinuity::Retained {
                            parser_instance,
                            cursor,
                        },
                        RecoveryEvidence::ScreenParser {
                            parser_instance: accepted,
                            cursor: accepted_cursor,
                        },
                    ) if parser_instance != [0; 16]
                        && parser_instance == accepted
                        && cursor == accepted_cursor =>
                    {
                        cursor
                    }
                    (
                        false,
                        ParserContinuity::DataCursor { cursor },
                        RecoveryEvidence::DataCursor(accepted),
                    ) if cursor == accepted => cursor,
                    _ => return Err(ResumeError::InvalidState),
                };
                if cursor.channel != start.channel
                    || checked_end(
                        cursor.offset,
                        usize::try_from(start.total_bytes).map_err(|_| ResumeError::Overflow)?,
                    )? != start.boundary.offset
                {
                    return Err(ResumeError::InvalidState);
                }
            }
            _ => {}
        }
        Ok(Self {
            start,
            received: 0,
            ended: false,
        })
    }
    pub fn chunk(&mut self, chunk: &RecoveryChunk) -> Result<(), ResumeError> {
        if chunk.attachment != self.start.attachment {
            return Err(ResumeError::StaleAttachment);
        }
        if self.ended
            || chunk.channel != self.start.channel
            || chunk.recovery_id != self.start.recovery_id
            || chunk.offset != self.received
            || chunk.data.is_empty()
            || chunk.data.len() > MAX_RESUME_DATA
        {
            return Err(ResumeError::InvalidState);
        }
        let next = checked_end(self.received, chunk.data.len())?;
        if next > self.start.total_bytes {
            return Err(ResumeError::TooLarge);
        }
        self.received = next;
        Ok(())
    }
    pub fn end(&mut self, end: RecoveryEnd) -> Result<RecoveryCompletion, ResumeError> {
        if end.attachment != self.start.attachment {
            return Err(ResumeError::StaleAttachment);
        }
        if self.ended
            || end.channel != self.start.channel
            || end.recovery_id != self.start.recovery_id
            || end.total_bytes != self.start.total_bytes
            || end.boundary != self.start.boundary
            || self.received != self.start.total_bytes
        {
            return Err(ResumeError::InvalidState);
        }
        self.ended = true;
        Ok(RecoveryCompletion {
            attachment: end.attachment,
            channel: end.channel,
            boundary: end.boundary,
            geometry: self.start.geometry,
        })
    }
}
/// Catalog plus all exact channel recoveries gate input. Attached alone does not.
#[derive(Debug)]
pub struct RecoveryGate {
    attachment: Attachment,
    pending: Vec<(OutputCursor, GeometryRecord)>,
}
impl RecoveryGate {
    pub fn new(catalog: &RetainedCatalog) -> Self {
        Self {
            attachment: catalog.attachment(),
            pending: catalog
                .positions()
                .iter()
                .map(|p| (p.output, p.geometry))
                .collect(),
        }
    }
    pub fn complete_channel(&mut self, completion: RecoveryCompletion) -> Result<(), ResumeError> {
        if completion.attachment != self.attachment {
            return Err(ResumeError::StaleAttachment);
        }
        let i = self
            .pending
            .iter()
            .position(|(p, g)| {
                p.channel == completion.channel
                    && *p == completion.boundary
                    && *g == completion.geometry
            })
            .ok_or(ResumeError::InvalidState)?;
        self.pending.swap_remove(i);
        Ok(())
    }
    pub fn enable_input(self, state: &mut AttachmentState) -> Result<(), ResumeError> {
        if !self.pending.is_empty() {
            return Err(ResumeError::InvalidState);
        }
        state.mark_recovery_complete(self.attachment)
    }
}
