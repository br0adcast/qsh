//! Checked identities and authoritative channel geometry values.
//!
//! Wire validation cannot determine PTY classification: an owner must also
//! validate geometry against the channel's OPEN metadata before using it.

use std::num::NonZeroU64;
use terminal_size::TerminalSize;

/// A daemon-assigned channel lifetime, distinct from its reusable stream ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelInstance(NonZeroU64);

impl ChannelInstance {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Exhaustion must end allocation, never alias a previous channel.
    pub fn checked_next(self) -> Option<Self> {
        Self::new(self.get().checked_add(1)?)
    }
}

/// A correlated resize within one channel and attachment request-ID scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResizeRequestId(NonZeroU64);

impl ResizeRequestId {
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// A new attachment must establish a new scope before IDs can restart.
    pub fn checked_next(self) -> Option<Self> {
        Self::new(self.get().checked_add(1)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResizeRefusal {
    InvalidSize = 1,
    NoPty = 2,
    ResourceLimit = 3,
    PtyResizeFailed = 4,
    ScreenPreparationFailed = 5,
}

impl ResizeRefusal {
    pub(crate) fn from_wire(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::InvalidSize,
            2 => Self::NoPty,
            3 => Self::ResourceLimit,
            4 => Self::PtyResizeFailed,
            5 => Self::ScreenPreparationFailed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryOutcome {
    Established,
    Applied,
    Refused(ResizeRefusal),
}

/// An ordered geometry boundary. A zero request ID is exclusively Established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeometryRecord {
    pub instance: ChannelInstance,
    pub request_id: u64,
    pub outcome: GeometryOutcome,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeometryError {
    InvalidCorrelation,
    InvalidSize,
    NoPtyGeometryChanged,
}

impl GeometryRecord {
    /// Validate the fields available before OPEN metadata arrives. Either-zero
    /// geometry is only provisional; it must subsequently match a no-PTY OPEN.
    pub fn validate(self) -> Result<(), GeometryError> {
        if matches!(self.outcome, GeometryOutcome::Established) != (self.request_id == 0) {
            return Err(GeometryError::InvalidCorrelation);
        }
        if self.cols != 0 && self.rows != 0 {
            TerminalSize::new(self.cols, self.rows).map_err(|_| GeometryError::InvalidSize)?;
        }
        Ok(())
    }

    /// Validate against explicit OPEN classification. No-PTY geometry is kept
    /// exactly as opened and never turned into a terminal model. Nonzero OPEN
    /// dimensions identify a PTY, so a zero-sized checkpoint cannot reclassify it.
    pub fn validate_for_open(
        self,
        open_cols: u16,
        open_rows: u16,
    ) -> Result<Option<TerminalSize>, GeometryError> {
        self.validate()?;
        if open_cols == 0 || open_rows == 0 {
            if (self.cols, self.rows) != (open_cols, open_rows) {
                return Err(GeometryError::NoPtyGeometryChanged);
            }
            Ok(None)
        } else {
            TerminalSize::new(open_cols, open_rows).map_err(|_| GeometryError::InvalidSize)?;
            TerminalSize::new(self.cols, self.rows)
                .map(Some)
                .map_err(|_| GeometryError::InvalidSize)
        }
    }
}

/// A continuity disclosure, not a claim that every unconfirmed byte was lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputGapCause {
    PreviousConnectionOutputUnconfirmed = 1,
    /// Required terminal replies could not be delivered; the channel is ending.
    TerminalReplyFailure = 2,
}

impl OutputGapCause {
    pub(crate) fn from_wire(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::PreviousConnectionOutputUnconfirmed),
            2 => Some(Self::TerminalReplyFailure),
            _ => None,
        }
    }
}

/// Fixed protocol-attempt failure codes; never process exit or OPEN refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProtocolErrorCode {
    ResizePipelineOverflow = 1,
}

impl ProtocolErrorCode {
    pub(crate) fn from_wire(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ResizePipelineOverflow),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_exhausted_ids_cannot_alias_a_live_scope() {
        assert_eq!(ChannelInstance::new(0), None);
        assert_eq!(ResizeRequestId::new(0), None);
        assert_eq!(ChannelInstance::new(u64::MAX).unwrap().checked_next(), None);
        assert_eq!(ResizeRequestId::new(u64::MAX).unwrap().checked_next(), None);
        assert_eq!(
            ChannelInstance::new(1)
                .unwrap()
                .checked_next()
                .unwrap()
                .get(),
            2
        );
        assert_eq!(
            ResizeRequestId::new(1)
                .unwrap()
                .checked_next()
                .unwrap()
                .get(),
            2
        );
    }

    #[test]
    fn geometry_rejects_invalid_fields() {
        let base = GeometryRecord {
            instance: ChannelInstance::new(1).unwrap(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        };
        assert_eq!(
            base.validate_for_open(80, 24).unwrap(),
            Some(TerminalSize::new(80, 24).unwrap())
        );
        assert_eq!(
            GeometryRecord {
                request_id: 1,
                ..base
            }
            .validate(),
            Err(GeometryError::InvalidCorrelation)
        );
        for outcome in [
            GeometryOutcome::Applied,
            GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
        ] {
            assert_eq!(
                GeometryRecord { outcome, ..base }.validate(),
                Err(GeometryError::InvalidCorrelation)
            );
            assert!(GeometryRecord {
                outcome,
                request_id: 1,
                ..base
            }
            .validate()
            .is_ok());
        }
        for (cols, rows) in [(1, 24), (513, 1), (2, 257), (0, 24), (80, 0)] {
            assert!(GeometryRecord { cols, rows, ..base }
                .validate_for_open(80, 24)
                .is_err());
        }
        for (cols, rows) in [(0, 0), (0, u16::MAX), (u16::MAX, 0)] {
            let no_pty = GeometryRecord { cols, rows, ..base };
            assert_eq!(no_pty.validate_for_open(cols, rows), Ok(None));
            assert!(base.validate_for_open(cols, rows).is_err());
        }
        assert!(GeometryRecord {
            cols: 0,
            rows: 24,
            ..base
        }
        .validate_for_open(0, 25)
        .is_err());
    }
}
