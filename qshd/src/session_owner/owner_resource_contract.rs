//! Owner-to-host request DTOs. Decoding never registers or releases resources.
use super::host_protocol::ReservationRefusal;
use super::protocol::{OwnerProtocolError as Error, OwnerRole};
use super::resource_contract::{ReservationId, ReservationKind, ScreenCharge};
use super::wire::{put_locator, Reader};
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::{RequestId, SessionLocator};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerResourceRequest {
    pub locator: SessionLocator,
    pub channel: ChannelInstance,
    pub kind: ReservationKind,
    pub bytes: u64,
    pub screen_charge: Option<ScreenCharge>,
}
impl OwnerResourceRequest {
    pub fn validate(self) -> Result<(), Error> {
        match (self.kind, self.screen_charge) {
            (ReservationKind::ScreenModel, Some(s))
                if self.bytes == 0 && s.cells > 0 && s.rows > 0 && s.models <= 1 =>
            {
                Ok(())
            }
            (ReservationKind::ScreenModel, _) => Err(Error::Malformed),
            (_, None) if self.bytes > 0 => Ok(()),
            _ => Err(Error::Malformed),
        }
    }
    fn len(self) -> usize {
        50 + self.screen_charge.map_or(0, |_| 24)
    }
    fn put(self, out: &mut Vec<u8>) {
        put_locator(out, self.locator);
        out.extend_from_slice(&self.channel.get().to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.push(u8::from(self.screen_charge.is_some()));
        if let Some(s) = self.screen_charge {
            for n in [s.cells, s.rows, s.models] {
                out.extend_from_slice(&n.to_be_bytes());
            }
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let locator = r.locator()?;
        let channel = ChannelInstance::new(r.u64()?).ok_or(Error::Malformed)?;
        let kind = match r.byte()? {
            1 => ReservationKind::ScreenModel,
            2 => ReservationKind::OutputHistory,
            3 => ReservationKind::SnapshotTransfer,
            4 => ReservationKind::ControlQueue,
            _ => return Err(Error::Malformed),
        };
        let bytes = r.u64()?;
        let screen_charge = match r.byte()? {
            0 => None,
            1 => Some(ScreenCharge {
                cells: r.u64()?,
                rows: r.u64()?,
                models: r.u64()?,
            }),
            _ => return Err(Error::Malformed),
        };
        let v = Self {
            locator,
            channel,
            kind,
            bytes,
            screen_charge,
        };
        v.validate()?;
        Ok(v)
    }
}
/// Public receipt correlation only; no conversion to a private cleanup token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerReleaseReport {
    pub locator: SessionLocator,
    pub channel: ChannelInstance,
    pub reservation: ReservationId,
    pub cleanup: RequestId,
}
impl OwnerReleaseReport {
    fn put(self, out: &mut Vec<u8>) {
        put_locator(out, self.locator);
        out.extend_from_slice(&self.channel.get().to_be_bytes());
        out.extend_from_slice(&self.reservation.get().to_be_bytes());
        out.extend_from_slice(&self.cleanup.get().to_be_bytes());
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            locator: r.locator()?,
            channel: ChannelInstance::new(r.u64()?).ok_or(Error::Malformed)?,
            reservation: ReservationId::new(r.u64()?).ok_or(Error::Malformed)?,
            cleanup: RequestId::new(r.u64()?).ok_or(Error::Malformed)?,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerResourceMessage {
    Reserve(OwnerResourceRequest),
    Reserved {
        request: OwnerResourceRequest,
        reservation: ReservationId,
        cleanup: RequestId,
    },
    Refused {
        request: OwnerResourceRequest,
        reason: ReservationRefusal,
    },
    Release(OwnerReleaseReport),
    Reported(OwnerReleaseReport),
}
impl OwnerResourceMessage {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Reserve(_) => 0x50,
            Self::Reserved { .. } => 0x51,
            Self::Refused { .. } => 0x52,
            Self::Release(_) => 0x53,
            Self::Reported(_) => 0x54,
        }
    }
    pub(super) fn role(&self) -> OwnerRole {
        match self {
            Self::Reserve(_) | Self::Release(_) => OwnerRole::Owner,
            _ => OwnerRole::Host,
        }
    }
    pub(super) fn locator(&self) -> SessionLocator {
        match self {
            Self::Reserve(r)
            | Self::Reserved { request: r, .. }
            | Self::Refused { request: r, .. } => r.locator,
            Self::Release(r) | Self::Reported(r) => r.locator,
        }
    }
    pub(super) fn request_kind(&self) -> Option<u8> {
        match self {
            Self::Reserve(_) => Some(0x50),
            Self::Release(_) => Some(0x53),
            _ => None,
        }
    }
    pub(super) fn reply_kind(&self) -> Option<u8> {
        match self {
            Self::Reserved { .. } | Self::Refused { .. } => Some(0x50),
            Self::Reported(_) => Some(0x53),
            _ => None,
        }
    }
    pub(super) fn matches_reply(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Reserve(a),
                Self::Reserved { request: b, .. } | Self::Refused { request: b, .. },
            ) => a == b,
            (Self::Release(a), Self::Reported(b)) => a == b,
            _ => false,
        }
    }
    pub(super) fn len(&self) -> Result<usize, Error> {
        Ok(match self {
            Self::Reserve(r) => {
                r.validate()?;
                r.len()
            }
            Self::Reserved { request: r, .. } => {
                r.validate()?;
                r.len() + 16
            }
            Self::Refused { request: r, .. } => {
                r.validate()?;
                r.len() + 1
            }
            Self::Release(_) | Self::Reported(_) => 56,
        })
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Reserve(r) => r.put(out),
            Self::Reserved {
                request,
                reservation,
                cleanup,
            } => {
                request.put(out);
                out.extend_from_slice(&reservation.get().to_be_bytes());
                out.extend_from_slice(&cleanup.get().to_be_bytes());
            }
            Self::Refused { request, reason } => {
                request.put(out);
                out.push(*reason as u8);
            }
            Self::Release(r) | Self::Reported(r) => r.put(out),
        }
    }
    pub(super) fn read(kind: u8, r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match kind {
            0x50 => Self::Reserve(OwnerResourceRequest::read(r)?),
            0x51 => Self::Reserved {
                request: OwnerResourceRequest::read(r)?,
                reservation: ReservationId::new(r.u64()?).ok_or(Error::Malformed)?,
                cleanup: RequestId::new(r.u64()?).ok_or(Error::Malformed)?,
            },
            0x52 => Self::Refused {
                request: OwnerResourceRequest::read(r)?,
                reason: match r.byte()? {
                    1 => ReservationRefusal::ResourceLimit,
                    2 => ReservationRefusal::InvalidRequest,
                    3 => ReservationRefusal::Unauthorized,
                    _ => return Err(Error::Malformed),
                },
            },
            0x53 => Self::Release(OwnerReleaseReport::read(r)?),
            0x54 => Self::Reported(OwnerReleaseReport::read(r)?),
            _ => return Err(Error::UnknownKind(kind)),
        })
    }
}
