//! Local owner lifecycle and administrative contracts, without runtime dispatch.
use super::authorization_contract::*;
use super::owner_resource_contract::OwnerResourceMessage;
use super::protocol::{OwnerProtocolError as Error, OwnerRole};
use super::status_contract::*;
use super::wire::*;
use transport::channel::{self, ClientRecord};
use transport::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, ResizeRefusal, ResizeRequestId,
};
use transport::session_resume::*;
use transport::Features;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenRefusal {
    InvalidOpen = 1,
    ResourceLimit = 2,
    BackendFailure = 3,
    Restarting = 4,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerOperation {
    Resource(OwnerResourceMessage),
    Open(OwnerOpen),
    Opened {
        attachment: Attachment,
        channel: ChannelInstance,
        stream: u8,
        geometry: GeometryRecord,
        has_screen: bool,
    },
    OpenRefused {
        attachment: Attachment,
        stream: u8,
        reason: OpenRefusal,
    },
    Resize(OwnerResize),
    ResizeResult {
        attachment: Attachment,
        geometry: GeometryRecord,
    },
    CloseChannel(OwnerCloseChannel),
    CloseSession(OwnerCloseSession),
    CloseAccepted(CloseAccepted),
    ExitReceipt(ExitReceipt),
    CatalogRequest {
        attachment: Attachment,
    },
    Catalog(RetainedCatalog),
    AttachWithGrant {
        locator: SessionLocator,
        frontend: FrontendGeneration,
        last_epoch: u64,
        grant: AttachGrant,
        binding: GrantBinding,
    },
    GrantRejected {
        locator: SessionLocator,
        frontend: FrontendGeneration,
        reason: AttachRefusal,
    },
    OwnerStatusRequest,
    OwnerStatus(OwnerStatus),
    Shutdown {
        transaction: RequestId,
        reason: CloseReason,
    },
    ShutdownReceipt {
        transaction: RequestId,
    },
}
impl OwnerOperation {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Resource(r) => r.kind(),
            Self::Open(_) => 0x10,
            Self::Opened { .. } => 0x11,
            Self::OpenRefused { .. } => 0x12,
            Self::Resize(_) => 0x13,
            Self::ResizeResult { .. } => 0x14,
            Self::CloseChannel(_) => 0x15,
            Self::CloseSession(_) => 0x16,
            Self::CloseAccepted(_) => 0x17,
            Self::ExitReceipt(_) => 0x18,
            Self::CatalogRequest { .. } => 0x19,
            Self::Catalog(_) => 0x1a,
            Self::AttachWithGrant { .. } => 0x20,
            Self::GrantRejected { .. } => 0x21,
            Self::OwnerStatusRequest => 0x22,
            Self::OwnerStatus(_) => 0x23,
            Self::Shutdown { .. } => 0x24,
            Self::ShutdownReceipt { .. } => 0x25,
        }
    }
    pub(super) fn role(&self) -> OwnerRole {
        match self {
            Self::Resource(r) => r.role(),
            Self::Open(_)
            | Self::Resize(_)
            | Self::CloseChannel(_)
            | Self::CloseSession(_)
            | Self::CatalogRequest { .. }
            | Self::AttachWithGrant { .. } => OwnerRole::Frontend,
            Self::OwnerStatusRequest | Self::Shutdown { .. } => OwnerRole::Host,
            _ => OwnerRole::Owner,
        }
    }
    pub(super) fn attachment(&self) -> Option<Attachment> {
        match self {
            Self::Open(o) => Some(o.attachment),
            Self::Opened { attachment, .. }
            | Self::OpenRefused { attachment, .. }
            | Self::ResizeResult { attachment, .. }
            | Self::CatalogRequest { attachment } => Some(*attachment),
            Self::Resize(r) => Some(r.attachment),
            Self::CloseChannel(c) => Some(c.attachment),
            Self::CloseSession(c) => Some(c.attachment),
            Self::CloseAccepted(c) => Some(c.attachment),
            Self::ExitReceipt(c) => Some(c.attachment),
            Self::Catalog(c) => Some(c.attachment()),
            _ => None,
        }
    }
    pub(super) fn owner(&self) -> Option<OwnerInstance> {
        if let Self::Resource(r) = self {
            return Some(r.locator().owner);
        }
        self.attachment().map(|a| a.locator.owner).or(match self {
            Self::AttachWithGrant { locator, .. } | Self::GrantRejected { locator, .. } => {
                Some(locator.owner)
            }
            Self::OwnerStatus(s) => Some(s.locator.owner),
            _ => None,
        })
    }
    pub(super) fn request_kind(&self) -> Option<u8> {
        if let Self::Resource(r) = self {
            return r.request_kind();
        }
        matches!(
            self,
            Self::Open(_)
                | Self::Resize(_)
                | Self::CloseChannel(_)
                | Self::CloseSession(_)
                | Self::CatalogRequest { .. }
                | Self::AttachWithGrant { .. }
                | Self::OwnerStatusRequest
                | Self::Shutdown { .. }
        )
        .then_some(self.kind())
    }
    pub(super) fn reply_kind(&self) -> Option<u8> {
        match self {
            Self::Resource(r) => r.reply_kind(),
            Self::Opened { .. } | Self::OpenRefused { .. } => Some(0x10),
            Self::ResizeResult { .. } => Some(0x13),
            Self::CloseAccepted(a) => Some(match a.target {
                CloseTarget::Channel(_) => 0x15,
                CloseTarget::Session => 0x16,
            }),
            Self::Catalog(_) => Some(0x19),
            Self::GrantRejected { .. } => Some(0x20),
            Self::OwnerStatus(_) => Some(0x22),
            Self::ShutdownReceipt { .. } => Some(0x24),
            _ => None,
        }
    }
    pub(super) fn matches_reply(&self, reply: &Self) -> bool {
        match (self, reply) {
            (Self::Resource(a), Self::Resource(b)) => a.matches_reply(b),
            (
                Self::Open(o),
                Self::Opened {
                    attachment, stream, ..
                }
                | Self::OpenRefused {
                    attachment, stream, ..
                },
            ) => o.attachment == *attachment && o.request.stream == *stream,
            (
                Self::Resize(r),
                Self::ResizeResult {
                    attachment,
                    geometry,
                },
            ) => {
                r.attachment == *attachment
                    && r.channel == geometry.instance
                    && r.request_id.get() == geometry.request_id
            }
            (Self::CloseChannel(c), Self::CloseAccepted(a)) => {
                c.attachment == a.attachment && a.target == CloseTarget::Channel(c.channel)
            }
            (Self::CloseSession(c), Self::CloseAccepted(a)) => {
                c.attachment == a.attachment && a.target == CloseTarget::Session
            }
            (Self::CatalogRequest { attachment }, Self::Catalog(c)) => {
                *attachment == c.attachment()
            }
            (
                Self::AttachWithGrant {
                    locator: l,
                    frontend: f,
                    ..
                },
                Self::GrantRejected {
                    locator, frontend, ..
                },
            ) => l == locator && f == frontend,
            (Self::OwnerStatusRequest, Self::OwnerStatus(_)) => true,
            (Self::Shutdown { transaction, .. }, Self::ShutdownReceipt { transaction: t }) => {
                transaction == t
            }
            _ => false,
        }
    }
    pub(super) fn body_len(&self) -> Result<usize, Error> {
        Ok(match self {
            Self::Resource(r) => r.len()?,
            Self::Open(o) => {
                o.validate()?;
                56 + 9 + o.request.command.len()
            }
            Self::Opened {
                channel,
                stream,
                geometry,
                has_screen,
                ..
            } => {
                if *stream < channel::FIRST_CHANNEL_STREAM
                    || *channel != geometry.instance
                    || geometry.request_id != 0
                    || *has_screen && (geometry.cols == 0 || geometry.rows == 0)
                {
                    return Err(Error::Malformed);
                }
                geometry.validate().map_err(|_| Error::Malformed)?;
                88
            }
            Self::OpenRefused { stream, .. } => {
                if *stream < channel::FIRST_CHANNEL_STREAM {
                    return Err(Error::Malformed);
                }
                58
            }
            Self::Resize(r) => {
                r.validate()?;
                76
            }
            Self::ResizeResult { geometry, .. } => {
                geometry.validate().map_err(|_| Error::Malformed)?;
                if geometry.request_id == 0 {
                    return Err(Error::Malformed);
                }
                78
            }
            Self::CloseChannel(_) => 73,
            Self::CloseSession(_) => 65,
            Self::CloseAccepted(_) => 73,
            Self::ExitReceipt(_) => 77,
            Self::CatalogRequest { .. } => 64,
            Self::Catalog(c) => {
                8 + 56 + 4 + c.channels().payload_len() + 2 + c.positions().len() * 79
            }
            Self::AttachWithGrant {
                locator,
                frontend,
                binding,
                ..
            } => {
                binding.validate()?;
                if *locator != binding.locator || *frontend != binding.frontend {
                    return Err(Error::Binding);
                }
                184
            }
            Self::GrantRejected { .. } => 49,
            Self::OwnerStatusRequest => 0,
            Self::OwnerStatus(s) => {
                s.validate()?;
                s.len()
            }
            Self::Shutdown { reason, .. } => {
                if *reason != CloseReason::Administrator {
                    return Err(Error::Binding);
                }
                9
            }
            Self::ShutdownReceipt { .. } => 8,
        })
    }
    pub(super) fn encode(&self, id: u64) -> Result<Vec<u8>, Error> {
        let len = self.body_len()?;
        let mut out = Vec::with_capacity(len);
        if let Self::Resource(r) = self {
            r.put(&mut out);
            return Ok(out);
        }
        let request = || RequestId::new(id).ok_or(Error::Binding);
        let control = match self {
            Self::CloseChannel(c) => Some(ResumeControl::CloseChannel {
                request_id: request()?,
                close: *c,
            }),
            Self::CloseSession(c) => Some(ResumeControl::CloseSession {
                request_id: request()?,
                close: *c,
            }),
            Self::CloseAccepted(a) => Some(ResumeControl::CloseAccepted {
                request_id: request()?,
                accepted: *a,
            }),
            Self::ExitReceipt(r) => Some(ResumeControl::ExitReceipt(*r)),
            Self::CatalogRequest { attachment } => Some(ResumeControl::CatalogRequest {
                request_id: request()?,
                attachment: *attachment,
            }),
            Self::Catalog(c) => Some(ResumeControl::Catalog {
                request_id: request()?,
                catalog: c.clone(),
            }),
            _ => None,
        };
        if let Some(c) = control {
            return Ok(
                transport::session_resume::encode_control(&c, Features::SESSION_RESUME)?[5..]
                    .to_vec(),
            );
        }
        match self {
            Self::Open(o) => {
                put_attachment(&mut out, o.attachment);
                let open = channel::encode_client(&ClientRecord::Open(o.request.clone()));
                out.extend_from_slice(&open[5..]);
            }
            Self::Opened {
                attachment,
                channel,
                stream,
                geometry,
                has_screen,
            } => {
                put_attachment(&mut out, *attachment);
                out.extend_from_slice(&channel.get().to_be_bytes());
                out.push(*stream);
                put_geometry(&mut out, *geometry);
                out.push(u8::from(*has_screen));
            }
            Self::OpenRefused {
                attachment,
                stream,
                reason,
            } => {
                put_attachment(&mut out, *attachment);
                out.push(*stream);
                out.push(*reason as u8);
            }
            Self::Resize(r) => {
                put_attachment(&mut out, r.attachment);
                out.extend_from_slice(&r.channel.get().to_be_bytes());
                out.extend_from_slice(&r.request_id.get().to_be_bytes());
                out.extend_from_slice(&r.cols.to_be_bytes());
                out.extend_from_slice(&r.rows.to_be_bytes());
            }
            Self::ResizeResult {
                attachment,
                geometry,
            } => {
                put_attachment(&mut out, *attachment);
                put_geometry(&mut out, *geometry);
            }
            Self::AttachWithGrant {
                locator,
                frontend,
                last_epoch,
                grant,
                binding,
            } => {
                out.extend_from_slice(&id.to_be_bytes());
                put_locator(&mut out, *locator);
                out.extend_from_slice(frontend.as_bytes());
                out.extend_from_slice(&last_epoch.to_be_bytes());
                out.extend_from_slice(grant.as_bytes());
                put_binding(&mut out, *binding);
            }
            Self::GrantRejected {
                locator,
                frontend,
                reason,
            } => {
                put_locator(&mut out, *locator);
                out.extend_from_slice(frontend.as_bytes());
                out.push(reason.to_wire());
            }
            Self::OwnerStatusRequest => {}
            Self::OwnerStatus(s) => s.put(&mut out),
            Self::Shutdown {
                transaction,
                reason,
            } => {
                out.extend_from_slice(&transaction.get().to_be_bytes());
                out.push(reason.to_wire());
            }
            Self::ShutdownReceipt { transaction } => {
                out.extend_from_slice(&transaction.get().to_be_bytes())
            }
            _ => unreachable!(),
        };
        Ok(out)
    }
    pub(super) fn decode(kind: u8, id: u64, body: &[u8]) -> Result<Self, Error> {
        if matches!(kind, 0x50..=0x54) {
            let mut r = Reader::new(body);
            let m = OwnerResourceMessage::read(kind, &mut r)?;
            r.finish()?;
            return Ok(Self::Resource(m));
        }
        let public = match kind {
            0x15 => Some(0x3a),
            0x16 => Some(0x3b),
            0x17 => Some(0x3c),
            0x18 => Some(0x3d),
            0x19 => Some(0x36),
            0x1a => Some(0x37),
            _ => None,
        };
        if let Some(kind) = public {
            let c = transport::session_resume::decode_control_payload(
                kind,
                body,
                Features::SESSION_RESUME,
            )?;
            if c.request_id().map_or(0, RequestId::get) != id {
                return Err(Error::Binding);
            }
            return Ok(match c {
                ResumeControl::CloseChannel { close, .. } => Self::CloseChannel(close),
                ResumeControl::CloseSession { close, .. } => Self::CloseSession(close),
                ResumeControl::CloseAccepted { accepted, .. } => Self::CloseAccepted(accepted),
                ResumeControl::ExitReceipt(r) => Self::ExitReceipt(r),
                ResumeControl::CatalogRequest { attachment, .. } => {
                    Self::CatalogRequest { attachment }
                }
                ResumeControl::Catalog { catalog, .. } => Self::Catalog(catalog),
                _ => unreachable!(),
            });
        }
        let mut r = Reader::new(body);
        let operation = match kind {
            0x10 => {
                let attachment = r.attachment()?;
                let payload = r.take(body.len() - 56)?;
                if payload.len() > 9 + channel::MAX_COMMAND_LEN {
                    return Err(Error::TooLarge);
                }
                let o = OwnerOpen::decode_payload(attachment, payload)?;
                Self::Open(o)
            }
            0x11 => {
                let attachment = r.attachment()?;
                let channel = read_channel(&mut r)?;
                let stream = r.byte()?;
                let geometry = read_geometry(&mut r)?;
                let has_screen = match r.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Malformed),
                };
                Self::Opened {
                    attachment,
                    channel,
                    stream,
                    geometry,
                    has_screen,
                }
            }
            0x12 => Self::OpenRefused {
                attachment: r.attachment()?,
                stream: r.byte()?,
                reason: match r.byte()? {
                    1 => OpenRefusal::InvalidOpen,
                    2 => OpenRefusal::ResourceLimit,
                    3 => OpenRefusal::BackendFailure,
                    4 => OpenRefusal::Restarting,
                    _ => return Err(Error::Malformed),
                },
            },
            0x13 => Self::Resize(OwnerResize {
                attachment: r.attachment()?,
                channel: read_channel(&mut r)?,
                request_id: ResizeRequestId::new(r.u64()?).ok_or(Error::Malformed)?,
                cols: r.u16()?,
                rows: r.u16()?,
            }),
            0x14 => Self::ResizeResult {
                attachment: r.attachment()?,
                geometry: read_geometry(&mut r)?,
            },
            0x20 => {
                if r.u64()? != id {
                    return Err(Error::Binding);
                }
                Self::AttachWithGrant {
                    locator: r.locator()?,
                    frontend: r.frontend()?,
                    last_epoch: r.u64()?,
                    grant: AttachGrant::new(r.array()?).ok_or(Error::Malformed)?,
                    binding: r.binding()?,
                }
            }
            0x21 => Self::GrantRejected {
                locator: r.locator()?,
                frontend: r.frontend()?,
                reason: AttachRefusal::from_wire(r.byte()?).ok_or(Error::Malformed)?,
            },
            0x22 => Self::OwnerStatusRequest,
            0x23 => Self::OwnerStatus(OwnerStatus::read(&mut r)?),
            0x24 => Self::Shutdown {
                transaction: RequestId::new(r.u64()?).ok_or(Error::Malformed)?,
                reason: CloseReason::from_wire(r.byte()?).ok_or(Error::Malformed)?,
            },
            0x25 => Self::ShutdownReceipt {
                transaction: RequestId::new(r.u64()?).ok_or(Error::Malformed)?,
            },
            _ => return Err(Error::UnknownKind(kind)),
        };
        r.finish()?;
        operation.body_len()?;
        Ok(operation)
    }
}
fn read_channel(r: &mut Reader<'_>) -> Result<ChannelInstance, Error> {
    ChannelInstance::new(r.u64()?).ok_or(Error::Malformed)
}
fn put_geometry(out: &mut Vec<u8>, g: GeometryRecord) {
    out.extend_from_slice(&g.instance.get().to_be_bytes());
    out.extend_from_slice(&g.request_id.to_be_bytes());
    let (code, reason) = match g.outcome {
        GeometryOutcome::Established => (0, 0),
        GeometryOutcome::Applied => (1, 0),
        GeometryOutcome::Refused(r) => (2, r as u8),
    };
    out.push(code);
    out.push(reason);
    out.extend_from_slice(&g.cols.to_be_bytes());
    out.extend_from_slice(&g.rows.to_be_bytes());
}
fn read_geometry(r: &mut Reader<'_>) -> Result<GeometryRecord, Error> {
    let instance = read_channel(r)?;
    let request_id = r.u64()?;
    let code = r.byte()?;
    let reason = r.byte()?;
    let outcome = match (code, reason) {
        (0, 0) => GeometryOutcome::Established,
        (1, 0) => GeometryOutcome::Applied,
        (2, r) => GeometryOutcome::Refused(match r {
            1 => ResizeRefusal::InvalidSize,
            2 => ResizeRefusal::NoPty,
            3 => ResizeRefusal::ResourceLimit,
            4 => ResizeRefusal::PtyResizeFailed,
            5 => ResizeRefusal::ScreenPreparationFailed,
            _ => return Err(Error::Malformed),
        }),
        _ => return Err(Error::Malformed),
    };
    let g = GeometryRecord {
        instance,
        request_id,
        outcome,
        cols: r.u16()?,
        rows: r.u16()?,
    };
    g.validate().map_err(|_| Error::Malformed)?;
    Ok(g)
}
