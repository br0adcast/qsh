//! Global-host IPC has no owner-instance field or owner-zero sentinel.
//! Decoding and role checks are not host authentication or grant minting.
use super::authorization_contract::*;
use super::protocol::{
    OwnerProtocolError as Error, OwnerRole, MAX_OWNER_FRAME, MAX_OWNER_REQUESTS,
};
use super::resource_contract::*;
use super::status_contract::*;
use super::wire::*;
use std::collections::BTreeMap;
use transport::session_resume::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReservationRefusal {
    ResourceLimit = 1,
    InvalidRequest = 2,
    Unauthorized = 3,
}
pub const HOST_HEADER_LEN: usize = 36;
pub const HOST_VERSION: u16 = 1;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostHeader {
    pub role: OwnerRole,
    pub host: HostInstance,
    pub request_id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostMessage {
    StatusRequest {
        frontend: FrontendGeneration,
        cursor: Option<StatusCursor>,
    },
    Status(StatusPage),
    Reserve {
        reservation: Reservation,
        cleanup: RequestId,
    },
    Reserved {
        reservation: Reservation,
        cleanup: RequestId,
    },
    ReservationRefused {
        reservation: Reservation,
        reason: ReservationRefusal,
    },
    Release {
        reservation: Reservation,
        receipt: ReservationReceipt,
    },
    Released {
        reservation: Reservation,
        receipt: ReservationReceipt,
    },
    AuthorizeAttach {
        principal: AuthenticatedPrincipalRef,
        locator: SessionLocator,
        frontend: FrontendGeneration,
    },
    AttachAuthorized {
        grant: AttachGrant,
        binding: GrantBinding,
    },
    AttachAuthorizationRefused {
        principal: AuthenticatedPrincipalRef,
        locator: SessionLocator,
        frontend: FrontendGeneration,
        reason: AttachRefusal,
    },
    RevokeFrontend {
        frontend: FrontendGeneration,
    },
    FrontendRevoked {
        frontend: FrontendGeneration,
    },
}
impl HostMessage {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::StatusRequest { .. } => 0x20,
            Self::Status(_) => 0x21,
            Self::Reserve { .. } => 0x22,
            Self::Reserved { .. } => 0x23,
            Self::ReservationRefused { .. } => 0x24,
            Self::Release { .. } => 0x25,
            Self::Released { .. } => 0x26,
            Self::AuthorizeAttach { .. } => 0x10,
            Self::AttachAuthorized { .. } => 0x11,
            Self::AttachAuthorizationRefused { .. } => 0x12,
            Self::RevokeFrontend { .. } => 0x13,
            Self::FrontendRevoked { .. } => 0x14,
        }
    }
    fn role(&self) -> OwnerRole {
        match self {
            Self::StatusRequest { .. }
            | Self::Reserve { .. }
            | Self::Release { .. }
            | Self::AuthorizeAttach { .. }
            | Self::FrontendRevoked { .. } => OwnerRole::Frontend,
            _ => OwnerRole::Host,
        }
    }
    fn body_len(&self) -> usize {
        match self {
            Self::StatusRequest { cursor, .. } => 17 + cursor.map_or(0, |_| 24),
            Self::Status(p) => p.len(),
            Self::Reserve { reservation, .. } | Self::Reserved { reservation, .. } => {
                reservation.len() + 8
            }
            Self::ReservationRefused { reservation, .. } => reservation.len() + 1,
            Self::Release { reservation, .. } | Self::Released { reservation, .. } => {
                reservation.len() + 56
            }
            Self::AuthorizeAttach { .. } => 64,
            Self::AttachAuthorized { .. } => 120,
            Self::AttachAuthorizationRefused { .. } => 65,
            Self::RevokeFrontend { .. } | Self::FrontendRevoked { .. } => 16,
        }
    }
    fn request_kind(&self) -> Option<u8> {
        match self {
            Self::StatusRequest { .. } => Some(0x20),
            Self::Reserve { .. } => Some(0x22),
            Self::Release { .. } => Some(0x25),
            Self::AuthorizeAttach { .. } => Some(0x10),
            Self::RevokeFrontend { .. } => Some(0x13),
            _ => None,
        }
    }
    fn reply_kind(&self) -> Option<u8> {
        match self {
            Self::Status(_) => Some(0x20),
            Self::Reserved { .. } | Self::ReservationRefused { .. } => Some(0x22),
            Self::Released { .. } => Some(0x25),
            Self::AttachAuthorized { .. } | Self::AttachAuthorizationRefused { .. } => Some(0x10),
            Self::FrontendRevoked { .. } => Some(0x13),
            _ => None,
        }
    }
    fn matches_reply(&self, reply: &Self) -> bool {
        match (self, reply) {
            (Self::StatusRequest { frontend, cursor }, Self::Status(p)) => {
                *frontend == p.frontend.generation
                    && match cursor {
                        None => p.cursor == 0,
                        Some(c) => p.epoch == c.epoch && p.cursor == c.index,
                    }
            }
            (
                Self::Reserve {
                    reservation: r,
                    cleanup: c,
                },
                Self::Reserved {
                    reservation,
                    cleanup,
                },
            ) => r == reservation && c == cleanup,
            (
                Self::Reserve { reservation: r, .. },
                Self::ReservationRefused { reservation, .. },
            ) => r == reservation,
            (
                Self::Release {
                    reservation: r,
                    receipt: c,
                },
                Self::Released {
                    reservation,
                    receipt,
                },
            ) => r == reservation && c == receipt,
            (
                Self::AuthorizeAttach {
                    principal,
                    locator,
                    frontend,
                },
                Self::AttachAuthorized { binding, .. },
            ) => {
                *principal == binding.principal
                    && *locator == binding.locator
                    && *frontend == binding.frontend
            }
            (
                Self::AuthorizeAttach {
                    principal: p,
                    locator: l,
                    frontend: f,
                },
                Self::AttachAuthorizationRefused {
                    principal,
                    locator,
                    frontend,
                    ..
                },
            ) => p == principal && l == locator && f == frontend,
            (Self::RevokeFrontend { frontend: a }, Self::FrontendRevoked { frontend: b }) => a == b,
            _ => false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFrame {
    pub header: HostHeader,
    pub message: HostMessage,
}
fn validate(frame: &HostFrame) -> Result<(), Error> {
    if frame.header.request_id == 0 || frame.header.role != frame.message.role() {
        return Err(Error::Binding);
    }
    match &frame.message {
        HostMessage::AttachAuthorized { binding, .. } => binding.validate()?,
        HostMessage::Status(p) => {
            p.validate()?;
            if p.host != frame.header.host {
                return Err(Error::Binding);
            }
        }
        HostMessage::Reserve { reservation, .. }
        | HostMessage::Reserved { reservation, .. }
        | HostMessage::ReservationRefused { reservation, .. } => reservation.validate()?,
        HostMessage::Release {
            reservation,
            receipt,
        }
        | HostMessage::Released {
            reservation,
            receipt,
        } => {
            reservation.validate()?;
            if !receipt.matches(*reservation) {
                return Err(Error::Binding);
            }
        }
        _ => {}
    }
    if frame.message.body_len() > MAX_OWNER_FRAME - HOST_HEADER_LEN {
        return Err(Error::TooLarge);
    }
    Ok(())
}
pub fn encode(frame: &HostFrame) -> Result<Vec<u8>, Error> {
    validate(frame)?;
    let len = frame.message.body_len();
    let mut out = Vec::with_capacity(HOST_HEADER_LEN + len);
    out.extend_from_slice(b"QSHH");
    out.extend_from_slice(&HOST_VERSION.to_be_bytes());
    out.push(frame.header.role.to_wire());
    out.push(frame.message.kind());
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.extend_from_slice(frame.header.host.as_bytes());
    out.extend_from_slice(&frame.header.request_id.to_be_bytes());
    match &frame.message {
        HostMessage::StatusRequest { frontend, cursor } => {
            out.extend_from_slice(frontend.as_bytes());
            if let Some(c) = cursor {
                out.push(1);
                out.extend_from_slice(c.epoch.as_bytes());
                out.extend_from_slice(&c.index.to_be_bytes());
            } else {
                out.push(0);
            }
        }
        HostMessage::Status(p) => p.put(&mut out),
        HostMessage::Reserve {
            reservation,
            cleanup,
        }
        | HostMessage::Reserved {
            reservation,
            cleanup,
        } => {
            reservation.put(&mut out);
            out.extend_from_slice(&cleanup.get().to_be_bytes());
        }
        HostMessage::ReservationRefused {
            reservation,
            reason,
        } => {
            reservation.put(&mut out);
            out.push(*reason as u8);
        }
        HostMessage::Release {
            reservation,
            receipt,
        }
        | HostMessage::Released {
            reservation,
            receipt,
        } => {
            reservation.put(&mut out);
            receipt.put(&mut out);
        }
        HostMessage::AuthorizeAttach {
            principal,
            locator,
            frontend,
        }
        | HostMessage::AttachAuthorizationRefused {
            principal,
            locator,
            frontend,
            ..
        } => {
            out.extend_from_slice(principal.as_bytes());
            put_locator(&mut out, *locator);
            out.extend_from_slice(frontend.as_bytes());
            if let HostMessage::AttachAuthorizationRefused { reason, .. } = &frame.message {
                out.push(reason.to_wire());
            }
        }
        HostMessage::AttachAuthorized { grant, binding } => {
            out.extend_from_slice(grant.as_bytes());
            put_binding(&mut out, *binding);
        }
        HostMessage::RevokeFrontend { frontend } | HostMessage::FrontendRevoked { frontend } => {
            out.extend_from_slice(frontend.as_bytes())
        }
    }
    Ok(out)
}
fn parse_header(bytes: &[u8]) -> Result<(HostHeader, u8, usize), Error> {
    if &bytes[..4] != b"QSHH" {
        return Err(Error::Malformed);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != HOST_VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let role = OwnerRole::from_wire(bytes[6]).ok_or(Error::Malformed)?;
    let kind = bytes[7];
    let len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if len > MAX_OWNER_FRAME - HOST_HEADER_LEN {
        return Err(Error::TooLarge);
    }
    let (min, max) = match kind {
        0x10 => (64, 64),
        0x11 => (120, 120),
        0x12 => (65, 65),
        0x13 | 0x14 => (16, 16),
        0x20 => (17, 41),
        0x21 => (150, 13740),
        0x22 | 0x23 => (82, 106),
        0x24 => (75, 99),
        0x25 | 0x26 => (130, 154),
        _ => return Err(Error::UnknownKind(kind)),
    };
    if len > max {
        return Err(Error::TooLarge);
    }
    if len < min {
        return Err(Error::Malformed);
    }
    let expected_role = if matches!(kind, 0x10 | 0x14 | 0x20 | 0x22 | 0x25) {
        OwnerRole::Frontend
    } else {
        OwnerRole::Host
    };
    if role != expected_role {
        return Err(Error::Binding);
    }
    let host = HostInstance::new(bytes[12..28].try_into().unwrap()).ok_or(Error::Malformed)?;
    let request_id = u64::from_be_bytes(bytes[28..36].try_into().unwrap());
    if request_id == 0 {
        return Err(Error::Binding);
    }
    Ok((
        HostHeader {
            role,
            host,
            request_id,
        },
        kind,
        len,
    ))
}
fn decode(bytes: &[u8]) -> Result<HostFrame, Error> {
    let (header, kind, len) = parse_header(&bytes[..HOST_HEADER_LEN])?;
    if bytes.len() != HOST_HEADER_LEN + len {
        return Err(Error::Malformed);
    }
    let mut r = Reader::new(&bytes[HOST_HEADER_LEN..]);
    let message = match kind {
        0x20 => {
            let frontend = r.frontend()?;
            let cursor = match r.byte()? {
                0 => None,
                1 => Some(StatusCursor {
                    epoch: StatusEpoch::new(r.array()?).ok_or(Error::Malformed)?,
                    index: r.u64()?,
                }),
                _ => return Err(Error::Malformed),
            };
            HostMessage::StatusRequest { frontend, cursor }
        }
        0x21 => HostMessage::Status(StatusPage::read(&mut r)?),
        0x22 | 0x23 => {
            let reservation = Reservation::read(&mut r)?;
            let cleanup = RequestId::new(r.u64()?).ok_or(Error::Malformed)?;
            if kind == 0x22 {
                HostMessage::Reserve {
                    reservation,
                    cleanup,
                }
            } else {
                HostMessage::Reserved {
                    reservation,
                    cleanup,
                }
            }
        }
        0x24 => HostMessage::ReservationRefused {
            reservation: Reservation::read(&mut r)?,
            reason: match r.byte()? {
                1 => ReservationRefusal::ResourceLimit,
                2 => ReservationRefusal::InvalidRequest,
                3 => ReservationRefusal::Unauthorized,
                _ => return Err(Error::Malformed),
            },
        },
        0x25 | 0x26 => {
            let reservation = Reservation::read(&mut r)?;
            let receipt = ReservationReceipt::read(&mut r)?;
            if kind == 0x25 {
                HostMessage::Release {
                    reservation,
                    receipt,
                }
            } else {
                HostMessage::Released {
                    reservation,
                    receipt,
                }
            }
        }
        0x10 => HostMessage::AuthorizeAttach {
            principal: r.principal()?,
            locator: r.locator()?,
            frontend: r.frontend()?,
        },
        0x11 => HostMessage::AttachAuthorized {
            grant: AttachGrant::new(r.array()?).ok_or(Error::Malformed)?,
            binding: r.binding()?,
        },
        0x12 => HostMessage::AttachAuthorizationRefused {
            principal: r.principal()?,
            locator: r.locator()?,
            frontend: r.frontend()?,
            reason: AttachRefusal::from_wire(r.byte()?).ok_or(Error::Malformed)?,
        },
        0x13 => HostMessage::RevokeFrontend {
            frontend: r.frontend()?,
        },
        0x14 => HostMessage::FrontendRevoked {
            frontend: r.frontend()?,
        },
        _ => return Err(Error::UnknownKind(kind)),
    };
    r.finish()?;
    let frame = HostFrame { header, message };
    validate(&frame)?;
    Ok(frame)
}
#[derive(Debug)]
pub struct HostDecoder {
    buf: Vec<u8>,
    expected: Option<usize>,
    failed: Option<Error>,
}
impl Default for HostDecoder {
    fn default() -> Self {
        Self::new()
    }
}
impl HostDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(HOST_HEADER_LEN),
            expected: None,
            failed: None,
        }
    }
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
    pub fn buffer_capacity(&self) -> usize {
        self.buf.capacity()
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<HostFrame>, Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let result = self.push_frames(bytes);
        if let Err(e) = result {
            self.failed = Some(e);
            self.buf.clear();
        }
        result
    }
    fn push_frames(&mut self, mut bytes: &[u8]) -> Result<Vec<HostFrame>, Error> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let target = self.expected.unwrap_or(HOST_HEADER_LEN);
            let count = (target - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.expected.is_none() && self.buf.len() == HOST_HEADER_LEN {
                let (_, _, len) = parse_header(&self.buf)?;
                self.expected = Some(HOST_HEADER_LEN + len);
                self.buf.reserve_exact(len);
            }
            if self.expected == Some(self.buf.len()) {
                frames.push(decode(&self.buf)?);
                self.buf.clear();
                self.expected = None;
            }
        }
        Ok(frames)
    }
    pub fn finish(&mut self) -> Result<(), Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if !self.buf.is_empty() {
            self.failed = Some(Error::Truncated);
            return Err(Error::Truncated);
        }
        Ok(())
    }
}
/// Bounded bidirectional monotonic request correlation with semantic reply binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPeerState {
    local: OwnerRole,
    peer: OwnerRole,
    host: HostInstance,
    last_sent: u64,
    last_received: u64,
    outgoing: BTreeMap<u64, HostMessage>,
    incoming: BTreeMap<u64, HostMessage>,
}
impl HostPeerState {
    pub fn new(local: OwnerRole, peer: OwnerRole, host: HostInstance) -> Self {
        Self {
            local,
            peer,
            host,
            last_sent: 0,
            last_received: 0,
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
        }
    }
    pub fn outstanding(&self) -> usize {
        self.outgoing.len()
    }
    pub fn incoming(&self) -> usize {
        self.incoming.len()
    }
    pub fn next_request_id(&self) -> Result<RequestId, Error> {
        self.last_sent
            .checked_add(1)
            .and_then(RequestId::new)
            .ok_or(Error::Exhausted)
    }
    pub fn send(&mut self, f: &HostFrame) -> Result<(), Error> {
        self.apply(f, true)
    }
    pub fn receive(&mut self, f: &HostFrame) -> Result<(), Error> {
        self.apply(f, false)
    }
    fn apply(&mut self, f: &HostFrame, sending: bool) -> Result<(), Error> {
        validate(f)?;
        if f.header.role != if sending { self.local } else { self.peer }
            || f.header.host != self.host
        {
            return Err(Error::Binding);
        }
        let id = f.header.request_id;
        if f.message.request_kind().is_some() {
            let (table, last) = if sending {
                (&mut self.outgoing, &mut self.last_sent)
            } else {
                (&mut self.incoming, &mut self.last_received)
            };
            if id <= *last {
                return Err(Error::ReusedRequest);
            }
            if table.len() >= MAX_OWNER_REQUESTS {
                return Err(Error::RequestLimit);
            }
            table.insert(id, f.message.clone());
            *last = id;
        } else if let Some(kind) = f.message.reply_kind() {
            let table = if sending {
                &mut self.incoming
            } else {
                &mut self.outgoing
            };
            let request = table.get(&id).ok_or(Error::UnexpectedReply)?;
            if request.request_kind() != Some(kind) || !request.matches_reply(&f.message) {
                return Err(Error::Binding);
            }
            table.remove(&id);
        } else {
            return Err(Error::UnknownKind(f.message.kind()));
        }
        Ok(())
    }
}
