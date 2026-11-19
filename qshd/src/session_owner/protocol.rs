//! Independently versioned, bounded owner-specific IPC foundation.
//!
//! A matching role/instance is a routing check, not proof of authentication.
//! Runtime callers must validate their inherited/credential-checked endpoints.
use super::local_admission_contract::{AdmissionSpec, AdmissionState, LocalAdmission};
use super::operations::OwnerOperation;
use std::collections::BTreeMap;
use transport::session_resume::{
    self, HostInstance, OwnerInstance, RequestId, ResumeControl, ResumeData, ResumeError,
};
use transport::Features;

pub const OWNER_VERSION: u16 = 1;
pub const OWNER_HEADER_LEN: usize = 52;
pub const MAX_OWNER_FRAME: usize = 65536;
pub const MAX_OWNER_REQUESTS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRole {
    Host,
    Frontend,
    Owner,
}
impl OwnerRole {
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Frontend => 2,
            Self::Owner => 3,
        }
    }
    pub const fn from_wire(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Host),
            2 => Some(Self::Frontend),
            3 => Some(Self::Owner),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerHeader {
    pub role: OwnerRole,
    pub host: HostInstance,
    pub owner: OwnerInstance,
    pub request_id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerMessage {
    Admission(LocalAdmission),
    Operation(OwnerOperation),
    Hello { min_version: u16, max_version: u16 },
    HelloAck { selected_version: u16 },
    Control(ResumeControl),
    Data(ResumeData),
}
impl OwnerMessage {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Admission(a) => a.kind(),
            Self::Operation(op) => op.kind(),
            Self::Hello { .. } => 1,
            Self::HelloAck { .. } => 2,
            Self::Control(record) => record.kind(),
            Self::Data(record) => record.kind(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerFrame {
    pub header: OwnerHeader,
    pub message: OwnerMessage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerProtocolError {
    Malformed,
    UnsupportedVersion,
    UnknownKind(u8),
    TooLarge,
    Binding,
    Truncated,
    InvalidState,
    RequestLimit,
    ReusedRequest,
    UnexpectedReply,
    Exhausted,
    Resume(ResumeError),
}
impl From<ResumeError> for OwnerProtocolError {
    fn from(error: ResumeError) -> Self {
        match error {
            ResumeError::Malformed => Self::Malformed,
            ResumeError::TooLarge => Self::TooLarge,
            ResumeError::UnknownKind(kind) => Self::UnknownKind(kind),
            other => Self::Resume(other),
        }
    }
}

fn validate_frame(frame: &OwnerFrame) -> Result<(), OwnerProtocolError> {
    let h = frame.header;
    if required_role(frame.message.kind()).is_some_and(|role| role != h.role) {
        return Err(OwnerProtocolError::Binding);
    }
    match &frame.message {
        OwnerMessage::Admission(a) => {
            a.validate()?;
            if h.request_id == 0 || !a.role_allowed(h.role, true) {
                return Err(OwnerProtocolError::Binding);
            }
        }
        OwnerMessage::Operation(op) => {
            if h.role != op.role()
                || op.owner().is_some_and(|owner| owner != h.owner)
                || (op.kind() == 0x18) != (h.request_id == 0)
            {
                return Err(OwnerProtocolError::Binding);
            }
            if op.body_len()? > MAX_OWNER_FRAME - OWNER_HEADER_LEN {
                return Err(OwnerProtocolError::TooLarge);
            }
        }
        OwnerMessage::Hello {
            min_version,
            max_version,
        } => {
            if *min_version > OWNER_VERSION || *max_version < OWNER_VERSION {
                return Err(OwnerProtocolError::UnsupportedVersion);
            }
            if h.request_id == 0 {
                return Err(OwnerProtocolError::Binding);
            }
        }
        OwnerMessage::HelloAck { selected_version } => {
            if *selected_version != OWNER_VERSION {
                return Err(OwnerProtocolError::UnsupportedVersion);
            }
            if h.request_id == 0 {
                return Err(OwnerProtocolError::Binding);
            }
        }
        OwnerMessage::Control(record) => {
            if record.request_id().map_or(0, RequestId::get) != h.request_id
                || record
                    .locator()
                    .is_some_and(|locator| locator.owner != h.owner)
            {
                return Err(OwnerProtocolError::Binding);
            }
        }
        OwnerMessage::Data(record) => {
            if h.request_id != 0 || record.attachment().locator.owner != h.owner {
                return Err(OwnerProtocolError::Binding);
            }
        }
    }
    Ok(())
}

pub fn encode(frame: &OwnerFrame) -> Result<Vec<u8>, OwnerProtocolError> {
    validate_frame(frame)?;
    let body = match &frame.message {
        OwnerMessage::Admission(a) => {
            let mut bytes = Vec::with_capacity(a.len());
            a.put(&mut bytes);
            bytes
        }
        OwnerMessage::Operation(op) => op.encode(frame.header.request_id)?,
        OwnerMessage::Hello {
            min_version,
            max_version,
        } => [min_version.to_be_bytes(), max_version.to_be_bytes()].concat(),
        OwnerMessage::HelloAck { selected_version } => selected_version.to_be_bytes().to_vec(),
        OwnerMessage::Control(record) => {
            session_resume::encode_control(record, Features::SESSION_RESUME)?[5..].to_vec()
        }
        OwnerMessage::Data(record) => {
            session_resume::encode_data(record, Features::SESSION_RESUME)?[5..].to_vec()
        }
    };
    if body.len() > MAX_OWNER_FRAME - OWNER_HEADER_LEN {
        return Err(OwnerProtocolError::TooLarge);
    }
    let mut out = Vec::with_capacity(OWNER_HEADER_LEN + body.len());
    out.extend_from_slice(b"QSHO");
    out.extend_from_slice(&OWNER_VERSION.to_be_bytes());
    out.push(frame.header.role.to_wire());
    out.push(frame.message.kind());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(frame.header.host.as_bytes());
    out.extend_from_slice(frame.header.owner.as_bytes());
    out.extend_from_slice(&frame.header.request_id.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn parse_header(bytes: &[u8]) -> Result<(OwnerHeader, u8, usize), OwnerProtocolError> {
    if &bytes[..4] != b"QSHO" {
        return Err(OwnerProtocolError::Malformed);
    }
    if u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != OWNER_VERSION {
        return Err(OwnerProtocolError::UnsupportedVersion);
    }
    let role = OwnerRole::from_wire(bytes[6]).ok_or(OwnerProtocolError::Malformed)?;
    let kind = bytes[7];
    let body_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if body_len > MAX_OWNER_FRAME - OWNER_HEADER_LEN {
        return Err(OwnerProtocolError::TooLarge);
    }
    let (min, max) = match kind {
        3 => (52, 52),
        4 => (50, 50),
        0x50 => (50, 74),
        0x51 => (66, 90),
        0x52 => (51, 75),
        0x53 | 0x54 => (56, 56),
        1 => (4, 4),
        2 => (2, 2),
        0x10 => (65, 65 + transport::channel::MAX_COMMAND_LEN),
        0x11 => (88, 88),
        0x12 => (58, 58),
        0x13 => (76, 76),
        0x14 => (78, 78),
        0x15 | 0x17 => (73, 73),
        0x16 => (65, 65),
        0x18 => (77, 77),
        0x19 => (64, 64),
        0x1a | 0x37 => (72, 8 + session_resume::MAX_CATALOG_BODY),
        0x20 => (184, 184),
        0x21 => (49, 49),
        0x22 => (0, 0),
        0x23 => (81, 208),
        0x24 => (9, 9),
        0x25 => (8, 8),
        0x36 | 0x39 => (64, 64),
        0x38 => (73, 105),
        0x3a | 0x3c => (73, 73),
        0x3b => (65, 65),
        0x3d => (77, 77),
        0x44 => (130, 130),
        0x45 => (93, 92 + session_resume::MAX_RESUME_DATA),
        0x46 => (104, 104),
        0x47 => (80, 80),
        0x30 | 0x31 | 0x34 | 0x35 => (64, 64),
        0x32 => (9, 9),
        0x33 => (57, 57),
        0x40 => (92, 92 + session_resume::MAX_RESUME_DATA),
        0x41 => (96, 96),
        0x42 => (76, 76 + session_resume::MAX_RESUME_DATA),
        0x43 => (72, 72),
        other => return Err(OwnerProtocolError::UnknownKind(other)),
    };
    if body_len < min || (min == max && body_len != max) {
        return Err(OwnerProtocolError::Malformed);
    }
    if body_len > max {
        return Err(OwnerProtocolError::TooLarge);
    }
    if (kind == 0x50 && !matches!(body_len, 50 | 74))
        || (kind == 0x51 && !matches!(body_len, 66 | 90))
        || (kind == 0x52 && !matches!(body_len, 51 | 75))
    {
        return Err(OwnerProtocolError::Malformed);
    }
    if (kind == 3 && role == OwnerRole::Host) || (kind == 4 && role == OwnerRole::Frontend) {
        return Err(OwnerProtocolError::Binding);
    }
    // Continuity tags0/1/2 have exactly these body sizes, before allocation.
    if kind == 0x38 && !matches!(body_len, 73 | 89 | 105) {
        return Err(OwnerProtocolError::Malformed);
    }
    let host = HostInstance::new(bytes[12..28].try_into().unwrap())
        .ok_or(OwnerProtocolError::Malformed)?;
    let owner = OwnerInstance::new(bytes[28..44].try_into().unwrap())
        .ok_or(OwnerProtocolError::Malformed)?;
    let request_id = u64::from_be_bytes(bytes[44..52].try_into().unwrap());
    let is_event = matches!(kind, 0x18 | 0x33 | 0x3d | 0x40..=0x47);
    if required_role(kind).is_some_and(|expected| role != expected) {
        return Err(OwnerProtocolError::Binding);
    }
    if is_event != (request_id == 0) {
        return Err(OwnerProtocolError::Binding);
    }
    Ok((
        OwnerHeader {
            role,
            host,
            owner,
            request_id,
        },
        kind,
        body_len,
    ))
}
fn decode(bytes: &[u8]) -> Result<OwnerFrame, OwnerProtocolError> {
    let (header, kind, len) = parse_header(&bytes[..OWNER_HEADER_LEN])?;
    if bytes.len() != OWNER_HEADER_LEN + len {
        return Err(OwnerProtocolError::Malformed);
    }
    let body = &bytes[OWNER_HEADER_LEN..];
    let message = match kind {
        3 | 4 => {
            let mut r = super::wire::Reader::new(body);
            let a = LocalAdmission::read(kind, &mut r)?;
            r.finish()?;
            OwnerMessage::Admission(a)
        }
        1 => OwnerMessage::Hello {
            min_version: u16::from_be_bytes(body[..2].try_into().unwrap()),
            max_version: u16::from_be_bytes(body[2..].try_into().unwrap()),
        },
        2 => OwnerMessage::HelloAck {
            selected_version: u16::from_be_bytes(body.try_into().unwrap()),
        },
        0x10..=0x25 | 0x50..=0x54 => {
            OwnerMessage::Operation(OwnerOperation::decode(kind, header.request_id, body)?)
        }
        0x30..=0x3d => OwnerMessage::Control(session_resume::decode_control_payload(
            kind,
            body,
            Features::SESSION_RESUME,
        )?),
        0x40..=0x47 => OwnerMessage::Data(session_resume::decode_data_payload(
            kind,
            body,
            Features::SESSION_RESUME,
        )?),
        other => return Err(OwnerProtocolError::UnknownKind(other)),
    };
    let frame = OwnerFrame { header, message };
    validate_frame(&frame)?;
    Ok(frame)
}

/// Buffers only one bounded frame. Header fields and kind-specific length are
/// validated before reserving body space. Any framing error is terminal.
#[derive(Debug)]
pub struct OwnerDecoder {
    buf: Vec<u8>,
    expected: Option<usize>,
    failed: Option<OwnerProtocolError>,
}
impl Default for OwnerDecoder {
    fn default() -> Self {
        Self::new()
    }
}
impl OwnerDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(OWNER_HEADER_LEN),
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
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<OwnerFrame>, OwnerProtocolError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.push_frames(bytes);
        if let Err(error) = result {
            self.failed = Some(error);
            self.buf.clear();
        }
        result
    }
    fn push_frames(&mut self, mut bytes: &[u8]) -> Result<Vec<OwnerFrame>, OwnerProtocolError> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let target = self.expected.unwrap_or(OWNER_HEADER_LEN);
            let count = (target - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if self.expected.is_none() && self.buf.len() == OWNER_HEADER_LEN {
                let (_, _, body_len) = parse_header(&self.buf)?;
                self.expected = Some(OWNER_HEADER_LEN + body_len);
                self.buf.reserve_exact(body_len);
            }
            if self.expected == Some(self.buf.len()) {
                frames.push(decode(&self.buf)?);
                self.buf.clear();
                self.expected = None;
            }
        }
        Ok(frames)
    }
    pub fn finish(&mut self) -> Result<(), OwnerProtocolError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !self.buf.is_empty() {
            self.failed = Some(OwnerProtocolError::Truncated);
            return Err(OwnerProtocolError::Truncated);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Admission,
    Hello,
    Attach,
    Fence,
    Extension(u8),
}
fn request_kind(message: &OwnerMessage) -> Option<RequestKind> {
    match message {
        OwnerMessage::Admission(a) => (a.kind() == 3).then_some(RequestKind::Admission),
        OwnerMessage::Operation(op) => op.request_kind().map(|k| {
            if k == 0x20 {
                RequestKind::Attach
            } else {
                RequestKind::Extension(k)
            }
        }),
        OwnerMessage::Control(ResumeControl::CatalogRequest { .. }) => {
            Some(RequestKind::Extension(0x36))
        }
        OwnerMessage::Control(ResumeControl::RecoveryRequest { .. }) => {
            Some(RequestKind::Extension(0x38))
        }
        OwnerMessage::Control(ResumeControl::CloseChannel { .. }) => {
            Some(RequestKind::Extension(0x3a))
        }
        OwnerMessage::Control(ResumeControl::CloseSession { .. }) => {
            Some(RequestKind::Extension(0x3b))
        }
        OwnerMessage::Hello { .. } => Some(RequestKind::Hello),
        OwnerMessage::Control(ResumeControl::Attach { .. }) => Some(RequestKind::Attach),
        OwnerMessage::Control(ResumeControl::Fence { .. }) => Some(RequestKind::Fence),
        _ => None,
    }
}
fn reply_kind(message: &OwnerMessage) -> Option<RequestKind> {
    match message {
        OwnerMessage::Admission(a) => (a.kind() == 4).then_some(RequestKind::Admission),
        OwnerMessage::Operation(op) => op.reply_kind().map(|k| {
            if k == 0x20 {
                RequestKind::Attach
            } else {
                RequestKind::Extension(k)
            }
        }),
        OwnerMessage::Control(ResumeControl::Catalog { .. }) => Some(RequestKind::Extension(0x36)),
        OwnerMessage::Control(ResumeControl::RecoveryReady { .. }) => {
            Some(RequestKind::Extension(0x38))
        }
        OwnerMessage::Control(ResumeControl::CloseAccepted { accepted, .. }) => {
            Some(RequestKind::Extension(match accepted.target {
                session_resume::CloseTarget::Channel(_) => 0x3a,
                session_resume::CloseTarget::Session => 0x3b,
            }))
        }
        OwnerMessage::HelloAck { .. } => Some(RequestKind::Hello),
        OwnerMessage::Control(
            ResumeControl::Attached { .. } | ResumeControl::AttachRefused { .. },
        ) => Some(RequestKind::Attach),
        OwnerMessage::Control(ResumeControl::Fenced { .. }) => Some(RequestKind::Fence),
        _ => None,
    }
}

/// Request correlation only. It neither authenticates principals nor schedules
/// queues; data events never occupy the separately bounded control tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerState {
    admission: Option<AdmissionState>,
    local_role: OwnerRole,
    peer_role: OwnerRole,
    host: HostInstance,
    owner: OwnerInstance,
    outgoing: BTreeMap<u64, OwnerMessage>,
    incoming: BTreeMap<u64, OwnerMessage>,
    last_sent: u64,
    last_received: u64,
    hello_sent: bool,
    hello_received: bool,
    ready: bool,
}
impl PeerState {
    pub fn new(
        local_role: OwnerRole,
        peer_role: OwnerRole,
        host: HostInstance,
        owner: OwnerInstance,
    ) -> Self {
        Self {
            admission: None,
            local_role,
            peer_role,
            host,
            owner,
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
            last_sent: 0,
            last_received: 0,
            hello_sent: false,
            hello_received: false,
            ready: false,
        }
    }
    pub fn with_admission(
        local: OwnerRole,
        peer: OwnerRole,
        host: HostInstance,
        owner: OwnerInstance,
        spec: AdmissionSpec,
    ) -> Result<Self, OwnerProtocolError> {
        let admission = AdmissionState::new(spec, local, peer, host, Some(owner))?;
        let mut value = Self::new(local, peer, host, owner);
        value.admission = Some(admission);
        Ok(value)
    }
    pub fn outstanding(&self) -> usize {
        self.outgoing.len()
    }
    pub fn incoming(&self) -> usize {
        self.incoming.len()
    }
    pub fn next_request_id(&self) -> Result<RequestId, OwnerProtocolError> {
        self.last_sent
            .checked_add(1)
            .and_then(RequestId::new)
            .ok_or(OwnerProtocolError::Exhausted)
    }
    pub fn send(&mut self, frame: &OwnerFrame) -> Result<(), OwnerProtocolError> {
        self.apply(frame, true)
    }
    pub fn receive(&mut self, frame: &OwnerFrame) -> Result<(), OwnerProtocolError> {
        self.apply(frame, false)
    }
    fn apply(&mut self, frame: &OwnerFrame, sending: bool) -> Result<(), OwnerProtocolError> {
        let mut admission = self.admission.clone();
        match &frame.message {
            OwnerMessage::Admission(m) => admission
                .as_mut()
                .ok_or(OwnerProtocolError::InvalidState)?
                .apply(frame.header.request_id, frame.header.role, m)?,
            _ => {
                if admission.as_ref().is_some_and(|a| !a.ready()) {
                    return Err(OwnerProtocolError::InvalidState);
                }
                if matches!(
                    &frame.message,
                    OwnerMessage::Operation(OwnerOperation::Resource(_))
                ) && admission.is_none()
                {
                    return Err(OwnerProtocolError::InvalidState);
                }
            }
        }
        self.apply_correlated(frame, sending)?;
        self.admission = admission;
        Ok(())
    }
    fn apply_correlated(
        &mut self,
        frame: &OwnerFrame,
        sending: bool,
    ) -> Result<(), OwnerProtocolError> {
        validate_frame(frame)?;
        // Validate nested lengths/offsets on typed frames as well as decoded ones.
        match &frame.message {
            OwnerMessage::Operation(op) => {
                op.body_len()?;
            }
            OwnerMessage::Data(record) => {
                session_resume::encode_data(record, Features::SESSION_RESUME)?;
            }
            OwnerMessage::Control(record) => {
                session_resume::encode_control(record, Features::SESSION_RESUME)?;
            }
            _ => {}
        }
        let role = if sending {
            self.local_role
        } else {
            self.peer_role
        };
        if frame.header.role != role
            || frame.header.host != self.host
            || frame.header.owner != self.owner
        {
            return Err(OwnerProtocolError::Binding);
        }
        let id = frame.header.request_id;
        if let Some(kind) = request_kind(&frame.message) {
            if kind == RequestKind::Admission {
                // The separate opt-in admission gate precedes Hello.
            } else if kind == RequestKind::Hello {
                if self.ready
                    || if sending {
                        self.hello_sent
                    } else {
                        self.hello_received
                    }
                {
                    return Err(OwnerProtocolError::InvalidState);
                }
            } else if !self.ready {
                return Err(OwnerProtocolError::InvalidState);
            }
            let (table, last) = if sending {
                (&mut self.outgoing, &mut self.last_sent)
            } else {
                (&mut self.incoming, &mut self.last_received)
            };
            if id <= *last {
                return Err(OwnerProtocolError::ReusedRequest);
            }
            if table.len() >= MAX_OWNER_REQUESTS {
                return Err(OwnerProtocolError::RequestLimit);
            }
            table.insert(id, frame.message.clone());
            *last = id;
            if kind == RequestKind::Hello {
                if sending {
                    self.hello_sent = true;
                } else {
                    self.hello_received = true;
                }
            }
        } else if let Some(kind) = reply_kind(&frame.message) {
            if kind != RequestKind::Hello && kind != RequestKind::Admission && !self.ready {
                return Err(OwnerProtocolError::InvalidState);
            }
            let table = if sending {
                &mut self.incoming
            } else {
                &mut self.outgoing
            };
            if table.get(&id).is_none_or(|request| {
                request_kind(request) != Some(kind) || !reply_matches(request, &frame.message)
            }) {
                return Err(OwnerProtocolError::UnexpectedReply);
            }
            table.remove(&id);
            if kind == RequestKind::Hello {
                self.ready = true;
            }
        } else if !self.ready {
            return Err(OwnerProtocolError::InvalidState);
        }
        Ok(())
    }
}

fn reply_matches(request: &OwnerMessage, reply: &OwnerMessage) -> bool {
    use session_resume::ResumeControl as C;
    match (request, reply) {
        (OwnerMessage::Admission(a), OwnerMessage::Admission(b)) => a.matches_reply(b),
        (OwnerMessage::Hello { .. }, OwnerMessage::HelloAck { .. }) => true,
        (OwnerMessage::Operation(a), OwnerMessage::Operation(b)) => a.matches_reply(b),
        (
            OwnerMessage::Operation(OwnerOperation::AttachWithGrant {
                locator,
                frontend,
                last_epoch,
                ..
            }),
            OwnerMessage::Control(C::Attached { attachment, .. }),
        ) => {
            *locator == attachment.locator
                && *frontend == attachment.frontend
                && attachment.epoch.get() > *last_epoch
        }
        (
            OwnerMessage::Control(C::Attach {
                locator,
                frontend,
                last_epoch,
                ..
            }),
            OwnerMessage::Control(C::Attached { attachment, .. }),
        ) => {
            *locator == attachment.locator
                && *frontend == attachment.frontend
                && attachment.epoch.get() > *last_epoch
        }
        (
            OwnerMessage::Control(C::Attach { .. }),
            OwnerMessage::Control(C::AttachRefused { .. }),
        ) => true,
        (
            OwnerMessage::Control(C::Fence { attachment: a, .. }),
            OwnerMessage::Control(C::Fenced { attachment: b, .. }),
        ) => a == b,
        (
            OwnerMessage::Control(C::CatalogRequest { attachment, .. }),
            OwnerMessage::Control(C::Catalog { catalog, .. }),
        ) => *attachment == catalog.attachment(),
        (
            OwnerMessage::Control(C::RecoveryRequest { request, .. }),
            OwnerMessage::Control(C::RecoveryReady { attachment, .. }),
        ) => request.attachment == *attachment,
        (
            OwnerMessage::Control(C::CloseChannel { close, .. }),
            OwnerMessage::Control(C::CloseAccepted { accepted, .. }),
        ) => {
            close.attachment == accepted.attachment
                && accepted.target == session_resume::CloseTarget::Channel(close.channel)
        }
        (
            OwnerMessage::Control(C::CloseSession { close, .. }),
            OwnerMessage::Control(C::CloseAccepted { accepted, .. }),
        ) => {
            close.attachment == accepted.attachment
                && accepted.target == session_resume::CloseTarget::Session
        }
        _ => false,
    }
}

fn required_role(kind: u8) -> Option<OwnerRole> {
    match kind {
        0x10 | 0x13 | 0x15 | 0x16 | 0x19 | 0x20 | 0x36 | 0x38 | 0x3a | 0x3b => {
            Some(OwnerRole::Frontend)
        }
        0x22 | 0x24 | 0x51 | 0x52 | 0x54 => Some(OwnerRole::Host),
        0x50 | 0x53 => Some(OwnerRole::Owner),
        0x11
        | 0x12
        | 0x14
        | 0x17
        | 0x18
        | 0x1a
        | 0x21
        | 0x23
        | 0x25
        | 0x37
        | 0x39
        | 0x3c
        | 0x3d
        | 0x44..=0x47 => Some(OwnerRole::Owner),
        _ => None,
    }
}
