//! Independently versioned, bounded owner-specific IPC foundation.
//!
//! A matching role/instance is a routing check, not proof of authentication.
//! Runtime callers must validate their inherited/credential-checked endpoints.
use std::collections::BTreeMap;
use transport::session_resume::{
    self, HostInstance, OwnerInstance, RequestId, ResumeControl, ResumeData, ResumeError,
};
use transport::{shell_frame::RawRecord, Features};

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
    Hello { min_version: u16, max_version: u16 },
    HelloAck { selected_version: u16 },
    Control(ResumeControl),
    Data(ResumeData),
}
impl OwnerMessage {
    pub const fn kind(&self) -> u8 {
        match self {
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
    match &frame.message {
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
        1 => (4, 4),
        2 => (2, 2),
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
    let host = HostInstance::new(bytes[12..28].try_into().unwrap())
        .ok_or(OwnerProtocolError::Malformed)?;
    let owner = OwnerInstance::new(bytes[28..44].try_into().unwrap())
        .ok_or(OwnerProtocolError::Malformed)?;
    let request_id = u64::from_be_bytes(bytes[44..52].try_into().unwrap());
    let is_event = matches!(kind, 0x33 | 0x40..=0x43);
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
        1 => OwnerMessage::Hello {
            min_version: u16::from_be_bytes(body[..2].try_into().unwrap()),
            max_version: u16::from_be_bytes(body[2..].try_into().unwrap()),
        },
        2 => OwnerMessage::HelloAck {
            selected_version: u16::from_be_bytes(body.try_into().unwrap()),
        },
        0x30..=0x35 => OwnerMessage::Control(session_resume::decode_control(
            RawRecord {
                kind,
                payload: body.to_vec(),
            },
            Features::SESSION_RESUME,
        )?),
        0x40..=0x43 => OwnerMessage::Data(session_resume::decode_data(
            RawRecord {
                kind,
                payload: body.to_vec(),
            },
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
    Hello,
    Attach,
    Fence,
}
fn request_kind(message: &OwnerMessage) -> Option<RequestKind> {
    match message {
        OwnerMessage::Hello { .. } => Some(RequestKind::Hello),
        OwnerMessage::Control(ResumeControl::Attach { .. }) => Some(RequestKind::Attach),
        OwnerMessage::Control(ResumeControl::Fence { .. }) => Some(RequestKind::Fence),
        _ => None,
    }
}
fn reply_kind(message: &OwnerMessage) -> Option<RequestKind> {
    match message {
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
    local_role: OwnerRole,
    peer_role: OwnerRole,
    host: HostInstance,
    owner: OwnerInstance,
    outgoing: BTreeMap<u64, RequestKind>,
    incoming: BTreeMap<u64, RequestKind>,
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
        validate_frame(frame)?;
        // Validate nested lengths/offsets on typed frames as well as decoded ones.
        match &frame.message {
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
            if kind == RequestKind::Hello {
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
            table.insert(id, kind);
            *last = id;
            if kind == RequestKind::Hello {
                if sending {
                    self.hello_sent = true;
                } else {
                    self.hello_received = true;
                }
            }
        } else if let Some(kind) = reply_kind(&frame.message) {
            if kind != RequestKind::Hello && !self.ready {
                return Err(OwnerProtocolError::InvalidState);
            }
            let table = if sending {
                &mut self.incoming
            } else {
                &mut self.outgoing
            };
            if table.get(&id) != Some(&kind) {
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
