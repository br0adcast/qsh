//! Untrusted QSHH authentication records and bounded semantic correlation.
//! Nothing here verifies a key, admits a peer, mints a grant or owns a child.
use super::authorization_contract::{AttachGrant, GrantBinding};
use super::protocol::{OwnerProtocolError as Error, OwnerRole};
use super::wire::{put_binding, put_locator, Reader};
use std::collections::BTreeMap;
use std::io::Write;
use transport::session_resume::{AttachRefusal, FrontendGeneration, SessionLocator};
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthReference([u8; 16]);
impl AuthReference {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
impl std::fmt::Debug for AuthReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthReference([REDACTED])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    Personal = 1,
    System = 2,
}
impl AuthMethod {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        match r.byte()? {
            1 => Ok(Self::Personal),
            2 => Ok(Self::System),
            _ => Err(Error::Malformed),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthRefusal {
    InvalidRequest = 1,
    Unavailable = 2,
    Unauthorized = 3,
    Expired = 4,
    Cancelled = 5,
}
impl AuthRefusal {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        match r.byte()? {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::Unavailable),
            3 => Ok(Self::Unauthorized),
            4 => Ok(Self::Expired),
            5 => Ok(Self::Cancelled),
            _ => Err(Error::Malformed),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    Accepted(AuthReference),
    Refused(AuthRefusal),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachOutcome {
    Granted {
        grant: AttachGrant,
        binding: GrantBinding,
    },
    Refused(AttachRefusal),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostAuthMessage {
    Begin {
        method: AuthMethod,
    },
    Challenge {
        method: AuthMethod,
        ticket: AuthReference,
        deadline: u64,
        nonce: Option<[u8; 16]>,
    },
    ChallengeRefused {
        method: AuthMethod,
        reason: AuthRefusal,
    },
    SystemProof {
        ticket: AuthReference,
        handshake_hash: [u8; 32],
        record: transport::AuthRecord,
    },
    PersonalReport {
        ticket: AuthReference,
        key: [u8; 32],
        session_id: u64,
        token: [u8; 16],
    },
    Result {
        ticket: AuthReference,
        outcome: AuthOutcome,
    },
    Cancel {
        ticket: AuthReference,
    },
    Cancelled {
        ticket: AuthReference,
    },
    AuthorizeAttach {
        context: AuthReference,
        locator: SessionLocator,
    },
    AttachResult {
        context: AuthReference,
        locator: SessionLocator,
        outcome: AttachOutcome,
    },
}
fn reference(r: &mut Reader<'_>) -> Result<AuthReference, Error> {
    AuthReference::new(r.array()?).ok_or(Error::Malformed)
}
// Serialize-only borrowed mirror of helper::protocol::Request::Verify. This
// counts its existing exact cap and is never a wire payload or helper request.
#[derive(serde::Serialize)]
enum HelperBound<'a> {
    Verify {
        login: &'a str,
        public_key: &'a [u8],
        signature: &'a [u8],
        handshake_hash: [u8; 32],
        nonce: [u8; 16],
        login_id: [u8; 16],
        rhost: &'a str,
    },
}
fn helper_bound<'a>(
    record: &'a transport::AuthRecord,
    hash: [u8; 32],
) -> Result<HelperBound<'a>, Error> {
    let v2 = record.v2.as_ref().ok_or(Error::Malformed)?;
    Ok(HelperBound::Verify {
        login: &v2.login,
        public_key: &record.public_key,
        signature: &record.signature,
        handshake_hash: hash,
        nonce: v2.nonce,
        login_id: [0; 16],
        rhost: "",
    })
}
struct Count(usize);
impl Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let n = self
            .0
            .checked_add(b.len())
            .ok_or_else(|| std::io::Error::other("proof bound"))?;
        if n > 8192 {
            return Err(std::io::Error::other("proof bound"));
        }
        self.0 = n;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn proof_bytes(record: &transport::AuthRecord, hash: [u8; 32]) -> Result<Vec<u8>, Error> {
    let v2 = record.v2.as_ref().ok_or(Error::Malformed)?;
    let len = 22usize
        .checked_add(v2.login.len())
        .and_then(|n| n.checked_add(record.public_key.len()))
        .and_then(|n| n.checked_add(record.signature.len()))
        .ok_or(Error::TooLarge)?;
    if len > 8142 {
        return Err(Error::TooLarge);
    }
    let bytes = transport::encode_auth_record(record).map_err(|_| Error::Malformed)?;
    serde_json::to_writer(Count(0), &helper_bound(record, hash)?).map_err(|_| Error::TooLarge)?;
    Ok(bytes)
}
impl HostAuthMessage {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Begin { .. } => 0x30,
            Self::Challenge { .. } | Self::ChallengeRefused { .. } => 0x31,
            Self::SystemProof { .. } => 0x32,
            Self::PersonalReport { .. } => 0x33,
            Self::Result { .. } => 0x34,
            Self::Cancel { .. } => 0x35,
            Self::Cancelled { .. } => 0x36,
            Self::AuthorizeAttach { .. } => 0x37,
            Self::AttachResult { .. } => 0x38,
        }
    }
    pub(super) fn role(&self) -> OwnerRole {
        match self {
            Self::Begin { .. }
            | Self::SystemProof { .. }
            | Self::PersonalReport { .. }
            | Self::Cancel { .. }
            | Self::AuthorizeAttach { .. } => OwnerRole::Frontend,
            _ => OwnerRole::Host,
        }
    }
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Begin { .. } => 1,
            Self::Challenge { nonce, .. } => 26 + nonce.map_or(0, |_| 16),
            Self::ChallengeRefused { .. } => 3,
            Self::SystemProof { record, .. } => 72usize
                .saturating_add(record.v2.as_ref().map_or(0, |v| v.login.len()))
                .saturating_add(record.public_key.len())
                .saturating_add(record.signature.len()),
            Self::PersonalReport { .. } => 72,
            Self::Result {
                outcome: AuthOutcome::Accepted(_),
                ..
            } => 33,
            Self::Result { .. } => 18,
            Self::Cancel { .. } | Self::Cancelled { .. } => 16,
            Self::AuthorizeAttach { .. } => 48,
            Self::AttachResult {
                outcome: AttachOutcome::Granted { .. },
                ..
            } => 169,
            Self::AttachResult { .. } => 50,
        }
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Challenge {
                method,
                deadline,
                nonce,
                ..
            } => {
                if *deadline == 0 || (*method == AuthMethod::System) != nonce.is_some() {
                    return Err(Error::Malformed);
                }
            }
            Self::SystemProof {
                handshake_hash,
                record,
                ..
            } => {
                proof_bytes(record, *handshake_hash)?;
            }
            Self::Result {
                ticket,
                outcome: AuthOutcome::Accepted(c),
            } if ticket == c => return Err(Error::Binding),
            Self::AttachResult {
                locator,
                outcome: AttachOutcome::Granted { binding, .. },
                ..
            } => {
                binding.validate()?;
                if *locator != binding.locator {
                    return Err(Error::Binding);
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn request_kind(&self) -> Option<u8> {
        match self {
            Self::SystemProof { .. } | Self::PersonalReport { .. } => Some(0x32),
            Self::Begin { .. } | Self::Cancel { .. } | Self::AuthorizeAttach { .. } => {
                Some(self.kind())
            }
            _ => None,
        }
    }
    pub(super) fn reply_kind(&self) -> Option<u8> {
        match self {
            Self::Challenge { .. } | Self::ChallengeRefused { .. } => Some(0x30),
            Self::Result { .. } => Some(0x32),
            Self::Cancelled { .. } => Some(0x35),
            Self::AttachResult { .. } => Some(0x37),
            _ => None,
        }
    }
    pub(super) fn matches_reply(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Begin { method: a },
                Self::Challenge { method: b, .. } | Self::ChallengeRefused { method: b, .. },
            ) => a == b,
            (
                Self::SystemProof { ticket: a, .. } | Self::PersonalReport { ticket: a, .. },
                Self::Result { ticket: b, .. },
            )
            | (Self::Cancel { ticket: a }, Self::Cancelled { ticket: b }) => a == b,
            (
                Self::AuthorizeAttach {
                    context: a,
                    locator: b,
                },
                Self::AttachResult {
                    context: c,
                    locator: d,
                    ..
                },
            ) => a == c && b == d,
            _ => false,
        }
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Begin { method } => out.push(*method as u8),
            Self::Challenge {
                method,
                ticket,
                deadline,
                nonce,
            } => {
                out.extend_from_slice(&[1, *method as u8]);
                out.extend_from_slice(ticket.as_bytes());
                out.extend_from_slice(&deadline.to_be_bytes());
                if let Some(n) = nonce {
                    out.extend_from_slice(n);
                }
            }
            Self::ChallengeRefused { method, reason } => {
                out.extend_from_slice(&[0, *method as u8, *reason as u8])
            }
            Self::SystemProof {
                ticket,
                handshake_hash,
                record,
            } => {
                out.extend_from_slice(ticket.as_bytes());
                out.extend_from_slice(handshake_hash);
                let bytes =
                    transport::encode_auth_record(record).expect("validated canonical proof");
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(&bytes);
            }
            Self::PersonalReport {
                ticket,
                key,
                session_id,
                token,
            } => {
                out.extend_from_slice(ticket.as_bytes());
                out.extend_from_slice(key);
                out.extend_from_slice(&session_id.to_be_bytes());
                out.extend_from_slice(token);
            }
            Self::Result { ticket, outcome } => {
                out.extend_from_slice(ticket.as_bytes());
                match outcome {
                    AuthOutcome::Accepted(c) => {
                        out.push(1);
                        out.extend_from_slice(c.as_bytes());
                    }
                    AuthOutcome::Refused(r) => out.extend_from_slice(&[0, *r as u8]),
                }
            }
            Self::Cancel { ticket } | Self::Cancelled { ticket } => {
                out.extend_from_slice(ticket.as_bytes())
            }
            Self::AuthorizeAttach { context, locator } => {
                out.extend_from_slice(context.as_bytes());
                put_locator(out, *locator);
            }
            Self::AttachResult {
                context,
                locator,
                outcome,
            } => {
                out.extend_from_slice(context.as_bytes());
                put_locator(out, *locator);
                match outcome {
                    AttachOutcome::Granted { grant, binding } => {
                        out.push(1);
                        out.extend_from_slice(grant.as_bytes());
                        put_binding(out, *binding);
                    }
                    AttachOutcome::Refused(r) => out.extend_from_slice(&[0, r.to_wire()]),
                }
            }
        }
    }
    pub(super) fn read(kind: u8, r: &mut Reader<'_>) -> Result<Self, Error> {
        let m = match kind {
            0x30 => Self::Begin {
                method: AuthMethod::read(r)?,
            },
            0x31 => {
                let status = r.byte()?;
                let method = AuthMethod::read(r)?;
                match status {
                    0 => Self::ChallengeRefused {
                        method,
                        reason: AuthRefusal::read(r)?,
                    },
                    1 => Self::Challenge {
                        method,
                        ticket: reference(r)?,
                        deadline: r.u64()?,
                        nonce: if method == AuthMethod::System {
                            Some(r.array()?)
                        } else {
                            None
                        },
                    },
                    _ => return Err(Error::Malformed),
                }
            }
            0x32 => {
                let ticket = reference(r)?;
                let handshake_hash = r.array()?;
                let len = r.u16()? as usize;
                if len > 8142 {
                    return Err(Error::TooLarge);
                }
                let bytes = r.take(len)?;
                let record = transport::parse_auth_record(bytes).map_err(|_| Error::Malformed)?;
                if proof_bytes(&record, handshake_hash)? != bytes {
                    return Err(Error::Malformed);
                }
                Self::SystemProof {
                    ticket,
                    handshake_hash,
                    record,
                }
            }
            0x33 => Self::PersonalReport {
                ticket: reference(r)?,
                key: r.array()?,
                session_id: r.u64()?,
                token: r.array()?,
            },
            0x34 => {
                let ticket = reference(r)?;
                let outcome = match r.byte()? {
                    0 => AuthOutcome::Refused(AuthRefusal::read(r)?),
                    1 => AuthOutcome::Accepted(reference(r)?),
                    _ => return Err(Error::Malformed),
                };
                Self::Result { ticket, outcome }
            }
            0x35 => Self::Cancel {
                ticket: reference(r)?,
            },
            0x36 => Self::Cancelled {
                ticket: reference(r)?,
            },
            0x37 => Self::AuthorizeAttach {
                context: reference(r)?,
                locator: r.locator()?,
            },
            0x38 => {
                let context = reference(r)?;
                let locator = r.locator()?;
                let outcome = match r.byte()? {
                    0 => AttachOutcome::Refused(
                        AttachRefusal::from_wire(r.byte()?).ok_or(Error::Malformed)?,
                    ),
                    1 => AttachOutcome::Granted {
                        grant: AttachGrant::new(r.array()?).ok_or(Error::Malformed)?,
                        binding: r.binding()?,
                    },
                    _ => return Err(Error::Malformed),
                };
                Self::AttachResult {
                    context,
                    locator,
                    outcome,
                }
            }
            _ => return Err(Error::UnknownKind(kind)),
        };
        m.validate()?;
        Ok(m)
    }
    pub(super) fn retired_by(&self, r: Retired) -> bool {
        match self {
            Self::SystemProof { ticket, .. }
            | Self::PersonalReport { ticket, .. }
            | Self::Cancel { ticket } => *ticket == r.ticket,
            Self::AuthorizeAttach { context, .. } => Some(*context) == r.context,
            _ => false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ticket {
    deadline: u64,
    nonce: Option<[u8; 16]>,
    proof: Option<u64>,
    context: Option<AuthReference>,
    attach: Option<(u64, SessionLocator)>,
    cancel: Option<u64>,
}
#[derive(Debug, Clone, Copy)]
pub(super) struct Retired {
    ticket: AuthReference,
    context: Option<AuthReference>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthCorrelation {
    method: AuthMethod,
    frontend: FrontendGeneration,
    limit: usize,
    begins: BTreeMap<u64, AuthMethod>,
    tickets: BTreeMap<AuthReference, Ticket>,
}
impl AuthCorrelation {
    pub(super) fn new(
        method: AuthMethod,
        frontend: FrontendGeneration,
        limit: usize,
    ) -> Result<Self, Error> {
        if limit == 0 || limit > 64 {
            return Err(Error::RequestLimit);
        }
        Ok(Self {
            method,
            frontend,
            limit,
            begins: BTreeMap::new(),
            tickets: BTreeMap::new(),
        })
    }
    pub(super) fn retire_local(&mut self, ticket: AuthReference) -> Option<Retired> {
        self.tickets.remove(&ticket).map(|t| Retired {
            ticket,
            context: t.context,
        })
    }
    pub(super) fn apply(
        &mut self,
        id: u64,
        m: &HostAuthMessage,
        now: u64,
    ) -> Result<Option<Retired>, Error> {
        match m {
            HostAuthMessage::Begin { method } => {
                if *method != self.method {
                    return Err(Error::Binding);
                }
                if self.begins.len() + self.tickets.len() >= self.limit {
                    return Err(Error::RequestLimit);
                }
                if self.begins.contains_key(&id) {
                    return Err(Error::ReusedRequest);
                }
                self.begins.insert(id, *method);
            }
            HostAuthMessage::Challenge {
                method,
                ticket,
                deadline,
                nonce,
            } => {
                if self.begins.get(&id) != Some(method)
                    || *method != self.method
                    || *deadline <= now
                    || self.tickets.contains_key(ticket)
                    || self.tickets.values().any(|t| t.context == Some(*ticket))
                {
                    return Err(Error::Binding);
                }
                self.begins.remove(&id);
                self.tickets.insert(
                    *ticket,
                    Ticket {
                        deadline: *deadline,
                        nonce: *nonce,
                        proof: None,
                        context: None,
                        attach: None,
                        cancel: None,
                    },
                );
            }
            HostAuthMessage::ChallengeRefused { method, .. } => {
                if self.begins.get(&id) != Some(method) {
                    return Err(Error::UnexpectedReply);
                }
                self.begins.remove(&id);
            }
            HostAuthMessage::SystemProof { ticket, .. }
            | HostAuthMessage::PersonalReport { ticket, .. } => {
                let t = self.tickets.get_mut(ticket).ok_or(Error::UnexpectedReply)?;
                if t.proof.is_some()
                    || t.context.is_some()
                    || t.cancel.is_some()
                    || now >= t.deadline
                {
                    return Err(Error::InvalidState);
                }
                match m {
                    HostAuthMessage::SystemProof { record, .. } => {
                        if self.method != AuthMethod::System
                            || record.v2.as_ref().map(|v| v.nonce) != t.nonce
                        {
                            return Err(Error::Binding);
                        }
                    }
                    HostAuthMessage::PersonalReport { .. } => {
                        if self.method != AuthMethod::Personal {
                            return Err(Error::Binding);
                        }
                    }
                    _ => unreachable!(),
                }
                t.proof = Some(id);
            }
            HostAuthMessage::Result { ticket, outcome } => {
                let t = self.tickets.get(ticket).ok_or(Error::UnexpectedReply)?;
                if t.proof != Some(id) || t.cancel.is_some() || now >= t.deadline {
                    return Err(Error::InvalidState);
                }
                match outcome {
                    AuthOutcome::Accepted(c) => {
                        if c == ticket
                            || self.tickets.contains_key(c)
                            || self.tickets.values().any(|t| t.context == Some(*c))
                        {
                            return Err(Error::Binding);
                        }
                        let t = self.tickets.get_mut(ticket).unwrap();
                        t.proof = None;
                        t.context = Some(*c);
                    }
                    AuthOutcome::Refused(_) => {
                        self.tickets.remove(ticket);
                        return Ok(Some(Retired {
                            ticket: *ticket,
                            context: None,
                        }));
                    }
                }
            }
            HostAuthMessage::Cancel { ticket } => {
                let t = self.tickets.get_mut(ticket).ok_or(Error::UnexpectedReply)?;
                if t.cancel.is_some() {
                    return Err(Error::InvalidState);
                }
                t.cancel = Some(id);
            }
            HostAuthMessage::Cancelled { ticket } => {
                let t = self.tickets.get(ticket).ok_or(Error::UnexpectedReply)?;
                if t.cancel != Some(id) {
                    return Err(Error::UnexpectedReply);
                }
                let context = t.context;
                self.tickets.remove(ticket);
                return Ok(Some(Retired {
                    ticket: *ticket,
                    context,
                }));
            }
            HostAuthMessage::AuthorizeAttach { context, locator } => {
                let t = self
                    .tickets
                    .values_mut()
                    .find(|t| t.context == Some(*context))
                    .ok_or(Error::UnexpectedReply)?;
                if t.cancel.is_some() || t.attach.is_some() {
                    return Err(Error::InvalidState);
                }
                t.attach = Some((id, *locator));
            }
            HostAuthMessage::AttachResult {
                context,
                locator,
                outcome,
            } => {
                let t = self
                    .tickets
                    .values_mut()
                    .find(|t| t.context == Some(*context))
                    .ok_or(Error::UnexpectedReply)?;
                if t.cancel.is_some() || t.attach != Some((id, *locator)) {
                    return Err(Error::UnexpectedReply);
                }
                if let AttachOutcome::Granted { binding, .. } = outcome {
                    if binding.frontend != self.frontend {
                        return Err(Error::Binding);
                    }
                }
                t.attach = None;
            }
        }
        Ok(None)
    }
}
#[cfg(all(test, feature = "system"))]
mod tests {
    use super::*;
    #[test]
    fn ipc529_helper_bound_is_exact_actual_3a2_envelope() {
        let record = transport::AuthRecord {
            public_key: vec![0, 127, 255],
            signature: vec![255, 1],
            v2: Some(transport::AuthV2 {
                login: "fixture\"name".into(),
                nonce: [255; 16],
            }),
        };
        let hash = [255; 32];
        let v = record.v2.as_ref().unwrap();
        let actual = crate::helper::protocol::Request::Verify {
            login: v.login.clone(),
            public_key: record.public_key.clone(),
            signature: record.signature.clone(),
            handshake_hash: hash,
            nonce: v.nonce,
            login_id: [0; 16],
            rhost: String::new(),
        };
        assert_eq!(
            serde_json::to_vec(&helper_bound(&record, hash).unwrap()).unwrap(),
            crate::helper::protocol::encode(&actual).unwrap()
        );
        assert_eq!(crate::helper::protocol::MAX_MESSAGE_LEN, 8192);
    }
}
