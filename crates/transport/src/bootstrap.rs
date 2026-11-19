//! Server release and session profiles carried by authenticated discovery.

/// A complete ordinary-session protocol profile, independent of release age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionProfile {
    pub wire: u8,
    pub handshake: u8,
    pub channel: u8,
}

/// Descriptive server metadata. Possessing this value does not prove authenticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    pub generation: [u8; 16],
    pub core_version: String,
    pub session_protocols: Vec<SessionProfile>,
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;

use crate::cookie::{CookieCheck, Verdict};
use crate::handshake::Handshake;
use crate::wire::{self, Kind};
use std::net::SocketAddr;
use std::time::Instant;
use zeroize::Zeroizing;

const PREFIX: &[u8; 5] = b"QSHB\x01";

pub const REQUEST_LEN: usize = 512;
const HEADER: usize = 8;
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const COOKIE: u8 = 3;
const COOKIE_REQUEST: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedServerInfo(ServerInfo);
impl VerifiedServerInfo {
    pub fn info(&self) -> &ServerInfo {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    Malformed,
    Authentication,
    Challenge,
    Completed,
    Retry,
    Bounds,
}
impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bootstrap {self:?}")
    }
}
impl std::error::Error for BootstrapError {}

/// Parse the public bounded metadata codec. This does not authenticate it.
pub fn decode_server_info(bytes: &[u8]) -> Result<ServerInfo, BootstrapError> {
    if bytes.len() < 18 {
        return Err(BootstrapError::Malformed);
    }
    let generation = bytes[..16]
        .try_into()
        .map_err(|_| BootstrapError::Malformed)?;
    let len = bytes[16] as usize;
    if len == 0 || len > 128 || bytes.len() < 18 + len {
        return Err(BootstrapError::Bounds);
    }
    let core_version = std::str::from_utf8(&bytes[17..17 + len])
        .map_err(|_| BootstrapError::Malformed)?
        .to_owned();
    if !core_version.is_ascii() || core_version.bytes().any(|b| b.is_ascii_control()) {
        return Err(BootstrapError::Malformed);
    }
    let count = bytes[17 + len] as usize;
    if count > 16 || bytes.len() != 18 + len + count * 3 {
        return Err(BootstrapError::Bounds);
    }
    let session_protocols = bytes[18 + len..]
        .as_chunks::<3>()
        .0
        .iter()
        .map(|p| SessionProfile {
            wire: p[0],
            handshake: p[1],
            channel: p[2],
        })
        .collect();
    Ok(ServerInfo {
        generation,
        core_version,
        session_protocols,
    })
}
pub fn encode_server_info(info: &ServerInfo) -> Result<Vec<u8>, BootstrapError> {
    if info.core_version.is_empty()
        || info.core_version.len() > 128
        || !info.core_version.is_ascii()
        || info.core_version.bytes().any(|b| b.is_ascii_control())
        || info.session_protocols.len() > 16
    {
        return Err(BootstrapError::Bounds);
    }
    let mut out = info.generation.to_vec();
    out.push(info.core_version.len() as u8);
    out.extend_from_slice(info.core_version.as_bytes());
    out.push(info.session_protocols.len() as u8);
    for p in &info.session_protocols {
        out.extend_from_slice(&[p.wire, p.handshake, p.channel]);
    }
    Ok(out)
}
pub fn is_bootstrap(bytes: &[u8]) -> bool {
    bytes.starts_with(b"QSHB")
}
fn frame(kind: u8, body: &[u8], padded: bool) -> Vec<u8> {
    let mut out = PREFIX.to_vec();
    out.push(kind);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    if padded {
        out.resize(REQUEST_LEN, 0);
    }
    out
}
fn parse(bytes: &[u8]) -> Result<(u8, &[u8]), BootstrapError> {
    if bytes.len() < HEADER || bytes.len() > REQUEST_LEN || !bytes.starts_with(PREFIX) {
        return Err(BootstrapError::Malformed);
    }
    let len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let end = HEADER.checked_add(len).ok_or(BootstrapError::Bounds)?;
    if end > bytes.len() || bytes[end..].iter().any(|b| *b != 0) {
        return Err(BootstrapError::Malformed);
    }
    if matches!(bytes[5], REPLY | COOKIE) && end != bytes.len() {
        return Err(BootstrapError::Malformed);
    }
    Ok((bytes[5], &bytes[HEADER..end]))
}

pub struct BootstrapClient {
    handshake: Option<Handshake>,
    challenge: [u8; 32],
    msg1: Vec<u8>,
    cookie: Option<[u8; 16]>,
    completed: bool,
}
impl BootstrapClient {
    pub fn new(local_private: [u8; 32], pinned_server: [u8; 32], challenge: [u8; 32]) -> Self {
        let secret = Zeroizing::new(local_private);
        let mut hs = Handshake::new_bootstrap_initiator(&secret, &pinned_server);
        let msg1 = hs.write_msg(&challenge);
        Self {
            handshake: Some(hs),
            challenge,
            msg1,
            cookie: None,
            completed: false,
        }
    }
    pub fn request(&self) -> Vec<u8> {
        match self.cookie {
            None => frame(REQUEST, &self.msg1, true),
            Some(cookie) => {
                let mut body = cookie.to_vec();
                body.extend_from_slice(&self.msg1);
                frame(COOKIE_REQUEST, &body, true)
            }
        }
    }
    pub fn accept(&mut self, bytes: &[u8]) -> Result<VerifiedServerInfo, BootstrapError> {
        if self.completed {
            return Err(BootstrapError::Completed);
        }
        let (kind, body) = parse(bytes)?;
        if kind == COOKIE {
            if body.len() != 32 || body[..16] != self.msg1[..16] {
                return Err(BootstrapError::Malformed);
            }
            self.cookie = Some(
                body[16..]
                    .try_into()
                    .map_err(|_| BootstrapError::Malformed)?,
            );
            return Err(BootstrapError::Retry);
        }
        if kind != REPLY {
            return Err(BootstrapError::Malformed);
        }
        let payload = self
            .handshake
            .as_mut()
            .ok_or(BootstrapError::Completed)?
            .read_msg(body)
            .map_err(|_| BootstrapError::Authentication)?;
        // A successful Noise response consumes this initiator, even when malformed.
        self.completed = true;
        self.handshake = None;
        if payload.len() < 32 || payload[..32] != self.challenge {
            return Err(BootstrapError::Challenge);
        }
        decode_server_info(&payload[32..]).map(VerifiedServerInfo)
    }
}

/// Bounded one-shot server authentication, with no session or admission side effects.
pub struct BootstrapResponder {
    secret: Zeroizing<[u8; 32]>,
    metadata: Vec<u8>,
    cookies: CookieCheck,
}
impl BootstrapResponder {
    pub fn new(server_private: [u8; 32], info: ServerInfo) -> Result<Self, BootstrapError> {
        let secret = Zeroizing::new(server_private);
        let metadata = encode_server_info(&info)?;
        Ok(Self {
            secret,
            metadata,
            cookies: CookieCheck::bootstrap(Instant::now()),
        })
    }
    pub fn on_datagram(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if bytes.len() != REQUEST_LEN {
            return None;
        }
        let (kind, body) = parse(bytes).ok()?;
        let kind = match kind {
            REQUEST => Kind::HandshakeInit,
            COOKIE_REQUEST => Kind::HandshakeInitCookie,
            _ => return None,
        };
        let msg1 = match self.cookies.check(now, source, kind, body, 0) {
            Verdict::Drop => return None,
            Verdict::Reply(reply) => {
                let (_, body) = match wire::parse(&reply).ok()? {
                    wire::Frame::Handshake { kind, body } => (kind, body),
                    _ => return None,
                };
                let (echo, cookie) = wire::parse_cookie_reply(body)?;
                let mut body = echo.to_vec();
                body.extend_from_slice(&cookie);
                return Some(frame(COOKIE, &body, false));
            }
            Verdict::Handshake { msg1, .. } => msg1,
        };
        let mut hs = Handshake::new_bootstrap_responder(&self.secret);
        let challenge = hs.read_msg(msg1).ok()?;
        if challenge.len() != 32 {
            return None;
        }
        let mut payload = challenge;
        payload.extend_from_slice(&self.metadata);
        let response = frame(REPLY, &hs.write_msg(&payload), false);
        (response.len() <= REQUEST_LEN).then_some(response)
    }
}
