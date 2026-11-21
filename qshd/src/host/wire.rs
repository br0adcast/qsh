//! The channel between the host and its frontend process: one message per
//! packet of a Unix sequenced-packet socket pair, with the descriptors a
//! reply hands over attached to its packet.
//!
//! Every packet is `u32 length (big-endian) | u8 kind | payload`, as on the
//! host channel of a session owner, at most [`MAX_PACKET`] bytes in all and
//! with at most [`MAX_DESCRIPTORS`] descriptors.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use nix::libc;
use transport::Principal;

use crate::owner_process::wire::{level_from, level_wire, Dec, Enc, WireError};

/// Largest packet, length prefix included.
pub(crate) const MAX_PACKET: usize = 64 * 1024;
/// Most descriptors one packet carries.
pub(crate) const MAX_DESCRIPTORS: usize = 2;
/// Most keys one `AllowKeys` carries.
pub(crate) const KEYS_PER_PACKET: usize = 1024;
/// Most known logins `Init` carries: the daemon's session ceiling.
pub(crate) const MAX_KNOWN: usize = transport::session_manager::MAX_SESSIONS_TOTAL;

/// What a frontend process starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrontendInit {
    pub(crate) server_priv: [u8; 32],
    pub(crate) server_pub: [u8; 32],
    /// The daemon's generation: every frontend of one host answers with it.
    pub(crate) generation: [u8; 16],
    /// The host's session-reset secret (`transport::session_reset`), if it
    /// has one: every frontend answers connections it does not route with
    /// tokens derived from it.
    pub(crate) reset_secret: Option<[u8; 32]>,
    /// The `authorized_keys` file of the signature gate, if there is one.
    pub(crate) authorized_keys: Option<PathBuf>,
    /// The account's name, for the log and the allowlist path's principal.
    pub(crate) account: String,
    /// The daemon is replacing itself: no handshake is admitted.
    pub(crate) admission_closed: bool,
    /// Runtime workers; 0 for the default.
    pub(crate) runtime_threads: u32,
    /// The logins that have a session now (the catalog's snapshot).
    pub(crate) known: Vec<[u8; 16]>,
}

/// What the host tells a frontend of one session's owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reply {
    /// The owner: the packet carries the frontend's end of its link and a
    /// descriptor of its process.
    Owner,
    /// No session under that login.
    Unknown,
    /// A session of another account.
    Foreign,
    /// No owner can be started: why.
    Full(String),
    /// A link that replaces the session's current one: the packet carries
    /// the frontend's end.
    Link,
    /// The session's owner is gone.
    Gone,
    /// The session's owner cannot be reached just now (its relink channel
    /// is full): nothing changed, ask again later.
    Unavailable,
}

/// Host to frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToFrontend {
    Init(Box<FrontendInit>),
    /// Keys the allowlist holds, each with its addition's sequence number,
    /// at start and as `ADD-CLIENT` adds them (again).
    AllowKeys(Vec<([u8; 32], u64)>),
    /// Keys the host scrubbed itself, each with the addition it removed: the
    /// frontend drops one it holds under that same addition.
    RevokeKeys(Vec<([u8; 32], u64)>),
    /// The start is complete (`Init`, then the allowlist): serve.
    Serve,
    /// The daemon's admission gate closed or opened.
    Admission {
        closed: bool,
    },
    /// Stop in order and exit.
    Stop,
    Reply {
        id: u64,
        reply: Reply,
    },
}

/// Frontend to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToHost {
    /// Whether `token` has a session, for a warm start by `uid`; answered
    /// `Owner` (on a link that replaces its current one), `Unknown` or
    /// `Foreign`.
    Lookup { id: u64, token: [u8; 16], uid: u32 },
    /// Start an owner for `token`'s new session; answered `Owner` or `Full`.
    Create {
        id: u64,
        token: [u8; 16],
        principal: Principal,
    },
    /// Replace the link of `token`'s session; answered `Link`, `Gone`, or
    /// `Unavailable` (its owner does not take a link just now).
    Relink { id: u64, token: [u8; 16] },
    /// `token`'s client was last heard `idle_ms` ago.
    Traffic {
        token: [u8; 16],
        idle_ms: u64,
        active: bool,
    },
    /// `token`'s client died now: the session is retained.
    Retained { token: [u8; 16] },
    /// A key the router scrubbed, under the addition the frontend had.
    ForgetKey { key: [u8; 32], seq: u64 },
    /// `token`'s session is its client's under `key`.
    ClientKey { token: [u8; 16], key: [u8; 32] },
    /// The frontend admits handshakes under every addition up to `seq`.
    KeysTaken { seq: u64 },
    /// One record for the daemon's log, which only the host writes.
    Log {
        level: log::Level,
        component: String,
        message: String,
    },
}

const F_INIT: u8 = 1;
const F_ALLOW: u8 = 2;
const F_ADMISSION: u8 = 3;
const F_STOP: u8 = 4;
const F_REPLY: u8 = 5;
const F_REVOKE: u8 = 6;
const F_SERVE: u8 = 7;

const H_LOOKUP: u8 = 1;
const H_CREATE: u8 = 2;
const H_RELINK: u8 = 3;
const H_TRAFFIC: u8 = 4;
const H_RETAINED: u8 = 5;
const H_FORGET: u8 = 6;
const H_LOG: u8 = 7;
const H_CLIENT_KEY: u8 = 8;
const H_KEYS_TAKEN: u8 = 9;

fn finish(e: Enc) -> Result<Vec<u8>, WireError> {
    let packet = e.finish()?;
    if packet.len() > MAX_PACKET {
        return Err(WireError::TooLong);
    }
    Ok(packet)
}

/// The kind and payload of `packet`, whose length prefix must match.
fn body(packet: &[u8]) -> Result<(u8, Dec<'_>), WireError> {
    let mut d = Dec(packet);
    let len = d.u32()? as usize;
    if len != d.0.len() || len == 0 {
        return Err(WireError::Truncated);
    }
    let kind = d.u8()?;
    Ok((kind, d))
}

impl ToFrontend {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let e = match self {
            ToFrontend::Init(init) => {
                use std::os::unix::ffi::OsStrExt;
                if init.known.len() > MAX_KNOWN {
                    return Err(WireError::TooLong);
                }
                let mut e = Enc::new(F_INIT);
                e.raw(&init.server_priv)
                    .raw(&init.server_pub)
                    .raw(&init.generation);
                match &init.reset_secret {
                    Some(secret) => e.u8(1).raw(secret),
                    None => e.u8(0),
                };
                match &init.authorized_keys {
                    Some(path) => e.u8(1).bytes(path.as_os_str().as_bytes()),
                    None => e.u8(0),
                };
                e.bytes(init.account.as_bytes())
                    .u8(init.admission_closed as u8)
                    .u32(init.runtime_threads)
                    .u32(init.known.len() as u32);
                for token in &init.known {
                    e.raw(token);
                }
                e
            }
            ToFrontend::AllowKeys(keys) | ToFrontend::RevokeKeys(keys) => {
                if keys.len() > KEYS_PER_PACKET {
                    return Err(WireError::TooLong);
                }
                let mut e = Enc::new(if matches!(self, ToFrontend::AllowKeys(_)) {
                    F_ALLOW
                } else {
                    F_REVOKE
                });
                e.u32(keys.len() as u32);
                for (key, seq) in keys {
                    e.raw(key).u64(*seq);
                }
                e
            }
            ToFrontend::Serve => Enc::new(F_SERVE),
            ToFrontend::Admission { closed } => {
                let mut e = Enc::new(F_ADMISSION);
                e.u8(*closed as u8);
                e
            }
            ToFrontend::Stop => Enc::new(F_STOP),
            ToFrontend::Reply { id, reply } => {
                let mut e = Enc::new(F_REPLY);
                e.u64(*id);
                match reply {
                    Reply::Owner => e.u8(1),
                    Reply::Unknown => e.u8(2),
                    Reply::Foreign => e.u8(3),
                    Reply::Full(why) => e.u8(4).bytes(why.as_bytes()),
                    Reply::Link => e.u8(5),
                    Reply::Gone => e.u8(6),
                    Reply::Unavailable => e.u8(7),
                };
                e
            }
        };
        finish(e)
    }

    pub(crate) fn decode(packet: &[u8]) -> Result<ToFrontend, WireError> {
        let (kind, mut d) = body(packet)?;
        let msg = match kind {
            F_INIT => {
                use std::os::unix::ffi::OsStringExt;
                let server_priv = d.array()?;
                let server_pub = d.array()?;
                let generation = d.array()?;
                let reset_secret = if d.bool()? { Some(d.array()?) } else { None };
                let authorized_keys = if d.bool()? {
                    Some(PathBuf::from(std::ffi::OsString::from_vec(d.bytes()?)))
                } else {
                    None
                };
                let account = d.string()?;
                let admission_closed = d.bool()?;
                let runtime_threads = d.u32()?;
                let n = d.u32()? as usize;
                if n > MAX_KNOWN {
                    return Err(WireError::TooLong);
                }
                let mut known = Vec::with_capacity(n);
                for _ in 0..n {
                    known.push(d.array()?);
                }
                ToFrontend::Init(Box::new(FrontendInit {
                    server_priv,
                    server_pub,
                    generation,
                    reset_secret,
                    authorized_keys,
                    account,
                    admission_closed,
                    runtime_threads,
                    known,
                }))
            }
            F_ALLOW | F_REVOKE => {
                let n = d.u32()? as usize;
                if n > KEYS_PER_PACKET {
                    return Err(WireError::TooLong);
                }
                let mut keys = Vec::with_capacity(n);
                for _ in 0..n {
                    keys.push((d.array()?, d.u64()?));
                }
                if kind == F_ALLOW {
                    ToFrontend::AllowKeys(keys)
                } else {
                    ToFrontend::RevokeKeys(keys)
                }
            }
            F_SERVE => ToFrontend::Serve,
            F_ADMISSION => ToFrontend::Admission { closed: d.bool()? },
            F_STOP => ToFrontend::Stop,
            F_REPLY => {
                let id = d.u64()?;
                let reply = match d.u8()? {
                    1 => Reply::Owner,
                    2 => Reply::Unknown,
                    3 => Reply::Foreign,
                    4 => Reply::Full(d.string()?),
                    5 => Reply::Link,
                    6 => Reply::Gone,
                    7 => Reply::Unavailable,
                    _ => return Err(WireError::BadValue),
                };
                ToFrontend::Reply { id, reply }
            }
            _ => return Err(WireError::BadKind),
        };
        d.end()?;
        Ok(msg)
    }
}

impl Reply {
    /// How many descriptors a packet with this reply carries.
    pub(crate) fn descriptors(&self) -> usize {
        match self {
            Reply::Owner => 2,
            Reply::Link => 1,
            _ => 0,
        }
    }
}

impl ToHost {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e;
        match self {
            ToHost::Lookup { id, token, uid } => {
                e = Enc::new(H_LOOKUP);
                e.u64(*id).raw(token).u32(*uid);
            }
            ToHost::Create {
                id,
                token,
                principal,
            } => {
                e = Enc::new(H_CREATE);
                e.u64(*id)
                    .raw(token)
                    .u32(principal.uid)
                    .bytes(principal.name.as_bytes())
                    .bytes(principal.identity.as_bytes())
                    .u64(principal.incarnation);
            }
            ToHost::Relink { id, token } => {
                e = Enc::new(H_RELINK);
                e.u64(*id).raw(token);
            }
            ToHost::Traffic {
                token,
                idle_ms,
                active,
            } => {
                e = Enc::new(H_TRAFFIC);
                e.raw(token).u64(*idle_ms).u8(*active as u8);
            }
            ToHost::Retained { token } => {
                e = Enc::new(H_RETAINED);
                e.raw(token);
            }
            ToHost::ForgetKey { key, seq } => {
                e = Enc::new(H_FORGET);
                e.raw(key).u64(*seq);
            }
            ToHost::ClientKey { token, key } => {
                e = Enc::new(H_CLIENT_KEY);
                e.raw(token).raw(key);
            }
            ToHost::KeysTaken { seq } => {
                e = Enc::new(H_KEYS_TAKEN);
                e.u64(*seq);
            }
            ToHost::Log {
                level,
                component,
                message,
            } => {
                e = Enc::new(H_LOG);
                e.u8(level_wire(*level))
                    .bytes(component.as_bytes())
                    .bytes(message.as_bytes());
            }
        }
        finish(e)
    }

    pub(crate) fn decode(packet: &[u8]) -> Result<ToHost, WireError> {
        let (kind, mut d) = body(packet)?;
        let msg = match kind {
            H_LOOKUP => ToHost::Lookup {
                id: d.u64()?,
                token: d.array()?,
                uid: d.u32()?,
            },
            H_CREATE => ToHost::Create {
                id: d.u64()?,
                token: d.array()?,
                principal: Principal {
                    uid: d.u32()?,
                    name: d.string()?,
                    identity: d.string()?,
                    incarnation: d.u64()?,
                },
            },
            H_RELINK => ToHost::Relink {
                id: d.u64()?,
                token: d.array()?,
            },
            H_TRAFFIC => ToHost::Traffic {
                token: d.array()?,
                idle_ms: d.u64()?,
                active: d.bool()?,
            },
            H_RETAINED => ToHost::Retained { token: d.array()? },
            H_FORGET => ToHost::ForgetKey {
                key: d.array()?,
                seq: d.u64()?,
            },
            H_CLIENT_KEY => ToHost::ClientKey {
                token: d.array()?,
                key: d.array()?,
            },
            H_KEYS_TAKEN => ToHost::KeysTaken { seq: d.u64()? },
            H_LOG => ToHost::Log {
                level: level_from(d.u8()?)?,
                component: d.string()?,
                message: d.string()?,
            },
            _ => return Err(WireError::BadKind),
        };
        d.end()?;
        Ok(msg)
    }
}

// ---- packets -----------------------------------------------------------------

/// Room for the control data of [`MAX_DESCRIPTORS`] descriptors (and for a
/// few more on receipt, so a packet carrying too many is seen whole and
/// refused), aligned for a control header.
type Control = [u64; 8];

/// Send `packet` with `descriptors` attached, without waiting: `WouldBlock`
/// when the peer's queue is full.
pub(crate) fn send_packet(
    channel: BorrowedFd<'_>,
    packet: &[u8],
    descriptors: &[BorrowedFd<'_>],
) -> io::Result<()> {
    assert!(descriptors.len() <= MAX_DESCRIPTORS && packet.len() <= MAX_PACKET);
    let mut vector = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };
    let mut control: Control = [0; 8];
    // SAFETY: an all-zero `msghdr` has no address and no control data.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        let bytes = std::mem::size_of_val(descriptors) as libc::c_uint;
        // SAFETY: a small, fixed argument.
        let space = unsafe { libc::CMSG_SPACE(bytes) } as usize;
        assert!(space <= size_of_val(&control));
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space as _;
        // SAFETY: `control` is zeroed, aligned and `space` bytes long, so
        // the first header and its descriptors lie inside it.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(bytes) as _;
            let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
            for (i, descriptor) in descriptors.iter().enumerate() {
                std::ptr::write_unaligned(data.add(i), descriptor.as_raw_fd());
            }
        }
    }
    // SAFETY: every pointer in `message` refers to a live local.
    let sent = unsafe {
        libc::sendmsg(
            channel.as_raw_fd(),
            &message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One packet off `channel`, without waiting, with the descriptors it
/// carried: `None` at the end of input, `WouldBlock` when nothing waits. A
/// packet that was cut, or that carried more than [`MAX_DESCRIPTORS`], is an
/// error (whatever it carried is closed).
pub(crate) fn receive_packet(
    channel: BorrowedFd<'_>,
    wait: bool,
) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let mut packet = vec![0u8; MAX_PACKET];
    let mut vector = libc::iovec {
        iov_base: packet.as_mut_ptr().cast(),
        iov_len: packet.len(),
    };
    let mut control: Control = [0; 8];
    // SAFETY: an all-zero `msghdr` has no address and no control data.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control) as _;
    let flags = libc::MSG_CMSG_CLOEXEC | if wait { 0 } else { libc::MSG_DONTWAIT };
    // SAFETY: every pointer in `message` refers to a live local of the
    // length given with it.
    let got = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, flags) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut descriptors = Vec::new();
    // SAFETY: the kernel filled `msg_controllen` bytes of `control`; the
    // header macros walk only inside them, and every integer of an
    // `SCM_RIGHTS` record is a descriptor this process now owns, adopted
    // here exactly once.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for i in 0..bytes / size_of::<libc::c_int>() {
                    descriptors.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if got == 0 {
        return Ok(None);
    }
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() > MAX_DESCRIPTORS
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a packet that was cut or carries too many descriptors",
        ));
    }
    packet.truncate(got as usize);
    Ok(Some((packet, descriptors)))
}

/// One end of the channel inside a runtime.
pub(crate) struct Channel(tokio::io::unix::AsyncFd<OwnedFd>);

impl Channel {
    pub(crate) fn new(end: OwnedFd) -> io::Result<Channel> {
        // SAFETY: the socket is owned by the `AsyncFd` and stays open for
        // as long as it is registered.
        Ok(Channel(unsafe { tokio::io::unix::AsyncFd::register(end)? }))
    }

    /// Send one packet, waiting while the peer's queue is full.
    pub(crate) async fn send(
        &self,
        packet: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> io::Result<()> {
        use std::os::fd::AsFd;
        loop {
            let mut ready = self.0.writable().await?;
            match send_packet(self.0.get_ref().as_fd(), packet, descriptors) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => ready.clear_ready(),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                done => return done,
            }
        }
    }

    /// The next packet; `None` when the peer closed its end.
    pub(crate) async fn receive(&self) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
        use std::os::fd::AsFd;
        loop {
            let mut ready = self.0.readable().await?;
            match receive_packet(self.0.get_ref().as_fd(), false) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => ready.clear_ready(),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                done => return done,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> FrontendInit {
        FrontendInit {
            server_priv: [1; 32],
            server_pub: [2; 32],
            generation: [3; 16],
            reset_secret: Some([6; 32]),
            authorized_keys: Some(PathBuf::from("/home/me/.ssh/authorized_keys")),
            account: "me".into(),
            admission_closed: true,
            runtime_threads: 2,
            known: vec![[4; 16], [5; 16]],
        }
    }

    #[test]
    fn frontend_channel_messages_round_trip() {
        let to_frontend = [
            ToFrontend::Init(Box::new(init())),
            ToFrontend::Init(Box::new(FrontendInit {
                authorized_keys: None,
                reset_secret: None,
                admission_closed: false,
                known: Vec::new(),
                ..init()
            })),
            ToFrontend::AllowKeys(vec![([7; 32], 1), ([8; 32], u64::MAX)]),
            ToFrontend::AllowKeys(Vec::new()),
            ToFrontend::RevokeKeys(vec![([9; 32], 3)]),
            ToFrontend::Serve,
            ToFrontend::Admission { closed: true },
            ToFrontend::Stop,
            ToFrontend::Reply {
                id: 9,
                reply: Reply::Owner,
            },
            ToFrontend::Reply {
                id: 10,
                reply: Reply::Full("every session envelope is taken".into()),
            },
            ToFrontend::Reply {
                id: 11,
                reply: Reply::Link,
            },
            ToFrontend::Reply {
                id: 12,
                reply: Reply::Gone,
            },
            ToFrontend::Reply {
                id: 15,
                reply: Reply::Unavailable,
            },
            ToFrontend::Reply {
                id: 13,
                reply: Reply::Unknown,
            },
            ToFrontend::Reply {
                id: 14,
                reply: Reply::Foreign,
            },
        ];
        for msg in to_frontend {
            assert_eq!(ToFrontend::decode(&msg.encode().unwrap()), Ok(msg));
        }
        let to_host = [
            ToHost::Lookup {
                id: 1,
                token: [6; 16],
                uid: 1000,
            },
            ToHost::Create {
                id: 2,
                token: [6; 16],
                principal: Principal {
                    uid: 1000,
                    name: "me".into(),
                    identity: "SHA256:x".into(),
                    incarnation: 3,
                },
            },
            ToHost::Relink {
                id: 3,
                token: [6; 16],
            },
            ToHost::Traffic {
                token: [6; 16],
                idle_ms: 1500,
                active: true,
            },
            ToHost::Retained { token: [6; 16] },
            ToHost::ForgetKey {
                key: [9; 32],
                seq: 4,
            },
            ToHost::ClientKey {
                token: [3; 16],
                key: [9; 32],
            },
            ToHost::KeysTaken { seq: 5 },
            ToHost::Log {
                level: log::Level::Warn,
                component: "transport".into(),
                message: "a record".into(),
            },
        ];
        for msg in to_host {
            assert_eq!(ToHost::decode(&msg.encode().unwrap()), Ok(msg));
        }
    }

    #[test]
    fn frontend_channel_refuses_malformed_packets() {
        let good = ToHost::Relink {
            id: 3,
            token: [6; 16],
        }
        .encode()
        .unwrap();
        assert!(ToHost::decode(&good[..good.len() - 1]).is_err(), "cut");
        let mut long = good.clone();
        long.push(0);
        assert!(ToHost::decode(&long).is_err(), "length mismatch");
        let mut kind = good.clone();
        kind[4] = 0xee;
        assert_eq!(ToHost::decode(&kind), Err(WireError::BadKind));
        assert!(ToFrontend::decode(&[]).is_err());
        let too_many = ToFrontend::AllowKeys(vec![([0; 32], 0); KEYS_PER_PACKET + 1]);
        assert_eq!(too_many.encode(), Err(WireError::TooLong));
    }

    /// A packet crosses whole, with exactly the descriptors it was sent
    /// with, and the end of input is seen as such.
    #[test]
    fn a_packet_carries_its_descriptors() {
        use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
        use std::os::fd::AsFd;
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let (x, y) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        send_packet(a.as_fd(), b"one", &[x.as_fd(), y.as_fd()]).unwrap();
        send_packet(a.as_fd(), b"two", &[]).unwrap();
        let (packet, descriptors) = receive_packet(b.as_fd(), false).unwrap().unwrap();
        assert_eq!((packet.as_slice(), descriptors.len()), (&b"one"[..], 2));
        let (packet, descriptors) = receive_packet(b.as_fd(), false).unwrap().unwrap();
        assert_eq!((packet.as_slice(), descriptors.len()), (&b"two"[..], 0));
        assert_eq!(
            receive_packet(b.as_fd(), false).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(a);
        assert!(receive_packet(b.as_fd(), false).unwrap().is_none());
    }
}
