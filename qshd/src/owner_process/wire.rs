//! The host channel between a daemon and one session owner process: a
//! small length-prefixed codec, separate from the frontend/owner link.
//!
//! Every frame is `u32 length (big-endian) | u8 kind | payload`, the length
//! counting the kind and the payload, at most [`MAX_FRAME`]. Strings and
//! byte strings carry a `u32` length, bounded by the frame.

use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncReadExt};
use transport::channel::{About, DaemonMode, RejectCode, UpdateAnswer, UpdateOffer, UpdateResult};
use transport::channel_server::{RestartPhase, RestartSignal};
use transport::Principal;

/// Largest frame body (kind and payload).
pub(crate) const MAX_FRAME: usize = 128 * 1024;
/// Largest image piece one `Write` carries.
pub(crate) const WRITE_CHUNK: usize = 64 * 1024;

/// What a session owner starts from: the frontend/owner link's `OwnerInit`
/// plus what the host decides for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostInit {
    pub(crate) principal: Principal,
    pub(crate) login: [u8; 16],
    pub(crate) last_generation: u64,
    /// The daemon answers `About` and update offers for this owner's session.
    pub(crate) updates: bool,
    /// Where the daemon's log is; the owner appends to the same file.
    pub(crate) log_dir: Option<PathBuf>,
}

/// Host to owner.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToOwner {
    Init(HostInit),
    /// End the session: stop, drain, report `Drained`, exit.
    Stop,
    Signal(RestartSignal),
    About {
        id: u64,
        about: Option<About>,
    },
    Offered {
        id: u64,
        result: Result<u64, UpdateAnswer>,
    },
    Written {
        id: u64,
        result: Result<(), String>,
    },
    Verified {
        id: u64,
        result: Result<(), UpdateResult>,
    },
    /// The replacement did not happen: why.
    Restarted {
        id: u64,
        result: UpdateResult,
    },
}

/// Owner to host.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToHost {
    About {
        id: u64,
    },
    Offer {
        id: u64,
        offer: UpdateOffer,
    },
    Write {
        id: u64,
        transfer: u64,
        bytes: Vec<u8>,
    },
    Verify {
        id: u64,
        transfer: u64,
    },
    Restart {
        id: u64,
        transfer: u64,
    },
    Abandon {
        transfer: u64,
    },
    Joined {
        restart: u64,
    },
    Released {
        restart: u64,
    },
    /// The session ended on its own (its backend finished).
    End,
    /// The owner's receipt: every task and worker of its session joined
    /// (`Ok`) or one failed (`Err`, a detail for the log). Its last frame.
    Drained(Result<(), String>),
    /// One record for the daemon's log, which only the host writes (and
    /// rotates), under the owner's pid.
    Log {
        level: log::Level,
        component: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    TooLong,
    Truncated,
    BadKind,
    BadValue,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "host channel frame: {self:?}")
    }
}

impl std::error::Error for WireError {}

// ---- primitives --------------------------------------------------------------

struct Enc(Vec<u8>);
impl Enc {
    fn new(kind: u8) -> Enc {
        // Length placeholder, then the kind.
        Enc(vec![0, 0, 0, 0, kind])
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32).raw(v)
    }
    fn finish(mut self) -> Result<Vec<u8>, WireError> {
        let body = self.0.len() - 4;
        if body > MAX_FRAME {
            return Err(WireError::TooLong);
        }
        self.0[..4].copy_from_slice(&(body as u32).to_be_bytes());
        Ok(self.0)
    }
}

struct Dec<'a>(&'a [u8]);
impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Truncated);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, WireError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Result<String, WireError> {
        String::from_utf8(self.bytes()?).map_err(|_| WireError::BadValue)
    }
    fn bool(&mut self) -> Result<bool, WireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::BadValue),
        }
    }
    fn end(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::BadValue)
        }
    }
}

fn reject_code_wire(code: RejectCode) -> u8 {
    match code {
        RejectCode::Other => 0,
        RejectCode::SizeMismatch => 1,
        RejectCode::ChecksumMismatch => 2,
        RejectCode::SelfCheckFailed => 3,
        RejectCode::VersionNotAccepted => 4,
        RejectCode::DiskError => 5,
        RejectCode::ExecFailed => 6,
        RejectCode::TransferStalled => 7,
        RejectCode::ControlBusy => 8,
        RejectCode::Unknown(code) => code,
    }
}

fn reject_code_from(code: u8) -> RejectCode {
    match code {
        0 => RejectCode::Other,
        1 => RejectCode::SizeMismatch,
        2 => RejectCode::ChecksumMismatch,
        3 => RejectCode::SelfCheckFailed,
        4 => RejectCode::VersionNotAccepted,
        5 => RejectCode::DiskError,
        6 => RejectCode::ExecFailed,
        7 => RejectCode::TransferStalled,
        8 => RejectCode::ControlBusy,
        other => RejectCode::Unknown(other),
    }
}

fn put_result(e: &mut Enc, result: &UpdateResult) {
    match result {
        UpdateResult::Restarting => {
            e.u8(0);
        }
        UpdateResult::Rejected { code, detail } => {
            e.u8(1).u8(reject_code_wire(*code)).bytes(detail.as_bytes());
        }
        UpdateResult::Busy { others } => {
            e.u8(2).u32(*others);
        }
        UpdateResult::Unknown(code) => {
            e.u8(3).u8(*code);
        }
    }
}

fn get_result(d: &mut Dec<'_>) -> Result<UpdateResult, WireError> {
    Ok(match d.u8()? {
        0 => UpdateResult::Restarting,
        1 => UpdateResult::Rejected {
            code: reject_code_from(d.u8()?),
            detail: d.string()?,
        },
        2 => UpdateResult::Busy { others: d.u32()? },
        3 => UpdateResult::Unknown(d.u8()?),
        _ => return Err(WireError::BadValue),
    })
}

fn put_answer(e: &mut Enc, answer: &UpdateAnswer) {
    let (tag, others) = match answer {
        UpdateAnswer::Accept => (0, 0),
        UpdateAnswer::UpToDate => (1, 0),
        UpdateAnswer::DaemonNewer => (2, 0),
        UpdateAnswer::Busy { others } => (3, *others),
        UpdateAnswer::Managed => (4, 0),
        UpdateAnswer::ArchMismatch => (5, 0),
        UpdateAnswer::TooLarge => (6, 0),
        UpdateAnswer::NotAllowed => (7, 0),
        UpdateAnswer::InProgress => (8, 0),
        UpdateAnswer::ResourceExhausted => (9, 0),
        UpdateAnswer::ProviderFailed => (10, 0),
        UpdateAnswer::Unknown(code) => (11, *code as u32),
    };
    e.u8(tag).u32(others);
}

fn get_answer(d: &mut Dec<'_>) -> Result<UpdateAnswer, WireError> {
    let tag = d.u8()?;
    let others = d.u32()?;
    Ok(match tag {
        0 => UpdateAnswer::Accept,
        1 => UpdateAnswer::UpToDate,
        2 => UpdateAnswer::DaemonNewer,
        3 => UpdateAnswer::Busy { others },
        4 => UpdateAnswer::Managed,
        5 => UpdateAnswer::ArchMismatch,
        6 => UpdateAnswer::TooLarge,
        7 => UpdateAnswer::NotAllowed,
        8 => UpdateAnswer::InProgress,
        9 => UpdateAnswer::ResourceExhausted,
        10 => UpdateAnswer::ProviderFailed,
        11 => UpdateAnswer::Unknown(u8::try_from(others).map_err(|_| WireError::BadValue)?),
        _ => return Err(WireError::BadValue),
    })
}

fn phase_wire(phase: RestartPhase) -> u8 {
    match phase {
        RestartPhase::Idle => 0,
        RestartPhase::Announced => 1,
        RestartPhase::Draining => 2,
    }
}

fn phase_from(phase: u8) -> Result<RestartPhase, WireError> {
    Ok(match phase {
        0 => RestartPhase::Idle,
        1 => RestartPhase::Announced,
        2 => RestartPhase::Draining,
        _ => return Err(WireError::BadValue),
    })
}

// ---- messages ----------------------------------------------------------------

const O_INIT: u8 = 1;
const O_STOP: u8 = 2;
const O_SIGNAL: u8 = 3;
const O_ABOUT: u8 = 4;
const O_OFFERED: u8 = 5;
const O_WRITTEN: u8 = 6;
const O_VERIFIED: u8 = 7;
const O_RESTARTED: u8 = 8;

const H_ABOUT: u8 = 1;
const H_OFFER: u8 = 2;
const H_WRITE: u8 = 3;
const H_VERIFY: u8 = 4;
const H_RESTART: u8 = 5;
const H_ABANDON: u8 = 6;
const H_JOINED: u8 = 7;
const H_RELEASED: u8 = 8;
const H_END: u8 = 9;
const H_DRAINED: u8 = 10;
const H_LOG: u8 = 11;

fn level_wire(level: log::Level) -> u8 {
    match level {
        log::Level::Error => 1,
        log::Level::Warn => 2,
        log::Level::Info => 3,
        log::Level::Debug => 4,
        log::Level::Trace => 5,
    }
}

fn level_from(level: u8) -> Result<log::Level, WireError> {
    Ok(match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        3 => log::Level::Info,
        4 => log::Level::Debug,
        5 => log::Level::Trace,
        _ => return Err(WireError::BadValue),
    })
}

impl ToOwner {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, WireError> {
        use std::os::unix::ffi::OsStrExt;
        let mut e;
        match self {
            ToOwner::Init(init) => {
                e = Enc::new(O_INIT);
                e.u32(init.principal.uid)
                    .bytes(init.principal.name.as_bytes())
                    .bytes(init.principal.identity.as_bytes())
                    .u64(init.principal.incarnation)
                    .raw(&init.login)
                    .u64(init.last_generation)
                    .u8(init.updates as u8);
                match &init.log_dir {
                    Some(dir) => e.u8(1).bytes(dir.as_os_str().as_bytes()),
                    None => e.u8(0),
                };
            }
            ToOwner::Stop => e = Enc::new(O_STOP),
            ToOwner::Signal(signal) => {
                e = Enc::new(O_SIGNAL);
                e.u64(signal.restart)
                    .u64(signal.invalidation_epoch)
                    .u8(phase_wire(signal.phase));
            }
            ToOwner::About { id, about } => {
                e = Enc::new(O_ABOUT);
                e.u64(*id);
                match about {
                    None => {
                        e.u8(0);
                    }
                    Some(about) => {
                        e.u8(1)
                            .u64(about.build)
                            .raw(&about.checksum)
                            .bytes(about.arch.as_bytes())
                            .u8(about.protocol)
                            .u8(match about.mode {
                                DaemonMode::Personal => 0,
                                DaemonMode::Managed => 1,
                            });
                    }
                }
            }
            ToOwner::Offered { id, result } => {
                e = Enc::new(O_OFFERED);
                e.u64(*id);
                match result {
                    Ok(transfer) => {
                        e.u8(1).u64(*transfer);
                    }
                    Err(answer) => {
                        e.u8(0);
                        put_answer(&mut e, answer);
                    }
                }
            }
            ToOwner::Written { id, result } => {
                e = Enc::new(O_WRITTEN);
                e.u64(*id);
                match result {
                    Ok(()) => e.u8(1),
                    Err(detail) => e.u8(0).bytes(detail.as_bytes()),
                };
            }
            ToOwner::Verified { id, result } => {
                e = Enc::new(O_VERIFIED);
                e.u64(*id);
                match result {
                    Ok(()) => {
                        e.u8(1);
                    }
                    Err(result) => {
                        e.u8(0);
                        put_result(&mut e, result);
                    }
                }
            }
            ToOwner::Restarted { id, result } => {
                e = Enc::new(O_RESTARTED);
                e.u64(*id);
                put_result(&mut e, result);
            }
        }
        e.finish()
    }

    pub(crate) fn decode(body: &[u8]) -> Result<ToOwner, WireError> {
        use std::os::unix::ffi::OsStringExt;
        let (&kind, rest) = body.split_first().ok_or(WireError::Truncated)?;
        let mut d = Dec(rest);
        let msg = match kind {
            O_INIT => ToOwner::Init(HostInit {
                principal: Principal {
                    uid: d.u32()?,
                    name: d.string()?,
                    identity: d.string()?,
                    incarnation: d.u64()?,
                },
                login: d.array()?,
                last_generation: d.u64()?,
                updates: d.bool()?,
                log_dir: if d.bool()? {
                    Some(PathBuf::from(std::ffi::OsString::from_vec(d.bytes()?)))
                } else {
                    None
                },
            }),
            O_STOP => ToOwner::Stop,
            O_SIGNAL => ToOwner::Signal(RestartSignal {
                restart: d.u64()?,
                invalidation_epoch: d.u64()?,
                phase: phase_from(d.u8()?)?,
            }),
            O_ABOUT => ToOwner::About {
                id: d.u64()?,
                about: if d.bool()? {
                    Some(About {
                        build: d.u64()?,
                        checksum: d.array()?,
                        arch: d.string()?,
                        protocol: d.u8()?,
                        mode: match d.u8()? {
                            0 => DaemonMode::Personal,
                            1 => DaemonMode::Managed,
                            _ => return Err(WireError::BadValue),
                        },
                    })
                } else {
                    None
                },
            },
            O_OFFERED => ToOwner::Offered {
                id: d.u64()?,
                result: if d.bool()? {
                    Ok(d.u64()?)
                } else {
                    Err(get_answer(&mut d)?)
                },
            },
            O_WRITTEN => ToOwner::Written {
                id: d.u64()?,
                result: if d.bool()? { Ok(()) } else { Err(d.string()?) },
            },
            O_VERIFIED => ToOwner::Verified {
                id: d.u64()?,
                result: if d.bool()? {
                    Ok(())
                } else {
                    Err(get_result(&mut d)?)
                },
            },
            O_RESTARTED => ToOwner::Restarted {
                id: d.u64()?,
                result: get_result(&mut d)?,
            },
            _ => return Err(WireError::BadKind),
        };
        d.end()?;
        Ok(msg)
    }
}

impl ToHost {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut e;
        match self {
            ToHost::About { id } => {
                e = Enc::new(H_ABOUT);
                e.u64(*id);
            }
            ToHost::Offer { id, offer } => {
                e = Enc::new(H_OFFER);
                e.u64(*id)
                    .u64(offer.build)
                    .raw(&offer.checksum)
                    .bytes(offer.arch.as_bytes())
                    .u64(offer.size);
            }
            ToHost::Write {
                id,
                transfer,
                bytes,
            } => {
                if bytes.len() > WRITE_CHUNK {
                    return Err(WireError::TooLong);
                }
                e = Enc::new(H_WRITE);
                e.u64(*id).u64(*transfer).bytes(bytes);
            }
            ToHost::Verify { id, transfer } => {
                e = Enc::new(H_VERIFY);
                e.u64(*id).u64(*transfer);
            }
            ToHost::Restart { id, transfer } => {
                e = Enc::new(H_RESTART);
                e.u64(*id).u64(*transfer);
            }
            ToHost::Abandon { transfer } => {
                e = Enc::new(H_ABANDON);
                e.u64(*transfer);
            }
            ToHost::Joined { restart } => {
                e = Enc::new(H_JOINED);
                e.u64(*restart);
            }
            ToHost::Released { restart } => {
                e = Enc::new(H_RELEASED);
                e.u64(*restart);
            }
            ToHost::End => e = Enc::new(H_END),
            ToHost::Drained(result) => {
                e = Enc::new(H_DRAINED);
                match result {
                    Ok(()) => e.u8(1),
                    Err(detail) => e.u8(0).bytes(detail.as_bytes()),
                };
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
        e.finish()
    }

    pub(crate) fn decode(body: &[u8]) -> Result<ToHost, WireError> {
        let (&kind, rest) = body.split_first().ok_or(WireError::Truncated)?;
        let mut d = Dec(rest);
        let msg = match kind {
            H_ABOUT => ToHost::About { id: d.u64()? },
            H_OFFER => ToHost::Offer {
                id: d.u64()?,
                offer: UpdateOffer {
                    build: d.u64()?,
                    checksum: d.array()?,
                    arch: d.string()?,
                    size: d.u64()?,
                },
            },
            H_WRITE => {
                let id = d.u64()?;
                let transfer = d.u64()?;
                let bytes = d.bytes()?;
                if bytes.len() > WRITE_CHUNK {
                    return Err(WireError::TooLong);
                }
                ToHost::Write {
                    id,
                    transfer,
                    bytes,
                }
            }
            H_VERIFY => ToHost::Verify {
                id: d.u64()?,
                transfer: d.u64()?,
            },
            H_RESTART => ToHost::Restart {
                id: d.u64()?,
                transfer: d.u64()?,
            },
            H_ABANDON => ToHost::Abandon { transfer: d.u64()? },
            H_JOINED => ToHost::Joined { restart: d.u64()? },
            H_RELEASED => ToHost::Released { restart: d.u64()? },
            H_END => ToHost::End,
            H_LOG => ToHost::Log {
                level: level_from(d.u8()?)?,
                component: d.string()?,
                message: d.string()?,
            },
            H_DRAINED => ToHost::Drained(if d.bool()? { Ok(()) } else { Err(d.string()?) }),
            _ => return Err(WireError::BadKind),
        };
        d.end()?;
        Ok(msg)
    }
}

/// The next frame body off `read`; `None` at a clean end of input between
/// frames. Never allocates past [`MAX_FRAME`].
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    read: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = read.read(&mut len[got..]).await?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        got += n;
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            WireError::TooLong,
        ));
    }
    let mut body = vec![0; len];
    read.read_exact(&mut body).await?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> Principal {
        Principal {
            uid: 1000,
            name: "me".into(),
            identity: "SHA256:x".into(),
            incarnation: 7,
        }
    }

    fn owner_round_trip(msg: ToOwner) {
        let bytes = msg.encode().unwrap();
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize,
            bytes.len() - 4
        );
        assert_eq!(ToOwner::decode(&bytes[4..]).unwrap(), msg);
    }

    fn host_round_trip(msg: ToHost) {
        let bytes = msg.encode().unwrap();
        assert_eq!(ToHost::decode(&bytes[4..]).unwrap(), msg);
    }

    #[test]
    fn host_channel_messages_round_trip() {
        owner_round_trip(ToOwner::Init(HostInit {
            principal: principal(),
            login: [3; 16],
            last_generation: 9,
            updates: true,
            log_dir: Some("/tmp/x y".into()),
        }));
        owner_round_trip(ToOwner::Init(HostInit {
            principal: principal(),
            login: [0; 16],
            last_generation: 0,
            updates: false,
            log_dir: None,
        }));
        owner_round_trip(ToOwner::Stop);
        owner_round_trip(ToOwner::Signal(RestartSignal::draining(4, 3)));
        owner_round_trip(ToOwner::About {
            id: 1,
            about: Some(About {
                build: 5,
                checksum: [8; 32],
                arch: "x86_64".into(),
                protocol: 2,
                mode: DaemonMode::Managed,
            }),
        });
        owner_round_trip(ToOwner::About { id: 2, about: None });
        owner_round_trip(ToOwner::Offered {
            id: 3,
            result: Ok(11),
        });
        for answer in [
            UpdateAnswer::Busy { others: 4 },
            UpdateAnswer::InProgress,
            UpdateAnswer::Unknown(200),
        ] {
            owner_round_trip(ToOwner::Offered {
                id: 3,
                result: Err(answer),
            });
        }
        owner_round_trip(ToOwner::Written {
            id: 4,
            result: Err("disk".into()),
        });
        owner_round_trip(ToOwner::Verified {
            id: 5,
            result: Err(UpdateResult::Rejected {
                code: RejectCode::SelfCheckFailed,
                detail: "no".into(),
            }),
        });
        owner_round_trip(ToOwner::Restarted {
            id: 6,
            result: UpdateResult::Busy { others: 2 },
        });
        host_round_trip(ToHost::Offer {
            id: 1,
            offer: UpdateOffer {
                build: 2,
                checksum: [1; 32],
                arch: "aarch64".into(),
                size: 99,
            },
        });
        host_round_trip(ToHost::Write {
            id: 2,
            transfer: 3,
            bytes: vec![7; WRITE_CHUNK],
        });
        host_round_trip(ToHost::Drained(Err("worker".into())));
        host_round_trip(ToHost::Drained(Ok(())));
        host_round_trip(ToHost::End);
        host_round_trip(ToHost::Joined { restart: 5 });
        host_round_trip(ToHost::Log {
            level: log::Level::Warn,
            component: "transport".into(),
            message: "parking\nsecond line".into(),
        });
    }

    #[test]
    fn host_channel_refuses_malformed_frames() {
        assert_eq!(ToHost::decode(&[]), Err(WireError::Truncated));
        assert_eq!(ToHost::decode(&[99]), Err(WireError::BadKind));
        assert_eq!(ToHost::decode(&[H_JOINED, 0, 0]), Err(WireError::Truncated));
        let mut trailing = ToHost::End.encode().unwrap();
        trailing.push(0);
        assert_eq!(ToHost::decode(&trailing[4..]), Err(WireError::BadValue));
        assert_eq!(
            ToHost::Write {
                id: 0,
                transfer: 0,
                bytes: vec![0; WRITE_CHUNK + 1],
            }
            .encode(),
            Err(WireError::TooLong)
        );
        // A string length past the frame is truncation, never an allocation.
        assert_eq!(
            ToHost::decode(&[H_DRAINED, 0, 0xff, 0xff, 0xff, 0xff]),
            Err(WireError::Truncated)
        );
    }

    #[tokio::test]
    async fn frames_are_read_whole_and_bounded() {
        let one = ToHost::Released { restart: 1 }.encode().unwrap();
        let two = ToHost::End.encode().unwrap();
        let mut input: &[u8] = &[one.clone(), two.clone()].concat();
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), one[4..]);
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), two[4..]);
        assert!(read_frame(&mut input).await.unwrap().is_none());
        let huge = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert!(read_frame(&mut &huge[..]).await.is_err());
        let cut = &one[..one.len() - 1];
        assert!(read_frame(&mut &cut[..]).await.is_err());
    }
}
