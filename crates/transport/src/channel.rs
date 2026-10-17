//! The session control stream: what a client asks of a session and what the
//! session answers. This is the whole tmux-shaped knowledge the transport
//! used to carry, replaced by something that knows only about channels --
//! the same trade sshd makes.
//!
//! Records share the envelope of `crate::shell_frame` (`type | len |
//! payload`), so an unknown record kind is skipped by its length and cannot
//! desynchronise the stream.

use crate::shell_frame::{encode_record, RawRecord};
// Only the tests exercise the deframer directly (production code decodes
// records handed to it by the connection layer); keep the import out of a
// non-test build so it doesn't sit there unused.
#[cfg(test)]
use crate::shell_frame::RecordDeframer;

/// The stream carrying session control records.
///
/// Deliberately NOT 0. `crates/transport/src/conn.rs`'s `is_bulk_output_stream`
/// treats stream 0 as bulk, replaceable-by-a-repaint output (`OUTPUT_STREAM`,
/// the old single-product protocol's shell I/O) and drops its send backlog
/// after a long absence instead of holding it. Every record here is the
/// opposite: one-shot and order-critical (`OPENED`/`REFUSED`/`EXIT` each
/// happen exactly once; a repaint cannot regenerate a lost one). Numbering
/// this stream 0 too -- which this constant did until this fix -- meant the
/// channel protocol inherited that drop-after-a-long-absence behavior by
/// coincidence, not by design: two protocols each starting their own
/// numbering from zero. See `conn.rs`'s own docs for the fuller account.
pub const CONTROL_STREAM: u8 = 1;

/// The lowest stream number a channel may take. Below it sit the control
/// stream, [`UPDATE_STREAM`] (14) and `crate::auth::AUTH_STREAM` (15).
pub const FIRST_CHANNEL_STREAM: u8 = 16;

/// How many channels one session may hold open at once. Two is what the app
/// needs (a shell and a tmux control client); the cap is a resource bound,
/// not a design limit.
pub const MAX_CHANNELS: usize = 8;

/// Longest command line a client may ask for.
pub const MAX_COMMAND_LEN: usize = 4096;

const REC_OPEN: u8 = 0x10;
const REC_RESIZE: u8 = 0x11;
const REC_CLOSE: u8 = 0x12;
const REC_TERM: u8 = 0x13;
const REC_OPENED: u8 = 0x20;
const REC_REFUSED: u8 = 0x21;
const REC_EXIT: u8 = 0x22;
const REC_CHANNELS: u8 = 0x23;

const REC_ABOUT_REQUEST: u8 = 0x14;
const REC_UPDATE_OFFER: u8 = 0x15;
const REC_ABOUT: u8 = 0x24;
const REC_UPDATE_ANSWER: u8 = 0x25;
const REC_UPDATE_RESULT: u8 = 0x26;
const REC_RESTARTING: u8 = 0x27;

const ANSWER_ACCEPT: u8 = 0;
const ANSWER_UP_TO_DATE: u8 = 1;
const ANSWER_DAEMON_NEWER: u8 = 2;
const ANSWER_BUSY: u8 = 3;
const ANSWER_MANAGED: u8 = 4;
const ANSWER_ARCH_MISMATCH: u8 = 5;
const ANSWER_TOO_LARGE: u8 = 6;
const ANSWER_NOT_ALLOWED: u8 = 7;
const ANSWER_IN_PROGRESS: u8 = 8;

const RESULT_RESTARTING: u8 = 0;
const RESULT_REJECTED: u8 = 1;
const RESULT_BUSY: u8 = 2;

/// The stream an accepted daemon image travels on, raw and unframed: the
/// offer already said how many bytes to expect, and the transport has no
/// per-stream close to mark the end with. Reserved below
/// [`FIRST_CHANNEL_STREAM`], next to `crate::auth::AUTH_STREAM`, so no
/// channel can ever be opened on it.
pub const UPDATE_STREAM: u8 = 14;

/// Version of this control-stream vocabulary. A daemon states it in
/// [`About`] and `qshd self-check` prints it; a staged binary that reports a
/// different one is refused before it can replace a running daemon.
pub const PROTOCOL_VERSION: u8 = 1;

/// Longest architecture name [`About`] and [`UpdateOffer`] carry. Real ones
/// (`x86_64`, `aarch64`) are a fraction of it.
pub const MAX_ARCH_LEN: usize = 32;

/// Who replaces a daemon's binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonMode {
    /// Installed and kept up to date by a client (`transport-ensure`): it
    /// takes new binaries over qsh.
    Personal,
    /// Started by a service manager or a package (`serve`, `serve --system`):
    /// it never replaces itself.
    Managed,
}

impl DaemonMode {
    fn to_wire(self) -> u8 {
        match self {
            DaemonMode::Personal => 0,
            DaemonMode::Managed => 1,
        }
    }

    /// Anything but `0` is `Managed`: a mode this build does not know is one
    /// it must not try to update.
    fn from_wire(byte: u8) -> DaemonMode {
        if byte == 0 {
            DaemonMode::Personal
        } else {
            DaemonMode::Managed
        }
    }
}

/// What a daemon says about itself in answer to [`ClientRecord::AboutRequest`].
/// Tail-extensible: a field appended later is read by this build as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct About {
    /// Build stamp: ordered, larger is newer.
    pub build: u64,
    /// sha256 of the daemon's own binary.
    pub checksum: [u8; 32],
    /// Target architecture, as `std::env::consts::ARCH` names it.
    pub arch: String,
    /// [`PROTOCOL_VERSION`] of the daemon.
    pub protocol: u8,
    pub mode: DaemonMode,
}

/// A binary the client is ready to hand over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOffer {
    pub build: u64,
    pub checksum: [u8; 32],
    pub arch: String,
    /// Exactly how many bytes will follow on [`UPDATE_STREAM`].
    pub size: u64,
}

/// The daemon's answer to an [`UpdateOffer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateAnswer {
    /// Send it.
    Accept,
    /// The checksums match.
    UpToDate,
    /// The daemon's build is newer than the offer's: no downgrades.
    DaemonNewer,
    /// Other sessions are active; replacing the daemon would cut them off.
    Busy {
        others: u32,
    },
    /// A service manager or a package owns this daemon's binary.
    Managed,
    ArchMismatch,
    TooLarge,
    /// This session may not update this daemon.
    NotAllowed,
    /// Another update is already under way.
    InProgress,
    /// A code this build does not know -- from a newer daemon.
    Unknown(u8),
}

/// How a transfer ended, from the daemon's side.
/// Why a daemon refused an image it had accepted -- machine-readable, so a
/// client can say it in its own words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCode {
    Other,
    /// Fewer or more bytes than offered.
    SizeMismatch,
    ChecksumMismatch,
    /// The staged binary did not start, or reported another build or
    /// architecture.
    SelfCheckFailed,
    /// The staged binary does not speak the current protocol, or cannot take
    /// this daemon's handover.
    VersionNotAccepted,
    /// The image could not be written or flushed.
    DiskError,
    /// Handing over or the exec itself failed.
    ExecFailed,
    /// The sender went quiet mid-transfer.
    TransferStalled,
    /// The daemon's control socket stayed busy past its bound, so the
    /// allowlist could not be held still for the handover. Nothing was
    /// exec'd; trying again later may succeed.
    ControlBusy,
    /// A code this build does not know -- from a newer daemon.
    Unknown(u8),
}

impl RejectCode {
    fn to_wire(self) -> u8 {
        match self {
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

    fn from_wire(code: u8) -> RejectCode {
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateResult {
    /// The image is good; the daemon is replacing itself now.
    Restarting,
    /// Refused: `code` for the client to act on, `detail` in English for a
    /// log.
    Rejected { code: RejectCode, detail: String },
    /// Other sessions arrived while the image was on its way.
    Busy { others: u32 },
    /// A code this build does not know -- from a newer daemon.
    Unknown(u8),
}

/// Whether `name` is an architecture name this protocol carries: lower-case
/// letters, digits and `_`, at most [`MAX_ARCH_LEN`] bytes. Empty is allowed
/// and means "not said" (a short [`About`]).
fn is_arch_name(name: &str) -> bool {
    name.len() <= MAX_ARCH_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Append a length-prefixed architecture name. Panics on a name
/// [`is_arch_name`] refuses: this side is the one that built it.
fn put_arch(buf: &mut Vec<u8>, arch: &str) {
    assert!(
        is_arch_name(arch),
        "architecture name {arch:?} is not one this protocol carries"
    );
    buf.push(arch.len() as u8);
    buf.extend_from_slice(arch.as_bytes());
}

/// A cursor over a record's payload: each read takes a whole field or says
/// the payload ended.
struct Fields<'a> {
    payload: &'a [u8],
    pos: usize,
}

impl<'a> Fields<'a> {
    fn new(payload: &'a [u8]) -> Fields<'a> {
        Fields { payload, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.payload.len()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.payload.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().expect("eight bytes")))
    }

    fn checksum(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|b| b.try_into().expect("32 bytes"))
    }

    /// A length-prefixed architecture name. Present but broken is
    /// `Malformed`.
    fn arch(&mut self) -> Result<String, ChannelCodecError> {
        let len = self.u8().ok_or(ChannelCodecError::Malformed)? as usize;
        let bytes = self.take(len).ok_or(ChannelCodecError::Malformed)?;
        let name = std::str::from_utf8(bytes).map_err(|_| ChannelCodecError::Malformed)?;
        if !is_arch_name(name) {
            return Err(ChannelCodecError::Malformed);
        }
        Ok(name.to_string())
    }
}

/// Read an [`About`]: `build` is required; every later field is either whole
/// or absent together with everything after it.
fn decode_about(payload: &[u8]) -> Result<About, ChannelCodecError> {
    let mut f = Fields::new(payload);
    let mut about = About {
        build: f.u64().ok_or(ChannelCodecError::Malformed)?,
        checksum: [0; 32],
        arch: String::new(),
        protocol: 0,
        mode: DaemonMode::Personal,
    };
    if f.is_empty() {
        return Ok(about);
    }
    about.checksum = f.checksum().ok_or(ChannelCodecError::Malformed)?;
    if f.is_empty() {
        return Ok(about);
    }
    about.arch = f.arch()?;
    let Some(protocol) = f.u8() else {
        return Ok(about);
    };
    about.protocol = protocol;
    let Some(mode) = f.u8() else {
        return Ok(about);
    };
    about.mode = DaemonMode::from_wire(mode);
    // Anything after this is a newer daemon's field: skipped.
    Ok(about)
}

fn answer_payload(answer: &UpdateAnswer) -> Vec<u8> {
    match answer {
        UpdateAnswer::Accept => vec![ANSWER_ACCEPT],
        UpdateAnswer::UpToDate => vec![ANSWER_UP_TO_DATE],
        UpdateAnswer::DaemonNewer => vec![ANSWER_DAEMON_NEWER],
        UpdateAnswer::Busy { others } => {
            let mut p = vec![ANSWER_BUSY];
            p.extend_from_slice(&others.to_be_bytes());
            p
        }
        UpdateAnswer::Managed => vec![ANSWER_MANAGED],
        UpdateAnswer::ArchMismatch => vec![ANSWER_ARCH_MISMATCH],
        UpdateAnswer::TooLarge => vec![ANSWER_TOO_LARGE],
        UpdateAnswer::NotAllowed => vec![ANSWER_NOT_ALLOWED],
        UpdateAnswer::InProgress => vec![ANSWER_IN_PROGRESS],
        UpdateAnswer::Unknown(code) => vec![*code],
    }
}

fn decode_answer(payload: &[u8]) -> Result<UpdateAnswer, ChannelCodecError> {
    let mut f = Fields::new(payload);
    let code = f.u8().ok_or(ChannelCodecError::Malformed)?;
    Ok(match code {
        ANSWER_ACCEPT => UpdateAnswer::Accept,
        ANSWER_UP_TO_DATE => UpdateAnswer::UpToDate,
        ANSWER_DAEMON_NEWER => UpdateAnswer::DaemonNewer,
        ANSWER_BUSY => UpdateAnswer::Busy {
            others: f.u32().ok_or(ChannelCodecError::Malformed)?,
        },
        ANSWER_MANAGED => UpdateAnswer::Managed,
        ANSWER_ARCH_MISMATCH => UpdateAnswer::ArchMismatch,
        ANSWER_TOO_LARGE => UpdateAnswer::TooLarge,
        ANSWER_NOT_ALLOWED => UpdateAnswer::NotAllowed,
        ANSWER_IN_PROGRESS => UpdateAnswer::InProgress,
        other => UpdateAnswer::Unknown(other),
    })
}

fn result_payload(result: &UpdateResult) -> Vec<u8> {
    match result {
        UpdateResult::Restarting => vec![RESULT_RESTARTING],
        UpdateResult::Rejected { code, detail } => {
            let mut p = vec![RESULT_REJECTED, code.to_wire()];
            p.extend_from_slice(detail.as_bytes());
            p
        }
        UpdateResult::Busy { others } => {
            let mut p = vec![RESULT_BUSY];
            p.extend_from_slice(&others.to_be_bytes());
            p
        }
        UpdateResult::Unknown(code) => vec![*code],
    }
}

fn decode_result(payload: &[u8]) -> Result<UpdateResult, ChannelCodecError> {
    let (&code, rest) = payload.split_first().ok_or(ChannelCodecError::Malformed)?;
    match code {
        RESULT_RESTARTING => Ok(UpdateResult::Restarting),
        RESULT_REJECTED => {
            // `code(1) | detail`; a body cut before the code reads as `Other`.
            let (code, detail) = match rest.split_first() {
                Some((&code, detail)) => (RejectCode::from_wire(code), detail),
                None => (RejectCode::Other, &[][..]),
            };
            String::from_utf8(detail.to_vec())
                .map(|detail| UpdateResult::Rejected { code, detail })
                .map_err(|_| ChannelCodecError::Malformed)
        }
        RESULT_BUSY => Ok(UpdateResult::Busy {
            others: Fields::new(rest)
                .u32()
                .ok_or(ChannelCodecError::Malformed)?,
        }),
        other => Ok(UpdateResult::Unknown(other)),
    }
}

/// What a channel runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// The user's login shell (`$SHELL`).
    Shell,
    /// The command carried in `OpenRequest::command`.
    Command,
}

/// What the client asks for when opening a channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// The stream this channel's data will use -- also its identity. The
    /// client picks it: only the client opens channels, so nothing can
    /// collide.
    pub stream: u8,
    pub kind: ChannelKind,
    /// Terminal size. `0` in either field means "no pseudo-terminal".
    pub cols: u16,
    pub rows: u16,
    /// What the CLIENT is asking for: whether it wants the server to keep a
    /// screen model for this channel, so a client returning after a long
    /// absence gets its screen back. Right to ask for a shell; wrong for a
    /// line protocol like `tmux -C`, where replaying a screen would corrupt
    /// the conversation.
    ///
    /// Not a guarantee of what the channel actually gets -- `channel_server.rs`
    /// declares recoverability off the SPAWNED channel's own
    /// `SessionScreen::has_screen` answer, both when the channel opens and
    /// again after a warm reattach, not off this field directly: a caller
    /// can ask for a screen here and still be handed `NoScreen` (any request
    /// that didn't ask for one gets `NoScreen` unconditionally; see
    /// `qshd/src/channel_backend.rs`'s `make_screen`). The transport drops
    /// a stream's backlog after a long absence exactly when the channel that
    /// owns it declared a screen model to repaint from, never by the stream
    /// number alone, and never by this request field alone either.
    pub screen: bool,
    /// The command line, empty for `ChannelKind::Shell`.
    pub command: Vec<u8>,
}

/// A record the client sends on [`CONTROL_STREAM`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRecord {
    Open(OpenRequest),
    Resize {
        stream: u8,
        cols: u16,
        rows: u16,
    },
    Close {
        stream: u8,
    },
    /// The terminal type of the client's own emulator, for every channel
    /// this session opens from here on. Sent before the first `Open`.
    ///
    /// SSH carries this in `pty-req`; qsh had nowhere to put it, so the
    /// daemon assumed one value for everybody. That is right for the app,
    /// whose emulator is fixed, and wrong for a console client, whose keys
    /// are encoded by ITS terminal: a Home key sent as `\e[1~` reaches a
    /// remote configured for `\eOH`, does nothing, and leaves its trailing
    /// `~` in the line.
    ///
    /// Its own record rather than a field of [`OpenRequest`] so the wire
    /// layout `Open` and `Channels` share stays untouched: a daemon that
    /// predates this ignores an unknown record kind and keeps its default,
    /// instead of failing to parse a request it otherwise understands.
    Term(String),
    /// "Who are you": answered by [`ServerRecord::About`], or not at all by a
    /// daemon that predates the record.
    AboutRequest,
    /// A binary the client is ready to hand over; answered by
    /// [`ServerRecord::UpdateAnswer`].
    UpdateOffer(UpdateOffer),
}

/// Longest terminal type accepted. Real names run to about twenty
/// characters (`rxvt-unicode-256color`); this leaves room without letting
/// the field become a place to stuff data.
pub const MAX_TERM_LEN: usize = 64;

/// Whether a terminal type is one we will hand to a process as `TERM`.
/// terminfo names are drawn from this alphabet, and holding the line here
/// keeps a newline or a path separator from ever reaching an environment
/// variable.
fn is_terminal_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TERM_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

/// A record the server sends on [`CONTROL_STREAM`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRecord {
    Opened {
        stream: u8,
    },
    /// The channel could not be opened. The reason is meant for a human and
    /// may come from this library or the daemon's channel backend. The host
    /// decides how to display it.
    Refused {
        stream: u8,
        reason: String,
    },
    /// The channel's process ended. The stream closes after this.
    Exit {
        stream: u8,
        code: i32,
    },
    /// Sent as the first record after a warm reattach, and only then: the
    /// channels already running, so the client binds to them instead of
    /// opening a second copy of each. Never sent on a cold start, where an
    /// empty list would be indistinguishable from a server that forgot to
    /// answer.
    Channels(Vec<OpenRequest>),
    /// The answer to [`ClientRecord::AboutRequest`].
    About(About),
    /// The answer to [`ClientRecord::UpdateOffer`].
    UpdateAnswer(UpdateAnswer),
    /// How an accepted transfer ended.
    UpdateResult(UpdateResult),
    /// The daemon is about to replace itself: sent to every session, so a
    /// client reconnects at once instead of waiting out a silence.
    Restarting,
}

/// Why a record could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelCodecError {
    /// A record kind this build does not know. Its envelope was still
    /// well-formed, so the stream is intact and parsing continues.
    UnknownKind(u8),
    /// The payload does not match the kind: too short, too long, or a field
    /// out of range.
    Malformed,
}

/// Bytes an [`OpenRequest`] takes before its command: stream, kind, cols,
/// rows, flags, cmd_len.
const OPEN_HEADER_LEN: usize = 1 + 1 + 2 + 2 + 1 + 2;

/// Bit 0 of the `flags` byte: the server should keep a screen model.
const FLAG_SCREEN: u8 = 0x01;

/// Append an [`OpenRequest`] in the wire layout shared by `OPEN` and every
/// entry of `CHANNELS`. The one function is what keeps the two record kinds
/// from drifting apart.
///
/// **Panics** if `req.command` is longer than [`MAX_COMMAND_LEN`]. The
/// length field below is two bytes wide: a command past 65535 bytes would
/// wrap silently into a length that lies about the bytes that follow it,
/// corrupting every record after it on the stream, and anything between
/// `MAX_COMMAND_LEN` and 65535 would encode a length the far side's
/// `take_open` rejects as `Malformed` -- leaving whatever channel this
/// record was about stuck `Opening` forever (see `ChannelSession::open` in
/// `crates/client/src/channel.rs`, the caller responsible for never handing
/// this function a command that long in the first place; this assertion is
/// the last line of defense, not the primary one).
fn put_open(buf: &mut Vec<u8>, req: &OpenRequest) {
    assert!(
        req.command.len() <= MAX_COMMAND_LEN,
        "command length {} exceeds MAX_COMMAND_LEN ({MAX_COMMAND_LEN})",
        req.command.len()
    );
    buf.push(req.stream);
    buf.push(match req.kind {
        ChannelKind::Shell => 0,
        ChannelKind::Command => 1,
    });
    buf.extend_from_slice(&req.cols.to_be_bytes());
    buf.extend_from_slice(&req.rows.to_be_bytes());
    buf.push(if req.screen { FLAG_SCREEN } else { 0 });
    buf.extend_from_slice(&(req.command.len() as u16).to_be_bytes());
    buf.extend_from_slice(&req.command);
}

/// Read one [`OpenRequest`] out of `payload` starting at `*pos`, advancing
/// `*pos` past it. The counterpart of [`put_open`], used by both `OPEN` and
/// `CHANNELS` so the two record kinds cannot disagree about the layout.
fn take_open(payload: &[u8], pos: &mut usize) -> Result<OpenRequest, ChannelCodecError> {
    if payload.len() - *pos < OPEN_HEADER_LEN {
        return Err(ChannelCodecError::Malformed);
    }
    let mut p = *pos;
    let stream = payload[p];
    p += 1;
    let kind = match payload[p] {
        0 => ChannelKind::Shell,
        1 => ChannelKind::Command,
        _ => return Err(ChannelCodecError::Malformed),
    };
    p += 1;
    let cols = u16::from_be_bytes([payload[p], payload[p + 1]]);
    p += 2;
    let rows = u16::from_be_bytes([payload[p], payload[p + 1]]);
    p += 2;
    let flags = payload[p];
    p += 1;
    let cmd_len = u16::from_be_bytes([payload[p], payload[p + 1]]) as usize;
    p += 2;
    // The length field is attacker controlled: reject an oversized command
    // before it can be turned into an allocation request, and before the
    // slice below could be asked to run past the payload.
    if cmd_len > MAX_COMMAND_LEN {
        return Err(ChannelCodecError::Malformed);
    }
    if payload.len() - p < cmd_len {
        return Err(ChannelCodecError::Malformed);
    }
    let command = payload[p..p + cmd_len].to_vec();
    p += cmd_len;
    if stream < FIRST_CHANNEL_STREAM {
        return Err(ChannelCodecError::Malformed);
    }
    if kind == ChannelKind::Shell && !command.is_empty() {
        return Err(ChannelCodecError::Malformed);
    }
    *pos = p;
    Ok(OpenRequest {
        stream,
        kind,
        cols,
        rows,
        screen: flags & FLAG_SCREEN != 0,
        command,
    })
}

/// Encode a record the client sends on [`CONTROL_STREAM`].
pub fn encode_client(rec: &ClientRecord) -> Vec<u8> {
    match rec {
        ClientRecord::Open(req) => {
            let mut payload = Vec::new();
            put_open(&mut payload, req);
            encode_record(REC_OPEN, &payload)
        }
        ClientRecord::Resize { stream, cols, rows } => {
            let mut payload = Vec::with_capacity(5);
            payload.push(*stream);
            payload.extend_from_slice(&cols.to_be_bytes());
            payload.extend_from_slice(&rows.to_be_bytes());
            encode_record(REC_RESIZE, &payload)
        }
        ClientRecord::Close { stream } => encode_record(REC_CLOSE, &[*stream]),
        ClientRecord::Term(name) => encode_record(REC_TERM, name.as_bytes()),
        ClientRecord::AboutRequest => encode_record(REC_ABOUT_REQUEST, &[]),
        ClientRecord::UpdateOffer(offer) => {
            let mut payload = Vec::with_capacity(8 + 32 + 8 + 1 + offer.arch.len());
            payload.extend_from_slice(&offer.build.to_be_bytes());
            payload.extend_from_slice(&offer.checksum);
            payload.extend_from_slice(&offer.size.to_be_bytes());
            put_arch(&mut payload, &offer.arch);
            encode_record(REC_UPDATE_OFFER, &payload)
        }
    }
}

/// Decode a record the client sent on [`CONTROL_STREAM`]. `Err(UnknownKind)`
/// means the envelope was fine but this build doesn't recognize the type;
/// `Err(Malformed)` means the payload didn't match what the type promises.
pub fn decode_client(raw: &RawRecord) -> Result<ClientRecord, ChannelCodecError> {
    match raw.kind {
        REC_OPEN => {
            let mut pos = 0;
            let req = take_open(&raw.payload, &mut pos)?;
            if pos != raw.payload.len() {
                return Err(ChannelCodecError::Malformed);
            }
            Ok(ClientRecord::Open(req))
        }
        REC_RESIZE => {
            if raw.payload.len() != 5 {
                return Err(ChannelCodecError::Malformed);
            }
            let stream = raw.payload[0];
            if stream < FIRST_CHANNEL_STREAM {
                return Err(ChannelCodecError::Malformed);
            }
            let cols = u16::from_be_bytes([raw.payload[1], raw.payload[2]]);
            let rows = u16::from_be_bytes([raw.payload[3], raw.payload[4]]);
            Ok(ClientRecord::Resize { stream, cols, rows })
        }
        REC_CLOSE => {
            if raw.payload.len() != 1 {
                return Err(ChannelCodecError::Malformed);
            }
            let stream = raw.payload[0];
            if stream < FIRST_CHANNEL_STREAM {
                return Err(ChannelCodecError::Malformed);
            }
            Ok(ClientRecord::Close { stream })
        }
        REC_TERM => {
            let name =
                std::str::from_utf8(&raw.payload).map_err(|_| ChannelCodecError::Malformed)?;
            if !is_terminal_name(name) {
                return Err(ChannelCodecError::Malformed);
            }
            Ok(ClientRecord::Term(name.to_string()))
        }
        // Tail-extensible: a newer client may give the request a body.
        REC_ABOUT_REQUEST => Ok(ClientRecord::AboutRequest),
        REC_UPDATE_OFFER => {
            let mut f = Fields::new(&raw.payload);
            let build = f.u64().ok_or(ChannelCodecError::Malformed)?;
            let checksum = f.checksum().ok_or(ChannelCodecError::Malformed)?;
            let size = f.u64().ok_or(ChannelCodecError::Malformed)?;
            let arch = f.arch()?;
            Ok(ClientRecord::UpdateOffer(UpdateOffer {
                build,
                checksum,
                arch,
                size,
            }))
        }
        other => Err(ChannelCodecError::UnknownKind(other)),
    }
}

/// Encode a record the server sends on [`CONTROL_STREAM`].
pub fn encode_server(rec: &ServerRecord) -> Vec<u8> {
    match rec {
        ServerRecord::Opened { stream } => encode_record(REC_OPENED, &[*stream]),
        ServerRecord::Refused { stream, reason } => {
            let mut payload = Vec::with_capacity(1 + reason.len());
            payload.push(*stream);
            payload.extend_from_slice(reason.as_bytes());
            encode_record(REC_REFUSED, &payload)
        }
        ServerRecord::Exit { stream, code } => {
            let mut payload = Vec::with_capacity(5);
            payload.push(*stream);
            payload.extend_from_slice(&code.to_be_bytes());
            encode_record(REC_EXIT, &payload)
        }
        ServerRecord::Channels(list) => {
            let mut payload = Vec::new();
            payload.push(list.len() as u8);
            for req in list {
                put_open(&mut payload, req);
            }
            encode_record(REC_CHANNELS, &payload)
        }
        ServerRecord::About(about) => {
            let mut payload = Vec::with_capacity(8 + 32 + 1 + about.arch.len() + 2);
            payload.extend_from_slice(&about.build.to_be_bytes());
            payload.extend_from_slice(&about.checksum);
            put_arch(&mut payload, &about.arch);
            payload.push(about.protocol);
            payload.push(about.mode.to_wire());
            encode_record(REC_ABOUT, &payload)
        }
        ServerRecord::UpdateAnswer(answer) => {
            encode_record(REC_UPDATE_ANSWER, &answer_payload(answer))
        }
        ServerRecord::UpdateResult(result) => {
            encode_record(REC_UPDATE_RESULT, &result_payload(result))
        }
        ServerRecord::Restarting => encode_record(REC_RESTARTING, &[]),
    }
}

/// Decode a record the server sent on [`CONTROL_STREAM`]. Same two-error
/// shape as [`decode_client`]: an unknown kind leaves the stream intact, a
/// malformed payload does not.
pub fn decode_server(raw: &RawRecord) -> Result<ServerRecord, ChannelCodecError> {
    match raw.kind {
        REC_OPENED => {
            if raw.payload.len() != 1 {
                return Err(ChannelCodecError::Malformed);
            }
            let stream = raw.payload[0];
            if stream < FIRST_CHANNEL_STREAM {
                return Err(ChannelCodecError::Malformed);
            }
            Ok(ServerRecord::Opened { stream })
        }
        REC_REFUSED => {
            if raw.payload.is_empty() {
                return Err(ChannelCodecError::Malformed);
            }
            let stream = raw.payload[0];
            if stream < FIRST_CHANNEL_STREAM {
                return Err(ChannelCodecError::Malformed);
            }
            let reason = String::from_utf8(raw.payload[1..].to_vec())
                .map_err(|_| ChannelCodecError::Malformed)?;
            Ok(ServerRecord::Refused { stream, reason })
        }
        REC_EXIT => {
            if raw.payload.len() != 5 {
                return Err(ChannelCodecError::Malformed);
            }
            let stream = raw.payload[0];
            if stream < FIRST_CHANNEL_STREAM {
                return Err(ChannelCodecError::Malformed);
            }
            let code = i32::from_be_bytes([
                raw.payload[1],
                raw.payload[2],
                raw.payload[3],
                raw.payload[4],
            ]);
            Ok(ServerRecord::Exit { stream, code })
        }
        REC_CHANNELS => {
            if raw.payload.is_empty() {
                return Err(ChannelCodecError::Malformed);
            }
            let count = raw.payload[0] as usize;
            let mut pos = 1;
            let mut channels = Vec::with_capacity(count);
            for _ in 0..count {
                channels.push(take_open(&raw.payload, &mut pos)?);
            }
            if pos != raw.payload.len() {
                return Err(ChannelCodecError::Malformed);
            }
            Ok(ServerRecord::Channels(channels))
        }
        REC_ABOUT => decode_about(&raw.payload).map(ServerRecord::About),
        REC_UPDATE_ANSWER => decode_answer(&raw.payload).map(ServerRecord::UpdateAnswer),
        REC_UPDATE_RESULT => decode_result(&raw.payload).map(ServerRecord::UpdateResult),
        REC_RESTARTING => Ok(ServerRecord::Restarting),
        other => Err(ChannelCodecError::UnknownKind(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_frame::encode_record;

    /// A terminal type that is not one goes no further than the codec. The
    /// value becomes the `TERM` of a process the daemon spawns, so a name
    /// carrying a newline, a path separator or a shell metacharacter has no
    /// business being decoded into one -- and the daemon, which ignores a
    /// record it cannot read, keeps its own default instead.
    #[test]
    fn a_terminal_type_that_is_not_a_terminfo_name_is_refused() {
        for bad in [
            "",
            "xterm 256color",
            "xterm\n256color",
            "../../etc/passwd",
            "xterm;rm -rf /",
            "xterm$(id)",
        ] {
            let raw = RawRecord {
                kind: REC_TERM,
                payload: bad.as_bytes().to_vec(),
            };
            assert_eq!(
                decode_client(&raw),
                Err(ChannelCodecError::Malformed),
                "a terminal type must be a terminfo name, but {bad:?} decoded"
            );
        }
    }

    /// The length cap holds at its own boundary: one byte over and the
    /// record is refused, exactly at the cap it is accepted.
    #[test]
    fn a_terminal_type_is_capped_at_its_documented_length() {
        let at_cap = "a".repeat(MAX_TERM_LEN);
        let over = "a".repeat(MAX_TERM_LEN + 1);
        let raw_ok = RawRecord {
            kind: REC_TERM,
            payload: at_cap.as_bytes().to_vec(),
        };
        assert_eq!(decode_client(&raw_ok), Ok(ClientRecord::Term(at_cap)));
        let raw_over = RawRecord {
            kind: REC_TERM,
            payload: over.as_bytes().to_vec(),
        };
        assert_eq!(decode_client(&raw_over), Err(ChannelCodecError::Malformed));
    }

    /// A daemon that predates the terminal type must not be broken by one:
    /// its record kind is unknown there, which the envelope skips by length,
    /// leaving the records around it readable.
    #[test]
    fn an_older_peer_skips_the_terminal_type_and_reads_on() {
        let mut bytes = encode_client(&ClientRecord::Term("xterm-256color".to_string()));
        bytes.extend_from_slice(&encode_client(&ClientRecord::Close { stream: 16 }));
        let mut d = RecordDeframer::new();
        let raw = d.push(&bytes);
        assert_eq!(raw.len(), 2, "both records are framed");
        // What an older build does with the first one: it does not know the
        // kind, and says so rather than mis-reading it.
        assert!(matches!(
            raw[0].kind,
            k if k == REC_TERM
        ));
        assert_eq!(
            decode_client(&raw[1]),
            Ok(ClientRecord::Close { stream: 16 }),
            "the record after an unknown one is still readable"
        );
    }

    /// Every record survives a trip through the wire format unchanged. The
    /// loop is the point: a new record kind added without a round-trip is
    /// the classic way a codec grows a hole.
    #[test]
    fn every_record_round_trips() {
        let client = vec![
            ClientRecord::Open(OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 120,
                rows: 40,
                screen: true,
                command: Vec::new(),
            }),
            ClientRecord::Open(OpenRequest {
                stream: 17,
                kind: ChannelKind::Command,
                cols: 0,
                rows: 0,
                screen: false,
                command: b"tmux -C attach".to_vec(),
            }),
            ClientRecord::Resize {
                stream: 16,
                cols: 80,
                rows: 24,
            },
            ClientRecord::Close { stream: 17 },
            ClientRecord::Term("rxvt-unicode-256color".to_string()),
        ];
        for rec in client {
            let bytes = encode_client(&rec);
            let mut d = RecordDeframer::new();
            let raw = d.push(&bytes);
            assert_eq!(raw.len(), 1, "one record in, one record out");
            assert_eq!(
                decode_client(&raw[0]),
                Ok(rec.clone()),
                "client record must survive the round trip: {rec:?}"
            );
        }

        let server = vec![
            ServerRecord::Opened { stream: 16 },
            ServerRecord::Refused {
                stream: 18,
                reason: "too many channels".to_string(),
            },
            ServerRecord::Exit {
                stream: 16,
                code: 130,
            },
            ServerRecord::Channels(vec![OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 100,
                rows: 30,
                screen: true,
                command: Vec::new(),
            }]),
        ];
        for rec in server {
            let bytes = encode_server(&rec);
            let mut d = RecordDeframer::new();
            let raw = d.push(&bytes);
            assert_eq!(raw.len(), 1, "one record in, one record out");
            assert_eq!(
                decode_server(&raw[0]),
                Ok(rec.clone()),
                "server record must survive the round trip: {rec:?}"
            );
        }
    }

    /// Spec §4.16 (QSH-06): the longest control record this protocol defines
    /// -- a `CHANNELS` list of `MAX_CHANNELS` commands at `MAX_COMMAND_LEN`,
    /// 32 841 bytes of payload -- and the longest `OPEN` fit
    /// `CONTROL_RECORD_MAX` with room to spare, so the limit refuses only
    /// what no build sends.
    #[test]
    fn the_longest_control_record_fits_the_control_limit() {
        let open = |stream| OpenRequest {
            stream,
            kind: ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: vec![b'c'; MAX_COMMAND_LEN],
        };
        let longest = encode_server(&ServerRecord::Channels(
            (0..MAX_CHANNELS as u8).map(|i| open(16 + i)).collect(),
        ));
        let limit = crate::shell_frame::CONTROL_RECORD_MAX;
        assert!(
            longest.len() - 5 <= limit * 3 / 4,
            "{} bytes",
            longest.len()
        );
        assert!(encode_client(&ClientRecord::Open(open(16))).len() - 5 <= limit / 8);
        assert_eq!(RecordDeframer::for_control().push(&longest).len(), 1);
    }

    /// A reliable stream delivers bytes in whatever chunks it pleases. Fed
    /// one byte at a time, the deframer must still produce exactly the same
    /// records, and produce each one only once it is whole.
    #[test]
    fn records_survive_byte_by_byte_delivery() {
        let mut wire = encode_client(&ClientRecord::Open(OpenRequest {
            stream: 16,
            kind: ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: b"tmux -C attach".to_vec(),
        }));
        wire.extend_from_slice(&encode_client(&ClientRecord::Close { stream: 16 }));

        let mut d = RecordDeframer::new();
        let mut got = Vec::new();
        for b in &wire {
            got.extend(d.push(&[*b]));
        }
        assert_eq!(got.len(), 2, "both records arrive, and only when complete");
        assert!(matches!(decode_client(&got[0]), Ok(ClientRecord::Open(_))));
        assert_eq!(
            decode_client(&got[1]),
            Ok(ClientRecord::Close { stream: 16 })
        );
    }

    /// An unknown record type is skipped by its own length, so the records
    /// after it still parse. The old resize parser shifted by one byte on an
    /// unknown type and could resynchronise onto payload bytes; the envelope
    /// makes that unnecessary.
    #[test]
    fn an_unknown_record_type_does_not_desynchronise_the_stream() {
        let mut wire = crate::shell_frame::encode_record(0x7f, b"a kind from a newer peer");
        wire.extend_from_slice(&encode_client(&ClientRecord::Close { stream: 20 }));

        let mut d = RecordDeframer::new();
        let raw = d.push(&wire);
        assert_eq!(
            raw.len(),
            2,
            "the unknown record is still a well-formed envelope"
        );
        assert!(
            matches!(
                decode_client(&raw[0]),
                Err(ChannelCodecError::UnknownKind(0x7f))
            ),
            "the unknown kind is reported, not guessed at"
        );
        assert_eq!(
            decode_client(&raw[1]),
            Ok(ClientRecord::Close { stream: 20 }),
            "the record after an unknown one still parses"
        );
    }

    /// A truncated payload is a malformed record, not a panic and not a
    /// silently different record.
    #[test]
    fn a_truncated_payload_is_reported_as_malformed() {
        let raw = RawRecord {
            kind: 0x11,
            payload: vec![16, 0],
        };
        assert_eq!(decode_client(&raw), Err(ChannelCodecError::Malformed));
    }

    /// A command longer than the cap is rejected while decoding, rather
    /// than allocated because a peer said so. The length field is attacker
    /// controlled; the cap is what keeps it from being a memory request.
    #[test]
    fn an_oversized_command_is_rejected_rather_than_allocated() {
        let raw = RawRecord {
            kind: 0x10,
            payload: {
                let mut p = vec![16, 1, 0, 80, 0, 24, 0];
                p.extend_from_slice(&(MAX_COMMAND_LEN as u16 + 1).to_be_bytes());
                p.extend(std::iter::repeat_n(b'x', MAX_COMMAND_LEN + 1));
                p
            },
        };
        assert_eq!(decode_client(&raw), Err(ChannelCodecError::Malformed));
    }

    /// The encode side must refuse an oversized command loudly rather than
    /// silently wrap or truncate its two-byte length field. Reception
    /// already rejects a too-long command (the test above); without this,
    /// nothing stopped a caller from producing a wire record whose length
    /// byte lied about its own payload -- the send-side half of the gap the
    /// final review's item 2 exists to close.
    #[test]
    #[should_panic(expected = "exceeds MAX_COMMAND_LEN")]
    fn encoding_an_oversized_command_panics_instead_of_wrapping_the_length() {
        let _ = encode_client(&ClientRecord::Open(OpenRequest {
            stream: 16,
            kind: ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: vec![b'x'; MAX_COMMAND_LEN + 1],
        }));
    }

    fn about() -> About {
        About {
            build: 1_790_000_000,
            checksum: [0xab; 32],
            arch: "x86_64".to_string(),
            protocol: PROTOCOL_VERSION,
            mode: DaemonMode::Personal,
        }
    }

    /// Every update record survives the trip, in both directions -- the same
    /// guard `every_record_round_trips` keeps for the channel records.
    #[test]
    fn every_update_record_round_trips() {
        let client = vec![
            ClientRecord::AboutRequest,
            ClientRecord::UpdateOffer(UpdateOffer {
                build: 1_790_000_001,
                checksum: [0xcd; 32],
                arch: "aarch64".to_string(),
                size: 3_413_032,
            }),
        ];
        for rec in client {
            let mut d = RecordDeframer::new();
            let raw = d.push(&encode_client(&rec));
            assert_eq!(raw.len(), 1);
            assert_eq!(decode_client(&raw[0]), Ok(rec.clone()), "{rec:?}");
        }

        let server = vec![
            ServerRecord::About(about()),
            ServerRecord::About(About {
                mode: DaemonMode::Managed,
                ..about()
            }),
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept),
            ServerRecord::UpdateAnswer(UpdateAnswer::UpToDate),
            ServerRecord::UpdateAnswer(UpdateAnswer::DaemonNewer),
            ServerRecord::UpdateAnswer(UpdateAnswer::Busy { others: 3 }),
            ServerRecord::UpdateAnswer(UpdateAnswer::Managed),
            ServerRecord::UpdateAnswer(UpdateAnswer::ArchMismatch),
            ServerRecord::UpdateAnswer(UpdateAnswer::TooLarge),
            ServerRecord::UpdateAnswer(UpdateAnswer::NotAllowed),
            ServerRecord::UpdateAnswer(UpdateAnswer::InProgress),
            ServerRecord::UpdateAnswer(UpdateAnswer::Unknown(0x7f)),
            ServerRecord::UpdateResult(UpdateResult::Restarting),
            ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::SelfCheckFailed,
                detail: "self-check failed: exit status: 3".to_string(),
            }),
            ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::Unknown(0x7f),
                detail: String::new(),
            }),
            ServerRecord::UpdateResult(UpdateResult::Busy { others: 1 }),
            ServerRecord::UpdateResult(UpdateResult::Unknown(0x7f)),
            ServerRecord::Restarting,
        ];
        for rec in server {
            let mut d = RecordDeframer::new();
            let raw = d.push(&encode_server(&rec));
            assert_eq!(raw.len(), 1);
            assert_eq!(decode_server(&raw[0]), Ok(rec.clone()), "{rec:?}");
        }
    }

    /// A daemon one step older than this build sends a shorter `About`:
    /// whatever is missing reads as its default, the way a short msg2 does
    /// in `handshake_payload`.
    #[test]
    fn a_short_about_reads_its_missing_fields_as_defaults() {
        let only_build = RawRecord {
            kind: REC_ABOUT,
            payload: 7u64.to_be_bytes().to_vec(),
        };
        assert_eq!(
            decode_server(&only_build),
            Ok(ServerRecord::About(About {
                build: 7,
                checksum: [0; 32],
                arch: String::new(),
                protocol: 0,
                mode: DaemonMode::Personal,
            }))
        );

        let mut up_to_arch = 7u64.to_be_bytes().to_vec();
        up_to_arch.extend_from_slice(&[9; 32]);
        up_to_arch.push(6);
        up_to_arch.extend_from_slice(b"x86_64");
        assert_eq!(
            decode_server(&RawRecord {
                kind: REC_ABOUT,
                payload: up_to_arch,
            }),
            Ok(ServerRecord::About(About {
                build: 7,
                checksum: [9; 32],
                arch: "x86_64".to_string(),
                protocol: 0,
                mode: DaemonMode::Personal,
            }))
        );
    }

    /// A newer daemon appends fields this build does not know: they are
    /// skipped, and the ones it does know still read.
    #[test]
    fn a_longer_about_from_a_newer_daemon_keeps_the_fields_this_build_knows() {
        let mut bytes = encode_server(&ServerRecord::About(about()));
        bytes.extend_from_slice(&[0xaa, 0xbb]);
        // Fix the envelope's length to cover the two extra bytes.
        let len = (bytes.len() - 5) as u32;
        bytes[1..5].copy_from_slice(&len.to_be_bytes());
        let raw = RecordDeframer::new().push(&bytes);
        assert_eq!(decode_server(&raw[0]), Ok(ServerRecord::About(about())));
    }

    /// Every rejection code survives the trip, and one this build does not
    /// know is kept as `Unknown` rather than refusing the record. A body
    /// with no code at all (nothing after the result byte) reads as `Other`.
    #[test]
    fn rejection_codes_are_kept_and_unknown_ones_survive() {
        for code in [
            RejectCode::Other,
            RejectCode::SizeMismatch,
            RejectCode::ChecksumMismatch,
            RejectCode::SelfCheckFailed,
            RejectCode::VersionNotAccepted,
            RejectCode::DiskError,
            RejectCode::ExecFailed,
            RejectCode::TransferStalled,
            RejectCode::ControlBusy,
        ] {
            let rec = ServerRecord::UpdateResult(UpdateResult::Rejected {
                code,
                detail: "why".to_string(),
            });
            let raw = RecordDeframer::new().push(&encode_server(&rec));
            assert_eq!(decode_server(&raw[0]), Ok(rec), "{code:?}");
        }
        // The busy control socket is code 8 on the wire (protocol.md §8).
        let busy = RawRecord {
            kind: REC_UPDATE_RESULT,
            payload: vec![RESULT_REJECTED, 8, b'x'],
        };
        assert_eq!(
            decode_server(&busy),
            Ok(ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::ControlBusy,
                detail: "x".to_string(),
            }))
        );
        let unknown = RawRecord {
            kind: REC_UPDATE_RESULT,
            payload: vec![RESULT_REJECTED, 0x40, b'x'],
        };
        assert_eq!(
            decode_server(&unknown),
            Ok(ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::Unknown(0x40),
                detail: "x".to_string(),
            }))
        );
        let bare = RawRecord {
            kind: REC_UPDATE_RESULT,
            payload: vec![RESULT_REJECTED],
        };
        assert_eq!(
            decode_server(&bare),
            Ok(ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::Other,
                detail: String::new(),
            }))
        );
    }

    /// A field cut off half-way is a broken promise, not a missing field.
    #[test]
    fn a_checksum_cut_short_is_malformed_not_a_default() {
        let mut payload = 7u64.to_be_bytes().to_vec();
        payload.extend_from_slice(&[9; 10]);
        assert_eq!(
            decode_server(&RawRecord {
                kind: REC_ABOUT,
                payload,
            }),
            Err(ChannelCodecError::Malformed)
        );
    }

    /// The architecture name is compared and logged, never executed -- but
    /// holding it to a name's alphabet keeps a record from smuggling
    /// anything else into a log line.
    #[test]
    fn an_architecture_that_is_not_a_name_is_malformed() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&[1; 32]);
        payload.extend_from_slice(&10u64.to_be_bytes());
        payload.push(6);
        payload.extend_from_slice(b"x86 64");
        assert_eq!(
            decode_client(&RawRecord {
                kind: REC_UPDATE_OFFER,
                payload,
            }),
            Err(ChannelCodecError::Malformed)
        );
    }

    /// An older daemon or client meets these records as unknown kinds: the
    /// envelope carries it past them, and the record after still reads.
    #[test]
    fn an_older_peer_skips_the_update_records_by_their_length() {
        let mut wire = encode_server(&ServerRecord::About(about()));
        wire.extend_from_slice(&encode_server(&ServerRecord::Restarting));
        wire.extend_from_slice(&encode_record(0x2f, b"a record from a newer daemon"));
        wire.extend_from_slice(&encode_server(&ServerRecord::Opened { stream: 16 }));
        let raw = RecordDeframer::new().push(&wire);
        assert_eq!(raw.len(), 4, "every record is its own envelope");
        assert_eq!(raw[0].kind, REC_ABOUT);
        assert_eq!(raw[1].kind, REC_RESTARTING);
        assert_eq!(
            decode_server(&raw[2]),
            Err(ChannelCodecError::UnknownKind(0x2f))
        );
        assert_eq!(
            decode_server(&raw[3]),
            Ok(ServerRecord::Opened { stream: 16 }),
            "the record after the unknown ones still parses"
        );
    }
}
