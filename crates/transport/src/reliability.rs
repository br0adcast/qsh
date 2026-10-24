//! A reliable ordered stream on top of unreliable datagrams (sans-IO).
//!
//! The module does no I/O: it only turns a byte stream into a set of internal
//! frames (`StreamFrame`), which the caller packs into the datagram's AEAD
//! payload (see `wire.rs`), and reassembles the stream on the receive side.
//! Only ARQ logic lives here: the sender's unacknowledged buffer, timeout
//! (RTO) retransmit, and in-order assembly on the receiver.
//!
//! Internal frames (inside the decrypted payload) are distinct from the
//! outer datagram. Frame layout: a `type` byte, then big-endian fields.
//! - `0x01 ACK`        : `stream_id(1), cum_ack(u32)`
//! - `0x02 DATA`       : `stream_id(1), offset(u32), len(u16), payload[len]`
//! - `0x03 PING`       : `token(u32)`
//! - `0x04 PONG`       : `token(u32)`
//! - `0x05 CLOSE`      : `stream_id(1)`
//! - `0x06 RESET`      : `stream_id(1), new_offset(u32)`
//! - `0x07 PATH_PROBE` : `token(u32)`
//! - `0x08 PATH_PROBE_ACK` : `token(u32)`
//! - `0x09 CREDIT`     : `stream_id(1), limit(u32)` -- only with `stream-credit` (spec §6)
//! - `0x0a SESSION_ABORT` : `reason(1)` -- only with `resource-limits`
//!
//! Offsets on the wire are the low 32 bits of a full 64-bit offset; with
//! `offset-wrap` the reader expands them (`expand`), without it they are the
//! offset (spec §4.14).
//!
//! With `stream-credit` a receiver keeps at most `CREDIT_ANNOUNCED_MAX`
//! limits announced per stream (plus one more that a `Reset` may add): a
//! bound against a hostile peer growing that list without limit (spec §6.4).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use crate::features::Features;

/// Frame type tag bytes on the wire.
const TYPE_ACK: u8 = 0x01;
const TYPE_DATA: u8 = 0x02;
const TYPE_PING: u8 = 0x03;
const TYPE_PONG: u8 = 0x04;
const TYPE_CLOSE: u8 = 0x05;
const TYPE_RESET: u8 = 0x06;
const TYPE_PATH_PROBE: u8 = 0x07;
const TYPE_PATH_PROBE_ACK: u8 = 0x08;
const TYPE_CREDIT: u8 = 0x09;
const TYPE_SESSION_ABORT: u8 = 0x0a;

/// Limit on unacknowledged bytes "in flight" (sender window), 256 KiB.
pub const MAX_IN_FLIGHT: usize = 256 * 1024;

/// What a sender's ring keeps of its room as it drains: twice the 512 KiB
/// tail at which the widest send gate closes (spec §4.7.2), about the size a
/// gated stream's ring grows to. Such a ring is never shrunk -- it fills and
/// drains all the time, and would pay for a reallocation on every burst. A
/// ring a burst past every gate grew bigger (past `SEND_HARD_CAP` at worst,
/// whose bytes a stream nobody can rebuild keeps) gives the rest back as it
/// is acknowledged, instead of holding its peak for the connection's life.
const RING_KEEP: usize = 1024 * 1024;

/// Maximum payload size of a single DATA frame. Kept well below `u16::MAX`
/// so the length field doesn't overflow and the frame fits in one datagram.
pub(crate) const MAX_SEGMENT_SIZE: usize = 1024;

/// What a receiver keeps past its cumulative point for a sender without
/// credits (spec §4.16, QSH-01): the window every such sender stays in,
/// this build's and every older one's -- at most `MAX_IN_FLIGHT` past the
/// last byte it saw acknowledged, and nothing is acknowledged past the
/// receiver's point.
pub const LEGACY_RECEIVE_WINDOW: u64 = MAX_IN_FLIGHT as u64;

/// The credit window (spec §3.2, §6.2): how far past what its consumer has
/// taken a stream's sender may write, from the first byte on. Twice
/// `MAX_IN_FLIGHT`, so a consumer that keeps up never holds a sender back.
/// Fixed by the `stream-credit` bit: another value would be another bit.
pub const STREAM_WINDOW: u64 = 512 * 1024;

/// A limit grown by this much since it was last announced is announced
/// (spec §6.4): at most four `CREDIT` frames a window.
pub const CREDIT_UPDATE_STEP: u64 = 128 * 1024;

/// How many times the newest limit is sent again, one `rto` apart, to a
/// sender that may be stopped at an older one (spec §6.4); the PONGs carry
/// it meanwhile and after that, each stream at most once per `rto`
/// ([`StreamReceiver::credit_for_pong`]).
pub const CREDIT_RESENDS: u32 = 3;

/// How many limits [`StreamReceiver::credit_due`] keeps announced at once
/// for one stream, at most (spec §6.4): a bound on `Credit::announced`. A
/// growth that would push past it does not happen yet -- once data passes
/// the oldest entry and pops it, which every data arrival and every call to
/// [`StreamReceiver::on_consumed`] gives another chance at, that growth
/// becomes eligible again and is judged by the ordinary rules (an `urgent`
/// flag from a `Reset` is not remembered across the wait). A sender flagged
/// "possibly stopped" still gets the newest entry repeated and riding the
/// PONGs meanwhile, so nothing stalls: only the growth is delayed. `Reset`'s
/// own `q` (`StreamReceiver::on_reset`) is not bound by this -- it may add
/// one entry past the cap, so the list holds at most
/// `CREDIT_ANNOUNCED_MAX + 1` after a `Reset`. Without a cap, a hostile peer
/// sending forward `Reset`s of one byte each could grow the list without
/// bound -- the cap does not lower the CREDIT rate that draws (each forward
/// `Reset` still draws its announcement and arms its own repeat cycle: the
/// newest goes out again `CREDIT_RESENDS` times in all, one `rto` apart,
/// the first one `rto` after it was last sent, or at once if that was
/// already an `rto` or more ago), only the memory. Only a client takes a
/// `Reset` at all: a server drops a client's (ruling R15, spec §6.5).
pub const CREDIT_ANNOUNCED_MAX: usize = 16;

/// What one out-of-order chunk costs a receiver beyond its bytes: its key
/// and `Vec` header in the map's nodes, which the tree keeps no less than
/// 5/11 full and a peer can keep near that by the order it sends in, and
/// the smallest heap block its bytes take. Measured (2026-09-28, x86_64,
/// Rust 1.98's `BTreeMap<u64, Vec<u8>>`, a window of chunks inserted in
/// ascending, descending, random and node-sealing order): at most 108
/// bytes beyond a one-byte chunk and 92 beyond a full segment with glibc,
/// 100 beyond a one-byte chunk with musl. Charged per chunk because a
/// window of offsets can be sent as tens of thousands of one-byte chunks
/// (the reasoning of probation's `EARLY_ENTRY_COST`). Not counted: how the
/// allocator rounds the bytes themselves up -- musl keeps a 1 KiB block in
/// about 1.15 KiB, so there a window of full segments takes up to a tenth
/// more than its cost (with glibc the cost covers it).
pub const CHUNK_COST: usize = 128;

/// The last stream offset a sender writes up to (spec §4.14, the mode without
/// modular offsets): 16 MiB short of the end of the 32-bit space, so nothing
/// in flight or in a peer's reorder buffer comes near the wrap. A stream that
/// reaches it stops; the connection's owner reconnects.
pub const OFFSET_LIMIT: u32 = u32::MAX - 16 * 1024 * 1024;

/// A write refused because it would reach past [`OFFSET_LIMIT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetSpaceExhausted;

/// The stream offset a 32-bit wire field names (spec §4.14). With modular
/// offsets (`offset-wrap`) it is the full offset nearest `expected` whose
/// low 32 bits the field holds: RFC 1982 serial arithmetic, as QUIC expands
/// its packet numbers (RFC 9000 §A.3). A field exactly 2^31 away reads as
/// behind, and one that would name an offset below zero names nothing.
/// Without them the field is the offset itself.
pub(crate) fn expand(expected: u64, wire: u32, wrap: bool) -> Option<u64> {
    if !wrap {
        return Some(u64::from(wire));
    }
    let delta = wire.wrapping_sub(expected as u32) as i32;
    expected.checked_add_signed(i64::from(delta))
}

/// A credit limit as the wire can carry it: without `offset-wrap` never past
/// `OFFSET_LIMIT`, where such a stream stops anyway (spec §6.2).
fn ceiling(limit: u64, wrap: bool) -> u64 {
    if wrap {
        limit
    } else {
        limit.min(u64::from(OFFSET_LIMIT))
    }
}

/// The last full offset a receiver with `offset-wrap` takes (spec §4.14):
/// 2^62, more than a century of a stream at 1 GB/s. Nothing past it is
/// kept, delivered or reached by a `Reset`, so no sum of an offset and a
/// length the receiver forms comes near the end of `u64`, whatever its peer
/// sends -- a `Reset` moves the point less than 2^31 at a time (`expand`),
/// and crafted ones walk it no farther than here.
pub(crate) const FULL_OFFSET_MAX: u64 = 1 << 62;

/// Why an authenticated peer terminated the entire session. This is not a
/// channel exit status, transport outage, or cleanup receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionAbortReason {
    ResourceExhausted,
    Unknown(u8),
}
impl SessionAbortReason {
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            Self::ResourceExhausted => 1,
            Self::Unknown(code) => code,
        }
    }
    pub(crate) fn from_wire(code: u8) -> Self {
        match code {
            1 => Self::ResourceExhausted,
            other => Self::Unknown(other),
        }
    }
}

/// An internal reliable-stream frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamFrame {
    /// Cumulative acknowledgment: all stream bytes up to `cum_ack` have been
    /// received.
    Ack { stream_id: u8, cum_ack: u32 },
    /// A chunk of stream data with absolute offset `offset`.
    Data {
        stream_id: u8,
        offset: u32,
        data: Vec<u8>,
    },
    /// A liveness check: the receiver must reply with `Pong` carrying the
    /// same `token`.
    Ping { token: u32 },
    /// A reply to `Ping`.
    Pong { token: u32 },
    /// The sender closing the stream.
    Close { stream_id: u8 },
    /// Terminal session failure, only with the resource-limits feature.
    SessionAbort { reason: SessionAbortReason },
    /// The sender discarded its output backlog after a long client absence and
    /// restarts the stream at `new_offset`. The receiver jumps its cumulative
    /// point there -- but only if `new_offset` is actually ahead of where it
    /// already is: the sender re-arms this on every flush until it's acked,
    /// so duplicates are expected, not exceptional, and a repeat (or a stale
    /// copy that arrives after the point already moved past it) is a no-op
    /// rather than a rewind. See `StreamReceiver::on_reset`.
    Reset { stream_id: u8, new_offset: u32 },
    /// A check that a road to the peer works. The receiver answers with
    /// `PathProbeAck` carrying the same token, addressed to where the probe
    /// CAME FROM -- and, unlike every other authenticated frame, must not
    /// migrate the session to that address (see `Connection::on_transport`).
    /// That exemption is the whole reason this is its own frame and not a
    /// flag on `Ping`: probing a backup road must not drag the live traffic
    /// onto it.
    PathProbe { token: u32 },
    /// The reply to `PathProbe`. Its arrival is what turns a road from
    /// "unverified" into "verified", and its round trip is the road's
    /// measured latency.
    PathProbeAck { token: u32 },
    /// The receiver of stream `stream_id` lets its sender write below
    /// `limit` -- an absolute offset's low 32 bits (spec §6). Sent only
    /// between two ends that agreed `stream-credit`: a parser from before it
    /// stops at the unknown type and drops the rest of the datagram.
    Credit { stream_id: u8, limit: u32 },
}

impl StreamFrame {
    /// A road check or its answer: frames that never share a datagram with
    /// any other (spec §4.11) and never move a session (see
    /// `Connection::on_transport`).
    pub fn is_probe(&self) -> bool {
        matches!(
            self,
            StreamFrame::PathProbe { .. } | StreamFrame::PathProbeAck { .. }
        )
    }

    /// Append the encoded frame to the end of `buf`.
    pub fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            StreamFrame::Ack { stream_id, cum_ack } => {
                buf.push(TYPE_ACK);
                buf.push(*stream_id);
                buf.extend_from_slice(&cum_ack.to_be_bytes());
            }
            StreamFrame::Data {
                stream_id,
                offset,
                data,
            } => {
                buf.push(TYPE_DATA);
                buf.push(*stream_id);
                buf.extend_from_slice(&offset.to_be_bytes());
                // Length is bounded by u16; the sender chunks by
                // MAX_SEGMENT_SIZE. A direct call with a huge payload is
                // caught in debug builds so the tail doesn't silently get
                // lost.
                debug_assert!(
                    data.len() <= u16::MAX as usize,
                    "DATA payload exceeds u16::MAX, the tail will be truncated"
                );
                let len = data.len().min(u16::MAX as usize);
                buf.extend_from_slice(&(len as u16).to_be_bytes());
                buf.extend_from_slice(&data[..len]);
            }
            StreamFrame::Ping { token } => {
                buf.push(TYPE_PING);
                buf.extend_from_slice(&token.to_be_bytes());
            }
            StreamFrame::Pong { token } => {
                buf.push(TYPE_PONG);
                buf.extend_from_slice(&token.to_be_bytes());
            }
            StreamFrame::Close { stream_id } => {
                buf.push(TYPE_CLOSE);
                buf.push(*stream_id);
            }
            StreamFrame::SessionAbort { reason } => {
                buf.push(TYPE_SESSION_ABORT);
                buf.push(reason.to_wire());
            }
            StreamFrame::Reset {
                stream_id,
                new_offset,
            } => {
                buf.push(TYPE_RESET);
                buf.push(*stream_id);
                buf.extend_from_slice(&new_offset.to_be_bytes());
            }
            StreamFrame::PathProbe { token } => {
                buf.push(TYPE_PATH_PROBE);
                buf.extend_from_slice(&token.to_be_bytes());
            }
            StreamFrame::PathProbeAck { token } => {
                buf.push(TYPE_PATH_PROBE_ACK);
                buf.extend_from_slice(&token.to_be_bytes());
            }
            StreamFrame::Credit { stream_id, limit } => {
                buf.push(TYPE_CREDIT);
                buf.push(*stream_id);
                buf.extend_from_slice(&limit.to_be_bytes());
            }
        }
    }

    /// Parse all frames in a row out of the payload. A single datagram may
    /// carry several (e.g. an ACK piggybacked onto DATA). The input comes
    /// from the network and is untrusted: a truncated frame or an unknown
    /// type doesn't panic, it just stops parsing -- frames already parsed
    /// are returned.
    pub fn decode_all(bytes: &[u8]) -> Vec<StreamFrame> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                TYPE_ACK => {
                    // type(1) + stream_id(1) + cum_ack(4)
                    if i + 6 > bytes.len() {
                        break;
                    }
                    let stream_id = bytes[i + 1];
                    let cum_ack = u32::from_be_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                    out.push(StreamFrame::Ack { stream_id, cum_ack });
                    i += 6;
                }
                TYPE_DATA => {
                    // type(1) + stream_id(1) + offset(4) + len(2) + payload
                    if i + 8 > bytes.len() {
                        break;
                    }
                    let stream_id = bytes[i + 1];
                    let offset = u32::from_be_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                    let len = u16::from_be_bytes(bytes[i + 6..i + 8].try_into().unwrap()) as usize;
                    if i + 8 + len > bytes.len() {
                        break; // payload not fully received yet
                    }
                    let data = bytes[i + 8..i + 8 + len].to_vec();
                    out.push(StreamFrame::Data {
                        stream_id,
                        offset,
                        data,
                    });
                    i += 8 + len;
                }
                TYPE_PING => {
                    if i + 5 > bytes.len() {
                        break;
                    }
                    let token = u32::from_be_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                    out.push(StreamFrame::Ping { token });
                    i += 5;
                }
                TYPE_PONG => {
                    if i + 5 > bytes.len() {
                        break;
                    }
                    let token = u32::from_be_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                    out.push(StreamFrame::Pong { token });
                    i += 5;
                }
                TYPE_CLOSE => {
                    if i + 2 > bytes.len() {
                        break;
                    }
                    out.push(StreamFrame::Close {
                        stream_id: bytes[i + 1],
                    });
                    i += 2;
                }
                TYPE_SESSION_ABORT => {
                    if i + 2 > bytes.len() {
                        break;
                    }
                    out.push(StreamFrame::SessionAbort {
                        reason: SessionAbortReason::from_wire(bytes[i + 1]),
                    });
                    i += 2;
                }
                TYPE_RESET => {
                    // type(1) + stream_id(1) + new_offset(4)
                    if i + 6 > bytes.len() {
                        break;
                    }
                    let stream_id = bytes[i + 1];
                    let new_offset = u32::from_be_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                    out.push(StreamFrame::Reset {
                        stream_id,
                        new_offset,
                    });
                    i += 6;
                }
                TYPE_PATH_PROBE => {
                    if i + 5 > bytes.len() {
                        break;
                    }
                    let token = u32::from_be_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                    out.push(StreamFrame::PathProbe { token });
                    i += 5;
                }
                TYPE_PATH_PROBE_ACK => {
                    if i + 5 > bytes.len() {
                        break;
                    }
                    let token = u32::from_be_bytes(bytes[i + 1..i + 5].try_into().unwrap());
                    out.push(StreamFrame::PathProbeAck { token });
                    i += 5;
                }
                TYPE_CREDIT => {
                    // type(1) + stream_id(1) + limit(4)
                    if i + 6 > bytes.len() {
                        break;
                    }
                    let stream_id = bytes[i + 1];
                    let limit = u32::from_be_bytes(bytes[i + 2..i + 6].try_into().unwrap());
                    out.push(StreamFrame::Credit { stream_id, limit });
                    i += 6;
                }
                _ => break, // unknown type -- nothing further to parse
            }
        }
        out
    }
}

/// A single sent segment: the stream byte range and the time it was last
/// sent. The actual bytes live in the sender's buffer -- only coordinates
/// and timing live here.
struct Segment {
    /// Absolute offset of the segment's start in the stream: a full one; the
    /// wire carries its low 32 bits.
    start: u64,
    /// Segment length in bytes.
    len: u32,
    /// When the segment was last sent (for the retransmit decision).
    last_sent: Instant,
    /// When it first went out, and whether an ACK for it may time a round
    /// trip from then: not once it has gone out again (Karn's rule), and not
    /// once the connection has forgotten its send times
    /// ([`StreamSender::forget_send_times`]).
    first_sent: Instant,
    timeable: bool,
    /// Taken for lost: its own deadline passed, or (from the congestion
    /// window on) the acknowledgements said so. A lost segment is out of the
    /// network as far as the sender is concerned: it waits for its turn to go
    /// out again and has no deadline of its own meanwhile.
    lost: bool,
    /// Goes out on the next flush whatever the congestion window says: the
    /// oldest segment after a retransmit timeout (RFC 5681 §3.1), or the one
    /// a fast retransmit or a partial ACK names (RFC 6582). Always `lost` too.
    urgent: bool,
    /// Taken for lost by the latest retransmit timeout, and not sent again
    /// since: given back if that timeout turns out spurious
    /// ([`StreamSender::forget_timeout_losses`]). Set only when a timeout
    /// fires ([`StreamSender::settle_timeout_marks`]); an ordinary flush in
    /// between leaves it.
    timed_out: bool,
    /// Taken for lost by the due check of the flush going on now; whether
    /// that was a timeout is settled after it.
    due_now: bool,
}

/// The reliable stream sender. Accumulates unacknowledged bytes, chunks them
/// into DATA frames, and retransmits ones that weren't acknowledged within
/// the RTO.
pub struct StreamSender {
    stream_id: u8,
    /// Absolute offset of the first unacknowledged byte; `buf[0]` sits here.
    base_offset: u64,
    /// Unacknowledged stream bytes, starting at `base_offset`: a ring, so an
    /// acknowledgement drops its bytes from the head without moving the rest
    /// (spec §4.6). Offsets are full `u64` counts; the wire carries their low
    /// 32 bits (spec §4.14).
    buf: VecDeque<u8>,
    /// Absolute offset up to which bytes have been sent at least once.
    sent_up_to: u64,
    /// Sent but not-yet-acknowledged segments (in offset order).
    segments: Vec<Segment>,
    /// Set after a long client absence: the buffer was dropped and further
    /// output is discarded (a repaint on resume replaces it), so we don't hoard
    /// a whole background period.
    desynced: bool,
    /// Whether the connection agreed modular offsets (spec §4.14): a stream
    /// then has no end, and a 32-bit field is read by `expand`.
    wrap: bool,
    /// While `Some(new_offset)`, prepend a `Reset` to every send until the
    /// receiver acks past it -- a reliably delivered stream discontinuity.
    pending_reset: Option<u64>,
    /// When the armed `Reset` was last put on the wire. `None` means it
    /// hasn't gone out yet (send it immediately). Paces re-emission like a
    /// segment retransmit -- only after `rto` has elapsed -- so a burst of
    /// `frames_to_send` calls within one RTT (e.g. several PTY chunks from
    /// one repaint) doesn't produce a duplicate-Reset storm.
    reset_last_sent: Option<Instant>,
    /// Duplicate ACKs in a row (see [`AckEffect::duplicates`]).
    dup_acks: u32,
    /// RFC 6582 §3.2 step 1: no fast retransmit until the base passes this
    /// offset (see [`StreamSender::hold_fast_retransmit`]).
    fast_retransmit_held_to: Option<u64>,
    /// Where this stream had sent up to at the latest retransmit timeout,
    /// while its base is below that: the round trip after the timeout (see
    /// [`StreamSender::acks_timeout_flight`]).
    timeout_flight_end: Option<u64>,
    /// With `stream-credit` (spec §6.2): new bytes go out only below this
    /// full offset. Grows with every `CREDIT` that raises it. `None` without
    /// credits: no limit but `MAX_IN_FLIGHT`.
    credit_limit: Option<u64>,
}

/// One DATA frame a sender put out.
#[derive(Debug)]
pub struct SegmentOut {
    pub frame: StreamFrame,
    /// Payload bytes it carries.
    pub len: usize,
    /// Whether these bytes went out before.
    pub retransmit: bool,
}

/// What one ACK did to a sender.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AckEffect {
    /// Bytes it acknowledged for the first time.
    pub acked: usize,
    /// When it is a duplicate: how many in a row, this one included. 0
    /// otherwise.
    ///
    /// A duplicate ACK (RFC 5681 §2, for this protocol) is one that moves
    /// nothing and so can only come from a DATA that arrived past a hole:
    /// its `cum_ack` equals the base exactly (below it: a stale ACK
    /// overtaken on the way, ignored, and the run goes on); bytes past the
    /// base are in flight; and it is not the answer to an armed `Reset` (it
    /// clears that). A receiver of this build sends an `Ack` only for a DATA
    /// that arrived since its last one, and at once for every DATA past a
    /// hole (spec §4.11), so one DATA past a hole makes at most one
    /// duplicate: the first past a hole may instead carry a point the
    /// receiver held for a ride (in-order DATA it had not acknowledged yet),
    /// which moves the base and is no duplicate -- the second makes the first
    /// duplicate. An older receiver acknowledges every DATA.
    ///
    /// The ACKs our own copies of already-delivered segments draw, and those
    /// of segments the road only reordered, look the same one by one: the
    /// connection holds the fast retransmit where copies are on their way
    /// ([`StreamSender::hold_fast_retransmit`]) and undoes one that turns
    /// out spurious (`CongestionWindow::on_advance`).
    pub duplicates: u32,
}

impl StreamSender {
    /// Create a sender for stream `stream_id`.
    pub fn new(stream_id: u8) -> Self {
        StreamSender {
            stream_id,
            base_offset: 0,
            buf: VecDeque::new(),
            sent_up_to: 0,
            segments: Vec::new(),
            desynced: false,
            wrap: false,
            pending_reset: None,
            reset_last_sent: None,
            dup_acks: 0,
            fast_retransmit_held_to: None,
            timeout_flight_end: None,
            credit_limit: None,
        }
    }

    /// Take what the connection agreed (spec §5.4): modular offsets, and
    /// credits -- with the implicit first limit, a window past where the
    /// stream starts (spec §6.2).
    pub fn set_features(&mut self, features: Features) {
        self.wrap = features.contains(Features::OFFSET_WRAP);
        self.credit_limit = if features.contains(Features::STREAM_CREDIT) {
            Some(
                self.credit_limit
                    .unwrap_or_else(|| ceiling(self.base_offset + STREAM_WINDOW, self.wrap)),
            )
        } else {
            None
        };
    }

    /// The limit this sender holds, if it runs with credits.
    pub fn credit_limit(&self) -> Option<u64> {
        self.credit_limit
    }

    /// Apply a `CREDIT` (spec §6.2): a limit only grows; a lower one is
    /// stale and changes nothing, as does one on a stream without credits.
    /// Returns whether it grew -- room opened, which the connection fills at
    /// once.
    pub fn on_credit(&mut self, limit: u32) -> bool {
        let Some(current) = self.credit_limit else {
            return false;
        };
        let Some(limit) = expand(current, limit, self.wrap) else {
            return false;
        };
        if limit <= current {
            return false;
        }
        self.credit_limit = Some(limit);
        true
    }

    /// Where new bytes stop: the end of the buffer, or the credit limit.
    fn send_end(&self) -> u64 {
        let buf_end = self.base_offset + self.buf.len() as u64;
        self.credit_limit
            .map_or(buf_end, |limit| buf_end.min(limit))
    }

    /// Remaining bounded admission before allocating a new byte. Peer credit
    /// is measured from queued end, not the already transmitted frontier.
    pub(crate) fn write_room(&self, max_unacked: usize) -> usize {
        if self.desynced {
            return 0;
        }
        let end = self.queued_total();
        let credit = self
            .credit_limit
            .map_or(u64::MAX, |limit| limit.saturating_sub(end));
        let offset = self.offset_room();
        max_unacked
            .saturating_sub(self.buf.len())
            .min(usize::try_from(credit.min(offset)).unwrap_or(usize::MAX))
    }

    pub(crate) fn offset_room(&self) -> u64 {
        let limit = if self.wrap {
            FULL_OFFSET_MAX
        } else {
            u64::from(OFFSET_LIMIT)
        };
        limit.saturating_sub(self.queued_total())
    }

    /// Queue bytes for reliable sending. Refused whole, and nothing queued,
    /// when, without `offset-wrap`, they would reach past [`OFFSET_LIMIT`];
    /// bytes already queued stay.
    pub fn push(&mut self, data: &[u8]) -> Result<(), OffsetSpaceExhausted> {
        if self.desynced {
            return Ok(()); // dropping output during a long absence; a repaint follows on resume
        }
        let end = self.base_offset + self.buf.len() as u64 + data.len() as u64;
        if !self.wrap && end > u64::from(OFFSET_LIMIT) {
            return Err(OffsetSpaceExhausted);
        }
        self.buf.extend(data);
        Ok(())
    }

    /// Test-only: a sender whose stream starts at `offset` instead of 0, to
    /// reach the edge of the offset space without writing 4 GiB.
    #[cfg(any(test, feature = "testnet"))]
    pub fn starting_at(stream_id: u8, offset: u32) -> Self {
        let mut s = StreamSender::new(stream_id);
        s.base_offset = u64::from(offset);
        s.sent_up_to = u64::from(offset);
        s
    }

    /// How many bytes have been sent but not yet acknowledged.
    pub fn bytes_in_flight(&self) -> usize {
        (self.sent_up_to - self.base_offset) as usize
    }

    /// Bytes queued and not yet acknowledged, sent or not.
    pub fn unacked_len(&self) -> usize {
        self.buf.len()
    }

    /// Every byte ever queued on this stream: the acknowledged ones plus
    /// those still waiting.
    pub fn queued_total(&self) -> u64 {
        self.base_offset + self.buf.len() as u64
    }

    /// Test-only: where the `i`-th unacknowledged byte lives in memory. An
    /// acknowledgement that moves the bytes behind it changes the answer.
    #[cfg(test)]
    fn byte_address_for_test(&self, i: usize) -> *const u8 {
        self.buf.get(i).expect("a byte that is buffered") as *const u8
    }

    /// Copy `len` unacknowledged bytes starting `from` bytes past the base
    /// into a frame's own buffer (the copy was there with the `Vec` too). The
    /// ring may hold them in two pieces.
    fn copy_out(&self, from: usize, len: usize) -> Vec<u8> {
        let (head, tail) = self.buf.as_slices();
        let end = from + len;
        let mut out = Vec::with_capacity(len);
        if from < head.len() {
            out.extend_from_slice(&head[from..end.min(head.len())]);
        }
        if end > head.len() {
            let start = from.saturating_sub(head.len());
            out.extend_from_slice(&tail[start..end - head.len()]);
        }
        out
    }

    /// Whether this sender is in the drop-output state after a long absence.
    pub fn is_desynced(&self) -> bool {
        self.desynced
    }

    /// Drop the unacknowledged backlog and stop buffering: base jumps to the
    /// current write head, buffer and segments clear. Called once when the client
    /// has been absent past `RESYNC_AFTER`.
    ///
    /// Also clears any still-armed `pending_reset`: if the client resynced
    /// (arming a `Reset` at the OLD base) and then went absent again before
    /// that `Reset` was acked, a stale `pending_reset` would keep emitting a
    /// `Reset` at an offset that no longer matches the new base. The next
    /// `begin_resync` re-arms it at the current (new) base.
    pub fn mark_desynced(&mut self) {
        self.pending_reset = None;
        self.reset_last_sent = None;
        let head = self.base_offset + self.buf.len() as u64;
        // Spec §6.5 (amended 2026-09-28, slice 4 task 3 fix round 1, then
        // fix round 2): the receiver's `on_reset` always keeps a live limit
        // at or above `head` (the `Reset`'s point `q`) -- everything it
        // announced below `q` is dropped, and `q` itself takes the front
        // unless data past `q` already arrived there (fix round 2: such
        // data is itself proof of a limit above `q`, see `on_reset`). A
        // plain `+= head - sent_up_to` shift can land the sender strictly
        // between two limits the receiver actually holds, where a single
        // lost post-Reset CREDIT stalls the stream until the next desync.
        // `max` keeps the limit here exactly among the receiver's
        // candidates; `ceiling` keeps it from passing `OFFSET_LIMIT` without
        // `offset-wrap`, where such a stream stops anyway.
        if let Some(limit) = self.credit_limit.as_mut() {
            *limit = ceiling((*limit).max(head), self.wrap);
        }
        // Released, not just emptied: the backlog of a long absence can be
        // megabytes, and nothing is buffered again until the resync.
        self.buf = VecDeque::new();
        self.segments.clear();
        self.base_offset = head;
        self.sent_up_to = head;
        self.dup_acks = 0;
        self.fast_retransmit_held_to = None;
        self.timeout_flight_end = None;
        self.desynced = true;
    }

    /// Leave the drop state on resume and arm a reliable Reset: the receiver will
    /// be told to jump to the current base. Returns that `new_offset`.
    pub fn begin_resync(&mut self) -> u64 {
        self.desynced = false;
        self.pending_reset = Some(self.base_offset);
        self.reset_last_sent = None; // a freshly armed Reset always goes out immediately
        self.base_offset
    }

    /// The armed `Reset`, when it is due: immediately the first time, then
    /// only once `rto` has passed since it last went out.
    pub fn take_due_reset(&mut self, now: Instant, rto: Duration) -> Option<StreamFrame> {
        let new_offset = self.pending_reset?;
        let due = match self.reset_last_sent {
            None => true,
            Some(last) => now.saturating_duration_since(last) >= rto,
        };
        if !due {
            return None;
        }
        self.reset_last_sent = Some(now);
        Some(StreamFrame::Reset {
            stream_id: self.stream_id,
            // The wire's low 32 bits (spec §4.14).
            new_offset: new_offset as u32,
        })
    }

    /// Take every segment whose own deadline (`last_sent + rto`) has passed
    /// for lost. Returns whether this stream's OLDEST unacknowledged segment
    /// was among those newly taken -- the retransmit timer expiring (RFC 6298
    /// §5.5); the segments behind it only follow it.
    pub fn mark_due_lost(&mut self, now: Instant, rto: Duration) -> bool {
        let base = self.base_offset;
        let mut oldest = false;
        for seg in &mut self.segments {
            if !seg.lost && now.saturating_duration_since(seg.last_sent) >= rto {
                seg.lost = true;
                seg.due_now = true;
                oldest |= seg.start == base;
            }
        }
        oldest
    }

    /// After a flush's due check ([`StreamSender::mark_due_lost`]) on every
    /// stream: if the retransmit timer expired, what the check took for lost
    /// is that timeout's -- in place of an earlier timeout's marks, which
    /// stood; if it did not, the check's losses are plain ones, and the
    /// latest timeout's marks stay as they were.
    pub fn settle_timeout_marks(&mut self, timeout: bool) {
        for seg in &mut self.segments {
            if timeout {
                seg.timed_out = seg.due_now;
            }
            seg.due_now = false;
        }
    }

    /// The latest retransmit timeout was spurious (see
    /// `CongestionWindow::undo_timeout_if_spurious`): what it took for lost
    /// and has not sent again is in the network after all. Not lost any
    /// more, and timed from `now` -- its deadline had passed already, and
    /// would read as the next timeout at once.
    pub fn forget_timeout_losses(&mut self, now: Instant) {
        self.timeout_flight_end = None;
        for seg in &mut self.segments {
            if seg.timed_out && seg.lost && !seg.urgent {
                seg.lost = false;
                seg.last_sent = seg.last_sent.max(now);
            }
            seg.timed_out = false;
        }
    }

    /// The next DATA frame this stream would put out: its oldest lost segment
    /// again, else new bytes -- at most `MAX_SEGMENT_SIZE`, within the
    /// `MAX_IN_FLIGHT` window. `None` when there is neither.
    pub fn next_segment(&mut self, now: Instant) -> Option<SegmentOut> {
        if let Some(i) = self.segments.iter().position(|s| s.lost) {
            return Some(self.resend(i, now));
        }
        self.send_new(now)
    }

    /// Take the oldest unacknowledged segment for lost and have it go out on
    /// the next flush whatever the window says. `false` if nothing is in
    /// flight.
    pub fn mark_oldest_urgent(&mut self) -> bool {
        match self.segments.first_mut() {
            Some(seg) => {
                seg.lost = true;
                seg.urgent = true;
                true
            }
            None => false,
        }
    }

    /// Restart the retransmit timer of everything still in the network, on
    /// every repair of a fast recovery: RFC 6582's "Slow-but-Steady" variant
    /// (§4). The RFC's own step 4 restarts it on the first partial ACK only
    /// ("Impatient"), so that a recovery with many holes ends in a timeout
    /// and a go-back; here a timeout marks everything due for lost and
    /// resends it, much of it already delivered, so each hole is repaired one
    /// round trip after the last instead and the segments behind it must not
    /// expire meanwhile and collapse the window to one segment.
    pub fn restart_timers(&mut self, now: Instant) {
        for seg in &mut self.segments {
            if !seg.lost {
                seg.last_sent = seg.last_sent.max(now);
            }
        }
    }

    /// Take everything in flight for lost, with no retransmit timeout: after
    /// a move, a rebind or a wake the congestion window starts afresh, and
    /// what went out before is resent under it instead of expiring on the
    /// next flush -- which would read as a timeout and undo the restart.
    pub fn take_in_flight_for_lost(&mut self) {
        for seg in &mut self.segments {
            seg.lost = true;
        }
        self.hold_fast_retransmit();
        // A restart is not a timeout: the window starts afresh, and so does
        // what its ACKs count for.
        self.timeout_flight_end = None;
    }

    /// The retransmit timer expired (on this stream or another): what this
    /// stream has in flight now is the timeout's flight, and the ACKs that
    /// acknowledge any of it are the round trip after the timeout (see
    /// [`StreamSender::acks_timeout_flight`]). A later timeout moves the
    /// point on.
    pub fn note_timeout_flight(&mut self) {
        self.timeout_flight_end = (self.sent_up_to > self.base_offset).then_some(self.sent_up_to);
    }

    /// Whether the next ACK that moves the base acknowledges some of what
    /// was in flight at the latest retransmit timeout: the base is still
    /// below where the stream had sent up to then. Asked before the ACK is
    /// applied -- the ACK that reaches the point is the one that covers
    /// what the receiver held past the hole. Such an ACK counts for one
    /// segment of slow start at most (RFC 3465 §2.3, see
    /// `CongestionWindow::on_advance`). An undone timeout, a restart and a
    /// desync forget the point.
    pub fn acks_timeout_flight(&self) -> bool {
        self.timeout_flight_end.is_some()
    }

    /// Hold this stream's fast retransmit until an ACK passes everything it
    /// has sent so far (RFC 6582 §3.2 step 1, "recover"). After a retransmit
    /// timeout or a restart (the end of a recovery holds to where it began:
    /// [`StreamSender::hold_fast_retransmit_to`]), copies of segments the peer
    /// may already have are on their way, each drawing an ACK of the base that
    /// looks like a duplicate; three of them must not start a recovery for
    /// a loss that did not happen. Also with nothing in flight past the
    /// base: those ACKs are of the base, and new data will be behind them.
    pub fn hold_fast_retransmit(&mut self) {
        self.fast_retransmit_held_to = Some(self.sent_up_to);
    }

    /// The same, to `offset`: at the end of a recovery, to where it began
    /// (RFC 6582's `recover`) -- its repairs are all below that. Nothing is
    /// held once the base is past it.
    pub fn hold_fast_retransmit_to(&mut self, offset: u64) {
        if self.base_offset <= offset {
            self.fast_retransmit_held_to = Some(offset);
        }
    }

    /// Whether duplicates may set off a fast retransmit on this stream now
    /// (see [`StreamSender::hold_fast_retransmit`]).
    pub fn may_fast_retransmit(&self) -> bool {
        self.fast_retransmit_held_to.is_none()
    }

    /// The next urgent retransmit (see [`StreamSender::mark_oldest_urgent`]).
    pub fn next_urgent(&mut self, now: Instant) -> Option<SegmentOut> {
        let i = self.segments.iter().position(|s| s.urgent)?;
        Some(self.resend(i, now))
    }

    pub fn has_urgent(&self) -> bool {
        self.segments.iter().any(|s| s.urgent)
    }

    /// Everything below this offset has gone out at least once.
    pub fn sent_up_to(&self) -> u64 {
        self.sent_up_to
    }

    /// The first unacknowledged offset.
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    fn resend(&mut self, i: usize, now: Instant) -> SegmentOut {
        let (start, len) = {
            let seg = &mut self.segments[i];
            seg.lost = false;
            seg.urgent = false;
            seg.timed_out = false;
            seg.last_sent = now;
            seg.timeable = false; // Karn: its ACK may answer either copy
            (seg.start, seg.len as usize)
        };
        SegmentOut {
            frame: StreamFrame::Data {
                stream_id: self.stream_id,
                offset: start as u32,
                data: self.copy_out((start - self.base_offset) as usize, len),
            },
            len,
            retransmit: true,
        }
    }

    fn send_new(&mut self, now: Instant) -> Option<SegmentOut> {
        let base = self.base_offset;
        let end = self.send_end();
        let in_flight = (self.sent_up_to - base) as usize;
        if self.sent_up_to >= end || in_flight >= MAX_IN_FLIGHT {
            return None;
        }
        let len = ((end - self.sent_up_to) as usize)
            .min(MAX_SEGMENT_SIZE)
            .min(MAX_IN_FLIGHT - in_flight);
        let offset = self.sent_up_to;
        let data = self.copy_out((offset - base) as usize, len);
        self.segments.push(Segment {
            start: offset,
            len: len as u32,
            last_sent: now,
            first_sent: now,
            timeable: true,
            lost: false,
            urgent: false,
            timed_out: false,
            due_now: false,
        });
        self.sent_up_to += len as u64;
        Some(SegmentOut {
            frame: StreamFrame::Data {
                stream_id: self.stream_id,
                offset: offset as u32,
                data,
            },
            len,
            retransmit: false,
        })
    }

    /// Whether `next_segment` has something: a lost segment, or unsent bytes
    /// with room in the `MAX_IN_FLIGHT` window.
    pub fn has_sendable(&self) -> bool {
        self.segments.iter().any(|s| s.lost)
            || (self.sent_up_to < self.send_end() && self.bytes_in_flight() < MAX_IN_FLIGHT)
    }

    /// Whether data waits to go out -- a segment taken for lost, or bytes
    /// queued past what was sent -- whatever holds it back: the congestion
    /// window, the bulk budget or this stream's own `MAX_IN_FLIGHT`. Bytes
    /// held back by the credit limit do not count: the reader sets their
    /// pace, not the network.
    pub fn has_waiting(&self) -> bool {
        self.sent_up_to < self.send_end() || self.segments.iter().any(|s| s.lost)
    }

    /// Whether an armed `Reset` has not gone out yet.
    pub fn has_unsent_reset(&self) -> bool {
        self.pending_reset.is_some() && self.reset_last_sent.is_none()
    }

    /// Bytes sent and neither acknowledged nor taken for lost: what this
    /// stream has in the network.
    pub fn pipe(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| !s.lost)
            .map(|s| s.len as usize)
            .sum()
    }

    /// Frames to send at time `now`: first a still-armed `Reset` (paced like a
    /// retransmit -- sent immediately the first time, then only again once
    /// `rto` has elapsed since it last went out), then retransmits of segments
    /// last sent no later than `now - rto`, then still-unsent bytes within the
    /// `MAX_IN_FLIGHT` window.
    pub fn frames_to_send(&mut self, now: Instant, rto: Duration) -> Vec<StreamFrame> {
        let mut frames: Vec<StreamFrame> = self.take_due_reset(now, rto).into_iter().collect();
        self.mark_due_lost(now, rto);
        while let Some(seg) = self.next_segment(now) {
            frames.push(seg.frame);
        }
        frames
    }

    /// When the next retransmit of this stream falls due: the earliest
    /// `last_sent + rto` among the unacknowledged segments, and of an armed
    /// `Reset` that has already gone out. `None` when nothing waits for an
    /// answer. At most `MAX_IN_FLIGHT / MAX_SEGMENT_SIZE` (256) segments, so
    /// the scan is cheap. A freshly armed `Reset` that has not gone out yet
    /// has no deadline here: whoever arms one flushes it in the same call.
    /// A segment taken for lost has none: it goes out when the window lets
    /// it (see [`StreamSender::next_segment`]).
    pub fn retransmit_deadline(&self, rto: Duration) -> Option<Instant> {
        let reset = self
            .pending_reset
            .and(self.reset_last_sent)
            .map(|sent| sent + rto);
        self.segments
            .iter()
            .filter(|s| !s.lost)
            .map(|s| s.last_sent + rto)
            .chain(reset)
            .min()
    }

    /// The send an ACK up to `cum_ack` times, per Karn's rule (RFC 6298 §3):
    /// the first send of the newest segment the ACK newly covers whole, and
    /// only when none of the segments it newly covers, whole or in part, was
    /// ever retransmitted -- after a hole is filled the cumulative ACK jumps
    /// over segments that arrived long before, and its timing belongs to the
    /// retransmit -- or had its send time forgotten
    /// ([`StreamSender::forget_send_times`]). `None` when it covers no whole segment it had not covered
    /// before. Ask before [`StreamSender::on_ack`] applies the same ACK.
    ///
    /// The sample includes however long the peer held the ACK back: a
    /// delayed ACK makes the round trip read a little longer, the safe side
    /// for a retransmit timer.
    pub fn ack_timed_from(&self, cum_ack: u32) -> Option<Instant> {
        let cum = expand(self.base_offset, cum_ack, self.wrap)?.min(self.sent_up_to);
        let mut newest = None;
        for seg in self.segments.iter().take_while(|s| s.start < cum) {
            if !seg.timeable {
                return None;
            }
            if seg.start + u64::from(seg.len) <= cum {
                newest = Some(seg.first_sent);
            }
        }
        newest
    }

    /// Let no ACK for what is in flight now time a round trip: after a
    /// freeze of this thread, or a move onto another road, the time since
    /// these segments went out measures the freeze or the old road, not the
    /// road ahead. The segment twin of forgetting the outstanding PINGs.
    pub fn forget_send_times(&mut self) {
        for seg in &mut self.segments {
            seg.timeable = false;
        }
    }

    /// Apply a cumulative acknowledgment (see [`StreamSender::on_ack`]) and
    /// say what it did: how many bytes it newly acknowledged, or -- when it
    /// moved nothing while bytes are in flight -- how many duplicates in a
    /// row it makes (the fast-retransmit signal, RFC 5681 §3.2).
    pub fn on_ack_counting(&mut self, cum_ack: u32) -> AckEffect {
        // The field is the low 32 bits of an offset near the base (spec
        // §4.14); one that names no offset at all is noise.
        let Some(full) = expand(self.base_offset, cum_ack, self.wrap) else {
            return AckEffect::default();
        };
        let mut cleared_reset = false;
        if let Some(new_offset) = self.pending_reset {
            if full >= new_offset {
                self.pending_reset = None;
                self.reset_last_sent = None;
                cleared_reset = true;
            }
        }
        // Clamp to what was actually sent: only what went out on the wire
        // can be acknowledged. An ACK for bytes that are in the buffer but
        // not yet sent is ignored, otherwise the bytes would be cut out of
        // the buffer and never go out -- a silent, permanent data loss.
        let cum = full.min(self.sent_up_to);
        if cum <= self.base_offset {
            if full == self.base_offset && self.sent_up_to > self.base_offset && !cleared_reset {
                self.dup_acks += 1;
                return AckEffect {
                    acked: 0,
                    duplicates: self.dup_acks,
                };
            }
            return AckEffect::default();
        }
        let advance = (cum - self.base_offset) as usize;
        // Drops the head of the ring; the bytes behind it stay where they are.
        self.buf.drain(..advance);
        self.give_back_room();
        self.base_offset = cum;
        self.dup_acks = 0;
        if self.fast_retransmit_held_to.is_some_and(|to| cum > to) {
            self.fast_retransmit_held_to = None;
        }
        if self.timeout_flight_end.is_some_and(|end| cum >= end) {
            self.timeout_flight_end = None;
        }
        // Trim/drop segments that are wholly or partially acknowledged.
        self.segments.retain_mut(|s| {
            let seg_end = s.start + u64::from(s.len);
            if seg_end <= cum {
                return false; // the whole segment is acknowledged
            }
            if s.start < cum {
                s.len = (seg_end - cum) as u32; // trim the acknowledged head
                s.start = cum;
            }
            true
        });
        AckEffect {
            acked: advance,
            duplicates: 0,
        }
    }

    /// Hand back the room of a ring that has drained to a quarter of it, down
    /// to twice what it holds and never below [`RING_KEEP`]. Moves what is
    /// left once: the halving between the trigger and the target means the
    /// ring was acknowledged down by at least as many bytes as the move
    /// copies, so an acknowledgement's cost stays independent of the backlog
    /// on the average.
    fn give_back_room(&mut self) {
        let room = self.buf.capacity();
        if room > RING_KEEP && self.buf.len() <= room / 4 {
            self.buf.shrink_to((self.buf.len() * 2).max(RING_KEEP));
        }
    }

    /// Apply a cumulative acknowledgment: all stream bytes up to `cum_ack`
    /// have been delivered. Advances the base forward, dropping what's
    /// acknowledged. A stale ack (`cum_ack` no greater than the base) or an
    /// acknowledgment of bytes not yet even queued in the buffer is ignored;
    /// the base never moves backward. Returns whether the base moved -- room
    /// opened in the window, which the connection fills at once (ACK
    /// clocking, spec §4.2).
    pub fn on_ack(&mut self, cum_ack: u32) -> bool {
        self.on_ack_counting(cum_ack).acked > 0
    }
}

/// The reliable stream receiver. Buffers out-of-order segments and delivers
/// bytes strictly in order, as soon as a contiguous run from `next_offset`
/// forms.
pub struct StreamReceiver {
    stream_id: u8,
    /// Absolute offset of the next expected byte (the cumulative point).
    next_offset: u64,
    /// Out-of-order segments: offset -> bytes. Each key is unique; on
    /// collision the longer chunk is kept.
    buffered: BTreeMap<u64, Vec<u8>>,
    /// What `buffered` costs: its bytes plus [`CHUNK_COST`] a chunk.
    buffered_cost: usize,
    /// Whether the connection agreed modular offsets (spec §4.14): a 32-bit
    /// field is read by `expand`.
    wrap: bool,
    /// The first byte its consumer has not taken (spec §4.10.1); never past
    /// `next_offset`.
    consumed: u64,
    /// The end of the furthest DATA received within the limit: its sender
    /// has written at least this far.
    highest_end: u64,
    /// With `stream-credit`: what the receiver keeps about its sender's
    /// limit (spec §6).
    credit: Option<Credit>,
}

/// What a receiver keeps about its sender's limit, with `stream-credit`
/// (spec §6).
struct Credit {
    /// The limits announced -- the first implicitly (spec §6.2) -- that the
    /// sender may still hold, oldest first: every one no data has gone past
    /// yet. It holds one of them; the oldest is where it may be stopped.
    /// Never empty: the newest is the limit in force, and a limit only grows.
    /// At most [`CREDIT_ANNOUNCED_MAX`] entries from growth
    /// ([`StreamReceiver::credit_due`]), plus one more a `Reset`'s `q` may
    /// add ([`StreamReceiver::on_reset`]) past that cap.
    announced: VecDeque<u64>,
    /// The older limit the repeats of the newest are for (spec §6.4): a
    /// sender found stopped at another one gets its own.
    repeating_for: Option<u64>,
    /// Repeats left.
    resends_left: u32,
    /// When the newest limit was last sent, by whatever sent it -- an
    /// announcement ([`StreamReceiver::credit_due`]), an explicit repeat
    /// ([`StreamReceiver::credit_resend`]) or a PONG copy
    /// ([`StreamReceiver::credit_for_pong`]). The next repeat is always one
    /// `rto` after this, whichever of the three last set it (fix round 4,
    /// spec §6.4 amended).
    sent_at: Option<Instant>,
}

impl Credit {
    fn newest(&self) -> u64 {
        *self
            .announced
            .back()
            .expect("a stream's credit always has a limit")
    }

    fn oldest(&self) -> u64 {
        *self
            .announced
            .front()
            .expect("a stream's credit always has a limit")
    }
}

impl StreamReceiver {
    /// Create a receiver for stream `stream_id`.
    pub fn new(stream_id: u8) -> Self {
        StreamReceiver {
            stream_id,
            next_offset: 0,
            buffered: BTreeMap::new(),
            buffered_cost: 0,
            wrap: false,
            consumed: 0,
            highest_end: 0,
            credit: None,
        }
    }

    /// Read the wire the way the connection agreed (spec §4.14), and keep a
    /// credit window if it agreed `stream-credit` (spec §6.2) -- the first
    /// limit implicitly a window past what the consumer has taken.
    pub fn set_features(&mut self, features: Features) {
        self.wrap = features.contains(Features::OFFSET_WRAP);
        if !features.contains(Features::STREAM_CREDIT) {
            self.credit = None;
        } else if self.credit.is_none() {
            let first = self.limit_now();
            self.credit = Some(Credit {
                announced: VecDeque::from([first]),
                repeating_for: None,
                resends_left: 0,
                sent_at: None,
            });
        }
    }

    /// The cumulative point as a full offset.
    pub fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Where the offset space ends for this receiver: the end of the 32-bit
    /// space without `offset-wrap`, [`FULL_OFFSET_MAX`] with it.
    fn offset_end(&self) -> u64 {
        if self.wrap {
            FULL_OFFSET_MAX
        } else {
            u64::from(u32::MAX)
        }
    }

    /// Test-only: a receiver expecting its stream to start at `offset`.
    #[cfg(any(test, feature = "testnet"))]
    pub fn starting_at(stream_id: u8, offset: u32) -> Self {
        let mut r = StreamReceiver::new(stream_id);
        r.next_offset = u64::from(offset);
        r.consumed = u64::from(offset);
        r.highest_end = u64::from(offset);
        r
    }

    /// The window this receiver keeps: the credit window with
    /// `stream-credit`, else the one every sender without it stays in.
    fn window(&self) -> u64 {
        if self.credit.is_some() {
            STREAM_WINDOW
        } else {
            LEGACY_RECEIVE_WINDOW
        }
    }

    /// Where DATA stops being kept (spec §4.16, §6.2): the newest limit
    /// announced, or a window past the cumulative point for a sender
    /// without credits.
    fn accept_limit(&self) -> u64 {
        match &self.credit {
            Some(credit) => credit.newest(),
            None => self.next_offset + LEGACY_RECEIVE_WINDOW,
        }
    }

    /// What this receiver may keep out of order, by cost: one window of
    /// full segments, each its bytes plus [`CHUNK_COST`] (`window +
    /// window / 8`).
    pub fn cost_cap(&self) -> usize {
        let window = self.window() as usize;
        window + window / MAX_SEGMENT_SIZE * CHUNK_COST
    }

    /// What it keeps out of order now, by cost.
    pub fn buffered_cost(&self) -> usize {
        self.buffered_cost
    }

    /// Accept a data segment with no bound but this stream's own (see
    /// [`StreamReceiver::on_data_within`]).
    pub fn on_data(&mut self, offset: u32, data: Vec<u8>) -> Vec<u8> {
        self.on_data_within(offset, data, usize::MAX)
    }

    /// Accept a data segment. Returns freshly delivered in-order bytes (may
    /// be empty if the segment is out of order or entirely a repeat).
    /// Repeats and partial overlaps don't break assembly and don't move the
    /// point backward. What lies at or past [`StreamReceiver::accept_limit`]
    /// is neither kept nor acknowledged, and an out-of-order chunk is kept
    /// only if its cost fits this stream's `cost_cap` and `room`, what the
    /// connection has left (spec §4.16). In-order bytes are delivered
    /// whatever the buffer holds.
    pub fn on_data_within(&mut self, offset: u32, data: Vec<u8>, room: usize) -> Vec<u8> {
        // Whatever this segment turns out to be, a chunk a `Reset` left at
        // the point drains with it (see `drain`).
        let Some(start) = expand(self.next_offset, offset, self.wrap) else {
            return self.drain();
        };
        let end = start + data.len() as u64;
        // Past the end of the offset space: without `offset-wrap` no sender
        // following this protocol writes there (it stops at `OFFSET_LIMIT`),
        // with it no sender gets there. Dropped, not acknowledged.
        if end > self.offset_end() {
            return self.drain();
        }
        // Only what lies between the point and the window's edge is new and
        // may be kept: below the point it was delivered, past the edge no
        // sender that follows this protocol writes.
        let from = start.max(self.next_offset);
        let to = end.min(self.accept_limit());
        if from >= to {
            return self.drain();
        }
        self.note_received(to);
        let chunk = if from == start && to == end {
            data
        } else {
            data[(from - start) as usize..(to - start) as usize].to_vec()
        };
        if from == self.next_offset {
            self.next_offset = to;
            let mut out = chunk;
            out.extend(self.drain());
            return out;
        }
        self.buffer_segment(from, chunk, room);
        self.drain()
    }

    /// The cumulative acknowledgment point: offset of the next expected
    /// byte -- the cumulative point's low 32 bits, as the wire carries it.
    pub fn ack(&self) -> u32 {
        self.next_offset as u32
    }

    /// The sender restarted the stream after dropping its backlog: discard any
    /// out-of-order buffer and jump the cumulative point to `new_offset` --
    /// but ONLY if that actually moves the point forward. Returns whether it did.
    ///
    /// The sender re-arms the same `Reset` on every flush until it is acked
    /// (see `StreamSender::frames_to_send`), so duplicates are the norm, not
    /// the exception -- several can arrive after we've already advanced past
    /// `new_offset` on the strength of an earlier copy (data the sender has
    /// since dropped from its own buffer on our ack). Rewinding on such a
    /// stale/duplicate Reset would un-deliver bytes the sender can no longer
    /// resend, stalling the stream forever. A `new_offset` at or behind the
    /// current point is therefore a no-op: `buffered` and `next_offset` are
    /// left untouched. So is one past the end of the offset space, which no
    /// sender reaches (spec §4.14).
    ///
    /// How far a `Reset` jumps is not bounded otherwise: a sender that drops
    /// its tail again before its `Reset` is acknowledged forgets that `Reset`
    /// and names its new head, so the tails of resyncs whose `Reset`s were
    /// lost add up -- refusing such a jump would stall the stream for good.
    pub fn on_reset(&mut self, new_offset: u32) -> bool {
        let Some(new_offset) = expand(self.next_offset, new_offset, self.wrap) else {
            return false;
        };
        if new_offset <= self.next_offset || new_offset > self.offset_end() {
            return false;
        }
        // Spec §6.2 (fix round 2): with credits and without `offset-wrap`,
        // a `Reset` past `OFFSET_LIMIT` is refused, not just past `offset_end`
        // (`u32::MAX` there without credits): a limit announced at `q` past
        // `OFFSET_LIMIT` would break the ceiling every credited limit keeps.
        // A stream without credits stays bound by `offset_end` alone, as
        // before -- this is `push`'s own ceiling on the sender's side, mirrored
        // here only for a receiver that tracks a limit at all.
        if self.credit.is_some() && !self.wrap && new_offset > u64::from(OFFSET_LIMIT) {
            return false;
        }
        // Segments fully or partially below the new point carry nothing the
        // sender still has: split off what is at or past it, and give back
        // what the rest cost. A split, not a scan -- a `Reset` costs about
        // the chunks it drops, not every chunk held.
        let kept = self.buffered.split_off(&new_offset);
        for (_, chunk) in std::mem::replace(&mut self.buffered, kept) {
            self.buffered_cost -= chunk.len() + CHUNK_COST;
        }
        // The bytes skipped will never reach the consumer: taken (spec §6.5).
        self.consumed += new_offset - self.next_offset;
        self.next_offset = new_offset;
        self.note_received(new_offset);
        // Spec §6.5 (amended 2026-09-28, slice 4 task 3 fix round 1, then
        // fix round 2): after `mark_desynced`, the sender's own limit is
        // `max(old limit, q)` -- so every limit this receiver announced
        // below `q` is now stale, and `q` itself takes the front, UNLESS
        // data past `q` has already arrived (`self.highest_end`, just
        // updated by `note_received` above, is past `new_offset`): a
        // repaint that overtook the Reset's own first, lost copy (a
        // `Reset` and the repaint behind it can travel in different
        // datagrams) proves the sender's limit is already above `q`, and
        // pushing `q` there anyway would report "possibly stopped"
        // (`stopped_at`) forever -- data past the repaint is the only
        // thing that pops a `q` sitting where nothing more is coming
        // (fix round 2, re-review new issue 1). This keeps the oldest live
        // limit (`stopped_at`, spec §6.4) an exact match for what the
        // sender may actually hold: a single lost post-Reset CREDIT still
        // gets repeated instead of stalling the stream, and no idle screen
        // draws CREDIT chatter forever.
        let data_past_q = self.highest_end > new_offset;
        if let Some(credit) = self.credit.as_mut() {
            while matches!(credit.announced.front(), Some(&f) if f < new_offset) {
                credit.announced.pop_front();
            }
            if !data_past_q && credit.announced.front() != Some(&new_offset) {
                credit.announced.push_front(new_offset);
            }
        }
        true
    }

    /// Keep an out-of-order chunk -- the longer one where two start at the
    /// same offset -- if what it costs fits this stream's `cost_cap` and the
    /// connection's `room`. One that does not fit is dropped unacknowledged:
    /// its sender sends it again.
    fn buffer_segment(&mut self, offset: u64, data: Vec<u8>, room: usize) {
        let old = self.buffered.get(&offset).map_or(0, Vec::len);
        if old >= data.len() {
            return; // the chunk held there is at least as long
        }
        let old_cost = if old > 0 { old + CHUNK_COST } else { 0 };
        let grows = data.len() + CHUNK_COST - old_cost;
        if self.buffered_cost + grows > self.cost_cap() || grows > room {
            return;
        }
        self.buffered_cost += grows;
        self.buffered.insert(offset, data);
    }

    /// Drain the contiguous run starting at next_offset, returning the fresh
    /// bytes. Every DATA ends here, whatever it carried: a chunk a `Reset`
    /// landed on sits at the point itself and goes out with the next DATA.
    fn drain(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some((&off, _)) = self.buffered.iter().next() {
            if off > self.next_offset {
                break; // a gap remains -- nothing further to drain
            }
            let seg = self.buffered.remove(&off).expect("just seen");
            self.buffered_cost -= seg.len() + CHUNK_COST;
            let seg_end = off + seg.len() as u64;
            if seg_end <= self.next_offset {
                continue; // the segment was already delivered entirely -- discard
            }
            let skip = (self.next_offset - off) as usize;
            out.extend_from_slice(&seg[skip..]);
            self.next_offset = seg_end;
        }
        out
    }

    /// The consumer took `n` more bytes (spec §4.10.1); never past what was
    /// delivered.
    pub fn on_consumed(&mut self, n: u64) {
        self.consumed = self.consumed.saturating_add(n).min(self.next_offset);
    }

    /// Delivered and not taken yet.
    pub fn unconsumed(&self) -> u64 {
        self.next_offset - self.consumed
    }

    /// The newest limit announced, with credits.
    pub fn credit_limit(&self) -> Option<u64> {
        self.credit.as_ref().map(Credit::newest)
    }

    /// The limit the consumer allows now (spec §6.2): a window past what it
    /// took.
    fn limit_now(&self) -> u64 {
        ceiling(self.consumed + STREAM_WINDOW, self.wrap)
    }

    /// Data up to `end` arrived within the limit: its sender has written that
    /// far, so it holds a limit past every one announced below `end`.
    fn note_received(&mut self, end: u64) {
        if end <= self.highest_end {
            return;
        }
        self.highest_end = end;
        if let Some(credit) = self.credit.as_mut() {
            while credit.announced.len() > 1 && credit.oldest() < end {
                credit.announced.pop_front();
            }
        }
    }

    /// The limit the sender may be stopped at (spec §6.4, as corrected by
    /// fix round 4): the oldest it may still hold, exactly when the data
    /// received reaches it. A sender stopped at its limit writes up to it
    /// exactly -- `send_new` cuts its last segment there -- so equality is
    /// the only honest signal. The earlier "within a segment" rule (fix
    /// round 3) mistook an idle stream whose data simply ran out short of
    /// an older limit for a stopped one, about once in
    /// `CREDIT_UPDATE_STEP / MAX_SEGMENT_SIZE` (128) idle points on
    /// irregular segment sizes -- drawing a `CREDIT` on every PONG for as
    /// long as the stream stayed idle there. Measured (the diagnosis that
    /// ran parallel to this fix): a flowing stream's data lands on each
    /// announced limit exactly (both are multiples of `MAX_SEGMENT_SIZE`),
    /// so the exact rule changes no run of the credits/no-credits
    /// throughput comparison -- this is purely about not mistaking silence
    /// for a stop.
    fn stopped_at(&self) -> Option<u64> {
        let oldest = self.credit.as_ref()?.oldest();
        (self.highest_end == oldest).then_some(oldest)
    }

    /// Whether its sender may be stopped at a limit this receiver announced
    /// (spec §6.4): room given now goes at once, not after `ACK_DELAY`.
    pub fn may_be_stopped(&self) -> bool {
        self.stopped_at().is_some()
    }

    /// A `CREDIT` to send now, if any (spec §6.4). The limit is announced
    /// when it grew by `CREDIT_UPDATE_STEP` since the last announcement, or
    /// by anything at all when `urgent` (a `Reset` just skipped bytes, spec
    /// §6.5) -- unless `Credit::announced` already holds
    /// `CREDIT_ANNOUNCED_MAX` entries, in which case the growth waits: once
    /// data passes the oldest entry and pops it, which every data arrival
    /// and every call to [`StreamReceiver::on_consumed`] gives another
    /// chance at, it becomes eligible again and is judged by these same
    /// rules on the next call (an `urgent` flag from that Reset is not
    /// remembered across the wait).
    ///
    /// A sender that may be stopped at a limit older than the newest -- a
    /// `CREDIT` lost on the way, or one held back by the cap -- has its
    /// repeat cycle armed here (`CREDIT_RESENDS` repeats, once for each
    /// limit it may be stopped at: the cap only delays growth, it never
    /// stalls a sender that is actually stopped), but arming alone sends
    /// nothing. This call sends the newest limit only when it is also
    /// announcing growth in the same call; otherwise the repeat's own
    /// timing (fix round 4, spec §6.4 amended) is one `rto` after the
    /// newest limit was last sent -- by whatever sent it: an announcement
    /// here, an explicit repeat ([`StreamReceiver::credit_resend`]) or a
    /// PONG copy ([`StreamReceiver::credit_for_pong`]) -- judged by
    /// [`StreamReceiver::credit_resend_deadline`] and `credit_resend`, not
    /// by this function. Sending it here too, at the moment of arming, gave
    /// a flowing stream -- whose data lands on each announced limit exactly
    /// -- an immediate duplicate of a `CREDIT` it had just sent moments
    /// before: measured (the diagnosis that ran parallel to this fix),
    /// 20-28 % of all `CREDIT`s in a continuous upload, with `took`/
    /// `resent` unchanged. A sender stopped at the newest, with nothing
    /// grown, gets nothing here: there is
    /// nothing new to tell it.
    ///
    /// A growth of a whole segment while the sender may be stopped is
    /// deliberately NOT its own immediacy rule (fix round 3, spec §6.4
    /// amended): a sender stopped at `L = consumed_then + STREAM_WINDOW`
    /// still has about `STREAM_WINDOW` unconsumed bytes the receiver holds
    /// for it, so a growth short of `CREDIT_UPDATE_STEP` (128 KiB, a quarter
    /// of the window) never feeds a starving consumer -- it only multiplies
    /// `CREDIT`s. Measured (fix round 3 report, 33 combinations of delay,
    /// rate and consumer piece size): this rule draws 3.6x to 260x fewer
    /// `CREDIT`s than the segment-immediacy rule it replaces, for identical
    /// consumed throughput in every configuration measured.
    pub fn credit_due(&mut self, now: Instant, urgent: bool) -> Option<StreamFrame> {
        let limit = self.limit_now();
        let stopped_at = self.stopped_at();
        let stream_id = self.stream_id;
        let credit = self.credit.as_mut()?;
        let grown = limit.saturating_sub(credit.newest());
        let wants_to_grow = grown > 0 && (urgent || grown >= CREDIT_UPDATE_STEP);
        // Spec §6.4 (amended 2026-09-28, fix round 2): a growth that would
        // push `announced` past `CREDIT_ANNOUNCED_MAX` does not happen yet
        // -- a hostile peer forcing forward `Reset`s of one byte each would
        // otherwise grow the list without bound (the CREDIT rate it draws is
        // unaffected -- see the constant's own doc).
        let announce = wants_to_grow && credit.announced.len() < CREDIT_ANNOUNCED_MAX;
        if announce {
            credit.announced.push_back(limit);
            // A real transmission of the newest limit: any repeat cycle,
            // armed here or already running, counts its own rto from this
            // send (fix round 4, spec §6.4 amended).
            credit.sent_at = Some(now);
        }
        // Arm the repeat cycle the moment the sender may first be found
        // stopped at an older limit than the newest. Arming alone sends
        // nothing -- see this function's own doc and fix round 4.
        if let Some(at) =
            stopped_at.filter(|at| *at < credit.newest() && credit.repeating_for != Some(*at))
        {
            credit.repeating_for = Some(at);
            credit.resends_left = CREDIT_RESENDS;
        }
        announce.then_some(StreamFrame::Credit {
            stream_id,
            limit: credit.newest() as u32,
        })
    }

    /// When the next repeat of the newest limit is due, if one is: armed by
    /// [`StreamReceiver::credit_due`], while the sender may still be stopped
    /// at the limit it was armed for -- one `rto` after `credit.sent_at`,
    /// whichever of the three sends last set it (fix round 4, spec §6.4
    /// amended). Due now, on the very next call, when the newest limit was
    /// already sent an `rto` or more ago at the moment the cycle armed.
    pub fn credit_resend_deadline(&self, rto: Duration) -> Option<Instant> {
        let credit = self.credit.as_ref()?;
        let at = credit.repeating_for?;
        if credit.resends_left == 0 || self.stopped_at() != Some(at) {
            return None;
        }
        credit.sent_at.map(|sent| sent + rto)
    }

    /// The repeat due at `now`, if any. Consumes exactly the deadline
    /// [`StreamReceiver::credit_resend_deadline`] reports (spec §4.1).
    pub fn credit_resend(&mut self, now: Instant, rto: Duration) -> Option<StreamFrame> {
        if now < self.credit_resend_deadline(rto)? {
            return None;
        }
        let stream_id = self.stream_id;
        let credit = self.credit.as_mut()?;
        credit.resends_left -= 1;
        credit.sent_at = Some(now);
        Some(StreamFrame::Credit {
            stream_id,
            limit: credit.newest() as u32,
        })
    }

    /// The newest limit again, for a PONG (spec §6.4): while the sender may
    /// be stopped at an older one, a PONG may carry it -- during the repeats
    /// and after them. Counts as a real transmission of the newest limit,
    /// like an announcement or an explicit repeat (fix round 4): a repeat
    /// cycle still running has its next deadline pushed one `rto` past
    /// `now`, not past whatever sent the newest limit before this PONG.
    ///
    /// Not when the newest limit went out less than `rto` ago, by whatever
    /// sent it (final review C1, ruling R15, spec §6.4 amended): a sender
    /// that may be stopped hears the newest at most once per `rto` from a
    /// PONG, however many PINGs its peer sends. The connection also puts at
    /// most one such copy in a PONG, taking its streams in turn (once per
    /// datagram, in `Connection::on_transport`, through
    /// `Connection::pong_credit`): together the two bound what a PING can
    /// draw to one PONG and one `CREDIT`.
    pub fn credit_for_pong(&mut self, now: Instant, rto: Duration) -> Option<StreamFrame> {
        let at = self.stopped_at()?;
        let stream_id = self.stream_id;
        let credit = self.credit.as_mut()?;
        if at >= credit.newest() {
            return None;
        }
        if credit.sent_at.is_some_and(|sent| now < sent + rto) {
            return None;
        }
        credit.sent_at = Some(now);
        Some(StreamFrame::Credit {
            stream_id,
            limit: credit.newest() as u32,
        })
    }
}

#[cfg(test)]
#[path = "reliability_tests.rs"]
mod tests;
