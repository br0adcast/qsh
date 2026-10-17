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
mod tests {
    use super::*;

    fn both_wrapping() -> Features {
        Features::HEADER_AAD | Features::OFFSET_WRAP
    }

    /// Spec §4.14: a 32-bit field names the full offset nearest where its
    /// reader stands -- across 2^32 either way, never below zero -- and,
    /// without `offset-wrap`, the field itself.
    #[test]
    fn a_wire_offset_names_the_nearest_full_offset() {
        const EDGE: u64 = 1 << 32;
        assert_eq!(expand(0, 5, true), Some(5));
        assert_eq!(
            expand(EDGE - 10, 3, true),
            Some(EDGE + 3),
            "just past the edge"
        );
        assert_eq!(
            expand(EDGE + 3, u32::MAX - 9, true),
            Some(EDGE - 10),
            "just behind it"
        );
        assert_eq!(expand(5, u32::MAX - 15, true), None, "below zero");
        let x = 3 * EDGE + 100;
        let ahead = (x as u32).wrapping_add((1 << 31) - 1);
        assert_eq!(expand(x, ahead, true), Some(x + (1 << 31) - 1));
        let halfway = (x as u32).wrapping_add(1 << 31);
        assert_eq!(
            expand(x, halfway, true),
            Some(x - (1 << 31)),
            "exactly 2^31 away reads as behind"
        );
        assert_eq!(expand(EDGE + 3, 7, false), Some(7), "without offset-wrap");
    }

    /// Spec §4.14: with `offset-wrap` a stream goes on past 2^32. The
    /// sender's offsets are full ones, the wire carries their low 32 bits,
    /// and the receiver and the sender's ACK handling read them back.
    #[test]
    fn a_stream_with_offset_wrap_crosses_2_pow_32() {
        let start = u32::MAX - 3 * 1024 + 1; // 3 KiB short of 2^32
        let mut tx = StreamSender::starting_at(7, start);
        let mut rx = StreamReceiver::starting_at(7, start);
        tx.set_features(both_wrapping());
        rx.set_features(both_wrapping());
        let data: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
        tx.push(&data).expect("no edge with offset-wrap");
        let mut got = Vec::new();
        for f in tx.frames_to_send(Instant::now(), Duration::from_secs(1)) {
            if let StreamFrame::Data { offset, data, .. } = f {
                got.extend(rx.on_data(offset, data));
            }
        }
        assert_eq!(got, data);
        assert_eq!(rx.next_offset(), u64::from(start) + data.len() as u64);
        assert!(rx.next_offset() > 1 << 32);
        assert!(
            tx.on_ack(rx.ack()),
            "the ACK's low 32 bits move the base across"
        );
        assert_eq!(tx.base_offset(), rx.next_offset());
        assert_eq!(tx.bytes_in_flight(), 0);
    }

    /// A `Reset` past 2^32 moves a receiver that still stands below it.
    #[test]
    fn a_reset_past_2_pow_32_moves_a_receiver_below_it() {
        let start = u32::MAX - 1023;
        let mut rx = StreamReceiver::starting_at(0, start);
        rx.set_features(both_wrapping());
        let target = u64::from(start) + 64 * 1024;
        assert!(rx.on_reset(target as u32));
        assert_eq!(rx.next_offset(), target);
        assert_eq!(rx.on_data(target as u32, b"after".to_vec()), b"after");
    }

    /// Spec §4.14: without `offset-wrap` -- a peer built before it -- the
    /// edge stays where slice 1 put it.
    #[test]
    fn without_offset_wrap_the_limit_still_stands() {
        let mut tx = StreamSender::starting_at(0, OFFSET_LIMIT - 4);
        tx.set_features(Features::HEADER_AAD);
        assert_eq!(tx.push(b"abcde"), Err(OffsetSpaceExhausted));
        tx.set_features(both_wrapping());
        tx.push(b"abcde")
            .expect("with offset-wrap there is no limit");
    }

    /// Spec §4.14: with `offset-wrap` a `Reset` is taken as far as a field
    /// can name -- the tails of several resyncs whose `Reset`s were lost add
    /// up, and refusing one would stall the stream for good -- and crafted
    /// ones of 2^31 - 1 each walk the point no farther than
    /// `FULL_OFFSET_MAX`.
    #[test]
    fn with_offset_wrap_a_reset_as_far_as_a_field_names_is_taken() {
        let mut rx = StreamReceiver::new(20);
        rx.set_features(both_wrapping());
        assert_eq!(rx.on_data(0, vec![1u8; 10]).len(), 10);
        let farthest = (1u64 << 31) - 1;
        assert!(
            rx.on_reset((10 + farthest) as u32),
            "2^31 - 1 past the point"
        );
        assert_eq!(rx.next_offset(), 10 + farthest);
        rx.next_offset = FULL_OFFSET_MAX - 3 * farthest;
        let mut walked = 0;
        while rx.on_reset((rx.next_offset() + farthest) as u32) {
            walked += 1;
            assert!(walked <= 3, "past the last full offset");
        }
        assert_eq!(walked, 3);
        assert_eq!(rx.next_offset(), FULL_OFFSET_MAX);
        assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
    }

    /// Without `offset-wrap` a `Reset` jumps as far as it says, within the
    /// 32-bit space.
    #[test]
    fn without_offset_wrap_a_reset_may_jump_as_far_as_it_says() {
        let mut rx = StreamReceiver::new(0);
        let far = 512 * 1024 * 1024;
        assert!(rx.on_reset(far as u32));
        assert_eq!(rx.next_offset(), far);
    }

    /// A `Reset` keeps exactly the chunks that start at or past its offset
    /// -- one that starts below it and reaches past is dropped too -- and
    /// gives back exactly what the dropped ones cost.
    #[test]
    fn a_reset_keeps_exactly_the_chunks_at_or_past_its_offset() {
        let mut rx = StreamReceiver::new(0);
        for (offset, len) in [
            (100u32, 50usize),
            (900, 200),
            (1000, 10),
            (1005, 1),
            (4000, 30),
        ] {
            let _ = rx.on_data(offset, vec![1u8; len]);
        }
        assert!(rx.on_reset(1000));
        let kept: Vec<(u64, usize)> = rx.buffered.iter().map(|(o, c)| (*o, c.len())).collect();
        assert_eq!(kept, vec![(1000, 10), (1005, 1), (4000, 30)]);
        assert_eq!(rx.buffered_cost(), 41 + 3 * CHUNK_COST);
        assert!(rx.on_reset(5000), "past every chunk");
        assert!(rx.buffered.is_empty());
        assert_eq!(rx.buffered_cost(), 0);
    }

    /// Spec §4.14: with `offset-wrap` a receiver takes nothing past
    /// `FULL_OFFSET_MAX` -- neither a `Reset` nor `DATA` -- so every sum of an
    /// offset and a length it forms stays far from the end of `u64`.
    #[test]
    fn with_offset_wrap_nothing_past_the_last_full_offset_is_taken() {
        let mut rx = StreamReceiver::new(20);
        rx.set_features(both_wrapping());
        rx.next_offset = FULL_OFFSET_MAX - 8;
        assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
        assert_eq!(rx.next_offset(), FULL_OFFSET_MAX - 8);
        assert_eq!(
            rx.on_data((FULL_OFFSET_MAX - 8) as u32, vec![1u8; 8]),
            vec![1u8; 8],
            "up to the last offset"
        );
        assert!(rx.on_data(FULL_OFFSET_MAX as u32, vec![1u8]).is_empty());
        assert!(rx
            .on_data((FULL_OFFSET_MAX + 1000) as u32, vec![1u8; 10])
            .is_empty());
        assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
        assert_eq!(rx.next_offset(), FULL_OFFSET_MAX);
        assert_eq!(
            rx.ack(),
            FULL_OFFSET_MAX as u32,
            "nothing past it acknowledged"
        );
        // The farthest a field can name, with the longest payload a frame
        // carries: dropped, and nothing overflows.
        let farthest = (FULL_OFFSET_MAX + (1 << 31) - 1) as u32;
        assert!(rx
            .on_data(farthest, vec![1u8; u16::MAX as usize])
            .is_empty());
    }

    /// The numbers themselves, pinned: `CHUNK_COST` is a measurement (see
    /// its doc), and every test that exercises it scales by the constant.
    /// A window of full segments is what a stream may hold.
    #[test]
    fn the_chunk_cost_is_the_measured_one_and_a_window_of_segments_fits() {
        assert_eq!(CHUNK_COST, 128);
        let rx = StreamReceiver::new(20);
        let segments = LEGACY_RECEIVE_WINDOW as usize / MAX_SEGMENT_SIZE;
        assert_eq!(rx.cost_cap(), segments * (MAX_SEGMENT_SIZE + CHUNK_COST));
    }

    /// Spec §4.16 (QSH-01): without credits a receiver keeps nothing past
    /// the window every such sender stays in -- `LEGACY_RECEIVE_WINDOW` past
    /// its cumulative point. Such DATA is neither kept nor acknowledged.
    #[test]
    fn data_past_the_legacy_window_is_neither_kept_nor_acknowledged() {
        let mut rx = StreamReceiver::new(20);
        assert!(rx
            .on_data(LEGACY_RECEIVE_WINDOW as u32, vec![1u8; 10])
            .is_empty());
        assert_eq!(rx.buffered_cost(), 0);
        assert_eq!(rx.ack(), 0);
    }

    /// The same with `offset-wrap`, as far ahead as a field can name.
    #[test]
    fn with_offset_wrap_data_as_far_ahead_as_a_field_names_is_dropped() {
        let mut rx = StreamReceiver::new(20);
        rx.set_features(both_wrapping());
        for offset in [LEGACY_RECEIVE_WINDOW as u32, 1 << 20, u32::MAX >> 1] {
            assert!(rx.on_data(offset, vec![1u8; u16::MAX as usize]).is_empty());
        }
        assert_eq!(rx.buffered_cost(), 0);
        assert_eq!(rx.ack(), 0);
    }

    /// A chunk across the window's edge keeps what lies inside it.
    #[test]
    fn a_chunk_across_the_window_keeps_what_fits() {
        let mut rx = StreamReceiver::new(20);
        let edge = LEGACY_RECEIVE_WINDOW as u32;
        assert!(
            rx.on_data(edge - 4, vec![7u8; 10]).is_empty(),
            "out of order"
        );
        assert_eq!(rx.buffered_cost(), 4 + CHUNK_COST);
        let mut got = Vec::new();
        let mut at = 0u32;
        while at < edge - 4 {
            let len = (edge - 4 - at).min(1024);
            got.extend(rx.on_data(at, vec![1u8; len as usize]));
            at += len;
        }
        assert_eq!(
            got.len() as u64,
            LEGACY_RECEIVE_WINDOW,
            "up to the edge, the kept tail included"
        );
        assert_eq!(rx.buffered_cost(), 0);
    }

    /// Spec §4.16: what a receiver keeps is counted by cost, not payload --
    /// one-byte chunks at every other offset of the window cost no more
    /// than `cost_cap`, and fewer than one chunk per `1 + CHUNK_COST` of it.
    #[test]
    fn one_byte_chunks_cost_no_more_than_the_cap() {
        let mut rx = StreamReceiver::new(20);
        for i in 0..40_000u32 {
            let _ = rx.on_data(1 + 2 * i, vec![0xEE]);
        }
        assert!(
            rx.buffered_cost() <= rx.cost_cap(),
            "{} > {}",
            rx.buffered_cost(),
            rx.cost_cap()
        );
        assert!(rx.buffered.len() <= rx.cost_cap() / (1 + CHUNK_COST));
        // The same chunks again, and longer ones on the same offsets: no growth past the cap.
        for i in 0..40_000u32 {
            let _ = rx.on_data(1 + 2 * i, vec![0xEE; 2]);
        }
        assert!(rx.buffered_cost() <= rx.cost_cap());
    }

    /// Spec §4.16: chunks that overlap one another -- a segment's length at
    /// every offset -- cost no more than the cap either, and the bytes they
    /// hold still assemble into the stream exactly.
    #[test]
    fn overlapping_chunks_cost_no_more_than_the_cap_and_assemble_exactly() {
        fn byte_at(offset: u32) -> u8 {
            (offset % 251) as u8
        }
        let mut rx = StreamReceiver::new(20);
        for offset in 1..5_000u32 {
            let chunk = (offset..offset + 1024).map(byte_at).collect();
            let _ = rx.on_data(offset, chunk);
        }
        assert!(rx.buffered_cost() <= rx.cost_cap());
        let kept = rx.buffered.len();
        assert_eq!(kept, rx.cost_cap() / (1024 + CHUNK_COST));
        let got = rx.on_data(0, vec![byte_at(0)]);
        let expected: Vec<u8> = (0..kept as u32 + 1024).map(byte_at).collect();
        assert_eq!(got, expected);
        assert_eq!(rx.buffered_cost(), 0);
    }

    /// In-order bytes are delivered whatever the buffer holds: a full buffer
    /// never stalls the stream.
    #[test]
    fn in_order_bytes_are_delivered_even_with_the_buffer_full() {
        let mut rx = StreamReceiver::new(20);
        for i in 0..40_000u32 {
            let _ = rx.on_data(1 + 2 * i, vec![0xEE]);
        }
        let full = rx.buffered_cost();
        assert_eq!(
            rx.on_data(0, vec![0xAA]),
            vec![0xAA, 0xEE],
            "the hole and the byte kept after it"
        );
        assert!(rx.buffered_cost() < full);
    }

    /// The connection's room bounds what one stream may keep.
    #[test]
    fn the_connections_room_bounds_what_a_stream_keeps() {
        let mut rx = StreamReceiver::new(20);
        assert!(rx
            .on_data_within(1000, vec![1u8; 100], 100 + CHUNK_COST - 1)
            .is_empty());
        assert_eq!(rx.buffered_cost(), 0, "no room: dropped");
        assert!(rx
            .on_data_within(1000, vec![1u8; 100], 100 + CHUNK_COST)
            .is_empty());
        assert_eq!(rx.buffered_cost(), 100 + CHUNK_COST);
    }

    /// A chunk a `Reset` lands on is delivered with the next DATA, whatever
    /// that DATA is -- as before the receiver had bounds.
    #[test]
    fn a_chunk_a_reset_lands_on_is_delivered_with_the_next_data() {
        let mut rx = StreamReceiver::new(0);
        assert!(rx.on_data(1000, b"abc".to_vec()).is_empty());
        assert!(rx.on_reset(1000));
        assert_eq!(rx.on_data(5000, b"x".to_vec()), b"abc", "out of order");
        assert_eq!(rx.buffered_cost(), 1 + CHUNK_COST);
        assert!(rx.on_data(3000, b"y".to_vec()).is_empty());
        assert!(rx.on_reset(3000));
        assert_eq!(rx.on_data(0, b"old".to_vec()), b"y", "a repeat");
        // With `offset-wrap`, even a field that names an offset below zero.
        let mut rx = StreamReceiver::new(0);
        rx.set_features(both_wrapping());
        assert!(rx.on_data(1000, b"abc".to_vec()).is_empty());
        assert!(rx.on_reset(1000));
        let below_zero = 1000u32.wrapping_sub(2000);
        assert_eq!(rx.on_data(below_zero, b"x".to_vec()), b"abc");
    }

    /// A `Reset` gives back the cost of what it drops.
    #[test]
    fn a_reset_gives_back_what_it_drops() {
        let mut rx = StreamReceiver::new(0);
        let _ = rx.on_data(100, vec![1u8; 50]);
        let _ = rx.on_data(5000, vec![1u8; 50]);
        assert!(rx.on_reset(1000));
        assert_eq!(
            rx.buffered_cost(),
            50 + CHUNK_COST,
            "the chunk past the new point stays"
        );
    }

    /// Spec §4.16 under any chunking a peer picks -- tiny, overlapping,
    /// repeated, behind, ahead, past the window, `Reset`s among them, the
    /// connection's room coming and going: what is kept costs exactly its
    /// bytes plus `CHUNK_COST` a chunk, lies inside the window, never costs
    /// more than the cap and never grows by more than the room; every byte
    /// delivered is the stream's byte at its offset.
    #[test]
    fn under_any_chunking_the_cost_is_what_is_kept_and_delivery_is_exact() {
        fn byte_at(offset: u64) -> u8 {
            (offset % 251) as u8
        }
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for wrap in [false, true] {
            let mut rx = StreamReceiver::new(20);
            if wrap {
                rx.set_features(both_wrapping());
            }
            for _ in 0..20_000 {
                let point = rx.next_offset();
                let before = rx.buffered_cost();
                if next(20) == 0 {
                    let to = point + next(4096);
                    // What the chunks were before a `Reset` split them off:
                    // exactly those at or past its offset stay.
                    let mut expected = rx.buffered.clone();
                    if to > point {
                        expected.retain(|off, _| *off >= to);
                    }
                    assert_eq!(rx.on_reset(to as u32), to > point);
                    assert_eq!(rx.next_offset(), to.max(point));
                    assert_eq!(rx.buffered, expected);
                } else {
                    let start = (point + next(LEGACY_RECEIVE_WINDOW + 8192)).saturating_sub(4096);
                    let longest = if next(2) == 0 { 8 } else { 1500 };
                    let len = 1 + next(longest);
                    let data = (start..start + len).map(byte_at).collect();
                    let room = if next(4) == 0 {
                        next(4096) as usize
                    } else {
                        usize::MAX
                    };
                    let got = rx.on_data_within(start as u32, data, room);
                    for (i, b) in got.iter().enumerate() {
                        assert_eq!(*b, byte_at(point + i as u64), "byte {}", point + i as u64);
                    }
                    assert_eq!(rx.next_offset(), point + got.len() as u64);
                    if rx.buffered_cost() > before {
                        assert!(rx.buffered_cost() - before <= room);
                    }
                }
                let held: usize = rx.buffered.values().map(|c| c.len() + CHUNK_COST).sum();
                assert_eq!(rx.buffered_cost(), held);
                assert!(held <= rx.cost_cap());
                // A chunk may sit at the point itself: one a `Reset` landed
                // on waits for the next DATA to drain it.
                let (point, limit) = (rx.next_offset(), rx.accept_limit());
                assert!(rx
                    .buffered
                    .iter()
                    .all(|(off, c)| *off >= point && off + c.len() as u64 <= limit));
            }
        }
    }

    #[test]
    fn frames_codec_roundtrip() {
        let mut buf = Vec::new();
        StreamFrame::Data {
            stream_id: 0,
            offset: 4,
            data: vec![1, 2, 3],
        }
        .encode(&mut buf);
        StreamFrame::Ack {
            stream_id: 0,
            cum_ack: 7,
        }
        .encode(&mut buf);
        let out = StreamFrame::decode_all(&buf);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn reliable_in_order_delivery() {
        let mut tx = StreamSender::new(0);
        let mut rx = StreamReceiver::new(0);
        tx.push(b"hello ").expect("room in the offset space");
        tx.push(b"world").expect("room in the offset space");
        let rto = Duration::from_millis(500);
        let now = Instant::now();
        let mut delivered = Vec::new();
        for f in tx.frames_to_send(now, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                delivered.extend(rx.on_data(offset, data));
            }
        }
        assert_eq!(delivered, b"hello world");
        tx.on_ack(rx.ack());
        assert_eq!(tx.bytes_in_flight(), 0);
    }

    #[test]
    fn retransmits_on_loss() {
        let mut tx = StreamSender::new(0);
        let mut rx = StreamReceiver::new(0);
        tx.push(b"abcdef").expect("room in the offset space");
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let first = tx.frames_to_send(t0, rto); // sent, "lost"
        assert!(!first.is_empty());
        // before RTO -- nothing new
        assert!(tx
            .frames_to_send(t0 + Duration::from_millis(100), rto)
            .is_empty());
        // after RTO -- retransmit
        let again = tx.frames_to_send(t0 + Duration::from_millis(600), rto);
        assert!(!again.is_empty());
        // deliver the retransmit -- data is intact, in order
        let mut got = Vec::new();
        for f in again {
            if let StreamFrame::Data { offset, data, .. } = f {
                got.extend(rx.on_data(offset, data));
            }
        }
        assert_eq!(got, b"abcdef");
    }

    #[test]
    fn out_of_order_buffered() {
        let mut rx = StreamReceiver::new(0);
        assert_eq!(rx.on_data(3, vec![b'd']), Vec::<u8>::new()); // gap -- hold it
        assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), b"abcd");
        assert_eq!(rx.ack(), 4);
    }

    #[test]
    fn codec_all_frame_kinds_roundtrip() {
        let mut buf = Vec::new();
        StreamFrame::Ack {
            stream_id: 1,
            cum_ack: 0xDEAD_BEEF,
        }
        .encode(&mut buf);
        StreamFrame::Data {
            stream_id: 2,
            offset: 9,
            data: vec![7, 8, 9, 10],
        }
        .encode(&mut buf);
        StreamFrame::Ping { token: 42 }.encode(&mut buf);
        StreamFrame::Pong { token: 42 }.encode(&mut buf);
        StreamFrame::Close { stream_id: 3 }.encode(&mut buf);
        let out = StreamFrame::decode_all(&buf);
        assert_eq!(
            out,
            vec![
                StreamFrame::Ack {
                    stream_id: 1,
                    cum_ack: 0xDEAD_BEEF,
                },
                StreamFrame::Data {
                    stream_id: 2,
                    offset: 9,
                    data: vec![7, 8, 9, 10],
                },
                StreamFrame::Ping { token: 42 },
                StreamFrame::Pong { token: 42 },
                StreamFrame::Close { stream_id: 3 },
            ]
        );
    }

    #[test]
    fn decode_stops_on_truncated_frame() {
        // A full ACK, then a truncated DATA (header promises 3 bytes, only 1 given).
        let mut buf = Vec::new();
        StreamFrame::Ack {
            stream_id: 0,
            cum_ack: 5,
        }
        .encode(&mut buf);
        buf.extend_from_slice(&[TYPE_DATA, 0, 0, 0, 0, 0, 0, 3, 0xAA]);
        let out = StreamFrame::decode_all(&buf);
        // Only the full ACK got parsed, the truncated DATA is dropped without a panic.
        assert_eq!(
            out,
            vec![StreamFrame::Ack {
                stream_id: 0,
                cum_ack: 5,
            }]
        );
    }

    #[test]
    fn decode_stops_on_unknown_type() {
        let mut buf = Vec::new();
        StreamFrame::Ping { token: 1 }.encode(&mut buf);
        buf.push(0x7F); // unknown type -- parsing stops here
        buf.extend_from_slice(&[0, 0, 0, 0]);
        let out = StreamFrame::decode_all(&buf);
        assert_eq!(out, vec![StreamFrame::Ping { token: 1 }]);
    }

    #[test]
    fn duplicate_and_overlapping_segments_do_not_regress() {
        let mut rx = StreamReceiver::new(0);
        assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), b"abc");
        assert_eq!(rx.ack(), 3);
        // A full repeat of already-delivered data -- nothing new, the point doesn't move back.
        assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), Vec::<u8>::new());
        assert_eq!(rx.ack(), 3);
        // Partial overlap: part old, part new -- deliver only the new part.
        assert_eq!(rx.on_data(1, vec![b'b', b'c', b'd', b'e']), b"de");
        assert_eq!(rx.ack(), 5);
    }

    #[test]
    fn ack_ignores_stale_and_never_regresses_base() {
        let mut tx = StreamSender::new(0);
        tx.push(b"abcdef").expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        assert_eq!(tx.bytes_in_flight(), 6);
        tx.on_ack(4);
        assert_eq!(tx.bytes_in_flight(), 2);
        // A stale ACK doesn't move the base backward.
        tx.on_ack(2);
        assert_eq!(tx.bytes_in_flight(), 2);
        // An ACK beyond what was sent is clamped to what was actually sent.
        tx.on_ack(999);
        assert_eq!(tx.bytes_in_flight(), 0);
    }

    #[test]
    fn ack_does_not_drop_unsent_bytes() {
        // Regression: an ACK for bytes that are in the buffer but haven't
        // been sent yet via frames_to_send must be ignored -- otherwise the
        // bytes would be cut out of the buffer and never go out on the wire.
        let mut tx = StreamSender::new(0);
        tx.push(b"abcdef").expect("room in the offset space"); // nothing sent yet
        tx.on_ack(4); // acknowledging unsent bytes -- ignored
                      // all 6 bytes are still pending, starting from offset zero
        let mut rx = StreamReceiver::new(0);
        let mut got = Vec::new();
        for f in tx.frames_to_send(Instant::now(), Duration::from_millis(500)) {
            if let StreamFrame::Data { offset, data, .. } = f {
                got.extend(rx.on_data(offset, data));
            }
        }
        assert_eq!(got, b"abcdef");
        assert_eq!(rx.ack(), 6);
    }

    #[test]
    fn window_limits_new_bytes_in_flight() {
        let mut tx = StreamSender::new(0);
        let big = vec![0u8; MAX_IN_FLIGHT + 4096];
        tx.push(&big).expect("room in the offset space");
        let frames = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        let sent: usize = frames
            .iter()
            .map(|f| match f {
                StreamFrame::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(sent, MAX_IN_FLIGHT);
        assert_eq!(tx.bytes_in_flight(), MAX_IN_FLIGHT);
    }

    #[test]
    fn reset_frame_roundtrip() {
        let mut buf = Vec::new();
        StreamFrame::Reset {
            stream_id: 0,
            new_offset: 12345,
        }
        .encode(&mut buf);
        assert_eq!(
            StreamFrame::decode_all(&buf),
            vec![StreamFrame::Reset {
                stream_id: 0,
                new_offset: 12345
            }]
        );
    }

    #[test]
    fn receiver_on_reset_jumps_and_delivers_without_waiting_for_gap() {
        let mut rx = StreamReceiver::new(0);
        assert_eq!(rx.on_data(0, vec![b'a', b'b']), b"ab");
        assert_eq!(rx.ack(), 2);
        // Server dropped its backlog and restarted the stream far ahead.
        rx.on_reset(1000);
        assert_eq!(rx.ack(), 1000);
        // Data at the new base delivers immediately -- no stall waiting for 2..1000.
        assert_eq!(rx.on_data(1000, vec![b'X']), b"X");
        assert_eq!(rx.ack(), 1001);
    }

    #[test]
    fn mark_desynced_drops_buffer_and_stops_buffering() {
        let mut tx = StreamSender::new(0);
        tx.push(b"hello").expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        tx.mark_desynced();
        assert!(tx.is_desynced());
        assert_eq!(tx.bytes_in_flight(), 0);
        // While desynced, new output is dropped (nothing to replay later).
        tx.push(b"world").expect("room in the offset space");
        let frames = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        assert!(frames
            .iter()
            .all(|f| !matches!(f, StreamFrame::Data { .. })));
    }

    #[test]
    fn begin_resync_emits_reset_until_acked_then_streams_from_new_base() {
        let mut tx = StreamSender::new(0);
        tx.push(&[0u8; 100]).expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500)); // base advanced via send? no -- send only marks segments
        tx.mark_desynced(); // base jumps to write head (=100), buf empty
        let new_off = tx.begin_resync(); // pending reset at 100
        assert_eq!(new_off, 100);
        let now = Instant::now();
        // Reset is emitted while pending, even with no data.
        let f1 = tx.frames_to_send(now, Duration::from_millis(500));
        assert!(f1.iter().any(|f| matches!(
            f,
            StreamFrame::Reset {
                new_offset: 100,
                ..
            }
        )));
        // New (repaint) data streams from the new base.
        tx.push(b"NOW").expect("room in the offset space");
        let f2 = tx.frames_to_send(now, Duration::from_millis(500));
        assert!(f2
            .iter()
            .any(|f| matches!(f, StreamFrame::Data { offset: 100, .. })));
        // Once the receiver acks the reset point, Reset stops being sent.
        tx.on_ack(103);
        let f3 = tx.frames_to_send(now + Duration::from_millis(600), Duration::from_millis(500));
        assert!(f3.iter().all(|f| !matches!(f, StreamFrame::Reset { .. })));
    }

    #[test]
    fn second_desync_clears_stale_pending_reset() {
        // Regression: resync once (arming a Reset at the old base), then go
        // desynced AGAIN before that Reset is acked. The second
        // `mark_desynced` must clear the stale `pending_reset`, or the sender
        // keeps emitting a Reset whose offset no longer matches its base.
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        tx.mark_desynced(); // base jumps to 4 (write head)
        let first = tx.begin_resync(); // pending_reset = Some(4)
        assert_eq!(first, 4);

        // More output queues before the Reset above is ever acked...
        tx.push(b"bb").expect("room in the offset space");
        // ...but the client goes silent again: desync a second time.
        tx.mark_desynced(); // base jumps to 6; must drop the stale pending_reset(4)
        assert!(tx.is_desynced());

        // No Reset should be emitted yet -- we haven't called begin_resync
        // again. A stale pending_reset(4) would wrongly emit one here, at an
        // offset that no longer matches the (new) base.
        let now = Instant::now();
        let frames = tx.frames_to_send(now, Duration::from_millis(500));
        assert!(
            frames
                .iter()
                .all(|f| !matches!(f, StreamFrame::Reset { .. })),
            "a stale pending_reset must not survive a second mark_desynced"
        );

        // The next real resync arms a Reset at the NEW base, not the old one.
        let second = tx.begin_resync();
        assert_eq!(
            second, 6,
            "begin_resync after a second desync must use the new base"
        );
        let frames2 = tx.frames_to_send(now, Duration::from_millis(500));
        assert!(frames2
            .iter()
            .any(|f| matches!(f, StreamFrame::Reset { new_offset: 6, .. })));
    }

    /// Feed a batch of `frames_to_send` output into a receiver, appending any
    /// freshly delivered bytes to `delivered`. A small test-only helper
    /// (`StreamFrame::Data`/`Reset` are the only kinds a sender's own
    /// `frames_to_send` output ever contains) so the CRITICAL-1 regression
    /// tests below read as a plain sender-to-receiver pipe.
    fn apply_to_receiver(
        rx: &mut StreamReceiver,
        frames: Vec<StreamFrame>,
        delivered: &mut Vec<u8>,
    ) {
        for f in frames {
            match f {
                StreamFrame::Reset { new_offset, .. } => {
                    rx.on_reset(new_offset);
                }
                StreamFrame::Data { offset, data, .. } => {
                    delivered.extend(rx.on_data(offset, data))
                }
                _ => {}
            }
        }
    }

    #[test]
    fn pending_reset_is_paced_like_a_retransmit_not_resent_every_flush() {
        // CRITICAL-1 (source fix): before pacing, `frames_to_send` prepended
        // the armed Reset on EVERY call while it was pending, with no RTO
        // gating -- so several `Connection::send` flushes within one RTT (as
        // happens when a tmux repaint is chunked into multiple 8 KiB PTY
        // reads) each carried their OWN Reset, guaranteeing duplicates.
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        tx.mark_desynced();
        let _ = tx.begin_resync(); // pending_reset armed at the write head (4)

        let rto = Duration::from_millis(500);
        let now = Instant::now();

        // First flush: the Reset goes out -- it hasn't been sent before.
        let f1 = tx.frames_to_send(now, rto);
        assert!(
            f1.iter().any(|f| matches!(f, StreamFrame::Reset { .. })),
            "the Reset must go out immediately the first time"
        );

        // A SECOND flush at the SAME instant (e.g. the very next PTY chunk of
        // the same repaint, handled in the same wakeup) must NOT re-include
        // the Reset -- not a full RTO has passed since it last went out.
        tx.push(b"NOW").expect("room in the offset space");
        let f2 = tx.frames_to_send(now, rto);
        assert!(
            f2.iter().all(|f| !matches!(f, StreamFrame::Reset { .. })),
            "the Reset must be paced like a retransmit, not resent on every flush"
        );
        assert!(
            f2.iter().any(|f| matches!(f, StreamFrame::Data { .. })),
            "new data still goes out normally while the Reset is paced"
        );

        // Once RTO elapses with the Reset still unacked, it is resent.
        let f3 = tx.frames_to_send(now + rto, rto);
        assert!(
            f3.iter().any(|f| matches!(f, StreamFrame::Reset { .. })),
            "a still-unacked Reset must be resent after RTO, like a segment retransmit"
        );
    }

    #[test]
    fn duplicate_reset_across_two_flushes_does_not_stall_or_duplicate_delivery() {
        // CRITICAL-1 repro (reviewer-verified): a big repaint chunked across
        // more than one `frames_to_send` batch, with the Reset still unacked
        // (and so re-armed/re-sent) on the second batch. The receiver must
        // treat the second Reset as a no-op and keep delivering forward --
        // not rewind and stall waiting for bytes the sender has already
        // dropped from its own buffer on the first batch's ack.
        let mut tx = StreamSender::new(0);
        tx.push(&[b'A'; 20]).expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
        tx.mark_desynced(); // base jumps to the write head (20)
        let base = tx.begin_resync(); // pending_reset armed at 20
        assert_eq!(base, 20);

        let rto = Duration::from_millis(500);
        let t0 = Instant::now();

        // Batch 1: Reset(20) + the repaint's first chunk (8192 bytes, like a
        // full tmux PTY read).
        tx.push(&vec![b'B'; 8192])
            .expect("room in the offset space");
        let batch1 = tx.frames_to_send(t0, rto);
        assert!(batch1
            .iter()
            .any(|f| matches!(f, StreamFrame::Reset { new_offset: 20, .. })));

        let mut rx = StreamReceiver::new(0);
        let mut delivered = Vec::new();
        apply_to_receiver(&mut rx, batch1, &mut delivered);
        assert_eq!(rx.ack(), 20 + 8192);
        assert_eq!(delivered.len(), 8192);

        // Batch 2, issued past RTO with the Reset still unacked (the ack
        // hasn't made it back to the sender yet) -- a genuine paced resend of
        // the SAME Reset, plus newly queued repaint output "in between".
        tx.push(&vec![b'C'; 4096])
            .expect("room in the offset space");
        let batch2 = tx.frames_to_send(t0 + rto, rto);
        assert!(
            batch2
                .iter()
                .any(|f| matches!(f, StreamFrame::Reset { new_offset: 20, .. })),
            "the still-unacked Reset must be resent after RTO"
        );
        apply_to_receiver(&mut rx, batch2, &mut delivered);

        // The receiver ends exactly at the write head, and every byte arrived
        // exactly once: no stall (the bug), no duplication.
        assert_eq!(rx.ack(), 20 + 8192 + 4096);
        let mut expected = vec![b'B'; 8192];
        expected.extend(vec![b'C'; 4096]);
        assert_eq!(delivered, expected);
    }

    #[test]
    fn on_reset_replayed_after_delivery_is_a_no_op() {
        // CRITICAL-1: a Reset that doesn't move the point FORWARD must be a
        // true no-op -- not just "doesn't crash", but leaves next_offset and
        // any already-buffered out-of-order data untouched.
        let mut rx = StreamReceiver::new(0);
        assert!(rx.on_reset(100));
        assert_eq!(rx.on_data(100, b"abc".to_vec()), b"abc");
        assert_eq!(rx.ack(), 103);

        // An out-of-order segment sits buffered ahead of the point.
        assert_eq!(rx.on_data(110, vec![b'z']), Vec::<u8>::new());

        // The SAME Reset replays (or an even older one would) -- it must
        // report false and touch nothing: the point stays put and the
        // buffered segment ahead of it survives (a rewind would have cleared it).
        assert!(
            !rx.on_reset(100),
            "on_reset must report false when it doesn't move the point"
        );
        assert_eq!(
            rx.ack(),
            103,
            "a stale/duplicate Reset must not rewind the point"
        );

        // Filling the gap up to the buffered segment now delivers it too --
        // proof the segment was never dropped by the no-op reset.
        let filled = rx.on_data(103, vec![b'd', b'e', b'f', b'g', b'h', b'i', b'j']);
        assert_eq!(
            filled, b"defghijz",
            "the buffered segment ahead of the point survived the no-op reset"
        );
    }

    /// The new frames survive the wire format, and their type codes do not
    /// collide with the ones already spoken.
    #[test]
    fn path_probe_frames_round_trip() {
        let frames = vec![
            StreamFrame::PathProbe { token: 0xDEAD_BEEF },
            StreamFrame::PathProbeAck { token: 7 },
        ];
        for frame in frames {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            assert_eq!(
                StreamFrame::decode_all(&buf),
                vec![frame.clone()],
                "a path frame must survive the round trip: {frame:?}"
            );
        }
    }

    /// A build that predates these frames stops at the unknown type instead
    /// of reading its bytes as something else. That is what lets an older
    /// daemon simply not answer a probe -- the path stays unverified -- while
    /// everything else on the connection keeps working.
    #[test]
    fn an_older_peer_stops_at_the_unknown_frame_rather_than_misreading_it() {
        let mut buf = Vec::new();
        StreamFrame::PathProbe { token: 1 }.encode(&mut buf);
        // What an older `decode_all` would see: an unknown leading byte.
        assert_eq!(buf[0], TYPE_PATH_PROBE);
        let mut unknown = vec![0x7F_u8];
        unknown.extend_from_slice(&1u32.to_be_bytes());
        assert!(
            StreamFrame::decode_all(&unknown).is_empty(),
            "an unknown frame type yields nothing, and never a misparsed frame"
        );
    }

    /// Spec §4.2: the retransmit wake-up is per segment -- the oldest
    /// unacknowledged segment's last send plus `rto` -- and an armed Reset
    /// that has gone out is paced the same way.
    #[test]
    fn the_retransmit_deadline_is_the_oldest_unacked_segment_plus_rto() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(100);
        let mut tx = StreamSender::new(0);
        assert_eq!(tx.retransmit_deadline(rto), None, "nothing sent");
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        tx.push(b"bb").expect("room in the offset space");
        let _ = tx.frames_to_send(t1, rto);
        assert_eq!(tx.retransmit_deadline(rto), Some(t0 + rto));
        assert!(tx.on_ack(4), "the ack moved the base");
        assert_eq!(tx.retransmit_deadline(rto), Some(t1 + rto));
        assert!(!tx.on_ack(4), "a repeated ack moves nothing");
        assert!(tx.on_ack(6));
        assert_eq!(tx.retransmit_deadline(rto), None, "everything acknowledged");

        tx.mark_desynced();
        let _ = tx.begin_resync();
        let t2 = t1 + Duration::from_millis(100);
        let _ = tx.frames_to_send(t2, rto);
        assert_eq!(
            tx.retransmit_deadline(rto),
            Some(t2 + rto),
            "a Reset that went out is due again rto later"
        );
    }

    /// Karn's rule for data (RFC 6298 §3): an ACK that newly covers segments
    /// which all went out once times the newest of them from its send.
    #[test]
    fn an_ack_times_the_newest_segment_it_newly_covers() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(10);
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        tx.push(b"bb").expect("room in the offset space");
        let _ = tx.frames_to_send(t1, rto);
        assert_eq!(tx.ack_timed_from(4), Some(t0));
        assert_eq!(tx.ack_timed_from(6), Some(t1), "the newest covered");
        assert!(tx.on_ack(4));
        assert_eq!(tx.ack_timed_from(4), None, "covers nothing new");
        assert_eq!(tx.ack_timed_from(6), Some(t1));
        assert_eq!(tx.ack_timed_from(5), None, "covers no whole segment");
    }

    /// An ACK that covers a retransmitted segment -- a hole filled, the
    /// cumulative ACK jumping over segments that arrived long before -- says
    /// nothing about any one send, so it times nothing.
    #[test]
    fn an_ack_covering_a_retransmitted_segment_times_nothing() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        tx.push(b"bb").expect("room in the offset space");
        let _ = tx.frames_to_send(t0 + Duration::from_millis(400), rto);
        let resent = tx.frames_to_send(t0 + rto, rto);
        assert_eq!(resent.len(), 1, "the first segment went out again");
        assert_eq!(tx.ack_timed_from(4), None);
        assert_eq!(
            tx.ack_timed_from(6),
            None,
            "the jump includes the resent one"
        );
        assert!(tx.on_ack(4));
        assert_eq!(
            tx.ack_timed_from(6),
            Some(t0 + Duration::from_millis(400)),
            "past the resent segment, timing resumes"
        );
    }

    /// After `forget_send_times` nothing already in flight times a round
    /// trip; what is sent afterwards does again.
    #[test]
    fn forgotten_send_times_time_nothing_and_later_sends_time_again() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        tx.forget_send_times();
        assert_eq!(tx.ack_timed_from(4), None);
        let t1 = t0 + Duration::from_secs(600);
        tx.push(b"bb").expect("room in the offset space");
        let _ = tx.frames_to_send(t1, rto);
        assert_eq!(
            tx.ack_timed_from(6),
            None,
            "the ACK still covers a forgotten one"
        );
        assert!(tx.on_ack(4));
        assert_eq!(tx.ack_timed_from(6), Some(t1));
    }

    /// Final review, Important 1: the deadline that wakes the sender belongs
    /// to the oldest segment, but a wake-up resends only the segments whose
    /// OWN last send is `rto` old -- not the whole window with them.
    #[test]
    fn a_retransmit_wake_up_resends_only_the_segments_that_are_due() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(400);
        let mut tx = StreamSender::new(0);
        tx.push(b"aaaa").expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        tx.push(b"bb").expect("room in the offset space");
        let _ = tx.frames_to_send(t1, rto);
        let due = tx.retransmit_deadline(rto).expect("both unacknowledged");
        assert_eq!(due, t0 + rto);
        let resent = tx.frames_to_send(due, rto);
        assert_eq!(
            resent,
            vec![StreamFrame::Data {
                stream_id: 0,
                offset: 0,
                data: b"aaaa".to_vec(),
            }],
            "the segment sent 100 ms ago waits for its own deadline"
        );
        assert_eq!(tx.retransmit_deadline(rto), Some(t1 + rto));
    }

    /// What `Connection::sendable_now` asks a sender: something that has no
    /// deadline of its own -- unsent bytes with room in the window, a
    /// segment taken for lost, an armed Reset that has not gone out yet.
    /// A segment merely waiting for its ACK has a deadline instead.
    #[test]
    fn has_sendable_and_has_unsent_reset_count_what_has_no_deadline_of_its_own() {
        let rto = Duration::from_millis(500);
        let t0 = Instant::now();
        let mut tx = StreamSender::new(0);
        assert!(!tx.has_sendable(), "nothing queued");
        tx.push(b"abc").expect("room in the offset space");
        assert!(tx.has_sendable(), "queued, never sent");
        let _ = tx.frames_to_send(t0, rto);
        assert!(!tx.has_sendable(), "sent, waiting for its ACK");
        assert!(
            tx.mark_due_lost(t0 + rto, rto),
            "the oldest segment expired"
        );
        assert!(tx.has_sendable(), "a segment taken for lost");
        assert_eq!(tx.retransmit_deadline(rto), None, "and it has no deadline");
        let _ = tx.next_segment(t0 + rto).expect("the lost segment again");
        assert!(!tx.has_sendable(), "out again, waiting for its ACK");

        tx.push(&vec![b'x'; MAX_IN_FLIGHT])
            .expect("room in the offset space");
        let _ = tx.frames_to_send(t0, rto);
        assert!(tx.bytes_in_flight() >= MAX_IN_FLIGHT, "the window is full");
        assert!(
            !tx.has_sendable(),
            "bytes waiting for room in the window wait for an ACK, not a timer"
        );

        tx.mark_desynced();
        assert!(!tx.has_sendable(), "a desynced sender holds nothing");
        assert!(!tx.has_unsent_reset(), "and no Reset");
        let _ = tx.begin_resync();
        assert!(tx.has_unsent_reset(), "an armed Reset that never went out");
        let _ = tx.frames_to_send(t0, rto);
        assert!(!tx.has_unsent_reset(), "the Reset went out");
    }

    /// Spec §4.14 (legacy mode): a write that would reach past
    /// `OFFSET_LIMIT` is refused whole, and nothing already queued is lost.
    #[test]
    fn a_write_past_the_offset_limit_is_refused_whole() {
        let mut tx = StreamSender::starting_at(0, OFFSET_LIMIT - 4);
        tx.push(b"abcd").expect("exactly up to the limit fits");
        assert_eq!(tx.push(b"e"), Err(OffsetSpaceExhausted));
        assert_eq!(tx.queued_total(), u64::from(OFFSET_LIMIT));
        assert_eq!(
            tx.unacked_len(),
            4,
            "the bytes before the limit are still there"
        );
    }

    /// A DATA frame that ends past `u32::MAX` is dropped, not wrapped: no
    /// sender following this protocol writes there, and `drain`'s
    /// `off + len` would overflow.
    #[test]
    fn a_data_frame_ending_past_u32_max_is_dropped_without_panic() {
        let mut rx = StreamReceiver::starting_at(0, u32::MAX - 100);
        assert!(rx.on_data(u32::MAX - 10, vec![1u8; 20]).is_empty());
        assert_eq!(rx.ack(), u32::MAX - 100, "nothing moved");
        assert_eq!(rx.on_data(u32::MAX - 100, vec![2u8; 100]), vec![2u8; 100]);
        assert_eq!(rx.ack(), u32::MAX, "up to the very last offset is fine");
    }

    /// Spec §9.2 (1a): an acknowledgement costs the same whatever lies
    /// behind it. With a `Vec` every ACK moved the whole remaining backlog to
    /// the front (`drain(0..n)`), so 32 MiB queued at once took 52 s. With a
    /// ring only the head moves: the first byte still waiting after the ACK
    /// sits at the very address it had before it.
    #[test]
    fn ack_cost_does_not_depend_on_backlog() {
        for backlog in [64 * 1024usize, 32 * 1024 * 1024] {
            let mut tx = StreamSender::new(1);
            tx.push(&vec![0xA5; backlog])
                .expect("room in the offset space");
            let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
            let acked = 4 * 1024;
            let before = tx.byte_address_for_test(acked);
            assert!(tx.on_ack(acked as u32));
            assert_eq!(
                tx.byte_address_for_test(0),
                before,
                "backlog {backlog}: the bytes behind the ACK were moved"
            );
            assert_eq!(tx.unacked_len(), backlog - acked);
        }
    }

    /// A burst past every send gate -- past `SEND_HARD_CAP` at worst, whose
    /// data a stream nobody can rebuild keeps -- grows the ring to its size.
    /// Once acknowledged, that memory comes back: a ring does not stay at
    /// its peak for the rest of the connection. The move is made on a ring
    /// that wraps, and the bytes still waiting come through it intact.
    #[test]
    fn a_ring_grown_by_a_burst_gives_its_memory_back_as_it_drains() {
        let rto = Duration::from_secs(1);
        let now = Instant::now();
        let all: Vec<u8> = (0..11 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let (first, second) = all.split_at(8 * 1024 * 1024);
        let mut tx = StreamSender::new(1);
        tx.push(first).expect("room");
        let grown = tx.buf.capacity();
        assert!(grown >= first.len());
        let mut acked = 0usize;
        let mut ack_up_to = |tx: &mut StreamSender, to: usize| {
            while acked < to {
                let _ = tx.frames_to_send(now, rto);
                let next = (tx.sent_up_to as usize).min(to);
                assert!(tx.on_ack(next as u32));
                acked = next;
            }
        };
        ack_up_to(&mut tx, 4 * 1024 * 1024);
        assert_eq!(tx.buf.capacity(), grown, "half full keeps its room");
        tx.push(second).expect("room");
        let (head, tail) = tx.buf.as_slices();
        assert!(!head.is_empty() && !tail.is_empty(), "the ring wraps");
        let left = 100 * 1024;
        ack_up_to(&mut tx, all.len() - left);
        assert!(
            tx.buf.capacity() <= RING_KEEP,
            "capacity {} after the burst drained",
            tx.buf.capacity()
        );
        assert_eq!(tx.copy_out(0, left), &all[all.len() - left..]);
    }

    /// A ring no bigger than what a send gate lets through (spec §4.7.2) is
    /// never shrunk: a gated stream fills and drains it all the time, and
    /// would pay for a reallocation on every burst.
    #[test]
    fn a_ring_within_what_a_gate_lets_through_keeps_its_capacity() {
        let rto = Duration::from_secs(1);
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        for _ in 0..80 {
            tx.push(&[0x5A; 8 * 1024]).expect("room");
        }
        let grown = tx.buf.capacity();
        assert!(
            grown <= RING_KEEP,
            "a 640 KiB tail grows the ring to {grown}"
        );
        while tx.unacked_len() > 0 {
            let _ = tx.frames_to_send(now, rto);
            assert!(tx.on_ack(tx.sent_up_to as u32));
        }
        assert_eq!(tx.buf.capacity(), grown);
    }

    /// The ring wraps: bytes pushed after an ACK freed its head come out of
    /// `frames_to_send` intact and in order.
    #[test]
    fn segments_cut_across_the_rings_wrap_carry_the_right_bytes() {
        let rto = Duration::from_secs(1);
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        let first: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
        tx.push(&first).expect("room");
        let _ = tx.frames_to_send(now, rto);
        assert!(tx.on_ack(6 * 1024));
        let second: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 241) as u8).collect();
        tx.push(&second).expect("room");
        let mut rx = StreamReceiver::starting_at(1, 8 * 1024);
        for f in tx.frames_to_send(now, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                let _ = rx.on_data(offset, data);
            }
        }
        let mut tail = Vec::new();
        for f in tx.frames_to_send(now + rto, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                if (6 * 1024..8 * 1024).contains(&offset) {
                    tail.extend_from_slice(&data);
                }
            }
        }
        assert_eq!(
            tail,
            &first[6 * 1024..],
            "the retransmitted head of the ring"
        );
        assert_eq!(rx.ack(), 16 * 1024, "the new bytes arrived whole");
    }

    /// `copy_out` across a ring that really is in two pieces: every range,
    /// including the ones that straddle the split, comes out as the bytes a
    /// flat copy of the backlog holds there. (The test above pins the
    /// behaviour; its buffer grows in one piece and does not split.)
    #[test]
    fn copy_out_reads_across_the_split_of_the_ring() {
        let mut tx = StreamSender::new(1);
        let first: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
        tx.push(&first).expect("room");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
        assert!(tx.on_ack(6 * 1024));
        let second: Vec<u8> = (0..4 * 1024u32).map(|i| (i % 241) as u8).collect();
        tx.push(&second).expect("room");
        let (head, tail) = tx.buf.as_slices();
        assert!(
            !head.is_empty() && !tail.is_empty(),
            "the ring holds the backlog in two pieces"
        );
        let split = head.len();
        let flat: Vec<u8> = tx.buf.iter().copied().collect();
        assert_eq!(&flat[..2 * 1024], &first[6 * 1024..]);
        assert_eq!(&flat[2 * 1024..], &second[..]);
        for from in [0, 1, split - 1, split, split + 1, flat.len() - 1] {
            for len in [0, 1, 7, split, flat.len() - from] {
                if from + len > flat.len() {
                    continue;
                }
                assert_eq!(
                    tx.copy_out(from, len),
                    &flat[from..from + len],
                    "from {from}, len {len}, split at {split}"
                );
            }
        }
    }

    /// RFC 5681 §3.2: an ACK that moves nothing while bytes are in flight is
    /// a duplicate; the count restarts when one moves the base.
    #[test]
    fn duplicate_acks_are_counted_until_one_moves_the_base() {
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
        assert_eq!(tx.on_ack_counting(0).duplicates, 1);
        assert_eq!(tx.on_ack_counting(0).duplicates, 2);
        assert_eq!(tx.on_ack_counting(0).duplicates, 3);
        let moved = tx.on_ack_counting(1024);
        assert_eq!((moved.acked, moved.duplicates), (1024, 0));
        assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
        let mut idle = StreamSender::new(2);
        assert_eq!(
            idle.on_ack_counting(0),
            AckEffect::default(),
            "nothing in flight"
        );
    }

    /// The urgent retransmit is the oldest segment and goes out first.
    #[test]
    fn an_urgent_segment_is_the_oldest_and_goes_out_before_anything_else() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[7u8; 3 * 1024]).expect("room");
        let _ = tx.frames_to_send(now, Duration::from_secs(1));
        assert!(tx.mark_oldest_urgent());
        assert!(tx.has_urgent());
        let seg = tx.next_urgent(now).expect("urgent");
        assert!(matches!(seg.frame, StreamFrame::Data { offset: 0, .. }) && seg.retransmit);
        assert!(!tx.has_urgent());
        assert_eq!(tx.pipe(), 3 * 1024, "back in the network");
    }

    /// An ACK below the base is a stale one overtaken on the way: neither a
    /// duplicate nor the end of a run of them.
    #[test]
    fn a_stale_ack_is_not_a_duplicate_and_does_not_break_the_run() {
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
        let _ = tx.on_ack_counting(1024);
        assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
        assert_eq!(tx.on_ack_counting(0), AckEffect::default());
        assert_eq!(tx.on_ack_counting(1024).duplicates, 2);
    }

    /// An ACK that acknowledges an armed `Reset` moved something: it is the
    /// answer to the `Reset`, not a sign of a hole in the DATA.
    #[test]
    fn the_ack_that_clears_a_reset_is_not_a_duplicate() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.mark_desynced();
        let base = tx.begin_resync();
        tx.push(&[0u8; 2048]).expect("room");
        let frames = tx.frames_to_send(now, Duration::from_secs(1));
        assert!(matches!(frames[0], StreamFrame::Reset { .. }));
        assert_eq!(tx.on_ack_counting(base as u32), AckEffect::default());
        assert!(!tx.has_unsent_reset() && tx.take_due_reset(now, Duration::ZERO).is_none());
        assert_eq!(
            tx.on_ack_counting(base as u32).duplicates,
            1,
            "the next one is"
        );
    }

    /// RFC 6582 §3.2 step 1: once held, a stream's fast retransmit waits
    /// for an ACK past everything sent at the time -- one equal to it is
    /// not enough: its copies may still draw ACKs of that base.
    #[test]
    fn a_held_fast_retransmit_waits_for_an_ack_past_what_was_sent() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 20 * 1024]).expect("room");
        for _ in 0..10 {
            let _ = tx.next_segment(now).expect("room");
        }
        assert!(tx.may_fast_retransmit());
        tx.hold_fast_retransmit();
        assert!(!tx.may_fast_retransmit());
        let _ = tx.on_ack_counting(10 * 1024);
        assert!(!tx.may_fast_retransmit(), "equal to it");
        let _ = tx.next_segment(now).expect("new data");
        let _ = tx.on_ack_counting(11 * 1024);
        assert!(tx.may_fast_retransmit());
    }

    /// RFC 3465 §2.3 (ruling R20): the round trip after a timeout lasts, for
    /// a stream, until an ACK reaches where it had sent up to at the
    /// timeout. The ACK that reaches it is still in it (asked before the ACK
    /// is applied); the next is not. A stream with nothing in flight has no
    /// such round trip.
    #[test]
    fn the_round_trip_after_a_timeout_lasts_until_its_flight_is_acknowledged() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 20 * 1024]).expect("room");
        tx.note_timeout_flight();
        assert!(!tx.acks_timeout_flight(), "nothing in flight");
        for _ in 0..10 {
            let _ = tx.next_segment(now).expect("room");
        }
        tx.note_timeout_flight();
        assert!(tx.acks_timeout_flight());
        let _ = tx.on_ack_counting(4 * 1024);
        assert!(tx.acks_timeout_flight(), "part of the flight");
        let _ = tx.next_segment(now).expect("new data");
        assert!(
            tx.acks_timeout_flight(),
            "what goes out since does not move it"
        );
        let _ = tx.on_ack_counting(10 * 1024);
        assert!(!tx.acks_timeout_flight(), "the flight acknowledged");
    }

    /// An undone timeout, a restart and a desync forget the round trip
    /// after the timeout.
    #[test]
    fn an_undo_a_restart_and_a_desync_forget_the_timeouts_flight() {
        let now = Instant::now();
        let flying = || {
            let mut tx = StreamSender::new(1);
            tx.push(&[0u8; 4096]).expect("room");
            let _ = tx.next_segment(now).expect("room");
            tx.note_timeout_flight();
            assert!(tx.acks_timeout_flight());
            tx
        };
        let mut undone = flying();
        undone.forget_timeout_losses(now);
        assert!(!undone.acks_timeout_flight(), "undo");
        let mut restarted = flying();
        restarted.take_in_flight_for_lost();
        assert!(!restarted.acks_timeout_flight(), "restart");
        let mut desynced = flying();
        desynced.mark_desynced();
        assert!(!desynced.acks_timeout_flight(), "desync");
    }

    /// A restart resends everything in flight: those copies hold it.
    #[test]
    fn taking_the_flight_for_lost_holds_the_fast_retransmit() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.next_segment(now).expect("room");
        tx.take_in_flight_for_lost();
        assert!(!tx.may_fast_retransmit());
    }

    /// A recovery that ended with nothing past the base in flight still
    /// holds: its repairs draw ACKs of that base, with new data behind them.
    #[test]
    fn a_hold_with_nothing_in_flight_waits_for_the_next_advance() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.next_segment(now).expect("room");
        let _ = tx.on_ack_counting(1024);
        tx.hold_fast_retransmit();
        let _ = tx.next_segment(now).expect("new data");
        assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
        assert!(!tx.may_fast_retransmit());
        let _ = tx.on_ack_counting(2048);
        assert!(tx.may_fast_retransmit());
    }

    /// A desync drops everything the hold was about.
    #[test]
    fn a_desync_releases_the_hold() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.next_segment(now).expect("room");
        tx.hold_fast_retransmit();
        tx.mark_desynced();
        assert!(tx.may_fast_retransmit());
    }

    /// Review round 2 (Minor 1): the hold after a recovery runs to where the
    /// recovery began (RFC 6582's `recover`), not to all the stream has sent
    /// since -- and a full ACK already past that point holds nothing.
    #[test]
    fn a_hold_to_an_offset_waits_only_while_the_base_has_not_passed_it() {
        let now = Instant::now();
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 20 * 1024]).expect("room");
        for _ in 0..14 {
            let _ = tx.next_segment(now).expect("room");
        }
        let _ = tx.on_ack_counting(10 * 1024);
        tx.hold_fast_retransmit_to(10 * 1024);
        assert!(!tx.may_fast_retransmit(), "the base is at it");
        let _ = tx.on_ack_counting(11 * 1024);
        assert!(
            tx.may_fast_retransmit(),
            "past it, not past all that was sent"
        );
        tx.hold_fast_retransmit_to(10 * 1024);
        assert!(tx.may_fast_retransmit(), "already past: nothing to hold");
    }

    fn with_credits() -> Features {
        Features::HEADER_AAD | Features::STREAM_CREDIT | Features::OFFSET_WRAP
    }

    fn crediting_sender(stream_id: u8) -> StreamSender {
        let mut tx = StreamSender::new(stream_id);
        tx.set_features(with_credits());
        tx
    }

    fn crediting_receiver(stream_id: u8) -> StreamReceiver {
        let mut rx = StreamReceiver::new(stream_id);
        rx.set_features(with_credits());
        rx
    }

    /// Send what `tx` may and acknowledge it at once, until it stops.
    /// Returns how far it got.
    fn send_and_ack_until_stopped(tx: &mut StreamSender, now: Instant) -> u64 {
        loop {
            if tx.frames_to_send(now, Duration::from_secs(1)).is_empty() {
                return tx.sent_up_to();
            }
            let _ = tx.on_ack(tx.sent_up_to() as u32);
        }
    }

    /// Deliver `n` bytes in order to `rx` from where it stands.
    fn deliver_in_order(rx: &mut StreamReceiver, n: u64) {
        let mut left = n;
        while left > 0 {
            let len = left.min(MAX_SEGMENT_SIZE as u64);
            let at = rx.next_offset() as u32;
            assert_eq!(rx.on_data(at, vec![0u8; len as usize]).len() as u64, len);
            left -= len;
        }
    }

    /// Spec §6.1: `0x09 CREDIT stream_id(1) limit(u32, BE)`, six bytes.
    #[test]
    fn a_credit_frame_is_six_bytes_and_round_trips() {
        let mut buf = Vec::new();
        StreamFrame::Credit {
            stream_id: 20,
            limit: 0x0102_0304,
        }
        .encode(&mut buf);
        assert_eq!(buf, [0x09, 20, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            StreamFrame::decode_all(&buf),
            vec![StreamFrame::Credit {
                stream_id: 20,
                limit: 0x0102_0304
            }]
        );
        assert!(
            StreamFrame::decode_all(&buf[..5]).is_empty(),
            "a cut frame is dropped"
        );
    }

    /// Spec §6.2: with credits a sender puts out new bytes only below its
    /// limit -- the implicit `STREAM_WINDOW` at first -- and goes on once a
    /// `CREDIT` raises it; a stale or repeated one changes nothing. A sender
    /// stopped at its limit has nothing to send and is not backlogged: the
    /// reader sets the pace, not the network.
    #[test]
    fn a_sender_writes_new_bytes_only_below_its_limit() {
        let now = Instant::now();
        let mut tx = crediting_sender(20);
        tx.push(&vec![1u8; 600 * 1024]).expect("room");
        assert_eq!(tx.credit_limit(), Some(STREAM_WINDOW));
        assert_eq!(send_and_ack_until_stopped(&mut tx, now), STREAM_WINDOW);
        assert!(!tx.has_sendable());
        assert!(!tx.has_waiting());
        assert!(!tx.on_credit((STREAM_WINDOW - 1) as u32), "stale");
        assert!(!tx.on_credit(STREAM_WINDOW as u32), "the same again");
        assert!(tx.on_credit((STREAM_WINDOW + 64 * 1024) as u32));
        assert_eq!(
            send_and_ack_until_stopped(&mut tx, now),
            STREAM_WINDOW + 64 * 1024
        );
    }

    /// Spec §6.2, §6.5: a retransmit neither spends nor checks the credit.
    #[test]
    fn a_retransmit_goes_out_at_the_limit() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(500);
        let mut tx = crediting_sender(20);
        tx.push(&vec![2u8; STREAM_WINDOW as usize]).expect("room");
        let _ = tx.frames_to_send(t0, rto);
        assert!(tx.on_ack(tx.sent_up_to() as u32));
        let second = tx.frames_to_send(t0, rto);
        assert_eq!(tx.sent_up_to(), STREAM_WINDOW, "at the limit");
        let resent = tx.frames_to_send(t0 + rto, rto);
        assert_eq!(
            resent.len(),
            second.len(),
            "all of it again at its deadline"
        );
    }

    /// A `CREDIT` on a stream without credits -- a stray one -- is ignored.
    #[test]
    fn a_credit_without_credits_is_ignored() {
        let mut tx = StreamSender::new(20);
        assert_eq!(tx.credit_limit(), None);
        assert!(!tx.on_credit(1 << 30));
        assert_eq!(tx.credit_limit(), None);
    }

    /// Spec §6.5 (amended 2026-09-28, fix round 1): dropping a backlog that
    /// still fit in the room the sender already had leaves its limit
    /// standing -- there was nothing to wait for, so the repaint goes out
    /// at once.
    #[test]
    fn a_desync_within_the_old_room_keeps_the_limit_and_the_repaint_goes_out_at_once() {
        let now = Instant::now();
        let mut tx = crediting_sender(0);
        tx.push(&vec![3u8; 300 * 1024]).expect("room");
        assert_eq!(send_and_ack_until_stopped(&mut tx, now), 300 * 1024);
        tx.push(&vec![4u8; 200 * 1024]).expect("room"); // queued, never sent -- head 500 KiB, inside 512 KiB
        tx.mark_desynced();
        assert_eq!(
            tx.credit_limit(),
            Some(STREAM_WINDOW),
            "the backlog fit -- the limit stands"
        );
        assert_eq!(tx.begin_resync(), 500 * 1024);
        tx.push(b"repaint").expect("room");
        let frames = tx.frames_to_send(now, Duration::from_secs(1));
        assert!(frames.iter().any(|f| matches!(
            f,
            StreamFrame::Data { offset, .. } if u64::from(*offset) == 500 * 1024
        )));
    }

    /// Spec §6.5 (amended 2026-09-28, fix round 1): dropping a backlog past
    /// the room the sender already had takes the limit to exactly `q` --
    /// not the plain `+= head - sent_up_to` shift, which would land it
    /// strictly between the receiver's candidates (Important 1) -- and the
    /// repaint then waits for the `CREDIT` that rides the `Reset`'s ACK.
    #[test]
    fn a_desync_past_the_old_room_takes_the_limit_to_q_and_the_repaint_waits_for_credit() {
        let now = Instant::now();
        let mut tx = crediting_sender(0);
        tx.push(&vec![3u8; 300 * 1024]).expect("room");
        assert_eq!(send_and_ack_until_stopped(&mut tx, now), 300 * 1024);
        tx.push(&vec![4u8; 300 * 1024]).expect("room"); // queued, never sent -- head 600 KiB, past 512 KiB
        tx.mark_desynced();
        assert_eq!(
            tx.credit_limit(),
            Some(600 * 1024),
            "past the room -- the limit takes q"
        );
        assert_eq!(tx.begin_resync(), 600 * 1024);
        tx.push(b"repaint").expect("room");
        let frames = tx.frames_to_send(now, Duration::from_secs(1));
        assert!(
            !frames.iter().any(|f| matches!(f, StreamFrame::Data { .. })),
            "no room yet -- the repaint waits for a CREDIT past q"
        );
        assert!(tx.on_credit((600 * 1024 + 64 * 1024) as u32));
        let frames = tx.frames_to_send(now, Duration::from_secs(1));
        assert!(frames.iter().any(|f| matches!(
            f,
            StreamFrame::Data { offset, .. } if u64::from(*offset) == 600 * 1024
        )));
    }

    /// Spec §6.2: a receiver with credits keeps nothing past its newest
    /// limit -- DATA across it is cut there, the rest neither kept nor
    /// acknowledged -- and its cost cap is the credit window's.
    #[test]
    fn data_past_the_announced_limit_is_cut_there() {
        let mut rx = crediting_receiver(20);
        assert_eq!(rx.credit_limit(), Some(STREAM_WINDOW));
        assert_eq!(
            rx.cost_cap(),
            STREAM_WINDOW as usize + STREAM_WINDOW as usize / MAX_SEGMENT_SIZE * CHUNK_COST
        );
        deliver_in_order(&mut rx, STREAM_WINDOW - 100);
        assert_eq!(
            rx.on_data((STREAM_WINDOW - 100) as u32, vec![5u8; 1000])
                .len(),
            100
        );
        assert!(rx.on_data(STREAM_WINDOW as u32, vec![5u8; 10]).is_empty());
        assert_eq!(rx.ack(), STREAM_WINDOW as u32);
    }

    /// Spec §6.4: a step of consumption is announced; less is not worth a
    /// frame.
    #[test]
    fn a_step_of_consumption_is_announced_and_less_is_not() {
        let now = Instant::now();
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, 200 * 1024);
        rx.on_consumed(CREDIT_UPDATE_STEP - 1);
        assert_eq!(rx.credit_due(now, false), None);
        rx.on_consumed(1);
        let limit = STREAM_WINDOW + CREDIT_UPDATE_STEP;
        assert_eq!(
            rx.credit_due(now, false),
            Some(StreamFrame::Credit {
                stream_id: 20,
                limit: limit as u32
            })
        );
        assert_eq!(rx.credit_due(now, false), None, "said once");
        assert_eq!(rx.credit_limit(), Some(limit));
        assert_eq!(rx.unconsumed(), 200 * 1024 - CREDIT_UPDATE_STEP);
    }

    /// Spec §6.4 (amended fix round 3): a sender stopped at its limit hears
    /// of room of `CREDIT_UPDATE_STEP` or more at once and three times more,
    /// one rto apart; the PONGs carry it after that; once data goes past
    /// the old limit nothing more is said. Before that much room there is
    /// nothing to say: a stuck consumer costs no frames, and neither does a
    /// growth too small to feed it -- a whole segment used to be enough
    /// (fix round 2), but a sender stopped at `L = consumed_then + W` still
    /// has about `W` unconsumed held for it, so a growth short of
    /// `CREDIT_UPDATE_STEP` (a quarter of `W`) never actually frees the
    /// consumer; measured (fix round 3 report), it only multiplied
    /// `CREDIT`s for identical throughput.
    #[test]
    fn a_stopped_sender_hears_of_room_at_once_and_three_times_more() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, STREAM_WINDOW);
        assert_eq!(
            rx.credit_due(t0, false),
            None,
            "nothing taken, nothing to say"
        );
        assert_eq!(rx.credit_for_pong(t0, rto), None);
        assert_eq!(rx.credit_resend_deadline(rto), None);
        rx.on_consumed(CREDIT_UPDATE_STEP - 1);
        assert_eq!(
            rx.credit_due(t0, false),
            None,
            "less than a step frees nothing"
        );
        rx.on_consumed(1);
        let frame = StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
        };
        assert_eq!(rx.credit_due(t0, false), Some(frame.clone()));
        let mut at = t0;
        for repeat in 0..CREDIT_RESENDS {
            let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
            assert_eq!(due, at + rto, "repeat {repeat}");
            assert_eq!(rx.credit_resend(due - Duration::from_millis(1), rto), None);
            assert_eq!(rx.credit_resend(due, rto), Some(frame.clone()));
            at = due;
        }
        assert_eq!(
            rx.credit_resend_deadline(rto),
            None,
            "three, then the PONGs"
        );
        assert_eq!(
            rx.credit_for_pong(at, rto),
            None,
            "the repeat just went: no PONG copy within an rto of it"
        );
        assert_eq!(rx.credit_for_pong(at + rto, rto), Some(frame.clone()));
        assert_eq!(rx.on_data(STREAM_WINDOW as u32, vec![0u8; 10]).len(), 10);
        assert_eq!(
            rx.credit_for_pong(at + rto, rto),
            None,
            "the sender has the new limit"
        );
        assert_eq!(rx.credit_resend_deadline(rto), None);
    }

    /// R9 (fix round 4, spec §6.4 amended), shaped like the review's probe
    /// C: an `OnDelivery` stream whose data simply runs out 100 bytes short
    /// of an older limit -- every byte delivered is taken at once, and
    /// nothing more is coming -- is idle, not stopped. The earlier "within
    /// a segment" rule (fix round 3) read that 100-byte gap (less than
    /// `MAX_SEGMENT_SIZE`) as "possibly stopped" and kept the newest limit
    /// riding every PONG for as long as the stream stayed idle there. This
    /// test fails under that rule (the deadline and PONG assertions below
    /// return `Some`, not `None`) and passes under the exact one.
    #[test]
    fn an_idle_stream_short_of_an_older_limit_draws_nothing_ever() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        // 100 bytes short of the implicit limit: the stream's data simply
        // ends there, and every byte delivered is taken at once.
        deliver_in_order(&mut rx, STREAM_WINDOW - 100);
        rx.on_consumed(STREAM_WINDOW - 100);
        // The growth announces a second, newer limit -- so there is now an
        // "older" one (the implicit first) to be wrongly judged against.
        assert!(rx.credit_due(t0, false).is_some(), "growth is announced");
        assert_eq!(
            rx.credit_resend_deadline(rto),
            None,
            "not armed -- idle, not stopped"
        );
        assert_eq!(
            rx.credit_for_pong(t0, rto),
            None,
            "not armed -- idle, not stopped"
        );

        // Many PING intervals pass with nothing more ever arriving: still
        // nothing, for as long as the stream stays idle.
        let mut now = t0;
        for _ in 0..5 {
            now += Duration::from_millis(1500);
            assert_eq!(rx.credit_resend(now, rto), None, "no timer repeat");
            assert_eq!(rx.credit_for_pong(now, rto), None, "no PONG-borne CREDIT");
        }
    }

    /// Spec §6.4 as this plan corrects it (Review Focus 1; fix round 4): a
    /// `CREDIT` lost while the consumer stops at a step would, judged
    /// against the newest limit, leave the sender stopped at the older one
    /// for good -- nothing grows, no step fires. The receiver sees the
    /// sender stopped at the older limit it may still hold, and arms a
    /// repeat -- but does not send the newest again on the spot: it was
    /// just sent (the announcement above), well under an `rto` ago, so
    /// sending it again here would be a duplicate the sender cannot even
    /// have missed yet. The repeat's own timing (fix round 4, spec §6.4
    /// amended) is one `rto` after that announcement. A PONG in between
    /// carries nothing either (ruling R15, spec §6.4 amended): a PONG copy
    /// too waits an `rto` from the newest limit's last send. Once that
    /// long has passed, a PONG does carry it and counts as a send: the
    /// next repeat is then one `rto` after the PONG.
    #[test]
    fn a_lost_credit_is_repeated_once_the_sender_stops_at_the_older_limit() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, CREDIT_UPDATE_STEP);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        let newer = StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
        };
        assert_eq!(
            rx.credit_due(t0, false),
            Some(newer.clone()),
            "announced -- and lost"
        );
        // The sender, still at the implicit limit, stops there; the consumer
        // takes nothing more.
        deliver_in_order(&mut rx, STREAM_WINDOW - CREDIT_UPDATE_STEP);
        let t1 = t0 + Duration::from_millis(50);
        assert_eq!(
            rx.credit_due(t1, false),
            None,
            "armed, but the newest went out less than an rto ago"
        );
        assert_eq!(rx.credit_resend_deadline(rto), Some(t0 + rto));
        assert_eq!(
            rx.credit_for_pong(t1, rto),
            None,
            "a PONG within an rto of the announcement carries nothing"
        );
        assert_eq!(rx.credit_resend(t0 + rto, rto), Some(newer.clone()));
        let t2 = t0 + 2 * rto;
        assert_eq!(
            rx.credit_for_pong(t2, rto),
            Some(newer.clone()),
            "an rto after the repeat, a PONG carries it"
        );
        assert_eq!(
            rx.credit_resend_deadline(rto),
            Some(t2 + rto),
            "the PONG counts as a send too"
        );
        assert_eq!(rx.credit_resend(t2 + rto, rto), Some(newer));
    }

    /// Spec §6.5: a `Reset` counts what it skips as taken -- the delivered
    /// bytes not taken yet stay owed -- and any room is announced at once.
    #[test]
    fn a_reset_counts_what_it_skips_as_taken_and_announces_at_once() {
        let now = Instant::now();
        let mut rx = crediting_receiver(0);
        deliver_in_order(&mut rx, 10 * 1024);
        rx.on_consumed(4 * 1024);
        assert!(rx.on_reset(20 * 1024));
        assert_eq!(rx.unconsumed(), 6 * 1024);
        assert_eq!(
            rx.credit_due(now, true),
            Some(StreamFrame::Credit {
                stream_id: 0,
                limit: (STREAM_WINDOW + 14 * 1024) as u32
            })
        );
    }

    /// Spec §4.10.1: what is consumed never passes what was delivered.
    #[test]
    fn consumption_stops_at_what_was_delivered() {
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, 1000);
        rx.on_consumed(5000);
        assert_eq!(rx.unconsumed(), 0);
        deliver_in_order(&mut rx, 1000);
        assert_eq!(rx.unconsumed(), 1000);
    }

    /// Spec §4.14 with §6: limits and `CREDIT`s cross 2^32 as offsets do.
    #[test]
    fn credit_limits_cross_2_pow_32() {
        let start = u32::MAX - 100 * 1024 + 1;
        let mut tx = StreamSender::starting_at(20, start);
        tx.set_features(with_credits());
        let mut rx = StreamReceiver::starting_at(20, start);
        rx.set_features(with_credits());
        assert_eq!(tx.credit_limit(), Some(u64::from(start) + STREAM_WINDOW));
        deliver_in_order(&mut rx, 200 * 1024);
        rx.on_consumed(200 * 1024);
        let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(Instant::now(), false) else {
            panic!("a step was taken");
        };
        assert!(tx.on_credit(limit));
        let full = u64::from(start) + 200 * 1024 + STREAM_WINDOW;
        assert_eq!(tx.credit_limit(), Some(full));
        assert!(full > 1 << 32);
    }

    /// Spec §6.2: without `offset-wrap` a limit never passes `OFFSET_LIMIT`.
    #[test]
    fn without_offset_wrap_a_limit_stops_at_offset_limit() {
        let mut rx = StreamReceiver::starting_at(20, OFFSET_LIMIT - 1024);
        rx.set_features(Features::STREAM_CREDIT);
        assert_eq!(rx.credit_limit(), Some(u64::from(OFFSET_LIMIT)));
        assert_eq!(rx.on_data(OFFSET_LIMIT - 1024, vec![0u8; 2048]).len(), 1024);
    }

    /// PROBE A (review, fix round 1): a sender stopped at the implicit first
    /// limit, with several newer, unheard limits announced (every CREDIT
    /// before the outage was lost), desyncs; the one CREDIT that rides the
    /// Reset's ACK is lost too. §6.5's `on_reset` must still leave a live
    /// limit the sender's own shift lands on, so the receiver keeps
    /// repeating it -- under the plain `+=` shift this stalled for good.
    #[test]
    fn a_lost_post_reset_credit_is_still_repeated_past_unheard_limits() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut tx = crediting_sender(0);
        let mut rx = crediting_receiver(0);
        tx.push(&vec![1u8; 542 * 1024]).expect("room");
        // Delivered and consumed at once; every CREDIT the receiver computes
        // is lost -- the sender never learns of the room the receiver grants.
        loop {
            let frames = tx.frames_to_send(t0, rto);
            if frames.is_empty() {
                break;
            }
            for f in frames {
                if let StreamFrame::Data { offset, data, .. } = f {
                    let n = rx.on_data(offset, data).len() as u64;
                    rx.on_consumed(n);
                    let _ = rx.credit_due(t0, false); // lost
                }
            }
            let _ = tx.on_ack(rx.ack());
        }
        assert_eq!(
            tx.sent_up_to(),
            STREAM_WINDOW,
            "stopped at the implicit limit"
        );

        // A long outage: the sender drops its tail and resyncs at q; the
        // urgent CREDIT that rides the Reset's ACK is lost too.
        tx.mark_desynced();
        let q = tx.begin_resync();
        assert_eq!(q, 542 * 1024);
        tx.push(b"repaint").expect("room");
        let t1 = t0 + Duration::from_secs(12);
        assert!(rx.on_reset(q as u32));
        let _ = tx.on_ack(rx.ack());
        let lost = rx.credit_due(t1, true);
        assert!(lost.is_some(), "the urgent CREDIT is computed -- and lost");

        assert!(
            rx.credit_resend_deadline(rto).is_some() || rx.credit_for_pong(t1, rto).is_some(),
            "a lost post-Reset CREDIT must still be repeated: sender holds {:?}, receiver newest {:?}",
            tx.credit_limit(),
            rx.credit_limit()
        );
    }

    /// PROBE B (review, fix round 1): a stuck consumer (nothing taken) gets
    /// a Reset past every limit it ever announced. The sender already holds
    /// `q` after its own shift, so PONGs must not keep repeating a limit it
    /// already has (§6.6: a stuck consumer costs no frames).
    #[test]
    fn a_reset_past_every_limit_of_a_stuck_consumer_is_quiet() {
        let t0 = Instant::now();
        let mut rx = crediting_receiver(0);
        deliver_in_order(&mut rx, STREAM_WINDOW); // nothing consumed
        let q = STREAM_WINDOW + 100 * 1024;
        assert!(rx.on_reset(q as u32));
        let _ = rx.credit_due(t0, true);
        assert_eq!(
            rx.credit_for_pong(t0 + Duration::from_secs(10), Duration::from_millis(300)),
            None,
            "the sender already holds q from its own shift -- nothing to repeat"
        );
    }

    /// PROBE C (review, fix round 1): the desynced sender's own room is
    /// less than what the repaint needs, and the one urgent CREDIT that
    /// rides the Reset's ACK is lost. Nothing goes out until a CREDIT past
    /// `q` arrives; the receiver's later repeats and PONGs must still
    /// deliver one, and the repaint must complete. The partial fix (only
    /// `on_reset`'s drop-and-push-front, without correcting `mark_desynced`'s
    /// shift) still stalls here (review's Important 1).
    #[test]
    fn a_repaint_longer_than_the_room_still_completes_after_a_lost_urgent_credit() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut tx = crediting_sender(0);
        let mut rx = crediting_receiver(0);
        tx.push(&vec![1u8; 500 * 1024]).expect("room");
        loop {
            let frames = tx.frames_to_send(t0, rto);
            if frames.is_empty() {
                break;
            }
            for f in frames {
                if let StreamFrame::Data { offset, data, .. } = f {
                    let n = rx.on_data(offset, data).len() as u64;
                    rx.on_consumed(n);
                    let _ = rx.credit_due(t0, false); // lost
                }
            }
            let _ = tx.on_ack(rx.ack());
        }
        assert_eq!(tx.sent_up_to(), 500 * 1024);
        tx.push(&vec![2u8; 100 * 1024]).expect("room"); // output during the outage
        tx.mark_desynced();
        let q = tx.begin_resync();
        tx.push(&vec![3u8; 20 * 1024]).expect("room"); // the repaint
        let t1 = t0 + Duration::from_secs(12);
        assert!(rx.on_reset(q as u32));
        let lost = rx.credit_due(t1, true);
        assert!(lost.is_some(), "the urgent CREDIT is computed -- and lost");

        // Nothing goes out at first: the repaint is longer than the room the
        // sender gave itself.
        assert!(
            tx.frames_to_send(t1, rto)
                .iter()
                .all(|f| !matches!(f, StreamFrame::Data { .. })),
            "no room yet -- waiting for a CREDIT"
        );

        // The repeats and PONGs eventually deliver a CREDIT past q, and the
        // repaint completes.
        let mut now = t1;
        for _ in 0..5 {
            for f in tx.frames_to_send(now, rto) {
                if let StreamFrame::Data { offset, data, .. } = f {
                    let n = rx.on_data(offset, data).len() as u64;
                    rx.on_consumed(n);
                    if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, false) {
                        tx.on_credit(limit);
                    }
                }
            }
            let _ = tx.on_ack(rx.ack());
            if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_resend(now, rto) {
                tx.on_credit(limit);
            }
            if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_for_pong(now, rto) {
                tx.on_credit(limit);
            }
            now += Duration::from_secs(2);
        }
        assert_eq!(tx.sent_up_to(), q + 20 * 1024, "the repaint completed");
    }

    /// Spec §6.4: once data passes the limit currently being repeated, a
    /// sender that turns out stopped at the NEXT older limit gets its own
    /// fresh cycle of repeats -- "once for each limit it may be stopped at".
    /// (Fix round 3: each growth here is a full `CREDIT_UPDATE_STEP`, not a
    /// segment -- that is the only immediacy rule left for a sender that
    /// may be stopped.) Fresh does not mean immediate (fix round 4, spec
    /// §6.4 amended): the second limit was just announced moments ago, so
    /// arming its own cycle sends nothing on the spot -- its first repeat
    /// waits the same one `rto` from that announcement everyone else's
    /// does.
    #[test]
    fn a_second_older_limit_gets_its_own_fresh_repeats() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, STREAM_WINDOW);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        let first = StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
        };
        assert_eq!(rx.credit_due(t0, false), Some(first.clone()));
        let mut at = t0;
        for _ in 0..CREDIT_RESENDS {
            let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
            assert_eq!(rx.credit_resend(due, rto), Some(first.clone()));
            at = due;
        }
        assert_eq!(
            rx.credit_resend_deadline(rto),
            None,
            "the first limit's repeats are spent"
        );

        // A second CREDIT_UPDATE_STEP of consumption grows the newest
        // further, past a second, still-unheard limit.
        rx.on_consumed(CREDIT_UPDATE_STEP);
        let second = StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + 2 * CREDIT_UPDATE_STEP) as u32,
        };
        assert_eq!(rx.credit_due(at, false), Some(second.clone()));

        // Data reaches exactly the first limit -- the sender had it after
        // all -- so the first entry pops and the second becomes the oldest,
        // with no room to spare: possibly stopped there at once.
        assert_eq!(
            rx.on_data(STREAM_WINDOW as u32, vec![0u8; CREDIT_UPDATE_STEP as usize])
                .len() as u64,
            CREDIT_UPDATE_STEP
        );

        // Stopped again, now at the first limit's own successor: a fresh
        // cycle of repeats arms, but `second` was announced only moments
        // ago (the `credit_due(at, false)` call above) -- well under an
        // `rto` -- so nothing new goes out on the spot.
        let t2 = at + Duration::from_millis(50);
        assert_eq!(
            rx.credit_due(t2, false),
            None,
            "armed, but the newest went out less than an rto ago"
        );
        let due2 = rx
            .credit_resend_deadline(rto)
            .expect("the second limit gets its own repeats");
        assert_eq!(
            due2,
            at + rto,
            "one rto after `second` was announced, not after t2"
        );
        assert_eq!(rx.credit_resend(due2, rto), Some(second));
    }

    /// Spec §6.4: `urgent` still needs some growth to say anything. Once a
    /// limit has been announced, calling `credit_due` again with nothing
    /// consumed since says nothing new, `urgent` or not.
    #[test]
    fn urgent_with_nothing_grown_since_the_last_announcement_says_nothing() {
        let now = Instant::now();
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, 10 * 1024);
        rx.on_consumed(10 * 1024);
        assert!(rx.credit_due(now, true).is_some(), "growth is announced");
        assert_eq!(
            rx.credit_due(now, true),
            None,
            "urgent alone announces nothing new"
        );
    }

    /// Spec §6.2, §6.4: `accept_limit` is always the NEWEST announced limit
    /// -- data between an older one (where a sender may be stopped) and the
    /// newest is still inside the window, and is kept.
    #[test]
    fn data_between_an_older_limit_and_the_newest_is_kept() {
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, STREAM_WINDOW);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        let now = Instant::now();
        assert!(
            rx.credit_due(now, false).is_some(),
            "a newer limit is announced"
        );
        // The oldest announced limit (the implicit first one) is still
        // live -- the sender may be stopped there -- but data between it
        // and the newest limit is still accepted, only out of order.
        let past_the_old_limit = STREAM_WINDOW + 10 * 1024;
        assert_eq!(
            rx.on_data(past_the_old_limit as u32, vec![7u8; 1024]).len(),
            0,
            "out of order -- buffered, not yet delivered"
        );
        assert_eq!(rx.buffered_cost(), 1024 + CHUNK_COST, "kept, not dropped");
    }

    /// RE-REVIEW PROBE D (fix round 2): the repaint's DATA overtakes a lost
    /// first copy of the Reset (a `Reset` and the repaint behind it can
    /// travel in different datagrams). The receiver
    /// then learns of `q` with data past `q` already in hand -- proof the
    /// sender holds more than `q` -- and must not report "possibly stopped"
    /// at `q` regardless.
    #[test]
    fn a_repaint_that_overtakes_the_reset_does_not_report_stopped_at_q() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut tx = crediting_sender(0);
        let mut rx = crediting_receiver(0);
        tx.push(&vec![1u8; 100 * 1024]).expect("room");
        loop {
            let frames = tx.frames_to_send(t0, rto);
            if frames.is_empty() {
                break;
            }
            for f in frames {
                if let StreamFrame::Data { offset, data, .. } = f {
                    let n = rx.on_data(offset, data).len() as u64;
                    rx.on_consumed(n);
                    if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t0, false) {
                        tx.on_credit(limit);
                    }
                }
            }
            let _ = tx.on_ack(rx.ack());
        }
        assert_eq!(tx.sent_up_to(), 100 * 1024);
        tx.push(&vec![2u8; 50 * 1024]).expect("room"); // during the outage
        tx.mark_desynced();
        let q = tx.begin_resync();
        tx.push(&vec![3u8; 20 * 1024]).expect("room"); // the repaint
        let t1 = t0 + Duration::from_secs(12);
        // The Reset's first copy is lost; the repaint's DATA arrives.
        for f in tx.frames_to_send(t1, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t1, false) {
                    tx.on_credit(limit);
                }
            }
        }
        // The Reset's repeat arrives; its CREDIT reaches the sender.
        let t2 = t1 + rto;
        assert!(rx.on_reset(q as u32));
        if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t2, true) {
            tx.on_credit(limit);
        }
        let _ = tx.on_ack(rx.ack());
        assert_eq!(
            tx.credit_limit(),
            rx.credit_limit(),
            "the sender already holds the newest"
        );
        assert_eq!(
            rx.credit_resend_deadline(rto),
            None,
            "not possibly stopped -- data past q proves it"
        );
        assert_eq!(rx.credit_for_pong(t2, rto), None);

        // An idle screen afterward draws nothing: no repeats, no PONG-borne
        // CREDITs, over many PING intervals.
        let mut now = t2;
        for _ in 0..40 {
            for f in tx.frames_to_send(now, rto) {
                if let StreamFrame::Data { offset, data, .. } = f {
                    let n = rx.on_data(offset, data).len() as u64;
                    rx.on_consumed(n);
                    if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, false) {
                        tx.on_credit(limit);
                    }
                }
            }
            let _ = tx.on_ack(rx.ack());
            assert_eq!(rx.credit_resend(now, rto), None, "no repeat");
            assert_eq!(rx.credit_for_pong(now, rto), None, "no PONG-borne CREDIT");
            now += Duration::from_millis(1500);
        }
    }

    /// Spec §6.4 (fix round 2): a hostile run of forward `Reset`s of one
    /// byte each keeps `Credit::announced` at `CREDIT_ANNOUNCED_MAX + 1`
    /// entries at most -- one live for `q` (`on_reset`'s own push, never
    /// capped) plus `CREDIT_ANNOUNCED_MAX` from growth (`credit_due`'s
    /// capped push) -- and the distinct limit values it ever puts in a
    /// `CREDIT` frame stay bounded the same way: once growth is capped,
    /// every further `CREDIT` repeats the same frozen newest, not a fresh
    /// one. Without the cap both would grow by one per `Reset`, without
    /// bound.
    #[test]
    fn a_hostile_run_of_one_byte_resets_keeps_the_announced_list_and_its_credits_capped() {
        let mut rx = crediting_receiver(0);
        let now = Instant::now();
        let mut distinct_limits = std::collections::BTreeSet::new();
        for offset in 1..=200u32 {
            assert!(rx.on_reset(offset));
            if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, true) {
                distinct_limits.insert(limit);
            }
            let len = rx.credit.as_ref().unwrap().announced.len();
            assert!(
                len <= CREDIT_ANNOUNCED_MAX + 1,
                "announced grew past the cap after Reset {offset}: {len}"
            );
        }
        assert!(
            distinct_limits.len() <= CREDIT_ANNOUNCED_MAX + 1,
            "drew {} distinct CREDIT contents from 200 one-byte Resets",
            distinct_limits.len()
        );
    }

    /// Spec §6.4 (fix round 2; renamed and re-scoped by fix round 3's
    /// re-review, Minor 1): consumption that happens to land in exact
    /// `CREDIT_UPDATE_STEP` pieces never comes near `CREDIT_ANNOUNCED_MAX`
    /// -- every step is announced at once. This pins step-sized growth
    /// specifically, not every honest pattern: with the segment-while-
    /// possibly-stopped immediacy this test's old name claimed for it,
    /// smaller pieces filled the list instead (fix round 3's report, and
    /// the re-review's Minor 1). Fix round 3 removed that rule, so the
    /// bound now holds for any honest consumption pattern -- see
    /// `a_small_piece_consumer_behind_a_stopped_sender_draws_credits_only_per_step`.
    #[test]
    fn step_sized_consumption_never_hits_the_announced_cap() {
        let mut rx = crediting_receiver(20);
        let now = Instant::now();
        let mut announcements = 0;
        for _ in 0..40 {
            deliver_in_order(&mut rx, CREDIT_UPDATE_STEP);
            rx.on_consumed(CREDIT_UPDATE_STEP);
            if rx.credit_due(now, false).is_some() {
                announcements += 1;
            }
            let len = rx.credit.as_ref().unwrap().announced.len();
            assert!(
                len < CREDIT_ANNOUNCED_MAX,
                "an honest flow should stay far short of the cap: {len}"
            );
        }
        assert_eq!(
            announcements, 40,
            "every 128 KiB step is announced, exactly as without the cap"
        );
    }

    /// Spec §6.4 (fix round 3): a small-piece `Explicit` consumer (1 KiB
    /// pieces) behind a stopped sender draws a `CREDIT` only once per full
    /// `CREDIT_UPDATE_STEP` of consumption -- not once a segment, which is
    /// what let this family of scenarios draw 3.6x to 260x as many `CREDIT`s
    /// before this fix (fix round 3 report) -- plus the ordinary repeats if
    /// that one `CREDIT` is lost.
    #[test]
    fn a_small_piece_consumer_behind_a_stopped_sender_draws_credits_only_per_step() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, STREAM_WINDOW);
        let piece = 1024u64;
        let pieces_per_step = CREDIT_UPDATE_STEP / piece;
        let mut announced = 0u32;
        for _ in 0..pieces_per_step {
            rx.on_consumed(piece);
            if rx.credit_due(t0, false).is_some() {
                announced += 1;
            }
        }
        assert_eq!(
            announced, 1,
            "one CREDIT for the whole step, not one a piece"
        );
        let frame = StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
        };
        assert_eq!(rx.credit_limit(), Some(STREAM_WINDOW + CREDIT_UPDATE_STEP));

        // That one CREDIT, lost: the ordinary repeats still find it, one
        // rto apart, up to CREDIT_RESENDS times, then on the PONGs.
        let mut at = t0;
        for _ in 0..CREDIT_RESENDS {
            let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
            assert_eq!(rx.credit_resend(due, rto), Some(frame.clone()));
            at = due;
        }
        assert_eq!(rx.credit_resend_deadline(rto), None, "repeats spent");
        assert_eq!(rx.credit_for_pong(at + rto, rto), Some(frame));
    }

    /// Spec §6.4 (fix round 2): a sender stopped at the oldest of a FULL
    /// `announced` list still gets the newest repeated on schedule and on
    /// PONGs -- the cap only defers growth, it never stalls a stopped
    /// sender -- and once data passes the oldest entry, freeing a slot, the
    /// deferred growth is announced at last.
    #[test]
    fn a_stopped_sender_with_a_full_list_still_gets_repeats_then_the_deferred_growth() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        // Exactly the implicit first limit: the sender may be stopped there
        // from the first byte past it.
        deliver_in_order(&mut rx, STREAM_WINDOW);
        // CREDIT_ANNOUNCED_MAX - 1 rounds of one-byte consumption, urgent so
        // each announces regardless of CREDIT_UPDATE_STEP: fills the list to
        // the cap without ever moving highest_end (no more data arrives),
        // so the sender reads as stopped at the very first (oldest) limit
        // throughout.
        for _ in 0..CREDIT_ANNOUNCED_MAX - 1 {
            rx.on_consumed(1);
            assert!(rx.credit_due(t0, true).is_some());
        }
        assert_eq!(
            rx.credit.as_ref().unwrap().announced.len(),
            CREDIT_ANNOUNCED_MAX,
            "the list is at the cap"
        );
        let newest_before = rx.credit_limit().unwrap();

        // One more round of growth: deferred by the cap, not announced.
        rx.on_consumed(1);
        assert_eq!(
            rx.credit_due(t0, true),
            None,
            "the list is full -- this growth waits"
        );
        assert_eq!(
            rx.credit.as_ref().unwrap().announced.len(),
            CREDIT_ANNOUNCED_MAX,
            "still capped"
        );
        assert_eq!(
            rx.credit_limit(),
            Some(newest_before),
            "newest did not move"
        );

        // Still not stalled: the repeat armed on the very first call is
        // due, and fires.
        let due = rx
            .credit_resend_deadline(rto)
            .expect("a repeat is still due");
        assert_eq!(due, t0 + rto);
        assert_eq!(
            rx.credit_resend(due, rto),
            Some(StreamFrame::Credit {
                stream_id: 20,
                limit: newest_before as u32
            })
        );
        assert_eq!(
            rx.credit_for_pong(due + rto, rto),
            Some(StreamFrame::Credit {
                stream_id: 20,
                limit: newest_before as u32
            })
        );

        // Data passes the oldest entry by a single byte -- just enough --
        // and a slot frees.
        assert_eq!(rx.on_data(STREAM_WINDOW as u32, vec![0u8; 1]).len(), 1);
        assert_eq!(
            rx.credit.as_ref().unwrap().announced.len(),
            CREDIT_ANNOUNCED_MAX - 1,
            "the oldest popped"
        );

        // The deferred growth is announced at once.
        assert_eq!(
            rx.credit_due(t0, true),
            Some(StreamFrame::Credit {
                stream_id: 20,
                limit: (STREAM_WINDOW + CREDIT_ANNOUNCED_MAX as u64) as u32
            }),
            "the deferred growth is announced now that there is room"
        );
    }

    /// Spec §6.2 (fix round 2): with credits and without `offset-wrap`, a
    /// `Reset` past `OFFSET_LIMIT` is refused outright -- like one past
    /// `FULL_OFFSET_MAX` with `offset-wrap` -- so a credited limit never
    /// breaks the ceiling every credited limit keeps. A receiver without
    /// credits keeps its wider rule (`offset_end`, `u32::MAX` there).
    #[test]
    fn without_offset_wrap_a_credited_reset_past_offset_limit_is_refused() {
        let mut rx = StreamReceiver::new(0);
        rx.set_features(Features::STREAM_CREDIT); // credits, no offset-wrap
        assert!(
            !rx.on_reset(OFFSET_LIMIT + 1),
            "past OFFSET_LIMIT -- refused"
        );
        assert_eq!(rx.next_offset(), 0, "nothing moved");
        assert!(
            rx.on_reset(OFFSET_LIMIT),
            "exactly at OFFSET_LIMIT -- allowed"
        );
        assert_eq!(rx.next_offset(), u64::from(OFFSET_LIMIT));

        // A legacy receiver (no credits) keeps the wider rule: up to
        // `offset_end` (`u32::MAX` without `offset-wrap`), past
        // `OFFSET_LIMIT`.
        let mut legacy = StreamReceiver::new(0);
        assert!(
            legacy.on_reset(OFFSET_LIMIT + 1),
            "legacy: past OFFSET_LIMIT is fine"
        );
        assert_eq!(legacy.next_offset(), u64::from(OFFSET_LIMIT) + 1);
    }

    /// Minor 2 (fix round 1), pinned by fix round 2: an announce of a newer
    /// limit while a repeat cycle is still armed (`resends_left > 0`)
    /// refreshes `sent_at` -- the next repeat is due one `rto` after THAT
    /// announce, not after whenever the cycle was first armed.
    #[test]
    fn an_announce_during_an_armed_repeat_refreshes_the_next_deadline() {
        let t0 = Instant::now();
        let rto = Duration::from_millis(300);
        let mut rx = crediting_receiver(20);
        deliver_in_order(&mut rx, STREAM_WINDOW);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        // Arms the repeat cycle for the implicit first limit.
        assert!(rx.credit_due(t0, false).is_some());
        assert_eq!(rx.credit_resend_deadline(rto), Some(t0 + rto));

        // Part way to the first repeat, a second CREDIT_UPDATE_STEP of
        // growth is announced -- a real transmission of the newest limit --
        // while the cycle is still armed (resends_left == CREDIT_RESENDS,
        // untouched).
        let t1 = t0 + Duration::from_millis(100);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        assert!(
            rx.credit_due(t1, false).is_some(),
            "the growth is announced"
        );

        // The next repeat is due one rto after THAT announce, not after t0.
        assert_eq!(rx.credit_resend_deadline(rto), Some(t1 + rto));
    }
}
