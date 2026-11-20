//! Bounded framing and message codec for the frontend/owner socketpair.
//!
//! Frame: `QSHL | version:u16 | lane:u8 | kind:u8 | length:u32`, big endian,
//! then `length` payload bytes. The reader validates magic, version, lane,
//! kind and the per-kind length bound from the 12 header bytes alone, so a
//! hostile length never reaches an allocation. The message types are plain
//! data: custody objects (charges, permits, deliveries, oneshots) are
//! represented by owner queue positions (`u64` ids) and are never serialized.

use crate::channel::CHANNEL_SNAPSHOT_MAX;
use crate::shell_frame::CONTROL_RECORD_MAX;
use std::collections::VecDeque;

pub(crate) const LINK_VERSION: u16 = 1;
const MAGIC: [u8; 4] = *b"QSHL";
pub(crate) const HEADER_LEN: usize = 12;
/// Slack a frame payload may carry on top of its largest content: the fixed
/// fields (ids, origin context, stream, flags) of the widest message.
pub(crate) const FRAME_OVERHEAD: usize = 64;
/// Content bound for control records (the payload adds `FRAME_OVERHEAD`).
pub(crate) const CONTROL_FRAME_MAX: usize = CONTROL_RECORD_MAX;
/// Content bound for stream or channel data (the payload adds `FRAME_OVERHEAD`).
pub(crate) const DATA_FRAME_MAX: usize = 64 * 1024;
/// Content bound for `Snapshot` (the payload adds `FRAME_OVERHEAD`).
pub(crate) const SNAPSHOT_FRAME_MAX: usize = CHANNEL_SNAPSHOT_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkError {
    BadMagic,
    UnknownVersion,
    UnknownKind,
    BadLane,
    /// The declared or encoded payload exceeds the bound of its kind.
    TooLong,
    /// Input ended before a header, payload or field was complete.
    Truncated,
    /// A payload carried bytes past its last field.
    Trailing,
    /// A field held a value outside its enumeration.
    BadValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Lane {
    Data = 0,
    Priority = 1,
}

/// Attachment context as plain data (`features` is the raw bit set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ctx {
    pub generation: u64,
    pub session_id: u64,
    pub features: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GeometryOutcomeWire {
    Established,
    Applied,
    /// The resize refusal code.
    Refused(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GeometryWire {
    pub instance: u64,
    pub request_id: u64,
    pub outcome: GeometryOutcomeWire,
    pub cols: u16,
    pub rows: u16,
}

/// The owner's gate a charge counts on: its link-wide id and kind code
/// (0 screen, 1 pipe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWire {
    pub id: u64,
    pub kind: u8,
}

/// Immutable OPEN classification; `kind` is the channel kind code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpenWire {
    pub kind: u8,
    pub cols: u16,
    pub rows: u16,
    pub screen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutputBody {
    Data(Vec<u8>),
    Geometry(GeometryWire),
    EchoAck(u64),
    /// The output gap cause code.
    OutputGap(u8),
    DeliveryMarker {
        token: u64,
    },
}

/// A typed outbound record. `id` is the owner's queue position, and names the
/// custody objects (charge, permit, delivery) the owner keeps for it: each
/// one is `id` plus a fixed slot (see `owner_link`). A `charge` names the
/// gate its bytes count on; the charge's size follows from the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutRecord {
    RetirementReady {
        origin: Ctx,
        decisions_complete: bool,
    },
    ReservedControl {
        id: u64,
        origin: Ctx,
        bytes: Vec<u8>,
        charge: Option<GateWire>,
    },
    UpdateAccept {
        id: u64,
        origin: Ctx,
        bytes: Vec<u8>,
        charge: Option<GateWire>,
    },
    ReservedSessionControl {
        id: u64,
        bytes: Vec<u8>,
        charge: Option<GateWire>,
    },
    ResourceExhausted {
        origin: Ctx,
    },
    CloseSession {
        origin: Ctx,
    },
    RepaintBarrier {
        id: u64,
        generation: u64,
        sequence: u64,
    },
    ChannelClosed {
        id: u64,
        stream: u8,
        instance: u64,
        origin: Ctx,
    },
    ChannelOutput {
        id: u64,
        stream: u8,
        instance: u64,
        origin: Ctx,
        output: OutputBody,
        gate: GateWire,
        /// The record carries the pre-reserved gap/bootstrap allowance.
        gap_reserve: bool,
    },
    ChannelExit {
        id: u64,
        stream: u8,
        instance: u64,
        origin: Ctx,
        code: Option<i32>,
        open: OpenWire,
        /// Encoded length of the Exit record its reply reservation covers.
        control_bytes: u32,
        charge: Option<GateWire>,
    },
    ProtocolFailure {
        origin: Ctx,
        code: Option<u16>,
    },
    Data {
        stream: u8,
        data: Vec<u8>,
    },
    Resyncable {
        stream: u8,
        resyncable: bool,
    },
    StreamClass {
        stream: u8,
        bulk: bool,
    },
    Consumed {
        stream: u8,
        n: u64,
    },
    NotifyDelivered {
        stream: u8,
        token: u64,
    },
    ChannelOpened {
        stream: u8,
        origin: Ctx,
    },
    ChannelRefused {
        stream: u8,
        origin: Ctx,
        reason: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargeOp {
    /// Admission succeeded: move the charge to this connection tail.
    Transfer(u64),
    /// `headers` independently framed slices took `n` bytes of the charge
    /// into the connection, whose tail is `tail`; each owes the next slice
    /// one more 5-byte header.
    Slice {
        n: u64,
        tail: u64,
        headers: u64,
    },
    Withdraw,
}

/// One operation on an owner gate, by id (the frontend's mirror gates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOpWire {
    Admit(u64),
    Withdraw(u64),
    Transfer {
        n: u64,
        tail: u64,
    },
    /// `ready` is the `(instance, generation)` scope to wake if it opened.
    Update {
        tail: u64,
        ready: Option<(u64, u64)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetainedKind {
    Marker,
    Gap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndKind {
    Graceful,
    Destroy,
}

/// Frontend to owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToOwner {
    Data {
        stream: u8,
        data: Vec<u8>,
    },
    /// A leading piece of the next `Data` event (one event, one credit).
    DataPart(Vec<u8>),
    Live(Ctx),
    ResumeReset(Ctx),
    RepaintCutover {
        generation: u64,
        sequence: u64,
    },
    Repaint,
    Gate {
        gate: u64,
        op: GateOpWire,
    },
    Charge {
        id: u64,
        op: ChargeOp,
    },
    Progress {
        stream: u8,
        instance: u64,
        generation: u64,
    },
    Admitted {
        id: u64,
    },
    Released {
        id: u64,
    },
    Retained {
        id: u64,
        kind: RetainedKind,
    },
    Committed {
        id: u64,
    },
    Frontier {
        stream: u8,
        instance: u64,
        geometry: GeometryWire,
    },
    Unconfirmed {
        stream: u8,
        unconfirmed: bool,
    },
    MarkerDelivered {
        stream: u8,
        token: u64,
        generation: u64,
    },
    BudgetRetired {
        origin: Ctx,
    },
    Liveness {
        last_client_recv: u64,
    },
    End(EndKind),
}

/// Owner to frontend. Only `Terminal` travels on the priority lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToFrontend {
    /// Inbound credit: the owner has room for `slots` more events.
    Grant {
        slots: u32,
    },
    Record(OutRecord),
    /// A leading piece of the next record's data body (a body may exceed
    /// one data frame; a screen repaint is one record).
    DataPart(Vec<u8>),
    Snapshot {
        id: u64,
        generation: u64,
        prefix: u64,
        dto: Vec<u8>,
    },
    Terminal {
        origin: Ctx,
        disposition: u8,
    },
    /// Rebuild after a frontend death: journal items in position order, then
    /// the retained state, then `ReplayDone`.
    ReplayItem(OutRecord),
    ReplayFrontier {
        stream: u8,
        instance: u64,
        geometry: GeometryWire,
    },
    ReplayUnconfirmed {
        stream: u8,
        unconfirmed: bool,
    },
    ReplayRetained {
        id: u64,
        kind: RetainedKind,
    },
    ReplayDone {
        observed: u64,
    },
}

// Kind numbers. The frontend-to-owner kinds are 1..=0x3f, the owner-to-
// frontend kinds start at 0x40; `Record` and `ReplayItem` carry the record
// kind (0x80..) as their first payload byte.
const K_DATA: u8 = 1;
const K_LIVE: u8 = 2;
const K_RESUME_RESET: u8 = 3;
const K_REPAINT_CUTOVER: u8 = 4;
const K_GATE: u8 = 5;
const K_CHARGE: u8 = 6;
const K_PROGRESS: u8 = 7;
const K_ADMITTED: u8 = 8;
const K_RELEASED: u8 = 9;
const K_RETAINED: u8 = 10;
const K_COMMITTED: u8 = 11;
const K_FRONTIER: u8 = 12;
const K_UNCONFIRMED: u8 = 13;
const K_MARKER_DELIVERED: u8 = 14;
const K_BUDGET_RETIRED: u8 = 15;
const K_LIVENESS: u8 = 16;
const K_END: u8 = 17;
const K_REPAINT: u8 = 18;
const K_DATA_PART_IN: u8 = 19;
const K_GRANT: u8 = 0x40;
const K_RECORD: u8 = 0x41;
const K_SNAPSHOT: u8 = 0x44;
const K_TERMINAL: u8 = 0x45;
const K_REPLAY_ITEM: u8 = 0x46;
const K_REPLAY_FRONTIER: u8 = 0x47;
const K_REPLAY_UNCONFIRMED: u8 = 0x48;
const K_REPLAY_RETAINED: u8 = 0x49;
const K_REPLAY_DONE: u8 = 0x4a;
const K_DATA_PART: u8 = 0x4b;

const R_RETIREMENT_READY: u8 = 0x80;
const R_RESERVED_CONTROL: u8 = 0x81;
const R_UPDATE_ACCEPT: u8 = 0x82;
const R_RESERVED_SESSION_CONTROL: u8 = 0x83;
const R_RESOURCE_EXHAUSTED: u8 = 0x84;
const R_CLOSE_SESSION: u8 = 0x85;
const R_REPAINT_BARRIER: u8 = 0x86;
const R_CHANNEL_CLOSED: u8 = 0x87;
const R_CHANNEL_OUTPUT: u8 = 0x88;
const R_CHANNEL_EXIT: u8 = 0x89;
const R_PROTOCOL_FAILURE: u8 = 0x8a;
const R_DATA: u8 = 0x8b;
const R_RESYNCABLE: u8 = 0x8c;
const R_STREAM_CLASS: u8 = 0x8d;
const R_CONSUMED: u8 = 0x8e;
const R_NOTIFY_DELIVERED: u8 = 0x8f;
const R_CHANNEL_OPENED: u8 = 0x90;
const R_CHANNEL_REFUSED: u8 = 0x91;

fn known_kind(kind: u8) -> bool {
    matches!(
        kind,
        K_DATA..=K_DATA_PART_IN | K_GRANT | K_RECORD | K_SNAPSHOT..=K_DATA_PART
    )
}

fn kind_is_data(kind: u8) -> bool {
    matches!(
        kind,
        K_DATA | K_DATA_PART_IN | K_RECORD | K_REPLAY_ITEM | K_DATA_PART
    )
}

fn payload_bound(kind: u8) -> usize {
    FRAME_OVERHEAD + content_bound(kind)
}

fn content_bound(kind: u8) -> usize {
    if kind == K_SNAPSHOT {
        SNAPSHOT_FRAME_MAX
    } else if kind_is_data(kind) {
        DATA_FRAME_MAX
    } else {
        CONTROL_FRAME_MAX
    }
}

fn lane_of(kind: u8) -> Lane {
    if kind == K_TERMINAL {
        Lane::Priority
    } else {
        Lane::Data
    }
}

/// One framed, length-validated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    lane: Lane,
    kind: u8,
    payload: Vec<u8>,
}
#[cfg(test)]
impl Frame {
    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }
}

/// Incremental frame parser. `next` and `next_priority` take newly read bytes
/// (possibly empty) and return one complete frame, keeping the rest queued.
/// Any error is sticky: the link is dead and the caller parks the session.
pub(crate) struct FrameReader {
    header: [u8; HEADER_LEN],
    header_len: usize,
    body: Vec<u8>,
    want: usize,
    ready: VecDeque<Frame>,
    failed: Option<LinkError>,
}
impl FrameReader {
    pub(crate) fn new() -> Self {
        Self {
            header: [0; HEADER_LEN],
            header_len: 0,
            body: Vec::new(),
            want: 0,
            ready: VecDeque::new(),
            failed: None,
        }
    }

    /// Capacity of the payload buffer: zero until a header was accepted.
    #[cfg(test)]
    pub(crate) fn body_capacity(&self) -> usize {
        self.body.capacity()
    }

    #[cfg(test)]
    pub(crate) fn next(&mut self, buf: &[u8]) -> Result<Option<Frame>, LinkError> {
        self.feed(buf)?;
        Ok(self.ready.pop_front())
    }

    /// Like `next`, but a frame on the priority lane is returned before any
    /// queued data frame.
    pub(crate) fn next_priority(&mut self, buf: &[u8]) -> Result<Option<Frame>, LinkError> {
        self.feed(buf)?;
        match self.ready.iter().position(|f| f.lane == Lane::Priority) {
            Some(i) => Ok(self.ready.remove(i)),
            None => Ok(self.ready.pop_front()),
        }
    }

    /// End of input: an incomplete frame is a truncation.
    pub(crate) fn finish(&self) -> Result<(), LinkError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.header_len != 0 || self.want != 0 || !self.ready.is_empty() {
            return Err(LinkError::Truncated);
        }
        Ok(())
    }

    fn feed(&mut self, mut buf: &[u8]) -> Result<(), LinkError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        while !buf.is_empty() {
            if self.header_len < HEADER_LEN {
                let n = (HEADER_LEN - self.header_len).min(buf.len());
                self.header[self.header_len..self.header_len + n].copy_from_slice(&buf[..n]);
                self.header_len += n;
                buf = &buf[n..];
                if self.header_len == HEADER_LEN {
                    if let Err(e) = self.accept_header() {
                        self.failed = Some(e);
                        return Err(e);
                    }
                }
            } else {
                let n = (self.want - self.body.len()).min(buf.len());
                self.body.extend_from_slice(&buf[..n]);
                buf = &buf[n..];
            }
            if self.header_len == HEADER_LEN && self.body.len() == self.want {
                self.complete();
            }
        }
        Ok(())
    }

    fn accept_header(&mut self) -> Result<(), LinkError> {
        let h = &self.header;
        if h[..4] != MAGIC {
            return Err(LinkError::BadMagic);
        }
        if u16::from_be_bytes([h[4], h[5]]) != LINK_VERSION {
            return Err(LinkError::UnknownVersion);
        }
        if h[6] > Lane::Priority as u8 {
            return Err(LinkError::BadLane);
        }
        let kind = h[7];
        if !known_kind(kind) {
            return Err(LinkError::UnknownKind);
        }
        // Only `Terminal` may use the priority lane, and it must: a mislabeled
        // frame is never promoted by `next_priority`.
        if h[6] != lane_of(kind) as u8 {
            return Err(LinkError::BadLane);
        }
        let len = u32::from_be_bytes([h[8], h[9], h[10], h[11]]) as usize;
        if len > payload_bound(kind) {
            return Err(LinkError::TooLong);
        }
        self.want = len;
        self.body = Vec::with_capacity(len);
        Ok(())
    }

    fn complete(&mut self) {
        let lane = if self.header[6] == 0 {
            Lane::Data
        } else {
            Lane::Priority
        };
        self.ready.push_back(Frame {
            lane,
            kind: self.header[7],
            payload: std::mem::take(&mut self.body),
        });
        self.header_len = 0;
        self.want = 0;
    }
}

// ---- payload reader and writer ---------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], LinkError> {
        let end = self.pos.checked_add(len).ok_or(LinkError::Truncated)?;
        let b = self.bytes.get(self.pos..end).ok_or(LinkError::Truncated)?;
        self.pos = end;
        Ok(b)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], LinkError> {
        let mut a = [0; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, LinkError> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, LinkError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, LinkError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn i32(&mut self) -> Result<i32, LinkError> {
        Ok(i32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, LinkError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn bool(&mut self) -> Result<bool, LinkError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(LinkError::BadValue),
        }
    }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, LinkError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(LinkError::TooLong);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn ctx(&mut self) -> Result<Ctx, LinkError> {
        Ok(Ctx {
            generation: self.u64()?,
            session_id: self.u64()?,
            features: self.u32()?,
        })
    }
    fn gate(&mut self) -> Result<GateWire, LinkError> {
        Ok(GateWire {
            id: self.u64()?,
            kind: self.u8()?,
        })
    }
    fn opt_gate(&mut self) -> Result<Option<GateWire>, LinkError> {
        if self.bool()? {
            Ok(Some(self.gate()?))
        } else {
            Ok(None)
        }
    }
    fn geometry(&mut self) -> Result<GeometryWire, LinkError> {
        let instance = self.u64()?;
        let request_id = self.u64()?;
        let outcome = match self.u8()? {
            0 => GeometryOutcomeWire::Established,
            1 => GeometryOutcomeWire::Applied,
            2 => GeometryOutcomeWire::Refused(self.u8()?),
            _ => return Err(LinkError::BadValue),
        };
        Ok(GeometryWire {
            instance,
            request_id,
            outcome,
            cols: self.u16()?,
            rows: self.u16()?,
        })
    }
    fn open(&mut self) -> Result<OpenWire, LinkError> {
        Ok(OpenWire {
            kind: self.u8()?,
            cols: self.u16()?,
            rows: self.u16()?,
            screen: self.bool()?,
        })
    }
    fn retained(&mut self) -> Result<RetainedKind, LinkError> {
        match self.u8()? {
            0 => Ok(RetainedKind::Marker),
            1 => Ok(RetainedKind::Gap),
            _ => Err(LinkError::BadValue),
        }
    }
    fn finish(self) -> Result<(), LinkError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(LinkError::Trailing)
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8], max: usize) -> Result<(), LinkError> {
    if b.len() > max {
        return Err(LinkError::TooLong);
    }
    out.extend_from_slice(
        &u32::try_from(b.len())
            .map_err(|_| LinkError::TooLong)?
            .to_be_bytes(),
    );
    out.extend_from_slice(b);
    Ok(())
}
fn put_ctx(out: &mut Vec<u8>, c: Ctx) {
    out.extend_from_slice(&c.generation.to_be_bytes());
    out.extend_from_slice(&c.session_id.to_be_bytes());
    out.extend_from_slice(&c.features.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_gate(out: &mut Vec<u8>, g: GateWire) {
    put_u64(out, g.id);
    out.push(g.kind);
}
fn put_opt_gate(out: &mut Vec<u8>, g: Option<GateWire>) {
    match g {
        Some(g) => {
            out.push(1);
            put_gate(out, g);
        }
        None => out.push(0),
    }
}
fn put_geometry(out: &mut Vec<u8>, g: GeometryWire) {
    put_u64(out, g.instance);
    put_u64(out, g.request_id);
    match g.outcome {
        GeometryOutcomeWire::Established => out.push(0),
        GeometryOutcomeWire::Applied => out.push(1),
        GeometryOutcomeWire::Refused(code) => out.extend_from_slice(&[2, code]),
    }
    out.extend_from_slice(&g.cols.to_be_bytes());
    out.extend_from_slice(&g.rows.to_be_bytes());
}
fn put_open(out: &mut Vec<u8>, o: OpenWire) {
    out.push(o.kind);
    out.extend_from_slice(&o.cols.to_be_bytes());
    out.extend_from_slice(&o.rows.to_be_bytes());
    out.push(u8::from(o.screen));
}
fn put_retained(out: &mut Vec<u8>, k: RetainedKind) {
    out.push(match k {
        RetainedKind::Marker => 0,
        RetainedKind::Gap => 1,
    });
}

fn put_record(out: &mut Vec<u8>, r: &OutRecord) -> Result<(), LinkError> {
    match r {
        OutRecord::RetirementReady {
            origin,
            decisions_complete,
        } => {
            out.push(R_RETIREMENT_READY);
            put_ctx(out, *origin);
            out.push(u8::from(*decisions_complete));
        }
        OutRecord::ReservedControl {
            id,
            origin,
            bytes,
            charge,
        } => {
            out.push(R_RESERVED_CONTROL);
            put_u64(out, *id);
            put_ctx(out, *origin);
            put_opt_gate(out, *charge);
            put_bytes(out, bytes, CONTROL_FRAME_MAX)?;
        }
        OutRecord::UpdateAccept {
            id,
            origin,
            bytes,
            charge,
        } => {
            out.push(R_UPDATE_ACCEPT);
            put_u64(out, *id);
            put_ctx(out, *origin);
            put_opt_gate(out, *charge);
            put_bytes(out, bytes, CONTROL_FRAME_MAX)?;
        }
        OutRecord::ReservedSessionControl { id, bytes, charge } => {
            out.push(R_RESERVED_SESSION_CONTROL);
            put_u64(out, *id);
            put_opt_gate(out, *charge);
            put_bytes(out, bytes, CONTROL_FRAME_MAX)?;
        }
        OutRecord::ResourceExhausted { origin } => {
            out.push(R_RESOURCE_EXHAUSTED);
            put_ctx(out, *origin);
        }
        OutRecord::CloseSession { origin } => {
            out.push(R_CLOSE_SESSION);
            put_ctx(out, *origin);
        }
        OutRecord::RepaintBarrier {
            id,
            generation,
            sequence,
        } => {
            out.push(R_REPAINT_BARRIER);
            put_u64(out, *id);
            put_u64(out, *generation);
            put_u64(out, *sequence);
        }
        OutRecord::ChannelClosed {
            id,
            stream,
            instance,
            origin,
        } => {
            out.push(R_CHANNEL_CLOSED);
            put_u64(out, *id);
            out.push(*stream);
            put_u64(out, *instance);
            put_ctx(out, *origin);
        }
        OutRecord::ChannelOutput {
            id,
            stream,
            instance,
            origin,
            output,
            gate,
            gap_reserve,
        } => {
            out.push(R_CHANNEL_OUTPUT);
            put_u64(out, *id);
            out.push(*stream);
            put_u64(out, *instance);
            put_ctx(out, *origin);
            put_gate(out, *gate);
            out.push(u8::from(*gap_reserve));
            match output {
                OutputBody::Data(d) => {
                    out.push(0);
                    put_bytes(out, d, DATA_FRAME_MAX)?;
                }
                OutputBody::Geometry(g) => {
                    out.push(1);
                    put_geometry(out, *g);
                }
                OutputBody::EchoAck(v) => {
                    out.push(2);
                    put_u64(out, *v);
                }
                OutputBody::OutputGap(cause) => out.extend_from_slice(&[3, *cause]),
                OutputBody::DeliveryMarker { token } => {
                    out.push(4);
                    put_u64(out, *token);
                }
            }
        }
        OutRecord::ChannelExit {
            id,
            stream,
            instance,
            origin,
            code,
            open,
            control_bytes,
            charge,
        } => {
            out.push(R_CHANNEL_EXIT);
            put_u64(out, *id);
            out.push(*stream);
            put_u64(out, *instance);
            put_ctx(out, *origin);
            out.extend_from_slice(&control_bytes.to_be_bytes());
            put_opt_gate(out, *charge);
            match code {
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(&c.to_be_bytes());
                }
                None => out.push(0),
            }
            put_open(out, *open);
        }
        OutRecord::ProtocolFailure { origin, code } => {
            out.push(R_PROTOCOL_FAILURE);
            put_ctx(out, *origin);
            match code {
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(&c.to_be_bytes());
                }
                None => out.push(0),
            }
        }
        OutRecord::Data { stream, data } => {
            out.push(R_DATA);
            out.push(*stream);
            put_bytes(out, data, DATA_FRAME_MAX)?;
        }
        OutRecord::Resyncable { stream, resyncable } => {
            out.extend_from_slice(&[R_RESYNCABLE, *stream, u8::from(*resyncable)]);
        }
        OutRecord::StreamClass { stream, bulk } => {
            out.extend_from_slice(&[R_STREAM_CLASS, *stream, u8::from(*bulk)]);
        }
        OutRecord::Consumed { stream, n } => {
            out.extend_from_slice(&[R_CONSUMED, *stream]);
            put_u64(out, *n);
        }
        OutRecord::NotifyDelivered { stream, token } => {
            out.extend_from_slice(&[R_NOTIFY_DELIVERED, *stream]);
            put_u64(out, *token);
        }
        OutRecord::ChannelOpened { stream, origin } => {
            out.extend_from_slice(&[R_CHANNEL_OPENED, *stream]);
            put_ctx(out, *origin);
        }
        OutRecord::ChannelRefused {
            stream,
            origin,
            reason,
        } => {
            out.extend_from_slice(&[R_CHANNEL_REFUSED, *stream]);
            put_ctx(out, *origin);
            put_bytes(out, reason, CONTROL_FRAME_MAX)?;
        }
    }
    Ok(())
}

fn get_record(r: &mut Reader<'_>) -> Result<OutRecord, LinkError> {
    Ok(match r.u8()? {
        R_RETIREMENT_READY => OutRecord::RetirementReady {
            origin: r.ctx()?,
            decisions_complete: r.bool()?,
        },
        R_RESERVED_CONTROL => OutRecord::ReservedControl {
            id: r.u64()?,
            origin: r.ctx()?,
            charge: r.opt_gate()?,
            bytes: r.bytes(CONTROL_FRAME_MAX)?,
        },
        R_UPDATE_ACCEPT => OutRecord::UpdateAccept {
            id: r.u64()?,
            origin: r.ctx()?,
            charge: r.opt_gate()?,
            bytes: r.bytes(CONTROL_FRAME_MAX)?,
        },
        R_RESERVED_SESSION_CONTROL => OutRecord::ReservedSessionControl {
            id: r.u64()?,
            charge: r.opt_gate()?,
            bytes: r.bytes(CONTROL_FRAME_MAX)?,
        },
        R_RESOURCE_EXHAUSTED => OutRecord::ResourceExhausted { origin: r.ctx()? },
        R_CLOSE_SESSION => OutRecord::CloseSession { origin: r.ctx()? },
        R_REPAINT_BARRIER => OutRecord::RepaintBarrier {
            id: r.u64()?,
            generation: r.u64()?,
            sequence: r.u64()?,
        },
        R_CHANNEL_CLOSED => OutRecord::ChannelClosed {
            id: r.u64()?,
            stream: r.u8()?,
            instance: r.u64()?,
            origin: r.ctx()?,
        },
        R_CHANNEL_OUTPUT => {
            let id = r.u64()?;
            let stream = r.u8()?;
            let instance = r.u64()?;
            let origin = r.ctx()?;
            let gate = r.gate()?;
            let gap_reserve = r.bool()?;
            let output = match r.u8()? {
                0 => OutputBody::Data(r.bytes(DATA_FRAME_MAX)?),
                1 => OutputBody::Geometry(r.geometry()?),
                2 => OutputBody::EchoAck(r.u64()?),
                3 => OutputBody::OutputGap(r.u8()?),
                4 => OutputBody::DeliveryMarker { token: r.u64()? },
                _ => return Err(LinkError::BadValue),
            };
            OutRecord::ChannelOutput {
                id,
                stream,
                instance,
                origin,
                output,
                gate,
                gap_reserve,
            }
        }
        R_CHANNEL_EXIT => {
            let id = r.u64()?;
            let stream = r.u8()?;
            let instance = r.u64()?;
            let origin = r.ctx()?;
            let control_bytes = r.u32()?;
            let charge = r.opt_gate()?;
            let code = if r.bool()? { Some(r.i32()?) } else { None };
            OutRecord::ChannelExit {
                id,
                stream,
                instance,
                origin,
                code,
                open: r.open()?,
                control_bytes,
                charge,
            }
        }
        R_PROTOCOL_FAILURE => {
            let origin = r.ctx()?;
            let code = if r.bool()? { Some(r.u16()?) } else { None };
            OutRecord::ProtocolFailure { origin, code }
        }
        R_DATA => OutRecord::Data {
            stream: r.u8()?,
            data: r.bytes(DATA_FRAME_MAX)?,
        },
        R_RESYNCABLE => OutRecord::Resyncable {
            stream: r.u8()?,
            resyncable: r.bool()?,
        },
        R_STREAM_CLASS => OutRecord::StreamClass {
            stream: r.u8()?,
            bulk: r.bool()?,
        },
        R_CONSUMED => OutRecord::Consumed {
            stream: r.u8()?,
            n: r.u64()?,
        },
        R_NOTIFY_DELIVERED => OutRecord::NotifyDelivered {
            stream: r.u8()?,
            token: r.u64()?,
        },
        R_CHANNEL_OPENED => OutRecord::ChannelOpened {
            stream: r.u8()?,
            origin: r.ctx()?,
        },
        R_CHANNEL_REFUSED => OutRecord::ChannelRefused {
            stream: r.u8()?,
            origin: r.ctx()?,
            reason: r.bytes(CONTROL_FRAME_MAX)?,
        },
        _ => return Err(LinkError::UnknownKind),
    })
}

// ---- messages -------------------------------------------------------------

/// A message that can be framed and parsed.
pub(crate) trait LinkMessage: Sized {
    /// Append the kind and payload.
    fn write(&self, out: &mut Vec<u8>) -> Result<u8, LinkError>;
    fn decode(frame: &Frame) -> Result<Self, LinkError>;
}

/// Append one frame carrying `msg`. On error `out` is left unchanged.
pub(crate) fn encode<M: LinkMessage>(msg: &M, out: &mut Vec<u8>) -> Result<(), LinkError> {
    let start = out.len();
    out.extend_from_slice(&[0; HEADER_LEN]);
    let result = msg.write(out).and_then(|kind| {
        let len = out.len() - start - HEADER_LEN;
        if len > payload_bound(kind) {
            return Err(LinkError::TooLong);
        }
        let mut h = Vec::with_capacity(HEADER_LEN);
        h.extend_from_slice(&MAGIC);
        h.extend_from_slice(&LINK_VERSION.to_be_bytes());
        h.push(lane_of(kind) as u8);
        h.push(kind);
        h.extend_from_slice(
            &u32::try_from(len)
                .map_err(|_| LinkError::TooLong)?
                .to_be_bytes(),
        );
        out[start..start + HEADER_LEN].copy_from_slice(&h);
        Ok(())
    });
    if result.is_err() {
        out.truncate(start);
    }
    result
}

fn check_lane(frame: &Frame) -> Result<(), LinkError> {
    if frame.lane == lane_of(frame.kind) {
        Ok(())
    } else {
        Err(LinkError::BadLane)
    }
}

impl LinkMessage for ToOwner {
    fn write(&self, out: &mut Vec<u8>) -> Result<u8, LinkError> {
        Ok(match self {
            Self::Data { stream, data } => {
                out.push(*stream);
                put_bytes(out, data, DATA_FRAME_MAX)?;
                K_DATA
            }
            Self::Live(c) => {
                put_ctx(out, *c);
                K_LIVE
            }
            Self::ResumeReset(c) => {
                put_ctx(out, *c);
                K_RESUME_RESET
            }
            Self::RepaintCutover {
                generation,
                sequence,
            } => {
                put_u64(out, *generation);
                put_u64(out, *sequence);
                K_REPAINT_CUTOVER
            }
            Self::Repaint => K_REPAINT,
            Self::DataPart(d) => {
                put_bytes(out, d, DATA_FRAME_MAX)?;
                K_DATA_PART_IN
            }
            Self::Gate { gate, op } => {
                put_u64(out, *gate);
                match op {
                    GateOpWire::Admit(n) => {
                        out.push(0);
                        put_u64(out, *n);
                    }
                    GateOpWire::Withdraw(n) => {
                        out.push(1);
                        put_u64(out, *n);
                    }
                    GateOpWire::Transfer { n, tail } => {
                        out.push(2);
                        put_u64(out, *n);
                        put_u64(out, *tail);
                    }
                    GateOpWire::Update { tail, ready } => {
                        out.push(3);
                        put_u64(out, *tail);
                        match ready {
                            Some((instance, generation)) => {
                                out.push(1);
                                put_u64(out, *instance);
                                put_u64(out, *generation);
                            }
                            None => out.push(0),
                        }
                    }
                }
                K_GATE
            }
            Self::Charge { id, op } => {
                put_u64(out, *id);
                match op {
                    ChargeOp::Transfer(tail) => {
                        out.push(0);
                        put_u64(out, *tail);
                    }
                    ChargeOp::Withdraw => out.push(2),
                    ChargeOp::Slice { n, tail, headers } => {
                        out.push(3);
                        put_u64(out, *n);
                        put_u64(out, *tail);
                        put_u64(out, *headers);
                    }
                }
                K_CHARGE
            }
            Self::Progress {
                stream,
                instance,
                generation,
            } => {
                out.push(*stream);
                put_u64(out, *instance);
                put_u64(out, *generation);
                K_PROGRESS
            }
            Self::Admitted { id } => {
                put_u64(out, *id);
                K_ADMITTED
            }
            Self::Released { id } => {
                put_u64(out, *id);
                K_RELEASED
            }
            Self::Retained { id, kind } => {
                put_u64(out, *id);
                put_retained(out, *kind);
                K_RETAINED
            }
            Self::Committed { id } => {
                put_u64(out, *id);
                K_COMMITTED
            }
            Self::Frontier {
                stream,
                instance,
                geometry,
            } => {
                out.push(*stream);
                put_u64(out, *instance);
                put_geometry(out, *geometry);
                K_FRONTIER
            }
            Self::Unconfirmed {
                stream,
                unconfirmed,
            } => {
                out.extend_from_slice(&[*stream, u8::from(*unconfirmed)]);
                K_UNCONFIRMED
            }
            Self::MarkerDelivered {
                stream,
                token,
                generation,
            } => {
                out.push(*stream);
                put_u64(out, *token);
                put_u64(out, *generation);
                K_MARKER_DELIVERED
            }
            Self::BudgetRetired { origin } => {
                put_ctx(out, *origin);
                K_BUDGET_RETIRED
            }
            Self::Liveness { last_client_recv } => {
                put_u64(out, *last_client_recv);
                K_LIVENESS
            }
            Self::End(kind) => {
                out.push(match kind {
                    EndKind::Graceful => 0,
                    EndKind::Destroy => 1,
                });
                K_END
            }
        })
    }

    fn decode(frame: &Frame) -> Result<Self, LinkError> {
        check_lane(frame)?;
        let mut r = Reader::new(&frame.payload);
        let msg = match frame.kind {
            K_DATA => Self::Data {
                stream: r.u8()?,
                data: r.bytes(DATA_FRAME_MAX)?,
            },
            K_LIVE => Self::Live(r.ctx()?),
            K_RESUME_RESET => Self::ResumeReset(r.ctx()?),
            K_REPAINT_CUTOVER => Self::RepaintCutover {
                generation: r.u64()?,
                sequence: r.u64()?,
            },
            K_REPAINT => Self::Repaint,
            K_DATA_PART_IN => Self::DataPart(r.bytes(DATA_FRAME_MAX)?),
            K_GATE => {
                let gate = r.u64()?;
                let op = match r.u8()? {
                    0 => GateOpWire::Admit(r.u64()?),
                    1 => GateOpWire::Withdraw(r.u64()?),
                    2 => GateOpWire::Transfer {
                        n: r.u64()?,
                        tail: r.u64()?,
                    },
                    3 => GateOpWire::Update {
                        tail: r.u64()?,
                        ready: if r.bool()? {
                            Some((r.u64()?, r.u64()?))
                        } else {
                            None
                        },
                    },
                    _ => return Err(LinkError::BadValue),
                };
                Self::Gate { gate, op }
            }
            K_CHARGE => {
                let id = r.u64()?;
                let op = match r.u8()? {
                    0 => ChargeOp::Transfer(r.u64()?),
                    2 => ChargeOp::Withdraw,
                    3 => ChargeOp::Slice {
                        n: r.u64()?,
                        tail: r.u64()?,
                        headers: r.u64()?,
                    },
                    _ => return Err(LinkError::BadValue),
                };
                Self::Charge { id, op }
            }
            K_PROGRESS => Self::Progress {
                stream: r.u8()?,
                instance: r.u64()?,
                generation: r.u64()?,
            },
            K_ADMITTED => Self::Admitted { id: r.u64()? },
            K_RELEASED => Self::Released { id: r.u64()? },
            K_RETAINED => Self::Retained {
                id: r.u64()?,
                kind: r.retained()?,
            },
            K_COMMITTED => Self::Committed { id: r.u64()? },
            K_FRONTIER => Self::Frontier {
                stream: r.u8()?,
                instance: r.u64()?,
                geometry: r.geometry()?,
            },
            K_UNCONFIRMED => Self::Unconfirmed {
                stream: r.u8()?,
                unconfirmed: r.bool()?,
            },
            K_MARKER_DELIVERED => Self::MarkerDelivered {
                stream: r.u8()?,
                token: r.u64()?,
                generation: r.u64()?,
            },
            K_BUDGET_RETIRED => Self::BudgetRetired { origin: r.ctx()? },
            K_LIVENESS => Self::Liveness {
                last_client_recv: r.u64()?,
            },
            K_END => Self::End(match r.u8()? {
                0 => EndKind::Graceful,
                1 => EndKind::Destroy,
                _ => return Err(LinkError::BadValue),
            }),
            _ => return Err(LinkError::UnknownKind),
        };
        r.finish()?;
        Ok(msg)
    }
}

impl LinkMessage for ToFrontend {
    fn write(&self, out: &mut Vec<u8>) -> Result<u8, LinkError> {
        Ok(match self {
            Self::Grant { slots } => {
                out.extend_from_slice(&slots.to_be_bytes());
                K_GRANT
            }
            Self::Record(r) => {
                put_record(out, r)?;
                K_RECORD
            }
            Self::DataPart(d) => {
                put_bytes(out, d, DATA_FRAME_MAX)?;
                K_DATA_PART
            }
            Self::Snapshot {
                id,
                generation,
                prefix,
                dto,
            } => {
                put_u64(out, *id);
                put_u64(out, *generation);
                put_u64(out, *prefix);
                put_bytes(out, dto, SNAPSHOT_FRAME_MAX)?;
                K_SNAPSHOT
            }
            Self::Terminal {
                origin,
                disposition,
            } => {
                put_ctx(out, *origin);
                out.push(*disposition);
                K_TERMINAL
            }
            Self::ReplayItem(r) => {
                put_record(out, r)?;
                K_REPLAY_ITEM
            }
            Self::ReplayFrontier {
                stream,
                instance,
                geometry,
            } => {
                out.push(*stream);
                put_u64(out, *instance);
                put_geometry(out, *geometry);
                K_REPLAY_FRONTIER
            }
            Self::ReplayUnconfirmed {
                stream,
                unconfirmed,
            } => {
                out.extend_from_slice(&[*stream, u8::from(*unconfirmed)]);
                K_REPLAY_UNCONFIRMED
            }
            Self::ReplayRetained { id, kind } => {
                put_u64(out, *id);
                put_retained(out, *kind);
                K_REPLAY_RETAINED
            }
            Self::ReplayDone { observed } => {
                put_u64(out, *observed);
                K_REPLAY_DONE
            }
        })
    }

    fn decode(frame: &Frame) -> Result<Self, LinkError> {
        check_lane(frame)?;
        let mut r = Reader::new(&frame.payload);
        let msg = match frame.kind {
            K_GRANT => Self::Grant { slots: r.u32()? },
            K_RECORD => Self::Record(get_record(&mut r)?),
            K_DATA_PART => Self::DataPart(r.bytes(DATA_FRAME_MAX)?),
            K_SNAPSHOT => Self::Snapshot {
                id: r.u64()?,
                generation: r.u64()?,
                prefix: r.u64()?,
                dto: r.bytes(SNAPSHOT_FRAME_MAX)?,
            },
            K_TERMINAL => Self::Terminal {
                origin: r.ctx()?,
                disposition: r.u8()?,
            },
            K_REPLAY_ITEM => Self::ReplayItem(get_record(&mut r)?),
            K_REPLAY_FRONTIER => Self::ReplayFrontier {
                stream: r.u8()?,
                instance: r.u64()?,
                geometry: r.geometry()?,
            },
            K_REPLAY_UNCONFIRMED => Self::ReplayUnconfirmed {
                stream: r.u8()?,
                unconfirmed: r.bool()?,
            },
            K_REPLAY_RETAINED => Self::ReplayRetained {
                id: r.u64()?,
                kind: r.retained()?,
            },
            K_REPLAY_DONE => Self::ReplayDone { observed: r.u64()? },
            _ => return Err(LinkError::UnknownKind),
        };
        r.finish()?;
        Ok(msg)
    }
}
