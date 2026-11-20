//! The frontend/owner link (#529 M1): one session's backend runs behind a
//! byte link, and the network frontend's bridge talks to it as if it were
//! in-process.
//!
//! The owner side ([`OwnerLink`]) builds a real [`SessionIo`] and runs the
//! session's backend on it unchanged, taking the bridge's place on that io's
//! queues. The frontend side ([`RemoteBackend`]) is a [`SessionBackend`]: the
//! bridge hands it the frontend's own io, and it relays inbound events to the
//! owner and pushes the owner's outbound records into the bridge's queue.
//!
//! The owner is authoritative for every session-lived object: gates, the
//! snapshot mailbox, the session control and every reply, timeline and charge
//! reservation. A record that crosses carries only ids. The frontend holds
//! *tokens* in their place -- remote variants of `OutputCharge`,
//! `TimelinePermit` and `ResponsePermit`, and a local oneshot for an update
//! acceptance -- whose operations and drop send the matching message back, so
//! every release point of the unchanged bridge code reaches the owner. A gate
//! the bridge charges on its own (gap and bootstrap records, tail refreshes)
//! is a mirror whose byte operations go to the owner's real gate.
//!
//! Ids are owner queue positions: every forwarded record that carries custody
//! takes the next position `p`, and its custody objects are `p << 2 | slot`
//! ([`SLOT_CHARGE`], [`SLOT_PERMIT`], [`SLOT_PART`], [`SLOT_COMMIT`]).
//!
//! Inbound events cross on credit: the owner grants one slot per free place
//! in the backend's bounded inbound queue, so at most `INBOUND_CAP` events are
//! ever between the bridge's queue and the backend, and the bridge's own
//! queue, `PENDING_CAP` and its "handed over" moment keep their meaning.
//!
//! The link runs over any byte stream ([`LinkIo`]): one end of a Unix
//! socket pair to an owner process an [`OwnerStarter`] started, or an
//! in-process [`loopback`] (tests).
//!
//! **Handing an event over.** The bridge books an inbound event as handed
//! over when it takes a credit and enters the frontend's queue. The
//! frontend's writer drains that queue into the socket as soon as it is
//! woken, without waiting to fill a batch; a write waits only while the
//! owner's socket buffer is full, that is while the owner does not read.
//! What the frontend has written stays readable in the socket after the
//! frontend dies. So the window in which a booked event can still be lost
//! is the events in the queue, or in a batch being written, when the
//! frontend process dies -- at most the owner's credits (`INBOUND_CAP`).
//! They are lost, never duplicated: nothing is ever sent twice, and the
//! owner applies only whole frames, so a frame cut by the death is dropped.
//!
//! **A stalled or dead owner.** The frontend's queue has no fixed cap;
//! every kind of message in it is bounded by what produces it (see
//! `Coalesce`), so an owner that stops reading holds the queue at those
//! bounds. An owner that dies fails the next write, and the failed link
//! clears the queue.
//!
//! Not yet here (Task 5): the custody journal and the rebuild of a new
//! frontend's bridge. The owner records the frontend's `Retained`, `Frontier`
//! and `Unconfirmed` reports but does not act on them, and a link lost
//! without an explicit `End` parks the backend for good.

#[path = "owner_link_codec.rs"]
pub(crate) mod codec;
#[cfg(test)]
#[path = "owner_link_codec_tests.rs"]
mod codec_tests;
#[cfg(test)]
#[path = "owner_link_tests.rs"]
mod tests;

use super::*;
use crate::channel::{ChannelKind, OpenClassification};
use crate::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause, ProtocolErrorCode,
    ResizeRefusal,
};
use crate::channel_timeline::{RemotePermit, RemoteTimeline, Retention, TimelineBudget};
use crate::control_budget::{RemoteClass, RemoteResponse, ResponsePart, ResponsePermit};
use crate::send_gate::{GateMirror, GateOp};
use codec::Frame;
use codec::*;
use std::sync::Weak;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Custody slot of a record's byte charge.
const SLOT_CHARGE: u64 = 0;
/// Custody slot of a record's timeline permit (a snapshot's merged permit).
const SLOT_PERMIT: u64 = 1;
/// Custody slot of a record's reply part, a gap reserve, or a snapshot's
/// wire permit.
const SLOT_PART: u64 = 2;
/// Custody slot of an update acceptance's commit receipt, or a snapshot's
/// source permit.
const SLOT_COMMIT: u64 = 3;
/// A record's gap/bootstrap reserve shares the part slot: no record carries both.
const SLOT_GAP_RESERVE: u64 = SLOT_PART;

/// The largest charge a frontend may admit on its own (a slice header, a gap
/// or a bootstrap geometry record); anything larger is a protocol error.
const MAX_LINK_ADMIT: u64 = 64;
/// Inbound slots the owner keeps back for events it makes itself
/// (`Writable`, `OutputReady`), so a frontend holding every granted credit
/// can never starve them.
const SYNTH_RESERVE: usize = 16;
/// Most credits outstanding at the frontend.
const MAX_GRANT: usize = INBOUND_CAP - SYNTH_RESERVE;
/// Bytes read from the link per turn; `FrameReader` queues at most the
/// frames of one chunk.
const READ_CHUNK: usize = 16 * 1024;
/// Bytes one writer turn batches before writing.
const WRITE_BATCH: usize = 64 * 1024;
/// Largest data record body the frontend joins from `DataPart` pieces. A
/// screen repaint is one record; its size follows the screen model's, which
/// the owner's screen budget bounds well below this.
const MAX_DATA_RECORD: usize = 1 << 30;
/// In-memory buffer of each direction of a loopback link.
const LOOPBACK_BUFFER: usize = 256 * 1024;

/// One end of an in-process link.
pub type LinkEnd = tokio::io::DuplexStream;

/// An in-process duplex byte pipe: the frontend and owner talk through the
/// real codec, in one process.
pub fn loopback() -> (LinkEnd, LinkEnd) {
    tokio::io::duplex(LOOPBACK_BUFFER)
}

/// Any byte stream a link can run over: an in-process [`loopback`] end, or
/// one end of a Unix stream socket pair to an owner process.
pub trait LinkIo: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> LinkIo for T {}

/// Starts the owner of one cold-created session somewhere else (an owner
/// process), and hands back the frontend's end of its link.
///
/// Called on the bridge's task inside the runtime, once per session, before
/// the bridge's first event. Whatever the frontend writes before the owner
/// reads it waits in the link's own buffer. An error ends the session as a
/// backend that stopped at once.
pub trait OwnerStarter: Send + Sync + 'static {
    fn start(&self, init: OwnerInit) -> std::io::Result<Box<dyn LinkIo>>;
}

// ---- wire conversions ------------------------------------------------------

fn ctx_wire(c: AttachmentContext) -> Ctx {
    Ctx {
        generation: c.generation,
        session_id: c.session_id,
        features: c.features.bits(),
    }
}
fn ctx_from(c: Ctx) -> AttachmentContext {
    AttachmentContext {
        generation: c.generation,
        session_id: c.session_id,
        features: crate::Features::from_bits(c.features),
    }
}
fn instance_from(raw: u64) -> Result<ChannelInstance, LinkError> {
    ChannelInstance::new(raw).ok_or(LinkError::BadValue)
}
fn geometry_wire(g: GeometryRecord) -> GeometryWire {
    GeometryWire {
        instance: g.instance.get(),
        request_id: g.request_id,
        outcome: match g.outcome {
            GeometryOutcome::Established => GeometryOutcomeWire::Established,
            GeometryOutcome::Applied => GeometryOutcomeWire::Applied,
            GeometryOutcome::Refused(r) => GeometryOutcomeWire::Refused(r as u8),
        },
        cols: g.cols,
        rows: g.rows,
    }
}
fn geometry_from(g: GeometryWire) -> Result<GeometryRecord, LinkError> {
    Ok(GeometryRecord {
        instance: instance_from(g.instance)?,
        request_id: g.request_id,
        outcome: match g.outcome {
            GeometryOutcomeWire::Established => GeometryOutcome::Established,
            GeometryOutcomeWire::Applied => GeometryOutcome::Applied,
            GeometryOutcomeWire::Refused(code) => {
                GeometryOutcome::Refused(ResizeRefusal::from_wire(code).ok_or(LinkError::BadValue)?)
            }
        },
        cols: g.cols,
        rows: g.rows,
    })
}
fn open_wire(o: OpenClassification) -> OpenWire {
    OpenWire {
        kind: match o.kind {
            ChannelKind::Shell => 0,
            ChannelKind::Command => 1,
        },
        cols: o.cols,
        rows: o.rows,
        screen: o.screen,
    }
}
fn open_from(o: OpenWire) -> Result<OpenClassification, LinkError> {
    Ok(OpenClassification {
        kind: match o.kind {
            0 => ChannelKind::Shell,
            1 => ChannelKind::Command,
            _ => return Err(LinkError::BadValue),
        },
        cols: o.cols,
        rows: o.rows,
        screen: o.screen,
    })
}
fn gate_kind_wire(kind: GateKind) -> u8 {
    match kind {
        GateKind::Screen => 0,
        GateKind::Pipe => 1,
    }
}
fn gate_kind_from(kind: u8) -> Result<GateKind, LinkError> {
    match kind {
        0 => Ok(GateKind::Screen),
        1 => Ok(GateKind::Pipe),
        _ => Err(LinkError::BadValue),
    }
}
fn disposition_wire(d: TerminalDisposition) -> u8 {
    match d {
        TerminalDisposition::Close => 0,
        TerminalDisposition::ResourceExhausted => 1,
    }
}
fn disposition_from(d: u8) -> Result<TerminalDisposition, LinkError> {
    match d {
        0 => Ok(TerminalDisposition::Close),
        1 => Ok(TerminalDisposition::ResourceExhausted),
        _ => Err(LinkError::BadValue),
    }
}

pub(super) fn budget_retired(origin: AttachmentContext) -> ToOwner {
    ToOwner::BudgetRetired {
        origin: ctx_wire(origin),
    }
}

// ---- framed byte I/O ---------------------------------------------------------

/// Reads whole frames off a link, in bounded chunks.
struct LinkReader<R> {
    read: R,
    frames: FrameReader,
    buf: Box<[u8]>,
}
impl<R: AsyncRead + Unpin> LinkReader<R> {
    fn new(read: R) -> Self {
        Self {
            read,
            frames: FrameReader::new(),
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
        }
    }
    /// The next frame, priority lane first; `None` at a clean end of input.
    /// Cancel-safe: bytes are consumed only by a completed read.
    async fn next(&mut self) -> Result<Option<Frame>, LinkError> {
        loop {
            if let Some(frame) = self.frames.next_priority(&[])? {
                return Ok(Some(frame));
            }
            let n = match self.read.read(&mut self.buf).await {
                Ok(n) => n,
                Err(_) => return Err(LinkError::Truncated),
            };
            if n == 0 {
                self.frames.finish()?;
                return Ok(None);
            }
            if let Some(frame) = self.frames.next_priority(&self.buf[..n])? {
                return Ok(Some(frame));
            }
        }
    }
}

/// A link that failed on its writing side: both ends must see it.
#[derive(Default)]
struct LinkFailure {
    failed: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}
impl LinkFailure {
    fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    async fn failed(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.failed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// Write `out`, or on failure mark the link failed and shut the write half:
/// dropping one half of a split stream would not tell the peer anything.
async fn write_or_fail<W: AsyncWrite + Unpin>(
    write: &mut W,
    out: &[u8],
    failure: &LinkFailure,
) -> bool {
    if write.write_all(out).await.is_ok() {
        return true;
    }
    failure.fail();
    let _ = write.shutdown().await;
    false
}

async fn encode_failed<W: AsyncWrite + Unpin>(write: &mut W, failure: &LinkFailure) {
    log::error!("owner link: a message exceeds its frame bound; closing the link");
    failure.fail();
    let _ = write.shutdown().await;
}

/// The owner's writer: `priority` first, until both senders are gone (then
/// the write half is shut, an orderly end of input), a write fails, or the
/// session's lifecycle stops.
async fn owner_write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    mut data: mpsc::UnboundedReceiver<ToFrontend>,
    mut priority: mpsc::UnboundedReceiver<ToFrontend>,
    failure: Arc<LinkFailure>,
    lifecycle: Arc<Lifecycle>,
) {
    let mut out = Vec::new();
    loop {
        let first = tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => return,
            Some(m) = priority.recv() => m,
            m = data.recv() => match m {
                Some(m) => m,
                // Every sender is gone; what is left on the priority lane
                // still goes out before the end of input.
                None => match priority.try_recv() {
                    Ok(m) => m,
                    Err(_) => break,
                },
            },
        };
        out.clear();
        if encode(&first, &mut out).is_err() {
            return encode_failed(&mut write, &failure).await;
        }
        while out.len() < WRITE_BATCH {
            let next = priority.try_recv().or_else(|_| data.try_recv());
            let Ok(m) = next else { break };
            if encode(&m, &mut out).is_err() {
                return encode_failed(&mut write, &failure).await;
            }
        }
        if !write_or_fail(&mut write, &out, &failure).await {
            return;
        }
    }
    let _ = write.flush().await;
    let _ = write.shutdown().await;
}

/// The frontend's writer: drains its queue until every sender is gone, a
/// write fails, or the lifecycle stops.
async fn frontend_write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    queue: Arc<LinkQueue>,
    failure: Arc<LinkFailure>,
    lifecycle: Arc<Lifecycle>,
) {
    let mut batch = Vec::new();
    let mut out = Vec::new();
    loop {
        let more = tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => return,
            more = queue.next_batch(&mut batch) => more,
        };
        match more {
            Batch::Messages => {}
            Batch::End | Batch::Failed => break,
        }
        out.clear();
        for m in batch.drain(..) {
            if encode(&m, &mut out).is_err() {
                queue.fail();
                return encode_failed(&mut write, &failure).await;
            }
        }
        if !write_or_fail(&mut write, &out, &failure).await {
            queue.fail();
            return;
        }
    }
    let _ = write.flush().await;
    let _ = write.shutdown().await;
}

// ---- frontend tokens ---------------------------------------------------------

/// A queued message that a newer one of the same key supersedes (or, for a
/// charge's slices, absorbs).
///
/// Nothing in the frontend's queue is ever dropped, and its size is bounded
/// by what produces it, not by a number:
/// - inbound events, by the owner's credits (at most `INBOUND_CAP`);
/// - tail, progress, frontier and confirmation reports, by their keys (gates,
///   stream instances, streams), since a newer one replaces a queued one;
/// - a charge's slices, one entry per charge, merged;
/// - every release, transfer, commit, admission or retention report, and a
///   bridge charge's admission, by the owner's custody objects and the
///   bridge's own records, each of which reports at most once;
/// - `End` and budget retirement, once per session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Coalesce {
    Update(u64),
    Progress(u8, u64),
    Unconfirmed(u8),
    Frontier(u8),
    Slice(u64),
}
fn coalesce_key(msg: &ToOwner) -> Option<Coalesce> {
    match msg {
        ToOwner::Gate {
            gate,
            op: GateOpWire::Update { .. },
        } => Some(Coalesce::Update(*gate)),
        ToOwner::Progress {
            stream, instance, ..
        } => Some(Coalesce::Progress(*stream, *instance)),
        ToOwner::Unconfirmed { stream, .. } => Some(Coalesce::Unconfirmed(*stream)),
        ToOwner::Frontier { stream, .. } => Some(Coalesce::Frontier(*stream)),
        ToOwner::Charge {
            id,
            op: ChargeOp::Slice { .. },
        } => Some(Coalesce::Slice(*id)),
        _ => None,
    }
}

/// `older` slices of a charge folded into the queued `newer` ones.
fn absorb(newer: &mut ToOwner, older: ToOwner) {
    if let (
        ToOwner::Charge {
            op:
                ChargeOp::Slice {
                    n: total,
                    headers: count,
                    ..
                },
            ..
        },
        ToOwner::Charge {
            op: ChargeOp::Slice { n, headers, .. },
            ..
        },
    ) = (newer, older)
    {
        *total = total.saturating_add(n);
        *count = count.saturating_add(headers);
    }
}

#[derive(Default)]
struct QueueState {
    /// Message groups in order; `None` marks one a newer report replaced.
    entries: VecDeque<Option<Vec<ToOwner>>>,
    /// Sequence number of `entries[0]`.
    base: u64,
    keyed: HashMap<Coalesce, u64>,
    live: usize,
    /// The link failed: nothing more reaches the owner, which parks.
    failed: bool,
}

enum Batch {
    Messages,
    End,
    Failed,
}

/// The frontend's ordered queue to its owner.
#[derive(Default)]
struct LinkQueue {
    state: Mutex<QueueState>,
    ready: tokio::sync::Notify,
    senders: std::sync::atomic::AtomicUsize,
}
impl LinkQueue {
    fn push(&self, mut group: Vec<ToOwner>) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.failed {
            return;
        }
        let key = match group.as_slice() {
            [single] => coalesce_key(single),
            _ => None,
        };
        if let Some(key) = key {
            if let Some(seq) = st.keyed.remove(&key) {
                let at = (seq - st.base) as usize;
                if let Some(mut older) = st.entries[at].take() {
                    st.live -= 1;
                    if let (Some(newer), Some(older)) = (group.first_mut(), older.pop()) {
                        absorb(newer, older);
                    }
                }
            }
            let seq = st.base + st.entries.len() as u64;
            st.keyed.insert(key, seq);
        }
        st.entries.push_back(Some(group));
        st.live += 1;
        // Replaced entries never outnumber live ones.
        if st.entries.len() > 2 * st.live + 64 {
            st.compact();
        }
        drop(st);
        self.ready.notify_one();
    }

    /// The link is gone: what is queued can no longer reach the owner.
    fn fail(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.failed = true;
        st.entries.clear();
        st.keyed.clear();
        st.live = 0;
        drop(st);
        self.ready.notify_one();
    }

    #[cfg(test)]
    fn len(&self) -> (usize, usize) {
        let st = self.state.lock().unwrap();
        (st.live, st.entries.len())
    }

    async fn next_batch(&self, batch: &mut Vec<ToOwner>) -> Batch {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if st.failed {
                    return Batch::Failed;
                }
                while let Some(entry) = st.entries.pop_front() {
                    let seq = st.base;
                    st.base += 1;
                    let Some(group) = entry else { continue };
                    st.live -= 1;
                    if let [single] = group.as_slice() {
                        if let Some(key) = coalesce_key(single) {
                            if st.keyed.get(&key) == Some(&seq) {
                                st.keyed.remove(&key);
                            }
                        }
                    }
                    batch.extend(group);
                    if batch.len() >= 256 {
                        break;
                    }
                }
                if !batch.is_empty() {
                    return Batch::Messages;
                }
                if self.senders.load(Ordering::SeqCst) == 0 {
                    return Batch::End;
                }
            }
            notified.await;
        }
    }
}
impl QueueState {
    fn compact(&mut self) {
        let base = self.base;
        let mut entries = VecDeque::with_capacity(self.live);
        let mut keyed = HashMap::new();
        for (i, entry) in self.entries.drain(..).enumerate() {
            let Some(group) = entry else { continue };
            let seq = base + i as u64;
            if let [single] = group.as_slice() {
                if let Some(key) = coalesce_key(single) {
                    if self.keyed.get(&key) == Some(&seq) {
                        keyed.insert(key, base + entries.len() as u64);
                    }
                }
            }
            entries.push_back(Some(group));
        }
        self.entries = entries;
        self.keyed = keyed;
    }
}

/// A sender on the frontend's queue to its owner. Every token, mirror and
/// the bridge's inbound sender write here, so the owner sees their
/// operations in program order. The writer ends once every sender is gone.
pub(super) struct LinkTx(Arc<LinkQueue>);
impl LinkTx {
    fn new() -> (LinkTx, Arc<LinkQueue>) {
        let queue = Arc::new(LinkQueue::default());
        queue.senders.store(1, Ordering::SeqCst);
        (LinkTx(queue.clone()), queue)
    }
    pub(super) fn send(&self, msg: ToOwner) {
        // A failed link means the owner parked: nothing more reaches it.
        self.0.push(vec![msg]);
    }
    /// Several frames that must stay together (a data event in pieces).
    fn send_group(&self, group: Vec<ToOwner>) {
        self.0.push(group);
    }
}
impl Clone for LinkTx {
    fn clone(&self) -> Self {
        self.0.senders.fetch_add(1, Ordering::SeqCst);
        LinkTx(self.0.clone())
    }
}
impl Drop for LinkTx {
    fn drop(&mut self) {
        if self.0.senders.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.ready.notify_one();
        }
    }
}
impl std::fmt::Debug for LinkTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkTx")
    }
}

/// A byte charge the owner holds on its real gate.
pub(super) struct ChargeToken {
    id: u64,
    link: LinkTx,
    done: bool,
}
impl ChargeToken {
    pub(super) fn transfer(&mut self, tail: u64) {
        self.done = true;
        self.op(ChargeOp::Transfer(tail));
    }
    /// One slice of `n` bytes went, and the next owes a new header.
    pub(super) fn slice(&mut self, n: u64, tail: u64) {
        self.op(ChargeOp::Slice {
            n,
            tail,
            headers: 1,
        });
    }
    fn op(&self, op: ChargeOp) {
        self.link.send(ToOwner::Charge { id: self.id, op });
    }
}
impl Drop for ChargeToken {
    fn drop(&mut self) {
        if !self.done {
            self.op(ChargeOp::Withdraw);
        }
    }
}

/// Any owner reservation whose only frontend operation is its release.
struct ReleaseToken {
    id: u64,
    link: LinkTx,
}
impl Drop for ReleaseToken {
    fn drop(&mut self) {
        self.link.send(ToOwner::Released { id: self.id });
    }
}
impl RemotePermit for ReleaseToken {
    fn retained(&self, retention: Retention) {
        self.link.send(ToOwner::Retained {
            id: self.id,
            kind: match retention {
                Retention::Marker => RetainedKind::Marker,
                Retention::Gap => RetainedKind::Gap,
            },
        });
    }
}
impl RemoteResponse for ReleaseToken {
    fn admitted(&self) {
        self.link.send(ToOwner::Admitted { id: self.id });
    }
}

/// The frontend view of one stream's timeline budget.
struct StreamTimeline {
    stream: u8,
    link: LinkTx,
}
impl RemoteTimeline for StreamTimeline {
    fn progress(&self, instance: ChannelInstance, generation: u64) {
        self.link.send(ToOwner::Progress {
            stream: self.stream,
            instance: instance.get(),
            generation,
        });
    }
    fn frontier(&self, geometry: GeometryRecord) {
        self.link.send(ToOwner::Frontier {
            stream: self.stream,
            instance: geometry.instance.get(),
            geometry: geometry_wire(geometry),
        });
    }
    fn unconfirmed(&self, unconfirmed: bool) {
        self.link.send(ToOwner::Unconfirmed {
            stream: self.stream,
            unconfirmed,
        });
    }
}

/// A frontend stand-in for an owner gate. A repeated tail is not sent again:
/// only this frontend moves the owner gate's tail, so the owner would find
/// no transition.
#[derive(Debug)]
struct MirrorGate {
    id: u64,
    link: LinkTx,
    tail: Mutex<Option<u64>>,
}
impl GateMirror for MirrorGate {
    fn apply(&self, op: GateOp) {
        let op = match op {
            GateOp::Admit(n) => GateOpWire::Admit(n),
            GateOp::Withdraw(n) => GateOpWire::Withdraw(n),
            GateOp::Transfer { n, tail } => {
                *self.tail.lock().unwrap_or_else(|e| e.into_inner()) = Some(tail);
                GateOpWire::Transfer { n, tail }
            }
            GateOp::Update { tail, ready } => {
                let mut last = self.tail.lock().unwrap_or_else(|e| e.into_inner());
                if *last == Some(tail) {
                    return;
                }
                *last = Some(tail);
                GateOpWire::Update { tail, ready }
            }
        };
        self.link.send(ToOwner::Gate { gate: self.id, op });
    }
    fn tail_moved(&self, tail: u64) {
        *self.tail.lock().unwrap_or_else(|e| e.into_inner()) = Some(tail);
    }
}

// ---- frontend ----------------------------------------------------------------

/// The frontend's inbound credit: one slot per free place in the owner's
/// queue, granted by the owner.
#[derive(Default)]
struct Credits {
    state: Mutex<CreditState>,
    changed: tokio::sync::Notify,
}
#[derive(Default)]
struct CreditState {
    credits: usize,
    closed: bool,
}
impl Credits {
    fn grant(&self, slots: u32) -> Result<(), LinkError> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.credits = st
            .credits
            .checked_add(slots as usize)
            .filter(|&c| c <= INBOUND_CAP)
            .ok_or(LinkError::BadValue)?;
        drop(st);
        self.changed.notify_waiters();
        Ok(())
    }
    fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        self.changed.notify_waiters();
    }
    fn give_back(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).credits += 1;
        self.changed.notify_waiters();
    }
}

/// The bridge's inbound sender when its backend is behind an owner link: an
/// event is handed over when it is written to the link, under one credit.
/// Dropping it ends the owner's backend, as dropping the queue's sender does.
pub(super) struct CreditSender {
    credits: Arc<Credits>,
    link: LinkTx,
}

/// One reserved credit; unused, it goes back.
pub(super) struct CreditPermit<'a> {
    sender: &'a CreditSender,
    used: bool,
}

/// The frames of one inbound event, or `None` for a wake only the owner
/// decides (its own gates and timeline latches make those).
fn inbound_frames(ev: SessionInbound) -> Option<Vec<ToOwner>> {
    Some(vec![match ev {
        SessionInbound::Data(StreamData {
            stream_id,
            mut data,
        }) => {
            // A delivered chunk may exceed one frame: leading pieces go
            // ahead, and the owner joins them into one event again.
            let mut frames = Vec::new();
            if data.len() > DATA_FRAME_MAX {
                let last = (data.len() - 1) / DATA_FRAME_MAX * DATA_FRAME_MAX;
                frames.extend(
                    data[..last]
                        .chunks(DATA_FRAME_MAX)
                        .map(|part| ToOwner::DataPart(part.to_vec())),
                );
                data.drain(..last);
            }
            frames.push(ToOwner::Data {
                stream: stream_id,
                data,
            });
            return Some(frames);
        }
        SessionInbound::Live(c) => ToOwner::Live(ctx_wire(c)),
        SessionInbound::ResumeReset(c) => ToOwner::ResumeReset(ctx_wire(c)),
        SessionInbound::Repaint => ToOwner::Repaint,
        SessionInbound::RepaintCutover {
            generation,
            sequence,
        } => ToOwner::RepaintCutover {
            generation,
            sequence,
        },
        SessionInbound::Delivered {
            stream,
            token,
            generation,
        } => ToOwner::MarkerDelivered {
            stream,
            token,
            generation,
        },
        SessionInbound::Writable { .. } | SessionInbound::OutputReady { .. } => return None,
    }])
}

impl CreditSender {
    pub(super) fn try_send(
        &self,
        ev: SessionInbound,
    ) -> Result<(), mpsc::error::TrySendError<SessionInbound>> {
        if matches!(
            ev,
            SessionInbound::Writable { .. } | SessionInbound::OutputReady { .. }
        ) {
            return Ok(());
        }
        let mut st = self.credits.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return Err(mpsc::error::TrySendError::Closed(ev));
        }
        if st.credits == 0 {
            return Err(mpsc::error::TrySendError::Full(ev));
        }
        st.credits -= 1;
        drop(st);
        if let Some(frames) = inbound_frames(ev) {
            self.link.send_group(frames);
        }
        Ok(())
    }

    /// Wait for one credit. Cancel-safe: nothing is taken until it is there.
    pub(super) async fn reserve(&self) -> Result<CreditPermit<'_>, ()> {
        loop {
            let notified = self.credits.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.credits.state.lock().unwrap_or_else(|e| e.into_inner());
                if st.closed {
                    return Err(());
                }
                if st.credits > 0 {
                    st.credits -= 1;
                    return Ok(CreditPermit {
                        sender: self,
                        used: false,
                    });
                }
            }
            notified.await;
        }
    }
}
impl CreditPermit<'_> {
    pub(super) fn send(mut self, ev: SessionInbound) {
        if let Some(frames) = inbound_frames(ev) {
            self.used = true;
            self.sender.link.send_group(frames);
        }
    }
}
impl Drop for CreditPermit<'_> {
    fn drop(&mut self) {
        if !self.used {
            self.sender.credits.give_back();
        }
    }
}
impl Drop for CreditSender {
    fn drop(&mut self) {
        self.link.send(ToOwner::End(EndKind::Graceful));
    }
}

/// What the frontend's session control holds for its owner link.
pub(super) struct RemoteControl {
    pub(super) link: LinkTx,
    inbound: Mutex<Option<CreditSender>>,
}
impl RemoteControl {
    /// The bridge's inbound sender, taken once by the bridge.
    pub(super) fn take_inbound(&self) -> Option<CreditSender> {
        self.inbound
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
}

/// A [`SessionBackend`] whose session runs behind an owner link: in an
/// owner process an [`OwnerStarter`] starts per session, or (for tests) in
/// this process over [`loopback`], on the frontend's own lifecycle.
pub struct RemoteBackend {
    /// The backend each owner runs: its features and consumption model are
    /// the session's. An in-process owner runs it here.
    inner: Arc<dyn SessionBackend>,
    starter: Option<Arc<dyn OwnerStarter>>,
}

impl RemoteBackend {
    /// Run `inner` for each session in an in-process owner over a loopback link.
    pub fn loopback(inner: Arc<dyn SessionBackend>) -> RemoteBackend {
        RemoteBackend {
            inner,
            starter: None,
        }
    }

    /// Run each session in an owner that `starter` starts. `inner` is the
    /// backend those owners run; here it only answers for its features and
    /// its consumption model.
    pub fn with_owners(
        inner: Arc<dyn SessionBackend>,
        starter: Arc<dyn OwnerStarter>,
    ) -> RemoteBackend {
        RemoteBackend {
            inner,
            starter: Some(starter),
        }
    }
}

impl SessionBackend for RemoteBackend {
    fn required_features(&self) -> crate::Features {
        self.inner.required_features()
    }

    /// Called by the bridge before its first event: the link and its
    /// inbound sender exist when this returns.
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if let Some(starter) = &self.starter {
            let init = OwnerInit::new(io.principal().clone(), io.login());
            let link: Box<dyn LinkIo> = match starter.start(init) {
                Ok(link) => link,
                Err(error) => {
                    log::error!("cannot start a session owner: {error}");
                    // A link whose owner end is gone: the frontend reads end
                    // of input at once, and the session ends as with a
                    // backend that stopped.
                    let (front, _owner) = loopback();
                    Box::new(front)
                }
            };
            return Box::pin(start_frontend(io, link));
        }
        let (front, owner) = loopback();
        let init = OwnerInit {
            principal: io.principal().clone(),
            login: io.login(),
            last_generation: 0,
            lifecycle: Some(io.lifecycle.clone()),
        };
        let inner = self.inner.clone();
        io.lifecycle.spawn(async move {
            let exit = OwnerLink::run(owner, inner, init).await;
            if exit == OwnerExit::LinkLost {
                log::warn!("session owner lost its frontend link");
            }
        });
        Box::pin(start_frontend(io, front))
    }

    fn consumption(&self) -> Consumption {
        self.inner.consumption()
    }
}

struct Frontend {
    io: SessionIo,
    link: LinkTx,
    credits: Arc<Credits>,
    mirrors: HashMap<u64, Weak<SendGate>>,
    mirrors_pruned_at: usize,
    /// Leading pieces of the next data record's body.
    data_parts: Vec<u8>,
}

/// Set up the frontend end of `link` for the bridge that owns `io` (its
/// writer, and the inbound sender the bridge takes from the session
/// control), and return the reader that feeds the owner's records into the
/// bridge's queue. The reader returns when the owner closes the link (the
/// backend is done), on a link error (the session then ends as with a
/// backend that stopped), or on shutdown.
pub(super) fn start_frontend<L>(io: SessionIo, link: L) -> impl Future<Output = ()> + Send
where
    L: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read, write) = tokio::io::split(link);
    let (tx, queue) = LinkTx::new();
    let lifecycle = io.lifecycle.clone();
    let failure = Arc::new(LinkFailure::default());
    let credits = Arc::new(Credits::default());
    let _ = io.control().remote.set(RemoteControl {
        link: tx.clone(),
        inbound: Mutex::new(Some(CreditSender {
            credits: credits.clone(),
            link: tx.clone(),
        })),
    });
    lifecycle.spawn(frontend_write_loop(
        write,
        queue,
        failure.clone(),
        lifecycle.clone(),
    ));
    let front = Frontend {
        io,
        link: tx,
        credits,
        mirrors: HashMap::new(),
        mirrors_pruned_at: 0,
        data_parts: Vec::new(),
    };
    front.read(LinkReader::new(read), failure, lifecycle)
}

impl Frontend {
    async fn read<R: AsyncRead + Unpin>(
        mut self,
        mut reader: LinkReader<R>,
        failure: Arc<LinkFailure>,
        lifecycle: Arc<Lifecycle>,
    ) {
        loop {
            let frame = tokio::select! {
                biased;
                _ = lifecycle.shutdown.requested() => break,
                _ = failure.failed() => {
                    log::error!("owner link: frontend write failed");
                    break;
                }
                frame = reader.next() => frame,
            };
            match frame {
                Ok(Some(frame)) => {
                    if let Err(error) = self.on_frame(&frame) {
                        log::error!("owner link: frontend refused a frame ({error:?})");
                        self.link.send(ToOwner::End(EndKind::Destroy));
                        break;
                    }
                }
                // The owner forwarded everything its backend sent.
                Ok(None) => break,
                Err(error) => {
                    log::error!("owner link: frontend read failed ({error:?})");
                    self.link.send(ToOwner::End(EndKind::Destroy));
                    break;
                }
            }
        }
        // The backend is gone: what still waits for it goes with it.
        self.credits.close();
    }

    fn on_frame(&mut self, frame: &Frame) -> Result<(), LinkError> {
        match ToFrontend::decode(frame)? {
            ToFrontend::Grant { slots } => self.credits.grant(slots)?,
            ToFrontend::DataPart(part) => {
                if self.data_parts.len() + part.len() > MAX_DATA_RECORD {
                    return Err(LinkError::TooLong);
                }
                self.data_parts.extend_from_slice(&part);
            }
            ToFrontend::Record(mut record) => {
                if !self.data_parts.is_empty() {
                    let (OutRecord::ChannelOutput {
                        output: OutputBody::Data(data),
                        ..
                    }
                    | OutRecord::Data { data, .. }) = &mut record
                    else {
                        // Pieces belong to the data record right behind them.
                        return Err(LinkError::BadValue);
                    };
                    let mut joined = std::mem::take(&mut self.data_parts);
                    joined.append(data);
                    *data = joined;
                }
                self.on_record(record)?
            }
            ToFrontend::Snapshot {
                id,
                generation,
                prefix,
                dto,
            } => {
                let snapshot = crate::channel::ChannelSnapshot::decode_payload(&dto)
                    .map_err(|_| LinkError::BadValue)?;
                let permits = [SLOT_COMMIT, SLOT_PERMIT, SLOT_PART].map(|slot| {
                    ResponsePermit::remote(self.release(id | slot), RemoteClass::Snapshot)
                });
                if self
                    .io
                    .resume_snapshots
                    .install_remote(generation, prefix, snapshot, permits)
                {
                    let _ = self.io.outbound.send(SessionOutbound::ResumeSnapshotReady);
                }
            }
            ToFrontend::Terminal {
                origin,
                disposition,
            } => self.io.control().mirror_terminal(TerminalRequest {
                origin: ctx_from(origin),
                disposition: disposition_from(disposition)?,
            }),
            // The rebuild after a frontend death arrives with the journal.
            ToFrontend::ReplayItem(_)
            | ToFrontend::ReplayFrontier { .. }
            | ToFrontend::ReplayUnconfirmed { .. }
            | ToFrontend::ReplayRetained { .. }
            | ToFrontend::ReplayDone { .. } => return Err(LinkError::UnknownKind),
        }
        Ok(())
    }

    fn release(&self, id: u64) -> Box<ReleaseToken> {
        Box::new(ReleaseToken {
            id,
            link: self.link.clone(),
        })
    }

    fn permit(&self, id: u64, stream: u8) -> crate::channel_timeline::TimelinePermit {
        crate::channel_timeline::TimelinePermit::remote(
            self.release(id),
            Arc::new(StreamTimeline {
                stream,
                link: self.link.clone(),
            }),
        )
    }

    fn mirror(&mut self, gate: GateWire) -> Result<Arc<SendGate>, LinkError> {
        let kind = gate_kind_from(gate.kind)?;
        if let Some(live) = self.mirrors.get(&gate.id).and_then(Weak::upgrade) {
            return if live.kind() == kind {
                Ok(live)
            } else {
                Err(LinkError::BadValue)
            };
        }
        let mirror = Arc::new(SendGate::mirror(
            kind,
            Arc::new(MirrorGate {
                id: gate.id,
                link: self.link.clone(),
                tail: Mutex::new(None),
            }),
        ));
        self.mirrors.insert(gate.id, Arc::downgrade(&mirror));
        if self.mirrors.len() > 64 && self.mirrors.len() > 2 * self.mirrors_pruned_at {
            self.mirrors.retain(|_, gate| gate.strong_count() > 0);
            self.mirrors_pruned_at = self.mirrors.len();
        }
        Ok(mirror)
    }

    fn charge(&mut self, id: u64, gate: GateWire, bytes: usize) -> Result<OutputCharge, LinkError> {
        Ok(OutputCharge {
            gate: self.mirror(gate)?,
            bytes: bytes as u64,
            remote: Some(Box::new(ChargeToken {
                id: id | SLOT_CHARGE,
                link: self.link.clone(),
                done: false,
            })),
        })
    }

    fn delivery(
        &mut self,
        id: u64,
        bytes: usize,
        charge: Option<GateWire>,
    ) -> Result<ControlDelivery, LinkError> {
        let charge = charge.map(|g| self.charge(id, g, bytes)).transpose()?;
        Ok(ControlDelivery {
            part: ResponsePart::remote(self.release(id | SLOT_PART), bytes),
            charge,
        })
    }

    fn send_ordered(&self, message: SessionOutbound) {
        // Positions restart in the frontend's own mailbox, in the owner's
        // order, so the owner's snapshot prefixes keep their meaning.
        let _ = self
            .io
            .resume_snapshots
            .send_ordered(&self.io.outbound, message);
    }

    fn send(&self, message: SessionOutbound) {
        let _ = self.io.outbound.send(message);
    }

    fn on_record(&mut self, record: OutRecord) -> Result<(), LinkError> {
        match record {
            OutRecord::RetirementReady {
                origin,
                decisions_complete,
            } => self.send(SessionOutbound::RetirementReady {
                origin: ctx_from(origin),
                decisions_complete,
            }),
            OutRecord::ReservedControl {
                id,
                origin,
                bytes,
                charge,
            } => {
                let delivery = self.delivery(id, bytes.len(), charge)?;
                self.send(SessionOutbound::ReservedControl {
                    origin: ctx_from(origin),
                    bytes,
                    delivery,
                });
            }
            OutRecord::UpdateAccept {
                id,
                origin,
                bytes,
                charge,
            } => {
                let delivery = self.delivery(id, bytes.len(), charge)?;
                let (committed, receipt) = oneshot::channel();
                let link = self.link.clone();
                let lifecycle = self.io.lifecycle.clone();
                self.io.lifecycle.spawn(async move {
                    let id = id | SLOT_COMMIT;
                    tokio::select! {
                        biased;
                        _ = lifecycle.shutdown.requested() => {}
                        receipt = receipt => link.send(match receipt {
                            Ok(()) => ToOwner::Committed { id },
                            // Dropped uncommitted: the offer is not accepted.
                            Err(_) => ToOwner::Released { id },
                        }),
                    }
                });
                self.send(SessionOutbound::UpdateAccept {
                    origin: ctx_from(origin),
                    bytes,
                    delivery,
                    committed,
                });
            }
            OutRecord::ReservedSessionControl { id, bytes, charge } => {
                let delivery = self.delivery(id, bytes.len(), charge)?;
                self.send(SessionOutbound::ReservedSessionControl { bytes, delivery });
            }
            OutRecord::ResourceExhausted { origin } => {
                self.send(SessionOutbound::ResourceExhausted {
                    origin: ctx_from(origin),
                })
            }
            OutRecord::CloseSession { origin } => self.send(SessionOutbound::CloseSession {
                origin: ctx_from(origin),
            }),
            OutRecord::RepaintBarrier {
                id: _,
                generation,
                sequence,
            } => self.send(SessionOutbound::RepaintBarrier {
                generation,
                sequence,
            }),
            OutRecord::ChannelClosed {
                id: _,
                stream,
                instance,
                origin,
            } => {
                let instance = instance_from(instance)?;
                self.send_ordered(SessionOutbound::ChannelClosed {
                    position: 0,
                    stream,
                    instance,
                    origin: ctx_from(origin),
                });
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
                let instance = instance_from(instance)?;
                // Validate every raw value before any token exists.
                enum Body {
                    Data(Vec<u8>),
                    Geometry(GeometryRecord),
                    EchoAck(u64),
                    OutputGap(OutputGapCause),
                    DeliveryMarker(u64),
                }
                let body = match output {
                    OutputBody::Data(data) => Body::Data(data),
                    OutputBody::Geometry(g) => Body::Geometry(geometry_from(g)?),
                    OutputBody::EchoAck(n) => Body::EchoAck(n),
                    OutputBody::OutputGap(cause) => Body::OutputGap(
                        OutputGapCause::from_wire(cause).ok_or(LinkError::BadValue)?,
                    ),
                    OutputBody::DeliveryMarker { token } => Body::DeliveryMarker(token),
                };
                gate_kind_from(gate.kind)?;
                let permit = |front: &Self| front.permit(id | SLOT_PERMIT, stream);
                let output = match body {
                    Body::Data(data) => ChannelOutput::Data(data),
                    Body::Geometry(g) => ChannelOutput::Geometry(g, permit(self)),
                    Body::EchoAck(n) => ChannelOutput::EchoAck(n, permit(self)),
                    Body::OutputGap(cause) => ChannelOutput::OutputGap(cause, permit(self)),
                    Body::DeliveryMarker(token) => {
                        ChannelOutput::DeliveryMarker(DeliveryMarker { token }, permit(self))
                    }
                };
                let charge = self.charge(id, gate, output.framed_len())?;
                let gap_reserve = gap_reserve.then(|| self.permit(id | SLOT_GAP_RESERVE, stream));
                self.send_ordered(SessionOutbound::ChannelOutput {
                    position: 0,
                    stream,
                    instance,
                    origin: ctx_from(origin),
                    output,
                    charge,
                    gap_reserve,
                });
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
                let instance = instance_from(instance)?;
                let open = open_from(open)?;
                if let Some(gate) = charge {
                    gate_kind_from(gate.kind)?;
                }
                let control = self.delivery(id, control_bytes as usize, charge)?;
                self.send_ordered(SessionOutbound::ChannelExit {
                    position: 0,
                    stream,
                    instance,
                    origin: ctx_from(origin),
                    code,
                    open,
                    permit: self.permit(id | SLOT_PERMIT, stream),
                    control,
                });
            }
            OutRecord::ProtocolFailure { origin, code } => {
                let code = code
                    .map(|c| ProtocolErrorCode::from_wire(c).ok_or(LinkError::BadValue))
                    .transpose()?;
                self.send(SessionOutbound::ProtocolFailure {
                    origin: ctx_from(origin),
                    code,
                });
            }
            OutRecord::Data { stream, data } => self.send(SessionOutbound::Data(StreamData {
                stream_id: stream,
                data,
            })),
            OutRecord::Resyncable { stream, resyncable } => {
                self.send(SessionOutbound::Resyncable {
                    stream_id: stream,
                    resyncable,
                })
            }
            OutRecord::StreamClass { stream, bulk } => self.send(SessionOutbound::StreamClass {
                stream_id: stream,
                class: if bulk {
                    StreamClass::Bulk
                } else {
                    StreamClass::Interactive
                },
            }),
            OutRecord::Consumed { stream, n } => self.send(SessionOutbound::Consumed {
                stream_id: stream,
                n: usize::try_from(n).map_err(|_| LinkError::BadValue)?,
            }),
            OutRecord::NotifyDelivered { stream, token } => {
                self.send(SessionOutbound::NotifyDelivered {
                    stream_id: stream,
                    token,
                })
            }
            OutRecord::ChannelOpened { stream, origin } => {
                self.send(SessionOutbound::ChannelOpened {
                    stream,
                    origin: ctx_from(origin),
                })
            }
            OutRecord::ChannelRefused {
                stream,
                origin,
                reason,
            } => self.send(SessionOutbound::ChannelRefused {
                stream,
                origin: ctx_from(origin),
                reason: String::from_utf8(reason).map_err(|_| LinkError::BadValue)?,
            }),
        }
        Ok(())
    }
}

// ---- owner -------------------------------------------------------------------

/// What an owner starts its session with.
pub struct OwnerInit {
    pub principal: Principal,
    pub login: LoginId,
    /// The highest attachment generation an earlier frontend used (0 for a
    /// fresh session). Carried for the bridge rebuild; nothing reads it yet.
    pub last_generation: u64,
    /// The lifecycle the owner's backend joins: the frontend's own one for an
    /// in-process owner, a fresh one otherwise.
    lifecycle: Option<Arc<Lifecycle>>,
}

impl OwnerInit {
    /// A session owner with its own lifecycle.
    pub fn new(principal: Principal, login: LoginId) -> OwnerInit {
        OwnerInit {
            principal,
            login,
            last_generation: 0,
            lifecycle: None,
        }
    }
}

/// How an owner's link ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerExit {
    /// The frontend ended the session and the backend finished.
    Finished,
    /// The lifecycle stopped.
    Shutdown,
    /// The link died without an explicit end, and the backend then finished.
    LinkLost,
}

/// The owner side of a link: a real [`SessionIo`] driven from link frames.
pub struct OwnerLink;

/// How an owner process's session ended: the link's end, then the drain of
/// every task and blocking worker the session started (its receipt).
#[derive(Debug)]
pub struct OwnerRun {
    pub exit: OwnerExit,
    pub drained: Result<(), ShutdownError>,
}

/// One object the owner holds for the frontend; dropping it releases it.
enum Custody {
    Charge(OutputCharge),
    Permit {
        _held: crate::channel_timeline::TimelinePermit,
    },
    Part {
        _held: ResponsePart,
    },
    Response {
        _held: ResponsePermit,
    },
    Commit(oneshot::Sender<()>),
}

struct OwnedGate {
    stream: u8,
    gate: Weak<SendGate>,
}

/// What the frontend reported about retained bridge state, kept for the
/// rebuild after a frontend death.
#[derive(Default)]
struct Reports {
    admitted: std::collections::BTreeSet<u64>,
    retained: BTreeMap<u64, RetainedKind>,
    frontier: BTreeMap<u8, GeometryRecord>,
    unconfirmed: BTreeMap<u8, bool>,
    last_client_recv: u64,
}

struct Owner {
    control: Arc<SessionControl>,
    mailbox: channel_bridge::SnapshotMailbox,
    gates: Arc<GateTable>,
    in_tx: Option<mpsc::Sender<SessionInbound>>,
    /// Reserved inbound slots not granted to the frontend.
    pool: Vec<mpsc::OwnedPermit<SessionInbound>>,
    /// Reserved slots backing the frontend's outstanding credits, in order.
    granted: VecDeque<mpsc::OwnedPermit<SessionInbound>>,
    /// Owner-made events waiting for a reserved slot, without duplicates.
    synth: VecDeque<SessionInbound>,
    custody: HashMap<u64, Custody>,
    next_position: u64,
    gate_ids: HashMap<usize, u64>,
    gates_by_id: HashMap<u64, OwnedGate>,
    next_gate: u64,
    gates_pruned_at: usize,
    budgets: BTreeMap<(u8, u64), TimelineBudget>,
    reports: Reports,
    /// `None` once the backend finished: the frontend then sees end of input.
    data: Option<mpsc::UnboundedSender<ToFrontend>>,
    priority: Option<mpsc::UnboundedSender<ToFrontend>>,
    /// Messages kept after the link died, with their custody (bounded as the
    /// bridge's own FIFO is: by gates, timeline and reply budgets).
    parked: Vec<SessionOutbound>,
    /// Leading pieces of the next inbound data event.
    data_parts: Vec<u8>,
}

impl OwnerLink {
    /// [`OwnerLink::run`] on a lifecycle of its own that `shutdown` stops,
    /// then stop that lifecycle and drain it: when this returns, every task
    /// and blocking worker of the session has joined (the owner process's
    /// receipt). Any lifecycle in `init` is replaced.
    pub async fn run_and_drain<L>(
        link: L,
        backend: Arc<dyn SessionBackend>,
        mut init: OwnerInit,
        shutdown: Shutdown,
    ) -> OwnerRun
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        let lifecycle = Lifecycle::new(shutdown);
        init.lifecycle = Some(lifecycle.clone());
        let run = Self::run(link, backend, init);
        tokio::pin!(run);
        // A blocking callback's result is published by the lifecycle's
        // joiner, as the session manager's loop does for a daemon's
        // sessions: nothing else here would ever hand it to the backend.
        // The joiner sleeps until a task ends or one is registered.
        let exit = loop {
            tokio::select! {
                exit = &mut run => break exit,
                _ = lifecycle.join_next_or_wait() => {}
            }
        };
        lifecycle.shutdown.request();
        let drained = lifecycle.drain().await;
        OwnerRun { exit, drained }
    }

    /// Run `backend` for one session behind `link` until the session ends.
    /// A link that dies without an explicit end parks the backend: it keeps
    /// running, its custody stays charged, and only shutdown (or the backend
    /// finishing) ends the owner.
    pub async fn run<L>(link: L, backend: Arc<dyn SessionBackend>, init: OwnerInit) -> OwnerExit
    where
        L: AsyncRead + AsyncWrite + Send + 'static,
    {
        let OwnerInit {
            principal,
            login,
            last_generation: _,
            lifecycle,
        } = init;
        let lifecycle = lifecycle.unwrap_or_else(|| Lifecycle::new(Shutdown::default()));
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let gates = Arc::new(GateTable::new());
        let io = SessionIo {
            lifecycle: lifecycle.clone(),
            control: OnceLock::new(),
            resume_snapshots: channel_bridge::SnapshotMailbox::default(),
            inbound: in_rx,
            outbound: out_tx,
            principal,
            login,
            gates: Arc::clone(&gates),
        };
        let control = io.control().clone();
        let mailbox = io.resume_snapshots.clone();
        lifecycle.spawn(async move { backend.run(io).await });

        let (read, write) = tokio::io::split(link);
        let (data, data_rx) = mpsc::unbounded_channel();
        let (priority, priority_rx) = mpsc::unbounded_channel();
        let failure = Arc::new(LinkFailure::default());
        lifecycle.spawn(owner_write_loop(
            write,
            data_rx,
            priority_rx,
            failure.clone(),
            lifecycle.clone(),
        ));
        let mut reader = LinkReader::new(read);
        let mut owner = Owner {
            control,
            mailbox,
            gates,
            in_tx: Some(in_tx),
            pool: Vec::new(),
            granted: VecDeque::new(),
            synth: VecDeque::new(),
            custody: HashMap::new(),
            next_position: 0,
            gate_ids: HashMap::new(),
            gates_by_id: HashMap::new(),
            next_gate: 0,
            gates_pruned_at: 0,
            budgets: BTreeMap::new(),
            reports: Reports::default(),
            data: Some(data),
            priority: Some(priority),
            parked: Vec::new(),
            data_parts: Vec::new(),
        };
        let mut linked = true;
        let mut ended = false;
        // The backend finished and everything it sent went out; the frontend
        // still holds custody until it closes the link.
        let mut backend_done = false;
        loop {
            let reserve = owner
                .in_tx
                .as_ref()
                .filter(|_| owner.pool.len() + owner.granted.len() < INBOUND_CAP)
                .cloned();
            let control = owner.control.clone();
            let wake = tokio::select! {
                biased;
                _ = lifecycle.shutdown.requested() => {
                    owner.gates.close_all();
                    return OwnerExit::Shutdown;
                }
                // Not fenced by anything: the frontend's priority lane.
                _ = control.terminal_ready.notified() => OwnerWake::Terminal,
                _ = failure.failed(), if linked => OwnerWake::WriteFailed,
                // Neither a frame flood nor a busy backend starves the other.
                wake = async {
                    tokio::select! {
                        frame = reader.next(), if linked => OwnerWake::Frame(frame),
                        message = out_rx.recv(), if !backend_done => OwnerWake::Backend(message),
                        permit = async {
                            match reserve {
                                Some(tx) => tx.reserve_owned().await.ok(),
                                None => std::future::pending().await,
                            }
                        } => OwnerWake::Slot(permit),
                    }
                } => wake,
            };
            match wake {
                OwnerWake::Terminal => {
                    if let Some(request) = control.take_priority_abort() {
                        owner.to_frontend_priority(ToFrontend::Terminal {
                            origin: ctx_wire(request.origin),
                            disposition: disposition_wire(request.disposition),
                        });
                    }
                }
                OwnerWake::WriteFailed if backend_done => return OwnerExit::Finished,
                OwnerWake::WriteFailed => {
                    log::error!("owner link: owner write failed; parking");
                    linked = false;
                }
                OwnerWake::Frame(frame) => match frame.and_then(|frame| {
                    frame
                        .map(|frame| owner.on_frame(&frame, &mut ended))
                        .transpose()
                }) {
                    Ok(Some(())) => {}
                    // Every frontend token is gone: custody may go too.
                    Ok(None) | Err(_) if backend_done => return OwnerExit::Finished,
                    Ok(None) | Err(_) if ended => linked = false,
                    Ok(None) => {
                        log::warn!(
                            "owner link: the frontend closed without ending the session; parking"
                        );
                        linked = false;
                    }
                    Err(error) => {
                        log::error!("owner link: owner refused the link ({error:?}); parking");
                        linked = false;
                    }
                },
                OwnerWake::Backend(Some(message)) if linked => {
                    if let Err(error) = owner.forward(message) {
                        log::error!("owner link: a record cannot cross ({error:?}); parking");
                        linked = false;
                    }
                }
                OwnerWake::Backend(Some(message)) => owner.parked.push(message),
                OwnerWake::Backend(None) if !linked => {
                    return if ended {
                        OwnerExit::Finished
                    } else {
                        OwnerExit::LinkLost
                    };
                }
                // The backend is done and everything it sent is queued: end
                // the frontend's input, but keep each custody object until
                // the frontend releases it or closes the link.
                OwnerWake::Backend(None) => {
                    backend_done = true;
                    owner.end_inbound();
                    owner.data = None;
                    owner.priority = None;
                }
                OwnerWake::Slot(Some(permit)) => {
                    owner.pool.push(permit);
                    owner.serve_synth();
                    owner.grant();
                }
                // The backend's queue closed: nothing more can be handed over.
                OwnerWake::Slot(None) => owner.end_inbound(),
            }
        }
    }
}

enum OwnerWake {
    Terminal,
    WriteFailed,
    Frame(Result<Option<Frame>, LinkError>),
    Backend(Option<SessionOutbound>),
    Slot(Option<mpsc::OwnedPermit<SessionInbound>>),
}

impl Owner {
    fn to_frontend(&self, msg: ToFrontend) {
        if let Some(data) = &self.data {
            let _ = data.send(msg);
        }
    }
    fn to_frontend_priority(&self, msg: ToFrontend) {
        if let Some(priority) = &self.priority {
            let _ = priority.send(msg);
        }
    }

    /// Grant reserved slots to the frontend, keeping `SYNTH_RESERVE` back.
    fn grant(&mut self) {
        let room = MAX_GRANT.saturating_sub(self.granted.len());
        let spare = self.pool.len().saturating_sub(SYNTH_RESERVE);
        let n = room.min(spare);
        // Batch small grants unless the frontend is running low.
        if n == 0 || (n < 32 && self.granted.len() >= 16) {
            return;
        }
        let at = self.pool.len() - n;
        self.granted.extend(self.pool.drain(at..));
        self.to_frontend(ToFrontend::Grant { slots: n as u32 });
    }

    fn serve_synth(&mut self) {
        while let Some(ev) = self.synth.pop_front() {
            let Some(permit) = self.pool.pop() else {
                self.synth.push_front(ev);
                return;
            };
            permit.send(ev);
        }
    }

    /// An owner-made inbound wake, coalesced while it waits for a slot.
    fn synthesize(&mut self, ev: SessionInbound) {
        if self.in_tx.is_none() {
            return;
        }
        let duplicate = self.synth.iter().any(|queued| match (queued, &ev) {
            (SessionInbound::Writable { stream: a }, SessionInbound::Writable { stream: b }) => {
                a == b
            }
            (
                SessionInbound::OutputReady {
                    stream: a,
                    instance: i,
                    generation: g,
                },
                SessionInbound::OutputReady {
                    stream: b,
                    instance: j,
                    generation: h,
                },
            ) => a == b && i == j && g == h,
            _ => false,
        });
        if !duplicate {
            self.synth.push_back(ev);
        }
        self.serve_synth();
    }

    /// One inbound event the frontend sent on credit.
    fn deliver(&mut self, ev: SessionInbound) -> Result<(), LinkError> {
        if self.in_tx.is_none() {
            // After `End`: the backend's queue is closed.
            return Ok(());
        }
        let permit = self.granted.pop_front().ok_or(LinkError::BadValue)?;
        permit.send(ev);
        Ok(())
    }

    fn end_inbound(&mut self) {
        self.in_tx = None;
        self.pool.clear();
        self.granted.clear();
        self.synth.clear();
    }

    fn on_frame(&mut self, frame: &Frame, ended: &mut bool) -> Result<(), LinkError> {
        match ToOwner::decode(frame)? {
            ToOwner::DataPart(part) => {
                if self.data_parts.len() + part.len() > MAX_DATA_RECORD {
                    return Err(LinkError::TooLong);
                }
                self.data_parts.extend_from_slice(&part);
            }
            ToOwner::Data { stream, mut data } => {
                if !self.data_parts.is_empty() {
                    let mut joined = std::mem::take(&mut self.data_parts);
                    joined.append(&mut data);
                    data = joined;
                }
                self.deliver(SessionInbound::Data(StreamData {
                    stream_id: stream,
                    data,
                }))?
            }
            ToOwner::Live(c) => self.deliver(SessionInbound::Live(ctx_from(c)))?,
            ToOwner::ResumeReset(c) => self.deliver(SessionInbound::ResumeReset(ctx_from(c)))?,
            ToOwner::Repaint => self.deliver(SessionInbound::Repaint)?,
            ToOwner::RepaintCutover {
                generation,
                sequence,
            } => self.deliver(SessionInbound::RepaintCutover {
                generation,
                sequence,
            })?,
            ToOwner::MarkerDelivered {
                stream,
                token,
                generation,
            } => self.deliver(SessionInbound::Delivered {
                stream,
                token,
                generation,
            })?,
            ToOwner::Gate { gate, op } => self.on_gate(gate, op)?,
            ToOwner::Charge { id, op } => {
                let Some(Custody::Charge(charge)) = self.custody.get_mut(&id) else {
                    return Err(LinkError::BadValue);
                };
                match op {
                    ChargeOp::Transfer(tail) => {
                        if let Some(Custody::Charge(charge)) = self.custody.remove(&id) {
                            charge.transfer(tail);
                        }
                    }
                    // Every slice moves a 5-byte header and at least one
                    // payload byte, and gives back one header for the next;
                    // merged slices keep that per slice. So a merge always
                    // shrinks the charge, and leaves at least one header and
                    // one byte for the final transfer.
                    ChargeOp::Slice { n, tail, headers } => {
                        let admit = headers.checked_mul(5).ok_or(LinkError::BadValue)?;
                        let least = headers.checked_mul(6).ok_or(LinkError::BadValue)?;
                        let most = charge
                            .bytes
                            .checked_add(admit)
                            .and_then(|v| v.checked_sub(6))
                            .ok_or(LinkError::BadValue)?;
                        if headers == 0 || n < least || n > most {
                            return Err(LinkError::BadValue);
                        }
                        // Admit first: the gate's transfer saturates, so a
                        // merged `n` past its pending bytes would undercount.
                        charge.gate.admit(admit);
                        charge.gate.transfer(n, tail);
                        charge.bytes = charge.bytes + admit - n;
                    }
                    ChargeOp::Withdraw => drop(self.custody.remove(&id)),
                }
            }
            ToOwner::Progress {
                stream,
                instance,
                generation,
            } => {
                let instance = instance_from(instance)?;
                self.output_ready(stream, instance, generation);
            }
            ToOwner::Admitted { id } => {
                if !matches!(
                    self.custody.get(&id),
                    Some(Custody::Part { .. } | Custody::Response { .. })
                ) {
                    return Err(LinkError::BadValue);
                }
                self.reports.admitted.insert(id);
            }
            ToOwner::Released { id } => {
                // Dropping the owner's object refunds and wakes as it does
                // in-process; an uncommitted receipt means "not accepted".
                self.custody.remove(&id).ok_or(LinkError::BadValue)?;
                self.reports.admitted.remove(&id);
                self.reports.retained.remove(&id);
            }
            ToOwner::Retained { id, kind } => {
                if !matches!(self.custody.get(&id), Some(Custody::Permit { .. })) {
                    return Err(LinkError::BadValue);
                }
                self.reports.retained.insert(id, kind);
            }
            ToOwner::Committed { id } => {
                if !matches!(self.custody.get(&id), Some(Custody::Commit(_))) {
                    return Err(LinkError::BadValue);
                }
                if let Some(Custody::Commit(committed)) = self.custody.remove(&id) {
                    let _ = committed.send(());
                }
            }
            ToOwner::Frontier {
                stream,
                instance,
                geometry,
            } => {
                let geometry = geometry_from(geometry)?;
                if geometry.instance.get() != instance {
                    return Err(LinkError::BadValue);
                }
                self.reports.frontier.insert(stream, geometry);
            }
            ToOwner::Unconfirmed {
                stream,
                unconfirmed,
            } => {
                self.reports.unconfirmed.insert(stream, unconfirmed);
            }
            ToOwner::BudgetRetired { origin } => {
                let attachment = self
                    .control
                    .origin
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .attachment;
                if attachment == ctx_from(origin) {
                    self.control.budget.retire();
                }
            }
            ToOwner::Liveness { last_client_recv } => {
                self.reports.last_client_recv = last_client_recv;
            }
            ToOwner::End(_) => {
                *ended = true;
                self.end_inbound();
            }
        }
        Ok(())
    }

    fn on_gate(&mut self, id: u64, op: GateOpWire) -> Result<(), LinkError> {
        if id >= self.next_gate {
            return Err(LinkError::BadValue);
        }
        // A gate the owner no longer holds has no producer left to wake.
        let Some((stream, gate)) = self
            .gates_by_id
            .get(&id)
            .and_then(|owned| Some((owned.stream, owned.gate.upgrade()?)))
        else {
            return Ok(());
        };
        match op {
            // A bridge charges its own gap and bootstrap records only.
            GateOpWire::Admit(n) if n > MAX_LINK_ADMIT => return Err(LinkError::BadValue),
            GateOpWire::Admit(n) => gate.admit(n),
            GateOpWire::Withdraw(n) => gate.withdraw(n),
            GateOpWire::Transfer { n, tail } => {
                // As in-process: an opening by charge transfer wakes only the
                // gate's own waiters.
                gate.transfer(n, tail);
            }
            GateOpWire::Update { tail, ready } => {
                if gate.update(tail) {
                    if gate.kind() == GateKind::Screen {
                        self.synthesize(SessionInbound::Writable { stream });
                    }
                    if let Some((instance, generation)) = ready {
                        self.output_ready(stream, instance_from(instance)?, generation);
                    }
                }
            }
        }
        Ok(())
    }

    /// The bridge's coalesced metadata wake, latched on the owner's budget.
    fn output_ready(&mut self, stream: u8, instance: ChannelInstance, generation: u64) {
        let ready = self
            .budgets
            .get(&(stream, instance.get()))
            .is_some_and(|budget| budget.mark_output_ready(instance, generation));
        if ready {
            self.synthesize(SessionInbound::OutputReady {
                stream,
                instance,
                generation,
            });
        }
    }

    /// A data body longer than one frame goes ahead in `DataPart` frames;
    /// the record keeps the last piece, and the frontend joins them again.
    fn split_data(&self, mut record: OutRecord) -> OutRecord {
        let (OutRecord::ChannelOutput {
            output: OutputBody::Data(data),
            ..
        }
        | OutRecord::Data { data, .. }) = &mut record
        else {
            return record;
        };
        if data.len() <= DATA_FRAME_MAX {
            return record;
        }
        let last = (data.len() - 1) / DATA_FRAME_MAX * DATA_FRAME_MAX;
        for part in data[..last].chunks(DATA_FRAME_MAX) {
            self.to_frontend(ToFrontend::DataPart(part.to_vec()));
        }
        data.drain(..last);
        record
    }

    fn position(&mut self) -> u64 {
        let position = self.next_position;
        self.next_position = position.saturating_add(1);
        position << 2
    }

    fn gate_wire(&mut self, gate: &Arc<SendGate>, stream: u8) -> GateWire {
        let key = Arc::as_ptr(gate) as usize;
        let kind = gate_kind_wire(gate.kind());
        if let Some(&id) = self.gate_ids.get(&key) {
            // The held Weak keeps the address from being reused.
            return GateWire { id, kind };
        }
        let id = self.next_gate;
        self.next_gate += 1;
        self.gate_ids.insert(key, id);
        self.gates_by_id.insert(
            id,
            OwnedGate {
                stream,
                gate: Arc::downgrade(gate),
            },
        );
        if self.gates_by_id.len() > 64 && self.gates_by_id.len() > 2 * self.gates_pruned_at {
            // Forget gates nothing here holds any more. An address whose
            // Weak is dropped may be reused, so its key goes at the same time.
            self.gates_by_id
                .retain(|_, owned| owned.gate.strong_count() > 0);
            let live = &self.gates_by_id;
            self.gate_ids.retain(|_, id| live.contains_key(id));
            self.gates_pruned_at = self.gates_by_id.len();
        }
        GateWire { id, kind }
    }

    fn charge_wire(&mut self, position: u64, charge: OutputCharge, stream: u8) -> GateWire {
        let gate = self.gate_wire(charge.gate(), stream);
        self.custody
            .insert(position | SLOT_CHARGE, Custody::Charge(charge));
        gate
    }

    fn delivery_wire(&mut self, position: u64, delivery: ControlDelivery) -> Option<GateWire> {
        let ControlDelivery { part, charge } = delivery;
        self.custody
            .insert(position | SLOT_PART, Custody::Part { _held: part });
        charge.map(|charge| self.charge_wire(position, charge, crate::channel::CONTROL_STREAM))
    }

    fn budget(&mut self, stream: u8, instance: ChannelInstance, budget: TimelineBudget) {
        self.budgets.insert((stream, instance.get()), budget);
        // A stream keeps the budgets of its few latest instances.
        let stale: Vec<_> = self
            .budgets
            .range((stream, 0)..=(stream, u64::MAX))
            .rev()
            .skip(4)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.budgets.remove(&key);
        }
    }

    /// One message the backend sent, onto the link with its custody kept here.
    fn forward(&mut self, message: SessionOutbound) -> Result<(), LinkError> {
        let record = match message {
            SessionOutbound::RetirementReady {
                origin,
                decisions_complete,
            } => OutRecord::RetirementReady {
                origin: ctx_wire(origin),
                decisions_complete,
            },
            SessionOutbound::ReservedControl {
                origin,
                bytes,
                delivery,
            } => {
                let id = self.position();
                OutRecord::ReservedControl {
                    id,
                    origin: ctx_wire(origin),
                    charge: self.delivery_wire(id, delivery),
                    bytes,
                }
            }
            SessionOutbound::UpdateAccept {
                origin,
                bytes,
                delivery,
                committed,
            } => {
                let id = self.position();
                self.custody
                    .insert(id | SLOT_COMMIT, Custody::Commit(committed));
                OutRecord::UpdateAccept {
                    id,
                    origin: ctx_wire(origin),
                    charge: self.delivery_wire(id, delivery),
                    bytes,
                }
            }
            SessionOutbound::ReservedSessionControl { bytes, delivery } => {
                let id = self.position();
                OutRecord::ReservedSessionControl {
                    id,
                    charge: self.delivery_wire(id, delivery),
                    bytes,
                }
            }
            message @ (SessionOutbound::ResourceExhausted { .. }
            | SessionOutbound::CloseSession { .. }) => {
                let fallback = match message {
                    SessionOutbound::ResourceExhausted { origin } => TerminalRequest {
                        origin,
                        disposition: TerminalDisposition::ResourceExhausted,
                    },
                    SessionOutbound::CloseSession { origin } => TerminalRequest {
                        origin,
                        disposition: TerminalDisposition::Close,
                    },
                    _ => unreachable!("matched above"),
                };
                // The owner's control takes the bridge's part: consuming the
                // alias rearms `request_terminal` for a later attachment.
                let request = self.control.take_abort(fallback);
                let origin = ctx_wire(request.origin);
                match request.disposition {
                    TerminalDisposition::Close => OutRecord::CloseSession { origin },
                    TerminalDisposition::ResourceExhausted => {
                        OutRecord::ResourceExhausted { origin }
                    }
                }
            }
            SessionOutbound::ChannelOpened { stream, origin } => OutRecord::ChannelOpened {
                stream,
                origin: ctx_wire(origin),
            },
            SessionOutbound::ChannelRefused {
                stream,
                origin,
                reason,
            } => OutRecord::ChannelRefused {
                stream,
                origin: ctx_wire(origin),
                reason: reason.into_bytes(),
            },
            SessionOutbound::RepaintBarrier {
                generation,
                sequence,
            } => OutRecord::RepaintBarrier {
                id: self.position(),
                generation,
                sequence,
            },
            SessionOutbound::ChannelClosed {
                position: _,
                stream,
                instance,
                origin,
            } => {
                let stale: Vec<_> = self
                    .budgets
                    .range((stream, 0)..=(stream, instance.get()))
                    .map(|(key, _)| *key)
                    .collect();
                for key in stale {
                    self.budgets.remove(&key);
                }
                OutRecord::ChannelClosed {
                    id: self.position(),
                    stream,
                    instance: instance.get(),
                    origin: ctx_wire(origin),
                }
            }
            SessionOutbound::ChannelOutput {
                position: _,
                stream,
                instance,
                origin,
                output,
                charge,
                gap_reserve,
            } => {
                let id = self.position();
                let (body, permit) = match output {
                    ChannelOutput::Data(data) => (OutputBody::Data(data), None),
                    ChannelOutput::Geometry(g, permit) => {
                        (OutputBody::Geometry(geometry_wire(g)), Some(permit))
                    }
                    ChannelOutput::EchoAck(n, permit) => (OutputBody::EchoAck(n), Some(permit)),
                    ChannelOutput::OutputGap(cause, permit) => {
                        (OutputBody::OutputGap(cause as u8), Some(permit))
                    }
                    ChannelOutput::DeliveryMarker(marker, permit) => (
                        OutputBody::DeliveryMarker {
                            token: marker.token,
                        },
                        Some(permit),
                    ),
                };
                if let Some(budget) = gap_reserve.as_ref().or(permit.as_ref()).map(|p| p.budget()) {
                    self.budget(stream, instance, budget);
                }
                let gate = self.charge_wire(id, charge, stream);
                if let Some(permit) = permit {
                    self.custody
                        .insert(id | SLOT_PERMIT, Custody::Permit { _held: permit });
                }
                let has_reserve = gap_reserve.is_some();
                if let Some(reserve) = gap_reserve {
                    self.custody
                        .insert(id | SLOT_GAP_RESERVE, Custody::Permit { _held: reserve });
                }
                OutRecord::ChannelOutput {
                    id,
                    stream,
                    instance: instance.get(),
                    origin: ctx_wire(origin),
                    output: body,
                    gate,
                    gap_reserve: has_reserve,
                }
            }
            SessionOutbound::ChannelExit {
                position: _,
                stream,
                instance,
                origin,
                code,
                open,
                permit,
                control,
            } => {
                let id = self.position();
                let control_bytes =
                    u32::try_from(control.part.encoded_bytes()).map_err(|_| LinkError::TooLong)?;
                self.budget(stream, instance, permit.budget());
                self.custody
                    .insert(id | SLOT_PERMIT, Custody::Permit { _held: permit });
                let charge = self.delivery_wire(id, control);
                OutRecord::ChannelExit {
                    id,
                    stream,
                    instance: instance.get(),
                    origin: ctx_wire(origin),
                    code,
                    open: open_wire(open),
                    control_bytes,
                    charge,
                }
            }
            SessionOutbound::ResumeSnapshotReady => {
                let Some((generation, reserved)) = self.mailbox.take_for_link() else {
                    return Ok(());
                };
                let (snapshot, prefix, [source, merged, wire]) = reserved.into_link_parts();
                let mut dto = snapshot.encode_record();
                dto.drain(..5);
                let id = self.position();
                self.custody
                    .insert(id | SLOT_COMMIT, Custody::Response { _held: source });
                self.custody
                    .insert(id | SLOT_PERMIT, Custody::Response { _held: merged });
                self.custody
                    .insert(id | SLOT_PART, Custody::Response { _held: wire });
                self.to_frontend(ToFrontend::Snapshot {
                    id,
                    generation,
                    prefix,
                    dto,
                });
                return Ok(());
            }
            SessionOutbound::ProtocolFailure { origin, code } => OutRecord::ProtocolFailure {
                origin: ctx_wire(origin),
                code: code.map(|c| c as u16),
            },
            SessionOutbound::Data(StreamData { stream_id, data }) => {
                // `SessionIo::send` counts raw bytes on the stream's gate until
                // the bridge takes them; for a remote bridge, until here.
                if let Some(gate) = self.gates.admit(stream_id, 0) {
                    gate.withdraw(data.len() as u64);
                }
                OutRecord::Data {
                    stream: stream_id,
                    data,
                }
            }
            SessionOutbound::Resyncable {
                stream_id,
                resyncable,
            } => OutRecord::Resyncable {
                stream: stream_id,
                resyncable,
            },
            SessionOutbound::StreamClass { stream_id, class } => OutRecord::StreamClass {
                stream: stream_id,
                bulk: class == StreamClass::Bulk,
            },
            SessionOutbound::NotifyDelivered { stream_id, token } => OutRecord::NotifyDelivered {
                stream: stream_id,
                token,
            },
            SessionOutbound::Consumed { stream_id, n } => OutRecord::Consumed {
                stream: stream_id,
                n: n as u64,
            },
        };
        self.to_frontend(ToFrontend::Record(self.split_data(record)));
        Ok(())
    }
}
