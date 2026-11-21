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
//! **A replaced link.** A link ends without ending the session when the
//! frontend retires it in order (`Retire`, at every warm reattach) or when
//! it is lost (end of input or a write failure with no `End`: the frontend
//! died, or the socket did). The owner then keeps the backend running and
//! everything it sends, with its custody, in its *journal* (`Journal`), and
//! a link that replaces the old one ([`OwnerRelink`]) starts with a replay
//! from which the frontend builds a fresh bridge: declarations and
//! tombstones, the stream instances the earlier bridge held, the journal's
//! items in position order, then each stream's frontier, confirmation flag
//! and retained marker or gap. The attachment generation continues from the
//! highest one the owner has seen.
//!
//! What a lost link costs, and never more: inbound events the dead frontend
//! had not written (see above), and output bytes that had crossed it. The
//! link's last reports may be missing, so the owner cannot tell which of
//! those bytes the old connection carried: it gives them all up rather than
//! send one twice, and every stream that had sent or was sent anything owes
//! its next client the gap warning (`PreviousConnectionOutputUnconfirmed`),
//! spuriously if nothing was in fact missing. Output produced while no link
//! was up never crossed, and follows. A retired link reports exactly --
//! the owner reads it to its `Retire` even when its own writes to it fail,
//! since the frontend closes it right behind that frame -- and then nothing
//! is given up and nothing replayed twice. Input is never replayed at all.

#[path = "owner_link_codec.rs"]
pub(crate) mod codec;
#[cfg(test)]
#[path = "owner_link_codec_tests.rs"]
mod codec_tests;
#[cfg(test)]
#[path = "owner_link_journal_tests.rs"]
mod journal_tests;
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
/// The framed size of an output gap record.
const GAP_RECORD_BYTES: u64 = 14;
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
/// How long an owner lets a link that is being replaced go on before it
/// takes it for lost: its frontend ends it in order (`Retire`) right behind
/// handing over the next one, so a link still up after this belongs to a
/// frontend that hangs. Below the frontend's wait for the replay
/// (`REBUILD_TIMEOUT`), so the new link is still listened to when it starts.
const RETIRE_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);
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
    fn start(&self, init: OwnerInit) -> std::io::Result<StartedOwner>;
}

/// A started owner, as its frontend holds it.
pub struct StartedOwner {
    /// The frontend's end of the owner's first link.
    pub link: Box<dyn LinkIo>,
    /// Replaces the link, at every warm reattach and after a lost one.
    pub relink: Arc<dyn FrontendRelink>,
}

/// The frontend's way to give a running owner a new link.
pub trait FrontendRelink: Send + Sync + 'static {
    /// Asked once a link was lost: whether the owner is gone, and the
    /// session with it (it then ends, as with a backend that stopped). An
    /// owner that dies takes its link down a moment before its exit can be
    /// observed, so an implementation waits for that exit, for a short
    /// bounded time, before it answers `false`.
    fn exited(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
    /// Hand the owner one end of a new link and return the other. The
    /// owner ends its current link first (it reads it to its `Retire` or
    /// to its end), then replays its custody on the new one.
    ///
    /// An error of kind [`std::io::ErrorKind::TimedOut`] or
    /// [`std::io::ErrorKind::WouldBlock`] says the owner could not be
    /// reached just now ([`relink_unavailable`]): the session is kept for
    /// a later attempt. Any other error says the owner is gone. "Not now"
    /// usually means nothing changed; but after an answer that came too
    /// late (or a local failure taking it), the host has already handed the
    /// owner its end of a link nobody holds. The owner then moves onto that
    /// link, takes the current one for lost once `RETIRE_WITHIN` passed,
    /// and the next attempt recovers the session through the lost-link
    /// path (its replay).
    fn relink(&self) -> std::io::Result<Box<dyn LinkIo>>;
}

/// Whether a [`FrontendRelink::relink`] error means "not now" rather than
/// "the owner is gone".
pub fn relink_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// What a frontend that can be replaced keeps where it outlives it (#529):
/// the host process, which holds every session's owner. The router asks it
/// about logins it has never heard of, and tells it what a later frontend
/// must find unchanged.
pub trait SessionDirectory: Send + Sync + 'static {
    /// Whether `login`'s session runs behind an owner an earlier frontend
    /// left, for a warm start by `uid`. Bounded: no answer in time is
    /// [`Lookup::Unavailable`], never `Unknown`.
    fn lookup(&self, login: LoginId, uid: u32)
        -> Pin<Box<dyn Future<Output = Lookup> + Send + '_>>;
    /// Whether `login` had a session when this frontend started: the hint
    /// an unproven warm handshake is answered with. Never waits.
    fn known(&self, login: LoginId) -> bool;
    /// `login`'s client was heard, or its session was retained. Never waits.
    fn liveness(&self, login: LoginId, liveness: Liveness);
    /// `key` was scrubbed off the allowlist. Never waits.
    fn key_scrubbed(&self, key: [u8; 32]);
    /// `login`'s session is now its client's under `key`, the key its
    /// handshake proved: whoever ends the session where this process
    /// cannot scrubs it. Never waits.
    fn client_key(&self, login: LoginId, key: [u8; 32]) {
        let _ = (login, key);
    }
    /// The secret this process answers connections it does not route with
    /// (`crate::session_reset`): kept by the host, so every frontend -- and
    /// the daemon after a restart -- derives the same tokens. `None`: no
    /// resets, and the feature is not offered in msg2.
    fn session_reset(&self) -> Option<crate::session_reset::SessionResetSecret> {
        None
    }
}

/// What the directory knows of a login the router does not.
pub enum Lookup {
    /// No session: a warm start gets a fresh one, as before.
    Unknown,
    /// No answer (in time): whether there is a session is not known. The
    /// handshake is dropped and nothing else changes -- above all no fresh
    /// session replaces one that may still run. A client whose `msg1` was
    /// not answered yet (the allowlist path) asks again with its
    /// retransmit; one that already holds `msg2` (the signature path, whose
    /// `msg2` goes out when its proof is checked) hears nothing more on that
    /// connection and comes back when its death timer ends it.
    Unavailable,
    /// A session of another account: refused.
    Foreign,
    /// The session runs behind this owner, on a link that replaces the one
    /// its earlier frontend held.
    Running(StartedOwner),
}

/// What a frontend reports of a session's client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The client was last heard `idle` ago; `active` while that is recent
    /// (the daemon's count of active sessions).
    Traffic {
        idle: std::time::Duration,
        active: bool,
    },
    /// The client's connection died, now: the session is retained.
    Retained,
}

/// Hands a session owner the link that replaces its current one
/// ([`OwnerInit::relinks`]). A link given while an earlier one still waits
/// takes its place.
#[derive(Clone, Default)]
pub struct OwnerRelink(Arc<LinkSlot>);

#[derive(Default)]
struct LinkSlot {
    next: Mutex<Option<Box<dyn LinkIo>>>,
    ready: tokio::sync::Notify,
}

impl OwnerRelink {
    /// Replace the owner's link with `link`.
    pub fn relink(&self, link: impl LinkIo) {
        *self.0.next.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(link));
        self.0.ready.notify_one();
    }

    /// The next link handed over. Cancel-safe.
    async fn next(&self) -> Box<dyn LinkIo> {
        loop {
            let notified = self.0.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(link) = self.0.next.lock().unwrap_or_else(|e| e.into_inner()).take() {
                return link;
            }
            notified.await;
        }
    }
}

/// An in-process owner's relink: the other end goes straight to its slot.
struct LoopbackRelink {
    owner: OwnerRelink,
    done: Arc<std::sync::atomic::AtomicBool>,
}
impl FrontendRelink for LoopbackRelink {
    fn exited(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(std::future::ready(self.done.load(Ordering::SeqCst)))
    }
    fn relink(&self) -> std::io::Result<Box<dyn LinkIo>> {
        if self.done.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the session owner is gone"));
        }
        let (front, owner) = loopback();
        self.owner.relink(owner);
        Ok(Box::new(front))
    }
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

/// Read a retired link to its end and drop what arrives: the owner closes
/// its side once it has read the link's `Retire` (or at once, if the link
/// was lost).
async fn drain_retired<R: AsyncRead + Unpin>(mut read: R, lifecycle: Arc<Lifecycle>) {
    let mut buf = vec![0; READ_CHUNK].into_boxed_slice();
    loop {
        tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => return,
            got = read.read(&mut buf) => {
                if !matches!(got, Ok(n) if n > 0) {
                    return;
                }
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

/// How long a stopping owner's writer may take to say `Finished`.
const FAREWELL_WITHIN: std::time::Duration = std::time::Duration::from_millis(200);

/// The owner's writer: `priority` first, until both senders are gone (then
/// the write half is shut, an orderly end of input), a write fails, or the
/// session's lifecycle stops. A stop ends the session: the writer says so
/// (`Finished`, between whole frames) if the link takes it at once, so a
/// frontend that lives on ends the session instead of taking the link for
/// lost.
async fn owner_write_loop<W: AsyncWrite + Unpin>(
    mut write: W,
    mut data: mpsc::UnboundedReceiver<ToFrontend>,
    mut priority: mpsc::UnboundedReceiver<ToFrontend>,
    failure: Arc<LinkFailure>,
    lifecycle: Arc<Lifecycle>,
    abandon: Shutdown,
) {
    let mut out = Vec::new();
    loop {
        let first = tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => {
                // A lost session says nothing on its way out.
                if abandon.is_requested() {
                    return;
                }
                out.clear();
                if encode(&ToFrontend::Finished, &mut out).is_ok() {
                    let _ = tokio::time::timeout(FAREWELL_WITHIN, async {
                        if write.write_all(&out).await.is_ok() {
                            let _ = write.shutdown().await;
                        }
                    })
                    .await;
                }
                return;
            }
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
            _ = lifecycle.shutdown.requested() => {
                // This frontend stops in order. What its bridge handed over
                // and is still queued here goes out, if the owner takes it
                // at once: input booked as handed over is then not lost
                // with the process. Never an `End`: a frontend that stops
                // does not end its sessions (the link is then lost, and the
                // owner parks).
                out.clear();
                let whole = queue
                    .take_for_exit()
                    .iter()
                    .all(|m| encode(m, &mut out).is_ok());
                if whole && !out.is_empty() {
                    let _ = tokio::time::timeout(FAREWELL_WITHIN, async {
                        if write.write_all(&out).await.is_ok() {
                            let _ = write.flush().await;
                        }
                    })
                    .await;
                }
                return;
            }
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
    /// The link was retired in order: `Retire` is its last message.
    retired: bool,
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
        if st.failed || st.retired {
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

    fn failed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).failed
    }

    /// The frontend stops: everything queued, in order, up to an `End` (a
    /// stopping frontend's bridges drop their senders, and that must not
    /// end a session). Nothing is accepted afterwards.
    fn take_for_exit(&self) -> Vec<ToOwner> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.failed {
            return Vec::new();
        }
        st.failed = true;
        st.keyed.clear();
        st.live = 0;
        std::mem::take(&mut st.entries)
            .into_iter()
            .flatten()
            .flatten()
            .take_while(|m| !matches!(m, ToOwner::End(_)))
            .collect()
    }

    /// End this link in order: `Retire` goes last, and whatever a token of
    /// this link reports afterwards is dropped -- the owner's journal
    /// decides about everything the link's bridge still held.
    fn retire(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.failed || st.retired {
            return;
        }
        st.entries.push_back(Some(vec![ToOwner::Retire]));
        st.live += 1;
        st.retired = true;
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
                if st.retired || self.senders.load(Ordering::SeqCst) == 0 {
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
    fn unconfirmed(&self, instance: ChannelInstance, unconfirmed: bool) {
        self.link.send(ToOwner::Unconfirmed {
            stream: self.stream,
            instance: instance.get(),
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

/// One link of a frontend to its owner, from its setup until the next one
/// replaces it.
struct Epoch {
    read: tokio::io::ReadHalf<Box<dyn LinkIo>>,
    link: LinkTx,
    queue: Arc<LinkQueue>,
    credits: Arc<Credits>,
    failure: Arc<LinkFailure>,
    /// A link that replaced an earlier one starts with the owner's replay.
    replaces: bool,
}

/// The writing side of a new link: its queue, credits and writer task.
fn open_epoch(
    link: Box<dyn LinkIo>,
    lifecycle: &Arc<Lifecycle>,
    replaces: bool,
) -> (Epoch, CreditSender) {
    let (read, write) = tokio::io::split(link);
    let (tx, queue) = LinkTx::new();
    let failure = Arc::new(LinkFailure::default());
    let credits = Arc::new(Credits::default());
    lifecycle.spawn(frontend_write_loop(
        write,
        queue.clone(),
        failure.clone(),
        lifecycle.clone(),
    ));
    let sender = CreditSender {
        credits: credits.clone(),
        link: tx.clone(),
    };
    (
        Epoch {
            read,
            link: tx,
            queue,
            credits,
            failure,
            replaces,
        },
        sender,
    )
}

struct RemoteState {
    /// The current link's queue.
    link: LinkTx,
    queue: Arc<LinkQueue>,
    /// The first link's inbound sender, until the bridge takes it.
    inbound: Option<CreditSender>,
    /// A link the bridge set up that the reader has not taken over yet.
    next: Option<Epoch>,
    /// The current link was lost and no other has replaced it.
    lost: bool,
}

/// What the frontend's session control holds for its owner link.
pub(super) struct RemoteControl {
    state: Mutex<RemoteState>,
    next_ready: tokio::sync::Notify,
    relinker: Option<Arc<dyn FrontendRelink>>,
    lifecycle: Arc<Lifecycle>,
}
impl RemoteControl {
    fn state(&self) -> std::sync::MutexGuard<'_, RemoteState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The bridge's inbound sender, taken once by the bridge.
    pub(super) fn take_inbound(&self) -> Option<CreditSender> {
        self.state().inbound.take()
    }

    /// A message of the bridge's own on the current link.
    pub(super) fn send(&self, msg: ToOwner) {
        let link = self.state().link.clone();
        link.send(msg);
    }

    /// Whether this owner's link can be replaced: then every warm reattach
    /// rebuilds the bridge from the owner's custody over a new link.
    pub(super) fn can_relink(&self) -> bool {
        self.relinker.is_some()
    }

    /// The link was lost, and the bridge waits for a warm reattach to
    /// replace it.
    pub(super) fn lost(&self) -> bool {
        self.state().lost
    }

    /// Replace the current link: hand the owner a new one, end the current
    /// one in order behind everything its bridge reported (a lost one has
    /// ended already), and return the new link's inbound sender. The
    /// owner's replay arrives in the bridge's queue behind a `Start` step;
    /// whatever is ahead of that belongs to the replaced link, and its
    /// tokens report nothing any more.
    ///
    /// Also says whether the replaced link was lost, as known once the new
    /// one is in place: a loss the reader has seen but not announced yet
    /// (it is still asking whether the owner exited) counts.
    ///
    /// Two steps: [`RemoteControl::replacement`] obtains the new link and
    /// changes nothing else -- when it fails, the current link and every
    /// report are as they were -- and this installs it.
    pub(super) fn replacement(&self) -> std::io::Result<Box<dyn LinkIo>> {
        self.relinker
            .as_ref()
            .ok_or_else(|| std::io::Error::other("this owner link cannot be replaced"))?
            .relink()
    }

    /// See [`RemoteControl::replacement`].
    pub(super) fn relink_with(&self, link: Box<dyn LinkIo>) -> (CreditSender, bool) {
        let (epoch, sender) = open_epoch(link, &self.lifecycle, true);
        let (old, lost) = {
            let mut state = self.state();
            let old = std::mem::replace(&mut state.queue, epoch.queue.clone());
            state.link = epoch.link.clone();
            state.next = Some(epoch);
            let lost = std::mem::take(&mut state.lost) || old.failed();
            (old, lost)
        };
        old.retire();
        self.next_ready.notify_one();
        (sender, lost)
    }

    /// [`RemoteControl::replacement`], then [`RemoteControl::relink_with`].
    #[cfg(test)]
    pub(super) fn relink(&self) -> std::io::Result<(CreditSender, bool)> {
        Ok(self.relink_with(self.replacement()?))
    }

    /// The next link the bridge set up. Cancel-safe.
    async fn next_epoch(&self) -> Epoch {
        loop {
            let notified = self.next_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(epoch) = self.state().next.take() {
                return epoch;
            }
            notified.await;
        }
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
    directory: Option<Arc<dyn SessionDirectory>>,
}

impl RemoteBackend {
    /// Run `inner` for each session in an in-process owner over a loopback link.
    pub fn loopback(inner: Arc<dyn SessionBackend>) -> RemoteBackend {
        RemoteBackend {
            inner,
            starter: None,
            directory: None,
        }
    }

    /// The owners outlive this process: `directory` knows the sessions an
    /// earlier frontend left running, and keeps what a later one must find.
    pub fn with_directory(mut self, directory: Arc<dyn SessionDirectory>) -> RemoteBackend {
        self.directory = Some(directory);
        self
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
            directory: None,
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
            return match starter.start(init) {
                Ok(started) => Box::pin(start_frontend(
                    io,
                    started.link,
                    Some(started.relink),
                    false,
                )),
                Err(error) => {
                    log::error!("cannot start a session owner: {error}");
                    // A link whose owner end is gone: the frontend reads end
                    // of input at once, and the session ends as with a
                    // backend that stopped.
                    let (front, _owner) = loopback();
                    Box::pin(start_frontend(io, Box::new(front), None, false))
                }
            };
        }
        let (front, owner) = loopback();
        let init = OwnerInit {
            principal: io.principal().clone(),
            login: io.login(),
            last_generation: 0,
            lifecycle: Some(io.lifecycle.clone()),
            relinks: OwnerRelink::default(),
            abandon: Shutdown::default(),
        };
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let relink = Arc::new(LoopbackRelink {
            owner: init.relinks(),
            done: done.clone(),
        });
        let inner = self.inner.clone();
        io.lifecycle.spawn(async move {
            let exit = OwnerLink::run(owner, inner, init).await;
            done.store(true, Ordering::SeqCst);
            if exit == OwnerExit::LinkLost {
                log::warn!("session owner lost its frontend link");
            }
        });
        Box::pin(start_frontend(io, Box::new(front), Some(relink), false))
    }

    fn consumption(&self) -> Consumption {
        self.inner.consumption()
    }

    fn directory(&self) -> Option<Arc<dyn SessionDirectory>> {
        self.directory.clone()
    }

    /// A new frontend process takes a running owner over: `owner.link`
    /// replaces the link the earlier frontend held, so the owner's replay
    /// comes first on it.
    fn resume(
        &self,
        io: SessionIo,
        owner: StartedOwner,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(start_frontend(io, owner.link, Some(owner.relink), true))
    }
}

struct Frontend<'a> {
    io: &'a SessionIo,
    link: LinkTx,
    credits: Arc<Credits>,
    mirrors: HashMap<u64, Weak<SendGate>>,
    mirrors_pruned_at: usize,
    /// Leading pieces of the next data record's body.
    data_parts: Vec<u8>,
    /// A replacing link has not started its replay yet.
    awaits_replay: bool,
    /// Between the owner's `ReplayStart` and `ReplayDone`.
    replaying: bool,
    /// The owner said its backend finished.
    finished: bool,
}

/// How one link's reading ended.
enum ReadEnd {
    /// The session is over: the backend finished, the frontend refused the
    /// link, or the lifecycle stopped.
    Over,
    /// The link died under a running session.
    Lost,
    /// The bridge replaced the link.
    Replaced(Epoch),
}

/// Set up the frontend end of `link` for the bridge that owns `io` (its
/// writer, and the inbound sender the bridge takes from the session
/// control), and return the reader that feeds the owner's records into the
/// bridge's queue. The reader returns when the owner closes the link behind
/// `Finished` (the backend is done), on a link error (the session then ends
/// as with a backend that stopped), or on shutdown. A link that is lost
/// under an owner that `relink` says still runs does not end it: the bridge
/// hears `Lost`, and the reader goes on with the link the bridge replaces
/// it with (`RemoteControl::relink`), as it does at every replacement.
///
/// `replaces` says `link` itself replaces a link an earlier frontend held to
/// a running owner (a new frontend process): the owner's replay comes first
/// on it, and the bridge starts from `rebuild_from_owner`.
pub(super) fn start_frontend(
    io: SessionIo,
    link: Box<dyn LinkIo>,
    relink: Option<Arc<dyn FrontendRelink>>,
    replaces: bool,
) -> impl Future<Output = ()> + Send {
    let lifecycle = io.lifecycle.clone();
    let (epoch, sender) = open_epoch(link, &lifecycle, replaces);
    let _ = io.control().remote.set(RemoteControl {
        state: Mutex::new(RemoteState {
            link: epoch.link.clone(),
            queue: epoch.queue.clone(),
            inbound: Some(sender),
            next: None,
            lost: false,
        }),
        next_ready: tokio::sync::Notify::new(),
        relinker: relink,
        lifecycle: lifecycle.clone(),
    });
    run_epochs(io, epoch, lifecycle)
}

async fn run_epochs(io: SessionIo, mut epoch: Epoch, lifecycle: Arc<Lifecycle>) {
    let control = io.control().clone();
    let Some(remote) = control.remote.get() else {
        return;
    };
    loop {
        let Epoch {
            read,
            link,
            queue,
            credits,
            failure,
            replaces,
        } = epoch;
        let mut front = Frontend {
            io: &io,
            link,
            credits: credits.clone(),
            mirrors: HashMap::new(),
            mirrors_pruned_at: 0,
            data_parts: Vec::new(),
            awaits_replay: replaces,
            replaying: false,
            finished: false,
        };
        let end = front
            .read(LinkReader::new(read), failure, &lifecycle, remote)
            .await;
        drop(front);
        match end {
            ReadEnd::Replaced(next) => epoch = next,
            ReadEnd::Over => {
                // The backend is gone: what still waits for it goes with it.
                credits.close();
                return;
            }
            ReadEnd::Lost => {
                // Nothing reaches the owner over this link any more.
                credits.close();
                queue.fail();
                let Some(relinker) = remote.relinker.as_ref() else {
                    return;
                };
                let exited = tokio::select! {
                    biased;
                    _ = lifecycle.shutdown.requested() => return,
                    exited = relinker.exited() => exited,
                };
                if exited {
                    return;
                }
                // Unless the bridge replaced the link meanwhile: then this
                // loss is the replaced link's, and nobody's concern.
                let lost = {
                    let mut state = remote.state();
                    state.lost = state.next.is_none();
                    state.lost
                };
                if lost {
                    log::warn!("owner link: the link was lost; waiting for a warm reattach");
                    let _ = io
                        .outbound
                        .send(SessionOutbound::Replay(ReplayStep::new(Replay::Lost)));
                }
                epoch = tokio::select! {
                    biased;
                    _ = lifecycle.shutdown.requested() => return,
                    next = remote.next_epoch() => next,
                };
            }
        }
    }
}

impl Frontend<'_> {
    async fn read<R: AsyncRead + Unpin + Send + 'static>(
        &mut self,
        mut reader: LinkReader<R>,
        failure: Arc<LinkFailure>,
        lifecycle: &Arc<Lifecycle>,
        remote: &RemoteControl,
    ) -> ReadEnd {
        loop {
            let frame = tokio::select! {
                biased;
                _ = lifecycle.shutdown.requested() => return ReadEnd::Over,
                // The bridge replaced this link: what it still carries
                // belongs to the bridge that is gone. It stays open until
                // the owner has read its `Retire` and closed its side, so
                // the owner never finds it broken under its own writes.
                next = remote.next_epoch() => {
                    lifecycle.spawn(drain_retired(reader.read, lifecycle.clone()));
                    return ReadEnd::Replaced(next);
                }
                _ = failure.failed() => {
                    log::error!("owner link: frontend write failed");
                    return ReadEnd::Lost;
                }
                frame = reader.next() => frame,
            };
            match frame {
                Ok(Some(frame)) => {
                    if let Err(error) = self.on_frame(&frame) {
                        log::error!("owner link: frontend refused a frame ({error:?})");
                        self.link.send(ToOwner::End(EndKind::Destroy));
                        return ReadEnd::Over;
                    }
                }
                // The owner forwarded everything its backend sent.
                Ok(None) if self.finished => return ReadEnd::Over,
                // No `Finished`, or a frame cut short: the link died.
                Ok(None) | Err(LinkError::Truncated) => return ReadEnd::Lost,
                Err(error) => {
                    log::error!("owner link: frontend read failed ({error:?})");
                    self.link.send(ToOwner::End(EndKind::Destroy));
                    return ReadEnd::Over;
                }
            }
        }
    }

    fn on_frame(&mut self, frame: &Frame) -> Result<(), LinkError> {
        let message = ToFrontend::decode(frame)?;
        let replay = matches!(message, ToFrontend::ReplayItem(_));
        match message {
            ToFrontend::Grant { slots } => self.credits.grant(slots)?,
            ToFrontend::DataPart(part) => {
                if self.data_parts.len() + part.len() > MAX_DATA_RECORD {
                    return Err(LinkError::TooLong);
                }
                self.data_parts.extend_from_slice(&part);
            }
            ToFrontend::Record(mut record) | ToFrontend::ReplayItem(mut record) => {
                if self.awaits_replay || replay != self.replaying {
                    return Err(LinkError::BadValue);
                }
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
            ToFrontend::ReplayStart {
                last_generation,
                live_seen,
                observed,
            } => {
                if !std::mem::take(&mut self.awaits_replay) {
                    return Err(LinkError::BadValue);
                }
                self.replaying = true;
                // Typed records behind the replay continue the owner's
                // numbering; the replayed ones carry no queue prefix.
                self.io.resume_snapshots.rebase(observed);
                self.step(Replay::Start {
                    last_generation,
                    live_seen,
                });
            }
            ToFrontend::ReplayStream {
                stream,
                instance,
                reserve,
                gate,
            } => {
                self.in_replay()?;
                let instance = instance_from(instance)?;
                let gate = self.mirror(gate)?;
                let reserve = self.permit(reserve, stream);
                self.step(Replay::Stream {
                    stream,
                    instance,
                    gate,
                    reserve,
                });
            }
            ToFrontend::ReplayFrontier {
                stream,
                instance,
                geometry,
            } => {
                self.in_replay()?;
                let geometry = geometry_from(geometry)?;
                if geometry.instance.get() != instance {
                    return Err(LinkError::BadValue);
                }
                self.step(Replay::Frontier { stream, geometry });
            }
            ToFrontend::ReplayUnconfirmed {
                stream,
                unconfirmed,
            } => {
                self.in_replay()?;
                if unconfirmed {
                    self.step(Replay::Unconfirmed { stream });
                }
            }
            ToFrontend::ReplayRetained { stream, kind } => {
                self.in_replay()?;
                self.step(Replay::Retained {
                    stream,
                    marker: kind == RetainedKind::Marker,
                });
            }
            ToFrontend::ReplayDone => {
                self.in_replay()?;
                self.replaying = false;
                self.step(Replay::Done);
            }
            ToFrontend::Finished => self.finished = true,
        }
        Ok(())
    }

    fn in_replay(&self) -> Result<(), LinkError> {
        if self.replaying {
            Ok(())
        } else {
            Err(LinkError::BadValue)
        }
    }

    fn step(&self, step: Replay) {
        self.send(SessionOutbound::Replay(ReplayStep::new(step)));
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
        if self.replaying {
            // A replayed record keeps position 0: it satisfied its queue
            // prefix under the link that is gone.
            return self.send(message);
        }
        // Positions follow the frontend's own mailbox, in the owner's
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
    /// fresh session): the owner's count continues from it.
    pub last_generation: u64,
    /// The lifecycle the owner's backend joins: the frontend's own one for an
    /// in-process owner, a fresh one otherwise.
    lifecycle: Option<Arc<Lifecycle>>,
    relinks: OwnerRelink,
    /// Requested ahead of the lifecycle's stop when the session is lost
    /// rather than ended (`OwnerInit::abandon`).
    abandon: Shutdown,
}

impl OwnerInit {
    /// A session owner with its own lifecycle.
    pub fn new(principal: Principal, login: LoginId) -> OwnerInit {
        OwnerInit {
            principal,
            login,
            last_generation: 0,
            lifecycle: None,
            relinks: OwnerRelink::default(),
            abandon: Shutdown::default(),
        }
    }

    /// The handle that gives this owner a link in place of its current one.
    pub fn relinks(&self) -> OwnerRelink {
        self.relinks.clone()
    }

    /// Requested before the owner's lifecycle stops when its session is
    /// lost, not ended -- the owner's host process died: its link then
    /// closes without `Finished`. Whatever still reads the link (a
    /// frontend process that outlives the host for a moment) must not end
    /// the client's session as if its shell had ended; the client finds
    /// the session gone, as when a single-process daemon dies.
    pub fn abandon(&self) -> Shutdown {
        self.abandon.clone()
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

/// One journaled record: what it takes to send it again.
struct JournalItem {
    record: OutRecord,
    /// The bridge kept it past its admission (a delivered final marker, a
    /// terminal gap): a rebuilt bridge puts it back there.
    retained: Option<RetainedKind>,
    /// It crossed a link: that link's bridge may have sent it on, whatever
    /// reports of it arrived.
    forwarded: bool,
}

/// A stream instance the frontend's bridge holds state for: it took the
/// instance's gap reserve with the instance's first record, and has not
/// released it.
struct JournalStream {
    instance: u64,
    /// The custody id of the gap reserve.
    reserve: u64,
    gate: GateWire,
}

/// What a session owner keeps so that a new frontend's bridge can be built
/// from nothing (the bridge-held state a frontend death would lose).
///
/// - **J1, output.** Every typed record (`ChannelOutput`, `ChannelExit`) and
///   every `ReservedSessionControl` the frontend has neither released nor
///   reported admitted, by owner queue position, with its body. A record's
///   custody stays in `Owner::custody`; the item goes when the frontend
///   reports it admitted, transferred, withdrawn or released. An item the
///   frontend reported `Retained`, and a terminal gap whose charge it
///   transferred, stays until its permit is released. A data record loses
///   the bytes the frontend reports sent slice by slice, so a rebuild never
///   sends them twice.
/// - **Stream instances.** The gap reserve of each instance the bridge
///   holds (one per stream): a rebuilt bridge needs the instance's state
///   even when nothing of it is queued.
/// - **J2, frontier** and **J3, the confirmation flag**, per stream, as the
///   frontend last reported them.
/// - **J4, declarations**: the latest recoverability and class per stream,
///   and the highest closed or exited instance per stream (tombstones).
/// - **J5, consumption**: per stream, bytes handed to the backend that it
///   has not reported (`unreported`), and the part of them a replaced link
///   handed over (`owed`): later reports pay that first and are not
///   forwarded, so a new connection is never credited another's bytes.
/// - **J6**: the highest attachment generation seen, and whether the
///   backend heard `Live`.
///
/// Bounds: items and their bodies by the gates, timeline budgets and reply
/// budgets that bound the bridge's own queue (the custody is the same);
/// everything else by the stream number space.
#[derive(Default)]
struct Journal {
    items: BTreeMap<u64, JournalItem>,
    streams: BTreeMap<u8, JournalStream>,
    frontier: BTreeMap<u8, GeometryRecord>,
    /// The instance the flag was reported for, and the flag.
    unconfirmed: BTreeMap<u8, (u64, bool)>,
    resyncable: BTreeMap<u8, bool>,
    bulk: std::collections::BTreeSet<u8>,
    tombstones: BTreeMap<u8, u64>,
    unreported: BTreeMap<u8, u64>,
    owed: BTreeMap<u8, u64>,
    last_generation: u64,
    live_seen: bool,
    /// The backend's queue position of the last typed record taken from it.
    last_typed: u64,
}

impl Journal {
    fn tombstone(&mut self, stream: u8, instance: u64) {
        let old = self.tombstones.entry(stream).or_insert(instance);
        *old = (*old).max(instance);
    }

    /// A record the backend sent: keep what a rebuild needs of it.
    fn record(&mut self, record: &OutRecord) {
        match record {
            OutRecord::ChannelOutput {
                id,
                stream,
                instance,
                gate,
                gap_reserve,
                ..
            } => {
                if *gap_reserve {
                    if self
                        .streams
                        .get(stream)
                        .is_none_or(|held| held.instance != *instance)
                    {
                        self.frontier.remove(stream);
                        self.unconfirmed.remove(stream);
                    }
                    self.streams.insert(
                        *stream,
                        JournalStream {
                            instance: *instance,
                            reserve: id | SLOT_GAP_RESERVE,
                            gate: *gate,
                        },
                    );
                }
                let mut record = record.clone();
                // A rebuild hands the reserve over with the stream instance.
                if let OutRecord::ChannelOutput { gap_reserve, .. } = &mut record {
                    *gap_reserve = false;
                }
                self.items.insert(
                    id >> 2,
                    JournalItem {
                        record,
                        retained: None,
                        forwarded: false,
                    },
                );
            }
            OutRecord::ChannelExit { id, .. } | OutRecord::ReservedSessionControl { id, .. } => {
                self.items.insert(
                    id >> 2,
                    JournalItem {
                        record: record.clone(),
                        retained: None,
                        forwarded: false,
                    },
                );
            }
            OutRecord::ChannelClosed {
                stream, instance, ..
            } => self.tombstone(*stream, *instance),
            OutRecord::Resyncable { stream, resyncable } => {
                self.resyncable.insert(*stream, *resyncable);
            }
            OutRecord::StreamClass { stream, bulk } => {
                if *bulk {
                    self.bulk.insert(*stream);
                } else {
                    self.bulk.remove(stream);
                }
            }
            _ => {}
        }
    }

    /// `record` went onto a link.
    fn forwarded(&mut self, record: &OutRecord) {
        if let OutRecord::ChannelOutput { id, .. } = record {
            if let Some(item) = self.items.get_mut(&(id >> 2)) {
                item.forwarded = true;
            }
        }
    }

    /// A link was lost, and its last reports with it: output bytes that had
    /// crossed it may have reached the client, or not. They are not sent
    /// again -- a byte stream must never carry a byte twice -- and their
    /// stream owes its next client the gap warning instead. Output that
    /// never crossed (sent while no link was up) stays.
    fn forget_forwarded_data(&mut self) {
        let mut gone = Vec::new();
        for (&position, item) in &self.items {
            if let OutRecord::ChannelOutput {
                stream,
                instance,
                output: OutputBody::Data(_),
                ..
            } = &item.record
            {
                if item.forwarded {
                    gone.push((position, *stream, *instance));
                }
            }
        }
        for (position, stream, instance) in gone {
            self.items.remove(&position);
            if self
                .streams
                .get(&stream)
                .is_some_and(|held| held.instance == instance)
            {
                self.unconfirmed.insert(stream, (instance, true));
            }
        }
    }

    /// The frontend transferred (`sent`) or withdrew a record's charge.
    fn charge_settled(&mut self, id: u64, sent: bool) {
        let position = id >> 2;
        let Some(item) = self.items.get_mut(&position) else {
            return;
        };
        let OutRecord::ChannelOutput { output, .. } = &item.record else {
            // An exit's or a control record's part decides.
            return;
        };
        let gap = matches!(output, OutputBody::OutputGap(_));
        if sent && gap {
            // The bridge keeps an admitted terminal gap for the next
            // attachment (its `Retained` report follows).
            item.retained = Some(RetainedKind::Gap);
        } else if !sent && item.retained == Some(RetainedKind::Gap) {
            // The charge a rebuild gave the gap again, back in its place.
        } else {
            self.items.remove(&position);
        }
    }

    /// `payload` leading bytes of a data record went out in slices.
    fn sliced(&mut self, id: u64, payload: u64) {
        if let Some(JournalItem {
            record:
                OutRecord::ChannelOutput {
                    output: OutputBody::Data(data),
                    ..
                },
            ..
        }) = self.items.get_mut(&(id >> 2))
        {
            let sent = usize::try_from(payload)
                .unwrap_or(usize::MAX)
                .min(data.len());
            data.drain(..sent);
        }
    }

    /// The frontend released the custody object `id`.
    fn released(&mut self, id: u64) {
        let (position, slot) = (id >> 2, id & 3);
        if slot == SLOT_GAP_RESERVE {
            let held = self
                .streams
                .iter()
                .find(|(_, held)| held.reserve == id)
                .map(|(stream, _)| *stream);
            if let Some(stream) = held {
                self.streams.remove(&stream);
                self.frontier.remove(&stream);
                self.unconfirmed.remove(&stream);
            }
        }
        let gone = match self.items.get(&position).map(|item| &item.record) {
            Some(OutRecord::ChannelOutput { .. }) => slot == SLOT_PERMIT,
            Some(OutRecord::ChannelExit { .. }) => slot == SLOT_PERMIT || slot == SLOT_PART,
            Some(OutRecord::ReservedSessionControl { .. }) => slot == SLOT_PART,
            _ => false,
        };
        if gone {
            self.items.remove(&position);
        }
    }

    /// The frontend enqueued the reply part `id` whole on its connection.
    fn admitted(&mut self, id: u64) {
        let position = id >> 2;
        match self.items.get(&position).map(|item| &item.record) {
            Some(OutRecord::ChannelExit {
                stream, instance, ..
            }) => {
                // The bridge forgets an instance whose exit it sent.
                let (stream, instance) = (*stream, *instance);
                self.tombstone(stream, instance);
                self.items.remove(&position);
            }
            Some(OutRecord::ReservedSessionControl { .. }) => {
                self.items.remove(&position);
            }
            _ => {}
        }
    }

    /// `n` stream bytes entered the backend's queue.
    fn received(&mut self, stream: u8, n: usize) {
        if n > 0 {
            *self.unreported.entry(stream).or_insert(0) += n as u64;
        }
    }

    /// The backend reported `n` bytes of `stream` taken: what is left of
    /// the report once a replaced link's bytes are paid.
    fn reported(&mut self, stream: u8, n: u64) -> u64 {
        if let Some(left) = self.unreported.get_mut(&stream) {
            *left = left.saturating_sub(n);
            if *left == 0 {
                self.unreported.remove(&stream);
            }
        }
        let Some(owed) = self.owed.get_mut(&stream) else {
            return n;
        };
        let paid = (*owed).min(n);
        *owed -= paid;
        if *owed == 0 {
            self.owed.remove(&stream);
        }
        n - paid
    }

    /// Whether custody object `id` belongs to something a rebuild replays.
    fn holds(&self, id: u64, reserves: &std::collections::HashSet<u64>) -> bool {
        if reserves.contains(&id) {
            return true;
        }
        let slot = id & 3;
        match self.items.get(&(id >> 2)).map(|item| &item.record) {
            Some(OutRecord::ChannelOutput { .. }) => slot == SLOT_CHARGE || slot == SLOT_PERMIT,
            Some(OutRecord::ChannelExit { .. }) => {
                slot == SLOT_CHARGE || slot == SLOT_PERMIT || slot == SLOT_PART
            }
            Some(OutRecord::ReservedSessionControl { .. }) => {
                slot == SLOT_CHARGE || slot == SLOT_PART
            }
            _ => false,
        }
    }
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
    journal: Journal,
    /// Reply parts the current link's connection holds (enqueued, awaiting
    /// acknowledgement): they go with the link.
    admitted: std::collections::BTreeSet<u64>,
    /// Bytes the current link's bridge charged on its own (gap, bootstrap
    /// and rearmed records) and has not settled, per gate.
    bridge_admits: HashMap<u64, u64>,
    last_client_recv: u64,
    /// The current link's writer queues: `None` while there is no link, and
    /// once the backend finished (the frontend then sees end of input).
    data: Option<mpsc::UnboundedSender<ToFrontend>>,
    priority: Option<mpsc::UnboundedSender<ToFrontend>>,
    failure: Arc<LinkFailure>,
    /// Leading pieces of the next inbound data event.
    data_parts: Vec<u8>,
    /// The session is lost, not ended: no link hears `Finished` at the stop.
    abandon: Shutdown,
}

/// What a frame did beyond its own effect.
enum FrameEffect {
    None,
    /// The frontend ended the session.
    Ended,
    /// The frontend ended this link in order; another replaces it.
    Retired,
}

type OwnerReader = LinkReader<tokio::io::ReadHalf<Box<dyn LinkIo>>>;

impl OwnerLink {
    /// [`OwnerLink::run`] on a lifecycle of its own that `shutdown` stops,
    /// then stop that lifecycle and drain it: when this returns with
    /// `drained: Ok`, every task and blocking worker of the session has
    /// joined (the owner process's receipt). A drain that has not finished
    /// within `drain_within` is given up on (`drained: Err`): a worker
    /// blocked for good -- a write into a pseudo-terminal whose other side
    /// is gone, say -- must not keep the owner process alive, and it ends
    /// with the process. Any lifecycle in `init` is replaced.
    pub async fn run_and_drain<L>(
        link: L,
        backend: Arc<dyn SessionBackend>,
        mut init: OwnerInit,
        shutdown: Shutdown,
        drain_within: std::time::Duration,
    ) -> OwnerRun
    where
        L: LinkIo,
    {
        // One session envelope of the daemon's control budget: the host
        // leases one to each owner process it starts, so owners together
        // hold no more than one daemon did.
        let lifecycle = Lifecycle::with_control_budget(
            shutdown,
            crate::control_budget::GlobalBudget::envelope(),
        );
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
        let drained = tokio::time::timeout(drain_within, lifecycle.drain())
            .await
            .unwrap_or_else(|_| Err(ShutdownError::unjoined(drain_within)));
        OwnerRun { exit, drained }
    }

    /// Run `backend` for one session behind `link` until the session ends.
    ///
    /// A link that ends without ending the session -- retired in order by
    /// its frontend, or lost -- leaves the backend running: what it sends
    /// stays here with its custody (`Journal`), and the next link handed
    /// over through [`OwnerInit::relinks`] starts with a replay of it. Only
    /// an explicit `End`, shutdown, or the backend finishing ends the owner.
    pub async fn run<L>(link: L, backend: Arc<dyn SessionBackend>, init: OwnerInit) -> OwnerExit
    where
        L: LinkIo,
    {
        let OwnerInit {
            principal,
            login,
            last_generation,
            lifecycle,
            relinks,
            abandon,
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
            journal: Journal {
                last_generation,
                ..Journal::default()
            },
            admitted: Default::default(),
            bridge_admits: HashMap::new(),
            last_client_recv: 0,
            data: None,
            priority: None,
            failure: Arc::new(LinkFailure::default()),
            data_parts: Vec::new(),
            abandon,
        };
        // The link being read, if any.
        let mut reader = Some(owner.open(Box::new(link), &lifecycle));
        // A link handed over while the current one has not ended yet, and
        // until when it waits for that end.
        let mut waiting: Option<Box<dyn LinkIo>> = None;
        let mut retire_by: Option<tokio::time::Instant> = None;
        // The current link no longer takes what the owner writes.
        let mut write_dead = false;
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
            let failure = owner.failure.clone();
            let linked = reader.is_some();
            // Its writes failed, but what the frontend wrote is still read.
            let writable = linked && !write_dead;
            // Also once the backend is done: the link that replaces the
            // current one still has to hear what is left, and `Finished`.
            let relinkable = waiting.is_none() && !ended;
            let wake = tokio::select! {
                biased;
                _ = lifecycle.shutdown.requested() => {
                    owner.gates.close_all();
                    return OwnerExit::Shutdown;
                }
                // Not fenced by anything: the frontend's priority lane.
                _ = control.terminal_ready.notified() => OwnerWake::Terminal,
                _ = failure.failed(), if writable => OwnerWake::WriteFailed,
                // Neither a frame flood nor a busy backend starves the other.
                wake = async {
                    tokio::select! {
                        frame = async {
                            match reader.as_mut() {
                                Some(reader) => reader.next().await,
                                None => std::future::pending().await,
                            }
                        } => OwnerWake::Frame(frame),
                        message = out_rx.recv(), if !backend_done => OwnerWake::Backend(message),
                        permit = async {
                            match reserve {
                                Some(tx) => tx.reserve_owned().await.ok(),
                                None => std::future::pending().await,
                            }
                        } => OwnerWake::Slot(permit),
                        link = relinks.next(), if relinkable => OwnerWake::Relink(link),
                        _ = async {
                            match retire_by {
                                Some(by) => tokio::time::sleep_until(by).await,
                                None => std::future::pending().await,
                            }
                        } => OwnerWake::RetireOverdue,
                    }
                } => wake,
            };
            // `Some(orderly)` once the current link is over.
            let mut link_over = None;
            match wake {
                OwnerWake::Terminal => {
                    if let Some(request) = control.take_priority_abort() {
                        if owner.data.is_some() {
                            owner.to_frontend_priority(ToFrontend::Terminal {
                                origin: ctx_wire(request.origin),
                                disposition: disposition_wire(request.disposition),
                            });
                        } else {
                            owner.terminal_unlinked(request);
                        }
                    }
                }
                // The frontend's end no longer takes anything -- at a warm
                // reattach it closes right behind its `Retire`. What it
                // wrote before is still in the link and still counts: its
                // last reports, input it sent on credit, the `Retire`
                // itself. Stop writing, and read the link to its end.
                OwnerWake::WriteFailed => {
                    log::debug!("owner link: owner write failed; reading the link to its end");
                    owner.data = None;
                    owner.priority = None;
                    write_dead = true;
                }
                // The link that was to be retired did not end in time: its
                // frontend hangs, or its `Retire` is lost. The link that
                // waits takes over as after a lost one.
                OwnerWake::RetireOverdue => {
                    log::warn!(
                        "owner link: the replaced link did not end within {} s; taking it for lost",
                        RETIRE_WITHIN.as_secs()
                    );
                    link_over = Some(false);
                }
                OwnerWake::Frame(frame) => match frame
                    .and_then(|frame| frame.map(|frame| owner.on_frame(&frame)).transpose())
                {
                    Ok(Some(FrameEffect::None)) => {}
                    Ok(Some(FrameEffect::Ended)) => ended = true,
                    Ok(Some(FrameEffect::Retired)) => link_over = Some(true),
                    // Every frontend token is gone: custody may go too.
                    Ok(None) | Err(_) if backend_done => return OwnerExit::Finished,
                    Ok(None) | Err(_) if ended => link_over = Some(false),
                    Ok(None) => {
                        log::warn!(
                            "owner link: the frontend closed without ending the session; parking"
                        );
                        link_over = Some(false);
                    }
                    Err(error) => {
                        log::error!("owner link: owner refused the link ({error:?}); parking");
                        link_over = Some(false);
                    }
                },
                OwnerWake::Backend(Some(message)) => {
                    if let Err(error) = owner.forward(message) {
                        log::error!("owner link: a record cannot cross ({error:?}); parking");
                        if linked {
                            link_over = Some(false);
                        }
                    }
                }
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
                    owner.to_frontend(ToFrontend::Finished);
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
                OwnerWake::Relink(link) if linked => {
                    waiting = Some(link);
                    retire_by = Some(tokio::time::Instant::now() + RETIRE_WITHIN);
                }
                OwnerWake::Relink(link) => {
                    reader = Some(owner.open(link, &lifecycle));
                    write_dead = false;
                    owner.replay();
                }
            }
            if let Some(orderly) = link_over {
                reader = None;
                retire_by = None;
                owner.unlink(orderly);
                let mut next = waiting.take().filter(|_| !ended);
                if backend_done {
                    // The session is over, and the link went before its
                    // frontend heard so. A link retired in order always has
                    // a successor (the frontend hands it over first): its
                    // bridge gets what is left and `Finished`, so its client
                    // hears the end. Nobody left to tell: the owner is done.
                    if next.is_none() && orderly && !ended {
                        next = tokio::select! {
                            biased;
                            _ = lifecycle.shutdown.requested() => None,
                            link = tokio::time::timeout(RETIRE_WITHIN, relinks.next()) => link.ok(),
                        };
                    }
                    if next.is_none() {
                        return if ended {
                            OwnerExit::Finished
                        } else {
                            OwnerExit::LinkLost
                        };
                    }
                }
                if let Some(link) = next {
                    reader = Some(owner.open(link, &lifecycle));
                    write_dead = false;
                    owner.replay();
                    if backend_done {
                        owner.to_frontend(ToFrontend::Finished);
                        owner.data = None;
                        owner.priority = None;
                    }
                }
            }
        }
    }
}

enum OwnerWake {
    Terminal,
    WriteFailed,
    RetireOverdue,
    Frame(Result<Option<Frame>, LinkError>),
    Backend(Option<SessionOutbound>),
    Slot(Option<mpsc::OwnedPermit<SessionInbound>>),
    Relink(Box<dyn LinkIo>),
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
        if self.data.is_none() {
            return;
        }
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
        match &ev {
            SessionInbound::Data(data) => self.journal.received(data.stream_id, data.data.len()),
            SessionInbound::Live(context) => {
                self.journal.live_seen = true;
                self.journal.last_generation = self.journal.last_generation.max(context.generation);
            }
            SessionInbound::ResumeReset(context) => {
                self.journal.last_generation = self.journal.last_generation.max(context.generation);
            }
            _ => {}
        }
        permit.send(ev);
        Ok(())
    }

    /// Start `link`: its writer, and the reader the owner's loop drives.
    fn open(&mut self, link: Box<dyn LinkIo>, lifecycle: &Arc<Lifecycle>) -> OwnerReader {
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
            self.abandon.clone(),
        ));
        self.data = Some(data);
        self.priority = Some(priority);
        self.failure = failure;
        LinkReader::new(read)
    }

    /// The current link is over, in order (`Retire`: every report of its
    /// bridge arrived) or not. What its connection and its bridge held goes
    /// with it, as when a warm reattach destroys the old connection; what a
    /// rebuilt bridge needs stays (`Journal`).
    fn unlink(&mut self, orderly: bool) {
        // The old writer sends what is queued and closes its half.
        self.data = None;
        self.priority = None;
        self.data_parts.clear();
        // Credits the link held: the events they were for never come.
        self.pool.extend(self.granted.drain(..));
        self.serve_synth();
        let journal = &mut self.journal;
        // Every byte the backend holds unreported came over a link that is
        // gone: its reports credit no later connection.
        journal.owed = journal.unreported.clone();
        if !orderly {
            // The last reports of a lost link may never have arrived: a
            // record the journal still holds may have gone out, and sent
            // output may be unacknowledged. Output bytes that crossed the
            // link are given up (never sent twice), and whatever stream
            // sent anything owes its next client the gap warning.
            journal.forget_forwarded_data();
            for (stream, held) in &journal.streams {
                if journal
                    .frontier
                    .get(stream)
                    .is_some_and(|g| g.instance.get() == held.instance)
                {
                    journal.unconfirmed.insert(*stream, (held.instance, true));
                }
            }
        }
        // Custody of the old connection's reliable copies (admitted reply
        // parts), of its attachment's replies and offers (dropped unaccepted),
        // of a published snapshot, and of records that were past the queue.
        let reserves: std::collections::HashSet<u64> =
            journal.streams.values().map(|held| held.reserve).collect();
        self.custody.retain(|id, _| journal.holds(*id, &reserves));
        self.admitted.clear();
        for (gate, n) in std::mem::take(&mut self.bridge_admits) {
            if let Some(gate) = self.gates_by_id.get(&gate).and_then(|g| g.gate.upgrade()) {
                gate.withdraw(n);
            }
        }
        drop(self.mailbox.take_for_link());
    }

    /// The first frames of a link that replaces an earlier one: everything
    /// a fresh bridge is built from, in the order it applies it.
    fn replay(&mut self) {
        // The connection whose tails the gates carried is gone, as at a
        // warm reattach; charges of journaled records stay.
        let gates: Vec<(u8, Arc<SendGate>)> = self
            .gates_by_id
            .values()
            .filter_map(|owned| Some((owned.stream, owned.gate.upgrade()?)))
            .collect();
        for (stream, gate) in gates {
            if gate.update(0) && gate.kind() == GateKind::Screen {
                self.synthesize(SessionInbound::Writable { stream });
            }
        }
        // The next attachment's snapshot is the one a rebuilt bridge takes.
        self.mailbox
            .discard_before(self.journal.last_generation.saturating_add(1));
        self.to_frontend(ToFrontend::ReplayStart {
            last_generation: self.journal.last_generation,
            live_seen: self.journal.live_seen,
            observed: self.journal.last_typed,
        });
        let journal = std::mem::take(&mut self.journal);
        for (&stream, &resyncable) in &journal.resyncable {
            self.to_frontend(ToFrontend::ReplayItem(OutRecord::Resyncable {
                stream,
                resyncable,
            }));
        }
        for &stream in &journal.bulk {
            self.to_frontend(ToFrontend::ReplayItem(OutRecord::StreamClass {
                stream,
                bulk: true,
            }));
        }
        let nobody = Ctx {
            generation: 0,
            session_id: 0,
            features: 0,
        };
        for (&stream, &instance) in &journal.tombstones {
            self.to_frontend(ToFrontend::ReplayItem(OutRecord::ChannelClosed {
                id: 0,
                stream,
                instance,
                origin: nobody,
            }));
        }
        for (&stream, held) in &journal.streams {
            self.to_frontend(ToFrontend::ReplayStream {
                stream,
                instance: held.instance,
                reserve: held.reserve,
                gate: held.gate,
            });
        }
        let mut retained = Vec::new();
        for item in journal.items.values() {
            let record = item.record.clone();
            if let (
                Some(kind),
                OutRecord::ChannelOutput {
                    id, stream, gate, ..
                },
            ) = (item.retained, &record)
            {
                retained.push((*stream, kind));
                if kind == RetainedKind::Gap {
                    // Its admission transferred the charge. The record
                    // crosses with one again, which the rebuilt bridge
                    // gives back when it puts the gap in its place.
                    let gate = self
                        .gates_by_id
                        .get(&gate.id)
                        .and_then(|owned| owned.gate.upgrade())
                        .unwrap_or_else(|| Arc::new(SendGate::new(GateKind::Pipe)));
                    gate.admit(GAP_RECORD_BYTES);
                    self.custody.insert(
                        id | SLOT_CHARGE,
                        Custody::Charge(OutputCharge::admitted(gate, GAP_RECORD_BYTES)),
                    );
                }
            }
            let record = self.split_data(record);
            self.to_frontend(ToFrontend::ReplayItem(record));
        }
        let mut journal = journal;
        for item in journal.items.values_mut() {
            item.forwarded = true;
        }
        for (&stream, held) in &journal.streams {
            if let Some(geometry) = journal
                .frontier
                .get(&stream)
                .filter(|g| g.instance.get() == held.instance)
            {
                self.to_frontend(ToFrontend::ReplayFrontier {
                    stream,
                    instance: held.instance,
                    geometry: geometry_wire(*geometry),
                });
            }
            if journal.unconfirmed.get(&stream) == Some(&(held.instance, true)) {
                self.to_frontend(ToFrontend::ReplayUnconfirmed {
                    stream,
                    unconfirmed: true,
                });
            }
        }
        for (stream, kind) in retained {
            self.to_frontend(ToFrontend::ReplayRetained { stream, kind });
        }
        self.to_frontend(ToFrontend::ReplayDone);
        self.journal = journal;
        self.grant();
    }

    /// A terminal request while no frontend is linked. A bridge parked on a
    /// dead connection applies a request of its own attachment by retiring
    /// the session's reply budget; nobody is there to hear more than that.
    fn terminal_unlinked(&self, request: TerminalRequest) {
        let attachment = self
            .control
            .origin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attachment;
        if attachment == request.origin {
            self.control.budget.retire();
        }
    }

    fn end_inbound(&mut self) {
        self.in_tx = None;
        self.pool.clear();
        self.granted.clear();
        self.synth.clear();
    }

    fn on_frame(&mut self, frame: &Frame) -> Result<FrameEffect, LinkError> {
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
                        self.journal.charge_settled(id, true);
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
                        self.journal.sliced(id, n - admit);
                    }
                    ChargeOp::Withdraw => {
                        drop(self.custody.remove(&id));
                        self.journal.charge_settled(id, false);
                    }
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
                self.admitted.insert(id);
                self.journal.admitted(id);
            }
            ToOwner::Released { id } => {
                // Dropping the owner's object refunds and wakes as it does
                // in-process; an uncommitted receipt means "not accepted".
                self.custody.remove(&id).ok_or(LinkError::BadValue)?;
                self.admitted.remove(&id);
                self.journal.released(id);
            }
            ToOwner::Retained { id, kind } => {
                if !matches!(self.custody.get(&id), Some(Custody::Permit { .. })) {
                    return Err(LinkError::BadValue);
                }
                if let Some(item) = self.journal.items.get_mut(&(id >> 2)) {
                    item.retained = Some(kind);
                }
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
                // Only for the instance the bridge holds now.
                if self
                    .journal
                    .streams
                    .get(&stream)
                    .is_some_and(|held| held.instance == instance)
                {
                    self.journal.frontier.insert(stream, geometry);
                }
            }
            ToOwner::Unconfirmed {
                stream,
                instance,
                unconfirmed,
            } => {
                if self
                    .journal
                    .streams
                    .get(&stream)
                    .is_some_and(|held| held.instance == instance)
                {
                    self.journal
                        .unconfirmed
                        .insert(stream, (instance, unconfirmed));
                }
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
                self.last_client_recv = last_client_recv;
            }
            ToOwner::End(_) => {
                self.end_inbound();
                return Ok(FrameEffect::Ended);
            }
            ToOwner::Retire => return Ok(FrameEffect::Retired),
        }
        Ok(FrameEffect::None)
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
            GateOpWire::Admit(n) => {
                gate.admit(n);
                let held = self.bridge_admits.entry(id).or_insert(0);
                *held = held.saturating_add(n);
            }
            GateOpWire::Withdraw(n) => {
                gate.withdraw(n);
                self.bridge_settled(id, n);
            }
            GateOpWire::Transfer { n, tail } => {
                // As in-process: an opening by charge transfer wakes only the
                // gate's own waiters.
                gate.transfer(n, tail);
                self.bridge_settled(id, n);
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

    /// The bridge settled `n` bytes it had charged on gate `id` on its own.
    fn bridge_settled(&mut self, id: u64, n: u64) {
        if let Some(held) = self.bridge_admits.get_mut(&id) {
            *held = held.saturating_sub(n);
            if *held == 0 {
                self.bridge_admits.remove(&id);
            }
        }
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

    /// One message the backend sent: its custody is kept here, what a
    /// rebuild needs of it goes into the journal, and it goes onto the link
    /// if there is one.
    fn forward(&mut self, message: SessionOutbound) -> Result<(), LinkError> {
        if let Some(position) = message.channel_position().filter(|p| *p != 0) {
            self.journal.last_typed = position;
        }
        let linked = self.data.is_some();
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
                if !linked {
                    self.terminal_unlinked(request);
                    return Ok(());
                }
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
                if !linked {
                    // Its attachment's bridge is gone; the next attachment
                    // gets a snapshot of its own.
                    return Ok(());
                }
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
            SessionOutbound::Consumed { stream_id, n } => {
                // A replaced link's bytes are paid first, and credit nobody.
                let n = self.journal.reported(stream_id, n as u64);
                if n == 0 {
                    return Ok(());
                }
                OutRecord::Consumed {
                    stream: stream_id,
                    n,
                }
            }
            // Only an owner link's frontend makes these, for its bridge.
            SessionOutbound::Replay(_) => return Ok(()),
        };
        self.journal.record(&record);
        if linked {
            self.journal.forwarded(&record);
        }
        if !linked {
            // A reply or an offer of an attachment whose bridge is gone is
            // stale for every later one: it is dropped, the offer unaccepted.
            if let OutRecord::ReservedControl { id, .. } | OutRecord::UpdateAccept { id, .. } =
                &record
            {
                for slot in [SLOT_CHARGE, SLOT_PART, SLOT_COMMIT] {
                    self.custody.remove(&(id | slot));
                }
            }
            return Ok(());
        }
        self.to_frontend(ToFrontend::Record(self.split_data(record)));
        Ok(())
    }
}
