//! Async multi-session manager on top of the sans-IO `Connection` core: one
//! UDP socket, a session router, and a per-session backend.
//!
//! This is the tmux-agnostic multiplex core the rest of the daemon builds
//! on. The manager owns the UDP socket and, on a `HandshakeInit`, runs
//! [`Connection::accept`]; after probation proves the peer it spawns:
//! - a **backend** (the application-level driver -- a shell, a tmux server,
//!   an echo, ... -- created by a [`BackendFactory`]), which talks to its
//!   session only through a [`SessionIo`] handle (no socket, no
//!   `Connection`); and
//! - a **per-session task** that owns the `Connection` and bridges it to the
//!   backend: incoming datagrams (routed from the socket by the manager loop)
//!   go through `on_datagram`, delivered stream bytes flow to the backend as
//!   [`SessionInbound::Data`], and the backend's outbound [`SessionOutbound`]
//!   messages flow back into `conn.send` (data) or `conn.set_stream_resyncable`
//!   (a recoverability declaration). Timers drive `on_timeout`.
//!
//! **Multiplex by token, demux by `session_id`.** The manager holds a router
//! table (see [`Router`]): a `backends` map keyed by the 16-byte token (one
//! entry per device) and a `sessions` map keyed by `session_id` (the datagram
//! demux). A brand-new token cold-creates an independent session, so distinct
//! tokens run concurrently without cross-talk; a `Transport` datagram is routed
//! to the one session whose `session_id` matches, and dropped if none.
//!
//! **Reattach / replace by token.** A repeated token is resolved against its
//! existing entry (see [`AcceptDecision`]): a **Warm** handshake REATTACHES the
//! new connection to the still-running backend -- the bridge swaps connections
//! and emits [`SessionInbound::ResumeReset`] without respawning, and the manager
//! repoints the datagram route to the new `session_id`; a **Cold** handshake
//! REPLACES it (tears the old backend down, cold-creates fresh); and an exact
//! msg1 retransmit (byte-identical body = same ephemeral key) is idempotent --
//! the manager re-sends the ORIGINAL msg2 (same `session_id`) and touches
//! nothing else, so it neither spawns a second backend nor repoints the
//! client's still-live route (which would wedge it). Reattach is gated
//! behind the allowlist: a non-allowlisted key is `Rejected` by
//! [`Connection::accept`] before any of this runs, so a stranger who knows a
//! token can never hijack another device's backend.
//!
//! **Nothing binds before its peer is proven.** Both policies enter bounded
//! probation (see [`crate::probation`]). Allowlist membership requires a fresh
//! authenticated transport packet; signatures additionally require a verified
//! record on [`crate::auth::AUTH_STREAM`]. Only the provisional route exists
//! before proof. A completed proof must retain its original registered seat
//! and current binding revision, and the manager resolves its decision again
//! before changing any backend. A captured msg1 cannot replace a live session.
//!
//! **Nothing costs work before its return address is known -- under load.**
//! Every handshake datagram passes `Router::cookies` first (spec §4.16):
//! while more than 64 arrive a second, or more than half the probation table
//! is taken, a msg1 is answered with a cookie and nothing else, and only a
//! msg1 sent again behind a valid cookie reaches `Connection::accept`. A
//! forged source never sees its cookie, so it never costs Noise work, a
//! nonce or a seat; the per-source probation cap then counts addresses that
//! really receive. A cookie proves an address, not a datagram, so a proven
//! source is also held to 20 handshakes a second after a burst of 5
//! ([`crate::cookie::PROVEN_PER_SECOND`]) while the load lasts.
//!
//! **Persistent bridge, swappable connection.** Each backend has exactly ONE
//! backend task and ONE bridge task ([`run_backend_bridge`]), joined by stable
//! io channels for the backend's whole life; only the `Connection` they drive
//! is swapped (via the bridge's control channel) on a warm reattach. The seams
//! (`SessionIo`/`SessionBackend`/`SessionInbound`) are unchanged: reattach adds
//! only routing, never reshapes the backend contract.
//!
//! **Slot reclamation.** The router owns the table alone (no shared lock on the
//! datagram path). Each per-session task holds a clone of a completion channel
//! and, when its session ends (a clean `StateChanged(Closed)`, the router
//! dropping the datagram channel, ...), signals `SessionEnded { session_id,
//! token }`. The `serve` loop drains that channel in the same `select!` as the
//! socket and reclaims the entries, so a cleanly closed session never leaks its
//! slots. The `backends[token]` removal is guarded by `session_id` so a
//! same-token overwrite is not reclaimed by the previous session's stale
//! end-signal.
//!
//! **Why two channels per session.** The manager loop must never block on a
//! slow backend or a slow session task, or it would stop reading the socket
//! for every session. So the router forwards raw datagrams to the session
//! task over an UNbounded channel (a synchronous, non-blocking send), and the
//! session task -- not the router -- pays any backpressure to the backend.

#[path = "binding_revision.rs"]
pub(crate) mod binding_revision;
#[path = "channel_bridge.rs"]
mod channel_bridge;
#[path = "session_lifecycle.rs"]
mod lifecycle;
use binding_revision::{BindingRevision, BindingRevisions, RevisionChange};
pub(crate) use lifecycle::CallbackFailure;
use lifecycle::Lifecycle;
pub(crate) use lifecycle::WorkerReceipt;
#[cfg(test)]
#[path = "session_manager_fixture.rs"]
pub(crate) mod fixture;
pub use lifecycle::{Shutdown, ShutdownError};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::auth::{AuthVerifier, Principal, AUTH_NONCE_LEN, AUTH_STREAM, NO_INCARNATION};
use crate::auth_acceptance::{AuthAcceptance, SessionDisposition};
use crate::conn::{
    AcceptedHandshake, AuthPolicy, Connection, ConnectionConfig, Consumption, Datagram, Event,
    LinkState, Msg2Inputs, Msg2Resolution, ResolvedAccept, Role, StreamClass,
};
use crate::cookie::{source_group_key, CookieCheck, Verdict};
use crate::dgram_queue::{dgram_queue, probation_dgram_queue, DgramRx, DgramTx, DGRAM_QUEUE_BYTES};
use crate::handshake_payload::{AuthMethod, Msg1Payload, StartKind};
use crate::probation::{
    run_probation, BridgeStart, Probation, ProbationEnded, ProofPolicy, ProvenSession,
    MAX_PROBATION, MAX_PROBATION_PER_SOURCE,
};
use crate::send_gate::{GateKind, GateTable, SendGate};
use crate::wire::{
    encode_handshake, encode_key_offer_body, parse, Frame, Kind, KEY_REQUEST_MIN_LEN,
};

/// Receive buffer size for a single UDP datagram.
const RECV_BUF_LEN: usize = 64 * 1024;

/// Capacity of a session's inbound channel (bridge -> backend), in events.
/// Bounded, and the bridge does not wait on it: what does not fit waits in
/// the bridge's `Inbound`, bounded per stream by its credit window and per
/// session by `PENDING_CAP`.
const INBOUND_CAP: usize = 256;

/// How much a session's bridge queues for a backend that is not reading
/// (spec §4.10.5, §4.10.7): past this the bridge waits for the backend, as
/// every build before credits did. In both modes:
/// - a client without credits knows no limits, and a bridge that neither
///   queued nor acknowledged would draw a storm of resends; below this an
///   ordinary paste never stops the bridge;
/// - with credits each stream is bounded by its window, but not the session:
///   there are up to 256 streams, and every warm reattach brings a
///   connection whose streams start with a fresh window while the old one's
///   bytes still wait. An honest client uses at most 10 streams (8
///   channels, control, the update stream) -- 5 MiB of windows -- and never
///   gets here.
pub const PENDING_CAP: usize = 8 * 1024 * 1024;

/// How many live sessions ONE account may hold. The old single cap was a
/// per-daemon number back when a daemon served one account; keeping it
/// global would let one person on a shared machine crowd everybody else out.
pub const MAX_SESSIONS_PER_OWNER: usize = 16;

/// How many live sessions the daemon holds across every account. A ceiling
/// on memory, not a fairness rule -- that is what the per-owner cap is for.
pub const MAX_SESSIONS_TOTAL: usize = 128;

/// How long a backend is RETAINED after an unexpected death (the connection
/// closed via the `DEATH_AFTER` liveness timeout, not a graceful `Close`),
/// waiting for a warm reconnect. Past this, GC tears it down -- one pass
/// later if a handshake naming its token is in probation just then (see
/// `Router::gc_retained`).
pub const RETAIN_AFTER_DEATH: std::time::Duration = std::time::Duration::from_secs(3600);

/// Period of the GC tick that reaps expired retained backends. Passes are at
/// least this far apart, also after the router loop has stalled -- see
/// [`gc_timer`].
const GC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The GC's timer. Missed ticks are DELAYED, not fired back to back (tokio's
/// default `Burst`), nor put back on the old schedule (`Skip`, whose next
/// tick can come arbitrarily soon): after the router loop has been away for
/// more than an interval, the pass after the one that caught up is a whole
/// `GC_INTERVAL` later. That gap is what `Router::gc_retained`'s one-pass
/// reprieve is measured in -- fired back to back, the reprieve and the
/// removal would land together while the proof it was granted for still
/// waits to be served. The GC loses nothing by it: one pass collects every
/// expired entry, however many ticks were missed.
///
/// A stall that long needs something to hold the router's own task, which is
/// never meant to happen -- and has happened. [`NonceSource::issue`] runs on
/// that task for every msg1, and [`NonceSource::release`] and
/// [`LoginSink::login_ended`] run there too, one call for each login a GC
/// pass ends. The system mode's sources used to send to their helper right
/// there: with the helper alive but not reading and its socket full, each of
/// those calls held the task for a send timeout (two seconds) -- measured, in
/// the review of the system mode's nonce pool -- and each `issue` for an
/// answer's whole budget before that. They no longer wait (see those
/// methods' docs); a source that did would bring the stall back.
fn gc_timer() -> tokio::time::Interval {
    let mut timer = tokio::time::interval(GC_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    timer
}

/// A session counts as "active" for version reconciliation while its last
/// authenticated receive is within this window. Comfortably above
/// `PING_INTERVAL` (1.5 s) so a merely-idle-but-attached client still counts,
/// but well below a background/Doze gap.
const ACTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

/// Pure activity predicate (unit-testable without a socket).
fn is_active(idle: std::time::Duration) -> bool {
    idle <= ACTIVE_WINDOW
}

/// Withdraw a bridge's contribution to the shared active-session count, if it
/// is currently counted. IDEMPOTENT: a second call with `was_active` already
/// `false` is a no-op, so calling this at more than one exit/parking point in
/// `run_backend_bridge` -- or after the normal per-wakeup recompute already
/// saw the same transition -- can never double-decrement.
fn deactivate(was_active: &mut bool, active_count: &AtomicUsize) {
    if *was_active {
        active_count.fetch_sub(1, Ordering::SeqCst);
        *was_active = false;
    }
}

/// Logged when the daemon comes under load (spec §4.16): from now on a msg1
/// is answered with a cookie, and only one sent again behind a valid cookie
/// is worked on.
const LOAD_ON_LINE: &str =
    "under load: a handshake must prove its return address (cookie) before any work";

/// Logged when the load is over.
const LOAD_OFF_LINE: &str = "load is over: handshakes are answered directly again";

/// How long load must have stayed off before the log says it is over (see
/// [`LoadLog`]).
const LOAD_LOG_SETTLE: std::time::Duration = std::time::Duration::from_secs(10);

/// What the daemon's log says about load (spec §4.16): its start at once,
/// its end only once load has stayed off for [`LOAD_LOG_SETTLE`] -- told at
/// the first handshake datagram after that, since load is measured at
/// handshake datagrams and nowhere else.
///
/// Why not every change the meter reports: load flickers at its threshold.
/// A slow forged flood holds the probation table at 64 or 65 seats; each
/// seat that expires turns load off for the one datagram that takes the
/// seat again, a dozen times a second on the signature path -- two lines
/// each, from a flood of a few dozen datagrams a second. With the settle
/// such a flood is one episode in the log.
struct LoadLog {
    /// Whether the log last said the daemon is under load.
    said_loaded: bool,
    /// When a check last found load.
    loaded_at: Option<Instant>,
    /// [`LOAD_LOG_SETTLE`]; a test shortens it.
    settle: std::time::Duration,
}

impl LoadLog {
    fn new() -> Self {
        LoadLog {
            said_loaded: false,
            loaded_at: None,
            settle: LOAD_LOG_SETTLE,
        }
    }

    /// The line to log after a check that found `loaded` at `now`, if any.
    fn note(&mut self, now: Instant, loaded: bool) -> Option<&'static str> {
        if loaded {
            self.loaded_at = Some(now);
            if self.said_loaded {
                return None;
            }
            self.said_loaded = true;
            return Some(LOAD_ON_LINE);
        }
        let settled = self
            .loaded_at
            .is_some_and(|at| now.saturating_duration_since(at) >= self.settle);
        if !(self.said_loaded && settled) {
            return None;
        }
        self.said_loaded = false;
        Some(LOAD_OFF_LINE)
    }
}

// Backend-lifecycle notices ("no silent cap": cap-eviction, rejection and GC
// teardown must all be visible somewhere) are `log` records of this crate,
// component `transport` (their target is this module's path). The manager
// itself stays I/O-agnostic: whoever runs it installs a logger -- `qshd`
// routes them into `qshd.log` (and `serve`'s stderr, for the journal) --
// and without one they are no-ops.

/// One line per connection a session binds (spec §5.5): what it agreed with
/// its client.
fn log_session_features(session_id: u64, features: crate::Features) {
    let line = format!(
        "session {session_id:016x}: transport features {}",
        features.describe()
    );
    #[cfg(test)]
    SESSION_FEATURES_LOGGED.with(|l| l.borrow_mut().push(line.clone()));
    log::info!("{line}");
}

/// Log a transport socket's buffer sizes (spec §4.12) as a `log` record of
/// the `transport` component, like every other lifecycle notice here: the
/// daemon's file log, and -- where the daemon mirrors to stderr, as `qshd
/// serve` does -- the journal too.
pub fn log_socket_buffers(report: &crate::BufferReport) {
    log::info!("{}", report.line());
}

/// Lifecycle state of a backend entry. A `Live` entry has a connected session;
/// a `Retained` entry outlived its connection. Unexpected death keeps it for
/// warm reconnect; a graceful close keeps it only while a proof is pending.
///
/// `since` is a `tokio::time::Instant` (NOT `std::time::Instant`) so retention
/// and GC deadlines are driven by tokio's test clock in unit tests, without a
/// real 45 s `DEATH_AFTER` wait.
///
/// `reprieved` records that the GC has already let this retention run one
/// pass past `RETAIN_AFTER_DEATH` (see [`Router::gc_retained`]). It lives in
/// the variant, so every retention starts without one.
enum EntryState {
    Live,
    Retained {
        since: tokio::time::Instant,
        reprieved: bool,
        reason: RetentionReason,
    },
}

enum RetentionReason {
    UnexpectedDeath,
    /// The connection closed gracefully, but a candidate's proof may already
    /// have created helper state. Resolve that proof before ending the login.
    PendingProof,
}

/// The shared, in-memory allowlist of accepted client static public keys.
///
/// This is the CANONICAL definition of the type. The daemon
/// (`qshd`) imports/aliases it rather than defining its own, so a single
/// `Arc<Mutex<..>>` is shared between whoever mutates the allowlist (e.g. the
/// SSH `ensure` path adding a freshly minted client key) and the manager,
/// which snapshots it at every handshake.
///
/// INVARIANT: a key is unique to the connection attempt that authenticated
/// with it (the design mints a fresh key per `ADD-CLIENT` rather than
/// reusing one across reconnects, see `scrub_superseded_key`/
/// `remove_from_allowlist`), so removing a key BY VALUE can never strip a
/// concurrent, unrelated session's key out from under it.
pub type SharedAllowlist = Arc<Mutex<Vec<[u8; 32]>>>;

/// A chunk of bytes for a single logical stream `stream_id`. The manager's
/// unit of exchange with a backend in both directions.
pub struct StreamData {
    pub stream_id: u8,
    pub data: Vec<u8>,
}

/// Context ordered before the input delivered by this attachment. Backend owners
/// keep the last event they processed, never a mutable bridge-side latest value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttachmentContext {
    pub generation: u64,
    pub session_id: u64,
    pub features: crate::Features,
}
impl AttachmentContext {
    fn for_connection(conn: &Connection, generation: u64) -> Self {
        Self {
            generation,
            session_id: conn.session_id(),
            features: conn.features(),
        }
    }
    pub fn has_geometry(self) -> bool {
        self.features.contains(crate::Features::CHANNEL_GEOMETRY)
    }
}

/// A fixed final output position; the surrounding emission identifies its
/// instance and attachment. Exactly one marker exists per ended instance.
#[derive(Clone, Copy, Debug)]
pub struct DeliveryMarker {
    pub token: u64,
}

/// Channel records stay typed until the bridge admits their complete encoding.
/// Metadata permits move with the record, and are never cloned at queue moves.
pub enum ChannelOutput {
    Data(Vec<u8>),
    Geometry(
        crate::channel_geometry::GeometryRecord,
        crate::channel_timeline::TimelinePermit,
    ),
    EchoAck(u64, crate::channel_timeline::TimelinePermit),
    /// One terminal failure disclosure retained through attachment and ACK.
    OutputGap(
        crate::channel_geometry::OutputGapCause,
        crate::channel_timeline::TimelinePermit,
    ),
    DeliveryMarker(DeliveryMarker, crate::channel_timeline::TimelinePermit),
}
impl ChannelOutput {
    pub fn framed_len(&self) -> usize {
        match self {
            Self::Data(bytes) => 5 + bytes.len(),
            Self::Geometry(..) => 27,
            Self::EchoAck(..) => 13,
            Self::OutputGap(..) => 14,
            Self::DeliveryMarker(..) => crate::channel_timeline::DELIVERY_MARKER_BYTES,
        }
    }
}

/// Pending bytes belong to the original instance's gate, even after its stream
/// number is reused. Dropping an unsent emission withdraws once; successful
/// bridge admission transfers the charge atomically to that Connection tail.
pub struct OutputCharge {
    gate: Arc<SendGate>,
    bytes: u64,
}
impl OutputCharge {
    pub fn transfer(mut self, tail: u64) -> bool {
        let opened = self.gate.transfer(self.bytes, tail);
        self.bytes = 0;
        opened
    }
}
impl Drop for OutputCharge {
    fn drop(&mut self) {
        self.gate.withdraw(self.bytes);
    }
}

/// What the manager delivers to a backend over its [`SessionIo`].
pub enum SessionInbound {
    /// Freshly delivered in-order stream bytes.
    Data(StreamData),
    /// The connection reached `Live` for the FIRST time (a cue to start
    /// writing to the tty). Sent once per session.
    Live(AttachmentContext),
    /// The session was reattached by a NEW client connection (a warm reconnect
    /// on the same token): the backend must reset its per-connection state
    /// (echo_ack / tty / control buffers). The persistent bridge emits this
    /// into the SAME `io` when it swaps in the new `Connection`, so the backend
    /// (and, later, its PTYs) keep running across the reattach.
    ResumeReset(AttachmentContext),
    /// Repaint the current screen (a hot-roam resync after a long absence: the
    /// server dropped its output backlog and the client just returned). Unlike
    /// `ResumeReset`, this must NOT reset per-connection echo/tty/input
    /// accounting -- a hot-roam resync continues on the SAME connection, so
    /// `input_consumed`/echo_ack stay valid; only the screen needs repainting.
    Repaint,
    /// Ordered hot-reset cutover, without resetting input/request correlation.
    RepaintCutover { generation: u64, sequence: u64 },
    /// Stream `stream`'s send gate just opened (spec §4.7.2) -- sent only for
    /// screen gates: a screen channel that dropped output behind the closed
    /// gate repaints now.
    Writable { stream: u8 },
    /// One coalesced metadata-capacity wake; stale scopes cannot resume work.
    OutputReady {
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        generation: u64,
    },
    /// Everything the backend had sent on `stream` when it asked
    /// ([`SessionIo::notify_delivered`]) has been acknowledged by the peer --
    /// or will never be: a warm reattach brought a connection that holds
    /// none of it. `token` is the one the backend asked with, so it can tell
    /// an answer to an earlier request on the same stream from this one.
    /// Geometry-profile owners additionally match the delivery generation.
    Delivered {
        stream: u8,
        token: u64,
        generation: u64,
    },
}

/// What a backend sends towards its connection.
pub enum SessionOutbound {
    /// Ordered retirement barrier after admitted Open jobs settle. The flag
    /// distinguishes published decisions from same-attachment nondelivery.
    RetirementReady {
        origin: AttachmentContext,
        decisions_complete: bool,
    },
    /// One pre-reserved control item, with exact enqueue-generation custody.
    ReservedControl {
        origin: AttachmentContext,
        bytes: Vec<u8>,
        delivery: ControlDelivery,
    },
    /// An offer becomes accepted only when its original attachment commits the
    /// complete reserved Accept record. Dropped receipt means no receive effects.
    UpdateAccept {
        origin: AttachmentContext,
        bytes: Vec<u8>,
        delivery: ControlDelivery,
        committed: tokio::sync::oneshot::Sender<()>,
    },
    /// Outcome of an already accepted backend operation. The bridge binds it
    /// to its current committed connection, not the callback's start origin.
    ReservedSessionControl {
        bytes: Vec<u8>,
        delivery: ControlDelivery,
    },
    /// Fixed terminal overload request; the bridge validates its exact origin.
    ResourceExhausted {
        origin: AttachmentContext,
    },
    /// Explicit compatibility teardown without a protocol-error classification.
    CloseSession {
        origin: AttachmentContext,
    },
    ChannelOpened {
        stream: u8,
        origin: AttachmentContext,
    },
    ChannelRefused {
        stream: u8,
        origin: AttachmentContext,
        reason: String,
    },
    RepaintBarrier {
        generation: u64,
        sequence: u64,
    },
    ChannelClosed {
        /// Successful typed-output queue position; zero only in direct fixtures.
        position: u64,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
    },
    ChannelOutput {
        /// Successful typed-output queue position; zero only in direct fixtures.
        position: u64,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
        output: ChannelOutput,
        charge: OutputCharge,
        /// One pre-reserved 41-byte gap/bootstrap allowance accompanies the first checkpoint.
        /// The bridge takes ownership even if it discards that Screen record;
        /// both fixed states reuse it; pending byte charges still track each actual record.
        gap_reserve: Option<crate::channel_timeline::TimelinePermit>,
    },
    /// A final control record whose permit survives the outbound queue. Stage 4
    /// admits it on CONTROL_STREAM only for its current instance/attachment.
    /// None means confirmed child cleanup with a lost exit status; it never
    /// means that cleanup is still unknown or in progress.
    ChannelExit {
        /// Successful typed-output queue position; zero only in direct fixtures.
        position: u64,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
        code: Option<i32>,
        open: crate::channel::OpenClassification,
        permit: crate::channel_timeline::TimelinePermit,
        control: ControlDelivery,
    },
    /// One coalesced mailbox wake, not an attachment-scoped control record.
    /// The consumer takes only payload matching its actual bridge target.
    ResumeSnapshotReady,
    /// End only the originating attempt; a late old-generation failure cannot
    /// close a replacement connection. At most one diagnostic per attempt.
    ProtocolFailure {
        origin: AttachmentContext,
        code: Option<crate::channel_geometry::ProtocolErrorCode>,
    },
    /// Bytes for a stream.
    Data(StreamData),
    /// Whether this stream's backlog may be dropped after a long absence and
    /// rebuilt from scratch afterwards. A backend declares this when it opens
    /// a stream; a connection that never hears about a stream falls back to
    /// the old protocol's rule (see [`Connection::is_bulk_output_stream`]).
    Resyncable {
        stream_id: u8,
        resyncable: bool,
    },
    /// This stream's class for the fairness rule and the congestion window
    /// (spec §4.8). Kept by the bridge and declared again to every
    /// connection a warm reattach brings.
    StreamClass {
        stream_id: u8,
        class: StreamClass,
    },
    /// Say [`SessionInbound::Delivered`], with `token`, once everything sent
    /// on this stream so far is acknowledged.
    NotifyDelivered {
        stream_id: u8,
        token: u64,
    },
    /// The backend took `n` bytes of `stream_id` (spec §4.10.3): only a
    /// backend whose [`SessionBackend::consumption`] is `Explicit` sends it,
    /// and only such a backend's are counted.
    Consumed {
        stream_id: u8,
        n: usize,
    },
}

impl SessionOutbound {
    fn channel_position(&self) -> Option<u64> {
        match self {
            Self::ChannelOutput { position, .. }
            | Self::ChannelExit { position, .. }
            | Self::ChannelClosed { position, .. } => Some(*position),
            _ => None,
        }
    }
    fn assign_channel_position(&mut self, next: u64) {
        match self {
            Self::ChannelOutput { position, .. }
            | Self::ChannelExit { position, .. }
            | Self::ChannelClosed { position, .. } => *position = next,
            _ => unreachable!("only typed channel output has prefix custody"),
        }
    }
}

/// The router's own token for one device (see [`Router`]'s `backends` map):
/// 16 bytes, chosen by the client, stable across a warm reattach.
///
/// A session's `session_id` is NOT this: a warm reattach mints a fresh
/// `session_id` for the same device (see the module docs, "Reattach /
/// replace by token"), so anything that has to survive a roam -- the system
/// mode's PAM session, in particular, which belongs to a LOGIN rather than
/// to any one connection -- must be keyed by the token, not by the session
/// that happens to be carrying it right now.
pub type LoginId = [u8; 16];

/// Opaque, non-cloneable control delivery custody. Created only by SessionIo.
pub struct ControlDelivery {
    part: crate::control_budget::ResponsePart,
    charge: Option<OutputCharge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalDisposition {
    Close,
    ResourceExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalRequest {
    origin: AttachmentContext,
    disposition: TerminalDisposition,
}

#[derive(Default)]
struct ControlOrigin {
    attachment: AttachmentContext,
    aborting: bool,
    /// Irreversible revocation; callbacks admitted earlier retain their owners.
    retiring: Option<Instant>,
    requested_abort: Option<TerminalRequest>,
    abort_notification_queued: bool,
}
struct SessionControl {
    retire_backend: tokio::sync::Notify,
    retire_bridge: tokio::sync::Notify,
    terminal_ready: tokio::sync::Notify,
    budget: crate::control_budget::SessionBudget,
    origin: Mutex<ControlOrigin>,
}
impl SessionControl {
    fn new(global: &crate::control_budget::GlobalBudget, uid: u32) -> Self {
        Self {
            retire_backend: tokio::sync::Notify::new(),
            retire_bridge: tokio::sync::Notify::new(),
            terminal_ready: tokio::sync::Notify::new(),
            budget: global.session(uid),
            origin: Mutex::new(ControlOrigin::default()),
        }
    }
    fn retire(&self) {
        // This lock is also the Open-admission/final-installation boundary.
        let mut state = self
            .origin
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.retiring.get_or_insert_with(Instant::now);
        drop(state);
        self.retire_backend.notify_one();
        self.retire_bridge.notify_one();
    }
    fn retirement_deadline(&self) -> Option<Instant> {
        self.origin.lock().map_or(Some(Instant::now()), |state| {
            state
                .retiring
                .map(|at| at + crate::conn::CLIENT_DEATH_AFTER)
        })
    }
    fn retiring(&self) -> bool {
        self.origin
            .lock()
            .map_or(true, |state| state.retiring.is_some())
    }

    fn has_priority_abort(&self) -> bool {
        self.origin
            .lock()
            .map_or(true, |state| state.requested_abort.is_some())
    }

    fn take_priority_abort(&self) -> Option<TerminalRequest> {
        // The ordinary queued alias may remain behind a snapshot fence.
        // Keep its latch until that alias is actually consumed: generation
        // churn must not enqueue another alias after this priority read.
        self.origin.lock().unwrap().requested_abort.take()
    }

    fn take_abort(&self, fallback: TerminalRequest) -> TerminalRequest {
        let mut state = self.origin.lock().unwrap();
        state.abort_notification_queued = false;
        state.requested_abort.take().unwrap_or(fallback)
    }
}

/// A backend's handle to its session: receive [`SessionInbound`] events, send
/// outbound [`SessionOutbound`]. The backend never sees the socket or the
/// `Connection`.
pub struct SessionIo {
    lifecycle: Arc<Lifecycle>,
    control: OnceLock<Arc<SessionControl>>,
    resume_snapshots: channel_bridge::SnapshotMailbox,
    inbound: mpsc::Receiver<SessionInbound>,
    outbound: mpsc::UnboundedSender<SessionOutbound>,
    /// Who this session belongs to. Set once, when the session is created:
    /// a session never changes hands, and a warm reattach by a different
    /// account is refused rather than allowed to rewrite this.
    principal: Principal,
    /// The router's token for this device -- see [`LoginId`]'s own docs for
    /// why this, and not `session_id`, is what a login-scoped resource must
    /// be keyed by. Set once, at cold-create, same as `principal`: a warm
    /// reattach keeps the same backend entry, and so the same token.
    login: LoginId,
    /// The session's send gates (spec §4.7.2), shared with the bridge that
    /// refreshes them. Outlives warm reattaches, like the io itself.
    gates: Arc<GateTable>,
}

impl SessionIo {
    fn control(&self) -> &Arc<SessionControl> {
        self.control.get_or_init(|| {
            Arc::new(SessionControl::new(
                &self.lifecycle.control_budget,
                self.principal.uid,
            ))
        })
    }

    pub(crate) fn retiring(&self) -> bool {
        self.control().retiring()
    }

    /// No callback, I/O or await runs inside this admission/installation lock.
    pub(crate) fn admit_effect<T>(&self, effect: impl FnOnce() -> T) -> Result<T, ()> {
        let state = self.control().origin.lock().map_err(|_| ())?;
        if state.retiring.is_some() {
            return Err(());
        }
        let result = effect();
        drop(state);
        Ok(result)
    }

    pub(crate) fn retirement_ready(&self, origin: AttachmentContext, decisions_complete: bool) {
        let _ = self.outbound.send(SessionOutbound::RetirementReady {
            origin,
            decisions_complete,
        });
    }

    pub(crate) fn control_budget(&self) -> &crate::control_budget::SessionBudget {
        &self.control().budget
    }

    pub(crate) fn global_control_budget(&self) -> crate::control_budget::GlobalBudget {
        self.lifecycle.control_budget.clone()
    }

    pub(crate) fn spawn_callback<T: Send + 'static>(
        &self,
        lease: crate::control_job::JobLease,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> tokio::sync::oneshot::Receiver<Result<T, CallbackFailure>> {
        // This backend's registered parent retains custody until synchronous
        // callback registration, even when STOP raced its earlier admission.
        self.lifecycle.spawn_callback(lease, work)
    }

    pub(crate) fn processed_attachment(&self) -> AttachmentContext {
        self.control().origin.lock().unwrap().attachment
    }

    fn set_control_origin(&self, attachment: AttachmentContext) {
        let mut state = self.control().origin.lock().unwrap();
        if state.attachment != attachment {
            state.attachment = attachment;
            state.aborting = false;
        }
    }

    pub(crate) fn close_session(&self, origin: AttachmentContext) {
        self.request_terminal(origin, TerminalDisposition::Close);
    }

    pub(crate) fn resource_exhausted(&self, origin: AttachmentContext) {
        self.request_terminal(origin, TerminalDisposition::ResourceExhausted);
    }

    fn request_terminal(&self, origin: AttachmentContext, disposition: TerminalDisposition) {
        let mut state = self.control().origin.lock().unwrap();
        if state.attachment != origin || state.aborting {
            return;
        }
        // First terminal cause wins within one attachment. A newly processed
        // attachment may replace the fixed mailbox, never add another signal.
        state.aborting = true;
        state.requested_abort = Some(TerminalRequest {
            origin,
            disposition,
        });
        let enqueue_alias = !state.abort_notification_queued;
        state.abort_notification_queued = true;
        drop(state);
        // One stored Notify permit wakes the existing fixed mailbox even
        // when snapshot backpressure fences ordinary backend reception.
        self.control().terminal_ready.notify_one();
        if !enqueue_alias {
            return;
        }
        let notification = match disposition {
            TerminalDisposition::Close => SessionOutbound::CloseSession { origin },
            TerminalDisposition::ResourceExhausted => SessionOutbound::ResourceExhausted { origin },
        };
        let _ = self.outbound.send(notification);
    }

    /// The caller reserved the complete encoding before accepting its effect.
    pub(crate) fn send_reserved_control(
        &self,
        origin: AttachmentContext,
        mut bytes: Vec<u8>,
        part: crate::control_budget::ResponsePart,
    ) {
        let state = self.control().origin.lock().unwrap();
        if state.attachment != origin || state.aborting {
            return;
        }
        drop(state);
        if bytes.len() != part.encoded_bytes() {
            self.resource_exhausted(origin);
            return;
        }
        if bytes.capacity() > bytes.len().saturating_mul(2) {
            bytes = bytes.into_boxed_slice().into_vec();
        }
        let charge = self
            .gates
            .admit(crate::channel::CONTROL_STREAM, bytes.len() as u64)
            .map(|gate| OutputCharge {
                gate,
                bytes: bytes.len() as u64,
            });
        let _ = self.outbound.send(SessionOutbound::ReservedControl {
            origin,
            bytes,
            delivery: ControlDelivery { part, charge },
        });
    }

    pub(crate) fn commit_update(
        &self,
        origin: AttachmentContext,
        part: crate::control_budget::ResponsePart,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (committed, receipt) = tokio::sync::oneshot::channel();
        let bytes = crate::channel::encode_server(&crate::channel::ServerRecord::UpdateAnswer(
            crate::channel::UpdateAnswer::Accept,
        ));
        assert_eq!(bytes.len(), part.encoded_bytes());
        let state = self.control().origin.lock().unwrap();
        if state.attachment != origin || state.aborting {
            return receipt;
        }
        drop(state);
        let delivery = self.operation_delivery(bytes.len(), part);
        let _ = self.outbound.send(SessionOutbound::UpdateAccept {
            origin,
            bytes,
            delivery,
            committed,
        });
        receipt
    }

    pub(crate) fn send_session_control(
        &self,
        bytes: Vec<u8>,
        part: crate::control_budget::ResponsePart,
    ) {
        assert_eq!(bytes.len(), part.encoded_bytes());
        let delivery = self.operation_delivery(bytes.len(), part);
        let _ = self
            .outbound
            .send(SessionOutbound::ReservedSessionControl { bytes, delivery });
    }

    fn operation_delivery(
        &self,
        bytes: usize,
        part: crate::control_budget::ResponsePart,
    ) -> ControlDelivery {
        let charge = self
            .gates
            .admit(crate::channel::CONTROL_STREAM, bytes as u64)
            .map(|gate| OutputCharge {
                gate,
                bytes: bytes as u64,
            });
        ControlDelivery { part, charge }
    }

    fn send_control(&self, origin: AttachmentContext, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let state = self.control().origin.lock().unwrap();
        if state.attachment != origin || state.aborting {
            return;
        }
        drop(state);
        let permit = match self
            .control_budget()
            .reserve(crate::control_budget::Response::Ordinary(bytes.len()))
        {
            Ok(permit) => permit,
            Err(crate::control_budget::CapacityError::Retired) => return,
            Err(_) => {
                self.resource_exhausted(origin);
                return;
            }
        };
        let mut owner = permit.into_owner();
        let Some(part) = owner.take_record(bytes.len()) else {
            self.resource_exhausted(origin);
            return;
        };
        self.send_reserved_control(origin, bytes, part);
    }

    /// Register descendant cleanup synchronously from this owned backend.
    /// The backend's registered parent stays alive through this registration,
    /// so drain cannot observe an empty owner between admission and publication.
    /// Already admitted work remains owned even after a shutdown request; the
    /// supervisor must await its actual worker, regardless of stale receivers.
    #[cfg(test)]
    pub(crate) fn spawn_owned(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.lifecycle.spawn(future);
    }

    pub(crate) fn publish_resume_snapshot(
        &self,
        origin: AttachmentContext,
        build: impl FnOnce()
            -> Result<crate::channel::ChannelSnapshot, crate::channel::ChannelCodecError>,
    ) -> bool {
        match self
            .resume_snapshots
            .publish(origin.generation, self.control_budget(), build)
        {
            Ok(publication) => {
                if publication.notify {
                    self.resume_snapshot_ready();
                }
                publication.published
            }
            Err(channel_bridge::SnapshotError::Capacity(
                crate::control_budget::CapacityError::Retired,
            )) => false,
            Err(channel_bridge::SnapshotError::Capacity(_)) => {
                self.resource_exhausted(origin);
                false
            }
            Err(channel_bridge::SnapshotError::Codec) => {
                self.protocol_failure(origin, None);
                false
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn channel_opened(&self, origin: AttachmentContext, stream: u8) {
        self.send_control(
            origin,
            crate::channel::encode_server(&crate::channel::ServerRecord::Opened { stream }),
        );
    }
    #[cfg(test)]
    pub(crate) fn channel_refused(&self, origin: AttachmentContext, stream: u8, reason: String) {
        // Normalize before encoder allocation; the maximum is derived from
        // the actual one-byte stream prefix, not an arbitrary diagnostic cap.
        let reason = crate::channel::bounded_control_diagnostic(reason, 1);
        let n = reason.len().checked_add(6).expect("bounded refusal length");
        let permit = match self
            .control_budget()
            .reserve(crate::control_budget::Response::Ordinary(n))
        {
            Ok(permit) => permit,
            Err(crate::control_budget::CapacityError::Retired) => return,
            Err(_) => {
                self.resource_exhausted(origin);
                return;
            }
        };
        let mut owner = permit.into_owner();
        let part = owner.take_record(n).expect("one pre-reserved refusal");
        self.send_reserved_control(
            origin,
            crate::channel::encode_server_owned(crate::channel::ServerRecord::Refused {
                stream,
                reason,
            }),
            part,
        );
    }
    pub(crate) fn spawn_blocking_owned(
        &self,
        work: impl FnOnce() + Send + 'static,
    ) -> WorkerReceipt {
        self.lifecycle.spawn_blocking(work)
    }
    /// Await the next inbound event. `None` once the session task has ended
    /// (the connection closed or the manager shut down) -- the backend should
    /// then wind down.
    pub async fn recv(&mut self) -> Option<SessionInbound> {
        let control = self.control().clone();
        if control.retiring() {
            self.inbound.close();
            while self.inbound.try_recv().is_ok() {}
            return None;
        }
        let received = tokio::select! {
            biased;
            _ = self.lifecycle.shutdown.requested() => {
                self.gates.close_all();
                self.inbound.close();
                while self.inbound.try_recv().is_ok() {}
                None
            }
            _ = control.retire_backend.notified() => None,
            inbound = self.inbound.recv() => inbound,
        };
        if let Some(SessionInbound::Live(origin) | SessionInbound::ResumeReset(origin)) = &received
        {
            self.set_control_origin(*origin);
        }
        received
    }

    /// Whose session this is. A backend that spawns a process runs it as
    /// this account.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Which login this session belongs to -- the router's own token for
    /// this device, stable across a warm reattach even though `session_id`
    /// is not. See [`LoginId`]'s docs for why this is the key a resource
    /// that must outlive a roam (a PAM session, say) has to use.
    pub fn login(&self) -> LoginId {
        self.login
    }

    /// Queue outbound bytes for `stream_id`. Non-blocking; a send after the
    /// session task has ended is silently dropped. A stream with a send gate
    /// counts the bytes on it from here until the bridge takes them (spec
    /// §4.7.2). Control records additionally require shared response custody;
    /// raw control overload requests an explicit scoped abort. A gate
    /// that saw only the connection's tail would let a producer faster than
    /// the bridge fill it past the gate's marks.
    pub fn send(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == crate::channel::CONTROL_STREAM {
            let origin = self.control().origin.lock().unwrap().attachment;
            self.send_control(origin, data);
            return;
        }
        let n = data.len() as u64;
        // Counted before the bridge can take them, never after: taken first,
        // they would count forever.
        let gate = self.gates.admit(stream_id, n);
        let sent = self
            .outbound
            .send(SessionOutbound::Data(StreamData { stream_id, data }));
        if sent.is_err() {
            if let Some(gate) = gate {
                gate.withdraw(n);
            }
        }
    }

    fn send_ordered_channel(&self, origin: AttachmentContext, message: SessionOutbound) {
        if !self.resume_snapshots.send_ordered(&self.outbound, message) {
            self.resource_exhausted(origin);
        }
    }

    pub(crate) fn send_channel_output(
        &self,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
        gate: Arc<SendGate>,
        output: ChannelOutput,
        gap_reserve: Option<crate::channel_timeline::TimelinePermit>,
    ) {
        let bytes = output.framed_len() as u64;
        gate.admit(bytes);
        self.send_ordered_channel(
            origin,
            SessionOutbound::ChannelOutput {
                position: 0,
                stream,
                instance,
                origin,
                output,
                charge: OutputCharge { gate, bytes },
                gap_reserve,
            },
        );
    }
    pub(crate) fn channel_closed(
        &self,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
    ) {
        self.send_ordered_channel(
            origin,
            SessionOutbound::ChannelClosed {
                position: 0,
                stream,
                instance,
                origin,
            },
        );
    }
    pub(crate) fn send_channel_exit(
        &self,
        descriptor: crate::channel::DrainingChannel,
        origin: AttachmentContext,
        code: Option<i32>,
        permit: crate::channel_timeline::TimelinePermit,
        response: crate::control_budget::ResponsePart,
    ) {
        let control = self.operation_delivery(response.encoded_bytes(), response);
        self.send_ordered_channel(
            origin,
            SessionOutbound::ChannelExit {
                position: 0,
                stream: descriptor.stream,
                instance: descriptor.instance,
                origin,
                code,
                open: descriptor.open,
                permit,
                control,
            },
        );
    }
    pub(crate) fn repaint_barrier(&self, generation: u64, sequence: u64) {
        let _ = self.outbound.send(SessionOutbound::RepaintBarrier {
            generation,
            sequence,
        });
    }
    fn resume_snapshot_ready(&self) {
        let _ = self.outbound.send(SessionOutbound::ResumeSnapshotReady);
    }
    pub(crate) fn protocol_failure(
        &self,
        origin: AttachmentContext,
        code: Option<crate::channel_geometry::ProtocolErrorCode>,
    ) {
        let _ = self
            .outbound
            .send(SessionOutbound::ProtocolFailure { origin, code });
    }

    /// Tell the connection whether `stream_id`'s backlog may be dropped
    /// after a long absence. Non-blocking, like `send`.
    pub fn set_stream_resyncable(&self, stream_id: u8, resyncable: bool) {
        let _ = self.outbound.send(SessionOutbound::Resyncable {
            stream_id,
            resyncable,
        });
    }

    /// `stream_id`'s send gate, made with `kind`'s marks on first use (see
    /// [`GateTable::gate`]). The bridge closes it when the stream's tail
    /// reaches the high mark and opens it at the low one.
    pub fn send_gate(&self, stream_id: u8, kind: GateKind) -> Arc<SendGate> {
        self.gates.gate(stream_id, kind)
    }

    /// Forget `stream_id`'s gate and wake whoever waits on it: its channel is
    /// gone.
    pub fn drop_send_gate(&self, stream_id: u8) {
        self.gates.remove(stream_id);
    }

    /// Close every gate for good: the session is ending.
    pub fn close_send_gates(&self) {
        self.gates.close_all();
    }

    /// Ask to hear [`SessionInbound::Delivered`] for `stream_id` once the peer
    /// has acknowledged everything sent on it before this call -- how a
    /// backend orders a record on another stream after this stream's data,
    /// which the transport does not do by itself: streams are delivered
    /// independently. Non-blocking, like `send`, and in the same order as
    /// it: the request is taken only after the data sent before it. The
    /// answer carries `token` back: a backend that reuses a stream number
    /// tells whose request it answers by it.
    pub fn notify_delivered(&self, stream_id: u8, token: u64) {
        if stream_id == crate::channel::CONTROL_STREAM
            && self.control().origin.lock().unwrap().aborting
        {
            return;
        }
        let _ = self
            .outbound
            .send(SessionOutbound::NotifyDelivered { stream_id, token });
    }

    /// Declare `stream_id`'s class (spec §4.8). Non-blocking, like `send`.
    pub fn set_stream_class(&self, stream_id: u8, class: StreamClass) {
        let _ = self
            .outbound
            .send(SessionOutbound::StreamClass { stream_id, class });
    }

    /// Report that `n` bytes of `stream_id` are taken (spec §4.10.3): for a
    /// backend that counts its own consumption (`SessionBackend::consumption`
    /// = `Explicit`). Every byte this backend is ever handed on this
    /// stream must eventually be reported this way, including one it
    /// drops rather than delivers -- a channel that ends with unread input
    /// still owes it a report for that input, dropped or not (see
    /// `SessionBackend::consumption`'s own doc for what happens to a
    /// stream nobody ever finishes reporting). Non-blocking, like `send`.
    pub fn consumed(&self, stream_id: u8, n: usize) {
        if n > 0 {
            let _ = self
                .outbound
                .send(SessionOutbound::Consumed { stream_id, n });
        }
    }

    /// A handle a blocking task reports consumption through. It does not
    /// keep the session's outbound queue open: once the io is gone its
    /// reports go nowhere, as the session is over.
    pub fn consumption_reporter(&self) -> ConsumptionReporter {
        ConsumptionReporter {
            outbound: self.outbound.downgrade(),
        }
    }

    /// Test-only: build a `SessionIo` paired with the sender that feeds its
    /// inbound events and the receiver that collects its outbound stream data.
    /// Lets the runner (`run_channel_session`) be driven and observed WITHOUT
    /// a real `Connection`/manager -- the test plays the role of the
    /// per-session bridge. `pub(crate)` so the runner module's `#[cfg(test)]`
    /// suite can reach it while it stays out of the public API.
    #[cfg(test)]
    pub(crate) fn test_pair() -> (
        SessionIo,
        mpsc::Sender<SessionInbound>,
        mpsc::UnboundedReceiver<SessionOutbound>,
    ) {
        // Most runner tests don't care who the session belongs to, or which
        // login it is, so a fixed placeholder is enough for both.
        Self::test_pair_for(
            Principal {
                uid: 0,
                name: "test".to_string(),
                identity: "test".to_string(),
                incarnation: 0,
            },
            [0u8; 16],
        )
    }

    /// Observe the actual replaceable mailbox in runner fixtures without a bridge.
    #[cfg(any(test, feature = "testnet"))]
    pub fn snapshot_reader_for_test(
        &self,
    ) -> impl Fn() -> Option<(u64, crate::channel::ChannelSnapshot)> + Send + 'static {
        let snapshots = self.resume_snapshots.clone();
        move || snapshots.take_fixture()
    }

    /// Build an in-process session fixture owned by `principal` and `login`.
    /// Available only for crate tests and the explicit `testnet` fixture feature,
    /// so consumers can test real backend lifetime without starting a daemon.
    #[cfg(any(test, feature = "testnet"))]
    pub fn test_pair_for(
        principal: Principal,
        login: LoginId,
    ) -> (
        SessionIo,
        mpsc::Sender<SessionInbound>,
        mpsc::UnboundedReceiver<SessionOutbound>,
    ) {
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        (
            SessionIo {
                lifecycle: Arc::new(Lifecycle::default()),
                control: OnceLock::new(),
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal,
                login,
                gates: Arc::new(GateTable::new()),
            },
            in_tx,
            out_rx,
        )
    }

    /// Test-only: [`SessionIo::test_pair`] plus the gate table, so a test can
    /// play the bridge's part in opening and closing gates.
    #[cfg(test)]
    pub(crate) fn test_pair_with_gates() -> (
        SessionIo,
        mpsc::Sender<SessionInbound>,
        mpsc::UnboundedReceiver<SessionOutbound>,
        Arc<GateTable>,
    ) {
        let (io, tx, rx) = Self::test_pair();
        let gates = Arc::clone(&io.gates);
        (io, tx, rx, gates)
    }
}

/// Reports consumption from a task that is not the backend's own -- a
/// channel's PTY writer, the update image's receiver (spec §4.10.3). The
/// same contract as [`SessionIo::consumed`] applies: every byte this task
/// is ever handed on its stream must eventually be reported, dropped ones
/// included, or that stream's window stays short for the rest of the
/// session (see [`SessionBackend::consumption`]'s doc).
#[derive(Clone)]
pub struct ConsumptionReporter {
    outbound: mpsc::WeakUnboundedSender<SessionOutbound>,
}

impl ConsumptionReporter {
    /// Report that `n` bytes of `stream_id` are taken -- see the struct's
    /// own doc for what must eventually be reported and why.
    pub fn consumed(&self, stream_id: u8, n: usize) {
        if n == 0 {
            return;
        }
        if let Some(outbound) = self.outbound.upgrade() {
            let _ = outbound.send(SessionOutbound::Consumed { stream_id, n });
        }
    }
}

/// The io goes exactly when its session's backend goes, whichever way: the
/// backend returned, its task panicked, or the runtime was dropped with it
/// (the daemon stopping). Every gate closes for good then, so a producer
/// waiting on one -- a line channel's reader, on a blocking thread -- wakes
/// and ends: never left behind with its process, and never holding up a
/// runtime's drop, which waits for every blocking thread.
impl Drop for SessionIo {
    fn drop(&mut self) {
        self.gates.close_all();
        if let Some(control) = self.control.get() {
            control.budget.retire();
        }
    }
}

/// An application-level session driver. `run` is called once per backend with
/// a fresh [`SessionIo`]; the returned future lives for the session. Boxed
/// future rather than `async_trait` to keep the crate dependency-free.
pub trait SessionBackend: Send + Sync + 'static {
    /// Mandatory application profile, checked before resolving or creating a session.
    fn required_features(&self) -> crate::Features {
        crate::Features::NONE
    }

    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Who says when a stream's bytes are consumed (spec §4.10.3), fixed
    /// before the backend runs. `OnDelivery` (the default): the bridge counts
    /// them the moment it hands them over.
    ///
    /// `Explicit`: the CONTRACT is that this backend reports every byte it
    /// is ever handed, on every stream, through [`SessionIo::consumed`] (or
    /// a task of its own, through [`SessionIo::consumption_reporter`]) --
    /// once it is written where it goes, or DROPPED rather than delivered
    /// (a channel that ends with unread input still owes a report for that
    /// input; the plan requires this of the channel runner from Task 8 on).
    /// A byte handed to this backend and never reported is a byte the
    /// stream's window can never grow past again: it stays short by that
    /// many bytes for the rest of the session, however many later reports
    /// arrive, and however many other channels go on to reuse the same
    /// stream number -- the ledger keeps no per-stream memory of WHICH
    /// channel a still-unreported byte belonged to, so complete reporting
    /// is what keeps a reused stream number's count exact, not any action
    /// of the ledger's own (spec §4.10.3; `session_manager::ConsumptionLedger`'s
    /// own doc).
    fn consumption(&self) -> Consumption {
        Consumption::OnDelivery
    }
}

/// Creates a backend per accepted session. Cloneable handle to a shared
/// backend implementation.
pub struct BackendFactory(pub Arc<dyn SessionBackend>);

/// Where a server gets the single-use nonce it puts in a handshake's msg2.
///
/// The personal mode mints one locally ([`RandomNonces`], which cannot
/// fail). The system mode's nonces come from its privileged helper instead,
/// so a compromised worker cannot mint its own -- handed out from a pool the
/// helper filled in advance (`qshd::nonce_pool::PooledNonces`). That source
/// can fail (the pool is empty: the helper is slow, unreachable, or its own
/// outstanding table is full), which `issue` surfaces as `Err` for the
/// caller to refuse the handshake and log why, rather than admit a client
/// with no nonce at all.
pub trait NonceSource: Send + Sync + 'static {
    /// A nonce for one handshake, never handed out before -- or `Err` at once.
    ///
    /// Must be fast, and must never wait on anything outside this process --
    /// no network, no other process, no helper, no lock held across any of
    /// those: the router calls it right on the one task that reads the socket
    /// and routes every live session's datagrams, for every msg1 that gets as
    /// far as asking, so however long it takes, every session on the server
    /// waits that long. A source that cannot answer at once refuses; the
    /// client sends its msg1 again. A source whose nonces come from elsewhere
    /// fetches them ahead of time, off this task.
    fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String>;

    /// Give up a nonce that was issued but will never be spent: the
    /// handshake it belonged to was refused, authenticated by allowlist (so
    /// no proof will ever echo it back), or its probation ended without one
    /// arriving. Cached msg2 replay issues no nonce. A tell, not
    /// an ask -- no result, and the caller never waits for it: like
    /// [`NonceSource::issue`], this runs on the router's own task, and must
    /// never wait on anything outside this process -- a source whose table
    /// lives elsewhere hands the release to be sent off this task. No
    /// default body: every source decides for itself what "give up" means (a
    /// source that stores nothing, like `RandomNonces`, does nothing here;
    /// one backed by a table removes the entry).
    fn release(&self, nonce: [u8; AUTH_NONCE_LEN]);
}

/// Mints every handshake nonce locally, with no privileged helper involved:
/// the personal mode's [`NonceSource`], and the only one a daemon that
/// serves exactly one account needs.
///
/// Lives here, in the crate that already depends on `rand`, rather than in
/// `qshd`: the system mode's nonces come from its helper instead
/// (`qshd::nonce_pool::PooledNonces`, filled over the same seam as the
/// helper's verdicts), so a compromised worker cannot mint its own, and
/// `qshd` itself needs no randomness dependency of its own for this.
pub struct RandomNonces;

impl NonceSource for RandomNonces {
    fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
        Ok(crate::auth::random_nonce())
    }

    /// Stores nothing, so there is nothing to give up.
    fn release(&self, _nonce: [u8; AUTH_NONCE_LEN]) {}
}

/// Where a server reports that a login is over for good -- the entry that
/// carried it is gone from the [`Router`]'s table, not merely disconnected
/// (see [`Router::forget_backend`] for the three ways that happens).
///
/// The system mode's helper is the real subscriber: it stops trusting the
/// uid that login belonged to once nothing keeps that promise alive
/// (`qshd::helper::spawner::HelperAuth`), and from the PAM slice on, this is
/// also where a login's PAM session gets closed. The personal mode has
/// nothing to forget -- see [`ForgetNothing`].
///
/// Called on the router's own task -- once for each login a GC pass ends --
/// so, like [`NonceSource`]'s calls, it must never wait on anything outside
/// this process: a sink that reports elsewhere hands the report to be sent
/// off this task.
pub trait LoginSink: Send + Sync + 'static {
    fn login_ended(&self, login: LoginId);
}

/// The personal mode's [`LoginSink`]: that daemon serves exactly one login,
/// keeps no PAM session tied to it, and holds nothing else keyed by
/// [`LoginId`] -- so there is nothing to do when one ends.
pub struct ForgetNothing;

impl LoginSink for ForgetNothing {
    fn login_ended(&self, _login: LoginId) {}
}

/// Why a login's end could not be handed to the router -- see
/// [`LoginEndedReporter::report`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginEndNotReported {
    /// As many ends are already waiting as the reporter was built to hold,
    /// and the router has taken none of them. Nothing is dropped quietly:
    /// the caller decides what a report it cannot deliver means for it, and
    /// the system mode's worker ends itself over one.
    Queued(usize),
    /// The router is gone: its loop has ended, or `serve` was never given
    /// this reporter's other half at all.
    RouterGone,
}

/// The other direction of [`LoginSink`]: where something OUTSIDE the router
/// says a login is over for good, and the router ends its session
/// ([`SessionManager::serve`] drains the other half, [`LoginEndedReports`]).
///
/// The system mode's privileged helper is the one reporter there is. A login
/// can end on its side -- its monitor lost, its entry swept, or one of the
/// orderings the split leaves open -- while the worker's session for it is
/// still perfectly alive, and that session is then STERILE: it pings fine
/// and every channel it asks for is refused, for good. Nothing the worker
/// can see says so on its own, because a refusal from the helper carries one
/// shared reason whatever caused it (`qshd::helper::server::REFUSED_REASON`),
/// deliberately, so that a taken-over worker cannot enumerate accounts. So
/// the helper says it plainly instead, and this is where that lands.
///
/// Ending the session is the whole remedy: the client then reconnects and
/// proves itself again, which is the only way back, since the proof rides
/// the handshake and a session resumed after a roam does not present it
/// again.
///
/// Every report names WHICH LIFE of that login ended, because the report
/// and a fresh admission of the same device race and nothing in the router
/// orders them -- see [`LoginEndedReporter::report`] and
/// [`Principal::incarnation`].
///
/// Cloneable and callable from any thread -- in the system mode the reader
/// of the helper's seam is a plain thread, not a task -- and it never
/// blocks: [`LoginEndedReporter::report`] either queues or returns.
#[derive(Clone)]
pub struct LoginEndedReporter {
    tx: mpsc::Sender<(LoginId, u64)>,
    /// What `tx` was built to hold, for the `Queued` report above: a bounded
    /// sender does not say its own capacity back.
    capacity: usize,
}

impl LoginEndedReporter {
    /// Hand the router one login that is over. Never waits, and never drops
    /// the news silently: a report that will not fit, or that nothing is
    /// left to receive, comes back as [`LoginEndNotReported`].
    ///
    /// `incarnation` says WHICH life of that login ended -- the value the
    /// reporter gave the same device in [`Principal::incarnation`] when it
    /// admitted it. The router needs it because this report and that
    /// admission race (see this type's own docs), and a report about a
    /// login that has already been replaced must not end the session that
    /// replaced it.
    pub fn report(&self, login: LoginId, incarnation: u64) -> Result<(), LoginEndNotReported> {
        match self.tx.try_send((login, incarnation)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                Err(LoginEndNotReported::Queued(self.capacity))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(LoginEndNotReported::RouterGone),
        }
    }
}

/// The router's half of [`LoginEndedReporter`]: what [`SessionManager::serve`]
/// drains, on its own task, one login per turn of its loop.
pub struct LoginEndedReports {
    rx: Option<mpsc::Receiver<(LoginId, u64)>>,
}

impl LoginEndedReports {
    /// For a server nobody reports to -- the personal mode, and every test
    /// that is not about this path. Never yields, rather than yielding
    /// `None` at once: a `serve` arm that completed immediately and for ever
    /// would be re-armed on every turn of the loop for nothing.
    pub fn none() -> LoginEndedReports {
        LoginEndedReports { rx: None }
    }

    /// The next login somebody outside says has ended, or `None` once every
    /// reporter is gone -- and never, for a [`LoginEndedReports::none()`].
    ///
    /// `pub` for one reason: a caller that wires a reporter into something
    /// of its own has no other way to prove the wiring reaches THIS half
    /// (`qshd::helper::spawner::worker_clients` does exactly that). Taking
    /// `&mut self`, and `serve` taking the whole value, is what keeps a
    /// second reader from competing with the router for the same reports.
    pub async fn recv(&mut self) -> Option<(LoginId, u64)> {
        match self.rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => std::future::pending().await,
        }
    }
}

/// A reporter and the router's half of it, holding at most `queued_at_most`
/// ends of logins between two turns of the router's loop.
///
/// The bound is the caller's, not this crate's: the system mode already has
/// one for the OPPOSITE direction, sized from this crate's own session and
/// probation caps (`qshd::helper::spawner::MAX_QUEUED_LOGIN_ENDS`), and the
/// two directions carry the same news about the same logins. One constant,
/// passed in, rather than a second one here that could drift from it.
pub fn login_end_channel(queued_at_most: usize) -> (LoginEndedReporter, LoginEndedReports) {
    let (tx, rx) = mpsc::channel::<(LoginId, u64)>(queued_at_most);
    (
        LoginEndedReporter {
            tx,
            capacity: queued_at_most,
        },
        LoginEndedReports { rx: Some(rx) },
    )
}

/// The server's authentication setup, shared by every session.
pub struct ServerAuth {
    /// Client static keys admitted without a signature (the SSH-bootstrap
    /// path). Live: the control socket can add to it while the daemon runs.
    pub allowlist: SharedAllowlist,
    /// When set, clients may instead announce `SshSignature` and prove
    /// themselves with this verifier. `None` = signature clients are refused.
    pub verifier: Option<Arc<dyn AuthVerifier>>,
    /// The server's static public key -- what a discovery request is answered
    /// with.
    pub server_pub: [u8; 32],
    /// The account for an allowlisted key after fresh transport possession
    /// is confirmed. This path uses no SSH signature verifier.
    /// This is the daemon's own account, the same `uid`/`name` handed to the
    /// verifier above.
    pub self_principal: Principal,
    /// Where this server's handshake nonces come from -- see [`NonceSource`].
    pub nonces: Arc<dyn NonceSource>,
    /// Where a login going away is reported -- see [`LoginSink`].
    pub logins: Arc<dyn LoginSink>,
}

/// Authority to publish the outcome of a completed manager admission.
/// This value is private to the manager/bridge handoff.
#[derive(Debug)]
struct CommittedAdmission(AuthAcceptance);

impl CommittedAdmission {
    fn enqueue(self, conn: &mut Connection, now: Instant) -> Option<Vec<Datagram>> {
        if self.0.session_id != conn.session_id() {
            return None;
        }
        // This is the first server write to AUTH_STREAM on a fresh transport.
        // Its implicit credit window cannot be reduced by the peer. A bounded
        // enqueue succeeds even when congestion defers the actual datagram.
        conn.try_send_bounded(
            now,
            AUTH_STREAM,
            &crate::encode_auth_acceptance(self.0),
            crate::auth_acceptance::AUTH_ACCEPTANCE_LEN,
        )
        .ok()
    }
}

/// A control message from the manager to a backend's PERSISTENT bridge task.
enum BridgeControl {
    /// A new client `Connection` has reattached (warm) to this backend: drive
    /// it in place of the current one. The bridge emits [`SessionInbound::ResumeReset`]
    /// to the backend and repoints itself at the new connection, WITHOUT the
    /// backend being torn down or respawned. Boxed so this rare control message
    /// doesn't bloat the bridge's `Wakeup` on the hot datagram path.
    ///
    /// The connection is always one whose peer has already authenticated: an
    /// allowlist handshake proved itself by its static key, a signature
    /// handshake by finishing its probation. So `Attach` carries no verifier
    /// -- there is nothing left to check -- only the stream bytes the peer
    /// sent before its proof landed, which the bridge replays to the backend
    /// after `ResumeReset`.
    ///
    /// The third field is the datagrams the new peer sent while its proof was
    /// being checked, which the bridge runs through the new connection before
    /// it reads its own route: sent into that route instead, `select!` could
    /// take one before the `Attach` and feed it to the connection being
    /// replaced.
    Attach(
        Box<Connection>,
        Vec<StreamData>,
        Vec<(SocketAddr, Vec<u8>)>,
        oneshot::Receiver<CommittedAdmission>,
    ),
}

/// A registered backend for one token (= one device). One backend task + one
/// persistent bridge task run per entry; the `Connection` they drive is
/// SWAPPABLE (warm reattach) while the backend keeps running.
struct BackendEntry {
    admission: Arc<SessionControl>,
    /// The session currently bound to this token. Updated on every (re)attach;
    /// guards `reclaim` so a same-token swap is not reclaimed by a stale
    /// end-signal from the connection it replaced.
    session_id: u64,
    /// Control channel to this backend's persistent bridge task (warm reattach).
    control: mpsc::UnboundedSender<BridgeControl>,
    /// The exact msg1 body that most recently (re)bound this entry. A
    /// byte-identical msg1 is a retransmit (same ephemeral key) rather than a
    /// deliberate new start: the client is retransmitting because it hasn't seen
    /// msg2 yet. Such a duplicate is handled idempotently -- re-send the ORIGINAL
    /// reply (see `msg2`) rather than mint a new session -- so it neither spawns
    /// a second backend NOR repoints the client's still-live route.
    last_msg1_body: Vec<u8>,
    /// The wire bytes of the HandshakeResp (msg2) for the session currently
    /// bound to this entry. Cached so a byte-identical msg1 retransmit can be
    /// answered by REPRODUCING the original reply (same `session_id`) to the
    /// client's current address, which also recovers a lost first msg2. Refreshed
    /// on every (re)bind so it always matches `session_id`.
    msg2: Vec<u8>,
    /// The authenticated client static key for the session currently bound to
    /// this entry. Stored here so `on_session_ended` can return it
    /// to the caller, which scrubs it off the SHARED allowlist -- the key of
    /// an ended connection (graceful teardown or a death/retain) must not
    /// linger, so it can't be reused unless the client is re-added.
    client_key: [u8; 32],
    /// Lifecycle state: `Live` while a session is attached, `Retained` while
    /// waiting for warm reconnect or resolution of a graceful end's proof.
    state: EntryState,
    /// While `Retained`, the STABLE datagram sender for the parked bridge's
    /// `dgram_rx` -- moved here out of `sessions` on death so the bridge's
    /// receiver stays open (its backend keeps running), and moved back into
    /// `sessions` under a new `session_id` on a warm reattach. `None` while
    /// `Live` (the sender then lives in `sessions`).
    parked_dgram: Option<DgramTx>,
    /// The account this session belongs to. Set when the entry is created
    /// and never rewritten: a session does not change hands.
    owner: u32,
    /// Which INCARNATION of this device's login the handshake that bound
    /// this entry was admitted under ([`Principal::incarnation`]), refreshed
    /// on every (re)bind so it always matches the proof behind the session
    /// that is attached right now.
    ///
    /// What [`Router::end_login`] compares against. `0` for every server
    /// whose verifier keeps nothing per login, which is also every server
    /// with no reporter, so the comparison never runs there.
    incarnation: u64,
}

/// How the manager routes an accepted `HandshakeInit` against the token's
/// existing backend (if any). Computed as a value so the immutable `backends`
/// borrow used to decide is released before the mutating step runs.
enum AcceptDecision {
    /// No entry for this token yet: spawn a fresh backend + bridge.
    ColdCreate,
    /// An entry exists and this msg1 is BYTE-IDENTICAL to the one that bound it
    /// (same ephemeral key = a retransmit, because the client hasn't seen msg2).
    /// This is exactly what a normal driver handshake retransmit produces: the
    /// client fixes its Noise ephemeral for the whole handshake and re-sends the
    /// stored first msg1 datagram verbatim (see `driver_std`), so a lost msg2
    /// lands here, NOT on `WarmReattach`/`ColdReplace`. Idempotent: re-send the
    /// ORIGINAL msg2 (same `session_id`) and touch NOTHING else -- no new
    /// session, no route repoint, no respawn. An early cache hit needs no
    /// fresh connection; an already-proven in-flight twin is discarded.
    ResendMsg2,
    /// An entry exists and this is a genuine warm reconnect (a NEW ephemeral key,
    /// same token): reattach the NEW connection to the still-running backend,
    /// minting a new `session_id` and repointing the route, without respawning.
    WarmReattach,
    /// An entry exists and this is a deliberate cold restart (different msg1,
    /// `start_kind=Cold`): tear the old backend down and cold-create fresh.
    ColdReplace,
}

/// One connection in probation, as the router tracks it.
struct ProbationSeat {
    /// Canonical source group, shared with the cookie rate limiter.
    source: [u8; 16],
    /// The login its handshake named. Unproven, so it binds nothing -- it
    /// only tells the removers of a retained session that a proof for that
    /// session's login may already be with the verifier.
    login: LoginId,
}

/// The router's session table, owned solely by the `serve` loop (no shared
/// lock on the datagram path).
struct Router {
    revisions: BindingRevisions,
    /// `session_id` -> router->task datagram sender, for demuxing `Transport`
    /// frames to the owning session task. Holds both bound sessions and the
    /// provisional routes of connections still in probation.
    sessions: HashMap<u64, DgramTx>,
    /// Token -> backend entry, one per device.
    backends: HashMap<[u8; 16], BackendEntry>,
    /// Moved entries remain charged until their exact old bridge ends.
    retiring: HashMap<u64, BackendEntry>,
    /// The `session_id`s currently in PROBATION (see `crate::probation`):
    /// accepted on the signature path, routed so their proof can arrive, but
    /// bound to nothing. Kept apart from `backends` so what an unproven peer
    /// can create is counted -- and capped -- on its own. Each entry also
    /// remembers WHERE its handshake came from, so the cap can be applied per
    /// source as well as globally (see [`Router::admit_probation`]), and
    /// which login it named (see [`Router::in_probation`]).
    probation: HashMap<u64, ProbationSeat>,
    /// Logins [`Router::forget_backend`] has ended since the last
    /// [`Router::take_ended_logins`], waiting to be forwarded to
    /// `ServerAuth.logins` -- the `Router` itself holds no `ServerAuth`, so
    /// it only collects; the caller (`SessionManager::serve`, which does
    /// hold one) is what actually tells the sink.
    ended_logins: Vec<LoginId>,
    /// The return-address check every handshake datagram passes first (spec
    /// §4.16): under load a msg1 is answered with a cookie instead of Noise
    /// work or a probation seat. Lives here because it reads the probation
    /// table and `handle_datagram` owns the router.
    cookies: CookieCheck,
    /// What the log last said about that load.
    load_log: LoadLog,
}

impl Router {
    fn new() -> Self {
        Router {
            revisions: BindingRevisions::new(MAX_SESSIONS_TOTAL + MAX_PROBATION),
            sessions: HashMap::new(),
            backends: HashMap::new(),
            retiring: HashMap::new(),
            probation: HashMap::new(),
            ended_logins: Vec::new(),
            cookies: CookieCheck::new(Instant::now()),
            load_log: LoadLog::new(),
        }
    }

    /// Every path that drops a backend goes through here: a graceful end, the
    /// last pending proof after graceful end, garbage collection past
    /// `RETAIN_AFTER_DEATH`, and eviction of the oldest retained entry. The
    /// login is over for good at that moment --
    /// not when the connection dropped, because a retained entry is exactly
    /// the promise that the same login may come back (roaming, a flaky
    /// link).
    fn forget_backend(&mut self, token: LoginId, why: &str) {
        if self.backends.remove(&token).is_some() {
            self.revisions.invalidate(token);
            self.ended_logins.push(token);
            log::info!("login ended ({why})");
        }
    }

    /// Drain every login ended since the last call. See `ended_logins`'s own
    /// docs for who this is for.
    fn take_ended_logins(&mut self) -> Vec<LoginId> {
        std::mem::take(&mut self.ended_logins)
    }

    /// End a login because something OUTSIDE the router says it is over --
    /// the system mode's privileged helper, which has forgotten it and will
    /// refuse every channel that login asks for from now on. See
    /// [`LoginEndedReporter`] for why the helper has to say so out loud and
    /// why ending the session is the whole remedy.
    ///
    /// "That login", not "the session that holds the token": which of the
    /// token's lives the report is about is what `incarnation` says, and a
    /// report about a life that is over says nothing about the one that
    /// replaced it -- see below.
    ///
    /// No SECOND way for a session to end is introduced here; this is a new
    /// REASON for the one that exists. The teardown is exactly
    /// `AcceptDecision::ColdReplace`'s: the entry goes -- which drops the
    /// bridge's control channel, and, for a RETAINED entry, the parked
    /// datagram sender -- and the datagram ROUTE goes with it, which is what
    /// actually ends a LIVE bridge (`Wakeup::Dgram(None)`; dropping the
    /// control channel alone only stops a live bridge polling that arm, see
    /// `Wakeup::Control(None)`). The bridge then signals its own
    /// [`SessionEnded`] as it always does, and [`Router::on_session_ended`]'s
    /// `session_id` guard finds no entry and ignores it, exactly as it
    /// ignores a cold replace's.
    ///
    /// This is the FIRST caller that can reach a `Live` entry: the other
    /// removers ([`Router::forget_backend`]'s callers) each run where
    /// the bridge has already exited or is parked. That is why the route is
    /// removed here and not there.
    ///
    /// Deliberately does NOT record the login in `ended_logins`, unlike
    /// the other removers: the news came FROM the sink those ends are
    /// forwarded to. Echoing it back would at best be redundant -- and at
    /// worst destructive, because by the time it arrived the client may have
    /// proved itself again under the same token, which gives the helper a
    /// FRESH entry (`Request::Verify` is the one thing that creates one),
    /// and the echo would end that instead.
    ///
    /// That silence is also what makes the comparison below load-bearing
    /// rather than tidy: a teardown this method performs is one the
    /// reporter never hears about, so a teardown it performs WRONGLY is one
    /// nothing corrects.
    ///
    /// **`incarnation` is what makes this safe to act on at all.** The
    /// report and a fresh admission of the same device race: they cross the
    /// worker on separate sockets, are read by separate threads, and meet in
    /// this loop's own `select!`, which has no `biased;` and so picks a
    /// ready arm at random. A report that was written while the OLD login
    /// was alive can therefore be taken off the queue after the same device
    /// has proved itself again and been given a session -- most easily when
    /// many logins end at once and the queue drains one per turn while those
    /// clients all reconnect. Acting on it then would tear down a session
    /// that is perfectly good, and -- because this path deliberately tells
    /// the reporter nothing back -- would leave the reporter holding a login
    /// with no session behind it, which on the system mode's helper is a
    /// root monitor process and a PAM session that nothing expires.
    ///
    /// So a report older than the incarnation the current binding was
    /// admitted under is DROPPED. Equal is acted on: that is the ordinary
    /// case, the same life of the same login. Newer cannot happen from a
    /// well-behaved reporter -- it would mean a login ended that this
    /// router was never told had begun -- and is acted on rather than
    /// dropped, since the alternative is to ignore news about a login that
    /// really has ended.
    ///
    /// Answers whether there was anything to end. `false` is ordinary, not
    /// an error: the report and the session's own end race by nature, and a
    /// login whose session has already gone needs nothing done to it -- and
    /// so does a report this comparison drops.
    ///
    /// **`false` for an empty table is not the same kind of harmless**, and
    /// it is the one case this notice does not cover: a report consumed
    /// against no entry is a report SPENT, and none of that login's later
    /// bindings will ever hear it. If one appears a moment afterwards -- a
    /// cold create for the same token -- it is sterile for its whole life,
    /// exactly as if nothing had been sent, because the notice is
    /// edge-triggered and nothing here remembers the edge. Closing that
    /// needs a token-to-incarnation record outliving the report; do not read
    /// this `false` as "nothing was lost".
    fn end_login(&mut self, token: LoginId, incarnation: u64) -> bool {
        match self.backends.get(&token) {
            None => return false,
            Some(entry) if entry.incarnation > incarnation => {
                log::info!(
                    "ignoring the end of a login that has already been replaced by a \
                     fresher one"
                );
                return false;
            }
            Some(_) => {}
        }
        let entry = self
            .backends
            .remove(&token)
            .expect("just found under the same key, on this one task");
        // Revoke effects synchronously, then retain only the exact old route
        // for admitted outcomes and their ACKs. A retained route is restored
        // from parked_dgram; it cannot be used to resume this backend again.
        entry.admission.retire();
        if let Some(route) = entry.parked_dgram.as_ref() {
            self.sessions.insert(entry.session_id, route.clone());
        }
        self.retiring.insert(entry.session_id, entry);
        self.revisions.invalidate(token);
        log::info!("login ended (reported over for good from outside the router)");
        true
    }

    /// Admit one more connection to probation, or refuse. Refusal is a SILENT
    /// DROP: unlike `admit_new_backend` there is nothing to evict, because a
    /// probation entry belongs to a peer that has proved nothing, and evicting
    /// one would only let the newest stranger displace the previous one.
    ///
    /// TWO caps, and both must pass. The global [`MAX_PROBATION`] bounds what
    /// the table costs; [`MAX_PROBATION_PER_SOURCE`] is what makes it
    /// hostile-proof, because a global cap alone is exhaustible by ONE
    /// unauthenticated source group -- and a full table is a lockout: every
    /// signature client's sign-in, and every warm reattach after a network
    /// change, has to pass through here.
    ///
    /// `login` is the token the handshake named. It is recorded, not
    /// trusted: see [`Router::in_probation`] for the one thing it is used for.
    fn admit_probation(&mut self, session_id: u64, src: SocketAddr, login: LoginId) -> bool {
        if self.probation.len() >= MAX_PROBATION {
            log::warn!("probation cap reached, dropping an unauthenticated handshake");
            return false;
        }
        // Counted by scanning rather than kept in a second index: the table
        // holds at most `MAX_PROBATION` entries, so the scan is trivial, and a
        // parallel counter would be one more thing to keep exactly in step
        // with every removal (a leak there would lock a source out for good).
        let source = source_group_key(src.ip());
        let from_this_source = self
            .probation
            .values()
            .filter(|s| s.source == source)
            .count();
        if from_this_source >= MAX_PROBATION_PER_SOURCE {
            log::warn!("per-source probation cap reached, dropping an unauthenticated handshake");
            return false;
        }
        self.probation
            .insert(session_id, ProbationSeat { source, login });
        true
    }

    /// Whether a handshake naming `login` is in probation right now.
    ///
    /// Its proof may already be with the verifier, and in the system mode the
    /// helper may already have put that proof into `login`'s existing entry.
    /// Ending `login` at that moment (`forget_backend`) makes the helper drop
    /// that very entry, and the proof then binds a fresh backend the helper
    /// opens no channel for, until the client reconnects. The router cannot
    /// tell a proof that has reached the helper from one that has not, so a
    /// remover of a retained session holds back for any of them -- and only
    /// so far: see [`Router::gc_retained`] and
    /// [`Router::evict_oldest_retained`].
    fn in_probation(&self, login: &LoginId) -> bool {
        self.probation.values().any(|s| s.login == *login)
    }

    /// Resolve an accepted handshake against this token's existing backend.
    /// The decision is a VALUE so the immutable borrow used to decide is
    /// released before the mutating step runs -- and so it can be taken twice
    /// on the signature path: once to see whether the handshake is a mere
    /// retransmit, and again, against the table as it stands THEN, when the
    /// peer's proof finally lands.
    fn resolve(&self, token: &[u8; 16], msg1_body: &[u8], start_kind: StartKind) -> AcceptDecision {
        match self.backends.get(token) {
            None => AcceptDecision::ColdCreate,
            Some(entry) => {
                if entry.last_msg1_body.as_slice() == msg1_body {
                    // Byte-identical msg1 = retransmit (same ephemeral key).
                    // NOT a reattach: minting a new session_id here would
                    // repoint the route while the client -- already Live on
                    // the first msg2 -- stays on the old one, wedging it.
                    // Re-send the original reply instead.
                    AcceptDecision::ResendMsg2
                } else {
                    match start_kind {
                        StartKind::Warm => AcceptDecision::WarmReattach,
                        StartKind::Cold => AcceptDecision::ColdReplace,
                    }
                }
            }
        }
    }

    /// Apply the lifecycle policy when a session ends,
    /// and report the ended connection's `client_key` so
    /// the caller can scrub it off the SHARED allowlist -- a live/self-cleaning
    /// allowlist means the key of an ended connection does not linger, whether
    /// the backend itself was torn down or merely retained.
    ///
    /// The `sessions` route (keyed by the unique `session_id`) is always
    /// removed. The `backends` entry is touched only if it still points at this
    /// session (a same-token overwrite may already have replaced it -- a stale
    /// end-signal, ignored):
    /// - `graceful` (a received `Close`): tear the backend down IMMEDIATELY --
    ///   drop the entry. The bridge has already exited, so this just clears the
    ///   table. EXCEPT while a handshake naming this token is in probation
    ///   ([`Router::in_probation`]): see below.
    /// - not graceful (an unexpected death via `DEATH_AFTER`): RETAIN the
    ///   backend -- mark it `Retained{since: now}` and park the removed dgram
    ///   sender so the still-running bridge's receiver stays open for a later
    ///   warm reattach. The key is scrubbed HERE too (not just on graceful
    ///   teardown): a retained-but-dead connection's key must not stay
    ///   allowlisted while it waits for a reconnect -- a genuine warm reconnect
    ///   mints a fresh key via `ADD-CLIENT` before its handshake, so removing
    ///   the OLD key on death does not block it.
    ///
    /// Repeated end-signals keep the first retention time, GC reprieve and
    /// parked route. A later graceful backend exit still tears down when no
    /// proof is pending, or upgrades retention to wait for that proof; a later
    /// death cannot undo the graceful end.
    ///
    /// Returns `Some(client_key)` when this end-signal matched the current
    /// entry (so the caller must scrub that key), `None` for a stale
    /// end-signal (nothing to scrub -- the entry it belonged to is already
    /// gone or was replaced).
    ///
    /// # The graceful branch holds back for a probation
    ///
    /// A close, however graceful, must not end a login whose PROOF may
    /// already be with the helper. The order that does it: a client opens a
    /// second handshake under the same token while the first connection is
    /// still up, that handshake's `Request::Verify` creates the login entry
    /// in the helper (`ensure_login`, the only place one is created), and
    /// the first connection then closes cleanly inside the same window.
    /// Ending the login here removes the entry the proof had just made, and
    /// the surviving session never presents a proof again -- roaming and a
    /// warm reattach do not repeat one -- so every `Request::Open` it ever
    /// makes is refused with the same "authentication failed" that a bad
    /// signature gets. Nobody on either side can tell those two apart, so
    /// nothing tears the session down: it pings as live and can never open
    /// a channel again. `ensure_login`'s counterpart is pinned by
    /// `qshd`'s `an_open_served_after_its_login_ended_does_not_bring_it_back`.
    ///
    /// So a graceful close of a token in probation RETAINS instead of
    /// forgetting. The last candidate's completion releases this retention
    /// after its binding decision, unless that decision revived the entry.
    /// The existing GC reprieve still bounds a candidate that lingers.
    /// Retaining a backend whose bridge has already exited is safe on the way back:
    /// `apply_decision`'s `WarmReattach` sends to that bridge's control
    /// channel and falls back to a cold create when the send fails, which
    /// is exactly what an exited bridge does.
    ///
    /// This is the same predicate `gc_retained` and `evict_oldest_retained`
    /// already apply when deciding which retained backends to remove.
    ///
    /// `now` is a `tokio::time::Instant` so retention is measured on tokio's
    /// (test-fast-forwardable) clock.
    fn on_session_ended(
        &mut self,
        ended: SessionEnded,
        now: tokio::time::Instant,
    ) -> Option<[u8; 32]> {
        if self.retiring.contains_key(&ended.session_id) {
            // A Death notification can already be queued when retirement
            // starts. It never proves that this bridge released custody.
            if ended.phase == SessionEndPhase::Final {
                self.sessions.remove(&ended.session_id);
                self.retiring.remove(&ended.session_id);
            }
            // Never mutate a newer token binding or scrub its possibly reused key.
            return None;
        }
        let dg_tx = self.sessions.remove(&ended.session_id);
        // Read before the entry is borrowed, not because the borrow checker
        // insists but because the question is about the probation table and
        // has nothing to do with which entry is about to be touched.
        let proving = self.in_probation(&ended.token);
        match self.backends.get_mut(&ended.token) {
            Some(entry) if entry.session_id == ended.session_id => {
                let client_key = entry.client_key;
                if ended.graceful && !proving {
                    self.forget_backend(ended.token, "graceful close");
                } else {
                    match &mut entry.state {
                        EntryState::Live => {
                            entry.state = EntryState::Retained {
                                since: now,
                                reprieved: false,
                                reason: if ended.graceful {
                                    RetentionReason::PendingProof
                                } else {
                                    RetentionReason::UnexpectedDeath
                                },
                            };
                            entry.parked_dgram = dg_tx;
                        }
                        EntryState::Retained { reason, .. } => {
                            // The first end already parked the stable route.
                            // Repeats cannot drop it or restart age/reprieve.
                            // A parked backend can subsequently exit: preserve
                            // that graceful end until its pending proof lands,
                            // even if another death notification follows it.
                            if ended.graceful {
                                *reason = RetentionReason::PendingProof;
                            }
                        }
                    }
                }
                Some(client_key)
            }
            // Stale end-signal from a swapped-out / replaced session, or a
            // teardown-exit whose entry was already evicted: nothing to do,
            // nothing to scrub.
            _ => None,
        }
    }

    /// Tear down every `Retained` backend older than `RETAIN_AFTER_DEATH`.
    /// Dropping the entry drops its control and parked-dgram senders, so the
    /// parked bridge wakes on a closed channel and exits, ending the backend.
    ///
    /// Except, for ONE pass, a backend whose login is [`Router::in_probation`]:
    /// that is a device coming back just as its time runs out, and ending
    /// its login now would strand it (see that method). A probation ends
    /// within a round trip and a verification, long before the next pass
    /// (`GC_INTERVAL`). One pass and no more, whatever is in probation by
    /// then: a proof that never lands -- a stranger replaying the token's
    /// handshake, over and over -- must not keep a dead session, and the
    /// login the helper still trusts for it, alive for good.
    fn gc_retained(&mut self, now: tokio::time::Instant) {
        let expired: Vec<[u8; 16]> = self
            .backends
            .iter()
            .filter_map(|(token, e)| match e.state {
                EntryState::Retained { since, .. }
                    if now.saturating_duration_since(since) >= RETAIN_AFTER_DEATH =>
                {
                    Some(*token)
                }
                _ => None,
            })
            .collect();
        for token in expired {
            let proving = self.in_probation(&token);
            if let Some(EntryState::Retained { reprieved, .. }) =
                self.backends.get_mut(&token).map(|e| &mut e.state)
            {
                if proving && !*reprieved {
                    *reprieved = true;
                    log::info!(
                        "gc spares a retained backend one pass: a handshake for its login \
                         is in probation"
                    );
                    continue;
                }
            }
            // No silent cap: `forget_backend` records the GC teardown.
            self.forget_backend(token, "gc past RETAIN_AFTER_DEATH");
        }
    }

    /// Whether another session would fit: this account is under its own cap,
    /// and the daemon as a whole is under the ceiling.
    fn has_room_for(&self, owner: u32) -> bool {
        let owned = self
            .backends
            .values()
            .chain(self.retiring.values())
            .filter(|e| e.owner == owner)
            .count();
        owned < MAX_SESSIONS_PER_OWNER
            && self.backends.len() + self.retiring.len() < MAX_SESSIONS_TOTAL
    }

    /// Evict the oldest `Retained` entry among those matching `owner_filter`
    /// (every entry, if `None`; only `owner`'s own, if `Some(owner)`), and
    /// report whether one was found. Shared by both branches of
    /// `admit_new_backend`: the TOTAL-ceiling branch scans every owner, the
    /// per-owner-cap branch scans only the caller's own entries, and both
    /// want the same "oldest first, none found means every match is `Live`"
    /// logic.
    ///
    /// "Oldest" among the backends whose login is not
    /// [`Router::in_probation`] first: evicting a device that is coming back
    /// right now would strand it (see that method), and another retained
    /// backend costs nobody anything. Only when every match is in probation
    /// does the oldest of those go. A preference, not an exemption: anyone
    /// who can replay a token's handshake could otherwise hold every retained
    /// backend out of reach and turn the session cap into a lockout.
    fn evict_oldest_retained(&mut self, owner_filter: Option<u32>) -> bool {
        let victim = self
            .backends
            .iter()
            .filter(|(_, e)| owner_filter.is_none_or(|o| e.owner == o))
            .filter_map(|(token, e)| match e.state {
                EntryState::Retained { since, .. } => Some((*token, since)),
                EntryState::Live => None,
            })
            .min_by_key(|(token, since)| (self.in_probation(token), *since))
            .map(|(token, _)| token);
        match victim {
            Some(token) => {
                self.forget_backend(token, "evicted to make room for a new login");
                true
            }
            None => false,
        }
    }

    /// Decide whether a NEW backend for `owner` may be admitted (cap +
    /// eviction). Under both caps: always yes.
    ///
    /// At `owner`'s OWN cap: evicting some OTHER account's retained backend
    /// would let this one go over the limit the per-owner cap exists to
    /// enforce, so that is never a candidate. `owner`'s OWN oldest `Retained`
    /// entry is, though -- swapping one of its own dead-but-retained sessions
    /// for a new one is not growth, so it can never breach the cap, and it is
    /// what lets a device holding a handful of stale, unreachable sessions
    /// reconnect at once instead of waiting out `RETAIN_AFTER_DEATH` for one
    /// of them to be GC'd. REJECT only if every one of `owner`'s own entries
    /// is `Live`.
    ///
    /// Otherwise (under its own cap, but the TOTAL ceiling is what's
    /// blocking): evict the OLDEST `Retained` entry, of ANY owner, and admit
    /// -- in both branches, one whose login is in probation only if nothing
    /// else matches (see [`Router::evict_oldest_retained`]);
    /// if every entry is `Live`, REJECT (return false) -- the caller must not
    /// create a session or reply with msg2. Every rejection and eviction is
    /// logged (no silent cap).
    fn admit_new_backend(&mut self, owner: u32) -> bool {
        if self.has_room_for(owner) {
            return true;
        }
        let owned = self
            .backends
            .values()
            .chain(self.retiring.values())
            .filter(|e| e.owner == owner)
            .count();
        if owned >= MAX_SESSIONS_PER_OWNER {
            if self.evict_oldest_retained(Some(owner)) {
                log::warn!("per-owner session cap reached, evicted the caller's own oldest retained backend");
                return true;
            }
            log::warn!("per-owner session cap reached, every one of the caller's own backends is live -- rejecting new session");
            return false;
        }
        if self.evict_oldest_retained(None) {
            log::warn!("session cap reached, evicted oldest retained backend");
            return true;
        }
        log::warn!("session cap reached, all backends live -- rejecting new session");
        false
    }

    /// Detach the STABLE datagram sender for `token`'s current binding, wherever
    /// it lives: the live `sessions` route (a `Live` entry) or the parked slot
    /// (a `Retained` entry being revived). `None` if the entry/route is gone.
    fn take_stable_route(&mut self, token: &[u8; 16]) -> Option<DgramTx> {
        let (old_id, retained) = {
            let e = self.backends.get(token)?;
            (e.session_id, matches!(e.state, EntryState::Retained { .. }))
        };
        if retained {
            self.backends
                .get_mut(token)
                .and_then(|e| e.parked_dgram.take())
        } else {
            self.sessions.remove(&old_id)
        }
    }

    /// Record which life of `token`'s login a fresh proof was admitted
    /// under, and touch nothing else about the entry.
    ///
    /// For the one receive branch that adopts NOTHING from the connection it
    /// is handed -- `AcceptDecision::ResendMsg2`, where the client is still
    /// Live on the session the entry already names, so a rebind would wedge
    /// it. The incarnation is the exception because it is not about this
    /// connection at all: it is about the LOGIN behind it, which both twins
    /// share and which can have ended and been admitted again between their
    /// two probations. An entry left claiming the older life would then be
    /// torn down by a report about a login that is over while the session on
    /// it is perfectly alive -- the very failure the comparison exists to
    /// prevent, reached through the one branch that does not refresh.
    ///
    /// Folds through [`incarnation_after`], so an admission that carries no
    /// incarnation leaves the entry's alone.
    fn note_incarnation(&mut self, token: &LoginId, admitted: u64) {
        if let Some(entry) = self.backends.get_mut(token) {
            entry.incarnation = incarnation_after(entry.incarnation, admitted);
        }
    }

    /// Rebind `token`'s entry to a revived/reattached connection: register the
    /// new route under `new_session_id`, mark the entry `Live`, refresh the
    /// retransmit-idempotency fields, and clear any parked route.
    ///
    /// Returns the SUPERSEDED `client_key` this entry carried before the
    /// rebind: a warm reattach with a NEW key must
    /// scrub the OLD one off the shared allowlist too, not just on a later
    /// `SessionEnded` (which a fast roam that beats `DEATH_AFTER` never even
    /// emits for the superseded connection -- `Wakeup::Control(Attach)` just
    /// swaps `conn` in place). `None` if, defensively, the entry was somehow
    /// already gone (the call sites all check presence first, so this is not
    /// expected in practice).
    /// `incarnation` is the reattaching handshake's own
    /// ([`Principal::incarnation`]), and it REPLACES the entry's. Usually
    /// the two are equal -- a verifier that keeps a login entry reuses it
    /// for a repeat proof under the same token, which is what a warm
    /// reattach is. They differ when the old login ended in between and the
    /// device came back to a retained backend: the entry would otherwise go
    /// on claiming a life that is over, and a notice about THAT life would
    /// end the session this call has just revived.
    fn rebind(&mut self, token: &[u8; 16], to: Rebind<'_>) -> Option<[u8; 32]> {
        self.sessions.insert(to.session_id, to.dgram);
        let e = self.backends.get_mut(token)?;
        let old_key = e.client_key;
        e.session_id = to.session_id;
        e.last_msg1_body = to.msg1_body.to_vec();
        e.msg2 = to.msg2;
        e.client_key = to.client_key;
        e.state = EntryState::Live;
        e.parked_dgram = None;
        e.incarnation = incarnation_after(e.incarnation, to.incarnation);
        Some(old_key)
    }
}

/// Which incarnation an entry should claim after an admission that reports
/// `admitted` -- the one rule every receive branch folds through, so that
/// none of them has to decide it for itself.
///
/// [`NO_INCARNATION`] means ABSENCE, not "the zeroth life", so an admission
/// carrying it says nothing about which life of the login it was proven
/// under and must not overwrite a number that does. The allowlist path
/// always carries it: that path has no verifier at all, its principal is the
/// daemon's own account, and fresh transport proof carries no login epoch. Writing
/// that 0 over a real number would make the entry claim "no life", which
/// compares as older than every report and so lets every report through --
/// the staleness check off, by accident, for that token.
///
/// The other way round needs no rule: a server whose verifier keeps nothing
/// per login has no reporter either, so its entries stay at
/// [`NO_INCARNATION`] and nothing ever compares them.
fn incarnation_after(stored: u64, admitted: u64) -> u64 {
    if admitted == NO_INCARNATION {
        stored
    } else {
        admitted
    }
}

/// Everything a warm reattach rebinds `token`'s entry to: the new
/// connection's own facts, gathered into one value so [`Router::rebind`]
/// takes a named field per fact rather than a row of positional arguments
/// (six of which were already `u64`, `Vec<u8>` and `[u8; 32]`).
struct Rebind<'a> {
    /// The freshly minted id the datagram route is registered under.
    session_id: u64,
    /// The STABLE datagram sender, taken from wherever it lived while the
    /// entry was Live or Retained -- see [`Router::take_stable_route`].
    dgram: DgramTx,
    /// The exact msg1 body that rebound the entry, for the
    /// retransmit-idempotency comparison.
    msg1_body: &'a [u8],
    /// The wire bytes of the msg2 that answered it.
    msg2: Vec<u8>,
    /// The authenticated client static key of the reattaching connection.
    client_key: [u8; 32],
    /// Which INCARNATION of this device's login the reattaching handshake
    /// was admitted under ([`Principal::incarnation`]). It REPLACES the
    /// entry's -- see [`Router::rebind`].
    incarnation: u64,
}

/// A bridge's parked notification or final route-custody receipt. Parking
/// retains the task; only Final can settle a revoked route and its cap charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionEndPhase {
    Parked,
    Final,
}

struct SessionEnded {
    phase: SessionEndPhase,
    session_id: u64,
    token: [u8; 16],
    /// Ordinary graceful close versus unexpected death. For a revoked route,
    /// true additionally requires complete exact decisions and final control ACKs;
    /// cancellation/deadline is nondelivery, independently of the Final phase.
    graceful: bool,
}

/// Tell `auth`'s [`LoginSink`] about every login the router ended since the
/// last drain. Private, and paired with each removal below and the completion
/// of a gracefully retained probation: a bare call to a `Router` method that can
/// go through [`Router::forget_backend`] is deliberately NOT enough on its
/// own to reach a call site -- see those wrappers' own docs for why.
fn notify_ended_logins(router: &mut Router, auth: &ServerAuth) {
    for login in router.take_ended_logins() {
        auth.logins.login_ended(login);
    }
}

/// [`Router::on_session_ended`], immediately followed by telling `auth`'s
/// sink about anything it just ended. The two cannot be pulled apart at a
/// call site the way a bare `router.on_session_ended(...)` followed by a
/// separate `notify_ended_logins(...)` line could: this task's own review
/// (finding F1) deleted all three such separate lines and the whole
/// workspace stayed green. Folding the notify into the same function as the
/// operation that can produce one to notify about is what makes that
/// mistake require editing THIS function, not merely trimming a call site.
fn on_session_ended_and_notify(
    router: &mut Router,
    auth: &ServerAuth,
    ended: SessionEnded,
    now: tokio::time::Instant,
) -> Option<[u8; 32]> {
    let client_key = router.on_session_ended(ended, now);
    notify_ended_logins(router, auth);
    client_key
}

/// [`Router::gc_retained`], immediately followed by telling `auth`'s sink --
/// see [`on_session_ended_and_notify`]'s docs for why this pairing exists.
fn gc_retained_and_notify(router: &mut Router, auth: &ServerAuth, now: tokio::time::Instant) {
    router.gc_retained(now);
    notify_ended_logins(router, auth);
}

/// [`Router::admit_new_backend`] for `token`'s brand-new login, followed by
/// telling `auth`'s sink about every login this one decision ended -- see
/// [`on_session_ended_and_notify`]'s docs for why the operation and the
/// notify share one body.
///
/// TWO things can end a login here, which is why this wrapper is shaped
/// around the whole decision rather than around the eviction alone:
///
/// - Admission EVICTED somebody's oldest retained backend to make room.
///   [`Router::forget_backend`] accumulated that one; the drain forwards it.
/// - Admission REFUSED (every candidate is live, at this owner's own cap or
///   the daemon-wide one). Then `token`'s own login is over before it began,
///   and nothing else will ever say so: the client's proof already created
///   this login's entry in the system mode's helper (`Request::Verify`, one
///   round trip earlier), no backend will ever exist for `token`, and
///   `forget_backend` -- the only other thing that reports a login ended --
///   can never fire for a token that never had an entry. Unreported, that
///   entry sits in the PRIVILEGED process keeping its account verified, and
///   256 of them refuse every new login on the daemon. The helper also
///   expires such an entry on its own (`qshd`'s `LOGIN_GRACE`), so this is
///   the prompt half of a belt-and-braces pair rather than the only
///   defence -- but this is the one path that is KNOWN to discard a proven
///   admission, and it should not have to wait out a timeout.
///
/// Safe precisely here and nowhere else on this path: a refused
/// `ColdCreate` means the table holds NO entry for `token`
/// ([`Router::resolve`] answers `ColdCreate` only when `backends` has none),
/// so this can never end somebody else's login -- unlike the
/// `refuse_foreign_owner` arms, where the token belongs to its rightful
/// owner and reporting it ended would cut THEM off.
fn admit_new_backend_or_end_login(
    router: &mut Router,
    auth: &ServerAuth,
    owner: u32,
    token: LoginId,
) -> bool {
    let admitted = router.admit_new_backend(owner);
    notify_ended_logins(router, auth);
    if !admitted {
        auth.logins.login_ended(token);
    }
    admitted
}

/// The multi-session manager. Stateless handle; `serve` runs the loop.
pub struct SessionManager;

/// Transfer a secret to its future before the first poll. This deliberately
/// runs outside an async body: cancellation before polling must also wipe it.
fn with_owned_secret<T, F, Fut>(secret: T, run: F) -> impl Future<Output = Fut::Output>
where
    T: Zeroize,
    F: FnOnce(Zeroizing<T>) -> Fut,
    Fut: Future,
{
    let secret = Zeroizing::new(secret);
    async move { run(secret).await }
}

impl SessionManager {
    /// Run the session router on `socket`. On a `HandshakeInit` -- plain or
    /// behind a cookie -- that the return-address check lets through (see
    /// the module doc), run [`Connection::accept`] against `auth` (a
    /// snapshot of its allowlist, and its signature policy if one is
    /// configured) and `server_priv`.
    ///
    /// On the ALLOWLIST path the handshake is itself the proof, so the
    /// accepted connection goes straight to [`SessionManager::apply_decision`]:
    /// cold-create a session -- spawn the backend (`factory`) and a per-session
    /// bridge, register the token and `session_id` in the [`Router`] table --
    /// or reattach/replace an existing one, then send msg2.
    ///
    /// On the SIGNATURE path it is not: `AuthPolicy::SshSignature` admits any
    /// static key, so the accepted connection goes into PROBATION instead (see
    /// [`crate::probation`]). Only its datagram route is registered; the
    /// backend table is untouched until the client's record on
    /// [`crate::auth::AUTH_STREAM`] verifies, at which point the SAME decision
    /// arms run against the table as it stands then.
    ///
    /// A `Transport` datagram is forwarded to the session (or probation) task
    /// whose `session_id` matches, and dropped if none. Ended sessions are
    /// reclaimed via the completion channel, drained in the same `select!` so
    /// the socket loop never blocks; ending a session also scrubs its
    /// `client_key` off `auth.allowlist`, so the
    /// allowlist is self-cleaning.
    ///
    /// `login_ends` is where something OUTSIDE the router says a login is
    /// over for good -- the system mode's privileged helper, and nothing
    /// else; see [`LoginEndedReporter`]. Every other server passes
    /// [`LoginEndedReports::none()`], which never yields.
    ///
    /// Never returns on its own: it runs until the task is canceled.
    /// Captures an erasing key owner at the call, including before first poll.
    pub fn serve(
        socket: Arc<UdpSocket>,
        server_priv: [u8; 32],
        auth: ServerAuth,
        factory: BackendFactory,
        active_count: Arc<AtomicUsize>,
        login_ends: LoginEndedReports,
    ) -> impl Future<Output = ()> + Send {
        // Capture the erasing key owner synchronously, even if never polled.
        let future = Self::serve_until_shutdown(
            socket,
            server_priv,
            auth,
            factory,
            active_count,
            login_ends,
            Shutdown::default(),
        );
        async move {
            // Legacy callers cancel this never-ending future. Cancellation is not
            // a joined cleanup receipt; daemon STOP uses the explicit API below.
            let _ = future.await;
        }
    }

    /// Stop accepting input on a sticky request and retain every registered
    /// task until it completes. Backend completion must itself own any process
    /// or blocking-I/O obligations; this API cannot invent those receipts.
    /// The returned Send future owns the key before its first poll; dropping
    /// it then or after cancellation erases this owner's array, not caller
    /// copies or snow's internal key buffers.
    pub fn serve_until_shutdown(
        socket: Arc<UdpSocket>,
        server_priv: [u8; 32],
        auth: ServerAuth,
        factory: BackendFactory,
        active_count: Arc<AtomicUsize>,
        login_ends: LoginEndedReports,
        shutdown: Shutdown,
    ) -> impl Future<Output = Result<(), ShutdownError>> + Send {
        with_owned_secret(server_priv, move |server_priv| {
            Self::serve_with_secret(
                socket,
                server_priv,
                auth,
                factory,
                active_count,
                login_ends,
                shutdown,
            )
        })
    }

    async fn serve_with_secret(
        socket: Arc<UdpSocket>,
        server_priv: Zeroizing<[u8; 32]>,
        auth: ServerAuth,
        factory: BackendFactory,
        active_count: Arc<AtomicUsize>,
        mut login_ends: LoginEndedReports,
        shutdown: Shutdown,
    ) -> Result<(), ShutdownError> {
        let lifecycle = Lifecycle::new(shutdown.clone());
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let mut router = Router::new();
        // Per-session tasks signal their end here; the router holds `done_tx`
        // for the whole loop (cloned into each task), so `done_rx` never
        // completes with `None` and its select arm always matches `Some`.
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        // Probation tasks signal their outcome here, on the same pattern.
        let (probation_tx, mut probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        // Periodic GC of retained-then-abandoned backends. The first tick fires
        // immediately (a no-op with no retained entries yet). Built only by
        // `gc_timer`: the one-pass reprieve depends on how it treats missed
        // ticks.
        let mut gc = gc_timer();
        let ctx = ManagerCtx {
            lifecycle: lifecycle.clone(),
            socket: &socket,
            server_priv: &server_priv,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        loop {
            // One ready datagram cannot postpone a sticky stop to another
            // turn. Keep ordinary arms fair under sustained input.
            if shutdown.is_requested() {
                break;
            }
            tokio::select! {
                _ = shutdown.requested() => break,
                _ = lifecycle.next(), if !lifecycle.is_empty() => {}
                recv = socket.recv_from(&mut buf) => {
                    let (len, src) = match recv {
                        Ok(v) => v,
                        // Receive error -- the socket is still alive, skip this
                        // datagram.
                        Err(_) => continue,
                    };
                    Self::handle_datagram(&ctx, &mut router, len, src, &buf).await;
                }
                Some(ended) = done_rx.recv() => {
                    // A session end (graceful teardown OR
                    // a death/retain) scrubs that connection's key off the
                    // SHARED allowlist -- self-cleaning, so an ended
                    // connection's key never lingers. The sink is notified
                    // as part of the SAME call (see
                    // `on_session_ended_and_notify`'s docs) -- there is no
                    // separate line here to lose.
                    if let Some(client_key) =
                        on_session_ended_and_notify(&mut router, &auth, ended, tokio::time::Instant::now())
                    {
                        remove_from_allowlist(&auth.allowlist, &client_key);
                    }
                }
                Some(ended) = probation_rx.recv() => {
                    Self::on_probation_ended(&ctx, &mut router, ended).await;
                }
                Some((login, incarnation)) = login_ends.recv() => {
                    // No `_and_notify` pairing here, and that is the point:
                    // this login's end came FROM the sink those wrappers
                    // report to. See `Router::end_login`.
                    router.end_login(login, incarnation);
                }
                _ = gc.tick() => {
                    gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
                }
            }
        }

        // No new manager admission can publish from this point. Every task
        // capable of registering a descendant already owns a registered slot.
        // Route removal wakes probation; shutdown reaches parked bridges and
        // backends independently of transport input or a full bounded queue.
        let mut logins: std::collections::HashSet<_> = router.backends.keys().copied().collect();
        logins.extend(router.probation.values().map(|seat| seat.login));
        router.sessions.clear();
        router.backends.clear();
        let result = lifecycle.drain().await;
        // Verification that was already dispatched retains real completion
        // custody. Its result cannot create a new backend after shutdown.
        while let Ok(ended) = probation_rx.try_recv() {
            if ended
                .proven
                .as_ref()
                .is_none_or(|proven| matches!(proven.msg1.method, AuthMethod::Allowlist))
            {
                auth.nonces.release(ended.nonce);
            }
        }
        for login in logins {
            auth.logins.login_ended(login);
        }
        result
    }

    /// Handle one received datagram against the router table. Split out of the
    /// `select!` arm so the socket-read borrow of `buf` is released before this
    /// runs.
    async fn handle_datagram(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        len: usize,
        src: SocketAddr,
        buf: &[u8],
    ) {
        match parse(&buf[..len]) {
            Ok(Frame::Handshake {
                kind: Kind::KeyRequest,
                ..
            }) => {
                // Answer only a request that carries its own weight (see
                // `KEY_REQUEST_MIN_LEN`); a short one is a spoofing attempt.
                // Reply-RATE throttling is deliberately out of scope: the
                // answer is smaller than the request floor, so there is no
                // volumetric gain in reflecting off it, and nothing else on
                // this path is rate-limited either.
                //
                // And answer only where discovery has a purpose: a signature
                // daemon (`qshd serve`) is met by clients that have never seen
                // its key and cannot build msg1 without it. A daemon without a
                // verifier is the `transport-ensure` one, whose clients were
                // handed the key over SSH -- there the reply would buy nobody
                // anything and hand a port scan an unauthenticated fingerprint
                // of the service.
                if len >= KEY_REQUEST_MIN_LEN && ctx.auth.verifier.is_some() {
                    let reply = encode_handshake(
                        Kind::KeyOffer,
                        &encode_key_offer_body(&ctx.auth.server_pub),
                    );
                    let _ = ctx.socket.send_to(&reply, src).await;
                }
            }
            Ok(Frame::Handshake {
                kind: kind @ (Kind::HandshakeInit | Kind::HandshakeInitCookie),
                body,
            }) => {
                let now = Instant::now();
                // QSH-02/03 (spec §4.16): before any Noise work, nonce or
                // probation seat -- under load, only a msg1 behind a valid
                // cookie goes on; any other gets a 35-byte answer and nothing
                // else. From here on `body` is the Noise msg1 alone, so the
                // retransmit comparison (`ResendMsg2`) and a twin in probation
                // see the same bytes with or without a cookie.
                let seats = router.probation.len();
                let verdict = router.cookies.check(now, src, kind, body, seats);
                // After EVERY check, not only on a reported change: what the
                // log says depends on how long load has been off, too.
                if let Some(line) = router.load_log.note(now, router.cookies.under_load()) {
                    #[cfg(test)]
                    LOAD_LOGGED.with(|l| l.borrow_mut().push(line));
                    if line == LOAD_ON_LINE {
                        log::warn!("{line}");
                    } else {
                        log::info!("{line}");
                    }
                }
                let body = match verdict {
                    Verdict::Handshake { msg1, .. } => msg1,
                    Verdict::Reply(reply) => {
                        let _ = ctx.socket.send_to(&reply, src).await;
                        return;
                    }
                    Verdict::Drop => return,
                };
                // Which policy applies is decided by the method byte inside
                // msg1, which is encrypted: only `accept` can read it. Try the
                // allowlist first (the established path), then the signature
                // policy if this server runs one. `accept` refuses a client
                // whose announced method is not the policy's, so this can
                // never downgrade one path into the other.
                let allowlist = snapshot_allowlist(&ctx.auth.allowlist);
                // The router's decision, taken while `accept` holds the
                // decrypted msg1 -- the only moment the token is readable and
                // msg2 is not yet written. Kept here so the code below uses
                // the SAME decision the client was told about, rather than
                // resolving a second time.
                let mut decision: Option<AcceptDecision> = None;
                // Memoized across BOTH `accept` attempts below (the same
                // closure is passed to each): at most one nonce per
                // handshake, obtained lazily -- only once `accept` has
                // decrypted and parsed msg1 and confirmed the announced
                // method matches the policy being tried, never for a
                // datagram that only LOOKS like a handshake (`wire::parse`
                // classifies any 2-byte `[VERSION, HandshakeInit]` as one).
                // Issuing any earlier would let junk datagrams -- no crypto,
                // no body required -- drain a bounded nonce source with
                // nothing to show for it.
                //
                // The memo itself guards a DIFFERENT, currently unreachable
                // case: `accept` has exactly one call site for `resolve`, so
                // nothing inside `accept` can call it twice for one
                // handshake today. Across the two attempts here, a msg1 that
                // reaches the second attempt's `resolve` already failed the
                // first attempt's KEY or METHOD check -- `admits` or the
                // announced-method comparison, both of which precede
                // `resolve` (see `a_genuine_but_rejected_handshake_issues_no_nonce`,
                // which covers each separately) -- before that attempt's
                // `resolve` ever ran. The memo is cheap insurance against a
                // future call site (inside `accept`, or a second direct
                // `issue()` added here) that stops honoring either
                // invariant -- see
                // `only_one_nonce_is_issued_even_when_both_accept_attempts_run`'s
                // own doc for what it does and does not prove about this.
                let mut issued_nonce: Option<[u8; AUTH_NONCE_LEN]> = None;
                // Set only when `issue()` itself fails, so the `Rejected`
                // arm below can tell "no nonce available" apart from every
                // other rejection reason (bad Noise, wrong method, unknown
                // key), which must stay silent as they always have.
                let mut nonce_failure: Option<String> = None;
                let mut resolve_for_msg2 = |msg1: &Msg1Payload| -> Option<Msg2Resolution> {
                    let d = router.resolve(&msg1.token, body, msg1.start_kind);
                    if matches!(d, AcceptDecision::ResendMsg2) {
                        return Some(Msg2Resolution::Cached);
                    }
                    let resumed = matches!(d, AcceptDecision::WarmReattach);
                    decision = Some(d);
                    let nonce = match issued_nonce {
                        Some(n) => n,
                        None => match ctx.auth.nonces.issue() {
                            Ok(n) => {
                                issued_nonce = Some(n);
                                n
                            }
                            Err(why) => {
                                nonce_failure = Some(why);
                                return None;
                            }
                        },
                    };
                    Some(Msg2Resolution::Fresh(Msg2Inputs { resumed, nonce }))
                };
                // An empty allowlist admits nobody, so that `accept` could
                // only ever reject -- and under `serve` the allowlist is
                // ALWAYS empty, because the signature path owns every client
                // there. Skipping it costs nothing and saves a full Noise
                // `accept` on every handshake, junk datagram included.
                let mut outcome = if allowlist.is_empty() {
                    ResolvedAccept::Rejected
                } else {
                    #[cfg(test)]
                    ACCEPT_ATTEMPTS.with(|n| n.set(n.get() + 1));
                    Connection::accept_resolved(
                        ConnectionConfig {
                            required_features: ctx.factory.0.required_features(),
                            features: crate::Features::SUPPORTED,
                            role: Role::Server,
                            local_static_priv: *ctx.server_priv,
                            remote_static_pub: None,
                            auth: AuthPolicy::Allowlist(allowlist),
                        },
                        now,
                        src,
                        body,
                        &mut resolve_for_msg2,
                    )
                };
                if matches!(outcome, ResolvedAccept::Rejected) && ctx.auth.verifier.is_some() {
                    #[cfg(test)]
                    ACCEPT_ATTEMPTS.with(|n| n.set(n.get() + 1));
                    outcome = Connection::accept_resolved(
                        ConnectionConfig {
                            required_features: ctx.factory.0.required_features(),
                            features: crate::Features::SUPPORTED,
                            role: Role::Server,
                            local_static_priv: *ctx.server_priv,
                            remote_static_pub: None,
                            auth: AuthPolicy::SshSignature,
                        },
                        now,
                        src,
                        body,
                        &mut resolve_for_msg2,
                    );
                }
                match outcome {
                    ResolvedAccept::Cached {
                        client_key: _client_key,
                        msg1,
                    } => {
                        Self::resend_original_msg2(ctx, router, &msg1.token, src).await;
                    }
                    ResolvedAccept::Fresh(AcceptedHandshake {
                        conn,
                        client_key,
                        msg1,
                        out,
                        nonce,
                    }) => {
                        // Taken inside `accept`, above: the same decision the
                        // client was told about in msg2.
                        let decision = decision
                            .expect("an accepted handshake resolved its decision inside `accept`");
                        let Some(revision) = router.revisions.capture(msg1.token) else {
                            ctx.auth.nonces.release(nonce);
                            return;
                        };
                        let admission = Admission {
                            revision,
                            conn,
                            client_key,
                            msg1,
                            msg1_body: body.to_vec(),
                            out,
                            src,
                            // Nothing has been consumed off this connection
                            // yet: whatever it queued is still there for the
                            // probation task to drain under either policy.
                            start: BridgeStart::default(),
                            nonce,
                            // A placeholder on the signature path: it goes
                            // into `begin_probation`, which discards it --
                            // the real principal only exists once the peer
                            // proves itself.
                            principal: ctx.auth.self_principal.clone(),
                            route: None,
                        };
                        // Both policies must prove this fresh responder split
                        // before any backend or existing route is changed.
                        Self::begin_probation(ctx, router, decision, admission).await;
                    }
                    // Validation failed -- no response, no registration. This is
                    // the auth gate: a non-allowlisted key (or bad Noise) never
                    // reaches the reattach/replace decision, so it cannot hijack
                    // an existing token's backend.
                    ResolvedAccept::Rejected => {
                        // Self-healing guard, not a live path today:
                        // `resolve` is the LAST check inside `accept` (see
                        // that function's docs), so nothing after a
                        // successful `issue()` can still return `Rejected`
                        // while that ordering holds -- see
                        // `a_genuine_but_rejected_handshake_issues_no_nonce`
                        // and `junk_datagrams_classified_as_a_handshake_issue_no_nonce`,
                        // which both prove `issued_nonce` stays `None` on
                        // every path that reaches this arm today. It stays
                        // here so a FUTURE check added inside `accept`,
                        // after the hook, cannot silently leak the nonce
                        // that check's `Rejected` would otherwise orphan.
                        if let Some(n) = issued_nonce {
                            ctx.auth.nonces.release(n);
                        }
                        // The ONE exception that needs a word said about
                        // it: a refusal caused by `resolve` itself finding
                        // no nonce available.
                        if let Some(why) = nonce_failure {
                            log::warn!("handshake refused: no nonce available: {why}");
                        }
                    }
                }
            }
            Ok(Frame::Transport { session_id, .. }) => {
                if let Some(tx) = router.sessions.get(&session_id) {
                    // Non-blocking hand-off to the session task, dropped past
                    // the route's bound (spec §4.16, QSH-04) or once the task
                    // has ended; its `SessionEnded` signal (or an
                    // already-drained one) reclaims the entry.
                    let _ = tx.send(src, buf[..len].to_vec());
                }
                // No matching session -- drop.
            }
            // HandshakeResp on the server side, or malformed input from the
            // network -- silently ignored.
            Ok(Frame::Handshake { .. }) => {}
            Err(_) => {}
        }
    }

    /// Put an accepted-but-unproven connection into probation: register its
    /// datagram route so the record can reach it, spawn the task that waits
    /// for that record, and answer msg2.
    ///
    /// `router.backends` is never MUTATED here -- nothing is created, rebound,
    /// replaced or evicted. That is the whole property: an unproven peer never
    /// reaches the code that could disturb somebody else's session. The one
    /// read is the retransmit reply below, which copies a cached msg2 and
    /// changes nothing; it is reachable only for a msg1 byte-identical to the
    /// one that bound the entry, so only the client that bound it (or a
    /// replay of that client's exact bytes, which cannot decrypt the answer)
    /// can provoke it. The token the handshake named is recorded with its
    /// probation seat, and that only ever holds a removal BACK, and boundedly:
    /// a retained backend for that token outlives one more GC pass, or is
    /// evicted after the other retained ones (see [`Router::in_probation`]).
    async fn begin_probation(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        decision: AcceptDecision,
        admission: Admission,
    ) {
        let Admission {
            revision,
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            start: _,
            nonce,
            // Allowlist uses the daemon's principal; signature replaces this
            // placeholder with the verifier's authenticated principal.
            principal,
            route: _,
        } = admission;
        // Early cached responses never construct an Admission. A fresh
        // probation may still become a proven twin before it completes;
        // on_probation_ended re-resolves that distinct race after proof.
        debug_assert!(!matches!(decision, AcceptDecision::ResendMsg2));
        let session_id = conn.session_id();
        // Over the probation cap: drop in silence. Nothing is evicted, because
        // nothing here belongs to anyone yet, and nothing real is reachable
        // from a probation entry to evict. The nonce this refused admission
        // was issued will never be spent either -- release it.
        if !router.admit_probation(session_id, src, msg1.token) {
            ctx.auth.nonces.release(nonce);
            return;
        }
        let policy = match msg1.method {
            AuthMethod::Allowlist => ProofPolicy::Allowlisted { principal },
            AuthMethod::SshSignature => match ctx.auth.verifier.clone() {
                Some(verifier) => ProofPolicy::SshSignature { verifier },
                None => {
                    router.probation.remove(&session_id);
                    ctx.auth.nonces.release(nonce);
                    return;
                }
            },
        };
        // A probation's route is small until its connection is proven
        // (spec §4.16); `cold_create` raises it.
        let (dg_tx, dg_rx) = probation_dgram_queue();
        ctx.lifecycle.spawn(run_probation(Probation {
            socket: ctx.socket.clone(),
            conn,
            policy,
            revision,
            dgram_rx: dg_rx,
            client_key,
            msg1,
            msg1_body,
            out: out.clone(),
            src,
            ended_tx: ctx.probation_tx.clone(),
            // One set of permits for the whole process -- see
            // `MAX_CONCURRENT_VERIFIES`.
            verify_permits: crate::probation::verify_permits(),
            nonce,
        }));
        // Register the ROUTE, and only the route, BEFORE sending msg2 -- so a
        // client that answers instantly is already routable.
        router.sessions.insert(session_id, dg_tx);
        // The client cannot sign this handshake's hash until the handshake
        // completes, so msg2 has to go out ahead of the proof. That is the
        // same cost an unproven cold-create already carried before probation
        // existed.
        send_all(ctx.socket, &out).await;
    }

    /// A probation ended: bind the connection if its peer proved itself, drop
    /// its route if it did not.
    async fn on_probation_ended(ctx: &ManagerCtx<'_>, router: &mut Router, ended: ProbationEnded) {
        let Some(seat) = router.probation.remove(&ended.session_id) else {
            // A completion owns effects only while its probation seat exists.
            // Duplicate/stale results must not remove a route, release another
            // admission's nonce, or bind a connection after retirement.
            return;
        };
        let revision_guard = ended.revision.clone();
        // Bind before retirement cleanup so an adopted helper login remains live.
        Self::apply_probation_result(ctx, router, ended).await;
        let still_ended = router.backends.get(&seat.login).is_some_and(|entry| {
            matches!(
                entry.state,
                EntryState::Retained {
                    reason: RetentionReason::PendingProof,
                    ..
                }
            )
        });
        if still_ended && !router.in_probation(&seat.login) {
            router.forget_backend(seat.login, "graceful close after last probation");
            notify_ended_logins(router, ctx.auth);
        }
        drop(revision_guard);
        router.revisions.prune();
    }

    async fn apply_probation_result(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        ended: ProbationEnded,
    ) {
        // Take the provisional route out of the table but keep it: a cold
        // create adopts this very sender and its queue as the bridge's own
        // route, a warm reattach empties the queue into its `Attach` (spec
        // §4.5). Every other outcome drops it. Nothing between here and those
        // arms awaits, so no datagram can be routed while it is out.
        let provisional = router.sessions.remove(&ended.session_id);
        let proven = match ended.proven {
            Some(proven) => *proven,
            // No record ever verified (a bad/missing one, or the connection
            // closed first): this handshake's nonce will never be spent by
            // a proof now -- release it rather than let it sit in the
            // (Task-7) table for its full lifetime.
            None => {
                ctx.auth.nonces.release(ended.nonce);
                return;
            }
        };
        let ProvenSession {
            revision,
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            start,
            nonce,
            principal,
            dgram_rx,
        } = proven;
        if matches!(msg1.method, AuthMethod::Allowlist) {
            // Fresh key confirmation never consumes the signature nonce.
            // Release it even if authorization or binding later rejects us.
            ctx.auth.nonces.release(nonce);
            if !ctx
                .auth
                .allowlist
                .lock()
                .expect("allowlist mutex")
                .contains(&client_key)
            {
                return;
            }
        }
        // `begin_probation` registered this route and only this method removes
        // it, so a proven probation always finds it. Were it missing, the
        // queue would go with `dgram_rx` below and a cold create would start
        // on an empty route: say so rather than lose it in silence.
        debug_assert!(
            provisional.is_some(),
            "a proven probation lost its provisional route"
        );
        if provisional.is_none() {
            log::warn!(
                "session {:016x}: the proven connection has no provisional route; \
                 datagrams queued during its probation are dropped",
                ended.session_id
            );
        }
        // Resolve AGAIN, against the table as it stands NOW. Probation takes
        // at least a round trip, and in that time this token's entry may have
        // appeared, been replaced, or ended: applying a decision computed
        // against a table that no longer exists would strand a route at best,
        // and at worst reach an arm that assumes an entry which is gone (both
        // `on_session_ended` and `gc_retained` can remove one, and both run in
        // the same `select!` as this signal).
        //
        // There is a FOURTH outcome, which only re-resolution can produce: the
        // entry may have been bound by a msg1 byte-identical to this one --
        // this client's own retransmit twin, which got a probation of its own
        // and proved first. Re-resolution then yields `ResendMsg2`, and that
        // is the right answer: the client is already Live on the session that
        // entry names, so this connection adopts nothing and is dropped, and
        // the cached msg2 goes out in case that is what went missing.
        let decision = router.resolve(&msg1.token, &msg1_body, msg1.start_kind);
        if !revision.is_current() {
            // A verified retransmit twin may reconcile the helper's exact
            // login incarnation, but must never replace the current route.
            if matches!(decision, AcceptDecision::ResendMsg2)
                && router.backends.get(&msg1.token).is_some_and(|entry| {
                    entry.owner == principal.uid && entry.client_key == client_key
                })
            {
                router.note_incarnation(&msg1.token, principal.incarnation);
                Self::resend_original_msg2(ctx, router, &msg1.token, src).await;
            }
            return;
        }
        Self::apply_decision(
            ctx,
            router,
            decision,
            Admission {
                revision,
                conn,
                client_key,
                msg1,
                msg1_body,
                out,
                src,
                start,
                nonce,
                principal,
                route: provisional.map(|tx| ProvisionalRoute { tx, rx: dgram_rx }),
            },
        )
        .await;
    }

    /// Answer a byte-identical msg1 retransmit by REPRODUCING the entry's
    /// ORIGINAL msg2 (same `session_id`) to the client's current address, and
    /// doing nothing else. Idempotent by construction: it reads one cached
    /// value and writes one datagram, so it neither mints a session nor
    /// repoints the client's still-live route (which would wedge it). Also
    /// recovers a first msg2 that went missing, which is why the client sent
    /// the retransmit in the first place.
    ///
    /// Shared by both paths on purpose: the answer to a retransmit must not be
    /// able to drift between an unproven connection and a proven one.
    async fn resend_original_msg2(
        ctx: &ManagerCtx<'_>,
        router: &Router,
        token: &[u8; 16],
        src: SocketAddr,
    ) {
        let msg2 = router
            .backends
            .get(token)
            .expect("entry present")
            .msg2
            .clone();
        let _ = ctx.socket.send_to(&msg2, src).await;
    }

    /// Bind an accepted, PROVEN connection to a backend according to
    /// `decision`. Both authentication policies arrive after successful
    /// probation. `admission.start` carries the events and stream data already
    /// consumed so the bridge can replay them after the session-start event.
    async fn apply_decision(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        decision: AcceptDecision,
        admission: Admission,
    ) {
        let token = admission.msg1.token;
        let new_id = admission.conn.session_id();
        let change = if matches!(decision, AcceptDecision::ResendMsg2) {
            None
        } else {
            let Some(change) = router.revisions.reserve_change() else {
                return;
            };
            Some(change)
        };
        match decision {
            AcceptDecision::ResendMsg2 => {
                // Do NOT adopt this call's fresh conn / new_id -- `admission`
                // is dropped here -- so the route and backend are untouched.
                //
                // Deliberately releases NOTHING here, even though the
                // discarded connection's nonce could look unspent from this
                // arm alone: this same arm is reached from TWO callers with
                // different answers to "will this nonce be spent". The
                // allowlist completion already released its own nonce before
                // reaching here. The signature path
                // (`on_probation_ended`'s re-resolution, the "fourth
                // outcome" of a proven twin) hands in a PROVEN connection
                // whose nonce its proof has just consumed -- releasing it
                // here would be spend-then-release. Neither caller needs
                // anything released at this point; see each caller's own
                // comment for where its nonce is actually accounted for.
                //
                // ONE thing it does take from this admission, because that
                // thing is not about this connection: which life of the
                // device's LOGIN the proof behind it was admitted under.
                // Both twins name the same login, and that login can end
                // and be admitted again between their two probations -- see
                // `Router::note_incarnation`, which is also where the
                // allowlist path's "no incarnation" is kept from
                // overwriting a real one.
                router.note_incarnation(&token, admission.principal.incarnation);
                Self::resend_original_msg2(ctx, router, &token, admission.src).await;
            }
            AcceptDecision::WarmReattach => {
                let Admission {
                    revision,
                    conn,
                    client_key,
                    msg1,
                    msg1_body,
                    out,
                    src,
                    mut start,
                    nonce,
                    // A reattach joins the backend that is already running --
                    // `SessionIo::principal` was set once, at cold-create,
                    // and this slice does not rewrite it (only the fallback
                    // cold-create below, on a raced-out bridge, uses this).
                    principal,
                    route,
                } = admission;
                // Which LIFE of this device's login this handshake was
                // admitted under. Unlike the principal above, this one IS
                // rewritten onto the entry below: the entry must not go on
                // claiming a login that ended while it was retained, or a
                // notice about that login would end the session this
                // reattach is about to revive. Read before `principal`
                // moves into the fallback cold-create.
                let incarnation = principal.incarnation;
                // The token names an entry, but tokens are chosen by clients
                // and authentication does not bind one to an account by
                // itself. Only the owner may come back to a session; anyone
                // else is refused outright rather than handed a fresh
                // session under the same token, which would overwrite what
                // is still running.
                if refuse_foreign_owner(router, &token, principal.uid) {
                    return;
                }
                // Only the early bytes go with the attach. `start.saw_live`
                // stays behind on purpose: the backend was told `Live` by the
                // connection it started on, and a reattach owes it
                // `ResumeReset`, never a second `Live`.
                let early = std::mem::take(&mut start.early);
                // What the peer sent while its proof was checked travels inside
                // the `Attach` (spec §4.5), ahead of anything the bridge reads.
                let queued = route.map(ProvisionalRoute::drain).unwrap_or_default();
                // Hand the new Connection to the still-running bridge. Attach
                // BEFORE repointing the route: every `new_id` datagram routed
                // to the stable channel afterwards finds the `Attach` already
                // queued, and the bridge takes control first (its `biased;`
                // `select!`), so none of them reaches the connection being
                // replaced. That order is what protects them, not the msg2
                // round trip: on the signature path the client got msg2 when
                // its probation began and has been sending `new_id`
                // datagrams since -- the ones sent before now are `queued`.
                let control = router
                    .backends
                    .get(&token)
                    .expect("entry present")
                    .control
                    .clone();
                // Read before the connection moves into the bridge; logged
                // once the attach took (a raced-out bridge falls back to
                // `cold_create`, which logs for itself).
                let features = conn.features();
                let (commit_tx, commit_rx) = oneshot::channel();
                match control.send(BridgeControl::Attach(
                    Box::new(conn),
                    early,
                    queued,
                    commit_rx,
                )) {
                    Ok(()) => {
                        // Bridge is alive. Repoint the datagram route to the
                        // new session_id: the STABLE dgram sender is taken
                        // from wherever it lives (the live `sessions` route,
                        // or the parked slot if the entry was Retained --
                        // reviving a dead-but-held backend) and re-registered
                        // under `new_id`, so the backend keeps running.
                        let dg_tx = router
                            .take_stable_route(&token)
                            .expect("live/retained entry must own its dgram route on reattach");
                        router
                            .revisions
                            .commit(token, change.expect("reserved binding change"));
                        let old_key = router.rebind(
                            &token,
                            Rebind {
                                session_id: new_id,
                                dgram: dg_tx,
                                msg1_body: &msg1_body,
                                msg2: first_bytes(&out),
                                client_key,
                                incarnation,
                            },
                        );
                        // This is the ONLY place a fast
                        // roam (beats DEATH_AFTER) ever sees the superseded
                        // key -- SessionEnded is never emitted for it.
                        scrub_superseded_key(&ctx.auth.allowlist, old_key, client_key);
                        // The bridge may already be runnable on another worker.
                        // Release it only after route/revision/incarnation and key
                        // ownership have all committed, before the first await.
                        if commit_tx
                            .send(CommittedAdmission(AuthAcceptance {
                                session_id: new_id,
                                disposition: SessionDisposition::Resumed,
                            }))
                            .is_err()
                        {
                            // The enqueued envelope owned the Connection, so a
                            // dropped receiver cannot cold-fallback. Retire only
                            // this committed route through normal lifecycle rules.
                            if let Some(key) = on_session_ended_and_notify(
                                router,
                                ctx.auth,
                                SessionEnded {
                                    phase: SessionEndPhase::Final,
                                    session_id: new_id,
                                    token,
                                    graceful: false,
                                },
                                tokio::time::Instant::now(),
                            ) {
                                remove_from_allowlist(&ctx.auth.allowlist, &key);
                            }
                            return;
                        }
                        send_all(ctx.socket, &out).await;
                        log_session_features(new_id, features);
                    }
                    Err(mpsc::error::SendError(BridgeControl::Attach(boxed, early, queued, _))) => {
                        // The bridge already ended (its connection closed just
                        // as this reattach raced in), so its backend is gone
                        // too. Fall back to a clean cold-create -- recovering
                        // the accepted connection AND its early bytes from the
                        // send error -- so the client gets a live session
                        // instead of a route wedged onto a dead bridge. Drop
                        // the stale route first.
                        start.early = early;
                        let old_id = router
                            .backends
                            .get(&token)
                            .expect("entry present")
                            .session_id;
                        router.sessions.remove(&old_id);
                        let old_key = Self::cold_create(
                            ctx,
                            router,
                            change.expect("reserved binding change"),
                            Admission {
                                revision,
                                conn: *boxed,
                                client_key,
                                msg1,
                                msg1_body,
                                out,
                                src,
                                start,
                                nonce,
                                principal,
                                route: Some(ProvisionalRoute::prefilled(queued)),
                            },
                        )
                        .await;
                        scrub_superseded_key(&ctx.auth.allowlist, old_key, client_key);
                    }
                }
            }
            AcceptDecision::ColdReplace => {
                // Tear the old backend down: dropping its dgram sender
                // closes the old bridge's dgram_rx (a Live entry), or
                // overwriting the entry below drops the parked control/dgram
                // senders (a Retained entry); either way the old bridge exits
                // -> its io sender drops -> the old backend future ends. Its
                // later SessionEnded is ignored by `on_session_ended`'s
                // session_id guard, and the cold-create below overwrites the
                // entry. This REPLACES an existing token, so it does not grow
                // the table -- no cap check needed.
                //
                // But it DOES need the same owner check as a warm reattach,
                // and for the same reason: a token proves nothing about
                // whose account it is, so a cold restart from a different
                // account must be refused before it tears anything down.
                if refuse_foreign_owner(router, &token, admission.principal.uid) {
                    return;
                }
                let client_key = admission.client_key;
                let old_id = router
                    .backends
                    .get(&token)
                    .expect("entry present")
                    .session_id;
                router.sessions.remove(&old_id);
                let old_key = Self::cold_create(
                    ctx,
                    router,
                    change.expect("reserved binding change"),
                    admission,
                )
                .await;
                scrub_superseded_key(&ctx.auth.allowlist, old_key, client_key);
            }
            AcceptDecision::ColdCreate => {
                // A brand-new token grows the table: enforce the session
                // caps (this owner's own, and the daemon-wide ceiling). If
                // full, admission evicts the oldest retained backend; if
                // every backend is live, or the owner is already at its own
                // cap, it REJECTS -- no msg2, no entry, drop conn.
                // The sink hears about this decision as part of the SAME
                // call (see `admit_new_backend_or_end_login`'s docs): the
                // login of an evicted backend, and -- on a rejection --
                // THIS token's own login, which the client's proof already
                // created in the helper and which nothing else could ever
                // report as ended.
                if !admit_new_backend_or_end_login(router, ctx.auth, admission.principal.uid, token)
                {
                    return;
                }
                // No prior entry for a brand-new token, so `cold_create`
                // returns `None` here -- this call is a no-op, kept for
                // symmetry/safety rather than special-cased away.
                let client_key = admission.client_key;
                let old_key = Self::cold_create(
                    ctx,
                    router,
                    change.expect("reserved binding change"),
                    admission,
                )
                .await;
                scrub_superseded_key(&ctx.auth.allowlist, old_key, client_key);
            }
        }
    }

    /// Cold-create a fresh session for `token`: start a persistent bridge and
    /// hand it the backend to run, joined by stable io channels, register the
    /// `session_id` and token in the router (overwriting any prior entry --
    /// the caller has already torn the old session's dgram route down for a
    /// cold replace), then send msg2.
    ///
    /// Returns the SUPERSEDED `client_key` of the entry this call overwrote --
    /// `Some` for a cold REPLACE (an entry already
    /// existed for `token`), `None` for a genuine cold CREATE (nothing to
    /// supersede). The caller scrubs the old key off the shared allowlist if
    /// it differs from the new one.
    async fn cold_create(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        change: RevisionChange,
        admission: Admission,
    ) -> Option<[u8; 32]> {
        let Admission {
            revision: _revision,
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src: _,
            start,
            nonce: _,
            principal,
            route,
        } = admission;
        let token = msg1.token;
        let session_id = conn.session_id();
        log_session_features(session_id, conn.features());
        // Captured before `principal` moves into `io` below: the entry
        // records only the uid and the incarnation, `SessionIo` carries the
        // whole `Principal`.
        let owner = principal.uid;
        let incarnation = principal.incarnation;
        // SessionIo channel pair (bridge <-> backend), stable for the backend's
        // whole life (it survives warm reattaches).
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        // The send gates live as long as the io: across every warm reattach.
        let gates = Arc::new(GateTable::new());
        let io = SessionIo {
            lifecycle: ctx.lifecycle.clone(),
            control: OnceLock::new(),
            resume_snapshots: channel_bridge::SnapshotMailbox::default(),
            inbound: in_rx,
            outbound: out_tx,
            principal,
            // `token` is exactly the router's own key for this device (see
            // `LoginId`'s docs) -- copied, not moved, since `BridgeSpawn`
            // below and `router.backends.insert` further down both still
            // need it.
            login: token,
            gates: Arc::clone(&gates),
        };

        let admission_owner = io.control().clone();
        // Stable datagram route + control channel into the persistent bridge.
        // A proven probation's route becomes the bridge's own: same sender
        // under the same `session_id`, same queue, nothing lost in between.
        let (dg_tx, dg_rx) = match route {
            Some(ProvisionalRoute { tx, rx }) => {
                // Proven: a bridge's route, not a probation's (spec §4.16).
                rx.raise_bound(DGRAM_QUEUE_BYTES);
                (tx, rx)
            }
            None => dgram_queue(),
        };
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        // Register BEFORE sending msg2, so a fast client reply is routable the
        // instant it arrives.
        router.sessions.insert(session_id, dg_tx);
        router.revisions.commit(token, change);
        let superseded = router.backends.insert(
            token,
            BackendEntry {
                admission: admission_owner,
                session_id,
                control: ctl_tx,
                last_msg1_body: msg1_body,
                msg2: first_bytes(&out),
                client_key,
                state: EntryState::Live,
                parked_dgram: None,
                owner,
                incarnation,
            },
        );
        // No backend callback or bridge scheduling precedes the synchronous
        // route, revision and backend registration above.
        spawn_committed_bridge(BridgeSpawn {
            socket: ctx.socket.clone(),
            committed: CommittedAdmission(AuthAcceptance {
                session_id: conn.session_id(),
                disposition: SessionDisposition::Fresh,
            }),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx: ctx.done_tx.clone(),
            },
            token,
            backend: ctx.factory.0.clone(),
            io,
            start,
            active_count: ctx.active_count.clone(),
            gates,
        });

        send_all(ctx.socket, &out).await;
        superseded.map(|e| e.client_key)
    }
}

/// The manager's ambient wiring: everything a decision arm needs that is not
/// about the particular connection being bound. Borrowed for the life of
/// `serve`, so the per-datagram path passes ONE reference instead of seven.
struct ManagerCtx<'a> {
    lifecycle: Arc<Lifecycle>,
    socket: &'a Arc<UdpSocket>,
    server_priv: &'a [u8; 32],
    auth: &'a ServerAuth,
    factory: &'a BackendFactory,
    done_tx: &'a mpsc::UnboundedSender<SessionEnded>,
    probation_tx: &'a mpsc::UnboundedSender<ProbationEnded>,
    active_count: &'a Arc<AtomicUsize>,
}

/// An accepted handshake carried through probation and into the decision arms.
/// Both policies need fresh transport-key confirmation before a decision arm;
/// the signature policy additionally needs a verified authentication record.
struct Admission {
    revision: BindingRevision,
    conn: Connection,
    client_key: [u8; 32],
    msg1: Msg1Payload,
    /// The exact msg1 body, for the retransmit-idempotency comparison.
    msg1_body: Vec<u8>,
    /// The msg2 datagrams `accept` produced.
    out: Vec<Datagram>,
    /// The address the handshake arrived from.
    src: SocketAddr,
    /// What a probation stage already consumed off this connection, for the
    /// bridge to replay. Either policy may already have received early events.
    start: BridgeStart,
    /// The nonce carried in msg2. Signature probation verifies a record against
    /// it; allowlist probation never spends it and releases it on completion.
    nonce: [u8; AUTH_NONCE_LEN],
    /// Who this connection belongs to. On the allowlist path this is
    /// `ServerAuth::self_principal` from acceptance, but binding still waits
    /// for fresh transport proof. On the signature path the value set here
    /// is a placeholder that `begin_probation` discards: the real value
    /// only exists once probation succeeds, and arrives via
    /// `ProvenSession::principal` when a fresh `Admission` is built for it
    /// in `on_probation_ended`.
    principal: Principal,
    /// The completed probation's route and queue (see [`ProvisionalRoute`]).
    /// Both policies populate it after proof; it is absent before probation.
    route: Option<ProvisionalRoute>,
}

/// A probation's route, handed on with its proven connection (spec §4.5):
/// the sender the router used for it and the queue behind that sender.
struct ProvisionalRoute {
    tx: DgramTx,
    rx: DgramRx,
}

impl ProvisionalRoute {
    /// Everything in the queue, in order. Only the manager task sends into a
    /// route, and the caller has taken this one out of the table, so nothing
    /// can arrive after this returns.
    fn drain(self) -> Vec<(SocketAddr, Vec<u8>)> {
        let ProvisionalRoute { tx, mut rx } = self;
        drop(tx);
        let mut queued = Vec::new();
        while let Some(d) = rx.try_recv() {
            queued.push(d);
        }
        queued
    }

    /// A fresh route whose queue already holds `queued`, in order.
    fn prefilled(queued: Vec<(SocketAddr, Vec<u8>)>) -> ProvisionalRoute {
        let (tx, rx) = dgram_queue();
        for (src, bytes) in queued {
            let _ = tx.send(src, bytes);
        }
        ProvisionalRoute { tx, rx }
    }
}

/// Whether `token`'s existing entry belongs to someone other than `caller`.
/// Called from `apply_decision`'s `WarmReattach`/`ColdReplace` arms, both of
/// which reach this only when `resolve` has already established the entry
/// exists -- so a missing entry here would mean the table changed underneath
/// the caller, which nothing in this crate does between resolving a decision
/// and applying it.
///
/// A refusal is logged through the same lifecycle logging a refused
/// probation uses, so an operator can see it, and leaves the entry
/// completely untouched: the caller's job is to bail out before touching
/// anything, never to create a fresh session under a token that still names
/// one -- that would overwrite a session that is still running.
fn refuse_foreign_owner(router: &Router, token: &[u8; 16], caller: u32) -> bool {
    let owner = router.backends.get(token).expect("entry present").owner;
    if owner == caller {
        return false;
    }
    log::warn!("session refused: token belongs to uid {owner}, caller is uid {caller}");
    true
}

/// The wire bytes of the first datagram of a handshake reply, cloned. `accept`
/// always yields exactly one (the HandshakeResp); an empty slice yields empty
/// bytes, which a retransmit would harmlessly re-send as nothing.
fn first_bytes(out: &[Datagram]) -> Vec<u8> {
    out.first().map(|d| d.bytes.clone()).unwrap_or_default()
}

/// Take a snapshot of the live allowlist for one handshake. A poisoned mutex
/// (a writer panicked mid-update) must not crash the whole daemon: recover the
/// inner list and proceed with it -- the allowlist is a plain set of keys, so
/// a partial write leaves it usable.
fn snapshot_allowlist(shared_allowlist: &SharedAllowlist) -> Vec<[u8; 32]> {
    match shared_allowlist.lock() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Scrubs `key` off the shared allowlist, called when a
/// session ends OR is superseded by a warm reattach/cold replace with a
/// different key (see `scrub_superseded_key`). Mirrors the poisoned-mutex
/// recovery of the handshake-time snapshot in `handle_datagram`: a writer
/// panicking mid-update must not crash the whole daemon, so a poisoned
/// lock's inner value is recovered and used. Removal is BY VALUE, which is
/// sound because of `SharedAllowlist`'s uniqueness invariant (see its doc):
/// no other live session can be authenticated with this same key.
fn remove_from_allowlist(shared_allowlist: &SharedAllowlist, key: &[u8; 32]) {
    match shared_allowlist.lock() {
        Ok(mut guard) => guard.retain(|k| k != key),
        Err(poisoned) => poisoned.into_inner().retain(|k| k != key),
    }
}

/// After a warm reattach or cold replace supersedes an existing entry's
/// `client_key` with a NEW one, scrub the OLD key off the shared allowlist --
/// UNLESS it's the SAME key the new connection also authenticated with (the
/// common case: a device reusing its persistent static key across an
/// ephemeral-only reconnect), in which case the new connection still needs
/// it allowlisted and it must NOT be removed. `old_key` is `None` for a pure
/// cold create (no entry existed to supersede) -- a no-op. This is the fix
/// for the gap a plain `SessionEnded`-driven scrub misses: a fast roam that
/// beats the old connection's `DEATH_AFTER` never emits `SessionEnded` for
/// the superseded session at all (`rebind`/`cold_create`'s in-place
/// overwrite is the ONLY place that ever sees the old key again).
fn scrub_superseded_key(
    shared_allowlist: &SharedAllowlist,
    old_key: Option<[u8; 32]>,
    new_key: [u8; 32],
) {
    if let Some(old_key) = old_key {
        if old_key != new_key {
            remove_from_allowlist(shared_allowlist, &old_key);
        }
    }
}

/// Make `conn` one this bridge drives: a proven peer's cap on out-of-order
/// data instead of probation's (spec §4.16), every stream counted explicitly
/// (see `ConsumptionLedger`) but the proof's, and every class the backend
/// declared, which a connection a warm reattach brings never heard (spec
/// §4.8). Called for the connection a bridge starts with and for every one
/// an `Attach` brings.
fn adopt_connection(conn: &mut Connection, classes: &BTreeMap<u8, StreamClass>) {
    // Binding/revision checks committed this admission. Restore roaming before
    // processing traffic queued while the actual proof was being verified.
    conn.admit_source_migration();
    // Every stream is counted when the bridge says its backend took the
    // bytes (spec §4.10.3) -- but the proof's: it never reaches a backend,
    // and is taken as it is read.
    conn.set_default_consumption(Consumption::Explicit);
    conn.set_stream_consumption(AUTH_STREAM, Consumption::OnDelivery);
    conn.set_undelivered_cap(crate::conn::UNDELIVERED_CAP);
    for (stream_id, class) in classes {
        conn.set_stream_class(*stream_id, *class);
    }
}

/// A control message from the manager, applied to the bridge's connection.
///
/// `Attach` is a warm reattach: swap in the new connection and reset the
/// backend's per-connection state. `first_live_sent` stays true (no second
/// `Live`); the manager sends the new connection's msg2 itself. This also
/// REVIVES a parked (retained) backend. The bridge's `drain_events` after the
/// wake-up drains the new connection's queued events, and its gate refresh
/// opens every gate (the new connection holds no tails).
enum AttachResult {
    Applied,
    Cancelled,
    Rejected(u64),
}

async fn apply_control(
    conn: &mut Connection,
    parked: &mut bool,
    link: &mut BackendLink,
    control: BridgeControl,
    classes: &BTreeMap<u8, StreamClass>,
    now: Instant,
    out: &mut Vec<Datagram>,
) -> AttachResult {
    let BridgeControl::Attach(mut new_conn, early, queued, commit) = control;
    let Ok(committed) = commit.await else {
        // The manager abandoned admission before committing it. Nothing in the
        // existing attachment, its ledger or its backend has changed.
        return AttachResult::Cancelled;
    };
    if committed.0.session_id != new_conn.session_id() {
        return AttachResult::Cancelled;
    }
    if new_conn.features().contains(crate::Features::AUTH_ACCEPTED) {
        let Some(datagrams) = committed.enqueue(&mut new_conn, Instant::now()) else {
            return AttachResult::Rejected(new_conn.session_id());
        };
        out.extend(datagrams);
    }
    // What this bridge handed its backend off the replaced connection and
    // the backend has not yet reported is owed to it (spec §4.10.3): its
    // late reports must not credit the new one. Not `conn`'s own
    // `unconsumed_streams()` -- a connection can hold `StreamData` events
    // that were never drained to the backend (review Important 1, fix round
    // 1: two `Attach`es applied back to back on one `on_routed_datagram`
    // turn skip `drain_events` between them).
    link.channel_output.observe_discards(conn);
    link.ledger.carry();
    link.channel_output.attach(conn, link.ledger.generation());
    *conn = *new_conn;
    // Destruction of the old Connection is the exact wire-custody boundary.
    // Release its ledger before ResumeReset can wake the backend to reserve
    // the new snapshot. Future effect/FIFO owners remain independently held.
    synchronize_control_delivery(conn, link.ledger.generation(), &mut link.control_delivery);
    // The new connection has heard none of this session's declarations of
    // class; recoverability the backend declares again on `ResumeReset`.
    // Before the queued datagrams below: an ACK among them may already let
    // a stream send, and it must go by its class. Before them too, the
    // proven peer's cap on out-of-order data replaces probation's.
    adopt_connection(conn, classes);
    *parked = false;
    let context = AttachmentContext::for_connection(conn, link.ledger.generation());
    link.hand_over(conn, now, SessionInbound::ResumeReset(context), out);
    // Then whatever the new peer had already sent before it was bound here --
    // after the reset, never before it.
    for sd in early {
        link.hand_over(conn, now, SessionInbound::Data(sd), out);
    }
    // And the datagrams it sent while its proof was checked, through the new
    // connection, before anything from the stable route.
    for (src, bytes) in queued {
        out.extend(conn.on_datagram(now, src, &bytes));
    }
    AttachResult::Applied
}

/// A backend's declaration of `stream_id`'s class: applied to `conn` now,
/// and kept in `classes`, because a warm reattach brings a connection that
/// never heard it (`apply_control` declares the kept ones again). The
/// interactive class is every stream's default on a new connection, so
/// declaring it -- a channel gone, its stream back to where it started --
/// forgets the stream instead of keeping it.
fn declare_class(
    conn: &mut Connection,
    classes: &mut BTreeMap<u8, StreamClass>,
    stream_id: u8,
    class: StreamClass,
) {
    if class == StreamClass::Interactive {
        classes.remove(&stream_id);
    } else {
        classes.insert(stream_id, class);
    }
    conn.set_stream_class(stream_id, class);
}

/// A datagram the manager routed to this bridge.
///
/// Any `Attach` already queued is applied FIRST. The bridge's `biased;`
/// `select!` orders its polls, not the arrivals: on the daemon's multi-thread
/// runtime the bridge can find the control channel empty, the manager then
/// sends `Attach`, re-homes the route and routes a datagram of the new
/// session, and the inner `select!` takes that datagram. Its send happened
/// after the `Attach`'s and receiving it synchronizes with that send, so the
/// `try_recv` here is guaranteed to see the `Attach`; without it the datagram
/// would reach the connection being replaced, which drops it for its
/// `session_id`. A closed control channel is left to the `select!`, which
/// sees it on its next turn.
///
/// A closed (parked) connection is deaf: `on_datagram` returns empty, so this
/// is a harmless no-op until a revive.
#[allow(clippy::too_many_arguments)]
async fn on_routed_datagram(
    conn: &mut Connection,
    parked: &mut bool,
    control_rx: &mut mpsc::UnboundedReceiver<BridgeControl>,
    link: &mut BackendLink,
    classes: &BTreeMap<u8, StreamClass>,
    now: Instant,
    src: SocketAddr,
    bytes: &[u8],
    out: &mut Vec<Datagram>,
) -> AttachResult {
    while let Ok(control) = control_rx.try_recv() {
        if let rejected @ AttachResult::Rejected(_) =
            apply_control(conn, parked, link, control, classes, now, out).await
        {
            return rejected;
        }
    }
    out.extend(conn.on_datagram(now, src, bytes));
    AttachResult::Applied
}

struct PendingControl {
    // None is a retained accepted-operation outcome, bound only on enqueue.
    origin: Option<AttachmentContext>,
    bytes: Vec<u8>,
    delivery: ControlDelivery,
    committed: Option<tokio::sync::oneshot::Sender<()>>,
}

fn synchronize_control_delivery(
    conn: &Connection,
    generation: u64,
    ledger: &mut crate::control_budget::ControlLedger,
) {
    let stream = crate::channel::CONTROL_STREAM;
    if ledger.generation() != generation {
        // The old Connection's representation was actually destroyed. Future
        // effect owners remain elsewhere; replacing this ledger refunds none.
        *ledger = crate::control_budget::ControlLedger::new(
            generation,
            conn.stream_progress(stream).queued,
        );
    }
    let progress = conn.stream_progress(stream);
    ledger.acknowledge(generation, progress.queued.saturating_sub(progress.unacked));
}

fn drain_reserved_control(
    conn: &mut Connection,
    generation: u64,
    pending: &mut VecDeque<PendingControl>,
    ledger: &mut crate::control_budget::ControlLedger,
    parked: bool,
    now: Instant,
    out: &mut Vec<Datagram>,
) {
    synchronize_control_delivery(conn, generation, ledger);
    let stream = crate::channel::CONTROL_STREAM;
    while let Some(item) = pending.pop_front() {
        if item.origin.is_some_and(|origin| {
            origin.generation != generation || origin.session_id != conn.session_id()
        }) {
            continue;
        }
        if parked {
            if item.origin.is_none() {
                pending.push_front(item);
                break;
            }
            continue;
        }
        let start = conn.stream_progress(stream).queued;
        match conn.try_send_consuming_bounded(
            now,
            stream,
            item.bytes,
            crate::control_budget::SESSION_BYTES,
        ) {
            Ok(datagrams) => {
                let progress = conn.stream_progress(stream);
                if let Some(charge) = item.delivery.charge {
                    charge.transfer(progress.unacked);
                }
                assert!(
                    ledger
                        .register(generation, start, progress.queued, item.delivery.part)
                        .is_ok(),
                    "whole control enqueue and reserved length diverged"
                );
                #[cfg(test)]
                CONTROL_RELIABLE_PEAK.with(|peak| peak.set(peak.get().max(progress.unacked)));
                out.extend(datagrams);
                // Whole reliable enqueue commits acceptance; this is not ACK.
                if let Some(committed) = item.committed {
                    let _ = committed.send(());
                }
            }
            Err((crate::conn::SendBlocked::WouldBlock, bytes)) => {
                pending.push_front(PendingControl { bytes, ..item });
                break;
            }
            Err((reason, bytes)) => {
                pending.push_front(PendingControl { bytes, ..item });
                if reason == crate::conn::SendBlocked::OffsetSpaceExhausted {
                    conn.abandon();
                }
                break;
            }
        }
    }
}

/// Both mailbox wake paths validate the actual target before retiring debt.
fn apply_terminal_request(
    conn: &mut Connection,
    generation: u64,
    budget: &crate::control_budget::SessionBudget,
    request: TerminalRequest,
    now: Instant,
    out: &mut Vec<Datagram>,
) {
    if request.origin.session_id != conn.session_id() || request.origin.generation != generation {
        return;
    }
    budget.retire();
    out.extend(match request.disposition {
        TerminalDisposition::Close => conn.close(now),
        TerminalDisposition::ResourceExhausted => {
            conn.abort_session(now, crate::SessionAbortReason::ResourceExhausted)
        }
    });
}

const INTAKE_RECORDS: usize = 32;
const INTAKE_BYTES: usize = 64 * 1024;

/// One original queue owner, never a reconstructed/rebound message. EOF is
/// deferred too: the accepted prefix gets its normal service turn first.
enum PendingBackend {
    Item(SessionOutbound),
    Eof,
}

struct DataIntake {
    origin: AttachmentContext,
    stream: u8,
    instance: crate::channel_geometry::ChannelInstance,
    records: usize,
    bytes: usize,
}
impl DataIntake {
    fn new(message: &SessionOutbound) -> Option<Self> {
        let SessionOutbound::ChannelOutput {
            origin,
            stream,
            instance,
            output: ChannelOutput::Data(data),
            ..
        } = message
        else {
            return None;
        };
        Some(Self {
            origin: *origin,
            stream: *stream,
            instance: *instance,
            records: 1,
            bytes: data.len().checked_add(5)?,
        })
    }
    fn take_next(
        &mut self,
        receiver: &mut mpsc::UnboundedReceiver<SessionOutbound>,
        held: &mut Option<PendingBackend>,
    ) -> Option<SessionOutbound> {
        // In particular an oversized original first item retains its existing
        // one-message path, with no speculative read of a successor.
        if held.is_some() || self.records >= INTAKE_RECORDS || self.bytes >= INTAKE_BYTES {
            return None;
        }
        let message = match receiver.try_recv() {
            Ok(message) => message,
            Err(mpsc::error::TryRecvError::Empty) => return None,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                *held = Some(PendingBackend::Eof);
                return None;
            }
        };
        let cost = match &message {
            SessionOutbound::ChannelOutput {
                origin,
                stream,
                instance,
                output: ChannelOutput::Data(data),
                ..
            } if *origin == self.origin && *stream == self.stream && *instance == self.instance => {
                data.len()
                    .checked_add(5)
                    .and_then(|cost| self.bytes.checked_add(cost))
            }
            _ => None,
        };
        if let Some(bytes) = cost.filter(|bytes| *bytes <= INTAKE_BYTES) {
            self.bytes = bytes;
            self.records += 1;
            Some(message)
        } else {
            *held = Some(PendingBackend::Item(message));
            None
        }
    }
}

#[derive(Default)]
struct IntakeReadiness {
    shutdown: bool,
    control: bool,
    retiring: bool,
    terminal: bool,
    datagram: bool,
    drain: bool,
    inbound: bool,
    fenced: bool,
    deadline: Option<Instant>,
}
impl IntakeReadiness {
    fn allows(&self, now: Instant) -> bool {
        !(self.shutdown
            || self.control
            || self.retiring
            || self.terminal
            || self.datagram
            || self.drain
            || self.inbound
            || self.fenced
            || self.deadline.is_some_and(|deadline| now >= deadline))
    }
}

/// What woke the persistent bridge loop.
enum Wakeup {
    /// An incoming datagram routed from the manager (`None` = router gone).
    Dgram(Option<(SocketAddr, Vec<u8>)>),
    /// A core timer fired.
    Timeout,
    /// One coalesced continuation after a finite channel-output drain turn.
    Drain,
    /// The fixed terminal mailbox became ready, independent of stream room.
    Terminal,
    /// The backend produced an outbound message -- data or a declaration
    /// (`None` = backend finished).
    Backend(Option<SessionOutbound>),
    /// A held item is taken only after this existing inner-select arm wins.
    DeferredBackend,
    /// A control message from the manager (`None` = the entry was dropped).
    Control(Option<BridgeControl>),
    /// The backend took what waited for it.
    Room(Vec<Handed>),
}

/// Readiness only for a held owner: cancellation cannot take it. Receiver
/// admission remains cancel-safe when no lookahead exists.
async fn backend_wakeup(
    held: bool,
    receiver: &mut mpsc::UnboundedReceiver<SessionOutbound>,
) -> Wakeup {
    if held {
        Wakeup::DeferredBackend
    } else {
        Wakeup::Backend(receiver.recv().await)
    }
}

/// The channels joining a bridge to the manager and to its backend, for the
/// backend's whole life. Bundled because they are one wiring harness: a
/// bridge is never built with some of them.
struct BridgeChannels {
    /// Datagrams routed to this session by the manager.
    dgram_rx: DgramRx,
    /// Inbound events to the backend. Bounded; the bridge does not wait on
    /// it below `PENDING_CAP` -- see `Inbound`.
    io_inbound_tx: mpsc::Sender<SessionInbound>,
    /// The backend's outbound messages: stream data, and declarations of
    /// recoverability and class.
    backend_out_rx: mpsc::UnboundedReceiver<SessionOutbound>,
    /// Warm reattaches from the manager.
    control_rx: mpsc::UnboundedReceiver<BridgeControl>,
    /// This bridge's end-of-session signal back to the manager.
    done_tx: mpsc::UnboundedSender<SessionEnded>,
}

/// Everything a bridge task is started with.
struct BridgeSpawn {
    socket: Arc<UdpSocket>,
    committed: CommittedAdmission,
    /// The FIRST connection this bridge drives; swappable thereafter.
    conn: Connection,
    channels: BridgeChannels,
    token: [u8; 16],
    /// The backend and its io handle: one cohesive pair, moved into the
    /// backend task at the top of the bridge and gone thereafter, so "spawned
    /// exactly once" is a fact about the types rather than a convention.
    backend: Arc<dyn SessionBackend>,
    io: SessionIo,
    /// What a probation stage already consumed off `conn`, replayed to the
    /// backend before anything else. Empty on the allowlist path.
    start: BridgeStart,
    active_count: Arc<AtomicUsize>,
    /// The session's send gates; the backend's io holds the same table.
    gates: Arc<GateTable>,
}

#[cfg(test)]
thread_local! {
    static POLL_COLD_BRIDGE_INLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn spawn_committed_bridge(spawn: BridgeSpawn) {
    let lifecycle = spawn.io.lifecycle.clone();
    #[cfg(test)]
    if POLL_COLD_BRIDGE_INLINE.with(|flag| flag.get()) {
        let mut future = Box::pin(run_backend_bridge(spawn));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        if future.as_mut().poll(&mut context).is_pending() {
            lifecycle.spawn(future);
        }
        return;
    }
    lifecycle.spawn(run_backend_bridge(spawn));
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct MailboxTurn {
    backend_data: bool,
    backend_eof: bool,
    setup_barrier: bool,
    setup_error: Option<&'static str>,
    setup_deadline: Option<Instant>,
    write_room: usize,
    flushes: usize,
    datagrams: usize,
}
#[cfg(test)]
struct MailboxObservation {
    token: LoginId,
    idle_until: Instant,
    turns: Arc<Mutex<Vec<MailboxTurn>>>,
}
#[cfg(test)]
thread_local! {
    // Current-thread fixture, scoped to one authenticated login. Observation
    // neither pauses nor changes selection, admission, draining or flushing.
    static MAILBOX_TURNS: std::cell::RefCell<Option<MailboxObservation>> = const { std::cell::RefCell::new(None) };
}

/// The PERSISTENT per-backend bridge task: it owns ONE backend's io channels
/// for the backend's whole life and drives a SWAPPABLE `Connection`. A cold
/// create starts it with the first accepted connection; a warm reattach sends
/// [`BridgeControl::Attach`] with a new connection, which the bridge swaps in
/// BEFORE emitting [`SessionInbound::ResumeReset`] -- the backend keeps
/// running.
///
/// That order is deliberate, not incidental, to make it clear that the two
/// operations form a unit. The single-threaded event loop processes backend
/// replies only on its next iteration, after both lines have executed
/// regardless of their order (see the `Wakeup::Backend` arm below, `conn.send`/
/// `conn.set_stream_resyncable`). Documenting this sequence prevents the
/// question from arising for the next reader.
///
/// Probation has already verified fresh possession and any required signature.
/// The bridge must additionally wait for the manager's committed admission
/// permission before adopting a warm connection. It queues explicit acceptance
/// before handing Live, ResumeReset or early input to the backend.
///
/// Send gates (spec §4.7.2). The bridge refreshes the session's send gates
/// (`crate::send_gate`) at the end of every turn from its connection's
/// stream tails -- while parked it opens them all at the end of every turn
/// instead; in between, bytes a backend hands over count against a gate
/// until the bridge takes them, and can close it -- and tells a screen
/// channel whose gate just opened with [`SessionInbound::Writable`]. What a
/// backend sent that the bridge has not taken yet counts on the gate too:
/// from [`SessionIo::send`] until `take_backend_data`. A
/// stream's class ([`SessionOutbound::StreamClass`]) it keeps and declares
/// again to the connection each warm reattach brings. A backend's
/// [`SessionOutbound::NotifyDelivered`] it answers with
/// [`SessionInbound::Delivered`] once that stream's tail is empty, checked at
/// the end of every turn like the gates -- at once after an `Attach`, never
/// while parked.
///
/// The bridge does not wait for its backend (spec §4.10.2): what the backend's
/// queue has no room for waits in order in the bridge and goes as room
/// opens, and the bridge meanwhile reads datagrams, answers PINGs and runs
/// its timers. Its size is bounded per stream by the stream's credit window
/// and per session by `PENDING_CAP`: past that the bridge waits for the
/// backend, as every build before credits did (spec §4.10.5, §4.10.7). On a
/// graceful end what waits still goes to the backend, in order, before its
/// queue closes (`BackendLink::finish`).
///
/// Lifecycle. When the current connection reaches `Closed`:
/// - GRACEFUL (a received `Close`): signal `SessionEnded{graceful:true}` and
///   EXIT immediately -- dropping the io channels ends the backend once it
///   has read what was delivered (`BackendLink::finish` hands it what still
///   waits in the bridge, then closes its queue).
/// - DEATH (`DEATH_AFTER` liveness timeout): signal `SessionEnded{graceful:false}`
///   and PARK -- the bridge keeps its channels (so the backend keeps running)
///   and waits on `control_rx` for either a warm `Attach` (revive) or the entry
///   being dropped (GC / cap eviction / cold replace / shutdown -> `None` ->
///   exit). This is what keeps a retained backend alive across a death so a
///   later warm reattach can revive it.
///
/// Otherwise ended by the manager dropping the datagram/control channels (cold
/// replace or shutdown -> `Dgram(None)` / `Control(None)`): it signals
/// `SessionEnded` for its CURRENT `session_id`; `on_session_ended`'s session_id
/// guard makes a stale end-signal from a swapped-out/replaced connection
/// harmless (and a teardown-exit never matches, so it never wrongly retains).
async fn run_backend_bridge(spawn: BridgeSpawn) {
    let BridgeSpawn {
        socket,
        committed,
        mut conn,
        channels,
        token,
        backend,
        io,
        start,
        active_count,
        gates,
    } = spawn;
    let BridgeChannels {
        mut dgram_rx,
        io_inbound_tx,
        mut backend_out_rx,
        mut control_rx,
        done_tx,
    } = channels;

    let now = Instant::now();
    let mut out = Vec::new();
    if conn.features().contains(crate::Features::AUTH_ACCEPTED) {
        let Some(datagrams) = committed.enqueue(&mut conn, now) else {
            let _ = done_tx.send(SessionEnded {
                phase: SessionEndPhase::Final,
                session_id: conn.session_id(),
                token,
                graceful: false,
            });
            return;
        };
        out.extend(datagrams);
    }

    // Fixed before the backend runs (spec §4.10.3): who says when its
    // stream bytes are consumed.
    let consumption = backend.consumption();
    // The backend runs for the bridge's whole life. `io` is MOVED into it and
    // is not `Clone`, so there is no second spawn to guard against.
    let resume_snapshots = io.resume_snapshots.clone();
    let lifecycle = io.lifecycle.clone();
    let control = io.control().clone();
    let control_budget = control.budget.clone();
    io.set_control_origin(AttachmentContext::for_connection(&conn, 0));
    lifecycle.spawn(async move { backend.run(io).await });
    let mut link = BackendLink::new(io_inbound_tx, consumption);
    link.channel_output.snapshots = resume_snapshots;
    let mut pending_control = VecDeque::new();
    link.control_delivery = crate::control_budget::ControlLedger::new(
        0,
        conn.stream_progress(crate::channel::CONTROL_STREAM).queued,
    );
    let mut backend_finished = false;
    let mut retirement_barrier = None;

    // `first_live_sent` is BRIDGE-level, spanning every connection this
    // backend drives: a reattach never re-sends `Live` (it sends
    // `ResumeReset` instead), and the backend outlives connection swaps.
    let mut first_live_sent = false;
    // Guarded off once the control sender is dropped (entry removed), so a
    // `recv()` returning `None` can't busy-loop.
    let mut control_open = true;
    // `true` after an unexpected death: the connection is `Closed` and the
    // bridge is holding the backend open, waiting on `control_rx` for a warm
    // reattach (revive) or teardown.
    let mut parked = false;
    // This bridge's contribution to the shared active-session count (see
    // `ACTIVE_WINDOW` / `is_active`): `true` once it has added itself in.
    // Never `true` before the loop below runs its first recompute, so the
    // early-return below never needs to decrement.
    let mut was_active = false;
    // Every class the backend declared: a class, like a recoverability
    // declaration, lives on `conn`, and a warm reattach brings a connection
    // that never heard it (`apply_control` declares these again).
    let mut classes: BTreeMap<u8, StreamClass> = BTreeMap::new();
    // Streams the backend waits to hear are delivered, in the order it
    // asked (see `take_delivered`).
    let mut awaiting_delivery: Vec<(u8, u64)> = Vec::new();
    let mut drain_pending = false;
    // A proven connection: probation's cap does not follow it here.
    adopt_connection(&mut conn, &classes);

    // Replay what a probation stage consumed off this connection before the
    // bridge got it. ORDER: the backend hears its session started before any
    // byte of it, exactly as it would have from the drain below.
    if start.saw_live {
        first_live_sent = true;
        let context = AttachmentContext::for_connection(&conn, link.ledger.generation());
        link.hand_over(&mut conn, now, SessionInbound::Live(context), &mut out);
    }
    for sd in start.early {
        link.hand_over(&mut conn, now, SessionInbound::Data(sd), &mut out);
    }

    // `accept` already queued HandshakeDone + StateChanged(Live): flush them so
    // the backend gets its first `Live` before any data. A close here is
    // degenerate (a fresh accept is Live), so just end.
    let first = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);
    send_all(&socket, &out).await;
    match first {
        CloseKind::None => {}
        kind => {
            let _ = done_tx.send(SessionEnded {
                phase: SessionEndPhase::Final,
                session_id: conn.session_id(),
                token,
                graceful: matches!(kind, CloseKind::Graceful),
            });
            return;
        }
    }

    let mut held_backend = None;
    loop {
        if control.retiring() {
            link.inbound.revoke();
        }
        // While parked the connection is `Closed` (deaf, no timers), so poll
        // without a timeout.
        let retirement_deadline = control.retirement_deadline();
        let next = match (
            if parked { None } else { conn.next_timeout() },
            retirement_deadline,
        ) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let timer = async move {
            match next {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
                }
                None => std::future::pending::<()>().await,
            }
        };
        // Control FIRST, on every turn (`biased;`): after a warm reattach the
        // manager sends `Attach` and only then routes the new connection's
        // datagrams into `dgram_rx`, so whenever one of those is ready the
        // `Attach` is ready too -- and must win, or the datagram goes to the
        // connection being replaced, which drops it for its `session_id`.
        // `biased;` orders the polls only; across worker threads the datagram
        // arm closes the rest (`on_routed_datagram` takes a queued `Attach`
        // first). A control message is rare and each is taken once, so it cannot
        // starve the rest. The rest stay in an unordered inner `select!`:
        // neither a datagram flood nor a backend that never pauses can
        // starve the other, and the timers run after every wake-up anyway
        // (below), whichever arm won.
        let wakeup = tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => break,
            c = control_rx.recv(), if control_open => Wakeup::Control(c),
            _ = control.terminal_ready.notified() => Wakeup::Terminal,
            _ = control.retire_bridge.notified() => Wakeup::Timeout,
            w = async {
                tokio::select! {
                    d = dgram_rx.recv() => Wakeup::Dgram(d),
                    _ = timer => Wakeup::Timeout,
                    w = backend_wakeup(held_backend.is_some(), &mut backend_out_rx), if !backend_finished && !link.channel_output.receive_fenced() => w,
                    _ = std::future::ready(()), if drain_pending => Wakeup::Drain,
                    // Room in the backend's queue for what waits (spec
                    // §4.10.2): the bridge never stands on its backend.
                    h = link.inbound.room(), if link.inbound.has_pending() => Wakeup::Room(h),
                }
            } => w,
        };

        let wakeup = match wakeup {
            Wakeup::DeferredBackend => Wakeup::Backend(match held_backend.take() {
                Some(PendingBackend::Item(message)) => Some(message),
                Some(PendingBackend::Eof) => None,
                None => unreachable!("held readiness selected without its owner"),
            }),
            other => other,
        };
        #[cfg(test)]
        let mailbox_backend_data = matches!(
            &wakeup,
            Wakeup::Backend(Some(SessionOutbound::ChannelOutput {
                output: ChannelOutput::Data(_),
                ..
            }))
        );
        #[cfg(test)]
        let mailbox_backend_eof = matches!(&wakeup, Wakeup::Backend(None));
        #[cfg(test)]
        let mailbox_setup_barrier = match &wakeup {
            Wakeup::Dgram(Some((_, bytes))) => conn.peek_frames(bytes).is_some_and(|frames| {
                frames.iter().any(|frame| {
                    matches!(frame, crate::reliability::StreamFrame::Ping { token: 305 })
                })
            }),
            _ => false,
        };
        let now = Instant::now();
        let mut out: Vec<Datagram> = Vec::new();
        // Screen streams whose gate opened on this turn before the refresh
        // at its end: that refresh finds them open already, and would not
        // say so.
        let mut writable: Vec<u8> = Vec::new();

        if retirement_deadline.is_some_and(|deadline| now >= deadline) {
            log::warn!("revoked session retirement ended without acknowledged refusal delivery");
            out.extend(conn.close(now));
            send_all(&socket, &out).await;
            break;
        }
        match wakeup {
            Wakeup::DeferredBackend => unreachable!("held owner normalized before dispatch"),
            Wakeup::Backend(Some(SessionOutbound::RetirementReady {
                origin,
                decisions_complete,
            })) => {
                if decisions_complete
                    && origin.session_id == conn.session_id()
                    && origin.generation == link.ledger.generation()
                {
                    retirement_barrier = Some(origin);
                    backend_finished = true;
                    #[cfg(test)]
                    CONTROL_RETIREMENT_BARRIER.with(|barrier| barrier.set(Some(origin)));
                } else if control.retiring() {
                    log::warn!("revoked session retirement lacks complete decisions for its exact attachment");
                    out.extend(conn.close(now));
                    send_all(&socket, &out).await;
                    break;
                }
            }
            Wakeup::Terminal => {
                if let Some(request) = control.take_priority_abort() {
                    apply_terminal_request(
                        &mut conn,
                        link.ledger.generation(),
                        &control_budget,
                        request,
                        now,
                        &mut out,
                    );
                }
            }
            Wakeup::Backend(Some(SessionOutbound::ReservedControl {
                origin,
                bytes,
                delivery,
            })) => {
                pending_control.push_back(PendingControl {
                    origin: Some(origin),
                    bytes,
                    delivery,
                    committed: None,
                });
            }
            Wakeup::Backend(Some(SessionOutbound::UpdateAccept {
                origin,
                bytes,
                delivery,
                committed,
            })) => {
                pending_control.push_back(PendingControl {
                    origin: Some(origin),
                    bytes,
                    delivery,
                    committed: Some(committed),
                });
            }
            Wakeup::Backend(Some(SessionOutbound::ReservedSessionControl { bytes, delivery })) => {
                pending_control.push_back(PendingControl {
                    origin: None,
                    bytes,
                    delivery,
                    committed: None,
                });
            }
            Wakeup::Backend(Some(
                message @ (SessionOutbound::ResourceExhausted { .. }
                | SessionOutbound::CloseSession { .. }),
            )) => {
                let fallback = match message {
                    SessionOutbound::ResourceExhausted { origin } => TerminalRequest {
                        origin,
                        disposition: TerminalDisposition::ResourceExhausted,
                    },
                    SessionOutbound::CloseSession { origin } => TerminalRequest {
                        origin,
                        disposition: TerminalDisposition::Close,
                    },
                    _ => unreachable!(),
                };
                // One signal consumes the latest origin/disposition together.
                // Validate before retirement: stale signals cannot poison the
                // replacement's budget or change its terminal classification.
                let request = control.take_abort(fallback);
                apply_terminal_request(
                    &mut conn,
                    link.ledger.generation(),
                    &control_budget,
                    request,
                    now,
                    &mut out,
                );
            }
            // Takes any `Attach` already queued first (see `on_routed_datagram`).
            Wakeup::Dgram(Some((src, bytes))) => {
                if let AttachResult::Rejected(session_id) = on_routed_datagram(
                    &mut conn,
                    &mut parked,
                    &mut control_rx,
                    &mut link,
                    &classes,
                    now,
                    src,
                    &bytes,
                    &mut out,
                )
                .await
                {
                    let _ = done_tx.send(SessionEnded {
                        phase: SessionEndPhase::Final,
                        session_id,
                        token,
                        graceful: false,
                    });
                    break;
                }
            }
            // The manager dropped the datagram channel -- shut the backend down.
            Wakeup::Dgram(None) => break,
            // Nothing of its own: the timers run after every wake-up, below.
            Wakeup::Timeout | Wakeup::Drain => {}
            Wakeup::Backend(Some(
                message @ (SessionOutbound::ChannelOutput { .. }
                | SessionOutbound::ChannelExit { .. }
                | SessionOutbound::ChannelClosed { .. }
                | SessionOutbound::ResumeSnapshotReady
                | SessionOutbound::RepaintBarrier { .. }),
            )) => {
                if conn.features().contains(crate::Features::CHANNEL_GEOMETRY) {
                    let mut intake = DataIntake::new(&message);
                    link.channel_output.push(message);
                    link.channel_output.seal_ended(&mut conn);
                    if let Some(intake) = intake.as_mut() {
                        loop {
                            let readiness = IntakeReadiness {
                                shutdown: lifecycle.shutdown.is_requested(),
                                control: !control_rx.is_empty()
                                    || (control_open && control_rx.is_closed()),
                                retiring: control.retiring(),
                                terminal: control.has_priority_abort(),
                                datagram: dgram_rx.has_ready(),
                                drain: drain_pending,
                                inbound: link.inbound.has_pending(),
                                fenced: link.channel_output.receive_fenced(),
                                deadline: conn.next_timeout(),
                            };
                            if !readiness.allows(Instant::now()) {
                                break;
                            }
                            let Some(message) =
                                intake.take_next(&mut backend_out_rx, &mut held_backend)
                            else {
                                break;
                            };
                            // Preserve the original position, origin, charge and
                            // permits. push also advances snapshot-prefix custody;
                            // the next iteration must recheck receive_fenced.
                            link.channel_output.push(message);
                            link.channel_output.seal_ended(&mut conn);
                        }
                    }
                } else {
                    log::error!("typed channel output without negotiated geometry profile");
                    out.extend(conn.close(now));
                }
            }
            Wakeup::Backend(Some(SessionOutbound::ProtocolFailure { origin, code })) => {
                if origin.session_id == conn.session_id()
                    && origin.generation == link.ledger.generation()
                {
                    if let Some(code) = code {
                        out.extend(conn.send(
                            now,
                            crate::channel::CONTROL_STREAM,
                            &crate::channel::encode_server(
                                &crate::channel::ServerRecord::ProtocolError { code },
                            ),
                        ));
                    }
                    out.extend(conn.close(now));
                }
            }
            Wakeup::Backend(Some(
                message @ (SessionOutbound::ChannelOpened { .. }
                | SessionOutbound::ChannelRefused { .. }),
            )) => {
                let (origin, record) = match message {
                    SessionOutbound::ChannelOpened { stream, origin } => {
                        (origin, crate::channel::ServerRecord::Opened { stream })
                    }
                    SessionOutbound::ChannelRefused {
                        stream,
                        origin,
                        reason,
                    } => (
                        origin,
                        crate::channel::ServerRecord::Refused { stream, reason },
                    ),
                    _ => unreachable!(),
                };
                if origin.generation == link.ledger.generation()
                    && origin.session_id == conn.session_id()
                {
                    if !conn.features().contains(crate::Features::CHANNEL_GEOMETRY) {
                        out.extend(conn.close(now));
                    } else {
                        writable.extend(take_backend_data(
                            &mut conn,
                            &gates,
                            parked,
                            now,
                            StreamData {
                                stream_id: crate::channel::CONTROL_STREAM,
                                data: crate::channel::encode_server(&record),
                            },
                            &mut out,
                        ));
                    }
                }
            }
            Wakeup::Backend(Some(SessionOutbound::Data(sd))) => {
                writable.extend(take_backend_data(
                    &mut conn, &gates, parked, now, sd, &mut out,
                ));
            }
            // A declaration is metadata on `conn`, not a datagram -- there is
            // nothing to withhold from a parked (closed) connection the way
            // `Data` withholds bytes above, so it is always applied.
            Wakeup::Backend(Some(SessionOutbound::Resyncable {
                stream_id,
                resyncable,
            })) => {
                conn.set_stream_resyncable(stream_id, resyncable);
                link.channel_output.declare(stream_id, resyncable);
            }
            // Like a recoverability declaration, metadata on `conn`, and
            // always applied; kept by the bridge as well (see `declare_class`).
            // Deliberately NOT a signal to the ledger (fix round 3, review
            // round 2 finding A): a channel's LAST reports -- of bytes it
            // drops rather than delivers -- arrive from a different
            // producer, AFTER this declaration, and forgetting the
            // stream's ledger debt here would misattribute them to
            // whoever reuses the number. See `ConsumptionLedger`'s own doc.
            Wakeup::Backend(Some(SessionOutbound::StreamClass { stream_id, class })) => {
                declare_class(&mut conn, &mut classes, stream_id, class);
            }
            // Everything the backend sent on the stream before this is in
            // `conn` by now (the channel is FIFO); the end of the turn says
            // when it is acknowledged.
            Wakeup::Backend(Some(SessionOutbound::NotifyDelivered { stream_id, token })) => {
                #[cfg(test)]
                if stream_id == crate::channel::CONTROL_STREAM {
                    CONTROL_PRODUCER_FENCE.with(|fence| fence.set(Some(token)));
                }
                awaiting_delivery.push((stream_id, token));
            }
            // What the backend took (spec §4.10.3): paid to the connection
            // that delivered it (see `ConsumptionLedger`).
            Wakeup::Backend(Some(SessionOutbound::Consumed { stream_id, n })) => {
                link.ledger.reported(&mut conn, now, stream_id, n, &mut out);
            }
            // Backend EOF ends admission but is not a delivery receipt. The
            // receiver is disabled thereafter, so pending ACK debt cannot spin.
            Wakeup::Backend(None) => {
                if control.retiring()
                    && retirement_barrier
                        != Some(AttachmentContext::for_connection(
                            &conn,
                            link.ledger.generation(),
                        ))
                {
                    log::warn!("revoked session retirement ended without an exact admitted-decision barrier");
                    out.extend(conn.close(now));
                    send_all(&socket, &out).await;
                    break;
                }
                backend_finished = true;
                #[cfg(test)]
                CONTROL_BACKEND_EOF.with(|count| count.set(count.get() + 1));
            }
            // Warm reattach (see `apply_control`); also revives a parked bridge.
            Wakeup::Control(Some(control)) => {
                if let AttachResult::Rejected(session_id) = apply_control(
                    &mut conn,
                    &mut parked,
                    &mut link,
                    control,
                    &classes,
                    now,
                    &mut out,
                )
                .await
                {
                    let _ = done_tx.send(SessionEnded {
                        phase: SessionEndPhase::Final,
                        session_id,
                        token,
                        graceful: false,
                    });
                    break;
                }
            }
            // What waited for the backend went to it: booked to the
            // connections that delivered it (see `ConsumptionLedger`).
            Wakeup::Room(handed) => {
                link.took(&mut conn, now, handed, &mut out);
            }
            // The entry's control sender was dropped (GC / cap eviction / cold
            // replace / shutdown): stop polling this arm. If parked, this is the
            // teardown signal -- exit; otherwise the bridge still exits via
            // `Dgram(None)`.
            Wakeup::Control(None) => {
                control_open = false;
                if parked {
                    break;
                }
            }
        }

        // Intake can cross a real deadline. Dispatch used its original time;
        // timer, event, output-drain and gate service use the actual fresh time.
        let now = Instant::now();
        drain_reserved_control(
            &mut conn,
            link.ledger.generation(),
            &mut pending_control,
            &mut link.control_delivery,
            parked,
            now,
            &mut out,
        );

        // Timers after EVERY wake-up (spec §4.1): a datagram, the backend's
        // output or a control message can be ready on every turn, and a fresh
        // sleep in `select!` is not guaranteed to win against them. A parked
        // connection is `Closed` and has no timers.
        out.extend(conn.on_timeout_if_due(now));
        // Delivered bytes go to the backend -- and what it is counted as
        // taking may send a CREDIT -- before this turn's datagrams go out.
        let mut closed = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);
        // A hot Reset changes framing before any queued channel bytes may be
        // admitted. Its event must reach the typed owner before this drain.
        #[cfg(test)]
        let mailbox_before = (
            conn.flush_calls_for_test(),
            conn.stream_write_room(16, 64 * 1024),
            out.len(),
        );
        drain_pending =
            link.channel_output
                .drain(&mut conn, now, parked, &mut out, &mut link.control_delivery);
        #[cfg(test)]
        MAILBOX_TURNS.with(|slot| {
            if let Some(observer) = slot
                .borrow()
                .as_ref()
                .filter(|observer| observer.token == token)
            {
                let setup_error = if mailbox_setup_barrier {
                    conn.postpone_idle_for_test(observer.idle_until).err()
                } else {
                    None
                };
                observer.turns.lock().unwrap().push(MailboxTurn {
                    backend_data: mailbox_backend_data,
                    backend_eof: mailbox_backend_eof,
                    setup_barrier: mailbox_setup_barrier,
                    setup_error,
                    setup_deadline: mailbox_setup_barrier.then(|| conn.next_timeout()).flatten(),
                    write_room: mailbox_before.1,
                    flushes: conn.flush_calls_for_test() - mailbox_before.0,
                    datagrams: out.len() - mailbox_before.2,
                });
            }
        });
        // Typed admission can discover permanent offset exhaustion. Observe its
        // abandonment in this turn so parking never waits for another event.
        if matches!(closed, CloseKind::None) && conn.state() == LinkState::Closed {
            closed = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);
        }
        send_all(&socket, &out).await;
        out.clear();
        // Past the per-session cap the bridge waits for its backend, as
        // before credits (spec §4.10.5, §4.10.7); below it this returns at
        // once.
        tokio::select! {
            biased;
            _ = lifecycle.shutdown.requested() => break,
            _ = link.wait_below_pending_cap(&control, &mut conn, &mut out) => {}
        }
        if !out.is_empty() {
            send_all(&socket, &out).await;
            out.clear();
        }

        // Maintain this bridge's contribution to the shared active-session
        // count. Parked (dead, retained) sessions never count. The recompute
        // runs on every wakeup; the ping timer fires ~every `PING_INTERVAL`
        // while Live/PathDown, so an active->inactive transition is noticed
        // within ~`ACTIVE_WINDOW` + a tick.
        let now_active = !parked && is_active(conn.idle_duration(Instant::now()));
        if now_active != was_active {
            if now_active {
                active_count.fetch_add(1, Ordering::SeqCst);
            } else {
                active_count.fetch_sub(1, Ordering::SeqCst);
            }
            was_active = now_active;
        }

        let retirement_delivered = retirement_barrier
            == Some(AttachmentContext::for_connection(
                &conn,
                link.ledger.generation(),
            ))
            && pending_control.is_empty()
            && link.control_delivery.is_empty();
        if backend_finished && pending_control.is_empty() && link.control_delivery.is_empty() {
            // EOF becomes graceful only after admitted control delivery settles.
            // A parked connection is already Closed, so close remains a no-op.
            out.extend(conn.close(now));
            send_all(&socket, &out).await;
            deactivate(&mut was_active, &active_count);
            let _ = done_tx.send(SessionEnded {
                phase: SessionEndPhase::Final,
                session_id: conn.session_id(),
                token,
                graceful: !control.retiring() || retirement_delivered,
            });
            link.finish(lifecycle.clone());
            return;
        }

        match closed {
            CloseKind::None => {}
            CloseKind::Graceful => {
                // Immediate teardown: signal graceful and EXIT (dropping the io
                // channels ends the backend once it has read what was
                // delivered: `finish` hands it what still waits first).
                // Withdraw this bridge's contribution to the active count
                // before it stops recomputing.
                deactivate(&mut was_active, &active_count);
                let _ = done_tx.send(SessionEnded {
                    phase: SessionEndPhase::Final,
                    session_id: conn.session_id(),
                    token,
                    graceful: !control.retiring() || retirement_delivered,
                });
                link.finish(lifecycle.clone());
                return;
            }
            CloseKind::Death => {
                // Unexpected death: signal retain (once) and PARK, keeping the
                // backend alive for a possible warm reattach.
                if !parked {
                    parked = true;
                    // Withdraw this bridge's contribution to the active count
                    // RIGHT NOW, not on the next recompute: once parked, the
                    // connection is deaf (no timers), so nothing wakes the
                    // loop to run the recompute again until a warm reattach
                    // revives it -- without this, a session that was active
                    // at the moment it died would leak a phantom "active"
                    // count until GC eviction (`RETAIN_AFTER_DEATH`, up to an
                    // hour). `deactivate` is idempotent with the normal
                    // recompute above: once `was_active` is `false` here, the
                    // next recompute's `!parked` check finds `now_active ==
                    // was_active == false` and is a no-op, so there is no
                    // double-decrement.
                    deactivate(&mut was_active, &active_count);
                    let _ = done_tx.send(SessionEnded {
                        phase: SessionEndPhase::Parked,
                        session_id: conn.session_id(),
                        token,
                        graceful: false,
                    });
                }
            }
        }

        // Send gates after every wake-up (spec §4.7.2): a datagram's ACKs
        // shrink tails, the backend's output grows them, an `Attach` brings a
        // connection with none. Last on the turn, after `drain_events`, so a
        // bridge that just parked opens its gates now: once parked nothing
        // wakes it -- no timers, and a producer behind a closed gate sends
        // nothing -- until a reattach. A screen gate that just opened tells
        // its channel, which repaints if it dropped output.
        if conn.features().contains(crate::Features::CHANNEL_GEOMETRY) {
            link.channel_output.refresh(&conn, parked);
            // Geometry pipes retain pending bytes and frozen tails while parked.
            writable.extend(gates.refresh(|stream| conn.stream_progress(stream).unacked));
        } else {
            writable.extend(refresh_gates(&gates, &conn, parked));
        }
        for event in link.channel_output.notifications() {
            link.hand_over(&mut conn, now, event, &mut out);
        }
        for stream in writable {
            link.hand_over(
                &mut conn,
                now,
                SessionInbound::Writable { stream },
                &mut out,
            );
        }
        // Deliveries, by the same tails and for the same reason at the end:
        // an ACK in this turn may complete one, and after an `Attach` (whose
        // `ResumeReset` went first) every one is complete.
        for (stream, token) in take_delivered(&mut awaiting_delivery, &conn, parked) {
            link.hand_over(
                &mut conn,
                now,
                SessionInbound::Delivered {
                    stream,
                    token,
                    generation: link.ledger.generation(),
                },
                &mut out,
            );
        }
        // `Writable` and `Delivered` carry no stream bytes, so nothing is
        // counted and nothing is sent -- unless that changes.
        if !out.is_empty() {
            send_all(&socket, &out).await;
        }
    }

    // Exited via a manager teardown (`Dgram(None)` / parked `Control(None)`).
    if lifecycle.shutdown.is_requested() {
        gates.close_all();
    }
    // Withdraw this bridge's contribution to the active count -- `deactivate`
    // is a no-op here if a prior exit point (graceful close, or parking on
    // death) already cleared it.
    deactivate(&mut was_active, &active_count);
    // Signal the end; `on_session_ended`'s guard makes it harmless if the entry
    // was already evicted/replaced (it won't match, so it neither reclaims a
    // live entry nor wrongly re-retains). A send error means the router is
    // already gone (shutdown), which is fine.
    let _ = done_tx.send(SessionEnded {
        phase: SessionEndPhase::Final,
        session_id: conn.session_id(),
        token,
        graceful: false,
    });
}

/// Why (and whether) the connection closed while draining its events.
enum CloseKind {
    /// Still open.
    None,
    /// A `StreamFrame::Close` was received: a graceful shutdown -> tear the
    /// backend down at once.
    Graceful,
    /// Closed via the `DEATH_AFTER` liveness timeout (an unexpected death) ->
    /// retain the backend for a warm reconnect.
    Death,
}

/// Drain the connection's events after an `on_datagram`/`on_timeout`/`send`:
/// hand delivered stream bytes and the first `Live` to the backend through
/// `link`, which counts what is handed over (spec §4.10.3). Returns how the
/// connection closed, if it did -- read from `Connection::closed_gracefully`
/// so the bridge can choose immediate teardown vs retention.
fn drain_events(
    conn: &mut Connection,
    link: &mut BackendLink,
    first_live_sent: &mut bool,
    now: Instant,
    out: &mut Vec<Datagram>,
) -> CloseKind {
    let mut closed = false;
    let mut exhausted = false;
    link.channel_output.observe_discards(conn);
    for ev in conn.poll_events() {
        match ev {
            Event::StreamData { stream_id, data } => {
                if stream_id == AUTH_STREAM {
                    // The authentication stream belongs to the session layer
                    // and NEVER reaches a backend. Anything still arriving on
                    // it here is a stray record from an already-proven peer
                    // (the proof itself was consumed in probation): drop it,
                    // do not hand a backend bytes addressed to the transport.
                    // It is counted as read (`adopt_connection`).
                    continue;
                }
                link.hand_over(
                    conn,
                    now,
                    SessionInbound::Data(StreamData { stream_id, data }),
                    out,
                );
            }
            Event::StateChanged(LinkState::Live) => {
                if !*first_live_sent {
                    *first_live_sent = true;
                    let context = AttachmentContext::for_connection(conn, link.ledger.generation());
                    link.hand_over(conn, now, SessionInbound::Live(context), out);
                }
            }
            Event::StateChanged(LinkState::Closed) => {
                closed = true;
            }
            Event::OutputResync => {
                // Server-side: output was desynced during a long absence and
                // the client just returned -- tell the backend to repaint the
                // current screen, WITHOUT resetting per-connection echo/tty
                // accounting (unlike `ResumeReset`; see `SessionInbound::Repaint`).
                if conn.features().contains(crate::Features::CHANNEL_GEOMETRY) {
                    if !link.channel_output.hot_reset() {
                        exhausted = true;
                    }
                } else {
                    link.hand_over(conn, now, SessionInbound::Repaint, out);
                }
            }
            Event::OffsetSpaceExhausted { stream_id } => {
                log::warn!(
                    "session {}: stream {stream_id} reached the end of its offset space; \
                     dropping the connection so the client reconnects",
                    conn.session_id()
                );
                exhausted = true;
            }
            Event::SendBufferOverCap { stream_id } => {
                #[cfg(test)]
                OVER_CAP_LOGGED.with(|n| n.set(n.get() + 1));
                log::warn!(
                    "session {}: stream {stream_id}: send buffer over the hard cap, \
                     a producer ignores its send gate",
                    conn.session_id()
                );
            }
            // `Event::StreamReset { .. }` and `Event::UnofferedFeatureEnabled
            // { .. }` are client-side only -- never observed here on the
            // server's bridge.
            _ => {}
        }
    }
    if exhausted {
        // Without a `Close` (spec §4.14): read as a death, so the bridge parks
        // and the session is retained for the client's warm return. The
        // `StateChanged(Closed)` this queues says nothing new -- dropped here.
        conn.abandon();
        let _ = conn.poll_events();
        closed = true;
    }
    if !closed {
        CloseKind::None
    } else if conn.closed_gracefully() {
        CloseKind::Graceful
    } else {
        CloseKind::Death
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many hard-cap reports `drain_events` logged on this
    /// thread. The log line is all that arm does, and a test cannot tell it
    /// from the `_ => {}` fallback below it otherwise.
    static OVER_CAP_LOGGED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    /// Test-only: the per-session features lines logged on this thread.
    static SESSION_FEATURES_LOGGED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many `Connection::accept` calls `handle_datagram` made
    /// on this thread -- the Noise work handshake datagrams cost.
    static ACCEPT_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    /// Test-only: the load lines (`LOAD_ON_LINE`, `LOAD_OFF_LINE`)
    /// `handle_datagram` logged on this thread.
    static LOAD_LOGGED: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Take one piece of the backend's output (spec §4.7.2): into `conn`, or,
/// parked, nowhere -- the client is gone, and holding the output in the
/// closed connection's sender would only grow it; on revival the backend
/// resets on `ResumeReset` and renders again, so nothing is lost that the
/// client will see. Off its stream's gate in the same step, which counted it
/// from the backend's `send` on ([`SessionIo::send`]). The stream, if that
/// opened a screen gate: its channel wants `Writable`.
fn take_backend_data(
    conn: &mut Connection,
    gates: &GateTable,
    parked: bool,
    now: Instant,
    sd: StreamData,
    out: &mut Vec<Datagram>,
) -> Option<u8> {
    let n = sd.data.len() as u64;
    let tail = if parked {
        0
    } else {
        out.extend(conn.send(now, sd.stream_id, &sd.data));
        conn.stream_progress(sd.stream_id).unacked
    };
    #[cfg(test)]
    if sd.stream_id == crate::channel::CONTROL_STREAM {
        CONTROL_RELIABLE_PEAK.with(|peak| peak.set(peak.get().max(tail)));
    }
    gates
        .transfer(sd.stream_id, n, tail)
        .then_some(sd.stream_id)
}

/// Open and close `gates` by the tails of `conn`'s streams. A parked bridge
/// (the client is gone) throws the backend's output away anyway and the
/// revival repaints everything, so there every gate is open. Returns the
/// screen streams whose gate just opened.
fn refresh_gates(gates: &GateTable, conn: &Connection, parked: bool) -> Vec<u8> {
    if parked {
        gates.open_all()
    } else {
        gates.refresh(|stream| conn.stream_progress(stream).unacked)
    }
}

/// The requests in `awaiting` whose stream's tail on `conn` is empty --
/// everything sent on it acknowledged -- taken out, in the order they were
/// made. A parked bridge's connection is gone: nothing more is acknowledged
/// on it, so they wait for the connection an `Attach` brings, which holds no
/// tail.
fn take_delivered(
    awaiting: &mut Vec<(u8, u64)>,
    conn: &Connection,
    parked: bool,
) -> Vec<(u8, u64)> {
    if parked {
        return Vec::new();
    }
    let mut delivered = Vec::new();
    awaiting.retain(|&(stream, token)| {
        let done = conn.stream_progress(stream).unacked == 0;
        if done {
            delivered.push((stream, token));
        }
        !done
    });
    delivered
}

/// The stream bytes a backend event carries, if any.
fn data_of(ev: &SessionInbound) -> Option<(u8, usize)> {
    match ev {
        SessionInbound::Data(sd) => Some((sd.stream_id, sd.data.len())),
        _ => None,
    }
}

/// What the bridge tells its connection a backend has consumed (spec
/// §4.10.3). The connection counts every stream explicitly
/// (`adopt_connection`); this says when. A backend that does not report is
/// counted by what the bridge hands it; one that does, by its reports. A
/// warm reattach replaces the connection while the backend may still hold
/// bytes THIS LEDGER HANDED IT off the old one: those are owed to it, and
/// the first reports of each stream pay them off -- the new connection's
/// streams start at zero, and its credit must not grow by bytes the backend
/// was never given.
///
/// Invariant, per stream, across the whole life of a `ConsumptionLedger`
/// (spec §4.10.3, review round 2 finding N1): `owed_old + outstanding`
/// always equals everything this ledger has ever handed its backend, on
/// every connection this session has had, and the backend has not yet
/// reported taken. Handing bytes over grows the right-hand side and
/// `outstanding` together (`handed_over`); a report shrinks the right-hand
/// side and spends itself on `owed_old` first, `outstanding` second, in
/// that order, because that is the order the bytes were actually given to
/// the backend (`pay`); a reattach only moves bytes from `outstanding` to
/// `owed_old` (`carry`), never changing the sum. A report past what the
/// ledger holds for the stream is dropped: it credits nobody.
///
/// "Handed over" is the moment bytes enter the backend's inbound queue, not
/// the moment they reach the bridge's `Inbound::pending` (spec §4.10.2): a
/// byte waiting there is not the backend's yet, is not counted, and so holds
/// its stream's window shut -- that is what bounds each stream's share of
/// `pending` by its window (the session's is bounded by `PENDING_CAP`).
/// And bytes are booked to the connection that DELIVERED them, not to the
/// one driving the bridge when they leave `pending`: every connection this
/// ledger counts for has a generation (`generation`, one more at every
/// `carry`), each waiting event carries the generation it was delivered
/// under, and bytes of a replaced generation that reach the backend after
/// the reattach are booked straight to the replaced connections
/// (`handed_over_by`): for a reporting backend they join `owed_old`, which
/// its first reports pay off; for one that does not report they are
/// settled at once, crediting nobody -- the connection that delivered them
/// is gone. Either way the current connection's `outstanding` and credit
/// never see them. The order of hand-over is the order of delivery (the
/// queue and `pending` are both FIFO), so a replaced connection's bytes
/// still reach the backend before any byte the new one delivers, and `pay`'s
/// owed-first order stays the order the bytes were given.
///
/// Debug builds check two things at the end of every `handed_over` and
/// every `pay`, for the stream it touched (`debug_check`), against running
/// totals that each only ever grow by one `+=` and are never derived from
/// `owed_old` or `outstanding`:
/// - conservation: everything ever handed over equals `owed_old +
///   outstanding` plus everything ever settled against a replaced
///   connection (reports paid on its debt; for a backend that does not
///   report, bytes it delivered that reached the backend after it was
///   replaced) plus everything ever credited to a connection. A byte taken off
///   either map without being paid or credited, or credited without being
///   taken off one, breaks it;
/// - the current connection: what it has been credited since the last
///   `carry` is at most what was handed over since then. A connection is
///   never credited bytes it did not give the backend, even when old debt
///   was paid off in between.
struct ConsumptionLedger {
    backend_reports: bool,
    /// Which connection this ledger counts for now: `0` for the one the
    /// bridge starts with, one more at every `carry`. What an event waiting
    /// in `Inbound::pending` remembers, so its bytes are booked to the
    /// connection that delivered them (see the struct's doc).
    generation: u64,
    /// For a reporting backend: bytes handed over on the CONNECTION NOW
    /// DRIVING THIS BRIDGE that the backend has not yet reported taken.
    /// Always empty for a backend that does not report -- there
    /// `handed_over` pays as it goes, so nothing is ever outstanding.
    /// `carry` moves this into `owed_old` and empties it at every warm
    /// reattach: what a reattach right now can owe is what THIS bridge
    /// actually handed its backend, not what the replaced connection's own
    /// receiver shows as delivered (spec §4.10.3, review Important 1) --
    /// bytes still queued as `StreamData` events inside a connection that
    /// was itself replaced before those events were drained were never
    /// given to the backend, and are not owed to anyone.
    ///
    /// A stream number a channel frees is reused with NO ledger action of
    /// its own (fix round 3, finding A -- an earlier `forget` on a
    /// channel's end was wrong: the channel's LAST reports, of bytes it
    /// drops rather than delivers, arrive AFTER that declaration, from a
    /// different producer, and a `forget` would then misattribute them to
    /// whoever reuses the number). The contract instead (spec §4.10.3;
    /// `SessionBackend::consumption`'s own doc) is that a reporting backend
    /// reports EVERY byte it is ever handed, dropped ones included: under
    /// that contract a stream's count always settles to zero by itself,
    /// however out of order two channels that shared a number report. A
    /// late report of an old connection's bytes, arriving after a reattach,
    /// pays `owed_old` first and so only DELAYS the new connection's credit
    /// -- it never credits the new connection for bytes it did not give.
    outstanding: BTreeMap<u8, u64>,
    /// Bytes handed over on connections a warm reattach replaced that the
    /// backend has not yet reported (`carry`). Reports pay these first.
    owed_old: BTreeMap<u8, u64>,
    /// What `debug_check` checks the two maps above against. Kept only in
    /// builds with debug assertions (tests among them): a release build
    /// carries none of it (final review M4).
    #[cfg(debug_assertions)]
    audit: LedgerAudit,
}

/// The running totals `ConsumptionLedger::debug_check` checks its maps
/// against, per stream (see `ConsumptionLedger`'s doc). Only in builds with
/// debug assertions.
#[cfg(debug_assertions)]
#[derive(Default)]
struct LedgerAudit {
    /// Bytes ever handed to the backend (`handed_over`,
    /// `handed_over_by_replaced`).
    handed_total: BTreeMap<u8, u64>,
    /// Bytes ever settled against a replaced connection -- reports spent on
    /// `owed_old` (in `pay`), and, for a backend that does not report, bytes
    /// a replaced connection delivered that reached the backend after the
    /// reattach (in `handed_over_by_replaced`), credited to nobody.
    paid_old_total: BTreeMap<u8, u64>,
    /// Bytes ever credited to a connection through
    /// `Connection::on_consumed` (touched only by `pay`).
    credited_total: BTreeMap<u8, u64>,
    /// Bytes handed over since the last `carry`, that is, off the
    /// connection now driving the bridge.
    handed_now: BTreeMap<u8, u64>,
    /// Bytes credited to the connection now driving the bridge.
    credited_now: BTreeMap<u8, u64>,
}

/// Add `n` to `stream_id`'s entry in `m`.
#[cfg(debug_assertions)]
fn add(m: &mut BTreeMap<u8, u64>, stream_id: u8, n: u64) {
    *m.entry(stream_id).or_insert(0) += n;
}

impl ConsumptionLedger {
    fn new(consumption: Consumption) -> Self {
        ConsumptionLedger {
            backend_reports: consumption == Consumption::Explicit,
            generation: 0,
            outstanding: BTreeMap::new(),
            owed_old: BTreeMap::new(),
            #[cfg(debug_assertions)]
            audit: LedgerAudit::default(),
        }
    }

    /// A warm reattach is about to replace the connection this ledger has
    /// been counting for: what THIS ledger handed its backend off it and
    /// the backend has not yet reported is owed to it.
    /// Bytes still waiting in `Inbound::pending` are not counted here: they
    /// keep the generation they were delivered under and are booked to it
    /// when they reach the backend (`handed_over_by`).
    fn carry(&mut self) {
        for (stream_id, n) in std::mem::take(&mut self.outstanding) {
            *self.owed_old.entry(stream_id).or_insert(0) += n;
        }
        #[cfg(debug_assertions)]
        {
            self.audit.handed_now.clear();
            self.audit.credited_now.clear();
        }
        self.generation += 1;
    }

    /// The generation of the connection this ledger counts for now.
    fn generation(&self) -> u64 {
        self.generation
    }

    /// Stream bytes entered the backend's queue: booked to the connection
    /// that delivered them -- the current one, or one a reattach replaced.
    fn handed_over_by(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        handed: Handed,
        out: &mut Vec<Datagram>,
    ) {
        if handed.generation == self.generation {
            self.handed_over(conn, now, handed.stream_id, handed.n, out);
        } else {
            self.handed_over_by_replaced(handed.stream_id, handed.n);
        }
    }

    /// `n` bytes of `stream_id` a REPLACED connection delivered reached the
    /// backend after the reattach (they waited in `Inbound::pending`). The
    /// current connection neither gave them nor is credited for them: a
    /// reporting backend's reports of them pay `owed_old`, like every
    /// other byte a replaced connection handed over; for a backend that
    /// does not report they are settled here and credit nobody.
    fn handed_over_by_replaced(&mut self, stream_id: u8, n: usize) {
        #[cfg(debug_assertions)]
        add(&mut self.audit.handed_total, stream_id, n as u64);
        if self.backend_reports {
            *self.owed_old.entry(stream_id).or_insert(0) += n as u64;
        } else {
            #[cfg(debug_assertions)]
            add(&mut self.audit.paid_old_total, stream_id, n as u64);
        }
        self.debug_check(stream_id);
    }

    /// `n` bytes of `stream_id` the CURRENT connection delivered went to
    /// the backend.
    fn handed_over(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        stream_id: u8,
        n: usize,
        out: &mut Vec<Datagram>,
    ) {
        #[cfg(debug_assertions)]
        {
            add(&mut self.audit.handed_total, stream_id, n as u64);
            add(&mut self.audit.handed_now, stream_id, n as u64);
        }
        if self.backend_reports {
            *self.outstanding.entry(stream_id).or_insert(0) += n as u64;
        } else {
            self.pay(conn, now, stream_id, n, out);
        }
        self.debug_check(stream_id);
    }

    /// The backend reported `n` bytes of `stream_id` taken -- every byte it
    /// was ever handed on this stream, dropped ones included, is expected
    /// to be reported eventually (`SessionBackend::consumption`'s doc); a
    /// stream a reporting backend never finishes reporting simply keeps a
    /// short window for the rest of the session. Settlement, not
    /// bookkeeping of its own: `pay` does the actual owed-first split
    /// (fix round 2, finding N1 -- `reported` used to spend `n` off
    /// `outstanding` on its own before `pay` ever ran, disagreeing with
    /// `pay`'s owed-first order and losing whatever `owed_old` absorbed).
    fn reported(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        stream_id: u8,
        n: usize,
        out: &mut Vec<Datagram>,
    ) {
        if self.backend_reports {
            self.pay(conn, now, stream_id, n, out);
        }
    }

    /// Settle `n` reported (or, for an `OnDelivery` backend, just
    /// delivered) bytes of `stream_id`: the OLDEST debt first (a replaced
    /// connection's `owed_old` -- those bytes reached the backend before
    /// anything the current connection gave it), then whatever remains
    /// credits the CURRENT connection -- but for a REPORTING backend, only
    /// up to what this ledger holds as `outstanding` for the stream (fix
    /// round 3, Minor D): a report past that is an over-report, and the
    /// ledger, not just the receiver's own delivered-bytes clamp, is the
    /// bound on what it can credit. An `OnDelivery` backend has no
    /// `outstanding` of its own to bound against -- `n` there IS exactly
    /// what the bridge just handed over, never a report, so it is credited
    /// in full.
    fn pay(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        stream_id: u8,
        n: usize,
        out: &mut Vec<Datagram>,
    ) {
        let mut n = n as u64;
        if let Some(owed) = self.owed_old.get_mut(&stream_id) {
            let paid = (*owed).min(n);
            *owed -= paid;
            n -= paid;
            if *owed == 0 {
                self.owed_old.remove(&stream_id);
            }
            #[cfg(debug_assertions)]
            add(&mut self.audit.paid_old_total, stream_id, paid);
        }
        let credited = if n == 0 {
            0
        } else if self.backend_reports {
            match self.outstanding.get_mut(&stream_id) {
                Some(left) => {
                    let taken = (*left).min(n);
                    *left -= taken;
                    if *left == 0 {
                        self.outstanding.remove(&stream_id);
                    }
                    taken
                }
                None => 0,
            }
        } else {
            n
        };
        if credited > 0 {
            #[cfg(debug_assertions)]
            {
                add(&mut self.audit.credited_total, stream_id, credited);
                add(&mut self.audit.credited_now, stream_id, credited);
            }
            out.extend(conn.on_consumed(now, stream_id, credited as usize));
        }
        self.debug_check(stream_id);
    }

    /// The two checks the struct's doc describes, for `stream_id`. Nothing
    /// without debug assertions, where there is no `audit` to check against.
    #[cfg(debug_assertions)]
    fn debug_check(&self, stream_id: u8) {
        let of = |m: &BTreeMap<u8, u64>| m.get(&stream_id).copied().unwrap_or(0);
        let audit = &self.audit;
        debug_assert_eq!(
            of(&audit.handed_total),
            of(&self.owed_old)
                + of(&self.outstanding)
                + of(&audit.paid_old_total)
                + of(&audit.credited_total),
            "stream {stream_id}: handed over must equal owed_old + outstanding + paid off + credited"
        );
        debug_assert!(
            of(&audit.credited_now) <= of(&audit.handed_now),
            "stream {stream_id}: the current connection was credited more than it handed over"
        );
    }

    #[cfg(not(debug_assertions))]
    fn debug_check(&self, _stream_id: u8) {}
}

/// Stream bytes that entered the backend's inbound queue, and the ledger
/// generation of the connection that delivered them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handed {
    stream_id: u8,
    n: usize,
    generation: u64,
}

/// An event waiting in `Inbound::pending`, with the ledger generation of
/// the connection that delivered it (see `ConsumptionLedger`).
struct Waiting {
    ev: SessionInbound,
    generation: u64,
}

impl Waiting {
    /// The stream bytes it carries, as handed over.
    fn handed(&self) -> Option<Handed> {
        data_of(&self.ev).map(|(stream_id, n)| Handed {
            stream_id,
            n,
            generation: self.generation,
        })
    }
}

/// The bridge's end of its backend's inbound queue (spec §4.10.2). It never
/// waits: what the queue has no room for waits here, in order, and goes as
/// room opens -- the bridge's `room` arm.
struct Inbound {
    tx: mpsc::Sender<SessionInbound>,
    pending: VecDeque<Waiting>,
    /// Stream bytes in `pending`.
    pending_bytes: usize,
    revoked: bool,
}

impl Inbound {
    fn new(tx: mpsc::Sender<SessionInbound>) -> Self {
        Inbound {
            tx,
            pending: VecDeque::new(),
            pending_bytes: 0,
            revoked: false,
        }
    }

    fn revoke(&mut self) {
        self.revoked = true;
        self.pending.clear();
        self.pending_bytes = 0;
    }

    fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Stream data waiting, the only thing counted against `PENDING_CAP`:
    /// the other events that may wait behind it (`Live`, `ResumeReset`,
    /// `Repaint`, `Writable`, `Delivered`) are few and carry no bytes.
    fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Queue `ev`, delivered under ledger generation `generation`, behind
    /// whatever waits already, or hand it over at once if nothing does and
    /// there is room. The stream bytes handed over now, if any.
    fn push(&mut self, ev: SessionInbound, generation: u64) -> Option<Handed> {
        if self.revoked {
            return None;
        }
        let waiting = Waiting { ev, generation };
        let handed = waiting.handed();
        if self.pending.is_empty() {
            match self.tx.try_send(waiting.ev) {
                Ok(()) => return handed,
                Err(mpsc::error::TrySendError::Full(ev)) => self.park(Waiting { ev, generation }),
                // The backend is gone, and the session ends with it.
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        } else {
            self.park(waiting);
        }
        None
    }

    fn park(&mut self, waiting: Waiting) {
        self.pending_bytes += waiting.handed().map_or(0, |h| h.n);
        self.pending.push_back(waiting);
        #[cfg(test)]
        PENDING_PEAK.with(|p| p.set(p.get().max(self.pending_bytes)));
    }

    /// Wait for room, then hand over the head and as much after it as fits.
    /// Returns the stream bytes handed over. Cancel-safe: nothing is taken
    /// before the room is. A backend that is gone takes everything with it.
    async fn room(&mut self) -> Vec<Handed> {
        let mut handed = Vec::new();
        let permit = match self.tx.reserve().await {
            Ok(permit) => permit,
            Err(_) => {
                self.pending.clear();
                self.pending_bytes = 0;
                return handed;
            }
        };
        let head = self
            .pending
            .pop_front()
            .expect("room is asked for only while something waits");
        if let Some(h) = head.handed() {
            self.pending_bytes -= h.n;
            handed.push(h);
        }
        permit.send(head.ev);
        while let Some(next) = self.pending.pop_front() {
            let h = next.handed();
            let generation = next.generation;
            match self.tx.try_send(next.ev) {
                Ok(()) => {
                    if let Some(h) = h {
                        self.pending_bytes -= h.n;
                        handed.push(h);
                    }
                }
                Err(mpsc::error::TrySendError::Full(ev)) => {
                    self.pending.push_front(Waiting { ev, generation });
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.pending.clear();
                    self.pending_bytes = 0;
                    break;
                }
            }
        }
        handed
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only: the most stream bytes a bridge on this thread ever queued
    /// for its backend.
    static PENDING_PEAK: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Actual reliable control debt retained by the running bridge, not bytes
    /// generated by a producer. Current-thread tests have separate local peaks.
    static CONTROL_RELIABLE_PEAK: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static CONTROL_PRODUCER_FENCE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static CONTROL_BACKEND_EOF: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CONTROL_RETIREMENT_BARRIER: std::cell::Cell<Option<AttachmentContext>> = const { std::cell::Cell::new(None) };
}

/// The bridge's side of its backend (spec §4.10): what goes in, and what the
/// backend counts as having taken.
struct BackendLink {
    inbound: Inbound,
    ledger: ConsumptionLedger,
    channel_output: channel_bridge::ChannelBridge,
    control_delivery: crate::control_budget::ControlLedger,
}

impl BackendLink {
    fn new(tx: mpsc::Sender<SessionInbound>, consumption: Consumption) -> Self {
        BackendLink {
            inbound: Inbound::new(tx),
            ledger: ConsumptionLedger::new(consumption),
            channel_output: channel_bridge::ChannelBridge::default(),
            control_delivery: crate::control_budget::ControlLedger::new(0, 0),
        }
    }

    /// Hand `ev`, which `conn` delivered (or which the bridge makes for it),
    /// to the backend -- at once, or after what waits already; never
    /// waiting (spec §4.10.2). Stream bytes count as handed over when they
    /// enter the backend's queue, booked to the connection that delivered
    /// them (see `ConsumptionLedger`).
    fn hand_over(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        ev: SessionInbound,
        out: &mut Vec<Datagram>,
    ) {
        if let Some(handed) = self.inbound.push(ev, self.ledger.generation()) {
            self.ledger.handed_over_by(conn, now, handed, out);
        }
    }

    /// Book what `Inbound::room` handed over.
    fn took(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        handed: Vec<Handed>,
        out: &mut Vec<Datagram>,
    ) {
        for h in handed {
            self.ledger.handed_over_by(conn, now, h, out);
        }
    }

    /// Past `PENDING_CAP`: wait for the backend, as every build before
    /// credits did (spec §4.10.5, §4.10.7), in both modes -- the windows
    /// bound each stream, not the session (see `PENDING_CAP`).
    async fn wait_below_pending_cap(
        &mut self,
        control: &SessionControl,
        conn: &mut Connection,
        out: &mut Vec<Datagram>,
    ) {
        if control.retiring() {
            self.inbound.revoke();
            return;
        }
        // Retiring backends no longer consume. Do not let their former
        // application backlog fence outcome/ACK/deadline processing forever.
        tokio::select! {
            biased;
            _ = control.retire_bridge.notified() => self.inbound.revoke(),
            _ = self.wait_below(PENDING_CAP, conn, out) => {}
        }
    }

    /// Wait for the backend while more than `cap` stream bytes wait for it.
    /// What each room hands over is booked at the time it went, read after
    /// the wait -- not at the turn's `now`, which a wait for a slow backend
    /// leaves arbitrarily far behind: a `CREDIT` this sends counts its
    /// repeat's `rto` from when it was sent (spec §6.4), and one booked at
    /// a stale time would be repeated at once.
    async fn wait_below(&mut self, cap: usize, conn: &mut Connection, out: &mut Vec<Datagram>) {
        while self.inbound.pending_bytes() > cap {
            let handed = self.inbound.room().await;
            self.took(conn, Instant::now(), handed, out);
        }
    }

    /// The bridge is ending gracefully: hand what waits to the backend, in
    /// order, and only then let its queue close, so the backend reads
    /// everything delivered before its `None`. On a task of its own -- the
    /// bridge ends now -- that holds only the backend's queue and what waits
    /// for it: at most `PENDING_CAP` plus what the last turn delivered, for
    /// as long as the backend takes to read it (a backend that is gone takes
    /// it all at once). Not the connection, which ends with the bridge, and
    /// not the ledger: every byte handed over from here on would be credited
    /// to a closed connection, which sends nothing, and nothing reads the
    /// ledger after the bridge (a graceful end is never reattached), so there
    /// is no bookkeeping left to do.
    fn finish(self, lifecycle: Arc<Lifecycle>) {
        let BackendLink { mut inbound, .. } = self;
        if !inbound.has_pending() {
            return;
        }
        let owner = lifecycle.clone();
        owner.spawn(async move {
            while inbound.has_pending() {
                tokio::select! {
                    biased;
                    _ = lifecycle.shutdown.requested() => break,
                    _ = inbound.room() => {}
                }
            }
        });
    }
}

/// Send a batch of outgoing datagrams. Individual send errors are ignored: one
/// lost datagram must not tear down the loop.
pub(crate) async fn send_all(socket: &UdpSocket, dgrams: &[Datagram]) {
    for dg in dgrams {
        let _ = socket.send_to(&dg.bytes, dg.to).await;
    }
}

#[cfg(test)]
#[path = "session_manager_tests.rs"]
mod tests;

#[cfg(test)]
mod key_erasure_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct ObservedSecret(Arc<AtomicBool>);
    impl zeroize::Zeroize for ObservedSecret {
        fn zeroize(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn unpolled_future_drops_its_secret_owner() {
        let wiped = Arc::new(AtomicBool::new(false));
        let future = with_owned_secret(ObservedSecret(wiped.clone()), |secret| async move {
            std::future::pending::<()>().await;
            drop(secret);
        });
        fn is_send<T: Send>(_: &T) {}
        is_send(&future);
        assert!(!wiped.load(Ordering::SeqCst));
        drop(future);
        assert!(wiped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn polled_future_retains_secret_until_cancelled() {
        let wiped = Arc::new(AtomicBool::new(false));
        let mut future = Box::pin(with_owned_secret(
            ObservedSecret(wiped.clone()),
            |secret| async move {
                std::future::pending::<()>().await;
                drop(secret);
            },
        ));
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        assert!(!wiped.load(Ordering::SeqCst));
        drop(future);
        assert!(wiped.load(Ordering::SeqCst));
    }
}
