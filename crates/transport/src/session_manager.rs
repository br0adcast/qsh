//! Async multi-session manager on top of the sans-IO `Connection` core: one
//! UDP socket, a session router, and a per-session backend.
//!
//! This is the tmux-agnostic multiplex core the rest of the daemon builds
//! on. The manager owns the UDP socket and, on a `HandshakeInit`, runs
//! [`Connection::accept`]; on success it spawns:
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
//! **Nothing binds before its peer is proven.** The paragraph above holds
//! because an allowlist handshake is itself a proof. `AuthPolicy::SshSignature`
//! admits ANY static key, so a signature handshake proves nothing at accept
//! time -- and the arms above tear down, repoint and evict. So a signature
//! handshake does not reach them: it goes into PROBATION (see
//! [`crate::probation`]), which registers only its datagram route and touches
//! `backends` not at all, and only when its record on
//! [`crate::auth::AUTH_STREAM`] verifies does the SAME decision logic run --
//! resolved afresh against the table as it stands then. The property is
//! therefore structural: an unproven connection never reaches the decision
//! logic, rather than being guarded at each of its write sites.
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

#[path = "channel_bridge.rs"]
mod channel_bridge;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::auth::{AuthVerifier, Principal, AUTH_NONCE_LEN, AUTH_STREAM, NO_INCARNATION};
use crate::conn::{
    AcceptOutcome, AuthPolicy, Connection, ConnectionConfig, Consumption, Datagram, Event,
    LinkState, Msg2Inputs, Role, StreamClass,
};
use crate::cookie::{source_group_key, CookieCheck, Verdict};
use crate::dgram_queue::{dgram_queue, probation_dgram_queue, DgramRx, DgramTx, DGRAM_QUEUE_BYTES};
use crate::handshake_payload::{Msg1Payload, StartKind};
use crate::probation::{
    run_probation, BridgeStart, Probation, ProbationEnded, ProvenSession, MAX_PROBATION,
    MAX_PROBATION_PER_SOURCE,
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
    DeliveryMarker(DeliveryMarker, crate::channel_timeline::TimelinePermit),
}
impl ChannelOutput {
    pub fn framed_len(&self) -> usize {
        match self {
            Self::Data(bytes) => 5 + bytes.len(),
            Self::Geometry(..) => 27,
            Self::EchoAck(..) => 13,
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
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
    },
    ChannelOutput {
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
    ChannelExit {
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
        code: i32,
        open: crate::channel::OpenClassification,
        permit: crate::channel_timeline::TimelinePermit,
    },
    ResumeBarrier {
        generation: u64,
    },
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

/// A backend's handle to its session: receive [`SessionInbound`] events, send
/// outbound [`SessionOutbound`]. The backend never sees the socket or the
/// `Connection`.
pub struct SessionIo {
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
    pub(crate) fn publish_resume_snapshot(
        &self,
        origin: AttachmentContext,
        build: impl FnOnce()
            -> Result<crate::channel::ChannelSnapshot, crate::channel::ChannelCodecError>,
    ) {
        match self.resume_snapshots.publish(origin.generation, build) {
            Ok(true) => self.resume_barrier(origin.generation),
            Ok(false) => {}
            Err(_) => self.protocol_failure(origin, None),
        }
    }
    pub(crate) fn channel_opened(&self, origin: AttachmentContext, stream: u8) {
        let _ = self
            .outbound
            .send(SessionOutbound::ChannelOpened { stream, origin });
    }
    pub(crate) fn channel_refused(&self, origin: AttachmentContext, stream: u8, reason: String) {
        let _ = self.outbound.send(SessionOutbound::ChannelRefused {
            stream,
            origin,
            reason,
        });
    }
    /// Await the next inbound event. `None` once the session task has ended
    /// (the connection closed or the manager shut down) -- the backend should
    /// then wind down.
    pub async fn recv(&mut self) -> Option<SessionInbound> {
        self.inbound.recv().await
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
    /// §4.7.2): the queue to the bridge has no bound of its own, and a gate
    /// that saw only the connection's tail would let a producer faster than
    /// the bridge fill it past the gate's marks.
    pub fn send(&self, stream_id: u8, data: Vec<u8>) {
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
        let _ = self.outbound.send(SessionOutbound::ChannelOutput {
            stream,
            instance,
            origin,
            output,
            charge: OutputCharge { gate, bytes },
            gap_reserve,
        });
    }
    pub(crate) fn channel_closed(
        &self,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        origin: AttachmentContext,
    ) {
        let _ = self.outbound.send(SessionOutbound::ChannelClosed {
            stream,
            instance,
            origin,
        });
    }
    pub(crate) fn send_channel_exit(
        &self,
        descriptor: crate::channel::DrainingChannel,
        origin: AttachmentContext,
        code: i32,
        permit: crate::channel_timeline::TimelinePermit,
    ) {
        let _ = self.outbound.send(SessionOutbound::ChannelExit {
            stream: descriptor.stream,
            instance: descriptor.instance,
            origin,
            code,
            open: descriptor.open,
            permit,
        });
    }
    pub(crate) fn repaint_barrier(&self, generation: u64, sequence: u64) {
        let _ = self.outbound.send(SessionOutbound::RepaintBarrier {
            generation,
            sequence,
        });
    }
    pub(crate) fn resume_barrier(&self, generation: u64) {
        let _ = self
            .outbound
            .send(SessionOutbound::ResumeBarrier { generation });
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
    ) -> impl Fn(u64) -> Option<crate::channel::ChannelSnapshot> + Send + 'static {
        let snapshots = self.resume_snapshots.clone();
        move |generation| snapshots.take(generation)
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
    /// handshake it belonged to was refused, discarded as a `ResendMsg2`
    /// retransmit, authenticated by allowlist (so no proof will ever echo
    /// it back), or its probation ended without one arriving. A tell, not
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
    /// Who the allowlist path's proof is: a static-key handshake IS its own
    /// proof, so there is no verifier and no `Principal` to ask for one.
    /// This is the daemon's own account, the same `uid`/`name` handed to the
    /// verifier above.
    pub self_principal: Principal,
    /// Where this server's handshake nonces come from -- see [`NonceSource`].
    pub nonces: Arc<dyn NonceSource>,
    /// Where a login going away is reported -- see [`LoginSink`].
    pub logins: Arc<dyn LoginSink>,
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
    Attach(Box<Connection>, Vec<StreamData>, Vec<(SocketAddr, Vec<u8>)>),
}

/// A registered backend for one token (= one device). One backend task + one
/// persistent bridge task run per entry; the `Connection` they drive is
/// SWAPPABLE (warm reattach) while the backend keeps running.
struct BackendEntry {
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
    /// session, no route repoint, no respawn. The freshly accepted connection
    /// from this call is discarded.
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
    /// `session_id` -> router->task datagram sender, for demuxing `Transport`
    /// frames to the owning session task. Holds both bound sessions and the
    /// provisional routes of connections still in probation.
    sessions: HashMap<u64, DgramTx>,
    /// Token -> backend entry, one per device.
    backends: HashMap<[u8; 16], BackendEntry>,
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
            sessions: HashMap::new(),
            backends: HashMap::new(),
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
        // A LIVE entry's stable datagram sender lives in `sessions`; a
        // RETAINED one's was moved into `parked_dgram` when it died, and
        // goes when `entry` is dropped at the end of this scope. Doing both
        // covers either state without having to ask which this one is in.
        self.sessions.remove(&entry.session_id);
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
        let owned = self.backends.values().filter(|e| e.owner == owner).count();
        owned < MAX_SESSIONS_PER_OWNER && self.backends.len() < MAX_SESSIONS_TOTAL
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
        let owned = self.backends.values().filter(|e| e.owner == owner).count();
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
/// daemon's own account, and a handshake on it is its own proof. Writing
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

/// Signalled by a per-session task when its session has ended, so the router
/// can apply the lifecycle policy (immediate teardown vs retain).
struct SessionEnded {
    session_id: u64,
    token: [u8; 16],
    /// `true` if the connection closed gracefully (a received `Close`) -- tear
    /// down at once; `false` on an unexpected death (`DEATH_AFTER`) -- retain.
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
    pub async fn serve(
        socket: Arc<UdpSocket>,
        server_priv: [u8; 32],
        auth: ServerAuth,
        factory: BackendFactory,
        active_count: Arc<AtomicUsize>,
        mut login_ends: LoginEndedReports,
    ) {
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
            socket: &socket,
            server_priv: &server_priv,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        loop {
            tokio::select! {
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
                let mut resolve_for_msg2 = |msg1: &Msg1Payload| -> Option<Msg2Inputs> {
                    let d = router.resolve(&msg1.token, body, msg1.start_kind);
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
                    Some(Msg2Inputs { resumed, nonce })
                };
                // An empty allowlist admits nobody, so that `accept` could
                // only ever reject -- and under `serve` the allowlist is
                // ALWAYS empty, because the signature path owns every client
                // there. Skipping it costs nothing and saves a full Noise
                // `accept` on every handshake, junk datagram included.
                let mut outcome = if allowlist.is_empty() {
                    AcceptOutcome::Rejected
                } else {
                    #[cfg(test)]
                    ACCEPT_ATTEMPTS.with(|n| n.set(n.get() + 1));
                    Connection::accept(
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
                let mut accepted_by_signature = false;
                if matches!(outcome, AcceptOutcome::Rejected) && ctx.auth.verifier.is_some() {
                    #[cfg(test)]
                    ACCEPT_ATTEMPTS.with(|n| n.set(n.get() + 1));
                    outcome = Connection::accept(
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
                    accepted_by_signature = matches!(outcome, AcceptOutcome::Accepted { .. });
                }
                match outcome {
                    AcceptOutcome::Accepted {
                        conn,
                        client_key,
                        msg1,
                        out,
                        nonce,
                    } => {
                        // Taken inside `accept`, above: the same decision the
                        // client was told about in msg2.
                        let decision = decision
                            .expect("an accepted handshake resolved its decision inside `accept`");
                        let admission = Admission {
                            conn,
                            client_key,
                            msg1,
                            msg1_body: body.to_vec(),
                            out,
                            src,
                            // Nothing has been consumed off this connection
                            // yet: whatever it queued is still there for the
                            // bridge (allowlist) or the probation task
                            // (signature) to drain.
                            start: BridgeStart::default(),
                            nonce,
                            // A placeholder on the signature path: it goes
                            // into `begin_probation`, which discards it --
                            // the real principal only exists once the peer
                            // proves itself.
                            principal: ctx.auth.self_principal.clone(),
                            route: None,
                        };
                        if accepted_by_signature {
                            // The signature policy admits ANY static key, so
                            // this handshake proves NOTHING. It must not reach
                            // the decision arms until its peer does.
                            Self::begin_probation(ctx, router, decision, admission).await;
                        } else {
                            // The allowlist checked this client's static key
                            // during the handshake: it is already proven, and
                            // binds immediately, exactly as it always has. It
                            // never sends a v2 auth record (design SS4.4), so
                            // this nonce will never be spent -- release it
                            // UNCONDITIONALLY, ResendMsg2 retransmit included.
                            // `apply_decision` itself never releases (see its
                            // ResendMsg2 arm's own comment): the very same arm
                            // is also reached, via `on_probation_ended`'s
                            // re-resolution, for a PROVEN signature
                            // connection whose nonce a proof has just
                            // consumed -- releasing there would be
                            // spend-then-release. Only this branch (the
                            // allowlist accept, which never has a proof to
                            // consume anything) is the right place to release
                            // unconditionally.
                            ctx.auth.nonces.release(nonce);
                            Self::apply_decision(ctx, router, decision, admission).await;
                        }
                    }
                    // Validation failed -- no response, no registration. This is
                    // the auth gate: a non-allowlisted key (or bad Noise) never
                    // reaches the reattach/replace decision, so it cannot hijack
                    // an existing token's backend.
                    AcceptOutcome::Rejected => {
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
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            start: _,
            nonce,
            // The real principal is not known yet -- it arrives with the
            // proof, via `ProvenSession::principal`, when probation ends.
            principal: _,
            route: _,
        } = admission;
        // A retransmit adopts nothing on either path, and must not create a
        // probation entry either: the client is already Live on the original
        // session, so re-sending the ORIGINAL msg2 is the whole answer. The
        // nonce issued for the discarded new connection will never be
        // spent -- release it.
        if matches!(decision, AcceptDecision::ResendMsg2) {
            ctx.auth.nonces.release(nonce);
            Self::resend_original_msg2(ctx, router, &msg1.token, src).await;
            return;
        }
        let session_id = conn.session_id();
        // Over the probation cap: drop in silence. Nothing is evicted, because
        // nothing here belongs to anyone yet, and nothing real is reachable
        // from a probation entry to evict. The nonce this refused admission
        // was issued will never be spent either -- release it.
        if !router.admit_probation(session_id, src, msg1.token) {
            ctx.auth.nonces.release(nonce);
            return;
        }
        let verifier = match ctx.auth.verifier.clone() {
            Some(v) => v,
            // Unreachable: a signature acceptance requires the verifier that
            // configured the policy. Refuse rather than assert -- an
            // unauthenticated peer must never be able to panic the daemon.
            None => {
                router.probation.remove(&session_id);
                ctx.auth.nonces.release(nonce);
                return;
            }
        };
        // A probation's route is small until its connection is proven
        // (spec §4.16); `cold_create` raises it.
        let (dg_tx, dg_rx) = probation_dgram_queue();
        tokio::spawn(run_probation(Probation {
            socket: ctx.socket.clone(),
            conn,
            verifier,
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
        let seat = router.probation.remove(&ended.session_id);
        // A successful verifier may already have created this helper login.
        // Bind first: reattach/cold fallback turns the entry Live, so cleanup
        // cannot revoke the login that the newly adopted session needs.
        Self::apply_probation_result(ctx, router, ended).await;
        if let Some(seat) = seat {
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
        }
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
        Self::apply_decision(
            ctx,
            router,
            decision,
            Admission {
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
    /// `decision`. Reached directly by the allowlist path (whose handshake is
    /// its own proof) and, one round trip later, by a signature path that
    /// finished its probation. Identical either way: the only difference is
    /// `admission.start`, which carries whatever probation already consumed
    /// off the connection so the bridge can replay it.
    async fn apply_decision(
        ctx: &ManagerCtx<'_>,
        router: &mut Router,
        decision: AcceptDecision,
        admission: Admission,
    ) {
        let token = admission.msg1.token;
        let new_id = admission.conn.session_id();
        match decision {
            AcceptDecision::ResendMsg2 => {
                // Do NOT adopt this call's fresh conn / new_id -- `admission`
                // is dropped here -- so the route and backend are untouched.
                //
                // Deliberately releases NOTHING here, even though the
                // discarded connection's nonce could look unspent from this
                // arm alone: this same arm is reached from TWO callers with
                // different answers to "will this nonce be spent". The
                // allowlist path (`handle_datagram`'s direct call) already
                // released its own nonce, unconditionally, before ever
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
                match control.send(BridgeControl::Attach(Box::new(conn), early, queued)) {
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
                        send_all(ctx.socket, &out).await;
                        log_session_features(new_id, features);
                    }
                    Err(mpsc::error::SendError(BridgeControl::Attach(boxed, early, queued))) => {
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
                            Admission {
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
                let old_key = Self::cold_create(ctx, router, admission).await;
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
                let old_key = Self::cold_create(ctx, router, admission).await;
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
        admission: Admission,
    ) -> Option<[u8; 32]> {
        let Admission {
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
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: ctx.socket.clone(),
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
        }));

        // Register BEFORE sending msg2, so a fast client reply is routable the
        // instant it arrives.
        router.sessions.insert(session_id, dg_tx);
        let superseded = router.backends.insert(
            token,
            BackendEntry {
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
        send_all(ctx.socket, &out).await;
        superseded.map(|e| e.client_key)
    }
}

/// The manager's ambient wiring: everything a decision arm needs that is not
/// about the particular connection being bound. Borrowed for the life of
/// `serve`, so the per-datagram path passes ONE reference instead of seven.
struct ManagerCtx<'a> {
    socket: &'a Arc<UdpSocket>,
    server_priv: &'a [u8; 32],
    auth: &'a ServerAuth,
    factory: &'a BackendFactory,
    done_tx: &'a mpsc::UnboundedSender<SessionEnded>,
    probation_tx: &'a mpsc::UnboundedSender<ProbationEnded>,
    active_count: &'a Arc<AtomicUsize>,
}

/// One accepted handshake whose peer is proven, as the decision arms see it.
/// Reaching a decision arm at all is the proof: an allowlist handshake is
/// admitted straight from `handle_datagram`, a signature handshake only after
/// its probation succeeded.
struct Admission {
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
    /// bridge to replay. Empty on the allowlist path.
    start: BridgeStart,
    /// The nonce this handshake's msg2 carried. Read by `begin_probation`,
    /// which carries it into the `AuthGate` that checks a v2 record's proof
    /// against it; unused past that point (the allowlist path builds no
    /// gate at all, and once probation has proved a connection the check
    /// has already happened).
    nonce: [u8; AUTH_NONCE_LEN],
    /// Who this connection belongs to. On the allowlist path this is
    /// `ServerAuth::self_principal` from the moment of acceptance -- the
    /// handshake is its own proof. On the signature path the value set here
    /// is a placeholder that `begin_probation` discards: the real value
    /// only exists once probation succeeds, and arrives via
    /// `ProvenSession::principal` when a fresh `Admission` is built for it
    /// in `on_probation_ended`.
    principal: Principal,
    /// The probation's route and queue, on the signature path only (see
    /// [`ProvisionalRoute`]). `None` on the allowlist path, which has none.
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
fn apply_control(
    conn: &mut Connection,
    parked: &mut bool,
    link: &mut BackendLink,
    control: BridgeControl,
    classes: &BTreeMap<u8, StreamClass>,
    now: Instant,
    out: &mut Vec<Datagram>,
) {
    let BridgeControl::Attach(new_conn, early, queued) = control;
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
fn on_routed_datagram(
    conn: &mut Connection,
    parked: &mut bool,
    control_rx: &mut mpsc::UnboundedReceiver<BridgeControl>,
    link: &mut BackendLink,
    classes: &BTreeMap<u8, StreamClass>,
    now: Instant,
    src: SocketAddr,
    bytes: &[u8],
    out: &mut Vec<Datagram>,
) {
    while let Ok(control) = control_rx.try_recv() {
        apply_control(conn, parked, link, control, classes, now, out);
    }
    out.extend(conn.on_datagram(now, src, bytes));
}

/// What woke the persistent bridge loop.
enum Wakeup {
    /// An incoming datagram routed from the manager (`None` = router gone).
    Dgram(Option<(SocketAddr, Vec<u8>)>),
    /// A core timer fired.
    Timeout,
    /// One coalesced continuation after a finite channel-output drain turn.
    Drain,
    /// The backend produced an outbound message -- data or a declaration
    /// (`None` = backend finished).
    Backend(Option<SessionOutbound>),
    /// A control message from the manager (`None` = the entry was dropped).
    Control(Option<BridgeControl>),
    /// The backend took what waited for it.
    Room(Vec<Handed>),
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
/// Every connection a bridge ever sees is already authenticated: the allowlist
/// checked its static key during the handshake, or its probation
/// (`crate::probation`) verified its signature before the manager bound it. So
/// the bridge has no authentication check of its own and nothing to withhold
/// -- the session exists precisely because the peer is proven.
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

    // Fixed before the backend runs (spec §4.10.3): who says when its
    // stream bytes are consumed.
    let consumption = backend.consumption();
    // The backend runs for the bridge's whole life. `io` is MOVED into it and
    // is not `Clone`, so there is no second spawn to guard against.
    let resume_snapshots = io.resume_snapshots.clone();
    tokio::spawn(async move { backend.run(io).await });
    let mut link = BackendLink::new(io_inbound_tx, consumption);
    link.channel_output.snapshots = resume_snapshots;

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
    let now = Instant::now();
    let mut out: Vec<Datagram> = Vec::new();
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
                session_id: conn.session_id(),
                token,
                graceful: matches!(kind, CloseKind::Graceful),
            });
            return;
        }
    }

    loop {
        // While parked the connection is `Closed` (deaf, no timers), so poll
        // without a timeout.
        let next = if parked { None } else { conn.next_timeout() };
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
            c = control_rx.recv(), if control_open => Wakeup::Control(c),
            w = async {
                tokio::select! {
                    d = dgram_rx.recv() => Wakeup::Dgram(d),
                    _ = timer => Wakeup::Timeout,
                    o = backend_out_rx.recv(), if !link.channel_output.receive_fenced() => Wakeup::Backend(o),
                    _ = std::future::ready(()), if drain_pending => Wakeup::Drain,
                    // Room in the backend's queue for what waits (spec
                    // §4.10.2): the bridge never stands on its backend.
                    h = link.inbound.room(), if link.inbound.has_pending() => Wakeup::Room(h),
                }
            } => w,
        };

        let now = Instant::now();
        let mut out: Vec<Datagram> = Vec::new();
        // Screen streams whose gate opened on this turn before the refresh
        // at its end: that refresh finds them open already, and would not
        // say so.
        let mut writable: Vec<u8> = Vec::new();

        match wakeup {
            // Takes any `Attach` already queued first (see `on_routed_datagram`).
            Wakeup::Dgram(Some((src, bytes))) => {
                on_routed_datagram(
                    &mut conn,
                    &mut parked,
                    &mut control_rx,
                    &mut link,
                    &classes,
                    now,
                    src,
                    &bytes,
                    &mut out,
                );
            }
            // The manager dropped the datagram channel -- shut the backend down.
            Wakeup::Dgram(None) => break,
            // Nothing of its own: the timers run after every wake-up, below.
            Wakeup::Timeout | Wakeup::Drain => {}
            Wakeup::Backend(Some(
                message @ (SessionOutbound::ChannelOutput { .. }
                | SessionOutbound::ChannelExit { .. }
                | SessionOutbound::ChannelClosed { .. }
                | SessionOutbound::ResumeBarrier { .. }
                | SessionOutbound::RepaintBarrier { .. }),
            )) => {
                if conn.features().contains(crate::Features::CHANNEL_GEOMETRY) {
                    link.channel_output.push(message);
                    link.channel_output.seal_ended(&mut conn);
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
                awaiting_delivery.push((stream_id, token));
            }
            // What the backend took (spec §4.10.3): paid to the connection
            // that delivered it (see `ConsumptionLedger`).
            Wakeup::Backend(Some(SessionOutbound::Consumed { stream_id, n })) => {
                link.ledger.reported(&mut conn, now, stream_id, n, &mut out);
            }
            // The backend finished (the shell/tmux hybrid exited on its own):
            // tell the peer the session is over -- exactly as
            // `CloseKind::Graceful` below does for a Close it RECEIVED,
            // except here the bridge is the one INITIATING it, and this arm
            // returns at once instead of looping back to poll anything.
            // `conn.close(now)` is a no-op by its own guard if `conn` is
            // already `Closed` (a `parked` bridge, retained after an earlier
            // death for a possible warm reattach): that case is a
            // pre-existing wart (a retained entry can outlive a backend that
            // has nothing left to reattach to) and is not fixed here -- this
            // only makes sure a live peer, if there still is one, learns the
            // session ended instead of the connection idling forever with no
            // backend behind it.
            Wakeup::Backend(None) => {
                deactivate(&mut was_active, &active_count);
                out.extend(conn.close(now));
                send_all(&socket, &out).await;
                let _ = done_tx.send(SessionEnded {
                    session_id: conn.session_id(),
                    token,
                    graceful: true,
                });
                // Whatever waited goes to the backend first; a backend whose
                // io is gone with it takes nothing, and this ends at once.
                link.finish();
                return;
            }
            // Warm reattach (see `apply_control`); also revives a parked bridge.
            Wakeup::Control(Some(control)) => {
                apply_control(
                    &mut conn,
                    &mut parked,
                    &mut link,
                    control,
                    &classes,
                    now,
                    &mut out,
                );
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
        drain_pending = link.channel_output.drain(&mut conn, now, parked, &mut out);
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
        link.wait_below_pending_cap(&mut conn, &mut out).await;
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
                    session_id: conn.session_id(),
                    token,
                    graceful: true,
                });
                link.finish();
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
    // Withdraw this bridge's contribution to the active count -- `deactivate`
    // is a no-op here if a prior exit point (graceful close, or parking on
    // death) already cleared it.
    deactivate(&mut was_active, &active_count);
    // Signal the end; `on_session_ended`'s guard makes it harmless if the entry
    // was already evicted/replaced (it won't match, so it neither reclaims a
    // live entry nor wrongly re-retains). A send error means the router is
    // already gone (shutdown), which is fine.
    let _ = done_tx.send(SessionEnded {
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
}

impl Inbound {
    fn new(tx: mpsc::Sender<SessionInbound>) -> Self {
        Inbound {
            tx,
            pending: VecDeque::new(),
            pending_bytes: 0,
        }
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
}

/// The bridge's side of its backend (spec §4.10): what goes in, and what the
/// backend counts as having taken.
struct BackendLink {
    inbound: Inbound,
    ledger: ConsumptionLedger,
    channel_output: channel_bridge::ChannelBridge,
}

impl BackendLink {
    fn new(tx: mpsc::Sender<SessionInbound>, consumption: Consumption) -> Self {
        BackendLink {
            inbound: Inbound::new(tx),
            ledger: ConsumptionLedger::new(consumption),
            channel_output: channel_bridge::ChannelBridge::default(),
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
    async fn wait_below_pending_cap(&mut self, conn: &mut Connection, out: &mut Vec<Datagram>) {
        self.wait_below(PENDING_CAP, conn, out).await;
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
    fn finish(self) {
        let BackendLink { mut inbound, .. } = self;
        if !inbound.has_pending() {
            return;
        }
        tokio::spawn(async move {
            while inbound.has_pending() {
                let _ = inbound.room().await;
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
mod tests {
    use super::*;
    use crate::auth::{encode_auth_record, AuthError, AuthRecord, Principal};
    use crate::channel::{encode_client, ChannelKind, ClientRecord, OpenRequest, CONTROL_STREAM};
    use crate::channel_server::run_channel_session;
    use crate::conn::{AuthPolicy, Connection, ConnectionConfig, Consumption, Event, Role};
    use crate::cookie::{CookieCheck, LoadLimits, PROVEN_BURST, PROVEN_PER_SECOND};
    use crate::handshake::{generate_keypair, Handshake};
    use crate::handshake_payload::{
        encode_msg1, encode_msg1_without_tail, AuthMethod, Msg1Payload, StartKind,
    };
    use crate::paths::PathState;
    use crate::reliability::{StreamFrame, CREDIT_UPDATE_STEP, OFFSET_LIMIT, STREAM_WINDOW};
    use crate::wire::{
        encode_handshake, encode_handshake_init_cookie, encode_key_request, parse,
        parse_cookie_reply, parse_key_offer, Kind, COOKIE_LEN, VERSION,
    };
    use rand::Rng;
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    /// A mock backend that echoes stream 0 back on stream 0.
    struct EchoBackend;

    impl SessionBackend for EchoBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(StreamData { stream_id: 0, data }) = ev {
                        io.send(0, data);
                    }
                }
            })
        }
    }

    /// An echo backend that counts how many times it was SPAWNED (`run` called),
    /// via a shared `Arc<AtomicUsize>`. A warm reattach reuses the running
    /// backend (count unchanged); a cold replace spawns a fresh one (count +1).
    /// It ignores non-`Data` inbound events (`Live`, `ResumeReset`) and keeps
    /// looping, so a reattach's `ResumeReset` does not tear it down.
    struct CountingEchoBackend {
        spawns: Arc<AtomicUsize>,
    }

    impl SessionBackend for CountingEchoBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let spawns = self.spawns.clone();
            Box::pin(async move {
                spawns.fetch_add(1, Ordering::SeqCst);
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(StreamData { stream_id: 0, data }) = ev {
                        io.send(0, data);
                    }
                }
            })
        }
    }

    /// A backend that records the principal it was handed and ends at once.
    struct RecordingPrincipalBackend {
        seen: Arc<Mutex<Option<Principal>>>,
    }

    impl SessionBackend for RecordingPrincipalBackend {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            *self.seen.lock().unwrap() = Some(io.principal().clone());
            Box::pin(async {})
        }
    }

    /// The principal a test proof carries.
    fn test_principal() -> Principal {
        Principal {
            uid: 1000,
            name: "test".to_string(),
            identity: "SHA256:test".to_string(),
            incarnation: 0,
        }
    }

    /// A single session over two real loopback UDP sockets: a real client
    /// `Connection` handshakes with the manager, sends "ping" on stream 0, and
    /// the `EchoBackend` echoes it back. Guarded by a timeout so a stuck
    /// manager can't hang the suite.
    #[tokio::test]
    async fn single_session_echo_over_udp() {
        tokio::time::timeout(Duration::from_secs(5), run_single_session_echo())
            .await
            .expect("single_session_echo_over_udp timed out");
    }

    async fn run_single_session_echo() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        // Two real loopback sockets: one for the manager, one for the client.
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        // Start the manager with the echo backend; the client is allowlisted.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // A real client Connection driven manually over UDP.
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });

        // msg1 must carry a versioned payload -- `accept` requires it.
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [1u8; 16],
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;

        // Receive msg2 and complete the client handshake -> Live.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), src, &buf[..len]);
        send_client(&client_sock, &out).await;

        // Send "ping" on stream 0.
        let ping = client.send(Instant::now(), 0, b"ping");
        send_client(&client_sock, &ping).await;

        // Pump until the echoed StreamData comes back on stream 0.
        let echoed = loop {
            let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
            let out = client.on_datagram(Instant::now(), src, &buf[..len]);
            send_client(&client_sock, &out).await;
            let mut found = None;
            for ev in client.poll_events() {
                if let Event::StreamData { stream_id: 0, data } = ev {
                    found = Some(data);
                }
            }
            if let Some(d) = found {
                break d;
            }
        };
        assert_eq!(echoed, b"ping");
    }

    /// Send a batch of client datagrams over the real UDP socket.
    async fn send_client(sock: &UdpSocket, dgrams: &[Datagram]) {
        for dg in dgrams {
            sock.send_to(&dg.bytes, dg.to).await.unwrap();
        }
    }

    /// Two clients with DISTINCT tokens connect to one manager and each sends a
    /// distinct byte on stream 0. Each must get back ITS OWN byte (no
    /// cross-talk) and the two sessions must carry different `session_id`s.
    #[tokio::test]
    async fn two_tokens_get_independent_sessions() {
        tokio::time::timeout(Duration::from_secs(5), run_two_tokens())
            .await
            .expect("two_tokens_get_independent_sessions timed out");
    }

    async fn run_two_tokens() {
        let server_kp = generate_keypair();
        let client1_kp = generate_keypair();
        let client2_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        // Both client keys are allowlisted; the two tokens differ (= two devices).
        let allowlist: SharedAllowlist =
            Arc::new(Mutex::new(vec![client1_kp.public, client2_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let (echo1, sid1) = drive_client(
            server_addr,
            server_kp.public,
            client1_kp.private,
            [1u8; 16],
            0xA1,
        )
        .await;
        let (echo2, sid2) = drive_client(
            server_addr,
            server_kp.public,
            client2_kp.private,
            [2u8; 16],
            0xB2,
        )
        .await;

        assert_eq!(echo1, vec![0xA1], "client 1 must get back its own byte");
        assert_eq!(echo2, vec![0xB2], "client 2 must get back its own byte");
        assert_ne!(
            sid1, sid2,
            "the two sessions must have distinct session_ids"
        );
    }

    /// Drive one real client `Connection` through the handshake and a single
    /// echo round-trip over loopback UDP: handshake with `token`, send `byte`
    /// on stream 0, wait for the echo. Returns the echoed bytes and the
    /// negotiated `session_id`.
    async fn drive_client(
        server_addr: SocketAddr,
        server_pub: [u8; 32],
        client_priv: [u8; 32],
        token: [u8; 16],
        byte: u8,
    ) -> (Vec<u8>, u64) {
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });

        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token,
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;

        // Receive msg2 and complete the handshake -> Live; the negotiated
        // session_id is set on the client from msg2.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), src, &buf[..len]);
        send_client(&client_sock, &out).await;
        let session_id = client.session_id();

        // Send our distinct byte on stream 0.
        let ping = client.send(Instant::now(), 0, &[byte]);
        send_client(&client_sock, &ping).await;

        // Pump until the echoed StreamData comes back on stream 0.
        let echoed = loop {
            let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
            let out = client.on_datagram(Instant::now(), src, &buf[..len]);
            send_client(&client_sock, &out).await;
            let mut found = None;
            for ev in client.poll_events() {
                if let Event::StreamData { stream_id: 0, data } = ev {
                    found = Some(data);
                }
            }
            if let Some(d) = found {
                break d;
            }
        };
        (echoed, session_id)
    }

    /// Handshake a fresh client `Connection` to `Live` against the manager at
    /// `server_addr`, using `token`. Shared setup for the auth-before-replace
    /// regression tests below.
    async fn establish_live_client(
        server_addr: SocketAddr,
        server_pub: [u8; 32],
        client_priv: [u8; 32],
        token: [u8; 16],
    ) -> (Connection, UdpSocket) {
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token,
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;

        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), src, &buf[..len]);
        send_client(&client_sock, &out).await;
        (client, client_sock)
    }

    /// Pump `client_sock`/`client` until a `StreamData` event on stream 0 is
    /// delivered, forwarding any ACK/handshake bytes `on_datagram` produces
    /// along the way. Shared by the auth-before-replace regression tests below.
    async fn recv_echoed_stream0(
        client_sock: &UdpSocket,
        client: &mut Connection,
        buf: &mut [u8],
    ) -> Vec<u8> {
        loop {
            let (len, src) = client_sock.recv_from(buf).await.unwrap();
            let out = client.on_datagram(Instant::now(), src, &buf[..len]);
            send_client(client_sock, &out).await;
            for ev in client.poll_events() {
                if let Event::StreamData { stream_id: 0, data } = ev {
                    return data;
                }
            }
        }
    }

    /// REGRESSION LOCK for vulnerability #1 ("authenticate before session
    /// replacement"). Client A establishes a live session and echoes a first
    /// byte. An attacker then sends (a) a garbage `HandshakeInit` -- a
    /// well-formed wire header with a junk Noise body -- and (b) a REAL Noise
    /// handshake from a key that is NOT allowlisted, one that even claims A's
    /// own token in its payload. Both are dropped at `accept` (unparseable
    /// Noise body / non-allowlisted key) before they can reach any session
    /// logic, so A's live session is untouched: A still echoes a second byte
    /// and its `session_id` is unchanged.
    ///
    /// This proves the AUTH GATE, not "hijack detection." Now that warm
    /// reattach exists (see `warm_reattaches_to_same_backend`), an ALLOWLISTED
    /// Warm handshake with A's token would legitimately take over A's backend;
    /// the allowlist is precisely what stops a stranger from doing the same. The
    /// focused anti-hijack case -- a non-allowlisted key claiming A's token via
    /// the warm-reattach vector -- is locked by
    /// `non_allowlisted_cannot_hijack_via_reattach`.
    #[tokio::test]
    async fn stray_handshake_does_not_drop_live_session() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_stray_handshake_does_not_drop_live_session(),
        )
        .await
        .expect("stray_handshake_does_not_drop_live_session timed out");
    }

    async fn run_stray_handshake_does_not_drop_live_session() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let attacker_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let token_a = [7u8; 16];

        // Only the client is allowlisted -- the attacker's key is a stranger.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // Client A establishes a live session and echoes a first byte.
        let (mut client, client_sock) =
            establish_live_client(server_addr, server_kp.public, client_kp.private, token_a).await;
        let session_id_before = client.session_id();
        let mut buf = vec![0u8; RECV_BUF_LEN];

        let ping1 = client.send(Instant::now(), 0, &[1u8]);
        send_client(&client_sock, &ping1).await;
        let echoed1 = recv_echoed_stream0(&client_sock, &mut client, &mut buf).await;
        assert_eq!(echoed1, vec![1u8]);

        // Attacker (a): a garbage HandshakeInit -- well-formed wire header,
        // random junk Noise body that will not even parse as a handshake.
        let garbage = encode_handshake(Kind::HandshakeInit, &[0x41u8; 96]);
        attacker_sock.send_to(&garbage, server_addr).await.unwrap();

        // Attacker (b): a REAL Noise handshake from a non-allowlisted key,
        // claiming A's own token -- an attempted hijack of A's session.
        let mut attacker_hs = Handshake::new_initiator(&attacker_kp.private, &server_kp.public);
        let attacker_payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: token_a,
            method: AuthMethod::Allowlist,
        });
        let attacker_body = attacker_hs.write_msg(&attacker_payload);
        let attacker_init = encode_handshake(Kind::HandshakeInit, &attacker_body);
        attacker_sock
            .send_to(&attacker_init, server_addr)
            .await
            .unwrap();

        // Let the manager process both attack datagrams before probing A
        // again, so a latent bug has a chance to act before we check.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A's session must be untouched: still routable, same session_id.
        let ping2 = client.send(Instant::now(), 0, &[2u8]);
        send_client(&client_sock, &ping2).await;
        let echoed2 = recv_echoed_stream0(&client_sock, &mut client, &mut buf).await;
        assert_eq!(
            echoed2,
            vec![2u8],
            "A's session must still be routable after the stray handshakes"
        );
        assert_eq!(
            client.session_id(),
            session_id_before,
            "A's session_id must not have changed"
        );
    }

    /// REGRESSION LOCK for vulnerability #1's other half. A well-formed Noise
    /// `HandshakeInit` from a key that is NOT in the allowlist must create
    /// nothing: no msg2 reply comes back, and the manager's loop is left in a
    /// clean enough state that a legit client can still establish a fresh
    /// session right after (a black-box proof that no backend/session table
    /// entry was left behind for the attacker).
    #[tokio::test]
    async fn non_allowlisted_handshake_creates_no_session() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_non_allowlisted_handshake_creates_no_session(),
        )
        .await
        .expect("non_allowlisted_handshake_creates_no_session timed out");
    }

    async fn run_non_allowlisted_handshake_creates_no_session() {
        let server_kp = generate_keypair();
        let attacker_kp = generate_keypair();
        let legit_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        // Only `legit_kp` is allowlisted -- `attacker_kp` is a stranger.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![legit_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // A real, well-formed Noise handshake -- but from a non-allowlisted key.
        let mut attacker_hs = Handshake::new_initiator(&attacker_kp.private, &server_kp.public);
        let attacker_payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [9u8; 16],
            method: AuthMethod::Allowlist,
        });
        let attacker_body = attacker_hs.write_msg(&attacker_payload);
        let attacker_init = encode_handshake(Kind::HandshakeInit, &attacker_body);
        attacker_sock
            .send_to(&attacker_init, server_addr)
            .await
            .unwrap();

        // No msg2 -- or anything else -- comes back within a short bound.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let recv_result = tokio::time::timeout(
            Duration::from_millis(300),
            attacker_sock.recv_from(&mut buf),
        )
        .await;
        assert!(
            recv_result.is_err(),
            "a non-allowlisted HandshakeInit must not get any reply"
        );

        // The manager loop still works: a legit client can establish a fresh
        // session and echo, proving the attack left no stuck/ghost state.
        let (mut legit, legit_sock) =
            establish_live_client(server_addr, server_kp.public, legit_kp.private, [1u8; 16]).await;
        let ping = legit.send(Instant::now(), 0, &[5u8]);
        send_client(&legit_sock, &ping).await;
        let echoed = recv_echoed_stream0(&legit_sock, &mut legit, &mut buf).await;
        assert_eq!(echoed, vec![5u8]);
    }

    /// Handshake a fresh client `Connection` to `Live` with an explicit
    /// `start_kind` (Cold to create, Warm to reattach). Generalizes
    /// [`establish_live_client`] for the reattach/replace tests below; each call
    /// makes a NEW `Connection` (hence a NEW ephemeral key) on a NEW socket.
    async fn handshake_to_live(
        server_addr: SocketAddr,
        server_pub: [u8; 32],
        client_priv: [u8; 32],
        token: [u8; 16],
        start_kind: StartKind,
    ) -> (Connection, UdpSocket) {
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind,
            token,
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;

        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), src, &buf[..len]);
        send_client(&client_sock, &out).await;
        (client, client_sock)
    }

    /// Round-trip one byte on stream 0 through the echo backend, returning the
    /// echoed bytes.
    async fn echo_one(client: &mut Connection, client_sock: &UdpSocket, byte: u8) -> Vec<u8> {
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let ping = client.send(Instant::now(), 0, &[byte]);
        send_client(client_sock, &ping).await;
        recv_echoed_stream0(client_sock, client, &mut buf).await
    }

    /// A same-token WARM reconnect (new ephemeral key) REATTACHES to the still
    /// running backend rather than spawning a second one: the `CountingEchoBackend`
    /// spawn count stays 1, the reattached connection gets a NEW `session_id`, and
    /// echo still works over it.
    #[tokio::test]
    async fn warm_reattaches_to_same_backend() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_warm_reattaches_to_same_backend(),
        )
        .await
        .expect("warm_reattaches_to_same_backend timed out");
    }

    async fn run_warm_reattaches_to_same_backend() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [3u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // First (cold) connect: one backend spawned, echo works.
        let (mut c1, s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xAA).await, vec![0xAA]);
        let sid1 = c1.session_id();
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "one backend after first connect"
        );

        // Second connect: SAME token, start_kind=Warm, NEW ephemeral key -> reattach.
        let (mut c2, s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Warm,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xBB).await, vec![0xBB]);
        let sid2 = c2.session_id();

        assert_ne!(sid1, sid2, "warm reattach must allocate a new session_id");
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "warm reattach must NOT respawn the backend"
        );
    }

    /// Echoes stream-0 data (so `echo_one` proves it is alive) and records
    /// what `io.login()` reports both when it starts and on every
    /// `ResumeReset` -- the event a warm reattach delivers to the backend
    /// (see the module docs, "Persistent bridge, swappable connection").
    /// Exists to pin [`SessionIo::login`]'s one real property: it must keep
    /// reporting the SAME token across a roam even though `session_id`
    /// (proven by `warm_reattaches_to_same_backend`, just above) does not --
    /// a login-scoped resource (a PAM session, from a later task on) is
    /// exactly what depends on that.
    struct LoginRecordingEchoBackend {
        logins: Arc<Mutex<Vec<LoginId>>>,
    }

    impl SessionBackend for LoginRecordingEchoBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let logins = self.logins.clone();
            Box::pin(async move {
                logins.lock().unwrap().push(io.login());
                while let Some(ev) = io.recv().await {
                    match ev {
                        SessionInbound::Data(StreamData { stream_id: 0, data }) => {
                            io.send(0, data);
                        }
                        SessionInbound::ResumeReset(_) => {
                            logins.lock().unwrap().push(io.login());
                        }
                        _ => {}
                    }
                }
            })
        }
    }

    /// Poll `logins` until it holds at least `want` entries, up to two
    /// seconds -- the backend records on its own task, not observable the
    /// instant an event reaches it.
    async fn wait_for_logins(logins: &Arc<Mutex<Vec<LoginId>>>, want: usize) -> Vec<LoginId> {
        for _ in 0..100 {
            if logins.lock().unwrap().len() >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        logins.lock().unwrap().clone()
    }

    /// What this guards is narrower than "a warm reattach reuses the live
    /// backend" -- `warm_reattaches_to_same_backend`, just above, is what
    /// catches THAT regression (a warm start wrongly cold-replacing instead
    /// of reattaching still builds `login: token` from the very same token,
    /// so the value this test compares would not move even then; proven by
    /// mutating `AcceptDecision` for `StartKind::Warm` to `ColdReplace` --
    /// `warm_reattaches_to_same_backend` fails on its own spawn-count
    /// assertion, this test still passes).
    ///
    /// What IS this test's own property: that the `login` field a
    /// [`SessionIo`] carries is the router's device TOKEN and nothing
    /// session-scoped -- proven by mutating the one production line that
    /// sets it (`login: token` in `SessionManager::cold_create`) to anything
    /// else, which fails only this test, in the whole workspace. That is
    /// exactly the regression a later task's login-keyed resource (a PAM
    /// session) needs ruled out: swap `login` for something tied to the
    /// connection rather than the device, and every roam would silently
    /// mint a fresh key for it.
    #[tokio::test]
    async fn login_survives_a_warm_reattach() {
        tokio::time::timeout(Duration::from_secs(5), run_login_survives_a_warm_reattach())
            .await
            .expect("login_survives_a_warm_reattach timed out");
    }

    async fn run_login_survives_a_warm_reattach() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [6u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let logins = Arc::new(Mutex::new(Vec::new()));
        let factory = BackendFactory(Arc::new(LoginRecordingEchoBackend {
            logins: logins.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // First (cold) connect: the backend starts and records its login once.
        let (mut c1, s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xAA).await, vec![0xAA]);
        let sid1 = c1.session_id();

        // Second connect: SAME token, start_kind=Warm -> a warm reattach,
        // which delivers `ResumeReset` to the same, still-running backend.
        let (mut c2, s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Warm,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xBB).await, vec![0xBB]);
        let sid2 = c2.session_id();
        assert_ne!(sid1, sid2, "a warm reattach must allocate a new session_id");

        let recorded = wait_for_logins(&logins, 2).await;
        assert_eq!(
            recorded,
            vec![token, token],
            "SessionIo::login() must report the same token before and after a warm reattach, \
             even though session_id changed"
        );
    }

    /// A same-token COLD reconnect REPLACES the backend: the old one is torn down
    /// and a fresh one is spawned, so the spawn count goes to 2. (This is where a
    /// device deliberately starts a new terminal.)
    #[tokio::test]
    async fn cold_replaces_backend_for_same_token() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_cold_replaces_backend_for_same_token(),
        )
        .await
        .expect("cold_replaces_backend_for_same_token timed out");
    }

    async fn run_cold_replaces_backend_for_same_token() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [4u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let (mut c1, s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xAA).await, vec![0xAA]);
        let sid1 = c1.session_id();
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "one backend after first connect"
        );

        // Second connect: SAME token, start_kind=Cold -> replace (respawn).
        let (mut c2, s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xBB).await, vec![0xBB]);
        let sid2 = c2.session_id();

        assert_ne!(sid1, sid2, "cold replace must allocate a new session_id");
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "cold replace must tear down the old backend and spawn a fresh one"
        );
    }

    /// An exact msg1 retransmit (same ephemeral key + same token, byte-identical
    /// datagram delivered twice) is idempotent: the manager recognizes the
    /// duplicate and re-sends the ORIGINAL msg2 (same `session_id`) rather than
    /// minting a new session. So exactly ONE backend is spawned AND the client's
    /// live route survives -- proven by completing the handshake and echoing a
    /// byte AFTER the duplicate. (Against the buggy repoint-on-retransmit code
    /// the client's Transport frames hit no route and this echo hangs to the
    /// 5s timeout.)
    #[tokio::test]
    async fn msg1_retransmit_is_idempotent() {
        tokio::time::timeout(Duration::from_secs(5), run_msg1_retransmit_is_idempotent())
            .await
            .expect("msg1_retransmit_is_idempotent timed out");
    }

    async fn run_msg1_retransmit_is_idempotent() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // Build ONE real cold msg1 and deliver the SAME datagram twice. Because a
        // `Connection` fixes its ephemeral key at `start`, the two datagrams are
        // byte-identical -- a true retransmit.
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [5u8; 16],
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;
        send_client(&client_sock, &m1).await; // exact retransmit

        // Complete the handshake: the client goes Live on the first msg2 and
        // fixes its session_id; a duplicate msg2 (from the retransmit) is
        // ignored. Both msg2s must carry the SAME session_id, or the route would
        // no longer point at the client.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, addr) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), addr, &buf[..len]);
        send_client(&client_sock, &out).await;

        // The route must survive the retransmit: echo a byte on stream 0 and
        // get it back. Against repoint-on-retransmit this hangs (frames for the
        // client's session_id hit no route) and the test times out.
        let echoed = echo_one(&mut client, &client_sock, 0x5A).await;
        assert_eq!(
            echoed,
            vec![0x5A],
            "the live route must survive a byte-identical retransmit"
        );

        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "a retransmitted msg1 must not create a second backend"
        );
    }

    /// REGRESSION LOCK (anti-hijack): now that warm reattach exists, an
    /// allowlisted Warm handshake with a live token DOES take over the backend --
    /// so the allowlist is the ONLY thing standing between an attacker and a
    /// victim's session. A NON-allowlisted attacker who knows/guesses the
    /// victim's token and sends a WARM handshake claiming it is `Rejected` by
    /// `accept` BEFORE any reattach decision: the victim's backend is not
    /// respawned or reattached, the victim's session stays routable with an
    /// unchanged `session_id`, and the attacker gets no msg2.
    #[tokio::test]
    async fn non_allowlisted_cannot_hijack_via_reattach() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_non_allowlisted_cannot_hijack_via_reattach(),
        )
        .await
        .expect("non_allowlisted_cannot_hijack_via_reattach timed out");
    }

    async fn run_non_allowlisted_cannot_hijack_via_reattach() {
        let server_kp = generate_keypair();
        let victim_kp = generate_keypair();
        let attacker_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let token = [8u8; 16];

        // Only the victim is allowlisted; the attacker's key is a stranger.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![victim_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // Victim establishes a live session and echoes a first byte.
        let (mut victim, victim_sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            victim_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut victim, &victim_sock, 0x11).await, vec![0x11]);
        let sid_before = victim.session_id();
        assert_eq!(spawns.load(Ordering::SeqCst), 1);

        // Attacker: a REAL, well-formed WARM Noise handshake from a
        // NON-allowlisted key, claiming the victim's token -- the reattach
        // hijack vector.
        let mut attacker_hs = Handshake::new_initiator(&attacker_kp.private, &server_kp.public);
        let attacker_payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Warm,
            token,
            method: AuthMethod::Allowlist,
        });
        let attacker_body = attacker_hs.write_msg(&attacker_payload);
        let attacker_init = encode_handshake(Kind::HandshakeInit, &attacker_body);
        attacker_sock
            .send_to(&attacker_init, server_addr)
            .await
            .unwrap();

        // No msg2 comes back to the attacker within a short bound.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let reply = tokio::time::timeout(
            Duration::from_millis(300),
            attacker_sock.recv_from(&mut buf),
        )
        .await;
        assert!(
            reply.is_err(),
            "a non-allowlisted Warm handshake must get no msg2"
        );

        // The victim's backend was neither respawned nor reattached, and its
        // session is still routable with the same session_id.
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "the attacker must not cause a reattach or respawn"
        );
        assert_eq!(echo_one(&mut victim, &victim_sock, 0x22).await, vec![0x22]);
        assert_eq!(
            victim.session_id(),
            sid_before,
            "the victim's session_id must be unchanged"
        );
    }

    // --- backend/PTY lifecycle ---

    /// A backend that counts both SPAWNS (`run` called) and TEARDOWNS (the run
    /// future ENDS -- reached only when the bridge drops its inbound channel, so
    /// `io.recv()` returns `None`). A retained backend keeps looping (no
    /// teardown); a torn-down backend's future ends (teardown +1).
    struct TeardownCountingBackend {
        spawns: Arc<AtomicUsize>,
        teardowns: Arc<AtomicUsize>,
    }

    impl SessionBackend for TeardownCountingBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let spawns = self.spawns.clone();
            let teardowns = self.teardowns.clone();
            Box::pin(async move {
                spawns.fetch_add(1, Ordering::SeqCst);
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(StreamData { stream_id: 0, data }) = ev {
                        io.send(0, data);
                    }
                }
                teardowns.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    /// What `begin_probation` leaves behind for a probation under
    /// `session_id`: its route in the table, and the queue behind it for the
    /// `ProvenSession` a test builds by hand.
    fn register_provisional_route(router: &mut Router, session_id: u64) -> DgramRx {
        let (tx, rx) = dgram_queue();
        router.sessions.insert(session_id, tx);
        rx
    }

    /// Build a synthetic Live backend entry for the router policy tests, plus a
    /// dgram route registered in `sessions`. The channels' receivers are
    /// returned so the caller can keep them alive (dropping them would close the
    /// senders, which the policy logic never sends on but which we keep tidy).
    /// A placeholder all-zero `client_key` -- tests that care about the key
    /// (scrub-on-end) use [`synthetic_live_entry_with_key`] instead.
    #[allow(clippy::type_complexity)]
    fn synthetic_live_entry(
        router: &mut Router,
        token: [u8; 16],
        session_id: u64,
    ) -> (mpsc::UnboundedReceiver<BridgeControl>, DgramRx) {
        synthetic_live_entry_with_key(router, token, session_id, [0u8; 32])
    }

    /// Like [`synthetic_live_entry`], but with an explicit `client_key` -- for
    /// tests that assert on which key `on_session_ended` reports for scrubbing.
    #[allow(clippy::type_complexity)]
    fn synthetic_live_entry_with_key(
        router: &mut Router,
        token: [u8; 16],
        session_id: u64,
        client_key: [u8; 32],
    ) -> (mpsc::UnboundedReceiver<BridgeControl>, DgramRx) {
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (dg_tx, dg_rx) = dgram_queue();
        router.sessions.insert(session_id, dg_tx);
        router.backends.insert(
            token,
            BackendEntry {
                session_id,
                control: ctl_tx,
                last_msg1_body: Vec::new(),
                msg2: Vec::new(),
                client_key,
                state: EntryState::Live,
                parked_dgram: None,
                // Placeholder owner: 0. Tests that care about ownership
                // overwrite `.owner` on the returned entry afterward, and
                // the same goes for `.incarnation`.
                owner: 0,
                incarnation: 0,
            },
        );
        (ctl_rx, dg_rx)
    }

    /// A client's graceful `Close` tears the backend down IMMEDIATELY: the
    /// backend's run future ends (teardown +1) rather than being retained. Real
    /// client over loopback UDP; not a policy-only test.
    #[tokio::test]
    async fn graceful_close_tears_down_immediately() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_graceful_close_tears_down_immediately(),
        )
        .await
        .expect("graceful_close_tears_down_immediately timed out");
    }

    async fn run_graceful_close_tears_down_immediately() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [21u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let teardowns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(TeardownCountingBackend {
            spawns: spawns.clone(),
            teardowns: teardowns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // Establish a live session and confirm echo works.
        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut client, &sock, 0xAA).await, vec![0xAA]);
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
        assert_eq!(
            teardowns.load(Ordering::SeqCst),
            0,
            "backend must still be running before Close"
        );

        // The client gracefully closes: send a Close frame on the wire.
        let close = client.close(Instant::now());
        send_client(&sock, &close).await;

        // The backend must be torn down PROMPTLY (its run future ends).
        let torn_down = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if teardowns.load(Ordering::SeqCst) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            torn_down.is_ok(),
            "a graceful Close must tear the backend down immediately, not retain it"
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "no respawn on close");
    }

    /// A backend that echoes the first byte it receives once, then ends its
    /// own `run` future -- standing in for a shell/tmux hybrid that runs one
    /// command and exits on its own, exactly the case `Wakeup::Backend(None)`
    /// exists to handle. Distinct from `TeardownCountingBackend`, which only
    /// ends when the MANAGER drops `io` (`io.recv()` returning `None`): this
    /// one ends on its own initiative while the connection is still Live.
    struct SelfEndingBackend {
        spawns: Arc<AtomicUsize>,
    }

    impl SessionBackend for SelfEndingBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let spawns = self.spawns.clone();
            Box::pin(async move {
                spawns.fetch_add(1, Ordering::SeqCst);
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(StreamData { stream_id: 0, data }) = ev {
                        io.send(0, data);
                        return;
                    }
                }
            })
        }
    }

    /// `Wakeup::Backend(None)` (the backend ending on its own -- NOT a
    /// received `Close` and NOT the manager tearing the session down) must
    /// behave like a graceful close: the peer sees `LinkState::Closed`, and
    /// the entry is REMOVED rather than retained -- a same-token reconnect
    /// spawns a FRESH backend instead of reviving the dead one (mirroring
    /// how `graceful_session_end_removes_entry_immediately` locks the same
    /// `graceful: true` consequence at the router-table level; this is the
    /// integration side, proving `Wakeup::Backend(None)` actually produces
    /// that signal in the first place).
    ///
    /// Regression lock for the bug `cli/tests/pty_session.rs` caught end to
    /// end: before the fix, this arm only stopped polling that channel, so
    /// the connection idled forever with no backend behind it, and a `qsh`
    /// client whose remote shell exited would hang instead of exiting 0.
    #[tokio::test]
    async fn backend_ending_on_its_own_closes_and_does_not_retain() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_backend_ending_on_its_own_closes_and_does_not_retain(),
        )
        .await
        .expect("backend_ending_on_its_own_closes_and_does_not_retain timed out");
    }

    async fn run_backend_ending_on_its_own_closes_and_does_not_retain() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [23u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        // A handle kept for re-adding the key after it is scrubbed below --
        // `allowlist_auth` takes the `Arc` itself, but cloning an `Arc` still
        // shares the same underlying `Mutex<Vec<_>>`.
        let allowlist_handle = allowlist.clone();
        let spawns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(SelfEndingBackend {
            spawns: spawns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(spawns.load(Ordering::SeqCst), 1);

        // One byte in: the backend echoes it once -- like the shell's last
        // bit of output -- then ends its own `run` future on the spot.
        assert_eq!(echo_one(&mut client, &sock, 0xAA).await, vec![0xAA]);

        // The peer must be told: `LinkState::Closed`, not silence.
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let (len, src) = sock.recv_from(&mut buf).await.unwrap();
                let out = client.on_datagram(Instant::now(), src, &buf[..len]);
                send_client(&sock, &out).await;
                for ev in client.poll_events() {
                    if matches!(ev, Event::StateChanged(LinkState::Closed)) {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "a backend that ends on its own must close the connection, not \
             leave it idling with no backend behind it"
        );

        // The manager's self-cleaning allowlist
        // scrubbed the client's key the moment its session ended -- exactly
        // as it would for any other ended session, graceful or not. Put it
        // back, as a real client's next signature would: this test's point
        // is the ENTRY's fate, not authentication, and this stand-in
        // `Allowlist` auth (unlike `qshd serve`'s real per-attempt signature
        // check) would otherwise silently refuse the reconnect below.
        //
        // Wait for the scrub to land BEFORE re-adding: it is driven by the
        // same `SessionEnded` signal the peer's `Closed` above came from,
        // but on the manager's task rather than the wire, so the two are
        // not ordered against each other. `remove_from_allowlist` retains
        // by inequality -- it would drop a copy pushed too early too, and
        // the reconnect below would then hang on a refused handshake.
        let scrubbed = tokio::time::timeout(Duration::from_secs(2), async {
            while allowlist_handle.lock().unwrap().contains(&client_kp.public) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            scrubbed.is_ok(),
            "an ended session must scrub its key off the shared allowlist"
        );
        allowlist_handle.lock().unwrap().push(client_kp.public);

        // Not retained: a same-token reconnect (even one asking to warm-
        // reattach) must spawn a FRESH backend rather than reviving the
        // (already-gone) old one -- `resolve()` finds no entry for the
        // token at all once it has been removed, so it spawns fresh
        // regardless of the requested `StartKind`.
        let (_client2, _sock2) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Warm,
        )
        .await;
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "the ended backend's entry must be removed, not retained -- a \
             reconnect must spawn a fresh backend, not revive a dead one"
        );
    }

    /// The server tells the client whether it got its own session back or a
    /// fresh one. The client cannot work this out for itself: an unknown
    /// token is answered with a new session and no complaint, which looks
    /// exactly like a resume from outside. A console client that guesses
    /// wrong either opens a second shell in a session that already has one,
    /// or waits for a channel list that is never coming.
    #[tokio::test]
    async fn msg2_says_whether_the_session_was_resumed() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            BackendFactory(Arc::new(EchoBackend)),
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let token = [42u8; 16];
        let (first, _s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert!(
            !first.resumed(),
            "a cold start creates a session, so there is nothing to have resumed"
        );

        let (second, _s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Warm,
        )
        .await;
        assert!(
            second.resumed(),
            "the same token, asked for warm, is the session the client left"
        );

        let (stranger, _s3) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            [7u8; 16],
            StartKind::Warm,
        )
        .await;
        assert!(
            !stranger.resumed(),
            "a token the server never saw gets a fresh session, and must say so"
        );
    }

    /// The consequence `driver_std::tests::detach_does_not_send_close_frame`
    /// establishes at the wire level, followed through to the session
    /// manager: a client that goes silent WITHOUT sending a `Close` frame
    /// (exactly what `StdClient::detach()` produces) must NOT have its
    /// backend torn down -- the mirror image of `graceful_close_tears_down_immediately`
    /// above. Real client over loopback UDP, same harness; the only
    /// difference is the teardown step sends nothing instead of a `Close`
    /// frame.
    ///
    /// This exercises the same `conn.rs` closed-vs-retained machinery
    /// `StdClient::detach()` relies on (`Connection::closed_gracefully`) without
    /// spinning up the std-thread driver inside this async test -- the
    /// driver-level test already proves `detach()` itself produces this exact
    /// "no Close frame" wire behavior; this test proves what the session
    /// manager does in response to it.
    #[tokio::test]
    async fn detach_like_silence_retains_backend() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_detach_like_silence_retains_backend(),
        )
        .await
        .expect("detach_like_silence_retains_backend timed out");
    }

    async fn run_detach_like_silence_retains_backend() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [22u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let teardowns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(TeardownCountingBackend {
            spawns: spawns.clone(),
            teardowns: teardowns.clone(),
        }));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // Establish a live session and confirm echo works.
        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut client, &sock, 0xBB).await, vec![0xBB]);
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
        assert_eq!(
            teardowns.load(Ordering::SeqCst),
            0,
            "backend must still be running before the client goes silent"
        );

        // The client detaches: unlike `close()` (above), NOTHING goes out --
        // just drop the connection state and the socket, like
        // `StdClient::detach()`'s driver thread exiting without calling
        // `Connection::close`.
        drop(sock);
        drop(client);

        // Give the manager a real window to notice and (wrongly, if the fix
        // regresses) tear the backend down. Comfortably below any liveness
        // timeout (`CLIENT_DEATH_AFTER` is 45s) -- silence alone must never
        // cause an immediate teardown the way a Close frame does.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            teardowns.load(Ordering::SeqCst),
            0,
            "silence (no Close frame) must NOT tear the backend down immediately, \
             unlike a graceful Close -- it must stay retained for a warm reattach"
        );
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            1,
            "no respawn while retained"
        );
    }

    /// A graceful end (a received Close -> `SessionEnded{graceful:true}`) tears
    /// the entry down at the POLICY level immediately: both the `sessions` route
    /// and the `backends` entry are removed, and it is NOT retained. (The
    /// integration test above observes the backend future ending; this locks the
    /// router-table side that an out-of-loop test can't inspect.)
    #[tokio::test(start_paused = true)]
    async fn graceful_session_end_removes_entry_immediately() {
        let mut router = Router::new();
        let token = [41u8; 16];
        let sid = 200u64;
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, sid);

        router.on_session_ended(
            SessionEnded {
                session_id: sid,
                token,
                graceful: true,
            },
            tokio::time::Instant::now(),
        );
        assert!(
            !router.backends.contains_key(&token),
            "a graceful end must remove the backend entry, not retain it"
        );
        assert!(
            !router.sessions.contains_key(&sid),
            "a graceful end must remove the session route"
        );
    }

    /// An unexpected death (non-graceful SessionEnded) RETAINS the backend; a
    /// warm reattach within the retention window revives it; past
    /// `RETAIN_AFTER_DEATH` with no reconnect, GC tears it down. Policy-level:
    /// synthetic end-signals + advanced tokio time (no real 45 s death).
    #[tokio::test(start_paused = true)]
    async fn unexpected_death_retains_then_gc() {
        let mut router = Router::new();
        let token = [31u8; 16];
        let sid = 100u64;
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, sid);

        // Death (non-graceful): the entry is RETAINED (backend not torn down);
        // the live route is removed but its dgram sender is parked.
        let t0 = tokio::time::Instant::now();
        router.on_session_ended(
            SessionEnded {
                session_id: sid,
                token,
                graceful: false,
            },
            t0,
        );
        assert!(
            router.backends.contains_key(&token),
            "an unexpected death must NOT tear the backend down"
        );
        assert!(
            matches!(
                router.backends.get(&token).unwrap().state,
                EntryState::Retained { .. }
            ),
            "the entry must be Retained after a death"
        );
        assert!(
            !router.sessions.contains_key(&sid),
            "the dead session route must be removed"
        );
        assert!(
            router.backends.get(&token).unwrap().parked_dgram.is_some(),
            "the stable dgram sender must be parked to survive retention"
        );

        // Well within the retention window: GC leaves it alone.
        tokio::time::advance(Duration::from_secs(1800)).await;
        router.gc_retained(tokio::time::Instant::now());
        assert!(
            router.backends.contains_key(&token),
            "GC must not evict a still-fresh retained entry"
        );

        // A warm reattach revives it: state back to Live, new route registered.
        let new_sid = 101u64;
        let dg_tx = router
            .take_stable_route(&token)
            .expect("retained entry must own its parked route");
        router.rebind(
            &token,
            Rebind {
                session_id: new_sid,
                dgram: dg_tx,
                msg1_body: b"m1",
                msg2: Vec::new(),
                client_key: [0u8; 32],
                incarnation: 0,
            },
        );
        assert!(matches!(
            router.backends.get(&token).unwrap().state,
            EntryState::Live
        ));
        assert!(
            router.sessions.contains_key(&new_sid),
            "revive must register the new session route"
        );
        assert_eq!(router.backends.get(&token).unwrap().session_id, new_sid);

        // It dies again and this time no one reconnects: past RETAIN_AFTER_DEATH,
        // GC tears it down.
        let t1 = tokio::time::Instant::now();
        router.on_session_ended(
            SessionEnded {
                session_id: new_sid,
                token,
                graceful: false,
            },
            t1,
        );
        assert!(matches!(
            router.backends.get(&token).unwrap().state,
            EntryState::Retained { .. }
        ));
        tokio::time::advance(RETAIN_AFTER_DEATH + Duration::from_secs(1)).await;
        router.gc_retained(tokio::time::Instant::now());
        assert!(
            !router.backends.contains_key(&token),
            "GC must tear down a retained entry past RETAIN_AFTER_DEATH"
        );
    }

    /// All three ways a backend disappears end the login: a graceful close, the
    /// GC past RETAIN_AFTER_DEATH, and the eviction that makes room for someone
    /// else. A path that forgets to tell leaves the helper trusting a uid whose
    /// owner is long gone.
    #[tokio::test(start_paused = true)]
    async fn every_way_a_backend_disappears_ends_its_login() {
        // (1) A graceful close.
        let mut router = Router::new();
        let graceful = [1u8; 16];
        let (_ctl, _dg) = synthetic_live_entry(&mut router, graceful, 1);
        router.on_session_ended(
            SessionEnded {
                session_id: 1,
                token: graceful,
                graceful: true,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(
            router.take_ended_logins(),
            vec![graceful],
            "a graceful close ends the login"
        );

        // (2) The GC, once a retained entry is past RETAIN_AFTER_DEATH.
        let retained = [2u8; 16];
        let (_ctl2, _dg2) = synthetic_live_entry(&mut router, retained, 2);
        router.on_session_ended(
            SessionEnded {
                session_id: 2,
                token: retained,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert!(
            router.take_ended_logins().is_empty(),
            "a retained entry may still come back"
        );
        tokio::time::advance(RETAIN_AFTER_DEATH + Duration::from_secs(1)).await;
        router.gc_retained(tokio::time::Instant::now());
        assert_eq!(
            router.take_ended_logins(),
            vec![retained],
            "the GC ends the login it tore down"
        );

        // (3) The eviction that makes room for a new login.
        let evicted = [3u8; 16];
        let (_ctl3, _dg3) = synthetic_live_entry(&mut router, evicted, 3);
        router.on_session_ended(
            SessionEnded {
                session_id: 3,
                token: evicted,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert!(
            router.evict_oldest_retained(None),
            "there is a retained entry to evict"
        );
        assert_eq!(
            router.take_ended_logins(),
            vec![evicted],
            "an eviction ends the login too"
        );
    }

    /// A `LoginSink` that remembers every login it was ever told about, in
    /// order, and never forgets (unlike `Router::take_ended_logins`, which
    /// drains) -- so a test can check the record grows exactly when
    /// expected. Fix-round F1: `every_way_a_backend_disappears_ends_its_login`
    /// proves the router's own accumulator sees every ended login, but
    /// nothing proved that accumulator actually reaches `ServerAuth.logins`
    /// -- all three `notify_ended_logins` call sites could be (and were,
    /// under review) deleted with the whole workspace staying green.
    #[derive(Default)]
    struct RecordingLogins(Mutex<Vec<LoginId>>);

    impl RecordingLogins {
        fn recorded(&self) -> Vec<LoginId> {
            self.0.lock().unwrap().clone()
        }
    }

    impl LoginSink for RecordingLogins {
        fn login_ended(&self, login: LoginId) {
            self.0.lock().unwrap().push(login);
        }
    }

    /// The two `*_and_notify` wrappers reachable without the full admission
    /// machinery: a graceful close and a GC teardown must each reach
    /// `ServerAuth.logins`, not merely `Router::take_ended_logins()` (which
    /// `every_way_a_backend_disappears_ends_its_login` already pins). The
    /// third wrapper, `admit_new_backend_or_end_login`, is proven through the
    /// real `apply_decision` call in
    /// `apply_decision_cold_create_tells_the_sink_about_an_eviction` and
    /// `apply_decision_cold_create_ends_the_login_it_refuses` below.
    #[tokio::test(start_paused = true)]
    async fn the_sink_hears_a_graceful_close_and_a_gc_teardown() {
        let sink = Arc::new(RecordingLogins::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: None,
            server_pub: [0u8; 32],
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: sink.clone(),
        };
        let mut router = Router::new();

        // A graceful close.
        let graceful = [7u8; 16];
        let (_ctl, _dg) = synthetic_live_entry(&mut router, graceful, 1);
        on_session_ended_and_notify(
            &mut router,
            &auth,
            SessionEnded {
                session_id: 1,
                token: graceful,
                graceful: true,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(
            sink.recorded(),
            vec![graceful],
            "a graceful close must reach ServerAuth.logins, not just Router's own accumulator"
        );

        // The GC, once a retained entry is past RETAIN_AFTER_DEATH.
        let retained = [8u8; 16];
        let (_ctl2, _dg2) = synthetic_live_entry(&mut router, retained, 2);
        on_session_ended_and_notify(
            &mut router,
            &auth,
            SessionEnded {
                session_id: 2,
                token: retained,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(
            sink.recorded(),
            vec![graceful],
            "a retained entry may still come back -- no second record yet"
        );
        tokio::time::advance(RETAIN_AFTER_DEATH + Duration::from_secs(1)).await;
        gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
        assert_eq!(
            sink.recorded(),
            vec![graceful, retained],
            "the GC's teardown must reach ServerAuth.logins too"
        );
    }

    /// A login reported over from OUTSIDE takes its LIVE session down -- and
    /// the datagram ROUTE is the half that matters. Dropping the entry alone
    /// only drops the bridge's control channel, which a live bridge reacts
    /// to by merely not polling that arm any more (`Wakeup::Control(None)`);
    /// what actually ends it is its `dgram_rx` reaching end-of-file
    /// (`Wakeup::Dgram(None)`), and that sender lives in `sessions`, not in
    /// the entry. Delete the `sessions.remove` line from `Router::end_login`
    /// and this assertion fails -- together with the full-stack test below,
    /// which is the point of it: without that line a live bridge never ends
    /// at all, so neither does its backend. Measured, not assumed.
    #[tokio::test]
    async fn a_login_ended_from_outside_takes_its_live_session_with_it() {
        let mut router = Router::new();
        let token = [31u8; 16];
        let (mut ctl_rx, mut dg_rx) = synthetic_live_entry(&mut router, token, 1);

        assert!(
            router.end_login(token, 0),
            "a login with a session must report that there was one to end"
        );

        assert!(
            !router.backends.contains_key(&token),
            "the entry must be gone"
        );
        // BOUNDED, both of them. A channel whose sender is still alive
        // never yields and never closes, so a bare `recv().await` here does
        // not fail when the route is left behind -- it hangs, and this file
        // has no per-test timeout. Caught by running exactly that mutation.
        assert_eq!(
            closed_within(dg_rx.recv()).await,
            Some(None),
            "the bridge's datagram route must be closed -- that is what ends a LIVE bridge"
        );
        assert_eq!(
            closed_within(ctl_rx.recv()).await.map(|c| c.is_none()),
            Some(true),
            "and its control channel with it"
        );
    }

    /// How long [`closed_within`] gives a channel to report itself closed.
    /// Generous next to the zero work involved -- the sender is either
    /// already dropped or it is not -- and short enough that a regression
    /// fails a test rather than holding the run.
    const CHANNEL_CLOSE_WAIT: Duration = Duration::from_secs(2);

    /// `Some(what the channel gave)` if it gave anything within
    /// [`CHANNEL_CLOSE_WAIT`], `None` if it just sat there. A `recv` that
    /// never resolves is what an un-dropped sender looks like, and it must
    /// show up as a failing assertion rather than a run that never returns.
    async fn closed_within<T>(recv: impl Future<Output = T>) -> Option<T> {
        tokio::time::timeout(CHANNEL_CLOSE_WAIT, recv).await.ok()
    }

    /// The news came FROM the sink, so it must not go back to it: the
    /// router's own accumulator stays empty. An echo would be redundant at
    /// best and destructive at worst -- by the time it arrived the client
    /// may have proved itself again under the same token, and the helper's
    /// FRESH entry for it is what the echo would end. See
    /// `Router::end_login`.
    #[tokio::test]
    async fn a_login_ended_from_outside_is_not_reported_back() {
        let mut router = Router::new();
        let token = [32u8; 16];
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);

        router.end_login(token, 0);

        assert!(
            router.take_ended_logins().is_empty(),
            "the sink told us this login ended; telling it back would end the entry a fresh \
             proof has since made"
        );
    }

    /// A report for a login with no session is ordinary, not an error: the
    /// report and the session's own end race by nature.
    #[tokio::test]
    async fn a_login_ended_from_outside_with_no_session_left_is_harmless() {
        let mut router = Router::new();
        assert!(
            !router.end_login([33u8; 16], 0),
            "there was nothing to end, and saying so is the whole of it"
        );
    }

    /// **The run this whole comparison exists for.** A report written while
    /// one life of a login was alive is taken off the queue only after the
    /// same device has proved itself again and been given a session -- which
    /// nothing in the worker prevents: the report and the admission cross on
    /// separate sockets, are read by separate threads, and meet in an
    /// unbiased `select!`. The fresh session must survive it.
    ///
    /// Modelled at the router, where the decision is, and in the order the
    /// run produces: the old life ends for real, a fresh one binds, and only
    /// then does the old life's report arrive.
    ///
    /// Delete the incarnation comparison from `Router::end_login` and this
    /// test fails on its own assertion: the fresh entry goes, its datagram
    /// route with it, and -- because this path deliberately reports nothing
    /// back -- the helper is left holding an established login with no
    /// session, whose monitor and PAM session nothing expires.
    #[tokio::test]
    async fn a_report_about_a_replaced_login_leaves_the_fresh_session_alone() {
        let mut router = Router::new();
        let token = [35u8; 16];

        // The first life: admitted under incarnation 5, and genuinely over.
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        router.backends.get_mut(&token).expect("entry").incarnation = 5;
        assert!(
            router.end_login(token, 5),
            "setup: the report about the life that really ended must be acted on"
        );

        // The same device proves itself again while that life's report is
        // still queued: a fresh entry, under a fresh incarnation.
        let (mut ctl_rx, mut dg_rx) = synthetic_live_entry(&mut router, token, 2);
        router.backends.get_mut(&token).expect("entry").incarnation = 6;

        // And now the stale report lands.
        assert!(
            !router.end_login(token, 5),
            "a report about a login that has already been replaced must be dropped"
        );

        assert_eq!(
            router
                .backends
                .get(&token)
                .map(|e| (e.session_id, e.incarnation)),
            Some((2, 6)),
            "the session the device has now must survive a report about the one it had before"
        );
        assert!(
            router.sessions.contains_key(&2),
            "and so must its datagram route -- removing that is what kills a live bridge"
        );
        // `Empty`, not merely `is_err()`. A channel that is open and idle
        // and one whose sender has been dropped BOTH answer `Err` here, so
        // `is_err()` is true in the case this assertion exists to exclude
        // -- it could not fail. Nothing bites today, because the entry is
        // still in the table and still owns both senders; the assertion
        // would simply have stopped noticing if it ever were not.
        assert!(
            matches!(
                dg_rx.try_recv_or_why(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "its bridge must not have been torn down: the datagram route is still open"
        );
        assert!(
            matches!(ctl_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "nor its control channel"
        );
    }

    /// The other half of the same rule, so that "drop a stale report" cannot
    /// be satisfied by dropping every report: the incarnation the session
    /// was admitted under is acted on, which is the ORDINARY case and the
    /// one the whole notice exists for.
    #[tokio::test]
    async fn a_report_about_the_login_the_session_has_is_acted_on() {
        let mut router = Router::new();
        let token = [36u8; 16];
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        router.backends.get_mut(&token).expect("entry").incarnation = 6;

        assert!(
            router.end_login(token, 6),
            "equal is the same life of the same login, and must end its session"
        );
        assert!(
            !router.backends.contains_key(&token),
            "the entry must be gone"
        );
    }

    /// The reporter holds what it was built to hold and no more, and it
    /// never drops a report quietly: past the bound it says so, naming the
    /// bound, and the caller decides (the system mode's worker ends itself).
    #[tokio::test]
    async fn a_reporter_that_cannot_keep_a_login_end_says_so() {
        let (reporter, reports) = login_end_channel(2);
        assert_eq!(reporter.report([1u8; 16], 1), Ok(()));
        assert_eq!(reporter.report([2u8; 16], 1), Ok(()));
        assert_eq!(
            reporter.report([3u8; 16], 1),
            Err(LoginEndNotReported::Queued(2)),
            "past the bound the news must come back, not vanish"
        );

        drop(reports);
        assert_eq!(
            reporter.report([4u8; 16], 1),
            Err(LoginEndNotReported::RouterGone),
            "and a router that is gone is a different answer from a queue that is full"
        );
    }

    /// The whole path, through the real `serve` loop and a real client over
    /// loopback UDP: a login reported ended from outside tears its backend
    /// down (teardown +1), where a graceful `Close` is not involved at all.
    /// This is what pins the `select!` arm itself -- delete it and every
    /// `Router::end_login` test above stays green.
    #[tokio::test]
    async fn a_login_ended_from_outside_tears_down_its_backend_through_serve() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_a_login_ended_from_outside_tears_down_its_backend_through_serve(),
        )
        .await
        .expect("a_login_ended_from_outside_tears_down_its_backend_through_serve timed out");
    }

    async fn run_a_login_ended_from_outside_tears_down_its_backend_through_serve() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [34u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let spawns = Arc::new(AtomicUsize::new(0));
        let teardowns = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(TeardownCountingBackend {
            spawns: spawns.clone(),
            teardowns: teardowns.clone(),
        }));
        let (reporter, reports) = login_end_channel(8);
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            reports,
        ));

        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut client, &sock, 0xAA).await, vec![0xAA]);
        assert_eq!(
            teardowns.load(Ordering::SeqCst),
            0,
            "setup: the backend must still be running"
        );

        reporter.report(token, 0).expect("the router is listening");

        let torn_down = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if teardowns.load(Ordering::SeqCst) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            torn_down.is_ok(),
            "a login reported over from outside must end its session, or the person sees a \
             channel that will not open rather than a disconnect"
        );
        assert_eq!(spawns.load(Ordering::SeqCst), 1, "and nothing respawns");
    }

    /// The hardest of the three sites to keep honest by accident:
    /// `apply_decision`'s `ColdCreate` arm, reached through the REAL
    /// admission-handling code (not a synthetic call to
    /// `admit_new_backend_and_notify` alone), on a table that must evict a
    /// retained entry to make room. Built the way this file's other
    /// `apply_decision`-adjacent tests build a `ManagerCtx` and an admitted
    /// connection (see `a_proof_whose_twin_already_bound_the_entry_adopts_nothing`
    /// and `a_warm_reattach_by_another_account_leaves_the_session_alone`
    /// below), except calling `apply_decision` directly with
    /// `AcceptDecision::ColdCreate` rather than routing through
    /// `on_probation_ended`.
    #[tokio::test(start_paused = true)]
    async fn apply_decision_cold_create_tells_the_sink_about_an_eviction() {
        const FRESH_OWNER: u32 = 9999;
        let mut router = Router::new();
        let mut keep_alive = Vec::new();

        // One retained entry (the victim), and the rest Live up to the
        // total cap, each its own owner -- same shape as
        // `cap_evicts_oldest_retained`'s Case 1, just one retained entry
        // rather than two (only need one victim here).
        let victim = [1u8; 16];
        let (c, d) = synthetic_live_entry(&mut router, victim, 1);
        router.backends.get_mut(&victim).expect("entry").owner = 1;
        keep_alive.push((c, d));
        router.on_session_ended(
            SessionEnded {
                session_id: 1,
                token: victim,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        for i in 0..(MAX_SESSIONS_TOTAL - 1) {
            let token = [(10 + i) as u8; 16];
            let sid = (10 + i) as u64;
            let (c, d) = synthetic_live_entry(&mut router, token, sid);
            router.backends.get_mut(&token).expect("entry").owner = (100 + i) as u32;
            keep_alive.push((c, d));
        }
        assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL);

        let sink = Arc::new(RecordingLogins::default());
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: sink.clone(),
        };
        let spawned = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let admission = Admission {
            conn: Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::SshSignature,
            }),
            client_key: [9u8; 32],
            msg1: Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Cold,
                token: [200u8; 16],
                method: AuthMethod::SshSignature,
            },
            msg1_body: b"a fresh admission for a fresh token".to_vec(),
            out: Vec::new(),
            src: "127.0.0.1:9999".parse().unwrap(),
            start: BridgeStart::default(),
            nonce: [0u8; AUTH_NONCE_LEN],
            principal: Principal {
                uid: FRESH_OWNER,
                name: "fresh".to_string(),
                identity: "SHA256:fresh".to_string(),
                incarnation: 0,
            },
            route: None,
        };

        SessionManager::apply_decision(&ctx, &mut router, AcceptDecision::ColdCreate, admission)
            .await;

        assert_eq!(
            sink.recorded(),
            vec![victim],
            "apply_decision's ColdCreate eviction must tell ServerAuth.logins about the login \
             it just ended, not just Router's own accumulator"
        );
    }

    /// Fix round 2's Critical, its prompt half: an `apply_decision`
    /// `ColdCreate` that the session caps REFUSE must report the refused
    /// token's own login as ended. The client's proof created that login's
    /// entry in the system mode's helper one round trip earlier
    /// (`Request::Verify`), no backend will ever exist for this token, and
    /// `Router::forget_backend` -- the only other thing that ever ends a
    /// login -- can never fire for a token that never had an entry. Left
    /// unreported, the entry keeps its account verified in the PRIVILEGED
    /// process until the daemon restarts.
    ///
    /// Every entry here is LIVE (the eviction test above keeps one
    /// Retained), so admission has nothing to evict and rejects. The two
    /// tests discriminate each other: an implementation that notified on
    /// EVERY ColdCreate, admitted or not, passes this one and fails the
    /// eviction test's exact `vec![victim]`.
    #[tokio::test(start_paused = true)]
    async fn apply_decision_cold_create_ends_the_login_it_refuses() {
        const FRESH_OWNER: u32 = 9999;
        const REFUSED: LoginId = [200u8; 16];
        let mut router = Router::new();
        let mut keep_alive = Vec::new();

        // Full to the daemon-wide ceiling, every entry Live and each its
        // own owner: the caller is well under its OWN cap, so it is the
        // total ceiling that blocks, and with nothing Retained there is
        // nothing to evict.
        for i in 0..MAX_SESSIONS_TOTAL {
            let token = [(10 + i) as u8; 16];
            let sid = (10 + i) as u64;
            let (c, d) = synthetic_live_entry(&mut router, token, sid);
            router.backends.get_mut(&token).expect("entry").owner = (100 + i) as u32;
            keep_alive.push((c, d));
        }
        assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL);

        let sink = Arc::new(RecordingLogins::default());
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: sink.clone(),
        };
        let spawned = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let admission = Admission {
            conn: Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::SshSignature,
            }),
            client_key: [9u8; 32],
            msg1: Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Cold,
                token: REFUSED,
                method: AuthMethod::SshSignature,
            },
            msg1_body: b"an admission the caps will refuse".to_vec(),
            out: Vec::new(),
            src: "127.0.0.1:9999".parse().unwrap(),
            start: BridgeStart::default(),
            nonce: [0u8; AUTH_NONCE_LEN],
            principal: Principal {
                uid: FRESH_OWNER,
                name: "fresh".to_string(),
                identity: "SHA256:fresh".to_string(),
                incarnation: 0,
            },
            route: None,
        };

        SessionManager::apply_decision(&ctx, &mut router, AcceptDecision::ColdCreate, admission)
            .await;

        assert_eq!(
            sink.recorded(),
            vec![REFUSED],
            "a ColdCreate the session caps refuse must tell ServerAuth.logins that the refused \
             token's own login is over -- nothing else can ever report it"
        );
        assert!(
            !router.backends.contains_key(&REFUSED),
            "setup: the admission really was refused -- no entry exists for its token"
        );
        assert_eq!(
            spawned.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "setup: a refused admission spawns no backend"
        );
    }

    /// A stale end-signal (its `session_id` no longer matches the entry -- a
    /// swapped-out connection, a replaced token, or a teardown-exit of an
    /// already-evicted entry) must be IGNORED: it must neither remove nor retain
    /// the CURRENT live entry. Locks the `session_id` guard.
    #[tokio::test(start_paused = true)]
    async fn stale_end_signal_leaves_current_entry_untouched() {
        let mut router = Router::new();
        let token = [51u8; 16];
        let current_sid = 300u64;
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, current_sid);

        // A stale (older) session_id for the same token.
        router.on_session_ended(
            SessionEnded {
                session_id: 299u64,
                token,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert!(
            matches!(router.backends.get(&token).unwrap().state, EntryState::Live),
            "a stale end-signal must not retain the current live entry"
        );
        assert!(
            router.sessions.contains_key(&current_sid),
            "a stale end-signal must not drop the current live route"
        );
    }

    /// At the session cap, admitting a NEW backend evicts the OLDEST retained
    /// entry; if every entry is Live, the new session is rejected. Policy-level
    /// with advanced tokio time to order the retained entries by `since`.
    #[tokio::test(start_paused = true)]
    async fn cap_evicts_oldest_retained() {
        // This test is about the TOTAL ceiling, not the per-owner one, so
        // every entry below gets its own distinct owner -- otherwise filling
        // the table would trip `MAX_SESSIONS_PER_OWNER` long before it trips
        // `MAX_SESSIONS_TOTAL`, and the eviction path below would never run.
        // The admission itself is attempted for yet another fresh owner
        // (9999), who owns nothing yet and so is nowhere near its own cap.
        const FRESH_OWNER: u32 = 9999;

        // Case 1: a mix with several retained entries -- the OLDEST retained is
        // evicted to make room.
        let mut router = Router::new();
        let mut keep_alive = Vec::new();

        // Two retained entries with distinct `since` (oldest first).
        let oldest = [1u8; 16];
        let (c, d) = synthetic_live_entry(&mut router, oldest, 1);
        router.backends.get_mut(&oldest).expect("entry").owner = 1;
        keep_alive.push((c, d));
        let t_oldest = tokio::time::Instant::now();
        router.on_session_ended(
            SessionEnded {
                session_id: 1,
                token: oldest,
                graceful: false,
            },
            t_oldest,
        );

        tokio::time::advance(Duration::from_secs(10)).await;
        let newer_retained = [2u8; 16];
        let (c, d) = synthetic_live_entry(&mut router, newer_retained, 2);
        router
            .backends
            .get_mut(&newer_retained)
            .expect("entry")
            .owner = 2;
        keep_alive.push((c, d));
        let t_newer = tokio::time::Instant::now();
        router.on_session_ended(
            SessionEnded {
                session_id: 2,
                token: newer_retained,
                graceful: false,
            },
            t_newer,
        );

        // Fill the rest with Live entries up to the cap, each its own owner.
        for i in 0..(MAX_SESSIONS_TOTAL - 2) {
            let token = [(10 + i) as u8; 16];
            let sid = (10 + i) as u64;
            let (c, d) = synthetic_live_entry(&mut router, token, sid);
            router.backends.get_mut(&token).expect("entry").owner = (100 + i) as u32;
            keep_alive.push((c, d));
        }
        assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL);

        // Admitting a new backend evicts the OLDEST retained entry.
        assert!(
            router.admit_new_backend(FRESH_OWNER),
            "admission must succeed by evicting a retained entry"
        );
        assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL - 1);
        assert!(
            !router.backends.contains_key(&oldest),
            "the OLDEST retained entry must be evicted"
        );
        assert!(
            router.backends.contains_key(&newer_retained),
            "a newer retained entry must survive"
        );

        // Case 2: every entry is Live -- admission is REJECTED (no eviction).
        let mut full = Router::new();
        let mut keep2 = Vec::new();
        for i in 0..MAX_SESSIONS_TOTAL {
            let token = [(40 + i) as u8; 16];
            let sid = (40 + i) as u64;
            let (c, d) = synthetic_live_entry(&mut full, token, sid);
            full.backends.get_mut(&token).expect("entry").owner = (1000 + i) as u32;
            keep2.push((c, d));
        }
        assert_eq!(full.backends.len(), MAX_SESSIONS_TOTAL);
        assert!(
            !full.admit_new_backend(FRESH_OWNER),
            "with every entry Live, a new session must be rejected"
        );
        assert_eq!(
            full.backends.len(),
            MAX_SESSIONS_TOTAL,
            "a rejected admission must not evict anything"
        );
    }

    // --- live, self-cleaning allowlist ---

    /// A key added to `shared_allowlist` AFTER the manager is already running
    /// is honored by a subsequent handshake, WITHOUT restarting the manager:
    /// `handle_datagram` snapshots the live allowlist on every `HandshakeInit`.
    /// First, a handshake from a not-yet-allowlisted key is
    /// rejected (no msg2); the key is then pushed onto the SAME
    /// `Arc<Mutex<Vec>>` mid-run; a FRESH handshake with that key succeeds and
    /// echoes.
    #[tokio::test]
    async fn live_added_key_is_accepted_without_restart() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_live_added_key_is_accepted_without_restart(),
        )
        .await
        .expect("live_added_key_is_accepted_without_restart timed out");
    }

    async fn run_live_added_key_is_accepted_without_restart() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [71u8; 16];

        // The manager starts with an EMPTY allowlist -- the client's key is a
        // stranger at first.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(Vec::new()));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist.clone(), server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // First attempt (real Noise handshake, not-yet-allowlisted key): no
        // msg2 comes back within a short bound.
        let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut hs = Handshake::new_initiator(&client_kp.private, &server_kp.public);
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token,
            method: AuthMethod::Allowlist,
        });
        let body = hs.write_msg(&payload);
        let init = encode_handshake(Kind::HandshakeInit, &body);
        attacker_sock.send_to(&init, server_addr).await.unwrap();
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let reply = tokio::time::timeout(
            Duration::from_millis(300),
            attacker_sock.recv_from(&mut buf),
        )
        .await;
        assert!(reply.is_err(), "a not-yet-allowlisted key must be rejected");

        // Add the key to the SHARED allowlist mid-run -- no manager restart.
        allowlist.lock().unwrap().push(client_kp.public);

        // A FRESH handshake (new client Connection, same static key) now
        // succeeds and echoes.
        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(
            echo_one(&mut client, &sock, 0x9A).await,
            vec![0x9A],
            "a key added live must be honored without restarting the manager"
        );
    }

    /// A graceful `Close` scrubs the ended connection's key off the SHARED
    /// allowlist: the same real-UDP setup as
    /// `graceful_close_tears_down_immediately`, but asserting on the allowlist
    /// rather than the backend's teardown. An unrelated key already in the
    /// allowlist survives untouched.
    #[tokio::test]
    async fn graceful_close_removes_key_from_shared_allowlist() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_graceful_close_removes_key_from_shared_allowlist(),
        )
        .await
        .expect("graceful_close_removes_key_from_shared_allowlist timed out");
    }

    async fn run_graceful_close_removes_key_from_shared_allowlist() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let unrelated_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [72u8; 16];

        let allowlist: SharedAllowlist =
            Arc::new(Mutex::new(vec![client_kp.public, unrelated_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist.clone(), server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let (mut client, sock) = handshake_to_live(
            server_addr,
            server_kp.public,
            client_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut client, &sock, 0xAA).await, vec![0xAA]);
        assert!(
            allowlist.lock().unwrap().contains(&client_kp.public),
            "the client's key must be allowlisted while its session is live"
        );

        // The client gracefully closes.
        let close = client.close(Instant::now());
        send_client(&sock, &close).await;

        // The key must be scrubbed PROMPTLY; poll with a bound so a latent bug
        // fails the test instead of hanging it.
        let scrubbed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !allowlist.lock().unwrap().contains(&client_kp.public) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            scrubbed.is_ok(),
            "a graceful Close must scrub the ended connection's key from the shared allowlist"
        );
        assert!(
            allowlist.lock().unwrap().contains(&unrelated_kp.public),
            "an unrelated key must survive untouched"
        );
    }

    /// A graceful session end scrubs the ended connection's `client_key` off a
    /// SHARED allowlist: `on_session_ended` returns the key, the
    /// caller removes it. Router-policy level (mirrors
    /// `graceful_session_end_removes_entry_immediately`, but asserts on the
    /// allowlist instead of the entry table).
    #[tokio::test(start_paused = true)]
    async fn graceful_end_scrubs_key_from_shared_allowlist() {
        let mut router = Router::new();
        let token = [81u8; 16];
        let sid = 700u64;
        let key = [91u8; 32];
        let other_key = [92u8; 32];
        let (_ctl_rx, _dg_rx) = synthetic_live_entry_with_key(&mut router, token, sid, key);

        let shared: SharedAllowlist = Arc::new(Mutex::new(vec![key, other_key]));
        let ended = router.on_session_ended(
            SessionEnded {
                session_id: sid,
                token,
                graceful: true,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(
            ended,
            Some(key),
            "a graceful end must report the ended connection's key"
        );
        remove_from_allowlist(&shared, &ended.unwrap());

        assert!(
            !shared.lock().unwrap().contains(&key),
            "a graceful end must scrub the key from the shared allowlist"
        );
        assert!(
            shared.lock().unwrap().contains(&other_key),
            "an unrelated key must survive untouched"
        );
    }

    /// The death/retain path ALSO scrubs the ended connection's key off the
    /// SHARED allowlist -- even though the `BackendEntry` itself is RETAINED
    /// (not torn down), waiting for a warm reconnect. A genuine warm reconnect
    /// mints a fresh key via `ADD-CLIENT` before its handshake, so removing
    /// the OLD key here does not block a later legitimate reattach (see
    /// `unexpected_death_retains_then_gc`, which locks the entry-retention
    /// side of this same event).
    #[tokio::test(start_paused = true)]
    async fn death_retain_scrubs_key_from_shared_allowlist() {
        let mut router = Router::new();
        let token = [82u8; 16];
        let sid = 701u64;
        let key = [93u8; 32];
        let (_ctl_rx, _dg_rx) = synthetic_live_entry_with_key(&mut router, token, sid, key);

        let shared: SharedAllowlist = Arc::new(Mutex::new(vec![key]));
        let ended = router.on_session_ended(
            SessionEnded {
                session_id: sid,
                token,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(
            ended,
            Some(key),
            "a death/retain end must ALSO report the ended connection's key"
        );
        remove_from_allowlist(&shared, &ended.unwrap());

        assert!(
            !shared.lock().unwrap().contains(&key),
            "the death/retain path must scrub the key from the shared allowlist"
        );
        assert!(
            router.backends.contains_key(&token),
            "the backend entry itself must still be RETAINED, not torn down"
        );
    }

    // --- scrub the SUPERSEDED key on warm reattach / cold replace ---

    /// `scrub_superseded_key` must NOT remove a key the new connection ALSO
    /// authenticated with (the common case: a device reusing its persistent
    /// static key across an ephemeral-only reconnect) -- only a DIFFERING old
    /// key gets scrubbed. Locks the guard directly, independent of the
    /// integration tests below.
    #[test]
    fn scrub_superseded_key_keeps_key_shared_by_old_and_new() {
        let key = [77u8; 32];
        let shared: SharedAllowlist = Arc::new(Mutex::new(vec![key]));
        scrub_superseded_key(&shared, Some(key), key);
        assert!(
            shared.lock().unwrap().contains(&key),
            "the SAME key must not be stripped just because it superseded itself"
        );
    }

    /// `scrub_superseded_key` is a no-op when there was nothing to supersede
    /// (a genuine cold create, `old_key: None`).
    #[test]
    fn scrub_superseded_key_is_noop_for_pure_cold_create() {
        let key = [78u8; 32];
        let shared: SharedAllowlist = Arc::new(Mutex::new(vec![key]));
        scrub_superseded_key(&shared, None, key);
        assert!(shared.lock().unwrap().contains(&key));
    }

    /// The gap the fix closes: a warm reattach with a DISTINCT NEW key (the
    /// "mint a fresh key via `ADD-CLIENT` before reconnecting" design)
    /// must scrub the OLD superseded key off the shared allowlist WHILE
    /// the old entry is still `Live` -- i.e. BEFORE any `DEATH_AFTER`, so a
    /// plain `SessionEnded`-driven scrub (which is never emitted for the
    /// superseded connection in a fast roam) cannot be the one doing it. The
    /// NEW key remains allowlisted and the reattached session still echoes.
    #[tokio::test]
    async fn warm_reattach_with_new_key_scrubs_old_key_from_shared_allowlist() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_warm_reattach_with_new_key_scrubs_old_key_from_shared_allowlist(),
        )
        .await
        .expect("warm_reattach_with_new_key_scrubs_old_key_from_shared_allowlist timed out");
    }

    async fn run_warm_reattach_with_new_key_scrubs_old_key_from_shared_allowlist() {
        let server_kp = generate_keypair();
        let old_kp = generate_keypair();
        let new_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [95u8; 16];

        // Both keys are allowlisted upfront -- the NEW key models a fresh
        // `ADD-CLIENT` mint made before the reconnect handshakes in.
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![old_kp.public, new_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist.clone(), server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        // First (cold) connect with the OLD key -- still Live, well before
        // any DEATH_AFTER.
        let (mut c1, s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            old_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xAA).await, vec![0xAA]);
        assert!(allowlist.lock().unwrap().contains(&old_kp.public));

        // Warm reattach: SAME token, NEW key.
        let (mut c2, s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            new_kp.private,
            token,
            StartKind::Warm,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xBB).await, vec![0xBB]);

        assert!(
            !allowlist.lock().unwrap().contains(&old_kp.public),
            "the OLD superseded key must be scrubbed from the shared allowlist"
        );
        assert!(
            allowlist.lock().unwrap().contains(&new_kp.public),
            "the NEW key must remain allowlisted"
        );
    }

    /// Same gap, the COLD replace path: a deliberate cold restart with a
    /// DISTINCT new key on the same token ALSO scrubs the old superseded key
    /// (shares the `cold_create` insert-return mechanism with the
    /// warm-reattach-fallback and pure-cold-create paths).
    #[tokio::test]
    async fn cold_replace_with_new_key_scrubs_old_key_from_shared_allowlist() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_cold_replace_with_new_key_scrubs_old_key_from_shared_allowlist(),
        )
        .await
        .expect("cold_replace_with_new_key_scrubs_old_key_from_shared_allowlist timed out");
    }

    async fn run_cold_replace_with_new_key_scrubs_old_key_from_shared_allowlist() {
        let server_kp = generate_keypair();
        let old_kp = generate_keypair();
        let new_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let token = [96u8; 16];

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![old_kp.public, new_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist.clone(), server_kp.public),
            factory,
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));

        let (mut c1, s1) = handshake_to_live(
            server_addr,
            server_kp.public,
            old_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xAA).await, vec![0xAA]);

        // Cold replace: SAME token, start_kind=Cold, NEW key.
        let (mut c2, s2) = handshake_to_live(
            server_addr,
            server_kp.public,
            new_kp.private,
            token,
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xBB).await, vec![0xBB]);

        assert!(
            !allowlist.lock().unwrap().contains(&old_kp.public),
            "the OLD superseded key must be scrubbed from the shared allowlist"
        );
        assert!(
            allowlist.lock().unwrap().contains(&new_kp.public),
            "the NEW key must remain allowlisted"
        );
    }

    /// A client that completes the handshake and exchanges a byte is within
    /// `ACTIVE_WINDOW` of its last authenticated receive, so the manager's
    /// shared `active_count` must reflect it. Mirrors the setup of
    /// `run_single_session_echo`.
    #[tokio::test]
    async fn active_count_reflects_recent_traffic() {
        tokio::time::timeout(
            Duration::from_secs(5),
            run_active_count_reflects_recent_traffic(),
        )
        .await
        .expect("active_count_reflects_recent_traffic timed out");
    }

    async fn run_active_count_reflects_recent_traffic() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();

        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client_kp.public]));
        let factory = BackendFactory(Arc::new(EchoBackend));
        let active = Arc::new(AtomicUsize::new(0));
        tokio::spawn(SessionManager::serve(
            server_sock.clone(),
            server_kp.private,
            allowlist_auth(allowlist, server_kp.public),
            factory,
            active.clone(),
            LoginEndedReports::none(),
        ));

        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });

        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [7u8; 16],
            method: AuthMethod::Allowlist,
        });
        let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
        send_client(&client_sock, &m1).await;

        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
        let out = client.on_datagram(Instant::now(), src, &buf[..len]);
        send_client(&client_sock, &out).await;

        // A byte on stream 0 wakes the bridge (Wakeup::Dgram), which recomputes
        // activity right after its send_all -- give it a moment to land.
        let ping = client.send(Instant::now(), 0, b"ping");
        send_client(&client_sock, &ping).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(
            active.load(Ordering::SeqCst),
            1,
            "a live client counts as active"
        );
    }

    /// Pure unit coverage for the activity predicate itself -- including the
    /// direction that drives the bridge's decrement (see
    /// `active_count_reflects_recent_traffic` above for the increment side,
    /// which a real `ACTIVE_WINDOW`-long sleep would make needlessly slow to
    /// exercise end-to-end).
    #[test]
    fn is_active_predicate_marks_the_active_to_inactive_boundary() {
        assert!(is_active(Duration::from_secs(0)), "no idle time is active");
        assert!(
            is_active(super::ACTIVE_WINDOW),
            "exactly at the window boundary is still active"
        );
        assert!(
            !is_active(super::ACTIVE_WINDOW + Duration::from_millis(1)),
            "one tick past the window is no longer active -- this is what drives the decrement"
        );
    }

    /// Fix-round-1 finding: `run_backend_bridge` withdraws its contribution to
    /// `active_count` at FOUR points (the backend finishing on its own, a
    /// graceful close, parking on an unexpected death, and the final
    /// post-loop teardown) -- the parking one precisely because parking stops
    /// the loop's own recompute from ever running again. Those
    /// paths share `deactivate`, and what this test pins is the IDEMPOTENCE
    /// they rely on: calling `deactivate` twice must decrement the shared
    /// atomic exactly ONCE, which is what protects the death path from
    /// double-decrementing against the loop's normal per-wakeup recompute.
    ///
    /// That the death path CALLS it at all is a different claim, and this
    /// test cannot make it -- it builds by hand exactly the state that call
    /// site would have produced. See
    /// `a_session_that_dies_while_active_stops_counting_as_active`, which
    /// drives a real non-graceful death instead. (`tokio::time::pause` /
    /// `advance` is no help there: `SERVER_DEATH_AFTER` is 24h of real
    /// `std::time::Instant`, which the test clock cannot fast-forward. What
    /// makes it reachable is the connection's own liveness budget,
    /// `Connection::set_death_after`.)
    #[test]
    fn deactivate_withdraws_exactly_once() {
        let active_count = AtomicUsize::new(1);
        let mut was_active = true;

        deactivate(&mut was_active, &active_count);
        assert_eq!(
            active_count.load(Ordering::SeqCst),
            0,
            "the first call withdraws"
        );
        assert!(!was_active);

        // A second call -- e.g. the loop's own recompute seeing `!parked` right
        // after the death handler already parked and deactivated -- must be a
        // no-op, or a live session elsewhere would be phantom-decremented.
        deactivate(&mut was_active, &active_count);
        assert_eq!(
            active_count.load(Ordering::SeqCst),
            0,
            "a second call on an already-inactive bridge must not double-decrement"
        );
    }

    /// A session that dies while it is being used stops counting as active
    /// AT THAT MOMENT, not eventually.
    ///
    /// The bridge withdraws its contribution to `active_count` at four points
    /// -- the backend finishing on its own, a graceful close, parking on an
    /// unexpected death, and the post-loop teardown -- and this is the one
    /// nothing witnessed. Once parked, the connection
    /// is deaf and has no timers, so the loop's per-wakeup recompute never
    /// runs again -- with the withdrawal gone, the dead session keeps
    /// counting as active until GC tears the retained entry down, up to
    /// `RETAIN_AFTER_DEATH` (an hour) later. `active_count` is what the
    /// daemon reports in its `STATUS` answer, the "is anyone still using this
    /// daemon" question the self-update path consults, so a phantom active
    /// session makes an idle daemon look busy and blocks its own update.
    ///
    /// A REAL death, not a stand-in for one. The bridge is handed a genuine
    /// accepted server connection whose liveness budget is this test's own
    /// (`Connection::set_death_after`, the per-connection override of the
    /// role's own budget), so `on_timeout` closes it
    /// non-gracefully in a fraction of a second rather than after
    /// `SERVER_DEATH_AFTER`'s 24 hours.
    ///
    /// Two things keep it honest. The `SessionEnded { graceful: false }` it
    /// waits for is what tells the PARKING path apart from the graceful-close
    /// and teardown-exit paths, which withdraw the count at their own,
    /// separate statements; and the test holds both the datagram and the
    /// control sender, so the bridge really parks rather than exiting the
    /// loop -- the post-loop withdrawal cannot stand in for the one under
    /// test. The withdrawal is made before the end-signal is sent, so
    /// receiving it means the decrement has already happened.
    #[tokio::test]
    async fn a_session_that_dies_while_active_stops_counting_as_active() {
        /// Long enough for the bridge to be counted in first, short enough
        /// to wait out in a test.
        const DEATH_AFTER: Duration = Duration::from_millis(300);

        // The one relation this test's validity rests on, asserted rather
        // than assumed. On the wakeup the death lands on, the loop's ordinary
        // recompute (`!parked && is_active(idle)`) runs FIRST; it must still
        // find the session active, or it would withdraw the contribution
        // itself and the assertion at the end would pass with the statement
        // under test deleted. That holds exactly while the death budget stays
        // inside `ACTIVE_WINDOW` -- sixteen-fold today, but nothing else
        // would notice if that ever inverted.
        assert!(
            DEATH_AFTER < super::ACTIVE_WINDOW,
            "the death budget must stay well inside ACTIVE_WINDOW ({:?}), or the ordinary \
             recompute withdraws the contribution before the statement this test is about does",
            super::ACTIVE_WINDOW
        );

        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        // Nothing listens there: the silence that follows is what kills the
        // connection.
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();

        // A real msg1 from a real client, so the server connection below is
        // one `accept` produced rather than one assembled by hand.
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [11u8; 16],
            method: AuthMethod::Allowlist,
        });
        let msg1 = client.start_with_payload(Instant::now(), peer, &payload);
        // `accept` reads the Noise message itself, which is what follows the
        // wire header -- the same unwrapping the manager's own datagram path
        // does before it calls `accept`.
        let Frame::Handshake {
            body: msg1_body, ..
        } = parse(&msg1[0].bytes).expect("a client's first datagram is a valid frame")
        else {
            panic!("a client's first datagram is a handshake");
        };
        let mut resolve = |_: &Msg1Payload| {
            Some(Msg2Inputs {
                resumed: false,
                nonce: [0u8; AUTH_NONCE_LEN],
            })
        };
        let outcome = Connection::accept(
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            },
            Instant::now(),
            peer,
            msg1_body,
            &mut resolve,
        );
        let AcceptOutcome::Accepted { mut conn, .. } = outcome else {
            panic!("the handshake this test builds must be accepted");
        };
        conn.set_death_after(DEATH_AFTER);

        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (dg_tx, dg_rx) = dgram_queue();
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let active = Arc::new(AtomicUsize::new(0));
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token: [11u8; 16],
            backend: Arc::new(EchoBackend),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: [11u8; 16],
                gates: Arc::new(GateTable::new()),
            },
            start: BridgeStart {
                saw_live: false,
                early: Vec::new(),
            },
            active_count: active.clone(),
            gates: Arc::new(GateTable::new()),
        }));

        // Wake the bridge once while the connection is still alive, so its
        // recompute counts this session in. Without this the death itself
        // would be the first wakeup, increment and withdrawal would fall in
        // the same iteration, and the assertion below could not tell a
        // withdrawal from a session that was never counted at all. The bytes
        // are not a datagram this connection can read, which is the point:
        // they wake the loop and change nothing else.
        assert!(
            dg_tx.send(peer, b"wake up".to_vec()),
            "the bridge is listening"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while active.load(Ordering::SeqCst) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a live session must count as active, or this test proves nothing about the end");

        let ended = tokio::time::timeout(Duration::from_secs(5), done_rx.recv())
            .await
            .expect("the connection must die within its own liveness budget")
            .expect("the bridge must signal the end of its session");
        assert!(
            !ended.graceful,
            "a connection nobody answers dies rather than closing gracefully -- the graceful path \
             withdraws the count at a different statement"
        );
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "a session that died while active must stop counting at once: parked, nothing ever \
             wakes the bridge to recompute, so it would stay 'active' until GC tears it down up \
             to RETAIN_AFTER_DEATH later"
        );
    }

    /// `drain_events` must forward a server-side `Event::OutputResync` to the
    /// backend as `SessionInbound::Repaint`, and ONLY that -- exactly one
    /// `Repaint`, nothing else queued on the inbound channel. Drives a real
    /// `Connection` whose event queue was seeded via the test-only
    /// `push_test_event` (see its doc: reproducing the full roam/timeout
    /// scenario that normally produces `OutputResync` is unnecessary to
    /// cover the manager's own forwarding logic).
    #[tokio::test]
    async fn output_resync_event_forwards_repaint_to_backend() {
        let kp = generate_keypair();
        let mut conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        conn.push_test_event(Event::OutputResync);

        let (tx, mut rx) = mpsc::channel::<SessionInbound>(4);
        let mut first_live_sent = false;
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut out = Vec::new();
        let kind = drain_events(
            &mut conn,
            &mut link,
            &mut first_live_sent,
            Instant::now(),
            &mut out,
        );

        assert!(
            matches!(kind, CloseKind::None),
            "no Closed event was queued"
        );
        assert!(
            matches!(rx.try_recv(), Ok(SessionInbound::Repaint)),
            "OutputResync must forward exactly one SessionInbound::Repaint"
        );
        assert!(
            rx.try_recv().is_err(),
            "no further inbound events beyond the single Repaint"
        );
    }

    /// Spec §4.7.1: the hard-cap report is a log line, nothing for the
    /// backend and no end of the connection.
    #[tokio::test]
    async fn a_hard_cap_report_is_logged_and_forwards_nothing() {
        let kp = generate_keypair();
        let mut conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        conn.push_test_event(Event::SendBufferOverCap { stream_id: 17 });
        let (tx, mut rx) = mpsc::channel::<SessionInbound>(4);
        let mut first_live_sent = false;
        let logged_before = OVER_CAP_LOGGED.with(std::cell::Cell::get);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut out = Vec::new();
        let kind = drain_events(
            &mut conn,
            &mut link,
            &mut first_live_sent,
            Instant::now(),
            &mut out,
        );
        assert!(matches!(kind, CloseKind::None));
        assert!(rx.try_recv().is_err());
        assert_eq!(
            OVER_CAP_LOGGED.with(std::cell::Cell::get) - logged_before,
            1,
            "the report took its own arm, the one that logs it"
        );
    }

    /// A server connection that is not live yet: `send` only queues, so a
    /// stream's tail is exactly what was written.
    fn a_quiet_server_connection() -> Connection {
        let kp = generate_keypair();
        Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        })
    }

    /// `SessionIo`'s gates are the session's one table, the one the bridge
    /// refreshes; dropping one or all of them wakes their waiters for good;
    /// a class goes out as a declaration for the bridge.
    #[test]
    fn session_io_hands_out_the_bridges_gates_and_declares_classes() {
        use crate::send_gate::{GateWait, SCREEN_HIGH};
        let (io, _inbound, mut outbound, gates) = SessionIo::test_pair_with_gates();
        let screen = io.send_gate(20, GateKind::Screen);
        assert!(
            Arc::ptr_eq(&screen, &gates.gate(20, GateKind::Pipe)),
            "the table the bridge holds"
        );
        assert!(gates.refresh(|_| SCREEN_HIGH).is_empty());
        assert!(
            !screen.is_open(),
            "the bridge's refresh reaches the backend's gate"
        );
        io.drop_send_gate(20);
        assert_eq!(screen.wait_open_for(Duration::ZERO), GateWait::Closed);
        let pipe = io.send_gate(21, GateKind::Pipe);
        io.close_send_gates();
        assert_eq!(pipe.wait_open_for(Duration::ZERO), GateWait::Closed);
        io.set_stream_class(14, StreamClass::Bulk);
        assert!(matches!(
            outbound.try_recv(),
            Ok(SessionOutbound::StreamClass {
                stream_id: 14,
                class: StreamClass::Bulk
            })
        ));
    }

    /// Final review of slice 2, Minor 4 (spec §4.7.2): what a backend
    /// hands the bridge waits in an unbounded queue the connection's tail
    /// does not see. It counts on the stream's gate from `send` on, and
    /// stops counting there only as the bridge takes it -- into the
    /// connection, where the tail holds it, or, parked, nowhere; a send the
    /// bridge will never take stops counting at once.
    #[test]
    fn bytes_a_backend_hands_the_bridge_count_against_their_gate_until_taken() {
        use crate::send_gate::{PIPE_HIGH, SCREEN_HIGH};
        let (io, _inbound, mut outbound, _gates) = SessionIo::test_pair_with_gates();
        let pipe = io.send_gate(21, GateKind::Pipe);
        let screen = io.send_gate(20, GateKind::Screen);
        let mut conn = a_quiet_server_connection();
        let now = Instant::now();
        let mut out = Vec::new();

        io.send(21, vec![0u8; PIPE_HIGH as usize]);
        assert!(
            !pipe.is_open(),
            "handed over: it counts before the bridge takes it"
        );
        let Ok(SessionOutbound::Data(sd)) = outbound.try_recv() else {
            panic!("the data is queued for the bridge");
        };
        assert_eq!(
            take_backend_data(&mut conn, &io.gates, false, now, sd, &mut out),
            None
        );
        assert_eq!(conn.stream_progress(21).unacked, PIPE_HIGH);
        assert!(
            !pipe.is_open(),
            "taken into the connection: the tail holds it"
        );

        io.send(20, vec![0u8; SCREEN_HIGH as usize]);
        assert!(!screen.is_open());
        let Ok(SessionOutbound::Data(sd)) = outbound.try_recv() else {
            panic!("the data is queued for the bridge");
        };
        assert_eq!(
            take_backend_data(&mut conn, &io.gates, true, now, sd, &mut out),
            Some(20),
            "parked: thrown away, and the screen channel hears its gate opened"
        );
        assert_eq!(conn.stream_progress(20).unacked, 0, "nothing queued");
        assert!(screen.is_open());

        let lost = io.send_gate(22, GateKind::Pipe);
        drop(outbound);
        io.send(22, vec![0u8; PIPE_HIGH as usize]);
        assert!(lost.is_open(), "nobody will take it: it does not count");
    }

    #[test]
    fn refresh_gates_closes_a_gate_past_its_high_mark() {
        let gates = GateTable::new();
        let screen = gates.gate(20, GateKind::Screen);
        let mut conn = a_quiet_server_connection();
        let _ = conn.send(Instant::now(), 20, &vec![0u8; 200 * 1024]);
        assert!(refresh_gates(&gates, &conn, false).is_empty());
        assert!(!screen.is_open());
    }

    /// Review Focus 1: a parked bridge throws the backend's output away and
    /// repaints on revival, so its gates stay open, and a screen channel shut
    /// until then hears `Writable`.
    #[test]
    fn refresh_gates_opens_every_gate_while_parked() {
        let gates = GateTable::new();
        let screen = gates.gate(20, GateKind::Screen);
        let pipe = gates.gate(21, GateKind::Pipe);
        let mut conn = a_quiet_server_connection();
        let now = Instant::now();
        let _ = conn.send(now, 20, &vec![0u8; 200 * 1024]);
        let _ = conn.send(now, 21, &vec![0u8; 600 * 1024]);
        assert!(refresh_gates(&gates, &conn, false).is_empty());
        assert!(!screen.is_open() && !pipe.is_open());
        assert_eq!(refresh_gates(&gates, &conn, true), vec![20]);
        assert!(screen.is_open() && pipe.is_open());
    }

    /// Plan correction 6: a class is a declaration on one connection, and a
    /// warm reattach swaps the connection; the bridge declares again.
    #[tokio::test]
    async fn a_warm_attach_keeps_the_declared_stream_classes() {
        let mut conn = a_quiet_server_connection();
        let mut parked = false;
        let (tx, _rx) = mpsc::channel::<SessionInbound>(4);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut classes = BTreeMap::new();
        classes.insert(14u8, StreamClass::Bulk);
        let mut out = Vec::new();
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(
                Box::new(a_quiet_server_connection()),
                Vec::new(),
                Vec::new(),
            ),
            &classes,
            Instant::now(),
            &mut out,
        );
        assert_eq!(conn.stream_class(14), StreamClass::Bulk);
    }

    /// The same, from the backend's declaration on: the bridge applies it to
    /// the connection it has and keeps it for the one a reattach brings.
    #[tokio::test]
    async fn a_class_the_backend_declares_reaches_this_connection_and_the_next() {
        let mut conn = a_quiet_server_connection();
        let mut classes = BTreeMap::new();
        declare_class(&mut conn, &mut classes, 14, StreamClass::Bulk);
        assert_eq!(conn.stream_class(14), StreamClass::Bulk, "this connection");
        let (tx, _rx) = mpsc::channel::<SessionInbound>(4);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut parked = false;
        let mut out = Vec::new();
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(
                Box::new(a_quiet_server_connection()),
                Vec::new(),
                Vec::new(),
            ),
            &classes,
            Instant::now(),
            &mut out,
        );
        assert_eq!(conn.stream_class(14), StreamClass::Bulk, "the next one");
        assert_eq!(
            conn.stream_class(15),
            StreamClass::Interactive,
            "nothing else"
        );
    }

    /// Wait (without blocking the runtime) until `gate`'s openness is `open`.
    async fn gate_becomes(gate: &SendGate, open: bool, what: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.is_open() != open {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    /// Spec §4.7.2 end to end at the bridge: a screen channel's output fills
    /// its tail past the high mark and the gate closes; the client's ACKs,
    /// routed back into the bridge, drain the tail, the gate opens, and the
    /// backend hears `Writable` for that stream.
    #[tokio::test]
    async fn the_clients_acks_open_a_screen_gate_and_the_backend_hears_writable() {
        const STREAM: u8 = 16;
        let server_kp = generate_keypair();
        let token = [0x3Cu8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut client, conn, msg2) = accepted_connection(&server_kp, token, peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);

        let gates = Arc::new(GateTable::new());
        let screen = gates.gate(STREAM, GateKind::Screen);
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (dg_tx, dg_rx) = dgram_queue();
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let backend_out = out_tx.clone();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend: Arc::new(InboundKindsBackend(heard_tx)),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::clone(&gates),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates: Arc::clone(&gates),
        }));

        backend_out
            .send(SessionOutbound::Data(StreamData {
                stream_id: STREAM,
                data: vec![7u8; 200 * 1024],
            }))
            .map_err(|_| "the bridge is listening")
            .unwrap();
        gate_becomes(&screen, false, "200 KiB queued closes the screen gate").await;

        let mut buf = vec![0u8; 65536];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                tokio::select! {
                    got = client_sock.recv_from(&mut buf) => {
                        let (len, src) = got.unwrap();
                        for dg in client.on_datagram(Instant::now(), src, &buf[..len]) {
                            assert!(dg_tx.send(peer, dg.bytes), "the route takes it");
                        }
                    }
                    heard = heard_rx.recv() => {
                        if heard.expect("the backend is alive") == "writable" {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("the ACKs drain the tail and the backend hears Writable");
        assert!(screen.is_open());
    }

    /// Review Focus 1, end to end at the bridge: the gates open the moment
    /// the bridge parks, not at some later wake-up -- a parked bridge has no
    /// timers, and a producer behind a closed gate (a line channel's reader
    /// waits on it; a screen channel drops output without sending any) never
    /// wakes it. A screen channel that was shut hears `Writable`.
    #[tokio::test]
    async fn a_bridge_that_parks_opens_its_gates_at_once() {
        const PIPE: u8 = 16;
        const SCREEN: u8 = 18;
        const EDGE: u8 = 17;
        let server_kp = generate_keypair();
        let token = [0x4Du8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut client, mut conn, msg2) =
            accepted_connection_with(&server_kp, token, peer, crate::Features::HEADER_AAD);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        conn.start_stream_at_for_test(EDGE, OFFSET_LIMIT - 10);

        let gates = Arc::new(GateTable::new());
        let pipe = gates.gate(PIPE, GateKind::Pipe);
        let screen = gates.gate(SCREEN, GateKind::Screen);
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (_dg_tx, dg_rx) = dgram_queue();
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let backend_out = out_tx.clone();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend: Arc::new(InboundKindsBackend(heard_tx)),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::clone(&gates),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates: Arc::clone(&gates),
        }));
        let send = |stream_id: u8, len: usize| {
            backend_out
                .send(SessionOutbound::Data(StreamData {
                    stream_id,
                    data: vec![1u8; len],
                }))
                .map_err(|_| "the bridge is listening")
                .unwrap();
        };

        // Nobody acknowledges: both tails stay where the output put them.
        send(PIPE, 600 * 1024);
        send(SCREEN, 200 * 1024);
        gate_becomes(&pipe, false, "600 KiB closes the pipe gate").await;
        gate_becomes(&screen, false, "200 KiB closes the screen gate").await;

        // 11 bytes where 10 fit: the connection is abandoned, a death -> parked.
        send(EDGE, 11);
        let ended = tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
            .await
            .expect("the bridge reports the death")
            .expect("the bridge is alive");
        assert!(!ended.graceful, "a death: the bridge parks");

        gate_becomes(&pipe, true, "parking opens the pipe gate").await;
        gate_becomes(&screen, true, "parking opens the screen gate").await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while heard_rx.recv().await.expect("the backend is alive") != "writable" {}
        })
        .await
        .expect("the screen channel hears Writable");
    }

    /// Spec §4.7.2, "after `Attach` every gate opens", on a bridge that is
    /// NOT parked: the old live connection's tails shut both gates, a warm
    /// `Attach` swaps in a connection holding none, and the same turn opens
    /// them. The screen channel hears `Writable`, after `ResumeReset`.
    #[tokio::test]
    async fn a_warm_attach_on_a_live_bridge_opens_its_gates() {
        const PIPE: u8 = 16;
        const SCREEN: u8 = 18;
        let server_kp = generate_keypair();
        let token = [0x6Eu8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut client, conn, msg2) = accepted_connection(&server_kp, token, peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);

        let gates = Arc::new(GateTable::new());
        let pipe = gates.gate(PIPE, GateKind::Pipe);
        let screen = gates.gate(SCREEN, GateKind::Screen);
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (_dg_tx, dg_rx) = dgram_queue();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let backend_out = out_tx.clone();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend: Arc::new(InboundKindsBackend(heard_tx)),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::clone(&gates),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates: Arc::clone(&gates),
        }));
        let send = |stream_id: u8, len: usize| {
            backend_out
                .send(SessionOutbound::Data(StreamData {
                    stream_id,
                    data: vec![1u8; len],
                }))
                .map_err(|_| "the bridge is listening")
                .unwrap();
        };

        // Nobody acknowledges: both tails stay where the output put them.
        send(PIPE, 600 * 1024);
        send(SCREEN, 200 * 1024);
        gate_becomes(&pipe, false, "600 KiB closes the pipe gate").await;
        gate_becomes(&screen, false, "200 KiB closes the screen gate").await;

        let (_client2, conn2, _msg2) = accepted_connection(&server_kp, token, peer);
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(conn2),
                Vec::new(),
                Vec::new(),
            ))
            .map_err(|_| "the bridge is listening")
            .unwrap();
        gate_becomes(&pipe, true, "the attach opens the pipe gate").await;
        gate_becomes(&screen, true, "the attach opens the screen gate").await;
        let heard = tokio::time::timeout(Duration::from_secs(2), async {
            let mut heard = Vec::new();
            while heard.last() != Some(&"writable") {
                heard.push(heard_rx.recv().await.expect("the backend is alive"));
            }
            heard
        })
        .await
        .expect("the screen channel hears Writable");
        let reset = heard.iter().position(|k| *k == "resume-reset");
        assert!(
            reset.is_some_and(|at| at < heard.len() - 1),
            "Writable comes after ResumeReset: {heard:?}"
        );
    }

    /// A bridge driving a real accepted connection, with `backend` behind
    /// it: what a delivery test needs to steer and to watch.
    struct DeliveryRig {
        client: Connection,
        client_sock: UdpSocket,
        peer: SocketAddr,
        server_kp: crate::handshake::Keypair,
        token: [u8; 16],
        backend_out: mpsc::UnboundedSender<SessionOutbound>,
        dg_tx: DgramTx,
        ctl_tx: mpsc::UnboundedSender<BridgeControl>,
        done_rx: mpsc::UnboundedReceiver<SessionEnded>,
        /// How many `StreamFrame::Pong`s the client has seen, across every
        /// `run`.
        pongs: usize,
    }

    async fn delivery_rig(
        backend: Arc<dyn SessionBackend>,
        prepare: impl FnOnce(&mut Connection),
    ) -> DeliveryRig {
        delivery_rig_with(crate::Features::SUPPORTED, backend, prepare).await
    }

    /// The same, with a connection that agreed `features`.
    async fn delivery_rig_with(
        features: crate::Features,
        backend: Arc<dyn SessionBackend>,
        prepare: impl FnOnce(&mut Connection),
    ) -> DeliveryRig {
        let server_kp = generate_keypair();
        let token = [0x7Au8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut client, mut conn, msg2) =
            accepted_connection_with(&server_kp, token, peer, features);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        prepare(&mut conn);
        let gates = Arc::new(GateTable::new());
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (dg_tx, dg_rx) = dgram_queue();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let backend_out = out_tx.clone();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend,
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::clone(&gates),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates,
        }));
        DeliveryRig {
            client,
            client_sock,
            peer,
            server_kp,
            token,
            backend_out,
            dg_tx,
            ctl_tx,
            done_rx,
            pongs: 0,
        }
    }

    impl DeliveryRig {
        fn backend_sends(&self, msg: SessionOutbound) {
            self.backend_out
                .send(msg)
                .map_err(|_| "the bridge is listening")
                .unwrap();
        }

        /// Take what the bridge sent the client for `window`; hand the
        /// client's answers back when `route` says so, else keep them.
        async fn pump(&mut self, window: Duration, route: bool, held: &mut Vec<Vec<u8>>) {
            let mut buf = vec![0u8; 65536];
            let _ = tokio::time::timeout(window, async {
                loop {
                    let (len, src) = self.client_sock.recv_from(&mut buf).await.unwrap();
                    for dg in self.client.on_datagram(Instant::now(), src, &buf[..len]) {
                        if route {
                            assert!(self.dg_tx.send(self.peer, dg.bytes), "the route takes it");
                        } else {
                            held.push(dg.bytes);
                        }
                    }
                }
            })
            .await;
        }

        fn attach_a_new_connection(&self) {
            let (_client, conn, _msg2) =
                accepted_connection(&self.server_kp, self.token, self.peer);
            self.ctl_tx
                .send(BridgeControl::Attach(
                    Box::new(conn),
                    Vec::new(),
                    Vec::new(),
                ))
                .map_err(|_| "the bridge is listening")
                .unwrap();
        }

        /// The client writes `data` on `stream_id`; its datagrams go to the
        /// bridge's route.
        fn client_sends(&mut self, stream_id: u8, data: &[u8]) {
            for dg in self.client.send(Instant::now(), stream_id, data) {
                assert!(
                    self.dg_tx.send(self.peer, dg.bytes),
                    "the bridge is listening"
                );
            }
        }

        /// Carry traffic both ways for `window`: the bridge's datagrams reach
        /// the client (its PONGs counted), the client's answers and what its
        /// own timers send reach the bridge.
        async fn run(&mut self, window: Duration) {
            let end = tokio::time::Instant::now() + window;
            let mut buf = vec![0u8; 65536];
            while tokio::time::Instant::now() < end {
                let mut out = Vec::new();
                if let Ok(Ok((len, src))) = tokio::time::timeout(
                    Duration::from_millis(10),
                    self.client_sock.recv_from(&mut buf),
                )
                .await
                {
                    if let Some(frames) = self.client.peek_frames(&buf[..len]) {
                        self.pongs += frames
                            .iter()
                            .filter(|f| matches!(f, StreamFrame::Pong { .. }))
                            .count();
                    }
                    out.extend(self.client.on_datagram(Instant::now(), src, &buf[..len]));
                }
                out.extend(self.client.on_timeout_if_due(Instant::now()));
                for dg in out {
                    let _ = self.dg_tx.send(self.peer, dg.bytes);
                }
            }
        }

        /// A warm reattach by a new client of the same device: the bridge
        /// gets its connection through `Attach`, and the rig speaks as that
        /// client from now on.
        fn reattach(&mut self) {
            let (mut client, conn, msg2) =
                accepted_connection(&self.server_kp, self.token, self.peer);
            let _ = client.on_datagram(Instant::now(), self.peer, &msg2[0].bytes);
            self.ctl_tx
                .send(BridgeControl::Attach(
                    Box::new(conn),
                    Vec::new(),
                    Vec::new(),
                ))
                .map_err(|_| "the bridge is listening")
                .unwrap();
            self.client = client;
        }
    }

    #[tokio::test]
    async fn snapshot_receive_fence_survives_two_attaches_and_wakes_on_credit_alone() {
        use crate::channel::{ChannelSnapshot, ServerRecord, CONTROL_STREAM};
        struct SnapshotBackend(mpsc::UnboundedSender<u64>);
        impl SessionBackend for SnapshotBackend {
            fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
                let observed = self.0.clone();
                Box::pin(async move {
                    while let Some(event) = io.recv().await {
                        if let SessionInbound::ResumeReset(origin) = event {
                            io.publish_resume_snapshot(origin, || {
                                ChannelSnapshot::new(vec![], vec![])
                            });
                            io.channel_opened(origin, 16 + origin.generation as u8);
                            io.channel_refused(
                                origin,
                                32 + origin.generation as u8,
                                "fixture".into(),
                            );
                            observed.send(origin.generation).unwrap();
                        }
                    }
                })
            }
        }
        let features = crate::Features::SUPPORTED | crate::Features::CHANNEL_GEOMETRY;
        let (observed, mut generations) = mpsc::unbounded_channel();
        let mut rig = delivery_rig_with(features, Arc::new(SnapshotBackend(observed)), |conn| {
            conn.enable_geometry_for_test()
        })
        .await;
        let occupied = crate::reliability::STREAM_WINDOW as usize - 6;
        for generation in 1..=2 {
            let (mut client, mut conn, msg2) =
                accepted_connection_with(&rig.server_kp, rig.token, rig.peer, features);
            client.on_datagram(Instant::now(), rig.peer, &msg2[0].bytes);
            client.enable_geometry_for_test();
            conn.enable_geometry_for_test();
            client.set_default_consumption(Consumption::Explicit);
            // Six bytes admit Opened, but cannot admit even the empty atomic
            // snapshot (seven bytes). Consume the filler only after Attach #2.
            let mut now = Instant::now();
            let mut out = conn.send(now, CONTROL_STREAM, &vec![0; occupied]);
            for _ in 0..100 {
                for dg in std::mem::take(&mut out) {
                    for ack in client.on_datagram(now, rig.peer, &dg.bytes) {
                        out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
                    }
                }
                client.poll_events();
                now += Duration::from_millis(20);
                for ack in client.on_timeout(now) {
                    out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
                }
                out.extend(conn.on_timeout(now));
                if out.is_empty() && conn.stream_progress(CONTROL_STREAM).unacked == 0 {
                    break;
                }
            }
            assert_eq!(
                client.unconsumed_streams(),
                vec![(CONTROL_STREAM, occupied as u64)]
            );
            assert_eq!(
                conn.stream_write_room(CONTROL_STREAM, crate::send_gate::PIPE_HIGH as usize),
                6
            );
            assert_eq!(conn.state(), LinkState::Live);
            assert!(conn.features().contains(crate::Features::CHANNEL_GEOMETRY));
            rig.ctl_tx
                .send(BridgeControl::Attach(Box::new(conn), vec![], vec![]))
                .unwrap();
            rig.client = client;
            rig.run(Duration::from_millis(100)).await;
            assert_eq!(generations.try_recv().unwrap(), generation);
            assert!(
                rig.done_rx.try_recv().is_err(),
                "bridge ended during blocked generation {generation}; client state {:?}",
                rig.client.state()
            );
            assert!(
                !rig.client.poll_events().iter().any(|event| matches!(
                    event,
                    Event::StreamData {
                        stream_id: CONTROL_STREAM,
                        ..
                    }
                )),
                "no later lifecycle control bypasses the blocked snapshot"
            );
        }
        // No backend event is produced after this point. Transport credit must
        // independently wake admission and the receive fence must then reopen.
        for dg in rig
            .client
            .on_consumed(Instant::now(), CONTROL_STREAM, occupied)
        {
            assert!(rig.dg_tx.send(rig.peer, dg.bytes));
        }
        rig.run(Duration::from_millis(200)).await;
        let mut frames = crate::shell_frame::RecordDeframer::for_control();
        let mut records = Vec::new();
        for event in rig.client.poll_events() {
            if let Event::StreamData {
                stream_id: CONTROL_STREAM,
                data,
            } = event
            {
                records.extend(
                    frames
                        .push(&data)
                        .iter()
                        .map(|raw| crate::channel::decode_server(raw).unwrap()),
                );
            }
        }
        assert_eq!(
            records,
            vec![
                ServerRecord::ChannelSnapshot(ChannelSnapshot::new(vec![], vec![]).unwrap()),
                ServerRecord::Opened { stream: 18 },
                ServerRecord::Refused {
                    stream: 34,
                    reason: "fixture".into()
                },
            ],
            "old-generation controls are discarded; new controls follow the atomic snapshot"
        );
        drop(rig.dg_tx);
        tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }

    /// A backend that takes every inbound event, counts the stream bytes it
    /// got, and reports consumption only when the test cues it
    /// (`Consumption::Explicit`).
    struct ReportOnCue {
        got: Arc<Mutex<BTreeMap<u8, usize>>>,
        cues: Mutex<Option<mpsc::UnboundedReceiver<(u8, usize)>>>,
    }

    impl SessionBackend for ReportOnCue {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let got = Arc::clone(&self.got);
            let mut cues = self.cues.lock().unwrap().take().expect("one session");
            Box::pin(async move {
                let mut cues_open = true;
                loop {
                    tokio::select! {
                        ev = io.recv() => match ev {
                            Some(SessionInbound::Data(sd)) => {
                                *got.lock().unwrap().entry(sd.stream_id).or_insert(0) += sd.data.len();
                            }
                            Some(_) => {}
                            None => return,
                        },
                        cue = cues.recv(), if cues_open => match cue {
                            Some((stream_id, n)) => io.consumed(stream_id, n),
                            None => cues_open = false,
                        },
                    }
                }
            })
        }

        fn consumption(&self) -> Consumption {
            Consumption::Explicit
        }
    }

    /// A backend that takes every inbound event and counts the stream bytes;
    /// it reports nothing (`Consumption::OnDelivery`: the bridge counts).
    struct CountsWhatItGets(Arc<Mutex<BTreeMap<u8, usize>>>);

    impl SessionBackend for CountsWhatItGets {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let got = Arc::clone(&self.0);
            Box::pin(async move {
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(sd) = ev {
                        *got.lock().unwrap().entry(sd.stream_id).or_insert(0) += sd.data.len();
                    }
                }
            })
        }
    }

    fn got_on(got: &Arc<Mutex<BTreeMap<u8, usize>>>, stream_id: u8) -> usize {
        got.lock().unwrap().get(&stream_id).copied().unwrap_or(0)
    }

    /// A backend that never reads its inbound queue: the slowest consumer.
    struct NeverReads;

    impl SessionBackend for NeverReads {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                let _io = io;
                std::future::pending::<()>().await
            })
        }
    }

    /// Spec §4.10.2, §9.2 (L1): a backend that never reads does not stop
    /// its bridge -- PINGs are answered -- and what waits for it is bounded
    /// by the stream's window: the client holds the rest.
    #[tokio::test]
    async fn a_backend_that_never_reads_leaves_the_bridge_answering() {
        PENDING_PEAK.with(|p| p.set(0));
        let mut rig = delivery_rig(Arc::new(NeverReads), |_| {}).await;
        rig.client_sends(20, &vec![1u8; 2 * 1024 * 1024]);
        rig.run(Duration::from_secs(4)).await;
        assert!(
            rig.pongs >= 2,
            "the bridge kept answering: {} PONGs",
            rig.pongs
        );
        assert_eq!(rig.client.state(), LinkState::Live);
        let peak = PENDING_PEAK.with(std::cell::Cell::get) as u64;
        assert!(peak <= STREAM_WINDOW, "{peak}");
        assert!(rig.client.stream_progress(20).unacked > 0);
    }

    /// Spec §9.2 (L1, the `SM` row): a handler that takes every stream but
    /// never consumes stream 20 still gets stream 16 and the control
    /// stream, and PINGs are answered. What this guards is per-stream
    /// independence under credits: the backend reads every event (it only
    /// withholds its reports for stream 20), so the bridge never had
    /// anything to wait for here, and this passes on the code before L1 as
    /// well. The L1 property -- a bridge that answers while its backend reads
    /// nothing -- is pinned by
    /// `a_backend_that_never_reads_leaves_the_bridge_answering`,
    /// `a_client_without_credits_below_8_mib_never_stops_the_bridge` and
    /// `a_turn_answers_acks_and_pings_while_the_backend_is_full`.
    #[tokio::test]
    async fn a_handler_that_never_consumes_one_stream_still_gets_the_others() {
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let (cue_tx, cue_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ReportOnCue {
            got: Arc::clone(&got),
            cues: Mutex::new(Some(cue_rx)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        rig.client_sends(20, &vec![1u8; 2 * 1024 * 1024]);
        rig.run(Duration::from_millis(500)).await;
        for _ in 0..20 {
            rig.client_sends(16, b"k");
            rig.client_sends(crate::channel::CONTROL_STREAM, b"c");
            rig.run(Duration::from_millis(100)).await;
            cue_tx.send((16, 1)).unwrap();
            cue_tx.send((crate::channel::CONTROL_STREAM, 1)).unwrap();
        }
        rig.run(Duration::from_secs(2)).await;
        assert_eq!(got_on(&got, 16), 20);
        assert_eq!(got_on(&got, crate::channel::CONTROL_STREAM), 20);
        assert_eq!(got_on(&got, 20) as u64, STREAM_WINDOW);
        assert!(rig.pongs >= 1);
    }

    /// Spec §4.10.7: a client without credits pasting less than
    /// `PENDING_CAP` into a backend that does not read never stops
    /// the bridge.
    #[tokio::test]
    async fn a_client_without_credits_below_8_mib_never_stops_the_bridge() {
        PENDING_PEAK.with(|p| p.set(0));
        let mut rig = delivery_rig_with(crate::Features::NONE, Arc::new(NeverReads), |_| {}).await;
        rig.client_sends(20, &vec![1u8; 4 * 1024 * 1024]);
        rig.run(Duration::from_secs(4)).await;
        assert!(rig.pongs >= 2, "{} PONGs", rig.pongs);
        let peak = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(peak > 2 * 1024 * 1024 && peak <= PENDING_CAP, "{peak}");
    }

    /// A backend that reads nothing for `after`, then everything, checking
    /// stream 20's bytes follow `i % 251` in order. When its queue closes it
    /// writes into `ended` how many bytes of stream 20 it had by then.
    struct ReadsAfter {
        after: Duration,
        got: Arc<Mutex<BTreeMap<u8, usize>>>,
        ended: Arc<Mutex<Option<usize>>>,
    }

    impl SessionBackend for ReadsAfter {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let after = self.after;
            let got = Arc::clone(&self.got);
            let ended = Arc::clone(&self.ended);
            Box::pin(async move {
                tokio::time::sleep(after).await;
                let mut next = 0usize;
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(sd) = ev {
                        if sd.stream_id == 20 {
                            for b in &sd.data {
                                assert_eq!(*b, (next % 251) as u8, "in order at byte {next}");
                                next += 1;
                            }
                        }
                        *got.lock().unwrap().entry(sd.stream_id).or_insert(0) += sd.data.len();
                    }
                }
                *ended.lock().unwrap() = Some(next);
            })
        }
    }

    /// Spec §4.10.7 (Review Focus 5): past `PENDING_CAP` the bridge
    /// of a client without credits waits for its backend, as every build
    /// did; nothing past the cap waits in it, and once the backend reads
    /// everything arrives, in order.
    #[tokio::test]
    async fn a_client_without_credits_past_8_mib_is_waited_on_then_carried_whole() {
        PENDING_PEAK.with(|p| p.set(0));
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let backend = Arc::new(ReadsAfter {
            after: Duration::from_secs(3),
            got: Arc::clone(&got),
            ended: Arc::new(Mutex::new(None)),
        });
        let mut rig = delivery_rig_with(crate::Features::NONE, backend, |_| {}).await;
        let paste: Vec<u8> = (0..12 * 1024 * 1024usize)
            .map(|i| (i % 251) as u8)
            .collect();
        rig.client_sends(20, &paste);
        rig.run(Duration::from_secs(3)).await;
        let peak = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(peak <= PENDING_CAP + 64 * 1024, "{peak}");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while got_on(&got, 20) < paste.len() && tokio::time::Instant::now() < deadline {
            rig.run(Duration::from_millis(200)).await;
        }
        assert_eq!(got_on(&got, 20), paste.len());
    }

    /// The client writes `data` on `stream_id` and the bridge's route takes
    /// what it can -- a bridge that waits past `PENDING_CAP` stops reading
    /// its route, which then drops, as the network would.
    fn client_sends_lossy(rig: &mut DeliveryRig, stream_id: u8, data: &[u8]) {
        for dg in rig.client.send(Instant::now(), stream_id, data) {
            let _ = rig.dg_tx.send(rig.peer, dg.bytes);
        }
    }

    /// Spec §4.10.5 (ruling R13): with credits each stream's window bounds
    /// what waits for it, not the session. A client holding 40 streams full
    /// into a backend that reads nothing fills at most `PENDING_CAP` -- past
    /// it the bridge waits, as before credits -- and once the backend reads,
    /// every byte arrives, stream 20's in order.
    #[tokio::test]
    async fn many_full_streams_into_a_backend_that_never_reads_hold_at_most_the_pending_cap() {
        PENDING_PEAK.with(|p| p.set(0));
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let backend = Arc::new(ReadsAfter {
            after: Duration::from_secs(4),
            got: Arc::clone(&got),
            ended: Arc::new(Mutex::new(None)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        let per_stream = 600 * 1024usize;
        let streams: Vec<u8> = (20..60).collect();
        let pattern: Vec<u8> = (0..per_stream).map(|i| (i % 251) as u8).collect();
        for &stream in &streams {
            client_sends_lossy(&mut rig, stream, &pattern);
        }
        rig.run(Duration::from_secs(4)).await;
        let peak = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(
            peak > PENDING_CAP && peak <= PENDING_CAP + 64 * 1024,
            "the cap was reached and held: {peak}"
        );
        let total = streams.len() * per_stream;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let sum =
            |got: &Arc<Mutex<BTreeMap<u8, usize>>>| got.lock().unwrap().values().sum::<usize>();
        while sum(&got) < total && tokio::time::Instant::now() < deadline {
            rig.run(Duration::from_millis(200)).await;
        }
        assert_eq!(
            sum(&got),
            total,
            "everything arrives once the backend reads"
        );
    }

    /// Spec §4.10.5 (ruling R13): every warm reattach brings a connection
    /// whose streams start with a fresh window while the replaced one's bytes
    /// still wait; however many reattaches come, what waits stays within
    /// `PENDING_CAP`.
    #[tokio::test]
    async fn repeated_warm_reattaches_into_a_backend_that_never_reads_hold_at_most_the_pending_cap()
    {
        PENDING_PEAK.with(|p| p.set(0));
        let mut rig = delivery_rig(Arc::new(NeverReads), |_| {}).await;
        for _ in 0..24 {
            client_sends_lossy(&mut rig, 20, &vec![1u8; 600 * 1024]);
            rig.run(Duration::from_millis(300)).await;
            rig.reattach();
        }
        let peak = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(
            peak > PENDING_CAP && peak <= PENDING_CAP + 64 * 1024,
            "the cap was reached and held: {peak}"
        );
    }

    /// Spec §4.10.5: an honest client -- 10 streams, the most a session
    /// uses, every window full into a backend that reads nothing -- never
    /// reaches `PENDING_CAP`, and the bridge answers throughout.
    #[tokio::test]
    async fn an_honest_session_with_every_window_full_never_reaches_the_pending_cap() {
        PENDING_PEAK.with(|p| p.set(0));
        let mut rig = delivery_rig(Arc::new(NeverReads), |_| {}).await;
        for stream in 20..30u8 {
            rig.client_sends(stream, &vec![1u8; 1024 * 1024]);
        }
        rig.run(Duration::from_secs(4)).await;
        let peak = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(peak <= 10 * STREAM_WINDOW as usize, "{peak}");
        assert!(peak < PENDING_CAP, "{peak}");
        assert!(
            peak > 4 * 1024 * 1024,
            "the windows were full: {peak} bytes waited"
        );
        assert!(
            rig.pongs >= 2,
            "the bridge kept answering: {} PONGs",
            rig.pongs
        );
    }

    /// Review Minor 1: on a graceful end what waits in the bridge still
    /// goes to the backend, in order, before its queue closes -- as it did
    /// when the bridge waited for its backend.
    #[tokio::test]
    async fn a_graceful_end_hands_what_waits_to_the_backend_before_its_end() {
        PENDING_PEAK.with(|p| p.set(0));
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let ended = Arc::new(Mutex::new(None));
        let backend = Arc::new(ReadsAfter {
            after: Duration::from_secs(1),
            got: Arc::clone(&got),
            ended: Arc::clone(&ended),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        let paste: Vec<u8> = (0..300 * 1024usize).map(|i| (i % 251) as u8).collect();
        rig.client_sends(20, &paste);
        rig.run(Duration::from_millis(500)).await;
        assert_eq!(rig.client.stream_progress(20).unacked, 0, "all delivered");
        assert!(
            PENDING_PEAK.with(std::cell::Cell::get) > 0,
            "part of it waits in the bridge"
        );
        for dg in rig.client.close(Instant::now()) {
            assert!(rig.dg_tx.send(rig.peer, dg.bytes), "the route takes it");
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while ended.lock().unwrap().is_none() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            *ended.lock().unwrap(),
            Some(paste.len()),
            "every delivered byte reached the backend before its queue closed"
        );
    }

    /// Task 7 re-review, Minor A: a graceful end whose backend is stalled
    /// -- it never reads, so what waits in the bridge cannot go -- leaves a
    /// hand-over task behind that holds only what waits, not the closed
    /// connection: the connection is dropped when the bridge ends.
    #[tokio::test]
    async fn a_graceful_end_into_a_stalled_backend_drops_the_connection() {
        PENDING_PEAK.with(|p| p.set(0));
        let mut watch = None;
        let mut rig = delivery_rig(Arc::new(NeverReads), |conn| {
            watch = Some(conn.watch_drop_for_test());
        })
        .await;
        let watch = watch.expect("the rig prepared the connection");
        rig.client_sends(20, &vec![1u8; 300 * 1024]);
        rig.run(Duration::from_millis(500)).await;
        assert!(
            PENDING_PEAK.with(std::cell::Cell::get) > 0,
            "part of it waits in the bridge"
        );
        assert!(watch.upgrade().is_some(), "the bridge holds its connection");
        for dg in rig.client.close(Instant::now()) {
            assert!(rig.dg_tx.send(rig.peer, dg.bytes), "the route takes it");
        }
        let ended = tokio::time::timeout(Duration::from_secs(5), rig.done_rx.recv())
            .await
            .expect("the bridge ends")
            .expect("and says so");
        assert!(ended.graceful);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while watch.upgrade().is_some() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            watch.upgrade().is_none(),
            "the connection is dropped with the bridge; only what waits stays"
        );
    }

    /// Task 7 re-review, Minor B (spec §6.4): what a wait for a slow
    /// backend hands over is booked at the time it went, not at the turn's
    /// `now` from before the wait. The `CREDIT` it frees counts its repeat's
    /// `rto` from when it was really sent: a sender stopped at its limit
    /// gets no repeat at once after a wait longer than an `rto`, and gets
    /// it one `rto` later.
    #[tokio::test]
    async fn a_credit_freed_by_a_long_wait_for_the_backend_repeats_an_rto_after_it_went() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:19".parse().unwrap();
        let (mut client, mut conn, msg2) = accepted_connection(&server_kp, [19u8; 16], peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        let classes = BTreeMap::new();
        adopt_connection(&mut conn, &classes);
        let (tx, mut rx) = mpsc::channel::<SessionInbound>(1);
        tx.try_send(SessionInbound::Repaint)
            .map_err(|_| "room for one")
            .unwrap();
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let (_ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let mut parked = false;
        let mut first_live_sent = true;

        // The client writes exactly its window, so it stops at the limit it
        // started with; everything waits in the bridge, the backend full.
        let window = STREAM_WINDOW as usize;
        let mut to_server = client.send(Instant::now(), 20, &vec![5u8; window]);
        let deadline = Instant::now() + Duration::from_secs(10);
        while link.inbound.pending_bytes() < window {
            assert!(Instant::now() < deadline, "the window arrives");
            let now = Instant::now();
            let mut out = Vec::new();
            for dg in to_server.drain(..) {
                on_routed_datagram(
                    &mut conn,
                    &mut parked,
                    &mut ctl_rx,
                    &mut link,
                    &classes,
                    now,
                    peer,
                    &dg.bytes,
                    &mut out,
                );
            }
            out.extend(conn.on_timeout_if_due(now));
            let closed = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);
            assert!(matches!(closed, CloseKind::None));
            for dg in &out {
                to_server.extend(client.on_datagram(now, peer, &dg.bytes));
            }
            to_server.extend(client.on_timeout_if_due(now));
            if to_server.is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        assert_eq!(link.inbound.pending_bytes(), window);
        assert_eq!(
            conn.unconsumed_streams(),
            vec![(20, window as u64)],
            "nothing is counted as taken yet"
        );

        // The backend reads only after more than an rto; the bridge waits
        // for it (as past `PENDING_CAP`) from a turn that began before.
        let rto = conn.rto_for_test();
        let slow = rto + Duration::from_millis(300);
        let reader = tokio::spawn(async move {
            tokio::time::sleep(slow).await;
            while rx.recv().await.is_some() {}
        });
        let turn = Instant::now();
        let mut out = Vec::new();
        link.wait_below(0, &mut conn, &mut out).await;
        let after = Instant::now();
        assert!(after >= turn + slow, "the wait was long");

        let credits = |client: &mut Connection, dgs: &[Datagram]| -> Vec<u32> {
            dgs.iter()
                .filter_map(|dg| client.peek_frames(&dg.bytes))
                .flatten()
                .filter_map(|f| match f {
                    StreamFrame::Credit {
                        stream_id: 20,
                        limit,
                    } => Some(limit),
                    _ => None,
                })
                .collect()
        };
        let announced = credits(&mut client, &out);
        let newest = (2 * window) as u32;
        assert_eq!(
            announced.last(),
            Some(&newest),
            "what the backend took is announced: {announced:?}"
        );
        assert_eq!(
            credits(&mut client, &conn.on_timeout_if_due(after)),
            Vec::<u32>::new(),
            "no repeat at once: it was sent just now, not a turn ago"
        );
        assert_eq!(
            credits(&mut client, &conn.on_timeout_if_due(after + rto)),
            vec![newest],
            "the repeat comes one rto after it was sent"
        );
        reader.abort();
    }

    /// Task 6 review, Minor 1 (spec §4.10.2): with the backend's queue full
    /// and nobody reading it, a turn still produces its ACKs and the PONG
    /// for a PING at once -- the hand-over never waits, so nothing on the
    /// turn stands behind the backend -- while the delivered bytes wait in
    /// the bridge, uncounted.
    #[test]
    fn a_turn_answers_acks_and_pings_while_the_backend_is_full() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:18".parse().unwrap();
        let now = Instant::now();
        let (mut client, mut conn, msg2) = accepted_connection(&server_kp, [18u8; 16], peer);
        let _ = client.on_datagram(now, peer, &msg2[0].bytes);
        let classes = BTreeMap::new();
        adopt_connection(&mut conn, &classes);
        let (tx, _rx) = mpsc::channel::<SessionInbound>(1);
        tx.try_send(SessionInbound::Repaint)
            .map_err(|_| "room for one")
            .unwrap();
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let (_ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let mut parked = false;
        let mut first_live_sent = true;

        let later = now + Duration::from_secs(2);
        let mut to_server = client.send(now, 20, &vec![3u8; 8 * 1024]);
        to_server.extend(client.on_timeout_if_due(later));
        assert!(
            to_server.iter().any(|dg| conn
                .peek_frames(&dg.bytes)
                .is_some_and(|f| f.iter().any(|f| matches!(f, StreamFrame::Ping { .. })))),
            "the client's PING is among what it sent"
        );

        let mut out = Vec::new();
        for dg in &to_server {
            on_routed_datagram(
                &mut conn,
                &mut parked,
                &mut ctl_rx,
                &mut link,
                &classes,
                later,
                peer,
                &dg.bytes,
                &mut out,
            );
        }
        out.extend(conn.on_timeout_if_due(later));
        let closed = drain_events(&mut conn, &mut link, &mut first_live_sent, later, &mut out);
        assert!(matches!(closed, CloseKind::None));
        assert_eq!(
            link.inbound.pending_bytes(),
            8 * 1024,
            "everything delivered waits in the bridge"
        );
        assert!(
            conn.unconsumed_streams().contains(&(20, 8 * 1024)),
            "and is not counted as taken: {:?}",
            conn.unconsumed_streams()
        );

        let mut pongs = 0;
        for dg in &out {
            if let Some(frames) = client.peek_frames(&dg.bytes) {
                pongs += frames
                    .iter()
                    .filter(|f| matches!(f, StreamFrame::Pong { .. }))
                    .count();
            }
            let _ = client.on_datagram(later, peer, &dg.bytes);
        }
        assert!(pongs >= 1, "the PING is answered on the turn");
        assert_eq!(
            client.stream_progress(20).unacked,
            0,
            "every byte is acknowledged on the turn"
        );
    }

    /// Stream-20 bytes a test backend received, drained from its queue one
    /// event at a time.
    fn data_len(ev: &SessionInbound) -> usize {
        data_of(ev).map_or(0, |(_, n)| n)
    }

    /// Spec §4.10.2-§4.10.3, a reporting backend: bytes connection A
    /// delivered that wait in the bridge for a full backend when a warm
    /// reattach brings B are A's, not B's, when they reach the backend
    /// after it. The backend's reports of them pay off A's debt; B is
    /// credited only for what B delivered.
    #[tokio::test]
    async fn bytes_waiting_at_a_reattach_are_owed_to_the_connection_that_delivered_them() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:19".parse().unwrap();
        let mut now = Instant::now();
        let classes = BTreeMap::new();
        let (mut client_a, mut conn) = explicit_pair(&server_kp, 19, peer, now);
        let (tx, mut rx) = mpsc::channel::<SessionInbound>(1);
        let mut link = BackendLink::new(tx, Consumption::Explicit);
        let mut parked = false;
        let mut out = Vec::new();

        // A delivers 1000 bytes, which fill the backend's queue, then 3000,
        // which wait in the bridge.
        for n in [1000usize, 3000] {
            assert_eq!(
                deliver(&mut client_a, &mut conn, &mut now, peer, 20, n),
                n as u64
            );
            let sd = StreamData {
                stream_id: 20,
                data: vec![1u8; n],
            };
            link.hand_over(&mut conn, now, SessionInbound::Data(sd), &mut out);
        }
        assert_eq!(link.inbound.pending_bytes(), 3000);

        // A warm reattach brings B, which delivers 2000 bytes of its own:
        // they wait behind A's.
        let (mut client_b, conn_b) = explicit_pair(&server_kp, 20, peer, now);
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(Box::new(conn_b), Vec::new(), Vec::new()),
            &classes,
            now,
            &mut out,
        );
        assert_eq!(
            deliver(&mut client_b, &mut conn, &mut now, peer, 20, 2000),
            2000
        );
        let sd = StreamData {
            stream_id: 20,
            data: vec![2u8; 2000],
        };
        link.hand_over(&mut conn, now, SessionInbound::Data(sd), &mut out);
        assert_eq!(link.inbound.pending_bytes(), 5000);
        assert_eq!(unconsumed_of(&conn, 20), 2000);

        // The backend reads everything, one event at a time.
        let mut got = 0usize;
        loop {
            let ev = rx.try_recv().expect("the queue holds the head");
            got += data_len(&ev);
            if !link.inbound.has_pending() {
                break;
            }
            let handed = link.inbound.room().await;
            link.took(&mut conn, now, handed, &mut out);
        }
        assert_eq!(got, 6000);
        assert_eq!(
            unconsumed_of(&conn, 20),
            2000,
            "B is credited nothing before its backend reports"
        );

        // It reports A's 4000: A's debt, B's credit untouched.
        link.ledger.reported(&mut conn, now, 20, 4000, &mut out);
        assert_eq!(
            unconsumed_of(&conn, 20),
            2000,
            "A's bytes, waiting in the bridge at the reattach, credit B nothing"
        );
        assert!(link.ledger.owed_old.is_empty(), "A's debt is paid");

        // Then B's own 2000: B is credited them, all of them.
        link.ledger.reported(&mut conn, now, 20, 2000, &mut out);
        assert_eq!(unconsumed_of(&conn, 20), 0);
        assert!(link.ledger.outstanding.is_empty());
    }

    /// The same order with a backend that does not report: A's bytes that
    /// waited in the bridge at the reattach reach the backend after it and
    /// credit nobody -- B's window grows only as B's own bytes reach the
    /// backend.
    #[tokio::test]
    async fn bytes_waiting_at_a_reattach_credit_the_new_connection_nothing_on_delivery() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:21".parse().unwrap();
        let mut now = Instant::now();
        let classes = BTreeMap::new();
        let (mut client_a, mut conn) = explicit_pair(&server_kp, 21, peer, now);
        let (tx, mut rx) = mpsc::channel::<SessionInbound>(1);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut parked = false;
        let mut out = Vec::new();

        for n in [1000usize, 3000] {
            assert_eq!(
                deliver(&mut client_a, &mut conn, &mut now, peer, 20, n),
                n as u64
            );
            let sd = StreamData {
                stream_id: 20,
                data: vec![1u8; n],
            };
            link.hand_over(&mut conn, now, SessionInbound::Data(sd), &mut out);
        }
        assert_eq!(
            unconsumed_of(&conn, 20),
            3000,
            "A is credited what entered the backend's queue, not what waits"
        );

        let (mut client_b, conn_b) = explicit_pair(&server_kp, 22, peer, now);
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(Box::new(conn_b), Vec::new(), Vec::new()),
            &classes,
            now,
            &mut out,
        );
        assert_eq!(
            deliver(&mut client_b, &mut conn, &mut now, peer, 20, 2000),
            2000
        );
        let sd = StreamData {
            stream_id: 20,
            data: vec![2u8; 2000],
        };
        link.hand_over(&mut conn, now, SessionInbound::Data(sd), &mut out);
        assert_eq!(unconsumed_of(&conn, 20), 2000);

        // The backend takes A's 1000; room lets A's 3000 in.
        assert_eq!(data_len(&rx.try_recv().expect("A's first")), 1000);
        let handed = link.inbound.room().await;
        assert_eq!(handed.iter().map(|h| h.n).sum::<usize>(), 3000);
        link.took(&mut conn, now, handed, &mut out);
        assert_eq!(
            unconsumed_of(&conn, 20),
            2000,
            "A's bytes reaching the backend after the reattach credit B nothing"
        );

        // Then the reset, then B's own 2000, which credit B.
        assert_eq!(data_len(&rx.try_recv().expect("A's second")), 3000);
        let handed = link.inbound.room().await;
        link.took(&mut conn, now, handed, &mut out);
        assert!(matches!(rx.try_recv(), Ok(SessionInbound::ResumeReset(_))));
        let handed = link.inbound.room().await;
        link.took(&mut conn, now, handed, &mut out);
        assert_eq!(unconsumed_of(&conn, 20), 0, "B's own bytes credit B");
        assert_eq!(data_len(&rx.try_recv().expect("B's")), 2000);
        assert!(!link.inbound.has_pending());
    }

    /// `ReportOnCue` that reads nothing until `start` fires.
    struct ReadsOnStartReportsOnCue {
        got: Arc<Mutex<BTreeMap<u8, usize>>>,
        start: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        cues: Mutex<Option<mpsc::UnboundedReceiver<(u8, usize)>>>,
    }

    impl SessionBackend for ReadsOnStartReportsOnCue {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let got = Arc::clone(&self.got);
            let start = self.start.lock().unwrap().take().expect("one session");
            let mut cues = self.cues.lock().unwrap().take().expect("one session");
            Box::pin(async move {
                let _ = start.await;
                loop {
                    tokio::select! {
                        ev = io.recv() => match ev {
                            Some(SessionInbound::Data(sd)) => {
                                *got.lock().unwrap().entry(sd.stream_id).or_insert(0) += sd.data.len();
                            }
                            Some(_) => {}
                            None => return,
                        },
                        Some((stream_id, n)) = cues.recv() => io.consumed(stream_id, n),
                    }
                }
            })
        }

        fn consumption(&self) -> Consumption {
            Consumption::Explicit
        }
    }

    /// The bridge in production order (spec §4.10.2-§4.10.3): A fills its
    /// window into a backend that is not reading, so part of it waits in
    /// the bridge; a warm reattach brings B, which sends its own bytes; the
    /// backend then reads everything and reports A's window -- B's credit
    /// does not move -- and then B's bytes, which credit B.
    #[tokio::test]
    async fn bytes_waiting_in_the_bridge_at_a_reattach_credit_the_new_connection_nothing() {
        PENDING_PEAK.with(|p| p.set(0));
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (cue_tx, cue_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ReadsOnStartReportsOnCue {
            got: Arc::clone(&got),
            start: Mutex::new(Some(start_rx)),
            cues: Mutex::new(Some(cue_rx)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        rig.client_sends(20, &vec![1u8; 1024 * 1024]);
        rig.run(Duration::from_millis(500)).await;
        let waiting = PENDING_PEAK.with(std::cell::Cell::get);
        assert!(waiting > 0, "part of A's window waits in the bridge");

        rig.reattach();
        let b_sends = 256 * 1024;
        rig.client_sends(20, &vec![2u8; b_sends]);
        rig.run(Duration::from_millis(300)).await;
        start_tx.send(()).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(got_on(&got, 20) as u64, STREAM_WINDOW + b_sends as u64);
        assert_eq!(rig.client.credit_limit_for_test(20), Some(STREAM_WINDOW));

        cue_tx.send((20, STREAM_WINDOW as usize)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW),
            "A's bytes, {waiting} of them waiting in the bridge at the reattach, credit B nothing"
        );
        cue_tx.send((20, b_sends)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW + b_sends as u64)
        );
    }

    /// Spec §4.10.3: a backend that does not report is counted by what the
    /// bridge hands it -- without that the client would stop at the window.
    #[tokio::test]
    async fn the_bridge_counts_what_it_hands_to_a_backend_that_does_not_report() {
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let mut rig = delivery_rig(Arc::new(CountsWhatItGets(Arc::clone(&got))), |_| {}).await;
        rig.client_sends(20, &vec![1u8; 2 * 1024 * 1024]);
        rig.run(Duration::from_secs(2)).await;
        assert_eq!(got_on(&got, 20), 2 * 1024 * 1024);
    }

    /// Spec §4.10.3: a backend that reports is credited by its reports and
    /// nothing else; a report past what was delivered counts no further.
    #[tokio::test]
    async fn a_reporting_backend_is_credited_by_its_reports_only() {
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let (cue_tx, cue_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ReportOnCue {
            got: Arc::clone(&got),
            cues: Mutex::new(Some(cue_rx)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        rig.client_sends(20, &vec![1u8; 1024 * 1024]);
        rig.run(Duration::from_millis(500)).await;
        assert_eq!(
            got_on(&got, 20) as u64,
            STREAM_WINDOW,
            "the window, nothing reported"
        );
        cue_tx.send((20, 256 * 1024)).unwrap();
        rig.run(Duration::from_millis(500)).await;
        assert_eq!(got_on(&got, 20) as u64, STREAM_WINDOW + 256 * 1024);
        cue_tx.send((20, 1024 * 1024)).unwrap();
        rig.run(Duration::from_millis(500)).await;
        let delivered = 1024 * 1024u64;
        assert_eq!(got_on(&got, 20) as u64, delivered);
        assert!(
            rig.client.credit_limit_for_test(20).unwrap() <= delivered + STREAM_WINDOW,
            "the over-report credited no further than what was delivered: {:?}",
            rig.client.credit_limit_for_test(20)
        );
    }

    /// Spec §4.10.3 (Review Focus 2): what the bridge HANDED the backend off
    /// the replaced connection, and the backend has not reported, is owed to
    /// that connection -- its reports are swallowed -- and only what comes
    /// after credits the new one, whose streams start at zero. (In this
    /// test the bridge hands over exactly what the connection delivered, so
    /// the two amounts happen to agree; fix round 2 changed the wording,
    /// not the numbers.)
    #[tokio::test]
    async fn a_warm_reattach_swallows_the_old_connections_reports_and_credits_the_new_one() {
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let (cue_tx, cue_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ReportOnCue {
            got: Arc::clone(&got),
            cues: Mutex::new(Some(cue_rx)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;
        rig.client_sends(20, &vec![1u8; 300 * 1024]);
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(got_on(&got, 20), 300 * 1024);
        rig.reattach();
        rig.client_sends(20, &vec![2u8; 500 * 1024]);
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(got_on(&got, 20), 800 * 1024);
        assert_eq!(rig.client.credit_limit_for_test(20), Some(STREAM_WINDOW));
        cue_tx.send((20, 300 * 1024)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW),
            "the old connection's bytes credit nothing here"
        );
        cue_tx.send((20, 500 * 1024)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW + 500 * 1024)
        );
    }

    /// Review round 1, minor 4: a `Consumed` report can arrive while the
    /// bridge is parked (the connection `Closed` after an unexpected death,
    /// per `Connection::abandon`) -- `Connection::on_consumed` still counts
    /// it and sends nothing. Paying it off there matters because a warm
    /// reattach's `carry` depends on exactly this order (review Important
    /// 1, fix round 1): a report the ledger already paid must not be owed
    /// again to whatever reattaches next.
    #[test]
    fn a_consumed_report_while_parked_pays_off_the_ledger_so_the_next_reattach_carries_nothing() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:12".parse().unwrap();
        let (_client, mut conn, _) = accepted_connection(&server_kp, [12u8; 16], peer);
        let (tx, _rx) = mpsc::channel::<SessionInbound>(4);
        let mut link = BackendLink::new(tx, Consumption::Explicit);
        let mut out = Vec::new();
        let now = Instant::now();

        // 2000 bytes handed to the (reporting) backend: outstanding, not
        // yet paid.
        link.ledger.handed_over(&mut conn, now, 20, 2000, &mut out);
        assert!(
            out.is_empty(),
            "an Explicit backend's hand-over sends nothing by itself"
        );

        // The connection dies without a Close (the bridge would PARK here,
        // per `run_backend_bridge`'s `CloseKind::Death` arm).
        conn.abandon();
        assert_eq!(conn.state(), LinkState::Closed);

        // The backend's report still arrives while parked: it counts, and
        // sends nothing (the connection is Closed).
        out.clear();
        link.ledger.reported(&mut conn, now, 20, 2000, &mut out);
        assert!(
            out.is_empty(),
            "a closed connection counts consumption but never sends"
        );

        // A warm reattach right after: nothing is left outstanding to
        // carry, because the report already paid it off.
        link.ledger.carry();
        assert!(
            link.ledger.owed_old.is_empty(),
            "the report already paid it off: nothing owed to the parked connection"
        );
    }

    /// Review round 1, minor 4: `ConsumptionReporter` holds its sender
    /// weakly (spec §4.10.3's implementer's note), so once the `SessionIo`
    /// it came from is gone -- the session over -- its reports go nowhere,
    /// exactly like a `send` after the io is dropped.
    #[test]
    fn a_consumption_reporter_reports_nowhere_once_its_io_is_gone() {
        let (io, _inbound, mut outbound) = SessionIo::test_pair();
        let reporter = io.consumption_reporter();
        reporter.consumed(20, 100);
        assert!(matches!(
            outbound.try_recv(),
            Ok(SessionOutbound::Consumed {
                stream_id: 20,
                n: 100
            })
        ));
        drop(io);
        reporter.consumed(20, 50);
        assert!(
            outbound.try_recv().is_err(),
            "the io is gone: the reporter's weak sender has nothing to upgrade to"
        );
    }

    /// Review round 2, finding N1 (`probe_split_report_then_second_reattach`):
    /// a report that covers bytes from BOTH an old, replaced connection's
    /// debt and the current connection's own outstanding bytes must settle
    /// the old debt first and touch `outstanding` only for what is left --
    /// exactly `pay`'s own order. Before this fix `reported` spent the
    /// WHOLE report off `outstanding` first, on its own, disagreeing with
    /// `pay`; a report that fully paid an old debt would then also wipe out
    /// bytes the current connection had not been reported for yet, so a
    /// second reattach right after carried nothing for them -- and the
    /// eventual late report of the current connection's own bytes wrongly
    /// credited whatever reattached next instead.
    #[test]
    fn a_report_spanning_old_debt_and_the_current_connections_own_bytes_splits_correctly() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:14".parse().unwrap();
        // A dummy connection for the ledger calls that must not credit
        // anything real (A's and B's hand-overs, A's report): what matters
        // there is the ledger's own bookkeeping, checked directly below.
        let (_client, mut dummy, _) = accepted_connection(&server_kp, [14u8; 16], peer);
        let mut ledger = ConsumptionLedger::new(Consumption::Explicit);
        let now = Instant::now();
        let mut out = Vec::new();

        // Connection A hands over 1000 bytes of stream 20, then a reattach:
        // owed_old = 1000.
        ledger.handed_over(&mut dummy, now, 20, 1000, &mut out);
        ledger.carry();
        assert_eq!(ledger.owed_old.get(&20), Some(&1000));
        assert!(!ledger.outstanding.contains_key(&20));

        // Connection B (now current) hands over 500 more.
        ledger.handed_over(&mut dummy, now, 20, 500, &mut out);
        assert_eq!(ledger.outstanding.get(&20), Some(&500));

        // The backend reports A's 1000: it must settle A's debt in full and
        // leave B's own 500 untouched, still outstanding.
        ledger.reported(&mut dummy, now, 20, 1000, &mut out);
        assert!(!ledger.owed_old.contains_key(&20), "A's debt is paid");
        assert_eq!(
            ledger.outstanding.get(&20),
            Some(&500),
            "B's own bytes must not be spent paying A's debt"
        );

        // A second reattach to C carries exactly B's still-unreported 500 --
        // nothing more, nothing less.
        ledger.carry();
        assert_eq!(ledger.owed_old.get(&20), Some(&500));
        assert!(!ledger.outstanding.contains_key(&20));

        // C is a REAL connection this time, and actually receives its own
        // 500 bytes of stream 20 -- so the final check below is a genuine
        // `Connection::on_consumed` effect, not just the ledger's map.
        let (mut client_c, mut conn_c, msg2_c) = accepted_connection(&server_kp, [15u8; 16], peer);
        let _ = client_c.on_datagram(now, peer, &msg2_c[0].bytes);
        conn_c.set_default_consumption(Consumption::Explicit);
        for dg in client_c.send(now, 20, &vec![9u8; 500]) {
            let _ = conn_c.on_datagram(now, peer, &dg.bytes);
        }
        for ev in conn_c.poll_events() {
            if let Event::StreamData {
                stream_id: 20,
                data,
            } = ev
            {
                ledger.handed_over(&mut conn_c, now, 20, data.len(), &mut out);
            }
        }
        assert_eq!(ledger.outstanding.get(&20), Some(&500));
        assert_eq!(
            conn_c.unconsumed_streams(),
            vec![(20, 500)],
            "delivered but not yet credited: C's own report has not arrived"
        );

        // The backend finally reports B's 500: it pays off B's debt and
        // must credit none of C's own -- C's 500 bytes stay unconsumed on
        // C's own connection until ITS OWN report arrives, not before.
        ledger.reported(&mut conn_c, now, 20, 500, &mut out);
        assert!(!ledger.owed_old.contains_key(&20), "B's debt is paid");
        assert_eq!(
            ledger.outstanding.get(&20),
            Some(&500),
            "C's own bytes must not be credited by a report that was B's"
        );
        assert_eq!(
            conn_c.unconsumed_streams(),
            vec![(20, 500)],
            "no connection is credited for bytes it did not give"
        );
    }

    /// A connection that counts every stream explicitly, with its client.
    fn explicit_pair(
        server_kp: &crate::handshake::Keypair,
        token_byte: u8,
        peer: SocketAddr,
        now: Instant,
    ) -> (Connection, Connection) {
        let (mut client, mut conn, msg2) = accepted_connection(server_kp, [token_byte; 16], peer);
        let _ = client.on_datagram(now, peer, &msg2[0].bytes);
        conn.set_default_consumption(Consumption::Explicit);
        (client, conn)
    }

    /// The client sends `n` bytes on `stream` and `conn` delivers them. The
    /// two exchange datagrams (ACKs included), and the clock steps on 20 ms
    /// whenever nothing is in flight, until every byte arrived and nothing
    /// is left to exchange, or 100 rounds passed. Returns how many bytes of
    /// `stream` `conn` delivered -- handed to nobody: the caller decides
    /// whether the ledger hands them over.
    fn deliver(
        client: &mut Connection,
        conn: &mut Connection,
        now: &mut Instant,
        peer: SocketAddr,
        stream: u8,
        n: usize,
    ) -> u64 {
        let mut to_conn = client.send(*now, stream, &vec![7u8; n]);
        let mut got = 0u64;
        for _ in 0..100 {
            let mut to_client = Vec::new();
            for dg in to_conn.drain(..) {
                to_client.extend(conn.on_datagram(*now, peer, &dg.bytes));
            }
            for ev in conn.poll_events() {
                if let Event::StreamData { stream_id, data } = ev {
                    if stream_id == stream {
                        got += data.len() as u64;
                    }
                }
            }
            for dg in to_client {
                to_conn.extend(client.on_datagram(*now, peer, &dg.bytes));
            }
            if to_conn.is_empty() {
                if got >= n as u64 {
                    break;
                }
                *now += Duration::from_millis(20);
                for dg in conn.on_timeout_if_due(*now) {
                    to_conn.extend(client.on_datagram(*now, peer, &dg.bytes));
                }
                to_conn.extend(client.on_timeout_if_due(*now));
            }
        }
        got
    }

    /// Bytes `conn` delivered on `stream` and has not been credited yet.
    fn unconsumed_of(conn: &Connection, stream: u8) -> u64 {
        conn.unconsumed_streams()
            .into_iter()
            .find(|&(s, _)| s == stream)
            .map(|(_, n)| n)
            .unwrap_or(0)
    }

    /// Review round 2, finding N1, and re-reviews 2 and 3, Minor B: a small
    /// property test. Random sequences of hand-over, delivery that is never
    /// handed over, report and reattach on three streams, checked against an
    /// independent model: per stream, a FIFO of `(generation, bytes)` chunks
    /// in hand-over order.
    ///
    /// - A report pops up to `n` bytes off the front of its stream's FIFO
    ///   (splitting a chunk if `n` lands inside one). The popped bytes that
    ///   belong to the CURRENT generation must be exactly the new credit on
    ///   the connection now driving the test (the drop in its
    ///   `unconsumed_streams()`); the part of a report past everything
    ///   queued must credit nothing.
    /// - After every step, `owed_old + outstanding` must equal what the
    ///   stream's FIFO still holds (the ledger's struct-doc invariant).
    ///
    /// Reports are random in size up to 1500 bytes past what the stream's
    /// FIFO holds, so some over-report, and they go to all three streams,
    /// including stream 22, which is never handed anything. Bytes delivered
    /// and never handed over (still inside a connection when a reattach
    /// replaced it, say) leave the connection holding more unconsumed bytes
    /// than the ledger's `outstanding`, so the receiver's own clamp cannot
    /// hide an over-credit. Mutation-checked in fix round 4: the test fails
    /// with the round-1 body of `reported` (a report taken off `outstanding`
    /// on top of what `pay` spends on `owed_old`) and with `pay` crediting
    /// the whole remainder of a report instead of what it takes off
    /// `outstanding` (Minor D), with the ledger's debug checks disabled.
    #[test]
    fn random_hand_over_report_reattach_sequences_keep_the_ledgers_invariant() {
        use std::collections::VecDeque;

        /// Streams bytes are handed over on.
        const HANDED: [u8; 2] = [20, 21];
        /// Every stream: 22 is delivered and reported, never handed over.
        const ALL: [u8; 3] = [20, 21, 22];
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:15".parse().unwrap();

        /// Pop up to `n` bytes off `queue`'s front, in order, splitting the
        /// front chunk if `n` lands inside it. Returns how many of the
        /// popped bytes belong to `current_gen`.
        fn pop_credit(queue: &mut VecDeque<(u64, u64)>, mut n: u64, current_gen: u64) -> u64 {
            let mut credited_current = 0u64;
            while n > 0 {
                let Some((gen, len)) = queue.front_mut() else {
                    break;
                };
                let take = (*len).min(n);
                if *gen == current_gen {
                    credited_current += take;
                }
                *len -= take;
                n -= take;
                if *len == 0 {
                    queue.pop_front();
                }
            }
            credited_current
        }

        let pick = |rng: &mut crate::testnet::SplitMix64, from: &[u8]| {
            from[(rng.next_u64() % from.len() as u64) as usize]
        };

        for seed in 0..30u64 {
            let mut rng = crate::testnet::SplitMix64::new(seed);
            let mut ledger = ConsumptionLedger::new(Consumption::Explicit);
            let mut queues: BTreeMap<u8, VecDeque<(u64, u64)>> = BTreeMap::new();
            let mut gen_id: u64 = 0;
            let mut now = Instant::now();
            let mut out = Vec::new();
            let (mut client, mut conn) = explicit_pair(&server_kp, 0, peer, now);

            for step in 0..200u32 {
                match rng.next_u64() % 6 {
                    0 | 1 => {
                        // Bytes delivered and handed over to the backend.
                        let stream = pick(&mut rng, &HANDED);
                        let n = 1 + (rng.next_u64() % 2000) as usize;
                        let got = deliver(&mut client, &mut conn, &mut now, peer, stream, n);
                        assert_eq!(got, n as u64, "seed {seed} step {step}: all delivered");
                        ledger.handed_over(&mut conn, now, stream, n, &mut out);
                        queues.entry(stream).or_default().push_back((gen_id, got));
                    }
                    2 => {
                        // Bytes delivered and never handed over.
                        let stream = pick(&mut rng, &ALL);
                        let n = 1 + (rng.next_u64() % 2000) as usize;
                        let got = deliver(&mut client, &mut conn, &mut now, peer, stream, n);
                        assert_eq!(got, n as u64, "seed {seed} step {step}: all delivered");
                    }
                    3 | 4 => {
                        // A report, sometimes past what the backend holds.
                        let stream = pick(&mut rng, &ALL);
                        let queue = queues.entry(stream).or_default();
                        let held: u64 = queue.iter().map(|&(_, len)| len).sum();
                        let n = 1 + rng.next_u64() % (held + 1500);
                        let before = unconsumed_of(&conn, stream);
                        ledger.reported(&mut conn, now, stream, n as usize, &mut out);
                        let actual_credit = before - unconsumed_of(&conn, stream);
                        let expected_credit = pop_credit(queue, n, gen_id);
                        assert_eq!(
                            actual_credit, expected_credit,
                            "seed {seed} step {step} stream {stream}: a report of {n} (the backend held {held}) must credit exactly the current generation's share of the bytes it covers, oldest first"
                        );
                    }
                    _ => {
                        // A warm reattach to a fresh connection: a new
                        // generation from here on.
                        ledger.carry();
                        gen_id += 1;
                        (client, conn) = explicit_pair(&server_kp, 0, peer, now);
                    }
                }

                for &stream in &ALL {
                    let owed = ledger.owed_old.get(&stream).copied().unwrap_or(0);
                    let outstanding = ledger.outstanding.get(&stream).copied().unwrap_or(0);
                    let queued: u64 = queues
                        .get(&stream)
                        .map(|q| q.iter().map(|&(_, len)| len).sum())
                        .unwrap_or(0);
                    assert_eq!(
                        owed + outstanding,
                        queued,
                        "seed {seed} step {step} stream {stream}: owed_old + outstanding must equal what was handed and not yet reported"
                    );
                }
            }
        }
    }

    /// Re-review 2, probe C; re-review 3, Minor 2: the order finding A was
    /// about, at the ledger. The backend was handed 4000 bytes of stream 20
    /// off connection A and has not reported them yet; a warm reattach
    /// brings connection C, which delivers 1000 bytes of stream 20 that are
    /// handed over too (to channel B, reusing the number). Only then does
    /// the report of A's 4000 arrive. It pays A's debt and credits C
    /// nothing; B's own report of 1000 then credits C exactly those 1000.
    #[test]
    fn a_late_report_after_a_reattach_pays_the_old_debt_and_credits_the_new_connection_only_its_own_bytes(
    ) {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:16".parse().unwrap();
        let mut now = Instant::now();
        let mut out = Vec::new();
        let mut ledger = ConsumptionLedger::new(Consumption::Explicit);

        let (_client_a, mut conn_a) = explicit_pair(&server_kp, 16, peer, now);
        ledger.handed_over(&mut conn_a, now, 20, 4000, &mut out);
        ledger.carry();

        let (mut client_c, mut conn_c) = explicit_pair(&server_kp, 17, peer, now);
        let got = deliver(&mut client_c, &mut conn_c, &mut now, peer, 20, 1000);
        assert_eq!(got, 1000);
        ledger.handed_over(&mut conn_c, now, 20, 1000, &mut out);

        ledger.reported(&mut conn_c, now, 20, 4000, &mut out);
        assert!(!ledger.owed_old.contains_key(&20), "A's debt is paid");
        assert_eq!(
            ledger.outstanding.get(&20),
            Some(&1000),
            "B's bytes are still unreported"
        );
        assert_eq!(
            conn_c.unconsumed_streams(),
            vec![(20, 1000)],
            "A's late report credits C nothing"
        );

        ledger.reported(&mut conn_c, now, 20, 1000, &mut out);
        assert!(ledger.outstanding.is_empty() && ledger.owed_old.is_empty());
        assert_eq!(
            conn_c.unconsumed_streams(),
            vec![],
            "B's own report credits C exactly B's bytes"
        );
    }

    /// Re-review 3, Minor C: once old debt has been paid off, an over-report
    /// credits the current connection no more than was handed over off it,
    /// although it delivered more (bytes still inside it, never handed
    /// over). A report for a stream never handed anything credits nothing.
    #[test]
    fn an_over_report_after_old_debt_is_paid_credits_the_current_connection_only_what_it_handed_over(
    ) {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:17".parse().unwrap();
        let mut now = Instant::now();
        let mut out = Vec::new();
        let mut ledger = ConsumptionLedger::new(Consumption::Explicit);

        // Connection A: 1000 handed over; a reattach; A's 1000 reported.
        let (_client_a, mut conn_a) = explicit_pair(&server_kp, 18, peer, now);
        ledger.handed_over(&mut conn_a, now, 20, 1000, &mut out);
        ledger.carry();
        let (mut client_b, mut conn_b) = explicit_pair(&server_kp, 19, peer, now);
        ledger.reported(&mut conn_b, now, 20, 1000, &mut out);
        assert!(ledger.owed_old.is_empty(), "A's debt is paid");

        // Connection B delivers 700 and 200 of them are handed over; the
        // backend reports 700.
        assert_eq!(
            deliver(&mut client_b, &mut conn_b, &mut now, peer, 20, 700),
            700
        );
        ledger.handed_over(&mut conn_b, now, 20, 200, &mut out);
        ledger.reported(&mut conn_b, now, 20, 700, &mut out);
        assert_eq!(
            unconsumed_of(&conn_b, 20),
            500,
            "B is credited the 200 it handed over, not the 700 reported"
        );
        assert!(ledger.outstanding.is_empty() && ledger.owed_old.is_empty());

        // Stream 22: delivered, never handed over, reported anyway.
        assert_eq!(
            deliver(&mut client_b, &mut conn_b, &mut now, peer, 22, 300),
            300
        );
        ledger.reported(&mut conn_b, now, 22, 300, &mut out);
        assert_eq!(
            unconsumed_of(&conn_b, 22),
            300,
            "a report for a stream never handed anything credits nothing"
        );
    }

    /// Re-review 2 finding A, re-review 3 Minor 2, at the bridge and in
    /// production order. Channel A on stream 20 is handed its bytes and ends
    /// with them unreported. The runner declares the stream Interactive at
    /// A's end (`channel_server::forget_channel_stream`), and a warm
    /// reattach follows. Channel B reuses stream 20 on the new connection and
    /// is handed its own bytes. Only then does A's writer report what A was
    /// handed, dropped bytes included (the contract in
    /// `SessionBackend::consumption`'s doc). That late report pays A's debt
    /// and credits the new connection nothing; B's own report then credits
    /// it exactly B's bytes. A ledger that forgot stream 20 at the
    /// declaration would credit the new connection for A's report.
    #[tokio::test]
    async fn an_ended_channels_late_report_after_a_reattach_credits_its_successor_nothing() {
        let got = Arc::new(Mutex::new(BTreeMap::new()));
        let (cue_tx, cue_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ReportOnCue {
            got: Arc::clone(&got),
            cues: Mutex::new(Some(cue_rx)),
        });
        let mut rig = delivery_rig(backend, |_| {}).await;

        // Channel A is handed 300 KiB, reports nothing yet, and ends.
        rig.client_sends(20, &vec![1u8; 300 * 1024]);
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(got_on(&got, 20), 300 * 1024, "A was handed its bytes");
        rig.backend_sends(SessionOutbound::StreamClass {
            stream_id: 20,
            class: StreamClass::Interactive,
        });
        rig.run(Duration::from_millis(100)).await;

        rig.reattach();

        // Channel B reuses stream 20 on the new connection.
        rig.client_sends(20, &vec![2u8; 500 * 1024]);
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(got_on(&got, 20), 800 * 1024, "B was handed its bytes");
        assert_eq!(rig.client.credit_limit_for_test(20), Some(STREAM_WINDOW));

        // A's late report of everything it was handed.
        cue_tx.send((20, 300 * 1024)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW),
            "A's late report pays A's debt and credits the new connection nothing"
        );

        // B's own report.
        cue_tx.send((20, 500 * 1024)).unwrap();
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(20),
            Some(STREAM_WINDOW + 500 * 1024),
            "B's report credits the new connection exactly B's bytes"
        );
    }

    /// The REAL channel runner (`channel_server::run_channel_session`)
    /// behind this crate's own bridge and ledger -- not a fake backend that
    /// already knows the ledger's answer, unlike `ReportOnCue` above. Its
    /// spawner is `channel_server::tests::FakeSpawner`, the same double
    /// that module's own writer tests use, reused here rather than
    /// hand-rolled again.
    struct RealChannelRunner(Arc<crate::channel_server::tests::FakeSpawner>);

    impl SessionBackend for RealChannelRunner {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let spawner = Arc::clone(&self.0);
            Box::pin(run_channel_session(io, spawner))
        }

        fn consumption(&self) -> Consumption {
            Consumption::Explicit
        }
    }

    /// Controller R12, at the bridge, with the real channel runner: channel
    /// A opens on stream 16, is handed bytes its process never reads (its
    /// writer held), and the client closes it -- unwritten input, unreported
    /// (spec §4.10.3, `channel_server`'s own "input the runner drops" and
    /// "input left in a closed channel's queue" tests cover the runner's
    /// half of this in isolation). A warm reattach follows; A's writer is
    /// then released -- its process reads, late -- and drains and reports
    /// everything it was ever handed, before channel B ever opens: no
    /// report-ordering race to reason about (the new connection's client has
    /// no local stream-16 state yet to read a credit limit from at this
    /// point -- `credit_limit_for_test` needs a stream the client itself has
    /// already touched -- so this is not checked directly; the final
    /// assertion below is what would fail if A's report never happened, see
    /// its own doc). Channel B then reuses stream 16 on
    /// the new connection, is handed its own, DIFFERENT-sized bytes, and its
    /// report must credit the new connection exactly those bytes: nothing
    /// owed from A swallows it (there is nothing left owed by then, or the
    /// two sizes below would make that visible), and nothing extra is
    /// credited.
    ///
    /// `B_BYTES` is deliberately an exact multiple of `CREDIT_UPDATE_STEP`
    /// (128 KiB, spec §6.4): a growth announces once it reaches a whole step
    /// since the last announcement (`StreamReceiver::credit_due`), not once
    /// it reaches `B_BYTES` -- reported in 1 KiB chunks here, a growth under
    /// a step (found first with `B_BYTES` = 150 KiB) announces only its
    /// first whole step and then sits, short of `B_BYTES`, with nothing left
    /// to cross a second one; a `B_BYTES` that is itself a whole number of
    /// steps has nothing left over to strand, and the final announcement
    /// lands exactly on `STREAM_WINDOW + B_BYTES`, which is what the
    /// assertion below checks.
    ///
    /// Mirrors `an_ended_channels_late_report_after_a_reattach_credits_its_successor_nothing`
    /// above, but puts the real writer-drain-after-CLOSE machinery (a
    /// blocking thread parked on another thread's condvar, released only
    /// after the reattach) together with the ledger's `owed_old`, instead of
    /// a fake backend that reports on a test's own cue.
    #[tokio::test]
    async fn a_channel_reused_after_a_reattach_is_credited_only_its_own_report() {
        const STREAM: u8 = 16;
        // Different sizes: if A's debt were never paid (or double-paid), B's
        // own report would credit something other than exactly `B_BYTES`
        // below, discriminating the bug even though this test does not read
        // the credit limit before B's own report (see the test's own doc).
        // Both exact multiples of `CREDIT_UPDATE_STEP` (see the test's own
        // doc) and well under `STREAM_WINDOW`, so neither send is itself
        // throttled.
        const A_BYTES: usize = 3 * CREDIT_UPDATE_STEP as usize; // 384 KiB
        const B_BYTES: usize = 2 * CREDIT_UPDATE_STEP as usize; // 256 KiB

        let spawner = crate::channel_server::tests::FakeSpawner::new();
        let backend = Arc::new(RealChannelRunner(Arc::clone(&spawner)));
        let mut rig = delivery_rig(backend, |_| {}).await;

        let open_record = |stream: u8| {
            encode_client(&ClientRecord::Open(OpenRequest {
                stream,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            }))
        };

        // Channel A opens, is handed 384 KiB its process never reads (held),
        // and the client closes it before any of it is reported.
        spawner.hold_writes(true);
        rig.client_sends(CONTROL_STREAM, &open_record(STREAM));
        rig.run(Duration::from_millis(300)).await;
        rig.client_sends(STREAM, &vec![1u8; A_BYTES]);
        rig.run(Duration::from_millis(300)).await;
        rig.client_sends(
            CONTROL_STREAM,
            &encode_client(&ClientRecord::Close { stream: STREAM }),
        );
        rig.run(Duration::from_millis(300)).await;

        rig.reattach();

        // A's writer is released -- its process reads, late -- and drains
        // and reports everything it was ever handed, paying A's debt in
        // full, before channel B ever opens: no report-ordering race left to
        // reason about below.
        spawner.hold_writes(false);
        rig.run(Duration::from_millis(300)).await;

        // Channel B reuses stream 16 on the new connection and is handed
        // its own 256 KiB, which its process reads at once (not held).
        rig.client_sends(CONTROL_STREAM, &open_record(STREAM));
        rig.run(Duration::from_millis(300)).await;
        rig.client_sends(STREAM, &vec![2u8; B_BYTES]);
        rig.run(Duration::from_millis(300)).await;
        assert_eq!(
            rig.client.credit_limit_for_test(STREAM),
            Some(STREAM_WINDOW + B_BYTES as u64),
            "B's own report credits the new connection exactly B's bytes -- \
             nothing owed from A left to swallow it, and nothing extra"
        );
    }

    /// Every kind the backend heard within `window`.
    async fn heard_within(
        rx: &mut mpsc::UnboundedReceiver<&'static str>,
        window: Duration,
    ) -> Vec<&'static str> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(kind)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            out.push(kind);
        }
        out
    }

    #[tokio::test]
    async fn unnegotiated_geometry_output_fails_closed() {
        let (heard_tx, _heard_rx) = mpsc::unbounded_channel();
        let mut rig = delivery_rig_with(
            crate::Features::NONE,
            Arc::new(InboundKindsBackend(heard_tx)),
            |_| {},
        )
        .await;
        rig.backend_sends(SessionOutbound::ResumeBarrier { generation: 0 });
        rig.run(Duration::from_millis(100)).await;
        let ended = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ended.graceful);
        assert_eq!(rig.client.state(), LinkState::Closed);
    }

    /// Review, Important 2, at the bridge: `NotifyDelivered` is answered
    /// only once the client has acknowledged everything sent on the stream
    /// before it -- not when the bytes merely went out.
    #[tokio::test]
    async fn a_delivery_is_reported_once_the_clients_acks_empty_the_stream() {
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let mut rig = delivery_rig(Arc::new(InboundKindsBackend(heard_tx)), |_| {}).await;
        rig.backend_sends(SessionOutbound::Data(StreamData {
            stream_id: 16,
            data: vec![3u8; 20_000],
        }));
        rig.backend_sends(SessionOutbound::NotifyDelivered {
            stream_id: 16,
            token: 1,
        });
        let mut held = Vec::new();
        rig.pump(Duration::from_millis(300), false, &mut held).await;
        assert!(!held.is_empty(), "the client acknowledged");
        assert!(
            !heard_within(&mut heard_rx, Duration::ZERO)
                .await
                .contains(&"delivered"),
            "sent is not delivered"
        );
        for bytes in held.drain(..) {
            assert!(rig.dg_tx.send(rig.peer, bytes), "the route takes it");
        }
        let mut heard = Vec::new();
        for _ in 0..20 {
            rig.pump(Duration::from_millis(50), true, &mut held).await;
            heard.extend(heard_within(&mut heard_rx, Duration::ZERO).await);
            if heard.contains(&"delivered") {
                break;
            }
        }
        assert!(
            heard.contains(&"delivered"),
            "the ACKs deliver it: {heard:?}"
        );
    }

    /// A warm reattach brings a connection that holds none of the old one's
    /// data: every awaited delivery is answered, after `ResumeReset`. While
    /// the bridge is parked none is.
    #[tokio::test]
    async fn awaited_deliveries_wait_while_parked_and_are_answered_after_an_attach() {
        const EDGE: u8 = 17;
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let mut rig = delivery_rig_with(
            crate::Features::HEADER_AAD,
            Arc::new(InboundKindsBackend(heard_tx)),
            |conn| conn.start_stream_at_for_test(EDGE, OFFSET_LIMIT - 10),
        )
        .await;
        rig.backend_sends(SessionOutbound::Data(StreamData {
            stream_id: 16,
            data: vec![3u8; 5_000],
        }));
        rig.backend_sends(SessionOutbound::NotifyDelivered {
            stream_id: 16,
            token: 1,
        });
        // 11 bytes where 10 fit: the connection is abandoned -- the bridge parks.
        rig.backend_sends(SessionOutbound::Data(StreamData {
            stream_id: EDGE,
            data: vec![1u8; 11],
        }));
        let ended = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv())
            .await
            .expect("the bridge reports the death")
            .expect("the bridge is alive");
        assert!(!ended.graceful);
        assert!(
            !heard_within(&mut heard_rx, Duration::from_millis(300))
                .await
                .contains(&"delivered"),
            "nothing is delivered on a connection that is gone"
        );
        rig.attach_a_new_connection();
        let heard = heard_within(&mut heard_rx, Duration::from_millis(500)).await;
        let reset = heard.iter().position(|k| *k == "resume-reset");
        let delivered = heard.iter().position(|k| *k == "delivered");
        assert!(
            matches!((reset, delivered), (Some(r), Some(d)) if r < d),
            "answered after ResumeReset: {heard:?}"
        );
    }

    /// End to end: a backend that puts a large last frame on its channel's
    /// stream and says the channel ended on the control stream only once
    /// that is delivered -- the client gets every byte of the frame before
    /// the end, although the control stream is served first.
    struct LastFrameThenExit;

    impl SessionBackend for LastFrameThenExit {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                io.send(16, vec![7u8; 100_000]);
                io.notify_delivered(16, 1);
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Delivered { stream: 16, .. } = ev {
                        io.send(1, b"exit".to_vec());
                    }
                }
            })
        }
    }

    #[tokio::test]
    async fn a_record_sent_after_delivery_reaches_the_client_after_the_stream() {
        let mut rig = delivery_rig(Arc::new(LastFrameThenExit), |_| {}).await;
        let mut frame_bytes = 0usize;
        let mut buf = vec![0u8; 65536];
        let got_exit = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let (len, src) = rig.client_sock.recv_from(&mut buf).await.unwrap();
                for dg in rig.client.on_datagram(Instant::now(), src, &buf[..len]) {
                    assert!(rig.dg_tx.send(rig.peer, dg.bytes), "the route takes it");
                }
                for ev in rig.client.poll_events() {
                    if let Event::StreamData { stream_id, data } = ev {
                        match stream_id {
                            16 => frame_bytes += data.len(),
                            1 => return data,
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .expect("the exit arrives");
        assert_eq!(got_exit, b"exit");
        assert_eq!(frame_bytes, 100_000, "the whole frame came first");
    }

    /// Task 7 review: a gate closes for good however the session's io goes
    /// -- dropped by a backend that returns, or by one that panics -- so a
    /// line channel's reader waiting on it never outlives its session.
    #[tokio::test]
    async fn a_session_io_closes_its_gates_however_it_goes() {
        use crate::send_gate::{GateWait, PIPE_HIGH};
        let (io, _inbound, _outbound, gates) = SessionIo::test_pair_with_gates();
        let gate = io.send_gate(20, GateKind::Pipe);
        assert!(gates.refresh(|_| PIPE_HIGH).is_empty());
        drop(io);
        assert_eq!(
            gate.wait_open_for(Duration::ZERO),
            GateWait::Closed,
            "dropped"
        );

        let (io, _inbound, _outbound, gates) = SessionIo::test_pair_with_gates();
        let gate = io.send_gate(20, GateKind::Pipe);
        assert!(gates.refresh(|_| PIPE_HIGH).is_empty());
        // A plain thread, not a blocking task: if the gate never closed, the
        // test's own runtime would wait for a blocking task forever.
        let (woke_tx, woke_rx) = std::sync::mpsc::channel::<bool>();
        {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let _ = woke_tx.send(gate.wait_open());
            });
        }
        let backend = tokio::spawn(async move {
            let _io = io;
            panic!("a backend that fails");
        });
        assert!(backend.await.is_err(), "the backend panicked");
        let woke = woke_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the waiter wakes");
        assert!(!woke, "woken by the gate closing");
    }

    /// Task 7 review: the daemon drops its runtime when it stops, and a
    /// runtime's drop waits for every blocking thread. A line channel's
    /// reader waiting on a shut gate is one: the session's io, dropped with
    /// its task, has to close the gate, or the daemon never exits.
    #[test]
    fn dropping_the_runtime_under_a_reader_waiting_on_a_gate_does_not_hang() {
        use crate::send_gate::PIPE_HIGH;
        let (io, _inbound, _outbound, gates) = SessionIo::test_pair_with_gates();
        let gate = io.send_gate(20, GateKind::Pipe);
        assert!(gates.refresh(|_| PIPE_HIGH).is_empty());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.spawn(async move {
            let _io = io;
            std::future::pending::<()>().await
        });
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        rt.spawn_blocking(move || {
            let _ = started_tx.send(());
            gate.wait_open()
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the reader is waiting");
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            drop(rt);
            let _ = dropped_tx.send(());
        });
        dropped_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the runtime drops: the reader woke off its gate");
    }

    /// Task 7 review: a channel that closes puts its stream back in the
    /// interactive class, and the bridge keeps nothing of the earlier class
    /// to declare again, so a stream number reused after a warm reattach
    /// starts as a new stream does.
    #[tokio::test]
    async fn a_class_reset_to_interactive_is_not_brought_back_by_a_reattach() {
        let mut conn = a_quiet_server_connection();
        let mut classes = BTreeMap::new();
        declare_class(&mut conn, &mut classes, 16, StreamClass::Bulk);
        declare_class(&mut conn, &mut classes, 16, StreamClass::Interactive);
        assert_eq!(
            conn.stream_class(16),
            StreamClass::Interactive,
            "this connection"
        );
        assert!(classes.is_empty(), "nothing kept to declare again");
        let (tx, _rx) = mpsc::channel::<SessionInbound>(4);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut parked = false;
        let mut out = Vec::new();
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(
                Box::new(a_quiet_server_connection()),
                Vec::new(),
                Vec::new(),
            ),
            &classes,
            Instant::now(),
            &mut out,
        );
        assert_eq!(
            conn.stream_class(16),
            StreamClass::Interactive,
            "the next one"
        );
    }

    // ---- The authentication gate ---------------------------------------

    /// A verifier that accepts exactly one record body and counts attempts.
    struct FakeVerifier {
        expected: Vec<u8>,
        attempts: Arc<AtomicUsize>,
    }

    impl FakeVerifier {
        /// A verifier that accepts the signature body `b"good"`, with a fresh
        /// attempt counter nobody looks at.
        fn accepting_good() -> FakeVerifier {
            FakeVerifier {
                expected: b"good".to_vec(),
                attempts: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl AuthVerifier for FakeVerifier {
        fn verify(
            &self,
            _handshake_hash: &[u8; 32],
            record: &AuthRecord,
            _login: [u8; 16],
            _rhost: &str,
        ) -> Result<Principal, AuthError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if record.signature == self.expected {
                Ok(Principal {
                    // Same uid as `test_self_principal` (every `start_manager`
                    // server's `self_principal`): in personal mode, the
                    // signature path and the allowlist path both speak for
                    // the daemon's one account, so a signature-proven
                    // reattach onto an allowlist-created session is the SAME
                    // owner -- exactly the case these tests exercise.
                    uid: 0,
                    name: "test".to_string(),
                    identity: "fake-key".to_string(),
                    incarnation: 0,
                })
            } else {
                Err(AuthError::BadSignature)
            }
        }
    }

    /// A backend that logs everything it is told -- data verbatim, other
    /// events as `<live>`/`<reset>` markers -- and, once started, produces
    /// output on its own. So a test can tell whether an unproven peer's input
    /// reached the session, and whether the session's output reached that
    /// peer, without either depending on the other.
    struct ChattyBackend {
        log: Arc<Mutex<Vec<u8>>>,
    }

    impl SessionBackend for ChattyBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let log = self.log.clone();
            Box::pin(async move {
                loop {
                    tokio::select! {
                        ev = io.recv() => {
                            let mut log = log.lock().unwrap();
                            match ev {
                                Some(SessionInbound::Data(StreamData { data, .. })) => {
                                    log.extend_from_slice(&data);
                                }
                                Some(SessionInbound::Live(_)) => log.extend_from_slice(b"<live>"),
                                Some(SessionInbound::ResumeReset(_)) => {
                                    log.extend_from_slice(b"<reset>");
                                }
                                Some(SessionInbound::Repaint | SessionInbound::RepaintCutover { .. }) => {
                                    log.extend_from_slice(b"<repaint>");
                                }
                                Some(SessionInbound::Writable { .. }) => {
                                    log.extend_from_slice(b"<writable>");
                                }
                                Some(SessionInbound::Delivered { .. }) => {
                                    log.extend_from_slice(b"<delivered>");
                                }
                                Some(SessionInbound::OutputReady { .. }) => log.extend_from_slice(b"<output-ready>"),
                                None => return,
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {
                            io.send(0, b"tick".to_vec());
                        }
                    }
                }
            })
        }
    }

    /// Read the backend's log as text.
    fn log_text(log: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8_lossy(&log.lock().unwrap()).to_string()
    }

    /// Poll the backend's log until it reads `want`, up to two seconds. The
    /// backend is a separate task, so what it has been told is not observable
    /// the instant the manager sends it.
    async fn wait_for_log(log: &Arc<Mutex<Vec<u8>>>, want: &str) -> String {
        for _ in 0..100 {
            if log_text(log) == want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        log_text(log)
    }

    /// A placeholder `Principal` for `ServerAuth::self_principal` in tests
    /// that never look at it -- everything below this line that isn't about
    /// the principal reaching a backend.
    fn test_self_principal() -> Principal {
        Principal {
            uid: 0,
            name: "test-server".to_string(),
            identity: "test-server".to_string(),
            incarnation: 0,
        }
    }

    /// A `NonceSource` for tests that don't care where a handshake's nonce
    /// comes from -- everything below this line that isn't about
    /// `NonceSource` itself (that lives in `conn.rs`'s own tests, which
    /// exercise `Connection::accept`'s nonce handling directly).
    struct TestNonces;

    impl NonceSource for TestNonces {
        fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
            Ok(rand::thread_rng().gen())
        }
        // Nothing is tracked, so there is nothing to give up.
        fn release(&self, _nonce: [u8; AUTH_NONCE_LEN]) {}
    }

    /// The allowlist-only server setup -- no verifier, so the gate is open
    /// from the start. What every manager test above this line runs with.
    fn allowlist_auth(allowlist: SharedAllowlist, server_pub: [u8; 32]) -> ServerAuth {
        ServerAuth {
            allowlist,
            verifier: None,
            server_pub,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        }
    }

    /// A manager running on a loopback socket, plus what a test needs to
    /// address it.
    struct TestServer {
        addr: SocketAddr,
        public_key: [u8; 32],
    }

    /// Spawn a manager on a fresh loopback socket with the given backend and
    /// authentication setup.
    async fn start_manager(
        backend: Arc<dyn SessionBackend>,
        allowlist: Vec<[u8; 32]>,
        verifier: Option<Arc<dyn AuthVerifier>>,
    ) -> TestServer {
        start_manager_shared(backend, Arc::new(Mutex::new(allowlist)), verifier).await
    }

    /// Like [`start_manager`], but the caller keeps the SHARED allowlist so it
    /// can watch what the manager does to it.
    async fn start_manager_shared(
        backend: Arc<dyn SessionBackend>,
        allowlist: SharedAllowlist,
        verifier: Option<Arc<dyn AuthVerifier>>,
    ) -> TestServer {
        let server_kp = generate_keypair();
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = server_sock.local_addr().unwrap();
        tokio::spawn(SessionManager::serve(
            server_sock,
            server_kp.private,
            ServerAuth {
                allowlist,
                verifier,
                server_pub: server_kp.public,
                self_principal: test_self_principal(),
                nonces: Arc::new(TestNonces),
                logins: Arc::new(ForgetNothing),
            },
            BackendFactory(backend),
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));
        TestServer {
            addr,
            public_key: server_kp.public,
        }
    }

    /// A manager that authenticates by SSH signature, and a client that
    /// announces that method. Returns the client and the server's public key.
    async fn start_manager_with_signature_auth(
        backend: impl SessionBackend,
        verifier: impl AuthVerifier,
    ) -> (TestClient, [u8; 32]) {
        let server = start_manager(Arc::new(backend), Vec::new(), Some(Arc::new(verifier))).await;
        let client = TestClient::new(
            &server,
            [1u8; 16],
            StartKind::Cold,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        (client, server.public_key)
    }

    /// A manager on the established allowlist path (no verifier), and a client
    /// whose static key is on that allowlist.
    async fn start_manager_with_allowlist(backend: impl SessionBackend) -> TestClient {
        let client_kp = generate_keypair();
        let server = start_manager(Arc::new(backend), vec![client_kp.public], None).await;
        TestClient::new(
            &server,
            [1u8; 16],
            StartKind::Cold,
            AuthMethod::Allowlist,
            client_kp.private,
        )
        .await
    }

    /// A manager for discovery-only tests: no handshake is exercised, so an
    /// empty allowlist is fine -- `KeyRequest` never reaches the auth gate.
    /// A verifier IS required though: discovery is answered only by a daemon
    /// that runs the signature path, which is the only kind whose clients need
    /// to learn its key. Returns the manager's address and its public key.
    async fn start_manager_for_discovery() -> (SocketAddr, [u8; 32]) {
        let server = start_manager(
            Arc::new(EchoBackend),
            Vec::new(),
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;
        (server.addr, server.public_key)
    }

    /// The daemon answers a well-formed discovery request with its key, and
    /// stays silent for a short one.
    #[tokio::test]
    async fn discovery_answers_a_padded_request_only() {
        let (addr, server_pub) = start_manager_for_discovery().await;
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        probe.send_to(&encode_key_request(), addr).await.unwrap();
        let mut buf = [0u8; 128];
        let n = tokio::time::timeout(Duration::from_secs(2), probe.recv(&mut buf))
            .await
            .expect("the daemon must answer a padded request")
            .unwrap();
        match parse(&buf[..n]).expect("valid frame") {
            Frame::Handshake { kind, body } => {
                assert_eq!(kind, Kind::KeyOffer);
                assert_eq!(parse_key_offer(body).unwrap(), server_pub);
            }
            _ => panic!("expected a key offer"),
        }

        // Too short to pay for the answer.
        probe
            .send_to(&encode_handshake(Kind::KeyRequest, &[VERSION]), addr)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), probe.recv(&mut buf))
                .await
                .is_err(),
            "an unpadded request must draw no reply"
        );
    }

    /// A daemon with no verifier -- the `transport-ensure` one, reached only
    /// by clients handed its key over SSH -- says NOTHING to a discovery
    /// request, however well-formed. Discovery exists for a client that has
    /// never met the server; answering where nobody needs it would only give
    /// a port scan an unauthenticated fingerprint of the service.
    #[tokio::test]
    async fn discovery_is_silent_without_a_verifier() {
        let server = start_manager(Arc::new(EchoBackend), Vec::new(), None).await;
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        probe
            .send_to(&encode_key_request(), server.addr)
            .await
            .unwrap();
        let mut buf = [0u8; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), probe.recv(&mut buf))
                .await
                .is_err(),
            "an allowlist-only daemon must not answer a discovery request"
        );
    }

    /// A client `Connection` on a loopback socket, pumped ON DEMAND (no
    /// background task), so a test can assert that nothing came back.
    struct TestClient {
        conn: Connection,
        sock: UdpSocket,
        server_addr: SocketAddr,
        token: [u8; 16],
        start_kind: StartKind,
        method: AuthMethod,
        buf: Vec<u8>,
        /// Stream-0 payloads already pumped off the socket, not yet consumed.
        inbox: std::collections::VecDeque<Vec<u8>>,
        /// Playing a client built before negotiation and cookies
        /// ([`TestClient::play_legacy`]).
        legacy: bool,
    }

    impl TestClient {
        async fn new(
            server: &TestServer,
            token: [u8; 16],
            start_kind: StartKind,
            method: AuthMethod,
            client_priv: [u8; 32],
        ) -> TestClient {
            TestClient {
                conn: Connection::new(ConnectionConfig {
                    required_features: crate::Features::NONE,
                    features: crate::Features::SUPPORTED,
                    role: Role::Client,
                    local_static_priv: client_priv,
                    remote_static_pub: Some(server.public_key),
                    auth: match method {
                        AuthMethod::Allowlist => AuthPolicy::Allowlist(Vec::new()),
                        AuthMethod::SshSignature => AuthPolicy::SshSignature,
                    },
                }),
                sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                server_addr: server.addr,
                token,
                start_kind,
                method,
                buf: vec![0u8; RECV_BUF_LEN],
                inbox: std::collections::VecDeque::new(),
                legacy: false,
            }
        }

        /// msg1 -> msg2 -> `Live`. Bounded so a wedged manager fails the test
        /// instead of hanging the suite.
        async fn handshake(&mut self) {
            let payload = encode_msg1(&self.msg1_payload());
            self.handshake_with(&payload).await;
        }

        /// What this client's msg1 says: its start, token and method, and an
        /// offer of what this build implements.
        fn msg1_payload(&self) -> Msg1Payload {
            Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: self.start_kind,
                token: self.token,
                method: self.method,
            }
        }

        /// [`TestClient::handshake`] with a msg1 payload of the caller's --
        /// one without the features field, say, as a build from before
        /// negotiation writes it.
        async fn handshake_with(&mut self, payload: &[u8]) {
            let m1 = self
                .conn
                .start_with_payload(Instant::now(), self.server_addr, payload);
            send_client(&self.sock, &m1).await;
            let (len, src) =
                tokio::time::timeout(Duration::from_secs(5), self.sock.recv_from(&mut self.buf))
                    .await
                    .expect("msg2 did not arrive")
                    .unwrap();
            let out = self.conn.on_datagram(Instant::now(), src, &self.buf[..len]);
            send_client(&self.sock, &out).await;
        }

        /// Play a client built before negotiation and cookies (spec §9.3):
        /// a 19-byte msg1, and deaf to `CookieReply`.
        fn play_legacy(&mut self) {
            self.legacy = true;
            self.conn.act_as_legacy_peer_for_test();
        }

        /// msg1 -> msg2 -> `Live` the way the driver does it: msg1 again
        /// every `HANDSHAKE_RETRANSMIT`, whatever the server answers fed
        /// back -- a cookie reply included. Starts the handshake on the
        /// first call and carries it on in later ones. `true` once `Live`.
        async fn handshake_through_load(&mut self, within: Duration) -> bool {
            if self.conn.handshake_datagrams().is_empty() && self.conn.state() != LinkState::Live {
                let fields = Msg1Payload {
                    start_kind: self.start_kind,
                    token: self.token,
                    method: self.method,
                    offered: if self.legacy {
                        crate::Features::NONE
                    } else {
                        crate::Features::SUPPORTED
                    },
                };
                let payload = if self.legacy {
                    encode_msg1_without_tail(&fields)
                } else {
                    encode_msg1(&fields)
                };
                let m1 = self
                    .conn
                    .start_with_payload(Instant::now(), self.server_addr, &payload);
                send_client(&self.sock, &m1).await;
            }
            let deadline = tokio::time::Instant::now() + within;
            let mut next_retransmit =
                tokio::time::Instant::now() + crate::driver_std::HANDSHAKE_RETRANSMIT;
            while self.conn.state() != LinkState::Live {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return false;
                }
                if now >= next_retransmit {
                    let again = self.conn.retransmit_handshake();
                    send_client(&self.sock, &again).await;
                    next_retransmit = now + crate::driver_std::HANDSHAKE_RETRANSMIT;
                }
                let wait = next_retransmit.min(deadline) - now;
                if let Ok(Ok((len, src))) =
                    tokio::time::timeout(wait, self.sock.recv_from(&mut self.buf)).await
                {
                    let out = self.conn.on_datagram(Instant::now(), src, &self.buf[..len]);
                    send_client(&self.sock, &out).await;
                }
            }
            true
        }

        /// Send `data` on `stream_id`.
        async fn send(&mut self, stream_id: u8, data: Vec<u8>) {
            let out = self.conn.send(Instant::now(), stream_id, &data);
            send_client(&self.sock, &out).await;
        }

        /// Process every datagram already waiting on the socket WITHOUT
        /// blocking, then hand over the first undelivered stream-0 payload.
        /// `None` means the server sent nothing but protocol chatter (ACKs).
        fn try_recv(&mut self) -> Option<Vec<u8>> {
            while let Ok((len, src)) = self.sock.try_recv_from(&mut self.buf) {
                let out = self.conn.on_datagram(Instant::now(), src, &self.buf[..len]);
                for dg in &out {
                    let _ = self.sock.try_send_to(&dg.bytes, dg.to);
                }
                self.collect_stream0();
            }
            self.inbox.pop_front()
        }

        /// Pump the socket until a stream-0 payload is delivered or `within`
        /// elapses.
        async fn recv_stream0_opt(&mut self, within: Duration) -> Option<Vec<u8>> {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if let Some(data) = self.inbox.pop_front() {
                    return Some(data);
                }
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    return None;
                }
                let recv = tokio::time::timeout(left, self.sock.recv_from(&mut self.buf)).await;
                let (len, src) = match recv {
                    Ok(Ok(v)) => v,
                    _ => return None,
                };
                let out = self.conn.on_datagram(Instant::now(), src, &self.buf[..len]);
                send_client(&self.sock, &out).await;
                self.collect_stream0();
            }
        }

        /// Read datagrams until the server has been quiet for `quiet`. Used
        /// before asserting on silence, so chatter that was already in flight
        /// cannot be mistaken for a reply to what comes next.
        async fn drain_until_silent(&mut self, quiet: Duration) {
            while tokio::time::timeout(quiet, self.sock.recv_from(&mut self.buf))
                .await
                .is_ok()
            {}
        }

        /// Wait for ANY datagram from the server -- an ACK counts. A server
        /// that tore this session down routes nothing back at all, which is
        /// what tells a refused session apart from a merely silent one.
        async fn saw_reply(&mut self, within: Duration) -> bool {
            tokio::time::timeout(within, self.sock.recv_from(&mut self.buf))
                .await
                .is_ok()
        }

        /// Like [`TestClient::recv_stream0_opt`], but the payload is required.
        async fn recv_stream0(&mut self, within: Duration) -> Vec<u8> {
            self.recv_stream0_opt(within)
                .await
                .expect("no stream-0 data arrived in time")
        }

        /// Like [`TestClient::recv_stream0`], but with the client's timers
        /// running while it waits, as a driver runs them: what the server
        /// never read -- a datagram its full socket buffer dropped, behind a
        /// flood -- the transport sends again.
        async fn recv_stream0_with_timers(&mut self, within: Duration) -> Vec<u8> {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if let Some(data) = self.inbox.pop_front() {
                    return data;
                }
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                assert!(!left.is_zero(), "no stream-0 data arrived in time");
                let slice = left.min(Duration::from_millis(20));
                if let Ok(Ok((len, src))) =
                    tokio::time::timeout(slice, self.sock.recv_from(&mut self.buf)).await
                {
                    let out = self.conn.on_datagram(Instant::now(), src, &self.buf[..len]);
                    send_client(&self.sock, &out).await;
                    self.collect_stream0();
                }
                let out = self.conn.on_timeout_if_due(Instant::now());
                send_client(&self.sock, &out).await;
            }
        }

        /// Send the proof `FakeVerifier::accepting_good` takes, then `data`
        /// on stream 0, and wait -- timers running, behind a flood, see
        /// [`TestClient::recv_stream0_with_timers`] -- for its echo.
        async fn prove_and_echo(&mut self, data: &[u8]) {
            self.send(
                AUTH_STREAM,
                encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"good".to_vec(),
                    v2: None,
                })
                .expect("encodes"),
            )
            .await;
            self.send(0, data.to_vec()).await;
            assert_eq!(
                self.recv_stream0_with_timers(Duration::from_secs(5)).await,
                data
            );
        }

        /// Move freshly delivered stream-0 bytes into the inbox.
        fn collect_stream0(&mut self) {
            for ev in self.conn.poll_events() {
                if let Event::StreamData { stream_id: 0, data } = ev {
                    self.inbox.push_back(data);
                }
            }
        }
    }

    /// Spec §5.5: the daemon's log names what each session's connection
    /// agreed.
    #[tokio::test]
    async fn a_session_logs_what_its_connection_agreed() {
        SESSION_FEATURES_LOGGED.with(|l| l.borrow_mut().clear());
        let mut client = start_manager_with_allowlist(EchoBackend).await;
        client.handshake().await;
        client.send(0, b"hi".to_vec()).await;
        assert_eq!(client.recv_stream0(Duration::from_secs(2)).await, b"hi");
        assert_eq!(
            SESSION_FEATURES_LOGGED.with(|l| l.borrow().clone()),
            vec![format!(
                "session {:016x}: transport features {}",
                client.conn.session_id(),
                crate::Features::SUPPORTED.describe()
            )]
        );
    }

    /// Task 3 review: the mode is negotiated on the session manager's own
    /// path, not only by `accept` called directly. A new client gets the
    /// header under the AEAD; one that sends the 19-byte msg1 of a build
    /// from before negotiation gets the old mode. Both sides agree (the
    /// client's reading of msg2, the daemon's log line), and both carry data.
    #[tokio::test]
    async fn the_manager_agrees_with_each_client_on_what_its_msg1_offered() {
        SESSION_FEATURES_LOGGED.with(|l| l.borrow_mut().clear());
        let new_kp = generate_keypair();
        let old_kp = generate_keypair();
        let server = start_manager(
            Arc::new(EchoBackend),
            vec![new_kp.public, old_kp.public],
            None,
        )
        .await;
        let mut new = TestClient::new(
            &server,
            [1u8; 16],
            StartKind::Cold,
            AuthMethod::Allowlist,
            new_kp.private,
        )
        .await;
        new.handshake().await;
        let mut old = TestClient::new(
            &server,
            [2u8; 16],
            StartKind::Cold,
            AuthMethod::Allowlist,
            old_kp.private,
        )
        .await;
        let legacy_msg1 = encode_msg1_without_tail(&old.msg1_payload());
        assert_eq!(legacy_msg1.len(), 19);
        old.handshake_with(&legacy_msg1).await;
        for (client, agreed, header) in [
            (&mut new, crate::Features::SUPPORTED, true),
            (&mut old, crate::Features::NONE, false),
        ] {
            assert_eq!(client.conn.features(), agreed);
            assert_eq!(client.conn.keys_use_header_for_test(), Some(header));
            client.send(0, b"hi".to_vec()).await;
            assert_eq!(client.recv_stream0(Duration::from_secs(2)).await, b"hi");
        }
        assert_eq!(
            SESSION_FEATURES_LOGGED.with(|l| l.borrow().clone()),
            vec![
                format!(
                    "session {:016x}: transport features {}",
                    new.conn.session_id(),
                    crate::Features::SUPPORTED.describe()
                ),
                format!(
                    "session {:016x}: transport features none",
                    old.conn.session_id()
                ),
            ]
        );
    }

    /// Spec §5.5: a warm reattach binds a new connection to the running
    /// session, and the log names what that one agreed as well.
    #[tokio::test]
    async fn a_warm_reattach_logs_what_its_new_connection_agreed() {
        SESSION_FEATURES_LOGGED.with(|l| l.borrow_mut().clear());
        let kp = generate_keypair();
        let server = start_manager(Arc::new(EchoBackend), vec![kp.public], None).await;
        let mut first = TestClient::new(
            &server,
            [7u8; 16],
            StartKind::Cold,
            AuthMethod::Allowlist,
            kp.private,
        )
        .await;
        first.handshake().await;
        first.send(0, b"first".to_vec()).await;
        assert_eq!(first.recv_stream0(Duration::from_secs(2)).await, b"first");
        let mut second = TestClient::new(
            &server,
            [7u8; 16],
            StartKind::Warm,
            AuthMethod::Allowlist,
            kp.private,
        )
        .await;
        second.handshake().await;
        second.send(0, b"second".to_vec()).await;
        assert_eq!(second.recv_stream0(Duration::from_secs(2)).await, b"second");
        assert_ne!(first.conn.session_id(), second.conn.session_id());
        assert_eq!(
            SESSION_FEATURES_LOGGED.with(|l| l.borrow().clone()),
            vec![
                format!(
                    "session {:016x}: transport features {}",
                    first.conn.session_id(),
                    crate::Features::SUPPORTED.describe()
                ),
                format!(
                    "session {:016x}: transport features {}",
                    second.conn.session_id(),
                    crate::Features::SUPPORTED.describe()
                ),
            ]
        );
    }

    /// Until the proof arrives the session does not exist: no backend is
    /// created, so no PTY is spawned for a client that never proves anything.
    #[tokio::test]
    async fn no_backend_is_created_before_the_client_authenticates() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let (mut client, _) = start_manager_with_signature_auth(
            CountingEchoBackend {
                spawns: spawned.clone(),
            },
            FakeVerifier::accepting_good(),
        )
        .await;

        // Handshake completes, then ordinary data goes out on stream 0.
        client.handshake().await;
        client.send(0, b"hello".to_vec()).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "a backend before the proof would mean a PTY for an unauthenticated peer"
        );
        assert!(
            client.try_recv().is_none(),
            "nothing may come back before the proof"
        );

        // The proof opens the gate: the backend appears and the echo flows.
        client
            .send(
                AUTH_STREAM,
                encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"good".to_vec(),
                    v2: None,
                })
                .expect("encodes"),
            )
            .await;
        client.send(0, b"hello".to_vec()).await;
        let echoed = client.recv_stream0(Duration::from_secs(2)).await;
        assert_eq!(echoed, b"hello");
        assert_eq!(spawned.load(Ordering::SeqCst), 1, "exactly one backend");
    }

    /// A wrong proof closes the connection instead of leaving it hanging.
    #[tokio::test]
    async fn a_bad_proof_closes_the_connection() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let (mut client, _) = start_manager_with_signature_auth(
            CountingEchoBackend {
                spawns: spawned.clone(),
            },
            FakeVerifier::accepting_good(),
        )
        .await;
        client.handshake().await;
        client
            .send(
                AUTH_STREAM,
                encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"wrong".to_vec(),
                    v2: None,
                })
                .expect("encodes"),
            )
            .await;
        // Wait for the ACK of the record's own datagram (the server sends it
        // before it ever looks at the record), then drain whatever else is
        // queued. No fixed sleep: the assertion below must be about what the
        // server does AFTER the refusal, not about how fast that ACK was.
        assert!(
            client.saw_reply(Duration::from_secs(2)).await,
            "the record's datagram is acknowledged at the transport level"
        );
        assert!(
            client.try_recv().is_none(),
            "a rejected client gets no session"
        );
        // Drain to SILENCE, not just one datagram: the server may have more
        // than one reply already in flight (an ACK and a PING, say), and one
        // left in the socket would land in the final window below and fail
        // this test for the wrong reason.
        client.drain_until_silent(Duration::from_millis(300)).await;

        // Closed, not merely shut: the session is gone from the router, so
        // nothing is answered any more -- not even an ACK. Asserting only
        // "no echo" would pass just as well if the refusal were ignored and
        // the gate simply stayed closed.
        client.send(0, b"hello".to_vec()).await;
        assert!(
            !client.saw_reply(Duration::from_millis(300)).await,
            "a refused proof closes the connection"
        );
        assert_eq!(spawned.load(Ordering::SeqCst), 0);
    }

    /// The allowlist path is untouched: no verifier, no gate, same behavior
    /// as before this task existed.
    #[tokio::test]
    async fn the_allowlist_path_needs_no_proof() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let mut client = start_manager_with_allowlist(CountingEchoBackend {
            spawns: spawned.clone(),
        })
        .await;
        client.handshake().await;
        client.send(0, b"hi".to_vec()).await;
        assert_eq!(client.recv_stream0(Duration::from_secs(2)).await, b"hi");
        assert_eq!(spawned.load(Ordering::SeqCst), 1);
    }

    /// A warm reattach brings a NEW handshake, so it brings a new challenge:
    /// a peer arriving on the signature path must prove itself before it
    /// inherits a session that the allowlist path created -- otherwise
    /// announcing `SshSignature` (which admits ANY static key) would be a way
    /// to walk into someone else's running backend.
    #[tokio::test]
    async fn a_signature_reattach_must_prove_itself_before_it_inherits_the_session() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let token = [7u8; 16];
        let allowlisted_kp = generate_keypair();
        // This server runs BOTH policies at once: the SSH-bootstrap allowlist
        // and the signature path.
        let server = start_manager(
            Arc::new(CountingEchoBackend {
                spawns: spawned.clone(),
            }),
            vec![allowlisted_kp.public],
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;

        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            allowlisted_kp.private,
        )
        .await;
        owner.handshake().await;
        owner.send(0, b"mine".to_vec()).await;
        assert_eq!(owner.recv_stream0(Duration::from_secs(2)).await, b"mine");

        // A second peer warm-reattaches to the SAME token over the signature
        // path, with a static key nobody allowlisted.
        let mut newcomer = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        newcomer.handshake().await;
        newcomer.send(0, b"theirs".to_vec()).await;
        assert!(
            newcomer
                .recv_stream0_opt(Duration::from_millis(300))
                .await
                .is_none(),
            "an unproven reattach must not reach the running session"
        );

        // Its proof lets it in -- to the SAME backend (no second spawn).
        newcomer
            .send(
                AUTH_STREAM,
                encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"good".to_vec(),
                    v2: None,
                })
                .expect("encodes"),
            )
            .await;
        newcomer.send(0, b"theirs".to_vec()).await;
        assert_eq!(
            newcomer.recv_stream0(Duration::from_secs(2)).await,
            b"theirs"
        );
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "the reattach inherits the running backend rather than spawning one"
        );
    }

    /// While the gate is shut over a RUNNING session, the peer behind it is
    /// deaf and mute: its bytes never reach the backend (an unproven peer must
    /// not get to type into someone's shell) and the backend's output never
    /// reaches it (it must not get to read that shell either). The backend
    /// talks on its own here, so each direction is observable without the
    /// other.
    #[tokio::test]
    async fn an_unproven_reattach_neither_speaks_to_the_session_nor_hears_it() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let token = [9u8; 16];
        let allowlisted_kp = generate_keypair();
        let server = start_manager(
            Arc::new(ChattyBackend { log: log.clone() }),
            vec![allowlisted_kp.public],
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;

        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            allowlisted_kp.private,
        )
        .await;
        owner.handshake().await;
        assert_eq!(
            owner.recv_stream0(Duration::from_secs(2)).await,
            b"tick",
            "the session is running and producing output"
        );

        // A newcomer takes the token over on the signature path and starts
        // typing without proving anything.
        let mut newcomer = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        newcomer.handshake().await;
        newcomer.send(0, b"secret-input".to_vec()).await;

        assert!(
            newcomer
                .recv_stream0_opt(Duration::from_millis(400))
                .await
                .is_none(),
            "the session keeps producing output, but none of it may reach an unproven peer"
        );
        assert_eq!(
            log_text(&log),
            "<live>",
            "neither an unproven peer's bytes nor its reattach may reach the backend"
        );
    }

    /// The reattach itself is not lost to the gate: on the allowlist path a
    /// warm reconnect still tells the backend to resume, exactly once, and
    /// still never repeats `Live`.
    #[tokio::test]
    async fn a_warm_reattach_still_resumes_the_backend() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let token = [4u8; 16];
        let client_kp = generate_keypair();
        let server = start_manager(
            Arc::new(ChattyBackend { log: log.clone() }),
            vec![client_kp.public],
            None,
        )
        .await;

        let mut first = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            client_kp.private,
        )
        .await;
        first.handshake().await;
        assert_eq!(first.recv_stream0(Duration::from_secs(2)).await, b"tick");

        let mut second = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::Allowlist,
            client_kp.private,
        )
        .await;
        second.handshake().await;
        assert_eq!(second.recv_stream0(Duration::from_secs(2)).await, b"tick");
        assert_eq!(wait_for_log(&log, "<live><reset>").await, "<live><reset>");
    }

    /// A peer that never proves anything does not get to linger: the gate's
    /// own deadline tears the session down, so an unauthenticated connection
    /// cannot sit on a routing entry, a bridge task and a session slot.
    #[tokio::test]
    async fn a_silent_peer_is_dropped_when_the_deadline_passes() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let (mut client, _) = start_manager_with_signature_auth(
            CountingEchoBackend {
                spawns: spawned.clone(),
            },
            FakeVerifier::accepting_good(),
        )
        .await;
        client.handshake().await;

        // Real time, not the paused clock: the probation deadline is a
        // `std::time::Instant`, which `tokio::time::advance` cannot move.
        tokio::time::sleep(crate::auth::AUTH_DEADLINE + Duration::from_millis(400)).await;
        // Drop the liveness pings that piled up while we waited.
        assert!(client.try_recv().is_none(), "a silent peer gets no session");

        client.send(0, b"hello".to_vec()).await;
        assert!(
            !client.saw_reply(Duration::from_millis(300)).await,
            "past the deadline the session is gone: nothing is answered any more"
        );
        assert_eq!(spawned.load(Ordering::SeqCst), 0);
    }

    /// The record `FakeVerifier::accepting_good` accepts.
    fn good_record() -> Vec<u8> {
        encode_auth_record(&AuthRecord {
            public_key: b"key".to_vec(),
            signature: b"good".to_vec(),
            v2: None,
        })
        .expect("encodes")
    }

    /// A client types in the same breath as its proof. Those bytes reach the
    /// probation task, whose connection ACKs them, so dropping them there
    /// would lose them for good -- the peer will never send them again. They
    /// must survive the handover and arrive AFTER the backend is told its
    /// session started, never before.
    #[tokio::test]
    async fn keystrokes_sent_before_the_proof_survive_the_handover() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let (mut client, _) = start_manager_with_signature_auth(
            ChattyBackend { log: log.clone() },
            FakeVerifier::accepting_good(),
        )
        .await;
        client.handshake().await;
        client.send(0, b"typed-early".to_vec()).await;
        // Long enough for the probation task to have taken those bytes in.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            log_text(&log),
            "",
            "nothing may reach a backend before the proof -- there is no backend"
        );

        client.send(AUTH_STREAM, good_record()).await;
        assert_eq!(
            wait_for_log(&log, "<live>typed-early").await,
            "<live>typed-early",
            "the early bytes arrive, and only after the backend hears its session started"
        );
    }

    /// Everything a peer sent BEFORE its proof landed is replayed to the
    /// backend when the session is finally bound -- after `Live`, in order,
    /// and however much of it there is. The replay goes into the BOUNDED
    /// inbound channel, so more entries than `INBOUND_CAP` are exactly the
    /// case that would wedge a bridge whose backend was not running yet.
    #[tokio::test]
    async fn a_backlog_collected_before_the_proof_is_replayed_after_live() {
        let backlog = INBOUND_CAP + 50;
        let log = Arc::new(Mutex::new(Vec::new()));
        let kp = generate_keypair();
        let conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::SshSignature,
        });
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (_dg_tx, dg_rx) = dgram_queue();
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token: [0u8; 16],
            backend: Arc::new(ChattyBackend { log: log.clone() }),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: [0u8; 16],
                gates: Arc::new(GateTable::new()),
            },
            start: BridgeStart {
                saw_live: true,
                early: (0..backlog)
                    .map(|_| StreamData {
                        stream_id: 0,
                        data: b"x".to_vec(),
                    })
                    .collect(),
            },
            active_count: Arc::new(AtomicUsize::new(0)),
            gates: Arc::new(GateTable::new()),
        }));

        let want = format!("<live>{}", "x".repeat(backlog));
        assert_eq!(
            wait_for_log(&log, &want).await,
            want,
            "everything collected in probation must reach the backend, after Live, in order"
        );
    }

    /// A signature peer that never proves anything creates NOTHING: no
    /// backend, and no entry for the token it claimed. So the token's real
    /// owner still gets a fresh session out of it, rather than finding it
    /// occupied by a stranger's unproven handshake.
    #[tokio::test]
    async fn a_silent_signature_peer_leaves_the_token_free_for_its_owner() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let token = [5u8; 16];
        let allowlisted_kp = generate_keypair();
        let server = start_manager(
            Arc::new(ChattyBackend { log: log.clone() }),
            vec![allowlisted_kp.public],
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;

        // A signature client claims the token, then says nothing.
        let mut silent = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        silent.handshake().await;
        assert!(
            silent
                .recv_stream0_opt(Duration::from_millis(200))
                .await
                .is_none(),
            "an unproven peer gets no session"
        );
        assert_eq!(log_text(&log), "", "and no backend was started for it");

        // The allowlisted owner takes the token: its key IS its proof.
        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::Allowlist,
            allowlisted_kp.private,
        )
        .await;
        owner.handshake().await;
        assert_eq!(owner.recv_stream0(Duration::from_secs(2)).await, b"tick");
        assert_eq!(
            wait_for_log(&log, "<live>").await,
            "<live>",
            "the backend is started, not told to reset something that never existed"
        );
    }

    /// The same on a WARM reattach: a proven newcomer inherits the running
    /// backend, and the bytes it typed while still on probation arrive there
    /// -- after the `ResumeReset` that tells the backend a new client took
    /// over, never before it.
    #[tokio::test]
    async fn keystrokes_sent_before_a_reattach_proof_arrive_after_the_reset() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let token = [6u8; 16];
        let owner_kp = generate_keypair();
        let server = start_manager(
            Arc::new(ChattyBackend { log: log.clone() }),
            vec![owner_kp.public],
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;
        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            owner_kp.private,
        )
        .await;
        owner.handshake().await;
        assert_eq!(wait_for_log(&log, "<live>").await, "<live>");

        // A signature peer reattaches and types before proving anything.
        let mut newcomer = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        newcomer.handshake().await;
        newcomer.send(0, b"typed-early".to_vec()).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            log_text(&log),
            "<live>",
            "an unproven reattach reaches the backend with neither its reset nor its bytes"
        );

        newcomer.send(AUTH_STREAM, good_record()).await;
        assert_eq!(
            wait_for_log(&log, "<live><reset>typed-early").await,
            "<live><reset>typed-early",
            "the reattach resets the backend first, then hands it what was typed"
        );
    }

    // ---- an unproven peer cannot disturb an existing session ----

    /// Owner + attacker on one manager that runs BOTH policies: the owner is
    /// allowlisted and holds `token`, the attacker announces `SshSignature`
    /// (which admits ANY static key) against the same token. Returns the
    /// shared allowlist, the owner's key and both clients, with the owner's
    /// session already running.
    async fn owner_and_unproven_attacker(
        backend: Arc<dyn SessionBackend>,
        token: [u8; 16],
        attacker_start: StartKind,
    ) -> (SharedAllowlist, [u8; 32], TestClient, TestClient) {
        let owner_kp = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![owner_kp.public]));
        let server = start_manager_shared(
            backend,
            allowlist.clone(),
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;
        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            owner_kp.private,
        )
        .await;
        owner.handshake().await;
        owner.send(0, b"mine".to_vec()).await;
        assert_eq!(
            owner.recv_stream0(Duration::from_secs(2)).await,
            b"mine",
            "the owner's session must be running before the attacker arrives"
        );

        let mut attacker = TestClient::new(
            &server,
            token,
            attacker_start,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        attacker.handshake().await;
        // Give the manager time to have done the damage, if it were going to.
        tokio::time::sleep(Duration::from_millis(200)).await;
        (allowlist, owner_kp.public, owner, attacker)
    }

    /// A COLD handshake on a token that already has a session tears the old
    /// backend down and cold-creates in its place. On the signature path that
    /// decision must wait for the proof: otherwise one handshake from anyone
    /// who has seen a token destroys the owner's running session.
    #[tokio::test]
    async fn an_unproven_cold_handshake_leaves_the_owners_session_running() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let (_allowlist, _owner_key, mut owner, _attacker) = owner_and_unproven_attacker(
            Arc::new(CountingEchoBackend {
                spawns: spawned.clone(),
            }),
            [7u8; 16],
            StartKind::Cold,
        )
        .await;

        owner.send(0, b"still-mine".to_vec()).await;
        assert_eq!(
            owner.recv_stream0(Duration::from_secs(2)).await,
            b"still-mine",
            "an unproven cold handshake must not replace the owner's session"
        );
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "no second backend: the attacker's handshake created nothing"
        );
    }

    /// A WARM handshake on a live token repoints the datagram route to the
    /// newcomer, overwrites the entry's `client_key` and scrubs the superseded
    /// key off the SHARED allowlist. All three must wait for the proof: an
    /// unproven peer that then stays silent would otherwise cost the owner its
    /// route, its session and its way back in.
    #[tokio::test]
    async fn an_unproven_warm_handshake_leaves_the_route_and_the_allowlist_alone() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let (allowlist, owner_key, mut owner, _attacker) = owner_and_unproven_attacker(
            Arc::new(CountingEchoBackend {
                spawns: spawned.clone(),
            }),
            [8u8; 16],
            StartKind::Warm,
        )
        .await;

        // The owner can still get back in: its key was not superseded.
        assert!(
            allowlist.lock().unwrap().contains(&owner_key),
            "an unproven warm handshake must not scrub the owner's key off the allowlist"
        );
        // And the route still points at the owner's session.
        owner.send(0, b"still-routed".to_vec()).await;
        assert_eq!(
            owner.recv_stream0(Duration::from_secs(2)).await,
            b"still-routed",
            "an unproven warm handshake must not repoint the owner's route"
        );
        assert_eq!(spawned.load(Ordering::SeqCst), 1, "no second backend");
    }

    /// The fourth thing re-resolution can find: while this connection was on
    /// probation, a BYTE-IDENTICAL msg1 -- its own retransmit twin, which got
    /// a probation of its own -- bound the entry first. The proof then arrives
    /// for a connection the client is not on, so it must adopt NOTHING: no
    /// rebind, no replace, no second backend, and the entry keeps naming the
    /// session the client is actually Live on.
    #[tokio::test]
    async fn a_proof_whose_twin_already_bound_the_entry_adopts_nothing() {
        let token = [3u8; 16];
        let body = b"the same msg1 both connections carried".to_vec();

        // The twin's binding: an entry naming session 42, remembering `body`.
        let mut router = Router::new();
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 42);
        {
            let entry = router.backends.get_mut(&token).expect("entry present");
            entry.last_msg1_body = body.clone();
            entry.msg2 = b"the cached msg2 for session 42".to_vec();
        }
        // This connection's own probation: a route and a slot, nothing more.
        let (probation_dg_tx, _probation_dg_rx) = dgram_queue();
        router.sessions.insert(99, probation_dg_tx);
        assert!(router.admit_probation(99, probation_src(99), token));

        let spawned = Arc::new(AtomicUsize::new(0));
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                // Unread on this path (`proven` is `Some` below): only the
                // `None` arm consults the top-level nonce.
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Warm,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: body,
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: test_principal(),
                    dgram_rx,
                })),
            },
        )
        .await;

        assert_eq!(
            router.backends.len(),
            1,
            "a retransmit's proof must not add or replace an entry"
        );
        assert_eq!(
            router
                .backends
                .get(&token)
                .expect("entry present")
                .session_id,
            42,
            "the entry keeps naming the session the client is actually Live on"
        );
        assert!(
            !router.sessions.contains_key(&99),
            "the provisional probation route is dropped"
        );
        assert!(
            router.sessions.contains_key(&42),
            "the twin's route is untouched"
        );
        assert!(
            router.probation.is_empty(),
            "the probation slot is released"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "no second backend for a connection that adopted nothing"
        );
    }

    /// A retransmit twin adopts nothing from the connection it is handed --
    /// except which life of the device's LOGIN that connection was proven
    /// under, which is not about the connection at all.
    ///
    /// The run: two byte-identical msg1s get a probation each. The first
    /// binds the entry under one life of the login. Between the two proofs
    /// that login ends and the device is admitted again, so the SECOND proof
    /// comes back naming a newer life -- and its decision is `ResendMsg2`,
    /// the one branch that touches nothing. An entry left claiming the older
    /// life is then torn down by a report about a login that really is over,
    /// while the session on it is perfectly alive: exactly the failure the
    /// comparison exists to prevent, reached through the branch that does
    /// not refresh.
    ///
    /// Delete the `note_incarnation` line from `AcceptDecision::ResendMsg2`
    /// and this test fails on its own assertion. Nothing else in the
    /// workspace does: every other receive branch records the number
    /// already.
    #[tokio::test]
    async fn a_resent_msg2_still_records_which_life_of_the_login_was_proven() {
        const OLD_LIFE: u64 = 5;
        const NEW_LIFE: u64 = 6;
        let token = [4u8; 16];
        let body = b"the same msg1 both connections carried".to_vec();

        // The twin's binding, made under the OLD life of the login.
        let mut router = Router::new();
        let (mut ctl_rx, mut dg_rx) = synthetic_live_entry(&mut router, token, 42);
        {
            let entry = router.backends.get_mut(&token).expect("entry present");
            entry.last_msg1_body = body.clone();
            entry.msg2 = b"the cached msg2 for session 42".to_vec();
            entry.incarnation = OLD_LIFE;
        }
        let (probation_dg_tx, _probation_dg_rx) = dgram_queue();
        router.sessions.insert(99, probation_dg_tx);
        assert!(router.admit_probation(99, probation_src(99), token));

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // The second twin's proof lands, naming the NEWER life.
        let mut proven = test_principal();
        proven.incarnation = NEW_LIFE;
        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Warm,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: body,
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: proven,
                    dgram_rx,
                })),
            },
        )
        .await;

        // Setup, so a resend that wrongly rebound would show as such rather
        // than as this test's own property.
        assert_eq!(
            router
                .backends
                .get(&token)
                .expect("entry present")
                .session_id,
            42,
            "setup: a resend must still adopt no session of its own"
        );

        // And now the report about the life that really ended.
        assert!(
            !router.end_login(token, OLD_LIFE),
            "a report about the life that ended before this proof must be dropped -- the entry \
             was told about a newer one by the resend"
        );
        assert!(
            router.backends.contains_key(&token),
            "so the session the client is Live on must survive it"
        );
        assert!(
            matches!(
                dg_rx.try_recv_or_why(),
                Err(mpsc::error::TryRecvError::Empty)
            ),
            "and its datagram route with it"
        );
        assert!(
            matches!(ctl_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "and its control channel"
        );
    }

    /// The whole point of this slice: an account that has authenticated
    /// perfectly well, naming someone else's token, must NOT get their shell.
    #[tokio::test]
    async fn a_warm_reattach_by_another_account_leaves_the_session_alone() {
        let token = [1u8; 16];
        let mut router = Router::new();
        let (mut ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 42);
        router.backends.get_mut(&token).expect("entry").owner = 1000;

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let spawned = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // An account that is not this token's owner (1001, not 1000), with
        // an msg1 body that does NOT match the entry's -- so `resolve` picks
        // `WarmReattach`, not the retransmit arm, and the owner check is
        // actually exercised.
        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                // Unread on this path (`proven` is `Some` below): only the
                // `None` arm consults the top-level nonce.
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Warm,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: b"a warm handshake from another account".to_vec(),
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: Principal {
                        uid: 1001,
                        name: "attacker".to_string(),
                        identity: "SHA256:attacker".to_string(),
                        incarnation: 0,
                    },
                    dgram_rx,
                })),
            },
        )
        .await;

        let entry = router.backends.get(&token).expect("the entry must survive");
        assert_eq!(entry.owner, 1000, "the owner must not be rewritten");
        assert_eq!(entry.session_id, 42, "the route must not be repointed");
        assert!(
            router.sessions.contains_key(&42),
            "the original route must still be registered"
        );
        assert!(
            ctl_rx.try_recv().is_err(),
            "the running bridge must never see an Attach for a refused reattach"
        );

        // No fallback cold-create either: the refusal happens before that
        // path is ever reachable.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "a refused reattach must not spawn a backend"
        );
    }

    /// `ColdReplace` is the more destructive arm -- unlike a refused
    /// `WarmReattach`, a successful one tears the old backend down before
    /// creating the new one. The owner check must stop it before that
    /// teardown ever starts: a foreign cold restart must leave the running
    /// session completely intact, route included.
    #[tokio::test]
    async fn a_cold_replace_by_another_account_leaves_the_session_alone() {
        let token = [1u8; 16];
        let mut router = Router::new();
        let (mut ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 42);
        router.backends.get_mut(&token).expect("entry").owner = 1000;

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let spawned = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // A COLD start from an account that is not this token's owner (1001,
        // not 1000), with an msg1 body that does NOT match the entry's -- so
        // `resolve` picks `ColdReplace`, not the retransmit arm.
        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                // Unread on this path (`proven` is `Some` below): only the
                // `None` arm consults the top-level nonce.
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Cold,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: b"a cold restart from another account".to_vec(),
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: Principal {
                        uid: 1001,
                        name: "attacker".to_string(),
                        identity: "SHA256:attacker".to_string(),
                        incarnation: 0,
                    },
                    dgram_rx,
                })),
            },
        )
        .await;

        let entry = router.backends.get(&token).expect("the entry must survive");
        assert_eq!(entry.owner, 1000, "the owner must not be rewritten");
        assert_eq!(entry.session_id, 42, "the old backend must not be replaced");
        assert!(
            router.sessions.contains_key(&42),
            "the original route must not be torn down before cold-create"
        );
        assert!(
            ctl_rx.try_recv().is_err(),
            "the old bridge's control channel must be untouched"
        );

        // No cold-create either: the refusal happens before the old backend
        // is torn down, so nothing new is ever spawned.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            0,
            "a refused cold replace must not spawn a backend"
        );
    }

    /// The owner coming back is untouched by the check: a genuine warm
    /// reattach by the SAME account still repoints the route as before.
    #[tokio::test]
    async fn a_warm_reattach_by_the_owner_still_attaches() {
        let token = [1u8; 16];
        let mut router = Router::new();
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 42);
        router.backends.get_mut(&token).expect("entry").owner = 1000;

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let spawned = Arc::new(AtomicUsize::new(0));
        let factory = BackendFactory(Arc::new(CountingEchoBackend {
            spawns: spawned.clone(),
        }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // The owner itself (uid 1000), reconnecting. A freshly constructed,
        // never-handshaked `Connection` defaults to `session_id() == 0` (see
        // `Connection::new`), so a successful reattach repoints the entry to
        // 0 -- proving the take-over, distinct from the original 42.
        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                // Unread on this path (`proven` is `Some` below): only the
                // `None` arm consults the top-level nonce.
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Warm,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: b"a warm handshake from the owner".to_vec(),
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: test_principal(), // uid 1000
                    dgram_rx,
                })),
            },
        )
        .await;

        let entry = router.backends.get(&token).expect("entry");
        assert_eq!(entry.owner, 1000);
        assert_eq!(entry.session_id, 0, "the owner's new connection took over");
    }

    /// One account cannot fill the table for everybody else.
    #[test]
    fn the_session_cap_is_per_owner() {
        let mut router = Router::new();
        for i in 0..MAX_SESSIONS_PER_OWNER {
            let token = [i as u8; 16];
            synthetic_live_entry(&mut router, token, i as u64);
            router.backends.get_mut(&token).expect("entry").owner = 1000;
        }
        assert!(!router.has_room_for(1000), "the owner is at their cap");
        assert!(
            router.has_room_for(1001),
            "a different account still gets in"
        );
    }

    /// At its own cap, a caller with a dead-but-`Retained` entry of its own
    /// reconnects at once by swapping that entry for the new one, rather than
    /// waiting out `RETAIN_AFTER_DEATH` for GC to free a slot. The swap
    /// cannot breach the per-owner cap: one entry leaves as one arrives.
    #[tokio::test(start_paused = true)]
    async fn at_their_own_cap_a_caller_evicts_their_own_oldest_retained_entry() {
        let mut router = Router::new();
        let mut keep_alive = Vec::new();

        // One entry, RETAINED, among the owner's own MAX_SESSIONS_PER_OWNER.
        let retained = [0u8; 16];
        let (c, d) = synthetic_live_entry(&mut router, retained, 0);
        router.backends.get_mut(&retained).expect("entry").owner = 1000;
        keep_alive.push((c, d));
        router.on_session_ended(
            SessionEnded {
                session_id: 0,
                token: retained,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(
            router.backends.get(&retained).expect("entry").state,
            EntryState::Retained { .. }
        ));

        for i in 1..MAX_SESSIONS_PER_OWNER {
            let token = [i as u8; 16];
            let (c, d) = synthetic_live_entry(&mut router, token, i as u64);
            router.backends.get_mut(&token).expect("entry").owner = 1000;
            keep_alive.push((c, d));
        }
        assert_eq!(
            router.backends.values().filter(|e| e.owner == 1000).count(),
            MAX_SESSIONS_PER_OWNER
        );

        assert!(
            router.admit_new_backend(1000),
            "the caller's own retained entry makes room"
        );
        assert!(
            !router.backends.contains_key(&retained),
            "the caller's own oldest retained entry was evicted"
        );
        assert_eq!(
            router.backends.values().filter(|e| e.owner == 1000).count(),
            MAX_SESSIONS_PER_OWNER - 1,
            "the swap frees exactly the one slot it took"
        );
    }

    /// At its OWN cap, too, eviction prefers and does not exempt: a caller
    /// whose every retained session has a handshake in probation still gets
    /// in by swapping the oldest of them -- otherwise replaying the handshakes
    /// of an account's own tokens would lock that account out of new
    /// sessions for as long as the replay went on.
    #[tokio::test(start_paused = true)]
    async fn at_their_own_cap_a_caller_still_evicts_their_own_session_in_probation() {
        let mut router = Router::new();
        let mut keep_alive = Vec::new();
        let retained = [0u8; 16];
        keep_alive.push(synthetic_live_entry(&mut router, retained, 0));
        router.backends.get_mut(&retained).expect("entry").owner = 1000;
        router.on_session_ended(
            SessionEnded {
                session_id: 0,
                token: retained,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        for i in 1..MAX_SESSIONS_PER_OWNER {
            let token = [i as u8; 16];
            keep_alive.push(synthetic_live_entry(&mut router, token, i as u64));
            router.backends.get_mut(&token).expect("entry").owner = 1000;
        }
        assert!(
            router.admit_probation(77, probation_src(77), retained),
            "setup: a handshake for the retained session's login is in probation"
        );
        assert!(
            router.admit_new_backend(1000),
            "a caller at its own cap must still get in when its only retained session's login is \
             in probation"
        );
        assert!(
            !router.backends.contains_key(&retained),
            "by swapping that retained session anyway"
        );
    }

    /// The property the eviction rewrite must not lose: at its own cap, a
    /// caller may swap out only ITS OWN retained entries, never someone
    /// else's. A foreign account's retained entry sitting in the table is
    /// not a way in.
    #[tokio::test]
    async fn at_their_own_cap_a_caller_cannot_evict_another_accounts_retained_entry() {
        let mut router = Router::new();
        let mut keep_alive = Vec::new();

        // The caller (1000) is at its own cap, every one of its entries LIVE.
        for i in 0..MAX_SESSIONS_PER_OWNER {
            let token = [i as u8; 16];
            let (c, d) = synthetic_live_entry(&mut router, token, i as u64);
            router.backends.get_mut(&token).expect("entry").owner = 1000;
            keep_alive.push((c, d));
        }

        // A DIFFERENT account (2000) has a RETAINED entry sitting in the
        // table -- the only evictable entry there is, and it belongs to
        // someone else entirely.
        let foreign = [99u8; 16];
        let (c, d) = synthetic_live_entry(&mut router, foreign, 99);
        router.backends.get_mut(&foreign).expect("entry").owner = 2000;
        keep_alive.push((c, d));
        router.on_session_ended(
            SessionEnded {
                session_id: 99,
                token: foreign,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(
            router.backends.get(&foreign).expect("entry").state,
            EntryState::Retained { .. }
        ));

        let total_before = router.backends.len();

        assert!(
            !router.admit_new_backend(1000),
            "the caller must not get in by evicting another account's entry"
        );
        assert!(
            router.backends.contains_key(&foreign),
            "the foreign retained entry must survive"
        );
        assert_eq!(
            router.backends.len(),
            total_before,
            "a rejected admission must not evict anything"
        );
    }

    /// The backend is told whose session it runs, so a system-mode spawner can
    /// later start the shell as that account.
    #[tokio::test]
    async fn a_backend_sees_the_principal_of_the_session_it_runs() {
        let seen = Arc::new(Mutex::new(None::<Principal>));
        let mut router = Router::new();
        let token = [42u8; 16];

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(RecordingPrincipalBackend { seen: seen.clone() }));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let dgram_rx = register_provisional_route(&mut router, 99);
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                // Unread on this path (`proven` is `Some` below): only the
                // `None` arm consults the top-level nonce.
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Cold,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: b"a fresh signature handshake".to_vec(),
                    out: Vec::new(),
                    src: "127.0.0.1:9999".parse().unwrap(),
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: test_principal(),
                    dgram_rx,
                })),
            },
        )
        .await;

        // `cold_create` spawns the bridge, which spawns the backend, on
        // separate tasks -- give them a moment to run.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(seen.lock().unwrap().as_ref(), Some(&test_principal()));
    }

    /// Spec §4.16 (ruling R14): a connection in probation has a small route
    /// -- past `PROBATION_DGRAM_QUEUE_BYTES` its datagrams are dropped --
    /// and once it is proven and bound to a new bridge the same route takes
    /// a bridge's `DGRAM_QUEUE_BYTES`.
    #[tokio::test]
    async fn a_proven_probations_route_is_raised_to_a_bridges() {
        use crate::dgram_queue::{DGRAM_ENTRY_COST, PROBATION_DGRAM_QUEUE_BYTES};
        let mut router = Router::new();
        let token = [43u8; 16];
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(NeverReads));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let (route, dgram_rx) = probation_dgram_queue();
        router.sessions.insert(99, route.clone());
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let entry = vec![0u8; 1024 - DGRAM_ENTRY_COST];
        let mut taken = 0;
        while route.send(src, entry.clone()) {
            taken += 1;
        }
        assert_eq!(
            taken,
            PROBATION_DGRAM_QUEUE_BYTES / 1024,
            "in probation the route drops past its small bound"
        );

        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                nonce: [0u8; AUTH_NONCE_LEN],
                proven: Some(Box::new(ProvenSession {
                    conn: Connection::new(ConnectionConfig {
                        required_features: crate::Features::NONE,
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    }),
                    client_key: [7u8; 32],
                    msg1: Msg1Payload {
                        offered: crate::Features::SUPPORTED,
                        start_kind: StartKind::Cold,
                        token,
                        method: AuthMethod::SshSignature,
                    },
                    msg1_body: b"a fresh signature handshake".to_vec(),
                    out: Vec::new(),
                    src,
                    start: BridgeStart::default(),
                    nonce: [0u8; AUTH_NONCE_LEN],
                    principal: test_principal(),
                    dgram_rx,
                })),
            },
        )
        .await;

        assert!(
            router.backends.contains_key(&token),
            "a session was created"
        );
        assert_eq!(
            route.bound(),
            DGRAM_QUEUE_BYTES,
            "bound to a bridge, the same route takes a bridge's bound"
        );
    }

    /// Build a router filled to `MAX_SESSIONS_TOTAL`, one entry RETAINED, and
    /// the pieces needed to drive `handle_datagram` against it directly. The
    /// channel receivers are returned so their senders stay open. Every
    /// entry defaults to owner 0 -- this test is about the total ceiling,
    /// not the per-owner cap, and it never calls `admit_new_backend`.
    #[allow(clippy::type_complexity)]
    fn router_at_the_session_cap(
        retained: [u8; 16],
    ) -> (
        Router,
        Vec<(mpsc::UnboundedReceiver<BridgeControl>, DgramRx)>,
    ) {
        let mut router = Router::new();
        let mut keep_alive = Vec::new();
        keep_alive.push(synthetic_live_entry(&mut router, retained, 1));
        router.on_session_ended(
            SessionEnded {
                session_id: 1,
                token: retained,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        for i in 0..(MAX_SESSIONS_TOTAL - 1) {
            keep_alive.push(synthetic_live_entry(
                &mut router,
                [(10 + i) as u8; 16],
                (10 + i) as u64,
            ));
        }
        assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL);
        (router, keep_alive)
    }

    /// At the session cap, a cold create EVICTS the oldest retained backend to
    /// make room. An unproven handshake must not be able to trigger that:
    /// otherwise anyone can destroy retained sessions by handshaking, and a
    /// burst of them locks legitimate clients out for `AUTH_DEADLINE`.
    #[tokio::test]
    async fn an_unproven_handshake_at_the_session_cap_evicts_nothing() {
        let retained = [1u8; 16];
        let (mut router, _keep_alive) = router_at_the_session_cap(retained);

        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // A real msg1 on the signature path, for a token nothing holds.
        let msg1 = signature_msg1(&server_kp.public, [99u8; 16], StartKind::Cold);
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), src, &msg1).await;

        assert_eq!(
            router.backends.len(),
            MAX_SESSIONS_TOTAL,
            "an unproven handshake must not grow or shrink the backend table"
        );
        assert!(
            router.backends.contains_key(&retained),
            "the retained backend must survive an unproven handshake"
        );
        assert_eq!(
            router.probation.len(),
            1,
            "the handshake went into probation instead of the decision arms"
        );
    }

    /// A `NonceSource` that always fails. The personal mode's `RandomNonces`
    /// (in `qshd`) can never fail; the system mode's helper-backed source
    /// (a later task) can -- the helper is unreachable, or its own
    /// outstanding table is full -- and this is what proves the manager
    /// handles that rather than assuming it never happens.
    struct FailingNonces;

    impl NonceSource for FailingNonces {
        fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
            Err("no nonces available (test)".to_string())
        }
        // Never issues anything, so there is nothing to give up.
        fn release(&self, _nonce: [u8; AUTH_NONCE_LEN]) {}
    }

    /// The nonce is obtained INSIDE `accept`'s `resolve` hook -- the one
    /// place a handshake either gets a nonce or is refused outright (see
    /// `Connection::accept`'s own docs). So when the source cannot produce
    /// one, `resolve` returns `None`, `accept` returns `Rejected` exactly as
    /// it would for a bad Noise message, and nothing about this handshake
    /// is registered anywhere in the router -- no probation, no backend, no
    /// route.
    #[tokio::test]
    async fn a_handshake_is_refused_when_no_nonce_is_available() {
        let mut router = Router::new();
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(FailingNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        // A real msg1 on the signature path -- would otherwise go straight
        // into probation, same as `an_unproven_handshake_at_the_session_cap_evicts_nothing`
        // above.
        let msg1 = signature_msg1(&server_kp.public, [55u8; 16], StartKind::Cold);
        let src: SocketAddr = "127.0.0.1:9998".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), src, &msg1).await;

        assert!(
            router.probation.is_empty(),
            "a handshake refused for lack of a nonce must never reach probation"
        );
        assert!(
            router.backends.is_empty(),
            "a handshake refused for lack of a nonce must never create a backend"
        );
        assert!(
            router.sessions.is_empty(),
            "a handshake refused for lack of a nonce must never register a datagram route"
        );
    }

    /// Counts issuances, so a test can prove exactly one nonce is minted per
    /// handshake, not one per `Connection::accept` attempt.
    struct CountingNonces(Arc<AtomicUsize>);

    impl NonceSource for CountingNonces {
        fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(rand::thread_rng().gen())
        }
        // This source counts ISSUES only; release accounting is
        // `TrackingNonces`'s job (below).
        fn release(&self, _nonce: [u8; AUTH_NONCE_LEN]) {}
    }

    /// What this proves: a handshake that fails the allowlist attempt and
    /// falls through to the signature attempt still obtains only ONE nonce
    /// in total -- the two attempts are one handshake, and the client is
    /// told exactly one nonce in msg2.
    ///
    /// What this does NOT prove: that the memoization inside
    /// `resolve_for_msg2` (`issued_nonce`, in `handle_datagram`) is what
    /// stops a second issue. In THIS scenario the allowlist attempt is
    /// rejected on the KEY check (`admits`, inside `accept`) -- the client
    /// below is a fresh keypair the allowlist never names, so `admits`
    /// fails before `parse_msg1` even runs, let alone the method
    /// comparison after it. Either check alone is enough to keep this
    /// attempt from ever reaching `resolve` (see
    /// `a_genuine_but_rejected_handshake_issues_no_nonce`, which covers
    /// each separately), so the memo is never exercised here either --
    /// only the signature attempt's single hook call ever issues anything.
    /// The memo exists as cheap insurance against a future call site that
    /// stops honoring that invariant (see its own comment, above
    /// `issued_nonce`'s declaration); this test cannot isolate it, and
    /// does not claim to.
    #[tokio::test]
    async fn only_one_nonce_is_issued_even_when_both_accept_attempts_run() {
        let mut router = Router::new();
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let issues = Arc::new(AtomicUsize::new(0));
        let auth = ServerAuth {
            // Non-empty, but names a key the client below never uses -- the
            // allowlist attempt runs (and is Rejected) before falling
            // through to the signature attempt.
            allowlist: Arc::new(Mutex::new(vec![generate_keypair().public])),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(CountingNonces(issues.clone())),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let msg1 = signature_msg1(&server_kp.public, [77u8; 16], StartKind::Cold);
        let src: SocketAddr = "127.0.0.1:9997".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), src, &msg1).await;

        assert_eq!(
            router.probation.len(),
            1,
            "the signature attempt must have succeeded and gone into probation"
        );
        assert_eq!(
            issues.load(Ordering::SeqCst),
            1,
            "one handshake must issue exactly one nonce, even across two accept attempts"
        );
    }

    /// Two-byte junk `wire::parse` still classifies as a `HandshakeInit`
    /// (version + kind, empty body), and a plausible-length body that never
    /// decrypts as a real Noise message, must issue NO nonce: `resolve` is
    /// only ever called once `accept` has decrypted and parsed msg1 and
    /// confirmed the announced method. A datagram that never gets that far
    /// never reaches it.
    #[tokio::test]
    async fn junk_datagrams_classified_as_a_handshake_issue_no_nonce() {
        let mut router = Router::new();
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let issues = Arc::new(AtomicUsize::new(0));
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(CountingNonces(issues.clone())),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };
        let src: SocketAddr = "127.0.0.1:9996".parse().unwrap();

        // The shortest datagram `wire::parse` still classifies as a
        // HandshakeInit: version + kind, empty body -- nothing for a Noise
        // reader to even attempt.
        let two_byte_junk = vec![VERSION, Kind::HandshakeInit as u8];
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            two_byte_junk.len(),
            src,
            &two_byte_junk,
        )
        .await;

        // A plausible-length body that still fails to decrypt as a real
        // Noise message.
        let mut undecryptable = vec![VERSION, Kind::HandshakeInit as u8];
        undecryptable.extend_from_slice(&[0xAAu8; 96]);
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            undecryptable.len(),
            src,
            &undecryptable,
        )
        .await;

        assert_eq!(
            issues.load(Ordering::SeqCst),
            0,
            "a datagram that never decrypts as a real handshake must not issue a nonce"
        );
        assert!(router.probation.is_empty());
        assert!(router.backends.is_empty());
    }

    /// A general-purpose msg1 builder: unlike `signature_msg1`/`allowlist_msg1`
    /// (which always announce the method matching their own name), this one
    /// takes the client key and the announced method independently, so a
    /// test can build a msg1 that mismatches its OWN server's policy on
    /// purpose -- a genuine, correctly-encrypted Noise handshake `accept`
    /// still rejects, for reasons that have nothing to do with a nonce.
    fn msg1_with_method(
        server_pub: &[u8; 32],
        client_priv: [u8; 32],
        token: [u8; 16],
        start_kind: StartKind,
        method: AuthMethod,
    ) -> Vec<u8> {
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(*server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind,
            token,
            method,
        });
        let out =
            client.start_with_payload(Instant::now(), "127.0.0.1:1".parse().unwrap(), &payload);
        out.first().expect("msg1 datagram").bytes.clone()
    }

    /// Two more ways a datagram can fail every check `accept` makes on its
    /// own, BEFORE `resolve` is ever called -- not junk this time, but a
    /// genuine, correctly-encrypted Noise handshake: an unlisted key (the
    /// `admits` check) and a LISTED key that announces the wrong method
    /// (the method check). Both must issue zero nonces, the same as junk.
    /// This is the fix-1 review's reproduction of finding 1, made a
    /// permanent test: `resolve` sits after both checks today, but nothing
    /// used to prove that -- only the eager placement finding 1 diagnosed
    /// was ever exercised by a test.
    #[tokio::test]
    async fn a_genuine_but_rejected_handshake_issues_no_nonce() {
        let mut router = Router::new();
        let server_kp = generate_keypair();
        let listed_kp = generate_keypair();
        let unlisted_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let issues = Arc::new(AtomicUsize::new(0));
        let auth = ServerAuth {
            // Allowlist-only, no verifier: the signature attempt is never
            // even tried, so a wrong-method msg1 is refused on the method
            // check alone, inside the one accept attempt that runs.
            allowlist: Arc::new(Mutex::new(vec![listed_kp.public])),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(CountingNonces(issues.clone())),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };
        let src: SocketAddr = "127.0.0.1:9991".parse().unwrap();

        // An unlisted key: a genuine Noise handshake, refused by the
        // `admits` check before `resolve` is ever called.
        let unlisted_msg1 = msg1_with_method(
            &server_kp.public,
            unlisted_kp.private,
            [1u8; 16],
            StartKind::Cold,
            AuthMethod::Allowlist,
        );
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            unlisted_msg1.len(),
            src,
            &unlisted_msg1,
        )
        .await;

        // A listed key, but announcing the WRONG method: refused by the
        // method check before `resolve` is ever called.
        let wrong_method_msg1 = msg1_with_method(
            &server_kp.public,
            listed_kp.private,
            [2u8; 16],
            StartKind::Cold,
            AuthMethod::SshSignature,
        );
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            wrong_method_msg1.len(),
            src,
            &wrong_method_msg1,
        )
        .await;

        assert_eq!(
            issues.load(Ordering::SeqCst),
            0,
            "a genuine handshake `accept` rejects on its own checks must issue no nonce"
        );
        assert!(router.probation.is_empty());
        assert!(router.backends.is_empty());
    }

    /// Tracks WHICH nonces are outstanding (issued minus released), not
    /// merely how many -- the dangerous direction: releasing a nonce a live
    /// probation still holds would make the helper refuse that probation's
    /// own proof later, and a bare count cannot tell "released the right
    /// one" apart from "released some other one, coincidentally leaving the
    /// same total" (or released everything). Also records issuance ORDER,
    /// so a test can name which of several requests a given nonce belongs
    /// to, by index, without having to read it back off the wire.
    #[derive(Default)]
    struct TrackingNonces {
        outstanding: Mutex<HashSet<[u8; AUTH_NONCE_LEN]>>,
        issued_order: Mutex<Vec<[u8; AUTH_NONCE_LEN]>>,
        /// A release naming a nonce this source never issued, or already
        /// released -- the surest sign a release named the WRONG nonce:
        /// releasing this source's own still-outstanding nonces can never
        /// produce one.
        bad_releases: AtomicUsize,
    }

    impl TrackingNonces {
        fn outstanding_snapshot(&self) -> HashSet<[u8; AUTH_NONCE_LEN]> {
            self.outstanding.lock().expect("not poisoned").clone()
        }
        fn nth_issued(&self, i: usize) -> [u8; AUTH_NONCE_LEN] {
            self.issued_order.lock().expect("not poisoned")[i]
        }
        fn bad_releases(&self) -> usize {
            self.bad_releases.load(Ordering::SeqCst)
        }
    }

    impl NonceSource for TrackingNonces {
        fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
            let nonce: [u8; AUTH_NONCE_LEN] = rand::thread_rng().gen();
            self.outstanding.lock().expect("not poisoned").insert(nonce);
            self.issued_order.lock().expect("not poisoned").push(nonce);
            Ok(nonce)
        }
        fn release(&self, nonce: [u8; AUTH_NONCE_LEN]) {
            let removed = self
                .outstanding
                .lock()
                .expect("not poisoned")
                .remove(&nonce);
            if !removed {
                self.bad_releases.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// More genuine signature `msg1`s from ONE source than
    /// `MAX_PROBATION_PER_SOURCE`: the ones within the cap stay in
    /// probation (still live, still holding their own nonce), and the one
    /// past it is refused by `begin_probation`'s `admit_probation` check
    /// and must release its own -- so outstanding must be EXACTLY the set
    /// of nonces the admitted probations hold, not merely the right count
    /// of some nonces or other.
    #[tokio::test]
    async fn outstanding_nonces_after_the_per_source_cap_equal_the_admitted_probations() {
        let mut router = Router::new();
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let src: SocketAddr = "127.0.0.1:9995".parse().unwrap();
        for i in 0..(MAX_PROBATION_PER_SOURCE + 1) {
            let msg1 = signature_msg1(&server_kp.public, [i as u8; 16], StartKind::Cold);
            SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), src, &msg1).await;
        }

        assert_eq!(
            router.probation.len(),
            MAX_PROBATION_PER_SOURCE,
            "only the per-source cap's worth of handshakes reach probation"
        );
        let admitted: HashSet<_> = (0..MAX_PROBATION_PER_SOURCE)
            .map(|i| tracking.nth_issued(i))
            .collect();
        assert_eq!(
            tracking.outstanding_snapshot(),
            admitted,
            "outstanding must be exactly the admitted probations' own nonces -- the one \
             refused past the cap must have released its own, and nothing else"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "no release may name a nonce this source never issued"
        );
    }

    /// An allowlist accept never sends a v2 auth record, so its nonce is
    /// never spent -- it must be released as soon as the accept is known to
    /// be an allowlist one, leaving outstanding at zero even though the
    /// session itself lives on.
    #[tokio::test]
    async fn outstanding_nonces_after_an_allowlist_accept_is_zero() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let mut router = Router::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(vec![client_kp.public])),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let msg1 = allowlist_msg1(
            &server_kp.public,
            client_kp.private,
            [3u8; 16],
            StartKind::Cold,
        );
        let src: SocketAddr = "127.0.0.1:9994".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), src, &msg1).await;

        assert_eq!(
            router.backends.len(),
            1,
            "the allowlist handshake must still create a backend"
        );
        assert!(
            tracking.outstanding_snapshot().is_empty(),
            "an allowlist accept must release its never-spent nonce"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "the release must have named the nonce this source actually issued"
        );
    }

    /// A probation that ends WITHOUT a proof (deadline, bad record, closed
    /// connection) must release its nonce -- driven directly against
    /// `on_probation_ended`, the same seam `an_unproven_handshake_at_the_session_cap_evicts_nothing`
    /// and friends already use to test the manager without a real
    /// probation task.
    #[tokio::test]
    async fn outstanding_nonces_after_a_probation_without_proof_is_zero() {
        let server_kp = generate_keypair();
        let mut router = Router::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let nonce = ctx.auth.nonces.issue().expect("issue");
        assert_eq!(
            tracking.outstanding_snapshot(),
            [nonce].into_iter().collect()
        );
        SessionManager::on_probation_ended(
            &ctx,
            &mut router,
            ProbationEnded {
                session_id: 99,
                nonce,
                proven: None,
            },
        )
        .await;

        assert!(
            tracking.outstanding_snapshot().is_empty(),
            "a probation that ends without proof must release its nonce"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "the release must have named the nonce this source actually issued"
        );
    }

    /// A `ResendMsg2` retransmit on the SIGNATURE path is caught inside
    /// `begin_probation`, BEFORE probation is ever entered: the fresh
    /// connection (and its freshly issued nonce) is discarded in favor of
    /// resending the entry's cached msg2.
    #[tokio::test]
    async fn outstanding_nonces_after_a_signature_resend_msg2_is_zero() {
        let token = [77u8; 16];
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let mut router = Router::new();
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 1);
        let msg1_datagram = signature_msg1(&server_kp.public, token, StartKind::Cold);
        {
            let entry = router.backends.get_mut(&token).expect("entry present");
            entry.last_msg1_body = msg1_datagram[2..].to_vec();
            entry.msg2 = b"cached-msg2".to_vec();
        }

        let src: SocketAddr = "127.0.0.1:9993".parse().unwrap();
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            msg1_datagram.len(),
            src,
            &msg1_datagram,
        )
        .await;

        assert!(
            tracking.outstanding_snapshot().is_empty(),
            "a ResendMsg2 retransmit must release the nonce issued for the discarded connection"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "the release must have named the nonce this source actually issued"
        );
    }

    /// The same retransmit, on the ALLOWLIST path: caught inside
    /// `apply_decision` (reached directly, not via `begin_probation`).
    /// `apply_decision` itself releases nothing (see its `ResendMsg2` arm's
    /// own comment) -- the allowlist accept's nonce is released
    /// unconditionally in `handle_datagram`, before `apply_decision` is
    /// even called, so this proves that single release is enough on its
    /// own: outstanding lands at exactly empty with no second release
    /// anywhere on this path.
    #[tokio::test]
    async fn outstanding_nonces_after_an_allowlist_resend_msg2_is_zero() {
        let token = [88u8; 16];
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(vec![client_kp.public])),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };

        let mut router = Router::new();
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token, 1);
        let msg1_datagram =
            allowlist_msg1(&server_kp.public, client_kp.private, token, StartKind::Cold);
        {
            let entry = router.backends.get_mut(&token).expect("entry present");
            entry.last_msg1_body = msg1_datagram[2..].to_vec();
            entry.msg2 = b"cached-msg2".to_vec();
        }

        let src: SocketAddr = "127.0.0.1:9992".parse().unwrap();
        SessionManager::handle_datagram(
            &ctx,
            &mut router,
            msg1_datagram.len(),
            src,
            &msg1_datagram,
        )
        .await;

        assert!(
            tracking.outstanding_snapshot().is_empty(),
            "an allowlist ResendMsg2 retransmit must release exactly once, not zero and not twice"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "the release must have named the nonce this source actually issued"
        );
    }

    /// Discrimination, not just counting: a live probation's OWN nonce
    /// must stay outstanding while an UNRELATED, discarded handshake's
    /// nonce is released -- so a bug that released the WRONG nonce (or
    /// cleared the table indiscriminately) would be caught here even
    /// though every `outstanding_nonces_after_*` test above, each landing
    /// on empty, cannot on its own tell "released the right one" apart
    /// from "released everything".
    #[tokio::test]
    async fn a_live_probations_nonce_survives_while_an_unrelated_discarded_ones_is_released() {
        let server_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let tracking = Arc::new(TrackingNonces::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: Some(Arc::new(FakeVerifier::accepting_good())),
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: tracking.clone(),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };
        let mut router = Router::new();

        // Token A: a genuine handshake that goes live into probation and
        // stays there -- its nonce must survive everything that happens to
        // token B below.
        let token_a = [0xAAu8; 16];
        let msg1_a = signature_msg1(&server_kp.public, token_a, StartKind::Cold);
        let src_a: SocketAddr = "127.0.0.1:9990".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1_a.len(), src_a, &msg1_a).await;
        assert_eq!(
            router.probation.len(),
            1,
            "token A's handshake must have reached probation"
        );
        let nonce_a = tracking.nth_issued(0);

        // Token B: a discarded ResendMsg2 retransmit against an unrelated,
        // already-bound entry -- its freshly issued nonce must be released.
        let token_b = [0xBBu8; 16];
        let (_ctl_rx, _dg_rx) = synthetic_live_entry(&mut router, token_b, 777);
        let msg1_b = signature_msg1(&server_kp.public, token_b, StartKind::Cold);
        {
            let entry = router.backends.get_mut(&token_b).expect("entry present");
            entry.last_msg1_body = msg1_b[2..].to_vec();
            entry.msg2 = b"cached-msg2".to_vec();
        }
        let src_b: SocketAddr = "127.0.0.1:9989".parse().unwrap();
        SessionManager::handle_datagram(&ctx, &mut router, msg1_b.len(), src_b, &msg1_b).await;
        let nonce_b = tracking.nth_issued(1);

        let outstanding = tracking.outstanding_snapshot();
        assert!(
            outstanding.contains(&nonce_a),
            "the live probation's own nonce must still be outstanding"
        );
        assert!(
            !outstanding.contains(&nonce_b),
            "the discarded retransmit's nonce must have been released"
        );
        assert_eq!(
            tracking.bad_releases(),
            0,
            "the release must have named the nonce this source actually issued"
        );
    }

    /// The wire bytes of a `HandshakeInit` announcing `SshSignature`, from a
    /// fresh client key the server has never seen.
    fn signature_msg1(server_pub: &[u8; 32], token: [u8; 16], start_kind: StartKind) -> Vec<u8> {
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(*server_pub),
            auth: AuthPolicy::SshSignature,
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind,
            token,
            method: AuthMethod::SshSignature,
        });
        let out =
            client.start_with_payload(Instant::now(), "127.0.0.1:1".parse().unwrap(), &payload);
        out.first().expect("msg1 datagram").bytes.clone()
    }

    /// The wire bytes of a `HandshakeInit` announcing `Allowlist`, from a
    /// given client key -- mirrors [`signature_msg1`], but for the allowlist
    /// path and a caller-chosen `client_priv` (rather than a fresh, unlisted
    /// one), so the resulting msg1 can be made to pass an allowlist that
    /// names that key.
    fn allowlist_msg1(
        server_pub: &[u8; 32],
        client_priv: [u8; 32],
        token: [u8; 16],
        start_kind: StartKind,
    ) -> Vec<u8> {
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(*server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind,
            token,
            method: AuthMethod::Allowlist,
        });
        let out =
            client.start_with_payload(Instant::now(), "127.0.0.1:1".parse().unwrap(), &payload);
        out.first().expect("msg1 datagram").bytes.clone()
    }

    /// A distinct source address per index, so a test that fills the GLOBAL
    /// probation cap does not trip the per-source one on its way there. The
    /// third octet keeps these clear of `198.51.100.x`, which the per-source
    /// test uses for its flooder: overlapping there would fail that test for
    /// a reason other than the one under test if the per-source cap grew.
    fn probation_src(i: u64) -> SocketAddr {
        format!("198.51.101.{}:{}", i % 250 + 1, 40000 + i % 1000)
            .parse()
            .expect("a literal address")
    }

    /// Probation entries are capped on their own, and going over the cap is a
    /// SILENT DROP: nothing is evicted, because nothing in probation belongs
    /// to anyone yet and letting the newest stranger displace the previous one
    /// would buy nothing.
    #[test]
    fn the_probation_cap_drops_rather_than_evicts() {
        let mut router = Router::new();
        for id in 0..MAX_PROBATION as u64 {
            assert!(
                router.admit_probation(id, probation_src(id), [0u8; 16]),
                "under the cap, admit"
            );
        }
        assert!(
            !router.admit_probation(
                MAX_PROBATION as u64,
                probation_src(MAX_PROBATION as u64),
                [0u8; 16]
            ),
            "over the cap, refuse"
        );
        assert_eq!(
            router.probation.len(),
            MAX_PROBATION,
            "a refused probation must not evict an existing one"
        );
        assert!(
            router.probation.contains_key(&0),
            "the OLDEST probation entry survives: there is nothing to evict for"
        );
    }

    /// The global cap alone is exhaustible by ONE address -- slots free only
    /// as `AUTH_DEADLINE` expires -- and an exhausted table is a LOCKOUT: every
    /// signature sign-in, and every warm reattach after a network change, has
    /// to pass through probation. So each source is capped on its own share,
    /// and a stranger's flood can never cost another address its seat.
    #[test]
    fn one_source_cannot_lock_another_out_of_probation() {
        let mut router = Router::new();
        let flooder: IpAddr = "198.51.100.9".parse().expect("a literal address");
        let mut id = 0u64;

        // Far more handshakes than the whole table holds, varying the source
        // PORT every time -- which costs an attacker nothing, so a cap keyed
        // on the port would stop none of this.
        for _ in 0..MAX_PROBATION * 4 {
            router.admit_probation(
                id,
                SocketAddr::new(flooder, 40000 + (id % 1000) as u16),
                [0u8; 16],
            );
            id += 1;
        }
        assert_eq!(
            router.probation.len(),
            MAX_PROBATION_PER_SOURCE,
            "one address may hold no more than its own share of the table"
        );

        // The table is nowhere near full, and honest clients elsewhere are
        // admitted exactly as if the flood had never happened.
        for seat in 0..MAX_PROBATION_PER_SOURCE as u64 {
            assert!(
                router.admit_probation(id, probation_src(seat), [0u8; 16]),
                "a client from another address must still get in"
            );
            id += 1;
        }
    }

    /// Documentation addresses only: vary all host segments, the port, and
    /// the scope ID without sending any packets.
    fn probation_v6_src(prefix: u16, host: u16) -> SocketAddr {
        std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, prefix, host, host, host, host),
            40000 + host,
            0,
            u32::from(host),
        )
        .into()
    }

    #[test]
    fn probation_source_groups_share_one_ipv6_64_quota() {
        let mut router = Router::new();
        for host in 0..(MAX_PROBATION_PER_SOURCE * 2) as u16 {
            assert_eq!(
                router.admit_probation(u64::from(host), probation_v6_src(1, host), [0; 16]),
                usize::from(host) < MAX_PROBATION_PER_SOURCE,
                "host bits, ports, and scope IDs must not create a new quota"
            );
        }
        assert_eq!(router.probation.len(), MAX_PROBATION_PER_SOURCE);
        for host in 0..MAX_PROBATION_PER_SOURCE as u16 {
            assert!(router.admit_probation(
                1000 + u64::from(host),
                probation_v6_src(2, host),
                [0; 16],
            ));
        }
        assert_eq!(router.probation.len(), MAX_PROBATION_PER_SOURCE * 2);
    }

    #[test]
    fn probation_source_groups_share_ipv4_and_mapped_quota() {
        for mapped_first in [false, true] {
            let mut router = Router::new();
            let ip = std::net::Ipv4Addr::new(192, 0, 2, 1);
            for id in 0..(MAX_PROBATION_PER_SOURCE * 2) as u64 {
                let source = if (id % 2 == 0) == mapped_first {
                    IpAddr::V6(ip.to_ipv6_mapped())
                } else {
                    IpAddr::V4(ip)
                };
                assert_eq!(
                    router.admit_probation(id, SocketAddr::new(source, 40000 + id as u16), [0; 16]),
                    id < MAX_PROBATION_PER_SOURCE as u64,
                    "both address forms must spend the same quota"
                );
            }
            assert_eq!(router.probation.len(), MAX_PROBATION_PER_SOURCE);
            for host in [2, 3] {
                let other = std::net::Ipv4Addr::new(192, 0, 2, host);
                let source = if host == 2 {
                    IpAddr::V4(other)
                } else {
                    IpAddr::V6(other.to_ipv6_mapped())
                };
                for seat in 0..MAX_PROBATION_PER_SOURCE as u64 {
                    assert!(router.admit_probation(
                        u64::from(host) * 1000 + seat,
                        SocketAddr::new(source, 40000 + seat as u16),
                        [0; 16],
                    ));
                }
            }
            assert_eq!(router.probation.len(), MAX_PROBATION_PER_SOURCE * 3);
        }
    }

    #[test]
    fn probation_source_groups_keep_compatible_ipv6_in_its_native_prefix() {
        let mut router = Router::new();
        for id in 0..MAX_PROBATION_PER_SOURCE as u64 {
            let source = format!("[::192.0.2.{}]:40000", id + 1).parse().unwrap();
            assert!(router.admit_probation(id, source, [0; 16]));
        }
        assert!(!router.admit_probation(100, "[::198.51.100.1]:40001".parse().unwrap(), [0; 16]));
        // IPv4-compatible addresses belong to ::/64, not the IPv4 host's
        // group. Only IPv4-mapped addresses are normalized to IPv4.
        assert!(router.admit_probation(101, "192.0.2.1:40000".parse().unwrap(), [0; 16]));
        assert!(router.admit_probation(102, "[::ffff:192.0.2.1]:40000".parse().unwrap(), [0; 16]));
    }

    #[test]
    fn probation_source_groups_still_obey_the_global_cap() {
        let mut router = Router::new();
        for id in 0..=MAX_PROBATION {
            let prefix = (id / MAX_PROBATION_PER_SOURCE) as u16;
            let host = (id % MAX_PROBATION_PER_SOURCE) as u16;
            assert_eq!(
                router.admit_probation(id as u64, probation_v6_src(prefix, host), [0; 16]),
                id < MAX_PROBATION,
            );
        }
        assert_eq!(router.probation.len(), MAX_PROBATION);
        assert!(
            router.probation.contains_key(&0),
            "no existing seat is evicted"
        );
    }

    #[tokio::test]
    async fn probation_source_groups_reclaim_removed_and_expired_seats() {
        let rig = SignatureRig::new().await;
        let mut router = Router::new();
        for id in 0..MAX_PROBATION_PER_SOURCE as u64 {
            assert!(router.admit_probation(id, probation_v6_src(1, id as u16), [0; 16]));
        }
        let replacement = MAX_PROBATION_PER_SOURCE as u64;
        let source = probation_v6_src(1, 100);
        assert!(!router.admit_probation(replacement, source, [0; 16]));

        router.probation.remove(&0).expect("existing seat");
        assert!(router.admit_probation(replacement, source, [0; 16]));
        assert!(!router.admit_probation(replacement + 1, probation_v6_src(1, 101), [0; 16]));

        // The same completion the probation task sends after its deadline.
        // Drive the manager seam directly instead of waiting for a timer.
        SessionManager::on_probation_ended(
            &rig.ctx(),
            &mut router,
            ProbationEnded {
                session_id: replacement,
                nonce: [0; AUTH_NONCE_LEN],
                proven: None,
            },
        )
        .await;
        assert_eq!(router.probation.len(), MAX_PROBATION_PER_SOURCE - 1);
        assert!(router.admit_probation(replacement + 1, probation_v6_src(1, 101), [0; 16]));
        assert!(!router.admit_probation(replacement + 2, probation_v6_src(1, 102), [0; 16]));
    }

    // ---- The return-address check under load (spec §4.16) -----------------

    /// Eight loopback addresses (127.0.0.2 to 127.0.0.9) sending signature
    /// msg1s as fast as a thread can, and reading back only to count what
    /// they were answered -- the shape of a forged flood on a real socket.
    /// Returns the bytes the flood sent, the bytes it was answered with, and
    /// the largest answer, once `stop` is set.
    ///
    /// Linux only: there the whole of 127.0.0.0/8 is on the loopback
    /// interface, so a socket can bind 127.0.0.2 without any setup. Other
    /// systems (macOS) answer only 127.0.0.1 unless an alias is added.
    #[cfg(target_os = "linux")]
    fn spawn_flood(
        server: SocketAddr,
        server_pub: [u8; 32],
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<(u64, u64, usize)> {
        let msgs: Vec<Vec<u8>> = (0..256u32)
            .map(|i| signature_msg1(&server_pub, [(i % 251) as u8; 16], StartKind::Cold))
            .collect();
        std::thread::spawn(move || {
            let socks: Vec<std::net::UdpSocket> = (2..=9u8)
                .map(|last| {
                    let s =
                        std::net::UdpSocket::bind((std::net::Ipv4Addr::new(127, 0, 0, last), 0))
                            .expect("a loopback address of its own");
                    s.set_nonblocking(true).expect("non-blocking");
                    s
                })
                .collect();
            let (mut sent, mut received, mut largest) = (0u64, 0u64, 0usize);
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::SeqCst) {
                for (i, m) in msgs.iter().enumerate() {
                    if socks[i % socks.len()].send_to(m, server).is_ok() {
                        sent += m.len() as u64;
                    }
                }
                for s in &socks {
                    while let Ok(n) = s.recv(&mut buf) {
                        received += n as u64;
                        largest = largest.max(n);
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            (sent, received, largest)
        })
    }

    /// QSH-02: eight addresses used to fill the probation table (sixteen
    /// seats each), and every honest sign-in -- a warm reattach after a
    /// network change included -- was then dropped in silence. Now a flood
    /// is load, and under load only a handshake that proves its return
    /// address takes a seat: a cold sign-in, and then a warm reattach of the
    /// same session from another socket, both get in while the flood goes
    /// on. The flood's answers weigh less than what it sent, and none
    /// outweighs a msg1.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_forged_flood_does_not_lock_an_honest_sign_in_out() {
        let spawned = Arc::new(AtomicUsize::new(0));
        let server = start_manager(
            Arc::new(CountingEchoBackend {
                spawns: spawned.clone(),
            }),
            Vec::new(),
            Some(Arc::new(FakeVerifier::accepting_good())),
        )
        .await;
        // A token none of the flood's msg1s names.
        let token = [253u8; 16];
        let stop = Arc::new(AtomicBool::new(false));
        let flood = spawn_flood(server.addr, server.public_key, Arc::clone(&stop));
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut cold = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        assert!(
            cold.handshake_through_load(Duration::from_secs(5)).await,
            "the honest client gets in under the flood"
        );
        assert!(cold.conn.cookie_for_test().is_some(), "through a cookie");
        cold.prove_and_echo(b"hello").await;

        let mut warm = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        assert!(
            warm.handshake_through_load(Duration::from_secs(5)).await,
            "the warm reattach gets in under the flood"
        );
        assert!(warm.conn.cookie_for_test().is_some(), "through a cookie");
        warm.prove_and_echo(b"again").await;
        assert_eq!(
            spawned.load(Ordering::SeqCst),
            1,
            "the reattach is to the running session"
        );

        stop.store(true, Ordering::SeqCst);
        let (sent, received, largest) = flood.join().expect("the flood thread");
        assert!(sent > 0);
        assert!(received <= sent, "{received} bytes answered {sent}");
        assert!(largest <= 121, "no answer outweighs a msg1: {largest}");
    }

    /// §4.16's stated cost, on a real socket: a client from before cookies
    /// is refused while the flood lasts, and gets in once the load is over.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_client_that_predates_cookies_waits_out_a_flood() {
        let (mut client, server_pub) =
            start_manager_with_signature_auth(EchoBackend, FakeVerifier::accepting_good()).await;
        client.play_legacy();
        let stop = Arc::new(AtomicBool::new(false));
        let flood = spawn_flood(client.server_addr, server_pub, Arc::clone(&stop));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !client.handshake_through_load(Duration::from_secs(2)).await,
            "refused under load"
        );
        stop.store(true, Ordering::SeqCst);
        let _ = flood.join();
        assert!(
            client.handshake_through_load(Duration::from_secs(4)).await,
            "admitted once the load is over"
        );
    }

    /// The cookie in a `CookieReply` datagram, which it must be.
    fn cookie_from(datagram: &[u8]) -> [u8; COOKIE_LEN] {
        match parse(datagram) {
            Ok(Frame::Handshake {
                kind: Kind::CookieReply,
                body,
            }) => parse_cookie_reply(body).expect("well formed").1,
            other => panic!("a cookie reply, not {other:?}"),
        }
    }

    /// What a `ManagerCtx` borrows for a signature daemon (an empty
    /// allowlist, a verifier that accepts `good`), owned in one place, for
    /// tests that hand `handle_datagram` datagrams themselves.
    struct SignatureRig {
        socket: Arc<UdpSocket>,
        server_priv: [u8; 32],
        server_pub: [u8; 32],
        auth: ServerAuth,
        factory: BackendFactory,
        done_tx: mpsc::UnboundedSender<SessionEnded>,
        _done_rx: mpsc::UnboundedReceiver<SessionEnded>,
        probation_tx: mpsc::UnboundedSender<ProbationEnded>,
        _probation_rx: mpsc::UnboundedReceiver<ProbationEnded>,
        active_count: Arc<AtomicUsize>,
    }

    impl SignatureRig {
        async fn new() -> SignatureRig {
            let server_kp = generate_keypair();
            let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
            let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
            SignatureRig {
                socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                server_priv: server_kp.private,
                server_pub: server_kp.public,
                auth: ServerAuth {
                    allowlist: Arc::new(Mutex::new(Vec::new())),
                    verifier: Some(Arc::new(FakeVerifier::accepting_good())),
                    server_pub: server_kp.public,
                    self_principal: test_self_principal(),
                    nonces: Arc::new(TestNonces),
                    logins: Arc::new(ForgetNothing),
                },
                factory: BackendFactory(Arc::new(EchoBackend)),
                done_tx,
                _done_rx,
                probation_tx,
                _probation_rx,
                active_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn ctx(&self) -> ManagerCtx<'_> {
            ManagerCtx {
                socket: &self.socket,
                server_priv: &self.server_priv,
                auth: &self.auth,
                factory: &self.factory,
                done_tx: &self.done_tx,
                probation_tx: &self.probation_tx,
                active_count: &self.active_count,
            }
        }
    }

    /// QSH-03: under load a handshake that has not proved its return
    /// address costs no Noise work and no seat, however many there are; the
    /// one that proves it is worked on.
    #[tokio::test]
    async fn under_load_an_unproven_handshake_costs_no_noise_work_and_no_seat() {
        let rig = SignatureRig::new().await;
        let ctx = rig.ctx();
        let mut router = Router::new();
        router.cookies = CookieCheck::with_limits(
            Instant::now(),
            LoadLimits {
                handshakes_per_window: 0,
                probation_seats: 0,
            },
        );
        ACCEPT_ATTEMPTS.with(|n| n.set(0));
        for i in 0..300u32 {
            let msg1 = signature_msg1(&rig.server_pub, [(i % 250) as u8; 16], StartKind::Cold);
            let from = SocketAddr::from(([198, 51, 102, (i % 250) as u8], 40_000 + i as u16));
            SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        }
        assert_eq!(ACCEPT_ATTEMPTS.with(|n| n.get()), 0, "no Noise work");
        assert!(router.probation.is_empty(), "no seat");

        let honest = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = honest.local_addr().unwrap();
        let msg1 = signature_msg1(&rig.server_pub, [7; 16], StartKind::Cold);
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), honest.recv(&mut buf))
            .await
            .expect("a cookie reply")
            .unwrap();
        assert!(n * 3 < msg1.len(), "{n} bytes answer {}", msg1.len());
        let cookie = cookie_from(&buf[..n]);
        let again = encode_handshake_init_cookie(&cookie, &msg1[2..]);
        SessionManager::handle_datagram(&ctx, &mut router, again.len(), from, &again).await;
        assert!(
            ACCEPT_ATTEMPTS.with(|n| n.get()) >= 1,
            "the proven msg1 is worked on"
        );
        assert_eq!(router.probation.len(), 1, "and takes a seat");
        // Spec §4.16 (ruling R14): its route is a probation's, small until
        // the connection is proven.
        let sid = *router.probation.keys().next().expect("the seat");
        assert_eq!(
            router.sessions.get(&sid).expect("routed").bound(),
            crate::dgram_queue::PROBATION_DGRAM_QUEUE_BYTES
        );
    }

    /// A client whose msg2 was lost before the load began sends its plain
    /// msg1 again, gets a cookie, and behind it its ORIGINAL msg2 --
    /// `ResendMsg2` works through the check.
    #[tokio::test]
    async fn a_msg1_retransmit_under_load_gets_its_original_msg2_behind_a_cookie() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(vec![client_kp.public])),
            verifier: None,
            server_pub: server_kp.public,
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: Arc::new(ForgetNothing),
        };
        let factory = BackendFactory(Arc::new(EchoBackend));
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (probation_tx, _probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let active_count = Arc::new(AtomicUsize::new(0));
        let ctx = ManagerCtx {
            socket: &socket,
            server_priv: &server_kp.private,
            auth: &auth,
            factory: &factory,
            done_tx: &done_tx,
            probation_tx: &probation_tx,
            active_count: &active_count,
        };
        let mut router = Router::new();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = client.local_addr().unwrap();
        let msg1 = allowlist_msg1(
            &server_kp.public,
            client_kp.private,
            [3; 16],
            StartKind::Cold,
        );
        let mut buf = [0u8; 256];
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("msg2")
            .unwrap();
        let first_msg2 = buf[..n].to_vec();

        router.cookies = CookieCheck::with_limits(
            Instant::now(),
            LoadLimits {
                handshakes_per_window: 0,
                probation_seats: 0,
            },
        );
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("a cookie reply")
            .unwrap();
        let cookie = cookie_from(&buf[..n]);
        let again = encode_handshake_init_cookie(&cookie, &msg1[2..]);
        SessionManager::handle_datagram(&ctx, &mut router, again.len(), from, &again).await;
        let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .expect("msg2 again")
            .unwrap();
        assert_eq!(buf[..n], first_msg2[..], "the original msg2, byte for byte");
    }

    /// Controller ruling on §4.16 (as WireGuard's rate limiter): a cookie
    /// proves an address, not a datagram -- the same msg1 behind it may come
    /// again, and each copy used to cost a Noise handshake. Under load a
    /// source that proves its address has at most `PROVEN_BURST` proven
    /// handshakes worked on at once and `PROVEN_PER_SECOND` a second after
    /// that; the rest are dropped for one MAC each.
    #[tokio::test]
    async fn under_load_a_proven_source_is_worked_on_at_most_twenty_times_a_second() {
        let rig = SignatureRig::new().await;
        let ctx = rig.ctx();
        let mut router = Router::new();
        router.cookies = CookieCheck::with_limits(
            Instant::now(),
            LoadLimits {
                handshakes_per_window: 0,
                probation_seats: 0,
            },
        );
        let real = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let from = real.local_addr().unwrap();
        let msg1 = signature_msg1(&rig.server_pub, [9; 16], StartKind::Cold);
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(2), real.recv(&mut buf))
            .await
            .expect("a cookie reply")
            .unwrap();
        let cookie = cookie_from(&buf[..n]);
        let again = encode_handshake_init_cookie(&cookie, &msg1[2..]);

        ACCEPT_ATTEMPTS.with(|n| n.set(0));
        let started = Instant::now();
        for _ in 0..100 {
            SessionManager::handle_datagram(&ctx, &mut router, again.len(), from, &again).await;
        }
        let elapsed = started.elapsed();
        let worked_on = ACCEPT_ATTEMPTS.with(|n| n.get());
        // What the bucket may have refilled while the loop ran: one proven
        // handshake per 1/PROVEN_PER_SECOND of it.
        let refilled = (elapsed.as_millis() * u128::from(PROVEN_PER_SECOND) / 1000) as usize;
        assert!(
            worked_on >= PROVEN_BURST as usize,
            "the burst is worked on: {worked_on}"
        );
        assert!(
            worked_on <= PROVEN_BURST as usize + refilled,
            "{worked_on} of 100 proven copies worked on in {elapsed:?}"
        );
    }

    /// The daemon logs the start of load at once, and its end only once the
    /// load has stayed off for `LOAD_LOG_SETTLE`: a load that flickers at
    /// its threshold -- a slow forged flood keeps the probation table at
    /// 64/65 seats, and every seat that expires turns load off for one
    /// datagram -- is one episode in the log, not two lines per seat.
    #[tokio::test]
    async fn a_load_that_flickers_is_one_episode_in_the_log() {
        let rig = SignatureRig::new().await;
        let ctx = rig.ctx();
        let mut router = Router::new();
        // Load is any seat taken; the rate never counts.
        router.cookies = CookieCheck::with_limits(
            Instant::now(),
            LoadLimits {
                handshakes_per_window: u32::MAX,
                probation_seats: 0,
            },
        );
        LOAD_LOGGED.with(|l| l.borrow_mut().clear());
        let mut forged = 0u8;
        let mut next_forged = || {
            forged += 1;
            (
                signature_msg1(&rig.server_pub, [forged; 16], StartKind::Cold),
                SocketAddr::from(([198, 51, 103, forged], 40_000)),
            )
        };
        for round in 0..3 {
            // No seat: no load, and the msg1 takes one.
            let (msg1, from) = next_forged();
            SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
            assert_eq!(router.probation.len(), 1, "round {round}");
            // A seat taken: load.
            let (msg1, from) = next_forged();
            SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
            assert!(router.cookies.under_load(), "round {round}");
            // The seat expires.
            router.probation.clear();
        }
        assert_eq!(
            LOAD_LOGGED.with(|l| l.borrow().clone()),
            vec![LOAD_ON_LINE],
            "three flickers, one line"
        );

        // Once the load has stayed off long enough, the next handshake says so.
        router.load_log.settle = Duration::ZERO;
        let (msg1, from) = next_forged();
        SessionManager::handle_datagram(&ctx, &mut router, msg1.len(), from, &msg1).await;
        assert_eq!(
            LOAD_LOGGED.with(|l| l.borrow().clone()),
            vec![LOAD_ON_LINE, LOAD_OFF_LINE]
        );
    }

    /// `LoadLog` on its own clock: the start of load is logged at once and
    /// once; its end after the load was last seen `LOAD_LOG_SETTLE` ago --
    /// told at the first check after that -- and a new start after an end
    /// is logged again.
    #[test]
    fn the_load_log_ends_an_episode_only_once_load_stayed_off_for_the_settle() {
        let t0 = Instant::now();
        let mut log = LoadLog::new();
        assert_eq!(log.note(t0, false), None, "nothing to say without load");
        assert_eq!(log.note(t0, true), Some(LOAD_ON_LINE));
        assert_eq!(log.note(t0 + Duration::from_millis(10), true), None);
        let last_seen = t0 + Duration::from_secs(1);
        assert_eq!(log.note(last_seen, true), None);
        assert_eq!(log.note(last_seen + Duration::from_millis(1), false), None);
        assert_eq!(
            log.note(
                last_seen + LOAD_LOG_SETTLE - Duration::from_millis(1),
                false
            ),
            None,
            "not yet"
        );
        assert_eq!(
            log.note(last_seen + LOAD_LOG_SETTLE, false),
            Some(LOAD_OFF_LINE)
        );
        assert_eq!(log.note(last_seen + 2 * LOAD_LOG_SETTLE, false), None);
        assert_eq!(
            log.note(last_seen + 3 * LOAD_LOG_SETTLE, true),
            Some(LOAD_ON_LINE),
            "a new episode"
        );
    }

    // ---- A retained session removed while a proof for its login is in flight ----

    /// The system mode's helper, as far as its login table goes, in ONE
    /// object that is both the verifier and the login sink -- so the order in
    /// which the router drives the two is exactly the order this table sees.
    /// A proof that verifies puts its login on file unless it is there
    /// already (the helper's `ensure_login`), `LoginEnded` takes it off
    /// (`forget_login`), and the helper opens a channel only for a login on
    /// file (`Request::Open` never creates one).
    struct HelperLogins {
        on_file: Mutex<HashSet<LoginId>>,
    }

    impl HelperLogins {
        /// A helper that already has `login` on file: the login a retained
        /// session was bound under.
        fn with(login: LoginId) -> Arc<HelperLogins> {
            Arc::new(HelperLogins {
                on_file: Mutex::new([login].into_iter().collect()),
            })
        }

        /// Whether the helper would open a channel for `login` now.
        fn opens_channels_for(&self, login: LoginId) -> bool {
            self.on_file.lock().unwrap().contains(&login)
        }
    }

    impl AuthVerifier for HelperLogins {
        fn verify(
            &self,
            _handshake_hash: &[u8; 32],
            record: &AuthRecord,
            login: [u8; 16],
            _rhost: &str,
        ) -> Result<Principal, AuthError> {
            if record.signature != b"good" {
                return Err(AuthError::BadSignature);
            }
            self.on_file.lock().unwrap().insert(login);
            Ok(test_principal())
        }
    }

    impl LoginSink for HelperLogins {
        fn login_ended(&self, login: LoginId) {
            self.on_file.lock().unwrap().remove(&login);
        }
    }

    /// Everything a `ManagerCtx` borrows, owned in one place, with a
    /// `HelperLogins` as both the verifier and the sink. The receiving end
    /// of the probation channel is handed back separately: the test, not a
    /// `serve` loop, gives each `ProbationEnded` to the router, and so
    /// decides what the router does before it sees a verdict.
    struct RouterWiring {
        socket: Arc<UdpSocket>,
        server_priv: [u8; 32],
        server_pub: [u8; 32],
        auth: ServerAuth,
        factory: BackendFactory,
        done_tx: mpsc::UnboundedSender<SessionEnded>,
        _done_rx: mpsc::UnboundedReceiver<SessionEnded>,
        probation_tx: mpsc::UnboundedSender<ProbationEnded>,
        active_count: Arc<AtomicUsize>,
    }

    impl RouterWiring {
        async fn new(
            helper: Arc<HelperLogins>,
        ) -> (RouterWiring, mpsc::UnboundedReceiver<ProbationEnded>) {
            let server_kp = generate_keypair();
            let (done_tx, done_rx) = mpsc::unbounded_channel::<SessionEnded>();
            let (probation_tx, probation_rx) = mpsc::unbounded_channel::<ProbationEnded>();
            let wiring = RouterWiring {
                socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                server_priv: server_kp.private,
                server_pub: server_kp.public,
                auth: ServerAuth {
                    allowlist: Arc::new(Mutex::new(Vec::new())),
                    verifier: Some(helper.clone() as Arc<dyn AuthVerifier>),
                    server_pub: server_kp.public,
                    self_principal: test_self_principal(),
                    nonces: Arc::new(TestNonces),
                    logins: helper,
                },
                factory: BackendFactory(Arc::new(EchoBackend)),
                done_tx,
                _done_rx: done_rx,
                probation_tx,
                active_count: Arc::new(AtomicUsize::new(0)),
            };
            (wiring, probation_rx)
        }

        fn ctx(&self) -> ManagerCtx<'_> {
            ManagerCtx {
                socket: &self.socket,
                server_priv: &self.server_priv,
                auth: &self.auth,
                factory: &self.factory,
                done_tx: &self.done_tx,
                probation_tx: &self.probation_tx,
                active_count: &self.active_count,
            }
        }
    }

    #[tokio::test]
    async fn shell_replacement_control_manager_rejects_candidates_without_replacing_active_route() {
        let token = [0xA4; 16];
        let helper = HelperLogins::with(token);
        let (mut wiring, _verdicts) = RouterWiring::new(helper.clone()).await;
        let allowed = generate_keypair();
        wiring.auth.verifier = None;
        wiring.auth.allowlist.lock().unwrap().push(allowed.public);
        let mut router = Router::new();
        let (mut control, mut route) =
            synthetic_live_entry_with_key(&mut router, token, 42, allowed.public);
        router.backends.get_mut(&token).unwrap().incarnation = 7;
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = stranger.local_addr().unwrap();
        let unlisted = generate_keypair();
        let candidates = [
            crate::wire::encode_handshake(Kind::HandshakeInit, &[]),
            crate::wire::encode_handshake(Kind::HandshakeInit, &[0; 40]),
            msg1_with_method(
                &wiring.server_pub,
                unlisted.private,
                token,
                StartKind::Cold,
                AuthMethod::Allowlist,
            ),
        ];
        for bytes in candidates {
            SessionManager::handle_datagram(&wiring.ctx(), &mut router, bytes.len(), src, &bytes)
                .await;
            let entry = &router.backends[&token];
            assert_eq!(
                (entry.session_id, entry.incarnation, entry.client_key),
                (42, 7, allowed.public)
            );
            assert!(matches!(entry.state, EntryState::Live));
            assert!(entry.parked_dgram.is_none());
            assert!(helper.opens_channels_for(token));
            assert!(wiring
                .auth
                .allowlist
                .lock()
                .unwrap()
                .contains(&allowed.public));
            assert!(router.probation.is_empty());
            assert!(matches!(
                control.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            // The router forwards by session id; decryption belongs to its
            // consumer. Observe the original receiver, not only table size.
            let marker =
                crate::wire::encode_transport(&crate::wire::transport_header(42, 1), &[0xA4; 16]);
            SessionManager::handle_datagram(&wiring.ctx(), &mut router, marker.len(), src, &marker)
                .await;
            assert_eq!(route.try_recv(), Some((src, marker)));
        }
    }

    /// A client handshakes into probation through the real `handle_datagram`,
    /// and the probation task verifies its proof. Returns the
    /// `ProbationEnded` that task queued -- NOT yet handed to the router, so
    /// the caller decides what the router does first -- and the client's
    /// socket, kept open for whatever the session sends it later.
    async fn a_proof_already_verified(
        wiring: &RouterWiring,
        router: &mut Router,
        verdicts: &mut mpsc::UnboundedReceiver<ProbationEnded>,
        token: LoginId,
        start_kind: StartKind,
    ) -> (ProbationEnded, UdpSocket) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = sock.local_addr().unwrap();
        let server_addr = wiring.socket.local_addr().unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::SshSignature,
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind,
            token,
            method: AuthMethod::SshSignature,
        });
        let in_probation = router.probation.len();
        for dg in client.start_with_payload(Instant::now(), server_addr, &payload) {
            SessionManager::handle_datagram(
                &wiring.ctx(),
                router,
                dg.bytes.len(),
                client_addr,
                &dg.bytes,
            )
            .await;
        }
        assert_eq!(
            router.probation.len(),
            in_probation + 1,
            "setup: the handshake went into probation"
        );

        let mut buf = vec![0u8; RECV_BUF_LEN];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("msg2 did not arrive")
            .unwrap();
        let mut to_server = client.on_datagram(Instant::now(), from, &buf[..len]);
        to_server.extend(client.send(Instant::now(), AUTH_STREAM, &good_record()));
        for dg in to_server {
            SessionManager::handle_datagram(
                &wiring.ctx(),
                router,
                dg.bytes.len(),
                client_addr,
                &dg.bytes,
            )
            .await;
        }

        let verdict = tokio::time::timeout(Duration::from_secs(5), verdicts.recv())
            .await
            .expect("the probation did not end")
            .expect("the probation channel is open");
        assert!(verdict.proven.is_some(), "setup: the proof verified");
        (verdict, sock)
    }

    /// A device comes back to its retained session just as the GC reaches
    /// it. A console client returning with its saved token about an hour
    /// later does exactly this, with no special timing of its own. Its warm
    /// handshake's proof has already verified -- the helper put it into the
    /// login entry it already had -- and the verdict is waiting for the
    /// router when the GC tick is served first. Were the GC to collect the
    /// session now and report its login ended, the helper would drop the very
    /// entry the proof went into, the proof would bind a fresh backend
    /// afterwards, and the helper would refuse every channel that backend
    /// asks for until the client reconnects.
    #[tokio::test]
    async fn the_gc_spares_a_retained_session_whose_proof_is_already_verified() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let token: LoginId = [0xD1; 16];
            let helper = HelperLogins::with(token);
            let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();

            // The device's session, dead and retained, under the account its
            // proof will name.
            let (mut ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
            router.backends.get_mut(&token).expect("entry").owner = test_principal().uid;
            let died = tokio::time::Instant::now();
            router.on_session_ended(
                SessionEnded {
                    session_id: 1,
                    token,
                    graceful: false,
                },
                died,
            );

            // It comes back: a warm handshake whose proof has verified.
            let (verdict, _client) = a_proof_already_verified(
                &wiring,
                &mut router,
                &mut verdicts,
                token,
                StartKind::Warm,
            )
            .await;

            // The GC tick, past RETAIN_AFTER_DEATH, is served before that
            // verdict.
            gc_retained_and_notify(
                &mut router,
                &wiring.auth,
                died + RETAIN_AFTER_DEATH + Duration::from_secs(1),
            );
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, verdict).await;

            let bound = router.backends.contains_key(&token);
            let on_file = helper.opens_channels_for(token);
            assert!(
                !bound || on_file,
                "a proof the helper already admitted must not be bound after the router told the \
                 helper its login was over -- the helper refuses every channel of that session \
                 (bound={bound}, on_file={on_file})"
            );
            assert!(bound, "the returning device must get a session");
            assert!(
                matches!(ctl.try_recv(), Ok(BridgeControl::Attach(..))),
                "and it must be the retained one, reattached -- not a fresh backend"
            );
        })
        .await
        .expect("the test timed out");
    }

    /// The same race through eviction. At the session cap a newcomer's
    /// admission evicts a retained session; if that is the session whose
    /// owner's proof has already verified, evicting it ends a login the
    /// helper has just put that proof into, and the proof then binds a fresh
    /// backend the helper opens nothing for. Here eviction has a choice --
    /// another retained session, newer, that nobody is coming back for --
    /// and must take that one.
    #[tokio::test]
    async fn eviction_passes_over_a_retained_session_whose_proof_is_already_verified() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let returning: LoginId = [0xD2; 16];
            let abandoned: LoginId = [0xD3; 16];
            let newcomer: LoginId = [0xD4; 16];
            let helper = HelperLogins::with(returning);
            let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();
            let mut keep_alive = Vec::new();
            let t0 = tokio::time::Instant::now();

            // The returning device's session: retained, and the OLDEST.
            keep_alive.push(synthetic_live_entry(&mut router, returning, 1));
            router.backends.get_mut(&returning).expect("entry").owner = test_principal().uid;
            router.on_session_ended(
                SessionEnded {
                    session_id: 1,
                    token: returning,
                    graceful: false,
                },
                t0,
            );
            // Another retained session, newer, that nobody is coming back for.
            keep_alive.push(synthetic_live_entry(&mut router, abandoned, 2));
            router.backends.get_mut(&abandoned).expect("entry").owner = 2;
            router.on_session_ended(
                SessionEnded {
                    session_id: 2,
                    token: abandoned,
                    graceful: false,
                },
                t0 + Duration::from_secs(10),
            );
            // Everything else live, each its own owner: the table is full.
            for i in 0..(MAX_SESSIONS_TOTAL - 2) {
                let token = [(10 + i) as u8; 16];
                keep_alive.push(synthetic_live_entry(&mut router, token, (10 + i) as u64));
                router.backends.get_mut(&token).expect("entry").owner = (100 + i) as u32;
            }
            assert_eq!(router.backends.len(), MAX_SESSIONS_TOTAL);

            let (returning_verdict, _c1) = a_proof_already_verified(
                &wiring,
                &mut router,
                &mut verdicts,
                returning,
                StartKind::Warm,
            )
            .await;
            let (newcomer_verdict, _c2) = a_proof_already_verified(
                &wiring,
                &mut router,
                &mut verdicts,
                newcomer,
                StartKind::Cold,
            )
            .await;

            // The newcomer's verdict is served first, and admitting it evicts.
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, newcomer_verdict).await;
            assert!(
                router.backends.contains_key(&newcomer),
                "setup: the newcomer was admitted"
            );
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, returning_verdict).await;

            let bound = router.backends.contains_key(&returning);
            let on_file = helper.opens_channels_for(returning);
            assert!(
                !bound || on_file,
                "a proof the helper already admitted must not be bound after an eviction told the \
                 helper its login was over -- the helper refuses every channel of that session \
                 (bound={bound}, on_file={on_file})"
            );
            assert!(bound, "the returning device must get a session");
            assert!(
                matches!(keep_alive[0].0.try_recv(), Ok(BridgeControl::Attach(..))),
                "and it must be the retained one, reattached -- not a fresh backend"
            );
            assert!(
                !router.backends.contains_key(&abandoned),
                "the retained session nobody was proving for is the one evicted"
            );
        })
        .await
        .expect("the test timed out");
    }

    /// A handshake for `token` from `src` goes into probation through the
    /// real `handle_datagram`, and its proof never comes.
    async fn an_unproven_handshake(
        wiring: &RouterWiring,
        router: &mut Router,
        token: LoginId,
        src: SocketAddr,
    ) {
        let msg1 = signature_msg1(&wiring.server_pub, token, StartKind::Warm);
        let in_probation = router.probation.len();
        SessionManager::handle_datagram(&wiring.ctx(), router, msg1.len(), src, &msg1).await;
        assert_eq!(
            router.probation.len(),
            in_probation + 1,
            "setup: the handshake went into probation"
        );
    }

    /// A graceful close must not end a login whose PROOF is still in
    /// probation.
    ///
    /// The garbage collector already holds back for one
    /// ([`Router::gc_retained`]); this path did not, and it is the one a
    /// client can reach without going near a cap. The cost of getting it
    /// wrong is not a reconnect: the login entry a `Verify` has just made
    /// in the helper is removed, the session that survives never presents a
    /// proof again -- neither roaming nor a warm reattach repeats one -- and
    /// every `Request::Open` it makes for the rest of its life is refused
    /// with the same "authentication failed" a bad signature gets. Nothing
    /// on either side can tell those apart, so nothing tears the session
    /// down; it stays up, answers pings, and can never open a channel.
    #[tokio::test]
    async fn a_graceful_close_spares_a_login_whose_proof_is_in_probation() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let token: LoginId = [0xC7; 16];

            // The control comes first and on the same path: with nothing in
            // probation, a graceful close still ends the login at once.
            // Without it the assertion below would pass equally well
            // against a router that had stopped ending logins at all.
            let plain_helper = HelperLogins::with(token);
            let (plain, _plain_verdicts) = RouterWiring::new(plain_helper.clone()).await;
            let mut router = Router::new();
            let (_plain_ctl, _plain_dg) = synthetic_live_entry(&mut router, token, 1);
            on_session_ended_and_notify(
                &mut router,
                &plain.auth,
                SessionEnded {
                    session_id: 1,
                    token,
                    graceful: true,
                },
                tokio::time::Instant::now(),
            );
            assert!(
                !router.backends.contains_key(&token),
                "control: a graceful close with no proof in flight must drop the backend"
            );
            assert!(
                !plain_helper.opens_channels_for(token),
                "control: and must tell the helper that login ended"
            );

            // And now the order that costs: a second handshake naming the
            // same token is in probation -- its `Verify` may already have
            // put this login on file with the helper -- when the first
            // connection closes cleanly.
            let helper = HelperLogins::with(token);
            let (wiring, _verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();
            let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
            an_unproven_handshake(
                &wiring,
                &mut router,
                token,
                "127.0.0.1:9971".parse().unwrap(),
            )
            .await;
            on_session_ended_and_notify(
                &mut router,
                &wiring.auth,
                SessionEnded {
                    session_id: 1,
                    token,
                    graceful: true,
                },
                tokio::time::Instant::now(),
            );

            assert!(
                helper.opens_channels_for(token),
                "a graceful close must not end a login whose proof is still in probation -- the \
                 session that survives it could never open a channel again"
            );
            assert!(
                matches!(
                    router.backends.get(&token).map(|entry| &entry.state),
                    Some(EntryState::Retained { .. })
                ),
                "and the entry is RETAINED rather than dropped, so the reprieve and the \
                 retention that already exist decide what becomes of it"
            );
        })
        .await
        .expect("the test timed out");
    }

    /// A real candidate, paused before it sends any proof. The router still
    /// owns its probation seat and the client can send a valid or bad record.
    async fn pending_ended_proof(
        wiring: &RouterWiring,
        router: &mut Router,
        token: LoginId,
    ) -> (Connection, UdpSocket) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = sock.local_addr().unwrap();
        let server = wiring.socket.local_addr().unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::SshSignature,
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Warm,
            token,
            method: AuthMethod::SshSignature,
        });
        for dg in client.start_with_payload(Instant::now(), server, &payload) {
            SessionManager::handle_datagram(&wiring.ctx(), router, dg.bytes.len(), src, &dg.bytes)
                .await;
        }
        let mut buf = vec![0; RECV_BUF_LEN];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let _ = client.on_datagram(Instant::now(), from, &buf[..n]);
        assert!(router.probation.contains_key(&client.session_id()));
        (client, sock)
    }

    fn end_for_proof(router: &mut Router, wiring: &RouterWiring, token: LoginId) {
        let session_id = router.backends[&token].session_id;
        on_session_ended_and_notify(
            router,
            &wiring.auth,
            SessionEnded {
                session_id,
                token,
                graceful: true,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(
            router.backends[&token].state,
            EntryState::Retained { .. }
        ));
    }

    async fn finish_failed_ended_proof(
        wiring: &RouterWiring,
        router: &mut Router,
        verdicts: &mut mpsc::UnboundedReceiver<ProbationEnded>,
        id: u64,
    ) {
        let ended = tokio::time::timeout(
            crate::auth::AUTH_DEADLINE + Duration::from_secs(2),
            verdicts.recv(),
        )
        .await
        .expect("probation did not finish")
        .unwrap();
        assert_eq!(ended.session_id, id);
        assert!(ended.proven.is_none());
        SessionManager::on_probation_ended(&wiring.ctx(), router, ended).await;
        assert!(!router.probation.contains_key(&id));
        assert!(!router.sessions.contains_key(&id));
    }

    async fn ended_proof_failure_case(kind: u8) {
        let token = [0xE1; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        let (mut client, socket) = pending_ended_proof(&wiring, &mut router, token).await;
        end_for_proof(&mut router, &wiring, token);
        assert!(helper.opens_channels_for(token));
        match kind {
            0 => {
                let bad = encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"wrong".to_vec(),
                    v2: None,
                })
                .unwrap();
                for dg in client.send(Instant::now(), AUTH_STREAM, &bad) {
                    SessionManager::handle_datagram(
                        &wiring.ctx(),
                        &mut router,
                        dg.bytes.len(),
                        socket.local_addr().unwrap(),
                        &dg.bytes,
                    )
                    .await;
                }
            }
            1 => {
                router.sessions.remove(&client.session_id());
            }
            2 => {} // The real authentication deadline expires; no injected verdict.
            _ => unreachable!(),
        }
        finish_failed_ended_proof(&wiring, &mut router, &mut verdicts, client.session_id()).await;
        assert!(
            !router.backends.contains_key(&token),
            "gracefully ended backend survived its last candidate"
        );
        assert!(
            !helper.opens_channels_for(token),
            "helper login must end without waiting for GC"
        );
        assert!(
            ctl.is_closed(),
            "backend control ownership must be released"
        );
    }

    #[tokio::test]
    async fn ended_proof_bad_signature_releases_backend_and_helper() {
        ended_proof_failure_case(0).await;
    }

    #[tokio::test]
    async fn ended_proof_cancellation_releases_backend_and_helper() {
        ended_proof_failure_case(1).await;
    }

    #[tokio::test]
    async fn ended_proof_expiry_releases_backend_and_helper() {
        ended_proof_failure_case(2).await;
    }

    #[tokio::test]
    async fn ended_proof_keeps_login_until_the_last_candidate_finishes() {
        let token = [0xE2; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        let (first, _one) = pending_ended_proof(&wiring, &mut router, token).await;
        let (last, _two) = pending_ended_proof(&wiring, &mut router, token).await;
        end_for_proof(&mut router, &wiring, token);
        router.sessions.remove(&first.session_id());
        finish_failed_ended_proof(&wiring, &mut router, &mut verdicts, first.session_id()).await;
        assert!(router.backends.contains_key(&token));
        assert!(
            helper.opens_channels_for(token),
            "remaining candidate can already be verifying"
        );
        router.sessions.remove(&last.session_id());
        finish_failed_ended_proof(&wiring, &mut router, &mut verdicts, last.session_id()).await;
        assert!(!router.backends.contains_key(&token));
        assert!(!helper.opens_channels_for(token));
    }

    #[tokio::test]
    async fn ended_proof_success_binds_before_any_login_cleanup() {
        for bridge_alive in [false, true] {
            let token = [0xE3; 16];
            let helper = HelperLogins::with(token);
            let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();
            let (ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
            router.backends.get_mut(&token).unwrap().owner = test_principal().uid;
            let (ended, _socket) = a_proof_already_verified(
                &wiring,
                &mut router,
                &mut verdicts,
                token,
                StartKind::Warm,
            )
            .await;
            let new_id = ended.session_id;
            end_for_proof(&mut router, &wiring, token);
            let _keep = bridge_alive.then_some(ctl);
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
            assert_eq!(router.backends[&token].session_id, new_id);
            assert!(matches!(router.backends[&token].state, EntryState::Live));
            assert!(
                helper.opens_channels_for(token),
                "a successful proof's helper login must survive both rebind and cold fallback"
            );
        }
    }

    #[tokio::test]
    async fn ended_proof_rejection_after_verification_releases_ended_login() {
        let token = [0xE4; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        router.backends.get_mut(&token).unwrap().owner = test_principal().uid + 1;
        let (ended, _socket) =
            a_proof_already_verified(&wiring, &mut router, &mut verdicts, token, StartKind::Warm)
                .await;
        end_for_proof(&mut router, &wiring, token);
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert!(
            !router.backends.contains_key(&token),
            "foreign owner refused; no session adopted the proof"
        );
        assert!(!helper.opens_channels_for(token));
    }

    #[tokio::test]
    async fn ended_proof_retransmit_without_adoption_releases_ended_login() {
        let token = [0xE5; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        let (mut ended, _socket) =
            a_proof_already_verified(&wiring, &mut router, &mut verdicts, token, StartKind::Warm)
                .await;
        let proven = ended.proven.as_mut().unwrap();
        proven.principal.incarnation = 2;
        router.backends.get_mut(&token).unwrap().last_msg1_body = proven.msg1_body.clone();
        end_for_proof(&mut router, &wiring, token);
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert!(
            !router.backends.contains_key(&token),
            "resending cached msg2 does not adopt a live session"
        );
        assert!(!helper.opens_channels_for(token));
    }

    #[tokio::test]
    async fn ended_proof_failure_preserves_active_and_unexpected_death_replacements() {
        for retained in [false, true] {
            let token = [0xE6; 16];
            let helper = HelperLogins::with(token);
            let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();
            let (_old_ctl, _old_dg) = synthetic_live_entry(&mut router, token, 1);
            let (candidate, _socket) = pending_ended_proof(&wiring, &mut router, token).await;
            end_for_proof(&mut router, &wiring, token);
            let (_new_ctl, _new_dg) = synthetic_live_entry(&mut router, token, 2);
            router.backends.get_mut(&token).unwrap().incarnation = 2;
            if retained {
                on_session_ended_and_notify(
                    &mut router,
                    &wiring.auth,
                    SessionEnded {
                        session_id: 2,
                        token,
                        graceful: false,
                    },
                    tokio::time::Instant::now(),
                );
            }
            router.sessions.remove(&candidate.session_id());
            finish_failed_ended_proof(&wiring, &mut router, &mut verdicts, candidate.session_id())
                .await;
            assert_eq!(router.backends[&token].session_id, 2);
            assert_eq!(router.backends[&token].incarnation, 2);
            assert_eq!(
                matches!(router.backends[&token].state, EntryState::Retained { .. }),
                retained
            );
            assert!(
                helper.opens_channels_for(token),
                "an old candidate cannot end the replacement's helper login"
            );
        }
    }

    #[tokio::test]
    async fn ended_proof_stale_verdict_without_a_seat_preserves_current_retention() {
        let token = [0xE7; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (ctl, mut parked) = synthetic_live_entry(&mut router, token, 1);
        let (candidate, socket) = pending_ended_proof(&wiring, &mut router, token).await;
        end_for_proof(&mut router, &wiring, token);
        // Model a stale completion whose seat was already removed. Leave no
        // other candidate to mask the missing-seat guard under test.
        assert!(router.probation.remove(&candidate.session_id()).is_some());
        router.sessions.remove(&candidate.session_id());
        assert!(router.probation.is_empty());
        finish_failed_ended_proof(&wiring, &mut router, &mut verdicts, candidate.session_id())
            .await;
        let entry = &router.backends[&token];
        assert_eq!(entry.session_id, 1);
        assert!(matches!(entry.state, EntryState::Retained { .. }));
        assert!(helper.opens_channels_for(token));
        assert!(!ctl.is_closed());
        let src = socket.local_addr().unwrap();
        assert!(entry
            .parked_dgram
            .as_ref()
            .unwrap()
            .send(src, b"still owned".to_vec()));
        assert_eq!(parked.try_recv(), Some((src, b"still owned".to_vec())));
    }

    /// The GC's reprieve is ONE pass for each retention, and no more. A
    /// probation that never ends -- or a fresh one behind it, which a
    /// stranger replaying the token's handshake over and over would keep up
    /// -- must not keep a dead session, and the login the helper still
    /// trusts for it, alive past the next pass.
    #[tokio::test]
    async fn the_gc_spares_a_retained_session_one_pass_only() {
        tokio::time::timeout(Duration::from_secs(20), async {
            let token: LoginId = [0xD5; 16];
            let helper = HelperLogins::with(token);
            let (wiring, _verdicts) = RouterWiring::new(helper.clone()).await;
            let mut router = Router::new();
            let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
            let died = tokio::time::Instant::now();
            router.on_session_ended(
                SessionEnded {
                    session_id: 1,
                    token,
                    graceful: false,
                },
                died,
            );

            // A handshake for the token that never proves anything.
            an_unproven_handshake(
                &wiring,
                &mut router,
                token,
                "127.0.0.1:9981".parse().unwrap(),
            )
            .await;
            let first_pass = died + RETAIN_AFTER_DEATH + Duration::from_secs(1);
            gc_retained_and_notify(&mut router, &wiring.auth, first_pass);
            assert!(
                router.backends.contains_key(&token) && helper.opens_channels_for(token),
                "the first pass past RETAIN_AFTER_DEATH spares a session whose login is in \
                 probation"
            );

            // Another one joins it before the next pass.
            an_unproven_handshake(
                &wiring,
                &mut router,
                token,
                "127.0.0.1:9982".parse().unwrap(),
            )
            .await;
            gc_retained_and_notify(&mut router, &wiring.auth, first_pass + GC_INTERVAL);
            let kept = router.backends.contains_key(&token);
            let on_file = helper.opens_channels_for(token);
            assert!(
                !kept && !on_file,
                "but only once: whatever is in probation at the next pass, a retained session and \
                 its login must not outlive it (kept={kept}, on_file={on_file})"
            );
        })
        .await
        .expect("the test timed out");
    }

    /// Drives the GC duty the way `serve` does -- a tick of [`gc_timer`],
    /// then `gc_retained_and_notify` -- for a retained session whose login is
    /// in probation when its time runs out. `stall` is how long the router
    /// loop is away just before that; `None` serves every tick on time.
    /// Returns whether another pass came less than a whole `GC_INTERVAL`
    /// after the reprieve, whether the login was reported ended, and how long
    /// after the reprieve that pass came.
    async fn the_pass_after_a_reprieve(stall: Option<Duration>) -> (bool, bool, Duration) {
        let token: LoginId = [0xD6; 16];
        let sink = Arc::new(RecordingLogins::default());
        let auth = ServerAuth {
            allowlist: Arc::new(Mutex::new(Vec::new())),
            verifier: None,
            server_pub: [0u8; 32],
            self_principal: test_self_principal(),
            nonces: Arc::new(TestNonces),
            logins: sink.clone(),
        };
        let mut router = Router::new();
        let (_ctl, _dg) = synthetic_live_entry(&mut router, token, 1);
        let mut gc = gc_timer();

        // The loop's first tick; then the session dies.
        gc.tick().await;
        gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
        let died = tokio::time::Instant::now();
        router.on_session_ended(
            SessionEnded {
                session_id: 1,
                token,
                graceful: false,
            },
            died,
        );
        // Every tick on time for most of the hour.
        while tokio::time::Instant::now() + GC_INTERVAL < died + RETAIN_AFTER_DEATH {
            gc.tick().await;
            gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
        }
        assert!(
            router.backends.contains_key(&token),
            "setup: still retained"
        );
        // The device comes back: its handshake is in probation.
        assert!(
            router.admit_probation(99, probation_src(99), token),
            "setup: the handshake is in probation"
        );
        if let Some(stall) = stall {
            // The loop is away, and the session's time runs out meanwhile.
            tokio::time::advance(stall).await;
        }
        // The loop serves its GC tick first.
        gc.tick().await;
        gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
        assert!(
            router.backends.contains_key(&token) && sink.recorded().is_empty(),
            "setup: the pass spares the session"
        );
        let reprieved_at = tokio::time::Instant::now();
        // Is another pass due before a whole interval has gone by? The proof
        // the reprieve was granted for is still waiting to be served.
        let early = tokio::time::timeout(GC_INTERVAL - Duration::from_millis(10), gc.tick())
            .await
            .is_ok();
        if early {
            gc_retained_and_notify(&mut router, &auth, tokio::time::Instant::now());
        }
        let gap = tokio::time::Instant::now() - reprieved_at;
        (early, sink.recorded().contains(&token), gap)
    }

    /// With every tick on time, the pass after a reprieve is a whole
    /// `GC_INTERVAL` away -- the control for the stalled case below.
    #[tokio::test(start_paused = true)]
    async fn without_a_stall_the_pass_after_a_reprieve_is_an_interval_away() {
        let (early, ended, gap) = the_pass_after_a_reprieve(None).await;
        assert!(
            !early && !ended,
            "without a stall the next pass is a whole GC_INTERVAL away (early={early}, \
             ended={ended}, gap={gap:?})"
        );
    }

    /// The router loop stalls for more than two intervals just as a
    /// returning device's session comes due. The pass after the reprieve
    /// must still be a whole `GC_INTERVAL` away: missed ticks fired back to
    /// back (`Burst`) spend the reprieve at once, while the proof it was
    /// granted for waits to be served, and the session is stranded exactly
    /// as if there were no reprieve. The stall ends 10 ms short of a
    /// multiple of the interval, so a timer that resumes its old schedule
    /// (`Skip`) is caught too: its next tick is 10 ms away.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_router_does_not_spend_the_reprieve_at_once() {
        let stall = GC_INTERVAL * 3 - Duration::from_millis(10);
        let (early, ended, gap) = the_pass_after_a_reprieve(Some(stall)).await;
        assert!(
            !early && !ended,
            "after a stall the pass that follows a reprieve must still be a whole GC_INTERVAL \
             away (early={early}, ended={ended}, gap={gap:?})"
        );
    }

    /// Eviction PREFERS a retained session whose login is not in probation;
    /// it does not exempt one whose login is. With every retained session
    /// under a handshake in probation, a newcomer still gets in by evicting
    /// the oldest of them -- otherwise replaying a token's handshake would
    /// hold that session out of reach and turn the session cap into a
    /// lockout.
    #[tokio::test(start_paused = true)]
    async fn eviction_still_takes_a_session_in_probation_when_nothing_else_is_retained() {
        let retained = [1u8; 16];
        // Every entry is owner 0; the newcomer below is another account, so
        // it is the daemon-wide ceiling that blocks it, not its own cap.
        let (mut router, _keep_alive) = router_at_the_session_cap(retained);
        assert!(
            router.admit_probation(77, probation_src(77), retained),
            "setup: a handshake for the retained session's login is in probation"
        );
        assert!(
            router.admit_new_backend(9999),
            "a newcomer must still be admitted at the cap when every retained session's login is \
             in probation"
        );
        assert!(
            !router.backends.contains_key(&retained),
            "by evicting that retained session anyway"
        );
    }

    /// A backend that writes output every millisecond for as long as it runs.
    struct FloodBackend;

    impl SessionBackend for FloodBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                let mut tick = tokio::time::interval(Duration::from_millis(1));
                loop {
                    tokio::select! {
                        ev = io.recv() => if ev.is_none() { return },
                        _ = tick.tick() => io.send(16, vec![b'x'; 512]),
                    }
                }
            })
        }
    }

    /// Spec §4.1 / §9.2 (defect 2'): under a backend that never pauses, the
    /// bridge still PINGs on schedule. Not demonstrated to fail before the
    /// fix (audit §2.3) -- it pins the property the timer rule guarantees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_bridge_keeps_its_ping_schedule_under_a_backend_that_never_pauses() {
        let mut client = start_manager_with_allowlist(FloodBackend).await;
        client.handshake().await;
        let started = tokio::time::Instant::now();
        let mut pings: Vec<Instant> = Vec::new();
        while started.elapsed() < Duration::from_secs(10) {
            let Ok(Ok((len, src))) = tokio::time::timeout(
                Duration::from_millis(100),
                client.sock.recv_from(&mut client.buf),
            )
            .await
            else {
                continue;
            };
            let now = Instant::now();
            if client
                .conn
                .peek_frames(&client.buf[..len])
                .is_some_and(|frames| frames.iter().any(|f| matches!(f, StreamFrame::Ping { .. })))
            {
                pings.push(now);
            }
            let out = client.conn.on_datagram(now, src, &client.buf[..len]);
            send_client(&client.sock, &out).await;
            let _ = client.conn.poll_events();
        }
        assert!(
            pings.len() >= 6,
            "{} PINGs in ten seconds of output",
            pings.len()
        );
        let worst = pings
            .windows(2)
            .map(|w| w[1] - w[0])
            .max()
            .expect("two PINGs or more");
        // The PING period is 1.5 s; the bound leaves 500 ms for a loaded
        // machine's scheduling. The defect this pins gave gaps of 13.5 s and
        // more -- or none at all.
        assert!(
            worst <= Duration::from_millis(2000),
            "the longest gap between PINGs was {worst:?}"
        );
    }

    /// A verifier that takes `delay` before it answers like `FakeVerifier`.
    struct SlowVerifier {
        inner: FakeVerifier,
        delay: Duration,
    }

    impl SlowVerifier {
        fn accepting_good(delay: Duration) -> SlowVerifier {
            SlowVerifier {
                inner: FakeVerifier::accepting_good(),
                delay,
            }
        }
    }

    impl AuthVerifier for SlowVerifier {
        fn verify(
            &self,
            handshake_hash: &[u8; 32],
            record: &AuthRecord,
            login: [u8; 16],
            rhost: &str,
        ) -> Result<Principal, AuthError> {
            std::thread::sleep(self.delay);
            self.inner.verify(handshake_hash, record, login, rhost)
        }
    }

    /// Like [`start_manager`], but listening on every local address, so
    /// 127.0.0.1, 127.0.0.2 and 127.0.0.3 are three roads to one daemon.
    ///
    /// Needs the whole 127.0.0.0/8 on loopback, as Linux has by default; a
    /// host with only 127.0.0.1 configured (macOS without aliases) cannot run
    /// the tests built on it.
    async fn start_manager_on_every_loopback_address(
        backend: Arc<dyn SessionBackend>,
        allowlist: Vec<[u8; 32]>,
        verifier: Option<Arc<dyn AuthVerifier>>,
    ) -> TestServer {
        let server_kp = generate_keypair();
        let server_sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let port = server_sock.local_addr().unwrap().port();
        tokio::spawn(SessionManager::serve(
            server_sock,
            server_kp.private,
            ServerAuth {
                allowlist: Arc::new(Mutex::new(allowlist)),
                verifier,
                server_pub: server_kp.public,
                self_principal: test_self_principal(),
                nonces: Arc::new(TestNonces),
                logins: Arc::new(ForgetNothing),
            },
            BackendFactory(backend),
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
        ));
        TestServer {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            public_key: server_kp.public,
        }
    }

    /// Pump `client` until every road in `roads` answered a check, or `within` passes.
    async fn all_roads_verified(
        client: &mut TestClient,
        roads: &[SocketAddr],
        within: Duration,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let _ = client.try_recv();
            let view = client.conn.roads(Instant::now());
            if roads.iter().all(|a| {
                view.iter()
                    .any(|r| r.addr == *a && r.state == PathState::Verified)
            }) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Checks of two roads sent while the proof is being verified (300 ms),
    /// and a third sent as it lands.
    ///
    /// Wall-clock timing: the 100 ms and 200 ms sleeps here must fall inside
    /// the `SlowVerifier`'s 300 ms, and `all_roads_verified` allows 2 s for
    /// the answers, which is far above a loopback round trip but still a
    /// deadline a badly overloaded machine could miss.
    async fn check_roads_around_the_proof(client: &mut TestClient, port: u16) -> Vec<SocketAddr> {
        client.send(AUTH_STREAM, good_record()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let a = client.server_addr;
        let b = SocketAddr::from(([127, 0, 0, 2], port));
        client.conn.set_paths(vec![a, b]);
        let checks = client.conn.on_timeout(Instant::now());
        send_client(&client.sock, &checks).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let c = SocketAddr::from(([127, 0, 0, 3], port));
        client.conn.set_paths(vec![a, b, c]);
        let checks = client.conn.on_timeout(Instant::now());
        send_client(&client.sock, &checks).await;
        vec![a, b, c]
    }

    /// Spec §4.5 / §9.2 (defect 5), cold create.
    #[tokio::test]
    async fn a_path_check_sent_while_the_proof_is_verified_is_answered() {
        let server = start_manager_on_every_loopback_address(
            Arc::new(EchoBackend),
            Vec::new(),
            Some(Arc::new(SlowVerifier::accepting_good(
                Duration::from_millis(300),
            ))),
        )
        .await;
        let mut client = TestClient::new(
            &server,
            [7u8; 16],
            StartKind::Cold,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        client.handshake().await;
        let roads = check_roads_around_the_proof(&mut client, server.addr.port()).await;
        assert!(
            all_roads_verified(&mut client, &roads, Duration::from_secs(2)).await,
            "every check was answered: {:?}",
            client.conn.roads(Instant::now())
        );
    }

    /// Spec §4.5 / §9.2 (defect 5), warm reattach onto a running backend.
    #[tokio::test]
    async fn a_path_check_sent_while_a_reattach_proof_is_verified_is_answered() {
        let token = [8u8; 16];
        let owner_kp = generate_keypair();
        let server = start_manager_on_every_loopback_address(
            Arc::new(EchoBackend),
            vec![owner_kp.public],
            Some(Arc::new(SlowVerifier::accepting_good(
                Duration::from_millis(300),
            ))),
        )
        .await;
        let mut owner = TestClient::new(
            &server,
            token,
            StartKind::Cold,
            AuthMethod::Allowlist,
            owner_kp.private,
        )
        .await;
        owner.handshake().await;
        owner.send(0, b"up".to_vec()).await;
        assert_eq!(owner.recv_stream0(Duration::from_secs(2)).await, b"up");

        let mut newcomer = TestClient::new(
            &server,
            token,
            StartKind::Warm,
            AuthMethod::SshSignature,
            generate_keypair().private,
        )
        .await;
        newcomer.handshake().await;
        let roads = check_roads_around_the_proof(&mut newcomer, server.addr.port()).await;
        assert!(
            all_roads_verified(&mut newcomer, &roads, Duration::from_secs(2)).await,
            "every check was answered: {:?}",
            newcomer.conn.roads(Instant::now())
        );
    }

    /// Review focus: a queue emptied for a warm reattach and rebuilt into a
    /// fresh route (the bridge ended as the `Attach` went out) keeps its order.
    #[test]
    fn a_drained_route_rebuilt_as_a_fresh_one_keeps_its_order() {
        let (tx, rx) = dgram_queue();
        let from: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for i in 0..5u8 {
            assert!(tx.send(from, vec![i]), "the route takes it");
        }
        let queued = ProvisionalRoute { tx, rx }.drain();
        assert_eq!(queued.len(), 5);
        let mut rebuilt = ProvisionalRoute::prefilled(queued);
        for i in 0..5u8 {
            assert_eq!(rebuilt.rx.try_recv().unwrap(), (from, vec![i]));
        }
        assert!(rebuilt.rx.try_recv().is_none(), "nothing else in it");
    }

    /// A real client and the server connection `accept` made for it, plus
    /// the msg2 datagrams that make the client `Live`.
    fn accepted_connection(
        server_kp: &crate::handshake::Keypair,
        token: [u8; 16],
        peer: SocketAddr,
    ) -> (Connection, Connection, Vec<Datagram>) {
        accepted_connection_with(server_kp, token, peer, crate::Features::SUPPORTED)
    }

    /// The same, with both ends offering and allowing `features`.
    pub(super) fn accepted_connection_with(
        server_kp: &crate::handshake::Keypair,
        token: [u8; 16],
        peer: SocketAddr,
        features: crate::Features,
    ) -> (Connection, Connection, Vec<Datagram>) {
        let client_kp = generate_keypair();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: features,
            start_kind: StartKind::Warm,
            token,
            method: AuthMethod::Allowlist,
        });
        let msg1 = client.start_with_payload(Instant::now(), peer, &payload);
        let Frame::Handshake {
            body: msg1_body, ..
        } = parse(&msg1[0].bytes).expect("a client's first datagram is a valid frame")
        else {
            panic!("a client's first datagram is a handshake");
        };
        let mut resolve = |_: &Msg1Payload| {
            Some(Msg2Inputs {
                resumed: true,
                nonce: [0u8; AUTH_NONCE_LEN],
            })
        };
        let outcome = Connection::accept(
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            },
            Instant::now(),
            peer,
            msg1_body,
            &mut resolve,
        );
        let AcceptOutcome::Accepted { conn, out, .. } = outcome else {
            panic!("the handshake this test builds must be accepted");
        };
        (client, conn, out)
    }

    /// A backend that hands every stream byte it hears to the test.
    struct ForwardingBackend(mpsc::UnboundedSender<Vec<u8>>);

    impl SessionBackend for ForwardingBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let tx = self.0.clone();
            Box::pin(async move {
                while let Some(ev) = io.recv().await {
                    if let SessionInbound::Data(sd) = ev {
                        let _ = tx.send(sd.data);
                    }
                }
            })
        }
    }

    /// Review of Task 7 (spec §4.5): after a warm reattach the manager sends
    /// `Attach` and only then routes the new connection's datagrams into the
    /// bridge's stable route, so when the bridge wakes both can be ready at
    /// once. The `Attach` must be taken first: a datagram of the new session
    /// fed to the connection being replaced is dropped (wrong `session_id`).
    /// Twenty fresh bridges, each woken with both ready: an unordered
    /// `select!` loses about half of them.
    #[tokio::test]
    async fn a_datagram_routed_right_after_an_attach_reaches_the_new_connection() {
        for round in 0..20u8 {
            let server_kp = generate_keypair();
            let token = [round; 16];
            let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
            let (_old_client, old_conn, _) = accepted_connection(&server_kp, token, peer);
            let (mut new_client, new_conn, msg2) = accepted_connection(&server_kp, token, peer);
            let _ = new_client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
            assert_ne!(old_conn.session_id(), new_conn.session_id());

            let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
            let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
            let (dg_tx, dg_rx) = dgram_queue();
            let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
            let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
            let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            tokio::spawn(run_backend_bridge(BridgeSpawn {
                socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                conn: old_conn,
                channels: BridgeChannels {
                    dgram_rx: dg_rx,
                    io_inbound_tx: in_tx,
                    backend_out_rx: out_rx,
                    control_rx: ctl_rx,
                    done_tx,
                },
                token,
                backend: Arc::new(ForwardingBackend(heard_tx)),
                io: SessionIo {
                    resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                    inbound: in_rx,
                    outbound: out_tx,
                    principal: test_principal(),
                    login: token,
                    gates: Arc::new(GateTable::new()),
                },
                start: BridgeStart::default(),
                active_count: Arc::new(AtomicUsize::new(0)),
                gates: Arc::new(GateTable::new()),
            }));
            // Let the bridge settle into its wait.
            tokio::time::sleep(Duration::from_millis(5)).await;

            let typed = new_client.send(Instant::now(), 0, b"typed");
            // No await between the two: the bridge wakes with both ready,
            // in the order the manager produces them.
            ctl_tx
                .send(BridgeControl::Attach(
                    Box::new(new_conn),
                    Vec::new(),
                    Vec::new(),
                ))
                .map_err(|_| "the bridge is listening")
                .unwrap();
            for dg in &typed {
                assert!(dg_tx.send(peer, dg.bytes.clone()), "the route takes it");
            }
            let heard = tokio::time::timeout(Duration::from_secs(1), heard_rx.recv())
                .await
                .ok()
                .flatten();
            assert_eq!(
                heard.as_deref(),
                Some(&b"typed"[..]),
                "round {round}: the new connection never saw its datagram"
            );
        }
    }

    /// Re-review of Task 7: on the daemon's multi-thread runtime `biased;`
    /// orders the polls, not the arrivals -- the bridge can find the control
    /// channel empty, then the manager (on another worker) sends `Attach`,
    /// re-homes the route and routes a datagram of the new session, and the
    /// bridge's inner `select!` takes that datagram. The datagram arm must
    /// therefore take any pending `Attach` before the datagram: the
    /// datagram's send happened after the `Attach`'s, so once the datagram
    /// is received a `try_recv` is guaranteed to see the `Attach`. Driven on
    /// the arm directly, since no scheduler interleaving can be forced.
    #[tokio::test]
    async fn the_datagram_arm_takes_a_pending_attach_first() {
        let server_kp = generate_keypair();
        let token = [7u8; 16];
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (_old_client, mut conn, _) = accepted_connection(&server_kp, token, peer);
        let (mut new_client, new_conn, msg2) = accepted_connection(&server_kp, token, peer);
        let _ = new_client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        let new_id = new_conn.session_id();
        assert_ne!(conn.session_id(), new_id);
        let _ = conn.poll_events();

        let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (in_tx, mut in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let mut link = BackendLink::new(in_tx, Consumption::OnDelivery);
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(new_conn),
                Vec::new(),
                Vec::new(),
            ))
            .map_err(|_| "the receiver is here")
            .unwrap();
        let typed = new_client.send(Instant::now(), 0, b"typed");
        assert_eq!(typed.len(), 1);

        let mut parked = true; // an Attach also revives a parked bridge
        let mut out = Vec::new();
        let mut classes = BTreeMap::new();
        classes.insert(14u8, StreamClass::Bulk);
        on_routed_datagram(
            &mut conn,
            &mut parked,
            &mut ctl_rx,
            &mut link,
            &classes,
            Instant::now(),
            peer,
            &typed[0].bytes,
            &mut out,
        );

        assert_eq!(conn.session_id(), new_id, "the Attach was applied");
        assert_eq!(
            conn.stream_class(14),
            StreamClass::Bulk,
            "the Attach taken on the datagram arm declares the classes again too"
        );
        assert!(!parked);
        assert!(matches!(
            in_rx.try_recv(),
            Ok(SessionInbound::ResumeReset(_))
        ));
        let data: Vec<u8> = conn
            .poll_events()
            .into_iter()
            .filter_map(|ev| match ev {
                Event::StreamData { stream_id: 0, data } => Some(data),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(data, b"typed", "the new connection took the datagram");
        assert!(ctl_rx.try_recv().is_err(), "the Attach was taken once");
    }

    /// Review round 1, Important 1: two `Attach`es taken back to back in one
    /// `on_routed_datagram` call (see `the_datagram_arm_takes_a_pending_attach_first`)
    /// must not carry bytes the backend was never handed. Connection B is
    /// attached with 1000 bytes of stream 20 QUEUED on it -- run through
    /// `conn.on_datagram` inside `apply_control`, which queues them as a
    /// `StreamData` event on B WITHOUT draining it. Connection C's `Attach`
    /// is taken in the very same `try_recv` loop right after, before
    /// anything ever polls B's events, so B's queued bytes are never handed
    /// to the backend. `carry` used to read the replaced connection's own
    /// `unconsumed_streams()`, which still counted them: the old code
    /// carried 1000 phantom bytes into `owed_old` and `pay` silently ate
    /// them out of C's own, real 3000-byte hand-over, leaving C's stream
    /// short by 1000 forever. The fixed `carry` reads only what THIS
    /// ledger actually handed its backend and never reported -- zero here,
    /// since B's queued bytes were never drained to it.
    #[tokio::test]
    async fn two_attaches_taken_back_to_back_do_not_carry_bytes_the_backend_never_saw() {
        let server_kp = generate_keypair();
        let token = [11u8; 16];
        let peer: SocketAddr = "127.0.0.1:11".parse().unwrap();

        // The bridge's placeholder connection before either Attach lands.
        let (_placeholder_client, mut conn, _) = accepted_connection(&server_kp, token, peer);

        // Connection B: 1000 bytes of stream 20 QUEUED on its Attach --
        // never drained, because C's Attach is taken right after it.
        let (mut client_b, conn_b, msg2_b) = accepted_connection(&server_kp, token, peer);
        let _ = client_b.on_datagram(Instant::now(), peer, &msg2_b[0].bytes);
        let b_queued: Vec<(SocketAddr, Vec<u8>)> = client_b
            .send(Instant::now(), 20, &[1u8; 1000])
            .into_iter()
            .map(|dg| (peer, dg.bytes))
            .collect();
        assert!(
            !b_queued.is_empty(),
            "the send produced at least one datagram"
        );

        // Connection C: attached clean. Its own 3000 bytes of stream 20
        // arrive as the ordinary routed datagram(s) right after both
        // Attaches -- the first one takes the control-drain, the rest (if
        // 3000 bytes fragments) go straight to `conn` the way the bridge's
        // main loop would feed a second datagram of the same turn.
        let (mut client_c, conn_c, msg2_c) = accepted_connection(&server_kp, token, peer);
        let _ = client_c.on_datagram(Instant::now(), peer, &msg2_c[0].bytes);
        let c_sent = client_c.send(Instant::now(), 20, &[2u8; 3000]);
        assert!(
            !c_sent.is_empty(),
            "the send produced at least one datagram"
        );

        let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(conn_b),
                Vec::new(),
                b_queued,
            ))
            .map_err(|_| "the receiver is here")
            .unwrap();
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(conn_c),
                Vec::new(),
                Vec::new(),
            ))
            .map_err(|_| "the receiver is here")
            .unwrap();

        let (in_tx, _in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let mut link = BackendLink::new(in_tx, Consumption::OnDelivery);
        let mut parked = true;
        let mut out = Vec::new();
        let now = Instant::now();
        on_routed_datagram(
            &mut conn,
            &mut parked,
            &mut ctl_rx,
            &mut link,
            &BTreeMap::new(),
            now,
            peer,
            &c_sent[0].bytes,
            &mut out,
        );
        for dg in &c_sent[1..] {
            out.extend(conn.on_datagram(now, peer, &dg.bytes));
        }

        // Hands C's 3000 bytes to the (`OnDelivery`) backend, which pays
        // them into `conn`'s own credit as it takes them.
        let mut first_live_sent = false;
        let _ = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);

        assert!(
            conn.unconsumed_streams().is_empty(),
            "C's own 3000 bytes must all credit, nothing phantom taken from them: {:?}",
            conn.unconsumed_streams()
        );

        // The residue must not carry across a LATER reattach either: a
        // clean connection D, attached next, starts with nothing owed.
        let (mut client_d, conn_d, msg2_d) = accepted_connection(&server_kp, token, peer);
        let _ = client_d.on_datagram(Instant::now(), peer, &msg2_d[0].bytes);
        let d_sent = client_d.send(Instant::now(), 20, &[3u8; 500]);
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(conn_d),
                Vec::new(),
                Vec::new(),
            ))
            .map_err(|_| "the receiver is here")
            .unwrap();
        let now = Instant::now();
        on_routed_datagram(
            &mut conn,
            &mut parked,
            &mut ctl_rx,
            &mut link,
            &BTreeMap::new(),
            now,
            peer,
            &d_sent[0].bytes,
            &mut out,
        );
        let _ = drain_events(&mut conn, &mut link, &mut first_live_sent, now, &mut out);
        assert!(
            conn.unconsumed_streams().is_empty(),
            "D's 500 bytes must all credit too, no leftover residue: {:?}",
            conn.unconsumed_streams()
        );
    }

    /// Spec §4.14: the daemon drops a connection whose stream ran out of
    /// offset space WITHOUT a `Close` -- a death, so the bridge parks and the
    /// session and its processes are retained for the client's warm return.
    #[tokio::test]
    async fn a_stream_out_of_offset_space_drops_the_connection_without_a_close() {
        let kp = generate_keypair();
        let mut conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        conn.push_test_event(Event::OffsetSpaceExhausted { stream_id: 16 });
        let (tx, mut rx) = mpsc::channel::<SessionInbound>(4);
        let mut first_live_sent = false;
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut out = Vec::new();
        let kind = drain_events(
            &mut conn,
            &mut link,
            &mut first_live_sent,
            Instant::now(),
            &mut out,
        );
        assert!(
            matches!(kind, CloseKind::Death),
            "a death, not a graceful close"
        );
        assert_eq!(conn.state(), LinkState::Closed);
        assert!(!conn.closed_gracefully());
        assert!(rx.try_recv().is_err(), "the backend is told nothing");
    }

    /// A backend that tells the test which inbound events it heard, by name.
    struct InboundKindsBackend(mpsc::UnboundedSender<&'static str>);

    impl SessionBackend for InboundKindsBackend {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let tx = self.0.clone();
            Box::pin(async move {
                while let Some(ev) = io.recv().await {
                    let kind = match ev {
                        SessionInbound::Data(_) => "data",
                        SessionInbound::Live(_) => "live",
                        SessionInbound::ResumeReset(_) => "resume-reset",
                        SessionInbound::Repaint | SessionInbound::RepaintCutover { .. } => {
                            "repaint"
                        }
                        SessionInbound::Writable { .. } => "writable",
                        SessionInbound::Delivered { .. } => "delivered",
                        SessionInbound::OutputReady { .. } => "output-ready",
                    };
                    let _ = tx.send(kind);
                }
            })
        }
    }

    /// Spec §4.14, end to end at the bridge (legacy mode): a backend's
    /// stream runs out of offset space -> the bridge drops the connection
    /// without a `Close` and parks (the backend keeps running) -> a warm
    /// `Attach` revives it -> the same stream starts again at offset 0 on
    /// the new connection, which a fresh client receiver delivers.
    #[tokio::test]
    async fn an_exhausted_stream_parks_the_session_and_a_warm_return_restarts_it_at_zero() {
        const STREAM: u8 = 16;
        let server_kp = generate_keypair();
        let token = [0x5Au8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut old_client, mut old_conn, old_msg2) =
            accepted_connection_with(&server_kp, token, peer, crate::Features::HEADER_AAD);
        let _ = old_client.on_datagram(Instant::now(), peer, &old_msg2[0].bytes);
        let old_id = old_conn.session_id();
        old_conn.start_stream_at_for_test(STREAM, OFFSET_LIMIT - 10);

        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (_dg_tx, dg_rx) = dgram_queue();
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<&'static str>();
        let backend_out = out_tx.clone();
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn: old_conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend: Arc::new(InboundKindsBackend(heard_tx)),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::new(GateTable::new()),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates: Arc::new(GateTable::new()),
        }));
        let within = Duration::from_secs(2);

        // 11 bytes where 10 fit: refused, reported, the connection abandoned.
        backend_out
            .send(SessionOutbound::Data(StreamData {
                stream_id: STREAM,
                data: vec![1u8; 11],
            }))
            .map_err(|_| "the bridge is listening")
            .unwrap();
        let ended = tokio::time::timeout(within, done_rx.recv())
            .await
            .expect("the bridge reports the connection's end")
            .expect("the bridge is alive");
        assert_eq!(ended.session_id, old_id);
        assert!(!ended.graceful, "a death, so the session is retained");
        // Nothing reached the old client: no `Close`, and no byte past the edge.
        let mut buf = vec![0u8; 65536];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client_sock.recv_from(&mut buf))
                .await
                .is_err(),
            "the peer is not told"
        );

        // The warm return.
        let (mut new_client, new_conn, new_msg2) = accepted_connection(&server_kp, token, peer);
        let _ = new_client.on_datagram(Instant::now(), peer, &new_msg2[0].bytes);
        let _ = new_client.poll_events();
        ctl_tx
            .send(BridgeControl::Attach(
                Box::new(new_conn),
                Vec::new(),
                Vec::new(),
            ))
            .map_err(|_| "the parked bridge is listening")
            .unwrap();
        loop {
            let heard = tokio::time::timeout(within, heard_rx.recv())
                .await
                .expect("the backend hears the reattach")
                .expect("the backend is alive -- it was parked, not ended");
            if heard == "resume-reset" {
                break;
            }
        }

        // The same stream, on the new connection, from offset 0.
        backend_out
            .send(SessionOutbound::Data(StreamData {
                stream_id: STREAM,
                data: b"after".to_vec(),
            }))
            .map_err(|_| "the bridge is listening")
            .unwrap();
        let mut delivered = Vec::new();
        while delivered.is_empty() {
            let (len, src) = tokio::time::timeout(within, client_sock.recv_from(&mut buf))
                .await
                .expect("the new connection sends the stream")
                .unwrap();
            let _ = new_client.on_datagram(Instant::now(), src, &buf[..len]);
            for ev in new_client.poll_events() {
                if let Event::StreamData { stream_id, data } = ev {
                    assert_eq!(stream_id, STREAM);
                    delivered.extend(data);
                }
            }
        }
        assert_eq!(
            delivered, b"after",
            "a receiver starting at 0 delivered it: the offsets restarted"
        );
    }

    /// Spec §4.16: probation's cap on out-of-order data does not follow a
    /// proven connection into its bridge -- `adopt_connection` lifts it --
    /// and the classes the bridge kept are declared on it.
    #[test]
    fn adopting_a_connection_lifts_probations_cap_and_declares_the_classes() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let (mut client, mut conn, msg2) = accepted_connection(&server_kp, [0x61; 16], peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        crate::probation::hold_for_probation(&mut conn);
        let mut classes = BTreeMap::new();
        classes.insert(14u8, StreamClass::Bulk);
        adopt_connection(&mut conn, &classes);
        assert_eq!(conn.stream_class(14), StreamClass::Bulk);
        let frames: Vec<StreamFrame> = (1..=200u32)
            .map(|k| StreamFrame::Data {
                stream_id: 16,
                offset: k * 1024,
                data: vec![1u8; 1024],
            })
            .collect();
        for dg in client.frames_for_test(frames) {
            let _ = conn.on_datagram(Instant::now(), peer, &dg.bytes);
        }
        assert!(conn.undelivered_cost_for_test() > crate::probation::PROBATION_UNDELIVERED_MAX);
        let delivered = client.send(Instant::now(), 17, &[5u8; 100]);
        for dg in delivered {
            let _ = conn.on_datagram(Instant::now(), peer, &dg.bytes);
        }
        let _ = conn.poll_events();
        assert!(
            conn.unconsumed_streams().contains(&(17, 100)),
            "counted explicitly: the bridge says when its backend took them"
        );
        let proof = client.send(Instant::now(), AUTH_STREAM, &[6u8; 50]);
        for dg in proof {
            let _ = conn.on_datagram(Instant::now(), peer, &dg.bytes);
        }
        assert!(!conn
            .unconsumed_streams()
            .iter()
            .any(|(s, _)| *s == AUTH_STREAM));
    }

    /// 200 out-of-order KiB on stream 16, past a hole at 0 -- more than
    /// probation lets a connection keep.
    fn past_a_hole(client: &mut Connection) -> Vec<Datagram> {
        let frames: Vec<StreamFrame> = (1..=200u32)
            .map(|k| StreamFrame::Data {
                stream_id: 16,
                offset: k * 1024,
                data: vec![k as u8; 1024],
            })
            .collect();
        client.frames_for_test(frames)
    }

    /// Spec §4.16: a warm reattach's connection comes out of probation held
    /// to its cap; `apply_control` lifts it before the datagrams queued
    /// while its proof was checked go through it.
    #[tokio::test]
    async fn a_warm_attach_lifts_probations_cap_before_its_queued_datagrams() {
        let server_kp = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let (mut client, mut new_conn, msg2) = accepted_connection(&server_kp, [0x63; 16], peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        crate::probation::hold_for_probation(&mut new_conn);
        let queued = past_a_hole(&mut client)
            .into_iter()
            .map(|dg| (peer, dg.bytes))
            .collect();
        let mut conn = a_quiet_server_connection();
        let mut parked = false;
        let (tx, _rx) = mpsc::channel::<SessionInbound>(4);
        let mut link = BackendLink::new(tx, Consumption::OnDelivery);
        let mut out = Vec::new();
        apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            BridgeControl::Attach(Box::new(new_conn), Vec::new(), queued),
            &BTreeMap::new(),
            Instant::now(),
            &mut out,
        );
        assert!(conn.undelivered_cost_for_test() > crate::probation::PROBATION_UNDELIVERED_MAX);
    }

    /// Spec §4.16 end to end at the bridge: the connection a bridge starts
    /// with, still held to probation's cap, is let go -- every out-of-order
    /// byte past 64 KiB is kept, and all of it reaches the backend once the
    /// hole is filled.
    #[tokio::test]
    async fn a_bridge_lifts_probations_cap_off_the_connection_it_starts_with() {
        let server_kp = generate_keypair();
        let token = [0x62u8; 16];
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = client_sock.local_addr().unwrap();
        let (mut client, mut conn, msg2) = accepted_connection(&server_kp, token, peer);
        let _ = client.on_datagram(Instant::now(), peer, &msg2[0].bytes);
        crate::probation::hold_for_probation(&mut conn);

        let (heard_tx, mut heard_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (in_tx, in_rx) = mpsc::channel::<SessionInbound>(INBOUND_CAP);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<SessionOutbound>();
        let (dg_tx, dg_rx) = dgram_queue();
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel::<BridgeControl>();
        let (done_tx, _done_rx) = mpsc::unbounded_channel::<SessionEnded>();
        let gates = Arc::new(GateTable::new());
        tokio::spawn(run_backend_bridge(BridgeSpawn {
            socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
            conn,
            channels: BridgeChannels {
                dgram_rx: dg_rx,
                io_inbound_tx: in_tx,
                backend_out_rx: out_rx,
                control_rx: ctl_rx,
                done_tx,
            },
            token,
            backend: Arc::new(ForwardingBackend(heard_tx)),
            io: SessionIo {
                resume_snapshots: channel_bridge::SnapshotMailbox::default(),
                inbound: in_rx,
                outbound: out_tx,
                principal: test_principal(),
                login: token,
                gates: Arc::clone(&gates),
            },
            start: BridgeStart::default(),
            active_count: Arc::new(AtomicUsize::new(0)),
            gates,
        }));

        let mut datagrams = past_a_hole(&mut client);
        datagrams.extend(client.frames_for_test(vec![StreamFrame::Data {
            stream_id: 16,
            offset: 0,
            data: vec![0u8; 1024],
        }]));
        for dg in datagrams {
            assert!(dg_tx.send(peer, dg.bytes), "the bridge is listening");
        }
        let mut heard = 0usize;
        tokio::time::timeout(Duration::from_secs(5), async {
            while heard < 201 * 1024 {
                heard += heard_rx.recv().await.expect("the backend is alive").len();
            }
        })
        .await
        .unwrap_or_else(|_| panic!("every byte, those past 64 KiB included: {heard} heard"));
        assert_eq!(heard, 201 * 1024);
    }
}
