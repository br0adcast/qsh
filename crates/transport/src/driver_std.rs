//! Client driver on top of the sans-IO `Connection` core: a dedicated thread
//! owning a blocking `std::net::UdpSocket` and the client `Connection`.
//!
//! The `conn` module does no I/O; this driver adds the real network, timers,
//! and handshake retransmit. It exposes plain Rust traits to the outside
//! (`ClientEvents`, `Binder`).
//!
//! Design. The driver waits for UDP readability, explicit producer notification,
//! or its nearest core/handshake/statistics deadline. Commands and authentication
//! results are enqueued before waking the current or following wait. Readiness
//! is only a hint: a bounded nonblocking receive pass restores blocking mode
//! before any send, preserving the existing UDP send/error/retry behavior.
//! Kernel-blocked sends and blocked caller callbacks remain existing limitations;
//! this wait change does not introduce a second transmit queue. Timers run after
//! every bounded turn, including notification and busy socket turns.
//!
//! Handshake retransmit. During the `Connecting` phase the core returns
//! `next_timeout() == None` (it has nothing to wait for until transport keys
//! appear), so the msg1 retransmit timer is driven by the driver itself. If
//! `HANDSHAKE_RETRANSMIT` elapses without reaching `Live`, the driver
//! RE-SENDS THE STORED FIRST msg1 datagram(s) VERBATIM -- it does NOT rebuild
//! the initiator. The connection keeps that msg1
//! (`Connection::retransmit_handshake`) and, when a daemon under load
//! answered it with a cookie (spec §4.16), puts the same bytes behind the
//! cookie: at once, and then on every other retransmit, beginning with the
//! next, the plain msg1 taking the turns between -- so that a cookie from a
//! party on the path cannot keep the msg1 from a daemon built before
//! cookies.
//! `Connection::start_session` mints a FRESH Noise ephemeral every call (see
//! `Handshake::new_initiator`), so re-calling it would emit a DIFFERENT msg1
//! body each period; the server's idempotent `ResendMsg2` path keys on a
//! BYTE-IDENTICAL msg1 body, so a re-minted retransmit would miss it and
//! instead take `ColdReplace`/`WarmReattach`, churning the per-session
//! backend under handshake loss. Storing the first datagram(s) fixes the
//! client's ephemeral for the whole handshake (standard behavior), making
//! every retransmit byte-identical and therefore truly idempotent on the
//! server -- the daemon takes a cookie off before it compares. Retransmit
//! stops once `Live` or `Closed` is reached on the single-endpoint API.
//!
//! Shared recovery. `connect_recovery_with` gives that same initiator the
//! full endpoint catalog. The recovery scheduler limits ordinary and immediate
//! cookie sends together, retaining endpoint-local cookies and acknowledging
//! each actual socket send. Only a successfully contacted source can consume
//! msg2, and the selected source becomes the peer before queued output or proof
//! can leave. Other endpoints keep receiving the unchanged msg1 while admission
//! is unresolved; their late msg2 cannot start another proof. AuthAccepted,
//! cancellation or closure retires scheduling. Sweep completion and selection
//! turnover belong to the recovery owner, not to the driver's Live event.
//!
//! Graceful stop vs. detach. `StdClient::close` emits the
//! client's `Close` frame (`Connection::close`) and flushes it to the socket
//! before the loop exits, so the server tears the backend down immediately
//! instead of retaining it for a warm reconnect -- this is what a
//! user-initiated disconnect uses. `StdClient::detach`
//! ends the loop WITHOUT calling `Connection::close`: no further datagram
//! goes out at all, so the server just sees silence and treats it exactly
//! like any other liveness-timeout death -- it RETAINS the backend for a
//! later warm reattach. This is what the app's own internal forced reconnect
//! uses, so a follow-up reconnect gets a warm reattach (echo-ack/prediction
//! state survives) instead of degenerating into a cold create. Detach is
//! STICKY: close/detach use an independent atomic signal, checked before
//! every bounded command turn. Once detach has been requested, the command
//! channel later disconnecting (the client handle dropped without an explicit call)
//! can never resurrect a graceful `Close` -- see the `graceful` flag in
//! `run_driver`.
//!
//! Authentication proof. When `connect` is given a `signer`, the moment the
//! handshake finishes (`Event::HandshakeDone`) the driver captures this
//! session's handshake hash AND its `server_nonce()` (`None` from a server
//! too old to send one) and hands both to a short-lived, detached thread --
//! it never calls `AuthSigner::sign` inline. The driver thread is the only
//! thing pumping this connection (ACKs, keepalives, retransmit), and a signer
//! can block for a long time: `AgentSigner` talks to a Unix socket with no
//! read timeout by design, and a signer backed by a hardware key waits on a
//! human touch, which is seconds -- blocking the driver thread for that would
//! kill the very connection it is trying to authenticate. `Connection` itself
//! is touched only here, on the driver thread, for exactly that reason --
//! the signing thread never reaches into it.
//!
//! The signing thread reports back over a channel OF ITS OWN (`auth_tx`/
//! `auth_rx`, created inside `run_driver`), tagged with a generation counter
//! the driver bumps on every `HandshakeDone` -- NOT over the external command
//! channel (`tx`/`rx`) `StdClient` hands the caller. That channel's
//! `Receiver::try_recv` reports `Disconnected` only once every `Sender` clone
//! is gone, and `StdClient` dropped without `close`/`detach` is exactly that:
//! its own `Sender` is the only thing keeping `rx` alive, and the implicit-
//! drop arm in the command loop below depends on losing it. A driver-held
//! clone of the SAME sender -- which is what handing `tx.clone()` to the
//! signing thread would be -- would keep that channel connected for the
//! entire life of the driver regardless of what the caller does, silently
//! disabling that teardown path. The auth-result channel is private to
//! `run_driver` precisely so its own liveness can never affect `rx`'s.
//!
//! `HandshakeDone` fires at most once per `Connection` today (a live client
//! connection has no re-handshake path -- roaming reuses the same transport
//! keys and surfaces as `Rehomed`, not a fresh handshake; a warm reconnect at
//! the `StdClient` level instead builds a brand new `Connection` and signs
//! its new hash from scratch), so in practice the generation counter never
//! actually has to tell two live rounds apart -- the equality check at its
//! only call site is unreachable dead-code insurance today, not live logic.
//! But a signature made for a handshake hash that a newer handshake has since
//! replaced is WORSE than no signature at all -- it fails verification and
//! the server refuses the session outright (`probation::AuthGate`) -- so the
//! driver checks the generation before acting on a result and drops anything
//! the counter has already moved past, on the off chance a re-handshake is
//! ever added to this driver.
//!
//! The record is queued via `Connection::send` exactly like an ordinary
//! outbound write, on `AUTH_STREAM`, as soon as the driver dequeues the
//! signing thread's result -- which is at the START of some LATER loop
//! iteration, never the one that completed the handshake: `on_handshake_resp`
//! pushes `HandshakeDone`, flips state to `Live`, and flushes every stream's
//! sender (so anything the caller already queued goes out) all inside the
//! SAME `on_datagram` call, and only after that datagram batch is sent does
//! the driver poll events and spawn the signing thread. So anything the
//! caller queued before the handshake completed is on the wire STRICTLY
//! AHEAD of the proof, ALWAYS, not just occasionally -- and even with an
//! instantaneous signer, the record itself can only leave on the loop
//! iteration after signing finishes at the earliest. The signing result wakes
//! the current or next readiness wait without waiting for unrelated UDP input.
//!
//! It is a DELIBERATE choice not to hold the caller's own writes back while a
//! signer is still working, for exactly the reason above: doing so would
//! serialize user output behind a possibly multi-second wait for a hardware
//! touch, trading a connection-level stall this design exists to avoid for a
//! UX-level one in its place. The server's probation stage already buffers a
//! bounded amount of pre-proof stream data and replays it, in order, once the
//! record verifies (see `probation::BridgeStart`) -- but the bound is real:
//! crossing it (`EARLY_DATA_MAX`, 64 KiB) REFUSES THE ENTIRE CONNECTION
//! outright rather than merely dropping the excess. So a fast signer costs
//! nothing beyond the ordinary case, but a slow one racing more than 64 KiB
//! of pre-proof output is fatal, not just buffered.
//!
//! A signing failure (a wrong passphrase, no agent, a refused touch) is not
//! retried -- nothing about the session changes by trying again -- so the
//! driver reports `on_state(Closed)` and tears down locally, exactly like
//! `detach` (no `Close` frame: there is nothing left worth saying). Without
//! this the caller would just watch the socket go silent for `AUTH_DEADLINE`
//! with no indication why. The reason itself goes to the `log` crate (an
//! `error` record), since neither the wire-level `AuthRecord` nor
//! `ClientEvents` has room for a diagnostic string -- on a host that has
//! installed no logger, that reason is simply not
//! visible anywhere.

#[path = "driver_std_wait.rs"]
mod wait;

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use crate::auth::{encode_auth_record, AuthSigner, AUTH_NONCE_LEN, AUTH_STREAM};
use crate::client_input_budget::ClientInputBudget;
use crate::client_input_queue::{DriverConnection, InputQueue, InputRecord, INPUT_TURN};
use crate::conn::{
    Connection, ConnectionConfig, Consumption, Datagram, Event, LinkState, Stats, StreamClass,
    StreamProgress, UseRoadError,
};
use crate::features::Features;
use crate::handshake_payload::StartKind;
use crate::paths::RoadInfo;
use crate::recovery_handshake::RecoveryEndpoint;
use crate::send_gate::{ClientAdmission, GateKind, GateTable, GateWait};
use crate::udp_buffers::{tune_udp_buffers, BufferReport};

/// Retransmit period for the handshake message until `Live` is established.
pub(crate) const HANDSHAKE_RETRANSMIT: Duration = Duration::from_millis(500);

/// Lateness beyond the requested readiness deadline that suggests a thread
/// freeze. Statistics always bound intended idle waits to one second. Resume
/// transactionally replaces the socket and restarts ping/liveness; monotonic
/// suspend behavior still depends on the platform, as before.
const FREEZE_RESUME_AFTER: Duration = Duration::from_secs(5);

/// Receive buffer size for a single UDP datagram.
const RECV_BUF_LEN: usize = 64 * 1024;

/// How many datagrams one readable pass takes before running timers and
/// handing out events (spec §4.1):
/// fewer passes and callbacks under a flood, and still no longer than about a
/// millisecond before the next look at the command queue (keystrokes).
const READY_DRAIN_MAX: usize = 64;

/// How stale a published report is ever allowed to be.
///
/// Statistics go out on change, which is not enough on its own: what the
/// caller reads alongside them -- the road in use and the whole road table
/// (`roads_out`) -- is refreshed in the same breath, and a road going quiet
/// moves no counter in [`Stats`] at all. Without a floor, a screen showing
/// the roads would keep calling a dead one verified until some unrelated
/// number happened to move.
///
/// One second, because that is the resolution of the coarsest thing on that
/// screen: `Stats::silent_secs` counts whole seconds.
const STATS_HEARTBEAT: Duration = Duration::from_secs(1);

/// How long `StdClient::stream_progress` waits for the driver to answer:
/// a bounded response deadline even if the owner or OS stalls.
const PROGRESS_REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// How long `StdClient::use_road` waits for the driver to act on the request: the same bound
/// as `PROGRESS_REPLY_TIMEOUT`, for the same reason.
const USE_ROAD_REPLY_TIMEOUT: Duration = PROGRESS_REPLY_TIMEOUT;

/// Whether to publish statistics now. Pure, so the rule is checked without a
/// socket: on change, and once every [`STATS_HEARTBEAT`] regardless.
fn stats_are_due(cur: Stats, last: Stats, since_last_publish: Duration) -> bool {
    cur != last || since_last_publish >= STATS_HEARTBEAT
}

fn next_wait_deadline(
    now: Instant,
    core: Option<Instant>,
    handshake: Option<Instant>,
    last_stats: Instant,
    continuation: bool,
) -> Instant {
    let mut deadline = last_stats + STATS_HEARTBEAT;
    for candidate in [core, handshake].into_iter().flatten() {
        deadline = deadline.min(candidate);
    }
    if continuation {
        deadline = deadline.min(now);
    }
    deadline
}

fn freeze_late(requested_deadline: Instant, wait_started: Instant, now: Instant) -> bool {
    // An already overdue core timer is work to service, not time asleep.
    now.saturating_duration_since(requested_deadline.max(wait_started)) > FREEZE_RESUME_AFTER
}

/// Incremental facts for the owner of one shared recovery attempt. No event
/// itself authorizes SSH or proves committed authentication acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryProgress {
    Sent {
        endpoint: SocketAddr,
        at: Instant,
        success: bool,
    },
    /// The initiator was consumed by an authenticated Noise response, even if
    /// payload validation subsequently rejects it. This is not AuthAccepted.
    Selected { endpoint: SocketAddr, at: Instant },
}

/// External client callbacks implemented by the caller.
pub trait ClientEvents: Send + Sync {
    /// Freshly delivered in-order bytes of stream `stream_id`.
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>);
    /// Link state change.
    fn on_state(&self, state: LinkState);
    /// Updated statistics (sent only when changed).
    fn on_stats(&self, stats: Stats);
    /// The peer reset stream `stream_id` after dropping its backlog: clear any
    /// partial render state; a repaint follows.
    fn on_reset(&self, stream_id: u8);
    /// What the handshake agreed (spec §5.5), once per handshake, before
    /// `Live` reaches `on_state`. The default takes no notice.
    fn on_features(&self, _features: Features) {}
    /// A bounded authenticated protocol failure, delivered before Closed.
    fn on_protocol_failure(&self, _failure: crate::ProtocolFailure) {}
    /// Authenticated terminal peer failure, delivered before Closed.
    fn on_session_aborted(&self, _reason: crate::SessionAbortReason) {}
    /// Accepted local input could not reach the transport. Delivered before
    /// Closed; the owner must report failure, never silently replay the input.
    fn on_input_failure(&self, failure: InputFailure);
    /// Committed server admission for this exact active transport.
    fn on_auth_accepted(&self, _accepted: crate::AuthAcceptance) {}
    /// Actual shared-handshake sends and consumed-source selection. The owner
    /// stamps these with its immutable attempt identity; legacy connects emit none.
    fn on_recovery_progress(&self, _progress: RecoveryProgress) {}
    /// The OS refused to send a datagram to `to`: its kind and its own
    /// words (e.g. `No route to host (os error 65)`). Called once per change
    /// of the error, not on every retransmit that fails the same way; the
    /// latest one is also kept for `StdClient::last_send_error`. The default
    /// takes no notice.
    fn on_send_error(&self, _to: SocketAddr, _kind: std::io::ErrorKind, _text: &str) {}
}

/// A send the OS refused: the kind of error and the OS's own words.
pub type SendFailure = (std::io::ErrorKind, String);

/// Binds a freshly created socket to a network before the driver uses it.
/// There is no `connect` for it to come before: this driver's socket is
/// deliberately left unconnected, so that an answer arriving over a spare
/// road reaches it at all (see `make_socket`).
///
/// The return value indicates whether network binding succeeded (the
/// driver proceeds either way -- binding is best-effort, no guarantee:
/// `false` means it will run over the default route).
pub trait Binder: Send + Sync {
    fn bind(&self, fd: i32) -> bool;
}

/// What became of a request to move the session onto one of its roads (`StdClient::use_road`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseRoadOutcome {
    /// The traffic now goes down the chosen road.
    Moved,
    /// It already did; nothing changed.
    AlreadyInUse,
    /// The road has not answered its last check.
    NotAnswering,
    /// The address is not one of the roads handed to `set_paths`.
    UnknownRoad,
    /// No session to move: the driver is gone, did not answer in time, or has no session.
    NoSession,
}

/// Why a bounded send queued nothing (`StdClient::send_bytes_bounded`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendBlocked {
    /// The stream's gate stayed shut for the whole wait: the peer has not
    /// acknowledged enough yet. Worth trying again.
    Full,
    /// The driver has ended -- however it ended, a panic in a callback on its
    /// thread included -- or there never was one (`StdClient::dead`). Nothing
    /// sent through this client goes anywhere any more; see
    /// `StdClient::is_gone`.
    Gone,
    /// Called from the driver thread itself (a `ClientEvents` callback),
    /// which would be waiting for itself to open the gate.
    OnDriverThread,
}

/// A terminal local failure discovered after whole-record admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputFailure {
    /// Accepted input cannot be serviced because the local wait/socket owner failed.
    DriverUnavailable,
    OffsetSpaceExhausted {
        stream_id: u8,
    },
}

/// A whole owned record that was not accepted. No bytes were queued or
/// partially appended; callers may retry or report an explicit failure.
#[derive(Debug, PartialEq, Eq)]
pub struct SendRejected {
    pub reason: SendBlocked,
    pub data: Vec<u8>,
}

/// A command to the driver thread.
enum Command {
    #[cfg(test)]
    UnconsumedForTest(Sender<Vec<(u8, u64)>>),
    Send {
        stream_id: u8,
        record: InputRecord,
    },
    Rebind,
    /// How long to tolerate silence before declaring the link dead. A command
    /// rather than a field of `ConnectionConfig` because the connection lives
    /// on the driver thread and every other setting reaches it the same way.
    SetDeathAfter(std::time::Duration),
    /// The roads this session may use, as the owner knows them. Reaches the
    /// connection the same way every other setting does: it lives on the
    /// driver thread.
    SetPaths(Vec<SocketAddr>),
    /// How far a stream has got. The connection lives on the driver thread,
    /// so the answer comes back on `reply`.
    StreamProgress {
        stream_id: u8,
        reply: Sender<StreamProgress>,
    },
    /// Move the session onto `addr` by hand (see `Connection::use_road`). The connection lives
    /// on the driver thread, so the outcome comes back on `reply`.
    UseRoad {
        addr: SocketAddr,
        reply: Sender<UseRoadOutcome>,
    },
    /// The class of a stream (spec §4.8), for the connection on the driver
    /// thread.
    SetStreamClass {
        stream_id: u8,
        class: StreamClass,
    },
    /// The owner took `n` bytes of a stream counted explicitly (see
    /// `StdClient::consumed`).
    Consumed {
        stream_id: u8,
        n: usize,
    },
}

/// A signing thread's result, delivered over its own private channel (see the
/// module doc's "Authentication proof" section) -- NEVER over the external
/// command channel above, so that channel's `Disconnected` semantics stay
/// tied only to the caller's own `Sender`. `generation` is checked against
/// the driver's own counter before the result is acted on, so a signature
/// superseded by a newer handshake is recognized as stale and dropped.
/// `record` is `None` when `AuthSigner::sign` failed outright.
struct AuthResult {
    generation: u64,
    record: Option<Vec<u8>>,
}

/// What a client's connection is told before its first datagram
/// (`StdClient::connect_with`): settings that must be in force before any
/// byte can arrive, which a command sent after `connect` returns cannot
/// promise -- the driver thread may already be reading.
#[derive(Clone, Debug, Default)]
pub struct DriverSetup {
    #[cfg(test)]
    pub(crate) wait_control: Option<Arc<wait::TestControl>>,
    /// How the streams nobody declared count their consumption (spec
    /// §4.10.1): `OnDelivery` for the app, `Explicit` for the console
    /// client (spec §4.13). AUTH_STREAM is always consumed by the driver.
    pub default_consumption: Consumption,
    /// Per-stream declarations, applied after the default.
    pub stream_consumption: Vec<(u8, Consumption)>,
    /// Share this invocation budget across replacement/retired drivers.
    /// None creates an independent default budget for this client.
    pub input_budget: Option<ClientInputBudget>,
}

#[derive(Default)]
struct RoadSnapshot {
    roads: Vec<RoadInfo>,
    probes: Vec<(SocketAddr, Instant)>,
}

/// Handle to the client driver. Owns the command channel to the thread, the
/// shared latest statistics, and the thread handle. All methods take `&self`,
/// so the type can be shared through `Arc`.
pub struct StdClient {
    tx: Mutex<wait::WakeSender<Command>>,
    wake: Arc<wait::Notifier>,
    input_budget: ClientInputBudget,
    stop: Arc<AtomicU8>,
    stats: Arc<Mutex<Stats>>,
    /// What the server answered about this handshake: whether it landed on
    /// the session named by the token, or on a fresh one. Set on the driver
    /// thread when the handshake completes; read by the owner afterwards --
    /// which is why it is shared and atomic rather than returned.
    resumed: Arc<AtomicBool>,
    /// Whether the connection ended with a `Close` frame (sent or received)
    /// rather than by death or abandonment. Set on the driver thread before
    /// `Closed` is dispatched; shared for the same reason `resumed` is.
    closed_gracefully: Arc<AtomicBool>,
    /// What the handshake agreed (spec §5.5), published by the driver thread
    /// when it completes; `None` before that. Shared for the same reason
    /// `resumed` is.
    features: Arc<Mutex<Option<Features>>>,
    /// The road the traffic is going down, shared with the driver thread
    /// because only that thread may touch the connection.
    active_path: Arc<Mutex<Option<SocketAddr>>>,
    /// The roads as the driver last published them. Shared for the same
    /// reason `active_path` is: only the driver thread may touch the
    /// connection.
    roads: Arc<Mutex<RoadSnapshot>>,
    /// The send gates of bounded producers (spec §4.7.3), refreshed by the
    /// driver thread after every pass and closed when it ends.
    gates: Arc<GateTable>,
    /// What the OS granted the current socket (spec §4.12), published by the
    /// driver thread whenever it makes one; `None` before the first.
    socket_buffers: Arc<Mutex<Option<BufferReport>>>,
    /// Whether the latest send failed, and how (see
    /// [`StdClient::last_send_error`]). Shared for the same reason `resumed`
    /// is.
    last_send_error: Arc<Mutex<Option<SendFailure>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// Id of the driver thread (`None` for `dead`). Needed by `close` so it
    /// doesn't try to join itself when called from a callback on the driver
    /// thread.
    driver_thread: Option<ThreadId>,
}

enum HandshakeTarget {
    Single(SocketAddr),
    Recovery(Vec<RecoveryEndpoint>),
}

impl StdClient {
    /// Spin up the driver: create a command channel and start a thread with a
    /// socket and a client `Connection`. Socket creation errors don't fail
    /// the call -- they surface as an `on_state(Closed)` event from the
    /// thread. `session_token`/`start_kind` ride inside the versioned msg1
    /// payload (see [`crate::handshake_payload::encode_msg1`]) -- they
    /// identify the retained backend on the server, not the connection's
    /// cryptographic identity (that's `cfg.local_static_priv`, an ephemeral
    /// key the caller mints fresh per connection). `signer` is `None` on the
    /// allowlist path (nothing to prove -- the handshake key IS the proof);
    /// when it is `Some`, the driver signs and sends the proof itself the
    /// moment the handshake completes, off its own thread (see the module
    /// doc's "Authentication proof" section). `setup` is in force before
    /// msg1 leaves (see [`DriverSetup`]).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_with(
        server: SocketAddr,
        cfg: ConnectionConfig,
        session_token: [u8; 16],
        start_kind: StartKind,
        binder: Arc<dyn Binder>,
        events: Arc<dyn ClientEvents>,
        signer: Option<Arc<dyn AuthSigner>>,
        setup: DriverSetup,
    ) -> StdClient {
        Self::connect_target(
            HandshakeTarget::Single(server),
            cfg,
            session_token,
            start_kind,
            binder,
            events,
            signer,
            setup,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_target(
        target: HandshakeTarget,
        cfg: ConnectionConfig,
        session_token: [u8; 16],
        start_kind: StartKind,
        binder: Arc<dyn Binder>,
        events: Arc<dyn ClientEvents>,
        signer: Option<Arc<dyn AuthSigner>>,
        setup: DriverSetup,
    ) -> StdClient {
        let (tx, rx) = mpsc::channel::<Command>();
        let wake = Arc::new(wait::Notifier::default());
        let tx = wait::WakeSender::new(tx, wake.clone());
        let wake_thread = wake.clone();
        let input_budget = setup.input_budget.clone().unwrap_or_default();
        let stop = Arc::new(AtomicU8::new(0));
        let stop_thread = Arc::clone(&stop);
        let stats = Arc::new(Mutex::new(Stats::default()));
        let stats_thread = Arc::clone(&stats);
        let resumed = Arc::new(AtomicBool::new(false));
        let resumed_thread = Arc::clone(&resumed);
        let closed_gracefully = Arc::new(AtomicBool::new(false));
        let closed_gracefully_thread = Arc::clone(&closed_gracefully);
        let features = Arc::new(Mutex::new(None));
        let features_thread = Arc::clone(&features);
        let active_path = Arc::new(Mutex::new(None));
        let active_path_thread = Arc::clone(&active_path);
        let roads = Arc::new(Mutex::new(RoadSnapshot::default()));
        let roads_thread = Arc::clone(&roads);
        let gates = Arc::new(GateTable::new());
        let gates_thread = Arc::clone(&gates);
        let socket_buffers = Arc::new(Mutex::new(None));
        let socket_buffers_thread = Arc::clone(&socket_buffers);
        let last_send_error = Arc::new(Mutex::new(None));
        let last_send_error_thread = Arc::clone(&last_send_error);
        let handle = thread::spawn(move || {
            run_driver(
                target,
                cfg,
                session_token,
                start_kind,
                binder,
                events,
                signer,
                setup,
                rx,
                wake_thread,
                stop_thread,
                stats_thread,
                resumed_thread,
                closed_gracefully_thread,
                features_thread,
                active_path_thread,
                roads_thread,
                gates_thread,
                socket_buffers_thread,
                last_send_error_thread,
            );
        });
        let driver_thread = Some(handle.thread().id());
        StdClient {
            tx: Mutex::new(tx),
            wake,
            input_budget,
            stop,
            stats,
            resumed,
            closed_gracefully,
            features,
            active_path,
            roads,
            gates,
            socket_buffers,
            last_send_error,
            handle: Mutex::new(Some(handle)),
            driver_thread,
        }
    }

    /// Start one recovery attempt across the complete eligible endpoint catalog.
    /// Unlike single-endpoint transport-only connections, shared recovery
    /// requires negotiated `AUTH_ACCEPTED`, even with a weaker configured
    /// minimum. Admission requires its session-bound record; owner cancellation
    /// or closure also terminates scheduling.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_recovery_with(
        endpoints: Vec<RecoveryEndpoint>,
        cfg: ConnectionConfig,
        session_token: [u8; 16],
        start_kind: StartKind,
        binder: Arc<dyn Binder>,
        events: Arc<dyn ClientEvents>,
        signer: Option<Arc<dyn AuthSigner>>,
        setup: DriverSetup,
    ) -> StdClient {
        Self::connect_target(
            HandshakeTarget::Recovery(endpoints),
            cfg,
            session_token,
            start_kind,
            binder,
            events,
            signer,
            setup,
        )
    }

    /// [`StdClient::connect_with`] with the default setup: every stream
    /// counted on delivery (the app, every test peer).
    pub fn connect(
        server: SocketAddr,
        cfg: ConnectionConfig,
        session_token: [u8; 16],
        start_kind: StartKind,
        binder: Arc<dyn Binder>,
        events: Arc<dyn ClientEvents>,
        signer: Option<Arc<dyn AuthSigner>>,
    ) -> StdClient {
        Self::connect_with(
            server,
            cfg,
            session_token,
            start_kind,
            binder,
            events,
            signer,
            DriverSetup::default(),
        )
    }

    /// The owner took `n` bytes of `stream_id` (spec §4.13): for a stream
    /// counted explicitly (`DriverSetup`), where its credit window moves on
    /// from. Ignored for a stream counted on delivery. Fire-and-forget.
    pub fn consumed(&self, stream_id: u8, n: usize) {
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::Consumed { stream_id, n });
    }

    /// A dead driver with no thread: for cases where the caller already knows
    /// a connection is impossible (e.g. invalid keys). Commands are silent
    /// no-ops, statistics are zero.
    pub fn dead() -> StdClient {
        let (tx, _rx) = mpsc::channel::<Command>();
        let wake = Arc::new(wait::Notifier::default());
        StdClient {
            tx: Mutex::new(wait::WakeSender::new(tx, wake.clone())),
            wake,
            input_budget: ClientInputBudget::default(),
            stop: Arc::new(AtomicU8::new(2)),
            driver_thread: None,
            stats: Arc::new(Mutex::new(Stats::default())),
            resumed: Arc::new(AtomicBool::new(false)),
            closed_gracefully: Arc::new(AtomicBool::new(false)),
            features: Arc::new(Mutex::new(None)),
            active_path: Arc::new(Mutex::new(None)),
            roads: Arc::new(Mutex::new(RoadSnapshot::default())),
            gates: Arc::new(GateTable::new()),
            socket_buffers: Arc::new(Mutex::new(None)),
            last_send_error: Arc::new(Mutex::new(None)),
            handle: Mutex::new(None),
        }
    }

    /// How long this client tolerates silence before declaring the link dead
    /// and closing. The default is short, so a client finds out fast that it
    /// must reconnect. The console `qsh` keeps the default; tests shorten it. See
    /// `Connection::set_death_after`.
    pub fn set_death_after(&self, after: std::time::Duration) {
        let _ = self
            .tx
            .lock()
            .expect("command channel")
            .send(Command::SetDeathAfter(after));
    }

    /// Tell the session which roads lead to the same server. Nonempty updates
    /// retain the actual active peer; an empty list disables path checking.
    pub fn set_paths(&self, addrs: Vec<SocketAddr>) {
        let _ = self
            .tx
            .lock()
            .expect("command channel")
            .send(Command::SetPaths(addrs));
    }

    /// Which road the traffic is going down right now.
    pub fn active_path(&self) -> Option<SocketAddr> {
        *self.active_path.lock().expect("active path")
    }

    /// What the roads looked like at the driver's last publication. Empty
    /// until roads are handed in, and on a session that has none.
    pub fn roads(&self) -> Vec<RoadInfo> {
        self.roads.lock().expect("roads mutex").roads.clone()
    }

    /// Actual probe send times from the driver's last road publication.
    pub fn path_probes(&self) -> Vec<(SocketAddr, Instant)> {
        self.roads.lock().expect("roads mutex").probes.clone()
    }

    /// Tentative msg2 resume hint. It may differ from the later committed
    /// AuthAcceptance (for example, a raced-out warm bridge cold-falls back).
    /// Use on_auth_accepted for authentication/recovery decisions; this hint
    /// remains useful for conservative teardown before acceptance arrives.
    pub fn resumed(&self) -> bool {
        self.resumed.load(Ordering::SeqCst)
    }

    /// Whether the connection, once `Closed`, ended with a `Close` frame --
    /// the peer's, or this client's own `close()` -- rather than by its
    /// death timer or by being abandoned (a stream out of offset space).
    /// Only the latter leave the session on the server for a warm return.
    /// Already set when the `Closed` callback runs; false before that.
    pub fn closed_gracefully(&self) -> bool {
        self.closed_gracefully.load(Ordering::SeqCst)
    }

    /// What the transport agreed with the server for this connection (spec
    /// §5.5): the features both sides use. `None` until the handshake
    /// completes, and for a client that never ran. Set before `Live` reaches
    /// the callbacks.
    pub fn features(&self) -> Option<Features> {
        *self.features.lock().expect("features mutex")
    }

    /// What the OS granted this client's socket, each way (spec §4.12, §5.5),
    /// as it reports it; `None` before the driver made one.
    pub fn socket_buffers(&self) -> Option<BufferReport> {
        *self.socket_buffers.lock().expect("buffers mutex")
    }

    /// How the latest datagram this client tried to send failed, if it did:
    /// `None` once a send goes through again. What a connection that never
    /// got an answer tells its owner beyond silence -- on macOS a denied
    /// Local Network permission is a `No route to host` here and nowhere
    /// else.
    pub fn last_send_error(&self) -> Option<SendFailure> {
        self.last_send_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Atomically accept a whole owned record without waiting for credit.
    /// Source API change for 0.6.0: Full/Gone return the original Vec unchanged.
    /// All application streams share byte/entry custody until actual ACK or
    /// teardown; LinkDown never refunds accepted input. Empty input is a no-op.
    pub fn send_bytes(&self, stream_id: u8, data: Vec<u8>) -> Result<(), SendRejected> {
        self.admit_bytes(stream_id, data, false)
    }

    fn input_unavailable(&self) -> bool {
        self.is_gone() || self.stop.load(Ordering::SeqCst) != 0 || self.wake.failed()
    }

    fn full_or_gone(&self) -> SendBlocked {
        if self.input_unavailable() {
            SendBlocked::Gone
        } else {
            SendBlocked::Full
        }
    }

    fn admit_bytes(&self, stream_id: u8, data: Vec<u8>, bounded: bool) -> Result<(), SendRejected> {
        if data.is_empty() {
            return Ok(());
        }
        let tx = self.tx.lock().expect("command channel mutex");
        if self.input_unavailable() {
            return Err(SendRejected {
                reason: SendBlocked::Gone,
                data,
            });
        }
        let permit = match self.input_budget.reserve_owned(data.len(), data.capacity()) {
            Ok(Some(permit)) => permit,
            Ok(None) => unreachable!("nonempty input has a record obligation"),
            Err(()) => {
                return Err(SendRejected {
                    reason: self.full_or_gone(),
                    data,
                })
            }
        };
        let n = data.len() as u64;
        let gate = self.gates.gate(stream_id, GateKind::Pipe);
        match gate.admit_client(n, bounded) {
            ClientAdmission::Admitted => {}
            ClientAdmission::Full => {
                drop(permit);
                return Err(SendRejected {
                    reason: self.full_or_gone(),
                    data,
                });
            }
            ClientAdmission::Closed => {
                drop(permit);
                return Err(SendRejected {
                    reason: SendBlocked::Gone,
                    data,
                });
            }
        }
        match tx.send(Command::Send {
            stream_id,
            record: InputRecord::new(data, permit),
        }) {
            Ok(()) => Ok(()),
            Err(mpsc::SendError(Command::Send { record, .. })) => {
                gate.withdraw(n);
                Err(SendRejected {
                    reason: SendBlocked::Gone,
                    data: record.into_bytes(),
                })
            }
            Err(_) => unreachable!("this publication contains only owned input"),
        }
    }

    /// Declare `stream_id`'s class for the fairness rule and the congestion
    /// window (spec §4.8): `Bulk` for a transfer that must not stand in
    /// front of keystrokes.
    pub fn set_stream_class(&self, stream_id: u8, class: StreamClass) {
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::SetStreamClass { stream_id, class });
    }

    /// Queue bytes on `stream_id` once its send gate is open (spec §4.7.3).
    /// The gate closes when what the stream holds queued and unacknowledged,
    /// plus what producers handed over that the driver has not taken yet,
    /// reaches 512 KiB, and opens again at 256 KiB. Waits at most `timeout`.
    /// `Err` queued nothing, and says why ([`SendBlocked`]): the gate stayed
    /// shut (`Full`), the driver is gone (`Gone`, at once -- a gate never
    /// opens again once its driver has ended), or this is the driver thread
    /// itself (`OnDriverThread`, at once: a `ClientEvents` callback would be
    /// waiting for itself -- the same guard `stream_progress` has).
    /// Both APIs share whole-record byte/entry admission and per-stream FIFO;
    /// this variant additionally waits for and atomically rechecks its gate.
    pub fn send_bytes_bounded(
        &self,
        stream_id: u8,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SendRejected> {
        if data.is_empty() {
            return Ok(());
        }
        if self.input_unavailable() {
            return Err(SendRejected {
                reason: SendBlocked::Gone,
                data,
            });
        }
        if self.driver_thread == Some(thread::current().id()) {
            return Err(SendRejected {
                reason: SendBlocked::OnDriverThread,
                data,
            });
        }
        let gate = self.gates.gate(stream_id, GateKind::Pipe);
        match gate.wait_open_for(timeout) {
            GateWait::Open => self.admit_bytes(stream_id, data, true),
            GateWait::TimedOut => Err(SendRejected {
                reason: self.full_or_gone(),
                data,
            }),
            GateWait::Closed => Err(SendRejected {
                reason: SendBlocked::Gone,
                data,
            }),
        }
    }

    /// Whether the driver has ended -- however it ended: `close`, `detach`,
    /// a dead link, or a panic in a `ClientEvents` callback on its thread,
    /// the one way out that tells the owner nothing (no `Closed`) -- or never
    /// ran (`dead`). Once true it stays true, and nothing sent through this
    /// client goes anywhere. For an owner that cannot tell a driver that is
    /// slow to answer (`stream_progress` returns `None` for both) from one
    /// that is gone.
    pub fn is_gone(&self) -> bool {
        self.driver_thread.is_none() || self.gates.is_closed()
    }

    /// Recreate the local socket (network change) without tearing down the
    /// session.
    pub fn rebind(&self) {
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::Rebind);
    }

    /// Last known connection statistics.
    pub fn stats(&self) -> Stats {
        *self.stats.lock().expect("stats mutex")
    }

    /// How far `stream_id` has got. `None` if the driver is gone or did not
    /// answer within `PROGRESS_REPLY_TIMEOUT`. Blocks the caller for up to
    /// that long, so calling it from a `ClientEvents` callback would normally
    /// deadlock the driver waiting on itself -- guarded against the same way
    /// `join_driver` is: called from the driver thread, this returns `None`
    /// at once without sending a command, rather than stalling the whole
    /// driver loop for the timeout.
    pub fn stream_progress(&self, stream_id: u8) -> Option<StreamProgress> {
        if self.driver_thread == Some(thread::current().id()) {
            return None;
        }
        let (reply, answer) = mpsc::channel();
        self.tx
            .lock()
            .expect("command channel mutex")
            .send(Command::StreamProgress { stream_id, reply })
            .ok()?;
        answer.recv_timeout(PROGRESS_REPLY_TIMEOUT).ok()
    }

    /// Move the session onto road `addr` now, without dropping it -- the owner's own choice
    /// (see `Connection::use_road` for which roads are taken). Blocks until the driver has
    /// acted, up to `USE_ROAD_REPLY_TIMEOUT`; by the time `Moved` comes back, `active_path()`
    /// already names the new road. No answer in time is `NoSession` -- the driver may still act
    /// on the request later, and the road in use then says so on the next statistics report.
    /// Called from the driver thread (a `ClientEvents` callback) it answers `NoSession` at once,
    /// for the reason `stream_progress` does.
    pub fn use_road(&self, addr: SocketAddr) -> UseRoadOutcome {
        if self.driver_thread == Some(thread::current().id()) {
            return UseRoadOutcome::NoSession;
        }
        let (reply, answer) = mpsc::channel();
        let sent = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::UseRoad { addr, reply });
        if sent.is_err() {
            return UseRoadOutcome::NoSession;
        }
        answer
            .recv_timeout(USE_ROAD_REPLY_TIMEOUT)
            .unwrap_or(UseRoadOutcome::NoSession)
    }

    /// Stop the driver gracefully and wait for the thread to finish: the
    /// client's `Close` frame reaches the server before the loop exits, so
    /// the server tears the backend down immediately (see the module doc).
    /// For a user-initiated disconnect.
    pub fn close(&self) {
        self.stop.fetch_max(1, Ordering::SeqCst);
        self.wake.notify();
        self.join_driver();
    }

    /// Tear the driver down locally WITHOUT emitting the client's `Close`
    /// frame: the server just sees silence and RETAINS the backend for a
    /// later warm reattach, instead of tearing it down at once (see the
    /// module doc). For the app's own internal forced reconnect -- NOT a
    /// user-initiated disconnect, which must keep using `close`.
    pub fn detach(&self) {
        self.stop.fetch_max(2, Ordering::SeqCst);
        self.wake.notify();
        self.join_driver();
    }

    /// Wait for the driver thread to finish after its sticky teardown signal
    /// was set. Guards against self-join. Callbacks
    /// (`ClientEvents`/`Binder`) run ON THE DRIVER THREAD; if a platform
    /// callback synchronously calls `close`/`detach`, `join` would block the
    /// driver waiting on itself -- deadlock. On its own thread we settle for
    /// having set the signal: the driver will finish on its own once it
    /// returns from the callback and checks the signal.
    fn join_driver(&self) {
        if self.driver_thread == Some(thread::current().id()) {
            return;
        }
        if let Some(handle) = self.handle.lock().expect("thread handle mutex").take() {
            let _ = handle.join();
        }
    }
}

/// Create a new UDP socket and ask `binder` to bind it to a network. `None`
/// if socket creation fails.
///
/// Deliberately left UNconnected: this driver talks to several addresses for
/// one session (the live road and every spare `Connection::set_paths` was
/// given), and a `connect`-ed socket's kernel-level peer filter would drop a
/// `PathProbeAck` -- or any reply at all -- arriving from anywhere but the
/// one address it was `connect`-ed to, which is exactly what a spare road
/// answering back, or a live road that just moved, looks like. Accepting
/// datagrams from any source is as safe here as it always has been on the
/// server side of this transport (which has never connect-ed its socket at
/// all): every packet is authenticated by session id and AEAD before it can
/// affect anything, so a stranger's datagram costs one failed decryption and
/// nothing else.
fn make_socket(binder: &dyn Binder) -> Option<(UdpSocket, BufferReport)> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // Best-effort binding: the result informs the platform, but failure
        // doesn't abort the attempt -- we run over the default route.
        let _ = binder.bind(socket.as_raw_fd());
    }
    #[cfg(not(unix))]
    {
        // Off unix the raw descriptor isn't available -- skip binding.
        let _ = binder;
    }
    // Sized before anything is sent or received on it (spec §4.12).
    let buffers = tune_udp_buffers(&socket);
    Some((socket, buffers))
}

/// Send a batch of outgoing datagrams, each to its own `Datagram::to`.
///
/// The socket is unconnected (see `make_socket`), so every send must name a
/// destination explicitly -- there is no default peer to fall back to.
/// Ordinary stream traffic targets `self.peer`; a path check targets
/// whatever spare road `Connection::set_paths` was given; and a road that
/// just took over after the live one died is a fresh `self.peer` a
/// destination-less send could never have reached anyway.
fn send_all(socket: &UdpSocket, dgrams: &[Datagram], record: &mut SendRecord) {
    for dg in dgrams {
        record.note(dg.to, socket.send_to(&dg.bytes, dg.to));
    }
}

/// A queued handshake becomes an endpoint check only after this actual send.
/// Cookie retries returned by on_datagram use the same acknowledgement path.
fn send_recovery_aware(
    socket: &UdpSocket,
    dgrams: &[Datagram],
    record: &mut SendRecord,
    conn: &mut Connection,
) {
    for dg in dgrams {
        let result = socket.send_to(&dg.bytes, dg.to);
        if matches!(
            crate::wire::parse(&dg.bytes),
            Ok(crate::wire::Frame::Handshake {
                kind: crate::wire::Kind::HandshakeInit | crate::wire::Kind::HandshakeInitCookie,
                ..
            })
        ) {
            let at = Instant::now();
            conn.recovery_handshake_sent(at, dg.to, result.is_ok());
            if conn.recovery_handshake().is_some() {
                record.events.on_recovery_progress(RecoveryProgress::Sent {
                    endpoint: dg.to,
                    at,
                    success: result.is_ok(),
                });
            }
        }
        record.note(dg.to, result);
    }
}

/// What the driver remembers about its sends failing: the latest outcome,
/// published for [`StdClient::last_send_error`], and the last failure the
/// owner was told about, so a retransmit failing the same way every half
/// second is reported once.
struct SendRecord {
    shared: Arc<Mutex<Option<SendFailure>>>,
    /// Whether the latest send failed: the shared slot is written only when
    /// this changes, or the failure does -- not on every datagram.
    failing: bool,
    /// The failure `on_send_error` last reported.
    told: Option<SendFailure>,
    events: Arc<dyn ClientEvents>,
}

impl SendRecord {
    fn new(shared: Arc<Mutex<Option<SendFailure>>>, events: Arc<dyn ClientEvents>) -> SendRecord {
        SendRecord {
            shared,
            failing: false,
            told: None,
            events,
        }
    }

    fn note(&mut self, to: SocketAddr, sent: std::io::Result<usize>) {
        match sent {
            Ok(_) => {
                if self.failing {
                    self.failing = false;
                    *self.shared.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
            }
            Err(e) => {
                let failure = (e.kind(), e.to_string());
                if self.failing && self.told.as_ref() == Some(&failure) {
                    return;
                }
                self.failing = true;
                *self.shared.lock().unwrap_or_else(|e| e.into_inner()) = Some(failure.clone());
                if self.told.as_ref() != Some(&failure) {
                    self.events.on_send_error(to, failure.0, &failure.1);
                    self.told = Some(failure);
                }
            }
        }
    }
}

fn with_receive_mode<T>(
    mut set_mode: impl FnMut(bool) -> std::io::Result<()>,
    receive: impl FnOnce() -> T,
) -> std::io::Result<T> {
    set_mode(true)?;
    let batch = receive();
    set_mode(false)?;
    Ok(batch)
}

/// A readable hint can be stale. Drain nonblocking, then restore blocking
/// before any generated datagram reaches the unchanged blocking send path.
fn drain_ready(
    socket: &UdpSocket,
    conn: &mut Connection,
    buf: &mut [u8],
    max: usize,
    clock: &wait::Clock,
) -> std::io::Result<Vec<Datagram>> {
    with_receive_mode(
        |nonblocking| socket.set_nonblocking(nonblocking),
        || {
            let mut out = Vec::new();
            for _ in 0..max {
                match socket.recv_from(buf) {
                    Ok((len, src)) => out.extend(conn.on_datagram(clock.now(), src, &buf[..len])),
                    Err(_) => break,
                }
            }
            out
        },
    )
}

/// A `recv` timeout surfaces as `WouldBlock` (unix) or `TimedOut` (windows).
#[cfg(test)]
fn is_read_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// Closes every send gate when the driver thread ends, however it ends, so a
/// producer waiting in `send_bytes_bounded` wakes with `SendBlocked` instead
/// of waiting out its timeout for a driver that is gone.
struct CloseGatesOnExit(Arc<GateTable>);

impl Drop for CloseGatesOnExit {
    fn drop(&mut self) {
        self.0.close_all();
    }
}

/// The driver thread body.
#[allow(clippy::too_many_arguments)]
fn run_driver(
    target: HandshakeTarget,
    cfg: ConnectionConfig,
    session_token: [u8; 16],
    start_kind: StartKind,
    binder: Arc<dyn Binder>,
    events: Arc<dyn ClientEvents>,
    signer: Option<Arc<dyn AuthSigner>>,
    setup: DriverSetup,
    rx: Receiver<Command>,
    wake: Arc<wait::Notifier>,
    stop: Arc<AtomicU8>,
    shared_stats: Arc<Mutex<Stats>>,
    resumed_flag: Arc<AtomicBool>,
    closed_gracefully_flag: Arc<AtomicBool>,
    features_flag: Arc<Mutex<Option<Features>>>,
    active_path_flag: Arc<Mutex<Option<SocketAddr>>>,
    roads_out: Arc<Mutex<RoadSnapshot>>,
    gates: Arc<GateTable>,
    buffers_out: Arc<Mutex<Option<BufferReport>>>,
    last_send_error: Arc<Mutex<Option<SendFailure>>>,
) {
    let _close_gates = CloseGatesOnExit(Arc::clone(&gates));
    // Private to this driver instance -- see the module doc's "Authentication
    // proof" section for why this must NOT be a clone of the external `tx`
    // above: `auth_tx` is cloned into the signing thread this driver spawns,
    // never handed outside, so its liveness can never mask `rx` losing its
    // only external sender (a `StdClient` dropped without close()/detach()).
    let (auth_tx, auth_rx) = mpsc::channel::<AuthResult>();
    let auth_tx = wait::WakeSender::new(auth_tx, wake.clone());
    #[cfg(test)]
    let clock = wait::Clock::controlled(setup.wait_control.clone());
    #[cfg(not(test))]
    let clock = wait::Clock::default();

    let (socket, initial_buffers) = match make_socket(binder.as_ref()) {
        Some(pair) => pair,
        None => {
            events.on_state(LinkState::Closed);
            return;
        }
    };

    #[cfg(test)]
    let initialized = match setup.wait_control.clone() {
        Some(control) => wait::DriverWait::controlled(socket, &wake, control),
        None => wait::DriverWait::new(socket, &wake),
    };
    #[cfg(not(test))]
    let initialized = wait::DriverWait::new(socket, &wake);
    let mut socket = match initialized {
        Ok(socket) => socket,
        Err(error) => {
            log::error!("cannot initialize the client readiness wait: {error}");
            stop.fetch_max(2, Ordering::SeqCst);
            events.on_state(LinkState::Closed);
            return;
        }
    };

    *buffers_out.lock().expect("buffers mutex") = Some(initial_buffers);
    let mut sends = SendRecord::new(last_send_error, Arc::clone(&events));
    let allowlist_proof = matches!(cfg.auth, crate::conn::AuthPolicy::Allowlist(_));
    let mut owned = DriverConnection {
        connection: Connection::new(cfg),
        inputs: InputQueue::default(),
    };
    let conn = &mut owned.connection;
    let inputs = &mut owned.inputs;
    // Before msg1: no byte can arrive before these are in force.
    conn.set_default_consumption(setup.default_consumption);
    for (stream_id, consumption) in setup.stream_consumption {
        conn.set_stream_consumption(stream_id, consumption);
    }
    // The reserved server-direction record is consumed by this driver, never
    // by the application. Override even an explicit per-stream setup once;
    // on-delivery accounting owns its credit, with no duplicate report.
    conn.set_stream_consumption(AUTH_STREAM, Consumption::OnDelivery);
    let start = clock.now();
    // The first msg1; the connection keeps it and hands it back for every
    // retransmit, byte for byte -- behind the daemon's cookie once one
    // arrived (spec §4.16). msg1 carries the start kind, the token, the
    // method `cfg.auth` announces and the features `cfg.features` offers
    // (spec §5.2).
    let first_msg1 = match target {
        HandshakeTarget::Single(server) => {
            conn.start_session(start, server, start_kind, session_token)
        }
        HandshakeTarget::Recovery(endpoints) => {
            conn.start_recovery(start, endpoints, start_kind, session_token)
        }
    };
    send_recovery_aware(socket.socket(), &first_msg1, &mut sends, conn);

    // The handshake retransmit timer is driven by the driver: during
    // `Connecting` the core doesn't ask to be woken for it.
    // `handshake_pending` goes false on the transition to Live/Closed.
    let mut handshake_pending = true;
    let mut handshake_sent_at = start;

    // Bumped once per `Event::HandshakeDone` (see the module doc's
    // "Authentication proof" section); each `spawn_auth_signing` call
    // captures the value at the time it was started, so an `AuthDone` for a
    // generation this counter has since moved past is recognized as stale.
    let mut auth_generation: u64 = 0;
    let mut acceptance_parser = None;
    let mut reported_selection = None;

    let mut state = LinkState::Connecting;
    events.on_state(state);
    let mut last_stats = Stats::default();
    let mut last_stats_at = clock.now();

    let mut buf = vec![0u8; RECV_BUF_LEN];

    loop {
        if wake.failed() {
            report_input_failure(
                conn,
                events.as_ref(),
                &stop,
                InputFailure::DriverUnavailable,
            );
            return;
        }
        // 1. Commands from the channel (at the start of the iteration).
        let mut should_close = stop.load(Ordering::SeqCst) != 0;
        // Whether the teardown (once `should_close` is set) puts a `Close`
        // frame on the wire. Defaults to `true` so an implicit drop (the
        // channel disconnecting without an explicit `close`/`detach` call)
        // keeps today's behavior. The sticky detach signal makes it `false` and
        // it STAYS false for the rest of this teardown -- in particular the
        // `Disconnected` arm below never sets it back to `true`, so a detach
        // can never be "resurrected" into a graceful Close by the client
        // handle being dropped afterward.
        let mut graceful = stop.load(Ordering::SeqCst) != 2;
        let mut command_count = 0;
        let mut command_processed = false;
        while !should_close && command_count < INPUT_TURN {
            let disposition = stop.load(Ordering::SeqCst);
            if disposition != 0 {
                should_close = true;
                graceful &= disposition != 2;
                break;
            }
            command_count += 1;
            let command = rx.try_recv();
            command_processed |= command.is_ok();
            #[cfg(test)]
            if let (Some(control), Ok(command)) = (&setup.wait_control, &command) {
                control.command(match command {
                    Command::Send { stream_id, .. } => format!("Send:{stream_id}"),
                    Command::Consumed { .. } => "Consumed".into(),
                    Command::Rebind => "Rebind".into(),
                    Command::SetDeathAfter(_) => "SetDeathAfter".into(),
                    Command::SetPaths(_) => "SetPaths".into(),
                    Command::SetStreamClass { .. } => "SetStreamClass".into(),
                    Command::StreamProgress { .. } => "StreamProgress".into(),
                    Command::UseRoad { .. } => "UseRoad".into(),
                    Command::UnconsumedForTest(_) => "UnconsumedForTest".into(),
                });
            }
            match command {
                Ok(Command::Send { stream_id, record }) => {
                    inputs.push(stream_id, record);
                }
                Ok(Command::Rebind) => {
                    if let Some((new_sock, buffers)) = make_socket(binder.as_ref()) {
                        match socket.replace(new_sock) {
                            Ok(true) => {
                                *buffers_out.lock().expect("buffers mutex") = Some(buffers);
                                let now = clock.now();
                                conn.request_ping(now);
                                let out = conn.on_timeout(now);
                                send_all(socket.socket(), &out, &mut sends);
                            }
                            Ok(false) => {} // Registration failed cleanly; old route stays active.
                            Err(error) => {
                                log::error!("cannot replace the client socket safely: {error}");
                                report_input_failure(
                                    conn,
                                    events.as_ref(),
                                    &stop,
                                    InputFailure::DriverUnavailable,
                                );
                                return;
                            }
                        }
                    }
                }
                Ok(Command::SetDeathAfter(after)) => conn.set_death_after(after),
                Ok(Command::SetPaths(addrs)) => conn.set_paths(addrs),
                Ok(Command::StreamProgress { stream_id, reply }) => {
                    let _ = reply.send(conn.stream_progress(stream_id));
                }
                Ok(Command::UseRoad { addr, reply }) => {
                    let now = clock.now();
                    // Decided here, on the driver thread, so nothing can move the session
                    // between this look and the request: `Connection::use_road` answers
                    // `Ok(())` both for a move and for the road already in use.
                    let was_in_use = conn.active_path() == Some(addr);
                    let outcome = match conn.use_road(addr, now) {
                        Ok(()) if was_in_use => UseRoadOutcome::AlreadyInUse,
                        Ok(()) => {
                            // The forced PING goes out now, down the new road: the server
                            // follows the session on its first ordinary packet from there.
                            let out = conn.on_timeout(now);
                            send_all(socket.socket(), &out, &mut sends);
                            UseRoadOutcome::Moved
                        }
                        Err(UseRoadError::NotAnswering) => UseRoadOutcome::NotAnswering,
                        Err(UseRoadError::UnknownRoad) => UseRoadOutcome::UnknownRoad,
                        Err(UseRoadError::NoSession) => UseRoadOutcome::NoSession,
                    };
                    // Published before the answer, so an owner that reads `active_path()` on
                    // hearing `Moved` sees the road it asked for, not the one before.
                    *active_path_flag.lock().expect("active path") = conn.active_path();
                    let _ = reply.send(outcome);
                }
                Ok(Command::SetStreamClass { stream_id, class }) => {
                    conn.set_stream_class(stream_id, class)
                }
                #[cfg(test)]
                Ok(Command::UnconsumedForTest(reply)) => {
                    let _ = reply.send(conn.unconsumed_streams());
                }
                Ok(Command::Consumed { stream_id, n }) => {
                    let now = clock.now();
                    let out = conn.on_consumed(now, stream_id, n);
                    send_all(socket.socket(), &out, &mut sends);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The client was dropped without close()/detach() --
                    // finish up. Doesn't touch `graceful`: if detach was
                    // already requested above in this same turn, it stays
                    // non-graceful (sticky); otherwise this preserves the
                    // pre-existing implicit-drop behavior.
                    should_close = true;
                    break;
                }
            }
        }
        let disposition = stop.load(Ordering::SeqCst);
        should_close |= disposition != 0;
        graceful &= disposition != 2;
        inputs.acknowledge(conn);
        if !should_close {
            match inputs.drain(conn, clock.now(), &gates) {
                Ok(out) => send_all(socket.socket(), &out, &mut sends),
                Err(failure) => {
                    report_input_failure(conn, events.as_ref(), &stop, failure);
                    should_close = true;
                    graceful = false;
                }
            }
        }
        // Auth-signing results, drained from their OWN channel -- see the
        // module doc's "Authentication proof" section for why this is not
        // folded into the `rx` loop above: `auth_tx` is a driver-local
        // sender, never handed to the caller, so nothing here can affect
        // whether `rx` (the external channel) reports `Disconnected`. `Err`
        // (`Empty`, or `Disconnected` -- which cannot happen while this
        // function is running, since it holds `auth_tx` for its whole
        // lifetime) both mean "nothing more to do this iteration".
        let mut auth_processed = false;
        while let Ok(AuthResult { generation, record }) = auth_rx.try_recv() {
            auth_processed = true;
            // A processed stop also retires results already queued by the signer.
            if !should_close && generation == auth_generation {
                match record {
                    Some(bytes) => {
                        let now = clock.now();
                        let out = conn.send(now, AUTH_STREAM, &bytes);
                        send_all(socket.socket(), &out, &mut sends);
                    }
                    None => {
                        // The signer could not produce a proof at all (a
                        // wrong passphrase, no agent, a refused touch):
                        // nothing to retry, so give up right here instead of
                        // leaving the app to watch the socket go silent
                        // until the server's own `AUTH_DEADLINE`. No further
                        // datagram goes out -- like `detach`, there is
                        // nothing left worth saying.
                        events.on_state(LinkState::Closed);
                        return;
                    }
                }
            }
            // Else: cancellation won, or this driver has moved past the
            // result's handshake generation (see the module doc). Sending
            // a stale generation now would
            // offer the server a signature over a hash that no longer
            // describes this session -- worse than sending nothing -- so it
            // is dropped in silence.
        }
        if should_close {
            if graceful {
                // Graceful stop: emit the client's Close frame and get it on
                // the wire BEFORE tearing down the loop, so the server
                // retires the backend immediately instead of retaining it for
                // a warm reconnect (see `Connection::close`). A no-op if the
                // handshake never completed (no transport keys yet) -- nothing
                // to close.
                let now = clock.now();
                let out = conn.close(now);
                send_all(socket.socket(), &out, &mut sends);
            }
            // A detach tears down locally without putting anything on the
            // wire: the server just sees silence and retains the backend for
            // a warm reattach.
            break;
        }

        // 2. Socket readiness, producer notification, or the nearest real timer.
        let now = clock.now();
        let handshake_deadline = if let Some(schedule) = conn.recovery_handshake() {
            schedule.next_deadline()
        } else {
            handshake_pending.then_some(handshake_sent_at + HANDSHAKE_RETRANSMIT)
        };
        let effective = next_wait_deadline(
            now,
            conn.next_timeout(),
            handshake_deadline,
            last_stats_at,
            command_processed
                || auth_processed
                || command_count == INPUT_TURN
                || inputs.turn_full(),
        );
        let wait_started = clock.now();
        let mut readable = match socket.wait(effective) {
            Ok(readable) => readable,
            Err(error) => {
                log::error!("client readiness wait failed: {error}");
                report_input_failure(
                    conn,
                    events.as_ref(),
                    &stop,
                    InputFailure::DriverUnavailable,
                );
                return;
            }
        };
        if wake.failed() {
            report_input_failure(
                conn,
                events.as_ref(),
                &stop,
                InputFailure::DriverUnavailable,
            );
            return;
        }
        // A stop wake does not run timers or send anything before its sticky
        // disposition is processed at the beginning of the next bounded turn.
        if stop.load(Ordering::SeqCst) != 0 {
            continue;
        }
        let now = clock.now();
        if freeze_late(effective, wait_started, now) {
            if let Some((new_sock, buffers)) = make_socket(binder.as_ref()) {
                match socket.replace(new_sock) {
                    Ok(true) => *buffers_out.lock().expect("buffers mutex") = Some(buffers),
                    Ok(false) => {}
                    Err(error) => {
                        log::error!("cannot replace the resumed client socket safely: {error}");
                        report_input_failure(
                            conn,
                            events.as_ref(),
                            &stop,
                            InputFailure::DriverUnavailable,
                        );
                        return;
                    }
                }
            }
            conn.request_ping(now);
            readable = false; // A stale old-generation event never reads a replacement.
        }
        let mut out = if readable {
            match drain_ready(socket.socket(), conn, &mut buf, READY_DRAIN_MAX, &clock) {
                Ok(out) => out,
                Err(error) => {
                    log::error!("client UDP receive mode transition failed: {error}");
                    report_input_failure(
                        conn,
                        events.as_ref(),
                        &stop,
                        InputFailure::DriverUnavailable,
                    );
                    return;
                }
            }
        } else {
            Vec::new()
        };
        // Timers after EVERY wake-up, not only after a read timeout (spec
        // §4.1): datagrams arriving more often than the read timeout used to
        // starve the PINGs, retransmits, `PathDown`, road checks and the
        // dead-road rule.
        let now = clock.now();
        out.extend(conn.on_timeout_if_due(now));
        // The msg1 retransmit follows the same rule. Re-send the first msg1
        // as the connection keeps it (`retransmit_handshake`: the same
        // bytes -- once the daemon's cookie arrived, behind it and plain in
        // turn) -- do NOT rebuild the initiator (that would mint a fresh
        // ephemeral and a different msg1 body, missing the server's
        // byte-identical `ResendMsg2` path and churning the backend). The
        // connection counts it as a retransmit (Karn: the reply may answer
        // either copy, so it seeds no round trip). `handshake_pending`
        // itself clears only when the events are handed out below, and msg2
        // may have arrived in THIS pass: the state says whether the
        // handshake is still waiting.
        if conn.recovery_handshake().is_some() {
            out.extend(conn.poll_recovery_handshake(now));
        } else if handshake_pending
            && conn.state() == LinkState::Connecting
            && now >= handshake_sent_at + HANDSHAKE_RETRANSMIT
        {
            send_all(socket.socket(), &conn.retransmit_handshake(), &mut sends);
            handshake_sent_at = now;
        }
        send_recovery_aware(socket.socket(), &out, &mut sends, conn);

        // The active path is settled by now (roaming re-points `conn`'s peer
        // synchronously inside `on_datagram`, above) -- published BEFORE the
        // events below reach the caller, so a caller who learns of `Live` (or
        // any other event) through `ClientEvents` never sees a stale
        // `active_path()` in response, the same reason `resumed_flag` is set
        // ahead of `dispatch_event` for `HandshakeDone` below.
        *active_path_flag.lock().expect("active path") = conn.active_path();

        // Publish the consumed source before either protocol failure or a
        // proof-producing HandshakeDone reaches the owner. The source may
        // have supplied an authenticated but invalid payload, never Live.
        let selected = conn
            .recovery_handshake()
            .and_then(|schedule| schedule.selected());
        if let Some(endpoint) = selected.filter(|selected| Some(*selected) != reported_selection) {
            reported_selection = Some(endpoint);
            events.on_recovery_progress(RecoveryProgress::Selected {
                endpoint,
                at: clock.now(),
            });
        }

        // 4. Forward core events and statistics.
        for ev in poll_events_abandoning_on_exhaustion(conn) {
            // Signing starts the moment the handshake ends, and again after
            // every re-handshake (see the module doc for the ordering this
            // does and does not guarantee). Signing happens off this thread
            // -- `Connection::handshake_hash` and `Connection::server_nonce`
            // are read here, on the driver thread, but `AuthSigner::sign`
            // never is.
            if matches!(ev, Event::HandshakeDone) {
                if allowlist_proof {
                    // Prove possession of the fresh responder keys immediately,
                    // without opening an application channel. A lost PING is
                    // retried by the existing keepalive schedule.
                    conn.request_ping(now);
                    send_all(socket.socket(), &conn.on_timeout(now), &mut sends);
                }
                resumed_flag.store(conn.resumed(), Ordering::SeqCst);
                *features_flag.lock().expect("features mutex") = Some(conn.features());
                events.on_features(conn.features());
                acceptance_parser = Some(crate::auth_acceptance::AuthAcceptanceParser::new(
                    conn.session_id(),
                    conn.features(),
                ));
                if let Some(signer) = signer.as_ref() {
                    auth_generation += 1;
                    let _ = spawn_auth_signing(
                        auth_generation,
                        conn.handshake_hash(),
                        conn.server_nonce(),
                        Arc::clone(signer),
                        auth_tx.clone(),
                    );
                }
            }
            if matches!(ev, Event::StateChanged(LinkState::Closed)) {
                closed_gracefully_flag.store(conn.closed_gracefully(), Ordering::SeqCst);
            }
            let acceptance = dispatch_authenticated_event(
                ev,
                events.as_ref(),
                &mut state,
                &mut handshake_pending,
                &mut acceptance_parser,
            );
            if matches!(acceptance, Ok(true)) {
                conn.stop_recovery_handshake();
            }
            if let Err(reason) = acceptance {
                events
                    .on_protocol_failure(crate::ProtocolFailure::InvalidAuthentication { reason });
                // Do not send Close: a malformed admission response must not
                // accidentally destroy a session the tentative msg2 resumed.
                conn.abandon();
                dispatch_event(
                    Event::StateChanged(LinkState::Closed),
                    events.as_ref(),
                    &mut state,
                    &mut handshake_pending,
                );
                break;
            }
        }
        let cur = conn.stats(now);
        if stats_are_due(
            cur,
            last_stats,
            now.saturating_duration_since(last_stats_at),
        ) {
            last_stats = cur;
            last_stats_at = now;
            *shared_stats.lock().expect("stats mutex") = cur;
            *roads_out.lock().expect("roads mutex") = RoadSnapshot {
                roads: conn.roads(now),
                probes: conn.path_probes(),
            };
            events.on_stats(cur);
        }

        // The bounded producers' gates follow the tails after every pass
        // (spec §4.7.3): an ACK that shrank a tail opens its gate here.
        let _ = gates.refresh(|stream| conn.stream_progress(stream).unacked);

        // Don't spin uselessly on a dead session.
        if matches!(state, LinkState::Closed) {
            break;
        }
    }
}

/// No peer Close or replay: failure is observable before the local Closed,
/// while accepted records still belong to the not-yet-destroyed connection.
pub(crate) fn report_input_failure(
    conn: &mut Connection,
    events: &dyn ClientEvents,
    stop: &AtomicU8,
    failure: InputFailure,
) {
    stop.fetch_max(2, Ordering::SeqCst);
    events.on_input_failure(failure);
    conn.abandon();
    events.on_state(LinkState::Closed);
}

/// Produce this handshake's proof off the driver thread and report the
/// result back over `auth_tx` -- a channel private to this driver instance,
/// NOT the external command channel (see the module doc's "Authentication
/// proof" section for why the two must stay separate). `generation` guards
/// against a result superseded by a newer handshake by the time it finishes.
///
/// Fire-and-forget: the `JoinHandle` is discarded on purpose. If the
/// connection closes while this thread is still working (a slow signer, e.g.
/// a hardware key waiting on a touch), `auth_tx`'s receiver is dropped along
/// with `run_driver`'s stack frame, and the eventual `auth_tx.send` below
/// simply errors and is discarded -- nothing to join, nothing panics, nothing
/// leaks beyond one OS thread blocked in `AuthSigner::sign` until it returns
/// on its own.
fn spawn_auth_signing(
    generation: u64,
    handshake_hash: [u8; 32],
    nonce: Option<[u8; AUTH_NONCE_LEN]>,
    signer: Arc<dyn AuthSigner>,
    auth_tx: wait::WakeSender<AuthResult>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let record = match signer.sign(&handshake_hash, nonce.as_ref()) {
            // Framing can fail too (a field past the record's u16 length),
            // and a proof that cannot be framed is as unsendable as one that
            // cannot be signed -- same outcome, its own reason.
            Ok(record) => match encode_auth_record(&record) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    log::error!("could not frame the authentication record: {e}");
                    None
                }
            },
            Err(e) => {
                // The record itself never carries diagnostics, so the log is
                // the only avenue left for the reason -- `on_state(Closed)`
                // alone would tell the caller THAT it failed, not why. On a
                // host with no logger installed, this reason is simply not
                // visible anywhere.
                log::error!("could not sign the handshake: {e}");
                None
            }
        };
        let _ = auth_tx.send(AuthResult { generation, record });
    })
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many hard-cap reports `dispatch_event` put in the log on
    /// this thread. The line is all that arm does, and a test cannot tell it
    /// from the no-op group below it otherwise.
    static OVER_CAP_LOGGED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    /// Test-only: how many unoffered-feature reports `dispatch_event` put in
    /// the log on this thread.
    static UNOFFERED_LOGGED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Routes one core event to the external callbacks, updating the driver's
/// local `state`/`handshake_pending` bookkeeping along the way. Returns true
/// only when this event delivers authenticated acceptance. Pulled out of
/// the driver loop as its own function so the routing itself (which event
/// reaches which callback) is unit-testable without spinning up sockets.
fn dispatch_authenticated_event(
    ev: Event,
    events: &dyn ClientEvents,
    state: &mut LinkState,
    handshake_pending: &mut bool,
    parser: &mut Option<crate::auth_acceptance::AuthAcceptanceParser>,
) -> Result<bool, crate::AuthAcceptanceError> {
    match ev {
        Event::StreamData {
            stream_id: AUTH_STREAM,
            data,
        } => {
            let parser = parser
                .as_mut()
                .ok_or(crate::AuthAcceptanceError::Unnegotiated)?;
            if let Some(accepted) = parser.feed(&data)? {
                events.on_auth_accepted(accepted);
                return Ok(true);
            }
        }
        Event::StreamReset {
            stream_id: AUTH_STREAM,
        } => {
            return Err(crate::AuthAcceptanceError::Malformed);
        }
        other => dispatch_event(other, events, state, handshake_pending),
    }
    Ok(false)
}

fn dispatch_event(
    ev: Event,
    events: &dyn ClientEvents,
    state: &mut LinkState,
    handshake_pending: &mut bool,
) {
    match ev {
        Event::StreamData { stream_id, data } => events.on_bytes(stream_id, data),
        Event::StateChanged(s) => {
            *state = s;
            if matches!(s, LinkState::Live | LinkState::Closed) {
                *handshake_pending = false;
            }
            events.on_state(s);
        }
        Event::StreamReset { stream_id } => events.on_reset(stream_id),
        Event::SessionAborted(reason) => events.on_session_aborted(reason),
        Event::SendBufferOverCap { stream_id } => {
            #[cfg(test)]
            OVER_CAP_LOGGED.with(|n| n.set(n.get() + 1));
            log::error!(
                "stream {stream_id}: send buffer over the hard cap, a producer ignores its send gate"
            );
        }
        Event::InvalidHandshakeResponse { reason } => {
            events.on_protocol_failure(if reason == crate::HsPayloadError::BadVersion {
                crate::ProtocolFailure::UnsupportedProtocol {
                    supported: crate::handshake_payload::HS_VERSION,
                }
            } else {
                crate::ProtocolFailure::InvalidHandshake { reason }
            });
            log::warn!("server sent an invalid authenticated handshake response: {reason}");
        }
        Event::MissingRequiredFeatures { required, enabled } => {
            events.on_protocol_failure(crate::ProtocolFailure::MissingRequiredFeatures {
                required,
                enabled,
            });
        }
        Event::UnofferedFeatureEnabled { enabled } => {
            events.on_protocol_failure(crate::ProtocolFailure::UnofferedFeatures { enabled });
            #[cfg(test)]
            UNOFFERED_LOGGED.with(|n| n.set(n.get() + 1));
            log::warn!(
                "server enabled a transport feature it was not offered: {:#010x}",
                enabled.bits()
            );
        }
        // `OutputResync` is server-side only (the backend decides to drop its
        // backlog); a client driver never needs to act on it.
        // `HandshakeDone`/`Rehomed` currently have no client-driver-level
        // callback of their own. `OffsetSpaceExhausted` was acted on before
        // dispatch (see `poll_events_abandoning_on_exhaustion`).
        Event::HandshakeDone
        | Event::PeerKeyConfirmed { .. }
        | Event::Rehomed { .. }
        | Event::OutputResync
        | Event::OffsetSpaceExhausted { .. } => {}
    }
}

/// The connection's events, with one rule applied first: a stream out of
/// offset space ends the connection here, silently ([`Connection::abandon`]),
/// so the server retains the session and the `Closed` that follows reaches
/// the owner at once -- the app and the console `qsh` both reconnect warm
/// (spec §4.14).
fn poll_events_abandoning_on_exhaustion(conn: &mut Connection) -> Vec<Event> {
    let mut events = conn.poll_events();
    if events
        .iter()
        .any(|e| matches!(e, Event::OffsetSpaceExhausted { .. }))
    {
        log::warn!("a stream reached the end of its offset space; dropping the connection");
        conn.abandon();
        events.extend(conn.poll_events());
    }
    events
}

#[cfg(test)]
#[path = "driver_std_tests.rs"]
mod tests;
