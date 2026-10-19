//! Client driver on top of the sans-IO `Connection` core: a dedicated thread
//! owning a blocking `std::net::UdpSocket` and the client `Connection`.
//!
//! The `conn` module does no I/O; this driver adds the real network, timers,
//! and handshake retransmit. It exposes plain Rust traits to the outside
//! (`ClientEvents`, `Binder`).
//!
//! Design. The thread runs a loop: it computes the sleep deadline as the
//! nearer of the core timer (`Connection::next_timeout`) and its own
//! handshake-retransmit timer, clamps it from above with a short command poll
//! interval, sets `set_read_timeout`, and does `recv_from` (the socket is
//! deliberately unconnected -- see `make_socket`). A packet goes into
//! `on_datagram` with its real source address, together with up to
//! `READY_DRAIN_MAX` more that have already arrived; then, after every wake-up
//! whatever woke it, the timers that are due run
//! (`Connection::on_timeout_if_due`, and the msg1 retransmit). Afterward it
//! sends all outgoing datagrams and forwards core events to the external
//! callbacks. Commands (`send_bytes`, `rebind`, `close`) arrive over
//! an mpsc channel and are drained at the start of each iteration.
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
//! Graceful stop vs. detach. `Command::Close` (`StdClient::close`) emits the
//! client's `Close` frame (`Connection::close`) and flushes it to the socket
//! before the loop exits, so the server tears the backend down immediately
//! instead of retaining it for a warm reconnect -- this is what a
//! user-initiated disconnect uses. `Command::Detach` (`StdClient::detach`)
//! ends the loop WITHOUT calling `Connection::close`: no further datagram
//! goes out at all, so the server just sees silence and treats it exactly
//! like any other liveness-timeout death -- it RETAINS the backend for a
//! later warm reattach. This is what the app's own internal forced reconnect
//! uses, so a follow-up reconnect gets a warm reattach (echo-ack/prediction
//! state survives) instead of degenerating into a cold create. Detach is
//! STICKY: once `Command::Detach` has been processed, the command channel
//! later disconnecting (the client handle dropped without an explicit call)
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
//! iteration after signing finishes at the earliest (and up to
//! `COMMAND_POLL_INTERVAL`, 50 ms, later than that, if the driver happens to
//! be parked in `recv_from` when the result arrives -- negligible against the
//! 5-second `AUTH_DEADLINE`, but it is the same self-pipe latency debt the
//! module's opening doc already calls out for commands in general).
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

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use crate::auth::{encode_auth_record, AuthSigner, AUTH_NONCE_LEN, AUTH_STREAM};
use crate::conn::{
    Connection, ConnectionConfig, Consumption, Datagram, Event, LinkState, Stats, StreamClass,
    StreamProgress, UseRoadError,
};
use crate::features::Features;
use crate::handshake_payload::StartKind;
use crate::paths::RoadInfo;
use crate::recovery_handshake::RecoveryEndpoint;
use crate::send_gate::{GateKind, GateTable, GateWait};
use crate::udp_buffers::{tune_udp_buffers, BufferReport};

/// Upper bound on the loop's sleep: how often the driver wakes up to check
/// the command queue, even if the network and timers are quiet. A deliberate
/// simplification versus instant wakeup of the socket from another thread (a
/// known debt: a self-pipe/socketpair would give zero input latency instead
/// of this 50 ms).
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Retransmit period for the handshake message until `Live` is established.
pub(crate) const HANDSHAKE_RETRANSMIT: Duration = Duration::from_millis(500);

/// If `socket.recv` blocked far longer than the (<= `COMMAND_POLL_INTERVAL`)
/// read timeout we asked for, the OS froze this thread -- an app Doze/standby.
/// Rather than declare the link dead (which forces a slow SSH reconnect), the
/// driver treats the wake as a rebind/resume: a fresh socket on the current
/// network, a restarted liveness window, and a forced PING, so a still-alive
/// server session hot-migrates to us over UDP. Chosen well above any GC or
/// scheduling pause (~1 s) and below the client death window.
const FREEZE_RESUME_AFTER: Duration = Duration::from_secs(5);

/// Receive buffer size for a single UDP datagram.
const RECV_BUF_LEN: usize = 64 * 1024;

/// How many already-arrived datagrams one pass of the loop takes in after the
/// one it woke for, before it runs timers and hands out events (spec §4.1):
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
/// several times `COMMAND_POLL_INTERVAL`, the longest it can take to notice.
const PROGRESS_REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// How long `StdClient::use_road` waits for the driver to act on the request: the same bound
/// as `PROGRESS_REPLY_TIMEOUT`, for the same reason.
const USE_ROAD_REPLY_TIMEOUT: Duration = PROGRESS_REPLY_TIMEOUT;

/// Whether to publish statistics now. Pure, so the rule is checked without a
/// socket: on change, and once every [`STATS_HEARTBEAT`] regardless.
fn stats_are_due(cur: Stats, last: Stats, since_last_publish: Duration) -> bool {
    cur != last || since_last_publish >= STATS_HEARTBEAT
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

/// A command to the driver thread.
enum Command {
    #[cfg(test)]
    UnconsumedForTest(Sender<Vec<(u8, u64)>>),
    Send {
        stream_id: u8,
        data: Vec<u8>,
    },
    Rebind,
    /// Graceful stop: emit the client's `Close` frame before tearing down (see
    /// the module doc). Used by `StdClient::close`.
    Close,
    /// Silent local teardown: no `Close` frame goes on the wire (see the
    /// module doc). Used by `StdClient::detach`.
    Detach,
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
    /// Bytes a bounded producer admitted through the stream's gate (see
    /// `StdClient::send_bytes_bounded`): taken into the connection, and off
    /// the gate's pending count in the same step.
    SendGated {
        stream_id: u8,
        data: Vec<u8>,
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
    /// How the streams nobody declared count their consumption (spec
    /// §4.10.1): `OnDelivery` for the app, `Explicit` for the console
    /// client (spec §4.13). AUTH_STREAM is always consumed by the driver.
    pub default_consumption: Consumption,
    /// Per-stream declarations, applied after the default.
    pub stream_consumption: Vec<(u8, Consumption)>,
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
    tx: Mutex<Sender<Command>>,
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
        StdClient {
            tx: Mutex::new(tx),
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

    /// Queue bytes of stream `stream_id` for reliable sending.
    pub fn send_bytes(&self, stream_id: u8, data: Vec<u8>) {
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::Send { stream_id, data });
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
    /// `send_bytes` stays as it was: keystrokes, pastes and resizes are
    /// fire-and-forget.
    pub fn send_bytes_bounded(
        &self,
        stream_id: u8,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), SendBlocked> {
        if self.driver_thread.is_none() {
            return Err(SendBlocked::Gone);
        }
        if self.driver_thread == Some(thread::current().id()) {
            return Err(SendBlocked::OnDriverThread);
        }
        let gate = self.gates.gate(stream_id, GateKind::Pipe);
        match gate.wait_open_for(timeout) {
            GateWait::Open => {}
            GateWait::TimedOut => return Err(SendBlocked::Full),
            GateWait::Closed => return Err(SendBlocked::Gone),
        }
        let n = data.len() as u64;
        gate.admit(n);
        let sent = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::SendGated { stream_id, data });
        if sent.is_err() {
            let _ = gate.transfer(n, 0);
            return Err(SendBlocked::Gone);
        }
        Ok(())
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
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::Close);
        self.join_driver();
    }

    /// Tear the driver down locally WITHOUT emitting the client's `Close`
    /// frame: the server just sees silence and RETAINS the backend for a
    /// later warm reattach, instead of tearing it down at once (see the
    /// module doc). For the app's own internal forced reconnect -- NOT a
    /// user-initiated disconnect, which must keep using `close`.
    pub fn detach(&self) {
        let _ = self
            .tx
            .lock()
            .expect("command channel mutex")
            .send(Command::Detach);
        self.join_driver();
    }

    /// Wait for the driver thread to finish after a teardown command
    /// (`Close`/`Detach`) was sent. Guards against self-join. Callbacks
    /// (`ClientEvents`/`Binder`) run ON THE DRIVER THREAD; if a platform
    /// callback synchronously calls `close`/`detach`, `join` would block the
    /// driver waiting on itself -- deadlock. On its own thread we settle for
    /// having signaled the command: the driver will finish on its own once it
    /// returns from the callback and processes the command.
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

/// Take in up to `max` datagrams already waiting on `socket`, without waiting
/// for more. The socket is back in blocking mode before this returns, whatever
/// happened: left non-blocking, the loop's timed `recv_from` would return at
/// once for ever -- a busy spin.
fn drain_ready(
    socket: &UdpSocket,
    conn: &mut Connection,
    buf: &mut [u8],
    max: usize,
) -> Vec<Datagram> {
    let mut out = Vec::new();
    if socket.set_nonblocking(true).is_err() {
        return out;
    }
    for _ in 0..max {
        match socket.recv_from(buf) {
            Ok((len, src)) => out.extend(conn.on_datagram(Instant::now(), src, &buf[..len])),
            Err(_) => break,
        }
    }
    let _ = socket.set_nonblocking(false);
    out
}

/// A `recv` timeout surfaces as `WouldBlock` (unix) or `TimedOut` (windows).
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

    let mut socket = match make_socket(binder.as_ref()) {
        Some((s, buffers)) => {
            *buffers_out.lock().expect("buffers mutex") = Some(buffers);
            s
        }
        None => {
            events.on_state(LinkState::Closed);
            return;
        }
    };

    let mut sends = SendRecord::new(last_send_error, Arc::clone(&events));
    let allowlist_proof = matches!(cfg.auth, crate::conn::AuthPolicy::Allowlist(_));
    let mut conn = Connection::new(cfg);
    // Before msg1: no byte can arrive before these are in force.
    conn.set_default_consumption(setup.default_consumption);
    for (stream_id, consumption) in setup.stream_consumption {
        conn.set_stream_consumption(stream_id, consumption);
    }
    // The reserved server-direction record is consumed by this driver, never
    // by the application. Override even an explicit per-stream setup once;
    // on-delivery accounting owns its credit, with no duplicate report.
    conn.set_stream_consumption(AUTH_STREAM, Consumption::OnDelivery);
    let start = Instant::now();
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
    send_recovery_aware(&socket, &first_msg1, &mut sends, &mut conn);

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
    let mut last_stats_at = Instant::now();

    let mut buf = vec![0u8; RECV_BUF_LEN];

    loop {
        // 1. Commands from the channel (at the start of the iteration).
        let mut should_close = false;
        // Whether the teardown (once `should_close` is set) puts a `Close`
        // frame on the wire. Defaults to `true` so an implicit drop (the
        // channel disconnecting without an explicit `close`/`detach` call)
        // keeps today's behavior. `Command::Detach` flips it to `false` and
        // it STAYS false for the rest of this teardown -- in particular the
        // `Disconnected` arm below never sets it back to `true`, so a detach
        // can never be "resurrected" into a graceful Close by the client
        // handle being dropped afterward.
        let mut graceful = true;
        loop {
            match rx.try_recv() {
                Ok(Command::Send { stream_id, data }) => {
                    let now = Instant::now();
                    let out = conn.send(now, stream_id, &data);
                    send_all(&socket, &out, &mut sends);
                }
                Ok(Command::Rebind) => {
                    if let Some((new_sock, buffers)) = make_socket(binder.as_ref()) {
                        socket = new_sock;
                        *buffers_out.lock().expect("buffers mutex") = Some(buffers);
                        // Nudge migration: force an immediate PING from the
                        // new address (the server will migrate to the new
                        // source, and the client will also grab a fresh RTT
                        // reading). request_ping also restarts the
                        // congestion window and takes what is in flight for
                        // lost, so on_timeout resends it under the fresh
                        // window -- the oldest first, the rest as ACKs open
                        // it.
                        // request_ping also restarts the liveness window, so a
                        // rebind after a network gap is not counted as death.
                        let now = Instant::now();
                        conn.request_ping(now);
                        let out = conn.on_timeout(now);
                        send_all(&socket, &out, &mut sends);
                    }
                }
                Ok(Command::SetDeathAfter(after)) => conn.set_death_after(after),
                Ok(Command::SetPaths(addrs)) => conn.set_paths(addrs),
                Ok(Command::StreamProgress { stream_id, reply }) => {
                    let _ = reply.send(conn.stream_progress(stream_id));
                }
                Ok(Command::UseRoad { addr, reply }) => {
                    let now = Instant::now();
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
                            send_all(&socket, &out, &mut sends);
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
                Ok(Command::SendGated { stream_id, data }) => {
                    let now = Instant::now();
                    let n = data.len() as u64;
                    let out = conn.send(now, stream_id, &data);
                    send_all(&socket, &out, &mut sends);
                    let tail = conn.stream_progress(stream_id).unacked;
                    let _ = gates.gate(stream_id, GateKind::Pipe).transfer(n, tail);
                }
                #[cfg(test)]
                Ok(Command::UnconsumedForTest(reply)) => {
                    let _ = reply.send(conn.unconsumed_streams());
                }
                Ok(Command::Consumed { stream_id, n }) => {
                    let now = Instant::now();
                    let out = conn.on_consumed(now, stream_id, n);
                    send_all(&socket, &out, &mut sends);
                }
                Ok(Command::Close) => should_close = true,
                Ok(Command::Detach) => {
                    should_close = true;
                    graceful = false;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // The client was dropped without close()/detach() --
                    // finish up. Doesn't touch `graceful`: if a Detach was
                    // already processed above in this same drain, it stays
                    // non-graceful (sticky); otherwise this preserves the
                    // pre-existing implicit-drop behavior.
                    should_close = true;
                    break;
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
        while let Ok(AuthResult { generation, record }) = auth_rx.try_recv() {
            // A processed stop also retires results already queued by the signer.
            if !should_close && generation == auth_generation {
                match record {
                    Some(bytes) => {
                        let now = Instant::now();
                        let out = conn.send(now, AUTH_STREAM, &bytes);
                        send_all(&socket, &out, &mut sends);
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
                let now = Instant::now();
                let out = conn.close(now);
                send_all(&socket, &out, &mut sends);
            }
            // A detach tears down locally without putting anything on the
            // wire: the server just sees silence and retains the backend for
            // a warm reattach.
            break;
        }

        // 2. Sleep deadline: the nearer of the core timer and the handshake
        //    timer, clamped above by the command poll interval.
        let now = Instant::now();
        let mut deadline = conn.next_timeout();
        let handshake_deadline = if let Some(schedule) = conn.recovery_handshake() {
            schedule.next_deadline()
        } else {
            handshake_pending.then_some(handshake_sent_at + HANDSHAKE_RETRANSMIT)
        };
        if let Some(hs_deadline) = handshake_deadline {
            deadline = Some(deadline.map_or(hs_deadline, |d| d.min(hs_deadline)));
        }
        let cap = now + COMMAND_POLL_INTERVAL;
        let effective = match deadline {
            Some(d) => d.min(cap),
            None => cap,
        };
        // `set_read_timeout(Some(ZERO))` is an error in std, so never pass zero.
        let mut dt = effective.saturating_duration_since(now);
        if dt.is_zero() {
            dt = Duration::from_millis(1);
        }
        let _ = socket.set_read_timeout(Some(dt));

        // 3. Receive a packet or a timer firing.
        let mut out: Vec<Datagram> = Vec::new();
        // Captured BEFORE the (blocking) recv_from, so `now - recv_started`
        // measures how long the receive actually spanned -- the same whether
        // it returns a buffered packet or a read timeout.
        let recv_started = Instant::now();
        let recv_result = socket.recv_from(&mut buf);
        let now = Instant::now();
        // Doze/freeze wake: the recv spanned an OS freeze of this thread far
        // longer than the (<= COMMAND_POLL_INTERVAL) read timeout we asked for.
        // Resume like a rebind -- fresh socket on the current network, restarted
        // liveness, forced PING -- so a still-alive server session hot-migrates
        // to us over UDP, instead of the frozen gap being counted as silence and
        // closing the link (which would force a slow SSH reconnect). Done for
        // BOTH recv outcomes, before processing, so a stale buffered packet on
        // wake can't slip past the check.
        if now.saturating_duration_since(recv_started) > FREEZE_RESUME_AFTER {
            if let Some((new_sock, buffers)) = make_socket(binder.as_ref()) {
                socket = new_sock;
                *buffers_out.lock().expect("buffers mutex") = Some(buffers);
            }
            conn.request_ping(now);
        }
        match recv_result {
            // The real source, not the address originally dialled: the
            // socket is unconnected (see `make_socket`), so a reply from a
            // spare road, or from a live road that just moved, arrives with
            // its own genuine source address rather than the server's --
            // and `on_datagram` needs that real address both to answer a
            // `PathProbe` to the right place and to notice a move at all.
            Ok((len, src)) => {
                out.extend(conn.on_datagram(now, src, &buf[..len]));
                // And whatever else has already arrived, up to a bound.
                out.extend(drain_ready(&socket, &mut conn, &mut buf, READY_DRAIN_MAX));
            }
            // A read timeout needs nothing of its own: the timers below run
            // after every wake-up.
            Err(ref e) if is_read_timeout(e) => {}
            // Other receive errors -- skip, the socket is still alive. An
            // unconnected socket does not surface an ICMP port-unreachable
            // the way a `connect`-ed one did; this arm is now mostly
            // theoretical, kept for whatever transient OS-level failure
            // `recv_from` can still report.
            Err(_) => {}
        }
        // Timers after EVERY wake-up, not only after a read timeout (spec
        // §4.1): datagrams arriving more often than the read timeout used to
        // starve the PINGs, retransmits, `PathDown`, road checks and the
        // dead-road rule.
        let now = Instant::now();
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
            send_all(&socket, &conn.retransmit_handshake(), &mut sends);
            handshake_sent_at = now;
        }
        send_recovery_aware(&socket, &out, &mut sends, &mut conn);

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
                at: Instant::now(),
            });
        }

        // 4. Forward core events and statistics.
        for ev in poll_events_abandoning_on_exhaustion(&mut conn) {
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
                    send_all(&socket, &conn.on_timeout(now), &mut sends);
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
                    spawn_auth_signing(
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
    auth_tx: Sender<AuthResult>,
) {
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
    });
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
mod tests {
    use super::*;
    use crate::auth::{parse_auth_record, AuthError, AuthRecord};
    use crate::conn::AuthPolicy;
    use crate::reliability::StreamFrame;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    /// Spec §5.5: a live client says what its handshake agreed -- published
    /// before `Live` reaches the owner -- and a client that never ran says
    /// nothing.
    #[test]
    fn a_client_says_what_its_handshake_agreed() {
        let (client, _arrivals) = crate::test_peer::client_whose_server_stops_acknowledging();
        assert_eq!(
            client.features(),
            Some(crate::Features::from_bits(
                crate::Features::SUPPORTED.bits() & !crate::Features::AUTH_ACCEPTED.bits(),
            ))
        );
        client.detach();
        assert_eq!(StdClient::dead().features(), None);
    }

    /// Spec §4.12: a client's socket is sized and says what it got.
    #[test]
    fn a_client_says_what_its_socket_buffers_are() {
        let (client, _arrivals) = crate::test_peer::client_whose_server_stops_acknowledging();
        let buffers = client.socket_buffers().expect("published with the socket");
        assert_eq!(buffers.recv_requested, crate::SOCKET_BUFFER_REQUEST);
        assert!(
            buffers.recv_granted > 0 && buffers.send_granted > 0,
            "{buffers:?}"
        );
        client.detach();
        assert_eq!(StdClient::dead().socket_buffers(), None);
    }

    /// A changed counter publishes at once -- the ordinary case, and the
    /// only one the driver had before the heartbeat.
    #[test]
    fn changed_statistics_publish_immediately() {
        let last = Stats::default();
        let cur = Stats {
            rtt_ms: 42,
            ..Stats::default()
        };
        assert!(stats_are_due(cur, last, Duration::ZERO));
    }

    /// And unchanged statistics publish anyway once the heartbeat is up.
    /// This is the whole reason the floor exists: a road going quiet changes
    /// nothing in `Stats`, and the road table travels out with the report.
    #[test]
    fn unchanged_statistics_publish_once_the_heartbeat_is_up() {
        let same = Stats {
            rtt_ms: 42,
            ..Stats::default()
        };
        assert!(
            !stats_are_due(same, same, Duration::from_millis(999)),
            "nothing changed and the second is not up: nothing to say"
        );
        assert!(stats_are_due(same, same, STATS_HEARTBEAT));
    }

    #[test]
    fn authenticated_protocol_errors_reach_owner_before_closed() {
        struct Capture(Mutex<Vec<Option<crate::ProtocolFailure>>>);
        impl ClientEvents for Capture {
            fn on_bytes(&self, _: u8, _: Vec<u8>) {}
            fn on_stats(&self, _: Stats) {}
            fn on_reset(&self, _: u8) {}
            fn on_state(&self, state: LinkState) {
                assert_eq!(state, LinkState::Closed);
                self.0.lock().unwrap().push(None);
            }
            fn on_protocol_failure(&self, failure: crate::ProtocolFailure) {
                self.0.lock().unwrap().push(Some(failure));
            }
        }
        for (event, expected) in [
            (
                Event::InvalidHandshakeResponse {
                    reason: crate::HsPayloadError::BadVersion,
                },
                crate::ProtocolFailure::UnsupportedProtocol {
                    supported: crate::handshake_payload::HS_VERSION,
                },
            ),
            (
                Event::MissingRequiredFeatures {
                    required: Features::CHANNEL_GEOMETRY,
                    enabled: Features::NONE,
                },
                crate::ProtocolFailure::MissingRequiredFeatures {
                    required: Features::CHANNEL_GEOMETRY,
                    enabled: Features::NONE,
                },
            ),
        ] {
            let owner = Capture(Mutex::new(vec![]));
            let mut state = LinkState::Connecting;
            let mut pending = true;
            dispatch_event(event, &owner, &mut state, &mut pending);
            dispatch_event(
                Event::StateChanged(LinkState::Closed),
                &owner,
                &mut state,
                &mut pending,
            );
            assert_eq!(*owner.0.lock().unwrap(), vec![Some(expected), None]);
            assert!(!pending);
        }
    }

    struct OkBinder;
    impl Binder for OkBinder {
        fn bind(&self, _fd: i32) -> bool {
            true
        }
    }

    struct NullEvents;
    impl ClientEvents for NullEvents {
        fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
        fn on_state(&self, _state: LinkState) {}
        fn on_stats(&self, _stats: Stats) {}
        fn on_reset(&self, _stream_id: u8) {}
    }

    /// Events fake that counts `on_reset` calls and records the last
    /// `stream_id`, so a test can assert the dispatcher routed a
    /// `StreamReset` event exactly where it should.
    struct ResetCountEvents {
        reset_calls: AtomicUsize,
        last_stream_id: AtomicU8,
    }
    impl ResetCountEvents {
        fn new() -> Self {
            ResetCountEvents {
                reset_calls: AtomicUsize::new(0),
                last_stream_id: AtomicU8::new(0),
            }
        }
    }
    impl ClientEvents for ResetCountEvents {
        fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
        fn on_state(&self, _state: LinkState) {}
        fn on_stats(&self, _stats: Stats) {}
        fn on_reset(&self, stream_id: u8) {
            self.reset_calls.fetch_add(1, Ordering::SeqCst);
            self.last_stream_id.store(stream_id, Ordering::SeqCst);
        }
    }

    /// `Event::StreamReset` routed through `dispatch_event` must call
    /// `ClientEvents::on_reset` exactly once, with the event's `stream_id`.
    #[test]
    fn dispatch_event_routes_stream_reset_to_on_reset() {
        let events = ResetCountEvents::new();
        let mut state = LinkState::Live;
        let mut handshake_pending = false;

        dispatch_event(
            Event::StreamReset { stream_id: 3 },
            &events,
            &mut state,
            &mut handshake_pending,
        );

        assert_eq!(events.reset_calls.load(Ordering::SeqCst), 1);
        assert_eq!(events.last_stream_id.load(Ordering::SeqCst), 3);

        // OutputResync is server-side only and must NOT reach on_reset.
        dispatch_event(
            Event::OutputResync,
            &events,
            &mut state,
            &mut handshake_pending,
        );
        assert_eq!(
            events.reset_calls.load(Ordering::SeqCst),
            1,
            "OutputResync must not trigger on_reset"
        );
    }

    /// Spec §4.7.1: on a client the hard-cap report is only a line in
    /// the log -- no callback fires and the link state stays as it was.
    #[test]
    fn a_hard_cap_report_reaches_no_callback() {
        let events = ResetCountEvents::new();
        let mut state = LinkState::Live;
        let mut handshake_pending = true;
        let logged_before = OVER_CAP_LOGGED.with(std::cell::Cell::get);
        dispatch_event(
            Event::SendBufferOverCap { stream_id: 0 },
            &events,
            &mut state,
            &mut handshake_pending,
        );
        assert_eq!(
            OVER_CAP_LOGGED.with(std::cell::Cell::get) - logged_before,
            1,
            "the report took its own arm, the one that logs it"
        );
        assert_eq!(events.reset_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state, LinkState::Live);
        assert!(handshake_pending, "the handshake bookkeeping is untouched");
    }

    /// Spec §5.2: a server that enabled what was not offered is a line in
    /// the log; the `Closed` that follows is what the owner hears.
    #[test]
    fn an_unoffered_feature_report_is_logged_and_reaches_no_callback() {
        let events = ResetCountEvents::new();
        let mut state = LinkState::Connecting;
        let mut handshake_pending = true;
        let before = UNOFFERED_LOGGED.with(std::cell::Cell::get);
        dispatch_event(
            Event::UnofferedFeatureEnabled {
                enabled: crate::Features::STREAM_CREDIT,
            },
            &events,
            &mut state,
            &mut handshake_pending,
        );
        assert_eq!(UNOFFERED_LOGGED.with(std::cell::Cell::get) - before, 1);
        assert_eq!(events.reset_calls.load(Ordering::SeqCst), 0);
        assert_eq!(state, LinkState::Connecting);
    }

    /// `make_socket` creates a bound socket and calls the binder, but must
    /// NOT connect it to one address: a connected socket's kernel-level peer
    /// filter would drop an answer arriving from a spare road (or from a
    /// live road that just moved), which is a different source than
    /// whatever address the session was first dialled against.
    #[test]
    fn make_socket_binds_without_connecting() {
        struct FlagBinder(Arc<AtomicBool>);
        impl Binder for FlagBinder {
            fn bind(&self, _fd: i32) -> bool {
                self.0.store(true, Ordering::SeqCst);
                true
            }
        }
        let called = Arc::new(AtomicBool::new(false));
        let binder = FlagBinder(Arc::clone(&called));
        let (sock, buffers) = make_socket(&binder).expect("socket created");
        assert!(called.load(Ordering::SeqCst), "binder was called");
        assert!(buffers.recv_granted > 0, "{buffers:?}");
        assert!(
            sock.peer_addr().is_err(),
            "the socket must not be connected to one address, or a reply from a spare road \
             could never reach it"
        );
    }

    /// A dead driver is inert: commands don't panic, statistics are zero.
    #[test]
    fn dead_client_is_inert() {
        let client = StdClient::dead();
        client.send_bytes(0, b"x".to_vec());
        client.rebind();
        assert_eq!(client.stats(), Stats::default());
        client.close();
    }

    /// `dead` creates no thread, so `close` shouldn't block.
    #[test]
    fn dead_client_close_returns() {
        let _binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let _events: Arc<dyn ClientEvents> = Arc::new(NullEvents);
        StdClient::dead().close();
    }

    /// Counts `on_send_error` calls and keeps what they said.
    #[derive(Default)]
    struct SendErrorEvents {
        told: Mutex<Vec<(SocketAddr, SendFailure)>>,
    }
    impl ClientEvents for SendErrorEvents {
        fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
        fn on_state(&self, _state: LinkState) {}
        fn on_stats(&self, _stats: Stats) {}
        fn on_reset(&self, _stream_id: u8) {}
        fn on_send_error(&self, to: SocketAddr, kind: std::io::ErrorKind, text: &str) {
            self.told
                .lock()
                .expect("told")
                .push((to, (kind, text.to_string())));
        }
    }

    fn os_error(code: i32) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(code))
    }

    /// The latest outcome is kept; the owner is told once per change of the
    /// error, however many retransmits fail the same way in between -- and
    /// not again when the same error comes back after a send went through.
    #[test]
    fn a_send_error_is_kept_and_told_once_per_change() {
        let events = Arc::new(SendErrorEvents::default());
        let shared = Arc::new(Mutex::new(None));
        let mut record = SendRecord::new(Arc::clone(&shared), events.clone());
        let unreachable = std::io::Error::from_raw_os_error(libc_codes::EHOSTUNREACH);
        let refused = std::io::Error::from_raw_os_error(libc_codes::EACCES);
        let to: SocketAddr = "192.0.2.7:60022".parse().expect("addr");

        record.note(to, os_error(libc_codes::EHOSTUNREACH));
        record.note(to, os_error(libc_codes::EHOSTUNREACH));
        record.note(to, os_error(libc_codes::EHOSTUNREACH));
        assert_eq!(
            *shared.lock().expect("shared"),
            Some((unreachable.kind(), unreachable.to_string()))
        );
        record.note(to, Ok(10));
        assert_eq!(*shared.lock().expect("shared"), None, "a send went through");
        record.note(to, os_error(libc_codes::EHOSTUNREACH));
        record.note(to, os_error(libc_codes::EACCES));
        assert_eq!(
            *shared.lock().expect("shared"),
            Some((refused.kind(), refused.to_string()))
        );
        assert_eq!(
            *events.told.lock().expect("told"),
            vec![
                (to, (unreachable.kind(), unreachable.to_string())),
                (to, (refused.kind(), refused.to_string())),
            ]
        );
    }

    /// Error numbers for the test above, without a dependency on `libc`.
    mod libc_codes {
        #[cfg(target_os = "linux")]
        pub const EHOSTUNREACH: i32 = 113;
        #[cfg(target_os = "macos")]
        pub const EHOSTUNREACH: i32 = 65;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        pub const EHOSTUNREACH: i32 = 113;
        pub const EACCES: i32 = 13;
    }

    /// A real client whose every send is refused by the OS: a broadcast
    /// address without `SO_BROADCAST` is refused on Linux. The OS's words
    /// reach the owner, once, although the handshake is retransmitted.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_client_whose_sends_fail_keeps_the_os_words() {
        let client_kp = crate::handshake::generate_keypair();
        let server_kp = crate::handshake::generate_keypair();
        let events = Arc::new(SendErrorEvents::default());
        let client = StdClient::connect(
            "255.255.255.255:9".parse().expect("addr"),
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [7u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            events.clone(),
            None,
        );
        // Three handshake retransmits at the least.
        thread::sleep(HANDSHAKE_RETRANSMIT * 3 + Duration::from_millis(200));
        let seen = client.last_send_error();
        client.close();
        assert_eq!(
            seen,
            Some((
                std::io::ErrorKind::PermissionDenied,
                "Permission denied (os error 13)".to_string()
            ))
        );
        assert_eq!(
            events.told.lock().expect("told").len(),
            1,
            "told once, not on every retransmit"
        );
    }

    /// A client with no driver never sent anything.
    #[test]
    fn a_dead_client_has_no_send_error() {
        assert_eq!(StdClient::dead().last_send_error(), None);
    }

    /// A client with no driver has nobody to ask: no answer, rather than a
    /// made-up zero that would read as "everything delivered".
    #[test]
    fn a_dead_client_has_no_answer_about_stream_progress() {
        assert_eq!(StdClient::dead().stream_progress(14), None);
    }

    /// Events adapter that forwards state changes into a channel, so the
    /// test can wait for `Live` deterministically instead of sleeping.
    struct StateEvents {
        tx: Mutex<Sender<LinkState>>,
    }
    impl ClientEvents for StateEvents {
        fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
        fn on_state(&self, state: LinkState) {
            let _ = self.tx.lock().expect("state channel mutex").send(state);
        }
        fn on_stats(&self, _stats: Stats) {}
        fn on_reset(&self, _stream_id: u8) {}
    }

    /// A graceful `close()` must put a `Close` frame on the wire BEFORE the
    /// driver thread exits, not merely mark local state -- otherwise the
    /// server retains the backend for up to an hour instead of tearing it
    /// down immediately (see `Connection::close`, `driver_std`'s
    /// `Command::Close` handling).
    ///
    /// Drives a REAL `StdClient` against a hand-rolled server loop (a bare
    /// `Connection` in the `Server` role, pumped directly over a std UDP
    /// socket -- no tokio needed): once the server observes the transition to
    /// `Closed`, `Connection::closed_gracefully()` tells apart a received
    /// `StreamFrame::Close` (this test) from a death-timeout close, which is
    /// exactly the distinction the server-side backend lifecycle depends on.
    #[test]
    fn stop_sends_close_frame() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");

        // The "server": a plain Connection in the Server role, pumped by hand
        // over the raw socket. Reports whether the Closed transition it saw
        // was graceful (a received Close) once it happens.
        let (done_tx, done_rx) = mpsc::channel::<bool>();
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            });
            let mut buf = [0u8; 65536];
            loop {
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = done_tx.send(false);
                        return;
                    }
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                for ev in server_conn.poll_events() {
                    if let Event::StateChanged(LinkState::Closed) = ev {
                        let _ = done_tx.send(server_conn.closed_gracefully());
                        return;
                    }
                }
            }
        });

        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        });
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [7u8; 16],
            StartKind::Cold,
            binder,
            events,
            None,
        );

        // Wait for Live before requesting a graceful close -- `Connection::close`
        // is a no-op without transport keys, so closing too early would prove
        // nothing about the wire behavior this test targets.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Live");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before reaching Live"),
            }
        }

        client.close();

        let graceful = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server observed a Closed transition in time");
        assert!(
            graceful,
            "the server must see the client's stop() as a graceful Close, not a death timeout"
        );
    }

    /// The mirror image of `stop_sends_close_frame`: `detach()` must tear the
    /// driver down WITHOUT putting a `Close` frame on the wire -- the server
    /// must just see silence, not a `StateChanged(Closed)` transition at all
    /// (graceful or otherwise) within a bounded window. This is exactly the
    /// distinction the server-side backend lifecycle's retain-for-warm-reattach
    /// depends on (see `session_manager`'s `SessionEnded { graceful }`).
    ///
    /// Same harness as `stop_sends_close_frame` (a real `StdClient` against a
    /// hand-rolled server `Connection` pumped over a raw UDP socket), except
    /// the server loop is bounded (a read timeout + deadline) instead of
    /// waiting forever for a `Closed` transition that, after a detach, should
    /// never come.
    #[test]
    fn detach_does_not_send_close_frame() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        server_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set server read timeout");

        // The "server": pumps datagrams for a bounded window and reports
        // whether it EVER observed a Closed transition (graceful or not).
        // `None` means the window elapsed with no such transition -- silence,
        // as `detach()` must produce.
        let (done_tx, done_rx) = mpsc::channel::<Option<bool>>();
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            });
            let mut buf = [0u8; 65536];
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if Instant::now() >= deadline {
                    let _ = done_tx.send(None);
                    return;
                }
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e) if is_read_timeout(e) => continue,
                    Err(_) => {
                        let _ = done_tx.send(None);
                        return;
                    }
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                for ev in server_conn.poll_events() {
                    if let Event::StateChanged(LinkState::Closed) = ev {
                        let _ = done_tx.send(Some(server_conn.closed_gracefully()));
                        return;
                    }
                }
            }
        });

        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        });
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [8u8; 16],
            StartKind::Cold,
            binder,
            events,
            None,
        );

        // Wait for Live before detaching -- otherwise the test would prove
        // nothing about wire behavior at Live (no transport keys yet).
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Live");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before reaching Live"),
            }
        }

        client.detach();

        let observed = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("server loop finished its bounded window in time");
        assert_eq!(
            observed, None,
            "detach() must not put a Close frame on the wire -- the server must see silence, \
             not any Closed transition (graceful or otherwise)"
        );
    }

    /// `ClientEvents` callbacks run ON the driver thread (see `join_driver`'s
    /// doc comment). Calling `stream_progress` from inside one must not block
    /// waiting for the driver's own command loop to answer -- that loop is
    /// the very thing running the callback, so it would be waiting on itself.
    /// The guard must return `None` at once, well under
    /// `PROGRESS_REPLY_TIMEOUT`, and the driver must keep running afterward.
    ///
    /// Same real-`StdClient`-against-a-hand-rolled-server harness as
    /// `stop_sends_close_frame`. The events object is handed an `Arc` to the
    /// very `StdClient` it belongs to (filled in right after `connect()`
    /// returns) and calls `stream_progress` back into it from `on_stats`,
    /// which fires repeatedly (at least once a second, per `STATS_HEARTBEAT`)
    /// once the driver is running -- so there is no race with the cell being
    /// filled a few nanoseconds later on the test thread: if the very first
    /// tick finds the cell still empty, a later tick simply tries again.
    #[test]
    fn stream_progress_from_a_callback_returns_none_at_once_without_stalling_the_driver() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        server_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set server read timeout");

        // A real "server": completes the handshake and keeps pumping
        // datagrams for a bounded window, exactly like the other harnesses
        // in this module -- just enough for the client to reach Live and for
        // its stats heartbeat to keep ticking.
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            });
            let mut buf = [0u8; 65536];
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if Instant::now() >= deadline {
                    return;
                }
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e) if is_read_timeout(e) => continue,
                    Err(_) => return,
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                let _ = server_conn.poll_events();
            }
        });

        /// Holds a handle to the `StdClient` it is attached to -- filled in
        /// by the test thread right after `connect()` returns -- and, the
        /// first time `on_stats` fires with that handle in place, calls
        /// `stream_progress` back into it from the driver thread and reports
        /// how long that took and what it returned.
        struct CallbackEvents {
            client: Mutex<Option<Arc<StdClient>>>,
            fired: AtomicBool,
            result_tx: Mutex<Sender<(Duration, Option<StreamProgress>)>>,
        }
        impl ClientEvents for CallbackEvents {
            fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
            fn on_state(&self, _state: LinkState) {}
            fn on_stats(&self, _stats: Stats) {
                if self.fired.load(Ordering::SeqCst) {
                    return; // already reported once
                }
                let Some(client) = self.client.lock().expect("client cell").clone() else {
                    return; // the test thread hasn't filled the cell yet -- try next tick
                };
                self.fired.store(true, Ordering::SeqCst);
                let start = Instant::now();
                let progress = client.stream_progress(0);
                let elapsed = start.elapsed();
                let _ = self
                    .result_tx
                    .lock()
                    .expect("result channel mutex")
                    .send((elapsed, progress));
            }
            fn on_reset(&self, _stream_id: u8) {}
        }

        let (result_tx, result_rx) = mpsc::channel();
        let events = Arc::new(CallbackEvents {
            client: Mutex::new(None),
            fired: AtomicBool::new(false),
            result_tx: Mutex::new(result_tx),
        });
        let events_for_client: Arc<dyn ClientEvents> = events.clone();

        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        };
        let client = Arc::new(StdClient::connect(
            server_addr,
            client_cfg,
            [10u8; 16],
            StartKind::Cold,
            binder,
            events_for_client,
            None,
        ));
        *events.client.lock().expect("client cell") = Some(Arc::clone(&client));

        let (elapsed, progress) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the callback reported a result in time");
        assert_eq!(
            progress, None,
            "a callback running on the driver thread must not get a real answer"
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "the guard must return at once instead of waiting on the driver's own command \
             loop for PROGRESS_REPLY_TIMEOUT: took {elapsed:?}"
        );

        // The driver must still be alive and processing commands after the
        // guard fired inside its own callback -- prove it with a normal
        // graceful close, exactly like `stop_sends_close_frame`.
        client.close();
    }

    /// A handshake retransmit must re-send the IDENTICAL msg1 bytes -- it must
    /// NOT re-mint a fresh initiator. Re-minting would produce a new Noise
    /// ephemeral (and thus a different msg1 body) every `HANDSHAKE_RETRANSMIT`,
    /// so every real driver retransmit would MISS the server's idempotent
    /// `ResendMsg2` path (which keys on a byte-identical msg1 body) and instead
    /// churn the per-session backend via `ColdReplace`/`WarmReattach` under
    /// handshake loss.
    ///
    /// Drives a REAL `StdClient` against a SILENT "server" -- a bare UDP socket
    /// that records every datagram but never replies with msg2 -- so the client
    /// never reaches `Live` and the retransmit timer keeps firing. Asserts the
    /// second datagram the server sees is byte-for-byte equal to the first.
    #[test]
    fn handshake_retransmit_resends_identical_msg1() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        // The silent "server": record datagrams, never reply.
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");

        let (dg_tx, dg_rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                match server_sock.recv_from(&mut buf) {
                    Ok((len, _src)) => {
                        if dg_tx.send(buf[..len].to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(NullEvents);
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [9u8; 16],
            StartKind::Cold,
            binder,
            events,
            None,
        );

        // The FIRST msg1 datagram, then its retransmit
        // (HANDSHAKE_RETRANSMIT = 500 ms).
        let first = dg_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first msg1 datagram");
        let second = dg_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("retransmitted msg1 datagram");
        assert_eq!(
            first, second,
            "a handshake retransmit must re-send the IDENTICAL msg1 bytes (fixed ephemeral), \
             not re-mint a fresh initiator"
        );

        client.close();
    }

    /// Spec §4.16: a daemon under load answers msg1 with a cookie; the
    /// driver sends msg1 again behind it at once. Here the daemon's first
    /// answer is lost, so only the retransmit -- with a fresh cookie --
    /// brings the client in.
    #[test]
    fn the_driver_retransmits_msg1_behind_the_daemons_cookie() {
        get_in_through_a_loaded_daemon(1, 0);
    }

    /// The retransmits carry the cookie too, in turn with the plain msg1:
    /// here the daemon's answer arrives but the client's retry behind it is
    /// lost, so the client gets in only if a later retransmit is that retry
    /// again. Were every retransmit the plain msg1, each would draw another
    /// cookie, waiting for the next retransmit -- plain again -- and the
    /// client would never get in.
    #[test]
    fn the_driver_retransmit_carries_the_cookie_after_the_retry_is_lost() {
        get_in_through_a_loaded_daemon(0, 1);
    }

    /// Review of slice 3, minor 1, through the real driver: a party on the
    /// path answers msg1 with a cookie of its own, the daemon predates
    /// cookies (it drops every msg1 behind one), and its first msg2 is
    /// lost. Only a plain retransmit can bring the client in, and the
    /// driver's turns send one.
    #[test]
    fn the_driver_gets_past_a_forged_cookie_to_a_daemon_that_predates_cookies() {
        use crate::wire::{encode_cookie_reply, parse, Frame, Kind};
        use crate::wire::{COOKIE_ECHO_LEN, COOKIE_LEN};
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_pub = server_kp.public;
        let client_pub = client_kp.public;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the server socket");
        let server_addr = sock.local_addr().expect("its address");
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        let behind_cookie = Arc::new(AtomicUsize::new(0));
        let plain = Arc::new(AtomicUsize::new(0));
        let (behind_seen, plain_seen) = (Arc::clone(&behind_cookie), Arc::clone(&plain));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_seen = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let mut conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            conn.act_as_legacy_peer_for_test();
            // The session manager's `ResendMsg2`, as an old daemon has it.
            let mut answered: Option<(Vec<u8>, Vec<u8>)> = None;
            let mut buf = [0u8; 65536];
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until && !stop_seen.load(Ordering::SeqCst) {
                let Ok((len, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let dg = buf[..len].to_vec();
                let out = match parse(&dg) {
                    Ok(Frame::Handshake {
                        kind: Kind::HandshakeInitCookie,
                        ..
                    }) => {
                        // An old parser's `BadKind`.
                        behind_seen.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    Ok(Frame::Handshake {
                        kind: Kind::HandshakeInit,
                        body,
                    }) => {
                        plain_seen.fetch_add(1, Ordering::SeqCst);
                        if let Some((msg1, msg2)) = &answered {
                            if *msg1 == dg {
                                let _ = sock.send_to(msg2, src);
                            }
                            continue;
                        }
                        // The party on the path saw msg1 go by: a cookie of
                        // its own, in the daemon's name.
                        let mut echo = [0u8; COOKIE_ECHO_LEN];
                        echo.copy_from_slice(&body[..COOKIE_ECHO_LEN]);
                        let _ = sock.send_to(&encode_cookie_reply(&echo, &[0xEE; COOKIE_LEN]), src);
                        let out = conn.on_datagram(Instant::now(), src, &dg);
                        let msg2 = out.first().expect("msg2").bytes.clone();
                        answered = Some((dg, msg2));
                        // And that first msg2 is lost.
                        continue;
                    }
                    _ => conn.on_datagram(Instant::now(), src, &dg),
                };
                for d in &out {
                    let _ = sock.send_to(&d.bytes, d.to);
                }
            }
        });
        let (tx, rx) = mpsc::channel();
        let client = StdClient::connect(
            server_addr,
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_pub),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [7; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(StateEvents { tx: Mutex::new(tx) }),
            None,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!(
                    "the client never got in: {} msg1s behind the cookie, {} plain",
                    behind_cookie.load(Ordering::SeqCst),
                    plain.load(Ordering::SeqCst)
                ),
            }
        }
        assert!(
            behind_cookie.load(Ordering::SeqCst) >= 1,
            "it took the cookie"
        );
        assert!(
            plain.load(Ordering::SeqCst) >= 2,
            "and sent the plain msg1 again"
        );
        assert_eq!(client.features(), Some(Features::NONE));
        client.detach();
        stop.store(true, Ordering::SeqCst);
        server.join().expect("the server thread");
    }

    /// A real `StdClient` against a daemon under load from its first
    /// datagram on (the session manager's check in front of one server
    /// connection) that loses its first `lost_replies` cookie replies and
    /// the first `lost_retries` msg1s behind a cookie. Fails unless the
    /// client gets in, and on a msg1 that carried a valid cookie.
    fn get_in_through_a_loaded_daemon(lost_replies: u32, lost_retries: u32) {
        use crate::cookie::{CookieCheck, LoadLimits, Verdict};
        use crate::wire::{encode_handshake, parse, Frame, Kind};
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_pub = server_kp.public;
        let client_pub = client_kp.public;
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the server socket");
        let server_addr = sock.local_addr().expect("its address");
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        let proven = Arc::new(AtomicBool::new(false));
        let proven_seen = Arc::clone(&proven);
        // Set once the client is in: the server thread then ends within one
        // read timeout instead of spinning on for the rest of its 10 s.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_seen = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let mut check = CookieCheck::with_limits(
                Instant::now(),
                LoadLimits {
                    handshakes_per_window: 0,
                    probation_seats: 0,
                },
            );
            let mut conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut replies = 0;
            let mut retries = 0;
            let mut buf = [0u8; 65536];
            let until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < until && !stop_seen.load(Ordering::SeqCst) {
                let Ok((len, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let dg = buf[..len].to_vec();
                let out = match parse(&dg) {
                    Ok(Frame::Handshake {
                        kind: kind @ (Kind::HandshakeInit | Kind::HandshakeInitCookie),
                        body,
                    }) => {
                        if kind == Kind::HandshakeInitCookie {
                            retries += 1;
                            if retries <= lost_retries {
                                continue;
                            }
                        }
                        match check.check(Instant::now(), src, kind, body, 0) {
                            Verdict::Reply(reply) => {
                                replies += 1;
                                if replies > lost_replies {
                                    let _ = sock.send_to(&reply, src);
                                }
                                continue;
                            }
                            Verdict::Handshake { msg1, proven } => {
                                proven_seen.store(proven, Ordering::SeqCst);
                                conn.on_datagram(
                                    Instant::now(),
                                    src,
                                    &encode_handshake(Kind::HandshakeInit, msg1),
                                )
                            }
                            Verdict::Drop => continue,
                        }
                    }
                    _ => conn.on_datagram(Instant::now(), src, &dg),
                };
                for d in &out {
                    let _ = sock.send_to(&d.bytes, d.to);
                }
            }
        });
        let (tx, rx) = mpsc::channel();
        let client = StdClient::connect(
            server_addr,
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_pub),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(StateEvents { tx: Mutex::new(tx) }),
            None,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("the client never got in through the cookie"),
            }
        }
        assert!(
            proven.load(Ordering::SeqCst),
            "the msg1 worked on carried a valid cookie"
        );
        client.detach();
        stop.store(true, Ordering::SeqCst);
        server.join().expect("the server thread");
    }

    /// A signer configured on the client turns the end of the handshake into
    /// an AUTH record on `AUTH_STREAM`, signed over THIS session's own
    /// handshake hash -- not a fabricated or stale one (`server.handshake_hash()`
    /// is read from the same `Connection` that just completed the handshake
    /// this signature is checked against).
    #[test]
    fn the_driver_sends_its_proof_as_soon_as_the_handshake_finishes() {
        struct StubSigner;
        impl AuthSigner for StubSigner {
            fn sign(
                &self,
                handshake_hash: &[u8; 32],
                _nonce: Option<&[u8; AUTH_NONCE_LEN]>,
            ) -> Result<AuthRecord, AuthError> {
                Ok(AuthRecord {
                    public_key: b"pub".to_vec(),
                    // Echo the hash back so the test can prove the signer got
                    // THIS session's value.
                    signature: handshake_hash.to_vec(),
                    v2: None,
                })
            }
        }

        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");

        // The "server": a plain Connection in the Server role, pumped by hand
        // over the raw socket -- same harness as `stop_sends_close_frame`.
        // Reports the first StreamData chunk it sees, plus this session's
        // handshake hash, so the test can check both the stream id and that
        // the signed bytes are THIS session's hash, not some other one.
        //
        // `client_pub` is copied out before the harness thread takes
        // ownership of the rest of the fixture.
        let client_pub = client_kp.public;
        let (done_tx, done_rx) = mpsc::channel::<(u8, Vec<u8>, [u8; 32])>();
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                // `on_datagram` -- the entry point this hand-pumped harness
                // drives -- refuses `SshSignature`, having no probation stage
                // to enforce it with (`conn::tests::
                // on_datagram_refuses_the_signature_policy`). Nothing here
                // checks a proof anyway; the CLIENT still runs the signature
                // policy, which is what makes it sign.
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut buf = [0u8; 65536];
            loop {
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                for ev in server_conn.poll_events() {
                    if let Event::StreamData { stream_id, data } = ev {
                        let _ = done_tx.send((stream_id, data, server_conn.handshake_hash()));
                        return;
                    }
                }
            }
        });

        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(NullEvents);
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [10u8; 16],
            StartKind::Cold,
            binder,
            events,
            Some(Arc::new(StubSigner)),
        );

        let (stream_id, data, server_hash) = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server observed a StreamData event in time");
        assert_eq!(stream_id, AUTH_STREAM, "the proof goes on the auth stream");
        let record = parse_auth_record(&data).expect("a well-formed record");
        assert_eq!(record.public_key, b"pub");
        assert_eq!(
            record.signature,
            server_hash.to_vec(),
            "the client signed this session's handshake hash"
        );

        client.close();
    }

    /// Closing the driver while an off-thread signer is still working must
    /// not hang: `close()` waits only for the DRIVER thread, never for the
    /// signer's short-lived thread -- an `AgentSigner` can block indefinitely
    /// (no read timeout on its socket, by design), so joining it here would
    /// defeat the entire point of moving signing off the driver thread. The
    /// signer must still be able to run to completion afterward without the
    /// test process observing anything worse than nothing happening: its
    /// result is sent to a channel whose receiver (`run_driver`'s `auth_rx`)
    /// is long gone by then, and `mpsc::Sender::send` on a disconnected
    /// receiver returns an error rather than panicking (see
    /// `spawn_auth_signing`) -- this test cannot observe that `send`'s
    /// `Result` directly (it is discarded in production code), so what it
    /// asserts instead is the part that WOULD fail loudly if something were
    /// wrong: the signer thread reaching its own end normally.
    #[test]
    fn close_does_not_wait_for_an_in_flight_signer() {
        struct SlowSigner {
            release: Mutex<Receiver<()>>,
            // Signaled from inside `sign`, right before it returns, so the
            // test can wait (bounded) for the signer to run to completion
            // instead of a fixed, unenforced sleep.
            finished: Sender<()>,
        }
        impl AuthSigner for SlowSigner {
            fn sign(
                &self,
                handshake_hash: &[u8; 32],
                _nonce: Option<&[u8; AUTH_NONCE_LEN]>,
            ) -> Result<AuthRecord, AuthError> {
                // Blocks until the test releases it -- standing in for an
                // `AgentSigner` waiting on a human touch.
                let _ = self.release.lock().expect("release-gate mutex").recv();
                let record = AuthRecord {
                    public_key: b"pub".to_vec(),
                    signature: handshake_hash.to_vec(),
                    v2: None,
                };
                let _ = self.finished.send(());
                Ok(record)
            }
        }

        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        // Copied out before the harness thread takes ownership of the rest.
        let client_pub = client_kp.public;
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                // `on_datagram` -- the entry point this hand-pumped harness
                // drives -- refuses `SshSignature`, having no probation stage
                // to enforce it with (`conn::tests::
                // on_datagram_refuses_the_signature_policy`). Nothing here
                // checks a proof anyway; the CLIENT still runs the signature
                // policy, which is what makes it sign.
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut buf = [0u8; 65536];
            loop {
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                server_conn.poll_events();
            }
        });

        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (finished_tx, finished_rx) = mpsc::channel::<()>();
        let signer: Arc<dyn AuthSigner> = Arc::new(SlowSigner {
            release: Mutex::new(release_rx),
            finished: finished_tx,
        });

        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        });
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [11u8; 16],
            StartKind::Cold,
            binder,
            events,
            Some(signer),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Live");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before reaching Live"),
            }
        }

        // The signer is now blocked inside `sign`, waiting on `release_rx`.
        // `close()` must return without waiting for it -- if it incorrectly
        // joined the signing thread, this would hang until the timeout below
        // fires, since the signer isn't released yet.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            client.close();
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("close() must not block on an in-flight signer");

        // Let the signer finish now that the driver -- and with it,
        // `auth_rx` -- is already gone. It must still run to completion
        // (`spawn_auth_signing`'s `auth_tx.send` then errors on the dropped
        // receiver, which is discarded rather than panicking): a bounded
        // wait for its own "I'm done" signal, not a fixed sleep with nothing
        // asserted, so a hang or a panic before this point fails the test.
        let _ = release_tx.send(());
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the signer must run to completion even after the driver is gone");
    }

    /// Regression for routing the signing thread's result back through a
    /// CLONE of the external command channel: `mpsc::Receiver::try_recv`
    /// reports `Disconnected` only once every `Sender` for that channel is
    /// gone, and a `StdClient` simply dropped -- no `close()`, no `detach()`
    /// -- relies on its own `Sender` being the ONLY one, so that dropping it
    /// disconnects `rx` and ends the driver loop (the `TryRecvError::
    /// Disconnected` arm in the command-drain loop). A driver-held clone
    /// of that same `Sender` (kept alive in `run_driver`'s stack frame for
    /// the whole loop, to hand to the signing thread) would keep the channel
    /// connected forever regardless of what the caller does, and this test
    /// would then time out.
    ///
    /// Drives `run_driver` directly (bypassing `StdClient::connect`) so the
    /// test can hold its own `Sender<Command>` and drop it deliberately,
    /// with its own `JoinHandle` to prove the driver thread actually returns
    /// -- something `StdClient` intentionally does not expose (dropping a
    /// `JoinHandle` detaches the OS thread; it proves nothing about whether
    /// the thread has finished).
    #[test]
    fn dropping_the_command_channel_ends_the_driver_even_with_a_signer() {
        struct StubSigner;
        impl AuthSigner for StubSigner {
            fn sign(
                &self,
                handshake_hash: &[u8; 32],
                _nonce: Option<&[u8; AUTH_NONCE_LEN]>,
            ) -> Result<AuthRecord, AuthError> {
                Ok(AuthRecord {
                    public_key: b"pub".to_vec(),
                    signature: handshake_hash.to_vec(),
                    v2: None,
                })
            }
        }

        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        // Copied out before the harness thread takes ownership of the rest.
        let client_pub = client_kp.public;
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                // `on_datagram` -- the entry point this hand-pumped harness
                // drives -- refuses `SshSignature`, having no probation stage
                // to enforce it with (`conn::tests::
                // on_datagram_refuses_the_signature_policy`). Nothing here
                // checks a proof anyway; the CLIENT still runs the signature
                // policy, which is what makes it sign.
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut buf = [0u8; 65536];
            loop {
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                server_conn.poll_events();
            }
        });

        let (tx, rx) = mpsc::channel::<Command>();
        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let stats = Arc::new(Mutex::new(Stats::default()));
        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        });
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        };
        let signer: Option<Arc<dyn AuthSigner>> = Some(Arc::new(StubSigner));
        let handle = thread::spawn(move || {
            run_driver(
                HandshakeTarget::Single(server_addr),
                client_cfg,
                [13u8; 16],
                StartKind::Cold,
                binder,
                events,
                signer,
                DriverSetup::default(),
                rx,
                stats,
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(RoadSnapshot::default())),
                Arc::new(GateTable::new()),
                Arc::new(Mutex::new(None)),
                Arc::new(Mutex::new(None)),
            );
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Live");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before reaching Live"),
            }
        }
        // Give the (instantaneous) signer its full round trip -- HandshakeDone,
        // spawn, sign, AuthDone, conn.send -- every chance to happen before
        // the channel is dropped, so a regression that kept `rx` alive via a
        // leftover `Sender` clone has already had its opportunity to bite.
        thread::sleep(Duration::from_millis(150));

        // Drop the ONLY sender for `rx` without close()/detach() -- exactly
        // what happens when a `StdClient` goes out of scope unasked. The
        // driver must notice on its own and return; PING keeps the link
        // Live throughout (CLIENT_DEATH_AFTER is 45 s), so nothing but the
        // `Disconnected` detection can end this within the bound below.
        drop(tx);

        let (done_tx, done_rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            let _ = handle.join();
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(Duration::from_secs(5)).expect(
            "the driver must end once its only external command-channel sender is dropped, \
             even with a signer configured",
        );
    }

    /// Spin up a bare `Connection` in the `Server` role on a real UDP socket
    /// (in a background thread, echoing back whatever bytes it receives on
    /// any stream) and connect a real `StdClient` to it. Returns the client
    /// together with the address it is live against, once `LinkState::Live`
    /// is reached.
    ///
    /// Modeled on the pattern several tests above hand-roll inline (a
    /// server `Connection` pumped over a raw socket, a `StdClient` dialled
    /// against it, waiting on `LinkState::Live` via `StateEvents`) -- those
    /// four are untouched, each still carrying its own copy of that setup;
    /// this is a new instance of the same shape, with an actual echo of
    /// `StreamData` added, for tests that only need a genuine two-sided
    /// connection rather than a hand-rolled assertion about what the server
    /// side does.
    fn live_client_against_echo_server() -> (StdClient, SocketAddr) {
        live_client_against_echo_server_bound_to("127.0.0.1")
    }

    /// [`live_client_against_echo_server`] with the server's socket bound to `ip`. `"0.0.0.0"`
    /// makes the one server reachable by every loopback address -- two roads to one session.
    /// The client always dials `127.0.0.1`.
    fn live_client_against_echo_server_bound_to(ip: &str) -> (StdClient, SocketAddr) {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();

        let server_sock = UdpSocket::bind((ip, 0)).expect("bind server socket");
        let server_addr = SocketAddr::from((
            [127, 0, 0, 1],
            server_sock.local_addr().expect("server local addr").port(),
        ));
        // Bounded so this background thread cannot outlive the test: if the
        // caller's own wait for `Live` times out and panics before
        // `client.close()` ever runs, `StateChanged(Closed)` never arrives to
        // end the loop below on its own -- the read timeout plus this
        // deadline are what end it instead.
        server_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set server read timeout");
        let server_deadline = Instant::now() + Duration::from_secs(30);
        let client_pub = client_kp.public;
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut buf = [0u8; 65536];
            loop {
                if Instant::now() >= server_deadline {
                    return;
                }
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e) if is_read_timeout(e) => continue,
                    Err(_) => return,
                };
                let now = Instant::now();
                let out = server_conn.on_datagram(now, src, &buf[..len]);
                for dg in &out {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                let mut echo: Vec<Datagram> = Vec::new();
                for ev in server_conn.poll_events() {
                    match ev {
                        Event::StreamData { stream_id, data } => {
                            echo.extend(server_conn.send(now, stream_id, &data));
                        }
                        Event::StateChanged(LinkState::Closed) => return,
                        _ => {}
                    }
                }
                for dg in &echo {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
            }
        });

        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let binder: Arc<dyn Binder> = Arc::new(OkBinder);
        let events: Arc<dyn ClientEvents> = Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        });
        let client_cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        };
        let client = StdClient::connect(
            server_addr,
            client_cfg,
            [42u8; 16],
            StartKind::Cold,
            binder,
            events,
            None,
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Live");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before reaching Live"),
            }
        }

        (client, server_addr)
    }

    /// The owner hands in the roads and can ask which one is in use. Both
    /// travel the same way everything else does -- a command in, a value out
    /// -- without changing the callback interface.
    #[test]
    fn the_owner_can_hand_in_roads_and_ask_which_is_in_use() {
        let (client, server_addr) = live_client_against_echo_server();
        assert_eq!(
            client.active_path(),
            Some(server_addr),
            "before anything else, the road in use is the one it dialled"
        );
        client.set_paths(vec![
            server_addr,
            "203.0.113.9:60000".parse().expect("a literal address"),
        ]);
        // Nothing about handing in a list changes which road is in use.
        assert_eq!(client.active_path(), Some(server_addr));
        client.close();
    }

    /// `set_paths` must not be a bookkeeping-only no-op: handing in a spare
    /// road has to make the driver actually check it over the wire. Binds a
    /// second real socket to stand in for that spare road (nothing needs to
    /// answer from it -- the point is only that the driver tries to reach
    /// it), hands its address to `set_paths` alongside the live one, and
    /// waits, bounded, for a datagram to land on it.
    #[test]
    fn handing_in_a_spare_road_makes_the_driver_check_it_over_the_wire() {
        let (client, server_addr) = live_client_against_echo_server();

        let spare_sock = UdpSocket::bind("127.0.0.1:0").expect("bind spare socket");
        let spare_addr = spare_sock.local_addr().expect("spare local addr");
        spare_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set spare read timeout");

        client.set_paths(vec![server_addr, spare_addr]);

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 65536];
        let mut arrived = false;
        while Instant::now() < deadline {
            match spare_sock.recv_from(&mut buf) {
                Ok((len, _src)) => {
                    arrived = len > 0;
                    break;
                }
                Err(ref e) if is_read_timeout(e) => continue,
                Err(_) => break,
            }
        }
        assert!(
            arrived,
            "no path check reached the spare road within 5s of handing it to set_paths -- \
             set_paths must make the driver probe every road it is given, not just record it"
        );

        client.close();
    }

    /// The owner can ask what the roads look like, and gets the same picture
    /// the connection is deciding by. Before anything is handed in there are
    /// no roads and nothing to report.
    #[test]
    fn the_owner_can_ask_what_the_roads_look_like() {
        let (client, server_addr) = live_client_against_echo_server();
        assert!(
            client.roads().is_empty(),
            "a session with no spare roads has nothing to show"
        );

        client.set_paths(vec![
            server_addr,
            "203.0.113.9:60000".parse().expect("a literal address"),
        ]);

        // The driver publishes on its own thread, so wait for it -- bounded,
        // and the assertion below is what reports a failure.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && client.roads().len() < 2 {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            client.roads().len(),
            2,
            "both roads appear once the driver has published them"
        );
        assert_eq!(
            client.path_probes().len(),
            2,
            "every published road actually sent a probe"
        );
        client.close();
    }

    /// A road that answered its check can be chosen, and the answer comes back only after the
    /// driver has acted: the road in use is already the new one when `use_road` returns.
    /// Two roads to one server are two loopback addresses of a socket bound to all of them --
    /// on Linux the whole 127.0.0.0/8 block is local with no configuration.
    #[cfg(target_os = "linux")]
    #[test]
    fn use_road_moves_onto_a_verified_road_and_publishes_it_before_answering() {
        let (client, first) = live_client_against_echo_server_bound_to("0.0.0.0");
        let second = SocketAddr::from(([127, 0, 0, 2], first.port()));
        client.set_paths(vec![first, second]);

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline
            && !client
                .roads()
                .iter()
                .any(|r| r.addr == second && r.state == crate::paths::PathState::Verified)
        {
            std::thread::sleep(Duration::from_millis(20));
        }

        assert_eq!(client.use_road(second), UseRoadOutcome::Moved);
        assert_eq!(
            client.active_path(),
            Some(second),
            "published before the answer, not on the next tick"
        );
        assert_eq!(client.use_road(second), UseRoadOutcome::AlreadyInUse);
        client.close();
    }

    /// A road that has not answered is refused, and so is an address that is not one of the
    /// session's roads; the road in use stays.
    #[test]
    fn use_road_refuses_a_silent_road_and_a_stranger() {
        let (client, server_addr) = live_client_against_echo_server();
        let silent: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![server_addr, silent]);

        assert_eq!(client.use_road(silent), UseRoadOutcome::NotAnswering);
        assert_eq!(
            client.use_road("203.0.113.10:1".parse().expect("a literal address")),
            UseRoadOutcome::UnknownRoad
        );
        assert_eq!(client.active_path(), Some(server_addr));
        client.close();
    }

    /// With no driver to ask -- closed, or never started -- the answer is `NoSession`, and it
    /// comes at once rather than after the reply timeout.
    #[test]
    fn use_road_without_a_driver_is_no_session_at_once() {
        let (client, server_addr) = live_client_against_echo_server();
        client.close();
        let asked = Instant::now();
        assert_eq!(client.use_road(server_addr), UseRoadOutcome::NoSession);
        assert!(
            asked.elapsed() < USE_ROAD_REPLY_TIMEOUT,
            "a closed channel answers at once"
        );
        assert_eq!(
            StdClient::dead().use_road(server_addr),
            UseRoadOutcome::NoSession
        );
    }

    /// The server side of the flood tests below: a bare server `Connection`
    /// pumped over a std socket.
    fn server_conn(server_priv: [u8; 32], client_pub: [u8; 32]) -> Connection {
        Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Server,
            local_static_priv: server_priv,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_pub]),
        })
    }

    fn client_cfg(client_priv: [u8; 32], server_pub: [u8; 32]) -> ConnectionConfig {
        ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        }
    }

    #[test]
    fn allowlist_driver_sends_immediate_proof_and_retries_a_lost_ping() {
        let server_key = crate::handshake::generate_keypair();
        let client_key = crate::handshake::generate_keypair();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();
        let (result_tx, result_rx) = mpsc::channel();
        let _server = StoppedOnDrop::spawn(move |stop| {
            let mut connection = server_conn(server_key.private, client_key.public);
            let mut buf = [0; 65536];
            let mut response_at = None;
            let mut first_delay = None;
            while !stop.load(Ordering::SeqCst) {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                let now = Instant::now();
                if let Some(frames) = connection.peek_frames(&buf[..n]) {
                    assert!(
                        frames
                            .iter()
                            .all(|frame| !matches!(frame, StreamFrame::Data { .. })),
                        "fresh proof must not open an application channel"
                    );
                    if frames
                        .iter()
                        .any(|frame| matches!(frame, StreamFrame::Ping { .. }))
                    {
                        if first_delay.is_none() {
                            first_delay =
                                Some(now.duration_since(response_at.expect("msg2 was sent")));
                            // Drop the initial proof before decryption; a later normal
                            // keepalive must establish fresh possession by itself.
                            continue;
                        }
                        connection.on_datagram(now, from, &buf[..n]);
                        let confirmed = connection
                            .poll_events()
                            .iter()
                            .any(|event| matches!(event, Event::PeerKeyConfirmed { .. }));
                        let _ = result_tx.send((first_delay.unwrap(), confirmed));
                        return;
                    }
                }
                let reply = connection.on_datagram(now, from, &buf[..n]);
                if response_at.is_none() && connection.state() == LinkState::Live {
                    response_at = Some(now);
                }
                for dg in reply {
                    socket.send_to(&dg.bytes, dg.to).unwrap();
                }
                let _ = connection.poll_events();
            }
        });
        let client = StdClient::connect(
            address,
            client_cfg(client_key.private, server_key.public),
            [0xBC; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(NullEvents),
            None,
        );
        let (first_delay, confirmed) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the driver must retry its lost proof without application traffic");
        client.close();
        assert!(
            first_delay < Duration::from_millis(750),
            "proof waited for the periodic timer: {first_delay:?}"
        );
        assert!(
            confirmed,
            "the retry must authenticate fresh transport keys"
        );
    }

    /// A helper thread of a flood test that stops when the test ends --
    /// passed, failed or panicked: dropping it raises the flag the thread's
    /// loops watch and joins it, so no busy loop outlives its test and loads
    /// the tests running next to it.
    struct StoppedOnDrop {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl StoppedOnDrop {
        fn spawn(body: impl FnOnce(Arc<AtomicBool>) + Send + 'static) -> StoppedOnDrop {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            StoppedOnDrop {
                stop,
                thread: Some(thread::spawn(move || body(flag))),
            }
        }
    }

    impl Drop for StoppedOnDrop {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// One burst of junk for the flood tests: 16 datagrams, then a 100 us
    /// pause. Still a datagram every few microseconds on average and never a
    /// gap near the driver's shortest read timeout (1 ms), so that timeout
    /// never runs out -- but the flooding thread no longer holds a core for
    /// seconds, starving the real-time tests that run beside it.
    fn flood_burst(flood: &UdpSocket, to: SocketAddr) {
        for _ in 0..16 {
            let _ = flood.send_to(&[0xAB; 40], to);
        }
        std::thread::sleep(Duration::from_micros(100));
    }

    /// Spec §4.1 / §9.2 (defect 2): the server streams a datagram every
    /// 100 us for ten seconds -- denser than the driver's shortest read
    /// timeout (1 ms), so that timeout never runs out -- and the client must
    /// still PING on schedule.
    #[test]
    fn the_client_pings_on_schedule_while_the_server_streams_without_pause() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        server_sock
            .set_read_timeout(Some(Duration::from_micros(50)))
            .expect("server read timeout");
        let (pings_tx, pings_rx) = mpsc::channel::<Vec<Instant>>();
        let client_pub = client_kp.public;
        let _server = StoppedOnDrop::spawn(move |stop| {
            let mut conn = server_conn(server_kp.private, client_pub);
            let mut buf = [0u8; 65536];
            let mut live_since: Option<Instant> = None;
            let mut pings = Vec::new();
            let mut last_push = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                if live_since.is_some_and(|t| t.elapsed() >= Duration::from_secs(10)) {
                    let _ = pings_tx.send(pings);
                    return;
                }
                if let Ok((len, src)) = server_sock.recv_from(&mut buf) {
                    let now = Instant::now();
                    if conn.peek_frames(&buf[..len]).is_some_and(|frames| {
                        frames.iter().any(|f| matches!(f, StreamFrame::Ping { .. }))
                    }) {
                        pings.push(now);
                    }
                    for dg in conn.on_datagram(now, src, &buf[..len]) {
                        let _ = server_sock.send_to(&dg.bytes, dg.to);
                    }
                    if live_since.is_none() && conn.state() == LinkState::Live {
                        live_since = Some(now);
                    }
                }
                let now = Instant::now();
                if live_since.is_some()
                    && now.duration_since(last_push) >= Duration::from_micros(100)
                {
                    last_push = now;
                    for dg in conn.send(now, 16, &[b'x'; 100]) {
                        let _ = server_sock.send_to(&dg.bytes, dg.to);
                    }
                }
                let _ = conn.poll_events();
            }
        });
        let client = StdClient::connect(
            server_addr,
            client_cfg(client_kp.private, server_kp.public),
            [5u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(NullEvents),
            None,
        );
        let pings = pings_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the stub server finished its ten seconds");
        client.close();
        assert!(
            pings.len() >= 6,
            "{} PINGs in ten seconds of streaming",
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

    /// Spec §9.2 (defect 2): msg1 is retransmitted on time even while junk
    /// keeps the client's socket busy -- the retransmit used to live only in
    /// the read-timeout arm.
    #[test]
    fn the_handshake_is_retransmitted_while_junk_floods_the_socket() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        let (dg_tx, dg_rx) = mpsc::channel::<Vec<u8>>();
        server_sock
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("server read timeout");
        let _server = StoppedOnDrop::spawn(move |stop| {
            let mut buf = [0u8; 65536];
            let src = loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok((len, src)) = server_sock.recv_from(&mut buf) {
                    let _ = dg_tx.send(buf[..len].to_vec());
                    break src;
                }
            };
            let until = Instant::now() + Duration::from_secs(3);
            // Junk in dense bursts (`flood_burst`): denser than the driver's
            // shortest read timeout (1 ms), so that timeout never runs out.
            // Stopped when this thread returns, which it does within a read
            // timeout of the test's own stop.
            let _flood = StoppedOnDrop::spawn(move |stop| {
                let flood = UdpSocket::bind("127.0.0.1:0").expect("flood socket");
                while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                    flood_burst(&flood, src);
                }
            });
            while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                if let Ok((len, _)) = server_sock.recv_from(&mut buf) {
                    if dg_tx.send(buf[..len].to_vec()).is_err() {
                        return;
                    }
                }
            }
        });
        let client = StdClient::connect(
            server_addr,
            client_cfg(client_kp.private, server_kp.public),
            [6u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(NullEvents),
            None,
        );
        let first = dg_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first msg1 datagram");
        let second = dg_rx
            .recv_timeout(Duration::from_millis(1500))
            .expect("msg1 must be retransmitted while junk keeps the socket busy");
        assert_eq!(first, second, "the retransmit is the stored msg1");
        client.close();
    }

    /// Spec §9.2 (defect 2): a server that goes silent after the handshake
    /// while junk keeps arriving must still read as `PathDown` on time.
    #[test]
    fn path_down_arrives_on_time_while_junk_floods_the_socket() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        let client_pub = client_kp.public;
        server_sock
            .set_read_timeout(Some(Duration::from_millis(2)))
            .expect("server read timeout");
        let _server = StoppedOnDrop::spawn(move |stop| {
            let mut conn = server_conn(server_kp.private, client_pub);
            let mut buf = [0u8; 65536];
            let src = loop {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok((len, src)) = server_sock.recv_from(&mut buf) else {
                    continue;
                };
                for dg in conn.on_datagram(Instant::now(), src, &buf[..len]) {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                if conn.state() == LinkState::Live {
                    break src;
                }
            };
            // From here on the server says nothing real; junk keeps coming in
            // dense bursts (`flood_burst`): denser than the driver's shortest
            // read timeout (1 ms), so that timeout never runs out.
            let flood = UdpSocket::bind("127.0.0.1:0").expect("flood socket");
            let until = Instant::now() + Duration::from_secs(8);
            while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                flood_burst(&flood, src);
            }
        });
        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let client = StdClient::connect(
            server_addr,
            client_cfg(client_kp.private, server_kp.public),
            [7u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(StateEvents {
                tx: Mutex::new(state_tx),
            }),
            None,
        );
        let live_by = Instant::now() + Duration::from_secs(5);
        loop {
            let left = live_by.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out waiting for Live");
            if let Ok(LinkState::Live) = state_rx.recv_timeout(left) {
                break;
            }
        }
        let down_by = Instant::now() + crate::conn::PATH_DOWN_AFTER + Duration::from_millis(1500);
        let mut went_down = false;
        while !went_down {
            let left = down_by.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            went_down = matches!(state_rx.recv_timeout(left), Ok(LinkState::PathDown));
        }
        client.close();
        assert!(
            went_down,
            "PathDown must come within PATH_DOWN_AFTER of the silence, junk or no junk"
        );
    }

    /// Review focus: the drain of already-arrived datagrams takes what is
    /// waiting and puts the socket back into blocking mode -- a socket left
    /// non-blocking would turn the loop's timed `recv_from` into a busy spin.
    #[test]
    fn draining_ready_datagrams_takes_what_is_waiting_and_leaves_the_socket_blocking() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = sock.local_addr().expect("its address");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind the sender");
        for _ in 0..3 {
            sender.send_to(b"junk", addr).expect("send");
        }
        thread::sleep(Duration::from_millis(50));
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let mut conn = Connection::new(client_cfg(client_kp.private, server_kp.public));
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let out = drain_ready(&sock, &mut conn, &mut buf, READY_DRAIN_MAX);
        assert!(out.is_empty(), "junk draws no answer");
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("read timeout");
        let started = Instant::now();
        assert!(
            sock.recv_from(&mut buf).is_err(),
            "the drain took every waiting datagram"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(80),
            "the socket is blocking again: an empty read waited for its timeout"
        );
    }

    /// Review focus: the header gets the handshake's round trip at once, not
    /// 0 until the first PONG 1.5 s later.
    #[test]
    fn the_handshake_round_trip_is_published_before_the_first_pong() {
        let (client, _server_addr) = live_client_against_echo_server();
        let deadline = Instant::now() + Duration::from_secs(1);
        while client.stats().rtt_ms == 0 {
            assert!(
                Instant::now() < deadline,
                "no round trip published within a second of Live"
            );
            thread::sleep(Duration::from_millis(10));
        }
        client.close();
    }

    /// Spec §4.14: on the client, a stream out of offset space ends the
    /// connection silently -- `Closed` reaches the owner at once, and
    /// `closed_gracefully` stays false (the session is kept).
    #[test]
    fn an_exhausted_stream_ends_the_client_connection_silently() {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let mut conn = Connection::new(client_cfg(client_kp.private, server_kp.public));
        conn.push_test_event(Event::OffsetSpaceExhausted { stream_id: 14 });
        let events = poll_events_abandoning_on_exhaustion(&mut conn);
        assert!(events.contains(&Event::StateChanged(LinkState::Closed)));
        assert_eq!(conn.state(), LinkState::Closed);
        assert!(!conn.closed_gracefully());
    }

    /// A live `StdClient` against a server that ENDS the connection when
    /// the client writes on stream 9: with a `Close` when `graceful`, by
    /// falling silent otherwise (the client's short death timer then closes
    /// it). Returns once the client has seen `Closed`.
    fn client_whose_server_ends_the_connection(graceful: bool) -> StdClient {
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind server socket");
        let server_addr = server_sock.local_addr().expect("server local addr");
        server_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set server read timeout");
        let server_deadline = Instant::now() + Duration::from_secs(30);
        let client_pub = client_kp.public;
        thread::spawn(move || {
            let mut server_conn = Connection::new(ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_pub]),
            });
            let mut buf = [0u8; 65536];
            while Instant::now() < server_deadline {
                let (len, src) = match server_sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(ref e) if is_read_timeout(e) => continue,
                    Err(_) => return,
                };
                let now = Instant::now();
                for dg in &server_conn.on_datagram(now, src, &buf[..len]) {
                    let _ = server_sock.send_to(&dg.bytes, dg.to);
                }
                let asked = server_conn
                    .poll_events()
                    .iter()
                    .any(|ev| matches!(ev, Event::StreamData { stream_id: 9, .. }));
                if asked {
                    if graceful {
                        for dg in &server_conn.close(now) {
                            let _ = server_sock.send_to(&dg.bytes, dg.to);
                        }
                    }
                    return;
                }
            }
        });

        let (state_tx, state_rx) = mpsc::channel::<LinkState>();
        let client = StdClient::connect(
            server_addr,
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [21u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(StateEvents {
                tx: Mutex::new(state_tx),
            }),
            None,
        );
        client.set_death_after(Duration::from_millis(500));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut asked = false;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out waiting for Closed");
            match state_rx.recv_timeout(remaining) {
                Ok(LinkState::Live) if !asked => {
                    asked = true;
                    client.send_bytes(9, b"end it".to_vec());
                }
                Ok(LinkState::Closed) => break,
                Ok(_) => continue,
                Err(_) => panic!("state channel closed before Closed"),
            }
        }
        client
    }

    /// The owner can tell a connection the peer ended with a `Close` from
    /// one that died or was abandoned -- the console client reconnects only
    /// after the second (the first means the session is gone). Set before `Closed` is
    /// dispatched, so an owner reacting to that callback already sees it.
    #[test]
    fn the_owner_can_tell_a_peer_close_from_a_death() {
        let closed = client_whose_server_ends_the_connection(true);
        assert!(closed.closed_gracefully(), "the server sent a Close");
        closed.close();
        let died = client_whose_server_ends_the_connection(false);
        assert!(!died.closed_gracefully(), "the server fell silent");
        died.close();
    }

    /// A client dialled at a socket that never answers: it stays
    /// `Connecting`, so `send` only queues and the tail is what was written.
    fn a_client_nobody_answers() -> (StdClient, UdpSocket) {
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind a silent socket");
        let addr = silent.local_addr().expect("its address");
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        struct Quiet;
        impl ClientEvents for Quiet {
            fn on_bytes(&self, _: u8, _: Vec<u8>) {}
            fn on_state(&self, _: LinkState) {}
            fn on_stats(&self, _: Stats) {}
            fn on_reset(&self, _: u8) {}
        }
        let client = StdClient::connect(
            addr,
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [0u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(Quiet),
            None,
        );
        (client, silent)
    }

    /// Spec §4.7.3 / §9.2: the gate closes once 512 KiB are queued or handed
    /// over, and a bounded send then waits its timeout and queues nothing.
    #[test]
    fn a_bounded_send_waits_once_half_a_megabyte_is_queued() {
        let (client, _silent) = a_client_nobody_answers();
        for _ in 0..8 {
            client
                .send_bytes_bounded(30, vec![0u8; 64 * 1024], Duration::from_secs(1))
                .expect("room below the high mark");
        }
        let started = Instant::now();
        assert_eq!(
            client.send_bytes_bounded(30, vec![0u8; 64 * 1024], Duration::from_millis(300)),
            Err(SendBlocked::Full)
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        let p = client.stream_progress(30).expect("the driver answers");
        assert_eq!(p.queued, 512 * 1024, "the refused chunk was not queued");
        client.detach();
    }

    /// Spec §4.7.3: against a peer that acknowledges, a producer pushing far
    /// more than the high mark goes through, and never holds more than the
    /// high mark plus one chunk in the connection.
    #[test]
    fn a_bounded_producer_goes_through_and_keeps_the_tail_near_the_high_mark() {
        let (client, _addr) = live_client_against_echo_server();
        for _ in 0..32 {
            client
                .send_bytes_bounded(30, vec![1u8; 64 * 1024], Duration::from_secs(10))
                .expect("the gate opens as the peer acknowledges");
            let p = client.stream_progress(30).expect("the driver answers");
            assert!(p.unacked <= 576 * 1024, "tail {} KiB", p.unacked / 1024);
        }
        client.close();
    }

    /// Spec §4.7.3: called from the driver thread (a `ClientEvents`
    /// callback) it answers `SendBlocked::OnDriverThread` at once instead of
    /// waiting on the thread that would have to open the gate.
    #[test]
    fn a_bounded_send_from_the_driver_thread_is_refused_at_once() {
        struct CallbackEvents {
            client: Mutex<Option<Arc<StdClient>>>,
            fired: AtomicBool,
            result_tx: Mutex<Sender<(Duration, Result<(), SendBlocked>)>>,
        }
        impl ClientEvents for CallbackEvents {
            fn on_bytes(&self, _: u8, _: Vec<u8>) {}
            fn on_state(&self, _: LinkState) {}
            fn on_stats(&self, _: Stats) {
                if self.fired.load(Ordering::SeqCst) {
                    return;
                }
                let Some(client) = self.client.lock().expect("client cell").clone() else {
                    return;
                };
                self.fired.store(true, Ordering::SeqCst);
                let started = Instant::now();
                let r = client.send_bytes_bounded(30, b"x".to_vec(), Duration::from_secs(5));
                let _ = self
                    .result_tx
                    .lock()
                    .expect("result")
                    .send((started.elapsed(), r));
            }
            fn on_reset(&self, _: u8) {}
        }
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let (result_tx, result_rx) = mpsc::channel();
        let events = Arc::new(CallbackEvents {
            client: Mutex::new(None),
            fired: AtomicBool::new(false),
            result_tx: Mutex::new(result_tx),
        });
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let client = Arc::new(StdClient::connect(
            silent.local_addr().expect("addr"),
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [0u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            events.clone(),
            None,
        ));
        *events.client.lock().expect("client cell") = Some(Arc::clone(&client));
        let (took, r) = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the callback ran");
        assert_eq!(r, Err(SendBlocked::OnDriverThread));
        assert!(took < Duration::from_millis(100), "{took:?}");
        client.detach();
    }

    /// A producer waiting on a shut gate wakes with `SendBlocked::Gone` when
    /// the driver ends, instead of waiting out its timeout; from then on the
    /// client says it is gone, and a bounded send is refused at once.
    #[test]
    fn a_producer_waiting_on_a_gate_wakes_when_the_driver_ends() {
        let (client, _silent) = a_client_nobody_answers();
        for _ in 0..8 {
            client
                .send_bytes_bounded(30, vec![0u8; 64 * 1024], Duration::from_secs(1))
                .expect("room");
        }
        assert!(!client.is_gone());
        let client = Arc::new(client);
        let waiter = {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let started = Instant::now();
                let r = client.send_bytes_bounded(30, vec![0u8; 1024], Duration::from_secs(30));
                (started.elapsed(), r)
            })
        };
        thread::sleep(Duration::from_millis(100));
        client.detach();
        let (took, r) = waiter.join().expect("the producer");
        assert_eq!(r, Err(SendBlocked::Gone));
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(client.is_gone());
        let started = Instant::now();
        assert_eq!(
            client.send_bytes_bounded(31, vec![0u8; 1024], Duration::from_secs(30)),
            Err(SendBlocked::Gone)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// However the driver thread ends -- here a panic in a callback on it,
    /// which is the platform's code -- a producer waiting on its gate wakes
    /// with `SendBlocked::Gone`, and the client says it is gone. No `Closed`
    /// reaches the owner on this way out: this is how it can still tell.
    #[test]
    fn a_driver_that_panics_leaves_its_producers_gone() {
        struct PanicWhenArmed(AtomicBool);
        impl ClientEvents for PanicWhenArmed {
            fn on_bytes(&self, _: u8, _: Vec<u8>) {}
            fn on_state(&self, _: LinkState) {}
            fn on_stats(&self, _: Stats) {
                if self.0.load(Ordering::SeqCst) {
                    panic!("a platform callback panicked");
                }
            }
            fn on_reset(&self, _: u8) {}
        }
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let server_kp = crate::handshake::generate_keypair();
        let client_kp = crate::handshake::generate_keypair();
        let events = Arc::new(PanicWhenArmed(AtomicBool::new(false)));
        let client = Arc::new(StdClient::connect(
            silent.local_addr().expect("addr"),
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: crate::conn::Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [0u8; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            events.clone(),
            None,
        ));
        for _ in 0..8 {
            client
                .send_bytes_bounded(30, vec![0u8; 64 * 1024], Duration::from_secs(1))
                .expect("room");
        }
        let waiter = {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let started = Instant::now();
                let r = client.send_bytes_bounded(30, vec![0u8; 1024], Duration::from_secs(30));
                (started.elapsed(), r)
            })
        };
        // The next statistics heartbeat (at most a second away) panics.
        events.0.store(true, Ordering::SeqCst);
        let (took, r) = waiter.join().expect("the producer");
        assert_eq!(r, Err(SendBlocked::Gone));
        assert!(took < Duration::from_secs(5), "{took:?}");
        assert!(client.is_gone());
        client.detach();
    }

    /// A dead client (no driver at all) is gone, and refuses a bounded send
    /// as such at once.
    #[test]
    fn a_dead_client_refuses_a_bounded_send_as_gone() {
        let client = StdClient::dead();
        assert!(client.is_gone());
        let started = Instant::now();
        assert_eq!(
            client.send_bytes_bounded(30, b"x".to_vec(), Duration::from_secs(30)),
            Err(SendBlocked::Gone)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// When the upload's first segment and the keystroke reached the server,
    /// by the server's clock; when the keystroke was pressed; how many chunks
    /// the producer handed over.
    struct KeystrokeRun {
        upload_at: Instant,
        pressed_at: Instant,
        keystroke_at: Option<Instant>,
        handed: usize,
    }

    /// The upload's first segment left just before it reached the server,
    /// and its retransmit timeout is 500 ms from then: a keystroke that
    /// reaches the server sooner than this after it did not wait for the
    /// window to open.
    const BEFORE_THE_WINDOW_OPENS: Duration = Duration::from_millis(400);

    /// A 2 MiB image pushed through `send_bytes_bounded` on stream 30 -- as
    /// the bulk class when `bulk` -- against a server that acknowledges
    /// nothing, and a keystroke on stream 16 as soon as the image's first
    /// segment arrives. The keystroke is waited for generously: the verdict
    /// is read off the server's clock, not off when this thread got to look.
    fn a_keystroke_during_an_upload(bulk: bool) -> KeystrokeRun {
        const CHUNK: usize = 64 * 1024;
        let (client, arrived) = crate::test_peer::client_whose_server_stops_acknowledging();
        if bulk {
            client.set_stream_class(30, StreamClass::Bulk);
        }
        let client = Arc::new(client);
        let producer = {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let image = vec![0x5au8; 2 * 1024 * 1024];
                let mut handed = 0;
                for chunk in image.chunks(CHUNK) {
                    if client
                        .send_bytes_bounded(30, chunk.to_vec(), Duration::from_secs(30))
                        .is_err()
                    {
                        break;
                    }
                    handed += 1;
                }
                handed
            })
        };
        let (stream, upload_at) = arrived
            .recv_timeout(Duration::from_secs(5))
            .expect("the upload's first segment arrives");
        assert_eq!(stream, 30);
        let pressed_at = Instant::now();
        client.send_bytes(16, b"k".to_vec());
        let keystroke_at = arrived
            .recv_timeout(Duration::from_secs(2))
            .ok()
            .map(|(stream, at)| {
                assert_eq!(stream, 16);
                at
            });
        client.detach();
        let handed = producer.join().expect("the producer");
        KeystrokeRun {
            upload_at,
            pressed_at,
            keystroke_at,
            handed,
        }
    }

    /// Spec §3.1 / §4.15: the image is the bulk class, so a keystroke typed
    /// while it fills the congestion window goes out at once on the
    /// interactive class's own headroom instead of waiting for the window --
    /// and the producer stands at its gate meanwhile, holding 512 KiB.
    #[test]
    fn a_keystroke_is_not_stuck_behind_a_bulk_upload() {
        let run = a_keystroke_during_an_upload(true);
        let at = run.keystroke_at.expect("the keystroke reached the server");
        assert!(
            at < run.upload_at + BEFORE_THE_WINDOW_OPENS,
            "arrived {:?} after the upload's first segment, {:?} after it was pressed",
            at - run.upload_at,
            at.saturating_duration_since(run.pressed_at)
        );
        assert_eq!(run.handed, 8, "512 KiB handed over, then the gate shut");
    }

    /// The control for the test above, one difference only: an upload left
    /// interactive takes the whole window and the headroom with it, and the
    /// keystroke waits behind it until the retransmit timeout shrinks the
    /// window and the headroom lets it out.
    #[test]
    fn a_keystroke_waits_behind_an_upload_left_interactive() {
        let run = a_keystroke_during_an_upload(false);
        if let Some(at) = run.keystroke_at {
            assert!(
                at >= run.upload_at + BEFORE_THE_WINDOW_OPENS,
                "the keystroke went out {:?} after the upload's first segment, before the \
                 window could open",
                at - run.upload_at
            );
        }
        assert_eq!(run.handed, 8);
    }

    /// What the owner hears about a handshake, in the order it hears it.
    #[derive(Debug, PartialEq)]
    enum Heard {
        Features(Features),
        Live,
    }

    struct HeardLog {
        log: Mutex<Sender<Heard>>,
        live: Mutex<Sender<()>>,
    }
    impl ClientEvents for HeardLog {
        fn on_bytes(&self, _: u8, _: Vec<u8>) {}
        fn on_state(&self, state: LinkState) {
            if state == LinkState::Live {
                let _ = self.log.lock().expect("log").send(Heard::Live);
                let _ = self.live.lock().expect("live").send(());
            }
        }
        fn on_stats(&self, _: Stats) {}
        fn on_reset(&self, _: u8) {}
        fn on_features(&self, features: Features) {
            let _ = self
                .log
                .lock()
                .expect("log")
                .send(Heard::Features(features));
        }
    }

    /// Spec §4.13: the owner hears what the handshake agreed once, before
    /// `Live` -- the console client decides from it whether its queue waits
    /// (a daemon without credits) or never does (one with them).
    #[test]
    fn the_owner_hears_the_agreed_features_once_before_live() {
        let (log_tx, log_rx) = mpsc::channel();
        let client = crate::test_peer::live_client_of(
            [35; 16],
            Duration::from_millis(5),
            DriverSetup::default(),
            |live| {
                Arc::new(HeardLog {
                    log: Mutex::new(log_tx),
                    live: Mutex::new(live),
                })
            },
            |sock, mut conn| {
                let mut buf = [0u8; 65536];
                let until = Instant::now() + Duration::from_secs(3);
                while Instant::now() < until {
                    let mut out = Vec::new();
                    if let Ok((len, src)) = sock.recv_from(&mut buf) {
                        out.extend(conn.on_datagram(Instant::now(), src, &buf[..len]));
                    }
                    out.extend(conn.on_timeout_if_due(Instant::now()));
                    for dg in &out {
                        let _ = sock.send_to(&dg.bytes, dg.to);
                    }
                    let _ = conn.poll_events();
                }
            },
        );
        // `live_client_of` returned: `Live` has been heard, so everything
        // before it is in the log already.
        let heard: Vec<Heard> = log_rx.try_iter().collect();
        assert_eq!(
            heard,
            vec![
                Heard::Features(Features::from_bits(
                    Features::SUPPORTED.bits() & !Features::AUTH_ACCEPTED.bits()
                )),
                Heard::Live
            ],
            "the agreed features, once, then Live"
        );
        client.detach();
    }

    /// Spec §4.13 with §6: a client counting its streams explicitly holds
    /// its server to exactly a window past what it reported -- the server's
    /// own sender says it stopped there, not a silence on the client's side
    /// -- and the rest follows its reports.
    #[test]
    fn a_client_counting_explicitly_is_held_to_a_window_until_it_reports() {
        use crate::reliability::STREAM_WINDOW;
        let setup = DriverSetup {
            default_consumption: crate::conn::Consumption::Explicit,
            stream_consumption: Vec::new(),
        };
        let data = vec![b'w'; 2 * 1024 * 1024];
        let (client, chunks, progress) =
            crate::test_peer::client_of_a_writing_server(40, data.clone(), setup);
        // Every report is a change and `acked` never passes the window
        // without failing, so this ends within a window's worth of reports.
        loop {
            let p = progress
                .recv_timeout(Duration::from_secs(5))
                .expect("the server goes on until it stops at the window");
            assert!(p.acked <= STREAM_WINDOW, "sent past the window: {p:?}");
            if p.acked == STREAM_WINDOW && p.credit_limit.is_none_or(|l| l == STREAM_WINDOW) {
                break;
            }
        }
        let mut got = 0usize;
        while got < STREAM_WINDOW as usize {
            got += chunks
                .recv_timeout(Duration::from_secs(5))
                .expect("what the server had acknowledged reaches the owner");
        }
        assert_eq!(got, STREAM_WINDOW as usize, "a window, not more");
        assert!(chunks.try_recv().is_err(), "nothing past the window");
        client.consumed(40, got);
        let mut total = got;
        while total < data.len() {
            let n = chunks
                .recv_timeout(Duration::from_secs(5))
                .expect("the rest follows the reports");
            total += n;
            client.consumed(40, n);
        }
        assert_eq!(total, data.len());
        client.detach();
    }

    /// The same client counting on delivery (the default, the app) is sent
    /// everything without a report.
    #[test]
    fn a_client_counting_on_delivery_is_sent_everything() {
        let data = vec![b'w'; 2 * 1024 * 1024];
        let (client, chunks, _progress) =
            crate::test_peer::client_of_a_writing_server(40, data.clone(), DriverSetup::default());
        let mut got = 0usize;
        while got < data.len() {
            got += chunks
                .recv_timeout(Duration::from_secs(5))
                .expect("everything arrives");
        }
        assert_eq!(got, data.len());
        client.detach();
    }
    #[derive(Default)]
    struct Auth17Events {
        accepted: Mutex<Vec<crate::AuthAcceptance>>,
        bytes: Mutex<Vec<(u8, Vec<u8>)>>,
    }
    impl ClientEvents for Auth17Events {
        fn on_bytes(&self, stream: u8, bytes: Vec<u8>) {
            self.bytes.lock().unwrap().push((stream, bytes));
        }
        fn on_state(&self, _: LinkState) {}
        fn on_stats(&self, _: Stats) {}
        fn on_reset(&self, _: u8) {}
        fn on_auth_accepted(&self, record: crate::AuthAcceptance) {
            self.accepted.lock().unwrap().push(record);
        }
    }

    #[test]
    fn auth17_driver_routes_only_complete_valid_record_to_typed_callback() {
        let accepted = crate::AuthAcceptance {
            session_id: 17,
            disposition: crate::SessionDisposition::Fresh,
        };
        let wire = crate::encode_auth_acceptance(accepted);
        for split in 0..=wire.len() {
            let events = Auth17Events::default();
            let mut parser = Some(crate::auth_acceptance::AuthAcceptanceParser::new(
                17,
                crate::Features::AUTH_ACCEPTED,
            ));
            let mut state = LinkState::Live;
            let mut pending = false;
            for chunk in [&wire[..split], &wire[split..]] {
                dispatch_authenticated_event(
                    Event::StreamData {
                        stream_id: AUTH_STREAM,
                        data: chunk.to_vec(),
                    },
                    &events,
                    &mut state,
                    &mut pending,
                    &mut parser,
                )
                .unwrap();
            }
            assert_eq!(*events.accepted.lock().unwrap(), vec![accepted]);
            assert!(
                events.bytes.lock().unwrap().is_empty(),
                "reserved bytes never become generic application data"
            );
        }
    }

    #[test]
    fn auth17_driver_rejects_auth_bytes_without_active_parser_and_malformed_records() {
        for active in [false, true] {
            let events = Auth17Events::default();
            let mut parser = active.then(|| {
                crate::auth_acceptance::AuthAcceptanceParser::new(
                    17,
                    crate::Features::AUTH_ACCEPTED,
                )
            });
            let mut state = LinkState::Live;
            let mut pending = false;
            assert!(dispatch_authenticated_event(
                Event::StreamData {
                    stream_id: AUTH_STREAM,
                    data: vec![0; 12]
                },
                &events,
                &mut state,
                &mut pending,
                &mut parser
            )
            .is_err());
            assert!(events.accepted.lock().unwrap().is_empty());
            assert!(events.bytes.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn auth17_driver_preserves_other_stream_delivery_without_inventing_acceptance() {
        let events = Auth17Events::default();
        let mut parser = None;
        let mut state = LinkState::Live;
        let mut pending = false;
        dispatch_authenticated_event(
            Event::StreamData {
                stream_id: 0,
                data: b"ordered metadata".to_vec(),
            },
            &events,
            &mut state,
            &mut pending,
            &mut parser,
        )
        .unwrap();
        assert!(events.accepted.lock().unwrap().is_empty());
        assert_eq!(
            *events.bytes.lock().unwrap(),
            vec![(0, b"ordered metadata".to_vec())]
        );
    }
    include!("driver_std_auth_tests.rs");
    include!("driver_std_cancel_tests.rs");
    include!("driver_std_recovery_tests.rs");
}
