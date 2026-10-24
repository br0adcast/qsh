//! Connection assembly (sans-IO): handshake, reliable stream, liveness, and
//! address migration in one `Connection` object.
//!
//! The module does no I/O. It accepts already-received datagrams and timer
//! events (`on_datagram`, `on_timeout`), and returns outgoing datagrams to the
//! caller, which sends them over the network itself. All state (sender
//! counter, anti-replay window, stream buffers, timers) lives here and ties
//! together the `handshake`, `wire`, and `reliability` modules.

use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::auth::AUTH_NONCE_LEN;
use crate::congestion::{AckVerdict, CongestionWindow};
use crate::features::Features;
use crate::handshake::{Handshake, TransportKeys};
use crate::handshake_payload::{
    encode_msg1, encode_msg2, encode_msg2_without_tail, parse_msg1, parse_msg2, AuthMethod,
    HsPayloadError, Msg1Payload, StartKind, SESSION_TOKEN_LEN,
};
use crate::paths::{PathTable, RoadInfo, PROBE_URGENT};
use crate::recovery_handshake::{RecoveryEndpoint, RecoveryHandshake};
use crate::reliability::{StreamFrame, StreamReceiver, StreamSender};
use crate::rtt::RttEstimator;
use crate::wire::{
    encode_handshake, encode_handshake_init_cookie, encode_transport, parse, parse_cookie_reply,
    transport_header, Frame, Kind, ReplayWindow, COOKIE_ECHO_LEN, COOKIE_LEN, MAX_PLAINTEXT,
    TRANSPORT_HEADER_LEN,
};

/// Idle interval after which we send a PING in the `Live`/`PathDown` phase.
const PING_INTERVAL: Duration = Duration::from_millis(1500);

/// How long the path stays down before PINGs slow down, and what they slow
/// down to. A link that has been silent for a minute is not coming back in
/// the next second, and something has to give if a client is allowed to wait
/// hours for it: at the lively rate that is thousands of wake-ups an hour, on
/// both sides, for a peer that is not listening. The cost of the slower rate
/// is bounded and small -- a return is noticed up to `PING_INTERVAL_DOWN`
/// later than it might have been, and only when the RETURNING side sends
/// nothing itself, which a client coming back never does.
const PING_BACKOFF_AFTER: Duration = Duration::from_secs(60);
const PING_INTERVAL_DOWN: Duration = Duration::from_secs(15);

/// How long we can go without a single authenticated incoming packet before
/// the path is considered unreachable (`PathDown`). The session is not torn
/// down. Threshold lowered from 6 to 3 s so "connection temporarily lost"
/// shows up faster.
pub const PATH_DOWN_AFTER: Duration = Duration::from_secs(3);

/// Client link-death: how long an ACTIVE client tolerates silence before
/// declaring the link dead (`Closed`) and triggering a reconnect. Kept short so
/// a genuinely-dead server is detected quickly. A Doze/freeze must NOT count
/// toward this: the driver treats a thread freeze as a rebind/resume and
/// restarts the liveness window (see `driver_std` and [`Connection::request_ping`]),
/// so a phone that was asleep hot-migrates over UDP instead of slowly reconnecting.
pub(crate) const CLIENT_DEATH_AFTER: Duration = Duration::from_secs(45);

/// Server session lifetime: how long the server keeps a SILENT session alive and
/// routable, so a returning client (a hot-roam over UDP, or a warm reattach by
/// token) finds it without a slow SSH reconnect. One day -- a phone can be idle
/// or asleep for a long time; the session and its retained tmux backend should
/// outlive that. Bounded by the session cap on the server side.
const SERVER_DEATH_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Default retransmit timeout (RTO) until RTT has been measured.
const DEFAULT_RTO: Duration = Duration::from_millis(500);

/// The bounds of the round-trip allowance derived from a measured round
/// trip. The floor bounds the retransmit timeout too; the ceiling bounds road
/// liveness only (`Connection::liveness_rto`, the seed-only retransmit
/// timeout) and is also how long a PING may go unanswered before anything
/// has been measured (see `Connection::unanswered_after`).
const RTO_FLOOR: Duration = Duration::from_millis(200);
const RTO_CEILING: Duration = Duration::from_secs(3);

/// The ceiling of the retransmit timeout once the estimator has samples
/// (see `Connection::rto`). Above `RTO_CEILING` on purpose: a fixed 256 KiB
/// window on a 64 KB/s uplink stands 4 s deep in its queue, and a timeout
/// capped at 3 s would resend every segment of it, every 3 s, for as long as
/// the transfer lasts. The estimator reaches it only when the measured round
/// trip demands it. RFC 6298 allows 60 s; road liveness (PINGs, the dead-road
/// rule, the move dwell) keeps `RTO_CEILING`.
const RETRANSMIT_CEILING: Duration = Duration::from_secs(15);

/// At most this many doublings of the retransmit timeout (RFC 6298 §5.5)
/// before a fresh round trip resets it; the result is capped at
/// `RETRANSMIT_CEILING` anyway.
const MAX_RTO_BACKOFF: u32 = 6;

/// How many unanswered PINGs are remembered, so that a PONG for any of them
/// still counts. Four intervals is six seconds of round trip, twice
/// `RTO_CEILING`, the longest round trip road liveness allows for. (A bulk
/// write's queue can hold a PING longer than that; its PONG then times
/// nothing, and the retransmit timer has the acknowledgements instead.)
const MAX_OUTSTANDING_PINGS: usize = 4;

/// After this long with no authenticated packet while the path is down, the
/// server stops hoarding output: it drops its send backlog and, on the
/// client's return, resyncs by resetting the stream and repainting the current
/// screen instead of replaying the whole gap. Above `PATH_DOWN_AFTER` (3 s) so
/// short blips/roaming still replay seamlessly.
///
/// Public because the console client's acceptance test
/// (`output_during_a_long_absence_survives_as_a_repaint` in
/// `cli/tests/pty_session.rs`) has to stop its client for LONGER than this,
/// and a literal there would silently stop testing anything the moment this
/// value is tuned upward. The test derives its stop duration from this
/// constant instead.
pub const RESYNC_AFTER: Duration = Duration::from_secs(10);

/// The bulk-output stream of the shell backend (`STREAM_IO` in
/// `crates/transport/src/shell_server.rs`). Resync has always applied to it.
///
/// **History, for the record.** For a stretch of early development on the
/// channel protocol (starting with the change that introduced
/// [`Connection::is_bulk_output_stream`], through the fix described below),
/// the channel protocol's `CONTROL_STREAM` shared this exact number, 0, by
/// coincidence: two protocols, introduced together in that same stretch of
/// work, each numbering their first stream from zero. This was NOT a gap
/// main carried before then -- main had no channel protocol at all, so
/// there was nothing for `OUTPUT_STREAM` to collide with. `CONTROL_STREAM`
/// records are one-shot and order-critical (`OPENED`/`REFUSED`/`EXIT` each
/// happen exactly once; nothing repaints a lost one), so treating that
/// stream as bulk output that can be dropped after a long absence was a
/// real, if short-lived, bug -- caught and fixed before release:
/// `crate::channel::CONTROL_STREAM` moved to 1 (see its own doc for why),
/// off this stream for good.
const OUTPUT_STREAM: u8 = 0;

/// Segments one stream gives per turn of the round-robin (spec §4.8). The
/// same as `ACK_EVERY`: one acknowledgement opens room for exactly one turn.
pub const RR_QUANTUM: usize = 4;

/// At most this many bulk segments per flush (spec §4.8): about 35 KB in
/// front of a keystroke, ~35 ms at 1 MB/s. Full segments never share a
/// datagram (spec §4.11), so this is as many datagrams too.
pub const BULK_FLUSH_BUDGET: usize = 32;

/// How long service frames -- ACKs, CREDITs -- wait for a datagram to ride
/// before they go alone (spec §3.2, §4.11): ten times less than the
/// shortest retransmit timeout an older peer uses (200 ms), and under a
/// terminal's frame time.
pub const ACK_DELAY: Duration = Duration::from_millis(20);

/// In-order DATA frames taken since an ACK last went out that send the ACKs
/// at once (spec §3.2, §4.11): about one acknowledgement for four segments.
pub const ACK_EVERY: usize = 4;

const _: () = assert!(RR_QUANTUM == ACK_EVERY);
// A round trip an ACK times carries up to ACK_DELAY of the receiver's wait:
// well under the tolerance the base delay is judged with.
const _: () = assert!(ACK_DELAY.as_millis() * 2 <= crate::congestion::BASE_TOLERANCE.as_millis());

/// How far one stream's tail -- queued and not acknowledged -- may grow
/// before the connection steps in (spec §4.7.1). Eight times `PIPE_HIGH`: a
/// producer that respects its send gate never gets here, so reaching it is a
/// bug above, and this is the net under it, not a policy.
pub const SEND_HARD_CAP: usize = 4 * 1024 * 1024;

/// How much out-of-order data one connection may hold across all its
/// streams, counted as its receivers count it (payload plus
/// [`crate::reliability::CHUNK_COST`] a chunk; spec §4.16, QSH-01). Far above
/// what an honest peer can put there: this build's sender keeps at most the
/// congestion window's 4 MiB in flight on all streams together, an older one
/// 256 KiB on each of the dozen streams a client uses. A peer in probation
/// is held to far less (`probation::PROBATION_UNDELIVERED_MAX`).
pub const UNDELIVERED_CAP: usize = 8 * 1024 * 1024;

/// What a stream's data is for, as the session layer declares it (spec §3.1,
/// §4.8). The interactive class -- keystrokes, terminal output, control
/// records -- goes first and without a count limit; the bulk class (a daemon
/// image today) gets what is left, at most `BULK_FLUSH_BUDGET` segments per
/// flush.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StreamClass {
    #[default]
    Interactive,
    Bulk,
}

/// When a stream's consumer is done with the bytes delivered to it (spec
/// §4.10.1). What is consumed is what the credit window moves on from
/// (spec §6.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Consumption {
    /// Taken the moment `Event::StreamData` is handed out: the owner's
    /// callback returning is the consumption (the app).
    #[default]
    OnDelivery,
    /// Taken when the owner says so, through [`Connection::on_consumed`]:
    /// the daemon's bridge, which knows when its backend took the bytes.
    Explicit,
}

/// Where a class's round-robin stopped (see [`Connection::serve_class`]).
#[derive(Clone, Copy, Debug)]
struct RrPosition {
    /// The stream served last.
    stream: u8,
    /// Segments left of its turn: more than 0 only when the budget or the
    /// window cut the turn short, and the next flush finishes it first.
    left: usize,
}

/// Role of the connection endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

/// What the server requires of a connecting client at handshake time.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthPolicy {
    /// Only these static keys are let in. The key itself IS the proof: it got
    /// onto the list over a trusted channel (the SSH bootstrap).
    Allowlist(Vec<[u8; 32]>),
    /// Any static key completes the handshake, but the session stays shut
    /// until the client's SSH signature verifies (see `crate::auth`). The
    /// client's Noise key is ephemeral here and proves nothing by itself.
    ///
    /// A server may run this policy ONLY through [`Connection::accept`], where
    /// the session manager's probation stage holds the connection until that
    /// signature lands. [`Connection::on_datagram`]'s handshake path refuses
    /// it outright: nothing there could ever check the proof, so admitting a
    /// client would mean admitting everyone.
    SshSignature,
}

impl AuthPolicy {
    /// Whether a client static key may finish the handshake under this policy.
    pub fn admits(&self, key: &[u8; 32]) -> bool {
        match self {
            AuthPolicy::Allowlist(keys) => keys.contains(key),
            AuthPolicy::SshSignature => true,
        }
    }

    /// The method byte a client with this policy puts in msg1.
    pub fn method(&self) -> AuthMethod {
        match self {
            AuthPolicy::Allowlist(_) => AuthMethod::Allowlist,
            AuthPolicy::SshSignature => AuthMethod::SshSignature,
        }
    }
}

/// Connection configuration: role, own static private key, and data for
/// verifying the remote side.
///
/// `Clone` is needed by the async driver (`driver_tokio`): the echo server
/// recreates the server `Connection` from the same config on every new
/// `HandshakeInit`.
/// Each config erases its private array on drop. As with any Drop type,
/// non-Copy fields cannot be moved out by destructuring; cloning remains supported.
#[derive(Clone)]
pub struct ConnectionConfig {
    pub role: Role,
    pub local_static_priv: [u8; 32],
    /// Client: `Some(server pub)`; server: `None`.
    pub remote_static_pub: Option<[u8; 32]>,
    /// Server: what a connecting client must satisfy. Client: which method it
    /// announces in msg1 (`Allowlist(vec![])` for the bootstrap path).
    pub auth: AuthPolicy,
    /// Which negotiable features this side may use (spec §5.2). A client
    /// started with [`Connection::start_session`] offers these, less any this
    /// build does not implement; a server enables a bit only when msg1 offered
    /// it and this set allows it. Production passes `Features::SUPPORTED`;
    /// tests pass `Features::NONE` to play a peer built before negotiation.
    pub features: Features,
    /// Mandatory negotiated features for this application profile. Generic
    /// transport tools may choose NONE; channel owners require CHANNEL_GEOMETRY.
    pub required_features: Features,
}

// Keep public array inputs compatible with struct literals. Explicit copies
// remain the caller's responsibility; every owned config clone wipes itself.
impl Zeroize for ConnectionConfig {
    fn zeroize(&mut self) {
        self.local_static_priv.zeroize();
    }
}

impl Drop for ConnectionConfig {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ConnectionConfig {}

/// An authenticated handshake cannot satisfy this application profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolFailure {
    InvalidAuthentication {
        reason: crate::AuthAcceptanceError,
    },
    UnsupportedProtocol {
        supported: u8,
    },
    MissingRequiredFeatures {
        required: Features,
        enabled: Features,
    },
    InvalidHandshake {
        reason: HsPayloadError,
    },
    UnofferedFeatures {
        enabled: Features,
    },
}

/// Link state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkState {
    Connecting,
    Live,
    PathDown,
    Closed,
}

/// A bounded send did not take ownership of any bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendBlocked {
    NotLive,
    Desynced,
    OffsetSpaceExhausted,
    WouldBlock,
}

// One current owner/frontier and one coalesced loss flag per u8 stream.
// Reuse replaces the owner; repeated discards cannot erase an earlier loss.
struct TrackedChannelOutput {
    instance: crate::channel_geometry::ChannelInstance,
    continuity_end: u64,
    lost: bool,
}

/// Event for the caller. Accumulates in an internal queue and is handed out
/// in a batch by `poll_events`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Handshake finished, transport encryption keys obtained.
    HandshakeDone,
    /// Server-side, once for this fresh key split: a transport packet passed
    /// authentication and replay acceptance. This precedes its stream events;
    /// owners must still drain the whole batch and reject a closing connection.
    /// Obtaining keys (`HandshakeDone`) alone does not prove fresh possession.
    PeerKeyConfirmed { peer: SocketAddr },
    /// Freshly delivered in-order bytes of stream `stream_id`.
    StreamData { stream_id: u8, data: Vec<u8> },
    /// Link state change.
    StateChanged(LinkState),
    /// Authenticated terminal peer failure, delivered before Closed.
    SessionAborted(crate::SessionAbortReason),
    /// The connection migrated to a new source address (roaming).
    Rehomed { peer: SocketAddr },
    /// Server-side: output was desynced during a long absence and the client
    /// returned, or a stream that can be rebuilt went past [`SEND_HARD_CAP`]
    /// and dropped its backlog -- the backend should repaint the current
    /// screen.
    OutputResync,
    /// Client-side: the peer reset stream `stream_id` (dropped its backlog).
    /// The renderer should clear partial stream state and let the repaint land.
    StreamReset { stream_id: u8 },
    /// Stream `stream_id` reached the end of its offset space
    /// ([`crate::reliability::OFFSET_LIMIT`]): its writes are refused from
    /// now on. Only without `offset-wrap` (a peer built before it): with it a
    /// stream has no end (spec §4.14). Reported once per stream per
    /// connection. The owner drops the connection WITHOUT a `Close`
    /// ([`Connection::abandon`]), so the daemon keeps the session. What the
    /// user sees depends on the client: the app reconnects warm and the
    /// repaint restores the screen; the console `qsh` reconnects warm the
    /// same way, into the same session. When the DAEMON
    /// abandons, the client hears nothing: it sits in `PathDown` until its
    /// death timer closes the connection.
    OffsetSpaceExhausted { stream_id: u8 },
    /// Stream `stream_id`'s tail went past [`SEND_HARD_CAP`] on a stream
    /// that cannot be rebuilt: a producer ignores its send gate. The data is
    /// kept. Reported once per stream per connection.
    SendBufferOverCap { stream_id: u8 },
    /// Client-side: msg2 enabled a feature msg1 did not offer -- a protocol
    /// violation (spec §5.2). Reported once; the connection closes, since
    /// reading msg2 spent the handshake.
    UnofferedFeatureEnabled { enabled: Features },
    /// Client-side: an authenticated msg2 payload could not be parsed.
    /// Reported once; reading msg2 spent the handshake, so the attempt closes.
    InvalidHandshakeResponse { reason: HsPayloadError },
    /// Authenticated msg2 omitted mandatory application features. No Live or
    /// queued application writes follow; the consumed attempt ends once.
    MissingRequiredFeatures {
        required: Features,
        enabled: Features,
    },
}

/// Outgoing datagram: where to send it and what to send.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Datagram {
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
}

/// What a handshake's msg2 needs, supplied by the `resolve` hook
/// `Connection::accept` calls once msg1 has decrypted, parsed, and passed
/// every check `accept` can still make on its own (announced method,
/// allowlist membership). Returning `None` from that hook refuses the
/// handshake -- see `accept`'s own docs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Msg2Inputs {
    /// Whether this handshake lands on the session its token names, rather
    /// than a fresh one -- the router's decision, not the client's request.
    pub resumed: bool,
    /// The single-use nonce to put in msg2. Minted by the hook's owner (a
    /// `NonceSource`), not by `accept` itself.
    pub nonce: [u8; AUTH_NONCE_LEN],
}

/// Outcome of `Connection::accept`: either the client failed validation (bad
/// Noise message, unknown static key, an unparseable msg1 payload, or a
/// refusal from the `resolve` hook), or it is accepted and the connection is
/// already `Live`.
// Rejected is empty and Accepted carries a whole Connection, but the value
// is returned from `accept` and destructured immediately -- it is never
// stored anywhere the size difference would cost anything.
#[allow(clippy::large_enum_variant)]
pub enum AcceptOutcome {
    /// Validation failed. No peer address or key was recorded, and no msg2
    /// was produced.
    Rejected,
    /// The client passed the Noise handshake and the auth policy check.
    Accepted {
        /// The new connection, already in the `Live` state.
        conn: Connection,
        /// The client's authenticated static public key.
        client_key: [u8; 32],
        /// The parsed msg1 payload (start kind + session token).
        msg1: Msg1Payload,
        /// Outgoing datagrams to send back (the msg2 handshake response).
        out: Vec<Datagram>,
        /// The nonce this handshake's msg2 carried. The probation stage
        /// checks the client's proof echoes exactly this one back.
        nonce: [u8; AUTH_NONCE_LEN],
    },
}

/// Internal router choice after all msg1 validation, before fresh msg2 work.
pub(crate) enum Msg2Resolution {
    Fresh(Msg2Inputs),
    // Only the optional async manager requests cached replies.
    #[cfg(any(feature = "tokio-driver", test))]
    Cached,
}

pub(crate) struct AcceptedHandshake {
    pub(crate) conn: Connection,
    pub(crate) client_key: [u8; 32],
    pub(crate) msg1: Msg1Payload,
    pub(crate) out: Vec<Datagram>,
    pub(crate) nonce: [u8; AUTH_NONCE_LEN],
}

// Like AcceptOutcome, this is immediately destructured rather than stored.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ResolvedAccept {
    Rejected,
    Fresh(AcceptedHandshake),
    #[cfg(any(feature = "tokio-driver", test))]
    Cached {
        client_key: [u8; 32],
        msg1: Msg1Payload,
    },
}

/// Summary connection statistics.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stats {
    pub rehomes: u32,
    /// The round trip in whole milliseconds, rounded, at least 1; 0 means
    /// nothing has been measured yet.
    pub rtt_ms: u32,
    pub retransmits: u32,
    /// Whole seconds since an ordinary (non-probing) frame last arrived on
    /// the road in use. There is no "never" case: the mark is re-baselined
    /// when the handshake completes, so zero means "just now".
    ///
    /// Seconds rather than milliseconds on purpose: the driver publishes
    /// statistics only when they change, and a millisecond count would
    /// change on every turn of its loop.
    pub silent_secs: u32,
}

/// How far one outgoing stream has got: how many bytes were ever queued on
/// it, and how many of those the peer has not acknowledged yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StreamProgress {
    pub queued: u64,
    pub unacked: u64,
}

/// Where a round-trip measurement came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RttSource {
    /// msg1 -> msg2 on a client whose msg1 was not retransmitted.
    Handshake,
    /// A PING answered by its PONG.
    Ping,
}

/// One round-trip measurement, kept at full `Duration` precision: a round
/// trip under a millisecond is a measurement like any other, not "none".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RttSample {
    pub value: Duration,
    pub source: RttSource,
}

/// A measured round trip as the header shows it: whole milliseconds, rounded,
/// and never 0 -- 0 in `Stats::rtt_ms` means nothing has been measured.
fn display_ms(rtt: Duration) -> u32 {
    let ms = (rtt.as_micros() + 500) / 1000;
    ms.clamp(1, u128::from(u32::MAX)) as u32
}

/// What a msg1 payload offers (spec §5.2): its `offered` field, and nothing
/// for a payload that does not parse -- like the empty one of
/// [`Connection::start`] -- or predates the field.
fn offered_in(msg1_payload: &[u8]) -> Features {
    parse_msg1(msg1_payload)
        .map(|m| m.offered)
        .unwrap_or(Features::NONE)
}

/// Sender+receiver pair for one logical stream `stream_id`.
struct StreamState {
    sender: StreamSender,
    receiver: StreamReceiver,
}

impl StreamState {
    fn new(stream_id: u8, features: Features) -> Self {
        let mut st = StreamState {
            sender: StreamSender::new(stream_id),
            receiver: StreamReceiver::new(stream_id),
        };
        st.set_features(features);
        st
    }

    /// What the connection agreed, for both halves (spec §4.14, §6).
    fn set_features(&mut self, features: Features) {
        self.sender.set_features(features);
        self.receiver.set_features(features);
    }
}

/// The single sans-IO connection object. Ties together the Noise IK
/// handshake, transport encryption, the reliable ordered stream, liveness
/// (PING/PONG), and address migration on roaming.
pub struct Connection {
    role: Role,
    local_priv: Zeroizing<[u8; 32]>,
    remote_pub: Option<[u8; 32]>,
    auth: AuthPolicy,
    /// What this side's configuration allows (`ConnectionConfig::features`).
    allowed_features: Features,
    required_features: Features,
    /// Client: what this handshake's msg1 offered, read back from the payload
    /// it was started with (`NONE` for one that does not parse, like the
    /// empty payload of `start`), less what this build does not implement.
    offered_features: Features,
    /// What this connection uses, from the handshake on (spec §5.4): the
    /// server decides it writing msg2, the client reads it there.
    features: Features,
    /// Test-only knob ([`Connection::act_as_legacy_peer_for_test`]): play a
    /// build from before negotiation. Always `false` in production.
    legacy_peer: bool,
    /// Test-only knob ([`Connection::stick_forced_ping_for_test`]): a forced
    /// PING that `on_timeout` never clears -- a deadline that stays due
    /// however often it is served, each service sending a PING. Always
    /// `false` in production.
    forced_ping_sticks: bool,
    /// Test-only ([`Connection::watch_drop_for_test`]): held here so a test
    /// can tell, through a `Weak`, when this connection is dropped.
    #[cfg(all(test, feature = "tokio-driver"))]
    alive_for_test: Option<std::sync::Arc<()>>,

    /// The handshake lives only during the `Connecting` phase; after
    /// `into_transport` it is taken by value and the keys move into `keys`.
    handshake: Option<Handshake>,
    keys: Option<TransportKeys>,

    state: LinkState,
    /// Set once a `StreamFrame::Close` has been processed: the peer closed the
    /// session gracefully. Distinguishes a graceful `Closed` (immediate
    /// teardown) from a `Closed` reached via the `DEATH_AFTER` liveness timeout
    /// (retain the backend). Read through [`Connection::closed_gracefully`].
    closed_gracefully: bool,
    session_abort: Option<crate::SessionAbortReason>,
    session_id: u64,
    /// Set by [`Connection::set_death_after`]; `None` leaves the role's own
    /// default in force.
    death_after_override: Option<Duration>,
    /// What the server answered about this handshake: whether it landed on
    /// the session the client asked for by token, or on a fresh one. Only
    /// meaningful on a client, and only after the handshake completes.
    resumed: bool,
    /// The nonce the server issued for this handshake, read from msg2.
    /// `None` on a client that talked to a server too old to send one, and
    /// always `None` on a server (which keeps its own copy in
    /// [`AcceptOutcome::Accepted`] instead). Meaningful once the link is
    /// `Live`.
    server_nonce: Option<[u8; AUTH_NONCE_LEN]>,
    peer: Option<SocketAddr>,
    /// Daemon probation accepts transport only from its handshake's source.
    /// Noise possession alone must not redirect replies before admission.
    probation_source: Option<SocketAddr>,
    /// The authenticated remote static key, recorded once the handshake
    /// completes (server: the client's key from msg1; unset on the client
    /// path today).
    peer_static: Option<[u8; 32]>,

    /// The roads this connection may use. Empty for a server, and for a
    /// client whose owner named a single address -- then nothing is checked
    /// and nothing costs anything.
    paths: PathTable,

    /// The Noise handshake hash of the CURRENT handshake, kept after the
    /// handshake state itself is consumed: the auth gate verifies a client's
    /// signature against it, and a warm reattach replaces it with the new
    /// connection's value.
    handshake_hash: [u8; 32],

    /// Monotonic nonce counter for our outgoing transport datagrams.
    next_counter: u64,
    /// Anti-replay window for incoming transport datagrams.
    replay: ReplayWindow,
    /// Server-only latch for the first authenticated, replay-accepted packet
    /// under this Connection's fresh split. Reattachment uses a new Connection.
    peer_key_confirmed: bool,

    streams: BTreeMap<u8, StreamState>,
    /// The stream number a PONG's one `CREDIT` copy is looked for from
    /// first (spec §6.4, ruling R15): the streams that may be stopped take
    /// it in turn, so one of them cannot starve the others.
    pong_credit_next: u8,
    /// ACK points waiting to go, per stream (spec §4.11): the latest a DATA
    /// or a `Reset` left, so a datagram of many frames on one stream draws
    /// one ACK (ruling R16). Bounded by the stream-number space.
    acks_due: BTreeMap<u8, u32>,
    /// `CREDIT` announcements waiting to go, per stream: the newest limit.
    /// Bounded by the stream-number space.
    credits_due: BTreeMap<u8, u32>,
    /// When the first service frame now waiting was queued: they go alone
    /// `ACK_DELAY` after it if nothing carries them sooner (spec §4.11).
    service_since: Option<Instant>,
    /// Whether one of them must go at once (spec §4.11): a `Reset`, a DATA
    /// that did not extend an unbroken stream (a repeat, one past a hole,
    /// one that fills a hole), `ACK_EVERY` DATA that did, room for a sender
    /// that may be stopped at its limit -- or a peer played as built
    /// before delayed ACKs.
    service_urgent: bool,
    /// In-order DATA frames taken since an ACK last went out.
    data_since_ack: usize,
    events: Vec<Event>,

    /// What the session layer said about each stream: whether its backlog
    /// may be dropped after a long absence and rebuilt afterwards. Only the
    /// layer above knows -- a channel's backlog is recoverable exactly when
    /// that channel has a screen model to redraw from, and this module has
    /// never heard of screens.
    ///
    /// A stream nobody declared falls back to the old single-product
    /// protocol's rule, where stream 0 IS the bulk output. That is what
    /// keeps the tmux hybrid and `serve_shell` behaving exactly as they did:
    /// neither declares anything.
    ///
    /// Bounded by the stream-number space (256 entries); a reused number
    /// overwrites its predecessor's declaration.
    stream_resyncable: BTreeMap<u8, bool>,
    channel_output: BTreeMap<u8, TrackedChannelOutput>,
    /// What the session layer declared about each stream's class (spec
    /// §4.8). A stream nobody declared is `Interactive`. Bounded by the
    /// stream-number space.
    stream_class: BTreeMap<u8, StreamClass>,
    /// What a stream nobody declared follows.
    default_consumption: Consumption,
    /// What the owner declared per stream. Bounded by the stream-number
    /// space.
    stream_consumption: BTreeMap<u8, Consumption>,
    /// Per class (`StreamClass as usize`): where the round-robin stopped, so
    /// the next flush goes on from there.
    rr_cursor: [Option<RrPosition>; 2],
    /// Streams already reported as out of offset space, so each is reported once.
    offset_exhausted: HashSet<u8>,
    /// Streams already reported past SEND_HARD_CAP, so each is reported once.
    over_cap_reported: HashSet<u8>,
    /// What out-of-order data this connection may hold across its streams
    /// (see [`UNDELIVERED_CAP`]).
    undelivered_cap: usize,
    /// Out-of-order data held on every stream, as the receivers count it:
    /// the sum of their `buffered_cost`, kept up as each one changes, so a
    /// DATA frame does not add up every stream to learn its room.
    undelivered: usize,

    /// Time of the last authenticated incoming packet, of ANY content --
    /// including a packet carrying nothing but path checks. Answers "is the
    /// peer alive at all", which is what the death timer (`death_after`)
    /// asks: a client that is plainly alive on some road must never have its
    /// session killed, and that is true even when the only thing heard from
    /// it lately is a spare road answering a check. See
    /// [`Connection::last_recv_ordinary`] for "is the road IN USE quiet",
    /// which is a different question with a different answer once a session
    /// has more than one road.
    last_recv_auth: Instant,
    /// Time of the last authenticated incoming packet that carried at least
    /// one non-probing frame -- `!probing_only` in `on_transport`, the same
    /// test used there. Ordinary frames are only ever sent to the road
    /// currently in use, so one of them coming back is proof THAT road
    /// works, whatever address it happened to be sourced from; a check's
    /// answer proves only that the road it was sent down still works, not
    /// that the road in use does. Everything that decides "the road in use
    /// has gone quiet" reads this instant instead of `last_recv_auth`:
    /// `PATH_DOWN_AFTER`, `RESYNC_AFTER`, and the `PathDown` -> `Live`
    /// revival.
    last_recv_ordinary: Instant,

    /// The PINGs sent and not yet answered, oldest first, as `(token, when it
    /// went out)`, at most [`MAX_OUTSTANDING_PINGS`]. Several, not one: on a
    /// road whose round trip is longer than `PING_INTERVAL` the next PING is
    /// minted while the last is still on its way, and a PONG for it is still
    /// an answer -- keeping only the latest token would throw every PONG away
    /// and leave the round trip unmeasured and `ping_unanswered` set for good.
    outstanding_pings: Vec<(u32, Instant)>,
    /// Whether a PING has gone unanswered for longer than it should -- set
    /// when a new PING is minted while an outstanding one is older than both
    /// the interval in force and the retransmit timeout (`rto`, twice the
    /// measured round trip), cleared when a PONG for any outstanding PING
    /// arrives. The retransmit timeout is what keeps a slow road's PINGs,
    /// which are always still in flight when the next one goes, from reading
    /// as unanswered.
    ///
    /// This, not `outstanding_pings` being non-empty, is what urgency means
    /// (see [`Connection::probes_are_urgent`]): a PING is outstanding for one
    /// round trip out of every interval, so reading that as urgency would
    /// speed the road checks up while the live road is perfectly healthy.
    ping_unanswered: bool,
    /// When the PINGs were found unanswered -- the mint that set
    /// `ping_unanswered` -- set together with it and cleared with it. Not when
    /// the oldest unanswered PING went out: the dead-road rule in
    /// [`Connection::on_timeout`] asks whether a check was sent down the road
    /// AFTER the road was already known to be dropping PINGs, and then failed
    /// too. A PING and a check lost in the same moment, and a second PING lost
    /// later, are three independent losses, not that.
    ping_unanswered_since: Option<Instant>,
    /// Time of the last PING sent -- drives the PING period by wall-clock time,
    /// independent of data sends. Otherwise continuous outgoing traffic (e.g. a
    /// debug counter plus ACKs) would keep pushing any send-based schedule back
    /// forever, idle time would never accrue, PING would never go out, and
    /// the round trip would never be measured.
    last_ping_sent: Option<Instant>,
    /// When the handshake completed: where the first PING is scheduled from,
    /// until there is a `last_ping_sent`. Not `last_recv_auth`, which every
    /// packet received moves: a server streaming output from the start of
    /// the session (a clock in tmux, `htop` after a reconnect) would push the
    /// first PING back for ever, and with it the round trip and the
    /// unanswered-PING evidence the dead-road rule reads.
    handshake_at: Instant,
    /// One-shot forced PING for the next `on_timeout` (set on rebind: we ping
    /// immediately from the new address -- this measures RTT and migrates the
    /// server).
    ping_forced: bool,
    /// PING token counter.
    ping_token: u32,

    /// When this client last re-pointed itself onto another road, if ever.
    /// A move is followed by a dwell (see [`Connection::may_move`]): without
    /// one the very next tick would offer the road just left straight back.
    moved_at: Option<Instant>,

    rehomes: u32,
    /// The round trip, or `None` while nothing has been measured (spec
    /// §4.3). Seeded on a client by its handshake, replaced by every PONG.
    rtt: Option<RttSample>,
    /// The retransmit timer's estimate (RFC 6298): every PONG and every data
    /// segment acknowledged without having been retransmitted.
    rtt_estimator: RttEstimator,
    /// How many times the retransmit timer has expired since the last round
    /// trip was measured: each expiry doubles the timeout (RFC 6298 §5.5),
    /// and a sample -- a PONG, or an ACK timed by Karn's rule -- resets it.
    rto_backoff: u32,
    /// Client: when msg1 went out, for the handshake seed.
    msg1_sent_at: Option<Instant>,
    /// Client: whether msg1 had to be sent again. A reply to a retransmitted
    /// msg1 cannot say which copy it answers, so it seeds nothing (Karn).
    handshake_retransmitted: bool,
    /// Client: the Noise msg1 this handshake sent, kept so it can go out
    /// again -- as it was, or behind a cookie (spec §4.16).
    msg1_body: Option<Vec<u8>>,
    /// Full cold-recovery catalog, separate from the bounded live path table.
    recovery_handshake: Option<RecoveryHandshake>,
    /// Client: the cookie the server last handed out for this msg1.
    cookie: Option<[u8; COOKIE_LEN]>,
    /// Client: whether the next retransmit goes out plain rather than
    /// behind `cookie` (spec §4.16). Once a cookie was taken the two take
    /// turns: a daemon built before cookies drops every msg1 behind one,
    /// and a party on the path that saw msg1 can hand the client a cookie
    /// in the daemon's name -- so a cookie must never stop the plain msg1
    /// from going out again.
    plain_turn: bool,
    retransmits: u32,
    /// How much DATA the whole connection may have in flight (spec §4.15).
    cc: CongestionWindow,
    /// Whether the last flush that put data out stopped at the window (or
    /// the bulk budget) with something still to send, or went past the
    /// window on the interactive allowance: only such a window grows when
    /// its ACKs come back. A flush with nothing to put out and nothing held
    /// back leaves it as it was: what is in flight went out under the
    /// verdict of the flush that sent it, and its ACKs are judged by that.
    /// Such empty flushes are frequent -- `on_timeout` flushes at every
    /// deadline, the delayed ACK's among them (spec §4.11) -- and each one
    /// taking the verdict back left a window that went past itself on the
    /// allowance never growing.
    window_limited: bool,
    /// The retransmit timer's back-off before the latest timeout, given back
    /// if that timeout turns out spurious.
    backoff_before_timeout: u32,
}

/// What one received datagram draws besides the ACKs and CREDITs queued in
/// `Connection::acks_due`/`credits_due` (ruling R16, spec §4.11): answers
/// are built per datagram, not per frame.
struct RoutedFrames {
    /// The last PING's token: one PONG answers the datagram's PINGs -- the
    /// pinger takes a PONG as the answer to that PING and every older one
    /// it still has out.
    pong: Option<u32>,
    /// The last `PathProbe`'s token: one answer, alone, to the datagram's
    /// source -- this checks the road we were asked about, not the one we
    /// use.
    probe_ack: Option<u32>,
    /// Whether an `Ack` in this packet moved some sender's base forward:
    /// room opened in that stream's window, and the next bytes go out now
    /// (ACK clocking, spec §4.2) rather than on the next timer -- or a
    /// `CREDIT` raised a sender's limit (spec §6.2) -- or a duplicate or
    /// partial ACK marked a segment to resend at once (spec §4.15).
    window_opened: bool,
}

/// Why [`Connection::use_road`] did not move the traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseRoadError {
    /// Not a client with a session: a server, a client before its handshake, or one that has
    /// closed.
    NoSession,
    /// The address is not one of the roads handed to [`Connection::set_paths`].
    UnknownRoad,
    /// The road did not answer its last check (or never has). Moving onto it would trade a
    /// working link for a silent one -- the same rule automatic moving follows.
    NotAnswering,
}

// A full DATA segment always fits one datagram (spec §3.2).
const _: () = assert!(8 + crate::reliability::MAX_SEGMENT_SIZE <= MAX_PLAINTEXT);

/// `ordered` and `service` frames packed into plaintexts of at most
/// [`MAX_PLAINTEXT`] bytes (spec §4.11). `ordered` keeps its order: each
/// frame goes after the one before it -- into the same plaintext if it fits,
/// else into a new one -- so DATA of one stream, or a `Reset` and the
/// repaint behind it, never reach a receiver out of order because of the
/// packing. `service` frames (ACK, CREDIT: cumulative and idempotent, their
/// order means nothing) each go into the first plaintext with room, a new
/// one if none has it: a full DATA segment (1032 bytes) leaves room for 22
/// of them.
fn pack(ordered: &[StreamFrame], service: &[StreamFrame]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for frame in ordered {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes);
        match out.last_mut() {
            Some(last) if last.len() + bytes.len() <= MAX_PLAINTEXT => {
                last.extend_from_slice(&bytes)
            }
            _ => out.push(bytes),
        }
    }
    for frame in service {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes);
        match out
            .iter_mut()
            .find(|p| p.len() + bytes.len() <= MAX_PLAINTEXT)
        {
            Some(p) => p.extend_from_slice(&bytes),
            None => out.push(bytes),
        }
    }
    out
}

impl Connection {
    /// Create a connection from config. The server immediately prepares a
    /// handshake responder; the client defers the initiator until `start` (that
    /// is where the peer address and the first message appear).
    pub fn new(cfg: ConnectionConfig) -> Self {
        Self::new_stamped(cfg, Instant::now())
    }

    /// Test-only: [`Connection::new`] with its clocks stamped at `now`
    /// instead of the real `Instant::now()`, so a simulator in virtual time
    /// owns every instant the connection ever sees.
    #[cfg(any(test, feature = "testnet"))]
    pub fn new_at(cfg: ConnectionConfig, now: Instant) -> Self {
        Self::new_stamped(cfg, now)
    }

    fn new_stamped(mut cfg: ConnectionConfig, now: Instant) -> Self {
        let handshake = match cfg.role {
            Role::Server => Some(Handshake::new_responder(&cfg.local_static_priv)),
            Role::Client => None,
        };
        Connection {
            role: cfg.role,
            local_priv: Zeroizing::new(cfg.local_static_priv),
            remote_pub: cfg.remote_static_pub,
            auth: std::mem::replace(&mut cfg.auth, AuthPolicy::Allowlist(vec![])),
            allowed_features: cfg.features,
            required_features: cfg.required_features,
            offered_features: Features::NONE,
            features: Features::NONE,
            legacy_peer: false,
            forced_ping_sticks: false,
            #[cfg(all(test, feature = "tokio-driver"))]
            alive_for_test: None,
            handshake,
            keys: None,
            state: LinkState::Connecting,
            closed_gracefully: false,
            session_abort: None,
            session_id: 0,
            death_after_override: None,
            resumed: false,
            server_nonce: None,
            peer: None,
            probation_source: None,
            peer_static: None,
            paths: PathTable::new(),
            handshake_hash: [0u8; 32],
            next_counter: 1,
            replay: ReplayWindow::default(),
            peer_key_confirmed: false,
            streams: BTreeMap::new(),
            pong_credit_next: 0,
            acks_due: BTreeMap::new(),
            credits_due: BTreeMap::new(),
            service_since: None,
            service_urgent: false,
            data_since_ack: 0,
            events: Vec::new(),
            stream_resyncable: BTreeMap::new(),
            channel_output: BTreeMap::new(),
            stream_class: BTreeMap::new(),
            default_consumption: Consumption::OnDelivery,
            stream_consumption: BTreeMap::new(),
            rr_cursor: [None, None],
            offset_exhausted: HashSet::new(),
            over_cap_reported: HashSet::new(),
            undelivered_cap: UNDELIVERED_CAP,
            undelivered: 0,
            last_recv_auth: now,
            last_recv_ordinary: now,
            outstanding_pings: Vec::new(),
            ping_unanswered: false,
            ping_unanswered_since: None,
            last_ping_sent: None,
            handshake_at: now,
            ping_forced: false,
            ping_token: 0,
            moved_at: None,
            rehomes: 0,
            rtt: None,
            rtt_estimator: RttEstimator::default(),
            rto_backoff: 0,
            msg1_sent_at: None,
            handshake_retransmitted: false,
            msg1_body: None,
            recovery_handshake: None,
            cookie: None,
            plain_turn: false,
            retransmits: 0,
            cc: CongestionWindow::new(),
            window_limited: false,
            backoff_before_timeout: 0,
        }
    }

    /// Accept an incoming client as a fresh server-side connection. Builds a
    /// responder from `cfg`, reads the Noise msg1 body (the handshake message
    /// bytes after the 2-byte wire header), verifies the client's static key
    /// against `cfg.auth`, and parses the versioned msg1 payload. Any
    /// failure along the way (malformed Noise message, unknown key,
    /// unparseable payload, a method that doesn't match the policy, or a
    /// refusal from `resolve`) yields `Rejected` -- no peer or key is
    /// recorded and no msg2 is produced. On success the connection is
    /// already `Live` with the msg2 response ready to send.
    ///
    /// `resolve` is called EXACTLY ONCE, and only once msg1 has decrypted,
    /// parsed, and passed every check `accept` can still make on its own
    /// (announced method, allowlist membership) -- the only moment the token
    /// lives inside the ENCRYPTED msg1 payload becomes readable, and msg2 is
    /// not yet written. It answers what msg2 needs
    /// ([`Msg2Inputs::resumed`], the router's decision rather than the
    /// client's request; [`Msg2Inputs::nonce`], minted by the caller's
    /// `NonceSource` rather than here -- so a system-mode server can obtain
    /// it from its privileged helper instead of generating it in the worker
    /// that talks to the network directly), or `None` to refuse the
    /// handshake outright (e.g. its owner could not obtain a nonce). A
    /// handshake that reaches `resolve` and gets `Some` back is guaranteed a
    /// msg2 -- nothing after this point can still fail.
    pub fn accept(
        cfg: ConnectionConfig,
        now: Instant,
        src: SocketAddr,
        msg1_bytes: &[u8],
        resolve: &mut dyn FnMut(&Msg1Payload) -> Option<Msg2Inputs>,
    ) -> AcceptOutcome {
        match Self::accept_resolved(cfg, now, src, msg1_bytes, &mut |msg1| {
            resolve(msg1).map(Msg2Resolution::Fresh)
        }) {
            ResolvedAccept::Rejected => AcceptOutcome::Rejected,
            ResolvedAccept::Fresh(AcceptedHandshake {
                conn,
                client_key,
                msg1,
                out,
                nonce,
            }) => AcceptOutcome::Accepted {
                conn,
                client_key,
                msg1,
                out,
                nonce,
            },
            #[cfg(any(feature = "tokio-driver", test))]
            ResolvedAccept::Cached { .. } => {
                unreachable!("fresh-only adapter requested cached msg2")
            }
        }
    }

    /// Validate msg1 once for either a fresh accept or a cached response.
    /// Cached returns before session-id generation, msg2 writing and key split;
    /// it does not bypass any cookie gate owned by the caller or checks here.
    pub(crate) fn accept_resolved(
        cfg: ConnectionConfig,
        now: Instant,
        src: SocketAddr,
        msg1_bytes: &[u8],
        resolve: &mut dyn FnMut(&Msg1Payload) -> Option<Msg2Resolution>,
    ) -> ResolvedAccept {
        let mut conn = Connection::new(cfg);
        let payload_bytes = {
            let hs = match conn.handshake.as_mut() {
                Some(h) => h,
                None => return ResolvedAccept::Rejected,
            };
            match hs.read_msg(msg1_bytes) {
                Ok(p) => p,
                Err(_) => return ResolvedAccept::Rejected,
            }
        };
        let client_key = match conn.handshake.as_ref().and_then(Handshake::remote_static) {
            Some(k) if conn.auth.admits(&k) => k,
            _ => return ResolvedAccept::Rejected,
        };
        let msg1 = match parse_msg1(&payload_bytes) {
            Ok(m) => m,
            Err(_) => return ResolvedAccept::Rejected,
        };
        // The client must announce the method this server actually runs:
        // silently downgrading a signature client to the allowlist path (or
        // the other way round) would leave one side thinking it authenticated.
        if msg1.method != conn.auth.method() {
            return ResolvedAccept::Rejected;
        }
        let features = Features::negotiate(msg1.offered, conn.allowed_features);
        if !features.contains(conn.required_features) {
            return ResolvedAccept::Rejected;
        }
        // The only call to `resolve`, and the last point at which this
        // handshake can still be refused -- see this function's docs.
        let Msg2Inputs { resumed, nonce } = match resolve(&msg1) {
            Some(Msg2Resolution::Fresh(inputs)) => inputs,
            #[cfg(any(feature = "tokio-driver", test))]
            Some(Msg2Resolution::Cached) => return ResolvedAccept::Cached { client_key, msg1 },
            None => return ResolvedAccept::Rejected,
        };
        // Spec §5.2: on when offered, allowed and implemented. The decision
        // is a function of msg1 and the configuration, so a retransmit twin
        // that went through probation on its own decides the same.
        let session_id: u64 = rand::thread_rng().gen();
        conn.session_id = session_id;
        let msg2 = conn
            .handshake
            .as_mut()
            .expect("handshake not yet taken")
            .write_msg(&encode_msg2(session_id, resumed, &nonce, features));
        let hs = conn.handshake.take().expect("handshake still present");
        conn.handshake_hash = hs.handshake_hash();
        // The server switches as it writes msg2 (spec §5.4).
        conn.keys = Some(hs.into_transport(features.contains(Features::HEADER_AAD)));
        conn.apply_features(features);
        conn.peer_static = Some(client_key);
        conn.peer = Some(src);
        conn.last_recv_auth = now;
        conn.handshake_at = now;
        // A slow (multi-retransmit) handshake must not look, the instant it
        // finishes, like the road that just came up had already gone quiet
        // for however long the handshake took.
        conn.last_recv_ordinary = now;
        conn.events.push(Event::HandshakeDone);
        let out = vec![Datagram {
            to: src,
            bytes: encode_handshake(Kind::HandshakeResp, &msg2),
        }];
        conn.set_state(LinkState::Live);
        ResolvedAccept::Fresh(AcceptedHandshake {
            conn,
            client_key,
            msg1,
            out,
            nonce,
        })
    }

    /// Start the connection. The client builds the IK initiator, remembers the
    /// peer, and returns the first handshake datagram. Empty for the server: it
    /// waits for the first message from the client.
    ///
    /// This is the no-payload form kept for backwards compatibility; it
    /// delegates to [`Connection::start_with_payload`] with an empty msg1
    /// payload, so it offers no features whatever `cfg.features` says --
    /// [`Connection::start_session`] is the form that negotiates.
    pub fn start(&mut self, now: Instant, peer: SocketAddr) -> Vec<Datagram> {
        self.start_with_payload(now, peer, &[])
    }

    /// Start the connection, carrying `msg1_payload` inside the Noise msg1.
    /// The client builds the IK initiator, remembers the peer, and returns the
    /// first handshake datagram (the msg1 payload is the versioned handshake
    /// body -- see [`crate::handshake_payload::encode_msg1`]). Empty for the
    /// server: it waits for the first message from the client.
    pub fn start_with_payload(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        msg1_payload: &[u8],
    ) -> Vec<Datagram> {
        self.recovery_handshake = None;
        self.session_abort = None;
        self.closed_gracefully = false;
        self.last_recv_auth = now;
        // Both liveness clocks start here, for the same reason
        // [`Connection::request_ping`] restarts both: whatever reads
        // `last_recv_ordinary` (`PATH_DOWN_AFTER`, and a client's death
        // timer) must not count the time before the connection existed as
        // silence on a road. Harmless today only because `on_timeout`
        // returns early while there are no keys.
        self.last_recv_ordinary = now;
        if !matches!(self.role, Role::Client) {
            return Vec::new();
        }
        // A client without the server's static key is misconfigured. This is
        // reachable via the public API, so we don't panic: close gracefully.
        let remote_pub = match self.remote_pub {
            Some(k) => k,
            None => {
                self.set_state(LinkState::Closed);
                return Vec::new();
            }
        };
        let mut hs = Handshake::new_initiator(&self.local_priv, &remote_pub);
        self.msg1_sent_at = Some(now);
        self.handshake_retransmitted = false;
        // A new handshake seeds its own round trip; the previous session's
        // measurement says nothing about this one.
        self.rtt = None;
        self.rtt_estimator = RttEstimator::default();
        self.rto_backoff = 0;
        let msg1 = hs.write_msg(msg1_payload);
        self.msg1_body = Some(msg1.clone());
        self.cookie = None;
        self.plain_turn = false;
        // What this msg1 offered, as its bytes say, and this build
        // implements: a msg2 enabling anything else is a violation (spec
        // §5.2). A msg1 built by hand may offer more than
        // [`Connection::start_session`] would; this build still must not
        // take what it cannot do.
        self.offered_features = offered_in(msg1_payload) & Features::SUPPORTED;
        self.apply_features(Features::NONE);
        self.handshake = Some(hs);
        self.peer = Some(peer);
        self.state = LinkState::Connecting;
        vec![Datagram {
            to: peer,
            bytes: encode_handshake(Kind::HandshakeInit, &msg1),
        }]
    }

    /// Start a client session (spec §5.2): msg1 carries `start_kind`,
    /// `token`, the method `cfg.auth` implements, and the features
    /// `cfg.features` allows that this build implements.
    pub fn start_session(
        &mut self,
        now: Instant,
        peer: SocketAddr,
        start_kind: StartKind,
        token: [u8; SESSION_TOKEN_LEN],
    ) -> Vec<Datagram> {
        let payload = encode_msg1(&Msg1Payload {
            start_kind,
            token,
            method: self.auth.method(),
            offered: self.allowed_features & Features::SUPPORTED,
        });
        self.start_with_payload(now, peer, &payload)
    }

    /// Start one recovery handshake over the complete eligible catalog.
    /// Requires negotiated `AUTH_ACCEPTED` in addition to the configured
    /// minimum, before Live or queued output. The offered bits are unchanged.
    /// Ordinary single-endpoint starts retain the configured feature minimum.
    pub fn start_recovery(
        &mut self,
        now: Instant,
        endpoints: Vec<RecoveryEndpoint>,
        start_kind: StartKind,
        token: [u8; SESSION_TOKEN_LEN],
    ) -> Vec<Datagram> {
        let Some(first) = endpoints.first() else {
            self.set_state(LinkState::Closed);
            return Vec::new();
        };
        // Construct the initiator once. Its initial datagram is replaced by
        // the bounded scheduler's dispatches, not sent a second time.
        let initial = self.start_session(now, first.endpoint, start_kind, token);
        if initial.is_empty() {
            return initial;
        }
        self.msg1_sent_at = None;
        self.recovery_handshake = Some(RecoveryHandshake::new(now, endpoints));
        self.poll_recovery_handshake(now)
    }

    /// Acknowledge the actual I/O attempt for one scheduled msg1 datagram.
    pub fn recovery_handshake_sent(&mut self, now: Instant, to: SocketAddr, success: bool) {
        if let Some(schedule) = &mut self.recovery_handshake {
            schedule.sent(now, to, success);
        }
    }

    /// Scheduled copies keep the same initiator body, even after one responder
    /// was selected. Other responders are never read through that initiator.
    pub fn poll_recovery_handshake(&mut self, now: Instant) -> Vec<Datagram> {
        if self.state == LinkState::Closed {
            return Vec::new();
        }
        let (Some(schedule), Some(msg1)) = (&mut self.recovery_handshake, &self.msg1_body) else {
            return Vec::new();
        };
        schedule
            .poll(now)
            .into_iter()
            .map(|dispatch| Datagram {
                to: dispatch.endpoint,
                bytes: match dispatch.cookie {
                    Some(cookie) => encode_handshake_init_cookie(&cookie, msg1),
                    None => encode_handshake(Kind::HandshakeInit, msg1),
                },
            })
            .collect()
    }

    pub fn recovery_handshake(&self) -> Option<&RecoveryHandshake> {
        self.recovery_handshake.as_ref()
    }

    /// Accepted authentication or cancellation stops recovery scheduling. It
    /// does not alter the selected transport or claim remote rollback.
    pub fn stop_recovery_handshake(&mut self) {
        if let Some(schedule) = &mut self.recovery_handshake {
            schedule.retire();
        }
    }

    /// Handle an incoming datagram from address `src`. Malformed input (too
    /// short, unknown kind, forged, replayed) does not crash the connection -- it
    /// is silently ignored.
    pub fn on_datagram(&mut self, now: Instant, src: SocketAddr, bytes: &[u8]) -> Vec<Datagram> {
        // A closed session is deaf: a late packet, even an authentic one,
        // must not update liveness, migrate, or deliver data. Symmetric with
        // `on_timeout`/`next_timeout`, where `Closed` is already short-circuited.
        if matches!(self.state, LinkState::Closed) {
            return Vec::new();
        }
        let frame = match parse(bytes) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        match frame {
            Frame::Handshake {
                kind: Kind::HandshakeInit,
                body,
            } => self.on_handshake_init(now, src, body),
            Frame::Handshake {
                kind: Kind::HandshakeResp,
                body,
            } => self.on_handshake_resp(now, src, body),
            Frame::Handshake {
                kind: Kind::CookieReply,
                body,
            } => self.on_cookie_reply(now, src, body),
            // What a `Connection` never answers: a msg1 behind a cookie
            // (`HandshakeInitCookie` -- the session manager takes the cookie
            // off and hands `accept` the plain msg1, spec §4.16) and
            // discovery (`KeyRequest`, answered by the session manager;
            // `KeyOffer`, read by `sshauth`'s discovery on a socket of its
            // own), both before any connection exists. A `Transport` kind
            // never arrives here: `parse` separates them.
            Frame::Handshake { .. } => Vec::new(),
            Frame::Transport {
                session_id,
                counter,
                aead,
                aad,
            } => self.on_transport(now, src, session_id, counter, aad, aead),
        }
    }

    /// Register the current typed owner without carrying a predecessor's loss.
    pub(crate) fn declare_channel_output(
        &mut self,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
    ) {
        if self
            .channel_output
            .get(&stream)
            .is_none_or(|state| state.instance != instance)
        {
            self.channel_output.insert(
                stream,
                TrackedChannelOutput {
                    instance,
                    continuity_end: 0,
                    lost: false,
                },
            );
        }
    }

    /// Called after successful DATA admission or a warning disclosing prior DATA loss.
    pub(crate) fn track_channel_continuity_end(
        &mut self,
        stream: u8,
        instance: crate::channel_geometry::ChannelInstance,
        continuity_end: u64,
    ) {
        self.declare_channel_output(stream, instance);
        self.channel_output.get_mut(&stream).unwrap().continuity_end = continuity_end;
    }

    /// Coalesced DATA loss or an unconfirmed warning about earlier DATA loss,
    /// classified against ACK state at discard time.
    /// Taking observations clears flags, never the current continuity frontier.
    pub(crate) fn take_discarded_output(
        &mut self,
    ) -> Vec<(u8, crate::channel_geometry::ChannelInstance)> {
        self.channel_output
            .iter_mut()
            .filter_map(|(&stream, state)| {
                std::mem::take(&mut state.lost).then_some((stream, state.instance))
            })
            .collect()
    }

    /// The model has ended: this stream can no longer regenerate a snapshot.
    /// If a discard already happened, arm its existing Reset exactly once.
    pub(crate) fn retain_stream_output(&mut self, stream: u8) -> bool {
        self.set_stream_resyncable(stream, false);
        if let Some(state) = self.streams.get_mut(&stream) {
            if state.sender.is_desynced() {
                state.sender.begin_resync();
                return true;
            }
        }
        false
    }

    fn discard_stream_output(&mut self, stream: u8) {
        let sender = &mut self.stream_mut(stream).sender;
        if sender.is_desynced() {
            return;
        }
        let queued = sender.queued_total();
        let acknowledged = queued - sender.unacked_len() as u64;
        sender.mark_desynced();
        if let Some(state) = self.channel_output.get_mut(&stream) {
            state.lost |= state.continuity_end > acknowledged && state.continuity_end <= queued;
            state.continuity_end = 0;
        }
        self.cc.forget_stream(stream);
    }

    /// Declare whether `stream_id`'s backlog may be dropped after a long
    /// absence. Called by the session layer when it opens a stream whose
    /// recoverability it knows.
    pub fn set_stream_resyncable(&mut self, stream_id: u8, resyncable: bool) {
        self.stream_resyncable.insert(stream_id, resyncable);
    }

    /// Whether this stream's backlog may be dropped after a long absence.
    fn is_bulk_output_stream(&self, stream_id: u8) -> bool {
        match self.stream_resyncable.get(&stream_id) {
            Some(declared) => *declared,
            None => stream_id == OUTPUT_STREAM,
        }
    }

    /// Declare `stream_id`'s class (spec §4.8). Called by the session layer
    /// when it opens a stream whose use it knows.
    pub fn set_stream_class(&mut self, stream_id: u8, class: StreamClass) {
        self.stream_class.insert(stream_id, class);
    }

    /// Cap the out-of-order data this connection holds across its streams
    /// (see [`UNDELIVERED_CAP`]). What it holds past a lowered cap stays;
    /// nothing more is kept until it drains below.
    pub fn set_undelivered_cap(&mut self, cap: usize) {
        self.undelivered_cap = cap;
    }

    /// Declare how `stream_id`'s consumption is counted (spec §4.10.1).
    pub fn set_stream_consumption(&mut self, stream_id: u8, consumption: Consumption) {
        self.stream_consumption.insert(stream_id, consumption);
    }

    /// How every stream nobody declared counts its consumption.
    pub fn set_default_consumption(&mut self, consumption: Consumption) {
        self.default_consumption = consumption;
    }

    fn consumption_of(&self, stream_id: u8) -> Consumption {
        self.stream_consumption
            .get(&stream_id)
            .copied()
            .unwrap_or(self.default_consumption)
    }

    /// The consumer of `stream_id` took `n` more bytes (spec §4.10.1): the
    /// window moves on, and a `CREDIT` goes out if it is worth one (spec
    /// §6.4). Ignored for a stream counted on delivery. A closed connection
    /// still counts -- the daemon's `ConsumptionLedger` still settles a
    /// backend's late report against whichever connection is owed it, closed
    /// or not (session_manager.rs) -- but sends nothing.
    pub fn on_consumed(&mut self, now: Instant, stream_id: u8, n: usize) -> Vec<Datagram> {
        let mut out = Vec::new();
        if n == 0 || self.consumption_of(stream_id) == Consumption::OnDelivery {
            return out;
        }
        let Some(st) = self.streams.get_mut(&stream_id) else {
            return out;
        };
        st.receiver.on_consumed(n as u64);
        let stopped = st.receiver.may_be_stopped();
        let credit = st.receiver.credit_due(now, false);
        // A closed connection sends nothing, so it queues nothing either: a
        // CREDIT left waiting would go out with whatever a stray datagram
        // drew.
        if !matches!(self.state, LinkState::Closed) {
            // Room for a sender that may be stopped at its limit goes at
            // once (spec §4.11, §6.4); other room rides, `ACK_DELAY` at most.
            self.queue_credit(now, credit, stopped);
            self.flush_service_if_due(now, &mut out);
        }
        out
    }

    /// Every ACK and `CREDIT` this side owes, sent now rather than with a
    /// ride or at `ACK_DELAY` (spec §4.11): for an owner about to stop
    /// pumping the connection for a while -- a probation verifying a proof,
    /// which may take as long as a PAM stack does. Nothing on a closed
    /// connection. Only probation calls it, so it exists only where
    /// probation does.
    #[cfg(feature = "tokio-driver")]
    pub(crate) fn answer_now(&mut self) -> Vec<Datagram> {
        let mut out = Vec::new();
        if !matches!(self.state, LinkState::Closed) {
            self.flush_service(&mut out);
        }
        out
    }

    /// Every stream with bytes delivered and not consumed yet, and how many.
    pub fn unconsumed_streams(&self) -> Vec<(u8, u64)> {
        self.streams
            .iter()
            .filter_map(|(id, s)| {
                let n = s.receiver.unconsumed();
                (n > 0).then_some((*id, n))
            })
            .collect()
    }

    /// Out-of-order data held on every stream, counted afresh: what
    /// `undelivered` always equals.
    fn recount_undelivered(&self) -> usize {
        self.streams
            .values()
            .map(|s| s.receiver.buffered_cost())
            .sum()
    }

    /// Take one receiver's change of cost, `before` to `after`, into
    /// `undelivered`.
    fn note_undelivered(&mut self, before: usize, after: usize) {
        self.undelivered = self.undelivered + after - before;
        debug_assert_eq!(self.undelivered, self.recount_undelivered());
    }

    /// The class declared for `stream_id` (`Interactive` if none was).
    pub fn stream_class(&self, stream_id: u8) -> StreamClass {
        self.class_of(stream_id)
    }

    fn class_of(&self, stream_id: u8) -> StreamClass {
        self.stream_class
            .get(&stream_id)
            .copied()
            .unwrap_or_default()
    }

    /// Bytes a whole-record handoff can admit now without exceeding the local
    /// unacked cap, negotiated credit or offset space. Does not create a stream.
    /// The existing global hard cap remains an additional ceiling.
    pub fn stream_write_room(&self, stream: u8, max_unacked: usize) -> usize {
        if self.state != LinkState::Live {
            return 0;
        }
        let cap = max_unacked.min(SEND_HARD_CAP);
        if let Some(state) = self.streams.get(&stream) {
            state.sender.write_room(cap)
        } else {
            let mut sender = StreamSender::new(stream);
            sender.set_features(self.features);
            sender.write_room(cap)
        }
    }

    /// Distinguish permanent framing exhaustion from recoverable credit pressure.
    pub(crate) fn stream_offset_room(&self, stream: u8) -> u64 {
        self.streams.get(&stream).map_or_else(
            || {
                let mut sender = StreamSender::new(stream);
                sender.set_features(self.features);
                sender.offset_room()
            },
            |state| state.sender.offset_room(),
        )
    }

    /// Atomically admit the complete slice before sender allocation. Err leaves
    /// every byte with its caller: no stream creation, event, flush or partial
    /// append. Producers retain their permit/charge until this returns Ok.
    pub fn try_send_bounded(
        &mut self,
        now: Instant,
        stream: u8,
        bytes: &[u8],
        max_unacked: usize,
    ) -> Result<Vec<Datagram>, SendBlocked> {
        if self.state != LinkState::Live {
            return Err(SendBlocked::NotLive);
        }
        if let Some(state) = self.streams.get(&stream) {
            if state.sender.is_desynced() {
                return Err(SendBlocked::Desynced);
            }
            if bytes.len() as u64 > state.sender.offset_room() {
                return Err(SendBlocked::OffsetSpaceExhausted);
            }
        }
        if bytes.len() > self.stream_write_room(stream, max_unacked) {
            return Err(SendBlocked::WouldBlock);
        }
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        self.stream_mut(stream)
            .sender
            .push(bytes)
            .map_err(|_| SendBlocked::OffsetSpaceExhausted)?;
        let mut out = Vec::new();
        self.flush_senders(now, &mut out);
        Ok(out)
    }

    /// Consume a whole source Vec after copying into the reliable sender. A
    /// blocked record is returned unchanged. Callers account source scratch and
    /// reliable bytes independently while both exist; this is not zero-copy.
    pub(crate) fn try_send_consuming_bounded(
        &mut self,
        now: Instant,
        stream: u8,
        bytes: Vec<u8>,
        max_unacked: usize,
    ) -> Result<Vec<Datagram>, (SendBlocked, Vec<u8>)> {
        match self.try_send_bounded(now, stream, &bytes, max_unacked) {
            Ok(datagrams) => Ok(datagrams),
            Err(reason) => Err((reason, bytes)),
        }
    }

    /// Queue bytes of stream `stream_id` for reliable sending. Before reaching
    /// `Live`, no datagrams are emitted -- bytes accumulate and go out on the
    /// transition.
    pub fn send(&mut self, now: Instant, stream_id: u8, data: &[u8]) -> Vec<Datagram> {
        if self.stream_mut(stream_id).sender.push(data).is_err()
            && self.offset_exhausted.insert(stream_id)
        {
            self.events.push(Event::OffsetSpaceExhausted { stream_id });
        }
        self.enforce_hard_cap(stream_id);
        if !matches!(self.state, LinkState::Live) {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.flush_senders(now, &mut out);
        out
    }

    /// Spec §4.7.1. A server stream whose backlog the session layer can
    /// rebuild (a screen model) takes the long-absence path at once: drop the
    /// backlog, arm a `Reset`, ask for a repaint. Anything else -- including
    /// every client stream, stream 0 among them, which nothing on a client
    /// can rebuild -- keeps its bytes and is reported once.
    fn enforce_hard_cap(&mut self, stream_id: u8) {
        if self.stream_mut(stream_id).sender.unacked_len() <= SEND_HARD_CAP {
            return;
        }
        if matches!(self.role, Role::Server) && self.is_bulk_output_stream(stream_id) {
            self.discard_stream_output(stream_id);
            self.stream_mut(stream_id).sender.begin_resync();
            self.events.push(Event::OutputResync);
        } else if self.over_cap_reported.insert(stream_id) {
            self.events.push(Event::SendBufferOverCap { stream_id });
        }
    }

    /// Handle a timer firing: ARQ retransmits, idle PING, and liveness
    /// transitions (`PathDown`, `Closed`). A client also checks its roads here
    /// and moves off the road in use when the link is down: `PathDown`, or the
    /// road in use failed its check while its PINGs go unanswered, the two
    /// failures overlapping in time.
    pub fn on_timeout(&mut self, now: Instant) -> Vec<Datagram> {
        let mut out = Vec::new();
        if self.keys.is_none() || matches!(self.state, LinkState::Closed) {
            return out;
        }
        if now.saturating_duration_since(self.death_base()) >= self.death_after() {
            self.set_state(LinkState::Closed);
            return out;
        }
        // Whether the road IN USE is quiet is judged from `last_recv_ordinary`,
        // not `last_recv_auth`: a spare road's check answer is authentic (so
        // it rightly keeps the connection off the death timer above) but says
        // nothing about the road actually carrying traffic.
        let since_road_live = now.saturating_duration_since(self.last_recv_ordinary);
        if matches!(self.state, LinkState::Live) && since_road_live >= PATH_DOWN_AFTER {
            self.set_state(LinkState::PathDown);
        }
        // Checks for the backup roads, and a move if the live one has gone
        // quiet. Client only: see `set_paths`.
        if matches!(self.role, Role::Client) {
            let urgent = self.probes_are_urgent();
            for (to, token) in self.paths.due(now, urgent) {
                self.emit_frames_to(to, vec![StreamFrame::PathProbe { token }], &mut out);
            }
            // The road in use failing its own check while its PINGs go unanswered counts as
            // the link being down, even while ordinary traffic still arrives: that traffic may
            // be the server talking over the road this client left (it follows the client
            // only once an ordinary packet reaches it over the new one), which keeps
            // `last_recv_ordinary` fresh and `PATH_DOWN_AFTER` from ever firing while
            // everything this client sends goes down a dead road -- a road chosen by hand while
            // its last answer was still standing.
            //
            // Both halves are needed, and they have to overlap in time: the PINGs must have
            // been found unanswered no later than the failed check was SENT, so that the
            // check went down a road already known to be dropping PINGs, failed too, and the
            // PINGs are still unanswered now. Anchoring on the check's expiry instead would
            // pair losses up to `PROBE_TIMEOUT` apart. A failed check alone is one lost datagram, and an
            // unanswered PING alone is only a slow round trip or another lost datagram; two
            // such losses seconds apart say nothing about the road being dead. A single loss
            // also does not linger: a road in use that reads `Dead` makes the checks urgent
            // (`probes_are_urgent`), so it is checked again within `PROBE_URGENT` and heals
            // one round trip later, and a PONG clears `ping_unanswered`. A road that is really
            // dead keeps failing those checks, one every `PROBE_TIMEOUT` or so, and each new
            // failure overlaps the PINGs going unanswered.
            //
            // The state is not touched: with no verified road to go to, flipping it here would
            // only have the arriving traffic flip it back on every tick.
            let road_in_use_failed_at = self.peer.and_then(|p| self.paths.failed_at(p));
            let failures_overlap = road_in_use_failed_at
                .zip(self.ping_unanswered_since)
                .is_some_and(|(check_sent, pings_found)| pings_found <= check_sent);
            let link_down = matches!(self.state, LinkState::PathDown) || failures_overlap;
            if link_down && self.may_move(now) {
                if let Some(better) = self.paths.best(self.peer) {
                    if self.paths.is_verified(better) {
                        self.set_peer(better);
                        self.moved_at = Some(now);
                        // Prove the new road at once, as a move by hand does: an ordinary
                        // packet down it clears `PathDown` after one round trip and makes the
                        // server follow. Waiting for the scheduled PING instead outlasts the
                        // dwell, and the client would bounce back onto the road it just left
                        // while that road's last answer is still standing.
                        self.force_ping_on_a_new_road();
                    }
                }
            }
        }
        // After a long absence while the path is down, the server stops
        // hoarding output on the streams whose backlog the session layer
        // declared droppable (see [`Connection::is_bulk_output_stream`]):
        // memory for them is bounded by time, not size. Every other stream
        // keeps buffering -- not because of its number, but because nobody
        // declared it safe to drop, or declared it explicitly unsafe (a line
        // protocol with no screen model to redraw from).
        if matches!(self.role, Role::Server)
            && matches!(self.state, LinkState::PathDown)
            && since_road_live >= RESYNC_AFTER
        {
            // Collect matching stream numbers first: `is_bulk_output_stream`
            // takes `&self`, which would conflict with the `&mut
            // self.streams` borrow of `iter_mut` below.
            let desyncable: Vec<u8> = self
                .streams
                .keys()
                .copied()
                .filter(|stream_id| self.is_bulk_output_stream(*stream_id))
                .collect();
            for stream_id in desyncable {
                self.discard_stream_output(stream_id);
            }
        }
        // Control before data (spec §4.8): on a slow uplink a PING behind a
        // window of data waits in the queue as long as the data does.
        // Scheduled PING: the period is measured from the LAST PING, not from
        // idle data-send time. This way PING goes out roughly every
        // PING_INTERVAL even under continuous traffic, and RTT keeps updating.
        // A forced request on rebind sends a PING immediately.
        let mut control = Vec::new();
        let ping_due = self.ping_forced || now >= self.next_ping_at();
        if matches!(self.state, LinkState::Live | LinkState::PathDown) && ping_due {
            control.push(self.mint_ping(now));
        }
        // A sender that may be stopped at an older limit hears the newest
        // again, one rto apart (spec §6.4). Service frames: no window holds
        // them back.
        let rto = self.rto();
        let repeats: Vec<StreamFrame> = self
            .streams
            .values_mut()
            .filter_map(|s| s.receiver.credit_resend(now, rto))
            .collect();
        control.extend(repeats);
        // Then the data (spec §4.8): the road checks above are already
        // ahead of it, the PING and the repeats lead it in the same
        // datagrams, and what waits for a ride goes with them (spec §4.11).
        self.flush_after(now, control, &mut out);
        // What nothing carried goes alone once it may wait no longer (spec
        // §4.11): the deadline `next_timeout` reports for it.
        self.flush_service_if_due(now, &mut out);
        out
    }

    /// A PING sent at `now`: its token noted as outstanding, and a forced
    /// request served.
    fn mint_ping(&mut self, now: Instant) -> StreamFrame {
        let token = self.next_ping_token();
        // Minting a PING while an earlier one is still outstanding past
        // both the interval and the retransmit timeout is what "the
        // liveness check went unanswered" means: its answer is overdue.
        // Checked before the push below, which is not evidence of
        // anything yet.
        let overdue_after = self.unanswered_after(now);
        if let Some(&(_, oldest)) = self.outstanding_pings.first() {
            if !self.ping_unanswered && now.saturating_duration_since(oldest) >= overdue_after {
                self.ping_unanswered = true;
                self.ping_unanswered_since = Some(now);
            }
        }
        if self.outstanding_pings.len() == MAX_OUTSTANDING_PINGS {
            self.outstanding_pings.remove(0);
        }
        self.outstanding_pings.push((token, now));
        self.last_ping_sent = Some(now);
        self.ping_forced = self.forced_ping_sticks;
        StreamFrame::Ping { token }
    }

    /// The nearest moment at which `on_timeout` should be called. `None` if
    /// there is nothing to wait for (no transport phase yet, or the connection
    /// is closed).
    pub fn next_timeout(&self) -> Option<Instant> {
        if self.keys.is_none() || matches!(self.state, LinkState::Closed) {
            return None;
        }
        let mut candidates: Vec<Instant> = Vec::new();
        // Retransmits are due per segment (spec §4.2): the oldest
        // unacknowledged segment's last send plus `rto`, on every stream.
        // Sending anything else -- an ACK, a PING -- does not move it.
        let rto = self.rto();
        candidates.extend(
            self.streams
                .values()
                .filter_map(|s| s.sender.retransmit_deadline(rto)),
        );
        // The repeats of a CREDIT (spec §6.4), by the same rto `on_timeout`
        // serves them with.
        candidates.extend(
            self.streams
                .values()
                .filter_map(|s| s.receiver.credit_resend_deadline(rto)),
        );
        // Something to send that has no deadline of its own is due at once
        // while `Live`: new bytes, a lost segment, an armed `Reset` -- after a
        // flush this is left only by the bulk budget (spec §4.8), and the
        // driver takes its commands before it comes back for more. Like the
        // forced PING below, "now" is a stored moment already in the past.
        if matches!(self.state, LinkState::Live) && self.sendable_now() {
            candidates.push(self.last_recv_auth);
        }
        if matches!(self.state, LinkState::Live | LinkState::PathDown) {
            if self.ping_forced {
                // Forced: wake `on_timeout` now (a moment in the past).
                candidates.push(self.last_recv_auth);
            } else {
                // The very moment `on_timeout` judges the PING due by.
                candidates.push(self.next_ping_at());
            }
        }
        if let Some(deadline) = self.death_base().checked_add(self.death_after()) {
            candidates.push(deadline);
        }
        if matches!(self.state, LinkState::Live) {
            candidates.push(self.last_recv_ordinary + PATH_DOWN_AFTER);
        }
        if matches!(self.role, Role::Client) {
            let urgent = self.probes_are_urgent();
            // `next_timeout` takes no `now` of its own (it works purely off
            // stored instants, like the `ping_forced` case just above), so a
            // never-yet-probed path -- whose deadline is "immediately" --
            // gets `last_recv_auth` as its stand-in: always in the past by
            // the time this is called, so it wakes the caller right away.
            if let Some(deadline) = self.paths.next_deadline(self.last_recv_auth, urgent) {
                candidates.push(deadline);
            }
        }
        // Service frames nothing carried go alone `ACK_DELAY` after the
        // first of them was owed (spec §4.11); `on_timeout` serves exactly
        // this deadline (`flush_service_if_due`).
        if let Some(since) = self.service_since {
            candidates.push(since + ACK_DELAY);
        }
        candidates.into_iter().min()
    }

    /// Run [`Connection::on_timeout`] if one of its deadlines has passed, and
    /// return nothing otherwise. The one rule every loop around a
    /// `Connection` applies after EVERY wake-up -- a datagram, a command, a
    /// backend's output, a control message -- not only when its sleep ran
    /// out (spec §4.1): a loop woken more often than its sleep would ever
    /// expire must still PING, retransmit, notice `PathDown` and check its
    /// roads. `on_timeout` compares every action against its own deadline,
    /// so calling it by this rule changes nothing on a quiet link.
    pub fn on_timeout_if_due(&mut self, now: Instant) -> Vec<Datagram> {
        match self.next_timeout() {
            Some(deadline) if deadline <= now => self.on_timeout(now),
            _ => Vec::new(),
        }
    }

    /// The link state as of the last datagram, timer or call.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Take the accumulated events.
    pub fn poll_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// The current peer address, if already known.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Called only after the daemon accepted a server handshake. Repeated
    /// probation setup preserves the original source; it never retargets it.
    #[cfg(feature = "tokio-driver")]
    pub(crate) fn restrict_to_handshake_source(&mut self) {
        self.probation_source
            .get_or_insert(self.peer.expect("probation follows an accepted handshake"));
    }

    /// Only committed bridge adoption restores ordinary server roaming.
    #[cfg(feature = "tokio-driver")]
    pub(crate) fn admit_source_migration(&mut self) {
        self.probation_source = None;
    }

    /// Tell the connection which roads lead to the same peer. Only a client
    /// has these: a server does not know what other addresses reach it.
    ///
    /// De-duplicated before it reaches the table: `PathTable::set_paths`
    /// keeps every address it is given as its own entry, and a repeat would
    /// become a second entry that never gets acked, wasting a check slot for
    /// nothing.
    pub fn set_paths(&mut self, addrs: Vec<SocketAddr>) {
        let mut seen = HashSet::new();
        // A UI candidate snapshot can race with an automatic move. Pin the
        // actual peer here before applying the table's size limit. An empty
        // list remains the explicit request to disable path checking.
        let active = if addrs.is_empty() || !matches!(self.role, Role::Client) {
            None
        } else {
            self.peer
        };
        self.paths.set_paths(
            active
                .into_iter()
                .chain(addrs)
                .filter(|a| seen.insert(*a))
                .collect(),
        );
    }

    /// Where the traffic is going right now.
    pub fn active_path(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Move the traffic to `addr`. The session does not notice: its keys,
    /// streams and delivery state are not bound to an address, and the peer
    /// migrates to the new source itself the moment an ordinary packet
    /// arrives from it.
    pub fn set_peer(&mut self, addr: SocketAddr) {
        self.peer = Some(addr);
    }

    /// Move the traffic onto `addr` because the owner asked to -- the app's "Switch" -- rather
    /// than because the road in use went quiet. Only onto one of the session's roads, and only
    /// one that answered its last check: by hand one cannot go anywhere automatic moving would
    /// not. The road already in use is `Ok` and changes nothing.
    ///
    /// Two things beyond the bare assignment:
    /// - the dwell ([`Connection::may_move`]) starts, as after an automatic move -- pressed
    ///   while the link is `PathDown`, the next tick must not overrule the choice with its own;
    /// - the PINGs sent down the road left are forgotten and a PING is forced for the next
    ///   `on_timeout`: an ordinary packet with a new counter down the new road, which the server
    ///   follows on arrival (`on_transport`), instead of waiting up to `PING_INTERVAL` for the
    ///   scheduled one.
    ///
    /// The liveness clocks are NOT restarted, unlike [`Connection::request_ping`]: the new road
    /// has to prove it carries traffic. One that does not is left by automatic moving as usual:
    /// it goes `PathDown` after `PATH_DOWN_AFTER`, or -- when the server keeps talking over the
    /// road left, so nothing ever goes quiet -- it fails its own check while the PINGs down it
    /// go unanswered, the two overlapping (see [`Connection::on_timeout`]). A road checked as
    /// working may have died
    /// since; this is what keeps choosing one from wedging the session there.
    ///
    /// Nothing is pinned. Automatic moving only ever leaves a road that went quiet or went dead
    /// under its PINGs, so a road chosen here keeps the session for as long as it carries
    /// traffic, however much faster another one is -- one lost check does not count -- and once
    /// it has been left, nothing brings the session back to it.
    pub fn use_road(&mut self, addr: SocketAddr, now: Instant) -> Result<(), UseRoadError> {
        if !matches!(self.role, Role::Client)
            || self.keys.is_none()
            || matches!(self.state, LinkState::Closed)
        {
            return Err(UseRoadError::NoSession);
        }
        if !self.paths.contains(addr) {
            return Err(UseRoadError::UnknownRoad);
        }
        if self.peer == Some(addr) {
            return Ok(());
        }
        if !self.paths.is_verified(addr) {
            return Err(UseRoadError::NotAnswering);
        }
        self.set_peer(addr);
        self.moved_at = Some(now);
        self.force_ping_on_a_new_road();
        Ok(())
    }

    /// Force a PING for the next `on_timeout` after a move onto another road, forgetting the
    /// PINGs sent down the road left -- as [`Connection::request_ping`] does after a rebind.
    /// Their fate says nothing about the new road, and a surviving one would have the forced
    /// PING, or the next scheduled one, read the new road as unanswered on the old road's
    /// account. A late PONG for one of them is ignored by token, and the round trip is
    /// measured afresh from the forced PING.
    ///
    /// The retransmit timer starts afresh on the new road too: its estimate and back-off
    /// describe the road left (a deep queue there would keep the timeout at seconds for data
    /// stranded on it and for losses on the new one), and the send times of what is in flight
    /// would time the old road. Until the forced PING's PONG, or an ACK for something sent
    /// from now on, the timeout falls back to the liveness value of the latest PONG.
    fn force_ping_on_a_new_road(&mut self) {
        self.ping_forced = true;
        self.clear_outstanding_pings();
        self.rtt_estimator = RttEstimator::default();
        self.forget_send_times();
        self.restart_congestion();
    }

    /// Let no ACK for what is in flight time a round trip, and drop the
    /// back-off: the segment twin of [`Connection::clear_outstanding_pings`],
    /// for the same moments -- a freeze of this thread, a rebind, a move --
    /// after which the time since those segments went out measures the gap,
    /// or the old road, not the road ahead.
    fn forget_send_times(&mut self) {
        for st in self.streams.values_mut() {
            st.sender.forget_send_times();
        }
        self.rto_backoff = 0;
    }

    /// A new road, or the same one after a gap: the congestion window starts
    /// afresh (spec §4.15), and what is in flight is taken for lost so it goes
    /// out again under the fresh window. Left in flight it would be overdue
    /// at the next flush and read as a retransmit timeout -- one segment of
    /// window, a threshold from before the gap, a back-off -- undoing the
    /// restart. A genuine timeout of the resent data reacts as usual.
    fn restart_congestion(&mut self) {
        self.cc.restart();
        for st in self.streams.values_mut() {
            st.sender.take_in_flight_for_lost();
        }
    }

    /// Forget every outstanding PING and the unanswered mark with them.
    fn clear_outstanding_pings(&mut self) {
        self.outstanding_pings.clear();
        self.ping_unanswered = false;
        self.ping_unanswered_since = None;
    }

    /// A check came back carrying `token`. Production code reaches this
    /// through the `PathProbeAck` frame; it is public so a test can verify a
    /// road without hand-assembling an authenticated packet. No address
    /// parameter: the token alone identifies which road was checked (see
    /// [`PathTable::on_ack`]).
    pub fn on_path_probe_ack(&mut self, token: u32, now: Instant) {
        self.paths.on_ack(token, now);
    }

    /// The session ID negotiated during the handshake. `0` before the
    /// handshake completes.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// The authenticated remote static key, if recorded (server-side, set by
    /// `accept`).
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.peer_static
    }

    /// The Noise handshake hash of the current handshake -- what the client
    /// signs and the server verifies (see `crate::auth`).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }

    /// Whether the connection reached `Closed` because a `StreamFrame::Close`
    /// was received (a graceful, intentional shutdown) rather than through the
    /// `DEATH_AFTER` liveness timeout. Meaningful only once the state is
    /// `Closed`; `false` before then and after a death-timeout close.
    pub fn closed_gracefully(&self) -> bool {
        self.closed_gracefully
    }

    /// How long since the last authenticated incoming packet. The session
    /// manager treats a connection as "active" (someone is really using it)
    /// when this is within `ACTIVE_WINDOW`: a live client PINGs every
    /// `PING_INTERVAL` (1.5 s), a backgrounded/roaming one is silent for far
    /// longer.
    pub fn idle_duration(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_recv_auth)
    }

    /// How far `stream_id` has got. All zero for a stream never written.
    pub fn stream_progress(&self, stream_id: u8) -> StreamProgress {
        self.streams
            .get(&stream_id)
            .map_or(StreamProgress::default(), |s| StreamProgress {
                queued: s.sender.queued_total(),
                unacked: s.sender.unacked_len() as u64,
            })
    }

    /// Gracefully close the connection: emit a `Close` frame to the peer and
    /// move to `Closed` locally. The client calls this on an intentional
    /// shutdown so the server tears the backend down at once instead of
    /// retaining it for a warm reconnect. A no-op without transport keys or
    /// once already `Closed`. `_now` keeps the sans-IO shape every entry
    /// point shares; closing needs no clock since sends stopped being timed.
    pub fn close(&mut self, _now: Instant) -> Vec<Datagram> {
        let mut out = Vec::new();
        if self.keys.is_none() || matches!(self.state, LinkState::Closed) {
            return out;
        }
        self.emit_frames(vec![StreamFrame::Close { stream_id: 0 }], &mut out);
        self.closed_gracefully = true;
        self.set_state(LinkState::Closed);
        out
    }

    /// Best-effort authenticated terminal failure. The fixed service frame
    /// bypasses reliable-stream credit; legacy peers receive ordinary Close.
    /// Neither packet emission nor local Closed proves peer delivery or cleanup.
    pub fn abort_session(
        &mut self,
        now: Instant,
        reason: crate::SessionAbortReason,
    ) -> Vec<Datagram> {
        if self.keys.is_none() || self.state == LinkState::Closed {
            return Vec::new();
        }
        self.session_abort = Some(reason);
        if !self.features.contains(Features::RESOURCE_LIMITS) {
            return self.close(now);
        }
        let mut out = Vec::new();
        self.emit_frames(vec![StreamFrame::SessionAbort { reason }], &mut out);
        self.closed_gracefully = true;
        self.set_state(LinkState::Closed);
        out
    }

    /// The authenticated terminal reason for this transport, when known.
    /// Legacy Close and liveness loss carry no reason.
    pub fn session_abort_reason(&self) -> Option<crate::SessionAbortReason> {
        self.session_abort
    }

    /// Drop the connection on the spot WITHOUT telling the peer: no `Close`
    /// frame, and `closed_gracefully` stays false, so the daemon retains the
    /// session (its processes live on) for a warm return -- the app's own
    /// reconnect, or the console `qsh`'s. The peer learns of it
    /// only by silence, through its death timer. What a stream out of offset
    /// space asks for (see [`Event::OffsetSpaceExhausted`]).
    pub fn abandon(&mut self) {
        self.set_state(LinkState::Closed);
    }

    /// Request an immediate PING on the next `on_timeout`, and restart the
    /// liveness window. Called on a rebind (network change) and on a
    /// Doze/freeze resume: we ping right away from the new local address (this
    /// measures fresh RTT and forces the server to migrate to the new source),
    /// and restart BOTH liveness clocks at `now` so the freeze gap is NOT
    /// counted as silence. The forced PING then gets one full death window to
    /// hear back from a still-alive peer; only genuine active silence closes
    /// the link.
    ///
    /// Both clocks, not just `last_recv_auth`: `PATH_DOWN_AFTER` reads
    /// `last_recv_ordinary`, so leaving that one stale would trip `PathDown`
    /// on the very next tick after every Doze wake and every rebind, and the
    /// app would paint "connection temporarily lost" for a round trip over a
    /// link that was never down.
    pub fn request_ping(&mut self, now: Instant) {
        self.ping_forced = true;
        self.last_recv_auth = now;
        self.last_recv_ordinary = now;
        // The previous check went unanswered because this thread was frozen,
        // not because the road is bad -- the same reason both clocks reset
        // here. Leaving it set costs the spare roads an urgent round for
        // nothing.
        //
        // The checks in flight are dropped along with the mark, and for the
        // same reason: `on_timeout` -- which the driver reaches in the very
        // next breath on both paths that call this -- sets the mark again
        // whenever it mints a PING while an overdue one is still outstanding,
        // so a surviving one would put back microseconds later exactly what
        // was just cleared. A late PONG for one is then ignored by token, and
        // the round trip is measured afresh from the forced PING, which is
        // what one wants after a freeze anyway: the old measurement spans the
        // gap.
        self.clear_outstanding_pings();
        // The same for the data in flight: an ACK that waited through the
        // freeze in the socket (the driver reads it right after this call)
        // would otherwise time the segment it covers from before the freeze
        // -- one sample the length of the freeze, the retransmit timeout at
        // its 15 s ceiling for a minute and more. The estimate itself is
        // kept: after a freeze, and usually after a rebind, it is the same
        // road; a move proper starts it afresh (`force_ping_on_a_new_road`).
        self.forget_send_times();
        self.restart_congestion();
    }

    /// The instant the death timer counts from, which is a different
    /// question for each role because the timer answers a different question
    /// for each.
    ///
    /// A SERVER asks "is this client alive anywhere?", and the answer this
    /// transport gives is that a client plainly alive on some road must never have its
    /// session killed -- so it counts from `last_recv_auth`, which any
    /// authenticated packet advances, a spare road's check answer included.
    ///
    /// A CLIENT asks "when do I give up so my owner can start over?", and
    /// answered checks do not make a session useful. A client whose road
    /// answers checks but carries no ordinary traffic would, on
    /// `last_recv_auth`, never reach `Closed` -- and the app's full
    /// reconnect, which keys on `Closed`, would never fire; before this
    /// branch such a client died in `CLIENT_DEATH_AFTER`. So it counts from
    /// `last_recv_ordinary`. With a verified spare the client moves long
    /// before this fires, which leaves it firing only when nothing works,
    /// which is exactly when it should.
    fn death_base(&self) -> Instant {
        match self.role {
            Role::Server => self.last_recv_auth,
            Role::Client => self.last_recv_ordinary,
        }
    }

    /// The liveness death timeout for this connection's role
    /// ([`CLIENT_DEATH_AFTER`] vs [`SERVER_DEATH_AFTER`]), unless the owner
    /// set its own with [`Self::set_death_after`].
    fn death_after(&self) -> Duration {
        self.death_after_override.unwrap_or(match self.role {
            Role::Server => SERVER_DEATH_AFTER,
            Role::Client => CLIENT_DEATH_AFTER,
        })
    }

    /// Override how long this connection tolerates silence before declaring
    /// the link dead. For a client this is a product decision, not a
    /// transport one. The console client keeps the default and treats a dead
    /// link as the cue to retry its address ladder in the background. A client that would
    /// rather wait out a long outage on the same connection can set it long.
    /// If its deadline is outside `Instant`'s representable range, no death
    /// wake-up is scheduled; the connection's other timers still run.
    pub fn set_death_after(&mut self, after: Duration) {
        self.death_after_override = Some(after);
    }

    /// Whether the spare roads should be checked on the urgent schedule
    /// rather than the idle one. Three reasons, and only three: the road in
    /// use is already known to be down, a liveness PING on it went unanswered
    /// (see `ping_unanswered`), or the road in use failed its own last check.
    /// The point of hurrying is to have a spare road verified BEFORE the live
    /// one is needed, so the trigger has to be the live road looking doubtful
    /// -- not a PING merely being in flight, which is the ordinary state of a
    /// healthy link for one round trip out of every interval.
    ///
    /// The third reason also heals a single lost check fast: checks are not
    /// retransmitted and a road goes `Dead` after one unanswered, so on the
    /// idle schedule one lost datagram would leave the road in use reading
    /// `Dead` for half a minute. Urgency re-checks it within `PROBE_URGENT`.
    ///
    /// Lives in one place because `on_timeout` and `next_timeout` must agree
    /// on it exactly: the second decides when the first is called, so two
    /// copies that drifted apart would schedule a wake for one rule and act
    /// on another.
    fn probes_are_urgent(&self) -> bool {
        matches!(self.state, LinkState::PathDown)
            || self.ping_unanswered
            || self.peer.is_some_and(|p| self.paths.is_dead(p))
    }

    /// Whether enough time has passed since the last move to consider
    /// another one. A move has to be given time to prove itself: `PathDown`
    /// clears only when an ordinary frame arrives, and none can arrive
    /// before a round trip on the road just moved to. Without a dwell the
    /// next tick -- 50 ms later, in the driver -- would find the connection
    /// still `PathDown`, ask for the best road OTHER than the new one, and
    /// be handed the one just left, still `Verified` because its own check
    /// has not timed out yet. The client would flap between the two instead
    /// of settling.
    fn may_move(&self, now: Instant) -> bool {
        match self.moved_at {
            None => true,
            Some(when) => now.saturating_duration_since(when) >= self.move_dwell(),
        }
    }

    /// Twice the destination's round-trip allowance, using its probe EWMA
    /// rather than a PONG from the road just left. Keep the existing liveness
    /// bounds and urgent-probe floor. Moves require a verified destination,
    /// so it normally has a measurement; if its path metadata was removed,
    /// give it the full unmeasured liveness allowance, not the old road's RTT.
    fn move_dwell(&self) -> Duration {
        let allowance = self
            .peer
            .and_then(|addr| self.paths.rtt(addr))
            .map_or(RTO_CEILING, |rtt| (rtt * 2).clamp(RTO_FLOOR, RTO_CEILING));
        (allowance * 2).max(PROBE_URGENT)
    }

    /// When the next scheduled PING is due. The one definition both
    /// `next_timeout` and `on_timeout` use: any disagreement between them
    /// leaves a deadline `on_timeout` refuses, and every loop around the
    /// connection wakes on it at once, over and over (spec §4.1).
    ///
    /// The period is measured from the LAST PING, not from idle data-send
    /// time, so a PING goes out roughly every `PING_INTERVAL` even under
    /// continuous traffic. Which period applies is decided once, at the
    /// lively deadline, never at whatever moment the caller woke: a wake-up
    /// that lands a little late, past `PING_BACKOFF_AFTER`, must still find
    /// the lively deadline due, or it would stay in the past until the slow
    /// one.
    fn next_ping_at(&self) -> Instant {
        let base = self.last_ping_sent.unwrap_or(self.handshake_at);
        base + self.ping_interval(base + PING_INTERVAL)
    }

    /// How often to PING right now: the lively rate, or the backed-off one
    /// once the path has been down long enough that nobody is listening.
    fn ping_interval(&self, now: Instant) -> Duration {
        if matches!(self.state, LinkState::PathDown)
            && now.saturating_duration_since(self.last_recv_auth) >= PING_BACKOFF_AFTER
        {
            PING_INTERVAL_DOWN
        } else {
            PING_INTERVAL
        }
    }

    /// Summary statistics.
    pub fn stats(&self, now: Instant) -> Stats {
        Stats {
            rehomes: self.rehomes,
            rtt_ms: self.rtt.map_or(0, |s| display_ms(s.value)),
            retransmits: self.retransmits,
            silent_secs: now
                .saturating_duration_since(self.last_recv_ordinary)
                .as_secs()
                .min(u64::from(u32::MAX)) as u32,
        }
    }

    /// The roads this connection knows, as of `now`. Empty on a server and on
    /// a client that was never given any -- there is nothing to look at.
    ///
    /// The road IN USE reports the round trip this connection measured
    /// itself, not the one the path table smoothed out of its checks. Both
    /// measure the same trip down the same road, but the connection's is a
    /// PING every `PING_INTERVAL` (1.5 s) while the table's is a check every
    /// `PROBE_IDLE` (30 s) put through an EWMA, so the table's number sits
    /// still for half a minute at a time and then moves by a fifth of the
    /// difference. Two numbers for one road, and the fresher one is also the
    /// one already on screen: `Stats::rtt_ms` is what the header shows, and
    /// a window that disagreed with the header about the road the traffic is
    /// going down would be reporting on a different connection than the one
    /// in front of the person reading it.
    ///
    /// Only the view is affected. Ranking still runs on the table's own
    /// measurement (`PathTable::score`), which is the only one every road
    /// has: a spare road has no PING of its own to be compared by.
    pub fn roads(&self, now: Instant) -> Vec<RoadInfo> {
        let mut view = self.paths.view(now);
        // Nothing measured yet: leave the road with whatever the table knows.
        if let (Some(sample), Some(peer)) = (self.rtt, self.peer) {
            let ms = display_ms(sample.value);
            for road in view.iter_mut().filter(|road| road.addr == peer) {
                road.ewma_ms = Some(ms);
            }
        }
        view
    }

    /// Actual path-probe send times, using the transport's monotonic clock.
    pub fn path_probes(&self) -> Vec<(SocketAddr, Instant)> {
        self.paths.probe_times()
    }

    /// Whether the server said this handshake landed on the session this
    /// client asked for by token, rather than a fresh one. Meaningful on a
    /// client, once the link is `Live`; always false on a server.
    ///
    /// A client cannot work this out for itself: an unknown token is answered
    /// with a new session and no complaint, which is the right behavior but
    /// looks exactly like a resume from the outside.
    pub fn resumed(&self) -> bool {
        self.resumed
    }

    /// The nonce the server issued for this handshake, or `None` from a
    /// server too old to send one. Meaningful on a client once the link is
    /// `Live`; always `None` on a server, which keeps its own copy in
    /// [`AcceptOutcome::Accepted`] instead.
    pub fn server_nonce(&self) -> Option<[u8; AUTH_NONCE_LEN]> {
        self.server_nonce
    }

    /// The features this connection uses (spec §5.2); `NONE` before the
    /// handshake, and with a peer built before negotiation.
    pub fn features(&self) -> Features {
        self.features
    }

    /// The driver's msg1 retransmit: what [`Connection::handshake_datagrams`]
    /// says goes out now, counted as a retransmit -- the handshake then
    /// seeds no round trip (Karn). Once a cookie was taken, each call also
    /// hands the next one the other form, plain or behind the cookie (spec
    /// §4.16, `plain_turn`). Empty unless a client handshake is under way.
    pub fn retransmit_handshake(&mut self) -> Vec<Datagram> {
        let out = self.handshake_datagrams();
        if out.is_empty() {
            return out;
        }
        self.handshake_retransmitted = true;
        if self.cookie.is_some() {
            self.plain_turn = !self.plain_turn;
        }
        out
    }

    /// The msg1 datagram the next retransmit sends (spec §4.16): the one
    /// the handshake started with, byte for byte, or the same Noise msg1
    /// behind the newest cookie the server handed out for it -- once a
    /// cookie was taken the two take turns, beginning behind the cookie.
    /// Empty unless a client handshake is under way.
    pub fn handshake_datagrams(&self) -> Vec<Datagram> {
        let cookie = if self.plain_turn { None } else { self.cookie };
        self.msg1_datagrams(cookie.as_ref())
    }

    /// This handshake's msg1, plain or behind `cookie`; empty unless a
    /// client handshake is under way.
    fn msg1_datagrams(&self, cookie: Option<&[u8; COOKIE_LEN]>) -> Vec<Datagram> {
        if !matches!(self.role, Role::Client)
            || self.state != LinkState::Connecting
            || self.handshake.is_none()
        {
            return Vec::new();
        }
        let (Some(peer), Some(msg1)) = (self.peer, self.msg1_body.as_ref()) else {
            return Vec::new();
        };
        let bytes = match cookie {
            Some(cookie) => encode_handshake_init_cookie(cookie, msg1),
            None => encode_handshake(Kind::HandshakeInit, msg1),
        };
        vec![Datagram { to: peer, bytes }]
    }

    /// The current round-trip measurement, if there is one.
    pub fn rtt(&self) -> Option<RttSample> {
        self.rtt
    }

    // --- Internal: handshake ---

    fn on_handshake_init(&mut self, now: Instant, src: SocketAddr, body: &[u8]) -> Vec<Datagram> {
        let mut out = Vec::new();
        if !matches!(self.role, Role::Server) || !matches!(self.state, LinkState::Connecting) {
            return out;
        }
        // THIS ENTRY POINT HAS NO AUTHENTICATION GATE. It goes straight to
        // `Live` once the Noise message reads, and there is nothing here that
        // could wait for a proof arriving afterwards -- that is the probation
        // stage, which only `Connection::accept` plus the session manager
        // provide. Under `AuthPolicy::SshSignature` the `admits` check below
        // passes for ANY key (the key is deliberately not the proof), so
        // running the signature policy through here would mean "admit
        // everyone". `accept` also checks msg1's announced method against the
        // policy.
        //
        // So refuse rather than half-enforce: one policy value must not mean
        // "guarded by probation" at one entry point and "open to all" at
        // another. Unreachable today (`SessionManager` uses `accept`, and
        // every caller that reaches here runs `Allowlist`), which is exactly
        // why it is worth pinning -- a refactor that routed a signature
        // server through `on_datagram` would otherwise be an authentication
        // bypass with no symptom.
        if matches!(self.auth, AuthPolicy::SshSignature) {
            self.set_state(LinkState::Closed);
            return out;
        }
        // Read msg1. A malformed message from the network doesn't crash the server.
        let payload = {
            let hs = match self.handshake.as_mut() {
                Some(h) => h,
                None => return out,
            };
            match hs.read_msg(body) {
                Ok(p) => p,
                Err(_) => return out,
            }
        };
        // Check the client's static key from msg1 against the auth policy.
        let remote = self.handshake.as_ref().and_then(Handshake::remote_static);
        let allowed = remote.is_some_and(|k| self.auth.admits(&k));
        if !allowed {
            self.set_state(LinkState::Closed);
            return out;
        }
        // This path does not refuse a payload it cannot read (a client may
        // send none at all, like `Connection::start`): such a msg1 offers
        // nothing.
        let offered = offered_in(&payload);
        let features = if self.legacy_peer {
            Features::NONE
        } else {
            Features::negotiate(offered, self.allowed_features)
        };
        if !features.contains(self.required_features) {
            self.handshake = None;
            self.set_state(LinkState::Closed);
            return out;
        }
        // Random session id in the authenticated, versioned msg2 payload.
        let session_id: u64 = rand::thread_rng().gen();
        self.session_id = session_id;
        // Fresh per handshake, and never reused: it is what stops a proof
        // made for one handshake from being presented for another.
        //
        // Minted HERE, directly, bypassing `NonceSource` entirely -- unlike
        // `Connection::accept`, which asks a `resolve` hook for one. That is
        // safe ONLY because this entry point refuses `AuthPolicy::SshSignature`
        // outright (see the guard above): a signature server's nonces must
        // come from the helper (`NonceSource`), and the only production path
        // that runs `SshSignature` (`SessionManager::serve`) never calls this
        // method, only `accept`. A refactor that routed a signature server
        // through `on_datagram` would silently sidestep the helper here.
        let nonce: [u8; AUTH_NONCE_LEN] = rand::thread_rng().gen();
        let msg2_payload = if self.legacy_peer {
            encode_msg2_without_tail(session_id, false, &nonce)
        } else {
            encode_msg2(session_id, false, &nonce, features)
        };
        let msg2 = self
            .handshake
            .as_mut()
            .expect("handshake not yet taken")
            // This entry point has no session table behind it (the manager's
            // router is what resumes), so it can only ever be a fresh one.
            .write_msg(&msg2_payload);
        let hs = self.handshake.take().expect("handshake still present");
        self.handshake_hash = hs.handshake_hash();
        // The server switches as it writes msg2 (spec §5.4).
        self.keys = Some(hs.into_transport(features.contains(Features::HEADER_AAD)));
        self.apply_features(features);
        self.peer = Some(src);
        self.last_recv_auth = now;
        self.handshake_at = now;
        // See the matching comment in `accept`.
        self.last_recv_ordinary = now;
        self.events.push(Event::HandshakeDone);
        out.push(Datagram {
            to: src,
            bytes: encode_handshake(Kind::HandshakeResp, &msg2),
        });
        self.set_state(LinkState::Live);
        // Flush anything queued on the stream before the transition to Live.
        self.flush_senders(now, &mut out);
        out
    }

    fn on_handshake_resp(&mut self, now: Instant, src: SocketAddr, body: &[u8]) -> Vec<Datagram> {
        let mut out = Vec::new();
        // Reject an ineligible source before reading Noise: even a valid msg2
        // consumes the only initiator and can release queued proof/data.
        if !matches!(self.role, Role::Client)
            || !matches!(self.state, LinkState::Connecting)
            || !self
                .recovery_handshake
                .as_ref()
                .map_or(self.peer == Some(src), |schedule| schedule.can_select(src))
        {
            return out;
        }
        let payload = {
            let hs = match self.handshake.as_mut() {
                Some(h) => h,
                None => return out,
            };
            match hs.read_msg(body) {
                Ok(p) => p,
                Err(_) => return out,
            }
        };
        // A successful Noise read consumes this initiator even if the
        // authenticated payload is invalid. Retain that exact source for
        // endpoint accounting; peer/keys/proof still wait for validation.
        if let Some(schedule) = &mut self.recovery_handshake {
            if !schedule.select(src) {
                self.handshake = None;
                self.set_state(LinkState::Closed);
                return out;
            }
        }
        let msg2 = match parse_msg2(&payload) {
            Ok(m) => m,
            Err(reason) => {
                // Authentication succeeded and consumed the initiator turn.
                // A fresh attempt is required; retransmission cannot repair it.
                self.handshake = None;
                self.events.push(Event::InvalidHandshakeResponse { reason });
                self.set_state(LinkState::Closed);
                return out;
            }
        };
        // Spec §5.2: a bit msg1 did not offer is a violation. Reading msg2
        // spent the handshake, so no later copy could be read either: say so
        // once, and close.
        if !self.offered_features.contains(msg2.enabled) {
            self.handshake = None;
            self.events.push(Event::UnofferedFeatureEnabled {
                enabled: msg2.enabled,
            });
            self.set_state(LinkState::Closed);
            return out;
        }
        // Shared recovery has no trustworthy completion boundary without the
        // explicit admission record. Keep this attempt-local: a later ordinary
        // transport-only start still uses the caller's configured minimum.
        let required = if self.recovery_handshake.is_some() {
            self.required_features | Features::AUTH_ACCEPTED
        } else {
            self.required_features
        };
        if !msg2.enabled.contains(required) {
            self.handshake = None;
            self.events.push(Event::MissingRequiredFeatures {
                required,
                enabled: msg2.enabled,
            });
            self.set_state(LinkState::Closed);
            return out;
        }
        if let Some(schedule) = &self.recovery_handshake {
            self.msg1_sent_at = schedule.first_checked(src);
            self.handshake_retransmitted = schedule.retransmitted(src);
            let paths = schedule.addresses().collect();
            self.peer = Some(src);
            // set_paths pins the selected source before its table limit. This
            // must precede flush_senders and every proof-producing callback.
            self.set_paths(paths);
        }
        self.session_id = msg2.session_id;
        self.resumed = msg2.resumed;
        self.server_nonce = msg2.nonce;
        let hs = self.handshake.take().expect("handshake still present");
        self.handshake_hash = hs.handshake_hash();
        // The client switches as it reads msg2 (spec §5.4).
        self.keys = Some(hs.into_transport(msg2.enabled.contains(Features::HEADER_AAD)));
        self.apply_features(msg2.enabled);
        // The handshake's own round trip seeds the measurement (spec §4.3):
        // without it the session lives with the 500 ms default until the
        // first PONG, at least 1.5 s away. It includes the server's work on
        // msg1, but crossed an empty queue: under a bulk write it is an
        // underestimate, so `rto` never lets it lower the timeout below
        // `DEFAULT_RTO`.
        if let (Some(sent), false) = (self.msg1_sent_at, self.handshake_retransmitted) {
            self.rtt = Some(RttSample {
                value: now.saturating_duration_since(sent),
                source: RttSource::Handshake,
            });
        }
        self.last_recv_auth = now;
        self.handshake_at = now;
        // See the matching comment in `accept`.
        self.last_recv_ordinary = now;
        self.events.push(Event::HandshakeDone);
        self.set_state(LinkState::Live);
        self.flush_senders(now, &mut out);
        out
    }

    /// A server under load asked for proof of our return address (spec
    /// §4.16). Taken only while this client's handshake is under way, from
    /// the address its msg1 went to, and only if the echo is the start of
    /// ITS msg1's ephemeral key -- which nobody off the path has seen, so a
    /// stranger cannot make this client send a retry an old daemon would
    /// drop. A party ON the path can (it saw msg1): that is why the
    /// retransmits then take turns with the plain msg1
    /// ([`Connection::retransmit_handshake`]). A client playing an old build
    /// does not know the kind at all.
    fn on_cookie_reply(&mut self, now: Instant, src: SocketAddr, body: &[u8]) -> Vec<Datagram> {
        if self.legacy_peer || !matches!(self.role, Role::Client) {
            return Vec::new();
        }
        let Some((echo, cookie)) = parse_cookie_reply(body) else {
            return Vec::new();
        };
        let answers_this_msg1 = self
            .msg1_body
            .as_ref()
            .is_some_and(|msg1| msg1.get(..COOKIE_ECHO_LEN) == Some(&echo[..]));
        if !answers_this_msg1 {
            return Vec::new();
        }
        if let Some(schedule) = &mut self.recovery_handshake {
            if schedule.on_cookie(now, src, cookie) {
                return self.poll_recovery_handshake(now);
            }
            return Vec::new();
        }
        if self.state != LinkState::Connecting || self.handshake.is_none() || self.peer != Some(src)
        {
            return Vec::new();
        }
        let first = self.cookie.is_none();
        self.cookie = Some(cookie);
        // Karn: two different msg1 datagrams are out now, and msg2 may
        // answer either.
        self.handshake_retransmitted = true;
        // The first cookie goes out at once, and the next retransmit carries
        // it again (the copy sent now may be only moments older than that
        // retransmit); the plain msg1 takes its turn after. A later cookie
        // waits for its turn and changes nothing else: a cookie that keeps
        // failing (a NAT changing the port on every packet) then costs a
        // datagram per `HANDSHAKE_RETRANSMIT`, not one per round trip, and
        // nobody who can hand out cookies can stop the plain turns.
        if first {
            self.plain_turn = false;
            self.msg1_datagrams(Some(&cookie))
        } else {
            Vec::new()
        }
    }

    // --- Internal: transport phase ---

    fn on_transport(
        &mut self,
        now: Instant,
        src: SocketAddr,
        session_id: u64,
        counter: u64,
        aad: &[u8; TRANSPORT_HEADER_LEN],
        aead: &[u8],
    ) -> Vec<Datagram> {
        let mut out = Vec::new();
        // Reject the whole other-source packet before AEAD, replay/liveness,
        // key confirmation or frame routing (including direct probe answers).
        // A source change before admission requires a fresh handshake there.
        if self.probation_source.is_some_and(|source| source != src) {
            return out;
        }
        if self.keys.is_none() || session_id != self.session_id {
            return out;
        }
        // Authenticate first: only an authenticated packet is allowed to
        // advance the anti-replay window, let alone migrate us to a new
        // address.
        let plaintext = match self.keys.as_ref().unwrap().decrypt(counter, aad, aead) {
            Ok(p) => p,
            Err(_) => return out, // forged or corrupted -- silently ignore
        };
        // Capture "this counter would become the window's new max" BEFORE
        // `accept`: accept mutates the window. The migration condition is
        // specifically a new max, not just any fresh-in-window packet.
        let advances = self.replay.is_new_max(counter);
        if !self.replay.accept(counter) {
            return out; // authenticated replay -- drop it
        }
        if matches!(self.role, Role::Server) && !self.peer_key_confirmed {
            self.peer_key_confirmed = true;
            self.events.push(Event::PeerKeyConfirmed { peer: src });
        }
        self.last_recv_auth = now;
        // Decoded before the migration decision, not after it: whether this
        // packet may move the session depends on WHAT is in it. A packet
        // carrying nothing but path checks is the one exception to "an
        // authenticated packet from a new address means the peer moved" --
        // otherwise checking a backup road would drag the live traffic onto
        // it. QUIC draws the same line between probing and non-probing
        // frames.
        //
        // Our own sender never packs a check with anything else (spec
        // §4.11), so in practice this is "the packet is a probe"; the rule
        // is written against the frames, not against that habit.
        let frames = StreamFrame::decode_all(&plaintext);
        let probing_only = !frames.is_empty() && frames.iter().all(StreamFrame::is_probe);
        // An ordinary frame is only ever sent to the road currently in use,
        // so one of them arriving back is proof THAT road works, whatever
        // address it happened to be sourced from -- a check's answer proves
        // only that the road it was sent down still works, not the road in
        // use. See `last_recv_ordinary`'s own doc for the rest of the story
        // (why the death timer above stays on `last_recv_auth` instead).
        if !probing_only {
            self.last_recv_ordinary = now;
        }
        // Migration: an authenticated packet with a NEW max counter arrived
        // from a new address -- the peer changed networks. Migrate to it; all
        // further traffic (including the responses below, and the PathDown
        // resync flush right after this) is addressed there from now on. A
        // late packet from the old (dead) address is fresh-in-window but
        // doesn't advance the max -- it still delivers data/ACK, but it won't
        // roll the peer back. This runs BEFORE the PathDown/resync block
        // below: a long absence (RESYNC_AFTER territory) is exactly when a
        // phone is likely to have roamed while asleep, and the resync's
        // "flush promptly" Reset must go to the new address, not the stale
        // pre-absence one.
        //
        // Server role only: following the peer's source address is the
        // SERVER's behavior. A client roams deliberately, through the path
        // table and `set_peer` -- if it also followed an ordinary packet's
        // source the way a server does, receiving one over a road it moved
        // away from would undo the move it just made on purpose.
        if advances && !probing_only && matches!(self.role, Role::Server) && self.peer != Some(src)
        {
            self.peer = Some(src);
            self.rehomes += 1;
            self.events.push(Event::Rehomed { peer: src });
            // A move starts afresh (spec §4.15) on this side as on the
            // client's (`force_ping_on_a_new_road`, `request_ping`): the
            // window, its threshold and the base delay describe the road
            // left, and the send times of what is in flight would time it.
            // Kept, the old base outlived the move -- onto a faster road the
            // answers to this side's resends came sooner than it, and genuine
            // timeouts were undone until a PONG lowered it (final review of
            // slice 2). The retransmit estimate stays: the first ACKs on the
            // new road correct it, and measured, starting it afresh here
            // gained nothing.
            //
            // A new port on the same address restarts too (round 3 of the
            // fix wave, the controller's ruling). Seen from here, the usual
            // port change is the client's own new socket -- a network
            // callback, a Doze wake -- which closes the old one: what this
            // side sent to the old port before following is lost in one
            // burst, which NewReno without selective acknowledgements repairs
            // a segment per round trip, and the restart's resend of the
            // flight at once (30 ms each way at 1 MB/s, 4 MiB: 6.1 s with the
            // window kept, 4.7 s restarted, 4.5 s with no rebinding). A NAT
            // that remaps in the middle of output while the old mapping still
            // delivers is rare, and pays one slow start (0.2-0.7 s in the
            // simulator); an idle NAT expiry has nothing in flight.
            self.forget_send_times();
            self.restart_congestion();
        }
        // A packet with nothing but checks in it must not declare the road
        // in use healthy again -- that is exactly the client behavior that
        // let a dead live road hide behind a spare's answers (see
        // `last_recv_ordinary`).
        let came_back = matches!(self.state, LinkState::PathDown) && !probing_only;
        if came_back {
            self.set_state(LinkState::Live);
            // The timer backed off while nothing came back: that was the road
            // being down, not a queue it was overfilling, and it is up again.
            // The backlog replays at the timeout the road last measured,
            // not one doubled for every expiry during the outage.
            self.rto_backoff = 0;
            // If we dropped output during the absence, resync on return: arm
            // a reliable Reset on every bulk-output stream that desynced
            // (see [`Connection::is_bulk_output_stream`]) and tell the
            // backend to repaint -- once, regardless of how many streams
            // resynced: `SessionInbound::Repaint` already asks every open
            // channel's screen model to repaint, not a specific one.
            if matches!(self.role, Role::Server) {
                // Collect matching stream numbers first, for the same
                // borrowing reason as the `on_timeout` desync-arming block.
                let to_resync: Vec<u8> = self
                    .streams
                    .keys()
                    .copied()
                    .filter(|stream_id| self.is_bulk_output_stream(*stream_id))
                    .collect();
                let mut resync = false;
                for stream_id in to_resync {
                    let st = self.stream_mut(stream_id);
                    if st.sender.is_desynced() {
                        st.sender.begin_resync();
                        resync = true;
                    }
                }
                if resync {
                    self.events.push(Event::OutputResync);
                }
            }
        }

        let routed = self.route_stream_frames(frames, now);
        // One answer per datagram, not per frame (ruling R16, spec §4.11):
        // one PONG for its last PING with at most one CREDIT copy (ruling
        // R15), and one ACK and one CREDIT per stream, packed for the live
        // road into the PONG, the flush below or, failing both, datagrams
        // of their own; one PathProbeAck, alone, for the datagram's source.
        if let Some(token) = routed.pong {
            // At once (spec §4.11): a PONG times a round trip. What waits for
            // a ride goes in it.
            let mut pong = vec![StreamFrame::Pong { token }];
            let rto = self.rto();
            pong.extend(self.pong_credit(now, rto));
            self.emit_frames(pong, &mut out);
        }
        if let Some(token) = routed.probe_ack {
            self.emit_frames_to(src, vec![StreamFrame::PathProbeAck { token }], &mut out);
        }
        // Flush now, not at the next timer, in two cases. ACK clocking (spec
        // §4.2): an acknowledgement that opened room in a window refills it.
        // And a return from `PathDown`: `send` queues without sending outside
        // `Live`, so whatever was written while the road was down -- a
        // keystroke, output, the resync's `Reset` -- goes out on this packet,
        // after its ACKs are in, and to `self.peer`, which by now reflects
        // any migration above. Not after a `Close` in the same packet. Only
        // `Live` is checked: any packet that carries an ACK is not
        // probing-only, so it has already moved `PathDown` to `Live` above.
        // The ACKs this packet owes ride the PONG above or this flush. A
        // PING forced meanwhile -- a base probe's queue just emptied (see
        // `take_round_trip`) -- leads it (spec §4.8): behind the data it
        // would time their time on the line too.
        if (routed.window_opened || came_back) && matches!(self.state, LinkState::Live) {
            let lead = if self.ping_forced {
                vec![self.mint_ping(now)]
            } else {
                Vec::new()
            };
            self.flush_after(now, lead, &mut out);
        }
        // What nothing carried goes alone once it may wait no longer (spec
        // §4.11): at once if urgent, else at its `ACK_DELAY` deadline, which
        // `next_timeout` reports and `on_timeout` serves.
        self.flush_service_if_due(now, &mut out);
        out
    }

    /// Dispatch already-decoded stream frames. The ACKs and CREDITs they
    /// draw are queued in `acks_due`/`credits_due`, one per stream; returns
    /// the rest of the datagram's answer -- the last PING's token, the last
    /// `PathProbe`'s token -- and whether a sender's window opened (see
    /// [`RoutedFrames`]). `now` is when a receiver's CREDIT goes out, and
    /// what the `PathProbeAck` arm feeds back into the path table through
    /// [`Connection::on_path_probe_ack`] -- the one way into the table,
    /// shared with the test-facing public method, so the wire path and a
    /// hand-driven test cannot drift apart. No `src` parameter: an answer is
    /// attributed by its token, not by the address it arrived from (see
    /// [`PathTable::on_ack`]).
    fn route_stream_frames(&mut self, frames: Vec<StreamFrame>, now: Instant) -> RoutedFrames {
        let mut pong = None;
        let mut probe_ack = None;
        let mut window_opened = false;
        for frame in frames {
            match frame {
                StreamFrame::Data {
                    stream_id,
                    offset,
                    data,
                } => {
                    // What the connection has left for out-of-order data
                    // (spec §4.16): all its streams share the cap.
                    let room = self.undelivered_cap.saturating_sub(self.undelivered);
                    let on_delivery = self.consumption_of(stream_id) == Consumption::OnDelivery;
                    let (delivered, ack, before, after, extended, stopped, credit) = {
                        let st = self.stream_mut(stream_id);
                        let before = st.receiver.buffered_cost();
                        let point = st.receiver.next_offset();
                        let delivered = st.receiver.on_data_within(offset, data, room);
                        let after = st.receiver.buffered_cost();
                        if on_delivery {
                            st.receiver.on_consumed(delivered.len() as u64);
                        }
                        // An unbroken stream grew: the point moved and no
                        // hole lay past it. Anything else -- a repeat, DATA
                        // past a hole, DATA that fills one -- is what a
                        // sender's loss recovery counts on hearing of at
                        // once (spec §4.11, RFC 5681 §4.2).
                        let extended = st.receiver.next_offset() > point && before == 0;
                        let stopped = st.receiver.may_be_stopped();
                        let credit = st.receiver.credit_due(now, false);
                        (
                            delivered,
                            st.receiver.ack(),
                            before,
                            after,
                            extended,
                            stopped,
                            credit,
                        )
                    };
                    self.note_undelivered(before, after);
                    if !delivered.is_empty() {
                        self.events.push(Event::StreamData {
                            stream_id,
                            data: delivered,
                        });
                    }
                    if extended {
                        self.data_since_ack += 1;
                    }
                    let urgent = !extended || self.data_since_ack >= ACK_EVERY;
                    // One ACK per stream (ruling R16): the latest point.
                    self.queue_ack(now, stream_id, ack, urgent);
                    // Room for a sender that may be stopped at its limit
                    // goes at once (spec §4.11, §6.4); other room rides.
                    self.queue_credit(now, credit, stopped);
                }
                StreamFrame::Ack { stream_id, cum_ack } => {
                    // FlightSize as the loss finds it (RFC 5681 (4)).
                    let flight = self.flight();
                    let Some(st) = self.streams.get_mut(&stream_id) else {
                        continue;
                    };
                    let timed_from = st.sender.ack_timed_from(cum_ack);
                    // Asked before the ACK moves the base (RFC 3465 §2.3).
                    let timeout_flight = st.sender.acks_timeout_flight();
                    let effect = st.sender.on_ack_counting(cum_ack);
                    let recover = st.sender.sent_up_to();
                    let mut timeout_undone = false;
                    let verdict = if effect.acked > 0 {
                        window_opened = true;
                        timeout_undone |= self.cc.undo_timeout_if_spurious(stream_id, now);
                        // The full offset the base moved to, not the 32-bit
                        // field: the recovery point is a full one (spec §4.14).
                        // An undone timeout gives its window back, and with
                        // it what the ACK counts for.
                        self.cc.on_advance(
                            stream_id,
                            st.sender.base_offset(),
                            effect.acked,
                            self.window_limited,
                            timeout_flight && !timeout_undone,
                            now,
                        )
                    } else if effect.duplicates > 0 && st.sender.may_fast_retransmit() {
                        self.cc
                            .on_duplicate(stream_id, effect.duplicates, flight, recover, now)
                    } else {
                        AckVerdict::Nothing
                    };
                    match verdict {
                        AckVerdict::Nothing => {}
                        AckVerdict::RetransmitOldest => {
                            st.sender.mark_oldest_urgent();
                            // Every repair restarts the timers of what is
                            // still in flight: see `restart_timers`.
                            st.sender.restart_timers(now);
                            window_opened = true;
                        }
                        AckVerdict::Recovered { recover } => {
                            st.sender.hold_fast_retransmit_to(recover);
                        }
                    }
                    if let Some(sent) = timed_from {
                        self.take_round_trip(now, now.saturating_duration_since(sent));
                    }
                    if timeout_undone {
                        self.give_back_spurious_timeout(now);
                    }
                }
                StreamFrame::Ping { token } => {
                    // One PONG per datagram, for its last PING (ruling R16);
                    // the one CREDIT copy it may carry is chosen once, in
                    // `on_transport`.
                    pong = Some(token);
                }
                StreamFrame::Pong { token } => {
                    if let Some(pos) = self.outstanding_pings.iter().position(|(t, _)| *t == token)
                    {
                        let sent = self.outstanding_pings[pos].1;
                        let rtt = self.last_recv_auth.saturating_duration_since(sent);
                        self.rtt = Some(RttSample {
                            value: rtt,
                            source: RttSource::Ping,
                        });
                        self.take_round_trip(now, rtt);
                        // The answered PING and every older one are moot: the
                        // peer answers. The newer ones are still on their way.
                        self.outstanding_pings.drain(..=pos);
                        // The peer answers again, so the road checks go back
                        // to the idle schedule.
                        self.ping_unanswered = false;
                        self.ping_unanswered_since = None;
                    }
                }
                StreamFrame::SessionAbort { reason } => {
                    if !self.features.contains(Features::RESOURCE_LIMITS) {
                        continue;
                    }
                    self.session_abort = Some(reason);
                    self.events.push(Event::SessionAborted(reason));
                    self.closed_gracefully = true;
                    self.set_state(LinkState::Closed);
                    break;
                }
                StreamFrame::Close { .. } => {
                    // A received Close is a GRACEFUL shutdown: flag it before the
                    // state change so the driver can tear the backend down
                    // immediately rather than retaining it (as it would on a
                    // death-timeout `Closed`).
                    self.closed_gracefully = true;
                    self.set_state(LinkState::Closed);
                }
                StreamFrame::Reset { .. } if matches!(self.role, Role::Server) => {
                    // Spec §6.5 (amended 2026-09-28, final review C1, ruling
                    // R15): only a server drops a tail and resyncs (screen
                    // streams, `enforce_hard_cap` and the `on_timeout`
                    // desync are server-only), so no client build ever
                    // sends a `Reset`. One from a client is dropped whole:
                    // no point move, nothing counted as taken, no limit
                    // pushed, no urgent `CREDIT`, no repeat armed, not even
                    // a stream made for its number. Taken, it put a stream
                    // in "possibly stopped" for good -- one per stream
                    // number, each drawing a `CREDIT` with every PONG, a
                    // lever an unproven peer could aim at a spoofed address.
                    //
                    // No ACK either. An ACK is what clears a sender's armed
                    // `Reset`, and no client has one to clear; for a hostile
                    // peer it would only be a reply drawn one for one. The
                    // datagram's other frames draw what they draw anyway.
                }
                StreamFrame::Reset {
                    stream_id,
                    new_offset,
                } => {
                    let (moved, ack, before, after) = {
                        let st = self.stream_mut(stream_id);
                        let before = st.receiver.buffered_cost();
                        let moved = st.receiver.on_reset(new_offset);
                        let after = st.receiver.buffered_cost();
                        (moved, st.receiver.ack(), before, after)
                    };
                    self.note_undelivered(before, after);
                    // Only a Reset that actually moved the point forward is a
                    // real discontinuity worth telling the backend about. The
                    // sender re-arms the same Reset on every flush until it's
                    // acked (see `StreamSender::frames_to_send`), so a repaint
                    // burst delivers several duplicates in a row; without this
                    // guard each one re-ran `ShellState::on_reset` on the
                    // client -- re-creating the prediction engine and emitting
                    // an extra frame every time, killing local echo exactly at
                    // resume. Still ACK unconditionally in both cases: the ack
                    // is what clears the SENDER's `pending_reset`.
                    if moved {
                        self.events.push(Event::StreamReset { stream_id });
                    }
                    self.queue_ack(now, stream_id, ack, true);
                    // What the Reset skipped is taken: the room goes with its
                    // ACK, at once (spec §4.11, §6.5).
                    let credit = self.stream_mut(stream_id).receiver.credit_due(now, true);
                    self.queue_credit(now, credit, true);
                }
                StreamFrame::Credit { stream_id, limit } => {
                    // A stream this side has no state for grants nothing
                    // yet: a stream gets its implicit window when it is
                    // made (harmless either way -- an honest peer never
                    // sends this, and one raising our limit only lets us
                    // send it more, Minor 7, review of this task). A raised
                    // limit opens room, filled at once like an ACK's (spec
                    // §4.2).
                    if let Some(st) = self.streams.get_mut(&stream_id) {
                        window_opened |= st.sender.on_credit(limit);
                    }
                }
                StreamFrame::PathProbe { token } => {
                    // Answered where it came from: this checks the road we
                    // were asked about, not the one we are using.
                    probe_ack = Some(token);
                }
                StreamFrame::PathProbeAck { token } => {
                    self.on_path_probe_ack(token, now);
                }
            }
        }
        RoutedFrames {
            pong,
            probe_ack,
            window_opened,
        }
    }

    // --- Internal: sending and timers ---

    /// Seal one plaintext for `to` under the next counter. `false` when it
    /// could not be sealed -- then nothing more goes out and the counter
    /// stays. Sealing fails two ways, neither reachable in practice:
    /// `NonceExhausted` -- the counter reached 2^64 - 1, which Noise
    /// reserves (a datagram a nanosecond for 584 years); `Encrypt` -- a
    /// plaintext past ChaCha20-Poly1305's limit (about 256 GiB).
    fn seal_to(&mut self, to: SocketAddr, payload: &[u8], out: &mut Vec<Datagram>) -> bool {
        let Some(keys) = self.keys.as_ref() else {
            return false;
        };
        let counter = self.next_counter;
        // Built once: the header sealed under is the header sent.
        let header = transport_header(self.session_id, counter);
        let Ok(aead) = keys.encrypt(counter, &header, payload) else {
            return false;
        };
        self.next_counter += 1;
        out.push(Datagram {
            to,
            bytes: encode_transport(&header, &aead),
        });
        true
    }

    /// Seal each of `frames` alone, one datagram each, for `to`: a road
    /// check and its answer, which never share a datagram (spec §4.11), a
    /// peer played as built before packing, and what a test puts on the
    /// wire exactly as given.
    fn emit_frames_to(
        &mut self,
        to: SocketAddr,
        frames: Vec<StreamFrame>,
        out: &mut Vec<Datagram>,
    ) {
        for frame in frames {
            let mut payload = Vec::new();
            frame.encode(&mut payload);
            if !self.seal_to(to, &payload, out) {
                return;
            }
        }
    }

    /// Seal `ordered` -- in their order -- and `service` -- in any -- for
    /// the live road, packed into as few datagrams of at most
    /// `MAX_DATAGRAM` bytes as hold them ([`pack`], spec §4.11). A peer
    /// played as built before packing gets one frame a datagram
    /// ([`Connection::act_as_legacy_peer_for_test`]). Never a road check or
    /// its answer: those go alone ([`Connection::emit_frames_to`]) -- a
    /// receiver built before packing would take a check packed with
    /// ordinary frames for an ordinary datagram and follow its source.
    fn emit_packed(
        &mut self,
        ordered: Vec<StreamFrame>,
        service: Vec<StreamFrame>,
        out: &mut Vec<Datagram>,
    ) {
        debug_assert!(
            !ordered.iter().chain(&service).any(StreamFrame::is_probe),
            "a road check or its answer goes alone"
        );
        let Some(peer) = self.peer else {
            return;
        };
        if self.keys.is_none() || (ordered.is_empty() && service.is_empty()) {
            return;
        }
        if self.legacy_peer {
            let mut each = ordered;
            each.extend(service);
            self.emit_frames_to(peer, each, out);
            return;
        }
        for payload in pack(&ordered, &service) {
            if !self.seal_to(peer, &payload, out) {
                return;
            }
        }
    }

    /// Seal `frames` for the live road, packed, with every service frame
    /// that waits riding along (spec §4.11): what a flush, a PING, a
    /// `CREDIT` repeat, a PONG and a `Close` go out through.
    fn emit_frames(&mut self, frames: Vec<StreamFrame>, out: &mut Vec<Datagram>) {
        if frames.is_empty() || self.keys.is_none() || self.peer.is_none() {
            return;
        }
        let service = self.take_service();
        self.emit_packed(frames, service, out);
    }

    /// Send what waits for a ride alone, now (spec §4.11).
    fn flush_service(&mut self, out: &mut Vec<Datagram>) {
        if self.keys.is_none() || self.peer.is_none() {
            return;
        }
        let service = self.take_service();
        self.emit_packed(Vec::new(), service, out);
    }

    /// Put out what the streams have to send (see [`Connection::flush_after`]).
    fn flush_senders(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        self.flush_after(now, Vec::new(), out);
    }

    /// Put out what the streams have to send (spec §4.8): every armed
    /// `Reset` first (tiny, and each opens its stream), then the interactive
    /// streams round-robin, then the bulk streams round-robin, at most
    /// `BULK_FLUSH_BUDGET` segments of them. `lead` -- a PING, `CREDIT`
    /// repeats -- goes in front of everything: control before data (spec
    /// §4.8), and in the same datagrams (spec §4.11). Counts retransmits for
    /// the statistics.
    fn flush_after(&mut self, now: Instant, lead: Vec<StreamFrame>, out: &mut Vec<Datagram>) {
        let rto = self.rto();
        let mut frames = lead;
        for st in self.streams.values_mut() {
            frames.extend(st.sender.take_due_reset(now, rto));
        }
        // Every segment whose own deadline passed is due again (spec §4.2).
        // The retransmit timer "expires" (RFC 6298 §5.5) when a stream's
        // OLDEST segment does, and backs off once however many fall due with
        // it. The congestion response (RFC 5681 §3.1, spec §4.15): one
        // segment of window, and the oldest segment goes out again whatever
        // the window says; the others follow as the ACKs open it.
        let flight = self.flight();
        let mut expired = Vec::new();
        for (id, st) in self.streams.iter_mut() {
            if st.sender.mark_due_lost(now, rto) {
                expired.push(*id);
            }
        }
        for st in self.streams.values_mut() {
            st.sender.settle_timeout_marks(!expired.is_empty());
        }
        if !expired.is_empty() {
            self.backoff_before_timeout = self.rto_backoff;
            self.rto_backoff = (self.rto_backoff + 1).min(MAX_RTO_BACKOFF);
            self.cc.on_retransmit_timeout(now, flight, &expired);
            for id in expired {
                if let Some(st) = self.streams.get_mut(&id) {
                    st.sender.mark_oldest_urgent();
                }
            }
            // What went out before the timeout goes out again as the window
            // opens, copies of what the peer may have included: their ACKs
            // must not start a fast recovery (RFC 6582 §3.2 step 1). An undo
            // of the timeout keeps this hold (see
            // `CongestionWindow::undo_timeout_if_spurious`).
            //
            // And what is in flight now marks the timeout's round trip: an
            // ACK that acknowledges any of it counts for one segment of slow
            // start at most (see `CongestionWindow::on_advance`). An undo
            // forgets that mark.
            for st in self.streams.values_mut() {
                st.sender.hold_fast_retransmit();
                st.sender.note_timeout_flight();
            }
        }
        let mut retransmits = 0u32;
        let mut pipe = self.pipe();
        let before_data = frames.len();
        for st in self.streams.values_mut() {
            while let Some(seg) = st.sender.next_urgent(now) {
                pipe += seg.len;
                retransmits += 1;
                frames.push(seg.frame);
            }
        }
        let mut limited = self.serve_class(
            StreamClass::Interactive,
            now,
            None,
            &mut pipe,
            &mut frames,
            &mut retransmits,
        );
        limited |= self.serve_class(
            StreamClass::Bulk,
            now,
            Some(BULK_FLUSH_BUDGET),
            &mut pipe,
            &mut frames,
            &mut retransmits,
        );
        // See `window_limited`: a flush that put nothing out and held
        // nothing back says nothing about the flight already out.
        if limited || frames.len() > before_data {
            self.window_limited = limited;
        }
        // Data left behind any window: the sender, not the application, set
        // this flush's pace (see `CongestionWindow::note_backlog`).
        if self.streams.values().any(|s| s.sender.has_waiting()) {
            self.cc.note_backlog(now);
        }
        self.retransmits += retransmits;
        self.emit_frames(frames, out);
    }

    /// Serve `class`'s streams round-robin: each in turn gives up to
    /// `RR_QUANTUM` segments -- lost ones first, then new bytes -- and the
    /// rounds go on while anything goes out, until `budget` segments (the
    /// bulk class) or the congestion window stops `class`
    /// ([`CongestionWindow::may_send`], spec §4.15: `pipe` for the whole
    /// connection, and the class's own share of it). Goes on from where the
    /// last flush stopped: a turn cut short by the budget or the window is
    /// finished first, otherwise the stream after the one served last starts.
    /// Returns whether it stopped at the window or at `budget` with something
    /// still to send, or went past the window on the interactive allowance:
    /// the sender, not the application, was the limit -- the congestion
    /// window grows only then. Past the window counts as much as stopped at
    /// it: a terminal session that a timeout left at one segment writes on
    /// its allowance, is never stopped, and would otherwise never grow back.
    fn serve_class(
        &mut self,
        class: StreamClass,
        now: Instant,
        budget: Option<usize>,
        pipe: &mut usize,
        frames: &mut Vec<StreamFrame>,
        retransmits: &mut u32,
    ) -> bool {
        let ids: Vec<u8> = self
            .streams
            .keys()
            .copied()
            .filter(|id| self.class_of(*id) == class)
            .collect();
        if ids.is_empty() {
            return false;
        }
        let mut own = self.class_pipe(class);
        let mut past_the_window = false;
        let slot = class as usize;
        // Where to start, and how much the first stream still has of its turn.
        let (start, mut first_quantum) = match self.rr_cursor[slot] {
            Some(RrPosition { stream, left }) if left > 0 && ids.contains(&stream) => {
                (ids.iter().position(|id| *id == stream).unwrap_or(0), left)
            }
            Some(RrPosition { stream, .. }) => (
                ids.iter().position(|id| *id > stream).unwrap_or(0),
                RR_QUANTUM,
            ),
            None => (0, RR_QUANTUM),
        };
        let order: Vec<u8> = ids[start..].iter().chain(&ids[..start]).copied().collect();
        let mut sent = 0usize;
        'rounds: loop {
            let mut this_round = 0usize;
            for id in &order {
                let quantum = std::mem::replace(&mut first_quantum, RR_QUANTUM);
                let Some(st) = self.streams.get_mut(id) else {
                    continue;
                };
                for given in 0..quantum {
                    if budget.is_some_and(|b| sent >= b) || !self.cc.may_send(class, *pipe, own) {
                        break 'rounds;
                    }
                    let Some(seg) = st.sender.next_segment(now) else {
                        // Out of data: its turn ends here.
                        if given > 0 {
                            self.rr_cursor[slot] = Some(RrPosition {
                                stream: *id,
                                left: 0,
                            });
                        }
                        break;
                    };
                    *pipe += seg.len;
                    own += seg.len;
                    past_the_window |= *pipe > self.cc.limit(StreamClass::Bulk);
                    if seg.retransmit {
                        *retransmits += 1;
                    }
                    frames.push(seg.frame);
                    sent += 1;
                    this_round += 1;
                    self.rr_cursor[slot] = Some(RrPosition {
                        stream: *id,
                        left: quantum - given - 1,
                    });
                }
            }
            if this_round == 0 {
                break;
            }
        }
        past_the_window
            || (!self.cc.may_send(class, *pipe, own) || budget.is_some_and(|b| sent >= b))
                && order.iter().any(|id| {
                    self.streams
                        .get(id)
                        .is_some_and(|s| s.sender.has_sendable())
                })
    }

    /// Bytes the whole connection has in the network: sent, not
    /// acknowledged, not taken for lost.
    fn pipe(&self) -> usize {
        self.streams.values().map(|s| s.sender.pipe()).sum()
    }

    /// `class`'s share of [`Connection::pipe`].
    fn class_pipe(&self, class: StreamClass) -> usize {
        self.streams
            .iter()
            .filter(|(id, _)| self.class_of(**id) == class)
            .map(|(_, s)| s.sender.pipe())
            .sum()
    }

    /// Whether a flush now would put something on the wire that is not
    /// merely a retransmit waiting for its own deadline.
    fn sendable_now(&self) -> bool {
        let pipe = self.pipe();
        let interactive = self.class_pipe(StreamClass::Interactive);
        self.streams.iter().any(|(id, st)| {
            let class = self.class_of(*id);
            let own = match class {
                StreamClass::Interactive => interactive,
                StreamClass::Bulk => pipe - interactive,
            };
            st.sender.has_unsent_reset()
                || st.sender.has_urgent()
                || (st.sender.has_sendable() && self.cc.may_send(class, pipe, own))
        })
    }

    /// Bytes sent and not yet acknowledged, on every stream: RFC 5681's
    /// FlightSize.
    fn flight(&self) -> usize {
        self.streams
            .values()
            .map(|s| s.sender.bytes_in_flight())
            .sum()
    }

    /// Queue an ACK point: the latest per stream wins (points only move on).
    fn queue_ack(&mut self, now: Instant, stream_id: u8, cum_ack: u32, urgent: bool) {
        self.acks_due.insert(stream_id, cum_ack);
        self.owe_service(now, urgent);
    }

    /// Queue a `CREDIT` announcement: the newest limit per stream wins.
    fn queue_credit(&mut self, now: Instant, credit: Option<StreamFrame>, urgent: bool) {
        let Some(StreamFrame::Credit { stream_id, limit }) = credit else {
            return;
        };
        self.credits_due.insert(stream_id, limit);
        self.owe_service(now, urgent);
    }

    /// A service frame was queued at `now` (spec §4.11): the wait starts
    /// with the first of them, and one that must go at once -- or any, to a
    /// peer played as built before delayed ACKs -- makes them all go at once.
    fn owe_service(&mut self, now: Instant, urgent: bool) {
        self.service_since.get_or_insert(now);
        self.service_urgent |= urgent || self.legacy_peer;
    }

    /// Every service frame waiting -- ACKs, then CREDITs -- taken for the
    /// next datagram out (spec §4.11): nothing waits any more.
    fn take_service(&mut self) -> Vec<StreamFrame> {
        self.service_since = None;
        self.service_urgent = false;
        self.data_since_ack = 0;
        let acks = std::mem::take(&mut self.acks_due)
            .into_iter()
            .map(|(stream_id, cum_ack)| StreamFrame::Ack { stream_id, cum_ack });
        let credits = std::mem::take(&mut self.credits_due)
            .into_iter()
            .map(|(stream_id, limit)| StreamFrame::Credit { stream_id, limit });
        acks.chain(credits).collect()
    }

    /// Send what waits for a ride alone once it may wait no longer (spec
    /// §4.11): at once when urgent, else `ACK_DELAY` after the first of it.
    fn flush_service_if_due(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        let due = self.service_urgent
            || self
                .service_since
                .is_some_and(|since| now >= since + ACK_DELAY);
        if due {
            self.flush_service(out);
        }
    }

    /// The one `CREDIT` copy a PONG carries, if any (spec §6.4, ruling
    /// R15): the first stream from `pong_credit_next` on, wrapping round,
    /// whose sender may be stopped at an older limit and whose newest limit
    /// went out an `rto` ago or more. The search starts after that stream
    /// next time, so the streams that may be stopped take the copies in
    /// turn.
    fn pong_credit(&mut self, now: Instant, rto: Duration) -> Option<StreamFrame> {
        let start = self.pong_credit_next;
        let mut found = None;
        for (&id, st) in self.streams.range_mut(start..) {
            if let Some(frame) = st.receiver.credit_for_pong(now, rto) {
                found = Some((id, frame));
                break;
            }
        }
        if found.is_none() {
            for (&id, st) in self.streams.range_mut(..start) {
                if let Some(frame) = st.receiver.credit_for_pong(now, rto) {
                    found = Some((id, frame));
                    break;
                }
            }
        }
        let (id, frame) = found?;
        self.pong_credit_next = id.wrapping_add(1);
        Some(frame)
    }

    fn stream_mut(&mut self, stream_id: u8) -> &mut StreamState {
        let features = self.features;
        self.streams
            .entry(stream_id)
            .or_insert_with(|| StreamState::new(stream_id, features))
    }

    /// Select the ordered profile explicitly in generic transport fixtures.
    #[cfg(test)]
    pub(crate) fn enable_geometry_for_test(&mut self) {
        self.apply_features(self.features | Features::CHANNEL_GEOMETRY);
    }

    /// Take `features` as this connection's (spec §5.4): on every stream it
    /// has already -- a client may have queued bytes before its handshake
    /// ended -- as on those it makes later.
    fn apply_features(&mut self, features: Features) {
        self.features = features;
        for st in self.streams.values_mut() {
            st.set_features(features);
        }
    }

    /// The retransmit timeout: [`Connection::estimated_rto`] doubled for every
    /// expiry since the last measured round trip (RFC 6298 §5.5), capped at
    /// `RETRANSMIT_CEILING`. The back-off is what keeps a window larger than
    /// a slow road's queue from resending everything the queue dropped, every
    /// round trip, into the same queue: no sample is taken while a lost
    /// segment holds the cumulative ACK back (Karn), so the timeout keeps
    /// doubling until the loss is repaired.
    fn rto(&self) -> Duration {
        (self.estimated_rto() * 2u32.pow(self.rto_backoff)).min(RETRANSMIT_CEILING)
    }

    /// The latest retransmit timeout was spurious (see
    /// `CongestionWindow::undo_timeout_if_spurious`, which gave the window
    /// back): its back-off goes, and what it took for lost is in flight after
    /// all -- not sent again, and timed from now.
    fn give_back_spurious_timeout(&mut self, now: Instant) {
        self.rto_backoff = self.rto_backoff.min(self.backoff_before_timeout);
        for st in self.streams.values_mut() {
            st.sender.forget_timeout_losses(now);
        }
    }

    /// One round-trip sample under the load the connection carries -- a
    /// PONG, or an ACK timed by Karn's rule: the retransmit timer's estimate
    /// (RFC 6298) and the congestion window's base delay and queue-delay
    /// signal (spec §4.15) all take it.
    fn take_round_trip(&mut self, now: Instant, sample: Duration) {
        self.rtt_estimator.sample(sample);
        self.rto_backoff = 0;
        let flight = self.flight();
        if self.cc.on_round_trip(now, sample, flight) {
            // A base probe's queue is gone, and its next round trip becomes
            // the base (spec §4.15). With two segments out, a receiver of
            // this build holds their ACK up to `ACK_DELAY` (spec §4.11) --
            // taken, the base read up to 20 ms long from then on, and the
            // undo rules that judge a repair's answer against it took
            // genuine answers for early ones. A PING now is answered the
            // moment it arrives, and the ACK of what went out with it rides
            // its PONG: the round trip that ends the probe is the road's.
            self.ping_forced = true;
        }
    }

    /// The retransmit timeout before any back-off.
    ///
    /// Once the estimator has a sample -- a PONG, or a data segment
    /// acknowledged without having been retransmitted (Karn's rule) --
    /// `SRTT + max(4 * RTTVAR, SRTT / 4)` within `[RTO_FLOOR,
    /// RETRANSMIT_CEILING]`. Acknowledgements time the queue a bulk write
    /// builds within one round trip, so the timeout follows it up instead of
    /// firing under it.
    ///
    /// Before any sample, a client has the handshake's seed: `2 * seed`
    /// within `[DEFAULT_RTO, RTO_CEILING]`. msg1 and msg2 cross an empty
    /// queue, so the seed may raise the timeout above the default but never
    /// lower it -- the first thing a session may do is a bulk write (the
    /// app's daemon update) whose tail waits seconds in a slow uplink's
    /// queue. With nothing at all, `DEFAULT_RTO`.
    fn estimated_rto(&self) -> Duration {
        if let Some(t) = self.rtt_estimator.timeout() {
            return t.clamp(RTO_FLOOR, RETRANSMIT_CEILING);
        }
        match self.rtt {
            Some(RttSample {
                value,
                source: RttSource::Handshake,
            }) => (value * 2).clamp(DEFAULT_RTO, RTO_CEILING),
            // Every PONG feeds the estimator, so a PING sample never gets
            // here; kept total rather than unreachable.
            Some(RttSample {
                value,
                source: RttSource::Ping,
            }) => (value * 2).clamp(RTO_FLOOR, RTO_CEILING),
            None => DEFAULT_RTO,
        }
    }

    /// Test-only: the retransmit timeout as of now.
    #[cfg(any(test, feature = "testnet"))]
    pub fn rto_for_test(&self) -> Duration {
        self.rto()
    }

    /// Test-only: the congestion window and its threshold (`None`: none yet).
    #[cfg(any(test, feature = "testnet"))]
    pub fn congestion_window_for_test(&self) -> (usize, Option<usize>) {
        (self.cc.cwnd(), self.cc.ssthresh())
    }

    /// Test-only: duplicate ACKs in a row that count as a loss -- 3, or more
    /// once an undone fast retransmit taught the connection the road's
    /// reordering.
    #[cfg(test)]
    pub(crate) fn duplicate_threshold_for_test(&self) -> u32 {
        self.cc.dup_threshold()
    }

    /// Test-only: the road's base delay, as the congestion window keeps it.
    #[cfg(test)]
    pub(crate) fn base_delay_for_test(&self) -> Option<Duration> {
        self.cc.base_delay()
    }

    /// Test-only: how often the congestion window was cut, by what.
    #[cfg(test)]
    pub(crate) fn cuts_for_test(&self) -> crate::congestion::Cuts {
        self.cc.cuts()
    }

    /// Test-only: the base probe in progress, if any.
    #[cfg(test)]
    pub(crate) fn base_probe_for_test(&self) -> Option<crate::congestion::Probe> {
        self.cc.probe()
    }

    /// Test-only: a window that never limits, for tests about something else.
    #[cfg(test)]
    fn open_congestion_window_for_test(&mut self) {
        self.cc.open_for_test();
    }

    /// Test-only: the cookie a server handed this client for its msg1, if
    /// it took one (spec §4.16). After `Live` nothing reads it, so this is
    /// the only way to see that a late reply was not taken.
    #[cfg(test)]
    pub(crate) fn cookie_for_test(&self) -> Option<[u8; COOKIE_LEN]> {
        self.cookie
    }

    /// The round-trip allowance for the unanswered-PING rule: `2 * rtt` of
    /// the latest PONG (or the handshake's
    /// seed, floored at `DEFAULT_RTO` as above) within `[RTO_FLOOR,
    /// RTO_CEILING]`, `DEFAULT_RTO` with nothing measured. Not the
    /// retransmit timeout: that one may grow past `RTO_CEILING` under a
    /// queue, and a road must not take longer to be called dead for it.
    fn liveness_rto(&self) -> Duration {
        match self.rtt {
            None => DEFAULT_RTO,
            Some(RttSample {
                value,
                source: RttSource::Handshake,
            }) => (value * 2).clamp(DEFAULT_RTO, RTO_CEILING),
            Some(RttSample {
                value,
                source: RttSource::Ping,
            }) => (value * 2).clamp(RTO_FLOOR, RTO_CEILING),
        }
    }

    /// How old an outstanding PING must be to count as unanswered. Measured:
    /// past both the interval and [`Connection::liveness_rto`] -- not the
    /// retransmit timeout, which a bulk write's queue may stretch to 15 s.
    /// Nothing measured yet: past both the
    /// interval and the 3 s ceiling -- `DEFAULT_RTO` (500 ms) is kept for
    /// retransmits, but a road slower than the PING interval would have its
    /// first PING called unanswered with it.
    fn unanswered_after(&self, now: Instant) -> Duration {
        match self.rtt {
            Some(_) => self.ping_interval(now).max(self.liveness_rto()),
            None => self.ping_interval(now).max(RTO_CEILING),
        }
    }

    fn next_ping_token(&mut self) -> u32 {
        self.ping_token = self.ping_token.wrapping_add(1);
        self.ping_token
    }

    fn set_state(&mut self, s: LinkState) {
        if self.state == s {
            return;
        }
        self.state = s;
        self.events.push(Event::StateChanged(s));
    }

    /// Test-only: start stream `stream_id` at `offset` on both its sender and
    /// its receiver. Call it on both ends, for the same stream.
    #[cfg(any(test, feature = "testnet"))]
    pub fn start_stream_at_for_test(&mut self, stream_id: u8, offset: u32) {
        let mut st = StreamState {
            sender: StreamSender::starting_at(stream_id, offset),
            receiver: StreamReceiver::starting_at(stream_id, offset),
        };
        st.set_features(self.features);
        if let Some(old) = self.streams.insert(stream_id, st) {
            self.undelivered -= old.receiver.buffered_cost();
        }
    }

    /// Test-only: whether this connection's keys take the header as the
    /// AEAD's associated data; `None` before the handshake.
    #[cfg(any(test, feature = "testnet"))]
    pub fn keys_use_header_for_test(&self) -> Option<bool> {
        self.keys.as_ref().map(TransportKeys::header_aad)
    }

    /// Test-only: play a peer built before negotiation (spec §9.3). A server
    /// on the `on_datagram` path -- the simulator's -- writes msg2 without its
    /// features field and enables nothing, whatever msg1 offered. (`accept`
    /// builds its connection itself, so this cannot reach it; nothing needs
    /// it to.) A client ignores `CookieReply`, whose kind an old parser does
    /// not know; its msg1 is whatever its caller hands `start_with_payload`
    /// (`encode_msg1_without_tail` for an old one). It also sends one frame a
    /// datagram and acknowledges every DATA at once, as builds before
    /// packing and delayed ACKs did (spec §9.3).
    #[cfg(any(test, feature = "testnet"))]
    pub fn act_as_legacy_peer_for_test(&mut self) {
        self.legacy_peer = true;
    }

    /// Test-only: a handle that stops upgrading once this connection is
    /// dropped. Only the session manager's tests use it.
    #[cfg(all(test, feature = "tokio-driver"))]
    pub(crate) fn watch_drop_for_test(&mut self) -> std::sync::Weak<()> {
        let alive = self
            .alive_for_test
            .get_or_insert_with(|| std::sync::Arc::new(()));
        std::sync::Arc::downgrade(alive)
    }

    /// Test-only: force a PING that is never cleared, so `next_timeout` stays
    /// in the past and every `on_timeout` sends one more PING. The simulator
    /// must fail such a run rather than spin at one instant forever.
    #[cfg(test)]
    pub(crate) fn stick_forced_ping_for_test(&mut self) {
        self.ping_forced = true;
        self.forced_ping_sticks = true;
    }

    /// Test-only: decrypt and decode a transport datagram addressed to this
    /// connection WITHOUT processing it -- no replay-window update, no
    /// liveness, no delivery. `None` if it is not a transport datagram of
    /// this session or does not decrypt with this side's receive key. The
    /// simulator counts frames by kind with it, and tests use it to see what
    /// a peer actually put on the wire.
    #[cfg(any(test, feature = "testnet"))]
    pub fn peek_frames(&self, bytes: &[u8]) -> Option<Vec<StreamFrame>> {
        let keys = self.keys.as_ref()?;
        match parse(bytes) {
            Ok(Frame::Transport {
                session_id,
                counter,
                aead,
                aad,
            }) if session_id == self.session_id => keys
                .decrypt(counter, aad, aead)
                .ok()
                .map(|plain| StreamFrame::decode_all(&plain)),
            _ => None,
        }
    }

    /// Test-only: out-of-order data held on every stream, by cost -- the
    /// running count, checked against a count afresh.
    #[cfg(any(test, feature = "testnet"))]
    pub fn undelivered_cost_for_test(&self) -> usize {
        assert_eq!(
            self.undelivered,
            self.recount_undelivered(),
            "the running count of out-of-order data drifted"
        );
        self.undelivered
    }

    /// Test-only: the limit `stream_id`'s sender holds, with credits.
    #[cfg(any(test, feature = "testnet"))]
    pub fn credit_limit_for_test(&self, stream_id: u8) -> Option<u64> {
        self.streams.get(&stream_id)?.sender.credit_limit()
    }

    /// Test-only: the newest limit `stream_id`'s receiver announced.
    #[cfg(any(test, feature = "testnet"))]
    pub fn receive_limit_for_test(&self, stream_id: u8) -> Option<u64> {
        self.streams.get(&stream_id)?.receiver.credit_limit()
    }

    /// Test-only: put `frames` on the wire exactly as given, one datagram
    /// each -- what a peer that ignores this protocol's rules would send.
    #[cfg(any(test, feature = "testnet"))]
    pub fn frames_for_test(&mut self, frames: Vec<StreamFrame>) -> Vec<Datagram> {
        let mut out = Vec::new();
        if let Some(peer) = self.peer {
            self.emit_frames_to(peer, frames, &mut out);
        }
        out
    }

    /// Test-only: `frames` sealed into ONE datagram whatever their size --
    /// what a hostile peer can send (past `MAX_DATAGRAM` a datagram arrives
    /// as IP fragments). Tests of what one datagram draws use it.
    #[cfg(any(test, feature = "testnet"))]
    pub fn packed_for_test(&mut self, frames: Vec<StreamFrame>) -> Datagram {
        let mut payload = Vec::new();
        for frame in &frames {
            frame.encode(&mut payload);
        }
        let peer = self.peer.expect("a peer to address");
        let mut out = Vec::new();
        assert!(self.seal_to(peer, &payload, &mut out), "sealed");
        out.pop().expect("one datagram")
    }

    /// Test-only: whether a PING is currently counted as unanswered (see the
    /// field's own doc). Simulator scenarios live outside this module.
    #[cfg(any(test, feature = "testnet"))]
    pub fn ping_unanswered(&self) -> bool {
        self.ping_unanswered
    }

    #[cfg(test)]
    pub(crate) fn limit_channel_offset_for_test(&mut self, stream: u8, remaining: u32) {
        self.stream_mut(stream).sender =
            StreamSender::starting_at(stream, crate::reliability::OFFSET_LIMIT - remaining);
    }

    /// Test-only shortcut: fabricate a server-side desync+resync on stream 0
    /// directly, without waiting out `RESYNC_AFTER` via `on_timeout`. Arms a
    /// `Reset` that goes out with the next `send`/`flush_senders`.
    #[cfg(test)]
    pub(crate) fn mark_output_desynced_for_test(&mut self) {
        let sender = &mut self.stream_mut(0).sender;
        sender.mark_desynced();
        sender.begin_resync();
        self.cc.forget_stream(0);
    }

    /// Test-only: queue an event directly, bypassing the state machine that
    /// normally produces it. Lets a consumer of `Connection` (e.g. the
    /// session manager's bridge tests) exercise its handling of a specific
    /// `Event` without reproducing the full scenario (roaming, timers, ...)
    /// that would otherwise emit it.
    // Called by the tests of the session manager, probation and the client driver.
    #[cfg(test)]
    pub(crate) fn push_test_event(&mut self, ev: Event) {
        self.events.push(ev);
    }
}

#[cfg(test)]
#[path = "recovery_connection_tests.rs"]
mod recovery_tests;

#[cfg(test)]
#[path = "conn_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
mod key_erasure_tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn cloned_config_private_keys_erase_independently() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let mut original = ConnectionConfig {
            role: Role::Client,
            local_static_priv: [7; 32],
            remote_static_pub: Some([9; 32]),
            auth: AuthPolicy::Allowlist(vec![]),
            features: Features::NONE,
            required_features: Features::NONE,
        };
        let mut cloned = original.clone();
        wipes_on_drop(&original);
        original.zeroize();
        assert_eq!(original.local_static_priv, [0; 32]);
        assert_eq!(original.remote_static_pub, Some([9; 32]));
        assert_eq!(cloned.local_static_priv, [7; 32]);
        let mut conn = Connection::new(cloned.clone());
        wipes_on_drop(&conn.local_priv);
        assert_eq!(*conn.local_priv, [7; 32]);
        conn.local_priv.zeroize();
        assert_eq!(*conn.local_priv, [0; 32]);
        assert_eq!(cloned.local_static_priv, [7; 32]);
        cloned.zeroize();
        assert_eq!(cloned.local_static_priv, [0; 32]);
    }
}
