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

use crate::auth::AUTH_NONCE_LEN;
use crate::congestion::{AckVerdict, CongestionWindow};
use crate::features::Features;
use crate::handshake::{Handshake, TransportKeys};
use crate::handshake_payload::{
    encode_msg1, encode_msg2, encode_msg2_without_tail, parse_msg1, parse_msg2, AuthMethod,
    HsPayloadError, Msg1Payload, StartKind, SESSION_TOKEN_LEN,
};
use crate::paths::{PathTable, RoadInfo, PROBE_URGENT};
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

/// How much earlier than [`crate::auth::AUTH_SETTLED_AFTER`] the link must
/// be able to reach `PathDown`: the tick that notices the silence, and the
/// handshake round trip a client may count its settle window from.
const REFUSAL_DETECTION_MARGIN: Duration = Duration::from_secs(1);

// Load-bearing, and written down nowhere else: a daemon that refuses a
// signature does not say so, it drops the route and stops answering. A
// client learns of the refusal only because the link falls to `PathDown`
// INSIDE its settle window -- a link still `Live` when the window ends is
// read as a key that was accepted. `PATH_DOWN_AFTER` was 6 s before it was
// lowered to 3 s, and at 6 s every silent refusal read as success, in the
// console client and the app alike. Whoever moves either value meets this
// first, at compile time.
const _: () = assert!(
    PATH_DOWN_AFTER.as_millis() + REFUSAL_DETECTION_MARGIN.as_millis()
        < crate::auth::AUTH_SETTLED_AFTER.as_millis(),
    "PATH_DOWN_AFTER must fall well inside AUTH_SETTLED_AFTER, or a refused signature reads as accepted"
);

/// Client link-death: how long an ACTIVE client tolerates silence before
/// declaring the link dead (`Closed`) and triggering a reconnect. Kept short so
/// a genuinely-dead server is detected quickly. A Doze/freeze must NOT count
/// toward this: the driver treats a thread freeze as a rebind/resume and
/// restarts the liveness window (see `driver_std` and [`Connection::request_ping`]),
/// so a phone that was asleep hot-migrates over UDP instead of slowly reconnecting.
const CLIENT_DEATH_AFTER: Duration = Duration::from_secs(45);

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
}

/// Link state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkState {
    Connecting,
    Live,
    PathDown,
    Closed,
}

/// Event for the caller. Accumulates in an internal queue and is handed out
/// in a batch by `poll_events`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// Handshake finished, transport encryption keys obtained.
    HandshakeDone,
    /// Freshly delivered in-order bytes of stream `stream_id`.
    StreamData { stream_id: u8, data: Vec<u8> },
    /// Link state change.
    StateChanged(LinkState),
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
    local_priv: [u8; 32],
    remote_pub: Option<[u8; 32]>,
    auth: AuthPolicy,
    /// What this side's configuration allows (`ConnectionConfig::features`).
    allowed_features: Features,
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

    fn new_stamped(cfg: ConnectionConfig, now: Instant) -> Self {
        let handshake = match cfg.role {
            Role::Server => Some(Handshake::new_responder(&cfg.local_static_priv)),
            Role::Client => None,
        };
        Connection {
            role: cfg.role,
            local_priv: cfg.local_static_priv,
            remote_pub: cfg.remote_static_pub,
            auth: cfg.auth,
            allowed_features: cfg.features,
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
            session_id: 0,
            death_after_override: None,
            resumed: false,
            server_nonce: None,
            peer: None,
            peer_static: None,
            paths: PathTable::new(),
            handshake_hash: [0u8; 32],
            next_counter: 1,
            replay: ReplayWindow::default(),
            streams: BTreeMap::new(),
            pong_credit_next: 0,
            acks_due: BTreeMap::new(),
            credits_due: BTreeMap::new(),
            service_since: None,
            service_urgent: false,
            data_since_ack: 0,
            events: Vec::new(),
            stream_resyncable: BTreeMap::new(),
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
        let mut conn = Connection::new(cfg);
        let payload_bytes = {
            let hs = match conn.handshake.as_mut() {
                Some(h) => h,
                None => return AcceptOutcome::Rejected,
            };
            match hs.read_msg(msg1_bytes) {
                Ok(p) => p,
                Err(_) => return AcceptOutcome::Rejected,
            }
        };
        let client_key = match conn.handshake.as_ref().and_then(Handshake::remote_static) {
            Some(k) if conn.auth.admits(&k) => k,
            _ => return AcceptOutcome::Rejected,
        };
        let msg1 = match parse_msg1(&payload_bytes) {
            Ok(m) => m,
            Err(_) => return AcceptOutcome::Rejected,
        };
        // The client must announce the method this server actually runs:
        // silently downgrading a signature client to the allowlist path (or
        // the other way round) would leave one side thinking it authenticated.
        if msg1.method != conn.auth.method() {
            return AcceptOutcome::Rejected;
        }
        // The only call to `resolve`, and the last point at which this
        // handshake can still be refused -- see this function's docs.
        let Msg2Inputs { resumed, nonce } = match resolve(&msg1) {
            Some(inputs) => inputs,
            None => return AcceptOutcome::Rejected,
        };
        // Spec §5.2: on when offered, allowed and implemented. The decision
        // is a function of msg1 and the configuration, so a retransmit twin
        // that went through probation on its own decides the same.
        let features = Features::negotiate(msg1.offered, conn.allowed_features);
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
        AcceptOutcome::Accepted {
            conn,
            client_key,
            msg1,
            out,
            nonce,
        }
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
            } => self.on_handshake_resp(now, body),
            Frame::Handshake {
                kind: Kind::CookieReply,
                body,
            } => self.on_cookie_reply(src, body),
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
            let sender = &mut self.stream_mut(stream_id).sender;
            sender.mark_desynced();
            sender.begin_resync();
            self.cc.forget_stream(stream_id);
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
                let st = self.stream_mut(stream_id);
                if !st.sender.is_desynced() {
                    st.sender.mark_desynced();
                    self.cc.forget_stream(stream_id);
                }
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
        candidates.push(self.death_base() + self.death_after());
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

    /// How long that dwell lasts: twice the retransmit timeout, which is
    /// comfortably longer than the round trip that traffic on the new road
    /// needs to come back and clear `PathDown`, with [`PROBE_URGENT`] as the
    /// floor -- nothing new can be learned about any road faster than the
    /// schedule that checks them.
    fn move_dwell(&self) -> Duration {
        (self.liveness_rto() * 2).max(PROBE_URGENT)
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

    fn on_handshake_resp(&mut self, now: Instant, body: &[u8]) -> Vec<Datagram> {
        let mut out = Vec::new();
        if !matches!(self.role, Role::Client) || !matches!(self.state, LinkState::Connecting) {
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
    fn on_cookie_reply(&mut self, src: SocketAddr, body: &[u8]) -> Vec<Datagram> {
        if self.legacy_peer
            || !matches!(self.role, Role::Client)
            || self.state != LinkState::Connecting
            || self.handshake.is_none()
            || self.peer != Some(src)
        {
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

    /// The round-trip allowance of road liveness -- the unanswered-PING rule
    /// and the move dwell: `2 * rtt` of the latest PONG (or the handshake's
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
    /// retransmits and the move dwell, but a road slower than the PING
    /// interval would have its first PING called unanswered with it.
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
mod tests {
    use super::*;
    use crate::handshake::generate_keypair;
    use crate::handshake_payload::{encode_msg1_without_tail, StartKind};
    use crate::reliability::MAX_IN_FLIGHT;
    use crate::reliability::OFFSET_LIMIT;
    use crate::reliability::{CHUNK_COST, LEGACY_RECEIVE_WINDOW};
    use crate::reliability::{CREDIT_RESENDS, STREAM_WINDOW};
    use crate::reliability::{CREDIT_UPDATE_STEP, MAX_SEGMENT_SIZE};
    use crate::wire::{encode_cookie_reply, COOKIE_VERSION};

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("valid address in test")
    }

    /// Feed datagrams into connection `conn` as if they arrived from address
    /// `src`. The returned datagrams are discarded -- tests fetch responses
    /// explicitly.
    fn deliver(conn: &mut Connection, now: Instant, src: SocketAddr, dgrams: Vec<Datagram>) {
        for dg in dgrams {
            let _ = conn.on_datagram(now, src, &dg.bytes);
        }
    }

    /// Same as `deliver`, but emphasizes in the roaming test that the source
    /// is a new address (the client "changed networks").
    fn deliver_from(conn: &mut Connection, now: Instant, src: SocketAddr, dgrams: Vec<Datagram>) {
        deliver(conn, now, src, dgrams);
    }

    /// Drive a client+server pair to the established (Live) state by manually
    /// pumping the two handshake messages (the server's response is returned
    /// from `on_datagram`, so `deliver` doesn't fit here).
    ///
    /// The handshake takes no time here, so the pair carries a ~0 ms handshake
    /// RTT seed and `rto()` sits at the 200 ms floor; a test that needs
    /// "nothing measured yet" uses [`established_pair_unmeasured`] instead.
    fn established_pair() -> (Connection, Connection, SocketAddr, SocketAddr) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });

        let now = Instant::now();
        let m1 = client.start_session(now, saddr, StartKind::Cold, [0; 16]);
        // The server receives msg1 from the client's address and replies with msg2.
        let mut m2 = Vec::new();
        for dg in m1 {
            m2.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        // The client receives msg2 from the server's address.
        for dg in m2 {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.peer(), Some(saddr));
        assert_eq!(server.peer(), Some(caddr));
        (client, server, caddr, saddr)
    }

    fn collect_stream_data(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::StreamData { data, .. } => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Same as `collect_stream_data`, but only for the given `stream_id` --
    /// used by tests that need to tell the output stream's data apart from a
    /// non-output stream's.
    fn collect_stream_data_for(events: &[Event], stream_id: u8) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::StreamData {
                    stream_id: sid,
                    data,
                } if *sid == stream_id => Some(data.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// A client offering `offer` and a server allowing `allow`, through
    /// `Connection::accept` (the session manager's entry) or `on_datagram`
    /// (the diagnostic servers'), driven to `Live`.
    fn handshake_with_features(
        offer: Features,
        allow: Features,
        via_accept: bool,
    ) -> (Connection, Connection, SocketAddr, SocketAddr) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: offer,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let server_cfg = ConnectionConfig {
            features: allow,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        };
        let now = Instant::now();
        let m1 = client.start_session(now, saddr, StartKind::Cold, [5; 16]);
        let (server, m2) = if via_accept {
            let body = match parse(&m1[0].bytes) {
                Ok(Frame::Handshake { body, .. }) => body.to_vec(),
                _ => panic!("msg1 is a handshake datagram"),
            };
            let resolve = &mut |_: &Msg1Payload| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [0u8; AUTH_NONCE_LEN],
                })
            };
            match Connection::accept(server_cfg, now, caddr, &body, resolve) {
                AcceptOutcome::Accepted { conn, out, .. } => (conn, out),
                AcceptOutcome::Rejected => panic!("an allowlisted client is accepted"),
            }
        } else {
            let mut server = Connection::new(server_cfg);
            let out = server.on_datagram(now, caddr, &m1[0].bytes);
            (server, out)
        };
        for dg in m2 {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.state(), LinkState::Live);
        (client, server, caddr, saddr)
    }

    /// Spec §9.2 (6): every combination of "the client offers / does not"
    /// and "the server allows / does not", through both server entry
    /// points. The header goes under the AEAD exactly when both say yes,
    /// both sides agree on it, and they talk either way.
    #[test]
    fn features_are_on_only_when_offered_and_allowed() {
        for offer in [Features::NONE, Features::SUPPORTED] {
            for allow in [Features::NONE, Features::SUPPORTED] {
                for via_accept in [false, true] {
                    let want = if offer == Features::SUPPORTED && allow == Features::SUPPORTED {
                        Features::SUPPORTED
                    } else {
                        Features::NONE
                    };
                    let what = format!("offer {offer:?}, allow {allow:?}, accept {via_accept}");
                    let (mut client, mut server, caddr, saddr) =
                        handshake_with_features(offer, allow, via_accept);
                    assert_eq!(client.features(), want, "{what}: client");
                    assert_eq!(server.features(), want, "{what}: server");
                    let header = Some(want.contains(Features::HEADER_AAD));
                    assert_eq!(client.keys_use_header_for_test(), header, "{what}");
                    assert_eq!(server.keys_use_header_for_test(), header, "{what}");
                    let now = Instant::now();
                    let _ = client.poll_events();
                    let out = server.send(now, 16, b"down");
                    deliver(&mut client, now, saddr, out);
                    assert_eq!(
                        collect_stream_data(&client.poll_events()),
                        b"down",
                        "{what}"
                    );
                    let _ = server.poll_events();
                    let out = client.send(now, 16, b"up");
                    deliver(&mut server, now, caddr, out);
                    assert_eq!(collect_stream_data(&server.poll_events()), b"up", "{what}");
                }
            }
        }
    }

    /// Spec §5.2: a msg2 that turns on what msg1 did not offer is a protocol
    /// violation. The client says so once and closes: reading msg2 spent its
    /// Noise state, so no later copy could be read either.
    #[test]
    fn a_msg2_enabling_what_was_not_offered_closes_the_connection() {
        for (offer, enabled) in [
            (Features::SUPPORTED, Features::from_bits(1 << 3)),
            (Features::NONE, Features::HEADER_AAD),
            (Features::SUPPORTED, Features::from_bits(1 << 30)),
        ] {
            let server_kp = generate_keypair();
            let client_kp = generate_keypair();
            let saddr = addr("198.51.100.1:41000");
            let mut client = Connection::new(ConnectionConfig {
                features: offer,
                role: Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            });
            let m1 = client.start_session(Instant::now(), saddr, StartKind::Cold, [5; 16]);
            let body = match parse(&m1[0].bytes) {
                Ok(Frame::Handshake { body, .. }) => body.to_vec(),
                _ => panic!("msg1"),
            };
            let mut responder = Handshake::new_responder(&server_kp.private);
            responder.read_msg(&body).expect("msg1 reads");
            let msg2 = responder.write_msg(&encode_msg2(9, false, &[0u8; AUTH_NONCE_LEN], enabled));
            let _ = client.on_datagram(
                Instant::now(),
                saddr,
                &encode_handshake(Kind::HandshakeResp, &msg2),
            );
            let events = client.poll_events();
            assert!(
                events.contains(&Event::UnofferedFeatureEnabled { enabled }),
                "{offer:?} / {enabled:?}: {events:?}"
            );
            assert!(!events.contains(&Event::HandshakeDone));
            assert_eq!(client.state(), LinkState::Closed);
        }
    }

    // Real Noise responders exercise the boundary between authentication and
    // payload parsing; all keys are freshly generated test-only identities.
    fn response_fixture(payload: &[u8]) -> (Connection, Vec<u8>, Instant, SocketAddr) {
        let server = generate_keypair();
        let client_key = generate_keypair();
        let peer = addr("198.51.100.1:41000");
        let now = Instant::now();
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let init = client.start_session(now, peer, StartKind::Cold, [5; 16]);
        let Frame::Handshake { body, .. } = parse(&init[0].bytes).unwrap() else {
            panic!("msg1");
        };
        let mut responder = Handshake::new_responder(&server.private);
        responder.read_msg(body).unwrap();
        let response = encode_handshake(Kind::HandshakeResp, &responder.write_msg(payload));
        client.poll_events();
        (client, response, now, peer)
    }

    #[test]
    fn authenticated_invalid_msg2_retires_attempt_without_flushing() {
        for (payload, reason) in [
            (vec![], HsPayloadError::BadVersion),
            (vec![2; 30], HsPayloadError::BadVersion),
            (vec![1; 8], HsPayloadError::TooShort),
        ] {
            let (mut client, response, now, peer) = response_fixture(&payload);
            assert!(client.send(now, 0, b"pending application data").is_empty());
            assert!(client.on_datagram(now, peer, &response).is_empty());
            assert_eq!(client.state(), LinkState::Closed);
            assert!(client.handshake.is_none());
            assert!(client.keys.is_none());
            let events = client.poll_events();
            assert_eq!(events.len(), 2, "one error and one Closed: {events:?}");
            assert_eq!(events[0], Event::InvalidHandshakeResponse { reason });
            assert_eq!(events[1], Event::StateChanged(LinkState::Closed));
            assert!(!events.contains(&Event::HandshakeDone));
            assert!(client.on_datagram(now, peer, &response).is_empty());
            assert!(client.on_timeout(now + Duration::from_secs(60)).is_empty());
            assert!(client.poll_events().is_empty());

            let (mut fresh, valid, now, peer) =
                response_fixture(&encode_msg2(9, false, &[0; AUTH_NONCE_LEN], Features::NONE));
            fresh.on_datagram(now, peer, &valid);
            assert_eq!(fresh.state(), LinkState::Live);
            assert!(fresh.poll_events().contains(&Event::HandshakeDone));
        }
    }

    #[test]
    fn authenticated_legacy_msg2_lengths_remain_accepted() {
        let full = encode_msg2(9, false, &[0; AUTH_NONCE_LEN], Features::NONE);
        for len in 9..=full.len() {
            let (mut client, response, now, peer) = response_fixture(&full[..len]);
            client.on_datagram(now, peer, &response);
            assert_eq!(client.state(), LinkState::Live, "payload length {len}");
            assert!(client.poll_events().contains(&Event::HandshakeDone));
        }
    }

    #[test]
    fn unauthenticated_msg2_does_not_poison_current_attempt() {
        for invalid_kind in 0..3 {
            let payload = encode_msg2(9, false, &[0; AUTH_NONCE_LEN], Features::NONE);
            let (mut client, valid, now, peer) = response_fixture(&payload);
            let mut invalid = valid.clone();
            match invalid_kind {
                0 => *invalid.last_mut().unwrap() ^= 1,
                1 => invalid.truncate(invalid.len() - 20),
                // A valid response from an unrelated responder/initiator pair.
                _ => invalid = response_fixture(&payload).1,
            }
            assert!(client.on_datagram(now, peer, &invalid).is_empty());
            assert_eq!(client.state(), LinkState::Connecting);
            assert!(client.poll_events().is_empty());
            client.on_datagram(now, peer, &valid);
            assert_eq!(client.state(), LinkState::Live, "case {invalid_kind}");
            assert!(client.poll_events().contains(&Event::HandshakeDone));
        }
    }

    /// Review of slice 3, minor 4: a msg1 built by hand may offer what this
    /// build does not implement (bit 3, reserved), but the client does not
    /// take a msg2 that enables it -- it offered only what it can do. What
    /// it implements still goes through.
    #[test]
    fn a_hand_built_msg1_offers_only_what_this_build_implements() {
        let unknown = Features::from_bits(1 << 30);
        let offered = Features::from_bits(
            Features::SUPPORTED.bits() | Features::from_bits(1 << 3).bits() | unknown.bits(),
        );
        for (enabled, live) in [
            (Features::from_bits(1 << 3), false),
            (unknown, false),
            (Features::HEADER_AAD, true),
        ] {
            let server_kp = generate_keypair();
            let client_kp = generate_keypair();
            let saddr = addr("198.51.100.1:41000");
            let mut client = Connection::new(ConnectionConfig {
                features: Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            });
            let payload = encode_msg1(&Msg1Payload {
                start_kind: StartKind::Cold,
                token: [5; 16],
                method: AuthMethod::Allowlist,
                offered,
            });
            let m1 = client.start_with_payload(Instant::now(), saddr, &payload);
            let body = match parse(&m1[0].bytes) {
                Ok(Frame::Handshake { body, .. }) => body.to_vec(),
                _ => panic!("msg1"),
            };
            let mut responder = Handshake::new_responder(&server_kp.private);
            let read = responder.read_msg(&body).expect("msg1 reads");
            assert_eq!(offered_in(&read), offered, "the bytes offer it all");
            let msg2 = responder.write_msg(&encode_msg2(9, false, &[0u8; AUTH_NONCE_LEN], enabled));
            let _ = client.on_datagram(
                Instant::now(),
                saddr,
                &encode_handshake(Kind::HandshakeResp, &msg2),
            );
            let events = client.poll_events();
            if live {
                assert_eq!(client.state(), LinkState::Live, "{enabled:?}");
                assert_eq!(client.features(), enabled);
            } else {
                assert!(
                    events.contains(&Event::UnofferedFeatureEnabled { enabled }),
                    "{enabled:?}: {events:?}"
                );
                assert_eq!(client.state(), LinkState::Closed, "{enabled:?}");
            }
        }
    }

    /// What a client offers is what its msg1 said -- `start` (no payload)
    /// offers nothing, whatever its configuration.
    #[test]
    fn a_client_started_without_a_payload_offers_nothing() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });
        let now = Instant::now();
        let m1 = client.start(now, saddr);
        let m2 = server.on_datagram(now, caddr, &m1[0].bytes);
        deliver(&mut client, now, saddr, m2);
        assert_eq!(client.state(), LinkState::Live);
        assert_eq!(client.features(), Features::NONE);
        assert_eq!(server.features(), Features::NONE);
    }

    /// Spec §5.2: what a msg1 payload offers is its `offered` field; one
    /// that does not parse, or predates the field, offers nothing.
    #[test]
    fn a_payload_offers_what_it_says_and_an_unreadable_one_nothing() {
        let payload = Msg1Payload {
            start_kind: StartKind::Cold,
            token: [2; 16],
            method: AuthMethod::Allowlist,
            offered: Features::SUPPORTED,
        };
        assert_eq!(offered_in(&encode_msg1(&payload)), Features::SUPPORTED);
        assert_eq!(
            offered_in(&encode_msg1_without_tail(&payload)),
            Features::NONE
        );
        assert_eq!(offered_in(&[]), Features::NONE);
        assert_eq!(offered_in(&[0x7f; 23]), Features::NONE);
    }

    /// Spec §9.3: a server that plays a build from before negotiation writes
    /// the 26-byte msg2; a new client reads it as "nothing enabled" and the
    /// two talk in the old mode.
    #[test]
    fn a_new_client_falls_back_to_the_old_mode_with_an_old_server() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });
        server.act_as_legacy_peer_for_test();
        let now = Instant::now();
        let m1 = client.start_session(now, saddr, StartKind::Cold, [1; 16]);
        let m2 = server.on_datagram(now, caddr, &m1[0].bytes);
        // IK's msg2 is the responder's ephemeral key and the sealed payload:
        // 32 + 26 + 16 bytes, no features field.
        match parse(&m2[0].bytes) {
            Ok(Frame::Handshake { body, .. }) => assert_eq!(body.len(), 32 + 26 + 16),
            _ => panic!("msg2"),
        }
        deliver(&mut client, now, saddr, m2);
        assert_eq!(client.state(), LinkState::Live);
        assert_eq!(client.features(), Features::NONE);
        assert_eq!(server.features(), Features::NONE);
        assert_eq!(client.keys_use_header_for_test(), Some(false));
        let _ = client.poll_events();
        let out = server.send(now, 16, b"old mode");
        deliver(&mut client, now, saddr, out);
        assert_eq!(collect_stream_data(&client.poll_events()), b"old mode");
    }

    #[test]
    fn client_server_stream_echo() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = Instant::now();
        // Client sends, server echoes StreamData back.
        let out = client.send(now, 0, b"ping");
        deliver(&mut server, now, caddr, out);
        for ev in server.poll_events() {
            if let Event::StreamData { stream_id, data } = ev {
                let back = server.send(now, stream_id, &data);
                deliver(&mut client, now, saddr, back);
            }
        }
        let got = collect_stream_data(&client.poll_events());
        assert_eq!(got, b"ping");
    }

    #[test]
    fn server_rehomes_on_source_change_midstream() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = Instant::now();
        // First packet from the original address.
        deliver(&mut server, now, caddr, client.send(now, 0, b"a"));
        assert_eq!(server.peer(), Some(caddr));

        // The client "changed networks": the same Connection (same counter stream), new src.
        let caddr2 = addr("203.0.113.9:55000");
        let out = client.send(now, 0, b"b");
        deliver_from(&mut server, now, caddr2, out);

        assert_eq!(server.peer(), Some(caddr2));
        let events = server.poll_events();
        assert!(events.iter().any(|e| matches!(e, Event::Rehomed { .. })));
        let data = collect_stream_data(&events);
        assert_eq!(data, b"ab");

        // The server's response is now addressed to the new src.
        let reply = server.send(now, 0, b"ok");
        assert_eq!(reply[0].to, caddr2);
    }

    /// The rule the whole feature rests on: a packet carrying nothing but a
    /// path check is answered, but does not move the session. Without this,
    /// checking a backup road would drag the live traffic onto it -- the
    /// roaming machinery cannot tell the two apart by itself.
    #[test]
    fn a_probing_packet_from_a_new_address_is_answered_without_moving_the_session() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = Instant::now();
        assert_eq!(server.peer(), Some(caddr));

        // The client checks a second road: same session, new source address.
        let other: SocketAddr = "203.0.113.7:9999".parse().expect("a literal address");
        let mut probe_out = Vec::new();
        client.emit_frames_to(
            other,
            vec![StreamFrame::PathProbe { token: 5 }],
            &mut probe_out,
        );
        let probe = probe_out.pop().expect("the probe is a datagram");
        let answer = server.on_datagram(now, other, &probe.bytes);

        assert_eq!(
            server.peer(),
            Some(caddr),
            "a path check must not move the session: the live road is unchanged"
        );
        assert!(
            !answer.is_empty(),
            "a path check must be answered, or no road could ever be verified"
        );
        assert_eq!(
            answer[0].to, other,
            "the answer goes back the way the check came, not to the live road"
        );
    }

    /// The guard against over-fixing: ordinary traffic from a new address
    /// still moves the session. That is roaming, and it must keep working.
    #[test]
    fn an_ordinary_packet_from_a_new_address_still_moves_the_session() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = Instant::now();
        assert_eq!(server.peer(), Some(caddr));

        let moved: SocketAddr = "203.0.113.8:9999".parse().expect("a literal address");
        let data = client.send(now, 0, b"hello");
        let dg = data
            .into_iter()
            .next()
            .expect("data goes out as a datagram");
        let _ = server.on_datagram(now, moved, &dg.bytes);

        assert_eq!(
            server.peer(),
            Some(moved),
            "an authenticated packet with real traffic in it is a roam, as before"
        );
    }

    #[test]
    fn stale_in_window_packet_from_old_addr_does_not_rehome_back() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = Instant::now();
        // Three client datagrams with counter 1, 2, 3: with the same `now`
        // there are no retransmits -- each send yields exactly one new data
        // frame with a fresh counter.
        let b1 = client.send(now, 0, b"a");
        let b2 = client.send(now, 0, b"b");
        let b3 = client.send(now, 0, b"c");

        // counter=1 from the original address: peer is pinned to caddr, window max = 1.
        deliver(&mut server, now, caddr, b1);
        assert_eq!(server.peer(), Some(caddr));
        let _ = server.poll_events();

        // counter=3 from a new address is a NEW max -- genuine roaming:
        // migrate to caddr2 and emit a Rehomed event.
        let caddr2 = addr("203.0.113.9:55000");
        deliver_from(&mut server, now, caddr2, b3);
        assert_eq!(server.peer(), Some(caddr2));
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::Rehomed { .. })));

        // counter=2 from the OLD address: within the window and not yet seen
        // (accept will pass, data will be delivered), but NOT a new max --
        // migration back must not happen.
        deliver(&mut server, now, caddr, b2);
        assert_eq!(
            server.peer(),
            Some(caddr2),
            "a late packet from the old address must not roll the peer back"
        );
        let events = server.poll_events();
        assert!(
            !events.iter().any(|e| matches!(e, Event::Rehomed { .. })),
            "there must not be a second Rehomed for a late fresh-in-window packet"
        );
        // The data is still delivered regardless (accept of a
        // fresh-in-window counter is unchanged): b, plus the earlier-held c,
        // assemble in order -> "bc".
        assert_eq!(collect_stream_data(&events), b"bc");
    }

    #[test]
    fn keepalive_and_path_down() {
        let (mut client, _server, _c, _s) = established_pair();
        let mut now = Instant::now();
        // While idle, the client sends a PING per next_timeout.
        now += Duration::from_millis(1600);
        let pings = client.on_timeout(now);
        assert!(!pings.is_empty());
        // 1.6 s elapsed -- less than PATH_DOWN_AFTER (3 s), the path is still Live.
        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))),
            "the path should remain Live before PATH_DOWN_AFTER elapses"
        );
        // No responses for another 2 s (3.6 s total, past the 3 s threshold)
        // -- state is PathDown, not Closed (DEATH_AFTER=45 s is far off).
        now += Duration::from_secs(2);
        let _ = client.on_timeout(now);
        assert!(client
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))));
    }

    /// A client that would rather wait out a long outage on the same
    /// connection can: a link that goes quiet for ten minutes is still there
    /// when the network comes back, not closed at three quarters of a
    /// minute. Both real clients keep the short default -- for them a dead
    /// link is the cue to reconnect, and waiting would delay the repair --
    /// so this has to be per-connection, not a new constant.
    #[test]
    fn a_client_can_be_told_to_wait_out_a_long_outage() {
        let (mut patient, _server, _c, _s) = established_pair();
        patient.set_death_after(Duration::from_secs(2 * 60 * 60));
        let (mut default_client, _server2, _c2, _s2) = established_pair();

        let start = Instant::now();
        let ten_minutes = start + Duration::from_secs(600);
        let _ = patient.on_timeout(ten_minutes);
        let _ = default_client.on_timeout(ten_minutes);

        assert!(
            !matches!(patient.state, LinkState::Closed),
            "a client told to wait must still be alive after ten minutes of silence"
        );
        assert!(
            matches!(default_client.state, LinkState::Closed),
            "the default is still short: this is a per-connection choice, not a new global"
        );

        // And the long wait is a wait, not forever.
        let _ = patient.on_timeout(start + Duration::from_secs(3 * 60 * 60));
        assert!(
            matches!(patient.state, LinkState::Closed),
            "past its own deadline even a patient client gives up"
        );
    }

    /// Once the path has been down a while, PINGs slow down. At the lively
    /// rate a client waiting out an hours-long outage would wake up thousands
    /// of times for a peer that is not listening -- and so would the server,
    /// which tolerates silence for a day.
    #[test]
    fn pings_slow_down_once_the_path_has_been_down_a_while() {
        let (mut client, _server, _c, _s) = established_pair();
        // The two go together: only a connection willing to wait out a long
        // outage is still around to ping through one. With the short default
        // this client would be closed before the backoff could matter.
        client.set_death_after(Duration::from_secs(2 * 60 * 60));
        let start = Instant::now();

        // Down, but only just: still the lively rate.
        let just_down = start + PATH_DOWN_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(just_down);
        assert!(matches!(client.state, LinkState::PathDown));
        let next = client
            .next_timeout()
            .expect("a live connection waits for something");
        assert!(
            next <= just_down + PING_INTERVAL,
            "a path that just went down is still worth asking about often"
        );

        // A minute of silence later: the slow rate.
        let long_down = start + PING_BACKOFF_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(long_down);
        let next = client
            .next_timeout()
            .expect("a connection waiting out an outage still has a deadline");
        assert!(
            next > long_down + PING_INTERVAL,
            "after a minute of silence the next PING must not be due in a second and a half"
        );
    }

    #[test]
    fn ping_fires_under_continuous_send() {
        let (mut client, _server, _c, _s) = established_pair();
        let mut now = Instant::now();
        // Continuous sending: push data every 250 ms (like an on-screen debug
        // counter). Every send moved the since-removed last_send, so under the
        // old condition (send idle time) PING would never fire. The new
        // condition is time since the last PING, so within 2.5 s
        // (> PING_INTERVAL ~1.5 s) PING must fire.
        for _ in 0..10 {
            now += Duration::from_millis(250);
            let _ = client.send(now, 0, b"x");
            let _ = client.on_timeout(now);
        }
        assert!(
            !client.outstanding_pings.is_empty(),
            "PING must fire once PING_INTERVAL elapses even under continuous sending"
        );
    }

    #[test]
    fn request_ping_forces_immediate_ping() {
        let (mut client, _server, _c, _s) = established_pair();
        let now = Instant::now();
        // Without forcing and without idle time, PING wouldn't fire at this same `now`.
        assert!(client.on_timeout(now).is_empty());
        assert!(client.outstanding_pings.is_empty());
        // Forced request (as on rebind) -- the next on_timeout sends PING
        // immediately.
        client.request_ping(now);
        let out = client.on_timeout(now);
        assert!(!out.is_empty(), "forced PING must fire immediately");
        assert!(!client.outstanding_pings.is_empty());
    }

    #[test]
    fn server_keeps_silent_session_alive_far_past_client_death() {
        let (mut client, mut server, _c, _s) = established_pair();
        let two_min = Instant::now() + Duration::from_secs(120);
        // The client (short death window) declares the link dead after
        // CLIENT_DEATH_AFTER of silence.
        let _ = client.on_timeout(two_min);
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "client link dies after CLIENT_DEATH_AFTER of silence"
        );
        // The server keeps the session alive for a day so a returning client
        // can hot-roam to it -- 2 min of silence must NOT close it.
        let _ = server.on_timeout(two_min);
        assert!(
            !server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "server session must survive far past the client death window"
        );
    }

    #[test]
    fn request_ping_restarts_the_liveness_window() {
        let (mut client, _server, _c, _s) = established_pair();
        let start = Instant::now();
        // A Doze/freeze of 2 minutes -- way past CLIENT_DEATH_AFTER. As the
        // driver does on a freeze wake, request_ping restarts the window at
        // `resume`; the frozen gap must not be counted as death.
        let resume = start + Duration::from_secs(120);
        client.request_ping(resume);
        let out = client.on_timeout(resume);
        let events = client.poll_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "a freeze gap must not close the link once request_ping restarts the window"
        );
        // The other liveness clock has to restart too. `PATH_DOWN_AFTER`
        // reads `last_recv_ordinary`, so leaving that one stale makes every
        // wake from Doze and every `Command::Rebind` -- which the app sends
        // on each return to the foreground and on each network change --
        // trip `PathDown` on the very next tick, and the app paints
        // "connection temporarily lost" for a round trip over nothing.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))),
            "a freeze gap must not look like the road in use had gone quiet either"
        );
        assert!(!out.is_empty(), "the forced PING must go out on resume");
        // Only genuine silence AFTER the reset, past a fresh death window,
        // still closes the link.
        let _ = client.on_timeout(resume + Duration::from_secs(46));
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "after the reset, genuine silence past the death window still closes the link"
        );
    }

    /// A forced ping is what a rebind and a wake from a freeze do, and neither
    /// is evidence about the road: the "the check went unanswered" flag must
    /// not survive it, or the spare roads get an urgent round for nothing.
    #[test]
    fn a_forced_ping_clears_the_unanswered_mark() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();
        // Two ping intervals with no answer: the second minting sets the mark.
        let _ = client.on_timeout(start + PING_INTERVAL + Duration::from_millis(1));
        let _ = client.on_timeout(start + PING_INTERVAL * 2 + Duration::from_millis(2));
        assert!(
            client.ping_unanswered,
            "two unanswered intervals set the mark"
        );

        let resume = start + PING_INTERVAL * 2 + Duration::from_millis(3);
        client.request_ping(resume);

        assert!(
            !client.ping_unanswered,
            "a freeze gap is not a road going unanswered"
        );

        // And it must still be clear one tick later. The forced PING is minted in
        // `on_timeout`, which the driver calls right after `request_ping` on the rebind path
        // and reaches in the same loop iteration on a freeze resume -- so a mark that comes
        // straight back when the forced ping finds an older one still outstanding is a mark
        // that was never cleared at all.
        let _ = client.on_timeout(resume);

        assert!(
            !client.ping_unanswered,
            "minting the forced ping must not put the mark straight back"
        );
    }

    #[test]
    fn server_rejects_unknown_client() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        // The server's allowlist doesn't have the client's key -- only someone else's.
        let allowed_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![allowed_kp.public]),
        });

        let now = Instant::now();
        let m1 = client.start_session(now, saddr, StartKind::Cold, [0; 16]);
        // The server reads msg1, doesn't find the client in the allowlist, and closes.
        let mut resp = Vec::new();
        for dg in m1 {
            resp.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        // The server doesn't send a response (msg2).
        assert!(resp.is_empty());
        // The server transitioned to Closed and delivered no data.
        let events = server.poll_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))));
        assert!(collect_stream_data(&events).is_empty());
        // The peer is never remembered: peer is not set before the allowlist check.
        assert_eq!(server.peer(), None);
    }

    #[test]
    fn send_before_live_is_flushed() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });

        let now = Instant::now();
        // Send BEFORE the handshake: bytes accumulate, no datagrams.
        assert!(client.send(now, 0, b"hel").is_empty());
        let m1 = client.start_session(now, saddr, StartKind::Cold, [0; 16]);
        // Another chunk, still before Live -- also queued.
        assert!(client.send(now, 0, b"lo").is_empty());

        // The server replies with msg2.
        let mut m2 = Vec::new();
        for dg in m1 {
            m2.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        // The client completes the handshake and flushes the accumulated data on the transition to Live.
        let mut flushed = Vec::new();
        for dg in m2 {
            flushed.extend(client.on_datagram(now, saddr, &dg.bytes));
        }
        assert!(!flushed.is_empty());
        deliver(&mut server, now, caddr, flushed);

        let got = collect_stream_data(&server.poll_events());
        assert_eq!(got, b"hello");
    }

    /// One server-side `accept()` of a fresh Warm, allowlisted client: a
    /// client keypair on the server's allowlist, a Warm msg1 carrying a
    /// token, and the server's answer, with `nonce` passed straight through
    /// to `accept` -- freshness is the caller's job now (see `accept`'s own
    /// docs), so this helper takes whatever the test wants to hand it rather
    /// than minting one itself. The one way this module raises a handshake
    /// for `accept` to answer, shared by `accept_ok_surfaces_key_and_payload`
    /// and `accept_returns_exactly_the_nonce_it_was_handed` so neither
    /// duplicates it.
    fn accept_one_handshake(nonce: [u8; AUTH_NONCE_LEN]) -> (AcceptOutcome, [u8; 32], SocketAddr) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        // Build a client msg1 with a token payload (mirror what FFI will send).
        let mut ini = Handshake::new_initiator(&client_kp.private, &server_kp.public);
        let payload =
            crate::handshake_payload::encode_msg1(&crate::handshake_payload::Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Warm,
                token: [3u8; 16],
                method: AuthMethod::Allowlist,
            });
        let m1_body = ini.write_msg(&payload);
        let cfg = ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        };
        let outcome = Connection::accept(cfg, Instant::now(), caddr, &m1_body, &mut |_| {
            Some(Msg2Inputs {
                resumed: false,
                nonce,
            })
        });
        (outcome, client_kp.public, caddr)
    }

    #[test]
    fn accept_ok_surfaces_key_and_payload() {
        let (outcome, client_pub, caddr) = accept_one_handshake([0u8; AUTH_NONCE_LEN]);
        match outcome {
            AcceptOutcome::Accepted {
                conn,
                client_key,
                msg1,
                out,
                nonce: _,
            } => {
                assert_eq!(client_key, client_pub);
                assert_eq!(msg1.token, [3u8; 16]);
                assert_eq!(msg1.start_kind, StartKind::Warm);
                assert!(conn.session_id() != 0 || conn.session_id() == 0); // just exists
                assert_eq!(out.len(), 1); // msg2
                assert_eq!(conn.peer(), Some(caddr));
            }
            AcceptOutcome::Rejected => panic!("should accept allowlisted client"),
        }
    }

    /// `accept` no longer mints the nonce itself -- freshness across
    /// handshakes is now the CALLER's job (a `NonceSource`, asked once per
    /// handshake by the session manager). What `accept` still owes is
    /// fidelity: whatever nonce it is handed must come back out of
    /// `AcceptOutcome::Accepted` UNCHANGED, since that is what lands in
    /// msg2 for the client to read back. Proven with several different
    /// nonces, not one, so a bug that happened to match on a single value
    /// (e.g. all-zero) would not hide behind it.
    #[test]
    fn accept_returns_exactly_the_nonce_it_was_handed() {
        for seed in 0u8..8 {
            let nonce = [seed; AUTH_NONCE_LEN];
            let (outcome, _client_pub, _caddr) = accept_one_handshake(nonce);
            let AcceptOutcome::Accepted { nonce: got, .. } = outcome else {
                panic!("the handshake must be accepted");
            };
            assert_eq!(got, nonce, "accept must not alter the nonce it was given");
        }
    }

    /// The `resolve` hook may refuse a handshake on its own (e.g. its owner
    /// could not obtain a nonce) -- `accept` must honor that exactly like
    /// every other rejection: no msg2, no peer recorded, nothing advanced.
    #[test]
    fn accept_honors_a_refusal_from_the_resolve_hook() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40002");
        let mut ini = Handshake::new_initiator(&client_kp.private, &server_kp.public);
        let payload =
            crate::handshake_payload::encode_msg1(&crate::handshake_payload::Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Warm,
                token: [4u8; 16],
                method: AuthMethod::Allowlist,
            });
        let m1_body = ini.write_msg(&payload);
        let cfg = ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        };
        let outcome = Connection::accept(cfg, Instant::now(), caddr, &m1_body, &mut |_| None);
        assert!(
            matches!(outcome, AcceptOutcome::Rejected),
            "a refusal from resolve must reject the whole handshake"
        );
    }

    /// Under the signature policy the server accepts a static key it has never
    /// seen -- the client's identity is proven later, by the auth gate. Under
    /// the allowlist policy the same client is rejected outright, exactly as
    /// before this field existed.
    #[test]
    fn signature_policy_accepts_an_unknown_static_key() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:9100".parse().unwrap();

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        });
        let msg1_payload = crate::handshake_payload::encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [0u8; 16],
            method: AuthMethod::SshSignature,
        });
        let out = client.start_with_payload(now, peer, &msg1_payload);
        let msg1 = match parse(&out[0].bytes).expect("valid frame") {
            Frame::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected a handshake datagram"),
        };

        let accepted = Connection::accept(
            ConnectionConfig {
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::SshSignature,
            },
            now,
            peer,
            &msg1,
            &mut |_| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [0u8; AUTH_NONCE_LEN],
                })
            },
        );
        assert!(
            matches!(accepted, AcceptOutcome::Accepted { .. }),
            "an unknown key is fine under the signature policy"
        );

        let rejected = Connection::accept(
            ConnectionConfig {
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            now,
            peer,
            &msg1,
            &mut |_| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [0u8; AUTH_NONCE_LEN],
                })
            },
        );
        assert!(
            matches!(rejected, AcceptOutcome::Rejected),
            "an empty allowlist still rejects"
        );
    }

    /// The `on_datagram` handshake path REFUSES the signature policy outright,
    /// where `Connection::accept` accepts the very same msg1. That path has no
    /// probation stage behind it and never parses msg1's announced method, so
    /// admitting a signature client there would put it straight into `Live`
    /// with nothing ever checking its proof -- `admits` says `true` for every
    /// key under that policy on purpose.
    #[test]
    fn on_datagram_refuses_the_signature_policy() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let now = Instant::now();

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        });
        let msg1_payload = crate::handshake_payload::encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [0u8; 16],
            method: AuthMethod::SshSignature,
        });
        let m1 = client.start_with_payload(now, saddr, &msg1_payload);
        let msg1_body = match parse(&m1[0].bytes).expect("valid frame") {
            Frame::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected a handshake datagram"),
        };

        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::SshSignature,
        });
        let mut resp = Vec::new();
        for dg in &m1 {
            resp.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        assert!(
            resp.is_empty(),
            "no msg2 from an entry point that cannot enforce this policy"
        );
        assert!(
            server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "the connection is closed, not left half-open and unauthenticated"
        );
        assert_eq!(
            server.peer(),
            None,
            "a refused handshake leaves nothing about the peer recorded"
        );

        // The SAME msg1, through the gated entry point, is accepted: what was
        // refused above is the entry point, not this client.
        assert!(
            matches!(
                Connection::accept(
                    ConnectionConfig {
                        features: crate::Features::SUPPORTED,
                        role: Role::Server,
                        local_static_priv: server_kp.private,
                        remote_static_pub: None,
                        auth: AuthPolicy::SshSignature,
                    },
                    now,
                    caddr,
                    &msg1_body,
                    &mut |_| {
                        Some(Msg2Inputs {
                            resumed: false,
                            nonce: [0u8; AUTH_NONCE_LEN],
                        })
                    },
                ),
                AcceptOutcome::Accepted { .. }
            ),
            "`accept` -- which the probation stage guards -- still admits it"
        );
    }

    /// A client whose static key IS on the allowlist is still rejected if it
    /// announces the wrong method: silently downgrading a signature client to
    /// the allowlist path (or the other way round) would leave one side
    /// thinking it authenticated when it didn't.
    #[test]
    fn accept_rejects_a_key_that_announces_the_wrong_method() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:9200".parse().unwrap();

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        });
        // The client's key IS on the server's allowlist, but the client
        // announces `SshSignature` while the server runs `Allowlist`.
        let msg1_payload = crate::handshake_payload::encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [0u8; 16],
            method: AuthMethod::SshSignature,
        });
        let out = client.start_with_payload(now, peer, &msg1_payload);
        let msg1 = match parse(&out[0].bytes).expect("valid frame") {
            Frame::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected a handshake datagram"),
        };

        let outcome = Connection::accept(
            ConnectionConfig {
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            },
            now,
            peer,
            &msg1,
            &mut |_| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [0u8; AUTH_NONCE_LEN],
                })
            },
        );
        assert!(
            matches!(outcome, AcceptOutcome::Rejected),
            "an allowlisted key announcing the wrong method must still be rejected"
        );
    }

    /// The connection keeps the handshake hash after the handshake is gone:
    /// the auth gate needs it long after `into_transport` consumed the state,
    /// and the client must be able to sign the same value the server checks.
    #[test]
    fn both_ends_keep_the_same_handshake_hash() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let now = Instant::now();
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        // `Connection::accept` (unlike `on_handshake_init`) parses the versioned
        // msg1 payload, so the plain no-payload `start` doesn't fit here -- send
        // a real one, as a fresh client normally would.
        let msg1_payload =
            crate::handshake_payload::encode_msg1(&crate::handshake_payload::Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Cold,
                token: [0u8; 16],
                method: AuthMethod::Allowlist,
            });
        let out = client.start_with_payload(now, peer, &msg1_payload);
        let msg1 = match parse(&out[0].bytes).expect("valid frame") {
            Frame::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected a handshake datagram"),
        };

        let accepted = Connection::accept(
            ConnectionConfig {
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            },
            now,
            peer,
            &msg1,
            &mut |_| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [42u8; AUTH_NONCE_LEN],
                })
            },
        );
        let (server, msg2, server_nonce) = match accepted {
            AcceptOutcome::Accepted {
                conn, out, nonce, ..
            } => (conn, out[0].bytes.clone(), nonce),
            AcceptOutcome::Rejected => panic!("the allowlisted client must be accepted"),
        };
        client.on_datagram(now, peer, &msg2);

        assert_ne!(server.handshake_hash(), [0u8; 32], "the hash is recorded");
        assert_eq!(
            client.handshake_hash(),
            server.handshake_hash(),
            "client and server must agree on what gets signed"
        );
        assert_eq!(
            client.server_nonce(),
            Some(server_nonce),
            "the client must read back exactly the nonce the server issued"
        );
    }

    #[test]
    fn received_close_marks_graceful() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = Instant::now();
        // The client gracefully closes: it emits a Close frame to the server.
        let close = client.close(now);
        assert!(!close.is_empty(), "close must emit a Close datagram");
        deliver(&mut server, now, caddr, close);
        // The server saw the Close: it is Closed AND flags the close as graceful.
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))));
        assert!(
            server.closed_gracefully(),
            "a received Close must mark the connection gracefully closed"
        );
        // The closing client also flags itself gracefully closed.
        assert!(client.closed_gracefully());
    }

    #[test]
    fn death_timeout_is_not_graceful() {
        let (_client, mut server, _caddr, _saddr) = established_pair();
        // No authenticated traffic for the server death window: the liveness
        // timeout closes the connection. This is an UNEXPECTED death, not a
        // graceful Close.
        let start = Instant::now();
        let _ = server.on_timeout(start + SERVER_DEATH_AFTER);
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))));
        assert!(
            !server.closed_gracefully(),
            "a death-timeout close must NOT be marked graceful"
        );
    }

    #[test]
    fn accept_rejects_unknown_key() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let other = generate_keypair();
        let mut ini = Handshake::new_initiator(&client_kp.private, &server_kp.public);
        let m1 = ini.write_msg(&crate::handshake_payload::encode_msg1(
            &crate::handshake_payload::Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: StartKind::Cold,
                token: [0u8; 16],
                method: AuthMethod::Allowlist,
            },
        ));
        let cfg = ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![other.public]),
        };
        assert!(matches!(
            Connection::accept(cfg, Instant::now(), addr("1.2.3.4:5"), &m1, &mut |_| {
                Some(Msg2Inputs {
                    resumed: false,
                    nonce: [0u8; AUTH_NONCE_LEN],
                })
            }),
            AcceptOutcome::Rejected
        ));
    }

    #[test]
    fn idle_duration_grows_since_last_auth_recv() {
        let (_c, server, _caddr, _saddr) = established_pair();
        let now = Instant::now();
        // A fresh authenticated recv (from established_pair) resets the idle clock.
        assert!(server.idle_duration(now) < Duration::from_millis(50));
        // 7 seconds later, idle_duration should be >= 7 seconds.
        assert!(server.idle_duration(now + Duration::from_secs(7)) >= Duration::from_secs(7));
    }

    /// The silence a person will read in the header is the silence the
    /// transport judges the road in use by: ordinary traffic resets it, and
    /// an answered path check -- which proves only that somebody is home --
    /// does not.
    #[test]
    fn only_ordinary_traffic_resets_the_silence() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let start = Instant::now();
        deliver(&mut server, start, caddr, client.send(start, 0, b"a"));
        assert_eq!(
            server.stats(start).silent_secs,
            0,
            "an ordinary frame just arrived"
        );

        // Five seconds of nothing.
        let quiet = start + Duration::from_secs(5);
        assert_eq!(server.stats(quiet).silent_secs, 5);

        // A path check arrives. It refreshes the peer's liveness -- the
        // client is plainly alive -- but says nothing about this road.
        //
        // Minted at `start`, delivered at `quiet`: at `start` neither the
        // unacked "a" segment's retransmit nor the periodic keepalive PING is
        // due yet, so `on_timeout` here hands back exactly one datagram, the
        // check -- what arrives five seconds later is that check and nothing
        // else, which is the only way to isolate its effect from the
        // keepalive traffic `on_timeout` would otherwise mix in for free.
        client.set_paths(vec![saddr]);
        let probes = client.on_timeout(start);
        deliver(&mut server, quiet, caddr, probes);
        assert_eq!(
            server.stats(quiet).silent_secs,
            5,
            "a check is not traffic: the road is as quiet as it was"
        );

        // Ordinary traffic again, and the count starts over.
        let back = quiet + Duration::from_secs(1);
        deliver(&mut server, back, caddr, client.send(back, 0, b"b"));
        assert_eq!(server.stats(back).silent_secs, 0);
    }

    /// Whole seconds, not milliseconds. The driver publishes statistics only
    /// when they change, so a value that moves every millisecond would fire a
    /// report on every turn of its loop -- for every consumer at once.
    #[test]
    fn the_silence_moves_once_a_second() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let start = Instant::now();
        deliver(&mut server, start, caddr, client.send(start, 0, b"a"));

        assert_eq!(
            server.stats(start + Duration::from_millis(900)).silent_secs,
            0
        );
        assert_eq!(
            server
                .stats(start + Duration::from_millis(1_100))
                .silent_secs,
            1
        );
        assert_eq!(
            server
                .stats(start + Duration::from_millis(1_900))
                .silent_secs,
            1
        );
    }

    /// The road in use is shown with the round trip this connection measured
    /// itself, not the one the path table smoothed out of its own checks.
    /// The two disagree by construction -- the table checks a road every
    /// `PROBE_IDLE` (30 s) and then moves its EWMA by a fifth of the
    /// difference, while a PING goes out every `PING_INTERVAL` (1.5 s) -- and
    /// the header on screen shows the PING one. A window quoting the table
    /// would sit on a number the header had already moved off, which is
    /// exactly what it looks like when somebody opens the window to find out
    /// why the connection feels slow.
    #[test]
    fn the_road_in_use_is_shown_with_the_connections_own_round_trip() {
        let (mut client, mut server, caddr, saddr) = established_pair_unmeasured();
        let start = Instant::now();
        client.set_paths(vec![saddr]);

        // A check goes out and is answered 300 ms later: the table now has a
        // measurement of its own, and no PING has been sent yet (one is due
        // `PING_INTERVAL` after the handshake, and this is the same instant),
        // so this is the only number anybody has.
        let answered = start + Duration::from_millis(300);
        let checks = client.on_timeout(start);
        let acks = deliver_and_collect(&mut server, start, caddr, checks);
        deliver(&mut client, answered, saddr, acks);
        assert_eq!(
            client.roads(answered)[0].ewma_ms,
            Some(300),
            "with no round trip of its own, the road falls back to the table's"
        );

        // A PING goes out and comes back in 20 ms. The check schedule has not
        // come round again (30 s), so the table still holds its 300.
        let pinged = answered + PING_INTERVAL + Duration::from_millis(1);
        let ponged = pinged + Duration::from_millis(20);
        let pings = client.on_timeout(pinged);
        let pongs = deliver_and_collect(&mut server, pinged, caddr, pings);
        deliver(&mut client, ponged, saddr, pongs);
        assert_eq!(client.stats(ponged).rtt_ms, 20, "the PING was answered");

        assert_eq!(
            client.roads(ponged)[0].ewma_ms,
            Some(20),
            "the road in use reports the round trip the header shows"
        );
        assert_eq!(
            client.paths.view(ponged)[0].ewma_ms,
            Some(300),
            "and the table keeps its own measurement, which is what ranks roads"
        );
    }

    /// Only the road in use. A spare has no PING of its own -- the connection
    /// measures the road it is on -- so putting this connection's round trip
    /// on every road would report the live road's speed three times over.
    #[test]
    fn a_spare_road_keeps_the_tables_measurement() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let start = Instant::now();
        let spare = addr("198.51.100.2:41000");
        client.set_paths(vec![saddr, spare]);

        // Both roads answer their first check, in 300 ms.
        let answered = start + Duration::from_millis(300);
        let checks = client.on_timeout(start);
        let acks = deliver_and_collect(&mut server, start, caddr, checks);
        deliver(&mut client, answered, saddr, acks);

        // And the connection measures 20 ms of its own.
        let pinged = answered + PING_INTERVAL + Duration::from_millis(1);
        let ponged = pinged + Duration::from_millis(20);
        let pings = client.on_timeout(pinged);
        let pongs = deliver_and_collect(&mut server, pinged, caddr, pings);
        deliver(&mut client, ponged, saddr, pongs);

        let view = client.roads(ponged);
        let of = |a: SocketAddr| view.iter().find(|r| r.addr == a).expect("road").ewma_ms;
        assert_eq!(of(saddr), Some(20), "the road in use");
        assert_eq!(of(spare), Some(300), "the spare, on the table's own number");
    }

    /// What `conn` holds for a ride and sends alone `ACK_DELAY` after `now`
    /// (spec §4.11): for the tests whose subject is not when an ACK goes,
    /// only that it does.
    fn held_acks(conn: &mut Connection, now: Instant) -> Vec<Datagram> {
        conn.on_timeout(now + ACK_DELAY)
    }

    /// Same as `deliver`, but returns the datagrams the connection emitted in
    /// response instead of discarding them.
    fn deliver_and_collect(
        conn: &mut Connection,
        now: Instant,
        src: SocketAddr,
        dgrams: Vec<Datagram>,
    ) -> Vec<Datagram> {
        let mut out = Vec::new();
        for dg in dgrams {
            out.extend(conn.on_datagram(now, src, &dg.bytes));
        }
        out
    }

    #[test]
    fn server_marks_output_desynced_after_long_absence_and_resyncs_on_return() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        // Server sends output; the client receives it, so its receiver offset
        // has advanced past zero before the desync (proves the reset actually
        // rewinds a live stream, not just an untouched one).
        let out = server.send(t0, 0, b"lots of htop frames");
        deliver(&mut client, t0, saddr, out);
        let _ = client.poll_events();

        // The client goes silent. Drive the server's timers past PATH_DOWN,
        // then past RESYNC_AFTER.
        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))));

        // More output is produced while the path stays down (e.g. ongoing PTY
        // frames) but never reaches the client -- the genuine gap the
        // desync/resync cycle exists to paper over with a repaint instead of
        // a replay. Without this, the write head would sit exactly where the
        // client already is and the Reset below would be a legitimate no-op
        // (see CRITICAL-1's forward-only `on_reset`).
        let _ = server.send(
            t0 + Duration::from_secs(5),
            0,
            b"more frames the client never sees",
        );

        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> desynced (no state event)
        let _ = server.poll_events();

        // The client returns: any authenticated packet flips PathDown -> Live
        // on the server.
        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);

        // The server queued an OutputResync event for the backend to repaint.
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::OutputResync)));

        // ...and a Reset frame actually reached the client: delivering the
        // server's response makes the client emit StreamReset.
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 0 })),
            "resume must send a stream Reset that reaches the client"
        );
    }

    /// A stream the session layer declared unrecoverable keeps its backlog
    /// through a long absence. Dropping it would be silent, permanent data
    /// loss: nothing upstream can redraw a line protocol from scratch.
    #[test]
    fn a_stream_declared_not_resyncable_is_never_desynced() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        server.set_stream_resyncable(17, false);
        let out = server.send(t0, 17, b"a control-mode line");
        deliver(&mut client, t0, saddr, out);
        let _ = client.poll_events();

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();
        let _ = server.send(
            t0 + Duration::from_secs(5),
            17,
            b"another line, never delivered",
        );
        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // past RESYNC_AFTER
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 17, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 17 })),
            "a stream the backend called unrecoverable must never be reset"
        );
    }

    /// A stream declared recoverable is desynced exactly as the output
    /// stream is -- the backend promised it can redraw from scratch.
    #[test]
    fn a_stream_declared_resyncable_is_desynced_like_the_output_stream() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        server.set_stream_resyncable(17, true);
        let out = server.send(t0, 17, b"bulk output");
        deliver(&mut client, t0, saddr, out);
        let _ = client.poll_events();

        let _ = server.on_timeout(t0 + Duration::from_secs(4));
        let _ = server.poll_events();
        let _ = server.send(
            t0 + Duration::from_secs(5),
            17,
            b"frames the client never sees",
        );
        let _ = server.on_timeout(t0 + Duration::from_secs(11));
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 17, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 17 })),
            "a stream the backend called recoverable must be reset on return"
        );
    }

    /// With nothing declared, the old single-product protocol behaves
    /// exactly as it always has: stream 0 drops, every other stream keeps
    /// its backlog. This test preserves compatibility for clients that do
    /// not send stream declarations.
    #[test]
    fn without_declarations_only_stream_zero_is_reset() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        for stream in [0u8, 1, 2, 17] {
            let out = server.send(t0, stream, b"payload");
            deliver(&mut client, t0, saddr, out);
        }
        let _ = client.poll_events();

        let _ = server.on_timeout(t0 + Duration::from_secs(4));
        let _ = server.poll_events();
        for stream in [0u8, 1, 2, 17] {
            let _ = server.send(t0 + Duration::from_secs(5), stream, b"never delivered");
        }
        let _ = server.on_timeout(t0 + Duration::from_secs(11));
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        let events = client.poll_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 0 })),
            "stream 0 is the old protocol's bulk output and must still reset"
        );
        for want in [1u8, 2, 17] {
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, Event::StreamReset { stream_id } if *stream_id == want)),
                "stream {want} must keep its backlog when nothing declared otherwise"
            );
        }
    }

    /// A channel's own stream, declared recoverable (the session layer's
    /// stand-in for "this channel has a screen model to redraw from"),
    /// desyncs and resyncs exactly like `OUTPUT_STREAM` always has. Same
    /// technique as
    /// `server_marks_output_desynced_after_long_absence_and_resyncs_on_return`,
    /// on stream 16 instead of 0, with the declaration `channel_server.rs`
    /// would make for a shell channel spelled out explicitly.
    #[test]
    fn a_channels_own_stream_desyncs_and_resyncs_just_like_output_stream_does() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        server.set_stream_resyncable(16, true);
        let out = server.send(t0, 16, b"shell output the client actually sees");
        deliver(&mut client, t0, saddr, out);
        let _ = client.poll_events();

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();

        // More output, produced while the path is down, that never reaches
        // the client -- the genuine gap the desync/resync cycle exists to
        // paper over with a repaint instead of a replay.
        let _ = server.send(
            t0 + Duration::from_secs(5),
            16,
            b"more shell output the client never sees",
        );

        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> desynced
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        assert!(
            server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::OutputResync)),
            "a channel's own stream desyncing must still queue exactly one repaint request"
        );

        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 16 })),
            "the Reset must land on the CHANNEL's own stream, not stream 0"
        );
    }

    /// The regression this test exists to pin down:
    /// the channel protocol's `CONTROL_STREAM` carries one-shot,
    /// order-critical records (`OPENED`/`REFUSED`/`EXIT`/`RESIZE`/`CLOSE`)
    /// that a repaint cannot regenerate -- unlike `OUTPUT_STREAM`, whose
    /// dropped backlog a repaint on return makes moot. It must therefore be
    /// immune to the RESYNC_AFTER desync/resync cycle, exactly like streams
    /// 2 and 15 above. `CONTROL_STREAM` used to be numbered 0, where it
    /// collided with `OUTPUT_STREAM` by coincidence (see that constant's own
    /// doc) and was treated as bulk output -- this test uses the symbolic
    /// constant precisely so it fails again the moment someone moves it back.
    #[test]
    fn channel_protocol_control_stream_is_never_desynced_after_long_absence() {
        use crate::channel::CONTROL_STREAM;

        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        let _ = server.send(t0, CONTROL_STREAM, b"a RESIZE record");

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();
        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> desync window
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        let _ = server.poll_events();
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        assert!(
            !client.poll_events().iter().any(|e| matches!(
                e,
                Event::StreamReset {
                    stream_id: CONTROL_STREAM
                }
            )),
            "the channel protocol's control stream must never see a Reset from the resync cycle"
        );

        // Its pre-absence backlog is still delivered in full on the next
        // retransmit -- proof the sender kept buffering it rather than
        // dropping it the way it drops `OUTPUT_STREAM`'s.
        let now2 = t0 + Duration::from_secs(12);
        let retrans = server.on_timeout(now2);
        deliver(&mut client, now2, saddr, retrans);
        assert_eq!(
            collect_stream_data_for(&client.poll_events(), CONTROL_STREAM),
            b"a RESIZE record",
            "the control stream's pre-absence backlog must survive the RESYNC_AFTER window intact"
        );
    }

    /// `crate::auth::AUTH_STREAM` (15) -- the boundary right below
    /// `FIRST_CHANNEL_STREAM` -- must never be desynced when nobody declares
    /// anything about it. Same technique as
    /// `resync_after_long_absence_leaves_a_non_output_stream_untouched`
    /// (which covers stream 1), on stream 15 instead: a boundary right next
    /// to the old channel-numbering range is exactly where a stray
    /// declaration would first show up.
    #[test]
    fn stream_15_the_auth_streams_number_is_never_desynced() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        let _ = server.send(t0, 15, b"auth-adjacent record");

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();
        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> desync window
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        let _ = server.poll_events();
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 15 })),
            "stream 15 must never see a Reset from the resync cycle"
        );

        let now2 = t0 + Duration::from_secs(12);
        let retrans = server.on_timeout(now2);
        deliver(&mut client, now2, saddr, retrans);
        assert_eq!(
            collect_stream_data_for(&client.poll_events(), 15),
            b"auth-adjacent record",
            "stream 15's pre-absence backlog must survive the RESYNC_AFTER window intact"
        );
    }

    /// Stream 2 carries tmux control events. Its consumer cannot reconstruct
    /// lost events from a terminal repaint, so resync must retain this stream
    /// instead of resetting it.
    #[test]
    fn stream_2_tmux_channel_bs_control_stream_is_never_desynced() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        let _ = server.send(t0, 2, b"%window-add @1");

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();
        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> desync window
        let _ = server.poll_events();

        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        let _ = server.poll_events();
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 2 })),
            "stream 2 (tmux channel B's control stream) must never see a Reset from the resync cycle -- \
             the control-stream consumer has no recovery path for one"
        );

        let now2 = t0 + Duration::from_secs(12);
        let retrans = server.on_timeout(now2);
        deliver(&mut client, now2, saddr, retrans);
        assert_eq!(
            collect_stream_data_for(&client.poll_events(), 2),
            b"%window-add @1",
            "stream 2's pre-absence backlog must survive the RESYNC_AFTER window intact"
        );
    }

    #[test]
    fn server_addresses_prompt_resync_reset_to_the_roamed_address() {
        // Regression: RESYNC_AFTER (10 s) is exactly the long-absence
        // scenario where a phone in Doze has also had its NAT UDP mapping
        // rebind, so the returning client's source address differs from the
        // pre-absence one. The prompt `flush_senders` inside the resync
        // block must address the Reset to the NEW (post-roam) address, not
        // the stale pre-absence `self.peer` -- otherwise it goes to a dead
        // address and only self-heals on the next retransmit, defeating the
        // "goes out promptly" point of the feature.
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let t0 = Instant::now();

        // Server sends output the client actually receives.
        let out = server.send(t0, 0, b"lots of htop frames");
        deliver(&mut client, t0, saddr, out);
        let _ = client.poll_events();

        // Client goes silent past PATH_DOWN, then past RESYNC_AFTER. More
        // output is produced in between but never reaches the client -- a
        // genuine gap (see the comment in
        // `server_marks_output_desynced_after_long_absence_and_resyncs_on_return`
        // for why this matters after CRITICAL-1's forward-only `on_reset`).
        let _ = server.on_timeout(t0 + Duration::from_secs(4));
        let _ = server.poll_events();
        let _ = server.send(
            t0 + Duration::from_secs(5),
            0,
            b"more frames the client never sees",
        );
        let _ = server.on_timeout(t0 + Duration::from_secs(11));
        let _ = server.poll_events();

        // The client returns from a DIFFERENT address -- a Doze/NAT rebind
        // while asleep, not the same source as before (_caddr).
        let caddr2 = addr("203.0.113.9:55000");
        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr2, ret);

        // The server rehomed to the new address and queued the resync.
        let events = server.poll_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Rehomed { peer } if *peer == caddr2)),
            "an authenticated packet from a new source must migrate the peer"
        );
        assert!(events.iter().any(|e| matches!(e, Event::OutputResync)));

        // Every datagram in the FIRST response batch -- the prompt flush
        // inside on_transport, not a later retransmit -- is addressed to the
        // NEW address, not the stale pre-absence one.
        assert!(!resp.is_empty(), "resume must produce a prompt response");
        assert!(
            resp.iter().all(|dg| dg.to == caddr2),
            "the prompt resync Reset must be addressed to the roamed-to address, not the stale one"
        );

        // Delivering exactly that first batch (as it would arrive over the
        // real network, from the new address) is already enough for the
        // client to see the Reset -- no need to wait for a later retransmit.
        deliver(&mut client, t0 + Duration::from_secs(11), caddr2, resp);
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 0 })),
            "the client must see StreamReset from the FIRST delivered response batch"
        );
    }

    #[test]
    fn client_receiving_reset_emits_stream_reset_event() {
        let (mut client, mut server, _c, saddr) = established_pair();
        let now = Instant::now();
        // Some output the client never sees, then a server-side desync+resync
        // (fabricated directly, without waiting out RESYNC_AFTER).
        let _ = server.send(now, 0, b"abc");
        server.mark_output_desynced_for_test();
        // The next send carries the armed Reset ahead of the repaint data.
        let out = server.send(now, 0, b"NOW");
        deliver(&mut client, now, saddr, out);

        let events = client.poll_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 0 })),
            "a received Reset must emit Event::StreamReset"
        );
        // The receiver jumped to the new offset: the repaint data ("NOW")
        // delivers immediately in the same batch, with no stall waiting for
        // the old 0..3 range.
        assert_eq!(collect_stream_data(&events), b"NOW");
    }

    #[test]
    fn resync_after_long_absence_leaves_a_non_output_stream_untouched() {
        // IMPORTANT-4: the RESYNC_AFTER desync/resync cycle must leave
        // streams 1 and 2 alone when nobody declares them recoverable (see
        // [`Connection::is_bulk_output_stream`] -- undeclared, only stream 0
        // resyncs; this test is about the streams it must NEVER touch).
        // Streams 1/2 carry small, order-critical control records (resize,
        // the channel A tty, tmux
        // `%window-add`/`%layout-change` notifications, ...); the client's
        // `TmuxEventsAdapter::on_reset` deliberately never resets them (it
        // early-returns for any `stream_id != 0`), so the SENDER must
        // never drop their backlog or arm a Reset for them either -- there
        // is no recovery path on the client side if it did.
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        // Data queued on the non-output stream 1 that never reaches the
        // client before it goes silent -- the same "genuine gap" setup used
        // by the output-stream desync tests above.
        let _ = server.send(t0, 1, b"control record");

        let _ = server.on_timeout(t0 + Duration::from_secs(4)); // -> PathDown
        let _ = server.poll_events();
        let _ = server.on_timeout(t0 + Duration::from_secs(11)); // -> output-stream desync window
        let _ = server.poll_events();

        // The client returns.
        let ret = client.send(t0 + Duration::from_secs(11), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(11), caddr, ret);
        let _ = server.poll_events();
        deliver(&mut client, t0 + Duration::from_secs(11), saddr, resp);

        // No Reset ever reaches the client on the non-output stream.
        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 1 })),
            "a non-output stream must never see a Reset from the output-stream resync"
        );

        // Its pre-absence backlog is still delivered in full on the next
        // retransmit -- proof the sender kept buffering it rather than
        // dropping it the way it drops `OUTPUT_STREAM`'s.
        let now2 = t0 + Duration::from_secs(12);
        let retrans = server.on_timeout(now2);
        deliver(&mut client, now2, saddr, retrans);
        assert_eq!(
            collect_stream_data_for(&client.poll_events(), 1),
            b"control record",
            "a non-output stream's backlog must survive the RESYNC_AFTER window intact"
        );
    }

    #[test]
    fn duplicate_reset_does_not_refire_stream_reset_event() {
        // IMPORTANT-5: the sender re-arms the same Reset on every flush
        // until it's acked (see `StreamSender::frames_to_send`), so a
        // repaint burst delivers several duplicates in a row. Only the
        // FIRST one that actually moves the receiver's point forward should
        // surface as `Event::StreamReset` -- re-running `ShellState::on_reset`
        // on every duplicate would re-create the prediction engine and kill
        // local echo exactly at resume.
        let (mut client, mut server, _c, saddr) = established_pair();
        let now = Instant::now();
        let _ = server.send(now, 0, b"abc");
        server.mark_output_desynced_for_test();

        // First flush: the Reset reaches the client and DOES move the
        // point -- Event::StreamReset fires once.
        let out1 = server.send(now, 0, b"NOW");
        deliver(&mut client, now, saddr, out1);
        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { stream_id: 0 })),
            "the first Reset that moves the point must fire StreamReset"
        );

        // The client's ack is never delivered back to the server (as in the
        // other Reset tests), so its `pending_reset` stays armed; a later
        // flush -- past RTO -- resends the SAME Reset, a legitimate
        // duplicate. It must not refire the event.
        let later = now + DEFAULT_RTO + Duration::from_millis(1);
        let out2 = server.send(later, 0, b"MORE");
        deliver(&mut client, later, saddr, out2);
        let events2 = client.poll_events();
        assert!(
            !events2
                .iter()
                .any(|e| matches!(e, Event::StreamReset { .. })),
            "a duplicate Reset that doesn't move the point must not refire StreamReset"
        );
        // The new data still delivers normally alongside the (suppressed)
        // duplicate Reset.
        assert_eq!(collect_stream_data(&events2), b"MORE");
    }

    #[test]
    fn short_interruption_before_resync_after_replays_seamlessly() {
        // IMPORTANT-6(a): an interruption SHORTER than RESYNC_AFTER must not
        // desync/resync at all -- this is the roaming case the project
        // fought hard for (instant WiFi<->mobile handoff): the buffered
        // pre-gap bytes replay in full, seamlessly, with no repaint and no
        // Reset.
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = Instant::now();

        // Output queued and sent while the client is unreachable (the
        // interruption starts here -- e.g. mid-handoff).
        let _ = server.send(t0, 0, b"htop frame during the gap");

        // Past PATH_DOWN (3 s)...
        let _ = server.on_timeout(t0 + Duration::from_secs(4));
        assert!(server
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))));

        // A real driver keeps ticking `on_timeout` on its own schedule while
        // the path is down, not just once -- simulate one more tick right
        // before the client returns, so this test actually exercises
        // whatever RESYNC_AFTER is configured to be, not just the single
        // fixed instant above.
        let _ = server.on_timeout(t0 + Duration::from_secs(5));
        let _ = server.poll_events();

        // ...but the client returns well before RESYNC_AFTER (10 s).
        let ret = client.send(t0 + Duration::from_secs(6), 0, b"x");
        let resp = deliver_and_collect(&mut server, t0 + Duration::from_secs(6), caddr, ret);

        // No resync on the server side: no OutputResync event.
        assert!(
            !server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::OutputResync)),
            "a short interruption under RESYNC_AFTER must not trigger a resync"
        );

        // The response to the client's return is the ACK for its packet and
        // the still-unacked pre-gap bytes with it: a return from `PathDown`
        // flushes at once instead of waiting for the next timer -- and they
        // arrive in full, seamlessly: no repaint, no jumped offset, no
        // dropped backlog.
        let acks = deliver_and_collect(&mut client, t0 + Duration::from_secs(6), saddr, resp);
        let events = client.poll_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::StreamReset { .. })),
            "a short interruption must not produce a stream Reset"
        );
        let mut seen = collect_stream_data(&events);
        assert_eq!(
            seen, b"htop frame during the gap",
            "the buffered pre-gap bytes must replay in full, not be dropped for a repaint"
        );
        deliver(&mut server, t0 + Duration::from_secs(6), caddr, acks);

        // And the stream carries on from exactly there: the next output
        // follows with no gap and no repeat, and a later timer -- which would
        // retransmit anything still unacknowledged -- neither resyncs nor
        // delivers anything twice.
        let more = server.send(t0 + Duration::from_millis(6100), 0, b" and after");
        deliver(&mut client, t0 + Duration::from_millis(6100), saddr, more);
        seen.extend(collect_stream_data(&client.poll_events()));
        let later = server.on_timeout(t0 + Duration::from_secs(7));
        assert!(
            !server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::OutputResync)),
            "the later timer must not be an OutputResync either"
        );
        deliver(&mut client, t0 + Duration::from_secs(7), saddr, later);
        let events = client.poll_events();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::StreamReset { .. })),
            "nor a stream Reset"
        );
        seen.extend(collect_stream_data(&events));
        assert_eq!(
            seen, b"htop frame during the gap and after",
            "the replay and what follows it read as one unbroken stream"
        );
    }

    #[test]
    fn client_role_never_desyncs_its_own_sender_after_long_silence() {
        // IMPORTANT-6(b): the desync/resync machinery is Server-only by
        // design (both `on_timeout`'s desync-arming block and
        // `on_transport`'s resync-arming block gate on
        // `matches!(self.role, Role::Server)`). A silent SERVER must never
        // make the CLIENT drop its own outgoing (keystroke) backlog -- the
        // client has no symmetric resync path to recover it if it did (only
        // a Server ever arms a Reset). This pins the invariant down against
        // a future refactor accidentally making it symmetric.
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let t0 = Instant::now();

        // The client sends a keystroke; the server never receives it (the
        // interruption starts here) and stays silent for the rest of the
        // test.
        let _ = client.send(t0, 0, b"keystroke");

        // Drive the CLIENT's own timers past PATH_DOWN, then past
        // RESYNC_AFTER -- 11 s of silence from the server's side.
        let _ = client.on_timeout(t0 + Duration::from_secs(4));
        assert!(client
            .poll_events()
            .iter()
            .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))));
        let _ = client.on_timeout(t0 + Duration::from_secs(11));
        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::OutputResync)),
            "a client must never emit OutputResync -- that event is server-only"
        );

        // The server, still alive, finally hears from the client again --
        // the keystroke buffered before the silence must still be exactly
        // what arrives: the client never dropped its own backlog for a
        // Reset-and-repaint it has no way to originate. The two expiries
        // above (4 s, 11 s) backed the 500 ms timeout off to 2 s (RFC 6298
        // §5.5), so the next resend is due 13 s in.
        let now2 = t0 + Duration::from_secs(13);
        let retrans = client.on_timeout(now2);
        let _ = deliver_and_collect(&mut server, now2, caddr, retrans);
        assert_eq!(
            collect_stream_data(&server.poll_events()),
            b"keystroke",
            "the client's own pre-silence backlog must survive intact, not be desynced"
        );
    }

    /// The client checks its backup roads on the schedule the table sets,
    /// addressing each check to the road it is about.
    #[test]
    fn a_client_checks_its_backup_roads() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);

        let out = client.on_timeout(Instant::now());
        let to_backup = out.iter().filter(|dg| dg.to == backup).count();
        assert!(
            to_backup >= 1,
            "a backup road must be checked, or it could never be verified: {out:?}"
        );
    }

    #[test]
    fn publishing_a_stale_candidate_group_keeps_the_current_active_path() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let moved: SocketAddr = "192.0.2.100:60000".parse().unwrap();
        client.set_peer(moved);
        let candidates = (1..=8)
            .map(|n| format!("192.0.2.{n}:60000").parse().unwrap())
            .collect();
        client.set_paths(candidates);
        assert!(
            client.paths.contains(moved),
            "the driver may move between snapshot and SetPaths"
        );
        assert_eq!(client.roads(Instant::now()).len(), 8);
        client.set_paths(Vec::new());
        assert!(
            client.roads(Instant::now()).is_empty(),
            "empty still disables path checks"
        );
    }

    #[test]
    fn a_foreign_server_cannot_verify_a_path_that_later_returns_to_the_expected_peer() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let (_other_client, mut other_server, _, _) = established_pair();
        let checked: SocketAddr = "192.0.2.9:60000".parse().unwrap();
        client.set_paths(vec![saddr, checked]);
        let now = Instant::now();
        let probe = client
            .on_timeout(now)
            .into_iter()
            .find(|d| d.to == checked)
            .unwrap();
        // The ordinary encrypted probe cannot open a session at another QSH.
        let foreign = other_server.on_datagram(now, caddr, &probe.bytes);
        for packet in foreign {
            client.on_datagram(now, checked, &packet.bytes);
        }
        assert!(!client.paths.is_verified(checked));
        let answer = server.on_datagram(now, caddr, &probe.bytes);
        for packet in answer {
            client.on_datagram(now + Duration::from_millis(10), checked, &packet.bytes);
        }
        assert!(client.paths.is_verified(checked));
        assert_eq!(client.active_path(), Some(saddr));
    }

    /// Urgency means the liveness check went UNANSWERED, not that one is in
    /// flight. A PING is outstanding from the moment it is sent until its
    /// PONG arrives -- one round trip out of every `PING_INTERVAL` -- and the
    /// driver polls at least every 50 ms, so a tick almost always lands
    /// inside that window. Reading "a PING is outstanding" as urgency put
    /// the road checks on the 1 s schedule while the live road was perfectly
    /// healthy: one round of checks per PING cycle instead of one per 30 s,
    /// twenty times the traffic and twenty times the wakeups, on a phone, on
    /// a metered network.
    #[test]
    fn a_healthy_link_checks_a_spare_road_once_in_thirty_seconds() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();
        let mut now = start;

        // A round trip takes two ticks here, so a PING really is outstanding
        // across tick boundaries -- as it is in production, where the RTT is
        // tens of milliseconds and the driver polls far more often than that.
        // Answering within the same tick would hide the bug completely.
        let mut to_server: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut to_client: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        let mut checks_to_backup = 0usize;

        // Just under the idle interval, so the only check the schedule owes
        // is the one at the very first tick.
        while now < start + Duration::from_secs(29) {
            now += Duration::from_millis(50);
            for (road, bytes) in std::mem::take(&mut to_client) {
                let _ = client.on_datagram(now, road, &bytes);
            }
            for (road, bytes) in std::mem::take(&mut to_server) {
                // The peer always sees this client at its own address;
                // `road` is which of the client's roads the packet took, and
                // the answer comes back the same way.
                for answer in server.on_datagram(now, caddr, &bytes) {
                    to_client.push((road, answer.bytes));
                }
            }
            for dg in client.on_timeout(now) {
                if dg.to == backup {
                    checks_to_backup += 1;
                }
                to_server.push((dg.to, dg.bytes));
            }
        }

        assert_eq!(
            checks_to_backup, 1,
            "a healthy link checks a spare road on the idle schedule, not once per PING cycle"
        );
    }

    /// A server never checks roads: it has no idea which other addresses lead
    /// to it, and a server-side probe would be a packet to nowhere.
    #[test]
    fn a_server_never_checks_roads() {
        let (_client, mut server, caddr, _saddr) = established_pair();
        server.set_paths(vec![caddr, "203.0.113.9:60000".parse().expect("addr")]);
        let out = server.on_timeout(Instant::now());
        assert!(
            out.iter().all(|dg| dg.to == caddr),
            "a server sends nothing to an address it was never talking to: {out:?}"
        );
    }

    /// The point of this whole scenario: when the live road goes quiet, the
    /// client moves to a verified backup instead of waiting out the death
    /// timeout. No handshake, no new session -- the same connection, a
    /// different address.
    #[test]
    fn a_silent_road_is_left_for_a_verified_one() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();

        // The backup answers its check, so it is a road we know works.
        let out = client.on_timeout(start);
        assert!(
            out.iter().any(|dg| dg.to == backup),
            "the backup is checked before it can be verified"
        );
        // The token that actually went out, asked of the table rather than
        // invented here: a made-up one would verify nothing.
        let token = client
            .paths
            .outstanding_token(backup)
            .expect("the check that went out is the one waiting for an answer");
        client.on_path_probe_ack(token, start + Duration::from_millis(20));

        // The live road goes quiet past PATH_DOWN_AFTER.
        let quiet = start + PATH_DOWN_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(quiet);

        assert_eq!(
            client.active_path(),
            Some(backup),
            "a road that answers is better than one that does not"
        );
    }

    /// A move needs a dwell. `PathDown` clears only when an ordinary frame
    /// arrives, and none can arrive before a round trip on the road just
    /// moved to; if the next tick comes first -- and at a 50 ms poll it
    /// always does -- then `best(exclude = the new road)` offers the old one
    /// back, still `Verified` because its own check has not timed out yet,
    /// and the client moves back. Then forth. Invisible on loopback, plain
    /// at 200-300 ms.
    #[test]
    fn a_client_that_just_moved_does_not_move_straight_back() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();

        // Both roads answer their first check, which is what makes a flap
        // possible at all: either one is a road we would move onto.
        let _ = client.on_timeout(start);
        for road in [saddr, backup] {
            let token = client
                .paths
                .outstanding_token(road)
                .expect("both roads are checked");
            client.on_path_probe_ack(token, start + Duration::from_millis(20));
        }

        // The road in use goes quiet, and the client moves onto the spare.
        let quiet = start + PATH_DOWN_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(quiet);
        assert_eq!(
            client.active_path(),
            Some(backup),
            "the move onto the verified spare happens"
        );

        // The very next tick, far too soon for an ordinary frame to have
        // crossed the new road and cleared `PathDown`.
        let _ = client.on_timeout(quiet + Duration::from_millis(100));
        assert_eq!(
            client.active_path(),
            Some(backup),
            "a client must stay on the road it just moved to long enough to hear from it"
        );
    }

    /// With nothing verified to move to, the connection stays where it is --
    /// moving to a road that has never answered would trade a quiet link for
    /// a silent one.
    #[test]
    fn a_silent_road_is_kept_when_no_backup_has_answered() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();
        let _ = client.on_timeout(start);

        let quiet = start + PATH_DOWN_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(quiet);

        assert_eq!(
            client.active_path(),
            Some(saddr),
            "an unanswered road is not a reason to leave the one we have"
        );
    }

    /// Latencies of the two kinds of road in the tests below, and the tick they are driven at.
    /// Both latencies stay under the tick, so the client's clock only ever moves forward.
    const NEAR: Duration = Duration::from_millis(10);
    const FAR: Duration = Duration::from_millis(80);
    const TICK: Duration = Duration::from_millis(100);

    /// One tick of a client talking to a real server `Connection`. Every datagram the client
    /// emits at `now` towards a road listed in `open` reaches the server, and the server's
    /// answers come back that road's latency later; datagrams towards any other road are lost.
    /// Checks and ordinary frames travel alike -- that is what an open road is. The server's
    /// own timers are not driven: these tests are about the client's choice of road.
    fn exchange(
        client: &mut Connection,
        server: &mut Connection,
        caddr: SocketAddr,
        now: Instant,
        open: &[(SocketAddr, Duration)],
    ) {
        for dg in client.on_timeout(now) {
            let Some(&(_, latency)) = open.iter().find(|(road, _)| *road == dg.to) else {
                continue;
            };
            for answer in server.on_datagram(now, caddr, &dg.bytes) {
                let _ = client.on_datagram(now + latency, dg.to, &answer.bytes);
            }
        }
    }

    /// Final fix wave, round 3: a move forgets the old road's retransmit
    /// estimate and back-off, and the send times of what is in flight -- the
    /// new road is measured afresh, starting from the PING forced down it.
    /// Until then the timeout is the liveness value of the latest PONG.
    #[test]
    fn a_move_measures_the_retransmit_timeout_afresh() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        assert!(
            client.paths.is_verified(far),
            "the spare answered its first check"
        );
        client.rtt_estimator.sample(Duration::from_secs(4));
        client.rto_backoff = 2;
        let _in_flight = client.send(start, 0, b"on the old road");
        assert_eq!(client.rto(), RETRANSMIT_CEILING);
        assert_eq!(client.use_road(far, start + TICK), Ok(()));
        assert_eq!(client.rtt_estimator, RttEstimator::default());
        assert_eq!(client.rto_backoff, 0);
        assert_eq!(client.rto(), client.liveness_rto());
        let st = client.streams.get(&0).expect("the stream exists");
        assert_eq!(
            st.sender.ack_timed_from(15),
            None,
            "its send time is forgotten"
        );
    }

    /// Final fix wave, round 3: after a freeze an ACK that waited through it
    /// in the socket must not be read as a round trip the length of the
    /// freeze. The estimate itself is kept -- the road is the same one.
    #[test]
    fn an_ack_read_after_a_freeze_times_nothing() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(20), false);
        ack_one_write(
            &mut client,
            &mut server,
            caddr,
            saddr,
            t0,
            t0 + Duration::from_millis(100),
        );
        let measured = client.rto();
        let sent = t0 + Duration::from_secs(1);
        let out = client.send(sent, 0, b"before the freeze");
        let acks = deliver_and_collect(&mut server, sent, caddr, out);
        client.rto_backoff = 3;
        let woke = sent + Duration::from_secs(600);
        client.request_ping(woke);
        deliver(&mut client, woke, saddr, acks);
        assert_eq!(
            client.rto_backoff, 0,
            "the back-off counted a freeze, not a queue"
        );
        assert_eq!(client.rto(), measured, "the stale ACK timed nothing");
    }

    /// A road that answered its check can be chosen by hand: the traffic goes there at once,
    /// and the very next tick sends a PING down it -- an ordinary packet with a new counter,
    /// which is what makes the server follow after one trip instead of up to `PING_INTERVAL`
    /// later.
    #[test]
    fn use_road_moves_onto_a_verified_spare_and_pings_down_it_at_once() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        assert!(
            client.paths.is_verified(far),
            "the spare answered its first check"
        );

        let press = start + TICK;
        assert_eq!(client.use_road(far, press), Ok(()));
        assert_eq!(
            client.active_path(),
            Some(far),
            "the traffic goes to the chosen road at once"
        );
        assert_eq!(
            client.moved_at,
            Some(press),
            "a move by hand starts the same dwell as an automatic one"
        );

        let out = client.on_timeout(press);
        assert_eq!(
            client.last_ping_sent,
            Some(press),
            "the PING is forced: none was due {TICK:?} after the handshake"
        );
        assert!(
            out.iter().any(|dg| dg.to == far),
            "and it goes down the chosen road"
        );
        assert!(
            out.iter().all(|dg| dg.to != saddr),
            "nothing goes down the road left: its next check is half a minute away"
        );

        // Handing the same roads in again does not undo the choice.
        client.set_paths(vec![saddr, far]);
        assert_eq!(client.active_path(), Some(far));
    }

    /// A road that has not answered -- never, or not lately -- is refused, as is an address that
    /// is not one of the session's roads. Nothing about the connection changes, and no PING is
    /// forced: a refusal is not a move.
    #[test]
    fn use_road_refuses_a_road_that_has_not_answered_or_is_not_one_of_the_sessions() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let fresh = addr("203.0.113.9:60000");
        let stranger = addr("203.0.113.77:1");
        client.set_paths(vec![saddr, fresh]);
        let start = Instant::now();
        let unchanged = |client: &Connection, why: &str| {
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "{why}: the road in use stays"
            );
            assert!(!client.ping_forced, "{why}: no PING is forced");
            assert_eq!(client.moved_at, None, "{why}: no dwell starts");
        };

        assert_eq!(
            client.use_road(stranger, start),
            Err(UseRoadError::UnknownRoad)
        );
        unchanged(&client, "an address never handed in");

        assert_eq!(
            client.use_road(fresh, start),
            Err(UseRoadError::NotAnswering)
        );
        unchanged(&client, "a road never checked");

        // Checked, and silent past PROBE_TIMEOUT (3 s): Dead.
        let _ = client.on_timeout(start);
        let _ = client.on_timeout(start + Duration::from_secs(4));
        assert!(!client.paths.is_verified(fresh));
        assert_eq!(
            client.use_road(fresh, start + Duration::from_secs(4)),
            Err(UseRoadError::NotAnswering)
        );
        unchanged(&client, "a road that stopped answering");
    }

    /// Choosing the road already in use is not an error and not a move.
    #[test]
    fn use_road_on_the_road_in_use_changes_nothing() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );

        assert_eq!(client.use_road(saddr, start + TICK), Ok(()));
        assert_eq!(client.active_path(), Some(saddr));
        assert!(!client.ping_forced);
        assert_eq!(client.moved_at, None);
    }

    /// Only a client in a session has roads to choose from: not a server, not a client
    /// before its handshake, not one that has closed.
    #[test]
    fn only_a_client_with_a_session_can_be_moved() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = Instant::now();
        assert_eq!(
            server.use_road(caddr, now),
            Err(UseRoadError::NoSession),
            "a server"
        );

        let mut unstarted = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(generate_keypair().public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        assert_eq!(
            unstarted.use_road(saddr, now),
            Err(UseRoadError::NoSession),
            "a client before its handshake"
        );

        client.set_paths(vec![saddr]);
        let _ = client.close(now);
        assert_eq!(
            client.use_road(saddr, now),
            Err(UseRoadError::NoSession),
            "a closed client"
        );
    }

    /// THE property of this stage: a road chosen by hand keeps the session for as long as it
    /// carries traffic -- here two minutes -- even though the road left is faster and answers
    /// every check. Automatic moving only ever leaves a road that went quiet (`PathDown`);
    /// there is no rebalancing onto a better one. If one is ever added, it must respect the
    /// person's choice, and this test is what fails first to say so.
    #[test]
    fn a_road_chosen_by_hand_is_kept_while_it_carries_traffic_even_if_another_is_faster() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let roads = [(saddr, NEAR), (far, FAR)];
        let start = Instant::now();
        exchange(&mut client, &mut server, caddr, start, &roads);
        assert!(
            client.paths.is_verified(far),
            "the far road answered its first check"
        );
        assert_eq!(
            client.paths.best(None),
            Some(saddr),
            "and the near one ranks better"
        );

        assert_eq!(client.use_road(far, start + TICK), Ok(()));
        let _ = client.poll_events();

        let mut now = start + TICK;
        let until = now + Duration::from_secs(120);
        while now < until {
            exchange(&mut client, &mut server, caddr, now, &roads);
            assert_eq!(
                client.active_path(),
                Some(far),
                "the connection left the road chosen by hand {:?} after the choice",
                now - start
            );
            now += TICK;
        }
        assert!(
            matches!(client.state, LinkState::Live),
            "the chosen road carried the traffic the whole time"
        );
        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))),
            "it never went quiet -- or the test would be about something else"
        );
        assert_eq!(
            client.paths.best(None),
            Some(saddr),
            "and the road left stayed the better-ranked one throughout"
        );
    }

    /// Pressed while the road in use is already down and the spares have only just answered:
    /// the next tick -- 50 ms later in the driver -- would pick the best spare on its own. The
    /// dwell a move by hand starts is what keeps it from overruling the person.
    #[test]
    fn a_road_chosen_while_the_link_is_down_is_not_overruled_by_the_next_tick() {
        let (mut client, _server, _caddr, saddr) = established_pair();
        let near = addr("203.0.113.9:60000");
        let far = addr("203.0.113.10:60000");
        client.set_paths(vec![saddr, near, far]);
        let start = Instant::now();
        let _ = client.on_timeout(start);

        // The road in use goes quiet, and no spare has answered yet: PathDown, nowhere to go.
        let quiet = start + PATH_DOWN_AFTER + Duration::from_secs(1);
        let _ = client.on_timeout(quiet);
        assert!(matches!(client.state, LinkState::PathDown));
        assert_eq!(client.active_path(), Some(saddr));

        // Both spares answer the urgent round that tick sent, the near one faster.
        for (road, rtt) in [(near, NEAR), (far, FAR)] {
            let token = client
                .paths
                .outstanding_token(road)
                .expect("the urgent round checked every road");
            client.on_path_probe_ack(token, quiet + rtt);
        }

        // Before the next tick, the person picks the far one.
        let press = quiet + FAR + Duration::from_millis(5);
        assert_eq!(client.use_road(far, press), Ok(()));

        let _ = client.on_timeout(press + Duration::from_millis(50));
        assert_eq!(
            client.active_path(),
            Some(far),
            "the tick right after a choice made during PathDown must not overrule it"
        );
    }

    /// A choice holds only while its road carries traffic. The chosen road goes quiet, and
    /// after `PATH_DOWN_AFTER` the automatic move takes the session to the best verified road
    /// -- here the very road it left, which is allowed (spec §3.3).
    #[test]
    fn when_the_chosen_road_goes_quiet_the_client_moves_on_even_back_to_the_road_it_left() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        assert_eq!(client.use_road(far, start + TICK), Ok(()));

        // Two seconds on the chosen road, carrying traffic.
        let mut now = start + TICK;
        while now < start + Duration::from_secs(2) {
            exchange(
                &mut client,
                &mut server,
                caddr,
                now,
                &[(saddr, NEAR), (far, FAR)],
            );
            now += TICK;
        }
        assert_eq!(client.active_path(), Some(far));

        // The chosen road stops carrying anything; the one left still answers. The client
        // moves within `PATH_DOWN_AFTER` and one tick, and never bounces back onto the silent
        // road: the move forces a PING down the new road, which clears `PathDown` after one
        // round trip -- before the dwell ends and while the silent road still reads `Verified`.
        let cut = now;
        let moved_by = cut + PATH_DOWN_AFTER + TICK;
        let mut moved_at = None;
        while now <= moved_by {
            exchange(&mut client, &mut server, caddr, now, &[(saddr, NEAR)]);
            if client.active_path() == Some(saddr) {
                moved_at.get_or_insert(now);
            } else {
                assert!(
                    moved_at.is_none(),
                    "bounced back onto the silent road {:?} after the cut",
                    now - cut
                );
            }
            now += TICK;
        }
        assert!(
            moved_at.is_some(),
            "a road chosen by hand that goes quiet is left like any other -- within {:?}",
            moved_by - cut
        );
        // And it has settled: on the road moved onto, carrying traffic, tick after tick.
        let hold_until = now + Duration::from_secs(5);
        while now < hold_until {
            exchange(&mut client, &mut server, caddr, now, &[(saddr, NEAR)]);
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "bounced back onto the silent road {:?} after the cut",
                now - cut
            );
            assert!(
                matches!(client.state, LinkState::Live),
                "and the road moved onto carries the traffic again ({:?} after the cut)",
                now - cut
            );
            now += TICK;
        }
    }

    /// A road that answered its last check but has died since can still be chosen: the check
    /// that would say so has not timed out yet. The session must not wedge there. The server,
    /// hearing nothing ordinary from the client's new road, keeps talking over the old one, and
    /// that traffic keeps the client's liveness clock fresh, so the link never goes quiet and
    /// `PATH_DOWN_AFTER` never fires -- while every keystroke goes down the dead road. The road
    /// in use failing its own check is what counts as the link being down then, and the
    /// automatic move takes the session back within one PING interval (the forced PING goes
    /// unanswered, the next one makes the checks urgent), one check timeout and one dwell.
    #[test]
    fn a_dead_road_chosen_by_hand_is_left_even_while_the_server_keeps_talking_over_the_old_one() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        assert!(
            client.paths.is_verified(far),
            "the far road answered its first check"
        );

        // From here on the far road carries nothing, but its check has not timed out.
        let press = start + TICK;
        assert_eq!(
            client.use_road(far, press),
            Ok(()),
            "a stale Verified road is accepted"
        );

        let bound = press + PING_INTERVAL + Duration::from_secs(3) + client.move_dwell() + TICK;
        let mut now = press;
        let mut left_at = None;
        while now < bound + Duration::from_secs(5) {
            exchange(&mut client, &mut server, caddr, now, &[(saddr, NEAR)]);
            // The server's own output and timers: everything it sends goes to `caddr` over
            // the old road and reaches the client from `saddr`.
            let mut talk = server.send(now, 0, b".");
            talk.extend(server.on_timeout(now));
            for dg in talk {
                for answer in client.on_datagram(now + NEAR, saddr, &dg.bytes) {
                    if answer.to == saddr {
                        let _ = server.on_datagram(now + NEAR, caddr, &answer.bytes);
                    }
                }
            }
            if left_at.is_none() && client.active_path() == Some(saddr) {
                left_at = Some(now);
            }
            if left_at.is_some() {
                assert_eq!(
                    client.active_path(),
                    Some(saddr),
                    "once back on the working road the client stays ({:?} after the choice)",
                    now - press
                );
            }
            now += TICK;
        }
        let left_at = left_at.expect("the client never left the dead road it was moved onto");
        assert!(
            left_at <= bound,
            "left the dead road {:?} after the choice, later than the bound {:?}",
            left_at - press,
            bound - press
        );
        assert!(
            matches!(client.state, LinkState::Live),
            "and the road it went back to carries the traffic"
        );
    }

    /// A road goes `Dead` after ONE unanswered check: one lost check must not move the session
    /// off a road that carries traffic both ways -- the PINGs down it are answered, which is
    /// what tells a lost check from a dead road, and the road is checked again at once and
    /// heals. Only the first check to the road in use is dropped here; a verified spare stands
    /// ready the whole time, and the session stays where it is.
    #[test]
    fn one_lost_check_does_not_move_the_session_off_a_road_that_carries_traffic() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();

        // The first round of checks: the one to the road in use is lost, the spare answers.
        for dg in client.on_timeout(start) {
            if dg.to != spare {
                continue;
            }
            for answer in server.on_datagram(start, caddr, &dg.bytes) {
                let _ = client.on_datagram(start + FAR, spare, &answer.bytes);
            }
        }
        assert!(
            client.paths.is_verified(spare),
            "the spare answered its check"
        );

        let roads = [(saddr, NEAR), (spare, FAR)];
        let mut read_dead = false;
        let mut now = start + TICK;
        let until = start + Duration::from_secs(20);
        while now < until {
            exchange(&mut client, &mut server, caddr, now, &roads);
            read_dead |= client.paths.is_dead(saddr);
            // Keystrokes one way, output the other, both over the road in use.
            for dg in client.send(now, 0, b"k") {
                if dg.to == saddr {
                    let _ = server.on_datagram(now, caddr, &dg.bytes);
                }
            }
            let mut talk = server.send(now, 0, b".");
            talk.extend(server.on_timeout(now));
            for dg in talk {
                for answer in client.on_datagram(now + NEAR, saddr, &dg.bytes) {
                    if answer.to == saddr {
                        let _ = server.on_datagram(now + NEAR, caddr, &answer.bytes);
                    }
                }
            }
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "one lost check moved the session off a working road {:?} in",
                now - start
            );
            now += TICK;
        }
        assert!(
            read_dead,
            "the road in use did read Dead -- or the test proves nothing"
        );
        assert!(matches!(client.state, LinkState::Live));
    }

    /// Keystrokes one way and output the other, both over the road in use, for one tick: what
    /// keeps `last_recv_ordinary` fresh from both ends in the tests below.
    fn traffic_both_ways(
        client: &mut Connection,
        server: &mut Connection,
        caddr: SocketAddr,
        road: SocketAddr,
        now: Instant,
    ) {
        for dg in client.send(now, 0, b"k") {
            if dg.to == road {
                let _ = server.on_datagram(now, caddr, &dg.bytes);
            }
        }
        let mut talk = server.send(now, 0, b".");
        talk.extend(server.on_timeout(now));
        for dg in talk {
            for answer in client.on_datagram(now + NEAR, road, &dg.bytes) {
                if answer.to == road {
                    let _ = server.on_datagram(now + NEAR, caddr, &answer.bytes);
                }
            }
        }
    }

    /// The first round of checks with the one to the road in use lost: the spare answers and
    /// is `Verified`, the road in use goes `Dead` once `PROBE_TIMEOUT` runs out.
    fn lose_the_first_check_to_the_road_in_use(
        client: &mut Connection,
        server: &mut Connection,
        caddr: SocketAddr,
        spare: SocketAddr,
        start: Instant,
    ) {
        for dg in client.on_timeout(start) {
            if dg.to != spare {
                continue;
            }
            for answer in server.on_datagram(start, caddr, &dg.bytes) {
                let _ = client.on_datagram(start + FAR, spare, &answer.bytes);
            }
        }
        assert!(
            client.paths.is_verified(spare),
            "the spare answered its check"
        );
    }

    /// One lost check makes the road in use read `Dead`, and a dead road in use makes the
    /// checks urgent: the road is checked again on the very next tick and heals within
    /// `PROBE_URGENT` and a round trip -- not half a minute later on the idle schedule, which
    /// is how long a single lost datagram used to leave it `Dead`, ready to be paired with
    /// anything else that went wrong in the meantime. It stays where it is throughout.
    #[test]
    fn one_lost_check_on_the_road_in_use_heals_within_a_second_and_a_round_trip() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();
        lose_the_first_check_to_the_road_in_use(&mut client, &mut server, caddr, spare, start);

        let roads = [(saddr, NEAR), (spare, FAR)];
        let mut went_dead = None;
        let mut healed = None;
        let mut now = start + TICK;
        while now < start + Duration::from_secs(60) {
            exchange(&mut client, &mut server, caddr, now, &roads);
            traffic_both_ways(&mut client, &mut server, caddr, saddr, now);
            if went_dead.is_none() && client.paths.is_dead(saddr) {
                went_dead = Some(now);
            }
            if went_dead.is_some() && healed.is_none() && client.paths.is_verified(saddr) {
                healed = Some(now);
            }
            if healed.is_some() {
                assert!(
                    client.paths.is_verified(saddr),
                    "once healed, the road in use stays verified ({:?} in)",
                    now - start
                );
            }
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "one lost check moved the session off a working road {:?} in",
                now - start
            );
            now += TICK;
        }
        let went_dead = went_dead.expect("the lost check made the road in use read Dead");
        let healed = healed.expect("the road in use never healed from one lost check");
        assert!(
            healed - went_dead <= PROBE_URGENT + NEAR + TICK,
            "healed {:?} after going Dead, later than one urgent check and a round trip",
            healed - went_dead
        );
        assert!(matches!(client.state, LinkState::Live));
    }

    /// Two losses far apart in time are not one failure. A check to the road in use is lost,
    /// and some twenty seconds later two PINGs in a row are lost too -- enough for
    /// `ping_unanswered` -- while traffic flows both ways the rest of the time. The dead-road
    /// rule needs the failed check and the unanswered PINGs to overlap; these do not, and the
    /// session stays on its road.
    #[test]
    fn a_lost_check_and_pings_lost_twenty_seconds_later_do_not_move_the_session() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();
        lose_the_first_check_to_the_road_in_use(&mut client, &mut server, caddr, spare, start);

        let roads = [(saddr, NEAR), (spare, FAR)];
        let mut pings_to_lose = 2;
        let mut saw_the_mark = false;
        let mut now = start + TICK;
        // Short of the next idle check (30 s), so the road left `Dead` by the lost check alone
        // would still read `Dead` when the PINGs go unanswered.
        while now < start + Duration::from_secs(28) {
            let out = client.on_timeout(now);
            let minted = client.last_ping_sent == Some(now);
            let lose = minted && pings_to_lose > 0 && now >= start + Duration::from_secs(20);
            if lose {
                pings_to_lose -= 1;
            }
            for dg in out {
                if lose && dg.to == saddr {
                    continue;
                }
                let Some(&(_, latency)) = roads.iter().find(|(road, _)| *road == dg.to) else {
                    continue;
                };
                for answer in server.on_datagram(now, caddr, &dg.bytes) {
                    let _ = client.on_datagram(now + latency, dg.to, &answer.bytes);
                }
            }
            saw_the_mark |= client.ping_unanswered;
            if !lose {
                traffic_both_ways(&mut client, &mut server, caddr, saddr, now);
            }
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "a lost check and PINGs lost ~20 s later moved the session {:?} in",
                now - start
            );
            now += TICK;
        }
        assert_eq!(pings_to_lose, 0, "both PINGs were lost");
        assert!(
            saw_the_mark,
            "the lost PINGs did go unanswered -- or the test proves nothing"
        );
        assert!(matches!(client.state, LinkState::Live));
    }

    /// A road whose round trip is longer than `PING_INTERVAL` has a PING minted while the last
    /// one is still in flight, every time. Its PONGs must still count: the round trip is
    /// measured, `ping_unanswered` clears and stays clear, and the road -- which answers every
    /// check within `PROBE_TIMEOUT` -- keeps the session while a fast verified spare stands by.
    #[test]
    fn a_road_slower_than_the_ping_interval_is_measured_and_kept() {
        for rtt in [Duration::from_millis(1700), Duration::from_millis(2900)] {
            // Unmeasured: a zero-length in-memory handshake would seed a 0 ms
            // round trip that this slow road does not have.
            let (mut client, mut server, caddr, saddr) = established_pair_unmeasured();
            let spare = addr("203.0.113.9:60000");
            client.set_paths(vec![saddr, spare]);
            let start = Instant::now();
            let latency = |road: SocketAddr| if road == saddr { rtt } else { NEAR };
            // Datagrams on their way to the client: (when they arrive, the road, the bytes).
            let mut in_flight: Vec<(Instant, SocketAddr, Vec<u8>)> = Vec::new();
            let mut now = start;
            let settled = start + Duration::from_secs(15);
            while now < start + Duration::from_secs(60) {
                in_flight.sort_by_key(|(at, _, _)| *at);
                let arrived: Vec<_> = {
                    let split = in_flight.partition_point(|(at, _, _)| *at <= now);
                    in_flight.drain(..split).collect()
                };
                let mut out = Vec::new();
                for (at, road, bytes) in arrived {
                    for answer in client.on_datagram(at, road, &bytes) {
                        out.push((at, answer));
                    }
                }
                for dg in client.on_timeout(now) {
                    out.push((now, dg));
                }
                // Five keystrokes a tick, 50 a second: with a 2.9 s round trip that keeps some
                // 145 server packets in flight on the slow road -- more than the 64 positions
                // the replay window used to hold -- so the fast spare's answers overtaking them
                // must not cost the slow road its PONGs (spec §4.4).
                for _ in 0..5 {
                    for dg in client.send(now, 0, b"k") {
                        out.push((now, dg));
                    }
                }
                for (sent, dg) in out {
                    for answer in server.on_datagram(sent, caddr, &dg.bytes) {
                        in_flight.push((sent + latency(dg.to), dg.to, answer.bytes));
                    }
                }
                assert_eq!(
                    client.active_path(),
                    Some(saddr),
                    "a road with a {rtt:?} round trip was left {:?} in",
                    now - start
                );
                if now >= settled {
                    assert!(
                        !client.ping_unanswered,
                        "a road with a {rtt:?} round trip reads its PINGs as unanswered {:?} in",
                        now - start
                    );
                }
                now += TICK;
            }
            let measured = Duration::from_millis(u64::from(client.stats(now).rtt_ms));
            assert!(
                measured >= rtt && measured <= rtt + TICK,
                "a road with a {rtt:?} round trip measured as {measured:?}"
            );
            assert!(matches!(client.state, LinkState::Live), "{rtt:?}");
        }
    }

    /// The dead-road rule, isolated: the road in use has failed its check, a verified spare
    /// stands ready, and PINGs are going unanswered. Whether the session moves depends only on
    /// whether the two failures overlap -- the PINGs were found unanswered no later than the
    /// failed check was sent. Found unanswered only after it went out, they are a second,
    /// separate loss, even while that check was still in flight.
    #[test]
    fn the_dead_road_rule_needs_the_failed_check_and_the_unanswered_pings_to_overlap() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();
        lose_the_first_check_to_the_road_in_use(&mut client, &mut server, caddr, spare, start);
        // Output from the server over the road in use, so it does not go quiet (`PathDown`
        // moves the session on its own).
        let talked = start + Duration::from_secs(2);
        for dg in server.send(talked, 0, b".") {
            let _ = client.on_datagram(talked, saddr, &dg.bytes);
        }
        let failed = start + Duration::from_secs(3);
        let _ = client.on_timeout(failed);
        assert_eq!(
            client.paths.failed_at(saddr),
            Some(start),
            "the check sent at the start failed"
        );
        assert_eq!(client.active_path(), Some(saddr));

        // PINGs found unanswered after the check went out -- while it was still in flight:
        // no overlap, no move.
        client.ping_unanswered = true;
        client.ping_unanswered_since = Some(start + Duration::from_secs(1));
        let _ = client.on_timeout(failed + TICK);
        assert_eq!(
            client.active_path(),
            Some(saddr),
            "a run of unanswered PINGs that began after the failed check moved the session"
        );
        assert_eq!(
            client.paths.failed_at(saddr),
            Some(start),
            "nothing else changed"
        );

        // Found unanswered before it went out: the two overlap, and the session moves.
        client.ping_unanswered_since = Some(start);
        let _ = client.on_timeout(failed + TICK * 2);
        assert_eq!(
            client.active_path(),
            Some(spare),
            "a failed check overlapping unanswered PINGs must move the session"
        );
    }

    /// Independent losses that happen to line up are not a dead road. On a road with a 300 ms
    /// round trip, the idle check to the road in use and the PING minted in the same tick are
    /// lost; the next PING is lost too, which marks the PINGs unanswered; and the urgent
    /// re-checks that mark brings are lost until the first check expires, while the mark still
    /// stands (the PONG that clears it is a round trip away). Everything else -- traffic both
    /// ways, the PINGs before and after -- gets through. The check that failed was sent before
    /// the PINGs were found unanswered, so the two failures do not overlap and the session
    /// stays.
    #[test]
    fn a_check_sent_before_the_pings_were_found_unanswered_does_not_overlap_them() {
        let rtt = Duration::from_millis(300);
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();
        let latency = |road: SocketAddr| if road == saddr { rtt } else { NEAR };
        let mut in_flight: Vec<(Instant, SocketAddr, Vec<u8>)> = Vec::new();
        // The idle check to the road in use falls due `PROBE_IDLE` (30 s) after the first one.
        let idle_check = start + Duration::from_secs(30);
        let mut lost_pings = 0;
        let mut lost_since: Option<Instant> = None;
        let mut failed_under_the_mark = false;
        let mut now = start;
        while now < start + Duration::from_secs(45) {
            in_flight.sort_by_key(|(at, _, _)| *at);
            let split = in_flight.partition_point(|(at, _, _)| *at <= now);
            let arrived: Vec<_> = in_flight.drain(..split).collect();
            let mut out = Vec::new();
            for (at, road, bytes) in arrived {
                for answer in client.on_datagram(at, road, &bytes) {
                    out.push((at, answer, false));
                }
            }
            let was_dead = client.paths.is_dead(saddr);
            let token_before = client.paths.outstanding_token(saddr);
            let tick = client.on_timeout(now);
            let minted = client.last_ping_sent == Some(now);
            let checked = client.paths.outstanding_token(saddr) != token_before
                && client.paths.outstanding_token(saddr).is_some();
            if !was_dead && client.paths.is_dead(saddr) && client.ping_unanswered {
                failed_under_the_mark = true;
            }
            // The losses: from the idle check on, the checks to the road in use until the
            // first of them expires, and the first two PINGs.
            if now >= idle_check && lost_since.is_none() && checked {
                lost_since = Some(now);
            }
            let losing_checks =
                lost_since.is_some_and(|since| now < since + Duration::from_secs(3));
            let lose_ping = minted && now >= idle_check && lost_pings < 2;
            if lose_ping {
                lost_pings += 1;
            }
            for dg in tick {
                let lose = dg.to == saddr && ((checked && losing_checks) || lose_ping);
                out.push((now, dg, lose));
            }
            if (now - start).as_millis().is_multiple_of(500) {
                for dg in client.send(now, 0, b"k") {
                    out.push((now, dg, false));
                }
            }
            for (sent, dg, lose) in out {
                if lose {
                    continue;
                }
                for answer in server.on_datagram(sent, caddr, &dg.bytes) {
                    in_flight.push((sent + latency(dg.to), dg.to, answer.bytes));
                }
            }
            assert_eq!(
                client.active_path(),
                Some(saddr),
                "independent losses moved the session {:?} in",
                now - start
            );
            now += TICK;
        }
        assert_eq!(lost_pings, 2, "both PINGs were lost");
        assert!(
            failed_under_the_mark,
            "the check expired while the PINGs read unanswered -- or the test proves nothing"
        );
    }

    /// A move -- by hand or automatic -- forgets the PINGs sent down the road left, as a rebind
    /// does: their fate says nothing about the new road. A surviving one would have the next
    /// PING minted on the new road find it overdue on the old road's account, and stamp that
    /// moment as when the PINGs were found unanswered (`ping_unanswered_since`) -- a stamp no
    /// later than any check the new road sends afterwards, so the first such check to fail
    /// would overlap it and move the session off a road that never dropped a PING.
    #[test]
    fn a_move_forgets_the_pings_sent_down_the_road_left() {
        // By hand.
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        // Two PINGs down the road in use, neither answered: the second marks the first.
        // The first PING is due `PING_INTERVAL` after the handshake.
        let first = client.handshake_at + PING_INTERVAL;
        let _ = client.on_timeout(first);
        // Output from the server keeps the road in use from going quiet (`PathDown` would
        // move the session on its own); the PING it answers is lost.
        for dg in server.send(first + TICK, 0, b".") {
            let _ = client.on_datagram(first + TICK, saddr, &dg.bytes);
        }
        let _ = client.on_timeout(first + PING_INTERVAL);
        assert_eq!(client.active_path(), Some(saddr));
        assert!(
            client.ping_unanswered,
            "the old road's PING went unanswered"
        );
        let press = first + PING_INTERVAL + TICK;
        assert_eq!(client.use_road(far, press), Ok(()));
        assert!(
            client.outstanding_pings.is_empty() && !client.ping_unanswered,
            "a move by hand forgets the old road's PINGs and the mark with them"
        );
        let _ = client.on_timeout(press);
        assert_eq!(
            client.outstanding_pings.len(),
            1,
            "only the forced PING is outstanding"
        );
        assert!(!client.ping_unanswered, "and it is not unanswered yet");

        // Automatic: the road in use goes quiet while its PINGs go unanswered.
        let (mut client, mut server, caddr, saddr) = established_pair();
        let spare = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, spare]);
        let start = Instant::now();
        let mut now = start;
        let mut pinged_the_old_road = false;
        while client.active_path() == Some(saddr) && now < start + Duration::from_secs(10) {
            now += TICK;
            pinged_the_old_road |= !client.outstanding_pings.is_empty();
            exchange(&mut client, &mut server, caddr, now, &[(spare, NEAR)]);
        }
        assert!(
            pinged_the_old_road,
            "a PING down the quiet road was outstanding"
        );
        assert_eq!(client.active_path(), Some(spare), "the quiet road was left");
        // The move and the forced PING down the new road happen in the same tick (and the
        // forced one may already be answered).
        assert!(
            client
                .outstanding_pings
                .iter()
                .all(|(_, sent)| *sent == now),
            "an automatic move forgets the old road's PINGs"
        );
        assert_eq!(
            client.last_ping_sent,
            Some(now),
            "and forces one down the new road"
        );
        assert!(!client.ping_unanswered, "and the mark goes with them");
    }

    /// Output from the server every 200 ms from the handshake on -- a clock in tmux, `htop`
    /// after a reconnect. The first PING is scheduled from the handshake, not from the last
    /// packet received: counted from that, it would be pushed back by every packet and never
    /// go out, leaving the round trip unmeasured and the liveness PINGs -- which the dead-road
    /// rule reads -- silent for the whole session.
    #[test]
    fn the_first_ping_goes_out_even_while_the_server_streams_output_from_the_handshake() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let handshake = client.handshake_at;
        let mut now = handshake;
        let mut first_ping = None;
        while now < handshake + Duration::from_secs(5) {
            if (now - handshake).as_millis().is_multiple_of(200) {
                for dg in server.send(now, 0, b".") {
                    for answer in client.on_datagram(now + NEAR, saddr, &dg.bytes) {
                        let _ = server.on_datagram(now + NEAR, caddr, &answer.bytes);
                    }
                }
            }
            for dg in client.on_timeout(now) {
                for answer in server.on_datagram(now, caddr, &dg.bytes) {
                    let _ = client.on_datagram(now + NEAR, saddr, &answer.bytes);
                }
            }
            if first_ping.is_none() {
                first_ping = client.last_ping_sent;
            }
            now += TICK;
        }
        let first_ping = first_ping.expect("no PING went out in five seconds of server output");
        assert!(
            first_ping - handshake <= PING_INTERVAL + TICK,
            "the first PING went out {:?} after the handshake",
            first_ping - handshake
        );
        assert_eq!(
            client.stats(now).rtt_ms,
            10,
            "and the round trip is measured"
        );
    }

    /// The wedge scenario under output streamed from the handshake on: the server has talked
    /// every 200 ms since the session began, so no PING had gone out before the choice. The
    /// dead road chosen by hand is still left within the same bound as in
    /// `a_dead_road_chosen_by_hand_is_left_even_while_the_server_keeps_talking_over_the_old_one`.
    #[test]
    fn a_dead_road_chosen_by_hand_is_left_under_output_streamed_from_the_handshake() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let handshake = client.handshake_at;
        let talk = |client: &mut Connection, server: &mut Connection, now: Instant| {
            if (now - handshake).as_millis().is_multiple_of(200) {
                let mut out = server.send(now, 0, b".");
                out.extend(server.on_timeout(now));
                for dg in out {
                    for answer in client.on_datagram(now + NEAR, saddr, &dg.bytes) {
                        if answer.to == saddr {
                            let _ = server.on_datagram(now + NEAR, caddr, &answer.bytes);
                        }
                    }
                }
            }
        };
        let mut now = handshake;
        while now < handshake + Duration::from_secs(5) {
            exchange(
                &mut client,
                &mut server,
                caddr,
                now,
                &[(saddr, NEAR), (far, FAR)],
            );
            talk(&mut client, &mut server, now);
            now += TICK;
        }
        assert!(
            client.paths.is_verified(far),
            "the far road answered its check"
        );

        // From here on the far road carries nothing, but its check has not timed out.
        let press = now;
        assert_eq!(client.use_road(far, press), Ok(()));
        let bound = press + PING_INTERVAL + Duration::from_secs(3) + client.move_dwell() + TICK;
        let mut left_at = None;
        while now < bound + Duration::from_secs(5) {
            exchange(&mut client, &mut server, caddr, now, &[(saddr, NEAR)]);
            talk(&mut client, &mut server, now);
            if left_at.is_none() && client.active_path() == Some(saddr) {
                left_at = Some(now);
            }
            now += TICK;
        }
        let left_at = left_at.expect("the client never left the dead road it was moved onto");
        assert!(
            left_at <= bound,
            "left the dead road {:?} after the choice, later than the bound {:?}",
            left_at - press,
            bound - press
        );
        assert_eq!(
            client.active_path(),
            Some(saddr),
            "and stays on the working road"
        );
    }

    /// A network change (`Rebind`, a wake from Doze) replaces the local socket, not the road:
    /// the forced PING it asks for goes down the road chosen by hand.
    #[test]
    fn a_rebind_keeps_the_road_chosen_by_hand() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let far = addr("203.0.113.9:60000");
        client.set_paths(vec![saddr, far]);
        let start = Instant::now();
        exchange(
            &mut client,
            &mut server,
            caddr,
            start,
            &[(saddr, NEAR), (far, FAR)],
        );
        assert_eq!(client.use_road(far, start + TICK), Ok(()));
        exchange(
            &mut client,
            &mut server,
            caddr,
            start + TICK,
            &[(saddr, NEAR), (far, FAR)],
        );

        let wake = start + Duration::from_secs(1);
        client.request_ping(wake);
        let out = client.on_timeout(wake);
        assert_eq!(
            client.active_path(),
            Some(far),
            "a rebind does not undo the choice"
        );
        assert_eq!(client.last_ping_sent, Some(wake));
        assert!(
            out.iter().any(|dg| dg.to == far),
            "the forced PING goes down the chosen road"
        );
    }

    /// An authenticated answer from a SPARE road must not stand in
    /// for the road in use being alive. A live check-and-answer cycle on the
    /// backup keeps arriving (as it genuinely would once the live road's own
    /// failed PING makes checks urgent), yet the live road itself never gets
    /// a single ordinary packet -- and `PATH_DOWN_AFTER` must still fire.
    /// This is the scenario an earlier end-to-end test could not get past:
    /// with a spare road configured, the client never reached `PathDown` at
    /// all.
    #[test]
    fn a_spare_roads_probe_answers_do_not_mask_the_live_road_going_quiet() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let backup: SocketAddr = "203.0.113.9:60000".parse().expect("a literal address");
        client.set_paths(vec![saddr, backup]);
        let start = Instant::now();
        let mut now = start;

        // Drive several seconds of timer ticks. Every check the client
        // sends to `backup` is genuinely answered (routed through `server`,
        // standing in for whatever is reachable at that address) -- but
        // nothing is ever delivered for `saddr`, the live road, which is
        // exactly what it going quiet means.
        for _ in 0..20 {
            now += Duration::from_millis(300);
            let out = client.on_timeout(now);
            for dg in out.iter().filter(|dg| dg.to == backup) {
                let answer = server.on_datagram(now, backup, &dg.bytes);
                for ack in answer {
                    let _ = client.on_datagram(now, backup, &ack.bytes);
                }
            }
        }

        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))),
            "a spare road's probe answers must not keep the live road looking healthy"
        );
    }

    /// A client that can be checked but cannot carry traffic has to give up,
    /// so its owner can start over. The death timer used to read
    /// `last_recv_auth` for both roles, and a check's answer is an
    /// authenticated packet: a road that answers checks while nothing
    /// ordinary gets back would hold the client open forever, and the app's
    /// full reconnect -- which keys on `Closed` -- would never fire. Before
    /// this branch such a client died in `CLIENT_DEATH_AFTER`.
    #[test]
    fn a_client_whose_road_answers_checks_but_carries_nothing_still_gives_up() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        // One road, so nowhere to move: this is a client whose only road
        // answers checks and delivers nothing.
        client.set_paths(vec![saddr]);
        let start = Instant::now();
        let mut now = start;

        while now < start + Duration::from_secs(46) {
            now += Duration::from_millis(250);
            for dg in client.on_timeout(now) {
                // Which datagram is a check and which is ordinary is asked of
                // the peer rather than guessed: a packet that advances the
                // SERVER's `last_recv_ordinary` carried ordinary frames, and
                // this road is one whose answers to those never come back.
                let before = server.last_recv_ordinary;
                let answers = server.on_datagram(now, caddr, &dg.bytes);
                if server.last_recv_ordinary == before {
                    for answer in answers {
                        let _ = client.on_datagram(now, saddr, &answer.bytes);
                    }
                }
            }
        }

        assert!(
            client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::Closed))),
            "no number of answered checks makes a session that carries nothing worth keeping"
        );
    }

    /// A check's answer is attributed by its token, not by the
    /// address it happened to arrive from. This is exactly what a loopback-
    /// bound or multihomed responder does: a daemon checked at
    /// `127.0.0.2` answers sourced from `127.0.0.1`, so the road that was
    /// actually checked could never be verified under the old,
    /// address-keyed lookup.
    #[test]
    fn a_check_answered_from_a_different_address_than_it_was_sent_to_still_verifies_the_road() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let checked: SocketAddr = "203.0.113.9:9000".parse().expect("a literal address");
        client.set_paths(vec![saddr, checked]);
        let start = Instant::now();

        let out = client.on_timeout(start);
        let probe = out
            .iter()
            .find(|dg| dg.to == checked)
            .expect("the new road is checked")
            .clone();

        // The peer receives the check as arriving from `checked` -- that is
        // what being checked at that address means -- and answers it.
        let answer = server.on_datagram(start, checked, &probe.bytes);
        let ack = answer.into_iter().next().expect("a check must be answered");

        // But the answer reaches the client sourced from a DIFFERENT
        // address than the one that was checked.
        let answered_from: SocketAddr = "203.0.113.1:9000".parse().expect("a literal address");
        let _ = client.on_datagram(start + Duration::from_millis(20), answered_from, &ack.bytes);

        assert!(
            client.paths.is_verified(checked),
            "the road that was actually checked must verify, whatever address answered"
        );
    }

    /// Only a server follows its peer's source address. The
    /// client's road changes exactly where this design says it does --
    /// through the path table and `set_peer` -- never because an ordinary
    /// packet showed up from somewhere else. Before `driver_std` reported
    /// the true source of an inbound datagram, this branch was unreachable
    /// for a client; now that it is reachable, it fights a deliberate move
    /// onto a verified spare road, undoing it the moment the old road's
    /// traffic shows up again.
    #[test]
    fn only_a_server_follows_its_peers_source_address() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = Instant::now();

        // The server still follows ordinary traffic to a new address --
        // this is what makes roaming work at all.
        let new_client_addr: SocketAddr = "203.0.113.9:55000".parse().expect("a literal address");
        let data = client.send(now, 0, b"hello");
        let dg = data
            .into_iter()
            .next()
            .expect("data goes out as a datagram");
        let _ = server.on_datagram(now, new_client_addr, &dg.bytes);
        assert_eq!(
            server.peer(),
            Some(new_client_addr),
            "a server must still follow its peer's source address"
        );

        // The client receiving ordinary traffic from a new address must NOT
        // move -- it has no path table entry for this address and never
        // asked to move there.
        let new_server_addr: SocketAddr = "203.0.113.10:9000".parse().expect("a literal address");
        let reply = server.send(now, 0, b"hi");
        let dg = reply
            .into_iter()
            .next()
            .expect("data goes out as a datagram");
        let _ = client.on_datagram(now, new_server_addr, &dg.bytes);
        assert_eq!(
            client.peer(),
            Some(saddr),
            "a client must not re-point itself at the source of an ordinary packet"
        );
    }

    /// Caught in self-review, not one of the three cases above directly: `last_recv_ordinary`
    /// has to be re-baselined wherever `last_recv_auth` already is at handshake
    /// completion, or a handshake slow enough to need a few retransmits would
    /// make `PATH_DOWN_AFTER` fire on the very first timer tick after
    /// finishing -- the road would read as having gone quiet for exactly as
    /// long as the handshake took, before a single ordinary byte crossed it.
    #[test]
    fn a_slow_handshake_does_not_look_like_the_road_already_went_quiet() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");

        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });

        let t0 = Instant::now();
        let m1 = client.start_session(t0, saddr, StartKind::Cold, [0; 16]);

        // The round trip takes several seconds -- past PATH_DOWN_AFTER --
        // before the server's reply reaches the client, as a couple of lost
        // msg1 retransmits genuinely would in production.
        let slow = t0 + PATH_DOWN_AFTER + Duration::from_secs(1);
        let mut m2 = Vec::new();
        for dg in m1 {
            m2.extend(server.on_datagram(slow, caddr, &dg.bytes));
        }
        for dg in m2 {
            let _ = client.on_datagram(slow, saddr, &dg.bytes);
        }

        // Right as the handshake finishes, the road must read as freshly
        // alive, not already quiet for however long the handshake took.
        let _ = client.on_timeout(slow);
        assert!(
            !client
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StateChanged(LinkState::PathDown))),
            "a slow handshake must not immediately look like the road went quiet"
        );
    }

    /// Bytes queued on a stream count as unacknowledged until the peer's
    /// cumulative ACK passes them, and as queued for good. The pair is what
    /// tells "nothing written yet" from "written and delivered" -- both have
    /// nothing unacknowledged.
    #[test]
    fn stream_progress_tells_nothing_written_from_all_delivered() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = Instant::now();
        assert_eq!(client.stream_progress(15), StreamProgress::default());
        let out = client.send(now, 15, &[7u8; 3000]);
        assert_eq!(
            client.stream_progress(15),
            StreamProgress {
                queued: 3000,
                unacked: 3000
            }
        );
        let mut acks = Vec::new();
        for dg in out {
            acks.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        acks.extend(held_acks(&mut server, now));
        deliver(&mut client, now, saddr, acks);
        assert_eq!(
            client.stream_progress(15),
            StreamProgress {
                queued: 3000,
                unacked: 0
            }
        );
    }

    /// The rule every loop around a `Connection` follows (spec §4.1): run the
    /// timers once one of their deadlines has passed, and not before.
    #[test]
    fn on_timeout_if_due_runs_the_timers_only_once_a_deadline_has_passed() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let t0 = client.handshake_at;
        assert!(
            client.on_timeout_if_due(t0).is_empty(),
            "nothing is due at the handshake"
        );
        assert!(client.outstanding_pings.is_empty());
        let due = client
            .next_timeout()
            .expect("a live connection has a deadline");
        assert!(
            client
                .on_timeout_if_due(due - Duration::from_millis(1))
                .is_empty(),
            "a millisecond early is not due"
        );
        let out = client.on_timeout_if_due(t0 + PING_INTERVAL);
        assert!(
            !out.is_empty() && !client.outstanding_pings.is_empty(),
            "the PING goes out once it is due"
        );
    }

    /// The simulator counts frames by kind without disturbing anything: a
    /// peeked datagram still delivers, and only the addressee can read it.
    #[test]
    fn peek_frames_reads_a_datagram_without_consuming_it() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        assert_eq!(client.state(), LinkState::Live);
        let now = client.handshake_at;
        let out = client.send(now, 3, b"peek");
        assert_eq!(out.len(), 1);
        assert_eq!(
            server.peek_frames(&out[0].bytes),
            Some(vec![StreamFrame::Data {
                stream_id: 3,
                offset: 0,
                data: b"peek".to_vec(),
            }])
        );
        assert_eq!(
            client.peek_frames(&out[0].bytes),
            None,
            "a side cannot read what it sent: the keys differ by direction"
        );
        deliver(&mut server, now, caddr, out);
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 3),
            b"peek",
            "peeking consumed nothing: the datagram still delivers"
        );
    }

    /// A simulator in virtual time stamps a new connection itself: nothing in
    /// it comes from the real clock.
    #[test]
    fn new_at_stamps_the_given_instant_not_the_real_clock() {
        let kp = generate_keypair();
        let at = Instant::now() + Duration::from_secs(3600);
        let conn = Connection::new_at(
            ConnectionConfig {
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            at,
        );
        assert_eq!(conn.handshake_at, at);
        assert_eq!(conn.last_recv_auth, at);
    }

    /// Spec §4.2 / §9.2 (defects 9.2, 9.3): a side busy acknowledging an
    /// inbound flow retransmits its own lost segment `rto` after it went out,
    /// not whenever its acknowledgements happen to stop.
    #[test]
    fn a_lost_segment_is_retransmitted_rto_after_it_went_out_while_acks_flow_the_other_way() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = client.handshake_at;
        let rto = client.rto();
        let lost = client.send(t0, 0, b"lost");
        assert_eq!(lost.len(), 1, "one segment, and it is dropped");
        let mut retransmitted_at = None;
        let mut now = t0;
        while now < t0 + Duration::from_secs(2) && retransmitted_at.is_none() {
            now += Duration::from_millis(10);
            let mut from_client = Vec::new();
            // The server streams output every 50 ms; the client acknowledges each piece.
            if (now - t0).as_millis().is_multiple_of(50) {
                for dg in server.send(now, 16, b".") {
                    from_client.extend(client.on_datagram(now, saddr, &dg.bytes));
                }
            }
            from_client.extend(client.on_timeout_if_due(now));
            for dg in from_client {
                let resent = server.peek_frames(&dg.bytes).is_some_and(|frames| {
                    frames
                        .iter()
                        .any(|f| matches!(f, StreamFrame::Data { stream_id: 0, .. }))
                });
                if resent && retransmitted_at.is_none() {
                    retransmitted_at = Some(now);
                }
                let _ = server.on_datagram(now, caddr, &dg.bytes);
            }
        }
        let at = retransmitted_at.expect("the lost segment was retransmitted within two seconds");
        assert!(
            at - t0 >= rto && at - t0 <= rto + Duration::from_millis(10),
            "retransmitted {:?} after it went out; rto is {rto:?}",
            at - t0
        );
    }

    /// Spec §4.2 (ACK clocking): an ACK that frees room in a full window sends
    /// the next bytes in the same call, not on the next timer.
    #[test]
    fn an_ack_that_opens_the_window_sends_the_next_bytes_at_once() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let first = client.send(now, 20, &vec![7u8; MAX_IN_FLIGHT + 64 * 1024]);
        let first_flight = data_streams(&server, &first).len() * 1024;
        let mut acks = Vec::new();
        for dg in first {
            acks.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        let mut next = Vec::new();
        for dg in acks {
            next.extend(client.on_datagram(now, saddr, &dg.bytes));
        }
        let past_the_first_flight = next
            .iter()
            .filter_map(|dg| server.peek_frames(&dg.bytes))
            .flatten()
            .any(|f| {
                matches!(f, StreamFrame::Data { stream_id: 20, offset, .. }
                    if offset as usize >= first_flight)
            });
        assert!(
            past_the_first_flight,
            "an ACK that frees window room must send the next bytes in the same breath"
        );
    }

    /// `next_timeout` must agree with `on_timeout` about when the next PING is
    /// due, across the backoff boundary too: with the timer rule of spec §4.1
    /// a deadline that `on_timeout` does not consume would wake every driver
    /// loop every millisecond. It did: `next_timeout` judged the interval at
    /// the last PING, `on_timeout` at `now`, so a last PING taken just before
    /// `PING_BACKOFF_AFTER` left a lively deadline that the backed-off
    /// `on_timeout` refused for 13.5 s.
    #[test]
    fn the_ping_deadline_agrees_with_on_timeout_across_the_backoff_boundary() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        client.set_death_after(Duration::from_secs(2 * 60 * 60));
        let t0 = client.handshake_at;
        let mut now = t0;
        while now < t0 + Duration::from_secs(90) {
            let next = client
                .next_timeout()
                .expect("a connection waiting out an outage has a deadline");
            now = now.max(next);
            let _ = client.on_timeout(now);
            assert!(
                client.next_timeout().is_some_and(|n| n > now),
                "a deadline at {:?} was still due after on_timeout",
                now - t0
            );
        }
    }

    /// Something queued but never sent while `Live` is due at once: a loop
    /// that no longer ticks on its own would otherwise leave it until the
    /// next PING. And once `on_timeout` has sent it, nothing is due.
    #[test]
    fn queued_but_unsent_output_is_due_at_once_while_live() {
        let (_client, mut server, _caddr, _saddr) = established_pair();
        let now = server.handshake_at + Duration::from_millis(100);
        let before = server
            .next_timeout()
            .expect("a live connection has a deadline");
        assert!(before > now, "nothing is due on a quiet link");
        // Arms a Reset without sending it -- the one way to hold unsent
        // output while `Live`.
        server.mark_output_desynced_for_test();
        assert!(
            server.next_timeout().is_some_and(|d| d <= now),
            "the armed Reset is due now"
        );
        let out = server.on_timeout_if_due(now);
        assert!(!out.is_empty(), "the Reset went out");
        assert!(
            server.next_timeout().is_some_and(|d| d > now),
            "and nothing is due any more"
        );
    }

    /// `next_timeout` wakes for the earliest retransmit over every stream,
    /// not for the first or last stream it happens to look at.
    #[test]
    fn next_timeout_takes_the_earliest_retransmit_over_all_streams() {
        let (_client, mut server, _caddr, _saddr) = established_pair();
        let t0 = server.handshake_at;
        let rto = server.rto();
        // Streams sent in an order that is neither the map's nor its reverse.
        let _ = server.send(t0 + Duration::from_millis(30), 7, b"late");
        let _ = server.send(t0 + Duration::from_millis(10), 21, b"early");
        let _ = server.send(t0 + Duration::from_millis(20), 3, b"middle");
        // The other deadlines are all later than the earliest retransmit.
        assert!(rto < PING_INTERVAL && rto < PATH_DOWN_AFTER);
        assert_eq!(
            server.next_timeout(),
            Some(t0 + Duration::from_millis(10) + rto)
        );
    }

    /// A loop that wakes a little LATE across the backoff boundary must not
    /// find the PING deadline still due after `on_timeout`: the lively
    /// deadline falls just before `PING_BACKOFF_AFTER`, the wake-up just
    /// after it. When `next_timeout` and `on_timeout` judged the interval at
    /// different moments, this left a deadline in the past for 13.5 s -- a
    /// bridge `sleep(0)` spin, a client waking every millisecond.
    #[test]
    fn a_late_wake_across_the_backoff_boundary_leaves_no_ping_deadline_due() {
        for late_us in [1u64, 500, 1_000, 5_000, 20_000] {
            let (mut client, _server, _caddr, _saddr) = established_pair();
            client.set_death_after(Duration::from_secs(2 * 60 * 60));
            let lra = client.last_recv_auth;
            client.state = LinkState::PathDown;
            client.last_recv_ordinary = lra;
            let deadline = lra + PING_BACKOFF_AFTER - Duration::from_micros(late_us / 2 + 1);
            client.last_ping_sent = Some(deadline - PING_INTERVAL);
            client.outstanding_pings.clear();
            assert_eq!(client.next_timeout(), Some(deadline), "the lively deadline");
            let now = lra + PING_BACKOFF_AFTER + Duration::from_micros(late_us / 2);
            let _ = client.on_timeout(now);
            assert!(
                client.next_timeout().is_some_and(|n| n > now),
                "{late_us} us late: a deadline was still due after on_timeout"
            );
        }
    }

    /// The same agreement over a long outage whose loop always wakes late,
    /// by an amount that varies from wake to wake (up to 80 ms) -- many such
    /// runs, whose PINGs drift by their accumulated lateness, so that some of
    /// them wake across the backoff boundary.
    #[test]
    fn late_wakes_over_a_long_outage_never_leave_a_deadline_due() {
        for step_us in (1u64..=400).map(|k| k * 197) {
            let (mut client, _server, _caddr, _saddr) = established_pair();
            client.set_death_after(Duration::from_secs(2 * 60 * 60));
            let t0 = client.handshake_at;
            let mut now = t0;
            let mut late = 0u64;
            while now < t0 + Duration::from_secs(75) {
                let next = client
                    .next_timeout()
                    .expect("a connection waiting out an outage has a deadline");
                late = (late + step_us) % 80_000;
                now = now.max(next) + Duration::from_micros(late);
                let _ = client.on_timeout(now);
                assert!(
                    client.next_timeout().is_some_and(|n| n > now),
                    "waking late by steps of {step_us} us: a deadline at {:?} was still due",
                    now - t0
                );
            }
        }
    }

    /// A client and a server whose handshake takes `trip` each way, driven by
    /// hand from `t0`. `retransmit` has the client report a msg1 retransmit
    /// before msg2 arrives (as `driver_std` does).
    fn handshake_taking(
        trip: Duration,
        retransmit: bool,
    ) -> (Connection, Connection, SocketAddr, SocketAddr, Instant) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });
        let t0 = Instant::now();
        let m1 = client.start_session(t0, saddr, StartKind::Cold, [0; 16]);
        if retransmit {
            // The same msg1 again; delivering `m1` once stands for either copy.
            assert_eq!(client.retransmit_handshake(), m1);
        }
        let mut m2 = Vec::new();
        for dg in m1 {
            m2.extend(server.on_datagram(t0 + trip, caddr, &dg.bytes));
        }
        for dg in m2 {
            let _ = client.on_datagram(t0 + trip * 2, saddr, &dg.bytes);
        }
        (client, server, caddr, saddr, t0)
    }

    /// `established_pair`, but with nothing measured: the client's msg1 counts
    /// as retransmitted, so the handshake seeds no round trip (Karn).
    fn established_pair_unmeasured() -> (Connection, Connection, SocketAddr, SocketAddr) {
        let (client, server, caddr, saddr, _) = handshake_taking(Duration::ZERO, true);
        (client, server, caddr, saddr)
    }

    /// Spec §4.3: the client seeds the round trip from msg1 -> msg2.
    #[test]
    fn the_handshake_round_trip_seeds_the_measurement() {
        let (client, _server, _caddr, _saddr, t0) =
            handshake_taking(Duration::from_millis(40), false);
        assert_eq!(
            client.rtt(),
            Some(RttSample {
                value: Duration::from_millis(80),
                source: RttSource::Handshake,
            })
        );
        assert_eq!(
            client.rto(),
            DEFAULT_RTO,
            "2 x 80 ms, floored at the unmeasured default: the seed crossed an empty queue"
        );
        assert_eq!(client.stats(t0 + Duration::from_millis(80)).rtt_ms, 80);
    }

    /// Final review, Important 1: the handshake crosses an empty queue, so its
    /// round trip is a floor under the one a bulk write right after it meets.
    /// It may raise the retransmit timeout above `DEFAULT_RTO`, never lower it.
    #[test]
    fn a_handshake_seed_only_raises_the_retransmit_timeout_above_the_default() {
        let (client, _server, _caddr, _saddr, _t0) =
            handshake_taking(Duration::from_millis(300), false);
        assert_eq!(client.rtt().map(|s| s.source), Some(RttSource::Handshake));
        assert_eq!(client.rto(), Duration::from_millis(1200), "2 x 600 ms");
    }

    /// The floor is the handshake's alone: once a PONG has measured the road
    /// under whatever load it carries, 2 x a short round trip counts again.
    #[test]
    fn a_pong_measured_round_trip_is_floored_at_200_ms_again() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(40), false);
        assert_eq!(client.rto(), DEFAULT_RTO);
        let pinged = t0 + Duration::from_millis(80) + PING_INTERVAL;
        let pings = client.on_timeout(pinged);
        let pongs = deliver_and_collect(&mut server, pinged, caddr, pings);
        deliver(
            &mut client,
            pinged + Duration::from_millis(60),
            saddr,
            pongs,
        );
        assert_eq!(
            client.rto(),
            Duration::from_millis(200),
            "2 x 60 ms, floored"
        );
    }

    /// Send `data` on stream 0 from `client` at `sent` and have the server's
    /// ACK reach it at `acked`.
    fn ack_one_write(
        client: &mut Connection,
        server: &mut Connection,
        caddr: SocketAddr,
        saddr: SocketAddr,
        sent: Instant,
        acked: Instant,
    ) {
        let out = client.send(sent, 0, b"bulk");
        let mut acks = deliver_and_collect(server, sent, caddr, out);
        // The server holds the ACK of a lone segment (spec §4.11); the
        // round trip is the moment it reaches the client, `acked`.
        acks.extend(held_acks(server, sent));
        deliver(client, acked, saddr, acks);
    }

    /// Round 2 of the final review's Important 1: a data segment acknowledged
    /// without having been retransmitted times the round trip under the load
    /// it carries (RFC 6298, Karn), and the retransmit timeout follows it:
    /// SRTT + 4 x RTTVAR = 400 + 4 x 200 ms.
    #[test]
    fn an_acknowledged_segment_times_the_retransmit_timeout() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(20), false);
        assert_eq!(client.rto(), DEFAULT_RTO, "the seed alone");
        ack_one_write(
            &mut client,
            &mut server,
            caddr,
            saddr,
            t0,
            t0 + Duration::from_millis(400),
        );
        assert_eq!(client.rto(), Duration::from_millis(1200));
    }

    /// Road liveness and the header keep reading the PONG (here the seed):
    /// a queue a bulk write built must neither slow the dead-road rule down
    /// nor make the header jump with every acknowledged segment.
    #[test]
    fn an_acknowledged_segment_leaves_the_displayed_round_trip_and_liveness_alone() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(20), false);
        let acked = t0 + Duration::from_secs(4);
        ack_one_write(&mut client, &mut server, caddr, saddr, t0, acked);
        assert_eq!(
            client.rtt(),
            Some(RttSample {
                value: Duration::from_millis(40),
                source: RttSource::Handshake,
            })
        );
        assert_eq!(client.stats(acked).rtt_ms, 40);
        assert_eq!(client.liveness_rto(), DEFAULT_RTO);
        assert_eq!(client.unanswered_after(acked), PING_INTERVAL);
    }

    /// A round trip the retransmit timer measures may take it past the 3 s
    /// ceiling of road liveness -- a 256 KiB window stands 4 s deep in a
    /// 64 KB/s uplink's queue -- up to `RETRANSMIT_CEILING`.
    #[test]
    fn a_deep_queue_takes_the_retransmit_timeout_past_three_seconds_up_to_its_own_ceiling() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(20), false);
        ack_one_write(
            &mut client,
            &mut server,
            caddr,
            saddr,
            t0,
            t0 + Duration::from_secs(4),
        );
        assert_eq!(client.rto(), Duration::from_secs(12), "4 s + 4 x 2 s");
        assert_eq!(client.liveness_rto(), DEFAULT_RTO);
        let later = t0 + Duration::from_secs(5);
        ack_one_write(
            &mut client,
            &mut server,
            caddr,
            saddr,
            later,
            later + Duration::from_secs(12),
        );
        assert_eq!(client.rto(), RETRANSMIT_CEILING);
    }

    /// RFC 6298 §5.5: every expiry of the retransmit timer -- the oldest
    /// unacknowledged segment going out again -- doubles the timeout; the
    /// segments behind it falling due do not count again. A new round trip
    /// measured resets the back-off.
    #[test]
    fn each_expiry_doubles_the_retransmit_timeout_until_a_round_trip_is_measured() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(20), false);
        let _lost = client.send(t0, 0, b"first");
        let _lost = client.send(t0 + Duration::from_millis(100), 0, b"second");
        assert_eq!(client.rto(), DEFAULT_RTO);
        let first_expiry = t0 + DEFAULT_RTO;
        assert!(
            !client.on_timeout(first_expiry).is_empty(),
            "the oldest went out again"
        );
        assert_eq!(client.rto(), DEFAULT_RTO * 2);
        // The second segment's own deadline (100 ms + 1 s) passes: it goes
        // out again, and that is not another expiry.
        let behind = t0 + Duration::from_millis(1100);
        let second = client.on_timeout(behind);
        assert!(!second.is_empty(), "the second went out again");
        assert_eq!(client.rto(), DEFAULT_RTO * 2);
        // The oldest is due again 1 s after its last send: a second expiry.
        let second_expiry = first_expiry + DEFAULT_RTO * 2;
        let first = client.on_timeout(second_expiry);
        assert!(!first.is_empty());
        assert_eq!(client.rto(), DEFAULT_RTO * 4);
        // Both resent copies arrive; the cumulative ACK covers resent
        // segments only, so it times nothing (Karn) and the back-off stays.
        let acked = second_expiry + Duration::from_millis(40);
        let acks = deliver_and_collect(&mut server, second_expiry, caddr, [second, first].concat());
        deliver(&mut client, acked, saddr, acks);
        assert_eq!(
            client.rto(),
            DEFAULT_RTO * 4,
            "an ACK over resent data times nothing"
        );
        // A fresh write acknowledged without a retransmit measures the road.
        let t2 = acked + Duration::from_millis(10);
        ack_one_write(
            &mut client,
            &mut server,
            caddr,
            saddr,
            t2,
            t2 + Duration::from_millis(40),
        );
        assert_eq!(
            client.rto(),
            RTO_FLOOR,
            "40 ms + 4 x 20 ms, floored; no back-off"
        );
    }

    /// Karn's rule: a reply to a retransmitted msg1 cannot say which copy it
    /// answers, so it seeds nothing.
    #[test]
    fn a_retransmitted_msg1_seeds_nothing() {
        let (client, _server, _caddr, _saddr, t0) =
            handshake_taking(Duration::from_millis(300), true);
        assert_eq!(client.rtt(), None);
        assert_eq!(client.rto(), DEFAULT_RTO);
        assert_eq!(client.stats(t0 + Duration::from_secs(1)).rtt_ms, 0);
    }

    /// A client, started (`Connecting`), the server address it dials, and
    /// the Noise msg1 body it sent.
    fn started_client() -> (Connection, SocketAddr, Vec<u8>) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let m1 = client.start_session(Instant::now(), saddr, StartKind::Cold, [4; 16]);
        let body = match parse(&m1[0].bytes) {
            Ok(Frame::Handshake {
                kind: Kind::HandshakeInit,
                body,
            }) => body.to_vec(),
            _ => panic!("msg1"),
        };
        (client, saddr, body)
    }

    fn echo_of(msg1: &[u8]) -> [u8; COOKIE_ECHO_LEN] {
        let mut echo = [0u8; COOKIE_ECHO_LEN];
        echo.copy_from_slice(&msg1[..COOKIE_ECHO_LEN]);
        echo
    }

    /// Spec §4.16: a cookie reply to this msg1 sends it again at once,
    /// behind the cookie, and the next retransmit carries the cookie too.
    /// The turns after that are
    /// `after_a_cookie_the_retransmits_take_turns_with_the_plain_msg1`.
    #[test]
    fn a_cookie_reply_sends_the_msg1_again_behind_the_cookie() {
        let (mut client, saddr, body) = started_client();
        assert_eq!(
            client.handshake_datagrams(),
            vec![Datagram {
                to: saddr,
                bytes: encode_handshake(Kind::HandshakeInit, &body),
            }],
            "before any cookie: the msg1 as it first went out"
        );
        let cookie = [0x5Au8; COOKIE_LEN];
        let out = client.on_datagram(
            Instant::now(),
            saddr,
            &encode_cookie_reply(&echo_of(&body), &cookie),
        );
        let behind = vec![Datagram {
            to: saddr,
            bytes: encode_handshake_init_cookie(&cookie, &body),
        }];
        assert_eq!(out, behind);
        assert_eq!(client.handshake_datagrams(), behind);
        assert_eq!(client.state(), LinkState::Connecting);
    }

    /// Review focus 1: a cookie that keeps failing (a NAT changing the port
    /// every packet) must not become a ping-pong at the round-trip rate. The
    /// second cookie goes out with the next retransmit, not at once.
    #[test]
    fn a_second_cookie_waits_for_the_retransmit_timer() {
        let (mut client, saddr, body) = started_client();
        let echo = echo_of(&body);
        let _ = client.on_datagram(
            Instant::now(),
            saddr,
            &encode_cookie_reply(&echo, &[1; COOKIE_LEN]),
        );
        let out = client.on_datagram(
            Instant::now(),
            saddr,
            &encode_cookie_reply(&echo, &[2; COOKIE_LEN]),
        );
        assert!(out.is_empty(), "nothing at once for a second cookie");
        assert_eq!(
            client.handshake_datagrams(),
            vec![Datagram {
                to: saddr,
                bytes: encode_handshake_init_cookie(&[2; COOKIE_LEN], &body),
            }],
            "the retransmit carries the newest cookie"
        );
    }

    /// Review of slice 3, minor 1: a party that sees msg1 and can inject
    /// may answer it with a cookie of its own, and a daemon built before
    /// cookies drops every msg1 behind one. So once a cookie is taken the
    /// retransmits do not all carry it: the first does (the copy sent at
    /// once may be only moments old), then the plain msg1 and the msg1
    /// behind the newest cookie take turns. A later cookie changes the
    /// cookie, not the turns. Every copy counts as a retransmit (Karn).
    #[test]
    fn after_a_cookie_the_retransmits_take_turns_with_the_plain_msg1() {
        let (mut client, saddr, body) = started_client();
        let plain = vec![Datagram {
            to: saddr,
            bytes: encode_handshake(Kind::HandshakeInit, &body),
        }];
        let behind = |cookie: [u8; COOKIE_LEN]| {
            vec![Datagram {
                to: saddr,
                bytes: encode_handshake_init_cookie(&cookie, &body),
            }]
        };
        assert_eq!(client.retransmit_handshake(), plain, "no cookie yet");
        assert_eq!(client.retransmit_handshake(), plain, "no cookie yet");
        let echo = echo_of(&body);
        let now = Instant::now();
        let at_once = client.on_datagram(now, saddr, &encode_cookie_reply(&echo, &[1; COOKIE_LEN]));
        assert_eq!(at_once, behind([1; COOKIE_LEN]));
        assert_eq!(client.retransmit_handshake(), behind([1; COOKIE_LEN]));
        assert_eq!(client.retransmit_handshake(), plain);
        assert_eq!(client.retransmit_handshake(), behind([1; COOKIE_LEN]));
        // A second cookie waits for its turn, and changes only the cookie.
        assert!(client
            .on_datagram(now, saddr, &encode_cookie_reply(&echo, &[2; COOKIE_LEN]))
            .is_empty());
        assert_eq!(client.retransmit_handshake(), plain);
        assert_eq!(client.retransmit_handshake(), behind([2; COOKIE_LEN]));
        assert_eq!(client.retransmit_handshake(), plain);
        assert_eq!(client.state(), LinkState::Connecting);
    }

    /// Review focus 2: a reply that does not answer THIS msg1 -- another
    /// echo, another address, a mangled body -- changes nothing; after
    /// `Live`, at a server, and at a client playing an old build, a cookie
    /// reply is nothing at all. (After `Live` and at a server with the
    /// msg1's own echo, so that the echo check is not what refuses it:
    /// `a_reply_to_this_msg1_is_nothing_once_the_handshake_is_over`.)
    #[test]
    fn a_cookie_reply_that_does_not_answer_this_msg1_changes_nothing() {
        let (mut client, saddr, body) = started_client();
        let plain = client.handshake_datagrams();
        let mut wrong = echo_of(&body);
        wrong[0] ^= 0xFF;
        for (from, reply) in [
            (saddr, encode_cookie_reply(&wrong, &[1; COOKIE_LEN])),
            (
                addr("198.51.100.9:41000"),
                encode_cookie_reply(&echo_of(&body), &[1; COOKIE_LEN]),
            ),
            (
                saddr,
                encode_handshake(Kind::CookieReply, &[COOKIE_VERSION, 1, 2]),
            ),
        ] {
            assert!(
                client.on_datagram(Instant::now(), from, &reply).is_empty(),
                "from {from}"
            );
            assert_eq!(client.handshake_datagrams(), plain, "from {from}");
        }
        let (mut live, mut server, _caddr, saddr) = established_pair();
        let stray = encode_cookie_reply(&[0; COOKIE_ECHO_LEN], &[1; COOKIE_LEN]);
        assert!(live.on_datagram(Instant::now(), saddr, &stray).is_empty());
        assert!(live.handshake_datagrams().is_empty());
        assert!(server.on_datagram(Instant::now(), saddr, &stray).is_empty());
        let (mut old, saddr, body) = started_client();
        old.act_as_legacy_peer_for_test();
        let plain = old.handshake_datagrams();
        assert!(old
            .on_datagram(
                Instant::now(),
                saddr,
                &encode_cookie_reply(&echo_of(&body), &[1; COOKIE_LEN])
            )
            .is_empty());
        assert_eq!(
            old.handshake_datagrams(),
            plain,
            "an old parser does not know the kind"
        );
    }

    /// Review of Task 8, minor 1: a reply that DOES answer this client's
    /// msg1 -- its own echo, from the address the msg1 went to -- is nothing
    /// once the handshake is over. A live client still holds its msg1, so
    /// the echo check would let the reply through: the state (`Connecting`)
    /// and handshake guards are what refuse it. At the server, the echo of
    /// the msg1 it answered is refused too -- by its role, and because a
    /// server holds no msg1 of its own.
    #[test]
    fn a_reply_to_this_msg1_is_nothing_once_the_handshake_is_over() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });
        let now = Instant::now();
        let m1 = client.start_session(now, saddr, StartKind::Cold, [4; 16]);
        let body = match parse(&m1[0].bytes) {
            Ok(Frame::Handshake { body, .. }) => body.to_vec(),
            _ => panic!("msg1"),
        };
        let m2 = server.on_datagram(now, caddr, &m1[0].bytes);
        deliver(&mut client, now, saddr, m2);
        assert_eq!(client.state(), LinkState::Live);

        let reply = encode_cookie_reply(&echo_of(&body), &[1; COOKIE_LEN]);
        assert!(client.on_datagram(now, saddr, &reply).is_empty());
        assert_eq!(client.cookie_for_test(), None, "a live client takes none");
        assert!(client.handshake_datagrams().is_empty());
        assert!(server.on_datagram(now, caddr, &reply).is_empty());
        assert_eq!(server.cookie_for_test(), None, "a server takes none");
        assert_eq!(server.state(), LinkState::Live);
    }

    /// Karn: once a cookie was taken, two different msg1 datagrams were
    /// out, and msg2 may answer either -- no round trip is seeded.
    #[test]
    fn a_handshake_through_a_cookie_seeds_no_round_trip() {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let caddr = addr("198.51.100.7:40000");
        let saddr = addr("198.51.100.1:41000");
        let mut client = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        let mut server = Connection::new(ConnectionConfig {
            features: Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_kp.public]),
        });
        let t0 = Instant::now();
        let m1 = client.start_session(t0, saddr, StartKind::Cold, [4; 16]);
        let body = match parse(&m1[0].bytes) {
            Ok(Frame::Handshake { body, .. }) => body.to_vec(),
            _ => panic!("msg1"),
        };
        let again = client.on_datagram(
            t0 + Duration::from_millis(40),
            saddr,
            &encode_cookie_reply(&echo_of(&body), &[7; COOKIE_LEN]),
        );
        assert_eq!(again.len(), 1);
        // The daemon takes the cookie off: the connection behind it sees plain msg1.
        let m2 = server.on_datagram(
            t0 + Duration::from_millis(60),
            caddr,
            &encode_handshake(Kind::HandshakeInit, &body),
        );
        deliver(&mut client, t0 + Duration::from_millis(80), saddr, m2);
        assert_eq!(client.state(), LinkState::Live);
        assert_eq!(client.rtt(), None);
    }

    /// A handshake started afresh forgets the cookie of the one before: that
    /// cookie was bound to the old msg1's ephemeral key, and the new msg1
    /// goes out plain, retransmits and all, until a cookie answers IT.
    #[test]
    fn a_new_handshake_forgets_the_cookie_of_the_old_one() {
        let (mut client, saddr, body) = started_client();
        let _ = client.on_datagram(
            Instant::now(),
            saddr,
            &encode_cookie_reply(&echo_of(&body), &[1; COOKIE_LEN]),
        );
        let fresh = client.start_session(Instant::now(), saddr, StartKind::Cold, [4; 16]);
        assert_eq!(client.handshake_datagrams(), fresh);
    }

    /// Review focus: the seed lasts only until the first PONG.
    #[test]
    fn the_first_pong_replaces_the_handshake_seed() {
        let (mut client, mut server, caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(40), false);
        let pinged = t0 + Duration::from_millis(80) + PING_INTERVAL;
        let pings = client.on_timeout(pinged);
        assert!(!pings.is_empty(), "the PING is due");
        let pongs = deliver_and_collect(&mut server, pinged, caddr, pings);
        deliver(
            &mut client,
            pinged + Duration::from_millis(20),
            saddr,
            pongs,
        );
        assert_eq!(
            client.rtt(),
            Some(RttSample {
                value: Duration::from_millis(20),
                source: RttSource::Ping,
            })
        );
    }

    /// Starting again forgets the previous handshake's measurement: a new
    /// session must not show, or time its PINGs by, the old one's round trip.
    #[test]
    fn starting_again_forgets_the_previous_round_trip() {
        let (mut client, _server, _caddr, saddr, t0) =
            handshake_taking(Duration::from_millis(40), false);
        assert!(client.rtt().is_some(), "the handshake seeded a round trip");
        let _ = client.start_session(t0 + Duration::from_secs(5), saddr, StartKind::Cold, [0; 16]);
        assert_eq!(client.rtt(), None);
        assert_eq!(client.rto(), DEFAULT_RTO);
        assert_eq!(client.stats(t0 + Duration::from_secs(5)).rtt_ms, 0);
    }

    /// Spec §9.2 (4 / 9.1): 300 µs is a measurement, not "nothing measured".
    #[test]
    fn a_round_trip_under_a_millisecond_is_a_measurement() {
        let (mut client, mut server, caddr, saddr) = established_pair_unmeasured();
        let pinged = client.handshake_at + PING_INTERVAL;
        let pings = client.on_timeout(pinged);
        assert!(!pings.is_empty(), "the PING is due");
        let pongs = deliver_and_collect(&mut server, pinged, caddr, pings);
        let ponged = pinged + Duration::from_micros(300);
        deliver(&mut client, ponged, saddr, pongs);
        assert_eq!(
            client.rtt().map(|s| s.value),
            Some(Duration::from_micros(300))
        );
        assert_eq!(client.rto(), Duration::from_millis(200));
        assert_eq!(client.stats(ponged).rtt_ms, 1);
    }

    /// Spec §4.3 (defect 4): before anything is measured, a PING is unanswered
    /// only once it is older than the 3 s ceiling, not the 1.5 s interval.
    #[test]
    fn before_anything_is_measured_a_ping_is_unanswered_only_past_the_rto_ceiling() {
        let (mut client, _server, _caddr, _saddr) = established_pair_unmeasured();
        let t0 = client.handshake_at;
        let _ = client.on_timeout(t0 + PING_INTERVAL);
        let _ = client.on_timeout(t0 + PING_INTERVAL * 2);
        assert!(
            !client.ping_unanswered,
            "a PING 1.5 s old is not overdue while the road is unmeasured"
        );
        let _ = client.on_timeout(t0 + PING_INTERVAL * 3);
        assert!(client.ping_unanswered, "one 3 s old is");
    }

    /// Spec §4.14 (without `offset-wrap`): the connection says so once per
    /// stream, however many writes are refused after the first.
    #[test]
    fn a_write_past_the_offset_limit_is_reported_once() {
        let (_client, mut server, _caddr, _saddr) =
            handshake_with_features(Features::HEADER_AAD, Features::HEADER_AAD, false);
        let now = server.handshake_at;
        server.start_stream_at_for_test(20, OFFSET_LIMIT - 10);
        let _ = server.poll_events();
        let _ = server.send(now, 20, &[1u8; 10]);
        assert!(server.poll_events().is_empty(), "up to the limit is fine");
        let _ = server.send(now, 20, &[2u8]);
        let _ = server.send(now, 20, &[3u8]);
        assert_eq!(
            server.poll_events(),
            vec![Event::OffsetSpaceExhausted { stream_id: 20 }]
        );
        assert_eq!(server.stream_progress(20).queued, u64::from(OFFSET_LIMIT));
    }

    /// `abandon` drops the connection without telling the peer.
    #[test]
    fn abandon_closes_without_a_close_frame() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let _ = client.poll_events();
        client.abandon();
        assert_eq!(client.state(), LinkState::Closed);
        assert!(!client.closed_gracefully());
        assert_eq!(
            client.poll_events(),
            vec![Event::StateChanged(LinkState::Closed)]
        );
        assert!(
            client.close(client.handshake_at).is_empty(),
            "nothing left to say"
        );
    }

    /// The streams each DATA frame of `out` belongs to, in order, as the
    /// peer `reader` decrypts them.
    fn data_streams(reader: &Connection, out: &[Datagram]) -> Vec<u8> {
        out.iter()
            .filter_map(|dg| reader.peek_frames(&dg.bytes))
            .flatten()
            .filter_map(|f| match f {
                StreamFrame::Data { stream_id, .. } => Some(stream_id),
                _ => None,
            })
            .collect()
    }

    /// Spec §4.8, and the slice-1 review: a PING and the road checks go out
    /// before the data a timer flushes, or on a slow uplink they wait behind
    /// it. With §4.11 the PING leads that data in the same datagram as the
    /// first segment: every segment's retransmit timer has run out by the
    /// PING's moment, and the oldest goes again in that turn.
    #[test]
    fn on_timeout_puts_the_ping_ahead_of_the_data_it_flushes() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let t0 = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        // Nothing is acknowledged: by the PING's moment every segment is due again.
        let _ = client.send(t0, 14, &vec![1u8; 8 * 1024]);
        let out = client.on_timeout(t0 + PING_INTERVAL);
        let kinds: Vec<&str> = out
            .iter()
            .filter_map(|dg| server.peek_frames(&dg.bytes))
            .flatten()
            .map(|f| match f {
                StreamFrame::Ping { .. } => "ping",
                StreamFrame::Data { .. } => "data",
                _ => "other",
            })
            .collect();
        let ping = kinds
            .iter()
            .position(|k| *k == "ping")
            .expect("the PING is due");
        let data = kinds
            .iter()
            .position(|k| *k == "data")
            .expect("the data is due again");
        assert!(ping < data, "{kinds:?}");
        let first = frames_read_by(&server, &out[..1]);
        assert!(
            matches!(first.first(), Some(StreamFrame::Ping { .. })),
            "{first:?}"
        );
        assert!(
            first.iter().any(|f| matches!(f, StreamFrame::Data { .. })),
            "the PING shares its datagram with the data: {first:?}"
        );
    }

    /// Spec §4.8: interactive streams take turns, `RR_QUANTUM` segments each.
    #[test]
    fn interactive_streams_take_turns_four_segments_at_a_time() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        for id in [16u8, 17] {
            client
                .stream_mut(id)
                .sender
                .push(&vec![id; 6 * 1024])
                .expect("room");
        }
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        assert_eq!(
            data_streams(&server, &out),
            vec![16, 16, 16, 16, 17, 17, 17, 17, 16, 16, 17, 17]
        );
    }

    /// Spec §4.8: in one flush the interactive class goes first.
    #[test]
    fn interactive_data_goes_before_bulk_in_one_flush() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client
            .stream_mut(14)
            .sender
            .push(&[0u8; 4 * 1024])
            .expect("room");
        client
            .stream_mut(16)
            .sender
            .push(&[1u8; 2 * 1024])
            .expect("room");
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        let order = data_streams(&server, &out);
        assert_eq!(&order[..2], &[16, 16], "{order:?}");
        assert!(order[2..].iter().all(|s| *s == 14), "{order:?}");
    }

    /// Spec §4.8: one flush gives the bulk class at most `BULK_FLUSH_BUDGET`
    /// datagrams; what is left is due at once, so the driver takes its
    /// commands (keystrokes) and comes straight back for more.
    #[test]
    fn a_flush_puts_out_at_most_32_bulk_datagrams_and_stays_due() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client
            .stream_mut(14)
            .sender
            .push(&vec![0u8; 64 * 1024])
            .expect("room");
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        assert_eq!(data_streams(&server, &out).len(), BULK_FLUSH_BUDGET);
        assert!(
            client.next_timeout().is_some_and(|t| t <= now),
            "the rest is due at once"
        );
        let more = client.on_timeout(now);
        assert_eq!(data_streams(&server, &more).len(), BULK_FLUSH_BUDGET);
    }

    /// Spec §4.8: the round-robin cursor survives between flushes -- the next
    /// flush starts with the stream after the one served last.
    #[test]
    fn bulk_round_robin_resumes_after_the_stream_served_last() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        for id in [12u8, 13, 14] {
            client.set_stream_class(id, StreamClass::Bulk);
            client
                .stream_mut(id)
                .sender
                .push(&vec![id; 64 * 1024])
                .expect("room");
        }
        let mut first = Vec::new();
        client.flush_senders(now, &mut first);
        // 32 = two rounds of three streams (24) and one more turn each for 12 and 13.
        let order = data_streams(&server, &first);
        assert_eq!(order.len(), 32);
        assert_eq!(&order[24..], &[12, 12, 12, 12, 13, 13, 13, 13]);
        let mut second = Vec::new();
        client.flush_senders(now, &mut second);
        assert_eq!(data_streams(&server, &second)[0], 14, "resumes after 13");
    }

    /// Spec §4.8: lost segments the bulk budget left over are due at once
    /// while `Live`, like new bytes -- they have no deadline of their own
    /// any more, so nothing else would wake the driver for them. Restated at
    /// the congestion window (spec §4.15): the timeout itself resends only
    /// the oldest segment; once the window is open again, the rest go out
    /// `BULK_FLUSH_BUDGET` at a time, due at once in between.
    #[test]
    fn lost_segments_left_over_by_the_bulk_budget_go_out_on_the_immediate_wake_up() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client
            .stream_mut(14)
            .sender
            .push(&vec![0u8; 64 * 1024])
            .expect("room");
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        let _ = client.on_timeout(now);
        assert_eq!(
            client.stream_mut(14).sender.pipe(),
            64 * 1024,
            "all sent once"
        );
        let offsets = |out: &[Datagram]| -> Vec<u32> {
            out.iter()
                .filter_map(|dg| server.peek_frames(&dg.bytes))
                .flatten()
                .filter_map(|f| match f {
                    StreamFrame::Data { offset, .. } => Some(offset),
                    _ => None,
                })
                .collect()
        };
        // Nothing is acknowledged: one `rto` later every segment is lost.
        let t = now + client.rto();
        assert!(t < now + PATH_DOWN_AFTER, "still Live");
        let first = client.on_timeout(t);
        assert_eq!(offsets(&first), vec![0], "the timeout resends the oldest");
        client.open_congestion_window_for_test();
        assert!(
            client.next_timeout().is_some_and(|d| d <= t),
            "lost segments with room in the window are due at once"
        );
        let second = offsets(&client.on_timeout(t));
        assert_eq!(second.len(), BULK_FLUSH_BUDGET);
        assert!(
            second.iter().all(|o| *o >= 1024 && *o < 33 * 1024),
            "the oldest lost ones first: {second:?}"
        );
        assert!(
            client.next_timeout().is_some_and(|d| d <= t),
            "the lost segments the budget left over are due at once"
        );
        let third = offsets(&client.on_timeout(t));
        assert_eq!(third.len(), 31);
        assert!(
            third.iter().all(|o| *o >= 33 * 1024 && *o < 64 * 1024),
            "the rest goes out again: {third:?}"
        );
        assert!(
            client.next_timeout().is_some_and(|d| d > t),
            "every lost segment is out again: nothing is due now"
        );
    }

    /// Spec §4.8: a turn the bulk budget cuts short is finished first in the
    /// next flush -- the round-robin keeps its position inside the turn, so
    /// no stream loses segments of its share to where the budget happens to
    /// fall.
    #[test]
    fn a_turn_the_bulk_budget_cuts_short_is_finished_first_in_the_next_flush() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        for id in [12u8, 13, 14] {
            client.set_stream_class(id, StreamClass::Bulk);
        }
        // Stream 12 has two segments only, so the turns stop lining up with
        // the budget: 2 + 4 + 4, then 4 + 4 three times, then 13's full turn
        // and half of 14's -- 32.
        client
            .stream_mut(12)
            .sender
            .push(&[12u8; 2 * 1024])
            .expect("room");
        for id in [13u8, 14] {
            client
                .stream_mut(id)
                .sender
                .push(&vec![id; 64 * 1024])
                .expect("room");
        }
        let mut first = Vec::new();
        client.flush_senders(now, &mut first);
        let order = data_streams(&server, &first);
        assert_eq!(order.len(), BULK_FLUSH_BUDGET);
        assert_eq!(&order[26..], &[13, 13, 13, 13, 14, 14], "{order:?}");
        let mut second = Vec::new();
        client.flush_senders(now, &mut second);
        assert_eq!(
            &data_streams(&server, &second)[..8],
            &[14, 14, 13, 13, 13, 13, 14, 14],
            "14 finishes its turn, then the rounds go on"
        );
    }

    /// Spec §4.15: a bulk write starts with the initial window, 10 segments;
    /// an interactive one with two segments more.
    #[test]
    fn a_write_starts_with_the_initial_window_and_an_interactive_one_with_two_more() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let bulk = client.send(now, 14, &vec![0u8; 64 * 1024]);
        assert_eq!(data_streams(&server, &bulk).len(), 10);
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let interactive = client.send(now, 16, &vec![0u8; 64 * 1024]);
        assert_eq!(data_streams(&server, &interactive).len(), 12);
    }

    /// Spec §4.15: the interactive class keeps two segments of its own in
    /// flight whatever the bulk class holds. After the delay signal's cut the
    /// bulk flight stands above the window until it drains (and during a
    /// base probe for the whole drain); a keystroke does not wait for that --
    /// and gets no more than those two segments.
    #[test]
    fn a_keystroke_goes_out_while_the_bulk_flight_stands_above_the_window() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.open_congestion_window_for_test();
        client.set_stream_class(14, StreamClass::Bulk);
        let bulk = client.send(now, 14, &vec![0u8; 64 * 1024]);
        assert_eq!(data_streams(&server, &bulk).len(), BULK_FLUSH_BUDGET);
        let flight = client.flight();
        client
            .cc
            .on_round_trip(now, Duration::from_millis(100), flight);
        // Well before any retransmit timer.
        let later = now + Duration::from_millis(10);
        client
            .cc
            .on_round_trip(later, Duration::from_millis(900), flight);
        assert_eq!(client.congestion_window_for_test().0, 16 * 1024, "the cut");
        let more_bulk = client.send(later, 14, &vec![0u8; 4 * 1024]);
        assert!(data_streams(&server, &more_bulk).is_empty());
        let keystroke = client.send(later, 16, b"k");
        assert_eq!(data_streams(&server, &keystroke), [16]);
        let output = client.send(later, 18, &vec![0u8; 8 * 1024]);
        assert_eq!(
            data_streams(&server, &output),
            [18, 18],
            "a byte and two segments: its own allowance"
        );
        let more = client.send(later, 18, &vec![0u8; 1024]);
        assert!(data_streams(&server, &more).is_empty(), "and no more");
    }

    /// Task 5 review round 2: a flush that leaves data behind -- here behind a
    /// stream's own `MAX_IN_FLIGHT`, the congestion window wide open -- is a
    /// sender with data waiting, not an application-limited one: the delay
    /// signal and the base probe count its queue as its own. A keystroke that
    /// all goes out leaves no backlog.
    #[test]
    fn data_left_behind_a_streams_own_window_is_a_backlog() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.open_congestion_window_for_test();
        let _ = client.send(now, 16, b"k");
        assert_eq!(client.cc.backlog_at(), None, "all of it went out");
        let out = client.send(now, 18, &vec![0u8; MAX_IN_FLIGHT + 1024]);
        assert_eq!(
            data_streams(&server, &out).len(),
            MAX_IN_FLIGHT / 1024,
            "the stream's own window is full"
        );
        assert_eq!(client.cc.backlog_at(), Some(now));
    }

    /// Task 5 round 3: a spurious timeout undone in the connection. The ACKs
    /// of the originals come back 10 ms after the resend -- sooner than any
    /// answer to it could -- so the segments the timeout took for lost are in
    /// flight after all: none goes out again, and the timer's back-off and
    /// the window come back.
    #[test]
    fn an_undone_timeout_sends_nothing_again_and_gives_the_backoff_back() {
        let (mut client, server, caddr, saddr) = established_pair();
        let mut server = server;
        let now = client.handshake_at;
        client.cc.on_round_trip(now, Duration::from_millis(100), 0);
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![7u8; 10 * 1024]);
        assert_eq!(first.len(), 10);
        let window = client.congestion_window_for_test();
        let t = now + client.rto();
        let resent = client.on_timeout(t);
        assert_eq!(
            data_offsets(&server, &resent),
            [0],
            "the oldest goes out again"
        );
        assert_eq!(
            (client.rto_backoff, client.congestion_window_for_test().0),
            (1, 1024)
        );
        let acks: Vec<Datagram> = first
            .iter()
            .flat_map(|dg| server.on_datagram(t, caddr, &dg.bytes))
            .collect();
        let soon = t + Duration::from_millis(10);
        // The first covers the resent segment alone: no round trip to time
        // (Karn), so only the undo gives the back-off back.
        let mut after = client.on_datagram(soon, saddr, &acks[0].bytes);
        assert_eq!(client.cuts_for_test().timeouts_undone, 1);
        assert_eq!(client.rto_backoff, 0);
        for ack in &acks[1..] {
            after.extend(client.on_datagram(soon, saddr, &ack.bytes));
        }
        assert_eq!(
            data_offsets(&server, &after),
            Vec::<u32>::new(),
            "nothing sent again"
        );
        assert!(
            client.congestion_window_for_test().0 >= window.0,
            "the window back"
        );
    }

    /// Ruling R20: an undone timeout gives back what its ACK counts for with
    /// the window. The ACK that shows the timeout spurious -- the originals'
    /// ACK of four segments, 10 ms after the resend -- counts four on the
    /// window given back, not the one segment of a timeout's round trip.
    #[test]
    fn the_ack_that_undoes_a_timeout_counts_as_any_other() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.cc.on_round_trip(now, Duration::from_millis(100), 0);
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![7u8; 64 * 1024]);
        assert_eq!(first.len(), 10);
        let window = client.congestion_window_for_test().0;
        let t = now + client.rto();
        let _ = client.on_timeout(t);
        let acks: Vec<Datagram> = first
            .iter()
            .flat_map(|dg| server.on_datagram(t, caddr, &dg.bytes))
            .collect();
        let _ = client.on_datagram(t + Duration::from_millis(10), saddr, &acks[0].bytes);
        assert_eq!(client.cuts_for_test().timeouts_undone, 1);
        assert_eq!(client.congestion_window_for_test().0, window + 4 * 1024);
    }

    /// Task 5 round 4 (re-review New-1): ordinary flushes between the timeout
    /// and the ACK that shows it spurious -- a keystroke 5 ms after it, more
    /// output on another stream -- do not take its marks away: after the
    /// undo nothing of stream 14 goes out again. Before, any flush cleared
    /// them, and all nine segments the timeout had taken for lost went out
    /// at once under the restored window, their ACKs no longer timeable.
    #[test]
    fn flushes_between_a_timeout_and_its_undo_keep_its_marks() {
        let (mut client, server, caddr, saddr) = established_pair();
        let mut server = server;
        let now = client.handshake_at;
        client.cc.on_round_trip(now, Duration::from_millis(100), 0);
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![7u8; 10 * 1024]);
        assert_eq!(first.len(), 10);
        let t = now + client.rto();
        let resent = client.on_timeout(t);
        assert_eq!(data_offsets(&server, &resent), [0]);
        let keystroke = client.send(t + Duration::from_millis(5), 16, b"k");
        assert_eq!(data_streams(&server, &keystroke), [16]);
        let output = client.send(t + Duration::from_millis(7), 18, b"$ ");
        assert_eq!(data_streams(&server, &output), [18]);
        let acks: Vec<Datagram> = first
            .iter()
            .flat_map(|dg| server.on_datagram(t, caddr, &dg.bytes))
            .collect();
        let soon = t + Duration::from_millis(10);
        let mut after = Vec::new();
        for ack in &acks {
            after.extend(client.on_datagram(soon, saddr, &ack.bytes));
        }
        assert_eq!(client.cuts_for_test().timeouts_undone, 1);
        let again: Vec<u32> = after
            .iter()
            .filter_map(|dg| server.peek_frames(&dg.bytes))
            .flatten()
            .filter_map(|f| match f {
                StreamFrame::Data {
                    stream_id: 14,
                    offset,
                    ..
                } => Some(offset),
                _ => None,
            })
            .collect();
        assert_eq!(again, Vec::<u32>::new(), "nothing of stream 14 sent again");
    }

    /// Task 5 round 3: output that goes past the window on the interactive
    /// allowance -- 2 KiB on a window a timeout left at one segment -- is
    /// held by the window as much as output blocked at it, and grows it.
    /// Counted only when blocked, a terminal session writing under its
    /// allowance stayed at one segment for as long as it ran.
    #[test]
    fn output_past_the_window_on_the_allowance_counts_as_window_limited() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.cc.on_retransmit_timeout(now, 0, &[]);
        assert_eq!(client.congestion_window_for_test().0, 1024);
        let _ = client.send(now, 16, &vec![0u8; 2048]);
        assert!(client.window_limited);
    }

    /// RFC 5681 (2) with RFC 3465: slow start -- each acknowledged segment
    /// of a full window adds one, so each ACK sends two segments for every
    /// one it covers. Of the first window's ten, eight draw an ACK each four
    /// (spec §4.11) and the last two theirs `ACK_DELAY` later: twenty go out.
    #[test]
    fn each_acknowledged_segment_of_a_full_window_sends_two_more() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![0u8; 64 * 1024]);
        let mut acks = Vec::new();
        for dg in first {
            acks.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        acks.extend(held_acks(&mut server, now));
        let mut next = Vec::new();
        for dg in acks {
            next.extend(client.on_datagram(now, saddr, &dg.bytes));
        }
        assert_eq!(data_streams(&server, &next).len(), 20);
        assert_eq!(client.congestion_window_for_test(), (20 * 1024, None));
    }

    /// RFC 5681 §3.1: after a retransmit timeout only the oldest segment goes
    /// out again, the window is one segment and the threshold half of what
    /// was in flight.
    #[test]
    fn a_retransmit_timeout_resends_only_the_oldest_segment() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        let t0 = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let _ = client.send(t0, 14, &vec![0u8; 64 * 1024]);
        let rto = client.rto();
        let out = client.on_timeout(t0 + rto);
        let resent: Vec<u32> = out
            .iter()
            .filter_map(|dg| server.peek_frames(&dg.bytes))
            .flatten()
            .filter_map(|f| match f {
                StreamFrame::Data { offset, .. } => Some(offset),
                _ => None,
            })
            .collect();
        assert_eq!(resent, vec![0]);
        assert_eq!(client.congestion_window_for_test(), (1024, Some(5 * 1024)));
    }

    /// RFC 3465 §2.3 (final review M3, ruling R20), through the connection:
    /// the first of ten segments is lost, the receiver holds the other nine,
    /// the timeout resends it, and the one ACK that answers covers all ten.
    /// It counts for one segment -- the window goes 1 -> 2 and two segments
    /// go out, not five. Their ACK, `ACK_DELAY` later, is past the timeout's
    /// flight: it counts for both.
    #[test]
    fn the_ack_that_answers_a_timeouts_resend_grows_the_window_by_one_segment() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let t0 = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(t0, 14, &vec![0u8; 64 * 1024]);
        assert_eq!(data_offsets(&server, &first).len(), 10);
        // The first datagram is lost; the receiver's ACKs of its hole are
        // not delivered (they would be duplicates).
        for dg in &first[1..] {
            let _ = server.on_datagram(t0, caddr, &dg.bytes);
        }
        let t = t0 + client.rto();
        let resent = client.on_timeout(t);
        assert_eq!(data_offsets(&server, &resent), [0]);
        assert_eq!(client.congestion_window_for_test().0, 1024);
        let answer: Vec<Datagram> = resent
            .iter()
            .flat_map(|dg| server.on_datagram(t, caddr, &dg.bytes))
            .collect();
        let mut next = Vec::new();
        for dg in &answer {
            next.extend(client.on_datagram(t, saddr, &dg.bytes));
        }
        assert_eq!(client.cuts_for_test().timeouts_undone, 0);
        assert_eq!(
            client.congestion_window_for_test().0,
            2 * 1024,
            "the stretch ACK counts one segment"
        );
        assert_eq!(data_offsets(&server, &next), [10 * 1024, 11 * 1024]);
        let mut acks: Vec<Datagram> = next
            .iter()
            .flat_map(|dg| server.on_datagram(t, caddr, &dg.bytes))
            .collect();
        acks.extend(held_acks(&mut server, t));
        for dg in &acks {
            let _ = client.on_datagram(t + ACK_DELAY, saddr, &dg.bytes);
        }
        assert_eq!(
            client.congestion_window_for_test().0,
            4 * 1024,
            "past the timeout's flight an ACK counts what it covers"
        );
    }

    /// Review Focus 3: every segment taken for lost while the window is one
    /// segment -- the stream still drains, one acknowledgement at a time,
    /// and always has either a deadline or something to send.
    #[test]
    fn a_window_full_of_lost_segments_drains_as_acknowledgements_open_it() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let mut now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let data = vec![9u8; 64 * 1024];
        let _ = client.send(now, 14, &data); // lost on the road
        now += client.rto();
        let mut to_server = client.on_timeout(now);
        let mut delivered = Vec::new();
        for _ in 0..400 {
            let mut to_client = Vec::new();
            for dg in std::mem::take(&mut to_server) {
                to_client.extend(server.on_datagram(now, caddr, &dg.bytes));
            }
            delivered.extend(collect_stream_data_for(&server.poll_events(), 14));
            if delivered.len() == data.len() {
                break;
            }
            for dg in to_client {
                to_server.extend(client.on_datagram(now, saddr, &dg.bytes));
            }
            if to_server.is_empty() {
                let next = client
                    .next_timeout()
                    .expect("something outstanding always has a deadline");
                now = now.max(next);
                to_server = client.on_timeout(now);
            }
        }
        assert_eq!(delivered, data);
    }

    /// Review Focus 5: a window that is full leaves nothing due -- the ACKs
    /// open it, not a timer spinning at "now".
    #[test]
    fn a_full_window_leaves_no_deadline_due() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let _ = client.send(now, 14, &vec![0u8; 64 * 1024]);
        assert!(
            client.next_timeout().is_some_and(|t| t > now),
            "a full window is waiting for ACKs, not due now"
        );
    }

    /// Spec §4.15: a move onto another road and a wake from sleep (and a
    /// rebind, which shares `request_ping`) start the window afresh.
    #[test]
    fn a_move_and_a_wake_start_the_window_afresh() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.cc.on_retransmit_timeout(now, 40 * 1024, &[]);
        client.request_ping(now);
        assert_eq!(client.congestion_window_for_test(), (10 * 1024, None));
        client.cc.on_retransmit_timeout(now, 40 * 1024, &[]);
        client.force_ping_on_a_new_road();
        assert_eq!(client.congestion_window_for_test(), (10 * 1024, None));
    }

    /// Put 64 KiB of bulk data in flight on stream 14, with no ACK.
    fn a_client_with_64_kib_in_flight() -> (Connection, Connection, Instant) {
        let (mut client, server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client
            .stream_mut(14)
            .sender
            .push(&vec![0u8; 64 * 1024])
            .expect("room");
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        let _ = client.on_timeout(now);
        assert_eq!(client.stream_mut(14).sender.pipe(), 64 * 1024);
        (client, server, now)
    }

    fn data_offsets(reader: &Connection, out: &[Datagram]) -> Vec<u32> {
        out.iter()
            .filter_map(|dg| reader.peek_frames(&dg.bytes))
            .flatten()
            .filter_map(|f| match f {
                StreamFrame::Data { offset, .. } => Some(offset),
                _ => None,
            })
            .collect()
    }

    /// Spec §4.15, review round 1: the restart must survive the data in
    /// flight at the moment. After a wake (or a rebind: both call
    /// `request_ping`) that data is long overdue; the next flush must not take
    /// that for a retransmit timeout -- it would put the window back at one
    /// segment with a threshold from before the gap -- but resend it under
    /// the fresh initial window. The next genuine timeout reacts as usual.
    #[test]
    fn a_wake_with_data_in_flight_resends_it_under_the_initial_window() {
        let (mut client, server, now) = a_client_with_64_kib_in_flight();
        let woke = now + 10 * client.rto();
        client.request_ping(woke);
        let out = client.on_timeout(woke);
        assert_eq!(client.congestion_window_for_test(), (10 * 1024, None));
        assert_eq!(client.rto_backoff, 0, "no back-off for the gap");
        let resent = data_offsets(&server, &out);
        assert_eq!(
            resent,
            (0..10).map(|i| i * 1024).collect::<Vec<u32>>(),
            "the oldest in-flight data goes out again, one initial window of it"
        );
        let later = woke + client.rto();
        let out = client.on_timeout(later);
        assert_eq!(data_offsets(&server, &out), vec![0]);
        assert_eq!(
            client.congestion_window_for_test(),
            (1024, Some(32 * 1024)),
            "a genuine timeout after the restart reacts"
        );
        assert_eq!(client.rto_backoff, 1);
    }

    /// The same for a move onto another road.
    #[test]
    fn a_move_with_data_in_flight_resends_it_under_the_initial_window() {
        let (mut client, server, now) = a_client_with_64_kib_in_flight();
        let moved = now + client.rto();
        client.force_ping_on_a_new_road();
        let out = client.on_timeout(moved);
        assert_eq!(client.congestion_window_for_test(), (10 * 1024, None));
        assert_eq!(client.rto_backoff, 0);
        assert_eq!(
            data_offsets(&server, &out),
            (0..10).map(|i| i * 1024).collect::<Vec<u32>>()
        );
    }

    /// Final review of slice 2, Important 2 (spec §4.15: a move starts
    /// afresh). The client starts its window afresh when it moves; the
    /// server, which sends the terminal's output, must too when it follows
    /// the client to its new address: its window, its threshold and the old
    /// road's base delay describe a road the session left, and its send
    /// times would time that road. What it had in flight goes out again
    /// under the initial window, to the new address.
    #[test]
    fn a_server_that_follows_its_client_to_a_new_address_starts_its_window_afresh() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        deliver(&mut server, now, caddr, client.send(now, 0, b"a"));
        let _ = server.send(now, 16, &vec![6u8; 64 * 1024]); // lost on the old road
        server.cc.on_round_trip(now, Duration::from_millis(100), 0);
        server.cc.on_retransmit_timeout(now, 40 * 1024, &[]);
        server.rto_backoff = 2;
        assert_ne!(server.congestion_window_for_test(), (10 * 1024, None));

        let moved = now + Duration::from_millis(50);
        let caddr2 = addr("203.0.113.9:55000");
        deliver_from(&mut server, moved, caddr2, client.send(moved, 0, b"b"));
        assert_eq!(server.peer(), Some(caddr2));
        assert_eq!(server.congestion_window_for_test(), (10 * 1024, None));
        assert_eq!(server.base_delay_for_test(), None, "the old road's base");
        assert_eq!(server.rto_backoff, 0);
        let out = server.on_timeout(moved);
        assert!(out.iter().all(|dg| dg.to == caddr2));
        assert_eq!(
            data_offsets(&client, &out),
            (0..12).map(|i| i * 1024).collect::<Vec<u32>>(),
            "the oldest in-flight data goes out again: the initial window and \
             the interactive class's two segments of it"
        );
    }

    /// Round 3 of the final fix wave (the controller's ruling): a new port on
    /// the same address starts the server's window afresh as a new address
    /// does. Seen from the server, the usual port change is the client's own
    /// new socket (a network callback, a Doze wake): the old one is closed,
    /// and what was sent to it is lost -- repaired at once by the resend of
    /// the flight, a segment per round trip by NewReno otherwise.
    #[test]
    fn a_new_port_on_the_same_address_starts_the_servers_window_afresh_too() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        deliver(&mut server, now, caddr, client.send(now, 0, b"a"));
        let _ = server.send(now, 16, &vec![6u8; 64 * 1024]);
        server.cc.on_round_trip(now, Duration::from_millis(100), 0);
        server.cc.on_retransmit_timeout(now, 40 * 1024, &[]);
        server.rto_backoff = 2;

        let rebound = now + Duration::from_millis(50);
        let new_port = SocketAddr::new(caddr.ip(), caddr.port() + 1);
        deliver_from(
            &mut server,
            rebound,
            new_port,
            client.send(rebound, 0, b"b"),
        );
        assert_eq!(server.peer(), Some(new_port), "followed");
        assert_eq!(server.congestion_window_for_test(), (10 * 1024, None));
        assert_eq!(server.base_delay_for_test(), None);
        assert_eq!(server.rto_backoff, 0);
        let out = server.on_timeout(rebound);
        assert!(out.iter().all(|dg| dg.to == new_port));
        assert_eq!(
            data_offsets(&client, &out),
            (0..12).map(|i| i * 1024).collect::<Vec<u32>>(),
            "what was in flight goes out again under the fresh window"
        );
    }

    /// Review round 1: a flush the bulk budget cut short, with room left in
    /// the window, was not application-limited -- its ACKs grow the window.
    #[test]
    fn a_flush_cut_by_the_bulk_budget_counts_as_window_limited() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        client.open_congestion_window_for_test();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client
            .stream_mut(14)
            .sender
            .push(&vec![0u8; 64 * 1024])
            .expect("room");
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        assert!(
            client.window_limited,
            "the budget, not the data, stopped it"
        );
        let _ = client.on_timeout(now);
        assert!(!client.window_limited, "out of data: application-limited");
    }

    /// Spec §4.15: three duplicate ACKs resend the lost segment and halve the
    /// window; every later duplicate adds a segment back.
    #[test]
    fn three_duplicate_acks_resend_the_lost_segment_and_halve_the_window() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![3u8; 20 * 1024]);
        assert_eq!(first.len(), 10, "the initial window");
        // The road loses the first segment; each of the other nine draws a
        // duplicate ACK of offset 0.
        let mut dups = Vec::new();
        for dg in first.into_iter().skip(1) {
            dups.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        assert_eq!(dups.len(), 9);
        let mut resent_at = None;
        for (i, dg) in dups.into_iter().enumerate() {
            let out = client.on_datagram(now, saddr, &dg.bytes);
            let again = out
                .iter()
                .filter_map(|d| server.peek_frames(&d.bytes))
                .flatten()
                .any(|f| {
                    matches!(
                        f,
                        StreamFrame::Data {
                            stream_id: 14,
                            offset: 0,
                            ..
                        }
                    )
                });
            if again {
                assert!(resent_at.is_none(), "resent once");
                resent_at = Some(i + 1);
            }
        }
        assert_eq!(resent_at, Some(3), "on the third duplicate");
        assert_eq!(
            client.congestion_window_for_test(),
            (5 * 1024 + 3 * 1024 + 6 * 1024, Some(5 * 1024)),
            "ssthresh half of ten segments; ssthresh + 3, plus one per later duplicate"
        );
    }

    /// RFC 6582: two holes in one window -- the partial ACK after the first
    /// repair resends the second at once, and the full ACK ends the recovery
    /// at the threshold, with no retransmit timeout on the way.
    #[test]
    fn a_partial_ack_resends_the_next_hole_and_the_full_ack_ends_recovery() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![4u8; 10 * 1024]);
        // Holes at segments 0 and 5.
        let mut acks = Vec::new();
        for (i, dg) in first.into_iter().enumerate() {
            if i != 0 && i != 5 {
                acks.extend(server.on_datagram(now, caddr, &dg.bytes));
            }
        }
        let mut to_server = Vec::new();
        for dg in acks {
            to_server.extend(client.on_datagram(now, saddr, &dg.bytes));
        }
        assert_eq!(data_offsets(&server, &to_server), vec![0], "the first hole");
        let mut back = Vec::new();
        for dg in to_server {
            back.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        let mut second = Vec::new();
        for dg in back {
            second.extend(client.on_datagram(now, saddr, &dg.bytes));
        }
        assert!(
            data_offsets(&server, &second).contains(&(5 * 1024)),
            "the partial ACK resends the second hole at once"
        );
        let mut last = Vec::new();
        for dg in second {
            last.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        for dg in last {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 14).len(),
            10 * 1024
        );
        assert_eq!(client.cc.recovery(), None);
        assert_eq!(
            client.congestion_window_for_test(),
            (5 * 1024, Some(5 * 1024))
        );
        assert_eq!(client.rto_backoff, 0, "no retransmit timeout on the way");
    }

    /// The ACKs our own resent copies draw do not start a recovery: after a
    /// wake the ten segments in flight go out again, the peer already had
    /// them, and each copy draws an ACK of the new base while new data is in
    /// flight behind it. The restart holds the fast retransmit until an ACK
    /// passes what had been sent (RFC 6582 §3.2 step 1); without that they
    /// would resend the new data and halve the window for a loss that never
    /// happened.
    #[test]
    fn the_acks_of_our_own_resent_copies_do_not_fast_retransmit() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![5u8; 30 * 1024]);
        assert_eq!(data_offsets(&server, &first).len(), 10);
        // The peer gets all ten; their ACKs are lost.
        for dg in first {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        let woke = now + 10 * client.rto();
        client.request_ping(woke);
        let copies = client.on_timeout(woke);
        assert_eq!(
            data_offsets(&server, &copies),
            (0..10).map(|i| i * 1024).collect::<Vec<u32>>()
        );
        let mut acks = Vec::new();
        for dg in copies {
            acks.extend(server.on_datagram(woke, caddr, &dg.bytes));
        }
        let retransmits = client.retransmits;
        let mut after = Vec::new();
        for dg in acks {
            after.extend(client.on_datagram(woke, saddr, &dg.bytes));
        }
        assert!(
            data_offsets(&server, &after)
                .iter()
                .all(|o| *o >= 10 * 1024),
            "only new data goes out"
        );
        assert_eq!(client.retransmits, retransmits, "nothing resent");
        assert_eq!(client.cc.recovery(), None);
        assert_eq!(client.congestion_window_for_test().1, None, "no cut");
    }

    fn ack_frames(client: &mut Connection, now: Instant, acks: &[u32]) {
        ack_frames_on(client, now, 14, acks);
    }

    /// Hand `client` one `Ack` of `stream_id` per entry of `acks`, and flush
    /// after each as the driver would.
    fn ack_frames_on(client: &mut Connection, now: Instant, stream_id: u8, acks: &[u32]) {
        for cum_ack in acks {
            let frames = vec![StreamFrame::Ack {
                stream_id,
                cum_ack: *cum_ack,
            }];
            let _ = client.route_stream_frames(frames, now);
            let mut out = Vec::new();
            client.flush_senders(now, &mut out);
        }
    }

    /// Review round 1 (Critical): when a recovery ends, its repairs may still
    /// be on their way and draw ACKs of the base; they must not start the
    /// next recovery. Held until an ACK passes what had been sent (RFC 6582
    /// §3.2 step 1).
    #[test]
    fn after_a_recovery_the_acks_its_repairs_draw_do_not_start_another() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let _ = client.send(now, 14, &vec![6u8; 40 * 1024]);
        ack_frames(&mut client, now, &[0, 0, 0]);
        assert!(client.cc.recovery().is_some());
        ack_frames(&mut client, now, &[10 * 1024]);
        assert_eq!(client.cc.recovery(), None, "the full ACK");
        let retransmits = client.retransmits;
        ack_frames(&mut client, now, &[10 * 1024; 5]);
        assert_eq!(client.cc.recovery(), None);
        assert_eq!(client.retransmits, retransmits, "nothing resent");
        assert!(!client.stream_mut(14).sender.has_urgent());
    }

    /// RFC 6582 §3.2 step 1: a retransmit timeout holds the fast retransmit
    /// too -- what it resends as the window opens draws ACKs of the base.
    #[test]
    fn a_retransmit_timeout_holds_the_next_fast_retransmit() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let _ = client.send(now, 14, &vec![7u8; 20 * 1024]);
        let later = now + client.rto();
        let _ = client.on_timeout(later);
        assert_eq!(client.congestion_window_for_test().0, 1024, "the timeout");
        ack_frames(&mut client, later, &[0, 0, 0, 0]);
        assert_eq!(client.cc.recovery(), None);
    }

    /// Review round 1 (Critical): a segment the road only held back sets off
    /// a fast retransmit, and its own ACK comes back far sooner than the
    /// resend could be answered. The retransmit was spurious: the window
    /// goes back to what it was, and the threshold learns the reordering.
    #[test]
    fn a_reordered_segment_undoes_its_spurious_fast_retransmit() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        client.cc.on_round_trip(now, Duration::from_millis(100), 0);
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![8u8; 20 * 1024]);
        assert_eq!(first.len(), 10);
        let window = client.congestion_window_for_test();
        let mut first = first.into_iter();
        let late = first.next().expect("segment 0");
        let mut resent = Vec::new();
        for dg in first {
            for ack in server.on_datagram(now, caddr, &dg.bytes) {
                resent.extend(client.on_datagram(now, saddr, &ack.bytes));
            }
        }
        assert!(
            data_offsets(&server, &resent).contains(&0),
            "the third duplicate resent segment 0"
        );
        assert!(client.cc.recovery().is_some());
        let soon = now + Duration::from_millis(5);
        for ack in server.on_datagram(soon, caddr, &late.bytes) {
            let _ = client.on_datagram(soon, saddr, &ack.bytes);
        }
        assert_eq!(client.cc.recovery(), None);
        assert_eq!(client.congestion_window_for_test().1, None, "no threshold");
        assert!(
            client.congestion_window_for_test().0 >= window.0,
            "not halved"
        );
        assert_eq!(client.cc.dup_threshold(), 10, "nine duplicates, plus one");
    }

    /// Review round 2 (Minor 1): the hold after a recovery runs to where the
    /// recovery began (RFC 6582 `recover`). Data first sent during the
    /// recovery is not held: a loss among it is repaired by duplicates, not
    /// by a timeout.
    #[test]
    fn the_hold_after_a_recovery_ends_where_the_recovery_began() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        let _ = client.send(now, 14, &vec![9u8; 40 * 1024]);
        // Segment 0 lost: three duplicates, then six more that let new data
        // out past the recovery's point, 10 KiB.
        ack_frames(&mut client, now, &[0; 9]);
        assert_eq!(client.cc.recovery().map(|r| r.recover), Some(10 * 1024));
        assert!(client.stream_mut(14).sender.sent_up_to() > 10 * 1024);
        ack_frames(&mut client, now, &[10 * 1024]);
        assert_eq!(client.cc.recovery(), None, "the full ACK");
        assert!(!client.stream_mut(14).sender.may_fast_retransmit());
        ack_frames(&mut client, now, &[11 * 1024]);
        assert!(client.stream_mut(14).sender.may_fast_retransmit());
        // Segment 11 lost, among the data sent during the recovery.
        ack_frames(&mut client, now, &[11 * 1024; 3]);
        assert_eq!(
            client.cc.recovery().map(|r| r.stream_id),
            Some(14),
            "three duplicates start its recovery"
        );
    }

    /// Spec §4.15, one recovery for the whole connection (review round 2):
    /// while stream 14 recovers, stream 16's third duplicate resends its
    /// oldest segment without a second cut; its partial ACK resends nothing
    /// and grows nothing -- its next hole needs three duplicates of its own
    /// -- and 14's full ACK still ends the recovery at the threshold.
    #[test]
    fn a_second_streams_loss_during_a_recovery_is_repaired_by_its_own_duplicates() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        client.set_stream_class(14, StreamClass::Bulk);
        client.set_stream_class(16, StreamClass::Bulk);
        client.open_congestion_window_for_test();
        for id in [14, 16] {
            client
                .stream_mut(id)
                .sender
                .push(&vec![1u8; 10 * 1024])
                .expect("room");
        }
        let mut out = Vec::new();
        client.flush_senders(now, &mut out);
        for id in [14, 16] {
            assert_eq!(client.stream_mut(id).sender.sent_up_to(), 10 * 1024);
        }
        ack_frames_on(&mut client, now, 14, &[0, 0, 0]);
        let recovering = client.congestion_window_for_test();
        let retransmits = client.retransmits;
        ack_frames_on(&mut client, now, 16, &[0, 0, 0]);
        assert_eq!(client.retransmits, retransmits + 1, "16's oldest resent");
        assert_eq!(
            client.congestion_window_for_test(),
            recovering,
            "no second cut"
        );
        assert_eq!(client.cc.recovery().map(|r| r.stream_id), Some(14));
        // 16's repair is answered; its next hole is at 5 KiB.
        ack_frames_on(&mut client, now, 16, &[5 * 1024]);
        assert_eq!(
            client.retransmits,
            retransmits + 1,
            "a partial ACK of 16 resends nothing"
        );
        assert_eq!(
            client.congestion_window_for_test(),
            recovering,
            "and grows nothing"
        );
        ack_frames_on(&mut client, now, 16, &[5 * 1024, 5 * 1024]);
        assert_eq!(client.retransmits, retransmits + 1);
        ack_frames_on(&mut client, now, 16, &[5 * 1024]);
        assert_eq!(
            client.retransmits,
            retransmits + 2,
            "the third duplicate resends it"
        );
        ack_frames_on(&mut client, now, 14, &[10 * 1024]);
        assert_eq!(client.cc.recovery(), None);
        assert_eq!(
            client.congestion_window_for_test().0,
            recovering.1.expect("a threshold")
        );
    }

    /// Slice 2's carry-over (spec §4.14): a fast recovery whose point lies
    /// below 2^32 ends when an ACK past 2^32 arrives -- an ACK whose 32-bit
    /// field is a small number, while the point's low bits are nearly
    /// 2^32, so a compare of the fields would keep the recovery going.
    #[test]
    fn a_recovery_that_begins_below_2_pow_32_ends_past_it() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        assert!(client.features().contains(Features::OFFSET_WRAP));
        let now = client.handshake_at;
        let start = u32::MAX - 12 * 1024 + 1; // twelve segments short of 2^32
        client.start_stream_at_for_test(14, start);
        client.set_stream_class(14, StreamClass::Bulk);
        let first = client.send(now, 14, &vec![6u8; 40 * 1024]);
        assert_eq!(
            first.len(),
            10,
            "the initial window, two segments short of the edge"
        );
        ack_frames(&mut client, now, &[start, start, start]);
        let recovery = client
            .cc
            .recovery()
            .expect("three duplicates start a recovery");
        assert_eq!(recovery.recover, u64::from(start) + 10 * 1024);
        assert!(recovery.recover < 1 << 32, "the point lies below 2^32");
        // Every further duplicate is a segment that left the network, and
        // lets one more out (RFC 6582 step 3): five carry the stream across.
        ack_frames(&mut client, now, &[start; 5]);
        let sent = client.streams[&14].sender.sent_up_to();
        assert!(sent > 1 << 32, "the stream went past 2^32: {sent}");
        assert!(client.cc.recovery().is_some(), "still recovering");
        let full_ack = sent as u32;
        assert!(
            full_ack < recovery.recover as u32,
            "the ACK's field is below the point's low bits"
        );
        ack_frames(&mut client, now, &[full_ack]);
        assert_eq!(
            client.cc.recovery(),
            None,
            "the full ACK past the edge ends it"
        );
        assert_eq!(
            client.congestion_window_for_test(),
            (5 * 1024, Some(5 * 1024))
        );
    }

    /// Spec §4.7.1: a server stream that can be rebuilt from a screen model
    /// goes past `SEND_HARD_CAP` only when a producer ignores its gate -- the
    /// backlog goes, a `Reset` goes out, and the backend is asked to repaint.
    #[test]
    fn a_resyncable_server_stream_past_the_hard_cap_drops_its_backlog_and_repaints() {
        let (client, mut server, _caddr, _saddr) = established_pair();
        let now = server.handshake_at;
        server.set_stream_resyncable(16, true);
        let out = server.send(now, 16, &vec![0u8; SEND_HARD_CAP + 1]);
        assert_eq!(server.stream_progress(16).unacked, 0, "the backlog went");
        assert!(server.poll_events().contains(&Event::OutputResync));
        assert!(
            out.iter()
                .filter_map(|d| client.peek_frames(&d.bytes))
                .flatten()
                .any(|f| matches!(f, StreamFrame::Reset { stream_id: 16, .. })),
            "the Reset goes out at once"
        );
    }

    /// Spec §4.7.1: a stream nobody can rebuild keeps its data past the cap
    /// and says so once per connection.
    #[test]
    fn a_stream_without_a_screen_past_the_hard_cap_keeps_its_data_and_says_so_once() {
        let (_client, mut server, _caddr, _saddr) = established_pair();
        let now = server.handshake_at;
        server.set_stream_resyncable(17, false);
        let _ = server.send(now, 17, &vec![0u8; SEND_HARD_CAP + 1]);
        let _ = server.send(now, 17, &[0u8; 1024]);
        let reports = server
            .poll_events()
            .into_iter()
            .filter(|e| *e == Event::SendBufferOverCap { stream_id: 17 })
            .count();
        assert_eq!(reports, 1);
        assert_eq!(
            server.stream_progress(17).unacked,
            (SEND_HARD_CAP + 1 + 1024) as u64
        );
    }

    /// Plan correction 2: on a client, stream 0 counts as resyncable by
    /// default, but nothing on a client can rebuild it -- a 5 MiB paste is
    /// kept whole.
    #[test]
    fn a_client_stream_past_the_hard_cap_is_never_dropped() {
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let _ = client.send(now, 0, &vec![0u8; SEND_HARD_CAP + 1]);
        let events = client.poll_events();
        assert!(!events.contains(&Event::OutputResync));
        assert!(events.contains(&Event::SendBufferOverCap { stream_id: 0 }));
        assert_eq!(
            client.stream_progress(0).unacked,
            (SEND_HARD_CAP + 1) as u64
        );
    }

    /// Spec §4.7.1, §4.14: a sender forgets an unacknowledged `Reset` when it
    /// drops its tail again, so the `Reset`s of resyncs lost one after
    /// another add up to one jump -- here three trips of the hard cap before
    /// any `Reset` lands, 12 MiB past the client's point. The client takes
    /// it, and the stream goes on. With credits, the dropped backlog does
    /// not fit under the old limit (the implicit 512 KiB), so the shift
    /// lands the sender's limit on `q` itself (spec §6.5, `max(limit, q)`)
    /// and the repaint has no room until the `CREDIT` on the `Reset`'s ACK
    /// completes one round trip (task 4's amendment, review Minor 2).
    #[test]
    fn resets_lost_one_after_another_add_up_and_the_stream_goes_on() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = server.handshake_at;
        server.set_stream_resyncable(16, true);
        let _lost = server.send(now, 16, &vec![0u8; SEND_HARD_CAP + 1]);
        let _lost = server.send(now, 16, &vec![0u8; SEND_HARD_CAP + 1]);
        let mut out = server.send(now, 16, &vec![0u8; SEND_HARD_CAP + 1]);
        let head = 3 * (SEND_HARD_CAP as u64 + 1);
        assert_eq!(server.stream_progress(16).queued, head);
        // Queued with the Reset's own wave, as the repaint was before
        // credits (Minor 2, review of this task). The dropped backlog does
        // not fit under the old limit (the implicit 512 KiB), so the shift
        // lands the sender's limit on `q` itself (spec §6.5, max(limit,
        // q)) -- exactly where "after" starts -- and nothing goes out for
        // it yet: it waits one round trip for the `CREDIT` the Reset's ACK
        // carries.
        let early = server.send(now, 16, b"after");
        assert!(
            data_offsets(&client, &early).is_empty(),
            "no room yet -- waiting for the CREDIT"
        );
        out.extend(early);
        pump_pair(&mut client, &mut server, caddr, saddr, now, Vec::new(), out);
        // The repaint's ACK, held for a ride (spec §4.11), goes alone.
        let held = held_acks(&mut client, now);
        pump_pair(
            &mut client,
            &mut server,
            caddr,
            saddr,
            now,
            held,
            Vec::new(),
        );
        let events = client.poll_events();
        assert!(events.contains(&Event::StreamReset { stream_id: 16 }));
        assert_eq!(collect_stream_data_for(&events, 16), b"after");
        assert_eq!(client.streams[&16].receiver.next_offset(), head + 5);
        assert_eq!(
            server.stream_progress(16).unacked,
            0,
            "the Reset and the repaint acknowledged"
        );
    }

    /// Spec §4.16 (QSH-01): a peer that writes far past what it may --
    /// one-byte chunks at every other offset of the window, and whole
    /// segments megabytes ahead -- makes the receiver keep at most its cost
    /// cap, and nothing past the cumulative point is acknowledged.
    #[test]
    fn a_forged_flood_past_the_window_leaves_the_receiver_bounded() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let mut frames: Vec<StreamFrame> = (0..20_000u32)
            .map(|i| StreamFrame::Data {
                stream_id: 20,
                offset: 1 + 2 * i,
                data: vec![0xEE],
            })
            .collect();
        frames.extend((1..=64u32).map(|k| StreamFrame::Data {
            stream_id: 20,
            offset: k * 1024 * 1024,
            data: vec![0xEE; 1024],
        }));
        let mut answers = Vec::new();
        for dg in client.frames_for_test(frames) {
            answers.extend(server.on_datagram(now, caddr, &dg.bytes));
        }
        let cap = server.streams[&20].receiver.cost_cap();
        assert!(server.undelivered_cost_for_test() <= cap);
        let acks: Vec<u32> = answers
            .iter()
            .filter_map(|d| client.peek_frames(&d.bytes))
            .flatten()
            .filter_map(|f| match f {
                StreamFrame::Ack { cum_ack, .. } => Some(cum_ack),
                _ => None,
            })
            .collect();
        assert!(!acks.is_empty() && acks.iter().all(|a| *a == 0));
        assert!(collect_stream_data(&server.poll_events()).is_empty());
    }

    /// Spec §4.16: the connection's cap binds all its streams together.
    #[test]
    fn all_streams_together_keep_no_more_than_the_connections_cap() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        server.set_undelivered_cap(64 * 1024);
        let mut frames = Vec::new();
        for stream_id in 20..30u8 {
            for k in 1..=20u32 {
                frames.push(StreamFrame::Data {
                    stream_id,
                    offset: k * 1024,
                    data: vec![stream_id; 1024],
                });
            }
        }
        for dg in client.frames_for_test(frames) {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        let held = server.undelivered_cost_for_test();
        assert!(held <= 64 * 1024, "{held}");
        assert!(held > 60 * 1024, "it fills up to the cap: {held}");
    }

    /// Spec §4.16, decision D1: without lowering it, the cap is
    /// `UNDELIVERED_CAP` -- a peer that fills the window of stream after
    /// stream makes the connection hold no more than that, where each
    /// stream alone would let it hold 256 times its cost cap.
    #[test]
    fn a_peer_filling_stream_after_stream_meets_the_default_cap() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let per_stream = LEGACY_RECEIVE_WINDOW as u32 / 1024;
        let mut frames = Vec::new();
        for stream_id in 20..60u8 {
            for k in 1..per_stream {
                frames.push(StreamFrame::Data {
                    stream_id,
                    offset: k * 1024,
                    data: vec![stream_id; 1024],
                });
            }
        }
        for dg in client.frames_for_test(frames) {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        let held = server.undelivered_cost_for_test();
        assert!(held <= UNDELIVERED_CAP, "{held}");
        assert!(
            held > UNDELIVERED_CAP - 2 * (1024 + CHUNK_COST),
            "it fills up to the cap: {held}"
        );
    }

    /// Spec §4.16: the connection keeps a running count of what its streams
    /// hold out of order -- not a sum over every stream on every DATA -- and
    /// through mixed traffic on several streams (out of order, in order, far
    /// ahead, `Reset`s, a room that fills) it stays what a count afresh says.
    #[test]
    fn the_running_count_of_out_of_order_data_follows_every_stream() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = client.handshake_at;
        // The server sends and the client receives: a server takes no
        // `Reset` from its client (ruling R15), a client takes its server's.
        client.set_undelivered_cap(40 * (1024 + CHUNK_COST));
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let mut points = [0u64; 4];
        for round in 0..3_000 {
            let s = next(4) as usize;
            let stream_id = 20 + s as u8;
            let frame = match next(10) {
                0 => {
                    points[s] += next(8 * 1024);
                    StreamFrame::Reset {
                        stream_id,
                        new_offset: points[s] as u32,
                    }
                }
                1 => {
                    let len = 1 + next(1024);
                    let frame = StreamFrame::Data {
                        stream_id,
                        offset: points[s] as u32,
                        data: vec![1u8; len as usize],
                    };
                    points[s] += len;
                    frame
                }
                _ => StreamFrame::Data {
                    stream_id,
                    offset: (points[s] + 1 + next(300 * 1024)) as u32,
                    data: vec![1u8; 1 + next(1024) as usize],
                },
            };
            for dg in server.frames_for_test(vec![frame]) {
                let _ = client.on_datagram(now, saddr, &dg.bytes);
            }
            if round % 100 == 0 {
                assert!(client.undelivered_cost_for_test() <= 40 * (1024 + CHUNK_COST));
            }
        }
        assert!(client.undelivered_cost_for_test() > 0);
    }

    /// Spec §4.16: what a stream held is the connection's again once it is
    /// delivered or dropped by a `Reset` -- the cap is a bound on what is
    /// held now, not a budget spent for good.
    #[test]
    fn what_is_delivered_or_reset_away_makes_room_again() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = client.handshake_at;
        // The server sends and the client receives: a server takes no
        // `Reset` from its client (ruling R15), a client takes its server's.
        client.set_undelivered_cap(8 * (1024 + CHUNK_COST));
        let ahead = |stream_id: u8| -> Vec<StreamFrame> {
            (1..=8u32)
                .map(|k| StreamFrame::Data {
                    stream_id,
                    offset: k * 1024,
                    data: vec![1u8; 1024],
                })
                .collect()
        };
        for dg in server.frames_for_test(ahead(20)) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.undelivered_cost_for_test(), 8 * (1024 + CHUNK_COST));
        for dg in server.frames_for_test(ahead(21)) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(
            client.undelivered_cost_for_test(),
            8 * (1024 + CHUNK_COST),
            "full: stream 21 keeps nothing"
        );
        let hole = vec![StreamFrame::Data {
            stream_id: 20,
            offset: 0,
            data: vec![1u8; 1024],
        }];
        for dg in server.frames_for_test(hole) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.undelivered_cost_for_test(), 0, "all delivered");
        for dg in server.frames_for_test(ahead(21)) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.undelivered_cost_for_test(), 8 * (1024 + CHUNK_COST));
        let reset = vec![StreamFrame::Reset {
            stream_id: 21,
            new_offset: 9 * 1024,
        }];
        for dg in server.frames_for_test(reset) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
        assert_eq!(client.undelivered_cost_for_test(), 0, "reset away");
    }

    /// Carry datagrams between a pair at one instant until neither says
    /// anything more: a lossless road with no delay.
    fn pump_pair(
        client: &mut Connection,
        server: &mut Connection,
        caddr: SocketAddr,
        saddr: SocketAddr,
        now: Instant,
        to_server: Vec<Datagram>,
        to_client: Vec<Datagram>,
    ) {
        let (mut to_server, mut to_client) = (to_server, to_client);
        for _ in 0..100_000 {
            if to_server.is_empty() && to_client.is_empty() {
                return;
            }
            for dg in std::mem::take(&mut to_server) {
                to_client.extend(server.on_datagram(now, caddr, &dg.bytes));
            }
            for dg in std::mem::take(&mut to_client) {
                to_server.extend(client.on_datagram(now, saddr, &dg.bytes));
            }
        }
        panic!("the pair never went quiet");
    }

    fn credit_frames(reader: &Connection, out: &[Datagram]) -> usize {
        out.iter()
            .filter_map(|d| reader.peek_frames(&d.bytes))
            .flatten()
            .filter(|f| matches!(f, StreamFrame::Credit { .. }))
            .count()
    }

    /// Spec §5.2 with §6: two ends of this build run with credits, and every
    /// stream starts with the implicit window.
    #[test]
    fn two_ends_of_this_build_run_with_credits() {
        let (mut client, server, _caddr, _saddr) = established_pair();
        assert_eq!(client.features(), Features::SUPPORTED);
        assert!(server.features().contains(Features::STREAM_CREDIT));
        let _ = client.send(client.handshake_at, 20, b"x");
        assert_eq!(client.credit_limit_for_test(20), Some(STREAM_WINDOW));
    }

    /// Spec §4.10.6: a stream whose consumer takes nothing stops at its
    /// window; nothing is in flight, so nothing is resent. Once the consumer
    /// takes some, a `CREDIT` lets the stream go on.
    #[test]
    fn a_stream_nobody_consumes_stops_at_its_window_and_resends_nothing() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        server.set_stream_consumption(20, Consumption::Explicit);
        let out = client.send(now, 20, &vec![7u8; 1024 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 20).len() as u64,
            STREAM_WINDOW
        );
        assert_eq!(
            client.stream_progress(20),
            StreamProgress {
                queued: 1024 * 1024,
                unacked: 1024 * 1024 - STREAM_WINDOW
            }
        );
        // Under PATH_DOWN_AFTER (3 s): the client stays Live, so the
        // CREDIT's arrival below is answered by window_opened's own flush,
        // not masked by the unconditional one a return from PathDown would
        // give it (Minor 1, review of this task).
        let later = now + Duration::from_secs(2);
        let retransmits = client.retransmits;
        let again = client.on_timeout(later);
        assert!(
            data_offsets(&server, &again).is_empty(),
            "nothing to resend"
        );
        assert_eq!(client.retransmits, retransmits);
        let credit = server.on_consumed(later, 20, (STREAM_WINDOW / 2) as usize);
        assert_eq!(credit_frames(&client, &credit), 1);
        pump_pair(
            &mut client,
            &mut server,
            caddr,
            saddr,
            later,
            Vec::new(),
            credit,
        );
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 20).len() as u64,
            STREAM_WINDOW / 2
        );
    }

    /// Spec §6.4: a `CREDIT` for a stopped sender that is lost is sent again
    /// three times, one rto apart, on the timer the connection reports; after
    /// that the PONGs carry it.
    #[test]
    fn a_lost_credit_is_repeated_on_the_timer_and_then_with_every_pong() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        server.set_stream_consumption(20, Consumption::Explicit);
        let out = client.send(now, 20, &vec![8u8; 1024 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        let _ = server.poll_events();
        let lost = server.on_consumed(now, 20, STREAM_WINDOW as usize);
        assert_eq!(credit_frames(&client, &lost), 1, "announced -- and lost");
        let rto = server.rto();
        assert!(server.next_timeout().expect("a deadline") <= now + rto);
        let mut t = now;
        for _ in 0..CREDIT_RESENDS {
            t += rto;
            assert_eq!(credit_frames(&client, &server.on_timeout(t)), 1);
        }
        t += rto;
        assert_eq!(
            credit_frames(&client, &server.on_timeout(t)),
            0,
            "three repeats"
        );
        let ping = client.frames_for_test(vec![StreamFrame::Ping { token: 99 }]);
        let pong = server.on_datagram(t, caddr, &ping[0].bytes);
        assert_eq!(credit_frames(&client, &pong), 1, "with the PONG");
        pump_pair(&mut client, &mut server, caddr, saddr, t, Vec::new(), pong);
        assert!(client.credit_limit_for_test(20) > Some(STREAM_WINDOW));
    }

    /// Spec §4.10.1: a stream counted on delivery ignores reports; one
    /// declared explicit, or covered by an explicit default, keeps what is
    /// not reported as unconsumed.
    #[test]
    fn consumption_is_counted_where_the_stream_says() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let out = client.send(now, 20, &vec![1u8; 10 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        assert!(server.unconsumed_streams().is_empty(), "taken as delivered");
        assert!(server.on_consumed(now, 20, 1024).is_empty());
        server.set_stream_consumption(21, Consumption::Explicit);
        let out = client.send(now, 21, &vec![1u8; 10 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        server.set_default_consumption(Consumption::Explicit);
        let out = client.send(now, 22, &vec![1u8; 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        assert_eq!(
            server.unconsumed_streams(),
            vec![(21, 10 * 1024), (22, 1024)]
        );
    }

    /// Spec §6.5: with credits the repaint after a resync goes with the
    /// `Reset`, before any `CREDIT`, when the dropped backlog fit under the
    /// old limit (100 KiB here, well under the implicit 512 KiB) -- and the
    /// sender's limit never passes the receiver's.
    #[test]
    fn a_resync_with_credits_lets_the_repaint_out_at_once() {
        let (mut client, mut server, caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let out = server.send(now, 0, &vec![b'a'; 100 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, Vec::new(), out);
        server.mark_output_desynced_for_test();
        let out = server.send(now, 0, b"the repaint");
        assert_eq!(data_offsets(&client, &out), vec![100 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, Vec::new(), out);
        assert!(collect_stream_data(&client.poll_events()).ends_with(b"the repaint"));
        assert!(server.credit_limit_for_test(0) <= client.receive_limit_for_test(0));
    }

    /// A `CREDIT` for a stream this side never wrote on grants nothing: the
    /// stream starts with its implicit window when it is made.
    #[test]
    fn a_credit_for_a_stream_never_written_changes_nothing() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        for dg in client.frames_for_test(vec![StreamFrame::Credit {
            stream_id: 40,
            limit: 1 << 30,
        }]) {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        let _ = server.send(now, 40, b"x");
        assert_eq!(server.credit_limit_for_test(40), Some(STREAM_WINDOW));
    }

    /// Minor 8 (review of this task): §6.1 gates every path that could
    /// build a `Credit` frame, not just the ones a happy-path test walks --
    /// `on_consumed`, a `Reset`'s ACK, a PONG and the timer -- even though
    /// both ends here are this build and support `stream-credit`: the
    /// client alone did not offer it, so it stays negotiated off (spec
    /// §5.2). The Reset leg uses a Reset that actually skips bytes the
    /// receiver never took (New Minor 1, re-review of fix round 1): a
    /// Reset to offset 0 on a stream nothing was ever sent on is a no-op
    /// (`on_reset` returns false), so it would read "0 CREDITs" whether or
    /// not negotiation gated anything. The control at the end runs the
    /// identical scenario with credits negotiated on both ends and shows it
    /// DOES build one, so the "0" above is a real negative.
    #[test]
    fn credit_stays_off_a_connection_that_did_not_negotiate_it() {
        let (mut client, mut server, caddr, saddr) = handshake_with_features(
            Features::HEADER_AAD | Features::OFFSET_WRAP,
            Features::SUPPORTED,
            false,
        );
        assert!(!client.features().contains(Features::STREAM_CREDIT));
        let now = Instant::now();
        server.set_stream_consumption(20, Consumption::Explicit);
        let out = client.send(now, 20, &vec![9u8; 2 * 1024 * 1024]);
        pump_pair(&mut client, &mut server, caddr, saddr, now, out, Vec::new());
        let _ = server.poll_events();
        let credit = server.on_consumed(now, 20, 1024 * 1024);
        assert!(credit.is_empty(), "on_consumed builds nothing");
        let mut t = now;
        for _ in 0..10 {
            t += server.rto();
            let out = server.on_timeout(t);
            assert_eq!(credit_frames(&client, &out), 0, "the timer builds nothing");
        }
        let ping = client.frames_for_test(vec![StreamFrame::Ping { token: 1 }]);
        let pong = server.on_datagram(t, caddr, &ping[0].bytes);
        assert_eq!(credit_frames(&client, &pong), 0, "the PONG builds nothing");

        // A Reset that genuinely moves the point forward: 4096 bytes queued
        // on stream 0, never delivered ("lost"), then the sender desyncs --
        // its own shift lands its base past them, so the Reset the resync
        // arms skips real, unconsumed bytes.
        let _lost = server.send(t, 0, &vec![1u8; 4096]);
        server.mark_output_desynced_for_test();
        let reset = server.send(t, 0, b"x");
        let mut replies = Vec::new();
        for dg in reset {
            replies.extend(client.on_datagram(t, saddr, &dg.bytes));
        }
        assert!(
            client
                .poll_events()
                .contains(&Event::StreamReset { stream_id: 0 }),
            "the Reset actually moved the point forward"
        );
        assert_eq!(
            credit_frames(&server, &replies),
            0,
            "a Reset's ACK builds nothing either"
        );
        assert_eq!(
            client.credit_limit_for_test(20),
            None,
            "the sender holds no limit"
        );
        assert_eq!(
            server.receive_limit_for_test(20),
            None,
            "the receiver announced no limit"
        );

        // Control: the identical Reset scenario, credits negotiated on
        // both ends this time, DOES build one.
        let (mut c2, mut s2, _ca2, sa2) = established_pair();
        let t2 = c2.handshake_at;
        let _lost2 = s2.send(t2, 0, &vec![1u8; 4096]);
        s2.mark_output_desynced_for_test();
        let reset2 = s2.send(t2, 0, b"x");
        let mut replies2 = Vec::new();
        for dg in reset2 {
            replies2.extend(c2.on_datagram(t2, sa2, &dg.bytes));
        }
        assert!(
            c2.poll_events()
                .contains(&Event::StreamReset { stream_id: 0 }),
            "the control's Reset also moved the point"
        );
        assert_eq!(
            credit_frames(&s2, &replies2),
            1,
            "with credits negotiated, the same Reset DOES build one"
        );
    }

    /// The frames a batch of datagrams carries, read by the peer they go to.
    fn frames_read_by(reader: &Connection, out: &[Datagram]) -> Vec<StreamFrame> {
        out.iter()
            .filter_map(|d| reader.peek_frames(&d.bytes))
            .flatten()
            .collect()
    }

    /// Puts `ids` on `client` in "possibly stopped" the way a server's
    /// `Reset` does (spec §6.5): one `Reset { new_offset: 1 }` each, whose
    /// urgent CREDIT (`q + STREAM_WINDOW`) the sender is taken not to have
    /// heard -- its data ends exactly at `q`, the oldest limit it may hold.
    /// Honest for one or two screen streams after a desync; a hostile
    /// server can do it on every stream number.
    fn stop_client_streams_by_reset(
        client: &mut Connection,
        server: &mut Connection,
        saddr: SocketAddr,
        now: Instant,
        ids: impl IntoIterator<Item = u8>,
    ) {
        let resets: Vec<StreamFrame> = ids
            .into_iter()
            .map(|stream_id| StreamFrame::Reset {
                stream_id,
                new_offset: 1,
            })
            .collect();
        for dg in server.frames_for_test(resets) {
            let _ = client.on_datagram(now, saddr, &dg.bytes);
        }
    }

    /// Final review C1, ruling R15 (spec §6.4 amended): however many
    /// streams may be stopped, one PING draws one PONG and at most one
    /// CREDIT copy. Before the bound, each of the 256 streams put in
    /// "possibly stopped" by a `Reset` added its own CREDIT datagram to
    /// every PONG: one PING drew 257 datagrams.
    #[test]
    fn a_ping_draws_one_pong_and_at_most_one_credit_however_many_streams_stopped() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let mut now = client.handshake_at;
        stop_client_streams_by_reset(&mut client, &mut server, saddr, now, 0..=255u8);
        let _ = client.poll_events();
        let rto = client.rto_for_test();
        // Past every stream's last send and its repeats: every stream is
        // eligible for a PONG copy now.
        for _ in 0..8 {
            now += rto;
            let _ = client.on_timeout(now);
        }
        for token in 0..20u32 {
            let ping = server.frames_for_test(vec![StreamFrame::Ping { token }]);
            let answers = client.on_datagram(now, saddr, &ping[0].bytes);
            let frames = frames_read_by(&server, &answers);
            assert!(
                answers.len() <= 2,
                "PING {token}: {} datagrams",
                answers.len()
            );
            assert_eq!(
                frames
                    .iter()
                    .filter(|f| matches!(f, StreamFrame::Pong { .. }))
                    .count(),
                1,
                "PING {token}: one PONG"
            );
            assert_eq!(
                credit_frames(&server, &answers),
                1,
                "PING {token}: one CREDIT copy, not one per stream"
            );
        }
    }

    /// Ruling R16 with ruling R15: a client whose 256 streams may all be
    /// stopped answers a datagram of 270 PINGs with one PONG and one CREDIT
    /// copy, in one datagram. Per frame it drew 270 PONGs and 256 CREDITs.
    /// (The client side: the code is the same for both roles, and this is
    /// where every stream can be put in "possibly stopped" cheaply.)
    #[test]
    fn a_datagram_of_pings_draws_one_pong_and_one_credit_copy_in_one_datagram() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let mut now = client.handshake_at;
        stop_client_streams_by_reset(&mut client, &mut server, saddr, now, 0..=255u8);
        let _ = client.poll_events();
        let rto = client.rto_for_test();
        for _ in 0..8 {
            now += rto;
            let _ = client.on_timeout(now);
        }
        let dg = server.packed_for_test(
            (0..270u32)
                .map(|token| StreamFrame::Ping { token })
                .collect(),
        );
        let answers = client.on_datagram(now, saddr, &dg.bytes);
        assert_eq!(answers.len(), 1, "one datagram");
        let frames = frames_read_by(&server, &answers);
        assert_eq!(frames.len(), 2, "a PONG and one CREDIT copy: {frames:?}");
        assert!(frames.contains(&StreamFrame::Pong { token: 269 }));
        assert_eq!(credit_frames(&server, &answers), 1);
    }

    /// Ruling R16: an authenticated client's datagram of 270 PINGs draws one
    /// PONG from the daemon, for its last token.
    #[test]
    fn a_server_answers_a_datagram_of_pings_once() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let dg = client.packed_for_test(
            (0..270u32)
                .map(|token| StreamFrame::Ping { token })
                .collect(),
        );
        let answers = server.on_datagram(now, caddr, &dg.bytes);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            frames_read_by(&client, &answers),
            vec![StreamFrame::Pong { token: 269 }]
        );
    }

    /// Ruling R16 (spec §4.11): DATA frames of one stream in one datagram
    /// draw one ACK, for the point the last of them left. Four of them, so
    /// the ACK is due at once under the rules of Task 3 as well.
    #[test]
    fn data_frames_of_one_stream_in_one_datagram_draw_one_ack() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let frames: Vec<StreamFrame> = (0..4u32)
            .map(|i| StreamFrame::Data {
                stream_id: 20,
                offset: i * 3,
                data: b"abc".to_vec(),
            })
            .collect();
        let dg = client.packed_for_test(frames);
        let answers = server.on_datagram(now, caddr, &dg.bytes);
        assert_eq!(
            frames_read_by(&client, &answers),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 12
            }]
        );
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 20),
            b"abcabcabcabc"
        );
    }

    /// Spec §4.11: a full segment and 22 six-byte frames share one
    /// datagram's 1 166 bytes; the 23rd opens another. Ordered frames keep
    /// their order even when a later one would fit an earlier datagram.
    #[test]
    fn packing_fills_a_datagram_to_its_limit_and_keeps_order() {
        let segment = StreamFrame::Data {
            stream_id: 20,
            offset: 0,
            data: vec![7u8; crate::reliability::MAX_SEGMENT_SIZE],
        };
        let acks: Vec<StreamFrame> = (0..23u8)
            .map(|s| StreamFrame::Ack {
                stream_id: s,
                cum_ack: 1,
            })
            .collect();
        let packed = pack(std::slice::from_ref(&segment), &acks);
        assert_eq!(packed.len(), 2);
        assert_eq!(packed[0].len(), 1032 + 22 * 6);
        assert!(packed[0].len() <= crate::wire::MAX_PLAINTEXT);
        assert_eq!(StreamFrame::decode_all(&packed[1]).len(), 1);
        let ordered = vec![
            StreamFrame::Data {
                stream_id: 20,
                offset: 0,
                data: vec![1u8; 700],
            },
            StreamFrame::Data {
                stream_id: 20,
                offset: 700,
                data: vec![1u8; 700],
            },
            StreamFrame::Data {
                stream_id: 20,
                offset: 1400,
                data: vec![1u8; 10],
            },
        ];
        let packed = pack(&ordered, &[]);
        let offsets: Vec<u32> = packed
            .iter()
            .flat_map(|p| StreamFrame::decode_all(p))
            .filter_map(|f| match f {
                StreamFrame::Data { offset, .. } => Some(offset),
                _ => None,
            })
            .collect();
        assert_eq!(offsets, vec![0, 700, 1400], "in order across datagrams");
        assert_eq!(
            packed.len(),
            2,
            "the short third rides with the second, not the first"
        );
    }

    /// Spec §4.11: the limit is exactly `MAX_PLAINTEXT` = 1 166 bytes, for
    /// ordered frames and service frames alike -- frames that total 1 166
    /// bytes stay in one plaintext (1 200 bytes on the wire), one byte more
    /// splits them.
    #[test]
    fn packing_holds_exactly_the_plaintext_limit() {
        let segment = StreamFrame::Data {
            stream_id: 20,
            offset: 0,
            data: vec![7u8; crate::reliability::MAX_SEGMENT_SIZE],
        };
        let tail = |len: usize| StreamFrame::Data {
            stream_id: 20,
            offset: crate::reliability::MAX_SEGMENT_SIZE as u32,
            data: vec![8u8; len],
        };
        // Ordered: 1 032 + (8 + 126) = 1 166.
        let packed = pack(&[segment.clone(), tail(126)], &[]);
        assert_eq!(
            packed.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![crate::wire::MAX_PLAINTEXT]
        );
        let packed = pack(&[segment.clone(), tail(127)], &[]);
        assert_eq!(packed.len(), 2, "1 167 bytes of ordered frames split");
        // Service: 1 032 + 8 + 21 * 6 = 1 166.
        let acks: Vec<StreamFrame> = (0..21u8)
            .map(|s| StreamFrame::Ack {
                stream_id: s,
                cum_ack: 1,
            })
            .collect();
        let packed = pack(&[segment.clone(), tail(0)], &acks);
        assert_eq!(
            packed.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![crate::wire::MAX_PLAINTEXT]
        );
        let packed = pack(&[segment, tail(1)], &acks);
        assert_eq!(
            packed.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1032 + 9 + 20 * 6, 6],
            "the ACK that would make 1 167 bytes opens a plaintext of its own"
        );
        let mut out = Vec::new();
        let (mut client, _server, _caddr, _saddr) = established_pair();
        let peer = client.peer.expect("a peer");
        assert!(client.seal_to(peer, &vec![0u8; crate::wire::MAX_PLAINTEXT], &mut out));
        assert_eq!(out[0].bytes.len(), crate::wire::MAX_DATAGRAM);
    }

    /// Ruling R16 with spec §4.11: an answer longer than one datagram --
    /// ACKs for 200 streams, 1 200 bytes of them -- goes out in as many
    /// datagrams of at most `MAX_DATAGRAM` bytes as it needs: 194 ACKs fill
    /// the first 1 164 bytes, the other six the second.
    #[test]
    fn an_answer_past_one_datagram_splits_at_the_limit() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let dg = client.packed_for_test(
            (0..200u8)
                .map(|i| StreamFrame::Data {
                    stream_id: 40 + i,
                    offset: 0,
                    data: Vec::new(),
                })
                .collect(),
        );
        let answers = server.on_datagram(now, caddr, &dg.bytes);
        assert!(
            answers
                .iter()
                .all(|d| d.bytes.len() <= crate::wire::MAX_DATAGRAM),
            "{answers:?}"
        );
        let per_datagram: Vec<usize> = answers
            .iter()
            .map(|d| client.peek_frames(&d.bytes).expect("readable").len())
            .collect();
        assert_eq!(per_datagram, vec![194, 6]);
        let frames = frames_read_by(&client, &answers);
        assert!(frames.iter().all(|f| matches!(f, StreamFrame::Ack { .. })));
        let streams: HashSet<u8> = frames
            .iter()
            .filter_map(|f| match f {
                StreamFrame::Ack { stream_id, .. } => Some(*stream_id),
                _ => None,
            })
            .collect();
        assert_eq!(streams.len(), 200, "one ACK per stream named");
    }

    /// Spec §4.11: what a flush puts out is packed, and the ACK waiting for
    /// a ride goes in it -- three keystrokes written while the road was down
    /// leave in one datagram with the ACK of what brought the road back.
    #[test]
    fn a_flush_packs_its_frames_and_the_waiting_ack_rides_along() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let t0 = client.handshake_at;
        let t1 = t0 + PATH_DOWN_AFTER;
        let _ = client.on_timeout(t1);
        assert_eq!(client.state(), LinkState::PathDown);
        for stream in [16u8, 17, 18] {
            assert!(
                client.send(t1, stream, b"k").is_empty(),
                "queued while the road is down"
            );
        }
        let from_server = server.send(t1, 30, b"x");
        assert_eq!(from_server.len(), 1);
        let answers = client.on_datagram(t1, saddr, &from_server[0].bytes);
        assert_eq!(answers.len(), 1, "one datagram: {answers:?}");
        let frames = frames_read_by(&server, &answers);
        assert_eq!(
            frames
                .iter()
                .filter(|f| matches!(f, StreamFrame::Data { .. }))
                .count(),
            3
        );
        assert!(frames.contains(&StreamFrame::Ack {
            stream_id: 30,
            cum_ack: 1
        }));
    }

    /// Ruling R15 (spec §6.4 amended): the streams that may be stopped take
    /// the PONG's one copy in turn, and none hears its newest limit from a
    /// PONG less than an `rto` after it last went out -- however fast the
    /// PINGs come. Before the bound every PING carried a copy for every
    /// stream; with the turn alone and no `rto` rule, each of four streams
    /// would get one every fourth PING.
    #[test]
    fn repeated_pings_draw_at_most_one_copy_per_stream_per_rto() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let t0 = client.handshake_at;
        let ids = [20u8, 21, 22, 23];
        stop_client_streams_by_reset(&mut client, &mut server, saddr, t0, ids);
        let rto = client.rto_for_test();
        let mut copies: BTreeMap<u8, Vec<Instant>> = BTreeMap::new();
        let mut now = t0;
        let end = t0 + 10 * rto;
        let mut token = 0u32;
        while now <= end {
            let ping = server.frames_for_test(vec![StreamFrame::Ping { token }]);
            token += 1;
            let answers = client.on_datagram(now, saddr, &ping[0].bytes);
            let credits: Vec<u8> = frames_read_by(&server, &answers)
                .into_iter()
                .filter_map(|f| match f {
                    StreamFrame::Credit { stream_id, .. } => Some(stream_id),
                    _ => None,
                })
                .collect();
            assert!(credits.len() <= 1, "one copy per PONG at most: {credits:?}");
            for id in credits {
                copies.entry(id).or_default().push(now);
            }
            now += Duration::from_millis(10);
        }
        assert_eq!(
            copies.keys().copied().collect::<Vec<_>>(),
            ids.to_vec(),
            "every stopped stream is served in turn"
        );
        for (id, times) in &copies {
            for pair in times.windows(2) {
                assert!(
                    pair[1] - pair[0] >= rto,
                    "stream {id}: copies {:?} apart, under the rto {rto:?}",
                    pair[1] - pair[0]
                );
            }
            assert!(
                times.len() >= 8,
                "stream {id}: still about one copy per rto ({} in ten)",
                times.len()
            );
        }
    }

    /// Ruling R15 (spec §6.4 amended): at the PING pace of a real peer --
    /// slower than an `rto`, so every stream is eligible at every PING --
    /// the one copy still goes round: with `k` streams that may be stopped,
    /// each hears its newest within `k` PINGs. Starting the search at the
    /// same stream every time would give the first stream every copy and
    /// the others none, for good.
    #[test]
    fn at_a_slow_ping_pace_every_stopped_stream_gets_its_turn() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let t0 = client.handshake_at;
        let ids = [20u8, 21, 22, 23];
        stop_client_streams_by_reset(&mut client, &mut server, saddr, t0, ids);
        let pace = 2 * client.rto_for_test();
        let mut now = t0;
        let mut order = Vec::new();
        for token in 0..(3 * ids.len() as u32) {
            now += pace;
            let ping = server.frames_for_test(vec![StreamFrame::Ping { token }]);
            let answers = client.on_datagram(now, saddr, &ping[0].bytes);
            order.extend(
                frames_read_by(&server, &answers)
                    .into_iter()
                    .filter_map(|f| match f {
                        StreamFrame::Credit { stream_id, .. } => Some(stream_id),
                        _ => None,
                    }),
            );
        }
        assert_eq!(order.len(), 3 * ids.len(), "a copy with every PING");
        let round: Vec<u8> = ids.iter().copied().cycle().take(order.len()).collect();
        assert_eq!(order, round, "the streams take the copy in turn");
    }

    /// Ruling R15 (spec §6.5 amended): a server drops a client's `Reset`
    /// whole -- no answer, no point moved, no stream made, no CREDIT then
    /// or with a later PONG. No client build sends one; taken, one per
    /// stream number was the lever of a PONG fan-out.
    #[test]
    fn a_server_takes_nothing_from_a_clients_reset() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let mut now = client.handshake_at;
        // Stream 20 holds a delivered first KiB; a Reset would jump past
        // the next.
        for dg in client.frames_for_test(vec![StreamFrame::Data {
            stream_id: 20,
            offset: 0,
            data: vec![1u8; 1024],
        }]) {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        let _ = server.poll_events();
        let resets: Vec<StreamFrame> = (0..=255u8)
            .map(|stream_id| StreamFrame::Reset {
                stream_id,
                new_offset: 4096,
            })
            .collect();
        let mut drawn = 0;
        for dg in client.frames_for_test(resets) {
            drawn += server.on_datagram(now, caddr, &dg.bytes).len();
        }
        assert_eq!(drawn, 0, "a client's Reset draws nothing, not even an ACK");
        assert!(
            !server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::StreamReset { .. })),
            "no point moved"
        );
        assert_eq!(server.receive_limit_for_test(21), None, "no stream made");
        assert_eq!(
            server.receive_limit_for_test(20),
            Some(STREAM_WINDOW),
            "nothing counted as taken, no limit announced"
        );
        // The point stayed at 1024: the next KiB is delivered, not skipped.
        for dg in client.frames_for_test(vec![StreamFrame::Data {
            stream_id: 20,
            offset: 1024,
            data: vec![2u8; 1024],
        }]) {
            let _ = server.on_datagram(now, caddr, &dg.bytes);
        }
        assert_eq!(
            collect_stream_data_for(&server.poll_events(), 20),
            vec![2u8; 1024]
        );
        let mut credits = 0;
        for _ in 0..8 {
            now += server.rto();
            credits += credit_frames(&client, &server.on_timeout(now));
        }
        let ping = client.frames_for_test(vec![StreamFrame::Ping { token: 5 }]);
        let pong = server.on_datagram(now, caddr, &ping[0].bytes);
        credits += credit_frames(&client, &pong);
        assert_eq!(pong.len(), 1, "the PING draws its PONG alone");
        assert_eq!(credits, 0, "no repeats, no PONG copies");
    }

    /// `from` sends DATA of `len` bytes on `stream_id` at each of
    /// `offsets`, each in its own datagram; what `to` answers to each.
    fn data_in_turn(
        from: &mut Connection,
        to: &mut Connection,
        from_addr: SocketAddr,
        now: Instant,
        stream_id: u8,
        offsets: &[u32],
        len: usize,
    ) -> Vec<Vec<Datagram>> {
        offsets
            .iter()
            .map(|&offset| {
                let dg = from.frames_for_test(vec![StreamFrame::Data {
                    stream_id,
                    offset,
                    data: vec![b'd'; len],
                }]);
                to.on_datagram(now, from_addr, &dg[0].bytes)
            })
            .collect()
    }

    /// Spec §4.11: in-order DATA is acknowledged every `ACK_EVERY` frames.
    #[test]
    fn in_order_data_is_acknowledged_every_fourth_frame() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let answers = data_in_turn(
            &mut client,
            &mut server,
            caddr,
            now,
            20,
            &[0, 100, 200, 300],
            100,
        );
        assert!(
            answers[..3].iter().all(Vec::is_empty),
            "three held: {answers:?}"
        );
        assert_eq!(
            frames_read_by(&client, &answers[3]),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 400
            }]
        );
    }

    /// Spec §4.11 (Review Focus 1), and the slice-1 invariant: an ACK
    /// nothing carries goes alone exactly `ACK_DELAY` after it was owed, the
    /// deadline is in `next_timeout`, and `on_timeout` consumes it.
    #[test]
    fn a_lone_segment_is_acknowledged_ack_delay_later_and_that_deadline_is_served() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let answers = data_in_turn(&mut client, &mut server, caddr, now, 20, &[0], 100);
        assert!(answers[0].is_empty());
        assert_eq!(server.next_timeout(), Some(now + ACK_DELAY));
        assert!(
            server
                .on_timeout(now + ACK_DELAY - Duration::from_millis(1))
                .is_empty(),
            "not before"
        );
        let out = server.on_timeout(now + ACK_DELAY);
        assert_eq!(
            frames_read_by(&client, &out),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 100
            }]
        );
        assert!(
            server.next_timeout().is_some_and(|t| t > now + ACK_DELAY),
            "the deadline was consumed"
        );
    }

    /// Spec §4.11 and RFC 5681 §4.2 (decision 2): DATA past a hole, a
    /// repeat of what was delivered, and the DATA that fills the hole are
    /// each acknowledged at once.
    #[test]
    fn data_past_a_hole_a_repeat_and_the_filling_segment_are_acknowledged_at_once() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        let answers = data_in_turn(&mut client, &mut server, caddr, now, 20, &[0, 200], 100);
        assert!(answers[0].is_empty(), "in order: held");
        assert_eq!(
            frames_read_by(&client, &answers[1]),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 100
            }]
        );
        let answers = data_in_turn(&mut client, &mut server, caddr, now, 20, &[0], 100);
        assert_eq!(
            frames_read_by(&client, &answers[0]),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 100
            }]
        );
        let answers = data_in_turn(&mut client, &mut server, caddr, now, 20, &[100], 100);
        assert_eq!(
            frames_read_by(&client, &answers[0]),
            vec![StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 300
            }]
        );
    }

    /// Spec §4.11, §6.5: a `Reset` is acknowledged at once, with its room --
    /// and at once as well where no room is announced (a peer without
    /// credits): the ACK does not wait for a `CREDIT` to make it urgent.
    #[test]
    fn a_reset_is_acknowledged_at_once_with_its_room() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let reset = server.frames_for_test(vec![StreamFrame::Reset {
            stream_id: 0,
            new_offset: 50,
        }]);
        let answers = client.on_datagram(now, saddr, &reset[0].bytes);
        let frames = frames_read_by(&server, &answers);
        assert!(
            frames.contains(&StreamFrame::Ack {
                stream_id: 0,
                cum_ack: 50
            }),
            "{frames:?}"
        );
        assert_eq!(credit_frames(&server, &answers), 1);

        let (mut client, mut server, _caddr, saddr) =
            handshake_with_features(Features::SUPPORTED, Features::NONE, false);
        assert!(!client.features().contains(Features::STREAM_CREDIT));
        let now = Instant::now();
        let reset = server.frames_for_test(vec![StreamFrame::Reset {
            stream_id: 0,
            new_offset: 50,
        }]);
        let answers = client.on_datagram(now, saddr, &reset[0].bytes);
        assert_eq!(
            frames_read_by(&server, &answers),
            vec![StreamFrame::Ack {
                stream_id: 0,
                cum_ack: 50
            }],
            "no credits: the ACK alone, still at once"
        );
    }

    /// Spec §4.11: a waiting ACK rides the next keystroke.
    #[test]
    fn a_waiting_ack_rides_the_next_keystroke() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let out = server.send(now, 20, b"out");
        assert!(
            client.on_datagram(now, saddr, &out[0].bytes).is_empty(),
            "held"
        );
        let t = now + Duration::from_millis(5);
        let keystroke = client.send(t, 16, b"k");
        assert_eq!(keystroke.len(), 1);
        let frames = frames_read_by(&server, &keystroke);
        assert!(
            frames.contains(&StreamFrame::Ack {
                stream_id: 20,
                cum_ack: 3
            }),
            "{frames:?}"
        );
        assert!(frames
            .iter()
            .any(|f| matches!(f, StreamFrame::Data { stream_id: 16, .. })));
        assert!(
            client.next_timeout().is_some_and(|d| d > now + ACK_DELAY),
            "nothing left to go alone"
        );
    }

    /// Spec §4.11 (§9.2 L2, "PONG is not delayed"): a PING is answered in
    /// the call that read it, and the PONG carries what waits.
    #[test]
    fn a_ping_is_answered_at_once_and_its_pong_carries_what_waits() {
        let (mut client, mut server, _caddr, saddr) = established_pair();
        let now = client.handshake_at;
        let out = server.send(now, 20, b"out");
        assert!(client.on_datagram(now, saddr, &out[0].bytes).is_empty());
        let ping = server.frames_for_test(vec![StreamFrame::Ping { token: 7 }]);
        let answers = client.on_datagram(now, saddr, &ping[0].bytes);
        assert_eq!(answers.len(), 1);
        assert_eq!(
            frames_read_by(&server, &answers),
            vec![
                StreamFrame::Pong { token: 7 },
                StreamFrame::Ack {
                    stream_id: 20,
                    cum_ack: 3
                }
            ]
        );
    }

    /// Spec §4.11 with §6.4: room for a sender that may be stopped at its
    /// limit goes at once; room for one still writing waits for a ride,
    /// `ACK_DELAY` at most.
    #[test]
    fn room_for_a_stopped_sender_goes_at_once_and_other_room_waits() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        server.set_stream_consumption(30, Consumption::Explicit);
        server.set_stream_consumption(31, Consumption::Explicit);
        let window = STREAM_WINDOW as usize;
        let segment_offsets =
            |n: usize| -> Vec<u32> { (0..n).map(|i| (i * MAX_SEGMENT_SIZE) as u32).collect() };
        let _ = data_in_turn(
            &mut client,
            &mut server,
            caddr,
            now,
            30,
            &segment_offsets(window / MAX_SEGMENT_SIZE),
            MAX_SEGMENT_SIZE,
        );
        let _ = data_in_turn(
            &mut client,
            &mut server,
            caddr,
            now,
            31,
            &segment_offsets(window / 2 / MAX_SEGMENT_SIZE),
            MAX_SEGMENT_SIZE,
        );
        let t = now + ACK_DELAY;
        let _ = server.on_timeout(t);
        let at_once = server.on_consumed(t, 30, CREDIT_UPDATE_STEP as usize);
        assert_eq!(
            credit_frames(&client, &at_once),
            1,
            "stream 30 stopped at its limit: at once"
        );
        let later = server.on_consumed(t, 31, CREDIT_UPDATE_STEP as usize);
        assert!(
            later.is_empty(),
            "stream 31 still writing: waits for a ride"
        );
        assert_eq!(server.next_timeout(), Some(t + ACK_DELAY));
        assert_eq!(credit_frames(&client, &server.on_timeout(t + ACK_DELAY)), 1);
    }

    /// Task 2 review, minor 1: a consumer's late report on a closed
    /// connection still counts (the daemon's ledger settles against it) but
    /// owes nothing -- nothing would ever send it (`on_datagram` and
    /// `on_timeout` refuse a closed connection), so a CREDIT queued there
    /// would only sit, contradicting "sends nothing". While open, the same
    /// report owes one.
    #[test]
    fn a_closed_connection_owes_nothing_for_a_late_report() {
        let (mut client, mut server, caddr, _saddr) = established_pair();
        let now = client.handshake_at;
        server.set_stream_consumption(30, Consumption::Explicit);
        let step = CREDIT_UPDATE_STEP as usize;
        let offsets: Vec<u32> = (0..2 * step / MAX_SEGMENT_SIZE)
            .map(|i| (i * MAX_SEGMENT_SIZE) as u32)
            .collect();
        let _ = data_in_turn(
            &mut client,
            &mut server,
            caddr,
            now,
            30,
            &offsets,
            MAX_SEGMENT_SIZE,
        );
        let _ = held_acks(&mut server, now);
        assert!(
            server.on_consumed(now, 30, step).is_empty(),
            "a sender still writing: it rides"
        );
        assert!(
            !server.credits_due.is_empty(),
            "open: the report owes a CREDIT"
        );
        let _ = held_acks(&mut server, now);
        let _ = server.close(now);
        assert!(
            server.on_consumed(now, 30, step).is_empty(),
            "a closed connection sends nothing"
        );
        assert!(server.credits_due.is_empty(), "and owes nothing");
        assert_eq!(server.service_since, None);
    }
}
