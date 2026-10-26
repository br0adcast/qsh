//! A deterministic network simulator for one client and one server
//! `Connection` (spec `2026-09-26-qsh-transport-defects-design.md` in the app
//! repository, §9.1).
//!
//! Time is virtual: the simulator keeps its own clock and hands every
//! `Connection` call an `Instant` computed from it, so a minute of traffic
//! runs in milliseconds and nothing waits for the real clock. Randomness is a
//! SplitMix64 with a caller-chosen seed, written out here rather than taken
//! from `rand`, so a run repeats exactly whatever version of any dependency
//! is built. (Keys, session ids and nonces are still random -- they change
//! bytes, never sizes or timing, so they change nothing a scenario observes.)
//! Both connections are built with `Connection::new_at` at the virtual start,
//! so none of their clocks comes from the real one.
//!
//! Every road has one link per direction: a one-way delay, uniform jitter
//! (delay variation on a FIFO link -- it never reorders), loss, reordering
//! (an extra delay for some datagrams, the one source of reordering), a
//! bandwidth with a serialization queue, and a limit on that queue. After every event -- a
//! scripted action, a delivery, a handshake retransmit -- both sides' timers
//! run by the rule every driver follows (`Connection::on_timeout_if_due`).
//! msg1 is retransmitted the way `driver_std` does it, and the server answers
//! a byte-identical msg1 retransmit with its first msg2, as the session
//! manager's `ResendMsg2` path does. A server may have the session manager's
//! return-address check in front of it (`Sim::guard_server`), and forged
//! datagrams can reach it from addresses no road has
//! (`Sim::inject_to_server`) -- or reach the client in the server's name
//! (`Sim::inject_to_client`). The client offers what this build
//! implements, so every scenario runs with the header under the AEAD unless
//! a side plays an old build (`Sim::play_legacy`).
//!
//! A side's consumer of a stream may take its bytes on delivery (every
//! stream's default), take nothing, or take them at a rate
//! (`Sim::set_consumer`); the simulator then reports what was delivered and
//! not taken, and what each side held out of order, at their peaks.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::conn::{
    AuthPolicy, Connection, ConnectionConfig, Consumption, Datagram, Event, LinkState, Role,
};
use crate::cookie::{CookieCheck, Verdict};
use crate::driver_std::HANDSHAKE_RETRANSMIT;
use crate::features::Features;
use crate::handshake::generate_keypair;
use crate::handshake_payload::{encode_msg1_without_tail, AuthMethod, Msg1Payload, StartKind};
use crate::reliability::StreamFrame;
use crate::wire::{encode_handshake, parse, Frame, Kind};

/// How many timer services in a row a side may have that put nothing on the
/// wire while one of its deadlines is still due. One or two are legitimate --
/// a PING minted as unanswered makes the road checks urgent, a state change
/// makes the next action due -- but a deadline `on_timeout` never consumes
/// would have every real driver loop wake every millisecond, and the
/// simulator reports it instead of hiding it. A service that DID send may
/// leave a deadline due: that is the bulk budget (spec §4.8), and the next
/// step serves it after whatever else is due at the same instant, as the
/// driver takes its commands between passes.
const TIMER_SERVICES_PER_INSTANT: usize = 8;

/// How many timer services one side may have at a single virtual instant
/// with nothing else to do -- no action, wake-up or delivery of an earlier
/// datagram in the same step -- whatever they send. The bulk budget
/// legitimately leaves a deadline due after a service that sent something,
/// but a full window takes `MAX_IN_FLIGHT / MAX_SEGMENT_SIZE /
/// BULK_FLUSH_BUDGET` = 8 services to put out; a deadline that stays due
/// while every service sends something (a forced PING never cleared, say)
/// would otherwise keep virtual time from advancing and hang the test run
/// instead of failing it. A service that follows the delivery of a datagram
/// sent BEFORE this instant is not counted: it is the driver's rule after
/// every wake-up, there is one per datagram, and those datagrams are finite
/// -- a road with no bandwidth limit lands a whole flight at one instant.
/// A datagram sent at this very instant (a road with no delay) exempts
/// nothing: a side stuck at one instant would otherwise feed itself the
/// exemptions.
const MAX_TIMER_SERVICES_AT_ONE_INSTANT: usize = 64;

/// How many steps of any kind the simulator takes at one virtual instant
/// before it calls the run stuck: a crude backstop for a loop the checks
/// above do not see (an action that reschedules itself at the same instant,
/// a ping-pong of deliveries over a road with no delay). A real burst is a
/// window of datagrams, a few hundred steps.
const MAX_STEPS_AT_ONE_INSTANT: usize = 1 << 16;

/// How a side's consumer takes a stream's bytes (spec §9.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Consumer {
    /// Everything, the moment it is delivered: every stream's default.
    OnDelivery,
    /// Nothing, until told otherwise.
    Stalled,
    /// This many bytes a second, in steps of [`CONSUME_TICK`].
    Rate(u64),
}

/// How often a consumer at a rate takes its share.
pub const CONSUME_TICK: Duration = Duration::from_millis(10);

/// SplitMix64 (Steele, Lea, Flood 2014; Vigna's reference `splitmix64.c`).
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`, from the top 53 bits.
    pub fn next_unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// What one direction of one road does to a datagram.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkSpec {
    /// One-way delay.
    pub delay: Duration,
    /// Delay variation: each datagram's delay moves by a uniform amount in
    /// `[-jitter, +jitter]` (floored at zero), but the link stays FIFO -- a
    /// datagram that would arrive before the one sent ahead of it waits for
    /// it, the way delay variation from a queue behaves. Jitter never
    /// reorders; `reorder` is the one source of reordering.
    pub jitter: Duration,
    /// Probability that a datagram is lost. The loss happens past the
    /// bottleneck: a lost datagram still occupies the serializer (and the
    /// queue) for its length, as a drop further down the path would.
    pub loss: f64,
    /// Probability that a datagram is held back by `reorder_extra` after its
    /// FIFO arrival, so the datagrams behind it overtake it. The only source
    /// of reordering on a link.
    pub reorder: f64,
    pub reorder_extra: Duration,
    /// Bytes per second; `None` is an infinitely fast link.
    pub bandwidth: Option<u64>,
    /// Bytes that may wait for serialization; a datagram that would go past
    /// it is dropped (tail drop). Only meaningful with a bandwidth.
    pub queue_limit: Option<usize>,
}

impl LinkSpec {
    pub fn new(delay: Duration) -> Self {
        LinkSpec {
            delay,
            jitter: Duration::ZERO,
            loss: 0.0,
            reorder: 0.0,
            reorder_extra: Duration::ZERO,
            bandwidth: None,
            queue_limit: None,
        }
    }

    pub fn with_jitter(mut self, jitter: Duration) -> Self {
        self.jitter = jitter;
        self
    }

    pub fn with_loss(mut self, loss: f64) -> Self {
        self.loss = loss;
        self
    }

    pub fn with_reorder(mut self, probability: f64, extra: Duration) -> Self {
        self.reorder = probability;
        self.reorder_extra = extra;
        self
    }

    pub fn with_bandwidth(mut self, bytes_per_sec: u64, queue_limit: Option<usize>) -> Self {
        self.bandwidth = Some(bytes_per_sec);
        self.queue_limit = queue_limit;
        self
    }
}

/// What happened to the datagrams one link was given.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkCounters {
    pub sent: u64,
    pub lost: u64,
    pub queue_dropped: u64,
    pub delivered: u64,
}

struct Link {
    spec: LinkSpec,
    /// When the serializer is free again.
    busy_until: Duration,
    /// The latest in-order arrival so far: the FIFO floor for the next
    /// datagram's arrival (a datagram held back by `reorder` does not raise it).
    last_arrival: Duration,
    counters: LinkCounters,
}

impl Link {
    fn new(spec: LinkSpec) -> Self {
        Link {
            spec,
            busy_until: Duration::ZERO,
            last_arrival: Duration::ZERO,
            counters: LinkCounters::default(),
        }
    }

    /// Take a datagram of `len` bytes at `now`; return when it arrives, or
    /// `None` if it is lost or dropped.
    fn admit(&mut self, now: Duration, len: usize, rng: &mut SplitMix64) -> Option<Duration> {
        // Every datagram draws the same three numbers whatever becomes of it,
        // so one datagram's fate never shifts the random stream of the rest.
        let loss_draw = rng.next_unit();
        let jitter_draw = rng.next_unit();
        let reorder_draw = rng.next_unit();
        self.counters.sent += 1;
        let departs = match self.spec.bandwidth {
            None => now,
            Some(bps) => {
                let start = self.busy_until.max(now);
                if let Some(limit) = self.spec.queue_limit {
                    let waiting = (start - now).as_nanos() * u128::from(bps) / 1_000_000_000;
                    if waiting as usize + len > limit {
                        self.counters.queue_dropped += 1;
                        return None;
                    }
                }
                let serialize =
                    Duration::from_nanos((len as u128 * 1_000_000_000 / u128::from(bps)) as u64);
                self.busy_until = start + serialize;
                self.busy_until
            }
        };
        if loss_draw < self.spec.loss {
            self.counters.lost += 1;
            return None;
        }
        let shift = self.spec.jitter.as_nanos() as f64 * (2.0 * jitter_draw - 1.0);
        let delay = if shift >= 0.0 {
            self.spec.delay + Duration::from_nanos(shift as u64)
        } else {
            self.spec
                .delay
                .saturating_sub(Duration::from_nanos((-shift) as u64))
        };
        // FIFO: jitter varies the delay but cannot overtake the datagram ahead.
        let in_order = (departs + delay).max(self.last_arrival);
        self.last_arrival = in_order;
        self.counters.delivered += 1;
        if reorder_draw < self.spec.reorder {
            Some(in_order + self.spec.reorder_extra)
        } else {
            Some(in_order)
        }
    }
}

/// One road: `up` carries client -> server, `down` server -> client.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RoadSpec {
    pub up: LinkSpec,
    pub down: LinkSpec,
}

impl RoadSpec {
    pub fn symmetric(link: LinkSpec) -> Self {
        RoadSpec {
            up: link,
            down: link,
        }
    }
}

struct Road {
    /// The client's address as the server sees it over this road.
    client_addr: SocketAddr,
    /// Addresses the client had on this road before a NAT gave it a new
    /// port, whose mappings still deliver the server's datagrams (see
    /// [`Sim::rebind_client_port`]).
    old_client_addrs: Vec<SocketAddr>,
    /// The server's address as the client dials it over this road.
    server_addr: SocketAddr,
    up: Link,
    down: Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    fn index(self) -> usize {
        match self {
            Side::Client => 0,
            Side::Server => 1,
        }
    }

    fn other(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

/// What made a side send a datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SendOrigin {
    /// A timer service (`Connection::on_timeout_if_due`) or a handshake
    /// retransmit.
    Timer,
    /// Handling a datagram from the peer (`Connection::on_datagram`).
    Received,
    /// A scripted action or a write: anything else.
    Action,
}

/// One datagram a side put on the wire, as its peer would decrypt it (empty
/// for a handshake or a datagram the peer cannot read yet).
#[derive(Clone, Debug)]
pub struct SentDatagram {
    pub at: Duration,
    pub frames: Vec<StreamFrame>,
    /// The address it was sent to, and the road that address belongs to
    /// (`None`: misaddressed).
    pub to: SocketAddr,
    pub road: Option<usize>,
    /// Its length on the wire.
    pub len: usize,
    pub origin: SendOrigin,
}

/// Datagrams one side put on the wire, by what was in them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameCounts {
    pub datagrams: u64,
    pub handshake: u64,
    /// Transport datagrams the addressee could not read (before its keys).
    pub opaque: u64,
    pub data: u64,
    /// Payload bytes carried by those DATA frames, first sends and
    /// retransmits alike.
    pub data_bytes: u64,
    pub ack: u64,
    pub ping: u64,
    pub pong: u64,
    pub close: u64,
    pub session_abort: u64,
    pub reset: u64,
    pub path_probe: u64,
    pub path_probe_ack: u64,
    /// `CREDIT` frames (spec §6).
    pub credit: u64,
    /// Datagrams that carried nothing but ACKs.
    pub ack_only: u64,
    /// Datagrams with at least one DATA frame.
    pub data_datagrams: u64,
    /// Datagrams with nothing but ACK and CREDIT frames: service frames
    /// nothing else carried (spec §4.11).
    pub service_only: u64,
    /// Datagrams with no DATA and no road check in them: what a side sends
    /// that is not data -- ACKs and CREDITs alone or riding a PONG, and its
    /// own PINGs (spec §9.2 L2, ruling R18). A change that moved ACKs into
    /// PONGs would leave `service_only` low; it cannot hide here.
    pub answers: u64,
    /// Datagrams that packed a road check or its answer with any other
    /// frame -- never, by spec §4.11.
    pub probe_mixed: u64,
}

/// What the return-address check in front of the server did (see
/// [`Sim::guard_server`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardCounts {
    /// Handshakes it let through from the client's own roads.
    pub passed_from_roads: u64,
    /// Handshakes it let through from anywhere else: the work a forged
    /// flood cost before load was seen. They go no further -- the one
    /// server connection is the client's.
    pub passed_from_elsewhere: u64,
    /// Cookie replies it sent.
    pub replies: u64,
    /// Datagrams too short for a msg1.
    pub dropped: u64,
}

struct Delivery {
    to: Side,
    src: SocketAddr,
    bytes: Vec<u8>,
    /// When it was put on the road (see [`MAX_TIMER_SERVICES_AT_ONE_INSTANT`]).
    sent_at: Duration,
}

type Action = Box<dyn FnOnce(&mut Sim)>;

/// A client and a server `Connection` joined by simulated roads.
pub struct Sim {
    base: Instant,
    now: Duration,
    rng: SplitMix64,
    /// `[client, server]`.
    conns: [Connection; 2],
    roads: Vec<Road>,
    seq: u64,
    deliveries: BinaryHeap<Reverse<(Duration, u64)>>,
    in_flight: HashMap<u64, Delivery>,
    actions: BinaryHeap<Reverse<(Duration, u64)>>,
    scripted: HashMap<u64, Action>,
    log: Vec<(Duration, Side, Event)>,
    delivered: BTreeMap<(Side, u8), Vec<u8>>,
    /// Bytes [`Sim::forget_delivered`] dropped from `delivered`, per stream.
    forgotten: BTreeMap<(Side, u8), usize>,
    frames: [FrameCounts; 2],
    tracked: Vec<(Side, u8)>,
    max_tail: BTreeMap<(Side, u8), u64>,
    misaddressed: u64,
    /// Bytes of those datagrams (see [`Sim::misaddressed_bytes`]).
    misaddressed_bytes: u64,
    /// The return-address check in front of the server, if any (see
    /// [`Sim::guard_server`]), and what it did.
    guard: Option<CookieCheck>,
    guard_counts: GuardCounts,
    /// Bytes [`Sim::inject_to_server`] put in front of the server.
    injected_bytes: u64,
    msg1: Option<Vec<u8>>,
    msg2: Option<Vec<u8>>,
    handshake_sent_at: Option<Duration>,
    /// `[client, server]`: until when a side's thread is frozen (see
    /// [`Sim::freeze`]), and what reached its socket meanwhile.
    frozen_until: [Option<Duration>; 2],
    held: [Vec<Delivery>; 2],
    /// `[client, server]`: timer services in a row that sent nothing while a
    /// deadline stayed due (see [`TIMER_SERVICES_PER_INSTANT`]).
    idle_services: [usize; 2],
    /// `[client, server]`: the virtual instant of the last timer service
    /// with nothing else to do, and how many such services that instant has
    /// had (see [`MAX_TIMER_SERVICES_AT_ONE_INSTANT`]).
    services_at: [(Duration, usize); 2],
    /// `[client, server]`: the same for the services that check exempts,
    /// and the most one instant has had (see
    /// [`Sim::peak_exempt_timer_services`]).
    exempt_services_at: [(Duration, usize); 2],
    peak_exempt_services: [usize; 2],
    /// The virtual instant of the last step and how many steps it has had
    /// (see [`MAX_STEPS_AT_ONE_INSTANT`]).
    steps_at: (Duration, usize),
    /// Every datagram each side sent, once [`Sim::record_sends`] asked.
    recorded: Option<[Vec<SentDatagram>; 2]>,
    /// What the sends being transmitted come from (see [`SendOrigin`]).
    origin: SendOrigin,
    /// `[client, server]`: plays a build from before negotiation (see
    /// [`Sim::play_legacy`]).
    legacy: [bool; 2],
    /// Consumers other than on delivery, with what each has delivered and
    /// not taken yet.
    consumers: BTreeMap<(Side, u8), (Consumer, u64)>,
    /// A `Rate` consumer's fractional byte carried from one tick to the
    /// next, in thousandths of a byte (`rate * CONSUME_TICK` truncates to
    /// whole bytes per tick otherwise, so a rate under `1000 /
    /// CONSUME_TICK.as_millis()` -- 100 B/s here -- would never consume
    /// anything).
    consume_carry: BTreeMap<(Side, u8), u64>,
    /// The most each of those ever had not taken.
    max_unconsumed: BTreeMap<(Side, u8), u64>,
    /// `[client, server]`: the most out-of-order data a side ever held.
    max_undelivered: [usize; 2],
    /// Whether a consume tick is scheduled.
    consume_tick_scheduled: bool,
}

impl Sim {
    /// A client on road 0 and an allowlisted server, not started yet.
    pub fn new(seed: u64, roads: Vec<RoadSpec>) -> Sim {
        assert!(!roads.is_empty(), "a simulation needs at least one road");
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        // The connections are stamped with the virtual start itself, so no
        // deadline derived before the handshake depends on the real clock.
        let base = Instant::now();
        let client = Connection::new_at(
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: client_kp.private,
                remote_static_pub: Some(server_kp.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            base,
        );
        let server = Connection::new_at(
            ConnectionConfig {
                required_features: crate::Features::NONE,
                features: crate::Features::SUPPORTED,
                role: Role::Server,
                local_static_priv: server_kp.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_kp.public]),
            },
            base,
        );
        let roads = roads
            .into_iter()
            .enumerate()
            .map(|(i, spec)| {
                let n = u8::try_from(i + 1).expect("at most 254 roads");
                Road {
                    client_addr: SocketAddr::from(([10, 0, 0, n], 40000)),
                    old_client_addrs: Vec::new(),
                    server_addr: SocketAddr::from(([10, 1, 0, n], 41000)),
                    up: Link::new(spec.up),
                    down: Link::new(spec.down),
                }
            })
            .collect();
        Sim {
            base,
            now: Duration::ZERO,
            rng: SplitMix64::new(seed),
            conns: [client, server],
            roads,
            seq: 0,
            deliveries: BinaryHeap::new(),
            in_flight: HashMap::new(),
            actions: BinaryHeap::new(),
            scripted: HashMap::new(),
            log: Vec::new(),
            delivered: BTreeMap::new(),
            forgotten: BTreeMap::new(),
            frames: [FrameCounts::default(); 2],
            tracked: Vec::new(),
            max_tail: BTreeMap::new(),
            misaddressed: 0,
            misaddressed_bytes: 0,
            guard: None,
            guard_counts: GuardCounts::default(),
            injected_bytes: 0,
            msg1: None,
            msg2: None,
            handshake_sent_at: None,
            frozen_until: [None, None],
            held: [Vec::new(), Vec::new()],
            idle_services: [0, 0],
            services_at: [(Duration::ZERO, 0); 2],
            exempt_services_at: [(Duration::ZERO, 0); 2],
            peak_exempt_services: [0, 0],
            steps_at: (Duration::ZERO, 0),
            recorded: None,
            origin: SendOrigin::Action,
            legacy: [false, false],
            consumers: BTreeMap::new(),
            consume_carry: BTreeMap::new(),
            max_unconsumed: BTreeMap::new(),
            max_undelivered: [0, 0],
            consume_tick_scheduled: false,
        }
    }

    /// Virtual time since the start.
    pub fn now(&self) -> Duration {
        self.now
    }

    /// Virtual time as the `Instant` the connections see.
    pub fn instant(&self) -> Instant {
        self.base + self.now
    }

    /// Record every datagram both sides send from now on (see [`Sim::sent`]).
    pub fn record_sends(&mut self) {
        self.recorded = Some([Vec::new(), Vec::new()]);
    }

    /// What `side` sent since [`Sim::record_sends`], in order.
    pub fn sent(&self, side: Side) -> &[SentDatagram] {
        self.recorded
            .as_ref()
            .map_or(&[], |r| r[side.index()].as_slice())
    }

    pub fn conn(&self, side: Side) -> &Connection {
        &self.conns[side.index()]
    }

    pub fn conn_mut(&mut self, side: Side) -> &mut Connection {
        &mut self.conns[side.index()]
    }

    /// `(client address as the server sees it, server address as the client
    /// dials it)` for road `i`.
    pub fn road(&self, i: usize) -> (SocketAddr, SocketAddr) {
        (self.roads[i].client_addr, self.roads[i].server_addr)
    }

    /// The client's NAT on road `road` maps it to `port` from now on: the
    /// server sees its datagrams from the same address with the new port.
    /// With `old_mapping_lives` the old mapping still delivers what the
    /// server sends to it (a NAT keeps an idle mapping for a while);
    /// without, those datagrams are lost ([`Sim::misaddressed`]). Datagrams
    /// already on the road arrive either way.
    pub fn rebind_client_port(&mut self, road: usize, port: u16, old_mapping_lives: bool) {
        let r = &mut self.roads[road];
        if old_mapping_lives {
            r.old_client_addrs.push(r.client_addr);
        }
        r.client_addr.set_port(port);
    }

    /// Change what road `road` does to datagrams sent by `from`, from now on.
    pub fn set_link(&mut self, road: usize, from: Side, spec: LinkSpec) {
        self.link_mut(road, from).spec = spec;
    }

    pub fn link_counters(&self, road: usize, from: Side) -> LinkCounters {
        self.link(road, from).counters
    }

    /// How long a datagram `from` would wait in road `road`'s serialization
    /// queue if it were sent now: the standing queue, in time.
    pub fn link_backlog(&self, road: usize, from: Side) -> Duration {
        self.link(road, from).busy_until.saturating_sub(self.now)
    }

    /// Every byte delivered TO `side` on `stream_id`, in order -- since the
    /// last [`Sim::forget_delivered`] of it, if any.
    pub fn delivered(&self, side: Side, stream_id: u8) -> &[u8] {
        self.delivered
            .get(&(side, stream_id))
            .map_or(&[], Vec::as_slice)
    }

    /// How many bytes were ever delivered TO `side` on `stream_id`, those
    /// forgotten included.
    pub fn delivered_len(&self, side: Side, stream_id: u8) -> usize {
        self.forgotten.get(&(side, stream_id)).copied().unwrap_or(0)
            + self.delivered(side, stream_id).len()
    }

    /// Drop the bytes delivered TO `side` on `stream_id` so far, keeping
    /// their count: a long run that only counts them need not hold them.
    pub fn forget_delivered(&mut self, side: Side, stream_id: u8) {
        if let Some(bytes) = self.delivered.get_mut(&(side, stream_id)) {
            *self.forgotten.entry((side, stream_id)).or_insert(0) += bytes.len();
            bytes.clear();
            bytes.shrink_to_fit();
        }
    }

    /// Have `side` take `stream_id`'s bytes the way `consumer` says. From
    /// `OnDelivery` to another it counts explicitly from now on; back to
    /// `OnDelivery` whatever waits is taken at once.
    pub fn set_consumer(&mut self, side: Side, stream_id: u8, consumer: Consumer) {
        let now = self.instant();
        let key = (side, stream_id);
        match consumer {
            Consumer::OnDelivery => {
                let left = self.consumers.remove(&key).map_or(0, |(_, left)| left);
                let conn = &mut self.conns[side.index()];
                let out = conn.on_consumed(now, stream_id, left as usize);
                conn.set_stream_consumption(stream_id, Consumption::OnDelivery);
                self.transmit(side, out);
            }
            Consumer::Stalled | Consumer::Rate(_) => {
                self.conns[side.index()].set_stream_consumption(stream_id, Consumption::Explicit);
                let left = self.consumers.get(&key).map_or(0, |(_, left)| *left);
                self.consumers.insert(key, (consumer, left));
                if matches!(consumer, Consumer::Rate(_)) {
                    self.schedule_consume_tick();
                }
            }
        }
    }

    /// What `side` has delivered on `stream_id` and not taken yet.
    pub fn unconsumed(&self, side: Side, stream_id: u8) -> u64 {
        self.consumers
            .get(&(side, stream_id))
            .map_or(0, |(_, left)| *left)
    }

    /// The most `side` ever had delivered on `stream_id` and not taken.
    pub fn max_unconsumed(&self, side: Side, stream_id: u8) -> u64 {
        self.max_unconsumed
            .get(&(side, stream_id))
            .copied()
            .unwrap_or(0)
    }

    /// The most out-of-order data `side` ever held, by its receivers' cost.
    pub fn max_undelivered(&self, side: Side) -> usize {
        self.max_undelivered[side.index()]
    }

    fn schedule_consume_tick(&mut self) {
        if self.consume_tick_scheduled {
            return;
        }
        self.consume_tick_scheduled = true;
        let at = self.now + CONSUME_TICK;
        self.schedule(at, |sim| {
            sim.consume_tick_scheduled = false;
            sim.consume_tick();
        });
    }

    /// Every consumer at a rate takes its share of a tick; a frozen side
    /// takes nothing (its thread does not run).
    fn consume_tick(&mut self) {
        let now = self.instant();
        let keys: Vec<(Side, u8)> = self.consumers.keys().copied().collect();
        let mut any = false;
        for (side, stream_id) in keys {
            let (consumer, left) = self.consumers[&(side, stream_id)];
            let Consumer::Rate(rate) = consumer else {
                continue;
            };
            any = true;
            if self.is_frozen(side) {
                continue;
            }
            // The exact rate, over enough ticks, however small: what a whole
            // tick's share truncates away carries to the next one (Minor 6
            // of the Task 5 review) rather than being lost, so even a rate
            // under 100 B/s (`1000 / CONSUME_TICK.as_millis()`, below which
            // a tick's share truncates to zero on its own) still consumes,
            // one byte every few ticks instead of never.
            let carry = self
                .consume_carry
                .get(&(side, stream_id))
                .copied()
                .unwrap_or(0);
            let numerator = carry + rate * CONSUME_TICK.as_millis() as u64;
            let share = numerator / 1000;
            self.consume_carry
                .insert((side, stream_id), numerator % 1000);
            let n = left.min(share);
            if n == 0 {
                continue;
            }
            if let Some(entry) = self.consumers.get_mut(&(side, stream_id)) {
                entry.1 -= n;
            }
            let out = self.conns[side.index()].on_consumed(now, stream_id, n as usize);
            self.transmit(side, out);
        }
        if any {
            self.schedule_consume_tick();
        }
    }

    /// Every event other than `StreamData`, with when and where it happened.
    pub fn log(&self) -> &[(Duration, Side, Event)] {
        &self.log
    }

    pub fn frames_sent(&self, side: Side) -> FrameCounts {
        self.frames[side.index()]
    }

    /// The largest `stream_progress(stream_id).unacked` seen on `side` for a
    /// stream written through [`Sim::send`].
    pub fn max_tail(&self, side: Side, stream_id: u8) -> u64 {
        self.max_tail.get(&(side, stream_id)).copied().unwrap_or(0)
    }

    /// Datagrams addressed to no road.
    pub fn misaddressed(&self) -> u64 {
        self.misaddressed
    }

    /// Bytes of the datagrams addressed to no road -- among them every
    /// answer to [`Sim::inject_to_server`].
    pub fn misaddressed_bytes(&self) -> u64 {
        self.misaddressed_bytes
    }

    /// Put the session manager's return-address check (spec §4.16) in
    /// front of the server: every handshake datagram passes it first.
    pub fn guard_server(&mut self, check: CookieCheck) {
        self.guard = Some(check);
    }

    /// What the check in front of the server did so far.
    pub fn guard_counts(&self) -> GuardCounts {
        self.guard_counts
    }

    /// A datagram from `src` -- an address no road has, as a forged
    /// flood's -- reaches the server now. Whatever it draws goes nowhere
    /// (and counts in [`Sim::misaddressed_bytes`]). It lands at this very
    /// instant, so the timer services after it count towards
    /// [`MAX_TIMER_SERVICES_AT_ONE_INSTANT`] as any datagram sent now does.
    pub fn inject_to_server(&mut self, src: SocketAddr, bytes: Vec<u8>) {
        self.injected_bytes += bytes.len() as u64;
        self.inject(Side::Server, src, bytes);
    }

    /// A datagram from `src` reaches the client now, off every road: what a
    /// party on the path that can inject sends in the server's name (with
    /// `src` the server's address). Not counted in
    /// [`Sim::injected_bytes`], which is about the server.
    pub fn inject_to_client(&mut self, src: SocketAddr, bytes: Vec<u8>) {
        self.inject(Side::Client, src, bytes);
    }

    fn inject(&mut self, to: Side, src: SocketAddr, bytes: Vec<u8>) {
        let id = self.next_seq();
        self.deliveries.push(Reverse((self.now, id)));
        self.in_flight.insert(
            id,
            Delivery {
                to,
                src,
                bytes,
                sent_at: self.now,
            },
        );
    }

    /// Bytes injected in front of the server so far.
    pub fn injected_bytes(&self) -> u64 {
        self.injected_bytes
    }

    /// The client's msg1 as it went on the wire, once [`Sim::start`] ran.
    pub fn msg1(&self) -> Option<&[u8]> {
        self.msg1.as_deref()
    }

    /// The most timer services `side` had at one virtual instant that the
    /// check of [`MAX_TIMER_SERVICES_AT_ONE_INSTANT`] did not count -- those
    /// that followed an action, a wake-up or the delivery of an earlier
    /// datagram in the same step.
    pub fn peak_exempt_timer_services(&self, side: Side) -> usize {
        self.peak_exempt_services[side.index()]
    }

    /// Send the client's msg1 down road 0.
    pub fn start(&mut self) {
        let now = self.instant();
        let server_addr = self.roads[0].server_addr;
        let out = if self.legacy[Side::Client.index()] {
            let payload = encode_msg1_without_tail(&Msg1Payload {
                start_kind: StartKind::Cold,
                token: [0; 16],
                method: AuthMethod::Allowlist,
                offered: Features::NONE,
            });
            self.conns[0].start_with_payload(now, server_addr, &payload)
        } else {
            self.conns[0].start_session(now, server_addr, StartKind::Cold, [0; 16])
        };
        self.msg1 = out.first().map(|d| d.bytes.clone());
        self.handshake_sent_at = Some(self.now);
        self.transmit(Side::Client, out);
    }

    /// Make `side` play a build from before negotiation (spec §9.3), before
    /// [`Sim::start`]: a client sends the 19-byte msg1 of those builds, a
    /// server writes their 26-byte msg2 and enables nothing.
    pub fn play_legacy(&mut self, side: Side) {
        assert!(
            self.handshake_sent_at.is_none(),
            "play_legacy goes before start: the handshake has begun"
        );
        self.legacy[side.index()] = true;
        self.conns[side.index()].act_as_legacy_peer_for_test();
    }

    /// Queue `data` on `side`'s `stream_id` now.
    pub fn send(&mut self, side: Side, stream_id: u8, data: &[u8]) {
        if !self.tracked.contains(&(side, stream_id)) {
            self.tracked.push((side, stream_id));
        }
        let now = self.instant();
        let out = self.conns[side.index()].send(now, stream_id, data);
        self.transmit(side, out);
        self.collect_events();
    }

    /// Freeze `side`'s thread for `d` from now, as Doze does to the app: its
    /// timers do not run and what arrives waits in its socket. On waking it
    /// does what `driver_std` does after a receive that spanned a freeze:
    /// `request_ping`, then the datagrams that waited, oldest first, then its
    /// timers.
    pub fn freeze(&mut self, side: Side, d: Duration) {
        self.frozen_until[side.index()] = Some(self.now + d);
    }

    fn is_frozen(&self, side: Side) -> bool {
        self.frozen_until[side.index()].is_some()
    }

    /// Wake a side whose freeze has run out, if any.
    fn wake_if_due(&mut self) -> bool {
        for side in [Side::Client, Side::Server] {
            let i = side.index();
            if self.frozen_until[i].is_some_and(|t| t <= self.now) {
                self.frozen_until[i] = None;
                let now = self.instant();
                self.conns[i].request_ping(now);
                for d in std::mem::take(&mut self.held[i]) {
                    self.deliver(d);
                }
                return true;
            }
        }
        false
    }

    /// Run `action` at virtual time `at`.
    pub fn schedule(&mut self, at: Duration, action: impl FnOnce(&mut Sim) + 'static) {
        let id = self.next_seq();
        self.actions.push(Reverse((at, id)));
        self.scripted.insert(id, Box::new(action));
    }

    pub fn run_for(&mut self, d: Duration) {
        self.run_until(self.now + d);
    }

    /// Process every event up to and including `end`, then set the clock to `end`.
    pub fn run_until(&mut self, end: Duration) {
        while let Some(next) = self.next_event_time() {
            if next > end {
                break;
            }
            if next > self.now {
                self.now = next;
            }
            self.step();
        }
        if end > self.now {
            self.now = end;
        }
    }

    /// Run until both sides are `Live` or `deadline` passes; say which.
    pub fn run_until_live(&mut self, deadline: Duration) -> bool {
        let live = |s: &Sim| {
            s.conns[0].state() == LinkState::Live && s.conns[1].state() == LinkState::Live
        };
        while self.now < deadline && !live(self) {
            let step = (self.now + Duration::from_millis(1)).min(deadline);
            self.run_until(step);
        }
        live(self)
    }

    /// Put `dgrams` from `from` on the roads they are addressed to.
    pub fn transmit(&mut self, from: Side, dgrams: Vec<Datagram>) {
        for dg in dgrams {
            let road = match from {
                Side::Client => self.roads.iter().position(|r| r.server_addr == dg.to),
                Side::Server => self
                    .roads
                    .iter()
                    .position(|r| r.client_addr == dg.to || r.old_client_addrs.contains(&dg.to)),
            };
            self.count_frames(from, &dg, road);
            let Some(i) = road else {
                self.misaddressed += 1;
                self.misaddressed_bytes += dg.bytes.len() as u64;
                continue;
            };
            let now = self.now;
            let r = &mut self.roads[i];
            let (link, src) = match from {
                Side::Client => (&mut r.up, r.client_addr),
                Side::Server => (&mut r.down, r.server_addr),
            };
            if let Some(at) = link.admit(now, dg.bytes.len(), &mut self.rng) {
                let id = self.next_seq();
                self.deliveries.push(Reverse((at, id)));
                self.in_flight.insert(
                    id,
                    Delivery {
                        to: from.other(),
                        src,
                        bytes: dg.bytes,
                        sent_at: now,
                    },
                );
            }
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn link(&self, road: usize, from: Side) -> &Link {
        let r = &self.roads[road];
        match from {
            Side::Client => &r.up,
            Side::Server => &r.down,
        }
    }

    fn link_mut(&mut self, road: usize, from: Side) -> &mut Link {
        let r = &mut self.roads[road];
        match from {
            Side::Client => &mut r.up,
            Side::Server => &mut r.down,
        }
    }

    fn since_base(&self, t: Instant) -> Duration {
        t.saturating_duration_since(self.base)
    }

    fn next_event_time(&self) -> Option<Duration> {
        let mut next: Option<Duration> = None;
        let mut consider = |t: Duration| next = Some(next.map_or(t, |n| n.min(t)));
        if let Some(Reverse((at, _))) = self.actions.peek() {
            consider(*at);
        }
        if let Some(Reverse((at, _))) = self.deliveries.peek() {
            consider(*at);
        }
        for side in [Side::Client, Side::Server] {
            if let Some(until) = self.frozen_until[side.index()] {
                consider(until.max(self.now));
                continue;
            }
            if let Some(deadline) = self.conns[side.index()].next_timeout() {
                consider(self.since_base(deadline).max(self.now));
            }
        }
        if self.conns[0].state() == LinkState::Connecting {
            if let Some(sent) = self.handshake_sent_at {
                consider((sent + HANDSHAKE_RETRANSMIT).max(self.now));
            }
        }
        next
    }

    /// One thing due at `now` -- a scripted action first, then a delivery,
    /// then a handshake retransmit -- followed by both sides' timers.
    fn step(&mut self) {
        let (at, steps) = &mut self.steps_at;
        if *at == self.now {
            *steps += 1;
        } else {
            (*at, *steps) = (self.now, 1);
        }
        assert!(
            *steps <= MAX_STEPS_AT_ONE_INSTANT,
            "{MAX_STEPS_AT_ONE_INSTANT} steps at {:?} and virtual time does not advance -- \
             something keeps itself due at one instant",
            self.now
        );
        let woken = if let Some(id) = pop_due(&mut self.actions, self.now) {
            let action = self.scripted.remove(&id).expect("a scheduled action");
            action(self);
            true
        } else if self.wake_if_due() {
            true
        } else if let Some(id) = pop_due(&mut self.deliveries, self.now) {
            let delivery = self.in_flight.remove(&id).expect("a scheduled delivery");
            let sent_earlier = delivery.sent_at < self.now;
            if self.is_frozen(delivery.to) {
                self.held[delivery.to.index()].push(delivery);
            } else {
                self.deliver(delivery);
            }
            sent_earlier
        } else {
            self.retransmit_handshake_if_due();
            false
        };
        self.run_timers(woken);
        self.collect_events();
    }

    fn deliver(&mut self, d: Delivery) {
        let origin = std::mem::replace(&mut self.origin, SendOrigin::Received);
        self.deliver_received(d);
        self.origin = origin;
    }

    fn deliver_received(&mut self, d: Delivery) {
        let Delivery { to, src, bytes, .. } = d;
        let Some(bytes) = self.through_guard(to, src, bytes) else {
            return;
        };
        // The session manager's `ResendMsg2`: a byte-identical msg1 retransmit
        // to a server that already answered draws the same msg2 again.
        if to == Side::Server && self.msg2.is_some() && self.msg1.as_deref() == Some(&bytes[..]) {
            let bytes = self.msg2.clone().expect("checked above");
            self.transmit(Side::Server, vec![Datagram { to: src, bytes }]);
            return;
        }
        let now = self.instant();
        let out = self.conns[to.index()].on_datagram(now, src, &bytes);
        // Taken right here, not only once per step in `collect_events`: a
        // wake-up delivers every datagram `held` during a freeze in one
        // step (`wake_if_due`, several calls to `deliver` in a row), and a
        // peak reached partway through that burst would otherwise be missed
        // (Minor 5 of the Task 5 review).
        let held_now = self.conns[to.index()].undelivered_cost_for_test();
        let peak = &mut self.max_undelivered[to.index()];
        *peak = (*peak).max(held_now);
        if to == Side::Server && self.msg2.is_none() {
            self.msg2 = out
                .iter()
                .find(|dg| {
                    matches!(
                        parse(&dg.bytes),
                        Ok(Frame::Handshake {
                            kind: Kind::HandshakeResp,
                            ..
                        })
                    )
                })
                .map(|dg| dg.bytes.clone());
        }
        self.transmit(to, out);
    }

    /// The datagram as the server's connection sees it once the guard (if
    /// any) had its say: a handshake it let through, as a plain msg1; `None`
    /// when it answered or dropped the datagram instead. Everything the
    /// guard does not look at -- every datagram of an unguarded run -- goes
    /// through as it came, uncopied.
    fn through_guard(&mut self, to: Side, src: SocketAddr, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if to != Side::Server || self.guard.is_none() {
            return Some(bytes);
        }
        let (kind, body) = match parse(&bytes) {
            Ok(Frame::Handshake {
                kind: kind @ (Kind::HandshakeInit | Kind::HandshakeInitCookie),
                body,
            }) => (kind, body),
            _ => return Some(bytes),
        };
        let now = self.instant();
        let verdict = self
            .guard
            .as_mut()
            .expect("checked above")
            .check(now, src, kind, body, 0);
        match verdict {
            Verdict::Handshake { msg1, .. } => {
                let from_a_road = self
                    .roads
                    .iter()
                    .any(|r| r.client_addr == src || r.old_client_addrs.contains(&src));
                if from_a_road {
                    self.guard_counts.passed_from_roads += 1;
                    Some(encode_handshake(Kind::HandshakeInit, msg1))
                } else {
                    self.guard_counts.passed_from_elsewhere += 1;
                    None
                }
            }
            Verdict::Reply(reply) => {
                self.guard_counts.replies += 1;
                self.transmit(
                    Side::Server,
                    vec![Datagram {
                        to: src,
                        bytes: reply,
                    }],
                );
                None
            }
            Verdict::Drop => {
                self.guard_counts.dropped += 1;
                None
            }
        }
    }

    /// `driver_std`'s rule: while the client is `Connecting`, re-send its
    /// msg1 every `HANDSHAKE_RETRANSMIT` -- once a cookie arrived, behind it
    /// and plain in turn (`Connection::retransmit_handshake`).
    fn retransmit_handshake_if_due(&mut self) {
        if self.conns[0].state() != LinkState::Connecting {
            return;
        }
        let Some(sent) = self.handshake_sent_at else {
            return;
        };
        if self.now < sent + HANDSHAKE_RETRANSMIT {
            return;
        }
        self.handshake_sent_at = Some(self.now);
        let out = self.conns[0].retransmit_handshake();
        let origin = std::mem::replace(&mut self.origin, SendOrigin::Timer);
        self.transmit(Side::Client, out);
        self.origin = origin;
    }

    /// The timer rule of every driver (spec §4.1), one service per side per
    /// step, with the livelock checks described at
    /// [`TIMER_SERVICES_PER_INSTANT`] and
    /// [`MAX_TIMER_SERVICES_AT_ONE_INSTANT`]. `woken`: the step had an
    /// action, a wake-up or the delivery of a datagram sent before this
    /// instant, so its services do not count towards the second check.
    fn run_timers(&mut self, woken: bool) {
        let now = self.instant();
        for side in [Side::Client, Side::Server] {
            let i = side.index();
            if self.is_frozen(side) || !self.conns[i].next_timeout().is_some_and(|d| d <= now) {
                self.idle_services[i] = 0;
                continue;
            }
            if woken {
                let (at, count) = &mut self.exempt_services_at[i];
                if *at == self.now {
                    *count += 1;
                } else {
                    (*at, *count) = (self.now, 1);
                }
                self.peak_exempt_services[i] = self.peak_exempt_services[i].max(*count);
            } else {
                let (at, count) = &mut self.services_at[i];
                if *at == self.now {
                    *count += 1;
                } else {
                    (*at, *count) = (self.now, 1);
                }
                assert!(
                    *count <= MAX_TIMER_SERVICES_AT_ONE_INSTANT,
                    "{side:?}: {MAX_TIMER_SERVICES_AT_ONE_INSTANT} timer services at {:?} with \
                     nothing else to do and a deadline is still due -- one that never clears \
                     keeps virtual time from advancing (and a real driver loop spinning)",
                    self.now
                );
            }
            let out = self.conns[i].on_timeout_if_due(now);
            if out.is_empty() {
                self.idle_services[i] += 1;
            } else {
                self.idle_services[i] = 0;
            }
            let origin = std::mem::replace(&mut self.origin, SendOrigin::Timer);
            self.transmit(side, out);
            self.origin = origin;
            assert!(
                self.idle_services[i] < TIMER_SERVICES_PER_INSTANT
                    || !self.conns[i].next_timeout().is_some_and(|d| d <= now),
                "{side:?}: a timer is still due after {TIMER_SERVICES_PER_INSTANT} services that \
                 sent nothing, at {:?} -- a deadline `on_timeout` never consumes would wake every \
                 driver loop every millisecond",
                self.now
            );
        }
    }

    fn collect_events(&mut self) {
        for side in [Side::Client, Side::Server] {
            for ev in self.conns[side.index()].poll_events() {
                match ev {
                    Event::StreamData { stream_id, data } => {
                        if let Some((_, left)) = self.consumers.get_mut(&(side, stream_id)) {
                            *left += data.len() as u64;
                            let peak = self.max_unconsumed.entry((side, stream_id)).or_insert(0);
                            *peak = (*peak).max(*left);
                        }
                        self.delivered
                            .entry((side, stream_id))
                            .or_default()
                            .extend_from_slice(&data)
                    }
                    other => self.log.push((self.now, side, other)),
                }
            }
        }
        for &(side, stream_id) in &self.tracked {
            let tail = self.conns[side.index()].stream_progress(stream_id).unacked;
            let max = self.max_tail.entry((side, stream_id)).or_insert(0);
            *max = (*max).max(tail);
        }
        for side in [Side::Client, Side::Server] {
            let held = self.conns[side.index()].undelivered_cost_for_test();
            let peak = &mut self.max_undelivered[side.index()];
            *peak = (*peak).max(held);
        }
    }

    fn count_frames(&mut self, from: Side, dg: &Datagram, road: Option<usize>) {
        let bytes = &dg.bytes[..];
        let i = from.index();
        self.frames[i].datagrams += 1;
        let frames = if let Ok(Frame::Handshake { .. }) = parse(bytes) {
            self.frames[i].handshake += 1;
            Vec::new()
        } else {
            match self.conns[from.other().index()].peek_frames(bytes) {
                None => {
                    self.frames[i].opaque += 1;
                    Vec::new()
                }
                Some(frames) => {
                    let counts = &mut self.frames[i];
                    if !frames.is_empty()
                        && frames.iter().all(|f| matches!(f, StreamFrame::Ack { .. }))
                    {
                        counts.ack_only += 1;
                    }
                    if frames.iter().any(|f| matches!(f, StreamFrame::Data { .. })) {
                        counts.data_datagrams += 1;
                    }
                    if !frames.is_empty()
                        && frames.iter().all(|f| {
                            matches!(f, StreamFrame::Ack { .. } | StreamFrame::Credit { .. })
                        })
                    {
                        counts.service_only += 1;
                    }
                    if !frames.is_empty()
                        && !frames
                            .iter()
                            .any(|f| matches!(f, StreamFrame::Data { .. }) || f.is_probe())
                    {
                        counts.answers += 1;
                    }
                    if frames.len() > 1 && frames.iter().any(StreamFrame::is_probe) {
                        counts.probe_mixed += 1;
                    }
                    for f in &frames {
                        match f {
                            StreamFrame::Data { data, .. } => {
                                counts.data += 1;
                                counts.data_bytes += data.len() as u64;
                            }
                            StreamFrame::Ack { .. } => counts.ack += 1,
                            StreamFrame::Ping { .. } => counts.ping += 1,
                            StreamFrame::Pong { .. } => counts.pong += 1,
                            StreamFrame::Close { .. } => counts.close += 1,
                            StreamFrame::SessionAbort { .. } => counts.session_abort += 1,
                            StreamFrame::Reset { .. } => counts.reset += 1,
                            StreamFrame::PathProbe { .. } => counts.path_probe += 1,
                            StreamFrame::PathProbeAck { .. } => counts.path_probe_ack += 1,
                            StreamFrame::Credit { .. } => counts.credit += 1,
                        }
                    }
                    frames
                }
            }
        };
        let at = self.now;
        if let Some(recorded) = self.recorded.as_mut() {
            recorded[i].push(SentDatagram {
                at,
                frames,
                to: dg.to,
                road,
                len: bytes.len(),
                origin: self.origin,
            });
        }
    }
}

fn pop_due(heap: &mut BinaryHeap<Reverse<(Duration, u64)>>, now: Duration) -> Option<u64> {
    match heap.peek() {
        Some(Reverse((at, _))) if *at <= now => heap.pop().map(|Reverse((_, id))| id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::PathState;

    const ROAD: Duration = Duration::from_millis(10);

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    /// If this fails, compare the implementation with Vigna's reference
    /// `splitmix64.c` (https://prng.di.unimi.it/splitmix64.c) before
    /// touching the constants.
    #[test]
    fn splitmix64_matches_the_reference_sequence() {
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn a_link_serializes_at_its_bandwidth_and_drops_past_its_queue_limit() {
        let mut rng = SplitMix64::new(1);
        let mut link = Link::new(LinkSpec::new(Duration::ZERO).with_bandwidth(1_000, Some(250)));
        assert_eq!(
            link.admit(Duration::ZERO, 100, &mut rng),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            link.admit(Duration::ZERO, 100, &mut rng),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            link.admit(Duration::ZERO, 100, &mut rng),
            None,
            "200 bytes waiting plus 100 more is past the 250-byte queue"
        );
        assert_eq!(
            link.counters,
            LinkCounters {
                sent: 3,
                lost: 0,
                queue_dropped: 1,
                delivered: 2
            }
        );
        assert_eq!(
            link.admit(Duration::from_secs(1), 100, &mut rng),
            Some(Duration::from_millis(1_100)),
            "an idle link starts serializing at once"
        );
    }

    /// Jitter varies each datagram's delay but a link stays FIFO: a burst
    /// that leaves at one instant arrives in the order it left, every
    /// arrival within `delay ± jitter` of its departure.
    #[test]
    fn jitter_varies_the_delay_but_never_reorders() {
        let mut rng = SplitMix64::new(7);
        let mut link = Link::new(LinkSpec::new(ROAD).with_jitter(Duration::from_millis(3)));
        let low = Duration::from_millis(7);
        let high = Duration::from_millis(13);
        let burst: Vec<Duration> = (0..256)
            .map(|_| {
                link.admit(Duration::ZERO, 1_000, &mut rng)
                    .expect("no loss")
            })
            .collect();
        assert!(
            burst.windows(2).all(|w| w[0] <= w[1]),
            "a burst arrives in the order it left"
        );
        assert!(burst.iter().all(|&a| low <= a && a <= high), "{burst:?}");
        // Spaced departures: nothing to push back, so the delay itself shows.
        let delays: Vec<Duration> = (1..=256u64)
            .map(|i| {
                let departs = Duration::from_millis(100 * i);
                link.admit(departs, 1_000, &mut rng).expect("no loss") - departs
            })
            .collect();
        assert!(delays.iter().all(|&d| low <= d && d <= high), "{delays:?}");
        assert!(
            delays.iter().min().unwrap() < &Duration::from_millis(8)
                && delays.iter().max().unwrap() > &Duration::from_millis(12),
            "the delay does vary across the whole range: {delays:?}"
        );
    }

    /// Jitter larger than the delay cannot make a datagram arrive before it
    /// left: the delay floors at zero.
    #[test]
    fn jitter_larger_than_the_delay_floors_at_zero() {
        let mut rng = SplitMix64::new(8);
        let mut link = Link::new(
            LinkSpec::new(Duration::from_millis(1)).with_jitter(Duration::from_millis(5)),
        );
        let delays: Vec<Duration> = (1..=256u64)
            .map(|i| {
                let departs = Duration::from_millis(100 * i);
                link.admit(departs, 1_000, &mut rng).expect("no loss") - departs
            })
            .collect();
        assert!(delays.iter().all(|&d| d <= Duration::from_millis(6)));
        assert!(
            delays.contains(&Duration::ZERO),
            "some shifts go below zero and are floored: {delays:?}"
        );
    }

    /// `with_reorder` is the one source of reordering: a held-back datagram
    /// is overtaken by the ones that follow it.
    #[test]
    fn with_reorder_holds_some_datagrams_back_past_later_ones() {
        let mut rng = SplitMix64::new(9);
        let mut link = Link::new(LinkSpec::new(ROAD).with_reorder(0.2, Duration::from_millis(30)));
        let arrivals: Vec<Duration> = (0..256u64)
            .map(|i| {
                link.admit(Duration::from_millis(i), 1_000, &mut rng)
                    .expect("no loss")
            })
            .collect();
        assert!(
            arrivals.windows(2).any(|w| w[0] > w[1]),
            "some datagram is overtaken"
        );
        let held = arrivals
            .iter()
            .enumerate()
            .filter(|&(i, &a)| {
                a == Duration::from_millis(i as u64) + ROAD + Duration::from_millis(30)
            })
            .count();
        assert!(held > 0 && held < 256, "held back: {held}");
    }

    fn transfer(seed: u64, road: RoadSpec, bytes: usize) -> Sim {
        let mut sim = Sim::new(seed, vec![road]);
        sim.start();
        assert!(
            sim.run_until_live(Duration::from_secs(10)),
            "the handshake completes"
        );
        for chunk in pattern(bytes).chunks(8 * 1024) {
            sim.send(Side::Server, 20, chunk);
            sim.run_for(Duration::from_millis(2));
        }
        sim.run_for(Duration::from_secs(60));
        sim
    }

    #[test]
    fn a_lossy_reordering_road_still_delivers_every_byte_in_order() {
        let road = RoadSpec::symmetric(
            LinkSpec::new(ROAD)
                .with_jitter(Duration::from_millis(3))
                .with_loss(0.1)
                .with_reorder(0.1, Duration::from_millis(30)),
        );
        let sim = transfer(11, road, 1024 * 1024);
        assert_eq!(sim.delivered(Side::Client, 20), &pattern(1024 * 1024)[..]);
        assert!(
            sim.link_counters(0, Side::Server).lost > 0,
            "the road did lose datagrams -- or the test proves nothing"
        );
        assert_eq!(sim.misaddressed(), 0);
    }

    #[test]
    fn the_same_seed_replays_the_same_run() {
        let road = RoadSpec::symmetric(
            LinkSpec::new(ROAD)
                .with_jitter(Duration::from_millis(3))
                .with_loss(0.05)
                .with_reorder(0.05, Duration::from_millis(20)),
        );
        let a = transfer(42, road, 256 * 1024);
        let b = transfer(42, road, 256 * 1024);
        for side in [Side::Client, Side::Server] {
            assert_eq!(a.link_counters(0, side), b.link_counters(0, side));
            assert_eq!(a.frames_sent(side), b.frames_sent(side));
        }
        let c = transfer(43, road, 256 * 1024);
        assert_ne!(
            a.link_counters(0, Side::Server),
            c.link_counters(0, Side::Server),
            "a different seed is a different run"
        );
    }

    /// A road with no bandwidth limit and no jitter lands a whole flight at
    /// one virtual instant. With bulk both ways, a datagram of such a burst
    /// acknowledges some of the receiver's own data and wakes it to send one
    /// more -- the driver's rule after every wake-up (spec §4.1). With a
    /// little loss this road takes a side past
    /// `MAX_TIMER_SERVICES_AT_ONE_INSTANT` such services at one instant, each
    /// for a datagram of its own. That is progress, not a deadline that never
    /// clears. The test checks that the burst did form: should the transport
    /// stop producing it on this road, the test fails instead of passing
    /// without its case.
    #[test]
    fn a_burst_landing_at_one_instant_wakes_a_side_once_per_datagram() {
        const SIZE: usize = 2 << 20;
        let road = LinkSpec::new(Duration::from_millis(20)).with_loss(0.005);
        let mut sim = Sim::new(3, vec![RoadSpec::symmetric(road)]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        sim.send(Side::Client, 20, &pattern(SIZE));
        sim.send(Side::Server, 20, &pattern(SIZE));
        sim.run_for(Duration::from_secs(30));
        assert_eq!(sim.delivered(Side::Server, 20), &pattern(SIZE)[..]);
        assert_eq!(sim.delivered(Side::Client, 20), &pattern(SIZE)[..]);
        let peak = [Side::Client, Side::Server].map(|side| sim.peak_exempt_timer_services(side));
        assert!(
            peak.iter().any(|&p| p > MAX_TIMER_SERVICES_AT_ONE_INSTANT),
            "a burst took a side past {MAX_TIMER_SERVICES_AT_ONE_INSTANT} services at one \
             instant, or this test proves nothing: {peak:?}"
        );
    }

    /// The message of the panic `f` ends in; fails if it returns.
    fn panic_message(f: impl FnOnce()) -> String {
        let payload =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).expect_err("the run fails");
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// What `MAX_TIMER_SERVICES_AT_ONE_INSTANT` is for: a deadline that stays
    /// due while every service sends something -- a forced PING that is never
    /// cleared -- keeps virtual time from advancing, and the run must fail
    /// rather than hang. Returns the failure.
    fn a_deadline_that_never_clears_on(delay: Duration) -> String {
        let mut sim = Sim::new(13, vec![RoadSpec::symmetric(LinkSpec::new(delay))]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        sim.send(Side::Client, 20, b"k");
        sim.run_for(Duration::from_secs(1));
        assert_eq!(sim.delivered(Side::Server, 20), b"k", "the road works");
        sim.conn_mut(Side::Client).stick_forced_ping_for_test();
        panic_message(move || sim.run_for(Duration::from_secs(1)))
    }

    #[test]
    fn a_deadline_that_never_clears_fails_the_run_while_every_service_sends() {
        let failure = a_deadline_that_never_clears_on(ROAD);
        assert!(
            failure.contains("Client: 64 timer services at") && failure.contains("still due"),
            "{failure}"
        );
    }

    /// The same over a road with no delay: the PINGs of the stuck side land
    /// at the very instant it is stuck at, and must not exempt it.
    #[test]
    fn a_deadline_that_never_clears_fails_the_run_on_a_road_with_no_delay() {
        let failure = a_deadline_that_never_clears_on(Duration::ZERO);
        assert!(
            failure.contains("Client: 64 timer services at") && failure.contains("still due"),
            "{failure}"
        );
    }

    /// The backstop: an action that reschedules itself at the same instant
    /// forever is not a timer service, yet the run fails rather than hangs.
    #[test]
    fn a_loop_that_keeps_itself_due_at_one_instant_fails_the_run() {
        fn again(sim: &mut Sim) {
            let now = sim.now();
            sim.schedule(now, again);
        }
        let mut sim = Sim::new(14, vec![RoadSpec::symmetric(LinkSpec::new(ROAD))]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        let now = sim.now();
        sim.schedule(now, again);
        let failure = panic_message(move || sim.run_for(Duration::from_secs(1)));
        assert!(
            failure.contains("65536 steps at") && failure.contains("does not advance"),
            "{failure}"
        );
    }

    #[test]
    fn a_lost_msg2_is_recovered_by_the_retransmitted_msg1() {
        let mut sim = Sim::new(
            5,
            vec![RoadSpec {
                up: LinkSpec::new(ROAD),
                down: LinkSpec::new(ROAD).with_loss(1.0),
            }],
        );
        sim.schedule(Duration::from_millis(400), |s| {
            s.set_link(0, Side::Server, LinkSpec::new(ROAD))
        });
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        assert!(
            sim.frames_sent(Side::Client).handshake >= 2,
            "msg1 went out again"
        );
        assert!(
            sim.frames_sent(Side::Server).handshake >= 2,
            "and the server answered it with its msg2 again"
        );
    }

    #[test]
    fn a_second_road_is_checked_and_answered_over_itself() {
        let mut sim = Sim::new(
            9,
            vec![
                RoadSpec::symmetric(LinkSpec::new(ROAD)),
                RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(40))),
            ],
        );
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        let (_, first) = sim.road(0);
        let (_, second) = sim.road(1);
        sim.conn_mut(Side::Client).set_paths(vec![first, second]);
        sim.run_for(Duration::from_secs(2));
        let view = sim.conn(Side::Client).roads(sim.instant());
        for addr in [first, second] {
            assert!(
                view.iter()
                    .any(|r| r.addr == addr && r.state == PathState::Verified),
                "{addr} verified: {view:?}"
            );
        }
        assert!(
            sim.link_counters(1, Side::Client).sent > 0
                && sim.link_counters(1, Side::Server).sent > 0,
            "the check and its answer both took the second road"
        );
        assert_eq!(
            sim.conn(Side::Client).active_path(),
            Some(first),
            "checking a road does not move the session"
        );
    }

    /// Bytes written while the road is down (`Connection::send` does not
    /// flush outside `Live`) wait for nothing once it comes back: the packet
    /// that turns the writer `Live` again sends them in the same breath. The
    /// driver loops no longer run `on_timeout` every 50 ms (spec §4.1), so
    /// without that they would sit until the writer's next PING. Returns how
    /// long after the road came back the other side had them.
    fn written_during_path_down_arrives_after(writer: Side) -> Duration {
        let mut sim = Sim::new(9, vec![RoadSpec::symmetric(LinkSpec::new(ROAD))]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        sim.run_for(Duration::from_secs(1));
        for from in [Side::Client, Side::Server] {
            sim.set_link(0, from, LinkSpec::new(ROAD).with_loss(1.0));
        }
        sim.run_for(crate::conn::PATH_DOWN_AFTER + Duration::from_secs(1));
        for side in [Side::Client, Side::Server] {
            assert_eq!(sim.conn(side).state(), LinkState::PathDown);
        }
        // Come back just after the writer's own timers ran, so that nothing
        // of its own is due for a second: its PING went out a moment ago.
        let mut waited = Duration::ZERO;
        while sim
            .conn(writer)
            .next_timeout()
            .is_some_and(|d| d < sim.instant() + Duration::from_secs(1))
        {
            assert!(
                waited < Duration::from_secs(3),
                "the writer's timers never slow down"
            );
            sim.run_for(Duration::from_millis(1));
            waited += Duration::from_millis(1);
        }
        for from in [Side::Client, Side::Server] {
            sim.set_link(0, from, LinkSpec::new(ROAD));
        }
        let back_at = sim.now();
        sim.send(writer, 20, b"k");
        // The other side speaks first: its PING turns the writer `Live`.
        let now = sim.instant();
        sim.conn_mut(writer.other()).request_ping(now);
        while sim.delivered(writer.other(), 20).is_empty() {
            assert!(
                sim.now() < back_at + Duration::from_secs(3),
                "the bytes never arrived"
            );
            sim.run_for(Duration::from_millis(1));
        }
        assert_eq!(sim.delivered(writer.other(), 20), b"k");
        sim.now() - back_at
    }

    #[test]
    fn a_keystroke_typed_during_path_down_goes_out_as_soon_as_the_road_is_back() {
        let took = written_during_path_down_arrives_after(Side::Client);
        assert!(
            took <= 2 * ROAD + Duration::from_millis(2),
            "the keystroke took {took:?}: one PING in, the keystroke out"
        );
    }

    #[test]
    fn output_written_during_path_down_goes_out_as_soon_as_the_client_is_back() {
        let took = written_during_path_down_arrives_after(Side::Server);
        assert!(
            took <= 2 * ROAD + Duration::from_millis(2),
            "the output took {took:?}: one PING in, the output out"
        );
    }
}
