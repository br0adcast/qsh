//! The probation stage: what a connection may do before its peer has proved
//! who it is.
//!
//! Both authentication policies enter probation after the Noise handshake.
//! Allowlist membership authorizes a static key, but a captured msg1 cannot
//! prove fresh possession of the responder's keys. That policy waits for
//! `PeerKeyConfirmed`; the signature policy also requires an SSH proof on
//! [`AUTH_STREAM`]. Only the datagram route exists while the proof is pending.
//!
//! A successful proof hands the connection and bounded early data to the
//! manager. The manager checks the captured binding revision and resolves the
//! current session decision before any create, attach, replacement or eviction.
//! A failed/expired/closed candidate drops its route without adopting a backend.
//! The complete event batch is examined: Close or excess early-data cost wins
//! even when the same packet established fresh possession.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};

use crate::auth::{
    parse_auth_record, AuthError, AuthRecord, AuthVerifier, Principal, AUTH_DEADLINE,
    AUTH_NONCE_LEN, AUTH_STREAM,
};
use crate::conn::{Connection, Consumption, Datagram, Event, LinkState};
use crate::dgram_queue::DgramRx;
use crate::handshake_payload::Msg1Payload;
use crate::session_manager::binding_revision::BindingRevision;
use crate::session_manager::{send_all, StreamData};

/// How many connections may sit in probation at once, across every source.
/// Capped SEPARATELY from `MAX_SESSIONS_TOTAL`: probation entries are what an
/// unproven peer can create, so they must never be able to crowd out -- let
/// alone evict -- a real backend. Over the cap a handshake is dropped
/// silently: there is nothing to evict, because nothing here belongs to
/// anyone yet. Generous relative to the
/// [`AUTH_DEADLINE`] budget for starting verification so a burst of honest
/// reconnects still gets through. Already-dispatched blocking verification
/// may keep its entry longer, bounded in concurrency by
/// [`MAX_CONCURRENT_VERIFIES`].
///
/// On its own this is a bound on COST, not a defense against a hostile
/// flood: slots free at only about `MAX_PROBATION / AUTH_DEADLINE` per
/// second, so one address handshaking a few times a second would keep the
/// whole table full and lock every honest client out of signing in -- warm
/// reattach after a network change included, since that goes through
/// probation too. What makes the table hostile-proof is
/// [`MAX_PROBATION_PER_SOURCE`] on top of it.
///
/// Raised from 32 to 128 (slice 2c task 9): 32 was sized for one person's
/// own machine. On a machine shared by a dozen people behind one NAT, the
/// per-source cap used to hit everyone at once long before the table itself
/// ever filled. An entry awaiting its proof or a verification permit lives
/// no longer than [`AUTH_DEADLINE`]; dispatched verification may finish later.
///
/// A flood still exhausts probation first, not the helper's own nonce table
/// (256 entries, swept every 30 s) -- but the margin that rests on narrowed
/// with this raise, from 8:1 to 2:1, and it is no longer true
/// unconditionally. It holds because a nonce goes back to the helper the
/// moment its probation ends without a proof (`NonceSource::release`), so
/// the table tracks LIVE probations (at most 128) rather than a 30-second
/// accumulation of them. Were those returns ever lost -- the worker's own
/// release queue overflowing, or the helper itself falling behind -- 128
/// probations turning over every `AUTH_DEADLINE` for one whole sweep window
/// would be 128 * (30 s / 5 s) = 768, well past 256, and the nonce table
/// would be what ran out first.
///
/// Only the manager admits to probation, and nothing outside the crate can
/// configure this. It is public so that a client of the manager can size
/// what it keeps per probation: `qshd` keeps the end of every login the
/// router may still report, and a probation can become one.
pub const MAX_PROBATION: usize = 128;

/// How many of [`MAX_PROBATION`]'s slots a SINGLE source may hold at once, so
/// no one address can fill the table and shut everybody else out.
///
/// Keyed by the same source group as the cookie rate limiter: one IPv4 host
/// (including its mapped IPv6 form), or one native IPv6 /64. Source ports and
/// IPv6 host bits cannot create extra budgets.
/// The price of that choice is that clients sharing one NAT share one budget,
/// which is why the number is not tiny.
///
/// Sixteen is comfortably above anything honest: a client holds one slot per
/// handshake in flight, plus one per 500 ms msg1 retransmit while msg2 is
/// lost (its "retransmit twin"), and a slot is released the moment the proof
/// lands -- a round trip, not the full deadline. Sixteen leaves room for
/// several sessions started at once from the same host, or a few devices
/// behind one address, and still caps any single source at an eighth of the
/// table, so a flood from one place always leaves at least 112 slots for
/// everyone else.
///
/// Raised from 8 to 16 (slice 2c task 9), for the same reason as
/// [`MAX_PROBATION`]: 8 was sized for one person, and a machine shared by a
/// dozen people behind one NAT put every one of them under that single
/// budget at once.
pub(crate) const MAX_PROBATION_PER_SOURCE: usize = 16;

// The return-address check calls the daemon under load at more than half of
// this table (spec §4.16); `cookie.rs` cannot see this constant (it builds
// without `tokio-driver`), so the link is asserted here.
const _: () = assert!(crate::cookie::LOAD_PROBATION_SEATS * 2 == MAX_PROBATION);

/// How many client proofs may be verified at once, across every probation.
///
/// [`AuthVerifier::verify`] is synchronous and can be slow. In the system
/// mode it crosses a seam to a single-threaded privileged helper that does
/// an NSS lookup and reads a file which may sit on a mount that hangs; in
/// the personal mode it reads a file too. Called straight from the
/// probation task, as it used to be, enough of those at once occupy every
/// worker thread the runtime has -- on a 2-4 vCPU box that is all of
/// them -- and the router task, the only reader of the UDP socket, stops
/// being polled at all: not one keystroke, ack, resize or roam of any LIVE
/// session is handled for as long as it lasts. So each verification goes to
/// the blocking pool instead, and this bounds how many may be in flight.
///
/// Four: enough that honest logins never queue behind one another in
/// practice (a verification is microseconds when nothing is hung), few
/// enough that a flood of them cannot be what exhausts the pool. A
/// probation that cannot have a permit AT ONCE waits briefly for one --
/// see [`VERIFY_PERMIT_WAIT`] -- rather than being told its key was
/// refused, and is refused only once that wait, too, finds none free.
pub(crate) const MAX_CONCURRENT_VERIFIES: usize = 4;

/// The permits [`MAX_CONCURRENT_VERIFIES`] hands out: one set for the whole
/// process, because the resource being bounded -- the runtime's blocking
/// pool -- is process-wide too.
///
/// Handed to each probation rather than reached for inside one, so that a
/// test can bound its own probations with a semaphore of its own without
/// being starved by, or starving, every other probation the same test
/// binary is running.
pub(crate) fn verify_permits() -> Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(PERMITS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFIES))))
}

/// How long a proof waits for a verification permit before it is refused.
///
/// Four permits bound how many proofs may be in flight, not how many people
/// may sign in at once. Refusing the fifth on the spot is read by a client
/// as "your key was not accepted", and a client does not retry that. So it
/// waits -- but briefly, and bounded: on a wedged helper this task must not
/// be held open for as long as the helper is stuck, and the client's own
/// `AUTH_DEADLINE` (5 s) would give up on it anyway. A quarter second is
/// far longer than an honest verification (microseconds) and far shorter
/// than that deadline.
pub(crate) const VERIFY_PERMIT_WAIT: Duration = Duration::from_millis(250);

/// Upper bound on the gate's pre-authentication buffer. A record does not
/// necessarily arrive in one piece -- it is chunked by `MAX_SEGMENT_SIZE`, so
/// an RSA-4096 record (about 1.1 KiB) arrives as two `StreamData` events and
/// the gate MUST buffer -- but a buffer with no ceiling, fed by a peer that
/// has proved nothing, is a denial of service of its own. Seven times the
/// largest record anyone actually presents.
const AUTH_RECORD_MAX: usize = 8 * 1024;

/// Upper bound on what a peer's pre-proof stream data may cost the server. A
/// real client sends its record in the same breath as its first keystrokes, so
/// this exists to carry a handful of bytes across the handover, not a
/// transfer: 64 KiB is orders of magnitude more than typing within one round
/// trip, and holding more for a peer that has proved nothing is the same
/// denial of service [`AUTH_RECORD_MAX`] guards against.
///
/// Measured in COST, not payload -- see [`EARLY_ENTRY_COST`].
const EARLY_DATA_MAX: usize = 64 * 1024;

/// What one collected chunk costs the server beyond its payload: the
/// [`StreamData`] record itself, plus a conservative allowance for the heap
/// bookkeeping of its `Vec`.
///
/// Charged per entry because payload alone under-accounts by more than an
/// order of magnitude on a path open to unauthenticated peers: a stream frame
/// is only guaranteed to be non-empty, so ONE 64 KiB datagram can deliver
/// thousands of one-byte `StreamData` events at distinct offsets. Counting
/// just their payload would let 64 KiB of "accounted" data become megabytes of
/// live allocations, once per probation slot and renewable as slots free.
const EARLY_ENTRY_COST: usize = std::mem::size_of::<StreamData>() + 32;

/// What out-of-order data a connection in probation may hold, across all
/// its streams (spec §4.16, QSH-01): besides `EARLY_DATA_MAX` of delivered
/// bytes, what a peer that proved nothing can make the daemon keep. A
/// client sends its record and perhaps a keystroke before it is proven;
/// 64 KiB lets them arrive out of order many times over.
pub(crate) const PROBATION_UNDELIVERED_MAX: usize = 64 * 1024;

/// Hold `conn` to what a peer that proved nothing may cost (spec §4.16).
/// The bridge that binds a proven connection lets it go
/// (`session_manager::adopt_connection`).
pub(crate) fn hold_for_probation(conn: &mut Connection) {
    conn.restrict_to_handshake_source();
    conn.set_undelivered_cap(PROBATION_UNDELIVERED_MAX);
    // What arrives before the proof is taken only when a backend takes it
    // (spec §4.10.3): counted explicitly, like every connection a bridge
    // drives. The proof's own stream is taken as it is read.
    conn.set_default_consumption(Consumption::Explicit);
    conn.set_stream_consumption(AUTH_STREAM, Consumption::OnDelivery);
}

/// The proof required before this connection may bind a backend. Allowlist
/// membership was checked at msg1; fresh possession is still required.
pub(crate) enum ProofPolicy {
    Allowlisted { principal: Principal },
    SshSignature { verifier: Arc<dyn AuthVerifier> },
}

struct AuthGate {
    policy: ProofPolicy,
    hash: [u8; 32],
    /// The nonce THIS handshake's msg2 delivered to the client. A version 2
    /// record must echo it back under its signature, so a proof made for a
    /// different handshake (even one to the same server, from the same key)
    /// cannot be replayed here.
    nonce: [u8; AUTH_NONCE_LEN],
    open: bool,
    /// A record has been handed out to be verified and no verdict has come
    /// back yet. Holds [`AuthGate::feed`] off exactly as `open` does: the
    /// proof is already being dealt with, so a second record arriving in
    /// the meantime must neither start a second verification nor be
    /// appended to the buffer the first was parsed out of.
    verifying: bool,
    deadline: Instant,
    /// Record bytes received so far. A record spans more than one stream
    /// chunk whenever the key is big enough, so the gate accumulates until
    /// [`parse_auth_record`] stops saying [`AuthError::Incomplete`].
    pending: Vec<u8>,
    /// Who the verifier decided this connection is, once the gate opens.
    /// Taken out into the `ProvenSession` when probation succeeds, so the
    /// backend knows whose session it is running.
    principal: Option<Principal>,
}

impl AuthGate {
    #[cfg(test)]
    fn new(
        verifier: Arc<dyn AuthVerifier>,
        hash: [u8; 32],
        nonce: [u8; AUTH_NONCE_LEN],
        now: Instant,
    ) -> Self {
        Self::from_policy(ProofPolicy::SshSignature { verifier }, hash, nonce, now)
    }

    fn from_policy(
        policy: ProofPolicy,
        hash: [u8; 32],
        nonce: [u8; AUTH_NONCE_LEN],
        now: Instant,
    ) -> Self {
        let principal = match &policy {
            ProofPolicy::Allowlisted { principal } => Some(principal.clone()),
            ProofPolicy::SshSignature { .. } => None,
        };
        AuthGate {
            policy,
            hash,
            nonce,
            open: false,
            verifying: false,
            deadline: now + AUTH_DEADLINE,
            pending: Vec::new(),
            principal,
        }
    }

    fn signature_verifier(&self) -> Option<&Arc<dyn AuthVerifier>> {
        match &self.policy {
            ProofPolicy::SshSignature { verifier } => Some(verifier),
            ProofPolicy::Allowlisted { .. } => None,
        }
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn expired(&self, now: Instant) -> bool {
        !self.open && now >= self.deadline
    }

    /// Feed a chunk from [`AUTH_STREAM`]. [`Fed::Waiting`] means "nothing is
    /// wrong so far, and there is nothing to do yet"; [`Fed::Verify`] hands
    /// back a complete record to be VERIFIED -- off the calling task, see
    /// [`MAX_CONCURRENT_VERIFIES`] -- whose verdict comes back through
    /// [`AuthGate::admit`]; an error means this client is refused.
    fn feed(&mut self, bytes: &[u8]) -> Result<Fed, AuthError> {
        // An open gate has nothing to check: the proof already landed, so a
        // stray second record is ignored rather than re-verified -- it must
        // not be able to shut a connection that is already proved. A gate
        // whose record is out with the verifier is the same case, one step
        // earlier.
        if self.open || self.verifying || matches!(self.policy, ProofPolicy::Allowlisted { .. }) {
            return Ok(Fed::Waiting);
        }
        if self.pending.len() + bytes.len() > AUTH_RECORD_MAX {
            return Err(AuthError::BadRecord);
        }
        self.pending.extend_from_slice(bytes);
        let record = match parse_auth_record(&self.pending) {
            Ok(record) => record,
            // A chunk boundary landed inside the record: wait for the rest.
            // `AUTH_DEADLINE` still bounds how long a peer may dawdle.
            Err(AuthError::Incomplete) => return Ok(Fed::Waiting),
            Err(e) => return Err(e),
        };
        // A v2 record must echo back the nonce THIS handshake issued.
        // Checked before the signature so a proof lifted from another
        // handshake is refused without the verifier ever being asked.
        if let Some(v2) = &record.v2 {
            if v2.nonce != self.nonce {
                return Err(AuthError::BadRecord);
            }
        }
        self.verifying = true;
        Ok(Fed::Verify(record))
    }

    /// The verdict for the record [`AuthGate::feed`] handed out: the gate
    /// opens, and the principal is kept for the session that follows.
    fn admit(&mut self, principal: Principal) {
        log::info!("session authenticated: {}", principal.identity);
        self.principal = Some(principal);
        self.pending = Vec::new();
        self.verifying = false;
        self.open = true;
    }
}

/// What [`AuthGate::feed`] wants done next.
enum Fed {
    /// Nothing to do: the record is not complete yet, or the proof is
    /// already open or already out being verified.
    Waiting,
    /// A complete record that passed every check the gate makes by itself.
    /// It must now be verified, and the verdict handed to
    /// [`AuthGate::admit`].
    Verify(AuthRecord),
}

/// What the probation stage consumed off a connection before handing it over,
/// for the bridge to replay to the backend.
///
/// The probation task has to poll the connection's events to see the auth
/// record at all, which also drains the `Live` transition and any stream
/// bytes the client sent alongside it. Those events are gone from the
/// connection by the time a bridge drives it, and the reliability layer has
/// already ACKed the bytes, so the bridge would lose them for good unless it
/// replays them. ORDER IS PART OF THE CONTRACT: the backend hears about its
/// session starting (`Live`/`ResumeReset`) before any of these bytes.
///
/// `Default` is an empty handoff. Both authentication policies collect the
/// initial Live transition and any early stream data before admission.
#[derive(Default)]
pub(crate) struct BridgeStart {
    /// The connection reached `Live` while in probation (always true in
    /// practice -- `accept` queues that transition -- but recorded rather
    /// than assumed, so the replay is checkable instead of a comment).
    pub saw_live: bool,
    /// Stream bytes the client sent before its proof landed, in arrival order.
    pub early: Vec<StreamData>,
}

/// A connection whose peer has proved itself, with everything the manager's
/// binding decision needs. Boxed by the channel: it is large and rare next to
/// the per-datagram traffic the same loop carries.
pub(crate) struct ProvenSession {
    pub revision: BindingRevision,
    pub conn: Connection,
    pub client_key: [u8; 32],
    pub msg1: Msg1Payload,
    /// The exact msg1 body, for the retransmit-idempotency comparison.
    pub msg1_body: Vec<u8>,
    /// The msg2 datagrams `accept` produced. Already sent once, when probation
    /// began; the decision arms cache them and re-send them, which a client
    /// that is already `Live` ignores (see `Connection::on_handshake_resp`).
    pub out: Vec<Datagram>,
    /// The address the handshake came from.
    pub src: SocketAddr,
    pub start: BridgeStart,
    /// The nonce this handshake's msg2 carried -- the same value `AuthGate`
    /// checked a v2 record's proof against. Carried onward rather than
    /// dropped once probation succeeds, so `Admission` is built from a real
    /// value on this path too, not a placeholder.
    pub nonce: [u8; AUTH_NONCE_LEN],
    /// Who the verifier decided this connection is. Taken out of `AuthGate`
    /// once its gate opens, so it reaches the backend's `SessionIo`.
    pub principal: Principal,
    /// The probation's datagram queue: everything routed to this connection
    /// while its proof was verified and since, not yet read (spec §4.5). The
    /// manager hands it to the bridge, so none of it -- a road check, a PING,
    /// DATA -- is lost with this task.
    pub dgram_rx: DgramRx,
}

/// Signalled by a probation task when its connection resolved, so the manager
/// can either bind it or drop its route. Mirrors `SessionEnded`: one
/// unbounded channel, drained in the same `select!` as the socket.
pub(crate) struct ProbationEnded {
    pub revision: BindingRevision,
    /// The provisional `session_id` the datagram route was registered under.
    pub session_id: u64,
    /// The nonce this handshake's msg2 carried. Duplicated here (rather than
    /// only inside `ProvenSession`) so the manager can release it when
    /// `proven` is `None` -- a refusal has no `ProvenSession` to read it
    /// from.
    pub nonce: [u8; AUTH_NONCE_LEN],
    /// `Some` once the peer's record verified; `None` for every refusal (a bad
    /// record, a closed connection, the deadline), which means "drop the
    /// route".
    pub proven: Option<Box<ProvenSession>>,
}

/// Everything a probation task is started with.
pub(crate) struct Probation {
    pub revision: BindingRevision,
    pub socket: Arc<UdpSocket>,
    pub conn: Connection,
    pub policy: ProofPolicy,
    pub dgram_rx: DgramRx,
    pub client_key: [u8; 32],
    pub msg1: Msg1Payload,
    pub msg1_body: Vec<u8>,
    pub out: Vec<Datagram>,
    pub src: SocketAddr,
    pub ended_tx: mpsc::UnboundedSender<ProbationEnded>,
    /// The nonce this handshake's msg2 carried, for `AuthGate` to check a
    /// v2 record's proof against.
    pub nonce: [u8; AUTH_NONCE_LEN],
    /// Permission to run this probation's verification: one permit for the
    /// duration of the call, or a refusal -- see [`MAX_CONCURRENT_VERIFIES`].
    pub verify_permits: Arc<Semaphore>,
}

/// Where a drain of the connection's events left the probation.
enum Step {
    /// Nothing decided yet: keep pumping the connection.
    Waiting,
    /// A complete record is ready to be verified -- the one thing a drain
    /// cannot do itself, because verifying is synchronous and a drain runs
    /// on an async task (see [`MAX_CONCURRENT_VERIFIES`]).
    Verify(AuthRecord),
    /// The record verified.
    Proved,
    /// Refused -- a bad record or a closed connection.
    Refused,
}

/// Run one connection's probation to its end and signal the manager. Owns the
/// `Connection` throughout: it is handed on only by the `Proved` path, so a
/// peer that never proves itself has no way to reach a backend.
pub(crate) async fn run_probation(p: Probation) {
    run_probation_with_clock(p, Instant::now).await;
}

// Only authentication uses this clock; Connection retains its own transport
// clock. Tests can cross the auth deadline while keeping socket readiness and
// transport timers under independent control.
async fn run_probation_with_clock(p: Probation, auth_now: impl Fn() -> Instant) {
    let Probation {
        socket,
        mut conn,
        policy,
        revision,
        mut dgram_rx,
        client_key,
        msg1,
        msg1_body,
        out,
        src,
        ended_tx,
        nonce,
        verify_permits,
    } = p;
    hold_for_probation(&mut conn);
    let session_id = conn.session_id();
    let mut gate = AuthGate::from_policy(policy, conn.handshake_hash(), nonce, auth_now());
    let mut start = BridgeStart::default();
    let mut early_cost = 0usize;

    // `accept` already queued HandshakeDone + StateChanged(Live): take those
    // in before waiting on anything.
    let mut step = drain(
        &mut conn,
        &mut gate,
        &mut start,
        &mut early_cost,
        auth_now(),
    );
    loop {
        match step {
            // A record waiting to be verified comes first: its verdict
            // decides everything else, and until it is in there is nothing
            // to wait for.
            Step::Verify(record) => {
                // What the connection owes goes before the verdict is
                // sought: nothing pumps it while a proof is verified, which
                // may take as long as a PAM stack does, and the ACK of the
                // record's own datagram -- owed either way (see below) --
                // would otherwise wait for a ride or `ACK_DELAY` that no
                // loop serves until then (spec §4.11).
                send_all(&socket, &conn.answer_now()).await;
                step = verify_off_task(
                    &mut gate,
                    record,
                    &verify_permits,
                    msg1.token,
                    src,
                    &auth_now,
                )
                .await;
                continue;
            }
            Step::Waiting => {}
            // Proved or Refused: nothing left to pump.
            _ => break,
        }
        // Never sleep past the gate's deadline, or a silent peer would linger
        // until the connection's own liveness timeout noticed it.
        let auth_wait = gate.deadline().saturating_duration_since(auth_now());
        let dur = conn.next_timeout().map_or(auth_wait, |t| {
            t.saturating_duration_since(Instant::now()).min(auth_wait)
        });
        let incoming = tokio::select! {
            d = dgram_rx.recv() => Some(d),
            _ = tokio::time::sleep(dur) => None,
        };
        // Readiness must never extend authentication: both arms can be ready
        // together, and the datagram arm may win after the absolute deadline.
        if gate.expired(auth_now()) {
            log::warn!("session refused: authentication deadline expired");
            return end(&ended_tx, session_id, nonce, revision, None);
        }
        let mut reply: Vec<Datagram> = Vec::new();
        match incoming {
            Some(Some((from, bytes))) => {
                reply.extend(conn.on_datagram(Instant::now(), from, &bytes));
            }
            // The manager dropped the route (shutdown, or supersession).
            Some(None) => return end(&ended_tx, session_id, nonce, revision, None),
            None => {}
        }
        // Timers after every wake-up (spec §4.1), the datagram arm included.
        reply.extend(conn.on_timeout_if_due(Instant::now()));
        // Answer at the transport level BEFORE deciding: the ACK for the
        // datagram that carried the record is owed either way, and a client
        // that never sees it retransmits a record the gate has already
        // consumed. What a datagram draws at once goes here; an ACK held
        // for a ride (spec §4.11) goes before verifying (the `Verify` arm
        // above), or at its deadline, which `next_timeout` above includes.
        send_all(&socket, &reply).await;
        step = drain(
            &mut conn,
            &mut gate,
            &mut start,
            &mut early_cost,
            auth_now(),
        );
    }

    let proven = match step {
        Step::Proved => Some(Box::new(ProvenSession {
            revision: revision.clone(),
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            start,
            nonce,
            principal: gate
                .principal
                .take()
                .expect("a proved gate always recorded a principal"),
            dgram_rx,
        })),
        // `Waiting` and `Verify` cannot reach here (the loop above breaks
        // on neither); `Refused` hands nothing over.
        _ => None,
    };
    end(&ended_tx, session_id, nonce, revision, proven);
}

/// Verify one record away from the probation's own task, and say what
/// became of the probation.
///
/// Two things happen here that must not happen on that task. A permit is
/// taken -- waited for briefly when there is none free, and refused only if
/// that wait finds none either, rather than queued indefinitely behind
/// verifications that may be stuck for as long as a hung mount -- and the
/// synchronous `verify` runs on the blocking pool, so the runtime's worker
/// threads, and with them the router task that reads every live session's
/// datagrams, stay free while it does. See [`MAX_CONCURRENT_VERIFIES`] and
/// [`VERIFY_PERMIT_WAIT`].
async fn verify_off_task(
    gate: &mut AuthGate,
    record: AuthRecord,
    permits: &Arc<Semaphore>,
    login: [u8; 16],
    src: SocketAddr,
    auth_now: &impl Fn() -> Instant,
) -> Step {
    // Four permits bound how many proofs may be in flight, not how many
    // people may sign in at once: the fifth waits its turn briefly instead
    // of being told its key was refused, which is how a client reads an
    // immediate refusal -- and it does not retry it. Bounded, because on a
    // wedged helper this task must not be held open for as long as the
    // helper is stuck. See VERIFY_PERMIT_WAIT.
    // The ACK send above may have yielded after the record was drained.
    // Waiting for capacity is still pre-authentication, not a started proof.
    if gate.expired(auth_now()) {
        log::warn!("session refused: authentication deadline expired");
        return Step::Refused;
    }
    let wait = VERIFY_PERMIT_WAIT.min(gate.deadline().saturating_duration_since(auth_now()));
    let permit = match tokio::time::timeout(wait, Arc::clone(permits).acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            // The semaphore itself was closed -- never happens in this
            // program (nothing ever calls `close` on it), but naming it
            // separately from a timed-out wait keeps the log honest if
            // that ever changes.
            log::warn!("session refused: the verification permit semaphore is closed");
            return Step::Refused;
        }
        Err(_) => {
            if gate.expired(auth_now()) {
                log::warn!("session refused: authentication deadline expired");
            } else {
                log::warn!("session refused: too many proofs are being verified at once");
            }
            return Step::Refused;
        }
    };
    // An available permit can win even when its timeout is already ready.
    if gate.expired(auth_now()) {
        log::warn!("session refused: authentication deadline expired");
        return Step::Refused;
    }
    let Some(verifier) = gate.signature_verifier().cloned() else {
        return Step::Refused;
    };
    let hash = gate.hash;
    // Where this handshake came from, for a verifier that records it (the
    // system mode's keeps it for `PAM_RHOST` and for the log). Rendered
    // here, from the address this process itself received the datagram
    // from, rather than anywhere the client can reach.
    let rhost = src.to_string();
    // Once dispatched, a PAM/file verification may finish after the arrival
    // deadline. Keep its permit and await the real verdict rather than abandon
    // blocking work or turn a successfully verified login into a timeout.
    let verdict = tokio::task::spawn_blocking(move || {
        // Held for exactly as long as the call it pays for.
        let _permit = permit;
        verifier.verify(&hash, &record, login, &rhost)
    })
    .await;
    match verdict {
        Ok(Ok(principal)) => {
            gate.admit(principal);
            Step::Proved
        }
        Ok(Err(e)) => {
            log::warn!("session refused: {e}");
            Step::Refused
        }
        // The blocking call panicked, or the runtime is shutting down.
        // Refuse: nobody is admitted on the strength of a verification that
        // did not finish.
        Err(e) => {
            log::warn!("session refused: the proof could not be verified: {e}");
            Step::Refused
        }
    }
}

/// Signal the manager once, at exactly one exit point, so a probation entry
/// can never be left occupying its cap slot and its route.
fn end(
    ended_tx: &mpsc::UnboundedSender<ProbationEnded>,
    session_id: u64,
    nonce: [u8; AUTH_NONCE_LEN],
    revision: BindingRevision,
    proven: Option<Box<ProvenSession>>,
) {
    // A send error means the manager is already gone; there is nothing left to
    // reclaim.
    let _ = ended_tx.send(ProbationEnded {
        revision,
        session_id,
        nonce,
        proven,
    });
}

/// Drain the connection's events: feed [`AUTH_STREAM`] to the gate and record
/// everything the backend will need replayed. NOTHING is forwarded anywhere:
/// there is no backend to forward to, which is the whole point.
///
/// `early_cost` is the running total of what has been collected (payload plus
/// [`EARLY_ENTRY_COST`] per entry), carried by the caller rather than
/// recomputed here: a peer that sends one small frame per datagram makes this
/// run once per datagram, and re-summing the whole collection each time would
/// be quadratic in exactly the case an attacker controls.
fn drain(
    conn: &mut Connection,
    gate: &mut AuthGate,
    start: &mut BridgeStart,
    early_cost: &mut usize,
    now: Instant,
) -> Step {
    // Includes the first drain and the drain after the async transport reply.
    if gate.expired(now) {
        log::warn!("session refused: authentication deadline expired");
        return Step::Refused;
    }
    let mut closed = false;
    let mut to_verify = None;
    for ev in conn.poll_events() {
        match ev {
            Event::PeerKeyConfirmed { .. } => {
                if matches!(gate.policy, ProofPolicy::Allowlisted { .. }) {
                    gate.open = true;
                }
            }
            Event::StreamData { stream_id, data } if stream_id == AUTH_STREAM => {
                // The proof never reaches a backend -- this stream belongs to
                // the session layer.
                match gate.feed(&data) {
                    Ok(Fed::Waiting) => {}
                    // Held until the whole batch is drained rather than
                    // acted on here: the bytes a client sent alongside its
                    // proof still have to be collected below, and the
                    // connection's own `Closed` still has to be seen. The
                    // gate has marked itself `verifying`, so a second
                    // record in this same batch cannot start a second one.
                    Ok(Fed::Verify(record)) => to_verify = Some(record),
                    Err(e) => {
                        log::warn!("session refused: {e}");
                        return Step::Refused;
                    }
                }
            }
            Event::StreamData { stream_id, data } => {
                *early_cost += data.len() + EARLY_ENTRY_COST;
                if *early_cost > EARLY_DATA_MAX {
                    log::warn!("session refused: too much data before the proof");
                    return Step::Refused;
                }
                start.early.push(StreamData { stream_id, data });
            }
            Event::StateChanged(LinkState::Live) => start.saw_live = true,
            Event::StateChanged(LinkState::Closed)
            | Event::SendBufferOverCap { .. }
            | Event::OffsetSpaceExhausted { .. } => closed = true,
            // `OutputResync` asks a backend to repaint. There is no backend
            // yet, and the bridge opens with `Live`/`ResumeReset` -- on which
            // a backend re-renders anyway -- so it is subsumed, not lost.
            // Every other event is client-side or informational.
            _ => {}
        }
    }
    if closed {
        return Step::Refused;
    }
    if let Some(record) = to_verify {
        return Step::Verify(record);
    }
    if gate.is_open() {
        Step::Proved
    } else {
        Step::Waiting
    }
}

#[cfg(test)]
#[path = "probation_tests.rs"]
mod tests;
