//! The probation stage: what a connection may do before its peer has proved
//! who it is.
//!
//! On the ALLOWLIST path a handshake IS a proof -- `Connection::accept`
//! checked the client's static key against the allowlist -- so the manager
//! binds the connection to a backend the moment it is accepted. On the
//! SIGNATURE path it is not: `AuthPolicy::SshSignature` admits ANY static
//! key, and the real proof (an SSH signature over this handshake's hash)
//! arrives afterwards, on [`AUTH_STREAM`].
//!
//! So a signature handshake does not become a session; it becomes a
//! PROBATION. A task owns the accepted `Connection`, answers its transport
//! chatter and waits for the record. The manager registers only the datagram
//! route (so the record can reach the task) and touches NOTHING in its
//! backend table -- no reattach, no replace, no eviction. An unproven peer
//! therefore cannot repoint another device's route, overwrite its client key,
//! scrub that key off the shared allowlist, or evict a retained backend,
//! because it never reaches the code that does any of those things.
//!
//! When the record verifies, the task hands the manager the proven connection
//! plus everything the binding decision needs, and the manager runs its
//! ordinary decision arms THEN -- the logic does not move, it only runs later.
//! When it does not verify -- a malformed or refused record, a closed
//! connection, or [`AUTH_DEADLINE`] -- the task exits and the manager drops
//! the route.

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
    conn.set_undelivered_cap(PROBATION_UNDELIVERED_MAX);
    // What arrives before the proof is taken only when a backend takes it
    // (spec §4.10.3): counted explicitly, like every connection a bridge
    // drives. The proof's own stream is taken as it is read.
    conn.set_default_consumption(Consumption::Explicit);
    conn.set_stream_consumption(AUTH_STREAM, Consumption::OnDelivery);
}

/// The per-connection authentication gate. It stays shut until the client's
/// record on [`AUTH_STREAM`] verifies against THIS connection's handshake
/// hash, so a warm reattach -- which brings a new handshake, hence a new
/// challenge -- must prove itself again before it inherits anything.
///
/// There is no "no verifier" case: the allowlist path builds no gate at all,
/// because it runs no probation stage.
struct AuthGate {
    verifier: Arc<dyn AuthVerifier>,
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
    fn new(
        verifier: Arc<dyn AuthVerifier>,
        hash: [u8; 32],
        nonce: [u8; AUTH_NONCE_LEN],
        now: Instant,
    ) -> Self {
        AuthGate {
            verifier,
            hash,
            nonce,
            open: false,
            verifying: false,
            deadline: now + AUTH_DEADLINE,
            pending: Vec::new(),
            principal: None,
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
        if self.open || self.verifying {
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
/// `Default` is the ALLOWLIST path: nothing was consumed, so there is nothing
/// to replay and the bridge behaves exactly as it did before probation
/// existed.
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
    pub socket: Arc<UdpSocket>,
    pub conn: Connection,
    pub verifier: Arc<dyn AuthVerifier>,
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
        verifier,
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
    let mut gate = AuthGate::new(verifier, conn.handshake_hash(), nonce, auth_now());
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
            return end(&ended_tx, session_id, nonce, None);
        }
        let mut reply: Vec<Datagram> = Vec::new();
        match incoming {
            Some(Some((from, bytes))) => {
                reply.extend(conn.on_datagram(Instant::now(), from, &bytes));
            }
            // The manager dropped the route (shutdown, or supersession).
            Some(None) => return end(&ended_tx, session_id, nonce, None),
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
    end(&ended_tx, session_id, nonce, proven);
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
    let verifier = Arc::clone(&gate.verifier);
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
    proven: Option<Box<ProvenSession>>,
) {
    // A send error means the manager is already gone; there is nothing left to
    // reclaim.
    let _ = ended_tx.send(ProbationEnded {
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
            Event::StateChanged(LinkState::Closed) => closed = true,
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
mod tests {
    use super::*;
    use crate::auth::{encode_auth_record, AuthRecord, AuthV2, AUTH_RECORD_VERSION};
    use crate::conn::{AcceptOutcome, AuthPolicy, ConnectionConfig, Msg2Inputs, Role};
    use crate::dgram_queue::{dgram_queue, DgramTx};
    use crate::handshake::generate_keypair;
    use crate::handshake_payload::{encode_msg1, AuthMethod, StartKind};
    use crate::reliability::StreamFrame;
    use crate::wire::{parse as parse_wire_frame, Frame as WireFrame};
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// The permits a test's own probations run under: its own semaphore,
    /// never the process-wide one, so nothing another test in this binary
    /// happens to be doing can take a permit this test is counting on, or
    /// be refused because this test is holding them all.
    fn test_permits() -> Arc<Semaphore> {
        Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFIES))
    }

    /// The numbers themselves, pinned. Both caps are judgement calls, and every
    /// test that exercises them loops over the constant -- so without this a
    /// revert to 32/8 leaves the whole workspace green. What the assertion buys
    /// is not arithmetic but a stop sign: changing it means reading the two doc
    /// comments above and the ratio to the helper's own MAX_OUTSTANDING_NONCES.
    ///
    /// [`VERIFY_PERMIT_WAIT`] is pinned here too, the same way: every test
    /// that exercises it scales by the constant rather than a literal, so on
    /// its own it would pass at any value -- including one past
    /// [`AUTH_DEADLINE`], which its own doc comment says must never happen.
    #[test]
    fn the_probation_caps_are_the_numbers_the_spec_argues_for() {
        // The ratio these have to keep is against the HELPER's
        // MAX_OUTSTANDING_NONCES (256), which lives in another crate entirely
        // (`qshd::helper::server`, and `pub(super)` there) -- so it cannot be
        // asserted from here, and the comparison stays prose in MAX_PROBATION's
        // own doc comment. What this test pins is the two numbers themselves.
        assert_eq!(MAX_PROBATION, 128, "see MAX_PROBATION's docs and spec 5.3");
        assert_eq!(MAX_PROBATION_PER_SOURCE, 16, "see its docs and spec 5.3");
        assert_eq!(
            MAX_PROBATION_PER_SOURCE * 8,
            MAX_PROBATION,
            "one source must be capped at an eighth of the table, as 5.3 argues"
        );
        // VERIFY_PERMIT_WAIT itself: both tests that exercise it only ever
        // compare against a multiple of the constant, so this is the one
        // place that reads its actual doc comment's promise -- a wedged
        // helper must not hold a probation open for as long as the helper
        // is stuck, and AUTH_DEADLINE is the outer bound on how long that
        // may ever be.
        assert!(
            VERIFY_PERMIT_WAIT < AUTH_DEADLINE,
            "the wait must not outlast the deadline it is meant to stay inside"
        );
    }

    /// [`AuthGate::feed`] plus, when it asks for one, the verification --
    /// both on this thread. Exactly what `run_probation` does across its
    /// two steps (`Fed::Verify`, the blocking pool, [`AuthGate::admit`]),
    /// for the tests below that are about the GATE rather than about where
    /// the verifying runs.
    fn feed_and_verify(gate: &mut AuthGate, bytes: &[u8]) -> Result<(), AuthError> {
        match gate.feed(bytes)? {
            Fed::Waiting => Ok(()),
            Fed::Verify(record) => {
                let verifier = Arc::clone(&gate.verifier);
                let hash = gate.hash;
                // These tests are about the gate, not about which device
                // this is -- a fixed placeholder is enough.
                let principal = verifier.verify(&hash, &record, [0u8; 16], "")?;
                gate.admit(principal);
                Ok(())
            }
        }
    }

    /// [`drain`] plus that same verification, for the tests below that are
    /// about what a drain collects rather than about where the verifying
    /// runs.
    fn drain_and_verify(
        conn: &mut Connection,
        gate: &mut AuthGate,
        start: &mut BridgeStart,
        early_cost: &mut usize,
    ) -> Step {
        match drain(conn, gate, start, early_cost, Instant::now()) {
            Step::Verify(record) => {
                let verifier = Arc::clone(&gate.verifier);
                let hash = gate.hash;
                // As in `feed_and_verify`: not about which device this is.
                match verifier.verify(&hash, &record, [0u8; 16], "") {
                    Ok(principal) => {
                        gate.admit(principal);
                        Step::Proved
                    }
                    Err(e) => {
                        log::warn!("session refused: {e}");
                        Step::Refused
                    }
                }
            }
            other => other,
        }
    }

    /// A verifier that accepts exactly one signature body and counts attempts.
    struct FakeVerifier {
        expected: Vec<u8>,
        attempts: Arc<AtomicUsize>,
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
                    uid: 1000,
                    name: "test".to_string(),
                    identity: "fake-key".to_string(),
                    incarnation: 0,
                })
            } else {
                Err(AuthError::BadSignature)
            }
        }
    }

    fn accepting_good() -> Arc<dyn AuthVerifier> {
        Arc::new(FakeVerifier {
            expected: b"good".to_vec(),
            attempts: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// A server-side connection whose event queue is seeded directly: what is
    /// under test is how a BATCH of events drains, which on the wire depends
    /// on how a peer chose to pack its datagram.
    fn seeded(events: Vec<Event>) -> Connection {
        let kp = crate::handshake::generate_keypair();
        let mut conn = Connection::new(crate::conn::ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: crate::conn::Role::Server,
            local_static_priv: kp.private,
            remote_static_pub: None,
            auth: crate::conn::AuthPolicy::SshSignature,
        });
        for ev in events {
            conn.push_test_event(ev);
        }
        conn
    }

    fn data(stream_id: u8, bytes: &[u8]) -> Event {
        Event::StreamData {
            stream_id,
            data: bytes.to_vec(),
        }
    }

    /// What a peer sends before its proof is COLLECTED in order for the
    /// backend, and the record itself is NOT among it: the auth stream belongs
    /// to the session layer and must never reach a backend.
    #[test]
    fn early_data_is_collected_in_order_and_the_record_is_not() {
        let mut conn = seeded(vec![
            Event::StateChanged(LinkState::Live),
            data(0, b"one"),
            Event::StreamData {
                stream_id: AUTH_STREAM,
                data: encode_auth_record(&AuthRecord {
                    public_key: b"key".to_vec(),
                    signature: b"good".to_vec(),
                    v2: None,
                })
                .expect("encodes"),
            },
            data(0, b"two"),
        ]);
        let mut gate = AuthGate::new(accepting_good(), [0u8; 32], [0u8; 16], Instant::now());
        let mut start = BridgeStart::default();
        assert!(matches!(
            drain_and_verify(&mut conn, &mut gate, &mut start, &mut 0),
            Step::Proved
        ));
        assert!(start.saw_live, "the Live transition is recorded, not lost");
        let collected: Vec<u8> = start.early.iter().flat_map(|sd| sd.data.clone()).collect();
        assert_eq!(
            collected, b"onetwo",
            "every non-auth byte is kept, in order, and no record byte leaks in"
        );
        assert!(
            start.early.iter().all(|sd| sd.stream_id == 0),
            "nothing from the auth stream may be handed to a backend"
        );
    }

    /// Holding pre-proof bytes is bounded. A peer that has proved nothing must
    /// not be able to make the server buffer for it without limit -- the same
    /// denial of service `AUTH_RECORD_MAX` guards the record against.
    #[test]
    fn too_much_data_before_the_proof_is_refused() {
        let mut conn = seeded(vec![
            data(0, &vec![b'x'; EARLY_DATA_MAX]),
            data(0, b"one byte too many"),
        ]);
        let mut gate = AuthGate::new(accepting_good(), [0u8; 32], [0u8; 16], Instant::now());
        let mut start = BridgeStart::default();
        assert!(
            matches!(
                drain(&mut conn, &mut gate, &mut start, &mut 0, Instant::now()),
                Step::Refused
            ),
            "past the cap the connection is refused, not buffered further"
        );
    }

    /// The cap is charged across DRAINS, not within one: a peer that spreads
    /// its flood over many datagrams gets one `drain` per datagram, so a total
    /// that reset each time would be no cap at all. Two halves, each fine on
    /// its own, must together exceed it.
    #[test]
    fn the_early_data_cap_accumulates_across_drains() {
        let half = vec![b'x'; EARLY_DATA_MAX / 2 + 1];
        let mut gate = AuthGate::new(accepting_good(), [0u8; 32], [0u8; 16], Instant::now());
        let mut start = BridgeStart::default();
        let mut cost = 0usize;

        let mut first = seeded(vec![data(0, &half)]);
        assert!(
            matches!(
                drain(&mut first, &mut gate, &mut start, &mut cost, Instant::now()),
                Step::Waiting
            ),
            "half the cap on its own is under it"
        );
        assert!(
            cost > 0,
            "the running total survives the drain that made it"
        );

        let mut second = seeded(vec![data(0, &half)]);
        assert!(
            matches!(
                drain(
                    &mut second,
                    &mut gate,
                    &mut start,
                    &mut cost,
                    Instant::now()
                ),
                Step::Refused
            ),
            "the second half is charged on top of the first, not instead of it"
        );
    }

    /// Payload alone is not what a peer costs the server. A stream frame is
    /// only guaranteed to be non-empty, so one datagram can deliver thousands
    /// of one-byte `StreamData` events -- each an allocation and a struct.
    /// Charging per entry is what stops 64 KiB of "accounted" bytes becoming
    /// megabytes of live memory.
    #[test]
    fn a_flood_of_one_byte_frames_is_refused_far_short_of_its_payload() {
        // Enough one-byte frames to exceed the cap by COST, while their
        // payload is a small fraction of it.
        let frames = EARLY_DATA_MAX / EARLY_ENTRY_COST + 1;
        let payload = frames; // one byte each
        assert!(
            payload * 8 < EARLY_DATA_MAX,
            "the fixture must stay well under the cap by payload, or it proves nothing"
        );
        let mut conn = seeded((0..frames).map(|_| data(0, b"x")).collect());
        let mut gate = AuthGate::new(accepting_good(), [0u8; 32], [0u8; 16], Instant::now());
        let mut start = BridgeStart::default();
        assert!(
            matches!(
                drain(&mut conn, &mut gate, &mut start, &mut 0, Instant::now()),
                Step::Refused
            ),
            "a peer is charged for what it makes the server hold, not just for what it sent"
        );
    }

    /// A refused record ends the probation rather than leaving it waiting for
    /// a better one: a peer gets one proof, not an oracle to guess against.
    #[test]
    fn a_refused_record_ends_the_probation() {
        let mut conn = seeded(vec![Event::StreamData {
            stream_id: AUTH_STREAM,
            data: encode_auth_record(&AuthRecord {
                public_key: b"key".to_vec(),
                signature: b"wrong".to_vec(),
                v2: None,
            })
            .expect("encodes"),
        }]);
        let mut gate = AuthGate::new(accepting_good(), [0u8; 32], [0u8; 16], Instant::now());
        let mut start = BridgeStart::default();
        assert!(matches!(
            drain_and_verify(&mut conn, &mut gate, &mut start, &mut 0),
            Step::Refused
        ));
        assert!(!gate.is_open());
    }

    /// A `Closed` in the same batch as the record refuses the connection,
    /// and that record never reaches the verifier.
    ///
    /// `drain` checks `closed` BEFORE the record it stashed, and that order
    /// is the whole property: a peer whose connection went away in the same
    /// batch that carried its proof has nothing left to be admitted to, and
    /// verifying is the one step here that can cost a seam, an NSS lookup
    /// and a file read on a mount that hangs. Swapping the two checks passes
    /// every other test in this module -- no other test contains a `Closed`
    /// event at all -- which is why this one exists.
    #[test]
    fn a_connection_closed_in_the_same_batch_as_its_record_is_refused() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut conn = seeded(vec![
            Event::StreamData {
                stream_id: AUTH_STREAM,
                data: good_record(),
            },
            Event::StateChanged(LinkState::Closed),
        ]);
        let mut gate = AuthGate::new(
            Arc::new(FakeVerifier {
                expected: b"good".to_vec(),
                attempts: Arc::clone(&attempts),
            }),
            [0u8; 32],
            [0u8; 16],
            Instant::now(),
        );
        let mut start = BridgeStart::default();
        assert!(
            matches!(
                drain_and_verify(&mut conn, &mut gate, &mut start, &mut 0),
                Step::Refused
            ),
            "a connection that closed in the same batch as its record must be refused, not \
             proved on the strength of a proof it can no longer be given anything for"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "the record of a connection that is already gone must never reach the verifier"
        );
        assert!(!gate.is_open(), "and the gate must stay shut");
    }

    /// A second record arriving while the first is still out for
    /// verification is IGNORED -- never appended to the buffer the first was
    /// parsed from.
    ///
    /// The `verifying` flag is load-bearing in a way that is easy to lose:
    /// `pending` is cleared only by [`AuthGate::admit`], and
    /// `parse_auth_record` refuses trailing bytes, so WITHOUT the flag a
    /// second record in the same batch would be concatenated onto the first
    /// and the re-parse would answer `BadRecord` -- refusing a proof that
    /// was about to verify. Before this refactor the same client was fine,
    /// because the gate was already `open` by the time the second record
    /// was fed. So what this pins is a spurious REFUSAL of an honest
    /// client, not merely a duplicate verification.
    #[test]
    fn a_second_record_while_the_first_is_out_for_verification_is_ignored() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut conn = seeded(vec![
            Event::StreamData {
                stream_id: AUTH_STREAM,
                data: good_record(),
            },
            Event::StreamData {
                stream_id: AUTH_STREAM,
                data: good_record(),
            },
        ]);
        let mut gate = AuthGate::new(
            Arc::new(FakeVerifier {
                expected: b"good".to_vec(),
                attempts: Arc::clone(&attempts),
            }),
            [0u8; 32],
            [0u8; 16],
            Instant::now(),
        );
        let mut start = BridgeStart::default();
        assert!(
            matches!(
                drain_and_verify(&mut conn, &mut gate, &mut start, &mut 0),
                Step::Proved
            ),
            "two records in one batch must prove the connection on the first and ignore the \
             second -- never refuse it for the trailing bytes the second would otherwise add"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the second record must not be verified a second time"
        );
        assert!(gate.is_open(), "the first record proved it");
    }

    /// A record bigger than one transport segment arrives as SEVERAL
    /// `StreamData` events. The gate must buffer them: parsing each chunk on
    /// its own would refuse an ordinary RSA-4096 key, whose record is about a
    /// kilobyte -- longer than `MAX_SEGMENT_SIZE`.
    #[test]
    fn a_record_split_across_two_chunks_authenticates() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let signature = vec![0x5Au8; 516];
        let bytes = encode_auth_record(&AuthRecord {
            public_key: vec![0x11u8; 535],
            signature: signature.clone(),
            v2: None,
        })
        .expect("encodes");
        assert!(
            bytes.len() > 1024,
            "the fixture must exceed one transport segment, or it proves nothing"
        );
        let mut gate = AuthGate::new(
            Arc::new(FakeVerifier {
                expected: signature,
                attempts: attempts.clone(),
            }),
            [3u8; 32],
            [0u8; 16],
            Instant::now(),
        );

        let (head, tail) = bytes.split_at(1024);
        assert!(
            feed_and_verify(&mut gate, head).is_ok(),
            "half a record is not a failure"
        );
        assert!(!gate.is_open(), "half a record proves nothing");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "a partial record must never reach the verifier"
        );
        assert!(feed_and_verify(&mut gate, tail).is_ok());
        assert!(gate.is_open(), "the two halves make one record");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the reassembled record is verified exactly once"
        );
    }

    /// The pre-authentication buffer is capped: a peer that has proved nothing
    /// must not be able to make the server hold memory for it indefinitely.
    #[test]
    fn an_oversized_record_is_refused_rather_than_buffered() {
        let mut gate = AuthGate::new(accepting_good(), [3u8; 32], [0u8; 16], Instant::now());
        // A well-formed prefix that never completes: version byte, then a
        // declared key length nothing will ever satisfy.
        let mut prefix = vec![AUTH_RECORD_VERSION, 0xFF, 0xFF];
        prefix.resize(AUTH_RECORD_MAX, 0);
        assert!(
            feed_and_verify(&mut gate, &prefix).is_ok(),
            "the cap itself is not exceeded"
        );
        assert_eq!(
            feed_and_verify(&mut gate, &[0u8]),
            Err(AuthError::BadRecord),
            "one byte past the cap ends the connection instead of growing the buffer"
        );
    }

    /// A silent peer runs out of time; a proved one never does, however long
    /// it then stays connected.
    #[test]
    fn the_gate_expires_only_while_it_is_shut() {
        let start = Instant::now();
        let mut gate = AuthGate::new(accepting_good(), [3u8; 32], [0u8; 16], start);
        assert!(!gate.expired(start + AUTH_DEADLINE - Duration::from_millis(1)));
        assert!(gate.expired(start + AUTH_DEADLINE));

        feed_and_verify(
            &mut gate,
            &encode_auth_record(&AuthRecord {
                public_key: b"key".to_vec(),
                signature: b"good".to_vec(),
                v2: None,
            })
            .expect("encodes"),
        )
        .expect("a good record opens the gate");
        assert!(gate.is_open());
        assert!(
            !gate.expired(start + AUTH_DEADLINE * 100),
            "a proved connection has no deadline left to run out of"
        );
    }

    /// A second record after the proof is ignored, not re-verified: otherwise
    /// anyone able to write on the stream could shut a session that already
    /// authenticated.
    #[test]
    fn a_second_record_cannot_shut_a_proved_gate() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut gate = AuthGate::new(
            Arc::new(FakeVerifier {
                expected: b"good".to_vec(),
                attempts: attempts.clone(),
            }),
            [3u8; 32],
            [0u8; 16],
            Instant::now(),
        );
        feed_and_verify(
            &mut gate,
            &encode_auth_record(&AuthRecord {
                public_key: b"key".to_vec(),
                signature: b"good".to_vec(),
                v2: None,
            })
            .expect("encodes"),
        )
        .unwrap();
        assert!(gate.is_open());
        assert!(feed_and_verify(
            &mut gate,
            &encode_auth_record(&AuthRecord {
                public_key: b"key".to_vec(),
                signature: b"wrong".to_vec(),
                v2: None,
            })
            .expect("encodes"),
        )
        .is_ok());
        assert!(gate.is_open(), "the gate stays open");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the second record never reaches the verifier"
        );
    }

    /// A proof that echoes some other handshake's nonce is refused.
    #[test]
    fn a_record_with_a_foreign_nonce_is_refused() {
        let mut gate = AuthGate::new(accepting_good(), [1u8; 32], [9u8; 16], Instant::now());
        let bytes = encode_auth_record(&AuthRecord {
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            v2: Some(AuthV2 {
                login: "alice".to_string(),
                nonce: [8u8; 16],
            }),
        })
        .expect("encodes");
        assert_eq!(
            feed_and_verify(&mut gate, &bytes),
            Err(AuthError::BadRecord)
        );
        assert!(!gate.is_open());
    }

    /// Everything `run_probation` needs to start, built by driving a real
    /// signature handshake through `Connection::accept` -- the exact path
    /// `begin_probation` takes in production -- so `run_probation` sees the
    /// same shape of `Connection` it would for a genuine client.
    struct Fixture {
        conn: Connection,
        client_key: [u8; 32],
        msg1: Msg1Payload,
        msg1_body: Vec<u8>,
        out: Vec<Datagram>,
        src: SocketAddr,
    }

    /// A [`Fixture`] whose msg2 carries exactly `nonce`, and the client it
    /// accepted -- which has read msg2 and can talk to it.
    fn accepted_signature_pair(nonce: [u8; AUTH_NONCE_LEN]) -> (Connection, Fixture) {
        let server_kp = generate_keypair();
        let client_kp = generate_keypair();
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut client = Connection::new(ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_kp.private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [9u8; 16],
            method: AuthMethod::SshSignature,
        });
        let out = client.start_with_payload(Instant::now(), src, &payload);
        let msg1_body = match parse_wire_frame(&out[0].bytes).expect("valid frame") {
            WireFrame::Handshake { body, .. } => body.to_vec(),
            _ => panic!("expected a handshake datagram"),
        };
        let cfg = ConnectionConfig {
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server_kp.private,
            remote_static_pub: None,
            auth: AuthPolicy::SshSignature,
        };
        match Connection::accept(cfg, Instant::now(), src, &msg1_body, &mut |_| {
            Some(Msg2Inputs {
                resumed: false,
                nonce,
            })
        }) {
            AcceptOutcome::Accepted {
                conn,
                client_key,
                msg1,
                out,
                ..
            } => {
                let _ = client.on_datagram(Instant::now(), src, &out[0].bytes);
                (
                    client,
                    Fixture {
                        conn,
                        client_key,
                        msg1,
                        msg1_body,
                        out,
                        src,
                    },
                )
            }
            AcceptOutcome::Rejected => panic!("accept must succeed for this test fixture"),
        }
    }

    /// Build a [`Fixture`] whose msg2 carries exactly `nonce` -- the same
    /// value the test then looks for in `ProbationEnded.nonce`.
    fn accepted_signature_connection(nonce: [u8; AUTH_NONCE_LEN]) -> Fixture {
        accepted_signature_pair(nonce).1
    }

    /// Spec §4.16 (QSH-01): a connection in probation keeps at most
    /// `PROBATION_UNDELIVERED_MAX` of out-of-order data, however much its
    /// unproven peer sends past a hole.
    #[test]
    fn a_connection_in_probation_keeps_little_out_of_order_data() {
        let (mut client, fixture) = accepted_signature_pair([3u8; AUTH_NONCE_LEN]);
        let mut conn = fixture.conn;
        hold_for_probation(&mut conn);
        let frames: Vec<StreamFrame> = (1..=300u32)
            .map(|k| StreamFrame::Data {
                stream_id: 16,
                offset: k * 1024,
                data: vec![1u8; 1024],
            })
            .collect();
        let now = Instant::now();
        for dg in client.frames_for_test(frames) {
            let _ = conn.on_datagram(now, fixture.src, &dg.bytes);
        }
        let held = conn.undelivered_cost_for_test();
        assert!(held <= PROBATION_UNDELIVERED_MAX, "{held}");
        assert!(
            held > PROBATION_UNDELIVERED_MAX - 2 * 1024,
            "it fills up to the cap: {held}"
        );
    }

    /// Spec §4.10.3: a connection in probation counts its streams
    /// explicitly -- what its peer sent before the proof is taken only when
    /// its backend takes it -- except the proof's own stream, taken as it is
    /// read.
    #[test]
    fn a_connection_in_probation_credits_nothing_but_its_proof() {
        let (mut client, fixture) = accepted_signature_pair([4u8; AUTH_NONCE_LEN]);
        let mut conn = fixture.conn;
        hold_for_probation(&mut conn);
        let now = Instant::now();
        let mut out = client.send(now, 16, &[b'k'; 1000]);
        out.extend(client.send(now, AUTH_STREAM, &[0u8; 300]));
        for dg in out {
            let _ = conn.on_datagram(now, fixture.src, &dg.bytes);
        }
        assert_eq!(conn.unconsumed_streams(), vec![(16, 1000)]);
    }

    /// Spec §4.16: `run_probation` itself holds its connection to the
    /// probation cap -- the connection a proof hands over still has it, for
    /// the bridge that adopts it to lift.
    #[tokio::test]
    async fn run_probation_holds_its_connection_to_the_probation_cap() {
        let nonce = [4u8; AUTH_NONCE_LEN];
        let (mut client, fixture) = accepted_signature_pair(nonce);
        let Fixture {
            mut conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
        } = fixture;
        conn.push_test_event(Event::StreamData {
            stream_id: AUTH_STREAM,
            data: good_record(),
        });
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let (_route, dgram_rx) = dgram_queue();
        tokio::spawn(run_probation(Probation {
            socket,
            conn,
            verifier: accepting_good(),
            dgram_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: test_permits(),
        }));
        let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
            .await
            .expect("the probation ended")
            .expect("and said so");
        let mut proven = ended.proven.expect("the proof verified");
        let frames: Vec<StreamFrame> = (1..=300u32)
            .map(|k| StreamFrame::Data {
                stream_id: 16,
                offset: k * 1024,
                data: vec![1u8; 1024],
            })
            .collect();
        let now = Instant::now();
        for dg in client.frames_for_test(frames) {
            let _ = proven.conn.on_datagram(now, src, &dg.bytes);
        }
        let held = proven.conn.undelivered_cost_for_test();
        assert!(held <= PROBATION_UNDELIVERED_MAX, "{held}");
    }

    /// The clock advances while the future is held between polls. The real
    /// Tokio timer is still pending, so only the queued datagram can wake it:
    /// accepting the proof cannot hide behind a randomly selected timer arm.
    #[tokio::test(start_paused = true)]
    async fn a_ready_proof_at_the_auth_deadline_is_refused() {
        let nonce = [0x36; AUTH_NONCE_LEN];
        let (mut client, fixture) = accepted_signature_pair(nonce);
        let Fixture {
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
        } = fixture;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (route, dgram_rx) = dgram_queue();
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        let clock = std::sync::Mutex::new(Instant::now());
        let now = || *clock.lock().unwrap();
        let p = Probation {
            socket,
            conn,
            verifier: Arc::new(FakeVerifier {
                expected: b"good".to_vec(),
                attempts: Arc::clone(&attempts),
            }),
            dgram_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: test_permits(),
        };
        let mut task = std::pin::pin!(run_probation_with_clock(p, now));
        std::future::poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        for dg in client.send(Instant::now(), AUTH_STREAM, &good_record()) {
            assert!(route.send(src, dg.bytes));
        }
        *clock.lock().unwrap() += AUTH_DEADLINE;
        tokio::time::timeout(Duration::from_secs(1), task.as_mut())
            .await
            .expect("ready input ends probation immediately");
        let ended = ended_rx.recv().await.expect("one outcome");
        assert!(
            ended.proven.is_none(),
            "a queued late proof must be refused"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert_eq!(ended.nonce, nonce);
        assert!(ended_rx.try_recv().is_err());
        assert!(
            !route.send(src, vec![0]),
            "the expired receiver was dropped"
        );
    }

    fn gate_with_record(now: Instant, attempts: &Arc<AtomicUsize>) -> (AuthGate, AuthRecord) {
        let mut gate = AuthGate::new(
            Arc::new(FakeVerifier {
                expected: b"good".to_vec(),
                attempts: Arc::clone(attempts),
            }),
            [0; 32],
            [0; AUTH_NONCE_LEN],
            now,
        );
        let Fed::Verify(record) = gate.feed(&good_record()).unwrap() else {
            panic!("complete proof");
        };
        (gate, record)
    }

    #[tokio::test]
    async fn an_expired_proof_does_not_start_verification() {
        let start = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (mut gate, record) = gate_with_record(start, &attempts);
        let permits = Arc::new(Semaphore::new(1));
        let step = verify_off_task(
            &mut gate,
            record,
            &permits,
            [0; 16],
            "127.0.0.1:1".parse().unwrap(),
            &|| start + AUTH_DEADLINE,
        )
        .await;
        assert!(matches!(step, Step::Refused));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_permit_released_at_the_deadline_cannot_start_verification() {
        let start = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (mut gate, record) = gate_with_record(start, &attempts);
        let permits = Arc::new(Semaphore::new(1));
        let held = permits.clone().acquire_owned().await.unwrap();
        let clock = std::sync::Mutex::new(start);
        let now = || *clock.lock().unwrap();
        let mut task = std::pin::pin!(verify_off_task(
            &mut gate,
            record,
            &permits,
            [0; 16],
            "127.0.0.1:1".parse().unwrap(),
            &now
        ));
        std::future::poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        *clock.lock().unwrap() += AUTH_DEADLINE;
        drop(held);
        assert!(matches!(task.await, Step::Refused));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn verification_permit_wait_is_bounded_by_the_auth_deadline() {
        let start = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (mut gate, record) = gate_with_record(start, &attempts);
        let permits = Arc::new(Semaphore::new(0));
        let remaining = Duration::from_millis(10);
        let clock = std::sync::Mutex::new(start + AUTH_DEADLINE - remaining);
        let now = || *clock.lock().unwrap();
        let mut task = std::pin::pin!(verify_off_task(
            &mut gate,
            record,
            &permits,
            [0; 16],
            "127.0.0.1:1".parse().unwrap(),
            &now
        ));
        std::future::poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        *clock.lock().unwrap() += remaining;
        tokio::time::advance(remaining).await;
        std::future::poll_fn(|cx| {
            assert!(
                matches!(
                    task.as_mut().poll(cx),
                    std::task::Poll::Ready(Step::Refused)
                ),
                "auth expiry bounds the permit wait, even before VERIFY_PERMIT_WAIT"
            );
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_partial_proof_completed_after_the_deadline_is_not_drained() {
        let now = Instant::now();
        let mut gate = AuthGate::new(accepting_good(), [0; 32], [0; AUTH_NONCE_LEN], now);
        let record = good_record();
        let mid = record.len() / 2;
        let mut start = BridgeStart::default();
        let mut cost = 0;
        let mut conn = seeded(vec![data(AUTH_STREAM, &record[..mid])]);
        assert!(matches!(
            drain(&mut conn, &mut gate, &mut start, &mut cost, now),
            Step::Waiting
        ));
        let mut conn = seeded(vec![data(AUTH_STREAM, &record[mid..])]);
        assert!(matches!(
            drain(
                &mut conn,
                &mut gate,
                &mut start,
                &mut cost,
                now + AUTH_DEADLINE
            ),
            Step::Refused
        ));
        assert_eq!(
            gate.pending,
            record[..mid],
            "expired events were not consumed"
        );
        assert!(!gate.verifying);
    }

    #[tokio::test]
    async fn a_timely_proof_still_verifies() {
        let start = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (mut gate, record) = gate_with_record(start, &attempts);
        let permits = Arc::new(Semaphore::new(1));
        let step = verify_off_task(
            &mut gate,
            record,
            &permits,
            [0; 16],
            "127.0.0.1:1".parse().unwrap(),
            &|| start + AUTH_DEADLINE - Duration::from_nanos(1),
        )
        .await;
        assert!(matches!(step, Step::Proved));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(permits.available_permits(), 1);
    }

    struct SignalledVerifier {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        released: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl AuthVerifier for SignalledVerifier {
        fn verify(
            &self,
            _hash: &[u8; 32],
            _record: &AuthRecord,
            _login: [u8; 16],
            _rhost: &str,
        ) -> Result<Principal, AuthError> {
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.released
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .expect("test must release the verifier");
            Ok(Principal {
                uid: 1000,
                name: "test".into(),
                identity: "signalled".into(),
                incarnation: 0,
            })
        }
    }

    #[tokio::test]
    async fn verification_started_before_expiry_may_finish_after_it() {
        let start = Instant::now();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut gate = AuthGate::new(
            Arc::new(SignalledVerifier {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                released: std::sync::Mutex::new(release_rx),
            }),
            [0; 32],
            [0; AUTH_NONCE_LEN],
            start,
        );
        let Fed::Verify(record) = gate.feed(&good_record()).unwrap() else {
            panic!("proof");
        };
        let permits = Arc::new(Semaphore::new(1));
        let clock = std::sync::Mutex::new(start);
        let now = || *clock.lock().unwrap();
        let mut task = std::pin::pin!(verify_off_task(
            &mut gate,
            record,
            &permits,
            [0; 16],
            "127.0.0.1:1".parse().unwrap(),
            &now
        ));
        std::future::poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            permits.available_permits(),
            0,
            "running verification owns its permit"
        );
        *clock.lock().unwrap() += AUTH_DEADLINE;
        release_tx.send(()).unwrap();
        assert!(matches!(task.await, Step::Proved));
        assert_eq!(permits.available_permits(), 1);
    }

    /// A record that parses and that [`accepting_good`] admits.
    fn good_record() -> Vec<u8> {
        encode_auth_record(&AuthRecord {
            public_key: b"key".to_vec(),
            signature: b"good".to_vec(),
            v2: None,
        })
        .expect("encodes")
    }

    /// One probation, with `record` already sitting on its connection's
    /// event queue, spawned.
    ///
    /// `run_probation` drains that queue before it waits on anything, so
    /// the record is seen on the very first pass: no datagram, no timer,
    /// nothing to race. The returned sender is the route, which the caller
    /// holds so that the `dgram_rx` exit -- another test's subject -- cannot
    /// fire and be mistaken for what this one is watching.
    fn spawn_probation_with(
        nonce: [u8; AUTH_NONCE_LEN],
        record: Vec<u8>,
        verifier: Arc<dyn AuthVerifier>,
        permits: Arc<Semaphore>,
        ended_tx: mpsc::UnboundedSender<ProbationEnded>,
        socket: Arc<UdpSocket>,
    ) -> DgramTx {
        let Fixture {
            mut conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
        } = accepted_signature_connection(nonce);
        conn.push_test_event(Event::StreamData {
            stream_id: AUTH_STREAM,
            data: record,
        });
        let (dg_tx, dg_rx) = dgram_queue();
        tokio::spawn(run_probation(Probation {
            socket,
            conn,
            verifier,
            dgram_rx: dg_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: permits,
        }));
        dg_tx
    }

    /// A verifier that blocks inside `verify` until it is let go, counting
    /// both how many calls are inside it at this moment and how many ever
    /// got in at all.
    struct BlockingVerifier {
        inside: Arc<AtomicUsize>,
        attempts: Arc<AtomicUsize>,
        released: Arc<AtomicBool>,
    }

    impl AuthVerifier for BlockingVerifier {
        fn verify(
            &self,
            _handshake_hash: &[u8; 32],
            _record: &AuthRecord,
            _login: [u8; 16],
            _rhost: &str,
        ) -> Result<Principal, AuthError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.inside.fetch_add(1, Ordering::SeqCst);
            // Bounded: a test that never releases must fail on its own
            // assertion, not pin a blocking thread for the rest of the run.
            let deadline = Instant::now() + Duration::from_secs(30);
            while !self.released.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.inside.fetch_sub(1, Ordering::SeqCst);
            Ok(Principal {
                uid: 1000,
                name: "test".to_string(),
                identity: "blocking".to_string(),
                incarnation: 0,
            })
        }
    }

    /// A login that arrives while every permit is taken WAITS for one and is
    /// then verified -- it is not told its key was refused.
    ///
    /// The wait is witnessed positively, and that is the point: for 60 ms after
    /// the fifth arrives, nothing may end. Restore `try_acquire_owned` at the
    /// call site and its refusal lands within microseconds, so that assertion
    /// -- not a timeout, not a hang -- is what fails. The window is far below
    /// VERIFY_PERMIT_WAIT (250 ms), so an honest probation has not given up
    /// inside it even under load.
    #[tokio::test]
    async fn a_login_arriving_with_no_permit_free_waits_and_is_verified() {
        let inside = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        // Not blocking: this test is about the permit, not about the verifier.
        let released = Arc::new(AtomicBool::new(true));
        let verifier: Arc<dyn AuthVerifier> = Arc::new(BlockingVerifier {
            inside: Arc::clone(&inside),
            attempts: Arc::clone(&attempts),
            released,
        });
        let permits = test_permits();
        // Every permit held by the TEST itself, so the wait is not racing any
        // other probation's progress.
        let mut held: Vec<_> = (0..MAX_CONCURRENT_VERIFIES)
            .map(|_| {
                Arc::clone(&permits)
                    .try_acquire_owned()
                    .expect("a free permit")
            })
            .collect();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();

        let waiting_nonce = [0xAAu8; AUTH_NONCE_LEN];
        let _route = spawn_probation_with(
            waiting_nonce,
            good_record(),
            Arc::clone(&verifier),
            Arc::clone(&permits),
            ended_tx.clone(),
            Arc::clone(&socket),
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(60), ended_rx.recv())
                .await
                .is_err(),
            "a login that finds no permit free must WAIT for one; refusing it at once is what a \
             client reads as 'your key was not accepted'"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "it must be waiting for a permit, not verifying without one"
        );

        // One permit comes back, well inside VERIFY_PERMIT_WAIT.
        drop(held.pop().expect("a held permit"));

        let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
            .await
            .expect("the waiting login must be verified once a permit frees")
            .expect("the channel must not close before sending");
        assert_eq!(
            ended.nonce, waiting_nonce,
            "the end must be that probation's own"
        );
        assert!(
            ended.proven.is_some(),
            "a login that waited its turn must then be VERIFIED, not refused"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the freed permit must have carried it into the verifier"
        );
        drop(held);
        let _ = inside;
    }

    /// Verifying is bounded, and over the bound the fifth WAITS for a
    /// permit rather than being refused on the spot: `MAX_CONCURRENT_VERIFIES`
    /// proofs may be in flight at once, and one arriving while they all
    /// still are waits up to `VERIFY_PERMIT_WAIT` for one to free, and is
    /// refused only once that wait, too, comes up empty.
    ///
    /// Two properties, and the first matters most. All four verifications
    /// must be able to be in flight SIMULTANEOUSLY on a current-thread
    /// runtime -- which is possible only because each runs on the blocking
    /// pool rather than on the probation's own task. Called straight from
    /// that task, as it used to be, the first would occupy this runtime's
    /// only thread and the other three would never start; the bounded wait
    /// below then fails, saying so. That is exactly the property the router
    /// task depends on for its own liveness: while a proof is being
    /// verified, the task that reads every live session's datagrams keeps
    /// running.
    ///
    /// The fifth is then refused only once its own wait for a permit runs
    /// out -- while the four still hold every one of them, wedged in the
    /// verifier -- and it never reaches the verifier itself.
    #[tokio::test]
    async fn a_verification_past_the_bound_is_refused_after_a_bounded_wait() {
        let inside = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let verifier: Arc<dyn AuthVerifier> = Arc::new(BlockingVerifier {
            inside: Arc::clone(&inside),
            attempts: Arc::clone(&attempts),
            released: Arc::clone(&released),
        });
        let permits = test_permits();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();

        // The ones that take every permit.
        let _routes: Vec<_> = (0..MAX_CONCURRENT_VERIFIES)
            .map(|i| {
                spawn_probation_with(
                    [i as u8; AUTH_NONCE_LEN],
                    good_record(),
                    Arc::clone(&verifier),
                    Arc::clone(&permits),
                    ended_tx.clone(),
                    Arc::clone(&socket),
                )
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        while inside.load(Ordering::SeqCst) < MAX_CONCURRENT_VERIFIES {
            assert!(
                Instant::now() < deadline,
                "all {MAX_CONCURRENT_VERIFIES} verifications must be able to run at once -- off \
                 the task, or the first would hold this runtime's only thread and the rest would \
                 never start; only {} ever got in",
                inside.load(Ordering::SeqCst)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), ended_rx.recv())
                .await
                .is_err(),
            "none of them may have ended yet: they are all still inside the verifier"
        );

        // One more, with no permit left for it.
        let refused_nonce = [0xEEu8; AUTH_NONCE_LEN];
        let _refused_route = spawn_probation_with(
            refused_nonce,
            good_record(),
            Arc::clone(&verifier),
            Arc::clone(&permits),
            ended_tx.clone(),
            Arc::clone(&socket),
        );
        // Replaces the immediate `timeout(5s, recv)`: the refusal must arrive,
        // and it must arrive on OUR schedule, not the wedged helper's.
        let started = std::time::Instant::now();
        let ended = tokio::time::timeout(VERIFY_PERMIT_WAIT * 4, ended_rx.recv())
            .await
            .expect(
                "with every verifier wedged the fifth must give up at about VERIFY_PERMIT_WAIT and be \
                 refused -- an unbounded wait holds this probation open for as long as the helper is \
                 stuck",
            )
            .expect("the channel must not close before sending");
        let waited = started.elapsed();
        assert!(
            waited >= VERIFY_PERMIT_WAIT,
            "the fifth was refused after only {waited:?}: it must WAIT for a permit first, up to \
             {VERIFY_PERMIT_WAIT:?}"
        );
        assert_eq!(
            ended.nonce, refused_nonce,
            "the refusal must be that probation's own, with its own nonce"
        );
        assert!(
            ended.proven.is_none(),
            "a probation refused for want of a permit is not a proof"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            MAX_CONCURRENT_VERIFIES,
            "the refused probation must never have reached the verifier at all"
        );

        // And the rest still finish, once they are let go.
        released.store(true, Ordering::SeqCst);
        for _ in 0..MAX_CONCURRENT_VERIFIES {
            let ended = tokio::time::timeout(Duration::from_secs(10), ended_rx.recv())
                .await
                .expect("every released verification must finish its own probation")
                .expect("the channel must not close before sending");
            assert!(
                ended.proven.is_some(),
                "a verification that succeeded must prove its probation"
            );
        }
    }

    /// The THIRD `end` call site: the tail of `run_probation`, reached when
    /// the loop stops for anything other than a route that went away or a
    /// deadline that ran out -- here, a client that sends garbage on
    /// `AUTH_STREAM`. It must report the probation's OWN nonce, exactly as
    /// the other two sites do. The manager releases that nonce when a
    /// probation ends unproven, so a wrong value there leaves the real one
    /// sitting in the (Task-7) helper's bounded table, unreleased, for its
    /// whole lifetime -- the cheapest way there is to fill that table and
    /// lock every honest login out.
    #[tokio::test]
    async fn a_probation_refused_for_a_bad_record_reports_its_own_nonce() {
        let nonce = [5u8; AUTH_NONCE_LEN];
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        // Not a record at all: the first byte is a version this parser does
        // not know, which is `BadRecord` at once -- never `Incomplete`,
        // which would leave the gate waiting for more rather than refusing.
        let _route = spawn_probation_with(
            nonce,
            vec![0xFFu8; 8],
            accepting_good(),
            test_permits(),
            ended_tx,
            socket,
        );

        let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
            .await
            .expect("a probation refused for a bad record must end promptly")
            .expect("the channel must not close before sending");
        assert_eq!(
            ended.nonce, nonce,
            "a probation refused for a bad record must report the nonce IT was started with"
        );
        assert!(
            ended.proven.is_none(),
            "garbage on the authentication stream is a refusal, not a proof"
        );
    }

    /// N1 (fix-2 review): a probation whose route the manager drops (the
    /// worker shut down, or this entry was superseded) must report ITS OWN
    /// nonce in `ProbationEnded`, not some other value -- this is the
    /// `dgram_rx.recv() => None` exit, the FIRST of the two `end(.., nonce,
    /// None)` call sites. Getting this wrong leaks the real nonce in the
    /// (Task-7) helper's table for its full 30s lifetime, unreleased.
    #[tokio::test]
    async fn a_probation_whose_route_is_dropped_reports_its_own_nonce() {
        let nonce = [7u8; AUTH_NONCE_LEN];
        let Fixture {
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
        } = accepted_signature_connection(nonce);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (dg_tx, dg_rx) = dgram_queue();
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();

        // Dropped BEFORE the task ever polls it, so `dgram_rx.recv()`
        // resolves to `None` on the very first iteration -- no real waiting
        // needed, unlike the deadline exit below.
        drop(dg_tx);

        tokio::spawn(run_probation(Probation {
            socket,
            conn,
            verifier: accepting_good(),
            dgram_rx: dg_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: test_permits(),
        }));

        let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
            .await
            .expect("the probation must end promptly once its route is gone")
            .expect("the channel must not close before sending");
        assert_eq!(
            ended.nonce, nonce,
            "a dropped-route probation must report the nonce IT was started with"
        );
        assert!(
            ended.proven.is_none(),
            "a dropped route is a refusal, not a proof"
        );
    }

    /// N1 (fix-2 review): a probation that times out waiting for a record
    /// must ALSO report its own nonce -- the SECOND `end(.., nonce, None)`
    /// call site, reached when [`AuthGate::expired`] trips.
    ///
    /// Real time, not tokio's pausable clock: the gate's deadline is a
    /// `std::time::Instant` (see `AuthGate::new`), which `tokio::time::advance`
    /// cannot move -- same reasoning as
    /// `a_silent_peer_is_dropped_when_the_deadline_passes` in
    /// `session_manager.rs`.
    #[tokio::test]
    async fn a_probation_that_times_out_reports_its_own_nonce() {
        let nonce = [8u8; AUTH_NONCE_LEN];
        let Fixture {
            conn,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
        } = accepted_signature_connection(nonce);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // Kept ALIVE (never sent on, never dropped until after the
        // assertion): dropping it would let the route-dropped exit above
        // win instead of the deadline this test means to reach.
        let (dg_tx, dg_rx) = dgram_queue();
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();

        tokio::spawn(run_probation(Probation {
            socket,
            conn,
            verifier: accepting_good(),
            dgram_rx: dg_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: test_permits(),
        }));

        let ended = tokio::time::timeout(AUTH_DEADLINE + Duration::from_secs(2), ended_rx.recv())
            .await
            .expect("the probation must end within the deadline plus slack")
            .expect("the channel must not close before sending");
        assert_eq!(
            ended.nonce, nonce,
            "a timed-out probation must report the nonce IT was started with"
        );
        assert!(
            ended.proven.is_none(),
            "a timeout is a refusal, not a proof"
        );

        drop(dg_tx);
    }

    /// Spec §4.5 (defect 5): datagrams that arrive while the proof is out
    /// being verified stay queued, and the queue goes with the proven
    /// connection instead of being dropped with the task.
    #[tokio::test]
    async fn datagrams_queued_during_verification_go_with_the_proven_session() {
        let inside = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let verifier: Arc<dyn AuthVerifier> = Arc::new(BlockingVerifier {
            inside: Arc::clone(&inside),
            attempts: Arc::new(AtomicUsize::new(0)),
            released: Arc::clone(&released),
        });
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<ProbationEnded>();
        let route = spawn_probation_with(
            [0x55u8; AUTH_NONCE_LEN],
            good_record(),
            verifier,
            test_permits(),
            ended_tx,
            socket,
        );
        // Once the proof is inside the verifier the task reads nothing.
        let deadline = Instant::now() + Duration::from_secs(5);
        while inside.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the proof never reached the verifier"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let from: SocketAddr = "127.0.0.1:2".parse().unwrap();
        assert!(
            route.send(from, b"queued while verifying".to_vec()),
            "the route is open"
        );
        released.store(true, Ordering::SeqCst);
        let ended = tokio::time::timeout(Duration::from_secs(5), ended_rx.recv())
            .await
            .expect("the probation ended")
            .expect("and said so");
        let mut proven = ended.proven.expect("the proof verified");
        assert_eq!(
            proven
                .dgram_rx
                .try_recv()
                .expect("the queued datagram came along"),
            (from, b"queued while verifying".to_vec())
        );
    }

    /// Final review C1, ruling R15, in the shape of the review's probe: an
    /// unproven peer with credits negotiated sends a `Reset` on every
    /// stream number, lets the timers run, then PINGs -- from its own
    /// address and from a spoofed one the connection follows. Before the
    /// fix the Resets drew 512 datagrams at once and 774 repeats over
    /// 10 s, and each 39-byte PING drew 257 datagrams (10 279 bytes), all
    /// of them to the spoofed address when it was the source. Now the
    /// Resets draw nothing and each PING draws its PONG alone.
    #[test]
    fn resets_and_pings_in_probation_draw_no_more_than_a_pong() {
        let (mut client, fixture) = accepted_signature_pair([5u8; AUTH_NONCE_LEN]);
        let mut conn = fixture.conn;
        hold_for_probation(&mut conn);
        assert!(conn.features().contains(crate::Features::STREAM_CREDIT));
        let mut now = Instant::now();
        let resets: Vec<StreamFrame> = (0..=255u8)
            .map(|stream_id| StreamFrame::Reset {
                stream_id,
                new_offset: 1,
            })
            .collect();
        let mut drawn = 0;
        for dg in client.frames_for_test(resets) {
            drawn += conn.on_datagram(now, fixture.src, &dg.bytes).len();
        }
        assert_eq!(drawn, 0, "the Resets draw nothing");
        let is_credit = |f: &StreamFrame| matches!(f, StreamFrame::Credit { .. });
        let mut credits = 0;
        for _ in 0..50 {
            now += Duration::from_millis(200);
            let out = conn.on_timeout_if_due(now);
            credits += out
                .iter()
                .filter_map(|d| client.peek_frames(&d.bytes))
                .flatten()
                .filter(is_credit)
                .count();
        }
        assert_eq!(credits, 0, "no CREDIT repeats over 10 s");
        let victim: SocketAddr = "192.0.2.7:9".parse().unwrap();
        for round in 0..3u32 {
            let ping = client.frames_for_test(vec![StreamFrame::Ping { token: 77 + round }]);
            let from = if round == 0 { fixture.src } else { victim };
            let answers = conn.on_datagram(now, from, &ping[0].bytes);
            let frames: Vec<StreamFrame> = answers
                .iter()
                .filter_map(|d| client.peek_frames(&d.bytes))
                .flatten()
                .collect();
            assert_eq!(
                frames,
                vec![StreamFrame::Pong { token: 77 + round }],
                "round {round}: the PONG alone"
            );
            assert_eq!(answers.len(), 1, "round {round}: one datagram");
        }
    }

    /// Ruling R16 (spec §4.11): a datagram is answered once, whatever it
    /// packs. Answers used to be built frame by frame: one 1 384-byte
    /// datagram of 270 PINGs from a peer in probation drew 270 PONG
    /// datagrams to the forged source it moved the session to, 270
    /// PathProbes as many PathProbeAcks, 160 empty DATA frames 160 ACKs
    /// (final re-review of slice 4, N1).
    #[test]
    fn one_probation_datagram_draws_one_answer_whatever_it_packs() {
        let (mut client, fixture) = accepted_signature_pair([5u8; AUTH_NONCE_LEN]);
        let mut conn = fixture.conn;
        hold_for_probation(&mut conn);
        let now = Instant::now();
        let victim: SocketAddr = "192.0.2.7:9".parse().unwrap();
        let prober: SocketAddr = "192.0.2.8:9".parse().unwrap();
        let read = |client: &Connection, out: &[Datagram]| -> Vec<StreamFrame> {
            out.iter()
                .filter_map(|d| client.peek_frames(&d.bytes))
                .flatten()
                .collect()
        };
        // 270 PINGs from a forged source: one PONG, for the last, to it.
        let dg = client.packed_for_test(
            (0..270u32)
                .map(|token| StreamFrame::Ping { token })
                .collect(),
        );
        let out = conn.on_datagram(now, victim, &dg.bytes);
        assert_eq!(out.len(), 1, "one datagram");
        assert_eq!(out[0].to, victim);
        assert_eq!(read(&client, &out), vec![StreamFrame::Pong { token: 269 }]);
        // 270 PathProbes: one answer, alone, to the datagram's own source.
        let dg = client.packed_for_test(
            (0..270u32)
                .map(|token| StreamFrame::PathProbe { token })
                .collect(),
        );
        let out = conn.on_datagram(now, prober, &dg.bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, prober);
        assert_eq!(
            read(&client, &out),
            vec![StreamFrame::PathProbeAck { token: 269 }]
        );
        // 160 empty DATA frames on one stream: one ACK.
        let dg = client.packed_for_test(
            (0..160)
                .map(|_| StreamFrame::Data {
                    stream_id: 40,
                    offset: 0,
                    data: Vec::new(),
                })
                .collect(),
        );
        let out = conn.on_datagram(now, victim, &dg.bytes);
        assert_eq!(out.len(), 1);
        assert_eq!(
            read(&client, &out),
            vec![StreamFrame::Ack {
                stream_id: 40,
                cum_ack: 0
            }]
        );
        // 160 on 160 streams: an ACK each, packed into one datagram no
        // larger than the one that drew them.
        let dg = client.packed_for_test(
            (0..160u8)
                .map(|i| StreamFrame::Data {
                    stream_id: 50 + i,
                    offset: 0,
                    data: Vec::new(),
                })
                .collect(),
        );
        let out = conn.on_datagram(now, victim, &dg.bytes);
        assert_eq!(out.len(), 1, "160 six-byte ACKs fit one datagram");
        let frames = read(&client, &out);
        assert_eq!(frames.len(), 160);
        assert!(frames.iter().all(|f| matches!(f, StreamFrame::Ack { .. })));
        assert!(out[0].bytes.len() <= dg.bytes.len());
        // Everything in one datagram: one answer to the peer, one to the
        // source, no more bytes than came plus one datagram's overhead.
        let mut mixed: Vec<StreamFrame> = (0..90u32)
            .map(|token| StreamFrame::Ping { token })
            .collect();
        mixed.extend((0..90u32).map(|token| StreamFrame::PathProbe { token }));
        mixed.extend((0..90u8).map(|i| StreamFrame::Data {
            stream_id: 100 + i,
            offset: 0,
            data: Vec::new(),
        }));
        let dg = client.packed_for_test(mixed);
        let out = conn.on_datagram(now, victim, &dg.bytes);
        assert_eq!(
            out.len(),
            2,
            "one answer to the peer, one to the source: {out:?}"
        );
        let probe_answers = out
            .iter()
            .filter(|d| {
                read(&client, std::slice::from_ref(*d))
                    == vec![StreamFrame::PathProbeAck { token: 89 }]
            })
            .count();
        assert_eq!(probe_answers, 1, "the check's answer travels alone");
        let drawn: usize = out.iter().map(|d| d.bytes.len()).sum();
        assert!(
            drawn <= dg.bytes.len() + TRANSPORT_OVERHEAD,
            "{drawn} bytes drawn by {}",
            dg.bytes.len()
        );
    }

    /// Spec §4.11 in probation: in-order DATA from an unproven peer draws
    /// one ACK datagram per `ACK_EVERY` frames, never one each.
    #[test]
    fn in_order_data_in_probation_draw_an_ack_per_four() {
        let (mut client, fixture) = accepted_signature_pair([5u8; AUTH_NONCE_LEN]);
        let mut conn = fixture.conn;
        hold_for_probation(&mut conn);
        let now = Instant::now();
        let mut drawn = 0;
        for i in 0..100u32 {
            let dg = client.frames_for_test(vec![StreamFrame::Data {
                stream_id: 40,
                offset: i * 10,
                data: vec![1u8; 10],
            }]);
            drawn += conn.on_datagram(now, fixture.src, &dg[0].bytes).len();
        }
        assert_eq!(drawn, 25);
    }

    /// One datagram's header and tag: what a second answer datagram costs.
    const TRANSPORT_OVERHEAD: usize = crate::wire::TRANSPORT_HEADER_LEN + crate::wire::AEAD_TAG_LEN;
}
