//! Making the connection, and working out what happened when it does not
//! work.
//!
//! A validated server acknowledgement establishes admission for this exact
//! transport. Refused proofs stay silent: a closed connection or the bounded
//! acceptance timeout can decide failure, but neither Live, arbitrary DATA nor
//! elapsed time establishes success. The pure verdict below also preserves
//! authenticated protocol failures ahead of unauthenticated network errors.

use crate::port_probe::{PortProbe, ProbeResult};
use ::connect::recovery_gate::RecoveryEpoch;
use std::collections::BTreeMap;
use std::net::SocketAddr;
#[cfg(test)]
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use transport::driver_std::{
    Binder, ClientEvents, DriverSetup, RecoveryProgress, SendFailure, StdClient,
};
use transport::{LinkState, Stats};

/// Failure budget for explicit server acceptance. Elapsed time never proves success.
const AUTH_ACCEPTANCE_TIMEOUT_MS: i64 = transport::AUTH_ACCEPTANCE_TIMEOUT.as_millis() as i64;

/// How long to wait for the handshake to complete AT ALL before giving up on
/// this address: `transport::HANDSHAKE_GIVE_UP_AFTER`, shared with the app.
/// Without a deadline `attempt_verdict` would report `StillTrying` forever
/// and the CLI would hang with no output.
const UNREACHABLE_AFTER_MS: i64 = transport::HANDSHAKE_GIVE_UP_AFTER.as_millis() as i64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// The server explicitly accepted this exact transport admission.
    Working,
    /// Authenticated protocol rejection; another key cannot repair it.
    ProtocolFailure(transport::ProtocolFailure),
    /// Authenticated terminal server abort; never try another key or fallback.
    SessionAborted(transport::SessionAbortReason),
    /// No acceptance arrived after the handshake before closure or the failure
    /// budget. Worth trying the next key; silence cannot prove why it failed.
    AuthRefused,
    /// Never got as far as a handshake. Another key will not help. Carries
    /// how the latest send failed, when it did: the one thing the client
    /// saw beyond silence.
    Unreachable(Option<SendFailure>),
    /// Not enough has happened to say.
    StillTrying,
}

/// Only a validated acceptance record establishes authentication. Link state and
/// elapsed budgets distinguish refusal/unreachability, never infer success.
pub fn attempt_verdict(
    reached_live: bool,
    accepted: Option<transport::AuthAcceptance>,
    closed: bool,
    elapsed_ms: i64,
    send_error: Option<SendFailure>,
) -> Verdict {
    if accepted.is_some() {
        return Verdict::Working;
    }
    if closed {
        return if reached_live {
            Verdict::AuthRefused
        } else {
            Verdict::Unreachable(send_error)
        };
    }
    if reached_live {
        return if elapsed_ms >= AUTH_ACCEPTANCE_TIMEOUT_MS {
            Verdict::AuthRefused
        } else {
            Verdict::StillTrying
        };
    }
    if elapsed_ms >= UNREACHABLE_AFTER_MS {
        return Verdict::Unreachable(send_error);
    }
    Verdict::StillTrying
}

/// The verbose log's line about what the transport agreed with the daemon
/// (spec §5.5). `NONE` from a daemon built before negotiation; `None` when
/// no handshake completed.
pub fn features_line(features: Option<transport::Features>) -> String {
    match features {
        None => "transport features: unknown (no handshake)".to_string(),
        Some(f) if f.is_empty() => {
            "transport features: none (peer predates negotiation)".to_string()
        }
        Some(f) => format!("transport features: {}", f.describe()),
    }
}

/// How much a console client lets wait between its driver and its terminal
/// against a daemon without credits (spec §4.13): past it the driver thread
/// waits for the terminal -- the pressure a slow terminal always put on the
/// daemon, now with a bound on memory. With credits the daemon sends no more
/// than a window past what the terminal took, and nothing waits here.
pub const UNCREDITED_QUEUE_MAX: usize = 1024 * 1024;

/// Prefer IPv4 when the daemon binds IPv4 only; see `sshauth::addr::preferred_addr`.
pub use sshauth::addr::preferred_addr;

/// Use the operating system's default route without binding to a network.
pub struct NoopBinder;

impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

/// Bridges the driver's callbacks into the main loop's channel, and keeps the
/// facts the verdict needs.
pub struct Events {
    pub tx: Sender<crate::session::UiEvent>,
    pub reached_live: AtomicBool,
    /// First completed handshake; later path recovery must not renew this budget.
    first_live_at: std::sync::OnceLock<std::time::Instant>,
    pub closed: AtomicBool,
    acceptance: Mutex<Option<transport::AuthAcceptance>>,
    /// Whether the connection runs with stream credits (spec §4.13).
    credits: AtomicBool,
    protocol_failure: Mutex<Option<transport::ProtocolFailure>>,
    session_abort: Mutex<Option<transport::SessionAbortReason>>,
    /// Bytes handed to the main loop and not written to the terminal yet.
    queued: Mutex<usize>,
    room: Condvar,
    /// Nothing takes from the queue any more: a waiting delivery returns.
    released: AtomicBool,
    recovery_progress: Option<Arc<dyn Fn(RecoveryProgress) + Send + Sync>>,
}

impl Events {
    pub fn new(tx: Sender<crate::session::UiEvent>) -> Events {
        Events {
            tx,
            reached_live: AtomicBool::new(false),
            first_live_at: std::sync::OnceLock::new(),
            closed: AtomicBool::new(false),
            acceptance: Mutex::new(None),
            credits: AtomicBool::new(false),
            protocol_failure: Mutex::new(None),
            session_abort: Mutex::new(None),
            queued: Mutex::new(0),
            room: Condvar::new(),
            released: AtomicBool::new(false),
            recovery_progress: None,
        }
    }

    /// The main loop wrote `n` bytes of what arrived to the terminal.
    pub fn took(&self, n: usize) {
        let mut queued = self.queued.lock().expect("queue count");
        *queued = queued.saturating_sub(n);
        self.room.notify_all();
    }

    /// Nothing takes from the queue any more: wake a waiting delivery for
    /// good. Call before `StdClient::close`, which joins the driver thread
    /// such a delivery holds.
    pub fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let _queued = self.queued.lock().expect("queue count");
        self.room.notify_all();
    }
}

impl ClientEvents for Events {
    fn on_recovery_progress(&self, progress: RecoveryProgress) {
        if let Some(observer) = &self.recovery_progress {
            observer(progress);
        }
    }

    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        {
            let mut queued = self.queued.lock().expect("queue count");
            while !self.credits.load(Ordering::SeqCst)
                && *queued > UNCREDITED_QUEUE_MAX
                && !self.released.load(Ordering::SeqCst)
            {
                queued = self.room.wait(queued).expect("queue count");
            }
            *queued += data.len();
        }
        let _ = self.tx.send(crate::session::UiEvent::Wire {
            stream: stream_id,
            bytes: data,
        });
    }

    fn on_auth_accepted(&self, accepted: transport::AuthAcceptance) {
        if !self.released.load(Ordering::SeqCst) {
            self.acceptance
                .lock()
                .expect("authentication acceptance")
                .get_or_insert(accepted);
        }
    }

    fn on_protocol_failure(&self, failure: transport::ProtocolFailure) {
        self.protocol_failure
            .lock()
            .expect("protocol failure")
            .get_or_insert(failure);
    }

    fn on_session_aborted(&self, reason: transport::SessionAbortReason) {
        if self.released.load(Ordering::SeqCst) {
            return;
        }
        let mut saved = self.session_abort.lock().expect("session abort");
        if saved.is_some() {
            return;
        }
        *saved = Some(reason);
        drop(saved);
        let _ = self
            .tx
            .send(crate::session::UiEvent::SessionAborted(reason));
    }

    fn on_features(&self, features: transport::Features) {
        self.credits.store(
            features.contains(transport::Features::STREAM_CREDIT),
            Ordering::SeqCst,
        );
    }

    fn on_state(&self, state: LinkState) {
        match state {
            LinkState::Live => {
                self.first_live_at.get_or_init(std::time::Instant::now);
                self.reached_live.store(true, Ordering::SeqCst);
            }
            LinkState::PathDown => {}
            LinkState::Closed => {
                self.closed.store(true, Ordering::SeqCst);
            }
            LinkState::Connecting => {}
        }
        let _ = self.tx.send(crate::session::UiEvent::Link(state));
    }

    fn on_stats(&self, stats: Stats) {
        let _ = self.tx.send(crate::session::UiEvent::Stats(stats));
    }

    fn on_reset(&self, stream_id: u8) {
        let _ = self.tx.send(crate::session::UiEvent::WireReset(stream_id));
    }

    // Once per change of the error (the transport's promise), so a
    // retransmit failing every half second leaves one line, not dozens.
    fn on_send_error(&self, to: SocketAddr, _kind: std::io::ErrorKind, text: &str) {
        crate::log::warn(&send_error_line(to, text));
    }
}

/// The log's line about a send the OS refused. No `qsh: ` prefix: the
/// record's header already names the component.
fn send_error_line(to: SocketAddr, text: &str) -> String {
    format!("a send to {to} failed: {text}")
}

pub(crate) fn abort_code(reason: transport::SessionAbortReason) -> u8 {
    match reason {
        transport::SessionAbortReason::ResourceExhausted => 1,
        transport::SessionAbortReason::Unknown(code) => code,
    }
}

pub fn abort_line_code(reason: u8) -> String {
    abort_line(match reason {
        1 => transport::SessionAbortReason::ResourceExhausted,
        other => transport::SessionAbortReason::Unknown(other),
    })
}

pub(crate) fn abort_line(reason: transport::SessionAbortReason) -> String {
    match reason {
        transport::SessionAbortReason::ResourceExhausted => {
            "The server ended the session because its resource limit was reached.".into()
        }
        transport::SessionAbortReason::Unknown(code) => {
            format!("The server ended the session (unknown reason {code}).")
        }
    }
}

/// What one batch of the main loop handed to the terminal, by stream (spec
/// §4.13): reported once per stream per batch, not once per delivery -- an
/// 8 MB flood is thousands of deliveries.
#[derive(Debug, Default)]
pub struct Taken {
    by_stream: BTreeMap<u8, usize>,
}

impl Taken {
    /// `n` bytes of `stream` reached the terminal.
    pub fn add(&mut self, stream: u8, n: usize) {
        *self.by_stream.entry(stream).or_default() += n;
    }

    /// Everything added since the last drain, one entry per stream, and
    /// nothing any more: each byte is reported exactly once.
    pub fn drain(&mut self) -> Vec<(u8, usize)> {
        std::mem::take(&mut self.by_stream).into_iter().collect()
    }
}

/// A connection attempt that has not yet been judged.
///
/// A caller trying several candidates in turn must close (`Attempt::close`)
/// and drain this attempt's events before opening the next one: two attempts
/// live against the same server at once share nothing to tell their events
/// apart by, so the wrong attempt's `Events` would end up mutated.
pub struct Attempt {
    /// `Arc`-wrapped (per `StdClient`'s own doc: every method takes `&self`
    /// precisely so it can be shared this way) so a caller building a
    /// channel session's substrate around it -- see `climb::settle_opening`
    /// -- can clone a handle into that substrate's sink closure without
    /// borrowing `Attempt` itself: the closure has to outlive this value
    /// being moved into the caller's own state once the attempt succeeds.
    pub client: Arc<StdClient>,
    pub events: Arc<Events>,
    started: std::time::Instant,
    refusal_probe: Mutex<Option<PortProbe>>,
}

/// How an attempt proves who it is.
pub enum Login {
    /// Step 1: sign with an SSH key (`AuthPolicy::SshSignature`).
    Signature(Arc<dyn transport::AuthSigner>),
    /// Step 3: the process key is on the daemon's list (`AuthPolicy::Allowlist(vec![])`, no signer).
    Allowlist,
}

/// The policy and signer an attempt runs with. On the client side the list
/// is empty: it is the daemon's list that matters, and this client's own
/// Noise key is what is on it (spec §4.2).
pub fn auth_for(
    login: &Login,
) -> (
    transport::AuthPolicy,
    Option<Arc<dyn transport::AuthSigner>>,
) {
    match login {
        Login::Signature(signer) => (
            transport::AuthPolicy::SshSignature,
            Some(Arc::clone(signer)),
        ),
        Login::Allowlist => (transport::AuthPolicy::Allowlist(Vec::new()), None),
    }
}

enum AttemptTarget {
    Single(SocketAddr),
    Shared(Vec<transport::recovery_handshake::RecoveryEndpoint>),
}

impl Attempt {
    /// Opens a connection that logs in the way `login` says.
    ///
    /// `local_priv` is the process's one Noise static key (spec §4.2): every
    /// attempt of this run uses it, and its public half is what step 2 hands
    /// the daemon with `--client-pubkey`, so step 3 is let in by the
    /// daemon's list without a signature. It is fresh per launch; under
    /// the signature policy it proves nothing by itself.
    pub fn open(
        addr: SocketAddr,
        server_pub: [u8; 32],
        local_priv: [u8; 32],
        login: Login,
        tx: Sender<crate::session::UiEvent>,
        token: [u8; 16],
    ) -> Attempt {
        Self::open_target(
            AttemptTarget::Single(addr),
            server_pub,
            local_priv,
            login,
            tx,
            token,
            None,
        )
    }

    /// One transcript for the complete physical recovery catalog. Progress is
    /// actual socket/Noise evidence, never a substitute for AuthAccepted.
    pub fn open_recovery(
        endpoints: Vec<transport::recovery_handshake::RecoveryEndpoint>,
        server_pub: [u8; 32],
        local_priv: [u8; 32],
        login: Login,
        tx: Sender<crate::session::UiEvent>,
        token: [u8; 16],
        progress: Arc<dyn Fn(RecoveryProgress) + Send + Sync>,
    ) -> Attempt {
        Self::open_target(
            AttemptTarget::Shared(endpoints),
            server_pub,
            local_priv,
            login,
            tx,
            token,
            Some(progress),
        )
    }

    fn open_target(
        target: AttemptTarget,
        server_pub: [u8; 32],
        local_priv: [u8; 32],
        login: Login,
        tx: Sender<crate::session::UiEvent>,
        token: [u8; 16],
        progress: Option<Arc<dyn Fn(RecoveryProgress) + Send + Sync>>,
    ) -> Attempt {
        let (auth, signer) = auth_for(&login);
        let mut events = Events::new(tx);
        events.recovery_progress = progress;
        let events = Arc::new(events);
        // The token identifies the SESSION, not this connection: it comes
        // from the caller's session store, so a later run of `qsh` returns to
        // the shell this one leaves behind rather than starting another.
        let config = transport::ConnectionConfig {
            required_features: transport::Features::CHANNEL_GEOMETRY
                | transport::Features::AUTH_ACCEPTED,
            features: transport::Features::SUPPORTED,
            role: transport::Role::Client,
            local_static_priv: local_priv,
            remote_static_pub: Some(server_pub),
            auth,
        };
        // Always warm: the server answers an unknown token with a fresh
        // session and no complaint, so asking to resume costs nothing
        // when there is nothing to resume -- and asking cold would
        // REPLACE a session that is still there, which is precisely the
        // one we came back for.
        // Spec §4.13: a channel's bytes count as taken when they reach
        // the terminal (reported by `interactive`); the control stream
        // and the proof's stream on delivery.
        let setup = DriverSetup {
            default_consumption: transport::Consumption::Explicit,
            stream_consumption: vec![
                (
                    transport::channel::CONTROL_STREAM,
                    transport::Consumption::OnDelivery,
                ),
                (transport::AUTH_STREAM, transport::Consumption::OnDelivery),
            ],
        };
        let client = Arc::new(match target {
            AttemptTarget::Single(addr) => StdClient::connect_with(
                addr,
                config,
                token,
                transport::StartKind::Warm,
                Arc::new(NoopBinder),
                events.clone(),
                signer,
                setup,
            ),
            AttemptTarget::Shared(endpoints) => StdClient::connect_recovery_with(
                endpoints,
                config,
                token,
                transport::StartKind::Warm,
                Arc::new(NoopBinder),
                events.clone(),
                signer,
                setup,
            ),
        });
        Attempt {
            client,
            events,
            started: std::time::Instant::now(),
            refusal_probe: Mutex::new(None),
        }
    }

    /// Best-effort refusal hint alongside the real handshake. The transport's
    /// main socket stays unconnected so authenticated alternative paths work.
    pub fn probe_port_refusal(&self, addr: SocketAddr) {
        self.probe_port_refusal_stamped(
            addr,
            RecoveryEpoch {
                connection: 0,
                network: 0,
            },
            0,
        );
    }

    pub fn probe_port_refusal_stamped(&self, addr: SocketAddr, epoch: RecoveryEpoch, attempt: u64) {
        *self.refusal_probe.lock().expect("refusal probe mutex") =
            PortProbe::start(addr, epoch, attempt).ok();
    }

    fn port_refusal(&self) -> Option<SendFailure> {
        let mut probe = self.refusal_probe.lock().expect("refusal probe mutex");
        if self.events.reached_live.load(Ordering::SeqCst) {
            *probe = None;
            return None;
        }
        match probe.as_mut()?.poll() {
            ProbeResult::Pending => None,
            result => {
                *probe = None;
                if matches!(result, ProbeResult::Refused { .. }) {
                    let error = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
                    Some((error.kind(), error.to_string()))
                } else {
                    None
                }
            }
        }
    }

    /// Reports what reached the terminal (spec §4.13): one `consumed` per
    /// stream, so the credit windows move on, and one `took` for all of it,
    /// so the queue the driver fills shrinks.
    pub fn report_taken(&self, taken: &mut Taken) {
        let mut total = 0;
        for (stream, n) in taken.drain() {
            self.client.consumed(stream, n);
            total += n;
        }
        if total > 0 {
            self.events.took(total);
        }
    }

    /// Ends the connection: releases a delivery that may be waiting for room
    /// in the queue, then closes -- `StdClient::close` joins the driver
    /// thread such a delivery holds, and nothing takes from the queue any
    /// more.
    pub fn close(&self) {
        self.events.release();
        self.client.close();
    }

    /// Lets the connection go without a `Close`: like [`Attempt::close`],
    /// but the server keeps the session -- a reconnect is coming back to it.
    pub fn detach(&self) {
        self.events.release();
        self.client.detach();
    }

    /// The committed admission outcome, distinct from msg2's tentative resume hint.
    pub fn acceptance(&self) -> Option<transport::AuthAcceptance> {
        *self
            .events
            .acceptance
            .lock()
            .expect("authentication acceptance")
    }

    pub fn verdict(&self) -> Verdict {
        if let Some(failure) = *self
            .events
            .protocol_failure
            .lock()
            .expect("protocol failure")
        {
            return Verdict::ProtocolFailure(failure);
        }
        if let Some(reason) = *self.events.session_abort.lock().expect("session abort") {
            return Verdict::SessionAborted(reason);
        }
        let refused = self.port_refusal();
        let reached_live = self.events.reached_live.load(Ordering::SeqCst);
        // Authenticated progress takes precedence over an unauthenticated
        // network error, including a handshake racing with the probe.
        if !reached_live && self.acceptance().is_none() {
            if let Some(error) = refused {
                return Verdict::Unreachable(Some(error));
            }
        }
        // A late handshake has not yet had time to produce its proof or receive
        // acceptance. Count that phase from its first Live, not from msg1; path
        // recovery cannot extend it because first_live_at is written only once.
        let phase_started = if reached_live {
            self.events
                .first_live_at
                .get()
                .copied()
                .unwrap_or(self.started)
        } else {
            self.started
        };
        attempt_verdict(
            reached_live,
            self.acceptance(),
            self.events.closed.load(Ordering::SeqCst),
            phase_started.elapsed().as_millis() as i64,
            self.client.last_send_error(),
        )
    }

    /// Waits until the attempt is decided, or the wait runs out.
    pub fn settle(&self) -> Verdict {
        self.settle_with(|| {})
    }

    /// Invoke application startup once explicit authentication acceptance arrives.
    pub fn settle_with(&self, on_accepted: impl FnMut()) -> Verdict {
        self.settle_until(on_accepted, || false)
    }

    /// Recovery can stop a stale attempt when SSH supplies a new port or
    /// authorization. The owner still detaches it before starting another.
    pub fn settle_until(
        &self,
        mut on_accepted: impl FnMut(),
        interrupted: impl Fn() -> bool,
    ) -> Verdict {
        loop {
            if interrupted() {
                return Verdict::Unreachable(None);
            }
            let v = self.verdict();
            if v == Verdict::Working {
                on_accepted();
            }
            if v != Verdict::StillTrying {
                return v;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration as StdDuration;

    fn events() -> (
        Arc<Events>,
        std::sync::mpsc::Receiver<crate::session::UiEvent>,
    ) {
        let (tx, rx) = channel();
        (Arc::new(Events::new(tx)), rx)
    }

    fn test_acceptance() -> transport::AuthAcceptance {
        transport::AuthAcceptance {
            session_id: 17,
            disposition: transport::SessionDisposition::Fresh,
        }
    }

    fn unstarted_attempt() -> Attempt {
        let (events, _rx) = events();
        Attempt {
            client: Arc::new(StdClient::dead()),
            events,
            started: std::time::Instant::now(),
            refusal_probe: Mutex::new(None),
        }
    }

    #[test]
    fn authenticated_protocol_failure_is_a_terminal_attempt_verdict() {
        let attempt = unstarted_attempt();
        attempt
            .events
            .on_protocol_failure(transport::ProtocolFailure::MissingRequiredFeatures {
                required: transport::Features::CHANNEL_GEOMETRY,
                enabled: transport::Features::NONE,
            });
        attempt.events.on_state(LinkState::Closed);
        assert_eq!(
            attempt.verdict(),
            Verdict::ProtocolFailure(transport::ProtocolFailure::MissingRequiredFeatures {
                required: transport::Features::CHANNEL_GEOMETRY,
                enabled: transport::Features::NONE
            })
        );
        assert!(!attempt.events.reached_live.load(Ordering::SeqCst));
    }

    #[test]
    fn refusal_probe_keeps_the_deadline_for_a_silent_peer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut attempt = unstarted_attempt();
        attempt.probe_port_refusal(server.local_addr().unwrap());
        assert_eq!(attempt.verdict(), Verdict::StillTrying);
        attempt.started -= Duration::from_millis(UNREACHABLE_AFTER_MS as u64);
        assert_eq!(attempt.verdict(), Verdict::Unreachable(None));
    }

    #[test]
    fn refusal_probe_does_not_trust_a_key_offer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let attempt = unstarted_attempt();
        attempt.probe_port_refusal(server.local_addr().unwrap());
        let mut buf = [0; 256];
        let (_, peer) = server.recv_from(&mut buf).unwrap();
        server
            .send_to(
                &transport::wire::encode_handshake(
                    transport::wire::Kind::KeyOffer,
                    &transport::wire::encode_key_offer_body(&[99; 32]),
                ),
                peer,
            )
            .unwrap();
        assert_eq!(attempt.verdict(), Verdict::StillTrying);
        assert!(!attempt.events.reached_live.load(Ordering::SeqCst));
    }

    #[test]
    fn refusal_probe_cannot_override_an_authenticated_session() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        drop(server);
        let attempt = unstarted_attempt();
        attempt.probe_port_refusal(addr);
        attempt.events.reached_live.store(true, Ordering::SeqCst);
        attempt.events.on_auth_accepted(test_acceptance());
        assert_eq!(attempt.verdict(), Verdict::Working);
        assert!(attempt.refusal_probe.lock().unwrap().is_none());
    }

    /// One report per stream per batch, however many deliveries the batch
    /// held, and each byte reported once.
    #[test]
    fn a_batch_is_reported_once_per_stream() {
        let mut taken = Taken::default();
        taken.add(20, 5);
        taken.add(1, 3);
        taken.add(20, 7);
        assert_eq!(taken.drain(), vec![(1, 3), (20, 12)]);
        assert_eq!(taken.drain(), Vec::new(), "nothing is reported twice");
    }

    /// `report_taken` frees in the queue the sum of what the batch took: a
    /// delivery waiting behind two chunks goes on once both are reported.
    #[test]
    fn a_report_frees_all_the_batch_took() {
        let (events, _rx) = events();
        events.on_features(transport::Features::NONE);
        let attempt = Attempt {
            client: Arc::new(StdClient::dead()),
            events: Arc::clone(&events),
            started: std::time::Instant::now(),
            refusal_probe: Mutex::new(None),
        };
        events.on_bytes(20, vec![0; UNCREDITED_QUEUE_MAX]);
        events.on_bytes(21, vec![0; 10]);
        let (done_tx, done_rx) = channel();
        let e = Arc::clone(&events);
        std::thread::spawn(move || {
            e.on_bytes(20, vec![1; 10]);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(StdDuration::from_millis(300)).is_err(),
            "it waits"
        );
        let mut taken = Taken::default();
        taken.add(20, UNCREDITED_QUEUE_MAX);
        taken.add(21, 10);
        attempt.report_taken(&mut taken);
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("it goes on once the batch is reported");
    }

    /// Spec §4.13: against a daemon without credits a delivery waits while
    /// more than a mebibyte waits for the terminal, and goes on once the
    /// terminal took it.
    #[test]
    fn without_credits_a_delivery_waits_past_a_mebibyte_until_the_terminal_takes_it() {
        let (events, rx) = events();
        events.on_features(transport::Features::HEADER_AAD);
        events.on_bytes(20, vec![0; UNCREDITED_QUEUE_MAX + 1]);
        let (done_tx, done_rx) = channel();
        let e = Arc::clone(&events);
        std::thread::spawn(move || {
            e.on_bytes(20, vec![1; 10]);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(StdDuration::from_millis(300)).is_err(),
            "it waits"
        );
        events.took(UNCREDITED_QUEUE_MAX + 1);
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("it goes on once taken");
        assert_eq!(rx.try_iter().count(), 2);
    }

    /// With credits the daemon sends at most a window past what was
    /// reported: a delivery never waits.
    #[test]
    fn with_credits_a_delivery_never_waits() {
        let (events, _rx) = events();
        events.on_features(transport::Features::SUPPORTED);
        let (done_tx, done_rx) = channel();
        let e = Arc::clone(&events);
        std::thread::spawn(move || {
            for _ in 0..3 {
                e.on_bytes(20, vec![0; UNCREDITED_QUEUE_MAX]);
            }
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("never waits");
    }

    /// Once nothing takes from the queue any more, a waiting delivery
    /// returns -- `StdClient::close` joins the thread it waits on.
    #[test]
    fn release_ends_a_wait_for_good() {
        let (events, _rx) = events();
        events.on_features(transport::Features::NONE);
        events.on_bytes(20, vec![0; UNCREDITED_QUEUE_MAX + 1]);
        let (done_tx, done_rx) = channel();
        let e = Arc::clone(&events);
        std::thread::spawn(move || {
            e.on_bytes(20, vec![1; 10]);
            e.on_bytes(20, vec![1; 10]);
            let _ = done_tx.send(());
        });
        assert!(done_rx.recv_timeout(StdDuration::from_millis(300)).is_err());
        events.release();
        done_rx
            .recv_timeout(StdDuration::from_secs(5))
            .expect("released");
    }

    fn addr(literal: &str) -> SocketAddr {
        literal.parse().expect("a literal address")
    }

    /// Spec §5.5: the verbose log's line about what the transport agreed.
    #[test]
    fn the_features_line_names_what_was_agreed() {
        assert_eq!(
            features_line(Some(transport::Features::HEADER_AAD)),
            "transport features: header-aad"
        );
        assert_eq!(
            features_line(Some(
                transport::Features::HEADER_AAD | transport::Features::STREAM_CREDIT
            )),
            "transport features: header-aad stream-credit"
        );
        assert_eq!(
            features_line(Some(transport::Features::NONE)),
            "transport features: none (peer predates negotiation)"
        );
        assert_eq!(
            features_line(None),
            "transport features: unknown (no handshake)"
        );
    }

    /// The failure this exists for: a dual-stack host whose AAAA record the
    /// resolver puts first. The daemon binds IPv4 only, so taking the first
    /// answer dials a port nothing is listening on -- and reports a running
    /// daemon as unreachable, which is the same misdiagnosis by a different
    /// route.
    #[test]
    fn an_ipv4_address_wins_even_when_the_resolver_puts_ipv6_first() {
        let chosen = preferred_addr(vec![addr("[2001:db8::1]:60022"), addr("192.0.2.7:60022")]);
        assert_eq!(chosen, Some(addr("192.0.2.7:60022")));
    }

    /// With no IPv4 anywhere, the first answer is still tried: an IPv6-only
    /// host is not a reason to refuse to connect, only a reason it may not
    /// work until the daemon binds both families.
    #[test]
    fn an_ipv6_only_host_falls_back_to_the_first_answer() {
        let chosen = preferred_addr(vec![
            addr("[2001:db8::1]:60022"),
            addr("[2001:db8::2]:60022"),
        ]);
        assert_eq!(chosen, Some(addr("[2001:db8::1]:60022")));
    }

    /// Among several IPv4 answers the resolver's own order stands: the
    /// preference is about the family, and nothing here knows better than
    /// the resolver which of two A records to prefer.
    #[test]
    fn the_first_ipv4_answer_is_the_one_taken() {
        let chosen = preferred_addr(vec![addr("192.0.2.7:60022"), addr("192.0.2.8:60022")]);
        assert_eq!(chosen, Some(addr("192.0.2.7:60022")));
    }

    /// A name that resolved to nothing has nothing to dial.
    #[test]
    fn nothing_resolved_is_no_address() {
        assert_eq!(preferred_addr(Vec::new()), None);
    }

    /// The settle deadline is only meaningful relative to the server's own,
    /// so it is derived from it rather than restated. A change to
    /// `AUTH_DEADLINE` that left this behind would make the client give up
    /// before the server had finished deciding.
    #[test]
    fn the_settle_deadline_sits_past_the_servers_own() {
        assert_eq!(
            AUTH_ACCEPTANCE_TIMEOUT_MS,
            (transport::AUTH_DEADLINE + transport::AUTH_DELIVERY_MARGIN).as_millis() as i64
        );
        assert!(AUTH_ACCEPTANCE_TIMEOUT_MS > transport::AUTH_DEADLINE.as_millis() as i64);
    }

    /// Step 1 signs with an SSH key; step 3 is let in by the daemon's list
    /// (spec §4.2) and carries no signer at all.
    #[test]
    fn the_login_kind_picks_the_policy() {
        struct NoSign;
        impl transport::AuthSigner for NoSign {
            fn sign(
                &self,
                _handshake_hash: &[u8; 32],
                _nonce: Option<&[u8; transport::AUTH_NONCE_LEN]>,
            ) -> Result<transport::AuthRecord, transport::AuthError> {
                unreachable!("the test only reads the policy")
            }
        }
        let (policy, signer) = auth_for(&Login::Allowlist);
        assert!(matches!(policy, transport::AuthPolicy::Allowlist(ref v) if v.is_empty()));
        assert!(signer.is_none());
        let (policy, signer) = auth_for(&Login::Signature(Arc::new(NoSign)));
        assert!(matches!(policy, transport::AuthPolicy::SshSignature));
        assert!(signer.is_some());
    }

    /// A validated explicit acceptance establishes the result even without application data.
    #[test]
    fn explicit_acceptance_means_the_key_was_accepted() {
        assert_eq!(
            attempt_verdict(true, Some(test_acceptance()), false, 100, None),
            Verdict::Working
        );
    }

    /// Handshake completed, proof sent, nothing came back, connection closed.
    /// The server accepts any static key under the signature policy, so
    /// reaching Live proves nothing -- being dropped right after does.
    #[test]
    fn a_close_after_the_handshake_with_no_data_is_a_refusal() {
        assert_eq!(
            attempt_verdict(true, None, true, 200, None),
            Verdict::AuthRefused
        );
    }

    /// Never reached Live: the daemon is not there, or not reachable. That is
    /// a different problem and a different exit code, and telling the user to
    /// check `authorized_keys` here would send them the wrong way entirely.
    #[test]
    fn a_close_before_the_handshake_is_unreachable_not_refused() {
        assert_eq!(
            attempt_verdict(false, None, true, 200, None),
            Verdict::Unreachable(None)
        );
    }

    /// Transport keepalives cannot stand in for committed authentication.
    #[test]
    fn a_live_link_past_the_deadline_without_acceptance_is_refused() {
        assert_eq!(
            attempt_verdict(true, None, false, 6_000, None),
            Verdict::AuthRefused
        );
    }

    /// Past the deadline with nothing delivered and the link no longer live:
    /// the server stopped answering, which is what a refused proof looks
    /// like once the probation task has dropped the route.
    #[test]
    fn silence_past_the_deadline_with_the_link_down_is_a_refusal() {
        assert_eq!(
            attempt_verdict(true, None, false, 6_000, None),
            Verdict::AuthRefused
        );
    }

    /// The handshake itself never completed, and the unreachable deadline has
    /// passed: nothing is listening on the port, or the path is dead. Another
    /// key will not help -- this is a different failure and a different exit
    /// code from a refusal.
    #[test]
    fn silence_past_the_unreachable_deadline_with_no_handshake_is_unreachable() {
        assert_eq!(
            attempt_verdict(false, None, false, 10_500, None),
            Verdict::Unreachable(None)
        );
    }

    /// A send the OS refused rides on the verdict, and decides nothing: the
    /// same facts give the same verdict with or without it.
    #[test]
    fn a_send_error_rides_on_unreachable_and_nothing_else() {
        let refused = Some((
            std::io::ErrorKind::HostUnreachable,
            "No route to host (os error 65)".to_string(),
        ));
        assert_eq!(
            attempt_verdict(false, None, false, 10_500, refused.clone()),
            Verdict::Unreachable(refused.clone())
        );
        assert_eq!(
            attempt_verdict(false, None, true, 200, refused.clone()),
            Verdict::Unreachable(refused.clone())
        );
        assert_eq!(
            attempt_verdict(false, None, false, 1_000, refused.clone()),
            Verdict::StillTrying
        );
        assert_eq!(
            attempt_verdict(true, None, true, 200, refused),
            Verdict::AuthRefused
        );
    }

    #[test]
    fn a_send_error_is_logged_in_the_os_words() {
        assert_eq!(
            send_error_line(
                "192.168.0.200:60200".parse().expect("addr"),
                "No route to host (os error 65)"
            ),
            "a send to 192.168.0.200:60200 failed: No route to host (os error 65)"
        );
    }

    /// Before either deadline there is nothing to conclude -- a slow link, or
    /// a hardware key waiting for a touch, look the same from here.
    #[test]
    fn silence_inside_the_deadlines_concludes_nothing() {
        assert_eq!(
            attempt_verdict(true, None, false, 1_000, None),
            Verdict::StillTrying
        );
        assert_eq!(
            attempt_verdict(false, None, false, 1_000, None),
            Verdict::StillTrying
        );
    }
    #[test]
    fn auth17_live_with_no_acceptance_never_becomes_working_after_old_settle_delay() {
        let mut attempt = unstarted_attempt();
        attempt.started = std::time::Instant::now() - StdDuration::from_secs(6);
        attempt.events.on_state(LinkState::Live);
        assert_ne!(attempt.verdict(), Verdict::Working);
    }

    #[test]
    fn auth17_application_bytes_do_not_establish_authentication() {
        let attempt = unstarted_attempt();
        attempt.events.on_state(LinkState::Live);
        attempt
            .events
            .on_bytes(0, b"channel metadata can arrive before acceptance".to_vec());
        assert_eq!(attempt.verdict(), Verdict::StillTrying);
    }

    #[test]
    fn auth17_live_without_acceptance_never_invokes_channel_open_callback() {
        let mut attempt = unstarted_attempt();
        attempt.started = std::time::Instant::now() - StdDuration::from_secs(6);
        attempt.events.first_live_at.set(attempt.started).unwrap();
        attempt.events.on_state(LinkState::Live);
        let mut opened = 0;
        let verdict = attempt.settle_until(|| opened += 1, || false);
        assert_eq!(
            opened, 0,
            "transport Live is not permission to open a shell"
        );
        assert_ne!(verdict, Verdict::Working);
    }
    #[test]
    fn auth17_explicit_acceptance_settles_immediately_and_calls_startup_once() {
        for disposition in [
            transport::SessionDisposition::Fresh,
            transport::SessionDisposition::Resumed,
        ] {
            let attempt = unstarted_attempt();
            attempt.events.on_state(LinkState::Live);
            let accepted = transport::AuthAcceptance {
                disposition,
                ..test_acceptance()
            };
            attempt.events.on_auth_accepted(accepted);
            let mut startup = 0;
            assert_eq!(
                attempt.settle_until(|| startup += 1, || false),
                Verdict::Working
            );
            assert_eq!(startup, 1);
            assert_eq!(attempt.acceptance(), Some(accepted));
        }
    }

    #[test]
    fn auth17_protocol_failure_and_cancellation_prevent_startup_after_acceptance() {
        let attempt = unstarted_attempt();
        attempt.events.on_auth_accepted(test_acceptance());
        assert_eq!(
            attempt.settle_until(|| panic!("cancelled startup"), || true),
            Verdict::Unreachable(None)
        );
        let failure = transport::ProtocolFailure::InvalidAuthentication {
            reason: transport::AuthAcceptanceError::Excess,
        };
        attempt.events.on_protocol_failure(failure);
        assert_eq!(
            attempt.settle_until(|| panic!("failed startup"), || false),
            Verdict::ProtocolFailure(failure)
        );
        let stale = unstarted_attempt();
        stale.events.release();
        stale.events.on_auth_accepted(test_acceptance());
        assert_eq!(stale.acceptance(), None);
    }
    #[test]
    fn auth17_late_handshake_gets_its_own_acceptance_budget() {
        let mut attempt = unstarted_attempt();
        attempt.started = std::time::Instant::now() - StdDuration::from_secs(9);
        assert_eq!(
            attempt.verdict(),
            Verdict::StillTrying,
            "handshake still has its own ten-second budget"
        );
        attempt.events.on_state(LinkState::Live);
        assert_eq!(
            attempt.verdict(),
            Verdict::StillTrying,
            "time spent waiting for msg2 cannot spend the proof/acceptance budget"
        );
        attempt.events.on_auth_accepted(test_acceptance());
        assert_eq!(attempt.verdict(), Verdict::Working);
    }

    #[test]
    fn auth17_path_recovery_cannot_renew_the_acceptance_deadline() {
        let attempt = unstarted_attempt();
        let first_live = std::time::Instant::now() - StdDuration::from_secs(6);
        attempt.events.first_live_at.set(first_live).unwrap();
        attempt.events.on_state(LinkState::Live);
        assert_eq!(attempt.verdict(), Verdict::AuthRefused);
        attempt.events.on_state(LinkState::PathDown);
        attempt.events.on_state(LinkState::Live);
        assert_eq!(attempt.events.first_live_at.get(), Some(&first_live));
        assert_eq!(attempt.verdict(), Verdict::AuthRefused);
    }
    #[test]
    fn capacity_cli_abort_callback_precedes_closed_and_does_not_duplicate() {
        let (events, rx) = events();
        let reason = transport::SessionAbortReason::ResourceExhausted;
        events.on_session_aborted(reason);
        events.on_session_aborted(reason);
        events.on_state(LinkState::Closed);
        let got: Vec<_> = rx.try_iter().collect();
        assert!(
            matches!(got.as_slice(), [crate::session::UiEvent::SessionAborted(found), crate::session::UiEvent::Link(LinkState::Closed)] if *found == reason)
        );
    }

    #[test]
    fn capacity_cli_abort_prevents_startup_even_if_acceptance_already_arrived() {
        let attempt = unstarted_attempt();
        attempt.events.on_auth_accepted(test_acceptance());
        attempt
            .events
            .on_session_aborted(transport::SessionAbortReason::ResourceExhausted);
        attempt.events.on_state(LinkState::Closed);
        assert_eq!(
            attempt.settle_until(|| panic!("aborted startup"), || false),
            Verdict::SessionAborted(transport::SessionAbortReason::ResourceExhausted)
        );
        let stale = unstarted_attempt();
        stale.events.release();
        stale
            .events
            .on_session_aborted(transport::SessionAbortReason::ResourceExhausted);
        assert_eq!(*stale.events.session_abort.lock().unwrap(), None);
    }
}
