//! Making the connection, and working out what happened when it does not
//! work.
//!
//! The transport never says "your signature was refused": under the
//! signature policy the server accepts any static key at the handshake and
//! then simply closes the connection if the proof does not verify, so an
//! attacker probing keys learns nothing from the failure mode. So a refusal
//! has to be INFERRED from what can be observed --
//! handshake completed, proof sent, no data, connection gone, and whether the
//! link is live right now. That inference decides both the exit code the
//! user sees and whether the next key is worth trying, so it is a pure
//! function with its own tests.

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

use transport::driver_std::{Binder, ClientEvents, DriverSetup, SendFailure, StdClient};
use transport::{LinkState, Stats};

/// How long to wait, once the handshake has completed, for either a byte of
/// data or the link to fall away before treating silence itself as an
/// answer: `transport::AUTH_SETTLED_AFTER`, the one definition every client
/// shares (derived there from the server's own `AUTH_DEADLINE`).
const AUTH_SETTLED_AFTER_MS: i64 = transport::AUTH_SETTLED_AFTER.as_millis() as i64;

/// How long to wait for the handshake to complete AT ALL before giving up on
/// this address: `transport::HANDSHAKE_GIVE_UP_AFTER`, shared with the app.
/// Without a deadline `attempt_verdict` would report `StillTrying` forever
/// and the CLI would hang with no output.
const UNREACHABLE_AFTER_MS: i64 = transport::HANDSHAKE_GIVE_UP_AFTER.as_millis() as i64;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Data flowed: this key is the right one.
    Working,
    /// The handshake succeeded and the session did not: the proof was not
    /// accepted. Worth trying the next key.
    AuthRefused,
    /// Never got as far as a handshake. Another key will not help. Carries
    /// how the latest send failed, when it did: the one thing the client
    /// saw beyond silence.
    Unreachable(Option<SendFailure>),
    /// Not enough has happened to say.
    StillTrying,
}

/// What an attempt amounts to, from what can be observed.
///
/// There is no "proof accepted" signal on the wire either: acceptance is
/// inferred, same as refusal, from what the link does. On refusal the
/// server's probation task exits and the session manager drops the route
/// (`crates/transport/src/probation.rs`), so it stops answering entirely and
/// the client's link falls to `PathDown` within a few seconds. An accepted
/// session keeps answering keepalives and stays `Live`. So past
/// `AUTH_SETTLED_AFTER_MS`, `live_now` -- not `reached_live`, which only
/// records that the link WAS live at some point -- is what tells the two
/// apart.
///
/// Residual ambiguity, knowingly accepted rather than overlooked: a session
/// that IS accepted, whose shell prints nothing at all, and whose shell then
/// exits before the deadline -- closing the link -- still reads as
/// `AuthRefused`. Nothing observable here distinguishes that from a genuine
/// refusal; both end the same way, a dead link with no data ever delivered.
///
/// `send_error` is the transport's latest send failure, if any; it rides on
/// an `Unreachable` verdict and changes no decision.
pub fn attempt_verdict(
    reached_live: bool,
    got_data: bool,
    closed: bool,
    live_now: bool,
    elapsed_ms: i64,
    send_error: Option<SendFailure>,
) -> Verdict {
    if got_data {
        return Verdict::Working;
    }
    if closed {
        // Reaching Live proves nothing on the signature path -- the server
        // admits any static key there. Being dropped right afterwards, with
        // nothing delivered, is what a refused proof looks like. A close
        // before the handshake ever finished is a different failure
        // entirely: the daemon isn't there, or isn't reachable, and another
        // key will not help.
        return if reached_live {
            Verdict::AuthRefused
        } else {
            Verdict::Unreachable(send_error)
        };
    }
    if reached_live {
        if elapsed_ms >= AUTH_SETTLED_AFTER_MS {
            return if live_now {
                Verdict::Working
            } else {
                Verdict::AuthRefused
            };
        }
        return Verdict::StillTrying;
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
    pub got_data: AtomicBool,
    pub closed: AtomicBool,
    /// Whether the link is live RIGHT NOW, as opposed to `reached_live`,
    /// which only ever records that it once was.
    pub live_now: AtomicBool,
    /// Whether the connection runs with stream credits (spec §4.13).
    credits: AtomicBool,
    /// Bytes handed to the main loop and not written to the terminal yet.
    queued: Mutex<usize>,
    room: Condvar,
    /// Nothing takes from the queue any more: a waiting delivery returns.
    released: AtomicBool,
}

impl Events {
    pub fn new(tx: Sender<crate::session::UiEvent>) -> Events {
        Events {
            tx,
            reached_live: AtomicBool::new(false),
            got_data: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            live_now: AtomicBool::new(false),
            credits: AtomicBool::new(false),
            queued: Mutex::new(0),
            room: Condvar::new(),
            released: AtomicBool::new(false),
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
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        // Any byte at all proves the key was accepted, regardless of which
        // stream it lands on: with channels, a cold session that opens no
        // channel may see nothing at all before the trial's own deadline
        // (see `attempt_verdict`'s "no data ever, link still live" branch
        // for what settles the verdict then).
        self.got_data.store(true, Ordering::SeqCst);
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

    fn on_features(&self, features: transport::Features) {
        self.credits.store(
            features.contains(transport::Features::STREAM_CREDIT),
            Ordering::SeqCst,
        );
    }

    fn on_state(&self, state: LinkState) {
        match state {
            LinkState::Live => {
                self.reached_live.store(true, Ordering::SeqCst);
                self.live_now.store(true, Ordering::SeqCst);
            }
            LinkState::PathDown => {
                self.live_now.store(false, Ordering::SeqCst);
            }
            LinkState::Closed => {
                self.closed.store(true, Ordering::SeqCst);
                self.live_now.store(false, Ordering::SeqCst);
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
        let (auth, signer) = auth_for(&login);
        let events = Arc::new(Events::new(tx));
        // The token identifies the SESSION, not this connection: it comes
        // from the caller's session store, so a later run of `qsh` returns to
        // the shell this one leaves behind rather than starting another.
        let client = Arc::new(StdClient::connect_with(
            addr,
            transport::ConnectionConfig {
                features: transport::Features::SUPPORTED,
                role: transport::Role::Client,
                local_static_priv: local_priv,
                remote_static_pub: Some(server_pub),
                auth,
            },
            token,
            // Always warm: the server answers an unknown token with a fresh
            // session and no complaint, so asking to resume costs nothing
            // when there is nothing to resume -- and asking cold would
            // REPLACE a session that is still there, which is precisely the
            // one we came back for.
            transport::StartKind::Warm,
            Arc::new(NoopBinder),
            events.clone(),
            signer,
            // Spec §4.13: a channel's bytes count as taken when they reach
            // the terminal (reported by `interactive`); the control stream
            // and the proof's stream on delivery.
            DriverSetup {
                default_consumption: transport::Consumption::Explicit,
                stream_consumption: vec![
                    (
                        transport::channel::CONTROL_STREAM,
                        transport::Consumption::OnDelivery,
                    ),
                    (transport::AUTH_STREAM, transport::Consumption::OnDelivery),
                ],
            },
        ));
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

    pub fn verdict(&self) -> Verdict {
        let refused = self.port_refusal();
        let reached_live = self.events.reached_live.load(Ordering::SeqCst);
        // Authenticated progress takes precedence over an unauthenticated
        // network error, including a handshake racing with the probe.
        if !reached_live && !self.events.got_data.load(Ordering::SeqCst) {
            if let Some(error) = refused {
                return Verdict::Unreachable(Some(error));
            }
        }
        attempt_verdict(
            self.events.reached_live.load(Ordering::SeqCst),
            self.events.got_data.load(Ordering::SeqCst),
            self.events.closed.load(Ordering::SeqCst),
            self.events.live_now.load(Ordering::SeqCst),
            self.started.elapsed().as_millis() as i64,
            self.client.last_send_error(),
        )
    }

    /// Waits until the attempt is decided, or the wait runs out.
    pub fn settle(&self) -> Verdict {
        self.settle_with(|| {})
    }

    /// Like [`Self::settle`], but calls `on_live` once -- the moment the
    /// link first comes alive, before the verdict is known at all -- rather
    /// than only after the whole attempt is decided.
    ///
    /// Why this exists: under a protocol where the caller must ask for
    /// something (open a channel) before the server ever answers with
    /// anything, `verdict()`'s "data arrived" signal never fires on its own
    /// -- a working key would otherwise sit out the FULL auth deadline in
    /// silence every single time, because nothing ever prompts the server to
    /// speak first. `on_live` is the caller's chance to send that first ask
    /// (see `climb::settle_opening`) the instant it can possibly matter,
    /// so a genuine answer -- and the `Verdict::Working` it produces via
    /// `got_data` -- arrives as fast as the round trip allows instead of
    /// waiting out a deadline that exists for the OPPOSITE case (a key that
    /// is accepted but whose session simply has nothing to say yet).
    ///
    /// The refusal path is unaffected: `on_live` firing changes nothing
    /// about `reached_live`/`closed`/`live_now`, which is everything
    /// `attempt_verdict` looks at for `AuthRefused` -- a refused key never
    /// gets a real answer to `on_live`'s ask, so `got_data` never flips
    /// either way.
    pub fn settle_with(&self, on_live: impl FnMut()) -> Verdict {
        self.settle_until(on_live, || false)
    }

    /// Recovery can stop a stale attempt when SSH supplies a new port or
    /// authorization. The owner still detaches it before starting another.
    pub fn settle_until(
        &self,
        mut on_live: impl FnMut(),
        interrupted: impl Fn() -> bool,
    ) -> Verdict {
        let mut fired = false;
        loop {
            if interrupted() {
                return Verdict::Unreachable(None);
            }
            if !fired && self.events.reached_live.load(Ordering::SeqCst) {
                on_live();
                fired = true;
            }
            let v = self.verdict();
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
        attempt.events.got_data.store(true, Ordering::SeqCst);
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
            AUTH_SETTLED_AFTER_MS,
            (transport::AUTH_DEADLINE + transport::AUTH_SETTLE_MARGIN).as_millis() as i64
        );
        assert!(AUTH_SETTLED_AFTER_MS > transport::AUTH_DEADLINE.as_millis() as i64);
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

    /// Data arrived: whatever else happened, this key worked.
    #[test]
    fn data_means_the_key_was_accepted() {
        assert_eq!(
            attempt_verdict(true, true, false, true, 100, None),
            Verdict::Working
        );
    }

    /// Handshake completed, proof sent, nothing came back, connection closed.
    /// The server accepts any static key under the signature policy, so
    /// reaching Live proves nothing -- being dropped right after does.
    #[test]
    fn a_close_after_the_handshake_with_no_data_is_a_refusal() {
        assert_eq!(
            attempt_verdict(true, false, true, false, 200, None),
            Verdict::AuthRefused
        );
    }

    /// Never reached Live: the daemon is not there, or not reachable. That is
    /// a different problem and a different exit code, and telling the user to
    /// check `authorized_keys` here would send them the wrong way entirely.
    #[test]
    fn a_close_before_the_handshake_is_unreachable_not_refused() {
        assert_eq!(
            attempt_verdict(false, false, true, false, 200, None),
            Verdict::Unreachable(None)
        );
    }

    /// Past the deadline with nothing delivered but the link STILL live: the
    /// server is still talking to us (keepalives), which is what an accepted
    /// session with a quiet shell looks like -- not a refusal.
    #[test]
    fn a_live_link_past_the_deadline_with_no_data_is_accepted() {
        assert_eq!(
            attempt_verdict(true, false, false, true, 6_000, None),
            Verdict::Working
        );
    }

    /// Past the deadline with nothing delivered and the link no longer live:
    /// the server stopped answering, which is what a refused proof looks
    /// like once the probation task has dropped the route.
    #[test]
    fn silence_past_the_deadline_with_the_link_down_is_a_refusal() {
        assert_eq!(
            attempt_verdict(true, false, false, false, 6_000, None),
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
            attempt_verdict(false, false, false, false, 10_500, None),
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
            attempt_verdict(false, false, false, false, 10_500, refused.clone()),
            Verdict::Unreachable(refused.clone())
        );
        assert_eq!(
            attempt_verdict(false, false, true, false, 200, refused.clone()),
            Verdict::Unreachable(refused.clone())
        );
        assert_eq!(
            attempt_verdict(false, false, false, false, 1_000, refused.clone()),
            Verdict::StillTrying
        );
        assert_eq!(
            attempt_verdict(true, false, true, false, 200, refused),
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
            attempt_verdict(true, false, false, true, 1_000, None),
            Verdict::StillTrying
        );
        assert_eq!(
            attempt_verdict(false, false, false, false, 1_000, None),
            Verdict::StillTrying
        );
    }
}
