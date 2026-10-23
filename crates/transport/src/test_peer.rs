//! Real peers on loopback for tests of what sits on top of `StdClient`
//! (feature `testnet`, always on in this crate's own tests): this crate's
//! driver tests and the app core's daemon-update tests share them.

use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::conn::{
    AuthPolicy, Connection, ConnectionConfig, Event, LinkState, Role, Stats, StreamProgress,
};
use crate::driver_std::{Binder, ClientEvents, DriverSetup, StdClient};
use crate::handshake::generate_keypair;
use crate::handshake_payload::StartKind;

/// How long the server thread lives: past any test that uses it.
const SERVER_LIFETIME: Duration = Duration::from_secs(10);

struct AnyNetwork;
impl Binder for AnyNetwork {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

struct LiveSignal(Mutex<Sender<()>>);
impl ClientEvents for LiveSignal {
    fn on_input_failure(&self, failure: crate::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, _: u8, _: Vec<u8>) {}
    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            let _ = self.0.lock().expect("live signal").send(());
        }
    }
    fn on_stats(&self, _: Stats) {}
    fn on_reset(&self, _: u8) {}
}

/// Chunk lengths handed to the client's owner, and the moment it is live.
struct Chunks {
    chunks: Mutex<Sender<usize>>,
    live: Mutex<Sender<()>>,
}
impl ClientEvents for Chunks {
    fn on_input_failure(&self, failure: crate::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, _: u8, data: Vec<u8>) {
        let _ = self.chunks.lock().expect("chunks").send(data.len());
    }
    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            let _ = self.live.lock().expect("live").send(());
        }
    }
    fn on_stats(&self, _: Stats) {}
    fn on_reset(&self, _: u8) {}
}

/// The set-up every peer here shares: a key pair each, a server socket on
/// loopback read with `read_timeout`, a server `Connection` allowing the
/// client's key, handed with the socket to `serve` on its own thread, and a
/// client set up by `setup` that is `Live` against it. `events` builds the
/// client's callbacks around the sender it must signal `Live` on.
///
/// Panics if the link is not live within 5 s.
pub(crate) fn live_client_of<S>(
    session_token: [u8; 16],
    read_timeout: Duration,
    setup: DriverSetup,
    events: impl FnOnce(Sender<()>) -> Arc<dyn ClientEvents>,
    serve: S,
) -> StdClient
where
    S: FnOnce(UdpSocket, Connection) + Send + 'static,
{
    let server = generate_keypair();
    let client = generate_keypair();
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the server socket");
    let addr = sock.local_addr().expect("the server's address");
    sock.set_read_timeout(Some(read_timeout))
        .expect("set the server's read timeout");
    let client_pub = client.public;
    thread::spawn(move || {
        let conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::from_bits(
                crate::Features::SUPPORTED.bits() & !crate::Features::AUTH_ACCEPTED.bits(),
            ),
            role: Role::Server,
            local_static_priv: server.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client_pub]),
        });
        serve(sock, conn);
    });
    let (live_tx, live_rx) = mpsc::channel();
    let std_client = StdClient::connect_with(
        addr,
        ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        session_token,
        StartKind::Cold,
        Arc::new(AnyNetwork),
        events(live_tx),
        None,
        setup,
    );
    live_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the link goes live");
    std_client
}

/// A client that is `Live` against a server that answers the handshake and
/// then acknowledges nothing: whatever the client sends stays in flight, so
/// an upload fills the congestion window and stands there until its
/// retransmit timeout -- 500 ms from the first segment, since no round trip
/// is ever measured on data. The receiver hears the first arrival of data
/// on each stream at that server, and when (the server's own clock, taken as
/// the datagram is read).
///
/// Panics if the link is not live within 5 s.
pub fn client_whose_server_stops_acknowledging() -> (StdClient, Receiver<(u8, Instant)>) {
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let std_client = live_client_of(
        [33; 16],
        Duration::from_millis(50),
        DriverSetup::default(),
        |live| Arc::new(LiveSignal(Mutex::new(live))),
        move |sock, mut conn| {
            let mut buf = [0u8; 65536];
            let mut quiet = false;
            let mut seen = BTreeSet::new();
            let until = Instant::now() + SERVER_LIFETIME;
            while Instant::now() < until {
                // A read timeout, or any other error: look at the clock again.
                let Ok((len, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let read_at = Instant::now();
                let out = conn.on_datagram(read_at, src, &buf[..len]);
                if !quiet {
                    // msg2 only: the handshake is done once it is out.
                    for dg in &out {
                        let _ = sock.send_to(&dg.bytes, dg.to);
                    }
                }
                for ev in conn.poll_events() {
                    match ev {
                        Event::HandshakeDone => quiet = true,
                        Event::StreamData { stream_id, .. } if seen.insert(stream_id) => {
                            let _ = arrived_tx.send((stream_id, read_at));
                        }
                        _ => {}
                    }
                }
            }
        },
    );
    (std_client, arrived_rx)
}

/// How far a writing server has got on its stream (see
/// [`client_of_a_writing_server`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterProgress {
    /// Bytes of the stream the client acknowledged.
    pub acked: u64,
    /// The limit the server's sender holds, with credits (`None` before
    /// any).
    pub credit_limit: Option<u64>,
}

/// A client, set up by `setup`, of a server that writes `data` on `stream`
/// the moment it is live and then serves the connection properly -- its
/// timers, its answers -- for `SERVER_LIFETIME`. The first receiver hears
/// the length of every chunk the client's owner is handed; the second, the
/// server's own [`WriterProgress`] on `stream` every time it changes.
///
/// Panics if the link is not live within 5 s.
pub fn client_of_a_writing_server(
    stream: u8,
    data: Vec<u8>,
    setup: DriverSetup,
) -> (StdClient, Receiver<usize>, Receiver<WriterProgress>) {
    let (chunks_tx, chunks_rx) = mpsc::channel();
    let (progress_tx, progress_rx) = mpsc::channel();
    let std_client = live_client_of(
        [34; 16],
        Duration::from_millis(5),
        setup,
        |live| {
            Arc::new(Chunks {
                chunks: Mutex::new(chunks_tx),
                live: Mutex::new(live),
            })
        },
        move |sock, mut conn| {
            let mut buf = [0u8; 65536];
            let mut wrote = false;
            let mut last = None;
            let until = Instant::now() + SERVER_LIFETIME;
            while Instant::now() < until {
                let mut out = Vec::new();
                if let Ok((len, src)) = sock.recv_from(&mut buf) {
                    out.extend(conn.on_datagram(Instant::now(), src, &buf[..len]));
                }
                if !wrote && conn.state() == LinkState::Live {
                    wrote = true;
                    out.extend(conn.send(Instant::now(), stream, &data));
                }
                out.extend(conn.on_timeout_if_due(Instant::now()));
                for dg in &out {
                    let _ = sock.send_to(&dg.bytes, dg.to);
                }
                let _ = conn.poll_events();
                if wrote {
                    let StreamProgress { queued, unacked } = conn.stream_progress(stream);
                    let now = WriterProgress {
                        acked: queued - unacked,
                        credit_limit: conn.credit_limit_for_test(stream),
                    };
                    if last != Some(now) {
                        last = Some(now);
                        let _ = progress_tx.send(now);
                    }
                }
            }
        },
    );
    (std_client, chunks_rx, progress_rx)
}
