#![cfg(feature = "tokio-driver")]
//! Loopback throughput (spec §9.4, §11.1): a real `StdClient` against
//! `driver_tokio::serve_echo` on 127.0.0.1, N MiB sent in 64 KiB pieces on
//! stream 20 and echoed back; the time is until the last echoed byte
//! arrives. Three runs per size, each against a fresh echo server.
//!
//! Measurements, not checks: `#[ignore]`, printing numbers. Run with
//! `cargo test -p transport --features tokio-driver --release --test loopback_throughput -- --ignored --nocapture --test-threads=1`.
//!
//! Each echo server runs on a thread of its own that never ends
//! (`serve_echo` does not return); the test process ends them all.

use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use transport::conn::{AuthPolicy, ConnectionConfig, LinkState, Role, Stats};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::driver_tokio::serve_echo;
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;

const STREAM: u8 = 20;
const PIECE: usize = 64 * 1024;

struct AnyNetwork;

impl Binder for AnyNetwork {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
struct Received {
    bytes: u64,
    live: bool,
}

#[derive(Default)]
struct Echoes {
    state: Mutex<Received>,
    changed: Condvar,
}

impl Echoes {
    fn wait(&self, within: Duration, done: impl Fn(&Received) -> bool) -> bool {
        let deadline = Instant::now() + within;
        let mut st = self.state.lock().expect("echo state");
        while !done(&st) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self.changed.wait_timeout(st, left).expect("echo state").0;
        }
        true
    }
}

impl ClientEvents for Echoes {
    fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == STREAM {
            self.state.lock().expect("echo state").bytes += data.len() as u64;
            self.changed.notify_all();
        }
    }
    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.state.lock().expect("echo state").live = true;
            self.changed.notify_all();
        }
    }
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

/// Start an echo server; return its address, its public key and the private
/// key of the one client it admits.
fn start_echo_server() -> (SocketAddr, [u8; 32], [u8; 32]) {
    let server_kp = generate_keypair();
    let client_kp = generate_keypair();
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind the echo server");
    let _ = transport::tune_udp_buffers(&socket); // as qshd's transport-echo does
    socket
        .set_nonblocking(true)
        .expect("non-blocking for tokio");
    let addr = socket.local_addr().expect("its address");
    let cfg = ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::SUPPORTED,
        role: Role::Server,
        local_static_priv: server_kp.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_kp.public]),
    };
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime for the echo server");
        rt.block_on(async move {
            let socket = tokio::net::UdpSocket::from_std(socket).expect("adopt the socket");
            serve_echo(socket, cfg).await;
        });
    });
    (addr, server_kp.public, client_kp.private)
}

fn one_run(mib: usize) -> Duration {
    let (addr, server_pub, client_priv) = start_echo_server();
    let echoes = Arc::new(Echoes::default());
    let client = StdClient::connect(
        addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        [3u8; 16],
        StartKind::Cold,
        Arc::new(AnyNetwork),
        echoes.clone(),
        None,
    );
    assert!(
        echoes.wait(Duration::from_secs(10), |r| r.live),
        "the echo server never answered the handshake"
    );
    let data = vec![0x5Au8; mib * 1024 * 1024];
    let total = data.len() as u64;
    let started = Instant::now();
    for piece in data.chunks(PIECE) {
        client
            .send_bytes_bounded(STREAM, piece.to_vec(), Duration::from_secs(30))
            .expect("fixture input admitted");
    }
    assert!(
        echoes.wait(Duration::from_secs(300), |r| r.bytes >= total),
        "{mib} MiB did not come back within five minutes"
    );
    let elapsed = started.elapsed();
    client.close();
    elapsed
}

#[test]
#[ignore = "timing measurement; run with --release -- --ignored --nocapture on a quiet machine"]
fn loopback_echo_round_trip() {
    for mib in [1usize, 2, 4, 8] {
        let runs: Vec<String> = (0..3)
            .map(|_| format!("{:.2} s", one_run(mib).as_secs_f64()))
            .collect();
        println!("loopback echo {mib} MiB: {}", runs.join(", "));
    }
}
