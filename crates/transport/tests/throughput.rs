//! In-process throughput (spec `2026-09-26-qsh-transport-defects-design.md`
//! §9.4, §11.1): a client and a server `Connection` in memory, no delay, no
//! loss, stream 20 from the server to the client, and an "ideal timer" -- the
//! moment the exchange goes quiet, the server's clock jumps to its next
//! deadline and its timers run. What is measured is CPU time, not network
//! time: virtual time only decides what the timers do.
//!
//! Measurements, not checks: `#[ignore]`, printing numbers. Run on a quiet
//! machine with
//! `cargo test -p transport --release --test throughput -- --ignored --nocapture --test-threads=1`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use transport::conn::{AuthPolicy, Connection, ConnectionConfig, Datagram, Event, Role};
use transport::handshake::generate_keypair;

const STREAM: u8 = 20;
const CHUNK: usize = 8 * 1024;

struct Pair {
    client: Connection,
    server: Connection,
    caddr: SocketAddr,
    saddr: SocketAddr,
    now: Instant,
    delivered: usize,
}

fn pair() -> Pair {
    let server_kp = generate_keypair();
    let client_kp = generate_keypair();
    let caddr: SocketAddr = "198.51.100.7:40000".parse().expect("a literal address");
    let saddr: SocketAddr = "198.51.100.1:41000".parse().expect("a literal address");
    let mut client = Connection::new(ConnectionConfig {
        features: transport::Features::SUPPORTED,
        role: Role::Client,
        local_static_priv: client_kp.private,
        remote_static_pub: Some(server_kp.public),
        auth: AuthPolicy::Allowlist(Vec::new()),
    });
    let mut server = Connection::new(ConnectionConfig {
        features: transport::Features::SUPPORTED,
        role: Role::Server,
        local_static_priv: server_kp.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_kp.public]),
    });
    let now = Instant::now();
    let mut msg2 = Vec::new();
    for dg in client.start(now, saddr) {
        msg2.extend(server.on_datagram(now, caddr, &dg.bytes));
    }
    for dg in msg2 {
        let _ = client.on_datagram(now, saddr, &dg.bytes);
    }
    let _ = client.poll_events();
    let _ = server.poll_events();
    Pair {
        client,
        server,
        caddr,
        saddr,
        now,
        delivered: 0,
    }
}

impl Pair {
    /// Carry datagrams both ways until neither side has anything to say.
    fn pump(&mut self, mut to_client: Vec<Datagram>) {
        let mut to_server: Vec<Datagram> = Vec::new();
        while !to_client.is_empty() || !to_server.is_empty() {
            for dg in std::mem::take(&mut to_client) {
                to_server.extend(self.client.on_datagram(self.now, self.saddr, &dg.bytes));
            }
            for ev in self.client.poll_events() {
                if let Event::StreamData { data, .. } = ev {
                    self.delivered += data.len();
                }
            }
            for dg in std::mem::take(&mut to_server) {
                to_client.extend(self.server.on_datagram(self.now, self.caddr, &dg.bytes));
            }
            let _ = self.server.poll_events();
        }
    }

    /// The ideal timer: while anything is unacknowledged, jump to the nearer
    /// of the two sides' deadlines and run that side's timers -- the
    /// client's too, which holds its acknowledgements up to `ACK_DELAY` when
    /// fewer than `ACK_EVERY` segments wait (spec §4.11).
    fn finish(&mut self) {
        while self.server.stream_progress(STREAM).unacked > 0 {
            let server_at = self
                .server
                .next_timeout()
                .expect("a sender with unacknowledged bytes has a deadline");
            match self.client.next_timeout() {
                Some(client_at) if client_at <= server_at => {
                    self.now = self.now.max(client_at);
                    let mut to_client = Vec::new();
                    for dg in self.client.on_timeout(self.now) {
                        to_client.extend(self.server.on_datagram(self.now, self.caddr, &dg.bytes));
                    }
                    let _ = self.server.poll_events();
                    self.pump(to_client);
                }
                _ => {
                    self.now = self.now.max(server_at);
                    let out = self.server.on_timeout(self.now);
                    self.pump(out);
                }
            }
        }
    }
}

fn all_at_once(mib: usize) -> Duration {
    let data = vec![0x5Au8; mib * 1024 * 1024];
    let mut p = pair();
    let started = Instant::now();
    let out = p.server.send(p.now, STREAM, &data);
    p.pump(out);
    p.finish();
    let elapsed = started.elapsed();
    assert_eq!(p.delivered, data.len(), "every byte arrived");
    elapsed
}

fn in_chunks(mib: usize) -> Duration {
    let data = vec![0x5Au8; mib * 1024 * 1024];
    let mut p = pair();
    let started = Instant::now();
    for chunk in data.chunks(CHUNK) {
        let out = p.server.send(p.now, STREAM, chunk);
        p.pump(out);
    }
    p.finish();
    let elapsed = started.elapsed();
    assert_eq!(p.delivered, data.len(), "every byte arrived");
    elapsed
}

fn report(mode: &str, mib: usize, elapsed: Duration) {
    println!(
        "in-process {mode} {mib} MiB: {:.3} s, {:.1} MiB/s",
        elapsed.as_secs_f64(),
        mib as f64 / elapsed.as_secs_f64()
    );
}

#[test]
#[ignore = "timing measurement; run with --release -- --ignored --nocapture on a quiet machine"]
fn in_process_all_at_once() {
    for mib in [4usize, 8, 16, 32] {
        report("all at once", mib, all_at_once(mib));
    }
}

#[test]
#[ignore = "timing measurement; run with --release -- --ignored --nocapture on a quiet machine"]
fn in_process_in_8_kib_chunks() {
    for mib in [8usize, 32] {
        report("in 8 KiB chunks", mib, in_chunks(mib));
    }
}

/// Spec §9.2 (1a) and §11.2: 32 MiB written at once costs no more than twice
/// the same 32 MiB written in 8 KiB chunks, and runs at 60 MiB/s or better.
/// Before the ring: 51.9 s against 0.25 s.
/// `cargo test -p transport --release --test throughput all_at_once_costs -- --ignored --nocapture`
#[test]
#[ignore = "timing check; run with --release -- --ignored --nocapture on a quiet machine"]
fn all_at_once_costs_at_most_twice_the_chunked_write() {
    let chunked = in_chunks(32);
    let at_once = all_at_once(32);
    report("in 8 KiB chunks", 32, chunked);
    report("all at once", 32, at_once);
    assert!(
        at_once <= chunked * 2,
        "all at once {at_once:?} against {chunked:?} in chunks"
    );
    let rate = 32.0 / at_once.as_secs_f64();
    assert!(rate >= 60.0, "{rate:.1} MiB/s");
}
