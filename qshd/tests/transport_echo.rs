//! Loopback integration test: bring up
//! `transport::driver_tokio::serve_echo` on `127.0.0.1:0` in a tokio task,
//! and drive a CLIENT `transport::Connection` on a separate UDP socket
//! through a Noise IK handshake and a data send, checking that the server
//! returns the same bytes back (echo).
//!
//! The client is also a sans-IO `Connection`: the test itself drives I/O
//! (sends outgoing datagrams over the socket, feeds incoming ones into
//! `on_datagram`/`on_timeout`), while the core drives the protocol logic.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use transport::handshake::generate_keypair;
use transport::{AuthPolicy, Connection, ConnectionConfig, Datagram, Event, Role};

/// Payload the client sends to the server and expects back.
const PAYLOAD: &[u8] = b"roam-proof";

/// Overall test timeout: on loopback the handshake and echo finish in a
/// fraction of a second, so a 5-second margin makes the test robust (not
/// tied to exact timing) without letting it hang if something breaks.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Send a batch of the client's outgoing datagrams onto the network.
async fn send_all(socket: &UdpSocket, dgrams: &[Datagram]) {
    for dg in dgrams {
        socket
            .send_to(&dg.bytes, dg.to)
            .await
            .expect("sending the client's datagram");
    }
}

#[tokio::test]
async fn transport_echo_round_trip() {
    // Peer keys: server static key, client static key. The client's
    // public key goes into the server's allowlist -- otherwise the
    // handshake will be rejected (see `Connection::on_handshake_init`).
    let server_kp = generate_keypair();
    let client_kp = generate_keypair();

    // Server socket on a random free loopback port; find out the actual
    // port before starting the echo task.
    let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binding the server socket");
    let server_addr = server_socket.local_addr().expect("local server address");

    let server_cfg = ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::SUPPORTED,
        role: Role::Server,
        local_static_priv: server_kp.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_kp.public]),
    };
    let server_task = tokio::spawn(async move {
        transport::driver_tokio::serve_echo(server_socket, server_cfg).await
    });

    // Client socket and client connection.
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binding the client socket");
    let mut client = Connection::new(ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::SUPPORTED,
        role: Role::Client,
        local_static_priv: client_kp.private,
        remote_static_pub: Some(server_kp.public),
        auth: AuthPolicy::Allowlist(Vec::new()),
    });

    // Client starts the handshake: msg1 to the server's address.
    let m1 = client.start(Instant::now(), server_addr);
    send_all(&client_socket, &m1).await;

    // Spin the client's recv/timeout loop until the echo arrives. The
    // whole loop is under an overall timeout, so a breakage doesn't hang
    // the test.
    let received = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let next = client.next_timeout();

            // Wait for either a packet from the server or the core's nearest timer.
            let packet = match next {
                Some(deadline) => {
                    let dur = deadline.saturating_duration_since(Instant::now());
                    tokio::select! {
                        r = client_socket.recv_from(&mut buf) => Some(r),
                        _ = tokio::time::sleep(dur) => None,
                    }
                }
                None => Some(client_socket.recv_from(&mut buf).await),
            };

            let now = Instant::now();
            match packet {
                Some(Ok((len, src))) => {
                    let out = client.on_datagram(now, src, &buf[..len]);
                    send_all(&client_socket, &out).await;
                }
                Some(Err(e)) => panic!("receiving on the client socket: {e}"),
                None => {
                    let out = client.on_timeout(now);
                    send_all(&client_socket, &out).await;
                }
            }

            // Core events. Once the handshake completes we send the
            // payload exactly once; we assemble the echo from delivered bytes.
            let mut echoed: Vec<u8> = Vec::new();
            let mut outgoing: Vec<Datagram> = Vec::new();
            for ev in client.poll_events() {
                match ev {
                    Event::HandshakeDone => {
                        outgoing.extend(client.send(now, 0, PAYLOAD));
                    }
                    Event::StreamData { data, .. } => echoed.extend(data),
                    _ => {}
                }
            }
            send_all(&client_socket, &outgoing).await;

            if echoed == PAYLOAD {
                break echoed;
            }
        }
    })
    .await
    .expect("echo arrived within the allotted timeout");

    assert_eq!(received, PAYLOAD, "the server returned the same bytes");

    server_task.abort();
}
