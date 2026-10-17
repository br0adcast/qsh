//! Loopback integration test: bring up
//! `transport::shell_server::serve_shell` on `127.0.0.1:0` in a tokio task
//! (with a real PTY `$SHELL`), and drive a CLIENT `transport::Connection`
//! on a separate UDP socket through a Noise IK handshake, sending a
//! command to the shell (stream 0) and a resize (stream 1), checking that
//! the shell's output comes back on stream 0 and that resize does not
//! crash the server (echo continues afterward).
//!
//! The client is also a sans-IO `Connection`: the test itself drives I/O
//! (sends outgoing datagrams over the socket, feeds incoming ones into
//! `on_datagram`/`on_timeout`), while the core drives the protocol logic.
//! Everything is under an overall timeout, with no fixed pauses -- the
//! test is not tied to exact timing.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use qshd::pty::{spawn_shell, PtyResizeHandle, DEFAULT_PTY_SIZE};
use transport::handshake::generate_keypair;
use transport::{AuthPolicy, Connection, ConnectionConfig, Datagram, Event, Role};

/// Marker the shell prints on our command, which we look for in the
/// output returned on stream 0.
const MARKER: &[u8] = b"ALACRITTY_OK";

/// Overall test timeout: on loopback the handshake, shell startup, and
/// echo finish in a fraction of a second; the margin makes the test
/// robust without letting it hang if something breaks.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Build a stream 1 resize control record: `type(1)=0x01 | cols(BE) | rows(BE)`.
fn resize_record(cols: u16, rows: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.push(0x01);
    v.extend_from_slice(&cols.to_be_bytes());
    v.extend_from_slice(&rows.to_be_bytes());
    v
}

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
async fn transport_shell_runs_command_and_survives_resize() {
    // Peer keys: the client's public key goes into the server's allowlist
    // -- otherwise the handshake will be rejected (see
    // `Connection::on_handshake_init`).
    let server_kp = generate_keypair();
    let client_kp = generate_keypair();

    // Server socket on a random free loopback port.
    let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binding the server socket");
    let server_addr = server_socket.local_addr().expect("local server address");

    // Unlike this crate's other integration tests, this one calls
    // `spawn_shell` directly IN this test binary's own process rather than
    // spawning the `qshd` binary as a subprocess with `HISTFILE` already
    // set on it -- so the same guard has to happen here instead. Left
    // unset, the REAL `$SHELL` launched below is interactive (it's
    // attached to a PTY) and appends whatever this test feeds it to the
    // process's inherited `~/.bash_history`, i.e. the launching user's own
    // history, not a sandboxed fixture. Only one test in this file spawns a
    // shell, so there is no concurrent-write race to guard against here.
    std::env::set_var("HISTFILE", "/dev/null");

    // The test side itself brings up the PTY shell and hands it to
    // `serve_shell` -- exactly as the `transport-shell` subcommand does in
    // qshd.
    let (master, mut child) =
        spawn_shell(DEFAULT_PTY_SIZE, None).expect("shell started in the PTY");
    let reader = master.try_clone_reader().expect("PTY master side's reader");
    let writer = master.take_writer().expect("PTY master side's writer");
    let resize: Box<dyn transport::shell_server::ResizeHandle> =
        Box::new(PtyResizeHandle::new(master));

    let server_cfg = ConnectionConfig {
        features: transport::Features::SUPPORTED,
        role: Role::Server,
        local_static_priv: server_kp.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_kp.public]),
    };
    let server_task = tokio::spawn(async move {
        transport::shell_server::serve_shell(server_socket, server_cfg, reader, writer, resize)
            .await
    });

    // Client socket and client connection.
    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("binding the client socket");
    let mut client = Connection::new(ConnectionConfig {
        features: transport::Features::SUPPORTED,
        role: Role::Client,
        local_static_priv: client_kp.private,
        remote_static_pub: Some(server_kp.public),
        auth: AuthPolicy::Allowlist(Vec::new()),
    });

    // Client starts the handshake: msg1 to the server's address.
    let m1 = client.start(Instant::now(), server_addr);
    send_all(&client_socket, &m1).await;

    // Spin the client's recv/timeout loop until the marker shows up among
    // stream 0's bytes. The whole loop is under an overall timeout.
    let outcome = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut collected: Vec<u8> = Vec::new();
        loop {
            let next = client.next_timeout();
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

            // Core events. Once the handshake completes we send resize
            // FIRST (stream 1), then the marker-printing command (stream
            // 0) -- exactly once; we accumulate output from the bytes
            // delivered on stream 0.
            let mut outgoing: Vec<Datagram> = Vec::new();
            for ev in client.poll_events() {
                match ev {
                    Event::HandshakeDone => {
                        outgoing.extend(client.send(now, 1, &resize_record(100, 40)));
                        outgoing.extend(client.send(now, 0, b"printf ALACRITTY_OK\n"));
                    }
                    Event::StreamData { stream_id: 0, data } => collected.extend(data),
                    _ => {}
                }
            }
            send_all(&client_socket, &outgoing).await;

            if collected
                .windows(MARKER.len())
                .any(|window| window == MARKER)
            {
                break;
            }
        }
    })
    .await;

    server_task.abort();
    let _ = child.kill();
    let _ = child.wait();

    outcome.expect(
        "the ALACRITTY_OK marker must arrive on stream 0 within the allotted timeout \
         (including after the resize was sent -- the server is alive)",
    );
}
