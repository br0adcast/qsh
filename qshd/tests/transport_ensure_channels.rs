//! Integration test for what switching the daemon over to channels
//! actually changed: a `transport-ensure` daemon serves CHANNELS -- it no
//! longer drives tmux itself on three hardcoded streams. Two things, in one
//! test:
//!
//! - a daemon started through `transport-ensure` opens a shell channel and
//!   carries a real shell's output over it at all;
//! - two independently connected clients (distinct tokens, both
//!   allowlisted) each get their OWN pseudo-terminal, with nothing one
//!   writes ever showing up in the other's channel.
//!
//! `qshd/tests/transport_multisession.rs` used to prove the second half of
//! this over the OLD server-side tmux hybrid (two clients, two real tmux
//! sessions on a dedicated `-L` socket); it was deleted along with that
//! hybrid, because it built its own backend straight from
//! `transport::tmux_server::run_tmux_session`, which no longer exists. This
//! is the channel path's replacement: no tmux involved at all, just two
//! shells -- what `transport-ensure` actually hands out today.
//!
//! Modeled on two existing tests rather than invented from scratch, the
//! same way `serve_channels.rs` already models itself on two OTHER existing
//! tests: `transport_ensure.rs` for spawning the real `transport-ensure`
//! process and picking a free port under a file-local lock
//! (`spawn_transport_ensure`/`free_udp_port`/`serialised`, duplicated here
//! rather than shared -- integration test binaries in this crate don't share
//! a common module, and `serve_channels.rs` already established that
//! duplicating these small pieces per file is the convention, not an
//! oversight); `serve_channels.rs` for driving a client against a real
//! channel with `StdClient`/`ClientEvents` and collecting its output by
//! marker (`Events`/`Collected`/`NoopBinder`).

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use qshd::control::{client_request, ControlRequest};
use transport::channel::{
    decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use transport::{LinkState, Stats};

mod daemon_guard;
use daemon_guard::DaemonGuard;

/// Serialises the tests in this file for the same reason
/// `transport_ensure.rs::ONE_DAEMON_AT_A_TIME` does: each one binds a real
/// port picked by `free_udp_port`, which is a hint (free at the moment it
/// was read), not a reservation.
static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Picks a free UDP port the same way `transport_ensure.rs` does: bind an
/// ephemeral port and close it right away, handing the number back.
fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("an ephemeral port is bound to pick a free number")
        .local_addr()
        .expect("the bound socket's local address")
        .port()
}

/// Launches `qshd transport-ensure ...` with an isolated `XDG_CACHE_HOME`,
/// reads the `server-pubkey:`/`TRANSPORT-READY` lines from stdout, waits for
/// the parent to exit, and returns the decoded server Noise public key. A
/// direct copy of `transport_ensure.rs::spawn_transport_ensure`'s startup
/// protocol, trimmed to what this file needs (just the key -- no reuse/
/// stderr assertions here, those are `transport_ensure.rs`'s job).
fn spawn_transport_ensure(home: &std::path::Path, port: u16, client_pubkey_b64: &str) -> [u8; 32] {
    let bin = env!("CARGO_BIN_EXE_qshd");
    let mut child: Child = Command::new(bin)
        .args([
            "transport-ensure",
            "--name",
            "main",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            client_pubkey_b64,
        ])
        .env("XDG_CACHE_HOME", home)
        // The daemon opens a real login shell in a pseudo-terminal, and this test types
        // probe commands into it. Without this the shell appends every one of them to the
        // history of whoever ran the suite -- these tests do not set HOME, so that is the
        // developer's own `~/.bash_history`.
        .env("HISTFILE", "/dev/null")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the `qshd transport-ensure` process starts");

    let stdout = child.stdout.take().expect("the process's stdout is piped");
    let mut reader = BufReader::new(stdout);

    let mut line1 = String::new();
    reader
        .read_line(&mut line1)
        .expect("the first line (server-pubkey) is read from stdout");
    if !line1.starts_with("server-pubkey: ") {
        let mut why = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut why);
        }
        panic!("expected a server-pubkey line, got: {line1:?}; the process's stderr: {why}");
    }
    let server_pub_b64 = line1.trim_start_matches("server-pubkey: ").trim_end();
    let raw = BASE64
        .decode(server_pub_b64)
        .expect("server-pubkey decodes from base64");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&raw);

    let mut line2 = String::new();
    reader
        .read_line(&mut line2)
        .expect("the second line (TRANSPORT-READY) is read from stdout");
    assert!(
        line2.starts_with("TRANSPORT-READY "),
        "expected a TRANSPORT-READY line, got: {line2:?}"
    );

    let status = child
        .wait()
        .expect("the `transport-ensure` wrapper process exits (the parent after the fork)");
    assert!(
        status.success(),
        "the `transport-ensure` wrapper process must exit successfully"
    );

    server_pub
}

/// Waits for `probe` to hold, or gives up loudly -- the same convention as
/// `serve_channels.rs::wait_until`.
fn wait_until(mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

/// Everything one client's driver needs back: decoded control records in
/// arrival order, and its own shell channel's assembled output. One
/// instance per client -- the whole point of this test is that the two
/// never share state.
#[derive(Default)]
struct Collected {
    control: Vec<ServerRecord>,
    shell_output: Vec<u8>,
    live: bool,
}

struct Events {
    control_deframer: Mutex<RecordDeframer>,
    shell_deframer: Mutex<ShellDeframer>,
    collected: Mutex<Collected>,
}

impl Default for Events {
    fn default() -> Self {
        Events {
            control_deframer: Mutex::new(RecordDeframer::new()),
            shell_deframer: Mutex::new(ShellDeframer::new()),
            collected: Mutex::new(Collected::default()),
        }
    }
}

impl ClientEvents for Events {
    fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == CONTROL_STREAM {
            let raws = self
                .control_deframer
                .lock()
                .expect("control deframer")
                .push(&data);
            let mut collected = self.collected.lock().expect("collected");
            for raw in raws {
                if let Ok(rec) = decode_server(&raw) {
                    collected.control.push(rec);
                }
            }
        } else if stream_id == FIRST_CHANNEL_STREAM {
            let recs = self
                .shell_deframer
                .lock()
                .expect("shell deframer")
                .push(&data);
            let mut collected = self.collected.lock().expect("collected");
            for rec in recs {
                if let ShellRecord::Data(bytes) = rec {
                    collected.shell_output.extend(bytes);
                }
            }
        }
    }

    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.collected.lock().expect("collected").live = true;
        }
    }

    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

/// Connects one client (allowlist auth, no signer), opens a shell channel at
/// a fixed size, and returns the driver plus its event collector.
fn connect_and_open_shell(
    server_addr: SocketAddr,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
) -> (StdClient, Arc<Events>) {
    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        server_addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        token,
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        None,
    );

    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the handshake with the transport-ensure daemon must complete"
    );

    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            })),
        )
        .expect("fixture input admitted");
    assert!(
        wait_until(|| {
            events
                .collected
                .lock()
                .expect("collected")
                .control
                .contains(&ServerRecord::Opened {
                    stream: FIRST_CHANNEL_STREAM,
                })
        }),
        "the daemon must confirm the shell channel is open"
    );

    (client, events)
}

/// A `transport-ensure` daemon serves a shell channel like any other channel
/// backend, and two independently connected clients each get their own
/// pseudo-terminal: what one types is never seen on the other's channel.
/// Each marker is COMPUTED by the shell (`$((...))`), not written as a
/// literal string, so a pseudo-terminal merely echoing the input back could
/// not make this test pass for the wrong reason.
#[test]
fn transport_ensure_serves_independent_shell_channels() {
    let _serial = serialised();
    let home = tempfile::tempdir().expect("a temporary XDG_CACHE_HOME is created");
    let sock_path = home.path().join("qsh").join("control.sock");
    // After the temp dir, so it drops first: the daemon is gone before the dir.
    let _daemon = DaemonGuard::new(sock_path.clone());

    let client1_kp = generate_keypair();
    let client2_kp = generate_keypair();

    let port = free_udp_port();
    let server_pub = spawn_transport_ensure(home.path(), port, &BASE64.encode(client1_kp.public));
    // The second client's key is live-added to the already-running daemon,
    // the same `ADD-CLIENT` path a second device joining the same server
    // goes through in production -- no second `transport-ensure` process.
    client_request(&sock_path, &ControlRequest::AddClient(client2_kp.public))
        .expect("ADD-CLIENT of the second key");

    let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    let (client1, events1) =
        connect_and_open_shell(server_addr, server_pub, client1_kp.private, [1u8; 16]);
    let (client2, events2) =
        connect_and_open_shell(server_addr, server_pub, client2_kp.private, [2u8; 16]);

    let marker1 = "MARK1-42-MARK1";
    let marker2 = "MARK2-56-MARK2";
    client1
        .send_bytes(
            FIRST_CHANNEL_STREAM,
            b"echo MARK1-$((6*7))-MARK1\n".to_vec(),
        )
        .expect("fixture input admitted");
    client2
        .send_bytes(
            FIRST_CHANNEL_STREAM,
            b"echo MARK2-$((7*8))-MARK2\n".to_vec(),
        )
        .expect("fixture input admitted");

    assert!(
        wait_until(|| {
            String::from_utf8_lossy(&events1.collected.lock().expect("collected").shell_output)
                .contains(marker1)
        }),
        "client 1 must see its own marker on its own shell channel; got: {:?}",
        String::from_utf8_lossy(&events1.collected.lock().expect("collected").shell_output)
    );
    assert!(
        wait_until(|| {
            String::from_utf8_lossy(&events2.collected.lock().expect("collected").shell_output)
                .contains(marker2)
        }),
        "client 2 must see its own marker on its own shell channel; got: {:?}",
        String::from_utf8_lossy(&events2.collected.lock().expect("collected").shell_output)
    );

    // A grace window after both markers showed up: any cross-talk (the
    // other client's marker leaking in) would have time to appear before we
    // assert its absence below.
    std::thread::sleep(Duration::from_millis(300));

    let output1 = events1
        .collected
        .lock()
        .expect("collected")
        .shell_output
        .clone();
    let output2 = events2
        .collected
        .lock()
        .expect("collected")
        .shell_output
        .clone();
    assert!(
        !String::from_utf8_lossy(&output1).contains(marker2),
        "client 2's marker must never reach client 1's channel (sessions leaking into each other)"
    );
    assert!(
        !String::from_utf8_lossy(&output2).contains(marker1),
        "client 1's marker must never reach client 2's channel (sessions leaking into each other)"
    );

    client1.close();
    client2.close();
}
