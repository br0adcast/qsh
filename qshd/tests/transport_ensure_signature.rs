//! A daemon started through SSH must admit both allowlisted and signed clients.
//!
//! `transport-ensure` registers a Noise static key through the control socket.
//! A different client can instead prove its identity with an SSH key signature.
//! This test ensures that both paths share one daemon and the same channels,
//! with the `authorized_keys` gate used by `qshd serve` also available here.
//!
//! Modeled on the files this crate already keeps for these two halves
//! rather than invented from scratch: `transport_ensure_channels.rs` for
//! spawning the real `transport-ensure` process, picking a free port under a
//! file-local lock, and driving a shell channel (`spawn_transport_ensure`/
//! `free_udp_port`/`serialised`/`Events`, duplicated per file as this
//! crate's integration tests do -- they share no common module);
//! `serve_auth.rs` for signing a connection the way `AuthorizedKeysVerifier`
//! expects, and for proving a stranger's refusal is the signature check
//! rather than a socket that was never reached.

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;

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
/// `transport_ensure.rs::ONE_DAEMON_AT_A_TIME` does: each binds a real port
/// picked by `free_udp_port`, which is a hint (free when it was read), not a
/// reservation.
static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("an ephemeral port is bound to pick a free number")
        .local_addr()
        .expect("the bound socket's local address")
        .port()
}

/// Polls `cond` until it holds or the ceiling passes. Generous on purpose:
/// every wait here crosses a real socket and two independently scheduled
/// processes.
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Generates an ed25519 key pair, writes the private half to `dir/name` in
/// OpenSSH format, and returns the key (for its public half) and the path.
fn write_key(dir: &std::path::Path, name: &str) -> (PrivateKey, std::path::PathBuf) {
    let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
    let path = dir.join(name);
    std::fs::write(
        &path,
        key.to_openssh(LineEnding::LF).expect("encode").as_bytes(),
    )
    .expect("write key");
    (key, path)
}

/// Launches `qshd transport-ensure ...` with `HOME` and `XDG_CACHE_HOME`
/// both pointed at an isolated directory -- `HOME` because that is where the
/// daemon looks for `authorized_keys`, which is the whole subject of this
/// file -- reads the `server-pubkey:`/`TRANSPORT-READY` lines, waits for the
/// parent to exit (it forks), and returns the server's Noise public key.
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
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home)
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
    let raw = BASE64
        .decode(line1.trim_start_matches("server-pubkey: ").trim_end())
        .expect("server-pubkey decodes from base64");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&raw);

    let mut line2 = String::new();
    reader
        .read_line(&mut line2)
        .expect("the second line (TRANSPORT-READY) is read from stdout");
    assert!(
        line2.starts_with("TRANSPORT-READY"),
        "expected TRANSPORT-READY, got: {line2:?}"
    );
    // `transport-ensure` forks: the process started here is the parent and
    // exits as soon as the daemon is up.
    let _ = child.wait();
    server_pub
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

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

/// Connects a client that proves itself by SSH signature -- the console
/// client's own policy: a fresh Noise static key every time, so there is
/// nothing an allowlist could hold.
fn connect_with_signature(
    server_addr: SocketAddr,
    server_pub: [u8; 32],
    key_path: &std::path::Path,
    token: [u8; 16],
) -> (StdClient, Arc<Events>) {
    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        server_addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::SshSignature,
        },
        token,
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(key_path, None)
                .expect("the client key loads")
                .with_login("client".to_string()),
        )),
    );
    (client, events)
}

/// One daemon, started the way the app starts it, serves both kinds of
/// client: the app by its allowlisted static key, and a console client by a
/// signature from a key in `authorized_keys`. A key that is not listed gets
/// nothing, which is what makes the first half mean something.
///
/// The marker is COMPUTED by the shell (`$((...))`) rather than written as a
/// literal, so a pseudo-terminal merely echoing the input back could not
/// make this pass for the wrong reason.
#[test]
fn a_signed_console_client_reaches_the_daemon_the_app_started() {
    let _serial = serialised();
    let home = tempfile::tempdir().expect("a temporary HOME is created");
    let sock_path = home.path().join("qsh").join("control.sock");
    // After the temp dir, so it drops first: the daemon is gone before the dir.
    let _daemon = DaemonGuard::new(sock_path.clone());

    let (listed, listed_path) = write_key(home.path(), "listed");
    let (_stranger, stranger_path) = write_key(home.path(), "stranger");
    std::fs::create_dir_all(home.path().join(".ssh")).expect("the .ssh directory is created");
    std::fs::write(
        home.path().join(".ssh").join("authorized_keys"),
        format!(
            "{}\n",
            listed.public_key().to_openssh().expect("openssh encoding")
        ),
    )
    .expect("authorized_keys is written");

    // The app's own key: allowlisted over the control socket at startup,
    // exactly as `transport-ensure` is called in production.
    let app_kp = generate_keypair();
    let port = free_udp_port();
    let server_pub = spawn_transport_ensure(home.path(), port, &BASE64.encode(app_kp.public));
    let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    // The console client is never handed the key over SSH: it asks the
    // daemon for it, the way `qsh` does on a host it has not pinned yet.
    // A daemon with no signature gate answers nothing here, so this is the
    // same change under test, seen from the other end.
    let discovered = sshauth::discover::discover_server_key(server_addr, Duration::from_secs(3))
        .expect("the daemon answers a discovery request once it has a signature gate");
    assert_eq!(
        discovered, server_pub,
        "the discovered key must be the daemon's own, as printed at startup"
    );

    let (console, events) =
        connect_with_signature(server_addr, discovered, &listed_path, [7u8; 16]);
    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the signed client's handshake with the transport-ensure daemon must complete"
    );

    console.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: FIRST_CHANNEL_STREAM,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        })),
    );
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
        "a key in authorized_keys must get a shell channel from the app's own daemon"
    );

    console.send_bytes(
        FIRST_CHANNEL_STREAM,
        b"echo SIGNED-$((6*7))-SIGNED\n".to_vec(),
    );
    assert!(
        wait_until(|| {
            String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output)
                .contains("SIGNED-42-SIGNED")
        }),
        "the signed client's shell must actually run its command; got: {:?}",
        String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output)
    );

    // The stranger's key proves nothing. Its own Noise handshake must still
    // complete -- that rules out an unreachable socket, so the refusal below
    // can only be the signature check.
    let (stranger_client, stranger_events) =
        connect_with_signature(server_addr, server_pub, &stranger_path, [8u8; 16]);
    assert!(
        wait_until(|| stranger_events.collected.lock().expect("collected").live),
        "the stranger's own Noise handshake must complete before its refusal means anything"
    );
    stranger_client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: FIRST_CHANNEL_STREAM,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        })),
    );
    // An ABSENCE, so a fixed window rather than a poll: nothing that arrives
    // later could make the daemon right.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        stranger_events
            .collected
            .lock()
            .expect("collected")
            .control
            .is_empty(),
        "a key that is not in authorized_keys must get no channel at all, got: {:?}",
        stranger_events.collected.lock().expect("collected").control
    );

    console.close();
    stranger_client.close();
}
