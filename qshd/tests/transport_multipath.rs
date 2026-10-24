//! End-to-end: a real `qshd serve` daemon, two real UDP roads to it, one of
//! them cut, and a shell that never noticed.
//!
//! This is where every piece of multipath meets: the
//! `PathProbe`/`PathProbeAck` frames (`reliability.rs`), the rule that a
//! check never migrates the session (`conn.rs`), the path table's scoring
//! and scheduling (`paths.rs`), the client driver's checked roads
//! (`driver_std.rs`), and the daemon answering a check to its source without
//! moving onto it. No single one of those proves the whole thing moves; this
//! test is the whole thing.
//!
//! Modeled on `serve_terminal_type.rs`, whose harness pieces (`serialised`,
//! `free_udp_port`, `wait_until`, `write_key`, `NoopBinder`, `Events`) are
//! duplicated here rather than shared -- this crate's integration tests
//! share no module, and `serve_channels.rs`'s own docs already establish why
//! that is a convention, not an oversight.
//!
//! **Platform note.** The second road is `127.0.0.2`. On Linux the whole
//! `127.0.0.0/8` block is local and reachable with no configuration, which is
//! what makes two roads to one socket possible here. On macOS only
//! `127.0.0.1` is up by default: this test needs
//! `sudo ifconfig lo0 alias 127.0.0.2` first, or it will not reach the daemon
//! by that address at all.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;
use tempfile::TempDir;

use transport::channel::{
    decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient, UseRoadOutcome};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::paths::PathState;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use transport::{LinkState, Stats};

static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

fn private_temp_home() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

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

fn write_key(dir: &std::path::Path, name: &str) -> (PrivateKey, std::path::PathBuf) {
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .expect("keygen");
    let path = dir.join(name);
    std::fs::write(
        &path,
        key.to_openssh(LineEnding::LF).expect("encode").as_bytes(),
    )
    .expect("write key");
    (key, path)
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

/// Kills the daemon when the test ends, however it ends. Carries `port` and
/// `server_pub` separately from any particular address: this test reaches
/// the same daemon by two different addresses, so neither the port nor the
/// key may be baked into one of them.
struct Daemon {
    child: Child,
    port: u16,
    server_pub: [u8; 32],
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts a real `qshd serve` daemon on a free port, with a fresh client key
/// already in its `authorized_keys`. Returns the daemon, the path to that
/// client's private key (for `FileSigner`), and the temp dir backing both
/// (kept alive so the daemon's host key and authorized-keys file survive).
fn start_daemon() -> (Daemon, std::path::PathBuf, TempDir) {
    let dir = private_temp_home().expect("tempdir");
    let (client_key, client_key_path) = write_key(dir.path(), "client");
    let authorized = dir.path().join("authorized_keys");
    let mut f = std::fs::File::create(&authorized).expect("create authorized_keys");
    writeln!(
        f,
        "{}",
        client_key.public_key().to_openssh().expect("openssh")
    )
    .expect("write authorized_keys");
    f.flush().expect("flush");

    let port = free_udp_port();
    let bin = env!("CARGO_BIN_EXE_qshd");
    let mut child = Command::new(bin)
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            authorized.to_str().expect("utf-8 path"),
            "--host-key",
            dir.path().join("host_key").to_str().expect("utf-8 path"),
        ])
        .env("XDG_CACHE_HOME", dir.path())
        // The daemon opens a real login shell in a pseudo-terminal, and this test types
        // probe commands into it. Without this the shell appends every one of them to the
        // history of whoever ran the suite -- these tests do not set HOME, so that is the
        // developer's own `~/.bash_history`.
        .env("HISTFILE", "/dev/null")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the `qshd serve` process starts");

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
        .expect("the second line (host-key-fingerprint) is read from stdout");
    assert!(
        line2.starts_with("host-key-fingerprint: "),
        "expected a host-key-fingerprint line, got: {line2:?}"
    );

    (
        Daemon {
            child,
            port,
            server_pub,
        },
        client_key_path,
        dir,
    )
}

/// Opens the shell channel on `FIRST_CHANNEL_STREAM` and waits for the
/// daemon's confirmation, the way `serve_terminal_type.rs` does inline.
fn open_shell_channel(client: &StdClient, events: &Arc<Events>) {
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
}

/// The shell channel's collected output so far, as a string.
fn shell_text(events: &Arc<Events>) -> String {
    String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output).into_owned()
}

/// A UDP relay with a switch: forwards datagrams both ways until it is
/// stopped, and then drops everything. This is how the test takes a road
/// away without touching a firewall.
struct Relay {
    /// Where the client sends: the relay's own address.
    front: SocketAddr,
    alive: Arc<AtomicBool>,
}

impl Relay {
    fn start(target: SocketAddr) -> Relay {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind the relay");
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        let front = sock.local_addr().expect("the relay's address");
        let alive = Arc::new(AtomicBool::new(true));
        let running = alive.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65535];
            // Whoever spoke to us first is the client; everything from the
            // target goes back to them.
            let mut client: Option<SocketAddr> = None;
            while running.load(Ordering::SeqCst) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if from == target {
                    if let Some(to) = client {
                        let _ = sock.send_to(&buf[..n], to);
                    }
                } else {
                    client = Some(from);
                    let _ = sock.send_to(&buf[..n], target);
                }
            }
        });
        Relay { front, alive }
    }

    /// The road goes away: nothing is forwarded from here on.
    fn stop(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }
}

/// Stops the relay when the test ends, however it ends -- the same reason
/// `Daemon` has one. A panic before `stop()` would otherwise leave the
/// forwarding thread and its port alive until the process exits.
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The whole point: when the road the traffic is on goes away,
/// the session moves to a road that answers -- and it is the SAME session,
/// which the shell proves by still knowing a variable set before the move.
#[test]
fn a_session_moves_to_a_live_road_when_its_own_goes_away() {
    let _serial = serialised();
    let (daemon, key_path, dir) = start_daemon();

    // Two roads to one daemon: through the relay, and straight to the same
    // socket by another loopback address.
    let direct: SocketAddr = format!("127.0.0.2:{}", daemon.port)
        .parse()
        .expect("a literal address");
    let relay = Relay::start(
        format!("127.0.0.1:{}", daemon.port)
            .parse()
            .expect("a literal address"),
    );

    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        relay.front,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(daemon.server_pub),
            auth: AuthPolicy::SshSignature,
        },
        [31u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&key_path, None)
                .expect("the client key loads")
                .with_login("client".to_string()),
        )),
    );
    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the handshake through the relay must complete"
    );
    client.set_paths(vec![relay.front, direct]);

    open_shell_channel(&client, &events);
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"MARK=road-$((6*7))\n".to_vec())
        .expect("fixture input admitted");
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"echo M=$MARK\n".to_vec())
        .expect("fixture input admitted");
    assert!(
        wait_until(|| shell_text(&events).contains("M=road-42")),
        "the shell answers through the first road; got: {}",
        shell_text(&events)
    );

    // The road goes away.
    relay.stop();

    assert!(
        wait_until(|| client.active_path() == Some(direct)),
        "the session must move to the road that answers"
    );

    // The same shell, not a new one: it still knows the variable.
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"echo AGAIN=$MARK\n".to_vec())
        .expect("fixture input admitted");
    assert!(
        wait_until(|| shell_text(&events).contains("AGAIN=road-42")),
        "the shell after the move is the same shell; got: {}",
        shell_text(&events)
    );

    // The move above is polled every 20 ms, so on its own it could have been
    // caught DURING a flap rather than after the connection settled. This
    // road has now carried a whole shell exchange, which takes far longer
    // than a flap would: it is still the one in use.
    assert_eq!(
        client.active_path(),
        Some(direct),
        "the client must settle on the road that answers, not oscillate onto it"
    );

    client.close();
    drop(dir);
}

/// A road chosen by hand: the session moves onto it at once, stays there while the road it
/// left is alive too, and the daemon follows -- with the relay gone, the SAME shell (it still
/// knows a variable set before the move) answers down the chosen road.
///
/// `set_paths` runs only after the shell round trip below, not right after the handshake: an
/// `SshSignature` connection sits in `run_probation`'s loop (`probation.rs`) until its proof
/// verifies, and `router.sessions` already routes to that task's `dgram_rx` throughout --
/// datagrams are not dropped for want of a route. What is lost is anything that arrives while
/// the loop is `.await`ing `verify_off_task` (`probation.rs`'s loop, the synchronous signature
/// check run via `spawn_blocking`): that await does not `select!` on `dgram_rx`, so a packet
/// landing in the window queues in the channel unread, and on `Step::Proved` the loop `break`s
/// without ever draining it -- the manager then wires a FRESH channel for the promoted session,
/// so whatever sat buffered in the old one is gone. Ordinary stream data survives this because
/// the reliable layer retransmits it; a `PathProbe` does not, and is only re-sent on
/// `PathTable`'s own schedule, 30 s away once the road in use is healthy. The shell round trip
/// below already proves probation is over (a channel only opens on a promoted session), so the
/// check queued right after it is not racing that window. The app itself never races it either:
/// `ManagedConnection.openCore` (service module) calls `setPaths` only after
/// `awaitSessionReady()`, which already waits for the shell channel (or the daemon's own
/// verdict) -- i.e. for the session to be well past probation.
#[test]
fn a_session_moved_by_hand_stays_on_the_chosen_road_and_the_daemon_follows() {
    let _serial = serialised();
    let (daemon, key_path, dir) = start_daemon();

    let direct: SocketAddr = format!("127.0.0.2:{}", daemon.port)
        .parse()
        .expect("a literal address");
    let relay = Relay::start(
        format!("127.0.0.1:{}", daemon.port)
            .parse()
            .expect("a literal address"),
    );

    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        relay.front,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(daemon.server_pub),
            auth: AuthPolicy::SshSignature,
        },
        [32u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&key_path, None)
                .expect("the client key loads")
                .with_login("client".to_string()),
        )),
    );
    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the handshake through the relay must complete"
    );

    open_shell_channel(&client, &events);
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"MARK=hand-$((6*7))\n".to_vec())
        .expect("fixture input admitted");
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"echo M=$MARK\n".to_vec())
        .expect("fixture input admitted");
    assert!(
        wait_until(|| shell_text(&events).contains("M=hand-42")),
        "the shell answers through the relay; got: {}",
        shell_text(&events)
    );

    client.set_paths(vec![relay.front, direct]);

    assert!(
        wait_until(|| client
            .roads()
            .iter()
            .any(|r| r.addr == direct && r.state == PathState::Verified)),
        "the direct road answers its check"
    );
    assert_eq!(client.use_road(direct), UseRoadOutcome::Moved);
    assert_eq!(
        client.active_path(),
        Some(direct),
        "the move is already published"
    );

    // Ten seconds with both roads alive: nothing takes the session back.
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        assert_eq!(
            client.active_path(),
            Some(direct),
            "the session must stay on the road chosen by hand while it carries traffic"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // The daemon followed: with the relay gone, the same shell still answers.
    relay.stop();
    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"echo AGAIN=$MARK\n".to_vec())
        .expect("fixture input admitted");
    assert!(
        wait_until(|| shell_text(&events).contains("AGAIN=hand-42")),
        "the daemon sends down the chosen road; got: {}",
        shell_text(&events)
    );
    assert_eq!(client.active_path(), Some(direct));

    client.close();
    drop(dir);
}
