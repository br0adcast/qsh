//! End to end: what the client says its terminal is becomes the `TERM` of
//! the shell the daemon spawns.
//!
//! SSH carries this in `pty-req`. qsh had nowhere to put it, so the daemon
//! set one value for everybody. A console client's keys are encoded by its
//! own terminal and may need a different value. A Home key sent as `\e[1~` to a shell configured for `\eOH`
//! does nothing at all and leaves its trailing `~` in the line, which is
//! exactly what the bug report looked like.
//!
//! The unit tests already pin both halves separately (`channel.rs` for the
//! record, `channel_server.rs` for it reaching the spawner,
//! `channel_backend.rs` for the spawned child's environment). This one
//! proves they meet over a real socket: a real `qshd serve` process, a real
//! transport client, a real pseudo-terminal, and a shell that prints what it
//! was actually given.
//!
//! Modeled on `serve_channels.rs`, whose harness pieces (`start_daemon`,
//! `free_udp_port`, `serialised`, `Events`) are duplicated here rather than
//! shared -- this crate's integration tests shared no module when this was
//! written, and that file's own docs already established the convention of
//! duplicating rather than inventing one. `tests/common/mod.rs` exists now,
//! but only for the `qshd serve --system` tests (`serve_system_split.rs`,
//! `system_mode_shell.rs`); this file predates it and has no reason to
//! adopt it, so the duplication here stands.

use std::io::{BufRead, BufReader, Read, Write};
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

/// Kills the daemon when the test ends, however it ends.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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

fn start_daemon(
    dir: &std::path::Path,
    port: u16,
    authorized_keys: &std::path::Path,
) -> (Daemon, [u8; 32]) {
    let bin = env!("CARGO_BIN_EXE_qshd");
    let mut child = Command::new(bin)
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            authorized_keys.to_str().expect("utf-8 path"),
            "--host-key",
            dir.join("host_key").to_str().expect("utf-8 path"),
        ])
        .env("XDG_CACHE_HOME", dir)
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

    (Daemon { child }, server_pub)
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

/// A shell channel opened after the client announced its terminal type runs
/// with THAT type, not the daemon's assumption. The name is one no host
/// would pick by accident, and the shell prints it itself, so nothing but
/// the announcement could put it there.
#[test]
fn the_announced_terminal_type_reaches_the_shell() {
    let _serial = serialised();
    let dir = tempfile::tempdir().expect("tempdir");
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
    let (_daemon, server_pub) = start_daemon(dir.path(), port, &authorized);

    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::SshSignature,
        },
        [23u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&client_key_path, None)
                .expect("the client key loads")
                .with_login("client".to_string()),
        )),
    );

    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the handshake with the daemon must complete"
    );

    // Announced BEFORE the channel is opened: the daemon spawns each
    // channel's process with what it knew at that moment.
    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Term("rxvt-unicode-256color".to_string())),
        )
        .expect("fixture input admitted");
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

    client
        .send_bytes(FIRST_CHANNEL_STREAM, b"echo T=$TERM\n".to_vec())
        .expect("fixture input admitted");
    assert!(
        wait_until(|| {
            String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output)
                .contains("T=rxvt-unicode-256color")
        }),
        "the shell must run with the announced terminal type; got: {:?}",
        String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output)
    );

    client.close();
}
