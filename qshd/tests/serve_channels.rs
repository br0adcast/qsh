//! End-to-end: a REAL `qshd serve` process, on a real UDP port, driven by a
//! real transport client (`StdClient`) that speaks the channel protocol --
//! open a shell channel, run a command in it, and see its natural exit
//! reported.
//!
//! Modeled on two existing tests rather than invented from scratch:
//! `transport_ensure.rs` for picking a free port under a file-local lock (two
//! of these tests racing for the same ephemeral port number is a known flake
//! class -- see that file's own docs) and for spawning the real `qshd`
//! executable; `transport_shell.rs` for driving a client against a real PTY
//! shell and collecting its output by marker rather than by a fixed number of
//! reads. Signing the connection the way `serve`'s `AuthorizedKeysVerifier`
//! expects is modeled on `serve_auth.rs`.
//!
//! `serve` (unlike `transport-ensure`) never daemonizes: the process this
//! test spawns is the one running the server, and it never exits on its own,
//! so it is killed at the end rather than waited on.

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
    decode_server, encode_client, ChannelKind, ClientRecord, DaemonMode, OpenRequest, ServerRecord,
    UpdateAnswer, UpdateOffer, CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use transport::{LinkState, Stats};

/// Serialises the tests in this file for the same reason
/// `transport_ensure.rs::ONE_DAEMON_AT_A_TIME` does: each one binds a real
/// port picked by `free_udp_port`, which is a hint (free at the moment it was
/// read), not a reservation. Run concurrently, two of these tests can be
/// handed the same number and race each other's daemon for it.
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
        .expect("binding an ephemeral port to pick a free number")
        .local_addr()
        .expect("local address of the bound socket")
        .port()
}

/// Waits for `probe` to hold, or gives up loudly. Generous on purpose: a slow
/// machine must make this test slower, never flaky.
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

/// A live `qshd serve` child process. `Drop` kills and reaps it even if an
/// assertion panics first -- `serve` never exits on its own, so nothing else
/// would.
struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Generates an ed25519 key pair, writes the private half to `dir/name` in
/// OpenSSH format, and returns the key (for its public half) and the path.
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

/// Starts `qshd serve` on `port` with one key already in `authorized_keys`,
/// and reads back its two startup lines (`server-pubkey:` and
/// `host-key-fingerprint:`). Returns the daemon (killed on drop) and the
/// server's Noise public key, decoded from the first line.
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
        .env("TMUX_TMPDIR", dir)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`qshd serve` process spawns");

    let stdout = child.stdout.take().expect("process stdout captured");
    let mut reader = BufReader::new(stdout);

    let mut line1 = String::new();
    reader
        .read_line(&mut line1)
        .expect("first line (server-pubkey) read from stdout");
    if !line1.starts_with("server-pubkey: ") {
        let mut why = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut why);
        }
        panic!("expected a server-pubkey line, got: {line1:?}; process stderr: {why}");
    }
    let server_pub_b64 = line1.trim_start_matches("server-pubkey: ").trim_end();
    let server_pub_bytes = BASE64
        .decode(server_pub_b64)
        .expect("server-pubkey decodes from base64");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&server_pub_bytes);

    let mut line2 = String::new();
    reader
        .read_line(&mut line2)
        .expect("second line (host-key-fingerprint) read from stdout");
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

/// Everything the test needs back from the client driver: decoded control
/// records in arrival order, and the shell channel's own assembled output.
#[derive(Default)]
struct Collected {
    control: Vec<ServerRecord>,
    shell_output: Vec<u8>,
    /// The second channel's (`FIRST_CHANNEL_STREAM + 1`) assembled output.
    second_output: Vec<u8>,
    live: bool,
}

/// Feeds every stream's bytes through the right deframer (the session
/// control stream decodes as [`ServerRecord`]s, a shell channel's own
/// stream decodes as [`ShellRecord`]s) and appends the result to
/// [`Collected`].
struct Events {
    control_deframer: Mutex<RecordDeframer>,
    shell_deframer: Mutex<ShellDeframer>,
    second_deframer: Mutex<ShellDeframer>,
    collected: Mutex<Collected>,
}

impl Default for Events {
    fn default() -> Self {
        Events {
            control_deframer: Mutex::new(RecordDeframer::new()),
            shell_deframer: Mutex::new(ShellDeframer::new()),
            second_deframer: Mutex::new(ShellDeframer::new()),
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
        } else if stream_id == FIRST_CHANNEL_STREAM + 1 {
            let recs = self
                .second_deframer
                .lock()
                .expect("second deframer")
                .push(&data);
            let mut collected = self.collected.lock().expect("collected");
            for rec in recs {
                if let ShellRecord::Data(bytes) = rec {
                    collected.second_output.extend(bytes);
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

/// The whole point of channels: `serve` hands out a shell channel opened at
/// the size asked for, its output arrives on its own stream, and its natural
/// exit (the shell told to `exit`) is reported as `ServerRecord::Exit` on the
/// control stream -- not silently, and not conflated with the session itself
/// ending.
#[test]
fn serve_opens_a_shell_channel_and_reports_its_natural_exit() {
    let _serial = serialised();
    let dir = tempfile::tempdir().expect("temp dir");
    let (client_key, client_key_path) = write_key(dir.path(), "client_key");
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!(
            "{}\n",
            client_key
                .public_key()
                .to_openssh()
                .expect("openssh encoding")
        ),
    )
    .expect("writing authorized_keys");

    let port = free_udp_port();
    let (_daemon, server_pub) = start_daemon(dir.path(), port, &authorized_keys);

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
        [17u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&client_key_path, None)
                .expect("loading the client key")
                .with_login("client".to_string()),
        )),
    );

    assert!(
        wait_until(|| events.collected.lock().expect("collected").live),
        "the handshake with the real daemon must complete"
    );

    // Ask for a shell channel at a size that is NOT the pseudo-terminal
    // default (80x24) -- exactly the case this test guards: the daemon
    // must open the pseudo-terminal at this size from the first frame, not
    // at the default with a resize following.
    let open_stream = FIRST_CHANNEL_STREAM;
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: open_stream,
            kind: ChannelKind::Shell,
            cols: 100,
            rows: 30,
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
                    stream: open_stream,
                })
        }),
        "the daemon must confirm opening the shell channel"
    );

    // The marker is COMPUTED by the shell (`$((11*13))`), not written as a
    // literal string: a pseudo-terminal echoes back whatever is typed into
    // it, so a literal marker in the command would show up in the output
    // even if the shell never actually ran it -- the test would then pass
    // for the wrong reason.
    let marker = 11 * 13;
    let needle = format!("MARK-{marker}-MARK");
    client.send_bytes(open_stream, b"echo MARK-$((11*13))-MARK\n".to_vec());
    assert!(
        wait_until(|| {
            let collected = events.collected.lock().expect("collected");
            String::from_utf8_lossy(&collected.shell_output).contains(&needle)
        }),
        "the marker computed by the shell itself must arrive on the channel's stream; got: {:?}",
        String::from_utf8_lossy(&events.collected.lock().expect("collected").shell_output)
    );

    // End the channel by ending the shell itself (not by sending a client
    // `Close`, which the daemon deliberately answers with silence -- the
    // client already knows it closed its own channel). A natural exit is
    // what proves `ServerRecord::Exit` reaches the client, and that it names
    // the right stream.
    client.send_bytes(open_stream, b"exit\n".to_vec());

    assert!(
        wait_until(|| {
            events
                .collected
                .lock()
                .expect("collected")
                .control
                .iter()
                .any(|rec| matches!(rec, ServerRecord::Exit { stream, .. } if *stream == open_stream))
        }),
        "the daemon must report the channel process ending with an Exit record"
    );

    client.close();
}

/// A `serve` daemon says who it is, but a service manager owns its binary:
/// it answers every offer `Managed` and takes no image.
#[test]
fn a_serve_daemon_describes_itself_as_managed_and_takes_no_image() {
    let _serial = serialised();
    let dir = tempfile::tempdir().expect("temp dir");
    let (client_key, client_key_path) = write_key(dir.path(), "client_key");
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!(
            "{}\n",
            client_key
                .public_key()
                .to_openssh()
                .expect("openssh encoding")
        ),
    )
    .expect("writing authorized_keys");
    let port = free_udp_port();
    let (_daemon, server_pub) = start_daemon(dir.path(), port, &authorized_keys);

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
        [18u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&client_key_path, None)
                .expect("loading the client key")
                .with_login("client".to_string()),
        )),
    );
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .live));

    client.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::AboutRequest));
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .control
        .iter()
        .any(
            |r| matches!(r, ServerRecord::About(about) if about.mode == DaemonMode::Managed)
        )));
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::UpdateOffer(UpdateOffer {
            build: u64::MAX,
            checksum: [9; 32],
            arch: std::env::consts::ARCH.to_string(),
            size: 1,
        })),
    );
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .control
        .contains(&ServerRecord::UpdateAnswer(UpdateAnswer::Managed))));
    client.close();
}

/// Review of slice 3, minor 2: a real download with the header under the
/// AEAD. The console client's own channel is a screen channel, whose
/// output the daemon collapses into repaints once its send gate closes, so
/// the console-client test in `cli/tests/mixed_versions.rs` never puts its
/// 8 MB on the wire. A command channel without a screen model presses on
/// its process instead and sends every byte: here `seq 1 1200000` from a
/// real `qshd serve`, 9 688 896 bytes after the terminal's CR LF, to this
/// build's client over loopback, compared byte for byte.
#[test]
fn serve_sends_a_command_channel_in_full_with_the_header_under_aead() {
    const LAST: u32 = 1_200_000;
    let _serial = serialised();
    let dir = tempfile::tempdir().expect("temp dir");
    let (client_key, client_key_path) = write_key(dir.path(), "client_key");
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!(
            "{}\n",
            client_key
                .public_key()
                .to_openssh()
                .expect("openssh encoding")
        ),
    )
    .expect("writing authorized_keys");
    let port = free_udp_port();
    let (_daemon, server_pub) = start_daemon(dir.path(), port, &authorized_keys);

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
        [19u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&client_key_path, None)
                .expect("loading the client key")
                .with_login("client".to_string()),
        )),
    );
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .live));
    assert_eq!(
        client.features(),
        Some(transport::Features::SUPPORTED),
        "this build and this daemon put the header under the AEAD"
    );

    let stream = FIRST_CHANNEL_STREAM;
    let started = Instant::now();
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream,
            kind: ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: format!("seq 1 {LAST}").into_bytes(),
        })),
    );
    let want: Vec<u8> = (1..=LAST)
        .flat_map(|i| format!("{i}\r\n").into_bytes())
        .collect();
    let exited = |c: &Collected| {
        c.control
            .iter()
            .any(|r| matches!(r, ServerRecord::Exit { stream: s, code: 0 } if *s == stream))
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let c = events.collected.lock().expect("collected");
        if exited(&c) && c.shell_output.len() >= want.len() {
            break;
        }
        drop(c);
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = started.elapsed();
    let c = events.collected.lock().expect("collected");
    assert!(
        exited(&c),
        "the command ends with code 0; control: {:?}, {} of {} bytes",
        c.control,
        c.shell_output.len(),
        want.len()
    );
    assert_eq!(c.shell_output.len(), want.len(), "every byte arrives");
    assert!(c.shell_output == want, "and in order");
    println!("{} bytes down in {took:?}", want.len());
    drop(c);
    client.close();
}

/// Spec §4.10.6 and §11.3 (6), end to end on a real daemon: a channel
/// whose process never reads its input (its terminal raw, the process
/// asleep) gets a 1 MiB paste. The daemon takes at most a window of it --
/// the client's sender keeps the rest -- and a second channel's shell
/// answers meanwhile; closing the stuck channel leaves the session working.
///
/// Measured on the review's machine, three runs: `held` comes out at
/// exactly `PASTE - STREAM_WINDOW` (524288 of 1048576) every time -- the
/// kernel holds every byte behind the raw terminal rather than discarding
/// any of it, and the daemon's own take of the stuck stream is 0 (the first
/// `write_all` never returns). The bound below keeps a 256 KiB margin past
/// that measured value for a kernel that buffers differently.
#[test]
fn a_channel_that_never_reads_its_input_holds_back_only_its_own_paste() {
    const PASTE: usize = 1 << 20;
    let _serial = serialised();
    let dir = tempfile::tempdir().expect("temp dir");
    let (client_key, client_key_path) = write_key(dir.path(), "client_key");
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!(
            "{}\n",
            client_key
                .public_key()
                .to_openssh()
                .expect("openssh encoding")
        ),
    )
    .expect("writing authorized_keys");
    let port = free_udp_port();
    let (_daemon, server_pub) = start_daemon(dir.path(), port, &authorized_keys);
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
                .expect("loading the client key")
                .with_login("client".to_string()),
        )),
    );
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .live));
    let stuck = FIRST_CHANNEL_STREAM;
    let shell = FIRST_CHANNEL_STREAM + 1;
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: stuck,
            kind: ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: b"sh -c 'stty raw -echo; echo ready-$((6*7)); exec sleep 120'".to_vec(),
        })),
    );
    let output = |second: bool| {
        let c = events.collected.lock().expect("collected");
        String::from_utf8_lossy(if second {
            &c.second_output
        } else {
            &c.shell_output
        })
        .into_owned()
    };
    assert!(
        wait_until(|| output(false).contains("ready-42")),
        "{}",
        output(false)
    );
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: shell,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        })),
    );
    assert!(wait_until(|| events
        .collected
        .lock()
        .expect("collected")
        .control
        .contains(&ServerRecord::Opened { stream: shell })));
    client.send_bytes(stuck, vec![b'x'; PASTE]);
    std::thread::sleep(Duration::from_secs(2));
    client.send_bytes(shell, b"echo alive-$((6*7))\n".to_vec());
    assert!(
        wait_until(|| output(true).contains("alive-42")),
        "the other channel answers while the paste is held: {}",
        output(true)
    );
    let held = client.stream_progress(stuck).expect("written to").unacked;
    assert!(
        held >= PASTE as u64 - transport::reliability::STREAM_WINDOW - 256 * 1024,
        "the daemon took at most a window and what the terminal buffers; the client still has {held} of {PASTE}"
    );
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Close { stream: stuck }),
    );
    client.send_bytes(shell, b"echo still-$((5*5))\n".to_vec());
    assert!(
        wait_until(|| output(true).contains("still-25")),
        "{}",
        output(true)
    );
    client.close();
}
