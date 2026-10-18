//! Spec §9.3 (2): this build against the build from before negotiation
//! (`ab40ae6`, the qshd the app ships today), with real binaries. Ignored:
//! run before the app's submodule pointer moves, with the old qshd built from
//! `ab40ae6` in a clone of its own (or the app's `qshd-0.2.0-x86_64`, the
//! same commit):
//!
//! `QSH_OLD_QSHD=<old qshd> cargo test -p qshd --test mixed_versions -- --ignored --nocapture --test-threads=1`
//!
//! Here: this build's client against an old personal daemon -- it signs in
//! and works in the old mode -- and the old daemon updated over qsh to this
//! build, after which the same client negotiates; and the same image through
//! a road that reorders past the old daemon's replay window of 64. The
//! console client's pairs are in `cli/tests/mixed_versions.rs`.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use qshd::control::{client_request, ControlReply, ControlRequest, StatusResponse};
use qshd::state::{SelfCheck, TEST_BUILD_LABELS_ENV};
use transport::channel::{
    decode_server, encode_client, About, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    UpdateAnswer, UpdateOffer, UpdateResult, CONTROL_STREAM, FIRST_CHANNEL_STREAM, UPDATE_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::RecordDeframer;
use transport::{Features, LinkState, Stats};

// The copies of `qshd` these tests run are made by a child process, never
// with `std::fs::copy`: see the module for the "Text file busy" it avoids.
mod executable_copy;
use executable_copy::copy_executable;

mod daemon_guard;
use daemon_guard::DaemonGuard;

/// Serialised for the same reason as `transport_ensure.rs`: real ports
/// picked by binding and closing.
static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("an ephemeral port")
        .local_addr()
        .expect("its address")
        .port()
}

fn wait_for(timeout: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// The daemon's own log, for failure messages.
fn daemon_log(home: &Path) -> String {
    std::fs::read_to_string(home.join("qsh").join("qshd.log")).unwrap_or_default()
}

fn self_check(bin: &Path) -> SelfCheck {
    let out = Command::new(bin)
        .arg("self-check")
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .env_remove(TEST_BUILD_LABELS_ENV)
        .output()
        .expect("self-check runs");
    assert!(out.status.success());
    SelfCheck::from_line(String::from_utf8_lossy(&out.stdout).lines().next().unwrap())
        .expect("a self-check line")
}

/// Start `transport-ensure` from `bin`, return the server's Noise key.
fn start_daemon(bin: &Path, home: &Path, port: u16, client_pub: [u8; 32]) -> [u8; 32] {
    let mut child = Command::new(bin)
        .args([
            "transport-ensure",
            "--name",
            "main",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            &BASE64.encode(client_pub),
        ])
        .env("XDG_CACHE_HOME", home)
        .env("HISTFILE", "/dev/null")
        .env("TMUX_TMPDIR", home)
        .env_remove("TMUX")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("transport-ensure starts");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line1 = String::new();
    reader.read_line(&mut line1).expect("first line");
    if !line1.starts_with("server-pubkey: ") {
        let mut why = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut why);
        }
        panic!("expected a server-pubkey line, got {line1:?}; stderr: {why}");
    }
    let raw = BASE64
        .decode(line1.trim_start_matches("server-pubkey: ").trim_end())
        .expect("base64");
    let mut line2 = String::new();
    reader.read_line(&mut line2).expect("second line");
    assert!(line2.starts_with("TRANSPORT-READY "), "{line2:?}");
    assert!(child.wait().expect("parent exits").success());
    raw.try_into().expect("32 bytes")
}

fn status(sock: &Path) -> Option<StatusResponse> {
    match client_request(sock, &ControlRequest::Status) {
        Ok(ControlReply::Answered(line)) => StatusResponse::from_line(&line).ok(),
        _ => None,
    }
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
struct Records {
    control: Vec<ServerRecord>,
    live: bool,
}

#[derive(Default)]
struct Events {
    deframer: Mutex<RecordDeframer>,
    records: Mutex<Records>,
}

impl Events {
    fn has(&self, want: impl Fn(&ServerRecord) -> bool) -> bool {
        self.records.lock().unwrap().control.iter().any(want)
    }

    fn control(&self) -> Vec<ServerRecord> {
        self.records.lock().unwrap().control.clone()
    }
}

impl ClientEvents for Events {
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id != CONTROL_STREAM {
            return;
        }
        let raws = self.deframer.lock().unwrap().push(&data);
        let mut records = self.records.lock().unwrap();
        for raw in raws {
            if let Ok(rec) = decode_server(&raw) {
                records.control.push(rec);
            }
        }
    }
    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.records.lock().unwrap().live = true;
        }
    }
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

/// Log in by allowlist and wait for the link. Live on the allowlist path
/// means admitted: a key the daemon does not know never gets a msg2.
fn connect(
    home: &Path,
    port: u16,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
) -> (StdClient, Arc<Events>) {
    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
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
        wait_for(Duration::from_secs(15), || events
            .records
            .lock()
            .unwrap()
            .live),
        "the daemon must admit this key; log:\n{}",
        daemon_log(home)
    );
    (client, events)
}

fn ask_about(home: &Path, client: &StdClient, events: &Events) -> About {
    let before = events.control().len();
    client.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::AboutRequest));
    let mut found = None;
    assert!(
        wait_for(Duration::from_secs(15), || {
            found = events.control()[before..].iter().find_map(|r| match r {
                ServerRecord::About(a) => Some(a.clone()),
                _ => None,
            });
            found.is_some()
        }),
        "the daemon must answer About; log:\n{}",
        daemon_log(home)
    );
    found.unwrap()
}

fn offer(client: &StdClient, image: &[u8], build: u64) {
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::UpdateOffer(UpdateOffer {
            build,
            checksum: sha256(image),
            arch: std::env::consts::ARCH.to_string(),
            size: image.len() as u64,
        })),
    );
}

fn send_image(client: &StdClient, image: &[u8]) {
    for chunk in image.chunks(64 * 1024) {
        client.send_bytes(UPDATE_STREAM, chunk.to_vec());
    }
}

/// The old qshd, copied into a directory of its own: an update renames the
/// new binary over the one the daemon runs from.
fn old_qshd_copy() -> (tempfile::TempDir, PathBuf) {
    let from = std::env::var("QSH_OLD_QSHD")
        .expect("QSH_OLD_QSHD names the qshd built from ab40ae6 (see the module doc)");
    let dir = tempfile::tempdir().expect("binary dir");
    let bin = dir.path().join("qshd");
    copy_executable(Path::new(&from), &bin);
    (dir, bin)
}

/// This build's qshd as an update image: stripped, since the debug build is
/// larger than `MAX_UPDATE_SIZE` with its debug info.
fn this_qshd_image() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().expect("image dir");
    let path = dir.path().join("qshd");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_qshd")), &path);
    let status = Command::new("strip")
        .arg(&path)
        .status()
        .expect("this test needs `strip` (binutils)");
    assert!(status.success());
    let bytes = std::fs::read(&path).expect("read the image");
    assert!((bytes.len() as u64) < qshd::update::MAX_UPDATE_SIZE);
    (dir, path, bytes)
}

/// §8.1, row 2: this build's client signs in to an old personal daemon, in
/// the old mode, and a channel opens.
#[test]
#[ignore = "needs QSH_OLD_QSHD, the qshd built from ab40ae6; see the module doc"]
fn this_client_signs_in_to_an_old_personal_daemon_in_the_old_mode() {
    let _serial = serialised();
    let (_bin_dir, bin) = old_qshd_copy();
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");
    let kp = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bin, home.path(), port, kp.public);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));

    let (client, events) = connect(home.path(), port, server_pub, kp.private, [1; 16]);
    assert_eq!(
        client.features(),
        Some(Features::NONE),
        "an old daemon enables nothing"
    );
    let _ = ask_about(home.path(), &client, &events);
    client.send_bytes(
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
        wait_for(Duration::from_secs(15), || events.has(|r| *r
            == ServerRecord::Opened {
                stream: FIRST_CHANNEL_STREAM
            })),
        "log:\n{}",
        daemon_log(home.path())
    );
    client.close();
}

/// §8.1, row 2 and device acceptance 4: an old personal daemon takes this
/// build over qsh -- the image goes up in the old mode -- and the same key
/// then negotiates with the daemon it became.
#[test]
#[ignore = "needs QSH_OLD_QSHD, the qshd built from ab40ae6; see the module doc"]
fn an_old_personal_daemon_takes_this_build_over_qsh_and_then_negotiates() {
    let _serial = serialised();
    let (_bin_dir, bin) = old_qshd_copy();
    let (_image_dir, image_path, image) = this_qshd_image();
    let new_build = self_check(&image_path).build;
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");
    let kp = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bin, home.path(), port, kp.public);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));

    let (client, events) = connect(home.path(), port, server_pub, kp.private, [1; 16]);
    assert_eq!(client.features(), Some(Features::NONE));
    let old = ask_about(home.path(), &client, &events);
    assert!(old.build < new_build, "this build is newer than ab40ae6");
    offer(&client, &image, new_build);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    send_image(&client, &image);
    assert!(
        wait_for(Duration::from_secs(180), || events.has(
            |r| *r == ServerRecord::UpdateResult(UpdateResult::Restarting)
        )),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    client.detach();
    assert!(
        wait_for(Duration::from_secs(15), || status(&sock)
            .is_some_and(|s| s.build == new_build)),
        "the daemon is this build now; log:\n{}",
        daemon_log(home.path())
    );

    let (again, again_events) = connect(home.path(), port, server_pub, kp.private, [2; 16]);
    assert_eq!(
        again.features(),
        Some(Features::SUPPORTED),
        "after the update the same daemon negotiates"
    );
    assert_eq!(
        ask_about(home.path(), &again, &again_events).build,
        new_build
    );
    again.close();
}

/// What passed a [`Relay`], in datagrams.
#[derive(Clone, Copy, Debug, Default)]
struct Passed {
    /// Client to daemon, all of them.
    up: u64,
    /// Client to daemon, of at least [`LARGE`] bytes: the image's DATA.
    up_large: u64,
    /// Of those, held back behind [`HOLD_BEHIND`] later ones.
    held: u64,
    /// Daemon to client.
    down: u64,
}

/// A datagram this large towards the daemon carries the image.
const LARGE: usize = 1000;
/// Every this many large datagrams, one is held back...
const HOLD_EVERY: u64 = 25;
/// ...until this many more have passed it: further back than an old
/// receiver's replay window of 64 reaches.
const HOLD_BEHIND: u64 = 100;

/// A loopback road between a client and a daemon that holds every
/// [`HOLD_EVERY`]-th large datagram towards the daemon back behind
/// [`HOLD_BEHIND`] later ones, and counts what passes each way. A daemon
/// from before this slice discards such a datagram as a replay, so its
/// bytes have to be sent again; a daemon of this build (a window of 32 704)
/// would take it late.
struct Relay {
    port: u16,
    stop: Arc<AtomicBool>,
    passed: Arc<Mutex<Passed>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Relay {
    fn start(daemon_port: u16) -> Relay {
        let front = UdpSocket::bind(("127.0.0.1", 0)).expect("the relay's front");
        let back = UdpSocket::bind(("127.0.0.1", 0)).expect("the relay's back");
        back.connect(("127.0.0.1", daemon_port))
            .expect("towards the daemon");
        for s in [&front, &back] {
            s.set_read_timeout(Some(Duration::from_millis(50)))
                .expect("a read timeout");
        }
        let port = front.local_addr().expect("the front's address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let passed = Arc::new(Mutex::new(Passed::default()));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();

        let up = {
            let (front, back) = (front.try_clone().unwrap(), back.try_clone().unwrap());
            let (stop, passed, client) = (stop.clone(), passed.clone(), client.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                let mut held: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
                while !stop.load(Ordering::SeqCst) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        // Quiet: what is held goes now, late.
                        for (_, late) in held.drain(..) {
                            let _ = back.send(&late);
                        }
                        continue;
                    };
                    *client.lock().unwrap() = Some(from);
                    let mut p = passed.lock().unwrap();
                    p.up += 1;
                    if n >= LARGE {
                        p.up_large += 1;
                        if p.up_large % HOLD_EVERY == 0 {
                            p.held += 1;
                            held.push_back((p.up + HOLD_BEHIND, buf[..n].to_vec()));
                            continue;
                        }
                    }
                    let up = p.up;
                    drop(p);
                    let _ = back.send(&buf[..n]);
                    while held.front().is_some_and(|(after, _)| *after <= up) {
                        let (_, late) = held.pop_front().unwrap();
                        let _ = back.send(&late);
                    }
                }
            })
        };
        let down = {
            let (front, back) = (front, back);
            let (stop, passed) = (stop.clone(), passed.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::SeqCst) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let Some(to) = *client.lock().unwrap() else {
                        continue;
                    };
                    passed.lock().unwrap().down += 1;
                    let _ = front.send_to(&buf[..n], to);
                }
            })
        };
        Relay {
            port,
            stop,
            passed,
            threads: vec![up, down],
        }
    }

    fn passed(&self) -> Passed {
        *self.passed.lock().unwrap()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// §8.1, row 2, with the old side's replay window of 64 and its ACK for
/// every DATA met by this build's sender (spec §9.3; the in-process old
/// peer models neither). The road holds every 25th datagram of the image
/// behind 100 later ones, so the old daemon discards it and the client
/// sends its bytes again; the image still arrives whole -- the daemon
/// checks its sha256 before it restarts. The old daemon answers each DATA
/// it takes with an ACK of its own, one datagram each, and the datagrams
/// held past its window draw none: that is what the counts on the road
/// show.
#[test]
#[ignore = "needs QSH_OLD_QSHD, the qshd built from ab40ae6; see the module doc"]
fn an_old_daemon_takes_this_build_through_a_road_that_reorders_past_its_replay_window() {
    let _serial = serialised();
    let (_bin_dir, bin) = old_qshd_copy();
    let (_image_dir, image_path, image) = this_qshd_image();
    let new_build = self_check(&image_path).build;
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");
    let kp = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bin, home.path(), port, kp.public);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));
    let relay = Relay::start(port);

    let (client, events) = connect(home.path(), relay.port, server_pub, kp.private, [1; 16]);
    assert_eq!(client.features(), Some(Features::NONE));
    let _ = ask_about(home.path(), &client, &events);
    offer(&client, &image, new_build);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    let before = relay.passed();
    let started = Instant::now();
    send_image(&client, &image);
    assert!(
        wait_for(Duration::from_secs(180), || events.has(
            |r| *r == ServerRecord::UpdateResult(UpdateResult::Restarting)
        )),
        "{:?}; {:?}; log:\n{}",
        events.control(),
        relay.passed(),
        daemon_log(home.path())
    );
    let took = started.elapsed();
    let after = relay.passed();
    client.detach();

    let data = after.up_large - before.up_large;
    let held = after.held - before.held;
    let answers = after.down - before.down;
    println!(
        "{} image bytes in {took:?}: {data} large datagrams up ({held} held back \
         past the window), {answers} datagrams down",
        image.len()
    );
    assert!(
        held > 0,
        "the road pushed datagrams out of the window: {after:?}"
    );
    assert!(
        data > image.len() as u64 / 1500,
        "the image went up in datagrams: {after:?}"
    );
    assert!(
        answers >= (data - held) * 9 / 10,
        "the old daemon answers every DATA it takes: {answers} for {data}"
    );
    assert!(
        answers + held / 2 <= data,
        "the datagrams held past its window draw no answer: {answers} for {data}, {held} held"
    );
    assert!(
        wait_for(Duration::from_secs(15), || status(&sock)
            .is_some_and(|s| s.build == new_build)),
        "the daemon is this build now; log:\n{}",
        daemon_log(home.path())
    );
}
