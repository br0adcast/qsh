//! End-to-end: a REAL personal daemon (`qshd transport-ensure`) replaces
//! itself over qsh (spec `2026-09-23-qshd-update-over-qsh-design.md` §8):
//! the same pid, port and server key afterwards; a key that only ever came
//! through `ADD-CLIENT` still admitted; the new binary renamed onto the old
//! one's path; `STATUS` and `About` on the new build.
//!
//! The daemon runs from a copy in the test's own directory, never from
//! `target/debug/qshd`: the update renames the new binary over the one the
//! daemon runs from. The copy is stripped -- the debug build is larger than
//! `MAX_UPDATE_SIZE` with its debug info -- and "the newer build" is that
//! copy with bytes appended, labelled `L + 1` through the debug-only
//! `QSHD_TEST_BUILD_LABELS` (see `qshd::state::build_label`).
//!
//! Also here: how `main` treats `QSHD_HANDOVER_FD` -- a continuation only
//! under `transport-resume`, ignored under anything else, and a handover it
//! cannot read logged before the process gives up.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use qshd::control::{client_request, ControlReply, ControlRequest, StatusResponse};
use qshd::handover::HANDOVER_FD_ENV;
use qshd::state::{SelfCheck, TEST_BUILD_LABELS_ENV};
use transport::channel::{
    decode_server, encode_client, About, ChannelKind, ClientRecord, OpenRequest, RejectCode,
    ServerRecord, UpdateAnswer, UpdateOffer, UpdateResult, CONTROL_STREAM, FIRST_CHANNEL_STREAM,
    UPDATE_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::RecordDeframer;
use transport::{LinkState, Stats};

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

/// A stripped copy of qshd in a directory of its own.
struct Binaries {
    dir: tempfile::TempDir,
    bin: PathBuf,
    old: Vec<u8>,
}

fn stripped_qshd() -> Binaries {
    let dir = tempfile::tempdir().expect("binary dir");
    let bin = dir.path().join("qshd");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_qshd")), &bin);
    let status = Command::new("strip").arg(&bin).status().expect(
        "this test needs `strip` (binutils): the debug qshd is larger than MAX_UPDATE_SIZE \
         until its debug info is stripped",
    );
    assert!(status.success(), "strip failed on {}", bin.display());
    let old = std::fs::read(&bin).expect("read the copy");
    assert!(
        (old.len() as u64) < qshd::update::MAX_UPDATE_SIZE,
        "the stripped copy is {} bytes",
        old.len()
    );
    Binaries { dir, bin, old }
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

/// Every child of `pid`, over all its threads.
fn children_of(pid: u32) -> Vec<String> {
    let mut all = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).expect("the daemon's threads") {
        let path = task.expect("a thread").path().join("children");
        all.extend(
            std::fs::read_to_string(path)
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string),
        );
    }
    all
}

fn leftovers(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(".qshd-update-"))
        })
        .collect()
}

/// Start `transport-ensure` from `bin`, return the server's Noise key.
fn start_daemon(
    bin: &Path,
    home: &Path,
    port: u16,
    client_pub: [u8; 32],
    labels: &str,
) -> [u8; 32] {
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
        .env(TEST_BUILD_LABELS_ENV, labels)
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

#[test]
fn a_personal_daemon_replaces_itself_over_qsh_keeping_its_pid_port_key_and_clients() {
    let _serial = serialised();
    let bins = stripped_qshd();
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");

    let old_build = self_check(&bins.bin).build;
    let mut new_image = bins.old.clone();
    new_image.extend_from_slice(b"\0qshd-update-test-trailer\0");
    let new_sum = sha256(&new_image);
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(new_sum));

    let first = generate_keypair();
    let second = generate_keypair();
    let port = free_udp_port();
    // Before the daemon exists: whatever fails from here on, it is stopped.
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bins.bin, home.path(), port, first.public, &labels);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));
    // A key that only ever reached the daemon live, the way a phone's does
    // over SSH: nothing but the daemon's memory holds it.
    client_request(&sock, &ControlRequest::AddClient(second.public)).expect("ADD-CLIENT");
    let before = status(&sock).expect("STATUS");
    assert_eq!(before.build, old_build);
    assert_ne!(before.pid, 0);

    // A phone that opened a shell and went to sleep: its session is parked,
    // not active, and its shell is a child of the daemon. The replacement
    // must end and reap that shell rather than hand a child nobody waits
    // for to the new binary.
    let (sleeper, sleeper_events) = connect(home.path(), port, server_pub, second.private, [9; 16]);
    sleeper.send_bytes(
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
    assert!(wait_for(Duration::from_secs(15), || sleeper_events.has(
        |r| *r
            == ServerRecord::Opened {
                stream: FIRST_CHANNEL_STREAM
            }
    )));
    assert!(
        !children_of(before.pid).is_empty(),
        "the shell is the daemon's child"
    );
    sleeper.detach();
    assert!(
        wait_for(Duration::from_secs(20), || status(&sock)
            .is_some_and(|s| s.total_connections == 0)),
        "the sleeping session stops counting as active"
    );

    let (client, events) = connect(home.path(), port, server_pub, first.private, [1; 16]);
    assert_eq!(
        client.features(),
        Some(transport::Features::SUPPORTED),
        "the image goes up with the header under the AEAD"
    );
    assert_eq!(
        ask_about(home.path(), &client, &events).checksum,
        sha256(&bins.old)
    );
    offer(&client, &new_image, new_build);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    send_image(&client, &new_image);
    assert!(
        wait_for(Duration::from_secs(180), || events.has(
            |r| *r == ServerRecord::UpdateResult(UpdateResult::Restarting)
        )),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::Restarting)),
        "every session is told, the one that sent the image included"
    );
    client.detach();

    assert!(
        wait_for(Duration::from_secs(15), || status(&sock)
            .is_some_and(|s| s.build == new_build)),
        "the control socket answers with the new build; log:\n{}",
        daemon_log(home.path())
    );
    let after = status(&sock).expect("STATUS");
    // Spec §4.12: the socket the old binary bound and the new one took over
    // were each sized, and each said so.
    let sized = daemon_log(home.path())
        .matches("udp buffers: receive 4194304 requested")
        .count();
    assert!(
        sized >= 2,
        "both binaries log their buffers; log:\n{}",
        daemon_log(home.path())
    );
    assert_eq!(after.pid, before.pid, "the same process, replaced in place");
    assert_eq!(after.checksum, hex::encode(new_sum));
    assert_eq!(
        std::fs::read(&bins.bin).expect("read"),
        new_image,
        "the new binary took the old one's place"
    );
    assert!(leftovers(bins.dir.path()).is_empty());
    assert!(
        children_of(after.pid).is_empty(),
        "the parked session's shell was ended and reaped before the exec, not inherited"
    );

    // Same port, same server key: a client pinned to both logs in again.
    let (again, again_events) = connect(home.path(), port, server_pub, first.private, [2; 16]);
    let about = ask_about(home.path(), &again, &again_events);
    assert_eq!(about.checksum, new_sum);
    assert_eq!(about.build, new_build);
    again.close();

    let (other, other_events) = connect(home.path(), port, server_pub, second.private, [3; 16]);
    let _ = ask_about(home.path(), &other, &other_events);
    other.close();
}

/// Measurement, not a check (spec §9.4, §11.1): how long the image of a real
/// update takes to go over qsh on loopback -- from the first piece handed to
/// the client until the daemon has acknowledged every byte on
/// `UPDATE_STREAM`. Uses the qshd this test run built, stripped: debug by
/// default (the image the "~26 s" in the app's ROADMAP was about), optimized
/// with `--release --features test-build-labels`. The size is printed. Run
/// with `cargo test -p qshd [--release --features test-build-labels] --test
/// transport_ensure_update measure_the_image_upload_over_loopback --
/// --ignored --nocapture`.
#[test]
#[ignore = "timing measurement; run with --ignored --nocapture on a quiet machine"]
fn measure_the_image_upload_over_loopback() {
    let _serial = serialised();
    let bins = stripped_qshd();
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");

    let old_build = self_check(&bins.bin).build;
    let mut new_image = bins.old.clone();
    new_image.extend_from_slice(b"\0qshd-update-measurement-trailer\0");
    let new_sum = sha256(&new_image);
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(new_sum));

    let kp = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bins.bin, home.path(), port, kp.public, &labels);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));

    let (client, events) = connect(home.path(), port, server_pub, kp.private, [1; 16]);
    let _ = ask_about(home.path(), &client, &events);
    offer(&client, &new_image, new_build);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );

    let size = new_image.len() as u64;
    let started = Instant::now();
    send_image(&client, &new_image);
    assert!(
        wait_for(Duration::from_secs(300), || client
            .stream_progress(UPDATE_STREAM)
            .is_some_and(|p| p.queued == size && p.unacked == 0)),
        "the image was not acknowledged within five minutes; log:\n{}",
        daemon_log(home.path())
    );
    let elapsed = started.elapsed();
    println!(
        "image upload over loopback: {size} bytes in {:.2} s ({:.2} MiB/s)",
        elapsed.as_secs_f64(),
        size as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );

    // Let the update finish cleanly; the guard stops the daemon either way.
    assert!(wait_for(Duration::from_secs(180), || events.has(
        |r| *r == ServerRecord::UpdateResult(UpdateResult::Restarting)
    )));
    client.detach();
}

/// One update over qsh from `client_priv`'s session, to `image` labelled
/// `build`: offered, accepted, streamed, `Restarting` heard, and the control
/// socket answering with the new build afterwards.
fn update_once(
    home: &Path,
    port: u16,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
    image: &[u8],
    build: u64,
) {
    let sock = home.join("qsh").join("control.sock");
    let (client, events) = connect(home, port, server_pub, client_priv, token);
    assert_ne!(ask_about(home, &client, &events).checksum, sha256(image));
    offer(&client, image, build);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home)
    );
    send_image(&client, image);
    assert!(
        wait_for(Duration::from_secs(180), || events.has(
            |r| *r == ServerRecord::UpdateResult(UpdateResult::Restarting)
        )),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home)
    );
    client.detach();
    assert!(
        wait_for(Duration::from_secs(15), || status(&sock)
            .is_some_and(|s| s.build == build)),
        "the control socket answers with build {build}; log:\n{}",
        daemon_log(home)
    );
}

/// A daemon that resumed after an update takes the next one too: a second
/// update in a row from the resumed process -- same pid, same port, same
/// server key throughout, and a key that only ever came through
/// `ADD-CLIENT` (before the first update) still admitted after both.
#[test]
fn a_resumed_daemon_takes_a_second_update_in_a_row() {
    let _serial = serialised();
    let bins = stripped_qshd();
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");

    let old_build = self_check(&bins.bin).build;
    let mut second_image = bins.old.clone();
    second_image.extend_from_slice(b"\0qshd-update-test-second\0");
    let mut third_image = bins.old.clone();
    third_image.extend_from_slice(b"\0qshd-update-test-third\0");
    let (second_build, third_build) = (old_build + 1, old_build + 2);
    let labels = format!(
        "{}={second_build},{}={third_build}",
        hex::encode(sha256(&second_image)),
        hex::encode(sha256(&third_image))
    );

    let first = generate_keypair();
    let added = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bins.bin, home.path(), port, first.public, &labels);
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));
    client_request(&sock, &ControlRequest::AddClient(added.public)).expect("ADD-CLIENT");
    let before = status(&sock).expect("STATUS");
    assert_eq!(before.build, old_build);

    update_once(
        home.path(),
        port,
        server_pub,
        first.private,
        [1; 16],
        &second_image,
        second_build,
    );
    let between = status(&sock).expect("STATUS");
    assert_eq!(between.pid, before.pid);
    assert_eq!(between.checksum, hex::encode(sha256(&second_image)));

    // The second update comes over the key the resumed daemon only knows
    // from the handover.
    update_once(
        home.path(),
        port,
        server_pub,
        added.private,
        [2; 16],
        &third_image,
        third_build,
    );
    let after = status(&sock).expect("STATUS");
    assert_eq!(after.pid, before.pid, "still the same process");
    assert_eq!(after.checksum, hex::encode(sha256(&third_image)));
    assert_eq!(std::fs::read(&bins.bin).expect("read"), third_image);
    assert!(leftovers(bins.dir.path()).is_empty());

    for (key, token) in [(&first, [3; 16]), (&added, [4; 16])] {
        let (client, events) = connect(home.path(), port, server_pub, key.private, token);
        let about = ask_about(home.path(), &client, &events);
        assert_eq!(about.build, third_build);
        assert_eq!(about.checksum, sha256(&third_image));
        client.close();
    }
}

#[test]
fn an_image_that_fails_its_self_check_leaves_the_running_daemon_as_it_was() {
    let _serial = serialised();
    let bins = stripped_qshd();
    let home = tempfile::tempdir().expect("home");
    let sock = home.path().join("qsh").join("control.sock");
    let old_build = self_check(&bins.bin).build;

    let key = generate_keypair();
    let port = free_udp_port();
    let _guard = DaemonGuard::new(sock.clone());
    let server_pub = start_daemon(&bins.bin, home.path(), port, key.public, "");
    assert!(wait_for(Duration::from_secs(15), || status(&sock).is_some()));
    let before = status(&sock).expect("STATUS");

    let (client, events) = connect(home.path(), port, server_pub, key.private, [1; 16]);
    let mut garbage = vec![0u8; 4096];
    OsRng.fill_bytes(&mut garbage);
    offer(&client, &garbage, old_build + 1);
    assert!(
        wait_for(Duration::from_secs(15), || events
            .has(|r| *r == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );
    send_image(&client, &garbage);
    assert!(
        wait_for(Duration::from_secs(30), || events.has(|r| matches!(
            r,
            ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::SelfCheckFailed,
                ..
            })
        ))),
        "{:?}; log:\n{}",
        events.control(),
        daemon_log(home.path())
    );

    let after = status(&sock).expect("STATUS");
    assert_eq!(after.pid, before.pid);
    assert_eq!(after.checksum, before.checksum);
    assert_eq!(std::fs::read(&bins.bin).unwrap(), bins.old);
    assert!(leftovers(bins.dir.path()).is_empty());
    assert_eq!(
        ask_about(home.path(), &client, &events).checksum,
        sha256(&bins.old),
        "the same connection is still served by the same daemon"
    );
    client.close();
}

/// A file holding `contents`, open on a descriptor a child inherits.
fn inheritable_file(dir: &Path, contents: &[u8]) -> std::fs::File {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.join("handover.json"))
        .expect("a handover file");
    file.write_all(contents).expect("write it");
    file.seek(SeekFrom::Start(0)).expect("rewind");
    qshd::handover::set_cloexec(file.as_raw_fd(), false).expect("inheritable");
    file
}

/// A handover in a format this binary cannot read is refused -- and the
/// reason lands in the daemon's log, the only place anyone would look for a
/// daemon that vanished after an update.
#[test]
fn a_resume_with_an_unreadable_handover_logs_why_and_exits_non_zero() {
    let bins = tempfile::tempdir().expect("binary dir");
    let bin = bins.path().join("qshd");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_qshd")), &bin);
    let home = tempfile::tempdir().expect("home");
    let file = inheritable_file(
        home.path(),
        br#"{"handover_version":99,"udp_fd":{"not":"a number"}}"#,
    );
    let out = Command::new(&bin)
        .arg("transport-resume")
        .env(HANDOVER_FD_ENV, file.as_raw_fd().to_string())
        .env("XDG_CACHE_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env("TMUX_TMPDIR", home.path())
        .env_remove("TMUX")
        .output()
        .expect("qshd runs");
    assert!(!out.status.success(), "an unreadable handover is fatal");
    let log = daemon_log(home.path());
    assert!(log.contains("handover version 99"), "log:\n{log}");
}

/// Only `transport-resume` is a continuation: any other command run with a
/// stray `QSHD_HANDOVER_FD` -- one a shell inherited, say -- ignores it.
#[test]
fn a_handover_descriptor_is_ignored_by_every_other_command() {
    let bins = tempfile::tempdir().expect("binary dir");
    let bin = bins.path().join("qshd");
    copy_executable(Path::new(env!("CARGO_BIN_EXE_qshd")), &bin);
    let home = tempfile::tempdir().expect("home");
    let file = inheritable_file(home.path(), b"not a handover at all");
    let out = Command::new(&bin)
        .arg("self-check")
        .env(HANDOVER_FD_ENV, file.as_raw_fd().to_string())
        .env("XDG_CACHE_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .output()
        .expect("qshd runs");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(SelfCheck::from_line(String::from_utf8_lossy(&out.stdout).trim()).is_ok());
}

/// `transport-resume` without a handover is not a daemon of any kind.
#[test]
fn a_resume_without_a_handover_is_refused() {
    let home = tempfile::tempdir().expect("home");
    let out = Command::new(env!("CARGO_BIN_EXE_qshd"))
        .arg("transport-resume")
        .env_remove(HANDOVER_FD_ENV)
        .env("XDG_CACHE_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .output()
        .expect("qshd runs");
    assert!(!out.status.success());
    assert!(
        daemon_log(home.path()).contains(HANDOVER_FD_ENV),
        "log:\n{}",
        daemon_log(home.path())
    );
}
