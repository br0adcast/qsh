//! Comprehensive upgrade and protocol-compatibility test matrix for console `qsh`.
//!
//! Covers:
//! - Scenario 1: older `qshd` with an attached client (same protocol vs
//!   incompatible protocol, session-preserving vs non-preserving, with and
//!   without SSH, legacy daemon without `About.os`, `Managed` daemon, TOCTOU
//!   busy race, multi-endpoint dialog deduplication, and survival of the
//!   attached client's live shell session).
//! - Scenario 2: newer `qshd` server (compatible vs incompatible protocol,
//!   upgrade offer eligibility, no daemon downgrade, multi-endpoint
//!   deduplication).
//! - Scenario 3: older `qshd` without attached clients (idle update omits busy
//!   prompts, updates once, and second connect is idempotent).
use crate::install_fixture_tests::support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use support::*;

const CHILD_ENTRY: &str = "upgrade_matrix_tests::matrix_fixture_child_entry";
const RECORD_ENV: &str = "QSH_UPGRADE_MATRIX_FIXTURE_RECORD";
const MAX_IMAGE: u64 = 64 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixFixtureRecord {
    args: Vec<String>,
    image: PathBuf,
    size: u64,
    sha256: [u8; 32],
    client_version: String,
    client_build: u64,
    marker: PathBuf,
}

struct Screen(Arc<Mutex<Vec<u8>>>);
impl Screen {
    fn of(client: &Client) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        drain_into(client.master.try_clone().unwrap(), seen.clone());
        Self(seen)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn wait(&self, needle: &str) {
        assert!(
            wait_until(|| self.text().contains(needle)),
            "missing {needle:?} in screen:\n{}",
            self.text()
        );
    }
    fn wait_within(&self, timeout: Duration, needle: &str) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        self.text().contains(needle)
    }
}

struct PersonalDaemonGuard {
    sock: PathBuf,
}
impl Drop for PersonalDaemonGuard {
    fn drop(&mut self) {
        let _ = Command::new(qshd_path())
            .args(["transport-stop", "--socket"])
            .arg(&self.sock)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn private_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn make_key(home: &Path) -> (PathBuf, String) {
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let path = home.join("identity");
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    drop(file);
    (path, key.public_key().to_openssh().unwrap())
}

fn copy_stripped_qshd(dir: &Path, name: &str) -> (PathBuf, Vec<u8>) {
    let dst = dir.join(name);
    let status = Command::new("cp")
        .arg(qshd_path())
        .arg(&dst)
        .status()
        .expect("cp qshd");
    assert!(status.success());
    let status = Command::new("strip")
        .arg(&dst)
        .status()
        .expect("strip qshd");
    assert!(status.success());
    let bytes = std::fs::read(&dst).unwrap();
    (dst, bytes)
}

fn read_build_label(bin: &Path) -> u64 {
    let out = Command::new(bin)
        .arg("self-check")
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .env_remove("QSHD_TEST_BUILD_LABELS")
        .output()
        .expect("self-check");
    assert!(out.status.success());
    let line = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    json["build"].as_u64().unwrap()
}

fn start_personal_daemon(
    bin: &Path,
    server_home: &Path,
    port: u16,
    authorized_pubkey: &str,
    labels: &str,
) -> ([u8; 32], PersonalDaemonGuard) {
    let ssh_dir = server_home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let auth_keys = ssh_dir.join("authorized_keys");
    std::fs::write(&auth_keys, format!("{authorized_pubkey}\n")).unwrap();
    std::fs::set_permissions(&auth_keys, std::fs::Permissions::from_mode(0o600)).unwrap();

    let dummy_kp = transport::generate_keypair();
    let sock = server_home.join("qsh/control.sock");
    let mut child = Command::new(bin)
        .args([
            "transport-ensure",
            "--name",
            "main",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            &BASE64.encode(dummy_kp.public),
        ])
        .env("HOME", server_home)
        .env("XDG_CACHE_HOME", server_home)
        .env("XDG_CONFIG_HOME", server_home)
        .env("SHELL", "/bin/sh")
        .env("HISTFILE", "/dev/null")
        .env("TMUX_TMPDIR", server_home)
        .env_remove("TMUX")
        .env("QSHD_TEST_BUILD_LABELS", labels)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("transport-ensure starts");

    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut line1 = String::new();
    reader.read_line(&mut line1).unwrap();
    let raw = BASE64
        .decode(
            line1
                .trim_end()
                .strip_prefix("server-pubkey: ")
                .unwrap_or_else(|| panic!("expected server-pubkey line, got {line1:?}")),
        )
        .unwrap();
    let mut line2 = String::new();
    reader.read_line(&mut line2).unwrap();
    assert!(line2.starts_with("TRANSPORT-READY "), "got {line2:?}");
    assert!(child.wait().unwrap().success());
    let key = <[u8; 32]>::try_from(raw).unwrap();
    let guard = PersonalDaemonGuard { sock: sock.clone() };
    assert!(
        wait_until(|| query_daemon_build(&sock).is_some()),
        "personal daemon control socket did not answer STATUS"
    );
    (key, guard)
}

fn query_daemon_build(sock: &Path) -> Option<u64> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(sock).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.write_all(b"STATUS\n").ok()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).ok()?;
    let json: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    json["build"].as_u64()
}

fn pin_server_key(client_home: &Path, port: u16, key: &[u8; 32]) {
    let store = sshauth::known_hosts::KnownHosts::open(client_home.join("qsh/known_hosts"));
    crate::trust::remember_proven("127.0.0.1", port, key, &store).unwrap();
}

fn mark(path: &Path, event: &str) {
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap(),
        "{event}"
    )
    .unwrap();
}

fn load_count(home: &Path) -> usize {
    std::fs::read_to_string(home.join("fixture-marker"))
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "load")
        .count()
}

fn spawn_matrix_fixture(
    args: &[&str],
    client_home: &Path,
    new_image: &Path,
    new_bytes: &[u8],
    client_version: &str,
    client_build: u64,
) -> (Client, Screen) {
    let record = MatrixFixtureRecord {
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        image: new_image.to_path_buf(),
        size: new_bytes.len() as u64,
        sha256: sha256(new_bytes),
        client_version: client_version.to_owned(),
        client_build,
        marker: client_home.join("fixture-marker"),
    };
    let record_path = client_home.join("matrix-fixture.json");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_ENTRY, "--nocapture", "--test-threads=1"])
        .env(RECORD_ENV, record_path);
    let (client, _slave) = spawn_command_on(command, client_home, &qshd_path(), 80, 24);
    let screen = Screen::of(&client);
    (client, screen)
}

struct MatrixLocalImage(MatrixFixtureRecord);
impl bringup::ImageSource for MatrixLocalImage {
    fn load(
        &self,
        request: &bringup::ImageRequest,
        _: &bringup::InstallTiming,
        cancel: &knock::Cancel,
        _: &dyn bringup::BringUpObserver,
    ) -> Result<bringup::DaemonImage, bringup::ImageError> {
        use bringup::ImageError;
        if cancel.is_cancelled() {
            return Err(ImageError::Cancelled);
        }
        request
            .validate()
            .map_err(|e| ImageError::Invalid(e.to_string()))?;
        let platform =
            bringup::Platform::from_rust_consts("linux", std::env::consts::ARCH).unwrap();
        if request.version != self.0.client_version || request.platform != platform {
            return Err(ImageError::Invalid("fixture request mismatch".into()));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&self.0.image)
            .map_err(|e| ImageError::Invalid(e.to_string()))?
            .take(MAX_IMAGE + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| ImageError::Invalid(e.to_string()))?;
        if bytes.len() as u64 != self.0.size || sha256(&bytes) != self.0.sha256 {
            return Err(ImageError::Checksum);
        }
        mark(&self.0.marker, "load");
        Ok(bringup::DaemonImage {
            request: request.clone(),
            size: self.0.size,
            sha256: self.0.sha256,
            bytes: bytes.into(),
        })
    }
}

#[test]
fn matrix_fixture_child_entry() {
    let Some(path) = std::env::var_os(RECORD_ENV) else {
        return;
    };
    let record: MatrixFixtureRecord =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let args = record.args.iter().map(std::ffi::OsString::from).collect();
    mark(&record.marker, "entry");
    crate::daemon_update::set_test_release_identity(
        Some(record.client_version.clone()),
        Some(record.client_build),
    );
    crate::climb::set_test_images(Arc::new(MatrixLocalImage(record)));
    crate::cli_entry::entry(args);
}

fn prepare_old_and_new_daemon(
    bin_dir: &Path,
    tag: &str,
) -> (PathBuf, u64, PathBuf, Vec<u8>, u64, String) {
    let (old_bin, old_bytes) = copy_stripped_qshd(bin_dir, "qshd");
    let old_build = read_build_label(&old_bin);
    let mut new_bytes = old_bytes;
    new_bytes.extend_from_slice(format!("\0matrix-{tag}\0").as_bytes());
    let new_image = bin_dir.join("qshd-new");
    std::fs::write(&new_image, &new_bytes).unwrap();
    std::fs::set_permissions(&new_image, std::fs::Permissions::from_mode(0o755)).unwrap();
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(sha256(&new_bytes)));
    (old_bin, old_build, new_image, new_bytes, new_build, labels)
}

fn wait_shell_ready(client: &mut Client, screen: &Screen, command: &str, token: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        client.type_line(command);
        if screen.wait_within(Duration::from_secs(2), token) {
            return;
        }
    }
    panic!("shell never produced {token:?}:\n{}", screen.text());
}

// ---------------------------------------------------------------------------
// Scenario 1: older qshd WITH an attached client
// ---------------------------------------------------------------------------

#[test]
fn scenario1_busy_same_proto_preserving_updates_once_and_preserves_old_client_session() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();
    let second_home = private_dir();
    let other_home = private_dir();

    let (old_bin, old_build, new_image, new_bytes, new_build, labels) =
        prepare_old_and_new_daemon(bin_dir.path(), "s1-preserve");
    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);
    pin_server_key(second_home.path(), port, &server_pub);
    pin_server_key(other_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut other, other_screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        other_home.path(),
        &new_image,
        &new_bytes,
        env!("CARGO_PKG_VERSION"),
        old_build,
    );
    wait_shell_ready(
        &mut other,
        &other_screen,
        "QSH_MATRIX_SURVIVE=alive_marker_42; echo READY_'OK'",
        "READY_OK",
    );

    let (mut client, screen) = spawn_matrix_fixture(
        &["--verbose", "-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("currently has 1 other active client");
    screen.wait("Update qshd now? [y/N]");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Uploading qshd");
    screen.wait("updated qshd");

    wait_shell_ready(&mut client, &screen, "echo NEW_SHELL_'OK'", "NEW_SHELL_OK");

    let text = screen.text();
    assert_eq!(text.matches("Update qshd to 9.9.9?").count(), 1, "{text}");
    assert_eq!(text.matches("Update qshd now? [y/N]").count(), 1, "{text}");
    assert_eq!(load_count(client_home.path()), 1);

    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(new_build));

    // Verify the previously connected client automatically reattached after
    // SESSION_RESET and its shell environment variable survived the upgrade.
    wait_shell_ready(
        &mut other,
        &other_screen,
        "echo SURVIVED:$QSH_MATRIX_SURVIVE",
        "SURVIVED:alive_marker_42",
    );

    // A subsequent login to the upgraded daemon must neither prompt nor re-upload.
    let (mut second, second_screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        second_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );
    wait_shell_ready(
        &mut second,
        &second_screen,
        "echo SECOND_NO_PROMPT_'OK'",
        "SECOND_NO_PROMPT_OK",
    );
    assert!(
        !second_screen.text().contains("Update qshd"),
        "second connect must not re-prompt:\n{}",
        second_screen.text()
    );
    assert_eq!(load_count(second_home.path()), 0);

    second.type_line("exit");
    assert!(wait_for_exit(&mut second.child).unwrap().success());
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    other.type_line("exit");
    assert!(wait_for_exit(&mut other.child).unwrap().success());
}

#[test]
fn scenario1_busy_same_proto_declining_disrupt_keeps_old_daemon_and_client() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();
    let other_home = private_dir();

    let (old_bin, old_build, new_image, new_bytes, new_build, labels) =
        prepare_old_and_new_daemon(bin_dir.path(), "s1-decline-disrupt");
    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);
    pin_server_key(other_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut other, other_screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        other_home.path(),
        &new_image,
        &new_bytes,
        env!("CARGO_PKG_VERSION"),
        old_build,
    );
    wait_shell_ready(
        &mut other,
        &other_screen,
        "QSH_MATRIX_KEEP=kept_77; echo OTHER_'OK'",
        "OTHER_OK",
    );

    let (mut client, screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("currently has 1 other active client");
    screen.wait("Update qshd now? [y/N]");
    client.master.write_all(b"no\n").unwrap();
    screen.wait("keeping the running qshd");

    wait_shell_ready(
        &mut client,
        &screen,
        "echo KEPT_OLD_SESSION_'OK'",
        "KEPT_OLD_SESSION_OK",
    );
    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(old_build));
    wait_shell_ready(
        &mut other,
        &other_screen,
        "echo STILL:$QSH_MATRIX_KEEP",
        "STILL:kept_77",
    );

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    other.type_line("exit");
    assert!(wait_for_exit(&mut other.child).unwrap().success());
}

#[test]
fn scenario1_busy_same_proto_declining_initial_prompt_skips_download_and_disrupt_prompt() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();
    let other_home = private_dir();

    let (old_bin, old_build, new_image, new_bytes, new_build, labels) =
        prepare_old_and_new_daemon(bin_dir.path(), "s1-decline-initial");
    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);
    pin_server_key(other_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut other, other_screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        other_home.path(),
        &new_image,
        &new_bytes,
        env!("CARGO_PKG_VERSION"),
        old_build,
    );
    wait_shell_ready(&mut other, &other_screen, "echo OTHER_'OK'", "OTHER_OK");

    let (mut client, screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"no\n").unwrap();
    wait_shell_ready(&mut client, &screen, "echo DIRECT_'OK'", "DIRECT_OK");

    let text = screen.text();
    assert_eq!(text.matches("Update qshd to 9.9.9?").count(), 1, "{text}");
    assert!(
        !text.contains("other active client"),
        "declining initial offer must not ask disrupt question:\n{text}"
    );
    assert_eq!(load_count(client_home.path()), 0);
    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(old_build));

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    other.type_line("exit");
    assert!(wait_for_exit(&mut other.child).unwrap().success());
}

#[test]
fn scenario1_multi_endpoint_deduplicates_dialog_and_updates_at_most_once() {
    let _serial = serialised();
    for accept in [false, true] {
        let bin_dir = private_dir();
        let server_home = private_dir();
        let client_home = private_dir();

        let (old_bin, old_build, new_image, new_bytes, new_build, labels) =
            prepare_old_and_new_daemon(
                bin_dir.path(),
                if accept { "multi-yes" } else { "multi-no" },
            );
        let (key_path, pubkey) = make_key(client_home.path());
        let dead_port = free_udp_port();
        let live_port = free_udp_port();
        let (server_pub, _guard) =
            start_personal_daemon(&old_bin, server_home.path(), live_port, &pubkey, &labels);
        pin_server_key(client_home.path(), live_port, &server_pub);

        let dead_addr = format!("127.0.0.1:{dead_port},nossh");
        let live_addr = format!("127.0.0.1:{live_port},nossh");
        let (mut client, screen) = spawn_matrix_fixture(
            &[
                "-i",
                key_path.to_str().unwrap(),
                &dead_addr,
                &live_addr,
                &live_addr,
            ],
            client_home.path(),
            &new_image,
            &new_bytes,
            "9.9.9",
            new_build,
        );

        screen.wait("Update qshd to 9.9.9?");
        client
            .master
            .write_all(if accept { b"yes\n" } else { b"no\n" })
            .unwrap();
        if accept {
            screen.wait("updated qshd");
        }
        wait_shell_ready(&mut client, &screen, "echo MULTI_'OK'", "MULTI_OK");

        let text = screen.text();
        assert_eq!(
            text.matches("Update qshd to 9.9.9?").count(),
            1,
            "multi-endpoint accept={accept} duplicated update prompt:\n{text}"
        );
        assert_eq!(load_count(client_home.path()), usize::from(accept));
        let sock = server_home.path().join("qsh/control.sock");
        assert_eq!(
            query_daemon_build(&sock),
            Some(if accept { new_build } else { old_build })
        );

        client.type_line("exit");
        assert!(wait_for_exit(&mut client.child).unwrap().success());
    }
}

#[test]
fn scenario1_ssh_busy_dialog_matrix_covers_protocol_preservation_and_activity() {
    use bringup::{
        BusyAttemptId, BusyChoice, BusyDaemonIdentity, BusyDaemonInfo, CandidateImageIdentity,
        FrontendUpgradeOffer, PersonalServiceProfile, PersonalServiceSelector,
        PreservationCapability, UpgradeCase,
    };
    use std::os::fd::AsRawFd;

    let make_info = |profiles: Option<Vec<[u8; 3]>>,
                     upgrade: Option<FrontendUpgradeOffer>,
                     active: u64,
                     sessions: u64,
                     service_restart: bool| {
        let preservation = if upgrade.is_some() {
            PreservationCapability::PreservesSessions
        } else {
            PreservationCapability::Unknown
        };
        let info = BusyDaemonInfo {
            schema: 3,
            attempt: BusyAttemptId::from_bytes([1; 16]),
            identity: BusyDaemonIdentity {
                pid: 4242,
                build: 1,
                checksum: "aa".repeat(32),
                version: if profiles.is_some() {
                    "0.6.0-alpha.3".into()
                } else {
                    "0.5.0".into()
                },
                generation: None,
            },
            candidate: CandidateImageIdentity {
                build: 2,
                checksum: "bb".repeat(32),
            },
            active_connections: active,
            sessions,
            preservation,
            service_restart: service_restart.then(|| PersonalServiceSelector {
                profile: PersonalServiceProfile::PersonalTransportV1,
                uid: 1000,
                endpoint: "/fixture/qsh/control.sock".into(),
                port: 60022,
            }),
            serving_profiles: profiles,
            upgrade,
        };
        assert!(info.valid(), "invalid BusyDaemonInfo fixture: {info:?}");
        info
    };

    let answer_in_pty = |input: &[u8], info: BusyDaemonInfo| {
        let _sig = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pty = nix::pty::openpty(None, None).unwrap();
        let tty = crate::prompt::Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
        let mut master = std::fs::File::from(pty.master);
        master.write_all(input).unwrap();
        let cancel = knock::Cancel::new();
        let (decision, consent) =
            crate::busy_daemon::ask_for_target(&tty, info, "alice", "server.example:22", &cancel)
                .unwrap();
        assert!(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } >= 0);
        let mut out = String::new();
        let _ = master.read_to_string(&mut out);
        (decision, consent, out)
    };

    let compat = Some(vec![crate::busy_daemon::required_profile()]);
    let incompat = Some(vec![[1, 1, 1]]);
    let soft = Some(FrontendUpgradeOffer {
        case: UpgradeCase::Soft,
        attached: 1,
        sessions: 1,
        stranded: 0,
    });
    let unreachable = Some(FrontendUpgradeOffer {
        case: UpgradeCase::Unreachable,
        attached: 1,
        sessions: 2,
        stranded: 1,
    });

    // Compatible + preserving (Soft): 3 choices, update requires no 2nd destructive confirm.
    let (dec, consent, out) = answer_in_pty(b"3\n", make_info(compat.clone(), soft, 1, 1, false));
    assert_eq!(dec.choice, BusyChoice::ForceUpdate);
    assert!(consent.is_some());
    assert!(out.contains("Continue with old daemon"), "{out}");
    assert!(out.contains("Update and keep sessions"), "{out}");
    assert!(!out.contains("will be interrupted"), "{out}");

    // Compatible + preserving (Soft): choosing ContinueOld skips update cleanly.
    let (dec, consent, _) = answer_in_pty(b"2\n", make_info(compat.clone(), soft, 1, 1, false));
    assert_eq!(dec.choice, BusyChoice::ContinueOld);
    assert!(consent.is_none());

    // Compatible + preserving with stranded old-proto clients (Unreachable): 2nd confirmation required.
    let (dec, consent, out) = answer_in_pty(
        b"3\n1\n",
        make_info(compat.clone(), unreachable, 1, 2, false),
    );
    assert_eq!(dec.choice, BusyChoice::Cancel);
    assert!(consent.is_none());
    assert!(out.contains("1 of 2 session(s) belong to clients"), "{out}");
    let (dec, consent, _) = answer_in_pty(
        b"3\n2\n",
        make_info(compat.clone(), unreachable, 1, 2, false),
    );
    assert_eq!(dec.choice, BusyChoice::ForceUpdate);
    assert!(consent.is_some());

    // Compatible + non-preserving: 2nd destructive confirmation (plain & service).
    for service in [false, true] {
        let (dec, consent, out) =
            answer_in_pty(b"3\n1\n", make_info(compat.clone(), None, 2, 3, service));
        assert_eq!(dec.choice, BusyChoice::Cancel);
        assert!(consent.is_none());
        assert!(out.contains("Continue with old daemon"), "{out}");
        assert!(out.contains("Force update"), "{out}");
        assert!(out.contains("will be interrupted"), "{out}");
        if service {
            assert!(out.contains("alice"), "{out}");
            assert!(out.contains("server.example:22"), "{out}");
        }

        let (dec, consent, _) =
            answer_in_pty(b"3\n2\n", make_info(compat.clone(), None, 2, 3, service));
        assert_eq!(dec.choice, BusyChoice::ForceUpdate);
        assert!(consent.is_some());
    }

    // Incompatible + non-preserving (both active & detached sessions) AND preserving:
    // hides "Continue with old daemon" and renumbers update to 2.
    for (upgrade, active, sessions, input, expected, has_consent) in [
        (
            None,
            2u64,
            2u64,
            &b"2\n2\n"[..],
            BusyChoice::ForceUpdate,
            true,
        ),
        (None, 2u64, 2u64, &b"2\n1\n"[..], BusyChoice::Cancel, false),
        (
            None,
            0u64,
            2u64,
            &b"2\n2\n"[..],
            BusyChoice::ForceUpdate,
            true,
        ),
        (soft, 1u64, 1u64, &b"2\n"[..], BusyChoice::ForceUpdate, true),
        (
            unreachable,
            1u64,
            2u64,
            &b"2\n2\n"[..],
            BusyChoice::ForceUpdate,
            true,
        ),
        (
            unreachable,
            1u64,
            2u64,
            &b"2\n1\n"[..],
            BusyChoice::Cancel,
            false,
        ),
    ] {
        let (dec, consent, out) = answer_in_pty(
            input,
            make_info(incompat.clone(), upgrade, active, sessions, false),
        );
        assert_eq!(dec.choice, expected, "{out}");
        assert_eq!(consent.is_some(), has_consent, "{out}");
        assert!(!out.contains("Continue with old daemon"), "{out}");
        assert!(
            out.contains("does not speak this client's protocol"),
            "{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario 2: newer qshd server (compatible vs incompatible)
// ---------------------------------------------------------------------------

struct FakeIncompatibleBootstrapPeer {
    port: u16,
    public: [u8; 32],
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeIncompatibleBootstrapPeer {
    fn start_with_key(
        key: transport::handshake::Keypair,
        version: &str,
        wire: u8,
        handshake: u8,
        channel: u8,
    ) -> Self {
        use transport::bootstrap::{BootstrapResponder, ServerInfo, SessionProfile};
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let public = key.public;
        let mut responder = BootstrapResponder::new(
            key.private,
            ServerInfo {
                generation: [7; 16],
                core_version: version.to_owned(),
                session_protocols: vec![SessionProfile {
                    wire,
                    handshake,
                    channel,
                }],
            },
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            while !done.load(Ordering::SeqCst) {
                let Ok((n, source)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if buf[..n].starts_with(b"QSHB") {
                    if let Some(reply) = responder.on_datagram(Instant::now(), source, &buf[..n]) {
                        let _ = socket.send_to(&reply, source);
                    }
                } else if let Ok(transport::wire::Frame::Handshake {
                    kind: transport::wire::Kind::HandshakeInit,
                    body,
                }) = transport::wire::parse(&buf[..n])
                {
                    let mut noise = transport::handshake::Handshake::new_responder(&key.private);
                    if noise.read_msg(body).is_ok() {
                        let mut payload = transport::handshake_payload::encode_msg2(
                            1,
                            false,
                            &[0; 16],
                            transport::Features::SUPPORTED,
                        );
                        payload[0] = handshake;
                        let resp = noise.write_msg(&payload);
                        let _ = socket.send_to(
                            &transport::wire::encode_handshake(
                                transport::wire::Kind::HandshakeResp,
                                &resp,
                            ),
                            source,
                        );
                    }
                }
            }
        });
        Self {
            port,
            public,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for FakeIncompatibleBootstrapPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn scenario2_newer_server_compatible_vs_incompatible_policy_and_presentations() {
    use crate::client_install::UpdateEligibility;
    use crate::upgrade_offer::{presentation, Presentation};
    use ::connect::upgrade::Compatibility;
    use transport::bootstrap::{ServerInfo, SessionProfile};

    // Compatible newer server: same session profile, higher version.
    let newer_compat = ServerInfo {
        generation: [1; 16],
        core_version: "9.9.9".into(),
        session_protocols: vec![SessionProfile {
            wire: transport::wire::VERSION,
            handshake: transport::handshake_payload::HS_VERSION,
            channel: transport::channel::PROTOCOL_VERSION,
        }],
    };
    let decision = crate::server_discovery::decision(Some(&newer_compat));
    assert_eq!(decision.compatibility, Compatibility::Compatible);
    let offer_ver = decision
        .offer
        .as_ref()
        .map(|o| o.version.as_str())
        .expect("newer compatible server offers client update");
    assert_eq!(offer_ver, "9.9.9");
    assert_eq!(
        presentation(|| UpdateEligibility::Managed, false, Some(offer_ver)),
        Presentation::Offer("9.9.9".into())
    );
    assert!(matches!(
        presentation(|| UpdateEligibility::PackageOwned, false, Some(offer_ver)),
        Presentation::Guidance(line) if line.contains("package manager")
    ));
    assert!(matches!(
        presentation(|| UpdateEligibility::Unmanaged, false, Some(offer_ver)),
        Presentation::Guidance(line) if line.contains("manually")
    ));
    assert_eq!(
        presentation(|| UpdateEligibility::SourceBuild, false, Some(offer_ver)),
        Presentation::Silent
    );

    // Incompatible newer server: future session profile, higher version.
    let newer_incompat = ServerInfo {
        generation: [2; 16],
        core_version: "9.9.9".into(),
        session_protocols: vec![SessionProfile {
            wire: transport::wire::VERSION + 1,
            handshake: transport::handshake_payload::HS_VERSION + 1,
            channel: transport::channel::PROTOCOL_VERSION + 1,
        }],
    };
    let decision = crate::server_discovery::decision(Some(&newer_incompat));
    assert_eq!(decision.compatibility, Compatibility::Incompatible);
    let offer_ver = decision
        .offer
        .as_ref()
        .map(|o| o.version.as_str())
        .expect("newer incompatible server offers client update");
    assert_eq!(offer_ver, "9.9.9");
    assert_eq!(
        presentation(|| UpdateEligibility::Managed, true, Some(offer_ver)),
        Presentation::Offer("9.9.9".into())
    );
    for eligibility in [
        UpdateEligibility::SourceBuild,
        UpdateEligibility::PackageOwned,
        UpdateEligibility::Unmanaged,
    ] {
        assert!(
            matches!(
                presentation(|| eligibility, true, Some(offer_ver)),
                Presentation::Guidance(_)
            ),
            "incompatible newer server must never be silent for {eligibility:?}"
        );
    }
}

#[test]
fn scenario2_newer_compatible_daemon_never_prompts_daemon_downgrade() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();

    let (daemon_bin, daemon_bytes) = copy_stripped_qshd(bin_dir.path(), "qshd");
    let daemon_build = read_build_label(&daemon_bin);
    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&daemon_bin, server_home.path(), port, &pubkey, "");
    pin_server_key(client_home.path(), port, &server_pub);

    // Client identifies itself as OLDER than the running daemon.
    let addr = format!("127.0.0.1:{port},nossh");
    let (mut client, screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &daemon_bin,
        &daemon_bytes,
        "0.5.9",
        daemon_build.saturating_sub(1),
    );
    wait_shell_ready(
        &mut client,
        &screen,
        "echo NEWER_DAEMON_'OK'",
        "NEWER_DAEMON_OK",
    );
    assert!(
        !screen.text().contains("Update qshd"),
        "older client must never offer to overwrite a newer daemon:\n{}",
        screen.text()
    );
    assert_eq!(load_count(client_home.path()), 0);

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}

#[test]
fn scenario2_newer_incompatible_server_deduplicates_diagnostic_across_two_endpoints() {
    let _serial = serialised();
    let client_home = private_dir();
    let (key_path, _) = make_key(client_home.path());
    let server_key = transport::generate_keypair();
    let peer1 = FakeIncompatibleBootstrapPeer::start_with_key(
        transport::handshake::Keypair {
            private: server_key.private,
            public: server_key.public,
        },
        "99.0.0",
        99,
        99,
        99,
    );
    let peer2 = FakeIncompatibleBootstrapPeer::start_with_key(server_key, "99.0.0", 99, 99, 99);
    pin_server_key(client_home.path(), peer1.port, &peer1.public);
    pin_server_key(client_home.path(), peer2.port, &peer2.public);

    let dummy = client_home.path().join("unused");
    std::fs::write(&dummy, b"unused").unwrap();
    let addr1 = format!("127.0.0.1:{},nossh", peer1.port);
    let addr2 = format!("127.0.0.1:{},nossh", peer2.port);
    let (mut client, screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr1, &addr2],
        client_home.path(),
        &dummy,
        b"unused",
        env!("CARGO_PKG_VERSION"),
        1,
    );

    let status = wait_for_exit(&mut client.child)
        .unwrap_or_else(|| panic!("incompatible newer server must exit:\n{}", screen.text()));
    assert_eq!(status.code(), Some(12), "{}", screen.text());
    let text = screen.text();
    assert!(
        !text.contains("\x1b[?1049h"),
        "must not enter alt screen:\n{text}"
    );
    assert_eq!(
        text.matches(
            "qsh: authenticated qshd 99.0.0 does not support this client's session profile"
        )
        .count(),
        1,
        "final incompatible newer server notice must not duplicate across endpoints:\n{text}"
    );
    assert_eq!(
        text.matches("Update the source and rebuild a compatible qsh client.")
            .count(),
        1,
        "client upgrade guidance must appear exactly once across endpoints:\n{text}"
    );
    assert_eq!(load_count(client_home.path()), 0);
}

// ---------------------------------------------------------------------------
// Scenario 3: older qshd WITHOUT attached clients (idle) + Managed daemon
// ---------------------------------------------------------------------------

#[test]
fn scenario3_idle_older_personal_daemon_omits_busy_prompts_and_is_idempotent() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();
    let second_home = private_dir();

    let (old_bin, _old_build, new_image, new_bytes, new_build, labels) =
        prepare_old_and_new_daemon(bin_dir.path(), "s3-idle");
    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);
    pin_server_key(second_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut client, screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("updated qshd");
    wait_shell_ready(&mut client, &screen, "echo IDLE_OK_'1'", "IDLE_OK_1");

    let text = screen.text();
    assert_eq!(text.matches("Update qshd to 9.9.9?").count(), 1, "{text}");
    assert!(
        !text.contains("other active client") && !text.contains("Update qshd now? [y/N]"),
        "idle daemon must never show busy/disrupt dialogs:\n{text}"
    );
    assert_eq!(load_count(client_home.path()), 1);
    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(new_build));

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());

    // Second connection after idle update: 0 prompts, 0 loads.
    let (mut second, second_screen) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        second_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );
    wait_shell_ready(&mut second, &second_screen, "echo IDLE_OK_'2'", "IDLE_OK_2");
    assert!(
        !second_screen.text().contains("Update qshd"),
        "second connect must not re-offer update:\n{}",
        second_screen.text()
    );
    assert_eq!(load_count(second_home.path()), 0);
    second.type_line("exit");
    assert!(wait_for_exit(&mut second.child).unwrap().success());
}

#[test]
fn scenario3_managed_daemon_never_prompts_idle_or_busy() {
    let _serial = serialised();
    let client_home = private_dir();
    let other_home = private_dir();
    let (daemon, key_path) = start_daemon();

    let dummy = client_home.path().join("unused");
    std::fs::write(&dummy, b"unused").unwrap();
    let addr = format!("127.0.0.1:{},nossh", daemon.port);

    // Idle managed daemon.
    let (mut client1, screen1) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &dummy,
        b"unused",
        "9.9.9",
        u64::MAX,
    );
    screen1.wait("Continue and remember this key? [y/N]");
    client1.master.write_all(b"yes\n").unwrap();
    wait_shell_ready(&mut client1, &screen1, "echo MGD_IDLE_'OK'", "MGD_IDLE_OK");
    assert!(
        !screen1.text().contains("Update qshd"),
        "{}",
        screen1.text()
    );
    assert_eq!(load_count(client_home.path()), 0);

    // Busy managed daemon (while client1 is still attached).
    let (mut client2, screen2) = spawn_matrix_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        other_home.path(),
        &dummy,
        b"unused",
        "9.9.9",
        u64::MAX,
    );
    screen2.wait("Continue and remember this key? [y/N]");
    client2.master.write_all(b"yes\n").unwrap();
    wait_shell_ready(&mut client2, &screen2, "echo MGD_BUSY_'OK'", "MGD_BUSY_OK");
    assert!(
        !screen2.text().contains("Update qshd"),
        "{}",
        screen2.text()
    );
    assert_eq!(load_count(other_home.path()), 0);

    client2.type_line("exit");
    assert!(wait_for_exit(&mut client2.child).unwrap().success());
    client1.type_line("exit");
    assert!(wait_for_exit(&mut client1.child).unwrap().success());
}
