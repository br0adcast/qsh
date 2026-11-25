//! Real CLI/qshd over-qsh daemon update orchestration tests with a private
//! local-image provider (no SSH required).
use crate::install_fixture_tests::support;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use support::*;

const CHILD_ENTRY: &str = "daemon_update_fixture_tests::over_qsh_fixture_child_entry";
const RECORD_ENV: &str = "QSH_OVER_QSH_UPDATE_FIXTURE_RECORD";
const MAX_IMAGE: u64 = 64 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateFixtureRecord {
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

fn spawn_over_qsh_fixture(
    args: &[&str],
    client_home: &Path,
    new_image: &Path,
    new_bytes: &[u8],
    client_version: &str,
    client_build: u64,
) -> (Client, Screen) {
    let record = UpdateFixtureRecord {
        args: args.iter().map(|s| (*s).to_owned()).collect(),
        image: new_image.to_path_buf(),
        size: new_bytes.len() as u64,
        sha256: sha256(new_bytes),
        client_version: client_version.to_owned(),
        client_build,
        marker: client_home.join("fixture-marker"),
    };
    let record_path = client_home.join("update-fixture.json");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_ENTRY, "--nocapture", "--test-threads=1"])
        .env(RECORD_ENV, record_path);
    let (client, _slave) = spawn_command_on(command, client_home, &qshd_path(), 80, 24);
    let screen = Screen::of(&client);
    (client, screen)
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

struct UpdateLocalImage(UpdateFixtureRecord);
impl bringup::ImageSource for UpdateLocalImage {
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
fn over_qsh_fixture_child_entry() {
    let Some(path) = std::env::var_os(RECORD_ENV) else {
        return;
    };
    let record: UpdateFixtureRecord =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let args = record.args.iter().map(std::ffi::OsString::from).collect();
    mark(&record.marker, "entry");
    crate::daemon_update::set_test_release_identity(
        Some(record.client_version.clone()),
        Some(record.client_build),
    );
    crate::climb::set_test_images(Arc::new(UpdateLocalImage(record)));
    crate::cli_entry::entry(args);
}

#[test]
fn direct_login_updates_older_personal_daemon_over_qsh_without_ssh() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();

    let (old_bin, old_bytes) = copy_stripped_qshd(bin_dir.path(), "qshd");
    let old_build = read_build_label(&old_bin);
    let mut new_bytes = old_bytes.clone();
    new_bytes.extend_from_slice(b"\0cli-over-qsh-update-test\0");
    let new_image = bin_dir.path().join("qshd-new");
    std::fs::write(&new_image, &new_bytes).unwrap();
    std::fs::set_permissions(&new_image, std::fs::Permissions::from_mode(0o755)).unwrap();
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(sha256(&new_bytes)));

    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut client, screen) = spawn_over_qsh_fixture(
        &["--verbose", "-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("via qsh");
    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Uploading qshd");
    screen.wait("updated qshd");

    // Reconnects cleanly without SSH and opens the shell.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut ready = false;
    while Instant::now() < deadline {
        client.type_line("echo OVER_QSH_'OK'");
        if wait_until(|| screen.text().contains("OVER_QSH_OK")) {
            ready = true;
            break;
        }
    }
    assert!(
        ready,
        "shell never responded after update:\n{}",
        screen.text()
    );

    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(new_build));
    assert_eq!(
        std::fs::read_to_string(client_home.path().join("fixture-marker")).unwrap(),
        "entry\nload\n"
    );

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}

#[test]
fn direct_login_declining_over_qsh_update_opens_shell_immediately() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();

    let (old_bin, old_bytes) = copy_stripped_qshd(bin_dir.path(), "qshd");
    let old_build = read_build_label(&old_bin);
    let mut new_bytes = old_bytes.clone();
    new_bytes.extend_from_slice(b"\0cli-over-qsh-decline-test\0");
    let new_image = bin_dir.path().join("qshd-new");
    std::fs::write(&new_image, &new_bytes).unwrap();
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(sha256(&new_bytes)));

    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);

    let addr = format!("127.0.0.1:{port},nossh");
    let (mut client, screen) = spawn_over_qsh_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"no\n").unwrap();
    client.type_line("echo KEPT_OLD_'OK'");
    screen.wait("KEPT_OLD_OK");

    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(old_build));
    assert_eq!(
        std::fs::read_to_string(client_home.path().join("fixture-marker")).unwrap(),
        "entry\n",
        "declining must never download the daemon image"
    );

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}

#[test]
fn direct_login_managed_daemon_never_prompts_for_update() {
    let _serial = serialised();
    let client_home = private_dir();
    let (daemon, key_path) = start_daemon();
    // Managed daemon (`qshd serve`): first-use trust asks once, never asks to update qshd.
    let dummy_image = client_home.path().join("unused-image");
    std::fs::write(&dummy_image, b"unused").unwrap();

    let addr = format!("127.0.0.1:{},nossh", daemon.port);
    let (mut client, screen) = spawn_over_qsh_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &dummy_image,
        b"unused",
        "9.9.9",
        u64::MAX,
    );

    screen.wait("Continue and remember this key? [y/N]");
    client.master.write_all(b"yes\n").unwrap();
    client.type_line("echo MANAGED_'OK'");
    screen.wait("MANAGED_OK");
    assert!(
        !screen.text().contains("Update qshd"),
        "managed daemon must never prompt for update:\n{}",
        screen.text()
    );

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
}

#[test]
fn direct_login_busy_personal_daemon_asks_disrupt_consent_and_updates_over_qsh() {
    let _serial = serialised();
    let bin_dir = private_dir();
    let server_home = private_dir();
    let client_home = private_dir();

    let (old_bin, old_bytes) = copy_stripped_qshd(bin_dir.path(), "qshd");
    let old_build = read_build_label(&old_bin);
    let mut new_bytes = old_bytes.clone();
    new_bytes.extend_from_slice(b"\0cli-over-qsh-busy-test\0");
    let new_image = bin_dir.path().join("qshd-new");
    std::fs::write(&new_image, &new_bytes).unwrap();
    std::fs::set_permissions(&new_image, std::fs::Permissions::from_mode(0o755)).unwrap();
    let new_build = old_build + 1;
    let labels = format!("{}={new_build}", hex::encode(sha256(&new_bytes)));

    let (key_path, pubkey) = make_key(client_home.path());
    let port = free_udp_port();
    let (server_pub, _guard) =
        start_personal_daemon(&old_bin, server_home.path(), port, &pubkey, &labels);
    pin_server_key(client_home.path(), port, &server_pub);

    // Keep another client actively connected on the personal daemon.
    let other_home = private_dir();
    pin_server_key(other_home.path(), port, &server_pub);
    let addr = format!("127.0.0.1:{port},nossh");
    let (mut other, other_screen) = spawn_over_qsh_fixture(
        &["-i", key_path.to_str().unwrap(), &addr],
        other_home.path(),
        &new_image,
        &new_bytes,
        env!("CARGO_PKG_VERSION"),
        old_build,
    );
    other.type_line("echo OTHER_READY_'OK'");
    other_screen.wait("OTHER_READY_OK");

    let (mut client, screen) = spawn_over_qsh_fixture(
        &["--verbose", "-i", key_path.to_str().unwrap(), &addr],
        client_home.path(),
        &new_image,
        &new_bytes,
        "9.9.9",
        new_build,
    );

    screen.wait("Update qshd to 9.9.9?");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("has 1 other active client");
    screen.wait("Update qshd now? [y/N]");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Uploading qshd");
    screen.wait("updated qshd");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut ready = false;
    while Instant::now() < deadline {
        client.type_line("echo BUSY_UPDATED_'OK'");
        if wait_until(|| screen.text().contains("BUSY_UPDATED_OK")) {
            ready = true;
            break;
        }
    }
    assert!(
        ready,
        "shell never responded after busy update:\n{}",
        screen.text()
    );
    let sock = server_home.path().join("qsh/control.sock");
    assert_eq!(query_daemon_build(&sock), Some(new_build));

    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    let _ = other.child.kill();
    let _ = other.child.wait();
}
