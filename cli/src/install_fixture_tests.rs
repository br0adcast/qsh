//! Real CLI/SSH orchestration with a private local-image provider.
//! This is not positive evidence for signed production releases.
#[path = "../tests/support/mod.rs"]
mod support;
use crate::ssh_step::test_support as support_home;
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use support::*;
use support_home::Sandbox;
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
            "missing {needle}: {}",
            self.text()
        );
    }
}
fn wait_for_bootstrap_ready(home: &Path) {
    let log = || std::fs::read_to_string(home.join("qsh/log")).unwrap_or_default();
    assert!(
        wait_until(|| log()
            .lines()
            .any(|line| line.contains("shell channel ") && line.ends_with(" ready"))),
        "SSH bootstrap did not deliver the current shell Ready: {}",
        log()
    );
}

fn assert_no_bootstrap_recovery_offer(home: &Path, screen: &Screen) {
    assert!(
        !screen.text().contains("Authorize SSH recovery"),
        "{}",
        screen.text()
    );
    assert!(
        !home.join("qsh/ssh_bindings.json").exists(),
        "SSH-first bootstrap must retain trust without a persistent grant"
    );
}

fn key(home: &Path) -> (PathBuf, String) {
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

const KEY_MODE_CHILD: &str = "install_fixture_tests::key_mode_child_entry";
const KEY_MODE_ENV: &str = "QSH_INSTALL_FIXTURE_KEY_MODE_RECORD";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyModeRequest {
    schema: u8,
    mask: u32,
    home: PathBuf,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyModeResult {
    schema: u8,
    mask: u32,
    mode: u32,
    uid: u32,
    regular: bool,
    loaded: bool,
    public_matches: bool,
}

struct KeyModeChild(std::process::Child);
impl Drop for KeyModeChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn fixture_keys_are_private_under_permissive_umasks() {
    let directory = tempfile::tempdir().unwrap();
    let mut results = Vec::new();
    for mask in [0o022, 0o000] {
        let home = directory.path().join(format!("mask-{mask:03o}"));
        std::fs::create_dir(&home).unwrap();
        let request = home.join("request.json");
        std::fs::write(
            &request,
            serde_json::to_vec(&KeyModeRequest {
                schema: 1,
                mask,
                home: home.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        let stdout = home.join("stdout");
        let stderr = home.join("stderr");
        // Only this owned child changes its umask; paths are positional args.
        let mut child = KeyModeChild(
            std::process::Command::new("/bin/sh")
                .args(["-c", "umask \"$1\"; shift; exec \"$@\"", "fixture-key-mode"])
                .arg(format!("{mask:03o}"))
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", KEY_MODE_CHILD, "--nocapture", "--test-threads=1"])
                .env(KEY_MODE_ENV, &request)
                .env("RUST_BACKTRACE", "0")
                .stdin(std::process::Stdio::null())
                .stdout(std::fs::File::create(&stdout).unwrap())
                .stderr(std::fs::File::create(&stderr).unwrap())
                .spawn()
                .unwrap(),
        );
        let status = wait_for_exit(&mut child.0).expect("key-mode child timed out and was reaped");
        for path in [&stdout, &stderr, &home.join("result.json")] {
            assert!(std::fs::metadata(path).unwrap().len() <= 65536);
        }
        let output = std::fs::read_to_string(stdout).unwrap();
        assert!(output.contains("running 1 test\n"));
        let result: KeyModeResult =
            serde_json::from_slice(&std::fs::read(home.join("result.json")).unwrap()).unwrap();
        assert_eq!((result.schema, result.mask), (1, mask));
        println!("key-mode child: {result:?}; exit={status}");
        results.push((result, status.success(), output));
    }
    assert_eq!(results.len(), 2);
    for (result, success, output) in results {
        assert_eq!(result.mode, 0o600, "mask {:03o}", result.mask);
        assert_eq!(result.uid, unsafe { libc::geteuid() });
        assert!(result.regular && result.loaded && result.public_matches && success);
        assert!(output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    }
}

/// Discovery alone must never create a key or change any process's umask.
#[test]
fn key_mode_child_entry() {
    use std::os::unix::fs::MetadataExt;
    let Some(path) = std::env::var_os(KEY_MODE_ENV) else {
        return;
    };
    assert!(std::fs::metadata(&path).unwrap().len() <= 4096);
    let request: KeyModeRequest = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(request.schema, 1);
    assert!(matches!(request.mask, 0o022 | 0o000));
    assert!(request.home.is_absolute() && request.home.is_dir());
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let mask = u32::from_str_radix(
        status
            .lines()
            .find_map(|line| line.strip_prefix("Umask:"))
            .unwrap()
            .trim(),
        8,
    )
    .unwrap();
    assert_eq!(mask, request.mask);
    let (path, public) = key(&request.home);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    let loaded = sshauth::sign_file::FileSigner::load(&path, None);
    let result = KeyModeResult {
        schema: 1,
        mask,
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        regular: metadata.is_file(),
        loaded: loaded.is_ok(),
        public_matches: loaded
            .as_ref()
            .is_ok_and(|signer| signer.public_key().to_openssh().unwrap() == public),
    };
    std::fs::write(
        request.home.join("result.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert_eq!(result.mode, 0o600);
    assert_eq!(result.uid, unsafe { libc::geteuid() });
    assert!(result.regular && result.loaded && result.public_matches);
}

#[test]
fn fixture_key_creation_refuses_an_existing_path_without_changing_it() {
    use std::os::unix::fs::MetadataExt;
    let home = tempfile::tempdir().unwrap();
    let (path, public) = key(home.path());
    let bytes = std::fs::read(&path).unwrap();
    let before = std::fs::symlink_metadata(&path).unwrap();
    assert!(std::panic::catch_unwind(|| key(home.path())).is_err());
    assert!(
        std::fs::read(&path).unwrap() == bytes,
        "existing key was overwritten"
    );
    let after = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(
        (after.mode(), after.uid(), after.ino()),
        (before.mode(), before.uid(), before.ino())
    );
    assert_eq!(after.mode() & 0o7777, 0o600);
    assert!(
        sshauth::sign_file::FileSigner::load(&path, None)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
            == public
    );
}

fn trust(home: &Path, sb: &Sandbox) {
    let path = home.join(".ssh");
    std::fs::create_dir_all(&path).unwrap();
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path.join("known_hosts"))
        .unwrap();
    writeln!(
        file,
        "[127.0.0.1]:{} {}",
        sb.sshd.port,
        sb.sshd.host_public_key_line()
    )
    .unwrap();
}
fn address(sb: &Sandbox) -> String {
    format!("127.0.0.1:{},ssh={}", free_udp_port(), sb.sshd.port)
}
fn image_path(sb: &Sandbox) -> PathBuf {
    sb.cache().join(format!(
        "qshd-{}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    ))
}

fn start(home: &Path, key: &Path, addresses: &[String]) -> (Client, Screen) {
    let mut args = vec!["--verbose", "-i", key.to_str().unwrap()];
    args.extend(addresses.iter().map(String::as_str));
    let client = fixture_on(&args, home).0;
    let screen = Screen::of(&client);
    (client, screen)
}
#[test]
fn accept_installs_and_opens_shell() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    let (mut client, screen) = start(home.path(), &key, &[address(&sb)]);
    screen.wait(&format!("Install qshd {}", env!("CARGO_PKG_VERSION")));
    assert!(screen
        .text()
        .contains(&format!("127.0.0.1:{}", sb.sshd.port)));
    let server_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => panic!("unsupported test server architecture: {other}"),
    };
    assert!(screen.text().contains(server_target));
    assert!(screen.text().contains(image_path(&sb).to_str().unwrap()));
    client.master.write_all(b"yes\n").unwrap();
    wait_for_bootstrap_ready(home.path());
    client.type_line("echo INSTALL_'OK'");
    screen.wait("INSTALL_OK");
    assert_no_bootstrap_recovery_offer(home.path(), &screen);
    assert!(
        !screen.text().contains("Key fingerprint"),
        "{}",
        screen.text()
    );
    assert!(image_path(&sb).is_file());
    assert_eq!(
        std::fs::read(image_path(&sb)).unwrap(),
        std::fs::read(home.path().join("prepared-qshd")).unwrap()
    );
    screen.wait("Uploading qshd");
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    assert_fixture_used(home.path());
}
#[test]
fn enter_accepts_installation_and_opens_shell() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with(&[public]);
    trust(home.path(), &sb);
    let (mut client, screen) = start(home.path(), &key, &[address(&sb)]);
    screen.wait(&format!("Install qshd {}", env!("CARGO_PKG_VERSION")));
    assert!(screen
        .text()
        .contains(&format!("127.0.0.1:{}", sb.sshd.port)));
    let server_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        other => panic!("unsupported test server architecture: {other}"),
    };
    assert!(screen.text().contains(server_target));
    assert!(screen.text().contains(image_path(&sb).to_str().unwrap()));
    screen.wait("[Y/n]");
    // This checks prompt wording only; the private provider does not authenticate releases.
    assert!(screen.text().contains("  Source    GitHub Releases"));
    client.master.write_all(b"\n").unwrap();
    wait_for_bootstrap_ready(home.path());
    client.type_line("echo INSTALL_'OK'");
    screen.wait("INSTALL_OK");
    assert_no_bootstrap_recovery_offer(home.path(), &screen);
    assert!(
        !screen.text().contains("Key fingerprint"),
        "{}",
        screen.text()
    );
    assert!(image_path(&sb).is_file());
    assert_eq!(
        std::fs::read(image_path(&sb)).unwrap(),
        std::fs::read(home.path().join("prepared-qshd")).unwrap()
    );
    screen.wait("Uploading qshd");
    client.type_line("exit");
    assert!(wait_for_exit(&mut client.child).unwrap().success());
    assert_fixture_used(home.path());
}
#[test]
fn approval_does_not_authorize_another_host() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let first = Sandbox::start_with_fault(
        std::slice::from_ref(&public),
        support_home::VerificationFault::FailVerification,
    );
    let second = Sandbox::start_with(&[public]);
    // Fail remote verification after approval, forcing a separate SSH operation.
    trust(home.path(), &first);
    trust(home.path(), &second);
    let (mut client, screen) = start(home.path(), &key, &[address(&first), address(&second)]);
    screen.wait("Install qshd");
    client.master.write_all(b"yes\n").unwrap();
    assert!(
        wait_until(|| screen.text().matches("Install qshd").count() == 2),
        "{}",
        screen.text()
    );
    assert!(!image_path(&second).exists());
    client.master.write_all(b"no\n").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
    assert_fixture_used(home.path());
}
#[test]
fn ctrl_c_during_install_restores_tty() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = key(home.path());
    let sb = Sandbox::start_with_fault(
        &[public],
        support_home::VerificationFault::HoldUploadedVerification,
    );
    trust(home.path(), &sb);
    // Keep verification in flight, so Ctrl-C cancels an installation after approval.
    let addr = address(&sb);
    let (mut client, slave) = fixture_on(&["-i", key.to_str().unwrap(), &addr], home.path());
    let original = nix::sys::termios::tcgetattr(&slave).unwrap();
    let screen = Screen::of(&client);
    screen.wait("Install qshd");
    client.master.write_all(b"yes\n").unwrap();
    screen.wait("Uploading qshd");
    assert!(
        wait_until(|| sb.home.path().join(".verification-held").is_file()),
        "uploaded verification never reached hold"
    );
    assert!(
        !sb.home.path().join(".verification-hold-complete").exists(),
        "verification finished before Ctrl-C reached the held operation"
    );
    assert!(
        client.child.try_wait().unwrap().is_none(),
        "client exited before verification cancellation"
    );
    client.master.write_all(b"\x03").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(130));
    assert_fixture_used(home.path());
    assert!(
        wait_until(|| sb.home.path().join(".verification-hold-complete").is_file()),
        "owned verification reader did not finish after cancellation"
    );
    assert_eq!(nix::sys::termios::tcgetattr(&slave).unwrap(), original);
    assert!(!image_path(&sb).exists());
}
const CHILD_ENTRY: &str = "install_fixture_tests::fixture_child_entry";
const RECORD_ENV: &str = "QSH_INSTALL_FIXTURE_RECORD";
const MAX_IMAGE: u64 = 32 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecord {
    args: Vec<String>,
    image: PathBuf,
    size: u64,
    sha256: [u8; 32],
    marker: PathBuf,
}

fn fixture_on(args: &[&str], home: &Path) -> (Client, std::os::fd::OwnedFd) {
    use sha2::{Digest, Sha256};
    let daemon = qshd_path();
    let image = home.join("prepared-qshd");
    std::fs::copy(&daemon, &image).unwrap();
    assert!(std::process::Command::new("strip")
        .arg(&image)
        .status()
        .unwrap()
        .success());
    let bytes = std::fs::read(&image).unwrap();
    assert!(!bytes.is_empty() && bytes.len() as u64 <= MAX_IMAGE);
    let record = FixtureRecord {
        args: args.iter().map(|arg| (*arg).to_owned()).collect(),
        image,
        size: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
        marker: home.join("fixture-used"),
    };
    let record_path = home.join("fixture-record.json");
    std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_ENTRY, "--nocapture", "--test-threads=1"])
        .env(RECORD_ENV, record_path);
    spawn_command_on(command, home, &daemon, 80, 24)
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

fn assert_fixture_used(home: &Path) {
    assert_eq!(
        std::fs::read_to_string(home.join("fixture-used")).unwrap(),
        "entry\nload\n",
        "the exact child must enter the shared CLI and consume the explicit provider once"
    );
}

struct LocalImage(FixtureRecord);
impl bringup::ImageSource for LocalImage {
    fn load(
        &self,
        request: &bringup::ImageRequest,
        _: &bringup::InstallTiming,
        cancel: &knock::Cancel,
        _: &dyn bringup::BringUpObserver,
    ) -> Result<bringup::DaemonImage, bringup::ImageError> {
        use bringup::ImageError;
        use sha2::{Digest, Sha256};
        use std::io::Read;
        if cancel.is_cancelled() {
            return Err(ImageError::Cancelled);
        }
        request
            .validate()
            .map_err(|error| ImageError::Invalid(error.to_string()))?;
        let platform = bringup::Platform::from_uname("Linux", std::env::consts::ARCH).unwrap();
        if request.version != env!("CARGO_PKG_VERSION") || request.platform != platform {
            return Err(ImageError::Invalid("local fixture request mismatch".into()));
        }
        if !self.0.image.is_absolute() || self.0.size == 0 || self.0.size > MAX_IMAGE {
            return Err(ImageError::Invalid(
                "invalid local fixture image record".into(),
            ));
        }
        let file = std::fs::File::open(&self.0.image)
            .map_err(|error| ImageError::Invalid(error.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|error| ImageError::Invalid(error.to_string()))?;
        if !metadata.is_file() || metadata.len() != self.0.size {
            return Err(ImageError::Invalid(
                "local fixture image size changed".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_IMAGE + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ImageError::Invalid(error.to_string()))?;
        if cancel.is_cancelled() {
            return Err(ImageError::Cancelled);
        }
        if bytes.len() as u64 != self.0.size
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.0.sha256
        {
            return Err(ImageError::Checksum);
        }
        if cancel.is_cancelled() {
            return Err(ImageError::Cancelled);
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

/// An ordinary test discovery run must never start an interactive CLI.
#[test]
fn fixture_child_entry() {
    let Some(path) = std::env::var_os(RECORD_ENV) else {
        return;
    };
    let record: FixtureRecord = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let args = record.args.iter().map(std::ffi::OsString::from).collect();
    mark(&record.marker, "entry");
    crate::climb::set_test_images(Arc::new(LocalImage(record)));
    crate::cli_entry::entry(args);
}

#[test]
fn local_provider_rejects_changed_bytes_request_mismatch_and_cancellation() {
    use bringup::{ImageError, ImageSource};
    use sha2::{Digest, Sha256};
    struct Silent;
    impl bringup::BringUpObserver for Silent {
        fn on_progress(&self, _: bringup::BringUpProgress) {
            panic!("a local fixture must not fabricate release authentication progress");
        }
    }
    let home = tempfile::tempdir().unwrap();
    let image = home.path().join("image");
    std::fs::write(&image, b"local fixture").unwrap();
    let record = FixtureRecord {
        args: Vec::new(),
        image,
        size: 13,
        sha256: Sha256::digest(b"local fixture").into(),
        marker: home.path().join("marker"),
    };
    let local = LocalImage(record);
    let request = bringup::ImageRequest::new(
        bringup::Platform::from_uname("Linux", std::env::consts::ARCH).unwrap(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    let cancel = knock::Cancel::new();
    let timing = bringup::InstallTiming::default();
    assert_eq!(
        local
            .load(&request, &timing, &cancel, &Silent)
            .unwrap()
            .bytes
            .as_ref(),
        b"local fixture"
    );
    let mut wrong = request.clone();
    wrong.version = "0.0.1".into();
    assert!(matches!(
        local.load(&wrong, &timing, &cancel, &Silent),
        Err(ImageError::Invalid(_))
    ));
    wrong = request.clone();
    wrong.platform.os = bringup::ServerOs::Darwin;
    assert!(matches!(
        local.load(&wrong, &timing, &cancel, &Silent),
        Err(ImageError::Invalid(_))
    ));
    std::fs::write(&local.0.image, b"other fixture").unwrap();
    assert_eq!(
        local.load(&request, &timing, &cancel, &Silent).unwrap_err(),
        ImageError::Checksum
    );
    cancel.cancel();
    assert_eq!(
        local.load(&request, &timing, &cancel, &Silent).unwrap_err(),
        ImageError::Cancelled
    );
    assert_eq!(std::fs::read_to_string(&local.0.marker).unwrap(), "load\n");
}
