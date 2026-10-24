//! A private sshd whose sessions live in a private home, and a qshd built
//! from this workspace. This machine may run the developer's own qshd under
//! ~/.cache/qsh: nothing here may reach it, so every session's HOME,
//! XDG_CACHE_HOME and PATH point into a temp dir, and that is checked over
//! SSH before any test runs qshd.

#![allow(dead_code)]

#[path = "../../../ssh/tests/support/mod.rs"]
pub mod ssh_support;

// The one daemon guard the qshd tests use, included by path (relative to
// this directory) so there is no second copy of the stop-then-kill logic.
#[path = "../../../../qshd/tests/daemon_guard/mod.rs"]
pub mod daemon_guard;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use client::channel::{ChannelSubstrate, SubstrateEvent};
use ssh_support::{SoftSigner, SshdOptions, TestSshd};
use transport::channel::{ChannelKind, OpenRequest};

/// How many `bring_up` logins one sandbox allows (each takes its own key).
const LOGINS: usize = 2;

pub struct Sandbox {
    // `Drop` below stops the daemon first; then sshd, then the home go.
    pub sshd: TestSshd,
    pub home: tempfile::TempDir,
    /// Keys for `request`, one per login, all in authorized_keys.
    logins: Vec<SoftSigner>,
}

impl Sandbox {
    pub fn start() -> Sandbox {
        Self::start_with(&[])
    }

    /// [`Sandbox::start`], with `extra_authorized` (OpenSSH public key
    /// lines) also in sshd's `authorized_keys`: a client that logs in with
    /// its own key, such as `qsh -i <file>`.
    pub fn start_with(extra_authorized: &[String]) -> Sandbox {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let home = tempfile::Builder::new()
            .prefix("qsh home ' ")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(home.path().join(".cache/qsh"))
            .unwrap();
        std::fs::create_dir_all(home.path().join("bin")).unwrap();
        let probe = SoftSigner::random();
        let logins: Vec<SoftSigner> = (0..LOGINS).map(|_| SoftSigner::random()).collect();
        let (sftp_key, sftp_public) = ssh_support::keygen_file("ed25519", home.path());
        let mut authorized = vec![probe.authorized_line(), sftp_public.trim_end().into()];
        authorized.extend(logins.iter().map(SoftSigner::authorized_line));
        authorized.extend(extra_authorized.iter().map(|l| l.trim_end().to_string()));
        let h = home.path().display().to_string();
        let sshd = TestSshd::start_with(SshdOptions {
            authorized_keys: authorized,
            session_env: vec![
                ("HOME".into(), h.clone()),
                ("XDG_CACHE_HOME".into(), format!("{h}/.cache")),
                ("XDG_CONFIG_HOME".into(), format!("{h}/.config")),
                ("PATH".into(), format!("{h}/bin:/usr/bin:/bin")),
            ],
            ..SshdOptions::default()
        });
        let sandbox = Sandbox { sshd, home, logins };
        sandbox.assert_private_home(probe);
        ssh_support::sftp_probe(&sandbox.sshd, &sftp_key);
        sandbox
    }

    pub fn cache(&self) -> PathBuf {
        self.home.path().join(".cache/qsh")
    }

    /// The request `bring_up` gets in these tests, with the next unused key.
    pub fn request(&mut self, qsh_port: u16) -> bringup::BringUpRequest {
        let signer = self.logins.pop().expect("more logins than LOGINS");
        bringup::BringUpRequest {
            name: "console".into(),
            ssh: self.params(),
            auth: ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
            qsh_port,
            client_pubkey: [9u8; 32],
        }
    }

    fn params(&self) -> ssh::SshParams {
        ssh_support::params(
            &self.sshd,
            vec![ssh_support::wire_of(&self.sshd.host_public_key_line())],
        )
    }

    /// Runs `script` over SSH (through the login shell, not `bringup`) and
    /// returns its output: an independent look at the session.
    fn run(&self, signer: SoftSigner, script: &str) -> String {
        struct Forward(mpsc::Sender<SubstrateEvent>);
        impl ssh::SshEvents for Forward {
            fn on_channel(&self, event: SubstrateEvent) {
                let _ = self.0.send(event);
            }
            fn on_closed(&self, _: String) {}
        }
        let (tx, rx) = mpsc::channel();
        let (conn, mut sub) = ssh::connect(
            self.params(),
            ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
            Arc::new(knock::NoBind),
            Arc::new(Forward(tx)),
            &knock::Cancel::new(),
        )
        .expect("ssh for the environment check");
        sub.open(&OpenRequest {
            stream: 1,
            kind: ChannelKind::Command,
            cols: 0,
            rows: 0,
            screen: false,
            command: script.as_bytes().to_vec(),
        })
        .expect("environment check Open admitted");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut out = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx
                .recv_timeout(left)
                .expect("the environment check finished in time")
            {
                SubstrateEvent::Data { bytes, .. } => out.extend(bytes),
                SubstrateEvent::Exit { .. } => break,
                SubstrateEvent::Refused { reason, .. } => {
                    panic!("the environment check was refused: {reason}")
                }
                _ => {}
            }
        }
        conn.close();
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Panics unless the session sees exactly the private home, cache and PATH.
    fn assert_private_home(&self, probe: SoftSigner) {
        let h = self.home.path().display().to_string();
        let seen = self.run(
            probe,
            "printf '%s|%s|%s' \"$HOME\" \"$XDG_CACHE_HOME\" \"$PATH\"",
        );
        assert_eq!(
            seen,
            format!("{h}|{h}/.cache|{h}/bin:/usr/bin:/bin"),
            "sshd did not give the session the private home: refusing to run qshd, \
             it would reach the developer's own daemon"
        );
    }

    /// Puts this workspace's qshd into the cache as `qshd-<version>-<arch>`.
    pub fn cache_real_qshd(&self, version: &str) -> PathBuf {
        let to = self
            .cache()
            .join(format!("qshd-{version}-{}", std::env::consts::ARCH));
        std::fs::copy(qshd_path(), &to).unwrap();
        to
    }

    /// A shell script posing as qshd, at `path`, executable.
    pub fn fake_qshd(&self, path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        // Only this sandbox's own daemon, through its own control socket,
        // and before the home it lives in goes (fields drop after this): the
        // shared guard stops it, waits for it, and finishes off one that
        // ignores STOP through a pidfd it opened while the daemon answered.
        drop(daemon_guard::DaemonGuard::new(
            self.cache().join("control.sock"),
        ));
    }
}

/// This workspace's qshd. `CARGO_BIN_EXE_qshd` exists only for the qshd
/// package's own tests (see `cli/tests/support/mod.rs`). Workspace runs
/// supply QSH_TEST_QSHD so this helper cannot replace their feature build.
/// Standalone runs without that override build here every time: cargo
/// makes that a no-op when it is fresh, and a
/// binary left over from before a qshd change would test the old daemon.
/// This test binary is `target/<profile>/deps/<name>`.
pub fn qshd_path() -> PathBuf {
    if let Some(path) = std::env::var_os("QSH_TEST_QSHD") {
        use std::os::unix::ffi::OsStrExt;

        let path = PathBuf::from(path);
        let executable = path.is_absolute()
            && path.is_file()
            && std::ffi::CString::new(path.as_os_str().as_bytes()).is_ok_and(|path| {
                // Check execute permission without running the fixture. The
                // CString owns a valid, NUL-terminated path for this call.
                unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
            });
        assert!(
            executable,
            "QSH_TEST_QSHD must name an absolute executable file"
        );
        return path;
    }

    let exe = std::env::current_exe().expect("the test binary's path");
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>/deps/<test>")
        .to_path_buf();
    let target_dir = profile_dir
        .parent()
        .expect("the target directory")
        .to_path_buf();
    // Cargo finds the workspace from any member's directory; the including
    // crate's own manifest directory works wherever this file is included
    // from (`crates/bringup` here, `cli` for the console client's tests).
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut build = Command::new(cargo);
    build
        .args(["build", "-p", "qshd", "--bin", "qshd", "--target-dir"])
        .arg(&target_dir)
        .current_dir(workspace);
    if profile_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    } else {
        // Match the workspace's optimized test profile. A plain dev build
        // hashes its large debug executable on the first STATUS request
        // slowly enough to exceed the control timeout on a busy runner.
        build.args(["--profile", "test"]);
    }
    let out = build.output().expect("run cargo to build qshd");
    assert!(
        out.status.success(),
        "building qshd failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let candidate = profile_dir.join("qshd");
    assert!(
        candidate.is_file(),
        "no qshd at {} after building",
        candidate.display()
    );
    candidate
}

/// Processes whose command line names `dir`: what a test started from its
/// sandbox and is still running. Read from /proc only; nothing is signalled.
pub fn processes_under(dir: &Path) -> Vec<String> {
    let needle = dir.display().to_string();
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&raw).replace('\0', " ");
        if cmdline.contains(&needle) {
            found.push(format!("{pid} {}", cmdline.trim_end()));
        }
    }
    found
}

/// One daemon test at a time in this binary: they pick UDP ports.
pub fn serialised() -> std::sync::MutexGuard<'static, ()> {
    static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ONE.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A caller-owned image with an observable load count.
pub struct MemoryImages {
    pub image: bringup::DaemonImage,
    pub calls: std::sync::atomic::AtomicUsize,
}

impl bringup::ImageSource for MemoryImages {
    fn load(
        &self,
        _: &bringup::ImageRequest,
        _: &bringup::InstallTiming,
        _: &knock::Cancel,
        _: &dyn bringup::BringUpObserver,
    ) -> Result<bringup::DaemonImage, bringup::ImageError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.image.clone())
    }
}

pub struct RecordingApproval {
    pub accept: bool,
    pub offers: std::sync::Mutex<Vec<bringup::InstallOffer>>,
}

impl bringup::InstallApproval for RecordingApproval {
    fn approve(
        &self,
        offer: &bringup::InstallOffer,
        _: &knock::Cancel,
    ) -> Result<bool, bringup::BringUpError> {
        self.offers.lock().unwrap().push(offer.clone());
        Ok(self.accept)
    }
}

#[derive(Default)]
pub struct RecordingObserver {
    pub events: std::sync::Mutex<Vec<bringup::BringUpProgress>>,
    /// Test-owned pause/cancel points at the public stage boundaries.
    pub callback: Option<Box<dyn Fn(bringup::BringUpProgress) + Send + Sync>>,
}

impl bringup::BringUpObserver for RecordingObserver {
    fn on_progress(&self, event: bringup::BringUpProgress) {
        self.events.lock().unwrap().push(event);
        if let Some(callback) = &self.callback {
            callback(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Child, Stdio};

    struct FixtureChild(Child);

    impl Drop for FixtureChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn check_in_child(valid: bool) -> bool {
        if std::env::var_os("QSH_FIXTURE_CHECK_CHILD").is_none() {
            return false;
        }
        let result = std::panic::catch_unwind(qshd_path);
        if valid {
            let expected = PathBuf::from(std::env::var_os("QSH_TEST_QSHD").unwrap());
            assert!(result.is_ok_and(|path| path == expected));
        } else {
            let error = result.expect_err("an invalid explicit fixture must fail");
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(message.contains("QSH_TEST_QSHD must name an absolute executable file"));
        }
        std::fs::write(std::env::var_os("QSH_FIXTURE_CHECK_DONE").unwrap(), b"done").unwrap();
        true
    }

    fn run_fixture_case(test_name: &str, candidate: &Path) {
        let sandbox = tempfile::tempdir().unwrap();
        let marker = sandbox.path().join("cargo-ran");
        let completed = sandbox.path().join("check-completed");
        // Libtest names omit the crate prefix supplied by module_path!().
        let test_name = test_name.split_once("::").unwrap().1;
        if !candidate.is_absolute() && !candidate.as_os_str().is_empty() {
            let relative_fixture = sandbox.path().join(candidate);
            std::fs::write(&relative_fixture, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&relative_fixture, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let cargo = sandbox.path().join("cargo-tripwire");
        std::fs::write(
            &cargo,
            b"#!/bin/sh\nprintf x > \"$QSH_FIXTURE_CARGO_MARKER\"\nexit 91\n",
        )
        .unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let mut child = FixtureChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .current_dir(sandbox.path())
                .env("QSH_FIXTURE_CHECK_CHILD", "1")
                .env("QSH_FIXTURE_CHECK_DONE", &completed)
                .env("QSH_TEST_QSHD", candidate)
                .env("CARGO", &cargo)
                .env("QSH_FIXTURE_CARGO_MARKER", &marker)
                .env("HOME", sandbox.path())
                .env("XDG_CACHE_HOME", sandbox.path().join("cache"))
                .env("XDG_CONFIG_HOME", sandbox.path().join("config"))
                .env("HISTFILE", "/dev/null")
                .env("RUST_BACKTRACE", "0")
                .env_remove("SSH_AUTH_SOCK")
                .env_remove("SSH_AGENT_PID")
                .stdin(Stdio::null())
                // Keep the nested libtest summary out of strict CI log checks.
                // The parent reports failures through bounded stderr below.
                .stdout(Stdio::null())
                .stderr(stderr.try_clone().unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "fixture check timed out");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(!marker.exists(), "Cargo ran for an explicit daemon fixture");
        stderr.seek(SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        stderr.take(1024).read_to_end(&mut output).unwrap();
        assert!(
            status.success(),
            "fixture check failed: {:?}",
            String::from_utf8_lossy(&output)
        );
        assert!(completed.exists(), "the selected fixture probe did not run");
    }

    #[test]
    fn explicit_prebuilt_qshd_is_used_without_rebuilding_or_changing_it() {
        if check_in_child(true) {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("prebuilt-qshd");
        let bytes = b"#!/bin/sh\nexit 0\n";
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        run_fixture_case(
            concat!(
                module_path!(),
                "::explicit_prebuilt_qshd_is_used_without_rebuilding_or_changing_it"
            ),
            &path,
        );
        assert!(std::fs::read(path).unwrap() == bytes);
    }

    #[test]
    fn invalid_prebuilt_qshd_fails_without_building_a_replacement() {
        if check_in_child(false) {
            return;
        }
        let fixture = tempfile::tempdir().unwrap();
        let non_executable = fixture.path().join("non-executable");
        std::fs::write(&non_executable, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        for path in [
            PathBuf::new(),
            PathBuf::from("relative-qshd"),
            fixture.path().join("missing"),
            fixture.path().to_path_buf(),
            non_executable,
        ] {
            run_fixture_case(
                concat!(
                    module_path!(),
                    "::invalid_prebuilt_qshd_fails_without_building_a_replacement"
                ),
                &path,
            );
        }
    }
}
