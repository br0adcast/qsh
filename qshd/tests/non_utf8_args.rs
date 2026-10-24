#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn output_preview(text: &str) -> String {
    format!("{:?}", text.chars().take(512).collect::<String>())
}

struct Running {
    child: Child,
    output: std::fs::File,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn spawn(args: &[OsString], home: &std::path::Path) -> Self {
        Self::spawn_named(args, home, std::ffi::OsStr::new("qshd"))
    }

    fn spawn_named(args: &[OsString], home: &std::path::Path, name: &std::ffi::OsStr) -> Self {
        let output = tempfile::tempfile().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_qshd"))
            .arg0(name)
            .args(args)
            .env("HOME", home)
            .env("XDG_CACHE_HOME", home)
            .env("XDG_CONFIG_HOME", home)
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("QSHD_HANDOVER_FD")
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output.try_clone().unwrap())
            .spawn()
            .unwrap();
        Self { child, output }
    }

    fn text(&mut self) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let n = self
                .output
                .read_at(&mut buffer, bytes.len() as u64)
                .unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..n]);
        }
        String::from_utf8(bytes).unwrap_or_else(|_| panic!("captured output must be valid UTF-8"))
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "argument parsing did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn invalid() -> OsString {
    OsString::from_vec(b"bad-\xff".to_vec())
}

#[test]
fn invalid_command_flags_and_text_values_fail_without_startup_side_effects() {
    let cases = [
        vec![invalid()],
        vec!["transport-echo".into(), invalid()],
        vec!["transport-echo".into(), "--port".into(), invalid()],
        vec![
            "transport-shell".into(),
            "--client-pubkey".into(),
            invalid(),
        ],
        vec!["transport-ensure".into(), "--name".into(), invalid()],
        vec!["serve".into(), "--port".into(), invalid()],
        vec!["serve".into(), "--worker-user".into(), invalid()],
        vec![
            "serve".into(),
            "--authorized-keys-template".into(),
            invalid(),
        ],
    ];
    for args in cases {
        let home = tempfile::tempdir().unwrap();
        let mut run = Running::spawn(&args, home.path());
        assert_eq!(run.wait().code(), Some(1));
        let text = run.text();
        let unsupported = !cfg!(feature = "system")
            && args
                .iter()
                .any(|a| a == "--worker-user" || a == "--authorized-keys-template");
        if unsupported {
            assert!(
                text.contains("built without the system mode"),
                "{}",
                output_preview(&text)
            );
        } else {
            assert!(
                text.contains(&format!("argument {} must be valid UTF-8", args.len())),
                "{}",
                output_preview(&text)
            );
        }
        assert!(!text.contains("panicked"));
        assert!(!text.contains("backtrace"));
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn invalid_diagnostics_are_bounded_and_do_not_echo_controls_or_secrets() {
    let mut bytes = b"\x1b[31m\nSYNTHETIC_SECRET_MARKER\n".repeat(1024);
    bytes.push(0xff);
    for prefix in [vec![], vec!["transport-ensure".into(), "--name".into()]] {
        let mut args = prefix;
        args.push(OsString::from_vec(bytes.clone()));
        let home = tempfile::tempdir().unwrap();
        let mut run = Running::spawn(&args, home.path());
        assert_eq!(run.wait().code(), Some(1));
        let text = run.text();
        assert!(
            text.contains("must be valid UTF-8"),
            "{}",
            output_preview(&text)
        );
        assert!(text.len() < 128);
        assert!(!text.contains("SYNTHETIC_SECRET_MARKER"));
        assert!(!text.contains('\x1b'));
    }
}

#[test]
fn help_version_and_self_check_keep_early_exit_semantics() {
    for flag in ["--help", "--version", "self-check"] {
        let home = tempfile::tempdir().unwrap();
        let mut run = Running::spawn_named(&[flag.into(), invalid()], home.path(), &invalid());
        assert!(run.wait().success());
        assert!(!run.text().contains("panicked"));
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn a_foreground_daemon_loads_its_exact_non_utf8_host_key_path() {
    use base64::Engine as _;
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = home.path().join(OsString::from_vec(b"host-\xff".to_vec()));
    let key = qshd::load_or_create_transport_key(&path).unwrap();
    let original = std::fs::read(&path).unwrap();
    let port = std::net::UdpSocket::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut run = Running::spawn(
        &[
            "transport-echo".into(),
            "--port".into(),
            port.to_string().into(),
            "--server-key-file".into(),
            path.clone().into_os_string(),
        ],
        home.path(),
    );
    let expected = format!(
        "server-pubkey: {}",
        base64::engine::general_purpose::STANDARD.encode(key.public)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = run.text();
        if text.contains(&expected) && std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        assert!(
            run.child.try_wait().unwrap().is_none(),
            "{}",
            output_preview(&text)
        );
        assert!(
            Instant::now() < deadline,
            "daemon did not start: {}",
            output_preview(&text)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::fs::read(&path).unwrap() == original,
        "the existing host key file must remain byte-for-byte unchanged"
    );
    assert!(!home.path().join("host-\u{fffd}").exists());
}
