#![cfg(unix)]

mod support;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::sync::{Arc, Mutex};
use support::*;

fn output_preview(text: &str) -> String {
    format!("{:?}", text.chars().take(512).collect::<String>())
}

fn malformed() -> OsString {
    OsString::from_vec(b"alice@invalid-\xff".to_vec())
}

fn exited_output(args: &[OsString], argv0: Option<&std::ffi::OsStr>) -> (i32, Vec<u8>) {
    let config = tempfile::tempdir().unwrap();
    let (mut client, slave) = spawn_qsh_os_on(args, config.path(), argv0);
    drop(slave);
    let mut reader = client.master.try_clone().unwrap();
    let collector = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0; 4096];
        while let Ok(n) = reader.read(&mut buffer) {
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..n]);
        }
        bytes
    });
    let status = wait_for_exit(&mut client.child).expect("argument parsing must exit");
    let bytes = collector.join().unwrap();
    assert_eq!(
        std::fs::read_dir(config.path()).unwrap().count(),
        0,
        "argument errors and early exits must not create client state"
    );
    (status.code().unwrap(), bytes)
}

#[test]
fn malformed_text_exits_with_usage_without_panicking_or_creating_state() {
    for args in [
        vec![malformed()],
        vec!["--port".into(), malformed()],
        vec![OsString::from_vec(b"--invalid-\xff".to_vec())],
    ] {
        let position = args.len();
        let (code, bytes) = exited_output(&args, None);
        assert_eq!(code, 2);
        let text = String::from_utf8(bytes)
            .unwrap_or_else(|_| panic!("captured output must be valid UTF-8"));
        assert!(text.contains(&format!("argument {position} must be valid UTF-8")));
        assert!(!text.contains("panicked"));
        assert!(!text.contains("backtrace"));
    }
}

#[test]
fn malformed_diagnostic_is_bounded_and_does_not_echo_argument_bytes() {
    let mut bytes = b"\x1b[31m\nSYNTHETIC_SECRET_MARKER\n".repeat(1024);
    bytes.push(0xff);
    let (code, output) = exited_output(&[OsString::from_vec(bytes)], None);
    assert_eq!(code, 2);
    let text =
        String::from_utf8(output).unwrap_or_else(|_| panic!("captured output must be valid UTF-8"));
    assert!(text.contains("argument 1 must be valid UTF-8"));
    assert!(!text.contains("SYNTHETIC_SECRET_MARKER"));
    assert!(!text.contains('\x1b'));
    assert!(text.len() <= qsh::args::USAGE.len() + qsh::args::USAGE.lines().count() + 128);
}

#[test]
fn executable_name_and_unconsumed_help_arguments_need_not_be_utf8() {
    let (code, bytes) = exited_output(&["--help".into(), malformed()], Some(&malformed()));
    assert_eq!(code, 0);
    assert!(String::from_utf8(bytes)
        .unwrap_or_else(|_| panic!("captured output must be valid UTF-8"))
        .contains("Usage:"));
}

#[test]
fn a_non_utf8_identity_filename_authenticates_and_runs_a_shell() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let identity = key_path.with_file_name(OsString::from_vec(b"identity-\xff".to_vec()));
    std::fs::rename(&key_path, &identity).unwrap();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh_os(
        &[
            "--port".into(),
            daemon.port.to_string().into(),
            "-i".into(),
            identity.into_os_string(),
            "127.0.0.1".into(),
        ],
        config.path(),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    let text = || String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "{}",
        output_preview(&text())
    );
    client.master.write_all(b"yes\n").unwrap();
    client.type_line("echo os-path-$((6*7))");
    assert!(
        wait_until(|| text().contains("os-path-42")),
        "{}",
        output_preview(&text())
    );
    client.type_line("exit");
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(0));
}
