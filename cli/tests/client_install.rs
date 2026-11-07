//! Actual command dispatch on the same controlling PTY as session regressions.
mod support;
use std::io::Read;

fn run(args: &[&str], home: &std::path::Path) -> (i32, String) {
    let mut client = support::spawn_qsh(args, home);
    let status = support::wait_for_exit(&mut client.child).expect("managed command timed out");
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match client.master.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => output.extend_from_slice(&buffer[..n]),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(e) => panic!("PTY read failed: {e}"),
        }
    }
    (
        status.code().unwrap(),
        String::from_utf8_lossy(&output).replace("\r\n", "\n"),
    )
}

#[test]
fn managed_help_capability_pty_has_no_state() {
    let home = tempfile::tempdir().unwrap();
    let (code, output) = run(&["--self-install", "--help"], home.path());
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        output,
        "Usage: qsh --self-install [--version VERSION] [--prefix PATH]\n"
    );
    let (code, output) = run(&["--self-update", "--help"], home.path());
    assert_eq!(code, 0, "{output}");
    assert_eq!(output, "Usage: qsh --self-update [--version VERSION]\n");
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn development_managed_commands_pty_refuse_without_state() {
    // Official release test builds have a different compile-time policy.
    if option_env!("QSH_CLIENT_OFFICIAL") == Some("1") {
        return;
    }
    let home = tempfile::tempdir().unwrap();
    for flag in ["--self-install", "--self-update"] {
        let (code, output) = run(&[flag], home.path());
        assert_eq!(code, 1, "{output}");
        assert!(
            output.contains("development/source builds cannot download"),
            "{output}"
        );
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }
}

#[test]
fn ordinary_help_lists_managed_commands_pty() {
    let home = tempfile::tempdir().unwrap();
    let (code, output) = run(&["--help"], home.path());
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("qsh --self-install [--version VERSION] [--prefix PATH]"));
    assert!(output.contains("qsh --self-update [--version VERSION]"));
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn invalid_managed_session_mix_pty_exits_before_startup() {
    let home = tempfile::tempdir().unwrap();
    let (code, output) = run(&["--self-update", "host"], home.path());
    assert_eq!(code, 2, "{output}");
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
