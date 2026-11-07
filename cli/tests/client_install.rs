//! Actual command dispatch on the same controlling PTY as session regressions.
mod support;
use std::io::Read;

fn drain(master: &mut std::fs::File, output: &mut Vec<u8>) {
    let mut buffer = [0u8; 4096];
    // Finite turns preserve the child/deadline checks even if a broken client
    // writes continuously. Capture is bounded independently of the PTY queue.
    for _ in 0..256 {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                assert!(output.len() + n <= 1024 * 1024, "PTY output exceeded 1 MiB");
                output.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(e) => panic!("PTY read failed: {e}"),
        }
    }
}

fn run(args: &[&str], home: &std::path::Path) -> (i32, String) {
    use std::{
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };
    // Keep the slave open through the final drain: Darwin flushes unread
    // output when the last slave closes. Never wait for PTY EOF with it held.
    let (mut client, slave) = support::spawn_qsh_on(args, home);
    let flags = rustix::fs::fcntl_getfl(&client.master).unwrap();
    rustix::fs::fcntl_setfl(&client.master, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut output = Vec::new();
    let status = loop {
        // Drain while the client is running, so a full PTY cannot block exit.
        drain(&mut client.master, &mut output);
        if let Some(status) = client.child.try_wait().unwrap() {
            drain(&mut client.master, &mut output);
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "managed command timed out after capturing {} bytes",
            output.len()
        );
        let mut ready = libc::pollfd {
            fd: client.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the owned master stays open and ready describes one live fd.
        let result = unsafe { libc::poll(&mut ready, 1, 20) };
        assert!(
            result >= 0
                || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
            "PTY poll failed"
        );
    };
    drop(slave);
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

#[test]
fn pty_capture_drains_output_larger_than_terminal_queue() {
    let home = tempfile::tempdir().unwrap();
    // A real argument error emits this whole option plus usage, exceeding the
    // PTY output queue without introducing a separate executable fixture.
    let option = format!("--{}", "x".repeat(64 * 1024));
    let (code, output) = run(&[&option], home.path());
    assert_eq!(code, 2);
    let expected = format!("qsh: unknown option {option}\n\n{}\n", qsh::args::USAGE);
    assert!(
        output == expected,
        "PTY capture mismatch: actual {} bytes, expected {} bytes",
        output.len(),
        expected.len()
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
