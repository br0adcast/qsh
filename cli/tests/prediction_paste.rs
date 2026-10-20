//! Large input remains byte-exact when speculative rendering reaches its budget.
mod support;

use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::*;

fn screen(seen: &Arc<Mutex<Vec<u8>>>) -> String {
    let mut terminal = terminal::TerminalCore::new(80, 24);
    terminal.feed(&seen.lock().unwrap());
    terminal.frame().cells.iter().map(|cell| cell.ch).collect()
}

// All duplicates share these flags. Install them before starting the matching
// drain below, which explicitly retries WouldBlock instead of losing output.
fn nonblocking(master: &std::fs::File) {
    let flags = nix::fcntl::fcntl(master.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFL).unwrap();
    nix::fcntl::fcntl(
        master.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .unwrap();
}

fn drain_nonblocking(mut master: std::fs::File, seen: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        loop {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => seen.lock().unwrap().extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
}

// Nonblocking writes keep the delivery itself inside the result deadline.
// On failure, terminate and reap only this fixture's client before returning.
fn write_before(client: &mut Client, mut payload: &[u8], deadline: Instant) -> io::Result<()> {
    let result = (|| {
        while !payload.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PTY input deadline",
                ));
            }
            match client.master.write(payload) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PTY input")),
                Ok(n) => payload = &payload[n..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = client.child.kill();
        let _ = client.child.wait();
    }
    result
}

fn wait_before(deadline: Instant, mut probe: impl FnMut() -> bool) -> bool {
    loop {
        if probe() {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        std::thread::sleep(remaining.min(Duration::from_millis(50)));
    }
}

#[test]
fn stalled_pty_input_times_out_and_reaps_its_owned_reader() {
    let _serial = serialised();
    let pty = nix::pty::openpty(None, None).unwrap();
    let mut settings = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
    nix::sys::termios::cfmakeraw(&mut settings);
    nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &settings)
        .unwrap();
    let mut command = Command::new("sleep");
    command
        .arg("60")
        .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
        .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
        .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
    make_it_the_controlling_terminal(&mut command);
    let child = command.spawn().unwrap();
    // No parent-owned slave may keep a blocked writer alive after child exit.
    drop(command);
    drop(pty.slave);
    let mut client = Client {
        child,
        master: std::fs::File::from(pty.master),
    };
    nonblocking(&client.master);
    let error = write_before(
        &mut client,
        &vec![b'p'; 1 << 20],
        Instant::now() + Duration::from_millis(100),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(client.child.try_wait().unwrap().is_some());
}

#[test]
fn raw_and_bracketed_megabyte_pastes_arrive_with_adaptive_or_disabled_prediction() {
    let _serial = serialised();
    for mode in ["adaptive", "never"] {
        for bracketed in [false, true] {
            let (daemon, key) = start_daemon();
            let config = tempfile::tempdir().unwrap();
            let mut client = spawn_client_with(&daemon, &key, config.path(), &["--predict", mode]);
            let seen = Arc::new(Mutex::new(Vec::new()));
            nonblocking(&client.master);
            drain_nonblocking(client.master.try_clone().unwrap(), seen.clone());
            assert!(
                wait_until(
                    || String::from_utf8_lossy(&seen.lock().unwrap()).contains("Key fingerprint")
                ),
                "trust prompt: {}; initial output: {}",
                screen(&seen),
                String::from_utf8_lossy(&seen.lock().unwrap())
                    .chars()
                    .take(1024)
                    .collect::<String>()
            );
            client.master.write_all(b"yes\n").unwrap();
            let mut payload = Vec::with_capacity(1 << 20);
            if bracketed {
                payload.extend_from_slice(b"\x1b[200~");
            }
            let target = (1 << 20) - if bracketed { 6 } else { 0 };
            let unit = "p界e\u{301}".as_bytes();
            while payload.len() + unit.len() <= target {
                payload.extend_from_slice(unit);
            }
            payload.resize(target, b'p');
            if bracketed {
                payload.extend_from_slice(b"\x1b[201~");
            }
            assert_eq!(payload.len(), 1 << 20);
            let digest = format!("{:x}", Sha256::digest(&payload));
            let paste_mode = if bracketed { "\\033[?2004h" } else { "" };
            // The reader runs with echo disabled. Its computed count and digest
            // cannot be supplied by local PTY echo or predicted text. Its file is
            // under this daemon's disposable HOME, with a trap for early exits.
            client.type_line(&format!(
                "unset HISTFILE; f=$(mktemp); trap 'stty sane; rm -f \"$f\"' EXIT; \
                 stty raw -echo; printf '{paste_mode}\\r\\nBUDGET-READY-%s\\r\\n' \"$((6*7))\"; \
                 head -c {} > \"$f\"; printf '\\r\\nBUDGET-SHA=%s\\r\\nBUDGET-N=%s\\r\\n' \
                 \"$(sha256sum \"$f\" | cut -d ' ' -f 1)\" \"$(wc -c < \"$f\")\"; \
                 rm -f \"$f\"; trap - EXIT; stty sane; printf '\\033[?2004lBUDGET-DONE-%s\\r\\n' \"$((6*7))\"",
                 payload.len()));
            assert!(
                wait_until(|| screen(&seen).contains("BUDGET-READY-42")),
                "ready {mode}/{bracketed}: {}",
                screen(&seen)
            );
            let deadline = Instant::now() + Duration::from_secs(20);
            write_before(&mut client, &payload, deadline).expect("bounded PTY paste delivery");
            assert!(
                wait_before(deadline, || screen(&seen).contains("BUDGET-DONE-42")),
                "paste {mode}/{bracketed}: {} daemon:{}",
                screen(&seen),
                daemon.output_text()
            );
            let output = screen(&seen);
            assert!(
                output.contains(&format!("BUDGET-SHA={digest}")),
                "digest {mode}/{bracketed}: {output}"
            );
            assert!(
                output.contains("BUDGET-N=1048576"),
                "count {mode}/{bracketed}: {output}"
            );
            client.type_line("printf '\\r\\nBUDGET-AFTER-%s\\r\\n' \"$((7*6))\"");
            assert!(
                wait_until(|| screen(&seen).contains("BUDGET-AFTER-42")),
                "fresh typing {mode}/{bracketed}: {}",
                screen(&seen)
            );
            client.master.write_all(b"\x1d.").unwrap();
            assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
        }
    }
}
