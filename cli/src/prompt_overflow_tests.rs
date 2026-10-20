// Acknowledges the real reader's overflow branch, so cancellation is delivered
// after discard starts rather than racing PTY line-discipline input delivery.
pub(super) static DISCARD_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// Real terminal I/O through Tty, not a copied confirmation parser.
#[test]
fn overlong_confirmation_line_cannot_answer_the_next_question() {
    let _serial = crate::tty::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let pty = nix::pty::openpty(None, None).unwrap();
    let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
    let mut master = File::from(pty.master);
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let first = tty.confirm("overflow-first?");
        let second = tty.confirm("overflow-second?");
        let _ = tx.send((first, second));
    });
    let first_shown = read_until(&mut master, "overflow-first? [y/N]");
    let mut line = vec![b'x'; 129];
    line.extend_from_slice(b"yes\n");
    let sent = master.write_all(&line).is_ok();
    let second_shown = read_until(&mut master, "overflow-second? [y/N]");
    let fresh_sent = master.write_all(b"no\n").is_ok();
    let result = rx.recv_timeout(std::time::Duration::from_secs(2));
    // On any failure, hangup releases the owned slave reader before joining.
    drop(master);
    worker.join().unwrap();
    assert!(first_shown.contains("overflow-first? [y/N]"));
    assert!(sent && fresh_sent && second_shown.contains("overflow-second? [y/N]"));
    assert_eq!(
        result.unwrap(),
        (false, false),
        "only the fresh answer may answer the second question"
    );
}

#[test]
fn confirmation_overflow_boundary_keeps_defaults_and_the_next_complete_line() {
    let _serial = crate::tty::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for accept_empty in [false, true] {
        for length in [0, 127, 128, 129] {
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let mut master = File::from(pty.master);
            let mut input = if length == 0 {
                Vec::new()
            } else {
                let mut input = b"yes".to_vec();
                input.resize(length, b' ');
                input
            };
            // The following complete line must survive, including its genuine
            // empty-answer default; no tcflush or buffered read-ahead is safe.
            input.extend_from_slice(b"\n\n");
            master.write_all(&input).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let cancel = knock::Cancel::new();
                let first = tty.confirm_with_default("boundary-first?", &cancel, accept_empty);
                let next = tty.confirm_with_default("boundary-next?", &cancel, accept_empty);
                let _ = tx.send((first, next));
            });
            let result = rx.recv_timeout(std::time::Duration::from_secs(2));
            drop(master);
            worker.join().unwrap();
            let (first, next) = result.unwrap();
            let expected = if length == 0 {
                accept_empty
            } else {
                length <= 128
            };
            assert_eq!(
                first.unwrap(),
                expected,
                "length={length}, default={accept_empty}"
            );
            assert_eq!(
                next.unwrap(),
                accept_empty,
                "the next line/default was consumed"
            );
        }
    }
}

fn noncanonical_confirmation_pty() -> (nix::pty::OpenptyResult, Tty) {
    use nix::sys::termios::{self, LocalFlags, SetArg, SpecialCharacterIndices};
    let pty = nix::pty::openpty(None, None).unwrap();
    let mut settings = termios::tcgetattr(&pty.slave).unwrap();
    settings.local_flags.remove(LocalFlags::ICANON);
    settings.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    settings.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    termios::tcsetattr(&pty.slave, SetArg::TCSANOW, &settings).unwrap();
    let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
    (pty, tty)
}

fn confirmation_discard_started() -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !DISCARD_STARTED.load(std::sync::atomic::Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    true
}

// The fixture makes a partial line readable; the production routine continues
// to use the caller's terminal settings unchanged.
fn confirmation_discard_interrupt(terminate: bool, eof: bool) {
    DISCARD_STARTED.store(false, std::sync::atomic::Ordering::SeqCst);
    let (pty, tty) = noncanonical_confirmation_pty();
    let mut master = Some(File::from(pty.master));
    let cancel = knock::Cancel::new();
    let worker_cancel = cancel.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = tty.confirm_install("discard-ready?", &worker_cancel);
        let _ = tx.send(result);
    });
    let shown = read_until(master.as_mut().unwrap(), "discard-ready? [Y/n]");
    let sent = master.as_mut().unwrap().write_all(&[b'x'; 129]).is_ok();
    let consumed = sent && confirmation_discard_started();
    let start = std::time::Instant::now();
    if terminate {
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).unwrap();
    } else if !eof {
        cancel.cancel();
    }
    if eof {
        drop(master.take());
    }
    let result = rx.recv_timeout(std::time::Duration::from_secs(1));
    let elapsed = start.elapsed();
    // Even a broken interruption path stays owned: sticky cancel releases it,
    // and the master is closed before the final worker join.
    cancel.cancel();
    drop(master.take());
    worker.join().unwrap();
    assert!(shown.contains("discard-ready? [Y/n]") && sent && consumed);
    if eof {
        assert!(!result.unwrap().unwrap(), "EOF must refuse default-Yes");
    } else {
        assert!(matches!(result.unwrap(), Err(ssh::SshError::Cancelled)));
    }
    assert!(elapsed < std::time::Duration::from_secs(1));
}

#[test]
fn confirmation_overflow_discard_observes_cancel_and_eof() {
    let _serial = crate::tty::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    confirmation_discard_interrupt(false, false);
    confirmation_discard_interrupt(false, true);
}

#[test]
fn confirmation_overflow_discard_observes_owned_sigterm() {
    const CHILD: &str = "QSH_CONFIRMATION_DISCARD_SIGNAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        crate::signals::install().unwrap();
        confirmation_discard_interrupt(true, false);
        return;
    }
    let output = tempfile::NamedTempFile::new().unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "prompt::tests::confirmation_overflow_discard_observes_owned_sigterm",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::null())
        .stdout(output.reopen().unwrap())
        .stderr(output.reopen().unwrap())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            // Child is still retained and unreaped; never signal a reaped PID.
            let _ = child.kill();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let log = std::fs::read_to_string(output.path()).unwrap();
    assert!(
        status.is_some_and(|s| s.success()),
        "owned signal control: {status:?}\n{log}"
    );
}
