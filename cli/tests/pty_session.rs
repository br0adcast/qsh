//! The client, end to end: a real `qshd serve`, a real `qsh` on a real
//! pseudo-terminal. Every piece below has its own unit tests; this is the
//! first time they run together, which is exactly where termios, signals,
//! the transport and the renderer can disagree.

mod support;

use std::io::{Read, Write};
use std::sync::Mutex;
use std::time::Duration;

use support::*;

/// Spec §5.5: `--verbose` writes what the transport agreed with the daemon.
#[test]
fn the_verbose_log_says_what_the_transport_agreed() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client_with(&daemon, &key_path, config.path(), &["--verbose"]);
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(
        client.master.try_clone().expect("clone master"),
        seen.clone(),
    );
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "client saw: {}",
        text()
    );
    client.master.write_all(b"yes\n").expect("answer");
    client
        .master
        .write_all(b"echo agreed-$((6*7))\n")
        .expect("type");
    assert!(
        wait_until(|| text().contains("agreed-42")),
        "client saw: {}\ndaemon: {}",
        text(),
        daemon.output_text()
    );
    let log = std::fs::read_to_string(config.path().join("qsh").join("log")).unwrap_or_default();
    assert!(
        log.contains("transport features: header-aad"),
        "the verbose log: {log}"
    );
    client.master.write_all(b"exit\n").expect("type exit");
    let _ = wait_for_exit(&mut client.child);
}

/// The whole path: first contact, a signed session, a live shell, and a
/// clean exit.
#[test]
fn a_signed_client_gets_a_shell_and_leaves_cleanly() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());

    // Reading the master from another thread: the client keeps painting, and
    // a blocking read here would otherwise stall the test's own writes.
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let collector = seen.clone();
    let mut reader = client.master.try_clone().expect("clone master");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            collector.lock().expect("seen").extend_from_slice(&buf[..n]);
        }
    });

    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();

    // First contact: the fingerprint, then the question.
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");

    // A shell that answers proves the signature was accepted, the PTY runs,
    // and the renderer is painting.
    client
        .master
        .write_all(b"echo qsh-works-$((6*7))\n")
        .expect("type");
    assert!(
        wait_until(|| text().contains("qsh-works-42")),
        "the shell must run the command and the client must paint it; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );

    // The shell exiting is the ordinary end, and it exits 0.
    client.master.write_all(b"exit\n").expect("type exit");
    let status = match wait_for_exit(&mut client.child) {
        Some(s) => s,
        None => panic!(
            "the client must exit on its own; client saw: {}\ndaemon's own output: {}",
            text(),
            daemon.output_text()
        ),
    };
    assert_eq!(
        status.code(),
        Some(0),
        "a shell that exited is not a failure; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );
}

/// A second run returns to the shell the first one left, rather than starting
/// another. The proof is a shell variable: only the process that was told
/// about it can print it back, so if the second run sees it, it is talking to
/// the same shell -- and the first run's client is not merely disconnected
/// but killed, the way a closed terminal or a network gone for good would
/// leave it.
#[test]
fn a_second_run_returns_to_the_shell_the_first_one_left() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    // The same config home for both runs: it holds the pinned host key and
    // the session store, which is what makes the second run a return.
    let config = tempfile::tempdir().expect("tempdir");

    let mut first = spawn_client(&daemon, &key_path, config.path());
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(
        first.master.try_clone().expect("clone master"),
        seen.clone(),
    );
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();

    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}",
        text()
    );
    first.master.write_all(b"yes\n").expect("answer");

    // A variable only this shell process knows.
    first
        .master
        .write_all(b"MARK=kept-$((6*7))\n")
        .expect("type");
    first.master.write_all(b"echo M=$MARK\n").expect("type");
    assert!(
        wait_until(|| text().contains("M=kept-42")),
        "the first run's shell must answer; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );

    // Killed, not exited: nothing tells the server this session is over, so
    // the session stays -- exactly the state a lost network leaves behind.
    let _ = first.child.kill();
    let _ = first.child.wait();

    let mut second = spawn_client(&daemon, &key_path, config.path());
    let seen2 = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(
        second.master.try_clone().expect("clone master"),
        seen2.clone(),
    );
    let text2 = || String::from_utf8_lossy(&seen2.lock().expect("seen")).into_owned();

    // No trust question this time: the host key is already pinned. A new
    // marker, not `M=`: the second run repaints the kept screen, where the
    // first run's `M=kept-42` still stands, so only a fresh answer proves
    // the shell took input.
    second
        .master
        .write_all(b"echo SECOND-$MARK\n")
        .expect("type");
    assert!(
        wait_until(|| text2().contains("SECOND-kept-42")),
        "the second run must land in the SAME shell, which still knows MARK; \
         client saw: {}\ndaemon's own output: {}",
        text2(),
        daemon.output_text()
    );

    second.master.write_all(b"exit\n").expect("type exit");
    let _ = wait_for_exit(&mut second.child);
}

/// The account the client claims, the way it works it out when neither the
/// address nor `-l` names one (`args::local_login`).
fn login() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

/// A key the server does not know must be refused with the code that says so
/// -- not with a timeout, and not with a shell. With one address and no ssh
/// the ladder has nothing else to try: every address failed, exit 12, and
/// the summary says why.
#[test]
fn an_unauthorised_key_is_refused_with_code_twelve() {
    let _serial = serialised();
    let (daemon, _authorised) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");

    // A key the server has never heard of. The first-contact question still
    // comes up on the way -- this run has its own empty config directory, so
    // nothing is pinned -- and is answered with `yes` below, exactly as the
    // happy path does; what is under test is what happens AFTER the server
    // has the signature.
    let stranger = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate");
    let stranger_path = config.path().join("stranger");
    std::fs::write(
        &stranger_path,
        stranger
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .as_bytes(),
    )
    .expect("write");

    let mut client = spawn_client(&daemon, &stranger_path, config.path());

    // Same threaded-read idiom as the happy path, and for the same reason:
    // a plain blocking `read` here has no deadline of its own, so a client
    // that neither prints nor exits would hang this read -- and the whole
    // suite behind it -- instead of failing this one test.
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let collector = seen.clone();
    let mut reader = client.master.try_clone().expect("clone master");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            collector.lock().expect("seen").extend_from_slice(&buf[..n]);
        }
    });
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();

    // Answer the first-contact question if it appears -- bounded by
    // `wait_until`'s own deadline, not an unbounded blocking read.
    let _ = wait_until(|| !text().is_empty());
    let _ = client.master.write_all(b"yes\n");

    let status = match wait_for_exit(&mut client.child) {
        Some(s) => s,
        None => panic!(
            "the client must give up; client saw: {}\ndaemon's own output: {}",
            text(),
            daemon.output_text()
        ),
    };
    assert_eq!(
        status.code(),
        Some(12),
        "an unauthorised key at the only address is exit 12 -- not a hang, \
         not a shell; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );
    // Exit 12 is also what an address that never answers ends in -- the
    // exit code alone would stay green through a regression that stops the
    // server from being reached at all. Pin the actual refusal too, so this
    // test fails on the right cause.
    assert!(
        text().contains(&format!(
            "qsh:   127.0.0.1:{}: no key was accepted over qsh for account {} (offered: {} (SHA256:",
            daemon.port,
            login(),
            stranger_path.display()
        )),
        "must specifically report the server refusing the key, and which key \
         was offered, not merely exit 12 for some other reason; client saw: {}\n\
         daemon's own output: {}",
        text(),
        daemon.output_text()
    );
}

/// Ctrl-C while a passphrase is typed (echo off, before any session and its
/// signal handlers) ends the run -- and the terminal has its echo back, as
/// after OpenSSH's own passphrase question.
#[test]
fn ctrl_c_at_a_passphrase_question_leaves_echo_on() {
    use std::os::unix::process::ExitStatusExt;
    let _serial = serialised();
    let (daemon, _) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate")
        .encrypt(&mut rand_core::OsRng, "correct horse")
        .expect("encrypt");
    let locked = config.path().join("locked");
    std::fs::write(
        &locked,
        key.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .as_bytes(),
    )
    .expect("write key");
    let port = daemon.port.to_string();
    let (mut client, slave) = spawn_qsh_on(
        &[
            "--port",
            &port,
            "-i",
            locked.to_str().expect("utf-8"),
            "127.0.0.1",
        ],
        config.path(),
    );
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(
        client.master.try_clone().expect("clone master"),
        seen.clone(),
    );
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();
    let echo = || {
        nix::sys::termios::tcgetattr(&slave)
            .expect("tcgetattr")
            .local_flags
            .contains(nix::sys::termios::LocalFlags::ECHO)
    };

    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "client saw: {}",
        text()
    );
    client.master.write_all(b"yes\n").expect("answer");
    assert!(
        wait_until(|| text().contains("Passphrase for key") && !echo()),
        "the passphrase question must be up with echo off, or this proves \
         nothing; client saw: {}",
        text()
    );

    client.master.write_all(&[0x03]).expect("Ctrl-C");
    let status = wait_for_exit(&mut client.child).expect("Ctrl-C ends the run");
    assert_eq!(
        status.signal(),
        Some(libc::SIGINT),
        "the run ends by the signal itself; client saw: {}",
        text()
    );
    assert!(echo(), "echo must be back on; client saw: {}", text());
}

/// The acceptance criterion, mechanised: output that happened while the
/// client was away must be on the screen when it comes back.
///
/// The client is stopped with `SIGSTOP` -- every one of its threads,
/// including the one that answers packets -- so the server sees silence: the
/// path is declared down after `PATH_DOWN_AFTER` (3 s) of silence, and the
/// server stops hoarding output and drops what the shell printed in the
/// meantime once `RESYNC_AFTER` (10 s) of silence has passed -- both
/// measured from the same start-of-silence instant (`last_recv_auth`, see
/// `crates/transport/src/conn.rs`), not stacked one after the other, so the
/// backlog is gone at 10 s of silence, not 13. Nothing retransmits those
/// bytes; the only way the marker below can land on the screen is a repaint
/// from the server's own screen model. Without that repaint, the final
/// assertion could not pass.
///
/// The stop duration is DERIVED from `transport::RESYNC_AFTER`, never
/// written out: a literal here would go on passing while testing nothing the
/// moment somebody tuned that constant above the stop, since the server would
/// then simply replay the backlog and the marker would arrive either way.
/// `CLIENT_DEATH_AFTER` is 45 s, so the stop has room to grow with it before
/// the client would be considered dead outright.
///
/// What this test does NOT distinguish is a repaint from a replayed backlog,
/// and no assertion on the client's screen can: the client is a full emulator
/// that paints FRAMES, not a pipe that echoes bytes, so both paths converge on
/// the same final screen. (Measured: with `RESYNC_AFTER` raised to 60 s -- the
/// backlog kept and replayed in full -- every assertion below still passes,
/// including one on the first of the 200 gap lines.) The property that
/// actually matters is this: with the backlog dropped, the screen still
/// comes back, and it comes back WHOLE.
#[test]
fn output_during_a_long_absence_survives_as_a_repaint() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());

    // Same threaded-read idiom as the other tests in this file: the client
    // keeps painting, and a blocking read here would stall the test's own
    // writes and signals.
    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let collector = seen.clone();
    let mut reader = client.master.try_clone().expect("clone master");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            collector.lock().expect("seen").extend_from_slice(&buf[..n]);
        }
    });
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();

    // First contact: the fingerprint, then the question.
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");

    // A shell that echoes back proves the session is live before the gap.
    client.type_line("echo shell-is-live-77");
    assert!(
        wait_until(|| text().contains("shell-is-live-77")),
        "the shell never produced anything before the gap; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );

    // A command that prints AFTER the client is already stopped -- squarely
    // inside the window the server later throws away. The marker is
    // computed by the shell (`$((6*7))`), not typed literally: the remote
    // pty echoes typed characters back over the wire as they are typed, so a
    // literal marker in the command text would show up on screen from that
    // echo alone, long before the command ever ran -- proving nothing about
    // repaint. `a_signed_client_gets_a_shell_and_leaves_cleanly`'s own
    // `qsh-works-$((6*7))` uses the same trick, for the same reason.
    //
    // A `printf` runs FIRST and is waited for below, before SIGSTOP: its
    // executed output is the only proof that the whole line -- including its
    // trailing Enter -- already reached the shell and started running.
    // Without that wait, SIGSTOP can land before the keystrokes ever leave
    // the client; `sleep 4` would then only start once the client resumes,
    // well outside the absence window, and the final assertion would pass
    // over ordinary live output -- proving nothing about repaint.
    //
    // Its sentinel is computed (`$((3+3))`), for exactly the same reason the
    // final marker is: a literal sentinel would be a substring of the typed
    // command itself, and the remote pty echoes typed characters back over
    // the wire as they are typed -- so a literal sentinel could be satisfied
    // by that echo alone, before Enter (let alone the command) ever ran,
    // making this wait no more meaningful than the race it exists to close.
    // 200 lines is far more than the 24-row pseudo-terminal holds, so the
    // gap scrolls the screen many times over -- the realistic shape of a
    // long absence, and the reason a repaint exists instead of a replay. It
    // also lets the assertions below demand a WHOLE screen back rather than
    // just the last line, which is what a partial or cursor-row-only repaint
    // would fail. The counter is zero-padded so no line's name is a prefix
    // of another's, and the loop is POSIX (`while`, not `seq`) because
    // `$SHELL` here is whatever the machine happens to set.
    client.type_line(
        "printf 'primed-%d\\n' $((3+3)); sleep 4; \
         i=1; while [ $i -le 200 ]; do printf 'gap-line-%03d\\n' $i; i=$((i+1)); done; \
         echo marker-in-the-gap-$((6*7))",
    );
    assert!(
        wait_until(|| text().contains("primed-6")),
        "the shell never started the command before the stop; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );

    let pid = client.pid();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGSTOP,
    )
    .expect("stop the client");

    // Past RESYNC_AFTER -- the point past which the backlog is dropped (see
    // the function doc comment) -- with a margin, and taken from the
    // transport itself rather than written out. The shell's output happens
    // at ~4 s into the stop, i.e. inside the window the server throws away.
    std::thread::sleep(transport::RESYNC_AFTER + Duration::from_secs(4));

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGCONT,
    )
    .expect("resume the client");

    assert!(
        wait_until(|| text().contains("marker-in-the-gap-42")),
        "the repaint never put the missed output on the screen.\nclient:\n{}\ndaemon:\n{}",
        text(),
        daemon.output_text()
    );
    // ...and a WHOLE screen came back, not just the line the marker is on: a
    // repaint that only re-sent the cursor's row, or stopped short of the
    // bottom, would satisfy the assertion above and fail this one.
    for line in ["gap-line-198", "gap-line-199", "gap-line-200"] {
        assert!(
            wait_until(|| text().contains(line)),
            "the repaint brought back the marker but not {line}, so it was not a whole screen.\nclient:\n{}\ndaemon:\n{}",
            text(),
            daemon.output_text()
        );
    }
}

/// Spec §4.13: the console client counts its channel's bytes as taken when
/// they reach the terminal, and says so. The daemon holds a stream with
/// credits to a window (512 KiB) past what was reported: a flood several
/// windows long gets through -- and the shell answers after it -- only if
/// the reports go out. Without them the daemon stops at the first window
/// and the screen freezes there for good.
#[test]
fn output_past_a_credit_window_keeps_coming() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());

    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    let collector = seen.clone();
    let mut reader = client.master.try_clone().expect("clone master");
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            collector.lock().expect("seen").extend_from_slice(&buf[..n]);
        }
    });
    let text = || String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned();

    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");
    client.type_line("echo flood-ready-$((6*7))");
    assert!(
        wait_until(|| text().contains("flood-ready-42")),
        "the shell never answered before the flood; client saw: {}\ndaemon's own output: {}",
        text(),
        daemon.output_text()
    );

    // 2 MB in lines of 100, four windows' worth; the marker is computed,
    // so the echo of the typed line cannot match it.
    client.type_line(
        "head -c 2000000 /dev/zero | tr '\\0' w | fold -w 100; echo flood-done-$((40+2))",
    );
    assert!(
        wait_until(|| text().contains("flood-done-42")),
        "the flood stopped short: a credit window and no more?\ndaemon's own output: {}",
        daemon.output_text()
    );

    client.type_line("exit");
    let status = wait_for_exit(&mut client.child).expect("the client exits on its own");
    assert_eq!(status.code(), Some(0));
}
