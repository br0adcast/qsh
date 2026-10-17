//! The address ladder end to end (spec §4.1): a real `qsh` on a real
//! pseudo-terminal walks several addresses -- qsh directly, then ssh to a
//! private sshd that brings a real `qshd` up, then qsh again on the port the
//! daemon reports.
//!
//! Nothing here can reach the developer's own setup: the client runs with a
//! temporary `HOME`, `XDG_CONFIG_HOME` and `XDG_CACHE_HOME` and without
//! `SSH_AUTH_SOCK` (`support::spawn_qsh`), and every daemon is either a
//! `qshd serve` on its own temp home or the sandbox's, in a home sshd was
//! checked to hand its sessions before anything ran there.
//!
//! Closed ports reject discovery promptly; KeyOnly peers below exercise
//! handshake silence separately from an explicit network refusal.

mod support;

#[path = "../../crates/bringup/tests/support_home/mod.rs"]
mod support_home;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use support::{
    free_udp_port, serialised, spawn_qsh, start_daemon, wait_for_exit, wait_until, Client, UdpRelay,
};
use support_home::{processes_under, ssh_support, Sandbox};

/// Everything the client has written to its terminal, and how far the test
/// has read it: [`Screen::next`] looks only past the last thing it found, so
/// a run of `next` calls checks that the lines came in that order.
struct Screen {
    seen: Arc<Mutex<Vec<u8>>>,
    from: usize,
}

impl Screen {
    fn of(client: &Client) -> Screen {
        let seen = Arc::new(Mutex::new(Vec::new()));
        support::drain_into(
            client.master.try_clone().expect("clone master"),
            seen.clone(),
        );
        Screen { seen, from: 0 }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }

    /// Waits for `needle` after what was found before, and moves past it.
    fn next(&mut self, needle: &str) -> bool {
        let mut at = None;
        let found = wait_until(|| {
            let text = self.text();
            let rest = text.get(self.from..).unwrap_or("");
            at = rest.find(needle).map(|i| self.from + i + needle.len());
            at.is_some()
        });
        if let Some(at) = at {
            self.from = at;
        }
        found
    }

    /// Waits for `needle` anywhere in what was seen.
    fn has(&self, needle: &str) -> bool {
        wait_until(|| self.text().contains(needle))
    }
}

/// A fresh ed25519 key for `qsh -i`, in `dir`: its path and its public line.
fn client_key(dir: &Path) -> (PathBuf, String) {
    let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate");
    let path = dir.join("id_test");
    std::fs::write(
        &path,
        key.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .as_bytes(),
    )
    .expect("write key");
    let public = key.public_key().to_openssh().expect("openssh");
    (path, public)
}

/// A UDP port on 127.0.0.1 nobody listens on, other than `taken`.
fn closed_port(taken: &[u16]) -> u16 {
    loop {
        let p = free_udp_port();
        if !taken.contains(&p) {
            return p;
        }
    }
}

/// Answers the question the screen shows last, the way a person would.
fn answer_yes(client: &mut Client) {
    client.master.write_all(b"yes\n").expect("answer");
}

/// The shell is live and runs what is typed, then leaves with code 0. The
/// marker is split by quotes so the echo of the typed line cannot match it.
fn a_shell_answers_and_exits_cleanly(client: &mut Client, screen: &mut Screen, context: &str) {
    client.type_line("echo IN'PUT'OK");
    assert!(
        screen.next("INPUTOK"),
        "the shell never answered; client saw: {}\n{context}",
        screen.text()
    );
    client.type_line("exit");
    let status = wait_for_exit(&mut client.child);
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(0),
        "a shell that exited is not a failure; client saw: {}\n{context}",
        screen.text()
    );
}

/// What an explicit port refusal reads as.
fn closed_words(port: u16) -> String {
    format!("UDP port {port} refused the connection")
}

/// The line the exit 12 summary ends with, for a client run with `home`.
fn details_line(home: &Path) -> String {
    format!("qsh: details: {}", home.join("qsh").join("log").display())
}

/// The last line the client wrote, without the line break.
fn last_line(screen: &Screen) -> String {
    screen
        .text()
        .lines()
        .rev()
        .map(|l| l.trim_end_matches('\r'))
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}

/// The client exits by itself; its exit code.
fn exit_code(client: &mut Client, screen: &Screen) -> Option<i32> {
    match wait_for_exit(&mut client.child) {
        Some(s) => s.code(),
        None => panic!("the client never gave up; client saw: {}", screen.text()),
    }
}

#[test]
fn the_second_address_is_used_when_the_first_is_silent() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let silent = closed_port(&[daemon.port]);
    let home = tempfile::tempdir().expect("tempdir");
    let first = format!("127.0.0.1:{silent}");
    let second = format!("127.0.0.1:{}", daemon.port);
    let mut client = spawn_qsh(
        &["-i", key_path.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert!(
        screen.next(&format!(
            "qsh: 127.0.0.1:{silent}: {}",
            closed_words(silent)
        )),
        "the silent address must be reported; client saw: {}",
        screen.text()
    );
    assert!(
        screen.next("Key fingerprint"),
        "the second address must be asked about; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
    answer_yes(&mut client);
    a_shell_answers_and_exits_cleanly(
        &mut client,
        &mut screen,
        &format!("daemon: {}", daemon.output_text()),
    );
}

#[test]
fn when_every_address_fails_each_one_is_listed() {
    let _serial = serialised();
    let a = closed_port(&[]);
    let b = closed_port(&[a]);
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let (first, second) = (format!("127.0.0.1:{a}"), format!("127.0.0.1:{b}"));
    let mut client = spawn_qsh(
        &["-i", key.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let screen = Screen::of(&client);

    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    for line in [
        "qsh: could not connect:".to_string(),
        format!("qsh:   127.0.0.1:{a}: {}", closed_words(a)),
        format!("qsh:   127.0.0.1:{b}: {}", closed_words(b)),
    ] {
        assert!(
            screen.has(&line),
            "missing {line:?}; client saw: {}",
            screen.text()
        );
    }
    assert_eq!(last_line(&screen), details_line(home.path()));
}

/// Spec §4.1, §4.3: a send the OS refuses is said in the OS's words, on the
/// step's own line and in the exit 12 summary -- not as "no answer". A
/// broadcast address without `SO_BROADCAST` is refused on Linux (`EACCES`),
/// at once: here by the key request, the first thing sent.
#[cfg(target_os = "linux")]
#[test]
fn a_send_the_os_refuses_is_said_in_its_words() {
    let _serial = serialised();
    let a = closed_port(&[]);
    let b = closed_port(&[a]);
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let (first, second) = (
        format!("255.255.255.255:{a}"),
        format!("255.255.255.255:{b}"),
    );
    let mut client = spawn_qsh(
        &["-i", key.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    let refused =
        |p: u16| format!("cannot send to 255.255.255.255:{p}: Permission denied (os error 13)");
    assert!(
        screen.next(&format!("qsh: 255.255.255.255:{a}: {}", refused(a))),
        "the step's own line; client saw: {}",
        screen.text()
    );
    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    for line in [
        "qsh: could not connect:".to_string(),
        format!("qsh:   255.255.255.255:{a}: {}", refused(a)),
        format!("qsh:   255.255.255.255:{b}: {}", refused(b)),
    ] {
        assert!(
            screen.next(&line),
            "missing {line:?}; client saw: {}",
            screen.text()
        );
    }
    assert_eq!(last_line(&screen), details_line(home.path()));
    assert!(
        !screen.text().contains("no answer"),
        "a refused send is not silence; client saw: {}",
        screen.text()
    );
}

/// Review focus: the transport's own send error reaches the screen. With
/// the server key already pinned there is no key request: the handshake is
/// the first thing sent, every retransmit is refused, and the attempt's
/// "unreachable" carries the OS's words up to the line and the summary.
#[cfg(target_os = "linux")]
#[test]
fn the_transport_s_send_error_reaches_the_summary() {
    let _serial = serialised();
    let a = closed_port(&[]);
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    std::fs::create_dir_all(home.path().join("qsh")).expect("mkdir qsh");
    sshauth::known_hosts::KnownHosts::open(home.path().join("qsh").join("known_hosts"))
        .pin("255.255.255.255", a, &[7u8; 32])
        .expect("pin");
    let address = format!("255.255.255.255:{a}");
    // `--verbose` for the log, which is where the once-only report goes.
    let mut client = spawn_qsh(
        &["--verbose", "-i", key.to_str().expect("utf-8"), &address],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    let line = format!(
        "qsh:   255.255.255.255:{a}: cannot send to 255.255.255.255:{a}: \
         Permission denied (os error 13)"
    );
    assert!(
        screen.next("qsh: could not connect:") && screen.next(&line),
        "missing {line:?}; client saw: {}",
        screen.text()
    );
    assert_eq!(last_line(&screen), details_line(home.path()));
    let log = std::fs::read_to_string(home.path().join("qsh").join("log")).unwrap_or_default();
    assert_eq!(
        log.matches(&format!(
            "] WARN  qsh: a send to 255.255.255.255:{a} failed: Permission denied (os error 13)\n"
        ))
        .count(),
        1,
        "the log gets a failing send once, at warn, not once per retransmit (20 of them): {log}"
    );
    assert!(
        !log.contains("qsh: qsh:"),
        "one prefix per line, the component's: {log}"
    );
}

/// A stand-in that answers the key request and nothing else: a daemon that
/// is there, and does not take the login.
struct KeyOnly {
    port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl KeyOnly {
    fn start() -> KeyOnly {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stopping.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok((n, src)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if let Ok(transport::wire::Frame::Handshake {
                    kind: transport::wire::Kind::KeyRequest,
                    ..
                }) = transport::wire::parse(&buf[..n])
                {
                    let offer = transport::wire::encode_handshake(
                        transport::wire::Kind::KeyOffer,
                        &transport::wire::encode_key_offer_body(&[21u8; 32]),
                    );
                    let _ = socket.send_to(&offer, src);
                }
            }
        });
        KeyOnly {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for KeyOnly {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Spec §4.1: the key came, the handshake stayed silent -- the daemon is
/// there, so the line must not say it is not running.
#[test]
fn a_daemon_that_gives_its_key_but_not_the_login_is_said_so() {
    let _serial = serialised();
    let stand_in = KeyOnly::start();
    let p = stand_in.port;
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let address = format!("127.0.0.1:{p}");
    let mut client = spawn_qsh(&["-i", key.to_str().expect("utf-8"), &address], home.path());
    let mut screen = Screen::of(&client);

    assert!(
        screen.next("Key fingerprint"),
        "the key offered is asked about; client saw: {}",
        screen.text()
    );
    answer_yes(&mut client);
    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    let line = format!(
        "qsh:   127.0.0.1:{p}: qshd answered the key request but not the login -- a different \
         qsh version, or the daemon is overloaded; its log says more"
    );
    assert!(
        screen.next("qsh: could not connect:") && screen.next(&line),
        "missing {line:?}; client saw: {}",
        screen.text()
    );
    assert_eq!(last_line(&screen), details_line(home.path()));
}

#[test]
fn a_name_that_does_not_resolve_is_one_failed_address() {
    let _serial = serialised();
    let silent = closed_port(&[]);
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let second = format!("127.0.0.1:{silent}");
    let mut client = spawn_qsh(
        &[
            "-i",
            key.to_str().expect("utf-8"),
            "no-such-host.invalid",
            &second,
        ],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert!(
        screen.next("qsh: no-such-host.invalid: could not resolve"),
        "the name must be reported as unresolvable; client saw: {}",
        screen.text()
    );
    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    for line in [
        "qsh: could not connect:".to_string(),
        "qsh:   no-such-host.invalid:60022: could not resolve: ".to_string(),
        format!("qsh:   127.0.0.1:{silent}: {}", closed_words(silent)),
    ] {
        assert!(
            screen.has(&line),
            "missing {line:?}; client saw: {}",
            screen.text()
        );
    }
    assert!(!screen.text().contains("panicked"), "{}", screen.text());
}

#[test]
fn ssh_brings_qshd_up_and_qsh_logs_in_with_the_process_key() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _serial = serialised();
    let home = tempfile::tempdir().expect("tempdir");
    let (key, public) = client_key(home.path());
    let sb = Sandbox::start_with(&[public]);
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let sandbox_home = sb.home.path().to_path_buf();
    let q = free_udp_port();
    let sshd = sb.sshd.port;
    let address = format!("127.0.0.1:{q},ssh={sshd}");
    let mut client = spawn_qsh(&["-i", key.to_str().expect("utf-8"), &address], home.path());
    let mut screen = Screen::of(&client);
    let sshd_log = || sb.sshd.log();

    for line in [
        format!("qsh: 127.0.0.1:{q}: {}", closed_words(q)),
        format!("qsh: 127.0.0.1: trying ssh:{sshd}"),
        format!("The authenticity of host '[127.0.0.1]:{sshd}'"),
    ] {
        assert!(
            screen.next(&line),
            "missing {line:?}; client saw: {}",
            screen.text()
        );
    }
    answer_yes(&mut client);
    assert!(
        screen.next(&format!("qsh: 127.0.0.1: qshd started, port {q}")),
        "qshd must come up on the port asked for; client saw: {}\nsshd: {}",
        screen.text(),
        sshd_log()
    );
    assert!(
        screen.next(&format!("First time seeing server 127.0.0.1:{q}"))
            && screen.next("Key fingerprint"),
        "the qsh server key must be asked about; client saw: {}",
        screen.text()
    );
    answer_yes(&mut client);
    a_shell_answers_and_exits_cleanly(&mut client, &mut screen, "");

    assert!(
        !screen.text().contains("Install qshd"),
        "an existing daemon requires no installation approval: {}",
        screen.text()
    );
    assert!(!screen.text().contains("daemon installation was declined"));
    let known = std::fs::read_to_string(home.path().join(".ssh/known_hosts")).unwrap_or_default();
    assert!(
        known
            .lines()
            .any(|l| l.starts_with(&format!("[127.0.0.1]:{sshd} "))),
        "the accepted ssh host key must be remembered: {known:?}"
    );
    assert!(
        sb.cache().join("control.sock").exists(),
        "the daemon runs in the sandbox's private cache"
    );
    drop(client);
    drop(sb);
    assert_eq!(
        processes_under(&sandbox_home),
        Vec::<String>::new(),
        "the sandbox's guard must have stopped its daemon"
    );
}

#[test]
fn a_daemon_on_another_port_is_reached_on_its_own_port() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _serial = serialised();
    let home = tempfile::tempdir().expect("tempdir");
    let (key, public) = client_key(home.path());
    let mut sb = Sandbox::start_with(&[public]);
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let a = free_udp_port();
    let ready = bringup::bring_up(
        sb.request(a),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .expect("the daemon comes up on A");
    assert_eq!(ready.ports, vec![a]);
    let b = closed_port(&[a]);
    let sshd = sb.sshd.port;

    // The sandbox's host key is already known, so nothing is asked about it.
    let host_key = sb.sshd.host_public_key_line();
    let mut fields = host_key.split_whitespace();
    let (kind, blob) = (fields.next().expect("type"), fields.next().expect("key"));
    std::fs::create_dir_all(home.path().join(".ssh")).expect("mkdir .ssh");
    std::fs::write(
        home.path().join(".ssh/known_hosts"),
        format!("[127.0.0.1]:{sshd} {kind} {blob}\n"),
    )
    .expect("write known_hosts");

    let address = format!("127.0.0.1:{b},ssh={sshd}");
    let mut client = spawn_qsh(&["-i", key.to_str().expect("utf-8"), &address], home.path());
    let mut screen = Screen::of(&client);

    for line in [
        format!("qsh: 127.0.0.1:{b}: {}", closed_words(b)),
        format!("qsh: 127.0.0.1: trying ssh:{sshd}"),
        format!("qsh: 127.0.0.1: qshd listens on {a}, not {b}"),
        format!("First time seeing server 127.0.0.1:{a}"),
        "Key fingerprint".to_string(),
    ] {
        assert!(
            screen.next(&line),
            "missing {line:?}; client saw: {}\nsshd: {}",
            screen.text(),
            sb.sshd.log()
        );
    }
    answer_yes(&mut client);
    a_shell_answers_and_exits_cleanly(&mut client, &mut screen, "");
    assert!(
        !screen.text().contains("The authenticity of host"),
        "a known ssh host key is not asked about; client saw: {}",
        screen.text()
    );
}

/// Recovery starts through a relay, then loses it permanently. SSH reports
/// the daemon's real port and installs the process key. UDP must consume
/// both facts without asking a new trust question or replacing the shell.
#[test]
fn ssh_recovery_hands_a_new_port_to_udp_and_keeps_the_shell() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let (key, public) = client_key(home.path());
    let mut sb = Sandbox::start_with(std::slice::from_ref(&public));
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    std::fs::create_dir_all(sb.home.path().join(".ssh")).unwrap();
    std::fs::write(sb.home.path().join(".ssh/authorized_keys"), &public).unwrap();
    let port = free_udp_port();
    bringup::bring_up(
        sb.request(port),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .unwrap();
    let relay = UdpRelay::start(port);
    let sshd = sb.sshd.port;
    std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
    std::fs::write(
        home.path().join(".ssh/known_hosts"),
        format!("[127.0.0.1]:{sshd} {}\n", sb.sshd.host_public_key_line()),
    )
    .unwrap();
    let address = format!("127.0.0.1:{},ssh={sshd}", relay.port);
    let mut client = spawn_qsh(&["-i", key.to_str().unwrap(), &address], home.path());
    let mut screen = Screen::of(&client);
    assert!(screen.next("Key fingerprint"), "{}", screen.text());
    answer_yes(&mut client);
    client.type_line("export PORT_MARK=kept");
    client.type_line("echo PORT'READY'");
    assert!(screen.next("PORTREADY"), "{}", screen.text());
    relay.cut();
    client.master.write_all(b"\x1dr").unwrap();
    let log_text = || std::fs::read_to_string(home.path().join("qsh/log")).unwrap_or_default();
    assert!(
        wait_until(|| log_text().contains(&format!("reconnected at address 0, qsh port {port}"))),
        "SSH must hand its new port and authorization to UDP: {}",
        log_text()
    );
    client.type_line("echo PORT$PORT_MARK");
    assert!(
        screen.next("PORTkept"),
        "the original shell must return: {}",
        screen.text()
    );
    assert_eq!(screen.text().matches("Key fingerprint").count(), 1);
    a_shell_answers_and_exits_cleanly(&mut client, &mut screen, "after SSH recovery");
}

/// Spec §11: qsh answers but takes none of the keys offered, so the ladder
/// goes to ssh, which logs in with another key and hands the running daemon
/// this process's key; qsh then logs in with that. The daemon is the
/// sandbox's own, brought up first so that step 1 has someone to refuse it.
#[test]
fn a_refusal_over_qsh_goes_to_ssh_and_the_process_key_logs_in() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _serial = serialised();
    let home = tempfile::tempdir().expect("tempdir");
    // K1, for `-i`: authorized nowhere.
    let (refused, _) = client_key(home.path());
    // K2, the default key of the client's home: sshd takes it.
    let ssh_dir = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).expect("mkdir .ssh");
    let (k2, k2_public) = client_key(&ssh_dir);
    std::fs::rename(&k2, ssh_dir.join("id_ed25519")).expect("name it id_ed25519");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            ssh_dir.join("id_ed25519"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
    }
    let mut sb = Sandbox::start_with(&[k2_public]);
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let sandbox_home = sb.home.path().to_path_buf();
    let q = free_udp_port();
    let ready = bringup::bring_up(
        sb.request(q),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .expect("the daemon comes up on Q");
    assert_eq!(ready.ports, vec![q]);
    let sshd = sb.sshd.port;

    let address = format!("127.0.0.1:{q},ssh={sshd}");
    let mut client = spawn_qsh(
        &["-i", refused.to_str().expect("utf-8"), &address],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert!(
        screen.next(&format!("First time seeing server 127.0.0.1:{q}"))
            && screen.next("Key fingerprint"),
        "the daemon answers qsh at step 1; client saw: {}",
        screen.text()
    );
    answer_yes(&mut client);
    for line in [
        format!("qsh: 127.0.0.1:{q}: no key was accepted over qsh for account "),
        format!("(offered: {} (SHA256:", refused.display()),
        "-- the server's authorized_keys, or in system mode the account or PAM; \
         qshd's log names the reason"
            .to_string(),
        format!("qsh: 127.0.0.1: trying ssh:{sshd}"),
        format!("The authenticity of host '[127.0.0.1]:{sshd}'"),
    ] {
        assert!(
            screen.next(&line),
            "missing {line:?}; client saw: {}",
            screen.text()
        );
    }
    answer_yes(&mut client);
    assert!(
        screen.next(&format!("qsh: 127.0.0.1: qshd started, port {q}")),
        "ssh must hand the running daemon the process key; client saw: {}\nsshd: {}",
        screen.text(),
        sb.sshd.log()
    );
    client.type_line("export WARM_MARK=retained");
    client.type_line("echo WARM'READY'");
    assert!(screen.next("WARMREADY"));
    client.master.write_all(b"\x1dr").unwrap();
    let log_text = || std::fs::read_to_string(home.path().join("qsh/log")).unwrap_or_default();
    assert!(
        wait_until(|| log_text().contains("reconnected at address 0")),
        "the process key must recover without repeating SSH: {}",
        log_text()
    );
    client.type_line("echo WARM$WARM_MARK");
    assert!(
        screen.next("WARMretained"),
        "the same shell must survive: {}",
        screen.text()
    );
    assert_eq!(
        log_text().matches("trying ssh:").count(),
        1,
        "the remembered process key must avoid a second SSH login"
    );
    a_shell_answers_and_exits_cleanly(&mut client, &mut screen, "");
    assert_eq!(
        screen.text().matches("Key fingerprint").count(),
        1,
        "the key accepted at step 1 is pinned: step 3 asks nothing; client saw: {}",
        screen.text()
    );

    drop(client);
    drop(sb);
    assert_eq!(
        processes_under(&sandbox_home),
        Vec::<String>::new(),
        "the sandbox's guard must have stopped its daemon"
    );
}

/// A command-line mistake ends the run before any connection attempt, on
/// the same private controlling PTY as every other CLI process in this suite.
#[test]
fn a_grammar_mistake_exits_2() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_qsh(&["h,knock=tcp:1"], home.path());
    let mut screen = Screen::of(&client);
    assert_eq!(
        exit_code(&mut client, &screen),
        Some(2),
        "{}",
        screen.text()
    );
    assert!(
        screen.next("address 1 (h): knock is only used before ssh"),
        "{}",
        screen.text()
    );
}

/// The client's own pin store, under the test's `home`.
fn pins(home: &Path) -> sshauth::known_hosts::KnownHosts {
    sshauth::known_hosts::KnownHosts::open(home.join("qsh").join("known_hosts"))
}

/// The key `qshd` on `port` offers, asked the way the client asks.
fn daemon_key(port: u16) -> [u8; 32] {
    sshauth::discover::discover(
        format!("127.0.0.1:{port}").parse().expect("addr"),
        std::time::Duration::from_secs(5),
    )
    .expect("the daemon offers its key")
}

/// Spec §4a rule 1: two addresses of one command line with different keys
/// pinned are not one server. Said before anything is tried -- neither
/// address has a daemon, and no line says so -- and the run ends with 11.
#[test]
fn different_keys_pinned_on_one_command_line_end_the_run_before_any_attempt() {
    let _serial = serialised();
    let a = closed_port(&[]);
    let b = closed_port(&[a]);
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let store = pins(home.path());
    store.pin("127.0.0.1", a, &[1u8; 32]).expect("pin a");
    store.pin("127.0.0.1", b, &[2u8; 32]).expect("pin b");
    let (first, second) = (format!("127.0.0.1:{a}"), format!("127.0.0.1:{b}"));
    let started = std::time::Instant::now();
    let mut client = spawn_qsh(
        &["-i", key.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert_eq!(
        exit_code(&mut client, &screen),
        Some(11),
        "{}",
        screen.text()
    );
    let line = format!(
        "qsh: {first} and {second} are on one command line but have different server keys \
         pinned -- they are not one server; remove the stale line for one of them from {}",
        home.path().join("qsh").join("known_hosts").display()
    );
    assert!(
        screen.next(&line),
        "missing {line:?}; client saw: {}",
        screen.text()
    );
    let prints = format!(
        "  {first} is pinned to {}; {second} is pinned to {}",
        sshauth::known_hosts::key_fingerprint(&[1u8; 32]),
        sshauth::known_hosts::key_fingerprint(&[2u8; 32])
    );
    assert!(
        screen.next(&prints),
        "missing {prints:?}; client saw: {}",
        screen.text()
    );
    assert!(
        !screen.text().contains("no answer"),
        "nothing is tried; client saw: {}",
        screen.text()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "a handshake with either key takes 10 s; this took {:?}",
        started.elapsed()
    );
}

/// Spec §4a rule 2: an address with no key pinned, next to one whose key
/// is pinned, logs in with that key -- no key request, no question -- says
/// it is the same server, and the key is pinned for it too. The unpinned
/// address is a relay in front of the one daemon, so it comes first and is
/// the one logged in at.
#[test]
fn an_unpinned_address_next_to_a_pinned_one_is_the_same_server_without_a_question() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let home = tempfile::tempdir().expect("tempdir");
    let server = daemon_key(daemon.port);
    let store = pins(home.path());
    store.pin("127.0.0.1", daemon.port, &server).expect("pin");
    let (first, second) = (
        format!("127.0.0.1:{}", relay.port),
        format!("127.0.0.1:{}", daemon.port),
    );
    let mut client = spawn_qsh(
        &["-i", key_path.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    let line = format!("qsh: {first}: the same server as {second} -- key remembered");
    assert!(
        screen.next(&line),
        "missing {line:?}; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
    a_shell_answers_and_exits_cleanly(
        &mut client,
        &mut screen,
        &format!("daemon: {}", daemon.output_text()),
    );
    assert!(
        !screen.text().contains("Key fingerprint"),
        "nobody is asked; client saw: {}",
        screen.text()
    );
    assert_eq!(
        store
            .check("127.0.0.1", relay.port, &server)
            .expect("check"),
        sshauth::known_hosts::HostVerdict::Known,
        "the key is pinned for the address it was proven at"
    );
}

/// Spec §4a rule 3: the handshake with the neighbour's key gets nothing at
/// an address whose daemon has another key, and the key request there says
/// so: not the same server, exit 11, both fingerprints, and nothing pinned.
#[test]
fn an_address_with_another_server_key_than_its_neighbour_ends_the_run() {
    let _serial = serialised();
    let (pinned, key_path) = start_daemon();
    let (other, _) = start_daemon();
    let home = tempfile::tempdir().expect("tempdir");
    let pinned_key = daemon_key(pinned.port);
    let other_key = daemon_key(other.port);
    assert_ne!(pinned_key, other_key, "two daemons, two host keys");
    let store = pins(home.path());
    store
        .pin("127.0.0.1", pinned.port, &pinned_key)
        .expect("pin");
    let (first, second) = (
        format!("127.0.0.1:{}", other.port),
        format!("127.0.0.1:{}", pinned.port),
    );
    let mut client = spawn_qsh(
        &["-i", key_path.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert_eq!(
        exit_code(&mut client, &screen),
        Some(11),
        "{}",
        screen.text()
    );
    let line = format!(
        "qsh: {first} answers with a different server key than {second} -- not the same \
         server; check the addresses on the command line"
    );
    assert!(
        screen.next(&line),
        "missing {line:?}; client saw: {}",
        screen.text()
    );
    let prints = format!(
        "  {second} is pinned to {}; {first} offers {}",
        sshauth::known_hosts::key_fingerprint(&pinned_key),
        sshauth::known_hosts::key_fingerprint(&other_key)
    );
    assert!(
        screen.next(&prints),
        "missing {prints:?}; client saw: {}",
        screen.text()
    );
    assert!(
        !screen.text().contains("Key fingerprint"),
        "a key that is not the neighbour's is not put to a vote; client saw: {}",
        screen.text()
    );
    assert_eq!(
        store
            .check("127.0.0.1", other.port, &other_key)
            .expect("check"),
        sshauth::known_hosts::HostVerdict::Unknown,
        "nothing is pinned for the other server"
    );
}

/// Spec §4a rule 3, the other answer: the key request at the silent
/// address offers the neighbour's very key, so the silence has another
/// cause -- the ordinary "answered the key request but not the login",
/// and nothing pinned on that offer alone. The neighbour is a name that
/// does not resolve: its pin is all it contributes, and it fails at once.
#[test]
fn the_neighbour_s_key_offered_back_is_the_ordinary_silence() {
    let _serial = serialised();
    let stand_in = KeyOnly::start();
    let k = stand_in.port;
    let home = tempfile::tempdir().expect("tempdir");
    let (key, _) = client_key(home.path());
    let store = pins(home.path());
    store
        .pin("no-such-host.invalid", 60022, &[21u8; 32])
        .expect("pin");
    let (first, second) = (
        format!("127.0.0.1:{k}"),
        "no-such-host.invalid:60022".to_string(),
    );
    let mut client = spawn_qsh(
        &["-i", key.to_str().expect("utf-8"), &first, &second],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert_eq!(
        exit_code(&mut client, &screen),
        Some(12),
        "{}",
        screen.text()
    );
    let line = format!(
        "qsh:   {first}: qshd answered the key request but not the login -- a different \
         qsh version, or the daemon is overloaded; its log says more"
    );
    assert!(
        screen.next("qsh: could not connect:") && screen.next(&line),
        "missing {line:?}; client saw: {}",
        screen.text()
    );
    assert!(
        !screen.text().contains("Key fingerprint"),
        "nobody is asked; client saw: {}",
        screen.text()
    );
    assert_eq!(
        store.check("127.0.0.1", k, &[21u8; 32]).expect("check"),
        sshauth::known_hosts::HostVerdict::Unknown,
        "a key request proves nothing: nothing is pinned on it"
    );
}

/// Spec §4a rule 4: a road the live session's own checks were answered on
/// is pinned for the session's key, silently, with a line in the log. The
/// spare is a relay in front of the one daemon; its first check comes on
/// the transport's own schedule, so this waits up to 45 s.
#[test]
fn a_road_that_carried_the_session_is_pinned() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let home = tempfile::tempdir().expect("tempdir");
    let (first, spare) = (
        format!("127.0.0.1:{}", daemon.port),
        format!("127.0.0.1:{}", relay.port),
    );
    let mut client = spawn_qsh(
        &["-i", key_path.to_str().expect("utf-8"), &first, &spare],
        home.path(),
    );
    let mut screen = Screen::of(&client);

    assert!(
        screen.next("Key fingerprint"),
        "first contact is asked about; client saw: {}",
        screen.text()
    );
    answer_yes(&mut client);
    let server = daemon_key(daemon.port);
    let store = pins(home.path());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let mut verdict = sshauth::known_hosts::HostVerdict::Unknown;
    while std::time::Instant::now() < deadline {
        verdict = store
            .check("127.0.0.1", relay.port, &server)
            .expect("check");
        if verdict == sshauth::known_hosts::HostVerdict::Known {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert_eq!(
        verdict,
        sshauth::known_hosts::HostVerdict::Known,
        "the spare must be pinned once it has carried the session; client saw: {}",
        screen.text()
    );
    a_shell_answers_and_exits_cleanly(&mut client, &mut screen, "");
    let log = std::fs::read_to_string(home.path().join("qsh").join("log")).unwrap_or_default();
    assert!(
        log.contains(&format!(
            "road {spare} carried the session: its server key is remembered"
        )),
        "the log says so: {log}"
    );
    assert!(
        !screen.text().contains(&format!("{spare}: the same server")),
        "rule 4 is silent on the screen; client saw: {}",
        screen.text()
    );
}
