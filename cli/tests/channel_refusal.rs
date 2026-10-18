//! Authenticated peer refusals are diagnostics, never terminal instructions.

mod support;

use std::io::Read;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use transport::auth::Principal;
use transport::channel::OpenRequest;
use transport::channel_server::{ChannelSpawner, SpawnedChannel};
use transport::session_manager::{
    BackendFactory, ForgetNothing, LoginEndedReports, LoginId, RandomNonces, ServerAuth,
    SessionManager,
};

const PREFIX: &str = "qsh: server refused the shell channel: ";
// Deliberately hostile test data, sent only to the test-owned qsh PTY.
const HOSTILE: &str = "access denied — résumé 中文 | \x1b]0;QSH_REFUSAL_TITLE\x07 | \x1b]52;c;UVNIX1JFRlVTQUw=\x1b\\ | \x1b[2J\x1b[3;4HQSH_REFUSAL_CURSOR | \u{9d}0;QSH_REFUSAL_C1\u{9c}\u{9b}2J | \0\x08\x7f | one\nforged\rline\tend";
const SAFE: &str = "access denied — résumé 中文 | ?]0;QSH_REFUSAL_TITLE? | ?]52;c;UVNIX1JFRlVTQUw=?\\ | ?[2J?[3;4HQSH_REFUSAL_CURSOR | ?0;QSH_REFUSAL_C1??2J | ??? | one forged line end";

struct RefusingSpawner {
    reason: String,
    identity: String,
    calls: Arc<AtomicUsize>,
}

impl ChannelSpawner for RefusingSpawner {
    fn spawn(
        &self,
        owner: &Principal,
        _login: LoginId,
        _request: &OpenRequest,
        _term: Option<&str>,
    ) -> Result<SpawnedChannel, String> {
        assert_eq!(owner.uid, 4242);
        assert_eq!(owner.name, "refusal-test");
        assert_eq!(owner.identity, self.identity);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.reason.clone())
    }
}

struct Peer {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.expect("refusing peer thread panicked");
            }
        }
    }
}

fn start_peer(
    authorized: &Path,
    identity: String,
    reason: &str,
) -> (Peer, SocketAddr, [u8; 32], Arc<AtomicUsize>) {
    let authorized = authorized.to_owned();
    let reason = reason.to_owned();
    let calls = Arc::new(AtomicUsize::new(0));
    let spawner = RefusingSpawner {
        reason,
        identity,
        calls: calls.clone(),
    };
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let key = transport::handshake::generate_keypair();
            let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let auth = ServerAuth {
                allowlist: Arc::new(Mutex::new(Vec::new())),
                verifier: Some(Arc::new(sshauth::verify::AuthorizedKeysVerifier::new(
                    authorized,
                    4242,
                    "refusal-test".into(),
                ))),
                server_pub: key.public,
                self_principal: Principal {
                    uid: 4242,
                    name: "refusal-test".into(),
                    identity: "unused allowlist identity".into(),
                    incarnation: 0,
                },
                nonces: Arc::new(RandomNonces),
                logins: Arc::new(ForgetNothing),
            };
            let backend =
                qshd::channel_backend::ChannelSessionBackend::with_spawner(Arc::new(spawner));
            ready_tx
                .send((socket.local_addr().unwrap(), key.public))
                .unwrap();
            tokio::select! {
                _ = SessionManager::serve(
                    socket, key.private, auth, BackendFactory(Arc::new(backend)),
                    Arc::new(AtomicUsize::new(0)), LoginEndedReports::none(),
                ) => panic!("session manager stopped unexpectedly"),
                _ = stop_rx => {}
            }
        });
        runtime.shutdown_timeout(Duration::from_secs(2));
    });
    // Establish ownership before a readiness assertion can unwind.
    let peer = Peer {
        stop: Some(stop_tx),
        thread: Some(thread),
    };
    let (addr, public) = ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("peer readiness");
    (peer, addr, public, calls)
}

fn drain_available(reader: &mut std::fs::File, output: &mut Vec<u8>) {
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                output.extend_from_slice(&chunk[..n]);
                assert!(output.len() <= 128 * 1024, "unexpectedly large PTY output");
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("reading owned PTY: {error}"),
        }
    }
}

fn check_refusal(reason: &str, expected_reason: &str) {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let identity =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let key_path = home.path().join("identity");
    std::fs::write(
        &key_path,
        identity
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let authorized = home.path().join("authorized_keys");
    std::fs::write(&authorized, identity.public_key().to_openssh().unwrap()).unwrap();
    let (_peer, addr, public, calls) = start_peer(
        &authorized,
        sshauth::verify::fingerprint(identity.public_key()),
        reason,
    );
    let pins = home.path().join("qsh/known_hosts");
    std::fs::create_dir_all(pins.parent().unwrap()).unwrap();
    sshauth::known_hosts::KnownHosts::open(pins)
        .pin("127.0.0.1", addr.port(), &public)
        .unwrap();
    let address = format!("refusal-test@127.0.0.1:{}", addr.port());
    let (mut client, slave) =
        support::spawn_qsh_on(&["-i", key_path.to_str().unwrap(), &address], home.path());
    // Drain synchronously while waiting, so the retained slave cannot leave an
    // EOF-blocked collector thread behind. Only this owned master is changed.
    // SAFETY: fcntl accesses a live owned descriptor and changes only its flags.
    unsafe {
        let flags = libc::fcntl(client.master.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(
                client.master.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK
            ),
            0
        );
    }
    let mut output = Vec::new();
    let mut status = None;
    let exited = support::wait_until(|| {
        drain_available(&mut client.master, &mut output);
        status = client.child.try_wait().expect("wait for owned qsh");
        status.is_some()
    });
    assert!(
        exited,
        "qsh did not exit; escaped output: {:?}",
        String::from_utf8_lossy(&output)
            .chars()
            .take(2000)
            .collect::<String>()
    );
    drain_available(&mut client.master, &mut output);
    assert_eq!(status.unwrap().code(), Some(1));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the authenticated shell-open callback must run once"
    );
    let flags = nix::sys::termios::tcgetattr(&slave).unwrap().local_flags;
    assert!(
        flags.contains(nix::sys::termios::LocalFlags::ECHO | nix::sys::termios::LocalFlags::ICANON),
        "qsh must restore echo and canonical input"
    );

    let text = String::from_utf8(output).expect("UTF-8 PTY output");
    let notice_start = text.find(PREFIX).expect("refusal notice is present");
    assert_eq!(
        text.matches(PREFIX).count(),
        1,
        "notice must appear exactly once"
    );
    let notice = text[notice_start..].split(['\r', '\n']).next().unwrap();
    let expected = format!("{PREFIX}{expected_reason}");
    assert_eq!(
        notice, expected,
        "the refusal must be printable and remain one line"
    );
    assert!(!notice.chars().any(char::is_control));
    assert!(
        text[..notice_start].contains("\x1b[?1049l"),
        "restore alternate screen before the notice"
    );
    if reason == HOSTILE {
        assert!(!text.contains(HOSTILE));
        for sequence in [
            "\x1b]0;QSH_REFUSAL_TITLE",
            "\x1b]52;c;UVNIX1JFRlVTQUw=",
            "\x1b[3;4HQSH_REFUSAL_CURSOR",
            "\u{9d}0;QSH_REFUSAL_C1",
        ] {
            assert!(
                !text.contains(sequence),
                "peer control sequence reached PTY: {sequence:?}"
            );
        }
    }
}

#[test]
fn authenticated_channel_refusal_cannot_control_the_terminal() {
    check_refusal(HOSTILE, SAFE);
}

#[test]
fn readable_channel_refusal_keeps_its_text_and_exit_status() {
    check_refusal("access denied — résumé 中文", "access denied — résumé 中文");
}
