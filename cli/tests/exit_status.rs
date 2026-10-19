//! A reaped child with unavailable status ends only its channel and restores qsh.

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
use transport::channel_server::ChannelSpawner;
use transport::session_manager::{
    BackendFactory, ForgetNothing, LoginEndedReports, LoginId, RandomNonces, ServerAuth,
    SessionManager,
};

const NOTICE: &str = "qsh: the remote process ended, but its exit status is unavailable";
const FINAL_OUTPUT: &[u8] = b"FINAL-STATUS-OUTPUT\r\n";

struct MissingStatusWait;
impl transport::channel_server::ChannelWait for MissingStatusWait {
    fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
        transport::channel_server::ChildStatus::Reaped { code: None }
    }
    fn kill(&mut self) {
        panic!("an exactly reaped fixture child must not be signalled");
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("retirement must preserve unavailable status");
    }
    fn cleanup_uninstalled(
        &mut self,
        authority: &transport::channel_open::CleanupAuthority<'_>,
    ) -> transport::channel_open::CleanupStatus {
        authority.no_child() // This fake backend owns no OS process.
    }
}
struct Resize;
impl transport::shell_server::ResizeHandle for Resize {
    fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
        Ok(())
    }
}

struct MissingStatusSpawner {
    opens: Arc<transport::channel_open::ChannelOpenRegistry>,
    identity: String,
    calls: Arc<AtomicUsize>,
}

impl ChannelSpawner for MissingStatusSpawner {
    fn open_registry(&self) -> Arc<transport::channel_open::ChannelOpenRegistry> {
        self.opens.clone()
    }
    fn spawn(
        &self,
        owner: &Principal,
        _login: LoginId,
        _request: &OpenRequest,
        _term: Option<&str>,
        custody: &transport::channel_open::OpenCustody,
    ) -> Result<transport::channel_open::UninstalledChannel, transport::channel_open::SpawnFailure>
    {
        assert_eq!(owner.uid, 4242);
        assert_eq!(owner.name, "exit-status-test");
        assert_eq!(owner.identity, self.identity);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(custody
            .protect(
                Box::new(MissingStatusWait),
                Box::new(transport::shell_server::NoScreen),
            )
            .finish(
                Box::new(std::io::Cursor::new(FINAL_OUTPUT)),
                Box::new(std::io::sink()),
                Box::new(Resize),
            ))
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
                result.expect("status peer thread panicked");
            }
        }
    }
}

fn start_peer(
    authorized: &Path,
    identity: String,
) -> (Peer, SocketAddr, [u8; 32], Arc<AtomicUsize>) {
    let authorized = authorized.to_owned();
    let calls = Arc::new(AtomicUsize::new(0));
    let spawner = MissingStatusSpawner {
        opens: transport::channel_open::ChannelOpenRegistry::new(Default::default()),
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
                    "exit-status-test".into(),
                ))),
                server_pub: key.public,
                self_principal: Principal {
                    uid: 4242,
                    name: "exit-status-test".into(),
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

#[test]
fn unavailable_remote_status_preserves_final_output_and_restores_the_qsh_pty() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let identity = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
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
    );
    let pins = home.path().join("qsh/known_hosts");
    std::fs::create_dir_all(pins.parent().unwrap()).unwrap();
    sshauth::known_hosts::KnownHosts::open(pins)
        .pin("127.0.0.1", addr.port(), &public)
        .unwrap();
    let address = format!("exit-status-test@127.0.0.1:{}", addr.port());
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
    let notice_start = text
        .find(NOTICE)
        .expect("specific unavailable-status notice");
    assert_eq!(
        text.matches(NOTICE).count(),
        1,
        "one terminal status notice"
    );
    let line = text[notice_start..].split(['\r', '\n']).next().unwrap();
    assert_eq!(line, NOTICE);
    let final_output = text
        .find("FINAL-STATUS-OUTPUT")
        .expect("final process output rendered");
    assert!(
        final_output < notice_start,
        "final output must precede terminal notice"
    );
    let restore = text[..notice_start]
        .rfind("\x1b[?1049l")
        .expect("alternate screen restored before notice");
    assert!(
        final_output < restore,
        "final output rendered before terminal restoration"
    );
    assert!(!text.contains("channel protocol failure"));
}
