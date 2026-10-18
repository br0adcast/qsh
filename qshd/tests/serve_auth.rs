//! The two halves meeting over the real transport: a client signing with a
//! key file, a server checking it against `authorized_keys`, and the session
//! layer's gate in between. Everything below the CLI, without the CLI.
//!
//! Signature authentication is the `serve` path's, and `sshauth` comes into
//! the daemon with it.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qshd::RandomNonces;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;
use sshauth::verify::AuthorizedKeysVerifier;
use transport::auth::Principal;
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::session_manager::{
    BackendFactory, LoginEndedReports, ServerAuth, SessionBackend, SessionInbound, SessionIo,
    SessionManager,
};
use transport::{LinkState, Stats};

/// Echoes stream 0 back and counts how many sessions were ever granted.
struct EchoBackend {
    granted: Arc<AtomicUsize>,
}

impl SessionBackend for EchoBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.granted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            while let Some(ev) = io.recv().await {
                if let SessionInbound::Data(data) = ev {
                    if data.stream_id == 0 {
                        io.send(0, data.data);
                    }
                }
            }
        })
    }
}

#[derive(Default)]
struct Collected {
    stream0: Vec<u8>,
    closed: bool,
    /// Whether this connection's own Noise handshake ever reached `Live`.
    /// The client sets this locally, purely from completing the handshake --
    /// `AuthPolicy::SshSignature` admits any static key at that layer -- so it
    /// fires the same for a listed key and a stranger. Used to prove that a
    /// stranger's rejection happens AFTER the handshake, i.e. because its
    /// signature was checked and refused, not because the socket never bound
    /// or a config mismatch kept the handshake from completing at all.
    live: bool,
}

#[derive(Default)]
struct Events(Mutex<Collected>);

impl ClientEvents for Events {
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == 0 {
            self.0.lock().expect("collected").stream0.extend(data);
        }
    }
    fn on_state(&self, state: LinkState) {
        let mut c = self.0.lock().expect("collected");
        match state {
            LinkState::Closed => c.closed = true,
            LinkState::Live => c.live = true,
            _ => {}
        }
    }
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

fn write_key(dir: &std::path::Path, name: &str) -> (PrivateKey, std::path::PathBuf) {
    let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
    let path = dir.join(name);
    std::fs::write(
        &path,
        key.to_openssh(LineEnding::LF).expect("encode").as_bytes(),
    )
    .expect("write key");
    (key, path)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listed_key_gets_a_session_and_a_stranger_does_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (listed, listed_path) = write_key(dir.path(), "listed");
    let (_stranger, stranger_path) = write_key(dir.path(), "stranger");

    let authorized = dir.path().join("authorized_keys");
    let mut f = std::fs::File::create(&authorized).expect("create");
    writeln!(f, "{}", listed.public_key().to_openssh().expect("openssh")).expect("write");
    f.flush().expect("flush");

    // The server: signature policy, a real authorized_keys verifier.
    let server_kp = generate_keypair();
    let socket = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind"),
    );
    let addr = socket.local_addr().expect("addr");
    let granted = Arc::new(AtomicUsize::new(0));
    let auth = ServerAuth {
        allowlist: Arc::new(Mutex::new(Vec::new())),
        verifier: Some(Arc::new(AuthorizedKeysVerifier::new(
            authorized.clone(),
            1000,
            "test".to_string(),
        ))),
        server_pub: server_kp.public,
        // Not exercised here: every client in this test signs in via
        // `AuthPolicy::SshSignature`, never the allowlist.
        self_principal: Principal {
            uid: 1000,
            name: "test".to_string(),
            identity: "allowlist".to_string(),
            incarnation: 0,
        },
        nonces: Arc::new(RandomNonces),
        logins: Arc::new(qshd::ForgetNothing),
    };
    let backend = Arc::new(EchoBackend {
        granted: granted.clone(),
    });
    tokio::spawn(SessionManager::serve(
        socket,
        server_kp.private,
        auth,
        BackendFactory(backend),
        Arc::new(AtomicUsize::new(0)),
        LoginEndedReports::none(),
    ));

    // The listed key gets a session.
    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        },
        [1u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(
            FileSigner::load(&listed_path, None)
                .expect("load the listed key")
                .with_login("listed".to_string()),
        )),
    );
    client.send_bytes(0, b"hello".to_vec());
    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if events.0.lock().expect("collected").stream0 == b"hello" {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(echoed.is_ok(), "a listed key must get its session");
    assert_eq!(
        granted.load(Ordering::SeqCst),
        1,
        "the listed key's session must be the only one granted so far"
    );
    client.close();

    // The stranger's key proves nothing: no session, no backend.
    let stranger_events = Arc::new(Events::default());
    let stranger_client = StdClient::connect(
        addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(server_kp.public),
            auth: AuthPolicy::SshSignature,
        },
        [2u8; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        stranger_events.clone(),
        Some(Arc::new(
            FileSigner::load(&stranger_path, None)
                .expect("load the stranger key")
                .with_login("stranger".to_string()),
        )),
    );
    stranger_client.send_bytes(0, b"hello".to_vec());

    // PRESENCE check, polled with a generous ceiling (like the acceptance
    // wait above) rather than assumed within a fixed window: the stranger's
    // own Noise handshake reaching `Live` needs a real round trip across two
    // independently scheduled OS threads (this task's tokio runtime and the
    // driver's own std thread) plus the driver's socket read-timeout loop.
    // A slow machine can only make this take LONGER, and the generous
    // ceiling absorbs that -- it must never be conflated with the fixed
    // wait below, which exists to confirm an ABSENCE and has the opposite
    // timing property.
    let reached_live = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if stranger_events.0.lock().expect("collected").live {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        reached_live.is_ok(),
        "the stranger's own Noise handshake must complete -- ruling out an \
         unbound socket or a config mismatch -- before its refusal can be \
         attributed to the signature check"
    );

    // ABSENCE check: now that the handshake is proven to have happened, a
    // short FIXED wait confirms the session-layer gate never let it through.
    // Unlike the presence check above, there is no positive condition to
    // poll for here, so a fixed sleep is appropriate -- and it is not
    // timing-fragile in the same way: `probation::AuthGate::feed` refuses an
    // unauthorized key on the first record chunk, well under a second on
    // loopback, so a slow machine can only make this margin more generous,
    // never cause a false failure.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let stranger_after_wait = stranger_events.0.lock().expect("collected");
    assert!(
        stranger_after_wait.stream0.is_empty(),
        "an unlisted key must get nothing back"
    );
    drop(stranger_after_wait);
    assert_eq!(
        granted.load(Ordering::SeqCst),
        1,
        "no second session was ever granted"
    );
    stranger_client.close();
}
