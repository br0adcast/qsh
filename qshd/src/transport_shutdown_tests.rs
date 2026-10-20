//! Daemon completion is a joined backend-lifetime receipt, not a STOP ack.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use transport::auth::Principal;
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::{LinkState, ServerAuth, SessionBackend, SessionIo, Stats};

struct HeldRun {
    started: Notify,
    cleaning: Notify,
    release: Semaphore,
    finished: Notify,
}
impl HeldRun {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Notify::new(),
            cleaning: Notify::new(),
            release: Semaphore::new(0),
            finished: Notify::new(),
        })
    }
}
struct HeldCleanup {
    runs: [Arc<HeldRun>; 2],
    next: AtomicUsize,
}
impl SessionBackend for HeldCleanup {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let run = self.runs[self.next.fetch_add(1, Ordering::SeqCst)].clone();
        Box::pin(async move {
            run.started.notify_one();
            while io.recv().await.is_some() {}
            run.cleaning.notify_one();
            run.release.acquire().await.unwrap().forget();
            run.finished.notify_one();
        })
    }
}

struct ReleaseOnDrop([Arc<HeldRun>; 2]);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        for run in &self.0 {
            run.release.add_permits(1);
        }
    }
}
struct Noop;
impl Binder for Noop {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}
impl ClientEvents for Noop {
    fn on_bytes(&self, _stream: u8, _data: Vec<u8>) {}
    fn on_state(&self, _state: LinkState) {}
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream: u8) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_does_not_complete_while_owned_backend_cleanup_is_held() {
    stop_with_held_cleanup(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_keeps_a_replaced_backend_until_its_cleanup_finishes() {
    stop_with_held_cleanup(true).await;
}

async fn stop_with_held_cleanup(replace: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let cleanup = crate::control::SocketCleanup::capture(&listener, &path).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let server = generate_keypair();
    let client_key = generate_keypair();
    let runs = [HeldRun::new(), HeldRun::new()];
    let _release_on_unwind = ReleaseOnDrop(runs.clone());
    let mut daemon = tokio::spawn(super::run_transport_daemon(
        socket,
        server.private,
        ServerAuth {
            allowlist: Arc::new(Mutex::new(vec![client_key.public])),
            verifier: None,
            server_pub: server.public,
            self_principal: Principal {
                uid: 1000,
                name: "fixture".into(),
                identity: "allowlist".into(),
                incarnation: 0,
            },
            nonces: Arc::new(crate::RandomNonces),
            logins: Arc::new(crate::ForgetNothing),
        },
        Arc::new(HeldCleanup {
            runs: runs.clone(),
            next: AtomicUsize::new(0),
        }),
        listener,
        cleanup,
        vec![addr.port()],
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
    ));
    let connect = || {
        StdClient::connect(
            addr,
            ConnectionConfig {
                required_features: transport::Features::NONE,
                features: transport::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: client_key.private,
                remote_static_pub: Some(server.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            [39; 16],
            StartKind::Cold,
            Arc::new(Noop),
            Arc::new(Noop),
            None,
        )
    };
    let client = connect();
    tokio::time::timeout(Duration::from_secs(5), runs[0].started.notified())
        .await
        .expect("authenticated backend started");
    let replacement = if replace {
        let client = connect();
        tokio::time::timeout(Duration::from_secs(5), runs[1].started.notified())
            .await
            .expect("cold replacement backend started");
        tokio::time::timeout(Duration::from_secs(5), runs[0].cleaning.notified())
            .await
            .expect("replaced backend retained in cleanup");
        Some(client)
    } else {
        None
    };
    let reply = tokio::task::spawn_blocking(move || {
        crate::control::client_request_with_timeout(
            &path,
            &crate::control::ControlRequest::Stop,
            Duration::from_secs(2),
        )
    })
    .await
    .unwrap()
    .unwrap();
    let stop_ack = match reply {
        crate::control::ControlReply::Answered(line) => {
            serde_json::from_str::<serde_json::Value>(&line).unwrap()
        }
        other => panic!("STOP did not answer: {other:?}"),
    };
    let current = usize::from(replace);
    tokio::time::timeout(Duration::from_secs(5), runs[current].cleaning.notified())
        .await
        .expect("owned backend entered cleanup");
    if replace {
        // End the current backend while the old, no-longer-routed owner stays
        // held. Tracking only Router.backends would now lose that old owner.
        runs[1].release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), runs[1].finished.notified())
            .await
            .expect("current backend finished");
    }
    // A negative observation window gives an incorrectly untracked current
    // completion time to reach the daemon. This is not a cleanup receipt:
    // all real fixture completion notifications and the daemon are joined below.
    let returned_early = tokio::time::timeout(Duration::from_millis(50), &mut daemon)
        .await
        .ok();
    // Release and join the fixture before asserting, including on the RED path.
    runs[0].release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), runs[0].finished.notified())
        .await
        .expect("released backend finished");
    if returned_early.is_none() {
        tokio::time::timeout(Duration::from_secs(5), daemon)
            .await
            .expect("daemon completed after release")
            .unwrap()
            .unwrap();
    }
    client.close();
    if let Some(client) = replacement {
        client.close();
    }
    assert!(
        returned_early.is_none(),
        "daemon completed before owned backend cleanup"
    );
    assert_eq!(
        stop_ack["stopping"], true,
        "ack must describe the pending cleanup"
    );
    assert!(
        stop_ack.get("stopped").is_none(),
        "ack cannot claim completed cleanup"
    );
}

#[tokio::test]
async fn stopping39_failed_enqueue_never_acknowledges_success() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
    drop(stop_rx);
    client.write_all(b"STOP\n").await.unwrap();
    let result = super::handle_transport_control_connection(
        server,
        Arc::new(Mutex::new(Vec::new())),
        Vec::new(),
        stop_tx,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
    )
    .await;
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert!(
        result.is_err(),
        "a closed shutdown receiver cannot accept STOP"
    );
    assert!(
        reply.is_empty(),
        "failed enqueue emitted a success acknowledgement"
    );
}
