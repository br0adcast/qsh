use super::*;
use std::task::Poll;

#[tokio::test]
async fn shutdown_bypasses_a_full_inbound_queue_and_discards_it() {
    let (mut io, inbound, _outbound) = SessionIo::test_pair();
    for _ in 0..INBOUND_CAP {
        inbound.try_send(SessionInbound::Repaint).unwrap();
    }
    assert!(matches!(
        inbound.try_send(SessionInbound::Repaint),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    io.lifecycle.shutdown.request();
    assert!(
        io.recv().await.is_none(),
        "shutdown queued behind ordinary input"
    );
    assert!(inbound.is_closed());
    assert!(io.inbound.is_empty());
}

#[tokio::test]
async fn ordinary_close_keeps_already_queued_backend_input() {
    let (mut io, inbound, _outbound) = SessionIo::test_pair();
    inbound.try_send(SessionInbound::Repaint).unwrap();
    drop(inbound);
    assert!(matches!(io.recv().await, Some(SessionInbound::Repaint)));
    assert!(io.recv().await.is_none());
}

#[tokio::test]
async fn shutdown_interrupts_a_graceful_finisher_behind_full_input() {
    let (mut io, inbound, _outbound) = SessionIo::test_pair();
    for _ in 0..INBOUND_CAP {
        inbound.try_send(SessionInbound::Repaint).unwrap();
    }
    let lifecycle = io.lifecycle.clone();
    let mut link = BackendLink::new(inbound, Consumption::OnDelivery);
    // Live itself consumes no stream credit, but it still waits behind a full
    // bounded queue and exercises the real graceful input-finisher path.
    let mut connection = Connection::new(ConnectionConfig {
        required_features: crate::Features::NONE,
        features: crate::Features::SUPPORTED,
        role: Role::Server,
        local_static_priv: crate::handshake::generate_keypair().private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(Vec::new()),
    });
    let mut out = Vec::new();
    link.hand_over(
        &mut connection,
        Instant::now(),
        SessionInbound::Repaint,
        &mut out,
    );
    assert!(link.inbound.has_pending());
    link.finish(lifecycle.clone());
    let mut drain = Box::pin(lifecycle.drain());
    assert!(std::future::poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await);
    lifecycle.shutdown.request();
    assert!(io.recv().await.is_none());
    tokio::time::timeout(std::time::Duration::from_secs(2), drain)
        .await
        .expect("shutdown retained a blocked graceful input finisher")
        .unwrap();
}

struct CancellationBackend {
    started: Arc<tokio::sync::Notify>,
    cleaning: Arc<tokio::sync::Notify>,
    finished: Arc<tokio::sync::Notify>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl SessionBackend for CancellationBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let started = self.started.clone();
        let cleaning = self.cleaning.clone();
        let finished = self.finished.clone();
        let release = self.release.lock().unwrap().take().unwrap();
        Box::pin(async move {
            started.notify_one();
            while io.recv().await.is_some() {}
            cleaning.notify_one();
            let _ = release.await;
            finished.notify_one();
        })
    }
}

#[tokio::test]
async fn cancelling_the_legacy_serve_wrapper_does_not_abort_backend_cleanup() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let server = crate::handshake::generate_keypair();
    let key = crate::handshake::generate_keypair();
    let started = Arc::new(tokio::sync::Notify::new());
    let cleaning = Arc::new(tokio::sync::Notify::new());
    let finished = Arc::new(tokio::sync::Notify::new());
    // Dropping this sender releases cleanup on every assertion/unwind path.
    let (release, held) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(SessionManager::serve(
        socket,
        server.private,
        allowlist_auth(Arc::new(Mutex::new(vec![key.public])), server.public),
        BackendFactory(Arc::new(CancellationBackend {
            started: started.clone(),
            cleaning: cleaning.clone(),
            finished: finished.clone(),
            release: Mutex::new(Some(held)),
        })),
        Arc::new(AtomicUsize::new(0)),
        LoginEndedReports::none(),
    ));
    let (_client, _socket) = tokio::time::timeout(
        Duration::from_secs(5),
        handshake_to_live(addr, server.public, key.private, [39; 16], StartKind::Cold),
    )
    .await
    .expect("real authenticated client became live");
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("owned backend started");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(5), cleaning.notified())
        .await
        .expect("legacy cancellation let backend enter cleanup");
    drop(release);
    tokio::time::timeout(Duration::from_secs(5), finished.notified())
        .await
        .expect("legacy cancellation aborted owned backend cleanup");
}
