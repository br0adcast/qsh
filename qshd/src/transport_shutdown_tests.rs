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
    received: Notify,
    cleaning: Notify,
    release: Semaphore,
    finished: Notify,
    fail: std::sync::atomic::AtomicBool,
}
impl HeldRun {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Notify::new(),
            received: Notify::new(),
            cleaning: Notify::new(),
            release: Semaphore::new(0),
            finished: Notify::new(),
            fail: std::sync::atomic::AtomicBool::new(false),
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
            while let Some(inbound) = io.recv().await {
                if matches!(inbound, transport::session_manager::SessionInbound::Data(_)) {
                    run.received.notify_one();
                }
            }
            run.cleaning.notify_one();
            run.release.acquire().await.unwrap().forget();
            run.finished.notify_one();
            assert!(
                !run.fail.load(Ordering::SeqCst),
                "injected owned backend failure"
            );
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
    fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, _stream: u8, _data: Vec<u8>) {}
    fn on_state(&self, _state: LinkState) {}
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream: u8) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_does_not_complete_while_owned_backend_cleanup_is_held() {
    stop_with_held_cleanup(false, false, false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_keeps_a_replaced_backend_until_its_cleanup_finishes() {
    stop_with_held_cleanup(true, false, false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn personal39_signal_drains_the_manager_while_retaining_a_silent_control() {
    stop_with_held_cleanup(false, true, false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn personal39_signal_preserves_a_failed_manager_outcome_after_all_joins() {
    stop_with_held_cleanup(false, true, true, None).await;
}

// The same stop and signal drains with every task on one runtime worker, as
// `qshd serve --runtime-threads 1` runs them.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn stop_waits_for_held_cleanup_on_one_runtime_worker() {
    stop_with_held_cleanup(false, false, false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn stop_keeps_a_replaced_backend_on_one_runtime_worker() {
    stop_with_held_cleanup(true, false, false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn signal_drain_retains_a_silent_control_on_one_runtime_worker() {
    stop_with_held_cleanup(false, true, false, None).await;
}

struct InjectedAcceptor {
    listener: tokio::net::UnixListener,
    errors: tokio::sync::mpsc::UnboundedReceiver<i32>,
    attempts: Arc<AtomicUsize>,
}
impl super::ControlAcceptor for InjectedAcceptor {
    async fn accept(&mut self) -> std::io::Result<tokio::net::UnixStream> {
        tokio::select! {
            biased;
            Some(errno) = self.errors.recv() => {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::from_raw_os_error(errno))
            }
            accepted = self.listener.accept() => accepted.map(|(stream, _)| stream),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept294_pressure_preserves_sessions_and_stop_drain() {
    stop_with_held_cleanup(false, false, false, Some(nix::libc::EMFILE)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept294_pressure_preserves_sessions_and_signal_drain() {
    stop_with_held_cleanup(false, true, false, Some(nix::libc::ENOBUFS)).await;
}

async fn stop_with_held_cleanup(replace: bool, signal: bool, fail: bool, pressure: Option<i32>) {
    let dir = crate::control::private_test_dir().unwrap();
    let path = dir.path().join("control.sock");
    let (listener, cleanup) = crate::control::bind_private_owned(&path).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let server = generate_keypair();
    let client_key = generate_keypair();
    let runs = [HeldRun::new(), HeldRun::new()];
    runs[0].fail.store(fail, Ordering::SeqCst);
    let _release_on_unwind = ReleaseOnDrop(runs.clone());
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let (pressure_tx, pressure_rx) = tokio::sync::mpsc::unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let auth = ServerAuth {
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
    };
    let backend = Arc::new(HeldCleanup {
        runs: runs.clone(),
        next: AtomicUsize::new(0),
    });
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    let stop = async move { signal_rx.await.map_err(anyhow::Error::new) };
    let mut daemon = if pressure.is_some() {
        listener.set_nonblocking(true).unwrap();
        let listener = InjectedAcceptor {
            listener: tokio::net::UnixListener::from_std(listener).unwrap(),
            errors: pressure_rx,
            attempts: attempts.clone(),
        };
        tokio::spawn(async move {
            let _cleanup = cleanup;
            super::run_transport_daemon_with_acceptor(
                socket,
                server.private,
                auth,
                backend,
                listener,
                vec![addr.port()],
                Arc::new(AtomicUsize::new(0)),
                gate,
                None,
                stop,
            )
            .await
        })
    } else {
        // Original shutdown cases still exercise the public adoption wrapper
        // and keep SocketCleanup owned by the daemon until all joins finish.
        tokio::spawn(super::run_transport_daemon_until_stop(
            socket,
            server.private,
            auth,
            backend,
            listener,
            cleanup,
            vec![addr.port()],
            Arc::new(AtomicUsize::new(0)),
            gate,
            None,
            stop,
        ))
    };
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
    if let Some(errno) = pressure {
        for _ in 0..4 {
            pressure_tx.send(errno).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accept error injected after authenticated session started");
        // A fresh input reaching the authenticated backend is a positive
        // manager-progress barrier, independent of wall-clock retry timing.
        let admitted = client.send_bytes(0, b"pressure probe".to_vec());
        let received =
            tokio::time::timeout(Duration::from_secs(5), runs[0].received.notified()).await;
        if admitted.is_err() || received.is_err() {
            let _ = signal_tx.send(());
            runs[0].release.add_permits(1);
            let outcome = join_test_daemon(daemon).await;
            client.close();
            panic!("accept pressure prevented live backend input: {outcome:?}");
        }
    }
    let mut silent = None;
    let stop_ack = if signal && pressure.is_some() {
        signal_tx.send(()).unwrap();
        None
    } else if signal {
        silent = Some(tokio::net::UnixStream::connect(&path).await.unwrap());
        // A later STATUS round trip proves the listener passed the silent
        // connection to its owned task before we request shutdown.
        let status_path = path.clone();
        tokio::task::spawn_blocking(move || {
            crate::control::client_request_with_timeout(
                &status_path,
                &crate::control::ControlRequest::Status,
                Duration::from_secs(2),
            )
        })
        .await
        .unwrap()
        .unwrap();
        signal_tx.send(()).unwrap();
        None
    } else {
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
        Some(stop_ack)
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
    if let Some(mut silent) = silent {
        use tokio::io::AsyncReadExt;
        let still_owned = tokio::time::timeout(Duration::from_millis(50), &mut daemon).await;
        assert!(
            still_owned.is_err(),
            "accepted silent control still needs its original deadline"
        );
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), silent.read_to_end(&mut bytes))
            .await
            .expect("original control deadline closed silent connection")
            .unwrap();
        assert!(bytes.is_empty());
    }
    if returned_early.is_none() {
        let result = join_test_daemon(daemon).await;
        if fail {
            assert!(
                result.is_err(),
                "failed manager remains failed after control joins"
            );
        } else {
            result.unwrap();
        }
    }
    client.close();
    if let Some(client) = replacement {
        client.close();
    }
    assert!(
        returned_early.is_none(),
        "daemon completed before owned backend cleanup"
    );
    if let Some(stop_ack) = stop_ack {
        assert_eq!(
            stop_ack["stopping"], true,
            "ack must describe the pending cleanup"
        );
        assert!(
            stop_ack.get("stopped").is_none(),
            "ack cannot claim completed cleanup"
        );
    }
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
        None,
        tokio::time::Instant::now() + super::CONTROL_REQUEST_TIMEOUT,
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

#[cfg(all(feature = "system", target_os = "linux"))]
#[tokio::test]
async fn worker40_owned_manager_observes_stop_requested_before_its_first_poll() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let key = generate_keypair();
    let stop = transport::Shutdown::default();
    stop.request();
    let runs = [HeldRun::new(), HeldRun::new()];
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        super::run_serve_loop_until_shutdown(
            socket,
            key.private,
            ServerAuth {
                allowlist: Arc::new(Mutex::new(Vec::new())),
                verifier: None,
                server_pub: key.public,
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
                runs,
                next: AtomicUsize::new(0),
            }),
            transport::LoginEndedReports::none(),
            stop,
        ),
    )
    .await;
    assert!(result.is_ok(), "actual worker manager ignored sticky stop");
    assert!(result.unwrap().is_ok());
}

#[cfg(all(feature = "system", target_os = "linux"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker40_owned_manager_retains_authenticated_backend_through_actual_cleanup() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let server = generate_keypair();
    let client_key = generate_keypair();
    let runs = [HeldRun::new(), HeldRun::new()];
    let _release_on_unwind = ReleaseOnDrop(runs.clone());
    let stop = transport::Shutdown::default();
    let mut manager = tokio::spawn(super::run_serve_loop_until_shutdown(
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
        transport::LoginEndedReports::none(),
        stop.clone(),
    ));
    let client = StdClient::connect(
        addr,
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        [40; 16],
        StartKind::Cold,
        Arc::new(Noop),
        Arc::new(Noop),
        None,
    );
    tokio::time::timeout(Duration::from_secs(5), runs[0].started.notified())
        .await
        .expect("authenticated worker backend started");
    stop.request();
    tokio::time::timeout(Duration::from_secs(5), runs[0].cleaning.notified())
        .await
        .expect("actual worker manager drove backend into cleanup");
    let early = tokio::time::timeout(Duration::from_millis(50), &mut manager)
        .await
        .ok();
    runs[0].release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), runs[0].finished.notified())
        .await
        .expect("actual backend finished after release");
    let returned_early = early.is_some();
    let result = match early {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(5), manager)
            .await
            .expect("actual manager joined after backend release"),
    };
    client.close();
    assert!(
        !returned_early,
        "worker manager returned while backend cleanup was held"
    );
    result.unwrap().unwrap();
}

/// A complete request already consumed from the kernel must still use its
/// original connection deadline while waiting for the update/control gate.
#[tokio::test(start_paused = true)]
async fn personal39_control_deadline_covers_the_gate_after_reading_the_request() {
    use std::os::fd::AsRawFd;
    use std::task::Poll;
    use tokio::io::AsyncWriteExt;

    let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
    let fd = server.as_raw_fd();
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    let held = gate.clone().write_owned().await;
    let (stop_tx, _stop_rx) = tokio::sync::mpsc::channel(1);
    client.write_all(b"STATUS\n").await.unwrap();
    let mut handler = Box::pin(super::handle_transport_control_connection(
        server,
        Arc::new(Mutex::new(Vec::new())),
        vec![1],
        stop_tx,
        Arc::new(AtomicUsize::new(0)),
        gate,
        None,
        tokio::time::Instant::now() + super::CONTROL_REQUEST_TIMEOUT,
    ));
    let setup_deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let polled = std::future::poll_fn(|cx| Poll::Ready(handler.as_mut().poll(cx))).await;
        assert!(
            polled.is_pending(),
            "held gate cannot have answered the request"
        );
        let mut unread: nix::libc::c_int = -1;
        assert_eq!(
            unsafe { nix::libc::ioctl(fd, nix::libc::FIONREAD, &mut unread) },
            0
        );
        if unread == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < setup_deadline,
            "request was never actually consumed"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(super::CONTROL_REQUEST_TIMEOUT).await;
    let polled = std::future::poll_fn(|cx| Poll::Ready(handler.as_mut().poll(cx))).await;
    // Release before asserting; this is local IO cancellation, no detached task.
    drop(held);
    assert!(
        matches!(polled, Poll::Ready(Err(_))),
        "the original control deadline must cover the gate, not just read_line"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn personal39_signal_preserves_an_admitted_gate_held_stop_ack() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let dir = crate::control::private_test_dir().unwrap();
    let path = dir.path().join("control.sock");
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    let held = gate.clone().write_owned().await;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut daemon = spawn_control_fixture(
        &path,
        gate.clone(),
        Arc::new(Mutex::new(Vec::new())),
        async move { stop_rx.await.map_err(anyhow::Error::new) },
    );
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(b"STOP\n").await.unwrap();
    // The test, write guard and daemon own three references. Only an accepted
    // handler creates the fourth: the signal must race an admitted connection.
    tokio::time::timeout(Duration::from_secs(3), async {
        while Arc::strong_count(&gate) < 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("STOP handler was admitted before the signal");
    stop_tx.send(()).unwrap();
    let early = tokio::time::timeout(Duration::from_millis(50), &mut daemon)
        .await
        .ok();
    let returned_early = early.is_some();
    // Always release the accepted task and join before checking its ACK.
    drop(held);
    let mut reply = String::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::BufReader::new(client).read_line(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    let result = match early {
        Some(result) => result.unwrap(),
        None => join_test_daemon(daemon).await,
    };
    result.unwrap();
    assert!(
        !returned_early,
        "admitted control task remains owned while its gate is held"
    );
    assert_eq!(reply, "{\"stopping\":true}\n");
}

#[tokio::test(start_paused = true)]
async fn personal39_control_deadline_covers_a_backpressured_reply() {
    use std::os::fd::AsRawFd;
    use std::task::Poll;
    use tokio::io::AsyncWriteExt;
    let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
    let fd = server.as_raw_fd();
    let capacity: nix::libc::c_int = 4096;
    assert_eq!(
        unsafe {
            nix::libc::setsockopt(
                fd,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_SNDBUF,
                (&capacity as *const nix::libc::c_int).cast(),
                std::mem::size_of_val(&capacity) as nix::libc::socklen_t,
            )
        },
        0
    );
    client.write_all(b"STATUS\n").await.unwrap();
    let (stop_tx, _stop_rx) = tokio::sync::mpsc::channel(1);
    let mut handler = Box::pin(super::handle_transport_control_connection(
        server,
        Arc::new(Mutex::new(Vec::new())),
        vec![1; 16_384],
        stop_tx,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
        None,
        tokio::time::Instant::now() + super::CONTROL_REQUEST_TIMEOUT,
    ));
    let setup = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let result = std::future::poll_fn(|cx| Poll::Ready(handler.as_mut().poll(cx))).await;
        assert!(result.is_pending());
        let mut queued: nix::libc::c_int = 0;
        assert_eq!(
            unsafe { nix::libc::ioctl(client.as_raw_fd(), nix::libc::FIONREAD, &mut queued) },
            0
        );
        if queued > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < setup,
            "STATUS actually entered its response write"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(super::CONTROL_REQUEST_TIMEOUT).await;
    assert!(
        matches!(
            std::future::poll_fn(|cx| Poll::Ready(handler.as_mut().poll(cx))).await,
            Poll::Ready(Err(_))
        ),
        "backpressured response shares the original deadline"
    );
}

#[tokio::test(start_paused = true)]
async fn personal39_join_retains_a_stop_ack_whose_writer_is_pending() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
    server.writable().await.unwrap();
    let mut padding = 0;
    let block = [b'x'; 4096];
    loop {
        match server.try_write(&block) {
            Ok(written) => padding += written,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("prefilling owned fixture response buffer: {error}"),
        }
    }
    assert!(padding > 0);
    client.write_all(b"STOP\n").await.unwrap();
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
    let mut handlers = tokio::task::JoinSet::new();
    super::spawn_control_handler(
        &mut handlers,
        server,
        Arc::new(Mutex::new(Vec::new())),
        vec![1],
        stop_tx,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::RwLock::new(())),
        None,
    );
    stop_rx
        .recv()
        .await
        .expect("STOP was accepted before its blocked ACK");
    let mut join = Box::pin(super::join_control_handlers(&mut handlers, &mut stop_rx));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(join.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let mut prefix = vec![0; padding];
    client.read_exact(&mut prefix).await.unwrap();
    assert!(prefix.iter().all(|byte| *byte == b'x'));
    join.await.unwrap();
    let mut ack = String::new();
    client.read_to_string(&mut ack).await.unwrap();
    assert_eq!(ack, "{\"stopping\":true}\n");
    assert!(handlers.is_empty());
}

fn spawn_control_fixture(
    path: &std::path::Path,
    gate: Arc<tokio::sync::RwLock<()>>,
    allowlist: Arc<Mutex<Vec<[u8; 32]>>>,
    stop: impl Future<Output = anyhow::Result<()>> + Send + 'static,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let (listener, cleanup) = crate::control::bind_private_owned(path).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = generate_keypair();
    tokio::spawn(super::run_transport_daemon_until_stop(
        socket,
        server.private,
        ServerAuth {
            allowlist,
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
            runs: [HeldRun::new(), HeldRun::new()],
            next: AtomicUsize::new(0),
        }),
        listener,
        cleanup,
        vec![1],
        Arc::new(AtomicUsize::new(0)),
        gate,
        None,
        stop,
    ))
}

#[tokio::test]
async fn personal39_a_panicked_control_task_fails_the_joined_daemon() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = crate::control::private_test_dir().unwrap();
    let path = dir.path().join("control.sock");
    let allowlist = Arc::new(Mutex::new(Vec::new()));
    let poisoned = allowlist.clone();
    let _ = std::panic::catch_unwind(|| {
        let _guard = poisoned.lock().unwrap();
        panic!("controlled poisoned allowlist");
    });
    let daemon = spawn_control_fixture(
        &path,
        Arc::new(tokio::sync::RwLock::new(())),
        allowlist,
        std::future::pending(),
    );
    let mut client = tokio::net::UnixStream::connect(path).await.unwrap();
    client
        .write_all(
            crate::control::format_request(&crate::control::ControlRequest::AddClient([3; 32]))
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let outcome = join_test_daemon(daemon).await;
    assert!(
        outcome.is_err(),
        "lost control task custody cannot be successful shutdown"
    );
    assert!(response.is_empty());
}

async fn join_test_daemon(
    mut daemon: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    match tokio::time::timeout(Duration::from_secs(5), &mut daemon).await {
        Ok(result) => result.expect("test daemon task returned instead of panicking"),
        Err(error) => {
            // This helper owns only test futures and sockets, never native
            // process custody. Failed observation still aborts AND joins.
            daemon.abort();
            let joined = daemon.await;
            panic!("test daemon did not join: {error}; canceled task: {joined:?}");
        }
    }
}

#[tokio::test]
async fn accept294_cancelled_handler_join_retains_other_handlers() {
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
    let mut handlers = tokio::task::JoinSet::new();
    let cancelled = handlers.spawn(std::future::pending::<()>());
    cancelled.abort();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    handlers.spawn(async move {
        release_rx.await.unwrap();
    });
    let mut join = Box::pin(super::join_control_handlers(&mut handlers, &mut stop_rx));
    assert!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(join.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    release_tx.send(()).unwrap();
    assert!(
        join.await.is_err(),
        "unexpected cancellation remains a failed joined outcome"
    );
    assert!(
        handlers.is_empty(),
        "failure cannot discard another owned handler"
    );
    drop(stop_tx);
}

fn spawn_accept_fixture(
    path: &std::path::Path,
    gate: Arc<tokio::sync::RwLock<()>>,
    allowlist: Arc<Mutex<Vec<[u8; 32]>>>,
    stop: impl Future<Output = anyhow::Result<()>> + Send + 'static,
    errors: tokio::sync::mpsc::UnboundedReceiver<i32>,
    attempts: Arc<AtomicUsize>,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let (listener, cleanup) = crate::control::bind_private_owned(path).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = generate_keypair();
    listener.set_nonblocking(true).unwrap();
    tokio::spawn(async move {
        let _cleanup = cleanup;
        super::run_transport_daemon_with_acceptor(
            socket,
            server.private,
            ServerAuth {
                allowlist,
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
                runs: [HeldRun::new(), HeldRun::new()],
                next: AtomicUsize::new(0),
            }),
            InjectedAcceptor {
                listener: tokio::net::UnixListener::from_std(listener).unwrap(),
                errors,
                attempts,
            },
            vec![1],
            Arc::new(AtomicUsize::new(0)),
            gate,
            None,
            stop,
        )
        .await
    })
}

#[tokio::test]
async fn accept294_unknown_listener_errors_fail_and_join() {
    for errno in [
        nix::libc::EBADF,
        nix::libc::EINVAL,
        nix::libc::EACCES,
        nix::libc::EIO,
    ] {
        let dir = crate::control::private_test_dir().unwrap();
        let path = dir.path().join("control.sock");
        let (errors_tx, errors_rx) = tokio::sync::mpsc::unbounded_channel();
        let attempts = Arc::new(AtomicUsize::new(0));
        errors_tx.send(errno).unwrap();
        let daemon = spawn_accept_fixture(
            &path,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(Mutex::new(Vec::new())),
            std::future::pending(),
            errors_rx,
            attempts.clone(),
        );
        let result = join_test_daemon(daemon).await;
        assert!(
            result.is_err(),
            "unclassified errno {errno} must fail closed"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(
            !path.exists(),
            "listener cleanup stays owned through joined failure"
        );
    }
}

// These fixtures own futures and sockets only, with no native process custody.
// Use a real-time watchdog so a regression cannot freeze a paused-clock test;
// failure still aborts AND joins its exclusively owned daemon task.
async fn wait_for_accept_fixture(
    daemon: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    condition: impl Fn() -> bool,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !condition() {
        if daemon.is_finished() || std::time::Instant::now() >= deadline {
            daemon.abort();
            let outcome = daemon.await;
            panic!("accept fixture did not reach its barrier: {outcome:?}");
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn accept294_admitted_stop_interrupts_retry_and_drains_its_ack() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let dir = crate::control::private_test_dir().unwrap();
    let path = dir.path().join("control.sock");
    let gate = Arc::new(tokio::sync::RwLock::new(()));
    let held = gate.clone().write_owned().await;
    let (errors_tx, errors_rx) = tokio::sync::mpsc::unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut daemon = spawn_accept_fixture(
        &path,
        gate.clone(),
        Arc::new(Mutex::new(Vec::new())),
        std::future::pending(),
        errors_rx,
        attempts.clone(),
    );
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(b"STOP\n").await.unwrap();
    wait_for_accept_fixture(&mut daemon, || Arc::strong_count(&gate) >= 4).await;
    errors_tx.send(nix::libc::ENOMEM).unwrap();
    wait_for_accept_fixture(&mut daemon, || attempts.load(Ordering::SeqCst) > 0).await;
    let before = tokio::time::Instant::now();
    drop(held);
    let mut reply = String::new();
    tokio::io::BufReader::new(client)
        .read_line(&mut reply)
        .await
        .unwrap();
    join_test_daemon(daemon).await.unwrap();
    assert_eq!(reply, "{\"stopping\":true}\n");
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "STOP cannot wait for accept backoff"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn accept294_backoff_is_capped_and_resets_after_success() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let dir = crate::control::private_test_dir().unwrap();
    let path = dir.path().join("control.sock");
    let (errors_tx, errors_rx) = tokio::sync::mpsc::unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut daemon = spawn_accept_fixture(
        &path,
        Arc::new(tokio::sync::RwLock::new(())),
        Arc::new(Mutex::new(Vec::new())),
        async move { stop_rx.await.map_err(anyhow::Error::new) },
        errors_rx,
        attempts.clone(),
    );
    for errno in [
        nix::libc::EMFILE,
        nix::libc::ENFILE,
        nix::libc::ENOBUFS,
        nix::libc::ENOMEM,
        nix::libc::EINTR,
        nix::libc::ECONNABORTED,
        nix::libc::ECONNRESET,
        nix::libc::EAGAIN,
    ] {
        errors_tx.send(errno).unwrap();
    }
    wait_for_accept_fixture(&mut daemon, || attempts.load(Ordering::SeqCst) > 0).await;
    for (index, delay) in [50, 100, 200, 400, 800, 1000, 1000].into_iter().enumerate() {
        tokio::time::advance(Duration::from_millis(delay - 1)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            index + 1,
            "retry must wait its deadline"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(
            !daemon.is_finished(),
            "recoverable accept error terminated manager"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            index + 2,
            "retry resumes at its capped deadline"
        );
    }
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(b"STATUS\n").await.unwrap();
    tokio::time::advance(Duration::from_millis(1000)).await;
    let mut reply = String::new();
    tokio::io::BufReader::new(client)
        .read_line(&mut reply)
        .await
        .unwrap();
    assert!(
        !reply.is_empty(),
        "successful accept after resource recovery"
    );
    errors_tx.send(nix::libc::EMFILE).unwrap();
    errors_tx.send(nix::libc::EMFILE).unwrap();
    wait_for_accept_fixture(&mut daemon, || attempts.load(Ordering::SeqCst) >= 9).await;
    tokio::time::advance(Duration::from_millis(49)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 9);
    tokio::time::advance(Duration::from_millis(1)).await;
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        10,
        "successful accept reset the retry delay"
    );
    stop_tx.send(()).unwrap();
    join_test_daemon(daemon).await.unwrap();
}
