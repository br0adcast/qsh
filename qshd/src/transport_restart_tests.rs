//! Actual control-dispatch boundaries: commitment survives ACK loss/cancellation.
use super::*;
use daemon_bootstrap_protocol::{
    BusyAttemptId, BusyDaemonIdentity, CandidateImageIdentity, DestructiveRestartAction,
    DestructiveRestartConsent,
};
fn binding() -> DestructiveRestartConsent {
    DestructiveRestartConsent {
        attempt: BusyAttemptId::from_bytes([1; 16]),
        identity: BusyDaemonIdentity {
            version: "0.6.0-rc1".into(),
            build: 1,
            checksum: "ab".repeat(32),
            pid: 42,
            generation: Some("cd".repeat(16)),
        },
        candidate: CandidateImageIdentity {
            build: 2,
            checksum: "ef".repeat(32),
        },
        action: DestructiveRestartAction::StopAndRestart,
    }
}
fn actions() -> Arc<Actions> {
    Arc::new(Actions::new(
        Some(binding().identity),
        Arc::new(tokio::sync::RwLock::new(())),
        Arc::new(crate::update::AdmissionGate::default()),
        true,
    ))
}
async fn dispatch(
    server: tokio::net::UnixStream,
    actions: Arc<Actions>,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let (stop_tx, _stop_rx) = mpsc::channel(1);
    handle_transport_control_connection_with_info(
        server,
        Arc::new(std::sync::Mutex::new(Vec::new())),
        vec![60000],
        stop_tx,
        Arc::new(AtomicUsize::new(2)),
        actions.control_gate.clone(),
        None,
        deadline,
        None,
        Some(actions),
    )
    .await
}
#[tokio::test]
async fn committed_shutdown_survives_failed_ack_without_mpsc_delivery() {
    let actions = actions();
    let receipt = actions.prepare(binding()).unwrap();
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    client
        .write_all(
            control::format_request(&ControlRequest::CommitDestructiveStop {
                receipt,
                consent: binding(),
            })
            .as_bytes(),
        )
        .await
        .unwrap();
    drop(client);
    assert!(dispatch(
        server,
        actions.clone(),
        tokio::time::Instant::now() + Duration::from_secs(1)
    )
    .await
    .is_err());
    assert!(actions.shutdown.is_requested());
    assert!(actions.admission.is_closed());
    assert_eq!(
        actions.commit(receipt, &binding()).await,
        Ok(crate::destructive_restart::Commit::AlreadyCommitted)
    );
}
#[tokio::test]
async fn deadline_before_exclusive_gate_has_zero_commit_effect() {
    let actions = actions();
    let receipt = actions.prepare(binding()).unwrap();
    let read = actions.control_gate.read().await;
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    client
        .write_all(
            control::format_request(&ControlRequest::CommitDestructiveStop {
                receipt,
                consent: binding(),
            })
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(dispatch(
        server,
        actions.clone(),
        tokio::time::Instant::now() + Duration::from_millis(20)
    )
    .await
    .is_err());
    assert!(!actions.shutdown.is_requested());
    assert!(!actions.admission.is_closed());
    drop(read);
    // Cancellation did not consume an operation that never acquired authority.
    assert_eq!(
        actions.commit(receipt, &binding()).await,
        Ok(crate::destructive_restart::Commit::New)
    );
}
#[tokio::test]
async fn info_and_prepare_are_explicit_checked_control_operations() {
    let actions = actions();
    for request in [
        ControlRequest::DestructiveRestartInfo([9; 32]),
        ControlRequest::PrepareDestructiveStop(binding()),
    ] {
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        client
            .write_all(control::format_request(&request).as_bytes())
            .await
            .unwrap();
        dispatch(
            server,
            actions.clone(),
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        assert!(out.len() <= 4096);
        match request {
            ControlRequest::DestructiveRestartInfo(_) => {
                let response: control::DestructiveRestartInfoResponse =
                    serde_json::from_str(&out).unwrap();
                assert_eq!(response.challenge, hex::encode([9; 32]));
                assert_eq!(response.identity, binding().identity);
                assert_eq!(response.capability, "conditional-stop-receipt-v1");
            }
            _ => {
                let control::DestructivePrepareResponse::Prepared { receipt, consent } =
                    serde_json::from_str(&out).unwrap()
                else {
                    panic!("not prepared")
                };
                assert_eq!(consent, binding());
                assert_eq!(hex::decode(receipt).unwrap().len(), 16);
            }
        }
        assert!(!actions.shutdown.is_requested());
        assert!(!actions.admission.is_closed());
    }
}

struct TeardownExecAcceptor {
    listener: tokio::net::UnixListener,
    actions: Arc<Actions>,
    lease: crate::destructive_restart::ReplacementLease,
    calls: Arc<AtomicUsize>,
    observation: Arc<std::sync::Mutex<Option<(crate::destructive_restart::ExecFailure, bool)>>>,
    fatal: bool,
}
impl ControlAcceptor for TeardownExecAcceptor {
    async fn accept(&mut self) -> std::io::Result<tokio::net::UnixStream> {
        if self.fatal {
            Err(std::io::Error::from_raw_os_error(nix::libc::EBADF))
        } else {
            std::future::pending().await
        }
    }
}
impl Drop for TeardownExecAcceptor {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let descriptor_open =
            unsafe { nix::libc::fcntl(self.listener.as_raw_fd(), nix::libc::F_GETFD) } >= 0;
        let result = crate::destructive_restart::ExecAttemptGuard::new(&self.actions, self.lease)
            .attempt(|| {
                self.calls.fetch_add(1, Ordering::SeqCst);
                nix::errno::Errno::ENOENT
            });
        *self.observation.lock().unwrap() = Some((result, descriptor_open));
    }
}
struct NoTeardownSessions;
impl transport::SessionBackend for NoTeardownSessions {
    fn run(
        &self,
        _: transport::SessionIo,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        panic!("teardown fixture admits no sessions")
    }
}
async fn assert_owner_teardown_revokes_exec(fatal: bool) {
    use crate::destructive_restart::{ExecAttemptGuard, ExecFailure};
    let actions = actions();
    let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
    let mut ordinary_calls = 0;
    assert_eq!(
        ExecAttemptGuard::new(&actions, lease).attempt(|| {
            ordinary_calls += 1;
            nix::errno::Errno::ENOENT
        }),
        ExecFailure::Os(nix::errno::Errno::ENOENT)
    );
    assert_eq!(
        ordinary_calls, 1,
        "ordinary active-lease exec is still allowed"
    );
    let dir = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observation = Arc::new(std::sync::Mutex::new(None));
    let acceptor = TeardownExecAcceptor {
        listener: tokio::net::UnixListener::from_std(listener).unwrap(),
        actions: actions.clone(),
        lease,
        calls: calls.clone(),
        observation: observation.clone(),
        fatal,
    };
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = transport::generate_keypair();
    let stop = async move {
        if fatal {
            std::future::pending::<Result<()>>().await
        } else {
            Ok(())
        }
    };
    let result = run_transport_daemon_with_acceptor(
        socket,
        server.private,
        transport::ServerAuth {
            allowlist: Arc::new(std::sync::Mutex::new(Vec::new())),
            verifier: None,
            server_pub: server.public,
            self_principal: transport::Principal {
                uid: nix::unistd::geteuid().as_raw(),
                name: "owned fixture".into(),
                identity: "allowlist".into(),
                incarnation: 0,
            },
            nonces: Arc::new(crate::RandomNonces),
            logins: Arc::new(crate::ForgetNothing),
        },
        Arc::new(NoTeardownSessions),
        acceptor,
        vec![1],
        Arc::new(AtomicUsize::new(0)),
        actions.control_gate.clone(),
        None,
        stop,
        Some(actions.clone()),
    )
    .await;
    assert_eq!(result.is_err(), fatal);
    assert_eq!(
        *observation.lock().unwrap(),
        Some((ExecFailure::Revoked, true)),
        "owner must revoke exec before releasing its original handover descriptor"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "teardown cannot execute a raw syscall under the old lease"
    );
    assert!(actions.shutdown.is_requested());
    assert!(actions.admission.is_closed());
}
#[tokio::test]
async fn stop_future_latches_shutdown_before_acceptor_drop_can_attempt_exec() {
    assert_owner_teardown_revokes_exec(false).await;
}
#[tokio::test]
async fn fatal_accept_latches_shutdown_before_acceptor_drop_can_attempt_exec() {
    assert_owner_teardown_revokes_exec(true).await;
}
