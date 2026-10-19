// Included in session_manager::tests; uses its real transport and manager fixtures.

fn committed_attach(
    conn: Box<Connection>,
    early: Vec<StreamData>,
    queued: Vec<(SocketAddr, Vec<u8>)>,
) -> BridgeControl {
    let (tx, rx) = oneshot::channel();
    tx.send(CommittedAdmission(AuthAcceptance {
        session_id: conn.session_id(),
        disposition: SessionDisposition::Resumed,
    }))
    .unwrap();
    BridgeControl::Attach(conn, early, queued, rx)
}

fn auth17_connection() -> Connection {
    accepted_connection(
        &generate_keypair(),
        [17; 16],
        "127.0.0.1:9".parse().unwrap(),
    )
    .1
}

#[tokio::test]
async fn auth17_warm_control_waits_for_manager_commit_before_any_effect() {
    let mut conn = auth17_connection();
    let old_id = conn.session_id();
    let new_conn = auth17_connection();
    let new_id = new_conn.session_id();
    let (commit_tx, commit_rx) = oneshot::channel();
    let (tx, mut rx) = mpsc::channel(INBOUND_CAP);
    let mut link = BackendLink::new(tx, Consumption::OnDelivery);
    let mut parked = true;
    let mut out = Vec::new();
    let classes = BTreeMap::new();
    let control = BridgeControl::Attach(Box::new(new_conn), vec![], vec![], commit_rx);
    {
        let work = apply_control(
            &mut conn,
            &mut parked,
            &mut link,
            control,
            &classes,
            Instant::now(),
            &mut out,
        );
        tokio::pin!(work);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(work.as_mut().poll(cx).is_pending()))
                .await,
            "a runnable bridge must wait for the manager's commit permission"
        );
        assert!(
            rx.try_recv().is_err(),
            "no reset or application effect before commit"
        );
        commit_tx
            .send(CommittedAdmission(AuthAcceptance {
                session_id: new_id,
                disposition: SessionDisposition::Resumed,
            }))
            .unwrap();
        work.await;
    }
    assert_ne!(old_id, new_id);
    assert_eq!(conn.session_id(), new_id);
    assert!(!parked);
    assert!(matches!(rx.try_recv(), Ok(SessionInbound::ResumeReset(_))));
}

#[tokio::test]
async fn auth17_cancelled_commit_preserves_old_connection_and_backend() {
    let mut conn = auth17_connection();
    let old_id = conn.session_id();
    let (commit_tx, commit_rx) = oneshot::channel();
    drop(commit_tx);
    let (tx, mut rx) = mpsc::channel(INBOUND_CAP);
    let mut link = BackendLink::new(tx, Consumption::OnDelivery);
    let old_generation = link.ledger.generation();
    let mut parked = true;
    let mut out = Vec::new();
    apply_control(
        &mut conn,
        &mut parked,
        &mut link,
        BridgeControl::Attach(Box::new(auth17_connection()), vec![], vec![], commit_rx),
        &BTreeMap::new(),
        Instant::now(),
        &mut out,
    )
    .await;
    assert_eq!(
        conn.session_id(),
        old_id,
        "cancelled admission cannot replace the old connection"
    );
    assert!(parked);
    assert_eq!(link.ledger.generation(), old_generation);
    assert!(rx.try_recv().is_err());
    assert!(out.is_empty());
}
/// Channel wake is synchronous inside send: this deterministically exposes
/// the runnable receiver before the manager has returned from enqueue.
struct Auth17CommitProbe {
    control: Mutex<mpsc::UnboundedReceiver<BridgeControl>>,
    held: Mutex<Option<BridgeControl>>,
    observed: AtomicBool,
    discard: bool,
}

impl std::task::Wake for Auth17CommitProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let Ok(mut control) = self.control.lock().unwrap().try_recv() else {
            return;
        };
        let BridgeControl::Attach(_, _, _, permission) = &mut control;
        assert!(
            matches!(
                permission.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ),
            "enqueue is before route commit and cannot carry permission yet"
        );
        self.observed.store(true, Ordering::SeqCst);
        if !self.discard {
            *self.held.lock().unwrap() = Some(control);
        }
    }
}

#[tokio::test]
async fn auth17_real_manager_releases_permission_after_route_commit_and_handles_receiver_loss() {
    for discard in [false, true] {
        let token = [0x17; 16];
        let helper = HelperLogins::with(token);
        let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
        let mut router = Router::new();
        let (control, _route) = synthetic_live_entry(&mut router, token, 1);
        router.backends.get_mut(&token).unwrap().owner = test_principal().uid;
        let (ended, _socket) =
            a_proof_already_verified(&wiring, &mut router, &mut verdicts, token, StartKind::Warm)
                .await;
        let new_id = ended.session_id;
        let probe = Arc::new(Auth17CommitProbe {
            control: Mutex::new(control),
            held: Mutex::new(None),
            observed: AtomicBool::new(false),
            discard,
        });
        let waker = std::task::Waker::from(probe.clone());
        assert!(probe
            .control
            .lock()
            .unwrap()
            .poll_recv(&mut std::task::Context::from_waker(&waker))
            .is_pending());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert!(
            probe.observed.load(Ordering::SeqCst),
            "receiver ran synchronously during enqueue"
        );
        let entry = &router.backends[&token];
        assert_eq!(entry.session_id, new_id);
        assert!(!router.sessions.contains_key(&1));
        if discard {
            assert!(!router.sessions.contains_key(&new_id));
            assert!(matches!(
                entry.state,
                EntryState::Retained {
                    reason: RetentionReason::UnexpectedDeath,
                    ..
                }
            ));
            assert!(!wiring
                .auth
                .allowlist
                .lock()
                .unwrap()
                .contains(&entry.client_key));
        } else {
            assert!(router.sessions.contains_key(&new_id));
            assert!(matches!(entry.state, EntryState::Live));
            let BridgeControl::Attach(conn, _, _, mut permission) =
                probe.held.lock().unwrap().take().unwrap();
            let accepted = permission.try_recv().unwrap().0;
            assert_eq!(accepted.session_id, new_id);
            assert_eq!(conn.session_id(), new_id);
            assert_eq!(accepted.disposition, SessionDisposition::Resumed);
        }
        assert!(
            helper.opens_channels_for(token),
            "unexpected receiver loss preserves existing login lifecycle"
        );
    }
}

#[test]
fn auth17_initial_auth_credit_queues_record_even_after_peer_advertises_zero() {
    let peer = "127.0.0.1:9".parse().unwrap();
    for disposition in [SessionDisposition::Fresh, SessionDisposition::Resumed] {
        let (mut client, mut conn, msg2) = accepted_connection(&generate_keypair(), [17; 16], peer);
        let now = Instant::now();
        let _ = client.on_datagram(now, peer, &msg2[0].bytes);
        // Create the bidirectional stream via the client proof, then send a
        // lower credit. Neither can revoke the server sender's initial window.
        for dg in client.frames_for_test(vec![
            StreamFrame::Data {
                stream_id: AUTH_STREAM,
                offset: 0,
                data: vec![1],
            },
            StreamFrame::Credit {
                stream_id: AUTH_STREAM,
                limit: 0,
            },
        ]) {
            let _ = conn.on_datagram(now, peer, &dg.bytes);
        }
        let _ = conn.poll_events();
        let record = AuthAcceptance {
            session_id: conn.session_id(),
            disposition,
        };
        let first = CommittedAdmission(record)
            .enqueue(&mut conn, now)
            .expect("initial sender credit admits twelve bytes");
        assert_eq!(conn.stream_progress(AUTH_STREAM).unacked, 12);
        assert!(
            !first.is_empty(),
            "the initial response has ordinary stream data"
        );
        // Lose the first response entirely: reliable transport, not a second
        // application acceptance, owns its retransmission.
        let retransmitted = conn.on_timeout(now + Duration::from_secs(2));
        let mut auth = Vec::new();
        for dg in retransmitted {
            let _ = client.on_datagram(now + Duration::from_secs(2), peer, &dg.bytes);
        }
        for ev in client.poll_events() {
            if let Event::StreamData {
                stream_id: AUTH_STREAM,
                data,
            } = ev
            {
                auth.extend(data);
            }
        }
        assert_eq!(
            crate::auth_acceptance::decode_auth_acceptance(&auth),
            Ok(record)
        );
    }
}

#[test]
fn auth17_commit_descriptor_cannot_queue_acceptance_for_another_transport() {
    let mut conn = auth17_connection();
    let wrong = CommittedAdmission(AuthAcceptance {
        session_id: conn.session_id().wrapping_add(1),
        disposition: SessionDisposition::Fresh,
    });
    assert!(wrong.enqueue(&mut conn, Instant::now()).is_none());
    assert_eq!(conn.stream_progress(AUTH_STREAM).unacked, 0);
}
async fn auth17_receive_acceptance(client: &mut TestClient) -> AuthAcceptance {
    assert!(
        client
            .conn
            .features()
            .contains(crate::Features::AUTH_ACCEPTED),
        "acceptance capability must actually be negotiated"
    );
    let mut parser = crate::auth_acceptance::AuthAcceptanceParser::new(
        client.conn.session_id(),
        client.conn.features(),
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            for event in client.conn.poll_events() {
                if let Event::StreamData { stream_id, data } = event {
                    assert_eq!(
                        stream_id, AUTH_STREAM,
                        "zero-channel admission needs no application traffic"
                    );
                    if let Some(accepted) = parser.feed(&data).unwrap() {
                        return accepted;
                    }
                }
            }
            let (n, source) = client.sock.recv_from(&mut client.buf).await.unwrap();
            let out = client
                .conn
                .on_datagram(Instant::now(), source, &client.buf[..n]);
            send_client(&client.sock, &out).await;
        }
    })
    .await
    .expect("explicit acceptance without a channel OPEN or settling delay")
}

#[tokio::test]
async fn auth17_real_manager_accepts_zero_channel_fresh_and_warm_transports() {
    for method in [AuthMethod::Allowlist, AuthMethod::SshSignature] {
        let key = generate_keypair();
        let spawns = Arc::new(AtomicUsize::new(0));
        let verifier = if method == AuthMethod::SshSignature {
            Some(Arc::new(FakeVerifier::accepting_good()) as Arc<dyn AuthVerifier>)
        } else {
            None
        };
        let server = start_manager(
            Arc::new(CountingEchoBackend {
                spawns: spawns.clone(),
            }),
            vec![key.public],
            verifier,
        )
        .await;
        let mut previous_id = None;
        for (kind, disposition) in [
            (StartKind::Cold, SessionDisposition::Fresh),
            (StartKind::Warm, SessionDisposition::Resumed),
        ] {
            let mut client = TestClient::new(&server, [17; 16], kind, method, key.private).await;
            client.handshake().await;
            if method == AuthMethod::SshSignature {
                if previous_id.is_none() {
                    assert_eq!(
                        spawns.load(Ordering::SeqCst),
                        0,
                        "no backend before signature proof"
                    );
                }
                client.send(AUTH_STREAM, good_record()).await;
            }
            let accepted = auth17_receive_acceptance(&mut client).await;
            assert_eq!(
                accepted,
                AuthAcceptance {
                    session_id: client.conn.session_id(),
                    disposition
                }
            );
            assert_ne!(previous_id, Some(accepted.session_id));
            previous_id = Some(accepted.session_id);
            tokio::time::timeout(Duration::from_secs(1), async {
                while spawns.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                spawns.load(Ordering::SeqCst),
                1,
                "warm admission keeps the original backend"
            );
        }
    }
}

#[test]
fn auth17_congestion_may_defer_datagrams_but_never_initial_record_admission() {
    let mut conn = auth17_connection();
    let now = Instant::now();
    let first = conn.send(now, 0, &vec![0; 64 * 1024]);
    assert!(!first.is_empty());
    let accepted = CommittedAdmission(AuthAcceptance {
        session_id: conn.session_id(),
        disposition: SessionDisposition::Fresh,
    });
    let deferred = accepted
        .enqueue(&mut conn, now)
        .expect("connection congestion does not consume auth stream credit");
    assert!(
        deferred.is_empty(),
        "fixture filled congestion window before the auth write"
    );
    assert_eq!(conn.stream_progress(AUTH_STREAM).unacked, 12);
}

struct Auth17ColdProbe {
    prior: BindingRevision,
    called: Arc<AtomicBool>,
}
impl SessionBackend for Auth17ColdProbe {
    fn consumption(&self) -> Consumption {
        assert!(
            !self.prior.is_current(),
            "a runnable cold bridge cannot invoke its backend before registration commits"
        );
        self.called.store(true, Ordering::SeqCst);
        Consumption::OnDelivery
    }
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move { while io.recv().await.is_some() {} })
    }
}

#[tokio::test]
async fn auth17_cold_bridge_cannot_run_before_registration_commit() {
    struct ResetInline;
    impl Drop for ResetInline {
        fn drop(&mut self) {
            POLL_COLD_BRIDGE_INLINE.with(|flag| flag.set(false));
        }
    }
    let token = [0x18; 16];
    let helper = HelperLogins::with(token);
    let (mut wiring, mut verdicts) = RouterWiring::new(helper).await;
    let mut router = Router::new();
    let (ended, _socket) =
        a_proof_already_verified(&wiring, &mut router, &mut verdicts, token, StartKind::Cold).await;
    let session_id = ended.session_id;
    let prior = ended.revision.clone();
    assert!(prior.is_current());
    let called = Arc::new(AtomicBool::new(false));
    wiring.factory = BackendFactory(Arc::new(Auth17ColdProbe {
        prior,
        called: called.clone(),
    }));
    // Force the first bridge poll synchronously at the actual spawn call,
    // independent of executor scheduling. The same future is then scheduled.
    POLL_COLD_BRIDGE_INLINE.with(|flag| flag.set(true));
    let _reset = ResetInline;
    SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
    assert!(
        called.load(Ordering::SeqCst),
        "the bridge was runnable at the spawn seam"
    );
    assert_eq!(router.backends[&token].session_id, session_id);
    assert!(router.sessions.contains_key(&session_id));
}

#[tokio::test]
async fn auth17_failed_warm_enqueue_reports_fresh_despite_tentative_resumed_hint() {
    let token = [0xF1; 16];
    let helper = HelperLogins::with(token);
    let (wiring, mut verdicts) = RouterWiring::new(helper.clone()).await;
    let mut router = Router::new();
    let (control, _route) = synthetic_live_entry(&mut router, token, 1);
    router.backends.get_mut(&token).unwrap().owner = test_principal().uid;
    let (ended, sock, conn) =
        a_proof_with_client(&wiring, &mut router, &mut verdicts, token, StartKind::Warm).await;
    assert!(
        conn.resumed(),
        "msg2 tentatively found the old retained backend"
    );
    drop(control); // Already disconnected: manager still owns the complete envelope.
    let session_id = ended.session_id;
    SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
    assert_eq!(router.backends[&token].session_id, session_id);
    let mut client = TestClient {
        conn,
        sock,
        server_addr: wiring.socket.local_addr().unwrap(),
        token,
        start_kind: StartKind::Warm,
        method: AuthMethod::SshSignature,
        buf: vec![0; RECV_BUF_LEN],
        inbox: Default::default(),
        legacy: false,
    };
    assert_eq!(
        auth17_receive_acceptance(&mut client).await,
        AuthAcceptance {
            session_id,
            disposition: SessionDisposition::Fresh,
        }
    );
    assert!(
        helper.opens_channels_for(token),
        "fallback keeps the proven helper login"
    );
}
