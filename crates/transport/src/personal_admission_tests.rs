// Real Noise packets drive the existing manager/probation boundary. These
// observers record transport evidence; they never substitute for host policy.
mod personal529 {
    use super::*;
    use crate::personal_admission::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct Counts {
        began: AtomicUsize,
        completed: AtomicUsize,
        cancelled: AtomicUsize,
    }
    struct Observer {
        counts: Arc<Counts>,
        refuse: bool,
    }
    struct Attempt {
        binding: PersonalBinding,
        counts: Arc<Counts>,
        done: bool,
    }
    impl Drop for Attempt {
        fn drop(&mut self) {
            if !self.done {
                self.counts.cancelled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    impl PersonalAdmissionObserver for Observer {
        fn try_begin(
            &self,
            binding: PersonalBinding,
        ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused> {
            if self.refuse {
                return Err(Refused);
            }
            self.counts.began.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Attempt {
                binding,
                counts: self.counts.clone(),
                done: false,
            }))
        }
    }
    impl PersonalAdmissionAttempt for Attempt {
        fn try_complete(
            mut self: Box<Self>,
            proof: PersonalPossessionCompletion,
        ) -> Result<(), Refused> {
            assert!(proof.matches(&self.binding));
            self.done = true;
            self.counts.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    async fn begin(
        wiring: &RouterWiring,
        router: &mut Router,
        key: &crate::handshake::Keypair,
        token: [u8; 16],
    ) -> (UdpSocket, Connection, Vec<u8>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = socket.local_addr().unwrap();
        let server = wiring.socket.local_addr().unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::Allowlist(vec![wiring.server_pub]),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token,
            method: AuthMethod::Allowlist,
        });
        let msg1 = client
            .start_with_payload(Instant::now(), server, &payload)
            .remove(0)
            .bytes;
        SessionManager::handle_datagram(&wiring.ctx(), router, msg1.len(), src, &msg1).await;
        let mut buf = vec![0; RECV_BUF_LEN];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        client.on_datagram(Instant::now(), from, &buf[..n]);
        (socket, client, msg1)
    }
    async fn prove(
        wiring: &RouterWiring,
        router: &mut Router,
        socket: &UdpSocket,
        client: &mut Connection,
        frames: Vec<crate::reliability::StreamFrame>,
    ) {
        for packet in [client.packed_for_test(frames)] {
            SessionManager::handle_datagram(
                &wiring.ctx(),
                router,
                packet.bytes.len(),
                socket.local_addr().unwrap(),
                &packet.bytes,
            )
            .await;
        }
    }
    async fn settle(wiring: &RouterWiring, router: &mut Router) {
        router.probation.clear();
        router.sessions.clear();
        router.backends.clear();
        wiring.lifecycle.drain().await.unwrap();
    }
    async fn rig(
        refuse: bool,
    ) -> (
        RouterWiring,
        mpsc::UnboundedReceiver<ProbationEnded>,
        Router,
        crate::handshake::Keypair,
        Arc<Counts>,
    ) {
        let (mut wiring, rx) = RouterWiring::new(HelperLogins::with([0; 16])).await;
        wiring.auth.verifier = None;
        let key = generate_keypair();
        wiring.auth.allowlist.lock().unwrap().push(key.public);
        let counts = Arc::new(Counts::default());
        let mut router = Router::new();
        router.personal_observer = Some(Arc::new(Observer {
            counts: counts.clone(),
            refuse,
        }));
        (wiring, rx, router, key, counts)
    }
    #[tokio::test]
    async fn personal529_msg1_reserves_but_cannot_complete_without_fresh_packet() {
        let (wiring, _rx, mut router, key, c) = rig(false).await;
        let (_socket, _client, _msg1) = begin(&wiring, &mut router, &key, [1; 16]).await;
        assert_eq!(c.began.load(Ordering::SeqCst), 1);
        assert_eq!(c.completed.load(Ordering::SeqCst), 0);
        settle(&wiring, &mut router).await;
        assert_eq!(c.cancelled.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn personal529_real_packet_mints_once_and_cached_msg1_never_mints_again() {
        let (wiring, mut rx, mut router, key, c) = rig(false).await;
        let (socket, mut client, msg1) = begin(&wiring, &mut router, &key, [2; 16]).await;
        prove(
            &wiring,
            &mut router,
            &socket,
            &mut client,
            vec![crate::reliability::StreamFrame::Ping { token: 1 }],
        )
        .await;
        let ended = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ended.proven.is_some());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert_eq!(c.completed.load(Ordering::SeqCst), 1);
        SessionManager::handle_datagram(
            &wiring.ctx(),
            &mut router,
            msg1.len(),
            socket.local_addr().unwrap(),
            &msg1,
        )
        .await;
        assert_eq!(c.began.load(Ordering::SeqCst), 1);
        assert_eq!(c.completed.load(Ordering::SeqCst), 1);
        settle(&wiring, &mut router).await;
    }
    #[tokio::test]
    async fn personal529_close_same_real_packet_refuses_and_cancels_ticket() {
        let (wiring, mut rx, mut router, key, c) = rig(false).await;
        let (socket, mut client, _) = begin(&wiring, &mut router, &key, [3; 16]).await;
        prove(
            &wiring,
            &mut router,
            &socket,
            &mut client,
            vec![
                crate::reliability::StreamFrame::Ping { token: 1 },
                crate::reliability::StreamFrame::Close { stream_id: 0 },
            ],
        )
        .await;
        let ended = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ended.proven.is_none());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert_eq!(c.completed.load(Ordering::SeqCst), 0);
        assert_eq!(c.cancelled.load(Ordering::SeqCst), 1);
        settle(&wiring, &mut router).await;
    }
    #[tokio::test]
    async fn personal529_revocation_stale_revision_and_missing_route_refuse_real_proof() {
        for mode in 0..3 {
            let (wiring, mut rx, mut router, key, c) = rig(false).await;
            let (socket, mut client, _) = begin(&wiring, &mut router, &key, [4; 16]).await;
            prove(
                &wiring,
                &mut router,
                &socket,
                &mut client,
                vec![crate::reliability::StreamFrame::Ping { token: 1 }],
            )
            .await;
            let ended = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(ended.proven.is_some());
            match mode {
                0 => wiring.auth.allowlist.lock().unwrap().clear(),
                1 => router.revisions.invalidate([4; 16]),
                _ => {
                    router.sessions.remove(&ended.session_id);
                }
            }
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
            assert_eq!(c.completed.load(Ordering::SeqCst), 0);
            assert_eq!(c.cancelled.load(Ordering::SeqCst), 1);
            assert!(router.backends.is_empty());
            settle(&wiring, &mut router).await;
        }
    }
    #[tokio::test]
    async fn personal529_observer_refusal_has_no_probation_route_or_backend() {
        let (wiring, _rx, mut router, key, c) = rig(true).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::Allowlist(vec![wiring.server_pub]),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [5; 16],
            method: AuthMethod::Allowlist,
        });
        let dg = client
            .start_with_payload(
                Instant::now(),
                wiring.socket.local_addr().unwrap(),
                &payload,
            )
            .remove(0);
        SessionManager::handle_datagram(
            &wiring.ctx(),
            &mut router,
            dg.bytes.len(),
            socket.local_addr().unwrap(),
            &dg.bytes,
        )
        .await;
        assert!(
            router.probation.is_empty() && router.sessions.is_empty() && router.backends.is_empty()
        );
        assert_eq!(c.completed.load(Ordering::SeqCst), 0);
        settle(&wiring, &mut router).await;
    }
    #[tokio::test]
    async fn personal529_excess_early_data_same_packet_cancels_without_completion() {
        let (wiring, mut rx, mut router, key, c) = rig(false).await;
        let (socket, mut client, _) = begin(&wiring, &mut router, &key, [6; 16]).await;
        let frames = (0..64)
            .map(|i| crate::reliability::StreamFrame::Data {
                stream_id: 16,
                offset: i * 1000,
                data: vec![1; 1000],
            })
            .collect();
        prove(&wiring, &mut router, &socket, &mut client, frames).await;
        let ended = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ended.proven.is_none());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert_eq!(c.completed.load(Ordering::SeqCst), 0);
        assert_eq!(c.cancelled.load(Ordering::SeqCst), 1);
        settle(&wiring, &mut router).await;
    }
    #[tokio::test(start_paused = true)]
    async fn personal529_timeout_retires_ticket_and_actual_probation_task() {
        let (wiring, mut rx, mut router, key, c) = rig(false).await;
        let (_socket, _client, _) = begin(&wiring, &mut router, &key, [7; 16]).await;
        tokio::time::advance(crate::auth::AUTH_DEADLINE + Duration::from_secs(1)).await;
        let ended = rx.recv().await.unwrap();
        assert!(ended.proven.is_none());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert_eq!(c.completed.load(Ordering::SeqCst), 0);
        assert_eq!(c.cancelled.load(Ordering::SeqCst), 1);
        settle(&wiring, &mut router).await;
    }

    #[tokio::test]
    async fn personal529_manager_shutdown_joins_probation_and_drops_only_its_ticket() {
        let server = generate_keypair();
        let key = generate_keypair();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let counts = Arc::new(Counts::default());
        let observer = Arc::new(Observer {
            counts: counts.clone(),
            refuse: false,
        });
        let stop = Shutdown::default();
        let task = tokio::spawn(SessionManager::serve_with_personal_admission(
            socket,
            server.private,
            allowlist_auth(Arc::new(Mutex::new(vec![key.public])), server.public),
            BackendFactory(Arc::new(EchoBackend)),
            Arc::new(AtomicUsize::new(0)),
            LoginEndedReports::none(),
            stop.clone(),
            None,
            Some(observer),
        ));
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(vec![server.public]),
        });
        let payload = encode_msg1(&Msg1Payload {
            offered: crate::Features::SUPPORTED,
            start_kind: StartKind::Cold,
            token: [8; 16],
            method: AuthMethod::Allowlist,
        });
        for packet in client.start_with_payload(Instant::now(), addr, &payload) {
            client_socket
                .send_to(&packet.bytes, packet.to)
                .await
                .unwrap();
        }
        let mut buf = vec![0; RECV_BUF_LEN];
        tokio::time::timeout(Duration::from_secs(2), client_socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.began.load(Ordering::SeqCst), 1);
        stop.request();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
        assert_eq!(counts.cancelled.load(Ordering::SeqCst), 1);
    }
    #[derive(Default)]
    struct Capture(Mutex<Vec<(PersonalBinding, PersonalPossessionCompletion)>>);
    struct CapturingAttempt {
        binding: PersonalBinding,
        sink: Arc<Capture>,
    }
    struct CapturingObserver(Arc<Capture>);
    impl PersonalAdmissionObserver for CapturingObserver {
        fn try_begin(
            &self,
            binding: PersonalBinding,
        ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused> {
            Ok(Box::new(CapturingAttempt {
                binding,
                sink: self.0.clone(),
            }))
        }
    }
    impl PersonalAdmissionAttempt for CapturingAttempt {
        fn try_complete(
            self: Box<Self>,
            proof: PersonalPossessionCompletion,
        ) -> Result<(), Refused> {
            assert!(proof.matches(&self.binding));
            self.sink.0.lock().unwrap().push((self.binding, proof));
            Ok(())
        }
    }
    #[tokio::test]
    async fn personal529_fresh_same_key_completions_cannot_match_another_ticket_or_stale_revision()
    {
        let (wiring, mut rx, mut router, key, _) = rig(false).await;
        let captured = Arc::new(Capture::default());
        router.personal_observer = Some(Arc::new(CapturingObserver(captured.clone())));
        let _old = captured_allowlist_connection(
            &wiring,
            &mut router,
            &mut rx,
            key.private,
            [9; 16],
            StartKind::Cold,
        )
        .await;
        let _new = captured_allowlist_connection(
            &wiring,
            &mut router,
            &mut rx,
            key.private,
            [9; 16],
            StartKind::Warm,
        )
        .await;
        {
            let records = captured.0.lock().unwrap();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].0.client_key(), records[1].0.client_key());
            assert!(!records[0].1.matches(&records[1].0));
            assert!(!records[1].1.matches(&records[0].0));
            assert!(!records[0].0.is_current());
        }
        settle(&wiring, &mut router).await;
    }
    struct RefusingObserver;
    struct RefusingAttempt(PersonalBinding);
    impl PersonalAdmissionObserver for RefusingObserver {
        fn try_begin(
            &self,
            binding: PersonalBinding,
        ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused> {
            Ok(Box::new(RefusingAttempt(binding)))
        }
    }
    impl PersonalAdmissionAttempt for RefusingAttempt {
        fn try_complete(
            self: Box<Self>,
            proof: PersonalPossessionCompletion,
        ) -> Result<(), Refused> {
            assert!(proof.matches(&self.0));
            Err(Refused)
        }
    }
    #[tokio::test]
    async fn personal529_refused_completion_preserves_the_existing_backend_and_route() {
        let (wiring, mut rx, mut router, key, _) = rig(false).await;
        let _old = captured_allowlist_connection(
            &wiring,
            &mut router,
            &mut rx,
            key.private,
            [10; 16],
            StartKind::Cold,
        )
        .await;
        let old = router.backends[&[10; 16]].session_id;
        router.personal_observer = Some(Arc::new(RefusingObserver));
        let (socket, mut client, _) = begin(&wiring, &mut router, &key, [10; 16]).await;
        prove(
            &wiring,
            &mut router,
            &socket,
            &mut client,
            vec![crate::reliability::StreamFrame::Ping { token: 1 }],
        )
        .await;
        let ended = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ended.proven.is_some());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, ended).await;
        assert_eq!(router.backends[&[10; 16]].session_id, old);
        assert!(router.sessions.contains_key(&old));
        assert!(!router.sessions.contains_key(&client.session_id()));
        assert!(wiring.auth.allowlist.lock().unwrap().contains(&key.public));
        settle(&wiring, &mut router).await;
    }
}
