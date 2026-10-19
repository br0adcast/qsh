// Included in session_manager::tests. These exercise real probation/admission
// owners with a manually pumped shared Connection. Driver signer ownership is
// independently covered in driver_std_recovery_tests.rs.

#[tokio::test]
async fn shared_recovery_real_managers_leave_delayed_loser_backend_and_route_untouched() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for start_kind in [StartKind::Warm, StartKind::Cold] {
            for signature in [false, true] {
                let token = [0x16; 16];
                let key = generate_keypair();
                let (mut a, mut verdict_a) = RouterWiring::new(HelperLogins::with(token)).await;
                let (mut b, mut verdict_b) = RouterWiring::new(HelperLogins::with(token)).await;
                // Independent daemon instances intentionally share a server key.
                b.server_priv = a.server_priv;
                b.server_pub = a.server_pub;
                b.auth.server_pub = a.server_pub;
                let spawns = Arc::new(AtomicUsize::new(0));
                let teardowns = Arc::new(AtomicUsize::new(0));
                for wiring in [&mut a, &mut b] {
                    wiring.auth.self_principal = test_principal();
                    wiring.auth.allowlist.lock().unwrap().push(key.public);
                    wiring.factory = BackendFactory(Arc::new(TeardownCountingBackend {
                        spawns: spawns.clone(),
                        teardowns: teardowns.clone(),
                    }));
                }
                let mut router_a = Router::new();
                let mut router_b = Router::new();
                let (_old_a, _, _) = captured_allowlist_connection(
                    &a,
                    &mut router_a,
                    &mut verdict_a,
                    key.private,
                    token,
                    StartKind::Cold,
                )
                .await;
                let (_old_b, _, _) = captured_allowlist_connection(
                    &b,
                    &mut router_b,
                    &mut verdict_b,
                    key.private,
                    token,
                    StartKind::Cold,
                )
                .await;
                let old_a = router_a.backends[&token].session_id;
                let old_control_a = router_a.backends[&token].control.clone();
                let old_b = router_b.backends[&token].session_id;
                let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let src = source.local_addr().unwrap();
                let addr_a = a.socket.local_addr().unwrap();
                let addr_b = b.socket.local_addr().unwrap();
                let mut client = Connection::new(ConnectionConfig {
                    role: Role::Client,
                    local_static_priv: key.private,
                    remote_static_pub: Some(a.server_pub),
                    auth: if signature {
                        AuthPolicy::SshSignature
                    } else {
                        AuthPolicy::Allowlist(Vec::new())
                    },
                    features: crate::Features::SUPPORTED,
                    required_features: crate::Features::AUTH_ACCEPTED,
                });
                let outgoing = client.start_recovery(
                    Instant::now(),
                    vec![
                        crate::recovery_handshake::RecoveryEndpoint {
                            address: 0,
                            endpoint: addr_a,
                        },
                        crate::recovery_handshake::RecoveryEndpoint {
                            address: 1,
                            endpoint: addr_b,
                        },
                    ],
                    start_kind,
                    token,
                );
                assert_eq!(outgoing.len(), 2);
                assert_eq!(outgoing[0].bytes, outgoing[1].bytes);
                let mut responses = HashMap::new();
                let mut buf = vec![0; RECV_BUF_LEN];
                for datagram in outgoing {
                    client.recovery_handshake_sent(Instant::now(), datagram.to, true);
                    let (wiring, router) = if datagram.to == addr_a {
                        (&a, &mut router_a)
                    } else {
                        (&b, &mut router_b)
                    };
                    SessionManager::handle_datagram(
                        &wiring.ctx(),
                        router,
                        datagram.bytes.len(),
                        src,
                        &datagram.bytes,
                    )
                    .await;
                    let (len, from) = source.recv_from(&mut buf).await.unwrap();
                    assert_eq!(from, datagram.to);
                    responses.insert(from, buf[..len].to_vec());
                }
                assert_eq!(router_a.probation.len(), 1);
                assert_eq!(router_b.probation.len(), 1);
                let losing_id = *router_a.probation.keys().next().unwrap();
                let mut proof = client.on_datagram(Instant::now(), addr_b, &responses[&addr_b]);
                if signature {
                    proof.extend(client.send(Instant::now(), AUTH_STREAM, &good_record()));
                } else {
                    client.request_ping(Instant::now());
                    proof.extend(client.on_timeout(Instant::now()));
                }
                assert!(!proof.is_empty());
                for datagram in proof {
                    // The selected transport may probe a spare physical path;
                    // those packets still belong exclusively to its key split.
                    assert!(matches!(parse(&datagram.bytes), Ok(Frame::Transport { session_id, .. }) if session_id == client.session_id()));
                    let (wiring, router) = if datagram.to == addr_b {
                        (&b, &mut router_b)
                    } else {
                        assert_eq!(datagram.to, addr_a);
                        (&a, &mut router_a)
                    };
                    SessionManager::handle_datagram(
                        &wiring.ctx(), router, datagram.bytes.len(), src, &datagram.bytes,
                    ).await;
                }
                let selected = verdict_b.recv().await.unwrap();
                assert!(selected.proven.is_some());
                SessionManager::on_probation_ended(&b.ctx(), &mut router_b, selected).await;
                assert_eq!(router_b.backends[&token].session_id, client.session_id());
                assert_ne!(
                    client.session_id(),
                    old_b,
                    "the winning manager really committed"
                );
                for _ in 0..3 {
                    assert!(
                        client
                            .on_datagram(Instant::now(), addr_a, &responses[&addr_a])
                            .is_empty(),
                        "late losing msg2 cannot produce AUTH or a possession proof"
                    );
                }
                assert_eq!(client.active_path(), Some(addr_b));
                assert_eq!(router_a.backends[&token].session_id, old_a);
                assert!(router_a.backends[&token]
                    .control
                    .same_channel(&old_control_a));
                assert!(router_a.sessions.contains_key(&old_a));
                assert_eq!(router_a.backends.len(), 1);
                assert_eq!(*a.auth.allowlist.lock().unwrap(), vec![key.public]);
                assert!(matches!(
                    verdict_a.try_recv(),
                    Err(mpsc::error::TryRecvError::Empty)
                ));

                // Close the loser's exact provisional route and await its task's
                // verdict. Runtime teardown is not our cleanup oracle.
                router_a.sessions.remove(&losing_id);
                let loser = verdict_a.recv().await.unwrap();
                assert_eq!(loser.session_id, losing_id);
                assert!(loser.proven.is_none());
                SessionManager::on_probation_ended(&a.ctx(), &mut router_a, loser).await;
                assert!(router_a.probation.is_empty());
                assert_eq!(router_a.backends[&token].session_id, old_a);
                assert!(router_a.backends[&token]
                    .control
                    .same_channel(&old_control_a));
                assert!(router_a.sessions.contains_key(&old_a));
                drop(old_control_a);
                drop(router_a);
                drop(router_b);
                let expected = if start_kind == StartKind::Cold { 3 } else { 2 };
                while teardowns.load(Ordering::SeqCst) < expected {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(spawns.load(Ordering::SeqCst), expected);
                assert_eq!(teardowns.load(Ordering::SeqCst), expected);
            }
        }
    })
    .await
    .expect("bounded real-manager shared recovery acceptance");
}

#[tokio::test]
async fn shared_recovery_real_manager_moves_over_an_authenticated_alias_without_reattach() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let token = [0x61; 16];
        let key = generate_keypair();
        let (mut wiring, mut verdicts) = RouterWiring::new(HelperLogins::with(token)).await;
        let spawns = Arc::new(AtomicUsize::new(0));
        let teardowns = Arc::new(AtomicUsize::new(0));
        wiring.factory = BackendFactory(Arc::new(TeardownCountingBackend {
            spawns: spawns.clone(),
            teardowns: teardowns.clone(),
        }));
        wiring.auth.allowlist.lock().unwrap().push(key.public);
        let mut router = Router::new();
        let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alias = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let src = source.local_addr().unwrap();
        let server = wiring.socket.local_addr().unwrap();
        let road = alias.local_addr().unwrap();
        let mut client = Connection::new(ConnectionConfig {
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
            features: crate::Features::SUPPORTED,
            required_features: crate::Features::AUTH_ACCEPTED,
        });
        let initial = client.start_recovery(
            Instant::now(),
            vec![
                crate::recovery_handshake::RecoveryEndpoint {
                    address: 0,
                    endpoint: server,
                },
                crate::recovery_handshake::RecoveryEndpoint {
                    address: 1,
                    endpoint: road,
                },
            ],
            StartKind::Warm,
            token,
        );
        // The alias is initially silent; this still uses the shared initiator.
        for datagram in initial {
            client.recovery_handshake_sent(Instant::now(), datagram.to, true);
            if datagram.to == server {
                SessionManager::handle_datagram(
                    &wiring.ctx(),
                    &mut router,
                    datagram.bytes.len(),
                    src,
                    &datagram.bytes,
                )
                .await;
            }
        }
        let mut buf = vec![0; RECV_BUF_LEN];
        let (len, from) = source.recv_from(&mut buf).await.unwrap();
        let mut out = client.on_datagram(Instant::now(), from, &buf[..len]);
        client.request_ping(Instant::now());
        out.extend(client.on_timeout(Instant::now()));
        for datagram in out {
            if datagram.to == server {
                SessionManager::handle_datagram(
                    &wiring.ctx(),
                    &mut router,
                    datagram.bytes.len(),
                    src,
                    &datagram.bytes,
                )
                .await;
            }
        }
        let admission = verdicts.recv().await.unwrap();
        assert!(admission.proven.is_some());
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, admission).await;
        let id = client.session_id();
        let control = router.backends[&token].control.clone();
        let mut accepted = Vec::new();
        while accepted.len() < crate::auth_acceptance::AUTH_ACCEPTANCE_LEN {
            let (len, from) = source.recv_from(&mut buf).await.unwrap();
            let out = client.on_datagram(Instant::now(), from, &buf[..len]);
            for datagram in out {
                SessionManager::handle_datagram(
                    &wiring.ctx(),
                    &mut router,
                    datagram.bytes.len(),
                    src,
                    &datagram.bytes,
                )
                .await;
            }
            for event in client.poll_events() {
                if let Event::StreamData {
                    stream_id: AUTH_STREAM,
                    data,
                } = event
                {
                    accepted.extend(data);
                }
            }
        }
        assert_eq!(
            crate::auth_acceptance::decode_auth_acceptance(&accepted)
                .unwrap()
                .session_id,
            id
        );
        client.stop_recovery_handshake();
        // Publish the newly available alias as a new path catalog. Its earlier
        // silent check must not be mistaken for a freshly scheduled query.
        client.set_paths(Vec::new());
        client.set_paths(vec![server, road]);
        let mut moved = false;
        let mut received = Vec::new();
        loop {
            let now = Instant::now();
            let mut out = client.on_timeout(now);
            if !moved
                && client
                    .roads(now)
                    .iter()
                    .any(|r| r.addr == road && r.state == PathState::Verified)
            {
                client.use_road(road, now).unwrap();
                out.extend(client.send(now, 0, b"same authenticated backend"));
                moved = true;
            }
            for datagram in out {
                assert!(
                    !matches!(parse(&datagram.bytes), Ok(Frame::Handshake { .. })),
                    "alias movement cannot open a new handshake"
                );
                if datagram.to == road {
                    // Owned UDP relay: receive actual client traffic at the alias,
                    // then dispatch it to this same manager's established route.
                    source.send_to(&datagram.bytes, road).await.unwrap();
                    let (len, from) = alias.recv_from(&mut buf).await.unwrap();
                    assert_eq!(from, src);
                    SessionManager::handle_datagram(
                        &wiring.ctx(),
                        &mut router,
                        len,
                        src,
                        &buf[..len],
                    )
                    .await;
                } else {
                    assert_eq!(datagram.to, server);
                    SessionManager::handle_datagram(
                        &wiring.ctx(),
                        &mut router,
                        datagram.bytes.len(),
                        src,
                        &datagram.bytes,
                    )
                    .await;
                }
            }
            if let Ok(Ok((len, from))) =
                tokio::time::timeout(Duration::from_millis(20), source.recv_from(&mut buf)).await
            {
                if from == server {
                    // Relay each packet separately. More server packets may
                    // already be queued ahead of this relayed copy.
                    alias.send_to(&buf[..len], src).await.unwrap();
                    continue;
                }
                assert_eq!(from, road);
                for datagram in client.on_datagram(Instant::now(), from, &buf[..len]) {
                    SessionManager::handle_datagram(
                        &wiring.ctx(),
                        &mut router,
                        datagram.bytes.len(),
                        src,
                        &datagram.bytes,
                    )
                    .await;
                }
                for event in client.poll_events() {
                    if let Event::StreamData { stream_id: 0, data } = event {
                        received.extend(data);
                    }
                }
            }
            if received == b"same authenticated backend" {
                break;
            }
        }
        assert!(moved);
        assert_eq!(client.active_path(), Some(road));
        assert_eq!(client.session_id(), id);
        assert_eq!(router.backends[&token].session_id, id);
        assert!(router.backends[&token].control.same_channel(&control));
        assert!(router.probation.is_empty());
        // Drop both routes/control owners and await the bridge/backend completion.
        drop(control);
        drop(router);
        let mut ended = wiring._done_rx;
        assert_eq!(ended.recv().await.unwrap().session_id, id);
        while teardowns.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(spawns.load(Ordering::SeqCst), 1);
        assert_eq!(teardowns.load(Ordering::SeqCst), 1);
    })
    .await
    .expect("bounded authenticated alias movement");
}
