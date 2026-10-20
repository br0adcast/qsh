// Full router -> real probation -> committed bridge adoption, with generated
// Noise keys, owned UDP sockets and a child-free echo backend.
async fn source135_admitted_roaming(method: AuthMethod) {
    let token = [135; 16];
    let helper = HelperLogins::with(token);
    let (mut wiring, mut verdicts) = RouterWiring::new(helper).await;
    let key = generate_keypair();
    wiring.auth.allowlist.lock().unwrap().push(key.public);
    let spawned = Arc::new(AtomicUsize::new(0));
    wiring.factory = BackendFactory(Arc::new(CountingEchoBackend {
        spawns: spawned.clone(),
    }));
    let mut router = Router::new();
    let result: Result<(), String> = async {
        for round in 0..2u8 {
            let initial = UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let migrated = UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let source = initial.local_addr().map_err(|e| e.to_string())?;
            let other = migrated.local_addr().map_err(|e| e.to_string())?;
            let server = wiring.socket.local_addr().map_err(|e| e.to_string())?;
            let mut client = Connection::new(ConnectionConfig {
                required_features: crate::Features::AUTH_ACCEPTED,
                features: crate::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: key.private,
                remote_static_pub: Some(wiring.server_pub),
                auth: match method {
                    AuthMethod::Allowlist => AuthPolicy::Allowlist(vec![wiring.server_pub]),
                    AuthMethod::SshSignature => AuthPolicy::SshSignature,
                },
            });
            let payload = encode_msg1(&Msg1Payload {
                offered: crate::Features::SUPPORTED,
                start_kind: if round == 0 {
                    StartKind::Cold
                } else {
                    StartKind::Warm
                },
                token,
                method,
            });
            let msg1 = client
                .start_with_payload(Instant::now(), server, &payload)
                .remove(0);
            SessionManager::handle_datagram(
                &wiring.ctx(),
                &mut router,
                msg1.bytes.len(),
                source,
                &msg1.bytes,
            )
            .await;
            let mut buffer = [0; RECV_BUF_LEN];
            let (len, from) =
                tokio::time::timeout(Duration::from_secs(2), initial.recv_from(&mut buffer))
                    .await
                    .map_err(|_| "no actual msg2".to_string())?
                    .map_err(|e| e.to_string())?;
            let mut proof = client.on_datagram(Instant::now(), from, &buffer[..len]);
            // A valid throwaway-key packet from B cannot select B before
            // admission; it precedes the real A proof in the actual route.
            let attempted = client
                .frames_for_test(vec![crate::reliability::StreamFrame::Ping { token: 135 }])
                .remove(0);
            SessionManager::handle_datagram(
                &wiring.ctx(),
                &mut router,
                attempted.bytes.len(),
                other,
                &attempted.bytes,
            )
            .await;
            if matches!(method, AuthMethod::SshSignature) {
                proof.extend(
                    client.send(
                        Instant::now(),
                        AUTH_STREAM,
                        &encode_auth_record(&AuthRecord {
                            public_key: b"key".to_vec(),
                            signature: b"good".to_vec(),
                            v2: None,
                        })
                        .map_err(|e| e.to_string())?,
                    ),
                );
            }
            client.request_ping(Instant::now());
            proof.extend(client.on_timeout(Instant::now()));
            for dg in proof {
                SessionManager::handle_datagram(
                    &wiring.ctx(),
                    &mut router,
                    dg.bytes.len(),
                    source,
                    &dg.bytes,
                )
                .await;
            }
            let verdict = tokio::time::timeout(Duration::from_secs(2), verdicts.recv())
                .await
                .map_err(|_| "no genuine probation completion".to_string())?
                .ok_or("verdict channel closed")?;
            if verdict.proven.as_ref().map(|p| p.conn.peer()) != Some(Some(source)) {
                return Err("other source changed probation peer or proof did not succeed".into());
            }
            // Hold the actual proven result while B's application packet
            // enters the provisional route. Both adoption paths must lift
            // source binding BEFORE processing this queued packet.
            let expected = vec![b'R', round, 135];
            for dg in client.send(Instant::now(), 0, &expected) {
                SessionManager::handle_datagram(
                    &wiring.ctx(),
                    &mut router,
                    dg.bytes.len(),
                    other,
                    &dg.bytes,
                )
                .await;
            }
            SessionManager::on_probation_ended(&wiring.ctx(), &mut router, verdict).await;
            if router.backends.get(&token).map(|entry| entry.session_id)
                != Some(client.session_id())
            {
                return Err("committed router did not adopt candidate".into());
            }
            let echoed = tokio::time::timeout(Duration::from_secs(2), async {
                let mut bytes = Vec::new();
                loop {
                    let (len, from) = migrated
                        .recv_from(&mut buffer)
                        .await
                        .map_err(|e| e.to_string())?;
                    let out = client.on_datagram(Instant::now(), from, &buffer[..len]);
                    for dg in out {
                        SessionManager::handle_datagram(
                            &wiring.ctx(),
                            &mut router,
                            dg.bytes.len(),
                            other,
                            &dg.bytes,
                        )
                        .await;
                    }
                    for event in client.poll_events() {
                        if let Event::StreamData { stream_id: 0, data } = event {
                            bytes.extend(data);
                        }
                    }
                    if bytes.len() >= expected.len() {
                        return Ok::<_, String>(bytes);
                    }
                }
            })
            .await
            .map_err(|_| "no backend echo on admitted new source".to_string())??;
            if echoed != expected {
                return Err("admitted roaming changed actual backend bytes".into());
            }
            // A probe answer from probation would still be waiting on B here
            // but cannot make this application-data oracle pass.
        }
        if spawned.load(Ordering::SeqCst) != 1 {
            return Err("warm attach replaced backend".into());
        }
        Ok(())
    }
    .await;
    wiring.lifecycle.shutdown.request();
    let drained = wiring.lifecycle.drain().await;
    assert!(drained.is_ok(), "owned manager tasks drained: {drained:?}");
    assert!(wiring.lifecycle.is_empty());
    assert!(
        result.is_ok(),
        "actual new/warm admission roaming: {result:?}"
    );
}

#[tokio::test]
async fn source135_real_allowlist_new_and_warm_adoption_restore_roaming() {
    source135_admitted_roaming(AuthMethod::Allowlist).await;
}

#[tokio::test]
async fn source135_real_signature_new_and_warm_adoption_restore_roaming() {
    source135_admitted_roaming(AuthMethod::SshSignature).await;
}
