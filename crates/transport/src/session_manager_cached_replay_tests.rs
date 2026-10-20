// These controls drive real Noise messages through manager probation and policy.
// The signature policy uses the existing deterministic verifier, not SSH crypto.
#[derive(Default)]
struct ReplayNonces {
    tracking: TrackingNonces,
    fail: std::sync::atomic::AtomicBool,
    issues: AtomicUsize,
    releases: AtomicUsize,
}

impl NonceSource for ReplayNonces {
    fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
        self.issues.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err("controlled unavailable nonce source".into())
        } else {
            self.tracking.issue()
        }
    }

    fn release(&self, nonce: [u8; AUTH_NONCE_LEN]) {
        self.releases.fetch_add(1, Ordering::SeqCst);
        self.tracking.release(nonce);
    }
}

async fn cached_replay_after_real_admission(signature: bool, cookie_gate: bool) {
    let mut rig = SignatureRig::new().await;
    let nonces = Arc::new(ReplayNonces::default());
    rig.auth.nonces = nonces.clone();
    let kp = generate_keypair();
    if !signature {
        rig.auth.allowlist.lock().unwrap().push(kp.public);
        rig.auth.verifier = None;
    }
    let mut router = Router::new();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let src = client_socket.local_addr().unwrap();
    let mut client = Connection::new(ConnectionConfig {
        required_features: crate::Features::NONE,
        features: crate::Features::SUPPORTED,
        role: Role::Client,
        local_static_priv: kp.private,
        remote_static_pub: Some(rig.server_pub),
        auth: if signature {
            AuthPolicy::SshSignature
        } else {
            AuthPolicy::Allowlist(Vec::new())
        },
    });
    let msg1 = client
        .start_session(
            Instant::now(),
            rig.socket.local_addr().unwrap(),
            StartKind::Cold,
            [91; 16],
        )
        .remove(0)
        .bytes;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        macro_rules! require {
            ($condition:expr, $message:literal) => {
                if !$condition {
                    return Err($message.to_string());
                }
            };
        }
        SessionManager::handle_datagram(&rig.ctx(), &mut router, msg1.len(), src, &msg1).await;
        require!(
            router.probation.len() == 1 && router.backends.is_empty(),
            "real msg1 must enter probation before binding"
        );
        let mut buf = vec![0; RECV_BUF_LEN];
        let (n, from) = client_socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        let original_msg2 = buf[..n].to_vec();
        let mut proof = client.on_datagram(Instant::now(), from, &original_msg2);
        let session_id = client.session_id();
        let original_nonce = client.server_nonce();
        if signature {
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
        } else {
            client.request_ping(Instant::now());
            proof.extend(client.on_timeout(Instant::now()));
        }
        for dg in proof {
            SessionManager::handle_datagram(
                &rig.ctx(),
                &mut router,
                dg.bytes.len(),
                src,
                &dg.bytes,
            )
            .await;
        }
        let ended = rig
            ._probation_rx
            .recv()
            .await
            .ok_or("probation stopped without receipt")?;
        require!(
            ended.proven.is_some(),
            "actual probation policy must prove the peer"
        );
        SessionManager::on_probation_ended(&rig.ctx(), &mut router, ended).await;
        require!(
            router.backends.len() == 1 && router.sessions.contains_key(&session_id),
            "proof must install the original backend and route"
        );
        require!(
            router.backends[&[91; 16]].msg2 == original_msg2,
            "cache must be the actual original responder message"
        );
        let revision = router
            .revisions
            .capture([91; 16])
            .ok_or("revision capture failed")?;
        // An unrelated obligation detects accidental table-wide cleanup.
        let pending_nonce = nonces.issue()?;
        let outstanding = nonces.tracking.outstanding_snapshot();
        require!(
            outstanding.contains(&pending_nonce),
            "independent nonce is outstanding"
        );
        let issues = nonces.issues.load(Ordering::SeqCst);
        let releases = nonces.releases.load(Ordering::SeqCst);
        nonces.fail.store(true, Ordering::SeqCst);
        // A new owned address cannot contain a delayed response to the original
        // admission; its first msg2 must be caused by this replay.
        let replay_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let replay_src = replay_socket.local_addr().map_err(|e| e.to_string())?;
        let replay_msg1 = if cookie_gate {
            router.cookies = CookieCheck::with_limits(
                Instant::now(),
                LoadLimits {
                    handshakes_per_window: 0,
                    probation_seats: 0,
                },
            );
            ACCEPT_ATTEMPTS.with(|n| n.set(0));
            SessionManager::handle_datagram(&rig.ctx(), &mut router, msg1.len(), replay_src, &msg1)
                .await;
            let n = replay_socket
                .recv(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            require!(
                ACCEPT_ATTEMPTS.with(|n| n.get()) == 0,
                "cookie gate must precede Noise/cache lookup"
            );
            require!(
                nonces.issues.load(Ordering::SeqCst) == issues,
                "cookie challenge must not issue a nonce"
            );
            require!(
                matches!(
                    parse(&buf[..n]),
                    Ok(Frame::Handshake {
                        kind: Kind::CookieReply,
                        ..
                    })
                ),
                "unproven replay gets a cookie, not cached msg2"
            );
            encode_handshake_init_cookie(&cookie_from(&buf[..n]), &msg1[2..])
        } else {
            msg1.clone()
        };
        SessionManager::handle_datagram(
            &rig.ctx(),
            &mut router,
            replay_msg1.len(),
            replay_src,
            &replay_msg1,
        )
        .await;
        let replay =
            tokio::time::timeout(Duration::from_secs(2), replay_socket.recv(&mut buf)).await;
        require!(
            replay.is_ok(),
            "validated cached replay must return original msg2 even when fresh nonces fail"
        );
        let n = replay.unwrap().map_err(|e| e.to_string())?;
        require!(
            buf[..n] == original_msg2,
            "replay response must be byte-exact original msg2"
        );
        require!(
            nonces.issues.load(Ordering::SeqCst) == issues,
            "cached replay must not ask for a nonce"
        );
        require!(
            nonces.releases.load(Ordering::SeqCst) == releases,
            "cached replay must not release any nonce"
        );
        require!(
            nonces.tracking.outstanding_snapshot() == outstanding,
            "cached replay must preserve outstanding obligations"
        );
        require!(
            nonces.tracking.bad_releases() == 0,
            "no foreign or duplicate nonce release"
        );
        require!(
            revision.is_current(),
            "cached replay must preserve binding revision"
        );
        require!(
            router.probation.is_empty()
                && router.backends.len() == 1
                && router.sessions.len() == 1
                && router.sessions.contains_key(&session_id),
            "cached replay must not adopt a connection or probation"
        );
        require!(
            client.session_id() == session_id && client.server_nonce() == original_nonce,
            "client retains original session and nonce"
        );
        let fresh = if signature {
            signature_msg1(&rig.server_pub, [91; 16], StartKind::Cold)
        } else {
            allowlist_msg1(&rig.server_pub, kp.private, [91; 16], StartKind::Cold)
        };
        // Leave load mode so this independently exercises fresh nonce failure.
        router.cookies = CookieCheck::with_limits(
            Instant::now(),
            LoadLimits {
                handshakes_per_window: u32::MAX,
                probation_seats: usize::MAX,
            },
        );
        SessionManager::handle_datagram(&rig.ctx(), &mut router, fresh.len(), src, &fresh).await;
        require!(
            nonces.issues.load(Ordering::SeqCst) == issues + 1,
            "different ephemeral must still require a fresh nonce"
        );
        require!(
            nonces.releases.load(Ordering::SeqCst) == releases
                && nonces.tracking.outstanding_snapshot() == outstanding,
            "fresh refusal must preserve other nonce obligations"
        );
        require!(
            router.probation.is_empty()
                && router.backends.len() == 1
                && router.sessions.len() == 1
                && router.sessions.contains_key(&session_id)
                && revision.is_current(),
            "fresh nonce failure must leave original binding usable"
        );
        Ok::<_, String>(())
    })
    .await;
    // Retain task custody through cleanup even when the regression fails.
    rig.lifecycle.shutdown.request();
    drop(router);
    tokio::time::timeout(Duration::from_secs(2), rig.lifecycle.drain())
        .await
        .expect("owned task cleanup deadline")
        .expect("owned task cleanup");
    assert!(rig.lifecycle.is_empty());
    result
        .expect("admission/replay deadline")
        .expect("cached replay control");
}

#[tokio::test]
async fn cached_replay_signature_ignores_unavailable_fresh_nonce_source() {
    cached_replay_after_real_admission(true, false).await;
}

#[tokio::test]
async fn cached_replay_allowlist_ignores_unavailable_fresh_nonce_source() {
    cached_replay_after_real_admission(false, false).await;
}

#[tokio::test]
async fn cached_replay_behind_cookie_ignores_unavailable_fresh_nonce_source() {
    cached_replay_after_real_admission(true, true).await;
}
