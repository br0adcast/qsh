// Included in driver_std::tests. All sockets and driver threads are fixture-owned.
struct Recovery16Client(StdClient);
impl Drop for Recovery16Client {
    fn drop(&mut self) {
        self.0.detach();
    }
}

#[test]
fn shared_recovery_driver_reaches_catalog_larger_than_live_path_limit() {
    let sockets: Vec<_> = (0..19)
        .map(|_| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
        })
        .collect();
    let endpoints = sockets
        .iter()
        .enumerate()
        .map(
            |(address, socket)| crate::recovery_handshake::RecoveryEndpoint {
                address,
                endpoint: socket.local_addr().unwrap(),
            },
        )
        .collect();
    let client_key = crate::handshake::generate_keypair();
    let server_key = crate::handshake::generate_keypair();
    let client = Recovery16Client(StdClient::connect_recovery_with(
        endpoints,
        ConnectionConfig {
            role: crate::Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server_key.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
            features: Features::SUPPORTED,
            required_features: Features::AUTH_ACCEPTED,
        },
        [16; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(NullEvents),
        None,
        DriverSetup::default(),
    ));
    let mut first = None;
    let mut source = None;
    let mut buffer = [0; 2048];
    let started = Instant::now();
    for (index, socket) in sockets.iter().enumerate() {
        let (len, from) = socket
            .recv_from(&mut buffer)
            .unwrap_or_else(|error| panic!("catalog endpoint {index} received no msg1: {error}"));
        assert!(matches!(
            crate::wire::parse(&buffer[..len]),
            Ok(crate::wire::Frame::Handshake {
                kind: crate::wire::Kind::HandshakeInit,
                ..
            })
        ));
        assert_eq!(
            *source.get_or_insert(from),
            from,
            "one client socket owns the attempt"
        );
        assert_eq!(
            first.get_or_insert_with(|| buffer[..len].to_vec()),
            &buffer[..len],
            "one initiator supplies every endpoint"
        );
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "no per-path silence deadline"
    );
    client.0.detach();
}

#[test]
fn shared_recovery_driver_signs_only_selected_transcript_and_stops_on_acceptance() {
    struct CountSigner(AtomicUsize);
    impl AuthSigner for CountSigner {
        fn sign(
            &self,
            hash: &[u8; 32],
            _: Option<&[u8; AUTH_NONCE_LEN]>,
        ) -> Result<AuthRecord, AuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(AuthRecord {
                public_key: b"fixture-only".to_vec(),
                signature: hash.to_vec(),
                v2: None,
            })
        }
    }
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let config = ConnectionConfig {
        role: crate::Role::Server,
        local_static_priv: server_key.private,
        // This hand-pumped Connection has no probation/manager. It checks
        // the fixture key; only the CLIENT runs the signature method here.
        // The test observes proof ownership, not server admission policy.
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_key.public]),
        features: Features::SUPPORTED,
        required_features: Features::AUTH_ACCEPTED,
    };
    let mut server_a = Connection::new(config.clone());
    let mut server_b = Connection::new(config);
    let (tx, events) = mpsc::channel();
    let signer = Arc::new(CountSigner(AtomicUsize::new(0)));
    let client = Recovery16Client(StdClient::connect_recovery_with(
        [&a, &b]
            .into_iter()
            .enumerate()
            .map(|(address, socket)| RecoveryEndpoint {
                address,
                endpoint: socket.local_addr().unwrap(),
            })
            .collect(),
        ConnectionConfig {
            role: crate::Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server_key.public),
            auth: AuthPolicy::SshSignature,
            features: Features::SUPPORTED,
            required_features: Features::AUTH_ACCEPTED,
        },
        [16; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(Auth17WireEvents(Mutex::new(tx))),
        Some(signer.clone()),
        DriverSetup::default(),
    ));
    let mut buffer = [0; 65536];
    let (len, from_a) = a.recv_from(&mut buffer).unwrap();
    let response_a = server_a.on_datagram(Instant::now(), from_a, &buffer[..len]);
    let (len, from_b) = b.recv_from(&mut buffer).unwrap();
    assert_eq!(from_a, from_b);
    let response_b = server_b.on_datagram(Instant::now(), from_b, &buffer[..len]);
    assert_eq!(response_a.len(), 1, "first fixture responder supplies msg2");
    assert_eq!(
        response_b.len(),
        1,
        "second fixture responder supplies msg2"
    );
    b.send_to(&response_b[0].bytes, from_b).unwrap();
    assert_eq!(
        events.recv_timeout(Duration::from_secs(2)).unwrap(),
        Auth17WireEvent::Live
    );
    assert_eq!(client.0.active_path(), Some(b.local_addr().unwrap()));
    a.send_to(&response_a[0].bytes, from_a).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    b.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut proof = None;
    while proof.is_none() && Instant::now() < deadline {
        let now = Instant::now();
        let mut out = Vec::new();
        if let Ok((len, src)) = b.recv_from(&mut buffer) {
            if !matches!(
                crate::wire::parse(&buffer[..len]),
                Ok(crate::wire::Frame::Handshake { .. })
            ) {
                out.extend(server_b.on_datagram(now, src, &buffer[..len]));
            }
        }
        for event in server_b.poll_events() {
            if let Event::StreamData {
                stream_id: AUTH_STREAM,
                data,
            } = event
            {
                proof = Some(parse_auth_record(&data).expect("one complete fixture proof"));
            }
        }
        out.extend(server_b.on_timeout_if_due(now));
        for datagram in out {
            b.send_to(&datagram.bytes, datagram.to).unwrap();
        }
    }
    let proof = proof.expect("selected responder receives the only proof");
    assert_eq!(proof.signature, server_b.handshake_hash());
    assert_ne!(proof.signature, server_a.handshake_hash());
    assert_eq!(signer.0.load(Ordering::SeqCst), 1);
    // Scheduling continues while authentication is unresolved, even after Live.
    let until = Instant::now() + Duration::from_secs(2);
    a.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let mut checked_again = false;
    while Instant::now() < until && !checked_again {
        if let Ok((len, src)) = a.recv_from(&mut buffer) {
            assert_eq!(src, from_a);
            // Established transport may also check this spare path, using
            // the selected responder's keys. It is not a second handshake.
            checked_again = matches!(
                crate::wire::parse(&buffer[..len]),
                Ok(crate::wire::Frame::Handshake { .. })
            );
        }
    }
    assert!(
        checked_again,
        "unselected endpoint still receives handshake checks"
    );
    let accepted = crate::AuthAcceptance {
        session_id: server_b.session_id(),
        disposition: crate::SessionDisposition::Resumed,
    };
    for datagram in server_b.send(
        Instant::now(),
        AUTH_STREAM,
        &crate::encode_auth_acceptance(accepted),
    ) {
        b.send_to(&datagram.bytes, datagram.to).unwrap();
    }
    assert_eq!(
        events.recv_timeout(Duration::from_secs(2)).unwrap(),
        Auth17WireEvent::Accepted(accepted)
    );
    a.set_nonblocking(true).unwrap();
    while a.recv_from(&mut buffer).is_ok() {}
    a.set_nonblocking(false).unwrap();
    let until = Instant::now() + Duration::from_millis(700);
    while Instant::now() < until {
        match a.recv_from(&mut buffer) {
            Ok((len, _)) => assert!(
                !matches!(
                    crate::wire::parse(&buffer[..len]),
                    Ok(crate::wire::Frame::Handshake { .. })
                ),
                "acceptance retires the remaining handshake checks"
            ),
            Err(error) => assert!(is_read_timeout(&error)),
        }
    }
    assert_eq!(signer.0.load(Ordering::SeqCst), 1);
    assert_eq!(client.0.active_path(), Some(b.local_addr().unwrap()));
}
