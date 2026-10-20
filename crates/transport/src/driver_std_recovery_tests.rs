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
            // The shared profile itself must require explicit acceptance.
            required_features: Features::NONE,
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

#[test]
fn shared_recovery_progress_reports_actual_checks_and_source_before_protocol_failure() {
    #[derive(Debug)]
    enum Trace {
        Progress(RecoveryProgress),
        Failure,
        Closed,
    }
    struct Capture(Mutex<Sender<Trace>>);
    impl ClientEvents for Capture {
        fn on_input_failure(&self, failure: crate::driver_std::InputFailure) {
            panic!("unexpected accepted-input failure: {failure:?}");
        }
        fn on_bytes(&self, _: u8, _: Vec<u8>) {}
        fn on_stats(&self, _: Stats) {}
        fn on_reset(&self, _: u8) {}
        fn on_state(&self, state: LinkState) {
            if state == LinkState::Closed {
                let _ = self.0.lock().unwrap().send(Trace::Closed);
            }
        }
        fn on_protocol_failure(&self, _: crate::ProtocolFailure) {
            let _ = self.0.lock().unwrap().send(Trace::Failure);
        }
        fn on_recovery_progress(&self, progress: RecoveryProgress) {
            let _ = self.0.lock().unwrap().send(Trace::Progress(progress));
        }
    }
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let (tx, traces) = mpsc::channel();
    let started = Instant::now();
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
            auth: AuthPolicy::Allowlist(Vec::new()),
            features: Features::SUPPORTED,
            required_features: Features::AUTH_ACCEPTED,
        },
        [16; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(Capture(Mutex::new(tx))),
        None,
        DriverSetup::default(),
    ));
    let mut buffer = [0; 2048];
    let (len, from) = b.recv_from(&mut buffer).unwrap();
    let crate::wire::Frame::Handshake { body, .. } = crate::wire::parse(&buffer[..len]).unwrap()
    else {
        panic!("msg1");
    };
    let mut responder = crate::handshake::Handshake::new_responder(&server_key.private);
    responder.read_msg(body).unwrap();
    b.send_to(
        &crate::wire::encode_handshake(
            crate::wire::Kind::HandshakeResp,
            &responder.write_msg(b"invalid"),
        ),
        from,
    )
    .unwrap();
    let mut history = Vec::new();
    loop {
        let trace = traces
            .recv_timeout(Duration::from_secs(2))
            .expect("closed driver trace");
        let closed = matches!(trace, Trace::Closed);
        history.push(trace);
        if closed {
            break;
        }
    }
    client.0.detach();
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();
    for endpoint in [a_addr, b_addr] {
        assert!(
            history.iter().any(|trace| matches!(trace,
            Trace::Progress(RecoveryProgress::Sent { endpoint: sent, at, success: true })
            if *sent == endpoint && *at >= started)),
            "actual endpoint send is observable: {endpoint}"
        );
    }
    let selected: Vec<_> = history
        .iter()
        .enumerate()
        .filter_map(|(index, trace)| match trace {
            Trace::Progress(RecoveryProgress::Selected { endpoint, at }) => {
                Some((index, *endpoint, *at))
            }
            _ => None,
        })
        .collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].1, b_addr);
    assert!(selected[0].2 >= started);
    let failed = history
        .iter()
        .position(|trace| matches!(trace, Trace::Failure))
        .unwrap();
    assert!(
        selected[0].0 < failed,
        "failure must already have an exact consumed source"
    );
}

#[test]
fn shared_recovery_driver_rejects_no_acceptance_peer_before_signing_or_data() {
    struct NoProof(AtomicUsize);
    impl AuthSigner for NoProof {
        fn sign(
            &self,
            _: &[u8; 32],
            _: Option<&[u8; AUTH_NONCE_LEN]>,
        ) -> Result<AuthRecord, AuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(AuthError::Backend(
                "controlled unexpected proof request".into(),
            ))
        }
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let mut server = Connection::new(ConnectionConfig {
        role: crate::Role::Server,
        local_static_priv: server_key.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_key.public]),
        features: Features::from_bits(Features::SUPPORTED.bits() & !Features::AUTH_ACCEPTED.bits()),
        required_features: Features::NONE,
    });
    let (tx, events) = mpsc::channel();
    let signer = Arc::new(NoProof(AtomicUsize::new(0)));
    let client = Recovery16Client(StdClient::connect_recovery_with(
        vec![RecoveryEndpoint {
            address: 0,
            endpoint: socket.local_addr().unwrap(),
        }],
        ConnectionConfig {
            role: crate::Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server_key.public),
            auth: AuthPolicy::SshSignature,
            features: Features::SUPPORTED,
            required_features: Features::NONE,
        },
        [147; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(Auth17WireEvents(Mutex::new(tx))),
        Some(signer.clone()),
        DriverSetup::default(),
    ));
    client
        .0
        .send_bytes(16, b"must not leave before admission".to_vec())
        .expect("fixture application input admitted locally before peer response");
    let mut buffer = [0; 65536];
    let (len, from) = socket.recv_from(&mut buffer).unwrap();
    let response = server.on_datagram(Instant::now(), from, &buffer[..len]);
    assert_eq!(response.len(), 1, "actual Noise responder");
    socket.send_to(&response[0].bytes, from).unwrap();
    let mut observed = Vec::new();
    loop {
        let event = events
            .recv_timeout(Duration::from_secs(2))
            .expect("owned driver closed");
        let closed = event == Auth17WireEvent::Closed;
        observed.push(event);
        if closed {
            break;
        }
    }
    client.0.detach();
    assert_eq!(
        signer.0.load(Ordering::SeqCst),
        0,
        "rejected peer cannot start a proof"
    );
    assert!(!observed.contains(&Auth17WireEvent::Live));
    assert!(!observed
        .iter()
        .any(|event| matches!(event, Auth17WireEvent::Accepted(_))));
    assert!(observed.iter().any(|event| matches!(event,
        Auth17WireEvent::Failure(crate::ProtocolFailure::MissingRequiredFeatures { required, enabled })
            if required.contains(Features::AUTH_ACCEPTED) && !enabled.contains(Features::AUTH_ACCEPTED)
    )));
    socket.set_nonblocking(true).unwrap();
    while let Ok((len, src)) = socket.recv_from(&mut buffer) {
        server.on_datagram(Instant::now(), src, &buffer[..len]);
    }
    assert!(
        !server
            .poll_events()
            .iter()
            .any(|event| matches!(event, Event::StreamData { .. })),
        "joined driver emitted neither proof nor queued application data"
    );
}
