// Included in driver_std::tests. Every socket, driver and signer is fixture-owned.
#[test]
fn processed_detach_discards_an_already_queued_signing_result() {
    struct OwnedClient(StdClient);
    impl Drop for OwnedClient {
        fn drop(&mut self) {
            self.0.detach();
        }
    }
    struct HeldSigner {
        release: Mutex<Receiver<()>>,
        entered: Sender<()>,
    }
    impl AuthSigner for HeldSigner {
        fn sign(
            &self,
            hash: &[u8; 32],
            _: Option<&[u8; AUTH_NONCE_LEN]>,
        ) -> Result<AuthRecord, AuthError> {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .expect("fixture releases signer");
            Ok(AuthRecord {
                public_key: b"fixture-only".to_vec(),
                signature: hash.to_vec(),
                v2: None,
            })
        }
    }
    struct HeldLive {
        release: Mutex<Receiver<()>>,
        entered: Sender<()>,
    }
    impl ClientEvents for HeldLive {
        fn on_input_failure(&self, failure: crate::driver_std::InputFailure) {
            panic!("unexpected accepted-input failure: {failure:?}");
        }
        fn on_bytes(&self, _: u8, _: Vec<u8>) {}
        fn on_stats(&self, _: Stats) {}
        fn on_reset(&self, _: u8) {}
        fn on_state(&self, state: LinkState) {
            if state == LinkState::Live {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .expect("fixture releases driver");
            }
        }
    }
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut server = Connection::new(ConnectionConfig {
        role: crate::Role::Server,
        local_static_priv: server_key.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_key.public]),
        features: Features::SUPPORTED,
        required_features: Features::NONE,
    });
    let (sign_release, sign_released) = mpsc::channel();
    let (sign_entered, sign_started) = mpsc::channel();
    let signer = Arc::new(HeldSigner {
        release: Mutex::new(sign_released),
        entered: sign_entered,
    });
    let (live_release, live_released) = mpsc::channel();
    let (live_entered, live_started) = mpsc::channel();
    // Deliberately use the unchanged single-endpoint API to establish whether
    // this cancellation window predates shared-recovery scheduling.
    let client = OwnedClient(StdClient::connect(
        socket.local_addr().unwrap(),
        ConnectionConfig {
            role: crate::Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server_key.public),
            auth: AuthPolicy::SshSignature,
            features: Features::SUPPORTED,
            required_features: Features::NONE,
        },
        [16; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(HeldLive {
            release: Mutex::new(live_released),
            entered: live_entered,
        }),
        Some(signer.clone()),
    ));
    let mut buffer = [0; 65536];
    let (len, from) = socket.recv_from(&mut buffer).unwrap();
    for datagram in server.on_datagram(Instant::now(), from, &buffer[..len]) {
        socket.send_to(&datagram.bytes, datagram.to).unwrap();
    }
    live_started.recv_timeout(Duration::from_secs(2)).unwrap();
    sign_started.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        Arc::strong_count(&signer),
        3,
        "fixture, parked driver and signer thread own the only references"
    );
    client.0.stop.fetch_max(2, Ordering::SeqCst);
    sign_release.send(()).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while Arc::strong_count(&signer) != 2 && Instant::now() < until {
        thread::yield_now();
    }
    assert_eq!(
        Arc::strong_count(&signer),
        2,
        "signer thread dropped its capture after queueing AuthResult"
    );
    live_release.send(()).unwrap();
    client.0.detach();
    // Driver has joined: no later packet or proof can be attributed to this
    // fixture. Decode what was actually emitted after processing Detach.
    socket.set_nonblocking(true).unwrap();
    let mut auth_bytes = 0;
    while let Ok((len, from)) = socket.recv_from(&mut buffer) {
        server.on_datagram(Instant::now(), from, &buffer[..len]);
        for event in server.poll_events() {
            if let Event::StreamData {
                stream_id: AUTH_STREAM,
                data,
            } = event
            {
                auth_bytes += data.len();
            }
        }
    }
    assert_eq!(
        auth_bytes, 0,
        "processed cancellation must win over a queued signature result"
    );
}
