// Included in driver_std::tests. Every socket/thread belongs to this fixture.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Auth17WireEvent {
    Live,
    Accepted(crate::AuthAcceptance),
    Failure(crate::ProtocolFailure),
    Bytes,
    Closed,
}

struct Auth17WireEvents(Mutex<Sender<Auth17WireEvent>>);
impl ClientEvents for Auth17WireEvents {
    fn on_input_failure(&self, failure: crate::driver_std::InputFailure) {
        panic!("unexpected accepted-input failure: {failure:?}");
    }
    fn on_bytes(&self, _: u8, _: Vec<u8>) {
        self.send(Auth17WireEvent::Bytes);
    }
    fn on_state(&self, state: LinkState) {
        match state {
            LinkState::Live => self.send(Auth17WireEvent::Live),
            LinkState::Closed => self.send(Auth17WireEvent::Closed),
            _ => {}
        }
    }
    fn on_stats(&self, _: Stats) {}
    fn on_reset(&self, _: u8) {}
    fn on_auth_accepted(&self, record: crate::AuthAcceptance) {
        self.send(Auth17WireEvent::Accepted(record));
    }
    fn on_protocol_failure(&self, failure: crate::ProtocolFailure) {
        self.send(Auth17WireEvent::Failure(failure));
    }
}
impl Auth17WireEvents {
    fn send(&self, event: Auth17WireEvent) {
        let _ = self.0.lock().unwrap().send(event);
    }
}

struct Auth17WirePeer {
    client: StdClient,
    events: Receiver<Auth17WireEvent>,
    partial_ack: Receiver<()>,
    release: Sender<()>,
    stop: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<()>>,
}
impl Drop for Auth17WirePeer {
    fn drop(&mut self) {
        self.client.detach();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            let result = server.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}
impl Auth17WirePeer {
    // 0: valid split, 1: initial excess, 2: wrong session, 3: later excess.
    fn new(consumption: Consumption, case: u8) -> Self {
        let server_key = crate::handshake::generate_keypair();
        let client_key = crate::handshake::generate_keypair();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let (release, released) = mpsc::channel();
        let (partial_tx, partial_ack) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server = thread::spawn(move || {
            let mut conn = Connection::new(ConnectionConfig {
                role: crate::Role::Server,
                local_static_priv: server_key.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![client_key.public]),
                features: Features::SUPPORTED,
                required_features: Features::AUTH_ACCEPTED,
            });
            let mut buffer = [0; 65536];
            let mut wire = Vec::new();
            let mut sent_first = false;
            let mut reported_partial = false;
            let mut sent_rest = false;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !server_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                let now = Instant::now();
                let mut out = match socket.recv_from(&mut buffer) {
                    Ok((len, from)) => conn.on_datagram(now, from, &buffer[..len]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        Vec::new()
                    }
                    Err(error) => panic!("owned UDP receive failed: {error}"),
                };
                for event in conn.poll_events() {
                    if matches!(event, Event::PeerKeyConfirmed { .. }) && !sent_first {
                        wire = crate::encode_auth_acceptance(crate::AuthAcceptance {
                            session_id: if case == 2 {
                                conn.session_id() ^ 1
                            } else {
                                conn.session_id()
                            },
                            disposition: crate::SessionDisposition::Fresh,
                        })
                        .to_vec();
                        if case == 1 {
                            wire.push(0);
                        }
                        let first = if case == 0 { &wire[..5] } else { &wire[..] };
                        out.extend(conn.send(now, AUTH_STREAM, first));
                        sent_first = true;
                    }
                }
                if sent_first && !reported_partial && conn.stream_progress(AUTH_STREAM).unacked == 0
                {
                    partial_tx.send(()).unwrap();
                    reported_partial = true;
                }
                if sent_first && !sent_rest && released.try_recv().is_ok() {
                    out.extend(conn.send(
                        now,
                        AUTH_STREAM,
                        if case == 0 { &wire[5..] } else { &[0] },
                    ));
                    sent_rest = true;
                }
                out.extend(conn.on_timeout(Instant::now()));
                for dg in out {
                    socket.send_to(&dg.bytes, dg.to).unwrap();
                }
            }
        });
        let (event_tx, events) = mpsc::channel();
        let client = StdClient::connect_with(
            addr,
            ConnectionConfig {
                role: crate::Role::Client,
                local_static_priv: client_key.private,
                remote_static_pub: Some(server_key.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
                features: Features::SUPPORTED,
                required_features: Features::AUTH_ACCEPTED,
            },
            [17; 16],
            StartKind::Cold,
            Arc::new(OkBinder),
            Arc::new(Auth17WireEvents(Mutex::new(event_tx))),
            None,
            DriverSetup {
                default_consumption: consumption,
                stream_consumption: vec![(AUTH_STREAM, Consumption::Explicit)],
                input_budget: None,
                ..DriverSetup::default()
            },
        );
        Self {
            client,
            events,
            partial_ack,
            release,
            stop,
            server: Some(server),
        }
    }
    fn next(&self) -> Auth17WireEvent {
        self.events
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded driver callback")
    }
    fn assert_no_reserved_debt(&self) {
        let (reply, received) = mpsc::channel();
        self.client
            .tx
            .lock()
            .unwrap()
            .send(Command::UnconsumedForTest(reply))
            .unwrap();
        let debt = received.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            !debt
                .iter()
                .any(|(stream, n)| *stream == AUTH_STREAM && *n != 0),
            "auth is driver-owned: {debt:?}"
        );
    }
}

#[test]
fn auth17_real_driver_partial_record_is_not_acceptance_and_credit_is_driver_owned() {
    for consumption in [Consumption::OnDelivery, Consumption::Explicit] {
        let peer = Auth17WirePeer::new(consumption, 0);
        assert_eq!(peer.next(), Auth17WireEvent::Live);
        peer.partial_ack
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        peer.assert_no_reserved_debt();
        assert!(
            peer.events.try_recv().is_err(),
            "partial record is neither application bytes nor acceptance"
        );
        peer.release.send(()).unwrap();
        assert!(matches!(
            peer.next(),
            Auth17WireEvent::Accepted(crate::AuthAcceptance {
                disposition: crate::SessionDisposition::Fresh,
                ..
            })
        ));
        peer.assert_no_reserved_debt();
        assert!(
            peer.events.try_recv().is_err(),
            "exactly one typed callback, no generic delivery"
        );
    }
}

#[test]
fn auth17_real_driver_malformed_or_excess_record_closes_without_generic_delivery() {
    for (case, reason) in [
        (1, crate::AuthAcceptanceError::Excess),
        (2, crate::AuthAcceptanceError::WrongSession),
        (3, crate::AuthAcceptanceError::Excess),
    ] {
        let peer = Auth17WirePeer::new(Consumption::Explicit, case);
        assert_eq!(peer.next(), Auth17WireEvent::Live);
        if case == 3 {
            assert!(matches!(peer.next(), Auth17WireEvent::Accepted(_)));
            peer.release.send(()).unwrap();
        }
        assert_eq!(
            peer.next(),
            Auth17WireEvent::Failure(crate::ProtocolFailure::InvalidAuthentication { reason })
        );
        assert_eq!(peer.next(), Auth17WireEvent::Closed);
        peer.client.detach();
        assert!(
            peer.events.try_recv().is_err(),
            "no generic bytes or second acceptance"
        );
    }
}
