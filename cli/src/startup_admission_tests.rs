// Component control: accepted-observer fixture, actual startup helper and
// fixture-owned silent UDP driver. This is not a second Noise-auth test.
struct StartupAdmissionAttempt {
    attempt: attempt::Attempt,
    _peer: std::net::UdpSocket,
}
impl Drop for StartupAdmissionAttempt {
    fn drop(&mut self) {
        self.attempt.detach();
    }
}
fn accepted_startup_attempt() -> StartupAdmissionAttempt {
    use transport::driver_std::ClientEvents;
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (tx, _rx) = std::sync::mpsc::channel();
    let att = attempt::Attempt::open(
        peer.local_addr().unwrap(),
        transport::generate_keypair().public,
        transport::generate_keypair().private,
        Login::Allowlist,
        tx,
        attempt::AttemptScope {
            token: [3; 16],
            input_budget: Default::default(),
        },
    );
    att.events.on_state(transport::LinkState::Live);
    att.events.on_auth_accepted(transport::AuthAcceptance {
        session_id: 1,
        disposition: transport::SessionDisposition::Fresh,
    });
    StartupAdmissionAttempt {
        attempt: att,
        _peer: peer,
    }
}

#[test]
fn client179_startup_term_and_open_refusals_are_local_terminal_outcomes() {
    use client::channel::ChannelSendError;
    for error in [ChannelSendError::Full, ChannelSendError::Gone] {
        for fail_at in [0, 1, 2] {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = calls.clone();
            let sink: Sink = Box::new(move |stream, bytes| {
                let mut calls = seen.lock().unwrap();
                let index = calls.len();
                calls.push((stream, bytes));
                if index == fail_at {
                    Err(error)
                } else {
                    Ok(())
                }
            });
            let mut channels = ChannelSession::new(QshSubstrate::new(sink));
            let fixture = accepted_startup_attempt();
            let (verdict, opened) = settle_opening(
                &fixture.attempt,
                &mut channels,
                Some("xterm-256color"),
                80,
                24,
                true,
                || false,
            );
            drop(fixture); // real driver joined even if following assertions fail
            if fail_at < 2 {
                assert_eq!(verdict, Verdict::LocalSendFailure(error));
                assert_eq!(opened, None);
                assert_eq!(
                    calls.lock().unwrap().len(),
                    fail_at + 1,
                    "no fallback/retry after refused record"
                );
            } else {
                assert_eq!(verdict, Verdict::Working);
                assert_eq!(opened, Some(16));
                assert_eq!(calls.lock().unwrap().len(), 2);
            }
            assert!(
                !channels.is_ready(16),
                "admitted Open still awaits actual remote confirmation"
            );
        }
    }
}

// Real authenticated peer: its positive hold fence precedes budget saturation.
// Neither acceptance nor refusal is injected through an observer or fake sink.
struct Startup179Peer {
    stop: Arc<std::sync::atomic::AtomicBool>,
    hold: Arc<std::sync::atomic::AtomicBool>,
    held: std::sync::mpsc::Receiver<()>,
    data_ready: std::sync::mpsc::Receiver<()>,
    data: Arc<std::sync::Mutex<Vec<u8>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Startup179Peer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !std::thread::panicking() {
                joined.unwrap();
            }
        }
    }
}
struct Startup179Owner(Option<attempt::Attempt>);
impl Drop for Startup179Owner {
    fn drop(&mut self) {
        if let Some(att) = &self.0 {
            att.detach();
        }
    }
}
fn authenticated_startup_attempt() -> (Startup179Owner, Startup179Peer) {
    authenticated_startup_for(None, false)
}
fn authenticated_startup_for(
    setup: Option<&Setup>,
    shared: bool,
) -> (Startup179Owner, Startup179Peer) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    let server_key = transport::generate_keypair();
    let client_key = setup.map_or_else(transport::generate_keypair, |setup| {
        transport::handshake::Keypair {
            public: setup.keypair.public,
            private: setup.keypair.private,
        }
    });
    let scope = setup.map_or_else(
        || attempt::AttemptScope {
            token: [179; 16],
            input_budget: Default::default(),
        },
        Setup::attempt_scope,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let hold = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server_hold = hold.clone();
    let (held_tx, held) = std::sync::mpsc::channel();
    let (data_tx, data_ready) = std::sync::mpsc::sync_channel(1);
    let data = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_data = data.clone();
    let worker = std::thread::spawn(move || {
        let mut conn = transport::Connection::new(transport::ConnectionConfig {
            role: transport::Role::Server,
            local_static_priv: server_key.private,
            remote_static_pub: None,
            auth: transport::AuthPolicy::Allowlist(vec![client_key.public]),
            features: transport::Features::SUPPORTED,
            required_features: transport::Features::AUTH_ACCEPTED,
        });
        let mut buffer = [0; 65536];
        let mut accepted = false;
        let mut reported_hold = false;
        while !server_stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            let mut out = match socket.recv_from(&mut buffer) {
                Ok((len, from)) => conn.on_datagram(now, from, &buffer[..len]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    Vec::new()
                }
                Err(e) => panic!("fixture receive: {e}"),
            };
            for event in conn.poll_events() {
                if let transport::Event::StreamData {
                    stream_id: 31,
                    data,
                } = &event
                {
                    let mut observed = observed_data.lock().unwrap();
                    // Fixed expected test input plus one overflow sentinel.
                    let room = 4097usize.saturating_sub(observed.len());
                    observed.extend_from_slice(&data[..data.len().min(room)]);
                    let _ = data_tx.try_send(()); // one coalesced fixture wake
                }
                if matches!(event, transport::Event::PeerKeyConfirmed { .. }) && !accepted {
                    out.extend(conn.send(
                        now,
                        transport::AUTH_STREAM,
                        &transport::encode_auth_acceptance(transport::AuthAcceptance {
                            session_id: conn.session_id(),
                            disposition: transport::SessionDisposition::Fresh,
                        }),
                    ));
                    accepted = true;
                }
            }
            out.extend(conn.on_timeout(Instant::now()));
            if server_hold.load(Ordering::SeqCst) {
                if !reported_hold {
                    let _ = held_tx.send(());
                    reported_hold = true;
                }
                continue;
            }
            for datagram in out {
                socket.send_to(&datagram.bytes, datagram.to).unwrap();
            }
        }
    });
    let (tx, _rx) = std::sync::mpsc::channel();
    let att = if shared {
        attempt::Attempt::open_recovery(
            vec![transport::recovery_handshake::RecoveryEndpoint {
                address: 0,
                endpoint: addr,
            }],
            server_key.public,
            client_key.private,
            Login::Allowlist,
            tx,
            scope,
            Arc::new(|_| {}),
        )
    } else {
        attempt::Attempt::open(
            addr,
            server_key.public,
            client_key.private,
            Login::Allowlist,
            tx,
            scope,
        )
    };
    let owner = Startup179Owner(Some(att));
    (
        owner,
        Startup179Peer {
            stop,
            hold,
            held,
            data_ready,
            data,
            worker: Some(worker),
        },
    )
}

#[test]
fn client179_shared_authenticated_startup_refusal_is_terminal_not_a_failed_sweep() {
    use ::connect::recovery_gate::{RecoveryEpoch, SweepId};
    use std::sync::atomic::Ordering;
    let home = tempfile::tempdir().unwrap();
    let (mut fixture, peer) = authenticated_startup_attempt();
    let att = fixture.0.as_ref().unwrap();
    let verdict = att.settle();
    assert_eq!(verdict, Verdict::Working, "actual authenticated acceptance");
    peer.hold.store(true, Ordering::SeqCst);
    peer.held
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    att.client
        .send_bytes(30, vec![b'a'; transport::client_input_budget::INPUT_BYTES])
        .unwrap();
    let rejected = att.client.send_bytes(30, vec![b'b']).unwrap_err();
    assert_eq!(rejected.reason, transport::driver_std::SendBlocked::Full);
    let args = crate::args::parse_args(&["127.0.0.1:60001".into()]).unwrap();
    let setup = Setup::new(
        args,
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        Tty::at(home.path().join("no-tty")),
        KnownHosts::new(home.path().join("ssh_known_hosts"), None),
        None,
        None,
        [179; 16],
    );
    let epoch = RecoveryEpoch {
        connection: 179,
        network: 0,
    };
    let sweep = SweepId(1);
    let recovery = Recovery::new(epoch, 1);
    recovery.begin_sweep(sweep);
    let (tx, rx) = std::sync::mpsc::channel();
    let climb = Climb::new(
        &setup,
        setup.args.addresses.clone(),
        0,
        Mode::Background {
            progress: tx.clone().into(),
            round: 1,
        },
        80,
        24,
        tx,
        &rx,
    )
    .recovering(&recovery, epoch, sweep)
    .allow_new_session(true);
    // Retain a driver guard through helper consumption and all result paths.
    let client = fixture.0.as_ref().unwrap().client.clone();
    struct Joined(Arc<transport::driver_std::StdClient>);
    impl Drop for Joined {
        fn drop(&mut self) {
            self.0.detach();
        }
    }
    let driver = Joined(client);
    let att = fixture.0.take().unwrap();
    let result = climb.shared_trial(att, 0);
    drop(driver);
    drop(peer);
    assert!(
        matches!(
            result,
            Err((
                ::connect::reconnect::RoundEnd::LocalSendFailure { addr: 0 },
                _
            ))
        ),
        "local refusal must not become retryable AllFailed"
    );
    assert!(
        !recovery.interrupted(climb.revision),
        "retain current revision for terminal result publication"
    );
    assert!(!recovery.ssh_allowed());
}

#[test]
fn client179_direct_wrapper_local_refusal_does_not_grant_ssh_credit() {
    use ::connect::recovery_gate::{RecoveryEpoch, SweepId};
    let home = tempfile::tempdir().unwrap();
    let setup = Setup::new(
        crate::args::parse_args(&["127.0.0.1:60001".into()]).unwrap(),
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        Tty::at(home.path().join("no-tty")),
        KnownHosts::new(home.path().join("ssh_known_hosts"), None),
        None,
        None,
        [179; 16],
    );
    let epoch = RecoveryEpoch {
        connection: 179,
        network: 0,
    };
    let sweep = SweepId(1);
    let recovery = Recovery::new(epoch, 1);
    recovery.begin_sweep(sweep);
    let (tx, rx) = std::sync::mpsc::channel();
    let climb = Climb::new(
        &setup,
        setup.args.addresses.clone(),
        0,
        Mode::Background {
            progress: tx.clone().into(),
            round: 1,
        },
        80,
        24,
        tx,
        &rx,
    )
    .recovering(&recovery, epoch, sweep);
    climb.account_direct(0, DirectOutcome::LocalSendFailure);
    assert!(!recovery.ssh_allowed());
    assert!(!recovery.interrupted(climb.revision));
    // Late ordinary completion must not reopen fallback for this terminal revision.
    climb.account_direct(0, DirectOutcome::Refused);
    assert!(!recovery.ssh_allowed());
}
