// Actual CLI action executor with fixture-owned connection/thread custody.
fn input_executor_links() -> (tempfile::TempDir, Links) {
    let home = tempfile::tempdir().unwrap();
    let args = args::parse_args(&["fixture@127.0.0.1:60022".into()]).unwrap();
    let addresses = args.addresses.clone();
    let setup = Arc::new(Setup::new(
        args,
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        prompt::Tty::at(home.path().join("no-tty")),
        known_hosts::KnownHosts::new(home.path().join("ssh_known_hosts"), None),
        None,
        None,
        [1; 16],
    ));
    let epoch = RecoveryEpoch {
        connection: 1,
        network: 1,
    };
    let (tx, _rx) = mpsc::channel();
    // No live link, recovery round, DNS request or terminal reader is started.
    let links = Links {
        setup,
        live: None,
        shell_channel: None,
        attachment_intent: None,
        next_link: 1,
        reconnect: Reconnect::new(0),
        catalog: RoadCatalog::new(addresses.clone(), epoch),
        addresses,
        at: 0,
        labels: Vec::new(),
        roads_at: None,
        resolver: BoundedResolver::new(),
        road_epoch: epoch,
        road_origin: Instant::now(),
        road_active: "127.0.0.1:60022".parse().unwrap(),
        refusal: None,
        probe_attempt: 0,
        probe_observed_at: None,
        recovery_view_deadline: None,
        keep: false,
        round: None,
        rounds: 0,
        round_line: None,
        farewell: None,
        stopped: false,
        replacement_at: None,
        tx: tx.into(),
    };
    (home, links)
}

struct InputExecutor {
    _home: tempfile::TempDir,
    _peer: std::net::UdpSocket,
    links: Links,
}
impl Drop for InputExecutor {
    fn drop(&mut self) {
        if let Some(live) = self.links.live.take() {
            live.attempt.detach();
        }
        self.links.resolver.cancel();
    }
}

fn input_executor(sink: Sink, ready: bool) -> InputExecutor {
    use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
    use transport::shell_frame::{encode_shell, ShellRecord};
    let (home, mut links) = input_executor_links();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = transport::generate_keypair();
    let (tx, _rx) = mpsc::channel();
    let attempt = connect::Attempt::open(
        peer.local_addr().unwrap(),
        server.public,
        transport::generate_keypair().private,
        connect::Login::Allowlist,
        tx,
        connect::AttemptScope {
            token: [2; 16],
            input_budget: Default::default(),
        },
    );
    let mut channel_session = ChannelSession::new(QshSubstrate::new(sink));
    channel_session.open_shell(20, 5).unwrap();
    if ready {
        channel_session.on_event(client::channel::SubstrateEvent::Opened(16));
        channel_session.on_bytes(
            16,
            &encode_shell(&ShellRecord::Geometry(GeometryRecord {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 20,
                rows: 5,
            }))
            .unwrap(),
        );
    }
    links.live = Some(Live {
        attempt,
        channel_session,
        link: 1,
    });
    links.shell_channel = Some(16);
    InputExecutor {
        _home: home,
        _peer: peer,
        links,
    }
}

fn predictive_input_session() -> Session {
    let mut session = Session::new(
        20,
        5,
        TermCaps::truecolor(),
        args::PredictMode::Always,
        Chrome {
            prefix: qsh::escape::DEFAULT_PREFIX,
            line: false,
            glyphs: qsh::window::Glyphs {
                utf8: true,
                colour: true,
            },
        },
    );
    session.handle(UiEvent::Link(LinkState::Live), 0);
    session.on_channel_ready(16, 0);
    session
}

#[test]
fn client179_executor_rejection_never_paints_or_replays_input() {
    use client::channel::ChannelSendError;
    for error in [ChannelSendError::Full, ChannelSendError::Gone] {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sent = seen.clone();
        let sink: Sink = Box::new(move |stream, bytes| {
            if stream == 16 {
                sent.lock().unwrap().push(bytes);
                return Err(error);
            }
            Ok(())
        });
        let mut fixture = input_executor(sink, true);
        let mut session = predictive_input_session();
        let budget = qsh::input_ingress::IngressBudget::default();
        let actions = session.handle(
            UiEvent::Stdin(budget.admit_slice(b"unaccepted").unwrap()),
            1,
        );
        let mut output = Vec::new();
        let mut notices = Vec::new();
        let result = apply_actions(
            actions,
            &mut output,
            &mut fixture.links,
            &mut session,
            &mut notices,
            1,
        );
        drop(fixture); // actual fixture driver joined before outcome assertions
        assert_eq!(result, Some(1));
        assert_eq!(*seen.lock().unwrap(), vec![b"unaccepted".to_vec()]);
        assert!(!output.windows(10).any(|part| part == b"unaccepted"));
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains(&format!("{error:?}")));
        assert_eq!(budget.usage(), (0, 0, 0));
        let closed = session.handle(UiEvent::Link(LinkState::Closed), 2);
        assert!(closed.contains(&Action::Exit(1)));
    }
}

#[test]
fn client179_executor_paints_after_acceptance_before_next_action() {
    let trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let accepted = trace.clone();
    let sink: Sink = Box::new(move |stream, bytes| {
        if stream == 16 {
            accepted.lock().unwrap().push("accepted");
            assert!(bytes == b"a" || bytes == b"typed");
        }
        Ok(())
    });
    struct Writer {
        trace: Arc<std::sync::Mutex<Vec<&'static str>>>,
        bytes: Vec<u8>,
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.trace.lock().unwrap().push("write");
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut fixture = input_executor(sink, true);
    let mut session = predictive_input_session();
    let budget = qsh::input_ingress::IngressBudget::default();
    // Existing prediction policy starts its first epoch tentative. Confirm
    // one actual accepted byte/echo before asserting visible prediction.
    let warm = session.handle(UiEvent::Stdin(budget.admit_slice(b"a").unwrap()), 0);
    assert_eq!(
        apply_actions(
            warm,
            &mut Vec::new(),
            &mut fixture.links,
            &mut session,
            &mut Vec::new(),
            0
        ),
        None
    );
    let mut echo = encode_record(REC_DATA, b"a");
    echo.extend(encode_record(REC_ECHO_ACK, &1u64.to_be_bytes()));
    session.handle(UiEvent::Stream0(echo), 0);
    trace.lock().unwrap().clear();
    let mut actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"typed").unwrap()), 1);
    actions.push(Action::Write(b"later-marker".to_vec()));
    let mut output = Writer {
        trace: trace.clone(),
        bytes: Vec::new(),
    };
    let result = apply_actions(
        actions,
        &mut output,
        &mut fixture.links,
        &mut session,
        &mut Vec::new(),
        1,
    );
    drop(fixture);
    assert_eq!(result, None);
    assert_eq!(trace.lock().unwrap().first(), Some(&"accepted"));
    let typed = output
        .bytes
        .windows(5)
        .position(|part| part == b"typed")
        .expect("confirmed prediction is visible");
    let marker = output
        .bytes
        .windows(12)
        .position(|part| part == b"later-marker")
        .unwrap();
    assert!(
        typed < marker,
        "admission prediction paint retains action order"
    );
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_executor_partial_acceptance_and_pathdown_keep_exact_prefix() {
    for pathdown in [false, true] {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sent = seen.clone();
        let sink: Sink = Box::new(move |stream, bytes| {
            if stream == 16 {
                let mut seen = sent.lock().unwrap();
                if !pathdown && !seen.is_empty() {
                    return Err(client::channel::ChannelSendError::Full);
                }
                seen.push(bytes);
            }
            Ok(())
        });
        let mut fixture = input_executor(sink, true);
        let mut session = predictive_input_session();
        if pathdown {
            session.handle(UiEvent::Link(LinkState::PathDown), 0);
        }
        let budget = qsh::input_ingress::IngressBudget::default();
        let mut actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"first").unwrap()), 1);
        actions.extend(session.handle(UiEvent::Stdin(budget.admit_slice(b"second").unwrap()), 1));
        let mut output = Vec::new();
        let mut notices = Vec::new();
        let result = apply_actions(
            actions,
            &mut output,
            &mut fixture.links,
            &mut session,
            &mut notices,
            1,
        );
        drop(fixture);
        let expected = if pathdown {
            vec![b"first".to_vec(), b"second".to_vec()]
        } else {
            vec![b"first".to_vec()]
        };
        assert_eq!(*seen.lock().unwrap(), expected);
        assert_eq!(result, if pathdown { None } else { Some(1) });
        assert_eq!(notices.len(), usize::from(!pathdown));
        if !pathdown {
            assert!(!output.windows(6).any(|part| part == b"second"));
        }
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}

#[test]
fn client179_executor_nonready_target_refuses_before_sink() {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sent = seen.clone();
    let sink: Sink = Box::new(move |stream, bytes| {
        if stream == 16 {
            sent.lock().unwrap().push(bytes);
        }
        Ok(())
    });
    let mut fixture = input_executor(sink, false);
    let mut session = predictive_input_session();
    let budget = qsh::input_ingress::IngressBudget::default();
    let actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"nope").unwrap()), 1);
    let mut notices = Vec::new();
    let result = apply_actions(
        actions,
        &mut Vec::new(),
        &mut fixture.links,
        &mut session,
        &mut notices,
        1,
    );
    drop(fixture);
    assert_eq!(result, Some(1));
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(notices.len(), 1);
    assert!(notices[0].contains("NotReady"));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_deferred_resize_failure_flushes_prior_output_then_exits_locally() {
    use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
    use transport::shell_frame::{encode_shell, ShellRecord};
    let failure = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = failure.clone();
    let mut owner = ChannelSession::new(QshSubstrate::new(move |_, _| {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            Err(client::channel::ChannelSendError::Full)
        } else {
            Ok(())
        }
    }));
    owner.open_shell(20, 5).unwrap();
    owner.on_event(client::channel::SubstrateEvent::Opened(16));
    let geometry = GeometryRecord {
        instance: ChannelInstance::new(1).unwrap(),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 20,
        rows: 5,
    };
    owner.on_bytes(16, &encode_shell(&ShellRecord::Geometry(geometry)).unwrap());
    owner.resize(16, 40, 5).unwrap();
    assert_eq!(
        owner.resize(16, 60, 5).unwrap(),
        client::channel::ResizeDisposition::Coalesced
    );
    failure.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut batch = encode_shell(&ShellRecord::Data(b"prior-output".to_vec())).unwrap();
    batch.extend(
        encode_shell(&ShellRecord::Geometry(GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Applied,
            cols: 40,
            ..geometry
        }))
        .unwrap(),
    );
    let mut session = geometry_session();
    session.on_channel_ready(16, 0);
    let actions = channel_events(
        owner.on_bytes(16, &batch),
        &mut Some(16),
        &mut session,
        &mut Vec::new(),
        &|| 1,
    );
    let (_home, mut links) = input_executor_links();
    let mut output = Vec::new();
    let mut notices = Vec::new();
    assert_eq!(
        apply_actions(
            actions,
            &mut output,
            &mut links,
            &mut session,
            &mut notices,
            1
        ),
        Some(1)
    );
    assert!(output.windows(12).any(|part| part == b"prior-output"));
    assert_eq!(notices.len(), 1);
    assert!(notices[0].contains("Full"));
    assert!(!notices[0].contains("protocol failure"));
    assert!(session
        .handle(UiEvent::Link(LinkState::Closed), 2)
        .contains(&Action::Exit(1)));
}

#[test]
fn client179_actual_session_gone_stop_discards_pending_before_exit() {
    let (_home, mut links) = input_executor_links();
    let mut session = geometry_session();
    session.on_channel_ready(16, 0);
    session.on_link_gone(1);
    let budget = qsh::input_ingress::IngressBudget::default();
    assert!(session
        .handle(
            UiEvent::Stdin(budget.admit_slice(b"never cold replay").unwrap()),
            2
        )
        .is_empty());
    let actions = links.obey(Order::Stop(Stop::SessionGone { addr: 0 }), &mut session, 3);
    let mut notices = Vec::new();
    let exit = apply_actions(
        actions,
        &mut Vec::new(),
        &mut links,
        &mut session,
        &mut notices,
        3,
    );
    assert_eq!(exit, Some(13));
    assert_eq!(links.replacement_at, Some(0));
    assert_eq!(
        budget.usage(),
        (0, 0, 0),
        "confirmed loss refunds while Session is still alive"
    );
    assert_eq!(
        notices
            .iter()
            .filter(|notice| notice.contains("pending input"))
            .count(),
        1
    );
    let again = links.obey(Order::Stop(Stop::SessionGone { addr: 0 }), &mut session, 4);
    apply_actions(
        again,
        &mut Vec::new(),
        &mut links,
        &mut session,
        &mut notices,
        4,
    );
    assert_eq!(
        notices
            .iter()
            .filter(|notice| notice.contains("pending input"))
            .count(),
        1
    );
    assert!(session.on_channel_ready(16, 5).is_empty());
}

#[test]
fn recovery206_local_failure_restores_and_exits_despite_failing_resize_sink() {
    for failure in [
        session::LocalInputFailure::IngressFull,
        session::LocalInputFailure::PendingFull,
    ] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fail = armed.clone();
        let sink: Sink = Box::new(move |_, _| {
            if fail.load(std::sync::atomic::Ordering::SeqCst) {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(client::channel::ChannelSendError::Full)
            } else {
                Ok(())
            }
        });
        let mut fixture = input_executor(sink, true);
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut session = predictive_input_session();
        session.handle(UiEvent::Resized { cols: 70, rows: 24 }, 0);
        let actions = session.handle(UiEvent::InputFailure(failure), 1);
        let mut output = Vec::new();
        let mut notices = Vec::new();
        assert_eq!(
            apply_actions(
                actions,
                &mut output,
                &mut fixture.links,
                &mut session,
                &mut notices,
                1
            ),
            Some(1)
        );
        assert!(fixture.links.keep);
        assert_eq!(notices.len(), 1);
        assert!(!output.is_empty(), "terminal restored");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "local failure teardown never attempts remote writes"
        );
    }
}
