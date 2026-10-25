use super::*;
use std::ops::Deref;

struct ClientGuard(Option<StdClient>);
impl Deref for ClientGuard {
    type Target = StdClient;
    fn deref(&self) -> &StdClient {
        self.0.as_ref().unwrap()
    }
}
impl Drop for ClientGuard {
    fn drop(&mut self) {
        if let Some(client) = &self.0 {
            client.detach();
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Notice {
    Failure(InputFailure),
    Live,
    Closed,
}
struct WakeEvents(Mutex<mpsc::Sender<Notice>>);
impl ClientEvents for WakeEvents {
    fn on_input_failure(&self, failure: InputFailure) {
        self.0
            .lock()
            .unwrap()
            .send(Notice::Failure(failure))
            .unwrap();
    }
    fn on_bytes(&self, _: u8, _: Vec<u8>) {
        panic!("quiet fixture received bytes");
    }
    fn on_state(&self, state: LinkState) {
        let notice = match state {
            LinkState::Live => Some(Notice::Live),
            LinkState::Closed => Some(Notice::Closed),
            _ => None,
        };
        if let Some(notice) = notice {
            let _ = self.0.lock().unwrap().send(notice);
        }
    }
    fn on_stats(&self, _: Stats) {}
    fn on_reset(&self, _: u8) {}
}
fn fixture(control: Arc<wait::TestControl>) -> (ClientGuard, UdpSocket, mpsc::Receiver<Notice>) {
    fixture_with_budget(control, None)
}
fn fixture_with_budget(
    control: Arc<wait::TestControl>,
    budget: Option<ClientInputBudget>,
) -> (ClientGuard, UdpSocket, mpsc::Receiver<Notice>) {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (tx, rx) = mpsc::channel();
    let client_key = crate::handshake::generate_keypair();
    let server_key = crate::handshake::generate_keypair();
    let client = StdClient::connect_with(
        peer.local_addr().unwrap(),
        client_cfg(client_key.private, server_key.public),
        [200; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(WakeEvents(Mutex::new(tx))),
        None,
        DriverSetup {
            wait_control: Some(control),
            input_budget: budget,
            ..DriverSetup::default()
        },
    );
    (ClientGuard(Some(client)), peer, rx)
}

#[test]
fn wake300_every_command_dispatches_without_udp_or_timer_fallback() {
    let control = Arc::new(wait::TestControl::default());
    let (client, _quiet_peer, _events) = fixture(control.clone());
    control.wait_parked(1);
    client.send_bytes(30, vec![1, 2]).unwrap();
    control.wait_commands(1);
    client.consumed(30, 2);
    control.wait_commands(2);
    client.rebind();
    control.wait_commands(3);
    client.set_death_after(Duration::from_secs(10));
    control.wait_commands(4);
    client.set_paths(Vec::new());
    control.wait_commands(5);
    client.set_stream_class(30, StreamClass::Bulk);
    control.wait_commands(6);
    assert!(client.stream_progress(30).is_some());
    assert_eq!(
        client.use_road("127.0.0.1:1".parse().unwrap()),
        UseRoadOutcome::NoSession
    );
    control.wait_commands(8);
    assert_eq!(
        control.commands(),
        vec![
            "Send:30",
            "Consumed",
            "Rebind",
            "SetDeathAfter",
            "SetPaths",
            "SetStreamClass",
            "StreamProgress",
            "UseRoad"
        ]
    );
    assert!(control.registrations() >= 2);
}

#[test]
fn wake300_coalesced_commands_preserve_fifo_across_bounded_turns() {
    let control = Arc::new(wait::TestControl::default());
    control.hold(true);
    let (client, _quiet_peer, _events) = fixture(control.clone());
    control.wait_parked(1);
    let count = 3 * INPUT_TURN + 1;
    for index in 0..count {
        client
            .send_bytes(100 + index as u8, vec![index as u8])
            .unwrap();
    }
    control.hold(false);
    control.wait_commands(count);
    // An empty queue must park again after its one immediate service pass.
    control.wait_parked(0);
    assert_eq!(
        control.commands(),
        (0..count)
            .map(|i| format!("Send:{}", 100 + i))
            .collect::<Vec<_>>()
    );
}

#[test]
fn wake300_close_detach_and_implicit_sender_drop_wake_quiet_driver() {
    for detach in [false, true] {
        let control = Arc::new(wait::TestControl::default());
        let (client, _quiet_peer, _events) = fixture(control.clone());
        control.wait_parked(1);
        if detach {
            client.detach();
        } else {
            client.close();
        }
        assert!(client.is_gone());
    }
    let control = Arc::new(wait::TestControl::default());
    let (client, _quiet_peer, _events) = fixture(control.clone());
    control.wait_parked(1);
    let join = client.handle.lock().unwrap().take().unwrap();
    // Drop only the external sender, without invoking explicit close/detach.
    let mut guard = client;
    let client = guard.0.take().unwrap();
    drop(client);
    join.join().unwrap();
}

#[test]
fn wake300_notify_failure_keeps_admission_and_terminates_on_actual_stats_deadline() {
    let control = Arc::new(wait::TestControl::default());
    let (client, _quiet_peer, events) = fixture(control.clone());
    control.wait_parked(1);
    let maximum = control.now() + STATS_HEARTBEAT;
    assert!(control.deadline() <= maximum);
    control.fail_notify();
    assert!(
        client.send_bytes(30, vec![1, 2, 3]).is_ok(),
        "enqueue already accepted ownership"
    );
    let later = client.send_bytes(30, vec![4, 5]).unwrap_err();
    assert_eq!(later.reason, SendBlocked::Gone);
    assert_eq!(later.data, vec![4, 5]);
    control.advance(STATS_HEARTBEAT);
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        Notice::Failure(InputFailure::DriverUnavailable)
    );
    assert_eq!(
        events.recv_timeout(Duration::from_secs(5)).unwrap(),
        Notice::Closed
    );
    assert!(
        control.commands().is_empty(),
        "failed notifier must not dispatch accepted data before failing"
    );
}

#[test]
fn wake300_deadline_selection_includes_real_stats_in_every_state_and_zero_due_work() {
    let now = Instant::now();
    assert_eq!(
        next_wait_deadline(now, None, None, now, false),
        now + STATS_HEARTBEAT
    );
    let core = now + Duration::from_millis(20);
    let handshake = now + Duration::from_millis(10);
    assert_eq!(
        next_wait_deadline(now, Some(core), Some(handshake), now, false),
        handshake
    );
    assert_eq!(next_wait_deadline(now, Some(core), None, now, false), core);
    assert_eq!(next_wait_deadline(now, None, None, now, true), now);
    let due = now - Duration::from_millis(1);
    assert_eq!(next_wait_deadline(now, Some(due), None, now, false), due);
    let long_intended_sleep = now + Duration::from_secs(60);
    assert!(!freeze_late(long_intended_sleep, now, long_intended_sleep));
    let already_overdue = now + Duration::from_secs(10);
    assert!(!freeze_late(now, already_overdue, already_overdue));
    assert!(!freeze_late(now, now, now + FREEZE_RESUME_AFTER));
    assert!(freeze_late(
        now,
        now,
        now + FREEZE_RESUME_AFTER + Duration::from_nanos(1)
    ));
}

#[test]
fn wake300_fake_clock_distinguishes_intended_waits_from_a_late_freeze() {
    let control = Arc::new(wait::TestControl::default());
    let (client, _quiet_peer, _events) = fixture(control.clone());
    control.wait_parked(1);
    for turn in 2..=3 {
        control.advance(HANDSHAKE_RETRANSMIT);
        control.wait_parked(turn);
        assert_eq!(control.registrations(), 1);
    }
    control.advance(HANDSHAKE_RETRANSMIT + FREEZE_RESUME_AFTER + Duration::from_millis(1));
    control.wait_parked(4);
    assert_eq!(control.registrations(), 2);
    client.detach();
}

#[test]
fn wake300_receive_mode_restore_failure_never_returns_a_batch_for_sending() {
    let mut modes = Vec::new();
    let mut sent = false;
    let result = with_receive_mode(
        |nonblocking| {
            modes.push(nonblocking);
            if nonblocking {
                Ok(())
            } else {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        },
        || vec![1, 2, 3],
    );
    if result.is_ok() {
        sent = true;
    }
    assert!(
        result.is_err(),
        "an un-restored socket must never reach send_all"
    );
    assert!(!sent);
    assert_eq!(modes, vec![true, false]);
}

#[test]
fn wake300_receive_mode_entry_failure_does_not_attempt_a_read() {
    let mut read = false;
    let result = with_receive_mode(
        |_| Err(std::io::ErrorKind::PermissionDenied.into()),
        || {
            read = true;
        },
    );
    assert!(result.is_err());
    assert!(!read);
}

#[test]
fn wake300_native_read_budget_rearms_for_datagrams_left_in_the_socket() {
    let wake = Arc::new(wait::Notifier::default());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    crate::udp_buffers::tune_udp_buffers(&socket);
    let wait = wait::DriverWait::new(socket, &wake).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for value in 0..READY_DRAIN_MAX + 3 {
        sender
            .send_to(&[value as u8], wait.socket().local_addr().unwrap())
            .unwrap();
    }
    assert!(wait.wait(Instant::now() + Duration::from_secs(5)).unwrap());
    let server = crate::handshake::generate_keypair();
    let client = crate::handshake::generate_keypair();
    let mut connection = Connection::new(client_cfg(client.private, server.public));
    let mut bytes = [0u8; RECV_BUF_LEN];
    drain_ready(
        wait.socket(),
        &mut connection,
        &mut bytes,
        READY_DRAIN_MAX,
        &wait::Clock::default(),
    )
    .unwrap();
    wait.socket().set_nonblocking(true).unwrap();
    let (length, _) = wait.socket().peek_from(&mut bytes).unwrap();
    wait.socket().set_nonblocking(false).unwrap();
    assert_eq!(&bytes[..length], &[READY_DRAIN_MAX as u8]);
    assert!(wait.wait(Instant::now() + Duration::from_secs(5)).unwrap());
    drain_ready(
        wait.socket(),
        &mut connection,
        &mut bytes,
        READY_DRAIN_MAX,
        &wait::Clock::default(),
    )
    .unwrap();
    assert!(!wait.wait(Instant::now()).unwrap());
}

// Deliberate framing sentinels, never a credential or valid signature.
struct WakeSigner(bool);
impl AuthSigner for WakeSigner {
    fn sign(
        &self,
        hash: &[u8; 32],
        _: Option<&[u8; AUTH_NONCE_LEN]>,
    ) -> Result<AuthRecord, AuthError> {
        if self.0 {
            Ok(AuthRecord {
                public_key: b"synthetic public type".to_vec(),
                signature: hash.to_vec(),
                v2: None,
            })
        } else {
            Err(AuthError::Backend("injected signer refusal".into()))
        }
    }
}
#[test]
fn wake300_auth_signer_success_and_failure_wake_the_separate_result_channel() {
    for success in [false, true] {
        let control = Arc::new(wait::TestControl::default());
        let wake = Arc::new(wait::Notifier::default());
        let wait = wait::DriverWait::controlled(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            &wake,
            control.clone(),
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();
        let tx = wait::WakeSender::new(tx, wake);
        let signer = spawn_auth_signing(7, [8; 32], None, Arc::new(WakeSigner(success)), tx);
        assert!(!wait.wait(control.now() + STATS_HEARTBEAT).unwrap());
        signer.join().unwrap();
        let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.generation, 7);
        assert_eq!(result.record.is_some(), success);
    }
}

#[test]
fn wake300_late_auth_sender_does_not_retain_backend_or_external_command_sender() {
    let control = Arc::new(wait::TestControl::default());
    let wake = Arc::new(wait::Notifier::default());
    let wait =
        wait::DriverWait::controlled(UdpSocket::bind("127.0.0.1:0").unwrap(), &wake, control)
            .unwrap();
    let (tx, rx) = mpsc::channel::<AuthResult>();
    let tx = wait::WakeSender::new(tx, wake.clone());
    drop(wait);
    assert!(!wake.backend_alive());
    drop(rx);
    let signer = spawn_auth_signing(9, [8; 32], None, Arc::new(WakeSigner(true)), tx);
    signer.join().unwrap();
    assert!(!wake.backend_alive());
}

#[test]
fn wake300_registration_preserves_closed_startup_and_wait_failure_is_typed() {
    for registration in [true, false] {
        let control = Arc::new(wait::TestControl::default());
        if registration {
            control.fail_registration();
        }
        let (client, _quiet_peer, events) = fixture(control.clone());
        if !registration {
            control.wait_parked(1);
            control.fail_wait();
        }
        if !registration {
            assert_eq!(
                events.recv_timeout(Duration::from_secs(5)).unwrap(),
                Notice::Failure(InputFailure::DriverUnavailable)
            );
        }
        assert_eq!(
            events.recv_timeout(Duration::from_secs(5)).unwrap(),
            Notice::Closed
        );
        assert_eq!(
            client.send_bytes(30, vec![1]).unwrap_err().reason,
            SendBlocked::Gone
        );
    }
}

#[test]
fn wake300_review_notify_failure_returns_gone_even_when_admitted_record_filled_budget() {
    let mut results = Vec::new();
    for bounded in [false, true] {
        let control = Arc::new(wait::TestControl::default());
        let (client, _peer, events) =
            fixture_with_budget(control.clone(), Some(ClientInputBudget::with_limits(1, 1)));
        control.wait_parked(1);
        control.fail_notify();
        client.send_bytes(30, vec![1]).unwrap();
        let bytes = vec![2];
        let pointer = bytes.as_ptr();
        let result = if bounded {
            client.send_bytes_bounded(30, bytes, Duration::ZERO)
        } else {
            client.send_bytes(30, bytes)
        };
        let rejected = result.unwrap_err();
        let unchanged = rejected.data.as_ptr() == pointer && rejected.data == vec![2];
        control.advance(STATS_HEARTBEAT);
        let first = events.recv_timeout(Duration::from_secs(5));
        let second = events.recv_timeout(Duration::from_secs(5));
        client.detach();
        assert_eq!(
            first.unwrap(),
            Notice::Failure(InputFailure::DriverUnavailable)
        );
        assert_eq!(second.unwrap(), Notice::Closed);
        results.push((rejected.reason, unchanged));
    }
    assert_eq!(
        results,
        vec![(SendBlocked::Gone, true), (SendBlocked::Gone, true)]
    );
}

fn live_fixture(
    control: Arc<wait::TestControl>,
) -> (ClientGuard, UdpSocket, mpsc::Receiver<Notice>) {
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let client_key = crate::handshake::generate_keypair();
    let server_key = crate::handshake::generate_keypair();
    // Transport-only fake peer isolates local event delivery; auth acceptance
    // is independently covered by the real authenticated driver regressions.
    let features =
        Features::from_bits(Features::SUPPORTED.bits() & !Features::AUTH_ACCEPTED.bits());
    let mut server = Connection::new(ConnectionConfig {
        role: crate::conn::Role::Server,
        local_static_priv: server_key.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client_key.public]),
        features,
        required_features: Features::NONE,
    });
    let (tx, events) = mpsc::channel();
    let client = ClientGuard(Some(StdClient::connect_with(
        peer.local_addr().unwrap(),
        ConnectionConfig {
            role: crate::conn::Role::Client,
            local_static_priv: client_key.private,
            remote_static_pub: Some(server_key.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
            features,
            required_features: Features::NONE,
        },
        [201; 16],
        StartKind::Warm,
        Arc::new(OkBinder),
        Arc::new(WakeEvents(Mutex::new(tx))),
        None,
        DriverSetup {
            wait_control: Some(control.clone()),
            ..DriverSetup::default()
        },
    )));
    control.wait_parked(1);
    let mut bytes = [0u8; RECV_BUF_LEN];
    let (length, from) = peer.recv_from(&mut bytes).unwrap();
    for datagram in server.on_datagram(control.now(), from, &bytes[..length]) {
        peer.send_to(&datagram.bytes, datagram.to).unwrap();
    }
    let watchdog = Instant::now() + Duration::from_secs(5);
    loop {
        let entered = control.entries();
        control.readable();
        control.wait_parked(entered + 1);
        match events.try_recv() {
            Ok(Notice::Live) => break,
            Ok(other) => panic!("fixture did not become Live: {other:?}"),
            Err(mpsc::TryRecvError::Empty) => assert!(
                Instant::now() < watchdog,
                "loopback handshake did not arrive"
            ),
            Err(error) => panic!("fixture ended: {error}"),
        }
    }
    (client, peer, events)
}

#[test]
fn wake300_review_known_closed_after_command_is_delivered_before_another_timer() {
    let control = Arc::new(wait::TestControl::default());
    let (client, _peer, events) = live_fixture(control.clone());
    control.hold(true);
    control.wait_parked(0);
    client.set_death_after(Duration::ZERO);
    client.rebind();
    control.hold(false);
    let notice = events.recv_timeout(Duration::from_secs(5));
    client.detach();
    assert_eq!(notice.unwrap(), Notice::Closed);
}

#[test]
fn wake300_review_lowered_death_deadline_is_not_misclassified_as_sleep() {
    let control = Arc::new(wait::TestControl::default());
    let (client, _peer, events) = live_fixture(control.clone());
    client.set_death_after(Duration::from_secs(60));
    control.wait_commands(1);
    control.wait_parked(0);
    let start = control.now();
    while control.now().duration_since(start) < Duration::from_secs(10) {
        let entered = control.entries();
        let by = control.deadline().saturating_duration_since(control.now());
        control.advance(by);
        control.wait_parked(entered + 1);
    }
    assert_eq!(control.registrations(), 1);
    client.set_death_after(Duration::from_secs(1));
    let notice = events.recv_timeout(Duration::from_secs(5));
    client.detach();
    assert_eq!(notice.unwrap(), Notice::Closed);
    assert_eq!(
        control.registrations(),
        1,
        "an already-overdue timer is not a freeze"
    );
}
