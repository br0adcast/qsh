struct MultiplicityProvider {
    signal: tokio::sync::watch::Sender<crate::channel_server::RestartSignal>,
    entered: tokio::sync::Notify,
    completed: AtomicUsize,
    held: Mutex<std::sync::mpsc::Receiver<()>>,
}
impl crate::channel_server::DaemonUpdates for MultiplicityProvider {
    fn about(&self) -> Option<crate::channel::About> {
        self.entered.notify_one();
        let _ = self.held.lock().unwrap().recv();
        self.completed.fetch_add(1, Ordering::SeqCst);
        None
    }
    fn offer(
        &self,
        _: &Principal,
        _: &crate::channel::UpdateOffer,
    ) -> Result<Box<dyn crate::channel_server::UpdateTransfer>, crate::channel::UpdateAnswer> {
        Err(crate::channel::UpdateAnswer::NotAllowed)
    }
    fn restart_signal(&self) -> tokio::sync::watch::Receiver<crate::channel_server::RestartSignal> {
        self.signal.subscribe()
    }
    fn restart_joined(&self, _: u64) -> bool {
        false
    }
    fn channels_released(&self, _: u64) {
        panic!("no restart in multiplicity control")
    }
}
struct MultiplicityBackend {
    spawner: Arc<crate::channel_server::tests::FakeSpawner>,
    provider: Arc<MultiplicityProvider>,
    processed: Arc<Mutex<Option<Arc<SessionControl>>>>,
}
impl SessionBackend for MultiplicityBackend {
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        *self.processed.lock().unwrap() = Some(io.control().clone());
        Box::pin(crate::channel_server::run_channel_session_with(
            io,
            self.spawner.clone(),
            Some(self.provider.clone()),
        ))
    }
    fn consumption(&self) -> Consumption {
        Consumption::Explicit
    }
}
struct MultiplicityCleanup {
    spawner: Arc<crate::channel_server::tests::FakeSpawner>,
    shutdown: Shutdown,
    release: Option<std::sync::mpsc::Sender<()>>,
}
impl Drop for MultiplicityCleanup {
    fn drop(&mut self) {
        self.release.take();
        self.spawner.end_channel(16);
        self.shutdown.request();
    }
}
async fn multiplicity_control(
    rig: &mut DeliveryRig,
    greeting_seen: &mut bool,
) -> crate::channel::ServerRecord {
    let mut records = crate::shell_frame::RecordDeframer::for_control();
    let mut shell = crate::shell_frame::RecordDeframer::with_max_payload(64);
    let mut answer = None;
    let mut packet = vec![0; 65536];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            // Intentionally withhold every delivery ACK/credit after receipt.
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                match event {
                    Event::StreamData {
                        stream_id: crate::channel::CONTROL_STREAM,
                        data,
                    } => {
                        if let Some(raw) = records.push(&data).first() {
                            answer = Some(crate::channel::decode_server(raw).unwrap());
                        }
                    }
                    Event::StreamData {
                        stream_id: 16,
                        data,
                    } => {
                        for raw in shell.push(&data) {
                            if let crate::shell_frame::ShellRecord::Data(bytes) =
                                crate::shell_frame::decode_shell(raw).unwrap()
                            {
                                assert_eq!(bytes, b"hello from the shell");
                                *greeting_seen = true;
                            }
                        }
                        assert!(!shell.overflowed(), "bounded initial greeting records");
                    }
                    _ => {}
                }
            }
            // Drain the entire event batch: Opened and the greeting may be
            // delivered together. Returning at Opened would discard that proof.
            if *greeting_seen {
                if let Some(answer) = answer.take() {
                    return answer;
                }
            }
        }
    })
    .await
    .expect("actual control reply and shell greeting while provider remains held")
}

#[tokio::test(flavor = "current_thread")]
async fn capacity_reachable_warm_repaints_stay_bounded_while_provider_and_delivery_are_held() {
    use crate::channel::{
        encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, CONTROL_STREAM,
    };
    const STREAM: u8 = 16;
    let (release, held) = std::sync::mpsc::channel();
    let provider = Arc::new(MultiplicityProvider {
        signal: tokio::sync::watch::channel(crate::channel_server::RestartSignal::IDLE).0,
        entered: tokio::sync::Notify::new(),
        completed: AtomicUsize::new(0),
        held: Mutex::new(held),
    });
    let spawner = crate::channel_server::tests::FakeSpawner::new();
    let processed = Arc::new(Mutex::new(None));
    let mut rig = delivery_rig_with(
        crate::Features::SUPPORTED,
        Arc::new(MultiplicityBackend {
            spawner: spawner.clone(),
            provider: provider.clone(),
            processed: processed.clone(),
        }),
        |conn| conn.enable_geometry_for_test(),
    )
    .await;
    let mut cleanup = MultiplicityCleanup {
        spawner: spawner.clone(),
        shutdown: rig.lifecycle.shutdown.clone(),
        release: Some(release),
    };
    rig.client.enable_geometry_for_test();
    CONTROL_RELIABLE_PEAK.with(|peak| peak.set(0));
    rig.client_sends(CONTROL_STREAM, &encode_client(&ClientRecord::AboutRequest));
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified())
        .await
        .expect("actual provider entered before other operations");
    let open = encode_client(&ClientRecord::Open(OpenRequest {
        stream: STREAM,
        kind: ChannelKind::Shell,
        cols: 80,
        rows: 24,
        screen: true,
        command: vec![],
    }));
    rig.client_sends(CONTROL_STREAM, &open);
    // Opened alone does not prove the blocking reader's greeting was processed.
    // Require actual shell data so the first repaint consumes ordinary capacity,
    // rather than a valid data-free lifecycle checkpoint before that greeting.
    let mut greeting_seen = false;
    let opened = multiplicity_control(&mut rig, &mut greeting_seen).await;
    rig.client_sends(CONTROL_STREAM, &open);
    let refused = multiplicity_control(&mut rig, &mut greeting_seen).await;
    let mut samples = Vec::new();
    let mut terminal = None;
    let rounds = crate::channel_timeline::ORDINARY_ENTRIES + 1;
    for round in 1..=rounds {
        let (mut client, mut conn, msg2) = accepted_connection_with(
            &rig.server_kp,
            rig.token,
            rig.peer,
            crate::Features::SUPPORTED,
        );
        client.on_datagram(Instant::now(), rig.peer, &msg2[0].bytes);
        client.enable_geometry_for_test();
        conn.enable_geometry_for_test();
        client.set_default_consumption(Consumption::Explicit);
        // Prime actual receiver windows before handing this authenticated
        // connection to the bridge. ACK filler, withhold consumption credit.
        // Filler is bounded fixture data, not charged response production.
        let mut now = Instant::now();
        for stream in [CONTROL_STREAM, STREAM] {
            let mut out = conn.send(
                now,
                stream,
                &vec![0; crate::reliability::STREAM_WINDOW as usize],
            );
            for _ in 0..100 {
                for dg in std::mem::take(&mut out) {
                    for ack in client.on_datagram(now, rig.peer, &dg.bytes) {
                        out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
                    }
                }
                client.poll_events();
                now += Duration::from_millis(20);
                for ack in client.on_timeout(now) {
                    out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
                }
                out.extend(conn.on_timeout(now));
                if out.is_empty() && conn.stream_progress(stream).unacked == 0 {
                    break;
                }
            }
            assert_eq!(
                conn.stream_write_room(stream, crate::send_gate::PIPE_HIGH as usize),
                0
            );
            assert_eq!(conn.stream_progress(stream).unacked, 0);
        }
        let expected_session = conn.session_id();
        rig.ctl_tx
            .send(committed_attach(Box::new(conn), vec![], vec![]))
            .unwrap();
        rig.client = client;
        let mut packet = vec![0; 65536];
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let actual = processed.lock().unwrap().as_ref().unwrap().origin.lock().unwrap().attachment;
                if actual.session_id == expected_session && actual.generation == round as u64 { break; }
                tokio::select! {
                    received = rig.client_sock.recv_from(&mut packet) => {
                        let (len, source) = received.unwrap();
                        let _withheld = rig.client.on_datagram(Instant::now(), source, &packet[..len]);
                        for event in rig.client.poll_events() {
                            if let Event::SessionAborted(reason) = event { terminal = Some(reason); return; }
                        }
                    }
                    _ = tokio::task::yield_now() => {}
                }
            }
        }).await.unwrap_or_else(|_| panic!("reset round {round}, repaints {}, expected session {expected_session}, processed {:?}, usage {:?}, previous samples {samples:?}", spawner.repaint_count(), processed.lock().unwrap().as_ref().unwrap().origin.lock().unwrap().attachment, rig.lifecycle.control_budget.retained_for_test()));
        if terminal.is_some() {
            break;
        }
        // The real runner processes reset and subsequent enqueues in one
        // synchronous turn. This explicitly current-thread fixture cannot
        // observe its processed origin until that entire source turn yields. A backend
        // FIFO marker would be invalid here: the snapshot intentionally fences
        // that queue until withheld credit returns.
        samples.push(rig.lifecycle.control_budget.retained_for_test());
    }
    let repaints_after_churn = spawner.repaint_count();
    let completed_while_held = provider.completed.load(Ordering::SeqCst);
    let reliable_peak = CONTROL_RELIABLE_PEAK.with(|peak| peak.get());
    cleanup.release.take();
    spawner.end_channel(STREAM);
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("bridge joins after explicit stop")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), rig.lifecycle.drain())
        .await
        .expect("all actual provider and process workers joined")
        .unwrap();
    let final_usage = rig.lifecycle.control_budget.retained_for_test();
    drop(cleanup);
    assert_eq!(opened, ServerRecord::Opened { stream: STREAM });
    assert!(matches!(
        refused,
        ServerRecord::Refused { stream: STREAM, .. }
    ));
    assert_eq!(
        completed_while_held, 0,
        "other replies and resets ran while actual provider stayed blocked"
    );
    assert_eq!(provider.completed.load(Ordering::SeqCst), 1);
    assert!(
        terminal.is_none(),
        "valid bounded reset churn should remain admitted: {terminal:?}"
    );
    assert_eq!(samples.len(), rounds);
    assert_eq!(repaints_after_churn, crate::channel_timeline::ORDINARY_ENTRIES,
        "128 admitted geometry/repaint prefixes remain owned; reset129 is processed with bounded deferred repaint, not a fabricated extra lease");
    let snapshot = crate::channel::CHANNEL_SNAPSHOT_MAX + 5;
    assert!(
        samples
            .iter()
            .all(|&(bytes, entries, jobs)| bytes >= 3 * snapshot
                && bytes <= crate::control_budget::SESSION_BYTES
                && entries == 5
                && jobs == 1),
        "current snapshot3 + About1 + future terminal1, independent actual job: {samples:?}"
    );
    assert!(reliable_peak > 0 && reliable_peak <= crate::conn::SEND_HARD_CAP as u64);
    assert_eq!(final_usage, (0, 0, 0));
}

struct TerminalAfterSnapshot;
impl SessionBackend for TerminalAfterSnapshot {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            while let Some(event) = io.recv().await {
                if let SessionInbound::ResumeReset(origin) = event {
                    assert!(io.publish_resume_snapshot(origin, || {
                        crate::channel::ChannelSnapshot::new(vec![], vec![])
                    }));
                    io.resource_exhausted(origin);
                }
            }
        })
    }
}
#[tokio::test]
async fn capacity_reachable_terminal_abort_bypasses_snapshot_receive_fence_without_peer_credit() {
    let mut rig = delivery_rig_with(
        crate::Features::SUPPORTED,
        Arc::new(TerminalAfterSnapshot),
        |conn| conn.enable_geometry_for_test(),
    )
    .await;
    let (mut client, mut conn, msg2) = accepted_connection_with(
        &rig.server_kp,
        rig.token,
        rig.peer,
        crate::Features::SUPPORTED,
    );
    client.on_datagram(Instant::now(), rig.peer, &msg2[0].bytes);
    client.enable_geometry_for_test();
    conn.enable_geometry_for_test();
    client.set_default_consumption(Consumption::Explicit);
    let mut now = Instant::now();
    let mut out = conn.send(
        now,
        crate::channel::CONTROL_STREAM,
        &vec![0; crate::reliability::STREAM_WINDOW as usize],
    );
    for _ in 0..100 {
        for dg in std::mem::take(&mut out) {
            for ack in client.on_datagram(now, rig.peer, &dg.bytes) {
                out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
            }
        }
        client.poll_events();
        now += Duration::from_millis(20);
        for ack in client.on_timeout(now) {
            out.extend(conn.on_datagram(now, rig.peer, &ack.bytes));
        }
        out.extend(conn.on_timeout(now));
        if out.is_empty() && conn.stream_progress(crate::channel::CONTROL_STREAM).unacked == 0 {
            break;
        }
    }
    assert_eq!(
        conn.stream_write_room(
            crate::channel::CONTROL_STREAM,
            crate::send_gate::PIPE_HIGH as usize
        ),
        0
    );
    rig.ctl_tx
        .send(committed_attach(Box::new(conn), vec![], vec![]))
        .unwrap();
    rig.client = client;
    let mut packet = vec![0; 65536];
    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                if let Event::SessionAborted(reason) = event {
                    return reason;
                }
            }
        }
    })
    .await;
    let held_before_stop = rig.lifecycle.control_budget.retained_for_test();
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("explicitSTOP joins fenced bridge")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert_eq!(
        terminal.expect("authenticated terminal must bypass blocked snapshot credit"),
        crate::SessionAbortReason::ResourceExhausted,
        "actual held usage beforeSTOP: {held_before_stop:?}"
    );
    assert_eq!(rig.lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_reachable_priority_terminal_churn_retains_one_queued_alias_and_spares_replacement(
) {
    let (io, input, mut output) = SessionIo::test_pair();
    let control = io.control().clone();
    let key = generate_keypair();
    let now = Instant::now();
    let (_, mut replacement) = explicit_pair(&key, 0x26, "127.0.0.1:26".parse().unwrap(), now);
    let replacement_id = replacement.session_id();
    let replacement_generation = 1000;
    let mut emitted = Vec::new();
    for generation in 0..300 {
        let origin = AttachmentContext {
            generation,
            session_id: replacement_id.wrapping_add(1),
            features: crate::Features::SUPPORTED,
        };
        io.set_control_origin(origin);
        io.resource_exhausted(origin);
        io.close_session(origin);
        tokio::time::timeout(Duration::from_secs(5), control.terminal_ready.notified())
            .await
            .expect("each latest fixed mailbox publication wakes independently of queued alias");
        let request = control.take_priority_abort().unwrap();
        assert_eq!(
            request,
            TerminalRequest {
                origin,
                disposition: TerminalDisposition::ResourceExhausted
            }
        );
        assert!(control.origin.lock().unwrap().abort_notification_queued);
        apply_terminal_request(
            &mut replacement,
            replacement_generation,
            &control.budget,
            request,
            now,
            &mut emitted,
        );
    }
    let mut aliases = Vec::new();
    while let Ok(event) = output.try_recv() {
        aliases.push(event);
    }
    let permit = control
        .budget
        .reserve(crate::control_budget::Response::Ordinary(1));
    let actual_state = replacement.state();
    drop((io, input, output));
    assert_eq!(
        aliases.len(),
        1,
        "priority reads never clear the outstanding ordinary alias latch"
    );
    assert!(matches!(
        aliases[0],
        SessionOutbound::ResourceExhausted { .. }
    ));
    assert!(
        emitted.is_empty(),
        "stale requests emit no replacement termination"
    );
    assert_eq!(actual_state, LinkState::Live);
    assert!(
        permit.is_ok(),
        "stale request must not retire replacement budget"
    );
}
