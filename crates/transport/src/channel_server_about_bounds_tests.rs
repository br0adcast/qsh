#[derive(Clone, Copy)]
enum AboutBehavior {
    MaximumArchitecture,
    None,
    Panic,
    LongArchitecture,
    InvalidArchitecture,
}
struct AboutProvider {
    inner: Arc<FakeDaemon>,
    behavior: AboutBehavior,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
}
impl AboutProvider {
    fn new(behavior: AboutBehavior) -> Arc<Self> {
        Arc::new(Self {
            inner: FakeDaemon::new(),
            behavior,
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
        })
    }
}
impl DaemonUpdates for AboutProvider {
    fn about(&self) -> Option<About> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        let mut about = fake_about();
        match self.behavior {
            AboutBehavior::MaximumArchitecture => {
                about.arch = "a".repeat(crate::channel::MAX_ARCH_LEN)
            }
            AboutBehavior::None => return None,
            AboutBehavior::Panic => panic!("controlled metadata provider failure"),
            AboutBehavior::LongArchitecture => {
                about.arch = "a".repeat(crate::channel::MAX_ARCH_LEN + 1)
            }
            AboutBehavior::InvalidArchitecture => about.arch = "invalid/architecture".into(),
        }
        Some(about)
    }
    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.inner.offer(from, offer)
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

fn resource_context() -> AttachmentContext {
    AttachmentContext {
        features: crate::Features::CHANNEL_GEOMETRY | crate::Features::RESOURCE_LIMITS,
        ..AttachmentContext::default()
    }
}
fn about_pair() -> Fixture {
    let fixture = SessionIo::test_pair();
    fixture
        .1
        .try_send(SessionInbound::Live(resource_context()))
        .unwrap();
    fixture
}
async fn consumed_control(rx: &mut mpsc::UnboundedReceiver<SessionOutbound>, expected: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if matches!(rx.recv().await.expect("runner alive for consumption fence"), SessionOutbound::Consumed { stream_id: CONTROL_STREAM, n } if n == expected) { break; }
        }
    }).await.expect("control consumption fence reached");
}

#[tokio::test]
async fn capacity_about_provider_panic_and_invalid_metadata_have_typed_failure() {
    for behavior in [
        AboutBehavior::Panic,
        AboutBehavior::LongArchitecture,
        AboutBehavior::InvalidArchitecture,
    ] {
        let provider = AboutProvider::new(behavior);
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(provider.clone()),
        ));
        inbound
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        let response = next_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        drop(outbound);
        assert_eq!(
            response,
            ServerRecord::AboutUnavailable(crate::channel::AboutUnavailable::ProviderFailed)
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }
}

#[tokio::test]
async fn capacity_about_principal_job_denial_is_typed_before_provider_effect() {
    let provider = AboutProvider::new(AboutBehavior::Panic);
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let uid = io.principal().uid;
    let mut retained = Vec::new();
    for _ in 0..2 * crate::session_manager::MAX_SESSIONS_PER_OWNER {
        retained.push(
            crate::control_job::JobOwner::reserve(
                &global.session(uid),
                crate::control_budget::Job::About,
            )
            .unwrap(),
        );
    }
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    let response = next_control(&mut outbound).await;
    drop(inbound);
    runner.await.unwrap();
    drop((outbound, retained));
    assert_eq!(
        response,
        ServerRecord::AboutUnavailable(crate::channel::AboutUnavailable::ResourceExhausted)
    );
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "denied job launches no callback"
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_about_optional_none_stays_silent_after_actual_completion() {
    let provider = AboutProvider::new(AboutBehavior::None);
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.entered.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let changed = global.changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if global.retained_for_test().2 == 0 {
                break;
            }
            changed.await;
        }
    })
    .await
    .expect("actual completion releases the flight owner");
    let term = encode_client(&ClientRecord::Term("fixture".into()));
    let n = term.len();
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: term,
        }))
        .await
        .unwrap();
    let mut answered = false;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound
                .recv()
                .await
                .expect("runner alive after optional metadata completion")
            {
                SessionOutbound::Consumed {
                    stream_id: CONTROL_STREAM,
                    n: consumed,
                } if consumed == n => break,
                SessionOutbound::ReservedControl { .. }
                | SessionOutbound::CloseSession { .. }
                | SessionOutbound::ResourceExhausted { .. } => answered = true,
                _ => {}
            }
        }
    })
    .await
    .expect("post-completion Term fence reached");
    drop(inbound);
    runner.await.unwrap();
    while let Some(event) = outbound.recv().await {
        answered |= matches!(
            event,
            SessionOutbound::ReservedControl { .. }
                | SessionOutbound::CloseSession { .. }
                | SessionOutbound::ResourceExhausted { .. }
        );
    }
    assert!(
        !answered,
        "intentional provider None is not an unavailable result"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_about_legacy_provider_failure_requests_explicit_close() {
    let provider = AboutProvider::new(AboutBehavior::Panic);
    let (io, inbound, mut outbound) = channel_pair();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider),
    ));
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    let explicit_close = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound
                .recv()
                .await
                .expect("runner alive for legacy terminal request")
            {
                SessionOutbound::CloseSession { .. } => break true,
                SessionOutbound::ResourceExhausted { .. }
                | SessionOutbound::ProtocolFailure { .. } => break false,
                _ => {}
            }
        }
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    assert!(
        explicit_close.unwrap(),
        "legacy provider failure carries no unrelated abort classification"
    );
}

#[tokio::test]
async fn capacity_about_pending_input_credit_is_bounded_before_callback_effect() {
    let _reset = ResetAdmissionHooks;
    let provider = AboutProvider::new(AboutBehavior::Panic);
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let request = encode_client(&ClientRecord::AboutRequest);
    let window = control_input::INPUT_LIMIT;
    let bytes = (0..window)
        .map(|index| request[index % request.len()])
        .collect();
    let paused = Arc::new(tokio::sync::Notify::new());
    let fence = paused.clone();
    CONTROL_REFUND_BEFORE_SELECT
        .with(|slot| *slot.borrow_mut() = Some(Box::new(move || fence.notify_one())));
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: bytes,
        }))
        .await
        .unwrap();
    let blocked = tokio::time::timeout(std::time::Duration::from_secs(5), paused.notified()).await;
    let mut early_credit = 0;
    let mut early_terminal = false;
    while let Ok(event) = outbound.try_recv() {
        match event {
            SessionOutbound::Consumed {
                stream_id: CONTROL_STREAM,
                n,
            } => early_credit += n,
            SessionOutbound::ResourceExhausted { .. } | SessionOutbound::CloseSession { .. } => {
                early_terminal = true
            }
            _ => {}
        }
    }
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: vec![0],
        }))
        .await
        .unwrap();
    let mut credited = 0;
    let exhausted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound.recv().await.expect("runner alive for input limit") {
                SessionOutbound::Consumed {
                    stream_id: CONTROL_STREAM,
                    n,
                } => credited += n,
                SessionOutbound::ResourceExhausted { .. } => break,
                _ => {}
            }
        }
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    drop((outbound, held));
    assert!(blocked.is_ok(), "real input reached paused admission");
    assert_eq!(
        early_credit, 0,
        "unadmitted input must retain its receive credit"
    );
    assert!(
        !early_terminal,
        "ordinary saturation first applies backpressure"
    );
    assert!(
        exhausted.is_ok(),
        "the whole retained window has a bounded terminal outcome"
    );
    assert_eq!(
        credited,
        window + 1,
        "pending and rejected bytes settle exactly once on teardown"
    );
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "paused input starts no provider work"
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_about_warm_reset_settles_pending_and_partial_old_input_once() {
    let provider = AboutProvider::new(AboutBehavior::Panic);
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let request = encode_client(&ClientRecord::AboutRequest);
    let mut old = request.clone();
    old.extend_from_slice(&request[..2]);
    let old_n = old.len();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: old,
        }))
        .await
        .unwrap();
    let origin = AttachmentContext {
        generation: 1,
        session_id: 2,
        ..resource_context()
    };
    inbound
        .send(SessionInbound::ResumeReset(origin))
        .await
        .unwrap();
    let term = encode_client(&ClientRecord::Term("fixture".into()));
    let term_n = term.len();
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: term,
        }))
        .await
        .unwrap();
    let credits = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut credits = Vec::new();
        while credits.len() < 2 {
            if let SessionOutbound::Consumed {
                stream_id: CONTROL_STREAM,
                n,
            } = outbound
                .recv()
                .await
                .expect("runner alive for reset credit")
            {
                credits.push(n);
            }
        }
        credits
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    drop((outbound, held));
    assert_eq!(credits.unwrap(), vec![old_n, term_n]);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_about_held_provider_survives_warm_reset_without_stale_reply() {
    let provider = Arc::new(HeldAbout {
        inner: FakeDaemon::new(),
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let release = ReleaseAbout(provider.clone());
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    let request = encode_client(&ClientRecord::AboutRequest);
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    consumed_control(&mut outbound, request.len()).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.changed.notified(),
    )
    .await
    .unwrap();
    let replacement = AttachmentContext {
        generation: 1,
        session_id: 2,
        ..resource_context()
    };
    inbound
        .send(SessionInbound::ResumeReset(replacement))
        .await
        .unwrap();
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    consumed_control(&mut outbound, request.len()).await;
    drop(release);
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let SessionOutbound::ReservedControl {
                origin,
                bytes,
                delivery,
            } = outbound
                .recv()
                .await
                .expect("runner alive for shared provider reply")
            {
                drop(delivery); // Standalone fixture consumption, not a real peer ACK.
                let raw = RecordDeframer::for_control().push(&bytes).remove(0);
                break (origin, decode_server(&raw).unwrap());
            }
        }
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    drop(outbound);
    assert_eq!(
        response.unwrap(),
        (replacement, ServerRecord::About(fake_about()))
    );
    assert_eq!(provider.entered.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.completed.load(Ordering::SeqCst),
        1,
        "fixture returned after actual worker join"
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_about_maximum_metadata_fits_its_reserved_wire_envelope() {
    let provider = AboutProvider::new(AboutBehavior::MaximumArchitecture);
    let (io, inbound, mut outbound) = about_pair();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound
        .send(control(ClientRecord::AboutRequest))
        .await
        .unwrap();
    let response = next_control(&mut outbound).await;
    drop(inbound);
    runner.await.unwrap();
    let mut expected = fake_about();
    expected.arch = "a".repeat(crate::channel::MAX_ARCH_LEN);
    assert_eq!(response, ServerRecord::About(expected));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn capacity_about_waiter_limit_pauses_input_and_keeps_runner_responsive() {
    let _reset = ResetAdmissionHooks;
    let provider = Arc::new(HeldAbout {
        inner: FakeDaemon::new(),
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let release = ReleaseAbout(provider.clone());
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let paused = Arc::new(tokio::sync::Notify::new());
    let fence = paused.clone();
    CONTROL_REFUND_BEFORE_SELECT
        .with(|slot| *slot.borrow_mut() = Some(Box::new(move || fence.notify_one())));
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    let entries = crate::channel_timeline::ORDINARY_ENTRIES;
    let request = encode_client(&ClientRecord::AboutRequest);
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: request.repeat(entries + 1),
        }))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), paused.notified())
        .await
        .expect("waiter ceiling pauses the next real request");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        provider.changed.notified(),
    )
    .await
    .expect("one actual provider is held");
    let retained = global.retained_for_test();
    let entered_while_held = provider.entered.load(Ordering::SeqCst);
    // This metadata arrives independently of ordered application records. Its
    // positive barrier proves reply-room waiting does not block the main loop.
    inbound
        .send(SessionInbound::RepaintCutover {
            generation: 0,
            sequence: 77,
        })
        .await
        .unwrap();
    let mut credited = 0;
    let responsive = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound
                .recv()
                .await
                .expect("runner alive while About waits")
            {
                SessionOutbound::Consumed {
                    stream_id: CONTROL_STREAM,
                    n,
                } => credited += n,
                SessionOutbound::RepaintBarrier {
                    generation: 0,
                    sequence: 77,
                } => break,
                _ => {}
            }
        }
    })
    .await;
    drop(release);
    let mut replies = Vec::new();
    for _ in 0..=entries {
        replies.push(next_control(&mut outbound).await);
    }
    drop(inbound);
    runner.await.unwrap();
    drop(outbound);
    assert_eq!(retained, (entries * ABOUT_RECORD_MAX, entries, 1));
    assert_eq!(entered_while_held, 1);
    assert!(responsive.is_ok());
    assert_eq!(
        credited,
        entries * request.len(),
        "the unadmitted request retains its credit"
    );
    assert!(replies
        .iter()
        .all(|reply| *reply == ServerRecord::About(fake_about())));
    assert_eq!(
        provider.entered.load(Ordering::SeqCst),
        2,
        "the next flight starts only after the first actual join and entry refund"
    );
    assert_eq!(provider.completed.load(Ordering::SeqCst), 2);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
