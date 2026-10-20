#[tokio::test]
async fn withheld_control_acks_cannot_retain_more_than_the_existing_hard_cap() {
    use crate::channel::{encode_server, ServerRecord};
    use crate::conn::SEND_HARD_CAP;
    use crate::shell_frame::CONTROL_RECORD_MAX;

    // Each complete refusal fits the existing control-record limit. A backend
    // may supply this human-readable reason; the real bridge encodes it.
    let reason = "r".repeat(CONTROL_RECORD_MAX - 6);
    let encoded = encode_server(&ServerRecord::Refused {
        stream: 16,
        reason: reason.clone(),
    });
    assert_eq!(encoded.len(), CONTROL_RECORD_MAX);
    let records = SEND_HARD_CAP / encoded.len() + 2;
    const FENCE: u64 = 0x26;
    let attempted = Arc::new(AtomicUsize::new(0));

    struct Refusals {
        reason: String,
        records: usize,
        attempted: Arc<AtomicUsize>,
        ended: mpsc::Sender<()>,
        first_observed: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }
    impl SessionBackend for Refusals {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let reason = self.reason.clone();
            let records = self.records;
            let attempted = self.attempted.clone();
            let ended = self.ended.clone();
            let first_observed = self.first_observed.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let mut first_observed = Some(first_observed);
                let mut sent = false;
                while let Some(event) = io.recv().await {
                    if let SessionInbound::Live(origin) = event {
                        if !sent {
                            sent = true;
                            for _ in 0..records {
                                io.channel_refused(origin, 16, reason.clone());
                                attempted.fetch_add(1, Ordering::SeqCst);
                                if let Some(observed) = first_observed.take() {
                                    // Retain real first-record debt before the
                                    // remaining burst may trigger priority abort.
                                    let _ = observed.await;
                                }
                            }
                            io.notify_delivered(CONTROL_STREAM, FENCE);
                        }
                    }
                }
                let _ = ended.send(()).await;
            })
        }
    }

    CONTROL_RELIABLE_PEAK.with(|peak| peak.set(0));
    CONTROL_PRODUCER_FENCE.with(|fence| fence.set(None));
    let (ended, mut end_rx) = mpsc::channel(1);
    let (first_observed, first_receipt) = tokio::sync::oneshot::channel();
    let mut first_observed = Some(first_observed);
    let mut rig = delivery_rig(
        Arc::new(Refusals {
            reason,
            records,
            attempted: attempted.clone(),
            ended,
            first_observed: Mutex::new(Some(first_receipt)),
        }),
        |_| {},
    )
    .await;
    // Observe real packets while discarding every generated ACK/CREDIT. The
    // bridge fence proves old source processed the burst; bounded source may
    // instead terminate explicitly before taking the final marker.
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        let mut packet = vec![0u8; 65536];
        loop {
            if CONTROL_PRODUCER_FENCE.with(|fence| fence.get()) == Some(FENCE) {
                return None;
            }
            tokio::select! {
                received = rig.client_sock.recv_from(&mut packet) => {
                    let (len, source) = received.unwrap();
                    let _withheld = rig.client.on_datagram(Instant::now(), source, &packet[..len]);
                    for event in rig.client.poll_events() {
                        if matches!(&event, Event::StreamData { stream_id: CONTROL_STREAM, data } if !data.is_empty()) {
                            if let Some(observed) = first_observed.take() { let _ = observed.send(()); }
                        }
                        if let Event::SessionAborted(reason) = event {
                            return Some(reason);
                        }
                    }
                }
                _ = tokio::task::yield_now() => {}
            }
        }
    })
    .await;
    let peak = CONTROL_RELIABLE_PEAK.with(|peak| peak.get());
    // Drop all fixture routes/control/output senders, then await backend exit.
    // No OS children or blocking workers are launched by this backend.
    drop(first_observed.take()); // Release the producer on every fixture result.
    drop(rig);
    tokio::time::timeout(Duration::from_secs(5), end_rx.recv())
        .await
        .expect("fixture backend terminates after bridge teardown")
        .expect("fixture backend reported completion");
    assert!(
        reached.is_ok(),
        "the bridge must actually retain the fixture replies"
    );
    assert_eq!(attempted.load(Ordering::SeqCst), records);
    assert!(
        peak >= encoded.len() as u64,
        "one complete valid record must be retained by real reliable output"
    );
    assert!(
        peak <= SEND_HARD_CAP as u64,
        "reliable control debt retained {peak} bytes beyond existing cap {SEND_HARD_CAP}"
    );
    assert_eq!(
        reached.unwrap(),
        Some(crate::SessionAbortReason::ResourceExhausted),
        "raw producer overload has an explicit authenticated bounded outcome"
    );
}

#[test]
fn capacity_owned_callback_survives_retired_receiver_and_registration_during_drain() {
    use std::future::poll_fn;
    use std::task::Poll;
    use tokio::sync::oneshot;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (pending_parent, pending_worker) = runtime.block_on(async {
        let (io, inbound, outbound) = SessionIo::test_pair();
        let lifecycle = io.lifecycle.clone();
        let (parent_release, parent_held) = oneshot::channel::<()>();
        // Dropping this sender releases the real blocking callback on all exits.
        let (worker_release, worker_held) = std::sync::mpsc::sync_channel::<()>(0);
        let (entered_tx, entered_rx) = oneshot::channel::<()>();
        let (result_tx, result_rx) = oneshot::channel::<()>();
        let (joined_tx, joined_rx) = oneshot::channel::<()>();
        drop(result_rx);
        drop(inbound);
        drop(outbound);
        lifecycle.spawn(async move {
            let _ = parent_held.await;
            io.spawn_owned(async move {
                let work = tokio::task::spawn_blocking(move || {
                    let _ = entered_tx.send(());
                    let _ = worker_held.recv();
                });
                // A stale result receiver must not cancel or detach this join.
                work.await.unwrap();
                let _ = result_tx.send(());
                let _ = joined_tx.send(());
            });
        });
        let mut drain = Box::pin(lifecycle.drain());
        let pending_parent = poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await;
        lifecycle.shutdown.request();
        drop(parent_release);
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .expect("real callback entered")
            .unwrap();
        // The registered parent has now returned; only the supervisor can retain custody.
        let pending_worker = poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await;
        drop(worker_release);
        // Join even on the old implementation before checking the RED outcome.
        tokio::time::timeout(Duration::from_secs(5), joined_rx)
            .await
            .expect("released callback was actually joined")
            .unwrap();
        if pending_worker {
            tokio::time::timeout(Duration::from_secs(5), drain)
                .await
                .expect("owned callback drain completes after actual join")
                .unwrap();
        }
        (pending_parent, pending_worker)
    });
    drop(runtime);
    assert!(
        pending_parent,
        "drain cannot pass an already registered publisher"
    );
    assert!(
        pending_worker,
        "retired result receiver detached a still-running callback from drain"
    );
}

#[test]
fn capacity_boundary_retired_tiny_replies_keep_the_global_entry_ceiling() {
    use crate::control_budget::GLOBAL_RESPONSE_ENTRIES;
    let lifecycle = Arc::new(Lifecycle::default());
    let record =
        crate::channel::encode_server(&crate::channel::ServerRecord::ExitStatusUnavailable {
            stream: 16,
        });
    assert_eq!(record.len(), 6);
    let mut held = Vec::new();
    while held.len() < GLOBAL_RESPONSE_ENTRIES {
        let (mut io, _inbound, mut outbound) = SessionIo::test_pair();
        io.lifecycle = lifecycle.clone();
        let remaining =
            (GLOBAL_RESPONSE_ENTRIES - held.len()).min(crate::channel_timeline::ORDINARY_ENTRIES);
        for _ in 0..remaining {
            io.send(CONTROL_STREAM, record.clone());
        }
        drop(io);
        while let Ok(item) = outbound.try_recv() {
            assert!(matches!(item, SessionOutbound::ReservedControl { .. }));
            held.push(item);
        }
    }
    assert_eq!(
        lifecycle.control_budget.retained_for_test(),
        (2 * GLOBAL_RESPONSE_ENTRIES * 6, GLOBAL_RESPONSE_ENTRIES, 0)
    );
    let (mut io, _input, mut output) = SessionIo::test_pair();
    io.lifecycle = lifecycle.clone();
    for _ in 0..8 {
        io.send(CONTROL_STREAM, record.clone());
    }
    assert!(matches!(
        output.try_recv(),
        Ok(SessionOutbound::ResourceExhausted { .. })
    ));
    assert!(
        output.try_recv().is_err(),
        "one bounded terminal item, no repeated rejection queue"
    );
    drop(io);
    drop(held.pop());
    let (mut replacement, _input, mut output) = SessionIo::test_pair();
    replacement.lifecycle = lifecycle.clone();
    replacement.send(CONTROL_STREAM, record.clone());
    let refunded = output.try_recv().unwrap();
    assert!(matches!(refunded, SessionOutbound::ReservedControl { .. }));
    assert_eq!(
        lifecycle.control_budget.retained_for_test().1,
        GLOBAL_RESPONSE_ENTRIES
    );
    let (mut other, _input, mut output) = SessionIo::test_pair();
    other.lifecycle = lifecycle.clone();
    other.send(CONTROL_STREAM, record);
    assert!(matches!(
        output.try_recv(),
        Ok(SessionOutbound::ResourceExhausted { .. })
    ));
    drop((replacement, other, held, refunded));
    assert_eq!(lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

struct FiniteControlBackend;
impl SessionBackend for FiniteControlBackend {
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        io.send(
            CONTROL_STREAM,
            crate::channel::encode_server(&crate::channel::ServerRecord::Restarting),
        );
        Box::pin(async {})
    }
}

#[tokio::test]
async fn capacity_boundary_backend_eof_retains_ack_debt_and_stop_joins_without_peer_ack() {
    CONTROL_BACKEND_EOF.with(|count| count.set(0));
    CONTROL_RELIABLE_PEAK.with(|peak| peak.set(0));
    let mut rig = delivery_rig(Arc::new(FiniteControlBackend), |_| {}).await;
    let (closed_sender, closed_receiver) = mpsc::unbounded_channel();
    drop(closed_receiver);
    drop(std::mem::replace(&mut rig.backend_out, closed_sender));
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        while CONTROL_BACKEND_EOF.with(|count| count.get()) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let before_stop = rig.lifecycle.control_budget.retained_for_test();
    let stayed_pending = !rig.bridge.is_finished();
    let eof_count = CONTROL_BACKEND_EOF.with(|count| count.get());
    let no_normal_end = rig.done_rx.try_recv().is_err();
    // STOP is a teardown signal, never a request to await an uncooperative ACK.
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("stopped bridge joins despite withheld ACK")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert!(reached.is_ok());
    assert!(
        stayed_pending && no_normal_end,
        "backend EOF cannot discard owed control"
    );
    assert_eq!(eof_count, 1, "the closed backend receiver must be masked");
    assert_eq!(
        before_stop,
        (10, 1, 0),
        "retired backend still owns real unacknowledged bytes"
    );
    assert_eq!(rig.lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_boundary_stale_overload_cannot_retire_a_replacement_attachment() {
    CONTROL_PRODUCER_FENCE.with(|fence| fence.set(None));
    let mut rig = delivery_rig(Arc::new(EchoBackend), |_| {}).await;
    let old = AttachmentContext::for_connection(&rig.client, 0);
    // Attach has priority over queued backend items in the actual bridge.
    rig.attach_a_new_connection();
    rig.backend_sends(SessionOutbound::ResourceExhausted { origin: old });
    rig.backend_sends(SessionOutbound::CloseSession { origin: old });
    rig.backend_sends(SessionOutbound::NotifyDelivered {
        stream_id: CONTROL_STREAM,
        token: 0x2601,
    });
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if CONTROL_PRODUCER_FENCE.with(|fence| fence.get()) == Some(0x2601) {
                return true;
            }
            tokio::select! {
                _ = rig.done_rx.recv() => return false,
                _ = tokio::task::yield_now() => {}
            }
        }
    })
    .await;
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("replacement bridge joins on STOP")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert!(
        reached.unwrap(),
        "stale abort closed replacement before its progress marker"
    );
}

#[test]
fn capacity_boundary_repeated_attachments_keep_one_pending_overload_notification() {
    let (io, _inbound, mut outbound) = SessionIo::test_pair();
    let lifecycle = io.lifecycle.clone();
    let record = crate::channel::encode_server(&crate::channel::ServerRecord::Refused {
        stream: 16,
        reason: "r".repeat(crate::shell_frame::CONTROL_RECORD_MAX - 1),
    });
    assert_eq!(record.len(), crate::control_budget::MAX_RECORD);
    io.send(CONTROL_STREAM, record.clone());
    for generation in 1..=MAX_SESSIONS_TOTAL as u64 {
        io.set_control_origin(AttachmentContext {
            generation,
            session_id: generation + 1,
            features: crate::Features::SUPPORTED,
        });
        io.send(CONTROL_STREAM, record.clone());
    }
    let latest_abort = io.control().origin.lock().unwrap().requested_abort;
    drop(io);
    let mut items = Vec::new();
    while let Ok(item) = outbound.try_recv() {
        items.push(item);
    }
    let replies = items
        .iter()
        .filter(|item| matches!(item, SessionOutbound::ReservedControl { .. }))
        .count();
    let overloads = items
        .iter()
        .filter(|item| matches!(item, SessionOutbound::ResourceExhausted { .. }))
        .count();
    drop(items);
    assert_eq!(lifecycle.control_budget.retained_for_test(), (0, 0, 0));
    assert_eq!(
        latest_abort.unwrap().origin.generation,
        MAX_SESSIONS_TOTAL as u64
    );
    assert_eq!(replies, 1);
    assert_eq!(
        overloads, 1,
        "generation churn must not mint exempt terminal queue entries"
    );
}

struct EofControlBackend(bool);
impl SessionBackend for EofControlBackend {
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if self.0 {
            io.send(
                CONTROL_STREAM,
                crate::channel::encode_server(&crate::channel::ServerRecord::Restarting),
            );
        }
        Box::pin(async {})
    }
}

async fn authenticated_peer_observes_backend_eof(with_control: bool) {
    CONTROL_BACKEND_EOF.with(|count| count.set(0));
    let mut rig = delivery_rig(Arc::new(EofControlBackend(with_control)), |_| {}).await;
    let (closed_sender, closed_receiver) = mpsc::unbounded_channel();
    drop(closed_receiver);
    drop(std::mem::replace(&mut rig.backend_out, closed_sender));
    let mut delivered = Vec::new();
    let mut packet = vec![0; 65536];
    let eof = tokio::time::timeout(Duration::from_secs(5), async {
        while CONTROL_BACKEND_EOF.with(|count| count.get()) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let retained_before_ack = rig.lifecycle.control_budget.retained_for_test();
    // Service the real peer's ACK deadlines, without a fixed waiting window.
    // After the bridge joins, every final send has completed and its queued
    // packets can be drained without a negative timeout for missing Close.
    let joined = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let deadline = rig.client.next_timeout();
            let mut replies = tokio::select! {
                received = rig.client_sock.recv_from(&mut packet) => {
                    let (len, source) = received.unwrap();
                    rig.client.on_datagram(Instant::now(), source, &packet[..len])
                }
                _ = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => rig.client.on_timeout_if_due(Instant::now()),
                result = &mut rig.bridge => {
                    result.unwrap();
                    break;
                }
            };
            for event in rig.client.poll_events() {
                if let Event::StreamData {
                    stream_id: CONTROL_STREAM,
                    data,
                } = event
                {
                    delivered.extend(data);
                }
            }
            for reply in replies.drain(..) {
                let _ = rig.dg_tx.send(rig.peer, reply.bytes);
            }
        }
    })
    .await;
    // Always finish fixture custody before outcome assertions, including when
    // EOF or ACK progress failed. This backend launches no blocking workers.
    rig.lifecycle.shutdown.request();
    if joined.is_err() {
        tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
            .await
            .expect("fixture STOP joins bridge")
            .unwrap();
    }
    rig.lifecycle.drain().await.unwrap();
    while let Ok((len, source)) = rig.client_sock.try_recv_from(&mut packet) {
        let _ = rig
            .client
            .on_datagram(Instant::now(), source, &packet[..len]);
        for event in rig.client.poll_events() {
            if let Event::StreamData {
                stream_id: CONTROL_STREAM,
                data,
            } = event
            {
                delivered.extend(data);
            }
        }
    }
    assert!(eof.is_ok(), "actual backend EOF reached the bridge");
    assert!(joined.is_ok(), "settled delivery permits graceful EOF");
    assert_eq!(
        retained_before_ack,
        if with_control { (10, 1, 0) } else { (0, 0, 0) }
    );
    let expected = if with_control {
        crate::channel::encode_server(&crate::channel::ServerRecord::Restarting)
    } else {
        Vec::new()
    };
    assert_eq!(delivered, expected, "admitted control precedes EOF");
    assert!(
        rig.client.closed_gracefully(),
        "authenticated peer must receive Close before backend EOF teardown"
    );
    assert!(rig.done_rx.try_recv().unwrap().graceful);
    assert_eq!(rig.lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_boundary_empty_backend_eof_sends_authenticated_close() {
    authenticated_peer_observes_backend_eof(false).await;
}

#[tokio::test]
async fn capacity_boundary_drained_control_backend_eof_sends_authenticated_close() {
    authenticated_peer_observes_backend_eof(true).await;
}

struct ExplicitTerminalBackend {
    close_first: bool,
}
impl SessionBackend for ExplicitTerminalBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let close_first = self.close_first;
        Box::pin(async move {
            while let Some(event) = io.recv().await {
                if let SessionInbound::Live(origin) = event {
                    if close_first {
                        io.close_session(origin);
                        io.resource_exhausted(origin);
                    } else {
                        io.resource_exhausted(origin);
                        io.close_session(origin);
                    }
                }
            }
        })
    }
}

#[tokio::test]
async fn capacity_terminal_first_request_preserves_explicit_close_or_resource_reason() {
    for close_first in [true, false] {
        let mut rig = delivery_rig(Arc::new(ExplicitTerminalBackend { close_first }), |_| {}).await;
        let mut reason = None;
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            let mut packet = vec![0; 65536];
            while rig.client.state() != LinkState::Closed {
                let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
                let _ = rig
                    .client
                    .on_datagram(Instant::now(), source, &packet[..len]);
                for event in rig.client.poll_events() {
                    if let Event::SessionAborted(value) = event {
                        reason = Some(value);
                    }
                }
            }
        })
        .await;
        rig.lifecycle.shutdown.request();
        tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
            .await
            .expect("terminal fixture bridge joins")
            .unwrap();
        rig.lifecycle.drain().await.unwrap();
        assert!(
            reached.is_ok(),
            "real authenticated terminal packet reaches peer"
        );
        assert!(rig.client.closed_gracefully());
        assert_eq!(
            reason,
            if close_first {
                None
            } else {
                Some(crate::SessionAbortReason::ResourceExhausted)
            },
            "first terminal request wins within one attachment"
        );
    }
}

#[test]
fn capacity_terminal_close_and_resource_share_one_notification_across_generations() {
    let (io, _input, mut output) = SessionIo::test_pair();
    for generation in 0..MAX_SESSIONS_TOTAL as u64 {
        let origin = AttachmentContext {
            generation,
            session_id: generation + 1,
            features: crate::Features::SUPPORTED,
        };
        io.set_control_origin(origin);
        if generation % 2 == 0 {
            io.close_session(origin);
            io.resource_exhausted(origin);
        } else {
            io.resource_exhausted(origin);
            io.close_session(origin);
        }
    }
    let latest = io.control().take_abort(TerminalRequest {
        origin: AttachmentContext::default(),
        disposition: TerminalDisposition::Close,
    });
    assert_eq!(latest.origin.generation, MAX_SESSIONS_TOTAL as u64 - 1);
    assert_eq!(latest.disposition, TerminalDisposition::ResourceExhausted);
    let mut notifications = 0;
    while let Ok(event) = output.try_recv() {
        assert!(matches!(
            event,
            SessionOutbound::CloseSession { .. } | SessionOutbound::ResourceExhausted { .. }
        ));
        notifications += 1;
    }
    drop(io);
    assert_eq!(
        notifications, 1,
        "generation churn cannot create a second terminal queue"
    );
}
