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
    let generated = (records * encoded.len()) as u64;

    struct Refusals {
        reason: String,
        records: usize,
        ended: mpsc::Sender<()>,
    }
    impl SessionBackend for Refusals {
        fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let reason = self.reason.clone();
            let records = self.records;
            let ended = self.ended.clone();
            Box::pin(async move {
                let mut sent = false;
                while let Some(event) = io.recv().await {
                    if let SessionInbound::Live(origin) = event {
                        if !sent {
                            sent = true;
                            for _ in 0..records {
                                io.channel_refused(origin, 16, reason.clone());
                            }
                        }
                    }
                }
                let _ = ended.send(()).await;
            })
        }
    }

    CONTROL_RELIABLE_PEAK.with(|peak| peak.set(0));
    let (ended, mut end_rx) = mpsc::channel(1);
    let rig = delivery_rig(
        Arc::new(Refusals {
            reason,
            records,
            ended,
        }),
        |_| {},
    )
    .await;
    // Deliberately never poll the client socket: neither delivery ACKs nor
    // credit can return. The hook counts actual retained Connection debt.
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let peak = CONTROL_RELIABLE_PEAK.with(|peak| peak.get());
            if peak >= generated {
                return peak;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let peak = CONTROL_RELIABLE_PEAK.with(|peak| peak.get());
    // Drop all fixture routes/control/output senders, then await backend exit.
    // No OS children or blocking workers are launched by this backend.
    drop(rig);
    tokio::time::timeout(Duration::from_secs(5), end_rx.recv())
        .await
        .expect("fixture backend terminates after bridge teardown")
        .expect("fixture backend reported completion");
    assert!(
        reached.is_ok(),
        "the bridge must actually retain the fixture replies"
    );
    assert!(
        peak <= SEND_HARD_CAP as u64,
        "reliable control debt retained {peak} bytes beyond existing cap {SEND_HARD_CAP}"
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
