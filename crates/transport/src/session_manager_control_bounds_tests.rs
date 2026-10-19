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
