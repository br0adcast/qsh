#[test]
fn capacity_snapshot_rejection_precedes_builder_and_model_reset() {
    let mut rig = ResizeRig::new(false, false);
    let held = (0..3)
        .map(|_| {
            rig.io
                .control_budget()
                .reserve(crate::control_budget::Response::Snapshot)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let built = std::cell::Cell::new(false);
    let origin = AttachmentContext {
        generation: 2,
        session_id: 12,
        ..rig.channel.producer.origin
    };
    rig.io.publish_resume_snapshot(origin, || {
        built.set(true);
        crate::channel::ChannelSnapshot::new(vec![], vec![])
    });
    rig.channel.input_consumed = 77;
    rig.channel.last_acked = 66;
    let mut channels = HashMap::from([(16, rig.channel)]);
    reset_attachment_outputs(&rig.io, &mut channels, &mut HashMap::new(), origin);
    let before = (
        channels[&16].input_consumed,
        channels[&16].last_acked,
        channels[&16].producer.origin,
    );
    let effects = rig.events.lock().unwrap().clone();
    drop((channels, held));
    assert!(
        !built.get(),
        "rejected mandatory snapshot must not run its builder"
    );
    assert_eq!(
        (before.0, before.1),
        (77, 66),
        "snapshot admission must precede model/view producer reset"
    );
    assert_ne!(before.2, origin);
    assert!(effects.is_empty(), "rejected snapshot cannot repaint model");
}

#[test]
fn capacity_snapshot_generation_churn_keeps_one_queued_wake() {
    let (io, _inbound, mut outbound) = SessionIo::test_pair();
    let mut published = 0;
    for generation in 1..=300 {
        let origin = AttachmentContext {
            generation,
            session_id: generation,
            ..resource_context()
        };
        published += usize::from(io.publish_resume_snapshot(origin, || {
            crate::channel::ChannelSnapshot::new(vec![], vec![])
        }));
    }
    let mut wakes = 0;
    while let Ok(message) = outbound.try_recv() {
        if matches!(message, SessionOutbound::ResumeSnapshotReady) {
            wakes += 1;
        }
    }
    assert_eq!(published, 300);
    assert_eq!(
        wakes, 1,
        "mailbox replacement must not accumulate stale queued notifications"
    );
}

#[tokio::test]
async fn capacity_snapshot_runner_has_explicit_scoped_failure_before_any_snapshot_output() {
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let held = (0..3)
        .map(|_| {
            io.control_budget()
                .reserve(crate::control_budget::Response::Snapshot)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let origin = AttachmentContext {
        generation: 1,
        session_id: 26,
        ..resource_context()
    };
    let runner = tokio::spawn(run_channel_session(io, FakeSpawner::new()));
    inbound
        .send(SessionInbound::ResumeReset(origin))
        .await
        .unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut snapshot_wakes = 0;
        loop {
            match outbound
                .recv()
                .await
                .expect("runner alive until explicit outcome")
            {
                SessionOutbound::ResumeSnapshotReady => snapshot_wakes += 1,
                SessionOutbound::ResourceExhausted { origin } => return (origin, snapshot_wakes),
                SessionOutbound::ProtocolFailure { .. } => {
                    panic!("capacity is not a protocol failure")
                }
                _ => {}
            }
        }
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    drop((outbound, held));
    assert_eq!(outcome.expect("bounded explicit failure"), (origin, 0));
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
