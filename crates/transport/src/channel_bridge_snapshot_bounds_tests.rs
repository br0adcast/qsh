#[test]
fn capacity_snapshot_independent_dto_and_wire_custody_survives_retirement_until_real_ack() {
    let mut rig = Rig::new();
    rig.attach();
    let global = rig.io.global_control_budget();
    let max = crate::channel::CHANNEL_SNAPSHOT_MAX + 5;
    assert!(
        rig.bridge
            .snapshots
            .publish(rig.generation, rig.io.control_budget(), || {
                assert!(
                    rig.bridge.snapshots.0.try_lock().is_ok(),
                    "builder must not hold mailbox mutex"
                );
                assert_eq!(
                    global.retained_for_test(),
                    (3 * max, 3, 0),
                    "source DTO and independent future merged/wire obligations"
                );
                ChannelSnapshot::new(vec![], vec![])
            })
            .unwrap()
            .published
    );
    assert_eq!(global.retained_for_test(), (3 * max, 3, 0));
    rig.bridge.push(SessionOutbound::ResumeSnapshotReady);
    assert_eq!(
        global.retained_for_test(),
        (3 * max, 3, 0),
        "source storage is gone; its lease remains for future encoding scratch beside merged DTO and reliable copy"
    );
    let mut withheld = Vec::new();
    rig.bridge.drain(
        &mut rig.server,
        rig.now,
        false,
        &mut withheld,
        &mut rig.control_delivery,
    );
    assert!(!withheld.is_empty());
    assert!(rig.bridge.pending_snapshot.is_none());
    assert_eq!(
        global.retained_for_test(),
        (max, 1, 0),
        "merged DTO and consumed scratch dropped after reliable copy enqueue; wire remains charged"
    );
    assert!(
        rig.server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .unacked
            > 0
    );
    rig.io.control_budget().retire();
    rig.control_delivery
        .acknowledge(rig.generation + 1, u64::MAX);
    assert_eq!(global.retained_for_test(), (max, 1, 0));
    rig.pump(withheld);
    rig.drain(false);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    assert!(rig.control_delivery.is_empty());
    assert_eq!(rig.control_records.len(), 1);
    assert!(
        matches!(&rig.control_records[0], crate::channel::ServerRecord::ChannelSnapshot(snapshot) if snapshot.active().is_empty() && snapshot.draining().is_empty())
    );
    rig.drain(false);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_snapshot_wake_never_relabels_future_payload_and_attach_recovers_it() {
    let mut rig = Rig::new();
    rig.bridge.attach(&rig.server, 1);
    let publication = rig
        .bridge
        .snapshots
        .publish(2, rig.io.control_budget(), || {
            ChannelSnapshot::new(vec![], vec![])
        })
        .unwrap();
    assert!(publication.published && publication.notify);
    rig.bridge.push(SessionOutbound::ResumeSnapshotReady);
    assert!(rig.bridge.pending_snapshot.is_none());
    assert_eq!(rig.bridge.target, Some(1));
    assert!(rig.bridge.snapshots.0.lock().unwrap().value.is_some());
    rig.bridge.attach(&rig.server, 2);
    assert!(rig.bridge.pending_snapshot.is_some());
    assert_eq!(rig.bridge.generation, 2);
    // The previously consumed wake cannot become a missing-payload failure.
    rig.bridge.push(SessionOutbound::ResumeSnapshotReady);
    assert!(!rig.bridge.snapshot_failed);
    assert!(rig.bridge.pending_snapshot.is_some());
}

#[test]
fn capacity_snapshot_wake_consumption_and_publication_have_no_lost_notification() {
    let mailbox = SnapshotMailbox::default();
    let global = crate::control_budget::GlobalBudget::default();
    let budget = global.session(1);
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let publisher_mailbox = mailbox.clone();
    let worker = std::thread::spawn(move || {
        publisher_mailbox.publish(1, &budget, || {
            entered.send(()).unwrap();
            let _ = release_rx.recv();
            ChannelSnapshot::new(vec![], vec![])
        })
    });
    let started = entered_rx.recv_timeout(std::time::Duration::from_secs(5));
    let before_publish = mailbox.take(Some(1), true);
    drop(release);
    let publication = worker.join().unwrap().unwrap();
    assert!(started.is_ok());
    assert!(before_publish.is_none());
    assert!(
        publication.published && publication.notify,
        "publication after wake consumption queues one new wake"
    );
    drop(
        mailbox
            .take(Some(1), true)
            .expect("wake consumes the actual published payload"),
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    let budget = global.session(1);
    let first = mailbox
        .publish(2, &budget, || ChannelSnapshot::new(vec![], vec![]))
        .unwrap();
    let latest = mailbox
        .publish(3, &budget, || ChannelSnapshot::new(vec![], vec![]))
        .unwrap();
    assert!(
        first.notify && !latest.notify,
        "publication before consumption shares the one queued wake"
    );
    assert!(mailbox.take(Some(2), false).is_none());
    drop(
        mailbox
            .take(Some(3), true)
            .expect("one wake consumes latest exact target"),
    );
    let next = mailbox
        .publish(4, &budget, || ChannelSnapshot::new(vec![], vec![]))
        .unwrap();
    assert!(
        next.notify,
        "publication after consumption must enqueue a new wake"
    );
}

#[test]
fn capacity_snapshot_stale_inflight_builder_cannot_overwrite_replacement() {
    let mailbox = SnapshotMailbox::default();
    let global = crate::control_budget::GlobalBudget::default();
    let budget = global.session(1);
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release, release_rx) = std::sync::mpsc::channel::<()>();
    let publisher_mailbox = mailbox.clone();
    let worker = std::thread::spawn(move || {
        publisher_mailbox.publish(1, &budget, || {
            entered.send(()).unwrap();
            let _ = release_rx.recv();
            ChannelSnapshot::new(vec![], vec![])
        })
    });
    let started = entered_rx.recv_timeout(std::time::Duration::from_secs(5));
    mailbox.discard_before(2);
    drop(release);
    let stale = worker.join().unwrap().unwrap();
    assert!(started.is_ok());
    assert!(!stale.published && !stale.notify);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    let budget = global.session(1);
    let current = mailbox
        .publish(2, &budget, || ChannelSnapshot::new(vec![], vec![]))
        .unwrap();
    assert!(current.published && current.notify);
    let stale = mailbox
        .publish(1, &budget, || panic!("stale source must not run"))
        .unwrap();
    assert!(!stale.published && !stale.notify);
    assert!(mailbox.take(Some(2), true).is_some());
}

#[test]
fn capacity_snapshot_old_wake_waits_for_new_geometry_prefix() {
    let mut rig = Rig::new();
    rig.bridge.attach(&rig.server, 1);
    let old = rig
        .bridge
        .snapshots
        .publish(1, rig.io.control_budget(), || {
            ChannelSnapshot::new(vec![], vec![])
        })
        .unwrap();
    assert!(old.notify);
    rig.generation = 2;
    rig.bridge.attach(&rig.server, 2);
    let permit = rig
        .budget
        .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
        .unwrap();
    let gap = rig
        .budget
        .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
        .unwrap();
    rig.io.send_channel_output(
        STREAM,
        ChannelInstance::new(1).unwrap(),
        rig.origin(),
        rig.gate.clone(),
        ChannelOutput::Geometry(
            GeometryRecord {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 80,
                rows: 24,
            },
            permit,
        ),
        Some(gap),
    );
    let latest = rig
        .bridge
        .snapshots
        .publish(2, rig.io.control_budget(), || {
            ChannelSnapshot::new(
                vec![crate::channel::ActiveChannel {
                    instance: ChannelInstance::new(1).unwrap(),
                    request: crate::channel::OpenRequest {
                        stream: STREAM,
                        kind: crate::channel::ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: vec![],
                    },
                }],
                vec![],
            )
        })
        .unwrap();
    assert!(
        !latest.notify,
        "the old wake is still queued ahead of the new Geometry"
    );
    rig.bridge.push(SessionOutbound::ResumeSnapshotReady);
    let prematurely_failed = rig.bridge.snapshot_failed;
    let prematurely_merged = rig.bridge.pending_snapshot.is_some();
    rig.bridge.push(
        rig.outbound
            .try_recv()
            .expect("real queued Geometry prefix"),
    );
    let completed = rig
        .bridge
        .pending_snapshot
        .as_ref()
        .map(|s| s.active().len());
    drop(rig);
    assert!(
        !prematurely_failed,
        "coalesced old wake must not abort before its latest snapshot's Geometry prefix"
    );
    assert!(!prematurely_merged);
    assert_eq!(
        completed,
        Some(1),
        "processing required Geometry completes the snapshot without another wake"
    );
}

#[test]
fn capacity_snapshot_concurrent_producers_commit_positions_in_actual_send_order() {
    let mailbox = SnapshotMailbox::default();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let start = Arc::new(std::sync::Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let mailbox = mailbox.clone();
            let tx = tx.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..16 {
                    assert!(mailbox.send_ordered(
                        &tx,
                        SessionOutbound::ChannelClosed {
                            position: 0,
                            stream: STREAM,
                            instance: ChannelInstance::new(1).unwrap(),
                            origin: AttachmentContext::default(),
                        }
                    ));
                }
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut positions = Vec::new();
    while let Ok(message) = rx.try_recv() {
        positions.push(message.channel_position().unwrap());
    }
    assert_eq!(positions, (1..=32).collect::<Vec<_>>());
    let global = crate::control_budget::GlobalBudget::default();
    let budget = global.session(1);
    assert!(
        mailbox
            .publish(1, &budget, || ChannelSnapshot::new(vec![], vec![]))
            .unwrap()
            .notify
    );
    assert!(mailbox.take(Some(1), true).is_none());
    for position in positions {
        mailbox.observed(position);
    }
    drop(
        mailbox
            .take(Some(1), false)
            .expect("already queued prefix settles without another wake"),
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    // Publication after the entire prefix was already observed is ready on its
    // sole wake; it cannot depend on another future typed message.
    assert!(
        mailbox
            .publish(2, &budget, || ChannelSnapshot::new(vec![], vec![]))
            .unwrap()
            .notify
    );
    assert!(mailbox.take(Some(2), true).is_some());
}

#[test]
fn capacity_snapshot_failed_send_and_position_exhaustion_leave_no_unfillable_prefix() {
    let mailbox = SnapshotMailbox::default();
    let message = || SessionOutbound::ChannelClosed {
        position: 0,
        stream: STREAM,
        instance: ChannelInstance::new(1).unwrap(),
        origin: AttachmentContext::default(),
    };
    let (tx, rx) = mpsc::unbounded_channel();
    drop(rx);
    assert!(
        mailbox.send_ordered(&tx, message()),
        "closed receiver is teardown, not sequence overflow"
    );
    assert_eq!(mailbox.0.lock().unwrap().produced, 0);
    let (tx, mut rx) = mpsc::unbounded_channel();
    assert!(mailbox.send_ordered(&tx, message()));
    let actual = rx.try_recv().unwrap().channel_position().unwrap();
    assert_eq!(actual, 1);
    mailbox.observed(actual);
    {
        let mut slot = mailbox.0.lock().unwrap();
        slot.produced = u64::MAX;
        slot.observed = u64::MAX;
    }
    assert!(!mailbox.send_ordered(&tx, message()));
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(mailbox.0.lock().unwrap().produced, u64::MAX);
    let global = crate::control_budget::GlobalBudget::default();
    let budget = global.session(1);
    assert!(
        mailbox
            .publish(1, &budget, || ChannelSnapshot::new(vec![], vec![]))
            .unwrap()
            .published
    );
    assert!(
        mailbox.take(Some(1), true).is_some(),
        "no missing position was committed on failure"
    );
}

#[test]
fn capacity_snapshot_discarded_stale_messages_still_advance_the_required_prefix() {
    let mut rig = Rig::new();
    rig.bridge.attach(&rig.server, 2);
    rig.io.channel_closed(
        STREAM,
        ChannelInstance::new(1).unwrap(),
        AttachmentContext {
            generation: 1,
            ..rig.origin()
        },
    );
    assert!(
        rig.bridge
            .snapshots
            .publish(2, rig.io.control_budget(), || ChannelSnapshot::new(
                vec![],
                vec![]
            ))
            .unwrap()
            .notify
    );
    rig.bridge.push(SessionOutbound::ResumeSnapshotReady);
    assert!(rig.bridge.pending_snapshot.is_none());
    rig.bridge.push(rig.outbound.try_recv().unwrap());
    assert!(rig.bridge.pending_snapshot.is_some());
    assert!(!rig.bridge.snapshot_failed);
}

#[test]
fn capacity_snapshot_position_exhaustion_has_one_scoped_terminal_outcome() {
    let (io, _inbound, mut outbound) = SessionIo::test_pair();
    let origin = AttachmentContext {
        features: crate::Features::CHANNEL_GEOMETRY | crate::Features::RESOURCE_LIMITS,
        ..AttachmentContext::default()
    };
    io.set_control_origin(origin);
    io.resume_snapshots.0.lock().unwrap().produced = u64::MAX;
    io.channel_closed(STREAM, ChannelInstance::new(1).unwrap(), origin);
    assert!(
        matches!(outbound.try_recv(),Ok(SessionOutbound::ResourceExhausted {origin: actual}) if actual == origin)
    );
    assert!(matches!(
        outbound.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}
