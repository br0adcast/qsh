fn intake_output(
    io: &SessionIo,
    stream: u8,
    instance: u64,
    origin: AttachmentContext,
    size: usize,
) {
    io.send_channel_output(
        stream,
        crate::channel_geometry::ChannelInstance::new(instance).unwrap(),
        origin,
        io.send_gate(stream, GateKind::Pipe),
        ChannelOutput::Data(vec![stream; size]),
        None,
    );
}
fn intake_origin() -> AttachmentContext {
    AttachmentContext {
        session_id: 305,
        generation: 1,
        features: crate::Features::SUPPORTED,
    }
}

#[test]
fn ready_intake_record_and_framed_byte_limits_keep_one_original_owner() {
    for (sizes, expected) in [
        (vec![1; 33], 32),
        (vec![32763, 32763, 1, 1], 2),
        (vec![32764, 32763, 1], 1),
    ] {
        let (io, _, mut rx) = SessionIo::test_pair();
        for size in sizes {
            intake_output(&io, 16, 1, intake_origin(), size);
        }
        let first = rx.try_recv().unwrap();
        let mut intake = DataIntake::new(&first).unwrap();
        let mut held = None;
        let mut owned = vec![first];
        while let Some(message) = intake.take_next(&mut rx, &mut held) {
            owned.push(message);
        }
        assert_eq!(owned.len(), expected);
        if expected == 32 || intake.bytes == INTAKE_BYTES {
            assert!(held.is_none(), "exact cutoff must not dequeue lookahead");
            assert!(rx.try_recv().is_ok());
        } else {
            assert!(matches!(held, Some(PendingBackend::Item(_))));
            assert!(
                rx.try_recv().is_ok(),
                "never scan beyond one overflow owner"
            );
        }
        assert!(intake.bytes <= 65536);
    }
}

#[test]
fn ready_intake_oversized_first_does_not_prefetch() {
    let (io, _, mut rx) = SessionIo::test_pair();
    intake_output(&io, 16, 1, intake_origin(), 65536);
    intake_output(&io, 16, 1, intake_origin(), 1);
    let first = rx.try_recv().unwrap();
    let mut intake = DataIntake::new(&first).unwrap();
    let mut held = None;
    assert!(intake.take_next(&mut rx, &mut held).is_none());
    assert!(held.is_none());
    assert!(rx.try_recv().is_ok());
}

#[test]
fn ready_intake_exact_key_fences_do_not_scan_or_rebind() {
    for kind in 0..4 {
        let (io, _, mut rx) = SessionIo::test_pair();
        let origin = intake_origin();
        intake_output(&io, 16, 1, origin, 1);
        match kind {
            0 => io.set_stream_resyncable(16, false),
            1 => intake_output(&io, 17, 1, origin, 2),
            2 => intake_output(&io, 16, 2, origin, 2),
            _ => intake_output(
                &io,
                16,
                1,
                AttachmentContext {
                    generation: 2,
                    ..origin
                },
                2,
            ),
        }
        intake_output(&io, 16, 1, origin, 3);
        let first = rx.try_recv().unwrap();
        let mut intake = DataIntake::new(&first).unwrap();
        let mut held = None;
        assert!(intake.take_next(&mut rx, &mut held).is_none());
        let Some(PendingBackend::Item(message)) = held.take() else {
            panic!("one held original fence")
        };
        match message {
            SessionOutbound::Resyncable { .. } => assert_eq!(kind, 0),
            SessionOutbound::ChannelOutput {
                stream,
                instance,
                origin: actual,
                output: ChannelOutput::Data(data),
                ..
            } => {
                assert_eq!(stream, if kind == 1 { 17 } else { 16 });
                assert_eq!(
                    instance,
                    crate::channel_geometry::ChannelInstance::new(if kind == 2 { 2 } else { 1 })
                        .unwrap()
                );
                assert_eq!(actual.generation, if kind == 3 { 2 } else { 1 });
                assert_eq!(data.len(), 2);
            }
            _ => panic!("original type changed"),
        }
        assert!(
            matches!(rx.try_recv(), Ok(SessionOutbound::ChannelOutput { output: ChannelOutput::Data(data), .. }) if data.len()==3)
        );
    }
}

#[test]
fn ready_intake_empty_and_eof_are_distinct_and_prefix_is_still_owned() {
    let (io, _, mut rx) = SessionIo::test_pair();
    intake_output(&io, 16, 1, intake_origin(), 1);
    let first = rx.try_recv().unwrap();
    let mut intake = DataIntake::new(&first).unwrap();
    let mut held = None;
    assert!(intake.take_next(&mut rx, &mut held).is_none());
    assert!(held.is_none());
    drop(io);
    assert!(intake.take_next(&mut rx, &mut held).is_none());
    assert!(matches!(held, Some(PendingBackend::Eof)));
    assert!(matches!(
        first,
        SessionOutbound::ChannelOutput {
            output: ChannelOutput::Data(_),
            ..
        }
    ));
}

#[test]
fn ready_intake_all_priority_and_fairness_guards_stop_only_extra_reads() {
    let now = Instant::now();
    assert!(IntakeReadiness::default().allows(now));
    let guards = [
        IntakeReadiness {
            shutdown: true,
            ..Default::default()
        },
        IntakeReadiness {
            control: true,
            ..Default::default()
        },
        IntakeReadiness {
            retiring: true,
            ..Default::default()
        },
        IntakeReadiness {
            terminal: true,
            ..Default::default()
        },
        IntakeReadiness {
            datagram: true,
            ..Default::default()
        },
        IntakeReadiness {
            drain: true,
            ..Default::default()
        },
        IntakeReadiness {
            inbound: true,
            ..Default::default()
        },
        IntakeReadiness {
            fenced: true,
            ..Default::default()
        },
        IntakeReadiness {
            deadline: Some(now),
            ..Default::default()
        },
    ];
    for guard in guards {
        assert!(!guard.allows(now));
    }
    let later = now + Duration::from_secs(1);
    let timed = IntakeReadiness {
        deadline: Some(later),
        ..Default::default()
    };
    assert!(timed.allows(now));
    assert!(
        !timed.allows(later),
        "fresh service time sees the crossed deadline"
    );
}

#[tokio::test]
async fn ready_intake_held_attach_keeps_original_permit_position_and_snapshot_prefix() {
    let (io, tx, mut rx) = SessionIo::test_pair();
    let key = generate_keypair();
    let peer = "127.0.0.1:41000".parse().unwrap();
    let (_, mut conn, _) =
        accepted_connection_with(&key, [5; 16], peer, crate::Features::SUPPORTED);
    let old = AttachmentContext::for_connection(&conn, 0);
    let instance = crate::channel_geometry::ChannelInstance::new(1).unwrap();
    let budget = crate::channel_timeline::TimelineBudget::new(instance, 0, |_| {});
    let gate = io.send_gate(16, GateKind::Pipe);
    intake_output(&io, 16, 1, old, 1);
    io.send_channel_output(
        16,
        instance,
        old,
        gate.clone(),
        ChannelOutput::Geometry(
            crate::channel_geometry::GeometryRecord {
                instance,
                request_id: 1,
                outcome: crate::channel_geometry::GeometryOutcome::Applied,
                cols: 81,
                rows: 24,
            },
            budget
                .try_reserve(crate::channel_timeline::EntryClass::Ordinary, 27)
                .unwrap(),
        ),
        None,
    );
    intake_output(&io, 16, 1, old, 2);
    let first = rx.try_recv().unwrap();
    let mut intake = DataIntake::new(&first).unwrap();
    let mut held = None;
    let mut link = BackendLink::new(tx, Consumption::OnDelivery);
    link.channel_output.snapshots = io.resume_snapshots.clone();
    link.channel_output.push(first);
    assert!(intake.take_next(&mut rx, &mut held).is_none());
    assert_eq!(io.resume_snapshots.positions_for_test(), (3, 1));
    assert_eq!(
        budget.usage(crate::channel_timeline::EntryClass::Ordinary),
        (1, 27)
    );
    assert_eq!(gate.pending_for_test(), 34);
    let (_, replacement, _) =
        accepted_connection_with(&key, [5; 16], peer, crate::Features::SUPPORTED);
    let (controls, mut control_rx) = mpsc::unbounded_channel();
    controls
        .send(committed_attach(
            Box::new(replacement),
            Vec::new(),
            Vec::new(),
        ))
        .unwrap();
    let selected = tokio::select! {
        biased;
        control = control_rx.recv() => control.unwrap(),
        _ = backend_wakeup(held.is_some(), &mut rx) => panic!("ready Attach has priority"),
    };
    // Losing the select must not take/drop/retag the original held owner.
    assert!(
        matches!(&held, Some(PendingBackend::Item(SessionOutbound::ChannelOutput { position:2, origin, .. })) if *origin==old)
    );
    let mut out = Vec::new();
    assert!(matches!(
        apply_control(
            &mut conn,
            &mut false,
            &mut link,
            selected,
            &BTreeMap::new(),
            Instant::now(),
            &mut out
        )
        .await,
        AttachResult::Applied
    ));
    assert_eq!(gate.pending_for_test(), 34);
    assert_eq!(io.resume_snapshots.positions_for_test(), (3, 1));
    let new_origin = AttachmentContext::for_connection(&conn, link.ledger.generation());
    assert!(
        io.publish_resume_snapshot(new_origin, || crate::channel::ChannelSnapshot::new(
            Vec::new(),
            Vec::new()
        ))
    );
    let Some(PendingBackend::Item(original)) = held.take() else {
        panic!("original owner retained")
    };
    link.channel_output.push(original); // original owner reaches the ordinary unknown-instance discard
    assert_eq!(
        budget.usage(crate::channel_timeline::EntryClass::Ordinary),
        (0, 0)
    );
    assert_eq!(gate.pending_for_test(), 7);
    assert_eq!(io.resume_snapshots.positions_for_test(), (3, 2));
    link.channel_output.push(rx.try_recv().unwrap());
    assert_eq!(gate.pending_for_test(), 0);
    assert_eq!(io.resume_snapshots.positions_for_test(), (3, 3));
    assert!(link.channel_output.receive_fenced());
    held = Some(PendingBackend::Item(rx.try_recv().unwrap()));
    let selected_held = tokio::select! {
        wake = backend_wakeup(held.is_some(), &mut rx), if !link.channel_output.receive_fenced() => matches!(wake, Wakeup::DeferredBackend),
        _ = std::future::ready(()) => false,
    };
    assert!(
        !selected_held,
        "snapshot receive fence parks a held ready owner"
    );
    assert!(held.is_some());
    link.channel_output.drain(
        &mut conn,
        Instant::now(),
        false,
        &mut out,
        &mut link.control_delivery,
    );
    assert!(!link.channel_output.receive_fenced());
    assert!(matches!(
        backend_wakeup(held.is_some(), &mut rx).await,
        Wakeup::DeferredBackend
    ));
    drop(held);
    drop(io);
    drop(rx);
}

#[test]
fn ready_intake_held_data_keeps_payload_pointer_and_exact_source_debt_until_teardown() {
    let (io, _, mut rx) = SessionIo::test_pair();
    let gate = io.send_gate(16, GateKind::Pipe);
    intake_output(&io, 16, 1, intake_origin(), 1);
    let data = vec![b'X'; 100];
    let ptr = data.as_ptr();
    io.send_channel_output(
        16,
        crate::channel_geometry::ChannelInstance::new(2).unwrap(),
        intake_origin(),
        gate.clone(),
        ChannelOutput::Data(data),
        None,
    );
    let first = rx.try_recv().unwrap();
    let mut intake = DataIntake::new(&first).unwrap();
    let mut held = None;
    assert!(intake.take_next(&mut rx, &mut held).is_none());
    assert_eq!(gate.pending_for_test(), 111);
    assert!(
        matches!(&held,Some(PendingBackend::Item(SessionOutbound::ChannelOutput {output:ChannelOutput::Data(bytes),..})) if bytes.as_ptr()==ptr)
    );
    drop(first);
    assert_eq!(gate.pending_for_test(), 105);
    drop(held);
    assert_eq!(gate.pending_for_test(), 0);
    drop(rx);
    drop(io);
}
