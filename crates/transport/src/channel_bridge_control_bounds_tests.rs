#[test]
fn capacity_open_terminal_and_generic_records_share_actual_cumulative_ack_custody() {
    let mut rig = Rig::new();
    rig.geometry(80, 0);
    rig.drain(false);
    let global = rig.io.global_control_budget();
    let ordinary = rig
        .io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let [decision, terminal] = rig.io.control_budget().reserve_open().unwrap();
    let mut owner = decision.into_owner();
    let mut terminal = terminal.into_owner();
    let bytes =
        crate::channel::encode_server(&crate::channel::ServerRecord::Opened { stream: STREAM });
    let part = owner.take_record(bytes.len()).unwrap();
    let mut pending = VecDeque::from([PendingControl {
        origin: Some(rig.origin()),
        bytes,
        delivery: ControlDelivery { part, charge: None },
        committed: None,
    }]);
    let mut withheld = Vec::new();
    drain_reserved_control(
        &mut rig.server,
        rig.generation,
        &mut pending,
        &mut rig.control_delivery,
        false,
        rig.now,
        &mut withheld,
    );
    let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
    let control = ControlDelivery {
        part: terminal.take_record(10).unwrap(),
        charge: None,
    };
    rig.bridge.push(SessionOutbound::ChannelExit {
        position: 0,
        stream: STREAM,
        instance: ChannelInstance::new(1).unwrap(),
        origin: rig.origin(),
        code: Some(42),
        open: crate::channel::OpenClassification {
            kind: crate::channel::ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
        },
        permit,
        control,
    });
    rig.bridge.drain(
        &mut rig.server,
        rig.now,
        false,
        &mut withheld,
        &mut rig.control_delivery,
    );
    drop((owner, terminal));
    rig.io.control_budget().retire();
    assert_eq!(
        rig.server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .queued,
        16
    );
    assert_eq!(
        rig.server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .unacked,
        16
    );
    assert!(!rig.control_delivery.is_empty());
    assert_eq!(
        global.retained_for_test(),
        (4 * crate::control_budget::MAX_RECORD + 10, 3, 0),
        "retired global debt survives both actual enqueues and future-owner drop"
    );
    rig.control_delivery
        .acknowledge(rig.generation + 1, u64::MAX);
    assert_eq!(
        global.retained_for_test(),
        (4 * crate::control_budget::MAX_RECORD + 10, 3, 0)
    );
    // Deliver the real encrypted records and their real generated ACKs. The
    // existing rig advances protocol time; no delivery guard is fabricated.
    rig.pump(withheld);
    rig.drain(false);
    assert_eq!(
        rig.control_records,
        vec![
            crate::channel::ServerRecord::Opened { stream: STREAM },
            crate::channel::ServerRecord::Exit {
                stream: STREAM,
                code: 42
            }
        ]
    );
    assert_eq!(
        rig.server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .unacked,
        0
    );
    assert!(rig.control_delivery.is_empty());
    assert_eq!(
        global.retained_for_test(),
        (2 * crate::control_budget::MAX_RECORD, 1, 0)
    );
    rig.drain(false);
    assert_eq!(
        global.retained_for_test(),
        (2 * crate::control_budget::MAX_RECORD, 1, 0),
        "duplicate settlement cannot refund twice"
    );
    drop(ordinary);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
