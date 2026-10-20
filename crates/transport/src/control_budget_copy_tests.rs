#[test]
fn capacity_copy_weight_covers_queued_source_and_simultaneous_reliable_copy() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    for (response, expected) in [
        (Response::Ordinary(10), 20),
        (Response::Open, 2 * MAX_RECORD),
        (Response::Update, 2 * UPDATE_ENVELOPE),
        (Response::Restart, 10),
        (Response::Snapshot, MAX_SNAPSHOT),
        (Response::Terminal, 10),
    ] {
        let permit = session.reserve(response).unwrap();
        assert_eq!(
            global.retained_for_test(),
            (expected, 1, 0),
            "distinct retained copies require independent charged bytes"
        );
        drop(permit);
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }
}

#[test]
fn capacity_copy_weight_keeps_logical_record_lengths_and_refunds_after_whole_ack_once() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let mut owner = session.reserve(Response::Update).unwrap().into_owner();
    let mut ledger = ControlLedger::new(7, 0);
    let mut end = 0;
    for bytes in [6, 6, MAX_RECORD] {
        let part = owner.take_record(bytes).unwrap();
        assert_eq!(part.encoded_bytes(), bytes);
        assert!(ledger.register(7, end, end + bytes as u64, part).is_ok());
        end += bytes as u64;
    }
    assert!(owner.take_record(1).is_none());
    drop(owner);
    session.retire();
    drop(session);
    assert_eq!(global.retained_for_test(), (2 * UPDATE_ENVELOPE, 1, 0));
    ledger.acknowledge(8, u64::MAX);
    ledger.acknowledge(7, 6);
    ledger.acknowledge(7, end - 1);
    assert_eq!(global.retained_for_test(), (2 * UPDATE_ENVELOPE, 1, 0));
    ledger.acknowledge(7, end);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    ledger.acknowledge(7, u64::MAX);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_copy_weight_shrink_refunds_both_source_and_copy_allowance_once() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let mut permit = session.reserve(Response::Ordinary(MAX_RECORD)).unwrap();
    permit.shrink_ordinary(10).unwrap();
    assert_eq!(global.retained_for_test(), (20, 1, 0));
    permit.shrink_ordinary(10).unwrap();
    assert_eq!(global.retained_for_test(), (20, 1, 0));
    let mut owner = permit.into_owner();
    assert!(
        owner.take_record(11).is_none(),
        "charged copy headroom cannot become extra wire allowance"
    );
    let part = owner.take_record(10).unwrap();
    assert!(owner.take_record(1).is_none());
    drop(owner);
    assert_eq!(global.retained_for_test(), (20, 1, 0));
    drop(part);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
