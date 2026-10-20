#[test]
fn capacity_open_atomic_pair_failure_does_not_refund_or_wake_unchanged_capacity() {
    for (class, count) in [
        (Response::Terminal, CHANNEL_IDENTITIES),
        (Response::Open, MAX_CHANNELS),
    ] {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let held = (0..count)
            .map(|_| session.reserve(class).unwrap())
            .collect::<Vec<_>>();
        let before = global.retained_for_test();
        let wake = RefundWake::new(&global, &session);
        let waker = Waker::from(wake.clone());
        let mut context = Context::from_waker(&waker);
        let mut changed = Box::pin(global.changed());
        changed.as_mut().enable();
        assert_eq!(changed.as_mut().poll(&mut context), Poll::Pending);
        let rejected = matches!(session.reserve_open(), Err(CapacityError::Session));
        let after = global.retained_for_test();
        let wakes = wake.wakes.load(Ordering::SeqCst);
        drop(changed);
        drop(held);
        assert!(rejected);
        assert_eq!(before, after, "failed pair leaves every counter unchanged");
        assert_eq!(
            wakes, 0,
            "provisional refund would spin a paused enabled runner"
        );
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }
}

#[test]
fn capacity_open_independent_terminal_survives_decision_ack_and_refunds_once_after_retirement() {
    let global = GlobalBudget::default();
    let session = global.session(1);
    let [decision, terminal] = session.reserve_open().unwrap();
    let mut decision = decision.into_owner();
    let mut terminal = terminal.into_owner();
    let mut ledger = ControlLedger::new(7, 0);
    assert!(ledger
        .register(7, 0, 6, decision.take_record(6).unwrap())
        .is_ok());
    drop(decision);
    session.retire();
    ledger.acknowledge(7, 6);
    assert_eq!(
        global.retained_for_test(),
        (10, 1, 0),
        "Opened ACK cannot refund future terminal allowance"
    );
    assert!(ledger
        .register(7, 6, 16, terminal.take_record(10).unwrap())
        .is_ok());
    drop(terminal);
    let wake = RefundWake::new(&global, &session);
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(global.changed());
    changed.as_mut().enable();
    assert_eq!(changed.as_mut().poll(&mut context), Poll::Pending);
    ledger.acknowledge(8, 16);
    assert_eq!(global.retained_for_test(), (10, 1, 0));
    ledger.acknowledge(7, 15);
    assert_eq!(global.retained_for_test(), (10, 1, 0));
    ledger.acknowledge(7, 16);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    assert_eq!(wake.wakes.load(Ordering::SeqCst), 1);
    assert!(wake.locks_released.load(Ordering::SeqCst));
    ledger.acknowledge(7, 16);
    drop(ledger);
    assert_eq!(
        wake.wakes.load(Ordering::SeqCst),
        1,
        "duplicate ACK/teardown cannot refund twice"
    );
}

#[test]
fn capacity_open_retired_terminal_entries_remain_globally_bounded_below_byte_cap() {
    let global = GlobalBudget::default();
    let mut held = Vec::new();
    while held.len() < GLOBAL_RESPONSE_ENTRIES {
        let session = global.session(1);
        for _ in 0..CHANNEL_IDENTITIES.min(GLOBAL_RESPONSE_ENTRIES - held.len()) {
            held.push(session.reserve(Response::Terminal).unwrap());
        }
        session.retire();
    }
    assert!(global.retained_for_test().0 < GLOBAL_BYTES / 100);
    let replacement = global.session(1);
    assert!(matches!(
        replacement.reserve_open(),
        Err(CapacityError::Global)
    ));
    assert!(matches!(
        replacement.reserve(Response::Terminal),
        Err(CapacityError::Global)
    ));
    drop(held.pop().unwrap());
    let wake = RefundWake::new(&global, &replacement);
    let waker = Waker::from(wake.clone());
    let mut context = Context::from_waker(&waker);
    let mut changed = Box::pin(global.changed());
    changed.as_mut().enable();
    assert_eq!(changed.as_mut().poll(&mut context), Poll::Pending);
    assert!(
        matches!(replacement.reserve_open(), Err(CapacityError::Global)),
        "one global entry cannot admit two obligations"
    );
    assert_eq!(wake.wakes.load(Ordering::SeqCst), 0);
    drop(changed);
    let moved = replacement.reserve(Response::Terminal).unwrap();
    assert!(matches!(
        replacement.reserve(Response::Terminal),
        Err(CapacityError::Global)
    ));
    drop(held);
    assert_eq!(global.retained_for_test(), (10, 1, 0));
    drop(moved);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
