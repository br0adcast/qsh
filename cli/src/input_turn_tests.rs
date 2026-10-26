#[test]
fn client179_ui_turn_caps_external_fifo_and_preserves_due_tick_signal_opportunity() {
    let mut rx = UiInbox::new().unwrap();
    let tx = rx.renew();
    let start = Instant::now();
    for index in 0..64 {
        tx.send(UiEvent::Resized {
            cols: index,
            rows: 1,
        })
        .unwrap();
    }
    let mut first = Vec::new();
    collect_ui_turn(&rx, &mut first, None, start);
    let count = first.len();
    let order: Vec<_> = first
        .iter()
        .map(|event| match event {
            UiEvent::Resized { cols, .. } => *cols,
            _ => u16::MAX,
        })
        .collect();
    // A new signal prefix is considered before still-queued external events.
    let mut second = vec![UiEvent::Terminate];
    collect_ui_turn(&rx, &mut second, Some(start), start);
    let remaining = rx.try_recv().ok();
    let (_home, mut links) = input_executor_links();
    let mut session = geometry_session();
    let signal = second.remove(0);
    let actions = session.handle(signal, 1);
    let exited = apply_actions(
        actions,
        &mut Vec::new(),
        &mut links,
        &mut session,
        &mut Vec::new(),
        1,
    );
    // The signal was handled before the next16 queued external events.
    let pending_external = second.len();
    assert_eq!(
        count, 16,
        "a continuously replenished receiver must not own the turn"
    );
    assert_eq!(order, (0..16).collect::<Vec<_>>());
    assert_eq!(exited, Some(0));
    assert_eq!(
        pending_external, 17,
        "16 external +due Tick remain unprocessed"
    );
    assert!(matches!(second.last(), Some(UiEvent::Tick)));
    assert!(matches!(remaining, Some(UiEvent::Resized { cols: 32, .. })));
}

#[test]
fn client179_ui_turn_keeps_unprocessed_ingress_owners_until_actual_drop() {
    let mut rx = UiInbox::new().unwrap();
    let tx = rx.renew();
    let start = Instant::now();
    let budget = qsh::input_ingress::IngressBudget::default();
    for index in 0..16 {
        tx.send(UiEvent::Stdin(budget.admit_slice(&[index as u8]).unwrap()))
            .unwrap();
        tx.send(UiEvent::Resized {
            cols: index,
            rows: 1,
        })
        .unwrap();
    }
    let mut first = Vec::new();
    collect_ui_turn(&rx, &mut first, None, start);
    let owners_collected = first
        .iter()
        .filter(|event| matches!(event, UiEvent::Stdin(_)))
        .count();
    let held_after_collect = budget.usage();
    drop(first);
    let held_after_drop = budget.usage();
    drop(rx);
    assert_eq!(owners_collected, 8);
    assert_eq!(held_after_collect, (16, 16, 16));
    assert_eq!(held_after_drop, (8, 8, 8));
    assert_eq!(budget.usage(), (0, 0, 0));
}
