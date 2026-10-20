// These source-boundary controls retain the real finite response owner; dropping
// a fixture delivery consumes its guard, never fabricates a peer ACK.
#[test]
fn capacity_restart_reserves_before_marking_announced() {
    let daemon = FakeDaemon::new();
    daemon
        .restart_tx
        .send_replace(RestartSignal::announced(1, 1));
    let (io, inbound, mut outbound) = SessionIo::test_pair();
    let global = io.global_control_budget();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Restart)
        .unwrap();
    let mut update = SessionUpdate::new(with_daemon(&daemon));
    update.announce(&io, 1);
    let announced = update.announced;
    let event = outbound.try_recv();
    drop((update, io, inbound, outbound, held));
    assert_eq!(
        announced, None,
        "failed admission cannot mark the record sent"
    );
    assert!(
        matches!(event, Ok(SessionOutbound::ResourceExhausted { .. })),
        "explicit scoped exhaustion instead of unreserved output"
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_restart_uses_independent_reservation_under_ordinary_saturation() {
    let daemon = FakeDaemon::new();
    daemon
        .restart_tx
        .send_replace(RestartSignal::announced(1, 1));
    let (io, inbound, mut outbound) = SessionIo::test_pair();
    let global = io.global_control_budget();
    let ordinary = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let mut update = SessionUpdate::new(with_daemon(&daemon));
    update.announce(&io, 1);
    update.announce(&io, 1);
    let event = outbound.try_recv().unwrap();
    let charged = global.retained_for_test();
    let duplicates = outbound.try_recv().is_ok();
    let reserved = matches!(&event, SessionOutbound::ReservedSessionControl { bytes, .. } if bytes == &encode_server(&ServerRecord::Restarting));
    drop((event, update, io, inbound, outbound, ordinary));
    assert!(
        reserved,
        "Restarting must own its mandatory finite response, not ordinary credit"
    );
    assert!(!duplicates);
    assert_eq!(charged, (2 * crate::control_budget::MAX_RECORD + 10, 2, 0));
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_restart_stale_watch_cannot_announce_or_abort_idle_replacement() {
    let daemon = FakeDaemon::new();
    daemon
        .restart_tx
        .send_replace(RestartSignal::announced(1, 1));
    let (io, inbound, mut outbound) = SessionIo::test_pair();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Restart)
        .unwrap();
    let mut update = SessionUpdate::new(with_daemon(&daemon));
    daemon.restart_tx.send_replace(RestartSignal::idle(1));
    update.announce(&io, 1);
    let announced = update.announced;
    let had_event = outbound.try_recv().is_ok();
    drop((update, io, inbound, outbound, held));
    assert_eq!(announced, None);
    assert!(
        !had_event,
        "old signal must not terminate or announce into Idle"
    );
}

#[tokio::test]
async fn capacity_restart_old_failure_stays_scoped_when_reset_observes_idle() {
    let daemon = FakeDaemon::new();
    daemon
        .restart_tx
        .send_replace(RestartSignal::announced(1, 1));
    let (mut io, inbound, mut outbound) = SessionIo::test_pair();
    let old = AttachmentContext {
        session_id: 11,
        generation: 0,
        ..resource_context()
    };
    let new = AttachmentContext {
        session_id: 22,
        generation: 1,
        ..resource_context()
    };
    inbound.send(SessionInbound::Live(old)).await.unwrap();
    io.recv().await.unwrap();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Restart)
        .unwrap();
    let mut update = SessionUpdate::new(with_daemon(&daemon));
    update.announce(&io, 1);
    let failure = outbound.try_recv().unwrap();
    daemon.restart_tx.send_replace(RestartSignal::idle(1));
    inbound
        .send(SessionInbound::ResumeReset(new))
        .await
        .unwrap();
    io.recv().await.unwrap();
    update.retry_announcement(&io);
    let pending = update.pending_announcement;
    let extra = outbound.try_recv().is_ok();
    drop((held, update, io, inbound, outbound));
    assert!(matches!(failure, SessionOutbound::ResourceExhausted { origin } if origin == old));
    assert_eq!(pending, None);
    assert!(
        !extra,
        "Idle cannot retry an old failure against replacement"
    );
}

#[tokio::test]
async fn capacity_restart_active_pending_commits_after_refund_and_processed_reset() {
    let daemon = FakeDaemon::new();
    daemon
        .restart_tx
        .send_replace(RestartSignal::announced(1, 1));
    let (mut io, inbound, mut outbound) = SessionIo::test_pair();
    let old = AttachmentContext {
        session_id: 11,
        generation: 0,
        ..resource_context()
    };
    let new = AttachmentContext {
        session_id: 22,
        generation: 1,
        ..resource_context()
    };
    inbound.send(SessionInbound::Live(old)).await.unwrap();
    io.recv().await.unwrap();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Restart)
        .unwrap();
    let mut update = SessionUpdate::new(with_daemon(&daemon));
    update.announce(&io, 1);
    let old_failure = outbound.try_recv().unwrap();
    assert_eq!(update.pending_announcement, Some(1));
    assert_eq!(update.announced, None);
    drop(held);
    inbound
        .send(SessionInbound::ResumeReset(new))
        .await
        .unwrap();
    io.recv().await.unwrap();
    update.retry_announcement(&io);
    update.retry_announcement(&io);
    let announced = update.announced;
    let pending = update.pending_announcement;
    let result = outbound.try_recv().unwrap();
    let extra = outbound.try_recv().is_ok();
    drop((update, io, inbound, outbound));
    assert!(matches!(old_failure, SessionOutbound::ResourceExhausted { origin } if origin == old));
    assert!(matches!(
        result,
        SessionOutbound::ReservedSessionControl { .. }
    ));
    assert_eq!(announced, Some(1));
    assert_eq!(pending, None);
    assert!(!extra, "successful admission commits exactly once");
}
