fn update_control_item(
    origin: Option<AttachmentContext>,
    record: crate::channel::ServerRecord,
    owner: &mut crate::control_budget::ResponseOwner,
    committed: Option<tokio::sync::oneshot::Sender<()>>,
) -> PendingControl {
    let bytes = crate::channel::encode_server(&record);
    let part = owner.take_record(bytes.len()).unwrap();
    PendingControl {
        origin,
        bytes,
        delivery: ControlDelivery { part, charge: None },
        committed,
    }
}

#[test]
fn capacity_update_bridge_rejects_stale_acceptance_without_commit() {
    let key = generate_keypair();
    let peer = "127.0.0.1:26".parse().unwrap();
    let now = Instant::now();
    let (_, old) = explicit_pair(&key, 90, peer, now);
    let origin = AttachmentContext::for_connection(&old, 0);
    let (_, mut current) = explicit_pair(&key, 91, peer, now);
    let global = crate::control_budget::GlobalBudget::default();
    let session = global.session(1);
    let mut owner = session
        .reserve(crate::control_budget::Response::Update)
        .unwrap()
        .into_owner();
    let (commit, mut receipt) = tokio::sync::oneshot::channel();
    let mut pending = VecDeque::from([update_control_item(
        Some(origin),
        crate::channel::ServerRecord::UpdateAnswer(crate::channel::UpdateAnswer::Accept),
        &mut owner,
        Some(commit),
    )]);
    let mut ledger = crate::control_budget::ControlLedger::new(0, 0);
    let mut out = Vec::new();
    drain_reserved_control(
        &mut current,
        1,
        &mut pending,
        &mut ledger,
        false,
        now,
        &mut out,
    );
    assert!(matches!(
        receipt.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(pending.is_empty() && ledger.is_empty() && out.is_empty());
    assert_eq!(current.stream_progress(CONTROL_STREAM).queued, 0);
    drop(owner);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[test]
fn capacity_update_bridge_commits_whole_accept_and_routes_future_result_to_current_peer() {
    let key = generate_keypair();
    let peer = "127.0.0.1:26".parse().unwrap();
    let now = Instant::now();
    let (_, mut conn) = explicit_pair(&key, 92, peer, now);
    let origin = AttachmentContext::for_connection(&conn, 0);
    let global = crate::control_budget::GlobalBudget::default();
    let session = global.session(1);
    let ordinary = session
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let mut owner = session
        .reserve(crate::control_budget::Response::Update)
        .unwrap()
        .into_owner();
    let (commit, mut receipt) = tokio::sync::oneshot::channel();
    let mut pending = VecDeque::from([update_control_item(
        Some(origin),
        crate::channel::ServerRecord::UpdateAnswer(crate::channel::UpdateAnswer::Accept),
        &mut owner,
        Some(commit),
    )]);
    let mut ledger = crate::control_budget::ControlLedger::new(0, 0);
    let mut out = Vec::new();
    assert!(matches!(
        receipt.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    drain_reserved_control(
        &mut conn,
        0,
        &mut pending,
        &mut ledger,
        false,
        now,
        &mut out,
    );
    assert_eq!(receipt.try_recv(), Ok(()));
    assert_eq!(conn.stream_progress(CONTROL_STREAM).queued, 6);
    assert!(
        !ledger.is_empty(),
        "commit is whole enqueue, never an ACK refund"
    );
    // The already queued Accept belongs to old transport and is not replayed.
    // Do not deliver its packets or ACK them before replacement.
    out.clear();
    let (mut current_peer, replacement) = explicit_pair(&key, 93, peer, now);
    conn = replacement;
    let result = crate::channel::ServerRecord::UpdateResult(crate::channel::UpdateResult::Busy {
        others: 7,
    });
    pending.push_back(update_control_item(None, result.clone(), &mut owner, None));
    drain_reserved_control(
        &mut conn,
        1,
        &mut pending,
        &mut ledger,
        false,
        now,
        &mut out,
    );
    for datagram in out {
        let _withheld_ack = current_peer.on_datagram(now, peer, &datagram.bytes);
    }
    let mut deframer = crate::shell_frame::RecordDeframer::for_control();
    let mut records = Vec::new();
    for event in current_peer.poll_events() {
        if let Event::StreamData {
            stream_id: CONTROL_STREAM,
            data,
        } = event
        {
            for raw in deframer.push(&data) {
                records.push(crate::channel::decode_server(&raw).unwrap());
            }
        }
    }
    assert_eq!(
        records,
        vec![result],
        "future session outcome reaches authenticated replacement; old Accept never relabelled"
    );
    drop((owner, ordinary, ledger, pending, conn));
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
