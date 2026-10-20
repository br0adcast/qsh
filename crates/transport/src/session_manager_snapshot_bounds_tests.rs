#[tokio::test]
async fn capacity_snapshot_old_wire_debt_is_gone_when_reset_is_delivered() {
    struct ObserveReset {
        budget: crate::control_budget::GlobalBudget,
        observed: Arc<Mutex<Vec<usize>>>,
    }
    impl std::task::Wake for ObserveReset {
        fn wake(self: Arc<Self>) {
            self.observed
                .lock()
                .unwrap()
                .push(self.budget.retained_for_test().1);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.observed
                .lock()
                .unwrap()
                .push(self.budget.retained_for_test().1);
        }
    }
    let key = generate_keypair();
    let peer = "127.0.0.1:26".parse().unwrap();
    let now = Instant::now();
    let (_, mut conn) = explicit_pair(&key, 100, peer, now);
    let (_, replacement) = explicit_pair(&key, 101, peer, now);
    let origin = AttachmentContext::for_connection(&conn, 0);
    let global = crate::control_budget::GlobalBudget::default();
    let session = global.session(1);
    let future = session
        .reserve(crate::control_budget::Response::Update)
        .unwrap();
    let mut owner = session
        .reserve(crate::control_budget::Response::Snapshot)
        .unwrap()
        .into_owner();
    let bytes = crate::channel::ChannelSnapshot::new(vec![], vec![])
        .unwrap()
        .encode_record();
    let part = owner.take_record(bytes.len()).unwrap();
    let mut pending = VecDeque::from([PendingControl {
        origin: Some(origin),
        bytes,
        delivery: ControlDelivery { part, charge: None },
        committed: None,
    }]);
    let (tx, mut rx) = mpsc::channel(4);
    let mut link = BackendLink::new(tx, Consumption::Explicit);
    let mut out = Vec::new();
    drain_reserved_control(
        &mut conn,
        0,
        &mut pending,
        &mut link.control_delivery,
        false,
        now,
        &mut out,
    );
    drop(owner);
    assert_eq!(global.retained_for_test().1, 2);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let waker = std::task::Waker::from(Arc::new(ObserveReset {
        budget: global.clone(),
        observed: observed.clone(),
    }));
    {
        let receive = rx.recv();
        tokio::pin!(receive);
        assert!(receive
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
            .is_pending());
    }
    let mut parked = false;
    let applied = apply_control(
        &mut conn,
        &mut parked,
        &mut link,
        committed_attach(Box::new(replacement), Vec::new(), Vec::new()),
        &BTreeMap::new(),
        now,
        &mut out,
    )
    .await;
    let heard = observed.lock().unwrap().clone();
    let reset = rx.try_recv();
    drop((link, conn));
    assert!(matches!(applied, AttachResult::Applied));
    assert!(matches!(reset, Ok(SessionInbound::ResumeReset(_))));
    assert_eq!(heard, vec![1], "actual reset delivery must not wake a backend while destroyed old wire debt is still charged");
    assert_eq!(
        global.retained_for_test().1,
        1,
        "independent future effect owner remains charged"
    );
    drop(future);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_snapshot_cancelled_or_mismatched_attach_keeps_live_wire_debt() {
    for mismatched in [false, true] {
        let key = generate_keypair();
        let peer = "127.0.0.1:26".parse().unwrap();
        let now = Instant::now();
        let (_, mut conn) = explicit_pair(&key, 102, peer, now);
        let (_, replacement) = explicit_pair(&key, 103, peer, now);
        let old_id = conn.session_id();
        let global = crate::control_budget::GlobalBudget::default();
        let session = global.session(1);
        let mut owner = session
            .reserve(crate::control_budget::Response::Snapshot)
            .unwrap()
            .into_owner();
        let bytes = crate::channel::ChannelSnapshot::new(vec![], vec![])
            .unwrap()
            .encode_record();
        let part = owner.take_record(bytes.len()).unwrap();
        let mut pending = VecDeque::from([PendingControl {
            origin: Some(AttachmentContext::for_connection(&conn, 0)),
            bytes,
            delivery: ControlDelivery { part, charge: None },
            committed: None,
        }]);
        let (tx, mut rx) = mpsc::channel(4);
        let mut link = BackendLink::new(tx, Consumption::Explicit);
        let mut out = Vec::new();
        drain_reserved_control(
            &mut conn,
            0,
            &mut pending,
            &mut link.control_delivery,
            false,
            now,
            &mut out,
        );
        drop(owner);
        let retained = global.retained_for_test();
        let queued = conn.stream_progress(CONTROL_STREAM);
        let (commit, receipt) = tokio::sync::oneshot::channel();
        if mismatched {
            commit
                .send(CommittedAdmission(AuthAcceptance {
                    session_id: old_id,
                    disposition: SessionDisposition::Resumed,
                }))
                .ok()
                .unwrap();
        } else {
            drop(commit);
        }
        let applied = apply_control(
            &mut conn,
            &mut false,
            &mut link,
            BridgeControl::Attach(Box::new(replacement), vec![], vec![], receipt),
            &BTreeMap::new(),
            now,
            &mut out,
        )
        .await;
        assert!(matches!(applied, AttachResult::Cancelled));
        assert_eq!(conn.session_id(), old_id);
        assert_eq!(conn.stream_progress(CONTROL_STREAM).queued, queued.queued);
        assert!(!link.control_delivery.is_empty());
        assert_eq!(global.retained_for_test(), retained);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop((conn, link));
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }
}
