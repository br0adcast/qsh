// The provider's lifetime is independent of the async receiver. Release every
// real callback before runtime destruction, including on a failed fixture fence.
struct HeldUpdateOffer {
    inner: Arc<FakeDaemon>,
    entered: AtomicUsize,
    completed: AtomicUsize,
    changed: tokio::sync::Notify,
    released: (Mutex<bool>, std::sync::Condvar),
}
impl HeldUpdateOffer {
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}
struct ReleaseUpdateOffer(Arc<HeldUpdateOffer>);
impl Drop for ReleaseUpdateOffer {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl DaemonUpdates for HeldUpdateOffer {
    fn about(&self) -> Option<About> {
        Some(fake_about())
    }
    fn offer(
        &self,
        _from: &Principal,
        _offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
        let mut released = self.released.0.lock().unwrap();
        while !*released {
            released = self.released.1.wait(released).unwrap();
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        Err(UpdateAnswer::Managed)
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

#[test]
fn capacity_update_reserves_mandatory_outcome_and_job_before_held_offer() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let provider = Arc::new(HeldUpdateOffer {
        inner: FakeDaemon::new(),
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let retained = runtime.block_on(async {
        let release = ReleaseUpdateOffer(provider.clone());
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let ordinary = io
            .control_budget()
            .reserve(crate::control_budget::Response::Ordinary(
                crate::control_budget::MAX_RECORD,
            ))
            .unwrap();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(provider.clone()),
        ));
        let record = offer_of(1);
        let encoded_len = encode_client(&record).len();
        inbound.send(control(record)).await.unwrap();
        consumed_control(&mut outbound, encoded_len).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let changed = provider.changed.notified();
                if provider.entered.load(Ordering::SeqCst) != 0 {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("real offer callback entered after admission");
        let retained = global.retained_for_test();
        drop(release);
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("released runner and lifecycle finish")
            .unwrap();
        drop((outbound, ordinary));
        (retained, global.retained_for_test())
    });
    drop(runtime);
    assert_eq!(provider.entered.load(Ordering::SeqCst), 1);
    assert_eq!(provider.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        retained.0,
        (2 * crate::control_budget::MAX_RECORD + 12, 2, 1),
        "the whole mandatory chain and actual-joined job precede provider effects"
    );
    assert_eq!(retained.1, (0, 0, 0));
}
struct CommitProbeDaemon {
    inner: Arc<FakeDaemon>,
    verifies: Arc<AtomicUsize>,
}
struct CommitProbeTransfer {
    _inner: Box<dyn UpdateTransfer>,
    verifies: Arc<AtomicUsize>,
}
impl UpdateTransfer for CommitProbeTransfer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self._inner.write(bytes)
    }
    fn verify(&mut self) -> Result<(), UpdateResult> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        Err(UpdateResult::Rejected {
            code: RejectCode::Other,
            detail: "controlled verification refusal".into(),
        })
    }
    fn restart(self: Box<Self>) -> UpdateResult {
        panic!("rejected verification must not restart")
    }
}
impl DaemonUpdates for CommitProbeDaemon {
    fn about(&self) -> Option<About> {
        Some(fake_about())
    }
    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.inner.offer(from, offer).map(|inner| {
            Box::new(CommitProbeTransfer {
                _inner: inner,
                verifies: self.verifies.clone(),
            }) as Box<dyn UpdateTransfer>
        })
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

#[test]
fn capacity_update_no_receive_effect_before_bridge_acceptance_commit() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let verifies = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(CommitProbeDaemon {
        inner: FakeDaemon::new(),
        verifies: verifies.clone(),
    });
    runtime.block_on(async {
        let (io, inbound, mut outbound) = about_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(provider),
        ));
        inbound.send(control(offer_of(0))).await.unwrap();
        let held_acceptance = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let message = outbound
                    .recv()
                    .await
                    .expect("runner produces acceptance proposal");
                let bytes = match &message {
                    SessionOutbound::ReservedControl { bytes, .. }
                    | SessionOutbound::UpdateAccept { bytes, .. } => bytes.as_slice(),
                    _ => continue,
                };
                let mut deframer = RecordDeframer::new();
                if deframer.push(bytes).into_iter().any(|raw| {
                    matches!(
                        decode_server(&raw),
                        Ok(ServerRecord::UpdateAnswer(UpdateAnswer::Accept))
                    )
                }) {
                    break message;
                }
            }
        })
        .await
        .expect("acceptance proposal observed without committing it");
        drop(inbound);
        runner.await.unwrap();
        drop((held_acceptance, outbound));
    });
    // The old detached receiver also finishes before this final assertion.
    drop(runtime);
    assert_eq!(
        verifies.load(Ordering::SeqCst),
        0,
        "bridge commitment must precede receive/verify side effects"
    );
}
struct HeldVerifyState {
    entered: AtomicUsize,
    completed: AtomicUsize,
    changed: tokio::sync::Notify,
    released: (Mutex<bool>, std::sync::Condvar),
}
impl HeldVerifyState {
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}
struct ReleaseVerify(Arc<HeldVerifyState>);
impl Drop for ReleaseVerify {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct HeldVerifyDaemon {
    inner: Arc<FakeDaemon>,
    state: Arc<HeldVerifyState>,
}
struct HeldVerifyTransfer {
    inner: Box<dyn UpdateTransfer>,
    state: Arc<HeldVerifyState>,
}
impl UpdateTransfer for HeldVerifyTransfer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.inner.write(bytes)
    }
    fn verify(&mut self) -> Result<(), UpdateResult> {
        self.state.entered.fetch_add(1, Ordering::SeqCst);
        self.state.changed.notify_one();
        let mut released = self.state.released.0.lock().unwrap();
        while !*released {
            released = self.state.released.1.wait(released).unwrap();
        }
        self.state.completed.fetch_add(1, Ordering::SeqCst);
        Err(UpdateResult::Rejected {
            code: RejectCode::SelfCheckFailed,
            detail: "controlled verification result".into(),
        })
    }
    fn restart(self: Box<Self>) -> UpdateResult {
        panic!("refused image must not restart")
    }
}
impl DaemonUpdates for HeldVerifyDaemon {
    fn about(&self) -> Option<About> {
        Some(fake_about())
    }
    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.inner.offer(from, offer).map(|inner| {
            Box::new(HeldVerifyTransfer {
                inner,
                state: self.state.clone(),
            }) as Box<dyn UpdateTransfer>
        })
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

#[test]
fn capacity_update_accepted_verify_survives_warm_and_ordinary_saturation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = Arc::new(HeldVerifyState {
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let provider = Arc::new(HeldVerifyDaemon {
        inner: FakeDaemon::new(),
        state: state.clone(),
    });
    let observed = runtime.block_on(async {
        let release = ReleaseVerify(state.clone());
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let ordinary = io
            .control_budget()
            .reserve(crate::control_budget::Response::Ordinary(
                crate::control_budget::MAX_RECORD,
            ))
            .unwrap();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(provider),
        ));
        inbound.send(control(offer_of(0))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), state.changed.notified())
            .await
            .unwrap();
        let held = global.retained_for_test();
        let replacement = AttachmentContext {
            generation: 1,
            session_id: 2,
            ..resource_context()
        };
        inbound
            .send(SessionInbound::ResumeReset(replacement))
            .await
            .unwrap();
        let term = ClientRecord::Term("xterm".into());
        let term_len = encode_client(&term).len();
        inbound.send(control(term)).await.unwrap();
        consumed_control(&mut outbound, term_len).await;
        drop(release);
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let SessionOutbound::ReservedSessionControl { bytes, delivery } =
                    outbound.recv().await.unwrap()
                {
                    let raw = RecordDeframer::for_control().push(&bytes).remove(0);
                    drop(delivery); // Fixture consumption, not peer ACK.
                    break decode_server(&raw).unwrap();
                }
            }
        })
        .await;
        drop(inbound);
        runner.await.unwrap();
        drop((ordinary, outbound));
        (held, result, global.retained_for_test())
    });
    drop(runtime);
    assert_eq!(state.entered.load(Ordering::SeqCst), 1);
    assert_eq!(state.completed.load(Ordering::SeqCst), 1);
    assert_eq!(
        observed.0,
        (2 * crate::control_budget::MAX_RECORD + 12, 2, 1)
    );
    assert_eq!(
        observed.1.unwrap(),
        ServerRecord::UpdateResult(UpdateResult::Rejected {
            code: RejectCode::SelfCheckFailed,
            detail: "controlled verification result".into()
        })
    );
    assert_eq!(observed.2, (0, 0, 0));
}
#[test]
fn capacity_update_runner_receiver_loss_retains_job_until_actual_verify_join() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let state = Arc::new(HeldVerifyState {
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let provider = Arc::new(HeldVerifyDaemon {
        inner: FakeDaemon::new(),
        state: state.clone(),
    });
    let retained = runtime.block_on(async {
        let release = ReleaseVerify(state.clone());
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let (returned, receiver) = tokio::sync::oneshot::channel();
        let runner = tokio::spawn(crate::session_manager::fixture::drive_backend(
            io,
            move |io| async move {
                super::run_channel_session_with(io, FakeSpawner::new(), Some(provider)).await;
                let _ = returned.send(());
            },
        ));
        inbound.send(control(offer_of(0))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), state.changed.notified())
            .await
            .unwrap();
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
            .await
            .expect("actual runner returned and dropped result receiver")
            .unwrap();
        let retained = global.retained_for_test();
        let completed_while_held = state.completed.load(Ordering::SeqCst);
        drop(release);
        runner.await.unwrap();
        drop(outbound);
        (retained, completed_while_held, global.retained_for_test())
    });
    drop(runtime);
    assert_eq!(
        retained.0 .2, 1,
        "only actual worker/completion custody remains after runner drops chain"
    );
    assert_eq!(retained.1, 0);
    assert_eq!(state.entered.load(Ordering::SeqCst), 1);
    assert_eq!(state.completed.load(Ordering::SeqCst), 1);
    assert_eq!(retained.2, (0, 0, 0));
}
struct OfferFailureDaemon {
    inner: Arc<FakeDaemon>,
    calls: AtomicUsize,
}
impl DaemonUpdates for OfferFailureDaemon {
    fn about(&self) -> Option<About> {
        Some(fake_about())
    }
    fn offer(
        &self,
        _from: &Principal,
        _offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("controlled offer provider failure")
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

#[tokio::test]
async fn capacity_update_job_denial_and_offer_panic_are_typed_before_acceptance() {
    for denied in [true, false] {
        let provider = Arc::new(OfferFailureDaemon {
            inner: FakeDaemon::new(),
            calls: AtomicUsize::new(0),
        });
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let mut held = Vec::new();
        if denied {
            for _ in 0..2 * crate::session_manager::MAX_SESSIONS_PER_OWNER {
                held.push(
                    crate::control_job::JobOwner::reserve(
                        &global.session(io.principal().uid),
                        crate::control_budget::Job::About,
                    )
                    .unwrap(),
                );
            }
        }
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(provider.clone()),
        ));
        inbound.send(control(offer_of(0))).await.unwrap();
        let answer = next_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        drop((outbound, held));
        assert_eq!(
            answer,
            ServerRecord::UpdateAnswer(if denied {
                UpdateAnswer::ResourceExhausted
            } else {
                UpdateAnswer::ProviderFailed
            })
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), usize::from(!denied));
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }
}

#[tokio::test]
async fn capacity_update_legacy_offer_panic_requests_explicit_close() {
    let provider = Arc::new(OfferFailureDaemon {
        inner: FakeDaemon::new(),
        calls: AtomicUsize::new(0),
    });
    let (io, inbound, mut outbound) = channel_pair();
    let global = io.global_control_budget();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider.clone()),
    ));
    inbound.send(control(offer_of(0))).await.unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound.recv().await.unwrap() {
                SessionOutbound::CloseSession { origin } => break Ok(origin),
                SessionOutbound::ResourceExhausted { .. }
                | SessionOutbound::ProtocolFailure { .. }
                | SessionOutbound::ReservedControl { .. }
                | SessionOutbound::UpdateAccept { .. } => {
                    break Err("unrelated failure or acceptance")
                }
                _ => {}
            }
        }
    })
    .await;
    drop(inbound);
    runner.await.unwrap();
    drop(outbound);
    assert_eq!(outcome.unwrap().unwrap(), channel_context());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}

#[derive(Clone, Copy, Debug)]
enum AcceptedBoundary {
    VerifyPanic,
    RestartPanic,
    Diagnostic(usize),
}
struct AcceptedBoundaryDaemon {
    inner: Arc<FakeDaemon>,
    behavior: AcceptedBoundary,
    phases: Arc<[AtomicUsize; 3]>,
}
struct AcceptedBoundaryTransfer {
    _inner: Box<dyn UpdateTransfer>,
    behavior: AcceptedBoundary,
    phases: Arc<[AtomicUsize; 3]>,
}
impl UpdateTransfer for AcceptedBoundaryTransfer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self._inner.write(bytes)
    }
    fn verify(&mut self) -> Result<(), UpdateResult> {
        self.phases[1].fetch_add(1, Ordering::SeqCst);
        if matches!(self.behavior, AcceptedBoundary::VerifyPanic) {
            panic!("controlled accepted verification panic");
        }
        Ok(())
    }
    fn restart(self: Box<Self>) -> UpdateResult {
        self.phases[2].fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            AcceptedBoundary::RestartPanic => panic!("controlled accepted restart panic"),
            AcceptedBoundary::Diagnostic(len) => UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                detail: "d".repeat(len),
            },
            AcceptedBoundary::VerifyPanic => unreachable!("verification did not succeed"),
        }
    }
}
impl DaemonUpdates for AcceptedBoundaryDaemon {
    fn about(&self) -> Option<About> {
        Some(fake_about())
    }
    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.phases[0].fetch_add(1, Ordering::SeqCst);
        self.inner.offer(from, offer).map(|inner| {
            Box::new(AcceptedBoundaryTransfer {
                _inner: inner,
                behavior: self.behavior,
                phases: self.phases.clone(),
            }) as Box<dyn UpdateTransfer>
        })
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

async fn accepted_boundary_record(
    outbound: &mut mpsc::UnboundedReceiver<SessionOutbound>,
) -> (ServerRecord, usize, crate::session_manager::ControlDelivery) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (bytes, delivery) = match outbound.recv().await.unwrap() {
                SessionOutbound::UpdateAccept {
                    bytes,
                    delivery,
                    committed,
                    ..
                } => {
                    // Standalone bridge commitment; retained guard is not a
                    // transport ACK and stays held through all later phases.
                    let _ = committed.send(());
                    (bytes, delivery)
                }
                SessionOutbound::ReservedSessionControl { bytes, delivery } => (bytes, delivery),
                _ => continue,
            };
            let raw = RecordDeframer::for_control().push(&bytes).remove(0);
            return (decode_server(&raw).unwrap(), bytes.len(), delivery);
        }
    })
    .await
    .expect("accepted update produces its bounded mandatory outcome")
}

async fn accepted_boundary_case(behavior: AcceptedBoundary) {
    let phases = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
    let inner = FakeDaemon::new();
    let provider = Arc::new(AcceptedBoundaryDaemon {
        inner: inner.clone(),
        behavior,
        phases: phases.clone(),
    });
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let ordinary = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        Some(provider),
    ));
    inbound.send(control(offer_of(0))).await.unwrap();
    let mut results = vec![accepted_boundary_record(&mut outbound).await];
    results.push(accepted_boundary_record(&mut outbound).await);
    if !matches!(behavior, AcceptedBoundary::VerifyPanic) {
        results.push(accepted_boundary_record(&mut outbound).await);
    }
    let retained_before_guard_drop = global.retained_for_test();
    drop(inbound);
    runner.await.unwrap();
    drop(outbound);
    let actual_phases = std::array::from_fn::<_, 3, _>(|i| phases[i].load(Ordering::SeqCst));
    let result_bytes: usize = results.iter().map(|(_, len, _)| len).sum();
    let records: Vec<_> = results
        .iter()
        .map(|(record, _, _)| record.clone())
        .collect();
    let encoded_lengths: Vec<_> = results.iter().map(|(_, len, _)| *len).collect();
    drop(results);
    let retained_after_guard_drop = global.retained_for_test();
    drop(ordinary);

    assert_eq!(records[0], ServerRecord::UpdateAnswer(UpdateAnswer::Accept));
    assert_eq!(
        actual_phases,
        [
            1,
            1,
            usize::from(!matches!(behavior, AcceptedBoundary::VerifyPanic))
        ]
    );
    assert!(
        !inner.busy.load(Ordering::SeqCst),
        "transfer cleanup completed"
    );
    assert_eq!(
        retained_before_guard_drop,
        (2 * crate::control_budget::MAX_RECORD + 12, 2, 0),
        "actual joined job refunded while independent record guards retain envelope"
    );
    assert_eq!(
        retained_after_guard_drop,
        (crate::control_budget::MAX_RECORD, 1, 0)
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
    assert!(result_bytes <= crate::control_budget::MAX_RECORD + 12);
    if !matches!(behavior, AcceptedBoundary::VerifyPanic) {
        assert_eq!(
            records[1],
            ServerRecord::UpdateResult(UpdateResult::Restarting)
        );
    }
    let expected = match behavior {
        AcceptedBoundary::VerifyPanic | AcceptedBoundary::RestartPanic => UpdateResult::Rejected {
            code: RejectCode::Other,
            detail: "the update provider failed".into(),
        },
        AcceptedBoundary::Diagnostic(len) => UpdateResult::Rejected {
            code: RejectCode::ExecFailed,
            detail: if len > crate::shell_frame::CONTROL_RECORD_MAX - 2 {
                crate::channel::OVERSIZED_CONTROL_DIAGNOSTIC.into()
            } else {
                "d".repeat(len)
            },
        },
    };
    assert_eq!(records.last(), Some(&ServerRecord::UpdateResult(expected)));
    if matches!(behavior, AcceptedBoundary::Diagnostic(len) if len == crate::shell_frame::CONTROL_RECORD_MAX - 2)
    {
        assert_eq!(
            encoded_lengths,
            vec![6, 6, crate::control_budget::MAX_RECORD]
        );
        assert_eq!(result_bytes, crate::control_budget::MAX_RECORD + 12);
    }
}

#[tokio::test]
async fn capacity_update_accepted_phase_panics_refund_actual_jobs_under_ordinary_saturation() {
    for behavior in [
        AcceptedBoundary::VerifyPanic,
        AcceptedBoundary::RestartPanic,
    ] {
        accepted_boundary_case(behavior).await;
    }
}

#[tokio::test]
async fn capacity_update_maximum_and_oversize_final_diagnostic_fit_three_record_chain() {
    for len in [
        17,
        crate::shell_frame::CONTROL_RECORD_MAX - 2,
        crate::shell_frame::CONTROL_RECORD_MAX - 1,
    ] {
        accepted_boundary_case(AcceptedBoundary::Diagnostic(len)).await;
    }
}
