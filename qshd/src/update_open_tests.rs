// Included in update::tests to exercise real restart publication.
mod open24_epoch_tests {
    use super::*;

    #[test]
    fn open24_restart_epoch_idle_retained() {
        let restarts = Restarts::new();
        let signal = restarts.subscribe();
        let attempt = restarts.announce().unwrap();
        assert_eq!(signal.borrow().invalidation_epoch, attempt);
        restarts.end();
        assert_eq!(signal.borrow().phase, RestartPhase::Idle);
        assert_eq!(
            signal.borrow().invalidation_epoch,
            attempt,
            "Idle must remember the invalidation a busy runner may have missed"
        );
    }

    #[test]
    fn open24_restart_epoch_two_coalesced_attempts() {
        let restarts = Restarts::new();
        let mut signal = restarts.subscribe();
        signal.borrow_and_update();
        let first = restarts.announce().unwrap();
        restarts.end();
        let second = restarts.announce().unwrap();
        restarts.end();
        assert!(second > first);
        let latest = *signal.borrow_and_update();
        assert_eq!(latest.phase, RestartPhase::Idle);
        assert_eq!(latest.invalidation_epoch, second);
    }

    #[test]
    fn open24_restart_epoch_exhaustion_refuses_without_panic_or_publication() {
        let restarts = Restarts::new();
        restarts.last.store(u64::MAX, Ordering::SeqCst);
        let signal = restarts.subscribe();
        let before = *signal.borrow();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| restarts.announce()));
        assert!(
            result.is_ok(),
            "restart counter exhaustion is a refusal, never a panic"
        );
        assert!(result.unwrap().is_err());
        assert_eq!(*signal.borrow(), before);
    }

    #[test]
    fn open24_restart_epoch_publish_join_order() {
        let restarts = Arc::new(Restarts::new());
        let signal = restarts.subscribe();
        let held = signal.borrow();
        let publisher = {
            let restarts = restarts.clone();
            std::thread::spawn(move || restarts.announce())
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut count_was_released = false;
        while Instant::now() < deadline {
            if restarts.last.load(Ordering::SeqCst) == 1 {
                if let Ok(count) = restarts.count.try_lock() {
                    if count.restart == 1 {
                        count_was_released = true;
                        break;
                    }
                }
            }
            std::thread::yield_now();
        }
        let still_idle = held.phase == RestartPhase::Idle;
        drop(held);
        let attempt = publisher.join().unwrap().unwrap();
        assert!(
            count_was_released,
            "publication cannot hold count while waiting for watch ownership"
        );
        assert!(still_idle);
        assert!(restarts.join(attempt));
        restarts.drain(attempt);
        assert!(!restarts.join(attempt));
        restarts.release(attempt);
        assert!(restarts.wait_drained(attempt, Duration::ZERO));
        restarts.end();
        assert_eq!(signal.borrow().invalidation_epoch, attempt);
    }
}

mod open24_exec_tests {
    use super::*;
    use transport::channel_open::{
        CleanupAuthority, CleanupStatus, OpenIdentity, OpenRequestSnapshot,
    };
    use transport::channel_server::ChannelWait;

    struct ReceiptWait(Arc<AtomicBool>);
    impl ChannelWait for ReceiptWait {
        fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
            transport::channel_server::ChildStatus::Reaped { code: Some(0) }
        }
        fn kill(&mut self) {}
        fn wait(self: Box<Self>) -> i32 {
            -1
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            if self.0.load(Ordering::SeqCst) {
                authority.reaped()
            } else {
                CleanupStatus::Unknown
            }
        }
    }

    fn pending_job(registry: &Arc<ChannelOpenRegistry>) -> transport::channel_open::OpenJob {
        let session = registry.session().unwrap();
        registry.try_reserve(&session, OpenRequestSnapshot {
            owner: me(), login: [0; 16], term: None,
            request: transport::channel::OpenRequest { stream: 16, kind: transport::channel::ChannelKind::Shell,
                cols: 80, rows: 24, screen: false, command: Vec::new() },
            identity: OpenIdentity { session: session.id(), instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                stream: 16, generation: 0, invalidation_epoch: 0 },
        }).unwrap()
    }

    #[test]
    fn cleanup143_early_refusal_preserves_a_real_active_channel_and_later_update() {
        use transport::channel::{encode_client, ClientRecord, ChannelKind, OpenRequest, CONTROL_STREAM};
        use transport::session_manager::{AttachmentContext, ChannelOutput, SessionBackend, SessionInbound, SessionIo, SessionOutbound, StreamData};
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let backend = crate::channel_backend::ChannelSessionBackend::new(Arc::new(crate::screen_budget::ScreenBudget::new(Default::default())));
            let registry = backend.open_registry();
            let execs = Arc::new(AtomicUsize::new(0));
            let observed = execs.clone();
            let Restartable { daemon, transfer, admission, udp: _udp, control: _control, .. } =
                verified_transfer_with_registry(dir.path(), Arc::new(move |_, _| { observed.fetch_add(1, Ordering::SeqCst); Errno::ENOENT }), registry.clone());
            let backend = backend.with_daemon(daemon.clone());
            let (io, input, mut output) = SessionIo::test_pair_for(me(), [3; 16]);
            let runner = tokio::spawn(backend.run(io));
            input.send(SessionInbound::Live(AttachmentContext { generation: 1, session_id: 15, features: transport::Features::CHANNEL_GEOMETRY })).await.unwrap();
            input.send(SessionInbound::Data(StreamData { stream_id: CONTROL_STREAM, data: encode_client(&ClientRecord::Open(OpenRequest {
                stream: 16, kind: ChannelKind::Command, cols: 80, rows: 24, screen: false, command: b"/bin/cat".to_vec(),
            })) })).await.unwrap();
            async fn exchange(input: &tokio::sync::mpsc::Sender<SessionInbound>, output: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>, bytes: &[u8]) -> bool {
                input.send(SessionInbound::Data(StreamData { stream_id: 16, data: bytes.to_vec() })).await.unwrap();
                tokio::time::timeout(Duration::from_secs(3), async {
                    let mut seen = Vec::new();
                    loop {
                        if let Some(SessionOutbound::ChannelOutput { stream: 16, output: ChannelOutput::Data(data), .. }) = output.recv().await {
                            seen.extend(data);
                            if seen.windows(bytes.len() - 1).any(|part| part == &bytes[..bytes.len()-1]) { break; }
                        }
                    }
                }).await.is_ok()
            }
            let opened = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match output.recv().await.unwrap() {
                        SessionOutbound::ChannelOpened { stream: 16, .. } => break,
                        SessionOutbound::ReservedControl { bytes, .. } => {
                            let mut decoder = transport::shell_frame::RecordDeframer::for_control();
                            if decoder.push(&bytes).iter().any(|record| matches!(transport::channel::decode_server(record), Ok(transport::channel::ServerRecord::Opened { stream: 16 }))) { break; }
                        }
                        _ => {}
                    }
                }
            }).await.is_ok();
            let before_io = if opened { exchange(&input, &mut output, b"before-refusal\n").await } else { false };
            let job = pending_job(&registry);
            let receipt = Arc::new(AtomicBool::new(false));
            drop(job.custody().protect(Box::new(ReceiptWait(receipt.clone())), Box::new(transport::shell_server::NoScreen)));
            let before = *daemon.restart_signal().borrow();
            let result = tokio::task::spawn_blocking(move || transfer.restart()).await.unwrap();
            let unchanged = *daemon.restart_signal().borrow() == before;
            let after_io = if opened { exchange(&input, &mut output, b"after-refusal\n").await } else { false };
            let retained = registry.cleanup_snapshot().unwrap().canceled_opens == 1;
            receipt.store(true, Ordering::SeqCst);
            assert!(matches!(job.cleanup(), CleanupStatus::Confirmed(_)));
            drop(job);
            // End and join the actual PTY/session before outcome assertions.
            drop(input);
            tokio::time::timeout(Duration::from_secs(5), runner).await.unwrap().unwrap();
            assert!(opened && before_io && after_io, "an installed PTY must exchange bytes across early refusal");
            assert!(matches!(result, UpdateResult::Rejected { code: RejectCode::Other, .. }));
            assert!(unchanged && retained && !admission.is_closed());
            assert_eq!(execs.load(Ordering::SeqCst), 0);
            assert!(!registry.cleanup_snapshot().unwrap().has_cleanup_debt());
            let image = script_image(101, 0);
            let mut later = daemon.offer(&me(), &offer_for(&image, 101)).unwrap();
            later.write(&image).unwrap();
            later.verify().unwrap();
            let _ = tokio::task::spawn_blocking(move || later.restart()).await.unwrap();
            assert_eq!(execs.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn cleanup143_verify_rejects_known_debt_but_allows_healthy_pending_work() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let Restartable { daemon, transfer, admission, udp: _udp, control: _control, .. } =
            verified_transfer(dir.path(), Arc::new(|_, _| Errno::ENOENT));
        drop(transfer);
        let signal = daemon.restart_signal();
        let before = *signal.borrow();
        let job = pending_job(&daemon.opens);
        let image = script_image(101, 0);
        let mut healthy = daemon.offer(&me(), &offer_for(&image, 101)).unwrap();
        healthy.write(&image).unwrap();
        healthy.verify().expect("healthy pending Open is eligible");
        assert!(!job.custody().is_cancelled());
        drop(healthy);
        job.cancel();
        let mut canceled = daemon.offer(&me(), &offer_for(&image, 101)).unwrap();
        canceled.write(&image).unwrap();
        assert!(matches!(canceled.verify(), Err(UpdateResult::Rejected { code: RejectCode::Other, .. })));
        assert_eq!(*signal.borrow(), before);
        assert!(!admission.is_closed());
        drop(canceled);
        let failure = job.custody().refuse_before_creation("owned fixture".into());
        let transport::channel_open::SpawnCleanup::NoChild(proof) = failure.cleanup else { unreachable!() };
        assert!(daemon.opens.finish_cleanup(job.id(), &proof));
    }

    #[test]
    fn cleanup143_healthy_pending_open_reaches_exec_after_fence_cancellation_and_exact_cleanup() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let execs = Arc::new(AtomicUsize::new(0));
        let observed = execs.clone();
        let Restartable { daemon, transfer, admission, udp: _udp, control: _control, .. } =
            verified_transfer(dir.path(), Arc::new(move |_, _| { observed.fetch_add(1, Ordering::SeqCst); Errno::ENOENT }));
        let job = pending_job(&daemon.opens);
        let receipt = Arc::new(AtomicBool::new(false));
        let guard = job.custody().protect(Box::new(ReceiptWait(receipt.clone())), Box::new(transport::shell_server::NoScreen));
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !job.custody().is_cancelled() && Instant::now() < deadline { std::thread::yield_now(); }
            let fence_canceled = job.custody().is_cancelled();
            receipt.store(true, Ordering::SeqCst);
            drop(guard);
            let settled = matches!(job.cleanup(), CleanupStatus::Confirmed(_));
            (fence_canceled, settled)
        });
        let result = transfer.restart();
        assert_eq!(worker.join().unwrap(), (true, true));
        assert!(matches!(result, UpdateResult::Rejected { code: RejectCode::ExecFailed, .. }), "injected exec is expected to fail only after reaching exec");
        assert_eq!(execs.load(Ordering::SeqCst), 1);
        assert_eq!(daemon.restarts.last.load(Ordering::SeqCst), 1);
        assert_eq!(daemon.opens.outstanding(), 0);
        assert!(!admission.is_closed());
    }

    #[test]
    fn cleanup143_direct_restart_owns_rollback_before_the_final_fence() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let Restartable { daemon, transfer, admission, udp: _udp, control: _control, .. } =
            verified_transfer(dir.path(), Arc::new(|_, _| panic!("early refusal must not exec")));
        drop(transfer);
        let job = pending_job(&daemon.opens);
        job.cancel();
        let image = script_image(101, 0);
        let staged = StagedImage {
            offer: offer_for(&image, 101), path: daemon.staging_path(), file: None, created: false,
            hasher: Sha256::new(), written: 0, closed_admission: false,
            binary_path: daemon.binary_path.clone(), active: daemon.active.clone(), in_progress: daemon.in_progress.clone(),
            restarts: daemon.restarts.clone(), opens: daemon.opens.clone(), handover: daemon.handover.clone(), exec: daemon.exec.clone(),
        };
        let before = *daemon.restart_signal().borrow();
        assert!(matches!(Box::new(staged).restart(), UpdateResult::Rejected { code: RejectCode::Other, .. }));
        assert_eq!(*daemon.restart_signal().borrow(), before);
        assert!(!admission.is_closed());
        let failure = job.custody().refuse_before_creation("owned fixture".into());
        let transport::channel_open::SpawnCleanup::NoChild(proof) = failure.cleanup else { unreachable!() };
        assert!(daemon.opens.finish_cleanup(job.id(), &proof));
    }

    #[test]
    fn cleanup143_debt_after_verify_refuses_before_announcement_and_reopens_admission() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let execs = Arc::new(AtomicUsize::new(0));
        let observed = execs.clone();
        let Restartable { daemon, transfer, admission, udp: _udp, control: _control, .. } =
            verified_transfer(dir.path(), Arc::new(move |_, _| { observed.fetch_add(1, Ordering::SeqCst); Errno::ENOENT }));
        let signal = daemon.restart_signal();
        let before = *signal.borrow();
        let job = pending_job(&daemon.opens);
        job.cancel();
        let result = transfer.restart();
        assert!(matches!(result, UpdateResult::Rejected { code: RejectCode::Other, .. }));
        assert_eq!(*signal.borrow(), before);
        assert_eq!(execs.load(Ordering::SeqCst), 0);
        assert!(!admission.is_closed());
        assert_eq!(daemon.opens.cleanup_snapshot().unwrap().canceled_opens, 1);
        let failure = job.custody().refuse_before_creation("owned fixture".into());
        let transport::channel_open::SpawnCleanup::NoChild(proof) = failure.cleanup else { unreachable!() };
        assert!(daemon.opens.finish_cleanup(job.id(), &proof));
        assert!(!daemon.opens.cleanup_snapshot().unwrap().has_cleanup_debt());
    }

    #[test]
    fn open24_verified_transfer_fence_failure_reopens_admission_without_releasing_other_fence() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let execs = Arc::new(AtomicUsize::new(0));
        let exec: ExecFn = {
            let execs = execs.clone();
            Arc::new(move |_, _| {
                execs.fetch_add(1, Ordering::SeqCst);
                Errno::ENOENT
            })
        };
        let Restartable {
            daemon,
            transfer,
            admission,
            udp: _udp,
            control: _control,
            ..
        } = verified_transfer(dir.path(), exec);
        assert!(admission.is_closed());
        let other_fence = daemon.opens.begin_restart_fence().unwrap();
        let result = transfer.restart();
        assert!(matches!(
            result,
            UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                ..
            }
        ));
        assert_eq!(execs.load(Ordering::SeqCst), 0);
        assert!(
            !admission.is_closed(),
            "verified transfer Drop must reopen its admission"
        );
        assert!(matches!(
            daemon.opens.begin_restart_fence(),
            Err(transport::channel_open::OpenRefusal::Restarting)
        ));
        assert!(other_fence.wait_until(Instant::now()).is_some());
        other_fence.reopen();
    }

    #[test]
    fn open24_actual_exec_is_fenced_after_runner_drop_without_subscribers() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let execs = Arc::new(AtomicUsize::new(0));
        let exec: ExecFn = {
            let execs = execs.clone();
            Arc::new(move |_, _| {
                execs.fetch_add(1, Ordering::SeqCst);
                Errno::ENOENT
            })
        };
        let Restartable {
            daemon,
            transfer,
            admission,
            udp: _udp,
            control: _control,
            ..
        } = verified_transfer(dir.path(), exec);
        let session = daemon.opens.session().unwrap();
        let job = daemon
            .opens
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: me(),
                    login: [0; 16],
                    term: None,
                    request: transport::channel::OpenRequest {
                        stream: 16,
                        kind: transport::channel::ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    },
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                        stream: 16,
                        generation: 0,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let confirmed = Arc::new(AtomicBool::new(false));
        let notifier = job.custody().cleanup_notifier();
        let guard = job.custody().protect(
            Box::new(ReceiptWait(confirmed.clone())),
            Box::new(transport::shell_server::NoScreen),
        );
        *daemon.restarts.before_open_fence.lock().unwrap() = Some(Box::new(move || {
            drop(guard);
            job.cleanup();
            drop(job); // Debt arrives after preflight; no runner/subscriber survives.
        }));
        let first_result = transfer.restart();
        assert_eq!(daemon.restarts.last.load(Ordering::SeqCst), 1, "must reach final fence after announcement");
        let first_execs = execs.load(Ordering::SeqCst);
        let charged_after_timeout = (daemon.opens.outstanding(), session.occupied());
        let admission_reopened = !admission.is_closed();
        // Explicit trusted receipt releases exactly this old obligation.
        confirmed.store(true, Ordering::SeqCst);
        notifier.retry_cleanup();
        let image = script_image(101, 0);
        let mut later = daemon.offer(&me(), &offer_for(&image, 101)).unwrap();
        later.write(&image).unwrap();
        later.verify().unwrap();
        let _ = later.restart();
        assert!(matches!(
            first_result,
            UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                ..
            }
        ));
        assert_eq!(charged_after_timeout, (1, 1));
        assert!(admission_reopened);
        assert_eq!(
            first_execs, 0,
            "actual ExecFn ran with unknown uninstalled cleanup"
        );
        assert_eq!(
            execs.load(Ordering::SeqCst),
            1,
            "a later proved-clean restart may reach exec"
        );
        assert_eq!(daemon.opens.outstanding(), 0);
    }
    struct ReplacementSpawner {
        registry: Arc<ChannelOpenRegistry>,
        calls: AtomicUsize,
        receipt: Arc<AtomicBool>,
        notifier: Mutex<Option<transport::channel_open::CleanupNotifier>>,
    }
    impl transport::channel_server::ChannelSpawner for ReplacementSpawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &Principal,
            _: transport::session_manager::LoginId,
            _: &transport::channel::OpenRequest,
            _: Option<&str>,
            custody: &transport::channel_open::OpenCustody,
        ) -> Result<
            transport::channel_open::UninstalledChannel,
            transport::channel_open::SpawnFailure,
        > {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                *self.notifier.lock().unwrap() = Some(custody.cleanup_notifier());
                drop(custody.protect(
                    Box::new(ReceiptWait(self.receipt.clone())),
                    Box::new(transport::shell_server::NoScreen),
                ));
                Err(custody.failure("fixture unknown cleanup".into()))
            } else {
                Err(custody.refuse_before_creation("fixture admitted after proof".into()))
            }
        }
    }

    #[test]
    fn open24_cold_backend_replacement_retains_old_capacity_and_actual_exec_obligation() {
        use transport::channel::{
            encode_client, ChannelKind, ClientRecord, OpenRequest, CONTROL_STREAM,
        };
        use transport::session_manager::{
            AttachmentContext, SessionBackend, SessionInbound, SessionIo, SessionOutbound,
            StreamData,
        };
        let _fds = fd_flags_lock();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            suppress_shell_history();
            let dir = tempfile::tempdir().unwrap();
            let registry = ChannelOpenRegistry::new(transport::channel_open::OpenLimits {
                global: 1,
                per_uid: 1,
            });
            let spawner = Arc::new(ReplacementSpawner {
                registry: registry.clone(),
                calls: AtomicUsize::new(0),
                receipt: Arc::new(AtomicBool::new(false)),
                notifier: Mutex::new(None),
            });
            let factory =
                crate::channel_backend::ChannelSessionBackend::with_spawner(spawner.clone());
            let execs = Arc::new(AtomicUsize::new(0));
            let exec: ExecFn = {
                let execs = execs.clone();
                Arc::new(move |_, _| {
                    execs.fetch_add(1, Ordering::SeqCst);
                    Errno::ENOENT
                })
            };
            let Restartable {
                daemon,
                transfer,
                admission,
                udp: _udp,
                control: _control,
                ..
            } = verified_transfer_with_registry(dir.path(), exec, factory.open_registry());
            let (arrived, observed) = std::sync::mpsc::sync_channel(1);
            let (release, proceed) = std::sync::mpsc::sync_channel(1);
            *daemon.restarts.before_open_fence.lock().unwrap() = Some(Box::new(move || {
                arrived.send(()).unwrap();
                proceed.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
            let first = tokio::task::spawn_blocking(move || transfer.restart());
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            let context = AttachmentContext {
                generation: 1,
                session_id: 11,
                features: transport::Features::CHANNEL_GEOMETRY,
            };
            let open = || {
                SessionInbound::Data(StreamData {
                    stream_id: CONTROL_STREAM,
                    data: encode_client(&ClientRecord::Open(OpenRequest {
                        stream: 16,
                        kind: ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    })),
                })
            };
            async fn refused(
                output: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
            ) -> String {
                tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        match output.recv().await.unwrap() {
                            SessionOutbound::ChannelRefused { reason, .. } => return reason,
                            SessionOutbound::ReservedControl { bytes, .. } => {
                                // Standalone fixture consumption, not peer ACK.
                                let raw = transport::shell_frame::RecordDeframer::for_control()
                                    .push(&bytes)
                                    .remove(0);
                                if let transport::channel::ServerRecord::Refused {
                                    stream,
                                    reason,
                                } = transport::channel::decode_server(&raw).unwrap()
                                {
                                    assert_eq!(stream, 16);
                                    return reason;
                                }
                            }
                            _ => {}
                        }
                    }
                })
                .await
                .unwrap()
            }
            let (io, input, mut output) = SessionIo::test_pair_for(me(), [1; 16]);
            let old_runner = tokio::spawn(factory.run(io));
            input.send(SessionInbound::Live(context)).await.unwrap();
            input.send(open()).await.unwrap();
            assert_eq!(refused(&mut output).await, "fixture unknown cleanup");
            old_runner.abort();
            assert!(old_runner.await.unwrap_err().is_cancelled());
            drop(input);
            drop(output);
            // A distinct cold backend and session must still use the factory owner.
            let replacement =
                crate::channel_backend::ChannelSessionBackend::with_spawner(spawner.clone());
            let mut alias = me();
            alias.name = "fixture-alias".into();
            let (io, input, mut output) = SessionIo::test_pair_for(alias, [2; 16]);
            let runner = tokio::spawn(replacement.run(io));
            input
                .send(SessionInbound::Live(AttachmentContext {
                    session_id: 12,
                    ..context
                }))
                .await
                .unwrap();
            input.send(open()).await.unwrap();
            let denied = refused(&mut output).await;
            assert_ne!(denied, "fixture admitted after proof");
            assert_eq!(
                spawner.calls.load(Ordering::SeqCst),
                1,
                "cold replacement bypassed outstanding admission"
            );
            release.send(()).unwrap();
            let first = first.await.unwrap();
            assert_eq!(daemon.restarts.last.load(Ordering::SeqCst), 1, "late debt must reach authoritative final fence");
            assert!(matches!(
                first,
                UpdateResult::Rejected {
                    code: RejectCode::ExecFailed,
                    ..
                }
            ));
            assert_eq!(execs.load(Ordering::SeqCst), 0);
            assert_eq!(registry.outstanding(), 1);
            assert!(!admission.is_closed());
            spawner.receipt.store(true, Ordering::SeqCst);
            spawner
                .notifier
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .retry_cleanup();
            assert_eq!(registry.outstanding(), 0);
            input.send(open()).await.unwrap();
            assert_eq!(refused(&mut output).await, "fixture admitted after proof");
            assert_eq!(spawner.calls.load(Ordering::SeqCst), 2);
            drop(input);
            runner.await.unwrap();
            let image = script_image(101, 0);
            let mut later = daemon.offer(&me(), &offer_for(&image, 101)).unwrap();
            later.write(&image).unwrap();
            later.verify().unwrap();
            let _ = tokio::task::spawn_blocking(move || later.restart())
                .await
                .unwrap();
            assert_eq!(execs.load(Ordering::SeqCst), 1);
            assert_eq!(registry.outstanding(), 0);
        });
    }
}
