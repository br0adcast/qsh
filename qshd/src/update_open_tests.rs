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
        drop(job.custody().protect(
            Box::new(ReceiptWait(confirmed.clone())),
            Box::new(transport::shell_server::NoScreen),
        ));
        job.cleanup();
        drop(job); // No runner, mailbox receiver, or watch subscriber survives.
        let first_result = transfer.restart();
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
            let first = tokio::task::spawn_blocking(move || transfer.restart())
                .await
                .unwrap();
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
