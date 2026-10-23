// Included inside channel_server::tests to reuse its real runner fixtures.
mod open24_tests {
    use super::*;
    use std::sync::Condvar;

    fn process_fixture_live(io: &mut SessionIo) {
        let mut event = std::pin::pin!(io.recv());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            std::future::Future::poll(event.as_mut(), &mut context),
            std::task::Poll::Ready(Some(SessionInbound::Live(_)))
        ));
    }
    fn reserved_open_control(
        message: SessionOutbound,
    ) -> Option<(AttachmentContext, ServerRecord)> {
        let SessionOutbound::ReservedControl {
            origin,
            bytes,
            delivery,
        } = message
        else {
            return None;
        };
        let mut records = RecordDeframer::for_control().push(&bytes);
        assert_eq!(records.len(), 1);
        let record = decode_server(&records.pop().unwrap()).unwrap();
        drop(delivery); // Standalone fixture consumption, not real ACK proof.
        Some((origin, record))
    }
    fn reserved_open_refusal(message: SessionOutbound) -> Option<(AttachmentContext, u8, String)> {
        let (origin, record) = reserved_open_control(message)?;
        match record {
            ServerRecord::Refused { stream, reason } => Some((origin, stream, reason)),
            _ => None,
        }
    }
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.0 .1.notify_all();
        }
    }

    struct BlockingOpen {
        inner: Arc<FakeSpawner>,
        entered: std_mpsc::SyncSender<()>,
        entered_async: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ChannelSpawner for BlockingOpen {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.inner.open_registry()
        }
        fn spawn(
            &self,
            owner: &Principal,
            login: LoginId,
            req: &OpenRequest,
            term: Option<&str>,
            custody: &crate::channel_open::OpenCustody,
        ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>
        {
            if req.stream == FIRST_CHANNEL_STREAM + 1 {
                self.entered.send(()).unwrap();
                self.entered_async.notify_one();
                let (lock, wake) = &*self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
            }
            self.inner.spawn(owner, login, req, term, custody)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn open24_blocked_spawn_does_not_stall_heartbeat_or_control() {
        let first = FIRST_CHANNEL_STREAM;
        let inner = FakeSpawner::new();
        let (entered, entered_rx) = std_mpsc::sync_channel(1);
        let entered_async = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let _release_on_unwind = ReleaseOnDrop(release.clone());
        let spawner = Arc::new(BlockingOpen {
            inner: inner.clone(),
            entered,
            entered_async: entered_async.clone(),
            release: release.clone(),
        });
        let (io, input, mut output) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner));
        input
            .send(open(first, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut output).await,
            ServerRecord::Opened { stream: first }
        );

        let (other_io, other_input, mut other_output) = channel_pair();
        let other_inner = FakeSpawner::new();
        let daemon = FakeDaemon::new();
        let other_runner = tokio::spawn(run_channel_session_with(
            other_io,
            other_inner,
            with_daemon(&daemon),
        ));
        let (progress, progress_rx) = std_mpsc::channel();
        let ended = Arc::new(AtomicBool::new(false));
        let heartbeat = tokio::spawn({
            let progress = progress.clone();
            let ended = ended.clone();
            async move {
                entered_async.notified().await;
                if !ended.load(Ordering::SeqCst) {
                    progress.send(0).unwrap();
                }
            }
        });
        let term = control(ClientRecord::Term("open24-progress-marker".into()));
        let term_bytes = match &term {
            SessionInbound::Data(data) => data.data.len(),
            _ => unreachable!(),
        };
        let observer = tokio::spawn({
            let progress = progress.clone();
            let ended = ended.clone();
            async move {
                while let Some(message) = output.recv().await {
                    if ended.load(Ordering::SeqCst) {
                        continue;
                    }
                    match message {
                        SessionOutbound::Consumed {
                            stream_id: CONTROL_STREAM,
                            n,
                        } if n == term_bytes => {
                            progress.send(1).unwrap();
                        }
                        SessionOutbound::ChannelOutput {
                            stream,
                            output: ChannelOutput::Data(bytes),
                            ..
                        } if stream == first && bytes == b"open24-installed-output" => {
                            progress.send(2).unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });
        let other_observer = tokio::spawn({
            let ended = ended.clone();
            async move {
                while let Some(message) = other_output.recv().await {
                    if matches!(
                        reserved_open_control(message),
                        Some((_, ServerRecord::About(_)))
                    ) && !ended.load(Ordering::SeqCst)
                    {
                        progress.send(3).unwrap();
                        return;
                    }
                }
            }
        });
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let watchdog = std::thread::spawn({
            let input = input.clone();
            let other_input = other_input.clone();
            let inner = inner.clone();
            move || {
                let entered = entered_rx.recv_timeout(Duration::from_secs(5)).is_ok();
                let mut seen = [false; 4];
                if entered {
                    input.blocking_send(term).unwrap();
                    other_input
                        .blocking_send(control(ClientRecord::AboutRequest))
                        .unwrap();
                    inner.feed(first, b"open24-installed-output");
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    while !seen.iter().all(|seen| *seen) {
                        let remaining =
                            deadline.saturating_duration_since(std::time::Instant::now());
                        match progress_rx.recv_timeout(remaining) {
                            Ok(which) => seen[which] = true,
                            Err(_) => break,
                        }
                    }
                }
                ended.store(true, Ordering::SeqCst);
                *release.0.lock().unwrap() = true;
                release.1.notify_all();
                let _ = done_tx.send((entered, seen));
            }
        });
        input
            .send(open(first + 1, ChannelKind::Shell, true))
            .await
            .unwrap();
        let (entered, progress) = done_rx.await.unwrap();
        watchdog.join().unwrap();
        // End every fake process before asserting RED, including the formerly blocked one.
        drop(input);
        drop(other_input);
        runner.await.unwrap();
        other_runner.await.unwrap();
        inner.end_channel(first);
        inner.end_channel(first + 1);
        heartbeat.await.unwrap();
        observer.abort();
        let _ = observer.await;
        other_observer.abort();
        let _ = other_observer.await;
        assert!(entered, "the blocking spawner must actually be entered");
        assert_eq!(progress, [true; 4], "heartbeat, same-session control, installed output, other-session About must progress before spawn release");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn open24_teardown_keeps_unresolved_open_until_actual_cleanup() {
        let inner = FakeSpawner::new();
        let registry = inner.open_registry();
        let (entered, entered_rx) = std_mpsc::sync_channel(1);
        let entered_async = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let _release_on_unwind = ReleaseOnDrop(release.clone());
        let spawner = Arc::new(BlockingOpen {
            inner: inner.clone(),
            entered,
            entered_async: entered_async.clone(),
            release: release.clone(),
        });
        let (io, input, output) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner));
        input
            .send(open(FIRST_CHANNEL_STREAM + 1, ChannelKind::Shell, true))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), entered_async.notified())
            .await
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(input);
        drop(output);
        let returned_before_cleanup = tokio::time::timeout(Duration::from_millis(100), &mut runner)
            .await
            .is_ok();
        let charged_before_cleanup = registry.outstanding();
        // Independent release runs even when the behavior under test is wrong.
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        if !returned_before_cleanup {
            tokio::time::timeout(Duration::from_secs(2), runner)
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while registry.outstanding() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        inner.end_channel(FIRST_CHANNEL_STREAM + 1);
        assert_eq!(charged_before_cleanup, 1);
        assert!(
            !returned_before_cleanup,
            "runner returned while an admitted constructor still owned possible creation"
        );
    }

    struct StalledReap {
        end: Option<std_mpsc::Sender<Vec<u8>>>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl StalledReap {
        fn reap(&mut self) {
            self.end.take();
            self.entered.notify_one();
            let mut released = self.release.0.lock().unwrap();
            while !*released {
                released = self.release.1.wait(released).unwrap();
            }
        }
    }
    impl ChannelWait for StalledReap {
        fn poll_exit(&mut self) -> ChildStatus {
            self.entered.notify_one();
            if *self.release.0.lock().unwrap() {
                ChildStatus::Reaped { code: Some(0) }
            } else {
                ChildStatus::Running
            }
        }
        fn kill(&mut self) {
            self.end.take();
        }
        fn wait(mut self: Box<Self>) -> i32 {
            self.reap();
            0
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            self.reap();
            authority.reaped()
        }
    }
    struct StalledReapSpawner {
        registry: Arc<crate::channel_open::ChannelOpenRegistry>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl ChannelSpawner for StalledReapSpawner {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &Principal,
            _: LoginId,
            req: &OpenRequest,
            _: Option<&str>,
            custody: &crate::channel_open::OpenCustody,
        ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>
        {
            let (tx, rx) = std_mpsc::channel();
            Ok(custody
                .protect(
                    Box::new(StalledReap {
                        end: Some(tx),
                        entered: self.entered.clone(),
                        release: self.release.clone(),
                    }),
                    Box::new(crate::shell_server::NoScreen),
                )
                .finish(
                    Box::new(FakeProcess {
                        greeting: None,
                        feed: rx,
                        held_reads: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                        reads: Arc::new(AtomicUsize::new(0)),
                        exited: Arc::new(AtomicBool::new(false)),
                    }),
                    Box::new(std::io::sink()),
                    Box::new(FakeResize {
                        stream: req.stream,
                        sizes: Arc::new(Mutex::new(Vec::new())),
                    }),
                ))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn open24_drain_keeps_control_responsive_until_reap() {
        let daemon = FakeDaemon::new();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let _release_on_unwind = ReleaseOnDrop(release.clone());
        let spawner = Arc::new(StalledReapSpawner {
            registry: crate::channel_open::ChannelOpenRegistry::new(Default::default()),
            entered: entered.clone(),
            release: release.clone(),
        });
        let (io, input, mut output) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(io, spawner, with_daemon(&daemon)));
        open_a_shell_channel(&input, &mut output).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert_eq!(next_control(&mut output).await, ServerRecord::Restarting);
        until(|| daemon.log().contains(&"joined 1".to_string())).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        input
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        let answered = tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let Some(message) = output.recv().await {
                    if matches!(
                        reserved_open_control(message),
                        Some((_, ServerRecord::About(_)))
                    ) {
                        break;
                    }
                }
            }
        })
        .await
        .is_ok();
        let released_early = daemon.log().contains(&"released 1".to_string());
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        until(|| daemon.log().contains(&"released 1".to_string())).await;
        drop(input);
        runner.await.unwrap();
        assert!(!released_early);
        assert!(
            answered,
            "About was frozen behind the installed-channel reap"
        );
    }

    struct FirstOpenBlocked {
        inner: Arc<FakeSpawner>,
        calls: AtomicUsize,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl ChannelSpawner for FirstOpenBlocked {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.inner.open_registry()
        }
        fn spawn(
            &self,
            owner: &Principal,
            login: LoginId,
            request: &OpenRequest,
            term: Option<&str>,
            custody: &crate::channel_open::OpenCustody,
        ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>
        {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.notify_one();
                let mut released = self.release.0.lock().unwrap();
                while !*released {
                    released = self.release.1.wait(released).unwrap();
                }
            }
            self.inner.spawn(owner, login, request, term, custody)
        }
    }
    async fn cancelled_open_stream_reuse(reset: bool) {
        let inner = FakeSpawner::new();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let _release_on_unwind = ReleaseOnDrop(release.clone());
        let spawner = Arc::new(FirstOpenBlocked {
            inner: inner.clone(),
            calls: AtomicUsize::new(0),
            entered: entered.clone(),
            release: release.clone(),
        });
        let (io, input, mut output) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        input
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .unwrap();
        if reset {
            input
                .send(SessionInbound::ResumeReset(AttachmentContext {
                    generation: 1,
                    ..channel_context()
                }))
                .await
                .unwrap();
            let snapshot = next_snapshot(&mut output, &snapshots).await;
            assert!(
                matches!(snapshot, ServerRecord::ChannelSnapshot(ref snapshot) if snapshot.active().is_empty() && snapshot.draining().is_empty())
            );
        } else {
            input
                .send(control(ClientRecord::Close { stream: 16 }))
                .await
                .unwrap();
        }
        input
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut output).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(spawner.calls.load(Ordering::SeqCst), 2);
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        tokio::time::timeout(Duration::from_secs(3), async {
            while inner.open_registry().outstanding() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let term = control(ClientRecord::Term("post-cleanup-barrier".into()));
        let n = match &term {
            SessionInbound::Data(data) => data.data.len(),
            _ => unreachable!(),
        };
        input.send(term).await.unwrap();
        let mut stale = Vec::new();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(3), output.recv())
                .await
                .unwrap()
                .unwrap();
            let done = matches!(&message, SessionOutbound::Consumed { stream_id: CONTROL_STREAM, n: count } if *count == n);
            match message {
                SessionOutbound::ChannelOpened { .. } => stale.push("Opened"),
                SessionOutbound::ChannelRefused { .. } => stale.push("Refused"),
                SessionOutbound::ChannelExit { .. } => stale.push("Exit"),
                message @ SessionOutbound::ReservedControl { .. } => {
                    match reserved_open_control(message) {
                        Some((_, ServerRecord::Opened { .. })) => stale.push("Opened"),
                        Some((_, ServerRecord::Refused { .. })) => stale.push("Refused"),
                        _ => {}
                    }
                }
                _ => {}
            }
            if done {
                break;
            }
        }
        drop(input);
        inner.end_channel(16);
        runner.await.unwrap();
        assert!(
            stale.is_empty(),
            "late cancelled result reached replacement: {stale:?}"
        );
        assert_eq!(inner.open_registry().outstanding(), 0);
    }
    #[tokio::test]
    async fn open24_reset_stream_reuse_never_installs_late_cancelled_result() {
        cancelled_open_stream_reuse(true).await;
    }
    #[tokio::test]
    async fn open24_close_stream_reuse_never_installs_late_cancelled_result() {
        cancelled_open_stream_reuse(false).await;
    }

    #[tokio::test]
    async fn open24_failed_completion_is_refused_only_in_its_original_epoch_and_attachment() {
        for (published_epoch, generation, should_refuse) in
            [(0, 0, true), (1, 0, false), (0, 1, false)]
        {
            let spawner = FakeSpawner::new();
            *spawner.refuse.lock().unwrap() = Some("exact original request failure".into());
            let mut context = channel_producer();
            context.opens = OpenScope::new(spawner.open_registry());
            let executor = crate::channel_open::ChannelOpenExecutor::new(
                spawner,
                context.opens.registry.clone(),
            );
            let daemon = FakeDaemon::new();
            let update = SessionUpdate::new(with_daemon(&daemon));
            let (mut io, _input, mut output) = channel_pair();
            process_fixture_live(&mut io);
            let mut channels = HashMap::new();
            let job = reserve_open(
                &io,
                &mut channels,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                1,
                0,
                &context,
            )
            .unwrap();
            executor.submit(&job).unwrap();
            job.take_worker().unwrap().await.unwrap();
            daemon
                .restart_tx
                .send_replace(RestartSignal::idle(published_epoch));
            context.attachment.generation = generation;
            let [response, terminal] = io.control_budget().reserve_open().unwrap();
            let mut opening = HashMap::from([(
                16,
                PendingOpen {
                    job,
                    response: response.into_owner(),
                    terminal: terminal.into_owner(),
                },
            )]);
            let (out_tx, _out_rx) = mpsc::channel(1);
            complete_opens(
                &io,
                &mut channels,
                &mut opening,
                &out_tx,
                &update,
                &context,
                &mut ReapSet::new(context.opens.registry.clone()),
            );
            let message = output.try_recv();
            if should_refuse {
                assert!(
                    matches!(message.ok().and_then(reserved_open_refusal), Some((origin, 16, reason)) if origin.generation == 0 && reason == "exact original request failure")
                );
            } else {
                assert!(matches!(message, Err(mpsc::error::TryRecvError::Empty)), "stale completion emitted output: epoch {published_epoch}, attachment {generation}");
            }
            assert!(matches!(
                output.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert!(opening.is_empty());
            assert!(channels.is_empty());
            assert_eq!(context.opens.registry.outstanding(), 0);
        }
    }

    struct RefusalPublicationWake {
        publication: Arc<watch::Sender<RestartSignal>>,
        completed: AtomicBool,
        publishers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    }
    impl std::task::Wake for RefusalPublicationWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let (sent, received) = std_mpsc::sync_channel(1);
            let publication = self.publication.clone();
            self.publishers
                .lock()
                .unwrap()
                .push(std::thread::spawn(move || {
                    publication.send_replace(RestartSignal::idle(1));
                    let _ = sent.send(());
                }));
            self.completed.store(
                received.recv_timeout(Duration::from_secs(1)).is_ok(),
                Ordering::SeqCst,
            );
        }
    }
    #[test]
    fn open24_admission_refusal_wakes_output_without_holding_restart_guard() {
        let daemon = FakeDaemon::new();
        let update = SessionUpdate::new(with_daemon(&daemon));
        let context = channel_producer();
        let spawner = FakeSpawner::new();
        let executor =
            crate::channel_open::ChannelOpenExecutor::new(spawner, context.opens.registry.clone());
        let (mut io, _input, mut output) = channel_pair();
        process_fixture_live(&mut io);
        let wake = Arc::new(RefusalPublicationWake {
            publication: daemon.restart_tx.clone(),
            completed: AtomicBool::new(false),
            publishers: Mutex::new(Vec::new()),
        });
        let waker = std::task::Waker::from(wake.clone());
        let mut poll_context = std::task::Context::from_waker(&waker);
        assert!(output.poll_recv(&mut poll_context).is_pending());
        let mut channels = HashMap::new();
        let mut opening = HashMap::new();
        let [response, terminal] = io.control_budget().reserve_open().unwrap();
        open_channel_async(
            &io,
            &mut channels,
            &executor,
            &mut opening,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 1,
                rows: 1,
                screen: false,
                command: Vec::new(),
            },
            None,
            1,
            &update,
            &context,
            response.into_owner(),
            terminal.into_owner(),
        );
        let refusal = output.try_recv();
        drop(output);
        for publisher in wake.publishers.lock().unwrap().drain(..) {
            publisher.join().unwrap();
        }
        assert!(matches!(
            refusal.ok().and_then(reserved_open_refusal),
            Some((_, 16, _))
        ));
        assert!(
            wake.completed.load(Ordering::SeqCst),
            "output wake blocked restart publication while admission guard was held"
        );
        assert_eq!(context.opens.registry.outstanding(), 0);
        assert!(opening.is_empty());
    }

    #[test]
    fn open24_admission_reads_latest_epoch_and_respects_the_surviving_fence() {
        let daemon = FakeDaemon::new();
        let update = SessionUpdate::new(with_daemon(&daemon));
        let context = channel_producer();
        let (io, _input, mut output) = channel_pair();
        let channels = HashMap::new();
        let prepare = || {
            prepare_open(
                &io,
                &channels,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                1,
                &context,
            )
            .unwrap()
        };
        let prepared_before_restart = prepare();
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        daemon.restart_tx.send_replace(RestartSignal::idle(1));
        let job =
            admit_prepared_open(prepared_before_restart, &update, &context.opens.registry).unwrap();
        assert_eq!(job.request().identity.invalidation_epoch, 1);
        let fence = context.opens.registry.begin_restart_fence().unwrap();
        assert!(job.custody().is_cancelled());
        assert!(matches!(
            admit_prepared_open(prepare(), &update, &context.opens.registry),
            Err(crate::channel_open::OpenRefusal::Restarting)
        ));
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(2, 2));
        assert!(matches!(
            admit_prepared_open(prepare(), &update, &context.opens.registry),
            Err(crate::channel_open::OpenRefusal::Restarting)
        ));
        // This test never submitted the exact admitted job to a constructor.
        job.custody()
            .refuse_before_creation("fixture never scheduled".into());
        job.cleanup();
        assert!(fence.wait_until(std::time::Instant::now()).is_some());
        daemon.restart_tx.send_replace(RestartSignal::idle(2));
        fence.reopen();
        let later = admit_prepared_open(prepare(), &update, &context.opens.registry).unwrap();
        assert_eq!(later.request().identity.invalidation_epoch, 2);
        later
            .custody()
            .refuse_before_creation("fixture never scheduled".into());
        later.cleanup();
        assert_eq!(context.opens.registry.outstanding(), 0);
        assert!(matches!(
            output.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    struct PublicationScreen {
        publication: Arc<watch::Sender<RestartSignal>>,
        published_in_callback: Arc<AtomicBool>,
        publisher: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    }
    impl SessionScreen for PublicationScreen {
        fn absorb(&mut self, _: &[u8]) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn flush_pending_output(
            &mut self,
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn prepare_resize(
            &mut self,
            size: TerminalSize,
        ) -> Result<
            Box<dyn crate::shell_server::PreparedScreenResize + '_>,
            crate::shell_server::ScreenPreparationError,
        > {
            let _ = size;
            Ok(Box::new(FakePreparedResize))
        }
        fn repaint(
            &mut self,
        ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError>
        {
            Ok(crate::shell_server::ScreenRepaint {
                bytes: Vec::new(),
                replies: Vec::new(),
            })
        }
        fn has_screen(&self) -> bool {
            let (done, received) = std_mpsc::sync_channel(1);
            let publication = self.publication.clone();
            *self.publisher.lock().unwrap() = Some(std::thread::spawn(move || {
                publication.send_replace(RestartSignal::idle(1));
                let _ = done.send(());
            }));
            self.published_in_callback.store(
                received.recv_timeout(Duration::from_secs(1)).is_ok(),
                Ordering::SeqCst,
            );
            false
        }
    }
    struct PublicationSpawner {
        registry: Arc<crate::channel_open::ChannelOpenRegistry>,
        screen: Mutex<Option<PublicationScreen>>,
    }
    impl ChannelSpawner for PublicationSpawner {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &Principal,
            _: LoginId,
            _: &OpenRequest,
            _: Option<&str>,
            custody: &crate::channel_open::OpenCustody,
        ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>
        {
            Ok(custody
                .protect(
                    Box::new(FakeWait {
                        stream: 16,
                        code: 0,
                        killed: Default::default(),
                        waited: Default::default(),
                        wait_hold: Arc::new((Mutex::new(false), Condvar::new())),
                        exited: Arc::new(AtomicBool::new(true)),
                        leader_exited: Arc::new(AtomicBool::new(false)),
                        observed: false,
                    }),
                    Box::new(self.screen.lock().unwrap().take().unwrap()),
                )
                .finish(
                    Box::new(std::io::empty()),
                    Box::new(std::io::sink()),
                    Box::new(FakeResize {
                        stream: 16,
                        sizes: Default::default(),
                    }),
                ))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn open24_installed_backend_callback_does_not_hold_restart_watch_guard() {
        let daemon = FakeDaemon::new();
        let published = Arc::new(AtomicBool::new(false));
        let publisher = Arc::new(Mutex::new(None));
        let spawner = Arc::new(PublicationSpawner {
            registry: crate::channel_open::ChannelOpenRegistry::new(Default::default()),
            screen: Mutex::new(Some(PublicationScreen {
                publication: daemon.restart_tx.clone(),
                published_in_callback: published.clone(),
                publisher: publisher.clone(),
            })),
        });
        let (io, input, mut output) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(io, spawner, with_daemon(&daemon)));
        input
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        let opened = next_control(&mut output).await;
        drop(input);
        runner.await.unwrap();
        publisher.lock().unwrap().take().unwrap().join().unwrap();
        assert_eq!(opened, ServerRecord::Opened { stream: 16 });
        assert!(
            published.load(Ordering::SeqCst),
            "backend callback blocked restart publication after ownership commit"
        );
    }

    fn ready_for_commit<'a>(
        channels: &'a mut HashMap<u8, Channel>,
        context: &ProducerContext,
        epoch: u64,
    ) -> (
        crate::channel_open::AdoptedOpen,
        crate::channel_open::OpenIdentity,
        crate::channel_open::OpenJobId,
        PreparedInstallation<'a>,
    ) {
        let spawner = FakeSpawner::new();
        let (io, _input, _output) = channel_pair();
        let req = OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        };
        let job = reserve_open(&io, channels, req.clone(), None, 1, epoch, context).unwrap();
        let id = job.id();
        let identity = job.request().identity;
        let ready = spawner
            .spawn(io.principal(), io.login(), &req, None, job.custody())
            .unwrap_or_else(|_| panic!("fake spawn"));
        let adopted = job.try_adopt(ready).expect("live preparation");
        let installation =
            PreparedInstallation::new(channels, req, identity.instance, context).unwrap();
        (adopted, identity, id, installation)
    }

    #[test]
    fn open24_prepared_commit_rechecks_persistent_epoch() {
        let context = channel_producer();
        let mut channels = HashMap::new();
        let (adopted, identity, id, installation) = ready_for_commit(&mut channels, &context, 1);
        let result = adopted.commit(
            &crate::channel_open::IdleEpochGuard::initial(),
            &identity,
            installation,
        );
        let installed = result.is_some();
        drop(result);
        let visible = channels.len();
        drop(channels);
        context.opens.registry.cleanup(id);
        assert!(!installed, "commit accepted a different persistent epoch");
        assert_eq!(visible, 0);
    }

    #[test]
    fn open24_prepared_commit_rechecks_exact_identity() {
        let context = channel_producer();
        let mut channels = HashMap::new();
        let (adopted, mut identity, id, installation) =
            ready_for_commit(&mut channels, &context, 0);
        identity.generation += 1;
        let result = adopted.commit(
            &crate::channel_open::IdleEpochGuard::initial(),
            &identity,
            installation,
        );
        let installed = result.is_some();
        drop(result);
        let visible = channels.len();
        drop(channels);
        context.opens.registry.cleanup(id);
        assert!(
            !installed,
            "commit accepted a different attachment identity"
        );
        assert_eq!(visible, 0);
    }

    #[test]
    fn open24_prepared_commit_loses_to_fence_before_announced() {
        let context = channel_producer();
        let mut channels = HashMap::new();
        let (adopted, identity, id, installation) = ready_for_commit(&mut channels, &context, 0);
        // try_adopt has returned, but no watch publication has happened.
        let (_watch_tx, watch_rx) = watch::channel(RestartSignal::IDLE);
        let epoch = crate::channel_open::IdleEpochGuard::from_signal(watch_rx.borrow()).unwrap();
        let registry = context.opens.registry.clone();
        let fence = std::thread::spawn(move || registry.begin_restart_fence().unwrap())
            .join()
            .unwrap();
        let result = adopted.commit(&epoch, &identity, installation);
        let installed = result.is_some();
        drop(result);
        let charges = (
            context.opens.registry.outstanding(),
            context.opens.occupied(),
        );
        let visible = channels.len();
        context.opens.registry.cleanup(id);
        fence.reopen();
        assert!(!installed);
        assert_eq!(visible, 0);
        assert_eq!(charges, (1, 1));
    }

    #[test]
    fn open24_prepared_commit_wins_then_fence_sees_installed_channel() {
        let context = channel_producer();
        let mut channels = HashMap::new();
        let (adopted, identity, _, installation) = ready_for_commit(&mut channels, &context, 0);
        let bridges = adopted
            .commit(
                &crate::channel_open::IdleEpochGuard::initial(),
                &identity,
                installation,
            )
            .expect("valid commit");
        let fence = context.opens.registry.begin_restart_fence().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(context.opens.registry.outstanding(), 0);
        assert_eq!(context.opens.occupied(), 1);
        assert!(fence.wait_until(std::time::Instant::now()).is_some());
        drop(bridges);
        drop(channels);
        assert_eq!(context.opens.occupied(), 0);
        fence.reopen();
    }

    #[test]
    fn open24_prepared_commit_unwind_preserves_registered_cleanup() {
        let context = channel_producer();
        let mut channels = HashMap::new();
        let mut identity = None;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (_adopted, _, id, _installation) = ready_for_commit(&mut channels, &context, 0);
            identity = Some(id);
            panic!("injected precommit preparation unwind");
        }));
        let charges = (
            context.opens.registry.outstanding(),
            context.opens.occupied(),
        );
        let visible = channels.len();
        context.opens.registry.cleanup(identity.unwrap());
        assert!(failed.is_err());
        assert_eq!(visible, 0);
        assert_eq!(charges, (1, 1));
        assert_eq!(context.opens.registry.outstanding(), 0);
    }

    #[test]
    fn open24_session_identity_exhaustion_refuses_without_panicking() {
        let registry = crate::channel_open::ChannelOpenRegistry::new(Default::default());
        let allocated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            OpenScope::from_allocation(registry, Err(crate::channel_open::OpenRefusal::Exhausted))
        }));
        assert!(
            allocated.is_ok(),
            "identity exhaustion must leave a control-capable runner, not panic"
        );
        let mut context = channel_producer();
        context.opens = allocated.unwrap();
        let (mut io, _input, mut output) = channel_pair();
        process_fixture_live(&mut io);
        let result = reserve_open(
            &io,
            &mut HashMap::new(),
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            1,
            0,
            &context,
        );
        assert!(result.is_none());
        assert!(matches!(
            output.try_recv().ok().and_then(reserved_open_refusal),
            Some((_, 16, _))
        ));
    }

    #[test]
    fn open24_restart_epoch_guard_tracks_latest_idle_and_refuses_active_restart() {
        let daemon = FakeDaemon::new();
        let update = SessionUpdate::new(with_daemon(&daemon));
        assert_eq!(update.idle_epoch_guard().unwrap().epoch(), 0);
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert!(matches!(
            update.idle_epoch_guard(),
            Err(crate::channel_open::OpenRefusal::Restarting)
        ));
        daemon.restart_tx.send_replace(RestartSignal::idle(1));
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(2, 2));
        daemon.restart_tx.send_replace(RestartSignal::idle(2));
        assert_eq!(update.idle_epoch_guard().unwrap().epoch(), 2);
        assert_eq!(
            SessionUpdate::new(None).idle_epoch_guard().unwrap().epoch(),
            0
        );
    }
}
