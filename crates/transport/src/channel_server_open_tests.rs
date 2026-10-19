// Included inside channel_server::tests to reuse its real runner fixtures.
mod open24_tests {
    use super::*;
    use std::sync::Condvar;

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
                let mut records = RecordDeframer::for_control();
                while let Some(message) = other_output.recv().await {
                    if let SessionOutbound::Data(data) = message {
                        if data.stream_id != CONTROL_STREAM {
                            continue;
                        }
                        for raw in records.push(&data.data) {
                            if matches!(decode_server(&raw), Ok(ServerRecord::About(_)))
                                && !ended.load(Ordering::SeqCst)
                            {
                                progress.send(3).unwrap();
                                return;
                            }
                        }
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
}
