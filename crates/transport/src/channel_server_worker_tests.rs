mod owned_io {
    use super::*;

    struct AfterReapWait {
        child: FakeWait,
        reaped: bool,
        late_observations: Arc<AtomicUsize>,
    }
    impl ChannelWait for AfterReapWait {
        fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
            if self.reaped {
                self.late_observations.fetch_add(1, Ordering::SeqCst);
            }
            self.child.poll_leader_status()
        }
        fn poll_exit(&mut self) -> ChildStatus {
            let status = self.child.poll_exit();
            self.reaped |= matches!(status, ChildStatus::Reaped { .. });
            status
        }
        fn kill(&mut self) {
            self.child.kill();
        }
        fn wait(self: Box<Self>) -> i32 {
            Box::new(self.child).wait()
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            self.child.cleanup_uninstalled(authority)
        }
    }
    #[test]
    fn worker39_pending_receipt_yields_reaper_thread_without_releasing_custody() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        let (io, inbound, outbound) = channel_pair();
        let hold = Arc::new((Mutex::new(true), std::sync::Condvar::new()));
        let (entered, observed) = std_mpsc::sync_channel(1);
        let held = hold.clone();
        let (reader, writer) = runtime.block_on(async {
            (
                io.spawn_blocking_owned(|| {}),
                io.spawn_blocking_owned(move || {
                    entered.send(()).unwrap();
                    let mut waiting = held.0.lock().unwrap();
                    while *waiting {
                        waiting = held.1.wait(waiting).unwrap();
                    }
                }),
            )
        });
        // Drive the lifecycle supervisors that launch and join the actual
        // blocking handles before waiting outside this current-thread runtime.
        runtime.block_on(async {
            until(|| observed.try_recv().is_ok()).await;
            until(|| reader.joined().is_some()).await;
        });
        let waited = Arc::new(Mutex::new(Vec::new()));
        let late_observations = Arc::new(AtomicUsize::new(0));
        let mut reaps = ReapSet::default();
        runtime.block_on(async {
            reaps.start(
                16,
                1,
                Box::new(IoOwnedWait {
                    child: Box::new(AfterReapWait {
                        reaped: false,
                        late_observations: late_observations.clone(),
                        child: FakeWait {
                            stream: 16,
                            code: 0,
                            killed: Arc::default(),
                            waited: waited.clone(),
                            wait_hold: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                            exited: Arc::new(AtomicBool::new(true)),
                            leader_exited: Arc::new(AtomicBool::new(false)),
                            observed: false,
                        },
                    }),
                    reaped: None,
                    workers: [reader, writer],
                }),
                None,
                false,
            );
            until(|| !waited.lock().unwrap().is_empty()).await;
        });
        let (done, progress) = std_mpsc::sync_channel(1);
        let probe = runtime.spawn_blocking(move || {
            done.send(()).unwrap();
        });
        let thread_available = progress.recv_timeout(Duration::from_millis(250)).is_ok();
        let custody_retained = !reaps.is_empty();
        // Release and actually join all owned work before asserting, even RED.
        *hold.0.lock().unwrap() = false;
        hold.1.notify_all();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), reaps.next())
                .await
                .unwrap();
            probe.await.unwrap();
        });
        drop((reaps, io, inbound, outbound));
        runtime.shutdown_timeout(Duration::from_secs(2));
        assert!(
            thread_available,
            "a pending worker receipt parked the only available blocking thread"
        );
        assert!(
            custody_retained,
            "pending worker receipt released cleanup custody"
        );
        assert_eq!(
            late_observations.load(Ordering::SeqCst),
            0,
            "worker notification reobserved the child after its cleanup receipt"
        );
    }

    #[tokio::test]
    async fn leader39_exit_drives_scope_before_eof_and_preserves_final_parser_reply() {
        let spawner = FakeSpawner::new();
        spawner.reply_queries.store(true, Ordering::SeqCst);
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        spawner.feed(16, b"eof-query");
        let _ = next_channel_data(&mut outbound, 16).await;
        spawner.leader_exited.store(true, Ordering::SeqCst);
        let cleanup_started_before_eof = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            until(|| spawner.waited.lock().unwrap().contains(&16)),
        )
        .await
        .is_ok();
        inbound
            .send(keystrokes(16, b"late client input"))
            .await
            .unwrap();
        // The actual reader remains live until this fixture-owned EOF. A final
        // parser reply must still be admitted before sealing writer delivery.
        spawner.end_channel(16);
        let exit = next_control(&mut outbound).await;
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("ordinary natural exit joins every worker")
            .unwrap();
        let written = spawner.written.lock().unwrap();
        let reply_delivered = written
            .iter()
            .any(|(stream, bytes)| *stream == 16 && bytes == b"reply");
        let late_input_written = written
            .iter()
            .any(|(stream, bytes)| *stream == 16 && bytes == b"late client input");
        assert!(
            cleanup_started_before_eof,
            "leader exit did not advance retained scope before reader EOF"
        );
        assert_eq!(
            exit,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        assert!(
            reply_delivered,
            "leader exit closed the writer before its EOF parser reply"
        );
        assert!(
            !late_input_written,
            "new client input reached an ended leader"
        );
    }

    #[tokio::test]
    async fn session_cleanup_waits_for_a_writer_after_exact_child_reap() {
        let spawner = FakeSpawner::new();
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        inbound
            .send(keystrokes(16, b"held owned write"))
            .await
            .unwrap();
        until(|| spawner.write_attempts.load(Ordering::SeqCst) != 0).await;
        // Independently end the reader/child. The held write is the only remaining
        // blocking operation, so a child receipt cannot stand in for its join.
        spawner.end_channel(16);
        until(|| spawner.waited.lock().unwrap().contains(&16)).await;
        drop(inbound);
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        // Release and join before asserting on RED as well as GREEN. The guard
        // also releases an owned fixture write on every earlier unwind path.
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("released writer allowed session cleanup")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "session cleanup completed while its PTY writer was still executing"
        );
    }

    #[tokio::test]
    async fn natural_exit_with_idle_writer_has_no_cleanup_cycle() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        spawner.end_channel(16);
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("idle writer joins after EOF drops its sender")
            .unwrap();
        assert!(
            spawner.killed.lock().unwrap().is_empty(),
            "natural exit must not signal a reaped child"
        );
    }

    #[tokio::test]
    async fn session_cleanup_retains_a_reader_inside_read_after_child_reap() {
        let spawner = FakeSpawner::new();
        *spawner.held_reads.0.lock().unwrap() = true;
        let release = asynchronous_reaping::ReleaseWait(spawner.held_reads.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        until(|| spawner.reads.load(Ordering::SeqCst) != 0).await;
        drop(inbound);
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("released reader allowed session cleanup")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "child reap must not refund an executing read"
        );
    }

    #[tokio::test]
    async fn retired_writer_remains_owned_after_stream_reuse() {
        let spawner = FakeSpawner::new();
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        inbound
            .send(keystrokes(16, b"old held write"))
            .await
            .unwrap();
        until(|| spawner.write_attempts.load(Ordering::SeqCst) != 0).await;
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        drop(inbound);
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("both exact instances joined after release")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "reusing a stream lost its retired writer owner"
        );
    }
}
