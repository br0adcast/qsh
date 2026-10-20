// Included in channel_server::tests; exercises the real session loop.
mod asynchronous_reaping {
    use super::*;

    pub(super) struct ReleaseWait(pub(super) Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Drop for ReleaseWait {
        fn drop(&mut self) {
            let (lock, changed) = &*self.0;
            *lock.lock().unwrap() = false;
            changed.notify_all();
        }
    }

    #[tokio::test]
    async fn output_eof_does_not_block_another_channel_while_child_lives() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = ReleaseWait(spawner.wait_hold.clone());
        spawner.end_channel(16);
        until(|| spawner.waited.lock().unwrap().contains(&16)).await;
        // The child's stdout ended, but the wait is deliberately still pending.
        // The barrier above proves the runner reached that exact state.
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            next_control(&mut outbound),
        )
        .await;
        drop(release);
        assert_eq!(
            answer.expect("a live child after EOF must not stall another OPEN"),
            ServerRecord::Opened { stream: 20 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 20).await,
            b"hello from the shell"
        );
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn delivered_output_waits_for_child_reap_without_blocking_input() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = ReleaseWait(spawner.wait_hold.clone());
        spawner.end_channel(16);
        until(|| !requests.lock().unwrap().is_empty()).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: token_for(&requests, 16),
            })
            .await
            .unwrap();
        // An ordered OPEN is a barrier proving the preceding delivery was applied.
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        inbound
            .send(keystrokes(20, b"still responsive"))
            .await
            .unwrap();
        until(|| {
            spawner
                .written
                .lock()
                .unwrap()
                .iter()
                .any(|(stream, bytes)| *stream == 20 && bytes == b"still responsive")
        })
        .await;
        assert_no_control(&mut outbound).await;
        drop(release);
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn closing_an_eof_channel_requests_stop_and_keeps_custody_until_reaped() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = ReleaseWait(spawner.wait_hold.clone());
        spawner.end_channel(16);
        until(|| spawner.waited.lock().unwrap().contains(&16)).await;
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        assert_eq!(spawner.opens.outstanding(), 1);
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        drop(release);
        until(|| spawner.opens.outstanding() == 0).await;
        assert_eq!(
            spawner
                .killed
                .lock()
                .unwrap()
                .iter()
                .filter(|&&s| s == 16)
                .count(),
            1
        );
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn old_reap_and_delivery_cannot_end_a_reused_stream() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = ReleaseWait(spawner.wait_hold.clone());
        spawner.end_channel(16);
        until(|| !requests.lock().unwrap().is_empty()).await;
        let old_token = token_for(&requests, 16);
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        drop(release);
        until(|| spawner.opens.outstanding() == 0).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: old_token,
            })
            .await
            .unwrap();
        inbound
            .send(keystrokes(16, b"replacement survives"))
            .await
            .unwrap();
        until(|| {
            spawner
                .written
                .lock()
                .unwrap()
                .iter()
                .any(|(stream, bytes)| *stream == 16 && bytes == b"replacement survives")
        })
        .await;
        assert_no_control(&mut outbound).await;
        spawner.end_channel(16);
        until(|| requests.lock().unwrap().len() == 2).await;
        let new_token = token_for(&requests, 16);
        assert_ne!(old_token, new_token);
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: new_token,
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn warm_reattach_retains_the_waiting_child_and_renews_delivery_proof() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = ReleaseWait(spawner.wait_hold.clone());
        spawner.end_channel(16);
        until(|| !requests.lock().unwrap().is_empty()).await;
        let token = token_for(&requests, 16);
        let mut context = channel_context();
        context.generation = 1;
        inbound
            .send(SessionInbound::ResumeReset(context))
            .await
            .unwrap();
        let snapshot = next_snapshot(&mut outbound, &snapshots).await;
        match snapshot {
            ServerRecord::ChannelSnapshot(snapshot) => {
                assert!(snapshot.active().is_empty());
                assert_eq!(snapshot.draining().len(), 1);
                assert_eq!(snapshot.draining()[0].stream, 16);
                assert_eq!(snapshot.draining()[0].instance.get(), token);
            }
            other => panic!("expected draining inventory, got {other:?}"),
        }
        // The bridge retains and retargets the original final marker. The
        // runner must not allocate another marker on every attachment.
        assert_eq!(requests.lock().unwrap().len(), 1);
        drop(release);
        until(|| spawner.opens.outstanding() == 0).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token,
            })
            .await
            .unwrap();
        assert_no_control(&mut outbound).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 1,
                stream: 16,
                token,
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        assert!(
            spawner.killed.lock().unwrap().is_empty(),
            "natural reap must never signal a dead PID"
        );
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn forced_stop_preserves_reader_tail_until_actual_eof() {
        let mut rig = ResizeRig::new(false, false);
        let killed = Arc::new(Mutex::new(Vec::new()));
        rig.channel.wait = Some(Box::new(FakeWait {
            stream: 16,
            code: 7,
            killed: killed.clone(),
            waited: Arc::default(),
            wait_hold: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
            exited: Arc::new(AtomicBool::new(false)),
            leader_exited: Arc::new(AtomicBool::new(false)),
            observed: false,
        }));
        let mut reaps = ReapSet::default();
        begin_channel_ending(&mut rig.channel, &mut reaps, true);
        let completion = reaps.next().await;
        assert_eq!(completion.code, Some(7));
        assert_eq!(*killed.lock().unwrap(), vec![16]);
        assert!(rig.channel.wait.is_none(), "one custody transfer");
        assert!(
            !rig.channel.producer.eof,
            "process cleanup is not proof that the PTY reader drained its final bytes"
        );
        rig.channel.terminal_code = Some(completion.code);
        forward_output(
            &rig.io,
            16,
            &mut rig.channel,
            b"buffered after process reap",
        );
        assert!(matches!(rig.outbound.try_recv().unwrap(),
            SessionOutbound::ChannelOutput { output: ChannelOutput::Data(ref bytes), .. }
            if bytes == b"buffered after process reap"));
        assert!(
            rig.outbound.try_recv().is_err(),
            "no premature final marker"
        );
        // The reader now reports its real EOF, after its ordered final chunk.
        rig.channel.producer.eof = true;
        let pending = finish_channel(&rig.io, rig.channel, &mut reaps);
        assert_eq!(
            pending.code,
            Some(Some(7)),
            "reap-before-EOF status survives"
        );
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::DeliveryMarker(..),
                ..
            }
        ));
        assert!(
            reaps.is_empty(),
            "finishing must not register the process twice"
        );
        assert_eq!(*killed.lock().unwrap(), vec![16]);
    }

    struct MissingStatusWait;
    impl ChannelWait for MissingStatusWait {
        fn poll_exit(&mut self) -> ChildStatus {
            ChildStatus::Reaped { code: None }
        }
        fn kill(&mut self) {
            panic!("a reaped child must not be signalled");
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("runner must use nonblocking status");
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            authority.reaped()
        }
    }
    struct MissingStatusSpawner(Arc<FakeSpawner>);
    impl ChannelSpawner for MissingStatusSpawner {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.0.open_registry()
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
            if req.stream != 16 {
                return self.0.spawn(owner, login, req, term, custody);
            }
            Ok(custody
                .protect(
                    Box::new(MissingStatusWait),
                    Box::new(crate::shell_server::NoScreen),
                )
                .finish(
                    Box::new(std::io::Cursor::new(b"last output")),
                    Box::new(std::io::sink()),
                    Box::new(FakeResize {
                        stream: req.stream,
                        sizes: Arc::new(Mutex::new(Vec::new())),
                    }),
                ))
        }
    }

    #[tokio::test]
    async fn reap32_missing_status_ends_only_its_channel_after_final_delivery() {
        let healthy = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let runner = tokio::spawn(run_channel_session(
            io,
            Arc::new(MissingStatusSpawner(healthy.clone())),
        ));
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        let _ = next_channel_data(&mut outbound, 20).await;
        open_a_shell_channel(&inbound, &mut outbound).await;
        assert_eq!(next_channel_data(&mut outbound, 16).await, b"last output");
        until(|| !requests.lock().unwrap().is_empty()).await;
        inbound
            .send(SessionInbound::Delivered {
                stream: 16,
                token: token_for(&requests, 16),
                generation: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::ExitStatusUnavailable { stream: 16 }
        );
        inbound
            .send(keystrokes(20, b"healthy sibling"))
            .await
            .unwrap();
        until(|| {
            healthy
                .written
                .lock()
                .unwrap()
                .iter()
                .any(|(stream, bytes)| *stream == 20 && bytes == b"healthy sibling")
        })
        .await;
        assert!(!runner.is_finished());
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(
            healthy.opens.outstanding(),
            0,
            "exact cleanup proof releases custody"
        );
    }
}
