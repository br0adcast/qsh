mod sync_deadlines {
    use super::*;

    #[tokio::test]
    async fn sync111_due_channel_progresses_behind_closed_gate_and_held_writer() {
        let spawner = FakeSpawner::new();
        spawner.reply_queries.store(true, Ordering::SeqCst);
        let (io, inbound, mut outbound) = channel_pair();
        let gate = io.send_gate(16, GateKind::Screen);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        gate.set_metadata_blocked(true);
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        spawner.feed(16, b"deferred-query");
        until(|| spawner.write_attempts.load(Ordering::SeqCst) == 1).await;
        assert!(spawner.written.lock().unwrap().is_empty());
        inbound
            .send(open(20, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 20).await,
            b"hello from the shell"
        );
        spawner.feed(20, b"deferred-query");
        until(|| spawner.write_attempts.load(Ordering::SeqCst) == 2).await;
        drop(release);
        until(|| spawner.written.lock().unwrap().len() == 2).await;
        // A later independently scheduled tick is witnessed by another due
        // batch. The first two must not be generated a second time.
        spawner.feed(20, b"deferred-query");
        until(|| spawner.written.lock().unwrap().len() == 3).await;
        let written = spawner.written.lock().unwrap().clone();
        assert_eq!(
            written.iter().filter(|(stream, _)| *stream == 16).count(),
            1
        );
        assert_eq!(
            written.iter().filter(|(stream, _)| *stream == 20).count(),
            2
        );
        assert!(written.iter().all(|(_, bytes)| bytes == b"reply"));
        while let Ok(event) = outbound.try_recv() {
            if let SessionOutbound::Consumed { stream_id, .. } = event {
                assert!(
                    stream_id < 16,
                    "local replies never consume network input credit"
                );
            }
        }
        drop(inbound);
        runner.await.unwrap();
    }
    struct FailingDueScreen(Arc<AtomicUsize>);
    impl SessionScreen for FailingDueScreen {
        fn absorb(&mut self, _: &[u8]) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            panic!("not a fresh-output test");
        }
        fn sync_deadline(&self) -> Option<std::time::Instant> {
            Some(std::time::Instant::now())
        }
        fn flush_due_output(
            &mut self,
            _: std::time::Instant,
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            self.flush_pending_output()
        }
        fn flush_pending_output(
            &mut self,
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(crate::shell_server::ScreenReplyError::Overflow)
        }
        fn repaint(
            &mut self,
        ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError>
        {
            panic!("failed models must not repaint");
        }
        fn prepare_resize(
            &mut self,
            _: TerminalSize,
        ) -> Result<
            Box<dyn crate::shell_server::PreparedScreenResize + '_>,
            crate::shell_server::ScreenPreparationError,
        > {
            Ok(Box::new(FakePreparedResize))
        }
    }

    #[test]
    fn sync111_due_overflow_is_disclosed_once_and_failed_or_eof_models_stay_silent() {
        for (failed, eof, expected_calls) in [(false, false, 1), (true, false, 0), (false, true, 0)]
        {
            let mut rig = ResizeRig::new(false, false);
            let calls = Arc::new(AtomicUsize::new(0));
            rig.channel.screen = Box::new(FailingDueScreen(calls.clone()));
            rig.channel.producer.reply_failed = failed;
            rig.channel.producer.eof = eof;
            let now = std::time::Instant::now();
            flush_due_terminal_output(&rig.io, &mut rig.channel, now);
            flush_due_terminal_output(&rig.io, &mut rig.channel, now);
            assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
            assert_eq!(rig.channel.producer.reply_failed, !eof);
            let mut gaps = 0;
            while let Ok(event) = rig.outbound.try_recv() {
                if matches!(
                    event,
                    SessionOutbound::ChannelOutput {
                        output: ChannelOutput::OutputGap(_, _),
                        ..
                    }
                ) {
                    gaps += 1;
                }
            }
            assert_eq!(gaps, expected_calls);
        }
    }
}
