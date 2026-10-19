mod terminal_replies {
    use super::*;
    use crate::channel_geometry::OutputGapCause;
    use crate::shell_server::{ScreenRepaint, ScreenReplyError};

    pub(super) struct QueryScreen;
    impl SessionScreen for QueryScreen {
        fn absorb(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ScreenReplyError> {
            match bytes {
                b"query" => Ok(b"reply".to_vec()),
                b"fail" => Err(ScreenReplyError::Overflow),
                _ => Ok(Vec::new()),
            }
        }
        fn flush_pending_output(&mut self) -> Result<Vec<u8>, ScreenReplyError> {
            Ok(Vec::new())
        }
        fn repaint(&mut self) -> Result<ScreenRepaint, ScreenReplyError> {
            Ok(ScreenRepaint {
                bytes: b"REPAINT".to_vec(),
                replies: Vec::new(),
            })
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

    struct ReplyScreen {
        calls: Arc<AtomicUsize>,
        overflow: bool,
        pending: Vec<u8>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl SessionScreen for ReplyScreen {
        fn absorb(&mut self, _: &[u8]) -> Result<Vec<u8>, ScreenReplyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.overflow {
                Err(ScreenReplyError::Overflow)
            } else {
                Ok(b"reply".to_vec())
            }
        }
        fn flush_pending_output(&mut self) -> Result<Vec<u8>, ScreenReplyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.events.lock().unwrap().push("flush");
            Ok(std::mem::take(&mut self.pending))
        }
        fn repaint(&mut self) -> Result<ScreenRepaint, ScreenReplyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ScreenRepaint {
                bytes: b"screen".to_vec(),
                replies: std::mem::take(&mut self.pending),
            })
        }
        fn prepare_resize(
            &mut self,
            _: TerminalSize,
        ) -> Result<
            Box<dyn crate::shell_server::PreparedScreenResize + '_>,
            crate::shell_server::ScreenPreparationError,
        > {
            self.events.lock().unwrap().push("prepare");
            Ok(Box::new(FakePreparedResize))
        }
    }

    fn screen(rig: &mut ResizeRig, overflow: bool, pending: &[u8]) -> Arc<AtomicUsize> {
        let calls = Arc::new(AtomicUsize::new(0));
        rig.channel.screened = true;
        rig.channel.screen = Box::new(ReplyScreen {
            calls: calls.clone(),
            overflow,
            pending: pending.to_vec(),
            events: rig.events.clone(),
        });
        calls
    }

    #[tokio::test]
    async fn reply44_actual_writer_keeps_fifo_and_only_reports_network_bytes() {
        let mut rig = ResizeRig::new(false, false);
        let (tx, rx) = mpsc::unbounded_channel();
        rig.channel.input_tx = tx;
        let network = rig
            .channel
            .input_budget
            .try_network(b"before".to_vec())
            .unwrap()
            .unwrap();
        rig.channel
            .input_tx
            .send(WriterInput::Network(network))
            .unwrap();
        assert!(admit_terminal_reply(
            &rig.io,
            &mut rig.channel,
            Ok(b"reply".to_vec())
        ));
        let network = rig
            .channel
            .input_budget
            .try_network(b"after".to_vec())
            .unwrap()
            .unwrap();
        rig.channel
            .input_tx
            .send(WriterInput::Network(network))
            .unwrap();
        assert_eq!(
            rig.channel.input_consumed, 0,
            "local replies cannot acknowledge user input"
        );
        let written = Arc::new(Mutex::new(Vec::new()));
        let writer = FakeWriter {
            stream: 16,
            written: written.clone(),
            attempts: Arc::default(),
            held: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
            broken: Arc::default(),
        };
        let reporter = rig.io.consumption_reporter();
        drop(rig.channel);
        tokio::task::spawn_blocking(move || {
            channel_writer_loop(16, rx, Box::new(writer), reporter)
        })
        .await
        .unwrap();
        assert_eq!(
            *written.lock().unwrap(),
            vec![
                (16, b"before".to_vec()),
                (16, b"reply".to_vec()),
                (16, b"after".to_vec()),
            ]
        );
        let mut consumed = 0;
        while let Ok(event) = rig.outbound.try_recv() {
            if let SessionOutbound::Consumed { stream_id, n } = event {
                assert_eq!(stream_id, 16);
                consumed += n;
            }
        }
        assert_eq!(consumed, 11);
    }

    #[test]
    fn reply44_held_local_batch_counts_toward_cap_and_ends_only_its_channel() {
        let mut rig = ResizeRig::new(false, false);
        let session_budget = crate::channel_input::SessionInputBudget::new();
        rig.channel.input_budget = session_budget.channel();
        let (tx, mut rx) = mpsc::unbounded_channel();
        rig.channel.input_tx = tx;
        assert!(admit_terminal_reply(
            &rig.io,
            &mut rig.channel,
            Ok(vec![b'r'; 64 * 1024])
        ));
        let held = rx.try_recv().unwrap();
        assert!(!admit_terminal_reply(
            &rig.io,
            &mut rig.channel,
            Ok(vec![b'x'])
        ));
        assert!(rig.channel.producer.reply_failed);
        assert!(
            !rig.channel.producer.eof,
            "admission failure is not reader EOF"
        );
        assert_eq!(held.bytes().len(), 64 * 1024);
        assert_eq!(held.network_bytes(), 0);
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ChannelOutput {
                stream: 16,
                output: ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, _),
                ..
            }
        ));
        let mut sibling = ResizeRig::new(false, false);
        sibling.channel.input_budget = session_budget.channel();
        let (tx, mut rx) = mpsc::unbounded_channel();
        sibling.channel.input_tx = tx;
        assert!(admit_terminal_reply(
            &sibling.io,
            &mut sibling.channel,
            Ok(b"ok".to_vec())
        ));
        assert_eq!(rx.try_recv().unwrap().bytes(), b"ok");
        drop(held);
        assert!(
            rig.channel.producer.reply_failed,
            "capacity return cannot revive a poisoned model"
        );
    }

    #[test]
    fn reply44_tiny_local_batches_stop_at_item_cap() {
        let mut rig = ResizeRig::new(false, false);
        let (tx, mut rx) = mpsc::unbounded_channel();
        rig.channel.input_tx = tx;
        for _ in 0..64 {
            assert!(admit_terminal_reply(
                &rig.io,
                &mut rig.channel,
                Ok(vec![b'x'])
            ));
        }
        let held = rx.try_recv().unwrap();
        assert!(!admit_terminal_reply(
            &rig.io,
            &mut rig.channel,
            Ok(vec![b'x'])
        ));
        assert!(rig.channel.producer.reply_failed);
        assert_eq!(held.bytes(), b"x");
    }

    #[test]
    fn reply44_failed_model_cannot_repaint_or_answer_after_attachment_reset() {
        let mut rig = ResizeRig::new(false, false);
        let calls = screen(&mut rig, true, b"pending");
        absorb_output(&rig.io, &mut rig.channel, b"offending query");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let first = rig.outbound.try_recv().unwrap();
        assert!(matches!(
            first,
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, _),
                ..
            }
        ));
        let origin = AttachmentContext {
            generation: 2,
            ..rig.channel.producer.origin
        };
        reset_producer(&mut rig.channel, origin);
        absorb_output(&rig.io, &mut rig.channel, b"new query");
        repaint_stale(&rig.io, 16, &mut rig.channel);
        resume_producer(&rig.io, &mut rig.channel);
        assert!(rig.resize(1, 120, 40));
        assert!(!admit_terminal_reply(
            &rig.io,
            &mut rig.channel,
            Ok(b"late".to_vec())
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            (rig.channel.request.cols, rig.channel.request.rows),
            (80, 24)
        );
        assert!(
            rig.outbound.try_recv().is_err(),
            "failure must be emitted only once by the producer"
        );
        let mut channels = HashMap::from([(16, rig.channel)]);
        repaint_all(&rig.io, &mut channels);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(rig.outbound.try_recv().is_err());
    }

    #[test]
    fn reply44_resize_flushes_old_geometry_before_preparation_and_ioctl() {
        let mut rig = ResizeRig::new(false, false);
        screen(&mut rig, false, b"old geometry reply");
        let (tx, mut rx) = mpsc::unbounded_channel();
        rig.channel.input_tx = tx;
        assert!(rig.resize(1, 100, 30));
        assert_eq!(
            *rig.events.lock().unwrap(),
            vec!["flush", "prepare", "ioctl"]
        );
        assert_eq!(rx.try_recv().unwrap().bytes(), b"old geometry reply");
        assert!(rx.try_recv().is_err());
        assert_eq!(
            (rig.channel.request.cols, rig.channel.request.rows),
            (100, 30)
        );
    }

    #[test]
    fn reply44_missing_writer_stops_before_resize_and_never_reports_input_credit() {
        let mut rig = ResizeRig::new(false, false);
        screen(&mut rig, false, b"old geometry reply");
        assert!(rig.resize(1, 100, 30));
        assert_eq!(*rig.events.lock().unwrap(), vec!["flush"]);
        assert_eq!(
            (rig.channel.request.cols, rig.channel.request.rows),
            (80, 24)
        );
        assert!(rig.channel.producer.reply_failed);
        assert_eq!(rig.channel.input_consumed, 0);
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, _),
                ..
            }
        ));
        assert!(rig.outbound.try_recv().is_err());
    }

    #[test]
    fn reply44_failed_bootstrap_waits_for_committed_geometry_without_replaying_model() {
        let mut rig = ResizeRig::new(false, false);
        let calls = screen(&mut rig, true, b"pending");
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                rig.channel
                    .producer
                    .timeline
                    .try_reserve(EntryClass::Lifecycle, GEOMETRY_BYTES)
                    .unwrap(),
            );
        }
        assert!(!checkpoint(&rig.io, &mut rig.channel));
        absorb_output(&rig.io, &mut rig.channel, b"bad query");
        assert!(rig.channel.producer.reply_failed);
        assert!(rig.channel.producer.checkpoint_due);
        let failure = rig.outbound.try_recv().unwrap();
        assert!(matches!(
            failure,
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, _),
                ..
            }
        ));
        drop(held.pop());
        resume_producer(&rig.io, &mut rig.channel);
        assert_eq!(rig.next_geometry(), current_geometry(&rig.channel));
        assert!(!rig.channel.producer.checkpoint_due);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(rig.outbound.try_recv().is_err());
    }

    #[tokio::test]
    async fn reply44_runner_keeps_sibling_progress_and_requires_real_eof_reap_and_delivery() {
        let spawner = FakeSpawner::new();
        spawner.reply_queries.store(true, Ordering::SeqCst);
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
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
        spawner.feed(16, b"query");
        until(|| {
            spawner
                .written
                .lock()
                .unwrap()
                .iter()
                .any(|(s, bytes)| *s == 16 && bytes == b"reply")
        })
        .await;
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = asynchronous_reaping::ReleaseWait(spawner.wait_hold.clone());
        spawner.feed(16, b"fail");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    outbound.recv().await.unwrap(),
                    SessionOutbound::ChannelOutput {
                        stream: 16,
                        output: ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, _),
                        ..
                    }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("ordered terminal failure");
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        assert!(
            requests.lock().unwrap().is_empty(),
            "stop is not reader EOF"
        );
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        inbound
            .send(keystrokes(20, b"healthy sibling"))
            .await
            .unwrap();
        until(|| {
            spawner
                .written
                .lock()
                .unwrap()
                .iter()
                .any(|(s, bytes)| *s == 20 && bytes == b"healthy sibling")
        })
        .await;
        assert!(!spawner.killed.lock().unwrap().contains(&20));
        spawner.end_channel(16);
        until(|| !requests.lock().unwrap().is_empty()).await;
        assert_no_control(&mut outbound).await;
        drop(release);
        until(|| spawner.opens.outstanding() == 0).await;
        assert_no_control(&mut outbound).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: token_for(&requests, 16),
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
}
