// Real backend records cross the client parser and CLI session dispatch seam.
mod async_open_tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{self, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc as blocking, Arc, Condvar, Mutex};
    use tokio::sync::mpsc;
    use transport::channel::{encode_server, ServerRecord, CONTROL_STREAM};
    use transport::channel_open::{
        ChannelOpenRegistry, CleanupAuthority, CleanupStatus, OpenCustody, SpawnFailure,
        UninstalledChannel,
    };
    use transport::channel_server::{ChannelSpawner, ChannelWait};
    use transport::session_manager::{
        AttachmentContext, ChannelOutput, LoginId, SessionBackend, SessionInbound, SessionIo,
        SessionOutbound, StreamData,
    };
    use transport::shell_frame::{encode_shell, ShellRecord};

    type Feeds = Arc<Mutex<HashMap<u8, blocking::Sender<()>>>>;
    struct Reader(blocking::Receiver<()>);
    impl Read for Reader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }
    struct Wait {
        feeds: Feeds,
        stream: u8,
    }
    impl ChannelWait for Wait {
        fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
            transport::channel_server::ChildStatus::Reaped { code: Some(7) }
        }
        fn kill(&mut self) {
            self.feeds.lock().unwrap().remove(&self.stream);
        }
        fn wait(self: Box<Self>) -> i32 {
            7
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            self.kill();
            authority.no_child() // This fixture owns no OS child.
        }
    }
    struct Resize;
    impl transport::shell_server::ResizeHandle for Resize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    struct Backend {
        registry: Arc<ChannelOpenRegistry>,
        feeds: Feeds,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
        blocked_calls: AtomicUsize,
    }
    impl ChannelSpawner for Backend {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &transport::auth::Principal,
            _: LoginId,
            req: &transport::channel::OpenRequest,
            _: Option<&str>,
            custody: &OpenCustody,
        ) -> Result<UninstalledChannel, SpawnFailure> {
            let (tx, rx) = blocking::channel();
            self.feeds.lock().unwrap().insert(req.stream, tx);
            let guard = custody.protect(
                Box::new(Wait {
                    feeds: self.feeds.clone(),
                    stream: req.stream,
                }),
                Box::new(transport::shell_server::NoScreen),
            );
            if req.stream == 18 {
                self.blocked_calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                let mut released = self.release.0.lock().unwrap();
                while !*released {
                    released = self.release.1.wait(released).unwrap();
                }
            }
            Ok(guard.finish(Box::new(Reader(rx)), Box::new(io::sink()), Box::new(Resize)))
        }
    }
    struct Cleanup(Arc<Backend>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            *self.0.release.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
            self.0.release.1.notify_all();
            self.0
                .feeds
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
        }
    }
    type Client = ChannelSession<QshSubstrate<Box<dyn FnMut(u8, Vec<u8>) + Send>>>;
    fn deliver(client: &mut Client, message: SessionOutbound) -> Vec<SessionEvent> {
        let (stream, bytes) = match message {
            SessionOutbound::ChannelOpened { stream, .. } => (
                CONTROL_STREAM,
                encode_server(&ServerRecord::Opened { stream }),
            ),
            SessionOutbound::ChannelRefused { stream, reason, .. } => (
                CONTROL_STREAM,
                encode_server(&ServerRecord::Refused { stream, reason }),
            ),
            SessionOutbound::ChannelExit { stream, code, .. } => (
                CONTROL_STREAM,
                encode_server(&match code { Some(code) => ServerRecord::Exit { stream, code }, None => ServerRecord::ExitStatusUnavailable { stream } }),
            ),
            SessionOutbound::ChannelOutput { stream, output, .. } => {
                let record = match output {
                    ChannelOutput::Geometry(record, _) => ShellRecord::Geometry(record),
                    ChannelOutput::Data(bytes) => ShellRecord::Data(bytes),
                    ChannelOutput::EchoAck(offset, _) => ShellRecord::EchoAck(offset),
                    ChannelOutput::DeliveryMarker(..) => return Vec::new(),
                };
                (stream, encode_shell(&record).unwrap())
            }
            SessionOutbound::Data(data) => (data.stream_id, data.data),
            SessionOutbound::ProtocolFailure { .. } => panic!("fixture server protocol failure"),
            _ => return Vec::new(),
        };
        client.on_bytes(stream, &bytes)
    }
    async fn next(
        output: &mut mpsc::UnboundedReceiver<SessionOutbound>,
        phase: &str,
    ) -> SessionOutbound {
        tokio::time::timeout(std::time::Duration::from_secs(5), output.recv())
            .await
            .expect(phase)
            .expect("backend remains live")
    }

    #[tokio::test]
    async fn open24_reset_does_not_replay_unacknowledged_command() {
        let backend = Arc::new(Backend {
            registry: ChannelOpenRegistry::new(Default::default()),
            feeds: Default::default(),
            entered: Default::default(),
            release: Default::default(),
            blocked_calls: AtomicUsize::new(0),
        });
        let cleanup = Cleanup(backend.clone());
        let (io, input, mut output) = SessionIo::test_pair_for(
            transport::auth::Principal {
                uid: 1000,
                name: "fixture".into(),
                identity: "fixture".into(),
                incarnation: 0,
            },
            [0; 16],
        );
        let snapshots = io.snapshot_reader_for_test();
        let owner = qshd::channel_backend::ChannelSessionBackend::with_spawner(backend.clone());
        let runner = tokio::spawn(owner.run(io));
        let initial = AttachmentContext {
            generation: 1,
            session_id: 11,
            features: transport::Features::CHANNEL_GEOMETRY,
        };
        input.send(SessionInbound::Live(initial)).await.unwrap();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let sink: Box<dyn FnMut(u8, Vec<u8>) + Send> = {
            let input = input.clone();
            let sent = sent.clone();
            Box::new(move |stream, bytes| {
                sent.lock().unwrap().push((stream, bytes.clone()));
                input
                    .try_send(SessionInbound::Data(StreamData {
                        stream_id: stream,
                        data: bytes,
                    }))
                    .unwrap();
            })
        };
        let mut client = ChannelSession::new(QshSubstrate::new(sink));
        let active = client.open_shell(20, 5).unwrap();
        let draining = client
            .open_command(b"fixture-retained-exit", 20, 5)
            .unwrap();
        assert_eq!((active, draining), (16, 17));
        let mut retained_geometry = None;
        while !client.is_ready(active) || !client.is_ready(draining) {
            let message = next(&mut output, "initial ready").await;
            if let SessionOutbound::ChannelOutput {
                stream,
                output: ChannelOutput::Geometry(record, _),
                ..
            } = &message
            {
                if *stream == draining {
                    retained_geometry = Some(*record);
                }
            }
            deliver(&mut client, message);
        }
        backend.feeds.lock().unwrap().remove(&draining);
        let retained_marker = loop {
            let message = next(&mut output, "original final marker").await;
            if let SessionOutbound::ChannelOutput {
                stream,
                output: ChannelOutput::DeliveryMarker(marker, _),
                ..
            } = &message
            {
                if *stream == draining {
                    break marker.token;
                }
            }
            deliver(&mut client, message);
        };
        let pending = client
            .open_command(b"fixture-side-effect-once", 20, 5)
            .unwrap();
        assert_eq!(pending, 18);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            backend.entered.notified(),
        )
        .await
        .unwrap();
        let before_reset = sent.lock().unwrap().clone();
        client.reset_attachment();
        let resumed = AttachmentContext {
            generation: 2,
            session_id: 12,
            ..initial
        };
        input
            .send(SessionInbound::ResumeReset(resumed))
            .await
            .unwrap();
        let snapshot = loop {
            let message = next(&mut output, "resume snapshot").await;
            if let SessionOutbound::ResumeBarrier { generation } = message {
                break snapshots(generation).expect("actual runner snapshot");
            }
        };
        assert_eq!(
            snapshot
                .active()
                .iter()
                .map(|entry| entry.request.stream)
                .collect::<Vec<_>>(),
            vec![active]
        );
        assert_eq!(
            snapshot
                .draining()
                .iter()
                .map(|entry| entry.stream)
                .collect::<Vec<_>>(),
            vec![draining]
        );
        let announced = client.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::ChannelSnapshot(snapshot)),
        );
        let mut pending_view = geometry_session();
        pending_view.assume_channel_opening();
        pending_view.on_reattached(0);
        let pending_actions = channel_events(
            announced.clone(),
            &mut Some(pending),
            &mut pending_view,
            &mut Vec::new(),
            &|| 0,
        );
        assert!(pending_actions
            .iter()
            .any(|a| matches!(a, Action::ShellUnavailable)));
        assert!(pending_actions
            .iter()
            .any(|a| matches!(a, Action::Exit(13))));
        assert!(!pending_actions
            .iter()
            .any(|a| matches!(a, Action::OpenShell { .. })));
        let mut retained_view = geometry_session();
        retained_view.on_channel_ready(draining, 0);
        retained_view.on_reattached(0);
        let mut retained_actions = channel_events(
            announced,
            &mut Some(draining),
            &mut retained_view,
            &mut Vec::new(),
            &|| 0,
        );
        assert!(!retained_actions
            .iter()
            .any(|a| matches!(a, Action::ShellUnavailable | Action::Exit(_))));
        // This in-process fixture owns the bridge's retained empty-output
        // frontier: replay the actual earlier Geometry, then acknowledge the
        // actual marker for the new attachment. The runner does not regenerate
        // a PendingExit's marker after reset; that owner normally is the bridge.
        let replay = client.on_bytes(
            draining,
            &encode_shell(&ShellRecord::Geometry(retained_geometry.unwrap())).unwrap(),
        );
        retained_actions.extend(channel_events(
            replay,
            &mut Some(draining),
            &mut retained_view,
            &mut Vec::new(),
            &|| 1,
        ));
        input
            .send(SessionInbound::Delivered {
                stream: draining,
                generation: resumed.generation,
                token: retained_marker,
            })
            .await
            .unwrap();
        loop {
            let message = next(&mut output, "retained final Exit").await;
            if let SessionOutbound::ChannelOutput {
                stream,
                origin,
                output: ChannelOutput::DeliveryMarker(marker, _),
                ..
            } = &message
            {
                input
                    .send(SessionInbound::Delivered {
                        stream: *stream,
                        generation: origin.generation,
                        token: marker.token,
                    })
                    .await
                    .unwrap();
            }
            let events = deliver(&mut client, message);
            let finished = events.iter().any(
                |event| matches!(event, SessionEvent::Exit { ch, code: 7 } if *ch == draining),
            );
            retained_actions.extend(channel_events(
                events,
                &mut Some(draining),
                &mut retained_view,
                &mut Vec::new(),
                &|| 1,
            ));
            if finished {
                break;
            }
        }
        assert!(retained_actions
            .iter()
            .any(|a| matches!(a, Action::Exit(7))));
        assert!(!retained_actions
            .iter()
            .any(|a| matches!(a, Action::OpenShell { .. } | Action::ShellUnavailable)));
        *backend.release.0.lock().unwrap() = true;
        backend.release.1.notify_all();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while backend.registry.outstanding() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        while let Ok(message) = output.try_recv() {
            assert!(!matches!(
                &message,
                SessionOutbound::ChannelOpened { stream: 18, .. }
                    | SessionOutbound::ChannelExit { stream: 18, .. }
                    | SessionOutbound::ChannelRefused { stream: 18, .. }
            ));
            deliver(&mut client, message);
        }
        assert_eq!(
            *sent.lock().unwrap(),
            before_reset,
            "reset must never issue another OPEN or replay the command"
        );
        assert_eq!(backend.blocked_calls.load(Ordering::SeqCst), 1);
        drop(client);
        drop(input);
        drop(cleanup);
        runner.await.unwrap();
        assert_eq!(backend.registry.outstanding(), 0);
    }
}
