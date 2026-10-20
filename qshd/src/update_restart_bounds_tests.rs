// Real Restarts counter + real channel runner/reaper integration. The process
// adapter is synthetic; a held exact reap observation cannot release custody.
struct RestartCountProvider(Arc<Restarts>);
impl DaemonUpdates for RestartCountProvider {
    fn about(&self) -> Option<About> {
        None
    }
    fn offer(
        &self,
        _: &Principal,
        _: &UpdateOffer,
    ) -> std::result::Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        Err(UpdateAnswer::NotAllowed)
    }
    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.0.subscribe()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        self.0.join(restart)
    }
    fn channels_released(&self, restart: u64) {
        self.0.release(restart);
    }
}
#[derive(Default)]
struct RestartHeldChild {
    released: AtomicBool,
    stopped: AtomicBool,
    reaped: AtomicBool,
    changed: tokio::sync::Notify,
    feed: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}
impl RestartHeldChild {
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.feed.lock().unwrap().take();
        self.changed.notify_one();
    }
}
struct RestartReleaseChild(Arc<RestartHeldChild>);
impl Drop for RestartReleaseChild {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct RestartCountWait(Arc<RestartHeldChild>);
impl transport::channel_server::ChannelWait for RestartCountWait {
    fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
        if self.0.released.load(Ordering::SeqCst) {
            self.0.reaped.store(true, Ordering::SeqCst);
            transport::channel_server::ChildStatus::Reaped { code: Some(0) }
        } else {
            transport::channel_server::ChildStatus::Running
        }
    }
    fn kill(&mut self) {
        self.0.stopped.store(true, Ordering::SeqCst);
        self.0.changed.notify_one();
    }
    fn wait(self: Box<Self>) -> i32 {
        assert!(self.0.released.load(Ordering::SeqCst));
        0
    }
    fn cleanup_uninstalled(
        &mut self,
        authority: &transport::channel_open::CleanupAuthority<'_>,
    ) -> transport::channel_open::CleanupStatus {
        if self.0.released.load(Ordering::SeqCst) {
            authority.reaped()
        } else {
            transport::channel_open::CleanupStatus::Unknown
        }
    }
}
struct RestartCountReader(std::sync::mpsc::Receiver<()>);
impl Read for RestartCountReader {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}
struct RestartCountResize;
impl transport::shell_server::ResizeHandle for RestartCountResize {
    fn try_resize(&self, _: u16, _: u16) -> std::result::Result<(), String> {
        Ok(())
    }
}
struct RestartCountSpawner {
    registry: Arc<ChannelOpenRegistry>,
    child: Arc<RestartHeldChild>,
}
impl transport::channel_server::ChannelSpawner for RestartCountSpawner {
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
    ) -> std::result::Result<
        transport::channel_open::UninstalledChannel,
        transport::channel_open::SpawnFailure,
    > {
        let (tx, rx) = std::sync::mpsc::channel();
        *self.child.feed.lock().unwrap() = Some(tx);
        Ok(custody
            .protect(
                Box::new(RestartCountWait(self.child.clone())),
                Box::new(transport::shell_server::NoScreen),
            )
            .finish(
                Box::new(RestartCountReader(rx)),
                Box::new(std::io::sink()),
                Box::new(RestartCountResize),
            ))
    }
}

#[tokio::test]
async fn capacity_restart_denied_announcement_joins_real_counter_until_actual_reap() {
    use transport::channel::{encode_client, ChannelKind, ClientRecord, OpenRequest};
    use transport::session_manager::{
        AttachmentContext, SessionInbound, SessionIo, SessionOutbound, StreamData,
    };
    let restarts = Arc::new(Restarts::new());
    let child = Arc::new(RestartHeldChild::default());
    let release = RestartReleaseChild(child.clone());
    let (io, inbound, mut outbound) = SessionIo::test_pair_for(me(), [0x26; 16]);
    inbound
        .try_send(SessionInbound::Live(AttachmentContext {
            features: transport::Features::CHANNEL_GEOMETRY | transport::Features::RESOURCE_LIMITS,
            ..Default::default()
        }))
        .unwrap();
    let runner = tokio::spawn(transport::channel_server::run_channel_session_with(
        io,
        Arc::new(RestartCountSpawner {
            registry: ChannelOpenRegistry::new(Default::default()),
            child: child.clone(),
        }),
        Some(Arc::new(RestartCountProvider(restarts.clone()))),
    ));
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: transport::channel::CONTROL_STREAM,
            data: encode_client(&ClientRecord::Open(OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: vec![],
            })),
        }))
        .await
        .unwrap();
    let opened = tokio::time::timeout(Duration::from_secs(5), async {
        loop { if matches!(outbound.recv().await.expect("runner alive until Opened"), SessionOutbound::ReservedControl { bytes, .. } if bytes == transport::channel::encode_server(&transport::channel::ServerRecord::Opened { stream: 16 })) { break; } }
    }).await;
    let first = restarts.announce().unwrap();
    // Hold the first actual reserved output: standalone consumption is not ACK.
    let old_debt = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = outbound.recv().await.expect("runner alive");
            if matches!(event, SessionOutbound::ReservedSessionControl { .. }) {
                break event;
            }
        }
    })
    .await;
    restarts.end();
    let current = restarts.announce().unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                outbound
                    .recv()
                    .await
                    .expect("runner alive until exhaustion"),
                SessionOutbound::ResourceExhausted { .. }
            ) {
                break;
            }
        }
    })
    .await;
    let before_drain = {
        let c = restarts.count();
        (c.restart, c.joined, c.released)
    };
    restarts.drain(current);
    let stopped = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let changed = child.changed.notified();
            if child.stopped.load(Ordering::SeqCst) {
                break;
            }
            changed.await;
        }
    })
    .await;
    let while_held = {
        let c = restarts.count();
        (c.joined, c.released)
    };
    drop(release);
    let completed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if restarts.count().released == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    drop(inbound);
    tokio::time::timeout(Duration::from_secs(5), runner)
        .await
        .expect("runner joins after actual reap")
        .unwrap();
    let final_count = {
        let c = restarts.count();
        (c.joined, c.released)
    };
    drop((outbound, old_debt));
    assert!(opened.is_ok());
    assert!(
        denied.is_ok(),
        "second announcement cannot reuse held first lease"
    );
    assert_ne!(first, current);
    assert_eq!(
        before_drain,
        (current, 1, 0),
        "denied current Announced still joins exactly once"
    );
    assert!(stopped.is_ok());
    assert_eq!(while_held, (1, 0), "kill request is not reap proof");
    assert!(completed.is_ok());
    assert!(child.reaped.load(Ordering::SeqCst));
    assert_eq!(final_count, (1, 1));
}
