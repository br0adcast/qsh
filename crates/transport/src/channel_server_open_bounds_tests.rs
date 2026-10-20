struct ControlOpenSpawner {
    registry: Arc<crate::channel_open::ChannelOpenRegistry>,
    entered: AtomicUsize,
    completed: AtomicUsize,
    changed: tokio::sync::Notify,
    released: (Mutex<bool>, std::sync::Condvar),
}
impl ControlOpenSpawner {
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}
struct ReleaseControlOpen(Arc<ControlOpenSpawner>);
impl Drop for ReleaseControlOpen {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl ChannelSpawner for ControlOpenSpawner {
    fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
        self.registry.clone()
    }
    fn spawn(
        &self,
        _owner: &Principal,
        _login: LoginId,
        _request: &OpenRequest,
        _term: Option<&str>,
        custody: &crate::channel_open::OpenCustody,
    ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
        let mut released = self.released.0.lock().unwrap();
        while !*released {
            released = self.released.1.wait(released).unwrap();
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        Err(custody.refuse_before_creation("controlled factory refusal".into()))
    }
}

#[test]
fn capacity_open_mandatory_preflight_precedes_factory_and_keeps_control_responsive() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let factory = Arc::new(ControlOpenSpawner {
        registry: FakeSpawner::new().open_registry(),
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let observed = runtime.block_on(async {
        let _reset = ResetAdmissionHooks;
        let release = ReleaseControlOpen(factory.clone());
        let (io, inbound, mut outbound) = about_pair();
        let global = io.global_control_budget();
        let mut held = (0..MAX_CHANNELS)
            .map(|_| {
                io.control_budget()
                    .reserve(crate::control_budget::Response::Open)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let paused = Arc::new(tokio::sync::Notify::new());
        let notify = paused.clone();
        CONTROL_REFUND_BEFORE_SELECT.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || notify.notify_one()));
        });
        let runner = tokio::spawn(run_channel_session(io, factory.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        let paused_before_factory =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::select! {
                    _ = paused.notified() => true,
                    _ = factory.changed.notified() => false,
                }
            })
            .await
            .expect("either real paused admission or actual factory entry");
        inbound
            .send(SessionInbound::RepaintCutover {
                generation: 0,
                sequence: 26,
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if matches!(
                    outbound.recv().await.unwrap(),
                    SessionOutbound::RepaintBarrier {
                        generation: 0,
                        sequence: 26
                    }
                ) {
                    break;
                }
            }
        })
        .await
        .expect("runner handles positive repaint barrier while request is held");
        let entered_before_refund = factory.entered.load(Ordering::SeqCst);
        drop(held.pop().unwrap());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let changed = factory.changed.notified();
                if factory.entered.load(Ordering::SeqCst) != 0 {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("refunded mandatory room admits the actual factory");
        drop(release);
        let response = next_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        drop((outbound, held));
        (
            paused_before_factory,
            entered_before_refund,
            response,
            global.retained_for_test(),
        )
    });
    drop(runtime); // Join every actual held factory before outcome assertions.
    assert_eq!(factory.entered.load(Ordering::SeqCst), 1);
    assert_eq!(factory.completed.load(Ordering::SeqCst), 1);
    assert!(
        observed.0,
        "mandatory response admission precedes factory entry"
    );
    assert_eq!(observed.1, 0, "no factory effect before response refund");
    assert_eq!(
        observed.2,
        ServerRecord::Refused {
            stream: 16,
            reason: "controlled factory refusal".into()
        }
    );
    assert_eq!(observed.3, (0, 0, 0));
}

#[tokio::test]
async fn capacity_open_opened_and_terminal_keep_mandatory_room_under_ordinary_saturation() {
    let factory = FakeSpawner::new();
    let (io, inbound, mut outbound) = about_pair();
    let global = io.global_control_budget();
    let ordinary = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let runner = tokio::spawn(run_channel_session(io, factory.clone()));
    inbound
        .send(open(16, ChannelKind::Shell, false))
        .await
        .unwrap();
    let opened = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match outbound.recv().await.unwrap() {
                SessionOutbound::ReservedControl {
                    bytes, delivery, ..
                } => {
                    let raw = RecordDeframer::for_control().push(&bytes).remove(0);
                    let record = decode_server(&raw).unwrap();
                    drop(delivery); // Fixture consumption, not a transport ACK.
                    break Ok(record);
                }
                SessionOutbound::ResourceExhausted { .. }
                | SessionOutbound::CloseSession { .. }
                | SessionOutbound::ProtocolFailure { .. } => {
                    break Err("admitted open lost its reserved outcome")
                }
                _ => {}
            }
        }
    })
    .await;
    let after_opened = global.retained_for_test();
    let mut terminal = None;
    if matches!(&opened, Ok(Ok(ServerRecord::Opened { stream: 16 }))) {
        factory.end_channel(16);
        terminal = Some(
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let message = outbound.recv().await.unwrap();
                    if let Some((stream, token, generation)) = delivery_marker(&message) {
                        inbound
                            .send(SessionInbound::Delivered {
                                stream,
                                token,
                                generation,
                            })
                            .await
                            .unwrap();
                    }
                    if matches!(&message, SessionOutbound::ChannelExit { stream: 16, .. }) {
                        break message;
                    }
                }
            })
            .await,
        );
    }
    let before_terminal_drop = global.retained_for_test();
    drop(inbound);
    runner.await.unwrap();
    drop(outbound);
    let code = terminal
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .and_then(|message| match message {
            SessionOutbound::ChannelExit { code, .. } => *code,
            _ => None,
        });
    drop(terminal);
    let after_terminal_drop = global.retained_for_test();
    drop(ordinary);
    assert_eq!(
        opened.unwrap().unwrap(),
        ServerRecord::Opened { stream: 16 }
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        after_opened,
        (2 * crate::control_budget::MAX_RECORD + 10, 2, 0),
        "Opened consumption does not refund future terminal capacity"
    );
    assert_eq!(
        before_terminal_drop, after_opened,
        "terminal output keeps the original mandatory envelope"
    );
    assert_eq!(
        after_terminal_drop,
        (2 * crate::control_budget::MAX_RECORD, 1, 0)
    );
    assert_eq!(global.retained_for_test(), (0, 0, 0));
}
