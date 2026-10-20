struct RestartBoundsDaemon {
    signal: tokio::sync::watch::Sender<crate::channel_server::RestartSignal>,
    joined: AtomicUsize,
    released: AtomicUsize,
}
impl RestartBoundsDaemon {
    fn announced() -> Arc<Self> {
        Arc::new(Self {
            signal: tokio::sync::watch::channel(crate::channel_server::RestartSignal::announced(
                1, 1,
            ))
            .0,
            joined: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
        })
    }
}
impl crate::channel_server::DaemonUpdates for RestartBoundsDaemon {
    fn about(&self) -> Option<crate::channel::About> {
        None
    }
    fn offer(
        &self,
        _: &Principal,
        _: &crate::channel::UpdateOffer,
    ) -> Result<Box<dyn crate::channel_server::UpdateTransfer>, crate::channel::UpdateAnswer> {
        Err(crate::channel::UpdateAnswer::NotAllowed)
    }
    fn restart_signal(&self) -> tokio::sync::watch::Receiver<crate::channel_server::RestartSignal> {
        self.signal.subscribe()
    }
    fn restart_joined(&self, restart: u64) -> bool {
        let signal = self.signal.borrow();
        if signal.restart != restart
            || signal.phase != crate::channel_server::RestartPhase::Announced
        {
            return false;
        }
        self.joined.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn channels_released(&self, _: u64) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}
struct RestartBoundsBackend {
    daemon: Arc<RestartBoundsDaemon>,
    deny_before_live: bool,
}
impl SessionBackend for RestartBoundsBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let daemon = self.daemon.clone();
        let deny_before_live = self.deny_before_live;
        Box::pin(async move {
            let held = if deny_before_live {
                Some(
                    io.control_budget()
                        .reserve(crate::control_budget::Response::Restart)
                        .unwrap(),
                )
            } else {
                None
            };
            // Hold the real bridge's queued Live without calling SessionIo::recv.
            // This forces the ready watch ahead of producer attachment setup;
            // run_backend_bridge's real origin initialization is untouched.
            let _queued_live = if deny_before_live {
                let live = io.inbound.recv().await.expect("actual bridge Live");
                assert!(matches!(live, SessionInbound::Live(_)));
                assert_ne!(io.processed_attachment().session_id, 0);
                Some(live)
            } else {
                None
            };
            crate::channel_server::run_channel_session_with(
                io,
                crate::channel_server::tests::FakeSpawner::new(),
                Some(daemon),
            )
            .await;
            drop(held);
        })
    }
}

#[tokio::test]
async fn capacity_restart_initial_watch_uses_actual_bridge_origin_before_queued_live() {
    let daemon = RestartBoundsDaemon::announced();
    let mut rig = delivery_rig(
        Arc::new(RestartBoundsBackend {
            daemon: daemon.clone(),
            deny_before_live: true,
        }),
        |_| {},
    )
    .await;
    let mut packet = vec![0; 65536];
    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                if let Event::SessionAborted(reason) = event {
                    return reason;
                }
            }
        }
    })
    .await;
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("bridge joins")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert_eq!(
        terminal.expect("authenticated explicit terminal outcome"),
        crate::SessionAbortReason::ResourceExhausted
    );
    assert_eq!(
        daemon.joined.load(Ordering::SeqCst),
        1,
        "failed announcement still joins cleanup"
    );
    assert_eq!(daemon.released.load(Ordering::SeqCst), 1);
    assert_eq!(rig.lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_restart_real_ack_releases_only_whole_reserved_wire_debt() {
    let daemon = RestartBoundsDaemon::announced();
    let mut rig = delivery_rig(
        Arc::new(RestartBoundsBackend {
            daemon,
            deny_before_live: false,
        }),
        |_| {},
    )
    .await;
    let mut packet = vec![0; 65536];
    let mut received = Vec::new();
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        while received.len() < 5 {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                if let Event::StreamData {
                    stream_id: crate::channel::CONTROL_STREAM,
                    data,
                } = event
                {
                    received.extend(data);
                }
            }
        }
    })
    .await;
    let before_ack = rig.lifecycle.control_budget.retained_for_test();
    let refunded = tokio::time::timeout(Duration::from_secs(5), async {
        while rig.lifecycle.control_budget.retained_for_test().0 != 0 {
            let deadline = rig.client.next_timeout();
            let replies = tokio::select! {
                received = rig.client_sock.recv_from(&mut packet) => {
                    let (len, source) = received.unwrap();
                    rig.client.on_datagram(Instant::now(), source, &packet[..len])
                }
                _ = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at.into()).await,
                        None => std::future::pending().await,
                    }
                } => rig.client.on_timeout_if_due(Instant::now()),
            };
            for reply in replies {
                let _ = rig.dg_tx.send(rig.peer, reply.bytes);
            }
            let _ = rig.client.poll_events();
        }
    })
    .await;
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("bridge joins")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert!(
        reached.is_ok(),
        "real encoded Restarting reaches authenticated peer"
    );
    assert_eq!(
        received,
        crate::channel::encode_server(&crate::channel::ServerRecord::Restarting)
    );
    assert_eq!(
        before_ack,
        (10, 1, 0),
        "source and reliable copy allowance stays until ACK"
    );
    assert!(
        refunded.is_ok(),
        "actual peer ACK refunds the shared ledger"
    );
    assert_eq!(rig.lifecycle.control_budget.retained_for_test(), (0, 0, 0));
}

#[tokio::test]
async fn capacity_restart_old_unacked_record_cannot_fund_second_attempt() {
    let daemon = RestartBoundsDaemon::announced();
    let mut rig = delivery_rig(
        Arc::new(RestartBoundsBackend {
            daemon: daemon.clone(),
            deny_before_live: false,
        }),
        |_| {},
    )
    .await;
    let mut packet = vec![0; 65536];
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                if let Event::StreamData {
                    stream_id: crate::channel::CONTROL_STREAM,
                    data,
                } = event
                {
                    return data;
                }
            }
        }
    })
    .await;
    let held = rig.lifecycle.control_budget.retained_for_test();
    daemon
        .signal
        .send_replace(crate::channel_server::RestartSignal::announced(2, 2));
    let terminal = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (len, source) = rig.client_sock.recv_from(&mut packet).await.unwrap();
            let _withheld = rig
                .client
                .on_datagram(Instant::now(), source, &packet[..len]);
            for event in rig.client.poll_events() {
                if let Event::SessionAborted(reason) = event {
                    return reason;
                }
            }
        }
    })
    .await;
    rig.lifecycle.shutdown.request();
    tokio::time::timeout(Duration::from_secs(5), &mut rig.bridge)
        .await
        .expect("bridge joins despite withheld ACK")
        .unwrap();
    rig.lifecycle.drain().await.unwrap();
    assert_eq!(
        reached.expect("first mandatory announcement reaches peer"),
        crate::channel::encode_server(&crate::channel::ServerRecord::Restarting)
    );
    assert_eq!(held, (10, 1, 0));
    assert_eq!(
        terminal.expect("second attempt explicitly exhausts fixed envelope"),
        crate::SessionAbortReason::ResourceExhausted
    );
    assert_eq!(
        daemon.joined.load(Ordering::SeqCst),
        2,
        "both current Announced attempts join cleanup independently of admission"
    );
    assert_eq!(
        rig.lifecycle.control_budget.retained_for_test(),
        (0, 0, 0),
        "exact teardown settles old wire debt"
    );
}
