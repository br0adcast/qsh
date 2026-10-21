// Included inside session_manager::tests. All keys/endpoints are owned fixtures.
mod refusal131_tests {
    use super::*;
    use crate::channel::{decode_server, ServerRecord, FIRST_CHANNEL_STREAM};
    use std::sync::Condvar;

    struct RefusalGate {
        released: Mutex<bool>,
        changed: Condvar,
    }
    impl RefusalGate {
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.changed.notify_all();
        }
    }
    struct Release(Arc<RefusalGate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    struct DelayedRefusal {
        registry: Arc<crate::channel_open::ChannelOpenRegistry>,
        entered: tokio::sync::Notify,
        calls: AtomicUsize,
        custody: Mutex<Option<crate::channel_open::OpenCustody>>,
        gate: Arc<RefusalGate>,
        ready_leaf: Option<Arc<ReadyLeafEvidence>>,
    }
    impl crate::channel_server::ChannelSpawner for DelayedRefusal {
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            let ready = if let Some(evidence) = &self.ready_leaf {
                let child = std::process::Command::new("/bin/sleep")
                    .arg("60")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|error| {
                        custody
                            .refuse_before_creation(format!("owned leaf creation failed: {error}"))
                    })?;
                evidence.pid.store(child.id() as usize, Ordering::SeqCst);
                let guard = custody.protect(
                    Box::new(LeafWait {
                        child,
                        evidence: evidence.clone(),
                        reaped: false,
                        lost: false,
                    }),
                    Box::new(crate::shell_server::NoScreen),
                );
                Some(guard)
            } else {
                None
            };
            *self.custody.lock().unwrap() = Some(custody.clone());
            self.entered.notify_one();
            let mut released = self.gate.released.lock().unwrap();
            while !*released {
                released = self.gate.changed.wait(released).unwrap();
            }
            if let Some(guard) = ready {
                Ok(guard.finish(
                    Box::new(LeafReader(self.ready_leaf.as_ref().unwrap().clone())),
                    Box::new(std::io::sink()),
                    Box::new(LeafResize),
                ))
            } else {
                Err(custody.refuse_before_creation("PAM account refused fixture".into()))
            }
        }
    }
    struct RefusalRunner(Arc<DelayedRefusal>);
    impl SessionBackend for RefusalRunner {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(run_channel_session(io, self.0.clone()))
        }
        fn consumption(&self) -> Consumption {
            Consumption::Explicit
        }
    }

    async fn retained_open_outcome(ready_leaf: bool, drop_and_hold: bool) {
        CONTROL_RETIREMENT_BARRIER.with(|barrier| barrier.set(None));
        let mut dropped_first = false;
        let mut control_packets = 0;
        let mut held_replies = Vec::new();
        let leaf = Arc::new(ReadyLeafEvidence::default());
        let gate = Arc::new(RefusalGate {
            released: Mutex::new(false),
            changed: Condvar::new(),
        });
        let _release_on_failure = Release(gate.clone());
        let spawner = Arc::new(DelayedRefusal {
            registry: crate::channel_open::ChannelOpenRegistry::new(Default::default()),
            entered: tokio::sync::Notify::new(),
            calls: AtomicUsize::new(0),
            custody: Mutex::new(None),
            gate: gate.clone(),
            ready_leaf: ready_leaf.then(|| leaf.clone()),
        });
        let DeliveryRig {
            bridge,
            lifecycle,
            mut client,
            client_sock,
            peer,
            token,
            dg_tx,
            ctl_tx,
            admission,
            backend_out,
            ..
        } = delivery_rig(Arc::new(RefusalRunner(spawner.clone())), |_| {}).await;
        // Only the real router owns either route/control sender after setup.
        drop(backend_out);
        let mut router = Router::new();
        let sid = client.session_id();
        let _models = synthetic_live_entry(&mut router, token, sid);
        router.sessions.insert(sid, dg_tx);
        router.backends.get_mut(&token).unwrap().control = ctl_tx;
        router.backends.get_mut(&token).unwrap().admission = admission;
        let global_budget = lifecycle.control_budget.clone();
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let open = encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            }));
            for dg in client.send(Instant::now(), CONTROL_STREAM, &open) {
                if !router.sessions[&sid].send(peer, dg.bytes) {
                    return Err("original Open route unexpectedly closed");
                }
            }
            spawner.entered.notified().await; // genuine admitted factory is held
            if !router.end_login(token, 0) || router.backends.contains_key(&token) {
                return Err("login was not revoked");
            }
            // An authenticated Open arriving after the synchronous fence must
            // not start another factory, even if the runner has not consumed
            // its retirement notification yet.
            let late = encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM + 2,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            }));
            for dg in client.send(Instant::now(), CONTROL_STREAM, &late) {
                if !router.sessions[&sid].send(peer, dg.bytes) {
                    return Err("retiring ACK route unexpectedly closed");
                }
            }
            gate.release(); // real refusal can only publish after actual revoke
            let mut deframer = crate::shell_frame::RecordDeframer::for_control();
            let mut buf = [0; 65536];
            loop {
                let (n, src) = client_sock
                    .recv_from(&mut buf)
                    .await
                    .map_err(|_| "fixture receive failed")?;
                if client.peek_frames(&buf[..n]).is_some_and(|frames| {
                    frames.iter().any(|frame| {
                        matches!(
                            frame,
                            crate::reliability::StreamFrame::Data {
                                stream_id: CONTROL_STREAM,
                                ..
                            }
                        )
                    })
                }) {
                    control_packets += 1;
                    if drop_and_hold && !dropped_first {
                        dropped_first = true;
                        continue; // no decode/delivery/ACK for this real packet
                    }
                }
                let mut replies = client.on_datagram(Instant::now(), src, &buf[..n]);
                replies.extend(client.on_timeout_if_due(Instant::now()));
                for reply in replies {
                    if drop_and_hold {
                        if held_replies.len() >= 32 {
                            return Err("bounded owned reply hold exhausted");
                        }
                        held_replies.push(reply.bytes);
                    } else if let Some(route) = router.sessions.get(&sid) {
                        let _ = route.send(peer, reply.bytes);
                    }
                }
                for event in client.poll_events() {
                    if let Event::StreamData {
                        stream_id: CONTROL_STREAM,
                        data,
                    } = event
                    {
                        for raw in deframer.push(&data) {
                            if let Ok(ServerRecord::Refused { stream, reason }) =
                                decode_server(&raw)
                            {
                                return Ok((stream, reason));
                            }
                        }
                    }
                }
            }
        })
        .await;
        // Cleanup is actual and precedes the expected RED assertion. A failure
        // cannot leave the blocking factory held or detach the bridge task.
        gate.release();
        let mut held_custody = true;
        if drop_and_hold && matches!(observed, Ok(Ok(_))) {
            let marker_processed = tokio::time::timeout(Duration::from_secs(2), async {
                while CONTROL_RETIREMENT_BARRIER
                    .with(|barrier| barrier.get().map(|origin| origin.session_id))
                    != Some(sid)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            let (bytes, entries, _) = global_budget.retained_for_test();
            held_custody = marker_processed && bytes > 0 && entries > 0 && !bridge.is_finished();
            // This is the real client's complete reply/ACK batch, not a
            // fabricated cumulative offset. Future ACK timer work follows too.
            for bytes in held_replies.drain(..) {
                if let Some(route) = router.sessions.get(&sid) {
                    let _ = route.send(peer, bytes);
                }
            }
        }
        // Drive the real client's ACK timer; a delivered record alone is not
        // the server's final-offset receipt. Keep the route until bridge exit.
        let acknowledged = if matches!(observed, Ok(Ok(_))) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while !bridge.is_finished() {
                    for reply in client.on_timeout_if_due(Instant::now()) {
                        if let Some(route) = router.sessions.get(&sid) {
                            let _ = route.send(peer, reply.bytes);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .is_ok()
        } else {
            false
        };
        lifecycle.shutdown.request();
        drop(router);
        bridge.await.expect("owned bridge joined");
        lifecycle
            .drain()
            .await
            .expect("owned backend/callback tasks drained");
        if drop_and_hold {
            assert!(
                dropped_first && control_packets >= 2,
                "actual first response dropped and later real retransmission observed"
            );
            assert!(
                held_custody,
                "processed exact barrier must retain charged refusal and live route while ACKs are withheld"
            );
            let (bytes, entries, _) = global_budget.retained_for_test();
            assert_eq!(
                (bytes, entries),
                (0, 0),
                "actual final ACK and cleanup refund response debt"
            );
        }
        if ready_leaf {
            assert!(
                leaf.pid.load(Ordering::SeqCst) > 0,
                "actual leaf was created before callback release"
            );
            assert_eq!(
                leaf.reaped.load(Ordering::SeqCst),
                1,
                "actual exclusive child wait completed"
            );
            assert_eq!(
                leaf.reader_calls.load(Ordering::SeqCst),
                0,
                "late Ready never installed its reader bridge"
            );
            assert_eq!(
                spawner.registry.outstanding(),
                0,
                "cleanup proof refunded the exact registry job"
            );
        }
        assert!(acknowledged, "bridge must finish after actual refusal ACK");
        assert_eq!(
            spawner.calls.load(Ordering::SeqCst),
            1,
            "post-revoke Open cannot invoke the factory"
        );
        assert_eq!(
            observed
                .expect("retired transport must deliver its admitted refusal")
                .expect("fixture routing succeeds"),
            (
                FIRST_CHANNEL_STREAM,
                if ready_leaf {
                    "the login ended"
                } else {
                    "PAM account refused fixture"
                }
                .into()
            )
        );
    }
    #[tokio::test]
    async fn refusal131_retirement_wakes_a_full_inbound_cap_without_backend_consumption() {
        let server = generate_keypair();
        let peer: SocketAddr = "127.0.0.1:131".parse().unwrap();
        let (_, mut conn, _) = accepted_connection(&server, [131; 16], peer);
        let (tx, _held_receiver) = mpsc::channel(1);
        tx.try_send(SessionInbound::Repaint).unwrap();
        let mut link = BackendLink::new(tx, Consumption::Explicit);
        link.inbound.push(
            SessionInbound::Data(StreamData {
                stream_id: FIRST_CHANNEL_STREAM,
                data: vec![7; PENDING_CAP + 1],
            }),
            0,
        );
        let (io, _inbound, _outbound) = SessionIo::test_pair();
        let control = io.control().clone();
        // No backend consumes or closes its receiver. Only actual revocation
        // may release this full-cap wait; timeout remains a failed assertion.
        let mut out = Vec::new();
        let result = {
            let wait = link.wait_below_pending_cap(&control, &mut conn, &mut out);
            tokio::pin!(wait);
            let blocked = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(wait.as_mut().poll(cx).is_pending())
            })
            .await;
            assert!(blocked, "positive full-cap wait before revocation");
            control.retire();
            tokio::time::timeout(Duration::from_millis(200), wait).await
        };
        assert!(
            result.is_ok(),
            "retirement must interrupt pending-cap backpressure"
        );
        assert!(
            !link.inbound.has_pending(),
            "unhanded application bytes are discarded on revoke"
        );
        link.hand_over(&mut conn, Instant::now(), SessionInbound::Repaint, &mut out);
        assert!(
            !link.inbound.has_pending(),
            "revocation cannot queue fresh backend effects"
        );
    }
    #[test]
    fn refusal131_revocation_is_immediate_and_its_deadline_never_renews() {
        let (io, _inbound, _outbound) = SessionIo::test_pair();
        let mut effects = 0;
        assert_eq!(
            io.admit_effect(|| {
                effects += 1;
                effects
            }),
            Ok(1)
        );
        let before = Instant::now();
        io.control().retire();
        let deadline = io.control().retirement_deadline().unwrap();
        assert!(deadline >= before + crate::conn::CLIENT_DEATH_AFTER);
        assert!(deadline <= Instant::now() + crate::conn::CLIENT_DEATH_AFTER);
        io.control().retire();
        assert_eq!(io.control().retirement_deadline(), Some(deadline));
        assert_eq!(
            io.admit_effect(|| {
                effects += 1;
                effects
            }),
            Err(())
        );
        assert_eq!(
            effects, 1,
            "no asynchronous retirement selection is needed to revoke admission"
        );
    }

    #[tokio::test]
    async fn refusal131_retired_entries_keep_owner_cap_until_exact_bridge_completion() {
        let mut router = Router::new();
        let mut held = Vec::new();
        for index in 0..MAX_SESSIONS_PER_OWNER {
            let token = [index as u8; 16];
            held.push(synthetic_live_entry(&mut router, token, index as u64 + 1));
            router.backends.get_mut(&token).unwrap().owner = 131;
            assert!(router.end_login(token, 0));
        }
        assert!(!router.has_room_for(131));
        assert!(router.has_room_for(132));
        assert_eq!(router.retiring.len(), MAX_SESSIONS_PER_OWNER);
        assert_eq!(
            router.on_session_ended(
                SessionEnded {
                    phase: SessionEndPhase::Final,
                    session_id: 1,
                    token: [0; 16],
                    graceful: true,
                },
                tokio::time::Instant::now()
            ),
            None
        );
        assert!(router.has_room_for(131));
        assert!(!router.sessions.contains_key(&1));
        assert_eq!(router.retiring.len(), MAX_SESSIONS_PER_OWNER - 1);
    }
    struct EndWithoutBarrier;
    impl SessionBackend for EndWithoutBarrier {
        fn run(&self, _io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async {})
        }
    }
    struct OldAttachmentBarrier;
    impl SessionBackend for OldAttachmentBarrier {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let old = io.processed_attachment();
            Box::pin(async move {
                io.retirement_ready(old, true);
            })
        }
    }

    #[tokio::test]
    async fn refusal131_retiring_eof_without_decision_barrier_reports_nondelivery() {
        let mut rig = delivery_rig(Arc::new(EndWithoutBarrier), |_| {}).await;
        let sid = rig.client.session_id();
        rig.admission.retire();
        drop(rig.backend_out);
        let ended = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv()).await;
        rig.lifecycle.shutdown.request();
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        rig.bridge.await.expect("bridge actually joined");
        rig.lifecycle
            .drain()
            .await
            .expect("backend actually joined");
        let ended = ended
            .expect("retiring EOF terminates boundedly")
            .expect("exact bridge receipt");
        assert_eq!(ended.session_id, sid);
        assert!(
            !ended.graceful,
            "EOF alone is not an admitted-decision delivery receipt"
        );
    }

    #[tokio::test]
    async fn refusal131_queued_warm_attach_cannot_use_old_attachment_barrier_as_success() {
        let mut rig = delivery_rig(Arc::new(OldAttachmentBarrier), |_| {}).await;
        let (_, replacement, _) = accepted_connection(&rig.server_kp, rig.token, rig.peer);
        let replacement_id = replacement.session_id();
        // The real manager commits Attach before it can consume LoginEnded.
        // Queue the committed control, then revoke before the bridge polls it.
        rig.ctl_tx
            .send(committed_attach(
                Box::new(replacement),
                Vec::new(),
                Vec::new(),
            ))
            .unwrap();
        rig.admission.retire();
        let ended = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv()).await;
        rig.lifecycle.shutdown.request();
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        drop(rig.backend_out);
        rig.bridge.await.expect("bridge actually joined");
        rig.lifecycle
            .drain()
            .await
            .expect("backend actually joined");
        let ended = ended
            .expect("mismatched old barrier reports bounded nondelivery")
            .expect("exact bridge receipt");
        assert_eq!(ended.session_id, replacement_id);
        assert!(
            !ended.graceful,
            "old generation's decision cannot certify the warm attachment"
        );
    }

    struct HoldUntilShutdown;
    impl SessionBackend for HoldUntilShutdown {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async move {
                io.lifecycle.shutdown.requested().await;
            })
        }
    }
    #[tokio::test]
    async fn refusal131_absolute_deadline_closes_without_fabricating_delivery() {
        let mut rig = delivery_rig(Arc::new(HoldUntilShutdown), |_| {}).await;
        // Exercise the actual expiry branch without sleeping 45 seconds. The
        // independent deadline control checks its unchanged production interval.
        rig.admission.origin.lock().unwrap().retiring =
            Some(Instant::now() - crate::conn::CLIENT_DEATH_AFTER);
        rig.admission.retire();
        let ended = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv()).await;
        rig.lifecycle.shutdown.request();
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        drop(rig.backend_out);
        rig.bridge.await.expect("bridge actually joined");
        rig.lifecycle
            .drain()
            .await
            .expect("backend actually joined");
        let ended = ended
            .expect("expired bridge actually terminates")
            .expect("exact bridge receipt");
        assert!(
            !ended.graceful,
            "deadline is nondelivery, not proof of peer ACK or backend cleanup"
        );
    }

    #[tokio::test]
    async fn refusal131_old_retirement_cannot_remove_new_independent_incarnation() {
        let mut router = Router::new();
        let token = [131; 16];
        let _old_routes = synthetic_live_entry(&mut router, token, 1);
        assert!(router.end_login(token, 0));
        let _new_routes = synthetic_live_entry(&mut router, token, 2);
        router.backends.get_mut(&token).unwrap().incarnation = 1;
        router.on_session_ended(
            SessionEnded {
                phase: SessionEndPhase::Final,
                session_id: 1,
                token,
                graceful: false,
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(router.backends[&token].session_id, 2);
        assert_eq!(router.backends[&token].incarnation, 1);
        assert!(router.sessions.contains_key(&2));
        assert!(!router.backends[&token].admission.retiring());
    }
    struct EpochDaemon(tokio::sync::watch::Sender<crate::channel_server::RestartSignal>);
    impl crate::channel_server::DaemonUpdates for EpochDaemon {
        fn about(&self) -> Option<crate::channel::About> {
            None
        }
        fn offer(
            &self,
            _: &Principal,
            _: &crate::channel::UpdateOffer,
        ) -> Result<Box<dyn crate::channel_server::UpdateTransfer>, crate::channel::UpdateAnswer>
        {
            Err(crate::channel::UpdateAnswer::InProgress)
        }
        fn restart_signal(
            &self,
        ) -> tokio::sync::watch::Receiver<crate::channel_server::RestartSignal> {
            self.0.subscribe()
        }
        fn restart_joined(&self, _: u64) -> bool {
            false
        }
        fn channels_released(&self, _: u64) {}
    }
    struct EpochRefusalRunner(Arc<DelayedRefusal>, Arc<EpochDaemon>);
    impl SessionBackend for EpochRefusalRunner {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(crate::channel_server::run_channel_session_with(
                io,
                self.0.clone(),
                Some(self.1.clone()),
            ))
        }
        fn consumption(&self) -> Consumption {
            Consumption::Explicit
        }
    }
    async fn invalidated_open_barrier(restart_selected_first: bool) {
        let gate = Arc::new(RefusalGate {
            released: Mutex::new(false),
            changed: Condvar::new(),
        });
        let _release_on_failure = Release(gate.clone());
        let spawner = Arc::new(DelayedRefusal {
            registry: crate::channel_open::ChannelOpenRegistry::new(Default::default()),
            entered: tokio::sync::Notify::new(),
            calls: AtomicUsize::new(0),
            custody: Mutex::new(None),
            gate: gate.clone(),
            ready_leaf: None,
        });
        let daemon = Arc::new(EpochDaemon(
            tokio::sync::watch::channel(crate::channel_server::RestartSignal::IDLE).0,
        ));
        let mut rig = delivery_rig(
            Arc::new(EpochRefusalRunner(spawner.clone(), daemon.clone())),
            |_| {},
        )
        .await;
        let sid = rig.client.session_id();
        let mut router = Router::new();
        let _model = synthetic_live_entry(&mut router, rig.token, sid);
        router.sessions.insert(sid, rig.dg_tx.clone());
        router.backends.get_mut(&rig.token).unwrap().control = rig.ctl_tx.clone();
        router.backends.get_mut(&rig.token).unwrap().admission = rig.admission.clone();
        drop(rig.backend_out);
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            let request = encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            }));
            for packet in rig.client.send(Instant::now(), CONTROL_STREAM, &request) {
                if !rig.dg_tx.send(rig.peer, packet.bytes) {
                    return Err("owned original route closed");
                }
            }
            spawner.entered.notified().await;
            // Real persistent restart epoch advances while the admitted factory
            // is held. Its result must not install or silently certify delivery.
            daemon
                .0
                .send_replace(crate::channel_server::RestartSignal::idle(1));
            if restart_selected_first {
                // The actual runner's Restart branch must remove/cancel the
                // held registry job before retirement; no callback outcome yet.
                loop {
                    if spawner
                        .custody
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .is_cancelled()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            if !router.end_login(rig.token, 0) {
                return Err("owned login was not retired");
            }
            gate.release();
            rig.done_rx
                .recv()
                .await
                .ok_or("bridge omitted exact termination receipt")
        })
        .await;
        gate.release();
        rig.lifecycle.shutdown.request();
        drop(router);
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        rig.bridge
            .await
            .expect("real bridge joined before assertions");
        rig.lifecycle
            .drain()
            .await
            .expect("real factory and runner drained before assertions");
        let ended = observed
            .expect("invalidated decision reports bounded nondelivery")
            .expect("fixture completed");
        assert_eq!(spawner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(ended.session_id, sid);
        assert!(
            !ended.graceful,
            "an admitted decision dropped by epoch invalidation is not delivered"
        );
    }
    #[tokio::test]
    async fn refusal131_invalidated_admitted_open_cannot_publish_an_empty_success_barrier() {
        invalidated_open_barrier(false).await;
    }
    #[tokio::test]
    async fn refusal131_restart_removal_before_outcome_cannot_publish_an_empty_success_barrier() {
        invalidated_open_barrier(true).await;
    }
    async fn parked_notice_keeps_retirement_custody(queued_before_retire: bool) {
        let mut rig = delivery_rig(Arc::new(HoldUntilShutdown), |connection| {
            // Existing explicit connection-policy seam: accelerate only the
            // fixture's real liveness death, not the retirement45s deadline.
            connection.set_death_after(Duration::from_millis(30));
        })
        .await;
        let sid = rig.client.session_id();
        let mut router = Router::new();
        let _model = synthetic_live_entry(&mut router, rig.token, sid);
        router.sessions.insert(sid, rig.dg_tx.clone());
        router.backends.get_mut(&rig.token).unwrap().control = rig.ctl_tx.clone();
        router.backends.get_mut(&rig.token).unwrap().admission = rig.admission.clone();
        let mut notice = if queued_before_retire {
            tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let retired = router.end_login(rig.token, 0);
        if !queued_before_retire {
            notice = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv())
                .await
                .ok()
                .flatten();
        }
        let actual_park =
            notice.as_ref().is_some_and(|notice| !notice.graceful) && !rig.bridge.is_finished();
        if let Some(notice) = notice {
            router.on_session_ended(notice, tokio::time::Instant::now());
        }
        let retained_until_final =
            router.retiring.contains_key(&sid) && router.sessions.contains_key(&sid);
        // Preserve route/charge until the real bridge exit, then consume its
        // separate final receipt. Cleanup happens before every result assertion.
        rig.lifecycle.shutdown.request();
        drop(rig.backend_out);
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        let joined = rig.bridge.await;
        let drained = rig.lifecycle.drain().await;
        let final_notice = rig.done_rx.try_recv().ok();
        let final_receipt = final_notice
            .as_ref()
            .is_some_and(|notice| notice.phase == SessionEndPhase::Final);
        if let Some(notice) = final_notice {
            router.on_session_ended(notice, tokio::time::Instant::now());
        }
        assert!(
            joined.is_ok() && drained.is_ok(),
            "actual bridge/backend cleanup"
        );
        assert!(
            retired && actual_park,
            "positive actual parked bridge precondition"
        );
        assert!(
            retained_until_final,
            "park notification is not exact bridge completion: retain retiring route and cap"
        );
        assert!(
            final_receipt,
            "actual bridge emits its separate final receipt"
        );
        assert!(!router.retiring.contains_key(&sid) && !router.sessions.contains_key(&sid));
    }
    #[tokio::test]
    async fn refusal131_queued_pre_retire_park_notice_cannot_refund_live_bridge() {
        parked_notice_keeps_retirement_custody(true).await;
    }
    #[tokio::test]
    async fn refusal131_death_during_retirement_cannot_refund_live_bridge() {
        parked_notice_keeps_retirement_custody(false).await;
    }
    #[tokio::test]
    async fn refusal131_authenticated_peer_close_before_decision_is_nondelivery() {
        let mut rig = delivery_rig(Arc::new(HoldUntilShutdown), |_| {}).await;
        let sid = rig.client.session_id();
        rig.admission.retire();
        let packets = rig.client.close(Instant::now());
        let emitted = !packets.is_empty();
        let mut routed = true;
        for packet in packets {
            routed &= rig.dg_tx.send(rig.peer, packet.bytes);
        }
        let observed = tokio::time::timeout(Duration::from_secs(2), rig.done_rx.recv()).await;
        rig.lifecycle.shutdown.request();
        drop(rig.backend_out);
        drop(rig.dg_tx);
        drop(rig.ctl_tx);
        let joined = rig.bridge.await;
        let drained = rig.lifecycle.drain().await;
        assert!(
            joined.is_ok() && drained.is_ok(),
            "owned bridge/backend joined"
        );
        assert!(
            emitted && routed,
            "real authenticated Close emitted and routed"
        );
        let ended = observed
            .expect("Close actually ends the bridge")
            .expect("exact final receipt");
        assert_eq!(ended.session_id, sid);
        assert!(
            !ended.graceful,
            "peer cancellation before decision is not refusal delivery"
        );
    }
    #[derive(Default)]
    struct ReadyLeafEvidence {
        pid: AtomicUsize,
        reaped: AtomicUsize,
        reader_calls: AtomicUsize,
    }
    struct LeafWait {
        child: std::process::Child,
        evidence: Arc<ReadyLeafEvidence>,
        reaped: bool,
        lost: bool,
    }
    impl LeafWait {
        fn record_wait(&mut self) {
            if !self.reaped {
                self.reaped = true;
                self.evidence.reaped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    impl crate::channel_server::ChannelWait for LeafWait {
        fn poll_exit(&mut self) -> crate::channel_server::ChildStatus {
            use crate::channel_server::ChildStatus;
            if self.reaped {
                return ChildStatus::Reaped { code: None };
            }
            if self.lost {
                return ChildStatus::Unknown("owned leaf wait authority lost".into());
            }
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.record_wait();
                    ChildStatus::Reaped {
                        code: status.code(),
                    }
                }
                Ok(None) => ChildStatus::Running,
                Err(error) => {
                    self.lost = true;
                    ChildStatus::Unknown(error.to_string())
                }
            }
        }
        fn kill(&mut self) {
            if matches!(
                self.poll_exit(),
                crate::channel_server::ChildStatus::Running
            ) {
                let _ = self.child.kill(); // exclusive, still-unreaped direct Child
            }
        }
        fn wait(mut self: Box<Self>) -> i32 {
            if self.reaped {
                return 0;
            }
            if self.lost {
                return 1;
            }
            match self.child.wait() {
                Ok(status) => {
                    self.record_wait();
                    status.code().unwrap_or(1)
                }
                Err(_) => {
                    self.lost = true;
                    1
                }
            }
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            self.kill();
            if !self.reaped && !self.lost {
                match self.child.wait() {
                    Ok(_) => self.record_wait(),
                    Err(_) => self.lost = true,
                }
            }
            if self.reaped {
                authority.reaped()
            } else {
                crate::channel_open::CleanupStatus::Unknown
            }
        }
    }
    impl Drop for LeafWait {
        fn drop(&mut self) {
            use crate::channel_server::ChannelWait;
            if !self.reaped && !self.lost {
                self.kill();
                if !self.lost {
                    if self.child.wait().is_ok() {
                        self.record_wait();
                    } else {
                        self.lost = true;
                    }
                }
            }
        }
    }
    struct LeafReader(Arc<ReadyLeafEvidence>);
    impl std::io::Read for LeafReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            self.0.reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        }
    }
    struct LeafResize;
    impl crate::shell_server::ResizeHandle for LeafResize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn refusal131_real_open_outcome_survives_login_retirement_before_callback_returns() {
        retained_open_outcome(false, false).await;
    }
    #[tokio::test]
    async fn refusal131_late_ready_after_revocation_is_reaped_without_installation() {
        retained_open_outcome(true, false).await;
    }
    #[tokio::test]
    async fn refusal131_first_refusal_loss_retransmits_and_held_acks_retain_exact_debt() {
        retained_open_outcome(false, true).await;
    }
}
