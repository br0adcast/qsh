// Characterize the actual admitted manager mailbox, not a preloaded bridge FIFO.
use crate::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
use crate::channel_timeline::{EntryClass, TimelineBudget, BRIDGE_LIFECYCLE_BYTES};
use crate::shell_frame::{ShellDeframer, ShellRecord};

#[derive(Clone, Copy)]
enum MailboxCohort {
    Four,
    Singleton,
    Fence,
}

struct MailboxBackend {
    commands: Mutex<Option<mpsc::UnboundedReceiver<MailboxCohort>>>,
    published: mpsc::UnboundedSender<(usize, usize)>,
}
impl SessionBackend for MailboxBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut commands = self.commands.lock().unwrap().take().unwrap();
        let published = self.published.clone();
        Box::pin(async move {
            let origin = loop {
                match io.recv().await {
                    Some(SessionInbound::Live(origin)) => break origin,
                    Some(_) => {}
                    None => return,
                }
            };
            let instance = ChannelInstance::new(1).unwrap();
            let gate = io.send_gate(16, GateKind::Pipe);
            let budget = TimelineBudget::new(instance, origin.generation, |_| {});
            io.set_stream_resyncable(16, false);
            let geometry = |cols, request_id| {
                ChannelOutput::Geometry(
                    GeometryRecord {
                        instance,
                        request_id,
                        outcome: if request_id == 0 {
                            GeometryOutcome::Established
                        } else {
                            GeometryOutcome::Applied
                        },
                        cols,
                        rows: 24,
                    },
                    budget.try_reserve(EntryClass::Ordinary, 27).unwrap(),
                )
            };
            io.send_channel_output(
                16,
                instance,
                origin,
                gate.clone(),
                geometry(80, 0),
                Some(
                    budget
                        .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
                        .unwrap(),
                ),
            );
            loop {
                tokio::select! {
                    command = commands.recv() => {
                        let Some(command) = command else { break };
                        // No await/yield between these synchronous real SessionIo
                        // publications. The current-thread manager cannot dequeue
                        // any cohort member until this task yields below.
                        let outputs = match command {
                            MailboxCohort::Four => (0..4).map(|n| ChannelOutput::Data(vec![b'A'+n])).collect(),
                            MailboxCohort::Singleton => vec![ChannelOutput::Data(vec![b'S'])],
                            MailboxCohort::Fence => vec![ChannelOutput::Data(vec![b'L']), geometry(81, 1), ChannelOutput::Data(vec![b'R'])],
                        };
                        let count = outputs.len();
                        for output in outputs {
                            io.send_channel_output(16, instance, origin, gate.clone(), output, None);
                        }
                        let prior_data_turns = MAILBOX_TURNS.with(|slot| {
                            let slot = slot.borrow();
                            let count = slot.as_ref().unwrap().turns.lock().unwrap().iter()
                                .filter(|turn| turn.backend_data).count();
                            count
                        });
                        published.send((count, prior_data_turns)).unwrap();
                    }
                    inbound = io.recv() => if inbound.is_none() { break },
                }
            }
        })
    }
}

struct MailboxClient {
    socket: UdpSocket,
    conn: Connection,
    frames: ShellDeframer,
    records: Vec<ShellRecord>,
    data_datagrams: usize,
}
impl MailboxClient {
    async fn receive_until(
        &mut self,
        wiring: &RouterWiring,
        router: &mut Router,
        ready: impl Fn(&[ShellRecord]) -> bool,
    ) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut buffer = [0; RECV_BUF_LEN];
            while !ready(&self.records) {
                let mut outgoing = Vec::new();
                tokio::select! {
                    result = self.socket.recv_from(&mut buffer) => {
                        let (len, from) = result.map_err(|e| e.to_string())?;
                        if self.conn.peek_frames(&buffer[..len]).is_some_and(|frames|
                            frames.iter().any(|frame| matches!(frame, StreamFrame::Data { stream_id: 16, .. }))) {
                            self.data_datagrams += 1;
                        }
                        outgoing.extend(self.conn.on_datagram(Instant::now(), from, &buffer[..len]));
                    }
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
                outgoing.extend(self.conn.on_timeout_if_due(Instant::now()));
                for event in self.conn.poll_events() {
                    if let Event::StreamData { stream_id, data } = event {
                        if stream_id == 16 {
                            self.records.extend(self.frames.push(&data));
                        }
                        outgoing.extend(self.conn.on_consumed(Instant::now(), stream_id, data.len()));
                    }
                }
                for datagram in outgoing {
                    SessionManager::handle_datagram(&wiring.ctx(), router, datagram.bytes.len(), self.socket.local_addr().unwrap(), &datagram.bytes).await;
                }
            }
            Ok::<_, String>(())
        }).await.map_err(|_| "owned client delivery watchdog".to_string())?
    }
}

struct MailboxObservationGuard;
impl Drop for MailboxObservationGuard {
    fn drop(&mut self) {
        MAILBOX_TURNS.with(|slot| *slot.borrow_mut() = None);
    }
}

async fn manager_mailbox_case(cohort: MailboxCohort) {
    let token = [0xD5; 16];
    let (mut wiring, mut verdicts) = RouterWiring::new(HelperLogins::with(token)).await;
    let key = generate_keypair();
    wiring.auth.allowlist.lock().unwrap().push(key.public);
    let (commands, receiver) = mpsc::unbounded_channel();
    let (published, mut publications) = mpsc::unbounded_channel();
    wiring.factory = BackendFactory(Arc::new(MailboxBackend {
        commands: Mutex::new(Some(receiver)),
        published,
    }));
    let mut router = Router::new();
    let observed = Arc::new(Mutex::new(Vec::new()));
    MAILBOX_TURNS.with(|slot| {
        *slot.borrow_mut() = Some(MailboxObservation {
            token,
            turns: observed.clone(),
        })
    });
    let _observation_guard = MailboxObservationGuard;
    // Cancellation of the inner fixture drops only its work, not the outer
    // owner: shutdown and exact lifecycle drain still run before assertions.
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let source = socket.local_addr().unwrap();
        let mut conn = Connection::new(ConnectionConfig {
            required_features: crate::Features::AUTH_ACCEPTED | crate::Features::CHANNEL_GEOMETRY,
            features: crate::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(wiring.server_pub),
            auth: AuthPolicy::Allowlist(vec![wiring.server_pub]),
        });
        let payload = encode_msg1(&Msg1Payload { offered: crate::Features::SUPPORTED, start_kind: StartKind::Cold, token, method: AuthMethod::Allowlist });
        let first = conn.start_with_payload(Instant::now(), wiring.socket.local_addr().unwrap(), &payload).remove(0);
        SessionManager::handle_datagram(&wiring.ctx(), &mut router, first.bytes.len(), source, &first.bytes).await;
        let mut bytes = [0; RECV_BUF_LEN];
        let (len, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut bytes)).await.map_err(|_| "msg2 watchdog")?.map_err(|e| e.to_string())?;
        let mut proof = conn.on_datagram(Instant::now(), from, &bytes[..len]);
        conn.request_ping(Instant::now());
        proof.extend(conn.on_timeout(Instant::now()));
        for datagram in proof {
            SessionManager::handle_datagram(&wiring.ctx(), &mut router, datagram.bytes.len(), source, &datagram.bytes).await;
        }
        let verdict = tokio::time::timeout(Duration::from_secs(5), verdicts.recv()).await.map_err(|_| "probation watchdog")?.ok_or("probation closed")?;
        if verdict.proven.is_none() { return Err("actual probation rejected".into()); }
        SessionManager::on_probation_ended(&wiring.ctx(), &mut router, verdict).await;
        let mut client = MailboxClient { socket, conn, frames: ShellDeframer::new(), records: Vec::new(), data_datagrams: 0 };
        client.receive_until(&wiring, &mut router, |records| records.iter().any(|r| matches!(r, ShellRecord::Geometry(_)))).await?;
        client.records.clear(); client.data_datagrams = 0;
        observed.lock().unwrap().clear();
        commands.send(cohort).map_err(|_| "backend ended")?;
        let count = tokio::time::timeout(Duration::from_secs(5), publications.recv()).await.map_err(|_| "publication watchdog")?.ok_or("publication closed")?;
        let target = match cohort { MailboxCohort::Four => 4, MailboxCohort::Singleton => 1, MailboxCohort::Fence => 3 };
        if count != (target, 0) { return Err(format!("cohort publication was not before its first dequeue: {count:?}")); }
        client.receive_until(&wiring, &mut router, |records| records.len() >= target).await?;
        let initial_data_datagrams = client.data_datagrams;
        let turns = observed.lock().unwrap().clone();
        let data: Vec<_> = client.records.iter().filter_map(|record| if let ShellRecord::Data(bytes) = record { Some(bytes.clone()) } else { None }).collect();
        match cohort {
            MailboxCohort::Four => {
                if data != vec![vec![b'A'], vec![b'B'], vec![b'C'], vec![b'D']]
                    || turns.iter().filter(|t| t.backend_data).count() != 4
                    || client.data_datagrams != 4 {
                    return Err(format!("four ready records: {data:?}, turns={turns:?}, datagrams={}", client.data_datagrams));
                }
            }
            MailboxCohort::Singleton => {
                if data != vec![vec![b'S']] { return Err(format!("singleton delivery: {data:?}")); }
                // The second message is not constructed/published until the
                // first was actually decoded, not merely queued at the server.
                commands.send(MailboxCohort::Singleton).map_err(|_| "second command closed")?;
                let second = tokio::time::timeout(Duration::from_secs(5), publications.recv())
                    .await.map_err(|_| "second publication watchdog")?.ok_or("second publication closed")?;
                if second != (1, 1) { return Err(format!("second publication boundary: {second:?}")); }
                client.receive_until(&wiring, &mut router, |records| records.len() >= 2).await?;
                if !matches!(&client.records[..], [ShellRecord::Data(a), ShellRecord::Data(b)] if a == b"S" && b == b"S") {
                    return Err(format!("two singleton records: {:?}", client.records));
                }
            }
            MailboxCohort::Fence => {
                if !matches!(&client.records[..], [ShellRecord::Data(a), ShellRecord::Geometry(g), ShellRecord::Data(b)] if a == b"L" && g.cols == 81 && g.request_id == 1 && b == b"R") {
                    return Err(format!("ordered metadata fence: {:?}", client.records));
                }
            }
        }
        let flushes: usize = turns.iter().map(|turn| turn.flushes).sum();
        if flushes != target || initial_data_datagrams != target || !turns.iter().all(|turn| !turn.backend_data || turn.write_room >= 24 && turn.datagrams == 1 && turn.flushes == 1) {
            return Err(format!("unqualified admission/flush room: {turns:?}"));
        }
        println!("manager-mailbox initial_records={} initial_data_datagrams={} total_data_datagrams={} backend_data_turns={} drain_turns={} core_flush_calls={}", target, initial_data_datagrams, client.data_datagrams, turns.iter().filter(|t|t.backend_data).count(), turns.len(), flushes);
        Ok(())
    }).await.unwrap_or_else(|_| Err("whole owned fixture watchdog".into()));
    drop(commands);
    wiring.lifecycle.shutdown.request();
    let drained = wiring.lifecycle.drain().await;
    MAILBOX_TURNS.with(|slot| *slot.borrow_mut() = None);
    assert!(drained.is_ok(), "owned manager drain: {drained:?}");
    assert!(wiring.lifecycle.is_empty());
    assert!(
        result.is_ok(),
        "actual manager characterization: {result:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn manager_ready_mailbox_four_data_records() {
    manager_mailbox_case(MailboxCohort::Four).await;
}
#[tokio::test(flavor = "current_thread")]
async fn manager_ready_mailbox_singleton_before_second_exists() {
    manager_mailbox_case(MailboxCohort::Singleton).await;
}
#[tokio::test(flavor = "current_thread")]
async fn manager_ready_mailbox_data_geometry_data_fence() {
    manager_mailbox_case(MailboxCohort::Fence).await;
}
