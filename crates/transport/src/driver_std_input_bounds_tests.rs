/// Real driver/peer control: authenticated input remains retained while every
/// transport ACK/CREDIT reply is withheld, rather than only being generated.
#[test]
fn client179_withheld_ack_and_credit_bound_actual_reliable_input() {
    const CHUNK: usize = 4096;
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(25)))
        .unwrap();
    let (data_tx, data_rx) = mpsc::channel();
    let peer = StoppedOnDrop::spawn(move |stop| {
        let mut connection = server_conn(server_key.private, client_key.public);
        connection.set_stream_consumption(30, Consumption::Explicit);
        let mut first_data = true;
        let mut bytes = [0u8; 65536];
        while !stop.load(Ordering::SeqCst) {
            let (len, source) = match socket.recv_from(&mut bytes) {
                Ok(packet) => packet,
                Err(error) if is_read_timeout(&error) => continue,
                Err(_) => return,
            };
            let replies = connection.on_datagram(Instant::now(), source, &bytes[..len]);
            for reply in replies {
                // Only handshake packets may leave this real peer. No
                // authenticated transport ACK/CREDIT/PONG is delivered.
                if matches!(
                    crate::wire::parse(&reply.bytes),
                    Ok(crate::wire::Frame::Handshake { .. })
                ) {
                    let _ = socket.send_to(&reply.bytes, reply.to);
                }
            }
            for event in connection.poll_events() {
                if let Event::StreamData {
                    stream_id: 30,
                    data,
                } = event
                {
                    if first_data {
                        first_data = false;
                        let _ = data_tx.send(data.len());
                    }
                }
            }
        }
    });
    let (state_tx, state_rx) = mpsc::channel();
    let client = StdClient::connect(
        address,
        client_cfg(client_key.private, server_key.public),
        [179; 16],
        StartKind::Cold,
        Arc::new(OkBinder),
        Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        }),
        None,
    );
    // Keep all outcome assertions after both real runtime owners are joined.
    let result = (|| -> Result<_, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match state_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(LinkState::Live) => break,
                Ok(_) => continue,
                Err(error) => return Err(format!("authenticated Live: {error}")),
            }
        }
        let generated = (crate::conn::SEND_HARD_CAP / CHUNK + 1) * CHUNK;
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..generated / CHUNK {
            match client.send_bytes(30, vec![0x41; CHUNK]) {
                Ok(()) => accepted += CHUNK,
                Err(SendRejected {
                    reason: SendBlocked::Full,
                    data,
                }) => {
                    if data != vec![0x41; CHUNK] {
                        return Err("whole rejected chunk changed".into());
                    }
                    rejected += data.len();
                }
                Err(error) => return Err(format!("unexpected rejection: {error:?}")),
            }
        }
        let retained = client.input_budget.usage();
        // This existing ordered command is a positive driver-consumption
        // fence; it observes actual retained sender debt after the burst.
        let progress = client
            .stream_progress(30)
            .ok_or_else(|| "the driver did not consume the burst fence".to_string())?;
        let received = data_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|error| format!("actual authenticated data: {error}"))?;
        Ok((generated, accepted, rejected, retained, received, progress))
    })();
    client.detach();
    drop(peer); // stop and join the actual peer before acceptance assertions
    let (generated, accepted, rejected, retained, received, progress) =
        result.expect("real input path completed");
    assert_eq!(accepted + rejected, generated);
    assert_eq!(accepted, crate::conn::SEND_HARD_CAP);
    assert_eq!(rejected, CHUNK);
    assert_eq!(retained, (accepted, accepted / CHUNK, 2 * accepted));
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
    assert!(received > 0, "real peer must receive authenticated input");
    assert!(progress.queued > 0, "positive actual driver send progress");
    assert_eq!(
        progress.unacked, progress.queued,
        "no peer ACK was delivered"
    );
    assert!(
        progress.unacked <= crate::conn::SEND_HARD_CAP as u64,
        "retained {} bytes exceed client input policy {}",
        progress.unacked,
        crate::conn::SEND_HARD_CAP
    );
}

/// A deliberately undriven command receiver isolates atomic publication from
/// socket scheduling. Actual socket/ACK ownership is covered above and in the
/// authenticated Connection queue controls.
fn client179_command_fixture(limit: usize, entries: usize) -> (StdClient, Receiver<Command>) {
    let (tx, rx) = mpsc::channel();
    let mut client = StdClient::dead();
    client.tx = Mutex::new(tx);
    client.stop.store(0, Ordering::SeqCst);
    client.driver_thread = Some(thread::spawn(|| thread::current().id()).join().unwrap());
    client.input_budget = ClientInputBudget::with_limits(limit, entries);
    (client, rx)
}

#[test]
fn client179_full_gone_and_failed_publication_return_exact_original_allocation() {
    let (client, rx) = client179_command_fixture(10, 2);
    let mut spare = Vec::with_capacity(100);
    spare.push(9);
    let pointer = spare.as_ptr();
    let capacity = spare.capacity();
    let rejected = client.send_bytes(30, spare).unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Full);
    assert_eq!(rejected.data, [9]);
    assert_eq!(rejected.data.as_ptr(), pointer);
    assert_eq!(rejected.data.capacity(), capacity);
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    client.send_bytes(30, vec![1; 7]).unwrap();
    let mut data = Vec::with_capacity(9);
    data.extend_from_slice(&[2; 4]);
    let pointer = data.as_ptr();
    let capacity = data.capacity();
    let rejected = client.send_bytes(30, data).unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Full);
    assert_eq!(rejected.data.as_ptr(), pointer);
    assert_eq!(rejected.data.capacity(), capacity);
    assert_eq!(rejected.data, [2; 4]);
    assert_eq!(client.input_budget.usage(), (7, 1, 14));
    drop(rx); // failed publication must roll back both global and gate debt
    let data = vec![3; 2];
    let pointer = data.as_ptr();
    let rejected = client.send_bytes(30, data).unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Gone);
    assert_eq!(rejected.data.as_ptr(), pointer);
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
    client.stop.store(2, Ordering::SeqCst);
    let data = vec![4; 2];
    let pointer = data.as_ptr();
    let rejected = client.send_bytes(30, data).unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Gone);
    assert_eq!(rejected.data.as_ptr(), pointer);
}

#[test]
fn client179_generic_and_gated_publication_share_fifo_and_empty_has_no_debt() {
    let (client, rx) = client179_command_fixture(32, 4);
    client.send_bytes(30, vec![1; 3]).unwrap();
    client
        .send_bytes_bounded(30, vec![2; 4], Duration::ZERO)
        .unwrap();
    client.send_bytes(30, vec![3; 5]).unwrap();
    client.send_bytes(30, Vec::with_capacity(1000)).unwrap();
    client
        .send_bytes_bounded(30, Vec::new(), Duration::ZERO)
        .unwrap();
    assert_eq!(client.input_budget.usage(), (12, 3, 24));
    for expected in [vec![1; 3], vec![2; 4], vec![3; 5]] {
        let Command::Send { stream_id, record } = rx.try_recv().unwrap() else {
            panic!("only accepted records may be published");
        };
        assert_eq!(stream_id, 30);
        assert_eq!(record.into_bytes(), expected);
    }
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
}

#[test]
fn client179_gate_recheck_rejects_whole_record_without_global_or_fifo_debit() {
    let (client, rx) = client179_command_fixture(1024 * 1024, 4);
    let gate = client.gates.gate(30, GateKind::Pipe);
    // Models two producers that both observed an open gate: the first wins
    // publication; the second must recheck and reserve the complete chunk.
    assert!(gate.is_open());
    client.send_bytes(30, vec![1; 512 * 1024]).unwrap();
    let data = vec![2; 2];
    let pointer = data.as_ptr();
    let rejected = client.admit_bytes(30, data, true).unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Full);
    assert_eq!(rejected.data.as_ptr(), pointer);
    assert_eq!(client.input_budget.usage(), (512 * 1024, 1, 1024 * 1024));
    drop(rx.try_recv().unwrap());
    assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
}

#[test]
fn client179_concurrent_command_producers_cannot_exceed_shared_whole_record_limit() {
    let (client, rx) = client179_command_fixture(7, 2);
    let client = Arc::new(client);
    let start = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|value| {
            let client = client.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                client.send_bytes(30, vec![value; 4])
            })
        })
        .collect();
    start.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(client.input_budget.usage(), (4, 1, 8));
    drop(rx);
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
}

#[test]
fn client179_real_peer_credit_resume_preserves_mixed_api_fifo_and_refunds_before_teardown() {
    let first = vec![1; 4096];
    let second = vec![2; crate::reliability::STREAM_WINDOW as usize + 4096];
    let last = vec![3; 8192];
    let expected = [first.as_slice(), second.as_slice(), last.as_slice()].concat();
    let expected_len = expected.len();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let peer_release = release.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (complete_tx, complete_rx) = mpsc::channel();
    let peer = StoppedOnDrop::spawn(move |stop| {
        let mut connection = server_conn(server_key.private, client_key.public);
        connection.set_stream_consumption(30, Consumption::Explicit);
        let mut bytes = [0; 65536];
        let mut held_consumption = 0;
        let mut received = Vec::new();
        let mut complete = false;
        while !stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            let mut replies = match socket.recv_from(&mut bytes) {
                Ok((len, source)) => connection.on_datagram(now, source, &bytes[..len]),
                Err(error) if is_read_timeout(&error) => connection.on_timeout(now),
                Err(_) => return,
            };
            for event in connection.poll_events() {
                if let Event::StreamData {
                    stream_id: 30,
                    data,
                } = event
                {
                    if received.is_empty() {
                        let _ = entered_tx.send(());
                    }
                    held_consumption += data.len();
                    if received.len() + data.len() > expected_len {
                        let _ = complete_tx.send(Err("duplicate or excess input".to_string()));
                        return;
                    }
                    received.extend(data);
                    if !complete && received.len() == expected_len {
                        complete = true;
                        let _ = complete_tx.send(Ok(std::mem::take(&mut received)));
                    }
                }
            }
            if peer_release.load(Ordering::SeqCst) && held_consumption > 0 {
                replies.extend(connection.on_consumed(now, 30, held_consumption));
                held_consumption = 0;
            }
            for reply in replies {
                if peer_release.load(Ordering::SeqCst)
                    || matches!(
                        crate::wire::parse(&reply.bytes),
                        Ok(crate::wire::Frame::Handshake { .. })
                    )
                {
                    let _ = socket.send_to(&reply.bytes, reply.to);
                }
            }
        }
    });
    let (state_tx, state_rx) = mpsc::channel();
    let client = StdClient::connect(
        address,
        client_cfg(client_key.private, server_key.public),
        [179; 16],
        StartKind::Cold,
        Arc::new(OkBinder),
        Arc::new(StateEvents {
            tx: Mutex::new(state_tx),
        }),
        None,
    );
    let result = (|| -> Result<_, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match state_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(LinkState::Live) => break,
                Ok(_) => {}
                Err(error) => return Err(format!("Live: {error}")),
            }
        }
        client
            .send_bytes_bounded(30, first, Duration::ZERO)
            .map_err(|e| format!("gated: {e:?}"))?;
        client
            .send_bytes(30, second)
            .map_err(|e| format!("large: {e:?}"))?;
        client
            .send_bytes(30, last)
            .map_err(|e| format!("last: {e:?}"))?;
        let _ = client.stream_progress(30).ok_or("initial command fence")?;
        entered_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| format!("actual held peer input: {e}"))?;
        let before = client
            .stream_progress(30)
            .ok_or("actual peer-entry send fence")?;
        let held = client.input_budget.usage();
        release.store(true, Ordering::SeqCst);
        let received = complete_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| format!("complete accepted input: {e}"))??;
        loop {
            let progress = client.stream_progress(30).ok_or("ACK observation fence")?;
            if client.input_budget.usage() == (0, 0, 0) {
                return Ok((before, held, progress, received, !client.is_gone()));
            }
            if Instant::now() >= deadline {
                return Err("whole-record ACK refund deadline".into());
            }
        }
    })();
    client.detach();
    drop(peer);
    let (before, held, after, received, still_live) = result.expect("real credit/ACK path");
    assert!(before.queued > 0);
    assert_eq!(held, (expected_len, 3, 2 * expected_len));
    assert_eq!(
        received, expected,
        "accepted mixed APIs preserve exactly-once FIFO"
    );
    assert_eq!(after.queued, expected_len as u64);
    assert_eq!(after.unacked, 0);
    assert!(still_live, "ACK refund precedes actual teardown");
}

#[test]
fn client179_bounded_large_chunk_crosses_gate_window_but_not_shared_budget() {
    let (client, rx) = client179_command_fixture(2 * 1024 * 1024, 2);
    let length = crate::reliability::STREAM_WINDOW as usize + 4096;
    client
        .send_bytes_bounded(30, vec![1; length], Duration::ZERO)
        .unwrap();
    assert!(!client.gates.gate(30, GateKind::Pipe).is_open());
    let rejected = client
        .send_bytes_bounded(30, vec![2; 1], Duration::ZERO)
        .unwrap_err();
    assert_eq!(rejected.reason, SendBlocked::Full);
    assert_eq!(client.input_budget.usage(), (length, 1, 2 * length));
    drop(rx);
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
}

#[test]
fn client179_shared_budget_survives_old_driver_until_real_teardown() {
    let first_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let budget = ClientInputBudget::with_limits(10, 3);
    let connect = |address| {
        StdClient::connect_with(
            address,
            client_cfg(client_key.private, server_key.public),
            [179; 16],
            StartKind::Warm,
            Arc::new(OkBinder),
            Arc::new(NullEvents),
            None,
            DriverSetup {
                input_budget: Some(budget.clone()),
                ..DriverSetup::default()
            },
        )
    };
    let old = connect(first_socket.local_addr().unwrap());
    let replacement = connect(second_socket.local_addr().unwrap());
    let result = (|| -> Result<_, String> {
        old.send_bytes(30, vec![1; 7])
            .map_err(|e| format!("old: {e:?}"))?;
        let rejected = replacement.send_bytes(30, vec![2; 4]);
        replacement
            .send_bytes(30, vec![3; 3])
            .map_err(|e| format!("replacement: {e:?}"))?;
        let before = budget.usage();
        old.detach(); // joins the actual old Connection, including unprocessed commands
        let after_old = budget.usage();
        replacement
            .send_bytes(30, vec![4; 7])
            .map_err(|e| format!("refunded capacity: {e:?}"))?;
        Ok((rejected, before, after_old, budget.usage()))
    })();
    old.detach();
    replacement.detach();
    let (rejected, before, after_old, after_reuse) = result.expect("shared runtime custody");
    assert_eq!(rejected.unwrap_err().reason, SendBlocked::Full);
    assert_eq!(before, (10, 2, 20));
    assert_eq!(after_old, (3, 1, 6));
    assert_eq!(after_reuse, (10, 2, 20));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_close_is_sticky_ahead_of_a_full_unprocessed_input_backlog() {
    struct HeldBinder {
        entered: Sender<()>,
        release: Mutex<Receiver<()>>,
    }
    impl Binder for HeldBinder {
        fn bind(&self, _: i32) -> bool {
            let _ = self.entered.send(());
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .is_ok()
        }
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_key = crate::handshake::generate_keypair();
    let client_key = crate::handshake::generate_keypair();
    let (entered, observed) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let client = Arc::new(StdClient::connect(
        socket.local_addr().unwrap(),
        client_cfg(client_key.private, server_key.public),
        [179; 16],
        StartKind::Cold,
        Arc::new(HeldBinder {
            entered,
            release: Mutex::new(held),
        }),
        Arc::new(NullEvents),
        None,
    ));
    let result = (|| -> Result<_, String> {
        observed
            .recv_timeout(Duration::from_secs(3))
            .map_err(|e| format!("held binder: {e}"))?;
        for _ in 0..crate::client_input_budget::INPUT_ENTRIES {
            client
                .send_bytes(30, vec![1])
                .map_err(|e| format!("whole entry: {e:?}"))?;
        }
        let full = client.send_bytes(30, vec![2]);
        let held = client.input_budget.usage();
        let closing = client.clone();
        let closer = thread::spawn(move || closing.close());
        let deadline = Instant::now() + Duration::from_secs(3);
        while client.stop.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::yield_now();
        }
        let stop = client.stop.load(Ordering::SeqCst);
        let _ = release.send(());
        closer.join().map_err(|_| "close caller panicked")?;
        Ok((full, held, stop))
    })();
    let _ = release.send(()); // every early error releases the actual held driver
    client.detach();
    let (full, held, stop) = result.expect("sticky close path");
    assert_eq!(full.unwrap_err().reason, SendBlocked::Full);
    assert_eq!(
        held,
        (
            crate::client_input_budget::INPUT_ENTRIES,
            crate::client_input_budget::INPUT_ENTRIES,
            2 * crate::client_input_budget::INPUT_ENTRIES
        )
    );
    assert_eq!(
        stop, 1,
        "close signal is published before consuming any queued command"
    );
    assert_eq!(client.input_budget.usage(), (0, 0, 0));
    assert!(client.is_gone());
}
