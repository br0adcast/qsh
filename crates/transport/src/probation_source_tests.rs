// Runtime-generated Noise keys and synthetic source labels; no external traffic.
fn check_probation_source135(frame: StreamFrame, label: &str) {
    let (mut client, fixture) = accepted_signature_pair([135; AUTH_NONCE_LEN]);
    let mut conn = fixture.conn;
    hold_for_probation(&mut conn);
    conn.poll_events();
    let start = Instant::now();
    let other: SocketAddr = "192.0.2.135:3135".parse().unwrap();
    // Three original-source DATA packets leave ACK debt below ACK_EVERY.
    // The proof prefix is incomplete but valid; consumption cannot earn the
    // 128 KiB CREDIT step before the 8 KiB proof-record cap ends probation.
    let mut outputs = Vec::new();
    for (stream_id, byte) in [(16, b'a'), (17, b'b'), (AUTH_STREAM, good_record()[0])] {
        let dg = client.frames_for_test(vec![StreamFrame::Data {
            stream_id,
            offset: 0,
            data: vec![byte],
        }]);
        outputs.extend(conn.on_datagram(start, fixture.src, &dg[0].bytes));
    }
    conn.poll_events();
    let packet = client.frames_for_test(vec![frame]);
    let immediate = conn.on_datagram(start, other, &packet[0].bytes);
    let immediate_bytes: usize = immediate
        .iter()
        .filter(|d| d.to == other)
        .map(|d| d.bytes.len())
        .sum();
    outputs.extend(immediate);
    // Include all timer-driven output within the real proof-start window,
    // plus the explicit debt flush used before a proof is verified.
    let mut now = start;
    let end = start + AUTH_DEADLINE;
    let mut turns = 0;
    while let Some(deadline) = conn.next_timeout() {
        if deadline >= end {
            break;
        }
        now = deadline.max(now);
        outputs.extend(conn.on_timeout_if_due(now));
        turns += 1;
        assert!(
            turns < 10_000,
            "transport deadline must make finite progress"
        );
    }
    outputs.extend(conn.answer_now());
    let victim_packets = outputs.iter().filter(|d| d.to == other).count();
    let victim_bytes: usize = outputs
        .iter()
        .filter(|d| d.to == other)
        .map(|d| d.bytes.len())
        .sum();
    let original_packets = outputs.iter().filter(|d| d.to == fixture.src).count();
    let original_bytes: usize = outputs
        .iter()
        .filter(|d| d.to == fixture.src)
        .map(|d| d.bytes.len())
        .sum();
    eprintln!("source135 {label}: immediate_other_bytes={immediate_bytes} window_other_packets={victim_packets} window_other_bytes={victim_bytes} original_packets={original_packets} original_bytes={original_bytes}");
    assert_eq!(
        victim_bytes, 0,
        "no immediate or timer output to an unadmitted new source: {label}"
    );
    let credits = outputs
        .iter()
        .filter_map(|d| client.peek_frames(&d.bytes))
        .flatten()
        .filter(|f| matches!(f, StreamFrame::Credit { .. }))
        .count();
    assert_eq!(credits, 0, "no probation CREDIT fanout or repeats");
    assert!(
        outputs
            .iter()
            .filter_map(|d| client.peek_frames(&d.bytes))
            .flatten()
            .any(|f| matches!(f, StreamFrame::Ack { .. })),
        "held ACK debt actually flushed"
    );
    assert_eq!(conn.peer(), Some(fixture.src));
    assert!(!conn.poll_events().iter().any(|event| matches!(
        event,
        Event::Rehomed { .. } | Event::PeerKeyConfirmed { .. }
    )));
}

#[test]
fn source135_probation_ping_cannot_redirect_immediate_or_timer_traffic() {
    check_probation_source135(StreamFrame::Ping { token: 135 }, "PING");
}

#[test]
fn source135_probation_probe_cannot_draw_direct_answer() {
    check_probation_source135(StreamFrame::PathProbe { token: 135 }, "probe");
}

#[test]
fn source135_other_source_counter_and_repeated_hold_cannot_poison_original() {
    let (mut client, fixture) = accepted_signature_pair([135; AUTH_NONCE_LEN]);
    let mut conn = fixture.conn;
    hold_for_probation(&mut conn);
    conn.poll_events();
    let now = Instant::now();
    let original = client.frames_for_test(vec![StreamFrame::Ping { token: 1 }]);
    let mut last = Vec::new();
    for token in 2..300 {
        last = client.frames_for_test(vec![StreamFrame::Ping { token }]);
    }
    let other: SocketAddr = "192.0.2.135:3135".parse().unwrap();
    assert!(conn.on_datagram(now, other, &last[0].bytes).is_empty());
    hold_for_probation(&mut conn);
    assert_eq!(conn.peer(), Some(fixture.src));
    assert!(conn.poll_events().is_empty(), "not fresh key possession");
    let out = conn.on_datagram(now, fixture.src, &original[0].bytes);
    let frames: Vec<_> = out
        .iter()
        .filter_map(|d| client.peek_frames(&d.bytes))
        .flatten()
        .collect();
    assert_eq!(frames, vec![StreamFrame::Pong { token: 1 }]);
    assert!(conn
        .poll_events()
        .iter()
        .any(|e| matches!(e, Event::PeerKeyConfirmed { peer } if *peer == fixture.src)));
    let (mut fresh_client, mut fresh) =
        accepted_pair_at([136; AUTH_NONCE_LEN], AuthMethod::SshSignature, other);
    hold_for_probation(&mut fresh.conn);
    let packet = fresh_client.frames_for_test(vec![StreamFrame::Ping { token: 136 }]);
    let reply = fresh.conn.on_datagram(now, other, &packet[0].bytes);
    assert!(
        reply
            .iter()
            .filter_map(|d| fresh_client.peek_frames(&d.bytes))
            .flatten()
            .any(|f| f == StreamFrame::Pong { token: 136 }),
        "fresh handshake at previously rejected source remains usable"
    );
}

async fn check_source135_real_refusal(invalid: bool) {
    let original = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = original.local_addr().unwrap();
    let other_source = other.local_addr().unwrap();
    let nonce = [135; AUTH_NONCE_LEN];
    let (mut client, fixture) = accepted_pair_at(nonce, AuthMethod::SshSignature, source);
    let Fixture {
        conn,
        client_key,
        msg1,
        msg1_body,
        out,
        src,
    } = fixture;
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (route, dgram_rx) = dgram_queue();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let clock = std::sync::Mutex::new(Instant::now());
    let now = || *clock.lock().unwrap();
    let mut task = std::pin::pin!(run_probation_with_clock(
        Probation {
            socket,
            conn,
            policy: ProofPolicy::SshSignature {
                verifier: Arc::new(FakeVerifier {
                    expected: b"good".to_vec(),
                    attempts: attempts.clone()
                }),
            },
            revision: test_revision(),
            dgram_rx,
            client_key,
            msg1,
            msg1_body,
            out,
            src,
            ended_tx,
            nonce,
            verify_permits: test_permits(),
        },
        now
    ));
    std::future::poll_fn(|cx| {
        assert!(task.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    for frame in [
        StreamFrame::Ping { token: 135 },
        StreamFrame::PathProbe { token: 136 },
    ] {
        for dg in client.frames_for_test(vec![frame]) {
            assert!(route.send(other_source, dg.bytes));
        }
    }
    // Positive FIFO processing witness: a legitimate packet follows the two
    // rejected-source packets in the actual probation route.
    for dg in client.frames_for_test(vec![StreamFrame::Ping { token: 137 }]) {
        assert!(route.send(source, dg.bytes));
    }
    let mut buffer = [0; 2048];
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            tokio::select! {
                _ = task.as_mut() => panic!("probation ended before the legitimate-source witness"),
                result = original.recv_from(&mut buffer) => {
                    let (len, _) = result.unwrap();
                    if client.peek_frames(&buffer[..len]).is_some_and(|frames| frames.contains(&StreamFrame::Pong { token: 137 })) {
                        break;
                    }
                }
            }
        }
    }).await.expect("original source receives its actual PONG");
    if invalid {
        let record = encode_auth_record(&AuthRecord {
            public_key: b"key".to_vec(),
            signature: b"bad".to_vec(),
            v2: None,
        })
        .unwrap();
        for dg in client.send(Instant::now(), AUTH_STREAM, &record) {
            assert!(route.send(source, dg.bytes));
        }
    } else {
        *clock.lock().unwrap() += AUTH_DEADLINE;
        assert!(route.send(source, vec![0])); // wake after the real absolute deadline
    }
    tokio::time::timeout(Duration::from_secs(1), task.as_mut())
        .await
        .expect("refusal task completed");
    let ended = ended_rx.recv().await.unwrap();
    assert!(ended.proven.is_none());
    assert_eq!(ended.nonce, nonce);
    assert_eq!(attempts.load(Ordering::SeqCst), usize::from(invalid));
    assert!(ended_rx.try_recv().is_err());
    assert_eq!(
        other.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "no immediate, probe, debt-flush or timer datagram reached other owned socket"
    );
    assert!(
        !route.send(source, vec![0]),
        "finished probation released its receiver"
    );
}

#[tokio::test]
async fn source135_real_missing_proof_refuses_without_other_source_output() {
    check_source135_real_refusal(false).await;
}

#[tokio::test]
async fn source135_real_invalid_proof_refuses_without_other_source_output() {
    check_source135_real_refusal(true).await;
}

#[tokio::test]
async fn source135_pending_verifier_keeps_unpumped_route_custody() {
    let original = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = original.local_addr().unwrap();
    let other_source = other.local_addr().unwrap();
    let nonce = [135; AUTH_NONCE_LEN];
    let (mut client, fixture) = accepted_pair_at(nonce, AuthMethod::SshSignature, source);
    let Fixture {
        conn,
        client_key,
        msg1,
        msg1_body,
        out,
        src,
    } = fixture;
    let (route, dgram_rx) = dgram_queue();
    for dg in client.send(Instant::now(), AUTH_STREAM, &good_record()) {
        assert!(route.send(source, dg.bytes));
    }
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
    let mut task = std::pin::pin!(run_probation(Probation {
        socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        conn,
        policy: ProofPolicy::SshSignature {
            verifier: Arc::new(SignalledVerifier {
                entered: std::sync::Mutex::new(Some(entered_tx)),
                released: std::sync::Mutex::new(release_rx),
            })
        },
        revision: test_revision(),
        dgram_rx,
        client_key,
        msg1,
        msg1_body,
        out,
        src,
        ended_tx,
        nonce,
        verify_permits: test_permits(),
    }));
    let initially_pending =
        std::future::poll_fn(|cx| std::task::Poll::Ready(task.as_mut().poll(cx).is_pending()))
            .await;
    // Drive until the real off-task verifier positively reports entry.
    let entered = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::select! {
            _ = task.as_mut() => false,
            entered = entered_rx => entered.is_ok(),
        }
    })
    .await
    .unwrap_or(false);
    let probe = client
        .frames_for_test(vec![StreamFrame::PathProbe { token: 135 }])
        .remove(0)
        .bytes;
    let ping = client
        .frames_for_test(vec![StreamFrame::Ping { token: 136 }])
        .remove(0)
        .bytes;
    let queued_other = route.send(other_source, probe.clone());
    let queued_original = route.send(source, ping.clone());
    // Explicitly poll the held future after queue publication: no sleep or
    // assumption about scheduler timing is used to infer whether it pumped.
    let held_pending =
        std::future::poll_fn(|cx| std::task::Poll::Ready(task.as_mut().poll(cx).is_pending()))
            .await;
    let released = release_tx.send(()).is_ok();
    tokio::time::timeout(Duration::from_secs(2), task.as_mut())
        .await
        .expect("released verifier actually joined");
    let ended = ended_rx.recv().await.unwrap();
    let mut proven = ended.proven.expect("real verifier admitted the proof");
    let queued_first = proven.dgram_rx.try_recv();
    let queued_second = proven.dgram_rx.try_recv();
    assert!(initially_pending && entered && held_pending && released);
    assert!(queued_other && queued_original);
    assert_eq!(queued_first, Some((other_source, probe)));
    assert_eq!(queued_second, Some((source, ping)));
    assert!(proven.dgram_rx.try_recv().is_none());
    assert_eq!(proven.conn.peer(), Some(source));
}
