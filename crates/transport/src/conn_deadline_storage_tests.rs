// The previous Vec/min aggregation is a test-only differential oracle.
// It deliberately evaluates every original branch and preserves arithmetic.
fn deadline_storage_reference(conn: &Connection) -> Option<Instant> {
    if conn.keys.is_none() || matches!(conn.state, LinkState::Closed) {
        return None;
    }
    let mut candidates: Vec<Instant> = Vec::new();
    // Retransmits are due per segment (spec §4.2): the oldest
    // unacknowledged segment's last send plus `rto`, on every stream.
    // Sending anything else -- an ACK, a PING -- does not move it.
    let rto = conn.rto();
    candidates.extend(
        conn.streams
            .values()
            .filter_map(|s| s.sender.retransmit_deadline(rto)),
    );
    // The repeats of a CREDIT (spec §6.4), by the same rto `on_timeout`
    // serves them with.
    candidates.extend(
        conn.streams
            .values()
            .filter_map(|s| s.receiver.credit_resend_deadline(rto)),
    );
    // Something to send that has no deadline of its own is due at once
    // while `Live`: new bytes, a lost segment, an armed `Reset` -- after a
    // flush this is left only by the bulk budget (spec §4.8), and the
    // driver takes its commands before it comes back for more. Like the
    // forced PING below, "now" is a stored moment already in the past.
    if matches!(conn.state, LinkState::Live) && conn.sendable_now() {
        candidates.push(conn.last_recv_auth);
    }
    if matches!(conn.state, LinkState::Live | LinkState::PathDown) {
        if conn.ping_forced {
            // Forced: wake `on_timeout` now (a moment in the past).
            candidates.push(conn.last_recv_auth);
        } else {
            // The very moment `on_timeout` judges the PING due by.
            candidates.push(conn.next_ping_at());
        }
    }
    if let Some(deadline) = conn.death_base().checked_add(conn.death_after()) {
        #[cfg(test)]
        let deadline = conn
            .test_idle_until
            .map_or(deadline, |until| deadline.max(until));
        candidates.push(deadline);
    }
    if matches!(conn.state, LinkState::Live) {
        let deadline = conn.last_recv_ordinary + PATH_DOWN_AFTER;
        #[cfg(test)]
        let deadline = conn
            .test_idle_until
            .map_or(deadline, |until| deadline.max(until));
        candidates.push(deadline);
    }
    if matches!(conn.role, Role::Client) {
        let urgent = conn.probes_are_urgent();
        // `next_timeout` takes no `now` of its own (it works purely off
        // stored instants, like the `ping_forced` case just above), so a
        // never-yet-probed path -- whose deadline is "immediately" --
        // gets `last_recv_auth` as its stand-in: always in the past by
        // the time this is called, so it wakes the caller right away.
        if let Some(deadline) = conn.paths.next_deadline(conn.last_recv_auth, urgent) {
            candidates.push(deadline);
        }
    }
    // Service frames nothing carried go alone `ACK_DELAY` after the
    // first of them was owed (spec §4.11); `on_timeout` serves exactly
    // this deadline (`flush_service_if_due`).
    if let Some(since) = conn.service_since {
        candidates.push(since + ACK_DELAY);
    }
    candidates.into_iter().min()
}

#[test]
fn deadline_storage_avoids_temporary_allocations_with_positive_control() {
    let (_, quiet, _, _) = established_pair();
    let (_, mut busy, _, _) = established_pair();
    let now = busy.handshake_at;
    for stream in 16..56 {
        std::hint::black_box(busy.send(now, stream, b"pending"));
    }
    let mut observations = Vec::new();
    assert_eq!(
        allocation_probe::measure(|| {}),
        0,
        "warm the existing thread-local probe"
    );
    for (name, conn) in [("quiet Live", quiet), ("40 active streams", busy)] {
        let expected = deadline_storage_reference(&conn);
        assert!(expected.is_some());
        assert_eq!(conn.next_timeout(), expected);
        std::hint::black_box(conn.next_timeout());
        let allocations = allocation_probe::measure(|| {
            for _ in 0..8 {
                std::hint::black_box(std::hint::black_box(&conn).next_timeout());
            }
        });
        let positive = allocation_probe::measure(|| {
            let extra = std::hint::black_box(vec![expected.unwrap(); 16]);
            std::hint::black_box(extra);
        });
        assert!(
            positive > 0,
            "the existing probe must see a deliberate allocation"
        );
        observations.push((name, allocations, positive));
    }
    println!(
        "next_timeout requests over eight calls / positive-control requests: {observations:?}"
    );
    assert!(
        observations.iter().all(|(_, actual, _)| *actual == 0),
        "{observations:?}"
    );
}

fn deadline_storage_check(conn: &Connection, expected: Option<Instant>, label: &str) {
    assert_eq!(
        deadline_storage_reference(conn),
        expected,
        "reference fixture: {label}"
    );
    assert_eq!(conn.next_timeout(), expected, "candidate: {label}");
}

#[test]
fn deadline_storage_matches_absent_closed_live_and_path_down_roles() {
    for role in [Role::Client, Role::Server] {
        let key = generate_keypair();
        let cold = Connection::new(ConnectionConfig {
            required_features: Features::NONE,
            features: Features::SUPPORTED,
            role,
            local_static_priv: key.private,
            remote_static_pub: matches!(role, Role::Client).then_some(key.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
        });
        assert!(cold.keys.is_none());
        deadline_storage_check(&cold, None, "before keys");
    }
    let (client, server, _, _) = established_pair();
    for mut conn in [client, server] {
        let start = conn.handshake_at;
        deadline_storage_check(&conn, Some(start + PING_INTERVAL), "ordinary Live ping");
        conn.set_death_after(Duration::from_millis(500));
        deadline_storage_check(
            &conn,
            Some(start + Duration::from_millis(500)),
            "ordinary death minimum",
        );
        conn.set_death_after(Duration::MAX);
        std::hint::black_box(conn.on_timeout(start + PATH_DOWN_AFTER));
        assert_eq!(conn.state, LinkState::PathDown);
        deadline_storage_check(&conn, Some(conn.next_ping_at()), "PathDown ordinary ping");
        std::hint::black_box(conn.close(start + Duration::from_secs(4)));
        deadline_storage_check(&conn, None, "authenticated Closed");
    }
}

#[test]
fn deadline_storage_checks_all_streams_and_minimum_ties() {
    let (_, mut server, _, _) = established_pair();
    let start = server.handshake_at;
    let rto = server.rto();
    assert!(!server.send(start, 55, b"earliest").is_empty());
    for stream in 16..55 {
        assert!(!server
            .send(
                start + Duration::from_millis(u64::from(stream)),
                stream,
                b"later"
            )
            .is_empty());
    }
    assert_eq!(server.streams.range(16..56).count(), 40);
    assert_eq!(
        server.streams[&55].sender.retransmit_deadline(rto),
        Some(start + rto)
    );
    deadline_storage_check(
        &server,
        Some(start + rto),
        "earliest retransmit at last map entry among 40",
    );
    server.set_death_after(rto);
    server.queue_ack(start + rto - ACK_DELAY, 7, 0, false);
    assert_eq!(
        server.service_since.map(|at| at + ACK_DELAY),
        Some(start + rto)
    );
    deadline_storage_check(&server, Some(start + rto), "retransmit/death/service tie");
}

#[test]
fn deadline_storage_preserves_ack_sendable_and_forced_sentinels() {
    let (mut client, mut server, caddr, _) = established_pair();
    let start = client.handshake_at;
    let answers = data_in_turn(&mut client, &mut server, caddr, start, 20, &[0], 100);
    assert!(answers[0].is_empty());
    deadline_storage_check(&server, Some(start + ACK_DELAY), "new owed ACK service");
    assert!(!server.on_timeout_if_due(start + ACK_DELAY).is_empty());
    let horizon = start + Duration::from_secs(60);
    server.postpone_idle_for_test(horizon).unwrap();
    deadline_storage_check(&server, Some(horizon), "qualified idle horizon");
    server.mark_output_desynced_for_test();
    assert!(server.sendable_now());
    deadline_storage_check(
        &server,
        Some(server.last_recv_auth),
        "unsent Reset continuation remains immediate",
    );
    server.request_ping(start + ACK_DELAY);
    assert!(server.ping_forced);
    deadline_storage_check(
        &server,
        Some(server.last_recv_auth),
        "forced ping retains stored sentinel before horizon",
    );
}

#[test]
fn deadline_storage_preserves_real_credit_resend_before_idle_horizon() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    let now = client.handshake_at;
    let horizon = now + Duration::from_secs(60);
    server.postpone_idle_for_test(horizon).unwrap();
    server.set_stream_consumption(20, Consumption::Explicit);
    let packets = client.send(now, 20, &vec![8; 1024 * 1024]);
    pump_pair(
        &mut client,
        &mut server,
        caddr,
        saddr,
        now,
        packets,
        Vec::new(),
    );
    server.poll_events();
    let lost = server.on_consumed(now, 20, STREAM_WINDOW as usize);
    assert_eq!(credit_frames(&client, &lost), 1);
    let rto = server.rto();
    assert_eq!(
        server.streams[&20].receiver.credit_resend_deadline(rto),
        Some(now + rto)
    );
    deadline_storage_check(&server, Some(now + rto), "real armed credit minimum");
    for repeat in 1..=CREDIT_RESENDS {
        let at = now + rto * repeat;
        assert_eq!(credit_frames(&client, &server.on_timeout_if_due(at)), 1);
        assert_eq!(server.next_timeout(), deadline_storage_reference(&server));
    }
    assert!(server.streams[&20]
        .receiver
        .credit_resend_deadline(rto)
        .is_none());
    deadline_storage_check(
        &server,
        Some(horizon),
        "credit exhaustion leaves only idle horizon",
    );
}

#[test]
fn deadline_storage_preserves_unprobed_ordinary_and_urgent_paths() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    let start = client.handshake_at;
    let horizon = start + Duration::from_secs(60);
    client.postpone_idle_for_test(horizon).unwrap();
    let spare = addr("192.0.2.2:41000");
    client.set_paths(vec![saddr, spare]);
    assert!(!client.probes_are_urgent());
    deadline_storage_check(
        &client,
        Some(client.last_recv_auth),
        "never-probed stored-past path sentinel",
    );
    for packet in client.on_timeout_if_due(start) {
        for answer in server.on_datagram(start, caddr, &packet.bytes) {
            client.on_datagram(start, packet.to, &answer.bytes);
        }
    }
    let ordinary = client
        .paths
        .next_deadline(client.last_recv_auth, false)
        .unwrap();
    assert!(ordinary > start && ordinary < horizon);
    deadline_storage_check(
        &client,
        Some(ordinary),
        "ordinary verified path schedule before horizon",
    );
    client.test_idle_until = None;
    std::hint::black_box(client.on_timeout(start + PATH_DOWN_AFTER));
    assert_eq!(client.state, LinkState::PathDown);
    assert!(client.probes_are_urgent());
    let urgent = client
        .paths
        .next_deadline(client.last_recv_auth, true)
        .unwrap();
    assert!(urgent <= client.next_ping_at());
    deadline_storage_check(&client, Some(urgent), "urgent path schedule");
}
