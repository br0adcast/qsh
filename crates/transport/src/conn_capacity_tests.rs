#[test]
fn capacity_wire_negotiated_abort_preserves_reason_before_closed_and_ignores_replay() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    assert!(client.features().contains(Features::RESOURCE_LIMITS));
    client.poll_events();
    server.poll_events();
    let now = Instant::now();
    let _ = server.send(
        now,
        crate::channel::CONTROL_STREAM,
        &vec![1; crate::send_gate::PIPE_HIGH as usize],
    );
    assert!(
        server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .unacked
            > 0
    );
    let packets = server.abort_session(now, crate::SessionAbortReason::ResourceExhausted);
    assert_eq!(packets.len(), 1);
    assert!(
        packets[0].bytes.len() < 128,
        "abort is a fixed service packet"
    );
    assert_eq!(
        client.peek_frames(&packets[0].bytes),
        Some(vec![StreamFrame::SessionAbort {
            reason: crate::SessionAbortReason::ResourceExhausted
        }])
    );
    deliver(&mut client, now, saddr, packets.clone());
    assert_eq!(
        client.poll_events(),
        vec![
            Event::SessionAborted(crate::SessionAbortReason::ResourceExhausted),
            Event::StateChanged(LinkState::Closed)
        ]
    );
    assert_eq!(
        client.session_abort_reason(),
        Some(crate::SessionAbortReason::ResourceExhausted)
    );
    assert!(client.closed_gracefully());
    deliver(&mut client, now, saddr, packets);
    assert!(client.poll_events().is_empty());
    assert!(server
        .abort_session(now, crate::SessionAbortReason::Unknown(200))
        .is_empty());
    let _ = caddr;
}

#[test]
fn capacity_wire_legacy_close_does_not_invent_a_peer_abort_reason() {
    let (mut client, mut server, _, saddr) = established_pair();
    let legacy = Features::from_bits(client.features.bits() & !Features::RESOURCE_LIMITS.bits());
    client.features = legacy;
    server.features = legacy;
    client.poll_events();
    let now = Instant::now();
    let packets = server.abort_session(now, crate::SessionAbortReason::ResourceExhausted);
    assert_eq!(
        client.peek_frames(&packets[0].bytes),
        Some(vec![StreamFrame::Close { stream_id: 0 }])
    );
    deliver(&mut client, now, saddr, packets);
    assert_eq!(client.session_abort_reason(), None);
    assert!(client.closed_gracefully());
    assert_eq!(
        client.poll_events(),
        vec![Event::StateChanged(LinkState::Closed)]
    );
}

#[test]
fn capacity_wire_unnegotiated_abort_cannot_terminate_the_session() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    client.features =
        Features::from_bits(client.features.bits() & !Features::RESOURCE_LIMITS.bits());
    client.poll_events();
    let packet = sealed_proof_packet(&mut server, caddr, &[0x0a, 1]);
    client.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(client.state(), LinkState::Live);
    assert_eq!(client.session_abort_reason(), None);
    assert!(client.poll_events().is_empty());
}

#[test]
fn capacity_wire_unauthenticated_abort_does_not_spend_the_valid_packet_counter() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    client.poll_events();
    let packet = sealed_proof_packet(&mut server, caddr, &[0x0a, 1]);
    let mut forged = packet.clone();
    *forged.last_mut().unwrap() ^= 1;
    client.on_datagram(Instant::now(), saddr, &forged);
    assert_eq!(client.state(), LinkState::Live);
    assert_eq!(client.session_abort_reason(), None);
    assert!(client.poll_events().is_empty());
    client.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(client.state(), LinkState::Closed);
}

#[test]
fn capacity_wire_old_session_abort_cannot_end_a_replacement_connection() {
    let (mut old, mut server, caddr, saddr) = established_pair();
    let (mut replacement, _, _, _) = established_pair();
    replacement.poll_events();
    let packet = sealed_proof_packet(&mut server, caddr, &[0x0a, 1]);
    replacement.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(replacement.state(), LinkState::Live);
    assert_eq!(replacement.session_abort_reason(), None);
    assert!(replacement.poll_events().is_empty());
    old.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(old.state(), LinkState::Closed);
}

#[test]
fn capacity_wire_unknown_reason_remains_terminal_and_survives_same_packet_close() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    client.poll_events();
    let packet = sealed_proof_packet(&mut server, caddr, &[0x0a, 200, 0x05, 0]);
    client.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(
        client.session_abort_reason(),
        Some(crate::SessionAbortReason::Unknown(200))
    );
    assert_eq!(
        client.poll_events(),
        vec![
            Event::SessionAborted(crate::SessionAbortReason::Unknown(200)),
            Event::StateChanged(LinkState::Closed)
        ]
    );
}

#[test]
fn capacity_wire_unknown_authenticated_frame_is_not_an_abort() {
    let (mut client, mut server, caddr, saddr) = established_pair();
    client.poll_events();
    let packet = sealed_proof_packet(&mut server, caddr, &[0xff, 1]);
    client.on_datagram(Instant::now(), saddr, &packet);
    assert_eq!(client.state(), LinkState::Live);
    assert_eq!(client.session_abort_reason(), None);
    assert!(client.poll_events().is_empty());
}

#[test]
fn capacity_accounting_owned_control_admission_returns_blocked_allocation_unchanged() {
    let (mut conn, _server, _client_addr, _server_addr) = established_pair();
    let now = conn.handshake_at;
    let bytes = vec![b'x'; 80];
    let allocation = bytes.as_ptr();
    let result = conn.try_send_owned_bounded(now, crate::channel::CONTROL_STREAM, bytes, 79);
    let (reason, returned) = match result {
        Err(blocked) => blocked,
        Ok(_) => panic!("over-limit record was admitted"),
    };
    assert_eq!(reason, SendBlocked::WouldBlock);
    assert_eq!(returned.as_ptr(), allocation);
    assert_eq!(returned, vec![b'x'; 80]);
    assert_eq!(
        conn.stream_progress(crate::channel::CONTROL_STREAM),
        StreamProgress::default()
    );
}

#[test]
fn capacity_accounting_owned_control_admission_obeys_existing_reliable_debt() {
    let (mut conn, _server, _client_addr, _server_addr) = established_pair();
    let now = conn.handshake_at;
    let stream = crate::channel::CONTROL_STREAM;
    let _ = conn.send(now, stream, b"opened");
    assert!(conn
        .try_send_owned_bounded(now, stream, vec![1; 10], 16)
        .is_ok());
    let before = conn.stream_progress(stream);
    assert_eq!(before.queued, 16);
    assert_eq!(before.unacked, 16);
    let blocked = conn.try_send_owned_bounded(now, stream, vec![2], 16);
    assert!(matches!(blocked, Err((SendBlocked::WouldBlock, bytes)) if bytes == vec![2]));
    assert_eq!(conn.stream_progress(stream), before);
}
