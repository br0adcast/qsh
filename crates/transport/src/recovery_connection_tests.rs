use super::*;
use crate::handshake::generate_keypair;
use crate::recovery_handshake::RecoveryEndpoint;

fn address(n: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 41000 + n))
}

fn fixture() -> (Connection, ConnectionConfig, Instant) {
    let client = generate_keypair();
    let server = generate_keypair();
    let config = ConnectionConfig {
        role: Role::Server,
        local_static_priv: server.private,
        remote_static_pub: None,
        auth: AuthPolicy::Allowlist(vec![client.public]),
        features: Features::SUPPORTED,
        required_features: Features::NONE,
    };
    (
        Connection::new(ConnectionConfig {
            role: Role::Client,
            local_static_priv: client.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
            features: Features::SUPPORTED,
            required_features: Features::NONE,
        }),
        config,
        Instant::now(),
    )
}

fn start(client: &mut Connection, now: Instant) -> Vec<Datagram> {
    client.start_recovery(
        now,
        vec![
            RecoveryEndpoint {
                address: 0,
                endpoint: address(0),
            },
            RecoveryEndpoint {
                address: 1,
                endpoint: address(1),
            },
            RecoveryEndpoint {
                address: 2,
                endpoint: address(0),
            },
        ],
        StartKind::Warm,
        [5; 16],
    )
}

#[test]
fn shared_recovery_same_msg1_selects_one_source_before_any_queued_output() {
    let (mut client, config, now) = fixture();
    let outgoing = start(&mut client, now);
    assert_eq!(
        outgoing.len(),
        2,
        "all physical endpoints get the single initiator's msg1"
    );
    assert_eq!(outgoing[0].bytes, outgoing[1].bytes);
    assert_eq!([outgoing[0].to, outgoing[1].to], [address(0), address(1)]);
    for datagram in &outgoing {
        client.recovery_handshake_sent(now, datagram.to, true);
    }
    let mut a = Connection::new(config.clone());
    let mut b = Connection::new(config);
    let response_a = a.on_datagram(now, address(99), &outgoing[0].bytes);
    let response_b = b.on_datagram(now, address(99), &outgoing[1].bytes);
    assert_eq!(response_a.len(), 1);
    assert_eq!(response_b.len(), 1);
    assert_ne!(
        response_a[0].bytes, response_b[0].bytes,
        "independent responder transcripts"
    );
    assert!(client.send(now, 16, b"queued output").is_empty());
    client.poll_events();
    let flushed = client.on_datagram(now, address(1), &response_b[0].bytes);
    assert_eq!(client.state(), LinkState::Live);
    assert_eq!(client.active_path(), Some(address(1)));
    assert!(!flushed.is_empty());
    assert!(flushed.iter().all(|datagram| datagram.to == address(1)));
    assert_eq!(
        client
            .poll_events()
            .iter()
            .filter(|event| **event == Event::HandshakeDone)
            .count(),
        1
    );
    assert!(client
        .on_datagram(now, address(0), &response_a[0].bytes)
        .is_empty());
    assert!(client.poll_events().is_empty());
    assert_eq!(client.active_path(), Some(address(1)));
}

#[test]
fn shared_recovery_only_a_successfully_sent_endpoint_can_consume_noise() {
    let (mut client, config, now) = fixture();
    let outgoing = start(&mut client, now);
    let mut server = Connection::new(config);
    let response = server.on_datagram(now, address(99), &outgoing[0].bytes);
    client.poll_events();
    assert!(client
        .on_datagram(now, address(0), &response[0].bytes)
        .is_empty());
    assert_eq!(
        client.state(),
        LinkState::Connecting,
        "reserved output was not sent yet"
    );
    assert!(client.poll_events().is_empty());
    client.recovery_handshake_sent(now, address(0), true);
    client.on_datagram(now, address(0), &response[0].bytes);
    assert_eq!(client.state(), LinkState::Live);
}

#[test]
fn shared_recovery_cookie_is_source_bound_and_never_replaces_another_endpoint() {
    let (mut client, _, now) = fixture();
    let outgoing = start(&mut client, now);
    assert_eq!(outgoing.len(), 2);
    for datagram in &outgoing {
        client.recovery_handshake_sent(now, datagram.to, true);
    }
    let Frame::Handshake { body, .. } = parse(&outgoing[0].bytes).unwrap() else {
        panic!("msg1");
    };
    let echo: [u8; COOKIE_ECHO_LEN] = body[..COOKIE_ECHO_LEN].try_into().unwrap();
    let cookie = crate::wire::encode_cookie_reply(&echo, &[7; COOKIE_LEN]);
    assert!(client.on_datagram(now, address(99), &cookie).is_empty());
    let wrong_echo = crate::wire::encode_cookie_reply(&[0; COOKIE_ECHO_LEN], &[7; COOKIE_LEN]);
    assert!(client.on_datagram(now, address(0), &wrong_echo).is_empty());
    let immediate = client.on_datagram(now, address(0), &cookie);
    assert_eq!(immediate.len(), 1);
    assert_eq!(immediate[0].to, address(0));
    let Frame::Handshake {
        kind: Kind::HandshakeInitCookie,
        body: wrapped,
    } = parse(&immediate[0].bytes).unwrap()
    else {
        panic!("cookie retry");
    };
    let (actual_cookie, actual_msg1) = crate::wire::split_cookie_init(wrapped).unwrap();
    assert_eq!(actual_cookie, [7; COOKIE_LEN]);
    assert_eq!(actual_msg1, body);
    client.recovery_handshake_sent(now, address(0), true);
    let retry = client.poll_recovery_handshake(now + Duration::from_millis(500));
    assert_eq!(retry.len(), 2);
    for datagram in retry {
        let Frame::Handshake { kind, .. } = parse(&datagram.bytes).unwrap() else {
            panic!("retry");
        };
        assert_eq!(
            kind,
            if datagram.to == address(0) {
                Kind::HandshakeInitCookie
            } else {
                Kind::HandshakeInit
            }
        );
    }
}

#[test]
fn shared_recovery_invalid_candidate_does_not_consume_later_valid_msg2() {
    let (mut client, config, now) = fixture();
    let outgoing = start(&mut client, now);
    for datagram in &outgoing {
        client.recovery_handshake_sent(now, datagram.to, true);
    }
    let mut server = Connection::new(config);
    let response = server.on_datagram(now, address(99), &outgoing[0].bytes);
    let mut forged = response[0].bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    client.poll_events();
    assert!(client.on_datagram(now, address(0), &forged).is_empty());
    assert_eq!(client.state(), LinkState::Connecting);
    assert!(client.poll_events().is_empty());
    client.on_datagram(now, address(1), &response[0].bytes);
    assert_eq!(client.state(), LinkState::Live);
    assert_eq!(client.active_path(), Some(address(1)));
}

#[test]
fn shared_recovery_authenticated_protocol_failure_keeps_exact_consumed_source() {
    let (mut client, config, now) = fixture();
    let outgoing = start(&mut client, now);
    for datagram in &outgoing {
        client.recovery_handshake_sent(now, datagram.to, true);
    }
    let Frame::Handshake { body, .. } = parse(&outgoing[1].bytes).unwrap() else {
        panic!("msg1");
    };
    let mut responder = Handshake::new_responder(&config.local_static_priv);
    responder.read_msg(body).unwrap();
    let malformed = encode_handshake(Kind::HandshakeResp, &responder.write_msg(b"invalid"));
    client.send(now, 16, b"must stay queued");
    client.poll_events();
    assert!(client.on_datagram(now, address(1), &malformed).is_empty());
    assert_eq!(client.state(), LinkState::Closed);
    assert!(
        client.keys.is_none(),
        "protocol failure cannot publish a usable transport"
    );
    assert_eq!(
        client.recovery_handshake().unwrap().selected(),
        Some(address(1)),
        "only this endpoint consumed the initiator; other checks remain unfinished"
    );
    let events = client.poll_events();
    assert!(events
        .iter()
        .any(|event| matches!(event, Event::InvalidHandshakeResponse { .. })));
    assert!(!events.contains(&Event::HandshakeDone));
    assert!(client
        .poll_recovery_handshake(now + Duration::from_secs(1))
        .is_empty());
}
