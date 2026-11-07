use super::*;
use crate::handshake::generate_keypair;
use std::time::Instant;

fn info() -> ServerInfo {
    ServerInfo {
        generation: [7; 16],
        core_version: "0.6.0".into(),
        session_protocols: vec![SessionProfile {
            wire: 2,
            handshake: 2,
            channel: 2,
        }],
    }
}

#[test]
fn bootstrap_pinned_exchange_is_fresh_and_independent_of_session_wire() {
    let server = generate_keypair();
    let client = generate_keypair();
    let mut responder = BootstrapResponder::new(server.private, info()).unwrap();
    let mut client = BootstrapClient::new(client.private, server.public, [9; 32]);
    let source = "192.0.2.7:1234".parse().unwrap();
    let request = client.request();
    assert_eq!(request.len(), 512);
    assert_eq!(&request[..5], b"QSHB\x01");
    assert!(crate::wire::parse(&request).is_err());
    let cookie = responder
        .on_datagram(Instant::now(), source, &request)
        .unwrap();
    assert_eq!(client.accept(&cookie), Err(BootstrapError::Retry));
    let response = responder
        .on_datagram(Instant::now(), source, &client.request())
        .unwrap();
    assert!(response.len() <= 512);
    let proof = client.accept(&response).unwrap();
    assert_eq!(proof.info(), &info());
    assert_eq!(client.accept(&response), Err(BootstrapError::Completed));
}

#[test]
fn bootstrap_wrong_pin_and_tampering_never_produce_proof() {
    let server = generate_keypair();
    let wrong = generate_keypair();
    let local = generate_keypair();
    let mut responder = BootstrapResponder::new(server.private, info()).unwrap();
    let source = "192.0.2.7:1234".parse().unwrap();
    let mut client = BootstrapClient::new(local.private, wrong.public, [1; 32]);
    let cookie = responder
        .on_datagram(Instant::now(), source, &client.request())
        .unwrap();
    assert_eq!(client.accept(&cookie), Err(BootstrapError::Retry));
    assert!(responder
        .on_datagram(Instant::now(), source, &client.request())
        .is_none());
}

#[test]
fn bootstrap_metadata_bounds_are_enforced_before_serving() {
    let key = generate_keypair();
    let mut value = info();
    value.core_version = "x".repeat(129);
    assert!(BootstrapResponder::new(key.private, value).is_err());
    let mut value = info();
    value.session_protocols = vec![value.session_protocols[0]; 17];
    assert!(BootstrapResponder::new(key.private, value).is_err());
}

#[test]
fn bootstrap_cookie_is_bound_to_source_and_noise_exchange() {
    let server = generate_keypair();
    let local = generate_keypair();
    let mut responder = BootstrapResponder::new(server.private, info()).unwrap();
    let source = "192.0.2.1:5000".parse().unwrap();
    let other = "192.0.2.2:5000".parse().unwrap();
    let mut client = BootstrapClient::new(local.private, server.public, [3; 32]);
    let cookie = responder
        .on_datagram(Instant::now(), source, &client.request())
        .unwrap();
    assert_eq!(client.accept(&cookie), Err(BootstrapError::Retry));
    let reflected = responder
        .on_datagram(Instant::now(), other, &client.request())
        .unwrap();
    assert_eq!(
        reflected[5], COOKIE,
        "wrong source receives only another cookie"
    );
    let mut tampered = client.request();
    tampered[REQUEST_LEN - 1] = 1;
    assert!(responder
        .on_datagram(Instant::now(), source, &tampered)
        .is_none());
    assert!(responder
        .on_datagram(Instant::now(), source, &tampered[..511])
        .is_none());
}

#[test]
fn bootstrap_replay_from_previous_attempt_cannot_authenticate_current_attempt() {
    let server = generate_keypair();
    let local = generate_keypair();
    let source = "192.0.2.1:5000".parse().unwrap();
    let mut responder = BootstrapResponder::new(server.private, info()).unwrap();
    let mut old = BootstrapClient::new(local.private, server.public, [1; 32]);
    let cookie = responder
        .on_datagram(Instant::now(), source, &old.request())
        .unwrap();
    old.accept(&cookie).unwrap_err();
    let response = responder
        .on_datagram(Instant::now(), source, &old.request())
        .unwrap();
    let mut current = BootstrapClient::new(local.private, server.public, [2; 32]);
    assert_eq!(
        current.accept(&response),
        Err(BootstrapError::Authentication)
    );
    let mut changed = response.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(old.accept(&changed), Err(BootstrapError::Authentication));
}

#[test]
fn bootstrap_generation_mismatch_refuses_before_resolve_and_preserves_legacy_msg2() {
    use crate::conn::{AuthPolicy, Connection, ConnectionConfig, ResolvedAccept, Role};
    use crate::handshake_payload::StartKind;
    use crate::Msg2Inputs;
    let server = generate_keypair();
    let local = generate_keypair();
    let source = "192.0.2.1:5000".parse().unwrap();
    let now = Instant::now();
    let config = |role, secret, remote, auth| ConnectionConfig {
        role,
        local_static_priv: secret,
        remote_static_pub: remote,
        auth,
        features: crate::Features::SUPPORTED,
        required_features: crate::Features::NONE,
    };
    for expected in [None, Some([7; 16]), Some([8; 16])] {
        let mut client = Connection::new(config(
            Role::Client,
            local.private,
            Some(server.public),
            AuthPolicy::Allowlist(vec![]),
        ));
        client.set_expected_generation(expected);
        let request = client.start_session(now, source, StartKind::Cold, [0; 16]);
        let wire::Frame::Handshake { body, .. } = wire::parse(&request[0].bytes).unwrap() else {
            panic!()
        };
        let mut resolved = 0;
        let accepted = Connection::accept_resolved_with_generation(
            config(
                Role::Server,
                server.private,
                None,
                AuthPolicy::Allowlist(vec![local.public]),
            ),
            now,
            source,
            body,
            &mut |_| {
                resolved += 1;
                Some(crate::conn::Msg2Resolution::Fresh(Msg2Inputs {
                    resumed: false,
                    nonce: [0; 16],
                }))
            },
            Some([7; 16]),
        );
        if expected == Some([8; 16]) {
            assert!(matches!(accepted, ResolvedAccept::Rejected));
            assert_eq!(resolved, 0);
        } else {
            let ResolvedAccept::Fresh(accepted) = accepted else {
                panic!()
            };
            client.on_datagram(now, source, &accepted.out[0].bytes);
            assert_eq!(client.server_generation(), Some([7; 16]));
            assert_eq!(resolved, 1);
        }
    }
}

#[test]
fn bootstrap_domain_challenge_and_rate_limits_are_enforced() {
    let server = generate_keypair();
    let local = generate_keypair();
    let now = Instant::now();
    let source = "192.0.2.1:5000".parse().unwrap();
    let mut responder = BootstrapResponder::new(server.private, info()).unwrap();
    let mut client = BootstrapClient::new(local.private, server.public, [3; 32]);
    assert_eq!(&client.request()[5..8], &[1, 0, 128]);
    let cookie = responder
        .on_datagram(now, source, &client.request())
        .unwrap();
    client.accept(&cookie).unwrap_err();
    let retry = client.request();
    for _ in 0..crate::cookie::PROVEN_BURST {
        assert_eq!(
            responder.on_datagram(now, source, &retry).unwrap()[5],
            REPLY
        );
    }
    assert!(responder.on_datagram(now, source, &retry).is_none());

    // Session Noise cannot authenticate a bootstrap exchange (distinct prologue).
    let mut ordinary = Handshake::new_initiator(&local.private, &server.public);
    let ordinary_request = frame(REQUEST, &ordinary.write_msg(&[3; 32]), true);
    let other = "192.0.2.2:5000".parse().unwrap();
    let cookie = responder
        .on_datagram(now, other, &ordinary_request)
        .unwrap();
    let (_, cookie_body) = parse(&cookie).unwrap();
    let (_, body) = parse(&ordinary_request).unwrap();
    let mut retry = cookie_body[16..].to_vec();
    retry.extend_from_slice(body);
    assert!(responder
        .on_datagram(now, other, &frame(COOKIE_REQUEST, &retry, true))
        .is_none());

    // A valid responder identity cannot accidentally satisfy a different challenge.
    let mut client = BootstrapClient::new(local.private, server.public, [4; 32]);
    let mut hs = Handshake::new_bootstrap_responder(&server.private);
    hs.read_msg(parse(&client.request()).unwrap().1).unwrap();
    let mut payload = vec![5; 32];
    payload.extend_from_slice(&encode_server_info(&info()).unwrap());
    assert_eq!(
        client.accept(&frame(REPLY, &hs.write_msg(&payload), false)),
        Err(BootstrapError::Challenge)
    );
}

#[test]
fn bootstrap_legacy_msg1_keeps_exact_msg2_length_while_parallel_client_announces_support() {
    use crate::conn::{AuthPolicy, Connection, ConnectionConfig, ResolvedAccept, Role};
    use crate::handshake_payload::{encode_msg1, AuthMethod, Msg1Payload, StartKind};
    let server = generate_keypair();
    let local = generate_keypair();
    let now = Instant::now();
    let source = "192.0.2.1:5000".parse().unwrap();
    for aware in [false, true] {
        let mut client = Connection::new(ConnectionConfig {
            role: Role::Client,
            local_static_priv: local.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(vec![]),
            features: crate::Features::NONE,
            required_features: crate::Features::NONE,
        });
        let payload = encode_msg1(&Msg1Payload {
            start_kind: StartKind::Cold,
            token: [3; 16],
            method: AuthMethod::Allowlist,
            offered: crate::Features::NONE,
        });
        assert_eq!(
            payload,
            vec![2, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0]
        );
        let request = if aware {
            client.start_session(now, source, StartKind::Cold, [3; 16])
        } else {
            client.start_with_payload(now, source, &payload)
        };
        let wire::Frame::Handshake { body, .. } = wire::parse(&request[0].bytes).unwrap() else {
            panic!()
        };
        let accepted = Connection::accept_resolved_with_generation(
            ConnectionConfig {
                role: Role::Server,
                local_static_priv: server.private,
                remote_static_pub: None,
                auth: AuthPolicy::Allowlist(vec![local.public]),
                features: crate::Features::NONE,
                required_features: crate::Features::NONE,
            },
            now,
            source,
            body,
            &mut |_| {
                Some(crate::conn::Msg2Resolution::Fresh(crate::Msg2Inputs {
                    resumed: false,
                    nonce: [0; 16],
                }))
            },
            Some([7; 16]),
        );
        let ResolvedAccept::Fresh(accepted) = accepted else {
            panic!()
        };
        assert_eq!(accepted.out[0].bytes.len(), if aware { 100 } else { 80 });
        client.on_datagram(now, source, &accepted.out[0].bytes);
        assert_eq!(
            client.server_generation(),
            if aware { Some([7; 16]) } else { None }
        );
    }
}

#[test]
fn bootstrap_aware_client_accepts_legacy_server_without_generation() {
    use crate::{AuthPolicy, Connection, ConnectionConfig, Features, Role, StartKind};
    let server = generate_keypair();
    let local = generate_keypair();
    let now = Instant::now();
    let address = "192.0.2.1:5000".parse().unwrap();
    let mut client = Connection::new(ConnectionConfig {
        role: Role::Client,
        local_static_priv: local.private,
        remote_static_pub: Some(server.public),
        auth: AuthPolicy::Allowlist(vec![]),
        features: Features::NONE,
        required_features: Features::NONE,
    });
    let request = client.start_session(now, address, StartKind::Cold, [3; 16]);
    let wire::Frame::Handshake { body, .. } = wire::parse(&request[0].bytes).unwrap() else {
        panic!()
    };
    let mut hs = Handshake::new_responder(&server.private);
    let payload = hs.read_msg(body).unwrap();
    assert_eq!(&payload[23..], b"QGEN\0");
    // The released v2 parser reads its fixed 23-byte prefix and ignores future tails.
    assert_eq!(payload[0], 2);
    assert_eq!(payload[1], 0);
    assert_eq!(&payload[2..18], &[3; 16]);
    assert_eq!(&payload[18..23], &[0; 5]);
    let response = wire::encode_handshake(
        wire::Kind::HandshakeResp,
        &hs.write_msg(&[vec![2], 7u64.to_be_bytes().to_vec(), vec![0; 21]].concat()),
    );
    assert_eq!(response.len(), 80);
    client.on_datagram(now, address, &response);
    assert_eq!(client.state(), crate::LinkState::Live);
    assert_eq!(client.server_generation(), None);
}

#[test]
fn bootstrap_version_text_is_bounded_printable_ascii_without_requiring_semver() {
    for text in ["", "x\n", "x\x1b[31m", "x\u{0085}", "vérsion"] {
        let mut value = info();
        value.core_version = text.into();
        assert!(
            encode_server_info(&value).is_err(),
            "unsafe version text must not be encoded"
        );
        let mut encoded = value.generation.to_vec();
        encoded.push(text.len() as u8);
        encoded.extend_from_slice(text.as_bytes());
        encoded.push(0);
        assert!(
            decode_server_info(&encoded).is_err(),
            "unsafe version text must not be decoded"
        );
    }
    let mut value = info();
    value.core_version = "unknown".into();
    assert_eq!(
        decode_server_info(&encode_server_info(&value).unwrap()).unwrap(),
        value
    );
}
