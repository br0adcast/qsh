//! The authenticated session reset (#529, `crate::session_reset`): a
//! frontend that does not route a connection says so at once, with a token
//! only the daemon's host secret can make, and only to a client that
//! negotiated it. Runs on the takeover rig of the parent module: a host that
//! keeps every session's owner across frontend "processes".

use super::*;
use crate::session_reset::{
    ResetResponder, SessionResetSecret, RESET_BURST, RESET_SESSION_BIT, RESET_SOURCE_BURST,
};
use crate::wire::{encode_session_reset, parse_session_reset, transport_header, SESSION_RESET_LEN};

/// The secret a test host keeps, as a daemon keeps it beside its key.
fn secret(byte: u8) -> SessionResetSecret {
    SessionResetSecret::from_bytes([byte; 32])
}

/// [`handshake_to_live`], for a client that offers `offered`.
async fn handshake_offering(
    server_addr: SocketAddr,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
    start_kind: StartKind,
    offered: crate::Features,
) -> (Connection, UdpSocket) {
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = Connection::new(ConnectionConfig {
        required_features: crate::Features::NONE,
        features: offered,
        role: Role::Client,
        local_static_priv: client_priv,
        remote_static_pub: Some(server_pub),
        auth: AuthPolicy::Allowlist(Vec::new()),
    });
    let payload = encode_msg1(&Msg1Payload {
        offered,
        start_kind,
        token,
        method: AuthMethod::Allowlist,
    });
    let m1 = client.start_with_payload(Instant::now(), server_addr, &payload);
    send_client(&client_sock, &m1).await;
    let mut buf = vec![0u8; RECV_BUF_LEN];
    let (len, src) = client_sock.recv_from(&mut buf).await.unwrap();
    let out = client.on_datagram(Instant::now(), src, &buf[..len]);
    send_client(&client_sock, &out).await;
    client.request_ping(Instant::now());
    send_client(&client_sock, &client.on_timeout(Instant::now())).await;
    (client, client_sock)
}

/// The next datagram `sock` receives within `within`, if any.
async fn next_datagram(sock: &UdpSocket, within: Duration) -> Option<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; RECV_BUF_LEN];
    match tokio::time::timeout(within, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, src))) => Some((buf[..len].to_vec(), src)),
        _ => None,
    }
}

/// `client` sends one byte on stream 0 to `to` (its server's new address,
/// as a frontend that took its predecessor's socket would be) and the
/// datagrams it sent come back, for their sizes.
async fn send_to_server(
    client: &mut Connection,
    sock: &UdpSocket,
    to: SocketAddr,
    byte: u8,
) -> Vec<Vec<u8>> {
    let mut sent = Vec::new();
    for dg in client.send(Instant::now(), 0, &[byte]) {
        sock.send_to(&dg.bytes, to).await.unwrap();
        sent.push(dg.bytes);
    }
    sent
}

/// The session id and token of a `SessionReset` datagram, or `None` for
/// anything else.
fn as_reset(bytes: &[u8]) -> Option<(u64, [u8; 16])> {
    match parse(bytes) {
        Ok(crate::wire::Frame::Handshake {
            kind: Kind::SessionReset,
            body,
        }) => parse_session_reset(body),
        _ => None,
    }
}

/// Whether `client` read its last datagram as the end of its connection:
/// closed without a `Close` (so a warm return follows), and said why.
fn was_reset(client: &mut Connection) -> bool {
    let events = client.poll_events();
    client.state() == LinkState::Closed
        && !client.closed_gracefully()
        && events.contains(&Event::SessionReset)
}

/// The frontend process goes away; the session's owner does not. The
/// client's next datagram reaches a frontend that never heard of its
/// connection, which answers with a reset no larger than that datagram;
/// the client abandons the connection on it and returns warm -- into the
/// same backend, well within a second of its datagram instead of after its
/// 45 s death timer.
#[tokio::test]
async fn reset_reattaches_new_client_within_one_second() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(1));
        let token = [31u8; 16];

        let (addr, shutdown, task) = takeover_frontend(&host, &server, &allowlist).await;
        let (mut c1, s1) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Cold).await;
        assert!(c1.features().contains(crate::Features::SESSION_RESET));
        assert_ne!(c1.session_id() & RESET_SESSION_BIT, 0);
        assert_eq!(
            c1.session_reset_token(),
            Some(secret(1).token(c1.session_id()))
        );
        assert_eq!(echo_one(&mut c1, &s1, 0xA1).await, vec![0xA1]);

        shutdown.request();
        task.await.unwrap();
        as_the_host_keeps(&allowlist, client.public);
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;

        let started = Instant::now();
        let sent = send_to_server(&mut c1, &s1, addr, 0xA2).await;
        let (reply, from) = next_datagram(&s1, Duration::from_secs(1))
            .await
            .expect("the new frontend answers the connection it does not know");
        assert_eq!(from, addr);
        assert_eq!(
            as_reset(&reply),
            Some((c1.session_id(), secret(1).token(c1.session_id())))
        );
        assert_eq!(reply.len(), SESSION_RESET_LEN);
        assert!(
            sent.iter().all(|dg| reply.len() <= dg.len()),
            "never larger"
        );
        c1.on_datagram(Instant::now(), from, &reply);
        assert!(
            was_reset(&mut c1),
            "the client lets the connection go at once"
        );

        let (mut c2, s2) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Warm).await;
        assert_eq!(echo_one(&mut c2, &s2, 0xA3).await, vec![0xA3]);
        let back = started.elapsed();
        assert!(c2.resumed());
        assert!(back < Duration::from_secs(1), "back in {back:?}");
        assert_eq!(
            takeover_events(&events, 2).await,
            ["start", "reset"],
            "the same backend hears ResumeReset on the new connection"
        );
    })
    .await
    .expect("timed out");
}

/// A reset the secret did not make is nothing to a client: one with a wrong
/// token, one made under another secret, one cut short, one too long. Its
/// connection stays live, it says nothing, and it echoes as before.
#[tokio::test]
async fn forged_reset_is_ignored() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(2));
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;
        let (mut c1, s1) = handshake_to_live(
            addr,
            server.public,
            client.private,
            [32; 16],
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xB1).await, vec![0xB1]);
        let _ = c1.poll_events();

        let id = c1.session_id();
        let genuine = encode_session_reset(id, &secret(2).token(id));
        let mut flipped = secret(2).token(id);
        flipped[15] ^= 1;
        let forgeries = [
            encode_session_reset(id, &[0; 16]),
            encode_session_reset(id, &flipped),
            encode_session_reset(id, &secret(3).token(id)),
            genuine[..SESSION_RESET_LEN - 1].to_vec(),
            [genuine.as_slice(), &[0]].concat(),
        ];
        for forged in &forgeries {
            assert!(c1.on_datagram(Instant::now(), addr, forged).is_empty());
            assert_eq!(c1.state(), LinkState::Live, "{forged:02x?}");
            assert!(c1.poll_events().is_empty(), "silent: {forged:02x?}");
        }
        assert_eq!(echo_one(&mut c1, &s1, 0xB2).await, vec![0xB2]);
        // The genuine one, for contrast; and once only: a repeat finds the
        // connection closed and says nothing.
        c1.on_datagram(Instant::now(), addr, &genuine);
        assert!(was_reset(&mut c1));
        c1.on_datagram(Instant::now(), addr, &genuine);
        assert!(c1.poll_events().is_empty(), "SessionReset is reported once");
    })
    .await
    .expect("timed out");
}

/// A genuine reset for one connection is nothing to another: neither with
/// the other's session id nor with its token, nor with its own token under
/// the other's id. Only the client it names
/// lets its connection go.
#[tokio::test]
async fn reset_for_other_session_is_ignored() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(4));
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;
        let (mut c1, s1) = handshake_to_live(
            addr,
            server.public,
            client.private,
            [33; 16],
            StartKind::Cold,
        )
        .await;
        let (mut c2, s2) = handshake_to_live(
            addr,
            server.public,
            client.private,
            [34; 16],
            StartKind::Cold,
        )
        .await;
        assert_eq!(echo_one(&mut c1, &s1, 0xC1).await, vec![0xC1]);
        assert_eq!(echo_one(&mut c2, &s2, 0xC2).await, vec![0xC2]);
        let _ = (c1.poll_events(), c2.poll_events());
        let (one, two) = (c1.session_id(), c2.session_id());
        assert_ne!(one, two);

        for other in [
            encode_session_reset(two, &secret(4).token(two)),
            encode_session_reset(one, &secret(4).token(two)),
            // Its own token, under another connection's id.
            encode_session_reset(two, &secret(4).token(one)),
        ] {
            c1.on_datagram(Instant::now(), addr, &other);
            assert_eq!(c1.state(), LinkState::Live);
            assert!(c1.poll_events().is_empty());
        }
        assert_eq!(echo_one(&mut c1, &s1, 0xC3).await, vec![0xC3]);

        c2.on_datagram(
            Instant::now(),
            addr,
            &encode_session_reset(two, &secret(4).token(two)),
        );
        assert!(was_reset(&mut c2), "the session it names");
        assert_eq!(c1.state(), LinkState::Live);
        assert_eq!(echo_one(&mut c1, &s1, 0xC4).await, vec![0xC4]);
    })
    .await
    .expect("timed out");
}

/// A client built before the session reset does not offer it: its msg2
/// carries no token, a frontend that does not know its connection says
/// nothing to it, and a genuine reset would not move it either. It comes
/// back as before, once its own death timer ends the connection -- into the
/// same session.
#[tokio::test]
async fn old_client_without_feature_never_gets_reset_and_reattaches_after_death_timer() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(5));
        let token = [35u8; 16];

        let (addr, shutdown, task) = takeover_frontend(&host, &server, &allowlist).await;
        let (mut c1, s1) = handshake_offering(
            addr,
            server.public,
            client.private,
            token,
            StartKind::Cold,
            crate::Features::SUPPORTED_WITHOUT_RESET,
        )
        .await;
        assert!(!c1.features().contains(crate::Features::SESSION_RESET));
        assert_eq!(c1.session_id() & RESET_SESSION_BIT, 0);
        assert_eq!(c1.session_reset_token(), None, "no token in its msg2");
        assert_eq!(echo_one(&mut c1, &s1, 0xD1).await, vec![0xD1]);

        shutdown.request();
        task.await.unwrap();
        as_the_host_keeps(&allowlist, client.public);
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;

        for byte in [0xD2, 0xD3, 0xD4] {
            send_to_server(&mut c1, &s1, addr, byte).await;
            assert!(
                next_datagram(&s1, Duration::from_millis(300))
                    .await
                    .is_none(),
                "nothing answers a connection that did not negotiate the reset"
            );
        }
        let id = c1.session_id();
        c1.on_datagram(
            Instant::now(),
            addr,
            &encode_session_reset(id, &secret(5).token(id)),
        );
        assert_ne!(c1.state(), LinkState::Closed, "a reset it never asked for");
        let _ = c1.poll_events();

        // Its death timer, shortened here from 45 s.
        c1.set_death_after(Duration::from_millis(200));
        tokio::time::sleep(Duration::from_millis(250)).await;
        c1.on_timeout(Instant::now());
        assert_eq!(c1.state(), LinkState::Closed);
        assert!(!c1.closed_gracefully());
        assert!(!c1.poll_events().contains(&Event::SessionReset));

        let (mut c2, s2) = handshake_offering(
            addr,
            server.public,
            client.private,
            token,
            StartKind::Warm,
            crate::Features::SUPPORTED_WITHOUT_RESET,
        )
        .await;
        assert_eq!(echo_one(&mut c2, &s2, 0xD5).await, vec![0xD5]);
        assert!(c2.resumed());
        assert_eq!(takeover_events(&events, 2).await, ["start", "reset"]);
    })
    .await
    .expect("timed out");
}

/// A frontend answers only what could be a connection's datagram, never
/// with more bytes than it got, and not every time: a source is held to a
/// short burst. A datagram shorter than a reset, a reset itself and the
/// handshake kinds get no reset at all.
#[tokio::test]
async fn reset_reply_is_rate_limited_and_not_amplifying() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(6));
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // An id the router minted for a connection that negotiated the reset.
        let marked = |n: u64| RESET_SESSION_BIT | n;
        let transport = |id: u64, len: usize| {
            let mut bytes = transport_header(id, 1).to_vec();
            bytes.resize(len, 0);
            bytes
        };

        // Shorter than the reset it would get: no answer, and no charge.
        probe
            .send_to(&transport(marked(7), SESSION_RESET_LEN - 1), addr)
            .await
            .unwrap();
        assert!(next_datagram(&probe, Duration::from_millis(300))
            .await
            .is_none());
        // Not a connection's datagram: no answer.
        for other in [
            encode_session_reset(marked(7), &secret(6).token(marked(7))),
            encode_handshake(Kind::HandshakeResp, &[0; 64]),
            encode_handshake(Kind::CookieReply, &[0; 64]),
        ] {
            probe.send_to(&other, addr).await.unwrap();
            assert!(next_datagram(&probe, Duration::from_millis(200))
                .await
                .is_none());
        }
        // A connection that never negotiated the reset: no answer.
        probe.send_to(&transport(7, 64), addr).await.unwrap();
        assert!(next_datagram(&probe, Duration::from_millis(300))
            .await
            .is_none());
        // Exactly as large: the reset for that id.
        probe
            .send_to(&transport(marked(7), SESSION_RESET_LEN), addr)
            .await
            .unwrap();
        let (reply, _) = next_datagram(&probe, Duration::from_secs(1))
            .await
            .expect("answered");
        assert_eq!(reply.len(), SESSION_RESET_LEN);
        assert_eq!(
            as_reset(&reply),
            Some((marked(7), secret(6).token(marked(7))))
        );

        // A flood from one source gets its burst and no more.
        let flood = 4 * RESET_SOURCE_BURST as usize;
        for id in 0..flood as u64 {
            probe
                .send_to(&transport(marked(1000 + id), 64), addr)
                .await
                .unwrap();
        }
        let mut answered = 0;
        while let Some((reply, _)) = next_datagram(&probe, Duration::from_millis(300)).await {
            assert!(reply.len() <= 64);
            assert!(as_reset(&reply).is_some());
            answered += 1;
        }
        assert!(
            answered >= 1 && answered < 2 * RESET_SOURCE_BURST as usize,
            "{answered} of {flood} answered"
        );
    })
    .await
    .expect("timed out");
}

/// The reset budget, off the network: a source gets its burst, then what
/// its rate earns back; every source together gets the global burst, then
/// what the global rate earns back. The state is bounded either way.
#[test]
fn session_reset_budget_is_bounded_per_source_and_in_all() {
    let t0 = Instant::now();
    let mut responder = ResetResponder::new(secret(7), t0);
    let one: SocketAddr = "198.51.100.1:40000".parse().unwrap();
    let answered = (0..3 * RESET_SOURCE_BURST as u64)
        .filter(|id| {
            responder
                .answer(t0, one, 64, RESET_SESSION_BIT | *id)
                .is_some()
        })
        .count();
    assert_eq!(answered, RESET_SOURCE_BURST as usize, "one source's burst");
    assert!(responder
        .answer(t0, one, 64, RESET_SESSION_BIT | 1)
        .is_none());
    assert!(
        responder
            .answer(t0 + Duration::from_secs(1), one, 64, RESET_SESSION_BIT | 1)
            .is_some(),
        "earned back"
    );
    assert!(responder
        .answer(
            t0 + Duration::from_secs(2),
            one,
            SESSION_RESET_LEN - 1,
            RESET_SESSION_BIT
        )
        .is_none());

    let mut responder = ResetResponder::new(secret(7), t0);
    let answered = (0..2 * RESET_BURST)
        .filter(|i| {
            let from = SocketAddr::from((std::net::Ipv4Addr::from(0x0A00_0000 + i), 40_000));
            responder
                .answer(t0, from, 64, RESET_SESSION_BIT | u64::from(*i))
                .is_some()
        })
        .count();
    assert_eq!(answered, RESET_BURST as usize, "the global burst");
    let fresh: SocketAddr = "203.0.113.9:40000".parse().unwrap();
    assert!(
        responder
            .answer(t0, fresh, 64, RESET_SESSION_BIT | 1)
            .is_none(),
        "spent for everyone"
    );
    let reply = responder
        .answer(
            t0 + Duration::from_secs(1),
            fresh,
            64,
            RESET_SESSION_BIT | 9,
        )
        .expect("earned back");
    assert!(
        responder
            .answer(t0 + Duration::from_secs(2), fresh, 64, 9)
            .is_none(),
        "never for an id that did not negotiate it"
    );
    assert_eq!(
        reply,
        encode_session_reset(
            RESET_SESSION_BIT | 9,
            &secret(7).token(RESET_SESSION_BIT | 9)
        )
    );
}

/// The daemon itself restarts, its sessions with it; the secret beside its
/// static key does not change. The new host's frontend tells the client its
/// connection is gone, and the client's warm return hears at once that the
/// session is not kept. A host with a new secret could not have said so.
#[tokio::test]
async fn full_daemon_restart_tells_client_session_is_gone() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let token = [36u8; 16];
        let first = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(8));
        let (addr, shutdown, task) = takeover_frontend(&first, &server, &allowlist).await;
        let (mut c1, s1) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Cold).await;
        assert_eq!(echo_one(&mut c1, &s1, 0xE1).await, vec![0xE1]);
        shutdown.request();
        task.await.unwrap();
        drop(first);
        as_the_host_keeps(&allowlist, client.public);

        // A host that lost the secret: its answer is no reset to this client.
        let forgetful =
            TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(9));
        let (other, stop_other, other_task) =
            takeover_frontend(&forgetful, &server, &allowlist).await;
        send_to_server(&mut c1, &s1, other, 0xE2).await;
        let (reply, from) = next_datagram(&s1, Duration::from_secs(1))
            .await
            .expect("a reset");
        c1.on_datagram(Instant::now(), from, &reply);
        assert_eq!(c1.state(), LinkState::Live, "not this client's token");
        let _ = c1.poll_events();
        stop_other.request();
        other_task.await.unwrap();

        let restarted =
            TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(8));
        let (addr, _shutdown, _task) = takeover_frontend(&restarted, &server, &allowlist).await;
        let started = Instant::now();
        send_to_server(&mut c1, &s1, addr, 0xE3).await;
        let (reply, from) = next_datagram(&s1, Duration::from_secs(1))
            .await
            .expect("a reset");
        c1.on_datagram(Instant::now(), from, &reply);
        assert!(was_reset(&mut c1), "the persisted secret's token");
        let (mut c2, s2) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Warm).await;
        assert!(
            !c2.resumed(),
            "the session is gone, and the client hears so"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(echo_one(&mut c2, &s2, 0xE4).await, vec![0xE4]);
        assert_eq!(takeover_events(&events, 2).await, ["start", "start"]);
    })
    .await
    .expect("timed out");
}

/// A warm return inside a running frontend whose owner link cannot be
/// replaced just now parks the session (Task 6's residual: a client that
/// already holds msg2 then waited out its death timer). Its connection is
/// no longer routed, so the next datagram it sends is answered with a
/// reset, and the client tries again at once.
#[tokio::test]
async fn a_parked_return_is_reset_and_comes_back_at_once() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let server = generate_keypair();
        let client = generate_keypair();
        let allowlist: SharedAllowlist = Arc::new(Mutex::new(vec![client.public]));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = TakeoverHost::with_reset(Arc::new(TakeoverBackend(events.clone())), secret(10));
        let token = [37u8; 16];
        let (addr, _shutdown, _task) = takeover_frontend(&host, &server, &allowlist).await;
        let (mut c1, s1) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Cold).await;
        assert_eq!(echo_one(&mut c1, &s1, 0xF1).await, vec![0xF1]);

        host.relink_unavailable.store(true, Ordering::SeqCst);
        let (mut c2, s2) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Warm).await;
        let mut reset = None;
        for byte in 0..20u8 {
            send_to_server(&mut c2, &s2, addr, byte).await;
            if let Some((reply, from)) = next_datagram(&s2, Duration::from_millis(100)).await {
                if as_reset(&reply).is_some() {
                    reset = Some((reply, from));
                    break;
                }
                c2.on_datagram(Instant::now(), from, &reply);
            }
        }
        let (reply, from) = reset.expect("the parked connection is reset");
        c2.on_datagram(Instant::now(), from, &reply);
        assert!(was_reset(&mut c2));
        assert_eq!(takeover_events(&events, 1).await, ["start"], "not ended");

        allowlist.lock().unwrap().push(client.public);
        host.relink_unavailable.store(false, Ordering::SeqCst);
        let (mut c3, s3) =
            handshake_to_live(addr, server.public, client.private, token, StartKind::Warm).await;
        assert_eq!(echo_one(&mut c3, &s3, 0xF2).await, vec![0xF2]);
        assert_eq!(takeover_events(&events, 2).await, ["start", "reset"]);
    })
    .await
    .expect("timed out");
}
