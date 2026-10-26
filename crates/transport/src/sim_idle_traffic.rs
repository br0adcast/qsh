//! What an idle session sends, classified by frame type, road and what made
//! each datagram go (`docs/protocol.md` §5.3): the attributable counts
//! behind any change to keepalive packing or cadence. Every datagram is
//! decrypted as its addressee would read it, so nothing here is inferred
//! from sizes.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::conn::Event;
use crate::reliability::StreamFrame;
use crate::testnet::{LinkSpec, RoadSpec, SendOrigin, SentDatagram, Side, Sim};

/// What one datagram was for. A road check and its answer are never packed
/// with anything else (protocol §1.4), so they are classes of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    /// A liveness PING alone.
    Ping,
    /// The answer to the peer's PING alone.
    Pong,
    /// A PING and a PONG in one datagram.
    PingPong,
    /// Nothing but ACK and CREDIT frames.
    Service,
    RoadCheck,
    RoadCheckAnswer,
    /// DATA, every segment in it sent for the first time.
    Data,
    /// DATA with at least one segment this side sent before.
    DataResend,
    Other,
}

type Key = (Side, SendOrigin, Option<usize>, Class);

fn classify(sim: &Sim) -> BTreeMap<Key, u64> {
    let mut counts = BTreeMap::new();
    for side in [Side::Client, Side::Server] {
        let mut segments = BTreeSet::new();
        for dg in sim.sent(side) {
            let class = class_of(dg, &mut segments);
            *counts.entry((side, dg.origin, dg.road, class)).or_default() += 1;
        }
    }
    counts
}

fn class_of(dg: &SentDatagram, segments: &mut BTreeSet<(u8, u32)>) -> Class {
    let has = |pick: fn(&StreamFrame) -> bool| dg.frames.iter().any(pick);
    if has(|f| matches!(f, StreamFrame::Data { .. })) {
        let mut resent = false;
        for f in &dg.frames {
            if let StreamFrame::Data {
                stream_id, offset, ..
            } = f
            {
                resent |= !segments.insert((*stream_id, *offset));
            }
        }
        return if resent {
            Class::DataResend
        } else {
            Class::Data
        };
    }
    let only = |pick: fn(&StreamFrame) -> bool| !dg.frames.is_empty() && dg.frames.iter().all(pick);
    if only(|f| matches!(f, StreamFrame::PathProbe { .. })) {
        Class::RoadCheck
    } else if only(|f| matches!(f, StreamFrame::PathProbeAck { .. })) {
        Class::RoadCheckAnswer
    } else if only(|f| matches!(f, StreamFrame::Ack { .. } | StreamFrame::Credit { .. })) {
        Class::Service
    } else if has(|f| matches!(f, StreamFrame::Ping { .. }))
        && has(|f| matches!(f, StreamFrame::Pong { .. }))
    {
        Class::PingPong
    } else if only(|f| matches!(f, StreamFrame::Ping { .. })) {
        Class::Ping
    } else if only(|f| matches!(f, StreamFrame::Pong { .. })) {
        Class::Pong
    } else {
        Class::Other
    }
}

fn carries(dg: &SentDatagram, pick: fn(&StreamFrame) -> bool) -> bool {
    dg.frames.iter().any(pick)
}

fn is_ping(f: &StreamFrame) -> bool {
    matches!(f, StreamFrame::Ping { .. })
}

fn is_pong(f: &StreamFrame) -> bool {
    matches!(f, StreamFrame::Pong { .. })
}

/// For every PING `side` sent, how far it was from the nearest PONG it sent.
fn ping_to_nearest_pong(sim: &Sim, side: Side) -> Vec<Duration> {
    let sent = sim.sent(side);
    let pongs: Vec<Duration> = sent
        .iter()
        .filter(|dg| carries(dg, is_pong))
        .map(|dg| dg.at)
        .collect();
    sent.iter()
        .filter(|dg| carries(dg, is_ping))
        .map(|dg| {
            pongs
                .iter()
                .map(|&at| at.abs_diff(dg.at))
                .min()
                .unwrap_or(Duration::MAX)
        })
        .collect()
}

/// Live, settled for 5 s, then recording.
fn idle(seed: u64, roads: Vec<RoadSpec>) -> Sim {
    let count = roads.len();
    let mut sim = Sim::new(seed, roads);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    if count > 1 {
        let paths = (0..count).map(|i| sim.road(i).1).collect();
        sim.conn_mut(Side::Client).set_paths(paths);
    }
    sim.run_for(Duration::from_secs(5));
    sim.record_sends();
    sim
}

fn twenty_ms() -> RoadSpec {
    RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)))
}

/// Protocol §5.3: on one road an idle session sends nothing but the two
/// liveness exchanges. Each side PINGs on its own clock every
/// `PING_INTERVAL` (1.5 s) and answers the other's PING with a PONG: four
/// 39-byte datagrams per interval, two each way, each frame in a datagram
/// of its own. No ACK, CREDIT or road check goes out.
#[test]
fn an_idle_session_on_one_road_sends_only_the_two_ping_exchanges() {
    let mut sim = idle(1, vec![twenty_ms()]);
    sim.run_for(Duration::from_secs(600));
    let expected: BTreeMap<Key, u64> = [
        ((Side::Client, SendOrigin::Timer, Some(0), Class::Ping), 400),
        (
            (Side::Client, SendOrigin::Received, Some(0), Class::Pong),
            400,
        ),
        ((Side::Server, SendOrigin::Timer, Some(0), Class::Ping), 400),
        (
            (Side::Server, SendOrigin::Received, Some(0), Class::Pong),
            400,
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(classify(&sim), expected);
    for side in [Side::Client, Side::Server] {
        assert!(sim.sent(side).iter().all(|dg| dg.len == 39), "{side:?}");
    }
}

/// Protocol §5.3, the packing gap the idle counts show. Both PING clocks start
/// at the handshake, and the server's starts one one-way delay earlier --
/// when it sent msg2 -- so its PING reaches the client exactly when the
/// client's own is due. The client then sends its PONG and its PING at one
/// instant, in two datagrams: the PONG while handling the datagram, the
/// PING from the timer service right after. The server's PING and its PONG
/// stay a round trip apart here, so only the client's pair is close enough
/// to pack without deferring anything. With delay variation, in the traces
/// below, the client's two fall within twice that variation of each other,
/// never at one instant.
#[test]
fn the_client_answers_and_pings_at_one_instant_in_two_datagrams() {
    let mut sim = idle(1, vec![twenty_ms()]);
    sim.run_for(Duration::from_secs(600));
    let client = ping_to_nearest_pong(&sim, Side::Client);
    assert_eq!(client.len(), 400);
    assert!(client.iter().all(|gap| gap.is_zero()), "{client:?}");
    assert!(sim
        .sent(Side::Client)
        .iter()
        .all(|dg| !(carries(dg, is_ping) && carries(dg, is_pong))));
    let server = ping_to_nearest_pong(&sim, Side::Server);
    assert!(
        server.iter().all(|&gap| gap == Duration::from_millis(40)),
        "{server:?}"
    );

    // Seed 7, one hour each: these traces, not every road. Delay variation
    // separates the two deadlines, so packing only what is already due
    // finds no pair here.
    for jitter in [Duration::from_millis(1), Duration::from_millis(5)] {
        let road =
            RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)).with_jitter(jitter));
        let mut sim = idle(7, vec![road]);
        sim.run_for(Duration::from_secs(3600));
        let client = ping_to_nearest_pong(&sim, Side::Client);
        assert_eq!(client.len(), 2400, "{jitter:?}");
        assert!(
            client
                .iter()
                .all(|&gap| !gap.is_zero() && gap <= 2 * jitter),
            "{jitter:?}: {client:?}"
        );
        let server = ping_to_nearest_pong(&sim, Side::Server);
        assert!(
            server
                .iter()
                .all(|&gap| gap >= Duration::from_millis(40) - 2 * jitter),
            "{jitter:?}: {server:?}"
        );
    }
}

/// Protocol §5.3 and §6: with a spare road, checks go out on every road every
/// `PROBE_IDLE` (30 s) from the client's timer, each alone, and are answered
/// over the road they came on, each answer alone. The liveness exchanges
/// stay on the road in use; nothing else is added.
#[test]
fn idle_road_checks_travel_alone_on_their_own_schedule() {
    let mut sim = idle(1, vec![twenty_ms(), twenty_ms()]);
    sim.run_for(Duration::from_secs(120));
    let expected: BTreeMap<Key, u64> = [
        ((Side::Client, SendOrigin::Timer, Some(0), Class::Ping), 80),
        (
            (Side::Client, SendOrigin::Timer, Some(0), Class::RoadCheck),
            4,
        ),
        (
            (Side::Client, SendOrigin::Timer, Some(1), Class::RoadCheck),
            4,
        ),
        (
            (Side::Client, SendOrigin::Received, Some(0), Class::Pong),
            80,
        ),
        ((Side::Server, SendOrigin::Timer, Some(0), Class::Ping), 80),
        (
            (Side::Server, SendOrigin::Received, Some(0), Class::Pong),
            80,
        ),
        (
            (
                Side::Server,
                SendOrigin::Received,
                Some(0),
                Class::RoadCheckAnswer,
            ),
            4,
        ),
        (
            (
                Side::Server,
                SendOrigin::Received,
                Some(1),
                Class::RoadCheckAnswer,
            ),
            4,
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(classify(&sim), expected);
    for road in [0, 1] {
        let checks: Vec<Duration> = sim
            .sent(Side::Client)
            .iter()
            .filter(|dg| dg.road == Some(road) && dg.frames.iter().any(StreamFrame::is_probe))
            .map(|dg| dg.at)
            .collect();
        assert!(
            checks
                .windows(2)
                .all(|w| w[1] - w[0] == Duration::from_secs(30)),
            "road {road}: {checks:?}"
        );
    }
    for side in [Side::Client, Side::Server] {
        assert_eq!(sim.frames_sent(side).probe_mixed, 0, "{side:?}");
    }
}

/// Protocol §5.3, §6 and §7: when the road in use dies with data in flight, the
/// classes separate. The server's retransmit timer resends DATA down the
/// dead road; the client's unanswered PINGs make its checks urgent; once
/// the spare is verified and the road in use counts as down, the client
/// moves and forces a PING down the spare ahead of its schedule; the server
/// follows that packet and resends its whole flight there in answer.
/// Afterwards the client's PING clock is anchored to the forced PING, so
/// its PINGs and its PONGs no longer coincide.
#[test]
fn a_dying_road_separates_retransmission_road_checks_and_the_move() {
    let mut sim = idle(1, vec![twenty_ms(), twenty_ms()]);
    let start = sim.now();
    sim.send(Side::Server, 20, &vec![b'o'; 4000]);
    sim.run_for(Duration::from_millis(5));
    for from in [Side::Client, Side::Server] {
        sim.set_link(
            0,
            from,
            LinkSpec::new(Duration::from_millis(20)).with_loss(1.0),
        );
    }
    sim.run_for(Duration::from_secs(15));
    let counts = classify(&sim);
    let count = |key: Key| counts.get(&key).copied().unwrap_or(0);

    assert_eq!(
        count((Side::Server, SendOrigin::Action, Some(0), Class::Data)),
        4
    );
    assert!(count((Side::Server, SendOrigin::Timer, Some(0), Class::DataResend)) > 0);
    assert_eq!(
        count((
            Side::Server,
            SendOrigin::Received,
            Some(1),
            Class::DataResend
        )),
        4
    );
    assert_eq!(
        count((Side::Server, SendOrigin::Timer, Some(1), Class::DataResend)),
        0
    );
    for road in [0, 1] {
        assert!(
            count((
                Side::Client,
                SendOrigin::Timer,
                Some(road),
                Class::RoadCheck
            )) > 0
        );
    }
    assert_eq!(
        count((
            Side::Server,
            SendOrigin::Received,
            Some(1),
            Class::RoadCheckAnswer
        )),
        count((Side::Client, SendOrigin::Timer, Some(1), Class::RoadCheck))
    );
    assert!(sim.log().iter().any(|(at, side, event)| *at >= start
        && *side == Side::Server
        && matches!(event, Event::Rehomed { .. })));

    let first_on_spare = sim
        .sent(Side::Client)
        .iter()
        .find(|dg| dg.road == Some(1) && carries(dg, is_ping))
        .expect("a PING down the spare");
    let last_on_dead = sim
        .sent(Side::Client)
        .iter()
        .rev()
        .find(|dg| dg.road == Some(0) && carries(dg, is_ping))
        .expect("PINGs down the road in use");
    assert!(
        first_on_spare.at - last_on_dead.at < Duration::from_millis(1500),
        "forced ahead of the schedule: {:?} after {:?}",
        first_on_spare.at,
        last_on_dead.at
    );
    let moved = first_on_spare.at;
    let after: Vec<&SentDatagram> = sim
        .sent(Side::Client)
        .iter()
        .filter(|dg| dg.at > moved)
        .collect();
    assert!(after.iter().all(|dg| dg.road == Some(1)));
    let pongs: Vec<Duration> = after
        .iter()
        .filter(|dg| carries(dg, is_pong))
        .map(|dg| dg.at)
        .collect();
    assert!(!pongs.is_empty());
    assert!(after
        .iter()
        .filter(|dg| carries(dg, is_ping))
        .all(|dg| pongs
            .iter()
            .all(|&at| at.abs_diff(dg.at) >= Duration::from_millis(100))));
    for side in [Side::Client, Side::Server] {
        assert_eq!(sim.frames_sent(side).probe_mixed, 0, "{side:?}");
    }
}
