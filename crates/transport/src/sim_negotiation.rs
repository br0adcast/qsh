//! Spec §9.3 (1): the in-process mixed-version runs. A side that plays a
//! build from before negotiation (`Sim::play_legacy`) writes msg1 or msg2
//! without its features field; the other side must fall back to the old
//! mode on its own, and everything the transport carries must still arrive
//! -- a keystroke and its echo, 8 MiB each way, the repaint after a long
//! absence, a session with two roads.

use std::time::Duration;

use crate::conn::Event;
use crate::features::Features;
use crate::paths::PathState;
use crate::reliability::{CHUNK_COST, LEGACY_RECEIVE_WINDOW, MAX_SEGMENT_SIZE, STREAM_WINDOW};
use crate::testnet::{LinkSpec, RoadSpec, Side, Sim};
use crate::wire::{parse, Frame};

#[derive(Clone, Copy, Debug)]
enum Pair {
    BothNew,
    OldServer,
    OldClient,
}

impl Pair {
    const ALL: [Pair; 3] = [Pair::BothNew, Pair::OldServer, Pair::OldClient];

    fn agreed(self) -> Features {
        match self {
            Pair::BothNew => Features::SUPPORTED,
            Pair::OldServer | Pair::OldClient => Features::NONE,
        }
    }
}

fn road() -> RoadSpec {
    RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)).with_loss(0.005))
}

/// A pair on `roads`, the old side set up, driven to `Live`.
fn live(pair: Pair, seed: u64, roads: Vec<RoadSpec>) -> Sim {
    let mut sim = Sim::new(seed, roads);
    match pair {
        Pair::BothNew => {}
        Pair::OldServer => sim.play_legacy(Side::Server),
        Pair::OldClient => sim.play_legacy(Side::Client),
    }
    sim.start();
    assert!(
        sim.run_until_live(Duration::from_secs(5)),
        "{pair:?}: the handshake completes"
    );
    sim
}

fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// Run until `side` has `want` bytes of `stream`, or `limit` of virtual
/// time passes.
fn run_until_delivered(sim: &mut Sim, side: Side, stream: u8, want: usize, limit: Duration) {
    let end = sim.now() + limit;
    while sim.delivered_len(side, stream) < want && sim.now() < end {
        sim.run_for(Duration::from_millis(500));
    }
}

#[test]
fn each_pair_agrees_on_what_both_sides_can_do() {
    for pair in Pair::ALL {
        let sim = live(pair, 1, vec![road()]);
        let header = Some(pair.agreed().contains(Features::HEADER_AAD));
        for side in [Side::Client, Side::Server] {
            assert_eq!(
                sim.conn(side).features(),
                pair.agreed(),
                "{pair:?}, {side:?}"
            );
            assert_eq!(
                sim.conn(side).keys_use_header_for_test(),
                header,
                "{pair:?}, {side:?}"
            );
        }
    }
}

/// An old client sends the msg1 of its build: the 19-byte payload, no
/// features field -- not a 23-byte one that offers nothing, which the
/// agreement alone could not tell from it.
#[test]
fn an_old_client_sends_the_19_byte_msg1() {
    for (pair, payload) in [(Pair::BothNew, 23), (Pair::OldClient, 19)] {
        let sim = live(pair, 6, vec![road()]);
        // IK's msg1: the initiator's ephemeral key, its sealed static key
        // and the sealed payload.
        match parse(sim.msg1().expect("msg1 went out")) {
            Ok(Frame::Handshake { body, .. }) => {
                assert_eq!(body.len(), 32 + (32 + 16) + (payload + 16), "{pair:?}")
            }
            other => panic!("{pair:?}: msg1 is a handshake frame: {other:?}"),
        }
    }
}

#[test]
#[should_panic(expected = "play_legacy goes before start")]
fn playing_an_old_build_once_the_handshake_began_is_refused() {
    let mut sim = Sim::new(7, vec![road()]);
    sim.start();
    sim.play_legacy(Side::Client);
}

#[test]
fn each_pair_carries_a_keystroke_and_its_echo() {
    for pair in Pair::ALL {
        let mut sim = live(pair, 2, vec![road()]);
        sim.send(Side::Client, 16, b"k");
        run_until_delivered(&mut sim, Side::Server, 16, 1, Duration::from_secs(5));
        assert_eq!(sim.delivered(Side::Server, 16), b"k", "{pair:?}");
        sim.send(Side::Server, 16, b"k");
        run_until_delivered(&mut sim, Side::Client, 16, 1, Duration::from_secs(5));
        assert_eq!(sim.delivered(Side::Client, 16), b"k", "{pair:?}");
    }
}

#[test]
fn each_pair_moves_8_mib_each_way_intact() {
    const SIZE: usize = 8 << 20;
    for pair in Pair::ALL {
        let mut sim = live(pair, 3, vec![road()]);
        let up = pattern(SIZE, 1);
        let down = pattern(SIZE, 2);
        for chunk in up.chunks(256 << 10) {
            sim.send(Side::Client, 20, chunk);
        }
        for chunk in down.chunks(256 << 10) {
            sim.send(Side::Server, 20, chunk);
        }
        run_until_delivered(&mut sim, Side::Server, 20, SIZE, Duration::from_secs(600));
        run_until_delivered(&mut sim, Side::Client, 20, SIZE, Duration::from_secs(600));
        assert!(sim.delivered(Side::Server, 20) == &up[..], "{pair:?}: up");
        assert!(
            sim.delivered(Side::Client, 20) == &down[..],
            "{pair:?}: down"
        );
    }
}

/// Spec §9.3 (1) with §4.11 (Review Focus 2): on a clean road a bulk write
/// each way goes through with no resend for every pair -- a side played as
/// an older build acknowledges every DATA at once and sends one frame a
/// datagram, and meets this build's packed datagrams and its ACKs held up
/// to `ACK_DELAY`, ten times under an older sender's shortest timeout.
#[test]
fn each_pair_moves_a_bulk_write_on_a_clean_road_without_a_resend() {
    const SIZE: usize = 2 << 20;
    let clean = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)));
    for pair in Pair::ALL {
        let mut sim = live(pair, 5, vec![clean]);
        sim.record_sends();
        let up = pattern(SIZE, 3);
        let down = pattern(SIZE, 4);
        sim.send(Side::Client, 20, &up);
        sim.send(Side::Server, 20, &down);
        run_until_delivered(&mut sim, Side::Server, 20, SIZE, Duration::from_secs(120));
        run_until_delivered(&mut sim, Side::Client, 20, SIZE, Duration::from_secs(120));
        assert!(sim.delivered(Side::Server, 20) == &up[..], "{pair:?}: up");
        assert!(
            sim.delivered(Side::Client, 20) == &down[..],
            "{pair:?}: down"
        );
        let now = sim.instant();
        for side in [Side::Client, Side::Server] {
            assert_eq!(
                sim.conn(side).stats(now).retransmits,
                0,
                "{pair:?}: {side:?} resent"
            );
        }
        let old = match pair {
            Pair::BothNew => None,
            Pair::OldServer => Some(Side::Server),
            Pair::OldClient => Some(Side::Client),
        };
        match old {
            Some(side) => {
                assert!(
                    sim.sent(side).iter().all(|d| d.frames.len() <= 1),
                    "{pair:?}: an older build sends one frame a datagram"
                );
                let new = if side == Side::Server {
                    Side::Client
                } else {
                    Side::Server
                };
                assert!(
                    sim.frames_sent(side).ack >= sim.frames_sent(new).data_datagrams,
                    "{pair:?}: an older build acknowledges every DATA: {:?} against {:?}",
                    sim.frames_sent(side),
                    sim.frames_sent(new)
                );
            }
            None => assert!(
                sim.sent(Side::Client).iter().any(|d| d.frames.len() > 1),
                "two new ends pack"
            ),
        }
    }
}

#[test]
fn each_pair_repaints_after_a_long_absence() {
    for pair in Pair::ALL {
        let mut sim = live(pair, 4, vec![road()]);
        sim.send(Side::Server, 0, b"first screen");
        sim.run_for(Duration::from_millis(300));
        sim.freeze(Side::Client, Duration::from_secs(12));
        for i in 1..=10u64 {
            let at = sim.now() + Duration::from_secs(i);
            sim.schedule(at, |s| {
                s.send(Side::Server, 0, b"a frame the client never sees")
            });
        }
        sim.run_for(Duration::from_secs(15));
        assert!(
            sim.log()
                .iter()
                .any(|(_, side, ev)| *side == Side::Server && matches!(ev, Event::OutputResync)),
            "{pair:?}: the server resyncs its screen"
        );
        assert!(
            sim.log().iter().any(|(_, side, ev)| *side == Side::Client
                && matches!(ev, Event::StreamReset { stream_id: 0 })),
            "{pair:?}: the client hears the reset"
        );
    }
}

#[test]
fn each_pair_keeps_a_session_with_two_roads() {
    for pair in Pair::ALL {
        let spare = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(60)));
        let mut sim = live(pair, 5, vec![road(), spare]);
        let (_, first) = sim.road(0);
        let (_, second) = sim.road(1);
        sim.conn_mut(Side::Client).set_paths(vec![first, second]);
        let data = pattern(256 << 10, 3);
        let typed = pattern(16 << 10, 4);
        sim.send(Side::Server, 16, &data);
        sim.send(Side::Client, 16, &typed);
        run_until_delivered(
            &mut sim,
            Side::Client,
            16,
            data.len(),
            Duration::from_secs(30),
        );
        run_until_delivered(
            &mut sim,
            Side::Server,
            16,
            typed.len(),
            Duration::from_secs(30),
        );
        sim.run_for(Duration::from_secs(5));
        assert!(sim.delivered(Side::Client, 16) == &data[..], "{pair:?}");
        assert!(
            sim.delivered(Side::Server, 16) == &typed[..],
            "{pair:?}: up"
        );
        let view = sim.conn(Side::Client).roads(sim.instant());
        assert!(
            view.iter()
                .any(|r| r.addr == second && r.state == PathState::Verified),
            "{pair:?}: the spare answers its check: {view:?}"
        );
    }
}

/// Spec §4.16 with §9.3: no `CREDIT` goes to, or comes from, a peer built
/// before credits, and what either side keeps out of order stays within
/// the window such a peer's sender keeps; between two new ends credits flow
/// and the credit window bounds it.
#[test]
fn each_pair_keeps_its_receive_bounds_and_credits_go_only_between_new_ends() {
    const SIZE: usize = 2 << 20;
    for pair in Pair::ALL {
        let mut sim = live(pair, 8, vec![road()]);
        sim.send(Side::Client, 20, &pattern(SIZE, 5));
        sim.send(Side::Server, 20, &pattern(SIZE, 6));
        run_until_delivered(&mut sim, Side::Server, 20, SIZE, Duration::from_secs(120));
        run_until_delivered(&mut sim, Side::Client, 20, SIZE, Duration::from_secs(120));
        let window = match pair {
            Pair::BothNew => STREAM_WINDOW,
            Pair::OldServer | Pair::OldClient => LEGACY_RECEIVE_WINDOW,
        };
        // Cap derived the same way `StreamReceiver::cost_cap` computes it:
        // one window of full segments, each its bytes plus `CHUNK_COST`.
        let cap = (window + window / MAX_SEGMENT_SIZE as u64 * CHUNK_COST as u64) as usize;
        for side in [Side::Client, Side::Server] {
            assert!(
                sim.max_undelivered(side) <= cap,
                "{pair:?} {side:?}: {} > {cap}",
                sim.max_undelivered(side)
            );
        }
        let credits = sim.frames_sent(Side::Client).credit + sim.frames_sent(Side::Server).credit;
        match pair {
            Pair::BothNew => assert!(credits > 0, "{pair:?}: credits flow"),
            Pair::OldServer | Pair::OldClient => {
                assert_eq!(credits, 0, "{pair:?}: no CREDIT to or from an old build")
            }
        }
    }
}
