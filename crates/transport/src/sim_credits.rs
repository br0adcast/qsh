//! Stream credits in virtual time (spec §6, §9.2 L1 and 9.4, §11.2, §4.16):
//! a consumer that stops, one slower than the road, a peer that writes past
//! its window, limits and a `Reset` across 2^32, a producer behind a gate.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::conn::{Event, LinkState, StreamClass};
use crate::reliability::{
    StreamFrame, CHUNK_COST, CREDIT_UPDATE_STEP, LEGACY_RECEIVE_WINDOW, MAX_SEGMENT_SIZE,
    STREAM_WINDOW,
};
use crate::send_gate::PIPE_HIGH;
use crate::testnet::{Consumer, LinkSpec, RoadSpec, Side, Sim};

fn live(seed: u64, road: RoadSpec) -> Sim {
    let mut sim = Sim::new(seed, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim
}

fn pattern(len: usize, modulus: u32) -> Vec<u8> {
    (0..len as u32).map(|i| (i % modulus) as u8).collect()
}

/// Spec §9.2 (L1) and §4.10.6: the daemon's consumer of stream 20 takes
/// nothing for 30 s while the client writes 4 MiB on it. The client stops
/// at the window -- the daemon holds exactly `STREAM_WINDOW` of it -- and
/// resends nothing; keystrokes on stream 16 and the PINGs go on. Once the
/// consumer reads again the stream finishes, intact.
#[test]
fn a_stalled_consumer_stops_only_its_own_stream_and_costs_no_resends() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20)).with_bandwidth(2_000_000, None),
    );
    let mut sim = live(31, road);
    sim.set_consumer(Side::Server, 20, Consumer::Stalled);
    let paste = pattern(4 * 1024 * 1024, 251);
    sim.send(Side::Client, 20, &paste);
    let until = sim.now() + Duration::from_secs(30);
    let mut typed = 0usize;
    while sim.now() < until {
        sim.send(Side::Client, 16, b"k");
        typed += 1;
        let at = sim.now();
        sim.run_for(Duration::from_millis(500));
        assert_eq!(
            sim.delivered_len(Side::Server, 16),
            typed,
            "the keystroke typed at {at:?} is through"
        );
        assert_eq!(sim.conn(Side::Client).state(), LinkState::Live);
    }
    assert_eq!(sim.delivered_len(Side::Server, 20) as u64, STREAM_WINDOW);
    assert!(sim.max_unconsumed(Side::Server, 20) <= STREAM_WINDOW);
    assert_eq!(
        sim.conn(Side::Client).stats(sim.instant()).retransmits,
        0,
        "nothing in flight, nothing resent"
    );
    assert!(!sim.conn(Side::Client).ping_unanswered());
    sim.set_consumer(Side::Server, 20, Consumer::Rate(1_000_000));
    sim.run_for(Duration::from_secs(10));
    assert!(sim.delivered(Side::Server, 20) == &paste[..]);
}

/// The same stall, and the way back losing 30 % once the consumer reads
/// again: the `CREDIT` that frees the stream may be lost, and its repeats
/// carry it, then the PONGs (spec §6.4, §9.2 L1). Made deterministic
/// (Important 1 of the Task 5 review): a plain 30 % loss lets a lucky seed
/// have every lost `CREDIT` overtaken by the next step's growth
/// announcement before a repeat is ever due, so the mechanism this
/// scenario names would never run and the test would still pass. Instead,
/// the moment the consumer resumes, the way back is fully blacked out
/// (loss 1.0) for 3 s: long enough to drain `STREAM_WINDOW` at 1 MB/s
/// (~524 ms) AND to exhaust all `CREDIT_RESENDS` (3) explicit repeats,
/// which this scenario's own `oldest` limit never re-arms once armed (see
/// `StreamReceiver::credit_due`'s `repeating_for` doc) -- so every step
/// `CREDIT`, and the whole repeat cycle, are lost for certain, not by
/// chance of the seed, and afterwards `credit_resend` structurally cannot
/// fire again for this stream. The road then settles to 30 % loss. That
/// last property is why the blackout must outlast the repeats rather than
/// merely the drain: with a shorter blackout a repeat can coincidentally
/// still be due at the exact instant of an unrelated `PONG` (both come out
/// of the same `on_timeout`/`on_datagram` machinery), which would make a
/// repeat look "PONG-borne" by pure timing coincidence, as a probe with an
/// 800 ms blackout showed. With the repeats exhausted first, any `CREDIT`
/// for this stream from then on can only be `credit_for_pong`'s. The end
/// asserts the mechanism actually fired: some limit on stream 20 went out
/// more than once outside a `PONG`'s own instant
/// (`StreamReceiver::credit_resend`'s own repeat, spec §6.4), and at least
/// one `CREDIT` went out at a `PONG`'s own instant
/// (`StreamReceiver::credit_for_pong`) -- not only that the stream
/// eventually finished. Verified in a git-archive copy with both
/// mechanisms disabled (the stream never gets past `STREAM_WINDOW`), and
/// with each disabled alone (repeats alone, or PONGs alone, still finish
/// it) -- see the Task 5 fix round 1 report.
#[test]
fn a_stalled_stream_resumes_when_the_credits_that_free_it_are_lost() {
    let lossless = LinkSpec::new(Duration::from_millis(20));
    let mut sim = live(32, RoadSpec::symmetric(lossless));
    sim.set_consumer(Side::Server, 20, Consumer::Stalled);
    let paste = pattern(4 * 1024 * 1024, 241);
    sim.send(Side::Client, 20, &paste);
    sim.run_for(Duration::from_secs(5));
    assert_eq!(sim.delivered_len(Side::Server, 20) as u64, STREAM_WINDOW);
    sim.record_sends();
    sim.set_link(0, Side::Server, lossless.with_loss(1.0));
    sim.set_consumer(Side::Server, 20, Consumer::Rate(1_000_000));
    let resettle = sim.now() + Duration::from_millis(3000);
    sim.schedule(resettle, move |s| {
        s.set_link(0, Side::Server, lossless.with_loss(0.3));
    });
    let deadline = sim.now() + Duration::from_secs(60);
    while sim.delivered_len(Side::Server, 20) < paste.len() && sim.now() < deadline {
        sim.run_for(Duration::from_millis(100));
    }
    assert!(
        sim.delivered(Side::Server, 20) == &paste[..],
        "{} of {} bytes",
        sim.delivered_len(Side::Server, 20),
        paste.len()
    );
    // A `CREDIT` that rides a PONG is in the PONG's own datagram (ruling
    // R16, spec §4.11); a repeat goes out on the timer. Correlated by `at`,
    // which holds either way.
    let sent = sim.sent(Side::Server);
    let pong_instants: HashSet<Duration> = sent
        .iter()
        .filter(|d| {
            d.frames
                .iter()
                .any(|f| matches!(f, StreamFrame::Pong { .. }))
        })
        .map(|d| d.at)
        .collect();
    let mut repeated_outside_pong: HashMap<u32, u32> = HashMap::new();
    let mut pong_credit = false;
    for d in sent {
        let is_pong_moment = pong_instants.contains(&d.at);
        for f in &d.frames {
            let StreamFrame::Credit { stream_id, limit } = f else {
                continue;
            };
            if *stream_id != 20 {
                continue;
            }
            if is_pong_moment {
                pong_credit = true;
            } else {
                *repeated_outside_pong.entry(*limit).or_insert(0) += 1;
            }
        }
    }
    assert!(
        repeated_outside_pong.values().any(|&n| n > 1),
        "some CREDIT limit on stream 20 must go out more than once outside a PONG's instant \
         (the timer's own repeat): {repeated_outside_pong:?}"
    );
    assert!(
        pong_credit,
        "some CREDIT on stream 20 must go out at a PONG's own instant"
    );
}

/// Spec §4.16 (QSH-01): a peer that writes far past its window -- one-byte
/// chunks at every other offset, and segments megabytes ahead -- costs a
/// receiver at most one window of out-of-order data, and the receiver's own
/// output to it goes on; with credits and against a peer built before them.
#[test]
fn a_peer_writing_far_past_its_window_costs_at_most_a_window() {
    for legacy in [false, true] {
        let mut sim = Sim::new(
            33,
            vec![RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(
                10,
            )))],
        );
        if legacy {
            sim.play_legacy(Side::Client);
        }
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        let window = if legacy {
            LEGACY_RECEIVE_WINDOW
        } else {
            STREAM_WINDOW
        };
        let mut forged: Vec<StreamFrame> = (0..20_000u32)
            .map(|i| StreamFrame::Data {
                stream_id: 20,
                offset: 1 + 2 * i,
                data: vec![0xEE],
            })
            .collect();
        forged.extend((0..64u32).map(|k| StreamFrame::Data {
            stream_id: 20,
            offset: window as u32 + k * 1024 * 1024,
            data: vec![0xEE; 1024],
        }));
        let out = sim.conn_mut(Side::Client).frames_for_test(forged);
        sim.transmit(Side::Client, out);
        sim.send(Side::Server, 16, b"still here");
        sim.run_for(Duration::from_secs(2));
        // Cap derived the same way `StreamReceiver::cost_cap` computes it:
        // one window of full segments, each its bytes plus `CHUNK_COST`.
        let cap = (window + window / MAX_SEGMENT_SIZE as u64 * CHUNK_COST as u64) as usize;
        assert!(
            sim.max_undelivered(Side::Server) <= cap,
            "legacy {legacy}: {} > {cap}",
            sim.max_undelivered(Side::Server)
        );
        assert_eq!(
            sim.delivered_len(Side::Server, 20),
            0,
            "nothing arrived in order"
        );
        assert_eq!(sim.delivered(Side::Client, 16), b"still here");
    }
}

/// Spec §4.14 with §6: a daemon stream that starts 1 MiB short of 2^32, on a
/// lossy, reordering road. Renamed and its doc corrected (Minor 1 of the
/// Task 5 review): its credit limits cross the edge by ordinary growth, and
/// a resync after a long absence sends a `Reset` that lands PAST the edge
/// too -- not straddling it (a `Reset` that straddles 2^32 is already
/// `sim_regressions::a_resync_across_the_end_of_the_offset_space_reaches_the_client`'s
/// own case, kept as is). The client's rate consumer here keeps up with
/// what arrives -- this road has no bandwidth limit, so 512 KB/s never
/// falls behind it -- exercising `on_consumed`/credit growth through the
/// edge, not a credit that binds (see the variant of scenario 6 below for
/// that). What was written before the freeze arrives, what was written
/// after the resync arrives, nothing reports an exhausted offset space, and
/// the client never holds more than a window.
#[test]
fn credit_limits_cross_the_end_of_the_offset_space_and_a_reset_lands_past_it() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(10))
            .with_loss(0.03)
            .with_reorder(0.03, Duration::from_millis(15)),
    );
    let mut sim = live(34, road);
    let start = u32::MAX - 1024 * 1024 + 1;
    sim.conn_mut(Side::Server)
        .start_stream_at_for_test(0, start);
    sim.conn_mut(Side::Client)
        .start_stream_at_for_test(0, start);
    sim.set_consumer(Side::Client, 0, Consumer::Rate(512_000));
    let before = pattern(1536 * 1024, 251);
    for chunk in before.chunks(8 * 1024) {
        sim.send(Side::Server, 0, chunk);
        sim.run_for(Duration::from_millis(5));
    }
    sim.run_for(Duration::from_secs(10));
    assert!(sim.delivered(Side::Client, 0) == &before[..]);
    let limit = sim
        .conn(Side::Server)
        .credit_limit_for_test(0)
        .expect("credits");
    assert!(limit > 1 << 32, "the limit crossed the edge: {limit}");
    sim.freeze(Side::Client, Duration::from_secs(12));
    for i in 1..=10u64 {
        let at = sim.now() + Duration::from_secs(i);
        sim.schedule(at, |s| s.send(Side::Server, 0, &[b'-'; 8 * 1024]));
    }
    sim.run_for(Duration::from_secs(13));
    let after = pattern(64 * 1024, 241);
    sim.send(Side::Server, 0, &after);
    sim.run_for(Duration::from_secs(10));
    let got = sim.delivered(Side::Client, 0);
    assert!(
        got.starts_with(&before) && got.ends_with(&after),
        "{} bytes",
        got.len()
    );
    assert!(sim
        .log()
        .iter()
        .any(|(_, side, ev)| *side == Side::Client
            && matches!(ev, Event::StreamReset { stream_id: 0 })));
    assert!(!sim
        .log()
        .iter()
        .any(|(_, _, ev)| matches!(ev, Event::OffsetSpaceExhausted { .. })));
    assert!(sim.max_unconsumed(Side::Client, 0) <= STREAM_WINDOW);
}

/// Spec §9.2 (L1, the `Reset` row): with credits, and a client that takes
/// what it gets, the repaint after a long absence leaves no later than a
/// moment after the `Reset` -- not a round trip -- because the dropped
/// backlog fits under the sender's own limit from before the freeze.
/// `mark_desynced` (spec §6.5) leaves the sender's limit at
/// `max(old limit, head)`; checked directly here, not inferred (Minor 3 of
/// the Task 5 review), that it lands strictly above `head` -- the sender's
/// own queued total at resync -- not merely equal to it (equality is the
/// sibling's own case below: zero room).
#[test]
fn a_resync_with_credits_sends_the_repaint_without_a_round_trip() {
    let mut sim = live(
        36,
        RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(50))),
    );
    sim.record_sends();
    sim.send(Side::Server, 0, &vec![b'a'; 300 * 1024]);
    sim.run_for(Duration::from_millis(200));
    sim.freeze(Side::Client, Duration::from_secs(12));
    for i in 1..=10u64 {
        let at = sim.now() + Duration::from_secs(i);
        sim.schedule(at, |s| s.send(Side::Server, 0, &[b'-'; 8 * 1024]));
    }
    let deadline = sim.now() + Duration::from_secs(15);
    while !sim
        .log()
        .iter()
        .any(|(_, side, ev)| *side == Side::Server && matches!(ev, Event::OutputResync))
    {
        assert!(
            sim.now() < deadline,
            "the client came back and the server resynced"
        );
        sim.run_for(Duration::from_millis(1));
    }
    // `head`: the sender's own queued total (base offset plus its unsent
    // buffer, acknowledged bytes included) at the moment it resyncs -- what
    // `mark_desynced` took the max of against its old limit. Frozen since
    // the moment it dropped its backlog (a desynced sender's `push` is a
    // no-op) until now, so this is exactly what `mark_desynced` saw.
    let head = sim.conn(Side::Server).stream_progress(0).queued;
    let limit_at_resync = sim
        .conn(Side::Server)
        .credit_limit_for_test(0)
        .expect("credits");
    assert!(
        limit_at_resync > head,
        "the sender's limit at resync ({limit_at_resync}) must sit strictly above its head \
         offset ({head}) for the repaint to need no round trip"
    );
    sim.send(Side::Server, 0, b"the repaint");
    let sent = sim.sent(Side::Server);
    let reset_at = sent
        .iter()
        .find(|d| {
            d.frames
                .iter()
                .any(|f| matches!(f, StreamFrame::Reset { stream_id: 0, .. }))
        })
        .expect("the Reset went")
        .at;
    let repaint_at = sent
        .iter()
        .filter(|d| d.at >= reset_at)
        .find(|d| {
            d.frames
                .iter()
                .any(|f| matches!(f, StreamFrame::Data { stream_id: 0, .. }))
        })
        .expect("the repaint went")
        .at;
    assert!(
        repaint_at - reset_at < Duration::from_millis(100),
        "no round trip between them: {reset_at:?} -> {repaint_at:?}"
    );
    sim.run_for(Duration::from_secs(2));
    assert!(sim.delivered(Side::Client, 0).ends_with(b"the repaint"));
    assert!(
        sim.conn(Side::Server).credit_limit_for_test(0)
            <= sim.conn(Side::Client).receive_limit_for_test(0)
    );
}

/// The sibling of the scenario above: the backlog the server drops does NOT
/// fit under its old limit. 900 KiB is written while the client is frozen
/// (nine 100 KiB chunks) on top of an initial 32 KiB -- under
/// `CREDIT_UPDATE_STEP`'s 128 KiB growth threshold, so no `CREDIT` is ever
/// sent for it, and the sender's limit stays at the implicit initial window
/// (`STREAM_WINDOW`, 512 KiB) right up to the freeze. Nothing is
/// acknowledged while the client is frozen, so the whole 900 KiB sits
/// unacknowledged at desync time, well past that 512 KiB. `mark_desynced`
/// (spec §6.5) then leaves the sender's limit at exactly its head offset --
/// checked directly, not inferred (Minor 3 of the Task 5 review) -- so the
/// repaint cannot go out with the `Reset`. It waits for the receiver's own
/// `CREDIT`, sent with the `Reset`'s `ACK`. On this road (50 ms one way, no
/// loss/jitter/reorder, so `Link::admit`'s random draws change nothing
/// about its timing) the gap from `reset_at` to `repaint_at` is exactly one
/// round trip, not merely "about" one: the `Reset` reaches the client at
/// `reset_at + delay`, its `CREDIT`-bearing `ACK` leaves at that same
/// instant and reaches the server at `reset_at + 2*delay`, where the
/// already-queued repaint leaves in the same step, nothing else in the way.
/// Asserted as an exact equality (Important 2 of the Task 5 review): the
/// prior `<= rtt + 20 ms` tolerance happened to equal spec §3.2's
/// `ACK_DELAY`, so a regression that let the `CREDIT` ride a *delayed* ACK
/// instead of the immediate one §6.5 requires would have landed at exactly
/// `rtt + ACK_DELAY` and still passed.
#[test]
fn a_resync_whose_backlog_does_not_fit_waits_one_round_trip_for_its_credit() {
    let delay = Duration::from_millis(50);
    let mut sim = live(37, RoadSpec::symmetric(LinkSpec::new(delay)));
    sim.record_sends();
    sim.send(Side::Server, 0, &vec![b'a'; 32 * 1024]);
    sim.run_for(Duration::from_millis(200));
    sim.freeze(Side::Client, Duration::from_secs(12));
    for i in 1..=9u64 {
        let at = sim.now() + Duration::from_secs(i);
        sim.schedule(at, |s| s.send(Side::Server, 0, &[b'-'; 100 * 1024]));
    }
    let deadline = sim.now() + Duration::from_secs(15);
    while !sim
        .log()
        .iter()
        .any(|(_, side, ev)| *side == Side::Server && matches!(ev, Event::OutputResync))
    {
        assert!(
            sim.now() < deadline,
            "the client came back and the server resynced"
        );
        sim.run_for(Duration::from_millis(1));
    }
    let head = sim.conn(Side::Server).stream_progress(0).queued;
    let limit_at_resync = sim
        .conn(Side::Server)
        .credit_limit_for_test(0)
        .expect("credits");
    assert_eq!(
        limit_at_resync, head,
        "mark_desynced must leave the sender at exactly its head offset (zero room), \
         or this test proves nothing"
    );
    sim.send(Side::Server, 0, b"the repaint");
    // Unlike scenario 5 above, the repaint needs a round trip for its
    // CREDIT before it can leave: give it one.
    let repaint_deadline = sim.now() + Duration::from_secs(5);
    while !sim.delivered(Side::Client, 0).ends_with(b"the repaint") {
        assert!(sim.now() < repaint_deadline, "the repaint never arrived");
        sim.run_for(Duration::from_millis(1));
    }
    let sent = sim.sent(Side::Server);
    let reset_at = sent
        .iter()
        .find(|d| {
            d.frames
                .iter()
                .any(|f| matches!(f, StreamFrame::Reset { stream_id: 0, .. }))
        })
        .expect("the Reset went")
        .at;
    let repaint_at = sent
        .iter()
        .filter(|d| d.at >= reset_at)
        .find(|d| {
            d.frames
                .iter()
                .any(|f| matches!(f, StreamFrame::Data { stream_id: 0, .. }))
        })
        .expect("the repaint went")
        .at;
    let rtt = 2 * delay;
    assert_eq!(
        repaint_at - reset_at,
        rtt,
        "the repaint must leave exactly one round trip after the Reset -- this road is \
         deterministic (no loss, jitter or reordering), so the gap is exact, not \
         approximate: {reset_at:?} -> {repaint_at:?}"
    );
}

/// Spec §11.2's literal configuration (Minor 2 of the Task 5 review says
/// what it actually exercises): a producer that respects a pipe gate (it
/// writes 8 KiB whenever its stream's tail is under `PIPE_HIGH`), 8 MiB
/// over 20 ms / 10 MB/s / 1 % loss, read by a client consumer at 1 MB/s. On
/// this road the LOSSY ROAD is the bottleneck (about 417 KB/s effective,
/// under the 1 MB/s reader), not the reader, so this exercises the gate
/// holding the tail near `PIPE_HIGH` under real loss and retransmits --
/// `max_tail` cannot exceed `PIPE_HIGH + a write - 1` however credits
/// behave, since nothing else here raises `unacked`. It does not exercise
/// the credit actually binding (the variant below does that): everything
/// arrives; the tail never stands higher than the gate plus a write plus a
/// credit step; the client never holds more than a window.
#[test]
fn a_gated_producer_behind_a_slow_reader_keeps_its_tail_near_the_gate() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20))
            .with_bandwidth(10_000_000, None)
            .with_loss(0.01),
    );
    let mut sim = live(35, road);
    sim.set_consumer(Side::Client, 20, Consumer::Rate(1_000_000));
    let total = 8 * 1024 * 1024;
    let chunk = vec![0x5Au8; 8 * 1024];
    let mut written = 0usize;
    let deadline = sim.now() + Duration::from_secs(60);
    while sim.delivered_len(Side::Client, 20) < total && sim.now() < deadline {
        if written < total && sim.conn(Side::Server).stream_progress(20).unacked < PIPE_HIGH {
            sim.send(Side::Server, 20, &chunk);
            written += chunk.len();
        }
        sim.forget_delivered(Side::Client, 20);
        sim.run_for(Duration::from_millis(1));
    }
    assert_eq!(sim.delivered_len(Side::Client, 20), total);
    let bound = PIPE_HIGH + chunk.len() as u64 + CREDIT_UPDATE_STEP;
    assert!(
        sim.max_tail(Side::Server, 20) <= bound,
        "{}",
        sim.max_tail(Side::Server, 20)
    );
    assert!(sim.max_unconsumed(Side::Client, 20) <= STREAM_WINDOW);
}

/// The variant Minor 2 of the Task 5 review asked for: a reader genuinely
/// slower than the road (200 KB/s against a 2 MB/s, low-latency, lossless
/// road, so the road is never the bottleneck), unrestricted by any send
/// gate. Here the credit itself binds: the sender keeps writing up to its
/// credit limit -- which tracks `consumed + STREAM_WINDOW` -- so once the
/// transfer settles, the receiver sits with close to a full window
/// delivered and not yet taken, not merely whatever a gate happened to
/// leave queued. `STREAM_WINDOW - CREDIT_UPDATE_STEP` is the threshold
/// (spec §6.2, §6.4): the credit grows only in `CREDIT_UPDATE_STEP` steps,
/// so the receiver's unconsumed backlog can sit up to one step short of a
/// full window and still mean the credit is what is binding, not a
/// coincidence of timing.
#[test]
fn a_gated_producer_behind_a_reader_slower_than_the_road_lets_the_credit_bind() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20)).with_bandwidth(2_000_000, None),
    );
    let mut sim = live(38, road);
    sim.set_consumer(Side::Client, 20, Consumer::Rate(200_000));
    let total = 2 * 1024 * 1024;
    let data = pattern(total, 251);
    sim.send(Side::Server, 20, &data);
    let deadline = sim.now() + Duration::from_secs(60);
    while sim.delivered_len(Side::Client, 20) < total && sim.now() < deadline {
        sim.run_for(Duration::from_millis(10));
    }
    assert_eq!(sim.delivered_len(Side::Client, 20), total);
    assert!(sim.delivered(Side::Client, 20) == &data[..]);
    assert!(
        sim.max_unconsumed(Side::Client, 20) >= STREAM_WINDOW - CREDIT_UPDATE_STEP,
        "the credit must bind (unconsumed close to a full window): {}",
        sim.max_unconsumed(Side::Client, 20)
    );
}

/// 8 MiB up over `bandwidth` behind a tail-drop queue of `queue` bytes
/// (50 ms each way), the daemon reading it at `rate`: (time, goodput as a
/// share of the road, bytes sent twice as a share of those delivered).
fn upload_read_at(
    seed: u64,
    bandwidth: u64,
    queue: usize,
    rate: u64,
) -> (Option<Duration>, f64, f64) {
    const STREAM: u8 = 30;
    const BYTES: usize = 8 * 1024 * 1024;
    let road = RoadSpec {
        up: LinkSpec::new(Duration::from_millis(50)).with_bandwidth(bandwidth, Some(queue)),
        down: LinkSpec::new(Duration::from_millis(50)),
    };
    let mut sim = live(seed, road);
    sim.set_consumer(Side::Server, STREAM, Consumer::Rate(rate));
    sim.conn_mut(Side::Client)
        .set_stream_class(STREAM, StreamClass::Bulk);
    let data = pattern(BYTES, 251);
    let start = sim.now();
    sim.send(Side::Client, STREAM, &data);
    let mut took = None;
    while sim.now() < start + Duration::from_secs(600) {
        sim.run_for(Duration::from_millis(10));
        if sim.delivered_len(Side::Server, STREAM) == BYTES {
            took = Some(sim.now() - start);
            break;
        }
    }
    let delivered = sim.delivered_len(Side::Server, STREAM) as u64;
    let sent = sim.frames_sent(Side::Client).data_bytes;
    let goodput = took.map_or(0.0, |t| {
        delivered as f64 / t.as_secs_f64() / bandwidth as f64
    });
    let resent = sent.saturating_sub(delivered) as f64 / delivered.max(1) as f64;
    (took, goodput, resent)
}

/// Spec §4.15's thresholds hold with the daemon counting its consumption
/// explicitly, as the channel runner does: a reader faster than the road
/// never lets its credit bind the upload.
#[test]
fn the_slow_uplink_thresholds_hold_when_the_daemon_reads_explicitly() {
    let mut misses = Vec::new();
    for bandwidth in [125_000u64, 64_000] {
        for queue in [64 * 1024usize, 256 * 1024] {
            let (took, goodput, resent) = upload_read_at(1, bandwidth, queue, 1_000_000);
            let row = format!(
                "{:>3} KB/s, queue {:>3} KiB: took {took:?}, goodput {:>3.0} %, resent {:>5.1} %",
                bandwidth / 1000,
                queue / 1024,
                goodput * 100.0,
                resent * 100.0
            );
            eprintln!("{row}");
            if took.is_none() || goodput < 0.80 || resent > 0.10 {
                misses.push(row);
            }
        }
    }
    assert!(
        misses.is_empty(),
        "rows under the thresholds:\n{}",
        misses.join("\n")
    );
}
