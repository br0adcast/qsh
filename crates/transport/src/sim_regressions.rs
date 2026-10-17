//! Regression scenarios of spec `2026-09-26-qsh-transport-defects-design.md`
//! §9.2 that need real delays, several roads or loss -- run on
//! [`crate::testnet::Sim`].

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use crate::congestion::{Cuts, Probe, INITIAL_WINDOW, QUEUE_DELAY_CAP, SEGMENT};
use crate::conn::{Event, RttSource, StreamClass, BULK_FLUSH_BUDGET};
use crate::features::Features;
use crate::paths::PathState;
use crate::reliability::{StreamFrame, OFFSET_LIMIT};
use crate::testnet::{LinkSpec, RoadSpec, Side, Sim};

/// Spec §9.2 (defect 4): a road with a 2.5 s round trip never reads its PINGs
/// as unanswered. Its handshake is retransmitted (msg1 every 500 ms), so no
/// seed is taken -- exactly the case the 3 s ceiling of `unanswered_after`
/// exists for.
#[test]
fn a_road_with_a_two_and_a_half_second_round_trip_never_reads_its_pings_unanswered() {
    let mut sim = Sim::new(
        25,
        vec![RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(
            1250,
        )))],
    );
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(10)));
    let end = sim.now() + Duration::from_secs(60);
    while sim.now() < end {
        sim.run_for(Duration::from_millis(50));
        assert!(
            !sim.conn(Side::Client).ping_unanswered(),
            "a 2.5 s road read its PINGs as unanswered {:?} in",
            sim.now()
        );
    }
    let rtt = sim.conn(Side::Client).rtt().expect("measured by now");
    assert_eq!(rtt.source, RttSource::Ping);
    assert_eq!(rtt.value, Duration::from_millis(2500));
}

/// Spec §9.2 (defect 3): a slow road in use (2.9 s round trip) next to a fast
/// verified spare (20 ms), 10 packets/s of output for a minute, then
/// 200 packets/s. The spare's check answers overtake everything still on the
/// slow road -- hundreds of packets at the higher rate -- and the receiver
/// must still take them. 2.9 s rather than the spec's "3 s": a check is
/// failed and a PING overdue at exactly 3 s (`PROBE_TIMEOUT`, `RTO_CEILING`),
/// so a road of exactly 3 s sits on the boundary of both rules.
///
/// On lossless roads the server has nothing to retransmit once its round trip
/// is measured; a datagram the client's replay window threw away is the only
/// thing that would make it retransmit during the fast minute.
#[test]
fn a_slow_road_next_to_a_fast_verified_spare_keeps_everything_it_carries() {
    let slow = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(1450)));
    let fast = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(10)));
    let mut sim = Sim::new(3, vec![slow, fast]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(15)));
    let (_, slow_addr) = sim.road(0);
    let (_, fast_addr) = sim.road(1);
    sim.conn_mut(Side::Client)
        .set_paths(vec![slow_addr, fast_addr]);
    let start = sim.now();
    let fast_phase = start + Duration::from_secs(60);
    let end = start + Duration::from_secs(120);
    let mut retransmits_before_fast_phase = None;
    let mut t = start;
    while t < end {
        sim.run_until(t);
        if t >= fast_phase && retransmits_before_fast_phase.is_none() {
            retransmits_before_fast_phase =
                Some(sim.conn(Side::Server).stats(sim.instant()).retransmits);
        }
        sim.send(Side::Server, 16, &[b'o'; 100]);
        assert_eq!(
            sim.conn(Side::Client).active_path(),
            Some(slow_addr),
            "the session left the slow road {:?} in",
            t - start
        );
        if t >= start + Duration::from_secs(15) {
            assert!(
                !sim.conn(Side::Client).ping_unanswered(),
                "the slow road's PINGs read as unanswered {:?} in",
                t - start
            );
        }
        t += if t < fast_phase {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(5)
        };
    }
    sim.run_until(end);
    assert_eq!(
        sim.conn(Side::Server).stats(sim.instant()).retransmits,
        retransmits_before_fast_phase.expect("the fast phase ran"),
        "on lossless roads nothing the server sent in the fast minute was thrown away"
    );
    let view = sim.conn(Side::Client).roads(sim.instant());
    assert!(
        view.iter()
            .any(|r| r.addr == fast_addr && r.state == PathState::Verified),
        "the spare was verified -- or the test proves nothing: {view:?}"
    );
}

/// Spec §9.2 (defect 3), the PONGs themselves: a 1.7 s road in use, a fast
/// verified spare, the server writing 200 packets/s. In this run a spare
/// check goes out together with a PING, so its answer overtakes the PONG to
/// the PING before it: the server sent that PONG some 0.65 s earlier, about
/// 130 packets back -- out of reach of the 64-position window this replaced.
/// With that window the PONG was thrown away and the PING read as unanswered
/// at the first check (31.5 s in). With the RFC 6479 window every PONG
/// counts and the session stays on the slow road.
#[test]
fn a_slow_road_keeps_its_pongs_while_a_fast_spare_is_checked() {
    let slow = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(850)));
    let fast = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(10)));
    let mut sim = Sim::new(7, vec![slow, fast]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(15)));
    let (_, slow_addr) = sim.road(0);
    let (_, fast_addr) = sim.road(1);
    sim.conn_mut(Side::Client)
        .set_paths(vec![slow_addr, fast_addr]);
    let start = sim.now();
    let end = start + Duration::from_secs(90);
    let mut t = start;
    while t < end {
        sim.run_until(t);
        sim.send(Side::Server, 16, &[b'o'; 100]);
        assert_eq!(
            sim.conn(Side::Client).active_path(),
            Some(slow_addr),
            "the session left the slow road {:?} in",
            t - start
        );
        if t >= start + Duration::from_secs(10) {
            assert!(
                !sim.conn(Side::Client).ping_unanswered(),
                "the slow road's PINGs read as unanswered {:?} in",
                t - start
            );
        }
        t += Duration::from_millis(5);
    }
    let checks = sim.frames_sent(Side::Client).path_probe;
    assert!(
        checks >= 3,
        "the spare was checked {checks} times -- or the test proves nothing"
    );
    let view = sim.conn(Side::Client).roads(sim.instant());
    assert!(
        view.iter()
            .any(|r| r.addr == fast_addr && r.state == PathState::Verified),
        "the spare was verified -- or the test proves nothing: {view:?}"
    );
}

/// Spec §4.14 / §9.2 (9.4, the mode without `offset-wrap`: a peer built
/// before it): a stream that starts 1 MiB short of `OFFSET_LIMIT` on a
/// lossy, reordering road delivers exactly that 1 MiB, refuses everything
/// past it, and says so once.
#[test]
fn a_stream_at_the_edge_of_its_offset_space_stops_there_and_says_so_once() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(10))
            .with_loss(0.05)
            .with_reorder(0.05, Duration::from_millis(15)),
    );
    let mut sim = Sim::new(14, vec![road]);
    sim.play_legacy(Side::Server);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    let start = OFFSET_LIMIT - 1024 * 1024;
    sim.conn_mut(Side::Server)
        .start_stream_at_for_test(20, start);
    sim.conn_mut(Side::Client)
        .start_stream_at_for_test(20, start);
    let data: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    for chunk in data.chunks(8 * 1024) {
        sim.send(Side::Server, 20, chunk);
        sim.run_for(Duration::from_millis(5));
    }
    sim.run_for(Duration::from_secs(30));
    assert_eq!(sim.delivered(Side::Client, 20), &data[..1024 * 1024]);
    let reported = sim
        .log()
        .iter()
        .filter(|(_, side, ev)| {
            *side == Side::Server && matches!(ev, Event::OffsetSpaceExhausted { stream_id: 20 })
        })
        .count();
    assert_eq!(reported, 1, "said once, not once per refused write");
}

/// Spec §4.14 (`offset-wrap`): between two ends of this build a stream that
/// starts 1 MiB short of 2^32 crosses it on a lossy, reordering road and
/// delivers every byte of 2 MiB in order; nothing reports an exhausted
/// offset space.
#[test]
fn a_stream_crosses_the_end_of_the_32_bit_offset_space_between_new_ends() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(10))
            .with_loss(0.05)
            .with_reorder(0.05, Duration::from_millis(15)),
    );
    let mut sim = Sim::new(14, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    assert!(sim
        .conn(Side::Server)
        .features()
        .contains(Features::OFFSET_WRAP));
    let start = u32::MAX - 1024 * 1024 + 1;
    sim.conn_mut(Side::Server)
        .start_stream_at_for_test(20, start);
    sim.conn_mut(Side::Client)
        .start_stream_at_for_test(20, start);
    let data: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    for chunk in data.chunks(8 * 1024) {
        sim.send(Side::Server, 20, chunk);
        sim.run_for(Duration::from_millis(5));
    }
    sim.run_for(Duration::from_secs(30));
    assert!(
        sim.delivered(Side::Client, 20) == &data[..],
        "{} of {} bytes, in order",
        sim.delivered_len(Side::Client, 20),
        data.len()
    );
    assert!(!sim
        .log()
        .iter()
        .any(|(_, _, ev)| matches!(ev, Event::OffsetSpaceExhausted { .. })));
    assert_eq!(
        sim.conn(Side::Server).stream_progress(20).queued,
        u64::from(start) + data.len() as u64,
        "queued counts on past 2^32"
    );
}

/// Spec §4.14: the resync after a long absence -- the daemon drops its
/// backlog and arms a `Reset` at its write head -- lands when that head is
/// past 2^32 and the client's cumulative point still below it: the client
/// jumps across the edge and the repaint after it arrives.
#[test]
fn a_resync_across_the_end_of_the_offset_space_reaches_the_client() {
    let road = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)));
    let mut sim = Sim::new(15, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    let start = u32::MAX - 64 * 1024 + 1;
    sim.conn_mut(Side::Server)
        .start_stream_at_for_test(0, start);
    sim.conn_mut(Side::Client)
        .start_stream_at_for_test(0, start);
    sim.send(Side::Server, 0, &[b'a'; 32 * 1024]);
    sim.run_for(Duration::from_millis(300));
    assert_eq!(sim.delivered_len(Side::Client, 0), 32 * 1024);
    sim.freeze(Side::Client, Duration::from_secs(12));
    for i in 1..=10u64 {
        let at = sim.now() + Duration::from_secs(i);
        sim.schedule(at, |s| s.send(Side::Server, 0, &[b'b'; 8 * 1024]));
    }
    sim.run_for(Duration::from_secs(13));
    assert!(
        sim.conn(Side::Server).stream_progress(0).queued > 1 << 32,
        "the head the Reset names is past 2^32"
    );
    sim.send(Side::Server, 0, b"the repaint");
    sim.run_for(Duration::from_secs(2));
    assert!(sim
        .log()
        .iter()
        .any(|(_, side, ev)| *side == Side::Client
            && matches!(ev, Event::StreamReset { stream_id: 0 })));
    assert!(sim.delivered(Side::Client, 0).ends_with(b"the repaint"));
}

/// What one bulk upload over a bandwidth-limited uplink came to.
#[derive(Debug)]
struct Upload {
    /// From the write to the last byte delivered; `None` if it never finished.
    took: Option<Duration>,
    /// DATA payload bytes the client put on the wire, retransmits included.
    sent: u64,
    delivered: u64,
    queue_dropped: u64,
    rtt: Option<Duration>,
}

impl Upload {
    /// Delivered bytes per second over the upload, as a share of `bandwidth`.
    fn goodput(&self, bandwidth: u64) -> f64 {
        self.took.map_or(0.0, |t| {
            self.delivered as f64 / t.as_secs_f64() / bandwidth as f64
        })
    }

    /// Bytes put on the wire more than once, as a share of those delivered.
    fn resent(&self) -> f64 {
        self.sent.saturating_sub(self.delivered) as f64 / self.delivered.max(1) as f64
    }
}

/// Bulk daemon image transfer: the client writes a whole image to one
/// stream in a single call, `idle` after the
/// handshake. `bandwidth` bytes/s up behind a tail-drop queue of `queue`
/// bytes, 50 ms one way in each direction, the way down unlimited.
fn bulk_upload(bytes: usize, bandwidth: u64, queue: usize, idle: Duration) -> Upload {
    let up = LinkSpec::new(Duration::from_millis(50)).with_bandwidth(bandwidth, Some(queue));
    upload_over(1, up, bytes, idle, None)
}

/// The same upload over any way up (the way down 50 ms, unlimited), from
/// simulator seed `seed`, the client frozen for `freeze.1` once `freeze.0`
/// of the upload has passed.
fn upload_over(
    seed: u64,
    up: LinkSpec,
    bytes: usize,
    idle: Duration,
    freeze: Option<(Duration, Duration)>,
) -> Upload {
    upload_watched(seed, up, bytes, idle, freeze, |_| {})
}

/// [`upload_over`], with `watch` shown the simulator every 10 ms of the
/// upload.
fn upload_watched(
    seed: u64,
    up: LinkSpec,
    bytes: usize,
    idle: Duration,
    freeze: Option<(Duration, Duration)>,
    watch: impl FnMut(&Sim),
) -> Upload {
    let road = RoadSpec {
        up,
        down: LinkSpec::new(Duration::from_millis(50)),
    };
    let step = Duration::from_millis(10);
    upload_on(seed, road, bytes, idle, freeze, step, watch)
}

/// The upload over any `road`, `watch` shown the simulator every `step` of
/// it -- the resolution its time is measured with.
fn upload_on(
    seed: u64,
    road: RoadSpec,
    bytes: usize,
    idle: Duration,
    freeze: Option<(Duration, Duration)>,
    step: Duration,
    mut watch: impl FnMut(&Sim),
) -> Upload {
    const STREAM: u8 = 30;
    let mut sim = Sim::new(seed, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.run_for(idle);
    // The image upload is the bulk class (spec §3.1).
    sim.conn_mut(Side::Client)
        .set_stream_class(STREAM, StreamClass::Bulk);
    let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let start = sim.now();
    sim.send(Side::Client, STREAM, &data);
    let limit = start + Duration::from_secs(600);
    let mut took = None;
    let mut freeze = freeze;
    while sim.now() < limit {
        if let Some((at, d)) = freeze {
            if sim.now() - start >= at {
                sim.freeze(Side::Client, d);
                freeze = None;
            }
        }
        sim.run_for(step);
        watch(&sim);
        if sim.delivered(Side::Server, STREAM).len() == bytes {
            took = Some(sim.now() - start);
            break;
        }
    }
    let delivered = sim.delivered(Side::Server, STREAM);
    assert_eq!(delivered, &data[..delivered.len()], "in order and intact");
    Upload {
        took,
        sent: sim.frames_sent(Side::Client).data_bytes,
        delivered: delivered.len() as u64,
        queue_dropped: sim.link_counters(0, Side::Client).queue_dropped,
        rtt: sim.conn(Side::Client).rtt().map(|s| s.value),
    }
}

/// Assert the review's bounds on one upload: it finished, at 80 % of the
/// road's bandwidth or better, with at most 10 % of the delivered bytes sent
/// a second time.
fn assert_clean_upload(u: &Upload, bandwidth: u64) {
    assert!(u.took.is_some(), "the upload finished: {u:?}");
    assert!(
        u.goodput(bandwidth) >= 0.80,
        "goodput {:.0} % of the road: {u:?}",
        u.goodput(bandwidth) * 100.0
    );
    assert!(
        u.resent() <= 0.10,
        "{:.1} % of the delivered bytes went out again: {u:?}",
        u.resent() * 100.0
    );
}

/// Final review, Important 1: 8 MiB written right after the handshake over a
/// 125 KB/s uplink whose queue holds the whole 256 KiB window. The handshake
/// crossed an empty queue (100 ms), but the window's tail waits some 2.1 s
/// in this one. With a retransmit timeout of 2 x 100 ms until the first PONG
/// every queued segment went out again every 200 ms, and the PING waited
/// behind its own duplicates.
///
/// Branch before the fix: 83 % goodput, 89 % of the delivered bytes sent
/// twice; the handshake floor alone: 89 % and 30 %; with acknowledgements
/// timing the queue (RFC 6298, Karn): 96 % and 0 %.
#[test]
fn a_bulk_upload_right_after_the_handshake_is_not_resent_under_its_own_queue() {
    let bandwidth = 125_000;
    let u = bulk_upload(8 * 1024 * 1024, bandwidth, 384 * 1024, Duration::ZERO);
    assert_clean_upload(&u, bandwidth);
}

/// The same write 10 s into an idle session: PINGs have measured the idle
/// 100 ms round trip, so the timeout starts at 200 ms under a queue a
/// megabyte deep. The PONG to the first PING behind the burst came back only
/// after that PING had been forgotten (four outstanding, 6 s), the queue was
/// never measured, and the upload did not finish in ten minutes. The
/// acknowledgements time it within one round trip.
#[test]
fn a_bulk_upload_mid_session_is_not_resent_under_a_deep_queue() {
    let bandwidth = 125_000;
    let u = bulk_upload(
        8 * 1024 * 1024,
        bandwidth,
        1024 * 1024,
        Duration::from_secs(10),
    );
    assert_clean_upload(&u, bandwidth);
}

/// 64 KB/s: the 256 KiB window stands 4.1 s deep in the queue, past the 3 s
/// ceiling road liveness keeps. A retransmit timeout capped there would
/// resend every segment every 3 s for the whole transfer; its own ceiling
/// (`RETRANSMIT_CEILING`, 15 s) lets it follow the queue. Before: the upload
/// did not finish in ten minutes.
#[test]
fn a_bulk_upload_over_a_64_kb_uplink_finishes_without_resending() {
    let bandwidth = 64_000;
    let u = bulk_upload(8 * 1024 * 1024, bandwidth, 384 * 1024, Duration::ZERO);
    assert_clean_upload(&u, bandwidth);
}

/// Spec §4.15: a queue smaller than the window, where the old fixed window
/// lost pieces of every burst. The slice-1 regression: 64 KB/s with a
/// 64 KiB queue took ~860 s for 8 MiB (before slice 1: 305-414 s); 125 KB/s
/// with a 64 KiB queue gave 59 % goodput and 242 % resends. With the window,
/// fast retransmit and NewReno recovery both are clean uploads.
#[test]
fn a_bulk_upload_over_a_small_uplink_queue_meets_the_congestion_thresholds() {
    for bandwidth in [64_000u64, 125_000] {
        let u = bulk_upload(8 * 1024 * 1024, bandwidth, 64 * 1024, Duration::ZERO);
        eprintln!("{} KB/s, 64 KiB queue: {u:?}", bandwidth / 1000);
        assert_clean_upload(&u, bandwidth);
    }
}

/// Review round 1 of the fast retransmit (Critical): a road that holds one
/// datagram in a thousand back by 10 ms, nothing lost, 1 MB/s up behind a
/// queue that never fills. At 1 MB/s some ten segments overtake the one held
/// back: its duplicates set off a fast retransmit. Before the fix one such
/// retransmit started an endless chain of spurious recoveries -- 19.5-23.2 s
/// and up to 69 % resent, where the code before fast retransmit took 9.0 s
/// with nothing resent. The ACK of the late segment comes back far sooner
/// than the resend could be answered: the retransmit is undone and the
/// duplicate threshold learns the reordering; the repairs of a recovery
/// cannot start another (RFC 6582 §3.2 step 1). Held back by 80 ms, most of
/// the 100 ms round trip, the late segment's ACK still comes before any
/// answer to the resend could: the code before fast retransmit took
/// 10.8-11.7 s there (seeds 1-2), an undo only below half the round trip
/// 17.0-23.0 s.
///
/// The bounds, swept over seeds (slice 4 task 9, the method of task 4's
/// diagnosis §4): this code over seeds 1..=500 of each row, the pre-fix
/// code (`fc00796`, fast retransmit before this review) over seeds 1..=64.
///   - took, per seed, at most 1.2 x 9.0 s = 10.8 s: this code's slowest
///     seed is 9.09 s at +10 ms and 9.25 s at +80 ms (SD 0.007 / 0.030 s);
///     the pre-fix code's fastest 12.13 / 11.86 s. A seed's bound holds:
///     no reshuffle of the draws comes near it from either side.
///   - resent at +10 ms, per seed, at most 2 %: this code's most is
///     0.024 %, the pre-fix code's least 3.6 %. Holds per seed too.
///   - resent at +80 ms: per seed it does not hold. The outcome has a
///     heavy tail -- mean 0.12 %, SD 0.19, but 4 of 500 seeds above 1 %
///     and 2 above 2 % (at most 2.53 %) -- so a reshuffle from an unrelated
///     datagram could put one of the old two seeds past a 2 % bound. The
///     bound is on the MEAN over seeds 1..=16 instead, set an equal number
///     of standard errors of a 16-seed mean from this code's distribution
///     and the pre-fix code's (mean 61.9 %, SD 30.5): 0.5 %, 7.9 SE from
///     this code and 8.0 SE from the pre-fix code. Checked on the sweep:
///     every one of the 31 disjoint 16-seed blocks of this code passes (the
///     worst 0.26 %); by bootstrap (20 000 draws) this code fails 1.5 in
///     10 000 draws and the pre-fix code never passes. Seeds 1..=16 here:
///     0.21 % (seed 16 alone is 1.94 %).
#[test]
fn light_reordering_does_not_turn_a_bulk_upload_into_resends() {
    const RESENT_MEAN_AT_80_MS: f64 = 0.5;
    let bandwidth = 1_000_000;
    let runs: Vec<(u64, u64)> = (1..=4)
        .map(|seed| (seed, 10))
        .chain((1..=16).map(|seed| (seed, 80)))
        .collect();
    let uploads = run_seeds(&runs, |(seed, extra)| {
        let up = LinkSpec::new(Duration::from_millis(50))
            .with_bandwidth(bandwidth, Some(4 * 1024 * 1024))
            .with_reorder(0.001, Duration::from_millis(extra));
        upload_over(seed, up, 8 * 1024 * 1024, Duration::from_secs(2), None)
    });
    let mut resent_at_80 = Vec::new();
    for (&(seed, extra), u) in runs.iter().zip(&uploads) {
        eprintln!("1 MB/s, reorder 0.001 +{extra} ms, seed {seed}: {u:?}");
        let took = u.took.expect("finished");
        assert!(
            took <= Duration::from_secs_f64(1.2 * 9.0),
            "+{extra} ms, seed {seed}: {took:?}, the code before fast retransmit took 9.0 s: {u:?}"
        );
        if extra == 80 {
            resent_at_80.push(u.resent() * 100.0);
        } else {
            assert!(
                u.resent() <= 0.02,
                "+{extra} ms, seed {seed}: {:.1} % resent: {u:?}",
                u.resent() * 100.0
            );
        }
    }
    let mean = resent_at_80.iter().sum::<f64>() / resent_at_80.len() as f64;
    eprintln!(
        "+80 ms: mean resent {mean:.3} % over {} seeds",
        resent_at_80.len()
    );
    assert!(
        mean <= RESENT_MEAN_AT_80_MS,
        "+80 ms: mean resent {mean:.3} % over {} seeds, bound {RESENT_MEAN_AT_80_MS} %",
        resent_at_80.len()
    );
}

/// Run `f(job)` for every job in `jobs`, `available_parallelism()` at a
/// time, and return the results in the same order (spec slice 4 task 4's
/// diagnosis, "What B costs": a worker pool rather than a thread per seed).
fn run_seeds<J: Copy + Send + Sync, T: Send>(jobs: &[J], f: impl Fn(J) -> T + Sync) -> Vec<T> {
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    let results: Vec<std::sync::Mutex<Option<T>>> =
        jobs.iter().map(|_| std::sync::Mutex::new(None)).collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Some(job) = jobs.get(i) else {
                    return;
                };
                *results[i].lock().unwrap() = Some(f(*job));
            });
        }
    });
    results
        .into_iter()
        .map(|m| m.into_inner().unwrap().expect("every job ran"))
        .collect()
}

/// Review round 2 of the fast retransmit (Important 1): 0.5 % loss and one
/// datagram in a thousand held back 80 ms, 1 MB/s up. The duplicate
/// threshold learns the reordering from each undo; while it stays high,
/// every loss with fewer segments behind it than the threshold waits for a
/// timeout. With the threshold falling only at a restart: 50.1 / 57.6 /
/// 58.9 s (seeds 1-3; the code before fast retransmit 48.0 / 64.0 / 64.4 s).
/// Put back at three by every timeout (our rule; Linux's `tcp_enter_loss`
/// lowers its `reordering` only in a narrower case), the review's variant
/// took 32.4 / 49.6 / 51.2 s (seeds 1-3).
///
/// A single seed's bound does not survive turning `stream-credit` on (spec
/// slice 4 task 4's diagnosis): an extra frame kind joins the datagram
/// stream, and every admitted datagram on every link draws three numbers
/// from the simulator's one shared RNG, so every later loss/reorder draw
/// from that point on lands on a different datagram than before --
/// reshuffling each seed's own outcome without moving the underlying
/// behaviour (the sender is never actually credit-held here; distributions
/// match within noise). Seed 1's old bound (32.4 s + 10 % = 35.64 s) was
/// met by only 1.6 % of the fixed code's own seeds over a 1000-seed sweep;
/// base passed it only because its particular random stream happened to
/// land there.
///
/// The bound below is on the MEAN `took` over a fixed block of seeds
/// instead, set an equal number of standard errors of a block mean from two
/// distributions (diagnosis §4, option B, ruling R10a; the means and SDs are
/// per seed over a sweep of this road, not over this test's own block).
/// Slice 4 (1000 seeds): the fixed code 45.66 s (SD 4.60), the regression
/// this test exists to catch -- the duplicate threshold never put back to
/// three by a timeout -- 52.02 s (SD 6.39); 48.3 s sat 4.0 SE of a 48-seed
/// mean from each.
///
/// Slice 5's delayed acknowledgements (spec §4.11, ruling R17) made this
/// road slower: a lossy road keeps the window far under its
/// bandwidth-delay product, so every round ends in a group of fewer than
/// `ACK_EVERY` segments whose ACK waits `ACK_DELAY` (500 seeds: 45.40 s at
/// qsh 52308e0, 47.62 s after, Mann-Whitney p 2.5e-11; `ACK_DELAY` = 1 ms
/// gave 45.22 s, p 0.6). A PING ending every flight the window cut short
/// (R17's option (a)) gave the time back (45.81 s, p 0.15) but drew 0.71
/// answers per DATA on the 1 % road of `sim_acks` against 0.41 -- most of
/// what delayed ACKs save -- and one PING outstanding at a time kept the
/// slowdown (46.46 s, p 4e-4); the slowdown was accepted (option (c)).
/// Re-derived over seeds 1..=500 of this road: the fixed code 47.62 s (SD
/// 5.19), the regression 50.72 s (SD 5.53). The gap shrank, and 48 seeds
/// put their equal-SE point only 2.0 SE from each; the block is 192 seeds,
/// where 49.1 s sits 4.0 SE of a 192-seed mean (0.37 s, 0.40 s) from each.
///
/// The final review's M3 (ruling R20: in the round trip after a timeout an
/// ACK counts for one segment of slow start) moved this road once more:
/// seeds 1..=500 47.62 s -> 48.29 s (SD
/// 4.79; Mann-Whitney p 0.048, 290 seeds slower and 209 faster), this
/// block 47.31 s -> 48.08 s, 2.05 SE toward the bound. Two narrower forms
/// of the same rule cost the same (48.25 s, 48.21 s): the time goes in the
/// round trips right after each timeout, where an ACK grows the window of
/// one segment by one instead of up to four. Kept (ruling R21).
///
/// Re-derived for that code (ruling R21, R10a's method), both over seeds
/// 1..=1000 of this road on top of qsh c5137d3: the fixed code 48.50 s (SD
/// 4.80), the regression -- the timeout's reset of the duplicate threshold
/// to three removed -- 53.44 s (SD 5.78). The gap grew from 3.10 s to
/// 4.93 s -- most likely because each loss the learned threshold leaves to
/// the timeout now costs more, the window climbing back from one segment a
/// segment per ACK -- so a smaller block reaches the 4 SE the previous
/// derivation had: equal SE from both is
/// reached at 50.74 s, and 96 seeds put it 4.57 SE from each (SE 0.49 s and
/// 0.59 s); the bound is 50.7 s, 4.49 SE above the fixed code and 4.64 SE
/// below the regression. Seeds 1..=96: the fixed code 47.91 s, the
/// regression 52.52 s (fails).
#[test]
fn a_learned_duplicate_threshold_does_not_leave_losses_to_the_timeout() {
    const SEEDS: u64 = 96;
    const BOUND: f64 = 50.7;
    let seeds: Vec<u64> = (1..=SEEDS).collect();
    let uploads = run_seeds(&seeds, |seed| {
        let up = LinkSpec::new(Duration::from_millis(50))
            .with_bandwidth(1_000_000, Some(4 * 1024 * 1024))
            .with_loss(0.005)
            .with_reorder(0.001, Duration::from_millis(80));
        upload_over(seed, up, 8 * 1024 * 1024, Duration::from_secs(2), None)
    });
    let mut sum = 0.0;
    for (seed, u) in seeds.iter().zip(&uploads) {
        let took = u.took.expect("finished").as_secs_f64();
        eprintln!("1 MB/s, loss 0.5 %, reorder 0.001 +80 ms, seed {seed}: {u:?}");
        sum += took;
    }
    let mean = sum / seeds.len() as f64;
    eprintln!("1 MB/s: mean took {mean:.3} s over {} seeds", seeds.len());
    assert!(
        mean <= BOUND,
        "mean took {mean:.3} s over {} seeds, bound {BOUND} s",
        seeds.len()
    );
}

/// Final review of slice 2, Important 1, in the simulator: a LAN-like road
/// -- 0.5 ms each way with 0.3 ms of jitter both ways, 20 MB/s up behind a
/// 64 KiB queue, 4 MiB written as the session goes live. The base delay
/// comes from round trips that crossed a full queue; the answer to a resend
/// crossed an emptier one and came sooner than that base, so real losses
/// were taken for spurious -- timeouts and fast retransmits undone, partial
/// ACKs that resent nothing: 1.59 / 0.95 / 0.86 s and 15.5 / 7.7 / 7.7 %
/// resent (seeds 1-3). With `HOST_SLACK`: 0.31 / 0.80 / 0.31 s and 2.7 /
/// 7.5 / 2.6 %. The same road at 1 ms each way: 0.89 / 0.45 / 0.45 s and
/// 8.9 / 5.3 / 5.3 % before, 0.48 / 0.51 / 0.51 s and 3.5 / 3.8 / 3.8 %
/// after (seeds 1-3).
///
/// A single seed's bound does not survive turning `stream-credit` on, for
/// the same reason as the mbps test above -- an extra frame kind reshuffles
/// every later random draw -- plus a second effect on this jittery road
/// (spec slice 4 task 4's diagnosis): a CREDIT datagram sits in the down
/// link's FIFO with everything else, and one that draws a long jitter delay
/// holds back the ACKs queued behind it by up to about 600 us on a 1-2 ms
/// round trip. The outcome here is bimodal (a fast mode around 0.31 s, a
/// slow mode from 0.75 s), and a timing change of a few microseconds flips
/// individual seeds between the modes in both directions -- about 10 % of
/// seeds are in the slow mode either way, and the credits/no-credits
/// distributions match within noise (Mann-Whitney p = 0.28/0.23 for
/// took/resent at 500 us).
///
/// The bounds below are on the MEAN `took` and MEAN `resent` over a fixed
/// block of 32 seeds, derived the same way as the mbps test's (diagnosis
/// §4, option B; the means and SDs are per seed over the diagnosis's
/// 2000-seed sweep of each row, not over this test's own 32): fixed code /
/// pre-fix (`HOST_SLACK` reverted to no slack) mean (SD).
///   - 500 us took: fixed 0.359 s (SD 0.135), pre-fix 1.158 s (SD 0.774) --
///     bound 0.48 s, 5.0 SE from each.
///   - 500 us resent: fixed 3.23 % (SD 1.52), pre-fix 10.39 % (SD 7.82) --
///     bound 4.4 %, 4.3 SE from each.
///   - 1000 us took: fixed 0.518 s (SD 0.091), pre-fix 1.616 s (SD 0.916) --
///     bound 0.62 s, 6.2 SE from each.
///   - 1000 us resent: fixed 3.99 % (SD 1.19), pre-fix 12.65 % (SD 5.86) --
///     bound 5.4 %, 7.0 SE from each.
///
/// A reshuffle from an unrelated wire change moves a 32-seed mean by about
/// 1.6 SE at 500 us (measured: credits against base, same seeds); each
/// bound above sits 4.3-7.0 SE from the fixed code -- well past what a
/// reshuffle alone can move it.
#[test]
fn a_lan_road_is_not_slowed_by_repairs_taken_for_spurious() {
    const SEEDS: u64 = 32;
    // (one way in us, mean took bound in s, mean resent bound in %)
    let rows: [(u64, f64, f64); 2] = [(500, 0.48, 4.4), (1_000, 0.62, 5.4)];
    let jobs: Vec<(u64, u64)> = rows
        .iter()
        .flat_map(|&(us, _, _)| (1..=SEEDS).map(move |seed| (us, seed)))
        .collect();
    let uploads = run_seeds(&jobs, |(us, seed)| {
        let one_way =
            LinkSpec::new(Duration::from_micros(us)).with_jitter(Duration::from_micros(300));
        let road = RoadSpec {
            up: one_way.with_bandwidth(20_000_000, Some(64 * 1024)),
            down: one_way,
        };
        upload_on(
            seed,
            road,
            4 * 1024 * 1024,
            Duration::ZERO,
            None,
            Duration::from_millis(1),
            |_| {},
        )
    });
    for (&(us, seed), u) in jobs.iter().zip(&uploads) {
        eprintln!(
            "LAN {us} us each way, seed {seed}: took {:?}, resent {:.2} %",
            u.took,
            u.resent() * 100.0
        );
    }
    for &(us, took_bound, resent_bound) in &rows {
        let row: Vec<&Upload> = jobs
            .iter()
            .zip(&uploads)
            .filter(|((r, _), _)| *r == us)
            .map(|(_, u)| u)
            .collect();
        let n = row.len() as f64;
        let took_mean: f64 = row
            .iter()
            .map(|u| u.took.expect("finished").as_secs_f64())
            .sum::<f64>()
            / n;
        let resent_mean: f64 = row.iter().map(|u| u.resent() * 100.0).sum::<f64>() / n;
        eprintln!(
            "LAN {us} us: mean took {took_mean:.3} s, mean resent {resent_mean:.2} % over {} seeds",
            row.len()
        );
        assert!(
            took_mean <= took_bound,
            "{us} us: mean took {took_mean:.3} s over {} seeds, bound {took_bound} s",
            row.len()
        );
        assert!(
            resent_mean <= resent_bound,
            "{us} us: mean resent {resent_mean:.2} % over {} seeds, bound {resent_bound} %",
            row.len()
        );
    }
}

/// Review round 1 of the fast retransmit (Minor 5): 125 KB/s up behind a
/// 384 KiB queue, the client frozen for 3 s 10 s into the upload. The code
/// before fast retransmit took 81.4 s; the first fast retransmit, 87.1 s --
/// the wake's slow start overran the queue and the recovery that followed
/// repaired its holes one round trip apart. No more than 5 % over the old.
///
/// One seed is the whole distribution here: the road draws nothing that
/// matters (no loss, jitter or reordering), and seeds 1..=32 all take
/// 73.07 s (slice 4 task 9's sweep), 14 % under the bound -- a datagram
/// the upload does not carry cannot move it by reshuffling draws.
#[test]
fn a_freeze_during_a_bulk_upload_costs_no_more_than_before_fast_retransmit() {
    let bandwidth = 125_000;
    let up = LinkSpec::new(Duration::from_millis(50)).with_bandwidth(bandwidth, Some(384 * 1024));
    let u = upload_over(
        1,
        up,
        8 * 1024 * 1024,
        Duration::from_secs(2),
        Some((Duration::from_secs(10), Duration::from_secs(3))),
    );
    eprintln!("125 KB/s, 384 KiB queue, 3 s freeze at 10 s: {u:?}");
    let took = u.took.expect("finished");
    assert!(
        took <= Duration::from_secs_f64(1.05 * 81.4),
        "{took:?}, before fast retransmit 81.4 s: {u:?}"
    );
}

/// The table behind the upload tests: 8 MiB up over 125 KB/s and 64 KB/s,
/// four queue sizes, written right after the handshake and 10 s into an idle
/// session (a PING has measured the idle 100 ms round trip by then). Spec
/// §4.15: every row -- every queue is at least 64 KiB -- at 80 % goodput or
/// better and at most 10 % sent twice. Prints the whole table before it
/// judges any row (`--nocapture` shows it). Run by default since the final
/// review of slice 2: the sixteen rows take some 3 s under the test
/// profile's `opt-level = 1`.
#[test]
fn the_slow_uplink_table_meets_the_congestion_thresholds() {
    let mut misses = Vec::new();
    for idle in [Duration::ZERO, Duration::from_secs(10)] {
        for bandwidth in [125_000u64, 64_000] {
            for queue in [64 * 1024usize, 256 * 1024, 384 * 1024, 1024 * 1024] {
                let u = bulk_upload(8 * 1024 * 1024, bandwidth, queue, idle);
                let row = format!(
                    "idle {:>2} s, {:>3} KB/s, queue {:>4} KiB: took {:>9}, goodput {:>3.0} %, \
                     resent {:>8.1} %, queue drops {:>6}, rtt {:?}",
                    idle.as_secs(),
                    bandwidth / 1000,
                    queue / 1024,
                    u.took
                        .map_or("never".into(), |t| format!("{:.1} s", t.as_secs_f64())),
                    u.goodput(bandwidth) * 100.0,
                    u.resent() * 100.0,
                    u.queue_dropped,
                    u.rtt
                );
                eprintln!("{row}");
                if u.took.is_none() || u.goodput(bandwidth) < 0.80 || u.resent() > 0.10 {
                    misses.push(row);
                }
            }
        }
    }
    assert!(
        misses.is_empty(),
        "rows under the §4.15 thresholds:\n{}",
        misses.join("\n")
    );
}

/// Final fix wave, round 3: a Doze freeze of 600 s in the middle of a write.
/// The ACKs for it wait in the socket through the freeze; on waking the
/// driver forces a PING and then reads them. Timed from the segments' send,
/// they would be one 600 s round trip: the retransmit timeout would sit at
/// its 15 s ceiling for a minute and more, and a datagram lost right after
/// waking -- the usual moment for losses on a phone -- would wait 15 s. The
/// freeze forgets the send times, as it forgets the PINGs.
#[test]
fn a_loss_right_after_a_long_freeze_is_repaired_at_the_roads_own_pace() {
    let road = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(50)));
    let mut sim = Sim::new(5, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.run_for(Duration::from_secs(5));
    let before = vec![b'a'; 8 * 1024];
    sim.send(Side::Client, 30, &before);
    sim.freeze(Side::Client, Duration::from_secs(600));
    sim.run_for(Duration::from_secs(600));
    // Awake: the forced PING is out and the stale ACKs are read.
    assert_eq!(sim.delivered(Side::Server, 30), &before[..]);
    let rto = sim.conn(Side::Client).rto_for_test();
    assert!(
        rto <= Duration::from_secs(1),
        "the freeze was not taken for a round trip: rto {rto:?}"
    );
    // A write whose datagram the road loses, right after waking.
    let lossless = LinkSpec::new(Duration::from_millis(50));
    sim.set_link(0, Side::Client, lossless.with_loss(1.0));
    let after = vec![b'b'; 100];
    sim.send(Side::Client, 30, &after);
    sim.set_link(0, Side::Client, lossless);
    let sent = sim.now();
    while sim.delivered(Side::Server, 30).len() < before.len() + after.len() {
        assert!(
            sim.now() - sent <= Duration::from_secs(1),
            "the lost write was not repaired within a second: rto {:?}",
            sim.conn(Side::Client).rto_for_test()
        );
        sim.run_for(Duration::from_millis(10));
    }
    sim.run_for(Duration::from_secs(2));
    let rto = sim.conn(Side::Client).rto_for_test();
    assert!(
        rto <= Duration::from_millis(500),
        "back near the road's 100 ms round trip: rto {rto:?}"
    );
}

/// Spec §9.2 (1.5): a keystroke typed during an 8 MiB bulk write leaves
/// before the 33rd bulk datagram of that write. It is typed at the very
/// instant of the write, the worst moment: the write opens the whole
/// `MAX_IN_FLIGHT` window (256 segments) at once. Served in stream-number
/// order with no budget, all 256 went out in front of it; now the write's
/// own flush puts out `BULK_FLUSH_BUDGET` of them and the keystroke's flush
/// puts it out first.
#[test]
fn a_keystroke_during_a_bulk_write_leaves_before_the_33rd_bulk_datagram() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20)).with_bandwidth(10_000_000, None),
    );
    let mut sim = Sim::new(9, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.conn_mut(Side::Client)
        .set_stream_class(14, StreamClass::Bulk);
    sim.record_sends();
    sim.send(Side::Client, 14, &vec![0x42; 8 * 1024 * 1024]);
    sim.send(Side::Client, 16, b"k");
    sim.run_for(Duration::from_millis(50));
    let mut bulk_before = 0usize;
    let mut keystroke_seen = false;
    for dg in sim.sent(Side::Client) {
        for f in &dg.frames {
            match f {
                StreamFrame::Data { stream_id: 16, .. } => keystroke_seen = true,
                StreamFrame::Data { stream_id: 14, .. } if !keystroke_seen => bulk_before += 1,
                _ => {}
            }
        }
        if keystroke_seen {
            break;
        }
    }
    assert!(keystroke_seen, "the keystroke went out");
    assert!(
        bulk_before <= BULK_FLUSH_BUDGET,
        "{bulk_before} bulk datagrams of the write went out before the keystroke"
    );
    assert_eq!(sim.delivered(Side::Server, 16), b"k");
}

/// Spec §4.15, the queue-delay signal: behind a queue as deep as the window
/// NewReno never loses, the window grows to 256 KiB and stands 4 s deep in a
/// 64 KB/s uplink. The delay signal keeps the standing queue near
/// `QUEUE_DELAY_CAP` once slow start is over.
#[test]
fn a_bulk_upload_behind_a_deep_uplink_queue_keeps_that_queue_near_the_cap() {
    let road = RoadSpec {
        up: LinkSpec::new(Duration::from_millis(50)).with_bandwidth(64_000, Some(384 * 1024)),
        down: LinkSpec::new(Duration::from_millis(50)),
    };
    let mut sim = Sim::new(1, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.conn_mut(Side::Client)
        .set_stream_class(30, StreamClass::Bulk);
    let data = vec![7u8; 4 * 1024 * 1024];
    sim.send(Side::Client, 30, &data);
    let start = sim.now();
    let mut worst = Duration::ZERO;
    while sim.delivered(Side::Server, 30).len() < data.len() {
        assert!(
            sim.now() - start < Duration::from_secs(300),
            "the upload finished"
        );
        sim.run_for(Duration::from_millis(10));
        if sim.now() - start > Duration::from_secs(20) {
            worst = worst.max(sim.link_backlog(0, Side::Client));
        }
    }
    eprintln!("worst uplink queue after the first 20 s: {worst:?}");
    assert!(
        worst <= QUEUE_DELAY_CAP + Duration::from_millis(300),
        "the queue stood {worst:?} deep"
    );
}

/// The server writes `bytes` of output, and 700 ms in the road it goes by
/// (`slow_ms` each way, `bandwidth` both ways behind a 1 MiB queue) dies
/// both ways; the client moves at once onto its verified spare (`fast_ms`,
/// the same bandwidth). How long the rest of the output took after the
/// move, and how the server's window was cut on the way.
fn output_across_a_move(
    slow_ms: u64,
    fast_ms: u64,
    bandwidth: u64,
    bytes: usize,
) -> (Duration, Cuts) {
    const OUTPUT: u8 = 16;
    let link =
        |ms| LinkSpec::new(Duration::from_millis(ms)).with_bandwidth(bandwidth, Some(1 << 20));
    let roads = vec![
        RoadSpec::symmetric(link(slow_ms)),
        RoadSpec::symmetric(link(fast_ms)),
    ];
    let mut sim = Sim::new(1, roads);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    let (_, a) = sim.road(0);
    let (_, b) = sim.road(1);
    sim.conn_mut(Side::Client).set_paths(vec![a, b]);
    sim.run_for(Duration::from_secs(8));
    let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    sim.send(Side::Server, OUTPUT, &data);
    sim.run_for(Duration::from_millis(700));
    for side in [Side::Client, Side::Server] {
        sim.set_link(0, side, link(slow_ms).with_loss(1.0));
    }
    let moved = sim.now();
    let now = sim.instant();
    sim.conn_mut(Side::Client)
        .use_road(b, now)
        .expect("the spare is verified");
    while sim.delivered(Side::Client, OUTPUT).len() < bytes {
        assert!(
            sim.now() - moved < Duration::from_secs(60),
            "the output finished"
        );
        sim.run_for(Duration::from_millis(2));
    }
    assert_eq!(sim.delivered(Side::Client, OUTPUT), &data[..]);
    (sim.now() - moved, sim.conn(Side::Server).cuts_for_test())
}

/// Final review of slice 2, Important 2 (spec §4.15: a move starts
/// afresh). The client restarted its window on the move, the server did
/// not: onto a faster road, the answers to its resends came sooner than the
/// old road's base delay, its genuine timeouts were undone -- every one of
/// three at 40 -> 5 ms -- until a PONG lowered the base. Before: 2.72 s after
/// the move at 40 -> 5 ms and 1 MB/s (2 MiB), 2.74 s at 30 -> 10 ms and
/// 500 KB/s (1 MiB); with the server's restart on the move 1.70 and 1.60 s,
/// no timeout at all. The bounds: those times plus 10 %, and no timeout of
/// the server's undone.
///
/// One seed is the whole distribution here too: neither road draws
/// anything that matters, and seeds 1..=32 all give 1.700 s and 1.604 s,
/// no timeout undone (slice 4 task 9's sweep).
#[test]
fn a_move_starts_the_servers_window_afresh() {
    for (slow, fast, bandwidth, bytes, after) in [
        (40, 5, 1_000_000, 2 << 20, 1.70),
        (30, 10, 500_000, 1 << 20, 1.604),
    ] {
        let (took, cuts) = output_across_a_move(slow, fast, bandwidth, bytes);
        eprintln!("{slow} -> {fast} ms, {bandwidth} B/s: {took:?} after the move, {cuts:?}");
        assert!(
            took <= Duration::from_secs_f64(1.1 * after),
            "{slow} -> {fast} ms: {took:?}, with the restart {after} s"
        );
        assert_eq!(cuts.timeouts_undone, 0, "{slow} -> {fast} ms: {cuts:?}");
    }
}

/// The server writes 4 MiB of output over one road, 30 ms each way at
/// 1 MB/s behind a 1 MiB queue; 700 ms in, `rebinding` -- if any -- the
/// client's NAT gives it a new port on the same address, the old mapping
/// still delivering (`true`) or not (`false`). How long the output took
/// from the write, the server's cuts and its retransmits.
fn output_across_a_rebinding(rebinding: Option<bool>) -> (Duration, Cuts, u32) {
    const OUTPUT: u8 = 16;
    let bytes = 4 << 20;
    let link = LinkSpec::new(Duration::from_millis(30)).with_bandwidth(1_000_000, Some(1 << 20));
    let mut sim = Sim::new(1, vec![RoadSpec::symmetric(link)]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.run_for(Duration::from_secs(8));
    let data: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let start = sim.now();
    sim.send(Side::Server, OUTPUT, &data);
    sim.run_for(Duration::from_millis(700));
    let (client, _) = sim.road(0);
    if let Some(old_mapping_lives) = rebinding {
        sim.rebind_client_port(0, client.port() + 1, old_mapping_lives);
    }
    while sim.delivered(Side::Client, OUTPUT).len() < bytes {
        assert!(
            sim.now() - start < Duration::from_secs(60),
            "the output finished"
        );
        sim.run_for(Duration::from_millis(2));
    }
    assert_eq!(sim.delivered(Side::Client, OUTPUT), &data[..]);
    if rebinding.is_some() {
        assert_eq!(
            sim.conn(Side::Server).peer(),
            Some(SocketAddr::new(client.ip(), client.port() + 1)),
            "the server followed the new port"
        );
    }
    let server = sim.conn(Side::Server);
    (
        sim.now() - start,
        server.cuts_for_test(),
        server.stats(sim.instant()).retransmits,
    )
}

/// Round 3 of the final fix wave (the controller's ruling): a new port on
/// the same address restarts the server's window too. The realistic port
/// change is the client's own new socket -- a network callback, a Doze
/// wake -- which closes the old one: what the server sent to the old port
/// before it followed is lost in one burst (28 segments here), and NewReno
/// without selective acknowledgements repairs a burst one segment per round
/// trip. With the window kept (round 2) the output took 6.14 s; restarted,
/// the flight goes out again at once: 4.73 s, against 4.49 s with no
/// rebinding. The bound: 4.8 s.
#[test]
fn a_rebinding_whose_old_mapping_died_is_repaired_by_the_servers_restart() {
    let (plain, _, _) = output_across_a_rebinding(None);
    let (took, cuts, resent) = output_across_a_rebinding(Some(false));
    eprintln!("no rebinding {plain:?}; old mapping dead {took:?}, {resent} resent, {cuts:?}");
    assert!(
        took <= Duration::from_millis(4_800),
        "{took:?}; with the window kept 6.14 s, with no rebinding {plain:?}"
    );
}

/// The price of that rule, where the old mapping still delivers -- a NAT
/// that remaps in the middle of output, rare: a slow start and the flight
/// resent (256 segments, one retransmit timeout on the way), 4.76 s
/// against 4.49 s with no rebinding; 0.2 to 0.7 s over the other rows
/// measured (30 ms at 500 KB/s, 50 ms at 250 KB/s, 100 ms at 1 MB/s).
/// Accepted. The bound: 0.3 s over no rebinding.
#[test]
fn a_rebinding_whose_old_mapping_lives_costs_the_server_one_slow_start() {
    let (plain, _, _) = output_across_a_rebinding(None);
    let (took, cuts, resent) = output_across_a_rebinding(Some(true));
    eprintln!("no rebinding {plain:?}; old mapping alive {took:?}, {resent} resent, {cuts:?}");
    assert!(
        resent > 0,
        "the flight went out again under the fresh window"
    );
    assert!(
        took <= plain + Duration::from_millis(300),
        "{took:?} against {plain:?} with no rebinding"
    );
}

/// The slice-1 review: during the image upload over a 64 KB/s road the
/// PINGs and road checks waited ~4 s behind the bulk data, and the dead-road
/// rule moved the session onto a verified spare. With control first in every
/// flush (§4.8), the congestion window (§4.15) and the queue-delay bound, the
/// session stays on its road -- behind a queue smaller than the window
/// (losses) and one deeper than it (none).
#[test]
fn a_slow_uplink_upload_keeps_the_session_on_its_road_next_to_a_verified_spare() {
    for queue in [64 * 1024usize, 384 * 1024] {
        let slow = RoadSpec {
            up: LinkSpec::new(Duration::from_millis(50)).with_bandwidth(64_000, Some(queue)),
            down: LinkSpec::new(Duration::from_millis(50)),
        };
        let fast = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(10)));
        let mut sim = Sim::new(11, vec![slow, fast]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        let (_, slow_addr) = sim.road(0);
        let (_, fast_addr) = sim.road(1);
        sim.conn_mut(Side::Client)
            .set_paths(vec![slow_addr, fast_addr]);
        let verified = |sim: &Sim| {
            sim.conn(Side::Client)
                .roads(sim.instant())
                .iter()
                .any(|r| r.addr == fast_addr && r.state == PathState::Verified)
        };
        let until = sim.now() + Duration::from_secs(10);
        while !verified(&sim) && sim.now() < until {
            sim.run_for(Duration::from_millis(10));
        }
        assert!(
            verified(&sim),
            "the spare was verified -- or the test proves nothing"
        );
        sim.conn_mut(Side::Client)
            .set_stream_class(14, StreamClass::Bulk);
        let data = vec![5u8; 4 * 1024 * 1024];
        sim.send(Side::Client, 14, &data);
        let start = sim.now();
        let mut unanswered_ticks = 0u32;
        while sim.delivered(Side::Server, 14).len() < data.len() {
            assert!(
                sim.now() - start < Duration::from_secs(300),
                "queue {} KiB: the upload finished",
                queue / 1024
            );
            sim.run_for(Duration::from_millis(10));
            assert_eq!(
                sim.conn(Side::Client).active_path(),
                Some(slow_addr),
                "queue {} KiB: the session left its road {:?} into the upload",
                queue / 1024,
                sim.now() - start
            );
            unanswered_ticks += u32::from(sim.conn(Side::Client).ping_unanswered());
        }
        eprintln!(
            "queue {} KiB: took {:?}; 10 ms ticks with a PING unanswered: {unanswered_ticks}",
            queue / 1024,
            sim.now() - start
        );
        // A PING unanswered is the first half of the second move trigger;
        // behind the 4 s queue it stood so for 51 s of the upload.
        assert_eq!(
            unanswered_ticks,
            0,
            "queue {} KiB: the PINGs waited behind the upload",
            queue / 1024
        );
    }
}

/// Spec §4.15: a keystroke during a bulk transfer arrives within the round
/// trip of the moment plus at most two segments on the line. It goes out
/// ahead of any bulk data of its own flush, so what stands in front of it is
/// the queue already on the line -- and that queue is kept near
/// `QUEUE_DELAY_CAP`.
#[test]
fn a_keystroke_during_a_slow_upload_waits_only_for_the_queue_already_on_the_line() {
    let bandwidth = 64_000u64;
    let one_way = Duration::from_millis(50);
    let road = RoadSpec {
        up: LinkSpec::new(one_way).with_bandwidth(bandwidth, Some(384 * 1024)),
        down: LinkSpec::new(one_way),
    };
    let mut sim = Sim::new(4, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.conn_mut(Side::Client)
        .set_stream_class(14, StreamClass::Bulk);
    sim.send(Side::Client, 14, &vec![1u8; 4 * 1024 * 1024]);
    sim.run_for(Duration::from_secs(30));
    // A full DATA datagram on the wire: 1024 payload bytes plus framing, AEAD
    // tag and header, rounded up.
    let segment_time = Duration::from_nanos(1_100 * 1_000_000_000 / bandwidth);
    for k in 0..5u8 {
        let backlog = sim.link_backlog(0, Side::Client);
        let typed = sim.now();
        let before = sim.delivered(Side::Server, 16).len();
        sim.send(Side::Client, 16, &[k]);
        while sim.delivered(Side::Server, 16).len() == before {
            sim.run_for(Duration::from_millis(1));
            assert!(
                sim.now() - typed < Duration::from_secs(10),
                "the keystroke arrived"
            );
        }
        let took = sim.now() - typed;
        eprintln!("keystroke {k}: {took:?} with {backlog:?} of queue ahead of it");
        assert!(
            took <= one_way + backlog + 2 * segment_time + Duration::from_millis(2),
            "keystroke {k}: {took:?} with {backlog:?} of queue ahead of it"
        );
        assert!(
            took <= one_way + QUEUE_DELAY_CAP + Duration::from_millis(400),
            "keystroke {k}: {took:?}"
        );
        sim.run_for(Duration::from_secs(3));
    }
}

/// Task 4 re-review (New 1), the traced case: 125 KB/s up behind a 384 KiB
/// queue, 0.03 % loss, 16 MiB written 2 s into the session, seed 3 -- a road
/// that reorders nothing. With the smallest round trip of the last 30 s (and
/// no delay signal yet), the standing queue became "the road" (2.176 s), the
/// repair of the connection's first loss was answered 2.159 s after it --
/// the queue drains a little behind a hole -- and the loss was taken for
/// reordering: its halving skipped, the duplicate threshold raised to 64,
/// 143.34 s. Against the base delay of ten minutes no loss is undone, with
/// the delay signal or without it: the threshold never leaves 3. (An undo
/// raises it, and only a timeout or a restart lowers it, neither within
/// 10 ms of the undo.)
#[test]
fn a_real_loss_behind_a_standing_queue_is_not_taken_for_reordering() {
    let up = LinkSpec::new(Duration::from_millis(50))
        .with_bandwidth(125_000, Some(384 * 1024))
        .with_loss(0.0003);
    let mut highest = 0;
    let u = upload_watched(
        3,
        up,
        16 * 1024 * 1024,
        Duration::from_secs(2),
        None,
        |sim| {
            highest = highest.max(sim.conn(Side::Client).duplicate_threshold_for_test());
        },
    );
    eprintln!("125 KB/s, 384 KiB queue, loss 0.03 %, seed 3: {u:?}, threshold at most {highest}");
    assert!(u.took.is_some(), "the upload finished: {u:?}");
    assert_eq!(highest, 3, "a loss was taken for reordering: {u:?}");
}

/// The same, with the delay signal on and a queue deeper than the stream
/// window: its cuts leave a standing queue, and the smallest round trip of
/// the last 30 s took that queue for the road within a minute (469 ms on
/// this 100 ms road). A loss 1.3 s after a cut held the window through its
/// duplicates while the queue drained a few segments below that level, and
/// the repair was answered 2.4 ms sooner than the "road": taken for
/// reordering 101 s in -- as in 24 of 60 lossy six-minute uploads at
/// 32-250 KB/s, 0.03-0.3 % loss. Against the base delay of ten minutes,
/// none of them.
#[test]
fn a_loss_soon_after_a_delay_cut_is_not_taken_for_reordering() {
    let up = LinkSpec::new(Duration::from_millis(50))
        .with_bandwidth(32_000, Some(1024 * 1024))
        .with_loss(0.0003);
    let mut highest = 0;
    let u = upload_watched(2, up, 32_000 * 180, Duration::ZERO, None, |sim| {
        highest = highest.max(sim.conn(Side::Client).duplicate_threshold_for_test());
    });
    eprintln!("32 KB/s, 1 MiB queue, loss 0.03 %, seed 2: {u:?}, threshold at most {highest}");
    assert!(u.took.is_some(), "the upload finished: {u:?}");
    assert_eq!(highest, 3, "a loss was taken for reordering: {u:?}");
}

/// One minute of [`long_upload`].
#[derive(Debug)]
struct Minute {
    /// Payload bytes delivered in it.
    delivered: usize,
    /// The deepest the uplink queue stood in it, sampled every 10 ms.
    deepest_queue: Duration,
    /// The client's base delay at its end.
    base_delay: Option<Duration>,
    /// Whether a base probe started in it.
    probed: bool,
    /// The server's congestion window and threshold at its end.
    server_window: (usize, Option<usize>),
}

/// A keystroke [`long_upload`] typed during a base probe.
#[derive(Debug)]
struct ProbeKeystroke {
    /// Typed once the probe's queue had drained, not as it began.
    emptied: bool,
    /// The uplink queue in front of it as it was typed.
    backlog: Duration,
    /// From the typing to the delivery.
    took: Duration,
}

/// What [`long_upload`] saw.
#[derive(Debug)]
struct LongRun {
    minutes: Vec<Minute>,
    /// One as each probe began, one once its queue had drained.
    keystrokes: Vec<ProbeKeystroke>,
    /// How long, over all probes, a PING stood unanswered.
    unanswered_in_probes: Duration,
    /// The longest a probe of the client's lasted, and whether one was still
    /// running at the end.
    longest_probe: Duration,
    probing_at_the_end: bool,
    /// The server's cuts. It only writes a terminal's output:
    /// application-limited, its round trips carrying the upload's queue.
    server_cuts: Cuts,
    /// The client's.
    client_cuts: Cuts,
}

/// A bulk upload that never runs dry: the client keeps 2 MiB ahead of what
/// was delivered, for `minutes` minutes, over `road` from seed 1, while the
/// server writes a terminal's output, 1 KiB a second. `at_minute(sim, m)`
/// runs as minute `m` (from 0) begins. As a base probe begins, and again
/// once its queue has drained, a keystroke is typed on an interactive
/// stream; while one is on its way the run steps by 1 ms.
fn long_upload(road: RoadSpec, minutes: u64, at_minute: impl FnMut(&mut Sim, u64)) -> LongRun {
    long_upload_with(road, minutes, at_minute, |_| {})
}

/// [`long_upload`], with `at_probe(sim)` run as each of the client's base
/// probes begins.
fn long_upload_with(
    road: RoadSpec,
    minutes: u64,
    mut at_minute: impl FnMut(&mut Sim, u64),
    mut at_probe: impl FnMut(&mut Sim),
) -> LongRun {
    const STREAM: u8 = 30;
    const KEYS: u8 = 16;
    const OUTPUT: u8 = 18;
    let mut sim = Sim::new(1, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.run_for(Duration::from_secs(2));
    sim.conn_mut(Side::Client)
        .set_stream_class(STREAM, StreamClass::Bulk);
    let chunk = vec![3u8; 1024 * 1024];
    let mut queued = 0;
    let start = sim.now();
    let mut run = LongRun {
        minutes: Vec::new(),
        keystrokes: Vec::new(),
        unanswered_in_probes: Duration::ZERO,
        longest_probe: Duration::ZERO,
        probing_at_the_end: false,
        server_cuts: Cuts::default(),
        client_cuts: Cuts::default(),
    };
    let mut probe = None;
    let mut probe_began = Duration::ZERO;
    let mut next_output = start;
    let mut keys_typed = 0;
    // (typed at, queue in front, typed once emptied, bytes delivered with it)
    let mut typed: Vec<(Duration, Duration, bool, usize)> = Vec::new();
    for m in 0..minutes {
        at_minute(&mut sim, m);
        let before = sim.delivered_len(Side::Server, STREAM);
        let end = start + Duration::from_secs(60 * (m + 1));
        let mut deepest_queue = Duration::ZERO;
        let mut probed = false;
        while sim.now() < end {
            if queued - sim.delivered_len(Side::Server, STREAM) < 2 * chunk.len() {
                sim.send(Side::Client, STREAM, &chunk);
                queued += chunk.len();
            }
            if sim.now() >= next_output {
                sim.send(Side::Server, OUTPUT, &[b'o'; 1024]);
                next_output += Duration::from_secs(1);
            }
            let step = Duration::from_millis(if typed.is_empty() { 10 } else { 1 });
            sim.run_for(step);
            deepest_queue = deepest_queue.max(sim.link_backlog(0, Side::Client));
            let client = sim.conn(Side::Client);
            let now_probe = client.base_probe_for_test();
            if now_probe.is_some() && client.ping_unanswered() {
                run.unanswered_in_probes += step;
            }
            let keys = sim.delivered(Side::Server, KEYS).len();
            let now = sim.now();
            typed.retain(|&(at, backlog, emptied, with)| {
                let arrived = keys >= with;
                if arrived {
                    run.keystrokes.push(ProbeKeystroke {
                        emptied,
                        backlog,
                        took: now - at,
                    });
                }
                !arrived
            });
            let began = probe.is_none() && now_probe.is_some();
            let emptied = probe.is_some_and(|p: Probe| p.emptied_at.is_none())
                && now_probe.is_some_and(|p| p.emptied_at.is_some());
            probed |= began;
            if began {
                probe_began = sim.now();
                at_probe(&mut sim);
            }
            if now_probe.is_some() {
                run.longest_probe = run.longest_probe.max(sim.now() - probe_began);
            }
            if began || emptied {
                keys_typed += 1;
                typed.push((now, sim.link_backlog(0, Side::Client), emptied, keys_typed));
                sim.send(Side::Client, KEYS, b"k");
            }
            probe = now_probe;
        }
        // Only counted: a long fast run would otherwise hold every byte.
        let delivered = sim.delivered_len(Side::Server, STREAM) - before;
        sim.forget_delivered(Side::Server, STREAM);
        run.minutes.push(Minute {
            delivered,
            deepest_queue,
            base_delay: sim.conn(Side::Client).base_delay_for_test(),
            probed,
            server_window: sim.conn(Side::Server).congestion_window_for_test(),
        });
    }
    run.probing_at_the_end = sim.conn(Side::Client).base_probe_for_test().is_some();
    run.server_cuts = sim.conn(Side::Server).cuts_for_test();
    run.client_cuts = sim.conn(Side::Client).cuts_for_test();
    run
}

/// A full DATA datagram's time on a `bandwidth` bytes/s line: 1024 payload
/// bytes plus framing, AEAD tag and header, rounded up.
fn segment_time(bandwidth: u64) -> Duration {
    Duration::from_nanos(1_100 * 1_000_000_000 / bandwidth)
}

/// 32 KB/s up behind a 1 MiB queue -- deeper than the stream window, which
/// never fills it -- 50 ms one way. Half the slice-1 road's speed, so ten
/// minutes cost half the simulation; the delay signal's dynamics are the
/// same in time.
fn deep_slow_uplink() -> RoadSpec {
    RoadSpec {
        up: LinkSpec::new(Duration::from_millis(50)).with_bandwidth(32_000, Some(1024 * 1024)),
        down: LinkSpec::new(Duration::from_millis(50)),
    }
}

/// Forty minutes of upload over [`deep_slow_uplink`], once for all the tests
/// that read it.
fn forty_minutes_behind_a_deep_queue() -> &'static LongRun {
    static RUN: OnceLock<LongRun> = OnceLock::new();
    RUN.get_or_init(|| {
        let run = long_upload(deep_slow_uplink(), 40, |_, _| {});
        for (m, minute) in run.minutes.iter().enumerate() {
            eprintln!(
                "deep queue, minute {:>2}: {:>5.1} KB/s, deepest queue {:>4.0} ms, base {:?}{}",
                m + 1,
                minute.delivered as f64 / 60_000.0,
                minute.deepest_queue.as_secs_f64() * 1000.0,
                minute.base_delay,
                if minute.probed { ", probe" } else { "" }
            );
        }
        eprintln!("deep queue: {:?}", run.keystrokes);
        run
    })
}

/// Spec §4.15, the base delay and its probe: behind a deep buffer the delay
/// signal's halving never empties the queue -- right after a cut it still
/// stands about 200 ms deep -- so every round trip of a long upload carries
/// it. Taken from those, the base rose each time its minute left the
/// history -- 102 ms, then 303, 402, 466, 493 ms at 10, 20, 30, 40 minutes,
/// the queue 535 ms up to 934 ms -- and with a 30 s window within the first
/// minute (935 ms in the second). A probe every nine minutes drains the queue
/// and measures the road again: the base stays within a segment's time on
/// the line (34 ms here) of the road's own 100 ms, and the queue near
/// `QUEUE_DELAY_CAP`, for all forty minutes.
#[test]
fn the_queue_delay_bound_does_not_creep() {
    let run = forty_minutes_behind_a_deep_queue();
    let road = Duration::from_millis(100);
    for (m, minute) in run.minutes.iter().enumerate().skip(1) {
        assert!(
            minute.deepest_queue <= QUEUE_DELAY_CAP + Duration::from_millis(100),
            "minute {}: {minute:?}",
            m + 1
        );
        let base = minute.base_delay.expect("measured");
        assert!(
            base <= road + segment_time(32_000) + Duration::from_millis(2),
            "minute {}: {minute:?}",
            m + 1
        );
    }
    let probes = run.minutes.iter().filter(|m| m.probed).count();
    assert!(probes >= 3, "{probes} probes -- or the test proves nothing");
}

/// Spec §4.15, the base delay: a road that gets 300 ms slower without a move
/// (a handover behind the same address) keeps its old base delay for up to
/// ten minutes, and the delay signal leaves it only 200 ms of queue in place
/// of 500 ms -- less than its new bandwidth-delay product, so each cut drains
/// the line. Once the fast minutes have left the history the road is
/// measured as it is and the upload runs at full speed again; a base kept
/// forever would hold it at the lower speed for good.
#[test]
fn a_road_that_gets_slower_without_a_move_gets_its_full_speed_back_within_ten_minutes() {
    let road = deep_slow_uplink();
    let table = long_upload(road, 12, |sim, m| {
        if m == 2 {
            let down = road.down;
            sim.set_link(
                0,
                Side::Server,
                LinkSpec {
                    delay: down.delay + Duration::from_millis(300),
                    ..down
                },
            );
        }
    })
    .minutes;
    for (m, minute) in table.iter().enumerate() {
        eprintln!("minute {}: {minute:?}", m + 1);
    }
    let full = table[1].delivered as f64;
    let share = |m: usize| table[m].delivered as f64 / full;
    assert!(
        share(3) <= 0.97,
        "the stale base cost nothing -- or the test proves nothing: {:.3}",
        share(3)
    );
    // The road got slower as table[2] began: table[11] is the tenth minute
    // after that.
    assert!(
        share(11) >= 0.995,
        "ten minutes after the road got slower: {:.3} of full speed",
        share(11)
    );
}

/// The probe's cost, on the road above: the minute a probe begins in
/// delivers at least 99 % of the minute before it. The queue drains at the
/// road's rate; what the probe costs is the round trip measured with two
/// segments out and the slow start back -- a handful of 100 ms round trips.
/// Measured: 30.6 against 30.7 KB/s.
#[test]
fn a_base_probe_costs_little_of_its_minute() {
    let run = forty_minutes_behind_a_deep_queue();
    assert_probes_cost_at_most(run, 0.01);
}

/// Assert that the minute a probe began in, and the one after it -- a probe
/// that begins late in its minute costs the next -- each delivered at least
/// `1 - share` of the minute before the probe.
fn assert_probes_cost_at_most(run: &LongRun, share: f64) {
    assert!(
        run.minutes.iter().any(|m| m.probed),
        "no probe ran -- or the test proves nothing"
    );
    let minutes = &run.minutes;
    for m in 1..minutes.len() {
        if minutes[m].probed {
            let before = minutes[m - 1].delivered as f64;
            for after in &minutes[m..(m + 2).min(minutes.len())] {
                let kept = after.delivered as f64 / before;
                assert!(
                    kept >= 1.0 - share,
                    "a probe in minute {}: {:.1} % of the minute before it",
                    m + 1,
                    kept * 100.0
                );
            }
        }
    }
}

/// Spec §4.15: during a probe the interactive class keeps its own two
/// segments and control frames never wait for the window. A keystroke typed
/// as a probe begins waits only for the queue already on the line, as it
/// would without the probe; one typed once the queue has drained arrives
/// within the road's one way and its own time on the line. No PING stands
/// unanswered during a probe.
#[test]
fn a_keystroke_during_a_base_probe_waits_only_for_the_queue_on_the_line() {
    let run = forty_minutes_behind_a_deep_queue();
    assert_keystrokes_during_probes(run, Duration::from_millis(50), 32_000);
}

/// Assert the keystroke and PING bounds above on `run`, a road `one_way`
/// each way and `bandwidth` up.
fn assert_keystrokes_during_probes(run: &LongRun, one_way: Duration, bandwidth: u64) {
    let two_segments = 2 * segment_time(bandwidth);
    for k in &run.keystrokes {
        assert!(
            k.took <= one_way + k.backlog + two_segments + Duration::from_millis(2),
            "{k:?}"
        );
        if k.emptied {
            assert!(k.took <= 2 * one_way + two_segments, "{k:?}");
        }
    }
    assert!(
        run.keystrokes.iter().any(|k| k.emptied) && run.keystrokes.iter().any(|k| !k.emptied),
        "keystrokes at both moments of a probe -- or the test proves nothing: {:?}",
        run.keystrokes
    );
    assert_eq!(run.unanswered_in_probes, Duration::ZERO);
}

/// A window the stream holds (spec §4.15): 500 KB/s up, 50 ms one way, a
/// queue deeper than anything we send. The stream's 256 KiB stand 446 ms
/// deep -- under the cap, so the delay signal never cuts, and nothing drains
/// that queue. Without the probe the base became the queue at the tenth
/// minute (100 ms to 544 ms), and a genuine loss would again be taken for
/// reordering. With it the base stays the road's, the probe's minute keeps
/// 99.2 % (476.5 against 480.3 KB/s), keystrokes wait only for the queue on
/// the line, and no PING goes unanswered.
///
/// Eleven minutes at 500 KB/s: the probe cannot come sooner than nine, and a
/// road the stream window holds below the cap is a fast one. Some 8 s in
/// the test build (lightly optimized: see the workspace `Cargo.toml`).
#[test]
fn a_window_the_stream_holds_is_probed_too() {
    let one_way = Duration::from_millis(50);
    let road = RoadSpec {
        up: LinkSpec::new(one_way).with_bandwidth(500_000, Some(4 * 1024 * 1024)),
        down: LinkSpec::new(one_way),
    };
    let run = long_upload(road, 11, |_, _| {});
    for (m, minute) in run.minutes.iter().enumerate() {
        eprintln!("minute {}: {minute:?}", m + 1);
    }
    eprintln!("{:?}", run.keystrokes);
    let base = run.minutes[10].base_delay.expect("measured");
    assert!(
        base <= 2 * one_way + segment_time(500_000) + Duration::from_millis(2),
        "the base became {base:?}"
    );
    assert!(run.minutes.iter().any(|m| m.probed), "a probe ran");
    assert_probes_cost_at_most(&run, 0.015);
    assert_keystrokes_during_probes(&run, one_way, 500_000);
}

/// Task 5 review round 2 (ruling on Important 1 and Minor 2): the server
/// writes a terminal's output, 1 KiB a second, all through the forty-minute
/// upload. Its ACK-timed round trips and its PONGs come back up behind the
/// upload's queue -- up to 535 ms of it, over the cap -- and never near its
/// base. An application-limited sender is not what stands in that queue:
/// the delay signal never cuts it, and its due probes count as done without
/// touching its window.
///
/// Round 3: as the upload's slow start first builds its queue, the ACKs of
/// the output come back later than the idle road's retransmit timeout, and
/// timeouts fire for nothing. Before, the second of them left the window at
/// one segment for all forty minutes: an output that fits in the allowance
/// never counted as held by the window. Now the first is undone -- its ACK
/// came 81 ms after the resend, sooner than the base -- and the window grows
/// back on the allowance to what the output needs. The others stand: their
/// ACKs came later than the base after the resend, held by the same queue
/// on the way back as any answer to the resend would be, with one segment
/// in flight -- nothing without timestamps tells those apart.
#[test]
fn a_client_upload_does_not_cut_the_servers_terminal_output() {
    let run = forty_minutes_behind_a_deep_queue();
    assert!(
        run.minutes
            .iter()
            .any(|m| m.deepest_queue > QUEUE_DELAY_CAP),
        "the server's round trips crossed a queue above the cap -- or the test proves nothing"
    );
    eprintln!("server cuts: {:?}", run.server_cuts);
    assert_eq!(
        (run.server_cuts.delay_signal, run.server_cuts.probes),
        (0, 0),
        "{:?}",
        run.server_cuts
    );
    assert!(
        run.server_cuts.timeouts_undone >= 1,
        "{:?}",
        run.server_cuts
    );
    for (m, minute) in run.minutes.iter().enumerate() {
        assert!(
            minute.server_window.0 > SEGMENT,
            "minute {}: the server's window {:?}",
            m + 1,
            minute.server_window
        );
    }
}

/// Task 5 round 3: a timeout that was no mistake stays a cut. Both ways of a
/// 125 KB/s road die for two seconds of a bulk upload and come back: the
/// timeouts of the outage fire, the first ACK after it answers a resend, and
/// none of them is undone -- the window starts again from one segment under
/// a threshold halved, and the upload completes.
#[test]
fn a_real_timeout_on_a_road_that_died_is_not_undone() {
    let link = LinkSpec::new(Duration::from_millis(50)).with_bandwidth(125_000, Some(384 * 1024));
    let mut sim = Sim::new(1, vec![RoadSpec::symmetric(link)]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.run_for(Duration::from_secs(2));
    sim.conn_mut(Side::Client)
        .set_stream_class(30, StreamClass::Bulk);
    let data = vec![5u8; 2 * 1024 * 1024];
    sim.send(Side::Client, 30, &data);
    sim.run_for(Duration::from_secs(3));
    let threshold_before = sim.conn(Side::Client).congestion_window_for_test().1;
    for side in [Side::Client, Side::Server] {
        sim.set_link(0, side, link.with_loss(1.0));
    }
    sim.run_for(Duration::from_secs(2));
    for side in [Side::Client, Side::Server] {
        sim.set_link(0, side, link);
    }
    sim.run_for(Duration::from_secs(1));
    let (cwnd, threshold) = sim.conn(Side::Client).congestion_window_for_test();
    let cuts = sim.conn(Side::Client).cuts_for_test();
    eprintln!("after the outage: window {cwnd}, threshold {threshold:?} (was {threshold_before:?}), {cuts:?}");
    assert!(cuts.timeouts >= 1, "{cuts:?}");
    assert_eq!(cuts.timeouts_undone, 0, "{cuts:?}");
    assert!(
        threshold < threshold_before,
        "{threshold:?} after {threshold_before:?}"
    );
    let start = sim.now();
    while sim.delivered(Side::Server, 30).len() < data.len() {
        assert!(
            sim.now() - start < Duration::from_secs(60),
            "the upload finished"
        );
        sim.run_for(Duration::from_millis(10));
    }
    assert_eq!(sim.conn(Side::Client).cuts_for_test().timeouts_undone, 0);
}

/// Task 5 round 3: a terminal session after a real timeout -- the way down
/// dead for 1.5 s under its output -- starts again from a few segments and a
/// threshold at half the initial window. Its later bursts of output are held
/// by the window, and each grows it: slow start to the threshold within the
/// first burst, congestion avoidance after, every burst sooner than the one
/// before. Measured: 30 KiB took 178 ms before the loss, then 406, 298, 281,
/// 264 and 219 ms, the window 3, 8, 10, 12 and 13 KiB before them.
#[test]
fn a_terminal_session_regrows_its_window_after_a_real_timeout() {
    const OUTPUT: u8 = 16;
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(50)).with_bandwidth(250_000, Some(256 * 1024)),
    );
    let mut sim = Sim::new(1, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    sim.send(Side::Server, OUTPUT, b"$ ");
    sim.run_for(Duration::from_secs(10));
    let output = vec![9u8; 30 * 1024];
    let burst = |sim: &mut Sim| {
        let before = sim.delivered(Side::Client, OUTPUT).len();
        let t = sim.now();
        sim.send(Side::Server, OUTPUT, &output);
        while sim.delivered(Side::Client, OUTPUT).len() < before + output.len() {
            sim.run_for(Duration::from_millis(1));
        }
        let took = sim.now() - t;
        sim.run_for(Duration::from_secs(10));
        took
    };
    let mut steady = Duration::ZERO;
    for _ in 0..3 {
        steady = burst(&mut sim);
    }
    sim.set_link(0, Side::Server, road.down.with_loss(1.0));
    sim.send(Side::Server, OUTPUT, &[1u8; 4 * 1024]);
    sim.run_for(Duration::from_millis(1500));
    sim.set_link(0, Side::Server, road.down);
    sim.run_for(Duration::from_secs(5));
    let cuts = sim.conn(Side::Server).cuts_for_test();
    let (cwnd, threshold) = sim.conn(Side::Server).congestion_window_for_test();
    assert!(
        cuts.timeouts >= 1 && cuts.timeouts_undone == 0,
        "a real timeout: {cuts:?}"
    );
    assert!(
        cwnd <= 4 * SEGMENT && threshold.is_some(),
        "({cwnd}, {threshold:?})"
    );
    let mut windows = vec![cwnd];
    let mut took = Vec::new();
    for _ in 0..5 {
        took.push(burst(&mut sim));
        windows.push(sim.conn(Side::Server).congestion_window_for_test().0);
    }
    eprintln!("steady {steady:?}; after the timeout {took:?}, windows {windows:?}");
    assert!(
        windows[1] >= 2 * windows[0],
        "the first burst grew the window: {windows:?}"
    );
    assert!(windows[3] >= INITIAL_WINDOW, "{windows:?}");
    assert!(took.windows(2).all(|w| w[1] <= w[0]), "{took:?}");
    assert!(took[4] <= steady * 13 / 10, "{took:?} against {steady:?}");
}

/// Task 5 review (Important 1): a terminal session -- the server writes
/// only its output -- whose down link got 100 ms slower half a minute in,
/// without a move. Its round trips never come near the base again, and at
/// nine minutes the probe fell due on a connection with nothing of its own
/// in the queue: the window went to two segments, the threshold to half the
/// initial window, and nothing grew them back. Four 30 KiB bursts of output,
/// ten seconds apart, took 432 / 393 / 372 / 363 ms at minute 8 and 977 /
/// 598 / 581 / 572 ms at minute 11. Now the due probe counts as done: the
/// window and the bursts are the same on both sides of it.
#[test]
fn a_terminal_session_keeps_its_speed_across_the_probe_point() {
    const OUTPUT: u8 = 16;
    let session = |minute: u64| {
        let road = RoadSpec::symmetric(
            LinkSpec::new(Duration::from_millis(50)).with_bandwidth(250_000, Some(256 * 1024)),
        );
        let mut sim = Sim::new(1, vec![road]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        sim.send(Side::Server, OUTPUT, b"$ ");
        sim.run_for(Duration::from_secs(30));
        let down = road.down;
        sim.set_link(
            0,
            Side::Server,
            LinkSpec {
                delay: down.delay + Duration::from_millis(100),
                ..down
            },
        );
        let until = sim.now() + Duration::from_secs(60 * (minute - 1));
        let mut probed = false;
        while sim.now() < until {
            sim.run_for(Duration::from_millis(100));
            probed |= sim.conn(Side::Server).base_probe_for_test().is_some();
        }
        let window = sim.conn(Side::Server).congestion_window_for_test();
        let base = sim.conn(Side::Server).base_delay_for_test();
        let output = vec![9u8; 30 * 1024];
        let mut took = Vec::new();
        for _ in 0..4 {
            let before = sim.delivered(Side::Client, OUTPUT).len();
            let t = sim.now();
            sim.send(Side::Server, OUTPUT, &output);
            while sim.delivered(Side::Client, OUTPUT).len() < before + output.len() {
                sim.run_for(Duration::from_millis(1));
            }
            took.push(sim.now() - t);
            sim.run_for(Duration::from_secs(10));
        }
        eprintln!(
            "minute {minute}: window {window:?}, base {base:?}, probed {probed}, bursts {took:?}"
        );
        (window, base, probed, took)
    };
    let (window_before, _, _, before) = session(8);
    let (window_after, base, probed, after) = session(11);
    assert!(
        base >= Some(Duration::from_millis(190)),
        "the base moved to the slower road -- the run went past the probe's time: {base:?}"
    );
    assert!(!probed);
    assert_eq!(window_after, window_before);
    for (b, a) in before.iter().zip(&after) {
        assert!(
            *a <= *b + Duration::from_millis(5),
            "{before:?} then {after:?}"
        );
    }
}

/// Task 5 review (Minor 6): the probe on a lossy road. A road that loses
/// 0.05-0.5 % of the upload needs no probe in twenty minutes -- its losses
/// empty the queue often enough for the base to be seen. So the road here is
/// lossless until the first probe begins and loses 0.5 % from that moment on,
/// eleven minutes more: the probe drains and ends under loss, the upload
/// goes on, the base stays the road's, and no probe is left running.
#[test]
fn a_probe_that_meets_loss_ends_and_the_upload_goes_on() {
    let road = deep_slow_uplink();
    let run = long_upload_with(
        road,
        20,
        |_, _| {},
        |sim| sim.set_link(0, Side::Client, road.up.with_loss(0.005)),
    );
    for (m, minute) in run.minutes.iter().enumerate() {
        eprintln!(
            "lossy, minute {:>2}: {:>5.1} KB/s, deepest queue {:>4.0} ms, base {:?}{}",
            m + 1,
            minute.delivered as f64 / 60_000.0,
            minute.deepest_queue.as_secs_f64() * 1000.0,
            minute.base_delay,
            if minute.probed { ", probe" } else { "" }
        );
    }
    eprintln!(
        "lossy: longest probe {:?}, client cuts {:?}",
        run.longest_probe, run.client_cuts
    );
    assert!(
        run.minutes.iter().any(|m| m.probed),
        "no probe -- or the test proves nothing"
    );
    assert!(run.longest_probe <= Duration::from_secs(10), "{run:?}");
    assert!(!run.probing_at_the_end);
    let steady = run.minutes[1].delivered as f64;
    for (m, minute) in run.minutes.iter().enumerate() {
        let base = minute.base_delay.expect("measured");
        assert!(
            base <= Duration::from_millis(100) + segment_time(32_000) + Duration::from_millis(2),
            "minute {}: {minute:?}",
            m + 1
        );
        assert!(
            minute.delivered as f64 >= 0.8 * steady,
            "minute {}: {minute:?}",
            m + 1
        );
    }
}

/// Task 5 review (Minor 2): the server's own bulk download while the client
/// uploads. The server's round trips carry the upload's queue on the way
/// back as well as its own on the way down, and with data waiting it is cut
/// for both -- accepted: a delay signal cannot tell the two directions apart.
/// The table: the download alone and during the upload, 32 KB/s up and
/// 250 KB/s down behind 1 MiB queues, 50 ms each way. Measured: 240 KB/s
/// alone, about 30 KB/s during the upload (the server's window 8-16 KiB);
/// with the delay signal off on both sides, 2-4 KB/s behind an upload
/// queue 8.5 s deep.
/// `cargo test -p transport --release --lib a_download_during_an_upload_measured -- --ignored --nocapture`
#[test]
#[ignore]
fn a_download_during_an_upload_measured() {
    for upload in [false, true] {
        let road = RoadSpec {
            up: LinkSpec::new(Duration::from_millis(50)).with_bandwidth(32_000, Some(1024 * 1024)),
            down: LinkSpec::new(Duration::from_millis(50))
                .with_bandwidth(250_000, Some(1024 * 1024)),
        };
        let mut sim = Sim::new(1, vec![road]);
        sim.start();
        assert!(sim.run_until_live(Duration::from_secs(5)));
        sim.run_for(Duration::from_secs(2));
        sim.conn_mut(Side::Client)
            .set_stream_class(30, StreamClass::Bulk);
        sim.conn_mut(Side::Server)
            .set_stream_class(32, StreamClass::Bulk);
        let chunk = vec![3u8; 1024 * 1024];
        let (mut up_queued, mut down_queued) = (0, 0);
        for minute in 1..=4 {
            let before = sim.delivered(Side::Client, 32).len();
            let (mut deepest_up, mut deepest_down) = (Duration::ZERO, Duration::ZERO);
            let mut smallest_window = usize::MAX;
            let end = sim.now() + Duration::from_secs(60);
            while sim.now() < end {
                if upload && up_queued - sim.delivered(Side::Server, 30).len() < 2 * chunk.len() {
                    sim.send(Side::Client, 30, &chunk);
                    up_queued += chunk.len();
                }
                if down_queued - sim.delivered(Side::Client, 32).len() < 4 * chunk.len() {
                    sim.send(Side::Server, 32, &chunk);
                    down_queued += chunk.len();
                }
                sim.run_for(Duration::from_millis(10));
                deepest_up = deepest_up.max(sim.link_backlog(0, Side::Client));
                deepest_down = deepest_down.max(sim.link_backlog(0, Side::Server));
                smallest_window =
                    smallest_window.min(sim.conn(Side::Server).congestion_window_for_test().0);
            }
            eprintln!(
                "upload {upload}, minute {minute}: download {:>5.1} KB/s, deepest queue up {:>4.0} ms down {:>4.0} ms, server window {:?} (smallest {} KiB), server base {:?}",
                (sim.delivered(Side::Client, 32).len() - before) as f64 / 60_000.0,
                deepest_up.as_secs_f64() * 1000.0,
                deepest_down.as_secs_f64() * 1000.0,
                sim.conn(Side::Server).congestion_window_for_test(),
                smallest_window / 1024,
                sim.conn(Side::Server).base_delay_for_test()
            );
        }
    }
}
