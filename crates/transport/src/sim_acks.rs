//! Acknowledgements and packing in virtual time (spec §4.11, §9.2 L2,
//! §11.2): road checks travel alone; bulk data draws few acknowledgements.

use std::time::Duration;

use crate::testnet::{FrameCounts, LinkSpec, RoadSpec, Side, Sim};

/// Spec §4.11 (Review Focus 3): under bulk traffic both ways and the spare
/// road's checks, no datagram mixes a road check or its answer with any
/// other frame -- an older receiver would take such a datagram for an
/// ordinary one and move the session to its source.
#[test]
fn no_datagram_mixes_a_road_check_with_anything_else() {
    let road = RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(20)));
    let mut sim = Sim::new(1, vec![road, road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    let (_, first) = sim.road(0);
    let (_, second) = sim.road(1);
    sim.conn_mut(Side::Client).set_paths(vec![first, second]);
    sim.send(Side::Server, 20, &vec![b'o'; 2 * 1024 * 1024]);
    sim.send(Side::Client, 16, &vec![b'k'; 256 * 1024]);
    sim.run_for(Duration::from_secs(40));
    for side in [Side::Client, Side::Server] {
        let c = sim.frames_sent(side);
        assert_eq!(c.probe_mixed, 0, "{side:?}: {c:?}");
    }
    assert!(
        sim.frames_sent(Side::Client).path_probe > 0,
        "the spare was checked"
    );
    assert!(
        sim.frames_sent(Side::Server).path_probe_ack > 0,
        "and answered"
    );
}

/// 8 MiB one way, server to client, on `road`: every byte arrives, and the
/// client's answer datagrams -- everything it sent without DATA or a road
/// check: ACKs and CREDITs alone or riding a PONG (ruling R18) -- against
/// the server's datagrams of DATA.
fn one_way(seed: u64, road: RoadSpec) -> (f64, FrameCounts, FrameCounts) {
    const SIZE: usize = 8 << 20;
    let mut sim = Sim::new(seed, vec![road]);
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(5)));
    let data: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    for chunk in data.chunks(256 << 10) {
        sim.send(Side::Server, 20, chunk);
    }
    let end = sim.now() + Duration::from_secs(120);
    while sim.delivered_len(Side::Client, 20) < SIZE && sim.now() < end {
        sim.run_for(Duration::from_millis(100));
    }
    sim.run_for(Duration::from_millis(100));
    assert!(
        sim.delivered(Side::Client, 20) == &data[..],
        "seed {seed}: {} of {SIZE} bytes, in order",
        sim.delivered_len(Side::Client, 20)
    );
    let client = sim.frames_sent(Side::Client);
    let server = sim.frames_sent(Side::Server);
    (
        client.answers as f64 / server.data_datagrams as f64,
        client,
        server,
    )
}

/// Spec §9.2 (L2): 8 MiB one way over a clean road draws at most a
/// quarter as many answer datagrams as datagrams of DATA --
/// an ACK for every `ACK_EVERY` segments -- plus the tails a delayed ACK
/// closes: one a round trip while the window still opens (10 segments to
/// the road's ~400: about six rounds) and the last. Before (an ACK per
/// DATA, each alone) the share was 1. Measured: 2050 answers (2048 of
/// ACKs and CREDITs alone, a PONG, a PING) for 8192 DATA datagrams, 0.250;
/// against the bound 2064. (That no datagram mixes a road check
/// with anything is `no_datagram_mixes_a_road_check_with_anything_else`'s,
/// on two roads.)
#[test]
fn bulk_data_on_a_clean_road_draws_a_quarter_as_many_acknowledgements() {
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20)).with_bandwidth(10_000_000, None),
    );
    let (share, client, server) = one_way(1, road);
    eprintln!("clean: share {share:.3}; client {client:?}; server {server:?}");
    assert!(
        client.answers <= server.data_datagrams / 4 + 16,
        "{} answer datagrams for {} of DATA",
        client.answers,
        server.data_datagrams
    );
}

/// Spec §11.2 at 1 % loss each way (decision 3): every byte arrives, and
/// the answers stay well under one per DATA. While a loss is
/// repaired every DATA behind the hole is acknowledged at once -- what fast
/// retransmit and recovery need (RFC 5681 §4.2) -- so the share sits above
/// the clean road's quarter. BOUND by R10a (spec slice 4): put at equal
/// standard errors of an 8-seed mean from this code and from the regression
/// this test exists for (an ACK per DATA, each alone: the code before
/// delayed ACKs, qsh 52308e0), never above 0.5. Measured over seeds 1..=8,
/// every answer datagram counted (ruling R18): this code 0.409 (SD 0.0182,
/// SE 0.0064), the regression 0.996 (SD 0.0010, SE 0.0004); equal SE lands
/// at 0.96, so the cap holds: BOUND 0.5, 14.1 SE above this code and 1345
/// SE below the regression. Ending every flight the window cut short with a
/// PING (R17's option (a)) moved the ACKs into PONGs: 0.086 counted as ACK
/// and CREDIT alone, 0.711 as answers -- this test fails it. The clean road
/// above: 0.250 (2050 for 8192), against 1.000 before.
#[test]
fn bulk_data_on_a_lossy_road_arrives_whole_with_fewer_acknowledgements() {
    const SEEDS: u64 = 8;
    const BOUND: f64 = 0.5;
    let road = RoadSpec::symmetric(
        LinkSpec::new(Duration::from_millis(20))
            .with_bandwidth(10_000_000, None)
            .with_loss(0.01),
    );
    let shares: Vec<f64> = (1..=SEEDS).map(|seed| one_way(seed, road).0).collect();
    let mean = shares.iter().sum::<f64>() / shares.len() as f64;
    eprintln!("1 % loss: shares {shares:?}, mean {mean:.3}");
    assert!(
        mean <= BOUND,
        "mean share {mean:.3} over {SEEDS} seeds, bound {BOUND}"
    );
}
