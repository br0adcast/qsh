//! Spec §4.16 (QSH-02/QSH-03) in virtual time: a server with the session
//! manager's return-address check in front of it (`Sim::guard_server`), a
//! client that answers cookies, a flood from forged addresses
//! (`Sim::inject_to_server`) whose answers go nowhere, and a party on the
//! path that answers msg1 with a cookie of its own (`Sim::inject_to_client`).

use std::net::SocketAddr;
use std::time::Duration;

use crate::cookie::{CookieCheck, LoadLimits, LOAD_HANDSHAKES_PER_WINDOW};
use crate::driver_std::HANDSHAKE_RETRANSMIT;
use crate::features::Features;
use crate::testnet::{LinkSpec, RoadSpec, Side, Sim};
use crate::wire::{encode_cookie_reply, encode_handshake, Kind, COOKIE_ECHO_LEN, COOKIE_LEN};

fn road() -> RoadSpec {
    RoadSpec::symmetric(LinkSpec::new(Duration::from_millis(25)))
}

fn always_loaded(sim: &Sim) -> CookieCheck {
    CookieCheck::with_limits(
        sim.instant(),
        LoadLimits {
            handshakes_per_window: 0,
            probation_seats: 0,
        },
    )
}

/// `per_ms` msg1-sized datagrams a millisecond from addresses no road has,
/// from `from` until `until`.
fn flood(sim: &mut Sim, from: Duration, until: Duration, per_ms: u32) {
    let mut t = from;
    let mut n = 0u32;
    while t < until {
        let first = n;
        sim.schedule(t, move |s: &mut Sim| {
            for i in first..first + per_ms {
                let src = SocketAddr::from((
                    [203, 0, (i >> 8) as u8, i as u8],
                    50_000 + (i % 1000) as u16,
                ));
                // 119 bytes of body: the size of a new client's msg1.
                s.inject_to_server(src, encode_handshake(Kind::HandshakeInit, &[0xA5; 119]));
            }
        });
        n += per_ms;
        t += Duration::from_millis(1);
    }
}

/// QSH-02: a flood of 2000 forged msg1s a second makes the server ask for
/// cookies; the honest client pays one round trip and gets in, the flood
/// cost at most the first window's worth of work, and its answers weigh
/// under a third of it.
#[test]
fn an_honest_client_gets_in_through_a_cookie_while_a_forged_flood_goes_on() {
    let mut sim = Sim::new(11, vec![road()]);
    let check = CookieCheck::new(sim.instant());
    sim.guard_server(check);
    flood(&mut sim, Duration::ZERO, Duration::from_secs(5), 2);
    sim.run_until(Duration::from_millis(300));
    sim.start();
    assert!(
        sim.run_until_live(Duration::from_millis(1200)),
        "a cookie round trip and the handshake"
    );
    let counts = sim.guard_counts();
    assert_eq!(counts.passed_from_roads, 1, "{counts:?}");
    assert!(
        counts.passed_from_elsewhere <= u64::from(LOAD_HANDSHAKES_PER_WINDOW),
        "{counts:?}"
    );
    assert!(sim.misaddressed_bytes() * 3 < sim.injected_bytes());
    assert_eq!(
        sim.conn(Side::Client).rtt(),
        None,
        "Karn: no handshake seed"
    );
}

/// A lost cookie reply costs one retransmit, not the handshake.
#[test]
fn a_lost_cookie_reply_costs_one_retransmit() {
    let mut sim = Sim::new(12, vec![road()]);
    let check = always_loaded(&sim);
    sim.guard_server(check);
    sim.set_link(
        0,
        Side::Server,
        LinkSpec::new(Duration::from_millis(25)).with_loss(1.0),
    );
    sim.schedule(Duration::from_millis(40), |s: &mut Sim| {
        s.set_link(0, Side::Server, LinkSpec::new(Duration::from_millis(25)))
    });
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(2)));
    assert!(
        sim.now() >= HANDSHAKE_RETRANSMIT,
        "the retransmit brought it in"
    );
    assert_eq!(sim.guard_counts().replies, 2);
}

/// Review focus 1: the NAT gives the client a new port after the server
/// answered msg1 and before the retry arrives. The retry draws a fresh
/// cookie for the new port, which waits for the retransmit timer -- one
/// more retransmit, no ping-pong.
#[test]
fn a_port_change_between_the_cookie_and_the_retry_costs_one_more_retransmit() {
    let mut sim = Sim::new(14, vec![road()]);
    let check = always_loaded(&sim);
    sim.guard_server(check);
    sim.schedule(Duration::from_millis(40), |s: &mut Sim| {
        s.rebind_client_port(0, 40_001, true)
    });
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(2)));
    assert_eq!(sim.guard_counts().replies, 2, "{:?}", sim.guard_counts());
    assert!(sim.now() >= HANDSHAKE_RETRANSMIT);
}

/// §4.16's stated cost: a client from before cookies is refused while the
/// load lasts, and gets in at its first retransmit after.
#[test]
fn a_client_that_predates_cookies_is_refused_under_load_and_admitted_after() {
    let mut sim = Sim::new(13, vec![road()]);
    let check = CookieCheck::new(sim.instant());
    sim.guard_server(check);
    sim.play_legacy(Side::Client);
    flood(&mut sim, Duration::ZERO, Duration::from_secs(3), 2);
    sim.run_until(Duration::from_millis(100));
    sim.start();
    assert!(
        !sim.run_until_live(Duration::from_millis(2900)),
        "refused under load"
    );
    assert!(
        sim.run_until_live(Duration::from_secs(6)),
        "admitted once the load is over"
    );
    assert!(sim.now() >= Duration::from_secs(3), "{:?}", sim.now());
}

/// The cookie a party that saw msg1 go by forges for it: the right echo (the
/// start of msg1's ephemeral key, in the clear), a cookie of its own.
const FORGED: [u8; COOKIE_LEN] = [0xEE; COOKIE_LEN];

/// Such a party answers the client's msg1 at `at`, in the daemon's name.
fn inject_a_forged_cookie(sim: &mut Sim, at: Duration) {
    let msg1 = sim.msg1().expect("msg1 went out").to_vec();
    let mut echo = [0u8; COOKIE_ECHO_LEN];
    // The datagram is `version | kind | body`; the echo starts the body.
    echo.copy_from_slice(&msg1[2..2 + COOKIE_ECHO_LEN]);
    let (_, daemon) = sim.road(0);
    sim.schedule(at, move |s: &mut Sim| {
        s.inject_to_client(daemon, encode_cookie_reply(&echo, &FORGED))
    });
}

/// Review of slice 3, minor 1: a party that sees msg1 and can inject
/// answers it with a cookie of its own; a daemon built before cookies drops
/// every msg1 behind one. With the first msg2 lost, only a plain msg1 can
/// still bring the client in -- and after the first retransmit behind the
/// cookie, the plain msg1 and the cookie take turns.
#[test]
fn an_injected_cookie_does_not_keep_a_new_client_out_of_an_old_daemon() {
    let mut sim = Sim::new(15, vec![road()]);
    sim.play_legacy(Side::Server);
    // The old daemon's first msg2 (sent at 25 ms) is lost.
    sim.set_link(
        0,
        Side::Server,
        LinkSpec::new(Duration::from_millis(25)).with_loss(1.0),
    );
    sim.schedule(Duration::from_millis(40), |s: &mut Sim| {
        s.set_link(0, Side::Server, LinkSpec::new(Duration::from_millis(25)))
    });
    sim.start();
    inject_a_forged_cookie(&mut sim, Duration::from_millis(5));
    assert!(
        sim.run_until_live(Duration::from_secs(3)),
        "a plain retransmit reaches the old daemon"
    );
    assert_eq!(
        sim.conn(Side::Client).cookie_for_test(),
        Some(FORGED),
        "the client did take the forged cookie"
    );
    assert_eq!(sim.conn(Side::Client).features(), Features::NONE);
    assert!(sim.now() >= 2 * HANDSHAKE_RETRANSMIT, "{:?}", sim.now());
    assert_eq!(
        sim.conn(Side::Client).rtt(),
        None,
        "Karn: no handshake seed"
    );
}

/// The other half of the same ruling: a daemon of this build under load
/// still admits a client that took a forged cookie. The daemon answers the
/// msg1 and the retry behind the forged cookie with a cookie of its own,
/// and the next retransmit -- behind the cookie, the plain msg1's turn
/// comes after it -- carries that one.
#[test]
fn a_new_daemon_under_load_admits_a_client_that_took_an_injected_cookie() {
    let mut sim = Sim::new(16, vec![road()]);
    let check = always_loaded(&sim);
    sim.guard_server(check);
    sim.start();
    inject_a_forged_cookie(&mut sim, Duration::from_millis(5));
    assert!(sim.run_until_live(Duration::from_secs(3)));
    let counts = sim.guard_counts();
    assert_eq!(counts.passed_from_roads, 1, "one proven msg1: {counts:?}");
    assert_eq!(counts.replies, 2, "{counts:?}");
    assert!(sim.now() < 2 * HANDSHAKE_RETRANSMIT, "{:?}", sim.now());
    assert_ne!(sim.conn(Side::Client).cookie_for_test(), Some(FORGED));
    assert_eq!(sim.conn(Side::Client).features(), Features::SUPPORTED);
}

/// The plain turn against a daemon under load: with the retransmit behind
/// the cookie lost as well, the plain msg1 draws one more cookie reply and
/// nothing else, and the turn after it gets the client in.
#[test]
fn a_plain_turn_under_load_costs_a_cookie_reply_and_one_more_retransmit() {
    let mut sim = Sim::new(18, vec![road()]);
    let check = always_loaded(&sim);
    sim.guard_server(check);
    // Lost: the retry at 50 ms (when the cookie lands) and the retransmit
    // behind the cookie at 500 ms. The plain msg1 at 1 s goes through.
    for (from, to) in [(45, 60), (495, 510)] {
        sim.schedule(Duration::from_millis(from), |s: &mut Sim| {
            s.set_link(
                0,
                Side::Client,
                LinkSpec::new(Duration::from_millis(25)).with_loss(1.0),
            )
        });
        sim.schedule(Duration::from_millis(to), |s: &mut Sim| {
            s.set_link(0, Side::Client, LinkSpec::new(Duration::from_millis(25)))
        });
    }
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(3)));
    let counts = sim.guard_counts();
    assert_eq!(counts.replies, 2, "the msg1 and its plain turn: {counts:?}");
    assert_eq!(counts.passed_from_roads, 1, "{counts:?}");
    assert!(sim.now() >= 3 * HANDSHAKE_RETRANSMIT, "{:?}", sim.now());
    assert!(sim.now() < 4 * HANDSHAKE_RETRANSMIT, "{:?}", sim.now());
}

/// And a daemon under load whose client lost its first msg1 behind the
/// cookie: the retransmit after it carries the cookie again, so the plain
/// turns cost the client nothing here.
#[test]
fn a_lost_retry_behind_the_cookie_costs_one_retransmit() {
    let mut sim = Sim::new(17, vec![road()]);
    let check = always_loaded(&sim);
    sim.guard_server(check);
    // The retry goes out at 50 ms, when the cookie reply lands.
    sim.schedule(Duration::from_millis(45), |s: &mut Sim| {
        s.set_link(
            0,
            Side::Client,
            LinkSpec::new(Duration::from_millis(25)).with_loss(1.0),
        )
    });
    sim.schedule(Duration::from_millis(60), |s: &mut Sim| {
        s.set_link(0, Side::Client, LinkSpec::new(Duration::from_millis(25)))
    });
    sim.start();
    assert!(sim.run_until_live(Duration::from_secs(2)));
    assert!(sim.now() >= HANDSHAKE_RETRANSMIT);
    assert!(sim.now() < 2 * HANDSHAKE_RETRANSMIT, "{:?}", sim.now());
    assert_eq!(sim.guard_counts().replies, 1);
}
