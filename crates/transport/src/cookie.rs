//! The return-address check under load (spec §4.16, QSH-02/QSH-03), in the
//! manner of WireGuard's cookie reply and QUIC's Retry.
//!
//! A `HandshakeInit` costs the daemon Noise's X25519 work and, on the
//! signature path, a probation seat -- both spent before anything proves
//! that the sender receives at the address it names, so a flood from forged
//! addresses could fill the probation table and keep a core busy. Under
//! load the daemon answers a msg1 with a `CookieReply` instead: a MAC over
//! the sender's address and port and the msg1's ephemeral key, under a
//! secret replaced every two minutes. A client that receives it sends the
//! same msg1 again behind the cookie; a valid cookie proves the return
//! address, and while the load lasts only such a msg1 is worked on.
//!
//! A cookie proves an address, not a datagram: the same msg1 behind it may
//! come again (a retransmit does), each copy a Noise handshake. So while the
//! load lasts a proven source is also held to [`PROVEN_PER_SECOND`] after a
//! burst of [`PROVEN_BURST`], as WireGuard's rate limiter holds it; only a
//! valid cookie is charged, so nobody can spend another source's budget by
//! forging its address.
//!
//! Sans-IO: the session manager asks [`CookieCheck::check`] about every
//! handshake datagram and does what the [`Verdict`] says. The work per
//! datagram is a keyed BLAKE2s over 63 bytes -- one to mint a cookie, up to
//! two to check one against both secrets, three for a wrong cookie under
//! load -- and, under load, a 35-byte answer.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use blake2::digest::consts::U16;
use blake2::digest::Mac;
use blake2::Blake2sMac;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::wire::{self, Kind, COOKIE_ECHO_LEN, COOKIE_LEN, MIN_MSG1_BODY};

/// How often the cookie secret is replaced. A cookie made under the current
/// secret or the one before it is accepted: it lives two to four minutes.
pub const COOKIE_ROTATION: Duration = Duration::from_secs(120);

/// The window the handshake rate is counted over.
pub const LOAD_WINDOW: Duration = Duration::from_secs(1);

/// Handshake datagrams per [`LOAD_WINDOW`] above which the daemon is under
/// load. Counted as they ARRIVE, whatever becomes of them: counting only the
/// Noise work done would switch load off the moment cookies start working.
/// Sixty-four handshakes a second cost a few percent of one core; an honest
/// burst of more (a daemon restarted under many clients) only costs new
/// clients one extra round trip.
pub const LOAD_HANDSHAKES_PER_WINDOW: u32 = 64;

/// Probation seats in use above which the daemon is under load: half of
/// `probation::MAX_PROBATION` (128), a link `probation.rs` asserts.
pub const LOAD_PROBATION_SEATS: usize = 64;

/// Proven handshakes a second one source may have worked on while the
/// daemon is under load, once its burst is spent; and that burst. WireGuard's
/// numbers (its `ratelimiter.c`): a cookie proves an address, not a
/// datagram, and without a limit an attacker at a real address could send
/// the same msg1 behind its cookie again and again, a Noise handshake each.
pub const PROVEN_PER_SECOND: u32 = 20;

/// See [`PROVEN_PER_SECOND`].
pub const PROVEN_BURST: u32 = 5;

/// Sources the rate table holds at once: 48 bytes an entry, under a
/// megabyte with the hash table's slack. A new source past that is dropped
/// until the table is swept, as WireGuard's limiter does when full.
pub const PROVEN_RATE_SOURCES: usize = 8192;

/// What one proven handshake costs a source's budget.
const PROVEN_COST: Duration = Duration::from_nanos(1_000_000_000 / PROVEN_PER_SECOND as u64);

/// A full budget: the burst. Also how long a spent budget takes to fill
/// again, so how often the table is swept of sources idle that long.
const PROVEN_BUCKET: Duration =
    Duration::from_nanos(1_000_000_000 / PROVEN_PER_SECOND as u64 * PROVEN_BURST as u64);

/// The domain of the cookie MAC.
const COOKIE_LABEL: &[u8] = b"qsh cookie v1";

/// The msg1's ephemeral public key: its first 32 bytes, in the clear.
const EPHEMERAL_LEN: usize = 32;

// What the MAC reads of a msg1 lies inside the smallest one that is checked
// at all, and the echo is a part of it.
const _: () = assert!(COOKIE_ECHO_LEN <= EPHEMERAL_LEN && EPHEMERAL_LEN <= MIN_MSG1_BODY);

/// Where load begins. Tests lower both to zero to be under load at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadLimits {
    pub handshakes_per_window: u32,
    pub probation_seats: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        LoadLimits {
            handshakes_per_window: LOAD_HANDSHAKES_PER_WINDOW,
            probation_seats: LOAD_PROBATION_SEATS,
        }
    }
}

/// What to do with one handshake datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Work on this msg1 (any cookie already taken off it). `proven`: it
    /// came behind a valid cookie.
    Handshake { msg1: &'a [u8], proven: bool },
    /// Send this datagram (a `CookieReply`) back to the sender and do
    /// nothing else.
    Reply(Vec<u8>),
    /// Drop it in silence: not a msg1 at all, or -- under load -- a proven
    /// one past its source's rate ([`PROVEN_PER_SECOND`]).
    Drop,
}

/// A cookie secret. Wiped when it is dropped: when the check goes, and when
/// a rotation retires it.
type Secret = Zeroizing<[u8; 32]>;

/// The daemon's cookie secret and load meter. Deliberately not `Debug`: it
/// holds the secrets, and wipes them when dropped (`Secret`).
pub struct CookieCheck {
    current: Secret,
    previous: Secret,
    rotated_at: Instant,
    window_start: Instant,
    this_window: u32,
    last_window: u32,
    limits: LoadLimits,
    loaded: bool,
    proven_rate: ProvenRate,
}

impl CookieCheck {
    pub fn new(now: Instant) -> Self {
        Self::with_limits(now, LoadLimits::default())
    }

    pub fn with_limits(now: Instant, limits: LoadLimits) -> Self {
        CookieCheck {
            current: fresh_secret(),
            previous: fresh_secret(),
            rotated_at: now,
            window_start: now,
            this_window: 0,
            last_window: 0,
            limits,
            loaded: false,
            proven_rate: ProvenRate::new(now),
        }
    }

    /// Decide about one datagram of `kind` (`HandshakeInit` or
    /// `HandshakeInitCookie`) from `src`, whose body is `body`, while
    /// `probation_seats` seats are taken.
    pub fn check<'a>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        kind: Kind,
        body: &'a [u8],
        probation_seats: usize,
    ) -> Verdict<'a> {
        self.rotate(now);
        let (cookie, msg1) = match kind {
            Kind::HandshakeInit => (None, body),
            Kind::HandshakeInitCookie => match wire::split_cookie_init(body) {
                Some((cookie, msg1)) => (Some(cookie), msg1),
                None => return Verdict::Drop,
            },
            _ => return Verdict::Drop,
        };
        if msg1.len() < MIN_MSG1_BODY {
            return Verdict::Drop;
        }
        self.count(now);
        let loaded = self.over_limits(probation_seats);
        self.loaded = loaded;
        if let Some(cookie) = cookie {
            if self.accepts(src, msg1, &cookie) {
                // Charged only here, behind a valid cookie: a wrong one in a
                // source's name, which anyone can send, costs it nothing.
                if loaded && !self.proven_rate.allow(now, src.ip()) {
                    return Verdict::Drop;
                }
                return Verdict::Handshake { msg1, proven: true };
            }
        }
        if !loaded {
            return Verdict::Handshake {
                msg1,
                proven: false,
            };
        }
        let mut echo = [0u8; COOKIE_ECHO_LEN];
        echo.copy_from_slice(&msg1[..COOKIE_ECHO_LEN]);
        Verdict::Reply(wire::encode_cookie_reply(
            &echo,
            &mint(&self.current, src, msg1),
        ))
    }

    /// What the last `check` found.
    pub fn under_load(&self) -> bool {
        self.loaded
    }

    /// Whether `cookie` is this sender's for this msg1 under either secret.
    /// Each comparison is constant-time (`verify_slice`).
    fn accepts(&self, src: SocketAddr, msg1: &[u8], cookie: &[u8; COOKIE_LEN]) -> bool {
        [&self.current, &self.previous]
            .into_iter()
            .any(|key| mac(key, src, msg1).verify_slice(cookie).is_ok())
    }

    fn rotate(&mut self, now: Instant) {
        let since = now.saturating_duration_since(self.rotated_at);
        if since < COOKIE_ROTATION {
            return;
        }
        // Each assignment drops, and so wipes, the secret it replaces.
        if since >= 2 * COOKIE_ROTATION {
            // Two periods or more: the secret before is as dead as the
            // current, and the schedule starts again from now.
            self.previous = fresh_secret();
            self.current = fresh_secret();
            self.rotated_at = now;
        } else {
            // One period: the turn was due at `rotated_at + COOKIE_ROTATION`,
            // whenever the first handshake after it came. Keeping to that
            // schedule, not to `now`, is what bounds a cookie's life to four
            // minutes on a quiet daemon.
            self.previous = std::mem::replace(&mut self.current, fresh_secret());
            self.rotated_at += COOKIE_ROTATION;
        }
    }

    fn count(&mut self, now: Instant) {
        let since = now.saturating_duration_since(self.window_start);
        if since >= 2 * LOAD_WINDOW {
            self.last_window = 0;
            self.this_window = 0;
            self.window_start = now;
        } else if since >= LOAD_WINDOW {
            self.last_window = self.this_window;
            self.this_window = 0;
            self.window_start += LOAD_WINDOW;
        }
        self.this_window = self.this_window.saturating_add(1);
    }

    fn over_limits(&self, probation_seats: usize) -> bool {
        self.this_window > self.limits.handshakes_per_window
            || self.last_window > self.limits.handshakes_per_window
            || probation_seats > self.limits.probation_seats
    }
}

/// Proven handshakes per source while the daemon is under load:
/// WireGuard's token bucket (`ratelimiter.c`). Each source starts with a full
/// budget of [`PROVEN_BUCKET`], pays [`PROVEN_COST`] per handshake worked
/// on, and earns it back as time passes.
struct ProvenRate {
    budgets: HashMap<[u8; 16], Budget>,
    /// When the table was last swept of budgets that have filled again.
    swept_at: Instant,
}

#[derive(Clone, Copy)]
struct Budget {
    /// The time's worth of handshakes this source may still have worked on.
    left: Duration,
    /// When `left` was last brought up to date.
    at: Instant,
}

impl ProvenRate {
    fn new(now: Instant) -> Self {
        ProvenRate {
            budgets: HashMap::new(),
            swept_at: now,
        }
    }

    /// Whether a proven handshake from `ip` may be worked on now; charges it
    /// if so. A new source past [`PROVEN_RATE_SOURCES`] may not.
    fn allow(&mut self, now: Instant, ip: IpAddr) -> bool {
        if now.saturating_duration_since(self.swept_at) >= PROVEN_BUCKET {
            // A budget untouched this long is full again: as good as none.
            // At most one sweep per `PROVEN_BUCKET`, whatever arrives.
            self.budgets
                .retain(|_, b| now.saturating_duration_since(b.at) < PROVEN_BUCKET);
            self.swept_at = now;
        }
        let full = self.budgets.len() >= PROVEN_RATE_SOURCES;
        match self.budgets.entry(rate_key(ip)) {
            Entry::Occupied(mut e) => {
                let b = e.get_mut();
                let left = (b.left + now.saturating_duration_since(b.at)).min(PROVEN_BUCKET);
                b.at = now;
                if left < PROVEN_COST {
                    b.left = left;
                    return false;
                }
                b.left = left - PROVEN_COST;
                true
            }
            Entry::Vacant(_) if full => false,
            Entry::Vacant(e) => {
                e.insert(Budget {
                    left: PROVEN_BUCKET - PROVEN_COST,
                    at: now,
                });
                true
            }
        }
    }
}

/// Whose budget a proven handshake from `ip` spends: an IPv4 address's (in
/// either form), or an IPv6 address's /64 -- what one host is handed, so it
/// cannot spread its handshakes over 2^64 budgets. WireGuard keys its limiter
/// the same way. The IPv4-mapped range is taken out first: as a /64 it would
/// be one budget for every IPv4 address.
fn rate_key(ip: IpAddr) -> [u8; 16] {
    let v6 = match ip {
        IpAddr::V4(v4) => return v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6,
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4.to_ipv6_mapped().octets();
    }
    let mut key = v6.octets();
    key[8..].fill(0);
    key
}

/// A new cookie secret, straight from the operating system's randomness.
/// `OsRng`, never `thread_rng()`, for the reason `auth::random_nonce` gives:
/// the daemon forks, and a secret must not rest on a generator's state
/// surviving that correctly.
fn fresh_secret() -> Secret {
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut secret[..]);
    secret
}

/// The cookie MAC for `src` and this msg1, under `key`: keyed BLAKE2s-128
/// over the label, the address (IPv4 mapped to IPv6), the port and the
/// msg1's ephemeral key.
fn mac(key: &[u8; 32], src: SocketAddr, msg1: &[u8]) -> Blake2sMac<U16> {
    let mut m = <Blake2sMac<U16> as Mac>::new_from_slice(key)
        .expect("a 32-byte key is a valid BLAKE2s key");
    m.update(COOKIE_LABEL);
    m.update(&address_bytes(src.ip()));
    m.update(&src.port().to_be_bytes());
    m.update(&msg1[..EPHEMERAL_LEN]);
    m
}

fn mint(key: &[u8; 32], src: SocketAddr, msg1: &[u8]) -> [u8; COOKIE_LEN] {
    let tag = mac(key, src, msg1).finalize().into_bytes();
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&tag);
    cookie
}

fn address_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        encode_handshake_init_cookie, parse, parse_cookie_reply, Frame, COOKIE_REPLY_LEN,
    };

    /// The body of a new client's msg1: 32 + 48 + 23 + 16 bytes. The check
    /// reads only its length and its first 32 bytes.
    fn msg1(seed: u8) -> Vec<u8> {
        (0..119u8)
            .map(|i| i.wrapping_mul(13).wrapping_add(seed))
            .collect()
    }

    fn src(s: &str) -> SocketAddr {
        s.parse().expect("an address")
    }

    const CLIENT: &str = "198.51.100.7:40000";

    /// A check under load from the first datagram on.
    fn loaded(now: Instant) -> CookieCheck {
        CookieCheck::with_limits(
            now,
            LoadLimits {
                handshakes_per_window: 0,
                probation_seats: 0,
            },
        )
    }

    fn reply_of(v: Verdict<'_>) -> Vec<u8> {
        match v {
            Verdict::Reply(dg) => dg,
            other => panic!("a cookie reply, not {other:?}"),
        }
    }

    fn cookie_of(dg: &[u8]) -> ([u8; COOKIE_ECHO_LEN], [u8; COOKIE_LEN]) {
        match parse(dg) {
            Ok(Frame::Handshake {
                kind: Kind::CookieReply,
                body,
            }) => parse_cookie_reply(body).expect("well formed"),
            other => panic!("a CookieReply datagram, not {other:?}"),
        }
    }

    /// The body of `msg1` sent again behind `cookie`.
    fn behind(cookie: &[u8; COOKIE_LEN], msg1: &[u8]) -> Vec<u8> {
        encode_handshake_init_cookie(cookie, msg1)[2..].to_vec()
    }

    /// Review of slice 3, minor 5: both secrets wipe themselves when the
    /// check is dropped, and the one a rotation retires when it is replaced.
    #[test]
    fn the_cookie_secrets_wipe_themselves_when_dropped() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let mut check = CookieCheck::new(Instant::now());
        wipes_on_drop(&check.current);
        wipes_on_drop(&check.previous);
        // A rotation keeps the types (and the current secret as the one
        // before): the retired secret is dropped, so wiped, in place.
        let before = *check.current;
        check.rotate(Instant::now() + COOKIE_ROTATION);
        assert_eq!(*check.previous, before);
        assert_ne!(*check.current, before);
    }

    #[test]
    fn without_load_a_handshake_goes_through_and_draws_no_reply() {
        let now = Instant::now();
        let mut check = CookieCheck::new(now);
        let m = msg1(1);
        assert_eq!(
            check.check(now, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Handshake {
                msg1: &m[..],
                proven: false
            }
        );
        assert!(!check.under_load());
    }

    /// Spec §4.16 (QSH-03): under load a msg1 costs one MAC and an answer
    /// under a third of its size, and the answer echoes the start of its
    /// ephemeral key.
    #[test]
    fn under_load_a_handshake_draws_only_a_reply_under_a_third_of_it() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        let dg = reply_of(check.check(now, src(CLIENT), Kind::HandshakeInit, &m, 0));
        assert_eq!(dg.len(), COOKIE_REPLY_LEN);
        assert!(
            dg.len() * 3 < 2 + m.len(),
            "{} bytes answer {}",
            dg.len(),
            2 + m.len()
        );
        let (echo, _) = cookie_of(&dg);
        assert_eq!(echo[..], m[..COOKIE_ECHO_LEN]);
    }

    #[test]
    fn the_cookie_it_hands_out_lets_the_same_msg1_through_under_load() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            now,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        let body = behind(&cookie, &m);
        assert_eq!(
            check.check(now, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Handshake {
                msg1: &m[..],
                proven: true
            }
        );
    }

    /// The cookie binds the address, the port, and the msg1 (its ephemeral
    /// key): anything else is answered with a fresh cookie, never let in.
    #[test]
    fn a_cookie_is_bound_to_the_address_the_port_and_the_msg1() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            now,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        for (from, msg) in [
            ("198.51.100.8:40000", m.clone()),
            ("198.51.100.7:40001", m.clone()),
            ("[2001:db8::7]:40000", m.clone()),
            (CLIENT, msg1(2)),
        ] {
            let body = behind(&cookie, &msg);
            assert!(
                matches!(
                    check.check(now, src(from), Kind::HandshakeInitCookie, &body, 0),
                    Verdict::Reply(_)
                ),
                "{from}: a fresh cookie, not a pass"
            );
        }
    }

    /// Review focus 3: a cookie minted just before the secret turns over is
    /// honoured after it; two turns later it is answered with a fresh one.
    #[test]
    fn a_cookie_outlives_one_rotation_and_not_two() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            t0,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        let body = behind(&cookie, &m);
        let later = t0 + COOKIE_ROTATION + Duration::from_secs(1);
        assert!(matches!(
            check.check(later, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Handshake { proven: true, .. }
        ));
        let much_later = later + COOKIE_ROTATION + Duration::from_secs(1);
        assert!(matches!(
            check.check(much_later, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Reply(_)
        ));
    }

    /// Review of Task 7, minor 1: the secret turns over on a fixed schedule
    /// however sparse the handshakes, so a cookie never lives beyond the
    /// documented four minutes. A cookie minted at t0 is still honoured at
    /// t0 + 239 s (its secret became the previous one at t0 + 120 s, even
    /// though nobody asked then) and dead at t0 + 241 s. A schedule restarted
    /// at the late turn (t0 + 239 s) would have honoured it until t0 + 359 s.
    #[test]
    fn a_cookie_never_outlives_two_periods_on_a_quiet_daemon() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            t0,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        let body = behind(&cookie, &m);
        let almost = t0 + 2 * COOKIE_ROTATION - Duration::from_secs(1);
        assert!(matches!(
            check.check(almost, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Handshake { proven: true, .. }
        ));
        let past = t0 + 2 * COOKIE_ROTATION + Duration::from_secs(1);
        assert!(
            matches!(
                check.check(past, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
                Verdict::Reply(_)
            ),
            "four minutes and a second after it was minted, a cookie is dead"
        );
    }

    /// A daemon that sees no handshake for two whole periods turns its
    /// secret over once, lazily, and must still forget both old secrets.
    #[test]
    fn a_cookie_dies_when_two_periods_pass_between_two_checks() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            t0,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        let body = behind(&cookie, &m);
        let silent = t0 + 2 * COOKIE_ROTATION;
        assert!(matches!(
            check.check(silent, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Reply(_)
        ));
    }

    /// Under load a wrong cookie draws a fresh one for the msg1 behind it --
    /// its echo is that msg1's, not the wrong cookie's -- and the fresh one
    /// lets it in.
    #[test]
    fn under_load_a_wrong_cookie_draws_a_fresh_one_for_its_msg1() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        let body = behind(&[0xEE; COOKIE_LEN], &m);
        let (echo, cookie) = cookie_of(&reply_of(check.check(
            now,
            src(CLIENT),
            Kind::HandshakeInitCookie,
            &body,
            0,
        )));
        assert_eq!(echo[..], m[..COOKIE_ECHO_LEN]);
        assert!(matches!(
            check.check(
                now,
                src(CLIENT),
                Kind::HandshakeInitCookie,
                &behind(&cookie, &m),
                0
            ),
            Verdict::Handshake { proven: true, .. }
        ));
    }

    /// The MAC reads an IPv4 sender as its IPv4-mapped IPv6 form, so a
    /// dual-stack socket and a v4 one agree on who a sender is.
    #[test]
    fn a_v4_sender_and_its_v6_mapped_form_share_a_cookie() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        let (_, cookie) = cookie_of(&reply_of(check.check(
            now,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            0,
        )));
        assert!(matches!(
            check.check(
                now,
                src("[::ffff:198.51.100.7]:40000"),
                Kind::HandshakeInitCookie,
                &behind(&cookie, &m),
                0
            ),
            Verdict::Handshake { proven: true, .. }
        ));
    }

    /// Load is MORE than half the probation table: exactly half is not.
    #[test]
    fn load_is_more_than_half_the_probation_table() {
        let now = Instant::now();
        let mut check = CookieCheck::new(now);
        let m = msg1(1);
        assert!(matches!(
            check.check(
                now,
                src(CLIENT),
                Kind::HandshakeInit,
                &m,
                LOAD_PROBATION_SEATS
            ),
            Verdict::Handshake { .. }
        ));
        assert!(matches!(
            check.check(
                now,
                src(CLIENT),
                Kind::HandshakeInit,
                &m,
                LOAD_PROBATION_SEATS + 1
            ),
            Verdict::Reply(_)
        ));
    }

    /// Load is more than 64 handshake datagrams in a one-second window, and
    /// lasts through the window after a busy one.
    #[test]
    fn load_is_more_than_64_handshakes_a_second_and_lasts_a_window_after() {
        let t0 = Instant::now();
        let mut check = CookieCheck::new(t0);
        let m = msg1(1);
        for i in 0..LOAD_HANDSHAKES_PER_WINDOW {
            assert!(
                matches!(
                    check.check(t0, src(CLIENT), Kind::HandshakeInit, &m, 0),
                    Verdict::Handshake { .. }
                ),
                "handshake {i}"
            );
        }
        assert!(matches!(
            check.check(t0, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Reply(_)
        ));
        let next = t0 + LOAD_WINDOW + Duration::from_millis(10);
        assert!(matches!(
            check.check(next, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Reply(_)
        ));
        let quiet = t0 + 2 * LOAD_WINDOW + Duration::from_millis(20);
        assert!(matches!(
            check.check(quiet, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Handshake { .. }
        ));
    }

    /// A busy window followed by two whole windows with no handshake at all
    /// is forgotten, not carried over as the window before.
    #[test]
    fn a_quiet_gap_of_two_windows_forgets_a_busy_one() {
        let t0 = Instant::now();
        let mut check = CookieCheck::new(t0);
        let m = msg1(1);
        for _ in 0..=LOAD_HANDSHAKES_PER_WINDOW {
            let _ = check.check(t0, src(CLIENT), Kind::HandshakeInit, &m, 0);
        }
        assert!(check.under_load());
        let quiet = t0 + 2 * LOAD_WINDOW;
        assert!(matches!(
            check.check(quiet, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Handshake { .. }
        ));
        assert!(!check.under_load());
    }

    /// Review of Task 7, minor 2 (plan decision 5): the meter counts
    /// cookie-carrying msg1s as well as plain ones -- counting only plain
    /// ones would switch load off as soon as cookies start working. Here the
    /// 65th datagram of the window, and every other one before it, carries a
    /// (wrong) cookie.
    #[test]
    fn the_load_meter_counts_cookie_carrying_msg1s_too() {
        let now = Instant::now();
        let mut check = CookieCheck::new(now);
        let m = msg1(1);
        let wrong = behind(&[0xEE; COOKIE_LEN], &m);
        for i in 0..LOAD_HANDSHAKES_PER_WINDOW {
            let kind = if i % 2 == 0 {
                Kind::HandshakeInitCookie
            } else {
                Kind::HandshakeInit
            };
            let body = if i % 2 == 0 { &wrong[..] } else { &m[..] };
            assert!(
                matches!(
                    check.check(now, src(CLIENT), kind, body, 0),
                    Verdict::Handshake { proven: false, .. }
                ),
                "datagram {i}"
            );
        }
        assert!(!check.under_load());
        assert!(matches!(
            check.check(now, src(CLIENT), Kind::HandshakeInitCookie, &wrong, 0),
            Verdict::Reply(_)
        ));
        assert!(check.under_load());
    }

    /// Review of Task 7, minor 2: what is dropped before any MAC is not
    /// counted either -- datagrams too short for a msg1 (in either kind) and
    /// every kind that is no msg1 at all. A hundred of each, and the window
    /// still takes 64 handshakes before load.
    #[test]
    fn the_load_meter_does_not_count_what_it_drops() {
        let now = Instant::now();
        let mut check = CookieCheck::new(now);
        let m = msg1(1);
        let short = vec![0u8; MIN_MSG1_BODY - 1];
        let short_behind = behind(&[0; COOKIE_LEN], &short);
        for _ in 0..100 {
            assert_eq!(
                check.check(now, src(CLIENT), Kind::HandshakeInit, &short, 0),
                Verdict::Drop
            );
            assert_eq!(
                check.check(
                    now,
                    src(CLIENT),
                    Kind::HandshakeInitCookie,
                    &short_behind,
                    0
                ),
                Verdict::Drop
            );
            for kind in [
                Kind::HandshakeResp,
                Kind::Transport,
                Kind::KeyRequest,
                Kind::KeyOffer,
                Kind::CookieReply,
            ] {
                assert_eq!(
                    check.check(now, src(CLIENT), kind, &m, 0),
                    Verdict::Drop,
                    "{kind:?}"
                );
            }
        }
        assert!(!check.under_load());
        for i in 0..LOAD_HANDSHAKES_PER_WINDOW {
            assert!(
                matches!(
                    check.check(now, src(CLIENT), Kind::HandshakeInit, &m, 0),
                    Verdict::Handshake { .. }
                ),
                "handshake {i}"
            );
        }
        assert!(matches!(
            check.check(now, src(CLIENT), Kind::HandshakeInit, &m, 0),
            Verdict::Reply(_)
        ));
    }

    /// Any kind but the two msg1 kinds is dropped, under load as well: the
    /// check never answers what is not a msg1.
    #[test]
    fn a_kind_that_is_no_msg1_is_dropped_under_load() {
        let now = Instant::now();
        let mut check = loaded(now);
        let m = msg1(1);
        for kind in [
            Kind::HandshakeResp,
            Kind::Transport,
            Kind::KeyRequest,
            Kind::KeyOffer,
            Kind::CookieReply,
        ] {
            assert_eq!(
                check.check(now, src(CLIENT), kind, &m, 0),
                Verdict::Drop,
                "{kind:?}"
            );
        }
    }

    /// A handshake datagram too short to be a msg1 is not worth an answer --
    /// under any load, in either kind.
    #[test]
    fn a_datagram_too_short_for_a_msg1_is_dropped_under_any_load() {
        let now = Instant::now();
        let short = vec![0u8; MIN_MSG1_BODY - 1];
        for mut check in [CookieCheck::new(now), loaded(now)] {
            assert_eq!(
                check.check(now, src(CLIENT), Kind::HandshakeInit, &short, 0),
                Verdict::Drop
            );
            assert_eq!(
                check.check(
                    now,
                    src(CLIENT),
                    Kind::HandshakeInitCookie,
                    &behind(&[0; COOKIE_LEN], &short),
                    0
                ),
                Verdict::Drop
            );
            assert_eq!(
                check.check(
                    now,
                    src(CLIENT),
                    Kind::HandshakeInitCookie,
                    &[0u8; COOKIE_LEN - 1],
                    0
                ),
                Verdict::Drop
            );
        }
    }

    /// Without load a wrong cookie costs nothing: the msg1 behind it is
    /// worked on as a plain one.
    #[test]
    fn without_load_a_wrong_cookie_is_ignored() {
        let now = Instant::now();
        let mut check = CookieCheck::new(now);
        let m = msg1(1);
        let body = behind(&[0xEE; COOKIE_LEN], &m);
        assert_eq!(
            check.check(now, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Handshake {
                msg1: &m[..],
                proven: false
            }
        );
    }

    /// The body of `m` behind the cookie a loaded `check` hands `from` for it.
    fn proven_body(check: &mut CookieCheck, now: Instant, from: &str, m: &[u8]) -> Vec<u8> {
        let (_, cookie) = cookie_of(&reply_of(check.check(
            now,
            src(from),
            Kind::HandshakeInit,
            m,
            0,
        )));
        behind(&cookie, m)
    }

    fn is_proven(v: &Verdict<'_>) -> bool {
        matches!(v, Verdict::Handshake { proven: true, .. })
    }

    /// `from` spends its whole burst on `body` at `now`, and the next copy
    /// is dropped.
    fn spend_the_burst(check: &mut CookieCheck, now: Instant, from: &str, body: &[u8]) {
        for i in 0..PROVEN_BURST {
            assert!(
                is_proven(&check.check(now, src(from), Kind::HandshakeInitCookie, body, 0)),
                "{from}: copy {i} of the burst"
            );
        }
        assert_eq!(
            check.check(now, src(from), Kind::HandshakeInitCookie, body, 0),
            Verdict::Drop,
            "{from}: past the burst"
        );
    }

    /// Controller ruling on §4.16, WireGuard's rate limiter: a cookie proves
    /// an address, not a datagram, and the same msg1 behind it may come
    /// again and again. Under load a proven source gets a burst of five
    /// handshakes worked on, then one every 50 ms -- twenty a second -- and
    /// the burst back after a quiet spell, never more.
    #[test]
    fn under_load_a_proven_source_gets_a_burst_of_five_and_then_twenty_a_second() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let body = proven_body(&mut check, t0, CLIENT, &m);
        spend_the_burst(&mut check, t0, CLIENT, &body);
        let cost = Duration::from_secs(1) / PROVEN_PER_SECOND;
        let mut at = t0;
        for k in 0..PROVEN_PER_SECOND {
            assert_eq!(
                check.check(
                    at + cost - Duration::from_millis(1),
                    src(CLIENT),
                    Kind::HandshakeInitCookie,
                    &body,
                    0
                ),
                Verdict::Drop,
                "a millisecond early, {k}"
            );
            at += cost;
            assert!(
                is_proven(&check.check(at, src(CLIENT), Kind::HandshakeInitCookie, &body, 0)),
                "on time, {k}"
            );
            assert_eq!(
                check.check(at, src(CLIENT), Kind::HandshakeInitCookie, &body, 0),
                Verdict::Drop,
                "twice at once, {k}"
            );
        }
        spend_the_burst(&mut check, at + Duration::from_secs(10), CLIENT, &body);
    }

    /// Without load nothing is rate-limited: the load meter itself bounds
    /// the handshakes worked on.
    #[test]
    fn without_load_a_proven_source_is_not_rate_limited() {
        let t0 = Instant::now();
        let mut check = CookieCheck::new(t0);
        let m = msg1(1);
        // Load for one datagram, by the probation table, to be handed a cookie.
        let (_, cookie) = cookie_of(&reply_of(check.check(
            t0,
            src(CLIENT),
            Kind::HandshakeInit,
            &m,
            LOAD_PROBATION_SEATS + 1,
        )));
        let body = behind(&cookie, &m);
        for i in 0..4 * PROVEN_BURST {
            assert!(
                is_proven(&check.check(t0, src(CLIENT), Kind::HandshakeInitCookie, &body, 0)),
                "copy {i}"
            );
        }
        assert!(!check.under_load());
    }

    /// Only a VALID cookie is charged: a flood of wrong ones in a source's
    /// name -- anyone can forge its address, nobody off its path its cookie
    /// -- costs that source nothing.
    #[test]
    fn a_wrong_cookie_costs_its_source_no_budget() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let body = proven_body(&mut check, t0, CLIENT, &m);
        let junk = behind(&[0xEE; COOKIE_LEN], &m);
        for _ in 0..100 {
            assert!(matches!(
                check.check(t0, src(CLIENT), Kind::HandshakeInitCookie, &junk, 0),
                Verdict::Reply(_)
            ));
        }
        spend_the_burst(&mut check, t0, CLIENT, &body);
    }

    /// A budget belongs to an IPv4 address -- every port of it, and its
    /// IPv4-mapped IPv6 form -- or to an IPv6 /64, what one host is handed,
    /// as WireGuard keys its limiter. The IPv4-mapped range is not one /64:
    /// two IPv4 addresses in that form have a budget each.
    #[test]
    fn a_budget_is_per_ipv4_address_and_per_ipv6_64_prefix() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        let body = proven_body(&mut check, t0, CLIENT, &m);
        spend_the_burst(&mut check, t0, CLIENT, &body);
        for (from, shares) in [
            ("198.51.100.7:40001", true),
            ("[::ffff:198.51.100.7]:40000", true),
            ("198.51.100.8:40000", false),
            ("[::ffff:198.51.100.9]:40000", false),
        ] {
            let body = proven_body(&mut check, t0, from, &m);
            let v = check.check(t0, src(from), Kind::HandshakeInitCookie, &body, 0);
            assert_eq!(is_proven(&v), !shares, "{from}");
        }
        let v6 = "[2001:db8::1]:40000";
        let body = proven_body(&mut check, t0, v6, &m);
        spend_the_burst(&mut check, t0, v6, &body);
        for (from, shares) in [
            ("[2001:db8::2]:40000", true),
            ("[2001:db8::ffff:1]:41000", true),
            ("[2001:db8:0:1::1]:40000", false),
        ] {
            let body = proven_body(&mut check, t0, from, &m);
            let v = check.check(t0, src(from), Kind::HandshakeInitCookie, &body, 0);
            assert_eq!(is_proven(&v), !shares, "{from}");
        }
    }

    /// The rate table holds `PROVEN_RATE_SOURCES` sources; a new one past
    /// that is dropped, as WireGuard's limiter does when full, until the
    /// table is swept -- every `PROVEN_BUCKET`, the time a spent budget
    /// takes to fill again, so a source idle that long is as good as gone.
    #[test]
    fn a_full_rate_table_refuses_a_new_source_until_it_is_swept() {
        let t0 = Instant::now();
        let mut check = loaded(t0);
        let m = msg1(1);
        for i in 0..PROVEN_RATE_SOURCES as u32 {
            let from = SocketAddr::from((std::net::Ipv4Addr::from(0x0A00_0000 + i), 40_000));
            let (_, cookie) =
                cookie_of(&reply_of(check.check(t0, from, Kind::HandshakeInit, &m, 0)));
            assert!(
                is_proven(&check.check(
                    t0,
                    from,
                    Kind::HandshakeInitCookie,
                    &behind(&cookie, &m),
                    0
                )),
                "source {i}"
            );
        }
        let newcomer = "198.51.100.200:40000";
        let body = proven_body(&mut check, t0, newcomer, &m);
        assert_eq!(
            check.check(t0, src(newcomer), Kind::HandshakeInitCookie, &body, 0),
            Verdict::Drop,
            "the table is full"
        );
        let just_before = t0 + PROVEN_BUCKET - Duration::from_millis(1);
        assert_eq!(
            check.check(
                just_before,
                src(newcomer),
                Kind::HandshakeInitCookie,
                &body,
                0
            ),
            Verdict::Drop,
            "not swept yet"
        );
        assert!(is_proven(&check.check(
            t0 + PROVEN_BUCKET,
            src(newcomer),
            Kind::HandshakeInitCookie,
            &body,
            0
        )));
    }
}
