//! Which roads to the peer exist, which of them work, and which is best.
//!
//! A session is not bound to an address: keys and a session id identify it,
//! and the peer address is just where the datagrams go. So one session can
//! have several roads to the same server -- a local address, an external one,
//! one through a VPN -- and moving between them costs an assignment rather
//! than a reconnect.
//!
//! This is the bookkeeping for that, and nothing else: it opens no sockets,
//! sends nothing, and waits for nothing. It is asked "what should happen at
//! this instant" and answers with checks to send and the road to prefer, so
//! the part that is easy to get wrong is testable without a network.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How many roads one session may keep. The list comes from a profile
/// somebody else edits, and every road costs a check on a schedule.
pub const MAX_PATHS: usize = 8;

/// How often a backup road is checked while the live one is healthy.
const PROBE_IDLE: Duration = Duration::from_secs(30);

/// How often it is checked once the live road starts failing -- so a backup
/// is already verified by the time it is needed. Visible to `conn`, which
/// uses it as the floor of the dwell after a move: nothing about the new
/// road can be learned faster than the schedule that checks it.
pub(crate) const PROBE_URGENT: Duration = Duration::from_secs(1);

/// How long a check waits for its answer before the road counts as failed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How many checks may be in flight to one road at once -- a bound kept as
/// defense, not one this crate's own call pattern can reach. Checks to a road
/// go out no closer together than the interval in force, and the retention
/// pass drops everything older than [`PROBE_TIMEOUT`] before the push: at the
/// urgent interval that leaves two survivors plus the new one, three in all.
/// So the eviction below never fires from here; it is there so that a caller
/// on some future, faster schedule cannot grow the list without bound.
const MAX_IN_FLIGHT: usize = 4;

/// How long a failure keeps weighing on a road's score, and by how much.
/// Without this a flapping road would be chosen, fail, and be chosen again.
const FAILURE_PENALTY_WINDOW: Duration = Duration::from_secs(60);
const FAILURE_PENALTY: Duration = Duration::from_secs(10);

/// What a road with no measurement is assumed to cost, and what a road that
/// failed its last check is assumed to cost. Both are worse than any real
/// latency, and neither is infinite: the road left may be the only one.
const UNVERIFIED_COST: Duration = Duration::from_secs(60);
const DEAD_COST: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Never answered a check (yet).
    Unverified,
    /// Answered its last check.
    Verified,
    /// Did not answer its last check within [`PROBE_TIMEOUT`].
    Dead,
}

/// One road as the table sees it, for someone who only wants to look.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RoadInfo {
    pub addr: SocketAddr,
    pub state: PathState,
    /// Smoothed round trip, or `None` while the road has never answered.
    pub ewma_ms: Option<u32>,
    /// How long ago the road last went down, or `None` if it never has. Not
    /// the age of the last failed check: a road that stays down is checked
    /// again on the ordinary schedule and fails again, and this counts from
    /// the first of those failures, not the latest. It is also not cleared by
    /// a recovery -- ask [`RoadInfo::state`] whether the road is down now.
    pub failed_ago_ms: Option<u32>,
}

struct Path {
    addr: SocketAddr,
    state: PathState,
    /// Smoothed round trip of the answered checks.
    ewma_ms: Option<u32>,
    /// When this road last went down -- written on the transition into
    /// [`PathState::Dead`] and never while already there (see `due`), so it
    /// answers "how long has this road been down", not "when was it last
    /// checked". Kept through a recovery, because `score`'s recent-failure
    /// penalty is about a road that has just let us down whatever it is doing
    /// now.
    last_failure: Option<Instant>,
    /// When the check that failed most recently was SENT -- the start of the
    /// silent run that expired ([`Path::unanswered_since`]) -- written on EVERY
    /// expiry, unlike `last_failure`. The dead-road rule in
    /// `Connection::on_timeout` asks whether that check went out after the
    /// PINGs down the road were found unanswered; the expiry itself comes
    /// `PROBE_TIMEOUT` later and would pair losses that far apart.
    last_expiry: Option<Instant>,
    /// The checks sent down this road and not yet answered, oldest first, as
    /// `(token, when it went out)`. Several at once because the urgent
    /// schedule is faster than a slow road's round trip: an answer to the
    /// check before last is still an answer, and throwing it away would
    /// declare a working road dead.
    in_flight: Vec<(u32, Instant)>,
    /// When this road last went quiet: the moment a check went out to a road
    /// that had none in flight. Kept across the further checks sent while it
    /// stays quiet, and cleared by an answer.
    ///
    /// This, not any single entry's own `sent_at` in [`Path::in_flight`], is
    /// what [`PROBE_TIMEOUT`] is measured from. Under urgency a fresh check
    /// joins the others every [`PROBE_URGENT`] (1 s), so an expiry clock
    /// restarted by each of them would never reach three seconds and the
    /// road would stay `Verified` however long it stayed silent -- which is
    /// precisely the situation the urgent schedule exists for.
    unanswered_since: Option<Instant>,
    last_probe: Option<Instant>,
}

impl Path {
    fn new(addr: SocketAddr) -> Self {
        Path {
            addr,
            state: PathState::Unverified,
            ewma_ms: None,
            last_failure: None,
            last_expiry: None,
            in_flight: Vec::new(),
            unanswered_since: None,
            last_probe: None,
        }
    }
}

/// A road's cost for ranking purposes: lower is better. Not a latency in the
/// verified case alone -- an unverified or dead road gets a fixed, high
/// stand-in, and a road that failed recently pays a further penalty on top
/// of whatever its base cost already was.
fn score(path: &Path, now: Instant) -> Duration {
    let base = match path.state {
        PathState::Verified => Duration::from_millis(u64::from(path.ewma_ms.unwrap_or(1000))),
        PathState::Unverified => UNVERIFIED_COST,
        PathState::Dead => DEAD_COST,
    };
    match path.last_failure {
        Some(when) if now.saturating_duration_since(when) < FAILURE_PENALTY_WINDOW => {
            base + FAILURE_PENALTY
        }
        _ => base,
    }
}

pub struct PathTable {
    paths: Vec<Path>,
    next_token: u32,
    /// The latest instant this table has been told about, through `due` or
    /// `on_ack`. `best` and `is_verified` take no clock of their own -- the
    /// caller that drives the schedule already has one -- so this is what
    /// lets them judge a failure's freshness without one.
    last_now: Option<Instant>,
}

impl PathTable {
    pub fn new() -> Self {
        PathTable {
            paths: Vec::new(),
            next_token: 0,
            last_now: None,
        }
    }

    /// Replace the list of roads, keeping everything already known about the
    /// ones that stayed.
    pub fn set_paths(&mut self, addrs: Vec<SocketAddr>) {
        let mut kept: Vec<Path> = Vec::with_capacity(addrs.len().min(MAX_PATHS));
        for addr in addrs.into_iter().take(MAX_PATHS) {
            if let Some(pos) = self.paths.iter().position(|p| p.addr == addr) {
                kept.push(self.paths.remove(pos));
            } else {
                kept.push(Path::new(addr));
            }
        }
        self.paths = kept;
    }

    /// Record that the table has been consulted at `now`, so `best` and
    /// `is_verified` -- which take no `now` of their own -- can still judge
    /// how fresh a failure is. Monotonic: an out-of-order call (e.g. two
    /// `on_ack`s for different roads racing in) never moves the clock back.
    fn touch_now(&mut self, now: Instant) {
        self.last_now = Some(self.last_now.map_or(now, |prev| prev.max(now)));
    }

    /// The checks to send right now, as `(where, token)`. `urgent` speeds the
    /// schedule up -- the caller passes it when the live road is failing.
    /// Also marks dead any road that has been silent for [`PROBE_TIMEOUT`],
    /// counted from when it went quiet rather than from the last check sent
    /// (see [`Path::unanswered_since`]).
    pub fn due(&mut self, now: Instant, urgent: bool) -> Vec<(SocketAddr, u32)> {
        self.touch_now(now);
        let interval = if urgent { PROBE_URGENT } else { PROBE_IDLE };
        let mut out = Vec::new();
        for path in &mut self.paths {
            // Measured from when the road went quiet, NOT from the last
            // check sent -- see `Path::unanswered_since`. Cleared along with
            // the pending check, so the next check that goes out starts the
            // road's silence over and gets its own full timeout to prove the
            // road is back.
            if let Some(since) = path.unanswered_since {
                if now.saturating_duration_since(since) >= PROBE_TIMEOUT {
                    path.in_flight.clear();
                    path.unanswered_since = None;
                    // Stamped on the way INTO `Dead`, not on every expiry once
                    // already there. A road that stays down is still checked on
                    // the ordinary schedule, and each of those checks expires
                    // too; re-stamping here would make `failed_ago_ms` cycle
                    // between nothing and half a minute forever, and the window
                    // would tell someone whose road has been unreachable for a
                    // week that it "failed 12 seconds ago".
                    //
                    // `score`'s recent-failure penalty is unaffected in the
                    // case it exists for: a road that fails once and comes
                    // back transitions into `Dead` exactly once, so it carries
                    // the same stamp -- and the same penalty, for the same
                    // [`FAILURE_PENALTY_WINDOW`] -- as it did before. The only
                    // ranking that moves at all is between two roads that are
                    // BOTH dead, and that ranking decides nothing: `best` is
                    // consulted in one place (`Connection::on_timeout`), which
                    // moves only onto a road [`PathTable::is_verified`] agrees
                    // to, and a dead road never is.
                    if path.state != PathState::Dead {
                        path.last_failure = Some(now);
                    }
                    path.last_expiry = Some(since);
                    path.state = PathState::Dead;
                }
            }
            // A road with a check already out is not skipped: the schedule
            // below still governs when the *next* one goes, and under
            // urgency that can arrive before the pending one has even timed
            // out. Sending it does NOT discard the earlier check -- both
            // stay in `in_flight` below, and an answer to either one still
            // verifies the road -- and it does NOT restart the road's
            // silence, which is what `unanswered_since` keeps and the expiry
            // above reads.
            // Every road is checked on this schedule regardless of its state
            // or how it compares to any other road: a spare that currently
            // looks best but silently dies must still be caught by its own
            // next check, not spared one because it once looked fine.
            let due_now = match path.last_probe {
                None => true,
                Some(last) => now.saturating_duration_since(last) >= interval,
            };
            if !due_now {
                continue;
            }
            let token = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);
            // An entry past PROBE_TIMEOUT can no longer be answered
            // usefully, so it goes before the new check is recorded. The
            // eviction after it is the bound, oldest first -- unreachable on
            // this path, see MAX_IN_FLIGHT.
            path.in_flight
                .retain(|(_, sent)| now.saturating_duration_since(*sent) < PROBE_TIMEOUT);
            if path.in_flight.len() == MAX_IN_FLIGHT {
                path.in_flight.remove(0);
            }
            path.in_flight.push((token, now));
            path.unanswered_since.get_or_insert(now);
            path.last_probe = Some(now);
            out.push((path.addr, token));
        }
        out
    }

    /// An answer arrived carrying `token`. The token, not any address,
    /// identifies which check it is for: only the real peer can produce an
    /// authentic answer carrying it, so it names the road that was checked
    /// exactly, whatever address the answer happens to be sourced from -- a
    /// host can (and, on plain Linux loopback, routinely does) reply from a
    /// different local address than the one the check reached it on. A
    /// token that matches no outstanding check is ignored, same as a late
    /// answer to a check already given up on is today.
    pub fn on_ack(&mut self, token: u32, now: Instant) {
        self.touch_now(now);
        let Some(path) = self
            .paths
            .iter_mut()
            .find(|p| p.in_flight.iter().any(|(t, _)| *t == token))
        else {
            // An answer to a check already given up on, or to one this table
            // never sent: it says nothing about any road now.
            return;
        };
        let sent_at = path
            .in_flight
            .iter()
            .find(|(t, _)| *t == token)
            .map(|(_, sent)| *sent)
            .expect("the entry the search above matched");
        // Everything older than the answered check is moot: the road works.
        path.in_flight.clear();
        path.unanswered_since = None;
        let rtt_ms = now
            .saturating_duration_since(sent_at)
            .as_millis()
            .min(u128::from(u32::MAX)) as u32;
        path.ewma_ms = Some(match path.ewma_ms {
            None => rtt_ms,
            Some(prev) => (0.8 * f64::from(prev) + 0.2 * f64::from(rtt_ms)).round() as u32,
        });
        path.state = PathState::Verified;
    }

    /// The road to prefer, `exclude`d one aside (the caller passes the road
    /// it is already on).
    pub fn best(&self, exclude: Option<SocketAddr>) -> Option<SocketAddr> {
        let now = self.last_now.unwrap_or_else(Instant::now);
        self.paths
            .iter()
            .filter(|p| Some(p.addr) != exclude)
            .min_by_key(|p| score(p, now))
            .map(|p| p.addr)
    }

    /// Whether this road answered its last check. Moving onto a road that
    /// never answered would trade a quiet link for a silent one, so the
    /// caller asks before it moves.
    pub fn is_verified(&self, addr: SocketAddr) -> bool {
        self.paths
            .iter()
            .find(|p| p.addr == addr)
            .map(|p| p.state == PathState::Verified)
            .unwrap_or(false)
    }

    /// Whether this road failed its last check (did not answer within
    /// [`PROBE_TIMEOUT`]). A road the table does not know is not dead: there is
    /// nothing to say about it.
    pub fn is_dead(&self, addr: SocketAddr) -> bool {
        self.paths
            .iter()
            .any(|p| p.addr == addr && p.state == PathState::Dead)
    }

    /// When the check this road failed most recently was sent, while it reads `Dead` -- `None`
    /// for a road that is not dead now, or that the table does not know. The send time, not the
    /// expiry (`PROBE_TIMEOUT` later), and not when the road first went down (that is
    /// [`RoadInfo::failed_ago_ms`]): a road that stays down fails check after check, and this
    /// is the latest of them.
    pub fn failed_at(&self, addr: SocketAddr) -> Option<Instant> {
        self.paths
            .iter()
            .find(|p| p.addr == addr && p.state == PathState::Dead)
            .and_then(|p| p.last_expiry)
    }

    /// Whether `addr` is one of the roads this table was handed -- whatever its state.
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.paths.iter().any(|p| p.addr == addr)
    }

    /// When `due` should next be called, or `None` when there are no roads.
    pub fn next_deadline(&self, now: Instant, urgent: bool) -> Option<Instant> {
        let interval = if urgent { PROBE_URGENT } else { PROBE_IDLE };
        self.paths
            .iter()
            .map(|path| {
                let next_probe = match path.last_probe {
                    None => now,
                    Some(last) => last + interval,
                };
                // A road that has gone quiet has two things ahead of it: the
                // next check on the schedule, and the moment its silence
                // reaches [`PROBE_TIMEOUT`] and it counts as dead. Under
                // urgency the first comes well before the second, so waking
                // only for the timeout -- as this did while expiry was
                // measured from the last check sent -- would skip checks the
                // schedule asked for.
                match path.unanswered_since {
                    Some(since) => next_probe.min(since + PROBE_TIMEOUT),
                    None => next_probe,
                }
            })
            .min()
    }

    /// The token of the most recently sent check to this road, if any --
    /// there may be older ones still awaiting an answer too (see
    /// `Path::in_flight`). Exists for the tests of the layer above: they need
    /// the token that actually went out on the wire, and inventing one there
    /// would test nothing.
    pub fn outstanding_token(&self, addr: SocketAddr) -> Option<u32> {
        self.paths
            .iter()
            .find(|p| p.addr == addr)
            .and_then(|p| p.in_flight.last())
            .map(|(token, _)| *token)
    }

    /// Everything the table knows, as of `now`. Pure: no clock of its own,
    /// nothing mutated -- the caller asks when it has someone to tell.
    pub fn view(&self, now: Instant) -> Vec<RoadInfo> {
        self.paths
            .iter()
            .map(|p| RoadInfo {
                addr: p.addr,
                state: p.state,
                ewma_ms: p.ewma_ms,
                failed_ago_ms: p.last_failure.map(|when| {
                    now.saturating_duration_since(when)
                        .as_millis()
                        .min(u128::from(u32::MAX)) as u32
                }),
            })
            .collect()
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(literal: &str) -> SocketAddr {
        literal.parse().expect("a literal address")
    }

    /// `use_road` asks whether an address is one of the session's roads before anything else:
    /// a road nobody handed in is not one to move onto, whatever state it would be in.
    #[test]
    fn the_table_knows_only_the_roads_it_was_handed() {
        let a: SocketAddr = "192.0.2.1:60000".parse().expect("a literal address");
        let b: SocketAddr = "192.0.2.2:60000".parse().expect("a literal address");
        let mut table = PathTable::new();
        assert!(!table.contains(a), "an empty table knows no roads");
        table.set_paths(vec![a]);
        assert!(table.contains(a));
        assert!(!table.contains(b));
    }

    /// A road is dead only once its own check has timed out -- never checked is not dead,
    /// and a road the table does not know is not dead either.
    #[test]
    fn a_road_is_dead_only_after_its_check_times_out() {
        let a = addr("192.0.2.1:60000");
        let stranger = addr("192.0.2.9:60000");
        let mut table = PathTable::new();
        table.set_paths(vec![a]);
        assert!(!table.is_dead(a), "never checked is not dead");
        let t0 = Instant::now();
        let _ = table.due(t0, true);
        assert!(!table.is_dead(a), "a check in flight is not a failure yet");
        let _ = table.due(t0 + PROBE_TIMEOUT, true);
        assert!(table.is_dead(a), "unanswered past PROBE_TIMEOUT");
        assert!(!table.is_dead(stranger), "an unknown road is not dead");
    }

    /// While the live road is healthy, a backup is checked rarely: this runs
    /// on a phone, and a check every second all day is a cost with nothing to
    /// show for it.
    #[test]
    fn a_healthy_link_checks_its_backups_rarely() {
        let mut t = PathTable::new();
        t.set_paths(vec![addr("10.0.0.1:60000")]);
        let start = Instant::now();

        assert_eq!(
            t.due(start, false).len(),
            1,
            "the first check goes out at once"
        );
        assert!(
            t.due(start + Duration::from_secs(5), false).is_empty(),
            "five seconds later there is nothing to do"
        );
        assert_eq!(
            t.due(start + PROBE_IDLE + Duration::from_secs(1), false)
                .len(),
            1,
            "the idle period is what schedules the next one"
        );
    }

    /// When the live road starts failing, checks speed up -- so that by the
    /// time it goes silent for good, a backup is already verified and the
    /// move is instant.
    #[test]
    fn a_failing_link_checks_its_backups_urgently() {
        let mut t = PathTable::new();
        t.set_paths(vec![addr("10.0.0.1:60000")]);
        let start = Instant::now();
        let _ = t.due(start, false);

        assert!(
            t.due(start + Duration::from_secs(2), true).len() == 1,
            "under urgency the next check comes in a second, not in thirty"
        );
    }

    /// A road that answered once and then went silent must stop being
    /// `Verified`, and the urgent schedule must not be what saves it. Under
    /// urgency a fresh check goes out every [`PROBE_URGENT`] while the old
    /// one is still unanswered; if expiry were measured from the LAST check
    /// sent, its clock would restart every second and never reach
    /// [`PROBE_TIMEOUT`] -- the road would stay `Verified` for as long as you
    /// care to wait, and `is_verified`, which is the gate on moving the
    /// session, would wave the client onto a road that has answered nothing
    /// for ten minutes. Expiry is measured from when the road went quiet
    /// instead.
    #[test]
    fn a_road_that_stops_answering_urgent_checks_stops_being_verified() {
        let mut t = PathTable::new();
        let road = addr("10.0.0.1:60000");
        t.set_paths(vec![road]);
        let start = Instant::now();

        // It answers once: that is what `Verified` means.
        let due = t.due(start, false);
        t.on_ack(due[0].1, start + Duration::from_millis(10));
        assert!(t.is_verified(road), "an answered check verifies the road");

        // From here it answers nothing, while the urgent schedule keeps
        // sending it a fresh check every second -- ten minutes of them.
        let mut now = start;
        for _ in 0..600 {
            now += PROBE_URGENT;
            let _ = t.due(now, true);
        }

        assert!(
            !t.is_verified(road),
            "a road silent for ten minutes must not still be a road we would move onto"
        );
    }

    /// An answered check is what makes a road usable, and its round trip is
    /// the road's latency. Two verified roads are ordered by that latency.
    #[test]
    fn the_faster_verified_road_wins() {
        let mut t = PathTable::new();
        let slow = addr("10.0.0.1:60000");
        let fast = addr("10.0.0.2:60000");
        t.set_paths(vec![slow, fast]);
        let start = Instant::now();
        let due = t.due(start, false);
        let token_of = |a: SocketAddr| {
            due.iter()
                .find(|(addr, _)| *addr == a)
                .map(|(_, token)| *token)
                .expect("both roads are checked")
        };

        t.on_ack(token_of(slow), start + Duration::from_millis(200));
        t.on_ack(token_of(fast), start + Duration::from_millis(20));

        assert_eq!(t.best(None), Some(fast));
        assert_eq!(
            t.best(Some(fast)),
            Some(slow),
            "excluding the one we are on is how the next road is chosen"
        );
    }

    /// A road that just failed is not picked again a second later. Without
    /// the penalty a flapping road would be chosen, fail, and be chosen
    /// again -- the client would spend the outage bouncing instead of
    /// settling on the road that works.
    #[test]
    fn a_road_that_just_failed_is_not_picked_again_immediately() {
        fn token_of(due: &[(SocketAddr, u32)], a: SocketAddr) -> u32 {
            due.iter()
                .find(|(addr, _)| *addr == a)
                .map(|(_, token)| *token)
                .expect("the road is checked")
        }

        let mut t = PathTable::new();
        let flapping = addr("10.0.0.1:60000");
        let steady = addr("10.0.0.2:60000");
        t.set_paths(vec![flapping, steady]);
        let start = Instant::now();

        // Both roads answer their first check -- flapping fast, steady slow.
        let due = t.due(start, false);
        t.on_ack(token_of(&due, flapping), start + Duration::from_millis(10));
        t.on_ack(token_of(&due, steady), start + Duration::from_millis(300));
        assert_eq!(t.best(None), Some(flapping), "on latency alone it wins");

        // Sixty seconds on, both are due again -- but only the steady one
        // answers this time.
        let later = start + Duration::from_secs(60);
        let due = t.due(later, true);
        t.on_ack(token_of(&due, steady), later + Duration::from_millis(300));

        // The flapping road's check times out: it goes `Dead`, with a fresh
        // failure timestamp, and both are due once more.
        let expired = later + PROBE_TIMEOUT + Duration::from_secs(1);
        let due = t.due(expired, true);

        // It answers its very next check right away -- it has recovered,
        // and is `Verified` again with a fast latency -- but the failure is
        // still fresh.
        t.on_ack(
            token_of(&due, flapping),
            expired + Duration::from_millis(10),
        );

        assert_eq!(
            t.best(None),
            Some(steady),
            "a fresh failure outweighs a good latency, for as long as it is fresh"
        );
    }

    /// A road nobody has answered on is worse than any answered one, and a
    /// dead road is worse still -- but neither is out of the running, because
    /// the road that is left may be the only one there is.
    #[test]
    fn an_unverified_road_loses_to_a_verified_one_but_is_still_a_candidate() {
        let mut t = PathTable::new();
        let unverified = addr("10.0.0.1:60000");
        let verified = addr("10.0.0.2:60000");
        t.set_paths(vec![unverified, verified]);
        let start = Instant::now();
        let due = t.due(start, false);
        let token = due
            .iter()
            .find(|(a, _)| *a == verified)
            .map(|(_, t)| *t)
            .expect("the road is checked");
        t.on_ack(token, start + Duration::from_millis(500));

        assert_eq!(t.best(None), Some(verified));
        assert_eq!(
            t.best(Some(verified)),
            Some(unverified),
            "with nothing better left, an unchecked road is still worth trying"
        );
    }

    /// The list comes from someone else's profile, so it is bounded here.
    #[test]
    fn the_number_of_roads_is_capped() {
        let mut t = PathTable::new();
        let many: Vec<SocketAddr> = (0..20)
            .map(|i| addr(&format!("10.0.0.{}:60000", i + 1)))
            .collect();
        t.set_paths(many);
        assert_eq!(
            t.due(Instant::now(), false).len(),
            MAX_PATHS,
            "checks go to at most MAX_PATHS roads, however long the list is"
        );
    }

    /// Handing in the list again -- which happens whenever the owner learns a
    /// new address -- must not throw away what is already known about the
    /// roads that stayed.
    #[test]
    fn re_setting_the_list_keeps_what_is_known_about_the_roads_that_stayed() {
        let mut t = PathTable::new();
        let kept = addr("10.0.0.1:60000");
        t.set_paths(vec![kept]);
        let start = Instant::now();
        let due = t.due(start, false);
        t.on_ack(due[0].1, start + Duration::from_millis(30));
        assert_eq!(t.best(None), Some(kept));

        // The new address goes first this time: if the road that stayed had
        // lost its state, the two would tie as fresh and unverified, and the
        // tie would go the new address's way, not `kept`'s.
        t.set_paths(vec![addr("10.0.0.2:60000"), kept]);
        assert!(
            t.is_verified(kept),
            "the road that stayed did not lose its verified state"
        );
        assert_eq!(
            t.best(None),
            Some(kept),
            "the road that stayed is still the verified one"
        );
    }

    /// The token identifies the check, not any address -- `on_ack` doesn't
    /// even take one. With two checks outstanding on two different roads,
    /// the answer naming one road's token must verify exactly that road,
    /// never the other one, and never "whichever road happens to still have
    /// a check outstanding" (a lookup keyed on `addr` would get exactly one
    /// road right and the other wrong the moment the answer is sourced from
    /// somewhere unexpected -- see `conn.rs`'s test for that scenario end to
    /// end).
    #[test]
    fn on_ack_credits_the_road_named_by_the_token_not_by_any_address() {
        let mut t = PathTable::new();
        let a = addr("10.0.0.1:60000");
        let b = addr("10.0.0.2:60000");
        t.set_paths(vec![a, b]);
        let start = Instant::now();
        let due = t.due(start, false);
        let token_of = |addr_to_find: SocketAddr| {
            due.iter()
                .find(|(addr, _)| *addr == addr_to_find)
                .map(|(_, token)| *token)
                .expect("both roads are checked")
        };

        t.on_ack(token_of(b), start + Duration::from_millis(20));

        assert!(
            t.is_verified(b),
            "the road whose token was answered must verify"
        );
        assert!(
            !t.is_verified(a),
            "a road whose token was NOT answered must stay unverified"
        );
    }

    /// A road slower than the urgent interval still verifies. The answer to a
    /// check arrives after the NEXT check has already gone out, so a table
    /// that remembers only the newest check would throw it away and call a
    /// working road dead.
    #[test]
    fn an_answer_that_arrives_after_the_next_check_still_verifies_the_road() {
        let mut t = PathTable::new();
        let road = addr("10.0.0.1:60000");
        t.set_paths(vec![road]);
        let start = Instant::now();

        let first = t.due(start, true);
        let first_token = first
            .iter()
            .find(|(a, _)| *a == road)
            .map(|(_, token)| *token)
            .expect("the road is checked");
        // A second later, urgency sends another check before the first was
        // answered.
        let _ = t.due(start + PROBE_URGENT, true);
        // Only now does the FIRST check's answer come back: 1.5 s round trip.
        t.on_ack(first_token, start + Duration::from_millis(1500));

        assert!(
            t.is_verified(road),
            "an answer to a check still in flight verifies the road it was sent down"
        );
    }

    /// The road's measured latency comes from the check that was answered,
    /// not from the newest one -- otherwise a slow road would look fast.
    #[test]
    fn the_latency_is_measured_from_the_check_that_was_answered() {
        let mut t = PathTable::new();
        let slow = addr("10.0.0.1:60000");
        let fast = addr("10.0.0.2:60000");
        t.set_paths(vec![slow, fast]);
        let start = Instant::now();

        let due = t.due(start, true);
        let token_of = |a: SocketAddr| {
            due.iter()
                .find(|(addr, _)| *addr == a)
                .map(|(_, token)| *token)
                .expect("both roads are checked")
        };
        let slow_first = token_of(slow);
        // Answered while it is the fast road's only check in flight, so this
        // reads 800 ms under either implementation -- it cannot by itself
        // tell them apart.
        t.on_ack(token_of(fast), start + Duration::from_millis(800));
        // Only now does the slow road get a second check before its first is
        // answered.
        let _ = t.due(start + PROBE_URGENT, true);
        // The answer to the FIRST check: 1.5 s round trip. Measured from the
        // newest in-flight entry instead, this would read 500 ms and beat
        // the fast road's 800.
        t.on_ack(slow_first, start + Duration::from_millis(1500));

        assert_eq!(
            t.best(None),
            Some(fast),
            "the slow road's latency must be its own round trip, not the newest check's"
        );
    }

    /// Still true after the change: a road that answers nothing dies, however
    /// many checks are in flight at once.
    #[test]
    fn a_road_that_answers_none_of_its_checks_still_dies() {
        let mut t = PathTable::new();
        let road = addr("10.0.0.1:60000");
        t.set_paths(vec![road]);
        let start = Instant::now();
        let token = t.due(start, true)[0].1;
        t.on_ack(token, start + Duration::from_millis(10));
        assert!(t.is_verified(road));

        // Ten seconds of urgent checks, none of them answered.
        for step in 1..=10 {
            let _ = t.due(start + Duration::from_secs(step), true);
        }
        assert!(
            !t.is_verified(road),
            "silence past PROBE_TIMEOUT is death, whatever the schedule"
        );
    }

    /// An empty table is the ordinary case for a profile with one address:
    /// nothing is checked, nothing is chosen, nothing costs anything.
    #[test]
    fn an_empty_table_asks_for_nothing() {
        let mut t = PathTable::new();
        assert!(t.due(Instant::now(), false).is_empty());
        assert_eq!(t.best(None), None);
        assert_eq!(t.next_deadline(Instant::now(), false), None);
    }

    /// The snapshot is what the window shows, so it must say the same thing
    /// the table decides by: what state each road is in, how fast it is, and
    /// how long ago it let us down.
    #[test]
    fn the_snapshot_tells_each_road_apart() {
        let mut t = PathTable::new();
        let fast = addr("10.0.0.1:60000");
        let slow = addr("10.0.0.2:60000");
        let never = addr("10.0.0.3:60000");
        t.set_paths(vec![fast, slow, never]);
        let start = Instant::now();

        let due = t.due(start, false);
        let token_of = |a: SocketAddr| {
            due.iter()
                .find(|(addr, _)| *addr == a)
                .map(|(_, token)| *token)
                .expect("every road is checked")
        };
        t.on_ack(token_of(fast), start + Duration::from_millis(20));
        t.on_ack(token_of(slow), start + Duration::from_millis(300));
        // The third one never answers and expires.
        let dead_at = start + PROBE_TIMEOUT + Duration::from_secs(1);
        let _ = t.due(dead_at, false);

        let view = t.view(dead_at + Duration::from_secs(4));
        assert_eq!(view.len(), 3, "every road is in the snapshot");

        let of = |a: SocketAddr| {
            view.iter()
                .find(|r| r.addr == a)
                .expect("the road is in the snapshot")
        };
        assert_eq!(of(fast).state, PathState::Verified);
        assert_eq!(of(fast).ewma_ms, Some(20));
        assert_eq!(of(fast).failed_ago_ms, None, "it never failed");
        assert_eq!(of(slow).ewma_ms, Some(300));
        assert_eq!(of(never).state, PathState::Dead);
        assert_eq!(
            of(never).ewma_ms,
            None,
            "a road that never answered has no latency to show"
        );
        assert_eq!(
            of(never).failed_ago_ms,
            Some(4_000),
            "counted from the failure, not from the check that found it"
        );
    }

    /// A road that stays down is re-checked on the ordinary schedule like any
    /// other, and every one of those checks goes unanswered and expires too.
    /// What the window puts on screen is how long the road has been down, so
    /// that age has to go on growing across those cycles. Re-stamping the
    /// failure on each expiry would reset it every half minute and tell
    /// somebody whose road has been unreachable for a week that it "failed 12
    /// seconds ago" -- which reads as "it was working twelve seconds ago".
    #[test]
    fn a_road_that_stays_dead_counts_from_when_it_went_down() {
        let mut t = PathTable::new();
        let road = addr("10.0.0.1:60000");
        t.set_paths(vec![road]);
        let start = Instant::now();

        // The first check goes out and is never answered: PROBE_TIMEOUT on,
        // the road is dead.
        assert_eq!(t.due(start, false).len(), 1, "the first check goes out");
        let died = start + PROBE_TIMEOUT;
        let _ = t.due(died, false);
        assert_eq!(
            t.view(died).first().expect("the one road").state,
            PathState::Dead,
            "an unanswered check past PROBE_TIMEOUT is what kills a road"
        );

        // Five minutes of the ordinary schedule, nobody ever answering: the
        // same thing a road that is genuinely gone does.
        let span = Duration::from_secs(300);
        let mut now = died;
        let mut checks = 0;
        while now < start + span {
            now = t.next_deadline(now, false).expect("a road left to check");
            checks += t.due(now, false).len();
        }
        assert!(
            checks >= 2,
            "the point of the test is the SECOND and later cycles -- got {checks} checks"
        );

        let age = t
            .view(now)
            .first()
            .expect("the one road")
            .failed_ago_ms
            .expect("a dead road has a failure to report");
        assert_eq!(
            age,
            (span - PROBE_TIMEOUT).as_millis() as u32,
            "the age counts from when the road went down, not from the last check that found it still down"
        );
    }

    /// The stamp is not written once and left: a road that comes back and
    /// then dies again went down a second time, and that second time is what
    /// the window should report -- and what the recent-failure penalty in
    /// `score` should weigh.
    #[test]
    fn a_road_that_dies_again_is_stamped_again() {
        let mut t = PathTable::new();
        let road = addr("10.0.0.1:60000");
        t.set_paths(vec![road]);
        let start = Instant::now();

        // Dies once...
        let _ = t.due(start, false);
        let first_death = start + PROBE_TIMEOUT;
        let _ = t.due(first_death, false);

        // ...answers its next check, so it is verified again...
        let recheck = start + PROBE_IDLE;
        let token = t.due(recheck, false)[0].1;
        t.on_ack(token, recheck + Duration::from_millis(10));
        assert!(t.is_verified(road), "an answer brings a road straight back");

        // ...and then goes quiet a second time.
        let _ = t.due(recheck + PROBE_IDLE, false);
        let second_death = recheck + PROBE_IDLE + PROBE_TIMEOUT;
        let _ = t.due(second_death, false);

        let age = t
            .view(second_death)
            .first()
            .expect("the one road")
            .failed_ago_ms
            .expect("a dead road has a failure to report");
        assert_eq!(
            age, 0,
            "the road went down again just now, not a minute ago"
        );
    }

    /// An empty table is the ordinary case for a profile with one address:
    /// nothing to show, and nothing to compute.
    #[test]
    fn an_empty_table_shows_nothing() {
        let t = PathTable::new();
        assert!(t.view(Instant::now()).is_empty());
    }
}
