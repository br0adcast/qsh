//! The congestion window (spec §4.15): how many bytes of DATA the whole
//! connection keeps in flight, on top of each stream's own `MAX_IN_FLIGHT`.
//! After RFC 5681 -- the initial window of RFC 6928, slow start, congestion
//! avoidance, the response to a retransmit timeout -- and, from the fast
//! retransmit on, RFC 6582 (NewReno), with an undo of a fast retransmit that
//! reordering set off (after RFC 4015) and a duplicate threshold that learns
//! the road's reordering -- and one signal NewReno does not have: a round
//! trip far above the road's base delay cuts the window as a loss would,
//! with a probe that drains the queue now and then to keep that base true.
//! Pure: the connection tells it what the acknowledgements, the round trips
//! and the timer did, and when, and asks it how much may be in flight.
//! Nothing here is on the wire; an older peer notices nothing.

use std::time::{Duration, Instant};

use crate::conn::StreamClass;
use crate::reliability::MAX_SEGMENT_SIZE;

/// One full segment's payload: the unit every rule here counts in.
pub(crate) const SEGMENT: usize = MAX_SEGMENT_SIZE;
/// The window a connection starts with: 10 segments (RFC 6928).
pub(crate) const INITIAL_WINDOW: usize = 10 * SEGMENT;
/// The window after a retransmit timeout: one segment (RFC 5681 §3.1).
pub(crate) const LOSS_WINDOW: usize = SEGMENT;
/// The floor of the slow-start threshold: two segments (RFC 5681 (4)).
pub(crate) const MIN_SSTHRESH: usize = 2 * SEGMENT;
/// What the interactive class may have in flight above the window (spec
/// §4.15): a keystroke never waits for room the bulk data took.
pub(crate) const INTERACTIVE_HEADROOM: usize = 2 * SEGMENT;
/// The window never grows past this. The streams' own windows are the real
/// bound (256 KiB each); this only keeps the arithmetic finite.
pub(crate) const MAX_WINDOW: usize = 4 * 1024 * 1024;
/// What one ACK may count for in the window's growth, in both phases:
/// `ACK_EVERY` segments (RFC 3465's L, spec §4.11). An honest delayed ACK
/// covers that many, so the window grows per round trip as it did with an
/// ACK a segment; a cumulative ACK over several windows -- a hole filled --
/// still counts for no more. An older peer's ACKs cover one segment each.
/// Not in the slow start that follows a retransmit timeout while its ACKs
/// still acknowledge what was in flight at the timeout: there one ACK counts
/// for `SEGMENT` at most (see [`CongestionWindow::on_advance`]).
pub(crate) const MAX_ACKED_PER_ACK: usize = crate::conn::ACK_EVERY * SEGMENT;

/// Duplicate ACKs in a row that count as a loss (RFC 5681 §3.2), until the
/// road shows it reorders deeper (see [`CongestionWindow::on_advance`]).
pub(crate) const DUPLICATE_THRESHOLD: u32 = 3;
/// The deepest the duplicate threshold learns to go. A loss is found by
/// duplicates only while at least threshold + 1 segments are in flight past
/// it; a stream has at most `MAX_IN_FLIGHT` = 256 of them, and a threshold of
/// a quarter of that still leaves fast retransmit working for any window of
/// 65 segments and more, where a timeout costs most. Reordering deeper than
/// 64 segments costs a halving each time, as NewReno's always does.
pub(crate) const MAX_DUPLICATE_THRESHOLD: u32 = 64;

// Half the initial window is above RFC 5681's two-segment floor, so
// `loss_threshold` never needs to apply that floor itself.
const _: () = assert!(INITIAL_WINDOW / 2 >= MIN_SSTHRESH);

/// The slow-start threshold after a loss with `flight` bytes outstanding --
/// a retransmit timeout or a fast retransmit: half of it (RFC 5681 (4)),
/// counting the flight as at least the initial window -- one lost keystroke
/// on a quiet terminal session must not pin the threshold at two segments
/// for the rest of it. That also keeps it at or above `MIN_SSTHRESH`.
fn loss_threshold(flight: usize) -> usize {
    flight.max(INITIAL_WINDOW) / 2
}

/// How far above the road's base delay a round trip may climb before the
/// window takes it as congestion (spec §4.15, the user's decision). NewReno
/// reacts to loss only; a bottleneck buffer as deep as the 256 KiB stream
/// window loses nothing, and on a 64 KB/s uplink that window then stands 4 s
/// deep, the PINGs and road checks behind it. Half a second keeps the
/// standing queue under `PING_INTERVAL` (1.5 s) and `PROBE_TIMEOUT` (3 s),
/// and still well above what a slow road needs to stay busy (its
/// bandwidth-delay product: 6 KB at 64 KB/s and 100 ms).
pub(crate) const QUEUE_DELAY_CAP: Duration = Duration::from_millis(500);

/// How much sooner than the road's base delay an ACK may come and still be
/// the answer to a repair (see [`CongestionWindow::answers_repair`]): the
/// hosts' part of a loaded round trip, which the answer to a lone resend
/// does not carry. The base comes from samples taken under load -- a driver
/// stamps a segment at the start of its pass and sends it at the end, and
/// the peer answers a whole receive batch at once -- while a resend crosses
/// idle hosts. On loopback that answer came 0.44-0.56 ms after the resend
/// against a base of 0.7-1.0 ms: every one read as too early, real losses
/// were undone, and each next hole waited for a 200 ms timeout (final
/// review of slice 2). 2 ms rather than the 1 ms that sufficed on the
/// review machine: a phone is a slower host. On a road whose base is within
/// it the undo rules never fire -- plain NewReno and the retransmit timer;
/// on any other a genuine answer still comes a round trip later.
pub(crate) const HOST_SLACK: Duration = Duration::from_millis(2);

/// How many minutes the base delay remembers: RFC 6817's `BASE_HISTORY`.
pub(crate) const BASE_HISTORY: usize = 10;
/// What one entry of that history stands for.
pub(crate) const BASE_INTERVAL: Duration = Duration::from_secs(60);

/// How near the base delay a round trip must come to show that the road
/// still has it. Well under the queue the delay signal's halving leaves
/// standing (some 200 ms on a 100 ms road), well over a road's own spread of
/// round trips once hundreds of them are taken.
///
/// A receiver of this build holds an ACK at most `ACK_DELAY` (20 ms, spec
/// §4.11), so a round trip an ACK times reads up to 20 ms long. The base
/// itself stays true -- PONGs are answered at once and the minimum takes
/// them -- and 20 ms is well under this tolerance (asserted next to
/// `ACK_DELAY`), so a road seen only through ACKs still reads as seen.
pub(crate) const BASE_TOLERANCE: Duration = Duration::from_millis(50);
/// How long the base may go unseen before the window drains the queue on
/// purpose to see it: a minute before the minute that holds it leaves the
/// history. "Seen" is timed from the start of the minute the round trip
/// fell in, so that margin is a whole minute however late in its minute the
/// round trip came (see [`CongestionWindow::on_round_trip`]).
pub(crate) const BASE_PROBE_AFTER: Duration = Duration::from_secs(9 * 60);
const _: () =
    assert!(BASE_PROBE_AFTER.as_secs() == (BASE_HISTORY as u64 - 1) * BASE_INTERVAL.as_secs());
/// The window a probe drains the queue with: two segments, RFC 5681's
/// floor. BBR's ProbeRTT keeps four packets; a slow uplink's queue empties
/// sooner with two.
pub(crate) const PROBE_WINDOW: usize = 2 * SEGMENT;

/// A road's base delay (spec §4.15): the smallest round trip of the last
/// `BASE_HISTORY` minutes, kept as one minimum per minute, as LEDBAT keeps
/// its own (RFC 6817 §3.4.2). The undo of a spurious fast retransmit and the
/// queue-delay signal both measure against it. Ten minutes rather than
/// seconds: a bulk transfer's standing queue must not become "the road" --
/// behind a 30 s window its round trip did within half a minute, and a
/// genuine loss was then taken for reordering (Task 4 re-review). Not
/// forever either: a road that got slower without a move gets its own delay
/// back once the faster minutes have left the history, instead of keeping
/// the delay signal on for good. The minute that held a sample counts for
/// between nine and ten minutes after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BaseDelay {
    /// When the minute `minima[0]` stands for began; `None` before the first
    /// sample.
    since: Option<Instant>,
    /// The smallest sample of each minute, the current one first; `None` for
    /// a minute that had none.
    minima: [Option<Duration>; BASE_HISTORY],
}

impl BaseDelay {
    fn get(&self) -> Option<Duration> {
        self.minima.iter().flatten().min().copied()
    }

    /// When the minute the latest sample fell in began.
    fn minute_began(&self) -> Option<Instant> {
        self.since
    }

    fn update(&mut self, now: Instant, sample: Duration) {
        let since = *self.since.get_or_insert(now);
        let whole = now.saturating_duration_since(since).as_secs() / BASE_INTERVAL.as_secs();
        if whole >= BASE_HISTORY as u64 {
            // Nothing from before counts any more.
            self.minima = [None; BASE_HISTORY];
            self.since = Some(now);
        } else if whole > 0 {
            // Every minute that passed, with a sample or not, moves the
            // history on; the oldest ones fall off its end.
            let whole = whole as usize;
            self.minima.rotate_right(whole);
            self.minima[..whole].fill(None);
            self.since = Some(since + BASE_INTERVAL * whole as u32);
        }
        let current = &mut self.minima[0];
        *current = Some(current.map_or(sample, |m| m.min(sample)));
    }
}

/// The window as a fast retransmit found it: put back if the retransmit
/// turns out spurious.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Before {
    cwnd: usize,
    ssthresh: usize,
    acked_since_growth: usize,
    last_reduction: Option<Instant>,
}

/// A base probe in progress (spec §4.15, after BBR's ProbeRTT and LEDBAT++'s
/// periodic slowdown): the window held at `PROBE_WINDOW` until the queue we
/// built is gone and a round trip without it is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Probe {
    /// When the flight first fell to what the probe lets out -- the window
    /// and the interactive allowance; `None` while the queue still drains.
    pub(crate) emptied_at: Option<Instant>,
    /// The flight when the probe began, and the round trip it took: the
    /// rate the road delivered, queue and all.
    flight: usize,
    round_trip: Duration,
}

/// Test-only: how often the window was cut, by what.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cuts {
    pub(crate) timeouts: u32,
    pub(crate) timeouts_undone: u32,
    pub(crate) fast_retransmits: u32,
    pub(crate) delay_signal: u32,
    pub(crate) probes: u32,
}

/// A set of stream numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StreamSet([u64; 4]);

impl StreamSet {
    fn of(ids: &[u8]) -> Self {
        let mut set = [0u64; 4];
        for &id in ids {
            set[usize::from(id / 64)] |= 1 << (id % 64);
        }
        StreamSet(set)
    }

    fn contains(&self, id: u8) -> bool {
        self.0[usize::from(id / 64)] & (1 << (id % 64)) != 0
    }
}

/// A retransmit timeout that may still turn out spurious (see
/// [`CongestionWindow::undo_timeout_if_spurious`]): the window as the
/// timeout found it, when it resent, and which streams it was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Timeout {
    before: Before,
    dup_threshold: u32,
    /// A probe the timeout ended.
    probe: Option<Probe>,
    resent_at: Instant,
    streams: StreamSet,
}

/// A fast recovery in progress (RFC 6582): on which stream, and the offset
/// that stream had sent up to when the loss was found, full (spec §4.14) --
/// an ACK reaching it ends the recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recovery {
    pub(crate) stream_id: u8,
    pub(crate) recover: u64,
    /// When the last repair went out: the fast retransmit, then the resend
    /// each partial ACK asked for.
    repaired_at: Instant,
    /// Whether that repair is still the fast retransmit itself: no ACK has
    /// moved the stream's base since the recovery began.
    first_repair: bool,
    /// Duplicates of this loss so far, while `first_repair`: how many
    /// segments got past the one taken for lost.
    duplicates: u32,
    before: Before,
}

/// What the connection must do after telling the window about an ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AckVerdict {
    Nothing,
    /// Resend the stream's oldest unacknowledged segment now, whatever the
    /// window says.
    RetransmitOldest,
    /// The recovery on this stream ended with everything in flight at the
    /// loss acknowledged. The stream's repairs may still be on their way and
    /// draw ACKs of the base: hold its next fast retransmit until the base
    /// passes `recover`, where the recovery began (RFC 6582 §3.2 step 1).
    /// Data first sent during the recovery is not held.
    Recovered {
        recover: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CongestionWindow {
    cwnd: usize,
    /// `usize::MAX` until the first loss: no threshold yet.
    ssthresh: usize,
    /// Congestion avoidance: bytes acknowledged since the window last grew.
    acked_since_growth: usize,
    /// The fast recovery in progress, if any. One at a time for the whole
    /// connection: one loss event cuts the window once.
    recovery: Option<Recovery>,
    /// Duplicates in a row that count as a loss: `DUPLICATE_THRESHOLD`, or
    /// more once a fast retransmit turned out spurious -- the reordering the
    /// road showed, plus one (like Linux's `tcp_reordering`).
    dup_threshold: u32,
    /// The road's base delay, since the window last started: an answer to a
    /// resend is not expected sooner, and a round trip far above it is our
    /// own queue.
    base_delay: BaseDelay,
    /// When the window was last cut -- by a timeout, a fast retransmit, the
    /// delay signal or a probe: the delay signal cuts at most once per round
    /// trip, and a probe does not start within one of a cut.
    last_reduction: Option<Instant>,
    /// When the minute began in which a round trip last came within
    /// `BASE_TOLERANCE` of the base, or a probe measured the road (or counted
    /// as measured, see [`CongestionWindow::on_round_trip`]).
    base_seen: Option<Instant>,
    /// When the sender last had data it could not send yet -- held by this
    /// window, the bulk budget or a stream's own window: when it was not
    /// the application that set the pace.
    backlog_at: Option<Instant>,
    /// The base probe in progress, if any.
    probe: Option<Probe>,
    /// The latest retransmit timeout, until the first ACK of a stream it
    /// named says whether it was spurious.
    timeout: Option<Timeout>,
    #[cfg(test)]
    cuts: Cuts,
}

impl CongestionWindow {
    pub(crate) fn new() -> Self {
        CongestionWindow {
            cwnd: INITIAL_WINDOW,
            ssthresh: usize::MAX,
            acked_since_growth: 0,
            recovery: None,
            dup_threshold: DUPLICATE_THRESHOLD,
            base_delay: BaseDelay::default(),
            last_reduction: None,
            base_seen: None,
            backlog_at: None,
            probe: None,
            timeout: None,
            #[cfg(test)]
            cuts: Cuts::default(),
        }
    }

    /// A move onto another road, a rebind, a wake from sleep (spec §4.15):
    /// what the window knew describes a road that may not be there any more.
    pub(crate) fn restart(&mut self) {
        *self = CongestionWindow::new();
    }

    // Read only by the test hooks for now; the fast retransmit and the
    // queue-delay signal read them from the connection.
    #[cfg(any(test, feature = "testnet"))]
    pub(crate) fn cwnd(&self) -> usize {
        self.cwnd
    }

    #[cfg(any(test, feature = "testnet"))]
    pub(crate) fn ssthresh(&self) -> Option<usize> {
        (self.ssthresh != usize::MAX).then_some(self.ssthresh)
    }

    /// What `class` may have in flight: the window, and for the interactive
    /// class two segments more.
    pub(crate) fn limit(&self, class: StreamClass) -> usize {
        match class {
            StreamClass::Interactive => self.cwnd + INTERACTIVE_HEADROOM,
            StreamClass::Bulk => self.cwnd,
        }
    }

    /// Whether `class` may put out another segment with `pipe` bytes in the
    /// network for the whole connection, `own` of them its own: below its
    /// [`CongestionWindow::limit`] -- and the interactive class also while it
    /// has less than `INTERACTIVE_HEADROOM` of its own out, whatever the bulk
    /// class holds (spec §4.15: a keystroke does not wait for the bulk
    /// queue). The check comes before a segment, so the class may reach about
    /// two segments: two and up to a segment less a byte. The bulk flight stands above the window after a cut until it
    /// drains, and during a probe for the whole drain.
    pub(crate) fn may_send(&self, class: StreamClass, pipe: usize, own: usize) -> bool {
        pipe < self.limit(class)
            || (class == StreamClass::Interactive && own < INTERACTIVE_HEADROOM)
    }

    /// A flush at `now` left data unsent: the sender, not the application,
    /// set the pace. The delay signal and the probe act only on a queue a
    /// sender like that may have built (see
    /// [`CongestionWindow::on_round_trip`]).
    pub(crate) fn note_backlog(&mut self, now: Instant) {
        self.backlog_at = Some(now);
    }

    /// Whether the sender had data waiting within the round trip `sample`
    /// that ends at `now`: whether the queue that round trip saw can be ours.
    fn backlogged_within(&self, now: Instant, sample: Duration) -> bool {
        self.backlog_at
            .is_some_and(|t| now.saturating_duration_since(t) <= sample)
    }

    /// An ACK acknowledged `acked` new bytes. Only a window that was the
    /// limit when they went out (`window_limited`) grows: one nobody filled
    /// -- keystrokes -- would otherwise grow without ever being tried, then
    /// take a burst all at once. `timeout_flight`: the ACK acknowledges some
    /// of what was in flight at the latest retransmit timeout (see
    /// [`CongestionWindow::on_advance`]).
    fn on_acked(&mut self, acked: usize, window_limited: bool, timeout_flight: bool) {
        // A probe holds the window: the ACKs of what drains are not room.
        if !window_limited || acked == 0 || self.probe.is_some() {
            return;
        }
        if self.cwnd < self.ssthresh {
            // Slow start, RFC 5681 (2) with RFC 3465: what the ACK covered, up to
            // `MAX_ACKED_PER_ACK` -- or up to one segment in the round trip
            // after a timeout (RFC 3465 §2.3).
            let limit = if timeout_flight {
                SEGMENT
            } else {
                MAX_ACKED_PER_ACK
            };
            self.cwnd += acked.min(limit);
        } else {
            // Congestion avoidance, RFC 5681 (3): about one segment per
            // window, each ACK counting for at most `MAX_ACKED_PER_ACK`.
            self.acked_since_growth += acked.min(MAX_ACKED_PER_ACK);
            if self.acked_since_growth >= self.cwnd {
                self.acked_since_growth -= self.cwnd;
                self.cwnd += SEGMENT;
            }
        }
        self.cwnd = self.cwnd.min(MAX_WINDOW);
    }

    /// The retransmit timer expired at `now` with `flight` bytes outstanding
    /// (RFC 5681 §3.1), for the oldest segments of `timed_out` streams, which
    /// go out again now: half the flight is the new threshold (see
    /// [`loss_threshold`]), and one segment the window. What the timeout
    /// found is kept until the first ACK of one of those streams says
    /// whether it was spurious (see
    /// [`CongestionWindow::undo_timeout_if_spurious`]) -- not for a timeout
    /// that ends a recovery: its repair went unanswered, a loss more likely
    /// than not.
    pub(crate) fn on_retransmit_timeout(&mut self, now: Instant, flight: usize, timed_out: &[u8]) {
        self.timeout = (!timed_out.is_empty() && self.recovery.is_none()).then(|| Timeout {
            before: Before {
                cwnd: self.cwnd,
                ssthresh: self.ssthresh,
                acked_since_growth: self.acked_since_growth,
                last_reduction: self.last_reduction,
            },
            dup_threshold: self.dup_threshold,
            probe: self.probe,
            resent_at: now,
            streams: StreamSet::of(timed_out),
        });
        self.ssthresh = loss_threshold(flight);
        self.cwnd = LOSS_WINDOW;
        self.acked_since_growth = 0;
        self.note_reduction(now);
        #[cfg(test)]
        {
            self.cuts.timeouts += 1;
        }
        // The timeout is the stronger response: whatever the recovery was
        // repairing now goes out again under the timeout's window. A probe
        // ends unmeasured and comes again once it may.
        self.recovery = None;
        self.probe = None;
        // The duplicates that should have found the loss did not come: the
        // reordering the threshold learned is overestimated, or the loss was
        // in a flight too short for it. Back to three, whatever it had
        // learned -- our rule (review round 2); Linux's `tcp_enter_loss`
        // lowers its `reordering` only in a narrower case.
        self.dup_threshold = DUPLICATE_THRESHOLD;
    }

    #[cfg(test)]
    pub(crate) fn recovery(&self) -> Option<Recovery> {
        self.recovery
    }

    #[cfg(test)]
    pub(crate) fn dup_threshold(&self) -> u32 {
        self.dup_threshold
    }

    #[cfg(test)]
    pub(crate) fn base_delay(&self) -> Option<Duration> {
        self.base_delay.get()
    }

    #[cfg(test)]
    pub(crate) fn probe(&self) -> Option<Probe> {
        self.probe
    }

    #[cfg(test)]
    pub(crate) fn backlog_at(&self) -> Option<Instant> {
        self.backlog_at
    }

    #[cfg(test)]
    pub(crate) fn cuts(&self) -> Cuts {
        self.cuts
    }

    /// A round-trip sample taken at `now` -- a PONG, or an ACK timed by
    /// Karn's rule -- with `flight` bytes outstanding.
    ///
    /// It is the queue-delay signal (spec §4.15): more than
    /// `QUEUE_DELAY_CAP` above the road's base delay is a congestion event
    /// with the fast retransmit's response -- the threshold half the flight
    /// (see [`loss_threshold`]), the window down to it -- but nothing is
    /// resent: nothing was lost. Only while the sender had data waiting
    /// within that round trip (see [`CongestionWindow::note_backlog`]): an
    /// application-limited sender -- a terminal session, the server's
    /// output while the client uploads -- is not what stands in the queue
    /// its round trips cross, and cutting its window would only slow its next
    /// burst. At most once per round trip (the samples of what was already
    /// queued say the same thing again, and a loss the window just answered
    /// was the same queue), never during a recovery, which has already cut,
    /// and never up: a window below the threshold stays where it is.
    ///
    /// And it keeps the base true. Behind a buffer deeper than the road
    /// needs, the halving leaves a queue standing, and a transfer that never
    /// pauses would carry it into every round trip for as long as it runs;
    /// so would a window the stream's own limit holds below the cap. Taken
    /// from such samples, the base would rise each time its minute left the
    /// history, and the cap and the undo with it. So once the base has gone
    /// unseen for `BASE_PROBE_AFTER`, a probe drains the queue: see
    /// [`CongestionWindow::start_probe`]. Only where our own flight can be
    /// holding that queue: data waiting within the round trip, and more in
    /// flight than the probe would leave (`PROBE_WINDOW` and the interactive
    /// allowance). Otherwise the round trip already measures the road as it
    /// is for us, someone else's queue and all, and the due probe counts as
    /// done without touching the window. Not during a recovery, and not
    /// within a round trip of a cut -- a cut drains already, and its round
    /// trip still carries the queue it drains; the probe comes with the
    /// first sample after that.
    ///
    /// Returns whether a probe's queue emptied with this round trip: the
    /// caller then has the road measured by an answer no receiver holds (a
    /// PING's), since the next round trip becomes the base.
    pub(crate) fn on_round_trip(&mut self, now: Instant, sample: Duration, flight: usize) -> bool {
        self.base_delay.update(now, sample);
        let Some(base) = self.base_delay.get() else {
            return false;
        };
        if sample <= base.saturating_add(BASE_TOLERANCE) {
            self.see_base(now);
        }
        if let Some(probe) = self.probe {
            self.probe_round_trip(probe, now, sample, flight);
            return probe.emptied_at.is_none()
                && self.probe.is_some_and(|p| p.emptied_at.is_some());
        }
        if self.recovery.is_some()
            || self
                .last_reduction
                .is_some_and(|t| now.saturating_duration_since(t) < sample)
        {
            return false;
        }
        let ours = self.backlogged_within(now, sample);
        if self
            .base_seen
            .is_some_and(|seen| now.saturating_duration_since(seen) >= BASE_PROBE_AFTER)
        {
            if ours && flight > PROBE_WINDOW + INTERACTIVE_HEADROOM {
                self.start_probe(now, sample, flight);
            } else {
                // Nothing of ours to drain: this round trip is the road as
                // it is for us, someone else's queue and all.
                self.see_base(now);
            }
            return false;
        }
        if ours && sample > base.saturating_add(QUEUE_DELAY_CAP) {
            self.ssthresh = loss_threshold(flight);
            self.cwnd = self.cwnd.min(self.ssthresh);
            self.acked_since_growth = 0;
            self.note_reduction(now);
            #[cfg(test)]
            {
                self.cuts.delay_signal += 1;
            }
        }
        false
    }

    /// Start a base probe at `now`, `flight` bytes in flight taking a round
    /// trip of `sample`: the window down to `PROBE_WINDOW`, held there while
    /// what is in flight drains. The threshold keeps the window it leaves --
    /// or the one a slow start was already heading for -- until the probe
    /// ends (a loss or a timeout during it answers with a threshold of its
    /// own). The interactive class keeps its own allowance (see
    /// [`CongestionWindow::may_send`]); control frames never wait for the
    /// window.
    fn start_probe(&mut self, now: Instant, sample: Duration, flight: usize) {
        self.ssthresh = if self.ssthresh == usize::MAX {
            self.cwnd
        } else {
            self.ssthresh.max(self.cwnd)
        };
        self.cwnd = self.cwnd.min(PROBE_WINDOW);
        self.acked_since_growth = 0;
        self.note_reduction(now);
        self.probe = Some(Probe {
            emptied_at: None,
            flight,
            round_trip: sample,
        });
        #[cfg(test)]
        {
            self.cuts.probes += 1;
        }
    }

    /// A round trip during a probe. The queue is gone once the flight has
    /// fallen to what the probe lets out; the probe ends with the first round
    /// trip of something sent after that -- the road measured without our
    /// queue, whatever it measured: a road that got slower is measured as it
    /// is, and the old base leaves the history within the minute.
    ///
    /// The slow start back begins there, towards what the road carries
    /// without the queue: the rate it delivered when the probe began (the
    /// flight over its round trip) times the round trip just measured --
    /// within half the initial window and the window the probe left. Not the
    /// old window: what it held above that was the queue the probe drained,
    /// and a slow start that doubles past the road's bandwidth-delay product
    /// sends at twice the rate the road delivers in its last round. On a
    /// 250 KB/s, 800 ms road with the stream window's 256 segments that
    /// burst stood 535 ms deep, the delay signal halved the window a round
    /// trip later, and congestion avoidance took a minute to fill the road
    /// again: 22 % of the probe's minute, against 6 % climbing to the
    /// estimate. Congestion avoidance grows the queue back from there, a
    /// segment a round trip.
    fn probe_round_trip(&mut self, probe: Probe, now: Instant, sample: Duration, flight: usize) {
        match probe.emptied_at {
            None if flight <= self.cwnd + INTERACTIVE_HEADROOM => {
                self.probe = Some(Probe {
                    emptied_at: Some(now),
                    ..probe
                });
            }
            Some(emptied) if now.checked_sub(sample).is_some_and(|sent| sent >= emptied) => {
                let carried = (probe.flight as u128 * sample.as_nanos()
                    / probe.round_trip.as_nanos().max(1)) as usize;
                self.ssthresh =
                    carried.clamp(INITIAL_WINDOW / 2, self.ssthresh.max(INITIAL_WINDOW / 2));
                self.probe = None;
                self.see_base(now);
            }
            _ => {}
        }
    }

    /// An ACK at `now` moved `stream_id`'s base: whether it shows the latest
    /// retransmit timeout spurious, and if so undo it. The first ACK of a
    /// stream the timeout named decides, once (after RFC 5682's F-RTO and
    /// the Eifel algorithm, without their timestamps): sooner than the
    /// road's base delay after the resend (by more than `HOST_SLACK`), it
    /// cannot answer the resend, so it answers the original -- the segment
    /// was only late, the ACK slower than the timeout allowed (a queue that
    /// grew on the way back, the timeout still measured on an idle road).
    /// The window, its threshold, the learned duplicate threshold and a
    /// probe the timeout ended go back to what the timeout found; the
    /// connection gives back the timer's back-off and forgets the lost marks
    /// the timeout set. A recovery begun since is a newer cut and ends the
    /// chance of an undo.
    ///
    /// The same heuristic as the fast retransmit's undo (see
    /// [`CongestionWindow::answers_repair`]), with its limits: an ACK that
    /// the queue on the way back holds for longer than the base after the
    /// resend reads as an answer to it, and the timeout stands. And one of
    /// its own: the timeout's hold on fast retransmit stays after an undo, so
    /// a real loss right behind the late segment -- its duplicates held --
    /// is found only by the next timeout, not by the duplicates as after the
    /// fast retransmit's undo. Giving the hold back cost more than it saved:
    /// on a road that holds 1 % of the datagrams back by 150 ms, 36.4 s
    /// against 26.9 s for 8 MiB.
    pub(crate) fn undo_timeout_if_spurious(&mut self, stream_id: u8, now: Instant) -> bool {
        let Some(t) = self.timeout else {
            return false;
        };
        if !t.streams.contains(stream_id) {
            return false;
        }
        self.timeout = None;
        if self.answers_repair(now, t.resent_at) {
            return false;
        }
        self.cwnd = t.before.cwnd;
        self.ssthresh = t.before.ssthresh;
        self.acked_since_growth = t.before.acked_since_growth;
        self.last_reduction = t.before.last_reduction;
        self.dup_threshold = t.dup_threshold;
        self.probe = t.probe;
        #[cfg(test)]
        {
            self.cuts.timeouts_undone += 1;
        }
        true
    }

    /// The base counts as seen as of the minute `now` falls in (see
    /// `BASE_PROBE_AFTER`).
    fn see_base(&mut self, now: Instant) {
        self.base_seen = Some(self.base_delay.minute_began().unwrap_or(now));
    }

    /// The window was cut at `now`: the delay signal waits a round trip.
    fn note_reduction(&mut self, now: Instant) {
        self.last_reduction = Some(now);
    }

    /// Whether an ACK at `now` can be the answer to a repair sent at
    /// `repaired_at`: a heuristic, RFC 8985 §6.2's for RACK ("last
    /// (re)transmitted less than min_rtt ago"). The answer to a resend takes
    /// a round trip, and round trips are rarely shorter than the road's base
    /// delay; an ACK sooner than that -- by more than `HOST_SLACK`, the
    /// hosts' part of the loaded round trips the base is taken from -- most
    /// likely answers a copy sent before the repair: the segment taken for
    /// lost was only late. The whole base delay rather than half:
    /// reordering by most of a round trip is still caught (80 ms on a
    /// 100 ms road, review round 1: twice as slow with half), and on a road
    /// with delay variation and loss the two measured the same.
    ///
    /// It is not a certainty. A genuine answer can come sooner than that --
    /// the rare low tail of delay variation, a road that got faster by more
    /// than the slack: then a real loss is taken for spurious, its halving
    /// skipped (and, for a fast retransmit, the duplicate threshold raised).
    /// Bounded in time, not in count: until a round trip measured on the
    /// faster road lowers the base -- a PONG, one every `PING_INTERVAL`, or
    /// an ACK Karn's rule times -- every repair answered that early may be
    /// misread. After an undone fast retransmit the ACKs of the data behind
    /// it are timed soon; after an undone timeout the ACKs that follow cover
    /// resent segments or jump a hole over them, Karn times neither, and the
    /// next timeout may be undone as well (on loopback, before the slack,
    /// five in a row until a PONG came). Each loss taken for spurious is
    /// found again by the next duplicates or the next timeout, and a timeout
    /// puts the duplicate threshold back at three. A standing queue drains a
    /// little behind a hole, but it does not become the base: the history
    /// keeps the road's own round trip for ten minutes (see [`BaseDelay`]),
    /// and a probe measures it again before they pass (see
    /// [`CongestionWindow::on_round_trip`]). The other way, a base from
    /// before the road got slower leaves reordering deeper than it
    /// undetected -- plain NewReno, until that minute leaves the history.
    /// With nothing measured, every ACK answers.
    fn answers_repair(&self, now: Instant, repaired_at: Instant) -> bool {
        self.base_delay
            .get()
            .is_none_or(|base| now.saturating_duration_since(repaired_at) + HOST_SLACK >= base)
    }

    /// An ACK at `now` moved `stream_id`'s base to `cum_ack` (a full offset),
    /// acknowledging `acked` new bytes (RFC 6582 §3.2 steps 4-5; outside a
    /// recovery RFC 5681).
    ///
    /// In the recovery's stream, an ACK too early to answer the last repair
    /// (see [`CongestionWindow::answers_repair`]) was drawn by a segment sent
    /// before it: after the fast retransmit, the segment taken for lost
    /// arrived after all -- the retransmit was spurious and is undone (after
    /// RFC 4015): the window and threshold go back to what they were, and the
    /// duplicate threshold rises to the reordering this showed. Later on, it
    /// is an in-flight segment arriving, not a sign of the next hole: the
    /// window deflates, nothing is resent.
    ///
    /// `timeout_flight`: the ACK acknowledges some of what the stream had in
    /// flight at the latest retransmit timeout -- the round trip after the
    /// timeout, which for this stream lasts until its base reaches where it
    /// had sent up to then (the connection keeps that point, see
    /// `StreamSender::acks_timeout_flight`). Such an ACK counts for one
    /// segment of slow start at most, not `MAX_ACKED_PER_ACK` (RFC 3465
    /// §2.3, L = 1 SMSS after a timeout): the resend fills a hole the
    /// receiver held the rest of the flight behind, and the ACK that answers
    /// it covers all of that at once -- counted as four segments, the window
    /// the timeout left at one would let five out in one burst. The ACKs of
    /// what goes out after that point cover only what the window let out
    /// since, and count as any other. Why that point and not the whole slow
    /// start RFC 3465 names: past it no ACK can acknowledge anything the
    /// receiver held from before the timeout, so the limit would only slow
    /// the delayed ACKs of this build to a segment each (spec §4.11).
    /// Congestion avoidance needs no such limit: there an ACK grows the
    /// window by one segment at most whatever it covers.
    pub(crate) fn on_advance(
        &mut self,
        stream_id: u8,
        cum_ack: u64,
        acked: usize,
        window_limited: bool,
        timeout_flight: bool,
        now: Instant,
    ) -> AckVerdict {
        match self.recovery {
            Some(r) if r.stream_id == stream_id => {
                let answers = self.answers_repair(now, r.repaired_at);
                if !answers && r.first_repair {
                    self.undo(r);
                    self.on_acked(acked, window_limited, timeout_flight);
                    return AckVerdict::Nothing;
                }
                if cum_ack >= r.recover {
                    // Everything in flight at the loss is acknowledged:
                    // recovery ends with the halved window (spec §4.15).
                    self.cwnd = self.ssthresh.min(MAX_WINDOW);
                    self.recovery = None;
                    return AckVerdict::Recovered { recover: r.recover };
                }
                // Deflate by what arrived; a full segment of it lets one
                // more segment out (RFC 6582 step 4).
                let back = if acked >= SEGMENT { SEGMENT } else { 0 };
                self.cwnd = self.cwnd.saturating_sub(acked).max(LOSS_WINDOW) + back;
                if !answers {
                    self.recovery = Some(Recovery {
                        first_repair: false,
                        ..r
                    });
                    return AckVerdict::Nothing;
                }
                // A partial ACK, the answer to the last repair: the next hole
                // is lost too. Resend it at once.
                self.recovery = Some(Recovery {
                    repaired_at: now,
                    first_repair: false,
                    ..r
                });
                AckVerdict::RetransmitOldest
            }
            // Another stream's ACK while one recovers: no growth until the
            // recovery ends.
            Some(_) => AckVerdict::Nothing,
            None => {
                self.on_acked(acked, window_limited, timeout_flight);
                AckVerdict::Nothing
            }
        }
    }

    /// The fast retransmit that began `r` was spurious: back to the window
    /// before it, and a duplicate threshold one past the reordering it met.
    fn undo(&mut self, r: Recovery) {
        self.cwnd = r.before.cwnd;
        self.ssthresh = r.before.ssthresh;
        self.acked_since_growth = r.before.acked_since_growth;
        self.last_reduction = r.before.last_reduction;
        self.recovery = None;
        let depth = (r.duplicates + 1).min(MAX_DUPLICATE_THRESHOLD);
        self.dup_threshold = self.dup_threshold.max(depth);
    }

    /// `stream_id` got its `count`-th duplicate ACK in a row (as
    /// [`crate::reliability::AckEffect::duplicates`] defines one) at `now`,
    /// with `flight` bytes outstanding on the connection and `recover` the
    /// offset the stream has sent up to. The connection does not ask while
    /// the stream's fast retransmit is held (RFC 6582 §3.2 step 1, see
    /// [`AckVerdict::Recovered`]).
    pub(crate) fn on_duplicate(
        &mut self,
        stream_id: u8,
        count: u32,
        flight: usize,
        recover: u64,
        now: Instant,
    ) -> AckVerdict {
        match self.recovery {
            // RFC 6582 §3.2 step 3: every duplicate during the recovery --
            // after a partial ACK the count starts again from one -- means
            // one more segment has left the network.
            Some(r) if r.stream_id == stream_id => {
                self.cwnd = (self.cwnd + SEGMENT).min(MAX_WINDOW);
                if r.first_repair {
                    self.recovery = Some(Recovery {
                        duplicates: r.duplicates + 1,
                        ..r
                    });
                }
                AckVerdict::Nothing
            }
            // Another stream lost a segment during a recovery: repair it,
            // but one loss event cuts the window once.
            Some(_) if count == self.dup_threshold => AckVerdict::RetransmitOldest,
            Some(_) => AckVerdict::Nothing,
            None if count == self.dup_threshold => {
                let before = Before {
                    cwnd: self.cwnd,
                    ssthresh: self.ssthresh,
                    acked_since_growth: self.acked_since_growth,
                    last_reduction: self.last_reduction,
                };
                self.ssthresh = loss_threshold(flight);
                // Each duplicate is a segment that left the network.
                self.cwnd = self.ssthresh + count as usize * SEGMENT;
                self.acked_since_growth = 0;
                self.note_reduction(now);
                // A loss during a probe: its response takes over, and the
                // probe comes again once it may -- the road was not measured.
                self.probe = None;
                // A newer cut than a timeout still waiting for its verdict:
                // undoing that timeout would undo this one too.
                self.timeout = None;
                #[cfg(test)]
                {
                    self.cuts.fast_retransmits += 1;
                }
                self.recovery = Some(Recovery {
                    stream_id,
                    recover,
                    repaired_at: now,
                    first_repair: true,
                    duplicates: count,
                    before,
                });
                AckVerdict::RetransmitOldest
            }
            None => AckVerdict::Nothing,
        }
    }

    /// `stream_id` dropped its backlog (a desync): a recovery on it has
    /// nothing left to recover, and ends as a full ACK would end it.
    pub(crate) fn forget_stream(&mut self, stream_id: u8) {
        if self.recovery.is_some_and(|r| r.stream_id == stream_id) {
            self.cwnd = self.ssthresh.min(MAX_WINDOW);
            self.recovery = None;
        }
    }

    /// Test-only: a window that never limits, for tests about something else.
    #[cfg(test)]
    pub(crate) fn open_for_test(&mut self) {
        self.cwnd = MAX_WINDOW;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_window_is_ten_segments_with_no_threshold() {
        let cc = CongestionWindow::new();
        assert_eq!(cc.cwnd(), 10 * SEGMENT);
        assert_eq!(cc.ssthresh(), None);
    }

    #[test]
    fn the_interactive_class_may_have_two_segments_more_in_flight() {
        let cc = CongestionWindow::new();
        assert_eq!(cc.limit(StreamClass::Bulk), 10 * SEGMENT);
        assert_eq!(cc.limit(StreamClass::Interactive), 12 * SEGMENT);
    }

    /// RFC 5681 (2): in slow start every acknowledged segment adds one.
    #[test]
    fn slow_start_adds_a_segment_for_every_segment_acknowledged() {
        let mut cc = CongestionWindow::new();
        for _ in 0..10 {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), 20 * SEGMENT);
        cc.on_acked(10 * SEGMENT, true, false);
        assert_eq!(
            cc.cwnd(),
            24 * SEGMENT,
            "at most ACK_EVERY segments per ACK"
        );
    }

    /// RFC 3465 §2.3 (final review M3, ruling R20): in the round trip after
    /// a retransmit timeout the ACK that answers the resend covers what the
    /// receiver held past the hole -- ten segments here -- and counts for one
    /// segment: the window goes 1 -> 2, not 1 -> 5. Past what was in flight
    /// at the timeout an ACK of four counts four again, and so does one in
    /// an ordinary slow start.
    #[test]
    fn after_a_timeout_an_ack_of_its_flight_counts_one_segment() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), 40 * SEGMENT, &[]);
        assert_eq!(cc.cwnd(), SEGMENT);
        let now = Instant::now();
        let _ = cc.on_advance(14, 10 * 1024, 10 * SEGMENT, true, true, now);
        assert_eq!(cc.cwnd(), 2 * SEGMENT, "one segment for the stretch ACK");
        let _ = cc.on_advance(14, 12 * 1024, 2 * SEGMENT, true, true, now);
        assert_eq!(cc.cwnd(), 3 * SEGMENT, "still the timeout's flight");
        let _ = cc.on_advance(14, 16 * 1024, 4 * SEGMENT, true, false, now);
        assert_eq!(cc.cwnd(), 7 * SEGMENT, "past it, four as before");
        let mut fresh = CongestionWindow::new();
        let _ = fresh.on_advance(14, 10 * 1024, 10 * SEGMENT, true, false, now);
        assert_eq!(
            fresh.cwnd(),
            14 * SEGMENT,
            "ordinary slow start: up to four"
        );
    }

    /// RFC 5681 (3): past the threshold, about one segment per window.
    #[test]
    fn congestion_avoidance_adds_about_one_segment_per_window() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), 20 * SEGMENT, &[]); // ssthresh 10 segments
        while cc.cwnd() < 10 * SEGMENT {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), 10 * SEGMENT);
        for _ in 0..9 {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(
            cc.cwnd(),
            10 * SEGMENT,
            "not yet a whole window acknowledged"
        );
        cc.on_acked(SEGMENT, true, false);
        assert_eq!(cc.cwnd(), 11 * SEGMENT);
    }

    /// A window nobody filled (keystrokes) does not grow: it would burst
    /// into room it never tried.
    #[test]
    fn a_window_that_was_not_the_limit_does_not_grow() {
        let mut cc = CongestionWindow::new();
        cc.on_acked(SEGMENT, false, false);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW);
    }

    /// RFC 5681 §3.1: `ssthresh = max(FlightSize / 2, 2 SMSS)`, one segment
    /// of window.
    #[test]
    fn a_retransmit_timeout_halves_the_threshold_and_leaves_one_segment() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), 40 * SEGMENT, &[]);
        assert_eq!(cc.ssthresh(), Some(20 * SEGMENT));
        assert_eq!(cc.cwnd(), SEGMENT);
    }

    /// One lost keystroke on a quiet terminal session must not pin the
    /// threshold at two segments for the rest of it: the flight counts as at
    /// least the initial window, so the threshold stays at half of that.
    #[test]
    fn a_loss_on_a_quiet_link_keeps_the_threshold_at_half_the_initial_window() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), SEGMENT, &[]);
        assert_eq!(cc.ssthresh(), Some(INITIAL_WINDOW / 2));
        cc.on_retransmit_timeout(Instant::now(), 0, &[]);
        assert_eq!(cc.ssthresh(), Some(5 * SEGMENT));
    }

    /// RFC 3465 with delayed ACKs (spec §4.11, decision 1): an ACK counts
    /// for at most `ACK_EVERY` segments -- what an honest delayed ACK covers
    /// -- so an ACK of four segments grows the window as four ACKs of one
    /// did, and a cumulative ACK over several windows (a hole filled) still
    /// cannot grow it by several segments in a burst.
    #[test]
    fn congestion_avoidance_counts_at_most_ack_every_segments_per_ack() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), 20 * SEGMENT, &[]); // ssthresh 10 segments
        while cc.cwnd() < 10 * SEGMENT {
            cc.on_acked(SEGMENT, true, false);
        }
        cc.on_acked(50 * SEGMENT, true, false);
        assert_eq!(cc.cwnd(), 10 * SEGMENT, "four segments counted, not fifty");
        for _ in 0..5 {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), 10 * SEGMENT, "nine segments counted so far");
        cc.on_acked(SEGMENT, true, false);
        assert_eq!(cc.cwnd(), 11 * SEGMENT);
        for _ in 0..2 {
            cc.on_acked(50 * SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), 11 * SEGMENT, "no burst from big ACKs either");
    }

    #[test]
    fn a_restart_forgets_everything() {
        let mut cc = CongestionWindow::new();
        cc.on_retransmit_timeout(Instant::now(), 40 * SEGMENT, &[]);
        cc.restart();
        assert_eq!(cc, CongestionWindow::new());
    }

    #[test]
    fn the_window_stops_growing_at_its_ceiling() {
        let mut cc = CongestionWindow::new();
        for _ in 0..(2 * MAX_WINDOW / SEGMENT) {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), MAX_WINDOW);
    }

    const RTT: Duration = Duration::from_millis(100);

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    /// RFC 6582 §3.2 steps 1-2: the third duplicate enters recovery --
    /// `ssthresh` half the flight (counted as at least the initial window,
    /// as for a timeout), `cwnd = ssthresh + 3 SMSS` -- and the lost segment
    /// goes out again.
    #[test]
    fn the_third_duplicate_enters_recovery_and_resends() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        assert_eq!(
            cc.on_duplicate(14, 1, 10 * SEGMENT, 10_240, t0),
            AckVerdict::Nothing
        );
        assert_eq!(
            cc.on_duplicate(14, 2, 10 * SEGMENT, 10_240, t0),
            AckVerdict::Nothing
        );
        assert_eq!(
            cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.ssthresh(), Some(5 * SEGMENT));
        assert_eq!(cc.cwnd(), 8 * SEGMENT);
        assert_eq!(
            cc.recovery().map(|r| (r.stream_id, r.recover)),
            Some((14, 10_240))
        );
    }

    /// Step 3: every further duplicate inflates the window by a segment.
    #[test]
    fn a_further_duplicate_inflates_the_window() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        assert_eq!(
            cc.on_duplicate(14, 4, 10 * SEGMENT, 10_240, t0),
            AckVerdict::Nothing
        );
        assert_eq!(cc.cwnd(), 9 * SEGMENT);
    }

    /// Step 4: a partial ACK resends the next hole and deflates the window by
    /// what it acknowledged, adding one segment back.
    #[test]
    fn a_partial_ack_resends_the_next_hole() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let _ = cc.on_duplicate(14, 4, 10 * SEGMENT, 10_240, t0); // cwnd 9 segments
        assert_eq!(
            cc.on_advance(14, 5 * 1024, 5 * SEGMENT, true, false, at(t0, 100)),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.cwnd(), 5 * SEGMENT);
        assert!(cc.recovery().is_some());
    }

    /// RFC 6582 step 4 adds a segment back only for a partial ACK of at least
    /// one.
    #[test]
    fn a_partial_ack_of_less_than_a_segment_adds_nothing_back() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0); // cwnd 8 segments
        let _ = cc.on_advance(14, 100, 100, true, false, t0);
        assert_eq!(cc.cwnd(), 8 * SEGMENT - 100);
    }

    /// Step 5 (spec §4.15: `cwnd = ssthresh`): the full ACK ends recovery.
    #[test]
    fn the_full_ack_ends_recovery_at_the_threshold() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        assert_eq!(
            cc.on_advance(14, 10_240, 10 * SEGMENT, true, false, t0),
            AckVerdict::Recovered { recover: 10_240 },
            "and says where the recovery began: the hold runs to there"
        );
        assert_eq!(cc.recovery(), None);
        assert_eq!(cc.cwnd(), 5 * SEGMENT);
    }

    /// Another stream's loss during recovery is repaired without a second cut.
    #[test]
    fn another_streams_loss_during_recovery_is_resent_without_a_second_cut() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let cwnd = cc.cwnd();
        assert_eq!(
            cc.on_duplicate(16, 3, 10 * SEGMENT, 4096, t0),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.cwnd(), cwnd);
        assert_eq!(cc.recovery().map(|r| r.stream_id), Some(14));
    }

    /// No growth for any stream while one is in recovery; a timeout ends it.
    #[test]
    fn recovery_freezes_growth_and_a_timeout_ends_it() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let cwnd = cc.cwnd();
        assert_eq!(
            cc.on_advance(16, 2048, 2 * SEGMENT, true, false, t0),
            AckVerdict::Nothing
        );
        assert_eq!(cc.cwnd(), cwnd);
        cc.on_retransmit_timeout(t0, 10 * SEGMENT, &[]);
        assert_eq!(cc.recovery(), None);
    }

    /// A desync ends the recovery as a full ACK would: at the threshold, not
    /// with the inflation of the duplicates.
    #[test]
    fn a_stream_that_drops_its_backlog_leaves_recovery_at_the_threshold() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let _ = cc.on_duplicate(14, 4, 10 * SEGMENT, 10_240, t0);
        cc.forget_stream(16);
        assert!(cc.recovery().is_some());
        cc.forget_stream(14);
        assert_eq!(cc.recovery(), None);
        assert_eq!(cc.cwnd(), 5 * SEGMENT);
    }

    /// The fast retransmit's threshold follows the same rule as a timeout's:
    /// half the flight, counted as at least the initial window.
    #[test]
    fn a_fast_retransmit_on_a_small_flight_keeps_half_the_initial_window() {
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 4 * SEGMENT, 4096, Instant::now());
        assert_eq!(cc.ssthresh(), Some(INITIAL_WINDOW / 2));
    }

    /// Outside a recovery an advance is plain RFC 5681 growth.
    #[test]
    fn an_advance_outside_recovery_grows_the_window() {
        let mut cc = CongestionWindow::new();
        assert_eq!(
            cc.on_advance(14, 1024, SEGMENT, true, false, Instant::now()),
            AckVerdict::Nothing
        );
        assert_eq!(cc.cwnd(), 11 * SEGMENT);
    }

    /// A restart (a move, a wake) ends a recovery, forgets the road's base
    /// delay and its reordering.
    #[test]
    fn a_restart_ends_a_recovery_and_forgets_the_roads_reordering() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let _ = cc.on_advance(14, 10_240, 10 * SEGMENT, false, false, at(t0, 5));
        assert!(cc.dup_threshold() > DUPLICATE_THRESHOLD);
        let _ = cc.on_duplicate(14, 4, 10 * SEGMENT, 20_480, t0);
        cc.restart();
        assert_eq!(cc, CongestionWindow::new());
    }

    /// RFC 4015's idea, timed without timestamps: the ACK over the segment
    /// resent came back sooner than a round trip after the resend, so it
    /// answers the first copy -- that one was only late. The window and
    /// the threshold go back to what they were, and the recovery is over.
    #[test]
    fn a_retransmit_answered_too_early_was_spurious_and_is_undone() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        for _ in 0..10 {
            cc.on_acked(SEGMENT, true, false);
        }
        let before = cc.clone();
        let _ = cc.on_duplicate(14, 3, 20 * SEGMENT, 20_480, t0);
        assert_eq!(cc.cwnd(), 13 * SEGMENT);
        assert_eq!(
            cc.on_advance(14, 4096, 4 * SEGMENT, false, false, at(t0, 10)),
            AckVerdict::Nothing,
            "nothing more to resend"
        );
        assert_eq!(cc.recovery(), None);
        assert_eq!(
            (cc.cwnd(), cc.ssthresh()),
            (before.cwnd(), before.ssthresh())
        );
    }

    /// A round trip after the resend, less the host's slack, or later, the
    /// ACK may answer the resend: a genuine loss, and the recovery goes on.
    /// Sooner than that, even by a little, it cannot.
    #[test]
    fn a_retransmit_answered_after_a_round_trip_stands() {
        let t0 = Instant::now();
        let boundary = t0 + RTT - HOST_SLACK;
        let mut early = CongestionWindow::new();
        early.on_round_trip(t0, RTT, 0);
        let _ = early.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        let _ = early.on_advance(
            14,
            5 * 1024,
            5 * SEGMENT,
            true,
            false,
            boundary - Duration::from_micros(1),
        );
        assert_eq!(early.recovery(), None, "undone");
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        assert_eq!(
            cc.on_advance(14, 5 * 1024, 5 * SEGMENT, true, false, boundary),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.ssthresh(), Some(5 * SEGMENT));
        assert_eq!(cc.dup_threshold(), DUPLICATE_THRESHOLD);
    }

    /// Final review of slice 2, Important 1: on loopback every sample the
    /// base was taken from carried the hosts' batching (0.97 ms), and the
    /// answer to a lone resend came sooner (0.49 ms) -- a real loss read as
    /// spurious, three rules at once: a timeout undone, a fast retransmit
    /// undone, a partial ACK that resent nothing. Within `HOST_SLACK` of the
    /// base an ACK answers the repair: on a road that fast none of them fires.
    #[test]
    fn an_answer_within_the_hosts_slack_of_the_base_answers_the_repair() {
        let t0 = Instant::now();
        let base = Duration::from_micros(966);
        let answer = Duration::from_micros(492);

        let mut cc = grown_to(40);
        cc.on_round_trip(t0, base, 0);
        cc.on_retransmit_timeout(at(t0, 1_000), 40 * SEGMENT, &[14]);
        assert!(
            !cc.undo_timeout_if_spurious(14, at(t0, 1_000) + answer),
            "the timeout stands"
        );
        assert_eq!(cc.cwnd(), LOSS_WINDOW);

        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, base, 0);
        let _ = cc.on_duplicate(14, 3, 20 * SEGMENT, 20_480, t0);
        assert_eq!(
            cc.on_advance(14, 5 * 1024, 5 * SEGMENT, true, false, t0 + answer),
            AckVerdict::RetransmitOldest,
            "the fast retransmit stands, and the partial ACK resends the next hole"
        );
        assert_eq!(cc.ssthresh(), Some(10 * SEGMENT));
        assert_eq!(
            cc.on_advance(14, 6 * 1024, SEGMENT, true, false, t0 + 2 * answer),
            AckVerdict::RetransmitOldest,
            "the answer to that repair: the next hole is lost too"
        );
    }

    /// With no round trip measured, nothing is taken for spurious.
    #[test]
    fn with_no_round_trip_measured_nothing_is_undone() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, t0);
        assert_eq!(
            cc.on_advance(14, 5 * 1024, 5 * SEGMENT, true, false, t0),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.ssthresh(), Some(5 * SEGMENT));
    }

    /// After the first repair stood, an ACK too early to answer the next
    /// repair is an in-flight segment arriving late, not the next hole:
    /// nothing is resent, the recovery goes on.
    #[test]
    fn an_advance_too_early_for_a_later_repair_resends_nothing() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        let _ = cc.on_duplicate(14, 3, 20 * SEGMENT, 20_480, t0);
        assert_eq!(
            cc.on_advance(14, 5 * 1024, 5 * SEGMENT, true, false, at(t0, 100)),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(
            cc.on_advance(14, 6 * 1024, SEGMENT, true, false, at(t0, 110)),
            AckVerdict::Nothing
        );
        assert!(cc.recovery().is_some());
        assert_eq!(cc.ssthresh(), Some(10 * SEGMENT), "not undone");
        assert_eq!(
            cc.on_advance(14, 7 * 1024, SEGMENT, true, false, at(t0, 200)),
            AckVerdict::RetransmitOldest,
            "the answer to the second repair"
        );
    }

    /// Like Linux's `tcp_reordering`: after a spurious fast retransmit the
    /// threshold is one past the reordering the road showed -- the
    /// duplicates that came before the late segment -- so the same
    /// reordering does not set it off again.
    #[test]
    fn a_spurious_fast_retransmit_raises_the_threshold_past_the_reordering() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        for n in 3..=10 {
            let _ = cc.on_duplicate(14, n, 20 * SEGMENT, 20_480, t0);
        }
        let _ = cc.on_advance(14, 11 * 1024, 11 * SEGMENT, false, false, at(t0, 10));
        assert_eq!(cc.dup_threshold(), 11);
        for n in 1..=10 {
            assert_eq!(
                cc.on_duplicate(14, n, 20 * SEGMENT, 30_720, t0),
                AckVerdict::Nothing
            );
        }
        assert_eq!(
            cc.on_duplicate(14, 11, 20 * SEGMENT, 30_720, t0),
            AckVerdict::RetransmitOldest
        );
        assert_eq!(cc.cwnd(), 10 * SEGMENT + 11 * SEGMENT, "ssthresh + 11");
    }

    /// The threshold never goes past `MAX_DUPLICATE_THRESHOLD`, however deep
    /// the reordering an undo meets -- the first undo or a later one.
    #[test]
    fn the_duplicate_threshold_is_capped_however_deep_the_reordering() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        for n in 3..=200 {
            let _ = cc.on_duplicate(14, n, 256 * SEGMENT, 262_144, t0);
        }
        let _ = cc.on_advance(14, 200 * 1024, 200 * SEGMENT, false, false, at(t0, 10));
        assert_eq!(cc.dup_threshold(), MAX_DUPLICATE_THRESHOLD);
        for n in 1..=64 {
            let _ = cc.on_duplicate(14, n, 20 * SEGMENT, 300_000, t0);
        }
        let _ = cc.on_advance(14, 205 * 1024, 5 * SEGMENT, false, false, at(t0, 20));
        assert_eq!(cc.dup_threshold(), MAX_DUPLICATE_THRESHOLD);
    }

    /// Our rule (review round 2), not Linux's -- `tcp_enter_loss` lowers its
    /// `reordering` only in a narrower case: a retransmit timeout says the
    /// duplicates did not come, and puts the threshold back at
    /// `DUPLICATE_THRESHOLD` whatever it had learned.
    #[test]
    fn a_retransmit_timeout_puts_the_duplicate_threshold_back() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        for n in 3..=10 {
            let _ = cc.on_duplicate(14, n, 20 * SEGMENT, 20_480, t0);
        }
        let _ = cc.on_advance(14, 11 * 1024, 11 * SEGMENT, false, false, at(t0, 10));
        assert_eq!(cc.dup_threshold(), 11);
        cc.on_retransmit_timeout(t0, 20 * SEGMENT, &[]);
        assert_eq!(cc.dup_threshold(), DUPLICATE_THRESHOLD);
    }

    fn minutes(t0: Instant, m: u64, s: u64) -> Instant {
        t0 + Duration::from_secs(60 * m + s)
    }

    /// The base delay is the smallest round trip of the last ten minutes,
    /// kept as one minimum per minute (RFC 6817's `BASE_HISTORY`): a smaller
    /// sample takes over at once, and the minute that held it counts for ten
    /// minutes -- nine full ones after it, and the one going on.
    #[test]
    fn the_base_delay_is_the_smallest_round_trip_of_the_last_ten_minutes() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(100), 0);
        cc.on_round_trip(at(t0, 1_000), Duration::from_millis(300), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(100)));
        cc.on_round_trip(at(t0, 2_000), Duration::from_millis(80), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(80)));
        cc.on_round_trip(minutes(t0, 9, 59), Duration::from_millis(300), 0);
        assert_eq!(
            cc.base_delay(),
            Some(Duration::from_millis(80)),
            "the first minute is still one of the last ten"
        );
        cc.on_round_trip(minutes(t0, 10, 1), Duration::from_millis(300), 0);
        assert_eq!(
            cc.base_delay(),
            Some(Duration::from_millis(300)),
            "the first minute is out; nothing smaller came since"
        );
    }

    /// When the minute that held the base leaves the history, the best of the
    /// minutes since stands -- not only the newest sample.
    #[test]
    fn the_base_delay_falls_back_to_the_best_minute_since() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(50), 0);
        cc.on_round_trip(minutes(t0, 3, 0), Duration::from_millis(120), 0);
        cc.on_round_trip(minutes(t0, 6, 0), Duration::from_millis(200), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(50)));
        cc.on_round_trip(minutes(t0, 10, 30), Duration::from_millis(250), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(120)));
        cc.on_round_trip(minutes(t0, 13, 30), Duration::from_millis(250), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(200)));
    }

    /// Minutes with no sample at all -- a quiet gap -- still pass: after
    /// twenty of them nothing from before counts.
    #[test]
    fn minutes_without_samples_still_age_the_base_delay() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(50), 0);
        cc.on_round_trip(minutes(t0, 20, 0), Duration::from_millis(400), 0);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(400)));
    }

    /// Task 4 re-review (New 1): behind a bulk transfer's standing queue
    /// every sample for minutes is the full-queue round trip. It must not
    /// become the road's delay -- the repair of a genuine loss, answered a
    /// little sooner as the queue drains behind the hole, would be taken for
    /// spurious and its halving skipped. The ten-minute history keeps the
    /// road's own round trip from before the queue.
    #[test]
    fn a_standing_queue_does_not_become_the_road() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(100), 0);
        let queued = Duration::from_millis(2_176);
        for s in 1..=(9 * 60) {
            cc.on_round_trip(at(t0, s * 1_000), queued, 0);
        }
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(100)));
        let now = minutes(t0, 9, 1);
        let _ = cc.on_duplicate(14, 3, 256 * SEGMENT, 262_144, now);
        assert_eq!(
            cc.on_advance(
                14,
                1024,
                SEGMENT,
                false,
                false,
                now + Duration::from_millis(2_159)
            ),
            AckVerdict::RetransmitOldest,
            "a genuine loss: its repair answered, the next hole resent"
        );
        assert_eq!(cc.ssthresh(), Some(128 * SEGMENT), "the halving stands");
        assert_eq!(cc.dup_threshold(), DUPLICATE_THRESHOLD);
    }

    /// A road whose round trip grew since its fastest sample gets its undo
    /// back against the new round trip once that sample leaves the history:
    /// kept forever, it would leave reordering deeper than the old round
    /// trip undetected.
    #[test]
    fn a_road_that_got_slower_is_undone_against_its_new_round_trip() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(100), 0);
        let now = minutes(t0, 10, 5);
        for i in 0..10 {
            cc.on_round_trip(now + Duration::from_secs(i), Duration::from_millis(300), 0);
        }
        let now = now + Duration::from_secs(10);
        let _ = cc.on_duplicate(14, 3, 10 * SEGMENT, 10_240, now);
        let _ = cc.on_advance(
            14,
            5 * 1024,
            5 * SEGMENT,
            false,
            false,
            now + Duration::from_millis(150),
        );
        assert_eq!(cc.recovery(), None, "150 ms is too early on a 300 ms road");
    }

    fn grown_to(segments: usize) -> CongestionWindow {
        let mut cc = CongestionWindow::new();
        while cc.cwnd() < segments * SEGMENT {
            cc.on_acked(SEGMENT, true, false);
        }
        cc
    }

    /// The queue-delay signal (spec §4.15): a round trip more than
    /// `QUEUE_DELAY_CAP` above the road's base delay is a congestion event --
    /// the window halves as for a fast retransmit, nothing is resent -- at
    /// most once per round trip.
    #[test]
    fn a_round_trip_far_above_the_base_delay_halves_the_window_once_per_round_trip() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        backlogged(&mut cc, t0, Duration::from_millis(550), 40 * SEGMENT);
        assert_eq!(cc.cwnd(), 40 * SEGMENT, "450 ms of queue is under the cap");
        let t1 = t0 + Duration::from_secs(1);
        backlogged(&mut cc, t1, Duration::from_millis(700), 40 * SEGMENT);
        assert_eq!(
            (cc.cwnd(), cc.ssthresh()),
            (20 * SEGMENT, Some(20 * SEGMENT))
        );
        backlogged(
            &mut cc,
            t1 + Duration::from_millis(300),
            Duration::from_millis(800),
            20 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), 20 * SEGMENT, "not again within the round trip");
        backlogged(
            &mut cc,
            t1 + Duration::from_millis(900),
            Duration::from_millis(800),
            20 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), 10 * SEGMENT, "a round trip later, again");
    }

    /// A loss the window already answered is not answered twice for the same
    /// queue; and a recovery in progress is left alone.
    #[test]
    fn a_recent_loss_or_a_recovery_holds_the_delay_signal_back() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        cc.note_reduction(t0);
        backlogged(
            &mut cc,
            at(t0, 200),
            Duration::from_millis(900),
            40 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), 40 * SEGMENT);
        let _ = cc.on_duplicate(14, 3, 40 * SEGMENT, 40_960, at(t0, 2_000));
        let cwnd = cc.cwnd();
        backlogged(
            &mut cc,
            at(t0, 5_000),
            Duration::from_millis(900),
            40 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), cwnd);
    }

    /// The fast retransmit and the retransmit timeout are cuts too: the
    /// delay signal waits a round trip after either.
    #[test]
    fn a_fast_retransmit_or_a_timeout_holds_the_delay_signal_back_a_round_trip() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        let _ = cc.on_duplicate(14, 3, 40 * SEGMENT, 40_960, t0);
        let _ = cc.on_advance(14, 40_960, 40 * SEGMENT, true, false, at(t0, 200));
        assert_eq!(cc.recovery(), None);
        let after_recovery = cc.cwnd();
        backlogged(
            &mut cc,
            at(t0, 300),
            Duration::from_millis(900),
            20 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), after_recovery, "within a round trip of the cut");
        let t1 = at(t0, 5_000);
        cc.on_retransmit_timeout(t1, 20 * SEGMENT, &[]);
        let threshold = cc.ssthresh();
        backlogged(
            &mut cc,
            t1 + Duration::from_millis(300),
            Duration::from_millis(900),
            0,
        );
        assert_eq!(
            cc.ssthresh(),
            threshold,
            "within a round trip of the timeout"
        );
    }

    /// The delay signal lowers the window, never raises it: after a timeout
    /// the window is one segment, below any threshold the flight gives.
    #[test]
    fn the_delay_signal_never_raises_the_window() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        cc.on_retransmit_timeout(t0, 40 * SEGMENT, &[]);
        assert_eq!(cc.cwnd(), LOSS_WINDOW);
        backlogged(
            &mut cc,
            at(t0, 2_000),
            Duration::from_millis(900),
            30 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), LOSS_WINDOW);
        assert_eq!(cc.ssthresh(), Some(15 * SEGMENT));
    }

    /// An undone fast retransmit was no cut: the delay signal is not held
    /// back by it.
    #[test]
    fn an_undone_fast_retransmit_does_not_hold_the_delay_signal_back() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        let _ = cc.on_duplicate(14, 3, 40 * SEGMENT, 40_960, t0);
        let _ = cc.on_advance(14, 4096, 4 * SEGMENT, false, false, at(t0, 10));
        assert_eq!((cc.recovery(), cc.cwnd()), (None, 40 * SEGMENT), "undone");
        backlogged(
            &mut cc,
            at(t0, 20),
            Duration::from_millis(700),
            40 * SEGMENT,
        );
        assert_eq!(cc.cwnd(), 20 * SEGMENT);
    }

    #[test]
    fn a_restart_forgets_the_roads_base_delay() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        cc.restart();
        backlogged(&mut cc, t0, Duration::from_millis(900), 10 * SEGMENT);
        assert_eq!(cc.cwnd(), INITIAL_WINDOW, "900 ms is the new road's base");
    }

    /// A sample a second from `from`, for `secs` seconds: a 100 ms road with
    /// `queue_ms` of queue standing on it, `flight` bytes outstanding.
    fn standing(cc: &mut CongestionWindow, from: Instant, secs: u64, queue_ms: u64, flight: usize) {
        for s in 0..secs {
            backlogged(
                cc,
                from + Duration::from_secs(s),
                Duration::from_millis(100 + queue_ms),
                flight,
            );
        }
    }

    /// A round trip taken while the sender has data waiting.
    fn backlogged(cc: &mut CongestionWindow, now: Instant, sample: Duration, flight: usize) {
        cc.note_backlog(now);
        cc.on_round_trip(now, sample, flight);
    }

    /// Forty segments on a 100 ms road, 200 ms of queue standing for nine
    /// minutes since the road was last seen, and the probe that starts then.
    fn probing() -> (CongestionWindow, Instant) {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        standing(&mut cc, t0 + Duration::from_secs(1), 540, 200, 40 * SEGMENT);
        assert!(cc.probe().is_some(), "the probe started");
        (cc, t0 + BASE_PROBE_AFTER)
    }

    /// Spec §4.15, the base probe: nine minutes without a round trip within
    /// `BASE_TOLERANCE` of the base, and the window drops to two segments to
    /// let the queue drain; the threshold keeps the window it left, for the
    /// slow start back.
    #[test]
    fn nine_minutes_without_the_base_start_a_probe() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        standing(&mut cc, t0 + Duration::from_secs(1), 539, 200, 40 * SEGMENT);
        assert!(cc.probe().is_none());
        assert_eq!(cc.cwnd(), 40 * SEGMENT, "200 ms of queue is under the cap");
        backlogged(
            &mut cc,
            t0 + BASE_PROBE_AFTER,
            Duration::from_millis(300),
            40 * SEGMENT,
        );
        assert!(cc.probe().is_some());
        assert_eq!(
            (cc.cwnd(), cc.ssthresh()),
            (PROBE_WINDOW, Some(40 * SEGMENT))
        );
    }

    /// A round trip near the base puts the probe off: only a queue that never
    /// drains needs one.
    #[test]
    fn a_round_trip_near_the_base_puts_the_probe_off() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        standing(&mut cc, t0 + Duration::from_secs(1), 299, 200, 40 * SEGMENT);
        let near = t0 + Duration::from_secs(300);
        backlogged(&mut cc, near, Duration::from_millis(140), 40 * SEGMENT);
        standing(
            &mut cc,
            near + Duration::from_secs(1),
            538,
            200,
            40 * SEGMENT,
        );
        assert!(cc.probe().is_none(), "nine minutes from the near sample");
        backlogged(
            &mut cc,
            near + BASE_PROBE_AFTER,
            Duration::from_millis(300),
            40 * SEGMENT,
        );
        assert!(cc.probe().is_some());
    }

    /// The probe holds the window at two segments -- the ACKs of what drains
    /// grow nothing -- until a round trip is measured of something sent once
    /// the flight had fallen to what the probe lets out (the window and the
    /// interactive allowance); then it slow-starts back to what the road
    /// carries without the queue: the rate when it began (forty segments in
    /// 300 ms) times the round trip it measured (105 ms), fourteen segments.
    #[test]
    fn a_probe_holds_the_window_until_the_emptied_road_is_measured() {
        let (mut cc, t) = probing();
        cc.on_acked(SEGMENT, true, false);
        assert_eq!(cc.cwnd(), PROBE_WINDOW, "no growth while it drains");
        backlogged(
            &mut cc,
            t + Duration::from_millis(200),
            Duration::from_millis(300),
            20 * SEGMENT,
        );
        assert_eq!(cc.probe().map(|p| p.emptied_at), Some(None));
        let emptied = t + Duration::from_millis(400);
        backlogged(&mut cc, emptied, Duration::from_millis(300), 4 * SEGMENT);
        assert_eq!(cc.probe().map(|p| p.emptied_at), Some(Some(emptied)));
        backlogged(
            &mut cc,
            emptied + Duration::from_millis(150),
            Duration::from_millis(200),
            2 * SEGMENT,
        );
        assert!(cc.probe().is_some(), "sent before the queue was gone");
        backlogged(
            &mut cc,
            emptied + Duration::from_millis(210),
            Duration::from_millis(105),
            2 * SEGMENT,
        );
        assert!(cc.probe().is_none(), "the road measured");
        assert_eq!(cc.ssthresh(), Some(14 * SEGMENT));
        for _ in 0..12 {
            cc.on_acked(SEGMENT, true, false);
        }
        assert_eq!(cc.cwnd(), 14 * SEGMENT, "slow start back to the road's own");
        cc.on_acked(SEGMENT, true, false);
        assert_eq!(
            cc.cwnd(),
            14 * SEGMENT,
            "and congestion avoidance from there"
        );
    }

    /// Spec §4.15 with §4.11: a round trip says so -- once -- when a probe's
    /// queue has emptied, for the connection to have the road measured by a
    /// PING, which no receiver holds: an ACK of two segments may wait
    /// `ACK_DELAY`, and the next round trip becomes the base.
    #[test]
    fn a_round_trip_says_once_when_a_probes_queue_emptied() {
        let (mut cc, t) = probing();
        cc.note_backlog(t + Duration::from_millis(200));
        assert!(!cc.on_round_trip(
            t + Duration::from_millis(200),
            Duration::from_millis(300),
            20 * SEGMENT
        ));
        let emptied = t + Duration::from_millis(400);
        cc.note_backlog(emptied);
        assert!(
            cc.on_round_trip(emptied, Duration::from_millis(300), 4 * SEGMENT),
            "emptied now"
        );
        let later = emptied + Duration::from_millis(150);
        cc.note_backlog(later);
        assert!(
            !cc.on_round_trip(later, Duration::from_millis(200), 2 * SEGMENT),
            "once"
        );
        assert!(cc.probe().is_some());
    }

    /// The slow start after a probe climbs no higher than the window it left
    /// and no lower than half the initial window, whatever the estimate.
    #[test]
    fn the_slow_start_after_a_probe_is_bounded_by_the_window_it_left() {
        let (mut cc, t) = probing();
        let emptied = t + Duration::from_millis(400);
        backlogged(&mut cc, emptied, Duration::from_millis(300), 4 * SEGMENT);
        backlogged(
            &mut cc,
            emptied + Duration::from_secs(1),
            Duration::from_millis(900),
            2 * SEGMENT,
        );
        assert_eq!(
            cc.ssthresh(),
            Some(40 * SEGMENT),
            "a road slower than the queue it had"
        );
        let (mut cc, t) = probing();
        let emptied = t + Duration::from_millis(400);
        backlogged(&mut cc, emptied, Duration::from_millis(300), 4 * SEGMENT);
        backlogged(
            &mut cc,
            emptied + Duration::from_millis(20),
            Duration::from_millis(10),
            2 * SEGMENT,
        );
        assert_eq!(cc.ssthresh(), Some(INITIAL_WINDOW / 2));
    }

    /// While a probe drains, the delay signal is silent: the queue it would
    /// answer is the one the probe is emptying.
    #[test]
    fn the_delay_signal_is_silent_during_a_probe() {
        let (mut cc, t) = probing();
        let threshold = cc.ssthresh();
        backlogged(
            &mut cc,
            t + Duration::from_secs(1),
            Duration::from_millis(900),
            40 * SEGMENT,
        );
        assert_eq!((cc.cwnd(), cc.ssthresh()), (PROBE_WINDOW, threshold));
    }

    /// No probe during a recovery, nor within a round trip of a cut: a cut
    /// drains the queue already, and its round trip still carries the queue
    /// it drains -- a probe on top would answer one queue twice. The probe
    /// comes with the first round trip after that.
    #[test]
    fn no_probe_during_a_recovery_or_within_a_round_trip_of_a_cut() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(100), 40 * SEGMENT);
        standing(&mut cc, t0 + Duration::from_secs(1), 538, 200, 40 * SEGMENT);
        let t = t0 + BASE_PROBE_AFTER;
        let _ = cc.on_duplicate(14, 3, 40 * SEGMENT, 40_960, t);
        backlogged(
            &mut cc,
            t + Duration::from_millis(100),
            Duration::from_millis(300),
            40 * SEGMENT,
        );
        assert!(cc.probe().is_none(), "not during the recovery");
        let _ = cc.on_advance(
            14,
            40_960,
            40 * SEGMENT,
            true,
            false,
            t + Duration::from_millis(200),
        );
        assert_eq!(cc.recovery(), None);
        backlogged(
            &mut cc,
            t + Duration::from_millis(250),
            Duration::from_millis(300),
            20 * SEGMENT,
        );
        assert!(cc.probe().is_none(), "not within a round trip of the cut");
        backlogged(
            &mut cc,
            t + Duration::from_millis(400),
            Duration::from_millis(300),
            20 * SEGMENT,
        );
        assert!(cc.probe().is_some(), "a round trip later");
    }

    /// A loss during a probe ends it -- the loss's response takes over -- and
    /// so does a timeout; the road was not measured, so the probe comes again
    /// once it may.
    #[test]
    fn a_loss_or_a_timeout_ends_a_probe_and_it_comes_again() {
        let (mut cc, t) = probing();
        let _ = cc.on_duplicate(14, 3, 20 * SEGMENT, 20_480, t + Duration::from_millis(200));
        assert!(cc.probe().is_none());
        let _ = cc.on_advance(
            14,
            20_480,
            20 * SEGMENT,
            true,
            false,
            t + Duration::from_millis(500),
        );
        backlogged(
            &mut cc,
            t + Duration::from_secs(1),
            Duration::from_millis(300),
            10 * SEGMENT,
        );
        assert!(cc.probe().is_some(), "the road is still unseen");
        cc.on_retransmit_timeout(t + Duration::from_secs(2), 10 * SEGMENT, &[]);
        assert!(cc.probe().is_none());
        assert_eq!(cc.cwnd(), LOSS_WINDOW);
        // What the timeout resends as its window opens: enough in flight to
        // be holding a queue again.
        backlogged(
            &mut cc,
            t + Duration::from_secs(3),
            Duration::from_millis(300),
            10 * SEGMENT,
        );
        assert!(cc.probe().is_some());
    }

    /// A finished probe counts as having seen the base, whatever it measured:
    /// on a road that got slower the old base is never come near again, and
    /// the next probe is nine minutes later, not at once.
    #[test]
    fn a_finished_probe_counts_as_seeing_the_base() {
        let (mut cc, t) = probing();
        let emptied = t + Duration::from_millis(500);
        backlogged(&mut cc, emptied, Duration::from_millis(400), 2 * SEGMENT);
        let done = emptied + Duration::from_millis(500);
        backlogged(&mut cc, done, Duration::from_millis(400), 2 * SEGMENT);
        assert!(cc.probe().is_none());
        standing(
            &mut cc,
            done + Duration::from_secs(1),
            538,
            300,
            40 * SEGMENT,
        );
        assert!(cc.probe().is_none());
        backlogged(
            &mut cc,
            done + BASE_PROBE_AFTER,
            Duration::from_millis(400),
            40 * SEGMENT,
        );
        assert!(cc.probe().is_some());
    }

    /// A window the stream holds below the cap: 446 ms of queue standing on
    /// a 100 ms road, and the delay signal never cuts. Nothing drains that
    /// queue but the probe: it comes at nine minutes all the same, and what it
    /// measures keeps the base when the minute from before the transfer
    /// leaves the history -- not the 546 ms every other sample says.
    #[test]
    fn a_window_the_stream_holds_below_the_cap_is_probed_too() {
        let t0 = Instant::now();
        let full = 256 * SEGMENT;
        let mut cc = grown_to(256);
        backlogged(&mut cc, t0, Duration::from_millis(100), SEGMENT);
        standing(&mut cc, t0 + Duration::from_secs(1), 539, 446, full);
        assert_eq!((cc.ssthresh(), cc.probe()), (None, None), "never cut");
        let t = t0 + BASE_PROBE_AFTER;
        backlogged(&mut cc, t, Duration::from_millis(546), full);
        assert!(cc.probe().is_some());
        let emptied = t + Duration::from_millis(600);
        backlogged(&mut cc, emptied, Duration::from_millis(546), 4 * SEGMENT);
        backlogged(
            &mut cc,
            emptied + Duration::from_millis(101),
            Duration::from_millis(101),
            2 * SEGMENT,
        );
        assert!(cc.probe().is_none());
        standing(&mut cc, t + Duration::from_secs(2), 50, 446, full);
        assert_eq!(cc.base_delay(), Some(Duration::from_millis(100)));
        standing(&mut cc, t + Duration::from_secs(52), 60, 446, full);
        assert_eq!(
            cc.base_delay(),
            Some(Duration::from_millis(101)),
            "the minute from before the transfer is out; the probe's stands"
        );
    }

    /// Task 5 review (Important 1): an application-limited connection --
    /// a terminal session -- whose road got 100 ms slower without a move goes
    /// nine minutes without seeing its base. Nothing of ours stands in that
    /// queue: the due probe counts as the measurement itself, and neither the
    /// window nor the threshold moves. Nor does a round trip far above the
    /// base cut it: an application-limited sender is not the cause.
    #[test]
    fn an_application_limited_connection_is_neither_probed_nor_cut() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(100), 0);
        let mut t = t0;
        while t < t0 + Duration::from_secs(20 * 60) {
            t += Duration::from_millis(1500);
            cc.on_round_trip(t, Duration::from_millis(200), SEGMENT);
            assert_eq!(cc.probe(), None);
        }
        cc.on_round_trip(
            t + Duration::from_secs(1),
            Duration::from_millis(900),
            SEGMENT,
        );
        assert_eq!((cc.cwnd(), cc.ssthresh()), (INITIAL_WINDOW, None));
    }

    /// Data waiting counts only within the round trip it could have queued
    /// in: a backlog older than the sample's own round trip is not the queue
    /// that sample saw.
    #[test]
    fn the_delay_signal_cuts_only_a_sender_with_data_waiting() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, Duration::from_millis(100), 40 * SEGMENT);
        let t1 = t0 + Duration::from_secs(5);
        cc.note_backlog(t1 - Duration::from_secs(1));
        cc.on_round_trip(t1, Duration::from_millis(900), 40 * SEGMENT);
        assert_eq!(cc.cwnd(), 40 * SEGMENT, "the backlog was a second ago");
        cc.note_backlog(t1 - Duration::from_millis(800));
        cc.on_round_trip(t1, Duration::from_millis(900), 40 * SEGMENT);
        assert_eq!(cc.cwnd(), 20 * SEGMENT, "within the round trip");
    }

    /// A sender with data waiting but no more in flight than a probe would
    /// leave -- a window at its floor, a few keystrokes -- holds no queue
    /// of its own either: the due probe counts as done, nothing is cut, and
    /// the next is nine minutes on (the road then 500 ms, so the 300 ms the
    /// history keeps is not come near).
    #[test]
    fn a_flight_no_larger_than_a_probe_counts_as_the_probe() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, Duration::from_millis(100), 0);
        let small = PROBE_WINDOW + INTERACTIVE_HEADROOM;
        standing(&mut cc, t0 + Duration::from_secs(1), 540, 200, small);
        assert_eq!(cc.probe(), None);
        assert_eq!((cc.cwnd(), cc.ssthresh()), (INITIAL_WINDOW, None));
        standing(
            &mut cc,
            t0 + Duration::from_secs(541),
            480,
            400,
            40 * SEGMENT,
        );
        assert_eq!(cc.probe(), None, "nine minutes from the probe it counted");
        standing(
            &mut cc,
            t0 + Duration::from_secs(1021),
            60,
            400,
            40 * SEGMENT,
        );
        assert!(cc.probe().is_some());
    }

    /// Task 5 review (Minor 1): the base's minute leaves the history ten
    /// minutes after that minute began, not after the sample. Seen at the
    /// end of its minute and timed from the sample, the base went into the
    /// last seconds of its tenth minute with no probe, rotated out at the
    /// next sample, and the standing queue's minimum became "the base":
    /// 100 to 300 ms and not one probe in forty minutes. Timed from the start
    /// of its minute, the probe comes a minute before the base could leave.
    #[test]
    fn the_base_is_seen_from_the_start_of_its_minute() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        backlogged(&mut cc, t0, Duration::from_millis(300), 20 * SEGMENT);
        backlogged(
            &mut cc,
            at(t0, 59_995),
            Duration::from_millis(100),
            20 * SEGMENT,
        );
        let mut probes = 0;
        let mut worst = Duration::ZERO;
        for k in 0..(40 * 60u64) {
            let t = t0 + Duration::from_secs(60 + k);
            match cc.probe() {
                // The flight falls to the probe's window, then a segment sent
                // after that is measured.
                Some(Probe {
                    emptied_at: None, ..
                }) => {
                    cc.on_round_trip(t, Duration::from_millis(300), 2 * SEGMENT);
                }
                Some(_) => {
                    cc.on_round_trip(t, Duration::from_millis(101), 2 * SEGMENT);
                }
                None => {
                    let s = if k % 2 == 0 { 300 } else { 550 };
                    backlogged(&mut cc, t, Duration::from_millis(s), 20 * SEGMENT);
                    probes += u32::from(cc.probe().is_some());
                }
            }
            worst = worst.max(cc.base_delay().expect("measured"));
        }
        assert!(probes >= 4, "{probes} probes in forty minutes");
        assert!(
            worst <= Duration::from_millis(101),
            "the base rose to {worst:?}"
        );
    }

    /// Task 5 round 3 (after RFC 5682's F-RTO and the Eifel idea, timed as
    /// the fast retransmit's undo is): the ACK over a timed-out segment
    /// came back sooner than a round trip after the resend, so it answers
    /// the original -- that was only late, and the timeout spurious. The
    /// window, the threshold and the learned duplicate threshold go back to
    /// what the timeout found. Decided once, by the first advance of a
    /// stream the timeout named; another stream's says nothing.
    #[test]
    fn a_timeout_answered_too_soon_after_the_resend_is_undone() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, RTT, 0);
        for n in 3..=10 {
            let _ = cc.on_duplicate(14, n, 40 * SEGMENT, 40_960, t0);
        }
        let _ = cc.on_advance(14, 11 * 1024, 11 * SEGMENT, false, false, at(t0, 10));
        assert_eq!(
            (cc.dup_threshold(), cc.cwnd()),
            (11, 40 * SEGMENT),
            "a learned reordering"
        );
        let t = at(t0, 1_000);
        cc.on_retransmit_timeout(t, 40 * SEGMENT, &[14]);
        assert_eq!(
            (cc.cwnd(), cc.dup_threshold()),
            (LOSS_WINDOW, DUPLICATE_THRESHOLD)
        );
        assert!(
            !cc.undo_timeout_if_spurious(16, at(t0, 1_010)),
            "not the stream it named"
        );
        assert!(cc.undo_timeout_if_spurious(14, at(t0, 1_050)));
        assert_eq!(
            (cc.cwnd(), cc.ssthresh(), cc.dup_threshold()),
            (40 * SEGMENT, None, 11)
        );
        assert_eq!(cc.cuts().timeouts_undone, 1);
        assert!(
            !cc.undo_timeout_if_spurious(14, at(t0, 1_060)),
            "decided once"
        );
    }

    /// A round trip after the resend, less the host's slack, or later, the
    /// ACK may answer it: the timeout stands, and a later advance does not
    /// bring the undo back. A microsecond sooner it cannot.
    #[test]
    fn a_timeout_answered_a_round_trip_after_the_resend_stands() {
        let t0 = Instant::now();
        let t = at(t0, 1_000);
        let mut early = grown_to(40);
        early.on_round_trip(t0, RTT, 0);
        early.on_retransmit_timeout(t, 40 * SEGMENT, &[14]);
        let too_soon = t + RTT - HOST_SLACK - Duration::from_micros(1);
        assert!(early.undo_timeout_if_spurious(14, too_soon));
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, RTT, 0);
        cc.on_retransmit_timeout(t, 40 * SEGMENT, &[14]);
        assert!(!cc.undo_timeout_if_spurious(14, t + RTT - HOST_SLACK));
        assert!(!cc.undo_timeout_if_spurious(14, t + RTT + Duration::from_millis(1)));
        assert_eq!(
            (cc.cwnd(), cc.ssthresh()),
            (LOSS_WINDOW, Some(20 * SEGMENT))
        );
        assert_eq!(cc.cuts().timeouts_undone, 0);
    }

    /// Nothing to time an answer by: with no round trip measured, and for a
    /// timeout that ended a recovery -- its repair went unanswered, a loss
    /// more likely than not -- the timeout stands.
    #[test]
    fn without_a_base_or_during_a_recovery_a_timeout_stands() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        cc.on_retransmit_timeout(t0, 40 * SEGMENT, &[14]);
        assert!(!cc.undo_timeout_if_spurious(14, at(t0, 1)));
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, RTT, 0);
        let _ = cc.on_duplicate(14, 3, 40 * SEGMENT, 40_960, t0);
        let t = at(t0, 1_000);
        cc.on_retransmit_timeout(t, 40 * SEGMENT, &[14]);
        assert!(!cc.undo_timeout_if_spurious(14, at(t0, 1_010)));
        assert_eq!(cc.cwnd(), LOSS_WINDOW);
    }

    /// Each timeout records what it found: undone, a second timeout gives
    /// back the window the first had left, not the one before both -- the
    /// first stood.
    #[test]
    fn only_the_latest_timeout_is_undone() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, RTT, 0);
        cc.on_retransmit_timeout(at(t0, 1_000), 40 * SEGMENT, &[14]);
        assert!(
            !cc.undo_timeout_if_spurious(14, at(t0, 1_200)),
            "the first stands"
        );
        cc.on_retransmit_timeout(at(t0, 3_000), 2 * SEGMENT, &[14]);
        assert!(cc.undo_timeout_if_spurious(14, at(t0, 3_010)));
        assert_eq!(
            (cc.cwnd(), cc.ssthresh()),
            (LOSS_WINDOW, Some(20 * SEGMENT))
        );
    }

    /// Task 5 round 4 (re-review New-3): a recovery that begins after a
    /// timeout -- a loss the duplicates found -- is a newer cut, and ends the
    /// timeout's chance of an undo: giving back the window from before the
    /// timeout would undo the recovery's too. Before, the undo restored a
    /// threshold never set (`usize::MAX`), the recovery ended at it, and the
    /// window overflowed.
    #[test]
    fn a_recovery_after_a_timeout_ends_its_chance_of_an_undo() {
        let t0 = Instant::now();
        let mut cc = CongestionWindow::new();
        cc.on_round_trip(t0, RTT, 0);
        cc.on_retransmit_timeout(at(t0, 1_000), 10 * SEGMENT, &[14]);
        let _ = cc.on_duplicate(16, 3, 10 * SEGMENT, 10_240, at(t0, 1_010));
        assert!(cc.recovery().is_some());
        assert!(!cc.undo_timeout_if_spurious(14, at(t0, 1_020)));
        let _ = cc.on_advance(16, 10_240, 10 * SEGMENT, true, false, at(t0, 1_200));
        assert_eq!((cc.cwnd(), cc.ssthresh()), (5 * SEGMENT, Some(5 * SEGMENT)));
        let _ = cc.limit(StreamClass::Interactive);
    }

    /// Task 5 round 4 (re-review New-4): a spurious timeout during a probe's
    /// drain gives the probe back with the window -- two segments, the queue
    /// still draining -- rather than leaving a window that small to be taken
    /// for a flight that holds no queue and the probe counted as done.
    #[test]
    fn an_undone_timeout_gives_back_the_probe_it_ended() {
        let (mut cc, t) = probing();
        let probe = cc.probe();
        let threshold = cc.ssthresh();
        cc.on_retransmit_timeout(t + Duration::from_millis(100), 40 * SEGMENT, &[14]);
        assert_eq!(cc.probe(), None);
        assert!(cc.undo_timeout_if_spurious(14, t + Duration::from_millis(110)));
        assert_eq!(cc.probe(), probe);
        assert_eq!((cc.cwnd(), cc.ssthresh()), (PROBE_WINDOW, threshold));
    }

    /// A restart forgets a timeout that could still be undone.
    #[test]
    fn a_restart_forgets_a_timeout_it_could_undo() {
        let t0 = Instant::now();
        let mut cc = grown_to(40);
        cc.on_round_trip(t0, RTT, 0);
        cc.on_retransmit_timeout(at(t0, 1_000), 40 * SEGMENT, &[14]);
        cc.restart();
        assert!(!cc.undo_timeout_if_spurious(14, at(t0, 1_010)));
        assert_eq!(cc, CongestionWindow::new());
    }

    #[test]
    fn a_restart_forgets_a_probe() {
        let (mut cc, _) = probing();
        cc.restart();
        assert_eq!(cc, CongestionWindow::new());
    }
}
