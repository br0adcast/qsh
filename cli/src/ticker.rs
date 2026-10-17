//! The loop's tick pacing.
//!
//! `Session::handle(UiEvent::Tick, ..)` is what expires predictions, counts
//! the seconds in the "link lost" overlay, and lets a debounced resize record
//! out to the server. Deriving a tick from "the event channel went quiet" --
//! a `recv_timeout` that timed out -- starves all three for the whole of a
//! sustained output burst (`yes`, a large `cat`, a compile), because the
//! channel never goes quiet. The user then watches their own terminal reflow
//! while the remote application keeps drawing at the old width, which is
//! exactly the failure this pacing exists to prevent.
//!
//! So the tick is paced by the clock instead. That decision lives here,
//! apart from the loop, because the loop itself -- blocking reads, a real
//! socket, a real terminal -- is not testable and this is.

use std::time::{Duration, Instant};

/// Says when the next tick is due, on the clock alone.
pub struct Ticker {
    period: Duration,
    last: Instant,
}

impl Ticker {
    pub fn new(period: Duration, now: Instant) -> Ticker {
        Ticker { period, last: now }
    }

    /// Whether a tick is due at `now`, marking it taken if it is.
    ///
    /// A long gap yields ONE tick, not one per missed period: the events a
    /// tick drives are all "where are things now" questions (has this
    /// prediction expired, how many seconds has the link been down, is the
    /// size settled), and answering them repeatedly against the same instant
    /// changes nothing while costing a burst of work exactly when the
    /// program has just been given back the CPU.
    pub fn due(&mut self, now: Instant) -> bool {
        if now.duration_since(self.last) >= self.period {
            self.last = now;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERIOD: Duration = Duration::from_millis(20);

    fn ticker(start: Instant) -> Ticker {
        Ticker::new(PERIOD, start)
    }

    /// Nothing is due before the period is up: a tick per loop iteration
    /// would repaint and re-expire as fast as the CPU allows.
    #[test]
    fn nothing_is_due_before_the_period_is_up() {
        let start = Instant::now();
        let mut t = ticker(start);
        assert!(!t.due(start));
        assert!(!t.due(start + Duration::from_millis(19)));
    }

    /// Exactly on the period counts: the boundary is the common case, since
    /// the loop's own wait is the same length.
    #[test]
    fn the_period_itself_is_due() {
        let start = Instant::now();
        let mut t = ticker(start);
        assert!(t.due(start + PERIOD));
    }

    /// THE POINT OF THIS MODULE: a tick is due because time passed, not
    /// because the loop happened to be idle. During an output burst the
    /// channel is never empty, so a tick derived from a timed-out wait never
    /// arrives at all -- and the resize record waits out the whole burst.
    /// Here the caller is busy the entire time and still gets its ticks.
    #[test]
    fn ticks_keep_coming_while_the_loop_is_never_idle() {
        let start = Instant::now();
        let mut t = ticker(start);
        let mut ticks = 0;
        // Ten periods' worth of a caller that always had an event to handle.
        for step in 1..=100 {
            let now = start + Duration::from_millis(step * 2);
            if t.due(now) {
                ticks += 1;
            }
        }
        assert_eq!(ticks, 10, "one tick per elapsed period, busy or not");
    }

    /// Taking a tick consumes it: asking twice at the same instant must not
    /// yield two.
    #[test]
    fn a_tick_is_taken_only_once() {
        let start = Instant::now();
        let mut t = ticker(start);
        let now = start + PERIOD;
        assert!(t.due(now));
        assert!(!t.due(now));
    }

    /// A gap far longer than the period -- the process was stopped, or the
    /// machine slept -- yields one tick, not a backlog of them.
    #[test]
    fn a_long_gap_yields_one_tick_not_a_backlog() {
        let start = Instant::now();
        let mut t = ticker(start);
        assert!(t.due(start + Duration::from_secs(60)));
        assert!(!t.due(start + Duration::from_secs(60)));
    }
}
