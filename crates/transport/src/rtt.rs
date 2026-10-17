//! The retransmit timer's round-trip estimate (RFC 6298 §2).
//!
//! Fed by every round trip the connection measures under the load it
//! carries: a data segment acknowledged without having been retransmitted
//! (Karn's rule), and a PING answered by its PONG. Road liveness does not
//! read it -- the dead-road rule, `unanswered_after` and the header keep the
//! latest PONG (see `Connection::rtt`).

use std::time::Duration;

/// SRTT and RTTVAR, updated with the gains RFC 6298 gives: 1/8 and 1/4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RttEstimator {
    /// `(srtt, rttvar)`; `None` until the first sample.
    state: Option<(Duration, Duration)>,
}

impl RttEstimator {
    /// Take one round-trip sample.
    pub(crate) fn sample(&mut self, r: Duration) {
        self.state = Some(match self.state {
            None => (r, r / 2),
            Some((srtt, rttvar)) => {
                let err = srtt.abs_diff(r);
                (srtt * 7 / 8 + r / 8, rttvar * 3 / 4 + err / 4)
            }
        });
    }

    /// `SRTT + max(4 * RTTVAR, SRTT / 4)`, or `None` before the first sample.
    ///
    /// The `SRTT / 4` margin stands in for RFC 6298's clock granularity `G`,
    /// at a size that matters: a sample on every acknowledged segment --
    /// hundreds per round trip under bulk output -- drives RTTVAR towards
    /// zero on a steady queue, and a timeout at exactly SRTT would fire on
    /// the first datagram that queued a little longer than the average. A
    /// deeper queue varies more in absolute terms, so the margin scales with
    /// the round trip rather than being a constant.
    pub(crate) fn timeout(&self) -> Option<Duration> {
        self.state
            .map(|(srtt, rttvar)| srtt + (rttvar * 4).max(srtt / 4))
    }

    /// Smoothed round trip, for tests and diagnostics.
    #[cfg(test)]
    pub(crate) fn srtt(&self) -> Option<Duration> {
        self.state.map(|(srtt, _)| srtt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_sampled_gives_no_timeout() {
        assert_eq!(RttEstimator::default().timeout(), None);
    }

    /// RFC 6298 §2.2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 * RTTVAR.
    #[test]
    fn the_first_sample_sets_srtt_and_half_of_it_as_the_variation() {
        let mut e = RttEstimator::default();
        e.sample(Duration::from_millis(400));
        assert_eq!(e.srtt(), Some(Duration::from_millis(400)));
        assert_eq!(e.timeout(), Some(Duration::from_millis(1200)));
    }

    /// RFC 6298 §2.3, with beta = 1/4 and alpha = 1/8.
    #[test]
    fn later_samples_move_the_estimate_by_the_rfc_gains() {
        let mut e = RttEstimator::default();
        e.sample(Duration::from_millis(400));
        e.sample(Duration::from_millis(800));
        // RTTVAR = 3/4 * 200 + 1/4 * 400 = 250; SRTT = 7/8 * 400 + 1/8 * 800 = 450.
        assert_eq!(e.srtt(), Some(Duration::from_millis(450)));
        assert_eq!(e.timeout(), Some(Duration::from_millis(1450)));
    }

    /// A steady round trip drives RTTVAR towards zero; the margin keeps the
    /// timeout a quarter of SRTT clear of the average.
    #[test]
    fn a_steady_round_trip_keeps_a_quarter_of_srtt_as_the_margin() {
        let mut e = RttEstimator::default();
        for _ in 0..200 {
            e.sample(Duration::from_millis(2000));
        }
        assert_eq!(e.timeout(), Some(Duration::from_millis(2500)));
    }
}
