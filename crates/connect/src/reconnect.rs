//! When and where a session whose link died is reconnected (spec §5.2), as a
//! state machine with no I/O and no clock: the caller says what happened and
//! when, and is told what to do. Each round is one background ladder
//! (`Ladder::background`) starting where the session last worked. The first
//! round starts at once; after a round that got nowhere the next one waits
//! 1, 2, 4, 8, 16, then 30 s -- the app's own `backoffDelayMs`. A changed
//! server key, or a session the server no longer has, ends it for good.

use std::time::Duration;

/// The longest pause between rounds.
pub const MAX_PAUSE: Duration = Duration::from_secs(30);

/// The pause after `failed` rounds in a row got nowhere (`failed` >= 1).
pub fn pause_after(failed: u32) -> Duration {
    let exp = failed.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << exp).min(MAX_PAUSE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The link died on its own (the transport's death timer).
    LinkDead,
    /// The person asked to reconnect right now.
    Now,
    /// Time passed.
    Tick,
    /// The round the last `Order::Climb` started is over.
    RoundOver(RoundEnd),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundEnd {
    /// Explicit authenticated terminal failure, not another failed round.
    SessionAborted {
        addr: usize,
        reason: u8,
    },
    /// Back in the session, at this address.
    Connected {
        addr: usize,
    },
    AllFailed,
    KeyChanged {
        addr: usize,
    },
    SessionGone {
        addr: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Nothing,
    /// Start a round at `first`. `detach`: the link is still up and must be
    /// let go first -- quietly, so the server keeps the session for this
    /// round to come back to.
    Climb {
        first: usize,
        detach: bool,
    },
    /// Stop: the run ends.
    Stop(Stop),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    SessionAborted { addr: usize, reason: u8 },
    KeyChanged { addr: usize },
    SessionGone { addr: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connected,
    Climbing,
    /// The next round starts at `until`.
    Waiting {
        until: Duration,
    },
    Over,
}

pub struct Reconnect {
    /// Where the session last worked: every round starts there.
    last: usize,
    /// Rounds in a row that got nowhere.
    failed: u32,
    phase: Phase,
}

impl Reconnect {
    pub fn new(connected_at: usize) -> Reconnect {
        Reconnect {
            last: connected_at,
            failed: 0,
            phase: Phase::Connected,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The traffic moved to address `addr` (a road switch): the next round
    /// starts there. Ignored unless connected -- a round under way, or the
    /// wait for the next one, already knows where it starts.
    pub fn in_use(&mut self, addr: usize) {
        if self.phase == Phase::Connected {
            self.last = addr;
        }
    }

    pub fn on(&mut self, event: Event, now: Duration) -> Order {
        match (self.phase, event) {
            (Phase::Over, _) => panic!("reconnecting is over: nothing follows Stop"),
            (Phase::Connected, Event::LinkDead) => self.climb(false),
            (Phase::Connected, Event::Now) => self.climb(true),
            (Phase::Connected, Event::Tick) => Order::Nothing,
            (Phase::Climbing, Event::RoundOver(end)) => match end {
                RoundEnd::Connected { addr } => {
                    self.last = addr;
                    self.failed = 0;
                    self.phase = Phase::Connected;
                    Order::Nothing
                }
                RoundEnd::AllFailed => {
                    self.failed = self.failed.saturating_add(1);
                    self.phase = Phase::Waiting {
                        until: now + pause_after(self.failed),
                    };
                    Order::Nothing
                }
                RoundEnd::SessionAborted { addr, reason } => {
                    self.stop(Stop::SessionAborted { addr, reason })
                }
                RoundEnd::KeyChanged { addr } => self.stop(Stop::KeyChanged { addr }),
                RoundEnd::SessionGone { addr } => self.stop(Stop::SessionGone { addr }),
            },
            // A round is already under way: one at a time.
            (Phase::Climbing, Event::LinkDead | Event::Now | Event::Tick) => Order::Nothing,
            (Phase::Waiting { until }, Event::Tick) if now >= until => self.climb(false),
            (Phase::Waiting { .. }, Event::Now) => self.climb(false),
            (Phase::Waiting { .. }, Event::Tick | Event::LinkDead) => Order::Nothing,
            (phase, Event::RoundOver(end)) => {
                panic!("a round ended that was never started: {end:?} while {phase:?}")
            }
        }
    }

    fn climb(&mut self, detach: bool) -> Order {
        self.phase = Phase::Climbing;
        Order::Climb {
            first: self.last,
            detach,
        }
    }

    fn stop(&mut self, stop: Stop) -> Order {
        self.phase = Phase::Over;
        Order::Stop(stop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_pauses_are_the_app_s_own() {
        let got: Vec<u64> = (1..=8).map(|n| pause_after(n).as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(pause_after(u32::MAX), MAX_PAUSE);
    }

    #[test]
    fn a_dead_link_starts_a_round_at_once_where_the_session_worked() {
        let mut r = Reconnect::new(2);
        assert_eq!(r.on(Event::Tick, secs(5)), Order::Nothing);
        assert_eq!(
            r.on(Event::LinkDead, secs(5)),
            Order::Climb {
                first: 2,
                detach: false
            }
        );
        assert_eq!(r.phase(), Phase::Climbing);
    }

    #[test]
    fn asking_now_on_a_live_link_lets_it_go_first() {
        let mut r = Reconnect::new(0);
        assert_eq!(
            r.on(Event::Now, secs(1)),
            Order::Climb {
                first: 0,
                detach: true
            }
        );
    }

    #[test]
    fn one_round_at_a_time() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        assert_eq!(r.on(Event::Now, secs(1)), Order::Nothing);
        assert_eq!(r.on(Event::LinkDead, secs(1)), Order::Nothing);
        assert_eq!(r.on(Event::Tick, secs(1)), Order::Nothing);
    }

    #[test]
    fn a_failed_round_waits_and_the_waits_grow() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        assert_eq!(
            r.on(Event::RoundOver(RoundEnd::AllFailed), secs(10)),
            Order::Nothing
        );
        assert_eq!(r.phase(), Phase::Waiting { until: secs(11) });
        assert_eq!(
            r.on(Event::Tick, Duration::from_millis(10_999)),
            Order::Nothing
        );
        assert_eq!(
            r.on(Event::Tick, secs(11)),
            Order::Climb {
                first: 0,
                detach: false
            }
        );
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(20));
        assert_eq!(r.phase(), Phase::Waiting { until: secs(22) });
    }

    #[test]
    fn asking_now_during_a_wait_starts_the_round_without_it() {
        let mut r = Reconnect::new(1);
        r.on(Event::LinkDead, secs(0));
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(3));
        assert_eq!(
            r.on(Event::Now, secs(3)),
            Order::Climb {
                first: 1,
                detach: false
            }
        );
        assert_eq!(r.phase(), Phase::Climbing);
    }

    #[test]
    fn a_death_during_a_wait_changes_nothing() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(3));
        assert_eq!(r.on(Event::LinkDead, secs(3)), Order::Nothing);
    }

    #[test]
    fn a_return_remembers_the_address_and_forgets_the_failures() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(1));
        r.on(Event::Now, secs(1));
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(2));
        r.on(Event::Now, secs(2));
        assert_eq!(
            r.on(Event::RoundOver(RoundEnd::Connected { addr: 3 }), secs(4)),
            Order::Nothing
        );
        assert_eq!(r.phase(), Phase::Connected);
        assert_eq!(
            r.on(Event::LinkDead, secs(100)),
            Order::Climb {
                first: 3,
                detach: false
            }
        );
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(110));
        assert_eq!(
            r.phase(),
            Phase::Waiting { until: secs(111) },
            "the pauses start over"
        );
    }

    #[test]
    fn a_changed_key_or_a_gone_session_ends_it() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        assert_eq!(
            r.on(Event::RoundOver(RoundEnd::KeyChanged { addr: 1 }), secs(1)),
            Order::Stop(Stop::KeyChanged { addr: 1 })
        );
        assert_eq!(r.phase(), Phase::Over);

        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        assert_eq!(
            r.on(Event::RoundOver(RoundEnd::SessionGone { addr: 0 }), secs(1)),
            Order::Stop(Stop::SessionGone { addr: 0 })
        );
    }

    #[test]
    fn a_road_switch_moves_where_the_next_round_starts() {
        let mut r = Reconnect::new(0);
        r.in_use(2);
        assert_eq!(
            r.on(Event::LinkDead, secs(1)),
            Order::Climb {
                first: 2,
                detach: false
            }
        );
        r.in_use(1);
        assert_eq!(r.phase(), Phase::Climbing, "ignored while climbing");
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(2));
        r.in_use(1);
        assert_eq!(
            r.on(Event::Now, secs(2)),
            Order::Climb {
                first: 2,
                detach: false
            },
            "ignored while waiting"
        );
    }

    #[test]
    #[should_panic(expected = "a round ended that was never started")]
    fn a_round_that_was_never_started_cannot_end() {
        let mut r = Reconnect::new(0);
        r.on(Event::RoundOver(RoundEnd::AllFailed), secs(0));
    }

    #[test]
    #[should_panic(expected = "reconnecting is over")]
    fn nothing_follows_the_end() {
        let mut r = Reconnect::new(0);
        r.on(Event::LinkDead, secs(0));
        r.on(Event::RoundOver(RoundEnd::SessionGone { addr: 0 }), secs(1));
        r.on(Event::Tick, secs(2));
    }
    #[test]
    fn capacity_recovery_abort_stops_instead_of_waiting_for_another_round() {
        let mut reconnect = Reconnect::new(0);
        reconnect.on(Event::LinkDead, secs(0));
        assert_eq!(
            reconnect.on(
                Event::RoundOver(RoundEnd::SessionAborted {
                    addr: 0,
                    reason: 200
                }),
                secs(1)
            ),
            Order::Stop(Stop::SessionAborted {
                addr: 0,
                reason: 200
            })
        );
        assert_eq!(reconnect.phase(), Phase::Over);
    }
}
