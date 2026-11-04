#![forbid(unsafe_code)]

//! Port knocking: a short sequence of UDP datagrams and TCP connection
//! attempts that makes a router open a port for this client's address.
//!
//! The sequence itself is sans-IO: sending and waiting sit behind
//! [`KnockSender`] and [`Pause`], so order, pauses and cancellation are
//! tested without a network. The real sender lives in [`socket`].
//!
//! [`run_within`] is the same sequence under one [`Deadline`] that every
//! step, every pause and the connection after them share; time comes from a
//! [`Clock`], so long pauses are tested without waiting for them.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod resolve;
pub mod socket;

pub use resolve::{resolve, resolve_with, RESOLVE_BUDGET};
pub use socket::{NoBind, SocketBind, SocketKnockSender, TCP_KNOCK_TIMEOUT};

/// The longest stretch anything here waits without looking at [`Cancel`]:
/// a person pressing Cancel is answered within this.
pub const SLICE: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnockProtocol {
    Udp,
    Tcp,
}

/// One knock: a packet to `port` on the knocked address, then a pause.
/// `Debug` shows the kind of step and the pause only: its port and data
/// are a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct KnockStep {
    pub protocol: KnockProtocol,
    pub port: u16,
    /// Empty means "no payload".
    pub payload: Vec<u8>,
    pub delay_after_ms: u32,
}

impl fmt::Debug for KnockStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnockStep")
            .field("protocol", &self.protocol)
            .field("port", &format_args!("<hidden>"))
            .field("payload", &format_args!("<hidden>"))
            .field("delay_after_ms", &self.delay_after_ms)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnockError {
    /// The host name gave no address to knock. The text is for a person.
    Resolve(String),
    Cancelled,
}

impl fmt::Display for KnockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KnockError::Resolve(reason) => write!(f, "{reason}"),
            KnockError::Cancelled => write!(f, "port knocking was cancelled"),
        }
    }
}

impl std::error::Error for KnockError {}

/// A cancellation flag shared between the knocking thread and whoever may
/// cancel it. Cloning shares the flag.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Sends one knock. Sending reports nothing: a UDP datagram has nobody to
/// refuse it, and for TCP every outcome -- accepted, refused, timed out --
/// means the SYN left, which is all a router watches for.
pub trait KnockSender {
    fn udp(&mut self, to: SocketAddr, payload: &[u8]);
    fn tcp(&mut self, to: SocketAddr, payload: &[u8]);
}

/// Waits between knocks.
pub trait Pause {
    /// Sleeps up to `ms`; returns false if `cancel` was set meanwhile.
    fn pause(&mut self, ms: u32, cancel: &Cancel) -> bool;
}

/// The real pause: sleeps in [`SLICE`]s, looking at the flag between them.
pub struct SleepPause;

impl Pause for SleepPause {
    fn pause(&mut self, ms: u32, cancel: &Cancel) -> bool {
        let deadline = Instant::now() + Duration::from_millis(ms.into());
        loop {
            if cancel.is_cancelled() {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            std::thread::sleep((deadline - now).min(SLICE));
        }
    }
}

/// Why a knock under a [`Deadline`] stopped before its end. Nothing more may
/// be sent, and nothing dialled, after either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    Cancelled,
    /// The deadline was reached.
    Expired,
}

/// One absolute point in time, shared by every knock step, every pause and
/// the connection after them. Nothing restarts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline(Instant);

impl Deadline {
    /// `budget` after `now`. `None` for a zero budget, and for one past the
    /// clock's range: nothing may start under either.
    pub fn after(now: Instant, budget: Duration) -> Option<Self> {
        if budget.is_zero() {
            return None;
        }
        now.checked_add(budget).map(Deadline)
    }

    pub fn instant(self) -> Instant {
        self.0
    }

    /// The time left at `now`; `None` once `now` has reached the deadline.
    pub fn remaining(self, now: Instant) -> Option<Duration> {
        self.0
            .checked_duration_since(now)
            .filter(|left| !left.is_zero())
    }

    /// The time left at `now`, or why to stop. A cancel wins over an expiry
    /// that falls on the same look.
    pub fn check(self, now: Instant, cancel: &Cancel) -> Result<Duration, Stopped> {
        if cancel.is_cancelled() {
            return Err(Stopped::Cancelled);
        }
        self.remaining(now).ok_or(Stopped::Expired)
    }
}

/// The time a knock under a [`Deadline`] sees and waits on.
pub trait Clock {
    fn now(&self) -> Instant;
    /// Sleeps `d`. Called with at most [`SLICE`].
    fn sleep(&mut self, d: Duration);
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d)
    }
}

/// Sends one knock within a [`Deadline`]. As for [`KnockSender`], an
/// ordinary failure is not reported: `Err` says only that the deadline was
/// reached or `cancel` was set, so the sequence must stop.
pub trait BoundedKnockSender {
    fn udp_within(
        &mut self,
        to: SocketAddr,
        payload: &[u8],
        deadline: Deadline,
        cancel: &Cancel,
    ) -> Result<(), Stopped>;
    fn tcp_within(
        &mut self,
        to: SocketAddr,
        payload: &[u8],
        deadline: Deadline,
        cancel: &Cancel,
    ) -> Result<(), Stopped>;
}

/// Knocks `target` with `steps`, in order, pausing after each step for its
/// `delay_after_ms`. Checks `cancel` before every step and during every
/// pause; a cancel ends the run with [`KnockError::Cancelled`].
pub fn run(
    target: IpAddr,
    steps: &[KnockStep],
    sender: &mut impl KnockSender,
    pause: &mut impl Pause,
    cancel: &Cancel,
) -> Result<(), KnockError> {
    struct Pair<'a, S, P>(&'a mut S, &'a mut P);
    impl<S: KnockSender, P> KnockSender for Pair<'_, S, P> {
        fn udp(&mut self, to: SocketAddr, payload: &[u8]) {
            self.0.udp(to, payload)
        }
        fn tcp(&mut self, to: SocketAddr, payload: &[u8]) {
            self.0.tcp(to, payload)
        }
    }
    impl<S, P: Pause> Pause for Pair<'_, S, P> {
        fn pause(&mut self, ms: u32, cancel: &Cancel) -> bool {
            self.1.pause(ms, cancel)
        }
    }
    run_split(target, steps, &mut Pair(sender, pause), cancel)
}

/// [`run`] over one object that both sends and pauses -- the shape a test
/// recorder has, since it must see sends and pauses in one ordered log.
fn run_split<T: KnockSender + Pause>(
    target: IpAddr,
    steps: &[KnockStep],
    both: &mut T,
    cancel: &Cancel,
) -> Result<(), KnockError> {
    for step in steps {
        if cancel.is_cancelled() {
            return Err(KnockError::Cancelled);
        }
        let to = SocketAddr::new(target, step.port);
        match step.protocol {
            KnockProtocol::Udp => both.udp(to, &step.payload),
            KnockProtocol::Tcp => both.tcp(to, &step.payload),
        }
        if step.delay_after_ms > 0 && !both.pause(step.delay_after_ms, cancel) {
            return Err(KnockError::Cancelled);
        }
    }
    Ok(())
}

/// [`run`] within `deadline`: the steps and their pauses share it, and a
/// pause is cut short at it. Looks at `cancel`, then at the deadline,
/// before every step, during every pause and after the last step, so `Ok`
/// leaves time for the connection that follows.
pub fn run_within(
    target: IpAddr,
    steps: &[KnockStep],
    sender: &mut impl BoundedKnockSender,
    clock: &mut impl Clock,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    struct Pair<'a, S, C>(&'a mut S, &'a mut C);
    impl<S: BoundedKnockSender, C> BoundedKnockSender for Pair<'_, S, C> {
        fn udp_within(
            &mut self,
            to: SocketAddr,
            payload: &[u8],
            deadline: Deadline,
            cancel: &Cancel,
        ) -> Result<(), Stopped> {
            self.0.udp_within(to, payload, deadline, cancel)
        }
        fn tcp_within(
            &mut self,
            to: SocketAddr,
            payload: &[u8],
            deadline: Deadline,
            cancel: &Cancel,
        ) -> Result<(), Stopped> {
            self.0.tcp_within(to, payload, deadline, cancel)
        }
    }
    impl<S, C: Clock> Clock for Pair<'_, S, C> {
        fn now(&self) -> Instant {
            self.1.now()
        }
        fn sleep(&mut self, d: Duration) {
            self.1.sleep(d)
        }
    }
    run_within_split(target, steps, &mut Pair(sender, clock), deadline, cancel)
}

/// [`run_within`] over one object that both sends and keeps time.
fn run_within_split<T: BoundedKnockSender + Clock>(
    target: IpAddr,
    steps: &[KnockStep],
    both: &mut T,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    for step in steps {
        deadline.check(both.now(), cancel)?;
        let to = SocketAddr::new(target, step.port);
        match step.protocol {
            KnockProtocol::Udp => both.udp_within(to, &step.payload, deadline, cancel)?,
            KnockProtocol::Tcp => both.tcp_within(to, &step.payload, deadline, cancel)?,
        }
        if step.delay_after_ms > 0 {
            pause_within(step.delay_after_ms, both, deadline, cancel)?;
        }
    }
    deadline.check(both.now(), cancel).map(|_| ())
}

/// Waits `ms` in [`SLICE`]s, never past `deadline`. A pause that would end
/// on the deadline or after it is [`Stopped::Expired`] there.
fn pause_within(
    ms: u32,
    clock: &mut impl Clock,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    // `None`: past the clock's range, so past the deadline too.
    let end = clock.now().checked_add(Duration::from_millis(ms.into()));
    loop {
        let now = clock.now();
        let left = deadline.check(now, cancel)?;
        let wait = match end {
            Some(end) => match end.checked_duration_since(now) {
                Some(wait) if !wait.is_zero() => wait.min(left),
                _ => return Ok(()),
            },
            None => left,
        };
        clock.sleep(wait.min(SLICE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Udp(SocketAddr, Vec<u8>),
        Tcp(SocketAddr, Vec<u8>),
        Pause(u32),
    }

    /// Records every send and pause, in order. `cancel_on_pause` makes the
    /// first pause cancel the run the way a person pressing Cancel would.
    #[derive(Default)]
    struct Recorder {
        events: Vec<Event>,
        cancel_on_pause: Option<Cancel>,
    }

    impl KnockSender for Recorder {
        fn udp(&mut self, to: SocketAddr, payload: &[u8]) {
            self.events.push(Event::Udp(to, payload.to_vec()));
        }
        fn tcp(&mut self, to: SocketAddr, payload: &[u8]) {
            self.events.push(Event::Tcp(to, payload.to_vec()));
        }
    }

    impl Pause for Recorder {
        fn pause(&mut self, ms: u32, cancel: &Cancel) -> bool {
            self.events.push(Event::Pause(ms));
            if let Some(c) = self.cancel_on_pause.take() {
                c.cancel();
            }
            !cancel.is_cancelled()
        }
    }

    const TARGET: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    fn step(protocol: KnockProtocol, port: u16, payload: &[u8], delay_after_ms: u32) -> KnockStep {
        KnockStep {
            protocol,
            port,
            payload: payload.to_vec(),
            delay_after_ms,
        }
    }

    fn at(port: u16) -> SocketAddr {
        SocketAddr::new(TARGET, port)
    }

    /// A knock's ports and data are a secret: `{:?}` of a step (in a log
    /// line, an assertion message) shows its kind and pause only.
    #[test]
    fn debug_hides_the_port_and_the_data() {
        let s = step(KnockProtocol::Udp, 7123, b"s3cr3t", 250);
        let shown = format!("{s:?}");
        assert!(!shown.contains("7123"), "{shown}");
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(!shown.contains("115, 51"), "payload bytes: {shown}");
        assert!(shown.contains("Udp") && shown.contains("250"), "{shown}");
        assert!(shown.contains("<hidden>"), "{shown}");
        let alt = format!("{:#?}", step(KnockProtocol::Tcp, 8456, b"", 0));
        assert!(!alt.contains("8456") && alt.contains("Tcp"), "{alt}");
    }

    fn run_recorded(
        steps: &[KnockStep],
        rec: &mut Recorder,
        cancel: &Cancel,
    ) -> Result<(), KnockError> {
        // One object sends and pauses, so both land in one ordered log.
        run_split(TARGET, steps, rec, cancel)
    }

    #[test]
    fn steps_go_out_in_order_with_their_ports_payloads_and_pauses() {
        let mut rec = Recorder::default();
        let steps = [
            step(KnockProtocol::Udp, 7000, b"ab", 250),
            step(KnockProtocol::Tcp, 8000, &[0xde, 0xad], 0),
            step(KnockProtocol::Udp, 9000, b"", 40),
        ];
        run_recorded(&steps, &mut rec, &Cancel::new()).expect("no cancel");
        assert_eq!(
            rec.events,
            vec![
                Event::Udp(at(7000), b"ab".to_vec()),
                Event::Pause(250),
                Event::Tcp(at(8000), vec![0xde, 0xad]),
                Event::Udp(at(9000), vec![]),
                Event::Pause(40),
            ]
        );
    }

    #[test]
    fn an_empty_sequence_sends_nothing() {
        let mut rec = Recorder::default();
        run_recorded(&[], &mut rec, &Cancel::new()).expect("nothing to cancel");
        assert!(rec.events.is_empty());
    }

    #[test]
    fn a_cancel_before_the_first_step_sends_nothing() {
        let mut rec = Recorder::default();
        let cancel = Cancel::new();
        cancel.cancel();
        let r = run_recorded(&[step(KnockProtocol::Udp, 1, b"", 0)], &mut rec, &cancel);
        assert_eq!(r, Err(KnockError::Cancelled));
        assert!(rec.events.is_empty());
    }

    #[test]
    fn a_cancel_during_a_pause_stops_before_the_next_step() {
        let cancel = Cancel::new();
        let mut rec = Recorder {
            cancel_on_pause: Some(cancel.clone()),
            ..Default::default()
        };
        let steps = [
            step(KnockProtocol::Udp, 1, b"", 1000),
            step(KnockProtocol::Tcp, 2, b"", 0),
        ];
        let r = run_recorded(&steps, &mut rec, &cancel);
        assert_eq!(r, Err(KnockError::Cancelled));
        assert_eq!(
            rec.events,
            vec![Event::Udp(at(1), vec![]), Event::Pause(1000)]
        );
    }

    /// A simulated network and clock for [`run_within`]: sends and sleeps
    /// land in one log stamped with the simulated time since `start`. Each
    /// send may take time and may cancel the run; nothing really waits.
    struct Sim {
        start: Instant,
        now: Instant,
        log: Vec<(Duration, Event)>,
        sleeps: Vec<Duration>,
        send_takes: Duration,
        cancel_at_send: Option<(usize, Cancel)>,
        sends: usize,
    }

    impl Sim {
        fn new() -> Self {
            let start = Instant::now();
            Sim {
                start,
                now: start,
                log: Vec::new(),
                sleeps: Vec::new(),
                send_takes: Duration::ZERO,
                cancel_at_send: None,
                sends: 0,
            }
        }

        fn deadline(&self, budget: Duration) -> Deadline {
            Deadline::after(self.now, budget).expect("a usable budget")
        }

        fn send(&mut self, event: Event) -> Result<(), Stopped> {
            self.log.push((self.now - self.start, event));
            self.now += self.send_takes;
            self.sends += 1;
            if let Some((at, cancel)) = &self.cancel_at_send {
                if *at == self.sends {
                    cancel.cancel();
                }
            }
            Ok(())
        }

        fn sent(&self) -> Vec<Duration> {
            self.log.iter().map(|(at, _)| *at).collect()
        }

        fn elapsed(&self) -> Duration {
            self.now - self.start
        }
    }

    impl BoundedKnockSender for Sim {
        fn udp_within(
            &mut self,
            to: SocketAddr,
            payload: &[u8],
            _: Deadline,
            _: &Cancel,
        ) -> Result<(), Stopped> {
            self.send(Event::Udp(to, payload.to_vec()))
        }
        fn tcp_within(
            &mut self,
            to: SocketAddr,
            payload: &[u8],
            _: Deadline,
            _: &Cancel,
        ) -> Result<(), Stopped> {
            self.send(Event::Tcp(to, payload.to_vec()))
        }
    }

    impl Clock for Sim {
        fn now(&self) -> Instant {
            self.now
        }
        fn sleep(&mut self, d: Duration) {
            assert!(!d.is_zero() && d <= SLICE, "a sleep of {d:?}");
            self.sleeps.push(d);
            self.now += d;
        }
    }

    fn run_sim(
        steps: &[KnockStep],
        sim: &mut Sim,
        deadline: Deadline,
        cancel: &Cancel,
    ) -> Result<(), Stopped> {
        run_within_split(TARGET, steps, sim, deadline, cancel)
    }

    const fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    const fn ms(m: u64) -> Duration {
        Duration::from_millis(m)
    }

    #[test]
    fn a_zero_or_out_of_range_budget_gives_no_deadline() {
        let now = Instant::now();
        assert_eq!(Deadline::after(now, Duration::ZERO), None);
        assert_eq!(Deadline::after(now, Duration::MAX), None);
        let tiny = Deadline::after(now, Duration::from_nanos(1)).expect("1 ns is a budget");
        assert_eq!(tiny.remaining(now), Some(Duration::from_nanos(1)));
    }

    #[test]
    fn a_deadline_is_reached_at_its_instant_not_after() {
        let now = Instant::now();
        let d = Deadline::after(now, secs(10)).unwrap();
        assert_eq!(d.instant(), now + secs(10));
        assert_eq!(
            d.remaining(now + secs(10) - Duration::from_nanos(1)),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(d.remaining(now + secs(10)), None);
        assert_eq!(d.remaining(now + secs(11)), None);
        assert_eq!(
            d.check(now + secs(10), &Cancel::new()),
            Err(Stopped::Expired)
        );
    }

    #[test]
    fn a_cancel_wins_over_an_expiry_on_the_same_look() {
        let now = Instant::now();
        let d = Deadline::after(now, secs(1)).unwrap();
        let cancel = Cancel::new();
        cancel.cancel();
        assert_eq!(d.check(now + secs(1), &cancel), Err(Stopped::Cancelled));
        assert_eq!(d.check(now, &cancel), Err(Stopped::Cancelled));
    }

    /// The bounded run keeps the order, ports, bytes and empty payloads of
    /// the steps, and spends exactly their pauses when they fit.
    #[test]
    fn a_sequence_that_fits_goes_out_unchanged() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(10));
        let steps = [
            step(KnockProtocol::Udp, 7000, b"ab", 250),
            step(KnockProtocol::Tcp, 8000, &[0xde, 0xad], 0),
            step(KnockProtocol::Udp, 9000, b"", 40),
        ];
        run_sim(&steps, &mut sim, deadline, &Cancel::new()).expect("it fits");
        assert_eq!(
            sim.log,
            vec![
                (ms(0), Event::Udp(at(7000), b"ab".to_vec())),
                (ms(250), Event::Tcp(at(8000), vec![0xde, 0xad])),
                (ms(250), Event::Udp(at(9000), vec![])),
            ]
        );
        assert_eq!(sim.elapsed(), ms(290));
        assert_eq!(deadline.remaining(sim.now), Some(ms(9_710)));
    }

    /// Pauses add up against one deadline: no pause gets a fresh one. Three
    /// pauses of 4 s under 10 s let three steps out, and the third pause is
    /// cut at 10 s; the fourth step never goes.
    #[test]
    fn cumulative_pauses_run_out_of_the_one_deadline() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(10));
        let steps: Vec<_> = (0..4)
            .map(|i| step(KnockProtocol::Udp, 7000 + i, b"k", 4_000))
            .collect();
        let r = run_sim(&steps, &mut sim, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sim.sent(), vec![secs(0), secs(4), secs(8)]);
        assert_eq!(sim.elapsed(), secs(10), "no time past the deadline");
        assert_eq!(sim.sleeps.iter().sum::<Duration>(), secs(10));
    }

    /// Time spent sending counts too.
    #[test]
    fn time_spent_sending_counts_against_the_deadline() {
        let mut sim = Sim::new();
        sim.send_takes = ms(300);
        let deadline = sim.deadline(secs(1));
        let steps: Vec<_> = (0..10)
            .map(|i| step(KnockProtocol::Tcp, 7000 + i, b"", 0))
            .collect();
        let r = run_sim(&steps, &mut sim, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sim.sent(), vec![ms(0), ms(300), ms(600), ms(900)]);
    }

    /// Many steps with short pauses stop at the deadline, not at their end.
    #[test]
    fn many_steps_stop_at_the_deadline() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(5));
        let steps: Vec<_> = (0..20_000u32)
            .map(|i| step(KnockProtocol::Udp, (i % 60_000) as u16 + 1, b"", 1))
            .collect();
        let r = run_sim(&steps, &mut sim, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sim.sends, 5_000, "one step per millisecond for 5 s");
        assert_eq!(sim.elapsed(), secs(5));
    }

    /// The longest pause the grammar accepts (`u32::MAX` ms, over 49 days)
    /// ends at the deadline, in sleeps of a slice at most, without waiting.
    #[test]
    fn the_longest_accepted_pause_ends_at_the_deadline() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(10));
        let steps = [
            step(KnockProtocol::Udp, 1, b"", u32::MAX),
            step(KnockProtocol::Udp, 2, b"", 0),
        ];
        let r = run_sim(&steps, &mut sim, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sim.sends, 1);
        assert_eq!(sim.elapsed(), secs(10));
        assert_eq!(
            sim.sleeps.len(),
            (secs(10).as_millis() / SLICE.as_millis()) as usize
        );
    }

    /// The last sleep of a cut pause is only the time left, so the run
    /// ends on the deadline, not up to a slice after it.
    #[test]
    fn a_pause_is_cut_exactly_at_the_deadline() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(ms(1_020));
        let r = run_sim(
            &[step(KnockProtocol::Udp, 1, b"", 5_000)],
            &mut sim,
            deadline,
            &Cancel::new(),
        );
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sim.elapsed(), ms(1_020));
        assert_eq!(sim.sleeps.last(), Some(&ms(20)));
    }

    /// A pause that ends exactly on the deadline leaves no time to connect;
    /// one that ends a nanosecond earlier does.
    #[test]
    fn a_pause_ending_on_the_deadline_is_an_expiry() {
        let steps = [step(KnockProtocol::Udp, 1, b"", 1_000)];
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(1));
        assert_eq!(
            run_sim(&steps, &mut sim, deadline, &Cancel::new()),
            Err(Stopped::Expired)
        );
        assert_eq!(sim.elapsed(), secs(1));

        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(1) + Duration::from_nanos(1));
        run_sim(&steps, &mut sim, deadline, &Cancel::new()).expect("1 ns is left");
        assert_eq!(deadline.remaining(sim.now), Some(Duration::from_nanos(1)));
    }

    #[test]
    fn an_expired_deadline_sends_nothing() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(ms(1));
        sim.now += ms(1);
        let r = run_sim(
            &[step(KnockProtocol::Tcp, 1, b"x", 0)],
            &mut sim,
            deadline,
            &Cancel::new(),
        );
        assert_eq!(r, Err(Stopped::Expired));
        assert!(sim.log.is_empty());
        assert!(run_sim(&[], &mut sim, deadline, &Cancel::new()) == Err(Stopped::Expired));
    }

    #[test]
    fn an_empty_sequence_within_time_is_ok() {
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(1));
        run_sim(&[], &mut sim, deadline, &Cancel::new()).expect("time is left");
        assert!(sim.log.is_empty() && sim.sleeps.is_empty());
    }

    /// A cancel during the last send, with no pause after it, still stops
    /// the run: the connection after it must not be dialled.
    #[test]
    fn a_cancel_during_the_last_step_is_reported() {
        let cancel = Cancel::new();
        let mut sim = Sim::new();
        sim.cancel_at_send = Some((2, cancel.clone()));
        let deadline = sim.deadline(secs(10));
        let steps = [
            step(KnockProtocol::Udp, 1, b"", 0),
            step(KnockProtocol::Tcp, 2, b"", 0),
        ];
        assert_eq!(
            run_sim(&steps, &mut sim, deadline, &cancel),
            Err(Stopped::Cancelled)
        );
        assert_eq!(sim.sends, 2);
    }

    /// A cancel during a send that also used up the time is a cancel.
    #[test]
    fn a_cancel_and_an_expiry_together_are_a_cancel() {
        let cancel = Cancel::new();
        let mut sim = Sim::new();
        sim.send_takes = secs(2);
        sim.cancel_at_send = Some((1, cancel.clone()));
        let deadline = sim.deadline(secs(1));
        let steps = [
            step(KnockProtocol::Udp, 1, b"", 500),
            step(KnockProtocol::Udp, 2, b"", 0),
        ];
        assert_eq!(
            run_sim(&steps, &mut sim, deadline, &cancel),
            Err(Stopped::Cancelled)
        );
        assert_eq!(sim.sends, 1);
        assert!(sim.sleeps.is_empty());
    }

    #[test]
    fn a_cancel_before_a_bounded_run_sends_nothing() {
        let cancel = Cancel::new();
        cancel.cancel();
        let mut sim = Sim::new();
        let deadline = sim.deadline(secs(10));
        let r = run_sim(
            &[step(KnockProtocol::Udp, 1, b"", 0)],
            &mut sim,
            deadline,
            &cancel,
        );
        assert_eq!(r, Err(Stopped::Cancelled));
        assert!(sim.log.is_empty());
    }

    /// A sender that reports the run stopped ends it: no later step.
    #[test]
    fn a_stopped_send_ends_the_sequence() {
        struct Stops(usize);
        impl BoundedKnockSender for Stops {
            fn udp_within(
                &mut self,
                _: SocketAddr,
                _: &[u8],
                _: Deadline,
                _: &Cancel,
            ) -> Result<(), Stopped> {
                self.0 += 1;
                Err(Stopped::Expired)
            }
            fn tcp_within(
                &mut self,
                _: SocketAddr,
                _: &[u8],
                _: Deadline,
                _: &Cancel,
            ) -> Result<(), Stopped> {
                self.0 += 1;
                Ok(())
            }
        }
        let mut sender = Stops(0);
        let steps = [
            step(KnockProtocol::Udp, 1, b"", 0),
            step(KnockProtocol::Tcp, 2, b"", 0),
        ];
        let deadline = Deadline::after(Instant::now(), secs(60)).unwrap();
        let r = run_within(
            TARGET,
            &steps,
            &mut sender,
            &mut SystemClock,
            deadline,
            &Cancel::new(),
        );
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(sender.0, 1);
    }

    /// The real clock: a bounded pause ends at the deadline, within a
    /// slice of a cancel.
    #[test]
    fn the_real_clock_cuts_a_long_pause_at_the_deadline() {
        let started = Instant::now();
        let deadline = Deadline::after(started, ms(120)).unwrap();
        let r = pause_within(u32::MAX, &mut SystemClock, deadline, &Cancel::new());
        let waited = started.elapsed();
        assert_eq!(r, Err(Stopped::Expired));
        assert!(
            waited >= ms(120) && waited < ms(120) + SLICE * 3,
            "waited {waited:?}"
        );
    }

    #[test]
    fn the_real_pause_sleeps_its_length() {
        let started = Instant::now();
        assert!(SleepPause.pause(120, &Cancel::new()));
        assert!(started.elapsed() >= Duration::from_millis(120));
    }

    #[test]
    fn the_real_pause_ends_within_a_slice_of_a_cancel() {
        let cancel = Cancel::new();
        let remote = cancel.clone();
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            remote.cancel();
        });
        let started = Instant::now();
        assert!(!SleepPause.pause(5_000, &cancel));
        let waited = started.elapsed();
        canceller.join().unwrap();
        assert!(
            waited < Duration::from_millis(100) + SLICE * 3,
            "waited {waited:?}"
        );
    }
}
