//! Port knocking: a short sequence of UDP datagrams and TCP connection
//! attempts that makes a router open a port for this client's address.
//!
//! The sequence itself is sans-IO: sending and waiting sit behind
//! [`KnockSender`] and [`Pause`], so order, pauses and cancellation are
//! tested without a network. The real sender lives in [`socket`].

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
