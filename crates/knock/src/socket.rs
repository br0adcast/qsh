//! The real knock: datagrams and connection attempts on fresh sockets, each
//! offered to the platform's network binding first.

use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    BoundedKnockSender, Cancel, Clock, Deadline, KnockSender, Stopped, SystemClock, SLICE,
};

/// How long a TCP knock waits for the connection. The SYN has left by the
/// time this runs out, and the SYN is all a router watches for.
///
/// Under a [`Deadline`] the wait is also cut at the deadline. It is one
/// connection attempt, during which `Cancel` is not looked at: a cancel is
/// answered within this, not within [`SLICE`].
pub const TCP_KNOCK_TIMEOUT: Duration = Duration::from_millis(200);

/// Binds a socket to a network before it is used. `false` means it could not; the socket is
/// used anyway and its traffic takes the default route, as the transport's
/// own sockets do (`driver_std::make_socket`). `Send + Sync`: an SSH
/// connection binds its socket on its own thread.
pub trait SocketBind: Send + Sync {
    fn bind(&self, fd: i32) -> bool;
}

/// No binding: the desktop, and tests.
pub struct NoBind;

impl SocketBind for NoBind {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

pub struct SocketKnockSender<B: SocketBind> {
    bind: B,
}

impl<B: SocketBind> SocketKnockSender<B> {
    pub fn new(bind: B) -> Self {
        Self { bind }
    }

    #[cfg(unix)]
    fn offer(&self, socket: &impl std::os::fd::AsRawFd) {
        let _ = self.bind.bind(socket.as_raw_fd());
    }

    #[cfg(not(unix))]
    fn offer<T>(&self, _socket: &T) {}
}

fn any_local(to: SocketAddr) -> SocketAddr {
    match to {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

impl<B: SocketBind> KnockSender for SocketKnockSender<B> {
    fn udp(&mut self, to: SocketAddr, payload: &[u8]) {
        let Ok(socket) = UdpSocket::bind(any_local(to)) else {
            return;
        };
        self.offer(&socket);
        let _ = socket.send_to(payload, to);
    }

    fn tcp(&mut self, to: SocketAddr, payload: &[u8]) {
        let Ok(mut socket) =
            Socket::new(Domain::for_address(to), Type::STREAM, Some(Protocol::TCP))
        else {
            return;
        };
        self.offer(&socket);
        // Refused, timed out, reset: the SYN went out, which is the knock.
        if socket
            .connect_timeout(&SockAddr::from(to), TCP_KNOCK_TIMEOUT)
            .is_ok()
            && !payload.is_empty()
        {
            let _ = socket.write_all(payload);
            let _ = socket.flush();
        }
    }
}

/// The same knocks, with every wait for the network cut at the deadline.
/// The binder is a synchronous callback that nothing here can cut short:
/// the deadline and `cancel` are looked at again after it.
impl<B: SocketBind> BoundedKnockSender for SocketKnockSender<B> {
    fn udp_within(
        &mut self,
        to: SocketAddr,
        payload: &[u8],
        deadline: Deadline,
        cancel: &Cancel,
    ) -> Result<(), Stopped> {
        let Ok(socket) = UdpSocket::bind(any_local(to)) else {
            return Ok(());
        };
        self.offer(&socket);
        send_datagram_within(
            &mut Datagram {
                socket: &socket,
                to,
            },
            payload,
            &SystemClock,
            deadline,
            cancel,
        )
    }

    fn tcp_within(
        &mut self,
        to: SocketAddr,
        payload: &[u8],
        deadline: Deadline,
        cancel: &Cancel,
    ) -> Result<(), Stopped> {
        let Ok(socket) = Socket::new(Domain::for_address(to), Type::STREAM, Some(Protocol::TCP))
        else {
            return Ok(());
        };
        self.offer(&socket);
        let to = SockAddr::from(to);
        knock_tcp_within(
            |wait| socket.connect_timeout(&to, wait).map(|()| &socket),
            payload,
            &SystemClock,
            deadline,
            cancel,
        )
    }
}

/// Where a knock's bytes go: a datagram, or the next part of a stream. A seam,
/// so the loops below are tested with partial writes, interruptions and a
/// busy socket without depending on a real one.
trait TimedSend {
    /// Bounds the next [`TimedSend::send`].
    fn set_send_timeout(&mut self, timeout: Duration) -> io::Result<()>;
    fn send(&mut self, data: &[u8]) -> io::Result<usize>;
}

struct Datagram<'a> {
    socket: &'a UdpSocket,
    to: SocketAddr,
}

impl TimedSend for Datagram<'_> {
    fn set_send_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.socket.set_write_timeout(Some(timeout))
    }

    fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        self.socket.send_to(data, self.to)
    }
}

impl TimedSend for &Socket {
    fn set_send_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.set_write_timeout(Some(timeout))
    }

    fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        Socket::send(self, data)
    }
}

/// Worth another try while time is left: the socket was busy or the call
/// was interrupted. Anything else ends the knock's send quietly.
fn busy(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The time the next send may block: a [`SLICE`] at most, so `cancel` is
/// looked at between them, and never past the deadline.
fn next_send(clock: &impl Clock, deadline: Deadline, cancel: &Cancel) -> Result<Duration, Stopped> {
    Ok(deadline.check(clock.now(), cancel)?.min(SLICE))
}

/// Sends one datagram, empty or not, trying again while the socket is busy
/// and time is left. A datagram leaves whole or not at all.
fn send_datagram_within(
    io: &mut impl TimedSend,
    payload: &[u8],
    clock: &impl Clock,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    loop {
        let wait = next_send(clock, deadline, cancel)?;
        if io.set_send_timeout(wait).is_err() {
            return Ok(());
        }
        match io.send(payload) {
            Ok(_) => return Ok(()),
            Err(e) if busy(&e) => {}
            Err(_) => return Ok(()),
        }
    }
}

/// Writes all of `payload` to a connected stream, part by part, while time
/// is left. A peer that takes no more ends it quietly, like any failure.
fn write_stream_within(
    io: &mut impl TimedSend,
    payload: &[u8],
    clock: &impl Clock,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    let mut rest = payload;
    while !rest.is_empty() {
        let wait = next_send(clock, deadline, cancel)?;
        if io.set_send_timeout(wait).is_err() {
            return Ok(());
        }
        match io.send(rest) {
            Ok(0) => return Ok(()),
            Ok(sent) => rest = &rest[sent.min(rest.len())..],
            Err(e) if busy(&e) => {}
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// One TCP knock: one connection attempt of [`TCP_KNOCK_TIMEOUT`] cut at
/// the deadline, then the payload, if any. `connect` gets the time it may
/// take.
fn knock_tcp_within<S: TimedSend>(
    connect: impl FnOnce(Duration) -> io::Result<S>,
    payload: &[u8],
    clock: &impl Clock,
    deadline: Deadline,
    cancel: &Cancel,
) -> Result<(), Stopped> {
    let left = deadline.check(clock.now(), cancel)?;
    // Refused, timed out, reset: the SYN went out, which is the knock.
    let Ok(mut stream) = connect(left.min(TCP_KNOCK_TIMEOUT)) else {
        return Ok(());
    };
    if payload.is_empty() {
        return Ok(());
    }
    write_stream_within(&mut stream, payload, clock, deadline, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn udp_receiver() -> (UdpSocket, SocketAddr) {
        let r = UdpSocket::bind("127.0.0.1:0").unwrap();
        r.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let a = r.local_addr().unwrap();
        (r, a)
    }

    #[test]
    fn udp_delivers_the_payload() {
        let (r, a) = udp_receiver();
        SocketKnockSender::new(NoBind).udp(a, &[9, 8, 7]);
        let mut buf = [0u8; 16];
        let n = r.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[9, 8, 7]);
    }

    #[test]
    fn udp_with_no_payload_sends_an_empty_datagram() {
        let (r, a) = udp_receiver();
        SocketKnockSender::new(NoBind).udp(a, &[]);
        let mut buf = [0u8; 16];
        assert_eq!(r.recv(&mut buf).unwrap(), 0);
    }

    #[test]
    fn tcp_connects_and_writes_the_payload() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).unwrap();
            got
        });
        SocketKnockSender::new(NoBind).tcp(a, &[1, 2, 3, 4]);
        assert_eq!(server.join().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn tcp_to_a_closed_port_is_quiet_and_quick() {
        let a = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let started = Instant::now();
        SocketKnockSender::new(NoBind).tcp(a, b"x");
        assert!(started.elapsed() < TCP_KNOCK_TIMEOUT + Duration::from_millis(500));
    }

    /// Simulated time that the fake I/O below advances.
    #[derive(Clone)]
    struct FakeClock(Rc<Cell<Instant>>);

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
        fn sleep(&mut self, d: Duration) {
            self.0.set(self.0.get() + d);
        }
    }

    /// What one fake send does: take some bytes, or fail with a kind.
    #[derive(Clone, Copy)]
    enum Reply {
        Take(usize),
        Fail(io::ErrorKind),
    }

    /// Scripted I/O: each send answers with the next reply and, when the
    /// socket is busy, uses up the timeout it was given -- what a blocked
    /// send with a send timeout does. Records every timeout and byte taken.
    struct FakeIo {
        clock: FakeClock,
        replies: Vec<Reply>,
        then: Reply,
        timeout: Option<Duration>,
        timeouts: Vec<Duration>,
        taken: Vec<u8>,
        sends: usize,
        cancel_on_send: Option<(usize, Cancel)>,
    }

    impl FakeIo {
        fn new(clock: &FakeClock, replies: &[Reply], then: Reply) -> Self {
            FakeIo {
                clock: clock.clone(),
                replies: replies.iter().rev().copied().collect(),
                then,
                timeout: None,
                timeouts: Vec::new(),
                taken: Vec::new(),
                sends: 0,
                cancel_on_send: None,
            }
        }
    }

    impl TimedSend for FakeIo {
        fn set_send_timeout(&mut self, timeout: Duration) -> io::Result<()> {
            assert!(!timeout.is_zero());
            self.timeout = Some(timeout);
            self.timeouts.push(timeout);
            Ok(())
        }

        fn send(&mut self, data: &[u8]) -> io::Result<usize> {
            self.sends += 1;
            if let Some((at, cancel)) = &self.cancel_on_send {
                if *at == self.sends {
                    cancel.cancel();
                }
            }
            match self.replies.pop().unwrap_or(self.then) {
                Reply::Take(n) => {
                    let n = n.min(data.len());
                    self.taken.extend_from_slice(&data[..n]);
                    Ok(n)
                }
                Reply::Fail(kind) => {
                    if matches!(kind, WouldBlock | TimedOut) {
                        let mut clock = self.clock.clone();
                        clock.sleep(self.timeout.expect("a timeout before every send"));
                    }
                    Err(kind.into())
                }
            }
        }
    }

    fn fake_clock() -> (FakeClock, Instant) {
        let start = Instant::now();
        (FakeClock(Rc::new(Cell::new(start))), start)
    }

    use io::ErrorKind::{ConnectionReset, Interrupted, TimedOut, WouldBlock};

    /// Partial writes, an interruption and a busy socket: every byte still
    /// goes, in order, and no wait is longer than a slice.
    #[test]
    fn a_stream_payload_survives_partial_writes_and_busy_sockets() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
        let replies = [
            Reply::Take(2),
            Reply::Fail(Interrupted),
            Reply::Fail(WouldBlock),
            Reply::Take(1),
            Reply::Fail(TimedOut),
        ];
        let mut io = FakeIo::new(&clock, &replies, Reply::Take(usize::MAX));
        let payload: Vec<u8> = (0..=9).collect();
        write_stream_within(&mut io, &payload, &clock, deadline, &Cancel::new()).unwrap();
        assert_eq!(io.taken, payload);
        assert_eq!(io.sends, 6);
        assert!(io.timeouts.iter().all(|t| *t == SLICE), "{:?}", io.timeouts);
        assert_eq!(clock.now() - start, SLICE * 2, "two busy waits");
    }

    /// A socket that stays busy is given up at the deadline, and its last
    /// wait is cut to the time left.
    #[test]
    fn a_stream_that_stays_busy_stops_at_the_deadline() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_millis(120)).unwrap();
        let mut io = FakeIo::new(&clock, &[Reply::Take(1)], Reply::Fail(WouldBlock));
        let r = write_stream_within(&mut io, b"abc", &clock, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(io.taken, b"a");
        assert_eq!(
            io.timeouts,
            vec![SLICE, SLICE, SLICE, Duration::from_millis(20)]
        );
        assert_eq!(clock.now(), deadline.instant());
    }

    #[test]
    fn a_cancel_while_the_stream_is_busy_stops_the_write() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
        let cancel = Cancel::new();
        let mut io = FakeIo::new(&clock, &[], Reply::Fail(WouldBlock));
        io.cancel_on_send = Some((3, cancel.clone()));
        let r = write_stream_within(&mut io, b"abc", &clock, deadline, &cancel);
        assert_eq!(r, Err(Stopped::Cancelled));
        assert_eq!(io.sends, 3);
    }

    /// A reset or a peer taking nothing more ends the payload quietly: an
    /// ordinary knock failure, not a stop.
    #[test]
    fn a_failed_or_closed_stream_ends_the_payload_quietly() {
        for then in [Reply::Fail(ConnectionReset), Reply::Take(0)] {
            let (clock, start) = fake_clock();
            let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
            let mut io = FakeIo::new(&clock, &[Reply::Take(1)], then);
            write_stream_within(&mut io, b"abc", &clock, deadline, &Cancel::new()).unwrap();
            assert_eq!((io.taken.as_slice(), io.sends), (&b"a"[..], 2));
        }
    }

    /// A busy datagram socket is tried again until the datagram leaves; it
    /// leaves once, whole, and an empty one is sent too.
    #[test]
    fn a_datagram_waits_out_a_busy_socket_and_leaves_once() {
        for payload in [&b"open"[..], b""] {
            let (clock, start) = fake_clock();
            let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
            let replies = [Reply::Fail(WouldBlock), Reply::Fail(Interrupted)];
            let mut io = FakeIo::new(&clock, &replies, Reply::Take(usize::MAX));
            send_datagram_within(&mut io, payload, &clock, deadline, &Cancel::new()).unwrap();
            assert_eq!((io.taken.as_slice(), io.sends), (payload, 3));
        }
    }

    #[test]
    fn a_datagram_socket_that_stays_busy_stops_at_the_deadline() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_millis(70)).unwrap();
        let mut io = FakeIo::new(&clock, &[], Reply::Fail(WouldBlock));
        let r = send_datagram_within(&mut io, b"x", &clock, deadline, &Cancel::new());
        assert_eq!(r, Err(Stopped::Expired));
        assert_eq!(io.timeouts, vec![SLICE, Duration::from_millis(20)]);
        assert!(io.taken.is_empty());
    }

    #[test]
    fn a_failed_datagram_is_not_retried() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
        let mut io = FakeIo::new(&clock, &[], Reply::Fail(ConnectionReset));
        send_datagram_within(&mut io, b"x", &clock, deadline, &Cancel::new()).unwrap();
        assert_eq!(io.sends, 1);
    }

    /// The TCP knock's one connection attempt gets 200 ms, or less when
    /// less is left; then the payload, under the same deadline.
    #[test]
    fn a_tcp_knock_connect_is_cut_to_the_time_left() {
        for (left, expected) in [
            (Duration::from_secs(10), TCP_KNOCK_TIMEOUT),
            (Duration::from_millis(150), Duration::from_millis(150)),
            (Duration::from_nanos(1), Duration::from_nanos(1)),
        ] {
            let (clock, start) = fake_clock();
            let deadline = Deadline::after(start, left).unwrap();
            let mut given = None;
            let r = knock_tcp_within(
                |wait| {
                    given = Some(wait);
                    Err::<FakeIo, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
                },
                b"x",
                &clock,
                deadline,
                &Cancel::new(),
            );
            assert_eq!(r, Ok(()), "a refusal is a knock");
            assert_eq!(given, Some(expected));
        }
    }

    /// A connection that takes the time that was left, or comes with a
    /// cancel, writes nothing: the cancel is looked at first.
    #[test]
    fn a_tcp_knock_writes_nothing_after_an_expiry_or_a_cancel() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_millis(150)).unwrap();
        let io = FakeIo::new(&clock, &[], Reply::Take(usize::MAX));
        let mut late = clock.clone();
        let r = knock_tcp_within(
            |wait| {
                late.sleep(wait);
                Ok(io)
            },
            b"x",
            &clock,
            deadline,
            &Cancel::new(),
        );
        assert_eq!(r, Err(Stopped::Expired));

        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_secs(5)).unwrap();
        let cancel = Cancel::new();
        let r = knock_tcp_within(
            |_| {
                cancel.cancel();
                Ok(FakeIo::new(&clock, &[], Reply::Take(usize::MAX)))
            },
            b"x",
            &clock,
            deadline,
            &cancel,
        );
        assert_eq!(r, Err(Stopped::Cancelled));
    }

    #[test]
    fn an_expired_tcp_knock_does_not_connect() {
        let (clock, start) = fake_clock();
        let deadline = Deadline::after(start, Duration::from_millis(1)).unwrap();
        let mut late = clock.clone();
        late.sleep(Duration::from_millis(1));
        let mut connected = false;
        let r = knock_tcp_within(
            |_| {
                connected = true;
                Ok(FakeIo::new(&clock, &[], Reply::Take(usize::MAX)))
            },
            b"",
            &clock,
            deadline,
            &Cancel::new(),
        );
        assert_eq!((r, connected), (Err(Stopped::Expired), false));
    }

    fn within(budget: Duration) -> Deadline {
        Deadline::after(Instant::now(), budget).unwrap()
    }

    /// Loopback: the bounded sender delivers datagrams, empty ones too, in
    /// the order of the steps.
    #[test]
    fn bounded_udp_knocks_arrive_in_order_on_loopback() {
        let (r, a) = udp_receiver();
        let steps: Vec<_> = [&b"1"[..], b"", b"22", b"333"]
            .iter()
            .map(|p| crate::KnockStep {
                protocol: crate::KnockProtocol::Udp,
                port: a.port(),
                payload: p.to_vec(),
                delay_after_ms: 5,
            })
            .collect();
        crate::run_within(
            a.ip(),
            &steps,
            &mut SocketKnockSender::new(NoBind),
            &mut SystemClock,
            within(Duration::from_secs(5)),
            &Cancel::new(),
        )
        .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        for _ in 0..steps.len() {
            let n = r.recv(&mut buf).unwrap();
            got.push(buf[..n].to_vec());
        }
        assert_eq!(
            got,
            vec![b"1".to_vec(), vec![], b"22".to_vec(), b"333".to_vec()]
        );
    }

    /// A TCP knock receiver on its own thread. It waits at most `wait` for
    /// the connection, so the test can always join it, and then reads what
    /// was written; `None` when nothing dialled.
    fn tcp_receiver(
        wait: Duration,
    ) -> (
        SocketAddr,
        std::thread::JoinHandle<io::Result<Option<Vec<u8>>>>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let a = l.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let end = Instant::now() + wait;
            let mut s = loop {
                match l.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == Interrupted => {}
                    Err(e) if e.kind() == WouldBlock && Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) if e.kind() == WouldBlock => return Ok(None),
                    Err(e) => return Err(e),
                }
            };
            // An accepted socket may keep the listener's nonblocking mode.
            s.set_nonblocking(false)?;
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut got = Vec::new();
            s.read_to_end(&mut got)?;
            Ok(Some(got))
        });
        (a, worker)
    }

    #[test]
    fn a_bounded_tcp_knock_writes_the_payload_on_loopback() {
        let (a, receiver) = tcp_receiver(Duration::from_secs(5));
        let payload: Vec<u8> = (0..=255).cycle().take(64 * 1024).collect();
        let sent = SocketKnockSender::new(NoBind).tcp_within(
            a,
            &payload,
            within(Duration::from_secs(5)),
            &Cancel::new(),
        );
        let got = receiver.join().expect("the receiver panicked");
        assert_eq!(sent, Ok(()));
        assert_eq!(got.unwrap(), Some(payload));
    }

    /// The control for the test above: a stopped TCP knock makes no
    /// connection, and the receiver reports that once its wait is over.
    #[test]
    fn a_stopped_bounded_tcp_knock_makes_no_connection_on_loopback() {
        let cancelled = Cancel::new();
        cancelled.cancel();
        let expired = Deadline::after(Instant::now(), Duration::from_nanos(1)).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        for (deadline, cancel, why) in [
            (
                within(Duration::from_secs(5)),
                &cancelled,
                Stopped::Cancelled,
            ),
            (expired, &Cancel::new(), Stopped::Expired),
        ] {
            let (a, receiver) = tcp_receiver(Duration::from_millis(200));
            let sent = SocketKnockSender::new(NoBind).tcp_within(a, b"t", deadline, cancel);
            let got = receiver.join().expect("the receiver panicked");
            assert_eq!(sent, Err(why));
            assert_eq!(got.unwrap(), None, "a connection was made");
        }
    }

    #[test]
    fn a_bounded_tcp_knock_to_a_closed_port_is_quiet_and_quick() {
        let a = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let started = Instant::now();
        let r = SocketKnockSender::new(NoBind).tcp_within(
            a,
            b"x",
            within(Duration::from_secs(5)),
            &Cancel::new(),
        );
        assert_eq!(r, Ok(()));
        assert!(started.elapsed() < TCP_KNOCK_TIMEOUT + Duration::from_millis(500));
    }

    /// A binder that outlasts the deadline cannot be cut short, but nothing
    /// is sent after it: neither the datagram nor the connection.
    #[test]
    fn nothing_is_sent_after_a_binder_that_outlasts_the_deadline() {
        struct SlowBind(Arc<AtomicU32>);
        impl SocketBind for SlowBind {
            fn bind(&self, _fd: i32) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(80));
                true
            }
        }
        if !cfg!(unix) {
            return;
        }
        let offered = Arc::new(AtomicU32::new(0));
        let mut sender = SocketKnockSender::new(SlowBind(Arc::clone(&offered)));
        let (r, a) = udp_receiver();
        let got = sender.udp_within(a, b"u", within(Duration::from_millis(20)), &Cancel::new());
        assert_eq!(got, Err(Stopped::Expired));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let got = sender.tcp_within(
            l.local_addr().unwrap(),
            b"t",
            within(Duration::from_millis(20)),
            &Cancel::new(),
        );
        assert_eq!(got, Err(Stopped::Expired));
        assert_eq!(offered.load(Ordering::SeqCst), 2);
        r.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 4];
        assert!(r.recv(&mut buf).is_err(), "a datagram went out");
        assert_eq!(
            l.accept().map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::WouldBlock),
            "a connection was made"
        );
    }

    /// Counts the sockets offered to it and refuses every one, the way a
    /// phone with no usable network would.
    struct RefusingBind(Arc<AtomicU32>);
    impl SocketBind for RefusingBind {
        fn bind(&self, _fd: i32) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    #[test]
    fn every_socket_is_offered_to_the_binder_and_a_refusal_does_not_stop_the_knock() {
        let offered = Arc::new(AtomicU32::new(0));
        let mut sender = SocketKnockSender::new(RefusingBind(Arc::clone(&offered)));
        let (r, a) = udp_receiver();
        sender.udp(a, b"u");
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        sender.tcp(closed, b"");
        let mut buf = [0u8; 4];
        assert_eq!(r.recv(&mut buf).unwrap(), 1, "the datagram went out anyway");
        if cfg!(unix) {
            assert_eq!(offered.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn bounded_knocks_offer_every_socket_and_a_refusal_does_not_stop_them() {
        let offered = Arc::new(AtomicU32::new(0));
        let mut sender = SocketKnockSender::new(RefusingBind(Arc::clone(&offered)));
        let (r, a) = udp_receiver();
        let deadline = within(Duration::from_secs(5));
        sender
            .udp_within(a, b"u", deadline, &Cancel::new())
            .unwrap();
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        sender
            .tcp_within(closed, b"", deadline, &Cancel::new())
            .unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(r.recv(&mut buf).unwrap(), 1, "the datagram went out anyway");
        if cfg!(unix) {
            assert_eq!(offered.load(Ordering::SeqCst), 2);
        }
    }
}
