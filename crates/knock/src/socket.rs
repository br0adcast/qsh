//! The real knock: datagrams and connection attempts on fresh sockets, each
//! offered to the platform's network binding first.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::KnockSender;

/// How long a TCP knock waits for the connection. The SYN has left by the
/// time this runs out, and the SYN is all a router watches for.
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

impl<B: SocketBind> KnockSender for SocketKnockSender<B> {
    fn udp(&mut self, to: SocketAddr, payload: &[u8]) {
        let local: SocketAddr = match to {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let Ok(socket) = UdpSocket::bind(local) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{TcpListener, UdpSocket};
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
}
