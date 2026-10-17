//! Asking a server we have never met for its static key.
//!
//! Noise IK needs the responder's key before the first message, so a first
//! connection has to learn it somehow. The answer is unauthenticated by
//! nature -- there is nothing yet to authenticate it with -- which is
//! exactly why the caller shows the fingerprint and asks (see
//! `known_hosts`).

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use transport::auth::AuthError;
use transport::wire::{encode_key_request, parse, parse_key_offer, Frame, Kind};

/// How many discovery requests to send before giving up. This is UDP and it
/// is FIRST CONTACT: nothing above this retransmits, so a single lost
/// datagram would otherwise turn a perfectly live daemon into a full-timeout
/// "did not answer" -- a bad first impression, and one the user cannot tell
/// apart from a wrong address or a closed port. The attempts SHARE `timeout`
/// rather than extending it: the caller's deadline is the caller's.
const DISCOVERY_ATTEMPTS: u32 = 3;

/// Why discovery produced no key, as the client observed it: the server
/// never refuses out loud, so this is all there is to say (the ladder's
/// line on screen is built from it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The client could not set up its own socket.
    Local(String),
    /// Sending the request failed on this machine: the OS said why.
    SendFailed {
        addr: SocketAddr,
        kind: std::io::ErrorKind,
        /// The OS's own words, e.g. `No route to host (os error 65)`.
        text: String,
    },
    /// Nothing came back from `addr` within `waited`.
    Silent { addr: SocketAddr, waited: Duration },
    /// Reading the reply failed.
    ReadFailed {
        addr: SocketAddr,
        kind: std::io::ErrorKind,
        text: String,
    },
    /// `addr` answered with a key offer that does not parse.
    Malformed { addr: SocketAddr },
    /// `addr` answered with something that is not a key offer at all.
    NotAKeyOffer { addr: SocketAddr },
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::Local(why) => write!(f, "{why}"),
            DiscoveryError::SendFailed { addr, text, .. } => {
                write!(f, "sending a discovery request to {addr}: {text}")
            }
            DiscoveryError::Silent { addr, waited } => write!(
                f,
                "{addr} did not answer in {waited:?} -- is a qshd daemon listening on that UDP port?"
            ),
            DiscoveryError::ReadFailed { addr, text, .. } => {
                write!(f, "reading the discovery reply from {addr}: {text}")
            }
            DiscoveryError::Malformed { addr } => write!(f, "{addr} offered a malformed key"),
            DiscoveryError::NotAKeyOffer { addr } => {
                write!(f, "{addr} answered something other than a key offer")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<DiscoveryError> for AuthError {
    fn from(e: DiscoveryError) -> AuthError {
        AuthError::Backend(e.to_string())
    }
}

/// Ask `addr` for its static public key, waiting at most `timeout` in total.
///
/// The same as [`discover`], with the reason flattened into an
/// [`AuthError`] for callers that only show it.
pub fn discover_server_key(addr: SocketAddr, timeout: Duration) -> Result<[u8; 32], AuthError> {
    discover(addr, timeout).map_err(AuthError::from)
}

/// Ask `addr` for its static public key, waiting at most `timeout` in total.
///
/// The request is sent up to [`DISCOVERY_ATTEMPTS`] times, spread evenly
/// across `timeout`, so one lost datagram costs a fraction of the wait
/// instead of all of it. A duplicate request is harmless: the daemon answers
/// each one, and the first well-formed answer ends the wait.
///
/// A UDP reply carries no proof of who sent it, so a datagram that doesn't
/// come from `addr` itself -- a stray packet, a delayed reply to an earlier
/// request on a reused socket, or someone else racing to answer first -- is
/// ignored and the wait continues against what's left of `timeout`. Once a
/// datagram from `addr` itself arrives, its content is final: if it isn't a
/// well-formed key offer, that is reported as an error immediately rather
/// than waited past, since there is nothing to be gained from waiting
/// longer for the one peer that just answered badly.
pub fn discover(addr: SocketAddr, timeout: Duration) -> Result<[u8; 32], DiscoveryError> {
    discover_until(addr, timeout, || false)
}

/// Discovery with cancellation checked before each send and at most every 50 ms while waiting.
/// No worker or socket remains after this function returns.
pub fn discover_until(
    addr: SocketAddr,
    timeout: Duration,
    interrupted: impl Fn() -> bool,
) -> Result<[u8; 32], DiscoveryError> {
    if interrupted() {
        return Err(DiscoveryError::Local("discovery was cancelled".into()));
    }
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("a literal address")
    } else {
        "[::]:0".parse().expect("a literal address")
    };
    let socket = UdpSocket::bind(bind)
        .map_err(|e| DiscoveryError::Local(format!("opening a socket for discovery: {e}")))?;

    // Discovery talks to exactly one peer. Connecting also lets BSD/macOS
    // report ICMP port refusals instead of waiting through the full timeout.
    socket
        .connect(addr)
        .map_err(|e| DiscoveryError::SendFailed {
            addr,
            kind: e.kind(),
            text: e.to_string(),
        })?;

    let started = Instant::now();
    let deadline = started + timeout;
    let mut buf = [0u8; 256];
    // How many requests have gone out, and when the next one is due. The
    // first is due immediately.
    let mut sent: u32 = 0;
    let mut next_send = started;
    loop {
        if interrupted() {
            return Err(DiscoveryError::Local("discovery was cancelled".into()));
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(DiscoveryError::Silent {
                addr,
                waited: timeout,
            });
        }
        if now >= next_send && sent < DISCOVERY_ATTEMPTS {
            socket
                .send(&encode_key_request())
                .map_err(|e| DiscoveryError::SendFailed {
                    addr,
                    kind: e.kind(),
                    text: e.to_string(),
                })?;
            sent += 1;
            // Evenly spaced inside the caller's deadline: attempt `k` of `n`
            // waits until `k/n` of the timeout has passed before the next.
            next_send = started + (timeout * sent) / DISCOVERY_ATTEMPTS;
        }
        // Wait no further than the next attempt is due -- or than the overall
        // deadline, whichever comes first.
        let remaining = next_send
            .min(deadline)
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        if remaining.is_zero() {
            // `set_read_timeout(Some(0))` means "block forever". A zero slice
            // only happens when the next moment of interest is already
            // behind us, and the top of the loop turns that into either the
            // next attempt or the timeout error.
            continue;
        }
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|e| DiscoveryError::Local(format!("setting the discovery timeout: {e}")))?;

        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            // This slice ran out, not necessarily the whole wait: go round
            // and let the loop head decide between retrying and giving up.
            Err(e) if is_timeout(&e) || e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(DiscoveryError::ReadFailed {
                    addr,
                    kind: e.kind(),
                    text: e.to_string(),
                })
            }
        };
        if src != addr {
            // Not the peer we asked -- keep waiting for the real answer.
            continue;
        }
        return match parse(&buf[..n]) {
            Ok(Frame::Handshake {
                kind: Kind::KeyOffer,
                body,
            }) => parse_key_offer(body).ok_or(DiscoveryError::Malformed { addr }),
            _ => Err(DiscoveryError::NotAKeyOffer { addr }),
        };
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn a_closed_port_fails_before_the_discovery_deadline() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        drop(server);
        let started = Instant::now();
        let error = discover(addr, Duration::from_secs(2)).unwrap_err();
        assert!(
            matches!(error, DiscoveryError::ReadFailed { .. }),
            "{error:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cancellation_stops_discovery_before_another_datagram() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            let query = scope.spawn(|| {
                discover_until(address, Duration::from_millis(600), || {
                    cancelled.load(std::sync::atomic::Ordering::SeqCst)
                })
            });
            let mut request = [0; 256];
            server.recv_from(&mut request).unwrap();
            let start = Instant::now();
            cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                matches!(query.join().unwrap(), Err(DiscoveryError::Local(message)) if message == "discovery was cancelled")
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            server
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            assert!(server.recv_from(&mut request).is_err());
        });
    }

    /// A stand-in daemon: answers one padded request with a key offer.
    #[test]
    fn discovery_returns_the_key_the_server_offers() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let (n, src) = server.recv_from(&mut buf).expect("recv");
            assert!(n >= transport::wire::KEY_REQUEST_MIN_LEN);
            let reply = transport::wire::encode_handshake(
                transport::wire::Kind::KeyOffer,
                &transport::wire::encode_key_offer_body(&[21u8; 32]),
            );
            server.send_to(&reply, src).expect("send");
        });

        let key = discover_server_key(addr, Duration::from_secs(2)).expect("discovery");
        assert_eq!(key, [21u8; 32]);
        handle.join().expect("server thread");
    }

    /// A LOST first request must not cost the whole wait: the daemon here
    /// answers only the second one, and discovery still succeeds well inside
    /// the caller's timeout. Without the retry there would never BE a second
    /// request, and a live daemon would look dead.
    #[test]
    fn a_lost_first_request_is_retried() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        // Bounded, so a missing retry fails this test rather than hanging it.
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            // The datagram the network ate: received, deliberately unanswered.
            server.recv_from(&mut buf).expect("the first request");
            let (_, src) = server
                .recv_from(&mut buf)
                .expect("a retried request must arrive");
            let reply = transport::wire::encode_handshake(
                transport::wire::Kind::KeyOffer,
                &transport::wire::encode_key_offer_body(&[21u8; 32]),
            );
            server.send_to(&reply, src).expect("send");
        });

        let key = discover_server_key(addr, Duration::from_secs(2)).expect("discovery");
        assert_eq!(key, [21u8; 32]);
        handle.join().expect("server thread");
    }

    /// A server that answers nothing still fails within the caller's
    /// deadline: the retries share `timeout`, they do not extend it.
    #[test]
    fn a_silent_server_times_out() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let started = Instant::now();
        assert!(matches!(
            discover_server_key(addr, Duration::from_millis(200)),
            Err(AuthError::Backend(_))
        ));
        // The bound has to be tighter than `DISCOVERY_ATTEMPTS * timeout`, or
        // it would pass just as happily if each attempt got its own full
        // deadline -- which is the regression this assertion exists to catch.
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the three attempts must share the caller's timeout, not each get one"
        );
    }

    /// An off-path or racing sender who is not the address we asked must
    /// never be able to answer in the real server's place, no matter how
    /// fast it replies.
    #[test]
    fn a_reply_from_an_unexpected_address_is_ignored() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let addr = server.local_addr().expect("addr");
        let impostor = UdpSocket::bind("127.0.0.1:0").expect("bind impostor");

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let (_, src) = server.recv_from(&mut buf).expect("recv");

            // The decoy is sent first, and given a head start, so a
            // first-datagram-wins bug would pick it over the real answer.
            let decoy = transport::wire::encode_handshake(
                transport::wire::Kind::KeyOffer,
                &transport::wire::encode_key_offer_body(&[0xEEu8; 32]),
            );
            impostor.send_to(&decoy, src).expect("send decoy");
            std::thread::sleep(Duration::from_millis(50));

            let reply = transport::wire::encode_handshake(
                transport::wire::Kind::KeyOffer,
                &transport::wire::encode_key_offer_body(&[21u8; 32]),
            );
            server.send_to(&reply, src).expect("send real reply");
        });

        let key = discover_server_key(addr, Duration::from_secs(2)).expect("discovery");
        assert_eq!(
            key, [21u8; 32],
            "a reply from the wrong address must not be accepted"
        );
        handle.join().expect("server thread");
    }

    /// The real server answering with something that isn't a key offer at
    /// all is reported as an error, not silently ignored.
    #[test]
    fn garbage_from_the_right_address_is_reported_as_an_error() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let (_, src) = server.recv_from(&mut buf).expect("recv");
            // Version byte plus an unknown kind byte: parses as neither a
            // handshake nor a transport frame.
            server
                .send_to(&[transport::wire::VERSION, 0x7F], src)
                .expect("send garbage");
        });

        assert!(matches!(
            discover_server_key(addr, Duration::from_secs(2)),
            Err(AuthError::Backend(_))
        ));
        handle.join().expect("server thread");
    }

    /// A `KeyOffer` whose body is too short to hold a 32-byte key is
    /// reported as an error, not truncated into a shorter "key".
    #[test]
    fn a_truncated_key_offer_is_reported_as_an_error() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let (_, src) = server.recv_from(&mut buf).expect("recv");
            let short = transport::wire::encode_handshake(
                transport::wire::Kind::KeyOffer,
                &[transport::wire::VERSION, 1, 2],
            );
            server.send_to(&short, src).expect("send truncated offer");
        });

        assert!(matches!(
            discover_server_key(addr, Duration::from_secs(2)),
            Err(AuthError::Backend(_))
        ));
        handle.join().expect("server thread");
    }

    /// The client keeps what it observed, so the line on screen can say it:
    /// a silent address is silence, for as long as it was waited on.
    #[test]
    fn silence_is_told_apart_and_says_how_long_it_waited() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let waited = Duration::from_millis(150);
        let err = discover(addr, waited).expect_err("nobody answers");
        assert_eq!(err, DiscoveryError::Silent { addr, waited });
        assert!(
            err.to_string()
                .starts_with(&format!("{addr} did not answer in 150ms")),
            "the flattened text is unchanged: {err}"
        );
    }

    /// Something that answers, but not with a key offer, is not silence.
    #[test]
    fn an_answer_that_is_not_a_key_offer_is_told_apart() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = server.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let (_, src) = server.recv_from(&mut buf).expect("recv");
            server
                .send_to(&[transport::wire::VERSION, 0x7F], src)
                .expect("send garbage");
        });
        assert_eq!(
            discover(addr, Duration::from_secs(2)),
            Err(DiscoveryError::NotAKeyOffer { addr })
        );
        handle.join().expect("server thread");
    }

    /// A send the OS refuses is reported with the OS's own words, at once:
    /// a broadcast address without `SO_BROADCAST` is refused on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_send_the_os_refuses_is_reported_with_its_words() {
        let addr: SocketAddr = "255.255.255.255:9".parse().expect("addr");
        let started = Instant::now();
        let err = discover(addr, Duration::from_secs(5)).expect_err("the send fails");
        assert_eq!(
            err,
            DiscoveryError::SendFailed {
                addr,
                kind: std::io::ErrorKind::PermissionDenied,
                text: "Permission denied (os error 13)".into(),
            }
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a failed send is not waited out"
        );
    }
}
