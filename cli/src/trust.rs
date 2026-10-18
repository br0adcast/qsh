//! Which server key to trust.
//!
//! Discovery is unauthenticated by construction -- that is what trust on
//! first use means, and it is why the fingerprint is shown to a human. The
//! logic of that decision is kept apart from the acts of asking and of
//! reaching a socket, so all of it is under test: those two read a terminal
//! and a network, and a test cannot.
//!
//! Discovery does NOT run once a key is pinned: it answers anyone who asks,
//! and doing it on every launch would announce to a bystander that qsh lives
//! here. There is exactly one exception, and it is on a failure path the
//! user is about to be told about anyway -- a connection made with a pinned
//! key that never got anywhere. A server whose static key has changed cannot
//! complete a Noise IK handshake against the old one, and the transport
//! reports that as silence, which is also what a stopped daemon looks like.
//! [`after_silence`] asks once, then, so the two are told apart:
//! a changed key must produce a loud, explicit refusal naming both
//! fingerprints, not get swallowed into the generic "unreachable" message.
//!
//! Every address on one command line is a road to one daemon, so they share
//! one key (spec §4a): an address with nothing pinned is tried with the key
//! pinned for a neighbour on the line, and [`after_neighbour_silence`] is
//! the same one question on the same kind of failure path -- that handshake
//! never got anywhere. A key is pinned without asking only when a completed
//! handshake proved the server holds it ([`remember_proven`]); what a key
//! request offers proves nothing, and is never pinned that way.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sshauth::discover::DiscoveryError;
use sshauth::known_hosts::{key_fingerprint, HostVerdict, KnownHosts};

/// How long to wait for a `KeyOffer` before giving up on discovery.
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Asks the user a yes/no question. Separate from the decision so the
/// decision can be tested; the real one reads the terminal.
pub trait Confirm {
    fn ask(&self, prompt: &str) -> bool;
}

/// Asks a server for its static key. Separate from the decision for the same
/// reason as [`Confirm`]: the real one reaches a socket, and a test must not
/// depend on one being there.
pub trait Discover {
    fn key(&self, addr: SocketAddr) -> Result<[u8; 32], DiscoveryError>;

    /// Foreground cancellation; existing injected sources may keep their synchronous behavior.
    fn key_until(
        &self,
        addr: SocketAddr,
        _interrupted: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], DiscoveryError> {
        self.key(addr)
    }
}

/// The real thing: one unauthenticated `KeyRequest`/`KeyOffer` exchange.
pub struct UdpDiscovery;

impl Discover for UdpDiscovery {
    fn key(&self, addr: SocketAddr) -> Result<[u8; 32], DiscoveryError> {
        sshauth::discover::discover(addr, DISCOVERY_TIMEOUT)
    }

    fn key_until(
        &self,
        addr: SocketAddr,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], DiscoveryError> {
        sshauth::discover::discover_until(addr, DISCOVERY_TIMEOUT, interrupted)
    }
}

/// Only initial login observes process termination; recovery retains its own lifetime.
pub struct ForegroundDiscovery<'a>(pub &'a dyn Discover);
impl Discover for ForegroundDiscovery<'_> {
    fn key(&self, addr: SocketAddr) -> Result<[u8; 32], DiscoveryError> {
        self.0
            .key_until(addr, &crate::signals::termination_requested)
    }
}

type KeyResult = Result<[u8; 32], DiscoveryError>;

struct PendingDiscovery {
    addr: SocketAddr,
    result: std::sync::mpsc::Receiver<KeyResult>,
    cancel: knock::Cancel,
}
impl Drop for PendingDiscovery {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// One diagnostic slot per configured address, so DNS/port changes cannot
/// accumulate completed results. Queries keep the normal discovery budget.
#[derive(Default)]
pub struct BackgroundDiscovery(std::sync::Mutex<Option<PendingDiscovery>>);
impl BackgroundDiscovery {
    pub fn invalidate(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Nonblocking adapter used only after a recovery handshake got no answer.
/// The driver of the next handshake can run while this query is pending.
pub struct RecoveryDiscovery<'a> {
    pub pending: &'a BackgroundDiscovery,
    pub source: std::sync::Arc<dyn Discover + Send + Sync>,
}

impl Discover for RecoveryDiscovery<'_> {
    fn key(&self, addr: SocketAddr) -> KeyResult {
        use std::sync::mpsc::{channel, TryRecvError};
        let mut pending = self.pending.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(query) = pending.as_ref().filter(|p| p.addr == addr) {
            match query.result.try_recv() {
                Ok(result) => {
                    *pending = None;
                    return result;
                }
                Err(TryRecvError::Disconnected) => {
                    *pending = None;
                    return Err(DiscoveryError::Local(
                        "key diagnostic ended without an answer".into(),
                    ));
                }
                Err(TryRecvError::Empty) => {}
            }
        } else {
            let (tx, result) = channel();
            let source = self.source.clone();
            let cancel = knock::Cancel::new();
            let worker_cancel = cancel.clone();
            std::thread::Builder::new()
                .name("qsh-key-diagnostic".into())
                .spawn(move || {
                    let result = source.key_until(addr, &|| worker_cancel.is_cancelled());
                    if !worker_cancel.is_cancelled() {
                        let _ = tx.send(result);
                    }
                })
                .map_err(|e| DiscoveryError::Local(e.to_string()))?;
            *pending = Some(PendingDiscovery {
                addr,
                result,
                cancel,
            });
        }
        // No key has arrived yet. The already-failed handshake determines
        // the user-facing timeout; a diagnostic never extends that timeout.
        Err(DiscoveryError::Silent {
            addr,
            waited: Duration::ZERO,
        })
    }
}

/// A [`Confirm`] that always says yes, without asking anyone.
pub struct AlwaysYes;

impl Confirm for AlwaysYes {
    fn ask(&self, _prompt: &str) -> bool {
        true
    }
}

/// A [`Confirm`] that always says no, without asking anyone.
pub struct AlwaysNo;

impl Confirm for AlwaysNo {
    fn ask(&self, _prompt: &str) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum TrustError {
    /// Discovery did not produce a usable key: the request could not be
    /// sent, the daemon stayed silent, or something answered that isn't a
    /// valid key offer (a version mismatch, or something else entirely on
    /// that port). `reason` is what `sshauth::discover` observed, so the
    /// line on screen tells these apart instead of collapsing them into one
    /// message that always blames a daemon that may well be running.
    NoAnswer {
        host: String,
        port: u16,
        reason: DiscoveryError,
    },
    /// A key is pinned for this host and it is not this one.
    KeyChanged {
        host: String,
        port: u16,
        pinned: [u8; 32],
        offered: [u8; 32],
        store: PathBuf,
    },
    /// The user said no.
    Refused,
    /// The known-hosts file could not be read or written.
    Store(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::NoAnswer { host, port, reason } => write!(
                f,
                "could not get the server's key for {host}:{port}: {reason}"
            ),
            TrustError::KeyChanged {
                host,
                port,
                pinned,
                offered,
                store,
            } => write!(
                f,
                "the server key for {host}:{port} has changed!\n  \
                 was: {}\n  now: {}\n\
                 If the server was reinstalled, or switched between qshd's personal and \
                 system mode (each keeps its own separate host key, so switching between \
                 them changes the fingerprint -- see docs/qshd-service.md), remove the \
                 line for {host} from \"{}\" and reconnect. If neither \
                 happened, someone is between you and the server.",
                key_fingerprint(pinned),
                key_fingerprint(offered),
                store.display()
            ),
            TrustError::Refused => write!(f, "server key not confirmed -- connection canceled"),
            TrustError::Store(why) => write!(f, "known-hosts file unavailable: {why}"),
        }
    }
}

impl std::error::Error for TrustError {}

/// Where the key handed to the handshake came from. Only a key that came
/// from the store leaves "the daemon never answered" with a second possible
/// explanation -- see [`after_silence`] and [`after_neighbour_silence`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeySource {
    /// Read from `known_hosts`; no discovery happened this run.
    Pinned,
    /// Learned by discovery, shown to the user, and pinned just now.
    Discovered,
    /// Nothing is pinned for this address, and this is the key pinned for
    /// another address of the same command line -- `of`, as `host:port`.
    /// Every address on one command line is a road to one daemon (spec §4a),
    /// so no key request is needed: a Noise IK handshake completes only
    /// against the holder of this key's private half, and that completion
    /// is the proof [`remember_proven`] pins it on.
    Neighbour { of: String },
}

/// The key to connect with, and where it came from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerKey {
    pub key: [u8; 32],
    pub source: KeySource,
}

/// `host:port`, the way the lines about one address and its neighbours
/// name it.
pub fn label(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Every recovery endpoint must prove the key of the existing session,
/// including a port just reported by SSH. A conflicting stored pin is a
/// refusal; a new endpoint is remembered only after the Noise handshake.
pub fn recovery_server_key(
    host: &str,
    port: u16,
    key: [u8; 32],
    hosts: &KnownHosts,
) -> Result<ServerKey, TrustError> {
    let source = match hosts
        .check(host, port, &key)
        .map_err(|e| TrustError::Store(e.to_string()))?
    {
        HostVerdict::Known => KeySource::Pinned,
        HostVerdict::Unknown => KeySource::Neighbour {
            of: "the current session".into(),
        },
        HostVerdict::Changed { pinned } => {
            return Err(TrustError::KeyChanged {
                host: host.into(),
                port,
                pinned: key,
                offered: pinned,
                store: hosts.path().to_owned(),
            })
        }
    };
    Ok(ServerKey { key, source })
}

/// The server's static key: from the store if it is pinned; otherwise the
/// key pinned for one of the `neighbours` -- the other addresses of the
/// command line, as `(host, port)` -- if any is (spec §4a rule 2);
/// otherwise by discovery, confirmed by the user and pinned.
///
/// A neighbour's key needs no question, so it serves a background round
/// as well as a login.
pub fn server_key(
    host: &str,
    port: u16,
    addr: SocketAddr,
    hosts: &KnownHosts,
    neighbours: &[(String, u16)],
    ask: &dyn Confirm,
    discover: &dyn Discover,
) -> Result<ServerKey, TrustError> {
    // The store is consulted FIRST. A pinned host needs no discovery, and
    // discovery answers anyone who asks -- running it on every launch would
    // announce to a bystander that qsh lives here.
    if let Some(pinned) = pinned_key(host, port, hosts)? {
        return Ok(ServerKey {
            key: pinned,
            source: KeySource::Pinned,
        });
    }
    // For the same reason a neighbour's key comes before discovery: it
    // costs nothing that could announce anyone.
    if let Some((of, key)) = neighbour_key(host, port, neighbours, hosts)? {
        return Ok(ServerKey {
            key,
            source: KeySource::Neighbour { of },
        });
    }
    let discovered = discover.key(addr);
    let key = server_key_with_discovered(host, port, hosts, ask, discovered)?;
    Ok(ServerKey {
        key,
        source: KeySource::Discovered,
    })
}

/// What one more key request says about a connection made with a pinned
/// key that never got anywhere.
#[derive(Debug)]
pub enum AfterSilence {
    /// The server offers another key: that is the explanation, loudly.
    Changed(TrustError),
    /// The server offers the very key on file: it answers the key request
    /// and not the login.
    SameKey,
    /// The key request got nowhere either; what discovery observed.
    NoKey(DiscoveryError),
}

/// What a changed server key -- or the lack of one -- says about a
/// connection that never got anywhere.
///
/// Called ONLY after an attempt made with a [`KeySource::Pinned`] key has
/// already concluded "unreachable": that is the single moment where the one
/// unauthenticated exchange is worth its privacy cost, because the attempt
/// has already failed and the user is about to be given a reason for it. A
/// key discovered on THIS run needs no second look -- the server named it
/// minutes ago.
pub fn after_silence(
    host: &str,
    port: u16,
    addr: SocketAddr,
    pinned: [u8; 32],
    discover: &dyn Discover,
    hosts: &KnownHosts,
) -> AfterSilence {
    after_silence_verdict(host, port, pinned, discover.key(addr), hosts)
}

/// The decision itself -- the pinned key against whatever discovery produced
/// -- with the socket already dealt with, so all of it is testable.
fn after_silence_verdict(
    host: &str,
    port: u16,
    pinned: [u8; 32],
    discovered: Result<[u8; 32], DiscoveryError>,
    hosts: &KnownHosts,
) -> AfterSilence {
    match discovered {
        Ok(offered) if offered != pinned => AfterSilence::Changed(TrustError::KeyChanged {
            host: host.to_string(),
            port,
            pinned,
            offered,
            store: hosts.path().to_owned(),
        }),
        Ok(_) => AfterSilence::SameKey,
        Err(e) => AfterSilence::NoKey(e),
    }
}

/// The first of `neighbours`, in command-line order, with a key pinned --
/// `host:port` itself left out, whichever index it has -- as its label and
/// that key.
fn neighbour_key(
    host: &str,
    port: u16,
    neighbours: &[(String, u16)],
    hosts: &KnownHosts,
) -> Result<Option<(String, [u8; 32])>, TrustError> {
    for (h, p) in neighbours {
        if h == host && *p == port {
            continue;
        }
        if let Some(key) = pinned_key(h, *p, hosts)? {
            return Ok(Some((label(h, *p), key)));
        }
    }
    Ok(None)
}

/// Two addresses of one command line with different keys pinned (spec §4a
/// rule 1): the first pinned address, and the first after it whose key
/// differs -- each as its label and its key.
#[derive(Debug, PartialEq, Eq)]
pub struct Disagreement {
    pub first: (String, [u8; 32]),
    pub second: (String, [u8; 32]),
}

/// Whether the keys pinned for `addrs` (the command line's, as `(host,
/// port)`) disagree. Read before the first attempt: addresses that are not
/// one server cannot be roads to one session, and nothing tried at either
/// would make that right.
pub fn pins_disagree(
    addrs: &[(String, u16)],
    hosts: &KnownHosts,
) -> Result<Option<Disagreement>, TrustError> {
    let mut first: Option<(String, [u8; 32])> = None;
    for (host, port) in addrs {
        let Some(key) = pinned_key(host, *port, hosts)? else {
            continue;
        };
        match &first {
            None => first = Some((label(host, *port), key)),
            Some((_, seen)) if *seen == key => {}
            Some(_) => {
                return Ok(first.map(|first| Disagreement {
                    first,
                    second: (label(host, *port), key),
                }))
            }
        }
    }
    Ok(None)
}

/// What one more key request says about a handshake made with a
/// neighbour's key that never got anywhere (spec §4a rule 3).
#[derive(Debug, PartialEq, Eq)]
pub enum NeighbourSilence {
    /// This address offers another key: it is not the neighbour's server.
    OtherServer { offered: [u8; 32] },
    /// It offers the neighbour's very key: the silence has another cause.
    SameKey,
    /// The key request got nowhere either; what discovery observed.
    NoKey(DiscoveryError),
}

/// Asks the address the handshake with `neighbour_key` got nothing from
/// for its key, once -- the same one exchange, on the same failure path, as
/// [`after_silence`].
pub fn after_neighbour_silence(
    addr: SocketAddr,
    neighbour_key: [u8; 32],
    discover: &dyn Discover,
) -> NeighbourSilence {
    match discover.key(addr) {
        Ok(offered) if offered != neighbour_key => NeighbourSilence::OtherServer { offered },
        Ok(_) => NeighbourSilence::SameKey,
        Err(e) => NeighbourSilence::NoKey(e),
    }
}

/// What pinning a key a handshake proved did to the store.
#[derive(Debug, PartialEq, Eq)]
pub enum Proven {
    /// Nothing was pinned for the address: the key is now.
    Remembered,
    /// This very key was already pinned there.
    AlreadyKnown,
    /// Another key is pinned there, and it is left alone: a line a person
    /// must look at is not replaced behind their back. The next run through
    /// that address gets the ordinary changed-key refusal.
    Stale { pinned: [u8; 32] },
}

/// Pins `key` for `host:port` without asking anyone -- for a key a
/// completed handshake proved the server there holds (spec §4a rules 2 and
/// 4), never for one a key request merely offered. A key already pinned is
/// never replaced.
pub fn remember_proven(
    host: &str,
    port: u16,
    key: &[u8; 32],
    hosts: &KnownHosts,
) -> Result<Proven, TrustError> {
    match hosts
        .pin_if_absent(host, port, key)
        .map_err(|e| TrustError::Store(e.to_string()))?
    {
        HostVerdict::Unknown => Ok(Proven::Remembered),
        HostVerdict::Known => Ok(Proven::AlreadyKnown),
        HostVerdict::Changed { pinned } => Ok(Proven::Stale { pinned }),
    }
}

/// The already-pinned key for `host:port`, if any. `None` means the store
/// has never seen this host before -- discovery is still needed.
fn pinned_key(host: &str, port: u16, hosts: &KnownHosts) -> Result<Option<[u8; 32]>, TrustError> {
    // A throwaway key: `check` only compares against what is on file, and an
    // `Unknown`/`Changed` verdict here does not depend on which key was
    // asked about, only on whether one is pinned at all.
    match hosts
        .check(host, port, &[0u8; 32])
        .map_err(|e| TrustError::Store(e.to_string()))?
    {
        HostVerdict::Known => Ok(Some([0u8; 32])),
        HostVerdict::Changed { pinned } => Ok(Some(pinned)),
        HostVerdict::Unknown => Ok(None),
    }
}

/// The decision, with discovery already done (or already failed). Split out
/// so the whole of it is testable without a socket.
fn server_key_with_discovered(
    host: &str,
    port: u16,
    hosts: &KnownHosts,
    ask: &dyn Confirm,
    discovered: Result<[u8; 32], DiscoveryError>,
) -> Result<[u8; 32], TrustError> {
    let offered = discovered.map_err(|reason| TrustError::NoAnswer {
        host: host.to_string(),
        port,
        reason,
    })?;

    match hosts
        .check(host, port, &offered)
        .map_err(|e| TrustError::Store(e.to_string()))?
    {
        HostVerdict::Known => Ok(offered),
        // Not reachable through `server_key`, which returns a pinned key
        // before discovery is ever run -- kept because the store is re-read
        // from disk here, so another process pinning this host in between
        // would land exactly on this arm, and because it is the arm that
        // makes this function correct for any caller, not just that one.
        HostVerdict::Changed { pinned } => Err(TrustError::KeyChanged {
            host: host.to_string(),
            port,
            pinned,
            offered,
            store: hosts.path().to_owned(),
        }),
        HostVerdict::Unknown => {
            let prompt = format!(
                "First time seeing server {host}:{port}.\n  Key fingerprint: {}\n\
                 Compare it with the fingerprint `qshd serve` prints at startup \
                 (a qshd started over ssh prints none: accepting it is trust on first use).\n\
                 Continue and remember this key?",
                key_fingerprint(&offered)
            );
            if !ask.ask(&prompt) {
                return Err(TrustError::Refused);
            }
            // The prompt may outlive another process's first connection.
            // Recheck and pin under the store's lock; consent to this offer
            // must never replace a different key accepted in the meantime.
            match hosts
                .pin_if_absent(host, port, &offered)
                .map_err(|e| TrustError::Store(e.to_string()))?
            {
                HostVerdict::Unknown | HostVerdict::Known => Ok(offered),
                HostVerdict::Changed { pinned } => Err(TrustError::KeyChanged {
                    host: host.to_string(),
                    port,
                    pinned,
                    offered,
                    store: hosts.path().to_owned(),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        answer: bool,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl Confirm for Recorder {
        fn ask(&self, prompt: &str) -> bool {
            self.asked.lock().expect("asked").push(prompt.to_string());
            self.answer
        }
    }

    fn recorder(answer: bool) -> Recorder {
        Recorder {
            answer,
            asked: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn hosts(dir: &std::path::Path) -> KnownHosts {
        KnownHosts::open(dir.join("known_hosts"))
    }

    struct PinDuringPrompt {
        path: std::path::PathBuf,
        key: [u8; 32],
        answer: bool,
    }

    impl Confirm for PinDuringPrompt {
        fn ask(&self, _: &str) -> bool {
            // A separate store writes after discovery but before the answer,
            // just as another process can while the user reads the prompt.
            KnownHosts::open(self.path.clone())
                .pin("example.org", 60022, &self.key)
                .unwrap();
            self.answer
        }
    }

    #[test]
    fn accepting_a_prompt_does_not_replace_a_concurrently_pinned_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = hosts(dir.path());
        let ask = PinDuringPrompt {
            path: store.path().to_owned(),
            key: [2; 32],
            answer: true,
        };
        let result = server_key_with_discovered("example.org", 60022, &store, &ask, Ok([1; 32]));
        assert!(matches!(
            result,
            Err(TrustError::KeyChanged { host, port: 60022, pinned, offered, store: path })
                if host == "example.org" && pinned == [2; 32] && offered == [1; 32]
                    && path == store.path()
        ));
        assert_eq!(
            store.check("example.org", 60022, &[2; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    #[test]
    fn a_prompt_accepts_the_same_concurrent_pin_and_preserves_it_on_refusal() {
        for answer in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = hosts(dir.path());
            let ask = PinDuringPrompt {
                path: store.path().to_owned(),
                key: [1; 32],
                answer,
            };
            let result =
                server_key_with_discovered("example.org", 60022, &store, &ask, Ok([1; 32]));
            if answer {
                assert_eq!(result.unwrap(), [1; 32]);
            } else {
                assert!(matches!(result, Err(TrustError::Refused)));
            }
            assert_eq!(
                store.check("example.org", 60022, &[1; 32]).unwrap(),
                HostVerdict::Known
            );
        }
    }

    #[test]
    fn a_slow_key_diagnostic_does_not_block_udp_recovery() {
        struct Slow;
        impl Discover for Slow {
            fn key(&self, _: SocketAddr) -> Result<[u8; 32], DiscoveryError> {
                std::thread::sleep(Duration::from_millis(700));
                Ok([3; 32])
            }
        }
        let pending = BackgroundDiscovery::default();
        let diagnostic = RecoveryDiscovery {
            pending: &pending,
            source: std::sync::Arc::new(Slow),
        };
        let started = std::time::Instant::now();
        let _ = diagnostic.key("127.0.0.1:60000".parse().unwrap());
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a diagnostic must run alongside UDP, not hold the next handshake"
        );
        let deadline = started + Duration::from_secs(3);
        loop {
            if diagnostic.key("127.0.0.1:60000".parse().unwrap()) == Ok([3; 32]) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the late key must still be returned"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn recovery_uses_the_session_key_at_a_new_port_without_pinning_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = hosts(dir.path());
        let server = recovery_server_key("host", 60001, [1; 32], &store).unwrap();
        assert_eq!(server.key, [1; 32]);
        assert!(matches!(server.source, KeySource::Neighbour { .. }));
        assert_eq!(
            store.check("host", 60001, &[1; 32]).unwrap(),
            HostVerdict::Unknown
        );
    }

    #[test]
    fn recovery_never_replaces_a_pin_conflicting_with_the_session_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = hosts(dir.path());
        store.pin("host", 60001, &[2; 32]).unwrap();
        assert!(matches!(
            recovery_server_key("host", 60001, [1; 32], &store),
            Err(TrustError::KeyChanged {
                pinned: [1, ..],
                offered: [2, ..],
                ..
            })
        ));
        assert_eq!(
            store.check("host", 60001, &[2; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    /// A [`Discover`] that answers from memory and counts how often it was
    /// reached. The count is the point: "a pinned host does not run
    /// discovery" and "the failure path runs it exactly once" are both
    /// claims about how many times this was called, and an address that
    /// answers nothing cannot prove either -- it only proves the test was
    /// slow.
    struct FakeDiscovery {
        /// `None` stands for a discovery that produced nothing, the way a
        /// silent daemon or a closed port does.
        answer: Option<[u8; 32]>,
        calls: std::sync::Mutex<u32>,
    }

    impl FakeDiscovery {
        fn answering(key: [u8; 32]) -> FakeDiscovery {
            FakeDiscovery {
                answer: Some(key),
                calls: std::sync::Mutex::new(0),
            }
        }

        fn silent() -> FakeDiscovery {
            FakeDiscovery {
                answer: None,
                calls: std::sync::Mutex::new(0),
            }
        }

        fn calls(&self) -> u32 {
            *self.calls.lock().expect("calls")
        }
    }

    impl Discover for FakeDiscovery {
        fn key(&self, _addr: SocketAddr) -> Result<[u8; 32], DiscoveryError> {
            *self.calls.lock().expect("calls") += 1;
            match self.answer {
                Some(key) => Ok(key),
                None => Err(DiscoveryError::Silent {
                    addr: any_addr(),
                    waited: DISCOVERY_TIMEOUT,
                }),
            }
        }
    }

    fn any_addr() -> SocketAddr {
        "127.0.0.1:9".parse().expect("addr")
    }

    /// A pinned key is used as it stands, and -- the point of pinning -- the
    /// unauthenticated discovery exchange does not happen at all.
    #[test]
    fn a_pinned_key_is_used_without_asking_anyone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        store.pin("example.org", 60022, &[7u8; 32]).expect("pin");
        let ask = recorder(false);
        let discovery = FakeDiscovery::answering([9u8; 32]);

        let found = server_key(
            "example.org",
            60022,
            any_addr(),
            &store,
            &[],
            &ask,
            &discovery,
        )
        .expect("a pinned key needs nothing else");

        assert_eq!(found.key, [7u8; 32]);
        assert_eq!(found.source, KeySource::Pinned);
        assert!(
            ask.asked.lock().expect("asked").is_empty(),
            "nothing to ask"
        );
        assert_eq!(
            discovery.calls(),
            0,
            "a pinned host must not be announced to whoever is listening"
        );
    }

    /// The whole PUBLIC path, twice over: first contact discovers the key,
    /// shows it and pins it; the run after that reads it back out of the
    /// store and goes nowhere near the network.
    ///
    /// Every other test in this file drives the private half
    /// (`server_key_with_discovered`), so a `server_key` that pinned nothing,
    /// or one that consulted the store and then discovered anyway, passed all
    /// of them. This is the round trip that pins the seam between the two.
    #[test]
    fn a_first_contact_is_pinned_and_the_next_run_asks_nobody() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(true);
        let discovery = FakeDiscovery::answering([3u8; 32]);

        let first = server_key(
            "example.org",
            60022,
            any_addr(),
            &store,
            &[],
            &ask,
            &discovery,
        )
        .expect("an approved key is accepted");
        assert_eq!(first.key, [3u8; 32]);
        assert_eq!(first.source, KeySource::Discovered);
        assert_eq!(discovery.calls(), 1, "first contact discovers, once");
        assert_eq!(ask.asked.lock().expect("asked").len(), 1);

        let second = server_key(
            "example.org",
            60022,
            any_addr(),
            &store,
            &[],
            &ask,
            &discovery,
        )
        .expect("the pinned key is enough");
        assert_eq!(second.key, [3u8; 32]);
        assert_eq!(second.source, KeySource::Pinned);
        assert_eq!(
            discovery.calls(),
            1,
            "the second run must read the store, not the network"
        );
        assert_eq!(
            ask.asked.lock().expect("asked").len(),
            1,
            "and it must not ask the user a second time"
        );
    }

    fn neighbours(list: &[(&str, u16)]) -> Vec<(String, u16)> {
        list.iter().map(|(h, p)| (h.to_string(), *p)).collect()
    }

    /// Spec §4a rule 2: an address with nothing pinned, next to one with a
    /// key, takes that key as it stands -- no key request, no question, so
    /// a background round can do it too.
    #[test]
    fn an_unpinned_address_takes_its_neighbour_s_key_without_asking_anyone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        store.pin("127.0.0.1", 60022, &[7u8; 32]).expect("pin");
        let ask = recorder(true);
        let discovery = FakeDiscovery::answering([9u8; 32]);

        let found = server_key(
            "127.0.0.2",
            60022,
            any_addr(),
            &store,
            &neighbours(&[("127.0.0.2", 60022), ("127.0.0.1", 60022)]),
            &ask,
            &discovery,
        )
        .expect("a neighbour's key needs nothing else");

        assert_eq!(found.key, [7u8; 32]);
        assert_eq!(
            found.source,
            KeySource::Neighbour {
                of: "127.0.0.1:60022".into()
            }
        );
        assert_eq!(discovery.calls(), 0, "no key request");
        assert!(ask.asked.lock().expect("asked").is_empty(), "no question");
        assert_eq!(
            store.check("127.0.0.2", 60022, &[7u8; 32]).expect("check"),
            HostVerdict::Unknown,
            "nothing is pinned before a handshake proves it"
        );
    }

    /// The address's own pin comes first; the first pinned neighbour in
    /// command-line order after that; and with no pin anywhere, first
    /// contact as ever (spec §4a rule 5).
    #[test]
    fn its_own_pin_wins_and_the_first_pinned_neighbour_is_taken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(true);
        let discovery = FakeDiscovery::answering([3u8; 32]);
        let line = neighbours(&[("a", 1), ("b", 2), ("c", 3)]);

        let first =
            server_key("a", 1, any_addr(), &store, &line, &ask, &discovery).expect("first contact");
        assert_eq!(first.source, KeySource::Discovered);
        assert_eq!(discovery.calls(), 1);

        store.pin("c", 3, &[5u8; 32]).expect("pin c");
        let b = server_key("b", 2, any_addr(), &store, &line, &ask, &discovery).expect("b");
        assert_eq!(
            b,
            ServerKey {
                key: [3u8; 32],
                source: KeySource::Neighbour { of: "a:1".into() }
            },
            "the first pinned neighbour in command-line order"
        );
        let a = server_key("a", 1, any_addr(), &store, &line, &ask, &discovery).expect("a");
        assert_eq!(a.source, KeySource::Pinned, "its own pin wins");
        assert_eq!(discovery.calls(), 1);
    }

    /// Spec §4a rule 1: different keys pinned on one command line are found
    /// before anything is tried; the same key twice, or one pin, is fine.
    #[test]
    fn pins_that_disagree_are_found_and_agreeing_ones_are_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let line = neighbours(&[("a", 1), ("b", 2), ("c", 3)]);
        assert_eq!(pins_disagree(&line, &store).expect("read"), None);

        store.pin("b", 2, &[1u8; 32]).expect("pin b");
        assert_eq!(pins_disagree(&line, &store).expect("read"), None, "one pin");
        store.pin("a", 1, &[1u8; 32]).expect("pin a");
        assert_eq!(pins_disagree(&line, &store).expect("read"), None, "one key");

        store.pin("c", 3, &[2u8; 32]).expect("pin c");
        assert_eq!(
            pins_disagree(&line, &store).expect("read"),
            Some(Disagreement {
                first: ("a:1".into(), [1u8; 32]),
                second: ("c:3".into(), [2u8; 32]),
            })
        );
    }

    /// Spec §4a rule 3: after the neighbour's key got nothing, the key
    /// request decides -- another key, the same key, or nothing at all.
    #[test]
    fn a_silent_neighbour_key_is_settled_by_one_key_request() {
        let other = FakeDiscovery::answering([9u8; 32]);
        assert_eq!(
            after_neighbour_silence(any_addr(), [7u8; 32], &other),
            NeighbourSilence::OtherServer { offered: [9u8; 32] }
        );
        assert_eq!(other.calls(), 1, "asked once");
        assert_eq!(
            after_neighbour_silence(any_addr(), [7u8; 32], &FakeDiscovery::answering([7u8; 32])),
            NeighbourSilence::SameKey
        );
        assert!(matches!(
            after_neighbour_silence(any_addr(), [7u8; 32], &FakeDiscovery::silent()),
            NeighbourSilence::NoKey(DiscoveryError::Silent { .. })
        ));
    }

    /// Spec §4a rules 2 and 4: a proven key is pinned where nothing is, and
    /// a line already there -- the same key or a stale one -- is left alone.
    #[test]
    fn a_proven_key_is_pinned_only_where_nothing_is() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        assert_eq!(
            remember_proven("a", 1, &[4u8; 32], &store).expect("pin"),
            Proven::Remembered
        );
        assert_eq!(
            store.check("a", 1, &[4u8; 32]).expect("check"),
            HostVerdict::Known
        );
        assert_eq!(
            remember_proven("a", 1, &[4u8; 32], &store).expect("again"),
            Proven::AlreadyKnown
        );
        assert_eq!(
            remember_proven("a", 1, &[6u8; 32], &store).expect("stale"),
            Proven::Stale { pinned: [4u8; 32] }
        );
        assert_eq!(
            store.check("a", 1, &[4u8; 32]).expect("check"),
            HostVerdict::Known,
            "never overwritten"
        );
    }

    /// The reason this path exists at all. A server whose key changed cannot
    /// complete the handshake against the pinned one, so the attempt ends as
    /// silence -- and reporting that as "the daemon is not running" sends the
    /// user to restart a daemon that never stopped. This path produces a
    /// loud refusal instead, naming both fingerprints and the file to fix.
    #[test]
    fn silence_from_a_host_whose_key_changed_is_reported_as_a_changed_key() {
        let discovery = FakeDiscovery::answering([9u8; 32]);
        let AfterSilence::Changed(err) = after_silence(
            "example.org",
            60022,
            any_addr(),
            [7u8; 32],
            &discovery,
            &KnownHosts::open(PathBuf::from(r"C:\Users\Example User\qsh\known_hosts")),
        ) else {
            panic!("a different key is the explanation");
        };

        assert!(matches!(err, TrustError::KeyChanged { .. }), "{err:?}");
        assert_eq!(discovery.calls(), 1, "asked once, on the failure path only");
        let message = err.to_string();
        assert!(
            message.contains(&key_fingerprint(&[7u8; 32])),
            "the pinned fingerprint belongs in it: {message}"
        );
        assert!(
            message.contains(&key_fingerprint(&[9u8; 32])),
            "and the offered one: {message}"
        );
        assert!(
            message.contains(r"C:\Users\Example User\qsh\known_hosts"),
            "and where to fix it: {message}"
        );
        assert!(
            message.contains("system mode"),
            "and the host key's move between qshd's personal and system mode as a \
             possible innocent cause: {message}"
        );
    }

    /// A server offering the key we already have is not a changed key: it
    /// answers the key request, and not the login.
    #[test]
    fn silence_from_a_host_offering_the_same_key_is_the_same_key() {
        let discovery = FakeDiscovery::answering([7u8; 32]);
        assert!(
            matches!(
                after_silence(
                    "example.org",
                    60022,
                    any_addr(),
                    [7u8; 32],
                    &discovery,
                    &KnownHosts::open(PathBuf::from(r"C:\Users\Example User\qsh\known_hosts"))
                ),
                AfterSilence::SameKey
            ),
            "the same key is not a changed key"
        );
    }

    /// Discovery going unanswered too is the ordinary case -- the daemon
    /// really is not there. It must not be dressed up as a key change, which
    /// would accuse someone of being in the path on no evidence at all; what
    /// discovery observed is kept for the line on screen.
    #[test]
    fn silence_that_discovery_cannot_explain_either_keeps_what_it_saw() {
        let discovery = FakeDiscovery::silent();
        assert!(
            matches!(
                after_silence(
                    "example.org",
                    60022,
                    any_addr(),
                    [7u8; 32],
                    &discovery,
                    &KnownHosts::open(PathBuf::from(r"C:\Users\Example User\qsh\known_hosts"))
                ),
                AfterSilence::NoKey(DiscoveryError::Silent { .. })
            ),
            "no answer is not evidence of a changed key"
        );
    }

    /// A changed key is refused outright. It is either a reinstalled server
    /// or someone in the path, and from here the two are indistinguishable
    /// -- so this is the one case where guessing is not allowed.
    #[test]
    fn a_changed_key_is_refused_and_not_put_to_a_vote() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        store.pin("example.org", 60022, &[7u8; 32]).expect("pin");
        let ask = recorder(true);

        let err = server_key_with_discovered("example.org", 60022, &store, &ask, Ok([9u8; 32]))
            .expect_err("a changed key must be refused");

        assert!(matches!(err, TrustError::KeyChanged { .. }), "{err:?}");
        assert!(
            ask.asked.lock().expect("asked").is_empty(),
            "the user is not asked to approve a changed key -- there is no safe yes"
        );
        let message = err.to_string();
        assert!(
            message.contains("SHA256:"),
            "both fingerprints belong in it: {message}"
        );
        assert!(
            message.contains("known_hosts"),
            "and where to fix it: {message}"
        );
        assert!(
            message.contains("system mode"),
            "and the host key's move between qshd's personal and system mode as a \
             possible innocent cause: {message}"
        );
    }

    #[test]
    fn changed_key_reports_the_store_used_for_discovery_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let store = hosts(&dir.path().join("Application Support"));
        store.pin("example.org", 60022, &[7; 32]).unwrap();
        let ask = recorder(true);
        let initial = server_key_with_discovered("example.org", 60022, &store, &ask, Ok([9; 32]))
            .unwrap_err();
        let recovery = recovery_server_key("example.org", 60022, [9; 32], &store).unwrap_err();
        for err in [initial, recovery] {
            let message = err.to_string();
            assert!(
                message.contains(&store.path().display().to_string()),
                "{message}"
            );
            assert!(!message.contains("~/.config/qsh/known_hosts"), "{message}");
        }
        assert!(ask.asked.lock().unwrap().is_empty());
        assert_eq!(
            store.check("example.org", 60022, &[7; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    /// First contact: show the fingerprint, ask, pin on yes.
    #[test]
    fn a_new_key_is_shown_asked_about_and_pinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(true);

        let key = server_key_with_discovered("example.org", 60022, &store, &ask, Ok([3u8; 32]))
            .expect("an approved key is accepted");
        assert_eq!(key, [3u8; 32]);

        let asked = ask.asked.lock().expect("asked");
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].contains(&key_fingerprint(&[3u8; 32])),
            "the fingerprint is what the user compares: {:?}",
            asked[0]
        );

        // Pinned, so the next run asks nothing.
        assert!(matches!(
            store
                .check("example.org", 60022, &[3u8; 32])
                .expect("check"),
            HostVerdict::Known
        ));
    }

    /// Saying no means no: nothing is pinned and nothing is connected to.
    #[test]
    fn refusing_a_new_key_pins_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(false);

        let err = server_key_with_discovered("example.org", 60022, &store, &ask, Ok([3u8; 32]))
            .expect_err("a refused key must not connect");
        assert!(matches!(err, TrustError::Refused), "{err:?}");
        assert!(matches!(
            store
                .check("example.org", 60022, &[3u8; 32])
                .expect("check"),
            HostVerdict::Unknown
        ));
    }

    /// A daemon that does not answer is the most common failure of all: the
    /// error keeps what discovery observed, for the ladder's line, and its
    /// own text carries no second screenful of advice.
    #[test]
    fn a_silent_daemon_keeps_what_discovery_saw() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(true);

        let err = server_key_with_discovered(
            "example.org",
            60022,
            &store,
            &ask,
            Err(DiscoveryError::Silent {
                addr: any_addr(),
                waited: DISCOVERY_TIMEOUT,
            }),
        )
        .expect_err("no answer, no key");

        let message = err.to_string();
        assert!(
            matches!(
                err,
                TrustError::NoAnswer {
                    reason: DiscoveryError::Silent { .. },
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(message.contains("example.org"), "and where: {message}");
        assert!(!message.contains('\n'), "one line: {message}");
    }

    /// A daemon that DID answer -- just not with a usable key -- must not
    /// be reported the same way as silence. The two need different fixes
    /// (nothing is running, versus something wrong is running), and a
    /// message that always blames a stopped daemon sends the user to check
    /// something that is not actually broken.
    #[test]
    fn a_reply_that_is_not_a_key_offer_is_not_mistaken_for_silence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = hosts(dir.path());
        let ask = recorder(true);

        let err = server_key_with_discovered(
            "example.org",
            60022,
            &store,
            &ask,
            Err(DiscoveryError::NotAKeyOffer { addr: any_addr() }),
        )
        .expect_err("garbage from the daemon is still not a usable key");

        assert!(matches!(err, TrustError::NoAnswer { .. }), "{err:?}");
        let message = err.to_string();
        assert!(
            message.contains("answered something other than a key offer"),
            "the real reason must survive, not be discarded: {message}"
        );
        assert!(
            !message.contains("did not answer"),
            "the daemon DID answer -- the message must not claim it stayed silent: {message}"
        );
    }
}
