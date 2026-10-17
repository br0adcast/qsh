//! Turning the host name into the one address every knock -- and then the
//! SSH connection -- goes to.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::{Cancel, KnockError, SLICE};

/// How long a host name may take to resolve. The system resolver has no
/// deadline of its own: behind a DNS server that is reachable but silent it
/// waits 30 s or more, which would read as a hung connect.
pub const RESOLVE_BUDGET: Duration = Duration::from_secs(10);

/// Resolves `host` once, with the system resolver, bounded by
/// [`RESOLVE_BUDGET`] and by `cancel`.
pub fn resolve(host: &str, cancel: &Cancel) -> Result<IpAddr, KnockError> {
    resolve_with(host, cancel, RESOLVE_BUDGET, system_lookup)
}

fn system_lookup(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    // The port is irrelevant: every knock names its own.
    (host, 0u16).to_socket_addrs().map(|it| it.collect())
}

/// [`resolve`] with the lookup handed in, so a test can stand in a resolver
/// that answers oddly or never.
///
/// The lookup runs on its own thread; this one waits for it in [`SLICE`]s,
/// looking at `cancel` between them. If the budget or a cancel wins, the
/// lookup thread is left to finish on its own -- it holds nothing of the
/// caller's.
///
/// The system resolver has no deadline of its own: behind a silent DNS
/// server it can wait 30 s or longer, so a lookup thread this function gives
/// up on keeps running until the resolver itself times out. That is not a
/// leak in the usual sense -- the thread holds no lock, no handle, nothing
/// of the caller's -- but the reconnect loop can start a new one on every
/// attempt, so a few may pile up at once while their predecessors are still
/// waiting on the resolver. Bounded by the loop's own attempt rate, this is
/// acceptable; it just isn't nothing.
pub fn resolve_with<F>(
    host: &str,
    cancel: &Cancel,
    budget: Duration,
    lookup: F,
) -> Result<IpAddr, KnockError>
where
    F: FnOnce(&str) -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
{
    // F5(a): already cancelled before starting -- spawning the lookup thread only to notice
    // this on the first look in the loop below would still leave it running for nothing.
    if cancel.is_cancelled() {
        return Err(KnockError::Cancelled);
    }
    let (tx, rx) = mpsc::channel();
    // Remove IPv6 address brackets: they belong to host:port notation,
    // not to the host name expected by to_socket_addrs().
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let owned = unbracketed.to_string();
    std::thread::spawn(move || {
        // Nobody may be listening any more; that is fine.
        let _ = tx.send(lookup(&owned));
    });
    let deadline = Instant::now() + budget;
    loop {
        if cancel.is_cancelled() {
            return Err(KnockError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(KnockError::Resolve(format!(
                "{host}: the address did not resolve within {budget:?}"
            )));
        }
        match rx.recv_timeout((deadline - now).min(SLICE)) {
            Ok(Ok(addrs)) => {
                // The shared rule, so a knock and a direct login turn the
                // same host into the same address.
                return sshauth::addr::preferred_addr(addrs)
                    .map(|a| a.ip())
                    .ok_or_else(|| {
                        KnockError::Resolve(format!("{host}: the address resolved to nothing"))
                    });
            }
            Ok(Err(e)) => {
                return Err(KnockError::Resolve(format!(
                    "{host}: could not resolve the address: {e}"
                )))
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(KnockError::Resolve(format!(
                    "{host}: the resolver ended without an answer"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn slow(_: &str) -> std::io::Result<Vec<SocketAddr>> {
        std::thread::sleep(Duration::from_secs(5));
        Ok(vec!["192.0.2.1:0".parse().unwrap()])
    }

    #[test]
    fn localhost_resolves_to_ipv4_loopback() {
        let ip = resolve("localhost", &Cancel::new()).expect("localhost resolves");
        assert!(ip.is_ipv4() && ip.is_loopback(), "got {ip}");
    }

    #[test]
    fn an_ipv4_answer_wins_over_an_ipv6_one_listed_first() {
        let ip = resolve_with("h", &Cancel::new(), RESOLVE_BUDGET, |_| {
            Ok(vec![
                "[2001:db8::1]:0".parse().unwrap(),
                "192.0.2.7:0".parse().unwrap(),
            ])
        })
        .unwrap();
        assert_eq!(ip.to_string(), "192.0.2.7");
    }

    #[test]
    fn an_ipv6_only_answer_is_used() {
        let ip = resolve_with("h", &Cancel::new(), RESOLVE_BUDGET, |_| {
            Ok(vec!["[2001:db8::1]:0".parse().unwrap()])
        })
        .unwrap();
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    // F4: a bracketed IPv6 literal is the notation a person typing an address (or a socket-
    // address string like `host:port`) reuses out of habit -- but the brackets are notation,
    // not part of the host name, and the system resolver's own `(host, 0).to_socket_addrs()`
    // does not accept them (Java's `getByName`, which this used to run on, did). Stripping
    // must happen before the lookup runs, not just before matching -- this checks what the
    // lookup itself is actually handed.
    #[test]
    fn a_bracketed_ipv6_host_reaches_the_lookup_without_its_brackets() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen_in_lookup = seen.clone();
        let ip = resolve_with("[2001:db8::1]", &Cancel::new(), RESOLVE_BUDGET, move |h| {
            *seen_in_lookup.lock().unwrap() = Some(h.to_string());
            Ok(vec!["[2001:db8::1]:0".parse().unwrap()])
        })
        .unwrap();
        assert_eq!(seen.lock().unwrap().as_deref(), Some("2001:db8::1"));
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    /// End to end (the real system resolver, via [`resolve`]): a bracketed literal for the
    /// IPv6 loopback still resolves, exactly as it did through sshj/Java's `getByName` before.
    #[test]
    fn resolve_accepts_a_bracketed_ipv6_literal() {
        let ip = resolve("[::1]", &Cancel::new()).expect("a bracketed IPv6 literal resolves");
        assert_eq!(ip.to_string(), "::1");
    }

    #[test]
    fn no_answer_is_a_resolve_error() {
        let r = resolve_with("h", &Cancel::new(), RESOLVE_BUDGET, |_| Ok(vec![]));
        assert!(
            matches!(r, Err(KnockError::Resolve(ref m)) if m.contains("resolved to nothing")),
            "{r:?}"
        );
    }

    #[test]
    fn a_lookup_failure_is_a_resolve_error_naming_the_host() {
        let r = resolve_with("nowhere.invalid", &Cancel::new(), RESOLVE_BUDGET, |_| {
            Err(std::io::Error::other("no such host"))
        });
        assert!(
            matches!(r, Err(KnockError::Resolve(ref m)) if m.contains("nowhere.invalid")),
            "{r:?}"
        );
    }

    #[test]
    fn a_silent_resolver_runs_out_of_budget() {
        let started = Instant::now();
        let r = resolve_with("h", &Cancel::new(), Duration::from_millis(150), slow);
        assert!(
            matches!(r, Err(KnockError::Resolve(ref m)) if m.contains("did not resolve")),
            "{r:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_cancel_ends_the_wait_for_a_silent_resolver() {
        let cancel = Cancel::new();
        let remote = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            remote.cancel();
        });
        let started = Instant::now();
        let r = resolve_with("h", &cancel, RESOLVE_BUDGET, slow);
        assert_eq!(r, Err(KnockError::Cancelled));
        assert!(started.elapsed() < Duration::from_millis(100) + SLICE * 3);
    }

    /// F5(a): a call that is already cancelled before it starts must not spawn the lookup
    /// thread at all -- spawning one only to notice the cancellation on the very first look
    /// would still leave a resolver thread running for a result nobody asked for.
    #[test]
    fn a_pre_cancelled_call_never_invokes_the_lookup() {
        let cancel = Cancel::new();
        cancel.cancel();
        let invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invoked_in_lookup = invoked.clone();
        let r = resolve_with("h", &cancel, RESOLVE_BUDGET, move |_| {
            invoked_in_lookup.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(vec!["192.0.2.1:0".parse().unwrap()])
        });
        assert_eq!(r, Err(KnockError::Cancelled));
        // Gives a wrongly-spawned lookup thread time to run before checking: without the
        // early-return this races the scheduler and would usually, not always, still catch
        // the bug -- the sleep makes the check reliable instead of lucky.
        std::thread::sleep(SLICE);
        assert!(!invoked.load(std::sync::atomic::Ordering::SeqCst));
    }
}
