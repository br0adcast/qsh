//! Which of a resolver's answers to dial, when the daemon may not listen on
//! every family the resolver offers -- and what a failure to reach one of
//! them may mean on the client's own machine.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};

/// What a person on macOS is told when a packet or a connection to a local
/// address fails as if there were no route: the system's Local Network
/// privacy setting denies the terminal app, and that is how it looks.
pub const LOCAL_NETWORK_HINT: &str = "on macOS this is how a denied Local Network permission \
     looks: allow your terminal app in System Settings > Privacy & Security > Local Network";

/// Whether a failure to reach `ip` deserves [`LOCAL_NETWORK_HINT`].
///
/// macOS 15 answers a send or a connect to an address on the local network
/// with `EHOSTUNREACH` (or `ENETUNREACH`) when the app is not allowed to use
/// the Local Network, so on macOS, for those two errors, to a private or
/// link-local address, the hint says what is most likely going on. Anywhere
/// else, or for another error, or for a public address, it would send the
/// person to a setting that has nothing to do with it.
///
/// `on_macos` is a parameter, not `cfg!`, so that every branch runs under
/// test on any system; callers pass `cfg!(target_os = "macos")`.
pub fn local_network_hint(on_macos: bool, kind: ErrorKind, ip: IpAddr) -> bool {
    on_macos
        && matches!(
            kind,
            ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
        )
        && is_local_network(ip)
}

/// A private (RFC 1918), link-local (`169.254/16`) or shared (`100.64/10`)
/// IPv4 address, or an IPv6 unique local (`fc00::/7`) or link-local
/// (`fe80::/10`) one: the addresses the Local Network permission governs.
/// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is judged as the IPv4
/// address it maps.
fn is_local_network(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_network(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

/// Which of the resolver's answers to dial.
///
/// An IPv4 address wins whenever there is one, even if the resolver put an
/// IPv6 address first. `qshd serve` binds `Ipv4Addr::UNSPECIFIED`
/// (`qshd/src/serve.rs`) -- a documented limit -- so it does not listen on
/// the host's AAAA address at all, while glibc's RFC 6724 sorting puts that
/// address first on a dual-stack client. Taking the first answer therefore
/// dialled a port nothing was listening on and reported a running daemon as
/// unreachable -- a bug the `qsh` CLI hit and fixed once already; every
/// caller that turns a resolver's answers into one address to dial shares
/// this one definition rather than risking a second copy that drifts back
/// into the same mistake.
///
/// REVISIT when the daemon learns to bind both families: the preference is
/// a workaround for where the server listens, not a statement about which
/// family is better, and it will silently prefer the worse route once IPv6
/// works.
///
/// `None` means the resolver produced nothing at all.
pub fn preferred_addr(addrs: impl IntoIterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut fallback = None;
    for addr in addrs {
        if addr.is_ipv4() {
            return Some(addr);
        }
        fallback.get_or_insert(addr);
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(literal: &str) -> SocketAddr {
        literal.parse().expect("a literal address")
    }

    /// The failure this exists for: a dual-stack host whose AAAA record the
    /// resolver puts first. The daemon binds IPv4 only, so taking the first
    /// answer dials a port nothing is listening on -- and reports a running
    /// daemon as unreachable, which is the same misdiagnosis by a different
    /// route.
    #[test]
    fn an_ipv4_address_wins_even_when_the_resolver_puts_ipv6_first() {
        let chosen = preferred_addr(vec![addr("[2001:db8::1]:60022"), addr("192.0.2.7:60022")]);
        assert_eq!(chosen, Some(addr("192.0.2.7:60022")));
    }

    /// With no IPv4 anywhere, the first answer is still tried: an IPv6-only
    /// host is not a reason to refuse to connect, only a reason it may not
    /// work until the daemon binds both families.
    #[test]
    fn an_ipv6_only_host_falls_back_to_the_first_answer() {
        let chosen = preferred_addr(vec![
            addr("[2001:db8::1]:60022"),
            addr("[2001:db8::2]:60022"),
        ]);
        assert_eq!(chosen, Some(addr("[2001:db8::1]:60022")));
    }

    /// Among several IPv4 answers the resolver's own order stands: the
    /// preference is about the family, and nothing here knows better than
    /// the resolver which of two A records to prefer.
    #[test]
    fn the_first_ipv4_answer_is_the_one_taken() {
        let chosen = preferred_addr(vec![addr("192.0.2.7:60022"), addr("192.0.2.8:60022")]);
        assert_eq!(chosen, Some(addr("192.0.2.7:60022")));
    }

    /// A name that resolved to nothing has nothing to dial.
    #[test]
    fn nothing_resolved_is_no_address() {
        assert_eq!(preferred_addr(Vec::new()), None);
    }

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("a literal address")
    }

    /// The case this exists for: macOS, no route, a LAN address.
    #[test]
    fn macos_with_no_route_to_a_lan_address_gets_the_hint() {
        assert!(local_network_hint(
            true,
            ErrorKind::HostUnreachable,
            ip("192.168.0.200")
        ));
        assert!(local_network_hint(
            true,
            ErrorKind::NetworkUnreachable,
            ip("192.168.0.200")
        ));
    }

    /// Linux has no such permission: the same error is just what it says.
    #[test]
    fn another_system_never_gets_the_hint() {
        assert!(!local_network_hint(
            false,
            ErrorKind::HostUnreachable,
            ip("192.168.0.200")
        ));
    }

    /// The permission governs the local network only.
    #[test]
    fn a_public_address_never_gets_the_hint() {
        assert!(!local_network_hint(
            true,
            ErrorKind::HostUnreachable,
            ip("203.0.113.7")
        ));
        assert!(!local_network_hint(
            true,
            ErrorKind::HostUnreachable,
            ip("2001:db8::1")
        ));
        assert!(!local_network_hint(
            true,
            ErrorKind::HostUnreachable,
            ip("127.0.0.1")
        ));
    }

    /// A refused connection is an answer from the host, not a denied
    /// permission.
    #[test]
    fn another_error_never_gets_the_hint() {
        assert!(!local_network_hint(
            true,
            ErrorKind::ConnectionRefused,
            ip("192.168.0.200")
        ));
        assert!(!local_network_hint(
            true,
            ErrorKind::PermissionDenied,
            ip("192.168.0.200")
        ));
    }

    /// Every range the permission covers, and the edges just outside them.
    #[test]
    fn the_local_ranges_are_the_ones_the_permission_covers() {
        for local in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.3.4",
            "100.64.0.1",
            "100.127.255.255",
            "fd12:3456::1",
            "fc00::1",
            "fe80::1",
            "::ffff:192.168.0.200",
            "::ffff:10.1.2.3",
        ] {
            assert!(is_local_network(ip(local)), "{local}");
        }
        for other in [
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "8.8.8.8",
            "fec0::1",
            "2001:db8::1",
            "::1",
            "::ffff:8.8.8.8",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_local_network(ip(other)), "{other}");
        }
    }
}
