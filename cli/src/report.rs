//! Every line a person reads before the session starts, as pure functions:
//! the ladder's progress, and the summary when every address failed.
//!
//! A knock is secret: a line about one says how many steps it has and
//! nothing else (spec §4.4).

use std::path::Path;

use ::connect::NoAnswerWhy;
use sshauth::known_hosts::key_fingerprint;

/// Step 1 or 3 got no handshake at `port`: what the client observed, with
/// the Local Network hint when the observation carries it.
pub fn no_answer(host: &str, port: u16, why: &NoAnswerWhy) -> String {
    with_hint(
        format!("qsh: {host}:{port}: {}", no_answer_words(host, port, why)),
        no_answer_hinted(why),
    )
}

/// `line`, and the Local Network hint after it when `hinted`.
fn with_hint(mut line: String, hinted: bool) -> String {
    if hinted {
        line.push_str(" -- ");
        line.push_str(sshauth::addr::LOCAL_NETWORK_HINT);
    }
    line
}

fn no_answer_hinted(why: &NoAnswerWhy) -> bool {
    matches!(
        why,
        NoAnswerWhy::SendFailed {
            local_network_hint: true,
            ..
        }
    )
}

/// Whether a reason carries the Local Network hint.
fn hinted(reason: &::connect::Reason) -> bool {
    use ::connect::Reason;
    match reason {
        Reason::NoAnswer(why) | Reason::NoAnswerAfterSsh { why, .. } => no_answer_hinted(why),
        Reason::Ssh(failure) => failure.local_network_hint,
        _ => false,
    }
}

/// The same words in the step line and in the summary, without the hint
/// (each place adds it once). The server never says why it is silent, so
/// these say only what the client saw -- and, where the observation allows
/// more than one cause, name the likely ones.
fn no_answer_words(host: &str, port: u16, why: &NoAnswerWhy) -> String {
    match why {
        NoAnswerWhy::PortRefused => format!("UDP port {port} refused the connection"),
        NoAnswerWhy::SendFailed { to, os_error, .. } => {
            format!("cannot send to {to}: {os_error}")
        }
        NoAnswerWhy::Silent { waited_secs } => format!(
            "no answer over qsh in {waited_secs} s -- qshd is not running there, \
             or a firewall drops UDP port {port}"
        ),
        NoAnswerWhy::KeyedButSilent => "qshd answered the key request but not the login -- \
             a different qsh version, or the daemon is overloaded; its log says more"
            .to_string(),
        NoAnswerWhy::NotQshd { reason } => format!(
            "something else answers on UDP port {port}: {}",
            printable(reason)
        ),
        NoAnswerWhy::Ipv6Only { literal: true } => {
            format!("{host} is an IPv6 address; qsh works over IPv4")
        }
        NoAnswerWhy::Ipv6Only { literal: false } => {
            "host resolves to IPv6 only; qsh works over IPv4".to_string()
        }
        NoAnswerWhy::Socket { reason } => {
            format!("the client's UDP socket failed: {}", printable(reason))
        }
    }
}

/// Step 1 answered and took none of `offered` for `account`; `looked` is
/// where keys were searched for when there were none to offer.
pub fn refused(
    host: &str,
    port: u16,
    account: &str,
    offered: &[String],
    looked: &[String],
) -> String {
    format!(
        "qsh: {host}:{port}: {}",
        refused_words(account, offered, looked)
    )
}

/// The same words in the step line and in the summary: the labels carry
/// fingerprints, which is what a person compares with `authorized_keys`.
/// The server does not say why it refused, so the tail names where the
/// reason can be: its keys, its account checks, its log.
fn refused_words(account: &str, offered: &[String], looked: &[String]) -> String {
    let offered = match (offered.is_empty(), looked.is_empty()) {
        (false, _) => offered.join(", "),
        (true, true) => "none".to_string(),
        (true, false) => format!("none; looked: {}", looked.join("; ")),
    };
    format!(
        "no key was accepted over qsh for account {} (offered: {offered}) -- the server's \
         authorized_keys, or in system mode the account or PAM; qshd's log names the reason",
        printable(account)
    )
}

/// Step 3 answered and did not let the process key in.
pub fn refused_after_ssh(host: &str, port: u16) -> String {
    format!("qsh: {host}:{port}: {REFUSED_AFTER_SSH}")
}

/// The same words in the step line and in the summary. The daemon ssh just
/// started knows this key, so what refuses it is one of its own limits.
const REFUSED_AFTER_SSH: &str = "the qshd started over ssh did not admit the key it was given \
     (a session limit, or another account owns the session) -- qshd's log says which";

/// The name did not resolve: `why` is the resolver's error, `None` when it
/// answered with no address at all.
pub fn could_not_resolve(host: &str, why: Option<&str>) -> String {
    format!("qsh: {host}: {}", unresolved_words(host, why))
}

fn unresolved_words(host: &str, why: Option<&str>) -> String {
    match why {
        Some(why) => format!("could not resolve: {why}"),
        None => format!("could not resolve {host}: no IPv4 or IPv6 address"),
    }
}

/// The last line of the exit 12 summary: where the log that says more is.
pub fn details(log: &Path) -> String {
    format!("qsh: details: {}", log.display())
}

/// Step 2 begins. The knock is counted, never shown.
pub fn trying_ssh(host: &str, route: &::connect::SshRoute) -> String {
    let mut line = format!("qsh: {host}: trying ssh:{}", route.port);
    let steps = route.knock.len();
    if steps > 0 {
        line.push_str(&format!(" (knock: {steps} steps)"));
    }
    line
}

/// `failure.why` may come from the server (its ssh error, qshd's own text).
pub fn ssh_failed(host: &str, failure: &::connect::SshFailure) -> String {
    with_hint(
        format!("qsh: {host}: ssh: {}", printable(&failure.why)),
        failure.local_network_hint,
    )
}

/// Step 2 ended with the daemon up on `port`; `asked` is the port the
/// address names (spec §6.3).
pub fn qshd_ready(host: &str, asked: u16, port: u16) -> String {
    if port == asked {
        format!("qsh: {host}: qshd started, port {port}")
    } else {
        format!("qsh: {host}: qshd listens on {port}, not {asked}")
    }
}

/// `warning` is qshd's own text.
pub fn qshd_warning(host: &str, warning: &str) -> String {
    format!("qsh: {host}: qshd: {}", printable(warning))
}

/// Spec §4a rule 1: two addresses of one command line have different keys
/// pinned, found before anything is tried. `a` and `b` are `host:port`;
/// `known_hosts` is the file to edit. The second line puts the two
/// fingerprints side by side, which is what tells the stale line apart.
pub fn pins_disagree(
    a: &str,
    a_key: &[u8; 32],
    b: &str,
    b_key: &[u8; 32],
    known_hosts: &Path,
) -> String {
    format!(
        "qsh: {a} and {b} are on one command line but have different server keys pinned -- \
         they are not one server; remove the stale line for one of them from {}\n  \
         {a} is pinned to {}; {b} is pinned to {}",
        known_hosts.display(),
        key_fingerprint(a_key),
        key_fingerprint(b_key)
    )
}

/// Spec §4a rule 2: `addr` had no key pinned, and the handshake with the
/// key pinned for `neighbour` completed there -- only the holder of that
/// key's private half can complete it.
pub fn same_server(addr: &str, neighbour: &str) -> String {
    format!("qsh: {addr}: the same server as {neighbour} -- key remembered")
}

/// Spec §4a rule 3: the handshake with `neighbour`'s key got no answer at
/// `addr`, and the key request there came back with `offered` instead.
pub fn not_the_same_server(
    addr: &str,
    neighbour: &str,
    neighbour_key: &[u8; 32],
    offered: &[u8; 32],
) -> String {
    format!(
        "qsh: {addr} answers with a different server key than {neighbour} -- not the same \
         server; check the addresses on the command line\n  {neighbour} is pinned to {}; \
         {addr} offers {}",
        key_fingerprint(neighbour_key),
        key_fingerprint(offered)
    )
}

/// Text from the other side, made safe for a terminal: a server must not be
/// able to move the cursor, retitle the window or clear the screen from a
/// line of ours. Line breaks and tabs become spaces (one line stays one
/// line); every other control character -- C0 with ESC, DEL, C1 -- becomes
/// `?`.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => '?',
            c => c,
        })
        .collect()
}

/// What the executor learned at one address beyond the ladder's reasons,
/// for the summary: the ladder keeps no text of its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detail {
    /// Why the name did not resolve; `None` for a resolver that answered
    /// with no address at all.
    pub unresolved: Option<String>,
    /// The keys step 1 offered there, all refused.
    pub offered: Vec<String>,
    /// Where keys were looked for, when step 1 had none to offer.
    pub looked: Vec<String>,
}

/// The summary a login prints before exit 12: [`all_failed`], then where
/// the log is.
pub fn exit_12_summary(
    addrs: &[::connect::Address],
    failures: &[::connect::Failure],
    details: &[Detail],
    account: &str,
    log: &Path,
) -> Vec<String> {
    let mut lines = all_failed(addrs, failures, details, account);
    lines.push(self::details(log));
    lines
}

/// The summary when the ladder ran out of addresses: a heading, then one
/// line per address with every step's reason, then -- if any reason looked
/// like a denied Local Network permission -- the hint, once. `details` is
/// indexed like `addrs`; an address without one gets the plain words.
/// `account` is the login step 1 claimed.
pub fn all_failed(
    addrs: &[::connect::Address],
    failures: &[::connect::Failure],
    details: &[Detail],
    account: &str,
) -> Vec<String> {
    let mut lines = vec!["qsh: could not connect:".to_string()];
    let none = Detail::default();
    let mut any_hint = false;
    for failure in failures {
        any_hint |= failure.reasons.iter().any(hinted);
        let addr = &addrs[failure.addr];
        let detail = details.get(failure.addr).unwrap_or(&none);
        let reasons: Vec<String> = failure
            .reasons
            .iter()
            .map(|r| words(r, addr, detail, account))
            .collect();
        lines.push(format!(
            "qsh:   {}:{}: {}",
            addr.host,
            addr.qsh_port,
            reasons.join("; ")
        ));
    }
    if any_hint {
        lines.push(format!("qsh: {}", sshauth::addr::LOCAL_NETWORK_HINT));
    }
    lines
}

/// A reason's words in the summary line of `addr`.
fn words(
    reason: &::connect::Reason,
    addr: &::connect::Address,
    detail: &Detail,
    account: &str,
) -> String {
    use ::connect::Reason;
    match reason {
        Reason::NoAnswer(why) => no_answer_words(&addr.host, addr.qsh_port, why),
        Reason::Unresolved => unresolved_words(&addr.host, detail.unresolved.as_deref()),
        Reason::Refused => refused_words(account, &detail.offered, &detail.looked),
        Reason::Ssh(failure) => format!("ssh: {}", printable(&failure.why)),
        Reason::NoAnswerAfterSsh { port, why } => format!(
            "on the port qshd reported ({port}): {}",
            no_answer_words(&addr.host, *port, why)
        ),
        Reason::RefusedAfterSsh => REFUSED_AFTER_SSH.to_string(),
        Reason::NeedsPrompt => "needs a prompt".to_string(),
        Reason::IdentityMismatch => {
            "server identity does not match the current session".to_string()
        }
    }
}

/// A refusal to install stops login independently of SSH host-key trust.
pub fn install_declined() -> String {
    "qsh: daemon installation was declined".into()
}

/// Separate recovery consent names both independently verified identities.
pub fn ssh_authorization(
    server: &::connect::server_identity::ServerIdentity,
    endpoint: &::connect::server_identity::SshEndpoint,
    ssh: &ssh::HostKeyInfo,
) -> String {
    format!(
        "QSH server {} (account {})\nSSH host {}:{} ({})\nAuthorize SSH recovery for this QSH server?",
        key_fingerprint(&server.qsh_key),
        printable(&server.username),
        printable(&endpoint.host),
        endpoint.port,
        printable(&ssh.fingerprint),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use connect::{Address, Failure, NoAnswerWhy, Reason, SshFailure, SshRoute};

    fn route(knock_steps: usize) -> SshRoute {
        SshRoute {
            port: 2222,
            knock: (0..knock_steps)
                .map(|i| knock::KnockStep {
                    protocol: knock::KnockProtocol::Udp,
                    port: 7000 + i as u16,
                    payload: b"secret".to_vec(),
                    delay_after_ms: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn the_ssh_line_counts_knock_steps_and_shows_nothing_else() {
        assert_eq!(trying_ssh("h", &route(0)), "qsh: h: trying ssh:2222");
        let with = trying_ssh("h", &route(3));
        assert_eq!(with, "qsh: h: trying ssh:2222 (knock: 3 steps)");
        assert!(!with.contains("secret") && !with.contains("7000"));
    }

    #[test]
    fn control_characters_from_the_server_never_reach_the_terminal() {
        assert_eq!(
            printable("a\x1b]0;owned\x07b\x1b[2Jc\u{9b}31md\x7fe\x00f"),
            "a?]0;owned?b?[2Jc?31md?e?f"
        );
        assert_eq!(printable("one\ntwo\r\tthree"), "one two  three");
        assert_eq!(printable("plain, ünïcode — ok"), "plain, ünïcode — ok");
    }

    #[test]
    fn every_server_text_line_is_made_printable() {
        assert_eq!(
            ssh_failed("h", &SshFailure::plain("qshd said \x1b[31mno\nreally")),
            "qsh: h: ssh: qshd said ?[31mno really"
        );
        assert_eq!(
            qshd_warning("h", "\x1b]0;x\x07careful"),
            "qsh: h: qshd: ?]0;x?careful"
        );
        let addrs = vec![Address {
            host: "a".into(),
            qsh_port: 1,
            ssh: Some(route(0)),
        }];
        let f = vec![Failure {
            addr: 0,
            reasons: vec![Reason::Ssh(SshFailure::plain("bad\x1b[2J"))],
        }];
        assert_eq!(
            all_failed(&addrs, &f, &[], "u")[1],
            "qsh:   a:1: ssh: bad?[2J"
        );
    }

    #[test]
    fn a_daemon_on_another_port_is_said_so() {
        assert_eq!(
            qshd_ready("h", 60022, 60022),
            "qsh: h: qshd started, port 60022"
        );
        assert_eq!(
            qshd_ready("h", 60022, 60000),
            "qsh: h: qshd listens on 60000, not 60022"
        );
    }

    const REFUSED_TAIL: &str = " -- the server's authorized_keys, or in system mode the account \
         or PAM; qshd's log names the reason";

    /// Spec §4.2: a refusal names the account and the keys offered, and
    /// where to look.
    #[test]
    fn a_refusal_names_the_account_and_the_keys_offered() {
        assert_eq!(
            refused(
                "h",
                1,
                "alice",
                &["agent: ed25519".into(), "/k/id".into()],
                &[]
            ),
            format!(
                "qsh: h:1: no key was accepted over qsh for account alice \
                 (offered: agent: ed25519, /k/id){REFUSED_TAIL}"
            )
        );
    }

    /// Spec §4.2: nothing offered says where keys were looked for.
    #[test]
    fn a_refusal_with_nothing_offered_says_where_keys_were_looked_for() {
        assert_eq!(
            refused(
                "h",
                1,
                "alice",
                &[],
                &[
                    "ssh-agent: SSH_AUTH_SOCK not set".into(),
                    "~/.ssh/id_ed25519: no such file".into()
                ]
            ),
            format!(
                "qsh: h:1: no key was accepted over qsh for account alice (offered: none; \
                 looked: ssh-agent: SSH_AUTH_SOCK not set; ~/.ssh/id_ed25519: no such file)\
                 {REFUSED_TAIL}"
            )
        );
        assert_eq!(
            refused("h", 1, "alice", &[], &[]),
            format!(
                "qsh: h:1: no key was accepted over qsh for account alice (offered: none)\
                 {REFUSED_TAIL}"
            )
        );
    }

    /// Spec §4.2: the refusal after ssh does not guess one cause.
    #[test]
    fn a_refusal_after_ssh_names_what_it_may_be() {
        assert_eq!(
            refused_after_ssh("h", 60111),
            "qsh: h:60111: the qshd started over ssh did not admit the key it was given \
             (a session limit, or another account owns the session) -- qshd's log says which"
        );
    }

    fn send_failed(hint: bool) -> NoAnswerWhy {
        NoAnswerWhy::SendFailed {
            to: "192.168.0.200:60200".parse().expect("addr"),
            os_error: "No route to host (os error 65)".into(),
            local_network_hint: hint,
        }
    }

    /// Spec §4.1, row 1: the send failed, in the OS's own words.
    #[test]
    fn a_failed_send_says_so_in_the_os_words() {
        assert_eq!(
            no_answer("192.168.0.200", 60200, &send_failed(false)),
            "qsh: 192.168.0.200:60200: cannot send to 192.168.0.200:60200: \
             No route to host (os error 65)"
        );
    }

    /// Spec §4.1, row 2: on macOS, to a local address, the Local Network
    /// permission is named.
    #[test]
    fn a_failed_send_on_macos_to_a_local_address_names_the_permission() {
        assert_eq!(
            no_answer("192.168.0.200", 60200, &send_failed(true)),
            "qsh: 192.168.0.200:60200: cannot send to 192.168.0.200:60200: \
             No route to host (os error 65) -- on macOS this is how a denied Local Network \
             permission looks: allow your terminal app in System Settings > Privacy & \
             Security > Local Network"
        );
    }

    /// Spec §4.1, row 3: the key request went unanswered.
    #[test]
    fn silence_says_how_long_and_what_it_may_be() {
        assert_eq!(
            no_answer("h", 60200, &NoAnswerWhy::Silent { waited_secs: 5 }),
            "qsh: h:60200: no answer over qsh in 5 s -- qshd is not running there, \
             or a firewall drops UDP port 60200"
        );
        assert_eq!(
            no_answer("h", 60200, &NoAnswerWhy::Silent { waited_secs: 10 }),
            "qsh: h:60200: no answer over qsh in 10 s -- qshd is not running there, \
             or a firewall drops UDP port 60200"
        );
    }

    /// Spec §4.1, row 4: the key came, the login did not.
    #[test]
    fn a_key_without_a_login_says_the_daemon_answered() {
        assert_eq!(
            no_answer("h", 60200, &NoAnswerWhy::KeyedButSilent),
            "qsh: h:60200: qshd answered the key request but not the login -- a different \
             qsh version, or the daemon is overloaded; its log says more"
        );
    }

    /// Spec §4.1, row 5: something that is not qshd answers there.
    #[test]
    fn something_else_on_the_port_is_said_so() {
        assert_eq!(
            no_answer(
                "h",
                60200,
                &NoAnswerWhy::NotQshd {
                    reason: "the reply is not a key offer\x1b[2J".into()
                }
            ),
            "qsh: h:60200: something else answers on UDP port 60200: \
             the reply is not a key offer?[2J"
        );
    }

    /// Spec §4.1, row 6: IPv6 only -- a name that resolves to it, or an
    /// address written as one.
    #[test]
    fn an_ipv6_only_name_or_literal_is_said_so() {
        assert_eq!(
            no_answer("h", 60200, &NoAnswerWhy::Ipv6Only { literal: false }),
            "qsh: h:60200: host resolves to IPv6 only; qsh works over IPv4"
        );
        assert_eq!(
            no_answer(
                "2001:db8::1",
                60200,
                &NoAnswerWhy::Ipv6Only { literal: true }
            ),
            "qsh: 2001:db8::1:60200: 2001:db8::1 is an IPv6 address; qsh works over IPv4"
        );
    }

    const HINT: &str = "on macOS this is how a denied Local Network permission looks: allow \
         your terminal app in System Settings > Privacy & Security > Local Network";

    /// Spec §4.2: the ssh step's line carries the hint when flagged.
    #[test]
    fn a_flagged_ssh_failure_carries_the_hint_on_its_line() {
        let failure = SshFailure {
            why: "192.168.0.200:22: No route to host (os error 65)".into(),
            local_network_hint: true,
        };
        assert_eq!(
            ssh_failed("h", &failure),
            format!("qsh: h: ssh: 192.168.0.200:22: No route to host (os error 65) -- {HINT}")
        );
    }

    /// The hint is ~150 characters: the summary says it once, on its own
    /// line, however many reasons carried it -- here both the qsh step's
    /// and the ssh step's at one address, and a second address.
    #[test]
    fn the_summary_says_the_hint_once() {
        let addrs = vec![
            Address {
                host: "192.168.0.200".into(),
                qsh_port: 60200,
                ssh: Some(route(0)),
            },
            Address {
                host: "192.168.0.201".into(),
                qsh_port: 60200,
                ssh: None,
            },
        ];
        let failures = vec![
            Failure {
                addr: 0,
                reasons: vec![
                    Reason::NoAnswer(send_failed(true)),
                    Reason::Ssh(SshFailure {
                        why: "192.168.0.200:2222: No route to host (os error 65)".into(),
                        local_network_hint: true,
                    }),
                ],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::NoAnswer(send_failed(true))],
            },
        ];
        let lines = exit_12_summary(
            &addrs,
            &failures,
            &[],
            "u",
            std::path::Path::new("/c/qsh/log"),
        );
        assert_eq!(
            lines,
            vec![
                "qsh: could not connect:".to_string(),
                "qsh:   192.168.0.200:60200: cannot send to 192.168.0.200:60200: No route to \
                 host (os error 65); ssh: 192.168.0.200:2222: No route to host (os error 65)"
                    .to_string(),
                "qsh:   192.168.0.201:60200: cannot send to 192.168.0.200:60200: No route to \
                 host (os error 65)"
                    .to_string(),
                format!("qsh: {HINT}"),
                "qsh: details: /c/qsh/log".to_string(),
            ]
        );
        let text = lines.join("\n");
        assert_eq!(
            text.matches("Local Network permission").count(),
            1,
            "{text}"
        );
    }

    /// Without a flagged reason there is no hint line.
    #[test]
    fn the_summary_has_no_hint_without_a_flag() {
        let addrs = vec![Address {
            host: "a".into(),
            qsh_port: 1,
            ssh: None,
        }];
        let f = vec![Failure {
            addr: 0,
            reasons: vec![Reason::NoAnswer(send_failed(false))],
        }];
        assert!(all_failed(&addrs, &f, &[], "u")
            .iter()
            .all(|l| !l.contains("Local Network")));
    }

    /// The client's own socket failing is the client's, not the server's.
    #[test]
    fn a_failed_socket_is_the_client_s_own() {
        assert_eq!(
            no_answer(
                "h",
                1,
                &NoAnswerWhy::Socket {
                    reason: "opening a socket for discovery: out of files".into()
                }
            ),
            "qsh: h:1: the client's UDP socket failed: opening a socket for discovery: \
             out of files"
        );
    }

    /// Spec §4.2: a name with no address at all.
    #[test]
    fn a_name_with_no_address_says_which_families_were_missing() {
        assert_eq!(
            could_not_resolve("h.example", None),
            "qsh: h.example: could not resolve h.example: no IPv4 or IPv6 address"
        );
        assert_eq!(
            could_not_resolve("h.example", Some("Name or service not known")),
            "qsh: h.example: could not resolve: Name or service not known"
        );
    }

    /// Spec §4.2: the exit 12 summary ends with where the log is.
    #[test]
    fn the_exit_12_summary_ends_with_the_log_path() {
        let addrs = vec![Address {
            host: "a".into(),
            qsh_port: 1,
            ssh: None,
        }];
        let f = vec![Failure {
            addr: 0,
            reasons: vec![Reason::NoAnswer(NoAnswerWhy::Silent { waited_secs: 5 })],
        }];
        let lines = exit_12_summary(&addrs, &f, &[], "alice", std::path::Path::new("/c/qsh/log"));
        assert_eq!(
            lines.last().map(String::as_str),
            Some("qsh: details: /c/qsh/log")
        );
        assert_eq!(
            lines[..lines.len() - 1],
            all_failed(&addrs, &f, &[], "alice")[..]
        );
    }

    #[test]
    fn the_summary_has_a_line_per_address() {
        let addrs = vec![
            Address {
                host: "a".into(),
                qsh_port: 60022,
                ssh: Some(route(0)),
            },
            Address {
                host: "b".into(),
                qsh_port: 61000,
                ssh: None,
            },
        ];
        let failures = vec![
            Failure {
                addr: 0,
                reasons: vec![
                    Reason::NoAnswer(NoAnswerWhy::Silent { waited_secs: 5 }),
                    Reason::Ssh(SshFailure::plain("qshd is not installed")),
                ],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::Refused],
            },
        ];
        let details = vec![
            Detail::default(),
            Detail {
                offered: vec!["/k/id (SHA256:abc)".into()],
                ..Detail::default()
            },
        ];
        assert_eq!(
            all_failed(&addrs, &failures, &details, "alice"),
            vec![
                "qsh: could not connect:".to_string(),
                "qsh:   a:60022: no answer over qsh in 5 s -- qshd is not running there, or a \
                 firewall drops UDP port 60022; ssh: qshd is not installed"
                    .to_string(),
                format!(
                    "qsh:   b:61000: no key was accepted over qsh for account alice \
                     (offered: /k/id (SHA256:abc)){REFUSED_TAIL}"
                ),
            ]
        );
    }

    #[test]
    fn the_summary_says_why_a_name_did_not_resolve_and_that_nothing_was_offered() {
        let addrs = vec![
            Address {
                host: "typo.example".into(),
                qsh_port: 60022,
                ssh: Some(route(0)),
            },
            Address {
                host: "b".into(),
                qsh_port: 1,
                ssh: None,
            },
        ];
        let failures = vec![
            Failure {
                addr: 0,
                reasons: vec![Reason::Unresolved],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::Refused],
            },
        ];
        let details = vec![
            Detail {
                unresolved: Some("Name or service not known".into()),
                ..Detail::default()
            },
            Detail::default(),
        ];
        assert_eq!(
            all_failed(&addrs, &failures, &details, "alice")[1..],
            [
                "qsh:   typo.example:60022: could not resolve: Name or service not known"
                    .to_string(),
                format!(
                    "qsh:   b:1: no key was accepted over qsh for account alice \
                     (offered: none){REFUSED_TAIL}"
                ),
            ]
        );
    }

    /// Spec §4a rule 1, word for word, and the two fingerprints below it.
    #[test]
    fn pins_that_disagree_name_both_addresses_the_file_and_both_fingerprints() {
        use sshauth::known_hosts::key_fingerprint;
        let text = pins_disagree(
            "a:1",
            &[1u8; 32],
            "b:2",
            &[2u8; 32],
            std::path::Path::new("/c/qsh/known_hosts"),
        );
        assert_eq!(
            text,
            format!(
                "qsh: a:1 and b:2 are on one command line but have different server keys \
                 pinned -- they are not one server; remove the stale line for one of them from \
                 /c/qsh/known_hosts\n  a:1 is pinned to {}; b:2 is pinned to {}",
                key_fingerprint(&[1u8; 32]),
                key_fingerprint(&[2u8; 32])
            )
        );
    }

    /// Spec §4a rule 2, word for word: one line.
    #[test]
    fn the_same_server_is_one_line() {
        assert_eq!(
            same_server("127.0.0.2:60022", "127.0.0.1:60022"),
            "qsh: 127.0.0.2:60022: the same server as 127.0.0.1:60022 -- key remembered"
        );
    }

    /// Spec §4a rule 3, word for word, and the two fingerprints on the line
    /// below -- never the keys themselves.
    #[test]
    fn another_server_names_both_addresses_and_both_fingerprints() {
        use sshauth::known_hosts::key_fingerprint;
        let text = not_the_same_server("b:2", "a:1", &[1u8; 32], &[2u8; 32]);
        assert_eq!(
            text,
            format!(
                "qsh: b:2 answers with a different server key than a:1 -- not the same \
                 server; check the addresses on the command line\n  a:1 is pinned to {}; b:2 \
                 offers {}",
                key_fingerprint(&[1u8; 32]),
                key_fingerprint(&[2u8; 32])
            )
        );
    }

    #[test]
    fn every_reason_reads_as_words() {
        let addrs = vec![Address {
            host: "a".into(),
            qsh_port: 1,
            ssh: None,
        }];
        let f = vec![Failure {
            addr: 0,
            reasons: vec![
                Reason::NoAnswerAfterSsh {
                    port: 60111,
                    why: NoAnswerWhy::KeyedButSilent,
                },
                Reason::RefusedAfterSsh,
                Reason::Unresolved,
            ],
        }];
        assert_eq!(
            all_failed(&addrs, &f, &[], "u")[1],
            "qsh:   a:1: on the port qshd reported (60111): qshd answered the key request but \
             not the login -- a different qsh version, or the daemon is overloaded; its log \
             says more; the qshd started over ssh did not admit the key it was given (a \
             session limit, or another account owns the session) -- qshd's log says which; \
             could not resolve a: no IPv4 or IPv6 address"
        );
    }
}
