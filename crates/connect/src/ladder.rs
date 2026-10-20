//! The ladder of one connection attempt over a list of addresses (spec §4.1):
//! for each address, qsh directly; if that does not work and the address has
//! SSH, bring the daemon up over SSH; then qsh again on the port the daemon
//! reported. During login a changed server key or a person declining it ends
//! the whole ladder. Recovery treats a mismatched key as a failed address.
//!
//! The same ladder also runs in the background, behind a live terminal, when
//! a session is being reconnected (spec §5.2): nobody is asked anything
//! there, so a step that would need a question is skipped instead
//! (`NeedsPrompt`), and a login that lands in a fresh session means the one
//! being returned to is gone (`SessionGone`).

/// Where a daemon may be reached.
#[derive(Clone, PartialEq, Eq)]
pub struct Address {
    pub host: String,
    pub qsh_port: u16,
    /// `None`: this address has no SSH fallback.
    pub ssh: Option<SshRoute>,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("host", &self.host)
            .field("qsh_port", &self.qsh_port)
            .field("ssh", &self.ssh)
            .finish()
    }
}

/// SSH to the same host, with an optional knock before it.
#[derive(Clone, PartialEq, Eq)]
pub struct SshRoute {
    pub port: u16,
    /// Empty: no knock. A knock's ports and data are a secret: never shown.
    pub knock: Vec<knock::KnockStep>,
}

impl std::fmt::Debug for SshRoute {
    // Only the number of knock steps, never their ports or data.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SshRoute {{ port: {}, knock: {} steps }}",
            self.port,
            self.knock.len()
        )
    }
}

/// Who can be asked while the ladder runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Logging in: a person is there to answer.
    Login,
    /// Reconnecting behind a session: nobody is asked anything.
    Background,
}

/// What the client observed when qsh got no answer at an address. The
/// server never refuses out loud (`docs/protocol.md` §2.3, §3.4), so this
/// is the whole story the client can tell -- facts, not the server's
/// reasons. Data only: the words for a person are the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoAnswerWhy {
    /// Noise authenticated an incompatible handshake protocol.
    UnsupportedProtocol { supported: u8 },
    /// Noise authenticated a profile missing required capabilities.
    MissingRequiredFeatures { required: u32, enabled: u32 },
    /// An authenticated handshake payload violated the protocol.
    InvalidProtocol,
    /// The network explicitly refused this UDP destination before a handshake.
    PortRefused,
    /// The OS refused to send to `to`; `os_error` is its own words, e.g.
    /// `No route to host (os error 65)`. `local_network_hint`: on macOS,
    /// to a local address, this is how a denied Local Network permission
    /// looks.
    SendFailed {
        to: std::net::SocketAddr,
        os_error: String,
        local_network_hint: bool,
    },
    /// Nothing came back in `waited_secs`.
    Silent { waited_secs: u64 },
    /// The daemon answered the key request, and then not the login.
    KeyedButSilent,
    /// Something answered on the port, and it was not a qshd key offer.
    NotQshd { reason: String },
    /// Only an IPv6 address to dial; qsh speaks IPv4. `literal`: the
    /// address was written as one, rather than a name resolving to it.
    Ipv6Only { literal: bool },
    /// The client's own UDP socket failed (opening it, reading from it).
    Socket { reason: String },
}

/// How a qsh login went (steps 1 and 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectOutcome {
    Connected,
    /// Explicit authenticated terminal server failure; no fallback is useful.
    SessionAborted {
        reason: u8,
    },
    /// No handshake: nothing answered qsh there, as far as can be seen.
    NoAnswer(NoAnswerWhy),
    /// The host name does not resolve: nothing can be tried there, ssh
    /// included.
    Unresolved,
    /// qsh answered and took none of the keys.
    Refused,
    /// The server's key is not the one pinned for it.
    KeyChanged,
    /// The person did not trust the server's key.
    Declined,
    /// Background only: going on would mean asking a person (a server key
    /// nobody has trusted yet).
    NeedsPrompt,
    /// Background only: the login worked, but into a fresh session -- the
    /// one being returned to is no longer on the server.
    SessionGone,
}

/// Why the SSH step failed: its own words, and whether the failure looks
/// like a denied Local Network permission (macOS, no route to a local
/// address) -- a fact for the caller to word once, not a suffix of `why`.
/// The local condition callers may preserve for their existing retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshFailureCause {
    Other,
    CryptoBusy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshFailure {
    pub why: String,
    pub local_network_hint: bool,
    pub cause: SshFailureCause,
}

impl SshFailure {
    /// A failure with nothing to hint at.
    pub fn plain(why: impl Into<String>) -> SshFailure {
        SshFailure {
            why: why.into(),
            local_network_hint: false,
            cause: SshFailureCause::Other,
        }
    }
}

/// How the SSH step went (step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshOutcome {
    /// The person declined installing the missing daemon during login.
    InstallDeclined,
    /// The daemon is up and listens on `port`.
    Ready { port: u16 },
    /// Why not, in the step's own words.
    Failed(SshFailure),
    /// Background only: the step would have to ask a person (an unknown
    /// host key, a password, a passphrase).
    NeedsPrompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Direct(DirectOutcome),
    Ssh(SshOutcome),
}

/// Why one step of an address did not get through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    NoAnswer(NoAnswerWhy),
    /// The host name did not resolve.
    Unresolved,
    Refused,
    /// This address did not prove the existing session's server identity.
    IdentityMismatch,
    Ssh(SshFailure),
    /// No answer on `port`, the one the daemon brought up over ssh reported.
    NoAnswerAfterSsh {
        port: u16,
        why: NoAnswerWhy,
    },
    RefusedAfterSsh,
    /// A step was skipped: it needed a question, and nobody is asked in the background.
    NeedsPrompt,
}

/// Everything that went wrong at one address, step by step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub addr: usize,
    pub reasons: Vec<Reason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GiveUp {
    SessionAborted {
        addr: usize,
        reason: u8,
    },
    KeyChanged {
        addr: usize,
    },
    Declined {
        addr: usize,
    },
    /// Background only: the session is gone from the server.
    SessionGone {
        addr: usize,
    },
    /// One entry per address, in order.
    AllFailed(Vec<Failure>),
}

/// What the caller does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    TryDirect { addr: usize },
    TrySsh { addr: usize },
    TryDirectAfterSsh { addr: usize, port: u16 },
    Connected { addr: usize, port: u16 },
    GiveUp(GiveUp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Direct,
    Ssh,
    AfterSsh { port: u16 },
    Over,
}

pub struct Ladder {
    addrs: Vec<Address>,
    mode: Mode,
    /// Indices into `addrs`, in the order they are tried.
    order: Vec<usize>,
    /// Position in `order`.
    pos: usize,
    /// `order[pos]`, kept at hand.
    at: usize,
    step: Step,
    reasons: Vec<Reason>,
    failures: Vec<Failure>,
}

impl Ladder {
    /// Logging in: the addresses in command-line order.
    pub fn new(addrs: Vec<Address>) -> Ladder {
        Ladder::with(addrs, 0, Mode::Login)
    }

    /// A reconnect round: `first` -- where the session last worked -- then
    /// every other address in command-line order. A `first` past the end
    /// means no preference.
    pub fn background(addrs: Vec<Address>, first: usize) -> Ladder {
        Ladder::with(addrs, first, Mode::Background)
    }

    fn with(addrs: Vec<Address>, first: usize, mode: Mode) -> Ladder {
        let n = addrs.len();
        let mut order = Vec::with_capacity(n);
        if first < n {
            order.push(first);
        }
        order.extend((0..n).filter(|&i| i != first));
        let step = if order.is_empty() {
            Step::Over
        } else {
            Step::Direct
        };
        let at = order.first().copied().unwrap_or(0);
        Ladder {
            addrs,
            mode,
            order,
            pos: 0,
            at,
            step,
            reasons: Vec::new(),
            failures: Vec::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn addresses(&self) -> &[Address] {
        &self.addrs
    }

    /// The first action; `on` gives every one after it.
    pub fn first(&self) -> Action {
        match self.order.first() {
            None => Action::GiveUp(GiveUp::AllFailed(Vec::new())),
            Some(&addr) => Action::TryDirect { addr },
        }
    }

    pub fn on(&mut self, outcome: Outcome) -> Action {
        match (self.step, outcome) {
            (Step::Over, _) => panic!("the ladder is over: nothing follows Connected or GiveUp"),
            (Step::Direct, Outcome::Direct(o)) => match o {
                DirectOutcome::Connected => self.end(Action::Connected {
                    addr: self.at,
                    port: self.addrs[self.at].qsh_port,
                }),
                DirectOutcome::SessionAborted { reason } => {
                    self.end(Action::GiveUp(GiveUp::SessionAborted {
                        addr: self.at,
                        reason,
                    }))
                }
                DirectOutcome::KeyChanged => self.key_changed(),
                DirectOutcome::Declined => {
                    self.not_in(
                        Mode::Background,
                        "Declined: nobody is asked in the background",
                    );
                    self.end(Action::GiveUp(GiveUp::Declined { addr: self.at }))
                }
                // The same question would come back after ssh: skip the address.
                DirectOutcome::NeedsPrompt => {
                    self.not_in(Mode::Login, "NeedsPrompt happens only in the background");
                    self.reasons.push(Reason::NeedsPrompt);
                    self.next_address()
                }
                DirectOutcome::SessionGone => {
                    self.not_in(Mode::Login, "SessionGone happens only in the background");
                    self.end(Action::GiveUp(GiveUp::SessionGone { addr: self.at }))
                }
                // ssh to a name that does not resolve cannot work either.
                DirectOutcome::Unresolved => {
                    self.reasons.push(Reason::Unresolved);
                    self.next_address()
                }
                DirectOutcome::NoAnswer(_) | DirectOutcome::Refused => {
                    self.reasons.push(match o {
                        DirectOutcome::NoAnswer(why) => Reason::NoAnswer(why),
                        _ => Reason::Refused,
                    });
                    if self.addrs[self.at].ssh.is_some() {
                        self.step = Step::Ssh;
                        Action::TrySsh { addr: self.at }
                    } else {
                        self.next_address()
                    }
                }
            },
            (Step::Ssh, Outcome::Ssh(o)) => match o {
                SshOutcome::InstallDeclined => {
                    self.not_in(
                        Mode::Background,
                        "installation is never offered in the background",
                    );
                    self.end(Action::GiveUp(GiveUp::Declined { addr: self.at }))
                }
                SshOutcome::Ready { port } => {
                    self.step = Step::AfterSsh { port };
                    Action::TryDirectAfterSsh {
                        addr: self.at,
                        port,
                    }
                }
                SshOutcome::Failed(why) => {
                    self.reasons.push(Reason::Ssh(why));
                    self.next_address()
                }
                SshOutcome::NeedsPrompt => {
                    self.not_in(
                        Mode::Login,
                        "ssh's NeedsPrompt happens only in the background",
                    );
                    self.reasons.push(Reason::NeedsPrompt);
                    self.next_address()
                }
            },
            (Step::AfterSsh { port }, Outcome::Direct(o)) => match o {
                DirectOutcome::Connected => self.end(Action::Connected {
                    addr: self.at,
                    port,
                }),
                DirectOutcome::SessionAborted { reason } => {
                    self.end(Action::GiveUp(GiveUp::SessionAborted {
                        addr: self.at,
                        reason,
                    }))
                }
                DirectOutcome::KeyChanged => self.key_changed(),
                DirectOutcome::Declined => {
                    self.not_in(
                        Mode::Background,
                        "Declined: nobody is asked in the background",
                    );
                    self.end(Action::GiveUp(GiveUp::Declined { addr: self.at }))
                }
                // The same question would come back after ssh: skip the address.
                DirectOutcome::NeedsPrompt => {
                    self.not_in(Mode::Login, "NeedsPrompt happens only in the background");
                    self.reasons.push(Reason::NeedsPrompt);
                    self.next_address()
                }
                DirectOutcome::SessionGone => {
                    self.not_in(Mode::Login, "SessionGone happens only in the background");
                    self.end(Action::GiveUp(GiveUp::SessionGone { addr: self.at }))
                }
                DirectOutcome::Unresolved => {
                    self.reasons.push(Reason::Unresolved);
                    self.next_address()
                }
                DirectOutcome::NoAnswer(why) => {
                    self.reasons.push(Reason::NoAnswerAfterSsh { port, why });
                    self.next_address()
                }
                DirectOutcome::Refused => {
                    self.reasons.push(Reason::RefusedAfterSsh);
                    self.next_address()
                }
            },
            (step, outcome) => {
                panic!("an outcome of a different step: {outcome:?} while at {step:?}")
            }
        }
    }

    fn key_changed(&mut self) -> Action {
        if self.mode == Mode::Background {
            self.reasons.push(Reason::IdentityMismatch);
            self.next_address()
        } else {
            self.end(Action::GiveUp(GiveUp::KeyChanged { addr: self.at }))
        }
    }

    /// An outcome that cannot happen in `mode` is the caller's bug.
    fn not_in(&self, mode: Mode, what: &str) {
        if self.mode == mode {
            panic!("{what}");
        }
    }

    fn next_address(&mut self) -> Action {
        self.failures.push(Failure {
            addr: self.at,
            reasons: std::mem::take(&mut self.reasons),
        });
        self.pos += 1;
        if let Some(&next) = self.order.get(self.pos) {
            self.at = next;
            self.step = Step::Direct;
            Action::TryDirect { addr: next }
        } else {
            let all_failed = std::mem::take(&mut self.failures);
            self.end(Action::GiveUp(GiveUp::AllFailed(all_failed)))
        }
    }

    fn end(&mut self, action: Action) -> Action {
        self.step = Step::Over;
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_only(host: &str) -> Address {
        Address {
            host: host.into(),
            qsh_port: 60022,
            ssh: None,
        }
    }

    fn with_ssh(host: &str) -> Address {
        Address {
            host: host.into(),
            qsh_port: 60022,
            ssh: Some(SshRoute {
                port: 22,
                knock: Vec::new(),
            }),
        }
    }

    use DirectOutcome as D;
    use SshOutcome as S;

    fn silent() -> NoAnswerWhy {
        NoAnswerWhy::Silent { waited_secs: 5 }
    }

    fn d(o: DirectOutcome) -> Outcome {
        Outcome::Direct(o)
    }
    fn s(o: SshOutcome) -> Outcome {
        Outcome::Ssh(o)
    }

    #[test]
    fn a_background_identity_mismatch_tries_the_next_address() {
        let mut ladder = Ladder::background(vec![with_ssh("first"), with_ssh("second")], 0);
        assert_eq!(ladder.on(d(D::KeyChanged)), Action::TryDirect { addr: 1 });
        assert_eq!(
            ladder.on(d(D::Connected)),
            Action::Connected {
                addr: 1,
                port: 60022
            }
        );
    }

    #[test]
    fn a_background_identity_mismatch_after_ssh_tries_the_next_address() {
        let mut ladder = Ladder::background(vec![with_ssh("first"), with_ssh("second")], 0);
        assert_eq!(ladder.on(d(D::Refused)), Action::TrySsh { addr: 0 });
        ladder.on(s(S::Ready { port: 60001 }));
        assert_eq!(ladder.on(d(D::KeyChanged)), Action::TryDirect { addr: 1 });
    }

    #[test]
    fn declining_installation_stops_all_remaining_addresses() {
        let mut ladder = Ladder::new(vec![with_ssh("first"), with_ssh("second")]);
        assert_eq!(
            ladder.on(d(D::NoAnswer(silent()))),
            Action::TrySsh { addr: 0 }
        );
        assert_eq!(
            ladder.on(s(S::InstallDeclined)),
            Action::GiveUp(GiveUp::Declined { addr: 0 })
        );
    }

    #[test]
    fn the_first_address_is_tried_directly() {
        let l = Ladder::new(vec![direct_only("a"), direct_only("b")]);
        assert_eq!(l.first(), Action::TryDirect { addr: 0 });
    }

    #[test]
    fn a_direct_login_ends_the_ladder_on_the_address_s_own_port() {
        let mut l = Ladder::new(vec![direct_only("a")]);
        assert_eq!(
            l.on(d(D::Connected)),
            Action::Connected {
                addr: 0,
                port: 60022
            }
        );
    }

    #[test]
    fn no_answer_without_ssh_goes_to_the_next_address() {
        let mut l = Ladder::new(vec![direct_only("a"), direct_only("b")]);
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::TryDirect { addr: 1 }
        );
    }

    #[test]
    fn no_answer_with_ssh_goes_to_ssh() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        assert_eq!(l.on(d(D::NoAnswer(silent()))), Action::TrySsh { addr: 0 });
    }

    #[test]
    fn a_refusal_with_ssh_goes_to_ssh_too() {
        let mut l = Ladder::new(vec![with_ssh("a")]);
        assert_eq!(l.on(d(D::Refused)), Action::TrySsh { addr: 0 });
    }

    #[test]
    fn an_unresolved_name_goes_to_the_next_address_without_ssh() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        assert_eq!(l.on(d(D::Unresolved)), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::Unresolved]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn a_name_that_stops_resolving_after_ssh_moves_on() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 60000 }));
        assert_eq!(l.on(d(D::Unresolved)), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::NoAnswer(silent()), Reason::Unresolved]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn a_ready_daemon_is_tried_on_the_port_it_reported() {
        let mut l = Ladder::new(vec![with_ssh("a")]);
        l.on(d(D::NoAnswer(silent())));
        assert_eq!(
            l.on(s(S::Ready { port: 60000 })),
            Action::TryDirectAfterSsh {
                addr: 0,
                port: 60000
            }
        );
        assert_eq!(
            l.on(d(D::Connected)),
            Action::Connected {
                addr: 0,
                port: 60000
            }
        );
    }

    #[test]
    fn after_ssh_a_failure_moves_on_without_ssh_again() {
        let mut l = Ladder::new(vec![with_ssh("a"), with_ssh("b")]);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 60000 }));
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::TryDirect { addr: 1 }
        );
    }

    #[test]
    fn a_failed_ssh_step_moves_on() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        l.on(d(D::Refused));
        assert_eq!(
            l.on(s(S::Failed(SshFailure::plain("qshd is not installed")))),
            Action::TryDirect { addr: 1 }
        );
    }

    #[test]
    fn a_changed_key_ends_everything_at_either_qsh_step() {
        let mut l = Ladder::new(vec![direct_only("a"), direct_only("b")]);
        assert_eq!(
            l.on(d(D::KeyChanged)),
            Action::GiveUp(GiveUp::KeyChanged { addr: 0 })
        );

        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 1 }));
        assert_eq!(
            l.on(d(D::KeyChanged)),
            Action::GiveUp(GiveUp::KeyChanged { addr: 0 })
        );
    }

    #[test]
    fn declining_the_key_ends_everything() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        assert_eq!(
            l.on(d(D::Declined)),
            Action::GiveUp(GiveUp::Declined { addr: 0 })
        );
    }

    #[test]
    fn when_every_address_fails_each_one_says_why() {
        let mut l = Ladder::new(vec![with_ssh("a"), direct_only("b")]);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 60000 }));
        l.on(d(D::Refused));
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::NoAnswer(silent()), Reason::RefusedAfterSsh]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn the_ssh_failure_text_is_kept() {
        let mut l = Ladder::new(vec![with_ssh("a")]);
        l.on(d(D::Refused));
        assert_eq!(
            l.on(s(S::Failed(SshFailure::plain("qshd is not installed")))),
            Action::GiveUp(GiveUp::AllFailed(vec![Failure {
                addr: 0,
                reasons: vec![
                    Reason::Refused,
                    Reason::Ssh(SshFailure::plain("qshd is not installed"))
                ],
            }]))
        );
    }

    /// What the client observed stays with the address: the summary can say
    /// "cannot send" rather than "no answer".
    #[test]
    fn what_was_observed_is_kept_for_the_summary() {
        let why = NoAnswerWhy::SendFailed {
            to: "192.168.0.200:60200".parse().expect("addr"),
            os_error: "No route to host (os error 65)".into(),
            local_network_hint: true,
        };
        let mut l = Ladder::new(vec![direct_only("a")]);
        assert_eq!(
            l.on(d(D::NoAnswer(why.clone()))),
            Action::GiveUp(GiveUp::AllFailed(vec![Failure {
                addr: 0,
                reasons: vec![Reason::NoAnswer(why)],
            }]))
        );
    }

    /// After ssh, the port tried is the one the daemon reported, and the
    /// reason names it.
    #[test]
    fn no_answer_after_ssh_names_the_port_the_daemon_reported() {
        let mut l = Ladder::new(vec![with_ssh("a")]);
        l.on(d(D::NoAnswer(NoAnswerWhy::Ipv6Only { literal: false })));
        l.on(s(S::Ready { port: 60111 }));
        assert_eq!(
            l.on(d(D::NoAnswer(NoAnswerWhy::KeyedButSilent))),
            Action::GiveUp(GiveUp::AllFailed(vec![Failure {
                addr: 0,
                reasons: vec![
                    Reason::NoAnswer(NoAnswerWhy::Ipv6Only { literal: false }),
                    Reason::NoAnswerAfterSsh {
                        port: 60111,
                        why: NoAnswerWhy::KeyedButSilent
                    },
                ],
            }]))
        );
    }

    #[test]
    fn no_addresses_gives_up_at_once() {
        assert_eq!(
            Ladder::new(vec![]).first(),
            Action::GiveUp(GiveUp::AllFailed(vec![]))
        );
    }

    #[test]
    #[should_panic(expected = "outcome of a different step")]
    fn an_outcome_of_the_wrong_step_is_a_caller_bug() {
        let mut l = Ladder::new(vec![direct_only("a")]);
        l.on(s(S::Ready { port: 1 }));
    }

    #[test]
    #[should_panic(expected = "ladder is over")]
    fn nothing_follows_the_end() {
        let mut l = Ladder::new(vec![direct_only("a")]);
        l.on(d(D::Connected));
        l.on(d(D::Connected));
    }

    #[test]
    fn an_address_debug_never_shows_knock_data() {
        let a = Address {
            host: "h".into(),
            qsh_port: 1,
            ssh: Some(SshRoute {
                port: 22,
                knock: vec![knock::KnockStep {
                    protocol: knock::KnockProtocol::Udp,
                    port: 7000,
                    payload: b"open-sesame".to_vec(),
                    delay_after_ms: 0,
                }],
            }),
        };
        let text = format!("{a:?}");
        assert!(
            !text.contains("open-sesame") && !text.contains("7000"),
            "{text}"
        );
        assert!(text.contains("knock: 1 steps"), "{text}");
    }

    #[test]
    fn the_background_starts_where_the_session_last_worked() {
        let mut l = Ladder::background(
            vec![direct_only("a"), direct_only("b"), direct_only("c")],
            1,
        );
        assert_eq!(l.mode(), Mode::Background);
        assert_eq!(l.first(), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::TryDirect { addr: 0 }
        );
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::TryDirect { addr: 2 }
        );
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
                Failure {
                    addr: 0,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
                Failure {
                    addr: 2,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn a_first_address_out_of_range_is_just_command_line_order() {
        let l = Ladder::background(vec![direct_only("a"), direct_only("b")], 9);
        assert_eq!(l.first(), Action::TryDirect { addr: 0 });
    }

    #[test]
    fn logging_in_is_the_login_mode() {
        assert_eq!(Ladder::new(vec![direct_only("a")]).mode(), Mode::Login);
    }

    #[test]
    fn a_question_needed_in_the_background_skips_the_whole_address() {
        let mut l = Ladder::background(vec![with_ssh("a"), direct_only("b")], 0);
        assert_eq!(l.on(d(D::NeedsPrompt)), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::NeedsPrompt]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn ssh_that_needs_a_question_moves_on_in_the_background() {
        let mut l = Ladder::background(vec![with_ssh("a"), direct_only("b")], 0);
        assert_eq!(l.on(d(D::NoAnswer(silent()))), Action::TrySsh { addr: 0 });
        assert_eq!(l.on(s(S::NeedsPrompt)), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::NoAnswer(silent()))),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::NoAnswer(silent()), Reason::NeedsPrompt]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::NoAnswer(silent())]
                },
            ]))
        );
    }

    #[test]
    fn a_question_after_ssh_moves_on_too() {
        let mut l = Ladder::background(vec![with_ssh("a"), direct_only("b")], 0);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 60000 }));
        assert_eq!(l.on(d(D::NeedsPrompt)), Action::TryDirect { addr: 1 });
    }

    #[test]
    fn a_fresh_session_in_the_background_means_the_old_one_is_gone() {
        let mut l = Ladder::background(vec![direct_only("a"), direct_only("b")], 1);
        assert_eq!(
            l.on(d(D::SessionGone)),
            Action::GiveUp(GiveUp::SessionGone { addr: 1 })
        );

        let mut l = Ladder::background(vec![with_ssh("a")], 0);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::Ready { port: 60000 }));
        assert_eq!(
            l.on(d(D::SessionGone)),
            Action::GiveUp(GiveUp::SessionGone { addr: 0 })
        );
    }

    #[test]
    fn mismatched_background_keys_fail_only_their_addresses() {
        let mut l = Ladder::background(vec![direct_only("a"), direct_only("b")], 0);
        assert_eq!(l.on(d(D::KeyChanged)), Action::TryDirect { addr: 1 });
        assert_eq!(
            l.on(d(D::KeyChanged)),
            Action::GiveUp(GiveUp::AllFailed(vec![
                Failure {
                    addr: 0,
                    reasons: vec![Reason::IdentityMismatch]
                },
                Failure {
                    addr: 1,
                    reasons: vec![Reason::IdentityMismatch]
                },
            ]))
        );
    }

    #[test]
    fn a_background_connection_ends_on_the_address_s_own_port() {
        let mut l = Ladder::background(vec![direct_only("a"), direct_only("b")], 1);
        assert_eq!(
            l.on(d(D::Connected)),
            Action::Connected {
                addr: 1,
                port: 60022
            }
        );
    }

    #[test]
    #[should_panic(expected = "nobody is asked in the background")]
    fn nobody_declines_in_the_background() {
        let mut l = Ladder::background(vec![direct_only("a")], 0);
        l.on(d(D::Declined));
    }

    #[test]
    #[should_panic(expected = "happens only in the background")]
    fn a_login_never_needs_a_prompt_it_could_not_ask() {
        let mut l = Ladder::new(vec![direct_only("a")]);
        l.on(d(D::NeedsPrompt));
    }

    #[test]
    #[should_panic(expected = "happens only in the background")]
    fn a_login_never_finds_its_session_gone() {
        let mut l = Ladder::new(vec![direct_only("a")]);
        l.on(d(D::SessionGone));
    }

    #[test]
    #[should_panic(expected = "happens only in the background")]
    fn a_login_s_ssh_never_needs_a_prompt_it_could_not_ask() {
        let mut l = Ladder::new(vec![with_ssh("a")]);
        l.on(d(D::NoAnswer(silent())));
        l.on(s(S::NeedsPrompt));
    }
    #[test]
    fn capacity_ladder_abort_stops_keys_addresses_and_ssh_fallback() {
        for background in [false, true] {
            for after_ssh in [false, true] {
                let addresses = vec![with_ssh("first.example"), with_ssh("second.example")];
                let mut ladder = if background {
                    Ladder::background(addresses, 0)
                } else {
                    Ladder::new(addresses)
                };
                if after_ssh {
                    assert_eq!(ladder.on(d(D::Refused)), Action::TrySsh { addr: 0 });
                    assert!(matches!(
                        ladder.on(s(S::Ready { port: 60001 })),
                        Action::TryDirectAfterSsh { .. }
                    ));
                }
                assert_eq!(
                    ladder.on(d(D::SessionAborted { reason: 1 })),
                    Action::GiveUp(GiveUp::SessionAborted { addr: 0, reason: 1 })
                );
            }
        }
    }
}
