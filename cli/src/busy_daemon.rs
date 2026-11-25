//! Foreground busy-daemon choices before registration and handshake.
use crate::prompt::Tty;
use bringup::{
    BusyChoice, BusyDaemonInfo, BusyDecision, DestructiveRestartConsent, FrontendUpgradeConsent,
    PendingBusy, UpgradeCase,
};

pub const LEGACY_WARNING: &str = "This qshd cannot preserve sessions during an update. Active sessions will be interrupted and running commands may terminate.";

pub enum RestartConsent {
    Exact(DestructiveRestartConsent),
    Service(bringup::ServiceRestartConsent),
    FrontendUpgrade(FrontendUpgradeConsent),
}
impl RestartConsent {
    fn matches(&self, info: &BusyDaemonInfo) -> bool {
        match self {
            Self::Exact(consent) => consent.matches(info),
            Self::Service(consent) => consent.matches(info),
            Self::FrontendUpgrade(consent) => consent.matches(info),
        }
    }
}
pub fn required_profile() -> [u8; 3] {
    [
        transport::wire::VERSION,
        transport::handshake_payload::HS_VERSION,
        transport::channel::PROTOCOL_VERSION,
    ]
}

pub fn can_continue_old(info: &BusyDaemonInfo) -> bool {
    info.supports_profile(required_profile())
}

fn service_warning(account: &str, host: &str) -> String {
    format!(
        "Restart the personal qshd service for {} on {}? Active sessions on this service will be interrupted and running commands may terminate, even if the service process changes.",
        crate::report::printable(account),
        crate::report::printable(host)
    )
}
fn parse_choice(input: Option<&str>, allow_continue: bool) -> BusyChoice {
    match (allow_continue, input.map(str::trim)) {
        (true, Some("2")) => BusyChoice::ContinueOld,
        (true, Some("3")) | (false, Some("2")) => BusyChoice::ForceUpdate,
        _ => BusyChoice::Cancel,
    }
}
fn question(info: &BusyDaemonInfo) -> String {
    let version = crate::report::printable(&info.identity.version);
    let allow_continue = can_continue_old(info);
    if let Some(offer) = &info.upgrade {
        // An offer that strands sessions may disconnect nobody.
        let disconnected = if offer.attached > 0 {
            format!(
                " {} other client(s) will briefly reconnect (up to a minute for older clients).",
                offer.attached
            )
        } else {
            String::new()
        };
        if allow_continue {
            return format!("qshd {version} can update and keep all sessions.{disconnected}\n\n1. Cancel (default)\n2. Continue with old daemon\n3. Update and keep sessions\nChoose [1]:");
        }
        return format!("qshd {version} does not speak this client's protocol. It can update and keep all sessions.{disconnected}\n\n1. Cancel (default)\n2. Update and keep sessions\nChoose [1]:");
    }
    if info.active_connections == 0 && info.sessions > 0 {
        if allow_continue {
            return format!("qshd {version} has {} detached session(s).\n\n1. Cancel (default)\n2. Continue with old daemon\n3. Force update\nChoose [1]:", info.sessions);
        }
        return format!("qshd {version} has {} detached session(s) and does not speak this client's protocol.\n\n1. Cancel (default)\n2. Force update\nChoose [1]:", info.sessions);
    }
    // A host also counts the sessions whose client is away.
    let retained = info.sessions.saturating_sub(info.active_connections);
    let others = if retained > 0 {
        format!(" and {retained} detached session(s)")
    } else {
        String::new()
    };
    if allow_continue {
        format!("qshd {version} has {} active connections{others}.\n\n1. Cancel (default)\n2. Continue with old daemon\n3. Force update\nChoose [1]:", info.active_connections)
    } else {
        format!("qshd {version} has {} active connections{others} and does not speak this client's protocol.\n\n1. Cancel (default)\n2. Force update\nChoose [1]:", info.active_connections)
    }
}
/// The second warning for an upgrade that leaves sessions unreachable.
fn unreachable_warning(info: &BusyDaemonInfo) -> Option<String> {
    let offer = info.upgrade.as_ref()?;
    Some(format!("{} of {} session(s) belong to older clients that cannot reconnect after the update (their commands keep running until they exit).\n\n1. Cancel (default)\n2. Update anyway\nChoose [1]:", offer.stranded, offer.sessions))
}
struct BusyPrompt {
    pending: Option<PendingBusy>,
}
impl BusyPrompt {
    fn new(info: BusyDaemonInfo) -> Option<Self> {
        Some(Self {
            pending: Some(PendingBusy::new(info)?),
        })
    }
    fn resolve(&mut self, expected: &BusyDaemonInfo, choice: BusyChoice) -> Option<BusyDecision> {
        let pending = self.pending.as_ref()?;
        if pending.info().attempt != expected.attempt
            || pending.info().identity != expected.identity
            || pending.info().candidate != expected.candidate
            || pending.info().service_restart != expected.service_restart
        {
            return None;
        }
        if choice == BusyChoice::ContinueOld && !can_continue_old(pending.info()) {
            return None;
        }
        Some(self.pending.take()?.decide(choice))
    }
}
fn legacy_consent(info: &BusyDaemonInfo, answer: Option<&str>) -> Option<RestartConsent> {
    if answer.map(str::trim) != Some("2") {
        return None;
    }
    let consent = match info.confirm_service_restart() {
        Some(consent) => RestartConsent::Service(consent),
        None => RestartConsent::Exact(info.confirm_destructive_restart()),
    };
    consent.matches(info).then_some(consent)
}
#[cfg(test)]
pub fn ask(
    tty: &Tty,
    info: BusyDaemonInfo,
    cancel: &knock::Cancel,
) -> Result<(BusyDecision, Option<RestartConsent>), ssh::SshError> {
    ask_for_target(tty, info, "this account", "the verified SSH server", cancel)
}
pub fn ask_for_target(
    tty: &Tty,
    info: BusyDaemonInfo,
    account: &str,
    host: &str,
    cancel: &knock::Cancel,
) -> Result<(BusyDecision, Option<RestartConsent>), ssh::SshError> {
    let mut prompt = BusyPrompt::new(info.clone()).ok_or(ssh::SshError::Cancelled)?;
    let answer = tty.read_choice(&question(&info), cancel)?;
    let mut choice = parse_choice(answer.as_deref(), can_continue_old(&info));
    let upgrade = info
        .upgrade
        .as_ref()
        .filter(|_| choice == BusyChoice::ForceUpdate);
    let consent = if let Some(offer) = upgrade {
        let confirmed = match offer.case {
            UpgradeCase::Unreachable => {
                let warning = unreachable_warning(&info).unwrap_or_default();
                let answer = tty.read_choice(&warning, cancel)?;
                (answer.as_deref().map(str::trim) == Some("2")).then_some(())
            }
            UpgradeCase::Soft => Some(()),
        };
        let consent = confirmed
            .and_then(|()| info.confirm_frontend_upgrade())
            .map(RestartConsent::FrontendUpgrade)
            .filter(|consent| consent.matches(&info));
        if consent.is_none() {
            choice = BusyChoice::Cancel;
        }
        consent
    } else if choice == BusyChoice::ForceUpdate {
        let scope = if info.service_restart.is_some() {
            service_warning(account, host)
        } else {
            LEGACY_WARNING.to_owned()
        };
        let warning = format!(
            "{scope}\n\n1. Cancel (default)\n2. Restart and interrupt sessions\nChoose [1]:"
        );
        let answer = tty.read_choice(&warning, cancel)?;
        let consent = legacy_consent(&info, answer.as_deref());
        if consent.is_none() {
            choice = BusyChoice::Cancel;
        }
        consent
    } else {
        None
    };
    Ok((
        prompt
            .resolve(&info, choice)
            .ok_or(ssh::SshError::Cancelled)?,
        consent,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info() -> bringup::BusyDaemonInfo {
        bringup::BusyDaemonInfo {
            schema: 3,
            attempt: bringup::BusyAttemptId::from_bytes([1; 16]),
            identity: bringup::BusyDaemonIdentity {
                version: "0.5.9".into(),
                build: 1,
                checksum: "ab".repeat(32),
                pid: 42,
                generation: None,
            },
            candidate: bringup::CandidateImageIdentity {
                build: 2,
                checksum: "ef".repeat(32),
            },
            active_connections: 2,
            sessions: 2,
            serving_profiles: Some(vec![required_profile()]),
            preservation: bringup::PreservationCapability::Unknown,
            service_restart: None,
            upgrade: None,
        }
    }
    fn offer_info(case: bringup::UpgradeCase) -> bringup::BusyDaemonInfo {
        let mut live = info();
        live.preservation = bringup::PreservationCapability::PreservesSessions;
        live.active_connections = 3;
        live.sessions = 5;
        live.upgrade = Some(match case {
            bringup::UpgradeCase::Soft => {
                live.sessions = 3;
                bringup::FrontendUpgradeOffer {
                    case,
                    attached: 3,
                    sessions: 3,
                    stranded: 0,
                }
            }
            bringup::UpgradeCase::Unreachable => bringup::FrontendUpgradeOffer {
                case,
                attached: 3,
                sessions: 5,
                stranded: 2,
            },
        });
        assert!(live.valid());
        live
    }
    fn answer(
        input: &[u8],
        live: bringup::BusyDaemonInfo,
    ) -> (BusyDecision, Option<RestartConsent>, String) {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let pty = nix::pty::openpty(None, None).unwrap();
        let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
        let mut master = std::fs::File::from(pty.master);
        master.write_all(input).unwrap();
        let (decision, consent) = ask(&tty, live, &knock::Cancel::new()).unwrap();
        assert!(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } >= 0);
        let mut output = String::new();
        let _ = master.read_to_string(&mut output);
        (decision, consent, output)
    }
    #[test]
    fn soft_offer_names_the_clients_and_the_delay() {
        let text = question(&offer_info(bringup::UpgradeCase::Soft));
        for expected in [
            "keep all sessions",
            "3 other client(s)",
            "briefly reconnect",
            "up to a minute",
            "3. Update and keep sessions",
        ] {
            assert!(text.contains(expected), "{text}");
        }
    }
    #[test]
    fn an_offer_that_disconnects_nobody_says_nothing_of_clients() {
        let mut live = offer_info(bringup::UpgradeCase::Unreachable);
        live.active_connections = 0;
        live.upgrade.as_mut().unwrap().attached = 0;
        assert!(live.valid());
        let text = question(&live);
        assert!(text.contains("keep all sessions."), "{text}");
        assert!(!text.contains("other client"), "{text}");
        assert!(!text.contains("reconnect"), "{text}");
        assert!(question(&offer_info(bringup::UpgradeCase::Unreachable))
            .contains("3 other client(s) will briefly reconnect"));
    }
    #[test]
    fn a_destructive_question_names_attached_and_retained_sessions() {
        let mut live = info();
        live.active_connections = 2;
        live.sessions = 5;
        let text = question(&live);
        assert!(
            text.contains("qshd 0.5.9 has 2 active connections and 3 detached session(s)."),
            "{text}"
        );
        // Without retained sessions, as from a daemon that is no host.
        let text = question(&info());
        assert!(
            text.contains("qshd 0.5.9 has 2 active connections."),
            "{text}"
        );
    }
    #[test]
    fn soft_choice_three_gives_an_upgrade_consent_without_a_second_question() {
        let live = offer_info(bringup::UpgradeCase::Soft);
        let (decision, consent, output) = answer(b"3\n", live.clone());
        assert_eq!(decision.choice, BusyChoice::ForceUpdate);
        let Some(RestartConsent::FrontendUpgrade(consent)) = consent else {
            panic!("no upgrade consent")
        };
        assert!(consent.matches(&live));
        assert!(!output.contains("cannot reconnect"), "{output}");
    }
    #[test]
    fn unreachable_needs_the_second_confirmation() {
        let live = offer_info(bringup::UpgradeCase::Unreachable);
        let (decision, consent, output) = answer(b"3\n2\n", live.clone());
        assert_eq!(decision.choice, BusyChoice::ForceUpdate);
        assert!(matches!(consent, Some(RestartConsent::FrontendUpgrade(_))));
        for expected in [
            "2 of 5 session(s) belong to older clients that cannot reconnect",
            "2. Update anyway",
        ] {
            assert!(output.contains(expected), "{output}");
        }
        let (decision, consent, _) = answer(b"3\n\n", live);
        assert_eq!(decision.choice, BusyChoice::Cancel);
        assert!(consent.is_none());
    }
    #[test]
    fn retained_only_destructive_question_counts_sessions() {
        let mut live = info();
        live.active_connections = 0;
        live.sessions = 4;
        let text = question(&live);
        assert!(
            text.contains("qshd 0.5.9 has 4 detached session(s)."),
            "{text}"
        );
        assert!(text.contains("3. Force update"), "{text}");
        let (decision, consent, output) = answer(b"3\n2\n", live.clone());
        assert_eq!(decision.choice, BusyChoice::ForceUpdate);
        assert!(matches!(consent, Some(RestartConsent::Exact(_))));
        assert!(output.contains(LEGACY_WARNING), "{output}");
    }
    #[test]
    fn a_changed_candidate_cannot_answer_an_upgrade_prompt() {
        let live = offer_info(bringup::UpgradeCase::Soft);
        let mut prompt = BusyPrompt::new(live.clone()).unwrap();
        let mut changed = live.clone();
        changed.candidate.build += 1;
        assert!(prompt.resolve(&changed, BusyChoice::ForceUpdate).is_none());
        let consent = live.confirm_frontend_upgrade().unwrap();
        assert!(!RestartConsent::FrontendUpgrade(consent).matches(&changed));
    }
    #[test]
    fn service_confirmation_survives_instance_change_but_not_selector_change() {
        let mut live = info();
        live.schema = 3;
        live.service_restart = Some(bringup::PersonalServiceSelector {
            profile: bringup::PersonalServiceProfile::PersonalTransportV1,
            uid: 1000,
            endpoint: "/fixture/qsh/control.sock".into(),
            port: 60022,
        });
        let consent = legacy_consent(&live, Some("2")).unwrap();
        let mut changed = live.clone();
        changed.identity.pid += 1;
        assert!(
            consent.matches(&changed),
            "explicit service scope includes changed processes"
        );
        changed.service_restart.as_mut().unwrap().port += 1;
        assert!(!consent.matches(&changed));
    }

    #[test]
    fn service_warning_names_verified_target_and_second_cancel_sends_no_consent() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for (input, expected) in [(&b"3\n2\n"[..], true), (&b"3\n\n"[..], false)] {
            let mut live = info();
            live.schema = 3;
            live.service_restart = Some(bringup::PersonalServiceSelector {
                profile: bringup::PersonalServiceProfile::PersonalTransportV1,
                uid: 1000,
                endpoint: "/fixture/qsh/control.sock".into(),
                port: 60022,
            });
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let mut master = std::fs::File::from(pty.master);
            master.write_all(input).unwrap();
            let (decision, consent) = ask_for_target(
                &tty,
                live,
                "fixture-account",
                "verified-host:22",
                &knock::Cancel::new(),
            )
            .unwrap();
            assert_eq!(consent.is_some(), expected);
            assert_eq!(
                decision.choice,
                if expected {
                    BusyChoice::ForceUpdate
                } else {
                    BusyChoice::Cancel
                }
            );
            if let Some(consent) = consent {
                assert!(matches!(consent, RestartConsent::Service(_)));
            }
            assert!(
                unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } >= 0
            );
            let mut output = String::new();
            let _ = master.read_to_string(&mut output);
            for text in [
                "fixture-account",
                "verified-host:22",
                "service process changes",
                "Cancel (default)",
            ] {
                assert!(output.contains(text), "{output}");
            }
        }
    }

    #[test]
    fn pty_choices_leave_canonical_terminal_usable() {
        use std::io::Write;
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (input, expected, confirmed) in [
            (&b"\n"[..], BusyChoice::Cancel, false),
            (&b"2\n"[..], BusyChoice::ContinueOld, false),
            (&b"3\n2\n"[..], BusyChoice::ForceUpdate, true),
            (&b"3\n\n"[..], BusyChoice::Cancel, false),
            (&b"\x04"[..], BusyChoice::Cancel, false),
            (&b"\x1b\n"[..], BusyChoice::Cancel, false),
        ] {
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let before = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
            let mut master = std::fs::File::from(pty.master);
            master.write_all(input).unwrap();
            let (decision, consent) = ask(&tty, info(), &knock::Cancel::new()).unwrap();
            assert_eq!(decision.choice, expected);
            assert_eq!(consent.is_some(), confirmed);
            let after = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
            assert_eq!(after.local_flags, before.local_flags);
            master.write_all(b"still-usable\n").unwrap();
            assert_eq!(
                tty.read_choice("next input", &knock::Cancel::new())
                    .unwrap()
                    .as_deref(),
                Some("still-usable")
            );
        }
    }
    #[test]
    fn missing_terminal_cancels_and_request_cancellation_is_preserved() {
        let tty = Tty::at("/nonexistent/qsh-busy-prompt");
        assert_eq!(
            ask(&tty, info(), &knock::Cancel::new()).unwrap().0.choice,
            BusyChoice::Cancel
        );
        let cancel = knock::Cancel::new();
        cancel.cancel();
        assert!(matches!(
            ask(&tty, info(), &cancel),
            Err(ssh::SshError::Cancelled)
        ));
    }
    #[test]
    fn empty_eof_escape_and_unrecognized_input_cancel() {
        for allow_continue in [true, false] {
            for input in [
                None,
                Some(""),
                Some("\x1b"),
                Some("back"),
                Some("9"),
                Some("yes"),
            ] {
                assert_eq!(
                    parse_choice(input, allow_continue),
                    bringup::BusyChoice::Cancel
                );
            }
        }
        assert_eq!(
            parse_choice(Some("2"), true),
            bringup::BusyChoice::ContinueOld
        );
        assert_eq!(
            parse_choice(Some("3"), true),
            bringup::BusyChoice::ForceUpdate
        );
        assert_eq!(
            parse_choice(Some("2"), false),
            bringup::BusyChoice::ForceUpdate
        );
        assert_eq!(parse_choice(Some("3"), false), bringup::BusyChoice::Cancel);
    }
    #[test]
    fn busy_prompt_has_three_named_actions_and_actual_activity() {
        let text = question(&info());
        for label in [
            "Cancel",
            "Continue with old daemon",
            "Force update",
            "0.5.9",
            "2 active connections",
        ] {
            assert!(text.contains(label), "{text}");
        }
        assert!(!text.contains("safe update"));
    }
    #[test]
    fn incompatible_busy_prompt_omits_continue_old_and_renumbers_update() {
        for profiles in [None, Some(vec![[1, 1, 1]])] {
            let mut legacy = info();
            legacy.identity.version = "0.5.0".into();
            legacy.serving_profiles = profiles.clone();
            let text = question(&legacy);
            assert!(!text.contains("Continue with old daemon"), "{text}");
            for expected in [
                "0.5.0",
                "does not speak this client's protocol",
                "1. Cancel (default)",
                "2. Force update",
            ] {
                assert!(text.contains(expected), "{text}");
            }
            assert!(!text.contains("3. "), "{text}");

            let mut retained = legacy.clone();
            retained.active_connections = 0;
            retained.sessions = 4;
            let text = question(&retained);
            assert!(!text.contains("Continue with old daemon"), "{text}");
            assert!(text.contains("2. Force update"), "{text}");
            assert!(!text.contains("3. "), "{text}");

            let mut offer = offer_info(bringup::UpgradeCase::Soft);
            offer.serving_profiles = profiles;
            let text = question(&offer);
            assert!(!text.contains("Continue with old daemon"), "{text}");
            assert!(text.contains("2. Update and keep sessions"), "{text}");
            assert!(!text.contains("3. "), "{text}");
        }
    }
    #[test]
    fn incompatible_pty_choices_never_continue_old_and_allow_confirmed_force() {
        for profiles in [None, Some(vec![[1, 1, 1]])] {
            let mut live = info();
            live.identity.version = "0.5.0".into();
            live.serving_profiles = profiles;
            for (input, expected, confirmed) in [
                (&b"\n"[..], BusyChoice::Cancel, false),
                (&b"3\n"[..], BusyChoice::Cancel, false),
                (&b"2\n\n"[..], BusyChoice::Cancel, false),
                (&b"2\n2\n"[..], BusyChoice::ForceUpdate, true),
            ] {
                let (decision, consent, output) = answer(input, live.clone());
                assert_eq!(decision.choice, expected);
                assert_eq!(consent.is_some(), confirmed);
                assert!(!output.contains("Continue with old daemon"), "{output}");
            }
        }
    }
    #[test]
    fn busy_prompt_refuses_continue_old_for_incompatible_daemon() {
        for profiles in [None, Some(vec![[1, 1, 1]])] {
            let mut live = info();
            live.serving_profiles = profiles;
            let mut prompt = BusyPrompt::new(live.clone()).unwrap();
            assert!(prompt.resolve(&live, BusyChoice::ContinueOld).is_none());
            assert!(prompt.resolve(&live, BusyChoice::Cancel).is_some());
        }
    }
    #[test]
    fn changed_candidate_cannot_answer_an_old_local_prompt() {
        let live = info();
        let mut prompt = BusyPrompt::new(live.clone()).unwrap();
        let mut changed = live.clone();
        changed.candidate.build += 1;
        assert!(prompt.resolve(&changed, BusyChoice::ForceUpdate).is_none());
        assert!(prompt.resolve(&live, BusyChoice::ContinueOld).is_some());
    }

    #[test]
    fn stale_or_duplicate_local_answers_are_inert() {
        let live = info();
        let mut prompt = BusyPrompt::new(live.clone()).unwrap();
        let mut stale = live.clone();
        stale.identity.pid += 1;
        assert!(prompt
            .resolve(&stale, bringup::BusyChoice::ContinueOld)
            .is_none());
        assert!(prompt
            .resolve(&live, bringup::BusyChoice::ContinueOld)
            .is_some());
        assert!(prompt
            .resolve(&live, bringup::BusyChoice::ForceUpdate)
            .is_none());
    }
    #[test]
    fn only_separate_affirmative_legacy_action_produces_consent() {
        let live = info();
        assert!(legacy_consent(&live, None).is_none());
        assert!(legacy_consent(&live, Some("")).is_none());
        assert!(legacy_consent(&live, Some("3")).is_none());
        assert!(legacy_consent(&live, Some("2")).unwrap().matches(&live));
        assert_eq!(
            LEGACY_WARNING,
            "This qshd cannot preserve sessions during an update. Active sessions will be interrupted and running commands may terminate."
        );
    }
}
