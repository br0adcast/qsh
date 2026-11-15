//! Foreground busy-daemon choices before registration and handshake.
use crate::prompt::Tty;
use bringup::{BusyChoice, BusyDaemonInfo, BusyDecision, DestructiveRestartConsent, PendingBusy};

pub const LEGACY_WARNING: &str = "This daemon cannot preserve its active qsh sessions during the update. All active qsh sessions will be interrupted, and running commands may terminate.";

pub enum RestartConsent {
    Exact(DestructiveRestartConsent),
    Service(bringup::ServiceRestartConsent),
}
impl RestartConsent {
    fn matches(&self, info: &BusyDaemonInfo) -> bool {
        match self {
            Self::Exact(consent) => consent.matches(info),
            Self::Service(consent) => consent.matches(info),
        }
    }
}
fn service_warning(account: &str, host: &str) -> String {
    format!("Restart the personal qshd service for account {} on {}. All active qsh sessions for this service will be interrupted, and running commands may terminate. This also applies if the service process changes while this dialog is open.", crate::report::printable(account), crate::report::printable(host))
}
fn parse_choice(input: Option<&str>) -> BusyChoice {
    match input.map(str::trim) {
        Some("2") => BusyChoice::ContinueOld,
        Some("3") => BusyChoice::ForceUpdate,
        _ => BusyChoice::Cancel,
    }
}
fn question(info: &BusyDaemonInfo) -> String {
    format!("Running qshd {} has {} active connections. The new daemon cannot start while these connections are active.\n\n1. Cancel (default)\n2. Continue with old daemon\n3. Force update\nChoose [1]:", crate::report::printable(&info.identity.version), info.active_connections)
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
    let mut choice = parse_choice(answer.as_deref());
    let consent = if choice == BusyChoice::ForceUpdate {
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
            schema: 2,
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
            serving_profiles: None,
            preservation: bringup::PreservationCapability::Unknown,
            service_restart: None,
        }
    }
    #[test]
    fn service_confirmation_survives_instance_change_but_not_selector_change() {
        let mut live = info();
        live.schema = 2;
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
            live.schema = 2;
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
        for input in [
            None,
            Some(""),
            Some("\x1b"),
            Some("back"),
            Some("9"),
            Some("yes"),
        ] {
            assert_eq!(parse_choice(input), bringup::BusyChoice::Cancel);
        }
        assert_eq!(parse_choice(Some("2")), bringup::BusyChoice::ContinueOld);
        assert_eq!(parse_choice(Some("3")), bringup::BusyChoice::ForceUpdate);
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
        assert_eq!(LEGACY_WARNING, "This daemon cannot preserve its active qsh sessions during the update. All active qsh sessions will be interrupted, and running commands may terminate.");
    }
}
