//! Consent policy and presentation at a terminal-owner boundary.
use crate::client_install::{self, UpdateEligibility};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferChoice {
    Update,
    Postpone,
}

pub fn approved_command(choice: OfferChoice, version: &str) -> Option<client_install::Command> {
    (choice == OfferChoice::Update).then(|| client_install::Command {
        update: true,
        version: Some(version.into()),
        prefix: None,
        help: false,
    })
}

fn dispatch(
    choice: OfferChoice,
    version: &str,
    installer: impl FnOnce(&client_install::Command) -> Result<String, String>,
) -> Option<Result<String, String>> {
    approved_command(choice, version).map(|command| installer(&command))
}

/// The terminal owner has already validated and recorded explicit consent.
pub fn install_approved(version: &str) -> Result<String, String> {
    let cancel = knock::Cancel::new();
    crate::signals::with_termination_cancel(&cancel, || {
        dispatch(OfferChoice::Update, version, |command| {
            client_install::run_cancellable(command, &cancel)
        })
        .expect("explicit consent")
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presentation {
    Silent,
    Guidance(String),
    Offer(String),
}

/// Cached context may explain an outage but cannot authorize an update choice.
pub fn with_authority(view: Presentation, version: &str, actionable: bool) -> Presentation {
    if actionable || view == Presentation::Silent {
        return view;
    }
    let context = format!(
        "Last authenticated observation: qshd {}.",
        crate::report::printable(version)
    );
    Presentation::Guidance(match view {
        Presentation::Guidance(line) => format!("{context} {line}"),
        _ => format!("{context} Waiting for fresh discovery before offering a client update."),
    })
}

/// `version` has already passed authenticated release policy.
/// `eligibility` queries package databases, hashes the executable and verifies
/// its receipt, so it runs only when an offer or incompatibility can be shown.
pub fn presentation(
    eligibility: impl FnOnce() -> UpdateEligibility,
    incompatible: bool,
    version: Option<&str>,
) -> Presentation {
    if version.is_none() && !incompatible {
        return Presentation::Silent;
    }
    view(eligibility(), incompatible, version)
}

fn view(eligibility: UpdateEligibility, incompatible: bool, version: Option<&str>) -> Presentation {
    match eligibility {
        UpdateEligibility::SourceBuild => {
            if incompatible {
                Presentation::Guidance(
                    "Update the source and rebuild a compatible qsh client.".into(),
                )
            } else {
                Presentation::Silent
            }
        }
        UpdateEligibility::PackageOwned if version.is_some() || incompatible => {
            Presentation::Guidance("Update qsh through its package manager.".into())
        }
        UpdateEligibility::Unmanaged if version.is_some() || incompatible => {
            Presentation::Guidance(
                "This qsh copy is not a validated managed installation; update it manually.".into(),
            )
        }
        UpdateEligibility::Managed => version
            .and_then(|v| semver::Version::parse(v).ok())
            .map(|mut v| {
                v.build = semver::BuildMetadata::EMPTY;
                Presentation::Offer(v.to_string())
            })
            .unwrap_or(Presentation::Silent),
        _ => Presentation::Silent,
    }
}

/// Must run on the terminal owner with cooked mode and no competing input reader.
/// The execution engine repeats ownership, receipt and artifact checks after consent.
pub fn present(
    tty: &crate::prompt::Tty,
    view: &Presentation,
    still_current: impl Fn() -> bool,
) -> bool {
    match view {
        Presentation::Silent => false,
        Presentation::Guidance(line) => {
            tty.say(line);
            false
        }
        Presentation::Offer(version) => {
            if !tty.confirm(&format!("The authenticated server runs qshd {version}. Update this qsh client to {version}?"))
                || !still_current() { return false; }
            match install_approved(version) {
                Ok(message) => {
                    tty.say(&format!(
                        "{message}\nRelaunch qsh explicitly to use the installed client."
                    ));
                    true
                }
                Err(error) => {
                    tty.say(&format!(
                        "Client update unavailable: {}",
                        crate::report::printable(&error)
                    ));
                    false
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cached_metadata_is_labeled_context_and_never_an_update_choice() {
        let view = view(UpdateEligibility::Managed, true, Some("1.2.3"));
        assert!(
            matches!(with_authority(view,"1.2.3",false),Presentation::Guidance(line)
            if line.starts_with("Last authenticated observation:") && line.contains("Waiting for fresh discovery"))
        );
    }
    #[test]
    fn postpone_has_no_engine_command_and_consent_pins_exact_version() {
        assert!(approved_command(OfferChoice::Postpone, "1.2.3").is_none());
        assert_eq!(
            approved_command(OfferChoice::Update, "1.2.3-rc.2"),
            Some(client_install::Command {
                update: true,
                version: Some("1.2.3-rc.2".into()),
                prefix: None,
                help: false,
            })
        );
    }
    #[test]
    fn installer_boundary_executes_only_explicit_consent_for_the_exact_release() {
        assert!(dispatch(OfferChoice::Postpone, "1.2.3", |_| panic!(
            "postpone invoked installer"
        ))
        .is_none());
        let called = std::cell::Cell::new(0);
        let result = dispatch(OfferChoice::Update, "1.2.3-rc.2", |command| {
            called.set(called.get() + 1);
            assert!(command.update && command.prefix.is_none() && !command.help);
            assert_eq!(command.version.as_deref(), Some("1.2.3-rc.2"));
            Err("authenticated artifact unavailable".into())
        });
        assert_eq!(called.get(), 1);
        assert_eq!(
            result,
            Some(Err("authenticated artifact unavailable".into()))
        );
    }
    #[test]
    fn source_never_offers_a_download_and_only_diagnoses_incompatibility() {
        assert_eq!(
            view(UpdateEligibility::SourceBuild, false, Some("1.2.3")),
            Presentation::Silent
        );
        assert!(matches!(
            view(UpdateEligibility::SourceBuild, true, Some("1.2.3")),
            Presentation::Guidance(_)
        ));
    }
    #[test]
    fn only_managed_copies_offer_exact_server_release() {
        assert_eq!(
            view(UpdateEligibility::Managed, false, Some("1.2.3+build.4")),
            Presentation::Offer("1.2.3".into())
        );
        for eligibility in [
            UpdateEligibility::PackageOwned,
            UpdateEligibility::Unmanaged,
        ] {
            assert!(matches!(
                view(eligibility, false, Some("1.2.3")),
                Presentation::Guidance(_)
            ));
        }
        assert_eq!(
            view(UpdateEligibility::Managed, false, None),
            Presentation::Silent
        );
    }
    #[test]
    fn eligibility_runs_only_when_its_answer_can_be_shown() {
        let all = [
            UpdateEligibility::SourceBuild,
            UpdateEligibility::PackageOwned,
            UpdateEligibility::Managed,
            UpdateEligibility::Unmanaged,
        ];
        // Skipping the query never hides anything: every ownership is silent here.
        for eligibility in all {
            assert_eq!(view(eligibility, false, None), Presentation::Silent);
        }
        assert_eq!(
            presentation(|| panic!("ownership queried without an offer"), false, None),
            Presentation::Silent
        );
        for (incompatible, version) in [(true, None), (false, Some("1.2.3")), (true, Some("1.2.3"))]
        {
            for eligibility in all {
                let calls = std::cell::Cell::new(0);
                let shown = presentation(
                    || {
                        calls.set(calls.get() + 1);
                        eligibility
                    },
                    incompatible,
                    version,
                );
                assert_eq!(calls.get(), 1);
                assert_eq!(shown, view(eligibility, incompatible, version));
            }
        }
    }
}
