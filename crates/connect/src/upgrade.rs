//! Pure release policy for metadata whose authenticity the caller has checked.
use transport::bootstrap::{ServerInfo, SessionProfile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseChannel {
    Stable,
    Preview,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compatibility {
    Compatible,
    Incompatible,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateOffer {
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeDecision {
    pub compatibility: Compatibility,
    pub offer: Option<UpdateOffer>,
}

/// Evaluate release age separately from session compatibility.
///
/// The caller must authenticate metadata before supplying it here. Missing
/// metadata (including a missing profile list) adds no admission denial.
/// This function neither retrieves artifacts nor authorizes installation.
pub fn evaluate_upgrade(
    client_core: &str,
    client_protocol: SessionProfile,
    server: Option<&ServerInfo>,
    channel: ReleaseChannel,
) -> UpgradeDecision {
    let compatibility = match server {
        None => Compatibility::Unknown,
        Some(info) if info.session_protocols.is_empty() => Compatibility::Unknown,
        Some(info) if info.session_protocols.contains(&client_protocol) => {
            Compatibility::Compatible
        }
        Some(_) => Compatibility::Incompatible,
    };
    let offer = server.and_then(|info| {
        let client = semver::Version::parse(client_core).ok()?;
        let mut offered = semver::Version::parse(&info.core_version).ok()?;
        if offered.cmp_precedence(&client) != std::cmp::Ordering::Greater {
            return None;
        }
        let allowed = offered.pre.is_empty()
            || (channel == ReleaseChannel::Preview
                && offered.major == client.major
                && offered.minor == client.minor);
        if !allowed {
            return None;
        }
        // Release precedence ignores build metadata. Artifact names separately
        // use the release version without that metadata.
        offered.build = semver::BuildMetadata::EMPTY;
        Some(UpdateOffer {
            version: offered.to_string(),
        })
    });
    UpgradeDecision {
        compatibility,
        offer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: SessionProfile = SessionProfile {
        wire: 1,
        handshake: 2,
        channel: 3,
    };

    #[test]
    fn upgrade_release_order_and_channel_table() {
        for (client, server, channel, expected) in [
            ("1.2.3", "1.2.4", ReleaseChannel::Stable, Some("1.2.4")),
            ("1.2.3", "1.2.3", ReleaseChannel::Stable, None),
            ("1.2.3", "1.2.2", ReleaseChannel::Stable, None),
            ("1.2.3+local", "1.2.3", ReleaseChannel::Stable, None),
            ("1.2.3", "1.2.3+server", ReleaseChannel::Stable, None),
            (
                "1.2.3",
                "1.2.4+server",
                ReleaseChannel::Stable,
                Some("1.2.4"),
            ),
            ("1.2.3", "1.3.0-rc.1", ReleaseChannel::Stable, None),
            (
                "1.3.0-rc.2",
                "1.3.0-rc.10",
                ReleaseChannel::Preview,
                Some("1.3.0-rc.10"),
            ),
            ("1.3.0-rc.10", "1.3.0-rc.2", ReleaseChannel::Preview, None),
            // SemVer compares an attached number as text: rc10 orders before
            // rc2 and every rc.N before rc1. The release workflow therefore
            // refuses such prerelease tags (#554).
            (
                "1.3.0-rc10",
                "1.3.0-rc2",
                ReleaseChannel::Preview,
                Some("1.3.0-rc2"),
            ),
            (
                "0.6.0-rc.2",
                "0.6.0-rc1",
                ReleaseChannel::Preview,
                Some("0.6.0-rc1"),
            ),
            (
                "1.3.0-rc.2",
                "1.3.0",
                ReleaseChannel::Preview,
                Some("1.3.0"),
            ),
            ("1.3.0-rc.2", "1.4.0-rc.1", ReleaseChannel::Preview, None),
            (
                "1.3.0-rc.2",
                "1.4.0",
                ReleaseChannel::Preview,
                Some("1.4.0"),
            ),
            (
                "1.3.0-rc.2",
                "2.0.0",
                ReleaseChannel::Preview,
                Some("2.0.0"),
            ),
            ("1.3.0-rc.2", "2.3.0-rc.1", ReleaseChannel::Preview, None),
            ("0.6.0-rc1", "0.7.0", ReleaseChannel::Preview, Some("0.7.0")),
            (
                "0.6.0-rc1",
                "1.0.0+release",
                ReleaseChannel::Preview,
                Some("1.0.0"),
            ),
            ("0.6.0-rc1", "0.7.0-rc1", ReleaseChannel::Preview, None),
            ("bad", "1.2.4", ReleaseChannel::Stable, None),
            ("1.2.3", "bad", ReleaseChannel::Stable, None),
        ] {
            let server_info = ServerInfo {
                generation: [1; 16],
                core_version: server.into(),
                session_protocols: vec![PROFILE],
            };
            let result = evaluate_upgrade(client, PROFILE, Some(&server_info), channel);
            assert_eq!(
                result.compatibility,
                Compatibility::Compatible,
                "{client} -> {server}"
            );
            assert_eq!(
                result.offer.as_ref().map(|o| o.version.as_str()),
                expected,
                "{client} -> {server}"
            );
        }
    }

    #[test]
    fn upgrade_profile_match_requires_a_complete_supported_tuple() {
        let mut server = ServerInfo {
            generation: [1; 16],
            core_version: "3.0.0".into(),
            session_protocols: vec![
                SessionProfile { wire: 9, ..PROFILE },
                SessionProfile {
                    handshake: 9,
                    ..PROFILE
                },
            ],
        };
        let decision = evaluate_upgrade("2.0.0", PROFILE, Some(&server), ReleaseChannel::Stable);
        assert_eq!(decision.compatibility, Compatibility::Incompatible);
        assert_eq!(
            decision.offer,
            Some(UpdateOffer {
                version: "3.0.0".into()
            })
        );
        server.session_protocols.push(PROFILE);
        assert_eq!(
            evaluate_upgrade("2.0.0", PROFILE, Some(&server), ReleaseChannel::Stable).compatibility,
            Compatibility::Compatible
        );
    }

    #[test]
    fn upgrade_profiles_are_independent_of_release_age() {
        for (version, profiles, expected) in [
            ("bad", vec![PROFILE], Compatibility::Compatible),
            (
                "1.0.0",
                vec![SessionProfile { wire: 9, ..PROFILE }],
                Compatibility::Incompatible,
            ),
            (
                "9.0.0",
                vec![SessionProfile {
                    handshake: 9,
                    ..PROFILE
                }],
                Compatibility::Incompatible,
            ),
            (
                "1.0.0",
                vec![SessionProfile {
                    channel: 9,
                    ..PROFILE
                }],
                Compatibility::Incompatible,
            ),
            ("9.0.0", vec![], Compatibility::Unknown),
        ] {
            let server = ServerInfo {
                generation: [1; 16],
                core_version: version.into(),
                session_protocols: profiles,
            };
            assert_eq!(
                evaluate_upgrade("2.0.0", PROFILE, Some(&server), ReleaseChannel::Stable)
                    .compatibility,
                expected
            );
        }
        assert_eq!(
            evaluate_upgrade("2.0.0", PROFILE, None, ReleaseChannel::Stable),
            UpgradeDecision {
                compatibility: Compatibility::Unknown,
                offer: None
            }
        );
    }
}
