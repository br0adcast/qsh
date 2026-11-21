//! Whether a newer qshd may replace only the network frontend of a hosted
//! personal daemon (#529 M2), and what that costs the daemon's sessions:
//! one pure decision, [`classify`], over the facts the host keeps of its
//! sessions and the facts a candidate's `self-check` reports.
//!
//! Three compatibilities are checked, and never one for another: the host
//! revision ([`crate::state::HOST_REVISION`]: the contracts between the host
//! and its frontend and owners), the owner link version (between a
//! frontend and every live owner, which keeps its own binary), and the qsh
//! session profiles (between clients and the frontend).

use serde::{Deserialize, Serialize};

use crate::version::Replacement;

/// One session of the running daemon, as the host's catalog keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFacts {
    /// Its client is attached: the session counts in
    /// `STATUS.total_connections`.
    pub attached: bool,
    /// The session profiles `[wire, handshake, channel]` of the frontend
    /// its client last reached it through. Which one the client negotiated
    /// is not kept, so a new frontend must serve each to be sure of it.
    pub profiles: Vec<[u8; 3]>,
    /// The owner link versions its owner speaks: those of the image it was
    /// started from.
    pub links: Vec<u16>,
}

/// What a candidate image is, from its `self-check` and the host's own hash
/// of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFacts {
    pub build: u64,
    /// sha256 of the image, lower-case hex.
    pub checksum: String,
    /// `None`: the image predates the host, and cannot serve one.
    pub host_revision: Option<u32>,
    pub link_versions: Vec<u16>,
    pub session_profiles: Vec<[u8; 3]>,
}

/// What the running daemon is: its host, the frontend that serves, and
/// every session of its catalog, attached or retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonFacts {
    pub host_revision: u32,
    pub serving_build: u64,
    pub serving_checksum: String,
    pub sessions: Vec<SessionFacts>,
}

/// What replacing the serving frontend with a candidate would come to: a
/// row of the spec's decision table, with the counts its dialog names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "case", rename_all = "snake_case")]
pub enum Outcome {
    /// The candidate is the serving image, byte for byte: nothing to do.
    UpToDate,
    /// The candidate is older than the serving frontend: it never replaces
    /// it.
    Older,
    /// Replace the frontend; no client is attached, and every session's
    /// client finds the new one.
    Silent,
    /// Replace the frontend; `attached` clients are disconnected briefly,
    /// and every session is kept.
    Soft { attached: u64 },
    /// Replace the frontend; `stranded` of the `sessions` sessions have
    /// clients the candidate cannot serve, which cannot reach them until
    /// they expire. `attached` clients are disconnected.
    Unreachable {
        attached: u64,
        sessions: u64,
        stranded: u64,
    },
    /// The candidate cannot be this host's frontend, or cannot speak to one
    /// of its owners: only a full restart, which loses all `sessions`.
    Destructive { attached: u64, sessions: u64 },
    /// The candidate cannot be this host's frontend, and there is no session
    /// to lose: a full restart, as before there were hosts.
    FullRestart,
}

/// A frontend replacement the user agreed to, at most this disruptive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeCase {
    Soft,
    Unreachable,
}

/// What replacing `daemon`'s frontend with `candidate` comes to. In order:
/// an image that is not newer never replaces (as [`crate::version::replacement`]
/// decides); an incompatible host revision, or an owner that shares no
/// link version with the candidate, leaves only a full restart; a session
/// with a profile the candidate does not serve is stranded; otherwise only
/// the attached clients are affected, briefly.
pub fn classify(daemon: &DaemonFacts, candidate: &CandidateFacts) -> Outcome {
    // No other client counts here: the counts below say who is affected.
    match crate::version::replacement(
        candidate.build,
        &candidate.checksum,
        daemon.serving_build,
        &daemon.serving_checksum,
        0,
    ) {
        Replacement::UpToDate => return Outcome::UpToDate,
        Replacement::DaemonNewer => return Outcome::Older,
        Replacement::Replace | Replacement::Busy { .. } => {}
    }
    let sessions = daemon.sessions.len() as u64;
    let attached = daemon.sessions.iter().filter(|s| s.attached).count() as u64;
    let linked = |s: &SessionFacts| s.links.iter().any(|v| candidate.link_versions.contains(v));
    if candidate.host_revision != Some(daemon.host_revision) || !daemon.sessions.iter().all(linked)
    {
        return if sessions == 0 {
            Outcome::FullRestart
        } else {
            Outcome::Destructive { attached, sessions }
        };
    }
    let served = |s: &&SessionFacts| {
        s.profiles
            .iter()
            .all(|p| candidate.session_profiles.contains(p))
    };
    let stranded = daemon.sessions.iter().filter(|s| !served(s)).count() as u64;
    if stranded > 0 {
        Outcome::Unreachable {
            attached,
            sessions,
            stranded,
        }
    } else if attached > 0 {
        Outcome::Soft { attached }
    } else {
        Outcome::Silent
    }
}

/// Whether `systemctl --user reload` may carry out `outcome`: the user's
/// command is consent to disconnect attached clients briefly, never to
/// strand or lose a session.
pub fn reload_permits(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::UpToDate | Outcome::Silent | Outcome::Soft { .. }
    )
}

/// Whether consent to `consented` covers `outcome`: a frontend replacement
/// at most as disruptive (`Silent` < `Soft` < `Unreachable`). Nothing that
/// is no frontend replacement is covered.
pub fn consent_covers(consented: UpgradeCase, outcome: &Outcome) -> bool {
    let needed = match outcome {
        Outcome::Silent => 0,
        Outcome::Soft { .. } => 1,
        Outcome::Unreachable { .. } => 2,
        _ => return false,
    };
    let given = match consented {
        UpgradeCase::Soft => 1,
        UpgradeCase::Unreachable => 2,
    };
    needed <= given
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVING: &str = "aa";
    const CANDIDATE: &str = "bb";
    const PROFILE: [u8; 3] = [4, 3, 2];
    const OTHER_PROFILE: [u8; 3] = [5, 3, 2];

    fn session(attached: bool) -> SessionFacts {
        SessionFacts {
            attached,
            profiles: vec![PROFILE],
            links: vec![1],
        }
    }

    fn daemon(sessions: Vec<SessionFacts>) -> DaemonFacts {
        DaemonFacts {
            host_revision: 1,
            serving_build: 10,
            serving_checksum: SERVING.into(),
            sessions,
        }
    }

    /// Newer, compatible on every count, serving the same profile.
    fn candidate() -> CandidateFacts {
        CandidateFacts {
            build: 11,
            checksum: CANDIDATE.into(),
            host_revision: Some(1),
            link_versions: vec![1, 2],
            session_profiles: vec![PROFILE, OTHER_PROFILE],
        }
    }

    #[test]
    fn classify_covers_every_decision_table_row() {
        let attached_and_retained = || daemon(vec![session(true), session(false)]);

        // Not newer, or byte-identical: as `version::replacement` says.
        let same = CandidateFacts {
            checksum: SERVING.into(),
            ..candidate()
        };
        assert_eq!(classify(&attached_and_retained(), &same), Outcome::UpToDate);
        let older = CandidateFacts {
            build: 9,
            ..candidate()
        };
        assert_eq!(classify(&attached_and_retained(), &older), Outcome::Older);
        let tied = CandidateFacts {
            build: 10,
            ..candidate()
        };
        assert_eq!(
            classify(&daemon(Vec::new()), &tied),
            Outcome::Silent,
            "a tied stamp with other bytes still replaces"
        );

        // Compatible, every client's protocol served, nobody attached.
        assert_eq!(classify(&daemon(Vec::new()), &candidate()), Outcome::Silent);
        assert_eq!(
            classify(&daemon(vec![session(false)]), &candidate()),
            Outcome::Silent,
            "a retained session alone disconnects nobody"
        );

        // Compatible, every client's protocol served, others attached.
        assert_eq!(
            classify(&attached_and_retained(), &candidate()),
            Outcome::Soft { attached: 1 }
        );

        // Compatible, a session's client protocol not served.
        let foreign = CandidateFacts {
            session_profiles: vec![OTHER_PROFILE],
            ..candidate()
        };
        let mut mixed = attached_and_retained();
        mixed.sessions.push(SessionFacts {
            attached: false,
            profiles: vec![OTHER_PROFILE],
            links: vec![2],
        });
        assert_eq!(
            classify(&mixed, &foreign),
            Outcome::Unreachable {
                attached: 1,
                sessions: 3,
                stranded: 2
            }
        );
        assert_eq!(
            classify(&daemon(vec![session(false)]), &foreign),
            Outcome::Unreachable {
                attached: 0,
                sessions: 1,
                stranded: 1
            },
            "retained-only sessions are stranded too"
        );
        let none = CandidateFacts {
            session_profiles: Vec::new(),
            ..candidate()
        };
        assert_eq!(classify(&daemon(Vec::new()), &none), Outcome::Silent);

        // Incompatible host, sessions exist.
        for host_revision in [Some(2), None] {
            let other_host = CandidateFacts {
                host_revision,
                ..candidate()
            };
            assert_eq!(
                classify(&attached_and_retained(), &other_host),
                Outcome::Destructive {
                    attached: 1,
                    sessions: 2
                }
            );
            assert_eq!(
                classify(&daemon(Vec::new()), &other_host),
                Outcome::FullRestart,
                "nothing to lose"
            );
        }
        let other_host = CandidateFacts {
            host_revision: Some(2),
            ..candidate()
        };
        assert_eq!(
            classify(&daemon(vec![session(false)]), &other_host),
            Outcome::Destructive {
                attached: 0,
                sessions: 1
            },
            "retained-only sessions are lost too"
        );

        // One owner whose link the candidate does not speak.
        let mut one_old_owner = attached_and_retained();
        one_old_owner.sessions[1].links = vec![0];
        assert_eq!(
            classify(&one_old_owner, &candidate()),
            Outcome::Destructive {
                attached: 1,
                sessions: 2
            }
        );
        // Ahead of the protocol check: losing every session is the worse news.
        assert_eq!(
            classify(&one_old_owner, &foreign),
            Outcome::Destructive {
                attached: 1,
                sessions: 2
            }
        );
    }

    #[test]
    fn reload_permits_only_the_kept_outcomes() {
        let permitted = [
            Outcome::UpToDate,
            Outcome::Silent,
            Outcome::Soft { attached: 3 },
        ];
        let refused = [
            Outcome::Older,
            Outcome::Unreachable {
                attached: 0,
                sessions: 1,
                stranded: 1,
            },
            Outcome::Destructive {
                attached: 1,
                sessions: 1,
            },
            Outcome::FullRestart,
        ];
        for outcome in &permitted {
            assert!(reload_permits(outcome), "{outcome:?}");
        }
        for outcome in &refused {
            assert!(!reload_permits(outcome), "{outcome:?}");
        }
    }

    #[test]
    fn consent_covers_only_equal_or_milder_cases() {
        let soft = Outcome::Soft { attached: 1 };
        let unreachable = Outcome::Unreachable {
            attached: 1,
            sessions: 2,
            stranded: 1,
        };
        assert!(consent_covers(UpgradeCase::Soft, &Outcome::Silent));
        assert!(consent_covers(UpgradeCase::Soft, &soft));
        assert!(!consent_covers(UpgradeCase::Soft, &unreachable));
        assert!(consent_covers(UpgradeCase::Unreachable, &Outcome::Silent));
        assert!(consent_covers(UpgradeCase::Unreachable, &soft));
        assert!(consent_covers(UpgradeCase::Unreachable, &unreachable));
        // No frontend upgrade consent covers what is no frontend upgrade.
        for outcome in [
            Outcome::UpToDate,
            Outcome::Older,
            Outcome::Destructive {
                attached: 1,
                sessions: 2,
            },
            Outcome::FullRestart,
        ] {
            assert!(
                !consent_covers(UpgradeCase::Unreachable, &outcome),
                "{outcome:?}"
            );
            assert!(!consent_covers(UpgradeCase::Soft, &outcome), "{outcome:?}");
        }
    }

    /// The JSON form an outcome takes in the answers to a prepared upgrade.
    #[test]
    fn an_outcome_is_named_by_its_case() {
        let json = serde_json::to_value(Outcome::Unreachable {
            attached: 1,
            sessions: 2,
            stranded: 1,
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"case": "unreachable", "attached": 1, "sessions": 2, "stranded": 1})
        );
        assert_eq!(
            serde_json::to_value(Outcome::FullRestart).unwrap(),
            serde_json::json!({"case": "full_restart"})
        );
        let back: Outcome = serde_json::from_value(json).unwrap();
        assert!(matches!(back, Outcome::Unreachable { stranded: 1, .. }));
    }
}
