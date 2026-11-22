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

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use daemon_bootstrap_protocol::{
    BusyDaemonIdentity, CandidateImageIdentity, FrontendUpgradeAction, FrontendUpgradeConsent,
};
use serde::{Deserialize, Serialize};

use crate::version::Replacement;

/// How long the daemon may take to answer `PREPARE-FRONTEND-UPGRADE`: the
/// candidate is hashed and its `self-check` runs
/// ([`crate::update::SELF_CHECK_TIMEOUT`]) within it.
pub const PREPARE_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a client waits for that answer: the daemon's bound and a margin.
pub const PREPARE_CLIENT_TIMEOUT: Duration = Duration::from_secs(25);
/// How long the daemon may take to answer `COMMIT-FRONTEND-UPGRADE`: the
/// old frontend's stop, the new one's start and its `Ready`, or a rollback.
pub const COMMIT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a client waits for that answer.
pub const COMMIT_CLIENT_TIMEOUT: Duration = Duration::from_secs(35);
/// How long the daemon may take to answer `RELOAD-FRONTEND`: a prepare and
/// a commit, each within its own bound.
pub const RELOAD_TIMEOUT: Duration = Duration::from_secs(50);
/// How long `qshd reload` waits for that answer.
pub const RELOAD_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// `PREPARE-FRONTEND-UPGRADE`: replace the serving frontend with the
/// executable at `path`, which the caller expects to be `size` bytes with
/// sha256 `checksum` and build `build`, while `identity` serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub path: String,
    pub size: u64,
    /// sha256 of the candidate, lower-case hex.
    pub checksum: String,
    pub build: u64,
    /// The serving frontend the caller saw: the upgrade is refused if
    /// another one serves by now.
    pub identity: BusyDaemonIdentity,
    /// The user's agreement to a disruptive case, if one was asked for.
    #[serde(default)]
    pub consent: Option<FrontendUpgradeConsent>,
}

/// The answer to a prepare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PrepareResponse {
    /// The candidate is held; `receipt` (hex) commits it, once, within
    /// `destructive_restart::RECEIPT_TTL`.
    Ready {
        receipt: String,
        outcome: Outcome,
    },
    /// The upgrade would disconnect or strand clients: prepare again with a
    /// consent that covers `outcome`.
    NeedsConsent {
        outcome: Outcome,
    },
    /// Only a full restart of the daemon installs this candidate.
    NotPreservable {
        outcome: Outcome,
    },
    /// The candidate is the serving frontend's image.
    UpToDate,
    Refused {
        reason: Refusal,
    },
}

/// The answer to a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CommitResponse {
    /// The candidate's frontend serves, as `identity`.
    Replaced { identity: BusyDaemonIdentity },
    /// The candidate was started and did not come up, or could not be
    /// started; the previous image was started again, under the identity it
    /// had. Attached clients were disconnected briefly; every session is
    /// kept.
    RolledBack { reason: String },
    /// Not carried out, and nothing was rolled back. Every refusal but two
    /// comes before anything changed. [`Refusal::Busy`] also answers a
    /// replacement the daemon could not take (no frontend served yet,
    /// another pending, the whole daemon replacing itself), and
    /// [`Refusal::Stopping`] one cut short by the daemon's stop.
    Refused { reason: Refusal },
}

/// The answer to `RELOAD-FRONTEND` (`systemctl --user reload qshd`): the
/// serving frontend replaced by the file the daemon was started from, or
/// why not. In every case but `Replaced` and `RolledBack` the frontend
/// serves on as it was, unless the daemon is stopping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReloadResponse {
    /// That file's frontend serves now, as `build`.
    Replaced { build: u64 },
    /// That file is the serving frontend's image.
    UpToDate,
    /// Nothing was replaced: `reason` says why (the daemon may be stopping),
    /// and `outcome` what the replacement would have come to, when it came
    /// that far.
    Refused {
        reason: String,
        outcome: Option<Outcome>,
    },
    /// The new frontend did not come up, for `reason`; the previous image
    /// serves again.
    RolledBack { reason: String },
}

/// Why a prepare or a commit was refused: see [`CommitResponse::Refused`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Refusal {
    /// Another frontend serves than the request names.
    Mismatch,
    /// The candidate is not what the request says, or cannot serve.
    Candidate { detail: String },
    /// The candidate is older than the serving frontend.
    Older,
    /// Another upgrade, or a replacement of the whole daemon, is under way,
    /// or no frontend serves yet. Which frontend serves next is not known.
    Busy,
    /// The receipt's time ran out.
    Expired,
    /// No such receipt: never issued, used already, or replaced by a newer
    /// prepare.
    Unknown,
    /// The daemon's sessions changed since the prepare, and the receipt no
    /// longer covers what the upgrade would come to now.
    Changed { outcome: Outcome },
    /// The daemon is stopping: no frontend serves on, whatever the upgrade
    /// had come to.
    Stopping,
}

/// A future the control server awaits without naming its type.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the control server of a hosted daemon hands the two upgrade
/// requests to, and a hosted `serve` daemon its reload. A daemon without
/// one answers none of them, as an older daemon.
pub trait FrontendUpgrades: Send + Sync {
    fn prepare(&self, request: PrepareRequest) -> BoxFuture<'_, PrepareResponse>;
    /// `None` when what came of the commit is not known (it failed in a
    /// way that tells nothing, a panic): the caller then answers nothing,
    /// as past the commit's bound.
    fn commit(&self, receipt: [u8; 16]) -> BoxFuture<'_, Option<CommitResponse>>;
    /// Replace the serving frontend with the file at the path the daemon
    /// was started from, if [`reload_permits`] what that comes to. `None`
    /// as for [`FrontendUpgrades::commit`].
    fn reload(&self) -> BoxFuture<'_, Option<ReloadResponse>>;
}

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
pub use daemon_bootstrap_protocol::UpgradeCase;

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

/// The case `consent` agrees to, if it names exactly the frontend that
/// serves (`serving`, pid and generation included) and exactly the held
/// `candidate`. Any other consent counts as none.
pub fn consented_case(
    consent: Option<&FrontendUpgradeConsent>,
    serving: &BusyDaemonIdentity,
    candidate: &CandidateImageIdentity,
) -> Option<UpgradeCase> {
    consent
        .filter(|c| {
            c.identity == *serving
                && c.candidate == *candidate
                && c.action == FrontendUpgradeAction::ReplaceFrontend
        })
        .map(|c| c.case)
}

/// Whether a receipt may be issued, and later carried out, for `outcome`:
/// a silent replacement needs nobody's consent, a disruptive one the
/// user's, to a case at least as disruptive.
pub fn receipt_covers(consented: Option<UpgradeCase>, outcome: &Outcome) -> bool {
    match consented {
        Some(case) => consent_covers(case, outcome),
        None => *outcome == Outcome::Silent,
    }
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

    fn serving() -> BusyDaemonIdentity {
        BusyDaemonIdentity {
            version: "0.6.0".into(),
            build: 10,
            checksum: SERVING.repeat(32),
            pid: 42,
            generation: Some("cd".repeat(16)),
        }
    }

    fn held() -> CandidateImageIdentity {
        CandidateImageIdentity {
            build: 11,
            checksum: CANDIDATE.repeat(32),
        }
    }

    fn consent(case: UpgradeCase) -> FrontendUpgradeConsent {
        FrontendUpgradeConsent {
            attempt: daemon_bootstrap_protocol::BusyAttemptId::from_bytes([1; 16]),
            identity: serving(),
            candidate: held(),
            case,
            action: FrontendUpgradeAction::ReplaceFrontend,
        }
    }

    #[test]
    fn a_matching_consent_covers_its_case() {
        let soft = Outcome::Soft { attached: 2 };
        let given = consent(UpgradeCase::Soft);
        let case = consented_case(Some(&given), &serving(), &held());
        assert_eq!(case, Some(UpgradeCase::Soft));
        assert!(receipt_covers(case, &soft));
        assert!(receipt_covers(case, &Outcome::Silent));
        // Without one, only a silent replacement is covered.
        assert!(receipt_covers(None, &Outcome::Silent));
        assert!(!receipt_covers(None, &soft));
        assert!(!receipt_covers(None, &Outcome::UpToDate));
    }

    #[test]
    fn a_consent_for_another_candidate_or_frontend_counts_as_none() {
        let given = consent(UpgradeCase::Unreachable);
        let other_build = CandidateImageIdentity {
            build: 12,
            ..held()
        };
        let other_bytes = CandidateImageIdentity {
            checksum: "ee".repeat(32),
            ..held()
        };
        for candidate in [other_build, other_bytes] {
            assert_eq!(consented_case(Some(&given), &serving(), &candidate), None);
        }
        for changed in 0..3 {
            let mut other = serving();
            match changed {
                0 => other.pid += 1,
                1 => other.generation = Some("ab".repeat(16)),
                _ => other.build += 1,
            }
            assert_eq!(consented_case(Some(&given), &other, &held()), None);
        }
        assert_eq!(consented_case(None, &serving(), &held()), None);
    }

    #[test]
    fn a_consent_to_a_milder_case_does_not_cover_a_worse_one() {
        let given = consent(UpgradeCase::Soft);
        let case = consented_case(Some(&given), &serving(), &held());
        let unreachable = Outcome::Unreachable {
            attached: 0,
            sessions: 1,
            stranded: 1,
        };
        assert!(!receipt_covers(case, &unreachable));
        assert!(!receipt_covers(
            case,
            &Outcome::Destructive {
                attached: 0,
                sessions: 1
            }
        ));
    }

    /// The JSON forms of the prepare and commit answers.
    #[test]
    fn upgrade_answers_are_tagged_by_status_and_kind() {
        let changed = PrepareResponse::Refused {
            reason: Refusal::Changed {
                outcome: Outcome::Soft { attached: 1 },
            },
        };
        let json = serde_json::to_value(&changed).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"status": "refused", "reason": {"kind": "changed",
                "outcome": {"case": "soft", "attached": 1}}})
        );
        assert_eq!(
            serde_json::from_value::<PrepareResponse>(json).unwrap(),
            changed
        );
        assert_eq!(
            serde_json::to_value(PrepareResponse::UpToDate).unwrap(),
            serde_json::json!({"status": "up_to_date"})
        );
        assert_eq!(
            serde_json::to_value(ReloadResponse::Refused {
                reason: "older".into(),
                outcome: Some(Outcome::Older),
            })
            .unwrap(),
            serde_json::json!({"status": "refused", "reason": "older",
                "outcome": {"case": "older"}})
        );
        assert_eq!(
            serde_json::to_value(ReloadResponse::Replaced { build: 7 }).unwrap(),
            serde_json::json!({"status": "replaced", "build": 7})
        );
        let rolled = CommitResponse::RolledBack {
            reason: "it exited".into(),
        };
        assert_eq!(
            serde_json::to_value(&rolled).unwrap(),
            serde_json::json!({"status": "rolled_back", "reason": "it exited"})
        );
    }
}
