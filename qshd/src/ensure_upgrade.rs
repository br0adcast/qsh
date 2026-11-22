//! What `transport-ensure`, run from a newer qshd at login, does about a
//! hosted personal daemon (#529 M2): it asks the daemon to replace only its
//! network frontend with this process's own image, and maps the answer to
//! a row of the spec's decision table.
//!
//! The daemon decides what an upgrade would cost (`PREPARE-FRONTEND-UPGRADE`)
//! and carries it out (`COMMIT-FRONTEND-UPGRADE`); this side only asks,
//! within bounds, and never reads a missing answer as permission to start a
//! second daemon. A daemon whose `STATUS` names no host is never asked, and
//! is handled as before ([`EnsureUpgrade::Legacy`]); that is every daemon
//! off Linux, so this module builds everywhere. A host always answers both
//! requests, so its silence means a reset or a dying daemon: an error, never
//! a reason to fall back to today's restart.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use daemon_bootstrap_protocol::{
    BusyDaemonIdentity, FrontendUpgradeConsent, FrontendUpgradeOffer, UpgradeCase,
};

use crate::control::{ControlReply, ControlRequest, EnsureLock, StatusResponse};
use crate::frontend_upgrade::{
    CommitResponse, Outcome, PrepareRequest, PrepareResponse, Refusal, COMMIT_CLIENT_TIMEOUT,
    PREPARE_CLIENT_TIMEOUT,
};
use crate::state;

/// The answer of a host's prepare or commit that never came: the daemon may
/// be dying, or the upgrade may or may not have happened, so nothing is
/// decided on it.
pub const UNANSWERED: &str =
    "the daemon's frontend upgrade did not answer; rediscover before choosing again";

/// A prepare or commit refused because the daemon is stopping: it is no
/// daemon to register with, nor one that serves on.
pub const STOPPING: &str = "the daemon is stopping; rediscover before choosing again";

/// The longest request line a daemon reads, its `\n` included: a longer one
/// is not parsed, so it is never answered.
const REQUEST_BOUND: usize = 4096;

/// What `transport-ensure` goes on to do about the running daemon.
// One value per login, returned once: its size does not matter, and the
// STATUS it carries is used as it is.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureUpgrade {
    /// No frontend upgrade applies: the daemon is no host, or already
    /// serves this image. Decide as before M2.
    Legacy,
    /// This image's frontend serves now, as the daemon's `STATUS` says.
    Replaced(StatusResponse),
    /// No upgrade now, for the reason given: the login registers with the
    /// frontend it saw, which fails if another serves by then.
    Keep { warning: String },
    /// The upgrade disconnects or strands somebody: ask the user.
    Ask(FrontendUpgradeOffer),
    /// Only a full restart installs this image, which ends `sessions`
    /// sessions, `attached` of them with a client.
    Destructive { attached: u64, sessions: u64 },
    /// Only a full restart installs this image, and there is no session to
    /// lose.
    FullRestart,
    /// This image's frontend did not come up, and the previous one serves
    /// again.
    RolledBack { warning: String },
}

/// The image a prepare names: this process's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: String,
    pub size: u64,
    /// sha256, lower-case hex.
    pub checksum: String,
    pub build: u64,
}

impl Candidate {
    /// This process's executable, as the daemon will open it. The daemon
    /// checks size, checksum and build against what it reads, so a file
    /// replaced meanwhile is refused, never installed.
    pub fn own() -> Result<Self> {
        let path = state::own_binary_path()?;
        let size = std::fs::metadata(&path)
            .with_context(|| format!("reading the size of {}", path.display()))?
            .len();
        Ok(Self {
            path: path.to_string_lossy().into_owned(),
            size,
            checksum: state::self_checksum()?,
            build: state::build_label(),
        })
    }
}

/// Asks the daemon `status` describes, served by `identity` (with its
/// SERVER-INFO generation), to replace its frontend with this process's
/// image, under the user's `consent` if one was given, and says what to do
/// next. `report_busy`: the caller can ask the user, so a disruptive
/// upgrade is offered rather than declined.
pub fn step(
    transaction: &EnsureLock,
    status: &StatusResponse,
    identity: &BusyDaemonIdentity,
    consent: Option<&FrontendUpgradeConsent>,
    report_busy: bool,
) -> Result<EnsureUpgrade> {
    // Only a host answers; asking anything else would cost a read timeout.
    if status.host.is_none() {
        return Ok(EnsureUpgrade::Legacy);
    }
    step_with(
        |request, timeout| transaction.request_with_timeout(request, timeout),
        &Candidate::own()?,
        identity,
        consent,
        report_busy,
    )
}

/// [`step`] over any control channel `ask`, for `candidate`, to a daemon
/// known to be a host.
pub fn step_with(
    mut ask: impl FnMut(&ControlRequest, Duration) -> Result<ControlReply>,
    candidate: &Candidate,
    identity: &BusyDaemonIdentity,
    consent: Option<&FrontendUpgradeConsent>,
    report_busy: bool,
) -> Result<EnsureUpgrade> {
    // A commit refused because the sessions changed since the prepare earns
    // one fresh prepare, which takes the census again; never a second.
    let mut fresh_prepare = true;
    let request = ControlRequest::PrepareFrontendUpgrade(PrepareRequest {
        path: candidate.path.clone(),
        size: candidate.size,
        checksum: candidate.checksum.clone(),
        build: candidate.build,
        identity: identity.clone(),
        consent: consent.cloned(),
    });
    // A host never answers a line it cannot read, and its silence is no
    // permission to go on: such a request is not sent at all.
    let length = crate::control::format_request(&request).len();
    if length > REQUEST_BOUND {
        return Ok(EnsureUpgrade::Keep {
            warning: kept(&format!(
                "its upgrade request would be {length} bytes, more than the daemon's \
                 {REQUEST_BOUND}-byte bound; the path of this qshd is too long"
            )),
        });
    }
    loop {
        let response: PrepareResponse = match ask(&request, PREPARE_CLIENT_TIMEOUT)? {
            // A host answers every prepare (ruling R6): no line is no
            // permission to stop it and start another.
            ControlReply::NoDaemon | ControlReply::TimedOut => bail!(UNANSWERED),
            ControlReply::Answered(line) => {
                serde_json::from_str(&line).context("invalid frontend upgrade answer")?
            }
        };
        let receipt = match response {
            PrepareResponse::UpToDate => return Ok(EnsureUpgrade::Legacy),
            PrepareResponse::Ready { receipt, .. } => decode_receipt(&receipt)?,
            PrepareResponse::NeedsConsent { outcome } => {
                return Ok(match (offer(&outcome), report_busy) {
                    (Some(offer), true) => EnsureUpgrade::Ask(offer),
                    (Some(offer), false) => EnsureUpgrade::Keep {
                        warning: declined(&offer),
                    },
                    (None, _) => EnsureUpgrade::Keep {
                        warning: kept(&format!("unexpected case {outcome:?}")),
                    },
                })
            }
            PrepareResponse::NotPreservable { outcome } => {
                return Ok(match outcome {
                    Outcome::Destructive { attached, sessions } => {
                        EnsureUpgrade::Destructive { attached, sessions }
                    }
                    Outcome::FullRestart => EnsureUpgrade::FullRestart,
                    other => EnsureUpgrade::Keep {
                        warning: kept(&format!("unexpected case {other:?}")),
                    },
                })
            }
            PrepareResponse::Refused { reason } => return refused(&reason),
        };
        let response: CommitResponse = match ask(
            &ControlRequest::CommitFrontendUpgrade(receipt),
            COMMIT_CLIENT_TIMEOUT,
        )? {
            ControlReply::Answered(line) => {
                serde_json::from_str(&line).context("invalid frontend upgrade commit answer")?
            }
            // The daemon was told to commit: no answer is not "no daemon".
            ControlReply::NoDaemon | ControlReply::TimedOut => bail!(UNANSWERED),
        };
        return match response {
            CommitResponse::Replaced { identity: serving } => {
                replaced(&mut ask, candidate, identity, &serving).map(EnsureUpgrade::Replaced)
            }
            CommitResponse::RolledBack { reason } => Ok(EnsureUpgrade::RolledBack {
                warning: format!(
                    "the newer qshd frontend did not start ({reason}); the running one serves on"
                ),
            }),
            CommitResponse::Refused {
                reason: Refusal::Changed { .. },
            } if fresh_prepare => {
                fresh_prepare = false;
                continue;
            }
            CommitResponse::Refused { reason } => refused(&reason),
        };
    }
}

/// The daemon after a commit that says `serving` serves: its `STATUS` must
/// name the candidate under the same host, or something else happened
/// meanwhile and nothing is registered with it.
fn replaced(
    ask: &mut impl FnMut(&ControlRequest, Duration) -> Result<ControlReply>,
    candidate: &Candidate,
    before: &BusyDaemonIdentity,
    serving: &BusyDaemonIdentity,
) -> Result<StatusResponse> {
    let changed =
        "the daemon changed during its frontend upgrade; rediscover before choosing again";
    let ControlReply::Answered(line) =
        ask(&ControlRequest::Status, crate::control::CLIENT_READ_TIMEOUT)?
    else {
        bail!(changed);
    };
    let status = StatusResponse::from_line(&line)?;
    let names_candidate =
        |build: u64, checksum: &str| build == candidate.build && checksum == candidate.checksum;
    if !names_candidate(status.build, &status.checksum)
        || !names_candidate(serving.build, &serving.checksum)
        || status.pid != before.pid
        || serving.pid != before.pid
    {
        bail!(changed);
    }
    Ok(status)
}

fn decode_receipt(receipt: &str) -> Result<[u8; 16]> {
    hex::decode(receipt)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .context("invalid frontend upgrade receipt")
}

/// The offer a disruptive `outcome` makes the user.
fn offer(outcome: &Outcome) -> Option<FrontendUpgradeOffer> {
    match *outcome {
        Outcome::Soft { attached } => Some(FrontendUpgradeOffer {
            case: UpgradeCase::Soft,
            attached,
            sessions: attached,
            stranded: 0,
        }),
        Outcome::Unreachable {
            attached,
            sessions,
            stranded,
        } => Some(FrontendUpgradeOffer {
            case: UpgradeCase::Unreachable,
            attached,
            sessions,
            stranded,
        }),
        _ => None,
    }
}

/// Why a login nobody can ask leaves the frontend as it is.
fn declined(offer: &FrontendUpgradeOffer) -> String {
    let cost = match offer.case {
        UpgradeCase::Soft => format!(
            "would disconnect {} other client(s) briefly",
            offer.attached
        ),
        UpgradeCase::Unreachable => format!(
            "would leave {} session(s) unreachable until they expire",
            offer.stranded
        ),
    };
    format!(
        "the daemon's version differs from the app's, but replacing its frontend {cost} -- not replacing"
    )
}

/// What a refused prepare or commit leaves to do. A stopping daemon is no
/// daemon to register with. Of a busy one, nothing is said of what serves
/// on: another upgrade or a restart may be replacing it.
fn refused(reason: &Refusal) -> Result<EnsureUpgrade> {
    match reason {
        Refusal::Stopping => bail!(STOPPING),
        Refusal::Busy => Ok(EnsureUpgrade::Keep {
            warning: format!(
                "the newer qshd frontend was not installed: {}",
                refusal(reason)
            ),
        }),
        other => Ok(EnsureUpgrade::Keep {
            warning: kept(&refusal(other)),
        }),
    }
}

fn kept(why: &str) -> String {
    format!("the newer qshd frontend was not installed ({why}); the running one serves on")
}

fn refusal(reason: &Refusal) -> String {
    match reason {
        Refusal::Mismatch => "another frontend serves than this login saw".into(),
        Refusal::Candidate { detail } => format!("the daemon refused the image: {detail}"),
        Refusal::Older => "the running frontend is newer".into(),
        Refusal::Busy => "another upgrade or restart is under way".into(),
        Refusal::Expired => "its receipt expired".into(),
        Refusal::Unknown => "its receipt was not known".into(),
        Refusal::Changed { .. } => "the daemon's sessions kept changing".into(),
        Refusal::Stopping => "the daemon is stopping".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_bootstrap_protocol::{BusyAttemptId, CandidateImageIdentity, FrontendUpgradeAction};
    use std::collections::VecDeque;

    fn identity() -> BusyDaemonIdentity {
        BusyDaemonIdentity {
            version: "0.6.0".into(),
            build: 1,
            checksum: "aa".repeat(32),
            pid: 42,
            generation: Some("cd".repeat(16)),
        }
    }

    fn candidate() -> Candidate {
        Candidate {
            path: "/fixture/qshd".into(),
            size: 7,
            checksum: "bb".repeat(32),
            build: 2,
        }
    }

    fn status(build: u64, checksum: &str, pid: u32) -> String {
        StatusResponse {
            logging_warning: None,
            cleanup: None,
            version: "0.6.0".into(),
            build,
            checksum: checksum.into(),
            ports: vec![],
            total_connections: 0,
            pid,
            host: None,
        }
        .to_line()
        .unwrap()
        .trim_end()
        .to_string()
    }

    fn json(value: &impl serde::Serialize) -> ControlReply {
        ControlReply::Answered(serde_json::to_string(value).unwrap())
    }

    const RECEIPT: &str = "07070707070707070707070707070707";

    fn ready() -> ControlReply {
        json(&PrepareResponse::Ready {
            receipt: RECEIPT.into(),
            outcome: Outcome::Silent,
        })
    }

    fn served() -> ControlReply {
        json(&CommitResponse::Replaced {
            identity: BusyDaemonIdentity {
                build: 2,
                checksum: "bb".repeat(32),
                generation: Some("ee".repeat(16)),
                ..identity()
            },
        })
    }

    fn changed() -> ControlReply {
        json(&CommitResponse::Refused {
            reason: Refusal::Changed {
                outcome: Outcome::Soft { attached: 1 },
            },
        })
    }

    /// Runs `step_with` over `replies`, in order; returns its result and the
    /// requests it sent, by kind.
    fn run(
        replies: Vec<ControlReply>,
        consent: Option<&FrontendUpgradeConsent>,
        report_busy: bool,
    ) -> (Result<EnsureUpgrade>, Vec<&'static str>) {
        let mut replies = VecDeque::from(replies);
        let mut sent = Vec::new();
        let result = step_with(
            |request, timeout| {
                sent.push(match request {
                    ControlRequest::PrepareFrontendUpgrade(prepare) => {
                        assert_eq!(timeout, PREPARE_CLIENT_TIMEOUT);
                        assert_eq!(prepare.identity, identity());
                        assert_eq!(prepare.consent.as_ref(), consent);
                        assert_eq!(
                            (prepare.size, prepare.build, prepare.checksum.as_str()),
                            (7, 2, "bb".repeat(32).as_str())
                        );
                        "prepare"
                    }
                    ControlRequest::CommitFrontendUpgrade(receipt) => {
                        assert_eq!(timeout, COMMIT_CLIENT_TIMEOUT);
                        assert_eq!(hex::encode(receipt), RECEIPT);
                        "commit"
                    }
                    ControlRequest::Status => "status",
                    other => panic!("unexpected {other:?}"),
                });
                Ok(replies.pop_front().expect("a scripted reply"))
            },
            &candidate(),
            &identity(),
            consent,
            report_busy,
        );
        (result, sent)
    }

    #[test]
    fn a_daemon_already_current_is_legacy() {
        let (result, sent) = run(vec![json(&PrepareResponse::UpToDate)], None, true);
        assert_eq!(result.unwrap(), EnsureUpgrade::Legacy);
        assert_eq!(sent, ["prepare"]);
    }

    #[test]
    fn a_host_that_does_not_answer_the_prepare_is_an_error_never_legacy() {
        for silence in [ControlReply::NoDaemon, ControlReply::TimedOut] {
            for report_busy in [false, true] {
                let (result, sent) = run(vec![silence.clone()], None, report_busy);
                assert_eq!(result.unwrap_err().to_string(), UNANSWERED);
                assert_eq!(sent, ["prepare"], "nothing else is sent");
            }
        }
    }

    #[test]
    fn a_ready_upgrade_commits_and_checks_the_new_status() {
        let (result, sent) = run(
            vec![
                ready(),
                served(),
                ControlReply::Answered(status(2, &"bb".repeat(32), 42)),
            ],
            None,
            false,
        );
        let EnsureUpgrade::Replaced(after) = result.unwrap() else {
            panic!("not replaced");
        };
        assert_eq!(after.build, 2);
        assert_eq!(sent, ["prepare", "commit", "status"]);

        // STATUS that names another image, or another host, is no success.
        for line in [
            status(1, &"aa".repeat(32), 42),
            status(2, &"bb".repeat(32), 43),
        ] {
            let (result, _) = run(
                vec![ready(), served(), ControlReply::Answered(line)],
                None,
                false,
            );
            assert!(result.unwrap_err().to_string().contains("rediscover"));
        }
    }

    #[test]
    fn an_unanswered_commit_is_an_error_never_a_fallback() {
        for silence in [ControlReply::NoDaemon, ControlReply::TimedOut] {
            let (result, sent) = run(vec![ready(), silence], None, false);
            assert_eq!(result.unwrap_err().to_string(), UNANSWERED);
            assert_eq!(sent, ["prepare", "commit"]);
        }
    }

    #[test]
    fn changed_sessions_earn_one_fresh_prepare_and_no_more() {
        let (result, sent) = run(
            vec![
                ready(),
                changed(),
                ready(),
                served(),
                ControlReply::Answered(status(2, &"bb".repeat(32), 42)),
            ],
            None,
            false,
        );
        assert!(matches!(result.unwrap(), EnsureUpgrade::Replaced(_)));
        assert_eq!(sent, ["prepare", "commit", "prepare", "commit", "status"]);

        let (result, sent) = run(vec![ready(), changed(), ready(), changed()], None, false);
        let EnsureUpgrade::Keep { warning } = result.unwrap() else {
            panic!("not kept");
        };
        assert!(warning.contains("kept changing"), "{warning}");
        assert_eq!(sent, ["prepare", "commit", "prepare", "commit"]);
    }

    #[test]
    fn a_disruptive_upgrade_is_offered_only_to_a_caller_that_can_ask() {
        let soft = json(&PrepareResponse::NeedsConsent {
            outcome: Outcome::Soft { attached: 2 },
        });
        let (result, _) = run(vec![soft.clone()], None, true);
        assert_eq!(
            result.unwrap(),
            EnsureUpgrade::Ask(FrontendUpgradeOffer {
                case: UpgradeCase::Soft,
                attached: 2,
                sessions: 2,
                stranded: 0
            })
        );
        let (result, _) = run(vec![soft], None, false);
        let EnsureUpgrade::Keep { warning } = result.unwrap() else {
            panic!("not kept");
        };
        assert!(warning.contains("2 other client(s)"), "{warning}");

        let unreachable = json(&PrepareResponse::NeedsConsent {
            outcome: Outcome::Unreachable {
                attached: 0,
                sessions: 3,
                stranded: 1,
            },
        });
        let (result, _) = run(vec![unreachable.clone()], None, true);
        assert_eq!(
            result.unwrap(),
            EnsureUpgrade::Ask(FrontendUpgradeOffer {
                case: UpgradeCase::Unreachable,
                attached: 0,
                sessions: 3,
                stranded: 1
            })
        );
        let (result, _) = run(vec![unreachable], None, false);
        let EnsureUpgrade::Keep { warning } = result.unwrap() else {
            panic!("not kept");
        };
        assert!(warning.contains("1 session(s) unreachable"), "{warning}");
    }

    #[test]
    fn the_consent_given_goes_with_every_prepare() {
        let consent = FrontendUpgradeConsent {
            attempt: BusyAttemptId::from_bytes([1; 16]),
            identity: identity(),
            candidate: CandidateImageIdentity {
                build: 2,
                checksum: "bb".repeat(32),
            },
            case: UpgradeCase::Soft,
            action: FrontendUpgradeAction::ReplaceFrontend,
        };
        let (result, sent) = run(
            vec![
                ready(),
                changed(),
                ready(),
                served(),
                ControlReply::Answered(status(2, &"bb".repeat(32), 42)),
            ],
            Some(&consent),
            true,
        );
        assert!(matches!(result.unwrap(), EnsureUpgrade::Replaced(_)));
        assert_eq!(sent.iter().filter(|s| **s == "prepare").count(), 2);
    }

    #[test]
    fn full_restarts_rollbacks_and_refusals_map_to_their_rows() {
        let cases = [
            (
                json(&PrepareResponse::NotPreservable {
                    outcome: Outcome::Destructive {
                        attached: 0,
                        sessions: 2,
                    },
                }),
                EnsureUpgrade::Destructive {
                    attached: 0,
                    sessions: 2,
                },
            ),
            (
                json(&PrepareResponse::NotPreservable {
                    outcome: Outcome::FullRestart,
                }),
                EnsureUpgrade::FullRestart,
            ),
        ];
        for (reply, expected) in cases {
            let (result, sent) = run(vec![reply], None, true);
            assert_eq!(result.unwrap(), expected);
            assert_eq!(sent, ["prepare"]);
        }
        let (result, _) = run(
            vec![
                ready(),
                json(&CommitResponse::RolledBack {
                    reason: "it exited".into(),
                }),
            ],
            None,
            false,
        );
        let EnsureUpgrade::RolledBack { warning } = result.unwrap() else {
            panic!("not rolled back");
        };
        assert!(warning.contains("it exited"), "{warning}");
        for reply in [
            json(&PrepareResponse::Refused {
                reason: Refusal::Busy,
            }),
            json(&PrepareResponse::Refused {
                reason: Refusal::Candidate {
                    detail: "too large".into(),
                },
            }),
        ] {
            let (result, _) = run(vec![reply], None, true);
            assert!(matches!(result.unwrap(), EnsureUpgrade::Keep { .. }));
        }
        let (result, _) = run(
            vec![
                ready(),
                json(&CommitResponse::Refused {
                    reason: Refusal::Expired,
                }),
            ],
            None,
            true,
        );
        let EnsureUpgrade::Keep { warning } = result.unwrap() else {
            panic!("not kept");
        };
        assert!(warning.contains("expired"), "{warning}");
    }

    /// A stopping daemon is an error, never one to register with, and a
    /// busy one is kept without a word on what serves on: at the prepare
    /// and at the commit alike.
    #[test]
    fn a_busy_or_stopping_daemon_is_never_said_to_serve_on() {
        let refused = |reason| json(&PrepareResponse::Refused { reason });
        let commit_refused = |reason| json(&CommitResponse::Refused { reason });
        for replies in [
            vec![refused(Refusal::Stopping)],
            vec![ready(), commit_refused(Refusal::Stopping)],
        ] {
            let (result, sent) = run(replies, None, true);
            assert_eq!(result.unwrap_err().to_string(), STOPPING);
            assert!(!sent.contains(&"status"), "{sent:?}");
        }
        for replies in [
            vec![refused(Refusal::Busy)],
            vec![ready(), commit_refused(Refusal::Busy)],
        ] {
            let (result, _) = run(replies, None, true);
            let EnsureUpgrade::Keep { warning } = result.unwrap() else {
                panic!("not kept");
            };
            assert!(warning.contains("under way"), "{warning}");
            assert!(!warning.contains("serves on"), "{warning}");
        }
    }

    /// A prepare the daemon could not read is never sent: the frontend
    /// serves on, with a warning that says why. One that fits is sent.
    #[test]
    fn a_prepare_over_the_request_bound_is_not_sent() {
        // What a candidate with a path of `n` bytes comes to, and the
        // length of the line sent, if one was.
        let with_path = |n: usize| {
            let long = Candidate {
                path: format!("/{}", "p".repeat(n)),
                ..candidate()
            };
            let mut sent = None;
            let result = step_with(
                |request, _| {
                    sent = Some(crate::control::format_request(request).len());
                    Ok(json(&PrepareResponse::UpToDate))
                },
                &long,
                &identity(),
                None,
                true,
            )
            .unwrap();
            (result, sent)
        };
        let fits = (0..REQUEST_BOUND)
            .rev()
            .find(|n| with_path(*n).1.is_some())
            .expect("a short path is sent");
        let (result, sent) = with_path(fits);
        assert_eq!(result, EnsureUpgrade::Legacy);
        assert!(
            sent.is_some_and(|length| length <= REQUEST_BOUND),
            "{sent:?}"
        );
        let (result, sent) = with_path(fits + 1);
        assert_eq!(sent, None, "nothing is sent");
        let EnsureUpgrade::Keep { warning } = result else {
            panic!("not kept");
        };
        assert!(warning.contains("4096-byte bound"), "{warning}");
        assert!(warning.contains("serves on"), "{warning}");
    }
}
