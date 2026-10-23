//! Bounded cleanup evidence, independent from authentication and child exit.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PamStep {
    Skipped,
    Attempted(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PamCompletion {
    NotOpened,
    Finished {
        close_session: PamStep,
        delete_cred: PamStep,
        end: PamStep,
    },
}

impl PamCompletion {
    /// Combine cleanup from an earlier refused transaction and final teardown.
    pub fn merge(&mut self, later: Self) {
        let Self::Finished {
            close_session: later_close,
            delete_cred: later_delete,
            end: later_end,
        } = later
        else {
            return;
        };
        match self {
            Self::NotOpened => *self = later,
            Self::Finished {
                close_session,
                delete_cred,
                end,
            } => {
                merge_step(close_session, later_close);
                merge_step(delete_cred, later_delete);
                merge_step(end, later_end);
            }
        }
    }

    pub fn succeeded(self) -> bool {
        match self {
            Self::NotOpened => true,
            Self::Finished {
                close_session,
                delete_cred,
                end,
            } => [close_session, delete_cred, end]
                .iter()
                .all(|step| matches!(step, PamStep::Skipped | PamStep::Attempted(0))),
        }
    }
}

fn merge_step(earlier: &mut PamStep, later: PamStep) {
    if matches!(earlier, PamStep::Attempted(code) if *code != 0) {
        return;
    }
    if matches!(later, PamStep::Attempted(_)) {
        *earlier = later;
    }
}

#[cfg(test)]
mod tests {
    use super::{PamCompletion::*, PamStep::*};

    #[test]
    fn pam40_cleanup_aggregate_never_overwrites_earlier_stage_failure() {
        let mut result = Finished {
            close_session: Skipped,
            delete_cred: Attempted(17),
            end: Attempted(4),
        };
        result.merge(Finished {
            close_session: Attempted(0),
            delete_cred: Attempted(0),
            end: Attempted(0),
        });
        assert_eq!(
            result,
            Finished {
                close_session: Attempted(0),
                delete_cred: Attempted(17),
                end: Attempted(4),
            }
        );
        assert!(!result.succeeded());
        result.merge(NotOpened);
        assert!(
            !result.succeeded(),
            "no later transaction cannot erase failed cleanup"
        );
    }

    #[test]
    fn pam40_cleanup_aggregate_distinguishes_no_transaction_and_skipped_steps() {
        let mut result = NotOpened;
        let partial = Finished {
            close_session: Skipped,
            delete_cred: Skipped,
            end: Attempted(0),
        };
        result.merge(partial);
        assert_eq!(
            result, partial,
            "successful pam_start acquired an end obligation"
        );
        assert!(result.succeeded());
        result.merge(Finished {
            close_session: Skipped,
            delete_cred: Attempted(0),
            end: Attempted(0),
        });
        assert!(result.succeeded());
        assert_ne!(result, NotOpened);
    }
}
