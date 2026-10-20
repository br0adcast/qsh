//! Finite callback representations for one admitted job envelope.

use crate::control_budget::{CapacityError, Job, JobPermit, SessionBudget};
use std::sync::Arc;

#[must_use = "retain future callback phases until the chain ends"]
pub(crate) struct JobOwner {
    permit: Arc<JobPermit>,
    workers_left: usize,
}

/// A registered blocking callback retains this through actual join and reap.
/// Callers cannot clone a lease or manufacture additional representations.
#[must_use = "move into registered blocking custody until actual join"]
pub(crate) struct JobLease {
    _permit: Arc<JobPermit>,
}

impl JobOwner {
    pub(crate) fn reserve(session: &SessionBudget, job: Job) -> Result<Self, CapacityError> {
        Ok(Self {
            permit: Arc::new(session.job(job)?),
            workers_left: match job {
                Job::About => 1,
                Job::Update => 3,
            },
        })
    }

    pub(crate) fn take_worker(&mut self) -> Option<JobLease> {
        if self.workers_left == 0 {
            return None;
        }
        self.workers_left -= 1;
        Some(JobLease {
            _permit: Arc::clone(&self.permit),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_budget::GlobalBudget;

    #[test]
    fn capacity_job_fixed_worker_leases_cannot_be_reissued_after_completion() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        for (job, workers) in [(Job::About, 1), (Job::Update, 3)] {
            let mut owner = JobOwner::reserve(&session, job).unwrap();
            for _ in 0..workers {
                drop(owner.take_worker().expect("reserved callback phase"));
                assert_eq!(global.retained_for_test().2, 1);
            }
            assert!(
                owner.take_worker().is_none(),
                "completed phases cannot create another registered representation"
            );
            drop(owner);
            assert_eq!(global.retained_for_test().2, 0);
        }
    }

    #[test]
    fn capacity_job_retired_owner_retains_all_leases_until_final_drop() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let mut owner = JobOwner::reserve(&session, Job::Update).unwrap();
        let first = owner.take_worker().unwrap();
        let second = owner.take_worker().unwrap();
        let third = owner.take_worker().unwrap();
        session.retire();
        drop(owner);
        drop(session);
        drop(first);
        drop(second);
        assert_eq!(global.retained_for_test().2, 1);
        drop(third);
        assert_eq!(global.retained_for_test().2, 0);
        assert!(JobOwner::reserve(&global.session(1), Job::Update).is_ok());
    }
}
