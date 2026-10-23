//! Worker-local physical joins and qualified producer fence.
//! This outcome never substitutes for the parent's exact native process receipt.

use super::worker_protocol::{Settled, WorkerCompletion};
use super::worker_stop::WorkerStop;
use super::worker_threads::WorkerThreads;
use crate::transport_daemon::ServeLoopError;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DrainFailure {
    Initialize,
    Manager,
    RequiredProducer,
    Auxiliary,
}
/// Retains fault observers until checked consumption. A copied pre-runtime
/// snapshot cannot certify the producer fence or hide a returning hook fault.
pub(crate) struct WorkerDrainOutcome {
    stop: WorkerStop,
    first_failure: Option<DrainFailure>,
    manager: Option<Settled>,
    auxiliary: WorkerThreads,
}

impl WorkerDrainOutcome {
    pub(super) fn completion(&mut self) -> Option<WorkerCompletion> {
        // All physical joins already finished. This repeats only the retained
        // fault scan and preserves actual joined bits independently of failure.
        let joined = self.auxiliary.stop_and_join();
        if self.stop.snapshot().first_failure.is_some() {
            self.first_failure
                .get_or_insert(DrainFailure::RequiredProducer);
        }
        if joined.failed != 0 || joined.panicked != 0 || joined.started != 15 || joined.joined != 15
        {
            self.first_failure.get_or_insert(DrainFailure::Auxiliary);
        }
        let completion = WorkerCompletion {
            manager: self.manager?,
            producers: if self.first_failure.is_none() {
                Settled::Joined
            } else {
                Settled::Failed
            },
            runtime: Settled::Joined,
            started: joined.started,
            joined: joined.joined,
            failed: joined.failed,
            panicked: joined.panicked,
        };
        completion.encode().is_ok().then_some(completion)
    }

    pub(crate) fn into_result(mut self) -> anyhow::Result<()> {
        if self.completion().is_some_and(WorkerCompletion::successful) {
            Ok(())
        } else {
            anyhow::bail!(
                "worker local drain failed: {:?}; first stop {:?}",
                self.first_failure,
                self.stop.snapshot().first_stop
            )
        }
    }
}

pub(crate) fn run(
    runtime: tokio::runtime::Runtime,
    manager: impl Future<Output = Result<(), ServeLoopError>>,
    auxiliary: WorkerThreads,
    stop: WorkerStop,
) -> WorkerDrainOutcome {
    run_with_runtime_finish(runtime, manager, auxiliary, stop, drop)
}

fn run_with_runtime_finish(
    runtime: tokio::runtime::Runtime,
    manager: impl Future<Output = Result<(), ServeLoopError>>,
    mut auxiliary: WorkerThreads,
    stop: WorkerStop,
    finish_runtime: impl FnOnce(tokio::runtime::Runtime),
) -> WorkerDrainOutcome {
    // block_on retains the real manager through its joined shutdown result.
    let manager_result = runtime.block_on(manager);
    let mut first_failure = stop
        .snapshot()
        .first_failure
        .map(|_| DrainFailure::RequiredProducer);
    let manager_status = match manager_result {
        Ok(()) => Some(Settled::Joined),
        Err(ServeLoopError::Initialize(error)) => {
            first_failure.get_or_insert(DrainFailure::Initialize);
            crate::log::warn(
                "worker",
                &format!("worker manager initialization failed: {error:#}"),
            );
            None
        }
        Err(ServeLoopError::Shutdown(error)) => {
            first_failure.get_or_insert(DrainFailure::Manager);
            crate::log::warn(
                "worker",
                &format!("worker manager shutdown failed: {error}"),
            );
            Some(Settled::Failed)
        }
    };
    auxiliary.stop_and_join();
    // Synchronous worker entry only: held blocking jobs keep this pending. No
    // timeout/background shutdown or Drop-generated completion may replace it.
    finish_runtime(runtime);
    // Keep exact already-joined custody and bounded fault observers until the
    // consumer checks its outcome. This is not a detached cleanup fallback.
    let mut outcome = WorkerDrainOutcome {
        stop,
        first_failure,
        manager: manager_status,
        auxiliary,
    };
    outcome.completion();
    outcome
}

#[cfg(test)]
#[path = "worker_drain_tests.rs"]
mod tests;
