//! Execution starts only after registry admission; no capacity waiters.

use super::*;
use crate::channel_server::ChannelSpawner;

pub enum OpenOutcome {
    Ready(UninstalledChannel),
    Failed(String),
}

pub struct ChannelOpenExecutor {
    spawner: Arc<dyn ChannelSpawner>,
    registry: Arc<ChannelOpenRegistry>,
}
impl ChannelOpenExecutor {
    pub fn new(spawner: Arc<dyn ChannelSpawner>, registry: Arc<ChannelOpenRegistry>) -> Self {
        Self { spawner, registry }
    }
    pub fn registry(&self) -> Arc<ChannelOpenRegistry> {
        self.registry.clone()
    }
    pub fn submit(&self, job: &OpenJob) -> Result<(), OpenRefusal> {
        {
            let state = self
                .registry
                .state
                .lock()
                .map_err(|_| OpenRefusal::InvalidIdentity)?;
            if state.fence.is_some() {
                return Err(OpenRefusal::Restarting);
            }
            if !Arc::ptr_eq(&job.registry, &self.registry)
                || !state
                    .jobs
                    .get(&job.id)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &job.registration))
                || job.registration.submitted.swap(true, Ordering::SeqCst)
            {
                return Err(OpenRefusal::InvalidIdentity);
            }
        }
        let spawner = self.spawner.clone();
        let registry = self.registry.clone();
        let registration = job.registration.clone();
        let id = job.id;
        // Admission already charged this exact job. No short lock spans scheduling.
        let worker =
            tokio::task::spawn_blocking(move || run_job(spawner, registry, registration, id));
        *job.registration
            .worker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(worker);
        Ok(())
    }
}

fn run_job(
    spawner: Arc<dyn ChannelSpawner>,
    registry: Arc<ChannelOpenRegistry>,
    registration: Arc<Registration>,
    id: OpenJobId,
) {
    let request = &registration.request;
    let custody = &registration.custody;
    let result = if custody.is_cancelled() {
        // This worker has not called a backend or any possibly creating operation.
        Err(custody.refuse_before_creation("channel opening cancelled".into()))
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            spawner.spawn(
                &request.owner,
                request.login,
                &request.request,
                request.term.as_deref(),
                custody,
            )
        })) {
            Ok(result) => result,
            Err(_) => Err(custody.failure("channel creation failed".into())),
        }
    };
    let (outcome, ready) = match result {
        Ok(channel) => (OpenOutcome::Ready(channel), true),
        Err(failure) => (OpenOutcome::Failed(failure.reason), false),
    };
    *registration
        .outcome
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(outcome);
    registration.session.ready.notify_one();
    if ready && custody.wait_for_resolution() {
        return;
    }
    // No registry/mailbox lock is held while the resource owner cleans up.
    // Unknown leaves registration and receipt notifier alive after this worker ends.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| registry.cleanup(id)));
    registration.session.ready.notify_one();
}
