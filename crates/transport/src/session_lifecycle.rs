//! Private ownership of manager tasks through an explicit shutdown drain.

use std::fmt;
use std::future::{poll_fn, Future};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

use crate::control_job::JobLease;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallbackFailure {
    Panicked,
}

/// Rust does not promise that a panic payload has a nonpanicking destructor.
/// A second panic while disposing it is exceptional: abort rather than leak an
/// arbitrary payload, recursively unwind, or report successful cleanup.
fn dispose_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    match catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        Ok(()) => {}
        Err(_secondary_payload) => std::process::abort(),
    }
}

struct PanicPayload(Option<Box<dyn std::any::Any + Send>>);
impl Drop for PanicPayload {
    fn drop(&mut self) {
        if let Some(payload) = self.0.take() {
            dispose_panic_payload(payload);
        }
    }
}

/// Completion remains in the existing JoinSet until the manager observes the
/// real blocking join. Publication and undeliverable-result destruction happen
/// outside its mutex, before the finite worker lease is refunded.
struct CallbackCompletion {
    _lease: JobLease,
    publication: Option<Box<dyn FnOnce() + Send>>,
}
impl Drop for CallbackCompletion {
    fn drop(&mut self) {
        // Unexpected owner cancellation detaches tasks. Their completed output
        // may then be discarded without normal manager publication; contain
        // result destruction there as well, after actual callback completion.
        if let Some(publication) = self.publication.take() {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(publication))) {
                dispose_panic_payload(payload);
            }
        }
    }
}

/// Sticky daemon stop request. Clones observe the same request even if they
/// subscribe after it was issued. A request is not a cleanup receipt.
#[derive(Clone)]
pub struct Shutdown(watch::Sender<bool>);
impl Default for Shutdown {
    fn default() -> Self {
        Self(watch::channel(false).0)
    }
}
impl Shutdown {
    pub fn request(&self) {
        self.0.send_replace(true);
    }
    pub fn is_requested(&self) -> bool {
        *self.0.borrow()
    }
    pub async fn requested(&self) {
        let mut rx = self.0.subscribe();
        if !*rx.borrow_and_update() {
            let _ = rx.changed().await;
        }
    }
}

/// An owned task failed. Other tasks are still drained before this is returned;
/// it does not certify process or descriptor cleanup in the failed task.
#[derive(Debug, Clone)]
pub struct ShutdownError(String);
impl fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session task failed during shutdown: {}", self.0)
    }
}
impl std::error::Error for ShutdownError {}

/// Completion is published only after joining the blocking worker itself.
#[derive(Clone, Default)]
pub(crate) struct WorkerReceipt(Arc<Mutex<WorkerState>>);
#[derive(Default)]
struct WorkerState {
    joined: Option<Result<(), String>>,
    notifier: Option<crate::channel_server::ReapNotifier>,
}
impl WorkerReceipt {
    pub(crate) fn joined(&self) -> Option<Result<(), String>> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .joined
            .clone()
    }
    pub(crate) fn set_notifier(&self, notifier: crate::channel_server::ReapNotifier) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).notifier = Some(notifier);
    }
    fn finish(&self, result: Result<(), String>) {
        let notifier = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.joined = Some(result);
            state.notifier.clone()
        };
        if let Some(notifier) = notifier {
            notifier.notify();
        }
    }
}

#[derive(Default)]
struct TaskOwner {
    tasks: Mutex<JoinSet<Option<CallbackCompletion>>>,
    failure: Mutex<Option<ShutdownError>>,
}
impl Drop for TaskOwner {
    fn drop(&mut self) {
        // Unexpected caller cancellation retains the legacy detached lifetime;
        // dropping the tracker must never abort a backend's cleanup. Only the
        // explicit drain below is a successful joined-lifetime receipt.
        self.tasks
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .detach_all();
    }
}

#[derive(Default)]
pub(super) struct Lifecycle {
    pub(super) shutdown: Shutdown,
    pub(super) control_budget: crate::control_budget::GlobalBudget,
    owner: TaskOwner,
}
impl Lifecycle {
    pub(super) fn new(shutdown: Shutdown) -> Arc<Self> {
        Arc::new(Self {
            shutdown,
            control_budget: crate::control_budget::GlobalBudget::default(),
            owner: TaskOwner::default(),
        })
    }
    pub(super) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        // Tokio does not poll the future synchronously. The short lock covers
        // registration only; no backend callback runs under this lock.
        self.owner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .spawn(async move {
                future.await;
                None
            });
    }
    pub(super) fn spawn_callback<T: Send + 'static>(
        &self,
        lease: JobLease,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> oneshot::Receiver<Result<T, CallbackFailure>> {
        let (sender, receiver) = oneshot::channel();
        self.owner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .spawn_blocking(move || {
                let result = catch_unwind(AssertUnwindSafe(work))
                    .map_err(|payload| PanicPayload(Some(payload)));
                Some(CallbackCompletion {
                    _lease: lease,
                    publication: Some(Box::new(move || {
                        let result = result.map_err(|payload| {
                            drop(payload);
                            CallbackFailure::Panicked
                        });
                        // A missing receiver destroys its result inside the
                        // manager's catch scope, never inside a running worker.
                        drop(sender.send(result));
                    })),
                })
            });
        receiver
    }
    pub(super) fn spawn_blocking(&self, work: impl FnOnce() + Send + 'static) -> WorkerReceipt {
        let receipt = WorkerReceipt::default();
        let completed = receipt.clone();
        // Register the supervisor before it can launch the blocking work. Its
        // handle remains owned even if the backend runner is cancelled.
        self.spawn(async move {
            let result = tokio::task::spawn_blocking(work)
                .await
                .map_err(|e| e.to_string());
            completed.finish(result.clone());
            if let Err(error) = result {
                panic!("owned blocking worker failed: {error}");
            }
        });
        receipt
    }
    pub(super) fn is_empty(&self) -> bool {
        self.owner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }
    pub(super) async fn next(&self) -> Option<()> {
        let completed = poll_fn(|cx| {
            self.owner
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await?;
        let failure = match completed {
            Ok(Some(mut completion)) => {
                let publication = completion.publication.take().unwrap();
                match catch_unwind(AssertUnwindSafe(publication)) {
                    Ok(()) => None,
                    Err(payload) => {
                        dispose_panic_payload(payload);
                        Some(ShutdownError("callback result publication panicked".into()))
                    }
                }
                // Completion still owns its lease here. No await separates
                // actual join, caught publication and this final refund.
            }
            Ok(None) => None,
            Err(error) => Some(ShutdownError(error.to_string())),
        };
        if let Some(failure) = failure {
            self.owner
                .failure
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert(failure);
        }
        Some(())
    }
    pub(super) async fn drain(&self) -> Result<(), ShutdownError> {
        // Only already-registered tasks may register descendants now. Their
        // handles cannot complete before that registration, so an empty set
        // cannot race a still-running publisher of new work.
        while self.next().await.is_some() {}
        self.owner
            .failure
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("session_lifecycle_callback_tests.rs");
    use std::task::Poll;
    use tokio::sync::{oneshot, Notify};

    #[tokio::test]
    async fn failed_blocking_worker_still_joins_an_independently_held_worker() {
        let lifecycle = Lifecycle::default();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let (started, entered) = oneshot::channel();
        let held_receipt = lifecycle.spawn_blocking(move || {
            let _ = started.send(());
            let _ = held.recv();
        });
        let failed_receipt =
            lifecycle.spawn_blocking(|| panic!("controlled blocking worker failure"));
        assert!(
            !lifecycle.is_empty(),
            "register before blocking work is published"
        );
        entered.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while failed_receipt.joined().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(failed_receipt.joined().unwrap().is_err());
        assert!(
            held_receipt.joined().is_none(),
            "held syscall is not a join receipt"
        );
        let mut drain = Box::pin(lifecycle.drain());
        assert!(poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await);
        drop(release);
        assert!(
            drain.await.is_err(),
            "report failure after all other workers join"
        );
        assert_eq!(held_receipt.joined(), Some(Ok(())));
        assert!(lifecycle.is_empty());
    }

    #[tokio::test]
    async fn shutdown_is_sticky_for_late_observers() {
        let shutdown = Shutdown::default();
        shutdown.request();
        shutdown.request();
        assert!(shutdown.clone().is_requested());
        shutdown.clone().requested().await;
    }

    #[tokio::test]
    async fn a_task_failure_does_not_abandon_another_owned_cleanup() {
        let lifecycle = Arc::new(Lifecycle::default());
        let (release, held) = oneshot::channel::<()>();
        lifecycle.spawn(async { panic!("controlled owned task failure") });
        lifecycle.spawn(async move {
            let _ = held.await;
        });
        while lifecycle.owner.failure.lock().unwrap().is_none() {
            lifecycle.next().await.unwrap();
        }
        let mut drain = Box::pin(lifecycle.drain());
        assert!(
            poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await,
            "task failure refunded still-held cleanup"
        );
        drop(release);
        assert!(
            drain.await.is_err(),
            "retain the first task failure after draining"
        );
        assert!(lifecycle.is_empty());
    }

    #[tokio::test]
    async fn a_registered_parent_cannot_publish_a_child_after_empty_drain() {
        let lifecycle = Arc::new(Lifecycle::default());
        let owner = lifecycle.clone();
        let (parent_release, parent_held) = oneshot::channel::<()>();
        let (child_release, child_held) = oneshot::channel::<()>();
        let published = Arc::new(Notify::new());
        let child_published = published.clone();
        lifecycle.spawn(async move {
            let _ = parent_held.await;
            owner.spawn(async move {
                let _ = child_held.await;
            });
            child_published.notify_one();
        });
        let mut drain = Box::pin(lifecycle.drain());
        assert!(poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await);
        drop(parent_release);
        published.notified().await;
        assert!(
            poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await,
            "parent completion lost registered child custody"
        );
        drop(child_release);
        drain.await.unwrap();
        assert!(lifecycle.is_empty());
    }

    #[tokio::test]
    async fn completed_handles_are_reclaimed_during_normal_service() {
        let lifecycle = Lifecycle::default();
        for _ in 0..128 {
            lifecycle.spawn(async {});
            lifecycle.next().await.unwrap();
            assert!(lifecycle.is_empty());
        }
    }
}
