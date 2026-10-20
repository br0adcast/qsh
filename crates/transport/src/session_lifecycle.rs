//! Private ownership of manager tasks through an explicit shutdown drain.

use std::fmt;
use std::future::{poll_fn, Future};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;
use tokio::task::JoinSet;

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

#[derive(Default)]
struct TaskOwner {
    tasks: Mutex<JoinSet<()>>,
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
            .spawn(future);
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
        if let Err(error) = completed {
            self.owner
                .failure
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert_with(|| ShutdownError(error.to_string()));
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
    use std::task::Poll;
    use tokio::sync::{oneshot, Notify};

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
