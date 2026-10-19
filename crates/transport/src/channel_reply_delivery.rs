//! Exact-instance completion ownership for generated terminal replies.
//!
//! The caller admits each reply under the existing local input byte/item quota
//! before reserving a receipt. Receipts do not grant transport credit. Their
//! count is bounded by those admitted local items, including writer-held ones.

use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReplySnapshot {
    pub(crate) pending: usize,
    pub(crate) failed: bool,
    pub(crate) sealed: bool,
}

struct Inner {
    state: Mutex<ReplySnapshot>,
    ready: Arc<Notify>,
}

/// One instance's reply state. A reused stream receives a fresh owner.
#[derive(Clone)]
pub(crate) struct ReplyDelivery(Arc<Inner>);

impl ReplyDelivery {
    pub(crate) fn new(ready: Arc<Notify>) -> Self {
        Self(Arc::new(Inner {
            state: Mutex::new(ReplySnapshot::default()),
            ready,
        }))
    }

    /// Call only after local input quota admission and before queue publication.
    pub(crate) fn try_reserve(&self) -> Option<ReplyReceipt> {
        let mut state = self.0.state.lock().unwrap();
        if state.sealed || state.failed {
            return None;
        }
        state.pending = state.pending.checked_add(1)?;
        Some(ReplyReceipt {
            inner: self.0.clone(),
            finished: false,
        })
    }

    pub(crate) fn seal(&self) {
        let mut state = self.0.state.lock().unwrap();
        if state.sealed {
            return;
        }
        state.sealed = true;
        drop(state);
        self.0.ready.notify_one();
    }

    /// Read failure and pending ownership together before final-marker admission.
    pub(crate) fn snapshot(&self) -> ReplySnapshot {
        *self.0.state.lock().unwrap()
    }
}

/// An unfinished drop is failure, including a queue or worker being discarded.
/// It is deliberately non-cloneable and moves with its admitted local payload.
pub(crate) struct ReplyReceipt {
    inner: Arc<Inner>,
    finished: bool,
}

impl ReplyReceipt {
    pub(crate) fn finish(mut self, success: bool) {
        self.settle(success);
    }

    fn settle(&mut self, success: bool) {
        if self.finished {
            return;
        }
        let mut state = self.inner.state.lock().unwrap();
        // Publish failure and release pending ownership in one transaction.
        // A finalizer must never observe pending0 before this failure flag.
        state.failed |= !success;
        state.pending = state.pending.checked_sub(1).expect("owned reply receipt");
        self.finished = true;
        drop(state);
        self.inner.ready.notify_one();
    }
}

impl Drop for ReplyReceipt {
    fn drop(&mut self) {
        self.settle(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::time::Duration;

    fn owner() -> (ReplyDelivery, Arc<Notify>) {
        let ready = Arc::new(Notify::new());
        (ReplyDelivery::new(ready.clone()), ready)
    }

    #[test]
    fn reply_delivery44_success_settles_once_and_seal_rejects_new_work() {
        let (owner, _) = owner();
        let first = owner.try_reserve().unwrap();
        let second = owner.try_reserve().unwrap();
        assert_eq!(owner.snapshot().pending, 2);
        owner.seal();
        assert!(owner.try_reserve().is_none());
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 2,
                failed: false,
                sealed: true
            }
        );
        first.finish(true);
        assert_eq!(owner.snapshot().pending, 1);
        second.finish(true);
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: false,
                sealed: true
            }
        );
    }

    #[test]
    fn reply_delivery44_failure_is_sticky_while_other_owned_receipts_settle() {
        let (owner, _) = owner();
        let failed = owner.try_reserve().unwrap();
        let successful = owner.try_reserve().unwrap();
        failed.finish(false);
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 1,
                failed: true,
                sealed: false
            }
        );
        assert!(owner.try_reserve().is_none());
        owner.seal();
        successful.finish(true);
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: true,
                sealed: true
            }
        );
    }

    #[test]
    fn reply_delivery44_receiver_drop_settles_unprocessed_queued_receipts() {
        let (owner, _) = owner();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(owner.try_reserve().unwrap()).unwrap();
        tx.send(owner.try_reserve().unwrap()).unwrap();
        owner.seal();
        drop(rx);
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: true,
                sealed: true
            }
        );
    }

    #[test]
    fn reply_delivery44_worker_unwind_settles_failed_receipt() {
        let (owner, _) = owner();
        let held = owner.try_reserve().unwrap();
        let worker = std::thread::spawn(move || {
            let _owned = held;
            panic!("synthetic writer failure");
        });
        assert!(worker.join().is_err());
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: true,
                sealed: false
            }
        );
    }

    #[tokio::test]
    async fn reply_delivery44_completion_wake_is_retained_until_runner_polls() {
        for success in [false, true] {
            let (owner, ready) = owner();
            let held = owner.try_reserve().unwrap();
            owner.seal();
            // Consume any seal notification so completion must supply its own.
            let _ = tokio::time::timeout(Duration::from_millis(1), ready.notified()).await;
            held.finish(success);
            tokio::time::timeout(Duration::from_secs(1), ready.notified())
                .await
                .unwrap();
            assert_eq!(
                owner.snapshot(),
                ReplySnapshot {
                    pending: 0,
                    failed: !success,
                    sealed: true
                }
            );
        }
    }

    #[test]
    fn reply_delivery44_retired_instance_cannot_poison_reused_stream() {
        let ready = Arc::new(Notify::new());
        let old = ReplyDelivery::new(ready.clone());
        let old_receipt = old.try_reserve().unwrap();
        old.seal();
        let new = ReplyDelivery::new(ready);
        let new_receipt = new.try_reserve().unwrap();
        drop(old_receipt);
        assert_eq!(
            old.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: true,
                sealed: true
            }
        );
        assert_eq!(
            new.snapshot(),
            ReplySnapshot {
                pending: 1,
                failed: false,
                sealed: false
            }
        );
        new_receipt.finish(true);
        assert_eq!(new.snapshot(), ReplySnapshot::default());
    }

    #[test]
    fn reply_delivery44_seal_and_reservation_share_one_atomic_boundary() {
        let (owner, _) = owner();
        let barrier = Arc::new(Barrier::new(2));
        let contender = owner.clone();
        let start = barrier.clone();
        let thread = std::thread::spawn(move || {
            start.wait();
            contender.try_reserve()
        });
        barrier.wait();
        owner.seal();
        let receipt = thread.join().unwrap();
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: usize::from(receipt.is_some()),
                failed: false,
                sealed: true,
            }
        );
        assert!(owner.try_reserve().is_none());
        if let Some(receipt) = receipt {
            receipt.finish(true);
        }
        assert_eq!(
            owner.snapshot(),
            ReplySnapshot {
                pending: 0,
                failed: false,
                sealed: true
            }
        );
    }
}
