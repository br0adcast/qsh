//! Rejecting per-channel metadata ownership and coalesced capacity wakeups.

use crate::channel_geometry::ChannelInstance;
use std::sync::{Arc, Mutex};

pub const ORDINARY_ENTRIES: usize = 128;
pub const ORDINARY_BYTES: usize = 8192;
pub const LIFECYCLE_ENTRIES: usize = 8;
pub const LIFECYCLE_BYTES: usize = 256;
pub const GEOMETRY_BYTES: usize = 27;
pub const OUTPUT_GAP_BYTES: usize = 14;
/// Declared allowance for an internal final delivery marker. Integration must
/// assert the eventual marker representation fits, before feature activation.
pub const DELIVERY_MARKER_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryClass {
    Ordinary,
    Lifecycle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitKey {
    pub instance: ChannelInstance,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitRegistration {
    Ready,
    Waiting,
    Retired,
}
/// Shared across producer and retained-output owners, not one budget per queue.
#[derive(Clone)]
pub struct TimelineBudget {
    inner: Arc<BudgetInner>,
}
struct BudgetInner {
    state: Mutex<BudgetState>,
    notify: Box<dyn Fn(WaitKey) + Send + Sync>,
}
struct BudgetState {
    scope: WaitKey,
    ordinary: Usage,
    lifecycle: Usage,
    waiter: bool,
    notification_pending: bool,
}
#[derive(Default)]
struct Usage {
    entries: usize,
    bytes: usize,
}
impl BudgetState {
    fn usage(&self, class: EntryClass) -> &Usage {
        match class {
            EntryClass::Ordinary => &self.ordinary,
            EntryClass::Lifecycle => &self.lifecycle,
        }
    }
    fn usage_mut(&mut self, class: EntryClass) -> &mut Usage {
        match class {
            EntryClass::Ordinary => &mut self.ordinary,
            EntryClass::Lifecycle => &mut self.lifecycle,
        }
    }
    fn has_room(&self, class: EntryClass, bytes: usize) -> bool {
        let (entries, limit) = match class {
            EntryClass::Ordinary => (ORDINARY_ENTRIES, ORDINARY_BYTES),
            EntryClass::Lifecycle => (LIFECYCLE_ENTRIES, LIFECYCLE_BYTES),
        };
        let usage = self.usage(class);
        bytes > 0 && usage.entries < entries && bytes <= limit.saturating_sub(usage.bytes)
    }
}

/// Exclusive ownership of a charged metadata entry. Moving a permit between
/// queues transfers ownership without making room. Only drop releases it.
pub struct TimelinePermit {
    inner: Arc<BudgetInner>,
    class: EntryClass,
    bytes: usize,
}

impl TimelineBudget {
    /// `notify` must wake the owner without creating an unbounded event queue.
    /// It runs outside the budget lock, possibly after its scope was retired.
    /// The owner must check `take_notification` with the captured key.
    pub fn new(
        instance: ChannelInstance,
        generation: u64,
        notify: impl Fn(WaitKey) + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(BudgetInner {
                state: Mutex::new(BudgetState {
                    scope: WaitKey {
                        instance,
                        generation,
                    },
                    ordinary: Usage::default(),
                    lifecycle: Usage::default(),
                    waiter: false,
                    notification_pending: false,
                }),
                notify: Box::new(notify),
            }),
        }
    }

    pub fn try_reserve(&self, class: EntryClass, bytes: usize) -> Option<TimelinePermit> {
        let mut state = self.inner.state.lock().expect("timeline budget");
        if !state.has_room(class, bytes) {
            return None;
        }
        let usage = state.usage_mut(class);
        usage.entries += 1;
        usage.bytes += bytes;
        Some(TimelinePermit {
            inner: self.inner.clone(),
            class,
            bytes,
        })
    }

    /// Register the single deferred ordinary GEOMETRY result, rechecking its
    /// complete admission under the same lock used by permit release. Ready
    /// means retry immediately; Waiting guarantees a future release can wake it.
    pub fn register_waiter_and_recheck(
        &self,
        instance: ChannelInstance,
        generation: u64,
    ) -> WaitRegistration {
        let mut state = self.inner.state.lock().expect("timeline budget");
        if state.scope
            != (WaitKey {
                instance,
                generation,
            })
        {
            return WaitRegistration::Retired;
        }
        state.notification_pending = false;
        if state.has_room(EntryClass::Ordinary, GEOMETRY_BYTES) {
            state.waiter = false;
            WaitRegistration::Ready
        } else {
            state.waiter = true;
            WaitRegistration::Waiting
        }
    }

    /// Consume exactly the notification for this attachment. An old callback
    /// cannot clear a newer attachment's waiter or pending signal.
    pub fn take_notification(&self, instance: ChannelInstance, generation: u64) -> bool {
        let mut state = self.inner.state.lock().expect("timeline budget");
        if state.scope
            != (WaitKey {
                instance,
                generation,
            })
        {
            return false;
        }
        let pending = std::mem::take(&mut state.notification_pending);
        if pending {
            state.waiter = false;
        }
        pending
    }

    /// Retire a previous attachment's waiter without releasing any owned
    /// output permits. Generations advance; stale resets cannot resurrect one.
    pub fn reset_attachment(&self, instance: ChannelInstance, generation: u64) -> bool {
        let mut state = self.inner.state.lock().expect("timeline budget");
        if state.scope.instance != instance || generation <= state.scope.generation {
            return false;
        }
        state.scope.generation = generation;
        state.waiter = false;
        state.notification_pending = false;
        true
    }

    #[cfg(test)]
    fn usage(&self, class: EntryClass) -> (usize, usize) {
        let state = self.inner.state.lock().expect("timeline budget");
        let usage = state.usage(class);
        (usage.entries, usage.bytes)
    }
}

impl Drop for TimelinePermit {
    fn drop(&mut self) {
        let notify = {
            let mut state = self.inner.state.lock().expect("timeline budget");
            let usage = state.usage_mut(self.class);
            usage.entries -= 1;
            usage.bytes -= self.bytes;
            if state.waiter
                && !state.notification_pending
                && state.has_room(EntryClass::Ordinary, GEOMETRY_BYTES)
            {
                state.notification_pending = true;
                Some(state.scope)
            } else {
                None
            }
        };
        if let Some(key) = notify {
            (self.inner.notify)(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn instance() -> ChannelInstance {
        ChannelInstance::new(1).unwrap()
    }
    fn budget() -> TimelineBudget {
        TimelineBudget::new(instance(), 1, |_| {})
    }

    #[test]
    fn lifecycle_wire_and_declared_marker_inventory_fits_reserved_allowance() {
        use crate::channel_geometry::{GeometryOutcome, GeometryRecord, OutputGapCause};
        use crate::shell_frame::{encode_shell, ShellRecord};
        let geometry = encode_shell(&ShellRecord::Geometry(GeometryRecord {
            instance: instance(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        }))
        .unwrap();
        let gap = encode_shell(&ShellRecord::OutputGap {
            instance: instance(),
            cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
        })
        .unwrap();
        let exit = crate::channel::encode_server(&crate::channel::ServerRecord::Exit {
            stream: 16,
            code: 0,
        });
        assert_eq!(geometry.len(), GEOMETRY_BYTES);
        assert_eq!(gap.len(), OUTPUT_GAP_BYTES);
        // Bootstrap/current geometry, one gap, one declared marker and Exit.
        // Final Stage3/4 marker types must separately prove this declaration.
        let costs = [
            geometry.len(),
            geometry.len(),
            gap.len(),
            DELIVERY_MARKER_BYTES,
            exit.len(),
        ];
        let a = budget();
        let held: Vec<_> = costs
            .into_iter()
            .map(|n| a.try_reserve(EntryClass::Lifecycle, n).unwrap())
            .collect();
        assert_eq!(a.usage(EntryClass::Lifecycle), (5, 110));
        drop(held);
    }

    #[test]
    fn concurrent_register_and_release_never_lose_capacity_wakeup() {
        for _ in 0..32 {
            let a = budget();
            let p = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other_barrier = barrier.clone();
            let release = std::thread::spawn(move || {
                other_barrier.wait();
                drop(p);
            });
            barrier.wait();
            let result = a.register_waiter_and_recheck(instance(), 1);
            release.join().unwrap();
            match result {
                WaitRegistration::Ready => {}
                WaitRegistration::Waiting => assert!(a.take_notification(instance(), 1)),
                WaitRegistration::Retired => panic!("the scope never changed"),
            }
            assert!(a.try_reserve(EntryClass::Ordinary, 27).is_some());
        }
    }

    #[test]
    fn callback_delayed_past_reset_cannot_consume_newest_wakeup() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let release_rx = Mutex::new(release_rx);
        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timeout = timed_out.clone();
        let a = TimelineBudget::new(instance(), 1, move |key| {
            if key.generation == 1 {
                started_tx.send(key).unwrap();
                if release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .is_err()
                {
                    timeout.store(true, Ordering::SeqCst);
                }
            }
        });
        let p = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 1),
            WaitRegistration::Waiting
        );
        let release = std::thread::spawn(move || drop(p));
        let old_key = started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        // These acquire the same mutex while callback 1 is deliberately paused.
        assert!(a.reset_attachment(instance(), 2));
        let p2 = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 2),
            WaitRegistration::Waiting
        );
        drop(p2);
        assert!(!a.take_notification(old_key.instance, old_key.generation));
        release_tx.send(()).unwrap();
        release.join().unwrap();
        assert!(
            !timed_out.load(Ordering::SeqCst),
            "callback ran outside the budget lock"
        );
        assert!(a.take_notification(instance(), 2));
        assert!(!a.take_notification(instance(), 2));
    }

    #[test]
    fn timeline_limit_is_shared_across_owners() {
        let a = budget();
        let b = a.clone();
        let mut permits = Vec::new();
        for _ in 0..128 {
            permits.push(a.try_reserve(EntryClass::Ordinary, 27).unwrap());
        }
        assert!(b.try_reserve(EntryClass::Ordinary, 1).is_none());
        assert_eq!(a.usage(EntryClass::Ordinary), (128, 3456));
        drop(permits.pop());
        assert!(b.try_reserve(EntryClass::Ordinary, 27).is_some());
        drop(permits);
        let full = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
        assert!(b.try_reserve(EntryClass::Ordinary, 1).is_none());
        assert_eq!(b.usage(EntryClass::Ordinary), (1, 8192));
        drop(full);
        assert!(a.try_reserve(EntryClass::Ordinary, 0).is_none());
        assert!(a.try_reserve(EntryClass::Ordinary, usize::MAX).is_none());
        assert_eq!(a.usage(EntryClass::Ordinary), (0, 0));
    }

    #[test]
    fn timeline_permits_drop_once() {
        let a = budget();
        let permit = a.try_reserve(EntryClass::Ordinary, 27).unwrap();
        let mut outbound = vec![permit];
        let retained = outbound.pop().unwrap();
        assert_eq!(a.usage(EntryClass::Ordinary), (1, 27));
        let b = a.clone();
        drop(a);
        drop(outbound);
        assert_eq!(b.usage(EntryClass::Ordinary), (1, 27));
        drop(retained);
        assert_eq!(b.usage(EntryClass::Ordinary), (0, 0));
    }

    #[test]
    fn timeline_lifecycle_reserve_is_separate() {
        let a = budget();
        let _full = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
        let mut lifecycle = Vec::new();
        for _ in 0..8 {
            lifecycle.push(a.try_reserve(EntryClass::Lifecycle, 32).unwrap());
        }
        assert!(a.try_reserve(EntryClass::Lifecycle, 1).is_none());
        assert_eq!(a.usage(EntryClass::Lifecycle), (8, 256));
        drop(lifecycle);
        let _bytes = a.try_reserve(EntryClass::Lifecycle, 256).unwrap();
        assert!(a.try_reserve(EntryClass::Lifecycle, 1).is_none());
        assert!(a.try_reserve(EntryClass::Ordinary, 1).is_none());
    }

    #[test]
    fn waiter_registration_cannot_lose_release() {
        for release_first in [true, false] {
            let wakes = Arc::new(AtomicUsize::new(0));
            let count = wakes.clone();
            let a = TimelineBudget::new(instance(), 1, move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            });
            let permit = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
            if release_first {
                drop(permit);
                assert_eq!(
                    a.register_waiter_and_recheck(instance(), 1),
                    WaitRegistration::Ready
                );
                assert_eq!(wakes.load(Ordering::SeqCst), 0);
            } else {
                assert_eq!(
                    a.register_waiter_and_recheck(instance(), 1),
                    WaitRegistration::Waiting
                );
                drop(permit);
                assert_eq!(wakes.load(Ordering::SeqCst), 1);
                assert!(a.take_notification(instance(), 1));
                assert!(!a.take_notification(instance(), 1));
                assert_eq!(
                    a.register_waiter_and_recheck(instance(), 1),
                    WaitRegistration::Ready
                );
            }
        }
    }

    #[test]
    fn stale_notification_cannot_consume_new_attachment_wakeup() {
        let count = Arc::new(AtomicUsize::new(0));
        let wakes = count.clone();
        let a = TimelineBudget::new(instance(), 1, move |_| {
            wakes.fetch_add(1, Ordering::SeqCst);
        });
        let p = a.try_reserve(EntryClass::Ordinary, 8192).unwrap();
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 1),
            WaitRegistration::Waiting
        );
        assert!(a.reset_attachment(instance(), 2));
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 1),
            WaitRegistration::Retired
        );
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 2),
            WaitRegistration::Waiting
        );
        drop(p);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!a.take_notification(instance(), 1));
        assert!(!a.take_notification(ChannelInstance::new(2).unwrap(), 2));
        assert!(!a.reset_attachment(instance(), 1));
        assert!(a.take_notification(instance(), 2));
    }

    #[test]
    fn repeated_releases_coalesce_until_notification_taken() {
        let count = Arc::new(AtomicUsize::new(0));
        let wakes = count.clone();
        let a = TimelineBudget::new(instance(), 1, move |_| {
            wakes.fetch_add(1, Ordering::SeqCst);
        });
        let mut p = Vec::new();
        for _ in 0..128 {
            p.push(a.try_reserve(EntryClass::Ordinary, 27).unwrap());
        }
        assert_eq!(
            a.register_waiter_and_recheck(instance(), 1),
            WaitRegistration::Waiting
        );
        drop(p);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(a.take_notification(instance(), 1));
        assert!(!a.take_notification(instance(), 1));
    }
}
