//! Private same-process functional qualification support, not release telemetry.

use crate::channel_geometry::ChannelInstance;
use crate::session_manager::{AttachmentContext, LoginId};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

/// Explicit fixture owner, never included in scalar reports or Debug output.
/// Attachment must come from actual authenticated Live/acceptance, not an
/// assumed generation. The fixture already supplies its login token to connect.
#[derive(Clone, Copy)]
pub struct Registration {
    pub login: LoginId,
    pub attachment: AttachmentContext,
    pub stream: u8,
    pub instance: ChannelInstance,
}

static ACTIVE: Mutex<Weak<Observation>> = Mutex::new(Weak::new());
#[cfg(test)]
pub(crate) static TEST_SCOPE: Mutex<()> = Mutex::new(());

struct ReportState {
    snapshot: Mutex<Snapshot>,
    sequence: AtomicU64,
    retired: AtomicBool,
    missed: AtomicU64,
    changed: Notify,
}
impl ReportState {
    fn retire(&self) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            self.sequence.fetch_add(1, Ordering::AcqRel);
            self.changed.notify_one();
        }
    }
    fn publish(&self, mut next: Snapshot) {
        let Ok(mut previous) = self.snapshot.try_lock() else {
            self.missed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if self.retired.load(Ordering::Acquire) {
            return;
        }
        next = next.classify();
        next.values_available = true;
        next.sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        next.pending_high_water = previous.pending_high_water.max(next.source_pending);
        next.tail_high_water = previous.tail_high_water.max(next.reliable_tail);
        next.combined_high_water = previous
            .combined_high_water
            .max(next.source_pending.saturating_add(next.reliable_tail));
        *previous = next;
        drop(previous);
        self.changed.notify_one();
    }
}
struct Observation {
    target: Registration,
    report: Arc<ReportState>,
}

/// One fixed latest-value report with copy-only reads, no exposed lock guard.
/// One logical consumer; notifications coalesce and do not count owner turns.
pub struct Reports {
    state: Arc<ReportState>,
    seen: u64,
}
impl Reports {
    pub fn latest(&self) -> Option<Snapshot> {
        let retired = self.state.retired.load(Ordering::Acquire);
        let mut sample = match self.state.snapshot.try_lock() {
            Ok(sample) => *sample,
            Err(_) if retired => Snapshot::default(),
            Err(_) => return None,
        };
        sample.publications_skipped = self.state.missed.load(Ordering::Relaxed);
        if self.state.retired.load(Ordering::Acquire) {
            sample.sequence = self.state.sequence.load(Ordering::Acquire);
            sample.valid = false;
            sample.retired = true;
            sample.credit_blocked = false;
        }
        Some(sample)
    }
    /// Register before rechecking the copied snapshot. Returns None after the
    /// retirement report has been observed; no timer or polling fallback.
    pub async fn changed(&mut self) -> Option<Snapshot> {
        loop {
            let notified = self.state.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(sample) = self.latest() {
                if sample.sequence > self.seen {
                    self.seen = sample.sequence;
                    return Some(sample);
                }
                if sample.retired {
                    return None;
                }
            }
            notified.await;
        }
    }
}

/// One active qualification registration. Retaining old copied reports cannot
/// keep registration occupied or allow an old scope to affect a new one.
pub struct Scope {
    observation: Arc<Observation>,
}
impl Scope {
    /// Creates the registration and its sole receiver together. Neither type
    /// exposes a subscription/clone operation, so notify_one has one consumer.
    pub fn register(target: Registration) -> Result<(Self, Reports), &'static str> {
        if target.stream < crate::channel::FIRST_CHANNEL_STREAM {
            return Err("not a channel stream");
        }
        let mut active = ACTIVE.lock().map_err(|_| "observer registry poisoned")?;
        if active.upgrade().is_some() {
            return Err("observer occupied");
        }
        let report = Arc::new(ReportState {
            snapshot: Mutex::new(Snapshot::default()),
            sequence: AtomicU64::new(0),
            retired: AtomicBool::new(false),
            missed: AtomicU64::new(0),
            changed: Notify::new(),
        });
        let observation = Arc::new(Observation { target, report });
        *active = Arc::downgrade(&observation);
        let reports = Reports {
            state: observation.report.clone(),
            seen: 0,
        };
        Ok((Self { observation }, reports))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.observation.report.retire();
    }
}

/// Owned by the actual bridge future. Drop invalidates only its visited scope,
/// never a later registration for reused login/stream numbers.
pub(crate) struct Probe {
    login: LoginId,
    visited: Weak<Observation>,
}
impl Probe {
    pub(crate) fn new(login: LoginId) -> Self {
        Self {
            login,
            visited: Weak::new(),
        }
    }
    pub(crate) fn observe(
        &mut self,
        attachment: AttachmentContext,
        capture: impl FnOnce(Registration) -> Option<Snapshot>,
    ) {
        let Some(observation) = ACTIVE.try_lock().ok().and_then(|slot| slot.upgrade()) else {
            return;
        };
        if observation.target.login != self.login {
            return;
        }
        if attachment != observation.target.attachment {
            if Weak::ptr_eq(&self.visited, &Arc::downgrade(&observation)) {
                observation.report.retire();
            }
            return;
        }
        if observation.report.retired.load(Ordering::Acquire) {
            return;
        }
        self.visited = Arc::downgrade(&observation);
        if let Some(sample) = capture(observation.target) {
            observation.report.publish(sample);
        } else {
            observation.report.retire();
        }
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(observation) = self.visited.upgrade() {
            observation.report.retire();
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Scalar values were copied from an actual publication. A retirement
    /// report can lack values when the cell is contended; never infer zeros.
    pub values_available: bool,
    pub valid: bool,
    pub retired: bool,
    pub sequence: u64,
    pub credit_remaining: Option<u64>,
    pub pending_data: u64,
    pub source_pending: u64,
    pub reliable_tail: u64,
    pub offset_room: u64,
    pub gate_byte_open: bool,
    pub gate_metadata_blocked: bool,
    pub gate_closed: bool,
    pub credit_blocked: bool,
    pub pending_high_water: u64,
    pub tail_high_water: u64,
    pub combined_high_water: u64,
    /// Contention can skip publication; maxima cover published snapshots only.
    pub publications_skipped: u64,
}

impl Snapshot {
    pub(crate) fn classify(mut self) -> Self {
        self.credit_blocked = self.valid
            && !self.retired
            && !self.gate_closed
            && !self.gate_metadata_blocked
            && self.pending_data > 0
            && self.offset_room >= 6
            && self.credit_remaining == Some(0);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_gate::{GateKind, SendGate};

    #[test]
    fn qualification305_credit_zero_with_acked_tail_is_positive() {
        let gate = SendGate::new(GateKind::Screen);
        gate.admit(12);
        gate.update(0);
        let sample = Snapshot {
            valid: true,
            credit_remaining: Some(0),
            pending_data: 7,
            source_pending: gate.pending_for_test(),
            reliable_tail: 0,
            offset_room: 64,
            gate_byte_open: gate.is_open(),
            ..Snapshot::default()
        }
        .classify();
        assert!(sample.credit_blocked);
        assert_eq!(sample.reliable_tail, 0);
        assert!(
            sample.gate_byte_open,
            "byte hysteresis closure is not required"
        );
        assert_eq!(
            gate.pending_for_test(),
            12,
            "observation cannot refund debt"
        );
    }

    #[test]
    fn qualification305_absent_credit_and_other_blockers_are_negative() {
        let base = Snapshot {
            valid: true,
            credit_remaining: Some(0),
            pending_data: 7,
            offset_room: 64,
            ..Snapshot::default()
        };
        for change in [
            Snapshot {
                credit_remaining: None,
                ..base
            },
            Snapshot {
                credit_remaining: Some(1),
                reliable_tail: 512 * 1024,
                ..base
            },
            Snapshot {
                credit_remaining: Some(1),
                offset_room: 0,
                ..base
            },
            Snapshot {
                pending_data: 0,
                ..base
            },
            Snapshot {
                valid: false,
                ..base
            },
            Snapshot {
                retired: true,
                ..base
            },
            Snapshot {
                gate_closed: true,
                ..base
            },
            Snapshot {
                gate_metadata_blocked: true,
                ..base
            },
        ] {
            assert!(!change.classify().credit_blocked, "{change:?}");
        }
    }
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn qualification305_registration_is_scoped_and_teardown_is_sticky() {
        let _serial = TEST_SCOPE.lock().unwrap();
        let registration = Registration {
            login: [7; 16],
            attachment: AttachmentContext {
                session_id: 81,
                generation: 4,
                features: crate::Features::SUPPORTED,
            },
            stream: 18,
            instance: ChannelInstance::new(3).unwrap(),
        };
        let (scope, receiver) = Scope::register(registration).unwrap();
        assert!(Scope::register(registration).is_err());
        let sample = Snapshot {
            valid: true,
            credit_remaining: Some(0),
            pending_data: 7,
            offset_room: 64,
            ..Snapshot::default()
        };
        let mut wrong = Probe::new([8; 16]);
        wrong.observe(registration.attachment, |_| Some(sample));
        assert_eq!(
            receiver.latest().unwrap().sequence,
            0,
            "wrong login cannot publish"
        );
        let mut unrelated = Probe::new(registration.login);
        unrelated.observe(
            AttachmentContext {
                session_id: 82,
                ..registration.attachment
            },
            |_| panic!("unrelated session cannot capture"),
        );
        assert_eq!(receiver.latest().unwrap().sequence, 0);
        let mut bridge = Probe::new(registration.login);
        bridge.observe(registration.attachment, |_| Some(sample));
        assert!(receiver.latest().unwrap().credit_blocked);
        let first = receiver.latest().unwrap().sequence;
        let replacement = AttachmentContext {
            generation: 5,
            ..registration.attachment
        };
        bridge.observe(replacement, |_| {
            panic!("mismatched attachment cannot capture")
        });
        assert!(receiver.latest().unwrap().retired);
        assert!(!receiver.latest().unwrap().credit_blocked);
        bridge.observe(registration.attachment, |_| Some(sample));
        assert!(
            receiver.latest().unwrap().retired,
            "late original owner cannot revive"
        );
        assert!(receiver.latest().unwrap().sequence > first);
        drop(scope);
        let (next, next_receiver) = Scope::register(registration).unwrap();
        assert_eq!(
            next_receiver.latest().unwrap().sequence,
            0,
            "no preceding scope contamination"
        );
        drop(bridge);
        assert!(
            !next_receiver.latest().unwrap().retired,
            "old bridge drop cannot retire replacement scope"
        );
        drop(next);
        assert!(next_receiver.latest().unwrap().retired);
        assert!(receiver.latest().unwrap().retired);
    }
}

#[cfg(test)]
mod nonblocking_tests {
    use super::*;
    #[test]
    fn qualification305_retained_reader_cannot_block_owner_or_retirement() {
        let _serial = TEST_SCOPE.lock().unwrap();
        let target = Registration {
            login: [9; 16],
            attachment: AttachmentContext {
                session_id: 91,
                generation: 2,
                features: crate::Features::SUPPORTED,
            },
            stream: 19,
            instance: ChannelInstance::new(2).unwrap(),
        };
        let (scope, receiver) = Scope::register(target).unwrap();
        let held = receiver.state.snapshot.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            let mut bridge = Probe::new(target.login);
            started_tx.send(()).unwrap();
            bridge.observe(target.attachment, |_| {
                Some(Snapshot {
                    valid: true,
                    credit_remaining: Some(0),
                    pending_data: 1,
                    offset_room: 64,
                    ..Snapshot::default()
                })
            });
            drop(scope);
            drop(bridge);
            done_tx.send(()).unwrap();
        });
        let started = started_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .is_ok();
        let returned = started
            && done_rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .is_ok();
        drop(held); // Always rescue/reap the owned worker before any assertion.
        owner.join().unwrap();
        assert!(started);
        assert!(
            returned,
            "held report reader blocked transport owner/retirement"
        );
        assert_eq!(receiver.latest().unwrap().publications_skipped, 1);
        assert!(receiver.latest().unwrap().retired);
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;
    use std::future::Future;
    #[tokio::test]
    async fn qualification305_notification_recheck_and_retirement_are_bounded() {
        let report = Arc::new(ReportState {
            snapshot: Mutex::new(Snapshot::default()),
            sequence: AtomicU64::new(0),
            retired: AtomicBool::new(false),
            missed: AtomicU64::new(0),
            changed: Notify::new(),
        });
        let mut reports = Reports {
            state: report.clone(),
            seen: 0,
        };
        let sample = Snapshot {
            valid: true,
            credit_remaining: Some(0),
            pending_data: 7,
            offset_room: 64,
            source_pending: 12,
            ..Snapshot::default()
        };
        report.publish(sample);
        let observed = tokio::time::timeout(std::time::Duration::from_secs(1), reports.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(observed.credit_blocked);
        assert_eq!(observed.pending_high_water, 12);
        {
            let pending = reports.changed();
            tokio::pin!(pending);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(pending.as_mut().poll(cx)))
                    .await
                    .is_pending()
            );
            report.retire();
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(1), pending)
                    .await
                    .unwrap()
                    .unwrap()
                    .retired
            );
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), reports.changed())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use std::future::Future;
    #[test]
    fn qualification305_retirement_is_observable_while_report_cell_is_held() {
        let report = Arc::new(ReportState {
            snapshot: Mutex::new(Snapshot::default()),
            sequence: AtomicU64::new(0),
            retired: AtomicBool::new(false),
            missed: AtomicU64::new(0),
            changed: Notify::new(),
        });
        let mut reports = Reports {
            state: report.clone(),
            seen: 0,
        };
        let mut pending = Box::pin(reports.changed());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        let held = report.snapshot.lock().unwrap();
        report.retire();
        let ready = matches!(pending.as_mut().poll(&mut cx),std::task::Poll::Ready(Some(sample)) if sample.retired && !sample.values_available);
        drop(held);
        drop(pending);
        assert!(
            ready,
            "retirement cannot need another wake after a contended read"
        );
    }
}

#[cfg(test)]
mod single_receiver_tests {
    use super::*;

    #[test]
    fn qualification305_single_receiver_does_not_own_registration_lifetime() {
        let _serial = TEST_SCOPE.lock().unwrap();
        let target = Registration {
            login: [11; 16],
            attachment: AttachmentContext {
                session_id: 101,
                generation: 6,
                features: crate::Features::SUPPORTED,
            },
            stream: 21,
            instance: ChannelInstance::new(4).unwrap(),
        };
        let (scope, receiver): (Scope, Reports) = Scope::register(target).unwrap();
        drop(receiver);
        assert!(
            Scope::register(target).is_err(),
            "dropping the only receiver cannot release a live registration"
        );
        drop(scope);
        let (replacement, receiver): (Scope, Reports) = Scope::register(target).unwrap();
        assert_eq!(receiver.latest().unwrap().sequence, 0);
        drop(replacement);
        assert!(
            receiver.latest().unwrap().retired,
            "keeping the sole receiver cannot keep its owner alive"
        );
    }
}
