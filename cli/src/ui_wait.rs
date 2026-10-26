//! The final UI event queue and its ordinary-thread notification.
use crate::input_wake::{self, WakeReader, WakeSender};
use crate::session::UiEvent;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
struct SendSide {
    tx: Option<mpsc::Sender<UiEvent>>,
    wake: Option<WakeSender>,
    failed: Arc<AtomicBool>,
    admission: Arc<Mutex<()>>,
}
impl Drop for SendSide {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(wake) = &self.wake {
            if wake.notify().is_err() {
                self.failed.store(true, Ordering::Release);
            }
        }
    }
}
#[derive(Clone)]
pub struct UiSender {
    inner: Arc<SendSide>,
}
pub struct UiInbox {
    rx: Option<mpsc::Receiver<UiEvent>>,
    wake: WakeReader,
    notify: WakeSender,
    failed: Arc<AtomicBool>,
    admission: Arc<Mutex<()>>,
}
#[cfg(test)]
fn channel() -> io::Result<(UiSender, UiInbox)> {
    let mut inbox = UiInbox::new()?;
    let sender = inbox.renew();
    Ok((sender, inbox))
}
impl From<mpsc::Sender<UiEvent>> for UiSender {
    fn from(tx: mpsc::Sender<UiEvent>) -> Self {
        Self {
            inner: Arc::new(SendSide {
                tx: Some(tx),
                wake: None,
                failed: Arc::new(AtomicBool::new(false)),
                admission: Arc::new(Mutex::new(())),
            }),
        }
    }
}
impl UiSender {
    pub fn with_notification(tx: mpsc::Sender<UiEvent>, wake: WakeSender) -> Self {
        Self {
            inner: Arc::new(SendSide {
                tx: Some(tx),
                wake: Some(wake),
                failed: Arc::new(AtomicBool::new(false)),
                admission: Arc::new(Mutex::new(())),
            }),
        }
    }
    pub fn notifier(&self) -> Option<WakeSender> {
        self.inner.wake.clone()
    }
    pub fn send(&self, event: UiEvent) -> Result<(), mpsc::SendError<UiEvent>> {
        self.send_after_precheck(event, || {})
    }
    fn send_after_precheck(
        &self,
        event: UiEvent,
        before_admission: impl FnOnce(),
    ) -> Result<(), mpsc::SendError<UiEvent>> {
        if self.inner.failed.load(Ordering::Acquire) {
            return Err(mpsc::SendError(event));
        }
        before_admission();
        // Seal and admission share this short custody section. Never notify,
        // process an event, or join a worker while holding it.
        let admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.inner.failed.load(Ordering::Acquire) {
            return Err(mpsc::SendError(event));
        }
        let accepted = self.inner.tx.as_ref().unwrap().send(event);
        drop(admission);
        accepted?;
        // Acceptance has happened. Notification failure must never invite a retry.
        if self
            .inner
            .wake
            .as_ref()
            .is_some_and(|wake| wake.notify().is_err())
        {
            self.inner.failed.store(true, Ordering::Release);
        }
        Ok(())
    }
}
impl UiInbox {
    pub fn new() -> io::Result<Self> {
        let (wake, notify) = input_wake::pair()?;
        Ok(Self {
            rx: None,
            wake,
            notify,
            failed: Arc::new(AtomicBool::new(false)),
            admission: Arc::new(Mutex::new(())),
        })
    }
    pub fn mark_failed(&self) {
        // On return every admitted event is already in the queue, and senders
        // paused before admission must return their original event as rejected.
        let _admission = self.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.failed.store(true, Ordering::Release);
    }
    /// Never drains before parking: after this returns, the caller commits one
    /// complete owner turn before any later park, observing non-event results too.
    pub fn wait_until(
        &self,
        deadline: Option<std::time::Instant>,
        signal: Option<RawFd>,
        probe: Option<RawFd>,
    ) -> io::Result<bool> {
        let mut fds = [
            libc::pollfd {
                fd: self.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: probe.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                timeout_ms(std::time::Instant::now(), deadline),
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(true);
            }
            return Err(error);
        }
        Ok(n > 0)
    }
    pub fn notifier(&self) -> WakeSender {
        self.notify.clone()
    }
    /// Called only after the previous InputReader has joined. Late old senders
    /// lose their receiver while the process's notification endpoints survive.
    pub fn retire(&mut self) {
        drop(self.rx.take());
    }
    pub fn renew(&mut self) -> UiSender {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        UiSender {
            inner: Arc::new(SendSide {
                tx: Some(tx),
                wake: Some(self.notify.clone()),
                failed: self.failed.clone(),
                admission: self.admission.clone(),
            }),
        }
    }
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub fn drain(&mut self) -> io::Result<()> {
        let result = drain_notifications(self.raw_fd(), || {});
        if result.is_err() {
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    pub fn collect_into(&self, events: &mut Vec<UiEvent>) -> QueueState {
        for _ in events.len()..16 {
            match self.try_recv() {
                Ok(event) => events.push(event),
                Err(mpsc::TryRecvError::Empty) => return QueueState::Empty,
                Err(mpsc::TryRecvError::Disconnected) => return QueueState::Disconnected,
            }
        }
        QueueState::BudgetReached
    }
    pub fn try_recv(&self) -> Result<UiEvent, mpsc::TryRecvError> {
        self.rx
            .as_ref()
            .ok_or(mpsc::TryRecvError::Disconnected)?
            .try_recv()
    }
    pub fn raw_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueState {
    BudgetReached,
    Empty,
    Disconnected,
}
fn drain_notifications(fd: RawFd, mut before_read: impl FnMut()) -> io::Result<()> {
    let mut bytes = [0u8; 256];
    for _ in 0..8 {
        before_read();
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UI notification EOF",
            ));
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => return Ok(()),
            io::ErrorKind::WouldBlock => return Ok(()),
            _ => return Err(error),
        }
    }
    Ok(())
}

pub fn timeout_ms(now: std::time::Instant, deadline: Option<std::time::Instant>) -> i32 {
    let Some(deadline) = deadline else { return -1 };
    let left = deadline.saturating_duration_since(now);
    let rounded = left
        .as_millis()
        .saturating_add(u128::from(left.subsec_nanos() % 1_000_000 != 0));
    rounded.min(i32::MAX as u128) as i32
}

#[derive(Default)]
pub struct ModelFollowup {
    due: Option<std::time::Instant>,
}
impl ModelFollowup {
    pub fn observe(&mut self, pending: bool, serviced: bool, now: std::time::Instant) {
        if serviced || !pending {
            self.due = None;
        }
        if pending && self.due.is_none() {
            self.due = now.checked_add(std::time::Duration::from_millis(20));
        }
    }
    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.due
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ui_wait_inbox_accepted_event_is_readable_before_another_event() {
        let (tx, rx) = channel().unwrap();
        tx.send(UiEvent::Tick).unwrap();
        let mut p = libc::pollfd {
            fd: rx.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut p, 1, 0) },
            1,
            "accepted event must wake the sole UI owner"
        );
        assert_eq!(rx.try_recv(), Ok(UiEvent::Tick));
    }
    #[test]
    fn ui_wait_inbox_failure_after_acceptance_never_invites_retry() {
        let (tx, mut rx) = channel().unwrap();
        tx.inner.wake.as_ref().unwrap().fail_next_notify();
        assert!(
            tx.send(UiEvent::Tick).is_ok(),
            "accepted event is not rejected by later notify failure"
        );
        assert_eq!(rx.try_recv(), Ok(UiEvent::Tick));
        assert!(
            rx.failed(),
            "the owner must know the permanent notification fault"
        );
        assert!(rx.drain().is_err());
        assert!(
            tx.send(UiEvent::Tick).is_err(),
            "a failed inbox stops future admissions"
        );
    }
    #[test]
    fn ui_wait_inbox_last_sender_drop_publishes_disconnect_before_wake() {
        let (tx, rx) = channel().unwrap();
        drop(tx);
        let mut p = libc::pollfd {
            fd: rx.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut p, 1, 0) }, 1);
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
    #[test]
    fn ui_wait_inbox_last_drop_notification_fault_is_sticky() {
        let (tx, mut rx) = channel().unwrap();
        tx.inner.wake.as_ref().unwrap().fail_next_notify();
        drop(tx);
        assert!(rx.failed());
        assert!(rx.drain().is_err());
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
    #[test]
    fn ui_wait_inbox_retirement_rejects_old_producers_without_replacing_wake() {
        let (old, mut rx) = channel().unwrap();
        let fd = rx.raw_fd();
        old.send(UiEvent::Tick).unwrap();
        rx.retire();
        assert!(
            old.send(UiEvent::Tick).is_err(),
            "a cooked phase cannot accumulate stale raw events"
        );
        let fresh = rx.renew();
        assert_eq!(rx.raw_fd(), fd);
        fresh.send(UiEvent::Resumed).unwrap();
        assert_eq!(rx.try_recv(), Ok(UiEvent::Resumed));
    }
    #[test]
    fn ui_wait_inbox_continuously_replenished_notifications_have_bounded_drain() {
        let (_tx, rx) = channel().unwrap();
        let notify = rx.notifier();
        let mut reads = 0;
        drain_notifications(rx.raw_fd(), || {
            reads += 1;
            assert!(
                reads <= 8,
                "continuously readable notifications starved the owner turn"
            );
            for _ in 0..512 {
                notify.notify().unwrap();
            }
        })
        .unwrap();
        assert_eq!(reads, 8);
        let mut p = libc::pollfd {
            fd: rx.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut p, 1, 0) },
            1,
            "remaining bytes retain readiness"
        );
    }
    #[test]
    fn ui_wait_inbox_fault_preserves_ingress_fence_beyond_sixteen_events() {
        use crate::input_ingress::{IngressBlocked, IngressBudget, INGRESS_BYTES};
        let (tx, rx) = channel().unwrap();
        let budget = IngressBudget::default();
        for _ in 0..15 {
            tx.send(UiEvent::Tick).unwrap();
        }
        tx.send(UiEvent::Stdin(
            budget.admit_slice(&vec![b'a'; INGRESS_BYTES]).unwrap(),
        ))
        .unwrap();
        let (marker, reply) = IngressBlocked::channel(budget.clone(), 1);
        tx.inner.wake.as_ref().unwrap().fail_next_notify();
        tx.send(UiEvent::IngressBlocked(marker)).unwrap();
        let mut events = Vec::new();
        assert_eq!(rx.collect_into(&mut events), QueueState::BudgetReached);
        assert_eq!(events.len(), 16);
        assert!(rx.failed());
        assert!(matches!(reply.try_recv(), Err(mpsc::TryRecvError::Empty)));
        let input = events.pop().unwrap();
        assert!(matches!(&input, UiEvent::Stdin(bytes) if bytes.as_slice().len() == INGRESS_BYTES));
        drop(input);
        events.clear();
        assert_eq!(budget.usage(), (0, 0, 0));
        assert_eq!(rx.collect_into(&mut events), QueueState::Empty);
        assert_eq!(events.len(), 1);
        let UiEvent::IngressBlocked(marker) = events.pop().unwrap() else {
            panic!("lost prefix fence")
        };
        assert!(marker.resolve());
        assert_eq!(reply.try_recv(), Ok(true));
    }
    #[test]
    fn ui_wait_inbox_seal_rejects_sender_paused_before_admission() {
        let (tx, rx) = channel().unwrap();
        let (arrived, at_admission) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send_after_precheck(UiEvent::Resumed, || {
                arrived.send(()).unwrap();
                proceed
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            })
        });
        at_admission
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        rx.mark_failed();
        release.send(()).unwrap();
        let result = worker.join().unwrap();
        assert!(matches!(result, Err(mpsc::SendError(UiEvent::Resumed))));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }
    #[test]
    fn ui_wait_inbox_actual_notify_fault_after_empty_requires_fresh_collection() {
        let (tx, mut rx) = channel().unwrap();
        let mut events = Vec::new();
        assert_eq!(rx.collect_into(&mut events), QueueState::Empty);
        let worker = std::thread::spawn(move || {
            tx.inner.wake.as_ref().unwrap().fail_next_notify();
            tx.send(UiEvent::Resumed).unwrap();
        });
        worker.join().unwrap();
        assert!(rx.drain().is_err());
        assert!(rx.failed());
        rx.mark_failed();
        assert_eq!(rx.collect_into(&mut events), QueueState::Disconnected);
        assert_eq!(events, vec![UiEvent::Resumed]);
    }
    #[test]
    fn ui_wait_timeout_uses_real_deadline_and_rounds_up() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        assert_eq!(timeout_ms(now, None), -1);
        assert_eq!(timeout_ms(now, Some(now)), 0);
        assert_eq!(timeout_ms(now, Some(now + Duration::from_micros(1))), 1);
        assert_eq!(timeout_ms(now, Some(now + Duration::from_millis(130))), 130);
    }
    #[test]
    fn ui_wait_followup_is_one_legacy_opportunity_without_sliding() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mut followup = ModelFollowup::default();
        followup.observe(true, true, now);
        assert_eq!(followup.deadline(), Some(now + Duration::from_millis(20)));
        followup.observe(true, false, now + Duration::from_millis(5));
        assert_eq!(followup.deadline(), Some(now + Duration::from_millis(20)));
        // An independently due model/resize/status/sync evaluation may settle
        // the obligation before the fallback. It is not a minimum display hold.
        followup.observe(false, true, now + Duration::from_millis(10));
        assert_eq!(followup.deadline(), None);
        followup.observe(true, false, now + Duration::from_millis(30));
        followup.observe(false, false, now + Duration::from_millis(31));
        assert_eq!(followup.deadline(), None);
    }
}
