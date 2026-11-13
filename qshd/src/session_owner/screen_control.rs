//! Explicit caller-owned timer-task custody for retained Screen engines.
use super::{
    resource_contract::{Reservation, ReservationKind},
    resources::{OwnerResourceClient, StorageCharge},
};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use tokio::{runtime::Handle, sync::Notify, task::JoinHandle};
use transport::{
    channel::MAX_CHANNELS,
    channel_geometry::ChannelInstance,
    session_resume::{RequestId, SessionLocator},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    Unavailable,
    Resource,
    Failed,
}
#[derive(Default)]
pub(super) struct ControlPoll {
    pub deadline: Option<Instant>,
    pub busy: bool,
}
pub(super) trait ControlChannel: Send + Sync {
    fn service(&self, now: Instant) -> ControlPoll;
}
struct ControlState {
    slots: Mutex<[Option<Weak<dyn ControlChannel>>; MAX_CHANNELS]>,
    notify: Notify,
    stopping: AtomicBool,
    phase: AtomicU8,
    charge: Arc<StorageCharge>,
}
struct JoinState {
    handle: Option<JoinHandle<()>>,
    result: Option<Result<(), ControlError>>,
}
struct Registration {
    state: Arc<ControlState>,
    join: Mutex<JoinState>,
    observed: Notify,
}
struct Scope {
    runtime: Handle,
    entries: Mutex<Vec<Arc<Registration>>>,
}
impl Drop for Scope {
    fn drop(&mut self) {
        for entry in self
            .entries
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            entry.state.stopping.store(true, Ordering::Release);
            entry.state.notify.notify_waiters();
            if let Some(handle) = &entry.join.lock().unwrap_or_else(|e| e.into_inner()).handle {
                handle.abort();
            }
        }
        // Abort is not a join receipt. Charges remain unreleasable.
    }
}
#[derive(Clone)]
pub struct ControlTaskScope {
    inner: Arc<Scope>,
}
impl ControlTaskScope {
    pub fn new(runtime: Handle) -> Self {
        Self {
            inner: Arc::new(Scope {
                runtime,
                entries: Mutex::new(Vec::new()),
            }),
        }
    }
    pub fn registered(&self) -> usize {
        self.inner
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
    pub async fn drain(&self) -> Result<(), ControlError> {
        let mut failed = false;
        loop {
            let entry = self
                .inner
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .first()
                .cloned();
            let Some(entry) = entry else { break };
            let ticket = ControlTicket {
                scope: self.clone(),
                entry,
            };
            ticket.stop();
            if ticket.join().await.is_err() {
                failed = true;
            }
        }
        if failed {
            Err(ControlError::Failed)
        } else {
            Ok(())
        }
    }
}
/// Constructor data is explicit; it is not an ambient runtime/budget lookup.
pub struct ScreenControlContext {
    scope: ControlTaskScope,
    reservation: Reservation,
    cleanup: RequestId,
}
impl ScreenControlContext {
    pub fn new(scope: ControlTaskScope, reservation: Reservation, cleanup: RequestId) -> Self {
        Self {
            scope,
            reservation,
            cleanup,
        }
    }
    pub(super) async fn start(
        &self,
        client: OwnerResourceClient,
        locator: SessionLocator,
        anchor: ChannelInstance,
    ) -> Result<ControlTicket, ControlError> {
        let r = self.reservation;
        // Tokio's task cell/header, join bookkeeping and scheduler links are
        // bounded by16KiB for this small fixed future on the qualified target.
        // Both old/new maximum registry vectors plus the fixed channel slots,
        // Arc headers and wake state are included before any scheduler allocation.
        let inventory = std::mem::size_of::<ControlState>()
            + std::mem::size_of::<Registration>()
            + 2 * MAX_CHANNELS * std::mem::size_of::<Arc<Registration>>()
            + MAX_CHANNELS * (std::mem::size_of::<super::output::SharedOutput>() + 64)
            + 16_384
            + 4096;
        if inventory > 65_536
            || r.kind != ReservationKind::ControlQueue
            || r.bytes < 65_536
            || r.principal != client.principal()
            || r.locator != locator
            || r.channel != anchor
        {
            return Err(ControlError::Unavailable);
        }
        let admitted = client
            .reserve(r, self.cleanup)
            .map_err(|_| ControlError::Resource)?;
        let charge = StorageCharge::new(client, admitted, self.cleanup);
        let state = Arc::new(ControlState {
            slots: Mutex::new(std::array::from_fn(|_| None)),
            notify: Notify::new(),
            stopping: AtomicBool::new(false),
            phase: AtomicU8::new(0),
            charge,
        });
        let entry = Arc::new(Registration {
            state: state.clone(),
            join: Mutex::new(JoinState {
                handle: None,
                result: None,
            }),
            observed: Notify::new(),
        });
        let future = run(state.clone());
        if inventory
            .checked_add(std::mem::size_of_val(&future))
            .is_none_or(|n| n > 65_536)
        {
            state.charge.allow_release();
            return Err(ControlError::Unavailable);
        }
        {
            let mut entries = self
                .scope
                .inner
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if entries.len() == MAX_CHANNELS || entries.try_reserve_exact(1).is_err() {
                state.charge.allow_release();
                return Err(ControlError::Unavailable);
            }
            entries.push(entry.clone());
            // Registration exists before spawning. No unowned startup future.
            entry.join.lock().unwrap_or_else(|e| e.into_inner()).handle =
                Some(self.scope.inner.runtime.spawn(future));
        }
        let ticket = ControlTicket {
            scope: self.scope.clone(),
            entry,
        };
        let ready_state = ticket.entry.state.clone();
        loop {
            let notified = ready_state.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if ticket.entry.state.phase.load(Ordering::Acquire) == 1 {
                return Ok(ticket);
            }
            tokio::select! {
                _=notified=>{},
                _=ticket.join()=>{return Err(ControlError::Failed);}
            }
        }
    }
}
pub(super) struct ControlTicket {
    scope: ControlTaskScope,
    entry: Arc<Registration>,
}
impl ControlTicket {
    pub(super) fn healthy(&self) -> bool {
        self.entry.state.phase.load(Ordering::Acquire) == 1
            && !self.entry.state.stopping.load(Ordering::Acquire)
            && self
                .entry
                .join
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .handle
                .as_ref()
                .is_some_and(|h| !h.is_finished())
    }
    pub(super) fn register(&self, channel: Arc<dyn ControlChannel>) -> Result<(), ControlError> {
        if !self.healthy() {
            return Err(ControlError::Unavailable);
        }
        let mut slots = self
            .entry
            .state
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let slot = slots
            .iter_mut()
            .find(|s| s.as_ref().is_none_or(|w| w.strong_count() == 0))
            .ok_or(ControlError::Unavailable)?;
        *slot = Some(Arc::downgrade(&channel));
        drop(slots);
        self.wake();
        Ok(())
    }
    pub(super) fn wake(&self) {
        self.entry.state.notify.notify_one();
    }
    pub(super) fn wake_handle(&self) -> ControlWake {
        ControlWake {
            state: Arc::downgrade(&self.entry.state),
            _charge: Some(self.entry.state.charge.clone()),
        }
    }
    pub(super) fn stop(&self) {
        self.entry.state.stopping.store(true, Ordering::Release);
        self.wake();
    }
    pub(super) async fn join(&self) -> Result<(), ControlError> {
        let result = loop {
            let observed = self.entry.observed.notified();
            tokio::pin!(observed);
            observed.as_mut().enable();
            let joining = std::future::poll_fn(|cx| {
                let mut join = self.entry.join.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(result) = join.result {
                    return std::task::Poll::Ready(result);
                }
                let Some(handle) = join.handle.as_mut() else {
                    return std::task::Poll::Ready(Err(ControlError::Failed));
                };
                match Pin::new(handle).poll(cx) {
                    std::task::Poll::Pending => std::task::Poll::Pending,
                    std::task::Poll::Ready(result) => {
                        join.handle.take();
                        let result = result.map_err(|_| ControlError::Failed);
                        join.result = Some(result);
                        self.entry.observed.notify_waiters();
                        std::task::Poll::Ready(result)
                    }
                }
            });
            tokio::select! {result=joining=>break result,_=observed=>{}}
        };
        {
            let mut entries = self
                .scope
                .inner
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            entries.retain(|e| !Arc::ptr_eq(e, &self.entry));
            // Dispose registry spare backing before permitting its last charge.
            let live = std::mem::take(&mut *entries);
            *entries = live.to_vec();
            drop(live);
        }
        if result.is_ok() {
            self.entry.state.charge.allow_release();
        }
        result
    }
}
#[derive(Clone, Default)]
pub(super) struct ControlWake {
    state: Weak<ControlState>,
    _charge: Option<Arc<StorageCharge>>,
}
impl ControlWake {
    pub(super) fn healthy(&self) -> bool {
        self._charge.is_none()
            || self.state.upgrade().is_some_and(|s| {
                s.phase.load(Ordering::Acquire) == 1 && !s.stopping.load(Ordering::Acquire)
            })
    }
    pub(super) fn wake(&self) {
        if let Some(s) = self.state.upgrade() {
            s.notify.notify_one();
        }
    }
}
struct RunningTask(Arc<ControlState>);
impl Drop for RunningTask {
    fn drop(&mut self) {
        if self.0.phase.load(Ordering::Acquire) != 2 {
            self.0.phase.store(3, Ordering::Release);
            self.0.notify.notify_waiters();
        }
    }
}
async fn run(state: Arc<ControlState>) {
    let _actual_task = RunningTask(state.clone());
    // A timer-disabled supplied runtime panics here; its owned JoinHandle is
    // observed by startup, before any Screen child can be admitted.
    tokio::time::sleep(Duration::ZERO).await;
    state.phase.store(1, Ordering::Release);
    state.notify.notify_waiters();
    let mut rotate = 0;
    loop {
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if state.stopping.load(Ordering::Acquire) {
            break;
        }
        let slots = state
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let now = Instant::now();
        let mut next = None;
        let mut busy = false;
        for i in 0..MAX_CHANNELS {
            if state.stopping.load(Ordering::Acquire) {
                break;
            }
            if let Some(channel) = slots[(i + rotate) % MAX_CHANNELS]
                .as_ref()
                .and_then(Weak::upgrade)
            {
                let poll = channel.service(now);
                busy |= poll.busy;
                if let Some(deadline) = poll.deadline {
                    next = Some(next.map_or(deadline, |old: Instant| old.min(deadline)));
                }
            }
        }
        rotate = (rotate + 1) % MAX_CHANNELS;
        if busy {
            let retry = now + Duration::from_millis(10);
            next = Some(next.map_or(retry, |old| old.min(retry)));
        }
        if let Some(deadline) = next {
            if deadline <= Instant::now() {
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {_=notified=>{},_=tokio::time::sleep_until(deadline.into())=>{}}
        } else {
            notified.await;
        }
    }
    state
        .slots
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .fill(None);
    state.phase.store(2, Ordering::Release);
}
