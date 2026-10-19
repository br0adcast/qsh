//! Bounded process-owned private-key work, independent of connection runtimes.
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, OnceLock},
    thread::JoinHandle,
};
use tokio::sync::oneshot;

const ACTIVE: usize = 2;
const QUEUED: usize = 4;
type Job = Box<dyn FnOnce() + Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Busy,
    Unavailable,
}

struct State {
    queue: VecDeque<Job>,
    active: usize,
    closed: bool,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}
pub(crate) struct Service {
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
}

impl Service {
    fn start() -> Result<Self, Error> {
        Self::start_with(|job| {
            std::thread::Builder::new()
                .name("qsh-key-crypto".into())
                .spawn(job)
        })
    }

    fn start_with(
        mut spawn: impl FnMut(Job) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<Self, Error> {
        let mut service = Self {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    queue: VecDeque::with_capacity(QUEUED),
                    active: 0,
                    closed: false,
                }),
                changed: Condvar::new(),
            }),
            workers: Vec::with_capacity(ACTIVE),
        };
        for _ in 0..ACTIVE {
            let shared = service.shared.clone();
            // On partial startup failure, Drop closes and joins only the idle
            // workers already created; no job was admitted yet.
            service
                .workers
                .push(spawn(Box::new(move || worker(shared))).map_err(|_| Error::Unavailable)?);
        }
        Ok(service)
    }

    pub(crate) fn submit<T: Send + 'static>(
        &self,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<oneshot::Receiver<T>, Error> {
        let (tx, rx) = oneshot::channel();
        let job: Job = Box::new(move || {
            // A cancelled queued operation never enters private cryptography.
            if !tx.is_closed() {
                let result = operation();
                let _ = tx.send(result);
            }
        });
        // This lock covers bounded counter/deque operations only. Brief
        // scheduler contention is not reported as capacity exhaustion.
        let mut state = self.shared.state.lock().map_err(|_| Error::Unavailable)?;
        let failure = if state.closed {
            Some(Error::Unavailable)
        } else if state.queue.len() == QUEUED || state.active + state.queue.len() == ACTIVE + QUEUED
        {
            Some(Error::Busy)
        } else {
            None
        };
        if let Some(error) = failure {
            drop(state);
            // Payloads can own keys and arbitrary destructors: never drop them
            // while holding the admission lock.
            drop(job);
            return Err(error);
        }
        state.queue.push_back(job);
        drop(state);
        self.shared.changed.notify_one();
        Ok(rx)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let pending = {
            let mut state = self.shared.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            std::mem::take(&mut state.queue)
        };
        self.shared.changed.notify_all();
        drop(pending);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

struct ActiveLease(Arc<Shared>);
impl Drop for ActiveLease {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        drop(state);
        self.0.changed.notify_all();
    }
}
fn worker(shared: Arc<Shared>) {
    loop {
        let job = {
            let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if state.closed {
                    return;
                }
                if let Some(job) = state.queue.pop_front() {
                    state.active += 1;
                    break job;
                }
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(|e| e.into_inner());
            }
        };
        let lease = ActiveLease(shared.clone());
        // A Rust panic drops owned payloads and the completion sender, yielding
        // Unavailable to the waiter; capacity is restored only after that drop.
        // Process abort/native faults are not recoverable by this boundary.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        drop(lease);
    }
}

pub(crate) async fn run<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Error> {
    static SERVICE: OnceLock<Result<Service, Error>> = OnceLock::new();
    // Static ownership deliberately outlives each Tokio runtime. Connection
    // cancellation drops its receiver, never joins an active native operation.
    let service = SERVICE
        .get_or_init(Service::start)
        .as_ref()
        .map_err(|e| *e)?;
    service
        .submit(operation)?
        .await
        .map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };

    struct Gate(Arc<(Mutex<bool>, Condvar)>);
    impl Gate {
        fn new() -> Self {
            Self(Arc::new((Mutex::new(false), Condvar::new())))
        }
        fn held(&self) -> impl FnOnce() + Send + 'static {
            let shared = self.0.clone();
            move || {
                let mut released = shared.0.lock().unwrap();
                while !*released {
                    released = shared.1.wait(released).unwrap();
                }
            }
        }
        fn release(&self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    impl Drop for Gate {
        fn drop(&mut self) {
            self.release();
        }
    }
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn idle(service: &Service) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut state = service.shared.state.lock().unwrap();
        while state.active != 0 || !state.queue.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "owned worker did not finish");
            state = service
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap()
                .0;
        }
    }

    #[test]
    fn two_active_four_queued_keep_all_six_owners_after_cancellation() {
        let service = Service::start().unwrap();
        let gate = Gate::new(); // releases before Service joins, including panic
        let drops = Arc::new(AtomicUsize::new(0));
        let executed = Arc::new(AtomicUsize::new(0));
        let (entered, received) = mpsc::channel();
        let mut receivers = Vec::new();
        for _ in 0..2 {
            let wait = gate.held();
            let entered = entered.clone();
            let owner = Owned(drops.clone());
            let calls = executed.clone();
            receivers.push(
                service
                    .submit(move || {
                        let _owner = owner;
                        calls.fetch_add(1, Ordering::SeqCst);
                        entered.send(()).unwrap();
                        wait();
                    })
                    .unwrap(),
            );
            received.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        for _ in 0..4 {
            let owner = Owned(drops.clone());
            let calls = executed.clone();
            receivers.push(
                service
                    .submit(move || {
                        let _owner = owner;
                        calls.fetch_add(1, Ordering::SeqCst);
                    })
                    .unwrap(),
            );
        }
        assert!(matches!(service.submit(|| ()), Err(Error::Busy)));
        drop(receivers);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(
            matches!(service.submit(|| ()), Err(Error::Busy)),
            "receiver cancellation must not refund owned jobs"
        );
        gate.release();
        idle(&service);
        assert_eq!(drops.load(Ordering::SeqCst), 6);
        assert_eq!(
            executed.load(Ordering::SeqCst),
            2,
            "cancelled queued work must not enter crypto"
        );
        assert_eq!(service.submit(|| 17).unwrap().blocking_recv().unwrap(), 17);
        idle(&service);
    }

    #[test]
    fn worker_panic_drops_its_owner_and_restores_capacity() {
        let service = Service::start().unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let owner = Owned(drops.clone());
        let rx = service
            .submit(move || {
                let _owner = owner;
                panic!("controlled worker panic");
            })
            .unwrap();
        assert!(rx.blocking_recv().is_err());
        idle(&service);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(service.submit(|| 21).unwrap().blocking_recv().unwrap(), 21);
        idle(&service);
    }

    #[test]
    fn partial_startup_failure_joins_the_created_worker_without_accepting_work() {
        let starts = Arc::new(AtomicUsize::new(0));
        let exits = Arc::new(AtomicUsize::new(0));
        let mut count = 0;
        let result = Service::start_with(|job| {
            count += 1;
            if count == 2 {
                return Err(std::io::Error::other("controlled spawn failure"));
            }
            let starts = starts.clone();
            let exits = exits.clone();
            std::thread::Builder::new().spawn(move || {
                starts.fetch_add(1, Ordering::SeqCst);
                job();
                exits.fetch_add(1, Ordering::SeqCst);
            })
        });
        assert!(matches!(result, Err(Error::Unavailable)));
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            exits.load(Ordering::SeqCst),
            1,
            "partial service must own and join its worker"
        );
    }

    #[test]
    fn a_completed_cancelled_job_drops_its_result_before_refunding_capacity() {
        let service = Service::start().unwrap();
        let gate = Gate::new();
        let (entered, received) = mpsc::sync_channel(1);
        let drops = Arc::new(AtomicUsize::new(0));
        let returned = Owned(drops.clone());
        let wait = gate.held();
        let rx = service
            .submit(move || {
                entered.send(()).unwrap();
                wait();
                returned
            })
            .unwrap();
        received.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(rx);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        gate.release();
        idle(&service);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod contention_test {
    use super::*;
    use std::{sync::mpsc, time::Duration};
    #[test]
    fn brief_counter_contention_is_not_capacity_exhaustion() {
        let service = Arc::new(Service::start().unwrap());
        let held = service.shared.state.lock().unwrap();
        let worker_service = service.clone();
        let (started, ready) = mpsc::sync_channel(1);
        let (result, received) = mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            started.send(()).unwrap();
            result.send(worker_service.submit(|| 41)).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = received.recv_timeout(Duration::from_millis(100));
        drop(held);
        let submitted = match early {
            Ok(result) => result,
            Err(_) => received.recv_timeout(Duration::from_secs(5)).unwrap(),
        };
        thread.join().unwrap();
        assert_eq!(
            submitted
                .expect("short lock contention is not a full service")
                .blocking_recv()
                .unwrap(),
            41
        );
    }
}
