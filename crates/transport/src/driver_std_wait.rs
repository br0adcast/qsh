//! Driver-owned UDP readiness and producer notifications.
use std::io;
use std::net::UdpSocket;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SendError, Sender};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

trait PollIo: Send + Sync {
    fn add(&self, socket: &UdpSocket, key: usize) -> io::Result<()>;
    fn modify(&self, socket: &UdpSocket, key: usize) -> io::Result<()>;
    fn delete(&self, socket: &UdpSocket) -> io::Result<()>;
    fn wait(&self, key: usize, deadline: Instant) -> io::Result<bool>;
    fn notify(&self) -> io::Result<()>;
}

struct NativeIo {
    poller: polling::Poller,
    events: Mutex<polling::Events>,
}
impl NativeIo {
    fn new() -> io::Result<Self> {
        Ok(Self {
            poller: polling::Poller::new()?,
            events: Mutex::new(polling::Events::new()),
        })
    }
}
impl PollIo for NativeIo {
    fn add(&self, socket: &UdpSocket, key: usize) -> io::Result<()> {
        // SAFETY: RegisteredSource owns the socket before this call, including
        // partial-add/panic paths. Failed deletion transfers it into Backend's
        // quarantine, which outlives this exact poller, not just a driver Arc.
        unsafe { self.poller.add(socket, polling::Event::readable(key)) }
    }
    fn modify(&self, socket: &UdpSocket, key: usize) -> io::Result<()> {
        self.poller.modify(socket, polling::Event::readable(key))
    }
    fn delete(&self, socket: &UdpSocket) -> io::Result<()> {
        match self.poller.delete(socket) {
            // Pinned Unix backends report NotFound for an absent registration.
            // IOCP removes bookkeeping before fallible cancellation, so never
            // infer successful deletion from an arbitrary Windows error.
            #[cfg(unix)]
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
    fn wait(&self, key: usize, deadline: Instant) -> io::Result<bool> {
        let mut events = self
            .events
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        events.clear();
        self.poller.wait_deadline(&mut events, deadline)?;
        let readable = events
            .iter()
            .any(|event| event.key == key && event.readable);
        Ok(readable)
    }
    fn notify(&self) -> io::Result<()> {
        self.poller.notify()
    }
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

struct Source {
    socket: UdpSocket,
    #[cfg(test)]
    trace: Option<(Arc<Mutex<Vec<String>>>, &'static str)>,
}
impl Source {
    fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            #[cfg(test)]
            trace: None,
        }
    }
    #[cfg(test)]
    fn tracked(socket: UdpSocket, trace: Arc<Mutex<Vec<String>>>, name: &'static str) -> Self {
        Self {
            socket,
            trace: Some((trace, name)),
        }
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some((trace, name)) = &self.trace {
            trace
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(format!("source_drop:{name}"));
        }
    }
}

struct Backend {
    // FIELD DROP ORDER IS A SAFETY INVARIANT. The actual last Arc owner drops
    // the poller before closing any quarantined source. A producer paused
    // inside notify owns this entire Backend, never an independent Poller Arc.
    io: Box<dyn PollIo>,
    quarantine: Mutex<Vec<Source>>,
    failed: AtomicBool,
}
impl Backend {
    fn new(io: Box<dyn PollIo>) -> Arc<Self> {
        Arc::new(Self {
            io,
            quarantine: Mutex::new(Vec::with_capacity(2)),
            failed: AtomicBool::new(false),
        })
    }
    fn retain(&self, source: Source) {
        self.failed.store(true, Ordering::SeqCst);
        // At most current + candidate exist. Any cleanup failure is fatal and
        // forbids another registration. The preallocated vector therefore
        // never needs to allocate here, including while unwinding/poisoned.
        self.quarantine
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(source);
    }
}

struct RegisteredSource {
    source: Option<Source>,
    backend: Arc<Backend>,
    key: usize,
}
impl RegisteredSource {
    fn register(backend: Arc<Backend>, source: Source, key: usize) -> io::Result<Self> {
        if backend.failed.load(Ordering::SeqCst) {
            return Err(io::Error::other("socket registration has failed"));
        }
        let mut owned = Self {
            source: Some(source),
            backend,
            key,
        };
        // Construct custody BEFORE add: kqueue/IOCP can partially register
        // before returning an error, and a backend panic must unwind via Drop.
        if let Err(error) = owned
            .backend
            .io
            .add(&owned.source.as_ref().unwrap().socket, key)
        {
            owned.remove();
            return Err(error);
        }
        Ok(owned)
    }
    fn socket(&self) -> &UdpSocket {
        &self.source.as_ref().expect("active source").socket
    }
    fn remove(&mut self) -> bool {
        let Some(source) = self.source.take() else {
            return true;
        };
        // A delete error can follow partial bookkeeping mutation (IOCP).
        // Retrying could falsely succeed merely because that entry is gone.
        let removed = catch_unwind(AssertUnwindSafe(|| self.backend.io.delete(&source.socket)));
        match removed {
            Ok(Ok(())) => true,
            _ => {
                self.backend.retain(source);
                false
            }
        }
    }
}
impl Drop for RegisteredSource {
    fn drop(&mut self) {
        self.remove();
    }
}

#[derive(Default)]
pub(super) struct Notifier {
    backend: OnceLock<Weak<Backend>>,
    failed: AtomicBool,
}
impl Notifier {
    fn install(&self, backend: &Arc<Backend>) {
        assert!(
            self.backend.set(Arc::downgrade(backend)).is_ok(),
            "one driver backend"
        );
    }
    #[cfg(test)]
    pub(super) fn backend_alive(&self) -> bool {
        self.backend.get().and_then(Weak::upgrade).is_some()
    }
    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }
    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::SeqCst);
    }
    pub(super) fn notify(&self) {
        if self.failed() {
            return;
        }
        if let Some(backend) = self.backend.get().and_then(Weak::upgrade) {
            if backend.io.notify().is_err() {
                self.fail();
            }
        }
        // Before backend installation, enqueue already happened and the first
        // driver drain is still ahead. After backend destruction no wait exists.
    }
}

pub(super) struct WakeSender<T> {
    sender: Option<Sender<T>>,
    wake: Arc<Notifier>,
}
impl<T> WakeSender<T> {
    pub(super) fn new(sender: Sender<T>, wake: Arc<Notifier>) -> Self {
        Self {
            sender: Some(sender),
            wake,
        }
    }
    pub(super) fn send(&self, value: T) -> Result<(), SendError<T>> {
        if self.wake.failed() {
            return Err(SendError(value));
        }
        self.sender.as_ref().expect("live sender").send(value)?;
        // Ownership was accepted by mpsc. Notify failure is a terminal local
        // driver error, never a rejection that lets the caller replay it.
        self.wake.notify();
        Ok(())
    }
}
impl<T> Clone for WakeSender<T> {
    fn clone(&self) -> Self {
        Self::new(
            self.sender.as_ref().expect("live sender").clone(),
            self.wake.clone(),
        )
    }
}
impl<T> Drop for WakeSender<T> {
    fn drop(&mut self) {
        drop(self.sender.take());
        self.wake.notify();
    }
}

pub(super) struct DriverWait {
    backend: Arc<Backend>,
    current: RegisteredSource,
    next_key: Option<usize>,
}
impl DriverWait {
    pub(super) fn new(socket: UdpSocket, wake: &Arc<Notifier>) -> io::Result<Self> {
        Self::from_backend(
            Backend::new(Box::new(NativeIo::new()?)),
            Source::new(socket),
            wake,
        )
    }
    fn from_backend(
        backend: Arc<Backend>,
        source: Source,
        wake: &Arc<Notifier>,
    ) -> io::Result<Self> {
        let current = RegisteredSource::register(backend.clone(), source, 1)?;
        wake.install(&backend);
        Ok(Self {
            backend,
            current,
            next_key: Some(2),
        })
    }
    pub(super) fn socket(&self) -> &UdpSocket {
        self.current.socket()
    }
    pub(super) fn replace(&mut self, socket: UdpSocket) -> io::Result<bool> {
        self.replace_source(Source::new(socket))
    }
    fn replace_source(&mut self, source: Source) -> io::Result<bool> {
        if self.backend.failed.load(Ordering::SeqCst) {
            return Err(io::Error::other("socket registration failed"));
        }
        let key = self
            .next_key
            .take()
            .ok_or_else(|| io::Error::other("socket generation exhausted"))?;
        // Failed/partially registered attempts can leave a stale queued event.
        // Consume the key before add, even when the candidate never commits.
        self.next_key = key.checked_add(1).filter(|key| *key != usize::MAX);
        let candidate = match RegisteredSource::register(self.backend.clone(), source, key) {
            Ok(candidate) => candidate,
            Err(error) if self.backend.failed.load(Ordering::SeqCst) => return Err(error),
            Err(_) => return Ok(false),
        };
        if !self.current.remove() {
            drop(candidate);
            return Err(io::Error::other("old socket could not be unregistered"));
        }
        self.current = candidate;
        Ok(true)
    }
    pub(super) fn wait(&self, deadline: Instant) -> io::Result<bool> {
        retry_interrupted(|| self.backend.io.modify(self.socket(), self.current.key))?;
        retry_interrupted(|| self.backend.io.wait(self.current.key, deadline))
    }
}

#[cfg(test)]
#[path = "driver_std_wait_control.rs"]
mod control;
#[cfg(test)]
pub(super) use control::TestControl;

#[derive(Default)]
pub(super) struct Clock {
    #[cfg(test)]
    control: Option<Arc<TestControl>>,
}
impl Clock {
    #[cfg(test)]
    pub(super) fn controlled(control: Option<Arc<TestControl>>) -> Self {
        Self { control }
    }
    pub(super) fn now(&self) -> Instant {
        #[cfg(test)]
        if let Some(control) = &self.control {
            return control.now();
        }
        Instant::now()
    }
}
impl DriverWait {
    #[cfg(test)]
    pub(super) fn controlled(
        socket: UdpSocket,
        wake: &Arc<Notifier>,
        control: Arc<TestControl>,
    ) -> io::Result<Self> {
        Self::from_backend(
            Backend::new(Box::new(control::TestIo(control))),
            Source::new(socket),
            wake,
        )
    }
}

#[cfg(test)]
#[path = "driver_std_wait_tests.rs"]
mod tests;
