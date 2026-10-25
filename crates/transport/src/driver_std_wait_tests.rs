use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Control {
    trace: Arc<Mutex<Vec<String>>>,
    registered: Mutex<HashSet<u16>>,
    keys: Mutex<Vec<usize>>,
    interrupt_wait: AtomicBool,
    interrupt_modify: AtomicBool,
    interrupt_delete: AtomicBool,
    waits: AtomicUsize,
    deadlines: Mutex<Vec<Instant>>,
    modifies: AtomicUsize,
    fail_add: AtomicBool,
    panic_add: AtomicBool,
    fail_delete: AtomicBool,
    uncertain_not_found: AtomicBool,
    panic_delete: AtomicBool,
    fail_notify: AtomicBool,
    notify_gate: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
    on_notify: Mutex<Option<Box<dyn Fn() + Send>>>,
}
struct FakeIo(Arc<Control>);
impl PollIo for FakeIo {
    fn add(&self, socket: &UdpSocket, key: usize) -> std::io::Result<()> {
        self.0.keys.lock().unwrap().push(key);
        self.0
            .registered
            .lock()
            .unwrap()
            .insert(socket.local_addr()?.port());
        assert!(
            !self.0.panic_add.swap(false, Ordering::SeqCst),
            "injected partial-add panic"
        );
        if self.0.fail_add.swap(false, Ordering::SeqCst) {
            Err(std::io::Error::other("injected partial add"))
        } else {
            Ok(())
        }
    }
    fn modify(&self, _: &UdpSocket, _: usize) -> std::io::Result<()> {
        self.0.modifies.fetch_add(1, Ordering::SeqCst);
        if self.0.interrupt_modify.swap(false, Ordering::SeqCst) {
            Err(std::io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        }
    }
    fn delete(&self, socket: &UdpSocket) -> std::io::Result<()> {
        if self.0.uncertain_not_found.load(Ordering::SeqCst) {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        if self.0.interrupt_delete.swap(false, Ordering::SeqCst) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        assert!(
            !self.0.panic_delete.load(Ordering::SeqCst),
            "injected delete panic"
        );
        if self.0.fail_delete.load(Ordering::SeqCst) {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        self.0
            .registered
            .lock()
            .unwrap()
            .remove(&socket.local_addr()?.port());
        Ok(())
    }
    fn wait(&self, _: usize, deadline: Instant) -> std::io::Result<bool> {
        self.0.deadlines.lock().unwrap().push(deadline);
        self.0.waits.fetch_add(1, Ordering::SeqCst);
        if self.0.interrupt_wait.swap(false, Ordering::SeqCst) {
            Err(std::io::ErrorKind::Interrupted.into())
        } else {
            Ok(false)
        }
    }
    fn notify(&self) -> std::io::Result<()> {
        if let Some((entered, release)) = self.0.notify_gate.lock().unwrap().take() {
            entered.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        if let Some(callback) = self.0.on_notify.lock().unwrap().as_ref() {
            callback();
        }
        if self.0.fail_notify.load(Ordering::SeqCst) {
            Err(std::io::Error::other("injected notify failure"))
        } else {
            Ok(())
        }
    }
}
impl Drop for FakeIo {
    fn drop(&mut self) {
        self.0.trace.lock().unwrap().push("poller_drop".into());
    }
}
fn socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").unwrap()
}
fn backend(control: &Arc<Control>) -> Arc<Backend> {
    Backend::new(Box::new(FakeIo(control.clone())))
}
fn tracked(control: &Arc<Control>, name: &'static str) -> Source {
    Source::tracked(socket(), control.trace.clone(), name)
}

#[test]
fn wake300_partial_add_is_cleaned_before_candidate_close_and_old_stays_usable() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait =
        DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    let old = wait.socket().local_addr().unwrap();
    control.fail_add.store(true, Ordering::SeqCst);
    assert!(!wait.replace_source(tracked(&control, "candidate")).unwrap());
    assert_eq!(wait.socket().local_addr().unwrap(), old);
    assert!(control.registered.lock().unwrap().contains(&old.port()));
    assert_eq!(control.registered.lock().unwrap().len(), 1);
    assert!(!backend.failed.load(Ordering::SeqCst));
}

#[test]
fn wake300_failed_add_cleanup_and_old_delete_keep_both_sources_until_actual_backend_drop() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait =
        DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    control.fail_add.store(true, Ordering::SeqCst);
    control.fail_delete.store(true, Ordering::SeqCst);
    assert!(wait.replace_source(tracked(&control, "candidate")).is_err());
    drop(wait);
    assert_eq!(backend.quarantine.lock().unwrap().len(), 2);
    assert!(control.trace.lock().unwrap().is_empty());
    drop(backend);
    let trace = control.trace.lock().unwrap();
    assert_eq!(trace[0], "poller_drop");
    assert_eq!(trace.len(), 3);
}

#[test]
fn wake300_notifier_strong_owner_retains_quarantined_source_after_driver_drop() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let wait = DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *control.notify_gate.lock().unwrap() = Some((entered_tx, release_rx));
    let producer = std::thread::spawn(move || wake.notify());
    let entered = entered_rx.recv_timeout(Duration::from_secs(5));
    control.fail_delete.store(true, Ordering::SeqCst);
    drop(wait);
    drop(backend);
    let retained = control.trace.lock().unwrap().is_empty();
    let _ = release_tx.send(());
    let joined = producer.join();
    assert!(entered.is_ok(), "producer did not enter notify");
    assert!(joined.is_ok());
    assert!(
        retained,
        "paused producer must retain the entire backend/source lease"
    );
    assert_eq!(
        *control.trace.lock().unwrap(),
        vec!["poller_drop", "source_drop:old"]
    );
}

#[test]
fn wake300_delete_panic_and_poisoned_quarantine_do_not_close_registered_source() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let wait = DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = backend.quarantine.lock().unwrap();
        panic!("injected poison");
    }));
    control.panic_delete.store(true, Ordering::SeqCst);
    drop(wait);
    assert!(control.trace.lock().unwrap().is_empty());
    drop(backend);
    assert_eq!(
        *control.trace.lock().unwrap(),
        vec!["poller_drop", "source_drop:old"]
    );
}

#[test]
fn wake300_notify_failure_after_enqueue_is_accepted_once_and_future_send_returns_data() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    wake.install(&backend);
    let (tx, rx) = mpsc::channel();
    let sender = WakeSender::new(tx, wake.clone());
    control.fail_notify.store(true, Ordering::SeqCst);
    assert!(sender.send(vec![1, 2, 3]).is_ok());
    assert_eq!(rx.try_recv().unwrap(), vec![1, 2, 3]);
    assert!(wake.failed());
    assert_eq!(sender.send(vec![4, 5]).unwrap_err().0, vec![4, 5]);
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn wake300_sender_drop_disconnects_before_notification() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    wake.install(&backend);
    let (tx, rx) = mpsc::channel::<u8>();
    *control.on_notify.lock().unwrap() = Some(Box::new(move || {
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
    }));
    drop(WakeSender::new(tx, wake));
}

#[test]
fn wake300_failed_candidate_generation_is_never_reused() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait = DriverWait::from_backend(backend, tracked(&control, "old"), &wake).unwrap();
    control.fail_add.store(true, Ordering::SeqCst);
    assert!(!wait.replace_source(tracked(&control, "failed")).unwrap());
    assert!(wait
        .replace_source(tracked(&control, "replacement"))
        .unwrap());
    assert_eq!(*control.keys.lock().unwrap(), vec![1, 2, 3]);
}

#[test]
fn wake300_interrupted_wait_rearm_keep_deadline_but_delete_error_retains_custody() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait =
        DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    control.interrupt_modify.store(true, Ordering::SeqCst);
    control.interrupt_wait.store(true, Ordering::SeqCst);
    let deadline = Instant::now();
    assert!(!wait.wait(deadline).unwrap());
    assert_eq!(*control.deadlines.lock().unwrap(), vec![deadline, deadline]);
    assert_eq!(control.modifies.load(Ordering::SeqCst), 2);
    assert_eq!(control.waits.load(Ordering::SeqCst), 2);
    control.interrupt_delete.store(true, Ordering::SeqCst);
    assert!(wait
        .replace_source(tracked(&control, "replacement"))
        .is_err());
    assert_eq!(backend.quarantine.lock().unwrap().len(), 1);
}

#[test]
fn wake300_native_notification_wakes_current_or_next_wait_without_udp() {
    let wake = Arc::new(Notifier::default());
    let wait = DriverWait::new(socket(), &wake).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let driver = std::thread::spawn(move || {
        let _ = entered_tx.send(());
        let result = wait.wait(Instant::now() + Duration::from_secs(10));
        done_tx.send(result).unwrap();
    });
    let entered = entered_rx.recv_timeout(Duration::from_secs(5));
    wake.notify();
    wake.notify(); // persistent and coalesced, not one token per command
    let result = done_rx.recv_timeout(Duration::from_secs(5));
    // Always reap the owned thread before asserting its watchdog result.
    driver.join().unwrap();
    assert!(entered.is_ok());
    assert!(!result.unwrap().unwrap());
}

#[test]
fn wake300_native_replacement_does_not_feed_old_socket_readiness_to_new_source() {
    let wake = Arc::new(Notifier::default());
    let mut wait = DriverWait::new(socket(), &wake).unwrap();
    let sender = socket();
    sender
        .send_to(b"old", wait.socket().local_addr().unwrap())
        .unwrap();
    let replacement = socket();
    let replacement_addr = replacement.local_addr().unwrap();
    assert!(wait.replace(replacement).unwrap());
    sender.send_to(b"new", replacement_addr).unwrap();
    assert!(wait.wait(Instant::now() + Duration::from_secs(5)).unwrap());
    wait.socket().set_nonblocking(true).unwrap();
    let mut bytes = [0u8; 16];
    let (length, _) = wait.socket().recv_from(&mut bytes).unwrap();
    wait.socket().set_nonblocking(false).unwrap();
    assert_eq!(&bytes[..length], b"new");
}

#[test]
fn wake300_partial_add_panic_quarantines_before_unwind_closes_any_source() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait =
        DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    control.panic_add.store(true, Ordering::SeqCst);
    control.fail_delete.store(true, Ordering::SeqCst);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = wait.replace_source(tracked(&control, "candidate"));
    }));
    assert!(result.is_err());
    drop(wait);
    assert_eq!(backend.quarantine.lock().unwrap().len(), 2);
    assert!(control.trace.lock().unwrap().is_empty());
    drop(backend);
    assert_eq!(control.trace.lock().unwrap()[0], "poller_drop");
}

#[test]
fn wake300_fatal_cleanup_forbids_another_registration_and_bounds_quarantine() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let mut wait =
        DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    control.fail_delete.store(true, Ordering::SeqCst);
    assert!(wait.replace_source(tracked(&control, "candidate")).is_err());
    assert!(wait
        .replace_source(tracked(&control, "unregistered"))
        .is_err());
    assert_eq!(*control.keys.lock().unwrap(), vec![1, 2]);
    assert_eq!(backend.quarantine.lock().unwrap().len(), 2);
}

#[test]
fn wake300_uncertain_not_found_delete_error_never_releases_source_early() {
    let control = Arc::new(Control::default());
    let backend = backend(&control);
    let wake = Arc::new(Notifier::default());
    let wait = DriverWait::from_backend(backend.clone(), tracked(&control, "old"), &wake).unwrap();
    control.uncertain_not_found.store(true, Ordering::SeqCst);
    drop(wait);
    assert_eq!(backend.quarantine.lock().unwrap().len(), 1);
    assert!(control.trace.lock().unwrap().is_empty());
    drop(backend);
    assert_eq!(
        *control.trace.lock().unwrap(),
        vec!["poller_drop", "source_drop:old"]
    );
}
