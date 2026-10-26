//! Deterministic wait/clock seam: no timer fallback unless the test advances it.
use super::*;
use std::sync::Condvar;
use std::time::Duration;

struct State {
    now: Instant,
    entered: usize,
    parked: bool,
    held: bool,
    pending: bool,
    readable: bool,
    fail_notify: bool,
    fail_add: bool,
    fail_wait: bool,
    deadline: Option<Instant>,
    commands: Vec<String>,
    registrations: usize,
}
pub(crate) struct TestControl {
    state: Mutex<State>,
    changed: Condvar,
}
impl std::fmt::Debug for TestControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("controlled driver wait")
    }
}
impl Default for TestControl {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                now: Instant::now(),
                entered: 0,
                parked: false,
                held: false,
                pending: false,
                readable: false,
                fail_notify: false,
                fail_add: false,
                fail_wait: false,
                deadline: None,
                commands: Vec::new(),
                registrations: 0,
            }),
            changed: Condvar::new(),
        }
    }
}
impl TestControl {
    pub(crate) fn readable(&self) {
        self.state.lock().unwrap().readable = true;
        self.changed.notify_all();
    }
    pub(crate) fn entries(&self) -> usize {
        self.state.lock().unwrap().entered
    }
    pub(crate) fn now(&self) -> Instant {
        self.state.lock().unwrap().now
    }
    pub(crate) fn hold(&self, held: bool) {
        self.state.lock().unwrap().held = held;
        self.changed.notify_all();
    }
    pub(crate) fn advance(&self, by: Duration) {
        self.state.lock().unwrap().now += by;
        self.changed.notify_all();
    }
    pub(crate) fn fail_registration(&self) {
        self.state.lock().unwrap().fail_add = true;
    }
    pub(crate) fn fail_wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.fail_wait = true;
        state.pending = true;
        self.changed.notify_all();
    }
    pub(crate) fn fail_notify(&self) {
        self.state.lock().unwrap().fail_notify = true;
    }
    pub(crate) fn command(&self, command: String) {
        self.state.lock().unwrap().commands.push(command);
        self.changed.notify_all();
    }
    pub(crate) fn commands(&self) -> Vec<String> {
        self.state.lock().unwrap().commands.clone()
    }
    pub(crate) fn wait_parked(&self, count: usize) {
        self.until(|state| state.parked && state.entered >= count);
    }
    pub(crate) fn wait_commands(&self, count: usize) {
        self.until(|state| state.commands.len() >= count);
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.state.lock().unwrap().deadline.unwrap()
    }
    pub(crate) fn registrations(&self) -> usize {
        self.state.lock().unwrap().registrations
    }
    fn until(&self, ready: impl Fn(&State) -> bool) {
        let timeout = Instant::now() + Duration::from_secs(5);
        let mut state = self.state.lock().unwrap();
        while !ready(&state) {
            let (next, result) = self
                .changed
                .wait_timeout(state, timeout.saturating_duration_since(Instant::now()))
                .unwrap();
            state = next;
            assert!(
                !result.timed_out(),
                "controlled driver did not make expected progress"
            );
        }
    }
}
pub(super) struct TestIo(pub(super) Arc<TestControl>);
impl PollIo for TestIo {
    fn add(&self, _: &UdpSocket, _: usize) -> io::Result<()> {
        let mut state = self.0.state.lock().unwrap();
        state.registrations += 1;
        self.0.changed.notify_all();
        if state.fail_add {
            Err(io::Error::other("injected registration failure"))
        } else {
            Ok(())
        }
    }
    fn modify(&self, _: &UdpSocket, _: usize) -> io::Result<()> {
        Ok(())
    }
    fn delete(&self, _: &UdpSocket) -> io::Result<()> {
        Ok(())
    }
    fn wait(&self, _: usize, deadline: Instant) -> io::Result<bool> {
        let mut state = self.0.state.lock().unwrap();
        state.entered += 1;
        state.deadline = Some(deadline);
        while state.held || (!state.pending && !state.readable && state.now < deadline) {
            state.parked = true;
            self.0.changed.notify_all();
            let (next, timeout) = self
                .0
                .changed
                .wait_timeout(state, Duration::from_secs(5))
                .unwrap();
            state = next;
            if timeout.timed_out() {
                return Err(io::Error::other("controlled wait deadlock watchdog"));
            }
        }
        state.parked = false;
        if state.fail_wait {
            return Err(io::Error::other("injected wait failure"));
        }
        state.pending = false;
        let readable = std::mem::take(&mut state.readable);
        Ok(readable)
    }
    fn notify(&self) -> io::Result<()> {
        let mut state = self.0.state.lock().unwrap();
        if state.fail_notify {
            return Err(io::Error::other("injected wake failure"));
        }
        state.pending = true;
        self.0.changed.notify_all();
        Ok(())
    }
}
