//! The system mode's source of handshake nonces: a pool the helper filled in
//! advance.
//!
//! The session router asks its [`NonceSource`] for a nonce on the one task
//! that reads the UDP socket and routes every live session's datagrams (see
//! `transport::session_manager`). A source that asked the helper right there
//! would hold every session on the machine for as long as the helper took to
//! answer -- up to a whole [`HELPER_ANSWER_TIMEOUT`] per msg1 once the helper
//! stops answering. [`PooledNonces`] instead hands out a nonce the helper
//! issued earlier, or refuses at once when none is ready -- the client sends
//! its msg1 again -- and leaves every round trip to the helper to a thread of
//! its own ([`AUTH_POOL_THREAD`]).
//!
//! What does not change: the helper mints every nonce and spends each one at
//! most once. The pool changes WHEN a nonce is fetched, never who issues it,
//! and it never hands the same nonce out twice.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use transport::session_manager::NonceSource;

use crate::helper::protocol::Nonce;
use crate::helper::spawner::{EndWorker, HelperAuth, AUTH_POOL_THREAD, HELPER_ANSWER_TIMEOUT};
use crate::helper::worker_threads::{Role as ThreadRole, WorkerThreads};

/// How many nonces the pool keeps ready.
///
/// Every handshake takes one, and the pool's thread fetches the next in one
/// round trip to the helper -- well under a millisecond for a helper that is
/// keeping up. Eight covers a burst of handshakes arriving faster than that,
/// and is a small share of the helper's own cap on unspent nonces
/// (`helper::server::MAX_OUTSTANDING_NONCES`, 256), which the pool's nonces
/// count against like any other.
pub const POOL_TARGET: usize = 8;

/// How old a pooled nonce may get before the pool gives it back to the
/// helper instead of handing it out.
///
/// The helper forgets a nonce `helper::server::NONCE_LIFETIME` (30 s) after
/// issuing it, and a nonce handed out must still be on file when the
/// client's proof reaches the helper. The client has `transport`'s
/// `AUTH_DEADLINE` (5 s) to send that proof, so a nonce handed out at this
/// age is spent, at the latest, about 25 s after it was issued; the
/// remaining 5 s cover the rest of the way -- a verification waiting for its
/// turn, a loaded machine. That margin is not a hard bound, and nothing here
/// claims it is: a proof that arrives after the helper forgot its nonce is
/// refused, and the client logs in again.
///
/// A nonce's age is counted from the moment the pool ASKED for it, before
/// the request was sent: never less than the age the helper counts.
pub const POOL_MAX_AGE: Duration = Duration::from_secs(20);

/// What the worker logs when the pool's thread stops any other way than the
/// pool being dropped -- by a panic.
pub(crate) const POOL_THREAD_GONE_LOG: &str = "the nonce pool's thread has stopped";

/// Why the worker then ends: the thread is the only way to nonces, and a
/// worker that can admit nobody is worse than a clean exit (see
/// `split_and_run`'s docs) -- and would blame the helper for every login it
/// refused.
pub(crate) const POOL_THREAD_GONE_REASON: &str =
    "the nonce pool's thread has stopped; no handshake can be handed a nonce any more";

/// How the pool starts its thread -- [`spawn_pool_thread`] outside tests. A
/// parameter only so a test can make that fail.
type SpawnThread =
    fn(Box<dyn FnOnce() + Send>) -> io::Result<std::thread::JoinHandle<io::Result<()>>>;

/// Starts the pool's thread, under its name.
fn spawn_pool_thread(
    body: Box<dyn FnOnce() + Send>,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
    std::thread::Builder::new()
        .name(AUTH_POOL_THREAD.to_string())
        .spawn(move || {
            body();
            Ok(())
        })
}

/// How long the whole warm-up in [`PooledNonces::start`] may take: one
/// answer's budget, however many nonces it has fetched by then.
const WARM_UP_BUDGET: Duration = HELPER_ANSWER_TIMEOUT;

/// How long the pool's thread waits before it asks again after the helper
/// did not issue a nonce. A helper that is gone or not answering has
/// already cost the failed call its whole budget; this delay is for a
/// helper that refuses at once -- its table of unspent nonces is full --
/// and must not be asked again in a tight loop.
const REFILL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// A pool of nonces the helper issued in advance -- the system mode's
/// [`NonceSource`]. See the module docs.
///
/// [`NonceSource::issue`] takes the oldest ready nonce, or refuses at once;
/// it never asks the helper and never waits for anything but a short lock.
/// [`NonceSource::release`] forwards to the helper and never puts a nonce
/// back into the pool: a nonce that was handed out is single-use, and a
/// second handshake given the same one could present it twice. The only
/// nonces the pool gives back itself are ones it let age past
/// [`POOL_MAX_AGE`] without handing them to anyone, and, when it is
/// dropped, the ones it still holds.
pub struct PooledNonces {
    shared: Arc<Shared>,
    /// The client every nonce comes from and goes back to -- the same one
    /// the pool's thread holds.
    helper: Arc<HelperAuth>,
    auxiliary: Mutex<Option<WorkerThreads>>,
}

/// What the pool and its thread share.
struct Shared {
    state: Mutex<State>,
    /// Wakes the pool's thread: a nonce was taken, `issue` found stale ones
    /// to give back, or the pool is being dropped.
    wake: Condvar,
    /// [`POOL_MAX_AGE`] outside tests.
    max_age: Duration,
    /// Makes the pool's thread panic the next time it looks at the state.
    #[cfg(test)]
    panic_now: std::sync::atomic::AtomicBool,
}

struct State {
    /// Nonces ready to hand out, oldest first, each with the moment the pool
    /// asked for it. Only ever appended to in order of that moment -- by the
    /// warm-up, then by the one thread -- so the front is always the oldest.
    ready: VecDeque<(Nonce, Instant)>,
    /// Aged nonces `issue` took out of `ready`, for the pool's thread to give
    /// back: `issue` itself never sends anything.
    stale: Vec<Nonce>,
    /// Set when the pool is dropped. The thread gives back everything the
    /// pool still holds, and ends.
    closing: bool,
    /// How many times the pool's thread has gone to sleep on a full pool --
    /// for a test that must act only once the thread is asleep.
    #[cfg(test)]
    sleeps: usize,
    /// Pauses this test pool after the predicate check, before atomic wait.
    #[cfg(test)]
    before_wait: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}

impl Shared {
    /// The state. A lock poisoned by a panic is taken anyway: every change
    /// under it is a single push, pop or flag, so nothing is left
    /// half-changed.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl State {
    /// Moves every ready nonce that has reached `max_age` by `now` over to
    /// `stale`. `ready` is oldest first, so they are all at its front.
    fn expire(&mut self, max_age: Duration, now: Instant) {
        while let Some(&(nonce, asked)) = self.ready.front() {
            if now.saturating_duration_since(asked) < max_age {
                break;
            }
            self.ready.pop_front();
            self.stale.push(nonce);
        }
    }
}

impl PooledNonces {
    /// Add the fourth fixed handle before publishing the pool to the manager.
    #[cfg(test)]
    pub(crate) fn start_owned(
        helper: Arc<HelperAuth>,
        owner: &mut WorkerThreads,
    ) -> io::Result<Arc<Self>> {
        Self::start_owned_with_hook(helper, owner, Arc::new(crate::helper::end_the_worker))
    }

    pub(crate) fn start_owned_with_hook(
        helper: Arc<HelperAuth>,
        owner: &mut WorkerThreads,
        end_worker: EndWorker,
    ) -> io::Result<Arc<Self>> {
        let pool = Self::start_with(helper, POOL_MAX_AGE, end_worker, spawn_pool_thread)?;
        let custody = pool
            .auxiliary
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("nonce pool custody is transferred once");
        owner.absorb(custody);
        Ok(pool)
    }

    /// Fill the pool, then start the thread that keeps it filled.
    ///
    /// The filling happens here, before this returns, so that the first
    /// handshakes after the daemon starts find nonces ready rather than
    /// being refused -- which a person would read as "my key was not
    /// accepted". It takes at most [`WARM_UP_BUDGET`] in all, and stops at the
    /// first nonce the helper does not issue; the thread goes on from
    /// there. Called once, in the worker, before its runtime exists, so the
    /// wait holds up nothing else.
    ///
    /// Starts a thread, so it must never run before `split_and_run`'s fork,
    /// which refuses to fork a process with more than one thread. Fails only
    /// if that thread cannot start; whatever the warm-up fetched is given
    /// back first. If the thread ever stops by a panic, it ends the worker
    /// ([`POOL_THREAD_GONE_REASON`]).
    pub fn start(helper: Arc<HelperAuth>) -> io::Result<Arc<PooledNonces>> {
        PooledNonces::start_with(
            helper,
            POOL_MAX_AGE,
            Arc::new(crate::helper::end_the_worker),
            spawn_pool_thread,
        )
    }

    /// As [`PooledNonces::start`], with nonces ageing out after `max_age`
    /// instead of [`POOL_MAX_AGE`] -- so a test can watch the ageing rather
    /// than wait it out -- and a thread whose death ends nothing.
    #[cfg(test)]
    pub(crate) fn with_max_age(
        helper: Arc<HelperAuth>,
        max_age: Duration,
    ) -> io::Result<Arc<PooledNonces>> {
        PooledNonces::start_with(helper, max_age, Arc::new(|_: &str| {}), spawn_pool_thread)
    }

    /// As [`PooledNonces::start`], with `end_worker` called in place of
    /// ending the process.
    #[cfg(test)]
    pub(crate) fn with_end_worker(
        helper: Arc<HelperAuth>,
        end_worker: EndWorker,
    ) -> io::Result<Arc<PooledNonces>> {
        PooledNonces::start_with(helper, POOL_MAX_AGE, end_worker, spawn_pool_thread)
    }

    /// As [`PooledNonces::start`], with the thread started by `spawn`.
    #[cfg(test)]
    fn with_spawn(helper: Arc<HelperAuth>, spawn: SpawnThread) -> io::Result<Arc<PooledNonces>> {
        PooledNonces::start_with(helper, POOL_MAX_AGE, Arc::new(|_: &str| {}), spawn)
    }

    fn start_with(
        helper: Arc<HelperAuth>,
        max_age: Duration,
        end_worker: EndWorker,
        spawn: SpawnThread,
    ) -> io::Result<Arc<PooledNonces>> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                ready: VecDeque::with_capacity(POOL_TARGET),
                stale: Vec::new(),
                closing: false,
                #[cfg(test)]
                sleeps: 0,
                #[cfg(test)]
                before_wait: None,
            }),
            wake: Condvar::new(),
            max_age,
            #[cfg(test)]
            panic_now: std::sync::atomic::AtomicBool::new(false),
        });
        warm_up(&shared, &helper, Instant::now() + WARM_UP_BUDGET);
        let thread_shared = Arc::clone(&shared);
        let thread_helper = Arc::clone(&helper);
        let thread = match spawn(Box::new(move || {
            keep_filled(thread_shared, thread_helper, end_worker)
        })) {
            Ok(thread) => thread,
            Err(e) => {
                let fetched: Vec<Nonce> = shared.lock().ready.drain(..).map(|(n, _)| n).collect();
                for nonce in fetched {
                    helper.release(nonce);
                }
                return Err(e);
            }
        };
        let mut auxiliary = WorkerThreads::default();
        let stopping = shared.clone();
        auxiliary.register(ThreadRole::NoncePool, thread, move || {
            stopping.lock().closing = true;
            stopping.wake.notify_one();
            Ok(())
        });
        Ok(Arc::new(PooledNonces {
            shared,
            helper,
            auxiliary: Mutex::new(Some(auxiliary)),
        }))
    }

    /// The nonces ready right now, oldest first.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<Nonce> {
        self.shared
            .lock()
            .ready
            .iter()
            .map(|(nonce, _)| *nonce)
            .collect()
    }

    /// Makes the pool's thread panic, and wakes it to do so.
    #[cfg(test)]
    pub(crate) fn panic_thread_for_test(&self) {
        // Serialize with the predicate check and atomic condition wait.
        let _state = self.shared.lock();
        self.shared
            .panic_now
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.shared.wake.notify_one();
    }

    /// How many times the pool's thread has gone to sleep on a full pool.
    #[cfg(test)]
    pub(crate) fn sleeps(&self) -> usize {
        self.shared.lock().sleeps
    }

    /// Which helper client this pool draws from -- for a test that has to
    /// see it is the very one the rest of the system mode's setup uses.
    #[cfg(test)]
    pub(crate) fn helper_ptr(&self) -> *const () {
        Arc::as_ptr(&self.helper).cast::<()>()
    }
}

impl NonceSource for PooledNonces {
    /// The oldest ready nonce that has not aged out, or a refusal at once.
    /// Aged ones met on the way are left for the pool's thread to give back.
    fn issue(&self) -> Result<Nonce, String> {
        let mut state = self.shared.lock();
        if state.closing {
            return Err("nonce issuance stopped".to_string());
        }
        state.expire(self.shared.max_age, Instant::now());
        let nonce = state.ready.pop_front().map(|(nonce, _)| nonce);
        drop(state);
        // Below the target now, or holding stale nonces to give back:
        // either way there is work for the pool's thread.
        self.shared.wake.notify_one();
        nonce.ok_or_else(|| {
            "no nonce ready: the pool is waiting for the helper to issue more".to_string()
        })
    }

    /// Forwards to the helper; the nonce never comes back into the pool.
    fn release(&self, nonce: Nonce) {
        self.helper.release(nonce);
    }
}

impl Drop for PooledNonces {
    /// Tells the pool's thread to give back what the pool holds and end. The
    /// thread holds its own reference to the helper client, and lets go of it
    /// once it ends -- after any call it is in the middle of.
    fn drop(&mut self) {
        self.shared.lock().closing = true;
        self.shared.wake.notify_one();
        if let Some(mut owner) = self
            .auxiliary
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            owner.stop_and_join();
        }
    }
}

/// Fetch up to [`POOL_TARGET`] nonces into the pool, one after another, all
/// by `deadline`, stopping at the first the helper does not issue.
fn warm_up(shared: &Shared, helper: &HelperAuth, deadline: Instant) {
    for fetched in 0..POOL_TARGET {
        let asked = Instant::now();
        match helper.issue_by(deadline) {
            Ok(nonce) => shared.lock().ready.push_back((nonce, asked)),
            Err(why) => {
                crate::log::info(
                    "worker",
                    &format!(
                        "the nonce pool starts with {fetched} of {POOL_TARGET} nonces \
                     ready ({why}); its thread fetches the rest"
                    ),
                );
                return;
            }
        }
    }
}

/// The pool's thread: gives back what has aged, keeps [`POOL_TARGET`] nonces
/// ready, and sleeps while there is nothing to do -- until a nonce is taken,
/// or the oldest one ages out. Every call to the helper happens here, with
/// the lock let go. Ends only once the pool is dropped; if it stops any other
/// way, its [`PoolThreadExit`] ends the worker.
fn keep_filled(shared: Arc<Shared>, helper: Arc<HelperAuth>, end_worker: EndWorker) {
    let _exit = PoolThreadExit { end_worker };
    let mut failing = false;
    loop {
        let give_back = {
            let mut state = shared.lock();
            loop {
                if state.closing {
                    let mut held: Vec<Nonce> = std::mem::take(&mut state.stale);
                    held.extend(state.ready.drain(..).map(|(nonce, _)| nonce));
                    drop(state);
                    for nonce in held {
                        helper.release(nonce);
                    }
                    return;
                }
                #[cfg(test)]
                if shared.panic_now.load(std::sync::atomic::Ordering::SeqCst) {
                    panic!("the pool's thread panics here, on purpose");
                }
                let now = Instant::now();
                state.expire(shared.max_age, now);
                if !state.stale.is_empty() {
                    break std::mem::take(&mut state.stale);
                }
                if state.ready.len() < POOL_TARGET {
                    break Vec::new();
                }
                // Full: nothing to do until a nonce is taken or the oldest
                // one ages out.
                let oldest_ages_in = state
                    .ready
                    .front()
                    .map(|&(_, asked)| (asked + shared.max_age).saturating_duration_since(now))
                    .unwrap_or(shared.max_age);
                #[cfg(test)]
                {
                    state.sleeps += 1;
                }
                #[cfg(test)]
                if let Some((entered, resume)) = state.before_wait.take() {
                    entered.send(()).expect("check-before-wait observer");
                    resume
                        .recv_timeout(Duration::from_secs(10))
                        .expect("release check-before-wait gate");
                }
                state = shared
                    .wake
                    .wait_timeout(state, oldest_ages_in)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0;
            }
        };
        if !give_back.is_empty() {
            for nonce in give_back {
                helper.release(nonce);
            }
            continue;
        }

        let asked = Instant::now();
        match helper.issue() {
            Ok(nonce) => {
                if failing {
                    failing = false;
                    crate::log::info("worker", "the nonce pool gets nonces from the helper again");
                }
                shared.lock().ready.push_back((nonce, asked));
            }
            Err(why) => {
                if !failing {
                    failing = true;
                    crate::log::warn(
                        "worker",
                        &format!(
                            "the nonce pool could not get a nonce from the helper \
                         ({why}); handshakes are refused while it is empty, and it keeps asking"
                        ),
                    );
                }
                let state = shared.lock();
                let _ = shared
                    .wake
                    .wait_timeout_while(state, REFILL_RETRY_DELAY, |state| !state.closing);
            }
        }
    }
}

/// Runs when the pool's thread ends. The ordinary end -- the pool was
/// dropped -- is nothing to report. A panic is logged and ends the worker
/// ([`POOL_THREAD_GONE_REASON`]).
struct PoolThreadExit {
    end_worker: EndWorker,
}

impl Drop for PoolThreadExit {
    fn drop(&mut self) {
        if std::thread::panicking() {
            crate::log::error("worker", POOL_THREAD_GONE_LOG);
            (self.end_worker)(POOL_THREAD_GONE_REASON);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    include!("nonce_pool_auxiliary_tests.rs");
    use super::*;
    use std::collections::HashSet;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering};

    use transport::AUTH_NONCE_LEN;

    use crate::helper::channel;
    use crate::helper::config::HelperConfig;
    use crate::helper::protocol::{decode, encode, AuthRequest, AuthResponse, Request, Response};

    /// What "at once" means for `issue`: far below the time a round trip to
    /// a slow stub helper takes ([`SLOW`]), far above a lock and a pop on a
    /// loaded machine.
    pub(crate) const AT_ONCE: Duration = Duration::from_millis(5);

    /// How long a slow stub helper takes to answer a nonce request.
    const SLOW: Duration = Duration::from_secs(1);

    /// How long a test waits for something the pool's thread does before
    /// concluding it will not happen.
    pub(crate) const TEST_WAIT: Duration = Duration::from_secs(10);

    /// How a stub helper treats the nonce request with this index (the
    /// first is 0).
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Pace {
        /// Answers with a fresh nonce after this long.
        After(Duration),
        /// Answers `NonceUnavailable` at once.
        Refuse,
        /// Never answers.
        Never,
    }

    /// Everything a stub helper has seen and done.
    #[derive(Default)]
    struct StubLog {
        issued: Vec<Nonce>,
        released: Vec<Nonce>,
        nonce_requests: usize,
        /// Nonce requests the stub read and will never answer.
        ignored: usize,
        verifies: usize,
    }

    /// A stub helper on the authentication seam, on a thread of its own. It
    /// ends when the worker's end of the seam closes.
    pub(crate) struct StubHelper {
        log: Arc<Mutex<StubLog>>,
        gone: Arc<AtomicBool>,
    }

    impl StubHelper {
        /// Every nonce given back to the stub so far.
        pub(crate) fn released(&self) -> HashSet<Nonce> {
            self.log().released.iter().copied().collect()
        }

        /// How many times the same nonce was given back, at most.
        fn most_releases_of_one(&self) -> usize {
            let log = self.log();
            log.released
                .iter()
                .map(|n| log.released.iter().filter(|m| *m == n).count())
                .max()
                .unwrap_or(0)
        }

        /// Every nonce the stub issued so far, in order.
        pub(crate) fn issued(&self) -> Vec<Nonce> {
            self.log().issued.clone()
        }

        /// How many nonce requests reached the stub so far.
        pub(crate) fn nonce_requests(&self) -> usize {
            self.log().nonce_requests
        }

        /// How many nonce requests the stub has read and left unanswered.
        pub(crate) fn ignored(&self) -> usize {
            self.log().ignored
        }

        /// How many verifications reached the stub so far.
        pub(crate) fn verifies(&self) -> usize {
            self.log().verifies
        }

        /// Whether the worker's end of the seam has closed.
        pub(crate) fn seam_closed(&self) -> bool {
            self.gone.load(Ordering::SeqCst)
        }

        fn log(&self) -> MutexGuard<'_, StubLog> {
            self.log.lock().expect("the stub's log")
        }
    }

    /// A fresh nonce, different for every `index` and never all zeros.
    fn nonce_number(index: usize) -> Nonce {
        let mut nonce = [0x5Au8; AUTH_NONCE_LEN];
        nonce[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        nonce
    }

    /// A stub helper: the worker's end of its seam, and the stub. `pace`
    /// decides each nonce request's fate; a verification is answered with
    /// `verdict` when there is one, and never otherwise.
    pub(crate) fn stub_helper(
        pace: impl Fn(usize) -> Pace + Send + 'static,
        verdict: Option<Response>,
    ) -> (UnixStream, StubHelper) {
        let (worker, stub_end) = channel::pair().expect("socketpair");
        let log = Arc::new(Mutex::new(StubLog::default()));
        let gone = Arc::new(AtomicBool::new(false));
        let stub = StubHelper {
            log: Arc::clone(&log),
            gone: Arc::clone(&gone),
        };
        std::thread::spawn(move || {
            let answer = |id, body| {
                let _ = channel::send(
                    &stub_end,
                    &encode(&AuthResponse { id, body }).expect("encode"),
                    None,
                );
            };
            while let Ok(Some((bytes, _fd))) = channel::recv(&stub_end) {
                let AuthRequest { id, body } = decode::<AuthRequest>(&bytes).expect("decode");
                match body {
                    Request::Nonce => {
                        let index = {
                            let mut log = log.lock().expect("the stub's log");
                            log.nonce_requests += 1;
                            log.nonce_requests - 1
                        };
                        match pace(index) {
                            Pace::After(delay) => {
                                std::thread::sleep(delay);
                                let nonce = nonce_number(index);
                                log.lock().expect("the stub's log").issued.push(nonce);
                                answer(id, Response::Nonce { nonce });
                            }
                            Pace::Refuse => answer(id, Response::NonceUnavailable),
                            Pace::Never => log.lock().expect("the stub's log").ignored += 1,
                        }
                    }
                    Request::ReleaseNonce { nonce } => {
                        log.lock().expect("the stub's log").released.push(nonce);
                    }
                    Request::Verify { .. } => {
                        log.lock().expect("the stub's log").verifies += 1;
                        if let Some(verdict) = &verdict {
                            answer(id, verdict.clone());
                        }
                    }
                    _ => {}
                }
            }
            gone.store(true, Ordering::SeqCst);
        });
        (worker, stub)
    }

    pub(crate) fn helper_stub_answering_nonces_at_once() -> (UnixStream, StubHelper) {
        stub_helper(|_| Pace::After(Duration::ZERO), None)
    }

    /// Answers the first [`POOL_TARGET`] nonce requests at once -- enough to
    /// fill a pool -- and every later one only after `slow`.
    fn helper_stub_answering_nonces_slowly(slow: Duration) -> (UnixStream, StubHelper) {
        stub_helper(
            move |index| {
                if index < POOL_TARGET {
                    Pace::After(Duration::ZERO)
                } else {
                    Pace::After(slow)
                }
            },
            None,
        )
    }

    fn helper_stub_that_never_answers() -> (UnixStream, StubHelper) {
        stub_helper(|_| Pace::Never, None)
    }

    /// The settings the helper runs with, as the daemon resolves them --
    /// what gives [`HelperAuth`] its production budgets.
    pub(crate) fn helper_config() -> HelperConfig {
        HelperConfig::resolve(&crate::serve::ServeArgs {
            status_socket: None,
            port: crate::serve::DEFAULT_SERVE_PORT,
            authorized_keys: None, // unread in the system mode -- see its own doc comment
            host_key: "/unused".into(),
            system: true,
            worker_user: "qshd".to_string(),
            permit_root: false,
            authorized_keys_template: "%h/.ssh/authorized_keys".to_string(),
            runtime_threads: None,
        })
    }

    /// A helper client on `worker`, with the production budgets.
    pub(crate) fn client(worker: UnixStream) -> Arc<HelperAuth> {
        Arc::new(HelperAuth::new(worker, &helper_config()).expect("auth"))
    }

    /// Whether `done` became true within `bound`, polling.
    pub(crate) fn wait_until(bound: Duration, mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + bound;
        while !done() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    /// Takes every nonce `pool` has ready and returns how many -- a few
    /// pools' worth at most, so a pool that never runs dry fails the test
    /// rather than hangs it.
    pub(crate) fn drain(pool: &PooledNonces) -> usize {
        let mut taken = 0;
        while taken < 4 * POOL_TARGET && pool.issue().is_ok() {
            taken += 1;
        }
        taken
    }

    /// Waits for `pool` to hold at least `count` nonces, and fails the test
    /// if it does not within `bound`.
    pub(crate) fn wait_until_warm(pool: &PooledNonces, count: usize, bound: Duration) {
        assert!(
            wait_until(bound, || pool.snapshot().len() >= count),
            "the pool did not hold {count} nonces within {bound:?}; it holds {}",
            pool.snapshot().len()
        );
    }

    /// Issuing must not depend on how fast the helper is: with a helper that
    /// takes a second for every nonce after the ones that filled the pool, a
    /// handshake still gets one at once from the warm pool.
    #[test]
    fn a_warm_pool_issues_without_waiting_for_the_helper() {
        let (worker, _stub) = helper_stub_answering_nonces_slowly(SLOW);
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);

        let started = Instant::now();
        let nonce = pool.issue().expect("a warm pool has one ready");
        assert!(
            started.elapsed() < AT_ONCE,
            "issue() waited {:?}",
            started.elapsed()
        );
        assert_ne!(nonce, [0u8; AUTH_NONCE_LEN]);
    }

    /// A pooled nonce older than POOL_MAX_AGE is handed back, not handed out:
    /// the helper's own lifetime is 30s, and a client must never get a nonce
    /// that expires mid-handshake.
    #[test]
    fn a_stale_pooled_nonce_is_returned_not_issued() {
        let (worker, stub) = helper_stub_answering_nonces_at_once();
        // A max age of 50ms instead of 20s, so the test watches ageing rather
        // than waiting it out.
        let pool =
            PooledNonces::with_max_age(client(worker), Duration::from_millis(50)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        let stale: HashSet<Nonce> = pool.snapshot().into_iter().collect();
        assert_eq!(stale.len(), POOL_TARGET, "the pool must warm up first");

        std::thread::sleep(Duration::from_millis(120));

        // Wait for the refill thread rather than racing it: a full pool none
        // of whose nonces is a stale one -- a pool still holding the stale
        // ones would satisfy a bare count at once. Not asserted: a pool that
        // never expires anything must still fail on the assertion below.
        wait_until(TEST_WAIT, || {
            let now = pool.snapshot();
            now.len() == POOL_TARGET && now.iter().all(|n| !stale.contains(n))
        });
        let issued = pool.issue();
        assert!(
            !matches!(issued, Ok(n) if stale.contains(&n)),
            "a nonce older than POOL_MAX_AGE was handed out instead of being returned: {issued:?}"
        );
        wait_until(TEST_WAIT, || stub.released().is_superset(&stale));
        assert!(
            stub.released().is_superset(&stale),
            "every stale nonce must go back to the helper, not be dropped: it would \
             otherwise hold one of the helper's 256 slots for its full lifetime"
        );
    }

    /// The pool's thread gives aged nonces back by itself, with nobody
    /// asking for one: a pool nobody draws from must not sit on nonces the
    /// helper has long forgotten, nor hold the helper's slots with them. It
    /// fills itself up again with fresh ones.
    #[test]
    fn an_idle_pool_gives_its_aged_nonces_back_by_itself() {
        let (worker, stub) = helper_stub_answering_nonces_at_once();
        let pool =
            PooledNonces::with_max_age(client(worker), Duration::from_millis(50)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        let aged: HashSet<Nonce> = pool.snapshot().into_iter().collect();
        assert_eq!(aged.len(), POOL_TARGET, "the pool must warm up first");

        assert!(
            wait_until(TEST_WAIT, || stub.released().is_superset(&aged)),
            "an idle pool must give its aged nonces back to the helper on its own; given back: \
             {} of {POOL_TARGET}",
            stub.released().intersection(&aged).count()
        );
        assert!(
            wait_until(TEST_WAIT, || {
                let now: Vec<Nonce> = pool.snapshot();
                now.len() == POOL_TARGET && now.iter().all(|n| !aged.contains(n))
            }),
            "the pool must fill up again with fresh nonces"
        );
    }

    /// `issue` checks a nonce's age itself, and does not rely on the pool's
    /// thread having given aged ones back: that thread may be waiting on a
    /// helper that is slow to answer while the pool ages.
    ///
    /// The stub fills the pool, then answers the next request only after
    /// [`SLOW`]. One nonce is taken, so the thread asks for its replacement
    /// and waits; the other seven age out in the meantime. The pool must
    /// refuse rather than hand one of them out, and they must still go back
    /// to the helper once the thread is free.
    #[test]
    fn a_nonce_that_ages_while_the_pool_waits_on_the_helper_is_not_handed_out() {
        const MAX_AGE: Duration = Duration::from_millis(100);
        let (worker, stub) = helper_stub_answering_nonces_slowly(SLOW);
        let pool = PooledNonces::with_max_age(client(worker), MAX_AGE).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        pool.issue().expect("setup: a warm pool has one ready");
        let ageing: HashSet<Nonce> = pool.snapshot().into_iter().collect();
        assert!(
            wait_until(TEST_WAIT, || stub.nonce_requests() > POOL_TARGET),
            "setup: the pool's thread must ask for the replacement"
        );

        std::thread::sleep(MAX_AGE * 2);
        assert!(
            stub.issued().len() == POOL_TARGET,
            "setup: the thread must still be waiting for its slow answer, or this proves nothing"
        );
        let issued = pool.issue();
        assert!(
            !matches!(issued, Ok(n) if ageing.contains(&n)),
            "a nonce that aged out while the pool's thread was busy was handed out: {issued:?}"
        );
        assert!(
            wait_until(TEST_WAIT, || stub.released().is_superset(&ageing)),
            "the nonces that aged out must go back to the helper once the thread is free"
        );
    }

    /// An empty pool refuses at once rather than waiting: the router task must
    /// never block, and the client retries.
    #[test]
    fn an_empty_pool_refuses_immediately() {
        // A stub that reads requests and never answers: the pool can never warm.
        let (worker, _stub) = helper_stub_that_never_answers();
        let pool = PooledNonces::start(client(worker)).expect("pool");

        let started = Instant::now();
        let refused = pool.issue();

        assert!(
            refused.is_err(),
            "an empty pool must refuse rather than invent a nonce"
        );
        assert!(
            started.elapsed() < AT_ONCE,
            "issue() waited {:?} on an empty pool; the router task must never block",
            started.elapsed()
        );
    }

    /// A daemon that has just started must not refuse the first login: the
    /// pool is filled, synchronously, before `start` returns, so the very
    /// first `issue()` has something to hand out -- and a full pool, so the
    /// first burst does too.
    ///
    /// The stub takes a little while for each nonce, far longer than this
    /// test takes to reach its first `issue`, so a pool that filled itself
    /// only on its thread would still be empty then: the test does not
    /// depend on which thread wins a race.
    #[test]
    fn a_freshly_started_pool_issues_at_once() {
        let (worker, _stub) = stub_helper(|_| Pace::After(Duration::from_millis(20)), None);
        let pool = PooledNonces::start(client(worker)).expect("pool");
        // No `wait_until_warm`: that is the point.
        let held = pool.snapshot().len();
        assert!(
            pool.issue().is_ok(),
            "a just-started pool must already hold nonces"
        );
        assert_eq!(
            held, POOL_TARGET,
            "a just-started pool must already be full"
        );
    }

    /// The warm-up is bounded AS A WHOLE, not call by call: a helper that
    /// takes almost a whole answer budget for each nonce still holds `start`
    /// up for about one budget, not one per nonce.
    #[test]
    fn the_warm_up_as_a_whole_takes_one_answer_budget_at_most() {
        let slow = HELPER_ANSWER_TIMEOUT - Duration::from_millis(100);
        let (worker, _stub) = stub_helper(move |_| Pace::After(slow), None);
        let started = Instant::now();
        let _pool = PooledNonces::start(client(worker)).expect("pool");
        let took = started.elapsed();
        assert!(
            took < HELPER_ANSWER_TIMEOUT + HELPER_ANSWER_TIMEOUT / 2,
            "starting the pool took {took:?}; the whole warm-up must take one answer budget \
             ({HELPER_ANSWER_TIMEOUT:?}) at most"
        );
    }

    /// A taken nonce is replaced at once, not only when the oldest one ages
    /// out -- [`POOL_MAX_AGE`] later. The nonce is taken once the pool's
    /// thread is asleep: a thread that has not got that far yet finds the
    /// pool short without being woken.
    #[test]
    fn a_taken_nonce_is_replaced_at_once() {
        let (worker, _stub) = helper_stub_answering_nonces_at_once();
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        assert!(
            wait_until(TEST_WAIT, || pool.sleeps() > 0),
            "setup: the pool's thread must be asleep on a full pool"
        );

        pool.issue().expect("a warm pool has one ready");
        assert!(
            wait_until(TEST_WAIT, || pool.snapshot().len() == POOL_TARGET),
            "the pool must fetch a replacement as soon as a nonce is taken; it holds {}",
            pool.snapshot().len()
        );
    }

    /// A released nonce goes to the helper, and never back into the pool: it
    /// was handed out once, and a second handshake given it could present it
    /// twice.
    #[test]
    fn a_released_nonce_goes_to_the_helper_not_back_into_the_pool() {
        let (worker, stub) = helper_stub_answering_nonces_at_once();
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        let nonce = pool.issue().expect("a warm pool has one ready");

        pool.release(nonce);
        let mut seen_in_pool = pool.snapshot().contains(&nonce);
        let reached_helper = wait_until(TEST_WAIT, || {
            seen_in_pool |= pool.snapshot().contains(&nonce);
            stub.released().contains(&nonce)
        });
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        seen_in_pool |= pool.snapshot().contains(&nonce);

        assert!(
            reached_helper,
            "a released nonce must be given back to the helper"
        );
        assert!(
            !seen_in_pool,
            "a released nonce must never be put back into the pool"
        );
        assert!(
            !pool.snapshot().contains(&nonce) && pool.issue() != Ok(nonce),
            "a released nonce must never be handed out again"
        );
    }

    /// A pool that is dropped gives back every nonce it still holds, and lets
    /// go of the helper client: the seam closes once nothing holds it. The
    /// pool is dropped once its thread is asleep, so the thread has to be
    /// woken for it.
    #[test]
    fn a_dropped_pool_gives_back_what_it_holds_and_lets_go_of_the_helper() {
        let (worker, stub) = helper_stub_answering_nonces_at_once();
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        assert!(
            wait_until(TEST_WAIT, || pool.sleeps() > 0),
            "setup: the pool's thread must be asleep on a full pool"
        );
        let held: HashSet<Nonce> = pool.snapshot().into_iter().collect();

        drop(pool);
        assert!(
            wait_until(TEST_WAIT, || stub.seam_closed()),
            "once the pool is dropped its thread must end and let go of the helper client"
        );
        assert!(
            stub.released().is_superset(&held),
            "a dropped pool must give back every nonce it held"
        );
        assert_eq!(
            stub.most_releases_of_one(),
            1,
            "each nonce must be given back once"
        );
    }

    /// A helper that refuses to issue -- its table of unspent nonces is full
    /// -- is asked again, but not in a tight loop; once it issues again the
    /// pool fills up.
    #[test]
    fn a_helper_that_refuses_is_asked_again_but_not_in_a_loop() {
        let refusing = Arc::new(AtomicBool::new(false));
        let pace_refusing = Arc::clone(&refusing);
        let (worker, stub) = stub_helper(
            move |_| {
                if pace_refusing.load(Ordering::SeqCst) {
                    Pace::Refuse
                } else {
                    Pace::After(Duration::ZERO)
                }
            },
            None,
        );
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);

        refusing.store(true, Ordering::SeqCst);
        drain(&pool);
        let before = stub.nonce_requests();
        std::thread::sleep(Duration::from_secs(1));
        let asked = stub.nonce_requests() - before;
        assert!(
            (1..=4).contains(&asked),
            "a helper that refuses must be asked again, about every {REFILL_RETRY_DELAY:?}, not \
             in a loop: it was asked {asked} times in a second"
        );

        refusing.store(false, Ordering::SeqCst);
        assert!(
            wait_until(TEST_WAIT, || pool.snapshot().len() == POOL_TARGET),
            "once the helper issues again the pool must fill up"
        );
    }

    /// The pool says in the log when it starts short, and when it cannot get
    /// nonces -- once for each spell of failures, not once per failed call --
    /// and when it gets them again.
    #[test]
    fn the_pool_logs_each_spell_without_nonces_once() {
        let (status, stdout, stderr) = crate::helper::spawner::tests::run_isolated(
            "nonce_pool::tests::the_pool_logs_each_spell_without_nonces_once_body",
        );
        assert!(
            status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_pool_logs_each_spell_without_nonces_once`], in a
    /// process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via the_pool_logs_each_spell_without_nonces_once, in a process of its \
                own"]
    fn the_pool_logs_each_spell_without_nonces_once_body() {
        const STARTS_SHORT: &str = "the nonce pool starts with";
        const CANNOT_GET: &str = "the nonce pool could not get a nonce";
        const GETS_AGAIN: &str = "the nonce pool gets nonces from the helper again";
        /// Nonce requests the stub answers before it first refuses one.
        const FIRST_ANSWERED: usize = 3;

        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let lines = |what: &str| {
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .matches(what)
                .count()
        };
        let log = || std::fs::read_to_string(&log_path).unwrap_or_default();

        // 0: refuse, 1: answer, 2: refuse again.
        let phase = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pace_phase = Arc::clone(&phase);
        let (worker, stub) = stub_helper(
            move |index| {
                if index < FIRST_ANSWERED {
                    return Pace::After(Duration::ZERO);
                }
                match pace_phase.load(Ordering::SeqCst) {
                    1 => Pace::After(Duration::ZERO),
                    _ => Pace::Refuse,
                }
            },
            None,
        );
        let pool = PooledNonces::start(client(worker)).expect("pool");
        assert_eq!(
            lines(STARTS_SHORT),
            1,
            "a pool that starts short must say so once; the log is:\n{}",
            log()
        );
        assert!(
            log().contains(&format!("starts with {FIRST_ANSWERED} of {POOL_TARGET}")),
            "the log must say how many nonces the pool starts with; the log is:\n{}",
            log()
        );

        let refused_by_thread = FIRST_ANSWERED + 1 + 3;
        assert!(
            wait_until(TEST_WAIT, || stub.nonce_requests() >= refused_by_thread),
            "setup: the pool's thread must be refused three times"
        );
        assert_eq!(
            lines(CANNOT_GET),
            1,
            "one spell of refusals must be logged once; the log is:\n{}",
            log()
        );

        phase.store(1, Ordering::SeqCst);
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        assert_eq!(
            lines(GETS_AGAIN),
            1,
            "the end of a spell must be logged once; the log is:\n{}",
            log()
        );

        phase.store(2, Ordering::SeqCst);
        drain(&pool);
        let before = stub.nonce_requests();
        assert!(
            wait_until(TEST_WAIT, || stub.nonce_requests() >= before + 2),
            "setup: the pool's thread must be refused again, twice"
        );
        assert_eq!(
            lines(CANNOT_GET),
            2,
            "a second spell of refusals must be logged once more; the log is:\n{}",
            log()
        );
        assert_eq!(
            lines(STARTS_SHORT),
            1,
            "only the start is logged as a start; the log is:\n{}",
            log()
        );
    }

    /// A pool thread that dies logs it and ends the worker, saying why; one
    /// that ends because the pool was dropped does neither.
    #[test]
    fn a_pool_thread_that_dies_ends_the_worker_and_a_dropped_one_does_not() {
        let recording = || {
            let (tx, rx) = std::sync::mpsc::channel::<String>();
            let end_worker: EndWorker = Arc::new(move |why: &str| {
                let _ = tx.send(why.to_string());
            });
            (end_worker, rx)
        };

        let (worker, _stub) = helper_stub_answering_nonces_at_once();
        let (end_worker, ended) = recording();
        let pool = PooledNonces::with_end_worker(client(worker), end_worker).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        pool.panic_thread_for_test();
        assert_eq!(
            ended.recv_timeout(TEST_WAIT),
            Ok(POOL_THREAD_GONE_REASON.to_string()),
            "a pool thread that dies must end the worker, and say why"
        );

        let (worker, stub) = helper_stub_answering_nonces_at_once();
        let (end_worker, ended) = recording();
        let pool = PooledNonces::with_end_worker(client(worker), end_worker).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        drop(pool);
        assert!(
            wait_until(TEST_WAIT, || stub.seam_closed()),
            "setup: the pool's thread must end once the pool is dropped"
        );
        assert_eq!(
            ended.recv_timeout(Duration::from_millis(200)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
            "a pool dropped on purpose must not end the worker"
        );
    }

    /// The worker's pool, as `start` builds it, in a process of its own: its
    /// thread dying ends the process, and the log and stderr say why.
    #[test]
    fn a_dead_pool_thread_ends_the_worker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (status, stdout, stderr) = crate::helper::spawner::tests::run_isolated_with_env(
            "nonce_pool::tests::a_dead_pool_thread_ends_the_worker_body",
            &[(POOL_TEST_LOG_DIR, dir.path().as_os_str())],
        );
        let log = std::fs::read_to_string(dir.path().join("qshd.log")).unwrap_or_default();
        assert_eq!(
            status.code(),
            Some(1),
            "a worker whose pool thread died must end itself (end_the_worker exits with 1):\n\
             stdout:\n{stdout}\nstderr:\n{stderr}\nlog:\n{log}"
        );
        let ended = format!("ERROR worker: ending the process -- {POOL_THREAD_GONE_REASON}");
        assert!(
            log.contains(POOL_THREAD_GONE_LOG) && log.contains(&ended) && stderr.contains(&ended),
            "the log must say the pool's thread stopped and why the worker ended, and stderr the \
             latter:\nstderr:\n{stderr}\nlog:\n{log}"
        );
    }

    /// Where [`a_dead_pool_thread_ends_the_worker_body`] writes its log.
    const POOL_TEST_LOG_DIR: &str = "QSHD_POOL_TEST_LOG_DIR";

    /// Runs only via [`a_dead_pool_thread_ends_the_worker`], in a process of
    /// its own.
    #[test]
    #[ignore = "runs only via a_dead_pool_thread_ends_the_worker, in a process of its own"]
    fn a_dead_pool_thread_ends_the_worker_body() {
        let dir = std::env::var_os(POOL_TEST_LOG_DIR).expect("the log directory");
        crate::log::init(std::path::Path::new(&dir));
        let (worker, _stub) = helper_stub_answering_nonces_at_once();
        let pool = PooledNonces::start(client(worker)).expect("pool");
        wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
        pool.panic_thread_for_test();
        std::thread::sleep(Duration::from_secs(5));
        eprintln!("still running 5s after the pool's thread died: nothing ended the worker");
        std::process::exit(2);
    }

    /// Starts nothing -- for a pool whose thread cannot start.
    fn spawn_nothing(
        _body: Box<dyn FnOnce() + Send>,
    ) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
        Err(io::Error::other("this test starts no thread"))
    }

    /// A pool whose thread cannot start fails to start, and gives back every
    /// nonce its warm-up fetched rather than leaving them in the helper's
    /// table.
    #[test]
    fn a_pool_whose_thread_cannot_start_gives_back_what_it_fetched() {
        let (worker, stub) = helper_stub_answering_nonces_at_once();
        let started = PooledNonces::with_spawn(client(worker), spawn_nothing);
        match started {
            Err(e) => assert!(
                e.to_string().contains("starts no thread"),
                "the pool must fail with the thread's own error, got: {e}"
            ),
            Ok(_) => panic!("a pool whose thread cannot start must not start"),
        }
        let fetched: HashSet<Nonce> = stub.issued().into_iter().collect();
        assert_eq!(
            fetched.len(),
            POOL_TARGET,
            "setup: the warm-up fetched a full pool"
        );
        assert!(
            wait_until(TEST_WAIT, || stub.released().is_superset(&fetched)),
            "every nonce the warm-up fetched must go back to the helper; given back: {} of \
             {POOL_TARGET}",
            stub.released().intersection(&fetched).count()
        );
    }

    /// A nonce handed out at the pool's age limit is still on file at the
    /// helper when the client's proof comes back at the client's own
    /// deadline, with room to spare.
    #[test]
    fn a_pooled_nonce_outlives_the_proof_it_is_for() {
        let spent_by = POOL_MAX_AGE + transport::AUTH_DEADLINE;
        assert!(
            spent_by + Duration::from_secs(5) <= crate::helper::server::NONCE_LIFETIME,
            "a nonce handed out at POOL_MAX_AGE ({POOL_MAX_AGE:?}) may be spent up to \
             {spent_by:?} after it was issued; the helper keeps it for \
             {:?}, which must leave a margin",
            crate::helper::server::NONCE_LIFETIME
        );
    }
}
