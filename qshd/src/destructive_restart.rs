//! Exact-image, bounded one-use authority for explicit interrupting restart.
use daemon_bootstrap_protocol::{BusyDaemonIdentity, DestructiveRestartConsent};
use rand_core::RngCore;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const RECEIPT_TTL: Duration = Duration::from_secs(120);
const CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejected {
    Unavailable,
    Mismatch,
    Expired,
    Unknown,
    Capacity,
    Collision,
    Replacing,
    ShutdownCommitted,
    Exhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    New,
    AlreadyCommitted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplacementLease(u64);
struct Receipt {
    id: [u8; 16],
    binding: DestructiveRestartConsent,
    expires: Instant,
}
enum Phase {
    Running,
    Replacing(ReplacementLease),
    ShutdownCommitted(Option<([u8; 16], DestructiveRestartConsent)>),
}

/// Always held through a short synchronous mutex guard. If the control gate
/// is also needed, acquire it first. No I/O, drain wait or ACK belongs here.
pub(crate) struct Coordinator {
    identity: Option<BusyDaemonIdentity>,
    phase: Phase,
    receipts: Vec<Receipt>,
    next_lease: u64,
}
impl Coordinator {
    #[cfg(test)]
    pub(crate) fn new(identity: BusyDaemonIdentity) -> Result<Self, Rejected> {
        if !identity.valid() || identity.generation.is_none() {
            return Err(Rejected::Mismatch);
        }
        Ok(Self {
            identity: Some(identity),
            phase: Phase::Running,
            receipts: Vec::new(),
            next_lease: 0,
        })
    }
    fn running(&self) -> Result<(), Rejected> {
        match self.phase {
            Phase::Running => Ok(()),
            Phase::Replacing(_) => Err(Rejected::Replacing),
            Phase::ShutdownCommitted(_) => Err(Rejected::ShutdownCommitted),
        }
    }
    /// The caller supplies a freshly sampled OS-random128 value. A collision
    /// never overwrites another receipt or broadens its binding.
    pub(crate) fn prepare(
        &mut self,
        now: Instant,
        binding: DestructiveRestartConsent,
        id: [u8; 16],
    ) -> Result<(), Rejected> {
        self.running()?;
        if self.identity.as_ref() != Some(&binding.identity) || !binding.candidate.valid() {
            return Err(Rejected::Mismatch);
        }
        self.receipts.retain(|r| r.expires > now);
        if self.receipts.iter().any(|r| r.id == id) {
            return Err(Rejected::Collision);
        }
        if self.receipts.len() == CAPACITY {
            return Err(Rejected::Capacity);
        }
        let expires = now.checked_add(RECEIPT_TTL).ok_or(Rejected::Exhausted)?;
        self.receipts.push(Receipt {
            id,
            binding,
            expires,
        });
        Ok(())
    }
    /// Consume and latch before reporting New to the synchronous dispatcher.
    /// The dispatcher seals admission and requests sticky shutdown while still
    /// holding this state guard; client ACK delivery never controls that effect.
    pub(crate) fn commit(
        &mut self,
        now: Instant,
        id: [u8; 16],
        binding: &DestructiveRestartConsent,
    ) -> Result<Commit, Rejected> {
        if let Phase::ShutdownCommitted(Some((prior, request))) = &self.phase {
            return if *prior == id && request == binding {
                Ok(Commit::AlreadyCommitted)
            } else {
                Err(Rejected::ShutdownCommitted)
            };
        }
        self.running()?;
        let index = self
            .receipts
            .iter()
            .position(|r| r.id == id)
            .ok_or(Rejected::Unknown)?;
        if self.receipts[index].binding != *binding {
            return Err(Rejected::Mismatch);
        }
        let receipt = self.receipts.remove(index);
        if receipt.expires <= now {
            return Err(Rejected::Expired);
        }
        self.phase = Phase::ShutdownCommitted(Some((id, receipt.binding)));
        self.receipts.clear();
        Ok(Commit::New)
    }
    pub(crate) fn begin_replacement(&mut self) -> Result<ReplacementLease, Rejected> {
        self.running()?;
        self.next_lease = self.next_lease.checked_add(1).ok_or(Rejected::Exhausted)?;
        let lease = ReplacementLease(self.next_lease);
        self.phase = Phase::Replacing(lease);
        self.receipts.clear();
        Ok(lease)
    }
    pub(crate) fn owns_replacement(&self, lease: ReplacementLease) -> bool {
        matches!(self.phase,Phase::Replacing(current) if current==lease)
    }
    /// Rollback operations must finish under the same guard before this call.
    pub(crate) fn finish_replacement(&mut self, lease: ReplacementLease) -> bool {
        if !self.owns_replacement(lease) {
            return false;
        }
        self.phase = Phase::Running;
        true
    }
    pub(crate) fn administrative_shutdown(&mut self) {
        if !self.shutdown_committed() {
            self.phase = Phase::ShutdownCommitted(None);
            self.receipts.clear();
        }
    }
    pub(crate) fn shutdown_committed(&self) -> bool {
        matches!(self.phase, Phase::ShutdownCommitted(_))
    }
}

/// The common authority for update replacement and terminal daemon shutdown.
/// Its state mutex never spans I/O, sleeps, gate acquisition or ACK delivery.
pub struct Actions {
    pub(crate) control_gate: Arc<tokio::sync::RwLock<()>>,
    pub(crate) admission: Arc<crate::update::AdmissionGate>,
    pub(crate) shutdown: transport::Shutdown,
    pub(crate) state: Mutex<Coordinator>,
    capable: bool,
    #[cfg(test)]
    pub(crate) after_exec_panic: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Actions {
    /// Unavailable metadata disables receipts without disabling normal service
    /// or the shared terminal latch used by updates and administrative STOP.
    pub fn new(
        identity: Option<BusyDaemonIdentity>,
        control_gate: Arc<tokio::sync::RwLock<()>>,
        admission: Arc<crate::update::AdmissionGate>,
        capable: bool,
    ) -> Self {
        let identity = identity.filter(|id| id.valid() && id.generation.is_some());
        Self {
            control_gate,
            admission,
            shutdown: transport::Shutdown::default(),
            capable: capable && identity.is_some(),
            state: Mutex::new(Coordinator {
                identity,
                phase: Phase::Running,
                receipts: Vec::new(),
                next_lease: 0,
            }),
            #[cfg(test)]
            after_exec_panic: Mutex::new(None),
        }
    }
    #[cfg(test)]
    fn with_identity(
        identity: BusyDaemonIdentity,
        control_gate: Arc<tokio::sync::RwLock<()>>,
        admission: Arc<crate::update::AdmissionGate>,
        capable: bool,
    ) -> Result<Self, Rejected> {
        Coordinator::new(identity.clone())?;
        Ok(Self::new(Some(identity), control_gate, admission, capable))
    }
    pub(crate) fn receipt_identity(&self) -> Option<BusyDaemonIdentity> {
        if !self.capable {
            return None;
        }
        self.state.lock().ok()?.identity.clone()
    }
    pub(crate) fn prepare(&self, binding: DestructiveRestartConsent) -> Result<[u8; 16], Rejected> {
        if !self.capable {
            return Err(Rejected::Unavailable);
        }
        let mut id = [0; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| Rejected::Unavailable)?;
        self.state
            .lock()
            .map_err(|_| Rejected::Unavailable)?
            .prepare(Instant::now(), binding, id)?;
        Ok(id)
    }
    pub(crate) async fn commit(
        &self,
        id: [u8; 16],
        binding: &DestructiveRestartConsent,
    ) -> Result<Commit, Rejected> {
        if !self.capable {
            return Err(Rejected::Unavailable);
        }
        let _control = self.control_gate.write().await;
        let mut state = self.state.lock().map_err(|_| Rejected::Unavailable)?;
        let committed = state.commit(Instant::now(), id, binding)?;
        if committed == Commit::New {
            self.admission.seal_shutdown();
            self.shutdown.request();
        }
        Ok(committed)
    }
    pub(crate) fn administrative_shutdown(&self) {
        // Poison is terminal too: never recover a replacement permission.
        if let Ok(mut state) = self.state.lock() {
            state.administrative_shutdown();
        }
        self.admission.seal_shutdown();
        self.shutdown.request();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecFailure {
    Revoked,
    Os(nix::errno::Errno),
}
impl std::fmt::Display for ExecFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Revoked => f.write_str("replacement authority revoked"),
            Self::Os(e) => e.fmt(f),
        }
    }
}
/// Bound to one existing lease. It cannot acquire replacement authority and
/// only holds the short state mutex over one raw exec syscall.
pub(crate) struct ExecAttemptGuard<'a> {
    actions: &'a Actions,
    lease: ReplacementLease,
}
impl<'a> ExecAttemptGuard<'a> {
    pub(crate) fn new(actions: &'a Actions, lease: ReplacementLease) -> Self {
        Self { actions, lease }
    }
    pub(crate) fn attempt(&self, exec: impl FnOnce() -> nix::errno::Errno) -> ExecFailure {
        let Ok(state) = self.actions.state.lock() else {
            return ExecFailure::Revoked;
        };
        if !state.owns_replacement(self.lease) {
            return ExecFailure::Revoked;
        }
        // Only the immutable syscall boundary is contained. Validation and
        // state changes are outside this catch; genuine poison stays refused.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(exec));
        drop(state);
        match result {
            Ok(errno) => ExecFailure::Os(errno),
            Err(payload) => {
                #[cfg(test)]
                {
                    let hook = self.actions.after_exec_panic.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                std::panic::resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_bootstrap_protocol::{
        BusyAttemptId, BusyDaemonIdentity, CandidateImageIdentity, DestructiveRestartAction,
        DestructiveRestartConsent,
    };
    fn binding() -> DestructiveRestartConsent {
        DestructiveRestartConsent {
            attempt: BusyAttemptId::from_bytes([1; 16]),
            identity: BusyDaemonIdentity {
                version: "0.6.0-rc1".into(),
                build: 1,
                checksum: "ab".repeat(32),
                pid: 42,
                generation: Some("cd".repeat(16)),
            },
            candidate: CandidateImageIdentity {
                build: 2,
                checksum: "ef".repeat(32),
            },
            action: DestructiveRestartAction::StopAndRestart,
        }
    }
    fn book() -> Coordinator {
        Coordinator::new(binding().identity).unwrap()
    }
    #[tokio::test]
    async fn action_commit_seals_admission_and_is_sticky_before_any_subscriber() {
        let actions = Actions::with_identity(
            binding().identity,
            std::sync::Arc::new(tokio::sync::RwLock::new(())),
            std::sync::Arc::new(crate::update::AdmissionGate::default()),
            true,
        )
        .unwrap();
        let receipt = actions.prepare(binding()).unwrap();
        assert_eq!(actions.commit(receipt, &binding()).await, Ok(Commit::New));
        assert!(actions.shutdown.is_requested());
        actions.admission.open();
        assert!(actions.admission.is_closed());
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            actions.shutdown.requested(),
        )
        .await
        .unwrap();
        assert_eq!(
            actions.commit(receipt, &binding()).await,
            Ok(Commit::AlreadyCommitted)
        );
    }
    #[tokio::test]
    async fn commit_uses_exclusive_gate_and_cannot_preempt_a_replacement_lease() {
        let actions = Actions::with_identity(
            binding().identity,
            std::sync::Arc::new(tokio::sync::RwLock::new(())),
            std::sync::Arc::new(crate::update::AdmissionGate::default()),
            true,
        )
        .unwrap();
        let receipt = actions.prepare(binding()).unwrap();
        let read = actions.control_gate.read().await;
        let request = binding();
        let committing = actions.commit(receipt, &request);
        tokio::pin!(committing);
        tokio::select! {biased;result=&mut committing=>panic!("commit passed a held read gate: {result:?}"),_ = tokio::task::yield_now()=>{}}
        assert!(!actions.shutdown.is_requested());
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        drop(read);
        assert_eq!(committing.await, Err(Rejected::Replacing));
        assert!(!actions.shutdown.is_requested());
        actions.administrative_shutdown();
        assert!(actions.shutdown.is_requested());
        assert!(!actions.state.lock().unwrap().finish_replacement(lease));
        actions.admission.open();
        assert!(actions.admission.is_closed());
    }

    #[test]
    fn exec_retry_wait_releases_state_and_shutdown_revokes_next_syscall() {
        let actions = Actions::new(
            None,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(crate::update::AdmissionGate::default()),
            false,
        );
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        let guard = ExecAttemptGuard::new(&actions, lease);
        let mut calls = 0;
        let mut waits = 0;
        let result = crate::handover::exec_guarded_with_retries(
            &guard,
            || {
                calls += 1;
                nix::errno::Errno::ETXTBSY
            },
            3,
            || {
                waits += 1;
                assert!(actions.state.try_lock().is_ok());
                actions.administrative_shutdown();
            },
        );
        assert_eq!(result, ExecFailure::Revoked);
        assert_eq!(calls, 1);
        assert_eq!(waits, 1);
    }
    #[test]
    fn exec_retry_cannot_use_a_new_lease_and_other_errno_never_retries() {
        let actions = Actions::new(
            None,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(crate::update::AdmissionGate::default()),
            false,
        );
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        let guard = ExecAttemptGuard::new(&actions, lease);
        let mut calls = 0;
        let result = crate::handover::exec_guarded_with_retries(
            &guard,
            || {
                calls += 1;
                nix::errno::Errno::ETXTBSY
            },
            3,
            || {
                let mut state = actions.state.lock().unwrap();
                assert!(state.finish_replacement(lease));
                let _new = state.begin_replacement().unwrap();
            },
        );
        assert_eq!(result, ExecFailure::Revoked);
        assert_eq!(calls, 1);
        assert!(!actions.state.lock().unwrap().finish_replacement(lease));
        assert_eq!(
            guard.attempt(|| panic!("revoked syscall")),
            ExecFailure::Revoked
        );
        let mut state = actions.state.lock().unwrap();
        state.administrative_shutdown();
        drop(state);
        assert_eq!(
            guard.attempt(|| panic!("shutdown syscall")),
            ExecFailure::Revoked
        );
    }
    #[test]
    fn shutdown_cannot_pass_a_guarded_syscall() {
        let actions = Arc::new(Actions::new(
            None,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(crate::update::AdmissionGate::default()),
            false,
        ));
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let running = actions.clone();
        let syscall = std::thread::spawn(move || {
            ExecAttemptGuard::new(&running, lease).attempt(|| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                nix::errno::Errno::ENOENT
            })
        });
        entered_rx.recv().unwrap();
        assert!(actions.state.try_lock().is_err());
        let stopping = actions.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let shutdown = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            stopping.administrative_shutdown();
            done_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        resume_tx.send(()).unwrap();
        assert_eq!(
            syscall.join().unwrap(),
            ExecFailure::Os(nix::errno::Errno::ENOENT)
        );
        shutdown.join().unwrap();
        done_rx.recv().unwrap();
        assert_eq!(
            ExecAttemptGuard::new(&actions, lease).attempt(|| panic!("late syscall")),
            ExecFailure::Revoked
        );
    }

    #[test]
    fn ordinary_exec_retries_only_busy_with_the_original_lease() {
        let actions = Actions::new(
            None,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(crate::update::AdmissionGate::default()),
            false,
        );
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        let guard = ExecAttemptGuard::new(&actions, lease);
        for (errors, expected_waits) in [
            (
                vec![nix::errno::Errno::ETXTBSY, nix::errno::Errno::ENOENT],
                1,
            ),
            (vec![nix::errno::Errno::EPERM], 0),
            (vec![nix::errno::Errno::ETXTBSY; 3], 2),
        ] {
            let expected = *errors.last().unwrap();
            let expected_calls = errors.len();
            let mut errors = errors.into_iter();
            let mut calls = 0;
            let mut waits = 0;
            assert_eq!(
                crate::handover::exec_guarded_with_retries(
                    &guard,
                    || {
                        assert!(actions.state.try_lock().is_err());
                        calls += 1;
                        errors.next().unwrap()
                    },
                    3,
                    || {
                        assert!(actions.state.try_lock().is_ok());
                        waits += 1
                    }
                ),
                ExecFailure::Os(expected)
            );
            assert_eq!(calls, expected_calls);
            assert_eq!(waits, expected_waits);
        }
    }

    #[test]
    fn genuinely_poisoned_action_state_never_grants_exec_or_replacement() {
        let actions = Arc::new(Actions::new(
            None,
            Arc::new(tokio::sync::RwLock::new(())),
            Arc::new(crate::update::AdmissionGate::default()),
            false,
        ));
        let lease = actions.state.lock().unwrap().begin_replacement().unwrap();
        let other = actions.clone();
        assert!(std::thread::spawn(move || {
            let _state = other.state.lock().unwrap();
            panic!("owned state poison fixture");
        })
        .join()
        .is_err());
        assert_eq!(
            ExecAttemptGuard::new(&actions, lease)
                .attempt(|| panic!("poisoned authority must not exec")),
            ExecFailure::Revoked
        );
        actions.administrative_shutdown();
        assert!(actions.shutdown.is_requested());
        actions.admission.open();
        assert!(actions.admission.is_closed());
    }

    #[test]
    fn receipt_is_consumed_before_effect_and_replay_cannot_repeat_effect() {
        let mut book = book();
        let now = std::time::Instant::now();
        let request = binding();
        book.prepare(now, request.clone(), [3; 16]).unwrap();
        assert_eq!(book.commit(now, [3; 16], &request), Ok(Commit::New));
        assert!(book.shutdown_committed());
        assert_eq!(
            book.commit(now, [3; 16], &request),
            Ok(Commit::AlreadyCommitted)
        );
        assert_eq!(
            book.prepare(now, request, [4; 16]),
            Err(Rejected::ShutdownCommitted)
        );
    }
    #[test]
    fn attempt_candidate_and_entire_actual_identity_are_bound() {
        let now = std::time::Instant::now();
        for changed in 0..7 {
            let mut book = book();
            let request = binding();
            book.prepare(now, request.clone(), [3; 16]).unwrap();
            let mut mismatch = request.clone();
            match changed {
                0 => mismatch.attempt = BusyAttemptId::from_bytes([8; 16]),
                1 => mismatch.identity.generation = Some("aa".repeat(16)),
                2 => mismatch.identity.pid += 1,
                3 => mismatch.identity.build += 1,
                4 => mismatch.identity.checksum = "bb".repeat(32),
                5 => mismatch.candidate.build += 1,
                6 => mismatch.candidate.checksum = "cc".repeat(32),
                _ => unreachable!(),
            }
            assert_eq!(
                book.commit(now, [3; 16], &mismatch),
                Err(Rejected::Mismatch)
            );
            assert!(!book.shutdown_committed());
            assert_eq!(book.commit(now, [3; 16], &request), Ok(Commit::New));
        }
    }
    #[test]
    fn expiry_capacity_and_collision_never_expand_authority() {
        let mut book = book();
        let now = std::time::Instant::now();
        let request = binding();
        book.prepare(now, request.clone(), [1; 16]).unwrap();
        assert_eq!(
            book.prepare(now, request.clone(), [1; 16]),
            Err(Rejected::Collision)
        );
        for id in 2..=64 {
            book.prepare(now, request.clone(), [id; 16]).unwrap();
        }
        assert_eq!(
            book.prepare(now, request.clone(), [65; 16]),
            Err(Rejected::Capacity)
        );
        assert_eq!(
            book.commit(now + RECEIPT_TTL, [1; 16], &request),
            Err(Rejected::Expired)
        );
        book.prepare(now + RECEIPT_TTL, request, [66; 16]).unwrap();
        assert!(!book.shutdown_committed());
    }
    #[test]
    fn replacement_lease_and_shutdown_are_mutually_exclusive() {
        let now = std::time::Instant::now();
        let request = binding();
        let mut first = book();
        first.prepare(now, request.clone(), [1; 16]).unwrap();
        let lease = first.begin_replacement().unwrap();
        assert_eq!(
            first.commit(now, [1; 16], &request),
            Err(Rejected::Replacing)
        );
        assert_eq!(
            first.prepare(now, request.clone(), [2; 16]),
            Err(Rejected::Replacing)
        );
        assert!(first.finish_replacement(lease));
        let second_lease = first.begin_replacement().unwrap();
        assert!(!first.finish_replacement(lease));
        first.administrative_shutdown();
        assert!(!first.finish_replacement(second_lease));
        assert!(first.shutdown_committed());
        let mut second = book();
        second.prepare(now, request.clone(), [1; 16]).unwrap();
        second.commit(now, [1; 16], &request).unwrap();
        assert_eq!(second.begin_replacement(), Err(Rejected::ShutdownCommitted));
    }
    #[test]
    fn missing_generation_and_wrong_prepare_identity_refuse() {
        let mut identity = binding().identity;
        identity.generation = None;
        assert!(Coordinator::new(identity).is_err());
        let mut book = book();
        let mut request = binding();
        request.identity.pid += 1;
        assert_eq!(
            book.prepare(std::time::Instant::now(), request, [1; 16]),
            Err(Rejected::Mismatch)
        );
        assert!(!book.shutdown_committed());
    }
}
