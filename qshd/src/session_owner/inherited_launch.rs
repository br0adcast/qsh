//! Dormant personal inherited admission. No ordinary daemon creates this owner.
use super::local_channel::{
    self, launch, AdmissionBudget, AdmissionError, AdmittedChannel, ExpectedAdmission,
    TrustedChannelConfig,
};
use launch::{LocalFd, PreparedFrontendEnd, RemoteEndObligation};
use nix::libc;
use record::LaunchDeadline;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) mod child;
#[cfg(test)]
mod native_tests;
pub(super) mod record;
#[cfg(test)]
mod tests;
pub(super) const MARKER: &str = "__qshd-frontend-admission-v1";
/// Constructible only after this capsule observes both physical receipts.
pub(in crate::session_owner) struct Settlement {
    _private: SettlementBasis,
}
enum SettlementBasis {
    SetupEofWithTerminalChild,
    NeverExportedLocalCloses,
}
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
enum ExportDisposition {
    LocalOnly,
    InFlight,
    Owned,
    ExecRefused,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchProgress {
    Preparing,
    Admitted,
    Closing,
    Settled,
    Unknown,
}
struct Control {
    logical: AtomicU8, // 0 preparing, 1 admitted observation, 2 irrevocably cancelled
}
impl Control {
    fn cancel(&self) {
        self.logical.store(2, Ordering::Release);
    }
}
pub(crate) struct LaunchHandle {
    control: Arc<Control>,
}
impl LaunchHandle {
    pub(crate) fn request_cancel(&self) {
        self.control.cancel();
    }
}
impl Drop for LaunchHandle {
    fn drop(&mut self) {
        self.request_cancel();
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitState {
    NotCreated,
    Pending,
    Terminal,
    Unknown,
}
struct Capsule {
    control: Arc<Control>,
    deadline: LaunchDeadline,
    progress: LaunchProgress,
    started: bool,
    export: ExportDisposition,
    setup_allocated: bool,
    host: Option<ExpectedAdmission>,
    admitted: Option<AdmittedChannel>,
    frontend: Option<PreparedFrontendEnd>,
    setup: Option<LocalFd>,
    setup_child: Option<LocalFd>,
    duplicates: [Option<LocalFd>; 2],
    remote: Option<RemoteEndObligation>,
    record: [u8; record::RECORD_LEN],
    child: Option<Child>,
    status: Option<ExitStatus>,
    #[cfg(test)]
    output: Option<std::process::ChildStdout>,
    #[cfg(test)]
    errors: Option<std::process::ChildStderr>,
    wait: WaitState,
    eof: bool,
    unknown: bool,
    kill_attempted: bool,
    write_shutdown: bool,
    quarantine: Option<Arc<Mutex<Capsule>>>,
    #[cfg(test)]
    modeled_child: bool,
    #[cfg(test)]
    interrupt_setup_read: bool,
    #[cfg(test)]
    setup_read_fault: Option<io::Error>,
    #[cfg(test)]
    first_unknown: Option<observation::Event>,
    #[cfg(test)]
    first_rejection: Option<observation::Rejection>,
}
impl Capsule {
    fn cancelled(&self) -> bool {
        self.control.logical.load(Ordering::Acquire) == 2
    }
    fn close_child_copies(&mut self) {
        self.duplicates = [None, None];
        self.frontend = None;
        self.setup_child = None;
    }
    fn retire(&mut self) {
        self.control.cancel();
        if self.progress == LaunchProgress::Settled {
            return;
        }
        self.progress = if self.unknown {
            LaunchProgress::Unknown
        } else {
            LaunchProgress::Closing
        };
        // Logical retirement precedes all fallible physical operations.
        self.admitted = None;
        self.host = None;
        if self.export == ExportDisposition::LocalOnly
            && self.wait == WaitState::NotCreated
            && self.child.is_none()
        {
            // No descriptor ever left this retained local capsule. Full known
            // local closes are stronger than waiting for an inapplicable peer EOF.
            self.close_child_copies();
            self.setup = None;
            return;
        }
        if self.wait == WaitState::NotCreated {
            self.close_child_copies();
        }
        if !self.write_shutdown {
            self.write_shutdown = true;
            if let Some(setup) = self.setup.as_ref() {
                if let Ok(fd) = setup.fd() {
                    if unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR) } != 0 {
                        #[cfg(test)]
                        {
                            let errno = io::Error::last_os_error().raw_os_error();
                            self.observe_unknown(observation::Origin::SetupShutdown, errno);
                        }
                        self.unknown = true;
                    }
                }
            }
        }
    }
    fn kill_owned(&mut self) {
        if !self.unknown && self.wait == WaitState::Pending && !self.kill_attempted {
            if let Some(child) = self.child.as_mut() {
                self.kill_attempted = true;
                // Success/ESRCH never supplies wait. Unknown prohibits signaling.
                let _ = child.kill();
            }
        }
    }
    fn publish(&mut self) -> bool {
        if self.cancelled() || Instant::now() >= self.deadline.local() || self.unknown {
            self.retire();
            false
        } else if self
            .control
            .logical
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.progress = LaunchProgress::Admitted;
            true
        } else {
            self.retire();
            false
        }
    }
    fn poll(&mut self) -> LaunchProgress {
        self.poll_at(Instant::now())
    }
    fn poll_at(&mut self, now: Instant) -> LaunchProgress {
        if self.progress == LaunchProgress::Settled {
            return self.progress;
        }
        if self.cancelled() || now >= self.deadline.local() {
            self.retire();
        }
        if now >= self.deadline.local() {
            self.kill_owned();
        }
        // One read and one exact owned-child observation, in either receipt order.
        if !self.eof {
            if let Some(setup) = self.setup.as_ref() {
                if let Ok(fd) = setup.fd() {
                    let mut byte = [0; 1];
                    #[cfg(test)]
                    let result = if std::mem::take(&mut self.interrupt_setup_read) {
                        Err(io::Error::from(io::ErrorKind::Interrupted))
                    } else if let Some(error) = self.setup_read_fault.take() {
                        Err(error)
                    } else {
                        launch::read(fd, &mut byte)
                    };
                    #[cfg(not(test))]
                    let result = launch::read(fd, &mut byte);
                    match result {
                        Ok(0) => {
                            self.eof = true;
                            self.retire();
                        }
                        Ok(_) => {
                            #[cfg(test)]
                            self.observe_unknown(observation::Origin::SetupUnexpectedData, None);
                            self.unknown = true;
                            self.retire();
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                            // Communication rejection does not lose the retained Child/FD.
                            // It supplies neither EOF nor wait; physical settlement stays gated.
                            #[cfg(test)]
                            self.first_rejection.get_or_insert(observation::Rejection {
                                errno: error.raw_os_error(),
                            });
                            self.retire();
                        }
                        Err(_error) => {
                            #[cfg(test)]
                            self.observe_unknown(
                                observation::Origin::SetupRead,
                                _error.raw_os_error(),
                            );
                            self.unknown = true;
                            self.retire();
                        }
                    }
                }
            }
        }
        if self.wait == WaitState::Pending {
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.status = Some(status);
                        self.wait = WaitState::Terminal;
                        self.retire();
                    }
                    Ok(None) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_error) => {
                        #[cfg(test)]
                        self.observe_unknown(observation::Origin::ChildWait, _error.raw_os_error());
                        self.wait = WaitState::Unknown;
                        self.unknown = true;
                        self.retire();
                    }
                }
            }
        }
        // LocalOnly is minted before any possible exec and never restored after
        // a spawn attempt. All local closes must still be confirmed by the
        // remote ledger. Missing setup alone is never an EOF/settlement receipt.
        // Local provenance cannot retire a still-active preparation.
        let retired_without_export = self.cancelled()
            && self.export == ExportDisposition::LocalOnly
            && self.wait == WaitState::NotCreated
            && self.child.is_none();
        if !self.unknown
            && (self.eof || retired_without_export)
            && matches!(self.wait, WaitState::Terminal | WaitState::NotCreated)
        {
            self.setup = None;
            self.close_child_copies();
            let status = self
                .remote
                .as_mut()
                .map(|remote| {
                    remote.settle(Settlement {
                        _private: if retired_without_export {
                            SettlementBasis::NeverExportedLocalCloses
                        } else {
                            SettlementBasis::SetupEofWithTerminalChild
                        },
                    })
                })
                .unwrap_or(launch::SettlementStatus::Settled);
            match status {
                launch::SettlementStatus::Settled => {
                    self.remote = None;
                    self.child = None;
                    self.progress = LaunchProgress::Settled;
                    return self.progress;
                }
                launch::SettlementStatus::Pending => {}
                launch::SettlementStatus::Unknown => {
                    #[cfg(test)]
                    self.observe_unknown(observation::Origin::RemoteSettlement, None);
                    self.unknown = true;
                }
            }
        }
        if self.unknown || self.wait == WaitState::Unknown {
            self.progress = LaunchProgress::Unknown;
        }
        if self.progress == LaunchProgress::Admitted && self.cancelled() {
            self.retire();
        }
        self.progress
    }
}

pub(crate) struct FrontendLaunches {
    limit: usize,
    budget: AdmissionBudget,
    slots: Vec<Arc<Mutex<Capsule>>>,
    #[cfg(test)]
    program: Option<TestProgram>,
    #[cfg(test)]
    prefix_bytes: Option<usize>,
    #[cfg(test)]
    fail_after_spawn: bool,
    #[cfg(test)]
    setup_pair_failure: bool,
    #[cfg(test)]
    setup_failure_after_allocation: bool,
    #[cfg(test)]
    uncertain_preparation_close: bool,
}
impl FrontendLaunches {
    pub(crate) fn new(limit: usize) -> Result<Self, AdmissionError> {
        if limit == 0 || limit.checked_mul(8).is_none() {
            return Err(AdmissionError::InvalidConfig);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| AdmissionError::Capacity)?;
        Ok(Self {
            limit,
            budget: AdmissionBudget::new(limit)?,
            slots,
            #[cfg(test)]
            program: None,
            #[cfg(test)]
            prefix_bytes: None,
            #[cfg(test)]
            fail_after_spawn: false,
            #[cfg(test)]
            setup_pair_failure: false,
            #[cfg(test)]
            setup_failure_after_allocation: false,
            #[cfg(test)]
            uncertain_preparation_close: false,
        })
    }
    fn find(&self, handle: &LaunchHandle) -> Option<Arc<Mutex<Capsule>>> {
        self.slots
            .iter()
            .find(|slot| {
                slot.lock()
                    .map(|capsule| Arc::ptr_eq(&capsule.control, &handle.control))
                    .unwrap_or(false)
            })
            .cloned()
    }
    pub(crate) fn in_use(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| {
                slot.lock()
                    .map(|c| c.progress != LaunchProgress::Settled)
                    .unwrap_or(true)
            })
            .count()
    }
    pub(crate) fn prepare(
        &mut self,
        config: TrustedChannelConfig,
        deadline: Instant,
    ) -> Result<LaunchHandle, AdmissionError> {
        launch::validate_config(config)?;
        let deadline = LaunchDeadline::new(deadline)?;
        self.slots.retain(|slot| {
            slot.lock()
                .map(|c| c.progress != LaunchProgress::Settled)
                .unwrap_or(true)
        });
        if self.slots.len() >= self.limit {
            return Err(AdmissionError::Capacity);
        }
        let control = Arc::new(Control {
            logical: AtomicU8::new(0),
        });
        let capsule = Arc::new(Mutex::new(Capsule {
            control: Arc::clone(&control),
            deadline,
            progress: LaunchProgress::Preparing,
            started: false,
            export: ExportDisposition::LocalOnly,
            setup_allocated: false,
            host: None,
            admitted: None,
            frontend: None,
            setup: None,
            setup_child: None,
            duplicates: [None, None],
            remote: None,
            record: [0; record::RECORD_LEN],
            child: None,
            status: None,
            #[cfg(test)]
            output: None,
            #[cfg(test)]
            errors: None,
            wait: WaitState::NotCreated,
            eof: false,
            unknown: false,
            kill_attempted: false,
            write_shutdown: false,
            quarantine: None,
            #[cfg(test)]
            modeled_child: false,
            #[cfg(test)]
            interrupt_setup_read: false,
            #[cfg(test)]
            setup_read_fault: None,
            #[cfg(test)]
            first_unknown: None,
            #[cfg(test)]
            first_rejection: None,
        }));
        // Retain the physical capsule before any socketpair or duplicate allocation.
        self.slots.push(Arc::clone(&capsule));
        let mut c = capsule.lock().map_err(|_| AdmissionError::Unavailable)?;
        let result = (|| {
            let (frontend, host) = local_channel::provision_pair(config, &self.budget)?;
            c.host = Some(host);
            let (frontend, remote) = launch::split_frontend(frontend)?;
            c.remote = Some(remote);
            c.record = frontend.setup(c.deadline.absolute()).encode();
            c.frontend = Some(frontend);
            #[cfg(test)]
            if self.setup_pair_failure {
                if self.uncertain_preparation_close {
                    c.frontend.as_mut().unwrap().fd.test_uncertain_close();
                }
                return Err(AdmissionError::Unavailable);
            }
            let (parent, child) = std::os::unix::net::UnixStream::pair()?;
            c.setup_allocated = true;
            // Track both new descriptors before any subsequent fallible operation.
            let remote = c.remote.as_ref().ok_or(AdmissionError::Refused)?;
            c.setup = Some(remote.track(parent.into()));
            c.setup_child = Some(c.remote.as_ref().unwrap().track(child.into()));
            launch::validate_personal_fd(c.setup.as_ref().unwrap().fd()?, unsafe {
                libc::geteuid()
            })?;
            launch::validate_personal_fd(c.setup_child.as_ref().unwrap().fd()?, unsafe {
                libc::geteuid()
            })?;
            #[cfg(test)]
            if self.setup_failure_after_allocation {
                c.interrupt_setup_read = true;
                if self.uncertain_preparation_close {
                    c.frontend.as_mut().unwrap().fd.test_uncertain_close();
                }
                return Err(AdmissionError::Unavailable);
            }
            c.duplicates[0] = Some(c.setup_child.as_ref().unwrap().duplicate()?);
            c.duplicates[1] = Some(c.frontend.as_ref().unwrap().fd.duplicate()?);
            Ok(())
        })();
        if let Err(error) = result {
            c.retire();
            c.poll();
            return Err(error);
        }
        Ok(LaunchHandle { control })
    }
    pub(crate) fn start(&mut self, handle: &LaunchHandle) -> Result<(), AdmissionError> {
        let capsule = self.find(handle).ok_or(AdmissionError::Refused)?;
        let mut c = capsule.lock().map_err(|_| AdmissionError::Unavailable)?;
        if c.started || c.cancelled() || c.progress != LaunchProgress::Preparing {
            c.retire();
            c.poll();
            return Err(AdmissionError::Refused);
        }
        c.started = true;
        let result = (|| {
            c.frontend
                .as_ref()
                .ok_or(AdmissionError::Refused)?
                .for_spawn()?;
            qualify_sigchld()?;
            if Instant::now() >= c.deadline.local() {
                return Err(AdmissionError::Deadline);
            }
            let executable = std::env::current_exe()?;
            #[cfg(test)]
            let executable = self
                .program
                .as_ref()
                .map(|p| p.executable.clone())
                .unwrap_or(executable);
            let setup = c.duplicates[0]
                .as_ref()
                .ok_or(AdmissionError::Refused)?
                .fd()?
                .as_raw_fd();
            let admission = c.duplicates[1]
                .as_ref()
                .ok_or(AdmissionError::Refused)?
                .fd()?
                .as_raw_fd();
            if setup <= 4 || admission <= 4 || setup == admission {
                return Err(AdmissionError::Refused);
            }
            let mut command = Command::new(executable);
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .env_remove(crate::service_stage::LAUNCH_ENV)
                .env_remove(crate::handover::HANDOVER_FD_ENV);
            #[cfg(test)]
            if let Some(program) = self.program.as_ref() {
                command
                    .args(&program.args)
                    .envs(program.environment.iter().map(|(key, value)| (key, value)));
                if program.body {
                    command.stdout(Stdio::piped()).stderr(Stdio::piped());
                }
            } else {
                command.arg(MARKER);
            }
            #[cfg(not(test))]
            command.arg(MARKER);
            // Parent-owned source duplicates remain CLOEXEC, so only 3/4 survive exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(setup, 3) < 0 || libc::dup2(admission, 4) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            c.export = ExportDisposition::InFlight;
            c.wait = WaitState::Unknown;
            let spawned = command.spawn();
            drop(command);
            match spawned {
                Ok(child) => {
                    c.child = Some(child);
                    c.export = ExportDisposition::Owned;
                    #[cfg(test)]
                    {
                        let child = c.child.as_mut().unwrap();
                        let output = child.stdout.take();
                        let errors = child.stderr.take();
                        c.output = output;
                        c.errors = errors;
                    }
                    c.wait = WaitState::Pending;
                }
                // Rust's exec-error path waits its child before returning Err.
                Err(error) => {
                    c.export = ExportDisposition::ExecRefused;
                    c.wait = WaitState::NotCreated;
                    c.close_child_copies();
                    return Err(error.into());
                }
            }
            c.close_child_copies();
            #[cfg(test)]
            if self.fail_after_spawn {
                return Err(AdmissionError::Unavailable);
            }
            if c.cancelled() {
                return Err(AdmissionError::Refused);
            }
            #[cfg(test)]
            if let Some(n) = self.prefix_bytes {
                launch::write_prefix(
                    c.setup.as_ref().unwrap().fd()?,
                    &c.record[..n],
                    c.deadline.local(),
                )?;
            } else {
                launch::write_setup(
                    c.setup.as_ref().ok_or(AdmissionError::Refused)?.fd()?,
                    &c.record,
                    c.deadline.local(),
                )?;
            }
            #[cfg(not(test))]
            launch::write_setup(
                c.setup.as_ref().ok_or(AdmissionError::Refused)?.fd()?,
                &c.record,
                c.deadline.local(),
            )?;
            let expected = c.host.take().ok_or(AdmissionError::Refused)?;
            let admitted = local_channel::admit_channel(expected, c.deadline.local())?;
            c.admitted = Some(admitted);
            if record::monotonic_now()? >= c.deadline.absolute() || !c.publish() {
                return Err(AdmissionError::Deadline);
            }
            Ok(())
        })();
        if result.is_err() {
            c.retire();
            c.poll();
        }
        result
    }
    pub(crate) fn cancel(&mut self, handle: &LaunchHandle) {
        if let Some(capsule) = self.find(handle) {
            if let Ok(mut c) = capsule.lock() {
                c.retire();
            }
        }
    }
    pub(crate) fn poll(&mut self, handle: &LaunchHandle) -> LaunchProgress {
        let Some(capsule) = self.find(handle) else {
            return LaunchProgress::Unknown;
        };
        let Ok(mut c) = capsule.lock() else {
            return LaunchProgress::Unknown;
        };
        c.poll()
    }
}
impl Drop for FrontendLaunches {
    fn drop(&mut self) {
        for capsule in &self.slots {
            // Poison also retains the exact physical capsule through its self-reference.
            let mut c = match capsule.lock() {
                Ok(c) => c,
                Err(poison) => {
                    let mut c = poison.into_inner();
                    #[cfg(test)]
                    c.observe_unknown(observation::Origin::DropPoison, None);
                    c.unknown = true;
                    if c.wait == WaitState::Pending {
                        c.wait = WaitState::Unknown;
                    }
                    c
                }
            };
            c.retire();
            c.kill_owned();
            if c.poll() != LaunchProgress::Settled {
                c.quarantine = Some(Arc::clone(capsule));
            }
        }
    }
}
fn qualify_sigchld() -> Result<(), AdmissionError> {
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0
        || disposition.sa_sigaction != libc::SIG_DFL
        || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(AdmissionError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
struct TestProgram {
    executable: std::path::PathBuf,
    args: Vec<std::ffi::OsString>,
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    body: bool,
}

#[cfg(test)]
impl FrontendLaunches {
    fn test_expire(&mut self, h: &LaunchHandle) {
        let capsule = self.find(h).unwrap();
        let mut c = capsule.lock().unwrap();
        let deadline = c.deadline.local();
        c.poll_at(deadline);
    }
    fn test_started(&mut self, h: &LaunchHandle) {
        let c = self.find(h).unwrap();
        let mut c = c.lock().unwrap();
        c.started = true;
        c.export = ExportDisposition::Owned;
        c.wait = WaitState::Pending;
        c.modeled_child = true;
    }
    fn test_publish(&mut self, h: &LaunchHandle) -> bool {
        self.find(h).unwrap().lock().unwrap().publish()
    }
    fn test_wait(&mut self, h: &LaunchHandle, lost: bool) {
        let c = self.find(h).unwrap();
        let mut c = c.lock().unwrap();
        assert!(c.modeled_child && c.child.is_none());
        if lost {
            c.observe_unknown(observation::Origin::ModeledLostWait, None);
        }
        c.wait = if lost {
            WaitState::Unknown
        } else {
            WaitState::Terminal
        };
        c.unknown |= lost;
    }
    fn test_eof(&mut self, h: &LaunchHandle) {
        let c = self.find(h).unwrap();
        let mut c = c.lock().unwrap();
        assert!(c.modeled_child && c.child.is_none());
        c.close_child_copies();
    }
    fn test_uncertain_close(&mut self, h: &LaunchHandle) {
        self.find(h)
            .unwrap()
            .lock()
            .unwrap()
            .remote
            .as_mut()
            .unwrap()
            .test_uncertain();
    }
    fn test_weak(&self, h: &LaunchHandle) -> std::sync::Weak<Mutex<Capsule>> {
        Arc::downgrade(&self.find(h).unwrap())
    }
    fn test_finish_dropped(&mut self) {
        for c in &self.slots {
            let mut c = c.lock().unwrap();
            assert!(c.modeled_child && c.child.is_none());
            c.retire();
            c.close_child_copies();
            c.wait = WaitState::Terminal;
            c.poll();
        }
    }
    fn test_quarantine_is_settled(w: &std::sync::Weak<Mutex<Capsule>>) -> bool {
        w.upgrade().unwrap().lock().unwrap().progress == LaunchProgress::Settled
    }
    fn test_release_quarantine(w: &std::sync::Weak<Mutex<Capsule>>) {
        let c = w.upgrade().unwrap();
        let mut c = c.lock().unwrap();
        assert!(c.child.is_none());
        c.close_child_copies();
        c.wait = WaitState::Terminal;
        c.poll();
        c.quarantine = None;
    }
}

#[cfg(test)]
impl Capsule {
    fn observation(&self) -> observation::Snapshot {
        let mut snapshot = self.observation_scalars();
        if let Some(remote) = self.remote.as_ref() {
            snapshot.debt = Some(remote.test_observation());
            snapshot.debt_sample = observation::DebtSample::Captured;
        }
        snapshot
    }
    fn observation_scalars(&self) -> observation::Snapshot {
        observation::Snapshot {
            export: self.export,
            wait: self.wait,
            status: observation::Status::capture(self.status.as_ref()),
            eof: self.eof,
            cancelled: self.cancelled(),
            started: self.started,
            kill_attempted: self.kill_attempted,
            write_shutdown: self.write_shutdown,
            presence: [
                self.child.is_some(),
                self.host.is_some(),
                self.admitted.is_some(),
                self.frontend.is_some(),
                self.setup.is_some(),
                self.setup_child.is_some(),
                self.duplicates[0].is_some(),
                self.duplicates[1].is_some(),
                self.remote.is_some(),
            ],
            // The standalone registry observer holds one added capsule guard:
            // it deliberately takes no debt lock and never reuses first debt.
            debt_sample: if self.remote.is_some() {
                observation::DebtSample::NotObserved
            } else {
                observation::DebtSample::NoRemote
            },
            debt: None,
        }
    }
    fn observe_unknown(&mut self, origin: observation::Origin, errno: Option<i32>) {
        if self.first_unknown.is_none() {
            let snapshot = self.observation();
            observation::record(
                &mut self.first_unknown,
                observation::Event {
                    origin,
                    errno,
                    snapshot,
                },
            );
        }
    }
}
#[cfg(test)]
impl FrontendLaunches {
    fn observation(&self, handle: &LaunchHandle) -> observation::Report {
        use observation::{Origin, Report};
        let mut unavailable = None;
        for capsule in &self.slots {
            match capsule.try_lock() {
                Ok(c) if Arc::ptr_eq(&c.control, &handle.control) => {
                    return Report {
                        unavailable: None,
                        first: c.first_unknown,
                        rejection: c.first_rejection,
                        current: Some(c.observation_scalars()),
                    }
                }
                Ok(_) => {}
                Err(std::sync::TryLockError::WouldBlock) => unavailable = Some(Origin::CapsuleBusy),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    unavailable = Some(Origin::CapsulePoisoned)
                }
            }
        }
        Report {
            unavailable: Some(unavailable.unwrap_or(Origin::RegistryMissing)),
            first: None,
            rejection: None,
            current: None,
        }
    }
}

// This entire observer is absent from the daemon and has no cleanup authority.
#[cfg(test)]
mod observation {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Origin {
        SetupShutdown,
        SetupUnexpectedData,
        SetupRead,
        ChildWait,
        RemoteSettlement,
        ModeledLostWait,
        RegistryMissing,
        CapsulePoisoned,
        CapsuleBusy,
        DropPoison,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Status {
        pub present: bool,
        pub code: Option<i32>,
        pub signal: Option<i32>,
    }
    impl Status {
        pub fn capture(status: Option<&ExitStatus>) -> Self {
            Self {
                present: status.is_some(),
                code: status.and_then(ExitStatus::code),
                signal: status.and_then(ExitStatusExt::signal),
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum DebtSample {
        Captured,
        NotObserved,
        NoRemote,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Snapshot {
        pub export: ExportDisposition,
        pub wait: WaitState,
        pub status: Status,
        pub eof: bool,
        pub cancelled: bool,
        pub started: bool,
        pub kill_attempted: bool,
        pub write_shutdown: bool,
        // Fixed schema order: child, host, admitted, frontend, setup,
        // setup_child, duplicate0, duplicate1, remote. No fd/id extraction.
        pub presence: [bool; 9],
        pub debt_sample: DebtSample,
        pub debt: Option<launch::DebtObservation>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Event {
        pub origin: Origin,
        pub errno: Option<i32>,
        pub snapshot: Snapshot,
    }
    pub(super) fn record(first: &mut Option<Event>, event: Event) {
        first.get_or_insert(event);
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Subcase {
        Other,
        RecordMagic,
        RecordHostZero,
        RecordChannelZero,
        RecordChallengeZero,
        RecordUid,
        RecordFrontendRole,
        RecordHostRole,
        RecordMinVersion,
        RecordMaxVersion,
        RecordReservedPrefix,
        RecordDeadlineZero,
        RecordTailVersion,
        RecordReservedTail,
        SetupRegular,
        SetupListener,
        SetupAlias,
        ExtraSetupBytes,
        DirectMissingFds,
        DirectExtraArgs,
    }
    impl Subcase {
        pub fn label(self) -> &'static str {
            match self {
                Self::Other => "other",
                Self::RecordMagic => "record_magic",
                Self::RecordHostZero => "record_host_zero",
                Self::RecordChannelZero => "record_channel_zero",
                Self::RecordChallengeZero => "record_challenge_zero",
                Self::RecordUid => "record_uid",
                Self::RecordFrontendRole => "record_frontend_role",
                Self::RecordHostRole => "record_host_role",
                Self::RecordMinVersion => "record_min_version",
                Self::RecordMaxVersion => "record_max_version",
                Self::RecordReservedPrefix => "record_reserved_prefix",
                Self::RecordDeadlineZero => "record_deadline_zero",
                Self::RecordTailVersion => "record_tail_version",
                Self::RecordReservedTail => "record_reserved_tail",
                Self::SetupRegular => "setup_regular",
                Self::SetupListener => "setup_listener",
                Self::SetupAlias => "setup_alias",
                Self::ExtraSetupBytes => "extra_setup_bytes",
                Self::DirectMissingFds => "direct_missing_fds",
                Self::DirectExtraArgs => "direct_extra_args",
            }
        }
    }
    // A rejected read is diagnostic data, never physical custody evidence.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Rejection {
        pub errno: Option<i32>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Report {
        pub unavailable: Option<Origin>,
        pub first: Option<Event>,
        pub rejection: Option<Rejection>,
        pub current: Option<Snapshot>,
    }
    pub(super) fn render(case: Subcase, report: &Report) -> String {
        render_capped(case, report, 2048)
    }
    pub(super) fn render_capped(case: Subcase, report: &Report, cap: usize) -> String {
        // Only closed enums, optional bounded integers and booleans are rendered.
        let rendered = format!(
            "launch529_diag_v1 subcase={} first={:?} rejection={:?} current={:?} unavailable={:?}",
            case.label(),
            report.first,
            report.rejection,
            report.current,
            report.unavailable
        );
        if rendered.len() <= cap.min(2048) {
            rendered
        } else {
            "launch529_diag_v1 unavailable".into()
        }
    }
}
