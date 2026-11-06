//! SDK-checked Darwin operations and the personal PTY ownership adapter.
use super::*;
use portable_pty::Child;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};
use transport::channel_open::{CleanupAuthority, CleanupStatus};
use transport::channel_server::{ChannelWait, ChildStatus, LeaderStatus};

#[repr(C)]
#[derive(Default)]
struct Error {
    domain: i32,
    code: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WireIdentity {
    pid: i32,
    version: u32,
    unique: u64,
}
impl From<WireIdentity> for Identity {
    fn from(value: WireIdentity) -> Self {
        Self {
            pid: value.pid,
            unique: value.unique,
            version: value.version,
        }
    }
}
impl From<Identity> for WireIdentity {
    fn from(value: Identity) -> Self {
        Self {
            pid: value.pid,
            unique: value.unique,
            version: value.version,
        }
    }
}
#[repr(C)]
#[derive(Default)]
struct WireClass {
    identity: WireIdentity,
    sid: i32,
    zombie: u32,
}
#[repr(C)]
#[derive(Default)]
pub(super) struct Token {
    words: [u32; 8],
}
unsafe extern "C" {
    fn qsh_scope_modern_signal_available() -> i32;
    fn qsh_scope_prepare(runtime: *mut Runtime, error: *mut Error) -> i32;
    fn qsh_scope_keeper_pre_exec(slave: i32, session: i32, broker: i32) -> i32;
    fn qsh_scope_keeper_prepare(runtime: *mut Runtime, error: *mut Error) -> i32;
    fn qsh_scope_group(expected: WireIdentity, sid: i32, group: *mut i32, error: *mut Error)
        -> i32;
    fn qsh_scope_identity(pid: i32, identity: *mut WireIdentity, error: *mut Error) -> i32;
    #[cfg(test)]
    fn qsh_scope_classification_matches(before: WireClass, after: WireClass) -> i32;
    fn qsh_scope_classify(pid: i32, value: *mut WireClass, error: *mut Error) -> i32;
    fn qsh_scope_all(pids: *mut i32, slots: u32, bytes: *mut u32, error: *mut Error) -> i32;
    fn qsh_scope_bind(
        expected: WireIdentity,
        cookie: u64,
        fd: *mut i32,
        bound: *mut WireIdentity,
        error: *mut Error,
    ) -> i32;
    fn qsh_scope_exit(fd: i32, pid: i32, cookie: u64, exited: *mut u32, error: *mut Error) -> i32;
    fn qsh_scope_token(
        expected: WireIdentity,
        sid: i32,
        token: *mut Token,
        error: *mut Error,
    ) -> i32;
    fn qsh_scope_signal(token: *const Token, signal: i32, error: *mut Error) -> i32;
    fn qsh_scope_leader(pid: i32, exited: *mut u32, code: *mut i32, error: *mut Error) -> i32;
}
fn result(code: i32, error: Error) -> Result<(), Failure> {
    if code == 0 {
        return Ok(());
    }
    Err(match error.domain {
        1 if error.code != 0 => Failure::Errno(error.code),
        2 => Failure::Mach(error.code),
        _ => Failure::Invalid,
    })
}
#[derive(Debug)]
pub(crate) enum AdmissionError {
    Native(Failure),
    UnsupportedContract,
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(error) => write!(f, "Darwin process ownership unavailable: {error:?}"),
            Self::UnsupportedContract => write!(
                f,
                "this Darwin runtime has no qualified process ownership contract"
            ),
        }
    }
}
#[repr(C)]
struct Runtime {
    release: [std::ffi::c_char; 64],
    version: [std::ffi::c_char; 512],
    build: [std::ffi::c_char; 64],
    machine: [std::ffi::c_char; 32],
}
fn runtime_text(value: &[std::ffi::c_char]) -> Result<&str, AdmissionError> {
    let bytes = unsafe { std::slice::from_raw_parts(value.as_ptr().cast::<u8>(), value.len()) };
    std::ffi::CStr::from_bytes_until_nul(bytes)
        .map_err(|_| AdmissionError::Native(Failure::Invalid))?
        .to_str()
        .map_err(|_| AdmissionError::Native(Failure::Invalid))
}
pub(super) fn modern_signal_available() -> bool {
    unsafe { qsh_scope_modern_signal_available() != 0 }
}
pub(crate) fn prepare() -> Result<QualifiedDarwin, AdmissionError> {
    let mut error = Error::default();
    let mut runtime = Runtime {
        release: [0; 64],
        version: [0; 512],
        build: [0; 64],
        machine: [0; 32],
    };
    let code = unsafe { qsh_scope_prepare(&mut runtime, &mut error) };
    result(code, error).map_err(AdmissionError::Native)?;
    let contract = runtime_contract(
        runtime_text(&runtime.release)?,
        runtime_text(&runtime.version)?,
        runtime_text(&runtime.build)?,
        runtime_text(&runtime.machine)?,
        std::env::consts::ARCH,
    )
    .ok_or(AdmissionError::UnsupportedContract)?;
    #[cfg(test)]
    eprintln!("{}", contract.receipt());
    Ok(QualifiedDarwin {
        contract: contract.family.id,
    })
}
pub(super) struct Watch {
    fd: OwnedFd,
    identity: Identity,
    cookie: u64,
}
#[cfg(test)]
impl Watch {
    pub(super) fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}
pub(super) struct NativeOps;
pub(super) struct PtyChild {
    child: Box<dyn Child + Send + Sync>,
    pid: Option<i32>,
}
impl NativeOps {
    pub(super) fn identity(&mut self, pid: i32) -> Result<Identity, Failure> {
        let mut value = WireIdentity::default();
        let mut error = Error::default();
        let code = unsafe { qsh_scope_identity(pid, &mut value, &mut error) };
        result(code, error)?;
        let value: Identity = value.into();
        if !value.valid() {
            return Err(Failure::Invalid);
        }
        Ok(value)
    }
}
impl Ops<PtyChild> for NativeOps {
    type Watch = Watch;
    type Token = Token;
    fn baseline(&mut self) -> Result<Vec<Classified>, Failure> {
        let mut pids = [0; CAPACITY];
        let bytes = self.raw_all(&mut pids)?;
        if bytes == 0 || !bytes.is_multiple_of(size_of::<i32>()) || bytes > size_of_val(&pids) {
            return Err(Failure::Invalid);
        }
        let raw = &pids[..bytes / size_of::<i32>()];
        let mut values = Vec::new();
        values
            .try_reserve(raw.len())
            .map_err(|_| Failure::Capacity)?;
        for (index, pid) in raw.iter().copied().enumerate() {
            if pid < 0 || raw[..index].contains(&pid) {
                return Err(Failure::Invalid);
            }
            if pid == 0 {
                continue;
            }
            // Missing pre-classification cannot contribute P or certify a later
            // positive returned PID; the scope requires its exact pre/post pair.
            if let Ok(value) = self.classify(pid) {
                values.push(value);
            }
        }
        Ok(values)
    }
    fn raw_all(&mut self, pids: &mut [i32; CAPACITY]) -> Result<usize, Failure> {
        let mut bytes = 0;
        let mut error = Error::default();
        let code =
            unsafe { qsh_scope_all(pids.as_mut_ptr(), CAPACITY as u32, &mut bytes, &mut error) };
        result(code, error)?;
        Ok(bytes as usize)
    }
    fn confirm(&mut self, identity: Identity) -> Result<Identity, Failure> {
        self.identity(identity.pid)
    }
    fn classify(&mut self, pid: i32) -> Result<Classified, Failure> {
        let mut value = WireClass::default();
        let mut error = Error::default();
        let code = unsafe { qsh_scope_classify(pid, &mut value, &mut error) };
        result(code, error)?;
        let identity: Identity = value.identity.into();
        if !identity.valid() || identity.pid != pid || value.zombie > 1 {
            return Err(Failure::Invalid);
        }
        let class = if value.zombie == 1 {
            Class::Zombie
        } else if value.sid > 0 {
            Class::Session(value.sid)
        } else {
            return Err(Failure::Invalid);
        };
        Ok(Classified { identity, class })
    }
    fn bind_exit(
        &mut self,
        process: Classified,
        cookie: u64,
    ) -> Result<Registration<Watch>, Failure> {
        let mut fd = -1;
        let mut bound = WireIdentity::default();
        let mut error = Error::default();
        let code = unsafe {
            qsh_scope_bind(
                process.identity.into(),
                cookie,
                &mut fd,
                &mut bound,
                &mut error,
            )
        };
        result(code, error)?;
        if fd < 0 {
            return Err(Failure::Invalid);
        }
        let watch = Watch {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            identity: bound.into(),
            cookie,
        };
        if !watch.identity.same_process(process.identity) {
            return Err(Failure::Invalid);
        }
        Ok(Registration {
            identity: watch.identity,
            cookie,
            handle: watch,
        })
    }
    fn observe_exit(&mut self, watch: &mut Watch) -> Result<Option<ExitEvent>, Failure> {
        let mut exited = 0;
        let mut error = Error::default();
        let code = unsafe {
            qsh_scope_exit(
                watch.fd.as_raw_fd(),
                watch.identity.pid,
                watch.cookie,
                &mut exited,
                &mut error,
            )
        };
        result(code, error)?;
        match exited {
            0 => Ok(None),
            1 => Ok(Some(ExitEvent {
                pid: watch.identity.pid,
                cookie: watch.cookie,
                process_filter: true,
                note_exit: true,
                error: false,
            })),
            _ => Err(Failure::Invalid),
        }
    }
    fn acquire_signal_token(
        &mut self,
        identity: Identity,
        sid: i32,
    ) -> Result<SignalToken<Token>, Failure> {
        let mut token = Token::default();
        let mut error = Error::default();
        let code = unsafe { qsh_scope_token(identity.into(), sid, &mut token, &mut error) };
        result(code, error)?;
        if token.words[5] != identity.pid as u32 || token.words[7] != identity.version {
            return Err(Failure::Invalid);
        }
        Ok(SignalToken {
            identity,
            sid,
            handle: token,
        })
    }
    fn signal_exact(&mut self, token: &Token, signal: Signal) -> Result<(), Failure> {
        let signal = match signal {
            Signal::Hup => nix::libc::SIGHUP,
            Signal::Kill => nix::libc::SIGKILL,
        };
        let mut error = Error::default();
        let code = unsafe { qsh_scope_signal(token, signal, &mut error) };
        result(code, error)
    }
    fn observe_leader(&mut self, child: &mut PtyChild) -> Result<Option<i32>, Failure> {
        let pid = child.pid.ok_or(Failure::Leader)?;
        let mut error = Error::default();
        let mut exited = 0;
        let mut code = 0;
        let rc = unsafe { qsh_scope_leader(pid, &mut exited, &mut code, &mut error) };
        result(rc, error)?;
        match exited {
            0 => Ok(None),
            1 => Ok(Some(code)),
            _ => Err(Failure::Invalid),
        }
    }
    fn reap_leader(&mut self, child: &mut PtyChild) -> Result<i32, Failure> {
        loop {
            match child.child.wait() {
                Ok(status) => return Ok(status.exit_code() as i32),
                Err(error) if error.raw_os_error() == Some(nix::libc::EINTR) => continue,
                Err(error) => {
                    return Err(Failure::Errno(
                        error.raw_os_error().unwrap_or(nix::libc::EIO),
                    ));
                }
            }
        }
    }
}
#[cfg(test)]
#[derive(Debug)]
pub(super) struct NativeReceipt {
    pub evidence: Option<(u64, usize, usize)>,
    pub retained: (usize, usize),
    pub progress: &'static str,
}
#[cfg(test)]
thread_local! { static RECEIPT: std::cell::RefCell<Option<NativeReceipt>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
pub(super) fn take_receipt() -> Option<NativeReceipt> {
    RECEIPT.with(|value| value.borrow_mut().take())
}
const HUP_GRACE: Duration = Duration::from_secs(1);
const OBSERVE_INTERVAL: Duration = Duration::from_millis(20);
struct NativeWait {
    scope: scope::Scope<PtyChild, Watch>,
    stop_started: Option<Instant>,
}
pub(super) fn owned_scope(
    child: Box<dyn Child + Send + Sync>,
    qualified: QualifiedDarwin,
) -> scope::Scope<PtyChild, Watch> {
    let pid = child
        .process_id()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|pid| *pid > 0);
    let mut ops = NativeOps;
    let initial = pid.map_or(Err(Failure::Leader), |pid| ops.classify(pid));
    // portable-pty completed setsid/exec and returned this original exclusive child.
    // Its unreaped lifetime reserves PID/SID even if the initial exec bracket fails.
    scope::Scope::post_handshake(PtyChild { child, pid }, pid, initial, qualified)
}
pub(crate) fn own_child(
    child: Box<dyn Child + Send + Sync>,
    qualified: QualifiedDarwin,
) -> Box<dyn ChannelWait> {
    Box::new(NativeWait {
        scope: owned_scope(child, qualified),
        stop_started: None,
    })
}
impl NativeWait {
    fn start_grace(&mut self) {
        self.stop_started.get_or_insert_with(Instant::now);
    }
    fn progress(&mut self) -> ChildStatus {
        if self
            .stop_started
            .is_some_and(|started| started.elapsed() >= HUP_GRACE)
        {
            self.scope.escalate();
        }
        let progress = self.scope.step(&mut NativeOps);
        #[cfg(test)]
        RECEIPT.with(|value| {
            *value.borrow_mut() = Some(NativeReceipt {
                evidence: self.scope.census(),
                retained: self.scope.retained(),
                progress: match progress {
                    scope::Progress::Pending | scope::Progress::Incomplete => "pending",
                    scope::Progress::Unknown => "unknown",
                    scope::Progress::Complete(_) => "reaped",
                },
            })
        });
        scope::cleanup_status(progress)
    }
}
impl ChannelWait for NativeWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let observed = self.scope.poll_leader(&mut NativeOps);
        if matches!(observed, Ok(Some(_))) {
            self.start_grace();
        }
        Some(scope::leader_status(observed))
    }
    fn poll_exit(&mut self) -> ChildStatus {
        if matches!(self.poll_leader_status(), Some(LeaderStatus::Unknown(_))) {
            return ChildStatus::Unknown("Darwin leader custody is unconfirmed".into());
        }
        self.progress()
    }
    fn kill(&mut self) {
        self.scope.request_stop();
        self.start_grace();
    }
    fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
        self.kill();
        loop {
            match self.poll_exit() {
                ChildStatus::Reaped { .. } => return authority.reaped(),
                ChildStatus::Unknown(_) => return CleanupStatus::Unknown,
                ChildStatus::Running | ChildStatus::WaitingForWorkers => {
                    std::thread::sleep(OBSERVE_INTERVAL)
                }
            }
        }
    }
    fn wait(mut self: Box<Self>) -> i32 {
        loop {
            if let ChildStatus::Reaped { code: Some(code) } = self.poll_exit() {
                return code;
            }
            std::thread::sleep(OBSERVE_INTERVAL);
        }
    }
}

#[cfg(test)]
pub(super) fn classification_matches_for_test(before: Classified, after: Classified) -> bool {
    fn wire(value: Classified) -> WireClass {
        WireClass {
            identity: value.identity.into(),
            sid: match value.class {
                Class::Session(sid) => sid,
                Class::Zombie => 0,
            },
            zombie: u32::from(value.class == Class::Zombie),
        }
    }
    unsafe { qsh_scope_classification_matches(wire(before), wire(after)) == 1 }
}

/// A distinct admission type: it cannot be passed to the modern exact-signal owner.
pub(crate) struct KeeperAdmission {
    pub(super) contract: &'static str,
}
pub(super) fn keeper_prepare() -> Result<KeeperAdmission, AdmissionError> {
    let mut error = Error::default();
    let mut runtime = Runtime {
        release: [0; 64],
        version: [0; 512],
        build: [0; 64],
        machine: [0; 32],
    };
    result(
        unsafe { qsh_scope_keeper_prepare(&mut runtime, &mut error) },
        error,
    )
    .map_err(AdmissionError::Native)?;
    // This first non-default checkpoint uses the already reviewed source families.
    // Older-family admission is a separate gate, not inferred from API presence.
    let contract = runtime_contract(
        runtime_text(&runtime.release)?,
        runtime_text(&runtime.version)?,
        runtime_text(&runtime.build)?,
        runtime_text(&runtime.machine)?,
        std::env::consts::ARCH,
    )
    .ok_or(AdmissionError::UnsupportedContract)?;
    Ok(KeeperAdmission {
        contract: contract.family.id,
    })
}
impl NativeOps {
    pub(super) fn keeper_group(&mut self, identity: Identity, sid: i32) -> Result<i32, Failure> {
        let mut group = 0;
        let mut error = Error::default();
        result(
            unsafe { qsh_scope_group(identity.into(), sid, &mut group, &mut error) },
            error,
        )?;
        if group <= 0 {
            return Err(Failure::Invalid);
        }
        Ok(group)
    }
    /// Same before/raw/after closure premise as the modern scope. A temporary
    /// refusal never supplies an empty successful session view.
    pub(super) fn keeper_census(&mut self, sid: i32) -> Result<Vec<Classified>, Failure> {
        Ok(self
            .keeper_full_census()?
            .into_iter()
            .filter(|p| p.class == Class::Session(sid))
            .collect())
    }
    /// Preserve the entire successful census for sticky application debt.
    /// Only this unfiltered view may positively exclude a previously observed PID.
    pub(super) fn keeper_full_census(&mut self) -> Result<Vec<Classified>, Failure> {
        let baseline = <Self as Ops<PtyChild>>::baseline(self)?;
        let mut pids = [0; CAPACITY];
        let bytes = <Self as Ops<PtyChild>>::raw_all(self, &mut pids)?;
        if bytes == 0 || !bytes.is_multiple_of(size_of::<i32>()) || bytes > size_of_val(&pids) {
            return Err(Failure::Invalid);
        }
        let raw = &pids[..bytes / size_of::<i32>()];
        if raw
            .iter()
            .enumerate()
            .any(|(i, pid)| *pid < 0 || raw[..i].contains(pid))
        {
            return Err(Failure::Invalid);
        }
        let persistent = baseline
            .iter()
            .filter(|before| {
                self.identity(before.identity.pid)
                    .is_ok_and(|after| after.same_process(before.identity))
            })
            .count();
        if raw.len() >= CAPACITY
            || !persistent
                .checked_add(20)
                .is_some_and(|minimum| raw.len() < minimum)
        {
            return Err(Failure::Capacity);
        }
        let mut classified = Vec::new();
        for pid in raw.iter().copied().filter(|pid| *pid > 0) {
            let after = <Self as Ops<PtyChild>>::classify(self, pid)?;
            if !baseline.iter().any(|before| {
                before.identity.same_process(after.identity)
                    && before.identity.version == after.identity.version
                    && before.class == after.class
            }) {
                return Err(Failure::Invalid);
            }
            classified.push(after);
        }
        Ok(classified)
    }
    pub(super) fn keeper_child_status(&mut self, pid: i32) -> Result<Option<i32>, Failure> {
        let mut error = Error::default();
        let mut exited = 0;
        let mut code = 0;
        result(
            unsafe { qsh_scope_leader(pid, &mut exited, &mut code, &mut error) },
            error,
        )?;
        match exited {
            0 => Ok(None),
            1 => Ok(Some(code)),
            _ => Err(Failure::Invalid),
        }
    }
}

/// Safety: only Command's post-fork child may call this with the three distinct
/// preopened descriptors kept alive by the parent throughout spawn.
pub(super) unsafe fn keeper_pre_exec(slave: i32, session: i32, broker: i32) -> std::io::Result<()> {
    if unsafe { qsh_scope_keeper_pre_exec(slave, session, broker) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn keeper_image_path() -> Result<std::path::PathBuf, Failure> {
    use std::os::unix::ffi::OsStrExt;
    let mut bytes = [0u8; nix::libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    nix::errno::Errno::clear();
    let returned = unsafe {
        nix::libc::proc_pidpath(
            nix::libc::getpid(),
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
        )
    };
    let error = nix::errno::Errno::last_raw();
    if returned == 0 {
        return Err(Failure::Errno(if error == 0 {
            nix::libc::EIO
        } else {
            error
        }));
    }
    let size = usize::try_from(returned)
        .ok()
        .filter(|n| *n < bytes.len())
        .ok_or(Failure::Invalid)?;
    if size == 0 || bytes[size] != 0 || bytes[..size].contains(&0) || bytes[0] != b'/' {
        return Err(Failure::Invalid);
    }
    Ok(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &bytes[..size],
    )))
}
