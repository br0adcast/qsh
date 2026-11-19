//! Dormant admission of locally provisioned socketpairs, not endpoint publication.
//! Kernel credentials describe socket creation/connection identity, not a later
//! credential change, executable identity, PID authority, or target-account login.
use super::authorization::FrontendAdmission;
use super::authorization::{fresh_bytes, AuthorityError, HostMode};
use super::host::{HostError, HostState};
use super::host_auth_contract::AuthMethod;
use super::host_protocol::{self, HostFrame, HostHeader, HostMessage};
use super::local_admission_contract::{AdmissionSpec, LocalAdmission};
use super::protocol::{self, OwnerFrame, OwnerHeader, OwnerMessage, OwnerRole};
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use transport::session_resume::{HostInstance, OwnerInstance};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    InvalidConfig,
    Capacity,
    Unavailable,
    Refused,
    Deadline,
}
impl From<io::Error> for AdmissionError {
    fn from(_: io::Error) -> Self {
        Self::Unavailable
    }
}

/// Invocation-owned test evidence; none of these scalars carries admission authority.
#[cfg(test)]
pub(super) mod prepare_observation {
    use super::AdmissionError;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum Site {
        ProvisionFrontend,
        ProvisionHost,
        SplitFrontend,
        SetupParent,
        SetupChild,
        OtherPreparation,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum Check {
        GetsocknameCall,
        UnixFamily,
        SocketTypeCall,
        SocketTypeLength,
        StreamType,
        AcceptConnCall,
        AcceptConnLength,
        NotListening,
        PeerAddressCall,
        PeerUidCall,
        AllowedPeer,
        NonblockingCall,
        PersonalCurrentIdentity,
        PersonalPeerUidCall,
        ExactPersonalPeer,
        TransferRole,
        MissingDescriptor,
        MissingObservation,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum Class {
        Syscall,
        Io,
        Length,
        Predicate,
        SyntheticSyscall,
        SyntheticPredicate,
        MissingObservation,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) struct Event {
        pub site: Site,
        pub check: Check,
        pub class: Class,
        pub errno: Option<i32>,
    }
    #[derive(Clone, Copy)]
    pub(in crate::session_owner) enum FaultKind {
        Syscall,
        Predicate,
    }
    #[derive(Clone, Copy)]
    pub(in crate::session_owner) enum AcceptFault {
        Errno(i32),
        Length,
        Listening,
    }
    #[derive(Default)]
    pub(in crate::session_owner) struct SocketProbe {
        pub accept_fault: Option<AcceptFault>,
        pub peer_error: Option<i32>,
        pub accept_calls: usize,
        pub peer_calls: usize,
        pub uid_calls: usize,
    }
    #[derive(Default)]
    pub(in crate::session_owner) struct Observer {
        pub first: Option<Event>,
        pub fault: Option<(Site, FaultKind)>,
        pub suppressed: bool,
        pub(in crate::session_owner) socket_probe: SocketProbe,
    }
    impl Observer {
        pub fn begin(&mut self) {
            self.first = None;
        }
        pub fn end(&mut self) {
            self.fault = None;
        }
        pub fn record(&mut self, event: Event) {
            if !self.suppressed {
                self.first.get_or_insert(event);
            }
        }
        pub fn render(&self, error: AdmissionError) -> String {
            let event = self.first.unwrap_or(Event {
                site: Site::OtherPreparation,
                check: Check::MissingObservation,
                class: Class::MissingObservation,
                errno: None,
            });
            let line = format!(
                "launch529_prepare_v1 site={:?} check={:?} class={:?} errno={:?} error={error:?}",
                event.site, event.check, event.class, event.errno
            );
            if line.len() <= 1024 {
                line
            } else {
                "launch529_prepare_v1 detail=Unavailable".into()
            }
        }
    }
    pub(in crate::session_owner) fn record(
        observer: Option<&mut Observer>,
        site: Site,
        check: Check,
        class: Class,
        errno: Option<i32>,
    ) {
        if let Some(observer) = observer {
            observer.record(Event {
                site,
                check,
                class,
                errno,
            });
        }
    }
    pub(in crate::session_owner) fn failed(
        observer: Option<&mut Observer>,
        site: Site,
        check: Check,
        class: Class,
        errno: Option<i32>,
        actual_failed: bool,
    ) -> bool {
        let Some(observer) = observer else {
            return actual_failed;
        };
        if actual_failed {
            observer.record(Event {
                site,
                check,
                class,
                errno,
            });
            return true;
        }
        let injected = match observer.fault {
            Some((wanted, FaultKind::Syscall))
                if wanted == site && check == Check::GetsocknameCall =>
            {
                Some((Class::SyntheticSyscall, Some(123)))
            }
            Some((wanted, FaultKind::Predicate))
                if wanted == site && check == Check::UnixFamily =>
            {
                Some((Class::SyntheticPredicate, None))
            }
            _ => None,
        };
        if let Some((class, errno)) = injected {
            observer.fault = None;
            observer.record(Event {
                site,
                check,
                class,
                errno,
            });
            return true;
        }
        false
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct TrustedChannelConfig {
    pub host: HostInstance,
    pub owner: Option<OwnerInstance>,
    pub requester: OwnerRole,
    pub mode: HostMode,
    pub system_uid: u32,
    pub min_version: u16,
    pub max_version: u16,
}
#[derive(Debug)]
struct BudgetState {
    limit: usize,
    used: usize,
    uncertain_ends: usize,
}
#[derive(Debug)]
pub(crate) struct AdmissionBudget {
    state: Arc<Mutex<BudgetState>>,
}
impl AdmissionBudget {
    pub(crate) fn new(limit: usize) -> Result<Self, AdmissionError> {
        if limit == 0 || limit.checked_mul(2).is_none() {
            return Err(AdmissionError::InvalidConfig);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(BudgetState {
                limit,
                used: 0,
                uncertain_ends: 0,
            })),
        })
    }
    pub(crate) fn in_use(&self) -> usize {
        self.state.lock().map(|s| s.used).unwrap_or(usize::MAX)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndState {
    Live,
    Closed,
    Uncertain,
}
#[derive(Debug)]
struct PairCharge {
    budget: Arc<Mutex<BudgetState>>,
    ends: Mutex<[EndState; 2]>,
}
impl PairCharge {
    fn terminal(&self, index: usize, confirmed: bool) {
        // Poison or uncertainty conservatively retains capacity; neither grants retry authority.
        let Ok(mut ends) = self.ends.lock() else {
            return;
        };
        if ends[index] != EndState::Live {
            return;
        }
        ends[index] = if confirmed {
            EndState::Closed
        } else {
            EndState::Uncertain
        };
        if let Ok(mut state) = self.budget.lock() {
            if !confirmed {
                state.uncertain_ends += 1;
            }
            if *ends == [EndState::Closed; 2] {
                state.used -= 1;
            }
        }
    }
}
fn close_once(fd: RawFd) -> bool {
    unsafe { nix::libc::close(fd) == 0 }
}
#[derive(Debug)]
struct Custody {
    fd: Option<OwnedFd>,
    pair: Arc<PairCharge>,
    index: usize,
    closer: fn(RawFd) -> bool,
}
impl Drop for Custody {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            // Invalidate numeric ownership before exactly one close, including EINTR.
            let raw = fd.into_raw_fd();
            let confirmed = (self.closer)(raw);
            self.pair.terminal(self.index, confirmed);
        }
    }
}
#[derive(Debug)]
pub(crate) struct ExpectedAdmission {
    custody: Custody,
    config: TrustedChannelConfig,
    local: OwnerRole,
    peer: OwnerRole,
    channel: [u8; 16],
    challenge: [u8; 32],
}
#[derive(Debug)]
pub(crate) struct AdmittedChannel {
    custody: Custody,
    config: TrustedChannelConfig,
    local: OwnerRole,
    peer: OwnerRole,
    evidence: bool,
    host_state: Option<host_protocol::HostPeerState>,
}
/// One nonclone handoff keeps the exact channel, its completed correlation,
/// and the actual host registration together. Correlation is not proof of
/// target-account authentication. No runtime constructs this dormant component.
/// Drop closes only channel custody; callers must explicitly retire the host
/// registration. EOF/cancel retirement belongs to the future dispatcher.
#[derive(Debug)]
pub(crate) struct HostDispatchChannel {
    channel: AdmittedChannel,
    state: host_protocol::HostPeerState,
    frontend: FrontendAdmission,
}
impl HostDispatchChannel {
    pub(crate) fn frontend(&self) -> FrontendAdmission {
        self.frontend
    }
    pub(crate) fn receive_at(
        &mut self,
        frame: &HostFrame,
        now: u64,
    ) -> Result<(), protocol::OwnerProtocolError> {
        self.state.receive_at(frame, now)
    }
    pub(crate) fn send_at(
        &mut self,
        frame: &HostFrame,
        now: u64,
    ) -> Result<(), protocol::OwnerProtocolError> {
        self.state.send_at(frame, now)
    }
    /// One nonblocking operation; the future dispatcher owns deadlines/queues.
    pub(crate) fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let socket = stream(
            self.channel
                .custody
                .fd
                .as_ref()
                .ok_or_else(|| io::Error::other("closed channel"))?,
        );
        (&*socket).read(bytes)
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let socket = stream(
            self.channel
                .custody
                .fd
                .as_ref()
                .ok_or_else(|| io::Error::other("closed channel"))?,
        );
        (&*socket).write(bytes)
    }
    pub(super) fn retire_local_ticket(&mut self, ticket: super::host_auth_contract::AuthReference) {
        self.state.retire_local_ticket(ticket);
    }
    pub(crate) fn retire(self, host: &mut HostState) -> Result<(), HostError> {
        host.retire_frontend(self.frontend)
    }
}
impl AdmittedChannel {
    /// Borrow exact frontend custody for one nonblocking operation.
    fn frontend_socket(
        &self,
        host: HostInstance,
        mode: HostMode,
    ) -> io::Result<ManuallyDrop<UnixStream>> {
        if self.local != OwnerRole::Frontend
            || self.peer != OwnerRole::Host
            || self.config.owner.is_some()
            || self.config.host != host
            || self.config.mode != mode
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "frontend channel identity mismatch",
            ));
        }
        Ok(stream(
            self.custody
                .fd
                .as_ref()
                .ok_or_else(|| io::Error::other("closed channel"))?,
        ))
    }
    pub(crate) fn frontend_read(
        &mut self,
        host: HostInstance,
        mode: HostMode,
        bytes: &mut [u8],
    ) -> io::Result<usize> {
        (&*self.frontend_socket(host, mode)?).read(bytes)
    }
    pub(crate) fn frontend_write(
        &mut self,
        host: HostInstance,
        mode: HostMode,
        bytes: &[u8],
    ) -> io::Result<usize> {
        (&*self.frontend_socket(host, mode)?).write(bytes)
    }
    /// Consume exact admitted custody, rather than pairing a freely supplied
    /// generation or detached correlation state with another descriptor.
    pub(crate) fn into_host_dispatch(
        mut self,
        host: &mut HostState,
        mode: HostMode,
        limit: usize,
    ) -> Result<HostDispatchChannel, HostError> {
        if !(1..=protocol::MAX_OWNER_REQUESTS).contains(&limit) {
            return Err(AuthorityError::InvalidLimits.into());
        }
        let mut state = self.host_state.take().ok_or(AuthorityError::Refused)?;
        let peer = super::authorization::local_peer::authenticate_frontend(&mut self, mode)?;
        let frontend = host.admit_frontend(peer)?;
        let method = match mode {
            HostMode::Personal { .. } => AuthMethod::Personal,
            HostMode::System => AuthMethod::System,
        };
        if state
            .bind_local_authentication(frontend.generation(), method, limit)
            .is_err()
        {
            host.retire_frontend(frontend)?;
            return Err(AuthorityError::Refused.into());
        }
        Ok(HostDispatchChannel {
            channel: self,
            state,
            frontend,
        })
    }
    pub(super) fn take_frontend_evidence(
        &mut self,
        mode: HostMode,
    ) -> Result<(HostInstance, HostMode), AuthorityError> {
        let available = std::mem::replace(&mut self.evidence, false);
        if !available
            || self.local != OwnerRole::Host
            || self.peer != OwnerRole::Frontend
            || self.config.owner.is_some()
            || self.config.mode != mode
        {
            return Err(AuthorityError::Refused);
        }
        Ok((self.config.host, self.config.mode))
    }
}
pub(crate) fn provision_pair(
    config: TrustedChannelConfig,
    budget: &AdmissionBudget,
) -> Result<(ExpectedAdmission, ExpectedAdmission), AdmissionError> {
    provision_pair_impl(
        config,
        budget,
        #[cfg(test)]
        None,
    )
}
#[cfg(test)]
pub(super) fn provision_pair_observed(
    config: TrustedChannelConfig,
    budget: &AdmissionBudget,
    observer: &mut prepare_observation::Observer,
) -> Result<(ExpectedAdmission, ExpectedAdmission), AdmissionError> {
    provision_pair_impl(config, budget, Some(observer))
}
fn provision_pair_impl(
    config: TrustedChannelConfig,
    budget: &AdmissionBudget,
    #[cfg(test)] mut observer: Option<&mut prepare_observation::Observer>,
) -> Result<(ExpectedAdmission, ExpectedAdmission), AdmissionError> {
    let responder = match (config.owner, config.requester) {
        (None, OwnerRole::Frontend) | (Some(_), OwnerRole::Owner) => OwnerRole::Host,
        (Some(_), OwnerRole::Frontend) => OwnerRole::Owner,
        _ => return Err(AdmissionError::InvalidConfig),
    };
    if config.min_version == 0 || config.min_version > 1 || config.max_version < 1 {
        return Err(AdmissionError::InvalidConfig);
    }
    let channel = fresh_bytes().map_err(|_| AdmissionError::Unavailable)?;
    let challenge = fresh_bytes().map_err(|_| AdmissionError::Unavailable)?;
    {
        let mut state = budget
            .state
            .lock()
            .map_err(|_| AdmissionError::Unavailable)?;
        let next = state.used.checked_add(1).ok_or(AdmissionError::Capacity)?;
        if next > state.limit {
            return Err(AdmissionError::Capacity);
        }
        state.used = next;
    }
    let pair = Arc::new(PairCharge {
        budget: Arc::clone(&budget.state),
        ends: Mutex::new([EndState::Live; 2]),
    });
    let (a, b) = match UnixStream::pair() {
        Ok(v) => v,
        Err(e) => {
            pair.terminal(0, true);
            pair.terminal(1, true);
            return Err(e.into());
        }
    };
    let end = |fd: OwnedFd, index, local, peer| ExpectedAdmission {
        custody: Custody {
            fd: Some(fd),
            pair: Arc::clone(&pair),
            index,
            closer: close_once,
        },
        config,
        local,
        peer,
        channel,
        challenge,
    };
    let a = end(a.into(), 0, config.requester, responder);
    let b = end(b.into(), 1, responder, config.requester);
    // Both kernel credential observations precede any admission bytes.
    validate_socket_impl(
        a.custody.fd.as_ref().unwrap(),
        config,
        #[cfg(test)]
        prepare_observation::Site::ProvisionFrontend,
        #[cfg(test)]
        observer.as_deref_mut(),
    )?;
    validate_socket_impl(
        b.custody.fd.as_ref().unwrap(),
        config,
        #[cfg(test)]
        prepare_observation::Site::ProvisionHost,
        #[cfg(test)]
        observer,
    )?;
    Ok((a, b))
}
// This borrowing facade never owns the number or closes it. Custody is sole owner.
fn stream(fd: &OwnedFd) -> ManuallyDrop<UnixStream> {
    ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(fd.as_raw_fd()) })
}
fn validate_socket(fd: &OwnedFd, config: TrustedChannelConfig) -> Result<(), AdmissionError> {
    validate_socket_impl(
        fd,
        config,
        #[cfg(test)]
        prepare_observation::Site::OtherPreparation,
        #[cfg(test)]
        None,
    )
}
fn socket_option(
    fd: &OwnedFd,
    name: i32,
    #[cfg(test)] site: prepare_observation::Site,
    #[cfg(test)] observer: Option<&mut prepare_observation::Observer>,
) -> Result<i32, AdmissionError> {
    let mut value = 0i32;
    let mut size = std::mem::size_of_val(&value) as nix::libc::socklen_t;
    #[cfg(test)]
    let mut observer = observer;
    #[cfg(test)]
    let injected = if name == nix::libc::SO_ACCEPTCONN {
        observer.as_deref_mut().and_then(|observer| {
            observer.socket_probe.accept_calls += 1;
            observer.socket_probe.accept_fault
        })
    } else {
        None
    };
    let get_option = |value: &mut i32, size: &mut nix::libc::socklen_t| unsafe {
        nix::libc::getsockopt(
            fd.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            name,
            (value as *mut i32).cast(),
            size,
        )
    };
    #[cfg(not(test))]
    let result = get_option(&mut value, &mut size);
    #[cfg(test)]
    let result = match injected {
        Some(prepare_observation::AcceptFault::Errno(_)) => -1,
        Some(prepare_observation::AcceptFault::Length) => {
            size = 0;
            0
        }
        Some(prepare_observation::AcceptFault::Listening) => {
            value = 1;
            0
        }
        None => get_option(&mut value, &mut size),
    };
    if result != 0 {
        #[cfg(test)]
        {
            let (class, errno) = match injected {
                Some(prepare_observation::AcceptFault::Errno(errno)) => {
                    (prepare_observation::Class::SyntheticSyscall, Some(errno))
                }
                _ => (
                    prepare_observation::Class::Syscall,
                    io::Error::last_os_error().raw_os_error(),
                ),
            };
            prepare_observation::record(
                observer,
                site,
                if name == nix::libc::SO_TYPE {
                    prepare_observation::Check::SocketTypeCall
                } else {
                    prepare_observation::Check::AcceptConnCall
                },
                class,
                errno,
            );
        }
        return Err(AdmissionError::Refused);
    }
    if size as usize != std::mem::size_of_val(&value) {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            if name == nix::libc::SO_TYPE {
                prepare_observation::Check::SocketTypeLength
            } else {
                prepare_observation::Check::AcceptConnLength
            },
            if injected.is_some() {
                prepare_observation::Class::SyntheticPredicate
            } else {
                prepare_observation::Class::Length
            },
            None,
        );
        return Err(AdmissionError::Refused);
    }
    Ok(value)
}
enum ConnectedProof {
    AcceptOption,
    PeerAddress,
}
const CONNECTED_PROOF: ConnectedProof = if cfg!(target_os = "macos") {
    ConnectedProof::PeerAddress
} else {
    ConnectedProof::AcceptOption
};
fn validate_socket_impl(
    fd: &OwnedFd,
    config: TrustedChannelConfig,
    #[cfg(test)] site: prepare_observation::Site,
    #[cfg(test)] observer: Option<&mut prepare_observation::Observer>,
) -> Result<(), AdmissionError> {
    validate_socket_with_proof(
        fd,
        config,
        CONNECTED_PROOF,
        #[cfg(test)]
        site,
        #[cfg(test)]
        observer,
    )
}
fn validate_socket_with_proof(
    fd: &OwnedFd,
    config: TrustedChannelConfig,
    proof: ConnectedProof,
    #[cfg(test)] site: prepare_observation::Site,
    #[cfg(test)] mut observer: Option<&mut prepare_observation::Observer>,
) -> Result<(), AdmissionError> {
    use nix::libc;
    let raw = fd.as_raw_fd();
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let failed = unsafe {
        libc::getsockname(
            raw,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } != 0;
    #[cfg(test)]
    let failed = prepare_observation::failed(
        observer.as_deref_mut(),
        site,
        prepare_observation::Check::GetsocknameCall,
        prepare_observation::Class::Syscall,
        if failed {
            io::Error::last_os_error().raw_os_error()
        } else {
            None
        },
        failed,
    );
    if failed {
        return Err(AdmissionError::Refused);
    }
    let failed = addr.ss_family as i32 != libc::AF_UNIX;
    #[cfg(test)]
    let failed = prepare_observation::failed(
        observer.as_deref_mut(),
        site,
        prepare_observation::Check::UnixFamily,
        prepare_observation::Class::Predicate,
        None,
        failed,
    );
    if failed {
        return Err(AdmissionError::Refused);
    }
    if socket_option(
        fd,
        libc::SO_TYPE,
        #[cfg(test)]
        site,
        #[cfg(test)]
        observer.as_deref_mut(),
    )? != libc::SOCK_STREAM
    {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            prepare_observation::Check::StreamType,
            prepare_observation::Class::Predicate,
            None,
        );
        return Err(AdmissionError::Refused);
    }
    // macOS proves connected/non-listening through mandatory getpeername below.
    // XNU solisten rejects connected sockets; soconnectlock rejects listeners:
    // https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_socket.c
    if matches!(proof, ConnectedProof::AcceptOption)
        && socket_option(
            fd,
            libc::SO_ACCEPTCONN,
            #[cfg(test)]
            site,
            #[cfg(test)]
            observer.as_deref_mut(),
        )? != 0
    {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            prepare_observation::Check::NotListening,
            prepare_observation::Class::Predicate,
            None,
        );
        return Err(AdmissionError::Refused);
    }
    let socket = stream(fd);
    let peer = socket.peer_addr();
    #[cfg(test)]
    let peer = if let Some(value) = observer.as_deref_mut() {
        value.socket_probe.peer_calls += 1;
        match value.socket_probe.peer_error {
            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
            None => peer,
        }
    } else {
        peer
    };
    #[cfg(test)]
    let peer_class = if observer
        .as_ref()
        .is_some_and(|value| value.socket_probe.peer_error.is_some())
    {
        prepare_observation::Class::SyntheticSyscall
    } else {
        prepare_observation::Class::Io
    };
    if let Err(error) = peer {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            prepare_observation::Check::PeerAddressCall,
            peer_class,
            error.raw_os_error(),
        );
        drop(error);
        return Err(AdmissionError::Refused);
    }
    #[cfg(test)]
    if let Some(value) = observer.as_deref_mut() {
        value.socket_probe.uid_calls += 1;
    }
    let uid = match crate::control::peer_uid(fd) {
        Ok(uid) => uid,
        Err(error) => {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                site,
                prepare_observation::Check::PeerUidCall,
                prepare_observation::Class::Io,
                error.raw_os_error(),
            );
            drop(error);
            return Err(AdmissionError::Refused);
        }
    };
    let allowed = match config.mode {
        HostMode::Personal { canonical_uid } => uid == canonical_uid || uid == 0,
        HostMode::System => uid == config.system_uid,
    };
    if !allowed {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            prepare_observation::Check::AllowedPeer,
            prepare_observation::Class::Predicate,
            None,
        );
        return Err(AdmissionError::Refused);
    }
    if let Err(error) = socket.set_nonblocking(true) {
        #[cfg(test)]
        prepare_observation::record(
            observer,
            site,
            prepare_observation::Check::NonblockingCall,
            prepare_observation::Class::Io,
            error.raw_os_error(),
        );
        return Err(error.into());
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn validate_socket_observed(
    fd: &OwnedFd,
    config: TrustedChannelConfig,
    site: prepare_observation::Site,
    observer: &mut prepare_observation::Observer,
) -> Result<(), AdmissionError> {
    validate_socket_impl(fd, config, site, Some(observer))
}
fn before(deadline: Instant) -> Result<(), AdmissionError> {
    if Instant::now() >= deadline {
        Err(AdmissionError::Deadline)
    } else {
        Ok(())
    }
}
fn wait(fd: RawFd, write: bool, deadline: Instant) -> Result<(), AdmissionError> {
    loop {
        before(deadline)?;
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = left.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
        let mut poll = nix::libc::pollfd {
            fd,
            events: if write {
                nix::libc::POLLOUT
            } else {
                nix::libc::POLLIN
            },
            revents: 0,
        };
        let result = unsafe { nix::libc::poll(&mut poll, 1, ms) };
        before(deadline)?;
        if result > 0 {
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(AdmissionError::Unavailable);
        }
    }
}
fn transfer(
    fd: &OwnedFd,
    bytes: &mut [u8],
    write: bool,
    deadline: Instant,
) -> Result<(), AdmissionError> {
    let socket = stream(fd);
    let mut socket_ref = &*socket;
    let mut offset = 0;
    while offset < bytes.len() {
        before(deadline)?;
        let result = if write {
            socket_ref.write(&bytes[offset..])
        } else {
            socket_ref.read(&mut bytes[offset..])
        };
        match result {
            Ok(0) => return Err(AdmissionError::Refused),
            Ok(n) => offset += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(fd.as_raw_fd(), write, deadline)?
            }
            Err(_) => return Err(AdmissionError::Refused),
        }
    }
    before(deadline)
}
fn frame(
    expected: &ExpectedAdmission,
    role: OwnerRole,
    offer: bool,
) -> Result<Vec<u8>, AdmissionError> {
    let a = if offer {
        LocalAdmission::Offer {
            channel: expected.channel,
            challenge: expected.challenge,
            min_version: expected.config.min_version,
            max_version: expected.config.max_version,
        }
    } else {
        LocalAdmission::Ack {
            channel: expected.channel,
            challenge: expected.challenge,
            selected_version: 1,
        }
    };
    let result = if let Some(owner) = expected.config.owner {
        protocol::encode(&OwnerFrame {
            header: OwnerHeader {
                role,
                host: expected.config.host,
                owner,
                request_id: 1,
            },
            message: OwnerMessage::Admission(a),
        })
    } else {
        host_protocol::encode(&HostFrame {
            header: HostHeader {
                role,
                host: expected.config.host,
                request_id: 1,
            },
            message: HostMessage::Admission(a),
        })
    };
    result.map_err(|_| AdmissionError::Refused)
}
fn receive_exact(
    fd: &OwnedFd,
    expected: &[u8],
    owner: bool,
    deadline: Instant,
) -> Result<(), AdmissionError> {
    let header = if owner {
        protocol::OWNER_HEADER_LEN
    } else {
        host_protocol::HOST_HEADER_LEN
    };
    // Fixed admission-only storage. Compare the full header before reading a body:
    // wrong lengths, application kinds and oversize declarations allocate nothing.
    let mut bytes = [0u8; protocol::OWNER_HEADER_LEN + 52];
    transfer(fd, &mut bytes[..header], false, deadline)?;
    if bytes[..header] != expected[..header] {
        return Err(AdmissionError::Refused);
    }
    transfer(fd, &mut bytes[header..expected.len()], false, deadline)?;
    if bytes[..expected.len()] != *expected {
        return Err(AdmissionError::Refused);
    }
    Ok(())
}
pub(crate) fn admit_channel(
    expected: ExpectedAdmission,
    deadline: Instant,
) -> Result<AdmittedChannel, AdmissionError> {
    before(deadline)?;
    let fd = expected
        .custody
        .fd
        .as_ref()
        .ok_or(AdmissionError::Refused)?;
    validate_socket(fd, expected.config)?;
    before(deadline)?;
    let requester = expected.local == expected.config.requester;
    let mut outgoing = frame(&expected, expected.local, requester)?;
    let incoming = frame(&expected, expected.peer, !requester)?;
    let mut host_state = if expected.config.owner.is_none() {
        Some(
            host_protocol::HostPeerState::for_local_admission(
                expected.local,
                expected.peer,
                expected.config.host,
                AdmissionSpec {
                    host: expected.config.host,
                    owner: None,
                    requester: expected.config.requester,
                    channel: expected.channel,
                    challenge: expected.challenge,
                    min_version: expected.config.min_version,
                    max_version: expected.config.max_version,
                },
            )
            .map_err(|_| AdmissionError::Refused)?,
        )
    } else {
        None
    };
    // The retained state observes only an exact successfully transferred frame.
    // receive_exact checks the private expectation before any state transition.
    let mut record = |bytes: &[u8], sending: bool| -> Result<(), AdmissionError> {
        if let Some(state) = host_state.as_mut() {
            let frames = host_protocol::HostDecoder::new()
                .push(bytes)
                .map_err(|_| AdmissionError::Refused)?;
            let [frame] = frames.as_slice() else {
                return Err(AdmissionError::Refused);
            };
            if sending {
                state.send(frame)
            } else {
                state.receive(frame)
            }
            .map_err(|_| AdmissionError::Refused)?;
        }
        Ok(())
    };
    if requester {
        transfer(fd, &mut outgoing, true, deadline)?;
        record(&outgoing, true)?;
        receive_exact(fd, &incoming, expected.config.owner.is_some(), deadline)?;
        record(&incoming, false)?;
    } else {
        receive_exact(fd, &incoming, expected.config.owner.is_some(), deadline)?;
        record(&incoming, false)?;
        transfer(fd, &mut outgoing, true, deadline)?;
        record(&outgoing, true)?;
    }
    before(deadline)?;
    Ok(AdmittedChannel {
        custody: expected.custody,
        config: expected.config,
        local: expected.local,
        peer: expected.peer,
        evidence: true,
        host_state,
    })
}

#[cfg(test)]
#[path = "local_channel_tests.rs"]
pub(super) mod tests;

/// Sealed launch-only transfer. The host expectation remains with its parent.
pub(super) mod launch {
    use super::*;
    use crate::session_owner::inherited_launch::record::SetupRecord;
    use nix::libc;

    #[derive(Default, Debug)]
    struct LocalCloses {
        live: usize,
        uncertain: bool,
    }
    /// Tracks every new parent-owned copy; a failed close is never retried.
    pub(in crate::session_owner) struct LocalFd {
        fd: Option<OwnedFd>,
        ledger: Arc<Mutex<LocalCloses>>,
        closer: fn(RawFd) -> bool,
    }
    impl LocalFd {
        pub(in crate::session_owner) fn fd(&self) -> Result<&OwnedFd, AdmissionError> {
            self.fd.as_ref().ok_or(AdmissionError::Refused)
        }
        #[cfg(test)]
        pub(in crate::session_owner) fn test_uncertain_close(&mut self) {
            fn close_but_report_uncertain(raw: RawFd) -> bool {
                let _ = close_once(raw);
                false
            }
            self.closer = close_but_report_uncertain;
        }
        pub(in crate::session_owner) fn duplicate(&self) -> Result<Self, AdmissionError> {
            let raw = unsafe { libc::fcntl(self.fd()?.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
            if raw < 0 {
                return Err(AdmissionError::Unavailable);
            }
            Ok(Self::track(
                unsafe { OwnedFd::from_raw_fd(raw) },
                Arc::clone(&self.ledger),
            ))
        }
        fn track(fd: OwnedFd, ledger: Arc<Mutex<LocalCloses>>) -> Self {
            if let Ok(mut state) = ledger.lock() {
                if let Some(next) = state.live.checked_add(1) {
                    state.live = next;
                } else {
                    state.uncertain = true;
                }
            }
            Self {
                fd: Some(fd),
                ledger,
                closer: close_once,
            }
        }
        pub(in crate::session_owner) fn close(&mut self) {
            if let Some(fd) = self.fd.take() {
                let confirmed = (self.closer)(fd.into_raw_fd());
                if let Ok(mut state) = self.ledger.lock() {
                    state.live = state.live.saturating_sub(1);
                    state.uncertain |= !confirmed;
                }
            }
        }
    }
    impl Drop for LocalFd {
        fn drop(&mut self) {
            self.close();
        }
    }
    pub(in crate::session_owner) struct PreparedFrontendEnd {
        pub(in crate::session_owner) fd: LocalFd,
        host: HostInstance,
        channel: [u8; 16],
        challenge: [u8; 32],
        uid: u32,
    }
    pub(in crate::session_owner) struct RemoteEndObligation {
        pair: Arc<PairCharge>,
        index: usize,
        ledger: Arc<Mutex<LocalCloses>>,
        settled: bool,
        #[cfg(test)]
        unknown_reason: Option<SettlementReason>,
    }
    pub(in crate::session_owner) fn validate_config(
        config: TrustedChannelConfig,
    ) -> Result<(), AdmissionError> {
        let uid = unsafe { libc::geteuid() };
        if uid == 0
            || config.mode != (HostMode::Personal { canonical_uid: uid })
            || config.owner.is_some()
            || config.requester != OwnerRole::Frontend
            || config.min_version != 1
            || config.max_version != 1
        {
            return Err(AdmissionError::InvalidConfig);
        }
        Ok(())
    }
    pub(in crate::session_owner) fn split_frontend(
        expected: ExpectedAdmission,
    ) -> Result<(PreparedFrontendEnd, RemoteEndObligation), AdmissionError> {
        split_frontend_impl(
            expected,
            #[cfg(test)]
            None,
        )
    }
    #[cfg(test)]
    pub(in crate::session_owner) fn split_frontend_observed(
        expected: ExpectedAdmission,
        observer: &mut prepare_observation::Observer,
    ) -> Result<(PreparedFrontendEnd, RemoteEndObligation), AdmissionError> {
        split_frontend_impl(expected, Some(observer))
    }
    fn split_frontend_impl(
        mut expected: ExpectedAdmission,
        #[cfg(test)] mut observer: Option<&mut prepare_observation::Observer>,
    ) -> Result<(PreparedFrontendEnd, RemoteEndObligation), AdmissionError> {
        validate_config(expected.config)?;
        if expected.local != OwnerRole::Frontend || expected.peer != OwnerRole::Host {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                prepare_observation::Site::SplitFrontend,
                prepare_observation::Check::TransferRole,
                prepare_observation::Class::Predicate,
                None,
            );
            return Err(AdmissionError::Refused);
        }
        let Some(fd) = expected.custody.fd.as_ref() else {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                prepare_observation::Site::SplitFrontend,
                prepare_observation::Check::MissingDescriptor,
                prepare_observation::Class::Predicate,
                None,
            );
            return Err(AdmissionError::Refused);
        };
        validate_personal_fd_impl(
            fd,
            unsafe { libc::geteuid() },
            #[cfg(test)]
            prepare_observation::Site::SplitFrontend,
            #[cfg(test)]
            observer.as_deref_mut(),
        )?;
        let Some(fd) = expected.custody.fd.take() else {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                prepare_observation::Site::SplitFrontend,
                prepare_observation::Check::MissingDescriptor,
                prepare_observation::Class::Predicate,
                None,
            );
            return Err(AdmissionError::Refused);
        };
        let ledger = Arc::new(Mutex::new(LocalCloses::default()));
        let prepared = PreparedFrontendEnd {
            fd: LocalFd::track(fd, Arc::clone(&ledger)),
            host: expected.config.host,
            channel: expected.channel,
            challenge: expected.challenge,
            uid: unsafe { libc::geteuid() },
        };
        let remote = RemoteEndObligation {
            pair: Arc::clone(&expected.custody.pair),
            index: expected.custody.index,
            ledger,
            settled: false,
            #[cfg(test)]
            unknown_reason: None,
        };
        Ok((prepared, remote))
    }
    impl PreparedFrontendEnd {
        fn check_uid(&self, uid: u32) -> Result<(), AdmissionError> {
            if uid == 0 || uid != self.uid {
                return Err(AdmissionError::Refused);
            }
            Ok(())
        }
        pub(in crate::session_owner) fn for_spawn(&self) -> Result<(), AdmissionError> {
            let uid = unsafe { libc::geteuid() };
            self.check_uid(uid)?;
            validate_personal_fd(self.fd.fd()?, uid)
        }
        #[cfg(test)]
        pub(in crate::session_owner) fn test_check_uid(
            &self,
            uid: u32,
        ) -> Result<(), AdmissionError> {
            self.check_uid(uid)
        }
        pub(in crate::session_owner) fn setup(&self, deadline: u64) -> SetupRecord {
            SetupRecord {
                host: self.host,
                channel: self.channel,
                challenge: self.challenge,
                uid: self.uid,
                deadline,
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(in crate::session_owner) enum SettlementStatus {
        Pending,
        Settled,
        Unknown,
    }
    // Read-only test evidence; unavailable locks never grant cleanup authority.
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum ObservationAccess {
        Available,
        Busy,
        Poisoned,
        Overflow,
    }
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum ObservationEnd {
        Live,
        Closed,
        Uncertain,
    }
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) enum SettlementReason {
        LocalPoison,
        LocalUncertain,
        EndsPoison,
        PeerUncertain,
        BudgetPoison,
        Inconsistent,
    }
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::session_owner) struct DebtObservation {
        pub local: ObservationAccess,
        pub live: Option<u32>,
        pub uncertain: Option<bool>,
        pub settled: bool,
        pub ends: ObservationAccess,
        pub own: Option<ObservationEnd>,
        pub peer: Option<ObservationEnd>,
        pub budget: ObservationAccess,
        pub budget_present: bool,
        pub budget_nonzero: Option<bool>,
        pub reason: Option<SettlementReason>,
    }
    impl RemoteEndObligation {
        #[cfg(test)]
        pub(in crate::session_owner) fn test_observation(&self) -> DebtObservation {
            use std::sync::TryLockError;
            // Each diagnostic guard ends before the next try_lock. No poison
            // recovery, waiting, fd access, settlement or authority is added.
            let (local, live, uncertain) = {
                match self.ledger.try_lock() {
                    Ok(s) => match u32::try_from(s.live) {
                        Ok(live) => (ObservationAccess::Available, Some(live), Some(s.uncertain)),
                        Err(_) => (ObservationAccess::Overflow, None, None),
                    },
                    Err(TryLockError::WouldBlock) => (ObservationAccess::Busy, None, None),
                    Err(TryLockError::Poisoned(_)) => (ObservationAccess::Poisoned, None, None),
                }
            };
            let (ends, own, peer) = {
                let end = |e| match e {
                    EndState::Live => ObservationEnd::Live,
                    EndState::Closed => ObservationEnd::Closed,
                    EndState::Uncertain => ObservationEnd::Uncertain,
                };
                match self.pair.ends.try_lock() {
                    Ok(s) => (
                        ObservationAccess::Available,
                        Some(end(s[self.index])),
                        Some(end(s[1 - self.index])),
                    ),
                    Err(TryLockError::WouldBlock) => (ObservationAccess::Busy, None, None),
                    Err(TryLockError::Poisoned(_)) => (ObservationAccess::Poisoned, None, None),
                }
            };
            let (budget, budget_nonzero) = {
                match self.pair.budget.try_lock() {
                    Ok(s) => (ObservationAccess::Available, Some(s.used != 0)),
                    Err(TryLockError::WouldBlock) => (ObservationAccess::Busy, None),
                    Err(TryLockError::Poisoned(_)) => (ObservationAccess::Poisoned, None),
                }
            };
            DebtObservation {
                local,
                live,
                uncertain,
                settled: self.settled,
                ends,
                own,
                peer,
                budget,
                budget_present: true,
                budget_nonzero,
                reason: self.unknown_reason,
            }
        }
        #[cfg(test)]
        pub(in crate::session_owner) fn test_busy_observation(&self) -> DebtObservation {
            let _guard = self.ledger.lock().unwrap();
            self.test_observation()
        }
        pub(in crate::session_owner) fn track(&self, fd: OwnedFd) -> LocalFd {
            LocalFd::track(fd, Arc::clone(&self.ledger))
        }
        /// Requires the retained capsule's sealed terminal/no-export receipt;
        /// every known local copy must also have a confirmed close.
        pub(in crate::session_owner) fn settle(
            &mut self,
            _receipt: crate::session_owner::inherited_launch::Settlement,
        ) -> SettlementStatus {
            let Ok(local) = self.ledger.lock() else {
                #[cfg(test)]
                self.unknown_reason
                    .get_or_insert(SettlementReason::LocalPoison);
                return SettlementStatus::Unknown;
            };
            if local.uncertain {
                #[cfg(test)]
                self.unknown_reason
                    .get_or_insert(SettlementReason::LocalUncertain);
                return SettlementStatus::Unknown;
            }
            if local.live != 0 {
                return SettlementStatus::Pending;
            }
            let Ok(mut ends) = self.pair.ends.lock() else {
                #[cfg(test)]
                self.unknown_reason
                    .get_or_insert(SettlementReason::EndsPoison);
                return SettlementStatus::Unknown;
            };
            match ends[1 - self.index] {
                EndState::Live => return SettlementStatus::Pending,
                EndState::Uncertain => {
                    #[cfg(test)]
                    self.unknown_reason
                        .get_or_insert(SettlementReason::PeerUncertain);
                    return SettlementStatus::Unknown;
                }
                EndState::Closed => {}
            }
            let Ok(mut budget) = self.pair.budget.lock() else {
                #[cfg(test)]
                self.unknown_reason
                    .get_or_insert(SettlementReason::BudgetPoison);
                return SettlementStatus::Unknown;
            };
            if ends[self.index] != EndState::Live || budget.used == 0 {
                #[cfg(test)]
                self.unknown_reason
                    .get_or_insert(SettlementReason::Inconsistent);
                return SettlementStatus::Unknown;
            }
            // Credit and the remote-end terminal fact commit under the original
            // local ledger locks; poison cannot silently discard the charge.
            ends[self.index] = EndState::Closed;
            budget.used -= 1;
            self.settled = true;
            SettlementStatus::Settled
        }
    }
    pub(in crate::session_owner) fn validate_personal_fd(
        fd: &OwnedFd,
        uid: u32,
    ) -> Result<(), AdmissionError> {
        validate_personal_fd_impl(
            fd,
            uid,
            #[cfg(test)]
            prepare_observation::Site::OtherPreparation,
            #[cfg(test)]
            None,
        )
    }
    #[cfg(test)]
    pub(in crate::session_owner) fn validate_personal_fd_observed(
        fd: &OwnedFd,
        uid: u32,
        site: prepare_observation::Site,
        observer: &mut prepare_observation::Observer,
    ) -> Result<(), AdmissionError> {
        validate_personal_fd_impl(fd, uid, site, Some(observer))
    }
    fn validate_personal_fd_impl(
        fd: &OwnedFd,
        uid: u32,
        #[cfg(test)] site: prepare_observation::Site,
        #[cfg(test)] mut observer: Option<&mut prepare_observation::Observer>,
    ) -> Result<(), AdmissionError> {
        if uid == 0 || uid != unsafe { libc::geteuid() } {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                site,
                prepare_observation::Check::PersonalCurrentIdentity,
                prepare_observation::Class::Predicate,
                None,
            );
            return Err(AdmissionError::Refused);
        }
        validate_socket_impl(
            fd,
            TrustedChannelConfig {
                host: HostInstance::new([1; 16]).unwrap(),
                owner: None,
                requester: OwnerRole::Frontend,
                mode: HostMode::Personal { canonical_uid: uid },
                system_uid: uid,
                min_version: 1,
                max_version: 1,
            },
            #[cfg(test)]
            site,
            #[cfg(test)]
            observer.as_deref_mut(),
        )?;
        let peer = match crate::control::peer_uid(fd) {
            Ok(peer) => peer,
            Err(error) => {
                #[cfg(test)]
                prepare_observation::record(
                    observer,
                    site,
                    prepare_observation::Check::PersonalPeerUidCall,
                    prepare_observation::Class::Io,
                    error.raw_os_error(),
                );
                return Err(error.into());
            }
        };
        if peer != uid {
            #[cfg(test)]
            prepare_observation::record(
                observer,
                site,
                prepare_observation::Check::ExactPersonalPeer,
                prepare_observation::Class::Predicate,
                None,
            );
            return Err(AdmissionError::Refused);
        }
        Ok(())
    }
    pub(in crate::session_owner) fn read(fd: &OwnedFd, bytes: &mut [u8]) -> io::Result<usize> {
        (&*stream(fd)).read(bytes)
    }
    pub(in crate::session_owner) fn write_setup(
        fd: &OwnedFd,
        bytes: &[u8; 112],
        deadline: Instant,
    ) -> Result<(), AdmissionError> {
        let mut bytes = *bytes;
        transfer(fd, &mut bytes, true, deadline)
    }
    pub(in crate::session_owner) fn read_setup(
        fd: &OwnedFd,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), AdmissionError> {
        transfer(fd, bytes, false, deadline)
    }
    pub(in crate::session_owner) fn restore_frontend(
        claimed: crate::session_owner::inherited_launch::child::ClaimedFrontend,
    ) -> Result<ExpectedAdmission, AdmissionError> {
        let (fd, record) = claimed.into_parts();
        let config = TrustedChannelConfig {
            host: record.host,
            owner: None,
            requester: OwnerRole::Frontend,
            mode: HostMode::Personal {
                canonical_uid: record.uid,
            },
            system_uid: record.uid,
            min_version: 1,
            max_version: 1,
        };
        validate_config(config)?;
        validate_personal_fd(&fd, record.uid)?;
        // This process owns one local end only. No parent Arc/ledger crosses exec.
        let budget = Arc::new(Mutex::new(BudgetState {
            limit: 1,
            used: 1,
            uncertain_ends: 0,
        }));
        let pair = Arc::new(PairCharge {
            budget,
            ends: Mutex::new([EndState::Live, EndState::Closed]),
        });
        Ok(ExpectedAdmission {
            custody: Custody {
                fd: Some(fd),
                pair,
                index: 0,
                closer: close_once,
            },
            config,
            local: OwnerRole::Frontend,
            peer: OwnerRole::Host,
            channel: record.channel,
            challenge: record.challenge,
        })
    }
    #[cfg(test)]
    pub(in crate::session_owner) fn write_prefix(
        fd: &OwnedFd,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), AdmissionError> {
        let mut bytes = bytes.to_vec();
        transfer(fd, &mut bytes, true, deadline)
    }
    #[cfg(test)]
    pub(in crate::session_owner) fn test_evidence(channel: &mut AdmittedChannel) -> bool {
        channel.take_frontend_evidence(channel.config.mode).is_ok()
    }
    #[cfg(test)]
    pub(in crate::session_owner) fn test_write(fd: &OwnedFd, bytes: &[u8]) -> io::Result<usize> {
        (&*stream(fd)).write(bytes)
    }
    #[cfg(test)]
    impl RemoteEndObligation {
        pub(in crate::session_owner) fn test_in_use(&self) -> usize {
            self.pair
                .budget
                .lock()
                .map(|state| state.used)
                .unwrap_or(usize::MAX)
        }
        pub(in crate::session_owner) fn test_uncertain(&mut self) {
            self.ledger.lock().unwrap().uncertain = true;
        }
    }
    impl Drop for RemoteEndObligation {
        fn drop(&mut self) {
            if !self.settled {
                self.pair.terminal(self.index, false);
            }
        }
    }
}
