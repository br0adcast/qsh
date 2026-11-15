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
    validate_socket(a.custody.fd.as_ref().unwrap(), config)?;
    validate_socket(b.custody.fd.as_ref().unwrap(), config)?;
    Ok((a, b))
}
// This borrowing facade never owns the number or closes it. Custody is sole owner.
fn stream(fd: &OwnedFd) -> ManuallyDrop<UnixStream> {
    ManuallyDrop::new(unsafe { UnixStream::from_raw_fd(fd.as_raw_fd()) })
}
fn validate_socket(fd: &OwnedFd, config: TrustedChannelConfig) -> Result<(), AdmissionError> {
    use nix::libc;
    let raw = fd.as_raw_fd();
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            raw,
            (&mut addr as *mut libc::sockaddr_storage).cast(),
            &mut len,
        )
    } != 0
        || addr.ss_family as i32 != libc::AF_UNIX
    {
        return Err(AdmissionError::Refused);
    }
    let option = |name| -> Result<i32, AdmissionError> {
        let mut value = 0i32;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                name,
                (&mut value as *mut i32).cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of_val(&value)
        {
            return Err(AdmissionError::Refused);
        }
        Ok(value)
    };
    if option(libc::SO_TYPE)? != libc::SOCK_STREAM || option(libc::SO_ACCEPTCONN)? != 0 {
        return Err(AdmissionError::Refused);
    }
    let socket = stream(fd);
    socket.peer_addr().map_err(|_| AdmissionError::Refused)?;
    let uid = crate::control::peer_uid(fd).map_err(|_| AdmissionError::Refused)?;
    let allowed = match config.mode {
        HostMode::Personal { canonical_uid } => uid == canonical_uid || uid == 0,
        HostMode::System => uid == config.system_uid,
    };
    if !allowed {
        return Err(AdmissionError::Refused);
    }
    socket.set_nonblocking(true)?;
    Ok(())
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
mod tests;

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
        mut expected: ExpectedAdmission,
    ) -> Result<(PreparedFrontendEnd, RemoteEndObligation), AdmissionError> {
        validate_config(expected.config)?;
        if expected.local != OwnerRole::Frontend || expected.peer != OwnerRole::Host {
            return Err(AdmissionError::Refused);
        }
        validate_personal_fd(
            expected
                .custody
                .fd
                .as_ref()
                .ok_or(AdmissionError::Refused)?,
            unsafe { libc::geteuid() },
        )?;
        let fd = expected.custody.fd.take().ok_or(AdmissionError::Refused)?;
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
    impl RemoteEndObligation {
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
                return SettlementStatus::Unknown;
            };
            if local.uncertain {
                return SettlementStatus::Unknown;
            }
            if local.live != 0 {
                return SettlementStatus::Pending;
            }
            let Ok(mut ends) = self.pair.ends.lock() else {
                return SettlementStatus::Unknown;
            };
            match ends[1 - self.index] {
                EndState::Live => return SettlementStatus::Pending,
                EndState::Uncertain => return SettlementStatus::Unknown,
                EndState::Closed => {}
            }
            let Ok(mut budget) = self.pair.budget.lock() else {
                return SettlementStatus::Unknown;
            };
            if ends[self.index] != EndState::Live || budget.used == 0 {
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
        if uid == 0 || uid != unsafe { libc::geteuid() } {
            return Err(AdmissionError::Refused);
        }
        validate_socket(
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
        )?;
        if crate::control::peer_uid(fd)? != uid {
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
