//! Private keeper control protocol. This does not select a process backend.
const FRAME_BYTES: usize = 72;
const MAGIC: &[u8; 8] = b"QSHKPR01";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operation {
    Ready = 1,
    Admit = 2,
    AppStarted = 3,
    AppWait = 4,
    Stop = 5,
    Drained = 6,
    Exit = 7,
    Refused = 8,
    Foreground = 9,
    ForegroundReady = 10,
    KeeperReady = 11,
    KeeperCreated = 12,
    KeeperWait = 13,
    BrokerMoved = 14,
    AppFailed = 15,
    KeeperSpawned = 16,
    BrokerParent = 17,
    KeeperTerminal = 18,
    AbortBeforeAdmit = 19,
    AppNotStarted = 20,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Frame {
    pub operation: Operation,
    pub fields: [i64; 4],
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProtocolError;
pub(super) struct Decoder {
    instance: [u8; 16],
    sequence: u64,
    buffer: Vec<u8>,
    failed: bool,
}
impl Decoder {
    pub fn new(instance: [u8; 16]) -> Self {
        Self {
            instance,
            sequence: 0,
            buffer: Vec::new(),
            failed: false,
        }
    }
    pub fn remaining(&self) -> usize {
        FRAME_BYTES - self.buffer.len()
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Option<Frame>, ProtocolError> {
        if self.failed || bytes.len() > self.remaining() {
            self.failed = true;
            return Err(ProtocolError);
        }
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() != FRAME_BYTES {
            return Ok(None);
        }
        let data = &self.buffer;
        let sequence = u64::from_be_bytes(data[32..40].try_into().unwrap());
        let operation = match data[9] {
            1 => Some(Operation::Ready),
            2 => Some(Operation::Admit),
            3 => Some(Operation::AppStarted),
            4 => Some(Operation::AppWait),
            5 => Some(Operation::Stop),
            6 => Some(Operation::Drained),
            7 => Some(Operation::Exit),
            8 => Some(Operation::Refused),
            9 => Some(Operation::Foreground),
            10 => Some(Operation::ForegroundReady),
            11 => Some(Operation::KeeperReady),
            12 => Some(Operation::KeeperCreated),
            13 => Some(Operation::KeeperWait),
            14 => Some(Operation::BrokerMoved),
            15 => Some(Operation::AppFailed),
            16 => Some(Operation::KeeperSpawned),
            17 => Some(Operation::BrokerParent),
            18 => Some(Operation::KeeperTerminal),
            19 => Some(Operation::AbortBeforeAdmit),
            20 => Some(Operation::AppNotStarted),
            _ => None,
        };
        if &data[..8] != MAGIC
            || data[8] != 1
            || data[10..12] != [0, 0]
            || u32::from_be_bytes(data[12..16].try_into().unwrap()) as usize != FRAME_BYTES
            || data[16..32] != self.instance
            || self.sequence.checked_add(1) != Some(sequence)
            || operation.is_none()
        {
            self.failed = true;
            return Err(ProtocolError);
        }
        let mut fields = [0; 4];
        for (i, value) in fields.iter_mut().enumerate() {
            *value = i64::from_be_bytes(data[40 + i * 8..48 + i * 8].try_into().unwrap());
        }
        if matches!(
            operation,
            Some(Operation::AbortBeforeAdmit | Operation::AppNotStarted)
        ) && fields != [0; 4]
        {
            self.failed = true;
            return Err(ProtocolError);
        }
        self.sequence = sequence;
        self.buffer.clear();
        Ok(Some(Frame {
            operation: operation.unwrap(),
            fields,
        }))
    }
}
pub(super) fn encode(instance: [u8; 16], sequence: u64, frame: Frame) -> [u8; FRAME_BYTES] {
    let mut bytes = [0; FRAME_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = 1;
    bytes[9] = frame.operation as u8;
    bytes[12..16].copy_from_slice(&(FRAME_BYTES as u32).to_be_bytes());
    bytes[16..32].copy_from_slice(&instance);
    bytes[32..40].copy_from_slice(&sequence.to_be_bytes());
    for (i, value) in frame.fields.iter().enumerate() {
        bytes[40 + i * 8..48 + i * 8].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

/// The private admission decision is committed only after its frame is queued.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) enum AdmissionDecision {
    #[default]
    Pending,
    Admit,
    Abort,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingAdmission {
    None,
    Abort,
    GuardedAdmit,
}
impl AdmissionDecision {
    pub fn pending(
        self,
        bound: bool,
        stopped: bool,
        expired: bool,
        authority: bool,
    ) -> PendingAdmission {
        if self != Self::Pending || !bound {
            PendingAdmission::None
        } else if stopped || expired || !authority {
            PendingAdmission::Abort
        } else {
            PendingAdmission::GuardedAdmit
        }
    }
    pub fn commit(&mut self, decision: Self) -> Result<(), ProtocolError> {
        if *self != Self::Pending || decision == Self::Pending {
            return Err(ProtocolError);
        }
        *self = decision;
        Ok(())
    }
}
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) enum AppDisposition {
    #[default]
    Pending,
    NotStarted,
    Waited(i32),
}
impl AppDisposition {
    pub fn status(self) -> Option<i32> {
        match self {
            Self::Waited(code) => Some(code),
            _ => None,
        }
    }
    pub fn not_started(
        &mut self,
        decision: AdmissionDecision,
        app_started: bool,
    ) -> Result<(), ProtocolError> {
        if decision != AdmissionDecision::Abort || app_started || *self != Self::Pending {
            return Err(ProtocolError);
        }
        *self = Self::NotStarted;
        Ok(())
    }
    pub fn settled(self) -> bool {
        self != Self::Pending
    }
}

/// App status and reservation wait are intentionally independent receipts.
#[derive(Default)]
pub(super) struct Completion {
    pub application: AppDisposition,
    pub session_wait: Option<i32>,
    pub broker_terminal: bool,
    pub final_census: bool,
    pub drained: bool,
}
impl Completion {
    pub fn status(&self) -> transport::channel_server::ChildStatus {
        use transport::channel_server::ChildStatus;
        if self.session_wait.is_some() && self.broker_terminal && self.final_census && self.drained
        {
            match self.application {
                AppDisposition::Waited(code) => return ChildStatus::Reaped { code: Some(code) },
                AppDisposition::NotStarted => return ChildStatus::Reaped { code: None },
                AppDisposition::Pending => {}
            }
        }
        ChildStatus::Running
    }
}

/// Portable test-only gate used by the actual native startup driver. A Core
/// request is not an arrival acknowledgement: the driver acknowledges only
/// after its Core guard has been released, then holds progress and completion.
#[cfg(test)]
pub(super) struct FixtureAdmissionGate {
    after_admit: bool,
    requested: std::sync::atomic::AtomicBool,
    reached: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    held_polls: std::sync::atomic::AtomicUsize,
    #[cfg(target_os = "macos")]
    expire: std::sync::atomic::AtomicBool,
    #[cfg(target_os = "macos")]
    resumed: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl FixtureAdmissionGate {
    pub fn new(after_admit: bool) -> Self {
        Self {
            after_admit,
            requested: false.into(),
            reached: false.into(),
            released: false.into(),
            held_polls: 0.into(),
            #[cfg(target_os = "macos")]
            expire: false.into(),
            #[cfg(target_os = "macos")]
            resumed: false.into(),
        }
    }
    pub fn after_admit(&self) -> bool {
        self.after_admit
    }
    pub fn pause(&self) -> bool {
        self.requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        !self.released()
    }
    pub fn requested(&self) -> bool {
        self.requested.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn reached(&self) -> bool {
        self.reached.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn released(&self) -> bool {
        self.released.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn held_polls(&self) -> usize {
        self.held_polls.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// Call only outside Core, custody and registry locks. This is the sole
    /// arrival acknowledgement, and neither ordering may complete while held.
    pub fn hold_until_release(&self, end: std::time::Instant) -> bool {
        self.reached
            .store(true, std::sync::atomic::Ordering::SeqCst);
        while !self.released() && std::time::Instant::now() < end {
            self.held_polls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        self.released()
    }
    #[cfg(target_os = "macos")]
    pub fn expire_startup(&self) {
        self.expire.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(target_os = "macos")]
    pub fn resumed(&self) -> bool {
        self.resumed.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(target_os = "macos")]
mod owner {
    use super::super::keeper_helper::Channel;
    use super::super::keeper_pty::Startup;
    use super::super::{native, Class, Identity, Ops, Registration};
    use super::*;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use transport::channel_open::{CleanupAuthority, CleanupStatus, OpenCustody};
    use transport::channel_server::{ChannelWait, ChildStatus, LeaderStatus};
    const GRACE: Duration = Duration::from_secs(1);
    const INTERVAL: Duration = Duration::from_millis(20);
    struct ChildReceipt {
        terminal: Option<i32>,
        pid: i32,
        identity: Option<Identity>,
        group: Option<i32>,
        wait: Option<i32>,
    }
    struct Core {
        session: std::process::Child,
        session_consumption_attempted: bool,
        sid: i32,
        session_identity: Option<Identity>,
        session_terminal_observed: Option<i32>,
        broker_parent: Option<i32>,
        moves: Vec<i32>,
        _admission: native::KeeperAdmission,
        session_control: Channel,
        broker_control: Channel,
        launch: Vec<u8>,
        launch_at: usize,
        session_ready: Option<i32>,
        broker_ready: Option<(i32, i32)>,
        broker: Option<Registration<native::Watch>>,
        app: Option<i32>,
        keepers: Vec<ChildReceipt>,
        completion: Completion,
        startup: Startup,
        deadline: Instant,
        decision: AdmissionDecision,
        failed: bool,
        broker_closed: bool,
        session_closed: bool,
        exit_broker: bool,
        exit_session: bool,
        stop_sent: i32,
        #[cfg(test)]
        admission_gate: Option<Arc<FixtureAdmissionGate>>,
    }
    struct Shared {
        core: Mutex<Core>,
        stop: OnceLock<Instant>,
        deadline: Instant,
    }
    pub(in crate::darwin_process_scope) struct KeeperOwner {
        shared: Arc<Shared>,
    }
    pub(in crate::darwin_process_scope) struct StartupDriver {
        shared: Arc<Shared>,
        armed: bool,
    }
    impl Drop for StartupDriver {
        fn drop(&mut self) {
            if self.armed {
                self.shared.stop.get_or_init(Instant::now);
            }
        }
    }
    impl StartupDriver {
        pub fn fail(&self) {
            self.shared.stop.get_or_init(Instant::now);
            if let Ok(mut core) = self.shared.core.lock() {
                core.refuse();
            }
        }
        pub fn complete(mut self, custody: &OpenCustody) -> Startup {
            loop {
                let cancelled = custody.is_cancelled();
                if cancelled {
                    self.shared.stop.get_or_init(Instant::now);
                }
                let stop = self.shared.stop.get().copied();
                #[cfg(test)]
                let paused;
                #[allow(unused_mut)]
                let mut state = {
                    let Ok(mut core) = self.shared.core.lock() else {
                        return Startup::Failed("keeper owner lock is poisoned".into());
                    };
                    core.advance(stop, Some(custody));
                    #[cfg(test)]
                    {
                        paused = core
                            .admission_gate
                            .as_ref()
                            .filter(|gate| gate.requested() && !gate.released())
                            .cloned();
                    }
                    if core.completion.application.status().is_some() {
                        self.shared.stop.get_or_init(Instant::now);
                    }
                    if Instant::now() >= self.shared.deadline {
                        core.startup = Startup::Failed("keeper startup deadline expired".into());
                        self.shared.stop.get_or_init(Instant::now);
                        core.startup.clone()
                    } else if cancelled && matches!(core.startup, Startup::Ready) {
                        Startup::Failed("keeper startup was cancelled after admission".into())
                    } else {
                        core.startup.clone()
                    }
                };
                #[cfg(test)]
                if let Some(gate) = paused {
                    // The Core guard is gone before this acknowledgement/wait.
                    // Hold BOTH orderings, including an already Ready startup,
                    // so controller cancellation cannot race driver completion.
                    if !gate.hold_until_release(self.shared.deadline) {
                        self.shared.stop.get_or_init(Instant::now);
                        return Startup::Failed(
                            "keeper fixture gate exceeded original deadline".into(),
                        );
                    }
                    if !gate.after_admit() {
                        // Keep the initial cancellation/stop snapshot: the real
                        // custody seam, not another poll, must detect cancel.
                        let Ok(mut core) = self.shared.core.lock() else {
                            return Startup::Failed("keeper owner lock is poisoned".into());
                        };
                        if gate.expire.load(std::sync::atomic::Ordering::SeqCst) {
                            core.deadline = core.deadline.min(Instant::now());
                        }
                        core.commit_pending_admission(stop, Some(custody));
                        gate.resumed.store(
                            core.decision != AdmissionDecision::Pending,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                        state = core.startup.clone();
                    }
                }
                match state {
                    Startup::Pending => std::thread::sleep(INTERVAL),
                    other => {
                        // Normal consumption does not request stop. The driver
                        // contains no child/descriptor rights outside Core.
                        if matches!(other, Startup::Ready) {
                            self.armed = false;
                        }
                        return other;
                    }
                }
            }
        }
    }
    impl KeeperOwner {
        pub(in crate::darwin_process_scope) fn created(
            session: std::process::Child,
            session_control: Channel,
            broker_control: Channel,
            launch: Vec<u8>,
            deadline: Instant,
            admission: native::KeeperAdmission,
        ) -> (Self, StartupDriver) {
            let sid = i32::try_from(session.id()).unwrap_or(0);
            let shared = Arc::new(Shared {
                core: Mutex::new(Core {
                    session,
                    session_consumption_attempted: false,
                    sid,
                    session_identity: None,
                    session_terminal_observed: None,
                    broker_parent: None,
                    moves: Vec::new(),
                    _admission: admission,
                    session_control,
                    broker_control,
                    launch,
                    launch_at: 0,
                    session_ready: None,
                    broker_ready: None,
                    broker: None,
                    app: None,
                    keepers: Vec::new(),
                    completion: Completion::default(),
                    startup: Startup::Pending,
                    deadline,
                    decision: AdmissionDecision::Pending,
                    failed: false,
                    broker_closed: false,
                    session_closed: false,
                    exit_broker: false,
                    exit_session: false,
                    stop_sent: 0,
                    #[cfg(test)]
                    admission_gate: None,
                }),
                stop: OnceLock::new(),
                deadline,
            });
            (
                Self {
                    shared: Arc::clone(&shared),
                },
                StartupDriver {
                    shared,
                    armed: true,
                },
            )
        }
        fn progress(&mut self) -> ChildStatus {
            let Ok(mut core) = self.shared.core.lock() else {
                return ChildStatus::Unknown("keeper owner lock is poisoned".into());
            };
            core.advance(self.shared.stop.get().copied(), None);
            if core.completion.application.status().is_some() {
                self.shared.stop.get_or_init(Instant::now);
            }
            if core.failed {
                ChildStatus::Unknown("keeper custody is unconfirmed".into())
            } else {
                core.completion.status()
            }
        }
    }
    impl ChannelWait for KeeperOwner {
        fn poll_exit(&mut self) -> ChildStatus {
            self.progress()
        }
        fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
            let status = self.progress();
            let Ok(core) = self.shared.core.lock() else {
                return Some(LeaderStatus::Unknown(
                    "keeper owner lock is poisoned".into(),
                ));
            };
            Some(match (status, core.completion.application.status()) {
                (ChildStatus::Unknown(reason), _) => LeaderStatus::Unknown(reason),
                (_, Some(code)) => LeaderStatus::Exited { code: Some(code) },
                _ => LeaderStatus::Running,
            })
        }
        fn kill(&mut self) {
            self.shared.stop.get_or_init(Instant::now);
        }
        fn wait(mut self: Box<Self>) -> i32 {
            loop {
                if let ChildStatus::Reaped { code: Some(code) } = self.progress() {
                    return code;
                }
                std::thread::sleep(INTERVAL);
            }
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            self.kill();
            loop {
                match self.progress() {
                    ChildStatus::Reaped { .. } => return authority.reaped(),
                    ChildStatus::Unknown(_) => return CleanupStatus::Unknown,
                    _ => std::thread::sleep(INTERVAL),
                }
            }
        }
    }
    impl Core {
        fn refuse(&mut self) {
            self.failed = true;
            self.startup = Startup::Failed("keeper custody is unconfirmed".into());
        }
        fn send_broker(&mut self, frame: Frame) -> bool {
            match self.broker_control.queue(frame) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(_) => {
                    self.refuse();
                    false
                }
            }
        }
        fn send_session(&mut self, frame: Frame) -> bool {
            match self.session_control.queue(frame) {
                Ok(()) => true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(_) => {
                    self.refuse();
                    false
                }
            }
        }
        fn broker_frame(&mut self, frame: Frame) -> bool {
            let identity = || -> Option<Identity> {
                let value = Identity {
                    pid: i32::try_from(frame.fields[0]).ok()?,
                    unique: frame.fields[1] as u64,
                    version: u32::try_from(frame.fields[2]).ok()?,
                };
                value.valid().then_some(value)
            };
            match frame.operation {
                Operation::Ready
                    if self.broker_ready.is_none()
                        && self.decision == AdmissionDecision::Pending
                        && frame.fields[2] == self.sid as i64
                        && frame.fields[3] == 0 =>
                {
                    let Ok(pid) = i32::try_from(frame.fields[0]) else {
                        return false;
                    };
                    let Ok(group) = i32::try_from(frame.fields[1]) else {
                        return false;
                    };
                    if pid <= 0 || pid == self.sid || group != pid {
                        return false;
                    }
                    self.broker_ready = Some((pid, group));
                    true
                }
                Operation::AppStarted | Operation::AppFailed
                    if self.decision == AdmissionDecision::Admit && self.app.is_none() =>
                {
                    let Ok(app) = i32::try_from(frame.fields[0]) else {
                        return false;
                    };
                    if app <= 0
                        || app == self.sid
                        || frame.fields[1..3] != [0; 2]
                        || self.broker.as_ref().is_some_and(|b| b.identity.pid == app)
                    {
                        return false;
                    }
                    if frame.operation == Operation::AppStarted {
                        if frame.fields[3] != self.sid as i64 {
                            return false;
                        }
                        self.startup = Startup::Ready;
                    } else {
                        if frame.fields[3] != 127 {
                            return false;
                        }
                        self.startup = Startup::Failed("keeper application exec failed".into());
                    }
                    self.app = Some(app);
                    true
                }
                Operation::AppWait
                    if self.app.is_some_and(|pid| pid as i64 == frame.fields[0])
                        && self.completion.application == AppDisposition::Pending
                        && frame.fields[2..] == [0; 2] =>
                {
                    let Ok(code) = i32::try_from(frame.fields[1]) else {
                        return false;
                    };
                    if !(0..=255).contains(&code) {
                        return false;
                    }
                    self.completion.application = AppDisposition::Waited(code);
                    true
                }
                Operation::KeeperSpawned
                    if self.decision == AdmissionDecision::Admit
                        && !self.completion.drained
                        && self.keepers.len() < 8
                        && frame.fields[1..] == [0; 3] =>
                {
                    let Ok(pid) = i32::try_from(frame.fields[0]) else {
                        return false;
                    };
                    if pid <= 0
                        || pid == self.sid
                        || self.broker.as_ref().is_some_and(|b| b.identity.pid == pid)
                        || self
                            .keepers
                            .iter()
                            .any(|k| k.pid == pid && k.wait.is_none())
                    {
                        return false;
                    }
                    self.keepers.push(ChildReceipt {
                        terminal: None,
                        pid,
                        identity: None,
                        group: None,
                        wait: None,
                    });
                    true
                }
                Operation::KeeperCreated
                    if self.decision == AdmissionDecision::Admit
                        && !self.completion.drained
                        && frame.fields[3] > 0
                        && frame.fields[3] <= i32::MAX as i64 =>
                {
                    let Some(id) = identity() else {
                        return false;
                    };
                    let Some(k) = self
                        .keepers
                        .iter_mut()
                        .find(|k| k.pid == id.pid && k.wait.is_none())
                    else {
                        return false;
                    };
                    if k.identity.is_some() {
                        return false;
                    }
                    k.identity = Some(id);
                    k.group = Some(frame.fields[3] as i32);
                    true
                }
                Operation::KeeperTerminal
                    if self.decision == AdmissionDecision::Admit
                        && !self.completion.drained
                        && frame.fields[2..] == [0; 2] =>
                {
                    let Ok(pid) = i32::try_from(frame.fields[0]) else {
                        return false;
                    };
                    let Ok(code) = i32::try_from(frame.fields[1]) else {
                        return false;
                    };
                    if !(0..=255).contains(&code) {
                        return false;
                    }
                    let Some(k) = self
                        .keepers
                        .iter_mut()
                        .find(|k| k.pid == pid && k.wait.is_none())
                    else {
                        return false;
                    };
                    if k.terminal.is_some() {
                        return false;
                    }
                    k.terminal = Some(code);
                    true
                }
                Operation::BrokerParent
                    if self
                        .broker_ready
                        .is_some_and(|(pid, _)| pid as i64 == frame.fields[0])
                        && frame.fields[1] > 0
                        && frame.fields[1] <= i32::MAX as i64
                        && frame.fields[2] == self.sid as i64
                        && frame.fields[3] == 0 =>
                {
                    self.broker_parent = Some(frame.fields[1] as i32);
                    true
                }
                Operation::KeeperWait
                    if self.decision == AdmissionDecision::Admit
                        && !self.completion.drained
                        && frame.fields[2..] == [0; 2] =>
                {
                    let Ok(pid) = i32::try_from(frame.fields[0]) else {
                        return false;
                    };
                    let Ok(code) = i32::try_from(frame.fields[1]) else {
                        return false;
                    };
                    if !(0..=255).contains(&code) {
                        return false;
                    }
                    let Some(k) = self
                        .keepers
                        .iter_mut()
                        .find(|k| k.pid == pid && k.wait.is_none())
                    else {
                        return false;
                    };
                    if k.terminal != Some(code) {
                        return false;
                    }
                    k.wait = Some(code);
                    true
                }
                Operation::BrokerMoved
                    if self.decision == AdmissionDecision::Admit
                        && !self.completion.drained
                        && self
                            .broker
                            .as_ref()
                            .is_some_and(|b| b.identity.pid as i64 == frame.fields[0]) =>
                {
                    if frame.fields[1] <= 0
                        || frame.fields[1] > i32::MAX as i64
                        || frame.fields[2] != self.sid as i64
                        || frame.fields[3] != 0
                        || self.moves.len() >= 8
                    {
                        return false;
                    }
                    self.moves.push(frame.fields[1] as i32);
                    true
                }
                Operation::AppNotStarted if frame.fields == [0; 4] => self
                    .completion
                    .application
                    .not_started(self.decision, self.app.is_some())
                    .is_ok(),
                Operation::Drained
                    if self.decision != AdmissionDecision::Pending
                        && !self.completion.drained
                        && self.completion.application.settled()
                        && frame.fields == [self.keepers.len() as i64, 0, 0, 0]
                        && self.keepers.iter().all(|k| k.wait.is_some()) =>
                {
                    self.completion.drained = true;
                    true
                }
                _ => false,
            }
        }
        fn queue_decision(&mut self, decision: AdmissionDecision) -> bool {
            if self.send_broker(Frame {
                operation: if decision == AdmissionDecision::Abort {
                    Operation::AbortBeforeAdmit
                } else {
                    Operation::Admit
                },
                fields: [0; 4],
            }) {
                self.decision.commit(decision).expect("pending admission");
                if decision == AdmissionDecision::Abort {
                    self.startup =
                        Startup::Failed("keeper startup was aborted before admission".into());
                }
                true
            } else {
                false
            }
        }
        fn commit_pending_admission(
            &mut self,
            stop: Option<Instant>,
            admission: Option<&OpenCustody>,
        ) {
            use transport::channel_open::InitialAdmissionError;
            match self.decision.pending(
                self.broker.is_some(),
                stop.is_some(),
                Instant::now() >= self.deadline,
                admission.is_some(),
            ) {
                PendingAdmission::None => {}
                PendingAdmission::Abort => {
                    self.queue_decision(AdmissionDecision::Abort);
                }
                PendingAdmission::GuardedAdmit => {
                    // Core -> Custody. Only in-memory queue+commit runs under
                    // this lock; all native validation and fixture waits precede it.
                    match admission
                        .expect("driver authority")
                        .try_commit_initial_admission(|| {
                            if Instant::now() >= self.deadline {
                                None
                            } else {
                                Some(self.queue_decision(AdmissionDecision::Admit))
                            }
                        }) {
                        Ok(Some(_)) => {} // WouldBlock keeps the decision Pending.
                        Ok(None) | Err(InitialAdmissionError::Cancelled) => {
                            self.queue_decision(AdmissionDecision::Abort);
                        }
                        Err(InitialAdmissionError::Unavailable) => self.refuse(),
                    }
                }
            }
        }
        fn advance(&mut self, stop: Option<Instant>, admission: Option<&OpenCustody>) {
            if self.failed || self.completion.session_wait.is_some() {
                return;
            }
            if self._admission.contract.is_empty() {
                self.refuse();
                return;
            }
            // The post-decision fixture barrier must also stop later polls
            // before flushing Admit/receiving AppStarted. Otherwise a ready
            // startup could escape the barrier while its observer is paused.
            #[cfg(test)]
            if self.decision == AdmissionDecision::Admit
                && self
                    .admission_gate
                    .as_ref()
                    .is_some_and(|gate| gate.after_admit && gate.pause())
            {
                return;
            }
            let mut ops = native::NativeOps;
            let session_status = match ops.keeper_child_status(self.sid) {
                Ok(status) => status,
                Err(_) => {
                    self.refuse();
                    return;
                }
            };
            if self.session_terminal_observed.is_some()
                && self.session_terminal_observed != session_status
            {
                self.refuse();
                return;
            }
            if session_status.is_some() {
                self.session_terminal_observed = session_status;
            }
            if self.launch_at < self.launch.len() {
                if self
                    .session_control
                    .bootstrap(&self.launch, &mut self.launch_at)
                    .is_err()
                {
                    self.refuse();
                    return;
                }
                if self.launch_at < self.launch.len() {
                    return;
                }
            }
            if self.session_control.flush().is_err() && !self.session_closed {
                self.refuse();
                return;
            }
            if self.broker_control.flush().is_err() && !self.broker_closed {
                self.refuse();
                return;
            }
            for _ in 0..16 {
                if self.session_closed {
                    break;
                }
                match self.session_control.receive() {
                    Ok(Some(frame))
                        if self.session_ready.is_none()
                            && frame.operation == Operation::Ready
                            && frame.fields[0] == self.sid as i64
                            && frame.fields[2..] == [0; 2] =>
                    {
                        let Ok(pid) = i32::try_from(frame.fields[1]) else {
                            self.refuse();
                            return;
                        };
                        if pid <= 0 {
                            self.refuse();
                            return;
                        }
                        self.session_ready = Some(pid);
                    }
                    Ok(Some(_)) => {
                        self.refuse();
                        return;
                    }
                    Ok(None) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        self.session_closed = true;
                        break;
                    }
                    Err(_) => {
                        self.refuse();
                        return;
                    }
                }
            }
            for _ in 0..16 {
                if self.broker_closed {
                    break;
                }
                match self.broker_control.receive() {
                    Ok(Some(frame)) => {
                        if !self.broker_frame(frame) {
                            self.refuse();
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            && self.completion.drained =>
                    {
                        self.broker_closed = true;
                        break;
                    }
                    Err(_) => {
                        self.refuse();
                        return;
                    }
                }
            }
            if self.broker.is_none() && self.decision == AdmissionDecision::Pending {
                if session_status.is_some() || Instant::now() >= self.deadline {
                    self.refuse();
                    return;
                }
                if self.session_identity.is_none() {
                    let Ok(value) = ops.classify(self.sid) else {
                        return;
                    };
                    if value.class != Class::Session(self.sid) {
                        self.refuse();
                        return;
                    }
                    self.session_identity = Some(value.identity);
                }
                if let (Some(from_session), Some((pid, group))) =
                    (self.session_ready, self.broker_ready)
                {
                    if from_session != pid {
                        self.refuse();
                        return;
                    }
                    let Ok(value) = ops.classify(pid) else {
                        return;
                    };
                    if value.class != Class::Session(self.sid) {
                        self.refuse();
                        return;
                    }
                    let Ok(actual) = ops.keeper_group(value.identity, self.sid) else {
                        return;
                    };
                    if actual != group {
                        self.refuse();
                        return;
                    }
                    let Ok(binding) = ops.bind_exit(value, 1) else {
                        return;
                    };
                    if binding.identity != value.identity {
                        self.refuse();
                        return;
                    }
                    self.broker = Some(binding);
                }
            }
            if self.decision == AdmissionDecision::Pending && self.broker.is_some() {
                if ops.keeper_child_status(self.sid) != Ok(None) {
                    self.refuse();
                    return;
                }
                #[cfg(test)]
                if self
                    .admission_gate
                    .as_ref()
                    .is_some_and(|gate| !gate.after_admit && gate.pause())
                {
                    return;
                }
                self.commit_pending_admission(stop, admission);
            }
            #[cfg(test)]
            if self.decision == AdmissionDecision::Admit
                && self
                    .admission_gate
                    .as_ref()
                    .is_some_and(|gate| gate.after_admit && gate.pause())
            {
                return;
            }
            if let Some(binding) = &mut self.broker {
                match ops.observe_exit(&mut binding.handle) {
                    Ok(Some(event))
                        if event.pid == binding.identity.pid
                            && event.cookie == binding.cookie
                            && event.process_filter
                            && event.note_exit
                            && !event.error =>
                    {
                        self.completion.broker_terminal = true
                    }
                    Ok(None) => {}
                    _ => {
                        self.refuse();
                        return;
                    }
                }
            }
            if let Some(started) = stop {
                let signal = if started.elapsed() >= GRACE { 9 } else { 1 };
                if self.decision == AdmissionDecision::Admit
                    && !self.completion.drained
                    && self.stop_sent != signal
                    && self.send_broker(Frame {
                        operation: Operation::Stop,
                        fields: [signal as i64, 0, 0, 0],
                    })
                {
                    self.stop_sent = signal;
                }
            }
            if self.completion.drained
                && !self.exit_broker
                && self.send_broker(Frame {
                    operation: Operation::Exit,
                    fields: [0; 4],
                })
            {
                self.exit_broker = true;
            }
            if self.completion.drained && self.completion.broker_terminal {
                let Ok(snapshot) = ops.keeper_census(self.sid) else {
                    return;
                };
                let Some(reservation) = self.session_identity else {
                    self.refuse();
                    return;
                };
                if snapshot.iter().any(|value| value.identity != reservation) {
                    return;
                }
                self.completion.final_census = true;
                if session_status.is_none() {
                    if !self.exit_session
                        && self.send_session(Frame {
                            operation: Operation::Exit,
                            fields: [0; 4],
                        })
                    {
                        self.exit_session = true;
                    }
                } else {
                    // The final census and positive nonconsuming observation
                    // precede the sole consuming S attempt. No B wait is owned.
                    self.session_consumption_attempted = true;
                    match self.session.try_wait() {
                        Ok(Some(status)) => {
                            self.completion.session_wait = Some(status.code().unwrap_or(1))
                        }
                        _ => self.refuse(),
                    }
                }
            }
        }
    }
    #[cfg(test)]
    #[derive(Clone)]
    pub(in crate::darwin_process_scope) struct FixtureAuthority {
        shared: Arc<Shared>,
    }
    #[cfg(test)]
    pub(in crate::darwin_process_scope) struct FixtureSnapshot {
        pub sid: i32,
        pub app: Option<i32>,
        pub app_status: Option<i32>,
        pub not_started: bool,
        pub decision: AdmissionDecision,
        pub custody_lost: bool,
        pub session_status: Option<i32>,
        pub session_wait: Option<i32>,
        pub broker: Option<Identity>,
        pub broker_parent: Option<i32>,
        pub broker_terminal: bool,
        pub drained: bool,
        pub census: bool,
        pub keepers: Vec<(i32, Option<i32>, Option<i32>, Option<i32>)>,
        pub moves: Vec<i32>,
        pub consumed: bool,
    }
    #[cfg(test)]
    impl StartupDriver {
        pub fn fixture(&self) -> FixtureAuthority {
            FixtureAuthority {
                shared: Arc::clone(&self.shared),
            }
        }
    }
    #[cfg(test)]
    impl FixtureAuthority {
        pub fn pause_admission(&self, after_admit: bool) -> Arc<FixtureAdmissionGate> {
            let gate = Arc::new(FixtureAdmissionGate::new(after_admit));
            let mut core = self.shared.core.lock().unwrap();
            assert_eq!(core.decision, AdmissionDecision::Pending);
            core.admission_gate = Some(Arc::clone(&gate));
            gate
        }
        #[cfg(all(test, feature = "test-darwin-keeper"))]
        pub(in crate::darwin_process_scope) fn with_core_locked_for_fixture<R>(
            &self,
            inspect: impl FnOnce() -> R,
        ) -> R {
            let _core = self.shared.core.lock().unwrap();
            inspect()
        }
        pub fn snapshot(&self) -> Option<FixtureSnapshot> {
            let core = self.shared.core.try_lock().ok()?;
            Some(FixtureSnapshot {
                sid: core.sid,
                app: core.app,
                app_status: core.completion.application.status(),
                not_started: core.completion.application == AppDisposition::NotStarted,
                decision: core.decision,
                custody_lost: core.failed,
                session_status: core.session_terminal_observed,
                session_wait: core.completion.session_wait,
                broker: core.broker.as_ref().map(|b| b.identity),
                broker_parent: core.broker_parent,
                broker_terminal: core.completion.broker_terminal,
                drained: core.completion.drained,
                census: core.completion.final_census,
                keepers: core
                    .keepers
                    .iter()
                    .map(|k| (k.pid, k.group, k.terminal, k.wait))
                    .collect(),
                moves: core.moves.clone(),
                consumed: core.session_consumption_attempted,
            })
        }
        /// Failure-only rescue on already-qualified modern test hosts. This
        /// never produces a normal keeper receipt or validates compatibility.
        pub fn rescue(&self, end: Instant) -> bool {
            self.shared.stop.get_or_init(Instant::now);
            let Some(snapshot) = self.snapshot() else {
                return false;
            };
            if snapshot.consumed {
                return true;
            }
            let sid = snapshot.sid;
            // Stop helper dispatch before inspecting; these are nonblocking
            // endpoint shutdowns, not readiness waits under Core's mutex.
            if let Ok(mut core) = self.shared.core.try_lock() {
                core.refuse();
                core.session_control.shutdown();
                core.broker_control.shutdown();
            } else {
                return false;
            }
            let mut ops = native::NativeOps;
            while Instant::now() < end {
                let discoveries = <native::NativeOps as Ops<native::PtyChild>>::baseline(&mut ops)
                    .unwrap_or_default();
                for process in discoveries
                    .into_iter()
                    .filter(|p| p.class == Class::Session(sid))
                {
                    if let Ok(token) = ops.acquire_signal_token(process.identity, sid) {
                        let _ = ops.signal_exact(&token.handle, super::super::Signal::Kill);
                    }
                }
                if ops.keeper_census(sid).is_ok_and(|view| view.is_empty()) {
                    let Ok(mut core) = self.shared.core.try_lock() else {
                        return false;
                    };
                    if ops
                        .keeper_child_status(sid)
                        .is_ok_and(|status| status.is_some())
                    {
                        core.session_consumption_attempted = true;
                        return core.session.try_wait().is_ok_and(|status| status.is_some());
                    }
                }
                std::thread::sleep(INTERVAL);
            }
            false
        }
    }
}
#[cfg(target_os = "macos")]
pub(super) use owner::{KeeperOwner, StartupDriver};

#[cfg(all(test, target_os = "macos"))]
pub(super) use owner::{FixtureAuthority, FixtureSnapshot};
