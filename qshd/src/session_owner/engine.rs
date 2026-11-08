//! Stable spawning/waiting owner, deliberately not wired into daemon routing.
//! Retained NoScreen I/O uses one writer and checked independent recovery.
//! Screen admission and canonical screen recovery remain unavailable.
use super::protocol::OwnerProtocolError;
use super::recovery_runtime::{
    ConsumedRecovery, RecoveryError, RecoveryProducer, TransferAllowance,
};
use super::resource_contract::{Reservation, ReservationKind, ReservationReceipt};
use super::resources::{AdmittedReservation, OwnerResourceClient, StorageCharge};
pub use super::writer::{InputSubmission, WriterError};
use super::writer::{WriterShared, CONTROL_METADATA};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Condvar, Mutex, Weak};
use transport::auth::Principal;
use transport::channel::{ActiveChannel, ChannelSnapshot, OpenRequest, MAX_CHANNELS};
use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
use transport::channel_open::{
    ChannelOpenExecutor, CleanupStatus, OpenCustody, OpenIdentity, OpenJob, OpenOutcome,
    OpenRequestSnapshot, SessionOpenLedger,
};
use transport::channel_owner::{installation_epoch, RetainedChannelSet, RetainedCleanup};
use transport::channel_server::{ChannelSpawner, RestartSignal};
use transport::session_manager::LoginId;
use transport::session_resume::*;
use transport::SessionInputBudget;

pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> u64;
}
#[derive(Debug)]
pub enum EngineError {
    InvalidRequest,
    StaleAttachment,
    Unavailable,
    Resource(OwnerProtocolError),
    Opening,
    CleanupPending,
    Writer(WriterError),
    Recovery(RecoveryError),
}
impl From<OwnerProtocolError> for EngineError {
    fn from(e: OwnerProtocolError) -> Self {
        Self::Resource(e)
    }
}
struct LeaseState {
    state: AttachmentState,
    current: Option<Attachment>,
    writers: Vec<Weak<WriterShared>>,
    generation: u64,
    ready_generation: Option<u64>,
    closed: bool,
    last_recovery_request: u64,
}
/// Disposable lease only; it cannot own or terminate the child or its workers.
pub struct FrontendAttachment {
    shared: Arc<Mutex<LeaseState>>,
    attachment: Attachment,
}
impl FrontendAttachment {
    pub fn attachment(&self) -> Attachment {
        self.attachment
    }
}

impl Drop for FrontendAttachment {
    fn drop(&mut self) {
        let mut lease = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        // Stale proxy destruction cannot revoke a newer attachment. Abandon
        // revokes authority only and asserts neither writer fence nor cleanup.
        if lease.current == Some(self.attachment) && lease.state.abandon(self.attachment).is_ok() {
            lease.ready_generation = None;
            for writer in lease.writers.iter().filter_map(Weak::upgrade) {
                let _ = writer.request_fence(self.attachment);
            }
        }
    }
}

/// A bounded local barrier receipt; it cannot be manufactured by a frontend.
pub struct SessionFence {
    shared: Arc<Mutex<LeaseState>>,
    attachment: Attachment,
    tickets: [Option<(Arc<WriterShared>, u64)>; MAX_CHANNELS],
}
impl SessionFence {
    pub async fn completed(self) -> Result<Vec<(ChannelInstance, InputPosition)>, EngineError> {
        let mut positions = Vec::with_capacity(MAX_CHANNELS);
        for (writer, ticket) in self.tickets.iter().flatten() {
            let position = writer
                .wait_fence(*ticket, self.attachment)
                .await
                .map_err(EngineError::Writer)?;
            positions.push((writer.channel(), position));
        }
        let mut leases = self.shared.lock().map_err(|_| EngineError::Unavailable)?;
        leases
            .state
            .fenced(self.attachment)
            .map_err(|_| EngineError::StaleAttachment)?;
        Ok(positions)
    }
}

#[derive(Clone, Copy)]
struct ExpectedRecovery {
    channel: ChannelInstance,
    request: RequestId,
    recovery: RecoveryId,
    consumed: bool,
}
/// One bounded catalog and its privately consumed per-channel recovery proofs.
pub struct OwnerRecovery {
    catalog: RetainedCatalog,
    gate: Option<RecoveryGate>,
    generation: u64,
    remaining: usize,
    expected: [Option<ExpectedRecovery>; MAX_CHANNELS],
    _allowance: TransferAllowance,
}
impl OwnerRecovery {
    pub fn catalog(&self) -> &RetainedCatalog {
        &self.catalog
    }
    pub fn accept_consumed(&mut self, consumed: ConsumedRecovery) -> Result<(), EngineError> {
        let (completion, id, recovery, attachment, channel, host) = consumed.take();
        if !self._allowance.same_host(&host) {
            return Err(EngineError::Resource(OwnerProtocolError::Binding));
        }
        if attachment != self.catalog.attachment() {
            return Err(EngineError::StaleAttachment);
        }
        let slot = self
            .expected
            .iter_mut()
            .find(|entry| {
                entry.is_some_and(|e| {
                    e.channel == channel && e.request == id && e.recovery == recovery && !e.consumed
                })
            })
            .ok_or(EngineError::InvalidRequest)?;
        self.gate
            .as_mut()
            .ok_or(EngineError::Unavailable)?
            .complete_channel(completion)
            .map_err(|e| EngineError::Recovery(RecoveryError::Protocol(e)))?;
        slot.as_mut().unwrap().consumed = true;
        self.remaining -= 1;
        Ok(())
    }
}

pub struct OwnerChannelResources {
    pub history: Reservation,
    pub control: Reservation,
    pub cleanup: RequestId,
    pub read_buffer_bytes: usize,
    pub input_epoch: InputEpoch,
}
struct OutputState {
    bytes: Vec<u8>,
    start: u64,
    closed: bool,
    eof: bool,
    failed: bool,
}
struct SharedOutput {
    state: Mutex<OutputState>,
    changed: Condvar,
    capacity: usize,
}
struct OwnedChannel {
    instance: ChannelInstance,
    output: Arc<SharedOutput>,
    admitted: AdmittedReservation,
    writer: Arc<WriterShared>,
    request: OpenRequest,
    cleanup: RequestId,
    job: Option<OpenJob>,
    custody: OpenCustody,
    opening_worker: Option<tokio::task::JoinHandle<()>>,
    installed: bool,
}
pub struct SessionOwnerEngine {
    locator: SessionLocator,
    principal: Principal,
    login: LoginId,
    resources: OwnerResourceClient,
    clock: Arc<dyn MonotonicClock>,
    leases: Arc<Mutex<LeaseState>>,
    executor: ChannelOpenExecutor,
    session: Arc<SessionOpenLedger>,
    retained: RetainedChannelSet,
    channels: BTreeMap<u8, OwnedChannel>,
    restart: tokio::sync::watch::Receiver<RestartSignal>,
    input_budget: SessionInputBudget,
}
impl SessionOwnerEngine {
    pub fn new(
        locator: SessionLocator,
        principal: Principal,
        login: LoginId,
        spawner: Arc<dyn ChannelSpawner>,
        resources: OwnerResourceClient,
        clock: Arc<dyn MonotonicClock>,
        restart: tokio::sync::watch::Receiver<RestartSignal>,
    ) -> Result<Self, EngineError> {
        let registry = spawner.open_registry();
        let session = registry.session().map_err(|_| EngineError::Unavailable)?;
        Ok(Self {
            locator,
            principal,
            login,
            resources,
            clock,
            leases: Arc::new(Mutex::new(LeaseState {
                state: AttachmentState::new(),
                current: None,
                writers: Vec::new(),
                generation: 0,
                ready_generation: None,
                closed: false,
                last_recovery_request: 0,
            })),
            executor: ChannelOpenExecutor::new(spawner, registry.clone()),
            session,
            retained: RetainedChannelSet::new(registry),
            channels: BTreeMap::new(),
            restart,
            input_budget: SessionInputBudget::new(),
        })
    }
    /// The host must already have authenticated and authorized this exact lease.
    /// This local seam is not a frontend decoder or a grant issuer.
    pub fn attach_trusted(
        &mut self,
        attachment: Attachment,
    ) -> Result<FrontendAttachment, EngineError> {
        if attachment.locator != self.locator {
            return Err(EngineError::InvalidRequest);
        }
        let mut leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
        if leases.closed
            || self
                .channels
                .values()
                .any(|c| !c.installed || !c.writer.settled())
        {
            return Err(EngineError::Unavailable);
        }
        leases
            .state
            .begin_attach(attachment)
            .map_err(|_| EngineError::StaleAttachment)?;
        leases
            .state
            .attached(attachment)
            .map_err(|_| EngineError::StaleAttachment)?;
        leases.current = Some(attachment);
        leases.last_recovery_request = 0;
        leases.ready_generation = None;
        for writer in leases.writers.iter().filter_map(Weak::upgrade) {
            writer.assign(attachment).map_err(EngineError::Writer)?;
        }
        Ok(FrontendAttachment {
            shared: self.leases.clone(),
            attachment,
        })
    }
    fn admission(
        &self,
        frontend: &FrontendAttachment,
    ) -> Result<std::sync::MutexGuard<'_, LeaseState>, EngineError> {
        if !Arc::ptr_eq(&frontend.shared, &self.leases) {
            return Err(EngineError::StaleAttachment);
        }
        let leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
        if leases.closed
            || leases.current != Some(frontend.attachment)
            || leases.state.phase() != AttachmentPhase::Attached
        {
            return Err(EngineError::StaleAttachment);
        }
        Ok(leases)
    }
    fn validate(&self, frontend: &FrontendAttachment) -> Result<(), EngineError> {
        drop(self.admission(frontend)?);
        Ok(())
    }
    pub fn user_input(
        &self,
        frontend: &FrontendAttachment,
        instance: ChannelInstance,
        epoch: InputEpoch,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InputSubmission, EngineError> {
        // The same admission guard orders full validation/copy against revoke.
        let leases = self.admission(frontend)?;
        leases
            .state
            .validate_input(frontend.attachment)
            .map_err(|_| EngineError::Unavailable)?;
        if leases.ready_generation != Some(leases.generation) {
            return Err(EngineError::Unavailable);
        }
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        if !self.retained.catalog_active(instance) {
            return Err(EngineError::Unavailable);
        }
        owned
            .writer
            .submit(frontend.attachment, instance, epoch, offset, bytes)
            .map_err(EngineError::Writer)
    }
    /// Owner-generated replies use the same writer; no frontend record maps here.
    pub fn queue_owner_reply(
        &self,
        instance: ChannelInstance,
        bytes: &[u8],
    ) -> Result<InputSubmission, EngineError> {
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        owned.writer.reply(bytes).map_err(EngineError::Writer)
    }
    pub fn input_position(&self, instance: ChannelInstance) -> Result<InputPosition, EngineError> {
        self.channels
            .values()
            .find(|c| c.instance == instance && c.installed)
            .map(|c| c.writer.position())
            .ok_or(EngineError::InvalidRequest)
    }
    pub fn barriers_settled(&self) -> bool {
        self.channels.values().all(|c| c.writer.settled())
    }
    pub fn fence(&self, frontend: &FrontendAttachment) -> Result<SessionFence, EngineError> {
        if !Arc::ptr_eq(&frontend.shared, &self.leases) {
            return Err(EngineError::StaleAttachment);
        }
        let mut leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
        if leases.closed || leases.current != Some(frontend.attachment) {
            return Err(EngineError::StaleAttachment);
        }
        if leases.state.phase() != AttachmentPhase::Fencing {
            leases
                .state
                .begin_fence(frontend.attachment)
                .map_err(|_| EngineError::StaleAttachment)?;
        }
        leases.ready_generation = None;
        let mut tickets = std::array::from_fn(|_| None);
        for (slot, writer) in tickets
            .iter_mut()
            .zip(leases.writers.iter().filter_map(Weak::upgrade))
        {
            let ticket = writer
                .request_fence(frontend.attachment)
                .map_err(EngineError::Writer)?;
            *slot = Some((writer, ticket));
        }
        Ok(SessionFence {
            shared: self.leases.clone(),
            attachment: frontend.attachment,
            tickets,
        })
    }
    pub fn catalog_available(&self) -> bool {
        self.barriers_settled()
            && self.channels.values().all(|c| {
                c.installed && c.writer.can_catalog() && self.retained.catalog_active(c.instance)
            })
    }
    pub fn catalog(
        &self,
        frontend: &FrontendAttachment,
        allowance: TransferAllowance,
    ) -> Result<OwnerRecovery, EngineError> {
        let mut leases = self.admission(frontend)?;
        if !allowance.same_host(&self.resources) {
            return Err(EngineError::Resource(OwnerProtocolError::Binding));
        }
        if !allowance.matches_locator(frontend.attachment) || !self.barriers_settled() {
            return Err(EngineError::Unavailable);
        }
        let mut active = Vec::with_capacity(self.channels.len());
        let mut positions = Vec::with_capacity(self.channels.len());
        let metadata = std::mem::size_of::<OwnerRecovery>()
            + self
                .channels
                .values()
                .map(|c| {
                    c.request.command.len()
                        + std::mem::size_of::<ActiveChannel>()
                        + std::mem::size_of::<ChannelPosition>() * 3
                })
                .sum::<usize>();
        if metadata > 65536 {
            return Err(EngineError::Unavailable);
        }
        for owned in self.channels.values() {
            if !owned.installed
                || !self.retained.catalog_active(owned.instance)
                || !owned.writer.can_catalog()
            {
                return Err(EngineError::Unavailable);
            }
            let output = owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?;
            if output.closed || output.eof || output.failed {
                return Err(EngineError::Unavailable);
            }
            let request = owned.request.clone();
            if request.command.capacity() != request.command.len() {
                return Err(EngineError::Unavailable);
            }
            active.push(ActiveChannel {
                instance: owned.instance,
                request,
            });
            positions.push(ChannelPosition {
                channel: owned.instance,
                input: owned.writer.position(),
                output: OutputCursor {
                    channel: owned.instance,
                    offset: checked_end(output.start, output.bytes.len())
                        .map_err(|_| EngineError::Unavailable)?,
                },
                geometry: GeometryRecord {
                    instance: owned.instance,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: owned.request.cols,
                    rows: owned.request.rows,
                },
                lifecycle: ChannelLifecycle::Active,
            });
        }
        let snapshot =
            ChannelSnapshot::new(active, Vec::new()).map_err(|_| EngineError::Unavailable)?;
        let catalog = RetainedCatalog::new(frontend.attachment, snapshot, positions)
            .map_err(|_| EngineError::Unavailable)?;
        let next = leases
            .generation
            .checked_add(1)
            .ok_or(EngineError::Unavailable)?;
        leases
            .state
            .invalidate_recovery(frontend.attachment)
            .map_err(|_| EngineError::StaleAttachment)?;
        leases.generation = next;
        leases.ready_generation = None;
        let remaining = catalog.positions().len();
        let gate = RecoveryGate::new(&catalog);
        Ok(OwnerRecovery {
            catalog,
            gate: Some(gate),
            generation: leases.generation,
            remaining,
            expected: [None; MAX_CHANNELS],
            _allowance: allowance,
        })
    }
    pub fn recover(
        &self,
        frontend: &FrontendAttachment,
        transaction: &mut OwnerRecovery,
        request: RecoveryRequest,
        recovery_id: RecoveryId,
        request_id: RequestId,
        allowance: TransferAllowance,
    ) -> Result<RecoveryProducer, EngineError> {
        let mut leases = self.admission(frontend)?;
        if !allowance.same_host(&self.resources) {
            return Err(EngineError::Resource(OwnerProtocolError::Binding));
        }
        if request.attachment != frontend.attachment
            || transaction.catalog.attachment() != frontend.attachment
            || transaction.generation != leases.generation
            || !self.barriers_settled()
        {
            return Err(EngineError::StaleAttachment);
        }
        let position = transaction
            .catalog
            .positions()
            .iter()
            .find(|p| p.channel == request.channel)
            .ok_or(EngineError::InvalidRequest)?;
        let ParserContinuity::DataCursor { cursor } = request.parser else {
            return Err(EngineError::Unavailable);
        };
        if request_id.get() <= leases.last_recovery_request
            || cursor.channel != request.channel
            || transaction.expected.iter().flatten().any(|e| {
                e.channel == request.channel || e.request == request_id || e.recovery == recovery_id
            })
        {
            return Err(EngineError::InvalidRequest);
        }
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == request.channel)
            .ok_or(EngineError::InvalidRequest)?;
        let output = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        let start = cursor
            .offset
            .checked_sub(output.start)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(EngineError::Unavailable)?;
        let end = position
            .output
            .offset
            .checked_sub(output.start)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|v| *v <= output.bytes.len())
            .ok_or(EngineError::Unavailable)?;
        if start > end {
            return Err(EngineError::Unavailable);
        }
        let producer = RecoveryProducer::new(
            request,
            recovery_id,
            request_id,
            position.geometry,
            position.output,
            &output.bytes[start..end],
            allowance,
        )
        .map_err(EngineError::Recovery)?;
        let slot = transaction
            .expected
            .iter_mut()
            .find(|e| e.is_none())
            .ok_or(EngineError::Unavailable)?;
        *slot = Some(ExpectedRecovery {
            channel: request.channel,
            request: request_id,
            recovery: recovery_id,
            consumed: false,
        });
        leases.last_recovery_request = request_id.get();
        Ok(producer)
    }
    pub fn finish_recovery(
        &self,
        frontend: &FrontendAttachment,
        mut transaction: OwnerRecovery,
    ) -> Result<(), EngineError> {
        let mut leases = self.admission(frontend)?;
        if transaction.catalog.attachment() != frontend.attachment
            || transaction.generation != leases.generation
            || transaction.remaining != 0
            || transaction.expected.iter().flatten().any(|e| !e.consumed)
            || !self.barriers_settled()
        {
            return Err(EngineError::Unavailable);
        }
        transaction
            .gate
            .take()
            .ok_or(EngineError::Unavailable)?
            .enable_input(&mut leases.state)
            .map_err(|e| EngineError::Recovery(RecoveryError::Protocol(e)))?;
        leases.ready_generation = Some(leases.generation);
        for writer in leases.writers.iter().filter_map(Weak::upgrade) {
            writer
                .resume(frontend.attachment)
                .map_err(EngineError::Writer)?;
        }
        Ok(())
    }
    pub fn monotonic_now(&self) -> u64 {
        self.clock.now()
    }
    pub fn locator(&self) -> SessionLocator {
        self.locator
    }
    pub async fn open(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: OwnerChannelResources,
    ) -> Result<ChannelInstance, EngineError> {
        self.validate(frontend)?;
        if request.screen {
            return Err(EngineError::Unavailable);
        }
        validate_open(&request).map_err(|_| EngineError::InvalidRequest)?;
        if term
            .as_ref()
            .is_some_and(|name| name.capacity() > transport::channel::MAX_TERM_LEN)
        {
            return Err(EngineError::InvalidRequest);
        }
        if self.channels.len() >= MAX_CHANNELS
            || self.channels.contains_key(&request.stream)
            || supplied.read_buffer_bytes == 0
            || supplied.read_buffer_bytes > 16_384
        {
            return Err(EngineError::InvalidRequest);
        }
        terminal_size::TerminalSize::new(request.cols, request.rows)
            .map_err(|_| EngineError::InvalidRequest)?;
        let instance = supplied.history.channel;
        if self
            .channels
            .values()
            .any(|channel| channel.instance == instance)
        {
            return Err(EngineError::InvalidRequest);
        }
        for (reservation, kind) in [
            (supplied.history, ReservationKind::OutputHistory),
            (supplied.control, ReservationKind::ControlQueue),
        ] {
            if reservation.locator != self.locator
                || reservation.channel != instance
                || reservation.principal != self.resources.principal()
                || reservation.kind != kind
            {
                return Err(EngineError::InvalidRequest);
            }
        }
        // Payload and response/control state have independent preallocated slots.
        let metadata = std::mem::size_of::<OwnedChannel>()
            + std::mem::size_of::<WriterShared>()
            + std::mem::size_of::<LeaseState>()
            + std::mem::size_of::<SessionFence>();
        let command_backing = request
            .command
            .capacity()
            .checked_mul(2)
            .ok_or(EngineError::InvalidRequest)?;
        if metadata > CONTROL_METADATA
            || request.command.capacity() > transport::channel::MAX_COMMAND_LEN
            || supplied.control.bytes < (65536 + CONTROL_METADATA + command_backing) as u64
        {
            return Err(EngineError::InvalidRequest);
        }
        let charged =
            usize::try_from(supplied.history.bytes).map_err(|_| EngineError::InvalidRequest)?;
        let capacity = charged
            .checked_sub(supplied.read_buffer_bytes)
            .filter(|v| *v > 0)
            .ok_or(EngineError::InvalidRequest)?;
        // Host requests occur outside custody/lease locks, before any read backing.
        let history = self.resources.reserve(supplied.history, supplied.cleanup)?;
        let control = match self.resources.reserve(supplied.control, supplied.cleanup) {
            Ok(v) => v,
            Err(e) => {
                self.release_storage(&history, supplied.cleanup)?;
                return Err(e.into());
            }
        };
        let control_charge = StorageCharge::new(self.resources.clone(), control, supplied.cleanup);
        let (writing, worker) = match WriterShared::new(
            instance,
            supplied.input_epoch,
            self.input_budget.channel(),
            control_charge.clone(),
        ) {
            Ok(v) => v,
            Err(e) => {
                control_charge.allow_release();
                self.release_storage(&history, supplied.cleanup)?;
                return Err(EngineError::Writer(e));
            }
        };
        writing
            .assign(frontend.attachment)
            .map_err(EngineError::Writer)?;
        let mut bytes = Vec::new();
        let mut read_buffer = Vec::new();
        if bytes.try_reserve_exact(capacity).is_err()
            || read_buffer
                .try_reserve_exact(supplied.read_buffer_bytes)
                .is_err()
            || bytes
                .capacity()
                .checked_add(read_buffer.capacity())
                .is_none_or(|n| n > charged)
        {
            drop(bytes);
            drop(read_buffer);
            self.release_storage(&history, supplied.cleanup)?;
            control_charge.allow_release();
            return Err(EngineError::Unavailable);
        }
        read_buffer.resize(supplied.read_buffer_bytes, 0);
        let output = Arc::new(SharedOutput {
            state: Mutex::new(OutputState {
                bytes,
                start: 0,
                closed: false,
                eof: false,
                failed: false,
            }),
            changed: Condvar::new(),
            capacity,
        });
        let generation = frontend.attachment.epoch.get();
        let mut identity = OpenIdentity {
            session: self.session.id(),
            instance,
            stream: request.stream,
            generation,
            invalidation_epoch: 0,
        };
        let stream = request.stream;
        let retained_request = request.clone();
        let lease_owner = self.leases.clone();
        {
            let mut leases = lease_owner.lock().map_err(|_| EngineError::Unavailable)?;
            if !Arc::ptr_eq(&frontend.shared, &self.leases)
                || leases.closed
                || leases.current != Some(frontend.attachment)
                || leases.state.phase() != AttachmentPhase::Attached
            {
                drop(leases);
                drop(output);
                drop(read_buffer);
                drop(retained_request);
                control_charge.allow_release();
                self.release_storage(&history, supplied.cleanup)?;
                return Err(EngineError::StaleAttachment);
            }
            let admission_epoch = match installation_epoch(&self.restart) {
                Ok(epoch) => epoch,
                Err(_) => {
                    drop(leases);
                    drop(output);
                    drop(read_buffer);
                    drop(retained_request);
                    control_charge.allow_release();
                    self.release_storage(&history, supplied.cleanup)?;
                    return Err(EngineError::Opening);
                }
            };
            identity.invalidation_epoch = admission_epoch.epoch();
            if leases.writers.try_reserve(1).is_err() {
                drop(admission_epoch);
                drop(leases);
                drop(output);
                drop(read_buffer);
                drop(retained_request);
                control_charge.allow_release();
                self.release_storage(&history, supplied.cleanup)?;
                return Err(EngineError::Unavailable);
            }
            let Some(next_generation) = leases.generation.checked_add(1) else {
                drop(admission_epoch);
                drop(leases);
                drop(output);
                drop(read_buffer);
                drop(retained_request);
                control_charge.allow_release();
                self.release_storage(&history, supplied.cleanup)?;
                return Err(EngineError::Unavailable);
            };
            leases
                .state
                .invalidate_recovery(frontend.attachment)
                .map_err(|_| EngineError::StaleAttachment)?;
            leases.generation = next_generation;
            leases.ready_generation = None;
            let job = match self.executor.registry().try_reserve(
                &self.session,
                OpenRequestSnapshot {
                    owner: self.principal.clone(),
                    login: self.login,
                    request,
                    term,
                    identity,
                },
            ) {
                Ok(job) => job,
                Err(_) => {
                    drop(admission_epoch);
                    drop(leases);
                    drop(output);
                    drop(read_buffer);
                    self.release_storage(&history, supplied.cleanup)?;
                    control_charge.allow_release();
                    return Err(EngineError::Opening);
                }
            };
            let custody = job.custody().clone();
            self.channels.insert(
                stream,
                OwnedChannel {
                    instance,
                    output: output.clone(),
                    admitted: history,
                    writer: writing.clone(),
                    request: retained_request,
                    cleanup: supplied.cleanup,
                    job: Some(job),
                    custody,
                    opening_worker: None,
                    installed: false,
                },
            );
            leases.writers.push(Arc::downgrade(&writing));
            drop(admission_epoch);
        }
        let owned = self.channels.get_mut(&stream).unwrap();
        if self.executor.submit(owned.job.as_ref().unwrap()).is_err() {
            // submit errors precede scheduling: no possibly creating callback ran.
            drop(
                owned
                    .custody
                    .refuse_before_creation("retained opening was not scheduled".into()),
            );
            owned.job.take();
            let _ = owned.custody.retry_cleanup();
            return Err(EngineError::Opening);
        }
        owned.opening_worker = owned.job.as_ref().unwrap().take_worker();
        let outcome = loop {
            if let Some(outcome) = self.channels[&stream].job.as_ref().unwrap().take_outcome() {
                break outcome;
            }
            self.session.notified().await;
        };
        let OpenOutcome::Ready(channel) = outcome else {
            self.channels.get_mut(&stream).unwrap().job.take();
            return Err(EngineError::Opening);
        };
        let job = self.channels.get_mut(&stream).unwrap().job.take().unwrap();
        let prepared = self
            .retained
            .prepare(job, channel, identity)
            .map_err(|_| EngineError::Opening)?;
        let epoch = installation_epoch(&self.restart).map_err(|_| EngineError::Opening)?;
        {
            let leases = lease_owner.lock().map_err(|_| EngineError::Unavailable)?;
            if leases.closed
                || leases.current != Some(frontend.attachment)
                || leases.state.phase() != AttachmentPhase::Attached
            {
                return Err(EngineError::StaleAttachment);
            }
            prepared.commit(&epoch).map_err(|_| EngineError::Opening)?;
            self.channels.get_mut(&stream).unwrap().installed = true;
        }
        drop(epoch);
        let reading = output.clone();
        drop(output);
        self.retained
            .start_workers(
                instance,
                move |reader| read_output(reader, reading, read_buffer),
                move |writer| worker.run(writer),
            )
            .map_err(|_| EngineError::Opening)?;
        self.validate(frontend)?;
        if !self.retained.ready_to_publish(instance) {
            return Err(EngineError::Opening);
        }
        Ok(instance)
    }
    pub fn copy_output(
        &self,
        frontend: &FrontendAttachment,
        instance: ChannelInstance,
        offset: u64,
        into: &mut [u8],
    ) -> Result<usize, EngineError> {
        let _admission = self.admission(frontend)?;
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance)
            .ok_or(EngineError::InvalidRequest)?;
        let output = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        let relative = offset
            .checked_sub(output.start)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|v| *v <= output.bytes.len())
            .ok_or(EngineError::InvalidRequest)?;
        let n = into.len().min(output.bytes.len() - relative);
        into[..n].copy_from_slice(&output.bytes[relative..relative + n]);
        Ok(n)
    }
    pub fn acknowledge_output(
        &self,
        frontend: &FrontendAttachment,
        instance: ChannelInstance,
        offset: u64,
    ) -> Result<(), EngineError> {
        let _admission = self.admission(frontend)?;
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance)
            .ok_or(EngineError::InvalidRequest)?;
        let mut output = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        let n = offset
            .checked_sub(output.start)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|v| *v <= output.bytes.len())
            .ok_or(EngineError::InvalidRequest)?;
        output.bytes.drain(..n);
        output.start = offset;
        owned.output.changed.notify_all();
        Ok(())
    }
    fn release_storage(
        &self,
        admitted: &AdmittedReservation,
        cleanup: RequestId,
    ) -> Result<(), EngineError> {
        let r = admitted.reservation();
        self.resources.release(
            admitted,
            ReservationReceipt {
                id: cleanup,
                reservation: r.id,
                locator: r.locator,
                channel: r.channel,
            },
        )?;
        Ok(())
    }
    /// Host-authorized explicit close. EOF/Drop of an attachment never calls it.
    pub async fn close_session(&mut self) -> Result<Vec<RetainedCleanup>, EngineError> {
        {
            let mut leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
            leases.closed = true;
            leases.ready_generation = None;
            if let Some(current) = leases.current {
                let _ = leases.state.invalidate_recovery(current);
            }
            self.input_budget.close();
            for writer in leases.writers.iter().filter_map(Weak::upgrade) {
                writer.close();
            }
        }
        for owned in self.channels.values_mut() {
            owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?
                .closed = true;
            owned.output.changed.notify_all();
            owned.writer.close();
            if let Some(job) = owned.job.take() {
                job.cancel();
            }
        }
        self.retained.close_all();
        let mut completed = Vec::new();
        while self.retained.channels() != 0 {
            completed.push(self.retained.next_cleanup().await);
        }
        self.retained
            .join_workers()
            .await
            .map_err(|_| EngineError::CleanupPending)?;
        for owned in self.channels.values_mut() {
            if let Some(worker) = owned.opening_worker.take() {
                worker.await.map_err(|_| EngineError::CleanupPending)?;
            }
            if !owned.installed
                && !matches!(owned.custody.retry_cleanup(), CleanupStatus::Confirmed(_))
            {
                return Err(EngineError::CleanupPending);
            }
        }
        {
            let mut leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
            drop(std::mem::take(&mut leases.writers));
        }
        // No reader, writer or spawning worker retains backing at this point.
        let channels = std::mem::take(&mut self.channels);
        for (_, owned) in channels {
            let OwnedChannel {
                output,
                admitted,
                writer,
                request,
                cleanup,
                ..
            } = owned;
            drop(output);
            drop(request);
            writer.allow_release();
            drop(writer);
            self.release_storage(&admitted, cleanup)?;
        }
        Ok(completed)
    }
}
impl Drop for SessionOwnerEngine {
    fn drop(&mut self) {
        // Unexpected owner teardown keeps resource debt, and still asks the
        // existing exact reaper to finish; it never treats Drop as a receipt.
        {
            let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
            leases.closed = true;
            leases.ready_generation = None;
            if let Some(current) = leases.current {
                let _ = leases.state.invalidate_recovery(current);
            }
            self.input_budget.close();
            for writer in leases.writers.iter().filter_map(Weak::upgrade) {
                writer.close();
            }
        }
        for owned in self.channels.values_mut() {
            owned
                .output
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closed = true;
            owned.output.changed.notify_all();
            owned.writer.close();
            if let Some(job) = owned.job.take() {
                job.cancel();
            }
        }
        self.retained.close_all();
    }
}

fn read_output(mut reader: Box<dyn Read + Send>, output: Arc<SharedOutput>, mut buffer: Vec<u8>) {
    loop {
        let allowance = {
            let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
            while !state.closed && state.bytes.len() == output.capacity {
                state = output
                    .changed
                    .wait(state)
                    .unwrap_or_else(|e| e.into_inner());
            }
            if state.closed {
                return;
            }
            buffer.len().min(output.capacity - state.bytes.len())
        };
        // Exactly one reader and a precharged slice. No engine/custody lock is
        // held across blocking I/O; a full NoScreen queue stops the next read.
        match reader.read(&mut buffer[..allowance]) {
            Ok(0) => {
                output.state.lock().unwrap_or_else(|e| e.into_inner()).eof = true;
                return;
            }
            Ok(n) => {
                let mut state = output.state.lock().unwrap_or_else(|e| e.into_inner());
                if state
                    .start
                    .checked_add(state.bytes.len() as u64)
                    .and_then(|v| v.checked_add(n as u64))
                    .is_none()
                {
                    state.failed = true;
                    return;
                }
                state.bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                output
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .failed = true;
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
