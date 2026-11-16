//! Stable spawning/waiting owner, deliberately not wired into daemon routing.
//! Retained NoScreen I/O uses one writer and checked independent recovery.
//! Screen admission and canonical screen recovery remain unavailable.
use super::output::{read_output, OutputModel, OutputState, SharedOutput};
use super::protocol::OwnerProtocolError;
use super::recovery_runtime::{
    ConsumedRecovery, RecoveryError, RecoveryProducer, TransferAllowance,
};
use super::resource_contract::{Reservation, ReservationKind};
use super::resources::{AdmittedReservation, OwnerResourceClient, StorageCharge};
use super::screen_control::{ControlTicket, ScreenControlContext};
pub use super::writer::{InputSubmission, WriterError};
use super::writer::{WriterShared, CONTROL_METADATA};
use std::collections::BTreeMap;
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
        self.wait_completed().await
    }
    pub(super) async fn wait_completed(
        &self,
    ) -> Result<Vec<(ChannelInstance, InputPosition)>, EngineError> {
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
        if !self._allowance.matches_client(&host) {
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

/// Host-minted reservations consumed once by the retained open pipeline.
pub(crate) struct AdmittedOwnerChannelResources {
    history: AdmittedReservation,
    control: AdmittedReservation,
    read_buffer_bytes: usize,
    input_epoch: InputEpoch,
}
impl AdmittedOwnerChannelResources {
    pub(crate) fn new(
        history: AdmittedReservation,
        control: AdmittedReservation,
        read_buffer_bytes: usize,
        input_epoch: InputEpoch,
    ) -> Self {
        Self {
            history,
            control,
            read_buffer_bytes,
            input_epoch,
        }
    }
}
/// Exclusive tokens which have not reached any backing or worker. Cancellation
/// before transfer can release this proved-unused custody, never a live channel.
struct UnstartedAdmittedOpen {
    client: OwnerResourceClient,
    tokens: Option<(AdmittedReservation, AdmittedReservation)>,
}
impl UnstartedAdmittedOpen {
    fn new(
        client: OwnerResourceClient,
        history: AdmittedReservation,
        control: AdmittedReservation,
    ) -> Self {
        Self {
            client,
            tokens: Some((history, control)),
        }
    }
    fn take(mut self) -> (AdmittedReservation, AdmittedReservation) {
        self.tokens.take().unwrap()
    }
}
impl Drop for UnstartedAdmittedOpen {
    fn drop(&mut self) {
        if let Some((history, control)) = self.tokens.take() {
            for token in [history, control] {
                let cleanup = token.cleanup();
                let charge = StorageCharge::owned(self.client.clone(), token, cleanup);
                charge.allow_release();
            }
        }
    }
}
pub struct OwnerChannelResources {
    pub history: Reservation,
    pub control: Reservation,
    pub cleanup: RequestId,
    pub read_buffer_bytes: usize,
    pub input_epoch: InputEpoch,
}
struct OwnedChannel {
    instance: ChannelInstance,
    output: Arc<SharedOutput>,
    admitted: Arc<StorageCharge>,
    writer: Arc<WriterShared>,
    request: OpenRequest,
    cleanup: RequestId,
    job: Option<OpenJob>,
    custody: OpenCustody,
    opening_worker: Option<tokio::task::JoinHandle<()>>,
    installed: bool,
    opening_failed: bool,
    last_resize: Option<(Attachment, u64)>,
}
pub(super) struct LocalEmptyCompletion {
    binding: Weak<super::host_engine::LocalBinding>,
    locator: SessionLocator,
    client: OwnerResourceClient,
}
impl LocalEmptyCompletion {
    pub(super) fn matches(
        &self,
        binding: &Arc<super::host_engine::LocalBinding>,
        locator: SessionLocator,
        client: &OwnerResourceClient,
    ) -> bool {
        self.binding
            .upgrade()
            .is_some_and(|actual| Arc::ptr_eq(&actual, binding))
            && self.locator == locator
            && self.client.same_registration(client)
    }
}
pub(super) struct LocalEstablishment {
    binding: Weak<super::host_engine::LocalBinding>,
    locator: SessionLocator,
    client: OwnerResourceClient,
}
impl LocalEstablishment {
    pub(super) fn matches(
        &self,
        binding: &Arc<super::host_engine::LocalBinding>,
        locator: SessionLocator,
        client: &OwnerResourceClient,
    ) -> bool {
        self.binding
            .upgrade()
            .is_some_and(|actual| Arc::ptr_eq(&actual, binding))
            && self.locator == locator
            && self.client.same_registration(client)
    }
}
pub(super) struct LocalCompletion {
    binding: Weak<super::host_engine::LocalBinding>,
    locator: SessionLocator,
    client: OwnerResourceClient,
    facts: Vec<super::host::CompletedChannelFact>,
}
impl LocalCompletion {
    pub(super) fn matches(
        &self,
        binding: &Arc<super::host_engine::LocalBinding>,
        locator: SessionLocator,
        client: &OwnerResourceClient,
    ) -> bool {
        self.binding
            .upgrade()
            .is_some_and(|actual| Arc::ptr_eq(&actual, binding))
            && self.locator == locator
            && self.client.same_registration(client)
    }
    pub(super) fn into_facts(self) -> Vec<super::host::CompletedChannelFact> {
        self.facts
    }
    pub(super) fn facts(&self) -> &[super::host::CompletedChannelFact] {
        &self.facts
    }
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
    /// Exact-reaper receipts already consumed by an unfinished close. They
    /// outlive a cancelled or failed close future until one close returns them.
    close_receipts: Vec<RetainedCleanup>,
    channels: BTreeMap<u8, OwnedChannel>,
    restart: tokio::sync::watch::Receiver<RestartSignal>,
    input_budget: SessionInputBudget,
    screen_factory: Option<Arc<super::screen_owner::RetainedScreenFactory>>,
    screen_control: Option<ScreenControlContext>,
    control_ticket: Option<ControlTicket>,
    control_joined: bool,
    control_failed: bool,
    ever_established: bool,
    local_binding: Option<Weak<super::host_engine::LocalBinding>>,
    local_establishment: Option<LocalEstablishment>,
    local_completion: Option<LocalCompletion>,
    close_facts: Option<Vec<super::host::CompletedChannelFact>>,
    cleanup_complete: bool,
    facts_captured: bool,
}
impl SessionOwnerEngine {
    pub(super) fn bind_local_binding(&mut self, binding: &Arc<super::host_engine::LocalBinding>) {
        self.local_binding = Some(Arc::downgrade(binding));
    }
    pub(super) fn take_local_establishment(&mut self) -> Option<LocalEstablishment> {
        self.local_establishment.take()
    }
    pub(super) fn take_local_completion(&mut self) -> Option<LocalCompletion> {
        self.local_completion.take()
    }
    pub(super) fn locally_established(&self) -> bool {
        self.ever_established
    }
    pub(super) fn matches_local_binding(
        &self,
        locator: SessionLocator,
        client: &OwnerResourceClient,
        uid: u32,
        name: &str,
    ) -> bool {
        self.leases
            .lock()
            .is_ok_and(|lease| !lease.closed && lease.current.is_none())
            && self.channels.is_empty()
            && self.control_ticket.is_none()
            && self.local_binding.is_none()
            && self.locator == locator
            && self.resources.same_registration(client)
            && self.principal.uid == uid
            && self.principal.name == name
    }
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
            close_receipts: Vec::new(),
            channels: BTreeMap::new(),
            restart,
            input_budget: SessionInputBudget::new(),
            screen_factory: None,
            screen_control: None,
            control_ticket: None,
            control_joined: false,
            control_failed: false,
            ever_established: false,
            local_binding: None,
            local_establishment: None,
            local_completion: None,
            close_facts: None,
            cleanup_complete: false,
            facts_captured: false,
        })
    }
    pub fn with_screen_factory(
        mut self,
        factory: Arc<super::screen_owner::RetainedScreenFactory>,
    ) -> Self {
        self.screen_factory = Some(factory);
        self
    }
    pub fn with_screen_control(mut self, context: ScreenControlContext) -> Self {
        self.screen_control = Some(context);
        self
    }
    #[cfg(test)]
    pub(super) fn control_identity_for_test(&self) -> Option<usize> {
        self.control_ticket
            .as_ref()
            .map(|ticket| ticket.identity_for_test())
    }
    pub fn control_joined(&self) -> bool {
        self.control_joined
    }
    pub async fn open_screen(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: OwnerChannelResources,
        lease: super::screen_owner::HostScreenLease,
    ) -> Result<ChannelInstance, EngineError> {
        drop(self.attachment_admission(frontend)?);
        let size = terminal_size::TerminalSize::new(request.cols, request.rows)
            .map_err(|_| EngineError::InvalidRequest)?;
        if !request.screen
            || self.screen_factory.is_none()
            || self.screen_control.is_none()
            || !lease.matches(
                &self.resources,
                self.locator,
                supplied.history.channel,
                size,
            )
        {
            return Err(EngineError::Unavailable);
        }
        self.ensure_screen_control(frontend, supplied.history.channel)
            .await?;
        self.open_impl(frontend, request, term, supplied, Some(lease), None)
            .await
    }
    /// The host must already have authenticated and authorized this exact lease.
    /// This local seam is not a frontend decoder or a grant issuer.
    pub(super) fn attach_trusted(
        &mut self,
        attachment: Attachment,
    ) -> Result<FrontendAttachment, EngineError> {
        if self.control_failed || self.control_ticket.as_ref().is_some_and(|t| !t.healthy()) {
            return Err(EngineError::Unavailable);
        }
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
        if self.control_failed || self.control_ticket.as_ref().is_some_and(|t| !t.healthy()) {
            return Err(EngineError::Unavailable);
        }
        self.attachment_admission(frontend)
    }
    fn attachment_admission(
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
        let mut output = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        if output.busy
            || owned
                .output
                .drain_reply(&mut output)
                .map_err(EngineError::Writer)?
        {
            return Err(EngineError::Writer(WriterError::Busy));
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
        if self.control_failed || self.control_ticket.as_ref().is_some_and(|t| !t.healthy()) {
            return Err(EngineError::Unavailable);
        }
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        let mut output = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        if output.busy
            || owned
                .output
                .drain_reply(&mut output)
                .map_err(EngineError::Writer)?
        {
            return Err(EngineError::Writer(WriterError::Busy));
        }
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
        !self.control_failed
            && self.control_ticket.as_ref().is_none_or(|t| t.healthy())
            && self.barriers_settled()
            && self.channels.values().all(|c| {
                if !c.installed
                    || !c.writer.can_catalog()
                    || !self.retained.catalog_active(c.instance)
                {
                    return false;
                }
                let output = c.output.state.lock().unwrap_or_else(|e| e.into_inner());
                !output.closed
                    && !output.failed
                    && !output.eof
                    && !output.busy
                    && !output.replies_pending()
            })
    }
    #[cfg(test)]
    pub(super) fn consumed_close_receipts_for_test(&self) -> usize {
        self.close_receipts.len()
    }
    #[cfg(test)]
    pub(super) fn writer_identity_for_test(&self, channel: ChannelInstance) -> Option<usize> {
        self.channels
            .values()
            .find(|owned| owned.instance == channel)
            .map(|owned| Arc::as_ptr(&owned.writer) as usize)
    }
    #[cfg(test)]
    pub(super) fn output_bounds_for_test(&self, channel: ChannelInstance) -> (u64, u64) {
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == channel)
            .unwrap();
        let output = owned.output.state.lock().unwrap();
        (
            output.start,
            checked_end(output.start, output.bytes.len()).unwrap(),
        )
    }
    #[cfg(test)]
    pub(super) fn screen_snapshot_for_test(
        &self,
        channel: ChannelInstance,
    ) -> (u64, terminal::StateSnapshot) {
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == channel)
            .unwrap();
        let mut output = owned.output.state.lock().unwrap();
        assert!(!output.busy && !output.failed);
        let end = checked_end(output.start, output.bytes.len()).unwrap();
        let screen = &mut output.model.as_mut().unwrap().screen;
        assert!(screen.sync_deadline().is_none());
        let actual = (&mut **screen as &mut dyn std::any::Any)
            .downcast_mut::<crate::screen::PtyScreen>()
            .unwrap()
            .snapshot();
        (end, actual)
    }
    pub fn catalog(
        &self,
        frontend: &FrontendAttachment,
        allowance: TransferAllowance,
    ) -> Result<OwnerRecovery, EngineError> {
        let mut leases = self.admission(frontend)?;
        if !allowance.matches_client(&self.resources) {
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
            if output.closed
                || output.eof
                || output.failed
                || output.busy
                || output.replies_pending()
            {
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
                geometry: output.geometry,
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
        if !allowance.matches_client(&self.resources) {
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
        if output.has_screen {
            return Err(EngineError::Unavailable);
        }
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
    pub fn screen_recovery_requirements(
        &self,
        instance: ChannelInstance,
    ) -> Result<super::screen_recovery::ScreenRecoveryRequirements, EngineError> {
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == instance && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        let state = owned
            .output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?;
        if !state.has_screen || state.busy || state.failed || state.closed {
            return Err(EngineError::Unavailable);
        }
        let envelope = state
            .model
            .as_ref()
            .and_then(|m| m.envelope)
            .ok_or(EngineError::Unavailable)?;
        let size = terminal_size::TerminalSize::new(state.geometry.cols, state.geometry.rows)
            .map_err(|_| EngineError::Unavailable)?;
        super::screen_recovery::ScreenRecoveryRequirements::new(envelope, size)
            .map_err(EngineError::Recovery)
    }
    // Parser evidence stays explicit beside the existing recovery correlations.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_screen(
        &self,
        frontend: &FrontendAttachment,
        transaction: &mut OwnerRecovery,
        request: RecoveryRequest,
        evidence: &super::screen_recovery::ScreenEvidence,
        recovery_id: RecoveryId,
        request_id: RequestId,
        allowance: super::screen_recovery::ScreenRecoveryAllowance,
    ) -> Result<RecoveryProducer, EngineError> {
        let leases = self.admission(frontend)?;
        if request.attachment != frontend.attachment
            || transaction.catalog.attachment() != frontend.attachment
            || transaction.generation != leases.generation
            || !self.barriers_settled()
        {
            return Err(EngineError::StaleAttachment);
        }
        if request_id.get() <= leases.last_recovery_request
            || matches!(request.parser, ParserContinuity::DataCursor { .. })
            || transaction.expected.iter().flatten().any(|e| {
                e.channel == request.channel || e.request == request_id || e.recovery == recovery_id
            })
        {
            return Err(EngineError::InvalidRequest);
        }
        let position = *transaction
            .catalog
            .positions()
            .iter()
            .find(|p| p.channel == request.channel)
            .ok_or(EngineError::InvalidRequest)?;
        drop(leases);
        let owned = self
            .channels
            .values()
            .find(|c| c.instance == request.channel && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        let quote = self.screen_recovery_requirements(request.channel)?;
        if !allowance.matches(&self.resources, request, quote) {
            return Err(EngineError::Resource(OwnerProtocolError::Binding));
        }
        // Host admission happened before taking/parking the actual model.
        let mut operation =
            super::output::ModelOperation::take(&owned.output).map_err(EngineError::Writer)?;
        let (mode, gap, mut bytes) = {
            let state = owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?;
            if !state.has_screen
                || state.geometry != position.geometry
                || checked_end(state.start, state.bytes.len())
                    .map_err(|_| EngineError::Unavailable)?
                    != position.output.offset
            {
                return Err(EngineError::Unavailable);
            }
            let cursor = match request.parser {
                ParserContinuity::Retained { cursor, .. } => Some(cursor),
                _ => None,
            };
            let replay = cursor.filter(|cursor| {
                cursor.channel == request.channel
                    && cursor.offset >= state.start
                    && cursor.offset <= position.output.offset
                    && evidence.matches(
                        &self.resources,
                        request,
                        state.geometry,
                        state.geometry_start,
                    )
            });
            if let Some(cursor) = replay {
                let from = usize::try_from(cursor.offset - state.start)
                    .map_err(|_| EngineError::Unavailable)?;
                let mut bytes = allowance
                    .transfer
                    .buffer(state.bytes.len() - from)
                    .map_err(EngineError::Recovery)?;
                bytes.extend_from_slice(&state.bytes[from..]);
                (RecoveryMode::Replay, false, bytes)
            } else {
                (
                    RecoveryMode::ScreenReset,
                    cursor.map_or(state.start > 0, |c| c.offset < state.start),
                    Vec::new(),
                )
            }
        };
        if mode == RecoveryMode::Replay {
            // A checkpoint executes every fresh byte at its boundary once,
            // including synchronized output whose timer has not fired yet.
            let replies = operation
                .model
                .as_mut()
                .unwrap()
                .screen
                .flush_pending_output()
                .map_err(|_| {
                    owned
                        .output
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .failed = true;
                    EngineError::Unavailable
                })?;
            let mut state = owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?;
            owned.output.retain_replies(&mut state, replies);
            owned
                .output
                .drain_reply(&mut state)
                .map_err(EngineError::Writer)?;
        }
        if mode == RecoveryMode::ScreenReset {
            let repaint = operation
                .model
                .as_mut()
                .unwrap()
                .screen
                .repaint()
                .map_err(|_| {
                    owned
                        .output
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .failed = true;
                    EngineError::Unavailable
                })?;
            if repaint.bytes.len() > quote.max_bytes
                || repaint.bytes.capacity() > 2 * quote.max_bytes
            {
                owned
                    .output
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .failed = true;
                return Err(EngineError::Unavailable);
            }
            bytes = repaint.bytes;
            let mut state = owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?;
            owned.output.retain_replies(&mut state, repaint.replies);
            owned
                .output
                .drain_reply(&mut state)
                .map_err(EngineError::Writer)?;
        }
        let start = RecoveryStart {
            attachment: request.attachment,
            channel: request.channel,
            recovery_id,
            mode,
            boundary: position.output,
            gap,
            geometry: position.geometry,
            total_bytes: bytes.len() as u64,
            snapshot_version: if mode == RecoveryMode::ScreenReset {
                1
            } else {
                0
            },
        };
        let producer = RecoveryProducer::from_owned(
            start,
            request_id,
            bytes,
            allowance.transfer,
            Some(allowance.scratch),
        )
        .map_err(EngineError::Recovery)?;
        drop(operation);
        let mut leases = self.admission(frontend)?;
        if transaction.generation != leases.generation {
            return Err(EngineError::StaleAttachment);
        }
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
        for owned in self.channels.values() {
            let mut output = owned
                .output
                .state
                .lock()
                .map_err(|_| EngineError::Unavailable)?;
            if output.busy
                || owned
                    .output
                    .drain_reply(&mut output)
                    .map_err(EngineError::Writer)?
            {
                return Err(EngineError::Unavailable);
            }
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
    async fn ensure_screen_control(
        &mut self,
        frontend: &FrontendAttachment,
        anchor: ChannelInstance,
    ) -> Result<(), EngineError> {
        drop(self.attachment_admission(frontend)?);
        if self.control_failed {
            return Err(EngineError::Unavailable);
        }
        if self.control_ticket.is_none() {
            let ticket = self
                .screen_control
                .as_mut()
                .ok_or(EngineError::Unavailable)?
                .begin_start(self.resources.clone(), self.locator, anchor)
                .map_err(|_| EngineError::Unavailable)?;
            // Store the exact ticket synchronously before readiness can suspend.
            self.control_ticket = Some(ticket);
        }
        if self.control_ticket.as_ref().unwrap().ready().await.is_err() {
            self.control_failed = true;
            return Err(EngineError::Unavailable);
        }
        self.validate(frontend)
    }
    pub(crate) async fn open_screen_admitted(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: AdmittedOwnerChannelResources,
        lease: super::screen_owner::HostScreenLease,
    ) -> Result<ChannelInstance, EngineError> {
        drop(self.attachment_admission(frontend)?);
        let (raw, history, control) = self.validate_admitted_open(supplied)?;
        let size = terminal_size::TerminalSize::new(request.cols, request.rows)
            .map_err(|_| EngineError::InvalidRequest)?;
        if !request.screen
            || self.screen_factory.is_none()
            || self.screen_control.is_none()
            || !lease.matches(&self.resources, self.locator, raw.history.channel, size)
        {
            return Err(EngineError::Unavailable);
        }
        let unstarted = UnstartedAdmittedOpen::new(self.resources.clone(), history, control);
        self.ensure_screen_control(frontend, raw.history.channel)
            .await?;
        self.open_impl(frontend, request, term, raw, Some(lease), Some(unstarted))
            .await
    }
    pub(crate) async fn open_admitted(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: AdmittedOwnerChannelResources,
    ) -> Result<ChannelInstance, EngineError> {
        self.validate(frontend)?;
        let (raw, history, control) = self.validate_admitted_open(supplied)?;
        let unstarted = UnstartedAdmittedOpen::new(self.resources.clone(), history, control);
        self.open_impl(frontend, request, term, raw, None, Some(unstarted))
            .await
    }
    fn validate_admitted_open(
        &self,
        supplied: AdmittedOwnerChannelResources,
    ) -> Result<
        (
            OwnerChannelResources,
            AdmittedReservation,
            AdmittedReservation,
        ),
        EngineError,
    > {
        self.resources.validate_admitted(&supplied.history, None)?;
        self.resources.validate_admitted(&supplied.control, None)?;
        let history = supplied.history.reservation();
        let control = supplied.control.reservation();
        if supplied.history.cleanup() != supplied.control.cleanup()
            || history.kind != ReservationKind::OutputHistory
            || control.kind != ReservationKind::ControlQueue
            || history.locator != self.locator
            || control.locator != self.locator
            || history.channel != control.channel
            || history.id == control.id
            || history.screen_charge.is_some()
            || control.screen_charge.is_some()
            || supplied.read_buffer_bytes == 0
            || supplied.read_buffer_bytes > 16_384
            || history.bytes <= supplied.read_buffer_bytes as u64
            || control.bytes < (65_536 + CONTROL_METADATA) as u64
        {
            return Err(EngineError::InvalidRequest);
        }
        let raw = OwnerChannelResources {
            history: supplied.history.reservation(),
            control: supplied.control.reservation(),
            cleanup: supplied.history.cleanup(),
            read_buffer_bytes: supplied.read_buffer_bytes,
            input_epoch: supplied.input_epoch,
        };
        Ok((raw, supplied.history, supplied.control))
    }
    pub async fn open(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: OwnerChannelResources,
    ) -> Result<ChannelInstance, EngineError> {
        self.open_impl(frontend, request, term, supplied, None, None)
            .await
    }
    async fn open_impl(
        &mut self,
        frontend: &FrontendAttachment,
        request: OpenRequest,
        term: Option<String>,
        supplied: OwnerChannelResources,
        model_lease: Option<super::screen_owner::HostScreenLease>,
        admitted: Option<UnstartedAdmittedOpen>,
    ) -> Result<ChannelInstance, EngineError> {
        self.validate(frontend)?;
        if request.screen != model_lease.is_some() {
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
        let metadata = 2
            * (std::mem::size_of::<StorageCharge>() + 2 * std::mem::size_of::<usize>())
            + std::mem::size_of::<super::host::CompletedChannelFact>()
            + std::mem::size_of::<(Arc<StorageCharge>, Arc<WriterShared>)>()
            + std::mem::size_of::<OwnedChannel>()
            + std::mem::size_of::<WriterShared>()
            + std::mem::size_of::<LeaseState>()
            + std::mem::size_of::<SessionFence>()
            + std::mem::size_of::<OutputState>()
            + std::mem::size_of::<SharedOutput>()
            + std::mem::size_of::<OutputModel>()
            + std::mem::size_of::<super::output::ModelOperation>();
        let command_backing = request
            .command
            .capacity()
            .checked_mul(if request.screen { 3 } else { 2 })
            .and_then(|n| {
                if request.screen {
                    n.checked_add(self.principal.name.len())?
                        .checked_add(self.principal.identity.len())
                } else {
                    Some(n)
                }
            })
            .ok_or(EngineError::InvalidRequest)?;
        if metadata > CONTROL_METADATA
            || request.command.capacity() > transport::channel::MAX_COMMAND_LEN
            || supplied.control.bytes
                < ((if request.screen {
                    4 * 65536 + super::screen_owner::RetainedScreenFactory::backing_bound()
                } else {
                    65536
                }) + CONTROL_METADATA
                    + command_backing) as u64
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
        let (history, control) = if let Some(unstarted) = admitted {
            let (history, control) = unstarted.take();
            (
                StorageCharge::new(self.resources.clone(), history, supplied.cleanup),
                control,
            )
        } else {
            let history = self.resources.reserve(supplied.history, supplied.cleanup)?;
            let history = StorageCharge::new(self.resources.clone(), history, supplied.cleanup);
            let control = match self.resources.reserve(supplied.control, supplied.cleanup) {
                Ok(v) => v,
                Err(e) => {
                    self.release_storage(&history, supplied.cleanup)?;
                    return Err(e.into());
                }
            };
            (history, control)
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
            state: Mutex::new(OutputState::new(
                bytes,
                GeometryRecord {
                    instance,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: request.cols,
                    rows: request.rows,
                },
            )),
            changed: Condvar::new(),
            capacity,
            writer: Some(writing.clone()),
            wake: self
                .control_ticket
                .as_ref()
                .map(|t| t.wake_handle())
                .unwrap_or_default(),
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
                    opening_failed: false,
                    last_resize: None,
                },
            );
            leases.writers.push(Arc::downgrade(&writing));
            drop(admission_epoch);
        }
        let envelope = model_lease.as_ref().map(|lease| lease.envelope());
        let _screen_registration = if let Some(lease) = model_lease {
            match self
                .screen_factory
                .as_ref()
                .unwrap()
                .register(self.channels[&stream].job.as_ref().unwrap(), lease)
            {
                Ok(registration) => Some(registration),
                Err(_) => {
                    let owned = self.channels.get_mut(&stream).unwrap();
                    drop(
                        owned
                            .custody
                            .refuse_before_creation("retained model registration refused".into()),
                    );
                    owned.job.take();
                    return Err(EngineError::Opening);
                }
            }
        } else {
            None
        };
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
        let (model, resize) = self
            .retained
            .take_model(identity)
            .map_err(|_| EngineError::Opening)?;
        let actual_screen = model.has_screen();
        {
            let mut state = output.state.lock().map_err(|_| EngineError::Unavailable)?;
            state.has_screen = actual_screen;
            state.model = Some(OutputModel {
                screen: model,
                resize,
                envelope,
            });
        }
        if actual_screen != self.channels[&stream].request.screen {
            return Err(EngineError::Unavailable);
        }
        if actual_screen {
            self.control_ticket
                .as_ref()
                .ok_or(EngineError::Unavailable)?
                .register(output.clone())
                .map_err(|_| EngineError::Unavailable)?;
        }
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
        if !self.ever_established {
            if let Some(binding) = &self.local_binding {
                self.local_establishment = Some(LocalEstablishment {
                    binding: binding.clone(),
                    locator: self.locator,
                    client: self.resources.clone(),
                });
            }
            self.ever_established = true;
        }
        Ok(instance)
    }
    /// Exact lease-scoped native/model transaction. No frontend callback or
    /// resource admission runs under adoption locks; model ordering is parked.
    pub fn resize(
        &mut self,
        frontend: &FrontendAttachment,
        instance: ChannelInstance,
        id: transport::channel_geometry::ResizeRequestId,
        cols: u16,
        rows: u16,
    ) -> Result<GeometryRecord, EngineError> {
        use transport::{channel_geometry::ResizeRefusal, shell_server::ScreenPreparationError};
        let leases = self.admission(frontend)?;
        leases
            .state
            .validate_resize(frontend.attachment)
            .map_err(|_| EngineError::Unavailable)?;
        let (&stream, owned) = self
            .channels
            .iter()
            .find(|(_, c)| c.instance == instance && c.installed)
            .ok_or(EngineError::InvalidRequest)?;
        if owned
            .last_resize
            .is_some_and(|(attachment, last)| attachment == frontend.attachment && id.get() <= last)
        {
            return Err(EngineError::InvalidRequest);
        }
        let output = owned.output.clone();
        let open_size = (owned.request.cols, owned.request.rows);
        drop(leases);
        let old = output
            .state
            .lock()
            .map_err(|_| EngineError::Unavailable)?
            .geometry;
        let result = |outcome, cols, rows| GeometryRecord {
            instance,
            request_id: id.get(),
            outcome,
            cols,
            rows,
        };
        let size = match terminal_size::TerminalSize::new(cols, rows) {
            Ok(size) if open_size.0 != 0 && open_size.1 != 0 => size,
            _ => {
                self.channels.get_mut(&stream).unwrap().last_resize =
                    Some((frontend.attachment, id.get()));
                return Ok(result(
                    GeometryOutcome::Refused(if open_size.0 == 0 || open_size.1 == 0 {
                        ResizeRefusal::NoPty
                    } else {
                        ResizeRefusal::InvalidSize
                    }),
                    old.cols,
                    old.rows,
                ));
            }
        };
        if (old.cols, old.rows) == (cols, rows) {
            self.channels.get_mut(&stream).unwrap().last_resize =
                Some((frontend.attachment, id.get()));
            return Ok(result(GeometryOutcome::Applied, cols, rows));
        }
        let mut operation =
            super::output::ModelOperation::take(&output).map_err(EngineError::Writer)?;
        let replies = operation
            .model
            .as_mut()
            .unwrap()
            .screen
            .flush_pending_output()
            .map_err(|_| {
                output
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .failed = true;
                EngineError::Unavailable
            })?;
        {
            let mut state = output.state.lock().map_err(|_| EngineError::Unavailable)?;
            output.retain_replies(&mut state, replies);
            if output
                .drain_reply(&mut state)
                .map_err(EngineError::Writer)?
            {
                return Err(EngineError::Writer(WriterError::Busy));
            }
        }
        let boundary = {
            let state = output.state.lock().map_err(|_| EngineError::Unavailable)?;
            checked_end(state.start, state.bytes.len()).map_err(|_| EngineError::Unavailable)?
        };
        let model = operation.model.as_mut().unwrap();
        let envelope = model
            .envelope
            .map(|e| {
                e.prepare_charge(
                    terminal_size::TerminalSize::new(old.cols, old.rows).unwrap(),
                    size,
                )
                .map(|(next, _)| next)
            })
            .transpose()
            .map_err(|_| EngineError::Unavailable)?;
        // The model is owned by this parked operation: no output/lease/custody
        // guard survives real host reservation or a native operation.
        let prepared = match model.screen.prepare_resize(size) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Ok(result(
                    GeometryOutcome::Refused(match error {
                        ScreenPreparationError::ResourceLimit(_) => ResizeRefusal::ResourceLimit,
                        _ => ResizeRefusal::ScreenPreparationFailed,
                    }),
                    old.cols,
                    old.rows,
                ))
            }
        };
        {
            let mut leases = self.admission(frontend)?;
            leases
                .state
                .validate_resize(frontend.attachment)
                .map_err(|_| EngineError::Unavailable)?;
            let generation = leases
                .generation
                .checked_add(1)
                .ok_or(EngineError::Unavailable)?;
            leases
                .state
                .invalidate_recovery(frontend.attachment)
                .map_err(|_| EngineError::StaleAttachment)?;
            leases.generation = generation;
            leases.ready_generation = None;
        }
        self.channels.get_mut(&stream).unwrap().last_resize = Some((frontend.attachment, id.get()));
        if model.resize.try_resize(cols, rows).is_err() {
            drop(prepared);
            return Ok(result(
                GeometryOutcome::Refused(ResizeRefusal::PtyResizeFailed),
                old.cols,
                old.rows,
            ));
        }
        let actual = result(GeometryOutcome::Applied, cols, rows);
        operation.effect = Some((actual, boundary, false));
        prepared.commit();
        model.envelope = envelope;
        operation.effect.as_mut().unwrap().2 = true;
        drop(operation);
        Ok(actual)
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
        charge: &Arc<StorageCharge>,
        cleanup: RequestId,
    ) -> Result<(), EngineError> {
        if charge.admitted().cleanup() != cleanup {
            return Err(EngineError::Resource(OwnerProtocolError::Binding));
        }
        // Every caller first destroys its actual output/read backing or proves
        // allocation never escaped. The final charge reference performs release.
        charge.allow_release();
        Ok(())
    }
    pub(super) async fn close_local_empty(&mut self) -> Result<LocalEmptyCompletion, EngineError> {
        if self.ever_established {
            return Err(EngineError::Unavailable);
        }
        self.close_session().await?;
        Ok(LocalEmptyCompletion {
            binding: self.local_binding.clone().ok_or(EngineError::Unavailable)?,
            locator: self.locator,
            client: self.resources.clone(),
        })
    }
    /// Host-authorized explicit close. EOF/Drop of an attachment never calls it.
    ///
    /// Cancel-safe: receipts consumed from the exact reaper are kept by the
    /// engine, so a retry after a cancelled or failed close returns each
    /// cleanup exactly once, on the close that finally succeeds.
    pub async fn close_session(&mut self) -> Result<Vec<RetainedCleanup>, EngineError> {
        if self.cleanup_complete {
            return Ok(std::mem::take(&mut self.close_receipts));
        }
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
        if let Some(ticket) = &self.control_ticket {
            ticket.stop();
        }
        self.retained.close_all();
        if let Some(ticket) = &self.control_ticket {
            if ticket.join().await.is_ok() {
                self.control_joined = true;
            } else {
                self.control_failed = true;
            }
        }
        // Capacity is reserved before waiting, so storing a consumed receipt
        // cannot fail between the reaper handing it over and the next await.
        self.close_receipts.reserve(self.retained.channels());
        while self.retained.channels() != 0 {
            let done = self.retained.next_cleanup().await;
            self.close_receipts.push(done);
        }
        self.retained
            .join_workers()
            .await
            .map_err(|_| EngineError::CleanupPending)?;
        for owned in self.channels.values_mut() {
            if owned.opening_failed {
                return Err(EngineError::CleanupPending);
            }
            if let Some(worker) = owned.opening_worker.as_mut() {
                let result = worker.await;
                owned.opening_failed = result.is_err();
                owned.opening_worker.take();
                if owned.opening_failed {
                    return Err(EngineError::CleanupPending);
                }
            }
            if !owned.installed
                && !matches!(owned.custody.retry_cleanup(), CleanupStatus::Confirmed(_))
            {
                return Err(EngineError::CleanupPending);
            }
        }
        // Validate release correlations and capture actual final facts while
        // their writer/output owners still exist. No removed state implies proof.
        if self.channels.len() > MAX_CHANNELS {
            return Err(EngineError::Unavailable);
        }
        if !self.facts_captured {
            let attachment = self
                .leases
                .lock()
                .map_err(|_| EngineError::Unavailable)?
                .current;
            let mut facts = Vec::new();
            facts
                .try_reserve_exact(self.channels.len())
                .map_err(|_| EngineError::Unavailable)?;
            for owned in self.channels.values() {
                let admitted = owned.admitted.admitted();
                if admitted.cleanup() != owned.cleanup
                    || admitted.reservation().channel != owned.instance
                    || admitted.reservation().locator != self.locator
                {
                    return Err(EngineError::Resource(OwnerProtocolError::Binding));
                }
                if !owned.installed {
                    continue;
                }
                let receipt = self
                    .close_receipts
                    .iter()
                    .find(|receipt| receipt.instance() == owned.instance)
                    .filter(|receipt| receipt.workers_joined())
                    .ok_or(EngineError::CleanupPending)?;
                let output = owned
                    .output
                    .state
                    .lock()
                    .map_err(|_| EngineError::Unavailable)?;
                let offset = checked_end(output.start, output.bytes.len())
                    .map_err(|_| EngineError::Unavailable)?;
                let input = owned.writer.position();
                input.validate().map_err(|_| EngineError::Unavailable)?;
                facts.push(super::host::CompletedChannelFact {
                    exit: ExitReceipt {
                        attachment: attachment.ok_or(EngineError::Unavailable)?,
                        channel: owned.instance,
                        receipt_id: owned.cleanup,
                        fact: receipt
                            .code()
                            .map_or(ExitFact::StatusUnavailable, |status| ExitFact::Reaped {
                                status,
                            }),
                    },
                    input,
                    output: OutputCursor {
                        channel: owned.instance,
                        offset,
                    },
                });
            }
            self.close_facts = Some(facts);
            self.facts_captured = true;
        }
        if self.close_facts.is_none() {
            return Err(EngineError::CleanupPending);
        }
        {
            let mut leases = self.leases.lock().map_err(|_| EngineError::Unavailable)?;
            drop(std::mem::take(&mut leases.writers));
        }
        // Keep final charge references on the bounded stack until every map
        // node/request/output backing is gone, including iterator spare backing.
        let mut release: [Option<(Arc<StorageCharge>, Arc<WriterShared>)>; MAX_CHANNELS] =
            std::array::from_fn(|_| None);
        let channels = std::mem::take(&mut self.channels);
        for (slot, (_, owned)) in release.iter_mut().zip(channels) {
            let OwnedChannel {
                output,
                admitted,
                writer,
                request,
                ..
            } = owned;
            drop(output);
            drop(request);
            *slot = Some((admitted, writer));
        }
        for (admitted, writer) in release.into_iter().flatten() {
            writer.allow_release();
            drop(writer);
            admitted.allow_release();
        }
        self.control_ticket.take();
        self.screen_control.take();
        if self.control_failed {
            return Err(EngineError::CleanupPending);
        }
        if self.ever_established {
            if let Some(binding) = &self.local_binding {
                self.local_completion = Some(LocalCompletion {
                    binding: binding.clone(),
                    locator: self.locator,
                    client: self.resources.clone(),
                    facts: self.close_facts.take().ok_or(EngineError::CleanupPending)?,
                });
            }
        }
        self.cleanup_complete = true;
        Ok(std::mem::take(&mut self.close_receipts))
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
        if let Some(ticket) = &self.control_ticket {
            ticket.stop();
        }
        self.retained.close_all();
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
pub(super) mod tests;
