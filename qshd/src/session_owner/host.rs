//! Dormant bounded host catalog and grant decisions. No endpoint, process,
//! engine attachment, PAM session, or per-owner budget is created here.
//!
//! All calls belong to one host serialization boundary. `now` and policy/grant
//! deadlines are monotonic milliseconds. Logical cancellation never completes
//! separately owned physical verifier or session cleanup.
use super::authorization::{
    fresh_bytes, AuthenticatedPeer, AuthenticationAttempt, AuthorityError, AuthorizationState,
    CanonicalAccount, FrontendAdmission, HostMode, PolicyIntent, PolicyKind, PolicyResolution,
    PolicyResult,
};
use super::authorization_contract::{
    AttachGrant, AuthenticatedPrincipalRef, FrontendRegistration, GrantAuthority, GrantBinding,
    GrantLedger, LedgerInstance, PrincipalRegistration,
};
use super::host_engine::{LocalBinding, LocalLeasePhase};
use super::host_resources::OwnerProvisioning;
use super::resource_contract::HostResourceBinding;
use super::resource_contract::{ResourceLedger, ResourceLimits};
use std::sync::{Arc, Mutex};
use transport::session_resume::*;

const NEVER_ESTABLISHED_GRACE_MS: u64 = 30_000;
const COMPLETED_RETENTION_MS: u64 = 300_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostError {
    Authority(AuthorityError),
    Capacity,
    Exhausted,
    Refused,
    ResourceDebt,
    AlreadyAttached,
}
impl From<AuthorityError> for HostError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

/// Inject the actual host resource limits once. Session admission retains the
/// existing global/per-account caps; there is no per-owner default ledger.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostLimits {
    resources: ResourceLimits,
    sessions: usize,
    sessions_per_account: usize,
    frontends: usize,
    attempts: usize,
    pending: usize,
    grants: usize,
    grant_lifetime_ms: u64,
}
impl HostLimits {
    pub(crate) fn new(
        resources: ResourceLimits,
        frontends: usize,
        attempts: usize,
        pending: usize,
        grants: usize,
        grant_lifetime_ms: u64,
    ) -> Result<Self, HostError> {
        if grants == 0 || grant_lifetime_ms == 0 || frontends == 0 || attempts == 0 || pending == 0
        {
            return Err(HostError::Refused);
        }
        Ok(Self {
            resources,
            sessions: transport::session_manager::MAX_SESSIONS_TOTAL,
            sessions_per_account: transport::session_manager::MAX_SESSIONS_PER_OWNER,
            frontends,
            attempts,
            pending,
            grants,
            grant_lifetime_ms,
        })
    }
}

/// Content-free terminal facts retained after real completion. This DTO is
/// neither proof of child cleanup nor resource-release authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompletedChannelFact {
    pub exit: ExitReceipt,
    pub input: InputPosition,
    pub output: OutputCursor,
}

#[derive(Debug)]
enum CatalogPhase {
    NeverEstablished,
    Established,
    Completed {
        at: u64,
        facts: Vec<CompletedChannelFact>,
    },
}
#[derive(Debug)]
struct CatalogEntry {
    locator: SessionLocator,
    principal: AuthenticatedPrincipalRef,
    account: CanonicalAccount,
    resources: Option<PrincipalRegistration>,
    created_at: u64,
    phase: CatalogPhase,
    last_epoch: u64,
    cleanup_operation: Option<u64>,
    local: Option<Arc<LocalBinding>>,
    final_status: Option<super::status_contract::OwnerStatus>,
}

/// These capabilities deliberately have no production constructors in 3A1.
/// A later accepted custody adapter must bind actual ownership evidence. Public
/// ExitReceipt/ReservationReceipt descriptions cannot manufacture them.
#[derive(Debug)]
pub(crate) struct OwnerEstablished {
    host: HostInstance,
    locator: SessionLocator,
}
#[derive(Debug)]
pub(crate) struct OwnerCompletion {
    host: HostInstance,
    locator: SessionLocator,
    operation: u64,
    facts: Vec<CompletedChannelFact>,
}
#[derive(Debug)]
pub(crate) struct CleanupIntent {
    host: HostInstance,
    locator: SessionLocator,
    operation: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GrantOffer {
    grant: AttachGrant,
    binding: GrantBinding,
}
impl GrantOffer {
    pub(crate) fn grant(self) -> AttachGrant {
        self.grant
    }
    pub(crate) fn binding(self) -> GrantBinding {
        self.binding
    }
}
#[derive(Debug)]
struct PendingGrant {
    offer: GrantOffer,
    attempt: AuthenticationAttempt,
    authority: GrantAuthority,
}
/// This is a host decision, not an engine writer lease or recovery readiness.
/// The later engine adapter must still enforce attachment/fence barriers.
#[derive(Debug)]
pub(crate) struct AuthorizedAttachment {
    attachment: Attachment,
    host: HostInstance,
    local: Option<std::sync::Weak<LocalBinding>>,
}
impl AuthorizedAttachment {
    pub(crate) fn attachment(&self) -> Attachment {
        self.attachment
    }
}
#[derive(Debug)]
pub(crate) enum HostDecision {
    Authenticated(AuthenticationAttempt),
    GrantIssued(GrantOffer),
    GrantConsumed(AuthorizedAttachment),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrontendRetirement {
    Active,
    AuthorityRetired,
}
#[derive(Debug)]
struct HostFrontend {
    admission: FrontendAdmission,
    registration: FrontendRegistration,
    retirement: FrontendRetirement,
}
#[derive(Debug)]
struct FrontendObligation {
    frontend: FrontendAdmission,
    capsule: Option<super::inherited_launch::CapsuleIdentity>,
}
#[derive(Debug)]
pub(super) struct SupervisionClaim {
    host: HostInstance,
    _identity: [u8; 16],
}
#[derive(Debug)]
pub(crate) struct HostState {
    instance: HostInstance,
    mode: HostMode,
    stopping: bool,
    supervision: Option<Arc<SupervisionClaim>>,
    stop_operation: Option<u64>,
    last_stop: u64,
    #[cfg(test)]
    fail_frontend_cleanup_once: Option<FrontendAdmission>,
    grant_scope: LedgerInstance,
    resource_scope: LedgerInstance,
    limits: HostLimits,
    authorization: AuthorizationState,
    frontends: Vec<HostFrontend>,
    frontend_debt: Vec<FrontendObligation>,
    catalog: Vec<CatalogEntry>,
    status_revision: Option<u64>,
    pub(super) status_resident_build: Option<super::status_contract::BuildIdentity>,
    pub(super) status_serving: Option<super::host_status::ServingObservation>,
    pub(super) status_snapshot: Option<super::host_status::StatusSnapshot>,
    offers: Vec<PendingGrant>,
    grants: GrantLedger,
    resources: Arc<Mutex<ResourceLedger>>,
    last_cleanup: u64,
    last_now: u64,
    pub(super) replacement: Option<Arc<Mutex<super::host_replacement::ReplacementSlot>>>,
}
impl HostState {
    #[cfg(test)]
    pub(super) fn frontend_for_generation_for_test(
        &self,
        generation: FrontendGeneration,
    ) -> Option<FrontendAdmission> {
        self.frontends
            .iter()
            .map(|record| record.admission)
            .find(|frontend| frontend.generation() == generation)
    }
    #[cfg(test)]
    pub(super) fn cleanup_operation_for_test(&self, locator: SessionLocator) -> Option<u64> {
        self.catalog
            .iter()
            .find(|entry| entry.locator == locator)
            .and_then(|entry| entry.cleanup_operation)
    }
    #[cfg(test)]
    pub(super) fn resource_reservations_for_test(&self) -> usize {
        self.resources.lock().unwrap().reservations()
    }
    pub(super) fn pin_local_engine(
        &mut self,
        provisioning: &OwnerProvisioning,
        engine: &super::engine::SessionOwnerEngine,
    ) -> Result<Arc<LocalBinding>, super::host_engine::LocalEngineError> {
        self.ensure_running()?;
        use super::host_engine::LocalEngineError;
        let binding = provisioning.binding();
        if binding.host != self.instance {
            return Err(LocalEngineError::Binding);
        }
        let entry = self
            .catalog
            .iter_mut()
            .find(|entry| entry.locator == binding.locator)
            .ok_or(LocalEngineError::Binding)?;
        let registration = entry.resources.ok_or(LocalEngineError::Binding)?;
        let expected =
            super::resources::OwnerResourceClient::new(self.resources.clone(), registration);
        if !expected.same_registration(&provisioning.client())
            || !engine.matches_local_binding(
                binding.locator,
                &expected,
                entry.account.uid(),
                entry.account.name(),
            )
            || !matches!(entry.phase, CatalogPhase::NeverEstablished)
            || entry.cleanup_operation.is_some()
        {
            return Err(LocalEngineError::Binding);
        }
        if entry.local.is_some() {
            return Err(LocalEngineError::AlreadyBound);
        }
        let binding = Arc::new(LocalBinding {
            identity: binding,
            phase: Mutex::new(LocalLeasePhase::Detached),
        });
        entry.local = Some(binding.clone());
        self.note_status_mutation();
        Ok(binding)
    }
    fn phase_available(phase: LocalLeasePhase) -> Result<(), HostError> {
        match phase {
            LocalLeasePhase::Detached => Ok(()),
            LocalLeasePhase::Reserved(_)
            | LocalLeasePhase::Attached(_)
            | LocalLeasePhase::Fencing(_) => Err(HostError::AlreadyAttached),
            _ => Err(HostError::Refused),
        }
    }
    fn local_available(entry: &CatalogEntry) -> Result<(), HostError> {
        if entry.cleanup_operation.is_some() {
            return Err(HostError::Refused);
        }
        if let Some(local) = &entry.local {
            Self::phase_available(*local.phase.lock().map_err(|_| HostError::Refused)?)?;
        }
        Ok(())
    }
    pub(super) fn validate_local_binding(
        &self,
        binding: &Arc<LocalBinding>,
    ) -> Result<(), HostError> {
        if binding.identity.host != self.instance
            || !self.catalog.iter().any(|entry| {
                entry.locator == binding.identity.locator
                    && entry
                        .local
                        .as_ref()
                        .is_some_and(|actual| Arc::ptr_eq(actual, binding))
                    && !matches!(entry.phase, CatalogPhase::Completed { .. })
            })
        {
            return Err(HostError::Refused);
        }
        Ok(())
    }
    /// Admit a route using the current sealed account and actual catalog binding.
    #[cfg(target_os = "linux")]
    pub(super) fn authorize_linux_route(
        &self,
        binding: &Arc<LocalBinding>,
        frontend: FrontendAdmission,
        attempt: AuthenticationAttempt,
        attachment: Attachment,
    ) -> Result<HostMode, HostError> {
        self.ensure_running()?;
        self.validate_local_binding(binding)?;
        let (account, actual_frontend) = self.authorization.identity(attempt)?;
        if actual_frontend != frontend
            || !self.frontend_is_current(frontend)
            || attachment.frontend != frontend.generation()
            || attachment.locator != binding.identity.locator
            || !self.catalog.iter().any(|entry| {
                entry.locator == attachment.locator
                    && entry.account == *account
                    && entry.cleanup_operation.is_none()
            })
        {
            return Err(HostError::Refused);
        }
        Ok(self.mode)
    }
    pub(super) fn consume_local_authority(
        &self,
        binding: &Arc<LocalBinding>,
        authorized: AuthorizedAttachment,
    ) -> Result<Attachment, HostError> {
        self.ensure_running()?;
        self.validate_local_binding(binding)?;
        if authorized.host != self.instance
            || authorized.attachment.locator != binding.identity.locator
            || !authorized
                .local
                .and_then(|weak| weak.upgrade())
                .is_some_and(|actual| Arc::ptr_eq(&actual, binding))
            || *binding.phase.lock().map_err(|_| HostError::Refused)?
                != LocalLeasePhase::Reserved(authorized.attachment)
        {
            return Err(HostError::Refused);
        }
        Ok(authorized.attachment)
    }
    fn retire_session_offers(&mut self, locator: SessionLocator) -> Result<(), HostError> {
        let mut index = 0;
        while index < self.offers.len() {
            if self.offers[index].offer.binding.locator == locator {
                self.grants
                    .retire_principal(self.offers[index].authority.principal)
                    .map_err(|_| HostError::Refused)?;
                self.offers.swap_remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }
    pub(super) fn establish_local_owner(
        &mut self,
        binding: &Arc<LocalBinding>,
        proof: super::engine::LocalEstablishment,
    ) -> Result<(), (HostError, super::engine::LocalEstablishment)> {
        let result = (|| {
            self.validate_local_binding(binding)?;
            let entry = self
                .catalog
                .iter()
                .find(|entry| entry.locator == binding.identity.locator)
                .ok_or(HostError::Refused)?;
            let client = super::resources::OwnerResourceClient::new(
                self.resources.clone(),
                entry.resources.ok_or(HostError::Refused)?,
            );
            if !proof.matches(binding, entry.locator, &client) {
                return Err(HostError::Refused);
            }
            self.establish_owner(OwnerEstablished {
                host: self.instance,
                locator: binding.identity.locator,
            })
        })();
        result.map_err(|error| (error, proof))
    }
    pub(super) fn complete_local_owner(
        &mut self,
        binding: &Arc<LocalBinding>,
        intent: &CleanupIntent,
        proof: super::engine::LocalCompletion,
        now: u64,
    ) -> Result<(), Box<(HostError, super::engine::LocalCompletion)>> {
        let preflight = (|| {
            self.validate_local_binding(binding)?;
            let entry = self
                .catalog
                .iter()
                .find(|entry| entry.locator == binding.identity.locator)
                .ok_or(HostError::Refused)?;
            let client = super::resources::OwnerResourceClient::new(
                self.resources.clone(),
                entry.resources.ok_or(HostError::Refused)?,
            );
            if intent.host != self.instance
                || intent.locator != entry.locator
                || entry.cleanup_operation != Some(intent.operation)
                || *binding.phase.lock().map_err(|_| HostError::Refused)?
                    != LocalLeasePhase::Closing
                || !proof.matches(binding, entry.locator, &client)
            {
                return Err(HostError::Refused);
            }
            self.completion_preflight(
                self.instance,
                entry.locator,
                intent.operation,
                proof.facts(),
                now,
            )
        })();
        let index = match preflight {
            Ok(index) => index,
            Err(error) => return Err(Box::new((error, proof))),
        };
        self.catalog[index].final_status =
            proof.final_status().and_then(|(build, total_channels)| {
                Some(super::status_contract::OwnerStatus {
                    locator: binding.identity.locator,
                    build,
                    ipc: super::status_contract::IpcRange::new(
                        super::protocol::OWNER_VERSION,
                        super::protocol::OWNER_VERSION,
                    )
                    .ok()?,
                    active_channels: 0,
                    total_channels,
                })
            });
        // The seal is consumed only after every fallible check/release. There
        // is no setter or constructor accepting replacement public exit facts.
        let converted = OwnerCompletion {
            host: self.instance,
            locator: binding.identity.locator,
            operation: intent.operation,
            facts: proof.into_facts(),
        };
        self.commit_completion(index, converted, now);
        Ok(())
    }
    pub(super) fn complete_local_empty(
        &mut self,
        binding: &Arc<LocalBinding>,
        proof: &super::engine::LocalEmptyCompletion,
        now: u64,
    ) -> Result<(), HostError> {
        self.observe(now)?;
        self.validate_local_binding(binding)?;
        let index = self
            .catalog
            .iter()
            .position(|entry| entry.locator == binding.identity.locator)
            .ok_or(HostError::Refused)?;
        let entry = &self.catalog[index];
        let registration = entry.resources.ok_or(HostError::Refused)?;
        let client =
            super::resources::OwnerResourceClient::new(self.resources.clone(), registration);
        if !matches!(entry.phase, CatalogPhase::NeverEstablished)
            || *binding.phase.lock().map_err(|_| HostError::Refused)? != LocalLeasePhase::Closing
            || !proof.matches(binding, entry.locator, &client)
        {
            return Err(HostError::Refused);
        }
        self.retire_session_offers(binding.identity.locator)?;
        self.resources
            .lock()
            .map_err(|_| HostError::ResourceDebt)?
            .retire_principal(registration)
            .map_err(|_| HostError::ResourceDebt)?;
        self.catalog.swap_remove(index);
        self.note_status_mutation();
        Ok(())
    }
    pub(crate) fn new(mode: HostMode, limits: HostLimits) -> Result<Self, HostError> {
        let instance = HostInstance::new(fresh_bytes()?).ok_or(HostError::Refused)?;
        let grant_scope = LedgerInstance::new(fresh_bytes()?).ok_or(HostError::Refused)?;
        let resource_scope = LedgerInstance::new(fresh_bytes()?).ok_or(HostError::Refused)?;
        if grant_scope == resource_scope {
            return Err(HostError::Refused);
        }
        let authorization = AuthorizationState::new(
            instance,
            mode,
            limits.frontends,
            limits.attempts,
            limits.pending,
        )?;
        let grants = GrantLedger::new(grant_scope, limits.grants.max(limits.frontends))
            .map_err(|_| HostError::Capacity)?;
        let resources = ResourceLedger::new(resource_scope, limits.resources)
            .map_err(|_| HostError::Capacity)?;
        Ok(Self {
            instance,
            mode,
            stopping: false,
            supervision: None,
            stop_operation: None,
            last_stop: 0,
            #[cfg(test)]
            fail_frontend_cleanup_once: None,
            grant_scope,
            resource_scope,
            limits,
            authorization,
            frontends: Vec::new(),
            frontend_debt: Vec::new(),
            catalog: Vec::new(),
            status_revision: Some(0),
            status_resident_build: None,
            status_serving: None,
            status_snapshot: None,
            offers: Vec::new(),
            grants,
            resources: Arc::new(Mutex::new(resources)),
            last_cleanup: 0,
            last_now: 0,
            replacement: None,
        })
    }
    #[cfg(test)]
    pub(super) fn retire_frontend_authority_for_test(&mut self, frontend: FrontendAdmission) {
        self.authorization.retire_frontend(frontend).unwrap();
    }
    #[cfg(test)]
    pub(super) fn fail_frontend_cleanup_once_for_test(&mut self, frontend: FrontendAdmission) {
        self.fail_frontend_cleanup_once = Some(frontend);
    }
    #[cfg(test)]
    pub(super) fn frontend_obligations_for_test(&self) -> usize {
        self.frontend_debt.len()
    }
    pub(super) fn frontend_retirement_pending(&self, frontend: FrontendAdmission) -> bool {
        self.frontends
            .iter()
            .any(|record| record.admission == frontend)
    }
    pub(super) fn frontend_is_current(&self, frontend: FrontendAdmission) -> bool {
        self.authorization.frontend_is_current(frontend)
            && self.frontends.iter().any(|record| {
                record.admission == frontend && record.retirement == FrontendRetirement::Active
            })
    }
    pub(super) fn ensure_running(&self) -> Result<(), HostError> {
        if self.stopping {
            Err(HostError::Refused)
        } else {
            Ok(())
        }
    }
    pub(super) fn claim_supervision(
        &mut self,
    ) -> Result<(Arc<SupervisionClaim>, HostMode, usize), HostError> {
        if self.supervision.is_some() {
            return Err(HostError::Refused);
        }
        let claim = Arc::new(SupervisionClaim {
            host: self.instance,
            _identity: fresh_bytes()?,
        });
        self.supervision = Some(claim.clone());
        Ok((claim, self.mode, self.limits.frontends))
    }
    pub(super) fn supervision_is_unclaimed(&self) -> bool {
        self.supervision.is_none()
    }
    pub(super) fn supervision_is_current(&self, claim: &Arc<SupervisionClaim>) -> bool {
        claim.host == self.instance
            && self
                .supervision
                .as_ref()
                .is_some_and(|actual| Arc::ptr_eq(actual, claim))
    }
    pub(super) fn latch_supervisor_stop(
        &mut self,
        claim: &Arc<SupervisionClaim>,
    ) -> Result<(u64, Vec<FrontendAdmission>), HostError> {
        if !self.supervision_is_current(claim) {
            return Err(HostError::Refused);
        }
        // This admission latch precedes every allocation and fallible custody operation.
        if !self.stopping {
            self.stopping = true;
            self.note_status_mutation();
        }
        let operation = match self.stop_operation {
            Some(operation) => operation,
            None => {
                self.last_stop = self.last_stop.checked_add(1).ok_or(HostError::Exhausted)?;
                self.stop_operation = Some(self.last_stop);
                self.last_stop
            }
        };
        Ok((
            operation,
            self.frontends
                .iter()
                .map(|record| record.admission)
                .collect(),
        ))
    }
    pub(super) fn pin_frontend_custody(
        &mut self,
        capsule: &super::inherited_launch::CapsuleIdentity,
    ) -> Result<(), HostError> {
        if capsule.instance() != self.instance
            || !self.supervision_is_current(capsule.claim())
            || !self.frontend_is_current(capsule.frontend())
        {
            return Err(HostError::Refused);
        }
        let debt = self
            .frontend_debt
            .iter_mut()
            .find(|debt| debt.frontend == capsule.frontend())
            .ok_or(HostError::Refused)?;
        if debt.capsule.is_some() {
            return Err(HostError::Refused);
        }
        debt.capsule = Some(capsule.clone());
        Ok(())
    }
    pub(super) fn settle_frontend_custody(
        &mut self,
        receipt: super::inherited_launch::FrontendSettlement,
    ) -> Result<(), (HostError, super::inherited_launch::FrontendSettlement)> {
        let result = (|| {
            let identity = receipt.identity();
            if identity.instance() != self.instance
                || !self.supervision_is_current(identity.claim())
                || self.frontend_is_current(identity.frontend())
            {
                return Err(HostError::Refused);
            }
            let index = self
                .frontend_debt
                .iter()
                .position(|debt| {
                    debt.frontend == identity.frontend()
                        && debt
                            .capsule
                            .as_ref()
                            .is_some_and(|actual| actual.same(identity))
                })
                .ok_or(HostError::Refused)?;
            self.frontend_debt.swap_remove(index);
            Ok(())
        })();
        result.map_err(|error| (error, receipt))
    }
    pub(super) fn supervision_is_stopping(&self) -> bool {
        self.stopping
    }
    pub(super) fn frontend_fences_pending(&self, frontend: FrontendGeneration) -> bool {
        self.catalog.iter().any(|entry| {
            if matches!(entry.phase, CatalogPhase::Completed { .. }) {
                return false;
            }
            let Some(binding) = &entry.local else {
                return true;
            };
            let Ok(phase) = binding.phase.lock() else {
                return true;
            };
            match *phase {
                LocalLeasePhase::Reserved(attachment)
                | LocalLeasePhase::Attached(attachment)
                | LocalLeasePhase::Fencing(attachment) => attachment.frontend == frontend,
                LocalLeasePhase::Closing | LocalLeasePhase::Unknown => true,
                LocalLeasePhase::Detached | LocalLeasePhase::Complete => false,
            }
        })
    }
    pub(super) fn supervision_has_unknown_owner(&self) -> bool {
        self.catalog.iter().any(|entry| {
            !matches!(entry.phase, CatalogPhase::Completed { .. })
                && entry.local.as_ref().is_some_and(|binding| {
                    binding
                        .phase
                        .lock()
                        .map_or(true, |phase| *phase == LocalLeasePhase::Unknown)
                })
        })
    }
    #[cfg(test)]
    pub(super) fn status_capacity_for_test(&mut self, capacity: usize) {
        self.limits.sessions = capacity;
    }
    #[cfg(test)]
    pub(super) fn exhaust_status_revision_for_test(&mut self) {
        self.status_revision = Some(u64::MAX);
    }
    pub(super) fn status_revision(&self) -> Option<u64> {
        self.status_revision
    }
    pub(super) fn note_status_mutation(&mut self) {
        self.status_snapshot = None;
        self.status_revision = self.status_revision.and_then(|v| v.checked_add(1));
    }
    pub(super) fn status_catalog_roster(
        &self,
    ) -> Result<Vec<super::host_status::StatusCatalogRow>, super::host_status::StatusError> {
        use super::host_status::{StatusCatalogRow, StatusError};
        if self.catalog.len() > self.limits.sessions {
            return Err(StatusError::Unavailable);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.catalog.len())
            .map_err(|_| StatusError::Unavailable)?;
        for entry in &self.catalog {
            rows.push(StatusCatalogRow {
                binding: entry.local.clone().ok_or(StatusError::Unavailable)?,
                completed: matches!(entry.phase, CatalogPhase::Completed { .. }),
                final_status: entry.final_status.clone(),
            });
        }
        Ok(rows)
    }
    pub(super) fn supervision_roster_complete(
        &self,
        owners: &[&super::host_engine::LocalOwnerEngine],
    ) -> bool {
        owners.len() <= self.limits.sessions
            && owners.iter().enumerate().all(|(i, owner)| {
                self.supervision_owner_known(owner.supervision_binding())
                    && !owners[..i].iter().any(|other| {
                        Arc::ptr_eq(other.supervision_binding(), owner.supervision_binding())
                    })
            })
            && self.catalog.iter().all(|entry| {
                if matches!(entry.phase, CatalogPhase::Completed { .. }) {
                    return true;
                }
                entry.local.as_ref().is_some_and(|binding| {
                    binding.phase.lock().is_ok_and(|phase| {
                        matches!(
                            *phase,
                            LocalLeasePhase::Detached
                                | LocalLeasePhase::Attached(_)
                                | LocalLeasePhase::Fencing(_)
                        )
                    }) && owners
                        .iter()
                        .any(|owner| Arc::ptr_eq(owner.supervision_binding(), binding))
                })
            })
    }
    pub(super) fn supervision_owner_limit(&self) -> usize {
        self.limits.sessions
    }
    pub(super) fn supervision_owner_known(&self, binding: &Arc<LocalBinding>) -> bool {
        binding.identity.host == self.instance
            && self.catalog.iter().any(|entry| {
                entry.locator == binding.identity.locator
                    && entry
                        .local
                        .as_ref()
                        .is_some_and(|actual| Arc::ptr_eq(actual, binding))
            })
    }
    pub(super) fn supervision_owners_settled(&self) -> bool {
        self.catalog
            .iter()
            .all(|entry| matches!(entry.phase, CatalogPhase::Completed { .. }))
            && self
                .resources
                .lock()
                .is_ok_and(|ledger| ledger.reservations() == 0 && ledger.principals() == 0)
    }
    pub(super) fn complete_supervisor_stop(
        &mut self,
        receipt: super::supervisor::StopCompletion,
    ) -> Result<(), HostError> {
        if !self.supervision_is_current(receipt.claim())
            || !self.stopping
            || self.stop_operation != Some(receipt.operation())
            || !self.frontends.is_empty()
            || !self.frontend_debt.is_empty()
            || !self.supervision_owners_settled()
        {
            return Err(HostError::Refused);
        }
        self.supervision = None;
        self.stop_operation = None;
        Ok(())
    }
    pub(crate) fn instance(&self) -> HostInstance {
        self.instance
    }
    /// Protocol registrations share these actual global authority bounds.
    pub(super) fn local_auth_registration_limit(&self) -> usize {
        self.limits.attempts.min(self.limits.pending).min(63)
    }
    pub(super) fn authentication_is_current(
        &self,
        attempt: AuthenticationAttempt,
        frontend: FrontendAdmission,
    ) -> bool {
        self.authorization
            .identity(attempt)
            .is_ok_and(|(_, f)| f == frontend)
    }
    pub(crate) fn catalog_len(&self) -> usize {
        self.catalog.len()
    }
    fn observe(&mut self, now: u64) -> Result<(), HostError> {
        if now < self.last_now {
            return Err(HostError::Refused);
        }
        self.last_now = now;
        Ok(())
    }
    pub(crate) fn admit_frontend(
        &mut self,
        peer: AuthenticatedPeer,
    ) -> Result<FrontendAdmission, HostError> {
        self.ensure_running()?;
        if self.frontend_debt.len() >= self.limits.frontends {
            return Err(HostError::Capacity);
        }
        self.frontends
            .try_reserve(1)
            .map_err(|_| HostError::Capacity)?;
        self.frontend_debt
            .try_reserve(1)
            .map_err(|_| HostError::Capacity)?;
        let frontend = self.authorization.admit_frontend(peer)?;
        match self.grants.register_fresh_frontend(frontend.generation()) {
            Ok(registration) => {
                self.frontends.push(HostFrontend {
                    admission: frontend,
                    registration,
                    retirement: FrontendRetirement::Active,
                });
                self.frontend_debt.push(FrontendObligation {
                    frontend,
                    capsule: None,
                });
                self.note_status_mutation();
                Ok(frontend)
            }
            Err(_) => {
                self.authorization.retire_frontend(frontend)?;
                Err(HostError::Capacity)
            }
        }
    }
    pub(crate) fn begin_authentication(
        &mut self,
        frontend: FrontendAdmission,
        now: u64,
        deadline: u64,
    ) -> Result<PolicyIntent, HostError> {
        self.ensure_running()?;
        self.observe(now)?;
        Ok(self
            .authorization
            .begin_authentication(frontend, now, deadline)?)
    }
    pub(crate) fn create_session(
        &mut self,
        attempt: AuthenticationAttempt,
        now: u64,
    ) -> Result<SessionLocator, HostError> {
        self.create_session_provisioned(attempt, now)
            .map(|(locator, _)| locator)
    }
    pub(crate) fn create_session_provisioned(
        &mut self,
        attempt: AuthenticationAttempt,
        now: u64,
    ) -> Result<(SessionLocator, OwnerProvisioning), HostError> {
        self.ensure_running()?;
        self.observe(now)?;
        let (account, _) = self.authorization.identity(attempt)?;
        if self.catalog.len() >= self.limits.sessions
            || self
                .catalog
                .iter()
                .filter(|e| e.account.uid() == account.uid())
                .count()
                >= self.limits.sessions_per_account
        {
            return Err(HostError::Capacity);
        }
        let locator = SessionLocator {
            session: RetainedSessionId::new(fresh_bytes()?).ok_or(HostError::Refused)?,
            owner: OwnerInstance::new(fresh_bytes()?).ok_or(HostError::Refused)?,
        };
        let principal = AuthenticatedPrincipalRef::new(fresh_bytes()?).ok_or(HostError::Refused)?;
        if self.catalog.iter().any(|e| {
            e.locator.session == locator.session
                || e.locator.owner == locator.owner
                || e.principal == principal
        }) {
            return Err(HostError::Refused);
        }
        let registration = self
            .resources
            .lock()
            .map_err(|_| HostError::Refused)?
            .register_host_principal(
                principal,
                account.uid(),
                HostResourceBinding {
                    host: self.instance,
                    locator,
                },
            )
            .map_err(|_| HostError::Capacity)?;
        self.catalog.push(CatalogEntry {
            locator,
            principal,
            account: account.clone(),
            resources: Some(registration),
            created_at: now,
            phase: CatalogPhase::NeverEstablished,
            last_epoch: 0,
            cleanup_operation: None,
            local: None,
            final_status: None,
        });
        self.note_status_mutation();
        Ok((
            locator,
            OwnerProvisioning::from_catalog(
                self.instance,
                locator,
                self.resources.clone(),
                registration,
            ),
        ))
    }
    fn session_for_attempt(
        &self,
        attempt: AuthenticationAttempt,
        locator: SessionLocator,
    ) -> Result<&CatalogEntry, HostError> {
        let (account, _) = self.authorization.identity(attempt)?;
        let e = self
            .catalog
            .iter()
            .find(|e| e.locator == locator)
            .ok_or(HostError::Refused)?;
        if &e.account != account || matches!(e.phase, CatalogPhase::Completed { .. }) {
            return Err(HostError::Refused);
        }
        Ok(e)
    }
    pub(crate) fn begin_issue(
        &mut self,
        attempt: AuthenticationAttempt,
        locator: SessionLocator,
        now: u64,
        deadline: u64,
    ) -> Result<PolicyIntent, HostError> {
        self.ensure_running()?;
        self.observe(now)?;
        self.retire_invalid_offers()?;
        Self::local_available(self.session_for_attempt(attempt, locator)?)?;
        if self
            .offers
            .iter()
            .any(|g| g.offer.binding.locator == locator)
        {
            return Err(HostError::Refused);
        }
        Ok(self.authorization.begin_policy(
            attempt,
            PolicyKind::IssueGrant,
            locator,
            None,
            now,
            deadline,
        )?)
    }
    pub(crate) fn begin_consume(
        &mut self,
        attempt: AuthenticationAttempt,
        grant: AttachGrant,
        binding: GrantBinding,
        now: u64,
        deadline: u64,
    ) -> Result<PolicyIntent, HostError> {
        self.ensure_running()?;
        self.observe(now)?;
        Self::local_available(self.session_for_attempt(attempt, binding.locator)?)?;
        if !self.offers.iter().any(|g| {
            g.attempt == attempt
                && g.offer.grant == grant
                && g.offer.binding == binding
                && now < binding.expires_at_monotonic
        }) {
            return Err(HostError::Refused);
        }
        Ok(self.authorization.begin_policy(
            attempt,
            PolicyKind::ConsumeGrant,
            binding.locator,
            Some(grant),
            now,
            deadline,
        )?)
    }
    pub(crate) fn apply_policy_result(
        &mut self,
        result: PolicyResult,
        now: u64,
    ) -> Result<HostDecision, HostError> {
        self.note_status_mutation();
        self.ensure_running()?;
        self.observe(now)?;
        let resolution = self.authorization.resolve(result, now);
        // Refusal/current-account mismatch may retire an attempt. Invalidate all
        // of its grant authority in this same serialized call; keep resource debt.
        self.retire_invalid_offers()?;
        match resolution? {
            PolicyResolution::Authenticated(attempt) => Ok(HostDecision::Authenticated(attempt)),
            PolicyResolution::Approved(policy) => {
                let e = self.session_for_attempt(policy.attempt, policy.locator)?;
                Self::local_available(e)?;
                if e.account != policy.account {
                    return Err(HostError::Refused);
                }
                match policy.kind {
                    PolicyKind::IssueGrant => {
                        if self.offers.len() >= self.limits.grants {
                            return Err(HostError::Capacity);
                        }
                        if self
                            .offers
                            .iter()
                            .any(|g| g.offer.binding.locator == policy.locator)
                        {
                            return Err(HostError::Refused);
                        }
                        let principal = e.principal;
                        let expires = now
                            .checked_add(self.limits.grant_lifetime_ms)
                            .ok_or(HostError::Exhausted)?;
                        let grant = AttachGrant::new(fresh_bytes()?).ok_or(HostError::Refused)?;
                        let frontend = self
                            .frontends
                            .iter()
                            .find(|record| {
                                record.admission == policy.frontend
                                    && record.retirement == FrontendRetirement::Active
                            })
                            .map(|record| record.registration)
                            .ok_or(HostError::Refused)?;
                        let registration = self
                            .grants
                            .register_fresh_principal(principal)
                            .map_err(|_| HostError::Capacity)?;
                        let authority = GrantAuthority {
                            principal: registration,
                            frontend,
                        };
                        let binding = GrantBinding {
                            principal,
                            locator: policy.locator,
                            frontend: policy.frontend.generation(),
                            owner: policy.locator.owner,
                            expires_at_monotonic: expires,
                        };
                        if self.grants.insert(authority, grant, binding, now).is_err() {
                            self.grants
                                .retire_principal(registration)
                                .map_err(|_| HostError::Refused)?;
                            return Err(HostError::Capacity);
                        }
                        let offer = GrantOffer { grant, binding };
                        self.offers.push(PendingGrant {
                            offer,
                            attempt: policy.attempt,
                            authority,
                        });
                        Ok(HostDecision::GrantIssued(offer))
                    }
                    PolicyKind::ConsumeGrant => {
                        let local = e.local.clone();
                        let mut local_phase = local
                            .as_ref()
                            .map(|binding| binding.phase.lock())
                            .transpose()
                            .map_err(|_| HostError::Refused)?;
                        if let Some(phase) = local_phase.as_ref() {
                            Self::phase_available(**phase)?;
                        }
                        let epoch = AttachEpoch::new(
                            e.last_epoch.checked_add(1).ok_or(HostError::Exhausted)?,
                        )
                        .ok_or(HostError::Exhausted)?;
                        let i = self
                            .offers
                            .iter()
                            .position(|g| {
                                g.attempt == policy.attempt
                                    && g.offer.binding.locator == policy.locator
                                    && Some(g.offer.grant) == policy.grant
                            })
                            .ok_or(HostError::Refused)?;
                        let g = &self.offers[i];
                        let attachment = self
                            .grants
                            .consume(g.authority, g.offer.grant, g.offer.binding, now, epoch)
                            .map_err(|_| HostError::Refused)?;
                        self.catalog
                            .iter_mut()
                            .find(|entry| entry.locator == policy.locator)
                            .ok_or(HostError::Refused)?
                            .last_epoch = epoch.get();
                        if let Some(phase) = local_phase.as_mut() {
                            **phase = LocalLeasePhase::Reserved(attachment);
                        }
                        let g = self.offers.swap_remove(i);
                        self.grants
                            .retire_principal(g.authority.principal)
                            .map_err(|_| HostError::Refused)?;
                        Ok(HostDecision::GrantConsumed(AuthorizedAttachment {
                            attachment,
                            host: self.instance,
                            local: local.as_ref().map(Arc::downgrade),
                        }))
                    }
                    PolicyKind::Authenticate => Err(HostError::Refused),
                }
            }
        }
    }
    fn retire_invalid_offers(&mut self) -> Result<(), HostError> {
        let mut i = 0;
        while i < self.offers.len() {
            if self.authorization.identity(self.offers[i].attempt).is_err()
                || self.offers[i].offer.binding.expires_at_monotonic <= self.last_now
                || !self.catalog.iter().any(|e| {
                    e.locator == self.offers[i].offer.binding.locator
                        && !matches!(e.phase, CatalogPhase::Completed { .. })
                })
            {
                let g = self.offers.swap_remove(i);
                self.grants
                    .retire_principal(g.authority.principal)
                    .map_err(|_| HostError::Refused)?;
            } else {
                i += 1;
            }
        }
        Ok(())
    }
    pub(crate) fn cancel_attempt(
        &mut self,
        attempt: AuthenticationAttempt,
    ) -> Result<(), HostError> {
        self.authorization.cancel_attempt(attempt)?;
        self.retire_invalid_offers()
    }
    fn invalidate_local_attachment(
        entry: &CatalogEntry,
        frontend: Option<FrontendGeneration>,
    ) -> Result<(), HostError> {
        if let Some(local) = &entry.local {
            let mut phase = local.phase.lock().map_err(|_| HostError::Refused)?;
            match *phase {
                LocalLeasePhase::Reserved(attachment)
                    if frontend.is_none_or(|generation| generation == attachment.frontend) =>
                {
                    *phase = LocalLeasePhase::Unknown;
                }
                LocalLeasePhase::Attached(attachment)
                    if frontend.is_none_or(|generation| generation == attachment.frontend) =>
                {
                    *phase = LocalLeasePhase::Fencing(attachment);
                }
                _ => {}
            }
        }
        Ok(())
    }
    pub(crate) fn retire_frontend(&mut self, frontend: FrontendAdmission) -> Result<(), HostError> {
        let Some(index) = self
            .frontends
            .iter()
            .position(|record| record.admission == frontend)
        else {
            // A completed logical retirement can be retried while its exact
            // physical obligation is still retained; this never refunds debt.
            return if self
                .frontend_debt
                .iter()
                .any(|debt| debt.frontend == frontend)
            {
                Ok(())
            } else {
                Err(HostError::Refused)
            };
        };
        if self.frontends[index].retirement == FrontendRetirement::Active {
            self.authorization.retire_frontend(frontend)?;
            self.frontends[index].retirement = FrontendRetirement::AuthorityRetired;
            self.status_frontend_lost(frontend);
        }
        for entry in &self.catalog {
            Self::invalidate_local_attachment(entry, Some(frontend.generation()))?;
        }
        #[cfg(test)]
        if self.fail_frontend_cleanup_once == Some(frontend) {
            self.fail_frontend_cleanup_once = None;
            return Err(HostError::Refused);
        }
        // Keep the registration and progress until every remaining step commits.
        // No retry restores authentication or re-mints grants/physical credit.
        self.retire_invalid_offers()?;
        self.grants
            .revoke_frontend(self.frontends[index].registration)
            .map_err(|_| HostError::Refused)?;
        self.frontends.swap_remove(index);
        Ok(())
    }
    pub(crate) fn revoke_account(&mut self, uid: u32) -> Result<(), HostError> {
        let revocation = self.authorization.revoke_account(uid);
        self.note_status_mutation();
        for entry in self
            .catalog
            .iter()
            .filter(|entry| entry.account.uid() == uid)
        {
            Self::invalidate_local_attachment(entry, None)?;
        }
        self.retire_invalid_offers()?;
        revocation?;
        Ok(())
    }
    pub(crate) fn establish_owner(&mut self, proof: OwnerEstablished) -> Result<(), HostError> {
        if proof.host != self.instance {
            return Err(HostError::Refused);
        }
        let e = self
            .catalog
            .iter_mut()
            .find(|e| e.locator == proof.locator)
            .ok_or(HostError::Refused)?;
        if !matches!(e.phase, CatalogPhase::NeverEstablished) {
            return Err(HostError::Refused);
        }
        e.phase = CatalogPhase::Established;
        self.note_status_mutation();
        Ok(())
    }
    pub(crate) fn begin_owner_cleanup(
        &mut self,
        locator: SessionLocator,
    ) -> Result<CleanupIntent, HostError> {
        let e = self
            .catalog
            .iter_mut()
            .find(|e| e.locator == locator)
            .ok_or(HostError::Refused)?;
        if e.cleanup_operation.is_some() || !matches!(e.phase, CatalogPhase::Established) {
            return Err(HostError::Refused);
        }
        let operation = self
            .last_cleanup
            .checked_add(1)
            .ok_or(HostError::Exhausted)?;
        e.cleanup_operation = Some(operation);
        self.last_cleanup = operation;
        self.note_status_mutation();
        Ok(CleanupIntent {
            host: self.instance,
            locator,
            operation,
        })
    }
    pub(crate) fn complete_owner(
        &mut self,
        proof: OwnerCompletion,
        now: u64,
    ) -> Result<(), HostError> {
        let index = self.completion_preflight(
            proof.host,
            proof.locator,
            proof.operation,
            &proof.facts,
            now,
        )?;
        self.commit_completion(index, proof, now);
        Ok(())
    }
    fn completion_preflight(
        &mut self,
        host: HostInstance,
        locator: SessionLocator,
        operation: u64,
        facts: &[CompletedChannelFact],
        now: u64,
    ) -> Result<usize, HostError> {
        self.observe(now)?;
        if host != self.instance || facts.len() > transport::channel::CHANNEL_IDENTITIES {
            return Err(HostError::Refused);
        }
        let index = self
            .catalog
            .iter()
            .position(|entry| entry.locator == locator)
            .ok_or(HostError::Refused)?;
        let entry = &self.catalog[index];
        if !matches!(entry.phase, CatalogPhase::Established)
            || entry.cleanup_operation != Some(operation)
            || facts.iter().enumerate().any(|(i, fact)| {
                fact.exit.attachment.locator != locator
                    || fact.exit.channel != fact.output.channel
                    || fact.input.validate().is_err()
                    || facts[..i]
                        .iter()
                        .any(|old| old.exit.channel == fact.exit.channel)
            })
        {
            return Err(HostError::Refused);
        }
        let registration = entry.resources.ok_or(HostError::Refused)?;
        self.retire_session_offers(locator)?;
        self.resources
            .lock()
            .map_err(|_| HostError::ResourceDebt)?
            .retire_principal(registration)
            .map_err(|_| HostError::ResourceDebt)?;
        Ok(index)
    }
    fn commit_completion(&mut self, index: usize, proof: OwnerCompletion, now: u64) {
        let entry = &mut self.catalog[index];
        entry.resources = None;
        entry.phase = CatalogPhase::Completed {
            at: now,
            facts: proof.facts,
        };
        self.note_status_mutation();
    }
    pub(crate) fn completed_facts(
        &self,
        attempt: AuthenticationAttempt,
        locator: SessionLocator,
    ) -> Result<&[CompletedChannelFact], HostError> {
        let (account, _) = self.authorization.identity(attempt)?;
        let e = self
            .catalog
            .iter()
            .find(|e| e.locator == locator && &e.account == account)
            .ok_or(HostError::Refused)?;
        match &e.phase {
            CatalogPhase::Completed { facts, .. } => Ok(facts),
            _ => Err(HostError::Refused),
        }
    }
    pub(crate) fn acknowledge_completion(
        &mut self,
        attempt: AuthenticationAttempt,
        locator: SessionLocator,
    ) -> Result<(), HostError> {
        self.completed_facts(attempt, locator)?;
        let i = self
            .catalog
            .iter()
            .position(|e| e.locator == locator)
            .ok_or(HostError::Refused)?;
        self.catalog.swap_remove(i);
        self.note_status_mutation();
        Ok(())
    }
    pub(crate) fn sweep(&mut self, now: u64) -> Result<(), HostError> {
        self.observe(now)?;
        self.authorization.sweep(now)?;
        self.retire_invalid_offers()?;
        let mut i = 0;
        while i < self.catalog.len() {
            let e = &self.catalog[i];
            let retire = match e.phase {
                CatalogPhase::NeverEstablished
                    if e.local.is_none()
                        && now.saturating_sub(e.created_at) >= NEVER_ESTABLISHED_GRACE_MS =>
                {
                    if let Some(p) = e.resources {
                        self.resources
                            .lock()
                            .map(|mut resources| resources.retire_principal(p).is_ok())
                            .unwrap_or(false)
                    } else {
                        false
                    }
                }
                CatalogPhase::Completed { at, .. } => {
                    now.saturating_sub(at) >= COMPLETED_RETENTION_MS
                }
                _ => false,
            };
            if retire {
                self.catalog.swap_remove(i);
                self.note_status_mutation();
            } else {
                i += 1;
            }
        }
        self.retire_invalid_offers()
    }
}

#[cfg(test)]
impl OwnerEstablished {
    fn for_test(host: HostInstance, locator: SessionLocator) -> Self {
        Self { host, locator }
    }
}
#[cfg(test)]
impl OwnerCompletion {
    fn for_test(intent: CleanupIntent, facts: Vec<CompletedChannelFact>) -> Self {
        Self {
            host: intent.host,
            locator: intent.locator,
            operation: intent.operation,
            facts,
        }
    }
}
#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "host_resource_tests.rs"]
pub(super) mod resource_tests;
