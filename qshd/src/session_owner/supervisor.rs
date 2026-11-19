//! Dormant exact inherited-custody supervision. No service route constructs it.
use super::authorization::{FrontendAdmission, HostMode};
use super::host::{HostState, SupervisionClaim};
use super::inherited_launch::{
    CapsuleIdentity, FrontendLaunches, FrontendSettlement, LaunchHandle, LaunchProgress,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use transport::session_resume::HostInstance;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupervisionError {
    Refused,
    Unavailable,
    CleanupPending,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupervisionProgress {
    Pending,
    AttachedChannel(FrontendAdmission),
    LossPending,
    Settled,
    Unknown,
}
#[derive(Debug, Default)]
struct HandleState {
    cancelled: AtomicBool,
}
#[derive(Debug)]
pub(crate) struct SupervisedFrontend {
    identity: Arc<HandleState>,
}
impl Drop for SupervisedFrontend {
    fn drop(&mut self) {
        self.identity.cancelled.store(true, Ordering::Release);
    }
}
pub(crate) struct SupervisorOwnerFailure {
    error: SupervisionError,
    owner: Box<super::host_engine::LocalOwnerEngine>,
}
impl SupervisorOwnerFailure {
    pub(crate) fn into_parts(self) -> (SupervisionError, super::host_engine::LocalOwnerEngine) {
        (self.error, *self.owner)
    }
}
impl std::fmt::Debug for SupervisorOwnerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorOwnerFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
struct Association {
    identity: Arc<HandleState>,
    launch: LaunchHandle,
    capsule: Option<CapsuleIdentity>,
    frontend: Option<FrontendAdmission>,
    dispatch: Option<super::local_channel::HostDispatchChannel>,
    lost: bool,
    settled: bool,
    physical_settled: bool,
    settlement: Option<FrontendSettlement>,
}
struct StopProgress {
    operation: u64,
    registrations: Vec<FrontendAdmission>,
    unknown_frontends: Vec<FrontendAdmission>,
    completed: bool,
}
/// Only this owner can construct the completion after all captured launch debt
/// and the host's exact resource/catalog checks have settled.
pub(super) struct StopCompletion {
    claim: Arc<SupervisionClaim>,
    operation: u64,
}
impl StopCompletion {
    pub(super) fn claim(&self) -> &Arc<SupervisionClaim> {
        &self.claim
    }
    pub(super) fn operation(&self) -> u64 {
        self.operation
    }
}
struct CapturedFenceOwner {
    binding: Arc<super::host_engine::LocalBinding>,
    attachment: Option<transport::session_resume::Attachment>,
    revision: u64,
    completed: bool,
}
struct ReplacementFencing {
    scope: super::host_replacement::ReplacementFenceScope,
    host_revision: u64,
    owners: Vec<CapturedFenceOwner>,
    receipt: Option<ReplacementFencedReceipt>,
}
/// Constructed only after the exact complete captured roster's real fences settle.
pub(super) struct ReplacementFencedReceipt {
    scope: super::host_replacement::ReplacementFenceScope,
}
impl ReplacementFencedReceipt {
    pub(super) fn scope(&self) -> &super::host_replacement::ReplacementFenceScope {
        &self.scope
    }
}
pub(crate) struct HostSupervisor {
    host: HostInstance,
    mode: HostMode,
    claim: Arc<SupervisionClaim>,
    launches: FrontendLaunches,
    associations: Vec<Association>,
    owners: Vec<super::host_engine::LocalOwnerEngine>,
    stop: Option<StopProgress>,
    replacement_fencing: Option<ReplacementFencing>,
}
impl HostSupervisor {
    pub(crate) fn status_page(
        &self,
        host: &mut HostState,
        requester: FrontendAdmission,
        cursor: Option<super::status_contract::StatusCursor>,
    ) -> Result<super::status_contract::StatusPage, super::host_status::StatusError> {
        self.current(host)
            .map_err(|_| super::host_status::StatusError::Refused)?;
        let owners: Vec<_> = self.owners.iter().collect();
        host.status_page(requester, cursor, &owners)
    }
    fn validate_fencing(&self, host: &HostState) -> Result<(), SupervisionError> {
        self.current(host)?;
        let progress = self
            .replacement_fencing
            .as_ref()
            .ok_or(SupervisionError::Refused)?;
        host.validate_replacement_fence_scope(&progress.scope)
            .map_err(|_| SupervisionError::Refused)?;
        let roster: Vec<_> = self.owners.iter().collect();
        if host.status_revision() != Some(progress.host_revision)
            || !host.supervision_roster_complete(&roster)
            || progress.owners.len() != self.owners.len()
            || progress
                .owners
                .iter()
                .zip(&self.owners)
                .any(|(captured, owner)| {
                    !Arc::ptr_eq(&captured.binding, owner.supervision_binding())
                        || owner.status_revision() != Some(captured.revision)
                        || if captured.completed {
                            owner.supervision_attachment().is_some()
                        } else {
                            owner.supervision_attachment() != captured.attachment
                        }
                })
        {
            return Err(SupervisionError::Refused);
        }
        Ok(())
    }
    pub(crate) fn begin_replacement_fencing(
        &mut self,
        host: &mut HostState,
        guard: &super::host_replacement::ReplacementGuard,
    ) -> Result<(), SupervisionError> {
        self.current(host)?;
        if self.replacement_fencing.is_some() {
            return Err(SupervisionError::Refused);
        }
        // Prepared must already have independent authority before any fence work.
        let scope = host
            .replacement_fence_scope(guard)
            .map_err(|_| SupervisionError::Refused)?;
        let roster: Vec<_> = self.owners.iter().collect();
        if !host.supervision_roster_complete(&roster) {
            return Err(SupervisionError::Refused);
        }
        let host_revision = host
            .status_revision()
            .ok_or(SupervisionError::Unavailable)?;
        let owners = self
            .owners
            .iter()
            .map(|owner| {
                Ok(CapturedFenceOwner {
                    binding: owner.supervision_binding().clone(),
                    attachment: owner.supervision_attachment(),
                    revision: owner
                        .status_revision()
                        .ok_or(SupervisionError::Unavailable)?,
                    completed: owner.supervision_attachment().is_none(),
                })
            })
            .collect::<Result<Vec<_>, SupervisionError>>()?;
        self.replacement_fencing = Some(ReplacementFencing {
            scope,
            host_revision,
            owners,
            receipt: None,
        });
        for index in 0..self.owners.len() {
            if self.replacement_fencing.as_ref().unwrap().owners[index].completed {
                continue;
            }
            let result = self.owners[index].begin_detach(host);
            let revision = self.owners[index]
                .status_revision()
                .ok_or(SupervisionError::Unavailable)?;
            self.replacement_fencing.as_mut().unwrap().owners[index].revision = revision;
            result.map_err(|_| SupervisionError::Unavailable)?;
        }
        self.validate_fencing(host)
    }
    pub(crate) async fn finish_replacement_fencing(
        &mut self,
        host: &mut HostState,
    ) -> Result<(), SupervisionError> {
        self.validate_fencing(host)?;
        for index in 0..self.owners.len() {
            if self.replacement_fencing.as_ref().unwrap().owners[index].completed {
                continue;
            }
            let result = self.owners[index].finish_detach(host).await;
            let revision = self.owners[index]
                .status_revision()
                .ok_or(SupervisionError::Unavailable)?;
            let captured = &mut self.replacement_fencing.as_mut().unwrap().owners[index];
            captured.revision = revision;
            if result.is_ok() {
                captured.completed = true;
            }
            result.map_err(|_| SupervisionError::Unavailable)?;
            self.validate_fencing(host)?;
        }
        let progress = self.replacement_fencing.as_mut().unwrap();
        let receipt = progress
            .receipt
            .take()
            .unwrap_or_else(|| ReplacementFencedReceipt {
                scope: progress.scope.clone(),
            });
        if let Err((_, receipt)) = host.record_replacement_fenced(receipt) {
            self.replacement_fencing.as_mut().unwrap().receipt = Some(receipt);
            return Err(SupervisionError::Refused);
        }
        self.replacement_fencing = None;
        Ok(())
    }
    pub(crate) fn new(host: &mut HostState) -> Result<Self, SupervisionError> {
        // Claim the one host scope before allocating an independent launch budget.
        let (claim, mode, limit) = host
            .claim_supervision()
            .map_err(|_| SupervisionError::Refused)?;
        let launches = FrontendLaunches::new(limit).map_err(|_| SupervisionError::Unavailable)?;
        Ok(Self {
            host: host.instance(),
            mode,
            claim,
            launches,
            associations: Vec::new(),
            owners: Vec::new(),
            stop: None,
            replacement_fencing: None,
        })
    }
    fn current(&self, host: &HostState) -> Result<(), SupervisionError> {
        if host.instance() != self.host || !host.supervision_is_current(&self.claim) {
            Err(SupervisionError::Refused)
        } else {
            Ok(())
        }
    }
    fn index(&self, handle: &SupervisedFrontend) -> Result<usize, SupervisionError> {
        self.associations
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.identity, &handle.identity))
            .ok_or(SupervisionError::Refused)
    }
    pub(crate) fn add_owner(
        &mut self,
        host: &HostState,
        owner: super::host_engine::LocalOwnerEngine,
    ) -> Result<(), SupervisorOwnerFailure> {
        let result = (|| {
            self.current(host)?;
            if owner.supervision_complete()
                || host
                    .validate_local_binding(owner.supervision_binding())
                    .is_err()
            {
                return Err(SupervisionError::Refused);
            }
            // Only already completed in-process adapters whose catalog receipt
            // was legitimately retired can be dropped; live/unknown debt stays.
            self.owners.retain(|resident| {
                !resident.supervision_complete()
                    || host.supervision_owner_known(resident.supervision_binding())
            });
            if self.owners.len() >= host.supervision_owner_limit()
                || self.owners.iter().any(|resident| {
                    resident.supervision_binding().identity.locator
                        == owner.supervision_binding().identity.locator
                })
            {
                return Err(SupervisionError::Refused);
            }
            self.owners
                .try_reserve(1)
                .map_err(|_| SupervisionError::Unavailable)?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err(SupervisorOwnerFailure {
                error,
                owner: Box::new(owner),
            });
        }
        self.owners.push(owner);
        Ok(())
    }
    pub(crate) async fn finish_frontend_loss(
        &mut self,
        handle: &SupervisedFrontend,
        host: &mut HostState,
    ) -> Result<(), SupervisionError> {
        self.current(host)?;
        let index = self.index(handle)?;
        if !self.associations[index].lost {
            return Err(SupervisionError::Refused);
        }
        let frontend = self.associations[index]
            .frontend
            .ok_or(SupervisionError::Refused)?;
        for owner in &mut self.owners {
            if owner
                .supervision_attachment()
                .is_some_and(|attachment| attachment.frontend == frontend.generation())
            {
                owner
                    .begin_detach(host)
                    .map_err(|_| SupervisionError::Unavailable)?;
                owner
                    .finish_detach(host)
                    .await
                    .map_err(|_| SupervisionError::Unavailable)?;
            }
        }
        if host.frontend_fences_pending(frontend.generation()) {
            return Err(SupervisionError::CleanupPending);
        }
        if self.associations[index].physical_settled {
            self.associations[index].settled = true;
        }
        Ok(())
    }
    pub(crate) fn prepare(
        &mut self,
        host: &mut HostState,
        config: super::local_channel::TrustedChannelConfig,
        deadline: std::time::Instant,
    ) -> Result<SupervisedFrontend, SupervisionError> {
        self.current(host)?;
        host.ensure_running()
            .map_err(|_| SupervisionError::Refused)?;
        if config.host != self.host
            || config.mode != self.mode
            || config.owner.is_some()
            || config.requester != super::protocol::OwnerRole::Frontend
        {
            return Err(SupervisionError::Refused);
        }
        self.associations.retain(|entry| !entry.settled);
        let launch = self
            .launches
            .prepare(config, deadline)
            .map_err(|_| SupervisionError::Unavailable)?;
        let identity = Arc::new(HandleState::default());
        self.associations.push(Association {
            identity: identity.clone(),
            launch,
            capsule: None,
            frontend: None,
            dispatch: None,
            lost: false,
            settled: false,
            physical_settled: false,
            settlement: None,
        });
        Ok(SupervisedFrontend { identity })
    }
    pub(crate) fn start(
        &mut self,
        host: &mut HostState,
        handle: &SupervisedFrontend,
    ) -> Result<(), SupervisionError> {
        self.current(host)?;
        host.ensure_running()
            .map_err(|_| SupervisionError::Refused)?;
        let index = self.index(handle)?;
        self.launches
            .start(&self.associations[index].launch)
            .map_err(|_| SupervisionError::Unavailable)
    }
    #[cfg(test)]
    pub(super) fn set_program_for_test(
        &mut self,
        program: super::inherited_launch::TestProgram,
    ) -> Result<(), SupervisionError> {
        self.launches
            .set_program_for_test(program)
            .map_err(|_| SupervisionError::Unavailable)
    }
    pub(crate) fn in_use(&self) -> usize {
        self.launches.in_use()
    }
    pub(crate) fn poll_frontend(
        &mut self,
        handle: &SupervisedFrontend,
        host: &mut HostState,
    ) -> Result<SupervisionProgress, SupervisionError> {
        self.current(host)?;
        let index = self.index(handle)?;
        self.poll_index(index, host)
    }
    fn poll_index(
        &mut self,
        index: usize,
        host: &mut HostState,
    ) -> Result<SupervisionProgress, SupervisionError> {
        self.current(host)?;
        let owner_unknown = host.supervision_has_unknown_owner();
        let stopping = host.supervision_is_stopping();
        let entry = &mut self.associations[index];
        if entry.physical_settled {
            let pending = entry
                .frontend
                .is_some_and(|frontend| host.frontend_fences_pending(frontend.generation()));
            entry.settled = !pending;
            return Ok(if owner_unknown {
                SupervisionProgress::Unknown
            } else if pending {
                SupervisionProgress::LossPending
            } else {
                SupervisionProgress::Settled
            });
        }
        if entry.identity.cancelled.load(Ordering::Acquire) {
            self.launches.cancel(&entry.launch);
        }
        let mut observation = self
            .launches
            .observe(&entry.launch)
            .map_err(|_| SupervisionError::Unavailable)?;
        if observation.instance() != self.host
            || entry
                .capsule
                .as_ref()
                .is_some_and(|identity| !observation.matches(identity))
        {
            return Err(SupervisionError::Refused);
        }
        if observation.progress() == LaunchProgress::Admitted
            && !observation.lost()
            && entry.frontend.is_none()
        {
            let (dispatch, capsule) = self
                .launches
                .take_host_dispatch(
                    &entry.launch,
                    host,
                    &self.claim,
                    self.mode,
                    super::protocol::MAX_OWNER_REQUESTS,
                )
                .map_err(|_| SupervisionError::Unavailable)?;
            entry.frontend = Some(dispatch.frontend());
            entry.capsule = Some(capsule);
            entry.dispatch = Some(dispatch);
        }
        if observation.lost() {
            // Admission is revoked before fallible physical cleanup. Neither an
            // EOF nor exact child wait alone is promoted into debt settlement.
            entry.lost = true;
            // The exact host descriptor must actually close before the capsule's
            // remote-end ledger can issue physical settlement.
            entry.dispatch = None;
            self.launches.cancel(&entry.launch);
            if let Some(frontend) = entry.frontend {
                if host.frontend_retirement_pending(frontend) {
                    host.retire_frontend(frontend)
                        .map_err(|_| SupervisionError::Unavailable)?;
                }
                if !stopping {
                    for owner in &mut self.owners {
                        if owner
                            .supervision_attachment()
                            .is_some_and(|attachment| attachment.frontend == frontend.generation())
                        {
                            owner
                                .begin_detach(host)
                                .map_err(|_| SupervisionError::Unavailable)?;
                        }
                    }
                }
            }
        }
        match observation.progress() {
            LaunchProgress::Unknown => Ok(SupervisionProgress::Unknown),
            LaunchProgress::Settled => {
                if !entry.physical_settled {
                    if entry.settlement.is_none() {
                        entry.settlement = observation.take_settlement();
                    }
                    if let Some(receipt) = entry.settlement.take() {
                        if let Err((_, receipt)) = host.settle_frontend_custody(receipt) {
                            entry.settlement = Some(receipt);
                            return Err(SupervisionError::Unavailable);
                        }
                    } else if entry.frontend.is_some() {
                        return Err(SupervisionError::Unavailable);
                    }
                    entry.physical_settled = true;
                }
                let pending = entry
                    .frontend
                    .is_some_and(|frontend| host.frontend_fences_pending(frontend.generation()));
                entry.settled = !pending;
                Ok(if owner_unknown {
                    SupervisionProgress::Unknown
                } else if pending {
                    SupervisionProgress::LossPending
                } else {
                    SupervisionProgress::Settled
                })
            }
            _ if owner_unknown => Ok(SupervisionProgress::Unknown),
            _ if entry.lost => Ok(SupervisionProgress::LossPending),
            LaunchProgress::Admitted => entry
                .frontend
                .map(SupervisionProgress::AttachedChannel)
                .ok_or(SupervisionError::Unavailable),
            _ => Ok(SupervisionProgress::Pending),
        }
    }
    pub(crate) fn poll_frontends(&mut self, host: &mut HostState) -> Result<(), SupervisionError> {
        self.current(host)?;
        let mut failed = None;
        for index in 0..self.associations.len() {
            if let Err(error) = self.poll_index(index, host) {
                failed.get_or_insert(error);
            }
        }
        failed.map_or(Ok(()), Err)
    }
    pub(crate) fn begin_stop(&mut self, host: &mut HostState) -> Result<(), SupervisionError> {
        self.current(host)?;
        if self.stop.is_none() {
            let (operation, registrations) = host
                .latch_supervisor_stop(&self.claim)
                .map_err(|_| SupervisionError::Unavailable)?;
            let unknown_frontends = registrations
                .iter()
                .copied()
                .filter(|frontend| {
                    !self
                        .associations
                        .iter()
                        .any(|entry| entry.frontend == Some(*frontend))
                })
                .collect();
            self.stop = Some(StopProgress {
                operation,
                registrations,
                unknown_frontends,
                completed: false,
            });
        }
        let mut failed = false;
        for frontend in &self.stop.as_ref().unwrap().registrations {
            if host.frontend_retirement_pending(*frontend)
                && host.retire_frontend(*frontend).is_err()
            {
                failed = true;
            }
        }
        for entry in &mut self.associations {
            entry.lost = true;
            entry.dispatch = None;
            self.launches.cancel(&entry.launch);
        }
        if failed {
            Err(SupervisionError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) async fn finish_stop(
        &mut self,
        host: &mut HostState,
        now: u64,
    ) -> Result<(), SupervisionError> {
        if self.stop.as_ref().is_some_and(|stop| stop.completed) {
            return if host.instance() == self.host && host.supervision_is_unclaimed() {
                Ok(())
            } else {
                Err(SupervisionError::Refused)
            };
        }
        self.current(host)?;
        if self.stop.is_none() {
            return Err(SupervisionError::Refused);
        }
        for index in 0..self.associations.len() {
            self.poll_index(index, host)?;
        }
        for owner in &mut self.owners {
            owner
                .close(host, now)
                .await
                .map_err(|_| SupervisionError::CleanupPending)?;
        }
        for index in 0..self.associations.len() {
            self.poll_index(index, host)?;
        }
        let stop = self.stop.as_ref().unwrap();
        if !stop.unknown_frontends.is_empty()
            || self.launches.in_use() != 0
            || self.associations.iter().any(|entry| !entry.settled)
            || !host.supervision_owners_settled()
        {
            return Err(SupervisionError::CleanupPending);
        }
        let receipt = StopCompletion {
            claim: self.claim.clone(),
            operation: stop.operation,
        };
        host.complete_supervisor_stop(receipt)
            .map_err(|_| SupervisionError::CleanupPending)?;
        self.stop.as_mut().unwrap().completed = true;
        Ok(())
    }
    #[cfg(test)]
    fn test_frontend(
        &mut self,
        host: &mut HostState,
    ) -> Result<SupervisedFrontend, SupervisionError> {
        self.current(host)?;
        host.ensure_running()
            .map_err(|_| SupervisionError::Refused)?;
        self.associations.retain(|entry| !entry.settled);
        let launch = self
            .launches
            .model_capsule(self.host)
            .map_err(|_| SupervisionError::Unavailable)?;
        let frontend = match host.admit_frontend(super::authorization::AuthenticatedPeer::for_test(
            self.host, self.mode,
        )) {
            Ok(frontend) => frontend,
            Err(_) => {
                self.launches.test_wait(&launch, false);
                self.launches.model_eof(&launch);
                self.launches.cancel(&launch);
                self.launches.poll(&launch);
                return Err(SupervisionError::Refused);
            }
        };
        let capsule = self
            .launches
            .model_registration(&launch, frontend, self.claim.clone());
        host.pin_frontend_custody(&capsule)
            .map_err(|_| SupervisionError::Unavailable)?;
        let identity = Arc::new(HandleState::default());
        self.associations.push(Association {
            identity: identity.clone(),
            launch,
            capsule: Some(capsule),
            frontend: Some(frontend),
            dispatch: None,
            lost: false,
            settled: false,
            physical_settled: false,
            settlement: None,
        });
        Ok(SupervisedFrontend { identity })
    }
    #[cfg(test)]
    fn test_registration(&self, handle: &SupervisedFrontend) -> FrontendAdmission {
        self.associations[self.index(handle).unwrap()]
            .frontend
            .unwrap()
    }
    #[cfg(test)]
    fn test_wait(&mut self, handle: &SupervisedFrontend, lost: bool) {
        let index = self.index(handle).unwrap();
        self.launches
            .test_wait(&self.associations[index].launch, lost);
    }
    #[cfg(test)]
    fn test_eof(&mut self, handle: &SupervisedFrontend) {
        let index = self.index(handle).unwrap();
        self.launches.model_eof(&self.associations[index].launch);
    }
}
#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
