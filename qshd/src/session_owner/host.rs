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
use super::resource_contract::{ResourceLedger, ResourceLimits};
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

#[derive(Debug)]
pub(crate) struct HostState {
    instance: HostInstance,
    grant_scope: LedgerInstance,
    resource_scope: LedgerInstance,
    limits: HostLimits,
    authorization: AuthorizationState,
    frontends: Vec<(FrontendAdmission, FrontendRegistration)>,
    catalog: Vec<CatalogEntry>,
    offers: Vec<PendingGrant>,
    grants: GrantLedger,
    resources: ResourceLedger,
    last_cleanup: u64,
    last_now: u64,
}
impl HostState {
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
            grant_scope,
            resource_scope,
            limits,
            authorization,
            frontends: Vec::new(),
            catalog: Vec::new(),
            offers: Vec::new(),
            grants,
            resources,
            last_cleanup: 0,
            last_now: 0,
        })
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
        let frontend = self.authorization.admit_frontend(peer)?;
        match self.grants.register_fresh_frontend(frontend.generation()) {
            Ok(registration) => {
                self.frontends.push((frontend, registration));
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
            .register_fresh_principal(principal, account.uid())
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
        });
        Ok(locator)
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
        self.observe(now)?;
        self.retire_invalid_offers()?;
        self.session_for_attempt(attempt, locator)?;
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
        self.observe(now)?;
        self.session_for_attempt(attempt, binding.locator)?;
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
        self.observe(now)?;
        let resolution = self.authorization.resolve(result, now);
        // Refusal/current-account mismatch may retire an attempt. Invalidate all
        // of its grant authority in this same serialized call; keep resource debt.
        self.retire_invalid_offers()?;
        match resolution? {
            PolicyResolution::Authenticated(attempt) => Ok(HostDecision::Authenticated(attempt)),
            PolicyResolution::Approved(policy) => {
                let e = self.session_for_attempt(policy.attempt, policy.locator)?;
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
                            .find(|(f, _)| *f == policy.frontend)
                            .map(|(_, r)| *r)
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
                        let g = self.offers.swap_remove(i);
                        self.grants
                            .retire_principal(g.authority.principal)
                            .map_err(|_| HostError::Refused)?;
                        self.catalog
                            .iter_mut()
                            .find(|e| e.locator == policy.locator)
                            .ok_or(HostError::Refused)?
                            .last_epoch = epoch.get();
                        Ok(HostDecision::GrantConsumed(AuthorizedAttachment {
                            attachment,
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
    pub(crate) fn retire_frontend(&mut self, frontend: FrontendAdmission) -> Result<(), HostError> {
        let i = self
            .frontends
            .iter()
            .position(|(f, _)| *f == frontend)
            .ok_or(HostError::Refused)?;
        self.authorization.retire_frontend(frontend)?;
        // Retire grant principals before frontend removal; resource registrations
        // and session entries are independent from these transient lifetimes.
        self.retire_invalid_offers()?;
        let (_, registration) = self.frontends.swap_remove(i);
        self.grants
            .revoke_frontend(registration)
            .map_err(|_| HostError::Refused)?;
        Ok(())
    }
    pub(crate) fn revoke_account(&mut self, uid: u32) -> Result<(), HostError> {
        let revocation = self.authorization.revoke_account(uid);
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
        self.observe(now)?;
        if proof.host != self.instance || proof.facts.len() > transport::channel::CHANNEL_IDENTITIES
        {
            return Err(HostError::Refused);
        }
        let e = self
            .catalog
            .iter_mut()
            .find(|e| e.locator == proof.locator)
            .ok_or(HostError::Refused)?;
        if !matches!(e.phase, CatalogPhase::Established)
            || e.cleanup_operation != Some(proof.operation)
            || proof.facts.iter().enumerate().any(|(i, f)| {
                f.exit.attachment.locator != proof.locator
                    || f.exit.channel != f.output.channel
                    || f.input.validate().is_err()
                    || proof.facts[..i]
                        .iter()
                        .any(|old| old.exit.channel == f.exit.channel)
            })
        {
            return Err(HostError::Refused);
        }
        // A real owner completion is still not a resource refund: backing storage
        // must already have its separately authenticated release evidence.
        self.resources
            .retire_principal(e.resources.ok_or(HostError::Refused)?)
            .map_err(|_| HostError::ResourceDebt)?;
        e.resources = None;
        e.phase = CatalogPhase::Completed {
            at: now,
            facts: proof.facts,
        };
        self.retire_invalid_offers()
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
                    if now.saturating_sub(e.created_at) >= NEVER_ESTABLISHED_GRACE_MS =>
                {
                    if let Some(p) = e.resources {
                        self.resources.retire_principal(p).is_ok()
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
