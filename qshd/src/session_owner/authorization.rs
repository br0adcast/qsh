//! Dormant host authority state. A policy intent is work to perform, never an
//! approval. System results accept only sealed isolated-verifier observations;
//! local peer admission remains unavailable until its real adapter is integrated.
//! The verifier adapter must retain physical child custody independently when
//! an intent is cancelled, expires, or loses its consumer.
use rand_core::{OsRng, RngCore};
use transport::session_resume::{FrontendGeneration, HostInstance, SessionLocator};

use super::authorization_contract::AttachGrant;
#[cfg(feature = "system")]
use crate::helper::server::policy_check::{SystemCredential, SystemPolicyApproval};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityError {
    InvalidLimits,
    Capacity,
    Exhausted,
    Unavailable,
    Refused,
}

pub(super) fn fresh_bytes<const N: usize>() -> Result<[u8; N], AuthorityError> {
    for _ in 0..8 {
        let mut bytes = [0; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| AuthorityError::Unavailable)?;
        if bytes != [0; N] {
            return Ok(bytes);
        }
    }
    Err(AuthorityError::Unavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostMode {
    System,
    Personal { canonical_uid: u32 },
}

/// Only a future real local-peer adapter may create this value. In particular,
/// neither a decoded UID nor another process's public Principal is evidence.
#[derive(Debug)]
pub(crate) struct AuthenticatedPeer {
    host: HostInstance,
    mode: HostMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrontendAdmission {
    host: HostInstance,
    generation: FrontendGeneration,
    serial: u64,
}
impl FrontendAdmission {
    pub(super) fn generation(self) -> FrontendGeneration {
        self.generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticationAttempt {
    host: HostInstance,
    identity: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CredentialRegistration {
    host: HostInstance,
    identity: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CanonicalAccount {
    uid: u32,
    name: String,
}
impl CanonicalAccount {
    pub(super) fn uid(&self) -> u32 {
        self.uid
    }
}

/// A private observation from the matching real credential adapter. Actual
/// system key material is retained through an opaque verified-key capability,
/// alongside its independently resolved canonical account. No caller-provided
/// identity maps an account into the catalog.
#[derive(Debug)]
struct VerifiedIdentity {
    account: CanonicalAccount,
    #[cfg(feature = "system")]
    system_credential: Option<SystemCredential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyKind {
    Authenticate,
    IssueGrant,
    ConsumeGrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PolicyBinding {
    host: HostInstance,
    mode: HostMode,
    frontend: FrontendAdmission,
    attempt: AuthenticationAttempt,
    operation: u64,
    kind: PolicyKind,
    target: Option<SessionLocator>,
    credential: Option<CredentialRegistration>,
    grant: Option<AttachGrant>,
    revision: u64,
    deadline: u64,
}

/// Non-Clone and non-serializable. Moving this work to an adapter transfers no
/// approval; only its exact pending destination may receive a policy result.
#[derive(Debug)]
pub(crate) struct PolicyIntent {
    binding: PolicyBinding,
    #[cfg(feature = "system")]
    system_credential: Option<SystemCredential>,
}

/// Opaque host/frontend/attempt binding carried by a verified system key.
#[cfg(feature = "system")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SystemContext {
    host: HostInstance,
    frontend: FrontendAdmission,
    attempt: AuthenticationAttempt,
}

/// Successful system construction requires the isolated verifier's sealed
/// approval. No bool, public Principal, UID, or wire frame can construct it.
#[derive(Debug)]
pub(crate) struct PolicyResult {
    binding: PolicyBinding,
    observation: Option<VerifiedIdentity>,
}

#[derive(Debug)]
struct Attempt {
    handle: AuthenticationAttempt,
    frontend: FrontendAdmission,
    credential: Option<(CredentialRegistration, CanonicalAccount)>,
    #[cfg(feature = "system")]
    system_credential: Option<SystemCredential>,
}

#[derive(Debug)]
pub(super) struct ApprovedPolicy {
    pub kind: PolicyKind,
    pub attempt: AuthenticationAttempt,
    pub frontend: FrontendAdmission,
    pub account: CanonicalAccount,
    pub locator: SessionLocator,
    pub grant: Option<AttachGrant>,
}
#[derive(Debug)]
pub(super) enum PolicyResolution {
    Authenticated(AuthenticationAttempt),
    Approved(ApprovedPolicy),
}

#[derive(Debug)]
pub(super) struct AuthorizationState {
    host: HostInstance,
    mode: HostMode,
    max_frontends: usize,
    max_attempts: usize,
    max_pending: usize,
    frontends: Vec<FrontendAdmission>,
    attempts: Vec<Attempt>,
    pending: Vec<PolicyBinding>,
    last_frontend: u64,
    last_operation: u64,
    revision: u64,
    last_now: u64,
    sealed: bool,
}
impl AuthorizationState {
    pub(super) fn new(
        host: HostInstance,
        mode: HostMode,
        frontends: usize,
        attempts: usize,
        pending: usize,
    ) -> Result<Self, AuthorityError> {
        if frontends == 0
            || attempts == 0
            || pending == 0
            || frontends
                .checked_mul(std::mem::size_of::<FrontendAdmission>())
                .is_none_or(|n| n > isize::MAX as usize)
            || attempts
                .checked_mul(std::mem::size_of::<Attempt>())
                .is_none_or(|n| n > isize::MAX as usize)
            || pending
                .checked_mul(std::mem::size_of::<PolicyBinding>())
                .is_none_or(|n| n > isize::MAX as usize)
        {
            return Err(AuthorityError::InvalidLimits);
        }
        Ok(Self {
            host,
            mode,
            max_frontends: frontends,
            max_attempts: attempts,
            max_pending: pending,
            frontends: Vec::new(),
            attempts: Vec::new(),
            pending: Vec::new(),
            last_frontend: 0,
            last_operation: 0,
            revision: 0,
            last_now: 0,
            sealed: false,
        })
    }
    fn observe(&mut self, now: u64) -> Result<(), AuthorityError> {
        if now < self.last_now {
            return Err(AuthorityError::Refused);
        }
        self.last_now = now;
        Ok(())
    }
    pub(super) fn admit_frontend(
        &mut self,
        peer: AuthenticatedPeer,
    ) -> Result<FrontendAdmission, AuthorityError> {
        if self.sealed {
            return Err(AuthorityError::Exhausted);
        }
        if peer.host != self.host || peer.mode != self.mode {
            return Err(AuthorityError::Refused);
        }
        if self.frontends.len() >= self.max_frontends {
            return Err(AuthorityError::Capacity);
        }
        let serial = self
            .last_frontend
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?;
        let generation =
            FrontendGeneration::new(fresh_bytes()?).ok_or(AuthorityError::Unavailable)?;
        if self.frontends.iter().any(|f| f.generation == generation) {
            return Err(AuthorityError::Unavailable);
        }
        let frontend = FrontendAdmission {
            host: self.host,
            generation,
            serial,
        };
        self.frontends.push(frontend);
        self.last_frontend = serial;
        Ok(frontend)
    }
    pub(super) fn begin_authentication(
        &mut self,
        frontend: FrontendAdmission,
        now: u64,
        deadline: u64,
    ) -> Result<PolicyIntent, AuthorityError> {
        self.observe(now)?;
        if self.sealed {
            return Err(AuthorityError::Exhausted);
        }
        if !self.frontends.contains(&frontend) || deadline <= now {
            return Err(AuthorityError::Refused);
        }
        if self.attempts.len() >= self.max_attempts || self.pending.len() >= self.max_pending {
            return Err(AuthorityError::Capacity);
        }
        let operation = self
            .last_operation
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?;
        let handle = AuthenticationAttempt {
            host: self.host,
            identity: fresh_bytes()?,
        };
        if self.attempts.iter().any(|a| a.handle == handle) {
            return Err(AuthorityError::Unavailable);
        }
        let binding = PolicyBinding {
            host: self.host,
            mode: self.mode,
            frontend,
            attempt: handle,
            operation,
            kind: PolicyKind::Authenticate,
            target: None,
            credential: None,
            grant: None,
            revision: self.revision,
            deadline,
        };
        self.attempts.push(Attempt {
            handle,
            frontend,
            credential: None,
            #[cfg(feature = "system")]
            system_credential: None,
        });
        self.pending.push(binding);
        self.last_operation = operation;
        Ok(PolicyIntent {
            binding,
            #[cfg(feature = "system")]
            system_credential: None,
        })
    }
    pub(super) fn identity(
        &self,
        handle: AuthenticationAttempt,
    ) -> Result<(&CanonicalAccount, FrontendAdmission), AuthorityError> {
        if self.sealed {
            return Err(AuthorityError::Exhausted);
        }
        let a = self
            .attempts
            .iter()
            .find(|a| a.handle == handle)
            .ok_or(AuthorityError::Refused)?;
        if !self.frontends.contains(&a.frontend) {
            return Err(AuthorityError::Refused);
        }
        let (_, account) = a.credential.as_ref().ok_or(AuthorityError::Refused)?;
        Ok((account, a.frontend))
    }
    #[allow(clippy::too_many_arguments)] // Exact typed operation binding plus its host deadline.
    pub(super) fn begin_policy(
        &mut self,
        attempt: AuthenticationAttempt,
        kind: PolicyKind,
        target: SessionLocator,
        grant: Option<AttachGrant>,
        now: u64,
        deadline: u64,
    ) -> Result<PolicyIntent, AuthorityError> {
        self.observe(now)?;
        if self.sealed {
            return Err(AuthorityError::Exhausted);
        }
        if kind == PolicyKind::Authenticate
            || (kind == PolicyKind::ConsumeGrant) != grant.is_some()
            || deadline <= now
        {
            return Err(AuthorityError::Refused);
        }
        let a = self
            .attempts
            .iter()
            .find(|a| a.handle == attempt)
            .ok_or(AuthorityError::Refused)?;
        let credential = a
            .credential
            .as_ref()
            .map(|(c, _)| *c)
            .ok_or(AuthorityError::Refused)?;
        if !self.frontends.contains(&a.frontend) {
            return Err(AuthorityError::Refused);
        }
        if self.pending.len() >= self.max_pending {
            return Err(AuthorityError::Capacity);
        }
        let operation = self
            .last_operation
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?;
        let binding = PolicyBinding {
            host: self.host,
            mode: self.mode,
            frontend: a.frontend,
            attempt,
            operation,
            kind,
            target: Some(target),
            credential: Some(credential),
            grant,
            revision: self.revision,
            deadline,
        };
        self.pending.push(binding);
        self.last_operation = operation;
        Ok(PolicyIntent {
            binding,
            #[cfg(feature = "system")]
            system_credential: a.system_credential.clone(),
        })
    }
    pub(super) fn resolve(
        &mut self,
        result: PolicyResult,
        now: u64,
    ) -> Result<PolicyResolution, AuthorityError> {
        self.observe(now)?;
        let b = result.binding;
        let i = self
            .pending
            .iter()
            .position(|p| *p == b)
            .ok_or(AuthorityError::Refused)?;
        self.pending.swap_remove(i);
        let valid = b.host == self.host
            && b.revision == self.revision
            && now < b.deadline
            && self.frontends.contains(&b.frontend);
        if !valid || result.observation.is_none() {
            self.cancel_attempt(b.attempt)?;
            return Err(AuthorityError::Refused);
        }
        let observation = result.observation.ok_or(AuthorityError::Refused)?;
        if matches!(self.mode, HostMode::Personal { canonical_uid } if observation.account.uid != canonical_uid)
            || observation.account.name.is_empty()
            || observation.account.name.len() > transport::auth::AUTH_LOGIN_MAX
            || observation.account.name.contains(['\0', '/'])
        {
            self.cancel_attempt(b.attempt)?;
            return Err(AuthorityError::Refused);
        }
        let a = self
            .attempts
            .iter_mut()
            .find(|a| a.handle == b.attempt && a.frontend == b.frontend)
            .ok_or(AuthorityError::Refused)?;
        if b.kind == PolicyKind::Authenticate {
            if a.credential.is_some()
                || b.credential.is_some()
                || b.target.is_some()
                || b.grant.is_some()
            {
                return Err(AuthorityError::Refused);
            }
            #[cfg(feature = "system")]
            {
                a.system_credential = observation.system_credential;
            }
            a.credential = Some((
                CredentialRegistration {
                    host: self.host,
                    identity: fresh_bytes()?,
                },
                observation.account,
            ));
            return Ok(PolicyResolution::Authenticated(b.attempt));
        }
        let (credential, account) = a.credential.as_ref().ok_or(AuthorityError::Refused)?;
        #[cfg(feature = "system")]
        let credential_matches = match (&a.system_credential, &observation.system_credential) {
            (Some(old), Some(new)) => old.same_registration(new),
            (None, None) => true,
            _ => false,
        };
        #[cfg(not(feature = "system"))]
        let credential_matches = true;
        if Some(*credential) != b.credential
            || *account != observation.account
            || !credential_matches
        {
            self.cancel_attempt(b.attempt)?;
            return Err(AuthorityError::Refused);
        }
        Ok(PolicyResolution::Approved(ApprovedPolicy {
            kind: b.kind,
            attempt: b.attempt,
            frontend: b.frontend,
            account: observation.account,
            locator: b.target.ok_or(AuthorityError::Refused)?,
            grant: b.grant,
        }))
    }
    pub(super) fn cancel_attempt(
        &mut self,
        attempt: AuthenticationAttempt,
    ) -> Result<(), AuthorityError> {
        let i = self
            .attempts
            .iter()
            .position(|a| a.handle == attempt)
            .ok_or(AuthorityError::Refused)?;
        self.attempts.swap_remove(i);
        self.pending.retain(|p| p.attempt != attempt);
        Ok(())
    }
    pub(super) fn retire_frontend(
        &mut self,
        frontend: FrontendAdmission,
    ) -> Result<(), AuthorityError> {
        let i = self
            .frontends
            .iter()
            .position(|f| *f == frontend)
            .ok_or(AuthorityError::Refused)?;
        self.frontends.swap_remove(i);
        self.pending.retain(|p| p.frontend != frontend);
        self.attempts.retain(|a| a.frontend != frontend);
        Ok(())
    }
    pub(super) fn revoke_account(&mut self, uid: u32) -> Result<(), AuthorityError> {
        let Some(revision) = self.revision.checked_add(1) else {
            // Known revocation must win even at exhaustion. Seal new admission
            // and retire every transient authority; never wrap/reuse a revision.
            self.sealed = true;
            self.pending.clear();
            self.attempts.clear();
            return Err(AuthorityError::Exhausted);
        };
        self.revision = revision;
        // One bounded global revision avoids an unbounded account-revocation map.
        // Unrelated pending work retries a fresh observation; live sessions stay.
        self.pending.clear();
        self.attempts.retain(|a| {
            a.credential
                .as_ref()
                .is_some_and(|(_, account)| account.uid != uid)
        });
        Ok(())
    }
    pub(super) fn sweep(&mut self, now: u64) -> Result<(), AuthorityError> {
        self.observe(now)?;
        self.pending.retain(|p| now < p.deadline);
        self.attempts.retain(|a| {
            a.credential.is_some() || self.pending.iter().any(|p| p.attempt == a.handle)
        });
        Ok(())
    }
    pub(super) fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub(super) fn attempt_count(&self) -> usize {
        self.attempts.len()
    }
}

#[cfg(feature = "system")]
impl PolicyIntent {
    pub(crate) fn system_context(&self) -> Option<SystemContext> {
        (self.binding.mode == HostMode::System).then_some(SystemContext {
            host: self.binding.host,
            frontend: self.binding.frontend,
            attempt: self.binding.attempt,
        })
    }
    pub(crate) fn attempt(&self) -> AuthenticationAttempt {
        self.binding.attempt
    }
    pub(crate) fn kind(&self) -> PolicyKind {
        self.binding.kind
    }
    pub(crate) fn deadline(&self) -> u64 {
        self.binding.deadline
    }
    pub(crate) fn system_credential(&self) -> Option<&SystemCredential> {
        self.system_credential.as_ref()
    }
}
#[cfg(feature = "system")]
impl PolicyResult {
    pub(crate) fn from_system(intent: PolicyIntent, approval: SystemPolicyApproval) -> Self {
        let (uid, name, credential) = approval.into_parts();
        let observation =
            (intent.system_context() == Some(credential.context())).then_some(VerifiedIdentity {
                account: CanonicalAccount { uid, name },
                system_credential: Some(credential),
            });
        Self {
            binding: intent.binding,
            observation,
        }
    }
    pub(crate) fn system_refusal(intent: PolicyIntent) -> Self {
        Self {
            binding: intent.binding,
            observation: None,
        }
    }
}

#[cfg(test)]
impl AuthenticatedPeer {
    pub(crate) fn for_test(host: HostInstance, mode: HostMode) -> Self {
        Self { host, mode }
    }
}
#[cfg(test)]
impl PolicyIntent {
    pub(crate) fn copy_for_test(&self) -> Self {
        Self {
            binding: self.binding,
            #[cfg(feature = "system")]
            system_credential: self.system_credential.clone(),
        }
    }
}
#[cfg(test)]
impl PolicyResult {
    pub(super) fn allow_for_test(intent: PolicyIntent, uid: u32, name: &str) -> Self {
        Self {
            binding: intent.binding,
            observation: Some(VerifiedIdentity {
                account: CanonicalAccount {
                    uid,
                    name: name.to_string(),
                },
                #[cfg(feature = "system")]
                system_credential: None,
            }),
        }
    }
    pub(super) fn refuse_for_test(intent: PolicyIntent) -> Self {
        Self {
            binding: intent.binding,
            observation: None,
        }
    }
}
#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
