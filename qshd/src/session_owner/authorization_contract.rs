//! Pure host decision ledger. Registration is a runtime authentication seam,
//! never proof that a frontend-provided identity has authenticated.
use transport::session_resume::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticatedPrincipalRef([u8; 16]);
impl AuthenticatedPrincipalRef {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachGrant([u8; 32]);
impl AttachGrant {
    pub fn new(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0; 32]).then_some(Self(bytes))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl std::fmt::Debug for AttachGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachGrant([REDACTED])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantBinding {
    pub principal: AuthenticatedPrincipalRef,
    pub locator: SessionLocator,
    pub frontend: FrontendGeneration,
    pub owner: OwnerInstance,
    pub expires_at_monotonic: u64,
}
impl GrantBinding {
    pub fn validate(self) -> Result<(), ResumeError> {
        if self.owner != self.locator.owner || self.expires_at_monotonic == 0 {
            Err(ResumeError::Malformed)
        } else {
            Ok(())
        }
    }
}
/// Host-generated fresh scope for exactly one ledger incarnation. The host must
/// mint a different value for every construction/reconstruction; never reuse it.
/// This is an identity check, not authentication or a random generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerInstance([u8; 16]);
impl LedgerInstance {
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }
}
/// Local host authority handle. Private fields prevent manufacturing a serial;
/// the owning ledger also checks the active registration and its incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalRegistration {
    pub(super) ledger: LedgerInstance,
    pub(super) serial: u64,
    pub(super) principal: AuthenticatedPrincipalRef,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontendRegistration {
    ledger: LedgerInstance,
    serial: u64,
    frontend: FrontendGeneration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantAuthority {
    pub principal: PrincipalRegistration,
    pub frontend: FrontendRegistration,
}
#[derive(Debug)]
struct Entry {
    grant: AttachGrant,
    binding: GrantBinding,
    authority: GrantAuthority,
    consumed: bool,
}
#[derive(Debug)]
pub struct GrantLedger {
    scope: LedgerInstance,
    capacity: usize,
    principals: Vec<PrincipalRegistration>,
    frontends: Vec<FrontendRegistration>,
    entries: Vec<Entry>,
    last_now: u64,
    last_registration: u64,
}
impl GrantLedger {
    pub fn new(scope: LedgerInstance, capacity: usize) -> Result<Self, ResumeError> {
        if capacity == 0
            || capacity
                .checked_mul(std::mem::size_of::<Entry>())
                .is_none_or(|v| v > isize::MAX as usize)
        {
            return Err(ResumeError::TooLarge);
        }
        Ok(Self {
            scope,
            capacity,
            principals: Vec::new(),
            frontends: Vec::new(),
            entries: Vec::new(),
            last_now: 0,
            last_registration: 0,
        })
    }
    /// Trusted host seam: register only an independently authenticated fresh
    /// principal lifetime. A public reference by itself grants no authority.
    pub fn register_fresh_principal(
        &mut self,
        principal: AuthenticatedPrincipalRef,
    ) -> Result<PrincipalRegistration, ResumeError> {
        if self.principals.iter().any(|p| p.principal == principal) {
            return Err(ResumeError::InvalidState);
        }
        if self.principals.len() >= self.capacity {
            return Err(ResumeError::RequestLimit);
        }
        let serial = self
            .last_registration
            .checked_add(1)
            .ok_or(ResumeError::Overflow)?;
        let p = PrincipalRegistration {
            ledger: self.scope,
            serial,
            principal,
        };
        self.principals.push(p);
        self.last_registration = serial;
        Ok(p)
    }
    /// Trusted host seam: the host independently admits a fresh frontend lifetime.
    /// Inserting a grant can never create or resurrect this registration.
    pub fn register_fresh_frontend(
        &mut self,
        frontend: FrontendGeneration,
    ) -> Result<FrontendRegistration, ResumeError> {
        if self.frontends.iter().any(|f| f.frontend == frontend) {
            return Err(ResumeError::InvalidState);
        }
        if self.frontends.len() >= self.capacity {
            return Err(ResumeError::RequestLimit);
        }
        let serial = self
            .last_registration
            .checked_add(1)
            .ok_or(ResumeError::Overflow)?;
        let f = FrontendRegistration {
            ledger: self.scope,
            serial,
            frontend,
        };
        self.frontends.push(f);
        self.last_registration = serial;
        Ok(f)
    }
    fn validate_authority(
        &self,
        authority: GrantAuthority,
        binding: GrantBinding,
    ) -> Result<(), ResumeError> {
        binding.validate()?;
        if authority.principal.ledger != self.scope
            || authority.frontend.ledger != self.scope
            || authority.principal.principal != binding.principal
            || authority.frontend.frontend != binding.frontend
            || !self.principals.contains(&authority.principal)
            || !self.frontends.contains(&authority.frontend)
        {
            return Err(ResumeError::InvalidState);
        }
        Ok(())
    }
    pub fn insert(
        &mut self,
        authority: GrantAuthority,
        grant: AttachGrant,
        binding: GrantBinding,
        now: u64,
    ) -> Result<(), ResumeError> {
        self.validate_authority(authority, binding)?;
        if now < self.last_now
            || binding.expires_at_monotonic <= now
            || self.entries.iter().any(|e| e.grant == grant)
        {
            return Err(ResumeError::InvalidState);
        }
        if self
            .entries
            .iter()
            .filter(|e| e.binding.expires_at_monotonic > now)
            .count()
            >= self.capacity
        {
            return Err(ResumeError::RequestLimit);
        }
        self.entries
            .retain(|e| e.binding.expires_at_monotonic > now);
        self.entries.push(Entry {
            grant,
            binding,
            authority,
            consumed: false,
        });
        self.last_now = now;
        Ok(())
    }
    pub fn consume(
        &mut self,
        authority: GrantAuthority,
        grant: AttachGrant,
        binding: GrantBinding,
        now: u64,
        epoch: AttachEpoch,
    ) -> Result<Attachment, ResumeError> {
        self.validate_authority(authority, binding)?;
        if now < self.last_now {
            return Err(ResumeError::InvalidState);
        }
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.grant == grant && e.authority == authority)
            .ok_or(ResumeError::InvalidState)?;
        if e.consumed || e.binding != binding || now >= e.binding.expires_at_monotonic {
            return Err(ResumeError::InvalidState);
        }
        e.consumed = true;
        self.last_now = now;
        Ok(Attachment {
            locator: binding.locator,
            frontend: binding.frontend,
            epoch,
        })
    }
    /// Revoke and retire atomically. Every outstanding grant is invalidated even
    /// when all registration/grant slots are occupied. No historical tombstones.
    pub fn revoke_frontend(&mut self, frontend: FrontendRegistration) -> Result<(), ResumeError> {
        if frontend.ledger != self.scope || !self.frontends.contains(&frontend) {
            return Err(ResumeError::InvalidState);
        }
        self.entries.retain(|e| e.authority.frontend != frontend);
        self.frontends.retain(|f| *f != frontend);
        Ok(())
    }
    /// Trusted retirement revokes unconsumed grants; it never closes a PTY/login.
    pub fn retire_principal(
        &mut self,
        principal: PrincipalRegistration,
    ) -> Result<(), ResumeError> {
        if principal.ledger != self.scope || !self.principals.contains(&principal) {
            return Err(ResumeError::InvalidState);
        }
        self.entries.retain(|e| e.authority.principal != principal);
        self.principals.retain(|p| *p != principal);
        Ok(())
    }
    pub fn grants(&self) -> usize {
        self.entries.len()
    }
    pub fn principals(&self) -> usize {
        self.principals.len()
    }
    pub fn frontends(&self) -> usize {
        self.frontends.len()
    }
}
