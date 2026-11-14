//! Optional evidence for an already admitted same-account personal frontend.
//! The trusted frontend delegates its actual Noise execution; this does not
//! independently verify Noise in a host or authorize system accounts.
use crate::session_manager::binding_revision::BindingRevision;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused;

/// Opaque association minted for one exact probation before msg2 is sent.
#[derive(Clone)]
pub struct PersonalBinding(Arc<Binding>);
struct Binding {
    session_id: u64,
    key: [u8; 32],
    token: [u8; 16],
    revision: BindingRevision,
}
impl PersonalBinding {
    pub(crate) fn new(
        session_id: u64,
        key: [u8; 32],
        token: [u8; 16],
        revision: BindingRevision,
    ) -> Self {
        Self(Arc::new(Binding {
            session_id,
            key,
            token,
            revision,
        }))
    }
    pub fn is_current(&self) -> bool {
        self.0.revision.is_current()
    }
    pub fn client_key(&self) -> [u8; 32] {
        self.0.key
    }
}
/// Non-Clone, non-serializable completion. No public constructor exists.
pub struct PersonalPossessionCompletion {
    binding: PersonalBinding,
}
impl PersonalPossessionCompletion {
    pub(crate) fn from_proven(
        binding: PersonalBinding,
        proven: &crate::probation::ProvenSession,
    ) -> Result<Self, Refused> {
        if !binding.is_current()
            || !proven.revision.is_current()
            || binding.0.session_id != proven.conn.session_id()
            || binding.0.key != proven.client_key
            || binding.0.token != proven.msg1.token
            || proven.msg1.method != crate::handshake_payload::AuthMethod::Allowlist
        {
            return Err(Refused);
        }
        Ok(Self { binding })
    }
    pub fn matches(&self, binding: &PersonalBinding) -> bool {
        Arc::ptr_eq(&self.binding.0, &binding.0) && binding.is_current()
    }
    pub fn client_key(&self) -> [u8; 32] {
        self.binding.client_key()
    }
    pub fn session_id(&self) -> u64 {
        self.binding.0.session_id
    }
    pub fn token(&self) -> [u8; 16] {
        self.binding.0.token
    }
}
/// Implementations reserve a bounded one-use host ticket, never wait for a
/// consumer, and cancel logical authority when their attempt is dropped.
pub trait PersonalAdmissionObserver: Send + Sync {
    fn try_begin(
        &self,
        binding: PersonalBinding,
    ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused>;
}
pub trait PersonalAdmissionAttempt: Send + Sync {
    fn try_complete(self: Box<Self>, proof: PersonalPossessionCompletion) -> Result<(), Refused>;
}
