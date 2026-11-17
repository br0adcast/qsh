//! Checked Linux owner operations; no physical owner process is activated.
use super::authorization::{AuthenticationAttempt, FrontendAdmission, HostMode};
use super::host::{HostError, HostState};
use super::host_engine::{LocalBinding, LocalEngineError, LocalOwnerEngine};
use std::sync::Arc;
use transport::session_resume::Attachment;

#[derive(Debug)]
pub(crate) enum LinuxOwnerError {
    Refused,
    Host(HostError),
    Engine(LocalEngineError),
}
impl From<HostError> for LinuxOwnerError {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}
impl From<LocalEngineError> for LinuxOwnerError {
    fn from(error: LocalEngineError) -> Self {
        Self::Engine(error)
    }
}
/// Correlation fields alone cannot mint this checked route. It never owns an engine.
pub(crate) struct LinuxOwnerRoute {
    binding: Arc<LocalBinding>,
    frontend: FrontendAdmission,
    attempt: AuthenticationAttempt,
    attachment: Attachment,
}
impl LinuxOwnerRoute {
    pub(crate) fn bind_personal(
        host: &HostState,
        owner: &LocalOwnerEngine,
        frontend: FrontendAdmission,
        attempt: AuthenticationAttempt,
        attachment: Attachment,
    ) -> Result<Self, LinuxOwnerError> {
        let binding = owner.supervision_binding();
        let mode = host.authorize_linux_route(binding, frontend, attempt, attachment)?;
        if !matches!(mode, HostMode::Personal { .. }) {
            return Err(LinuxOwnerError::Refused);
        }
        owner.validate_attachment(attachment)?;
        Ok(Self {
            binding: binding.clone(),
            frontend,
            attempt,
            attachment,
        })
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
