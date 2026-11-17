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
    operation: Operation,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Ready,
    Detaching,
    Detached,
    Terminating,
    Terminated,
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
            operation: Operation::Ready,
        })
    }
    fn destination(
        &self,
        host: &HostState,
        owner: &LocalOwnerEngine,
    ) -> Result<(), LinuxOwnerError> {
        if host.instance() != self.binding.identity.host
            || !Arc::ptr_eq(&self.binding, owner.supervision_binding())
        {
            return Err(LinuxOwnerError::Refused);
        }
        Ok(())
    }
    fn current(&self, host: &HostState, owner: &LocalOwnerEngine) -> Result<(), LinuxOwnerError> {
        self.destination(host, owner)?;
        host.authorize_linux_route(&self.binding, self.frontend, self.attempt, self.attachment)?;
        owner.validate_attachment(self.attachment)?;
        Ok(())
    }
    pub(crate) fn begin_detach(
        &mut self,
        host: &mut HostState,
        owner: &mut LocalOwnerEngine,
    ) -> Result<(), LinuxOwnerError> {
        self.destination(host, owner)?;
        if self.operation == Operation::Detaching {
            return Ok(());
        }
        if self.operation != Operation::Ready {
            return Err(LinuxOwnerError::Refused);
        }
        self.current(host, owner)?;
        owner.frontend_lost(host, self.attachment)?;
        self.operation = Operation::Detaching;
        Ok(())
    }
    pub(crate) async fn finish_detach(
        &mut self,
        host: &mut HostState,
        owner: &mut LocalOwnerEngine,
    ) -> Result<(), LinuxOwnerError> {
        self.destination(host, owner)?;
        if self.operation == Operation::Detached {
            return Ok(());
        }
        if self.operation != Operation::Detaching
            || owner.supervision_attachment() != Some(self.attachment)
        {
            return Err(LinuxOwnerError::Refused);
        }
        owner.finish_detach(host).await?;
        self.operation = Operation::Detached;
        Ok(())
    }
    pub(crate) fn begin_terminate(
        &mut self,
        host: &mut HostState,
        owner: &mut LocalOwnerEngine,
    ) -> Result<(), LinuxOwnerError> {
        self.destination(host, owner)?;
        if self.operation == Operation::Terminating {
            return Ok(());
        }
        if self.operation != Operation::Ready {
            return Err(LinuxOwnerError::Refused);
        }
        self.current(host, owner)?;
        owner.begin_terminate(host, self.attachment)?;
        self.operation = Operation::Terminating;
        Ok(())
    }
    pub(crate) async fn finish_terminate(
        &mut self,
        host: &mut HostState,
        owner: &mut LocalOwnerEngine,
        now: u64,
    ) -> Result<(), LinuxOwnerError> {
        self.destination(host, owner)?;
        if self.operation == Operation::Terminated {
            return Ok(());
        }
        if self.operation != Operation::Terminating {
            return Err(LinuxOwnerError::Refused);
        }
        owner.close(host, now).await?;
        self.operation = Operation::Terminated;
        Ok(())
    }
}
#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
