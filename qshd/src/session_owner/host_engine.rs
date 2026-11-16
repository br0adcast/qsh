//! Sealed in-process host-to-engine custody. No production route constructs it.
use super::engine::{EngineError, FrontendAttachment, SessionFence, SessionOwnerEngine};
use super::host::{AuthorizedAttachment, CleanupIntent, HostError, HostState};
use super::host_resources::OwnerProvisioning;
use super::resource_contract::HostResourceBinding;
use std::sync::{Arc, Mutex};
use transport::session_resume::Attachment;

#[derive(Debug)]
pub(crate) enum LocalEngineError {
    Host(HostError),
    Engine(EngineError),
    Binding,
    AlreadyBound,
    AlreadyAttached,
}
pub(crate) struct LocalEngineBindFailure {
    error: LocalEngineError,
    inputs: Box<(OwnerProvisioning, SessionOwnerEngine)>,
}
impl LocalEngineBindFailure {
    pub(crate) fn into_parts(self) -> (LocalEngineError, OwnerProvisioning, SessionOwnerEngine) {
        let (provisioning, engine) = *self.inputs;
        (self.error, provisioning, engine)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LocalLeasePhase {
    Detached,
    Reserved(Attachment),
    Attached(Attachment),
    Fencing(Attachment),
    Closing,
    Unknown,
    Complete,
}
#[derive(Debug)]
pub(super) struct LocalBinding {
    pub(super) identity: HostResourceBinding,
    pub(super) phase: Mutex<LocalLeasePhase>,
}
pub(crate) struct LocalOwnerEngine {
    provisioning: OwnerProvisioning,
    engine: SessionOwnerEngine,
    frontend: Option<FrontendAttachment>,
    fence: Option<SessionFence>,
    binding: Arc<LocalBinding>,
    empty_completion: Option<super::engine::LocalEmptyCompletion>,
    establishment: Option<super::engine::LocalEstablishment>,
    completion: Option<super::engine::LocalCompletion>,
    cleanup: Option<CleanupIntent>,
    close_receipts: Vec<transport::channel_owner::RetainedCleanup>,
    engine_closed: bool,
    established: bool,
}
impl From<HostError> for LocalEngineError {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}
impl From<EngineError> for LocalEngineError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}
impl LocalOwnerEngine {
    pub(crate) fn provision_channel_resources(
        &self,
        host: &HostState,
        attachment: Attachment,
        requests: (
            super::owner_resource_contract::OwnerResourceRequest,
            super::owner_resource_contract::OwnerResourceRequest,
        ),
        cleanup: transport::session_resume::RequestId,
        read_buffer_bytes: usize,
        input_epoch: transport::session_resume::InputEpoch,
    ) -> Result<super::engine::AdmittedOwnerChannelResources, LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        self.frontend_for(attachment)?;
        self.provisioning
            .reserve_channel_resources(
                requests.0,
                requests.1,
                cleanup,
                read_buffer_bytes,
                input_epoch,
            )
            .map_err(|error| EngineError::Resource(error).into())
    }
    fn frontend_for(
        &self,
        attachment: Attachment,
    ) -> Result<&FrontendAttachment, LocalEngineError> {
        self.validate_current()?;
        let frontend = self.frontend.as_ref().ok_or(LocalEngineError::Binding)?;
        if frontend.attachment() != attachment {
            return Err(EngineError::StaleAttachment.into());
        }
        Ok(frontend)
    }
    pub(crate) fn catalog(
        &self,
        attachment: Attachment,
        allowance: super::recovery_runtime::TransferAllowance,
    ) -> Result<super::engine::OwnerRecovery, LocalEngineError> {
        Ok(self
            .engine
            .catalog(self.frontend_for(attachment)?, allowance)?)
    }
    pub(crate) fn recover(
        &self,
        attachment: Attachment,
        transaction: &mut super::engine::OwnerRecovery,
        request: transport::session_resume::RecoveryRequest,
        recovery: transport::session_resume::RecoveryId,
        request_id: transport::session_resume::RequestId,
        allowance: super::recovery_runtime::TransferAllowance,
    ) -> Result<super::recovery_runtime::RecoveryProducer, LocalEngineError> {
        Ok(self.engine.recover(
            self.frontend_for(attachment)?,
            transaction,
            request,
            recovery,
            request_id,
            allowance,
        )?)
    }
    pub(crate) fn finish_recovery(
        &self,
        attachment: Attachment,
        transaction: super::engine::OwnerRecovery,
    ) -> Result<(), LocalEngineError> {
        Ok(self
            .engine
            .finish_recovery(self.frontend_for(attachment)?, transaction)?)
    }
    pub(crate) fn user_input(
        &self,
        attachment: Attachment,
        channel: transport::channel_geometry::ChannelInstance,
        epoch: transport::session_resume::InputEpoch,
        offset: u64,
        bytes: &[u8],
    ) -> Result<super::engine::InputSubmission, LocalEngineError> {
        Ok(self.engine.user_input(
            self.frontend_for(attachment)?,
            channel,
            epoch,
            offset,
            bytes,
        )?)
    }
    pub(crate) fn resize(
        &mut self,
        attachment: Attachment,
        channel: transport::channel_geometry::ChannelInstance,
        id: transport::channel_geometry::ResizeRequestId,
        cols: u16,
        rows: u16,
    ) -> Result<transport::channel_geometry::GeometryRecord, LocalEngineError> {
        self.frontend_for(attachment)?;
        Ok(self
            .engine
            .resize(self.frontend.as_ref().unwrap(), channel, id, cols, rows)?)
    }
    pub(crate) fn frontend_lost(
        &mut self,
        host: &mut HostState,
        attachment: Attachment,
    ) -> Result<(), LocalEngineError> {
        if self
            .frontend
            .as_ref()
            .is_none_or(|frontend| frontend.attachment() != attachment)
        {
            return Err(EngineError::StaleAttachment.into());
        }
        self.begin_detach(host)
    }
    pub(crate) async fn close_from_frontend(
        &mut self,
        host: &mut HostState,
        attachment: Attachment,
        now: u64,
    ) -> Result<(), LocalEngineError> {
        self.frontend_for(attachment)?;
        self.close(host, now).await
    }
    pub(crate) fn screen_recovery_requirements(
        &self,
        attachment: Attachment,
        channel: transport::channel_geometry::ChannelInstance,
    ) -> Result<super::screen_recovery::ScreenRecoveryRequirements, LocalEngineError> {
        self.frontend_for(attachment)?;
        Ok(self.engine.screen_recovery_requirements(channel)?)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_screen(
        &self,
        attachment: Attachment,
        transaction: &mut super::engine::OwnerRecovery,
        request: transport::session_resume::RecoveryRequest,
        evidence: &super::screen_recovery::ScreenEvidence,
        recovery: transport::session_resume::RecoveryId,
        request_id: transport::session_resume::RequestId,
        allowance: super::screen_recovery::ScreenRecoveryAllowance,
    ) -> Result<super::recovery_runtime::RecoveryProducer, LocalEngineError> {
        Ok(self.engine.recover_screen(
            self.frontend_for(attachment)?,
            transaction,
            request,
            evidence,
            recovery,
            request_id,
            allowance,
        )?)
    }
    fn validate_current(&self) -> Result<(), LocalEngineError> {
        let frontend = self.frontend.as_ref().ok_or(LocalEngineError::Binding)?;
        if *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)?
            != LocalLeasePhase::Attached(frontend.attachment())
        {
            return Err(EngineError::StaleAttachment.into());
        }
        Ok(())
    }
    fn publish_establishment(&mut self, host: &mut HostState) -> Result<(), LocalEngineError> {
        if self.established {
            return Ok(());
        }
        if self.establishment.is_none() {
            self.establishment = self.engine.take_local_establishment();
        }
        let proof = self.establishment.take().ok_or(EngineError::Unavailable)?;
        match host.establish_local_owner(&self.binding, proof) {
            Ok(()) => {
                self.established = true;
                Ok(())
            }
            Err((error, proof)) => {
                self.establishment = Some(proof);
                Err(error.into())
            }
        }
    }
    pub(crate) async fn open_admitted(
        &mut self,
        host: &mut HostState,
        request: transport::channel::OpenRequest,
        term: Option<String>,
        supplied: super::engine::AdmittedOwnerChannelResources,
    ) -> Result<transport::channel_geometry::ChannelInstance, LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        self.validate_current()?;
        let channel = self
            .engine
            .open_admitted(self.frontend.as_ref().unwrap(), request, term, supplied)
            .await?;
        self.publish_establishment(host)?;
        Ok(channel)
    }
    pub(crate) async fn open_screen_admitted(
        &mut self,
        host: &mut HostState,
        request: transport::channel::OpenRequest,
        term: Option<String>,
        supplied: super::engine::AdmittedOwnerChannelResources,
        lease: super::screen_owner::HostScreenLease,
    ) -> Result<transport::channel_geometry::ChannelInstance, LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        self.validate_current()?;
        let channel = self
            .engine
            .open_screen_admitted(
                self.frontend.as_ref().unwrap(),
                request,
                term,
                supplied,
                lease,
            )
            .await?;
        self.publish_establishment(host)?;
        Ok(channel)
    }
    pub(crate) async fn close(
        &mut self,
        host: &mut HostState,
        now: u64,
    ) -> Result<(), LocalEngineError> {
        if *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)?
            == LocalLeasePhase::Complete
        {
            return if host.instance() == self.binding.identity.host {
                Ok(())
            } else {
                Err(LocalEngineError::Binding)
            };
        }
        host.validate_local_binding(&self.binding)?;
        if self.engine.locally_established() {
            self.publish_establishment(host)?;
            if self.cleanup.is_none() {
                self.cleanup = Some(host.begin_owner_cleanup(self.binding.identity.locator)?);
            }
            *self
                .binding
                .phase
                .lock()
                .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Closing;
            if !self.engine_closed {
                self.close_receipts = self.engine.close_session().await?;
                self.engine_closed = true;
            }
            if self.completion.is_none() {
                self.completion = self.engine.take_local_completion();
            }
            // Our settled lease/fence references are not independent backing.
            self.frontend.take();
            self.fence.take();
            let proof = self.completion.take().ok_or(EngineError::CleanupPending)?;
            if let Err((error, proof)) =
                host.complete_local_owner(&self.binding, self.cleanup.as_ref().unwrap(), proof, now)
            {
                self.completion = Some(proof);
                return Err(error.into());
            }
            drop(std::mem::take(&mut self.close_receipts));
        } else {
            *self
                .binding
                .phase
                .lock()
                .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Closing;
            if self.empty_completion.is_none() {
                self.empty_completion = Some(self.engine.close_local_empty().await?);
            }
            self.frontend.take();
            self.fence.take();
            host.complete_local_empty(&self.binding, self.empty_completion.as_ref().unwrap(), now)?;
            self.empty_completion.take();
        }
        *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Complete;
        Ok(())
    }
    pub(crate) fn attach(
        &mut self,
        host: &mut HostState,
        authorized: AuthorizedAttachment,
    ) -> Result<Attachment, LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        let attachment = host.consume_local_authority(&self.binding, authorized)?;
        if self.frontend.is_some() {
            return Err(LocalEngineError::AlreadyAttached);
        }
        let frontend = match self.engine.attach_trusted(attachment) {
            Ok(frontend) => frontend,
            Err(error) => {
                *self
                    .binding
                    .phase
                    .lock()
                    .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Unknown;
                return Err(error.into());
            }
        };
        self.frontend = Some(frontend);
        *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Attached(attachment);
        Ok(attachment)
    }
    pub(crate) fn begin_detach(&mut self, host: &mut HostState) -> Result<(), LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        let frontend = self.frontend.as_ref().ok_or(LocalEngineError::Binding)?;
        let attachment = frontend.attachment();
        {
            let mut phase = self
                .binding
                .phase
                .lock()
                .map_err(|_| LocalEngineError::Binding)?;
            if !matches!(*phase, LocalLeasePhase::Attached(a) | LocalLeasePhase::Fencing(a) if a == attachment)
            {
                return Err(LocalEngineError::Binding);
            }
            *phase = LocalLeasePhase::Fencing(attachment);
        }
        if self.fence.is_none() {
            self.fence = Some(self.engine.fence(frontend)?);
        }
        Ok(())
    }
    pub(crate) async fn finish_detach(
        &mut self,
        host: &mut HostState,
    ) -> Result<(), LocalEngineError> {
        host.validate_local_binding(&self.binding)?;
        let attachment = self
            .frontend
            .as_ref()
            .ok_or(LocalEngineError::Binding)?
            .attachment();
        if *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)?
            != LocalLeasePhase::Fencing(attachment)
        {
            return Err(LocalEngineError::Binding);
        }
        self.fence
            .as_ref()
            .ok_or(LocalEngineError::Binding)?
            .wait_completed()
            .await?;
        host.validate_local_binding(&self.binding)?;
        *self
            .binding
            .phase
            .lock()
            .map_err(|_| LocalEngineError::Binding)? = LocalLeasePhase::Detached;
        self.fence.take();
        self.frontend.take();
        Ok(())
    }
}
impl Drop for LocalOwnerEngine {
    fn drop(&mut self) {
        let mut phase = self
            .binding
            .phase
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if *phase != LocalLeasePhase::Complete {
            *phase = LocalLeasePhase::Unknown;
        }
    }
}
impl HostState {
    pub(crate) fn bind_local_engine(
        &mut self,
        provisioning: OwnerProvisioning,
        mut engine: SessionOwnerEngine,
    ) -> Result<LocalOwnerEngine, LocalEngineBindFailure> {
        let binding = match self.pin_local_engine(&provisioning, &engine) {
            Ok(binding) => binding,
            Err(error) => {
                return Err(LocalEngineBindFailure {
                    error,
                    inputs: Box::new((provisioning, engine)),
                })
            }
        };
        engine.bind_local_binding(&binding);
        Ok(LocalOwnerEngine {
            provisioning,
            engine,
            frontend: None,
            fence: None,
            binding,
            empty_completion: None,
            establishment: None,
            completion: None,
            cleanup: None,
            close_receipts: Vec::new(),
            engine_closed: false,
            established: false,
        })
    }
}
#[cfg(test)]
#[path = "host_engine_tests.rs"]
mod tests;
