//! Catalog-issued resource custody; it does not establish or attach an owner.
use super::authorization_contract::PrincipalRegistration;
use super::owner_resource_contract::OwnerResourceRequest;
use super::protocol::OwnerProtocolError;
use super::resource_contract::{HostResourceBinding, ReservationKind, ResourceLedger};
use super::resources::{AdmittedReservation, OwnerResourceClient, StorageCharge};
use std::sync::{Arc, Mutex};
use transport::session_resume::{HostInstance, RequestId, SessionLocator};
/// Private producer custody before any backing/worker can receive this token.
struct UnallocatedHostReservation {
    client: OwnerResourceClient,
    token: Option<AdmittedReservation>,
}
impl UnallocatedHostReservation {
    fn into_token(mut self) -> AdmittedReservation {
        self.token.take().unwrap()
    }
}
impl Drop for UnallocatedHostReservation {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let cleanup = token.cleanup();
            let storage = StorageCharge::owned(self.client.clone(), token, cleanup);
            storage.allow_release();
        }
    }
}
/// Nonclone provisioning minted only with the host's freshly inserted catalog entry.
pub(crate) struct OwnerProvisioning {
    binding: HostResourceBinding,
    client: OwnerResourceClient,
}
impl OwnerProvisioning {
    pub(crate) fn reserve_channel_resources(
        &self,
        history: OwnerResourceRequest,
        control: OwnerResourceRequest,
        cleanup: RequestId,
        read_buffer_bytes: usize,
        input_epoch: transport::session_resume::InputEpoch,
    ) -> Result<super::engine::AdmittedOwnerChannelResources, OwnerProtocolError> {
        history.validate()?;
        control.validate()?;
        if history.locator != self.binding.locator
            || control.locator != self.binding.locator
            || history.channel != control.channel
            || history.kind != ReservationKind::OutputHistory
            || control.kind != ReservationKind::ControlQueue
            || history.screen_charge.is_some()
            || control.screen_charge.is_some()
            || read_buffer_bytes == 0
            || read_buffer_bytes > 16_384
            || history.bytes <= read_buffer_bytes as u64
            || control.bytes < (65_536 + super::writer::CONTROL_METADATA) as u64
        {
            return Err(OwnerProtocolError::Binding);
        }
        let history = UnallocatedHostReservation {
            client: self.client.clone(),
            token: Some(self.reserve(history, cleanup)?),
        };
        let control = self.reserve(control, cleanup)?;
        Ok(super::engine::AdmittedOwnerChannelResources::new(
            history.into_token(),
            control,
            read_buffer_bytes,
            input_epoch,
        ))
    }
    pub(super) fn binding(&self) -> HostResourceBinding {
        self.binding
    }
    pub(super) fn from_catalog(
        host: HostInstance,
        locator: SessionLocator,
        ledger: Arc<Mutex<ResourceLedger>>,
        registration: PrincipalRegistration,
    ) -> Self {
        Self {
            binding: HostResourceBinding { host, locator },
            client: OwnerResourceClient::new(ledger, registration),
        }
    }
    pub(crate) fn reserve(
        &self,
        request: OwnerResourceRequest,
        cleanup: RequestId,
    ) -> Result<AdmittedReservation, OwnerProtocolError> {
        self.client.reserve_host(self.binding, request, cleanup)
    }
    pub(crate) fn client(&self) -> OwnerResourceClient {
        self.client.clone()
    }
    pub(super) fn bind_storage(
        &self,
        admitted: AdmittedReservation,
    ) -> Result<Arc<StorageCharge>, Box<(OwnerProtocolError, AdmittedReservation)>> {
        if let Err(error) = self.client.validate_admitted(&admitted, Some(self.binding)) {
            return Err(Box::new((error, admitted)));
        }
        if admitted.reservation().kind == super::resource_contract::ReservationKind::ScreenModel {
            return Err(Box::new((OwnerProtocolError::Binding, admitted)));
        }
        let cleanup = admitted.cleanup();
        Ok(StorageCharge::new(self.client.clone(), admitted, cleanup))
    }
}
