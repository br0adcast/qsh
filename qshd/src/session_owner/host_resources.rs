//! Catalog-issued resource custody; it does not establish or attach an owner.
use super::authorization_contract::PrincipalRegistration;
use super::owner_resource_contract::OwnerResourceRequest;
use super::protocol::OwnerProtocolError;
use super::resource_contract::{HostResourceBinding, ResourceLedger};
use super::resources::{AdmittedReservation, OwnerResourceClient, StorageCharge};
use std::sync::{Arc, Mutex};
use transport::session_resume::{HostInstance, RequestId, SessionLocator};
/// Nonclone provisioning minted only with the host's freshly inserted catalog entry.
pub(crate) struct OwnerProvisioning {
    binding: HostResourceBinding,
    client: OwnerResourceClient,
}
impl OwnerProvisioning {
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
