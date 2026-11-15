//! Trusted local host resource adapter. All owners share the host's actual ledger.
use super::authorization_contract::{AuthenticatedPrincipalRef, PrincipalRegistration};
use super::host_protocol::HostMessage;
use super::owner_resource_contract::OwnerResourceRequest;
use super::protocol::OwnerProtocolError;
use super::resource_contract::{
    HostResourceBinding, Reservation, ReservationReceipt, ResourceLedger,
};
use std::sync::{Arc, Mutex, Weak};
use transport::session_resume::RequestId;

/// Retains host authority separately from the public principal reference.
#[derive(Clone)]
pub struct OwnerResourceClient {
    ledger: Arc<Mutex<ResourceLedger>>,
    registration: PrincipalRegistration,
}
/// A matching reservation acknowledgement, never evidence of resource cleanup.
#[derive(Debug)]
pub struct AdmittedReservation {
    reservation: Reservation,
    cleanup: RequestId,
    ledger: Weak<Mutex<ResourceLedger>>,
    registration: PrincipalRegistration,
}
impl AdmittedReservation {
    fn from_reserved(
        client: &OwnerResourceClient,
        reservation: Reservation,
        cleanup: RequestId,
        ack: HostMessage,
    ) -> Result<Self, OwnerProtocolError> {
        match ack {
            HostMessage::Reserved {
                reservation: r,
                cleanup: c,
            } if r == reservation && c == cleanup => Ok(Self {
                reservation,
                cleanup,
                ledger: Arc::downgrade(&client.ledger),
                registration: client.registration,
            }),
            _ => Err(OwnerProtocolError::Binding),
        }
    }
    pub(super) fn cleanup(&self) -> RequestId {
        self.cleanup
    }
    pub fn reservation(&self) -> Reservation {
        self.reservation
    }
}
impl OwnerResourceClient {
    /// Host setup supplies one shared ledger and its exact active registration.
    /// No limit, ledger incarnation or canonical account is invented here.
    pub fn new(ledger: Arc<Mutex<ResourceLedger>>, registration: PrincipalRegistration) -> Self {
        Self {
            ledger,
            registration,
        }
    }
    pub(super) fn same_host(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.ledger, &other.ledger)
    }
    pub(super) fn canonical_uid(&self) -> Result<u32, OwnerProtocolError> {
        self.ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?
            .canonical_uid(self.registration)
    }
    pub fn principal(&self) -> AuthenticatedPrincipalRef {
        self.registration.principal
    }
    pub fn reserve(
        &self,
        reservation: Reservation,
        cleanup: RequestId,
    ) -> Result<AdmittedReservation, OwnerProtocolError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?;
        if ledger.host_binding(self.registration)?.is_some() {
            return Err(OwnerProtocolError::Binding);
        }
        ledger.reserve(self.registration, reservation, cleanup)?;
        drop(ledger);
        // This local host adapter acknowledges only the actual ledger decision.
        AdmittedReservation::from_reserved(
            self,
            reservation,
            cleanup,
            HostMessage::Reserved {
                reservation,
                cleanup,
            },
        )
    }
    pub(super) fn reserve_host(
        &self,
        binding: HostResourceBinding,
        request: OwnerResourceRequest,
        cleanup: RequestId,
    ) -> Result<AdmittedReservation, OwnerProtocolError> {
        request.validate()?;
        if request.locator != binding.locator {
            return Err(OwnerProtocolError::Binding);
        }
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?;
        if ledger.host_binding(self.registration)? != Some(binding) {
            return Err(OwnerProtocolError::Binding);
        }
        let reservation = Reservation {
            id: ledger.next_reservation_id()?,
            principal: self.registration.principal,
            locator: request.locator,
            channel: request.channel,
            kind: request.kind,
            bytes: request.bytes,
            screen_charge: request.screen_charge,
        };
        ledger.reserve(self.registration, reservation, cleanup)?;
        drop(ledger);
        AdmittedReservation::from_reserved(
            self,
            reservation,
            cleanup,
            HostMessage::Reserved {
                reservation,
                cleanup,
            },
        )
    }
    pub(super) fn validate_admitted(
        &self,
        admitted: &AdmittedReservation,
        expected: Option<HostResourceBinding>,
    ) -> Result<(), OwnerProtocolError> {
        if admitted.registration != self.registration
            || !Weak::ptr_eq(&admitted.ledger, &Arc::downgrade(&self.ledger))
            || admitted.reservation.principal != self.registration.principal
        {
            return Err(OwnerProtocolError::Binding);
        }
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?;
        let actual = ledger.host_binding(self.registration)?;
        if expected.is_some() && expected != actual {
            return Err(OwnerProtocolError::Binding);
        }
        if actual.is_some_and(|binding| binding.locator != admitted.reservation.locator) {
            return Err(OwnerProtocolError::Binding);
        }
        Ok(())
    }
    // Only the exact sealed storage finalizer calls this.
    // Public release reports never reach this path for host-issued registrations.
    fn release_destroyed(
        &self,
        admitted: &AdmittedReservation,
        cleanup: RequestId,
    ) -> Result<(), OwnerProtocolError> {
        self.validate_admitted(admitted, None)?;
        let r = admitted.reservation;
        self.ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?
            .release(
                r,
                ReservationReceipt {
                    id: cleanup,
                    reservation: r.id,
                    locator: r.locator,
                    channel: r.channel,
                },
            )
    }
    pub(super) fn prepare_screen_commit(
        &self,
        base: &AdmittedReservation,
        pending: super::resource_contract::ScreenCharge,
        retained: super::resource_contract::ScreenCharge,
    ) -> Result<PreparedScreenAccounting, OwnerProtocolError> {
        if base.registration != self.registration
            || !Weak::ptr_eq(&base.ledger, &Arc::downgrade(&self.ledger))
        {
            return Err(OwnerProtocolError::Binding);
        }
        let (provisional, _, replacement, cleanup) = self
            .ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?
            .prepare_screen_commit(
                self.registration,
                base.reservation,
                base.cleanup,
                pending,
                retained,
            )?;
        Ok(PreparedScreenAccounting {
            client: self.clone(),
            base: base.reservation,
            provisional,
            replacement,
            cleanup,
            finished: false,
        })
    }
    /// Caller supplies independent exact cleanup evidence; dropping the admitted
    /// token alone deliberately cannot release live debt.
    pub fn release(
        &self,
        admitted: &AdmittedReservation,
        receipt: ReservationReceipt,
    ) -> Result<(), OwnerProtocolError> {
        if admitted.registration != self.registration
            || !Weak::ptr_eq(&admitted.ledger, &Arc::downgrade(&self.ledger))
            || receipt.id != admitted.cleanup
            || !receipt.matches(admitted.reservation)
        {
            return Err(OwnerProtocolError::Binding);
        }
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?;
        if ledger.host_binding(self.registration)?.is_some() {
            return Err(OwnerProtocolError::Binding);
        }
        ledger.release(admitted.reservation, receipt)
    }
}
/// Never exposed to a peer. Prepared metadata pins the exact live entries.
pub(super) struct PreparedScreenAccounting {
    client: OwnerResourceClient,
    base: Reservation,
    provisional: Reservation,
    replacement: Reservation,
    cleanup: RequestId,
    finished: bool,
}
impl PreparedScreenAccounting {
    pub(super) fn commit(mut self) -> AdmittedReservation {
        if let Ok(mut ledger) = self.client.ledger.lock() {
            ledger.finish_screen_commit(
                self.base,
                self.provisional,
                self.replacement,
                self.cleanup,
                true,
            );
        }
        self.finished = true;
        AdmittedReservation {
            reservation: self.replacement,
            cleanup: self.cleanup,
            ledger: Arc::downgrade(&self.client.ledger),
            registration: self.client.registration,
        }
    }
}
impl Drop for PreparedScreenAccounting {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut ledger) = self.client.ledger.lock() {
                ledger.finish_screen_commit(
                    self.base,
                    self.provisional,
                    self.replacement,
                    self.cleanup,
                    false,
                );
            }
        }
    }
}
/// Internal allocation lifetime, separately authorized after its custody ends.
/// Field owners drop their backing before this final charge reference.
pub(super) struct StorageCharge {
    client: OwnerResourceClient,
    admitted: AdmittedReservation,
    cleanup: RequestId,
    releasable: std::sync::atomic::AtomicBool,
}
impl StorageCharge {
    pub(super) fn new(
        client: OwnerResourceClient,
        admitted: AdmittedReservation,
        cleanup: RequestId,
    ) -> Arc<Self> {
        Arc::new(Self::owned(client, admitted, cleanup))
    }
    pub(super) fn owned(
        client: OwnerResourceClient,
        admitted: AdmittedReservation,
        cleanup: RequestId,
    ) -> Self {
        Self {
            client,
            admitted,
            cleanup,
            releasable: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn admitted(&self) -> &AdmittedReservation {
        &self.admitted
    }
    /// Only an exact prepared Screen consolidation supplies the replacement.
    pub(super) fn replace_admitted(&mut self, admitted: AdmittedReservation) {
        self.cleanup = admitted.cleanup;
        self.admitted = admitted;
    }
    pub(super) fn bytes(&self) -> u64 {
        self.admitted.reservation.bytes
    }
    /// This authorizes eventual backing destruction, not an immediate refund.
    pub(super) fn allow_release(&self) {
        self.releasable
            .store(true, std::sync::atomic::Ordering::Release);
    }
}
impl Drop for StorageCharge {
    fn drop(&mut self) {
        if self.releasable.load(std::sync::atomic::Ordering::Acquire) {
            let _ = self.client.release_destroyed(&self.admitted, self.cleanup);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mismatched_host_ack_does_not_admit() {
        use super::super::resource_contract::*;
        use transport::{channel_geometry::ChannelInstance, session_resume::*};
        let reservation = Reservation {
            id: ReservationId::new(1).unwrap(),
            principal: AuthenticatedPrincipalRef::new([1; 16]).unwrap(),
            locator: SessionLocator {
                session: RetainedSessionId::new([1; 16]).unwrap(),
                owner: OwnerInstance::new([1; 16]).unwrap(),
            },
            channel: ChannelInstance::new(1).unwrap(),
            kind: ReservationKind::ControlQueue,
            bytes: 1,
            screen_charge: None,
        };
        let cleanup = RequestId::new(1).unwrap();
        let byte = ByteLimits {
            channel_bytes: 1,
            session_bytes: 1,
            account_bytes: 1,
            global_bytes: 1,
        };
        let limits = ResourceLimits {
            max_reservations: 1,
            screen: ScreenLimits {
                global_cells: 0,
                account_cells: 0,
                global_rows: 0,
                account_rows: 0,
                global_models: 0,
                account_models: 0,
            },
            snapshot_transfer: byte,
            control_queue: byte,
        };
        let mut ledger = ResourceLedger::new(
            super::super::authorization_contract::LedgerInstance::new([9; 16]).unwrap(),
            limits,
        )
        .unwrap();
        let registration = ledger
            .register_fresh_principal(reservation.principal, 1000)
            .unwrap();
        let client = OwnerResourceClient::new(Arc::new(Mutex::new(ledger)), registration);
        assert!(AdmittedReservation::from_reserved(
            &client,
            reservation,
            cleanup,
            HostMessage::Reserved {
                reservation,
                cleanup: RequestId::new(2).unwrap()
            }
        )
        .is_err());
    }
}
