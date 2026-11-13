//! Trusted local host resource adapter. All owners share the host's actual ledger.
use super::authorization_contract::{AuthenticatedPrincipalRef, PrincipalRegistration};
use super::host_protocol::HostMessage;
use super::protocol::OwnerProtocolError;
use super::resource_contract::{Reservation, ReservationReceipt, ResourceLedger};
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
        self.ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?
            .reserve(self.registration, reservation, cleanup)?;
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
        self.ledger
            .lock()
            .map_err(|_| OwnerProtocolError::InvalidState)?
            .release(admitted.reservation, receipt)
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
        self.client
            .ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish_screen_commit(
                self.base,
                self.provisional,
                self.replacement,
                self.cleanup,
                true,
            );
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
            self.client
                .ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .finish_screen_commit(
                    self.base,
                    self.provisional,
                    self.replacement,
                    self.cleanup,
                    false,
                );
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
        Arc::new(Self {
            client,
            admitted,
            cleanup,
            releasable: std::sync::atomic::AtomicBool::new(false),
        })
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
            let r = self.admitted.reservation;
            let _ = self.client.release(
                &self.admitted,
                ReservationReceipt {
                    id: self.cleanup,
                    reservation: r.id,
                    locator: r.locator,
                    channel: r.channel,
                },
            );
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
