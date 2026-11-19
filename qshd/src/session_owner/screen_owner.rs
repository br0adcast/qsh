//! Actual retained screen model authority; no peer can mint cleanup or resize credit.
use super::protocol::OwnerProtocolError;
use super::resource_contract::{Reservation, ReservationKind, ScreenCharge};
use super::resources::{
    AdmittedReservation, OwnerResourceClient, PreparedScreenAccounting, StorageCharge,
};
use crate::screen_budget::{BackingSlots, ScreenEnvelope};
use terminal_size::TerminalSize;

fn charge(slots: BackingSlots, models: u64) -> Result<ScreenCharge, String> {
    Ok(ScreenCharge {
        cells: u64::try_from(slots.cells).map_err(|_| "screen cells overflow")?,
        rows: u64::try_from(slots.rows).map_err(|_| "screen rows overflow")?,
        models,
    })
}
pub struct HostScreenLease {
    client: OwnerResourceClient,
    storage: Box<StorageCharge>,
    envelope: ScreenEnvelope,
    current: TerminalSize,
}
impl HostScreenLease {
    /// Admit the actual supplied host authority before constructing TerminalCore.
    pub fn admit(
        client: OwnerResourceClient,
        reservation: Reservation,
        cleanup: transport::session_resume::RequestId,
        size: TerminalSize,
    ) -> Result<Self, OwnerProtocolError> {
        let envelope = ScreenEnvelope::new(size);
        let slots = envelope
            .charge()
            .map_err(|_| OwnerProtocolError::TooLarge)?;
        let required = charge(slots, 1).map_err(|_| OwnerProtocolError::TooLarge)?;
        if reservation.kind != ReservationKind::ScreenModel
            || reservation.screen_charge != Some(required)
        {
            return Err(OwnerProtocolError::Binding);
        }
        let admitted = client.reserve(reservation, cleanup)?;
        let storage = Box::new(StorageCharge::owned(client.clone(), admitted, cleanup));
        Ok(Self {
            client,
            storage,
            envelope,
            current: size,
        })
    }
    /// Consumes an already charged exact host token before model allocation.
    /// Validation refusal returns untouched custody, never a release receipt.
    #[allow(dead_code)] // Dormant host-issued provisioning; no runtime caller is activated.
    pub(crate) fn admit_reserved(
        client: OwnerResourceClient,
        admitted: AdmittedReservation,
        size: TerminalSize,
    ) -> Result<Self, Box<(OwnerProtocolError, AdmittedReservation)>> {
        let envelope = ScreenEnvelope::new(size);
        let validated = (|| {
            client.validate_admitted(&admitted, None)?;
            let required = charge(
                envelope
                    .charge()
                    .map_err(|_| OwnerProtocolError::TooLarge)?,
                1,
            )
            .map_err(|_| OwnerProtocolError::TooLarge)?;
            let reservation = admitted.reservation();
            if reservation.kind != ReservationKind::ScreenModel
                || reservation.bytes != 0
                || reservation.screen_charge != Some(required)
            {
                return Err(OwnerProtocolError::Binding);
            }
            Ok(())
        })();
        if let Err(error) = validated {
            return Err(Box::new((error, admitted)));
        }
        let cleanup = admitted.cleanup();
        let storage = Box::new(StorageCharge::owned(client.clone(), admitted, cleanup));
        Ok(Self {
            client,
            storage,
            envelope,
            current: size,
        })
    }
    pub(super) fn matches(
        &self,
        client: &OwnerResourceClient,
        locator: transport::session_resume::SessionLocator,
        channel: transport::channel_geometry::ChannelInstance,
        size: TerminalSize,
    ) -> bool {
        self.client.same_host(client)
            && self.client.principal() == client.principal()
            && self.storage.admitted().reservation().locator == locator
            && self.storage.admitted().reservation().channel == channel
            && self.current == size
    }
    pub(crate) fn size(&self) -> TerminalSize {
        self.current
    }
    pub(crate) fn envelope(&self) -> ScreenEnvelope {
        self.envelope
    }
    pub fn prepare(&mut self, size: TerminalSize) -> Result<HostResizeReservation<'_>, String> {
        let (envelope, scratch) = self.envelope.prepare_charge(self.current, size)?;
        let retained = envelope.charge()?;
        let pending = retained.delta(self.envelope.charge()?).plus(scratch)?;
        let accounting = if pending == BackingSlots::default() {
            None
        } else {
            // Source-qualified formulas produce both nonzero dimensions together.
            if pending.cells == 0 || pending.rows == 0 {
                return Err("one-dimensional screen charge".into());
            }
            Some(
                self.client
                    .prepare_screen_commit(
                        self.storage.admitted(),
                        charge(pending, 0)?,
                        charge(retained, 1)?,
                    )
                    .map_err(|_| "host screen resize refused")?,
            )
        };
        Ok(HostResizeReservation {
            lease: self,
            envelope,
            size,
            accounting,
            effect_started: false,
        })
    }
}
impl Drop for HostScreenLease {
    fn drop(&mut self) {
        // PtyScreen declares its terminal before this sole lease.
        self.storage.allow_release();
    }
}
pub struct HostResizeReservation<'a> {
    lease: &'a mut HostScreenLease,
    envelope: ScreenEnvelope,
    size: TerminalSize,
    accounting: Option<PreparedScreenAccounting>,
    effect_started: bool,
}
impl HostResizeReservation<'_> {
    pub(crate) fn begin_effect(&mut self) {
        self.effect_started = true;
    }
    pub fn commit(mut self) {
        if let Some(accounting) = self.accounting.take() {
            self.lease.storage.replace_admitted(accounting.commit());
        }
        self.lease.envelope = self.envelope;
        self.lease.current = self.size;
    }
}

impl Drop for HostResizeReservation<'_> {
    fn drop(&mut self) {
        if self.effect_started {
            // An unexpected model panic is not scratch-disposal proof. The
            // exact pinned debt remains unresolved instead of being refunded.
            if let Some(accounting) = self.accounting.take() {
                std::mem::forget(accounting);
            }
        }
    }
}

use std::sync::{Arc, Mutex};
use transport::{
    auth::Principal,
    channel::OpenRequest,
    channel_open::{OpenCustody, OpenJob},
    session_manager::LoginId,
    shell_server::SessionScreen,
};
struct RegisteredModel {
    custody: OpenCustody,
    owner: Principal,
    login: LoginId,
    request: OpenRequest,
    model: Box<dyn SessionScreen>,
}
/// Explicit personal-owner provider. Entries exist only for admitted OPEN jobs.
pub struct RetainedScreenFactory {
    models: Mutex<Vec<RegisteredModel>>,
}
pub struct ScreenRegistration {
    factory: Arc<RetainedScreenFactory>,
    custody: OpenCustody,
}
impl Default for RetainedScreenFactory {
    fn default() -> Self {
        Self::new()
    }
}
impl RetainedScreenFactory {
    pub fn new() -> Self {
        Self {
            models: Mutex::new(Vec::new()),
        }
    }
    pub(super) fn backing_bound() -> usize {
        2 * transport::channel::MAX_CHANNELS * std::mem::size_of::<RegisteredModel>()
    }
    fn trim(models: &mut Vec<RegisteredModel>) -> Vec<RegisteredModel> {
        let mut retained = Vec::with_capacity(models.len());
        retained.append(models);
        std::mem::replace(models, retained)
    }
    pub fn register(
        self: &Arc<Self>,
        job: &OpenJob,
        lease: HostScreenLease,
    ) -> Result<ScreenRegistration, String> {
        let r = job.request();
        if job.custody().is_cancelled()
            || !r.request.screen
            || lease
                .client
                .canonical_uid()
                .map_err(|_| "retained screen principal unavailable")?
                != r.owner.uid
            || lease.storage.admitted().reservation().channel != r.identity.instance
            || (lease.size().cols(), lease.size().rows()) != (r.request.cols, r.request.rows)
        {
            return Err("retained screen OPEN binding".into());
        }
        // Construction and host cleanup happen outside provider/custody locks.
        let entry = RegisteredModel {
            custody: job.custody().clone(),
            owner: r.owner.clone(),
            login: r.login,
            request: r.request.clone(),
            model: Box::new(crate::screen::PtyScreen::with_host_lease(lease)),
        };
        let mut models = self
            .models
            .lock()
            .map_err(|_| "retained model provider unavailable")?;
        if models.len() == transport::channel::MAX_CHANNELS
            || models.iter().any(|m| m.custody.same_capsule(job.custody()))
        {
            drop(models);
            drop(entry);
            return Err("retained model provider full or reused".into());
        }
        if models.try_reserve_exact(1).is_err()
            || models.capacity() > transport::channel::MAX_CHANNELS
        {
            drop(models);
            drop(entry);
            return Err("retained model metadata unavailable".into());
        }
        models.push(entry);
        Ok(ScreenRegistration {
            factory: self.clone(),
            custody: job.custody().clone(),
        })
    }
    pub fn take(
        &self,
        owner: &Principal,
        login: LoginId,
        request: &OpenRequest,
        custody: &OpenCustody,
    ) -> Result<Box<dyn SessionScreen>, String> {
        let mut models = self
            .models
            .lock()
            .map_err(|_| "retained model provider unavailable")?;
        let index = models
            .iter()
            .position(|m| {
                m.custody.same_capsule(custody)
                    && m.owner == *owner
                    && m.login == login
                    && m.request == *request
            })
            .ok_or("no exact preadmitted retained model")?;
        let entry = models.swap_remove(index);
        let retired = Self::trim(&mut models);
        drop(models);
        drop(retired);
        if custody.is_cancelled() {
            drop(entry);
            return Err("retained screen OPEN cancelled".into());
        }
        Ok(entry.model)
    }
}
impl Drop for ScreenRegistration {
    fn drop(&mut self) {
        let mut models = self
            .factory
            .models
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = models
            .iter()
            .position(|m| m.custody.same_capsule(&self.custody))
            .map(|i| models.swap_remove(i));
        let retired = entry
            .as_ref()
            .map(|_| RetainedScreenFactory::trim(&mut models));
        drop(models);
        drop(retired);
        drop(entry);
    }
}

#[cfg(test)]
#[path = "screen_owner_tests.rs"]
mod tests;
