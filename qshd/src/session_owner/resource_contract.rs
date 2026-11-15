//! One host-owned pure accounting ledger. Caller-provided trusted account
//! bindings and limits are not credentials and never arrive from a frontend UID.
use super::authorization_contract::{
    AuthenticatedPrincipalRef, LedgerInstance, PrincipalRegistration,
};
use super::protocol::OwnerProtocolError as Error;
use super::wire::{put_locator, Reader};
use std::num::NonZeroU64;
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationId(NonZeroU64);
impl ReservationId {
    pub fn new(v: u64) -> Option<Self> {
        NonZeroU64::new(v).map(Self)
    }
    pub fn get(self) -> u64 {
        self.0.get()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReservationKind {
    ScreenModel = 1,
    OutputHistory = 2,
    SnapshotTransfer = 3,
    ControlQueue = 4,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenCharge {
    pub cells: u64,
    pub rows: u64,
    pub models: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation {
    pub id: ReservationId,
    pub principal: AuthenticatedPrincipalRef,
    pub locator: SessionLocator,
    pub channel: ChannelInstance,
    pub kind: ReservationKind,
    pub bytes: u64,
    pub screen_charge: Option<ScreenCharge>,
}
impl Reservation {
    pub fn validate(self) -> Result<(), Error> {
        match (self.kind, self.screen_charge) {
            (ReservationKind::ScreenModel, Some(s))
                if self.bytes == 0 && s.cells > 0 && s.rows > 0 && s.models <= 1 => {}
            (ReservationKind::ScreenModel, _) => return Err(Error::Malformed),
            (_, None) if self.bytes > 0 => {}
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
    pub(super) fn len(self) -> usize {
        74 + self.screen_charge.map_or(0, |_| 24)
    }
    pub(super) fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.get().to_be_bytes());
        out.extend_from_slice(self.principal.as_bytes());
        put_locator(out, self.locator);
        out.extend_from_slice(&self.channel.get().to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&self.bytes.to_be_bytes());
        if let Some(s) = self.screen_charge {
            out.push(1);
            out.extend_from_slice(&s.cells.to_be_bytes());
            out.extend_from_slice(&s.rows.to_be_bytes());
            out.extend_from_slice(&s.models.to_be_bytes());
        } else {
            out.push(0);
        }
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let id = ReservationId::new(r.u64()?).ok_or(Error::Malformed)?;
        let principal = r.principal()?;
        let locator = r.locator()?;
        let channel = ChannelInstance::new(r.u64()?).ok_or(Error::Malformed)?;
        let kind = match r.byte()? {
            1 => ReservationKind::ScreenModel,
            2 => ReservationKind::OutputHistory,
            3 => ReservationKind::SnapshotTransfer,
            4 => ReservationKind::ControlQueue,
            _ => return Err(Error::Malformed),
        };
        let bytes = r.u64()?;
        let screen_charge = match r.byte()? {
            0 => None,
            1 => Some(ScreenCharge {
                cells: r.u64()?,
                rows: r.u64()?,
                models: r.u64()?,
            }),
            _ => return Err(Error::Malformed),
        };
        let v = Self {
            id,
            principal,
            locator,
            channel,
            kind,
            bytes,
            screen_charge,
        };
        v.validate()?;
        Ok(v)
    }
}
/// A later runtime producer issues this only after exact resource cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationReceipt {
    pub id: RequestId,
    pub reservation: ReservationId,
    pub locator: SessionLocator,
    pub channel: ChannelInstance,
}
impl ReservationReceipt {
    pub(super) fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.get().to_be_bytes());
        out.extend_from_slice(&self.reservation.get().to_be_bytes());
        put_locator(out, self.locator);
        out.extend_from_slice(&self.channel.get().to_be_bytes());
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            id: RequestId::new(r.u64()?).ok_or(Error::Malformed)?,
            reservation: ReservationId::new(r.u64()?).ok_or(Error::Malformed)?,
            locator: r.locator()?,
            channel: ChannelInstance::new(r.u64()?).ok_or(Error::Malformed)?,
        })
    }
    pub fn matches(self, r: Reservation) -> bool {
        self.reservation == r.id && self.locator == r.locator && self.channel == r.channel
    }
}
#[derive(Debug, Clone, Copy)]
pub struct ByteLimits {
    pub channel_bytes: u64,
    pub session_bytes: u64,
    pub account_bytes: u64,
    pub global_bytes: u64,
}
#[derive(Debug, Clone, Copy)]
pub struct ScreenLimits {
    pub global_cells: u64,
    pub account_cells: u64,
    pub global_rows: u64,
    pub account_rows: u64,
    pub global_models: u64,
    pub account_models: u64,
}
impl ScreenLimits {
    /// Checked adapter of the existing shared host budget; never a per-owner default.
    pub fn from_existing(limits: crate::screen_budget::BudgetLimits) -> Result<Self, Error> {
        Ok(Self {
            global_cells: u64::try_from(limits.global_cells).map_err(|_| Error::TooLarge)?,
            account_cells: u64::try_from(limits.owner_cells).map_err(|_| Error::TooLarge)?,
            global_rows: u64::try_from(limits.global_rows).map_err(|_| Error::TooLarge)?,
            account_rows: u64::try_from(limits.owner_rows).map_err(|_| Error::TooLarge)?,
            global_models: u64::try_from(limits.global_models).map_err(|_| Error::TooLarge)?,
            account_models: u64::try_from(limits.owner_models).map_err(|_| Error::TooLarge)?,
        })
    }
}
impl ScreenCharge {
    pub fn checked_slots(self) -> Result<(usize, usize, usize), Error> {
        Ok((
            usize::try_from(self.cells).map_err(|_| Error::TooLarge)?,
            usize::try_from(self.rows).map_err(|_| Error::TooLarge)?,
            usize::try_from(self.models).map_err(|_| Error::TooLarge)?,
        ))
    }
}
#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    pub max_reservations: usize,
    pub screen: ScreenLimits,
    pub snapshot_transfer: ByteLimits,
    pub control_queue: ByteLimits,
}
#[derive(Debug, Clone, Copy)]
struct Entry {
    reservation: Reservation,
    account: u32,
    cleanup: RequestId,
    pinned: Option<ReservationId>,
}
/// Private registration policy; never reconstructed from a request or receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HostResourceBinding {
    pub host: HostInstance,
    pub locator: SessionLocator,
}
#[derive(Debug)]
pub struct ResourceLedger {
    limits: ResourceLimits,
    scope: LedgerInstance,
    principals: Vec<(PrincipalRegistration, u32, Option<HostResourceBinding>)>,
    last_registration: u64,
    entries: Vec<Entry>,
    last_id: u64,
}
impl ResourceLedger {
    pub fn new(scope: LedgerInstance, limits: ResourceLimits) -> Result<Self, Error> {
        if limits.max_reservations == 0
            || limits
                .max_reservations
                .checked_mul(std::mem::size_of::<Entry>())
                .is_none_or(|v| v > isize::MAX as usize)
        {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            limits,
            scope,
            last_registration: 0,
            principals: Vec::new(),
            entries: Vec::new(),
            last_id: 0,
        })
    }
    /// Host-only trusted canonical account binding. Rebinding cannot reset charges.
    /// Trusted host-only fresh authentication lifetime and pinned canonical UID.
    /// The fresh ledger scope and serial make stale/reconstructed handles inert.
    pub fn register_fresh_principal(
        &mut self,
        p: AuthenticatedPrincipalRef,
        canonical_uid: u32,
    ) -> Result<PrincipalRegistration, Error> {
        if self.principals.iter().any(|(old, _, _)| old.principal == p) {
            return Err(Error::Binding);
        }
        if self.principals.len() >= self.limits.max_reservations {
            return Err(Error::RequestLimit);
        }
        let serial = self
            .last_registration
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let handle = PrincipalRegistration {
            ledger: self.scope,
            serial,
            principal: p,
        };
        self.principals.push((handle, canonical_uid, None));
        self.last_registration = serial;
        Ok(handle)
    }
    pub(super) fn register_host_principal(
        &mut self,
        principal: AuthenticatedPrincipalRef,
        uid: u32,
        binding: HostResourceBinding,
    ) -> Result<PrincipalRegistration, Error> {
        let registration = self.register_fresh_principal(principal, uid)?;
        self.principals.last_mut().expect("just registered").2 = Some(binding);
        Ok(registration)
    }
    pub(super) fn host_binding(
        &self,
        registration: PrincipalRegistration,
    ) -> Result<Option<HostResourceBinding>, Error> {
        self.canonical_uid(registration)?;
        self.principals
            .iter()
            .find(|(p, _, _)| *p == registration)
            .map(|(_, _, binding)| *binding)
            .ok_or(Error::Binding)
    }
    /// Retirement is refused until the principal's exact final resource receipt.
    /// It does not reset IDs, rebind a live UID, or alter another owner's charge.
    pub fn retire_principal(&mut self, p: PrincipalRegistration) -> Result<(), Error> {
        let i = self
            .principals
            .iter()
            .position(|(old, _, _)| *old == p && p.ledger == self.scope)
            .ok_or(Error::Binding)?;
        if self
            .entries
            .iter()
            .any(|e| e.reservation.principal == p.principal)
        {
            return Err(Error::InvalidState);
        }
        self.principals.swap_remove(i);
        Ok(())
    }
    /// Read-only proposal; reserve still atomically checks this global high-water.
    pub fn next_reservation_id(&self) -> Result<ReservationId, Error> {
        ReservationId::new(self.last_id.checked_add(1).ok_or(Error::Exhausted)?)
            .ok_or(Error::Exhausted)
    }
    pub(super) fn canonical_uid(&self, registration: PrincipalRegistration) -> Result<u32, Error> {
        if registration.ledger != self.scope {
            return Err(Error::Binding);
        }
        self.principals
            .iter()
            .find(|(p, _, _)| *p == registration)
            .map(|(_, uid, _)| *uid)
            .ok_or(Error::Binding)
    }
    pub fn principals(&self) -> usize {
        self.principals.len()
    }
    pub fn reservations(&self) -> usize {
        self.entries.len()
    }
    pub fn reserve(
        &mut self,
        principal: PrincipalRegistration,
        r: Reservation,
        cleanup: RequestId,
    ) -> Result<(), Error> {
        r.validate()?;
        if principal.ledger != self.scope || principal.principal != r.principal {
            return Err(Error::Binding);
        }
        let account = self
            .principals
            .iter()
            .find(|(p, _, _)| *p == principal)
            .map(|(_, a, _)| *a)
            .ok_or(Error::Binding)?;
        if r.id.get() <= self.last_id {
            return Err(Error::ReusedRequest);
        }
        if self.entries.len() >= self.limits.max_reservations {
            return Err(Error::RequestLimit);
        }
        // An owner lifetime is permanently bound to its session/account while live.
        if self.entries.iter().any(|e| {
            (e.reservation.locator.owner == r.locator.owner
                || e.reservation.locator.session == r.locator.session)
                && (e.account != account || e.reservation.locator != r.locator)
        }) {
            return Err(Error::Binding);
        }
        if let Some(charge) = r.screen_charge {
            charge.checked_slots()?;
            let mut global = charge;
            let mut owned = charge;
            let mut channel_models = charge.models;
            for e in &self.entries {
                if let Some(s) = e.reservation.screen_charge {
                    global = add_screen(global, s)?;
                    if e.account == account {
                        owned = add_screen(owned, s)?;
                    }
                    if e.reservation.locator == r.locator && e.reservation.channel == r.channel {
                        channel_models = channel_models
                            .checked_add(s.models)
                            .ok_or(Error::TooLarge)?;
                    }
                }
            }
            let l = self.limits.screen;
            if global.cells > l.global_cells
                || global.rows > l.global_rows
                || global.models > l.global_models
                || owned.cells > l.account_cells
                || owned.rows > l.account_rows
                || owned.models > l.account_models
                || channel_models > 1
            {
                return Err(Error::TooLarge);
            }
        } else {
            let caps = match r.kind {
                ReservationKind::OutputHistory => ByteLimits {
                    channel_bytes: 1 << 20,
                    session_bytes: 8 << 20,
                    account_bytes: 32 << 20,
                    global_bytes: 128 << 20,
                },
                ReservationKind::SnapshotTransfer => self.limits.snapshot_transfer,
                ReservationKind::ControlQueue => self.limits.control_queue,
                ReservationKind::ScreenModel => return Err(Error::Malformed),
            };
            let mut sums = [r.bytes; 4];
            for e in &self.entries {
                if e.reservation.kind != r.kind {
                    continue;
                }
                let scopes = [
                    e.reservation.locator == r.locator && e.reservation.channel == r.channel,
                    e.reservation.locator == r.locator,
                    e.account == account,
                    true,
                ];
                for (i, same) in scopes.iter().enumerate() {
                    if *same {
                        sums[i] = sums[i]
                            .checked_add(e.reservation.bytes)
                            .ok_or(Error::TooLarge)?;
                    }
                }
            }
            if sums[0] > caps.channel_bytes
                || sums[1] > caps.session_bytes
                || sums[2] > caps.account_bytes
                || sums[3] > caps.global_bytes
            {
                return Err(Error::TooLarge);
            }
        }
        self.entries.push(Entry {
            reservation: r,
            account,
            cleanup,
            pinned: None,
        });
        self.last_id = r.id.get();
        Ok(())
    }
    /// Trusted local screen operation: all admission/metadata precede native effects.
    pub(super) fn prepare_screen_commit(
        &mut self,
        principal: PrincipalRegistration,
        base: Reservation,
        base_cleanup: RequestId,
        pending: ScreenCharge,
        retained: ScreenCharge,
    ) -> Result<(Reservation, RequestId, Reservation, RequestId), Error> {
        let index = self
            .entries
            .iter()
            .position(|e| e.reservation == base && e.cleanup == base_cleanup && e.pinned.is_none())
            .ok_or(Error::Binding)?;
        let old = base.screen_charge.ok_or(Error::Binding)?;
        if base.kind != ReservationKind::ScreenModel
            || old.models != 1
            || pending.models != 0
            || retained.models != 1
            || retained.cells < old.cells
            || retained.rows < old.rows
            || retained.cells
                > old
                    .cells
                    .checked_add(pending.cells)
                    .ok_or(Error::TooLarge)?
            || retained.rows > old.rows.checked_add(pending.rows).ok_or(Error::TooLarge)?
        {
            return Err(Error::Binding);
        }
        // Burn both identities before admission; cancellation never resets high-water.
        let provisional_id = self.last_id.checked_add(1).ok_or(Error::Exhausted)?;
        let fresh_id = provisional_id.checked_add(1).ok_or(Error::Exhausted)?;
        let provisional = Reservation {
            id: ReservationId::new(provisional_id).unwrap(),
            screen_charge: Some(pending),
            ..base
        };
        let replacement = Reservation {
            id: ReservationId::new(fresh_id).unwrap(),
            screen_charge: Some(retained),
            ..base
        };
        replacement.validate()?;
        let cleanup = RequestId::new(provisional_id).unwrap();
        self.reserve(principal, provisional, cleanup)?;
        self.last_id = fresh_id;
        self.entries[index].pinned = Some(replacement.id);
        self.entries.last_mut().unwrap().pinned = Some(replacement.id);
        Ok((
            provisional,
            cleanup,
            replacement,
            RequestId::new(fresh_id).unwrap(),
        ))
    }
    /// The private prepared token pins both exact entries against ordinary release.
    /// No allocation, admission, callback or fallible operation follows the effect.
    pub(super) fn finish_screen_commit(
        &mut self,
        base: Reservation,
        provisional: Reservation,
        replacement: Reservation,
        cleanup: RequestId,
        commit: bool,
    ) {
        let i = self
            .entries
            .iter()
            .position(|e| e.reservation == provisional && e.pinned == Some(replacement.id))
            .expect("private pinned provisional");
        self.entries.swap_remove(i);
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.reservation == base && e.pinned == Some(replacement.id))
            .expect("private pinned base");
        if commit {
            e.reservation = replacement;
            e.cleanup = cleanup;
        }
        e.pinned = None;
    }
    pub fn release(&mut self, r: Reservation, receipt: ReservationReceipt) -> Result<(), Error> {
        let i = self
            .entries
            .iter()
            .position(|e| {
                e.reservation == r
                    && e.cleanup == receipt.id
                    && receipt.matches(r)
                    && e.pinned.is_none()
            })
            .ok_or(Error::Binding)?;
        self.entries.swap_remove(i);
        Ok(())
    }
}
fn add_screen(a: ScreenCharge, b: ScreenCharge) -> Result<ScreenCharge, Error> {
    Ok(ScreenCharge {
        cells: a.cells.checked_add(b.cells).ok_or(Error::TooLarge)?,
        rows: a.rows.checked_add(b.rows).ok_or(Error::TooLarge)?,
        models: a.models.checked_add(b.models).ok_or(Error::TooLarge)?,
    })
}
