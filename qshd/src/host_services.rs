//! Daemon-wide limits for session owner processes (#529 M1): the host side.
//!
//! A daemon that runs each session in an owner process of its own
//! ([`crate::owner_process`]) would multiply every limit that one process
//! enforced for all of its sessions -- each owner a full daemon's worth.
//! Instead the host keeps each such limit once, here, and every owner
//! charges it:
//!
//! - **Control budget envelopes** (transport's `GlobalBudget`): at most
//!   `MAX_SESSIONS_TOTAL` envelope leases, at most `MAX_SESSIONS_PER_OWNER`
//!   of them per uid. The host takes one ([`HostServices::admit`]) before it
//!   starts an owner. It counts against the caps until the session has
//!   ended ([`OwnerAccount::end_session`]: the owner's `End`, the router's
//!   end of the login, or the host's own stop of the owner), as a router
//!   stops counting a session the moment it ends it, though its backend
//!   still drains; and if the session never says so, until the host has
//!   reaped the owner. The owner runs its session under a budget of
//!   exactly one envelope (`OwnerLink::run_and_drain`), until it exits. A
//!   draining owner is thus outside the count but within its own envelope,
//!   and it drains within a bound: the host kills one still there after
//!   its stop escalation, and starts no owner while
//!   `owner_process::MAX_OWNERS` are unreaped. Without a free lease no owner starts:
//!   the session ends at once, as a stopped backend.
//! - **The screen budget** ([`crate::screen_budget`]): one pool for every
//!   owner. An owner's `ScreenBudget` charges it by request and reply
//!   (`acquire`) and refunds it by notice (`release`).
//! - **The open limits** (`OpenLimits`: opens in flight, globally and per
//!   uid): one count for every owner. Each owner's registry asks before it
//!   admits an open (`acquire`), charges a retirement unconditionally
//!   (`charge`), and gives back what is over (`release`).
//!
//! An owner speaks for its one principal only: a request for another uid is
//! refused. Whatever an owner still holds when the host reaps it -- after a
//! crash or a kill as much as after a clean end -- the host frees then
//! ([`OwnerAccount`]'s drop), so nothing an owner did can keep a charge
//! alive past its process.
//!
//! An owner that does not hear back within [`HOST_SERVICE_TIMEOUT`] takes
//! it as a refusal (fail-closed, as exhaustion is), and gives back a grant
//! that arrives after that.
//!
//! This module knows nothing of how requests travel: the host channel
//! carries them ([`crate::owner_process::wire`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use transport::channel_open::OpenLimits;
use transport::session_manager::{MAX_SESSIONS_PER_OWNER, MAX_SESSIONS_TOTAL};

use crate::screen_budget::{BackingSlots, BudgetLimits, ScreenBudget};

/// How long an owner waits for the host's answer to a limit request before
/// it takes the request as refused.
pub(crate) const HOST_SERVICE_TIMEOUT: Duration = Duration::from_secs(2);

/// What the host admits across all of its owners.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HostLimits {
    pub(crate) screen: BudgetLimits,
    pub(crate) opens: OpenLimits,
    /// Control budget envelopes in all, and per uid.
    pub(crate) envelopes: usize,
    pub(crate) envelopes_per_uid: usize,
}

impl Default for HostLimits {
    /// Exactly what one daemon process enforces for its sessions.
    fn default() -> Self {
        HostLimits {
            screen: BudgetLimits::default(),
            opens: OpenLimits::default(),
            envelopes: MAX_SESSIONS_TOTAL,
            envelopes_per_uid: MAX_SESSIONS_PER_OWNER,
        }
    }
}

/// A count in all and per uid.
#[derive(Default)]
struct Count {
    total: usize,
    uids: HashMap<u32, usize>,
}

impl Count {
    fn of(&self, uid: u32) -> usize {
        self.uids.get(&uid).copied().unwrap_or(0)
    }
    /// One more for `uid`, if neither bound is reached; any if `force`.
    fn take(&mut self, uid: u32, total: usize, per_uid: usize, force: bool) -> bool {
        if !force && (self.total >= total || self.of(uid) >= per_uid) {
            return false;
        }
        self.total += 1;
        *self.uids.entry(uid).or_default() += 1;
        true
    }
    /// Give back `n` of `uid`'s.
    fn give(&mut self, uid: u32, n: usize) {
        if n == 0 {
            return;
        }
        self.total -= n;
        let left = self.uids.get_mut(&uid).expect("a held count");
        *left -= n;
        if *left == 0 {
            self.uids.remove(&uid);
        }
    }
}

#[derive(Default)]
struct Counts {
    envelopes: Count,
    opens: Count,
}

/// The host's daemon-wide limits, shared by every owner it starts.
pub(crate) struct HostServices {
    limits: HostLimits,
    screen: ScreenBudget,
    counts: Mutex<Counts>,
}

impl HostServices {
    pub(crate) fn new(limits: HostLimits) -> Arc<HostServices> {
        Arc::new(HostServices {
            limits,
            screen: ScreenBudget::new(limits.screen),
            counts: Mutex::default(),
        })
    }

    fn counts(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One control budget envelope for a new owner of `uid`'s session: its
    /// account of everything it charges here, until it is dropped (when
    /// the host has reaped the owner). `Err` when every envelope, or every
    /// one `uid` may have, is taken.
    pub(crate) fn admit(self: &Arc<Self>, uid: u32) -> Result<OwnerAccount, String> {
        let l = self.limits;
        if !self
            .counts()
            .envelopes
            .take(uid, l.envelopes, l.envelopes_per_uid, false)
        {
            return Err(format!(
                "every session envelope is taken ({} in all, {} per account)",
                l.envelopes, l.envelopes_per_uid
            ));
        }
        Ok(OwnerAccount {
            services: self.clone(),
            uid,
            held: Mutex::default(),
            envelope: AtomicBool::new(true),
        })
    }

    /// Whether a new session of `uid` would get an envelope now; if not,
    /// which cap is reached.
    pub(crate) fn room(&self, uid: u32) -> Result<(), Cap> {
        let l = self.limits;
        let counts = self.counts();
        if counts.envelopes.of(uid) >= l.envelopes_per_uid {
            Err(Cap::Account)
        } else if counts.envelopes.total >= l.envelopes {
            Err(Cap::Daemon)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn in_use(&self) -> InUse {
        let counts = self.counts();
        InUse {
            envelopes: counts.envelopes.total,
            opens: counts.opens.total,
            screen: self.screen.used(),
        }
    }
}

/// Which session cap a new session would exceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cap {
    /// Its account's.
    Account,
    /// The daemon's, over all accounts.
    Daemon,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InUse {
    pub(crate) envelopes: usize,
    pub(crate) opens: usize,
    pub(crate) screen: crate::screen_budget::Usage,
}

/// What one owner holds of its host's limits.
#[derive(Default)]
struct Held {
    screen: BackingSlots,
    models: usize,
    opens: usize,
}

/// One owner's charges against its host's limits, and its envelope lease.
/// Dropped when the host has reaped the owner: everything still charged to
/// it goes back then.
pub(crate) struct OwnerAccount {
    services: Arc<HostServices>,
    uid: u32,
    held: Mutex<Held>,
    /// The session's envelope still counts against the caps.
    envelope: AtomicBool,
}

impl OwnerAccount {
    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The session has ended: its envelope no longer counts against the
    /// caps, though the owner keeps everything else it holds until it is
    /// reaped. Once; later calls, and the drop, give back nothing more.
    pub(crate) fn end_session(&self) {
        if self.envelope.swap(false, Ordering::SeqCst) {
            self.services.counts().envelopes.give(self.uid, 1);
        }
    }

    fn foreign(&self, uid: u32, what: &str) -> bool {
        if uid == self.uid {
            return false;
        }
        crate::log::error(
            "qshd",
            &format!(
                "a session owner of uid {} asked to {what} for uid {uid}; refused",
                self.uid
            ),
        );
        true
    }

    /// Charge the shared screen pool.
    pub(crate) fn screen_acquire(
        &self,
        uid: u32,
        slots: BackingSlots,
        models: usize,
    ) -> Result<(), String> {
        if self.foreign(uid, "charge the screen budget") {
            return Err("a session owner charges only its own account".into());
        }
        let mut held = self.held();
        // Worked out first: a charge the account could not record is never
        // made.
        let screen = held.screen.plus(slots)?;
        let total_models = held
            .models
            .checked_add(models)
            .ok_or("terminal screen budget arithmetic overflow")?;
        self.services.screen.acquire_slots(uid, slots, models)?;
        held.screen = screen;
        held.models = total_models;
        Ok(())
    }

    /// Refund the shared screen pool: never more than this owner holds.
    pub(crate) fn screen_release(&self, uid: u32, slots: BackingSlots, models: usize) {
        if self.foreign(uid, "refund the screen budget") {
            return;
        }
        if slots == BackingSlots::default() && models == 0 {
            return;
        }
        let mut held = self.held();
        if held.screen.cells < slots.cells || held.screen.rows < slots.rows || held.models < models
        {
            crate::log::error(
                "qshd",
                "a session owner gave back screen budget it does not hold; ignored",
            );
            return;
        }
        held.screen = held.screen.delta(slots);
        held.models -= models;
        self.services.screen.release_slots(uid, slots, models);
    }

    /// One more open in flight, if the daemon-wide open limits allow it.
    pub(crate) fn open_acquire(&self, uid: u32) -> bool {
        if self.foreign(uid, "open a channel") {
            return false;
        }
        let l = self.services.limits.opens;
        let mut held = self.held();
        if !self
            .services
            .counts()
            .opens
            .take(uid, l.global, l.per_uid, false)
        {
            return false;
        }
        held.opens += 1;
        true
    }

    /// One more, whatever the limits: a retiring channel.
    pub(crate) fn open_charge(&self, uid: u32) {
        if self.foreign(uid, "charge a channel") {
            return;
        }
        let mut held = self.held();
        self.services.counts().opens.take(uid, 0, 0, true);
        held.opens += 1;
    }

    /// One open of this owner is over.
    pub(crate) fn open_release(&self, uid: u32) {
        if self.foreign(uid, "release a channel") {
            return;
        }
        let mut held = self.held();
        if held.opens == 0 {
            crate::log::error(
                "qshd",
                "a session owner released a channel it does not hold; ignored",
            );
            return;
        }
        held.opens -= 1;
        self.services.counts().opens.give(uid, 1);
    }
}

impl Drop for OwnerAccount {
    fn drop(&mut self) {
        let held = std::mem::take(&mut *self.held());
        if held.screen != BackingSlots::default() || held.models != 0 {
            self.services
                .screen
                .release_slots(self.uid, held.screen, held.models);
        }
        let mut counts = self.services.counts();
        counts.opens.give(self.uid, held.opens);
        if self.envelope.swap(false, Ordering::SeqCst) {
            counts.envelopes.give(self.uid, 1);
        }
    }
}

#[cfg(test)]
#[path = "host_services_tests.rs"]
mod tests;
