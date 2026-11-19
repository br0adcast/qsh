//! Dormant personal authority for an already admitted same-account/root
//! frontend. Only real transport completion fills a reserved host ticket.
//! Canonical account lookup runs on the host consumer, never the UDP router.
//! This module creates no shell, PAM login, retained owner, or resource receipt.
use super::*;
use crate::session_owner::host::{HostDecision, HostError, HostState};
use crate::session_owner::host_auth_contract::{AuthReference, HostAuthMessage};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use transport::personal_admission::{
    PersonalAdmissionAttempt, PersonalAdmissionObserver, PersonalBinding,
    PersonalPossessionCompletion, Refused,
};

type Resolver = Arc<dyn Fn(u32) -> Option<CanonicalAccount> + Send + Sync>;
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
struct Inner {
    host: HostInstance,
    frontend: FrontendAdmission,
    mode: HostMode,
    account: CanonicalAccount,
    allowlist: transport::SharedAllowlist,
    limit: usize,
    registrations: AtomicUsize,
    resolve: Resolver,
    clock: Clock,
}
/// One pool is configured from the host's existing attempt/pending limits.
/// It retains no per-key permanent ownership and never removes allowlist keys.
#[derive(Clone)]
pub(crate) struct PersonalAuthorization {
    inner: Arc<Inner>,
    observer: Arc<Observer>,
}
/// Caller applies the authority-free refusal to retire its exact host intent.
#[derive(Debug)]
pub(crate) struct ReservationRefused {
    pub(crate) reason: AuthorityError,
    pub(crate) result: PolicyResult,
}
impl ReservationRefused {
    fn new(reason: AuthorityError, binding: PolicyBinding) -> Box<Self> {
        Box::new(Self {
            reason,
            result: PolicyResult {
                binding,
                observation: None,
            },
        })
    }
}
/// Delivery diagnostics describe logical authority and queue state only.
/// Actual transport task settlement still requires the manager's joined drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersonalDelivery {
    Pending,
    ProofQueued,
    Cancelled,
    QueueFull,
    ConsumerGone,
}
struct Slot {
    inner: Arc<Inner>,
    binding: PolicyBinding,
    active: AtomicBool,
    key: Mutex<Option<[u8; 32]>>,
    delivery: AtomicUsize,
    report_ticket: Option<AuthReference>,
    report: Mutex<Option<HostAuthMessage>>,
    report_consumer_alive: AtomicBool,
}
impl Slot {
    fn deactivate(&self) {
        if self.active.swap(false, Ordering::AcqRel) {
            self.inner.registrations.fetch_sub(1, Ordering::AcqRel);
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.deactivate();
    }
}
enum Completion {
    Proven(PersonalPossessionCompletion),
    Refused,
}
struct Ticket {
    slot: Arc<Slot>,
    reply: SyncSender<Completion>,
    answered: bool,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.answered {
            let _ = self.reply.try_send(Completion::Refused);
            let _ = self
                .slot
                .delivery
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
            self.slot.deactivate();
        }
    }
}
struct Observer {
    tickets: Mutex<VecDeque<Ticket>>,
}
impl Observer {
    fn prune(&self, now: u64) -> Result<(), AuthorityError> {
        self.tickets
            .try_lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .retain(|t| t.slot.active.load(Ordering::Acquire) && t.slot.binding.deadline > now);
        Ok(())
    }
}
struct Attempt {
    ticket: Ticket,
    binding: PersonalBinding,
}
/// Host-owned nonclone registration lease. Its one-slot result receiver exists
/// before probation accepts work. Drop discards any queued completion and
/// deauthorizes policy checks; the host retires its intent through cancel or
/// its existing deadline sweep. Transport cleanup is not resource cleanup.
pub(crate) struct PersonalAdmission {
    slot: Arc<Slot>,
    intent: Mutex<Option<PolicyIntent>>,
    reply: Mutex<Receiver<Completion>>,
}
fn resolve(uid: u32) -> Option<CanonicalAccount> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    (user.uid.as_raw() == uid
        && !user.name.is_empty()
        && user.name.len() <= transport::auth::AUTH_LOGIN_MAX
        && !user.name.contains(['\0', '/']))
    .then_some(CanonicalAccount {
        uid,
        name: user.name,
    })
}
impl PersonalAuthorization {
    pub(crate) fn new(
        host: HostInstance,
        frontend: FrontendAdmission,
        mode: HostMode,
        allowlist: transport::SharedAllowlist,
        limit: usize,
        clock: Clock,
    ) -> Result<Self, AuthorityError> {
        let HostMode::Personal { canonical_uid } = mode else {
            return Err(AuthorityError::Refused);
        };
        if frontend.host != host || limit == 0 {
            return Err(AuthorityError::Refused);
        }
        let account = resolve(canonical_uid).ok_or(AuthorityError::Unavailable)?;
        Ok(Self {
            inner: Arc::new(Inner {
                host,
                frontend,
                mode,
                account,
                allowlist,
                limit,
                registrations: AtomicUsize::new(0),
                resolve: Arc::new(resolve),
                clock,
            }),
            observer: Arc::new(Observer {
                tickets: Mutex::new(VecDeque::new()),
            }),
        })
    }
    pub(crate) fn reserve(
        &self,
        intent: PolicyIntent,
        now: u64,
    ) -> Result<(Arc<dyn PersonalAdmissionObserver>, PersonalAdmission), Box<ReservationRefused>>
    {
        self.reserve_inner(intent, now)
            .map(|(observer, lease)| (observer as Arc<dyn PersonalAdmissionObserver>, lease))
    }
    fn reserve_inner(
        &self,
        intent: PolicyIntent,
        now: u64,
    ) -> Result<(Arc<Observer>, PersonalAdmission), Box<ReservationRefused>> {
        let (ticket, lease) = self.reserve_ticket(intent, now, None)?;
        self.observer
            .tickets
            .try_lock()
            .map_err(|_| ReservationRefused::new(AuthorityError::Unavailable, ticket.slot.binding))?
            .push_back(ticket);
        Ok((self.observer.clone(), lease))
    }
    fn reserve_ticket(
        &self,
        intent: PolicyIntent,
        now: u64,
        report_ticket: Option<AuthReference>,
    ) -> Result<(Ticket, PersonalAdmission), Box<ReservationRefused>> {
        let b = intent.binding;
        let now = now.max((self.inner.clock)());
        self.observer
            .prune(now)
            .map_err(|e| ReservationRefused::new(e, b))?;
        if b.host != self.inner.host
            || b.frontend != self.inner.frontend
            || b.mode != self.inner.mode
            || b.kind != PolicyKind::Authenticate
            || b.deadline <= now
            || b.credential.is_some()
            || b.target.is_some()
            || b.grant.is_some()
        {
            return Err(ReservationRefused::new(AuthorityError::Refused, b));
        }
        let mut count = self.inner.registrations.load(Ordering::Acquire);
        loop {
            if count >= self.inner.limit {
                return Err(ReservationRefused::new(AuthorityError::Capacity, b));
            }
            match self.inner.registrations.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        let slot = Arc::new(Slot {
            inner: self.inner.clone(),
            binding: b,
            active: AtomicBool::new(true),
            key: Mutex::new(None),
            delivery: AtomicUsize::new(0),
            report_ticket,
            report: Mutex::new(None),
            report_consumer_alive: AtomicBool::new(report_ticket.is_some()),
        });
        let (tx, rx) = sync_channel(1);
        Ok((
            Ticket {
                slot: slot.clone(),
                reply: tx,
                answered: false,
            },
            PersonalAdmission {
                slot,
                intent: Mutex::new(Some(intent)),
                reply: Mutex::new(rx),
            },
        ))
    }
    pub(crate) fn registrations(&self) -> usize {
        self.inner.registrations.load(Ordering::Acquire)
    }
    pub(crate) fn check_current(
        &self,
        lease: &PersonalAdmission,
        host: &mut HostState,
        intent: PolicyIntent,
        now: u64,
    ) -> Result<HostDecision, HostError> {
        let now = now.max((self.inner.clock)());
        let b = intent.binding;
        let key = lease.slot.key.try_lock().ok().and_then(|k| *k);
        let matching = Arc::ptr_eq(&self.inner, &lease.slot.inner)
            && lease.slot.active.load(Ordering::Acquire)
            && b.host == lease.slot.binding.host
            && b.frontend == lease.slot.binding.frontend
            && b.attempt == lease.slot.binding.attempt
            && b.mode == self.inner.mode
            && b.revision == lease.slot.binding.revision
            && b.deadline > now
            && matches!(b.kind, PolicyKind::IssueGrant | PolicyKind::ConsumeGrant);
        let observation = if matching {
            key.and_then(|k| self.inner.current(k))
        } else {
            None
        };
        let now = now.max((self.inner.clock)());
        host.apply_policy_result(
            PolicyResult {
                binding: intent.binding,
                observation,
            },
            now,
        )
    }
}
impl Inner {
    fn current(&self, key: [u8; 32]) -> Option<VerifiedIdentity> {
        let account = (self.resolve)(self.account.uid)?;
        if account != self.account || !self.allowlist.try_lock().ok()?.contains(&key) {
            return None;
        }
        Some(VerifiedIdentity {
            account,
            #[cfg(feature = "system")]
            system_credential: None,
        })
    }
}
impl PersonalAdmissionObserver for Observer {
    fn try_begin(
        &self,
        binding: PersonalBinding,
    ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused> {
        let mut tickets = self.tickets.try_lock().map_err(|_| Refused)?;
        let ticket = loop {
            let ticket = tickets.pop_front().ok_or(Refused)?;
            if ticket.slot.active.load(Ordering::Acquire)
                && (ticket.slot.inner.clock)() < ticket.slot.binding.deadline
            {
                break ticket;
            }
        };
        if !binding.is_current() {
            return Err(Refused);
        }
        Ok(Box::new(Attempt { ticket, binding }))
    }
}
impl PersonalAdmissionAttempt for Attempt {
    fn try_complete(
        mut self: Box<Self>,
        proof: PersonalPossessionCompletion,
    ) -> Result<(), Refused> {
        if !proof.matches(&self.binding)
            || !self.ticket.slot.active.load(Ordering::Acquire)
            || (self.ticket.slot.inner.clock)() >= self.ticket.slot.binding.deadline
        {
            return Err(Refused);
        }
        self.ticket.answered = true;
        match self.ticket.reply.try_send(Completion::Proven(proof)) {
            Ok(()) => {
                self.ticket.slot.delivery.store(1, Ordering::Release);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.ticket.slot.deactivate();
                self.ticket.slot.delivery.store(3, Ordering::Release);
                Err(Refused)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.ticket.slot.deactivate();
                self.ticket.slot.delivery.store(4, Ordering::Release);
                Err(Refused)
            }
        }
    }
}
impl PersonalAdmission {
    pub(crate) fn delivery(&self) -> PersonalDelivery {
        match self.slot.delivery.load(Ordering::Acquire) {
            1 => PersonalDelivery::ProofQueued,
            2 => PersonalDelivery::Cancelled,
            3 => PersonalDelivery::QueueFull,
            4 => PersonalDelivery::ConsumerGone,
            _ => PersonalDelivery::Pending,
        }
    }
    pub(crate) fn try_authenticate(
        &self,
        host: &mut HostState,
        now: u64,
    ) -> Result<HostDecision, HostError> {
        let now = now.max((self.slot.inner.clock)());
        if !self.slot.active.load(Ordering::Acquire) || now >= self.slot.binding.deadline {
            self.slot.deactivate();
            let intent = self
                .intent
                .try_lock()
                .map_err(|_| AuthorityError::Unavailable)?
                .take()
                .ok_or(AuthorityError::Refused)?;
            return host.apply_policy_result(
                PolicyResult {
                    binding: intent.binding,
                    observation: None,
                },
                now,
            );
        }
        let completion = match self
            .reply
            .try_lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .try_recv()
        {
            Ok(c) => c,
            Err(TryRecvError::Empty) => return Err(AuthorityError::Unavailable.into()),
            Err(TryRecvError::Disconnected) => Completion::Refused,
        };
        let intent = self
            .intent
            .try_lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .take()
            .ok_or(AuthorityError::Refused)?;
        let observation =
            if self.slot.active.load(Ordering::Acquire) && now < intent.binding.deadline {
                if let Completion::Proven(proof) = completion {
                    let key = proof.client_key();
                    let observation = self.slot.inner.current(key);
                    if observation.is_some() {
                        *self
                            .slot
                            .key
                            .try_lock()
                            .map_err(|_| AuthorityError::Unavailable)? = Some(key);
                    }
                    observation
                } else {
                    None
                }
            } else {
                None
            };
        let now = now.max((self.slot.inner.clock)());
        let result = host.apply_policy_result(
            PolicyResult {
                binding: intent.binding,
                observation,
            },
            now,
        );
        if result.is_err() {
            self.slot.deactivate();
        }
        result
    }
    pub(crate) fn cancel(self, host: &mut HostState) -> Result<(), HostError> {
        host.cancel_attempt(self.slot.binding.attempt)
    }
}
impl Drop for PersonalAdmission {
    fn drop(&mut self) {
        self.slot.deactivate();
    }
}
#[cfg(test)]
#[path = "personal_authorization_tests.rs"]
mod tests;

#[path = "local_personal_dispatch.rs"]
pub(crate) mod local_personal_dispatch;

#[path = "local_auth_dispatch.rs"]
pub(crate) mod local_auth_dispatch;
