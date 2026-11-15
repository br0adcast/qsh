//! Personal sender reporting for a single precharged host challenge.
//! Serialized reports are trusted delegation only after the receiver validates
//! its actual admitted Personal channel, live ticket and current host policy.
use super::*;

struct ReportObserver {
    ticket: Mutex<Option<Ticket>>,
}
struct ReportAttempt {
    attempt: Attempt,
}
/// One fixed-size report slot belonging to the existing admission registration.
/// This is not another report pool or a receiver authentication capability.
pub(crate) struct PersonalReportSource {
    slot: Arc<Slot>,
}
impl PersonalAuthorization {
    pub(crate) fn reserve_report(
        &self,
        intent: PolicyIntent,
        ticket: AuthReference,
        now: u64,
    ) -> Result<
        (
            Arc<dyn PersonalAdmissionObserver>,
            PersonalAdmission,
            PersonalReportSource,
        ),
        Box<ReservationRefused>,
    > {
        let (ticket, lease) = self.reserve_ticket(intent, now, Some(ticket))?;
        let source = PersonalReportSource {
            slot: ticket.slot.clone(),
        };
        let observer = Arc::new(ReportObserver {
            ticket: Mutex::new(Some(ticket)),
        });
        Ok((observer, lease, source))
    }
}
impl PersonalAdmissionObserver for ReportObserver {
    fn try_begin(
        &self,
        binding: PersonalBinding,
    ) -> Result<Box<dyn PersonalAdmissionAttempt>, Refused> {
        let ticket = self
            .ticket
            .try_lock()
            .map_err(|_| Refused)?
            .take()
            .ok_or(Refused)?;
        if !binding.is_current()
            || !ticket.slot.report_consumer_alive.load(Ordering::Acquire)
            || !ticket.slot.active.load(Ordering::Acquire)
            || (ticket.slot.inner.clock)() >= ticket.slot.binding.deadline
        {
            return Err(Refused);
        }
        Ok(Box::new(ReportAttempt {
            attempt: Attempt { ticket, binding },
        }))
    }
}
impl PersonalAdmissionAttempt for ReportAttempt {
    fn try_complete(self: Box<Self>, proof: PersonalPossessionCompletion) -> Result<(), Refused> {
        let Self { attempt } = *self;
        let slot = attempt.ticket.slot.clone();
        if !slot.report_consumer_alive.load(Ordering::Acquire) {
            return Err(Refused);
        }
        let report = HostAuthMessage::PersonalReport {
            ticket: slot.report_ticket.ok_or(Refused)?,
            key: proof.client_key(),
            session_id: proof.session_id(),
            token: proof.token(),
        };
        // The existing attempt enforces exact binding/revision and one-use
        // completion, retaining actual proof in its original bounded receiver.
        Box::new(attempt).try_complete(proof)?;
        let result = (|| {
            let mut report_slot = slot.report.try_lock().map_err(|_| Refused)?;
            if report_slot.is_some()
                || !slot.active.load(Ordering::Acquire)
                || !slot.report_consumer_alive.load(Ordering::Acquire)
            {
                return Err(Refused);
            }
            *report_slot = Some(report);
            Ok(())
        })();
        if result.is_err() {
            slot.deactivate();
        }
        result
    }
}
impl PersonalReportSource {
    pub(crate) fn try_take_report(&self) -> Result<Option<HostAuthMessage>, Refused> {
        if !self.slot.active.load(Ordering::Acquire)
            || (self.slot.inner.clock)() >= self.slot.binding.deadline
        {
            self.slot.deactivate();
            return Err(Refused);
        }
        Ok(self.slot.report.try_lock().map_err(|_| Refused)?.take())
    }
}

/// Distinct private delegation evidence: never a fabricated transport
/// completion. Only an opaque guard from the actual owning dispatcher may
/// enter this constructor. The Personal frontend is the trusted delegate.
struct DelegatedPersonalEvidence<'a> {
    lease: &'a PersonalAdmission,
    key: [u8; 32],
    _session_id: u64,
    _token: [u8; 16],
    now: u64,
}
impl<'a> DelegatedPersonalEvidence<'a> {
    fn from_live(
        guard: super::local_auth_dispatch::LivePersonalReport<'a>,
    ) -> Result<Self, HostError> {
        let p = guard.into_parts();
        let slot = &p.lease.slot;
        let b = slot.binding;
        let now = p.now.max((slot.inner.clock)());
        if !slot.active.load(Ordering::Acquire)
            || b.deadline <= now
            || slot.report_ticket != Some(p.ticket)
            || b.host != p.host
            || b.frontend != p.frontend
            || slot.inner.host != p.host
            || slot.inner.frontend != p.frontend
            || b.kind != PolicyKind::Authenticate
            || b.mode != slot.inner.mode
            || !matches!(b.mode,HostMode::Personal{canonical_uid} if canonical_uid==slot.inner.account.uid)
        {
            return Err(AuthorityError::Refused.into());
        }
        Ok(Self {
            lease: p.lease,
            key: p.key,
            _session_id: p.session_id,
            _token: p.token,
            now,
        })
    }
    fn apply(self, host: &mut HostState) -> Result<HostDecision, HostError> {
        let slot = &self.lease.slot;
        let intent = self
            .lease
            .intent
            .try_lock()
            .map_err(|_| AuthorityError::Unavailable)?
            .take()
            .ok_or(AuthorityError::Refused)?;
        let mut observation = slot.inner.current(self.key);
        let now = self.now.max((slot.inner.clock)());
        // Cancellation and an absolute deadline may win during the canonical
        // policy read; neither can be converted into a late host approval.
        if !slot.active.load(Ordering::Acquire) || now >= intent.binding.deadline {
            observation = None;
        }
        let result = host.apply_policy_result(
            PolicyResult {
                binding: intent.binding,
                observation,
            },
            now,
        );
        if result.is_ok() {
            *slot
                .key
                .try_lock()
                .map_err(|_| AuthorityError::Unavailable)? = Some(self.key);
        } else {
            slot.deactivate();
        }
        result
    }
}
pub(super) fn accept_live_report(
    guard: super::local_auth_dispatch::LivePersonalReport<'_>,
    host: &mut HostState,
) -> Result<HostDecision, HostError> {
    DelegatedPersonalEvidence::from_live(guard)?.apply(host)
}

impl Drop for PersonalReportSource {
    fn drop(&mut self) {
        // Loss before callback completion is observed by the existing Ticket
        // path. A report already taken is independent delegated wire evidence;
        // receiver acceptance never depends on this process-local source flag.
        self.slot
            .report_consumer_alive
            .store(false, Ordering::Release);
    }
}
