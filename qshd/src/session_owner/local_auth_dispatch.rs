//! Dormant Personal authentication on one exact inherited admitted channel.
//! The canonical-UID/root frontend is a trusted Personal delegate. Its wire
//! fields are not independent Noise proof, System authority or a grant.
use super::local_personal_dispatch::{accept_live_report, PersonalReportSource};
use super::*;
use crate::session_owner::host_auth_contract::{
    AttachOutcome, AuthMethod, AuthOutcome, AuthRefusal,
};
use crate::session_owner::host_protocol::{HostDecoder, HostFrame, HostHeader, HostMessage};
use crate::session_owner::local_channel::{AdmittedChannel, HostDispatchChannel};
use crate::session_owner::protocol::OwnerRole;
use std::collections::{BTreeMap, VecDeque};
use std::io;

const ORDINARY_CREDIT: usize = 63;
const WRITE_QUANTUM: usize = 64;
type Reporter = (Arc<dyn PersonalAdmissionObserver>, PersonalReportSource);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchError {
    Refused,
    Protocol,
    Capacity,
    Deadline,
    Unavailable,
}
struct Registration {
    lease: PersonalAdmission,
    reporter: Option<Reporter>,
    context: Option<AuthReference>,
    deadline: u64,
    result_pending: bool,
}
enum WriteProgress {
    Open,
    PeerClosed,
}
enum Input {
    Pending,
    Frame(Box<HostFrame>),
    Eof,
}
struct Output {
    bytes: Vec<u8>,
    offset: usize,
    deadline: u64,
    ticket: Option<AuthReference>,
    requires_live: bool,
    ordinary: bool,
}
/// Nonclone custody and logical registrations stay in one serial owner. step
/// never blocks; one write quantum and at most two exact-length reads per turn
/// keep cancellation serviceable even while ordinary output cannot drain.
/// Call close or keep driving step through EOF; Drop alone cannot borrow a host
/// to refund its logical registration (the same rule as HostDispatchChannel).
pub(crate) struct PersonalAuthDispatch {
    channel: Option<HostDispatchChannel>,
    adapter: PersonalAuthorization,
    host: HostInstance,
    clock: Clock,
    last_now: u64,
    auth_timeout: u64,
    io_timeout: u64,
    decoder: HostDecoder,
    read_deadline: Option<u64>,
    slots: BTreeMap<AuthReference, Registration>,
    ordinary: VecDeque<Output>,
    lifecycle: Option<Output>,
    writing: Option<Output>,
}

/// Only the owning dispatcher can mint this guard, after timed correlation
/// and exact live-ticket lookup on its retained actual admitted channel.
/// No public DTO or raw report can construct it.
pub(super) struct LivePersonalReport<'a> {
    lease: &'a PersonalAdmission,
    frontend: FrontendAdmission,
    host: HostInstance,
    ticket: AuthReference,
    key: [u8; 32],
    session_id: u64,
    token: [u8; 16],
    now: u64,
}
pub(super) struct ReportParts<'a> {
    pub lease: &'a PersonalAdmission,
    pub frontend: FrontendAdmission,
    pub host: HostInstance,
    pub ticket: AuthReference,
    pub key: [u8; 32],
    pub session_id: u64,
    pub token: [u8; 16],
    pub now: u64,
}
impl<'a> LivePersonalReport<'a> {
    pub(super) fn into_parts(self) -> ReportParts<'a> {
        ReportParts {
            lease: self.lease,
            frontend: self.frontend,
            host: self.host,
            ticket: self.ticket,
            key: self.key,
            session_id: self.session_id,
            token: self.token,
            now: self.now,
        }
    }
}
impl PersonalAuthDispatch {
    pub(crate) fn new(
        channel: AdmittedChannel,
        host: &mut HostState,
        mode: HostMode,
        allowlist: transport::SharedAllowlist,
        clock: Clock,
        auth_timeout: u64,
        io_timeout: u64,
    ) -> Result<Self, DispatchError> {
        if !matches!(mode, HostMode::Personal { .. }) || auth_timeout == 0 || io_timeout == 0 {
            return Err(DispatchError::Refused);
        }
        let now = clock();
        if now.checked_add(auth_timeout).is_none() || now.checked_add(io_timeout).is_none() {
            return Err(DispatchError::Deadline);
        }
        let limit = host.local_auth_registration_limit();
        let channel = channel
            .into_host_dispatch(host, mode, limit)
            .map_err(|_| DispatchError::Refused)?;
        let adapter = match PersonalAuthorization::new(
            host.instance(),
            channel.frontend(),
            mode,
            allowlist,
            limit,
            clock.clone(),
        ) {
            Ok(a) => a,
            Err(_) => {
                channel.retire(host).map_err(|_| DispatchError::Refused)?;
                return Err(DispatchError::Refused);
            }
        };
        Ok(Self {
            channel: Some(channel),
            adapter,
            host: host.instance(),
            clock,
            last_now: now,
            auth_timeout,
            io_timeout,
            decoder: HostDecoder::new(),
            read_deadline: None,
            slots: BTreeMap::new(),
            ordinary: VecDeque::new(),
            lifecycle: None,
            writing: None,
        })
    }
    /// Trusted precharged setup handle, permanently associated with this exact
    /// host challenge before it is published. It is not completed proof or a
    /// cross-process setup protocol; actual observer completion is still needed.
    pub(crate) fn take_reporter(
        &mut self,
        ticket: AuthReference,
    ) -> Result<Reporter, AuthorityError> {
        self.slots
            .get_mut(&ticket)
            .and_then(|s| s.reporter.take())
            .ok_or(AuthorityError::Refused)
    }
    fn ordinary_count(&self) -> usize {
        self.ordinary.len() + usize::from(self.writing.as_ref().is_some_and(|o| o.ordinary))
    }
    fn credit(&self, lifecycle: bool) -> Result<(), DispatchError> {
        if if lifecycle {
            self.lifecycle.is_some() || self.writing.as_ref().is_some_and(|o| !o.ordinary)
        } else {
            self.ordinary_count() >= ORDINARY_CREDIT
        } {
            Err(DispatchError::Capacity)
        } else {
            Ok(())
        }
    }
    fn queue(
        &mut self,
        id: u64,
        message: HostAuthMessage,
        now: u64,
        lifecycle: bool,
    ) -> Result<(), DispatchError> {
        let now = now.max((self.clock)());
        self.credit(lifecycle)?;
        let (ticket, requires_live) = match &message {
            HostAuthMessage::Challenge { ticket, .. } => (Some(*ticket), true),
            HostAuthMessage::Result {
                ticket,
                outcome: AuthOutcome::Accepted(_),
            } => (Some(*ticket), true),
            HostAuthMessage::AttachResult { context, .. } => (
                self.slots
                    .iter()
                    .find_map(|(ticket, s)| (s.context == Some(*context)).then_some(*ticket)),
                false,
            ),
            _ => (None, false),
        };
        let frame = HostFrame {
            header: HostHeader {
                role: OwnerRole::Host,
                host: self.host,
                request_id: id,
            },
            message: HostMessage::Authentication(message),
        };
        let bytes = crate::session_owner::host_protocol::encode(&frame)
            .map_err(|_| DispatchError::Protocol)?;
        self.channel
            .as_mut()
            .ok_or(DispatchError::Refused)?
            .send_at(&frame, now)
            .map_err(|_| DispatchError::Protocol)?;
        let output = Output {
            bytes,
            offset: 0,
            deadline: now
                .checked_add(self.io_timeout)
                .ok_or(DispatchError::Deadline)?,
            ticket,
            requires_live,
            ordinary: !lifecycle,
        };
        if lifecycle {
            self.lifecycle = Some(output);
        } else {
            self.ordinary.push_back(output);
        }
        Ok(())
    }
    fn fresh_reference(&self) -> Result<AuthReference, DispatchError> {
        for _ in 0..8 {
            let r = AuthReference::new(fresh_bytes().map_err(|_| DispatchError::Unavailable)?)
                .ok_or(DispatchError::Unavailable)?;
            if !self.slots.contains_key(&r) && !self.slots.values().any(|s| s.context == Some(r)) {
                return Ok(r);
            }
        }
        Err(DispatchError::Unavailable)
    }
    fn retire_slot(
        &mut self,
        ticket: AuthReference,
        host: &mut HostState,
    ) -> Result<(), DispatchError> {
        if self
            .writing
            .as_ref()
            .is_some_and(|o| o.ticket == Some(ticket) && o.requires_live && o.offset > 0)
        {
            // An invalidated partially emitted success cannot be unsent or
            // interleaved: close this attempted seam rather than publish it.
            return Err(DispatchError::Refused);
        }
        self.ordinary
            .retain(|o| o.ticket != Some(ticket) || !o.requires_live);
        if self
            .writing
            .as_ref()
            .is_some_and(|o| o.ticket == Some(ticket) && o.requires_live)
        {
            self.writing = None;
        }
        if let Some(s) = self.slots.remove(&ticket) {
            let _ = s.lease.cancel(host);
        }
        if let Some(channel) = self.channel.as_mut() {
            channel.retire_local_ticket(ticket);
        }
        Ok(())
    }
    fn expire(&mut self, host: &mut HostState, now: u64) -> Result<(), DispatchError> {
        let retired: Vec<_> = self
            .slots
            .iter()
            .filter_map(|(t, s)| {
                ((!s.lease.slot.active.load(Ordering::Acquire))
                    || ((s.context.is_none() || s.result_pending) && now >= s.deadline))
                    .then_some(*t)
            })
            .collect();
        for ticket in retired {
            self.retire_slot(ticket, host)?;
        }
        if self.read_deadline.is_some_and(|d| now >= d)
            || self.writing.as_ref().is_some_and(|o| now >= o.deadline)
            || self.lifecycle.as_ref().is_some_and(|o| now >= o.deadline)
            || self.ordinary.iter().any(|o| now >= o.deadline)
        {
            return Err(DispatchError::Deadline);
        }
        Ok(())
    }
    fn context_current(&self, s: &Registration, host: &HostState) -> bool {
        let key = s.lease.slot.key.try_lock().ok().and_then(|k| *k);
        let observation = key.and_then(|k| s.lease.slot.inner.current(k));
        // Canonical lookup can run cancellation callbacks in a fixture, and
        // external Slot invalidation is monotonic. Check live custody AFTER
        // that read; any later invalidation also wins at every subsequent use.
        observation.is_some()
            && s.lease.slot.active.load(Ordering::Acquire)
            && host.authentication_is_current(
                s.lease.slot.binding.attempt,
                s.lease.slot.binding.frontend,
            )
    }
    fn write_turn(
        &mut self,
        host: &mut HostState,
        now: u64,
    ) -> Result<WriteProgress, DispatchError> {
        // A lifecycle frame may preempt only a frame for which no byte escaped.
        if self.lifecycle.is_some()
            && self
                .writing
                .as_ref()
                .is_some_and(|o| o.ordinary && o.offset == 0)
        {
            self.ordinary.push_front(self.writing.take().unwrap());
        }
        if self.writing.is_none() {
            self.writing = self.lifecycle.take().or_else(|| self.ordinary.pop_front());
        }
        let Some(output) = self.writing.as_ref() else {
            return Ok(WriteProgress::Open);
        };
        if output.requires_live {
            let ticket = output.ticket.ok_or(DispatchError::Refused)?;
            let live = self
                .slots
                .get(&ticket)
                .is_some_and(|s| s.context.is_none() || self.context_current(s, host));
            if !live {
                self.retire_slot(ticket, host)?;
                return Ok(WriteProgress::Open);
            }
            // The canonical policy read above can consume the remaining
            // authentication budget. Recheck after it, before any bytes escape.
            let checked_at = now.max((self.clock)());
            if self.slots.get(&ticket).is_some_and(|s| {
                (s.context.is_none() || s.result_pending) && checked_at >= s.deadline
            }) {
                return Err(DispatchError::Deadline);
            }
        }
        let now = now.max((self.clock)());
        let output = self.writing.as_mut().unwrap();
        if now >= output.deadline {
            return Err(DispatchError::Deadline);
        }
        let end = (output.offset + WRITE_QUANTUM).min(output.bytes.len());
        match self
            .channel
            .as_mut()
            .ok_or(DispatchError::Refused)?
            .write(&output.bytes[output.offset..end])
        {
            Ok(0) => Ok(WriteProgress::PeerClosed),
            Ok(n) => {
                output.offset += n;
                if output.offset == output.bytes.len() {
                    let completed = self.writing.take().unwrap();
                    if let Some(s) = completed.ticket.and_then(|t| self.slots.get_mut(&t)) {
                        if s.context.is_some() {
                            s.result_pending = false;
                        }
                    }
                }
                Ok(WriteProgress::Open)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(WriteProgress::Open)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                Ok(WriteProgress::PeerClosed)
            }
            Err(_) => Err(DispatchError::Unavailable),
        }
    }
    fn read_turn(&mut self, now: u64) -> Result<Input, DispatchError> {
        let mut bytes = [0; 4096];
        for _ in 0..2 {
            let wanted = self.decoder.remaining_frame_bytes().min(bytes.len());
            match self
                .channel
                .as_mut()
                .ok_or(DispatchError::Refused)?
                .read(&mut bytes[..wanted])
            {
                Ok(0) => {
                    self.decoder.finish().map_err(|_| DispatchError::Protocol)?;
                    return Ok(Input::Eof);
                }
                Ok(n) => {
                    if self.read_deadline.is_none() {
                        self.read_deadline = Some(
                            now.checked_add(self.io_timeout)
                                .ok_or(DispatchError::Deadline)?,
                        );
                    }
                    let frames = self
                        .decoder
                        .push(&bytes[..n])
                        .map_err(|_| DispatchError::Protocol)?;
                    if let Some(frame) = frames.into_iter().next() {
                        self.read_deadline = None;
                        return Ok(Input::Frame(Box::new(frame)));
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(Input::Pending)
                }
                Err(_) => return Err(DispatchError::Unavailable),
            }
        }
        Ok(Input::Pending)
    }
    fn receive(
        &mut self,
        frame: HostFrame,
        host: &mut HostState,
        now: u64,
    ) -> Result<(), DispatchError> {
        self.channel
            .as_mut()
            .ok_or(DispatchError::Refused)?
            .receive_at(&frame, now)
            .map_err(|_| DispatchError::Protocol)?;
        let id = frame.header.request_id;
        let HostMessage::Authentication(message) = frame.message else {
            return Err(DispatchError::Refused);
        };
        match message {
            HostAuthMessage::Begin {
                method: AuthMethod::Personal,
            } => {
                self.credit(false)?;
                let deadline = now
                    .checked_add(self.auth_timeout)
                    .ok_or(DispatchError::Deadline)?;
                let ticket = self.fresh_reference()?;
                let frontend = self
                    .channel
                    .as_ref()
                    .ok_or(DispatchError::Refused)?
                    .frontend();
                let intent = match host.begin_authentication(frontend, now, deadline) {
                    Ok(i) => i,
                    Err(_) => {
                        return self.queue(
                            id,
                            HostAuthMessage::ChallengeRefused {
                                method: AuthMethod::Personal,
                                reason: AuthRefusal::Unavailable,
                            },
                            now,
                            false,
                        )
                    }
                };
                let (observer, lease, source) =
                    match self.adapter.reserve_report(intent, ticket, now) {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = host.apply_policy_result(e.result, now);
                            return self.queue(
                                id,
                                HostAuthMessage::ChallengeRefused {
                                    method: AuthMethod::Personal,
                                    reason: AuthRefusal::Unavailable,
                                },
                                now,
                                false,
                            );
                        }
                    };
                self.slots.insert(
                    ticket,
                    Registration {
                        lease,
                        reporter: Some((observer, source)),
                        context: None,
                        deadline,
                        result_pending: false,
                    },
                );
                self.queue(
                    id,
                    HostAuthMessage::Challenge {
                        method: AuthMethod::Personal,
                        ticket,
                        deadline,
                        nonce: None,
                    },
                    now,
                    false,
                )
            }
            HostAuthMessage::PersonalReport {
                ticket,
                key,
                session_id,
                token,
            } => {
                self.credit(false)?;
                let slot = self.slots.get(&ticket).ok_or(DispatchError::Refused)?;
                if slot.context.is_some() || now >= slot.deadline {
                    return Err(DispatchError::Refused);
                }
                let frontend = self
                    .channel
                    .as_ref()
                    .ok_or(DispatchError::Refused)?
                    .frontend();
                let result = accept_live_report(
                    LivePersonalReport {
                        lease: &slot.lease,
                        frontend,
                        host: self.host,
                        ticket,
                        key,
                        session_id,
                        token,
                        now,
                    },
                    host,
                );
                match result {
                    Ok(HostDecision::Authenticated(_)) => {
                        let context = self.fresh_reference()?;
                        let slot = self.slots.get_mut(&ticket).unwrap();
                        slot.context = Some(context);
                        slot.result_pending = true;
                        self.queue(
                            id,
                            HostAuthMessage::Result {
                                ticket,
                                outcome: AuthOutcome::Accepted(context),
                            },
                            now,
                            false,
                        )
                    }
                    _ => {
                        self.queue(
                            id,
                            HostAuthMessage::Result {
                                ticket,
                                outcome: AuthOutcome::Refused(AuthRefusal::Unauthorized),
                            },
                            now,
                            false,
                        )?;
                        if let Some(s) = self.slots.remove(&ticket) {
                            let _ = s.lease.cancel(host);
                        }
                        Ok(())
                    }
                }
            }
            HostAuthMessage::Cancel { ticket } => {
                self.credit(true)?;
                let slot = self.slots.remove(&ticket).ok_or(DispatchError::Refused)?;
                let _ = slot.lease.cancel(host);
                // Discard unsent related responses. A partially emitted frame
                // forces this attempted seam to EOF on the next output turn;
                // never interleave Cancelled or publish a usable stale context.
                self.ordinary.retain(|o| o.ticket != Some(ticket));
                if let Some(output) = self.writing.as_mut() {
                    if output.ticket == Some(ticket) && output.offset > 0 {
                        output.requires_live = true;
                    }
                }
                if self
                    .writing
                    .as_ref()
                    .is_some_and(|o| o.ticket == Some(ticket) && o.offset == 0)
                {
                    self.writing = None;
                }
                self.queue(id, HostAuthMessage::Cancelled { ticket }, now, true)
            }
            HostAuthMessage::AuthorizeAttach { context, locator } => {
                self.credit(false)?;
                let ticket = self
                    .slots
                    .iter()
                    .find_map(|(t, s)| (s.context == Some(context)).then_some(*t))
                    .ok_or(DispatchError::Refused)?;
                let current = self.context_current(&self.slots[&ticket], host);
                let refusal = if current {
                    transport::session_resume::AttachRefusal::Unsupported
                } else {
                    transport::session_resume::AttachRefusal::Unauthorized
                };
                self.queue(
                    id,
                    HostAuthMessage::AttachResult {
                        context,
                        locator,
                        outcome: AttachOutcome::Refused(refusal),
                    },
                    now,
                    false,
                )?;
                if !current {
                    self.retire_slot(ticket, host)?;
                }
                Ok(())
            }
            _ => Err(DispatchError::Refused),
        }
    }
    pub(crate) fn step(&mut self, host: &mut HostState) -> Result<(), DispatchError> {
        if self.channel.is_none() {
            return Ok(());
        }
        if host.instance() != self.host {
            return Err(DispatchError::Refused);
        }
        let now = (self.clock)();
        let result = (|| {
            if now < self.last_now {
                return Err(DispatchError::Deadline);
            }
            self.last_now = now;
            self.expire(host, now)?;
            match self.write_turn(host, now)? {
                WriteProgress::PeerClosed => {
                    self.decoder.finish().map_err(|_| DispatchError::Protocol)?;
                    self.close(host)?;
                    return Ok(());
                }
                WriteProgress::Open => {}
            }
            match self.read_turn(now.max((self.clock)()))? {
                Input::Frame(frame) => {
                    let now = (self.clock)();
                    if now < self.last_now {
                        return Err(DispatchError::Deadline);
                    }
                    self.last_now = now;
                    self.expire(host, now)?;
                    self.receive(*frame, host, now)?;
                }
                Input::Eof => self.close(host)?,
                Input::Pending => {}
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = self.close(host);
        }
        // EOF is a terminal attempted seam, not a host/process shutdown.
        result
    }
    pub(crate) fn close(&mut self, host: &mut HostState) -> Result<(), DispatchError> {
        if host.instance() != self.host {
            return Err(DispatchError::Refused);
        }
        for (_, slot) in std::mem::take(&mut self.slots) {
            let _ = slot.lease.cancel(host);
        }
        self.ordinary.clear();
        self.lifecycle = None;
        self.writing = None;
        if let Some(channel) = self.channel.take() {
            channel.retire(host).map_err(|_| DispatchError::Refused)?;
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "local_auth_dispatch_tests.rs"]
mod tests;
