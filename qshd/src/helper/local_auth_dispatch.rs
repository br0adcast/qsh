//! Dormant single-proof System bridge. The caller retains the actual global
//! helper/host and real legacy seams; no loop, listener or dispatcher is started.
use super::*;
use crate::session_owner::authorization::{
    AuthenticationAttempt, FrontendAdmission, PolicyIntent, PolicyKind, PolicyResult, SystemContext,
};
use crate::session_owner::host::{HostDecision, HostError, HostState};
use crate::session_owner::host_auth_contract::{
    AuthMethod, AuthOutcome, AuthReference, AuthRefusal, HostAuthMessage,
};
use crate::session_owner::host_protocol::{self, HostDecoder, HostFrame, HostHeader, HostMessage};
use crate::session_owner::local_channel::HostDispatchChannel;
use crate::session_owner::protocol::{OwnerProtocolError, OwnerRole, MAX_OWNER_REQUESTS};
use rand_core::RngCore;
use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use transport::session_resume::HostInstance;

pub(super) struct HostTicket {
    frontend: FrontendAdmission,
    reference: AuthReference,
    ticket: policy_check::HostNonceTicket,
}
#[derive(Debug)]
pub(super) enum BridgeError {
    Refused,
    Io(io::Error),
    Protocol(OwnerProtocolError),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Idle,
    Progress,
    Closed,
}
struct Registration {
    ticket: AuthReference,
    attempt: AuthenticationAttempt,
    context: SystemContext,
    deadline: u64,
    proof_request: Option<u64>,
    accepted_context: Option<AuthReference>,
    sender: SyncSender<PolicyResult>,
    receiver: Receiver<PolicyResult>,
}
struct Current {
    deadline: u64,
    receiver: Receiver<PolicyResult>,
    outcome: Option<Result<HostDecision, HostError>>,
}
struct Output {
    bytes: Vec<u8>,
    offset: usize,
    deadline: u64,
}
pub(super) struct SystemHelperDispatch {
    channel: Option<HostDispatchChannel>,
    host: HostInstance,
    frontend: FrontendAdmission,
    auth_timeout: u64,
    io_timeout: u64,
    last_now: u64,
    decoder: HostDecoder,
    input_deadline: Option<u64>,
    outputs: VecDeque<Output>,
    registration: Option<Registration>,
    authenticated: Option<(AuthenticationAttempt, SystemContext)>,
    current: Option<Current>,
}
fn reference() -> Result<AuthReference, BridgeError> {
    for _ in 0..8 {
        let mut bytes = [0; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| BridgeError::Refused)?;
        if let Some(value) = AuthReference::new(bytes) {
            return Ok(value);
        }
    }
    Err(BridgeError::Refused)
}
impl SystemHelperDispatch {
    pub(super) fn bind(
        channel: HostDispatchChannel,
        host: &HostState,
        auth_timeout: u64,
        io_timeout: u64,
    ) -> Result<Self, BridgeError> {
        if auth_timeout == 0 || io_timeout == 0 || !cfg!(target_os = "linux") {
            return Err(BridgeError::Refused);
        }
        let frontend = channel.frontend();
        Ok(Self {
            channel: Some(channel),
            host: host.instance(),
            frontend,
            auth_timeout,
            io_timeout,
            last_now: 0,
            decoder: HostDecoder::new(),
            input_deadline: None,
            outputs: VecDeque::new(),
            registration: None,
            authenticated: None,
            current: None,
        })
    }
    fn queue(&mut self, id: u64, message: HostAuthMessage, now: u64) -> Result<(), BridgeError> {
        if self.outputs.len() >= MAX_OWNER_REQUESTS {
            return Err(BridgeError::Refused);
        }
        let frame = HostFrame {
            header: HostHeader {
                role: OwnerRole::Host,
                host: self.host,
                request_id: id,
            },
            message: HostMessage::Authentication(message),
        };
        let bytes = host_protocol::encode(&frame).map_err(BridgeError::Protocol)?;
        let deadline = now
            .checked_add(self.io_timeout)
            .ok_or(BridgeError::Refused)?;
        self.channel
            .as_mut()
            .ok_or(BridgeError::Refused)?
            .send_at(&frame, now)
            .map_err(BridgeError::Protocol)?;
        self.outputs.push_back(Output {
            bytes,
            offset: 0,
            deadline,
        });
        Ok(())
    }
    fn cancel_registration(&mut self, state: &mut LoopState, host: &mut HostState) {
        if let Some(registration) = self.registration.take() {
            if let Some(i) = state
                .host_auth_tickets
                .iter()
                .position(|t| t.frontend == self.frontend && t.reference == registration.ticket)
            {
                let entry = state.host_auth_tickets.swap_remove(i);
                let _ = policy_check::cancel_nonce_for_host(state, entry.ticket);
            }
            let _ = host.cancel_attempt(registration.attempt);
        }
        self.authenticated = None;
    }
    fn retire(&mut self, state: &mut LoopState, host: &mut HostState) {
        self.cancel_registration(state, host);
        self.current = None;
        self.outputs.clear();
        self.input_deadline = None;
        if let Some(channel) = self.channel.take() {
            let _ = channel.retire(host);
        }
    }
    pub(super) fn close(mut self, state: &mut LoopState, host: &mut HostState) {
        if host.instance() == self.host {
            self.retire(state, host);
        }
    }
    fn begin(
        &mut self,
        state: &mut LoopState,
        host: &mut HostState,
        id: u64,
        now: u64,
    ) -> Result<(), BridgeError> {
        if self.registration.is_some() || state.host_auth_tickets.len() >= MAX_OUTSTANDING_NONCES {
            return self.queue(
                id,
                HostAuthMessage::ChallengeRefused {
                    method: AuthMethod::System,
                    reason: AuthRefusal::Unavailable,
                },
                now,
            );
        }
        let deadline = now
            .checked_add(self.auth_timeout)
            .ok_or(BridgeError::Refused)?;
        let intent = match host.begin_authentication(self.frontend, now, deadline) {
            Ok(v) => v,
            Err(_) => {
                return self.queue(
                    id,
                    HostAuthMessage::ChallengeRefused {
                        method: AuthMethod::System,
                        reason: AuthRefusal::Unavailable,
                    },
                    now,
                )
            }
        };
        let attempt = intent.attempt();
        let Some(context) = intent.system_context() else {
            let _ = host.cancel_attempt(attempt);
            return Err(BridgeError::Refused);
        };
        // Host pending/attempt capacity and this one-slot destination precede Challenge.
        let (sender, receiver) = sync_channel(1);
        let reference = match (0..8).find_map(|_| {
            reference()
                .ok()
                .filter(|r| !state.host_auth_tickets.iter().any(|t| t.reference == *r))
        }) {
            Some(r) => r,
            None => {
                let _ = host.cancel_attempt(attempt);
                return Err(BridgeError::Refused);
            }
        };
        let ticket = match policy_check::issue_nonce_for_host(state, intent, now) {
            Ok(t) => t,
            Err(_) => {
                let _ = host.cancel_attempt(attempt);
                return self.queue(
                    id,
                    HostAuthMessage::ChallengeRefused {
                        method: AuthMethod::System,
                        reason: AuthRefusal::Unavailable,
                    },
                    now,
                );
            }
        };
        let nonce = ticket.nonce();
        state.host_auth_tickets.push(HostTicket {
            frontend: self.frontend,
            reference,
            ticket,
        });
        self.registration = Some(Registration {
            ticket: reference,
            attempt,
            context,
            deadline,
            proof_request: None,
            accepted_context: None,
            sender,
            receiver,
        });
        self.queue(
            id,
            HostAuthMessage::Challenge {
                method: AuthMethod::System,
                ticket: reference,
                deadline,
                nonce: Some(nonce),
            },
            now,
        )
    }
    fn received(
        &mut self,
        frame: HostFrame,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) -> Result<(), BridgeError> {
        self.channel
            .as_mut()
            .ok_or(BridgeError::Refused)?
            .receive_at(&frame, now)
            .map_err(BridgeError::Protocol)?;
        let id = frame.header.request_id;
        match frame.message {
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }) => self.begin(state, host, id, now),
            HostMessage::Authentication(HostAuthMessage::SystemProof {
                ticket,
                handshake_hash,
                record,
            }) => {
                let registration = self
                    .registration
                    .as_mut()
                    .filter(|r| {
                        r.ticket == ticket
                            && r.proof_request.is_none()
                            && r.accepted_context.is_none()
                    })
                    .ok_or(BridgeError::Refused)?;
                let i = state
                    .host_auth_tickets
                    .iter()
                    .position(|t| t.frontend == self.frontend && t.reference == ticket)
                    .ok_or(BridgeError::Refused)?;
                // Remove exact ticket before mutably borrowing the global state.
                let entry = state.host_auth_tickets.swap_remove(i);
                let nonce = entry.ticket.nonce();
                registration.proof_request = Some(id);
                if policy_check::start_authentication(
                    state,
                    entry.ticket,
                    policy_check::HostProof {
                        record,
                        handshake_hash,
                    },
                    registration.sender.clone(),
                    config,
                    switches,
                    now,
                )
                .is_err()
                {
                    // The shared cap refuses BEFORE spending; remove only this nonce.
                    state.host_nonces.remove(&nonce);
                }
                Ok(())
            }
            HostMessage::Authentication(HostAuthMessage::Cancel { ticket }) => {
                if self
                    .registration
                    .as_ref()
                    .is_none_or(|r| r.ticket != ticket)
                {
                    return Err(BridgeError::Refused);
                }
                self.cancel_registration(state, host);
                self.current = None;
                self.queue(id, HostAuthMessage::Cancelled { ticket }, now)
            }
            _ => Err(BridgeError::Refused),
        }
    }
    pub(super) fn start_current(
        &mut self,
        state: &mut LoopState,
        intent: PolicyIntent,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) -> Result<(), BridgeError> {
        let Some((attempt, context)) = self.authenticated else {
            return Err(BridgeError::Refused);
        };
        if self.channel.is_none()
            || self.current.is_some()
            || intent.attempt() != attempt
            || intent.system_context() != Some(context)
            || intent.deadline() <= now
            || !matches!(
                intent.kind(),
                PolicyKind::IssueGrant | PolicyKind::ConsumeGrant
            )
        {
            return Err(BridgeError::Refused);
        }
        let deadline = intent.deadline();
        let (sender, receiver) = sync_channel(1);
        self.current = Some(Current {
            deadline,
            receiver,
            outcome: None,
        });
        policy_check::start_policy_check(state, intent, sender, config, switches, now)
            .map_err(|_| BridgeError::Refused)
    }
    fn poll_results(
        &mut self,
        state: &mut LoopState,
        host: &mut HostState,
        now: u64,
    ) -> Result<bool, BridgeError> {
        let mut progress = false;
        if self.outputs.is_empty() {
            if let Some(registration) = self
                .registration
                .as_ref()
                .filter(|r| r.proof_request.is_some() && r.accepted_context.is_none())
            {
                match registration.receiver.try_recv() {
                    Ok(result) => {
                        let id = registration.proof_request.unwrap();
                        let ticket = registration.ticket;
                        let attempt = registration.attempt;
                        let context = registration.context;
                        let outcome = match host.apply_policy_result(result, now) {
                            Ok(HostDecision::Authenticated(a)) if a == attempt => {
                                let accepted = (0..8)
                                    .find_map(|_| reference().ok().filter(|r| *r != ticket))
                                    .ok_or(BridgeError::Refused)?;
                                self.authenticated = Some((attempt, context));
                                self.registration.as_mut().unwrap().accepted_context =
                                    Some(accepted);
                                AuthOutcome::Accepted(accepted)
                            }
                            _ => {
                                self.cancel_registration(state, host);
                                AuthOutcome::Refused(AuthRefusal::Unauthorized)
                            }
                        };
                        self.queue(id, HostAuthMessage::Result { ticket, outcome }, now)?;
                        progress = true;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => return Err(BridgeError::Refused),
                }
            }
        }
        if let Some(current) = self.current.as_mut().filter(|c| c.outcome.is_none()) {
            match current.receiver.try_recv() {
                Ok(result) => {
                    let outcome = host.apply_policy_result(result, now);
                    let refused = outcome.is_err();
                    current.outcome = Some(outcome);
                    if refused {
                        self.cancel_registration(state, host);
                    }
                    progress = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => return Err(BridgeError::Refused),
            }
        }
        Ok(progress)
    }
    #[allow(clippy::too_many_arguments)] // Actual legacy seams and global helper/host are borrowed per turn.
    pub(super) fn step(
        &mut self,
        seams: Seams<'_>,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) -> Result<Step, BridgeError> {
        if host.instance() != self.host {
            return Err(BridgeError::Refused);
        }
        #[cfg(target_os = "linux")]
        progress_verifications(seams, state, config);
        #[cfg(not(target_os = "linux"))]
        let _ = seams;
        if self.channel.is_none() {
            return Ok(Step::Closed);
        }
        if now < self.last_now
            || state.stopping
            || state.required_publication.is_some()
            || self
                .registration
                .as_ref()
                .is_some_and(|r| r.accepted_context.is_none() && now >= r.deadline)
            || self
                .current
                .as_ref()
                .is_some_and(|c| c.outcome.is_none() && now >= c.deadline)
            || self.input_deadline.is_some_and(|d| now >= d)
            || self.outputs.front().is_some_and(|o| now >= o.deadline)
        {
            self.retire(state, host);
            return Ok(Step::Closed);
        }
        self.last_now = now;
        let result = self.turn(state, host, config, switches, now);
        if result.is_err() {
            self.retire(state, host);
        }
        result
    }
    // A submitted proof still owes one reply even while its receiver is ready.
    fn check_batch(&self, frames: usize) -> Result<(), BridgeError> {
        let proof_debt = usize::from(
            self.registration
                .as_ref()
                .is_some_and(|r| r.proof_request.is_some() && r.accepted_context.is_none()),
        );
        if self
            .outputs
            .len()
            .checked_add(frames)
            .and_then(|n| n.checked_add(proof_debt))
            .is_none_or(|n| n > MAX_OWNER_REQUESTS)
        {
            return Err(BridgeError::Refused);
        }
        Ok(())
    }
    fn write_one(
        outputs: &mut VecDeque<Output>,
        mut write: impl FnMut(&[u8]) -> io::Result<usize>,
    ) -> Result<bool, BridgeError> {
        let Some(output) = outputs.front_mut() else {
            return Ok(false);
        };
        match write(&output.bytes[output.offset..]) {
            Ok(0) => Err(BridgeError::Refused),
            Ok(n) => {
                output.offset += n;
                if output.offset == output.bytes.len() {
                    outputs.pop_front();
                }
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(BridgeError::Io(e)),
        }
    }
    fn turn(
        &mut self,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) -> Result<Step, BridgeError> {
        let mut progress = false;
        // Drain the prior batch before admitting another bounded input chunk.
        if self.outputs.is_empty() {
            let mut bytes = [0u8; 4096];
            match self
                .channel
                .as_mut()
                .ok_or(BridgeError::Refused)?
                .read(&mut bytes)
            {
                Ok(0) => {
                    self.retire(state, host);
                    return Ok(Step::Closed);
                }
                Ok(n) => {
                    let frames = self
                        .decoder
                        .push(&bytes[..n])
                        .map_err(BridgeError::Protocol)?;
                    if self.decoder.buffered_len() == 0 {
                        self.input_deadline = None;
                    } else if self.input_deadline.is_none() {
                        self.input_deadline = Some(
                            now.checked_add(self.io_timeout)
                                .ok_or(BridgeError::Refused)?,
                        );
                    }
                    self.check_batch(frames.len())?;
                    for frame in frames {
                        self.received(frame, state, host, config, switches, now)?;
                    }
                    progress = true;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(BridgeError::Io(e)),
            }
        }
        progress |= self.poll_results(state, host, now)?;
        let channel = self.channel.as_mut().ok_or(BridgeError::Refused)?;
        progress |= Self::write_one(&mut self.outputs, |bytes| channel.write(bytes))?;
        Ok(if progress { Step::Progress } else { Step::Idle })
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) mod assertions {
    use super::*;
    fn completed(
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        seams: Seams<'_>,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
    ) -> Result<HostDecision, HostError> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                Instant::now() < until,
                "bounded current-policy child/result"
            );
            *clock += 1;
            bridge
                .step(seams, state, host, config, switches, *clock)
                .unwrap();
            if bridge.current.as_ref().is_some_and(|c| c.outcome.is_some()) {
                return bridge.current.take().unwrap().outcome.unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    pub(in crate::helper::server) fn queue_state(
        bridge: &mut SystemHelperDispatch,
        id: u64,
        now: u64,
    ) {
        assert!(bridge.outputs.is_empty());
        assert!(bridge.check_batch(MAX_OWNER_REQUESTS).is_ok());
        assert!(bridge.check_batch(MAX_OWNER_REQUESTS + 1).is_err());
        let mut outputs = VecDeque::from([
            Output {
                bytes: vec![1, 2, 3],
                offset: 0,
                deadline: 10,
            },
            Output {
                bytes: vec![4, 5],
                offset: 0,
                deadline: 11,
            },
        ]);
        assert!(SystemHelperDispatch::write_one(&mut outputs, |bytes| {
            assert_eq!(bytes, &[1, 2, 3]);
            Ok(1)
        })
        .unwrap());
        let snapshot = |q: &VecDeque<Output>| {
            q.iter()
                .map(|o| (o.bytes.clone(), o.offset, o.deadline))
                .collect::<Vec<_>>()
        };
        assert_eq!(outputs[0].offset, 1);
        assert_eq!(outputs[1].offset, 0);
        let before = snapshot(&outputs);
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            assert!(!SystemHelperDispatch::write_one(&mut outputs, |bytes| {
                assert_eq!(bytes, &[2, 3]);
                Err(kind.into())
            })
            .unwrap());
            assert_eq!(snapshot(&outputs), before);
        }
        let mut writes = 0;
        assert!(SystemHelperDispatch::write_one(&mut outputs, |bytes| {
            writes += 1;
            assert_eq!(bytes, &[2, 3]);
            Ok(bytes.len())
        })
        .unwrap());
        assert_eq!(writes, 1);
        assert_eq!(snapshot(&outputs), vec![(vec![4, 5], 0, 11)]);
        assert!(matches!(
            SystemHelperDispatch::write_one(&mut outputs, |_| Ok(0)),
            Err(BridgeError::Refused)
        ));
        assert_eq!(snapshot(&outputs), vec![(vec![4, 5], 0, 11)]);
        assert!(matches!(
            SystemHelperDispatch::write_one(
                &mut outputs,
                |_| Err(io::ErrorKind::BrokenPipe.into())
            ),
            Err(BridgeError::Io(_))
        ));
        assert_eq!(snapshot(&outputs), vec![(vec![4, 5], 0, 11)]);
        assert!(SystemHelperDispatch::write_one(&mut outputs, |bytes| {
            assert_eq!(bytes, &[4, 5]);
            Ok(2)
        })
        .unwrap());
        assert!(outputs.is_empty());
        assert!(!SystemHelperDispatch::write_one(&mut outputs, |_| panic!(
            "empty FIFO performs no write"
        ))
        .unwrap());

        // Reserve a real correlation request without invoking host authority.
        let frame = HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: bridge.host,
                request_id: id,
            },
            message: HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }),
        };
        bridge
            .channel
            .as_mut()
            .unwrap()
            .receive_at(&frame, now)
            .unwrap();
        let ticket = bridge.registration.as_ref().unwrap().ticket;
        for _ in 0..MAX_OWNER_REQUESTS {
            bridge.outputs.push_back(Output {
                bytes: vec![42],
                offset: 0,
                deadline: now + 10,
            });
        }
        let before = snapshot(&bridge.outputs);
        let reply = HostAuthMessage::ChallengeRefused {
            method: AuthMethod::System,
            reason: AuthRefusal::Unavailable,
        };
        assert!(matches!(
            bridge.queue(id, reply.clone(), now),
            Err(BridgeError::Refused)
        ));
        assert_eq!(snapshot(&bridge.outputs), before);
        assert_eq!(bridge.registration.as_ref().unwrap().ticket, ticket);
        bridge.outputs.pop_back();
        assert!(bridge.check_batch(1).is_ok());
        assert!(bridge.check_batch(2).is_err());
        bridge.outputs.clear();
        // The same reply is still admissible: full-queue refusal did not send_at.
        bridge.queue(id, reply.clone(), now).unwrap();
        let frame = HostDecoder::new()
            .push(&bridge.outputs[0].bytes)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(frame.header.request_id, id);
        assert_eq!(frame.message, HostMessage::Authentication(reply));
        bridge.outputs.clear();
    }
    pub(in crate::helper::server) fn short_output_timeout(bridge: &mut SystemHelperDispatch) {
        bridge.io_timeout = 2;
    }
    pub(in crate::helper::server) fn queued(bridge: &SystemHelperDispatch, count: usize) -> u64 {
        assert_eq!(bridge.outputs.len(), count);
        bridge.outputs.front().unwrap().deadline
    }
    pub(in crate::helper::server) fn proof_debt_boundaries(bridge: &SystemHelperDispatch) {
        assert!(bridge.outputs.is_empty());
        let r = bridge.registration.as_ref().unwrap();
        assert!(r.proof_request.is_some() && r.accepted_context.is_none());
        assert!(bridge.check_batch(MAX_OWNER_REQUESTS - 1).is_ok());
        assert!(bridge.check_batch(MAX_OWNER_REQUESTS).is_err());
    }
    pub(in crate::helper::server) fn ready_proof_deferred(
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        now: u64,
    ) {
        assert!(!bridge.outputs.is_empty());
        assert!(bridge.authenticated.is_none());
        assert!(!bridge.poll_results(state, host, now).unwrap());
        let r = bridge.registration.as_ref().unwrap();
        assert!(r.accepted_context.is_none());
        // Observe and return the exact real verdict, preserving the one-slot sink.
        let result = r
            .receiver
            .try_recv()
            .expect("ready real proof stays in its receiver under output backpressure");
        r.sender.try_send(result).unwrap();
        assert!(bridge.authenticated.is_none());
    }
    pub(in crate::helper::server) fn retired(bridge: &SystemHelperDispatch) {
        assert!(bridge.channel.is_none());
        assert!(bridge.outputs.is_empty());
        assert!(bridge.registration.is_none());
        assert!(bridge.authenticated.is_none());
        assert!(bridge.current.is_none());
        assert!(bridge.input_deadline.is_none());
    }
    pub(in crate::helper::server) fn start_queued_current(
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) {
        assert!(!bridge.outputs.is_empty());
        let attempt = bridge.authenticated.unwrap().0;
        let locator = host.create_session(attempt, now).unwrap();
        let intent = host
            .begin_issue(attempt, locator, now, now + 10_000)
            .unwrap();
        bridge
            .start_current(state, intent, config, switches, now)
            .unwrap();
    }
    pub(in crate::helper::server) fn queued_current_completed(bridge: &SystemHelperDispatch) {
        assert!(!bridge.outputs.is_empty());
        assert!(matches!(
            bridge.current.as_ref().unwrap().outcome.as_ref(),
            Some(Ok(HostDecision::GrantIssued(_)))
        ));
        assert!(bridge.authenticated.is_some());
    }
    pub(in crate::helper::server) fn expiring_current(
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        now: u64,
    ) -> AuthenticationAttempt {
        let attempt = bridge.authenticated.unwrap().0;
        let locator = host.create_session(attempt, now).unwrap();
        let intent = host.begin_issue(attempt, locator, now, now + 2).unwrap();
        bridge
            .start_current(state, intent, config, switches, now)
            .unwrap();
        attempt
    }
    pub(in crate::helper::server) fn current_revocation(
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        seams: Seams<'_>,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
    ) {
        let attempt = bridge.authenticated.unwrap().0;
        *clock += 1;
        let locator = host.create_session(attempt, *clock).unwrap();
        *clock += 1;
        let intent = host
            .begin_issue(attempt, locator, *clock, *clock + 10_000)
            .unwrap();
        bridge
            .start_current(state, intent, config, switches, *clock)
            .unwrap();
        let HostDecision::GrantIssued(offer) =
            completed(bridge, state, host, seams, config, switches, clock).unwrap()
        else {
            panic!("real current key policy must issue")
        };
        // Test-owned absolute authorized_keys path from trusting_config.
        std::fs::write(&config.authorized_keys_template, "").unwrap();
        *clock += 1;
        let intent = host
            .begin_consume(
                attempt,
                offer.grant(),
                offer.binding(),
                *clock,
                *clock + 10_000,
            )
            .unwrap();
        bridge
            .start_current(state, intent, config, switches, *clock)
            .unwrap();
        assert!(completed(bridge, state, host, seams, config, switches, clock).is_err());
        *clock += 1;
        assert!(host
            .begin_issue(attempt, locator, *clock, *clock + 10_000)
            .is_err());
        assert!(bridge.authenticated.is_none());
        assert_eq!(host.catalog_len(), 1);
    }
    pub(in crate::helper::server) fn foreign_current(
        bridge: &mut SystemHelperDispatch,
        other: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
    ) {
        let other_attempt = other.authenticated.unwrap().0;
        *clock += 1;
        let locator = host.create_session(other_attempt, *clock).unwrap();
        *clock += 1;
        let intent = host
            .begin_issue(other_attempt, locator, *clock, *clock + 10_000)
            .unwrap();
        let before = state.pending.verifying();
        assert!(bridge
            .start_current(state, intent, config, switches, *clock)
            .is_err());
        assert_eq!(state.pending.verifying(), before);
        assert!(bridge.current.is_none());
        host.cancel_attempt(other_attempt).unwrap();
    }

    #[allow(clippy::too_many_arguments)] // Test-only actual borrowed fixture boundaries.
    fn exchange(
        front: &mut crate::session_owner::local_channel::AdmittedChannel,
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        seams: Seams<'_>,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
        id: u64,
        message: HostAuthMessage,
    ) -> HostAuthMessage {
        use crate::session_owner::authorization::HostMode;
        let bytes = host_protocol::encode(&HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: host.instance(),
                request_id: id,
            },
            message: HostMessage::Authentication(message),
        })
        .unwrap();
        let mut at = 0;
        let until = Instant::now() + Duration::from_secs(5);
        let mut decoder = HostDecoder::new();
        loop {
            assert!(Instant::now() < until, "bounded actual fixture exchange");
            if at < bytes.len() {
                match front.frontend_write(host.instance(), HostMode::System, &bytes[at..]) {
                    Ok(n) => {
                        assert!(n > 0);
                        at += n
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("frontend: {e}"),
                }
            }
            *clock += 1;
            bridge
                .step(seams, state, host, config, switches, *clock)
                .unwrap();
            let mut read = [0; 4096];
            match front.frontend_read(host.instance(), HostMode::System, &mut read) {
                Ok(0) => panic!("unexpected fixture EOF"),
                Ok(n) => {
                    let frames = decoder.push(&read[..n]).unwrap();
                    if let Some(frame) = frames.into_iter().next() {
                        let HostMessage::Authentication(message) = frame.message else {
                            panic!()
                        };
                        return message;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("frontend: {e}"),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[allow(clippy::too_many_arguments)] // Test-only borrowed actual fixture, no exported capability.
    pub(in crate::helper::server) fn host_saturation(
        front: &mut crate::session_owner::local_channel::AdmittedChannel,
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        seams: Seams<'_>,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
    ) {
        let mut intents = Vec::new();
        for _ in 0..4 {
            *clock += 1;
            intents.push(
                host.begin_authentication(bridge.frontend, *clock, *clock + 10_000)
                    .unwrap(),
            );
        }
        let response = exchange(
            front,
            bridge,
            state,
            host,
            seams,
            config,
            switches,
            clock,
            2,
            HostAuthMessage::Begin {
                method: AuthMethod::System,
            },
        );
        assert!(matches!(response, HostAuthMessage::ChallengeRefused { .. }));
        assert!(state.host_auth_tickets.is_empty());
        assert!(state.host_nonces.is_empty());
        for intent in intents {
            host.cancel_attempt(intent.attempt()).unwrap();
        }
        let HostAuthMessage::Challenge { ticket, .. } = exchange(
            front,
            bridge,
            state,
            host,
            seams,
            config,
            switches,
            clock,
            3,
            HostAuthMessage::Begin {
                method: AuthMethod::System,
            },
        ) else {
            panic!("actual global host capacity must recover")
        };
        assert!(matches!(
            exchange(
                front,
                bridge,
                state,
                host,
                seams,
                config,
                switches,
                clock,
                4,
                HostAuthMessage::Cancel { ticket }
            ),
            HostAuthMessage::Cancelled { .. }
        ));
    }
    #[allow(clippy::too_many_arguments)] // Test-only actual stale result, actual frontend and shared helper context.
    pub(in crate::helper::server) fn full_sink(
        front: &mut crate::session_owner::local_channel::AdmittedChannel,
        bridge: &mut SystemHelperDispatch,
        state: &mut LoopState,
        host: &mut HostState,
        seams: Seams<'_>,
        config: &HelperConfig,
        switches: AccountSwitches,
        clock: &mut u64,
        key: &ssh_key::PrivateKey,
    ) {
        let registration = bridge.registration.as_ref().unwrap();
        let old_ticket = registration.ticket;
        let old = registration.receiver.try_recv().unwrap();
        assert!(bridge.authenticated.is_none());
        assert!(matches!(
            exchange(
                front,
                bridge,
                state,
                host,
                seams,
                config,
                switches,
                clock,
                4,
                HostAuthMessage::Cancel { ticket: old_ticket }
            ),
            HostAuthMessage::Cancelled { .. }
        ));
        let HostAuthMessage::Challenge {
            ticket,
            nonce: Some(nonce),
            ..
        } = exchange(
            front,
            bridge,
            state,
            host,
            seams,
            config,
            switches,
            clock,
            5,
            HostAuthMessage::Begin {
                method: AuthMethod::System,
            },
        )
        else {
            panic!()
        };
        // Fill the ONE real destination slot with a stale real verifier result,
        // never a manufactured approval. The current child cannot overwrite it.
        bridge
            .registration
            .as_ref()
            .unwrap()
            .sender
            .try_send(old)
            .unwrap();
        let login = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap()
            .name;
        let Request::Verify {
            login,
            public_key,
            signature,
            nonce,
            ..
        } = super::super::tests::proof_for_login(key, &login, [7; 32], nonce, [9; 16])
        else {
            unreachable!()
        };
        let frame = HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: host.instance(),
                request_id: 6,
            },
            message: HostMessage::Authentication(HostAuthMessage::SystemProof {
                ticket,
                handshake_hash: [7; 32],
                record: transport::AuthRecord {
                    public_key,
                    signature,
                    v2: Some(transport::auth::AuthV2 { login, nonce }),
                },
            }),
        };
        let bytes = host_protocol::encode(&frame).unwrap();
        assert_eq!(
            front
                .frontend_write(
                    host.instance(),
                    crate::session_owner::authorization::HostMode::System,
                    &bytes
                )
                .unwrap(),
            bytes.len()
        );
        // Submit through the same private handler used only after retained
        // receive_at; read the actual channel in turn, but hold its consumer.
        let mut incoming = [0; 4096];
        let n = bridge
            .channel
            .as_mut()
            .unwrap()
            .read(&mut incoming)
            .unwrap();
        let frames = bridge.decoder.push(&incoming[..n]).unwrap();
        assert_eq!(frames.len(), 1);
        *clock += 1;
        bridge
            .received(
                frames.into_iter().next().unwrap(),
                state,
                host,
                config,
                switches,
                *clock,
            )
            .unwrap();
        assert_eq!(state.pending.verifying(), 1);
        let until = Instant::now() + Duration::from_secs(5);
        while !state.pending.is_empty() {
            assert!(Instant::now() < until);
            progress_verifications(seams, state, config);
            std::thread::sleep(Duration::from_millis(1));
        }
        *clock += 1;
        bridge
            .step(seams, state, host, config, switches, *clock)
            .unwrap();
        assert!(bridge.authenticated.is_none());
        assert!(bridge.registration.is_none());
        assert!(state.host_nonces.is_empty());
        assert!(state.logins.is_empty());
    }
}
