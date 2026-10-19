//! Shared recovery ownership. Only one attempt can publish a proof at a time;
//! physical checks feed logical completion after that attempt is retired.
use super::*;
use ::connect::recovery_gate::{AddressId, AddressOutcome};
use ::connect::recovery_sweep::{CheckMembership, RecoveryMethod, RecoverySweep};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use transport::driver_std::RecoveryProgress;

/// Each endpoint contributes at most its first send and first successful send;
/// one consumed source follows. Retransmission volume cannot grow this queue.
struct Progress {
    sent: HashMap<SocketAddr, (bool, bool)>,
    selected: bool,
    pending: VecDeque<RecoveryProgress>,
}
impl Progress {
    fn new(endpoints: &[SocketAddr]) -> Self {
        Self {
            sent: endpoints.iter().map(|&e| (e, (false, false))).collect(),
            selected: false,
            pending: VecDeque::new(),
        }
    }
    fn observe(&mut self, progress: RecoveryProgress) {
        let publish = match progress {
            RecoveryProgress::Sent {
                endpoint, success, ..
            } => {
                let Some((seen, succeeded)) = self.sent.get_mut(&endpoint) else {
                    return;
                };
                let changed = !*seen || (success && !*succeeded);
                *seen = true;
                *succeeded |= success;
                changed
            }
            RecoveryProgress::Selected { endpoint, .. } => {
                if !self
                    .sent
                    .get(&endpoint)
                    .is_some_and(|(_, success)| *success)
                {
                    return;
                }
                let changed = !self.selected;
                self.selected = true;
                changed
            }
        };
        if publish {
            self.pending.push_back(progress);
        }
    }
}

struct OwnedAttempt(Option<attempt::Attempt>);
impl Drop for OwnedAttempt {
    fn drop(&mut self) {
        if let Some(attempt) = &self.0 {
            attempt.detach();
        }
    }
}

struct ActivityGuard<'a>(&'a Recovery, u64, ::connect::recovery_gate::SweepId);
impl Drop for ActivityGuard<'_> {
    fn drop(&mut self) {
        self.0.clear_qsh_attempt(self.1, self.2);
    }
}

impl Climb<'_> {
    pub(super) fn run_shared_recovery(&mut self, cancel: &knock::Cancel) -> Climbed {
        use ::connect::reconnect::RoundEnd;
        let failed = || Climbed::Failed {
            end: RoundEnd::AllFailed,
            line: None,
        };
        let recovery = self.recovery.expect("shared recovery owner");
        let (epoch, sweep_id) = self.recovery_attempt.expect("shared recovery stamp");
        let Some(identity) = self.setup.server_identity() else {
            return failed();
        };
        let dns_started = Instant::now();
        for (i, address) in self.addrs.iter_mut().enumerate() {
            if let Some(port) = recovery.port(i) {
                address.qsh_port = port;
                self.setup.allowlist(&address.host, port);
            }
        }
        let loaded = self
            .candidates()
            .expect("background key loading never exits");
        // Enrollment belongs to this immutable session/process identity. A new
        // alias still has to prove the same expected key and accept this key.
        // Replacement Setup clears enrollment; SSH bootstrap stays route-scoped.
        let enrolled = !self
            .setup
            .allowlisted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        let mut methods = Vec::new();
        if enrolled {
            methods.push(RecoveryMethod::Allowlist);
        }
        methods.extend(
            (0..loaded.keys.len()).map(|candidate| RecoveryMethod::Signature { candidate }),
        );
        let mut memberships = Vec::new();
        let mut servers = HashMap::new();
        let mut unresolved = Vec::new();
        // Keep the preferred-endpoint DNS policy. A catalog revision interrupts
        // this sweep; ready endpoints never wait behind an unresolved sibling.
        for offset in 0..self.addrs.len() {
            if self.interrupted() || cancel.is_cancelled() {
                return failed();
            }
            let i = (self.first + offset) % self.addrs.len();
            let address = &self.addrs[i];
            let resolved = if recovery.catalog_managed() {
                recovery.endpoint(i)
            } else {
                (address.host.as_str(), address.qsh_port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(attempt::preferred_addr)
            };
            let Some(resolved) = resolved else {
                unresolved.push(i);
                continue;
            };
            let endpoint = match dial_target(&address.host, resolved) {
                Ok(endpoint) => endpoint,
                Err(why) => {
                    self.say(&report::no_answer(&address.host, address.qsh_port, &why));
                    recovery.finish(
                        self.revision,
                        epoch,
                        sweep_id,
                        AddressId(i),
                        AddressOutcome::Failed,
                    );
                    continue;
                }
            };
            let server = match trust::recovery_server_key(
                &address.host,
                address.qsh_port,
                identity.qsh_key,
                &self.setup.pins,
            ) {
                Ok(server) => server,
                Err(error) => {
                    let outcome = if matches!(error, trust::TrustError::KeyChanged { .. }) {
                        AddressOutcome::IdentityMismatch
                    } else {
                        AddressOutcome::NeedsUser
                    };
                    self.say(&format!("qsh: {error}"));
                    recovery.finish(self.revision, epoch, sweep_id, AddressId(i), outcome);
                    continue;
                }
            };
            if methods.is_empty() {
                self.say(&report::refused(
                    &address.host,
                    address.qsh_port,
                    &self.setup.args.login,
                    &[],
                    &loaded.looked,
                ));
                recovery.finish(
                    self.revision,
                    epoch,
                    sweep_id,
                    AddressId(i),
                    AddressOutcome::Failed,
                );
                continue;
            }
            servers.insert(i, server);
            for &method in &methods {
                memberships.push(CheckMembership {
                    address: AddressId(i),
                    endpoint,
                    method,
                });
            }
        }
        let mut aliases = HashMap::<_, Vec<AddressId>>::new();
        for membership in &memberships {
            aliases
                .entry((membership.method, membership.endpoint))
                .or_default()
                .push(membership.address);
        }
        let mut sweep = RecoverySweep::new(epoch, sweep_id, self.revision, memberships.clone());
        while let Some(plan) = sweep.next_attempt() {
            if self.interrupted() || cancel.is_cancelled() {
                return failed();
            }
            let _activity = ActivityGuard(recovery, self.revision, sweep_id);
            let login = match plan.id.method {
                RecoveryMethod::Allowlist => Login::Allowlist,
                RecoveryMethod::Signature { candidate } => {
                    Login::Signature(loaded.keys[candidate].signer.clone())
                }
            };
            let progress = Arc::new(Mutex::new(Progress::new(&plan.endpoints)));
            let observer = progress.clone();
            let mut owned = OwnedAttempt(Some(attempt::Attempt::open_recovery(
                memberships
                    .iter()
                    .filter(|m| m.method == plan.id.method && plan.endpoints.contains(&m.endpoint))
                    .map(|m| transport::recovery_handshake::RecoveryEndpoint {
                        address: m.address.0,
                        endpoint: m.endpoint,
                    })
                    .collect(),
                identity.qsh_key,
                self.setup.keypair.private,
                login,
                self.tx.clone(),
                self.setup.token,
                Arc::new(move |event| {
                    observer
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .observe(event)
                }),
            )));
            let att = owned.0.as_ref().expect("owned shared attempt");
            let mut checked = HashMap::<SocketAddr, Instant>::new();
            let mut selected = None;
            let mut probes = HashMap::new();
            let mut probe_queue = VecDeque::new();
            let mut refused = HashSet::new();
            let mut terminal = None;
            loop {
                if self.interrupted() || cancel.is_cancelled() {
                    return failed();
                }
                let changes =
                    std::mem::take(&mut progress.lock().unwrap_or_else(|e| e.into_inner()).pending);
                for change in changes {
                    match change {
                        RecoveryProgress::Sent {
                            endpoint,
                            at,
                            success,
                        } => {
                            sweep.sent(plan.id, endpoint, at, success);
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                checked.entry(endpoint)
                            {
                                slot.insert(at);
                                probe_queue.push_back(endpoint);
                            }
                            // Only actual sends become active presentation.
                            for &address in &aliases[&(plan.id.method, endpoint)] {
                                recovery.observe_qsh(
                                    self.revision,
                                    sweep_id,
                                    address,
                                    Some(endpoint),
                                );
                            }
                        }
                        RecoveryProgress::Selected { endpoint, at } => {
                            if sweep.selected(plan.id, endpoint, at) {
                                selected = Some(endpoint);
                            }
                        }
                    }
                }
                if let Some(endpoint) = selected {
                    let verdict = att.verdict();
                    if verdict != Verdict::StillTrying {
                        terminal = Some((endpoint, verdict));
                        break;
                    }
                    // Refusal hints on other endpoints cannot terminate the
                    // selected authentication phase or renew its first-Live budget.
                    probes.clear();
                } else {
                    // Refusal probes are diagnostic sockets, bounded independently
                    // of the one proof-producing transcript. Queued probes prove
                    // nothing; only exact stamped ICMP refusal accelerates a check.
                    while probes.len() < 8 {
                        let Some(endpoint) = probe_queue.pop_front() else {
                            break;
                        };
                        if let Ok(probe) =
                            crate::port_probe::PortProbe::start(endpoint, epoch, plan.id.serial)
                        {
                            probes.insert(endpoint, probe);
                        }
                    }
                    probes.retain(|endpoint, probe| match probe.poll() {
                        crate::port_probe::ProbeResult::Pending => checked
                            .get(endpoint)
                            .is_some_and(|at| at.elapsed() < transport::HANDSHAKE_GIVE_UP_AFTER),
                        crate::port_probe::ProbeResult::Refused {
                            epoch: got_epoch,
                            attempt,
                            target,
                        } => {
                            if got_epoch == epoch
                                && attempt == plan.id.serial
                                && target == *endpoint
                            {
                                refused.insert(target);
                            }
                            false
                        }
                        crate::port_probe::ProbeResult::Finished => false,
                    });
                    if checked.len() == plan.endpoints.len()
                        && checked.iter().all(|(endpoint, at)| {
                            refused.contains(endpoint)
                                || at.elapsed() >= transport::HANDSHAKE_GIVE_UP_AFTER
                        })
                    {
                        break;
                    }
                    // A local driver failure before dispatch is not evidence that
                    // unsent addresses failed. Retry another sweep without SSH credit.
                    if att.events.closed.load(std::sync::atomic::Ordering::SeqCst) {
                        return failed();
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if let Some((endpoint, Verdict::Working)) = terminal {
                let i = memberships
                    .iter()
                    .find(|m| m.method == plan.id.method && m.endpoint == endpoint)
                    .expect("selected endpoint has logical membership")
                    .address
                    .0;
                let att = owned.0.take().expect("accepted attempt");
                let (verdict, att, trial) = self.trial_for_attempt(att);
                if verdict != Verdict::Working {
                    self.forget(&att);
                    return failed();
                }
                let (outcome, _) = self.logged_in(att, trial, endpoint, identity.qsh_key);
                if self.interrupted() {
                    return failed();
                }
                for completion in sweep.finish_checked(plan.id, endpoint, AddressOutcome::Recovered)
                {
                    recovery.finish(
                        self.revision,
                        epoch,
                        sweep_id,
                        completion.address,
                        completion.outcome,
                    );
                }
                if outcome == DirectOutcome::SessionGone {
                    return Climbed::Failed {
                        end: RoundEnd::SessionGone { addr: i },
                        line: Some(status::session_gone_text(&self.addrs[i].host)),
                    };
                }
                let (attempt, trial, remote) =
                    self.connected.take().expect("accepted shared login");
                return Climbed::Connected(Connected {
                    attempt,
                    trial,
                    addr: i,
                    port: self.addrs[i].qsh_port,
                    remote,
                });
            }
            // Stop/join the sole network proof owner before terminal accounting
            // or another initiator. A source selected during cancellation keeps
            // its unfinished obligation; cancellation itself is not refusal.
            self.forget(att);
            recovery.clear_qsh_attempt(self.revision, sweep_id);
            let late_selection = progress.lock().unwrap_or_else(|e| e.into_inner()).selected;
            let completed: Vec<_> = if let Some((endpoint, verdict)) = terminal {
                vec![(endpoint, verdict)]
            } else if !late_selection {
                checked
                    .keys()
                    .copied()
                    .map(|endpoint| (endpoint, Verdict::Unreachable(None)))
                    .collect()
            } else {
                Vec::new()
            };
            for (endpoint, verdict) in completed {
                let aliases: Vec<_> = memberships
                    .iter()
                    .filter(|m| m.method == plan.id.method && m.endpoint == endpoint)
                    .map(|m| m.address.0)
                    .collect();
                let mut outcome = AddressOutcome::Failed;
                for i in aliases {
                    let host = self.addrs[i].host.clone();
                    let port = self.addrs[i].qsh_port;
                    if let Verdict::ProtocolFailure(failure) = verdict {
                        self.say(&report::no_answer(&host, port, &protocol_why(failure)));
                    } else if matches!(verdict, Verdict::Unreachable(_)) {
                        let send = refused.contains(&endpoint).then(|| {
                            let error = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
                            (error.kind(), error.to_string())
                        });
                        let server = trust::ServerKey {
                            key: identity.qsh_key,
                            source: servers[&i].source.clone(),
                        };
                        let (diagnosis, line) =
                            self.silence(i, &host, port, endpoint, server, send);
                        if diagnosis == DirectOutcome::KeyChanged {
                            outcome = AddressOutcome::IdentityMismatch;
                        }
                        if let Some(line) = line {
                            self.say(&line);
                        }
                    }
                }
                let completions = if matches!(verdict, Verdict::ProtocolFailure(_)) {
                    sweep.finish_protocol_failure(plan.id, endpoint)
                } else {
                    sweep.finish_checked(plan.id, endpoint, outcome)
                };
                for completion in completions {
                    recovery.finish(
                        self.revision,
                        epoch,
                        sweep_id,
                        completion.address,
                        completion.outcome,
                    );
                }
            }
            sweep.retire(plan.id);
        }
        // DNS resolution runs in the retained catalog owner. A late DNS result
        // changes the revision and restarts this sweep, never completes this one.
        while !unresolved.is_empty() && dns_started.elapsed() < crate::road_catalog::DNS_TIMEOUT {
            if self.interrupted() || cancel.is_cancelled() {
                return failed();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for i in unresolved {
            if self.interrupted() {
                return failed();
            }
            self.say(&report::could_not_resolve(&self.addrs[i].host, None));
            recovery.finish(
                self.revision,
                epoch,
                sweep_id,
                AddressId(i),
                AddressOutcome::Failed,
            );
        }
        failed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_network_callbacks_keep_only_bounded_first_check_and_selection_evidence() {
        let a: SocketAddr = "127.0.0.1:60001".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:60002".parse().unwrap();
        let foreign: SocketAddr = "127.0.0.1:60003".parse().unwrap();
        let now = Instant::now();
        let mut state = Progress::new(&[a, b]);
        state.observe(RecoveryProgress::Selected {
            endpoint: a,
            at: now,
        });
        for n in 0..10000 {
            for endpoint in [a, b, foreign] {
                state.observe(RecoveryProgress::Sent {
                    endpoint,
                    at: now + Duration::from_millis(n),
                    success: n > 0,
                });
            }
        }
        state.observe(RecoveryProgress::Selected {
            endpoint: foreign,
            at: now,
        });
        state.observe(RecoveryProgress::Selected {
            endpoint: b,
            at: now,
        });
        state.observe(RecoveryProgress::Selected {
            endpoint: a,
            at: now,
        });
        assert_eq!(
            state.pending.len(),
            5,
            "two first checks, two first successes, one source"
        );
        assert!(
            matches!(state.pending[0], RecoveryProgress::Sent { endpoint, at, success: false } if endpoint == a && at == now)
        );
        assert!(
            matches!(state.pending[1], RecoveryProgress::Sent { endpoint, at, success: false } if endpoint == b && at == now)
        );
        assert!(
            matches!(state.pending[4], RecoveryProgress::Selected { endpoint, .. } if endpoint == b)
        );
        state.pending.clear();
        state.observe(RecoveryProgress::Sent {
            endpoint: a,
            at: now,
            success: true,
        });
        assert!(
            state.pending.is_empty(),
            "draining cannot renew retransmission evidence"
        );
    }
}
