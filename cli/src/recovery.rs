//! One UDP owner and independent SSH fallback, with generation-bound publication.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::climb::Setup;
use crate::{log, report};
use ::connect::recovery_gate::{
    AddressId, AddressOutcome, GateDecision, RecoveryEpoch, RecoveryGate, SweepId,
};

pub const UDP_ROUND_INTERVAL: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(20);

struct State {
    gate: RecoveryGate,
    revision: u64,
    local_send_failure: bool,
    endpoints: Option<Vec<Option<SocketAddr>>>,
    ports: Vec<Option<u16>>,
    ssh: Option<(u64, knock::Cancel)>,
    next_ssh: u64,
    qsh_activity: std::collections::HashMap<AddressId, (u64, SweepId, QshActivity)>,
    observed_sweep: Option<SweepId>,
    ssh_activity: Option<(u64, AddressId)>,
    ssh_retry_at: Option<Instant>,
}

struct SshAttempt {
    epoch: RecoveryEpoch,
    revision: u64,
    attempt: u64,
    cancel: knock::Cancel,
}

/// Observation only: none of these fields participates in recovery decisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Activity {
    pub qsh: Vec<QshActivity>,
    pub ssh: Option<AddressId>,
    pub ssh_retry_at: Option<Instant>,
    pub ssh_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QshActivity {
    pub address: AddressId,
    /// None while resolving; never substitute another protocol's DNS result.
    pub endpoint: Option<SocketAddr>,
}

pub struct Recovery {
    pub cancel: knock::Cancel,
    epoch: RecoveryEpoch,
    state: Mutex<State>,
    retry_now: AtomicBool,
    diagnostics: Vec<crate::trust::BackgroundDiscovery>,
}

impl State {
    fn cancel_ssh(&mut self) {
        self.ssh_activity = None;
        if let Some((_, cancel)) = self.ssh.take() {
            cancel.cancel();
        }
    }
    fn changed(&mut self, epoch: RecoveryEpoch) {
        self.cancel_ssh();
        self.revision += 1;
        self.local_send_failure = false;
        self.qsh_activity.clear();
        self.observed_sweep = None;
        self.gate.reset(epoch);
    }
}

impl Recovery {
    pub fn new(epoch: RecoveryEpoch, addresses: usize) -> Self {
        Self {
            cancel: knock::Cancel::new(),
            epoch,
            state: Mutex::new(State {
                gate: RecoveryGate::new(epoch, (0..addresses).map(AddressId).collect()),
                revision: 0,
                local_send_failure: false,
                endpoints: None,
                ports: vec![None; addresses],
                ssh: None,
                next_ssh: 0,
                qsh_activity: std::collections::HashMap::new(),
                observed_sweep: None,
                ssh_activity: None,
                ssh_retry_at: None,
            }),
            retry_now: AtomicBool::new(false),
            diagnostics: (0..addresses)
                .map(|_| crate::trust::BackgroundDiscovery::default())
                .collect(),
        }
    }

    /// Membership is the complete configured list, never the eight-slot table.
    pub fn with_catalog(
        epoch: RecoveryEpoch,
        addresses: Vec<AddressId>,
        endpoints: Vec<(AddressId, SocketAddr)>,
    ) -> Self {
        let count = addresses.iter().map(|id| id.0 + 1).max().unwrap_or(0);
        let recovery = Self::new(epoch, count);
        {
            let mut state = recovery.state.lock().unwrap_or_else(|e| e.into_inner());
            state.gate = RecoveryGate::new(epoch, addresses);
            state.endpoints = Some(vec![None; count]);
        }
        recovery.update_endpoints(epoch, endpoints);
        recovery
    }

    /// Called only by the catalog owner; stale DNS generations cannot publish.
    pub fn update_endpoints(&self, epoch: RecoveryEpoch, endpoints: Vec<(AddressId, SocketAddr)>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if epoch != self.epoch || self.cancel.is_cancelled() {
            return;
        }
        let mut updated = vec![None; state.ports.len()];
        for (id, endpoint) in endpoints {
            if let Some(slot) = updated.get_mut(id.0) {
                *slot = Some(endpoint);
            }
        }
        if state.endpoints.as_ref() != Some(&updated) {
            state.changed(self.epoch);
            for diagnostic in &self.diagnostics {
                diagnostic.invalidate();
            }
            state.endpoints = Some(updated);
        }
    }

    pub fn catalog_managed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .endpoints
            .is_some()
    }

    pub fn endpoint(&self, addr: usize) -> Option<SocketAddr> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut endpoint = state.endpoints.as_ref()?.get(addr).copied().flatten()?;
        if let Some(port) = state.ports[addr] {
            endpoint.set_port(port);
        }
        Some(endpoint)
    }

    /// Permit invalidation precedes cancellation, including tasks dropped at exit.
    pub fn stop(&self, setup: &Setup) {
        setup.invalidate_ssh_authorization();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.cancel.cancel();
        state.qsh_activity.clear();
        state.ssh_retry_at = None;
        state.cancel_ssh();
        for diagnostic in &self.diagnostics {
            diagnostic.invalidate();
        }
    }

    /// Stop fallback for a current local admission refusal without invalidating
    /// its terminal result. The same lock revokes any in-flight SSH publication.
    pub fn local_send_failed(&self, revision: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled() || state.revision != revision {
            return false;
        }
        state.local_send_failure = true;
        state.qsh_activity.clear();
        state.ssh_retry_at = None;
        state.cancel_ssh();
        true
    }

    fn stopped(&self) -> bool {
        self.cancel.is_cancelled()
            || self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .local_send_failure
    }

    pub fn begin_sweep(&self, sweep: SweepId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled() || state.local_send_failure {
            return;
        }
        state.gate.begin_sweep(sweep);
        state.observed_sweep = Some(sweep);
        state.qsh_activity.clear();
    }

    pub fn finish(
        &self,
        revision: u64,
        epoch: RecoveryEpoch,
        sweep: SweepId,
        addr: AddressId,
        outcome: AddressOutcome,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled() || state.local_send_failure || state.revision != revision {
            return;
        }
        if epoch == self.epoch
            && state
                .qsh_activity
                .get(&addr)
                .is_some_and(|(r, s, _)| *r == revision && *s == sweep)
        {
            state.qsh_activity.remove(&addr);
        }
        match state.gate.finish(epoch, sweep, addr, outcome) {
            GateDecision::AllowSsh => log::log("recovery: full QSH sweep failed; SSH permitted"),
            GateDecision::Recovered => state.cancel_ssh(),
            _ => {}
        }
    }

    pub fn activity(&self) -> Activity {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let running = !self.cancel.is_cancelled() && !state.local_send_failure;
        Activity {
            qsh: if running {
                let mut paths: Vec<_> = state
                    .qsh_activity
                    .values()
                    .map(|(_, _, q)| q.clone())
                    .collect();
                paths.sort_by_key(|q| q.address.0);
                paths
            } else {
                Vec::new()
            },
            ssh: running
                .then(|| state.ssh_activity.map(|(_, id)| id))
                .flatten(),
            ssh_retry_at: running.then_some(state.ssh_retry_at).flatten(),
            ssh_allowed: running && state.gate.ssh_allowed(),
        }
    }

    pub fn observe_qsh(
        &self,
        revision: u64,
        sweep: SweepId,
        address: AddressId,
        endpoint: Option<SocketAddr>,
    ) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled()
            || state.local_send_failure
            || state.revision != revision
            || state.observed_sweep != Some(sweep)
            || address.0 >= state.ports.len()
        {
            return;
        }
        state.qsh_activity.insert(
            address,
            (revision, sweep, QshActivity { address, endpoint }),
        );
    }

    /// Retiring one shared initiator makes its paths queued again. Logical
    /// completion remains separate because other methods may still be required.
    pub fn clear_qsh_attempt(&self, revision: u64, sweep: SweepId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.revision == revision && state.observed_sweep == Some(sweep) {
            state.qsh_activity.clear();
        }
    }

    fn observe_ssh(&self, attempt: &SshAttempt, address: AddressId) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !self.cancel.is_cancelled()
            && !attempt.cancel.is_cancelled()
            && state.revision == attempt.revision
            && attempt.epoch == self.epoch
            && state
                .ssh
                .as_ref()
                .is_some_and(|(id, _)| *id == attempt.attempt)
        {
            state.ssh_activity = Some((attempt.attempt, address));
            state.ssh_retry_at = None;
        }
    }

    fn finish_ssh(&self, attempt: &SshAttempt) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .ssh_activity
            .is_some_and(|(id, _)| id == attempt.attempt)
        {
            state.ssh_activity = None;
        }
    }

    pub fn ssh_allowed(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !self.cancel.is_cancelled() && !state.local_send_failure && state.gate.ssh_allowed()
    }
    pub fn retry_now(&self) {
        self.retry_now.store(true, Ordering::SeqCst);
    }
    pub fn revision(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .revision
    }
    pub fn port(&self, addr: usize) -> Option<u16> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).ports[addr]
    }
    pub fn discovery(
        &self,
        addr: usize,
        revision: u64,
        source: Arc<dyn crate::trust::Discover + Send + Sync>,
    ) -> RecoveryDiagnostic<'_> {
        RecoveryDiagnostic {
            recovery: self,
            addr,
            revision,
            source,
        }
    }

    fn begin_ssh(&self) -> Option<SshAttempt> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled() || state.local_send_failure || !state.gate.ssh_allowed() {
            return None;
        }
        state.cancel_ssh();
        state.next_ssh += 1;
        let attempt = state.next_ssh;
        let cancel = knock::Cancel::new();
        state.ssh = Some((attempt, cancel.clone()));
        Some(SshAttempt {
            epoch: self.epoch,
            revision: state.revision,
            attempt,
            cancel,
        })
    }

    /// Same lock as reset/cancel/recovered: a late worker cannot publish a port.
    fn publish_ready(&self, attempt: &SshAttempt, addr: usize, port: u16) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled()
            || state.local_send_failure
            || attempt.cancel.is_cancelled()
            || attempt.epoch != self.epoch
            || state.revision != attempt.revision
            || !state.gate.ssh_allowed()
            || !state
                .ssh
                .as_ref()
                .is_some_and(|(id, _)| *id == attempt.attempt)
        {
            return false;
        }
        if state.ports[addr] != Some(port) {
            state.ports[addr] = Some(port);
            state.changed(self.epoch);
            for diagnostic in &self.diagnostics {
                diagnostic.invalidate();
            }
        }
        true
    }

    pub fn interrupted(&self, revision: u64) -> bool {
        self.cancel.is_cancelled() || self.revision() != revision
    }
    pub fn wait_udp(&self, started: Instant, _revision: u64) -> bool {
        while started.elapsed() < UDP_ROUND_INTERVAL && !self.cancel.is_cancelled() {
            std::thread::sleep(POLL);
        }
        !self.cancel.is_cancelled()
    }
    fn wait_ssh(&self, failed: u32) -> bool {
        let until = Instant::now() + ::connect::reconnect::pause_after(failed);
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ssh_retry_at = Some(until);
        while Instant::now() < until && !self.stopped() {
            if self.retry_now.swap(false, Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(POLL);
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ssh_retry_at = None;
        !self.cancel.is_cancelled()
    }

    pub fn spawn_ssh(
        self: &Arc<Self>,
        setup: Arc<Setup>,
        addresses: Vec<::connect::Address>,
        first: usize,
    ) {
        if !addresses.iter().any(|a| a.ssh.is_some()) {
            return;
        }
        let recovery = self.clone();
        std::thread::Builder::new()
            .name("qsh-reconnect-ssh".into())
            .spawn(move || {
                let order: Vec<_> = (0..addresses.len())
                    .filter(|&i| i == first)
                    .chain((0..addresses.len()).filter(|&i| i != first))
                    .collect();
                let mut rounds = 0u32;
                loop {
                    recovery.retry_now.store(false, Ordering::SeqCst);
                    for &i in &order {
                        let address = &addresses[i];
                        let Some(route) = &address.ssh else { continue };
                        let attempt = loop {
                            if recovery.cancel.is_cancelled() {
                                return;
                            }
                            if let Some(attempt) = recovery.begin_ssh() {
                                break attempt;
                            }
                            std::thread::sleep(POLL);
                        };
                        log::shown(&report::trying_ssh(&address.host, route));
                        // All SSH auth and remote exec operations use this generation's
                        // token. Reset, QSH success and owner cancellation revoke it.
                        match setup.bring_up_observed(address, &attempt.cancel, || {
                            recovery.observe_ssh(&attempt, AddressId(i))
                        }) {
                            Ok(ready) => {
                                let port = ready.port_for(address.qsh_port);
                                if recovery.publish_ready(&attempt, i, port) {
                                    log::shown(&report::qshd_ready(
                                        &address.host,
                                        address.qsh_port,
                                        port,
                                    ));
                                    if let Some(warning) = ready.warning {
                                        log::shown(&report::qshd_warning(&address.host, &warning));
                                    }
                                }
                            }
                            Err(crate::ssh_step::SshStepError::NeedsPrompt) => log::log(&format!(
                                "recovery: ssh address {i}: NeedsPrompt; UDP keeps trying"
                            )),
                            Err(why) => log::log(&format!("recovery: ssh address {i}: {why:?}")),
                        }
                        recovery.finish_ssh(&attempt);
                    }
                    rounds = rounds.saturating_add(1);
                    log::log(&format!(
                        "recovery: next SSH round in {} s; UDP keeps trying",
                        ::connect::reconnect::pause_after(rounds).as_secs()
                    ));
                    if !recovery.wait_ssh(rounds) {
                        return;
                    }
                }
            })
            .expect("start SSH recovery");
    }
}
/// A nonblocking diagnostic's result belongs to the endpoint revision that
/// requested it, even when a later sweep asks about the same socket address.
pub struct RecoveryDiagnostic<'a> {
    recovery: &'a Recovery,
    addr: usize,
    revision: u64,
    source: Arc<dyn crate::trust::Discover + Send + Sync>,
}
impl crate::trust::Discover for RecoveryDiagnostic<'_> {
    fn key(&self, endpoint: SocketAddr) -> Result<[u8; 32], sshauth::discover::DiscoveryError> {
        let state = self
            .recovery
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.recovery.cancel.is_cancelled() || state.revision != self.revision {
            return Err(sshauth::discover::DiscoveryError::Silent {
                addr: endpoint,
                waited: Duration::ZERO,
            });
        }
        crate::trust::RecoveryDiscovery {
            pending: &self.recovery.diagnostics[self.addr],
            source: self.source.clone(),
        }
        .key(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: RecoveryEpoch = RecoveryEpoch {
        connection: 7,
        network: 0,
    };

    fn ready(r: &Recovery, addr: usize, port: u16) {
        let sweep = SweepId(r.revision() + 1);
        r.begin_sweep(sweep);
        for i in 0..2 {
            r.finish(
                r.revision(),
                EPOCH,
                sweep,
                AddressId(i),
                AddressOutcome::Failed,
            );
        }
        let attempt = r.begin_ssh().unwrap();
        assert!(r.publish_ready(&attempt, addr, port));
    }

    #[test]
    fn all_dispatched_recovery_paths_are_visible_without_lighting_queued_paths() {
        let r = Recovery::new(EPOCH, 3);
        r.begin_sweep(SweepId(1));
        let endpoints: Vec<_> = (0..3)
            .map(|i| {
                (
                    AddressId(i),
                    format!("127.0.0.1:{}", 60000 + i).parse().unwrap(),
                )
            })
            .collect();
        for &(id, endpoint) in &endpoints[..2] {
            r.observe_qsh(r.revision(), SweepId(1), id, Some(endpoint));
        }
        let args = crate::args::parse_args(
            &endpoints
                .iter()
                .map(|(_, endpoint)| endpoint.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let view = crate::recovery_status::View::build(
            &args.addresses,
            &endpoints,
            &[],
            &[],
            Some(&r.activity()),
            Instant::now(),
        );
        assert_eq!(
            view.targets
                .iter()
                .map(|target| target.qsh)
                .collect::<Vec<_>>(),
            vec![
                crate::recovery_status::QshState::Trying,
                crate::recovery_status::QshState::Trying,
                crate::recovery_status::QshState::Queued
            ]
        );
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        let view = crate::recovery_status::View::build(
            &args.addresses,
            &endpoints,
            &[],
            &[],
            Some(&r.activity()),
            Instant::now(),
        );
        assert_eq!(
            view.targets[0].qsh,
            crate::recovery_status::QshState::Queued
        );
        assert_eq!(
            view.targets[1].qsh,
            crate::recovery_status::QshState::Trying
        );
    }

    #[test]
    fn a_completed_new_sweep_cannot_be_replaced_by_old_progress() {
        let r = Recovery::new(EPOCH, 1);
        r.begin_sweep(SweepId(1));
        r.observe_qsh(r.revision(), SweepId(1), AddressId(0), None);
        r.begin_sweep(SweepId(2));
        r.observe_qsh(r.revision(), SweepId(2), AddressId(0), None);
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(2),
            AddressId(0),
            AddressOutcome::Failed,
        );
        r.observe_qsh(r.revision(), SweepId(1), AddressId(0), None);
        assert!(
            r.activity().qsh.is_empty(),
            "a delayed old sweep cannot look active"
        );
    }

    #[test]
    fn activity_is_concurrent_and_rejects_stale_completion() {
        let r = Recovery::new(EPOCH, 2);
        r.begin_sweep(SweepId(1));
        for i in 0..2 {
            r.finish(
                r.revision(),
                EPOCH,
                SweepId(1),
                AddressId(i),
                AddressOutcome::Failed,
            );
        }
        let old = r.begin_ssh().unwrap();
        r.observe_ssh(&old, AddressId(1));
        let rev = r.revision();
        r.begin_sweep(SweepId(2));
        r.observe_qsh(
            rev,
            SweepId(2),
            AddressId(0),
            Some("127.0.0.1:60000".parse().unwrap()),
        );
        let view = r.activity();
        assert_eq!(view.qsh[0].address, AddressId(0));
        assert_eq!(view.ssh, Some(AddressId(1)));
        let newer = r.begin_ssh().unwrap();
        r.observe_ssh(&newer, AddressId(0));
        r.finish_ssh(&old);
        assert_eq!(r.activity().ssh, Some(AddressId(0)));
        r.update_endpoints(
            EPOCH,
            vec![(AddressId(0), "127.0.0.2:60000".parse().unwrap())],
        );
        r.observe_qsh(rev, SweepId(2), AddressId(0), None);
        r.observe_ssh(&old, AddressId(1));
        assert!(r.activity().qsh.is_empty());
        assert!(r.activity().ssh.is_none());
    }

    #[test]
    fn stale_discovery_cannot_publish_after_an_endpoint_revision() {
        use crate::trust::Discover;
        struct Offer;
        impl Discover for Offer {
            fn key(&self, _: SocketAddr) -> Result<[u8; 32], sshauth::discover::DiscoveryError> {
                Ok([9; 32])
            }
        }
        let r = Recovery::new(EPOCH, 1);
        let diagnostic = r.discovery(0, r.revision(), Arc::new(Offer));
        let endpoint = "127.0.0.1:60001".parse().unwrap();
        let _ = diagnostic.key(endpoint);
        r.update_endpoints(EPOCH, vec![(AddressId(0), endpoint)]);
        for _ in 0..10 {
            assert!(diagnostic.key(endpoint).is_err());
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_catalog_change_revokes_ssh_and_rejects_its_late_port() {
        let r = Recovery::with_catalog(
            EPOCH,
            vec![AddressId(0)],
            vec![(AddressId(0), "127.0.0.1:60001".parse().unwrap())],
        );
        r.begin_sweep(SweepId(1));
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        let ssh = r.begin_ssh().expect("complete sweep admits SSH");
        r.update_endpoints(
            EPOCH,
            vec![(AddressId(0), "127.0.0.2:60001".parse().unwrap())],
        );
        assert!(ssh.cancel.is_cancelled());
        assert!(!r.ssh_allowed());
        assert!(!r.publish_ready(&ssh, 0, 60002));
        assert_eq!(r.port(0), None);
        r.finish(
            ssh.revision,
            EPOCH,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        assert!(!r.ssh_allowed());
        r.begin_sweep(SweepId(2));
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(2),
            AddressId(0),
            AddressOutcome::Failed,
        );
        assert!(r.begin_ssh().is_some());
    }

    #[test]
    fn client179_local_refusal_retains_result_but_revokes_ssh_publication() {
        let r = Recovery::new(EPOCH, 1);
        let revision = r.revision();
        r.begin_sweep(SweepId(1));
        r.finish(
            revision,
            EPOCH,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        let ssh = r
            .begin_ssh()
            .expect("ordinary remote failure still admits SSH");
        r.begin_sweep(SweepId(2));
        assert!(r.local_send_failed(revision));
        assert!(ssh.cancel.is_cancelled());
        assert!(!r.publish_ready(&ssh, 0, 60002));
        assert!(
            !r.interrupted(revision),
            "terminal result remains publishable"
        );
        assert_eq!(r.revision(), revision);
        r.finish(
            revision,
            EPOCH,
            SweepId(2),
            AddressId(0),
            AddressOutcome::Failed,
        );
        r.begin_sweep(SweepId(3));
        r.finish(
            revision,
            EPOCH,
            SweepId(3),
            AddressId(0),
            AddressOutcome::Failed,
        );
        assert!(!r.ssh_allowed());
        assert!(r.begin_ssh().is_none());
        assert!(!r.activity().ssh_allowed);
        assert!(r.activity().qsh.is_empty());
    }

    #[test]
    fn client179_stale_local_refusal_cannot_stop_replacement_revision() {
        let r = Recovery::with_catalog(
            EPOCH,
            vec![AddressId(0)],
            vec![(AddressId(0), "127.0.0.1:60001".parse().unwrap())],
        );
        let old = r.revision();
        assert!(r.local_send_failed(old));
        r.update_endpoints(
            EPOCH,
            vec![(AddressId(0), "127.0.0.2:60001".parse().unwrap())],
        );
        let current = r.revision();
        r.begin_sweep(SweepId(2));
        r.finish(
            current,
            EPOCH,
            SweepId(2),
            AddressId(0),
            AddressOutcome::Failed,
        );
        let ssh = r.begin_ssh().unwrap();
        assert!(!r.local_send_failed(old));
        assert!(!ssh.cancel.is_cancelled());
        assert!(r.publish_ready(&ssh, 0, 60002));
        assert_eq!(r.port(0), Some(60002));
    }

    #[test]
    fn recovered_qsh_cancels_an_inflight_ssh_attempt_before_publication() {
        let r = Recovery::new(EPOCH, 1);
        r.begin_sweep(SweepId(1));
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        let ssh = r.begin_ssh().unwrap();
        r.begin_sweep(SweepId(2));
        r.finish(
            r.revision(),
            EPOCH,
            SweepId(2),
            AddressId(0),
            AddressOutcome::Recovered,
        );
        assert!(ssh.cancel.is_cancelled());
        assert!(!r.publish_ready(&ssh, 0, 60002));
        assert!(!r.ssh_allowed());
    }

    #[test]
    fn old_network_results_cannot_change_endpoint_or_admit_ssh() {
        let endpoint = "127.0.0.1:60001".parse().unwrap();
        let r = Recovery::with_catalog(EPOCH, vec![AddressId(0)], vec![(AddressId(0), endpoint)]);
        let stale = RecoveryEpoch {
            network: 99,
            ..EPOCH
        };
        r.update_endpoints(
            stale,
            vec![(AddressId(0), "127.0.0.2:60002".parse().unwrap())],
        );
        assert_eq!(r.endpoint(0), Some(endpoint));
        r.begin_sweep(SweepId(1));
        r.finish(
            r.revision(),
            stale,
            SweepId(1),
            AddressId(0),
            AddressOutcome::Failed,
        );
        assert!(!r.ssh_allowed());
    }

    #[test]
    fn manual_retry_cannot_skip_a_pending_qsh_address() {
        let epoch = ::connect::recovery_gate::RecoveryEpoch {
            connection: 7,
            network: 0,
        };
        let sweep = ::connect::recovery_gate::SweepId(1);
        let recovery = Recovery::new(EPOCH, 2);
        recovery.begin_sweep(sweep);
        recovery.retry_now();
        assert!(!recovery.ssh_allowed());
        recovery.finish(
            recovery.revision(),
            epoch,
            sweep,
            ::connect::recovery_gate::AddressId(0),
            ::connect::recovery_gate::AddressOutcome::Failed,
        );
        assert!(!recovery.ssh_allowed());
    }

    #[test]
    fn an_endpoint_update_does_not_complete_an_interrupted_sweep() {
        let recovery = Recovery::new(EPOCH, 2);
        let sweep = SweepId(1);
        recovery.begin_sweep(sweep);
        let revision = recovery.revision();
        recovery.finish(revision, EPOCH, sweep, AddressId(0), AddressOutcome::Failed);
        recovery.update_endpoints(
            EPOCH,
            vec![(AddressId(1), "127.0.0.1:60001".parse().unwrap())],
        );
        recovery.finish(revision, EPOCH, sweep, AddressId(1), AddressOutcome::Failed);
        assert!(
            !recovery.ssh_allowed(),
            "an interrupted handshake cannot complete a failed QSH sweep"
        );
    }

    #[test]
    fn an_ssh_result_changes_only_its_address_and_interrupts_udp() {
        let r = Recovery::new(EPOCH, 2);
        let before = r.revision();
        ready(&r, 1, 60001);
        assert_eq!(r.port(0), None);
        assert_eq!(r.port(1), Some(60001));
        assert!(r.interrupted(before));
        let before = r.revision();
        ready(&r, 1, 60001);
        assert!(
            !r.interrupted(before),
            "repeated SSH success must not keep aborting the same UDP handshake"
        );
    }

    #[test]
    fn cancelling_wakes_both_waiters_without_their_deadlines() {
        let r = Recovery::new(EPOCH, 1);
        r.cancel.cancel();
        let started = Instant::now();
        assert!(!r.wait_ssh(100));
        assert!(!r.wait_udp(started, r.revision()));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn a_manual_retry_skips_the_ssh_pause() {
        let r = Recovery::new(EPOCH, 1);
        r.retry_now();
        let started = Instant::now();
        assert!(r.wait_ssh(100));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn endpoint_changes_do_not_remove_the_minimum_between_udp_rounds() {
        let r = Recovery::new(EPOCH, 1);
        let revision = r.revision();
        r.update_endpoints(
            EPOCH,
            vec![(AddressId(0), "127.0.0.1:60001".parse().unwrap())],
        );
        let now = Instant::now();
        assert!(r.wait_udp(now - Duration::from_millis(900), revision));
        assert!(now.elapsed() >= Duration::from_millis(90));
    }

    #[test]
    fn dns_refresh_preserves_the_ssh_reported_port() {
        let r = Recovery::with_catalog(
            EPOCH,
            vec![AddressId(0), AddressId(1)],
            vec![(AddressId(1), "127.0.0.1:60001".parse().unwrap())],
        );
        ready(&r, 1, 60002);
        r.update_endpoints(
            EPOCH,
            vec![(AddressId(1), "127.0.0.2:60001".parse().unwrap())],
        );
        assert_eq!(r.endpoint(1), Some("127.0.0.2:60002".parse().unwrap()));
    }

    #[test]
    fn udp_rounds_have_no_pause_after_a_slow_attempt() {
        let r = Recovery::new(EPOCH, 1);
        let started = Instant::now();
        assert!(r.wait_udp(started - Duration::from_secs(10), r.revision()));
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
