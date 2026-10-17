//! Shared control of continuous UDP recovery and the independent SSH fallback.
//! Only the UDP worker owns a transport connection. SSH publishes a port and
//! permission to use the process key, never a competing warm attachment.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ::connect::recovery_gate::{AddressId, AddressOutcome, RecoveryEpoch, RecoveryGate, SweepId};

use crate::climb::Setup;
use crate::{log, report};

/// Fast failures must not turn recovery into a busy loop.
pub const UDP_ROUND_INTERVAL: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(20);

pub struct Recovery {
    pub cancel: knock::Cancel,
    gate: Mutex<RecoveryGate>,
    retry_now: AtomicBool,
    revision: AtomicU64,
    ports: Mutex<Vec<Option<u16>>>,
    diagnostics: Vec<crate::trust::BackgroundDiscovery>,
}

impl Recovery {
    pub fn new(epoch: RecoveryEpoch, addresses: usize) -> Self {
        Self {
            cancel: knock::Cancel::new(),
            gate: Mutex::new(RecoveryGate::new(
                epoch,
                (0..addresses).map(AddressId).collect(),
            )),
            retry_now: AtomicBool::new(false),
            revision: AtomicU64::new(0),
            ports: Mutex::new(vec![None; addresses]),
            diagnostics: (0..addresses)
                .map(|_| crate::trust::BackgroundDiscovery::default())
                .collect(),
        }
    }

    pub fn begin_sweep(&self, sweep: SweepId) {
        self.gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .begin_sweep(sweep);
    }

    /// Only complete, current QSH results may admit the independent SSH worker.
    pub fn finish(
        &self,
        revision: u64,
        epoch: RecoveryEpoch,
        sweep: SweepId,
        addr: AddressId,
        outcome: AddressOutcome,
    ) {
        if self.interrupted(revision) {
            return;
        }
        let decision = self
            .gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish(epoch, sweep, addr, outcome);
        if decision == ::connect::recovery_gate::GateDecision::AllowSsh {
            log::log("recovery: full QSH sweep failed; SSH permitted");
        }
    }

    pub fn ssh_allowed(&self) -> bool {
        !self.cancel.is_cancelled()
            && self
                .gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .ssh_allowed()
    }

    pub fn retry_now(&self) {
        self.retry_now.store(true, Ordering::SeqCst);
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::SeqCst)
    }

    pub fn port(&self, addr: usize) -> Option<u16> {
        self.ports.lock().unwrap_or_else(|e| e.into_inner())[addr]
    }

    pub fn discovery(
        &self,
        addr: usize,
        source: Arc<dyn crate::trust::Discover + Send + Sync>,
    ) -> crate::trust::RecoveryDiscovery<'_> {
        crate::trust::RecoveryDiscovery {
            pending: &self.diagnostics[addr],
            source,
        }
    }

    /// Wake the sole UDP owner for a new endpoint or authorization. Repeated
    /// success at that endpoint must not keep interrupting its handshake.
    fn ready(&self, addr: usize, port: u16) {
        let mut ports = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        if ports[addr] != Some(port) {
            ports[addr] = Some(port);
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn interrupted(&self, revision: u64) -> bool {
        self.cancel.is_cancelled() || self.revision() != revision
    }

    /// Returns false on cancellation. A new SSH result also wakes UDP.
    pub fn wait_udp(&self, started: Instant, revision: u64) -> bool {
        while started.elapsed() < UDP_ROUND_INTERVAL && !self.interrupted(revision) {
            std::thread::sleep(POLL);
        }
        !self.cancel.is_cancelled()
    }

    /// The unchanged exponential pauses apply only to SSH rounds.
    fn wait_ssh(&self, failed: u32) -> bool {
        let until = Instant::now() + ::connect::reconnect::pause_after(failed);
        while Instant::now() < until && !self.cancel.is_cancelled() {
            if self.retry_now.swap(false, Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(POLL);
        }
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
                while !recovery.ssh_allowed() {
                    if recovery.cancel.is_cancelled() {
                        return;
                    }
                    std::thread::sleep(POLL);
                }
                let order: Vec<_> = (0..addresses.len())
                    .filter(|&i| i == first)
                    .chain((0..addresses.len()).filter(|&i| i != first))
                    .collect();
                let mut rounds = 0u32;
                loop {
                    recovery.retry_now.store(false, Ordering::SeqCst);
                    for &i in &order {
                        if !recovery.ssh_allowed() {
                            return;
                        }
                        let address = &addresses[i];
                        let Some(route) = &address.ssh else { continue };
                        log::shown(&report::trying_ssh(&address.host, route));
                        match setup.bring_up(address, &recovery.cancel) {
                            Ok(ready) if !recovery.cancel.is_cancelled() => {
                                let port = ready.port_for(address.qsh_port);
                                log::shown(&report::qshd_ready(
                                    &address.host,
                                    address.qsh_port,
                                    port,
                                ));
                                if let Some(warning) = ready.warning {
                                    log::shown(&report::qshd_warning(&address.host, &warning));
                                }
                                recovery.ready(i, port);
                            }
                            Ok(_) => return,
                            Err(crate::ssh_step::SshStepError::NeedsPrompt) => {
                                log::log(&format!(
                                    "recovery: ssh address {i}: NeedsPrompt; UDP keeps trying"
                                ));
                            }
                            Err(why) => log::log(&format!("recovery: ssh address {i}: {why:?}")),
                        }
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

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: RecoveryEpoch = RecoveryEpoch {
        connection: 7,
        network: 0,
    };

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
        recovery.ready(1, 60001);
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
        r.ready(1, 60001);
        assert_eq!(r.port(0), None);
        assert_eq!(r.port(1), Some(60001));
        assert!(r.interrupted(before));
        let before = r.revision();
        r.ready(1, 60001);
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
    fn udp_rounds_have_no_pause_after_a_slow_attempt() {
        let r = Recovery::new(EPOCH, 1);
        let started = Instant::now();
        assert!(r.wait_udp(started - Duration::from_secs(10), r.revision()));
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
