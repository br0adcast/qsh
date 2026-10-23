// Global stopping reuses the original helper's single-threaded child custody.
#[cfg(target_os = "linux")]
struct WorkerRootView(crate::process_scope::scope::ReservedRoot);
#[cfg(target_os = "linux")]
impl crate::process_scope::adoption::Roots for WorkerRootView {
    fn classify(&mut self, pid: u32) -> crate::process_scope::adoption::Reservation {
        use crate::process_scope::{adoption::Reservation, scope::ReservedRoot};
        match self.0 {
            ReservedRoot::Owned(root) if root.get() == pid => Reservation::Reserved,
            ReservedRoot::Lost => Reservation::Unknown,
            _ => Reservation::Other,
        }
    }
    fn state(&self) -> crate::process_scope::adoption::RootState {
        use crate::process_scope::{adoption::RootState, scope::ReservedRoot};
        match self.0 {
            ReservedRoot::Owned(_) => RootState::Active,
            ReservedRoot::Released => RootState::Settled,
            ReservedRoot::Lost => RootState::Unknown,
        }
    }
}
#[cfg(target_os = "linux")]
fn advance_adoption(
    state: &LoopState,
    worker: crate::process_scope::scope::ReservedRoot,
    owner: &mut crate::process_scope::adoption::Adoption,
    ops: &mut impl crate::process_scope::adoption::AdoptionOps,
) -> crate::process_scope::adoption::Progress {
    if !state.stopping || !monitor_and_verifier_domains_settled(state) {
        return crate::process_scope::adoption::Progress::Pending;
    }
    owner.step(ops, &mut WorkerRootView(worker))
}

#[cfg(target_os = "linux")]
fn monitor_and_verifier_domains_settled(state: &LoopState) -> bool {
    state.pending.verifying() == 0
        && state.orphans.is_empty()
        && state
            .retired
            .iter()
            .all(|owner| state.monitors.contains_key(owner))
        && state
            .live
            .values()
            .all(|slot| state.monitors.contains_key(&slot.owner()))
        && state.monitors.values().all(|monitor| {
            // Only actual NativeMonitor completion includes its authenticated
            // original-producer post-exit-empty fence and final exclusive wait.
            matches!(monitor.process, MonitorProcess::Native(_))
                && monitor.reaped
                && !monitor.wait_lost
        })
}

#[cfg(target_os = "linux")]
pub(super) struct AdoptionRuntime {
    owner: crate::process_scope::adoption::Adoption,
    ops: crate::process_scope::adoption::native::NativeOps,
    complete: bool,
}
#[cfg(target_os = "linux")]
impl AdoptionRuntime {
    pub(super) fn prepare() -> anyhow::Result<Self> {
        let (owner, ops) = crate::process_scope::adoption::native::NativeOps::prepare()
            .map_err(anyhow::Error::msg)?;
        Ok(Self {
            owner,
            ops,
            complete: false,
        })
    }
    fn advance(&mut self, state: &LoopState, root: crate::process_scope::scope::ReservedRoot) {
        self.complete = matches!(
            advance_adoption(state, root, &mut self.owner, &mut self.ops),
            crate::process_scope::adoption::Progress::Complete
        );
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default, PartialEq, Eq)]
struct ChannelReceiptDebt {
    cleanup: usize,
    exit: usize,
}
#[cfg(target_os = "linux")]
impl ChannelReceiptDebt {
    fn from_state(state: &LoopState) -> Self {
        let mut debt = Self::default();
        for slot in state.live.values() {
            match slot {
                ChannelSlot::Starting(_) | ChannelSlot::Cleaning(_) => {
                    debt.cleanup = debt.cleanup.saturating_add(1);
                }
                ChannelSlot::Running(_) => {
                    debt.cleanup = debt.cleanup.saturating_add(1);
                    debt.exit = debt.exit.saturating_add(1);
                }
                ChannelSlot::ReapedRunning(_) => {
                    // This exact cleanup receipt is already held. Only the
                    // missing exit/forwarded outcome remains unreported.
                    debt.exit = debt.exit.saturating_add(1);
                }
            }
        }
        debt
    }
    fn any(&self) -> bool {
        self.cleanup != 0 || self.exit != 0
    }
}

/// Full physical helper-child proof, with independent logical failure evidence.
/// No successful manager/PAM receipt is reconstructed from process termination.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct HelperPhysicalOutcome {
    worker: WorkerPhysicalOutcome,
    pam_received: PamCompletion,
    missing_pam: usize,
    channel_receipts: ChannelReceiptDebt,
    pending_requests: bool,
    monitor_failure: Option<MonitorShutdownFailure>,
    adoption_failed: bool,
    forced_worker: bool,
    required_publication: Option<RequiredPublicationFailure>,
}
#[cfg(target_os = "linux")]
impl HelperPhysicalOutcome {
    fn failed(&self) -> bool {
        self.worker.native_exit != 0
            || self.worker.first_failure.is_some()
            || !self.worker.terminal_received
            || self.worker.signal_failure.is_some()
            || !self.pam_received.succeeded()
            || self.missing_pam != 0
            || self.channel_receipts.any()
            || self.pending_requests
            || self.monitor_failure.is_some()
            || self.adoption_failed
            || self.forced_worker
            || self.required_publication.is_some()
    }
}

#[cfg(target_os = "linux")]
impl HelperShutdown {
    fn progress_adopted_children(&mut self) {
        if self.adoption.is_none()
            || !self.state.stopping
            || !monitor_and_verifier_domains_settled(&self.state)
        {
            return;
        }
        let Some(worker) = self.worker.as_mut() else {
            return;
        };
        let root = worker.owner.reserved_root();
        // A retained live slot needs a receipt from its now-dead native monitor.
        // The authenticated post-exit-empty fence makes that loss irrevocable.
        // PAM absence alone does not prevent a worker's cooperative join.
        // A failed required publication independently makes a cooperative
        // result unusable; a lost cleanup packet can otherwise strand the
        // worker after local physical slots were correctly retired.
        let debt = ChannelReceiptDebt::from_state(&self.state);
        if !self.forced_worker
            && (debt.any() || self.state.required_publication.is_some())
            && worker.stop_attempted
            && matches!(root, crate::process_scope::scope::ReservedRoot::Owned(_))
        {
            // The ordinary pump already made its bounded cooperative Stop
            // attempt in this pass. Do not send a second frame here.
            worker.record(if let Some(failure) = self.state.required_publication {
                ParentFailure::RequiredPublication(failure)
            } else if debt.cleanup != 0 {
                ParentFailure::RequiredCleanupLost
            } else {
                ParentFailure::RequiredExitLost
            });
            worker.owner.force_failed_cleanup();
            self.forced_worker = true;
        }
        self.adoption.as_mut().unwrap().advance(&self.state, root);
    }

    fn physical_helper_outcome(&self, diagnostics_settled: bool) -> Option<HelperPhysicalOutcome> {
        let adoption = self.adoption.as_ref()?;
        let worker = self.worker.as_ref()?;
        if !self.state.stopping
            || !worker.settled()
            || !adoption.complete
            || !monitor_and_verifier_domains_settled(&self.state)
            || self.channels_open
            || self.auth_open
            || !diagnostics_settled
        {
            return None;
        }
        let mut pam_received = self.state.pam_cleanup;
        let mut missing_pam = 0usize;
        for monitor in self.state.monitors.values() {
            match monitor.completion {
                Some(receipt) => pam_received.merge(receipt),
                None => missing_pam = missing_pam.saturating_add(1),
            }
        }
        // This report consumes final stopped state at function return. It is
        // never a serving-mode refund or a fabricated channel cleanup event.
        Some(HelperPhysicalOutcome {
            worker: worker.physical_outcome(),
            pam_received,
            missing_pam,
            channel_receipts: ChannelReceiptDebt::from_state(&self.state),
            pending_requests: !self.state.pending.is_empty(),
            monitor_failure: self.first_monitor_failure,
            adoption_failed: adoption.owner.failed(),
            forced_worker: self.forced_worker,
            required_publication: self.state.required_publication,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
impl HelperShutdown {
    // Existing component fixtures prove worker physical custody only. Production
    // owned entry requires AdoptionRuntime and cannot select this test-only tail.
    fn component_worker_outcome(&self, diagnostics_settled: bool) -> Option<WorkerPhysicalOutcome> {
        let worker = self.worker.as_ref()?;
        if self.adoption.is_none()
            && self.state.stopping
            && worker.settled()
            && !self.channels_open
            && !self.auth_open
            && diagnostics_settled
            && self.state.monitors.is_empty()
            && self.state.retired.is_empty()
            && self.state.live.is_empty()
            && self.verifications_settled()
        {
            Some(worker.physical_outcome())
        } else {
            None
        }
    }
}
