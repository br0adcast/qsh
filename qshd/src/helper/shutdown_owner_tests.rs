// First ownership/report increment. Not connected to the service shutdown path yet.
mod pam40_shutdown_owner {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Phase {
        Serving,
        Stopping,
        Joined,
        Unresolved,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum WorkerWait {
        Pending,
        Exited(i32),
        Signaled(i32),
        Unknown(i32),
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum WorkerDrain {
        Complete,
        Failed,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct QualifiedDomains {
        verification: bool,
        monitor_custody: bool,
        worker: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        Unqualified,
        Capacity,
        MissingMonitor,
        Monitor(MonitorFailure),
        WorkerWait(i32),
        WorkerDrain,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Outstanding {
        monitors: u16,
        shell_slots: u16,
        verification: u16,
        worker: bool,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Report {
        phase: Phase,
        // None explicitly means that the admission/count invariant failed.
        outstanding: Option<Outstanding>,
        pam: PamCompletion,
        worker: WorkerWait,
        worker_drain: Option<WorkerDrain>,
        first_failure: Option<Failure>,
    }

    // Owns the actual existing tables and socket handles, never copies a registry.
    struct ShutdownOwner {
        state: LoopState,
        stopping: bool,
        qualified: QualifiedDomains,
        worker: WorkerWait,
        worker_drain: Option<WorkerDrain>,
    }

    impl ShutdownOwner {
        fn new(state: LoopState) -> Self {
            Self {
                state,
                stopping: false,
                qualified: QualifiedDomains::default(),
                worker: WorkerWait::Pending,
                worker_drain: None,
            }
        }

        fn begin_stop(&mut self) {
            self.stopping = true;
        }

        fn report(&self) -> Report {
            // Project retained ownership only. Never remove a seam or release admission.
            let mut pam = self.state.pam_cleanup;
            let mut first_failure = None;
            for monitor in self.state.monitors.values() {
                if let Some(result) = monitor.completion {
                    pam.merge(result);
                }
                if let Some(failure) = monitor.failure {
                    first_failure.get_or_insert(Failure::Monitor(failure));
                }
            }
            let missing_monitors = self
                .state
                .retired
                .iter()
                .filter(|owner| !self.state.monitors.contains_key(owner))
                .count();
            if missing_monitors != 0 {
                first_failure.get_or_insert(Failure::MissingMonitor);
            }
            let monitors = self.state.monitors.len().checked_add(missing_monitors);
            let verification = self
                .state
                .pending
                .verifying()
                .checked_add(self.state.orphans.len());
            let counts = (|| {
                let verification = verification?;
                let monitors = monitors?;
                if monitors > MAX_LOGINS
                    || self.state.live.len() > MAX_LOGINS * MAX_CHANNELS_PER_LOGIN
                    || verification > MAX_VERIFYING
                {
                    return None;
                }
                Some(Outstanding {
                    monitors: u16::try_from(monitors).ok()?,
                    shell_slots: u16::try_from(self.state.live.len()).ok()?,
                    verification: u16::try_from(verification).ok()?,
                    worker: matches!(self.worker, WorkerWait::Pending | WorkerWait::Unknown(_)),
                })
            })();
            if counts.is_none() {
                first_failure.get_or_insert(Failure::Capacity);
            }
            if let WorkerWait::Unknown(error) = self.worker {
                first_failure.get_or_insert(Failure::WorkerWait(error));
            }
            if !(self.qualified.verification
                && self.qualified.monitor_custody
                && self.qualified.worker)
            {
                first_failure.get_or_insert(Failure::Unqualified);
            }
            // A failed drain receipt is a known completed operation, not a lost owner.
            let unresolved = first_failure.is_some();
            if self.worker_drain == Some(WorkerDrain::Failed) {
                first_failure.get_or_insert(Failure::WorkerDrain);
            }
            let all_joined = counts.is_some_and(|counts| {
                counts.monitors == 0
                    && counts.shell_slots == 0
                    && counts.verification == 0
                    && !counts.worker
            }) && self.worker_drain.is_some();
            Report {
                phase: if !self.stopping {
                    Phase::Serving
                } else if unresolved {
                    Phase::Unresolved
                } else if all_joined {
                    Phase::Joined
                } else {
                    Phase::Stopping
                },
                outstanding: counts,
                pam,
                worker: self.worker,
                worker_drain: self.worker_drain,
                first_failure,
            }
        }
    }

    fn qualified_empty_owner() -> ShutdownOwner {
        let mut owner = ShutdownOwner::new(empty_state());
        owner.qualified = QualifiedDomains {
            verification: true,
            monitor_custody: true,
            worker: true,
        };
        owner.begin_stop();
        owner
    }

    #[test]
    fn pam40_report_cannot_join_unqualified_domains_even_when_empty() {
        let mut owner = ShutdownOwner::new(empty_state());
        assert_eq!(owner.report().phase, Phase::Serving);
        owner.begin_stop();
        owner.worker = WorkerWait::Exited(0);
        owner.worker_drain = Some(WorkerDrain::Complete);
        assert_eq!(owner.report().phase, Phase::Unresolved);
        assert_eq!(owner.report().first_failure, Some(Failure::Unqualified));
    }

    #[test]
    fn pam40_report_requires_actual_worker_wait_and_drain_independently() {
        let mut owner = qualified_empty_owner();
        assert_eq!(owner.report().phase, Phase::Stopping);
        owner.worker = WorkerWait::Exited(0);
        assert_eq!(
            owner.report().phase,
            Phase::Stopping,
            "exit is not a drain receipt"
        );
        owner.worker_drain = Some(WorkerDrain::Complete);
        assert_eq!(owner.report().phase, Phase::Joined);
        owner.worker = WorkerWait::Pending;
        assert_eq!(
            owner.report().phase,
            Phase::Stopping,
            "receipt is not a wait"
        );
        owner.worker = WorkerWait::Unknown(nix::libc::ECHILD);
        assert_eq!(owner.report().phase, Phase::Unresolved);
        assert_eq!(
            owner.report().first_failure,
            Some(Failure::WorkerWait(nix::libc::ECHILD))
        );
        // Independent physical failed-drain case: wait authority lost above is
        // permanent in the future native adapter, never repaired by a new verdict.
        let mut owner = qualified_empty_owner();
        owner.worker = WorkerWait::Signaled(nix::libc::SIGTERM);
        owner.worker_drain = Some(WorkerDrain::Failed);
        let report = owner.report();
        assert_eq!(
            report.phase,
            Phase::Joined,
            "physical wait and failed drain are distinct"
        );
        assert_eq!(report.first_failure, Some(Failure::WorkerDrain));
    }

    #[test]
    fn pam40_report_retains_live_receipt_route_and_failed_pam_before_wait() {
        let (state, monitor_owner, peer) = pam40_controlled_retiring_monitor(false);
        let mut owner = qualified_empty_owner();
        owner.state = state;
        owner.worker = WorkerWait::Exited(0);
        owner.worker_drain = Some(WorkerDrain::Complete);
        let result = PamCompletion::Finished {
            close_session: super::super::super::pam_completion::PamStep::Attempted(17),
            delete_cred: super::super::super::pam_completion::PamStep::Attempted(0),
            end: super::super::super::pam_completion::PamStep::Attempted(0),
        };
        owner
            .state
            .monitors
            .get_mut(&monitor_owner)
            .unwrap()
            .completion = Some(result);
        let report = owner.report();
        assert_eq!(report.phase, Phase::Stopping);
        assert_eq!(
            report.pam, result,
            "pending wait cannot hide known failed PAM"
        );
        assert_eq!(report.outstanding.unwrap().monitors, 1);
        assert!(owner.state.retired.contains(&monitor_owner));
        channel::send(&peer, b"still owned", None).unwrap();
        assert_eq!(
            channel::recv(owner.state.monitors[&monitor_owner].seam())
                .unwrap()
                .unwrap()
                .0,
            b"still owned"
        );
        owner.state.monitors.get_mut(&monitor_owner).unwrap().reaped = true;
        finish_retired(&mut owner.state, monitor_owner);
        let report = owner.report();
        assert_eq!(report.phase, Phase::Joined);
        assert!(
            !report.pam.succeeded(),
            "actual wait does not erase failed cleanup"
        );
    }

    #[test]
    fn pam40_report_preserves_unresolved_monitor_and_rejects_count_overflow() {
        let (state, monitor_owner, _peer) = pam40_controlled_retiring_monitor(true);
        let mut owner = qualified_empty_owner();
        owner.state = state;
        owner
            .state
            .monitors
            .get_mut(&monitor_owner)
            .unwrap()
            .failure = Some(MonitorFailure::Stream);
        assert_eq!(owner.report().phase, Phase::Unresolved);
        assert_eq!(
            owner.report().first_failure,
            Some(Failure::Monitor(MonitorFailure::Stream))
        );
        owner.state.monitors.clear();
        owner.state.retired.clear();
        owner.state.orphans.resize(65, Pid::this());
        let report = owner.report();
        assert_eq!(report.phase, Phase::Unresolved);
        assert_eq!(
            report.outstanding, None,
            "overflow is explicit, never truncated"
        );
        assert_eq!(report.first_failure, Some(Failure::Capacity));
    }
    #[test]
    fn pam40_report_cannot_erase_retired_admission_without_monitor_receipt() {
        let (state, monitor_owner, _peer) = pam40_controlled_retiring_monitor(true);
        let mut owner = qualified_empty_owner();
        owner.state = state;
        owner.worker = WorkerWait::Exited(0);
        owner.worker_drain = Some(WorkerDrain::Complete);
        owner.state.monitors.remove(&monitor_owner);
        let report = owner.report();
        assert_eq!(report.phase, Phase::Unresolved);
        assert_eq!(report.outstanding.unwrap().monitors, 1);
        assert_eq!(report.first_failure, Some(Failure::MissingMonitor));
        assert!(owner.state.retired.contains(&monitor_owner));
    }
}
