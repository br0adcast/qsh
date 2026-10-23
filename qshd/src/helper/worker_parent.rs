// One worker domain inside the helper's existing live shutdown owner.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum ParentFailure {
    Channel,
    Auth,
    RequiredCleanupLost,
    RequiredExitLost,
    Setup(i32),
    Poll(i32),
    Worker(super::worker_owner::WorkerFailure),
    Send(super::worker_protocol::Fault),
}

/// Exact worker physical settlement only. Cooperative producer/role completion
/// is not reconstructed when the private final receipt was lost.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct WorkerPhysicalOutcome {
    first_failure: Option<ParentFailure>,
    signal_failure: Option<(i32, i32)>,
    terminal_received: bool,
    native_exit: i32,
}

#[cfg(target_os = "linux")]
struct WorkerDomain {
    owner: super::worker_owner::WorkerOwner,
    pending: Option<super::worker_control::PendingFrame>,
    stopping: bool,
    stop_queued: bool,
    stop_reason: Option<super::worker_protocol::StopReason>,
    stop_attempted: bool,
    native_complete: bool,
    native_exit: Option<i32>,
    first_failure: Option<ParentFailure>,
    signal_failure: Option<(i32, i32)>,
    setup_failed: bool,
}

#[cfg(target_os = "linux")]
impl WorkerDomain {
    fn new(owner: super::worker_owner::WorkerOwner) -> Self {
        Self {
            owner,
            pending: None,
            stopping: false,
            stop_queued: false,
            stop_reason: None,
            stop_attempted: false,
            native_complete: false,
            native_exit: None,
            first_failure: None,
            signal_failure: None,
            setup_failed: false,
        }
    }
    fn record(&mut self, failure: ParentFailure) {
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
            // Match explicitly to preserve bounded native/protocol diagnostics.
            let detail = match failure {
                ParentFailure::Channel => "channel seam closed or failed".to_string(),
                ParentFailure::Auth => "authentication seam closed or failed".to_string(),
                ParentFailure::RequiredExitLost => "native monitor ended after cleanup but without required exit/forwarded outcome".to_string(),
                ParentFailure::RequiredCleanupLost => "native monitor ended without required shell cleanup; worker drain cannot complete".to_string(),
                ParentFailure::Setup(errno) => format!("seam setup failed ({errno})"),
                ParentFailure::Poll(errno) => format!("poll failed ({errno})"),
                ParentFailure::Worker(failure) => format!("worker cleanup: {failure:?}"),
                ParentFailure::Send(failure) => format!("private Stop publication: {failure:?}"),
            };
            crate::log::error("helper", &format!("owned shutdown: {detail}"));
        }
    }
    fn record_seam_end(&mut self, end: Next, failure: ParentFailure) {
        match end {
            Next::Eof
                if self.stop_reason == Some(super::worker_protocol::StopReason::Requested) => {}
            Next::Eof | Next::Failed => self.record(failure),
            Next::Continue => unreachable!("live seam is not an end event"),
        }
    }
    fn request_stop(&mut self, reason: super::worker_protocol::StopReason) {
        use super::worker_protocol::StopReason;
        self.stop_reason.get_or_insert(reason);
        self.stopping = true;
        if self.native_complete || self.owner.terminal_received() {
            // Exact physical completion independently forbids more Stop sends;
            // it does not reconstruct a missing cooperative producer fence.
            // A final receipt also makes another Stop unnecessary.
            self.pending = None;
            return;
        }
        if !self.stop_queued {
            self.stop_queued = true;
            let code = match reason {
                StopReason::Requested => 0,
                StopReason::ChannelLost => 1,
                StopReason::AuthLost => 2,
                StopReason::NoncePoolLost => 3,
                StopReason::RequiredTellLost => 4,
                StopReason::Protocol => 5,
            };
            self.pending = Some(
                super::worker_control::PendingFrame::new(&[1, code])
                    .expect("fixed private Stop record"),
            );
        }
    }
    fn send_stop(&mut self) {
        let Some(pending) = self.pending.as_mut() else {
            return;
        };
        self.stop_attempted = true;
        match self.owner.send_stop(pending) {
            Ok(super::worker_control::Sent::Complete) => {
                self.pending = None;
            }
            Ok(super::worker_control::Sent::Blocked | super::worker_control::Sent::Yielded) => {}
            Err(failure) => {
                self.pending = None;
                self.record(ParentFailure::Send(failure));
            }
        }
    }
    fn advance(&mut self) {
        use crate::process_scope::scope::Progress;
        if self.native_complete {
            return;
        }
        let progress = self.owner.poll(Instant::now());
        if let Some(failure) = progress.failure {
            self.record(ParentFailure::Worker(failure));
            self.stopping = true;
        }
        if let Some((signal, errno)) = progress.signal_failure {
            if self.signal_failure.is_none() {
                self.signal_failure = Some((signal, errno));
                crate::log::error(
                    "helper",
                    &format!("owned worker signal failed: signal={signal}, errno={errno}"),
                );
            }
        }
        if progress.receipt.is_some() || matches!(progress.native, Progress::Complete(_)) {
            self.stopping = true;
        }
        if let Progress::Complete(code) = progress.native {
            self.native_exit = Some(code);
            self.native_complete = true;
        }
        if self.native_complete {
            self.pending = None;
        }
    }
    fn settled(&self) -> bool {
        // Missing cooperative evidence stays failed, but cannot keep an exactly
        // proved dead physical domain alive. Unknown native authority never settles.
        self.native_complete
    }
    fn physical_outcome(&self) -> WorkerPhysicalOutcome {
        assert!(self.settled());
        WorkerPhysicalOutcome {
            first_failure: self.first_failure,
            signal_failure: self.signal_failure,
            terminal_received: self.owner.terminal_received(),
            native_exit: self
                .native_exit
                .expect("settled worker retains exact native exit"),
        }
    }
}

#[cfg(target_os = "linux")]
fn begin_owned_stop(
    channels: &UnixStream,
    state: &mut LoopState,
    worker: &mut WorkerDomain,
    reason: super::worker_protocol::StopReason,
) {
    worker.request_stop(reason);
    if !state.stopping {
        state.stopping = true;
        // Keep every monitor's readable half and actual receipt/wait owner.
        let owners: Vec<_> = state.monitors.keys().copied().collect();
        for owner in owners {
            retire_login(channels, state, owner);
        }
    }
}
