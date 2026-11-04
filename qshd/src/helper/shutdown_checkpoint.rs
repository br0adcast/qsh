//! Opt-in test observation only; never cleanup or process authority.
use super::*;
use std::sync::{Mutex, TryLockError};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Serving,
    SeamEnded,
    Retiring,
    BeforePass,
    AfterPass,
    Returned,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SeamEnd {
    #[default]
    NotObserved,
    ChannelEof,
    ChannelFailed,
    AuthEof,
    AuthFailed,
    Other,
}
/// Closed projection of `HelperShutdown::first_monitor_failure`: fixed tags
/// only. Every identity, errno, exit status and signal number is discarded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum StickyKind {
    #[default]
    None,
    MissingOwner,
    Poll,
    Monitor(MonitorKind),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MonitorKind {
    Exit(ExitKind),
    Request(RequestKind),
    Shutdown,
    Send,
    Stream,
    #[cfg(any(test, not(target_os = "linux")))]
    Wait,
    #[cfg(target_os = "linux")]
    Native(NativeKind),
    DuplicateCompletion,
}
/// A native encoded value is not interpreted as a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExitKind {
    #[cfg(any(test, not(target_os = "linux")))]
    Code,
    #[cfg(any(test, not(target_os = "linux")))]
    Signal,
    #[cfg(target_os = "linux")]
    NativeEncoded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestKind {
    Exit,
    Deadline,
    Protocol,
    Receive,
    Send,
    Seal,
}
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NativeKind {
    Protocol,
    Request(RequestKind),
    Stream,
    LostAuthority,
    Signal,
}
/// Read-only latches of one actual native monitor that is not yet reaped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NativeSample {
    pub leader_exited: bool,
    pub producer_drained: bool,
    pub established: bool,
}

fn request_kind(failure: super::super::protocol::RequestDrainFailure) -> RequestKind {
    use super::super::protocol::RequestDrainFailure as F;
    match failure {
        F::Exit => RequestKind::Exit,
        F::Deadline => RequestKind::Deadline,
        F::Protocol => RequestKind::Protocol,
        F::Receive => RequestKind::Receive,
        F::Send => RequestKind::Send,
        F::Seal => RequestKind::Seal,
    }
}
fn exit_kind(status: MonitorExitStatus) -> ExitKind {
    match status {
        #[cfg(any(test, not(target_os = "linux")))]
        MonitorExitStatus::Code(_) => ExitKind::Code,
        #[cfg(any(test, not(target_os = "linux")))]
        MonitorExitStatus::Signal { .. } => ExitKind::Signal,
        #[cfg(target_os = "linux")]
        MonitorExitStatus::NativeEncoded(_) => ExitKind::NativeEncoded,
    }
}
#[cfg(target_os = "linux")]
fn native_kind(failure: super::super::monitor_owner::Failure) -> NativeKind {
    use super::super::monitor_owner::Failure as F;
    match failure {
        F::Protocol => NativeKind::Protocol,
        F::Request(failure) => NativeKind::Request(request_kind(failure)),
        F::Stream(_) => NativeKind::Stream,
        F::LostAuthority => NativeKind::LostAuthority,
        F::Signal(_, _) => NativeKind::Signal,
    }
}
fn monitor_kind(failure: MonitorFailure) -> MonitorKind {
    match failure {
        MonitorFailure::Exit(status) => MonitorKind::Exit(exit_kind(status)),
        MonitorFailure::Request(failure) => MonitorKind::Request(request_kind(failure)),
        MonitorFailure::Shutdown(_) => MonitorKind::Shutdown,
        MonitorFailure::Send(_) => MonitorKind::Send,
        MonitorFailure::Stream => MonitorKind::Stream,
        #[cfg(any(test, not(target_os = "linux")))]
        MonitorFailure::Wait(_) => MonitorKind::Wait,
        #[cfg(target_os = "linux")]
        MonitorFailure::Native(failure) => MonitorKind::Native(native_kind(failure)),
        MonitorFailure::DuplicateCompletion => MonitorKind::DuplicateCompletion,
    }
}
pub(super) fn sticky_kind(failure: Option<MonitorShutdownFailure>) -> StickyKind {
    match failure {
        None => StickyKind::None,
        Some(MonitorShutdownFailure::MissingOwner) => StickyKind::MissingOwner,
        Some(MonitorShutdownFailure::Poll(_)) => StickyKind::Poll,
        Some(MonitorShutdownFailure::Monitor(failure)) => {
            StickyKind::Monitor(monitor_kind(failure))
        }
    }
}
/// `None` means no actual unreaped native monitor exists; controlled models
/// never fabricate native latches. Sampling only reads stored latches.
fn first_unreaped_native(state: &LoopState) -> Option<NativeSample> {
    state
        .monitors
        .values()
        .find_map(|monitor| match &monitor.process {
            #[cfg(target_os = "linux")]
            MonitorProcess::Native(native) if !monitor.reaped => Some(NativeSample {
                leader_exited: native.leader_exited(),
                producer_drained: native.producer_drained(),
                established: native.established(),
            }),
            _ => None,
        })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub sequence: u64,
    pub phase: Phase,
    pub seam_end: SeamEnd,
    pub monitors: usize,
    pub retired: usize,
    pub live: usize,
    pub verifying: usize,
    pub orphans: usize,
    pub missing_completion: usize,
    pub not_reaped: usize,
    pub wait_lost: usize,
    pub monitor_failure: usize,
    pub missing_owner: usize,
    pub retired_live: usize,
    pub seal_pending: usize,
    pub seal_sent: usize,
    pub seal_failed: usize,
    pub sticky_monitor_failure: bool,
    pub cleanup_failure: bool,
    /// The first retained failure, as `observe_monitor_failures` latched it.
    /// This and `first_unreaped_native` are independent observations that may
    /// describe different monitors; the native sample is an arbitrary
    /// hash-map representative, not the chronologically first one.
    pub sticky_failure_kind: StickyKind,
    pub first_unreaped_native: Option<NativeSample>,
}
#[derive(Default)]
pub(super) struct Note {
    pub inner: Mutex<Snapshot>,
}
impl Note {
    pub fn publish(&self, phase: Phase, seam_end: Option<SeamEnd>, shutdown: &HelperShutdown) {
        let Ok(mut latest) = self.inner.try_lock() else {
            return;
        };
        let state = &shutdown.state;
        *latest = Snapshot {
            sequence: latest.sequence.saturating_add(1),
            phase,
            seam_end: seam_end.unwrap_or(latest.seam_end),
            monitors: state.monitors.len(),
            retired: state.retired.len(),
            live: state.live.len(),
            verifying: state.pending.verifying(),
            orphans: state.orphans.len(),
            missing_completion: state
                .monitors
                .values()
                .filter(|m| m.completion.is_none())
                .count(),
            not_reaped: state.monitors.values().filter(|m| !m.reaped).count(),
            wait_lost: state.monitors.values().filter(|m| m.wait_lost).count(),
            monitor_failure: state
                .monitors
                .values()
                .filter(|m| m.failure.is_some())
                .count(),
            missing_owner: state
                .retired
                .iter()
                .filter(|owner| !state.monitors.contains_key(*owner))
                .count(),
            retired_live: state
                .retired
                .iter()
                .filter(|owner| state.live.values().any(|slot| slot.owner() == **owner))
                .count(),
            seal_pending: state
                .monitors
                .values()
                .filter(|m| matches!(m.refusal_seal, Some(RefusalSeal::Pending { .. })))
                .count(),
            seal_sent: state
                .monitors
                .values()
                .filter(|m| matches!(m.refusal_seal, Some(RefusalSeal::Sent)))
                .count(),
            seal_failed: state
                .monitors
                .values()
                .filter(|m| matches!(m.refusal_seal, Some(RefusalSeal::Failed)))
                .count(),
            sticky_monitor_failure: shutdown.first_monitor_failure.is_some(),
            cleanup_failure: state.cleanup_failure.is_some(),
            sticky_failure_kind: sticky_kind(shutdown.first_monitor_failure),
            first_unreaped_native: first_unreaped_native(state),
        };
    }
    pub fn receipt(&self) -> String {
        match self.inner.try_lock() {
            Ok(snapshot) if snapshot.sequence == 0 => "checkpoint=not-observed".into(),
            Ok(snapshot) => format!("checkpoint=latest {snapshot:?}"),
            Err(TryLockError::WouldBlock) => "checkpoint=unavailable-busy".into(),
            Err(TryLockError::Poisoned(_)) => "checkpoint=unavailable-poisoned".into(),
        }
    }
}
