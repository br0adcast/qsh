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
