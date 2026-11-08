//! Confirmed modern destruction: exact generation, candidate and retained exit.
use daemon_bootstrap_protocol::{
    BusyDaemonIdentity, CandidateImageIdentity, DestructiveRestartConsent,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcome {
    ExactExit,
    Refused,
    Uncertain,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitEvidence {
    Pending,
    Exited,
    Unknown,
}
trait Witness {
    fn observe(&mut self) -> ExitEvidence;
}
enum Dispatch {
    Refused,
    Sent,
}
trait Peer {
    fn info(&mut self) -> Result<BusyDaemonIdentity, ()>;
    fn prepare(&mut self, consent: &DestructiveRestartConsent) -> Result<[u8; 16], ()>;
    /// A transport/malformed ACK failure after a possible write is Sent too.
    fn commit(&mut self, receipt: [u8; 16], consent: &DestructiveRestartConsent) -> Dispatch;
}
fn run<W: Witness>(
    peer: &mut impl Peer,
    consent: &DestructiveRestartConsent,
    candidate: &CandidateImageIdentity,
    acquire: impl FnOnce(u32) -> Result<W, ()>,
    mut wait: impl FnMut() -> bool,
) -> RestartOutcome {
    if candidate != &consent.candidate
        || !candidate.valid()
        || consent.identity.generation.is_none()
    {
        return RestartOutcome::Refused;
    }
    if peer.info().as_ref() != Ok(&consent.identity) {
        return RestartOutcome::Refused;
    }
    let Ok(mut witness) = acquire(consent.identity.pid) else {
        return RestartOutcome::Refused;
    };
    if peer.info().as_ref() != Ok(&consent.identity) {
        return RestartOutcome::Refused;
    }
    if witness.observe() != ExitEvidence::Pending {
        return RestartOutcome::Refused;
    }
    let Ok(receipt) = peer.prepare(consent) else {
        return RestartOutcome::Refused;
    };
    // PREPARE grants no priority and may take time. Recheck the original
    // retained OS/image witness immediately before dispatching COMMIT.
    if witness.observe() != ExitEvidence::Pending {
        return RestartOutcome::Refused;
    }
    if matches!(peer.commit(receipt, consent), Dispatch::Refused) {
        return RestartOutcome::Refused;
    }
    loop {
        match witness.observe() {
            ExitEvidence::Exited => return RestartOutcome::ExactExit,
            ExitEvidence::Unknown => return RestartOutcome::Uncertain,
            ExitEvidence::Pending if !wait() => return RestartOutcome::Uncertain,
            ExitEvidence::Pending => {}
        }
    }
}
struct ControlPeer<'a>(&'a crate::control::EnsureLock);
impl Peer for ControlPeer<'_> {
    fn info(&mut self) -> Result<BusyDaemonIdentity, ()> {
        use rand_core::RngCore;
        let mut challenge = [0; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| ())?;
        let crate::control::ControlReply::Answered(line) = self
            .0
            .request(&crate::control::ControlRequest::DestructiveRestartInfo(
                challenge,
            ))
            .map_err(|_| ())?
        else {
            return Err(());
        };
        let response: crate::control::DestructiveRestartInfoResponse =
            serde_json::from_str(&line).map_err(|_| ())?;
        if response.schema != 1
            || response.challenge != hex::encode(challenge)
            || response.capability != "conditional-stop-receipt-v1"
            || !response.identity.valid()
            || response.identity.generation.is_none()
        {
            return Err(());
        }
        Ok(response.identity)
    }
    fn prepare(&mut self, consent: &DestructiveRestartConsent) -> Result<[u8; 16], ()> {
        let crate::control::ControlReply::Answered(line) = self
            .0
            .request(&crate::control::ControlRequest::PrepareDestructiveStop(
                consent.clone(),
            ))
            .map_err(|_| ())?
        else {
            return Err(());
        };
        let response: crate::control::DestructivePrepareResponse =
            serde_json::from_str(&line).map_err(|_| ())?;
        match response {
            crate::control::DestructivePrepareResponse::Prepared {
                receipt,
                consent: bound,
            } if &bound == consent => hex::decode(receipt)
                .map_err(|_| ())?
                .try_into()
                .map_err(|_| ()),
            _ => Err(()),
        }
    }
    fn commit(&mut self, receipt: [u8; 16], consent: &DestructiveRestartConsent) -> Dispatch {
        // Any failure after issuing this single RPC is possibly committed.
        // Do not retry or translate an unparseable answer into safe refusal.
        let reply = self
            .0
            .request(&crate::control::ControlRequest::CommitDestructiveStop {
                receipt,
                consent: consent.clone(),
            });
        dispatch_reply(reply)
    }
}
fn dispatch_reply(reply: anyhow::Result<crate::control::ControlReply>) -> Dispatch {
    if let Ok(crate::control::ControlReply::Answered(line)) = reply {
        if let Ok(crate::control::DestructiveCommitResponse::Refused { .. }) =
            serde_json::from_str(&line)
        {
            return Dispatch::Refused;
        }
    }
    // Even a valid committed ACK does not prove exit. Malformed/lost replies
    // supply less certainty; retain their common conservative dispatch state.
    Dispatch::Sent
}
#[cfg(target_os = "linux")]
impl Witness for crate::process_scope::ObservedProcess {
    fn observe(&mut self) -> ExitEvidence {
        match self.observe_native() {
            crate::process_scope::Evidence::Pending => ExitEvidence::Pending,
            crate::process_scope::Evidence::Exited => ExitEvidence::Exited,
            crate::process_scope::Evidence::Unknown => ExitEvidence::Unknown,
        }
    }
}
#[cfg(target_os = "macos")]
impl Witness for crate::darwin_process_scope::NativeObserved {
    fn observe(&mut self) -> ExitEvidence {
        match self.observe() {
            crate::darwin_process_scope::ObservationEvidence::Pending => ExitEvidence::Pending,
            crate::darwin_process_scope::ObservationEvidence::Exited => ExitEvidence::Exited,
            crate::darwin_process_scope::ObservationEvidence::Unknown => ExitEvidence::Unknown,
        }
    }
}
#[cfg(target_os = "linux")]
fn acquire_observer(pid: u32) -> Result<crate::process_scope::ObservedProcess, ()> {
    crate::process_scope::ObservedProcess::acquire_native(pid).map_err(|_| ())
}
#[cfg(target_os = "macos")]
fn acquire_observer(pid: u32) -> Result<crate::darwin_process_scope::NativeObserved, ()> {
    crate::darwin_process_scope::NativeObserved::acquire(pid).map_err(|_| ())
}
/// No signal or PID-reopen authority escapes this helper. Candidate identity
/// must already name the actual executing helper, never a later pathname.
pub fn interrupt_selected(
    transaction: &crate::control::EnsureLock,
    consent: &DestructiveRestartConsent,
    candidate: &CandidateImageIdentity,
) -> RestartOutcome {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Existing Darwin proc_pidpath -> open is not an executing-byte
        // binding. Keep this operation refused before any peer mutation until
        // an immutable candidate-artifact profile is independently qualified.
        if !cfg!(target_os = "linux") {
            return RestartOutcome::Refused;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        run(
            &mut ControlPeer(transaction),
            consent,
            candidate,
            acquire_observer,
            || {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                std::thread::sleep(remaining.min(std::time::Duration::from_millis(20)));
                true
            },
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Darwin proc_pidpath -> open does not bind executing candidate bytes.
        // An exit observer alone cannot qualify complete destructive support.
        let _ = (transaction, consent, candidate);
        RestartOutcome::Refused
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use daemon_bootstrap_protocol::{BusyAttemptId, DestructiveRestartAction};
    use std::collections::VecDeque;
    fn binding() -> DestructiveRestartConsent {
        DestructiveRestartConsent {
            attempt: BusyAttemptId::from_bytes([1; 16]),
            identity: BusyDaemonIdentity {
                version: "0.6.0-rc1".into(),
                build: 1,
                checksum: "ab".repeat(32),
                pid: 42,
                generation: Some("cd".repeat(16)),
            },
            candidate: CandidateImageIdentity {
                build: 2,
                checksum: "ef".repeat(32),
            },
            action: DestructiveRestartAction::StopAndRestart,
        }
    }
    struct Fake {
        info: VecDeque<Result<BusyDaemonIdentity, ()>>,
        prepared: usize,
        committed: usize,
        refuse: bool,
    }
    impl Peer for Fake {
        fn info(&mut self) -> Result<BusyDaemonIdentity, ()> {
            self.info.pop_front().unwrap()
        }
        fn prepare(&mut self, _: &DestructiveRestartConsent) -> Result<[u8; 16], ()> {
            self.prepared += 1;
            Ok([3; 16])
        }
        fn commit(&mut self, _: [u8; 16], _: &DestructiveRestartConsent) -> Dispatch {
            self.committed += 1;
            if self.refuse {
                Dispatch::Refused
            } else {
                Dispatch::Sent
            }
        }
    }
    struct Observed(VecDeque<ExitEvidence>);
    impl Witness for Observed {
        fn observe(&mut self) -> ExitEvidence {
            self.0.pop_front().unwrap()
        }
    }
    fn peer() -> Fake {
        Fake {
            info: VecDeque::from([Ok(binding().identity.clone()), Ok(binding().identity)]),
            prepared: 0,
            committed: 0,
            refuse: false,
        }
    }
    #[test]
    fn changed_identity_at_either_bracket_never_prepares_or_commits() {
        for bracket in 0..2 {
            for field in 0..3 {
                let mut peer = peer();
                let mut changed = binding().identity;
                match field {
                    0 => changed.pid += 1,
                    1 => changed.generation = Some("aa".repeat(16)),
                    _ => changed.checksum = "bb".repeat(32),
                }
                peer.info[bracket] = Ok(changed);
                assert_eq!(
                    run(
                        &mut peer,
                        &binding(),
                        &binding().candidate,
                        |_| Ok(Observed(VecDeque::new())),
                        || panic!("no wait")
                    ),
                    RestartOutcome::Refused
                );
                assert_eq!((peer.prepared, peer.committed), (0, 0));
            }
        }
    }
    #[test]
    fn unqualified_candidate_observer_or_initial_evidence_has_zero_mutation() {
        let mut endpoint = peer();
        let mut wrong = binding().candidate;
        wrong.build += 1;
        assert_eq!(
            run(
                &mut endpoint,
                &binding(),
                &wrong,
                |_| Ok(Observed(VecDeque::new())),
                || false
            ),
            RestartOutcome::Refused
        );
        assert_eq!(endpoint.info.len(), 2);
        assert_eq!(
            run(
                &mut endpoint,
                &binding(),
                &binding().candidate,
                |_| Err::<Observed, _>(()),
                || false
            ),
            RestartOutcome::Refused
        );
        assert_eq!((endpoint.prepared, endpoint.committed), (0, 0));
        for initial in [ExitEvidence::Exited, ExitEvidence::Unknown] {
            let mut peer = peer();
            assert_eq!(
                run(
                    &mut peer,
                    &binding(),
                    &binding().candidate,
                    |_| Ok(Observed(VecDeque::from([initial]))),
                    || false
                ),
                RestartOutcome::Refused
            );
            assert_eq!((peer.prepared, peer.committed), (0, 0));
        }
    }
    #[test]
    fn image_change_while_preparing_never_dispatches_commit() {
        for changed in [ExitEvidence::Exited, ExitEvidence::Unknown] {
            let mut peer = peer();
            assert_eq!(
                run(
                    &mut peer,
                    &binding(),
                    &binding().candidate,
                    |_| Ok(Observed(VecDeque::from([ExitEvidence::Pending, changed]))),
                    || panic!("no wait before commit")
                ),
                RestartOutcome::Refused
            );
            assert_eq!((peer.prepared, peer.committed), (1, 0));
        }
    }

    #[test]
    fn acknowledged_missing_and_malformed_commit_replies_never_claim_refusal() {
        use crate::control::{ControlReply, DestructiveCommitResponse, DestructiveRestartRefusal};
        let acknowledged = serde_json::to_string(&DestructiveCommitResponse::Committed {
            receipt: hex::encode([3; 16]),
            consent: binding(),
            already_committed: false,
        })
        .unwrap();
        for reply in [
            Ok(ControlReply::Answered(acknowledged)),
            Ok(ControlReply::Answered("malformed".into())),
            Ok(ControlReply::NoDaemon),
            Ok(ControlReply::TimedOut),
            Err(anyhow::anyhow!("owned RPC error")),
        ] {
            assert!(matches!(dispatch_reply(reply), Dispatch::Sent));
        }
        let refused = serde_json::to_string(&DestructiveCommitResponse::Refused {
            reason: DestructiveRestartRefusal::Replacing,
        })
        .unwrap();
        assert!(matches!(
            dispatch_reply(Ok(ControlReply::Answered(refused))),
            Dispatch::Refused
        ));
    }

    #[test]
    fn committed_ack_loss_still_requires_exact_exit_without_second_commit() {
        for (observations, expected) in [
            (
                vec![
                    ExitEvidence::Pending,
                    ExitEvidence::Pending,
                    ExitEvidence::Exited,
                ],
                RestartOutcome::ExactExit,
            ),
            (
                vec![
                    ExitEvidence::Pending,
                    ExitEvidence::Pending,
                    ExitEvidence::Unknown,
                ],
                RestartOutcome::Uncertain,
            ),
            (
                vec![
                    ExitEvidence::Pending,
                    ExitEvidence::Pending,
                    ExitEvidence::Pending,
                ],
                RestartOutcome::Uncertain,
            ),
        ] {
            let mut peer = peer();
            assert_eq!(
                run(
                    &mut peer,
                    &binding(),
                    &binding().candidate,
                    |_| Ok(Observed(observations.into())),
                    || false
                ),
                expected
            );
            assert_eq!((peer.prepared, peer.committed), (1, 1));
        }
        let mut peer = peer();
        peer.refuse = true;
        assert_eq!(
            run(
                &mut peer,
                &binding(),
                &binding().candidate,
                |_| Ok(Observed(VecDeque::from([
                    ExitEvidence::Pending,
                    ExitEvidence::Pending
                ]))),
                || panic!("refused does not wait")
            ),
            RestartOutcome::Refused
        );
        assert_eq!(peer.committed, 1);
    }
}
