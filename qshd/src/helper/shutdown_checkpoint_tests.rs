#[test]
fn shutdown_checkpoint_reports_retained_obligations_without_changing_them() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    let mut shutdown = HelperShutdown::new(empty_state());
    let owner = MonitorOwner {
        login: [73; 16],
        incarnation: 7,
    };
    let missing = MonitorOwner {
        login: [74; 16],
        incarnation: 8,
    };
    let (seam, _peer) = super::channel::pair().expect("owned pair");
    shutdown.state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            pid: Pid::from_raw(i32::MAX),
            reaped: false,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: Some(RefusalSeal::Pending {
                until: Instant::now(),
                packet: Vec::new(),
            }),
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: true,
            failure: Some(MonitorFailure::Stream),
            #[cfg(target_os = "linux")]
            signal_failure: None,
        },
    );
    shutdown.state.retired.extend([owner, missing]);
    shutdown.state.live.insert(1, ChannelSlot::Running(owner));
    shutdown.state.orphans.push(Pid::from_raw(i32::MAX));
    shutdown.first_monitor_failure = Some(MonitorShutdownFailure::MissingOwner);
    let note = Note::default();
    note.publish(Phase::BeforePass, Some(SeamEnd::ChannelEof), &shutdown);
    let snapshot = *note.inner.lock().expect("observation");
    assert_eq!(
        (
            snapshot.monitors,
            snapshot.retired,
            snapshot.live,
            snapshot.orphans
        ),
        (1, 2, 1, 1)
    );
    assert_eq!(
        (
            snapshot.missing_completion,
            snapshot.not_reaped,
            snapshot.wait_lost,
            snapshot.monitor_failure
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        (
            snapshot.missing_owner,
            snapshot.retired_live,
            snapshot.seal_pending
        ),
        (1, 1, 1)
    );
    assert!(snapshot.sticky_monitor_failure);
    assert_eq!(
        (snapshot.phase, snapshot.seam_end, snapshot.sequence),
        (Phase::BeforePass, SeamEnd::ChannelEof, 1)
    );
    // Observation neither settles nor clears any stored custody evidence.
    assert_eq!(shutdown.state.monitors.len(), 1);
    assert_eq!(shutdown.state.live.len(), 1);
    assert_eq!(shutdown.state.retired.len(), 2);
    assert!(shutdown.state.monitors[&owner].wait_lost);
    let monitor = shutdown.state.monitors.get_mut(&owner).unwrap();
    monitor.refusal_seal = Some(RefusalSeal::Sent);
    monitor.completion = Some(PamCompletion::NotOpened);
    monitor.reaped = true;
    monitor.wait_lost = false;
    monitor.failure = None;
    note.publish(Phase::AfterPass, None, &shutdown);
    let completed = *note.inner.lock().unwrap();
    assert_eq!(
        (
            completed.seal_pending,
            completed.seal_sent,
            completed.missing_completion,
            completed.not_reaped,
            completed.wait_lost,
            completed.monitor_failure
        ),
        (0, 1, 0, 0, 0, 0)
    );
    assert_eq!(completed.seam_end, SeamEnd::ChannelEof);
    assert_eq!(
        (shutdown.state.live.len(), shutdown.state.retired.len()),
        (1, 2)
    );
    shutdown
        .state
        .monitors
        .get_mut(&owner)
        .unwrap()
        .refusal_seal = Some(RefusalSeal::Failed);
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(note.inner.lock().unwrap().seal_failed, 1);
}

#[test]
fn shutdown_checkpoint_try_lock_never_blocks_producer_or_timeout_reader() {
    use super::shutdown_checkpoint::{Note, Phase};
    use std::sync::{mpsc, Arc};
    let note = Arc::new(Note::default());
    let held = note.inner.lock().expect("held observation");
    let other = note.clone();
    let (done, completion) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let shutdown = HelperShutdown::new(empty_state());
        other.publish(Phase::BeforePass, None, &shutdown);
        done.send(other.receipt()).expect("observer result");
    });
    let early = completion.recv_timeout(Duration::from_millis(100));
    drop(held);
    thread.join().expect("owned observer thread joined");
    assert!(early.is_ok(), "diagnostics must not block on a held cell");
    assert!(early.unwrap().contains("unavailable-busy"));
}

#[test]
fn shutdown_checkpoint_poison_and_unobserved_are_explicit() {
    use super::shutdown_checkpoint::{Note, Phase};
    let note = std::sync::Arc::new(Note::default());
    assert!(note.receipt().contains("not-observed"));
    let other = note.clone();
    assert!(std::thread::spawn(move || {
        let _held = other.inner.lock().unwrap();
        panic!("controlled observation poison");
    })
    .join()
    .is_err());
    note.publish(Phase::BeforePass, None, &HelperShutdown::new(empty_state()));
    assert!(note.receipt().contains("unavailable-poisoned"));
}

#[test]
fn shutdown_checkpoint_timeout_keeps_failure_and_owned_thread_settlement() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    let note = Note::default();
    note.publish(
        Phase::BeforePass,
        Some(SeamEnd::AuthEof),
        &HelperShutdown::new(empty_state()),
    );
    let (release, held) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || held.recv().expect("release owned thread"));
    let expired = !wait_for_thread(&thread, Instant::now() + Duration::from_millis(20));
    let message = timeout_message("controlled shutdown", Some(&note));
    release.send(()).expect("release before assertion");
    thread.join().expect("owned timeout control joined");
    assert!(
        expired,
        "a checkpoint must never convert an unfinished join to success"
    );
    assert!(message.contains(&note.receipt()));
    assert_eq!(message.matches("checkpoint=").count(), 1);
}

#[test]
fn shutdown_checkpoint_receipt_bound_covers_maximum_counter_width() {
    #[cfg(target_os = "linux")]
    use super::shutdown_checkpoint::NativeKind;
    use super::shutdown_checkpoint::{
        MonitorKind, NativeSample, Note, Phase, RequestKind, SeamEnd, Snapshot, StickyKind,
    };
    let note = Note::default();
    *note.inner.lock().unwrap() = Snapshot {
        sequence: u64::MAX,
        phase: Phase::BeforePass,
        seam_end: SeamEnd::ChannelFailed,
        monitors: usize::MAX,
        retired: usize::MAX,
        live: usize::MAX,
        verifying: usize::MAX,
        orphans: usize::MAX,
        missing_completion: usize::MAX,
        not_reaped: usize::MAX,
        wait_lost: usize::MAX,
        monitor_failure: usize::MAX,
        missing_owner: usize::MAX,
        retired_live: usize::MAX,
        seal_pending: usize::MAX,
        seal_sent: usize::MAX,
        seal_failed: usize::MAX,
        sticky_monitor_failure: true,
        cleanup_failure: true,
        #[cfg(target_os = "linux")]
        sticky_failure_kind: StickyKind::Monitor(MonitorKind::Native(NativeKind::Request(
            RequestKind::Deadline,
        ))),
        #[cfg(not(target_os = "linux"))]
        sticky_failure_kind: StickyKind::Monitor(MonitorKind::Request(RequestKind::Deadline)),
        first_unreaped_native: Some(NativeSample {
            leader_exited: true,
            producer_drained: true,
            established: true,
        }),
    };
    assert!(
        note.receipt().len() <= 1024,
        "fixed observation must fit one bounded receipt"
    );
}

#[test]
fn shutdown_checkpoint_actual_seam_exit_categories_survive_final_return() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    for (auth_seam, malformed, expected) in [
        (false, false, SeamEnd::ChannelEof),
        (true, false, SeamEnd::AuthEof),
        (false, true, SeamEnd::ChannelFailed),
        (true, true, SeamEnd::AuthFailed),
    ] {
        let note = std::sync::Arc::new(Note::default());
        let observe = note.clone();
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
        if malformed {
            let seam = if auth_seam { &auth } else { &channels };
            super::channel::send(seam, b"malformed fixed test packet", None)
                .expect("queued packet");
        }
        let thread = std::thread::spawn(move || {
            let _ = serve_inner(
                helper_channels,
                helper_auth,
                test_config(),
                HashMap::new(),
                UNPRIVILEGED,
                None,
                #[cfg(target_os = "linux")]
                None,
                Some(observe),
            );
        });
        // Keep the other seam open so only the selected observation can end the loop.
        if auth_seam {
            drop(auth);
        } else {
            drop(channels);
        }
        join_within(thread, "empty diagnosed loop must settle");
        let latest = *note.inner.lock().expect("observation");
        assert_eq!(latest.seam_end, expected);
        assert_eq!(latest.phase, Phase::Returned);
        assert!(latest.sequence >= 4);
        assert_eq!((latest.monitors, latest.retired, latest.live), (0, 0, 0));
    }
}

/// Distinctive payload: no projected tag or receipt may carry it.
const CHECKPOINT_PAYLOAD: i32 = 424242;

fn checkpoint_kind(failure: Option<MonitorShutdownFailure>) -> super::shutdown_checkpoint::StickyKind {
    use super::shutdown_checkpoint::{Note, Phase};
    let mut shutdown = HelperShutdown::new(empty_state());
    shutdown.first_monitor_failure = failure;
    let note = Note::default();
    note.publish(Phase::AfterPass, None, &shutdown);
    let receipt = note.receipt();
    assert!(
        !receipt.contains(&CHECKPOINT_PAYLOAD.to_string()),
        "payload leaked into the checkpoint: {receipt}"
    );
    let kind = note.inner.lock().unwrap().sticky_failure_kind;
    assert_eq!(kind, super::shutdown_checkpoint::sticky_kind(failure));
    kind
}

#[test]
fn shutdown_checkpoint_projects_every_sticky_failure_branch_without_payloads() {
    use super::super::protocol::RequestDrainFailure as Drain;
    #[cfg(target_os = "linux")]
    use super::shutdown_checkpoint::NativeKind;
    use super::shutdown_checkpoint::{ExitKind, MonitorKind as M, RequestKind as R, StickyKind as K};
    let p = CHECKPOINT_PAYLOAD;
    let requests = [
        (Drain::Exit, R::Exit),
        (Drain::Deadline, R::Deadline),
        (Drain::Protocol, R::Protocol),
        (Drain::Receive, R::Receive),
        (Drain::Send, R::Send),
        (Drain::Seal, R::Seal),
    ];
    let mut cases = vec![
        (None, K::None),
        (Some(MonitorShutdownFailure::MissingOwner), K::MissingOwner),
        (Some(MonitorShutdownFailure::Poll(p)), K::Poll),
    ];
    let mut monitor = vec![
        (MonitorFailure::Exit(MonitorExitStatus::Code(p)), M::Exit(ExitKind::Code)),
        (
            MonitorFailure::Exit(MonitorExitStatus::Signal {
                number: p,
                core_dumped: true,
            }),
            M::Exit(ExitKind::Signal),
        ),
        (MonitorFailure::Shutdown(p), M::Shutdown),
        (MonitorFailure::Send(p), M::Send),
        (MonitorFailure::Stream, M::Stream),
        (MonitorFailure::Wait(p), M::Wait),
        (MonitorFailure::DuplicateCompletion, M::DuplicateCompletion),
    ];
    #[cfg(target_os = "linux")]
    {
        use super::super::monitor_owner::Failure as Native;
        monitor.push((
            MonitorFailure::Exit(MonitorExitStatus::NativeEncoded(p)),
            M::Exit(ExitKind::NativeEncoded),
        ));
        monitor.extend([
            (MonitorFailure::Native(Native::Protocol), M::Native(NativeKind::Protocol)),
            (MonitorFailure::Native(Native::Stream(p)), M::Native(NativeKind::Stream)),
            (
                MonitorFailure::Native(Native::LostAuthority),
                M::Native(NativeKind::LostAuthority),
            ),
            (MonitorFailure::Native(Native::Signal(p, p)), M::Native(NativeKind::Signal)),
        ]);
        for (failure, tag) in requests {
            monitor.push((
                MonitorFailure::Native(Native::Request(failure)),
                M::Native(NativeKind::Request(tag)),
            ));
        }
    }
    for (failure, tag) in requests {
        monitor.push((MonitorFailure::Request(failure), M::Request(tag)));
    }
    cases.extend(
        monitor
            .into_iter()
            .map(|(failure, tag)| (Some(MonitorShutdownFailure::Monitor(failure)), K::Monitor(tag))),
    );
    for (failure, expected) in cases {
        assert_eq!(checkpoint_kind(failure), expected, "{failure:?}");
    }
}

#[test]
fn shutdown_checkpoint_keeps_the_first_latched_sticky_failure() {
    use super::shutdown_checkpoint::{MonitorKind, Note, Phase, StickyKind};
    let mut shutdown = HelperShutdown::new(empty_state());
    let owner = MonitorOwner {
        login: [75; 16],
        incarnation: 9,
    };
    let (seam, _peer) = super::channel::pair().expect("owned pair");
    shutdown.state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            pid: Pid::from_raw(i32::MAX),
            reaped: false,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: None,
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: false,
            failure: Some(MonitorFailure::Stream),
            #[cfg(target_os = "linux")]
            signal_failure: None,
        },
    );
    let note = Note::default();
    shutdown.observe_monitor_failures();
    note.publish(Phase::AfterPass, None, &shutdown);
    let first = StickyKind::Monitor(MonitorKind::Stream);
    assert_eq!(note.inner.lock().unwrap().sticky_failure_kind, first);
    // A later different fault cannot replace the latched first one.
    shutdown.state.monitors.get_mut(&owner).unwrap().failure =
        Some(MonitorFailure::DuplicateCompletion);
    shutdown.observe_monitor_failures();
    note.publish(Phase::AfterPass, None, &shutdown);
    let latest = *note.inner.lock().unwrap();
    assert_eq!(latest.sticky_failure_kind, first);
    assert_eq!(latest.monitor_failure, 1);
    // A controlled model carries no native latches to sample.
    assert_eq!(latest.first_unreaped_native, None);
}

#[cfg(target_os = "linux")]
#[test]
fn shutdown_checkpoint_native_sample_is_independent_read_only_and_absent_when_unsampled() {
    use super::shutdown_checkpoint::{NativeSample, Note, Phase, StickyKind};
    let note = Note::default();
    let mut shutdown = HelperShutdown::new(empty_state());
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(note.inner.lock().unwrap().first_unreaped_native, None);

    let mut child = ChildOwnerForCheckpoint::new(
        std::process::Command::new("/bin/true")
            .spawn()
            .expect("owned native sample child"),
    );
    let view = crate::process_scope::prepare().expect("qualified proc view");
    let (seam, _peer) = super::channel::pair().expect("owned pair");
    let pid = std::num::NonZeroU32::new(child.0.id()).unwrap();
    let owner = MonitorOwner {
        login: [76; 16],
        incarnation: 10,
    };
    shutdown.state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Native(super::super::monitor_owner::NativeMonitor::new(
                pid, view, seam,
            )),
            pid: Pid::from_raw(pid.get() as i32),
            reaped: false,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: None,
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: false,
            failure: None,
            signal_failure: None,
        },
    );
    // An actual unreaped native monitor yields explicit false latches.
    shutdown.first_monitor_failure = Some(MonitorShutdownFailure::MissingOwner);
    note.publish(Phase::AfterPass, None, &shutdown);
    let fresh = *note.inner.lock().unwrap();
    let unlatched = NativeSample {
        leader_exited: false,
        producer_drained: false,
        established: false,
    };
    assert_eq!(fresh.first_unreaped_native, Some(unlatched));
    // Independent: the sticky failure names a different actor.
    assert_eq!(fresh.sticky_failure_kind, StickyKind::MissingOwner);
    // Repeated sampling does not observe or advance custody.
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(note.inner.lock().unwrap().first_unreaped_native, Some(unlatched));

    // Only the owner's own observation latches leader exit.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let MonitorProcess::Native(native) =
            &mut shutdown.state.monitors.get_mut(&owner).unwrap().process
        else {
            unreachable!()
        };
        if matches!(native.leader(), crate::process_scope::scope::LeaderStatus::Exited(_)) {
            break;
        }
        assert!(Instant::now() < deadline, "owned sample child did not exit");
        std::thread::sleep(Duration::from_millis(1));
    }
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(
        note.inner.lock().unwrap().first_unreaped_native,
        Some(NativeSample {
            leader_exited: true,
            ..unlatched
        })
    );
    shutdown.state.monitors.get_mut(&owner).unwrap().reaped = true;
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(note.inner.lock().unwrap().first_unreaped_native, None);
    drop(shutdown);
    // The non-consuming leader observation left the exact wait to this owner.
    assert!(child.0.wait().expect("owned child wait").success());
    child.1 = true;
}

#[cfg(target_os = "linux")]
struct ChildOwnerForCheckpoint(std::process::Child, bool);
#[cfg(target_os = "linux")]
impl ChildOwnerForCheckpoint {
    fn new(child: std::process::Child) -> Self {
        Self(child, false)
    }
}
#[cfg(target_os = "linux")]
impl Drop for ChildOwnerForCheckpoint {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
