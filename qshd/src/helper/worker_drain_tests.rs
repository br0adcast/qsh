use super::super::worker_threads::Role;
use super::*;
use std::sync::mpsc;
use std::time::Duration;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn four_threads() -> WorkerThreads {
    threads_with_observer(None)
}
fn threads_with_observer(observer: Option<mpsc::Sender<Role>>) -> WorkerThreads {
    let mut owner = WorkerThreads::default();
    for role in [
        Role::NoncePool,
        Role::ChannelReader,
        Role::AuthReader,
        Role::TellReleaser,
    ] {
        let (stop, stopped) = mpsc::channel();
        let observer = observer.clone();
        owner.register(
            role,
            std::thread::spawn(move || {
                stopped.recv().unwrap();
                Ok(())
            }),
            move || {
                if let Some(observer) = observer {
                    let _ = observer.send(role);
                }
                stop.send(()).map_err(std::io::Error::other)
            },
        );
    }
    owner
}

#[test]
fn worker40_driver_polls_and_finishes_the_retained_manager_before_auxiliary_stop() {
    let (entered, started) = mpsc::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let (stopped, observed_stop) = mpsc::channel();
    let (auxiliary_stop, observed_auxiliary_stop) = mpsc::channel();
    let mut auxiliary = threads_with_observer(Some(auxiliary_stop));
    // Watching an actual joined role is independent of the producer-fence result.
    let failure = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    auxiliary.watch(Role::ChannelReader, failure);
    let manager = async move {
        entered.send(()).unwrap();
        released.await.unwrap();
        stopped.send(()).unwrap();
        Ok(())
    };
    let driver =
        std::thread::spawn(move || run(runtime(), manager, auxiliary, WorkerStop::default()));
    let was_started = started.recv_timeout(Duration::from_secs(2)).is_ok();
    let manager_early = observed_stop.try_recv().is_ok();
    let auxiliary_early = observed_auxiliary_stop.try_recv().is_ok();
    let _ = release.send(());
    let mut outcome = driver.join().unwrap();
    assert!(
        was_started,
        "driver discarded rather than retained the real manager future"
    );
    assert!(!manager_early);
    assert!(
        !auxiliary_early,
        "auxiliary producers stopped before manager completion"
    );
    assert!(observed_stop.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(outcome.completion().unwrap().successful());
}

#[test]
fn worker40_actual_runtime_blocking_job_prevents_a_completion_outcome() {
    let runtime = runtime();
    let (started, observed_start) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let task = runtime.spawn_blocking(move || {
        started.send(()).unwrap();
        released.recv().unwrap();
    });
    observed_start.recv_timeout(Duration::from_secs(2)).unwrap();
    let (done, completed) = mpsc::channel();
    let (auxiliary_stop, observed_auxiliary_stop) = mpsc::channel();
    let driver = std::thread::spawn(move || {
        let outcome = run(
            runtime,
            async { Ok(()) },
            threads_with_observer(Some(auxiliary_stop)),
            WorkerStop::default(),
        );
        done.send(outcome).unwrap();
    });
    let reached_runtime_boundary = (0..4).all(|_| {
        observed_auxiliary_stop
            .recv_timeout(Duration::from_secs(2))
            .is_ok()
    });
    let early = completed.recv_timeout(Duration::from_millis(50)).ok();
    release.send(()).unwrap();
    let returned_early = early.is_some();
    let outcome = early.or_else(|| completed.recv_timeout(Duration::from_secs(2)).ok());
    driver.join().unwrap();
    assert!(
        reached_runtime_boundary,
        "driver never reached ordered auxiliary shutdown"
    );
    assert!(
        !returned_early,
        "completion escaped while an actual runtime job was held"
    );
    assert!(task.is_finished(), "actual blocking work was abandoned");
    assert!(outcome.unwrap().completion().unwrap().successful());
}

#[test]
fn worker40_incomplete_auxiliary_custody_cannot_look_like_a_clean_worker() {
    let mut outcome = run(
        runtime(),
        async { Ok(()) },
        WorkerThreads::default(),
        WorkerStop::default(),
    );
    assert_eq!(outcome.completion(), None);
    assert_eq!(outcome.first_failure, Some(DrainFailure::Auxiliary));
}

#[test]
fn worker40_actual_held_auxiliary_thread_prevents_a_completion_outcome() {
    let (release, released) = mpsc::channel();
    let (stopping, observed_stop) = mpsc::channel();
    let mut auxiliary = WorkerThreads::default();
    for role in [Role::NoncePool, Role::AuthReader, Role::TellReleaser] {
        auxiliary.register(role, std::thread::spawn(|| Ok(())), || Ok(()));
    }
    auxiliary.register(
        Role::ChannelReader,
        std::thread::spawn(move || {
            released.recv().unwrap();
            Ok(())
        }),
        move || stopping.send(()).map_err(std::io::Error::other),
    );
    let (done, completed) = mpsc::channel();
    let driver = std::thread::spawn(move || {
        done.send(run(
            runtime(),
            async { Ok(()) },
            auxiliary,
            WorkerStop::default(),
        ))
        .unwrap();
    });
    let reached_join = observed_stop.recv_timeout(Duration::from_secs(2)).is_ok();
    let early = completed.recv_timeout(Duration::from_millis(50)).ok();
    release.send(()).unwrap();
    let returned_early = early.is_some();
    let outcome = early.or_else(|| completed.recv_timeout(Duration::from_secs(2)).ok());
    driver.join().unwrap();
    assert!(reached_join);
    assert!(
        !returned_early,
        "completion escaped before the held auxiliary's actual join"
    );
    assert!(outcome.unwrap().completion().unwrap().successful());
}

#[test]
fn worker40_returned_fatal_hook_does_not_erase_actual_joins_or_certify_producers() {
    let stop = WorkerStop::default();
    stop.request(super::super::worker_protocol::StopReason::Requested);
    stop.fatal_hook(super::super::worker_protocol::StopReason::RequiredTellLost)(
        "controlled lost tell",
    );
    let mut outcome = run(runtime(), async { Ok(()) }, four_threads(), stop);
    let receipt = outcome.completion().unwrap();
    assert_eq!(
        receipt.manager,
        super::super::worker_protocol::Settled::Joined
    );
    assert_eq!(
        receipt.producers,
        super::super::worker_protocol::Settled::Failed
    );
    assert_eq!(receipt.joined, 15);
    assert_eq!(outcome.first_failure, Some(DrainFailure::RequiredProducer));
}

#[test]
fn worker40_controlled_initialization_failure_never_becomes_a_drained_receipt() {
    let (stopped, observed_stop) = mpsc::channel();
    let mut outcome = run(
        runtime(),
        async {
            Err(ServeLoopError::Initialize(anyhow::anyhow!(
                "controlled initialization failure"
            )))
        },
        threads_with_observer(Some(stopped)),
        WorkerStop::default(),
    );
    assert_eq!(
        observed_stop.iter().count(),
        4,
        "all actual auxiliary stop controls ran"
    );
    assert_eq!(outcome.first_failure, Some(DrainFailure::Initialize));
    assert_eq!(outcome.completion(), None);
}

#[test]
fn worker40_retained_producer_fault_after_auxiliary_joins_survives_runtime_settlement() {
    let runtime = runtime();
    let failure = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let late_failure = failure.clone();
    let (started, observed_start) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let task = runtime.spawn_blocking(move || {
        started.send(()).unwrap();
        released.recv().unwrap();
        late_failure.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    observed_start.recv_timeout(Duration::from_secs(2)).unwrap();
    let (auxiliary_stop, observed_auxiliary_stop) = mpsc::channel();
    let mut auxiliary = threads_with_observer(Some(auxiliary_stop));
    auxiliary.watch(Role::TellReleaser, failure);
    let (after_joins, joined_before_runtime) = mpsc::channel();
    let driver = std::thread::spawn(move || {
        run_with_runtime_finish(
            runtime,
            async { Ok(()) },
            auxiliary,
            WorkerStop::default(),
            move |runtime| {
                // The real first stop_and_join, including its watched-fault scan,
                // completed before this seam. This closure still drops the actual
                // runtime and waits for the real held blocking body.
                after_joins.send(()).unwrap();
                drop(runtime);
            },
        )
    });
    let reached_runtime_boundary = (0..4).all(|_| {
        observed_auxiliary_stop
            .recv_timeout(Duration::from_secs(2))
            .is_ok()
    });
    let actual_auxiliary_joined = joined_before_runtime
        .recv_timeout(Duration::from_secs(2))
        .is_ok();
    release.send(()).unwrap();
    let mut outcome = driver.join().unwrap();
    assert!(reached_runtime_boundary);
    assert!(actual_auxiliary_joined);
    assert!(task.is_finished());
    let receipt = outcome.completion().unwrap();
    assert_eq!(receipt.joined, 15);
    assert_eq!(receipt.failed, 1 << Role::TellReleaser as u8);
    assert_eq!(
        receipt.producers,
        super::super::worker_protocol::Settled::Failed
    );
    assert_eq!(outcome.first_failure, Some(DrainFailure::Auxiliary));
}

#[test]
fn worker40_returned_hook_fault_before_checked_consumption_cannot_use_an_old_snapshot() {
    let stop = WorkerStop::default();
    let hook = stop.fatal_hook(super::super::worker_protocol::StopReason::RequiredTellLost);
    let outcome = run(runtime(), async { Ok(()) }, four_threads(), stop);
    hook("controlled fault before checked local outcome consumption");
    assert!(
        outcome.into_result().is_err(),
        "copied completion hid retained hook failure"
    );
}
