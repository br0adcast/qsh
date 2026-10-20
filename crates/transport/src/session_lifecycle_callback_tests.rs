use crate::control_budget::{GlobalBudget, Job};
use crate::control_job::JobOwner;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn callback_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn callback_lease(lifecycle: &Lifecycle, uid: u32) -> JobLease {
    let mut owner = JobOwner::reserve(&lifecycle.control_budget.session(uid), Job::About).unwrap();
    owner.take_worker().unwrap()
}

#[test]
fn capacity_callback_completed_unreaped_result_and_panic_retain_job_capacity() {
    for panics in [false, true] {
        let lifecycle = Arc::new(Lifecycle::default());
        let global = lifecycle.control_budget.clone();
        let runtime = callback_runtime();
        let (mut result,) = runtime.block_on(async {
            let (entered, entry) = oneshot::channel();
            let result = lifecycle.spawn_callback(callback_lease(&lifecycle, 1), move || {
                let _ = entered.send(());
                assert!(!panics, "controlled provider callback panic");
                42u8
            });
            tokio::time::timeout(Duration::from_secs(5), entry)
                .await
                .expect("actual callback entered")
                .unwrap();
            (result,)
        });
        // Owned runtime shutdown joins the actual worker before inspecting an
        // unreaped task. No guessed sleep establishes callback completion.
        drop(runtime);
        let before_reap = global.retained_for_test().2;
        let unpublished = matches!(result.try_recv(), Err(oneshot::error::TryRecvError::Empty));
        let reaper = callback_runtime();
        reaper.block_on(lifecycle.drain()).unwrap();
        let published = result.try_recv();
        drop(reaper);
        assert_eq!(
            before_reap, 1,
            "completed unreaped callback refunded its lease"
        );
        assert!(
            unpublished,
            "result published before manager observed actual join"
        );
        assert_eq!(
            published.unwrap(),
            if panics {
                Err(CallbackFailure::Panicked)
            } else {
                Ok(42)
            }
        );
        assert_eq!(global.retained_for_test().2, 0);
    }
}

#[test]
fn capacity_callback_receiver_loss_and_cancelled_drain_keep_actual_worker_owned() {
    let runtime = callback_runtime();
    let completed = Arc::new(AtomicBool::new(false));
    let (pending, charged, joined_before_receipt) = runtime.block_on(async {
        let lifecycle = Arc::new(Lifecycle::default());
        let global = lifecycle.control_budget.clone();
        let (release, held) = std::sync::mpsc::sync_channel::<()>(0);
        let (entered, entry) = oneshot::channel();
        let worker_completed = completed.clone();
        let result = lifecycle.spawn_callback(callback_lease(&lifecycle, 1), move || {
            let _ = entered.send(());
            let _ = held.recv();
            worker_completed.store(true, Ordering::SeqCst);
        });
        drop(result);
        tokio::time::timeout(Duration::from_secs(5), entry)
            .await
            .unwrap()
            .unwrap();
        lifecycle.shutdown.request();
        let mut drain = Box::pin(lifecycle.drain());
        let pending = poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await;
        drop(drain);
        let charged = global.retained_for_test().2;
        drop(release);
        tokio::time::timeout(Duration::from_secs(5), lifecycle.drain())
            .await
            .unwrap()
            .unwrap();
        let joined_before_receipt = completed.load(Ordering::SeqCst);
        (pending, charged, (joined_before_receipt, global))
    });
    let (joined_before_receipt, owned_global) = joined_before_receipt;
    let global: GlobalBudget = owned_global;
    drop(runtime);
    assert!(
        pending,
        "drain passed a still-running callback after receiver loss"
    );
    assert_eq!(charged, 1, "cancelled drain refunded worker capacity");
    assert!(
        joined_before_receipt,
        "drain returned before actual callback completion"
    );
    assert!(completed.load(Ordering::SeqCst));
    assert_eq!(global.retained_for_test().2, 0);
}

struct CallbackResultPanic;
impl Drop for CallbackResultPanic {
    fn drop(&mut self) {
        panic!("controlled callback result destruction failure");
    }
}

#[test]
fn capacity_callback_result_destruction_failure_does_not_abandon_other_worker() {
    let runtime = callback_runtime();
    let (reaped, pending, failed, remaining, global) = runtime.block_on(async {
        let lifecycle = Arc::new(Lifecycle::default());
        let global = lifecycle.control_budget.clone();
        let result =
            lifecycle.spawn_callback(callback_lease(&lifecycle, 1), || CallbackResultPanic);
        drop(result);
        let (release, held) = std::sync::mpsc::sync_channel::<()>(0);
        let (entered, entry) = oneshot::channel();
        let result = lifecycle.spawn_callback(callback_lease(&lifecycle, 2), move || {
            let _ = entered.send(());
            let _ = held.recv();
        });
        drop(result);
        tokio::time::timeout(Duration::from_secs(5), entry)
            .await
            .unwrap()
            .unwrap();
        let reaped = tokio::time::timeout(Duration::from_secs(5), lifecycle.next())
            .await
            .unwrap();
        let remaining = global.retained_for_test().2;
        let mut drain = Box::pin(lifecycle.drain());
        let pending = poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx).is_pending())).await;
        drop(release);
        let failed = if pending {
            tokio::time::timeout(Duration::from_secs(5), drain)
                .await
                .unwrap()
                .is_err()
        } else {
            drop(drain);
            lifecycle.drain().await.is_err()
        };
        (reaped, pending, failed, remaining, global)
    });
    drop(runtime);
    assert_eq!(reaped, Some(()), "failed publication must still be reaped");
    assert!(
        pending,
        "publication failure abandoned another actual worker"
    );
    assert!(failed, "contained publication failure must remain explicit");
    assert_eq!(remaining, 1);
    assert_eq!(global.retained_for_test().2, 0);
}

#[test]
fn capacity_callback_unexpected_owner_drop_detaches_without_early_refund() {
    let runtime = callback_runtime();
    let (charged, global) = runtime.block_on(async {
        let lifecycle = Arc::new(Lifecycle::default());
        let global = lifecycle.control_budget.clone();
        let (release, held) = std::sync::mpsc::sync_channel::<()>(0);
        let (entered, entry) = oneshot::channel();
        let result = lifecycle.spawn_callback(callback_lease(&lifecycle, 1), move || {
            let _ = entered.send(());
            let _ = held.recv();
        });
        drop(result);
        tokio::time::timeout(Duration::from_secs(5), entry)
            .await
            .unwrap()
            .unwrap();
        drop(lifecycle);
        let charged = global.retained_for_test().2;
        drop(release);
        (charged, global)
    });
    drop(runtime);
    assert_eq!(
        charged, 1,
        "unexpected owner cancellation refunded a live callback"
    );
    assert_eq!(global.retained_for_test().2, 0);
}

#[cfg(target_os = "linux")]
#[test]
fn capacity_callback_panicking_panic_payload_destructor_aborts_isolated_child() {
    const CHILD: &str = "QSH_CALLBACK_PAYLOAD_ABORT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        dispose_panic_payload(Box::new(CallbackResultPanic));
        return;
    }
    use std::os::unix::process::ExitStatusExt;
    let test_name = format!(
        "{}::capacity_callback_panicking_panic_payload_destructor_aborts_isolated_child",
        module_path!().split_once("::").unwrap().1
    );
    let child = std::process::Command::new("sh")
        .args(["-c", "ulimit -c 0; exec \"$@\"", "callback-payload-child"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test_name.as_str()])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&child.stdout).contains("running 1 test"),
        "isolated child must execute exactly its intended control"
    );
    assert_eq!(
        child.status.signal(),
        Some(6),
        "exceptional payload destructor must SIGABRT, not leak or recurse"
    );
}
