use super::super::worker_control::{PendingFrame, Sent};
use super::super::worker_protocol::StopReason;
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

async fn controlled_child(case: u8) {
    let (parent, child) = worker_control::pair().unwrap();
    let stop = WorkerStop::default();
    let entered = Arc::new(Notify::new());
    let cleaning = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let count = Arc::new(AtomicUsize::new(0));
    let manager = {
        let entered = entered.clone();
        let cleaning = cleaning.clone();
        let release = release.clone();
        let shutdown = stop.shutdown();
        async move {
            entered.notify_one();
            shutdown.requested().await;
            cleaning.notify_one();
            release.acquire().await.unwrap().forget();
            7
        }
    };
    let receives = count.clone();
    let mut driver = tokio::spawn(drive_with(
        child,
        if case == 3 {
            u32::MAX
        } else {
            std::process::id()
        },
        stop.clone(),
        manager,
        move |socket| {
            let index = receives.fetch_add(1, Ordering::SeqCst);
            if case == 2 && index == 0 {
                return Ok(Received::Yielded);
            }
            worker_control::receive(socket)
        },
    ));
    entered.notified().await;
    if case == 1 {
        drop(parent);
    } else if case == 4 {
        super::super::channel::send(&parent, &[1, 99], None).unwrap();
    } else {
        assert_eq!(
            PendingFrame::new(&[1, 0]).unwrap().send(&parent),
            Ok(Sent::Complete)
        );
    }
    let observed_stop = tokio::time::timeout(Duration::from_millis(100), cleaning.notified())
        .await
        .is_ok();
    let reads_at_stop = count.load(Ordering::SeqCst);
    let early = tokio::time::timeout(Duration::from_millis(30), &mut driver)
        .await
        .ok();
    let reads_while_held = count.load(Ordering::SeqCst);
    let returned_early = early.is_some();
    // RED cleanup still requests the real token and awaits the exact manager.
    stop.shutdown().request();
    release.add_permits(1);
    let result = match early {
        Some(result) => result,
        None => tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .unwrap(),
    };
    assert_eq!(result.unwrap(), 7);
    assert!(
        !returned_early,
        "private control returned before actual manager cleanup"
    );
    assert!(
        observed_stop,
        "private control did not stop the retained manager"
    );
    assert_eq!(
        stop.snapshot().first_stop,
        Some(if matches!(case, 1 | 3 | 4) {
            StopReason::Protocol
        } else {
            StopReason::Requested
        })
    );
    if matches!(case, 1 | 3 | 4) {
        assert_eq!(reads_at_stop, 1);
        assert_eq!(
            reads_while_held, reads_at_stop,
            "closed control readiness hot-looped during held cleanup"
        );
    }
    if case == 2 {
        assert!(reads_at_stop >= 2, "Yielded discarded the queued real Stop");
    }
}

#[tokio::test]
async fn worker40_child_private_stop_retains_the_held_manager_until_actual_finish() {
    controlled_child(0).await;
}
#[tokio::test]
async fn worker40_child_private_eof_disables_readiness_while_manager_cleanup_is_held() {
    controlled_child(1).await;
}
#[tokio::test]
async fn worker40_child_private_yield_preserves_queued_stop_and_polls_manager_cleanup() {
    controlled_child(2).await;
}

#[tokio::test]
async fn worker40_child_private_wrong_sender_disables_readiness_and_keeps_cleanup_owned() {
    controlled_child(3).await;
}
#[tokio::test]
async fn worker40_child_private_malformed_packet_disables_readiness_and_keeps_cleanup_owned() {
    controlled_child(4).await;
}
