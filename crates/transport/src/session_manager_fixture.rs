//! Standalone backend fixtures drive the same lifecycle their manager normally owns.

use super::*;
use std::future::{poll_fn, Future};
use std::task::Poll;

pub(crate) async fn drive_backend<F: Future<Output = ()>>(
    io: SessionIo,
    run: impl FnOnce(SessionIo) -> F,
) {
    let lifecycle = io.lifecycle.clone();
    assert!(
        lifecycle.is_empty(),
        "standalone fixture must not have a manager parent"
    );
    let mut runner = Box::pin(run(io));
    poll_fn(|cx| {
        for _ in 0..crate::channel_timeline::ORDINARY_ENTRIES {
            if runner.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            let next = lifecycle.next();
            tokio::pin!(next);
            match next.as_mut().poll(cx) {
                Poll::Ready(Some(())) => {}
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
        // A bounded turn exhausted its quota by actual completions. No wake is
        // synthesized when the runner and its real JoinSet are both pending.
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
    drop(runner);
    lifecycle
        .drain()
        .await
        .expect("fixture joined its actual callbacks");
}
