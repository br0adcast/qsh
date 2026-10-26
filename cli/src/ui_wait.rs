//! The final UI event queue and its ordinary-thread notification.
use crate::input_wake::{self, WakeReader, WakeSender};
use crate::session::UiEvent;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
struct SendSide {
    tx: Option<mpsc::Sender<UiEvent>>,
    wake: WakeSender,
    failed: Arc<AtomicBool>,
}
impl Drop for SendSide {
    fn drop(&mut self) {
        drop(self.tx.take());
        let _ = self.wake.notify();
    }
}
#[derive(Clone)]
pub struct UiSender {
    inner: Arc<SendSide>,
}
pub struct UiInbox {
    rx: mpsc::Receiver<UiEvent>,
    wake: WakeReader,
    failed: Arc<AtomicBool>,
}
pub fn channel() -> io::Result<(UiSender, UiInbox)> {
    let (tx, rx) = mpsc::channel();
    let (wake, notify) = input_wake::pair()?;
    let failed = Arc::new(AtomicBool::new(false));
    Ok((
        UiSender {
            inner: Arc::new(SendSide {
                tx: Some(tx),
                wake: notify,
                failed: failed.clone(),
            }),
        },
        UiInbox { rx, wake, failed },
    ))
}
impl UiSender {
    pub fn send(&self, event: UiEvent) -> Result<(), mpsc::SendError<UiEvent>> {
        if self.inner.failed.load(Ordering::Acquire) {
            return Err(mpsc::SendError(event));
        }
        self.inner.tx.as_ref().unwrap().send(event)?;
        // Acceptance has happened. Notification failure must never invite a retry.
        if self.inner.wake.notify().is_err() {
            self.inner.failed.store(true, Ordering::Release);
        }
        Ok(())
    }
}
impl UiInbox {
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub fn drain(&mut self) -> io::Result<()> {
        self.wake.drain()
    }
    pub fn try_recv(&self) -> Result<UiEvent, mpsc::TryRecvError> {
        self.rx.try_recv()
    }
    pub fn raw_fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ui_wait_inbox_accepted_event_is_readable_before_another_event() {
        let (tx, rx) = channel().unwrap();
        tx.send(UiEvent::Tick).unwrap();
        let mut p = libc::pollfd {
            fd: rx.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut p, 1, 0) },
            1,
            "accepted event must wake the sole UI owner"
        );
        assert_eq!(rx.try_recv(), Ok(UiEvent::Tick));
    }
    #[test]
    fn ui_wait_inbox_failure_after_acceptance_never_invites_retry() {
        let (tx, mut rx) = channel().unwrap();
        tx.inner.wake.fail_next_notify();
        assert!(
            tx.send(UiEvent::Tick).is_ok(),
            "accepted event is not rejected by later notify failure"
        );
        assert_eq!(rx.try_recv(), Ok(UiEvent::Tick));
        assert!(
            rx.failed(),
            "the owner must know the permanent notification fault"
        );
        assert!(rx.drain().is_err());
        assert!(
            tx.send(UiEvent::Tick).is_err(),
            "a failed inbox stops future admissions"
        );
    }
    #[test]
    fn ui_wait_inbox_last_sender_drop_publishes_disconnect_before_wake() {
        let (tx, rx) = channel().unwrap();
        drop(tx);
        let mut p = libc::pollfd {
            fd: rx.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut p, 1, 0) }, 1);
        assert_eq!(rx.try_recv(), Err(mpsc::TryRecvError::Disconnected));
    }
}
