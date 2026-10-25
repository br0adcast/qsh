//! Coalesced acknowledgement obligation and optional absolute timer.
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct EchoDeadline {
    dirty: bool,
    due: Option<Instant>,
}
impl EchoDeadline {
    pub(crate) fn input(&mut self, now: Instant) {
        if !self.dirty {
            self.dirty = true;
            self.due = Some(now + Duration::from_millis(20));
        }
    }
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.due
    }
    pub(crate) fn pending(&self) -> bool {
        self.dirty
    }
    pub(crate) fn require(&mut self) {
        self.dirty = true;
        self.due = None;
    }
    pub(crate) fn blocked(&self) -> bool {
        self.dirty && self.due.is_none()
    }
    pub(crate) fn block(&mut self) {
        self.due = None;
    }
    pub(crate) fn retry(&mut self, now: Instant) {
        if self.dirty {
            self.due = Some(now);
        }
    }
    pub(crate) fn accepted(&mut self) {
        self.reset();
    }
    pub(crate) fn reset(&mut self) {
        self.dirty = false;
        self.due = None;
    }
}

pub(crate) async fn wait(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    #[test]
    fn deadlines302_echo_arms_once_and_cancels_only_after_acceptance() {
        let now = Instant::now();
        let mut echo = EchoDeadline::default();
        assert_eq!(echo.deadline(), None);
        echo.input(now);
        assert_eq!(echo.deadline(), Some(now + Duration::from_millis(20)));
        echo.input(now + Duration::from_millis(10));
        assert_eq!(echo.deadline(), Some(now + Duration::from_millis(20)));
        echo.block();
        assert_eq!(echo.deadline(), None);
        echo.input(now + Duration::from_secs(1));
        assert_eq!(
            echo.deadline(),
            None,
            "new input cannot rescue a lost capacity wake"
        );
        echo.retry(now);
        assert_eq!(echo.deadline(), Some(now));
        echo.accepted();
        assert_eq!(echo.deadline(), None);
        echo.input(now);
        echo.reset();
        assert_eq!(echo.deadline(), None);
    }
}
