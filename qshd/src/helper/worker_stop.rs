//! Worker-local sticky stop; a request is never a completion receipt.

use super::{spawner::EndWorker, worker_protocol::StopReason};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StopSnapshot {
    pub first_stop: Option<StopReason>,
    pub first_failure: Option<StopReason>,
}

#[derive(Clone, Default)]
pub(crate) struct WorkerStop {
    shutdown: transport::Shutdown,
    state: Arc<Mutex<StopSnapshot>>,
}
impl WorkerStop {
    pub(crate) fn shutdown(&self) -> transport::Shutdown {
        self.shutdown.clone()
    }
    pub(crate) fn nonce_pool_hook(&self) -> EndWorker {
        self.fatal_hook(StopReason::NoncePoolLost)
    }
    pub(super) fn snapshot(&self) -> StopSnapshot {
        *self.state.lock().unwrap()
    }
    pub(super) fn request(&self, reason: StopReason) -> bool {
        let first_failure = {
            let mut state = self.state.lock().unwrap();
            state.first_stop.get_or_insert(reason);
            if reason != StopReason::Requested && state.first_failure.is_none() {
                state.first_failure = Some(reason);
                true
            } else {
                false
            }
        };
        // Wake the real manager only after releasing our outcome lock.
        self.shutdown.request();
        first_failure
    }
    pub(super) fn fatal_hook(&self, reason: StopReason) -> EndWorker {
        let stop = self.clone();
        Arc::new(move |message| {
            if stop.request(reason) {
                crate::log::warn("worker", message);
            }
        })
    }
}

/// Linux requires its prepared private peer. Other system targets retain their
/// previous local-only profile, without a native process qualification claim.
pub(crate) struct WorkerContext {
    stop: WorkerStop,
    #[cfg(target_os = "linux")]
    control: (std::os::unix::net::UnixStream, u32),
}
impl WorkerContext {
    pub(super) fn new(
        stop: WorkerStop,
        control: Option<(std::os::unix::net::UnixStream, u32)>,
    ) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                stop,
                control: control.ok_or_else(|| {
                    anyhow::anyhow!("owned Linux worker control was not prepared")
                })?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            drop(control);
            Ok(Self { stop })
        }
    }
    pub(crate) fn stop(&self) -> WorkerStop {
        self.stop.clone()
    }
    pub(crate) async fn drive<T>(self, manager: impl std::future::Future<Output = T>) -> T {
        #[cfg(target_os = "linux")]
        {
            super::worker_child::drive(self.control.0, self.control.1, self.stop, manager).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            manager.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn worker40_actual_owned_channel_loss_requests_the_shared_manager_stop() {
        let (worker_channels, helper_channels) = super::super::channel::pair().unwrap();
        let (worker_auth, helper_auth) = super::super::channel::pair().unwrap();
        let config = super::super::HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: super::super::server::STARTUP_REPORT_TIMEOUT,
            verify_timeout: std::time::Duration::from_secs(3),
            pam_service: super::super::config::PAM_SERVICE.to_string(),
            pam_confdir: None,
        };
        let stop = WorkerStop::default();
        let (mut spawner, mut auth, _reports) = super::super::spawner::worker_clients_with_stop(
            worker_channels,
            worker_auth,
            &config,
            stop.clone(),
        )
        .unwrap();
        let mut auxiliary = super::super::worker_threads::WorkerThreads::default();
        auxiliary.absorb(spawner.take_auxiliary());
        auxiliary.absorb(auth.take_auxiliary());
        drop(helper_channels);
        let observed = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            stop.shutdown().requested(),
        )
        .await
        .is_ok();
        // Join the real owned readers/releaser before asserting on the RED path.
        let joined = auxiliary.stop_and_join();
        drop((spawner, auth, helper_auth));
        assert_eq!(joined.joined, 0b1110);
        assert!(
            observed,
            "owned channel reader lost its helper without stopping manager"
        );
        assert_eq!(stop.snapshot().first_failure, Some(StopReason::ChannelLost));
    }

    #[test]
    fn worker40_requested_stop_does_not_mask_a_later_retained_failure() {
        let stop = WorkerStop::default();
        let observer = stop.shutdown();
        stop.request(StopReason::Requested);
        stop.fatal_hook(StopReason::AuthLost)("controlled authentication loss");
        stop.fatal_hook(StopReason::NoncePoolLost)("controlled later pool loss");
        assert!(
            observer.is_requested(),
            "owned stop did not reach the real manager token"
        );
        assert_eq!(
            stop.snapshot(),
            StopSnapshot {
                first_stop: Some(StopReason::Requested),
                first_failure: Some(StopReason::AuthLost),
            }
        );
    }

    #[test]
    fn worker40_returning_fatal_hook_is_shared_with_late_shutdown_observers() {
        let stop = WorkerStop::default();
        let hook = stop.fatal_hook(StopReason::RequiredTellLost);
        let worker = std::thread::spawn(move || hook("controlled required tell failure"));
        worker.join().unwrap();
        stop.request(StopReason::Requested);
        assert!(stop.shutdown().is_requested());
        assert_eq!(
            stop.snapshot(),
            StopSnapshot {
                first_stop: Some(StopReason::RequiredTellLost),
                first_failure: Some(StopReason::RequiredTellLost),
            }
        );
    }
}
