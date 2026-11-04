//! Select an admission path only from the dedicated atomic-signal probe.
use std::time::Instant;

pub(crate) enum Prepared<M, K> {
    Modern(M),
    Keeper(K),
}

impl<M, K> Prepared<M, K> {
    /// Move the single screen/custody context into exactly the selected creator.
    /// Its result is final, including a custody-bearing creation failure.
    pub(crate) fn spawn<C, R>(
        self,
        context: C,
        modern: impl FnOnce(M, C) -> R,
        keeper: impl FnOnce(K, C) -> R,
    ) -> R {
        match self {
            Self::Modern(owner) => modern(owner, context),
            Self::Keeper(owner) => keeper(owner, context),
        }
    }
}

pub(super) fn select<M, K, E>(
    modern_available: bool,
    modern: impl FnOnce() -> Result<M, E>,
    keeper: impl FnOnce() -> Result<K, E>,
) -> Result<Prepared<M, K>, E> {
    if modern_available {
        modern().map(Prepared::Modern)
    } else {
        keeper().map(Prepared::Keeper)
    }
}

pub(super) fn check_startup(end: Instant, cancelled: bool) -> Result<(), &'static str> {
    if cancelled {
        Err("keeper startup was cancelled")
    } else if Instant::now() >= end {
        Err("keeper startup deadline expired")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn personal_selection_uses_only_the_dedicated_capability() {
        for available in [true, false] {
            let modern = Cell::new(0);
            let keeper = Cell::new(0);
            let selected = select::<_, _, &str>(
                available,
                || {
                    modern.set(modern.get() + 1);
                    Ok(17)
                },
                || {
                    keeper.set(keeper.get() + 1);
                    Ok(23)
                },
            )
            .unwrap();
            match selected {
                Prepared::Modern(value) => {
                    assert!(available);
                    assert_eq!(value, 17);
                }
                Prepared::Keeper(value) => {
                    assert!(!available);
                    assert_eq!(value, 23);
                }
            }
            assert_eq!(
                (modern.get(), keeper.get()),
                if available { (1, 0) } else { (0, 1) }
            );
        }
    }

    #[test]
    fn personal_refusals_never_change_backend() {
        for reason in [
            "unsupported runtime",
            "malformed metadata",
            "SIGCHLD",
            "observation denied",
            "ENOSYS from observation",
        ] {
            for available in [true, false] {
                let modern = Cell::new(0);
                let keeper = Cell::new(0);
                let result = select::<(), (), _>(
                    available,
                    || {
                        modern.set(modern.get() + 1);
                        Err(reason)
                    },
                    || {
                        keeper.set(keeper.get() + 1);
                        Err(reason)
                    },
                );
                assert!(matches!(result, Err(actual) if actual == reason));
                assert_eq!(
                    (modern.get(), keeper.get()),
                    if available { (1, 0) } else { (0, 1) }
                );
            }
        }
    }

    #[test]
    fn personal_startup_checks_keep_the_original_deadline() {
        let end = Instant::now() + Duration::from_secs(30);
        assert!(check_startup(end, false).is_ok());
        assert_eq!(
            check_startup(end, true),
            Err("keeper startup was cancelled")
        );
        let expired = Instant::now() - Duration::from_secs(1);
        for _ in 0..3 {
            assert_eq!(
                check_startup(expired, false),
                Err("keeper startup deadline expired")
            );
        }
    }
}

#[cfg(test)]
mod factory_tests {
    use super::*;
    use crate::darwin_process_scope::keeper_pty::{Created, Master, Startup};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use transport::channel_open::{
        ChannelOpenRegistry, CleanupAuthority, CleanupStatus, OpenIdentity, OpenRequestSnapshot,
        SpawnCleanup,
    };
    use transport::channel_server::{ChannelWait, ChildStatus};

    struct Wait(Arc<AtomicUsize>);
    impl Drop for Wait {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl ChannelWait for Wait {
        fn poll_exit(&mut self) -> ChildStatus {
            ChildStatus::Reaped { code: Some(37) }
        }
        fn kill(&mut self) {}
        fn wait(self: Box<Self>) -> i32 {
            37
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            authority.reaped()
        }
    }

    #[test]
    fn personal_selected_creation_keeps_one_capsule_without_fallback() {
        // These are portable construction/registry controls. Native identity,
        // helper execution and waits remain the separate Darwin runtime gate.
        for available in [true, false] {
            for fail in [false, true] {
                let registry = ChannelOpenRegistry::new(Default::default());
                let session = registry.session().unwrap();
                let owner = transport::auth::Principal {
                    uid: 1000,
                    name: "personal-control".into(),
                    identity: "personal-control".into(),
                    incarnation: 0,
                };
                let request = transport::channel::OpenRequest {
                    stream: 16,
                    kind: transport::channel::ChannelKind::Command,
                    cols: 2,
                    rows: 1,
                    screen: true,
                    command: b"/bin/true".to_vec(),
                };
                let budget = Arc::new(crate::screen_budget::ScreenBudget::new(Default::default()));
                let screen =
                    crate::channel_backend::make_screen(&request, &owner, budget.clone()).unwrap();
                let job = registry
                    .try_reserve(
                        &session,
                        OpenRequestSnapshot {
                            owner,
                            login: [0; 16],
                            request,
                            term: None,
                            identity: OpenIdentity {
                                session: session.id(),
                                instance: transport::channel_geometry::ChannelInstance::new(1)
                                    .unwrap(),
                                stream: 16,
                                generation: 0,
                                invalidation_epoch: 0,
                            },
                        },
                    )
                    .unwrap();
                let drops = Arc::new(AtomicUsize::new(0));
                let modern = AtomicUsize::new(0);
                let keeper = AtomicUsize::new(0);
                let create = |_, (custody, screen)| {
                    Created::new(
                        Box::new(Master::new(tempfile::tempfile().unwrap())),
                        Box::new(Wait(drops.clone())),
                        if fail {
                            Startup::Failed("selected creator refused".into())
                        } else {
                            Startup::Ready
                        },
                        custody,
                        screen,
                    )
                    .finish()
                };
                let selected = select::<_, _, ()>(available, || Ok(17), || Ok(23)).unwrap();
                let outcome = selected.spawn(
                    (job.custody(), screen),
                    |token, context| {
                        assert_eq!(token, 17);
                        modern.fetch_add(1, Ordering::SeqCst);
                        create(token, context)
                    },
                    |token, context| {
                        assert_eq!(token, 23);
                        keeper.fetch_add(1, Ordering::SeqCst);
                        create(token, context)
                    },
                );
                assert_eq!(
                    (modern.load(Ordering::SeqCst), keeper.load(Ordering::SeqCst)),
                    if available { (1, 0) } else { (0, 1) }
                );
                assert_eq!(drops.load(Ordering::SeqCst), 0);
                assert_eq!(session.occupied(), 1);
                if fail {
                    let failure = outcome.err().expect("selected refusal must propagate");
                    assert_eq!(failure.reason, "selected creator refused");
                    let SpawnCleanup::Pending(ticket) = failure.cleanup else {
                        panic!("post-creation refusal lost its capsule")
                    };
                    assert!(matches!(ticket.cleanup(), CleanupStatus::Confirmed(_)));
                    assert!(matches!(job.cleanup(), CleanupStatus::Confirmed(_)));
                } else {
                    let (channel, slot) = job
                        .adopt(outcome.unwrap())
                        .unwrap_or_else(|_| panic!("single created owner failed adoption"));
                    assert_eq!(channel.wait.wait(), 37);
                    drop(channel.reader);
                    drop(channel.writer);
                    drop(channel.resize);
                    drop(channel.screen);
                    drop(slot);
                }
                assert_eq!(session.occupied(), 0);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(budget.used(), crate::screen_budget::Usage::default());
            }
        }
    }
}
