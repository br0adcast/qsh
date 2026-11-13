use super::*;
use crate::session_owner::{authorization_contract::*, resource_contract::*};
use std::sync::{Arc, Mutex};
use transport::{
    auth::Principal,
    channel::{ChannelKind, OpenRequest},
    channel_geometry::ChannelInstance,
    channel_open::*,
    session_resume::*,
    shell_server::SessionScreen,
};
fn setup() -> (OwnerResourceClient, Arc<Mutex<ResourceLedger>>) {
    let byte = ByteLimits {
        channel_bytes: 1 << 26,
        session_bytes: 1 << 27,
        account_bytes: 1 << 28,
        global_bytes: 1 << 29,
    };
    let mut ledger = ResourceLedger::new(
        LedgerInstance::new([82; 16]).unwrap(),
        ResourceLimits {
            max_reservations: 8,
            screen: ScreenLimits {
                global_cells: 100_000_000,
                account_cells: 100_000_000,
                global_rows: 100_000_000,
                account_rows: 100_000_000,
                global_models: 1,
                account_models: 1,
            },
            snapshot_transfer: byte,
            control_queue: byte,
        },
    )
    .unwrap();
    let reg = ledger
        .register_fresh_principal(AuthenticatedPrincipalRef::new([82; 16]).unwrap(), 1000)
        .unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    (OwnerResourceClient::new(ledger.clone(), reg), ledger)
}
fn lease(client: OwnerResourceClient, id: u64) -> HostScreenLease {
    let size = TerminalSize::new(4, 2).unwrap();
    let slots = ScreenEnvelope::new(size).charge().unwrap();
    let r = Reservation {
        id: ReservationId::new(id).unwrap(),
        principal: client.principal(),
        locator: SessionLocator {
            session: RetainedSessionId::new([82; 16]).unwrap(),
            owner: OwnerInstance::new([82; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ScreenModel,
        bytes: 0,
        screen_charge: Some(charge(slots, 1).unwrap()),
    };
    HostScreenLease::admit(client, r, RequestId::new(id).unwrap(), size).unwrap()
}
#[test]
fn screen_host_factory_requires_exact_registered_capsule_and_drops_only_its_model() {
    let (client, ledger) = setup();
    let opens = ChannelOpenRegistry::new(Default::default());
    let session = opens.session().unwrap();
    let owner = Principal {
        uid: 1000,
        name: "fixture".into(),
        identity: "fixture".into(),
        incarnation: 0,
    };
    let request = OpenRequest {
        stream: 16,
        kind: ChannelKind::Shell,
        cols: 4,
        rows: 2,
        screen: true,
        command: vec![],
    };
    let job = opens
        .try_reserve(
            &session,
            OpenRequestSnapshot {
                owner: owner.clone(),
                login: [0; 16],
                request: request.clone(),
                term: None,
                identity: OpenIdentity {
                    session: session.id(),
                    instance: ChannelInstance::new(1).unwrap(),
                    stream: 16,
                    generation: 1,
                    invalidation_epoch: 0,
                },
            },
        )
        .unwrap();
    let factory = Arc::new(RetainedScreenFactory::new());
    let registration = factory.register(&job, lease(client, 1)).unwrap();
    assert!(factory
        .take(&owner, [0; 16], &request, &OpenCustody::new())
        .is_err());
    let mut wrong = request.clone();
    wrong.cols = 5;
    assert!(factory
        .take(&owner, [0; 16], &wrong, job.custody())
        .is_err());
    assert_eq!(ledger.lock().unwrap().reservations(), 1);
    let mut model = factory
        .take(&owner, [0; 16], &request, job.custody())
        .unwrap();
    assert_eq!(model.absorb(b"\x1b[18t").unwrap(), b"\x1b[8;2;4t");
    assert!(factory
        .take(&owner, [0; 16], &request, job.custody())
        .is_err());
    drop(registration);
    assert_eq!(ledger.lock().unwrap().reservations(), 1);
    drop(model);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
    job.cancel();
}
#[test]
fn screen_host_resize_pins_receipts_and_cancellation_preserves_actual_model() {
    let (client, ledger) = setup();
    let mut lease = lease(client.clone(), 1);
    let old = lease.admitted.reservation();
    let receipt = ReservationReceipt {
        id: lease.admitted.cleanup(),
        reservation: old.id,
        locator: old.locator,
        channel: old.channel,
    };
    let before = lease.envelope;
    {
        let pending = lease.prepare(TerminalSize::new(2, 1).unwrap()).unwrap();
        assert!(ledger.lock().unwrap().release(old, receipt).is_err());
        drop(pending);
    }
    assert_eq!(lease.envelope, before);
    assert_eq!(ledger.lock().unwrap().reservations(), 1);
    let mut screen = crate::screen::PtyScreen::with_host_lease(lease);
    screen.absorb(b"ok").unwrap();
    let snapshot = screen.snapshot();
    drop(
        screen
            .prepare_resize(TerminalSize::new(2, 1).unwrap())
            .unwrap(),
    );
    assert_eq!(screen.snapshot(), snapshot);
    screen
        .prepare_resize(TerminalSize::new(2, 1).unwrap())
        .unwrap()
        .commit();
    assert_eq!(screen.absorb(b"\x1b[18t").unwrap(), b"\x1b[8;1;2t");
    assert!(ledger.lock().unwrap().release(old, receipt).is_err());
    drop(screen);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
}

#[tokio::test]
async fn screen_control_explicit_scope_observes_actual_join_and_metadata_lifetime() {
    use crate::session_owner::screen_control::*;
    let (client, ledger) = setup();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: client.principal(),
        locator: SessionLocator {
            session: RetainedSessionId::new([82; 16]).unwrap(),
            owner: OwnerInstance::new([82; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 65536,
        screen_charge: None,
    };
    let context = ScreenControlContext::new(scope.clone(), r, RequestId::new(1).unwrap());
    let ticket = context.start(client, r.locator, r.channel).await.unwrap();
    assert!(ticket.healthy());
    assert_eq!(scope.registered(), 1);
    ticket.stop();
    ticket.join().await.unwrap();
    assert_eq!(scope.registered(), 0);
    assert_eq!(
        ledger.lock().unwrap().reservations(),
        1,
        "ticket still owns actual state backing"
    );
    drop(ticket);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
}

#[test]
fn screen_host_factory_refuses_foreign_trusted_uid_before_model_construction() {
    let (client, ledger) = setup();
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(
            &session,
            OpenRequestSnapshot {
                owner: Principal {
                    uid: 2000,
                    name: "foreign".into(),
                    identity: "foreign".into(),
                    incarnation: 0,
                },
                login: [0; 16],
                request: OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 4,
                    rows: 2,
                    screen: true,
                    command: vec![],
                },
                term: None,
                identity: OpenIdentity {
                    session: session.id(),
                    instance: ChannelInstance::new(1).unwrap(),
                    stream: 16,
                    generation: 1,
                    invalidation_epoch: 0,
                },
            },
        )
        .unwrap();
    let factory = Arc::new(RetainedScreenFactory::new());
    assert!(
        factory.register(&job, lease(client, 1)).is_err(),
        "foreign canonical uid consumed another account's model"
    );
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
    job.cancel();
}

fn control_context(
    client: &OwnerResourceClient,
    scope: crate::session_owner::screen_control::ControlTaskScope,
) -> crate::session_owner::screen_control::ScreenControlContext {
    use crate::session_owner::screen_control::ScreenControlContext;
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: client.principal(),
        locator: SessionLocator {
            session: RetainedSessionId::new([82; 16]).unwrap(),
            owner: OwnerInstance::new([82; 16]).unwrap(),
        },
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 65536,
        screen_charge: None,
    };
    ScreenControlContext::new(scope, r, RequestId::new(1).unwrap())
}
#[tokio::test]
async fn screen_control_concurrent_scope_drain_wakes_every_actual_join_waiter() {
    use crate::session_owner::screen_control::*;
    let (client, ledger) = setup();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let context = control_context(&client, scope.clone());
    let locator = SessionLocator {
        session: RetainedSessionId::new([82; 16]).unwrap(),
        owner: OwnerInstance::new([82; 16]).unwrap(),
    };
    let ticket = Arc::new(
        context
            .start(client, locator, ChannelInstance::new(1).unwrap())
            .await
            .unwrap(),
    );
    let observing = ticket.clone();
    let mut joiner = tokio::spawn(async move { observing.join().await });
    tokio::task::yield_now().await;
    scope.drain().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_millis(100), &mut joiner).await;
    if result.is_err() {
        joiner.abort();
        let _ = joiner.await;
        panic!("scope drain lost the engine's actual join waiter");
    }
    result.unwrap().unwrap().unwrap();
    drop(ticket);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
}
#[test]
fn screen_control_disabled_timer_startup_is_contained_and_keeps_unknown_debt() {
    let result = std::thread::spawn(|| {
        use crate::session_owner::screen_control::*;
        let (client, ledger) = setup();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let scope = ControlTaskScope::new(runtime.handle().clone());
        let context = control_context(&client, scope.clone());
        let locator = SessionLocator {
            session: RetainedSessionId::new([82; 16]).unwrap(),
            owner: OwnerInstance::new([82; 16]).unwrap(),
        };
        runtime.block_on(async {
            assert!(context
                .start(client, locator, ChannelInstance::new(1).unwrap())
                .await
                .is_err());
        });
        assert_eq!(scope.registered(), 0);
        assert_eq!(ledger.lock().unwrap().reservations(), 1);
    })
    .join();
    assert!(
        result.is_ok(),
        "implicit runtime timer panic escaped the owned task boundary"
    );
}

#[tokio::test]
async fn screen_control_fair_deadlines_coalesce_wakes_and_idle_has_no_periodic_poll() {
    use crate::session_owner::screen_control::*;
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::{Duration, Instant},
    };
    struct Timed {
        screen: Mutex<crate::screen::PtyScreen>,
        visits: AtomicUsize,
        answers: Mutex<Vec<Vec<u8>>>,
        busy: AtomicBool,
    }
    impl ControlChannel for Timed {
        fn service(&self, now: Instant) -> ControlPoll {
            self.visits.fetch_add(1, Ordering::SeqCst);
            if self.busy.load(Ordering::SeqCst) {
                return ControlPoll {
                    deadline: None,
                    busy: true,
                };
            }
            let mut screen = self.screen.lock().unwrap();
            let replies = screen.flush_due_output(now).unwrap();
            if !replies.is_empty() {
                self.answers.lock().unwrap().push(replies);
            }
            ControlPoll {
                deadline: screen.sync_deadline(),
                busy: false,
            }
        }
    }
    let (client, ledger) = setup();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let context = control_context(&client, scope.clone());
    let locator = SessionLocator {
        session: RetainedSessionId::new([82; 16]).unwrap(),
        owner: OwnerInstance::new([82; 16]).unwrap(),
    };
    let ticket = context
        .start(client, locator, ChannelInstance::new(1).unwrap())
        .await
        .unwrap();
    let budget = Arc::new(crate::screen_budget::ScreenBudget::new(
        crate::screen_budget::BudgetLimits {
            global_cells: 1024,
            owner_cells: 1024,
            global_rows: 1024,
            owner_rows: 1024,
            global_models: 2,
            owner_models: 2,
        },
    ));
    let create = || {
        Arc::new(Timed {
            screen: Mutex::new(
                crate::screen::PtyScreen::try_new(
                    TerminalSize::new(4, 2).unwrap(),
                    1000,
                    budget.clone(),
                )
                .unwrap(),
            ),
            visits: AtomicUsize::new(0),
            answers: Mutex::new(Vec::new()),
            busy: AtomicBool::new(false),
        })
    };
    let first = create();
    let second = create();
    first.busy.store(true, Ordering::SeqCst);
    ticket.register(first.clone()).unwrap();
    ticket.register(second.clone()).unwrap();
    second
        .screen
        .lock()
        .unwrap()
        .absorb(b"\x1b[?2026h\x1b[18t")
        .unwrap();
    ticket.wake();
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.answers.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        *second.answers.lock().unwrap(),
        vec![b"\x1b[8;2;4t".to_vec()]
    );
    first.busy.store(false, Ordering::SeqCst);
    for _ in 0..500 {
        ticket.wake();
    }
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    let counts = (
        first.visits.load(Ordering::SeqCst),
        second.visits.load(Ordering::SeqCst),
    );
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        counts,
        (
            first.visits.load(Ordering::SeqCst),
            second.visits.load(Ordering::SeqCst)
        ),
        "idle task kept polling after all deadlines/busy work ended"
    );
    ticket.stop();
    ticket.join().await.unwrap();
    drop(ticket);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
}
