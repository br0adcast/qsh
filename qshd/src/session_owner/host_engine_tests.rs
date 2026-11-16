use super::*;
use crate::session_owner::authorization::{AuthenticatedPeer, HostMode, PolicyResult};
use crate::session_owner::host::{HostDecision, HostLimits, HostState};
use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use crate::session_owner::resources::OwnerResourceClient;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use transport::channel::OpenRequest;
use transport::channel_open::{
    ChannelOpenRegistry, OpenCustody, OpenLimits, SpawnFailure, UninstalledChannel,
};
use transport::channel_server::{ChannelSpawner, RestartSignal};
use transport::session_manager::LoginId;
use transport::session_resume::SessionLocator;
use transport::Principal;

struct RefusingSpawner {
    registry: Arc<ChannelOpenRegistry>,
    calls: Arc<AtomicUsize>,
}

impl ChannelSpawner for RefusingSpawner {
    fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
        self.registry.clone()
    }

    fn spawn(
        &self,
        _: &Principal,
        _: LoginId,
        _: &OpenRequest,
        _: Option<&str>,
        custody: &OpenCustody,
    ) -> Result<UninstalledChannel, SpawnFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(custody.refuse_before_creation("binding must not spawn a channel".into()))
    }
}

struct Clock;

impl crate::session_owner::engine::MonotonicClock for Clock {
    fn now(&self) -> u64 {
        0
    }
}

fn empty_engine(
    locator: SessionLocator,
    client: OwnerResourceClient,
) -> (
    crate::session_owner::engine::SessionOwnerEngine,
    tokio::sync::watch::Sender<RestartSignal>,
    Arc<AtomicUsize>,
) {
    empty_engine_account(locator, client, 1000, "fixture-account")
}

fn empty_engine_account(
    locator: SessionLocator,
    client: OwnerResourceClient,
    uid: u32,
    name: &str,
) -> (
    crate::session_owner::engine::SessionOwnerEngine,
    tokio::sync::watch::Sender<RestartSignal>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let spawner = Arc::new(RefusingSpawner {
        registry: ChannelOpenRegistry::new(OpenLimits::default()),
        calls: calls.clone(),
    });
    let (sender, restart) = tokio::sync::watch::channel(RestartSignal::IDLE);
    let engine = crate::session_owner::engine::SessionOwnerEngine::new(
        locator,
        Principal {
            uid,
            name: name.into(),
            identity: "synthetic binding fixture".into(),
            incarnation: 0,
        },
        [61; 16],
        spawner,
        client,
        Arc::new(Clock),
        restart,
    )
    .unwrap();
    (engine, sender, calls)
}

// These binding controls exercise the host state machine's existing private
// policy fixture. The complete transaction will separately use real Personal
// admission; no production policy authority is introduced by this fixture.
fn catalog() -> (
    HostState,
    crate::session_owner::authorization::AuthenticationAttempt,
) {
    catalog_with_limits(ByteLimits {
        channel_bytes: 32 << 20,
        session_bytes: 64 << 20,
        account_bytes: 128 << 20,
        global_bytes: 256 << 20,
    })
}
fn catalog_with_limits(
    bytes: ByteLimits,
) -> (
    HostState,
    crate::session_owner::authorization::AuthenticationAttempt,
) {
    let resources = ResourceLimits {
        max_reservations: 128,
        screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let mode = HostMode::System;
    let mut host =
        HostState::new(mode, HostLimits::new(resources, 4, 4, 4, 4, 100).unwrap()).unwrap();
    let frontend = host
        .admit_frontend(AuthenticatedPeer::for_test(host.instance(), mode))
        .unwrap();
    let intent = host.begin_authentication(frontend, 0, 100).unwrap();
    let HostDecision::Authenticated(attempt) = host
        .apply_policy_result(
            PolicyResult::allow_for_test(intent, 1000, "fixture-account"),
            1,
        )
        .unwrap()
    else {
        panic!("controlled host authentication did not produce its attempt")
    };
    (host, attempt)
}

#[tokio::test]
async fn host_engine_binding_keeps_never_established_registration_pinned_after_unknown_drop() {
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart, calls) = empty_engine(locator, provisioning.client());
    let bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(failure) => {
            let (error, provisioning, engine) = failure.into_parts();
            drop((provisioning, engine));
            panic!("matching catalog-issued engine was refused: {error:?}")
        }
    };
    host.sweep(30_002).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "binding lost its catalog registration"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(bound);
    host.sweep(60_003).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "unknown engine destruction cannot authorize registration retirement"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_engine_same_ledger_wrong_registration_refuses_and_returns_both_owned_inputs() {
    let (mut host, attempt) = catalog();
    let (first, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (_, other) = host.create_session_provisioned(attempt, 3).unwrap();
    let (engine, _restart, calls) = empty_engine(first, other.client());
    let failure = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => {
            drop(bound);
            panic!("another registration on the same host acquired the binding")
        }
        Err(failure) => failure,
    };
    let (error, returned_provisioning, returned_engine) = failure.into_parts();
    assert!(matches!(error, LocalEngineError::Binding));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(host.catalog_len(), 2);
    drop(returned_engine);

    let (correct, _correct_restart, correct_calls) =
        empty_engine(first, returned_provisioning.client());
    let bound = match host.bind_local_engine(returned_provisioning, correct) {
        Ok(bound) => bound,
        Err(failure) => {
            let (error, provisioning, engine) = failure.into_parts();
            drop((provisioning, engine));
            panic!("refusal consumed or corrupted the returned catalog custody: {error:?}")
        }
    };
    assert_eq!(correct_calls.load(Ordering::SeqCst), 0);
    drop(bound);
}

#[tokio::test]
async fn host_engine_binding_refuses_wrong_catalog_and_canonical_account_before_spawn() {
    for (uid, name) in [(1001, "fixture-account"), (1000, "other-account")] {
        let (mut host, attempt) = catalog();
        let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
        let (engine, _restart, calls) =
            empty_engine_account(locator, provisioning.client(), uid, name);
        let failure = match host.bind_local_engine(provisioning, engine) {
            Ok(_) => panic!("noncanonical account was accepted"),
            Err(failure) => failure,
        };
        let (error, returned, engine) = failure.into_parts();
        assert!(matches!(error, LocalEngineError::Binding));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(engine);
        // Each iteration receives exactly the original catalog-issued custody.
        let (mut foreign, _) = catalog();
        let (engine, _restart, _) = empty_engine(locator, returned.client());
        let failure = match foreign.bind_local_engine(returned, engine) {
            Ok(_) => panic!("another catalog bound the engine"),
            Err(failure) => failure,
        };
        let (_, returned, engine) = failure.into_parts();
        drop(engine);
        let (engine, _restart, _) = empty_engine(locator, returned.client());
        let bound = match host.bind_local_engine(returned, engine) {
            Ok(bound) => bound,
            Err(failure) => {
                let (error, _, _) = failure.into_parts();
                panic!("valid returned custody was refused: {error:?}")
            }
        };
        drop(bound);
    }
}

#[tokio::test]
async fn host_engine_admitted_open_installs_real_inert_workers_and_releases_exact_custody() {
    use crate::session_owner::engine::{AdmittedOwnerChannelResources, EngineError};
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;

    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let client = provisioning.client();
    let channel = ChannelInstance::new(1).unwrap();
    let cleanup = RequestId::new(7).unwrap();
    let reserve = |kind, bytes| {
        provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind,
                    bytes,
                    screen_charge: None,
                },
                cleanup,
            )
            .unwrap()
    };
    let history = reserve(ReservationKind::OutputHistory, 4096);
    let control = reserve(ReservationKind::ControlQueue, 131072);
    assert!(
        client.reserve(history.reservation(), cleanup).is_err(),
        "host-issued admission must not weaken raw reserve refusal"
    );
    let (mut engine, _restart) =
        crate::session_owner::engine::tests::integrated::host_fixture(locator, client);
    let front = engine
        .attach_trusted(Attachment {
            locator,
            frontend: FrontendGeneration::new([81; 16]).unwrap(),
            epoch: AttachEpoch::new(1).unwrap(),
        })
        .unwrap();
    let result = engine
        .open_admitted(
            &front,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(
                history,
                control,
                128,
                InputEpoch::new([82; 16]).unwrap(),
            ),
        )
        .await;
    // Cleanup is independent of the assertion, including the RED refusal path.
    let cleanup_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), engine.close_session()).await;
    assert!(
        matches!(result, Ok(found) if found == channel),
        "valid admitted open did not install the actual engine pipeline: {result:?}"
    );
    assert!(!matches!(result, Err(EngineError::Resource(_))));
    assert_eq!(cleanup_result.unwrap().unwrap().len(), 1);
    host.sweep(30_003).unwrap();
    assert_eq!(
        host.catalog_len(),
        0,
        "destroyed admitted backing retained debt"
    );
}

#[tokio::test]
async fn host_engine_admitted_open_refuses_foreign_kind_channel_and_cleanup_before_spawn() {
    use crate::session_owner::engine::{AdmittedOwnerChannelResources, EngineError};
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;

    for case in 0..5 {
        let (mut host, attempt) = catalog();
        let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
        let (foreign_locator, foreign) = host.create_session_provisioned(attempt, 3).unwrap();
        let (mut engine, _restart, calls) = empty_engine(locator, provisioning.client());
        let channel = ChannelInstance::new(1).unwrap();
        let cleanup = RequestId::new(7).unwrap();
        let reserve = |owner: &crate::session_owner::host_resources::OwnerProvisioning,
                       channel,
                       kind,
                       bytes,
                       cleanup| {
            // Use the owner's sealed locator, never reconstruct a registration.
            owner
                .reserve(
                    OwnerResourceRequest {
                        locator: if case == 0 { foreign_locator } else { locator },
                        channel,
                        kind,
                        bytes,
                        screen_charge: None,
                    },
                    cleanup,
                )
                .unwrap()
        };
        let owner = if case == 0 { &foreign } else { &provisioning };
        let history = reserve(
            owner,
            channel,
            if case == 1 {
                ReservationKind::SnapshotTransfer
            } else {
                ReservationKind::OutputHistory
            },
            4096,
            cleanup,
        );
        let control = reserve(
            owner,
            if case == 2 {
                ChannelInstance::new(2).unwrap()
            } else {
                channel
            },
            ReservationKind::ControlQueue,
            if case == 4 { 1 } else { 131072 },
            if case == 3 {
                RequestId::new(8).unwrap()
            } else {
                cleanup
            },
        );
        let front = engine
            .attach_trusted(Attachment {
                locator,
                frontend: FrontendGeneration::new([81; 16]).unwrap(),
                epoch: AttachEpoch::new(1).unwrap(),
            })
            .unwrap();
        let result = engine
            .open_admitted(
                &front,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                AdmittedOwnerChannelResources::new(
                    history,
                    control,
                    128,
                    InputEpoch::new([82; 16]).unwrap(),
                ),
            )
            .await;
        engine.close_session().await.unwrap();
        assert!(
            matches!(
                result,
                Err(EngineError::InvalidRequest | EngineError::Resource(_))
            ),
            "case {case} was not rejected by exact admitted validation: {result:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "case {case} spawned a channel"
        );
    }
}

#[tokio::test]
async fn host_engine_unused_admitted_control_anchor_releases_only_its_own_credit() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;

    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (other_locator, other) = host.create_session_provisioned(attempt, 3).unwrap();
    let request = |locator| OwnerResourceRequest {
        locator,
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 65536,
        screen_charge: None,
    };
    let cleanup = RequestId::new(1).unwrap();
    let unrelated = other.reserve(request(other_locator), cleanup).unwrap();
    let anchor = provisioning.reserve(request(locator), cleanup).unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let context =
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), anchor) {
            Ok(context) => context,
            Err(_) => panic!("exact admitted control anchor was refused"),
        };
    assert_eq!(scope.registered(), 0);
    drop(context);
    host.sweep(30_004).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "unused anchor was not released independently"
    );
    drop(unrelated);
    host.sweep(60_005).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "arbitrary token Drop refunded foreign debt"
    );
}

#[tokio::test]
async fn host_engine_admitted_recovery_returns_foreign_token_then_retains_real_consumer_backing() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (_, foreign) = host.create_session_provisioned(attempt, 3).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let token = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::SnapshotTransfer,
                bytes: 4096 + 16384 + 65536,
                screen_charge: None,
            },
            RequestId::new(11).unwrap(),
        )
        .unwrap();
    let token = match TransferAllowance::admit_reserved(foreign.client(), token, 4096) {
        Ok(_) => panic!("same-ledger foreign registration accepted recovery credit"),
        Err(refused) => refused.1,
    };
    let allowance = match TransferAllowance::admit_reserved(provisioning.client(), token, 4096) {
        Ok(allowance) => allowance,
        Err(_) => panic!("matching admitted recovery credit refused"),
    };
    let consumer = NoScreenConsumer::new(channel, allowance).unwrap();
    host.sweep(30_004).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "live independent consumer lost its actual credit"
    );
    drop(consumer);
    host.sweep(60_005).unwrap();
    assert_eq!(
        host.catalog_len(),
        0,
        "last consumer backing did not release exact credit"
    );
}

#[tokio::test]
async fn host_engine_admitted_control_start_joins_actual_task_and_retains_last_wake_charge() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let anchor = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::ControlQueue,
                bytes: 65536,
                screen_charge: None,
            },
            RequestId::new(12).unwrap(),
        )
        .unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let mut context =
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), anchor) {
            Ok(context) => context,
            Err(_) => panic!("exact admitted control anchor refused"),
        };
    let started = context.start(provisioning.client(), locator, channel).await;
    let ticket = match started {
        Ok(ticket) => ticket,
        Err(error) => {
            drop(context);
            panic!("admitted task startup failed: {error:?}")
        }
    };
    let wake = ticket.wake_handle();
    ticket.stop();
    let joined = tokio::time::timeout(std::time::Duration::from_secs(5), ticket.join()).await;
    drop(ticket);
    drop(context);
    host.sweep(30_003).unwrap();
    let held = host.catalog_len();
    drop(wake);
    host.sweep(60_004).unwrap();
    assert!(joined.unwrap().is_ok());
    assert_eq!(held, 1, "actual retained wake lost its charged backing");
    assert_eq!(
        host.catalog_len(),
        0,
        "last wake destruction did not release exact anchor"
    );
    assert_eq!(scope.registered(), 0);
}

#[tokio::test]
async fn host_engine_concurrent_policy_consumptions_reserve_exactly_one_engine_lease() {
    use crate::session_owner::host::HostError;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart, _) = empty_engine(locator, provisioning.client());
    let _bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let issue = host.begin_issue(attempt, locator, 3, 103).unwrap();
    let HostDecision::GrantIssued(offer) = host
        .apply_policy_result(
            PolicyResult::allow_for_test(issue, 1000, "fixture-account"),
            4,
        )
        .unwrap()
    else {
        panic!("grant not issued")
    };
    let one = host
        .begin_consume(attempt, offer.grant(), offer.binding(), 5, 105)
        .unwrap();
    let two = host
        .begin_consume(attempt, offer.grant(), offer.binding(), 6, 106)
        .unwrap();
    let first = host.apply_policy_result(
        PolicyResult::allow_for_test(one, 1000, "fixture-account"),
        7,
    );
    let second = host.apply_policy_result(
        PolicyResult::allow_for_test(two, 1000, "fixture-account"),
        8,
    );
    assert!(matches!(first, Ok(HostDecision::GrantConsumed(_))));
    assert!(
        matches!(second, Err(HostError::AlreadyAttached)),
        "second current policy result did not observe the serialized reserved lease: {second:?}"
    );
    assert!(matches!(
        host.begin_issue(attempt, locator, 9, 109),
        Err(HostError::AlreadyAttached)
    ));
}

#[tokio::test]
async fn host_engine_admitted_screen_open_uses_distinct_anchor_channel_and_model_custody() {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::{ReservationKind, ScreenCharge};
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use crate::session_owner::screen_owner::HostScreenLease;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let reserve = |kind, bytes, screen_charge, cleanup| {
        provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind,
                    bytes,
                    screen_charge,
                },
                RequestId::new(cleanup).unwrap(),
            )
            .unwrap()
    };
    let anchor = reserve(ReservationKind::ControlQueue, 65536, None, 1);
    let context =
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), anchor) {
            Ok(context) => context,
            Err(_) => panic!("admitted anchor refused"),
        };
    let size = terminal_size::TerminalSize::new(80, 24).unwrap();
    let slots = crate::screen_budget::ScreenEnvelope::new(size)
        .charge()
        .unwrap();
    let model = reserve(
        ReservationKind::ScreenModel,
        0,
        Some(ScreenCharge {
            cells: slots.cells as u64,
            rows: slots.rows as u64,
            models: 1,
        }),
        2,
    );
    let lease = match HostScreenLease::admit_reserved(provisioning.client(), model, size) {
        Ok(lease) => lease,
        Err(_) => panic!("admitted model refused"),
    };
    let history = reserve(ReservationKind::OutputHistory, 4096, None, 3);
    let control = reserve(ReservationKind::ControlQueue, 512 * 1024, None, 3);
    let (mut engine, _restart) =
        crate::session_owner::engine::tests::integrated::host_screen_fixture(
            locator,
            provisioning.client(),
            context,
        );
    let front = engine
        .attach_trusted(Attachment {
            locator,
            frontend: FrontendGeneration::new([81; 16]).unwrap(),
            epoch: AttachEpoch::new(1).unwrap(),
        })
        .unwrap();
    let opened = engine
        .open_screen_admitted(
            &front,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: true,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(
                history,
                control,
                128,
                InputEpoch::new([82; 16]).unwrap(),
            ),
            lease,
        )
        .await;
    let recovery_result = if opened.is_ok() {
        use crate::session_owner::recovery_runtime::TransferAllowance;
        use crate::session_owner::screen_recovery::{ScreenConsumer, ScreenRecoveryAllowance};
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !engine.catalog_available() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let quote = engine.screen_recovery_requirements(channel).unwrap();
        let transfer = |retained: usize, serial: u64| {
            let token = reserve(
                ReservationKind::SnapshotTransfer,
                (retained.max(1) + 16384 + 65536) as u64,
                None,
                serial,
            );
            match TransferAllowance::admit_reserved(provisioning.client(), token, retained) {
                Ok(allowance) => allowance,
                Err(_) => panic!("real transfer credit refused"),
            }
        };
        let mut transaction = engine.catalog(&front, transfer(0usize, 4)).unwrap();
        let mut consumer = ScreenConsumer::new(
            channel,
            [93; 16],
            size,
            1000,
            Arc::new(crate::screen_budget::ScreenBudget::new(
                crate::screen_budget::BudgetLimits::default(),
            )),
            transfer(quote.max_bytes, 5),
        )
        .unwrap();
        let bytes = reserve(
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
            None,
            6,
        );
        let scratch = reserve(ReservationKind::ScreenModel, 0, Some(quote.scratch), 6);
        let allowance =
            ScreenRecoveryAllowance::admit_reserved(provisioning.client(), bytes, scratch, quote);
        match allowance {
            Ok(allowance) => {
                let (request, evidence) = consumer.request(front.attachment());
                let id = RequestId::new(30).unwrap();
                let mut producer = engine
                    .recover_screen(
                        &front,
                        &mut transaction,
                        request,
                        &evidence,
                        RecoveryId::new([94; 16]).unwrap(),
                        id,
                        allowance,
                    )
                    .unwrap();
                consumer.begin(id, request, producer.start()).unwrap();
                while let Some(chunk) = producer.next_chunk().unwrap() {
                    consumer.consume(&chunk).unwrap();
                }
                let (end, ready) = producer.end().unwrap();
                transaction
                    .accept_consumed(consumer.finish(end, ready).unwrap())
                    .unwrap();
                engine.finish_recovery(&front, transaction).unwrap();
                drop((evidence, consumer));
                true
            }
            Err(_) => false,
        }
    } else {
        false
    };
    let cleanup =
        tokio::time::timeout(std::time::Duration::from_secs(5), engine.close_session()).await;
    drop(engine);
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
    assert!(
        matches!(opened, Ok(found) if found == channel),
        "admitted Screen pipeline failed: {opened:?}"
    );
    assert_eq!(cleanup.unwrap().unwrap().len(), 1);
    assert!(
        recovery_result,
        "actual quote-bound admitted Screen recovery refused"
    );
    assert!(drained.unwrap().is_ok());
    host.sweep(30_003).unwrap();
    assert_eq!(
        host.catalog_len(),
        0,
        "actual Screen backing retained credit after joined close"
    );
}

fn try_authorize(
    host: &mut HostState,
    attempt: crate::session_owner::authorization::AuthenticationAttempt,
    locator: SessionLocator,
    now: u64,
) -> Result<crate::session_owner::host::AuthorizedAttachment, crate::session_owner::host::HostError>
{
    use crate::session_owner::host::HostError;
    let issue = host.begin_issue(attempt, locator, now, now + 100)?;
    let HostDecision::GrantIssued(offer) = host.apply_policy_result(
        PolicyResult::allow_for_test(issue, 1000, "fixture-account"),
        now + 1,
    )?
    else {
        return Err(HostError::Refused);
    };
    let consume =
        host.begin_consume(attempt, offer.grant(), offer.binding(), now + 2, now + 102)?;
    let HostDecision::GrantConsumed(authorized) = host.apply_policy_result(
        PolicyResult::allow_for_test(consume, 1000, "fixture-account"),
        now + 3,
    )?
    else {
        return Err(HostError::Refused);
    };
    Ok(authorized)
}
fn authorize(
    host: &mut HostState,
    attempt: crate::session_owner::authorization::AuthenticationAttempt,
    locator: SessionLocator,
    now: u64,
) -> crate::session_owner::host::AuthorizedAttachment {
    try_authorize(host, attempt, locator, now).unwrap()
}

async fn recover_bound_data(
    bound: &LocalOwnerEngine,
    attachment: transport::session_resume::Attachment,
    channel: transport::channel_geometry::ChannelInstance,
    serial: u64,
) -> Result<crate::session_owner::recovery_runtime::NoScreenConsumer, &'static str> {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::session_resume::*;
    while !bound.engine.catalog_available() {
        tokio::task::yield_now().await;
    }
    let transfer = |retained: usize, cleanup| {
        let token = bound
            .provisioning
            .reserve(
                OwnerResourceRequest {
                    locator: attachment.locator,
                    channel,
                    kind: ReservationKind::SnapshotTransfer,
                    bytes: (retained.max(1) + 16384 + 65536) as u64,
                    screen_charge: None,
                },
                RequestId::new(cleanup).unwrap(),
            )
            .map_err(|_| "reservation")?;
        TransferAllowance::admit_reserved(bound.provisioning.client(), token, retained)
            .map_err(|_| "transfer")
    };
    let mut consumer =
        NoScreenConsumer::new(channel, transfer(4096, serial)?).map_err(|_| "consumer")?;
    let mut transaction = bound
        .catalog(attachment, transfer(0, serial + 1)?)
        .map_err(|_| "catalog")?;
    let request = RecoveryRequest {
        attachment,
        channel,
        parser: ParserContinuity::DataCursor {
            cursor: consumer.cursor(),
        },
    };
    let id = RequestId::new(serial + 2).unwrap();
    let mut producer = bound
        .recover(
            attachment,
            &mut transaction,
            request,
            RecoveryId::new([serial as u8; 16]).unwrap(),
            id,
            transfer(4096, serial + 3)?,
        )
        .map_err(|_| "recover")?;
    consumer
        .begin(id, request, producer.start())
        .map_err(|_| "consumer-begin")?;
    while let Some(chunk) = producer.next_chunk().map_err(|_| "chunk")? {
        consumer.consume(&chunk).map_err(|_| "consume")?;
    }
    let (end, ready) = producer.end().map_err(|_| "end")?;
    transaction
        .accept_consumed(consumer.finish(end, ready).map_err(|_| "consumer-finish")?)
        .map_err(|_| "proof")?;
    bound
        .finish_recovery(attachment, transaction)
        .map_err(|_| "finish-recovery")?;
    Ok(consumer)
}

#[tokio::test]
async fn host_engine_empty_detach_keeps_exact_binding_and_requires_fresh_single_use_epoch() {
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart, _) = empty_engine(locator, provisioning.client());
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    let first = bound.attach(&mut host, authorized).unwrap();
    bound.begin_detach(&mut host).unwrap();
    assert!(matches!(
        host.begin_issue(attempt, locator, 8, 108),
        Err(crate::session_owner::host::HostError::AlreadyAttached)
    ));
    bound.finish_detach(&mut host).await.unwrap();
    let authorized = authorize(&mut host, attempt, locator, 9);
    let second = bound.attach(&mut host, authorized).unwrap();
    assert!(second.epoch.get() > first.epoch.get());
    bound.begin_detach(&mut host).unwrap();
    bound.finish_detach(&mut host).await.unwrap();
    host.sweep(30_014).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "detached bound owner lost its registration pin"
    );
}

#[tokio::test]
async fn host_engine_explicit_empty_close_releases_its_pin_without_program_tombstone() {
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart, calls) = empty_engine(locator, provisioning.client());
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    host.sweep(30_002).unwrap();
    assert_eq!(host.catalog_len(), 1);
    let (mut foreign, _) = catalog();
    assert!(bound.close(&mut foreign, 30_003).await.is_err());
    assert_eq!(host.catalog_len(), 1);
    bound.close(&mut host, 30_003).await.unwrap();
    assert_eq!(
        host.catalog_len(),
        0,
        "proved empty close retained binding pin"
    );
    assert!(
        host.completed_facts(attempt, locator).is_err(),
        "empty owner fabricated program completion"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_engine_control_constructor_refusal_returns_exact_unused_custody() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    for case in 0..3 {
        let (mut host, attempt) = catalog();
        let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
        let (_, foreign) = host.create_session_provisioned(attempt, 3).unwrap();
        let token = provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel: ChannelInstance::new(1).unwrap(),
                    kind: if case == 1 {
                        ReservationKind::SnapshotTransfer
                    } else {
                        ReservationKind::ControlQueue
                    },
                    bytes: if case == 2 { 1 } else { 65536 },
                    screen_charge: None,
                },
                RequestId::new(13).unwrap(),
            )
            .unwrap();
        let expected = token.reservation();
        let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
        let client = if case == 0 {
            foreign.client()
        } else {
            provisioning.client()
        };
        let refused = match ScreenControlContext::admit_reserved(scope.clone(), client, token) {
            Ok(_) => panic!("invalid anchor case {case} was accepted"),
            Err(refused) => refused,
        };
        assert_eq!(refused.1.reservation(), expected);
        assert_eq!(scope.registered(), 0);
        host.sweep(30_004).unwrap();
        assert_eq!(
            host.catalog_len(),
            1,
            "constructor refusal refunded untouched debt"
        );
        let charge = provisioning
            .bind_storage(refused.1)
            .unwrap_or_else(|_| panic!("returned custody changed"));
        charge.allow_release(); // This fixture proves no backing/task ever existed.
        drop(charge);
        host.sweep(60_005).unwrap();
        assert_eq!(host.catalog_len(), 0);
    }
}

#[tokio::test]
async fn host_engine_binding_refuses_an_engine_with_preexisting_component_frontend_authority() {
    use transport::session_resume::{AttachEpoch, Attachment, FrontendGeneration};
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (mut engine, _restart, calls) = empty_engine(locator, provisioning.client());
    let frontend = engine
        .attach_trusted(Attachment {
            locator,
            frontend: FrontendGeneration::new([91; 16]).unwrap(),
            epoch: AttachEpoch::new(1).unwrap(),
        })
        .unwrap();
    let failure = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => {
            drop(frontend);
            drop(bound);
            panic!("unowned prior frontend authority crossed local binding")
        }
        Err(failure) => failure,
    };
    let (error, provisioning, engine) = failure.into_parts();
    assert!(matches!(error, LocalEngineError::Binding));
    drop((frontend, engine));
    let (engine, _restart, _) = empty_engine(locator, provisioning.client());
    assert!(host.bind_local_engine(provisioning, engine).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn host_engine_cancelled_screen_start_retains_one_task_and_refunds_only_unstarted_channel_credit(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::{ReservationKind, ScreenCharge};
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use crate::session_owner::screen_owner::HostScreenLease;
    use std::future::Future;
    use std::task::{Context, Waker};
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let reserve = |kind, bytes, screen_charge, cleanup| {
        provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind,
                    bytes,
                    screen_charge,
                },
                RequestId::new(cleanup).unwrap(),
            )
            .unwrap()
    };
    let anchor = reserve(ReservationKind::ControlQueue, 65536, None, 1);
    let context =
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), anchor) {
            Ok(context) => context,
            Err(_) => panic!("anchor refused"),
        };
    let (mut engine, _restart) =
        crate::session_owner::engine::tests::integrated::host_screen_fixture(
            locator,
            provisioning.client(),
            context,
        );
    let front = engine
        .attach_trusted(Attachment {
            locator,
            frontend: FrontendGeneration::new([81; 16]).unwrap(),
            epoch: AttachEpoch::new(1).unwrap(),
        })
        .unwrap();
    let request = || OpenRequest {
        stream: 16,
        kind: ChannelKind::Shell,
        cols: 80,
        rows: 24,
        screen: true,
        command: Vec::new(),
    };
    let supplied = |serial| {
        let size = terminal_size::TerminalSize::new(80, 24).unwrap();
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let model = reserve(
            ReservationKind::ScreenModel,
            0,
            Some(ScreenCharge {
                cells: slots.cells as u64,
                rows: slots.rows as u64,
                models: 1,
            }),
            serial,
        );
        let lease = match HostScreenLease::admit_reserved(provisioning.client(), model, size) {
            Ok(lease) => lease,
            Err(_) => panic!("model refused"),
        };
        let resources = AdmittedOwnerChannelResources::new(
            reserve(ReservationKind::OutputHistory, 4096, None, serial),
            reserve(ReservationKind::ControlQueue, 512 * 1024, None, serial),
            128,
            InputEpoch::new([82; 16]).unwrap(),
        );
        (resources, lease)
    };
    let (resources, lease) = supplied(2);
    let initially_pending = {
        let opening = engine.open_screen_admitted(&front, request(), None, resources, lease);
        tokio::pin!(opening);
        opening
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    };
    let first_identity = engine.control_identity_for_test();
    let after_cancel = host.resource_reservations_for_test();
    let registered = scope.registered();
    let (resources, lease) = supplied(3);
    let retry = engine
        .open_screen_admitted(&front, request(), None, resources, lease)
        .await;
    let retry_identity = engine.control_identity_for_test();
    let cleanup =
        tokio::time::timeout(std::time::Duration::from_secs(5), engine.close_session()).await;
    drop(engine);
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
    assert!(cleanup.unwrap().is_ok() && drained.unwrap().is_ok());
    assert!(initially_pending);
    assert_eq!(registered, 1);
    assert!(
        first_identity.is_some() && first_identity == retry_identity,
        "retry replaced the actual control task"
    );
    assert!(retry.is_ok(), "retry failed: {retry:?}");
    assert_eq!(
        after_cancel, 1,
        "cancelled startup leaked proved-unstarted channel credit"
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn host_engine_establishment_is_emitted_only_by_actual_bound_channel_installation() {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let client = provisioning.client();
    let channel = ChannelInstance::new(1).unwrap();
    let reserve = |kind, bytes| {
        provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind,
                    bytes,
                    screen_charge: None,
                },
                RequestId::new(31).unwrap(),
            )
            .unwrap()
    };
    let history = reserve(ReservationKind::OutputHistory, 4096);
    let control = reserve(ReservationKind::ControlQueue, 131072);
    let (engine, _restart) =
        crate::session_owner::engine::tests::integrated::host_fixture(locator, client);
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    assert!(
        bound.engine.take_local_establishment().is_none(),
        "construction fabricated establishment"
    );
    let authorized = authorize(&mut host, attempt, locator, 3);
    bound.attach(&mut host, authorized).unwrap();
    assert!(
        bound.engine.take_local_establishment().is_none(),
        "attachment fabricated establishment"
    );
    let installed = bound
        .engine
        .open_admitted(
            bound.frontend.as_ref().unwrap(),
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(
                history,
                control,
                128,
                InputEpoch::new([95; 16]).unwrap(),
            ),
        )
        .await;
    let proof = bound.engine.take_local_establishment();
    let duplicate = bound.engine.take_local_establishment();
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.engine.close_session(),
    )
    .await;
    assert!(cleanup.unwrap().is_ok());
    assert!(installed.is_ok());
    assert!(
        proof.is_some(),
        "actual installation emitted no sealed establishment"
    );
    assert!(
        duplicate.is_none(),
        "one installation emitted duplicate establishment"
    );
}

#[tokio::test]
async fn host_engine_completion_is_emitted_after_actual_join_with_final_input_output_and_wait_facts(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let history = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::OutputHistory,
                bytes: 4096,
                screen_charge: None,
            },
            RequestId::new(32).unwrap(),
        )
        .unwrap();
    let control = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::ControlQueue,
                bytes: 131072,
                screen_charge: None,
            },
            RequestId::new(32).unwrap(),
        )
        .unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    bound.attach(&mut host, authorized).unwrap();
    let opened = bound
        .engine
        .open_admitted(
            bound.frontend.as_ref().unwrap(),
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(
                history,
                control,
                128,
                InputEpoch::new([96; 16]).unwrap(),
            ),
        )
        .await;
    let early = bound.engine.take_local_completion();
    let output_settled = if opened.is_ok() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while bound.engine.output_bounds_for_test(channel).1 != 14 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok()
    } else {
        false
    };
    let final_input = bound.engine.input_position(channel);
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.engine.close_session(),
    )
    .await;
    let completion = bound.engine.take_local_completion();
    let duplicate = bound.engine.take_local_completion();
    let receipts = cleanup.unwrap().unwrap();
    assert!(opened.is_ok() && output_settled);
    assert!(early.is_none(), "live program fabricated completion");
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].workers_joined());
    let completion = completion.expect("actual joined cleanup emitted no sealed completion");
    assert!(duplicate.is_none());
    assert_eq!(completion.facts().len(), 1);
    let fact = completion.facts()[0];
    assert_eq!(fact.exit.channel, channel);
    assert_eq!(fact.exit.fact, ExitFact::Reaped { status: 0 });
    assert_eq!(fact.input, final_input.unwrap());
    assert_eq!(
        fact.output,
        OutputCursor {
            channel,
            offset: 14
        }
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn host_engine_real_personal_policy_open_recovery_and_retained_completion_use_one_actual_ledger(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::host::HostError;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt, lease, policy, observation, proof_fixture) =
        crate::session_owner::host::resource_tests::authenticated_with_limits(ByteLimits {
            channel_bytes: 32 << 20,
            session_bytes: 64 << 20,
            account_bytes: 128 << 20,
            global_bytes: 256 << 20,
        })
        .await;
    let uid = nix::unistd::geteuid();
    let account = nix::unistd::User::from_uid(uid).unwrap().unwrap();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let history = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::OutputHistory,
                bytes: 4096,
                screen_charge: None,
            },
            RequestId::new(40).unwrap(),
        )
        .unwrap();
    let control = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::ControlQueue,
                bytes: 131072,
                screen_charge: None,
            },
            RequestId::new(40).unwrap(),
        )
        .unwrap();
    let (engine, _restart) =
        crate::session_owner::engine::tests::integrated::host_fixture_for_principal(
            locator,
            provisioning.client(),
            Principal {
                uid: uid.as_raw(),
                name: account.name,
                identity: "inert Personal owner fixture".into(),
                incarnation: 0,
            },
        );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("real canonical account binding refused"),
    };
    let issue = host.begin_issue(attempt, locator, 3, 103).unwrap();
    let HostDecision::GrantIssued(offer) = policy
        .check_current(&lease, &mut host, issue, 4)
        .unwrap_or_else(|error| {
            panic!(
                "current Personal issue {error:?}; key-listed={}, registrations={}, delivery={:?}",
                observation.key_is_listed(),
                policy.registrations(),
                lease.delivery()
            )
        })
    else {
        panic!("real current Personal issue refused")
    };
    let consume = host
        .begin_consume(attempt, offer.grant(), offer.binding(), 5, 105)
        .unwrap();
    let HostDecision::GrantConsumed(authorized) =
        policy.check_current(&lease, &mut host, consume, 6).unwrap()
    else {
        panic!("real current Personal consume refused")
    };
    bound.attach(&mut host, authorized).unwrap();
    let input_epoch = InputEpoch::new([97; 16]).unwrap();
    let opened = bound
        .open_admitted(
            &mut host,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(history, control, 128, input_epoch),
        )
        .await;
    let exercised = if opened.is_ok() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !bound.engine.catalog_available()
                || bound.engine.output_bounds_for_test(channel).1 != 14
            {
                tokio::task::yield_now().await;
            }
            let transfer = |retained: usize, serial| {
                let token = bound
                    .provisioning
                    .reserve(
                        OwnerResourceRequest {
                            locator,
                            channel,
                            kind: ReservationKind::SnapshotTransfer,
                            bytes: (retained.max(1) + 16384 + 65536) as u64,
                            screen_charge: None,
                        },
                        RequestId::new(serial).unwrap(),
                    )
                    .map_err(|_| "transfer-reservation")?;
                TransferAllowance::admit_reserved(bound.provisioning.client(), token, retained)
                    .map_err(|_| "transfer-admission")
            };
            let front = bound.frontend.as_ref().ok_or("frontend")?;
            let mut receiver =
                NoScreenConsumer::new(channel, transfer(4096, 41)?).map_err(|_| "consumer")?;
            let mut transaction = bound
                .engine
                .catalog(front, transfer(0, 42)?)
                .map_err(|_| "catalog")?;
            let request = RecoveryRequest {
                attachment: front.attachment(),
                channel,
                parser: ParserContinuity::DataCursor {
                    cursor: receiver.cursor(),
                },
            };
            let id = RequestId::new(43).unwrap();
            let mut producer = bound
                .engine
                .recover(
                    front,
                    &mut transaction,
                    request,
                    RecoveryId::new([98; 16]).unwrap(),
                    id,
                    transfer(4096, 44)?,
                )
                .map_err(|_| "producer")?;
            receiver
                .begin(id, request, producer.start())
                .map_err(|_| "receiver-begin")?;
            while let Some(chunk) = producer.next_chunk().map_err(|_| "producer-chunk")? {
                receiver.consume(&chunk).map_err(|_| "consumer-chunk")?;
            }
            let (end, ready) = producer.end().map_err(|_| "producer-end")?;
            transaction
                .accept_consumed(receiver.finish(end, ready).map_err(|_| "consumer-finish")?)
                .map_err(|_| "consumed-proof")?;
            bound
                .engine
                .finish_recovery(front, transaction)
                .map_err(|_| "recovery-finish")?;
            bound
                .engine
                .user_input(front, channel, input_epoch, 0, b"abcdef")
                .map_err(|_| "input")?
                .accepted()
                .await
                .map_err(|_| "accepted")?;
            while bound
                .engine
                .input_position(channel)
                .map_err(|_| "input-position")?
                .committed
                != 6
            {
                tokio::task::yield_now().await;
            }
            Ok::<_, &'static str>(receiver)
        })
        .await
    } else {
        Ok(Err("open"))
    };
    let (exercise_error, consumer) = match exercised {
        Ok(Ok(receiver)) => (None, Some(receiver)),
        Ok(Err(code)) => (Some(code), None),
        Err(_) => (Some("exercise-timeout"), None),
    };
    let first_close =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 7)).await;
    let closing_refused = host.begin_issue(attempt, locator, 8, 108).is_err();
    drop(consumer);
    let second_close =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 9)).await;
    let proof_cleanup = proof_fixture.finish().await;
    assert!(proof_cleanup.is_ok(), "proof fixture did not actually join");
    assert!(
        opened.is_ok(),
        "real Personal admitted owner open failed: {opened:?}"
    );
    assert!(
        exercise_error.is_none(),
        "actual Personal recovery/input failed: {exercise_error:?}"
    );
    assert!(
        matches!(
            first_close.unwrap(),
            Err(LocalEngineError::Host(HostError::ResourceDebt))
        ),
        "independent receiver backing did not hold real catalog debt"
    );
    assert!(closing_refused);
    assert!(
        second_close.unwrap().is_ok(),
        "retained completion failed after actual last backing release"
    );
    let facts = host.completed_facts(attempt, locator).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].exit.fact, ExitFact::Reaped { status: 0 });
    assert_eq!(
        facts[0].input,
        InputPosition {
            epoch: input_epoch,
            accepted: 6,
            committed: 6
        }
    );
    assert_eq!(
        facts[0].output,
        OutputCursor {
            channel,
            offset: 14
        }
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
    host.sweep(300_008).unwrap();
    assert_eq!(
        host.catalog_len(),
        1,
        "real completion lost its five-minute tombstone"
    );
    host.acknowledge_completion(attempt, locator).unwrap();
    assert_eq!(host.catalog_len(), 0);
}

#[tokio::test]
async fn host_engine_cancelled_partial_write_fence_blocks_grants_then_reuses_writer_after_independent_recovery(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::host::HostError;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use std::future::Future;
    use std::task::{Context, Waker};
    use transport::channel::ChannelKind;
    use transport::channel_geometry::{ChannelInstance, GeometryOutcome, ResizeRequestId};
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let reserve = |kind, bytes| {
        provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind,
                    bytes,
                    screen_charge: None,
                },
                RequestId::new(50).unwrap(),
            )
            .unwrap()
    };
    let history = reserve(ReservationKind::OutputHistory, 4096);
    let queue = reserve(ReservationKind::ControlQueue, 131072);
    let (engine, _restart, control) =
        crate::session_owner::engine::tests::integrated::host_fixture_controlled(
            locator,
            provisioning.client(),
        );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    let first = bound.attach(&mut host, authorized).unwrap();
    let input_epoch = InputEpoch::new([99; 16]).unwrap();
    let opened = bound
        .open_admitted(
            &mut host,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            AdmittedOwnerChannelResources::new(history, queue, 128, input_epoch),
        )
        .await;
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        opened.map_err(|_| "open")?;
        let _first_consumer = recover_bound_data(&bound, first, channel, 60).await?;
        let writer = bound
            .engine
            .writer_identity_for_test(channel)
            .ok_or("writer-identity")?;
        control.hold_writes();
        bound
            .user_input(first, channel, input_epoch, 0, b"abcd")
            .map_err(|_| "first-input")?
            .accepted()
            .await
            .map_err(|_| "first-accepted")?;
        while !control.write_entered() {
            tokio::task::yield_now().await;
        }
        let before = bound
            .engine
            .input_position(channel)
            .map_err(|_| "position")?;
        let queued = bound
            .user_input(first, channel, input_epoch, 4, b"ef")
            .map_err(|_| "queued")?;
        bound.begin_detach(&mut host).map_err(|_| "begin-detach")?;
        let pending = {
            let finish = bound.finish_detach(&mut host);
            tokio::pin!(finish);
            finish
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        };
        let blocked = matches!(
            host.begin_issue(attempt, locator, 8, 108),
            Err(HostError::AlreadyAttached)
        );
        let retained = bound.fence.is_some();
        // Independent release precedes every later result/assertion path.
        control.release_writes();
        bound
            .finish_detach(&mut host)
            .await
            .map_err(|_| "finish-detach")?;
        let queued = queued.accepted().await.map_err(|_| "queued-accepted")?;
        let fenced_bytes = control.written();
        let authorized =
            try_authorize(&mut host, attempt, locator, 9).map_err(|_| "fresh-policy")?;
        let second = bound
            .attach(&mut host, authorized)
            .map_err(|_| "reattach")?;
        let no_cursor_ready = bound
            .user_input(second, channel, input_epoch, 6, b"gh")
            .is_err();
        let _second_consumer = recover_bound_data(&bound, second, channel, 80).await?;
        let stale_input = bound
            .user_input(first, channel, input_epoch, 6, b"bad")
            .is_err();
        let stale_resize = bound
            .resize(first, channel, ResizeRequestId::new(1).unwrap(), 81, 24)
            .is_err();
        bound
            .user_input(second, channel, input_epoch, 6, b"gh")
            .map_err(|_| "fresh-input")?
            .accepted()
            .await
            .map_err(|_| "fresh-accepted")?;
        while bound
            .engine
            .input_position(channel)
            .map_err(|_| "final-position")?
            .committed
            != 8
        {
            tokio::task::yield_now().await;
        }
        let same_writer = bound.engine.writer_identity_for_test(channel) == Some(writer);
        let bytes = control.written();
        let stale_close = bound
            .close_from_frontend(&mut host, first, 13)
            .await
            .is_err();
        let stale_loss = bound.frontend_lost(&mut host, first).is_err();
        let resized = bound
            .resize(second, channel, ResizeRequestId::new(1).unwrap(), 81, 24)
            .map_err(|_| "fresh-resize")?;
        bound
            .frontend_lost(&mut host, second)
            .map_err(|_| "fresh-loss")?;
        bound
            .finish_detach(&mut host)
            .await
            .map_err(|_| "fresh-loss-fence")?;
        let still_owned = host.catalog_len() == 1
            && bound.engine.writer_identity_for_test(channel) == Some(writer)
            && control.kills(16) == 0;
        Ok::<_, &'static str>((
            before,
            queued,
            pending,
            blocked,
            retained,
            fenced_bytes,
            no_cursor_ready,
            stale_input,
            stale_resize,
            same_writer,
            bytes,
            stale_close,
            stale_loss,
            resized.outcome,
            still_owned,
            second.epoch.get() > first.epoch.get(),
        ))
    })
    .await;
    control.release_writes();
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.close(&mut host, 100),
    )
    .await;
    assert!(cleanup.unwrap().is_ok(), "actual fallback close failed");
    let facts = exercised
        .expect("bounded scenario")
        .expect("partial-write scenario failed");
    assert_eq!((facts.0.accepted, facts.0.committed), (4, 0));
    assert_eq!((facts.1.accepted, facts.1.committed), (6, 2));
    assert!(
        facts.2 && facts.3 && facts.4,
        "cancelled actual fence lost custody or admitted a new grant"
    );
    assert_eq!(facts.5, b"ab");
    assert!(facts.6 && facts.7 && facts.8 && facts.9);
    assert_eq!(facts.10, b"abcdefgh");
    assert!(facts.11 && facts.12 && facts.14 && facts.15);
    assert_eq!(facts.13, GeometryOutcome::Applied);
    assert_eq!(control.resize_calls(), 1);
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn host_engine_cancelled_close_keeps_same_operation_receipts_unknown_exit_and_completion_until_real_release(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::host::HostError;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
    use crate::session_owner::resource_contract::ReservationKind;
    use std::future::Future;
    use std::task::{Context, Waker};
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart, control) =
        crate::session_owner::engine::tests::integrated::host_fixture_controlled(
            locator,
            provisioning.client(),
        );
    control.gate_exit(16, Some(3), false);
    control.gate_exit(17, None, true);
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    bound.attach(&mut host, authorized).unwrap();
    let opened = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for serial in 1..=2u8 {
            let channel = ChannelInstance::new(u64::from(serial)).unwrap();
            let reserve = |kind, bytes| {
                bound
                    .provisioning
                    .reserve(
                        OwnerResourceRequest {
                            locator,
                            channel,
                            kind,
                            bytes,
                            screen_charge: None,
                        },
                        RequestId::new(100 + u64::from(serial)).unwrap(),
                    )
                    .map_err(|_| "reserve")
            };
            let supplied = AdmittedOwnerChannelResources::new(
                reserve(ReservationKind::OutputHistory, 4096)?,
                reserve(ReservationKind::ControlQueue, 131072)?,
                128,
                InputEpoch::new([serial; 16]).unwrap(),
            );
            bound
                .open_admitted(
                    &mut host,
                    OpenRequest {
                        stream: 15 + serial,
                        kind: ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    },
                    None,
                    supplied,
                )
                .await
                .map_err(|_| "open")?;
        }
        while (1..=2).any(|id| {
            bound
                .engine
                .output_bounds_for_test(ChannelInstance::new(id).unwrap())
                .1
                != 14
        }) {
            tokio::task::yield_now().await;
        }
        Ok::<_, &'static str>(())
    })
    .await;
    let channel = ChannelInstance::new(1).unwrap();
    let transfer = bound
        .provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::SnapshotTransfer,
                bytes: 4096 + 16384 + 65536,
                screen_charge: None,
            },
            RequestId::new(110).unwrap(),
        )
        .unwrap();
    let allowance =
        match TransferAllowance::admit_reserved(bound.provisioning.client(), transfer, 4096) {
            Ok(allowance) => allowance,
            Err(_) => panic!("sentinel credit refused"),
        };
    let consumer = NoScreenConsumer::new(channel, allowance).unwrap();
    let charged = host.resource_reservations_for_test();
    let mut premature = false;
    let cancelled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            {
                let closing = bound.close(&mut host, 7);
                tokio::pin!(closing);
                if closing
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    premature = true;
                }
            }
            if premature
                || (bound.engine.consumed_close_receipts_for_test() == 1
                    && control.held_exit_polls(17) > 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let operation = host.cleanup_operation_for_test(locator);
    let still_charged = host.resource_reservations_for_test() == charged;
    let first_reaped = control.reaps(16);
    let second_reaped = control.reaps(17);
    let gated_polls = control.held_exit_polls(17);
    let first_kills = control.kills(16);
    let closing_refused = host.begin_issue(attempt, locator, 8, 108).is_err();
    control.release_exit(17); // Independent release precedes every assertion.
    let debt =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 9)).await;
    let retained_operation = host.cleanup_operation_for_test(locator);
    let retained_receipts = bound.close_receipts.len();
    let retained_facts = bound
        .completion
        .as_ref()
        .map(|proof| proof.facts().to_vec());
    host.sweep(30_010).unwrap();
    let closing_pinned = host.catalog_len();
    drop(consumer);
    let completed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.close(&mut host, 30_011),
    )
    .await;
    assert!(
        completed.unwrap().is_ok(),
        "retained close did not complete after release"
    );
    assert!(opened.unwrap().is_ok() && cancelled.is_ok());
    assert!(!premature && still_charged && closing_refused);
    assert!(operation.is_some() && operation == retained_operation);
    assert_eq!((first_reaped, second_reaped), (1, 0));
    assert!(gated_polls > 0);
    assert!(matches!(
        debt.unwrap(),
        Err(LocalEngineError::Host(HostError::ResourceDebt))
    ));
    assert_eq!(retained_receipts, 2);
    assert_eq!(closing_pinned, 1);
    let mut facts = retained_facts.expect("actual final facts were not retained");
    facts.sort_by_key(|fact| fact.exit.channel.get());
    assert_eq!(facts[0].exit.fact, ExitFact::Reaped { status: 3 });
    assert_eq!(
        facts[1].exit.fact,
        ExitFact::StatusUnavailable,
        "unknown actual wait status became zero"
    );
    assert_eq!(host.completed_facts(attempt, locator).unwrap().len(), 2);
    assert_eq!(host.cleanup_operation_for_test(locator), operation);
    assert_eq!((control.reaps(16), control.reaps(17)), (1, 1));
    assert_eq!(control.kills(16), first_kills);
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn host_engine_control_start_refuses_wrong_ledger_locator_anchor_and_duplicate_without_spawning_or_refund(
) {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (mut foreign, foreign_attempt) = catalog();
    let (foreign_locator, foreign_owner) = foreign
        .create_session_provisioned(foreign_attempt, 2)
        .unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let token = provisioning
        .reserve(
            OwnerResourceRequest {
                locator,
                channel,
                kind: ReservationKind::ControlQueue,
                bytes: 65536,
                screen_charge: None,
            },
            RequestId::new(120).unwrap(),
        )
        .unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let token =
        match ScreenControlContext::admit_reserved(scope.clone(), foreign_owner.client(), token) {
            Ok(_) => panic!("foreign ledger accepted anchor"),
            Err(refused) => refused.1,
        };
    let mut context =
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), token) {
            Ok(context) => context,
            Err(_) => panic!("returned own anchor refused"),
        };
    let wrong_client = context
        .begin_start(foreign_owner.client(), locator, channel)
        .is_err();
    let wrong_locator = context
        .begin_start(provisioning.client(), foreign_locator, channel)
        .is_err();
    let wrong_anchor = context
        .begin_start(
            provisioning.client(),
            locator,
            ChannelInstance::new(2).unwrap(),
        )
        .is_err();
    let before = (scope.registered(), host.resource_reservations_for_test());
    let ticket = context.begin_start(provisioning.client(), locator, channel);
    let duplicate = context
        .begin_start(provisioning.client(), locator, channel)
        .is_err();
    let ready_and_joined = match ticket {
        Ok(ticket) => {
            let ready =
                tokio::time::timeout(std::time::Duration::from_secs(5), ticket.ready()).await;
            ticket.stop();
            let joined =
                tokio::time::timeout(std::time::Duration::from_secs(5), ticket.join()).await;
            ready.is_ok_and(|value| value.is_ok()) && joined.is_ok_and(|value| value.is_ok())
        }
        Err(_) => false,
    };
    drop(context);
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
    assert!(drained.unwrap().is_ok() && ready_and_joined);
    assert!(wrong_client && wrong_locator && wrong_anchor && duplicate);
    assert_eq!(
        before,
        (0, 1),
        "refused starts allocated or refunded the owned anchor"
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
    assert_eq!(foreign.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn host_engine_control_pre_spawn_capacity_failure_releases_only_proved_unused_anchor_once() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (other_locator, other) = host.create_session_provisioned(attempt, 3).unwrap();
    let unrelated = other
        .reserve(
            OwnerResourceRequest {
                locator: other_locator,
                channel: ChannelInstance::new(1).unwrap(),
                kind: ReservationKind::SnapshotTransfer,
                bytes: 16,
                screen_charge: None,
            },
            RequestId::new(130).unwrap(),
        )
        .unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let mut tickets = Vec::new();
    let make_context = |channel| {
        let token = provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind: ReservationKind::ControlQueue,
                    bytes: 65536,
                    screen_charge: None,
                },
                RequestId::new(131).unwrap(),
            )
            .unwrap();
        match ScreenControlContext::admit_reserved(scope.clone(), provisioning.client(), token) {
            Ok(context) => context,
            Err(_) => panic!("valid anchor refused"),
        }
    };
    for serial in 1..=transport::channel::MAX_CHANNELS {
        let channel = ChannelInstance::new(serial as u64).unwrap();
        let mut context = make_context(channel);
        let ticket = context
            .begin_start(provisioning.client(), locator, channel)
            .unwrap();
        tickets.push(ticket);
    }
    let extra_channel = ChannelInstance::new(1000).unwrap();
    let mut extra = make_context(extra_channel);
    let failed = extra
        .begin_start(provisioning.client(), locator, extra_channel)
        .is_err();
    let spent = extra
        .begin_start(provisioning.client(), locator, extra_channel)
        .is_err();
    let retained = (scope.registered(), host.resource_reservations_for_test());
    drop(extra);
    for ticket in &tickets {
        ticket.stop();
    }
    let mut all_joined = true;
    for ticket in &tickets {
        all_joined &= tokio::time::timeout(std::time::Duration::from_secs(5), ticket.join())
            .await
            .is_ok_and(|result| result.is_ok());
    }
    drop(tickets);
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
    let remaining = host.resource_reservations_for_test();
    drop(unrelated); // Arbitrary token Drop must not refund the sentinel debt.
    assert!(all_joined && drained.unwrap().is_ok());
    assert!(failed && spent);
    assert_eq!(
        retained,
        (
            transport::channel::MAX_CHANNELS,
            transport::channel::MAX_CHANNELS + 1
        )
    );
    assert_eq!(remaining, 1);
    assert_eq!(host.resource_reservations_for_test(), 1);
}

#[tokio::test]
async fn host_engine_producer_second_quota_failure_releases_first_unused_token_without_refunding_sentinel(
) {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog_with_limits(ByteLimits {
        channel_bytes: 64,
        session_bytes: 128,
        account_bytes: 256,
        global_bytes: 512,
    });
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let sentinel = provisioning
        .reserve(
            request(ReservationKind::SnapshotTransfer, 16),
            RequestId::new(140).unwrap(),
        )
        .unwrap();
    let sentinel_id = sentinel.reservation().id.get();
    let refused = provisioning
        .reserve_channel_resources(
            request(ReservationKind::OutputHistory, 4096),
            request(ReservationKind::ControlQueue, 131072),
            RequestId::new(141).unwrap(),
            128,
            InputEpoch::new([111; 16]).unwrap(),
        )
        .is_err();
    let remaining = host.resource_reservations_for_test();
    let next = provisioning
        .reserve(
            request(ReservationKind::OutputHistory, 4096),
            RequestId::new(142).unwrap(),
        )
        .unwrap();
    let next_id = next.reservation().id.get();
    let unused = provisioning
        .bind_storage(next)
        .unwrap_or_else(|_| panic!("own unused credit refused"));
    unused.allow_release();
    drop(unused);
    drop(sentinel);
    assert!(refused);
    assert_eq!(
        remaining, 1,
        "second refusal lost a first unused charge or refunded unrelated debt"
    );
    assert_eq!(
        next_id,
        sentinel_id + 2,
        "producer never exercised successful first admission before quota refusal"
    );
    assert_eq!(
        host.resource_reservations_for_test(),
        1,
        "arbitrary sentinel Drop became a refund"
    );
}

#[tokio::test]
async fn host_engine_producer_malformed_pair_refuses_before_any_reservation_id_is_minted() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::protocol::OwnerProtocolError;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let history = OwnerResourceRequest {
        locator,
        channel,
        kind: ReservationKind::SnapshotTransfer,
        bytes: 4096,
        screen_charge: None,
    };
    let control = OwnerResourceRequest {
        locator,
        channel,
        kind: ReservationKind::ControlQueue,
        bytes: 131072,
        screen_charge: None,
    };
    let result = provisioning.reserve_channel_resources(
        history,
        control,
        RequestId::new(143).unwrap(),
        128,
        InputEpoch::new([112; 16]).unwrap(),
    );
    let refused = matches!(result, Err(OwnerProtocolError::Binding));
    drop(result);
    let first = provisioning
        .reserve(
            OwnerResourceRequest {
                kind: ReservationKind::OutputHistory,
                ..history
            },
            RequestId::new(144).unwrap(),
        )
        .unwrap();
    let id = first.reservation().id.get();
    let unused = provisioning
        .bind_storage(first)
        .unwrap_or_else(|_| panic!("own unused credit refused"));
    unused.allow_release();
    drop(unused);
    assert!(refused);
    assert_eq!(
        id, 1,
        "malformed pair minted a reservation before validation"
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn host_engine_empty_catalog_then_real_producer_open_requires_new_independent_recovery() {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::TransferAllowance;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    let attachment = bound.attach(&mut host, authorized).unwrap();
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let token = bound
            .provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind: ReservationKind::SnapshotTransfer,
                    bytes: 81921,
                    screen_charge: None,
                },
                RequestId::new(150).unwrap(),
            )
            .map_err(|_| "empty-catalog-credit")?;
        let allowance = TransferAllowance::admit_reserved(bound.provisioning.client(), token, 0)
            .map_err(|_| "empty-catalog-allowance")?;
        let empty = bound
            .catalog(attachment, allowance)
            .map_err(|_| "empty-catalog")?;
        let was_empty = empty.catalog().positions().is_empty();
        bound
            .finish_recovery(attachment, empty)
            .map_err(|_| "empty-ready")?;
        let input_epoch = InputEpoch::new([113; 16]).unwrap();
        let request = |kind, bytes| OwnerResourceRequest {
            locator,
            channel,
            kind,
            bytes,
            screen_charge: None,
        };
        let supplied = bound
            .provision_channel_resources(
                &host,
                attachment,
                (
                    request(ReservationKind::OutputHistory, 4096),
                    request(ReservationKind::ControlQueue, 131072),
                ),
                RequestId::new(151).unwrap(),
                128,
                input_epoch,
            )
            .map_err(|_| "channel-provision")?;
        let before = host.resource_reservations_for_test();
        bound
            .open_admitted(
                &mut host,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                supplied,
            )
            .await
            .map_err(|_| "open")?;
        let after = host.resource_reservations_for_test();
        let old_empty_ready_refused = bound
            .user_input(attachment, channel, input_epoch, 0, b"x")
            .is_err();
        let _consumer = recover_bound_data(&bound, attachment, channel, 160).await?;
        bound
            .user_input(attachment, channel, input_epoch, 0, b"x")
            .map_err(|_| "input")?
            .accepted()
            .await
            .map_err(|_| "accepted")?;
        while bound
            .engine
            .input_position(channel)
            .map_err(|_| "position")?
            .committed
            != 1
        {
            tokio::task::yield_now().await;
        }
        Ok::<_, &'static str>((was_empty, before, after, old_empty_ready_refused))
    })
    .await;
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.close(&mut host, 100),
    )
    .await;
    assert!(cleanup.unwrap().is_ok());
    let (empty, before, after, gated) = exercised
        .expect("bounded scenario")
        .expect("empty catalog/open scenario");
    assert!(empty && gated);
    assert_eq!(
        (before, after),
        (2, 2),
        "admitted open reserved its producer-issued pair twice"
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
}

async fn test_bound_program(
    host: &mut HostState,
    attempt: crate::session_owner::authorization::AuthenticationAttempt,
    now: u64,
) -> (
    LocalOwnerEngine,
    Result<transport::channel_geometry::ChannelInstance, LocalEngineError>,
    tokio::sync::watch::Sender<RestartSignal>,
) {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (locator, provisioning) = host.create_session_provisioned(attempt, now).unwrap();
    let (engine, restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(host, attempt, locator, now + 1);
    let attachment = bound.attach(host, authorized).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = bound
        .provision_channel_resources(
            host,
            attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(200).unwrap(),
            128,
            InputEpoch::new([120; 16]).unwrap(),
        )
        .unwrap();
    let opened = bound
        .open_admitted(
            host,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            supplied,
        )
        .await;
    (bound, opened, restart)
}
fn independent_data_backing(
    bound: &LocalOwnerEngine,
    serial: u64,
) -> crate::session_owner::recovery_runtime::NoScreenConsumer {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::RequestId;
    let channel = ChannelInstance::new(1).unwrap();
    let token = bound
        .provisioning
        .reserve(
            OwnerResourceRequest {
                locator: bound.binding.identity.locator,
                channel,
                kind: ReservationKind::SnapshotTransfer,
                bytes: 4096 + 16384 + 65536,
                screen_charge: None,
            },
            RequestId::new(serial).unwrap(),
        )
        .unwrap();
    let allowance =
        match TransferAllowance::admit_reserved(bound.provisioning.client(), token, 4096) {
            Ok(allowance) => allowance,
            Err(_) => panic!("independent credit refused"),
        };
    NoScreenConsumer::new(channel, allowance).unwrap()
}

#[tokio::test]
async fn host_engine_sealed_completion_refuses_foreign_host_owner_and_operation_without_consuming_evidence(
) {
    use crate::session_owner::host::HostError;
    let (mut host, attempt) = catalog();
    let (mut first, opened_one, _restart_one) = test_bound_program(&mut host, attempt, 2).await;
    let (mut second, opened_two, _restart_two) = test_bound_program(&mut host, attempt, 10).await;
    let one_backing = independent_data_backing(&first, 201);
    let two_backing = independent_data_backing(&second, 202);
    let first_debt = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first.close(&mut host, 20),
    )
    .await;
    let second_debt = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        second.close(&mut host, 21),
    )
    .await;
    let mut proof = first.completion.take().expect("joined completion retained");
    let (mut foreign, _) = catalog();
    let foreign_result =
        foreign.complete_local_owner(&first.binding, first.cleanup.as_ref().unwrap(), proof, 22);
    let foreign_refused;
    match foreign_result {
        Err((error, returned)) => {
            foreign_refused = error == HostError::Refused;
            proof = returned;
        }
        Ok(()) => panic!("foreign host accepted completion"),
    }
    let wrong_operation =
        host.complete_local_owner(&first.binding, second.cleanup.as_ref().unwrap(), proof, 22);
    let operation_refused;
    match wrong_operation {
        Err((error, returned)) => {
            operation_refused = error == HostError::Refused;
            proof = returned;
        }
        Ok(()) => panic!("foreign operation accepted completion"),
    }
    let wrong_owner =
        host.complete_local_owner(&second.binding, second.cleanup.as_ref().unwrap(), proof, 22);
    let owner_refused;
    match wrong_owner {
        Err((error, returned)) => {
            owner_refused = error == HostError::Refused;
            proof = returned;
        }
        Ok(()) => panic!("foreign owner accepted completion"),
    }
    let fact_locator = proof.facts()[0].exit.attachment.locator;
    first.completion = Some(proof);
    let before_release = host.resource_reservations_for_test();
    drop((one_backing, two_backing));
    let completed_one = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        first.close(&mut host, 30),
    )
    .await;
    let completed_two = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        second.close(&mut host, 31),
    )
    .await;
    assert!(completed_one.unwrap().is_ok() && completed_two.unwrap().is_ok());
    assert!(opened_one.is_ok() && opened_two.is_ok());
    assert!(matches!(
        first_debt.unwrap(),
        Err(LocalEngineError::Host(HostError::ResourceDebt))
    ));
    assert!(matches!(
        second_debt.unwrap(),
        Err(LocalEngineError::Host(HostError::ResourceDebt))
    ));
    assert!(foreign_refused && operation_refused && owner_refused);
    assert_eq!(fact_locator, first.binding.identity.locator);
    assert_eq!(before_release, 2);
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[test]
fn host_engine_failed_admitted_control_task_burns_fresh_attach_epoch_and_retains_unknown_debt() {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::{ReservationKind, ScreenCharge};
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use crate::session_owner::screen_owner::HostScreenLease;
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let stopped = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let handle = stopped.handle().clone();
    drop(stopped);
    let driver = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    driver.block_on(async {
        let (mut host, attempt) = catalog();
        let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
        let channel = ChannelInstance::new(1).unwrap();
        let request = |kind, bytes, screen_charge| OwnerResourceRequest {
            locator,
            channel,
            kind,
            bytes,
            screen_charge,
        };
        let reserve = |kind, bytes, screen_charge| {
            provisioning
                .reserve(
                    request(kind, bytes, screen_charge),
                    RequestId::new(210).unwrap(),
                )
                .unwrap()
        };
        let scope = ControlTaskScope::new(handle);
        let context = match ScreenControlContext::admit_reserved(
            scope.clone(),
            provisioning.client(),
            reserve(ReservationKind::ControlQueue, 65536, None),
        ) {
            Ok(context) => context,
            Err(_) => panic!("anchor refused"),
        };
        let size = terminal_size::TerminalSize::new(80, 24).unwrap();
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let lease = match HostScreenLease::admit_reserved(
            provisioning.client(),
            reserve(
                ReservationKind::ScreenModel,
                0,
                Some(ScreenCharge {
                    cells: slots.cells as u64,
                    rows: slots.rows as u64,
                    models: 1,
                }),
            ),
            size,
        ) {
            Ok(lease) => lease,
            Err(_) => panic!("model refused"),
        };
        let supplied = AdmittedOwnerChannelResources::new(
            reserve(ReservationKind::OutputHistory, 4096, None),
            reserve(ReservationKind::ControlQueue, 512 * 1024, None),
            128,
            InputEpoch::new([121; 16]).unwrap(),
        );
        let (engine, _restart, control) =
            crate::session_owner::engine::tests::integrated::host_screen_fixture_controlled(
                locator,
                provisioning.client(),
                context,
            );
        let mut bound = match host.bind_local_engine(provisioning, engine) {
            Ok(bound) => bound,
            Err(_) => panic!("binding refused"),
        };
        let authorized = authorize(&mut host, attempt, locator, 3);
        let first = bound.attach(&mut host, authorized).unwrap();
        let opened = bound
            .open_screen_admitted(
                &mut host,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: Vec::new(),
                },
                None,
                supplied,
                lease,
            )
            .await;
        bound.begin_detach(&mut host).unwrap();
        bound.finish_detach(&mut host).await.unwrap();
        let authorized = try_authorize(&mut host, attempt, locator, 9).unwrap();
        let burned = authorized.attachment().epoch.get();
        let refused = bound.attach(&mut host, authorized).is_err();
        let unavailable = host.begin_issue(attempt, locator, 13, 113).is_err();
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            bound.close(&mut host, 100),
        )
        .await;
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
        host.sweep(30_001).unwrap();
        assert!(opened.is_err() && refused && unavailable);
        assert!(burned > first.epoch.get());
        assert!(
            closed.unwrap().is_err(),
            "failed join fabricated empty completion"
        );
        assert!(drained.unwrap().is_ok());
        assert_eq!(control.kills(16), 0);
        assert_eq!(host.catalog_len(), 1);
        assert_eq!(
            host.resource_reservations_for_test(),
            1,
            "failed actual task join refunded its anchor"
        );
        assert!(bound.engine.take_local_completion().is_none());
    });
}

#[tokio::test]
async fn host_engine_bound_screen_stale_generation_and_independent_scratch_chunk_backing_gate_completion(
) {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::host::HostError;
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::recovery_runtime::TransferAllowance;
    use crate::session_owner::resource_contract::{ReservationKind, ScreenCharge};
    use crate::session_owner::screen_control::{ControlTaskScope, ScreenControlContext};
    use crate::session_owner::screen_owner::HostScreenLease;
    use crate::session_owner::screen_recovery::{ScreenConsumer, ScreenRecoveryAllowance};
    use transport::channel::ChannelKind;
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::*;
    let (mut host, attempt) = catalog();
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let screen_channel = ChannelInstance::new(1).unwrap();
    let data_channel = ChannelInstance::new(2).unwrap();
    let size = terminal_size::TerminalSize::new(80, 24).unwrap();
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let (context, lease, supplied) = {
        let reserve = |kind, bytes, screen_charge, serial| {
            provisioning
                .reserve(
                    OwnerResourceRequest {
                        locator,
                        channel: screen_channel,
                        kind,
                        bytes,
                        screen_charge,
                    },
                    RequestId::new(serial).unwrap(),
                )
                .unwrap()
        };
        let context = match ScreenControlContext::admit_reserved(
            scope.clone(),
            provisioning.client(),
            reserve(ReservationKind::ControlQueue, 65536, None, 220),
        ) {
            Ok(context) => context,
            Err(_) => panic!("anchor refused"),
        };
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let lease = match HostScreenLease::admit_reserved(
            provisioning.client(),
            reserve(
                ReservationKind::ScreenModel,
                0,
                Some(ScreenCharge {
                    cells: slots.cells as u64,
                    rows: slots.rows as u64,
                    models: 1,
                }),
                221,
            ),
            size,
        ) {
            Ok(lease) => lease,
            Err(_) => panic!("model refused"),
        };
        let supplied = AdmittedOwnerChannelResources::new(
            reserve(ReservationKind::OutputHistory, 4096, None, 222),
            reserve(ReservationKind::ControlQueue, 512 * 1024, None, 222),
            128,
            InputEpoch::new([122; 16]).unwrap(),
        );
        (context, lease, supplied)
    };
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_screen_fixture(
        locator,
        provisioning.client(),
        context,
    );
    let mut bound = match host.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("binding refused"),
    };
    let authorized = authorize(&mut host, attempt, locator, 3);
    let attachment = bound.attach(&mut host, authorized).unwrap();
    let opened = bound
        .open_screen_admitted(
            &mut host,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: true,
                command: Vec::new(),
            },
            None,
            supplied,
            lease,
        )
        .await;
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        opened.map_err(|_| "screen-open")?;
        while !bound.engine.catalog_available()
            || bound.engine.output_bounds_for_test(screen_channel).1 != 14
        {
            tokio::task::yield_now().await;
        }
        let transfer = |bound: &LocalOwnerEngine, channel, retained: usize, serial| {
            let token = bound
                .provisioning
                .reserve(
                    OwnerResourceRequest {
                        locator,
                        channel,
                        kind: ReservationKind::SnapshotTransfer,
                        bytes: (retained.max(1) + 16384 + 65536) as u64,
                        screen_charge: None,
                    },
                    RequestId::new(serial).unwrap(),
                )
                .map_err(|_| "transfer-reserve")?;
            TransferAllowance::admit_reserved(bound.provisioning.client(), token, retained)
                .map_err(|_| "transfer-admit")
        };
        let quote = bound
            .screen_recovery_requirements(attachment, screen_channel)
            .map_err(|_| "quote")?;
        let make_allowance = |bound: &LocalOwnerEngine, serial| {
            let bytes = bound
                .provisioning
                .reserve(
                    OwnerResourceRequest {
                        locator,
                        channel: screen_channel,
                        kind: ReservationKind::SnapshotTransfer,
                        bytes: quote.transfer_bytes as u64,
                        screen_charge: None,
                    },
                    RequestId::new(serial).unwrap(),
                )
                .map_err(|_| "screen-bytes")?;
            let scratch = bound
                .provisioning
                .reserve(
                    OwnerResourceRequest {
                        locator,
                        channel: screen_channel,
                        kind: ReservationKind::ScreenModel,
                        bytes: 0,
                        screen_charge: Some(quote.scratch),
                    },
                    RequestId::new(serial).unwrap(),
                )
                .map_err(|_| "screen-scratch")?;
            ScreenRecoveryAllowance::admit_reserved(
                bound.provisioning.client(),
                bytes,
                scratch,
                quote,
            )
            .map_err(|_| "screen-allowance")
        };
        let mut consumer = ScreenConsumer::new(
            screen_channel,
            [123; 16],
            size,
            1000,
            Arc::new(crate::screen_budget::ScreenBudget::new(
                crate::screen_budget::BudgetLimits::default(),
            )),
            transfer(&bound, screen_channel, quote.max_bytes, 223)?,
        )
        .map_err(|_| "consumer")?;
        let mut old = bound
            .catalog(attachment, transfer(&bound, screen_channel, 0, 224)?)
            .map_err(|_| "old-catalog")?;
        let (request, evidence) = consumer.request(attachment);
        let id = RequestId::new(225).unwrap();
        let mut producer = bound
            .recover_screen(
                attachment,
                &mut old,
                request,
                &evidence,
                RecoveryId::new([124; 16]).unwrap(),
                id,
                make_allowance(&bound, 225)?,
            )
            .map_err(|_| "old-screen-producer")?;
        consumer
            .begin(id, request, producer.start())
            .map_err(|_| "consumer-begin")?;
        while let Some(chunk) = producer.next_chunk().map_err(|_| "screen-chunk")? {
            consumer.consume(&chunk).map_err(|_| "consume")?;
        }
        let (end, ready) = producer.end().map_err(|_| "screen-end")?;
        old.accept_consumed(consumer.finish(end, ready).map_err(|_| "screen-finish")?)
            .map_err(|_| "screen-proof")?;
        drop(evidence);
        let req = |kind, bytes| OwnerResourceRequest {
            locator,
            channel: data_channel,
            kind,
            bytes,
            screen_charge: None,
        };
        let next = bound
            .provision_channel_resources(
                &host,
                attachment,
                (
                    req(ReservationKind::OutputHistory, 4096),
                    req(ReservationKind::ControlQueue, 131072),
                ),
                RequestId::new(226).unwrap(),
                128,
                InputEpoch::new([125; 16]).unwrap(),
            )
            .map_err(|_| "new-channel-credit")?;
        bound
            .open_admitted(
                &mut host,
                OpenRequest {
                    stream: 17,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                next,
            )
            .await
            .map_err(|_| "new-channel")?;
        let stale_refused = bound.finish_recovery(attachment, old).is_err();
        let not_ready = bound
            .user_input(
                attachment,
                screen_channel,
                InputEpoch::new([122; 16]).unwrap(),
                0,
                b"x",
            )
            .is_err();
        while !bound.engine.catalog_available() {
            tokio::task::yield_now().await;
        }
        let mut current = bound
            .catalog(attachment, transfer(&bound, screen_channel, 0, 227)?)
            .map_err(|_| "current-catalog")?;
        drop(consumer);
        let consumer = ScreenConsumer::new(
            screen_channel,
            [127; 16],
            size,
            1000,
            Arc::new(crate::screen_budget::ScreenBudget::new(
                crate::screen_budget::BudgetLimits::default(),
            )),
            transfer(&bound, screen_channel, quote.max_bytes, 229)?,
        )
        .map_err(|_| "fresh-held-consumer")?;
        let (request, evidence) = consumer.request(attachment);
        let mut producer = bound
            .recover_screen(
                attachment,
                &mut current,
                request,
                &evidence,
                RecoveryId::new([126; 16]).unwrap(),
                RequestId::new(228).unwrap(),
                make_allowance(&bound, 228)?,
            )
            .map_err(|_| "held-screen-producer")?;
        let chunk = producer
            .next_chunk()
            .map_err(|_| "held-chunk")?
            .ok_or("missing-chunk")?;
        drop((current, evidence, consumer));
        Ok::<_, &'static str>((producer, chunk, stale_refused, not_ready))
    })
    .await;
    let (producer, chunk, flags, error) = match exercised {
        Ok(Ok((producer, chunk, stale, not_ready))) => {
            (Some(producer), Some(chunk), (stale, not_ready), None)
        }
        Ok(Err(error)) => (None, None, (false, false), Some(error)),
        Err(_) => (None, None, (false, false), Some("scenario-timeout")),
    };
    let first =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 7)).await;
    let operation = host.cleanup_operation_for_test(locator);
    let scratch_and_bytes = host.resource_reservations_for_test();
    drop(producer);
    let second =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 8)).await;
    let bytes_only = host.resource_reservations_for_test();
    drop(chunk);
    let third =
        tokio::time::timeout(std::time::Duration::from_secs(5), bound.close(&mut host, 9)).await;
    let drained = tokio::time::timeout(std::time::Duration::from_secs(5), scope.drain()).await;
    assert!(
        third.unwrap().is_ok() && drained.unwrap().is_ok(),
        "actual Screen cleanup failed"
    );
    assert!(error.is_none(), "bound Screen scenario failed: {error:?}");
    assert!(
        flags.0 && flags.1,
        "old Screen completion reopened input after a new catalog generation"
    );
    assert!(matches!(
        first.unwrap(),
        Err(LocalEngineError::Host(HostError::ResourceDebt))
    ));
    assert!(matches!(
        second.unwrap(),
        Err(LocalEngineError::Host(HostError::ResourceDebt))
    ));
    assert_eq!(
        (scratch_and_bytes, bytes_only),
        (2, 1),
        "Screen scratch/chunk backing was refunded before real final destruction"
    );
    assert_eq!(host.cleanup_operation_for_test(locator), operation);
    assert_eq!(host.resource_reservations_for_test(), 0);
    assert_eq!(host.completed_facts(attempt, locator).unwrap().len(), 2);
}

#[tokio::test]
async fn host_engine_revocation_and_late_old_auth_end_preserve_retained_child_and_new_frontend_authority(
) {
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::InputEpoch;
    let (mut host, attempt) = catalog();
    let (mut bound, opened, _restart) = test_bound_program(&mut host, attempt, 2).await;
    let channel = ChannelInstance::new(1).unwrap();
    let first = bound.frontend.as_ref().unwrap().attachment();
    let old_frontend = host
        .frontend_for_generation_for_test(first.frontend)
        .unwrap();
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        opened.map_err(|_| "open")?;
        let writer = bound
            .engine
            .writer_identity_for_test(channel)
            .ok_or("writer")?;
        bound.begin_detach(&mut host).map_err(|_| "detach")?;
        bound.finish_detach(&mut host).await.map_err(|_| "fence")?;
        let issue = host
            .begin_issue(attempt, first.locator, 7, 107)
            .map_err(|_| "old-issue")?;
        let HostDecision::GrantIssued(offer) = host
            .apply_policy_result(
                PolicyResult::allow_for_test(issue, 1000, "fixture-account"),
                8,
            )
            .map_err(|_| "old-offer")?
        else {
            return Err("old-decision");
        };
        let before = host.resource_reservations_for_test();
        host.revoke_account(1000).map_err(|_| "revoke")?;
        let old_refused = host
            .begin_consume(attempt, offer.grant(), offer.binding(), 9, 109)
            .is_err();
        let unchanged = before == host.resource_reservations_for_test()
            && bound.engine.writer_identity_for_test(channel) == Some(writer);
        let frontend = host
            .admit_frontend(AuthenticatedPeer::for_test(
                host.instance(),
                HostMode::System,
            ))
            .map_err(|_| "fresh-frontend")?;
        let intent = host
            .begin_authentication(frontend, 10, 110)
            .map_err(|_| "fresh-auth")?;
        let HostDecision::Authenticated(fresh) = host
            .apply_policy_result(
                PolicyResult::allow_for_test(intent, 1000, "fixture-account"),
                11,
            )
            .map_err(|_| "fresh-proof")?
        else {
            return Err("fresh-decision");
        };
        let authorized =
            try_authorize(&mut host, fresh, first.locator, 12).map_err(|_| "fresh-grant")?;
        let second = bound
            .attach(&mut host, authorized)
            .map_err(|_| "fresh-attach")?;
        let old_end = host.retire_frontend(old_frontend).is_ok();
        let _consumer = recover_bound_data(&bound, second, channel, 240).await?;
        bound
            .user_input(
                second,
                channel,
                InputEpoch::new([120; 16]).unwrap(),
                0,
                b"x",
            )
            .map_err(|_| "current-input")?
            .accepted()
            .await
            .map_err(|_| "current-accepted")?;
        let stale_loss = bound.frontend_lost(&mut host, first).is_err();
        bound
            .user_input(
                second,
                channel,
                InputEpoch::new([120; 16]).unwrap(),
                1,
                b"y",
            )
            .map_err(|_| "after-stale-input")?
            .accepted()
            .await
            .map_err(|_| "after-stale-accepted")?;
        while bound
            .engine
            .input_position(channel)
            .map_err(|_| "position")?
            .committed
            != 2
        {
            tokio::task::yield_now().await;
        }
        Ok::<_, &'static str>((
            old_refused,
            unchanged,
            old_end,
            stale_loss,
            second.epoch.get() > first.epoch.get(),
            fresh,
        ))
    })
    .await;
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        bound.close(&mut host, 100),
    )
    .await;
    assert!(cleanup.unwrap().is_ok());
    let (old_refused, unchanged, old_end, stale_loss, fresh_epoch, fresh) = exercised
        .expect("bounded scenario")
        .expect("revocation scenario");
    assert!(old_refused && unchanged && old_end && stale_loss && fresh_epoch);
    assert!(
        host.completed_facts(attempt, first.locator).is_err(),
        "revoked attempt read completed owner metadata"
    );
    assert_eq!(
        host.completed_facts(fresh, first.locator).unwrap()[0]
            .input
            .committed,
        2
    );
    assert_eq!(host.resource_reservations_for_test(), 0);
}
