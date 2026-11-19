use super::*;
use crate::session_owner::authorization::{
    AuthenticatedPeer, AuthenticationAttempt, HostMode, PolicyResult,
};
use crate::session_owner::host::{HostDecision, HostLimits};
use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use crate::session_owner::resources::OwnerResourceClient;
use crate::session_owner::status_contract::StatusCollector;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
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

fn host() -> HostState {
    let bytes = ByteLimits {
        channel_bytes: 32 << 20,
        session_bytes: 64 << 20,
        account_bytes: 128 << 20,
        global_bytes: 256 << 20,
    };
    HostState::new(
        HostMode::System,
        HostLimits::new(
            ResourceLimits {
                max_reservations: 256,
                screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                    .unwrap(),
                snapshot_transfer: bytes,
                control_queue: bytes,
            },
            16,
            16,
            16,
            16,
            100,
        )
        .unwrap(),
    )
    .unwrap()
}
fn admit(h: &mut HostState) -> FrontendAdmission {
    h.admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap()
}
fn authenticate(
    h: &mut HostState,
    f: FrontendAdmission,
    uid: u32,
    name: &str,
    now: u64,
) -> AuthenticationAttempt {
    let work = h.begin_authentication(f, now, now + 100).unwrap();
    let HostDecision::Authenticated(attempt) = h
        .apply_policy_result(PolicyResult::allow_for_test(work, uid, name), now + 1)
        .unwrap()
    else {
        panic!("inert policy fixture refused")
    };
    attempt
}
struct Fixture {
    host: HostState,
    requester: FrontendAdmission,
    owners: Vec<LocalOwnerEngine>,
    _restarts: Vec<tokio::sync::watch::Sender<RestartSignal>>,
    calls: Vec<Arc<AtomicUsize>>,
    attempt: AuthenticationAttempt,
    uid: u32,
    name: String,
    now: u64,
}
fn fixture(count: usize) -> Fixture {
    let mut h = host();
    if count > 128 {
        h.status_capacity_for_test(count);
    } // Explicit pagination-only cap fixture; production stays128.
    let f = admit(&mut h);
    let mut owners = Vec::new();
    let mut restarts = Vec::new();
    let mut calls = Vec::new();
    let mut attempt = None;
    let mut uid = 0;
    let mut name = String::new();
    let mut now = 0;
    for index in 0..count {
        if index % 16 == 0 {
            uid = 1000 + (index / 16) as u32;
            name = format!("fixture-account-{}", index / 16);
            now = (index / 16) as u64 * 1000;
            attempt = Some(authenticate(&mut h, f, uid, &name, now));
            now += 2;
        }
        let (locator, provisioning) = h.create_session_provisioned(attempt.unwrap(), now).unwrap();
        now += 1;
        let (engine, restart, called) =
            empty_engine_account(locator, provisioning.client(), uid, &name);
        owners.push(h.bind_local_engine(provisioning, engine).ok().unwrap());
        restarts.push(restart);
        calls.push(called);
    }
    if attempt.is_none() {
        attempt = Some(authenticate(&mut h, f, 1000, "fixture-account", 0));
        now = 2;
    }
    h.install_serving_for_test(f); // Fixture-only listener receipt: no production constructor exists.
    Fixture {
        host: h,
        requester: f,
        owners,
        _restarts: restarts,
        calls,
        attempt: attempt.unwrap(),
        uid,
        name,
        now,
    }
}
#[test]
fn status529_admission_and_candidate_never_supply_serving_authority() {
    let mut h = host();
    let f = admit(&mut h);
    let candidate = crate::session_owner::status_contract::FrontendIdentity {
        generation: transport::session_resume::FrontendGeneration::new([9; 16]).unwrap(),
        build: crate::session_owner::status_contract::BuildIdentity::new(
            "candidate-marker",
            1,
            [3; 32],
        )
        .unwrap(),
    };
    let _guard = h.begin_replacement(f, candidate).unwrap();
    assert_eq!(h.status_page(f, None, &[]), Err(StatusError::Unavailable));
}
#[test]
fn status529_foreign_and_retired_requesters_refuse() {
    let mut h = host();
    let f = admit(&mut h);
    let mut foreign = host();
    let other = admit(&mut foreign);
    assert_eq!(h.status_page(other, None, &[]), Err(StatusError::Refused));
    h.retire_frontend(f).unwrap();
    assert_eq!(h.status_page(f, None, &[]), Err(StatusError::Refused));
}
#[test]
fn status529_fixture_serving_empty_page_has_actual_resident_build() {
    let mut fixture = fixture(0);
    let page = fixture
        .host
        .status_page(fixture.requester, None, &[])
        .unwrap();
    assert_eq!(page.total, 0);
    assert!(page.owners.is_empty() && page.next.is_none());
    assert_eq!(page.host_build.version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(page.host_build.build, crate::state::build_label());
    assert_eq!(
        page.host_build.checksum,
        decode_checksum(&crate::state::self_checksum().unwrap()).unwrap()
    );
}
#[test]
fn status529_fixture_pages65_and129_are_complete_bounded_and_do_not_spawn() {
    for count in [65, 129] {
        let mut fixture = fixture(count);
        let refs: Vec<_> = fixture.owners.iter().collect();
        let mut cursor = None;
        let mut collector = StatusCollector::new(count).unwrap();
        loop {
            let page = fixture
                .host
                .status_page(fixture.requester, cursor, &refs)
                .unwrap();
            assert!(page.owners.len() <= 64);
            cursor = page.next;
            let done = collector.accept(page).unwrap();
            if cursor.is_none() {
                assert!(done);
                break;
            }
        }
        assert_eq!(collector.finish().unwrap().len(), count);
        assert!(fixture
            .calls
            .iter()
            .all(|calls| calls.load(Ordering::SeqCst) == 0));
    }
}
#[test]
fn status529_checksum_decoder_rejects_unverified_shape() {
    for invalid in [
        "".to_string(),
        "0".repeat(63),
        "g".repeat(64),
        "0".repeat(66),
    ] {
        assert_eq!(decode_checksum(&invalid), Err(StatusError::Unavailable));
    }
    assert_eq!(decode_checksum(&"ab".repeat(32)).unwrap(), [0xab; 32]);
}
#[test]
fn status529_fixture_missing_duplicate_and_foreign_rosters_never_emit_partial_page() {
    let foreign = fixture(1);
    let mut fixture = fixture(2);
    assert_eq!(
        fixture
            .host
            .status_page(fixture.requester, None, &[&fixture.owners[0]]),
        Err(StatusError::Unavailable)
    );
    assert_eq!(
        fixture.host.status_page(
            fixture.requester,
            None,
            &[&fixture.owners[0], &fixture.owners[0]]
        ),
        Err(StatusError::Unavailable)
    );
    assert_eq!(
        fixture.host.status_page(
            fixture.requester,
            None,
            &[&fixture.owners[0], &foreign.owners[0]]
        ),
        Err(StatusError::Unavailable)
    );
    assert_eq!(
        fixture
            .host
            .status_page(
                fixture.requester,
                None,
                &fixture.owners.iter().collect::<Vec<_>>()
            )
            .unwrap()
            .total,
        2
    );
}
#[test]
fn status529_fixture_cursor_requires_exact_epoch_index_and_requester() {
    let mut fixture = fixture(65);
    let refs: Vec<_> = fixture.owners.iter().collect();
    let page = fixture
        .host
        .status_page(fixture.requester, None, &refs)
        .unwrap();
    let mut wrong = page.next.unwrap();
    wrong.index += 1;
    assert_eq!(
        fixture
            .host
            .status_page(fixture.requester, Some(wrong), &refs),
        Err(StatusError::StaleCursor)
    );
    let page = fixture
        .host
        .status_page(fixture.requester, None, &refs)
        .unwrap();
    let mut wrong = page.next.unwrap();
    wrong.epoch = crate::session_owner::status_contract::StatusEpoch::new([99; 16]).unwrap();
    assert_eq!(
        fixture
            .host
            .status_page(fixture.requester, Some(wrong), &refs),
        Err(StatusError::StaleCursor)
    );
    let page = fixture
        .host
        .status_page(fixture.requester, None, &refs)
        .unwrap();
    let other = admit(&mut fixture.host);
    assert_eq!(
        fixture.host.status_page(other, page.next, &refs),
        Err(StatusError::StaleCursor)
    );
}
#[tokio::test]
async fn status529_fixture_equal_count_roster_aba_invalidates_old_continuation() {
    let mut fixture = fixture(65);
    let cursor = fixture
        .host
        .status_page(
            fixture.requester,
            None,
            &fixture.owners.iter().collect::<Vec<_>>(),
        )
        .unwrap()
        .next;
    let mut removed = fixture.owners.remove(0);
    removed.close(&mut fixture.host, fixture.now).await.unwrap();
    fixture.now += 1;
    let (locator, provisioning) = fixture
        .host
        .create_session_provisioned(fixture.attempt, fixture.now)
        .unwrap();
    let (engine, restart, calls) =
        empty_engine_account(locator, provisioning.client(), fixture.uid, &fixture.name);
    fixture.owners.push(
        fixture
            .host
            .bind_local_engine(provisioning, engine)
            .ok()
            .unwrap(),
    );
    fixture._restarts.push(restart);
    fixture.calls.push(calls);
    assert_eq!(fixture.host.catalog_len(), 65);
    assert_eq!(
        fixture.host.status_page(
            fixture.requester,
            cursor,
            &fixture.owners.iter().collect::<Vec<_>>()
        ),
        Err(StatusError::StaleCursor)
    );
}
#[tokio::test]
async fn status529_fixture_revision_overflow_is_unavailable_without_blocking_actual_cleanup() {
    let mut fixture = fixture(1);
    fixture.host.exhaust_status_revision_for_test();
    fixture.owners[0]
        .close(&mut fixture.host, fixture.now)
        .await
        .unwrap();
    assert_eq!(fixture.host.status_revision(), None);
    assert_eq!(fixture.host.catalog_len(), 0);
    assert_eq!(
        fixture.host.status_page(fixture.requester, None, &[]),
        Err(StatusError::Unavailable)
    );
}
#[test]
fn status529_fixture_page_encoding_contains_only_status_fields() {
    let mut fixture = fixture(1);
    let page = fixture
        .host
        .status_page(
            fixture.requester,
            None,
            &fixture.owners.iter().collect::<Vec<_>>(),
        )
        .unwrap();
    let mut bytes = Vec::new();
    page.put(&mut bytes);
    let diagnostic = format!("{page:?}");
    for marker in [
        "private-command-marker",
        "private-input-marker",
        "private-output-marker",
        "private-key-marker",
        "private-grant-marker",
    ] {
        assert!(!bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()));
        assert!(!diagnostic.contains(marker));
    }
}

use crate::session_owner::host::AuthorizedAttachment;
use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
use crate::session_owner::resource_contract::ReservationKind;
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::{Attachment, InputEpoch, RequestId};
fn authorize(
    h: &mut HostState,
    attempt: AuthenticationAttempt,
    locator: SessionLocator,
    now: u64,
) -> AuthorizedAttachment {
    let work = h.begin_issue(attempt, locator, now, now + 100).unwrap();
    let HostDecision::GrantIssued(grant) = h
        .apply_policy_result(
            PolicyResult::allow_for_test(work, 1000, "fixture-account"),
            now + 1,
        )
        .unwrap()
    else {
        panic!("grant fixture refused")
    };
    let work = h
        .begin_consume(attempt, grant.grant(), grant.binding(), now + 2, now + 102)
        .unwrap();
    let HostDecision::GrantConsumed(authorized) = h
        .apply_policy_result(
            PolicyResult::allow_for_test(work, 1000, "fixture-account"),
            now + 3,
        )
        .unwrap()
    else {
        panic!("consume fixture refused")
    };
    authorized
}
struct LiveFixture {
    host: HostState,
    requester: FrontendAdmission,
    owner: LocalOwnerEngine,
    control: crate::session_owner::engine::tests::integrated::HostFixtureControl,
    attachment: Attachment,
    channel: ChannelInstance,
    input: InputEpoch,
    consumer: Option<NoScreenConsumer>,
    _restart: tokio::sync::watch::Sender<RestartSignal>,
}
async fn live(unobserved: bool) -> LiveFixture {
    let mut h = host();
    let f = admit(&mut h);
    let attempt = authenticate(&mut h, f, 1000, "fixture-account", 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let client = provisioning.client();
    let channel = ChannelInstance::new(1).unwrap();
    let transfer = |retained: usize, serial: u64| {
        let token = provisioning
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
            .unwrap();
        TransferAllowance::admit_reserved(client.clone(), token, retained).unwrap()
    };
    let consumer_allowance = transfer(4096, 60);
    let catalog_allowance = transfer(0, 61);
    let producer_allowance = transfer(4096, 63);
    let (engine, restart, control) =
        crate::session_owner::engine::tests::integrated::host_fixture_controlled(locator, client);
    control.hold_leader_observation(unobserved);
    control.set_output_script(b"private-output-marker".to_vec());
    let mut owner = h.bind_local_engine(provisioning, engine).ok().unwrap();
    let authorized = authorize(&mut h, attempt, locator, 3);
    let attachment = owner.attach(&mut h, authorized).unwrap();
    let input = InputEpoch::new([88; 16]).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = owner
        .provision_channel_resources(
            &h,
            attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(50).unwrap(),
            128,
            input,
        )
        .unwrap();
    owner
        .open_admitted(
            &mut h,
            OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: b"private-command-marker".to_vec(),
            },
            None,
            supplied,
        )
        .await
        .unwrap();
    let mut consumer = NoScreenConsumer::new(channel, consumer_allowance).unwrap();
    if !unobserved {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !owner.catalog_available() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut transaction = owner.catalog(attachment, catalog_allowance).unwrap();
        let recovery = transport::session_resume::RecoveryRequest {
            attachment,
            channel,
            parser: transport::session_resume::ParserContinuity::DataCursor {
                cursor: consumer.cursor(),
            },
        };
        let id = RequestId::new(62).unwrap();
        let mut producer = owner
            .recover(
                attachment,
                &mut transaction,
                recovery,
                transport::session_resume::RecoveryId::new([60; 16]).unwrap(),
                id,
                producer_allowance,
            )
            .unwrap();
        consumer.begin(id, recovery, producer.start()).unwrap();
        while let Some(chunk) = producer.next_chunk().unwrap() {
            consumer.consume(&chunk).unwrap();
        }
        let (end, ready) = producer.end().unwrap();
        transaction
            .accept_consumed(consumer.finish(end, ready).unwrap())
            .unwrap();
        owner.finish_recovery(attachment, transaction).unwrap();
    }
    h.install_serving_for_test(f);
    LiveFixture {
        host: h,
        requester: f,
        owner,
        control,
        attachment,
        channel,
        input,
        consumer: Some(consumer),
        _restart: restart,
    }
}
async fn wait_unavailable(owner: &LocalOwnerEngine) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while owner.status_observation().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_actual_unobserved_leader_is_unavailable_until_real_running_observation() {
    let mut live = live(true).await;
    let revision = live.host.status_revision();
    assert_eq!(
        live.host.status_page(live.requester, None, &[&live.owner]),
        Err(StatusError::Unavailable)
    );
    live.control.hold_leader_observation(false);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while live.owner.status_observation().is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(live.host.status_revision(), revision);
    let page = live
        .host
        .status_page(live.requester, None, &[&live.owner])
        .unwrap();
    assert_eq!(
        (
            page.owners[0].active_channels,
            page.owners[0].total_channels
        ),
        (1, 1)
    );
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 100).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_actual_terminal_observation_between_sweeps_never_emits_stale_page() {
    let mut live = live(false).await;
    let revision = live.host.status_revision();
    let result = live
        .host
        .status_page_inner(live.requester, None, &[&live.owner], || {
            live.control.exit_backend();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while live.owner.status_observation().is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "actual reaper observation"
                );
                std::thread::yield_now();
            }
        });
    assert_eq!(result, Err(StatusError::Unavailable));
    assert_eq!(live.host.status_revision(), revision);
    assert!(live.host.status_snapshot.is_none());
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 100).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_actual_worker_and_writer_failure_without_host_mutation_are_unavailable() {
    for writer in [false, true] {
        let mut live = live(false).await;
        let revision = live.host.status_revision();
        let engine_revision = live.owner.status_revision();
        if writer {
            live.control.fail_writer();
            live.owner
                .user_input(
                    live.attachment,
                    live.channel,
                    live.input,
                    0,
                    b"failure-trigger",
                )
                .unwrap()
                .accepted()
                .await
                .unwrap();
        } else {
            live.control.finish_reader();
        }
        wait_unavailable(&live.owner).await;
        assert_eq!(live.host.status_revision(), revision);
        assert_eq!(live.owner.status_revision(), engine_revision);
        assert_eq!(
            live.host.status_page(live.requester, None, &[&live.owner]),
            Err(StatusError::Unavailable)
        );
        assert_eq!(live.control.kills(16), 0);
        drop(live.consumer.take());
        live.owner.close(&mut live.host, 100).await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_exact_completion_preserves_final_counts_after_live_map_destruction() {
    let mut live = live(false).await;
    let before = live
        .host
        .status_page(live.requester, None, &[&live.owner])
        .unwrap();
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 100).await.unwrap();
    assert!(live.owner.supervision_complete());
    let page = live.host.status_page(live.requester, None, &[]).unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(
        (
            page.owners[0].active_channels,
            page.owners[0].total_channels
        ),
        (0, 1)
    );
    assert_eq!(page.owners[0].build, before.owners[0].build);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_real_private_payload_and_candidate_markers_never_enter_page_or_diagnostic() {
    let mut live = live(false).await;
    live.control.hold_writes();
    let key_fixture = b"private-key-marker";
    let grant_fixture = b"private-grant-marker";
    let payload = [
        b"private-input-marker:".as_slice(),
        key_fixture,
        grant_fixture,
    ]
    .concat();
    live.owner
        .user_input(live.attachment, live.channel, live.input, 0, &payload)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    let candidate = FrontendIdentity {
        generation: transport::session_resume::FrontendGeneration::new([9; 16]).unwrap(),
        build: BuildIdentity::new("candidate-marker", 1, [3; 32]).unwrap(),
    };
    let _guard = live
        .host
        .begin_replacement(live.requester, candidate.clone())
        .unwrap();
    let page = live
        .host
        .status_page(live.requester, None, &[&live.owner])
        .unwrap();
    assert_ne!(page.host_build, candidate.build);
    assert_ne!(page.owners[0].build, candidate.build);
    let mut encoded = Vec::new();
    page.put(&mut encoded);
    let diagnostic = format!("{page:?}");
    for marker in [
        "private-command-marker",
        "private-input-marker",
        "private-output-marker",
        "private-key-marker",
        "private-grant-marker",
        "candidate-marker",
    ] {
        assert!(!encoded
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()));
        assert!(!diagnostic.contains(marker));
    }
    live.control.release_writes();
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 100).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_actual_exit_between_pages_invalidates_without_host_mutation() {
    let mut live = live(false).await;
    let mut owners = Vec::new();
    let mut restarts = Vec::new();
    for group in 0..4 {
        let uid = 1001 + group;
        let name = format!("status-account-{group}");
        let now = 1000 + u64::from(group) * 1000;
        let attempt = authenticate(&mut live.host, live.requester, uid, &name, now);
        for offset in 0..16 {
            let (locator, provisioning) = live
                .host
                .create_session_provisioned(attempt, now + 2 + offset)
                .unwrap();
            let (engine, restart, _) =
                empty_engine_account(locator, provisioning.client(), uid, &name);
            owners.push(
                live.host
                    .bind_local_engine(provisioning, engine)
                    .ok()
                    .unwrap(),
            );
            restarts.push(restart);
        }
    }
    let refs: Vec<_> = owners.iter().chain(std::iter::once(&live.owner)).collect();
    let first = live.host.status_page(live.requester, None, &refs).unwrap();
    assert_eq!(first.total, 65);
    assert!(first.next.is_some());
    let revision = live.host.status_revision();
    live.control.exit_backend();
    wait_unavailable(&live.owner).await;
    assert_eq!(live.host.status_revision(), revision);
    assert_eq!(
        live.host.status_page(live.requester, first.next, &refs),
        Err(StatusError::StaleCursor)
    );
    drop(refs);
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 10000).await.unwrap();
}
#[test]
fn status529_fixture_serving_loss_invalidates_pages_and_candidate_cannot_restore_it() {
    let mut fixture = fixture(65);
    let refs: Vec<_> = fixture.owners.iter().collect();
    let page = fixture
        .host
        .status_page(fixture.requester, None, &refs)
        .unwrap();
    fixture.host.retire_frontend(fixture.requester).unwrap();
    assert!(fixture.host.status_serving.is_none());
    assert!(fixture.host.status_snapshot.is_none());
    assert_eq!(
        fixture
            .host
            .status_page(fixture.requester, page.next, &refs),
        Err(StatusError::Refused)
    );
    let other = admit(&mut fixture.host);
    let candidate = FrontendIdentity {
        generation: transport::session_resume::FrontendGeneration::new([9; 16]).unwrap(),
        build: BuildIdentity::new("candidate-marker", 1, [3; 32]).unwrap(),
    };
    let _guard = fixture.host.begin_replacement(other, candidate).unwrap();
    assert_eq!(
        fixture.host.status_page(other, None, &refs),
        Err(StatusError::Unavailable)
    );
}
#[test]
fn status529_fixture_owner_drop_without_host_mutation_cannot_turn_unknown_into_inactive_zero() {
    let mut fixture = fixture(2);
    fixture
        .host
        .status_page(
            fixture.requester,
            None,
            &fixture.owners.iter().collect::<Vec<_>>(),
        )
        .unwrap();
    let revision = fixture.host.status_revision();
    drop(fixture.owners.pop().unwrap());
    assert_eq!(fixture.host.status_revision(), revision);
    assert_eq!(
        fixture.host.status_page(
            fixture.requester,
            None,
            &fixture.owners.iter().collect::<Vec<_>>()
        ),
        Err(StatusError::Unavailable)
    );
    assert_eq!(fixture.host.catalog_len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status529_final_total_keeps_accepted_identity_whose_open_failed_before_install() {
    let mut live = live(false).await;
    let channel = ChannelInstance::new(2).unwrap();
    let locator = live.attachment.locator;
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = live
        .owner
        .provision_channel_resources(
            &live.host,
            live.attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(80).unwrap(),
            128,
            InputEpoch::new([89; 16]).unwrap(),
        )
        .unwrap();
    live.control.fail_next_spawn();
    assert!(live
        .owner
        .open_admitted(
            &mut live.host,
            OpenRequest {
                stream: 17,
                kind: transport::channel::ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: b"failed-slot-marker".to_vec()
            },
            None,
            supplied
        )
        .await
        .is_err());
    assert_eq!(
        live.host.status_page(live.requester, None, &[&live.owner]),
        Err(StatusError::Unavailable)
    );
    drop(live.consumer.take());
    live.owner.close(&mut live.host, 100).await.unwrap();
    let page = live.host.status_page(live.requester, None, &[]).unwrap();
    assert_eq!(
        (
            page.owners[0].active_channels,
            page.owners[0].total_channels
        ),
        (0, 2)
    );
}
