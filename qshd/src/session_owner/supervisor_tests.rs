use super::super::authorization::AuthenticatedPeer;
use super::super::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use super::*;
use crate::session_owner::authorization::HostMode;
use crate::session_owner::host::{HostLimits, HostState};
use crate::session_owner::host_engine::LocalOwnerEngine;

fn host() -> HostState {
    let bytes = ByteLimits {
        channel_bytes: 32 << 20,
        session_bytes: 64 << 20,
        account_bytes: 128 << 20,
        global_bytes: 256 << 20,
    };
    let resources = ResourceLimits {
        max_reservations: 128,
        screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let limits = HostLimits::new(resources, 4, 4, 4, 4, 100).unwrap();
    HostState::new(HostMode::System, limits).unwrap()
}

// These controls model only Capsule receipt order. No OS child, descriptor or
// serving proof is manufactured; actual handoff is exercised by maintained CI.
fn frontend(supervisor: &mut HostSupervisor, host: &mut HostState) -> SupervisedFrontend {
    supervisor.test_frontend(host).unwrap()
}
#[test]
fn supervisor529_each_exact_loss_revokes_admission_but_requires_both_receipts() {
    for wait_first in [false, true] {
        let mut h = host();
        let mut supervisor = HostSupervisor::new(&mut h).unwrap();
        let handle = frontend(&mut supervisor, &mut h);
        let registration = supervisor.test_registration(&handle);
        let sentinel = h
            .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
            .unwrap();
        if wait_first {
            supervisor.test_wait(&handle, false);
        } else {
            supervisor.test_eof(&handle);
        }
        assert_eq!(
            supervisor.poll_frontend(&handle, &mut h).unwrap(),
            SupervisionProgress::LossPending
        );
        assert!(!h.frontend_is_current(registration));
        assert!(h.frontend_is_current(sentinel));
        assert_eq!(supervisor.in_use(), 1);
        if wait_first {
            supervisor.test_eof(&handle);
        } else {
            supervisor.test_wait(&handle, false);
        }
        assert_eq!(
            supervisor.poll_frontend(&handle, &mut h).unwrap(),
            SupervisionProgress::Settled
        );
        assert_eq!(supervisor.in_use(), 0);
    }
}
#[test]
fn supervisor529_unknown_wait_retains_capacity_without_restoring_admission() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let registration = supervisor.test_registration(&handle);
    supervisor.test_wait(&handle, true);
    supervisor.test_eof(&handle);
    assert_eq!(
        supervisor.poll_frontend(&handle, &mut h).unwrap(),
        SupervisionProgress::Unknown
    );
    assert!(!h.frontend_is_current(registration));
    assert_eq!(supervisor.in_use(), 1);
}
#[test]
fn supervisor529_foreign_handle_and_host_cannot_retire_another_registration() {
    let mut h = host();
    let mut other = host();
    let mut first = HostSupervisor::new(&mut h).unwrap();
    let mut second = HostSupervisor::new(&mut other).unwrap();
    let own = frontend(&mut first, &mut h);
    let foreign = frontend(&mut second, &mut other);
    let own_registration = first.test_registration(&own);
    let foreign_registration = second.test_registration(&foreign);
    assert_eq!(
        first.poll_frontend(&foreign, &mut h),
        Err(SupervisionError::Refused)
    );
    assert_eq!(
        first.poll_frontend(&own, &mut other),
        Err(SupervisionError::Refused)
    );
    assert!(h.frontend_is_current(own_registration));
    assert!(other.frontend_is_current(foreign_registration));
}
#[test]
fn supervisor529_stale_loss_cannot_revoke_a_successor_incarnation() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let old = frontend(&mut supervisor, &mut h);
    supervisor.test_eof(&old);
    supervisor.test_wait(&old, false);
    assert_eq!(
        supervisor.poll_frontend(&old, &mut h).unwrap(),
        SupervisionProgress::Settled
    );
    let next = frontend(&mut supervisor, &mut h);
    let registration = supervisor.test_registration(&next);
    let _ = supervisor.poll_frontend(&old, &mut h);
    assert!(h.frontend_is_current(registration));
    assert_eq!(
        supervisor.poll_frontend(&next, &mut h).unwrap(),
        SupervisionProgress::AttachedChannel(registration)
    );
}
#[tokio::test]
async fn supervisor529_administrative_stop_retains_physical_launch_until_settlement() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let registration = supervisor.test_registration(&handle);
    supervisor.begin_stop(&mut h).unwrap();
    assert!(!h.frontend_is_current(registration));
    assert!(supervisor.test_frontend(&mut h).is_err());
    assert!(h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .is_err());
    assert_eq!(
        supervisor.finish_stop(&mut h, 1).await,
        Err(SupervisionError::CleanupPending)
    );
    assert_eq!(supervisor.in_use(), 1);
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    supervisor.finish_stop(&mut h, 2).await.unwrap();
    assert_eq!(supervisor.in_use(), 0);
}

#[test]
fn supervisor529_second_scope_refuses_and_drop_cannot_release_the_claim() {
    let mut h = host();
    let supervisor = HostSupervisor::new(&mut h).unwrap();
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
    drop(supervisor);
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
}
#[test]
fn supervisor529_foreign_scope_cannot_begin_host_stop() {
    let mut h = host();
    let mut other = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    assert_eq!(
        supervisor.begin_stop(&mut other),
        Err(SupervisionError::Refused)
    );
    assert!(other
        .admit_frontend(AuthenticatedPeer::for_test(
            other.instance(),
            HostMode::System
        ))
        .is_ok());
    assert!(h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .is_ok());
}
#[tokio::test]
async fn supervisor529_unassociated_admission_blocks_settled_stop_claim() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let external = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap();
    supervisor.begin_stop(&mut h).unwrap();
    assert!(!h.frontend_is_current(external));
    assert_eq!(
        supervisor.finish_stop(&mut h, 1).await,
        Err(SupervisionError::CleanupPending)
    );
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
}

#[tokio::test]
async fn supervisor529_retired_unassociated_admission_cannot_disappear_from_stop_debt() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let external = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap();
    h.retire_frontend(external).unwrap();
    supervisor.begin_stop(&mut h).unwrap();
    assert_eq!(
        supervisor.finish_stop(&mut h, 1).await,
        Err(SupervisionError::CleanupPending)
    );
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
}
#[tokio::test]
async fn supervisor529_stale_stop_cannot_discharge_successor_claim() {
    let mut h = host();
    let mut first = HostSupervisor::new(&mut h).unwrap();
    first.begin_stop(&mut h).unwrap();
    first.finish_stop(&mut h, 1).await.unwrap();
    let mut successor = HostSupervisor::new(&mut h).unwrap();
    assert_eq!(
        first.finish_stop(&mut h, 2).await,
        Err(SupervisionError::Refused)
    );
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
    successor.begin_stop(&mut h).unwrap();
    successor.finish_stop(&mut h, 3).await.unwrap();
    assert!(h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .is_err());
}

#[test]
fn supervisor529_repeated_handoff_refuses_without_retiring_existing_capsule() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let index = supervisor.index(&handle).unwrap();
    let registration = supervisor.test_registration(&handle);
    let result = supervisor.launches.take_host_dispatch(
        &supervisor.associations[index].launch,
        &mut h,
        &supervisor.claim,
        supervisor.mode,
        64,
    );
    assert!(matches!(
        result,
        Err(super::super::local_channel::AdmissionError::Refused)
    ));
    assert!(h.frontend_is_current(registration));
    assert_eq!(
        supervisor.poll_frontend(&handle, &mut h).unwrap(),
        SupervisionProgress::AttachedChannel(registration)
    );
}

#[tokio::test]
async fn supervisor529_unpublished_capsule_debt_blocks_stop_without_registration() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    // Models failed preparation retained in the launch owner before publication.
    let unpublished = supervisor.launches.model_capsule(h.instance()).unwrap();
    supervisor.launches.test_wait(&unpublished, true);
    supervisor.launches.model_eof(&unpublished);
    supervisor.begin_stop(&mut h).unwrap();
    assert_eq!(supervisor.in_use(), 1);
    assert_eq!(
        supervisor.finish_stop(&mut h, 1).await,
        Err(SupervisionError::CleanupPending)
    );
}

#[test]
fn supervisor529_dropped_handle_revokes_only_its_admission_on_owned_poll() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let gone = frontend(&mut supervisor, &mut h);
    let gone_registration = supervisor.test_registration(&gone);
    let stay = frontend(&mut supervisor, &mut h);
    let stay_registration = supervisor.test_registration(&stay);
    drop(gone);
    supervisor.poll_frontends(&mut h).unwrap();
    assert!(!h.frontend_is_current(gone_registration));
    assert!(h.frontend_is_current(stay_registration));
    assert_eq!(
        supervisor.in_use(),
        2,
        "logical cancellation is not physical settlement"
    );
}
#[test]
fn supervisor529_retired_unknown_frontends_keep_the_actual_admission_cap_charged() {
    use crate::session_owner::host::HostError;
    let mut h = host();
    let _supervisor = HostSupervisor::new(&mut h).unwrap();
    for _ in 0..4 {
        let f = h
            .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
            .unwrap();
        h.retire_frontend(f).unwrap();
    }
    assert!(matches!(
        h.admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System)),
        Err(HostError::Capacity)
    ));
}

use crate::session_owner::authorization::{AuthenticationAttempt, PolicyResult};
use crate::session_owner::host::{AuthorizedAttachment, HostDecision};
use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
use crate::session_owner::recovery_runtime::{NoScreenConsumer, TransferAllowance};
use crate::session_owner::resource_contract::ReservationKind;
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::{Attachment, InputEpoch, RequestId, SessionLocator};

fn authenticate(h: &mut HostState, frontend: FrontendAdmission, now: u64) -> AuthenticationAttempt {
    let work = h.begin_authentication(frontend, now, now + 100).unwrap();
    let HostDecision::Authenticated(attempt) = h
        .apply_policy_result(
            PolicyResult::allow_for_test(work, 1000, "fixture-account"),
            now + 1,
        )
        .unwrap()
    else {
        panic!("fixture authentication refused")
    };
    attempt
}
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
        panic!("fixture grant refused")
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
        panic!("fixture consume refused")
    };
    authorized
}
struct BoundFixture {
    index: usize,
    locator: SessionLocator,
    attachment: Attachment,
    channel: ChannelInstance,
    input: InputEpoch,
    control: crate::session_owner::engine::tests::integrated::HostFixtureControl,
    consumer: NoScreenConsumer,
    _restart: tokio::sync::watch::Sender<transport::channel_server::RestartSignal>,
}
async fn program(
    supervisor: &mut HostSupervisor,
    h: &mut HostState,
    handle: &SupervisedFrontend,
) -> BoundFixture {
    let attempt = authenticate(h, supervisor.test_registration(handle), 0);
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
    let mut bound = match h.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("actual fixture binding refused"),
    };
    let index = supervisor.owners.len();
    if let Err(failure) = supervisor.add_owner(h, bound) {
        let (_, mut returned) = failure.into_parts();
        drop((consumer_allowance, catalog_allowance, producer_allowance));
        returned.close(h, 3).await.unwrap();
        panic!("supervisor refused its actual bound owner");
    }
    let authorized = authorize(h, attempt, locator, 3);
    bound = supervisor.owners.remove(index);
    let attachment = bound.attach(h, authorized).unwrap();
    let input = InputEpoch::new([88; 16]).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = bound
        .provision_channel_resources(
            h,
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
    bound
        .open_admitted(
            h,
            transport::channel::OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            supplied,
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !bound.catalog_available() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut consumer = NoScreenConsumer::new(channel, consumer_allowance).unwrap();
    let mut transaction = bound.catalog(attachment, catalog_allowance).unwrap();
    let recovery = transport::session_resume::RecoveryRequest {
        attachment,
        channel,
        parser: transport::session_resume::ParserContinuity::DataCursor {
            cursor: consumer.cursor(),
        },
    };
    let id = RequestId::new(62).unwrap();
    let mut producer = bound
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
    bound.finish_recovery(attachment, transaction).unwrap();
    supervisor.owners.insert(index, bound);
    BoundFixture {
        index,
        locator,
        attachment,
        channel,
        input,
        control,
        consumer,
        _restart: restart,
    }
}

#[tokio::test]
async fn supervisor529_frontend_loss_retains_the_actual_writer_and_cancelled_fence() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let first = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &first).await;
    fixture.control.hold_writes();
    supervisor.owners[fixture.index]
        .user_input(
            fixture.attachment,
            fixture.channel,
            fixture.input,
            0,
            b"abcd",
        )
        .unwrap()
        .accepted()
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !fixture.control.write_entered() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    supervisor.test_eof(&first);
    supervisor.test_wait(&first, false);
    let loss = supervisor.poll_frontend(&first, &mut h);
    let pending = {
        let fence = supervisor.finish_frontend_loss(&first, &mut h);
        tokio::pin!(fence);
        fence
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    };
    let second = frontend(&mut supervisor, &mut h);
    let retry = authenticate(&mut h, supervisor.test_registration(&second), 10);
    let blocked = matches!(
        h.begin_issue(retry, fixture.locator, 12, 112),
        Err(crate::session_owner::host::HostError::AlreadyAttached)
    );
    let killed = fixture.control.kills(16);
    fixture.control.release_writes();
    let finished = supervisor.finish_frontend_loss(&first, &mut h).await;
    let available = h.begin_issue(retry, fixture.locator, 13, 113).is_ok();
    let written = fixture.control.written();
    let position = supervisor.owners[fixture.index]
        .input_position_for_test(fixture.channel)
        .unwrap();
    drop(fixture.consumer);
    supervisor.test_wait(&second, false);
    supervisor.test_eof(&second);
    supervisor.begin_stop(&mut h).unwrap();
    let cleanup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervisor.finish_stop(&mut h, 100),
    )
    .await;
    assert_eq!(loss, Ok(SupervisionProgress::LossPending));
    assert!(pending && blocked);
    assert_eq!(killed, 0);
    assert!(finished.is_ok() && available);
    assert_eq!(written, b"ab");
    assert_eq!(
        (position.accepted, position.committed),
        (4, 2),
        "uncommitted accepted FIFO remains owned across fence"
    );
    assert!(cleanup.unwrap().is_ok());
}

#[tokio::test]
async fn supervisor529_stop_refuses_precaptured_attach_and_closes_actual_empty_owner() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let attempt = authenticate(&mut h, supervisor.test_registration(&handle), 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let bound = match h.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("actual empty binding refused"),
    };
    if let Err(failure) = supervisor.add_owner(&h, bound) {
        let (_, mut returned) = failure.into_parts();
        returned.close(&mut h, 3).await.unwrap();
        panic!("supervisor owner route missing")
    };
    let authorized = authorize(&mut h, attempt, locator, 3);
    supervisor.begin_stop(&mut h).unwrap();
    let refused = supervisor.owners[0].attach(&mut h, authorized).is_err();
    supervisor.test_wait(&handle, false);
    supervisor.test_eof(&handle);
    let stopped = supervisor.finish_stop(&mut h, 100).await;
    assert!(refused);
    assert_eq!(stopped, Ok(()));
    assert_eq!(h.catalog_len(), 0);
}
#[tokio::test]
async fn supervisor529_omitted_owner_requires_its_actual_cleanup_after_stop_latch() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let attempt = authenticate(&mut h, supervisor.test_registration(&handle), 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut omitted = match h.bind_local_engine(provisioning, engine) {
        Ok(bound) => bound,
        Err(_) => panic!("actual omitted binding refused"),
    };
    supervisor.begin_stop(&mut h).unwrap();
    supervisor.test_wait(&handle, false);
    supervisor.test_eof(&handle);
    assert_eq!(
        supervisor.finish_stop(&mut h, 3).await,
        Err(SupervisionError::CleanupPending)
    );
    omitted.close(&mut h, 4).await.unwrap();
    supervisor.finish_stop(&mut h, 5).await.unwrap();
    assert_eq!(h.catalog_len(), 0);
}

#[test]
fn supervisor529_owned_poll_resumes_bookkeeping_after_authority_was_retired() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let f = supervisor.test_registration(&handle);
    h.fail_frontend_cleanup_once_for_test(f);
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    assert_eq!(
        supervisor.poll_frontend(&handle, &mut h),
        Err(SupervisionError::Unavailable)
    );
    assert!(!h.frontend_is_current(f));
    assert!(h.frontend_retirement_pending(f));
    assert_eq!(h.frontend_obligations_for_test(), 1);
    assert_eq!(
        supervisor.poll_frontend(&handle, &mut h),
        Ok(SupervisionProgress::Settled)
    );
    assert!(!h.frontend_retirement_pending(f));
    assert_eq!(h.frontend_obligations_for_test(), 0);
}
#[tokio::test]
async fn supervisor529_stop_retries_partial_retirement_without_reopening_admission() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let f = supervisor.test_registration(&handle);
    h.fail_frontend_cleanup_once_for_test(f);
    assert_eq!(
        supervisor.begin_stop(&mut h),
        Err(SupervisionError::Unavailable)
    );
    assert!(!h.frontend_is_current(f));
    assert!(h.frontend_retirement_pending(f));
    assert!(h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .is_err());
    supervisor.begin_stop(&mut h).unwrap();
    assert!(!h.frontend_retirement_pending(f));
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    supervisor.finish_stop(&mut h, 1).await.unwrap();
    assert_eq!(h.frontend_obligations_for_test(), 0);
}
#[test]
fn supervisor529_direct_retirement_retry_preserves_unassociated_physical_debt() {
    let mut h = host();
    let f = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap();
    h.fail_frontend_cleanup_once_for_test(f);
    assert!(h.retire_frontend(f).is_err());
    assert!(!h.frontend_is_current(f));
    assert!(h.frontend_retirement_pending(f));
    h.retire_frontend(f).unwrap();
    assert!(!h.frontend_retirement_pending(f));
    assert_eq!(h.frontend_obligations_for_test(), 1);
}

#[tokio::test]
async fn supervisor529_attached_omitted_owner_keeps_loss_pending_until_actual_detach() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let attempt = authenticate(&mut h, supervisor.test_registration(&handle), 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut omitted = match h.bind_local_engine(provisioning, engine) {
        Ok(owner) => owner,
        Err(_) => panic!("omitted binding refused"),
    };
    let authorized = authorize(&mut h, attempt, locator, 3);
    omitted.attach(&mut h, authorized).unwrap();
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    let loss = supervisor.poll_frontend(&handle, &mut h);
    let premature = supervisor.finish_frontend_loss(&handle, &mut h).await;
    omitted.begin_detach(&mut h).unwrap();
    omitted.finish_detach(&mut h).await.unwrap();
    let settled = supervisor.poll_frontend(&handle, &mut h);
    let finished = supervisor.finish_frontend_loss(&handle, &mut h).await;
    omitted.close(&mut h, 100).await.unwrap();
    supervisor.begin_stop(&mut h).unwrap();
    supervisor.finish_stop(&mut h, 101).await.unwrap();
    assert_eq!(loss, Ok(SupervisionProgress::LossPending));
    assert_eq!(premature, Err(SupervisionError::CleanupPending));
    assert_eq!(settled, Ok(SupervisionProgress::Settled));
    assert_eq!(finished, Ok(()));
}
#[tokio::test]
async fn supervisor529_cancelled_administrative_close_retains_exact_operation_and_receipts() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    fixture.control.gate_exit(16, None, true);
    drop(fixture.consumer);
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    supervisor.begin_stop(&mut h).unwrap();
    let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let stop = supervisor.finish_stop(&mut h, 100);
        tokio::pin!(stop);
        loop {
            if stop
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return false;
            }
            if fixture.control.held_exit_polls(16) > 0 {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or(false);
    let operation = h.cleanup_operation_for_test(fixture.locator);
    let stop_operation = supervisor.stop.as_ref().unwrap().operation;
    let retained = h.resource_reservations_for_test() > 0;
    let kills = fixture.control.kills(16);
    fixture.control.release_exit(16);
    let resumed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervisor.finish_stop(&mut h, 101),
    )
    .await;
    assert!(pending && retained);
    assert!(operation.is_some());
    assert_eq!(kills, 1);
    assert_eq!(fixture.control.kills(16), 1);
    assert!(resumed.unwrap().is_ok());
    assert_eq!(h.cleanup_operation_for_test(fixture.locator), operation);
    assert_eq!(supervisor.stop.as_ref().unwrap().operation, stop_operation);
    assert_eq!(fixture.control.reaps(16), 1);
}
#[tokio::test]
async fn supervisor529_unknown_bound_owner_is_reported_without_closing_its_frontend() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let f = supervisor.test_registration(&handle);
    let attempt = authenticate(&mut h, f, 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut owner = match h.bind_local_engine(provisioning, engine) {
        Ok(owner) => owner,
        Err(_) => panic!("unknown owner binding refused"),
    };
    let authorized = authorize(&mut h, attempt, locator, 3);
    owner.attach(&mut h, authorized).unwrap();
    let binding = owner.supervision_binding().clone();
    if let Err(failure) = supervisor.add_owner(&h, owner) {
        let (_, mut returned) = failure.into_parts();
        returned.close(&mut h, 100).await.unwrap();
        panic!("unknown owner registration refused")
    };
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = binding.phase.lock().unwrap();
        panic!("modeled owner binding uncertainty");
    }));
    assert!(poisoned.is_err());
    assert_eq!(
        supervisor.poll_frontend(&handle, &mut h),
        Ok(SupervisionProgress::Unknown)
    );
    assert!(h.frontend_is_current(f));
    assert!(h.begin_issue(attempt, locator, 7, 107).is_err());
    assert_eq!(h.catalog_len(), 1);
    assert_eq!(h.frontend_obligations_for_test(), 1);
}
#[tokio::test]
async fn supervisor529_permanent_retirement_uncertainty_remains_charged_on_retry() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let f = supervisor.test_registration(&handle);
    let attempt = authenticate(&mut h, f, 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let owner = match h.bind_local_engine(provisioning, engine) {
        Ok(owner) => owner,
        Err(_) => panic!("uncertain binding refused"),
    };
    let binding = owner.supervision_binding().clone();
    if let Err(failure) = supervisor.add_owner(&h, owner) {
        let (_, mut returned) = failure.into_parts();
        returned.close(&mut h, 3).await.unwrap();
        panic!("uncertain registration refused")
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = binding.phase.lock().unwrap();
        panic!("modeled permanent retirement uncertainty");
    }));
    supervisor.test_eof(&handle);
    supervisor.test_wait(&handle, false);
    for _ in 0..2 {
        assert!(supervisor.begin_stop(&mut h).is_err());
        assert!(supervisor.finish_stop(&mut h, 100).await.is_err());
    }
    assert!(!h.frontend_is_current(f));
    assert!(h.frontend_retirement_pending(f));
    assert_eq!(h.frontend_obligations_for_test(), 1);
    assert_eq!(h.catalog_len(), 1);
    assert!(matches!(
        HostSupervisor::new(&mut h),
        Err(SupervisionError::Refused)
    ));
}

#[tokio::test]
async fn supervisor529_cancelled_close_resumes_before_frontend_wait_receipt_arrives() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    fixture.control.gate_exit(16, None, true);
    drop(fixture.consumer);
    supervisor.test_eof(&handle);
    supervisor.begin_stop(&mut h).unwrap();
    let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let stop = supervisor.finish_stop(&mut h, 100);
        tokio::pin!(stop);
        loop {
            if stop
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return false;
            }
            if fixture.control.held_exit_polls(16) > 0 {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or(false);
    fixture.control.release_exit(16);
    let before_wait = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervisor.finish_stop(&mut h, 101),
    )
    .await
    .unwrap();
    let owner_complete = supervisor.owners[fixture.index].supervision_complete();
    // Independent fallback cleanup keeps the real inert workers bounded in RED too.
    let fallback = supervisor.owners[fixture.index].close(&mut h, 102).await;
    supervisor.test_wait(&handle, false);
    let final_stop = supervisor.finish_stop(&mut h, 103).await;
    assert!(pending);
    assert_eq!(before_wait, Err(SupervisionError::CleanupPending));
    assert!(owner_complete);
    assert!(fallback.is_ok());
    assert_eq!(final_stop, Ok(()));
    assert_eq!(fixture.control.kills(16), 1);
    assert_eq!(fixture.control.reaps(16), 1);
}

#[tokio::test]
async fn supervisor529_stopped_open_returns_whole_pair_for_checked_unused_release() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let attempt = authenticate(&mut h, supervisor.test_registration(&handle), 0);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 2).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut bound = h.bind_local_engine(provisioning, engine).ok().unwrap();
    let authorized = authorize(&mut h, attempt, locator, 3);
    let attachment = bound.attach(&mut h, authorized).unwrap();
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
            &h,
            attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(50).unwrap(),
            128,
            InputEpoch::new([88; 16]).unwrap(),
        )
        .unwrap();
    let expected = supplied.descriptions();
    supervisor.begin_stop(&mut h).unwrap();
    let result = bound
        .open_admitted(
            &mut h,
            transport::channel::OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            supplied,
        )
        .await;
    let Err(crate::session_owner::host_engine::LocalEngineError::OpenRefused(inputs)) = result
    else {
        panic!("stopped open must return untouched custody");
    };
    let (_, returned, lease) = inputs.into_parts();
    assert!(lease.is_none());
    assert_eq!(returned.descriptions(), expected);
    assert_eq!(h.resource_reservations_for_test(), 2);
    bound.release_unstarted_admitted(returned).unwrap();
    assert_eq!(h.resource_reservations_for_test(), 0);
    assert!(
        bound.catalog_available(),
        "healthy empty owner remains unchanged"
    );
    bound.close(&mut h, 100).await.unwrap();
}

fn unused_open_fixture(
    h: &mut HostState,
    registration: FrontendAdmission,
    screen: bool,
) -> (
    LocalOwnerEngine,
    crate::session_owner::engine::AdmittedOwnerChannelResources,
    Option<crate::session_owner::screen_owner::HostScreenLease>,
    crate::session_owner::resources::OwnerResourceClient,
    tokio::sync::watch::Sender<transport::channel_server::RestartSignal>,
) {
    let attempt = authenticate(h, registration, 10);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 12).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let client = provisioning.client();
    let lease = if screen {
        let size = terminal_size::TerminalSize::new(80, 24).unwrap();
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let token = provisioning
            .reserve(
                OwnerResourceRequest {
                    locator,
                    channel,
                    kind: ReservationKind::ScreenModel,
                    bytes: 0,
                    screen_charge: Some(crate::session_owner::resource_contract::ScreenCharge {
                        cells: slots.cells as u64,
                        rows: slots.rows as u64,
                        models: 1,
                    }),
                },
                RequestId::new(49).unwrap(),
            )
            .unwrap();
        Some(
            match crate::session_owner::screen_owner::HostScreenLease::admit_reserved(
                client.clone(),
                token,
                size,
            ) {
                Ok(lease) => lease,
                Err(_) => panic!("actual model lease refused"),
            },
        )
    } else {
        None
    };
    let (engine, restart) =
        crate::session_owner::engine::tests::integrated::host_fixture(locator, client.clone());
    let mut bound = h.bind_local_engine(provisioning, engine).ok().unwrap();
    let authorized = authorize(h, attempt, locator, 13);
    let attachment = bound.attach(h, authorized).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = bound
        .provision_channel_resources(
            h,
            attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(50).unwrap(),
            128,
            InputEpoch::new([88; 16]).unwrap(),
        )
        .unwrap();
    (bound, supplied, lease, client, restart)
}
#[tokio::test]
async fn supervisor529_foreign_and_mixed_unused_pairs_return_intact_without_any_refund() {
    use crate::session_owner::engine::AdmittedOwnerChannelResources;
    use crate::session_owner::host_engine::LocalEngineError;
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let (mut bound, own, _, _, _restart) =
        unused_open_fixture(&mut h, supervisor.test_registration(&handle), false);
    let mut foreign = host();
    let registration = foreign
        .admit_frontend(AuthenticatedPeer::for_test(
            foreign.instance(),
            HostMode::System,
        ))
        .unwrap();
    let (_foreign_bound, supplied, _, _, _foreign_restart) =
        unused_open_fixture(&mut foreign, registration, false);
    let own_ids = own.descriptions();
    let foreign_ids = supplied.descriptions();
    supervisor.begin_stop(&mut h).unwrap();
    let Err(LocalEngineError::OpenRefused(inputs)) = bound
        .open_admitted(
            &mut h,
            transport::channel::OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            None,
            supplied,
        )
        .await
    else {
        panic!("foreign input custody lost")
    };
    let (_, supplied, _) = inputs.into_parts();
    assert_eq!(supplied.descriptions(), foreign_ids);
    let returned = bound.release_unstarted_admitted(supplied).unwrap_err();
    let (_, supplied, _) = returned.into_parts();
    assert_eq!(supplied.descriptions(), foreign_ids);
    assert_eq!(
        (
            h.resource_reservations_for_test(),
            foreign.resource_reservations_for_test()
        ),
        (2, 2)
    );
    let (own_history, own_control) = own.split_for_test();
    let (foreign_history, foreign_control) = supplied.split_for_test();
    let mixed = AdmittedOwnerChannelResources::new(
        own_history,
        foreign_control,
        128,
        InputEpoch::new([88; 16]).unwrap(),
    );
    let expected = mixed.descriptions();
    let returned = bound.release_unstarted_admitted(mixed).unwrap_err();
    let (_, mixed, _) = returned.into_parts();
    assert_eq!(mixed.descriptions(), expected);
    assert_eq!(
        (
            h.resource_reservations_for_test(),
            foreign.resource_reservations_for_test()
        ),
        (2, 2)
    );
    let (own_history, foreign_control) = mixed.split_for_test();
    let own = AdmittedOwnerChannelResources::new(
        own_history,
        own_control,
        128,
        InputEpoch::new([88; 16]).unwrap(),
    );
    assert_eq!(own.descriptions(), own_ids);
    bound.release_unstarted_admitted(own).unwrap();
    assert_eq!(
        (
            h.resource_reservations_for_test(),
            foreign.resource_reservations_for_test()
        ),
        (0, 2)
    );
    drop((foreign_history, foreign_control)); // Unknown foreign custody stays charged, never refunded by Drop.
    assert_eq!(foreign.resource_reservations_for_test(), 2);
}
#[tokio::test]
async fn supervisor529_stopped_screen_open_preserves_exact_lease_and_pair() {
    use crate::session_owner::host_engine::LocalEngineError;
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let (mut bound, supplied, lease, client, _restart) =
        unused_open_fixture(&mut h, supervisor.test_registration(&handle), true);
    let expected = supplied.descriptions();
    let lease = lease.unwrap();
    supervisor.begin_stop(&mut h).unwrap();
    let Err(LocalEngineError::OpenRefused(inputs)) = bound
        .open_screen_admitted(
            &mut h,
            transport::channel::OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: true,
                command: Vec::new(),
            },
            None,
            supplied,
            lease,
        )
        .await
    else {
        panic!("screen refusal lost lease")
    };
    let (_, returned, lease) = inputs.into_parts();
    assert_eq!(returned.descriptions(), expected);
    let lease = lease.expect("exact screen lease retained");
    assert!(lease.matches(
        &client,
        expected.0.locator,
        expected.0.channel,
        terminal_size::TerminalSize::new(80, 24).unwrap()
    ));
    assert_eq!(h.resource_reservations_for_test(), 3);
    bound.release_unstarted_admitted(returned).unwrap();
    assert_eq!(h.resource_reservations_for_test(), 1);
    drop(lease);
    assert_eq!(
        h.resource_reservations_for_test(),
        0,
        "sole unused Screen lease destruction settles its own backing"
    );
    assert!(
        bound.catalog_available(),
        "healthy empty owner remains unchanged"
    );
}

fn replacement_candidate() -> crate::session_owner::status_contract::FrontendIdentity {
    crate::session_owner::status_contract::FrontendIdentity {
        generation: transport::session_resume::FrontendGeneration::new([9; 16]).unwrap(),
        build: crate::session_owner::status_contract::BuildIdentity::new(
            "fixture-candidate",
            1,
            [3; 32],
        )
        .unwrap(),
    }
}
#[tokio::test]
async fn supervisor529_replacement_fenced_requires_prepared_and_actual_complete_roster() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    let guard = h
        .begin_replacement(
            supervisor.test_registration(&handle),
            replacement_candidate(),
        )
        .unwrap();
    assert!(supervisor
        .begin_replacement_fencing(&mut h, &guard)
        .is_err());
    assert_eq!(
        supervisor.owners[fixture.index].supervision_attachment(),
        Some(fixture.attachment)
    );
    h.prepare_replacement_for_test(&guard); // Explicit fixture-only staging; no production Prepared producer exists.
    supervisor
        .begin_replacement_fencing(&mut h, &guard)
        .unwrap();
    supervisor.finish_replacement_fencing(&mut h).await.unwrap();
    assert_eq!(
        h.replacement_status_for_test(),
        Some(crate::session_owner::status_contract::ReplacementStatus::Fenced)
    );
    assert!(supervisor.owners[fixture.index]
        .supervision_attachment()
        .is_none());
    assert_eq!(
        fixture.control.kills(16),
        0,
        "replacement fencing is not owner destruction"
    );
    drop(fixture.consumer);
}
#[tokio::test]
async fn supervisor529_replacement_omitted_actual_owner_refuses_before_fencing() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    let (omitted, _pair, _lease, _client, _restart) =
        unused_open_fixture(&mut h, supervisor.test_registration(&handle), false);
    let guard = h
        .begin_replacement(
            supervisor.test_registration(&handle),
            replacement_candidate(),
        )
        .unwrap();
    h.prepare_replacement_for_test(&guard);
    assert!(supervisor
        .begin_replacement_fencing(&mut h, &guard)
        .is_err());
    assert_eq!(
        supervisor.owners[fixture.index].supervision_attachment(),
        Some(fixture.attachment)
    );
    assert_eq!(
        omitted.supervision_attachment().unwrap().frontend,
        supervisor.test_registration(&handle).generation()
    );
    assert_eq!(
        h.replacement_status_for_test(),
        Some(crate::session_owner::status_contract::ReplacementStatus::Prepared)
    );
    drop(fixture.consumer);
}

#[tokio::test]
async fn supervisor529_replacement_cancelled_fence_resumes_exact_writer_without_kill() {
    use std::future::Future;
    use std::task::{Context, Waker};
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    fixture.control.hold_writes();
    supervisor.owners[fixture.index]
        .user_input(
            fixture.attachment,
            fixture.channel,
            fixture.input,
            0,
            b"abcd",
        )
        .unwrap()
        .accepted()
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !fixture.control.write_entered() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let guard = h
        .begin_replacement(
            supervisor.test_registration(&handle),
            replacement_candidate(),
        )
        .unwrap();
    h.prepare_replacement_for_test(&guard);
    supervisor
        .begin_replacement_fencing(&mut h, &guard)
        .unwrap();
    let pending = {
        let future = supervisor.finish_replacement_fencing(&mut h);
        tokio::pin!(future);
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    };
    fixture.control.release_writes();
    let result = supervisor.finish_replacement_fencing(&mut h).await;
    assert!(pending);
    assert_eq!(result, Ok(()));
    assert_eq!(fixture.control.kills(16), 0);
    assert_eq!(fixture.control.written(), b"ab");
    assert_eq!(
        h.replacement_status_for_test(),
        Some(crate::session_owner::status_contract::ReplacementStatus::Fenced)
    );
    drop(fixture.consumer);
}
#[tokio::test]
async fn supervisor529_replacement_equal_roster_aba_invalidates_captured_operation() {
    let mut h = host();
    let mut supervisor = HostSupervisor::new(&mut h).unwrap();
    let handle = frontend(&mut supervisor, &mut h);
    let fixture = program(&mut supervisor, &mut h, &handle).await;
    let guard = h
        .begin_replacement(
            supervisor.test_registration(&handle),
            replacement_candidate(),
        )
        .unwrap();
    h.prepare_replacement_for_test(&guard);
    supervisor
        .begin_replacement_fencing(&mut h, &guard)
        .unwrap();
    let before = h.catalog_len();
    let attempt = authenticate(&mut h, supervisor.test_registration(&handle), 10);
    let (locator, provisioning) = h.create_session_provisioned(attempt, 12).unwrap();
    let (engine, _restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut temporary = h.bind_local_engine(provisioning, engine).ok().unwrap();
    temporary.close(&mut h, 20).await.unwrap();
    assert_eq!(h.catalog_len(), before);
    assert!(supervisor.finish_replacement_fencing(&mut h).await.is_err());
    assert_eq!(
        h.replacement_status_for_test(),
        Some(crate::session_owner::status_contract::ReplacementStatus::Prepared)
    );
    assert_eq!(fixture.control.kills(16), 0);
    drop(fixture.consumer);
}
