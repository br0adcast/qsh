use super::*;
use crate::session_owner::authorization::{
    AuthenticatedPeer, AuthenticationAttempt, FrontendAdmission, HostMode, PolicyResult,
};
use crate::session_owner::host::{HostDecision, HostLimits, HostState};
use crate::session_owner::host_engine::LocalOwnerEngine;
use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use transport::session_resume::{Attachment, SessionLocator};

fn host(mode: HostMode) -> HostState {
    let bytes = ByteLimits {
        channel_bytes: 32 << 20,
        session_bytes: 64 << 20,
        account_bytes: 128 << 20,
        global_bytes: 256 << 20,
    };
    HostState::new(
        mode,
        HostLimits::new(
            ResourceLimits {
                max_reservations: 128,
                screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                    .unwrap(),
                snapshot_transfer: bytes,
                control_queue: bytes,
            },
            8,
            8,
            8,
            8,
            100,
        )
        .unwrap(),
    )
    .unwrap()
}
fn authenticate(
    host: &mut HostState,
    mode: HostMode,
    uid: u32,
    name: &str,
    now: u64,
) -> (FrontendAdmission, AuthenticationAttempt) {
    let frontend = host
        .admit_frontend(AuthenticatedPeer::for_test(host.instance(), mode))
        .unwrap();
    let intent = host.begin_authentication(frontend, now, now + 100).unwrap();
    let HostDecision::Authenticated(attempt) = host
        .apply_policy_result(PolicyResult::allow_for_test(intent, uid, name), now + 1)
        .unwrap()
    else {
        panic!("authentication refused")
    };
    (frontend, attempt)
}
fn authorize(
    host: &mut HostState,
    attempt: AuthenticationAttempt,
    locator: SessionLocator,
    now: u64,
) -> crate::session_owner::host::AuthorizedAttachment {
    let intent = host.begin_issue(attempt, locator, now, now + 100).unwrap();
    let HostDecision::GrantIssued(grant) = host
        .apply_policy_result(
            PolicyResult::allow_for_test(intent, 1000, "fixture-account"),
            now + 1,
        )
        .unwrap()
    else {
        panic!("issue refused")
    };
    let intent = host
        .begin_consume(attempt, grant.grant(), grant.binding(), now + 2, now + 102)
        .unwrap();
    let HostDecision::GrantConsumed(authorized) = host
        .apply_policy_result(
            PolicyResult::allow_for_test(intent, 1000, "fixture-account"),
            now + 3,
        )
        .unwrap()
    else {
        panic!("consume refused")
    };
    authorized
}
pub(crate) fn attached(
    mode: HostMode,
) -> (
    HostState,
    LocalOwnerEngine,
    FrontendAdmission,
    AuthenticationAttempt,
    Attachment,
    tokio::sync::watch::Sender<transport::channel_server::RestartSignal>,
) {
    let mut host = host(mode);
    let (frontend, attempt) = authenticate(&mut host, mode, 1000, "fixture-account", 0);
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, restart) = crate::session_owner::engine::tests::integrated::host_fixture(
        locator,
        provisioning.client(),
    );
    let mut owner = host
        .bind_local_engine(provisioning, engine)
        .unwrap_or_else(|_| panic!("binding refused"));
    let authorized = authorize(&mut host, attempt, locator, 3);
    let attachment = owner.attach(&mut host, authorized).unwrap();
    (host, owner, frontend, attempt, attachment, restart)
}
const PERSONAL: HostMode = HostMode::Personal {
    canonical_uid: 1000,
};

#[test]
fn linux529_route_refuses_foreign_host_attempt_frontend_owner_and_mode_without_mutation() {
    let (mut host, owner, frontend, attempt, attachment, _restart) = attached(PERSONAL);
    assert!(LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).is_ok());
    let (
        foreign,
        foreign_owner,
        foreign_frontend,
        foreign_attempt,
        foreign_attachment,
        _foreign_restart,
    ) = attached(PERSONAL);
    let before = host.catalog_len();
    assert!(
        LinuxOwnerRoute::bind_personal(&foreign, &owner, frontend, attempt, attachment).is_err()
    );
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &foreign_owner, frontend, attempt, attachment)
            .is_err()
    );
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &owner, foreign_frontend, attempt, attachment)
            .is_err()
    );
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, foreign_attempt, attachment)
            .is_err()
    );
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, foreign_attachment)
            .is_err()
    );
    let (other_frontend, other_attempt) =
        authenticate(&mut host, PERSONAL, 1000, "fixture-account", 7);
    assert!(LinuxOwnerRoute::bind_personal(
        &host,
        &owner,
        other_frontend,
        other_attempt,
        attachment
    )
    .is_err());
    let intent = host.begin_authentication(frontend, 9, 109).unwrap();
    let HostDecision::Authenticated(wrong_account) = host
        .apply_policy_result(
            PolicyResult::allow_for_test(intent, 1000, "different-account"),
            10,
        )
        .unwrap()
    else {
        panic!("account fixture refused")
    };
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, wrong_account, attachment).is_err()
    );
    host.cancel_attempt(attempt).unwrap();
    assert!(LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).is_err());
    assert_eq!(host.catalog_len(), before);
    assert_eq!(host.resource_reservations_for_test(), 0);
    let (system, owner, frontend, attempt, attachment, _restart) = attached(HostMode::System);
    assert!(
        LinuxOwnerRoute::bind_personal(&system, &owner, frontend, attempt, attachment).is_err()
    );
}

#[test]
fn linux529_route_rejects_equal_visible_but_foreign_binding() {
    let (host, owner, frontend, attempt, attachment, _restart) = attached(PERSONAL);
    let actual = owner.supervision_binding();
    let forged = std::sync::Arc::new(crate::session_owner::host_engine::LocalBinding {
        identity: actual.identity,
        phase: std::sync::Mutex::new(
            crate::session_owner::host_engine::LocalLeasePhase::Attached(attachment),
        ),
    });
    assert!(host
        .authorize_linux_route(&forged, frontend, attempt, attachment)
        .is_err());
    assert!(LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).is_ok());
}

#[tokio::test]
async fn linux529_detach_finishes_after_auth_retirement_without_completion_and_cannot_close_successor(
) {
    let (mut host, mut owner, frontend, attempt, first, _restart) = attached(PERSONAL);
    let mut route =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, first).unwrap();
    let mut competing =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, first).unwrap();
    route.begin_detach(&mut host, &mut owner).unwrap();
    route.begin_detach(&mut host, &mut owner).unwrap();
    assert!(route.begin_terminate(&mut host, &mut owner).is_err());
    assert!(competing.begin_terminate(&mut host, &mut owner).is_err());
    host.retire_frontend(frontend).unwrap();
    route.finish_detach(&mut host, &mut owner).await.unwrap();
    route.finish_detach(&mut host, &mut owner).await.unwrap();
    assert_eq!(host.catalog_len(), 1);
    assert!(!owner.supervision_complete());
    let (fresh_frontend, fresh_attempt) =
        authenticate(&mut host, PERSONAL, 1000, "fixture-account", 7);
    let authorized = authorize(&mut host, fresh_attempt, first.locator, 9);
    let second = owner.attach(&mut host, authorized).unwrap();
    assert!(route.begin_terminate(&mut host, &mut owner).is_err());
    assert!(competing.begin_terminate(&mut host, &mut owner).is_err());
    assert!(owner
        .close_from_frontend(&mut host, first, 14)
        .await
        .is_err());
    assert!(
        LinuxOwnerRoute::bind_personal(&host, &owner, fresh_frontend, fresh_attempt, second)
            .is_ok()
    );
    assert_eq!(host.catalog_len(), 1);
}

#[tokio::test]
async fn linux529_termination_latches_shared_exclusion_and_survives_requester_retirement() {
    let (mut host, mut owner, frontend, attempt, attachment, _restart) = attached(PERSONAL);
    let mut terminate =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).unwrap();
    let mut competing =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).unwrap();
    terminate.begin_terminate(&mut host, &mut owner).unwrap();
    assert!(competing.begin_detach(&mut host, &mut owner).is_err());
    assert!(competing.begin_terminate(&mut host, &mut owner).is_err());
    assert!(terminate.begin_detach(&mut host, &mut owner).is_err());
    host.retire_frontend(frontend).unwrap();
    terminate
        .finish_terminate(&mut host, &mut owner, 7)
        .await
        .unwrap();
    terminate
        .finish_terminate(&mut host, &mut owner, 8)
        .await
        .unwrap();
    assert!(owner.supervision_complete());
    assert_eq!(host.catalog_len(), 0);
    assert!(terminate.begin_terminate(&mut host, &mut owner).is_err());
}

async fn controlled() -> (
    HostState,
    LocalOwnerEngine,
    FrontendAdmission,
    AuthenticationAttempt,
    Attachment,
    tokio::sync::watch::Sender<transport::channel_server::RestartSignal>,
    crate::session_owner::engine::tests::integrated::HostFixtureControl,
) {
    use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
    use crate::session_owner::resource_contract::ReservationKind;
    use transport::channel::{ChannelKind, OpenRequest};
    use transport::channel_geometry::ChannelInstance;
    use transport::session_resume::{InputEpoch, RequestId};
    let mut host = host(PERSONAL);
    let (frontend, attempt) = authenticate(&mut host, PERSONAL, 1000, "fixture-account", 0);
    let (locator, provisioning) = host.create_session_provisioned(attempt, 2).unwrap();
    let (engine, restart, control) =
        crate::session_owner::engine::tests::integrated::host_fixture_controlled(
            locator,
            provisioning.client(),
        );
    let mut owner = host
        .bind_local_engine(provisioning, engine)
        .unwrap_or_else(|_| panic!("binding refused"));
    let authorized = authorize(&mut host, attempt, locator, 3);
    let attachment = owner.attach(&mut host, authorized).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let request = |kind, bytes| OwnerResourceRequest {
        locator,
        channel,
        kind,
        bytes,
        screen_charge: None,
    };
    let supplied = owner
        .provision_channel_resources(
            &host,
            attachment,
            (
                request(ReservationKind::OutputHistory, 4096),
                request(ReservationKind::ControlQueue, 131072),
            ),
            RequestId::new(50).unwrap(),
            128,
            InputEpoch::new([99; 16]).unwrap(),
        )
        .unwrap();
    owner
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
        .unwrap();
    (host, owner, frontend, attempt, attachment, restart, control)
}

#[tokio::test]
async fn linux529_actual_partial_write_fence_survives_cancellation_and_stale_route_cannot_mutate_successor(
) {
    use std::future::Future;
    use std::task::{Context, Waker};
    use transport::channel_geometry::{ChannelInstance, ResizeRequestId};
    use transport::session_resume::InputEpoch;
    let (mut host, mut owner, frontend, attempt, first, _restart, control) = controlled().await;
    let channel = ChannelInstance::new(1).unwrap();
    let epoch = InputEpoch::new([99; 16]).unwrap();
    let mut route =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, first).unwrap();
    let exercised = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let consumer = crate::session_owner::host_engine::tests::recover_bound_data(
            &owner, first, channel, 60,
        )
        .await
        .unwrap();
        control.hold_writes();
        owner
            .user_input(first, channel, epoch, 0, b"abcd")
            .unwrap()
            .accepted()
            .await
            .unwrap();
        while !control.write_entered() {
            tokio::task::yield_now().await;
        }
        route.begin_detach(&mut host, &mut owner).unwrap();
        let pending = {
            let finish = route.finish_detach(&mut host, &mut owner);
            tokio::pin!(finish);
            finish
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        };
        control.release_writes();
        route.finish_detach(&mut host, &mut owner).await.unwrap();
        assert!(pending);
        assert_eq!(control.written(), b"ab");
        assert!(!owner.supervision_complete());
        assert!(host.resource_reservations_for_test() > 0);
        assert!(owner.user_input(first, channel, epoch, 4, b"x").is_err());
        assert!(owner
            .resize(first, channel, ResizeRequestId::new(1).unwrap(), 90, 30)
            .is_err());
        let authorized = authorize(&mut host, attempt, first.locator, 8);
        let second = owner.attach(&mut host, authorized).unwrap();
        let fresh_consumer = crate::session_owner::host_engine::tests::recover_bound_data(
            &owner, second, channel, 80,
        )
        .await
        .unwrap();
        assert!(route.begin_terminate(&mut host, &mut owner).is_err());
        assert!(owner
            .close_from_frontend(&mut host, first, 12)
            .await
            .is_err());
        owner
            .user_input(second, channel, epoch, 4, b"ef")
            .unwrap()
            .accepted()
            .await
            .unwrap();
        owner.begin_detach(&mut host).unwrap();
        owner.finish_detach(&mut host).await.unwrap();
        drop((consumer, fresh_consumer));
    })
    .await;
    control.release_writes();
    owner.close(&mut host, 13).await.unwrap();
    assert!(exercised.is_ok());
    assert_eq!(host.resource_reservations_for_test(), 0);
}

#[tokio::test]
async fn linux529_cancelled_termination_retains_exact_real_cleanup_and_foreign_destinations_untouched(
) {
    use std::future::Future;
    use std::task::{Context, Waker};
    let (mut host, mut owner, frontend, attempt, attachment, _restart, control) =
        controlled().await;
    control.gate_exit(16, Some(3), true);
    let mut route =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).unwrap();
    route.begin_terminate(&mut host, &mut owner).unwrap();
    let (mut foreign_host, mut foreign_owner, _, _, _, _foreign_restart) = attached(PERSONAL);
    assert!(route
        .finish_terminate(&mut foreign_host, &mut foreign_owner, 7)
        .await
        .is_err());
    assert!(!foreign_owner.supervision_complete());
    let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let result = {
                let close = route.finish_terminate(&mut host, &mut owner, 7);
                tokio::pin!(close);
                close.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            };
            assert!(result.is_pending());
            if control.held_exit_polls(16) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let operation = host.cleanup_operation_for_test(attachment.locator);
    let charged = host.resource_reservations_for_test();
    host.retire_frontend(frontend).unwrap();
    control.release_exit(16);
    let completed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        route.finish_terminate(&mut host, &mut owner, 8),
    )
    .await;
    assert!(pending.is_ok());
    assert!(operation.is_some());
    assert!(charged > 0);
    completed.unwrap().unwrap();
    assert_eq!(control.reaps(16), 1);
    assert_eq!(host.resource_reservations_for_test(), 0);
    assert_eq!(
        host.cleanup_operation_for_test(attachment.locator),
        operation
    );
}

#[tokio::test]
async fn linux529_route_drop_preserves_supervisor_custody_and_omitted_owner_blocks_stop() {
    use crate::session_owner::supervisor::{HostSupervisor, SupervisionError};
    let (mut host, mut owner, frontend, attempt, attachment, _restart) = attached(PERSONAL);
    let mut route =
        LinuxOwnerRoute::bind_personal(&host, &owner, frontend, attempt, attachment).unwrap();
    route.begin_terminate(&mut host, &mut owner).unwrap();
    drop(route);
    assert_eq!(host.catalog_len(), 1);
    assert!(!owner.supervision_complete());
    let mut supervisor = HostSupervisor::new(&mut host).unwrap();
    assert!(HostSupervisor::new(&mut host).is_err());
    supervisor.begin_stop(&mut host).unwrap();
    assert!(matches!(
        supervisor.finish_stop(&mut host, 7).await,
        Err(SupervisionError::CleanupPending)
    ));
    assert_eq!(
        host.catalog_len(),
        1,
        "an omitted owner must remain actual debt"
    );
    supervisor
        .add_owner(&host, owner)
        .unwrap_or_else(|_| panic!("actual retained owner refused"));
    // The existing supervisor can resume the admitted close after route Drop.
    // This fixture has no physical frontend Capsule: its separate debt must
    // still refuse complete host-stop even after the owner really settles.
    assert!(matches!(
        supervisor.finish_stop(&mut host, 8).await,
        Err(SupervisionError::CleanupPending)
    ));
    assert_eq!(host.catalog_len(), 0);
    assert_eq!(host.frontend_obligations_for_test(), 1);
}

#[cfg(feature = "system")]
pub(crate) fn destination_binding(
    owner: &LocalOwnerEngine,
) -> std::sync::Arc<crate::session_owner::host_engine::LocalBinding> {
    owner.supervision_binding().clone()
}
