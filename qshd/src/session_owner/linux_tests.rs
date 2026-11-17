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
fn attached(
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
