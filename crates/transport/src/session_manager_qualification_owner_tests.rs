use super::*;
use std::future::Future;

#[tokio::test]
async fn qualification305_weak_owner_requires_actual_processed_live_and_retires() {
    let _serial = crate::qualification305::TEST_SCOPE.lock().unwrap();
    let (mut io, inbound, _outbound) = SessionIo::test_pair();
    let control = io.control().clone();
    let before = Arc::strong_count(&control);
    let owner = io.qualification_owner();
    assert_eq!(
        Arc::strong_count(&control),
        before,
        "owner cannot retain control/lifecycle custody"
    );
    let instance = crate::channel_geometry::ChannelInstance::new(5).unwrap();
    assert!(matches!(
        owner.register(71, 19, instance),
        Err(QualificationOwnerError::NotProcessed)
    ));
    let actual = AttachmentContext {
        session_id: 71,
        generation: 9,
        features: crate::Features::SUPPORTED,
    };
    inbound.try_send(SessionInbound::Live(actual)).unwrap();
    {
        let mut read = Box::pin(io.recv());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(read.as_mut().poll(&mut cx), std::task::Poll::Ready(Some(SessionInbound::Live(context))) if context == actual)
        );
    }
    assert!(matches!(
        owner.register(72, 19, instance),
        Err(QualificationOwnerError::SessionMismatch)
    ));
    let (scope, reports) = owner.register(71, 19, instance).unwrap();
    let mut probe = crate::qualification305::Probe::new(io.login());
    probe.observe(actual, |target| {
        assert_eq!(
            target.attachment, actual,
            "generation comes from processed Live, not zero"
        );
        Some(crate::qualification305::Snapshot {
            valid: true,
            credit_remaining: Some(0),
            pending_data: 1,
            offset_room: 64,
            ..Default::default()
        })
    });
    assert!(reports.latest().unwrap().credit_blocked);
    drop(scope);
    drop(probe);
    drop(io);
    assert!(matches!(
        owner.register(71, 19, instance),
        Err(QualificationOwnerError::Retired)
    ));
    drop(control);
    assert!(matches!(
        owner.register(71, 19, instance),
        Err(QualificationOwnerError::Missing)
    ));
}

#[test]
fn qualification305_weak_owner_preinitialized_admission_is_not_processed_live() {
    let _serial = crate::qualification305::TEST_SCOPE.lock().unwrap();
    let (io, _, _) = SessionIo::test_pair();
    let actual = AttachmentContext {
        session_id: 73,
        generation: 8,
        features: crate::Features::SUPPORTED,
    };
    // The real bridge does this before backend.run or SessionIo.recv.
    io.set_control_origin(actual);
    let owner = io.qualification_owner();
    assert!(matches!(
        owner.register(
            73,
            20,
            crate::channel_geometry::ChannelInstance::new(1).unwrap()
        ),
        Err(QualificationOwnerError::NotProcessed)
    ));
}

#[test]
fn qualification305_weak_owner_rechecks_retirement_after_registration() {
    let _serial = crate::qualification305::TEST_SCOPE.lock().unwrap();
    let (io, _, _) = SessionIo::test_pair();
    let context = AttachmentContext {
        session_id: 75,
        generation: 11,
        features: crate::Features::SUPPORTED,
    };
    let control = io.control().clone();
    {
        let mut state = control.origin.lock().unwrap();
        state.attachment = context;
        state.qualification_processed = Some(context);
    }
    let owner = io.qualification_owner();
    let result = owner.register_checked(
        75,
        20,
        crate::channel_geometry::ChannelInstance::new(1).unwrap(),
        || control.retire(),
    );
    assert!(
        matches!(result, Err(QualificationOwnerError::Retired)),
        "logical retirement does not have to retire the budget yet"
    );
}

#[test]
fn qualification305_weak_owner_rechecks_changed_unprocessed_attachment() {
    let _serial = crate::qualification305::TEST_SCOPE.lock().unwrap();
    let (io, _, _) = SessionIo::test_pair();
    let context = AttachmentContext {
        session_id: 77,
        generation: 13,
        features: crate::Features::SUPPORTED,
    };
    {
        let mut state = io.control().origin.lock().unwrap();
        state.attachment = context;
        state.qualification_processed = Some(context);
    }
    let owner = io.qualification_owner();
    let next = AttachmentContext {
        session_id: 78,
        generation: 14,
        ..context
    };
    let result = owner.register_checked(
        77,
        20,
        crate::channel_geometry::ChannelInstance::new(1).unwrap(),
        || io.set_control_origin(next),
    );
    assert!(matches!(
        result,
        Err(QualificationOwnerError::AttachmentChanged)
    ));
    assert!(
        matches!(
            owner.register(
                78,
                20,
                crate::channel_geometry::ChannelInstance::new(1).unwrap()
            ),
            Err(QualificationOwnerError::NotProcessed)
        ),
        "admitted replacement is not a processed ResumeReset"
    );
}
