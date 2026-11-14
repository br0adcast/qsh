//! Synthetic nonsecret bytes for untrusted contract DTOs. No fixture grants
//! access to a real account, service, owner, key, resource or authenticated seam.
use super::host_auth_contract::*;
use super::host_protocol::{self as hp, HostFrame, HostHeader, HostMessage, HostPeerState};
use super::local_admission_contract::*;
use super::operations::OwnerOperation;
use super::owner_resource_contract::*;
use super::protocol::{
    self as op, OwnerFrame, OwnerHeader, OwnerMessage, OwnerProtocolError as Error, OwnerRole,
    PeerState,
};
use super::resource_contract::{ReservationId, ReservationKind};
use transport::channel_geometry::ChannelInstance;
use transport::session_resume::*;
fn host() -> HostInstance {
    HostInstance::new([1; 16]).unwrap()
}
fn owner() -> OwnerInstance {
    OwnerInstance::new([2; 16]).unwrap()
}
fn reference(b: u8) -> AuthReference {
    AuthReference::new([b; 16]).unwrap()
}
fn frontend() -> FrontendGeneration {
    FrontendGeneration::new([3; 16]).unwrap()
}
fn locator() -> SessionLocator {
    SessionLocator {
        session: RetainedSessionId::new([4; 16]).unwrap(),
        owner: owner(),
    }
}
fn spec(owner_specific: bool) -> AdmissionSpec {
    AdmissionSpec {
        host: host(),
        owner: owner_specific.then(owner),
        requester: if owner_specific {
            OwnerRole::Owner
        } else {
            OwnerRole::Frontend
        },
        channel: [5; 16],
        challenge: [6; 32],
        min_version: 1,
        max_version: 1,
    }
}
fn hf(id: u64, message: HostMessage) -> HostFrame {
    HostFrame {
        header: HostHeader {
            role: if matches!(
                &message,
                HostMessage::Admission(LocalAdmission::Offer { .. })
            ) {
                OwnerRole::Frontend
            } else if let HostMessage::Authentication(a) = &message {
                a.role()
            } else {
                OwnerRole::Host
            },
            host: host(),
            request_id: id,
        },
        message,
    }
}
fn offer() -> LocalAdmission {
    LocalAdmission::Offer {
        channel: [5; 16],
        challenge: [6; 32],
        min_version: 1,
        max_version: 1,
    }
}
fn ack() -> LocalAdmission {
    LocalAdmission::Ack {
        channel: [5; 16],
        challenge: [6; 32],
        selected_version: 1,
    }
}
fn admitted(mode: AuthMethod) -> HostPeerState {
    let mut p = HostPeerState::with_admission(
        OwnerRole::Frontend,
        OwnerRole::Host,
        host(),
        spec(false),
        frontend(),
        mode,
        64,
    )
    .unwrap();
    p.send(&hf(1, HostMessage::Admission(offer()))).unwrap();
    p.receive(&hf(1, HostMessage::Admission(ack()))).unwrap();
    p
}
fn record() -> transport::AuthRecord {
    transport::AuthRecord {
        public_key: vec![1, 2, 3],
        signature: vec![4, 5],
        v2: Some(transport::AuthV2 {
            login: "fixture".into(),
            nonce: [7; 16],
        }),
    }
}
fn challenge(ticket: AuthReference) -> HostAuthMessage {
    HostAuthMessage::Challenge {
        method: AuthMethod::System,
        ticket,
        deadline: 100,
        nonce: Some([7; 16]),
    }
}
#[test]
fn ipc529_legacy_golden_bytes_and_separate_registries_are_preserved() {
    let old = OwnerFrame {
        header: OwnerHeader {
            role: OwnerRole::Owner,
            host: host(),
            owner: owner(),
            request_id: 1,
        },
        message: OwnerMessage::Hello {
            min_version: 1,
            max_version: 1,
        },
    };
    let mut expected = b"QSHO\0\x01\x03\x01\0\0\0\x04".to_vec();
    expected.extend_from_slice(host().as_bytes());
    expected.extend_from_slice(owner().as_bytes());
    expected.extend_from_slice(&1u64.to_be_bytes());
    expected.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(op::encode(&old).unwrap(), expected);
    let mut attach = b"QSHO\0\x01\x02\x30\0\0\0\x40".to_vec();
    attach.extend_from_slice(host().as_bytes());
    attach.extend_from_slice(owner().as_bytes());
    attach.extend_from_slice(&1u64.to_be_bytes());
    attach.extend_from_slice(&1u64.to_be_bytes());
    attach.extend_from_slice(locator().session.as_bytes());
    attach.extend_from_slice(owner().as_bytes());
    attach.extend_from_slice(frontend().as_bytes());
    attach.extend_from_slice(&0u64.to_be_bytes());
    assert!(matches!(
        op::OwnerDecoder::new().push(&attach).unwrap()[0].message,
        OwnerMessage::Control(ResumeControl::Attach { .. })
    ));
    assert_eq!(
        HostAuthMessage::Begin {
            method: AuthMethod::System
        }
        .kind(),
        0x30
    );
    assert_eq!(reserve().kind(), 0x50);
}
#[test]
fn ipc529_admission_gate_wrong_challenge_and_reply_are_inert() {
    let mut p = HostPeerState::with_admission(
        OwnerRole::Frontend,
        OwnerRole::Host,
        host(),
        spec(false),
        frontend(),
        AuthMethod::System,
        64,
    )
    .unwrap();
    assert!(p
        .send_at(
            &hf(
                1,
                HostMessage::Authentication(HostAuthMessage::Begin {
                    method: AuthMethod::System
                })
            ),
            0
        )
        .is_err());
    p.send(&hf(1, HostMessage::Admission(offer()))).unwrap();
    let before = p.clone();
    let bad = LocalAdmission::Ack {
        channel: [5; 16],
        challenge: [9; 32],
        selected_version: 1,
    };
    assert!(p.receive(&hf(1, HostMessage::Admission(bad))).is_err());
    assert_eq!(p, before);
    p.receive(&hf(1, HostMessage::Admission(ack()))).unwrap();
    assert!(p.send(&hf(2, HostMessage::Admission(offer()))).is_err());
}
#[test]
fn ipc529_new_frames_are_strict_bounded_incremental_and_cross_magic_refuses() {
    let f = hf(1, HostMessage::Admission(offer()));
    let bytes = hp::encode(&f).unwrap();
    assert_eq!(bytes.len(), 88);
    let mut d = hp::HostDecoder::new();
    for b in bytes.chunks(1) {
        let _ = d.push(b).unwrap();
    }
    d.finish().unwrap();
    for cut in 1..bytes.len() {
        let mut d = hp::HostDecoder::new();
        d.push(&bytes[..cut]).unwrap();
        assert_eq!(d.finish(), Err(Error::Truncated));
    }
    let mut wrong = bytes.clone();
    wrong[3] = b'O';
    assert!(hp::HostDecoder::new().push(&wrong).is_err());
    let mut huge = bytes[..36].to_vec();
    huge[7] = 0x32;
    huge[8..12].copy_from_slice(&8193u32.to_be_bytes());
    let mut d = hp::HostDecoder::new();
    assert_eq!(d.push(&huge), Err(Error::TooLarge));
    assert!(d.buffer_capacity() <= 36);
    let mut wrong_role = bytes;
    wrong_role[6] = OwnerRole::Host.to_wire();
    assert!(hp::HostDecoder::new().push(&wrong_role).is_err());
}
#[test]
fn ipc529_system_proof_uses_actual_canonical_v2_codec_and_rejects_malformed_or_helper_overflow() {
    let f = hf(
        2,
        HostMessage::Authentication(HostAuthMessage::SystemProof {
            ticket: reference(8),
            handshake_hash: [9; 32],
            record: record(),
        }),
    );
    let bytes = hp::encode(&f).unwrap();
    let canonical = transport::encode_auth_record(&record()).unwrap();
    assert_eq!(&bytes[86..], canonical);
    assert_eq!(hp::HostDecoder::new().push(&bytes).unwrap(), vec![f]);
    for corrupt in [0, 1, 2] {
        let mut bad = bytes.clone();
        match corrupt {
            0 => bad[86] = 1,
            1 => bad[84..86].copy_from_slice(&65535u16.to_be_bytes()),
            _ => {
                bad.push(0);
                let n = (bad.len() - 36) as u32;
                bad[8..12].copy_from_slice(&n.to_be_bytes());
            }
        }
        assert!(hp::HostDecoder::new().push(&bad).is_err());
    }
    let mut r = record();
    r.public_key = vec![255; 2000];
    r.signature = vec![255; 1000];
    let bad = hf(
        2,
        HostMessage::Authentication(HostAuthMessage::SystemProof {
            ticket: reference(8),
            handshake_hash: [255; 32],
            record: r,
        }),
    );
    assert_eq!(hp::encode(&bad), Err(Error::TooLarge));
}
#[test]
fn ipc529_auth_ticket_nonce_request_cancellation_and_late_result_are_bound() {
    let mut p = admitted(AuthMethod::System);
    p.send_at(
        &hf(
            2,
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }),
        ),
        0,
    )
    .unwrap();
    p.receive_at(
        &hf(2, HostMessage::Authentication(challenge(reference(8)))),
        0,
    )
    .unwrap();
    let mut wrong = record();
    wrong.v2.as_mut().unwrap().nonce = [10; 16];
    let before = p.clone();
    assert!(p
        .send_at(
            &hf(
                3,
                HostMessage::Authentication(HostAuthMessage::SystemProof {
                    ticket: reference(8),
                    handshake_hash: [9; 32],
                    record: wrong
                })
            ),
            1
        )
        .is_err());
    assert_eq!(p, before);
    p.send_at(
        &hf(
            3,
            HostMessage::Authentication(HostAuthMessage::SystemProof {
                ticket: reference(8),
                handshake_hash: [9; 32],
                record: record(),
            }),
        ),
        1,
    )
    .unwrap();
    p.send_at(
        &hf(
            4,
            HostMessage::Authentication(HostAuthMessage::Cancel {
                ticket: reference(8),
            }),
        ),
        2,
    )
    .unwrap();
    let late = hf(
        3,
        HostMessage::Authentication(HostAuthMessage::Result {
            ticket: reference(8),
            outcome: AuthOutcome::Accepted(reference(11)),
        }),
    );
    let before = p.clone();
    assert!(p.receive_at(&late, 2).is_err());
    assert_eq!(p, before);
    p.receive_at(
        &hf(
            4,
            HostMessage::Authentication(HostAuthMessage::Cancelled {
                ticket: reference(8),
            }),
        ),
        3,
    )
    .unwrap();
    assert_eq!(p.outstanding(), 0);
    assert!(p.receive_at(&late, 3).is_err());
}
#[test]
fn ipc529_system_mode_cannot_accept_personal_report_and_expired_proof_is_inert() {
    let mut p = admitted(AuthMethod::System);
    p.send_at(
        &hf(
            2,
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }),
        ),
        0,
    )
    .unwrap();
    p.receive_at(
        &hf(2, HostMessage::Authentication(challenge(reference(8)))),
        0,
    )
    .unwrap();
    let before = p.clone();
    let report = hf(
        3,
        HostMessage::Authentication(HostAuthMessage::PersonalReport {
            ticket: reference(8),
            key: [1; 32],
            session_id: 0,
            token: [0; 16],
        }),
    );
    assert!(p.send_at(&report, 1).is_err());
    assert_eq!(p, before);
    let proof = hf(
        3,
        HostMessage::Authentication(HostAuthMessage::SystemProof {
            ticket: reference(8),
            handshake_hash: [9; 32],
            record: record(),
        }),
    );
    assert!(p.send_at(&proof, 100).is_err());
    assert_eq!(p, before);
}
fn request() -> OwnerResourceRequest {
    OwnerResourceRequest {
        locator: locator(),
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::OutputHistory,
        bytes: 32,
        screen_charge: None,
    }
}
fn reserve() -> OwnerResourceMessage {
    OwnerResourceMessage::Reserve(request())
}
fn of(id: u64, m: OwnerResourceMessage) -> OwnerFrame {
    OwnerFrame {
        header: OwnerHeader {
            role: m.role(),
            host: host(),
            owner: owner(),
            request_id: id,
        },
        message: OwnerMessage::Operation(OwnerOperation::Resource(m)),
    }
}
#[test]
fn ipc529_owner_resource_new_direction_echo_and_shapes_do_not_reinterpret_frontend_reserve() {
    let f = of(3, reserve());
    let bytes = op::encode(&f).unwrap();
    assert_eq!(bytes.len(), 102);
    assert_eq!(bytes[7], 0x50);
    assert_eq!(
        op::OwnerDecoder::new().push(&bytes).unwrap(),
        vec![f.clone()]
    );
    let mut wrong = f.clone();
    wrong.header.role = OwnerRole::Frontend;
    assert!(op::encode(&wrong).is_err());
    wrong = f;
    wrong.header.owner = OwnerInstance::new([9; 16]).unwrap();
    assert!(op::encode(&wrong).is_err());
    let mut bad = request();
    bad.bytes = 0;
    assert!(op::encode(&of(3, OwnerResourceMessage::Reserve(bad))).is_err());
    assert_eq!(
        hp::encode(&HostFrame {
            header: HostHeader {
                role: OwnerRole::Host,
                host: host(),
                request_id: 1
            },
            message: HostMessage::Reserve {
                reservation: super::resource_contract::Reservation {
                    id: ReservationId::new(1).unwrap(),
                    principal: super::authorization_contract::AuthenticatedPrincipalRef::new(
                        [1; 16]
                    )
                    .unwrap(),
                    locator: locator(),
                    channel: ChannelInstance::new(1).unwrap(),
                    kind: ReservationKind::OutputHistory,
                    bytes: 32,
                    screen_charge: None
                },
                cleanup: RequestId::new(2).unwrap()
            }
        }),
        Err(Error::Binding)
    );
}
#[test]
fn ipc529_sixty_fifth_control_and_replayed_ids_refuse_without_mutation() {
    let mut p = admitted(AuthMethod::System);
    for id in 2..=65 {
        let f = HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: host(),
                request_id: id,
            },
            message: HostMessage::StatusRequest {
                frontend: frontend(),
                cursor: None,
            },
        };
        p.send(&f).unwrap();
    }
    let before = p.clone();
    let f = HostFrame {
        header: HostHeader {
            role: OwnerRole::Frontend,
            host: host(),
            request_id: 66,
        },
        message: HostMessage::StatusRequest {
            frontend: frontend(),
            cursor: None,
        },
    };
    assert_eq!(p.send(&f), Err(Error::RequestLimit));
    assert_eq!(p, before);
    let mut reused = f;
    reused.header.request_id = 2;
    assert_eq!(p.send(&reused), Err(Error::ReusedRequest));
    assert_eq!(p, before);
}

fn owner_admitted() -> PeerState {
    let mut p = PeerState::with_admission(
        OwnerRole::Owner,
        OwnerRole::Host,
        host(),
        owner(),
        spec(true),
    )
    .unwrap();
    let frame = |id, role, message| OwnerFrame {
        header: OwnerHeader {
            role,
            host: host(),
            owner: owner(),
            request_id: id,
        },
        message,
    };
    assert!(p
        .send(&frame(
            1,
            OwnerRole::Owner,
            OwnerMessage::Hello {
                min_version: 1,
                max_version: 1
            }
        ))
        .is_err());
    p.send(&frame(
        1,
        OwnerRole::Owner,
        OwnerMessage::Admission(offer()),
    ))
    .unwrap();
    p.receive(&frame(1, OwnerRole::Host, OwnerMessage::Admission(ack())))
        .unwrap();
    assert!(p.send(&of(2, reserve())).is_err());
    p.send(&frame(
        2,
        OwnerRole::Owner,
        OwnerMessage::Hello {
            min_version: 1,
            max_version: 1,
        },
    ))
    .unwrap();
    p.receive(&frame(
        2,
        OwnerRole::Host,
        OwnerMessage::HelloAck {
            selected_version: 1,
        },
    ))
    .unwrap();
    p
}
#[test]
fn ipc529_owner_admission_then_legacy_hello_and_exact_resource_echo_are_required() {
    let mut p = owner_admitted();
    p.send(&of(3, reserve())).unwrap();
    let before = p.clone();
    let mut wrong = request();
    wrong.bytes = 33;
    assert!(p
        .receive(&of(
            3,
            OwnerResourceMessage::Reserved {
                request: wrong,
                reservation: ReservationId::new(1).unwrap(),
                cleanup: RequestId::new(2).unwrap()
            }
        ))
        .is_err());
    assert_eq!(p, before);
    p.receive(&of(
        3,
        OwnerResourceMessage::Reserved {
            request: request(),
            reservation: ReservationId::new(1).unwrap(),
            cleanup: RequestId::new(2).unwrap(),
        },
    ))
    .unwrap();
    assert_eq!(p.outstanding(), 0);
    let release = OwnerReleaseReport {
        locator: locator(),
        channel: ChannelInstance::new(1).unwrap(),
        reservation: ReservationId::new(1).unwrap(),
        cleanup: RequestId::new(2).unwrap(),
    };
    p.send(&of(4, OwnerResourceMessage::Release(release)))
        .unwrap();
    let mut wrong = release;
    wrong.cleanup = RequestId::new(3).unwrap();
    let before = p.clone();
    assert!(p
        .receive(&of(4, OwnerResourceMessage::Reported(wrong)))
        .is_err());
    assert_eq!(p, before);
    p.receive(&of(4, OwnerResourceMessage::Reported(release)))
        .unwrap();
}
#[test]
fn ipc529_all_new_body_layouts_roundtrip_and_reject_trailing_or_wrong_role() {
    use super::authorization_contract::{AttachGrant, AuthenticatedPrincipalRef, GrantBinding};
    let binding = GrantBinding {
        principal: AuthenticatedPrincipalRef::new([1; 16]).unwrap(),
        locator: locator(),
        frontend: frontend(),
        owner: owner(),
        expires_at_monotonic: 100,
    };
    let records = vec![
        HostAuthMessage::Begin {
            method: AuthMethod::Personal,
        },
        HostAuthMessage::Challenge {
            method: AuthMethod::Personal,
            ticket: reference(8),
            deadline: 100,
            nonce: None,
        },
        challenge(reference(8)),
        HostAuthMessage::ChallengeRefused {
            method: AuthMethod::System,
            reason: AuthRefusal::Unavailable,
        },
        HostAuthMessage::SystemProof {
            ticket: reference(8),
            handshake_hash: [9; 32],
            record: record(),
        },
        HostAuthMessage::PersonalReport {
            ticket: reference(8),
            key: [0; 32],
            session_id: 0,
            token: [0; 16],
        },
        HostAuthMessage::Result {
            ticket: reference(8),
            outcome: AuthOutcome::Accepted(reference(9)),
        },
        HostAuthMessage::Result {
            ticket: reference(8),
            outcome: AuthOutcome::Refused(AuthRefusal::Unauthorized),
        },
        HostAuthMessage::Cancel {
            ticket: reference(8),
        },
        HostAuthMessage::Cancelled {
            ticket: reference(8),
        },
        HostAuthMessage::AuthorizeAttach {
            context: reference(9),
            locator: locator(),
        },
        HostAuthMessage::AttachResult {
            context: reference(9),
            locator: locator(),
            outcome: AttachOutcome::Granted {
                grant: AttachGrant::new([1; 32]).unwrap(),
                binding,
            },
        },
        HostAuthMessage::AttachResult {
            context: reference(9),
            locator: locator(),
            outcome: AttachOutcome::Refused(transport::session_resume::AttachRefusal::Unauthorized),
        },
    ];
    for m in records {
        let f = hf(1, HostMessage::Authentication(m));
        let bytes = hp::encode(&f).unwrap();
        assert_eq!(
            hp::HostDecoder::new().push(&bytes).unwrap(),
            vec![f.clone()]
        );
        let mut wrong = f;
        wrong.header.role = if wrong.header.role == OwnerRole::Host {
            OwnerRole::Frontend
        } else {
            OwnerRole::Host
        };
        assert!(hp::encode(&wrong).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        let len = (trailing.len() - 36) as u32;
        trailing[8..12].copy_from_slice(&len.to_be_bytes());
        assert!(hp::HostDecoder::new().push(&trailing).is_err());
    }
    let mut screen = request();
    screen.kind = ReservationKind::ScreenModel;
    screen.bytes = 0;
    screen.screen_charge = Some(super::resource_contract::ScreenCharge {
        cells: 100,
        rows: 10,
        models: 1,
    });
    let release = OwnerReleaseReport {
        locator: locator(),
        channel: ChannelInstance::new(1).unwrap(),
        reservation: ReservationId::new(1).unwrap(),
        cleanup: RequestId::new(2).unwrap(),
    };
    for m in [
        OwnerResourceMessage::Reserve(screen),
        OwnerResourceMessage::Reserved {
            request: screen,
            reservation: release.reservation,
            cleanup: release.cleanup,
        },
        OwnerResourceMessage::Refused {
            request: screen,
            reason: hp::ReservationRefusal::ResourceLimit,
        },
        OwnerResourceMessage::Release(release),
        OwnerResourceMessage::Reported(release),
    ] {
        let f = of(1, m);
        let bytes = op::encode(&f).unwrap();
        assert_eq!(op::OwnerDecoder::new().push(&bytes).unwrap(), vec![f]);
        for cut in [1, 51, bytes.len() - 1] {
            let mut d = op::OwnerDecoder::new();
            d.push(&bytes[..cut]).unwrap();
            assert_eq!(d.finish(), Err(Error::Truncated));
        }
    }
}
#[test]
fn ipc529_personal_context_attach_correlation_cancel_and_live_id_alias_refuse() {
    let mut p = admitted(AuthMethod::Personal);
    p.send_at(
        &hf(
            2,
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::Personal,
            }),
        ),
        0,
    )
    .unwrap();
    p.receive_at(
        &hf(
            2,
            HostMessage::Authentication(HostAuthMessage::Challenge {
                method: AuthMethod::Personal,
                ticket: reference(8),
                deadline: 100,
                nonce: None,
            }),
        ),
        0,
    )
    .unwrap();
    p.send_at(
        &hf(
            3,
            HostMessage::Authentication(HostAuthMessage::PersonalReport {
                ticket: reference(8),
                key: [1; 32],
                session_id: 0,
                token: [0; 16],
            }),
        ),
        1,
    )
    .unwrap();
    p.receive_at(
        &hf(
            3,
            HostMessage::Authentication(HostAuthMessage::Result {
                ticket: reference(8),
                outcome: AuthOutcome::Accepted(reference(9)),
            }),
        ),
        1,
    )
    .unwrap();
    p.send_at(
        &hf(
            4,
            HostMessage::Authentication(HostAuthMessage::AuthorizeAttach {
                context: reference(9),
                locator: locator(),
            }),
        ),
        2,
    )
    .unwrap();
    let before = p.clone();
    let wrong = hf(
        4,
        HostMessage::Authentication(HostAuthMessage::AttachResult {
            context: reference(10),
            locator: locator(),
            outcome: AttachOutcome::Refused(transport::session_resume::AttachRefusal::Unauthorized),
        }),
    );
    assert!(p.receive_at(&wrong, 2).is_err());
    assert_eq!(p, before);
    use super::authorization_contract::{AttachGrant, AuthenticatedPrincipalRef, GrantBinding};
    let binding = GrantBinding {
        principal: AuthenticatedPrincipalRef::new([1; 16]).unwrap(),
        locator: locator(),
        frontend: frontend(),
        owner: owner(),
        expires_at_monotonic: 100,
    };
    let mut foreign = binding;
    foreign.frontend = FrontendGeneration::new([20; 16]).unwrap();
    let result = |b| {
        hf(
            4,
            HostMessage::Authentication(HostAuthMessage::AttachResult {
                context: reference(9),
                locator: locator(),
                outcome: AttachOutcome::Granted {
                    grant: AttachGrant::new([1; 32]).unwrap(),
                    binding: b,
                },
            }),
        )
    };
    assert!(p.receive_at(&result(foreign), 2).is_err());
    assert_eq!(p, before);
    p.receive_at(&result(binding), 2).unwrap();
    p.send_at(
        &hf(
            5,
            HostMessage::Authentication(HostAuthMessage::AuthorizeAttach {
                context: reference(9),
                locator: locator(),
            }),
        ),
        3,
    )
    .unwrap();
    p.send_at(
        &hf(
            6,
            HostMessage::Authentication(HostAuthMessage::Cancel {
                ticket: reference(8),
            }),
        ),
        3,
    )
    .unwrap();
    p.receive_at(
        &hf(
            6,
            HostMessage::Authentication(HostAuthMessage::Cancelled {
                ticket: reference(8),
            }),
        ),
        3,
    )
    .unwrap();
    assert_eq!(p.outstanding(), 0);
    assert!(p
        .send_at(
            &hf(
                7,
                HostMessage::Authentication(HostAuthMessage::AuthorizeAttach {
                    context: reference(9),
                    locator: locator()
                })
            ),
            4
        )
        .is_err());
}
#[test]
fn ipc529_registration_bound_is_reused_by_proof_and_freed_only_by_terminal_stage() {
    let mut p = HostPeerState::with_admission(
        OwnerRole::Frontend,
        OwnerRole::Host,
        host(),
        spec(false),
        frontend(),
        AuthMethod::System,
        1,
    )
    .unwrap();
    p.send(&hf(1, HostMessage::Admission(offer()))).unwrap();
    p.receive(&hf(1, HostMessage::Admission(ack()))).unwrap();
    p.send_at(
        &hf(
            2,
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }),
        ),
        0,
    )
    .unwrap();
    p.receive_at(
        &hf(2, HostMessage::Authentication(challenge(reference(8)))),
        0,
    )
    .unwrap();
    let before = p.clone();
    assert_eq!(
        p.send_at(
            &hf(
                3,
                HostMessage::Authentication(HostAuthMessage::Begin {
                    method: AuthMethod::System
                })
            ),
            1
        ),
        Err(Error::RequestLimit)
    );
    assert_eq!(p, before);
    p.send_at(
        &hf(
            3,
            HostMessage::Authentication(HostAuthMessage::SystemProof {
                ticket: reference(8),
                handshake_hash: [1; 32],
                record: record(),
            }),
        ),
        1,
    )
    .unwrap();
    p.receive_at(
        &hf(
            3,
            HostMessage::Authentication(HostAuthMessage::Result {
                ticket: reference(8),
                outcome: AuthOutcome::Refused(AuthRefusal::Unauthorized),
            }),
        ),
        2,
    )
    .unwrap();
    p.send_at(
        &hf(
            4,
            HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::System,
            }),
        ),
        3,
    )
    .unwrap();
    let before = p.clone();
    assert!(p
        .send_at(
            &hf(
                5,
                HostMessage::Authentication(HostAuthMessage::PersonalReport {
                    ticket: reference(8),
                    key: [1; 32],
                    session_id: 1,
                    token: [0; 16]
                })
            ),
            3
        )
        .is_err());
    assert_eq!(p, before);
}
#[test]
fn ipc529_unknown_decoder_is_terminal_and_release_ack_never_refunds_ledger_debt() {
    use super::authorization_contract::*;
    use super::resource_contract::*;
    let b = ByteLimits {
        channel_bytes: 100,
        session_bytes: 200,
        account_bytes: 400,
        global_bytes: 800,
    };
    let limits = ResourceLimits {
        max_reservations: 4,
        screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
        snapshot_transfer: b,
        control_queue: b,
    };
    let mut ledger = ResourceLedger::new(LedgerInstance::new([1; 16]).unwrap(), limits).unwrap();
    let principal = AuthenticatedPrincipalRef::new([2; 16]).unwrap();
    let handle = ledger.register_fresh_principal(principal, 1000).unwrap();
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal,
        locator: locator(),
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::SnapshotTransfer,
        bytes: 32,
        screen_charge: None,
    };
    let cleanup = RequestId::new(2).unwrap();
    ledger.reserve(handle, r, cleanup).unwrap();
    let report = OwnerReleaseReport {
        locator: r.locator,
        channel: r.channel,
        reservation: r.id,
        cleanup,
    };
    let bytes = op::encode(&of(1, OwnerResourceMessage::Reported(report))).unwrap();
    assert!(op::OwnerDecoder::new().push(&bytes).is_ok());
    assert_eq!(ledger.reservations(), 1);
    assert!(ledger.retire_principal(handle).is_err());
    let mut unknown = bytes;
    unknown[7] = 0x55;
    let mut d = op::OwnerDecoder::new();
    assert_eq!(d.push(&unknown), Err(Error::UnknownKind(0x55)));
    let valid = op::encode(&of(2, reserve())).unwrap();
    assert_eq!(d.push(&valid), Err(Error::UnknownKind(0x55)));
    assert_eq!(ledger.reservations(), 1);
}

#[test]
fn ipc529_live_reference_alias_and_cross_request_replies_preserve_pending_slots() {
    let mut p = admitted(AuthMethod::System);
    for (begin, proof, ticket, context) in [
        (2, 3, reference(8), reference(9)),
        (4, 5, reference(10), reference(11)),
    ] {
        p.send_at(
            &hf(
                begin,
                HostMessage::Authentication(HostAuthMessage::Begin {
                    method: AuthMethod::System,
                }),
            ),
            0,
        )
        .unwrap();
        if begin == 4 {
            let before = p.clone();
            assert!(p
                .receive_at(
                    &hf(begin, HostMessage::Authentication(challenge(reference(9)))),
                    0
                )
                .is_err());
            assert_eq!(p, before);
        }
        p.receive_at(
            &hf(begin, HostMessage::Authentication(challenge(ticket))),
            0,
        )
        .unwrap();
        p.send_at(
            &hf(
                proof,
                HostMessage::Authentication(HostAuthMessage::SystemProof {
                    ticket,
                    handshake_hash: [1; 32],
                    record: record(),
                }),
            ),
            1,
        )
        .unwrap();
        if begin == 4 {
            let before = p.clone();
            assert!(p
                .receive_at(
                    &hf(
                        proof,
                        HostMessage::Authentication(HostAuthMessage::Result {
                            ticket,
                            outcome: AuthOutcome::Accepted(reference(9))
                        })
                    ),
                    1
                )
                .is_err());
            assert_eq!(p, before);
        }
        p.receive_at(
            &hf(
                proof,
                HostMessage::Authentication(HostAuthMessage::Result {
                    ticket,
                    outcome: AuthOutcome::Accepted(context),
                }),
            ),
            1,
        )
        .unwrap();
    }
    assert_eq!(p.outstanding(), 0);
}
#[test]
fn ipc529_both_owner_channel_ends_stage_admission_hello_and_separate_direction_ids() {
    let mut requester = PeerState::with_admission(
        OwnerRole::Owner,
        OwnerRole::Host,
        host(),
        owner(),
        spec(true),
    )
    .unwrap();
    let mut responder = PeerState::with_admission(
        OwnerRole::Host,
        OwnerRole::Owner,
        host(),
        owner(),
        spec(true),
    )
    .unwrap();
    for (role, id, message) in [
        (OwnerRole::Owner, 1, OwnerMessage::Admission(offer())),
        (OwnerRole::Host, 1, OwnerMessage::Admission(ack())),
        (
            OwnerRole::Owner,
            2,
            OwnerMessage::Hello {
                min_version: 1,
                max_version: 1,
            },
        ),
        (
            OwnerRole::Host,
            2,
            OwnerMessage::HelloAck {
                selected_version: 1,
            },
        ),
    ] {
        let f = OwnerFrame {
            header: OwnerHeader {
                role,
                host: host(),
                owner: owner(),
                request_id: id,
            },
            message,
        };
        let bytes = op::encode(&f).unwrap();
        let decoded = op::OwnerDecoder::new().push(&bytes).unwrap().pop().unwrap();
        if role == OwnerRole::Owner {
            requester.send(&f).unwrap();
            responder.receive(&decoded).unwrap();
        } else {
            responder.send(&f).unwrap();
            requester.receive(&decoded).unwrap();
        }
    }
    let req = of(3, reserve());
    requester.send(&req).unwrap();
    responder.receive(&req).unwrap();
    assert_eq!(requester.outstanding(), 1);
    assert_eq!(responder.incoming(), 1);
    let reply = of(
        3,
        OwnerResourceMessage::Refused {
            request: request(),
            reason: hp::ReservationRefusal::ResourceLimit,
        },
    );
    responder.send(&reply).unwrap();
    requester.receive(&reply).unwrap();
    assert_eq!(requester.outstanding(), 0);
    assert_eq!(responder.incoming(), 0);
}
