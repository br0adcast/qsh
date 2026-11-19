//! Synthetic, nonsecret identity/grant bytes for pure contract tests only.
//! No fixture authenticates to an account, daemon, SSH service or real owner.
use super::authorization_contract::*;
use transport::session_resume::*;
fn binding() -> GrantBinding {
    GrantBinding {
        principal: AuthenticatedPrincipalRef::new([1; 16]).unwrap(),
        locator: SessionLocator {
            session: RetainedSessionId::new([2; 16]).unwrap(),
            owner: OwnerInstance::new([3; 16]).unwrap(),
        },
        frontend: FrontendGeneration::new([4; 16]).unwrap(),
        owner: OwnerInstance::new([3; 16]).unwrap(),
        expires_at_monotonic: 10,
    }
}
#[test]
fn grants_are_bounded_registered_single_use_and_redacted() {
    let b = binding();
    let grant = AttachGrant::new([0xa5; 32]).unwrap();
    assert!(!format!("{grant:?}").contains("165"));
    let mut ledger = GrantLedger::new(LedgerInstance::new([201; 16]).unwrap(), 1).unwrap();
    let authority = foreign_grant_authority(b);
    assert!(ledger
        .consume(authority, grant, b, 1, AttachEpoch::new(1).unwrap())
        .is_err());
    assert!(ledger.insert(authority, grant, b, 0).is_err());
    let authority = grant_authority(&mut ledger, b);
    ledger.insert(authority, grant, b, 0).unwrap();
    assert!(ledger
        .insert(authority, AttachGrant::new([0xa6; 32]).unwrap(), b, 0)
        .is_err());
    let mut wrong = b;
    wrong.frontend = FrontendGeneration::new([9; 16]).unwrap();
    assert!(ledger
        .consume(authority, grant, wrong, 1, AttachEpoch::new(1).unwrap())
        .is_err());
    assert!(ledger
        .consume(authority, grant, b, 1, AttachEpoch::new(1).unwrap())
        .is_ok());
    assert!(ledger
        .consume(authority, grant, b, 1, AttachEpoch::new(2).unwrap())
        .is_err());
    ledger.insert(authority, grant, b, 1).unwrap_err();
    let mut ledger = GrantLedger::new(LedgerInstance::new([201; 16]).unwrap(), 1).unwrap();
    let authority = grant_authority(&mut ledger, b);
    let fresh = AttachGrant::new([0xa7; 32]).unwrap();
    ledger.insert(authority, fresh, b, 1).unwrap();
    ledger.revoke_frontend(authority.frontend).unwrap();
    assert!(ledger
        .consume(authority, fresh, b, 2, AttachEpoch::new(2).unwrap())
        .is_err());
}
#[test]
fn host_envelope_is_separate_bounded_and_incremental() {
    use super::host_protocol::*;
    use super::protocol::OwnerRole;
    let frame = HostFrame {
        header: HostHeader {
            role: OwnerRole::Frontend,
            host: HostInstance::new([8; 16]).unwrap(),
            request_id: 1,
        },
        message: HostMessage::AuthorizeAttach {
            principal: binding().principal,
            locator: binding().locator,
            frontend: binding().frontend,
        },
    };
    let bytes = encode(&frame).unwrap();
    assert_eq!(&bytes[..8], b"QSHH\0\x01\x02\x10");
    assert_eq!(bytes.len(), 100);
    let mut d = HostDecoder::new();
    assert!(d.push(&bytes[..36]).unwrap().is_empty());
    assert_eq!(d.push(&bytes[36..]).unwrap(), vec![frame]);
    d.finish().unwrap();
    let mut wrong = bytes.clone();
    wrong[3] = b'O';
    assert!(HostDecoder::new().push(&wrong[..36]).is_err());
    let mut too_large = bytes;
    too_large[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut d = HostDecoder::new();
    assert!(d.push(&too_large[..36]).is_err());
    assert!(d.buffer_capacity() <= HOST_HEADER_LEN);
}
#[test]
fn owner_open_and_grant_contracts_bind_header_identity() {
    use super::operations::*;
    use super::protocol::*;
    use transport::channel::{ChannelKind, OpenRequest};
    let header = OwnerHeader {
        role: OwnerRole::Frontend,
        host: HostInstance::new([8; 16]).unwrap(),
        owner: binding().owner,
        request_id: 1,
    };
    let attach = Attachment {
        locator: binding().locator,
        frontend: binding().frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    let open = OwnerOpen {
        attachment: attach,
        request: OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: true,
            command: vec![],
        },
    };
    let frame = OwnerFrame {
        header,
        message: OwnerMessage::Operation(OwnerOperation::Open(open.clone())),
    };
    let bytes = encode(&frame).unwrap();
    assert_eq!(bytes[7], 0x10);
    assert_eq!(OwnerDecoder::new().push(&bytes).unwrap(), vec![frame]);
    let mut bad = open;
    bad.request.cols = 513;
    assert!(encode(&OwnerFrame {
        header,
        message: OwnerMessage::Operation(OwnerOperation::Open(bad))
    })
    .is_err());
}
#[test]
fn status_pages_and_replacement_facts_cannot_mix_generations() {
    use super::status_contract::*;
    let build = BuildIdentity::new("0.6.0-rc1", 7, [5; 32]).unwrap();
    assert!(BuildIdentity::new(&"v".repeat(129), 7, [5; 32]).is_err());
    let front = FrontendIdentity {
        generation: binding().frontend,
        build: build.clone(),
    };
    let mut tx = ReplacementTransaction::new(ReplacementId::new([1; 16]).unwrap(), front.clone());
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::Activated,
            serving: Some(tx.candidate().clone())
        })
        .is_err());
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::Prepared,
        serving: None,
    })
    .unwrap();
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::Fenced,
        serving: None,
    })
    .unwrap();
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::Recovered,
            serving: Some(tx.candidate().clone())
        })
        .is_err());
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::Retired,
        serving: None,
    })
    .unwrap();
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::Recovered,
        serving: Some(tx.candidate().clone()),
    })
    .unwrap();
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::Activated,
            serving: Some(tx.candidate().clone())
        })
        .is_err());
    let epoch = StatusEpoch::new([6; 16]).unwrap();
    let page = StatusPage {
        host: HostInstance::new([8; 16]).unwrap(),
        host_build: build,
        frontend: front,
        epoch,
        cursor: 0,
        total: 0,
        owners: vec![],
        next: None,
    };
    let mut collector = StatusCollector::new(1).unwrap();
    assert!(collector.accept(page.clone()).unwrap());
    let mut wrong = page;
    wrong.frontend.generation = FrontendGeneration::new([9; 16]).unwrap();
    assert!(collector.accept(wrong).is_err());
    assert!(IpcRange::new(2, 3)
        .unwrap()
        .select(IpcRange::new(1, 1).unwrap())
        .is_err());
}
#[test]
fn reservations_charge_channels_accounts_and_cleanup_exactly() {
    use super::resource_contract::*;
    use transport::channel_geometry::ChannelInstance;
    let limits = ResourceLimits {
        max_reservations: 8,
        screen: ScreenLimits {
            global_cells: 100,
            account_cells: 100,
            global_rows: 100,
            account_rows: 100,
            global_models: 2,
            account_models: 2,
        },
        snapshot_transfer: ByteLimits {
            channel_bytes: 2 << 20,
            session_bytes: 4 << 20,
            account_bytes: 8 << 20,
            global_bytes: 16 << 20,
        },
        control_queue: ByteLimits {
            channel_bytes: 64,
            session_bytes: 128,
            account_bytes: 256,
            global_bytes: 512,
        },
    };
    let mut ledger = ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), limits).unwrap();
    let mut handles = std::collections::HashMap::new();
    let b = binding();
    handles.insert(
        b.principal,
        ledger.register_fresh_principal(b.principal, 1000).unwrap(),
    );
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: b.principal,
        locator: b.locator,
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::OutputHistory,
        bytes: 1 << 20,
        screen_charge: None,
    };
    let cleanup = RequestId::new(9).unwrap();
    reserve_registered(&mut ledger, &handles, r, cleanup).unwrap();
    let mut over = r;
    over.id = ReservationId::new(2).unwrap();
    over.bytes = 1;
    assert!(reserve_registered(&mut ledger, &handles, over, cleanup).is_err());
    let mut control = over;
    control.kind = ReservationKind::ControlQueue;
    reserve_registered(&mut ledger, &handles, control, cleanup).unwrap();
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: r.id,
        locator: r.locator,
        channel: r.channel,
    };
    let mut wrong = receipt;
    wrong.id = RequestId::new(8).unwrap();
    assert!(ledger.release(r, wrong).is_err());
    assert_eq!(ledger.reservations(), 2);
    ledger.release(r, receipt).unwrap();
    assert!(ledger.release(r, receipt).is_err());
    assert_eq!(ledger.reservations(), 1);
    let mut snapshot = r;
    snapshot.id = ReservationId::new(3).unwrap();
    snapshot.kind = ReservationKind::SnapshotTransfer;
    snapshot.bytes = (1 << 20) + 1;
    reserve_registered(&mut ledger, &handles, snapshot, cleanup).unwrap();
}
#[test]
fn revoked_frontend_cannot_receive_new_grants_and_expiry_is_exact() {
    let b = binding();
    let mut ledger = GrantLedger::new(LedgerInstance::new([201; 16]).unwrap(), 2).unwrap();
    let authority = grant_authority(&mut ledger, b);
    let g = AttachGrant::new([1; 32]).unwrap();
    ledger.insert(authority, g, b, 1).unwrap();
    assert!(ledger
        .consume(authority, g, b, 10, AttachEpoch::new(1).unwrap())
        .is_err());
    ledger.revoke_frontend(authority.frontend).unwrap();
    assert!(ledger
        .insert(authority, AttachGrant::new([2; 32]).unwrap(), b, 2)
        .is_err());
}
#[test]
fn host_status_and_reservation_codecs_preserve_boundaries() {
    use super::host_protocol::*;
    use super::protocol::OwnerRole;
    use super::resource_contract::*;
    use super::status_contract::*;
    use transport::channel_geometry::ChannelInstance;
    let h = HostHeader {
        role: OwnerRole::Frontend,
        host: HostInstance::new([8; 16]).unwrap(),
        request_id: 1,
    };
    let r = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: binding().principal,
        locator: binding().locator,
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::OutputHistory,
        bytes: 1,
        screen_charge: None,
    };
    let reserve = HostFrame {
        header: h,
        message: HostMessage::Reserve {
            reservation: r,
            cleanup: RequestId::new(9).unwrap(),
        },
    };
    let bytes = encode(&reserve).unwrap();
    assert_eq!(bytes[7], 0x22);
    assert_eq!(
        HostDecoder::new().push(&bytes).unwrap(),
        vec![reserve.clone()]
    );
    let mut peer = HostPeerState::new(OwnerRole::Frontend, OwnerRole::Host, h.host);
    peer.send(&reserve).unwrap();
    let mut wrong = r;
    wrong.bytes = 2;
    let mut reply = HostFrame {
        header: HostHeader {
            role: OwnerRole::Host,
            ..h
        },
        message: HostMessage::Reserved {
            reservation: wrong,
            cleanup: RequestId::new(9).unwrap(),
        },
    };
    assert!(peer.receive(&reply).is_err());
    assert_eq!(peer.outstanding(), 1);
    reply.message = HostMessage::Reserved {
        reservation: r,
        cleanup: RequestId::new(9).unwrap(),
    };
    peer.receive(&reply).unwrap();
    assert_eq!(peer.outstanding(), 0);
    let request = HostFrame {
        header: HostHeader { request_id: 2, ..h },
        message: HostMessage::StatusRequest {
            frontend: binding().frontend,
            cursor: Some(StatusCursor {
                epoch: StatusEpoch::new([9; 16]).unwrap(),
                index: 64,
            }),
        },
    };
    let bytes = encode(&request).unwrap();
    assert_eq!(HostDecoder::new().push(&bytes).unwrap(), vec![request]);
}
fn resource_limits() -> super::resource_contract::ResourceLimits {
    use super::resource_contract::*;
    ResourceLimits {
        max_reservations: 256,
        screen: ScreenLimits {
            global_cells: 1000,
            account_cells: 100,
            global_rows: 1000,
            account_rows: 100,
            global_models: 64,
            account_models: 16,
        },
        snapshot_transfer: ByteLimits {
            channel_bytes: 100,
            session_bytes: 100,
            account_bytes: 100,
            global_bytes: 100,
        },
        control_queue: ByteLimits {
            channel_bytes: 100,
            session_bytes: 100,
            account_bytes: 100,
            global_bytes: 100,
        },
    }
}
fn reservation(
    id: u64,
    session: u8,
    channel: u64,
    principal: AuthenticatedPrincipalRef,
    kind: super::resource_contract::ReservationKind,
    bytes: u64,
) -> super::resource_contract::Reservation {
    use super::resource_contract::*;
    use transport::channel_geometry::ChannelInstance;
    Reservation {
        id: ReservationId::new(id).unwrap(),
        principal,
        locator: SessionLocator {
            session: RetainedSessionId::new([session; 16]).unwrap(),
            owner: OwnerInstance::new([session; 16]).unwrap(),
        },
        channel: ChannelInstance::new(channel).unwrap(),
        kind,
        bytes,
        screen_charge: None,
    }
}
#[test]
fn output_history_caps_include_aliases_and_all_host_accounts() {
    use super::resource_contract::*;
    let p = binding().principal;
    let alias = AuthenticatedPrincipalRef::new([9; 16]).unwrap();
    let mut ledger =
        ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), resource_limits()).unwrap();
    let mut handles = std::collections::HashMap::new();
    handles.insert(p, ledger.register_fresh_principal(p, 10).unwrap());
    handles.insert(alias, ledger.register_fresh_principal(alias, 10).unwrap());
    let cleanup = RequestId::new(1).unwrap();
    let mut id = 1;
    for account in 0..4 {
        let principal = if account == 0 {
            p
        } else {
            let principal = AuthenticatedPrincipalRef::new([20 + account; 16]).unwrap();
            handles.insert(
                principal,
                ledger
                    .register_fresh_principal(principal, 10 + account as u32)
                    .unwrap(),
            );
            principal
        };
        for session in 0..4 {
            for channel in 1..=8 {
                reserve_registered(
                    &mut ledger,
                    &handles,
                    reservation(
                        id,
                        1 + account * 4 + session,
                        channel,
                        principal,
                        ReservationKind::OutputHistory,
                        1 << 20,
                    ),
                    cleanup,
                )
                .unwrap();
                id += 1;
            }
            if account == 0 && session == 0 {
                assert!(reserve_registered(
                    &mut ledger,
                    &handles,
                    reservation(id, 1, 9, p, ReservationKind::OutputHistory, 1),
                    cleanup
                )
                .is_err());
            }
        }
        if account == 0 {
            assert!(reserve_registered(
                &mut ledger,
                &handles,
                reservation(id, 90, 1, alias, ReservationKind::OutputHistory, 1),
                cleanup
            )
            .is_err());
        }
    }
    let fifth = AuthenticatedPrincipalRef::new([50; 16]).unwrap();
    handles.insert(fifth, ledger.register_fresh_principal(fifth, 50).unwrap());
    assert!(reserve_registered(
        &mut ledger,
        &handles,
        reservation(id, 91, 1, fifth, ReservationKind::OutputHistory, 1),
        cleanup
    )
    .is_err());
    assert_eq!(ledger.reservations(), 128);
}
#[test]
fn snapshot_and_control_enforce_each_scope_without_mutation() {
    use super::resource_contract::*;
    for kind in [
        ReservationKind::SnapshotTransfer,
        ReservationKind::ControlQueue,
    ] {
        for scope in 0..4 {
            let mut limits = resource_limits();
            let mut caps = ByteLimits {
                channel_bytes: 100,
                session_bytes: 100,
                account_bytes: 100,
                global_bytes: 100,
            };
            match scope {
                0 => caps.channel_bytes = 2,
                1 => caps.session_bytes = 2,
                2 => caps.account_bytes = 2,
                _ => caps.global_bytes = 2,
            };
            if kind == ReservationKind::SnapshotTransfer {
                limits.snapshot_transfer = caps;
            } else {
                limits.control_queue = caps;
            }
            let p = binding().principal;
            let alias = AuthenticatedPrincipalRef::new([9; 16]).unwrap();
            let mut ledger =
                ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), limits).unwrap();
            let mut handles = std::collections::HashMap::new();
            handles.insert(p, ledger.register_fresh_principal(p, 10).unwrap());
            handles.insert(
                alias,
                ledger
                    .register_fresh_principal(alias, if scope == 3 { 11 } else { 10 })
                    .unwrap(),
            );
            let cleanup = RequestId::new(1).unwrap();
            reserve_registered(
                &mut ledger,
                &handles,
                reservation(1, 1, 1, p, kind, 2),
                cleanup,
            )
            .unwrap();
            let next = reservation(
                2,
                if scope >= 2 { 2 } else { 1 },
                if scope == 0 { 1 } else { 2 },
                if scope >= 2 { alias } else { p },
                kind,
                1,
            );
            assert!(
                reserve_registered(&mut ledger, &handles, next, cleanup).is_err(),
                "{kind:?} scope {scope}"
            );
            assert_eq!(ledger.reservations(), 1);
        }
    }
}
#[test]
fn screen_dimensions_models_scratch_and_arithmetic_are_independent() {
    use super::resource_contract::*;
    let p = binding().principal;
    let cleanup = RequestId::new(1).unwrap();
    for field in 0..6 {
        let mut limits = resource_limits();
        match field {
            0 => limits.screen.global_cells = 2,
            1 => limits.screen.account_cells = 2,
            2 => limits.screen.global_rows = 2,
            3 => limits.screen.account_rows = 2,
            4 => limits.screen.global_models = 1,
            _ => limits.screen.account_models = 1,
        };
        let mut ledger =
            ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), limits).unwrap();
        let mut handles = std::collections::HashMap::new();
        handles.insert(p, ledger.register_fresh_principal(p, 10).unwrap());
        let mut r = reservation(1, 1, 1, p, ReservationKind::ScreenModel, 0);
        r.screen_charge = Some(ScreenCharge {
            cells: 2,
            rows: 2,
            models: 1,
        });
        reserve_registered(&mut ledger, &handles, r, cleanup).unwrap();
        let mut over = r;
        over.id = ReservationId::new(2).unwrap();
        over.channel = transport::channel_geometry::ChannelInstance::new(2).unwrap();
        over.screen_charge = Some(ScreenCharge {
            cells: 1,
            rows: 1,
            models: 1,
        });
        assert!(
            reserve_registered(&mut ledger, &handles, over, cleanup).is_err(),
            "dimension {field}"
        );
        assert_eq!(ledger.reservations(), 1);
    }
    let mut ledger =
        ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), resource_limits()).unwrap();
    let mut handles = std::collections::HashMap::new();
    handles.insert(p, ledger.register_fresh_principal(p, 10).unwrap());
    let mut r = reservation(1, 1, 1, p, ReservationKind::ScreenModel, 0);
    r.screen_charge = Some(ScreenCharge {
        cells: 1,
        rows: 1,
        models: 1,
    });
    reserve_registered(&mut ledger, &handles, r, cleanup).unwrap();
    r.id = ReservationId::new(2).unwrap();
    r.screen_charge = Some(ScreenCharge {
        cells: 1,
        rows: 1,
        models: 0,
    });
    reserve_registered(&mut ledger, &handles, r, cleanup).unwrap();
    r.id = ReservationId::new(3).unwrap();
    r.screen_charge = Some(ScreenCharge {
        cells: 1,
        rows: 1,
        models: 1,
    });
    assert!(reserve_registered(&mut ledger, &handles, r, cleanup).is_err());
    r.screen_charge = Some(ScreenCharge {
        cells: 1,
        rows: 1,
        models: 2,
    });
    assert!(r.validate().is_err());
    r.screen_charge = Some(ScreenCharge {
        cells: 1,
        rows: 1,
        models: 0,
    });
    r.bytes = 1;
    assert!(r.validate().is_err());
    let mut limits = resource_limits();
    limits.max_reservations = usize::MAX;
    assert!(ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), limits).is_err());
    assert!(GrantLedger::new(LedgerInstance::new([201; 16]).unwrap(), usize::MAX).is_err());
}
#[test]
fn grant_bindings_refuse_foreign_owner_principal_and_expired_replay() {
    let b = binding();
    let mut ledger = GrantLedger::new(LedgerInstance::new([201; 16]).unwrap(), 4).unwrap();
    let authority = grant_authority(&mut ledger, b);
    let grant = AttachGrant::new([3; 32]).unwrap();
    ledger.insert(authority, grant, b, 1).unwrap();
    for field in 0..4 {
        let mut wrong = b;
        match field {
            0 => wrong.principal = AuthenticatedPrincipalRef::new([8; 16]).unwrap(),
            1 => wrong.owner = OwnerInstance::new([8; 16]).unwrap(),
            2 => wrong.locator.session = RetainedSessionId::new([8; 16]).unwrap(),
            _ => wrong.frontend = FrontendGeneration::new([8; 16]).unwrap(),
        };
        assert!(ledger
            .consume(authority, grant, wrong, 2, AttachEpoch::new(1).unwrap())
            .is_err());
    }
    assert!(ledger
        .consume(authority, grant, b, 9, AttachEpoch::new(1).unwrap())
        .is_ok());
    assert!(ledger
        .consume(authority, grant, b, 10, AttachEpoch::new(2).unwrap())
        .is_err());
}
#[test]
fn host_peer_limits_ids_roles_and_semantic_replies_are_transactional() {
    use super::host_protocol::*;
    use super::protocol::{OwnerProtocolError, OwnerRole};
    let host = HostInstance::new([8; 16]).unwrap();
    let mut peer = HostPeerState::new(OwnerRole::Frontend, OwnerRole::Host, host);
    let b = binding();
    for id in 1..=64 {
        let f = HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host,
                request_id: id,
            },
            message: HostMessage::AuthorizeAttach {
                principal: b.principal,
                locator: b.locator,
                frontend: b.frontend,
            },
        };
        peer.send(&f).unwrap();
    }
    let f = HostFrame {
        header: HostHeader {
            role: OwnerRole::Frontend,
            host,
            request_id: 65,
        },
        message: HostMessage::AuthorizeAttach {
            principal: b.principal,
            locator: b.locator,
            frontend: b.frontend,
        },
    };
    let before = peer.clone();
    assert_eq!(peer.send(&f), Err(OwnerProtocolError::RequestLimit));
    assert_eq!(peer, before);
    let mut wrong = b;
    wrong.frontend = FrontendGeneration::new([9; 16]).unwrap();
    let reply = HostFrame {
        header: HostHeader {
            role: OwnerRole::Host,
            host,
            request_id: 1,
        },
        message: HostMessage::AttachAuthorized {
            grant: AttachGrant::new([3; 32]).unwrap(),
            binding: wrong,
        },
    };
    assert!(peer.receive(&reply).is_err());
    assert_eq!(peer, before);
    let valid = HostFrame {
        message: HostMessage::AttachAuthorized {
            grant: AttachGrant::new([3; 32]).unwrap(),
            binding: b,
        },
        ..reply
    };
    peer.receive(&valid).unwrap();
    assert_eq!(peer.outstanding(), 63);
    assert!(peer.receive(&valid).is_err());
    let mut replay = f;
    replay.header.request_id = 1;
    assert!(peer.send(&replay).is_err());
    let mut wrong_role = encode(&valid).unwrap();
    wrong_role[6] = OwnerRole::Frontend.to_wire();
    let mut decoder = HostDecoder::new();
    assert!(decoder.push(&wrong_role[..36]).is_err());
    assert_eq!(decoder.buffer_capacity(), 36);
}
#[test]
fn status_enumeration_is_atomic_across_epoch_and_build_changes() {
    use super::status_contract::*;
    let build = BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap();
    let front = FrontendIdentity {
        generation: binding().frontend,
        build: build.clone(),
    };
    let epoch = StatusEpoch::new([7; 16]).unwrap();
    let owner = OwnerStatus {
        locator: binding().locator,
        build: build.clone(),
        ipc: IpcRange::new(1, 1).unwrap(),
        active_channels: 1,
        total_channels: 1,
    };
    let first = StatusPage {
        host: HostInstance::new([8; 16]).unwrap(),
        host_build: build,
        frontend: front,
        epoch,
        cursor: 0,
        total: 2,
        owners: vec![owner.clone()],
        next: Some(StatusCursor { epoch, index: 1 }),
    };
    let mut second = first.clone();
    second.cursor = 1;
    second.next = None;
    second.owners[0].locator.session = RetainedSessionId::new([9; 16]).unwrap();
    second.owners[0].locator.owner = OwnerInstance::new([9; 16]).unwrap();
    for field in 0..3 {
        let mut collector = StatusCollector::new(2).unwrap();
        assert!(!collector.accept(first.clone()).unwrap());
        let mut wrong = second.clone();
        match field {
            0 => wrong.epoch = StatusEpoch::new([6; 16]).unwrap(),
            1 => wrong.frontend.generation = FrontendGeneration::new([6; 16]).unwrap(),
            _ => wrong.host_build.build += 1,
        };
        assert!(collector.accept(wrong).is_err());
        assert!(collector.finish().is_err());
    }
    let mut collector = StatusCollector::new(2).unwrap();
    collector.accept(first).unwrap();
    assert!(collector.accept(second).unwrap());
    assert_eq!(collector.finish().unwrap().len(), 2);
}
#[test]
fn resource_overflow_disabled_limits_and_foreign_receipts_preserve_charges() {
    use super::resource_contract::*;
    let p = binding().principal;
    let mut limits = resource_limits();
    limits.snapshot_transfer = ByteLimits {
        channel_bytes: u64::MAX,
        session_bytes: u64::MAX,
        account_bytes: u64::MAX,
        global_bytes: u64::MAX,
    };
    limits.control_queue.channel_bytes = 0;
    let mut ledger = ResourceLedger::new(LedgerInstance::new([203; 16]).unwrap(), limits).unwrap();
    let mut handles = std::collections::HashMap::new();
    let r = reservation(1, 1, 1, p, ReservationKind::SnapshotTransfer, u64::MAX - 1);
    let cleanup = RequestId::new(1).unwrap();
    assert!(reserve_registered(&mut ledger, &handles, r, cleanup).is_err());
    handles.insert(p, ledger.register_fresh_principal(p, 10).unwrap());
    assert!(ledger.register_fresh_principal(p, 11).is_err());
    reserve_registered(&mut ledger, &handles, r, cleanup).unwrap();
    let over = reservation(2, 1, 2, p, ReservationKind::SnapshotTransfer, 2);
    assert!(reserve_registered(&mut ledger, &handles, over, cleanup).is_err());
    assert!(reserve_registered(
        &mut ledger,
        &handles,
        reservation(2, 1, 2, p, ReservationKind::ControlQueue, 1),
        cleanup
    )
    .is_err());
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: r.id,
        locator: r.locator,
        channel: transport::channel_geometry::ChannelInstance::new(2).unwrap(),
    };
    assert!(ledger.release(r, receipt).is_err());
    assert_eq!(ledger.reservations(), 1);
}
#[test]
fn new_owner_record_roles_fail_before_allocation() {
    use super::protocol::*;
    let attachment = Attachment {
        locator: binding().locator,
        frontend: binding().frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    let frame = OwnerFrame {
        header: OwnerHeader {
            role: OwnerRole::Frontend,
            host: HostInstance::new([8; 16]).unwrap(),
            owner: binding().owner,
            request_id: 1,
        },
        message: OwnerMessage::Control(ResumeControl::CloseSession {
            request_id: RequestId::new(1).unwrap(),
            close: OwnerCloseSession {
                attachment,
                reason: CloseReason::ExplicitClient,
            },
        }),
    };
    let mut bytes = encode(&frame).unwrap();
    bytes[6] = OwnerRole::Owner.to_wire();
    let mut decoder = OwnerDecoder::new();
    assert!(decoder.push(&bytes[..52]).is_err());
    assert_eq!(decoder.buffer_capacity(), 52);
}
#[test]
fn all_global_host_kinds_roundtrip_every_split_and_truncation() {
    use super::host_protocol::*;
    use super::protocol::OwnerRole;
    use super::resource_contract::*;
    use super::status_contract::*;
    let b = binding();
    let host = HostInstance::new([8; 16]).unwrap();
    let build = BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap();
    let r = reservation(1, 1, 1, b.principal, ReservationKind::ScreenModel, 0);
    let r = Reservation {
        screen_charge: Some(ScreenCharge {
            cells: 1,
            rows: 1,
            models: 1,
        }),
        ..r
    };
    let cleanup = RequestId::new(7).unwrap();
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: r.id,
        locator: r.locator,
        channel: r.channel,
    };
    let messages = vec![
        (
            0x10,
            OwnerRole::Frontend,
            HostMessage::AuthorizeAttach {
                principal: b.principal,
                locator: b.locator,
                frontend: b.frontend,
            },
        ),
        (
            0x11,
            OwnerRole::Host,
            HostMessage::AttachAuthorized {
                grant: AttachGrant::new([5; 32]).unwrap(),
                binding: b,
            },
        ),
        (
            0x12,
            OwnerRole::Host,
            HostMessage::AttachAuthorizationRefused {
                principal: b.principal,
                locator: b.locator,
                frontend: b.frontend,
                reason: AttachRefusal::Unauthorized,
            },
        ),
        (
            0x13,
            OwnerRole::Host,
            HostMessage::RevokeFrontend {
                frontend: b.frontend,
            },
        ),
        (
            0x14,
            OwnerRole::Frontend,
            HostMessage::FrontendRevoked {
                frontend: b.frontend,
            },
        ),
        (
            0x20,
            OwnerRole::Frontend,
            HostMessage::StatusRequest {
                frontend: b.frontend,
                cursor: None,
            },
        ),
        (
            0x21,
            OwnerRole::Host,
            HostMessage::Status(StatusPage {
                host,
                host_build: build.clone(),
                frontend: FrontendIdentity {
                    generation: b.frontend,
                    build,
                },
                epoch: StatusEpoch::new([1; 16]).unwrap(),
                cursor: 0,
                total: 0,
                owners: vec![],
                next: None,
            }),
        ),
        (
            0x22,
            OwnerRole::Frontend,
            HostMessage::Reserve {
                reservation: r,
                cleanup,
            },
        ),
        (
            0x23,
            OwnerRole::Host,
            HostMessage::Reserved {
                reservation: r,
                cleanup,
            },
        ),
        (
            0x24,
            OwnerRole::Host,
            HostMessage::ReservationRefused {
                reservation: r,
                reason: ReservationRefusal::ResourceLimit,
            },
        ),
        (
            0x25,
            OwnerRole::Frontend,
            HostMessage::Release {
                reservation: r,
                receipt,
            },
        ),
        (
            0x26,
            OwnerRole::Host,
            HostMessage::Released {
                reservation: r,
                receipt,
            },
        ),
    ];
    for (kind, role, message) in messages {
        let frame = HostFrame {
            header: HostHeader {
                role,
                host,
                request_id: 1,
            },
            message,
        };
        let bytes = encode(&frame).unwrap();
        assert_eq!(bytes[7], kind);
        assert_eq!(
            bytes.len(),
            36 + u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize
        );
        for split in 1..bytes.len() {
            let mut d = HostDecoder::new();
            assert!(d.push(&bytes[..split]).unwrap().is_empty());
            assert!(d.finish().is_err());
            let mut d = HostDecoder::new();
            assert!(d.push(&bytes[..split]).unwrap().is_empty());
            assert_eq!(d.push(&bytes[split..]).unwrap(), vec![frame.clone()]);
            d.finish().unwrap();
        }
    }
}
#[test]
fn maximum_status_page_is_bounded_and_uses_separate_executable_identities() {
    use super::host_protocol::*;
    use super::protocol::OwnerRole;
    use super::status_contract::*;
    let build = BuildIdentity::new(&"v".repeat(128), 1, [3; 32]).unwrap();
    let host = HostInstance::new([8; 16]).unwrap();
    let epoch = StatusEpoch::new([9; 16]).unwrap();
    let owners = (1..=64)
        .map(|i| OwnerStatus {
            locator: SessionLocator {
                session: RetainedSessionId::new([i; 16]).unwrap(),
                owner: OwnerInstance::new([i; 16]).unwrap(),
            },
            build: build.clone(),
            ipc: IpcRange::new(1, 1).unwrap(),
            active_channels: 8,
            total_channels: 240,
        })
        .collect();
    let page = StatusPage {
        host,
        host_build: build.clone(),
        frontend: FrontendIdentity {
            generation: binding().frontend,
            build,
        },
        epoch,
        cursor: 0,
        total: 65,
        owners,
        next: Some(StatusCursor { epoch, index: 64 }),
    };
    let frame = HostFrame {
        header: HostHeader {
            role: OwnerRole::Host,
            host,
            request_id: 1,
        },
        message: HostMessage::Status(page),
    };
    let bytes = encode(&frame).unwrap();
    assert_eq!(bytes.len(), 36 + 13_740);
    assert_eq!(HostDecoder::new().push(&bytes).unwrap(), vec![frame]);
}
#[test]
fn owner_semantic_reply_does_not_consume_another_attachment_request() {
    use super::operations::*;
    use super::protocol::*;
    let host = HostInstance::new([8; 16]).unwrap();
    let b = binding();
    let h = OwnerHeader {
        role: OwnerRole::Frontend,
        host,
        owner: b.owner,
        request_id: 1,
    };
    let mut peer = PeerState::new(OwnerRole::Frontend, OwnerRole::Owner, host, b.owner);
    let hello = OwnerFrame {
        header: h,
        message: OwnerMessage::Hello {
            min_version: 1,
            max_version: 1,
        },
    };
    peer.send(&hello).unwrap();
    peer.receive(&OwnerFrame {
        header: OwnerHeader {
            role: OwnerRole::Owner,
            ..h
        },
        message: OwnerMessage::HelloAck {
            selected_version: 1,
        },
    })
    .unwrap();
    let attachment = Attachment {
        locator: b.locator,
        frontend: b.frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    peer.send(&OwnerFrame {
        header: OwnerHeader { request_id: 2, ..h },
        message: OwnerMessage::Operation(OwnerOperation::CatalogRequest { attachment }),
    })
    .unwrap();
    let mut foreign = attachment;
    foreign.frontend = FrontendGeneration::new([9; 16]).unwrap();
    let catalog = RetainedCatalog::new(
        foreign,
        transport::channel::ChannelSnapshot::new(vec![], vec![]).unwrap(),
        vec![],
    )
    .unwrap();
    let reply = OwnerFrame {
        header: OwnerHeader {
            role: OwnerRole::Owner,
            request_id: 2,
            ..h
        },
        message: OwnerMessage::Operation(OwnerOperation::Catalog(catalog)),
    };
    let before = peer.clone();
    assert!(peer.receive(&reply).is_err());
    assert_eq!(peer, before);
}
#[test]
fn all_local_owner_operations_have_frozen_kinds_and_bounded_roundtrips() {
    use super::operations::*;
    use super::protocol::*;
    use super::status_contract::*;
    use transport::channel::{ChannelKind, ChannelSnapshot, OpenRequest};
    use transport::channel_geometry::{
        ChannelInstance, GeometryOutcome, GeometryRecord, ResizeRequestId,
    };
    let b = binding();
    let a = Attachment {
        locator: b.locator,
        frontend: b.frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    let channel = ChannelInstance::new(1).unwrap();
    let geometry = GeometryRecord {
        instance: channel,
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 80,
        rows: 24,
    };
    let changed = GeometryRecord {
        request_id: 1,
        outcome: GeometryOutcome::Applied,
        ..geometry
    };
    let close = OwnerCloseChannel {
        attachment: a,
        channel,
        reason: CloseReason::ExplicitClient,
    };
    let status = OwnerStatus {
        locator: b.locator,
        build: BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap(),
        ipc: IpcRange::new(1, 1).unwrap(),
        active_channels: 1,
        total_channels: 1,
    };
    let operations = vec![
        (
            0x10,
            OwnerRole::Frontend,
            OwnerOperation::Open(OwnerOpen {
                attachment: a,
                request: OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: vec![],
                },
            }),
        ),
        (
            0x11,
            OwnerRole::Owner,
            OwnerOperation::Opened {
                attachment: a,
                channel,
                stream: 16,
                geometry,
                has_screen: true,
            },
        ),
        (
            0x12,
            OwnerRole::Owner,
            OwnerOperation::OpenRefused {
                attachment: a,
                stream: 16,
                reason: OpenRefusal::ResourceLimit,
            },
        ),
        (
            0x13,
            OwnerRole::Frontend,
            OwnerOperation::Resize(OwnerResize {
                attachment: a,
                channel,
                request_id: ResizeRequestId::new(1).unwrap(),
                cols: 81,
                rows: 25,
            }),
        ),
        (
            0x14,
            OwnerRole::Owner,
            OwnerOperation::ResizeResult {
                attachment: a,
                geometry: changed,
            },
        ),
        (
            0x15,
            OwnerRole::Frontend,
            OwnerOperation::CloseChannel(close),
        ),
        (
            0x16,
            OwnerRole::Frontend,
            OwnerOperation::CloseSession(OwnerCloseSession {
                attachment: a,
                reason: CloseReason::ExplicitClient,
            }),
        ),
        (
            0x17,
            OwnerRole::Owner,
            OwnerOperation::CloseAccepted(CloseAccepted {
                attachment: a,
                target: CloseTarget::Channel(channel),
            }),
        ),
        (
            0x18,
            OwnerRole::Owner,
            OwnerOperation::ExitReceipt(ExitReceipt {
                attachment: a,
                channel,
                receipt_id: RequestId::new(1).unwrap(),
                fact: ExitFact::StatusUnavailable,
            }),
        ),
        (
            0x19,
            OwnerRole::Frontend,
            OwnerOperation::CatalogRequest { attachment: a },
        ),
        (
            0x1a,
            OwnerRole::Owner,
            OwnerOperation::Catalog(
                RetainedCatalog::new(a, ChannelSnapshot::new(vec![], vec![]).unwrap(), vec![])
                    .unwrap(),
            ),
        ),
        (
            0x20,
            OwnerRole::Frontend,
            OwnerOperation::AttachWithGrant {
                locator: b.locator,
                frontend: b.frontend,
                last_epoch: 0,
                grant: AttachGrant::new([7; 32]).unwrap(),
                binding: b,
            },
        ),
        (
            0x21,
            OwnerRole::Owner,
            OwnerOperation::GrantRejected {
                locator: b.locator,
                frontend: b.frontend,
                reason: AttachRefusal::Unauthorized,
            },
        ),
        (0x22, OwnerRole::Host, OwnerOperation::OwnerStatusRequest),
        (0x23, OwnerRole::Owner, OwnerOperation::OwnerStatus(status)),
        (
            0x24,
            OwnerRole::Host,
            OwnerOperation::Shutdown {
                transaction: RequestId::new(1).unwrap(),
                reason: CloseReason::Administrator,
            },
        ),
        (
            0x25,
            OwnerRole::Owner,
            OwnerOperation::ShutdownReceipt {
                transaction: RequestId::new(1).unwrap(),
            },
        ),
    ];
    for (kind, role, op) in operations {
        let frame = OwnerFrame {
            header: OwnerHeader {
                role,
                host: HostInstance::new([8; 16]).unwrap(),
                owner: b.owner,
                request_id: if kind == 0x18 { 0 } else { 1 },
            },
            message: OwnerMessage::Operation(op),
        };
        let bytes = encode(&frame).unwrap();
        assert_eq!(bytes[7], kind);
        assert_eq!(
            bytes.len(),
            52 + u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize
        );
        for split in 1..bytes.len() {
            let mut d = OwnerDecoder::new();
            assert!(d.push(&bytes[..split]).unwrap().is_empty(), "kind {kind}");
            assert!(d.finish().is_err());
            let mut d = OwnerDecoder::new();
            assert!(d.push(&bytes[..split]).unwrap().is_empty());
            assert_eq!(d.push(&bytes[split..]).unwrap(), vec![frame.clone()]);
        }
    }
}
#[test]
fn prepared_failure_cannot_claim_detachment_before_actual_failure_or_fence() {
    use super::status_contract::*;
    let front = FrontendIdentity {
        generation: binding().frontend,
        build: BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap(),
    };
    let mut tx = ReplacementTransaction::new(ReplacementId::new([1; 16]).unwrap(), front);
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::Prepared,
        serving: None,
    })
    .unwrap();
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::DetachedFailure,
            serving: None
        })
        .is_err());
    tx.record_frontend_failure(tx.id()).unwrap();
    tx.record(ReplacementFact {
        transaction: Some(tx.id()),
        status: ReplacementStatus::DetachedFailure,
        serving: None,
    })
    .unwrap();
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::Activated,
            serving: Some(tx.candidate().clone())
        })
        .is_err());
}
#[test]
fn opened_requires_initial_geometry_and_cannot_claim_screen_for_no_pty() {
    use super::operations::*;
    use super::protocol::*;
    use transport::channel_geometry::*;
    let b = binding();
    let attachment = Attachment {
        locator: b.locator,
        frontend: b.frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    let channel = ChannelInstance::new(1).unwrap();
    let h = OwnerHeader {
        role: OwnerRole::Owner,
        host: HostInstance::new([8; 16]).unwrap(),
        owner: b.owner,
        request_id: 1,
    };
    for geometry in [
        GeometryRecord {
            instance: channel,
            request_id: 1,
            outcome: GeometryOutcome::Applied,
            cols: 80,
            rows: 24,
        },
        GeometryRecord {
            instance: channel,
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 0,
            rows: 0,
        },
    ] {
        assert!(encode(&OwnerFrame {
            header: h,
            message: OwnerMessage::Operation(OwnerOperation::Opened {
                attachment,
                channel,
                stream: 16,
                geometry,
                has_screen: true
            })
        })
        .is_err());
    }
}

#[test]
fn review_r1_capacity_boundary_revocation_actually_invalidates() {
    let b = binding();
    let mut ledger = GrantLedger::new(LedgerInstance::new([204; 16]).unwrap(), 1).unwrap();
    let authority = grant_authority(&mut ledger, b);
    ledger.revoke_frontend(authority.frontend).unwrap();
    let mut next = b;
    next.frontend = FrontendGeneration::new([91; 16]).unwrap();
    let next_authority = GrantAuthority {
        principal: authority.principal,
        frontend: ledger.register_fresh_frontend(next.frontend).unwrap(),
    };
    let grant = AttachGrant::new([91; 32]).unwrap();
    ledger.insert(next_authority, grant, next, 1).unwrap();
    assert!(ledger.revoke_frontend(next_authority.frontend).is_ok());
    assert!(ledger
        .consume(next_authority, grant, next, 2, AttachEpoch::new(1).unwrap())
        .is_err());
}

#[test]
fn review_r3_recovery_cannot_be_reported_without_actual_serving_identity() {
    use super::status_contract::*;
    let front = FrontendIdentity {
        generation: binding().frontend,
        build: BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap(),
    };
    let mut tx = ReplacementTransaction::new(ReplacementId::new([92; 16]).unwrap(), front);
    for status in [
        ReplacementStatus::Prepared,
        ReplacementStatus::Fenced,
        ReplacementStatus::Retired,
    ] {
        tx.record(ReplacementFact {
            transaction: Some(tx.id()),
            status,
            serving: None,
        })
        .unwrap();
    }
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(tx.id()),
            status: ReplacementStatus::Recovered,
            serving: None
        })
        .is_err());
}

#[test]
fn review_r1_churn_retires_authority_without_losing_an_unrelated_live_grant() {
    let scope = LedgerInstance::new([101; 16]).unwrap();
    let mut ledger = GrantLedger::new(scope, 2).unwrap();
    let mut long = binding();
    long.expires_at_monotonic = 10_000;
    let long_auth = GrantAuthority {
        principal: ledger.register_fresh_principal(long.principal).unwrap(),
        frontend: ledger.register_fresh_frontend(long.frontend).unwrap(),
    };
    let long_grant = AttachGrant::new([101; 32]).unwrap();
    ledger.insert(long_auth, long_grant, long, 1).unwrap();
    let mut stale = None;
    for i in 0..12u8 {
        let mut b = long;
        b.principal = AuthenticatedPrincipalRef::new([110 + i; 16]).unwrap();
        b.frontend = FrontendGeneration::new([130 + i; 16]).unwrap();
        let auth = GrantAuthority {
            principal: ledger.register_fresh_principal(b.principal).unwrap(),
            frontend: ledger.register_fresh_frontend(b.frontend).unwrap(),
        };
        let g = AttachGrant::new([150 + i; 32]).unwrap();
        if let Some((old, g, b)) = stale {
            assert!(ledger.insert(old, g, b, 1).is_err());
            assert!(ledger
                .consume(old, g, b, 1, AttachEpoch::new(1).unwrap())
                .is_err());
        }
        ledger.insert(auth, g, b, 1).unwrap();
        assert_eq!(ledger.grants(), 2);
        assert_eq!(ledger.frontends(), 2);
        ledger.revoke_frontend(auth.frontend).unwrap();
        assert!(ledger
            .consume(auth, g, b, 1, AttachEpoch::new(1).unwrap())
            .is_err());
        assert!(ledger.insert(auth, g, b, 1).is_err());
        ledger.retire_principal(auth.principal).unwrap();
        assert_eq!(
            (ledger.grants(), ledger.frontends(), ledger.principals()),
            (1, 1, 1)
        );
        stale = Some((auth, g, b));
    }
    ledger
        .consume(long_auth, long_grant, long, 1, AttachEpoch::new(1).unwrap())
        .unwrap();
    let mut other = GrantLedger::new(LedgerInstance::new([102; 16]).unwrap(), 2).unwrap();
    let fresh = GrantAuthority {
        principal: other.register_fresh_principal(long.principal).unwrap(),
        frontend: other.register_fresh_frontend(long.frontend).unwrap(),
    };
    other.insert(fresh, long_grant, long, 1).unwrap();
    assert!(other
        .consume(long_auth, long_grant, long, 1, AttachEpoch::new(1).unwrap())
        .is_err());
    other
        .consume(fresh, long_grant, long, 1, AttachEpoch::new(1).unwrap())
        .unwrap();
}
#[test]
fn review_r1_principal_churn_requires_exact_cleanup_and_preserves_live_accounting() {
    use super::resource_contract::*;
    let mut limits = resource_limits();
    limits.max_reservations = 2;
    let mut ledger = ResourceLedger::new(LedgerInstance::new([103; 16]).unwrap(), limits).unwrap();
    let p = binding().principal;
    let long = ledger.register_fresh_principal(p, 10).unwrap();
    let cleanup = RequestId::new(1).unwrap();
    let retained = reservation(1, 1, 1, p, ReservationKind::OutputHistory, 1);
    ledger.reserve(long, retained, cleanup).unwrap();
    for i in 0..12u8 {
        let p = AuthenticatedPrincipalRef::new([160 + i; 16]).unwrap();
        let handle = ledger.register_fresh_principal(p, 20).unwrap();
        let r = reservation(i as u64 + 2, 2, 1, p, ReservationKind::OutputHistory, 1);
        ledger.reserve(handle, r, cleanup).unwrap();
        assert!(ledger.retire_principal(handle).is_err());
        assert!(ledger.register_fresh_principal(p, 21).is_err());
        let mut receipt = ReservationReceipt {
            id: cleanup,
            reservation: r.id,
            locator: r.locator,
            channel: r.channel,
        };
        receipt.id = RequestId::new(2).unwrap();
        assert!(ledger.release(r, receipt).is_err());
        assert_eq!(ledger.reservations(), 2);
        receipt.id = cleanup;
        ledger.release(r, receipt).unwrap();
        ledger.retire_principal(handle).unwrap();
        let mut stale = r;
        stale.id = ReservationId::new(1000).unwrap();
        assert!(ledger.reserve(handle, stale, cleanup).is_err());
        assert!(ledger.release(r, receipt).is_err());
        assert_eq!((ledger.reservations(), ledger.principals()), (1, 1));
    }
    assert!(ledger.register_fresh_principal(p, 11).is_err());
    let receipt = ReservationReceipt {
        id: cleanup,
        reservation: retained.id,
        locator: retained.locator,
        channel: retained.channel,
    };
    ledger.release(retained, receipt).unwrap();
    ledger.retire_principal(long).unwrap();
    let fresh = ledger.register_fresh_principal(p, 10).unwrap();
    assert!(ledger.reserve(fresh, retained, cleanup).is_err());
    assert_eq!(ledger.reservations(), 0);
    let mut other = ResourceLedger::new(LedgerInstance::new([104; 16]).unwrap(), limits).unwrap();
    let new = other.register_fresh_principal(p, 10).unwrap();
    assert!(other.reserve(long, retained, cleanup).is_err());
    other.reserve(new, retained, cleanup).unwrap();
}
#[test]
fn review_r3_terminal_facts_bind_transaction_candidate_and_actual_rollback() {
    use super::status_contract::*;
    let id = ReplacementId::new([105; 16]).unwrap();
    let candidate = FrontendIdentity {
        generation: binding().frontend,
        build: BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap(),
    };
    let rollback = FrontendIdentity {
        generation: FrontendGeneration::new([106; 16]).unwrap(),
        build: BuildIdentity::new("0.5.0", 2, [2; 32]).unwrap(),
    };
    let mut tx = ReplacementTransaction::new(id, candidate.clone());
    for status in [
        ReplacementStatus::Prepared,
        ReplacementStatus::Fenced,
        ReplacementStatus::Retired,
    ] {
        tx.record(ReplacementFact {
            transaction: Some(id),
            status,
            serving: None,
        })
        .unwrap();
        assert_eq!(tx.serving(), None);
    }
    for fact in [
        ReplacementFact {
            transaction: None,
            status: ReplacementStatus::Recovered,
            serving: Some(rollback.clone()),
        },
        ReplacementFact {
            transaction: Some(ReplacementId::new([107; 16]).unwrap()),
            status: ReplacementStatus::Recovered,
            serving: Some(rollback.clone()),
        },
        ReplacementFact {
            transaction: Some(id),
            status: ReplacementStatus::Recovered,
            serving: None,
        },
        ReplacementFact {
            transaction: Some(id),
            status: ReplacementStatus::Activated,
            serving: Some(rollback.clone()),
        },
    ] {
        assert!(tx.record(fact).is_err());
        assert_eq!(tx.status(), Some(ReplacementStatus::Retired));
        assert_eq!(tx.serving(), None);
    }
    tx.record(ReplacementFact {
        transaction: Some(id),
        status: ReplacementStatus::Recovered,
        serving: Some(rollback.clone()),
    })
    .unwrap();
    assert_eq!(tx.candidate(), &candidate);
    assert_eq!(tx.serving(), Some(&rollback));
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(id),
            status: ReplacementStatus::Activated,
            serving: Some(candidate.clone())
        })
        .is_err());
    assert!(tx
        .record_frontend_failure(ReplacementId::new([108; 16]).unwrap())
        .is_err());
    let mut tx = ReplacementTransaction::new(id, candidate.clone());
    tx.record_frontend_failure(id).unwrap();
    tx.record(ReplacementFact {
        transaction: Some(id),
        status: ReplacementStatus::Prepared,
        serving: None,
    })
    .unwrap();
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(id),
            status: ReplacementStatus::DetachedFailure,
            serving: Some(candidate)
        })
        .is_err());
    tx.record(ReplacementFact {
        transaction: Some(id),
        status: ReplacementStatus::DetachedFailure,
        serving: None,
    })
    .unwrap();
    assert_eq!(tx.serving(), None);
}

fn grant_authority(ledger: &mut GrantLedger, b: GrantBinding) -> GrantAuthority {
    GrantAuthority {
        principal: ledger.register_fresh_principal(b.principal).unwrap(),
        frontend: ledger.register_fresh_frontend(b.frontend).unwrap(),
    }
}
fn foreign_grant_authority(b: GrantBinding) -> GrantAuthority {
    let mut foreign = GrantLedger::new(LedgerInstance::new([202; 16]).unwrap(), 2).unwrap();
    grant_authority(&mut foreign, b)
}
fn reserve_registered(
    ledger: &mut super::resource_contract::ResourceLedger,
    handles: &std::collections::HashMap<AuthenticatedPrincipalRef, PrincipalRegistration>,
    r: super::resource_contract::Reservation,
    cleanup: RequestId,
) -> Result<(), super::protocol::OwnerProtocolError> {
    let handle = if let Some(p) = handles.get(&r.principal) {
        *p
    } else {
        let mut foreign = super::resource_contract::ResourceLedger::new(
            LedgerInstance::new([205; 16]).unwrap(),
            resource_limits(),
        )
        .unwrap();
        foreign.register_fresh_principal(r.principal, 10).unwrap()
    };
    ledger.reserve(handle, r, cleanup)
}

#[test]
fn review_r1_same_public_values_require_new_registration_handles() {
    let b = binding();
    let mut ledger = GrantLedger::new(LedgerInstance::new([206; 16]).unwrap(), 1).unwrap();
    let stale = grant_authority(&mut ledger, b);
    ledger.revoke_frontend(stale.frontend).unwrap();
    ledger.retire_principal(stale.principal).unwrap();
    let fresh = grant_authority(&mut ledger, b);
    let g = AttachGrant::new([207; 32]).unwrap();
    ledger.insert(fresh, g, b, 1).unwrap();
    assert!(ledger.revoke_frontend(stale.frontend).is_err());
    assert!(ledger.retire_principal(stale.principal).is_err());
    assert!(ledger
        .consume(stale, g, b, 1, AttachEpoch::new(1).unwrap())
        .is_err());
    assert_eq!(
        (ledger.grants(), ledger.frontends(), ledger.principals()),
        (1, 1, 1)
    );
    ledger
        .consume(fresh, g, b, 1, AttachEpoch::new(1).unwrap())
        .unwrap();
    use super::resource_contract::*;
    let mut resources =
        ResourceLedger::new(LedgerInstance::new([208; 16]).unwrap(), resource_limits()).unwrap();
    let old = resources.register_fresh_principal(b.principal, 10).unwrap();
    resources.retire_principal(old).unwrap();
    let new = resources.register_fresh_principal(b.principal, 10).unwrap();
    let r = reservation(1, 1, 1, b.principal, ReservationKind::OutputHistory, 1);
    assert!(resources
        .reserve(old, r, RequestId::new(1).unwrap())
        .is_err());
    resources
        .reserve(new, r, RequestId::new(1).unwrap())
        .unwrap();
    assert!(resources.retire_principal(old).is_err());
    assert_eq!(resources.reservations(), 1);
}
#[test]
fn review_r2_owner_data_cursor_frame_has_an_exact_89_byte_body() {
    use super::protocol::*;
    let b = binding();
    let attachment = Attachment {
        locator: b.locator,
        frontend: b.frontend,
        epoch: AttachEpoch::new(1).unwrap(),
    };
    let request = RecoveryRequest {
        attachment,
        channel: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
        parser: ParserContinuity::DataCursor {
            cursor: OutputCursor {
                channel: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                offset: 2,
            },
        },
    };
    let frame = OwnerFrame {
        header: OwnerHeader {
            role: OwnerRole::Frontend,
            host: HostInstance::new([209; 16]).unwrap(),
            owner: b.owner,
            request_id: 1,
        },
        message: OwnerMessage::Control(ResumeControl::RecoveryRequest {
            request_id: RequestId::new(1).unwrap(),
            request,
        }),
    };
    let bytes = encode(&frame).unwrap();
    assert_eq!(bytes.len(), 141);
    assert_eq!(OwnerDecoder::new().push(&bytes).unwrap(), vec![frame]);
    for len in [74u32, 88, 90, 104] {
        let mut header = bytes[..52].to_vec();
        header[8..12].copy_from_slice(&len.to_be_bytes());
        let mut d = OwnerDecoder::new();
        assert!(d.push(&header).is_err());
        assert_eq!(d.buffer_capacity(), 52);
    }
}
#[test]
fn review_r3_activation_requires_exact_acknowledged_candidate_and_is_terminal() {
    use super::status_contract::*;
    let id = ReplacementId::new([210; 16]).unwrap();
    let candidate = FrontendIdentity {
        generation: binding().frontend,
        build: BuildIdentity::new("0.6.0-rc1", 1, [1; 32]).unwrap(),
    };
    let mut tx = ReplacementTransaction::new(id, candidate.clone());
    assert!(tx
        .record(ReplacementFact {
            transaction: Some(id),
            status: ReplacementStatus::Prepared,
            serving: Some(candidate.clone())
        })
        .is_err());
    assert_eq!(tx.status(), None);
    for status in [
        ReplacementStatus::Prepared,
        ReplacementStatus::Fenced,
        ReplacementStatus::Retired,
    ] {
        tx.record(ReplacementFact {
            transaction: Some(id),
            status,
            serving: None,
        })
        .unwrap();
    }
    let activated = ReplacementFact {
        transaction: Some(id),
        status: ReplacementStatus::Activated,
        serving: Some(candidate.clone()),
    };
    tx.record(activated.clone()).unwrap();
    assert_eq!(tx.serving(), Some(&candidate));
    assert!(tx.record(activated).is_err());
    assert!(tx.record_frontend_failure(id).is_err());
    assert_eq!(
        (tx.status(), tx.serving()),
        (Some(ReplacementStatus::Activated), Some(&candidate))
    );
}
