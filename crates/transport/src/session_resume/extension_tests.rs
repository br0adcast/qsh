//! Synthetic, nonsecret identity/grant bytes for pure contract tests only.
//! No fixture authenticates to an account, daemon, SSH service or real owner.
use super::*;
use crate::channel::{ActiveChannel, ChannelKind, ChannelSnapshot, OpenRequest};
use crate::channel_geometry::{GeometryOutcome, GeometryRecord};
fn attachment() -> Attachment {
    Attachment {
        locator: SessionLocator {
            session: RetainedSessionId::new([1; 16]).unwrap(),
            owner: OwnerInstance::new([2; 16]).unwrap(),
        },
        frontend: FrontendGeneration::new([3; 16]).unwrap(),
        epoch: AttachEpoch::new(1).unwrap(),
    }
}
fn instance() -> ChannelInstance {
    ChannelInstance::new(1).unwrap()
}
fn position() -> ChannelPosition {
    ChannelPosition {
        channel: instance(),
        input: InputPosition {
            epoch: InputEpoch::new([4; 16]).unwrap(),
            accepted: 0,
            committed: 0,
        },
        output: OutputCursor {
            channel: instance(),
            offset: 0,
        },
        geometry: GeometryRecord {
            instance: instance(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        },
        lifecycle: ChannelLifecycle::Active,
    }
}
fn snapshot() -> ChannelSnapshot {
    ChannelSnapshot::new(
        vec![ActiveChannel {
            instance: instance(),
            request: OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: true,
                command: vec![],
            },
        }],
        vec![],
    )
    .unwrap()
}
#[test]
fn catalog_requires_exact_unique_instance_positions() {
    assert!(RetainedCatalog::new(attachment(), snapshot(), vec![]).is_err());
    assert!(RetainedCatalog::new(attachment(), snapshot(), vec![position(), position()]).is_err());
    let mut wrong = position();
    wrong.channel = ChannelInstance::new(2).unwrap();
    assert!(RetainedCatalog::new(attachment(), snapshot(), vec![wrong]).is_err());
    assert!(RetainedCatalog::new(attachment(), snapshot(), vec![position()]).is_ok());
}
#[test]
fn recovery_requires_continuity_and_exact_transaction() {
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Recreated,
    };
    let start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([7; 16]).unwrap(),
        mode: RecoveryMode::ScreenReset,
        boundary: OutputCursor {
            channel: instance(),
            offset: 3,
        },
        gap: true,
        geometry: position().geometry,
        total_bytes: 3,
        snapshot_version: 1,
    };
    let mut tx = RecoveryReceiver::new(request, start, true, RecoveryEvidence::None, 3).unwrap();
    assert!(tx
        .end(RecoveryEnd {
            attachment: attachment(),
            channel: instance(),
            recovery_id: start.recovery_id,
            total_bytes: 3,
            boundary: start.boundary
        })
        .is_err());
    assert!(tx
        .chunk(&RecoveryChunk {
            attachment: attachment(),
            channel: instance(),
            recovery_id: start.recovery_id,
            offset: 1,
            data: vec![1]
        })
        .is_err());
    tx.chunk(&RecoveryChunk {
        attachment: attachment(),
        channel: instance(),
        recovery_id: start.recovery_id,
        offset: 0,
        data: vec![1, 2, 3],
    })
    .unwrap();
    assert!(tx
        .end(RecoveryEnd {
            attachment: attachment(),
            channel: instance(),
            recovery_id: start.recovery_id,
            total_bytes: 3,
            boundary: start.boundary
        })
        .is_ok());
    let mut replay = start;
    replay.mode = RecoveryMode::Replay;
    replay.snapshot_version = 0;
    assert!(RecoveryReceiver::new(request, replay, true, RecoveryEvidence::None, 3).is_err());
    assert!(RecoveryReceiver::new(request, start, false, RecoveryEvidence::None, 3).is_err());
    assert!(RecoveryReceiver::new(request, start, true, RecoveryEvidence::None, 2).is_err());
}
#[test]
fn extended_control_and_recovery_goldens_roundtrip() {
    use crate::shell_frame::RawRecord;
    let cat = RetainedCatalog::new(attachment(), snapshot(), vec![position()]).unwrap();
    let controls = [
        ResumeControl::CatalogRequest {
            request_id: RequestId::new(1).unwrap(),
            attachment: attachment(),
        },
        ResumeControl::Catalog {
            request_id: RequestId::new(1).unwrap(),
            catalog: cat,
        },
        ResumeControl::RecoveryRequest {
            request_id: RequestId::new(2).unwrap(),
            request: RecoveryRequest {
                attachment: attachment(),
                channel: instance(),
                parser: ParserContinuity::Recreated,
            },
        },
        ResumeControl::CloseChannel {
            request_id: RequestId::new(3).unwrap(),
            close: OwnerCloseChannel {
                attachment: attachment(),
                channel: instance(),
                reason: CloseReason::ExplicitClient,
            },
        },
    ];
    for c in controls {
        let bytes = encode_control(&c, Features::SESSION_RESUME).unwrap();
        assert_eq!(bytes[0], c.kind());
        assert_eq!(
            decode_control(
                RawRecord {
                    kind: bytes[0],
                    payload: bytes[5..].to_vec()
                },
                Features::SESSION_RESUME
            ),
            Ok(c)
        );
    }
    let data = ResumeData::RecoveryChunk(RecoveryChunk {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([8; 16]).unwrap(),
        offset: 0,
        data: vec![1, 2],
    });
    let bytes = encode_data(&data, Features::SESSION_RESUME).unwrap();
    assert_eq!(bytes[0], 0x45);
    assert_eq!(
        decode_data(
            RawRecord {
                kind: bytes[0],
                payload: bytes[5..].to_vec()
            },
            Features::SESSION_RESUME
        ),
        Ok(data.clone())
    );
    assert_eq!(
        encode_data(&data, Features::from_bits(0)),
        Err(ResumeError::FeatureRequired)
    );
}
#[test]
fn maximum_legal_catalog_is_atomic_and_fits_owner_frame() {
    use crate::channel::{
        DrainingChannel, OpenClassification, CHANNEL_IDENTITIES, MAX_CHANNELS, MAX_COMMAND_LEN,
    };
    use crate::shell_frame::RawRecord;
    let mut active = Vec::new();
    let mut draining = Vec::new();
    let mut positions = Vec::new();
    for i in 0..CHANNEL_IDENTITIES {
        let channel = ChannelInstance::new(i as u64 + 1).unwrap();
        let stream = (16 + i) as u8;
        let mut p = position();
        p.channel = channel;
        p.output.channel = channel;
        p.geometry.instance = channel;
        if i < MAX_CHANNELS {
            active.push(ActiveChannel {
                instance: channel,
                request: OpenRequest {
                    stream,
                    kind: ChannelKind::Command,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: vec![b'x'; MAX_COMMAND_LEN],
                },
            });
        } else {
            draining.push(DrainingChannel {
                stream,
                instance: channel,
                open: OpenClassification {
                    kind: ChannelKind::Command,
                    cols: 80,
                    rows: 24,
                    screen: false,
                },
            });
            p.lifecycle = ChannelLifecycle::Draining;
        }
        positions.push(p);
    }
    let snapshot = ChannelSnapshot::new(active, draining).unwrap();
    assert_eq!(snapshot.payload_len(), 36_386);
    let catalog = RetainedCatalog::new(attachment(), snapshot, positions).unwrap();
    let c = ResumeControl::Catalog {
        request_id: RequestId::new(1).unwrap(),
        catalog,
    };
    let bytes = encode_control(&c, Features::SESSION_RESUME).unwrap();
    assert_eq!(bytes.len(), 55_421);
    assert!(bytes.len() - 5 + 52 <= 65_536);
    assert_eq!(
        decode_control(
            RawRecord {
                kind: 0x37,
                payload: bytes[5..].to_vec()
            },
            Features::SESSION_RESUME
        ),
        Ok(c)
    );
}
#[test]
fn catalog_recovery_gate_rejects_changed_geometry_stale_completion_and_early_ready() {
    let catalog = RetainedCatalog::new(attachment(), snapshot(), vec![position()]).unwrap();
    let mut state = AttachmentState::new();
    state.begin_attach(attachment()).unwrap();
    state.attached(attachment()).unwrap();
    assert!(state.validate_input(attachment()).is_err());
    assert!(RecoveryGate::new(&catalog)
        .enable_input(&mut state)
        .is_err());
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Recreated,
    };
    let mut start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([9; 16]).unwrap(),
        mode: RecoveryMode::ScreenReset,
        boundary: position().output,
        gap: false,
        geometry: position().geometry,
        total_bytes: 0,
        snapshot_version: 1,
    };
    start.geometry.cols = 81;
    let mut tx = RecoveryReceiver::new(request, start, true, RecoveryEvidence::None, 0).unwrap();
    let completion = tx
        .end(RecoveryEnd {
            attachment: attachment(),
            channel: instance(),
            recovery_id: start.recovery_id,
            total_bytes: 0,
            boundary: start.boundary,
        })
        .unwrap();
    assert!(RecoveryGate::new(&catalog)
        .complete_channel(completion)
        .is_err());
}
#[test]
fn recovery_snapshot_aggregate_bound_is_distinct_from_chunk_or_history_budget() {
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Recreated,
    };
    let mut s = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([9; 16]).unwrap(),
        mode: RecoveryMode::ScreenReset,
        boundary: position().output,
        gap: false,
        geometry: position().geometry,
        total_bytes: (1 << 20) + 1,
        snapshot_version: 1,
    };
    assert!(RecoveryReceiver::new(request, s, true, RecoveryEvidence::None, s.total_bytes).is_ok());
    s.total_bytes = 41_457_965;
    assert!(
        RecoveryReceiver::new(request, s, true, RecoveryEvidence::None, s.total_bytes).is_err()
    );
}
#[test]
fn exact_recovery_enables_input_once_and_stale_close_stays_inert() {
    let catalog = RetainedCatalog::new(attachment(), snapshot(), vec![position()]).unwrap();
    let mut state = AttachmentState::new();
    state.begin_attach(attachment()).unwrap();
    state.attached(attachment()).unwrap();
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Recreated,
    };
    let start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([9; 16]).unwrap(),
        mode: RecoveryMode::ScreenReset,
        boundary: position().output,
        gap: false,
        geometry: position().geometry,
        total_bytes: 0,
        snapshot_version: 1,
    };
    let end = RecoveryEnd {
        attachment: attachment(),
        channel: instance(),
        recovery_id: start.recovery_id,
        total_bytes: 0,
        boundary: start.boundary,
    };
    let mut tx = RecoveryReceiver::new(request, start, true, RecoveryEvidence::None, 0).unwrap();
    let completion = tx.end(end).unwrap();
    assert!(tx.end(end).is_err());
    let mut gate = RecoveryGate::new(&catalog);
    gate.complete_channel(completion).unwrap();
    assert!(gate.complete_channel(completion).is_err());
    gate.enable_input(&mut state).unwrap();
    state.validate_input(attachment()).unwrap();
    let close = OwnerCloseChannel {
        attachment: attachment(),
        channel: instance(),
        reason: CloseReason::ExplicitClient,
    };
    close.validate_lease(&state).unwrap();
    state.abandon(attachment()).unwrap();
    let mut new = attachment();
    new.epoch = AttachEpoch::new(2).unwrap();
    new.frontend = FrontendGeneration::new([7; 16]).unwrap();
    state.begin_attach(new).unwrap();
    assert_eq!(
        close.validate_lease(&state),
        Err(ResumeError::StaleAttachment)
    );
}
#[test]
fn cleanup_requires_each_channel_receipt_and_rejects_duplicates() {
    let catalog = RetainedCatalog::new(attachment(), snapshot(), vec![position()]).unwrap();
    let mut cleanup = SessionCleanup::new(&catalog);
    assert!(!cleanup.complete());
    let receipt = ExitReceipt {
        attachment: attachment(),
        channel: instance(),
        receipt_id: RequestId::new(1).unwrap(),
        fact: ExitFact::Reaped { status: 0 },
    };
    let mut wrong = receipt;
    wrong.attachment.epoch = AttachEpoch::new(2).unwrap();
    assert!(cleanup.receipt(wrong).is_err());
    assert!(!cleanup.complete());
    cleanup.receipt(receipt).unwrap();
    assert!(cleanup.complete());
    assert!(cleanup.receipt(receipt).is_err());
}
#[test]
fn replay_requires_positive_parser_match_and_chunks_bind_all_identities() {
    let cursor = OutputCursor {
        channel: instance(),
        offset: 1,
    };
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Retained {
            parser_instance: [9; 16],
            cursor,
        },
    };
    let start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([7; 16]).unwrap(),
        mode: RecoveryMode::Replay,
        boundary: OutputCursor {
            channel: instance(),
            offset: 4,
        },
        gap: false,
        geometry: position().geometry,
        total_bytes: 3,
        snapshot_version: 0,
    };
    assert!(RecoveryReceiver::new(request, start, true, RecoveryEvidence::None, 3).is_err());
    let mut tx = RecoveryReceiver::new(
        request,
        start,
        true,
        RecoveryEvidence::ScreenParser {
            parser_instance: [9; 16],
            cursor,
        },
        3,
    )
    .unwrap();
    let chunk = RecoveryChunk {
        attachment: attachment(),
        channel: instance(),
        recovery_id: start.recovery_id,
        offset: 0,
        data: vec![1, 2],
    };
    for field in 0..3 {
        let mut wrong = chunk.clone();
        match field {
            0 => wrong.attachment.epoch = AttachEpoch::new(2).unwrap(),
            1 => wrong.recovery_id = RecoveryId::new([8; 16]).unwrap(),
            _ => wrong.channel = ChannelInstance::new(2).unwrap(),
        };
        assert!(tx.chunk(&wrong).is_err());
    }
    tx.chunk(&chunk).unwrap();
    assert!(tx.chunk(&chunk).is_err());
    let mut suffix = chunk;
    suffix.offset = 2;
    suffix.data = vec![3];
    tx.chunk(&suffix).unwrap();
    let mut end = RecoveryEnd {
        attachment: attachment(),
        channel: instance(),
        recovery_id: start.recovery_id,
        total_bytes: 3,
        boundary: start.boundary,
    };
    end.boundary.offset = 5;
    assert!(tx.end(end).is_err());
    end.boundary = start.boundary;
    tx.end(end).unwrap();
}
#[test]
fn all_extension_kinds_roundtrip_and_reject_truncation_and_trailing_bytes() {
    use crate::shell_frame::RawRecord;
    let a = attachment();
    let id = RequestId::new(1).unwrap();
    let receipt = ExitReceipt {
        attachment: a,
        channel: instance(),
        receipt_id: id,
        fact: ExitFact::NoChild,
    };
    let controls = vec![
        ResumeControl::CatalogRequest {
            request_id: id,
            attachment: a,
        },
        ResumeControl::Catalog {
            request_id: id,
            catalog: RetainedCatalog::new(a, snapshot(), vec![position()]).unwrap(),
        },
        ResumeControl::RecoveryRequest {
            request_id: id,
            request: RecoveryRequest {
                attachment: a,
                channel: instance(),
                parser: ParserContinuity::Retained {
                    parser_instance: [8; 16],
                    cursor: position().output,
                },
            },
        },
        ResumeControl::RecoveryReady {
            request_id: id,
            attachment: a,
        },
        ResumeControl::CloseChannel {
            request_id: id,
            close: OwnerCloseChannel {
                attachment: a,
                channel: instance(),
                reason: CloseReason::ExplicitClient,
            },
        },
        ResumeControl::CloseSession {
            request_id: id,
            close: OwnerCloseSession {
                attachment: a,
                reason: CloseReason::ExplicitClient,
            },
        },
        ResumeControl::CloseAccepted {
            request_id: id,
            accepted: CloseAccepted {
                attachment: a,
                target: CloseTarget::Session,
            },
        },
        ResumeControl::ExitReceipt(receipt),
    ];
    for c in controls {
        let bytes = encode_control(&c, Features::SESSION_RESUME).unwrap();
        let payload = &bytes[5..];
        assert_eq!(
            decode_control(
                RawRecord {
                    kind: c.kind(),
                    payload: payload.to_vec()
                },
                Features::SESSION_RESUME
            ),
            Ok(c.clone())
        );
        for end in 0..payload.len() {
            assert!(decode_control(
                RawRecord {
                    kind: c.kind(),
                    payload: payload[..end].to_vec()
                },
                Features::SESSION_RESUME
            )
            .is_err());
        }
        let mut extra = payload.to_vec();
        extra.push(0);
        assert!(decode_control(
            RawRecord {
                kind: c.kind(),
                payload: extra
            },
            Features::SESSION_RESUME
        )
        .is_err());
        assert_eq!(
            encode_control(&c, Features::from_bits(0)),
            Err(ResumeError::FeatureRequired)
        );
    }
    let recovery_id = RecoveryId::new([8; 16]).unwrap();
    let data = vec![
        ResumeData::RecoveryStart(RecoveryStart {
            attachment: a,
            channel: instance(),
            recovery_id,
            mode: RecoveryMode::ScreenReset,
            boundary: position().output,
            gap: false,
            geometry: position().geometry,
            total_bytes: 2,
            snapshot_version: 1,
        }),
        ResumeData::RecoveryChunk(RecoveryChunk {
            attachment: a,
            channel: instance(),
            recovery_id,
            offset: 0,
            data: vec![1, 2],
        }),
        ResumeData::RecoveryEnd(RecoveryEnd {
            attachment: a,
            channel: instance(),
            recovery_id,
            total_bytes: 2,
            boundary: position().output,
        }),
        ResumeData::RecoveryBlocked(RecoveryBlocked {
            attachment: a,
            channel: instance(),
            boundary: position().output,
        }),
    ];
    for d in data {
        let bytes = encode_data(&d, Features::SESSION_RESUME).unwrap();
        let payload = &bytes[5..];
        assert_eq!(
            decode_data(
                RawRecord {
                    kind: d.kind(),
                    payload: payload.to_vec()
                },
                Features::SESSION_RESUME
            ),
            Ok(d.clone())
        );
        for end in 0..payload.len() {
            assert!(decode_data(
                RawRecord {
                    kind: d.kind(),
                    payload: payload[..end].to_vec()
                },
                Features::SESSION_RESUME
            )
            .is_err());
        }
        let mut extra = payload.to_vec();
        extra.push(0);
        assert!(decode_data(
            RawRecord {
                kind: d.kind(),
                payload: extra
            },
            Features::SESSION_RESUME
        )
        .is_err());
    }
}
#[test]
fn unknown_extension_kinds_remain_distinct_from_malformed_known_bodies() {
    use crate::shell_frame::RawRecord;
    assert_eq!(
        decode_control(
            RawRecord {
                kind: 0x3e,
                payload: vec![]
            },
            Features::SESSION_RESUME
        ),
        Err(ResumeError::UnknownKind(0x3e))
    );
    assert_eq!(
        decode_data(
            RawRecord {
                kind: 0x48,
                payload: vec![]
            },
            Features::SESSION_RESUME
        ),
        Err(ResumeError::UnknownKind(0x48))
    );
}
#[test]
fn borrowed_payload_codecs_and_open_adapter_reject_nested_bounds() {
    let mut open = vec![16, 1, 0, 80, 0, 24, 1, 0x10, 1];
    open.resize(9 + 4097, b'x');
    assert!(OwnerOpen::decode_payload(attachment(), &open).is_err());
    open.truncate(9);
    open[1] = 0;
    open[7..9].copy_from_slice(&1u16.to_be_bytes());
    open.push(b'x');
    assert!(OwnerOpen::decode_payload(attachment(), &open).is_err());
    let data = ResumeData::OutputAck {
        attachment: attachment(),
        cursor: position().output,
    };
    let bytes = encode_data(&data, Features::SESSION_RESUME).unwrap();
    assert_eq!(
        decode_data_payload(0x43, &bytes[5..], Features::SESSION_RESUME),
        Ok(data)
    );
    let control = ResumeControl::Catalog {
        request_id: RequestId::new(1).unwrap(),
        catalog: RetainedCatalog::new(attachment(), snapshot(), vec![position()]).unwrap(),
    };
    let bytes = encode_control(&control, Features::SESSION_RESUME).unwrap();
    assert_eq!(
        decode_control_payload(0x37, &bytes[5..], Features::SESSION_RESUME),
        Ok(control)
    );
    let mut malformed = bytes[5..].to_vec();
    let snapshot_len = u32::from_be_bytes(malformed[64..68].try_into().unwrap()) as usize;
    malformed[68 + snapshot_len..70 + snapshot_len].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        decode_control_payload(0x37, &malformed, Features::SESSION_RESUME),
        Err(ResumeError::TooLarge)
    );
}
#[test]
fn review_r2_no_screen_cannot_use_fake_terminal_parser_continuity() {
    let cursor = position().output;
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::Retained {
            parser_instance: [93; 16],
            cursor,
        },
    };
    let start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([93; 16]).unwrap(),
        mode: RecoveryMode::Replay,
        boundary: cursor,
        gap: false,
        geometry: position().geometry,
        total_bytes: 0,
        snapshot_version: 0,
    };
    assert!(RecoveryReceiver::new(
        request,
        start,
        false,
        RecoveryEvidence::ScreenParser {
            parser_instance: [93; 16],
            cursor
        },
        0
    )
    .is_err());
}
#[test]
fn review_r2_data_cursor_recovery_is_explicit_bounded_and_separate_from_screen() {
    let cursor = OutputCursor {
        channel: instance(),
        offset: 2,
    };
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: instance(),
        parser: ParserContinuity::DataCursor { cursor },
    };
    let start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([94; 16]).unwrap(),
        mode: RecoveryMode::Replay,
        boundary: OutputCursor {
            channel: instance(),
            offset: 4,
        },
        gap: false,
        geometry: position().geometry,
        total_bytes: 2,
        snapshot_version: 0,
    };
    let evidence = RecoveryEvidence::DataCursor(cursor);
    assert!(RecoveryReceiver::new(request, start, false, evidence, 2).is_ok());
    assert!(RecoveryReceiver::new(request, start, true, evidence, 2).is_err());
    assert!(RecoveryReceiver::new(request, start, false, RecoveryEvidence::None, 2).is_err());
    assert!(RecoveryReceiver::new(
        request,
        start,
        false,
        RecoveryEvidence::DataCursor(OutputCursor {
            offset: 1,
            ..cursor
        }),
        2
    )
    .is_err());
    assert!(RecoveryReceiver::new(request, start, false, evidence, 1).is_err());
    let mut wrong = request;
    wrong.channel = ChannelInstance::new(2).unwrap();
    assert!(RecoveryReceiver::new(wrong, start, false, evidence, 2).is_err());
    let mut gap = start;
    gap.gap = true;
    assert!(RecoveryReceiver::new(request, gap, false, evidence, 2).is_err());
    let mut reset = start;
    reset.mode = RecoveryMode::ScreenReset;
    reset.snapshot_version = 1;
    assert!(RecoveryReceiver::new(request, reset, false, evidence, 2).is_err());
    let mut absent = request;
    absent.parser = ParserContinuity::Recreated;
    assert!(RecoveryReceiver::new(absent, start, false, evidence, 2).is_err());
    let cursor = OutputCursor {
        channel: instance(),
        offset: u64::MAX,
    };
    let request = RecoveryRequest {
        parser: ParserContinuity::DataCursor { cursor },
        ..request
    };
    let start = RecoveryStart {
        boundary: cursor,
        total_bytes: 1,
        ..start
    };
    assert!(RecoveryReceiver::new(
        request,
        start,
        false,
        RecoveryEvidence::DataCursor(cursor),
        1
    )
    .is_err());
}
#[test]
fn review_r2_mixed_catalog_requires_both_exact_recoveries_before_input() {
    let data_channel = ChannelInstance::new(2).unwrap();
    let mut data_position = position();
    data_position.channel = data_channel;
    data_position.output = OutputCursor {
        channel: data_channel,
        offset: 2,
    };
    data_position.geometry = GeometryRecord {
        instance: data_channel,
        cols: 0,
        rows: 0,
        ..position().geometry
    };
    let channels = ChannelSnapshot::new(
        vec![
            snapshot().active()[0].clone(),
            ActiveChannel {
                instance: data_channel,
                request: OpenRequest {
                    stream: 17,
                    kind: ChannelKind::Command,
                    cols: 0,
                    rows: 0,
                    screen: false,
                    command: b"cat".to_vec(),
                },
            },
        ],
        vec![],
    )
    .unwrap();
    let catalog =
        RetainedCatalog::new(attachment(), channels, vec![position(), data_position]).unwrap();
    let mut gate = RecoveryGate::new(&catalog);
    let mut state = AttachmentState::new();
    state.begin_attach(attachment()).unwrap();
    state.attached(attachment()).unwrap();
    let cursor = OutputCursor {
        channel: data_channel,
        offset: 1,
    };
    let data_start = RecoveryStart {
        attachment: attachment(),
        channel: data_channel,
        recovery_id: RecoveryId::new([95; 16]).unwrap(),
        mode: RecoveryMode::Replay,
        boundary: data_position.output,
        gap: false,
        geometry: data_position.geometry,
        total_bytes: 1,
        snapshot_version: 0,
    };
    let mut data = RecoveryReceiver::new(
        RecoveryRequest {
            attachment: attachment(),
            channel: data_channel,
            parser: ParserContinuity::DataCursor { cursor },
        },
        data_start,
        false,
        RecoveryEvidence::DataCursor(cursor),
        1,
    )
    .unwrap();
    data.chunk(&RecoveryChunk {
        attachment: attachment(),
        channel: data_channel,
        recovery_id: data_start.recovery_id,
        offset: 0,
        data: vec![b'x'],
    })
    .unwrap();
    let completion = data
        .end(RecoveryEnd {
            attachment: attachment(),
            channel: data_channel,
            recovery_id: data_start.recovery_id,
            total_bytes: 1,
            boundary: data_start.boundary,
        })
        .unwrap();
    gate.complete_channel(completion).unwrap();
    assert!(state.validate_input(attachment()).is_err());
    let screen_start = RecoveryStart {
        attachment: attachment(),
        channel: instance(),
        recovery_id: RecoveryId::new([96; 16]).unwrap(),
        mode: RecoveryMode::ScreenReset,
        boundary: position().output,
        gap: false,
        geometry: position().geometry,
        total_bytes: 0,
        snapshot_version: 1,
    };
    let mut screen = RecoveryReceiver::new(
        RecoveryRequest {
            attachment: attachment(),
            channel: instance(),
            parser: ParserContinuity::Recreated,
        },
        screen_start,
        true,
        RecoveryEvidence::None,
        0,
    )
    .unwrap();
    gate.complete_channel(
        screen
            .end(RecoveryEnd {
                attachment: attachment(),
                channel: instance(),
                recovery_id: screen_start.recovery_id,
                total_bytes: 0,
                boundary: screen_start.boundary,
            })
            .unwrap(),
    )
    .unwrap();
    gate.enable_input(&mut state).unwrap();
    state.validate_input(attachment()).unwrap();
    assert!(state.mark_recovery_complete(attachment()).is_err());
}
#[test]
fn review_r2_data_cursor_tag_roundtrips_and_rejects_every_truncation() {
    use crate::shell_frame::RawRecord;
    let c = ResumeControl::RecoveryRequest {
        request_id: RequestId::new(1).unwrap(),
        request: RecoveryRequest {
            attachment: attachment(),
            channel: instance(),
            parser: ParserContinuity::DataCursor {
                cursor: position().output,
            },
        },
    };
    let bytes = encode_control(&c, Features::SESSION_RESUME).unwrap();
    assert_eq!((bytes.len(), bytes[5 + 72]), (94, 2));
    assert_eq!(
        decode_control_payload(0x38, &bytes[5..], Features::SESSION_RESUME),
        Ok(c)
    );
    for end in 0..89 {
        assert!(decode_control(
            RawRecord {
                kind: 0x38,
                payload: bytes[5..5 + end].to_vec()
            },
            Features::SESSION_RESUME
        )
        .is_err());
    }
    let mut wrong = bytes[5..].to_vec();
    wrong[73..81].copy_from_slice(&2u64.to_be_bytes());
    assert!(decode_control_payload(0x38, &wrong, Features::SESSION_RESUME).is_err());
}
