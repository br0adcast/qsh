use super::*;
use crate::channel_geometry::ChannelInstance;
use crate::handshake_payload::{encode_msg1, encode_msg2, AuthMethod, Msg1Payload, StartKind};

fn attachment(epoch: u64) -> Attachment {
    Attachment {
        locator: SessionLocator {
            session: RetainedSessionId::new([1; 16]).unwrap(),
            owner: OwnerInstance::new([2; 16]).unwrap(),
        },
        frontend: FrontendGeneration::new([3; 16]).unwrap(),
        epoch: AttachEpoch::new(epoch).unwrap(),
    }
}

#[test]
fn identities_reject_zero_and_counters_never_wrap() {
    assert!(RetainedSessionId::new([0; 16]).is_none());
    assert!(OwnerInstance::new([0; 16]).is_none());
    assert!(HostInstance::new([0; 16]).is_none());
    assert!(FrontendGeneration::new([0; 16]).is_none());
    assert!(InputEpoch::new([0; 16]).is_none());
    assert_eq!(
        RetainedSessionId::new([1; 16]).unwrap().as_bytes(),
        &[1; 16]
    );
    assert!(AttachEpoch::new(0).is_none());
    assert!(RequestId::new(0).is_none());
    assert!(AttachEpoch::new(u64::MAX).unwrap().checked_next().is_none());
    assert!(RequestId::new(u64::MAX).unwrap().checked_next().is_none());
    assert_eq!(
        AttachEpoch::new(1).unwrap().checked_next().unwrap().get(),
        2
    );
    assert_eq!(RequestId::new(1).unwrap().checked_next().unwrap().get(), 2);
}

#[test]
fn input_positions_distinguish_accepted_and_committed_and_reject_overflow() {
    let epoch = InputEpoch::new([4; 16]).unwrap();
    assert_eq!(
        InputPosition {
            epoch,
            accepted: 9,
            committed: 7
        }
        .validate(),
        Ok(())
    );
    assert_eq!(
        InputPosition {
            epoch,
            accepted: 7,
            committed: 9
        }
        .validate(),
        Err(ResumeError::Malformed)
    );
    assert_eq!(checked_end(u64::MAX, 1), Err(ResumeError::Overflow));
    assert_eq!(checked_end(u64::MAX - 1, 1), Ok(u64::MAX));
}

#[test]
fn inactive_reservation_leaves_legacy_handshake_bytes_unchanged() {
    let msg1 = encode_msg1(&Msg1Payload {
        start_kind: StartKind::Cold,
        token: [0x11; 16],
        method: AuthMethod::Allowlist,
        offered: Features::SUPPORTED,
    });
    let mut expected = vec![2, 0];
    expected.extend([0x11; 16]);
    expected.extend([0, 0, 0, 0, 0x3f]);
    assert_eq!(msg1, expected);
    let mut expected = vec![2, 0, 0, 0, 0, 0, 0, 0, 7, 0];
    expected.extend([0x22; 16]);
    expected.extend([0, 0, 0, 0x3f]);
    assert_eq!(
        encode_msg2(7, false, &[0x22; 16], Features::SUPPORTED),
        expected
    );
}

fn request() -> RequestId {
    RequestId::new(7).unwrap()
}
fn channel() -> ChannelInstance {
    ChannelInstance::new(9).unwrap()
}
fn controls() -> Vec<ResumeControl> {
    let a = attachment(5);
    vec![
        ResumeControl::Attach {
            request_id: request(),
            locator: a.locator,
            frontend: a.frontend,
            last_epoch: 0,
        },
        ResumeControl::Attached {
            request_id: request(),
            attachment: a,
        },
        ResumeControl::AttachRefused {
            request_id: request(),
            reason: AttachRefusal::AlreadyAttached,
        },
        ResumeControl::Detach {
            attachment: a,
            reason: DetachReason::TransportLost,
        },
        ResumeControl::Fence {
            request_id: request(),
            attachment: a,
        },
        ResumeControl::Fenced {
            request_id: request(),
            attachment: a,
        },
    ]
}
fn data_records() -> Vec<ResumeData> {
    let a = attachment(5);
    vec![
        ResumeData::Input {
            attachment: a,
            channel: channel(),
            epoch: InputEpoch::new([4; 16]).unwrap(),
            offset: 11,
            data: b"ok".to_vec(),
        },
        ResumeData::InputAck {
            attachment: a,
            channel: channel(),
            position: InputPosition {
                epoch: InputEpoch::new([4; 16]).unwrap(),
                accepted: 13,
                committed: 11,
            },
        },
        ResumeData::Output {
            attachment: a,
            channel: channel(),
            offset: 11,
            data: b"ok".to_vec(),
        },
        ResumeData::OutputAck {
            attachment: a,
            cursor: OutputCursor {
                channel: channel(),
                offset: 13,
            },
        },
    ]
}
fn raw(bytes: &[u8]) -> crate::shell_frame::RawRecord {
    let len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), 5 + len);
    crate::shell_frame::RawRecord {
        kind: bytes[0],
        payload: bytes[5..].to_vec(),
    }
}
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
// Literal fixture fields, independent of the codec under test.
const LOCATOR: &str = "0101010101010101010101010101010102020202020202020202020202020202";
const FRONTEND: &str = "03030303030303030303030303030303";
fn attachment_hex() -> String {
    format!("{LOCATOR}{FRONTEND}0000000000000005")
}

#[test]
fn all_control_kinds_match_frozen_wire_goldens_and_roundtrip() {
    let a = attachment_hex();
    let fixtures = [
        format!("30000000400000000000000007{LOCATOR}{FRONTEND}0000000000000000"),
        format!("31000000400000000000000007{a}"),
        "3200000009000000000000000703".to_owned(),
        format!("3300000039{a}01"),
        format!("34000000400000000000000007{a}"),
        format!("35000000400000000000000007{a}"),
    ];
    for (record, fixture) in controls().into_iter().zip(fixtures) {
        let bytes = encode_control(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(bytes, hex(&fixture));
        assert_eq!(
            decode_control(raw(&bytes), Features::SESSION_RESUME),
            Ok(record)
        );
    }
}

#[test]
fn all_data_kinds_match_frozen_wire_goldens_and_roundtrip() {
    let a = attachment_hex();
    let fixtures = [
        format!("400000005e{a}000000000000000904040404040404040404040404040404000000000000000b000000026f6b"),
        format!("4100000060{a}000000000000000904040404040404040404040404040404000000000000000d000000000000000b"),
        format!("420000004e{a}0000000000000009000000000000000b000000026f6b"),
        format!("4300000048{a}0000000000000009000000000000000d"),
    ];
    for (record, fixture) in data_records().into_iter().zip(fixtures) {
        let bytes = encode_data(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(bytes, hex(&fixture));
        assert_eq!(
            decode_data(raw(&bytes), Features::SESSION_RESUME),
            Ok(record)
        );
    }
}

#[test]
fn resume_codecs_require_explicit_feature_and_do_not_reinterpret_legacy_records() {
    for record in controls() {
        assert_eq!(
            encode_control(&record, Features::SUPPORTED),
            Err(ResumeError::FeatureRequired)
        );
        let bytes = encode_control(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(
            decode_control(raw(&bytes), Features::NONE),
            Err(ResumeError::FeatureRequired)
        );
    }
    for record in data_records() {
        assert_eq!(
            encode_data(&record, Features::NONE),
            Err(ResumeError::FeatureRequired)
        );
        let bytes = encode_data(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(
            decode_data(raw(&bytes), Features::NONE),
            Err(ResumeError::FeatureRequired)
        );
        assert_eq!(
            decode_control(raw(&bytes), Features::SESSION_RESUME),
            Err(ResumeError::UnknownKind(bytes[0]))
        );
    }
    let output =
        crate::shell_frame::encode_shell(&crate::shell_frame::ShellRecord::Data(b"ok".to_vec()))
            .unwrap();
    assert_eq!(output, [0, 0, 0, 0, 2, b'o', b'k']);
    assert_eq!(
        decode_data(raw(&output), Features::SESSION_RESUME),
        Err(ResumeError::UnknownKind(0))
    );
    let open = crate::channel::encode_client(&crate::channel::ClientRecord::Open(
        crate::channel::OpenRequest {
            stream: 16,
            kind: crate::channel::ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: true,
            command: Vec::new(),
        },
    ));
    assert_eq!(open, [0x10, 0, 0, 0, 9, 16, 0, 0, 80, 0, 24, 1, 0, 0]);
    assert_eq!(
        decode_control(raw(&open), Features::SESSION_RESUME),
        Err(ResumeError::UnknownKind(0x10))
    );
}

#[test]
fn known_records_reject_every_truncation_and_trailing_bytes() {
    for bytes in controls()
        .iter()
        .map(|r| encode_control(r, Features::SESSION_RESUME).unwrap())
    {
        let r = raw(&bytes);
        for end in 0..r.payload.len() {
            assert_eq!(
                decode_control(
                    crate::shell_frame::RawRecord {
                        kind: r.kind,
                        payload: r.payload[..end].to_vec()
                    },
                    Features::SESSION_RESUME
                ),
                Err(ResumeError::Malformed)
            );
        }
        let mut r = r;
        r.payload.push(0);
        assert_eq!(
            decode_control(r, Features::SESSION_RESUME),
            Err(ResumeError::Malformed)
        );
    }
    for bytes in data_records()
        .iter()
        .map(|r| encode_data(r, Features::SESSION_RESUME).unwrap())
    {
        let r = raw(&bytes);
        for end in 0..r.payload.len() {
            assert_eq!(
                decode_data(
                    crate::shell_frame::RawRecord {
                        kind: r.kind,
                        payload: r.payload[..end].to_vec()
                    },
                    Features::SESSION_RESUME
                ),
                Err(ResumeError::Malformed)
            );
        }
        let mut r = r;
        r.payload.push(0);
        assert_eq!(
            decode_data(r, Features::SESSION_RESUME),
            Err(ResumeError::Malformed)
        );
    }
}

#[test]
fn invalid_id_enum_and_position_fields_fail_closed() {
    for index in [0, 8, 24, 40, 56] {
        let mut r = raw(&encode_control(&controls()[1], Features::SESSION_RESUME).unwrap());
        let len = if index == 0 || index == 56 { 8 } else { 16 };
        r.payload[index..index + len].fill(0);
        assert_eq!(
            decode_control(r, Features::SESSION_RESUME),
            Err(ResumeError::Malformed)
        );
    }
    for index in [2, 3] {
        let mut r = raw(&encode_control(&controls()[index], Features::SESSION_RESUME).unwrap());
        *r.payload.last_mut().unwrap() = 255;
        assert_eq!(
            decode_control(r, Features::SESSION_RESUME),
            Err(ResumeError::Malformed)
        );
    }
    let bad = ResumeData::InputAck {
        attachment: attachment(5),
        channel: channel(),
        position: InputPosition {
            epoch: InputEpoch::new([4; 16]).unwrap(),
            accepted: 1,
            committed: 2,
        },
    };
    assert_eq!(
        encode_data(&bad, Features::SESSION_RESUME),
        Err(ResumeError::Malformed)
    );
    let mut r = raw(&encode_data(&data_records()[1], Features::SESSION_RESUME).unwrap());
    r.payload[88..96].copy_from_slice(&14_u64.to_be_bytes());
    assert_eq!(
        decode_data(r, Features::SESSION_RESUME),
        Err(ResumeError::Malformed)
    );
}

#[test]
fn data_limits_and_offset_overflow_are_checked_on_both_boundaries() {
    for kind in [0, 2] {
        let mut record = data_records().remove(kind);
        if let ResumeData::Input { data, .. } | ResumeData::Output { data, .. } = &mut record {
            *data = vec![1; 16384];
        }
        let bytes = encode_data(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(
            decode_data(raw(&bytes), Features::SESSION_RESUME),
            Ok(record.clone())
        );
        if let ResumeData::Input { data, .. } | ResumeData::Output { data, .. } = &mut record {
            data.push(1);
        }
        assert_eq!(
            encode_data(&record, Features::SESSION_RESUME),
            Err(ResumeError::TooLarge)
        );
        let mut r = raw(&bytes);
        let length_index = if kind == 0 { 88 } else { 72 };
        r.payload[length_index..length_index + 4].copy_from_slice(&16385_u32.to_be_bytes());
        r.payload.push(1);
        assert_eq!(
            decode_data(r, Features::SESSION_RESUME),
            Err(ResumeError::TooLarge)
        );
        if let ResumeData::Input { data, offset, .. } | ResumeData::Output { data, offset, .. } =
            &mut record
        {
            *data = vec![1];
            *offset = u64::MAX;
        }
        assert_eq!(
            encode_data(&record, Features::SESSION_RESUME),
            Err(ResumeError::Overflow)
        );
        let mut r = raw(&encode_data(&data_records()[kind], Features::SESSION_RESUME).unwrap());
        let offset_index = if kind == 0 { 80 } else { 64 };
        r.payload[offset_index..offset_index + 8].fill(255);
        assert_eq!(
            decode_data(r, Features::SESSION_RESUME),
            Err(ResumeError::Overflow)
        );
    }
    assert_eq!(
        decode_data(
            crate::shell_frame::RawRecord {
                kind: 0x40,
                payload: vec![0; 65537]
            },
            Features::SESSION_RESUME
        ),
        Err(ResumeError::TooLarge)
    );
    let mut parser = crate::shell_frame::RecordDeframer::with_max_payload(65536);
    assert!(parser.push(&[0x40, 0xff, 0xff, 0xff, 0xff]).is_empty());
    assert!(parser.overflowed());
}

#[test]
fn attached_requires_explicit_recovery_and_fence_revokes_all_mutating_operations() {
    let a = attachment(5);
    let mut state = AttachmentState::new();
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    state.begin_attach(a).unwrap();
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    state.attached(a).unwrap();
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    state.mark_recovery_complete(a).unwrap();
    assert_eq!(state.validate_input(a), Ok(()));
    assert_eq!(state.validate_resize(a), Ok(()));
    assert_eq!(state.validate_close(a), Ok(()));
    state.begin_fence(a).unwrap();
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    assert_eq!(state.validate_resize(a), Err(ResumeError::InvalidState));
    assert_eq!(state.validate_close(a), Err(ResumeError::InvalidState));
    state.fenced(a).unwrap();
    assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
    state.begin_attach(attachment(6)).unwrap();
    state.attached(attachment(6)).unwrap();
    assert_eq!(
        state.validate_input(attachment(6)),
        Err(ResumeError::InvalidState)
    );
}

#[test]
fn attachment_transitions_bind_every_identity_and_reject_duplicate_acknowledgements() {
    let a = attachment(5);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    let mut impostors = vec![attachment(4), attachment(6)];
    let mut other = a;
    other.locator.owner = OwnerInstance::new([8; 16]).unwrap();
    impostors.push(other);
    let mut other = a;
    other.locator.session = RetainedSessionId::new([8; 16]).unwrap();
    impostors.push(other);
    let mut other = a;
    other.frontend = FrontendGeneration::new([8; 16]).unwrap();
    impostors.push(other);
    for wrong in impostors {
        assert_eq!(state.attached(wrong), Err(ResumeError::StaleAttachment));
    }
    state.attached(a).unwrap();
    assert_eq!(state.attached(a), Err(ResumeError::InvalidState));
    state.mark_recovery_complete(a).unwrap();
    state.detach(a, DetachReason::TransportLost).unwrap();
    assert_eq!(state.validate_close(a), Err(ResumeError::InvalidState));
    assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
    state.begin_attach(attachment(6)).unwrap();
    assert_eq!(state.fenced(a), Err(ResumeError::StaleAttachment));
    state.attached(attachment(6)).unwrap();
}

#[test]
fn data_identifiers_and_cross_kind_payloads_cannot_alias_a_channel() {
    for index in [0, 16, 32, 48, 56, 64] {
        let mut r = raw(&encode_data(&data_records()[0], Features::SESSION_RESUME).unwrap());
        let len = if index == 48 || index == 56 { 8 } else { 16 };
        r.payload[index..index + len].fill(0);
        assert_eq!(
            decode_data(r, Features::SESSION_RESUME),
            Err(ResumeError::Malformed)
        );
    }
    for (index, wrong_kind) in [(0, 0x42), (1, 0x43), (2, 0x40), (3, 0x41)] {
        let mut r = raw(&encode_data(&data_records()[index], Features::SESSION_RESUME).unwrap());
        r.kind = wrong_kind;
        assert!(decode_data(r, Features::SESSION_RESUME).is_err());
    }
}

#[test]
fn exhausted_attachment_epoch_cannot_be_reused_after_detach() {
    let a = attachment(u64::MAX);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    state.attached(a).unwrap();
    state.detach(a, DetachReason::ClientUpdate).unwrap();
    assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
    assert_eq!(
        state.begin_attach(attachment(1)),
        Err(ResumeError::StaleAttachment)
    );
    assert_eq!(state.phase(), AttachmentPhase::Detached);
}

#[test]
fn distinct_detach_and_close_reason_codes_have_strict_wire_domains() {
    for (code, reason) in [
        (1, DetachReason::TransportLost),
        (2, DetachReason::FrontendReplacement),
        (3, DetachReason::ClientUpdate),
    ] {
        let record = ResumeControl::Detach {
            attachment: attachment(5),
            reason,
        };
        let bytes = encode_control(&record, Features::SESSION_RESUME).unwrap();
        assert_eq!(bytes.last(), Some(&code));
        assert_eq!(
            decode_control(raw(&bytes), Features::SESSION_RESUME),
            Ok(record)
        );
    }
    for (code, reason) in [
        (1, CloseReason::ExplicitClient),
        (2, CloseReason::Administrator),
        (3, CloseReason::OwnerFailure),
    ] {
        assert_eq!(CloseReason::from_wire(code), Some(reason));
        assert_eq!(reason.to_wire(), code);
    }
    assert_eq!(CloseReason::from_wire(0), None);
    assert_eq!(DetachReason::from_wire(4), None);
}

#[test]
fn abandonment_during_attaching_revokes_pending_epoch_without_fabricating_attached() {
    let a = attachment(5);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    let mut wrong = a;
    wrong.frontend = FrontendGeneration::new([9; 16]).unwrap();
    assert_eq!(state.abandon(wrong), Err(ResumeError::StaleAttachment));
    assert_eq!(state.phase(), AttachmentPhase::Attaching);
    state.abandon(a).unwrap();
    assert_eq!(state.phase(), AttachmentPhase::Detached);
    assert_eq!(state.attached(a), Err(ResumeError::InvalidState));
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
    let mut next = attachment(6);
    next.frontend = FrontendGeneration::new([8; 16]).unwrap();
    state.begin_attach(next).unwrap();
    assert_eq!(state.abandon(a), Err(ResumeError::StaleAttachment));
    assert_eq!(state.attached(a), Err(ResumeError::StaleAttachment));
    assert_eq!(state.phase(), AttachmentPhase::Attaching);
    state.attached(next).unwrap();
    assert_eq!(state.validate_input(next), Err(ResumeError::InvalidState));
    state.mark_recovery_complete(next).unwrap();
    assert_eq!(state.validate_input(next), Ok(()));
    assert_eq!(state.abandon(a), Err(ResumeError::StaleAttachment));
    assert_eq!(state.validate_input(next), Ok(()));
}

#[test]
fn abandonment_during_fencing_revokes_epoch_without_fabricating_fenced_receipt() {
    let a = attachment(5);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    state.attached(a).unwrap();
    state.mark_recovery_complete(a).unwrap();
    state.begin_fence(a).unwrap();
    for wrong in [attachment(4), attachment(6)] {
        assert_eq!(state.abandon(wrong), Err(ResumeError::StaleAttachment));
        assert_eq!(state.phase(), AttachmentPhase::Fencing);
    }
    state.abandon(a).unwrap();
    assert_eq!(state.phase(), AttachmentPhase::Detached);
    assert_eq!(state.fenced(a), Err(ResumeError::InvalidState));
    assert_eq!(state.validate_input(a), Err(ResumeError::InvalidState));
    assert_eq!(state.validate_close(a), Err(ResumeError::InvalidState));
    assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
    let next = attachment(6);
    state.begin_attach(next).unwrap();
    assert_eq!(state.fenced(a), Err(ResumeError::StaleAttachment));
    assert_eq!(state.abandon(a), Err(ResumeError::StaleAttachment));
    state.attached(next).unwrap();
    assert_eq!(state.validate_input(next), Err(ResumeError::InvalidState));
    state.mark_recovery_complete(next).unwrap();
    assert_eq!(state.validate_input(next), Ok(()));
    assert_eq!(state.abandon(a), Err(ResumeError::StaleAttachment));
    assert_eq!(state.validate_input(next), Ok(()));
}

#[test]
fn abandonment_handles_cancelled_attach_and_attached_before_recovery() {
    for attached in [false, true] {
        let a = attachment(5);
        let mut state = AttachmentState::new();
        assert_eq!(state.abandon(a), Err(ResumeError::InvalidState));
        state.begin_attach(a).unwrap();
        if attached {
            state.attached(a).unwrap();
        }
        let phase = state.phase();
        let mut foreign_owner = a;
        foreign_owner.locator.owner = OwnerInstance::new([9; 16]).unwrap();
        let mut foreign_session = a;
        foreign_session.locator.session = RetainedSessionId::new([9; 16]).unwrap();
        let mut foreign_frontend = a;
        foreign_frontend.frontend = FrontendGeneration::new([9; 16]).unwrap();
        for wrong in [
            foreign_owner,
            foreign_session,
            foreign_frontend,
            attachment(u64::MAX),
        ] {
            assert_eq!(state.abandon(wrong), Err(ResumeError::StaleAttachment));
            assert_eq!(state.phase(), phase);
        }
        // A refused/cancelled pending attach and a peer lost before recovery
        // both have a local abandonment path without a remote success receipt.
        state.abandon(a).unwrap();
        assert_eq!(state.abandon(a), Err(ResumeError::InvalidState));
        assert_eq!(
            state.begin_attach(attachment(4)),
            Err(ResumeError::StaleAttachment)
        );
        assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
        let next = attachment(6);
        state.begin_attach(next).unwrap();
        state.attached(next).unwrap();
        assert_eq!(state.validate_input(next), Err(ResumeError::InvalidState));
        assert_eq!(state.validate_resize(next), Err(ResumeError::InvalidState));
        assert_eq!(state.validate_close(next), Err(ResumeError::InvalidState));
        assert_eq!(state.abandon(a), Err(ResumeError::StaleAttachment));
        state.mark_recovery_complete(next).unwrap();
        assert_eq!(state.validate_input(next), Ok(()));
    }
}

#[test]
fn abandonment_never_wraps_epoch_or_reopens_a_completed_fence() {
    for phase in [
        AttachmentPhase::Attaching,
        AttachmentPhase::Attached,
        AttachmentPhase::Fencing,
    ] {
        let a = attachment(u64::MAX);
        let mut state = AttachmentState::new();
        state.begin_attach(a).unwrap();
        if phase != AttachmentPhase::Attaching {
            state.attached(a).unwrap();
        }
        if phase == AttachmentPhase::Fencing {
            state.begin_fence(a).unwrap();
        }
        state.abandon(a).unwrap();
        assert_eq!(
            state.begin_attach(attachment(1)),
            Err(ResumeError::StaleAttachment)
        );
        assert_eq!(state.begin_attach(a), Err(ResumeError::StaleAttachment));
        assert_eq!(state.abandon(a), Err(ResumeError::InvalidState));
    }
    let a = attachment(5);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    state.attached(a).unwrap();
    state.begin_fence(a).unwrap();
    state.fenced(a).unwrap();
    assert_eq!(state.abandon(a), Err(ResumeError::InvalidState));
    assert_eq!(state.phase(), AttachmentPhase::Fenced);
    state.begin_attach(attachment(6)).unwrap();
}

#[test]
fn runtime_recovery_invalidation_revokes_same_attached_lease_until_new_gate() {
    let a = attachment(1);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    state.attached(a).unwrap();
    let catalog = RetainedCatalog::new(
        a,
        crate::channel::ChannelSnapshot::new(Vec::new(), Vec::new()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    RecoveryGate::new(&catalog)
        .enable_input(&mut state)
        .unwrap();
    assert!(state.validate_input(a).is_ok());
    let identity = (state.current, state.phase, state.revoked);
    state.invalidate_recovery(a).unwrap();
    assert!(
        state.validate_input(a).is_err(),
        "catalog invalidation left canonical input authority enabled"
    );
    assert!(state.validate_resize(a).is_err());
    assert!(state.validate_close(a).is_err());
    state.invalidate_recovery(a).unwrap();
    assert_eq!((state.current, state.phase, state.revoked), identity);
    RecoveryGate::new(&catalog)
        .enable_input(&mut state)
        .unwrap();
    assert!(state.validate_input(a).is_ok());
    assert!(RecoveryGate::new(&catalog)
        .enable_input(&mut state)
        .is_err());
}
#[test]
fn runtime_recovery_invalidation_rejects_stale_identity_and_all_other_phases_without_mutation() {
    for phase in 0..5 {
        let a = attachment(1);
        let mut state = AttachmentState::new();
        if phase > 0 {
            state.begin_attach(a).unwrap();
        }
        if phase > 1 {
            state.attached(a).unwrap();
            state.mark_recovery_complete(a).unwrap();
        }
        if phase > 2 {
            state.begin_fence(a).unwrap();
        }
        if phase > 3 {
            state.fenced(a).unwrap();
        }
        let before = (state.current, state.phase, state.revoked, state.recovered);
        let request = if phase == 2 { attachment(2) } else { a };
        assert!(state.invalidate_recovery(request).is_err());
        assert_eq!(
            (state.current, state.phase, state.revoked, state.recovered),
            before
        );
    }
}
