use super::protocol::*;
use transport::session_resume::*;

fn host() -> HostInstance {
    HostInstance::new([1; 16]).unwrap()
}
fn owner() -> OwnerInstance {
    OwnerInstance::new([2; 16]).unwrap()
}
fn attachment() -> Attachment {
    Attachment {
        locator: SessionLocator {
            session: RetainedSessionId::new([3; 16]).unwrap(),
            owner: owner(),
        },
        frontend: FrontendGeneration::new([4; 16]).unwrap(),
        epoch: AttachEpoch::new(5).unwrap(),
    }
}
fn frame(role: OwnerRole, id: u64, message: OwnerMessage) -> OwnerFrame {
    OwnerFrame {
        header: OwnerHeader {
            role,
            host: host(),
            owner: owner(),
            request_id: id,
        },
        message,
    }
}
fn hello(role: OwnerRole, id: u64) -> OwnerFrame {
    frame(
        role,
        id,
        OwnerMessage::Hello {
            min_version: 1,
            max_version: 1,
        },
    )
}
fn ack(role: OwnerRole, id: u64) -> OwnerFrame {
    frame(
        role,
        id,
        OwnerMessage::HelloAck {
            selected_version: 1,
        },
    )
}
fn attach(role: OwnerRole, id: u64) -> OwnerFrame {
    let a = attachment();
    frame(
        role,
        id,
        OwnerMessage::Control(ResumeControl::Attach {
            request_id: RequestId::new(id).unwrap(),
            locator: a.locator,
            frontend: a.frontend,
            last_epoch: 0,
        }),
    )
}
fn attached(role: OwnerRole, id: u64) -> OwnerFrame {
    frame(
        role,
        id,
        OwnerMessage::Control(ResumeControl::Attached {
            request_id: RequestId::new(id).unwrap(),
            attachment: attachment(),
        }),
    )
}
fn peer() -> PeerState {
    let mut p = PeerState::new(OwnerRole::Frontend, OwnerRole::Owner, host(), owner());
    p.send(&hello(OwnerRole::Frontend, 1)).unwrap();
    p.receive(&ack(OwnerRole::Owner, 1)).unwrap();
    p
}

#[test]
fn owner_header_golden_and_each_byte_split_and_coalesced_frames_roundtrip() {
    let first = hello(OwnerRole::Frontend, 7);
    let bytes = encode(&first).unwrap();
    let mut expected = b"QSHO\0\x01\x02\x01\0\0\0\x04".to_vec();
    expected.extend([1; 16]);
    expected.extend([2; 16]);
    expected.extend(7_u64.to_be_bytes());
    expected.extend([0, 1, 0, 1]);
    assert_eq!(bytes, expected);
    for split in 0..=bytes.len() {
        let mut decoder = OwnerDecoder::new();
        let mut frames = decoder.push(&bytes[..split]).unwrap();
        frames.extend(decoder.push(&bytes[split..]).unwrap());
        decoder.finish().unwrap();
        assert_eq!(frames.as_slice(), std::slice::from_ref(&first));
    }
    let mut decoder = OwnerDecoder::new();
    let mut frames = Vec::new();
    for b in &bytes {
        frames.extend(decoder.push(&[*b]).unwrap());
    }
    assert_eq!(frames.as_slice(), std::slice::from_ref(&first));
    decoder.finish().unwrap();
    let mut combined = bytes.clone();
    combined.extend(encode(&ack(OwnerRole::Owner, 7)).unwrap());
    assert_eq!(
        OwnerDecoder::new().push(&combined).unwrap(),
        [first, ack(OwnerRole::Owner, 7)]
    );
}

#[test]
fn owner_embeds_exact_transport_payloads_and_binds_request_and_owner() {
    let a = attachment();
    let controls = [
        ResumeControl::Attach {
            request_id: RequestId::new(7).unwrap(),
            locator: a.locator,
            frontend: a.frontend,
            last_epoch: 0,
        },
        ResumeControl::Attached {
            request_id: RequestId::new(7).unwrap(),
            attachment: a,
        },
        ResumeControl::AttachRefused {
            request_id: RequestId::new(7).unwrap(),
            reason: AttachRefusal::Missing,
        },
        ResumeControl::Detach {
            attachment: a,
            reason: DetachReason::ClientUpdate,
        },
        ResumeControl::Fence {
            request_id: RequestId::new(7).unwrap(),
            attachment: a,
        },
        ResumeControl::Fenced {
            request_id: RequestId::new(7).unwrap(),
            attachment: a,
        },
    ];
    for message in controls {
        let id = message.request_id().map_or(0, RequestId::get);
        let external = encode_control(&message, transport::Features::SESSION_RESUME).unwrap();
        let f = frame(OwnerRole::Frontend, id, OwnerMessage::Control(message));
        let bytes = encode(&f).unwrap();
        assert_eq!(bytes[7], external[0]);
        assert_eq!(&bytes[52..], &external[5..]);
        assert_eq!(OwnerDecoder::new().push(&bytes).unwrap(), [f]);
    }
    let mut bad = attach(OwnerRole::Frontend, 7);
    bad.header.request_id = 8;
    assert_eq!(encode(&bad), Err(OwnerProtocolError::Binding));
    bad.header.request_id = 7;
    bad.header.owner = OwnerInstance::new([9; 16]).unwrap();
    assert_eq!(encode(&bad), Err(OwnerProtocolError::Binding));
    let mut wire = encode(&attach(OwnerRole::Frontend, 7)).unwrap();
    wire[51] = 8;
    assert_eq!(
        OwnerDecoder::new().push(&wire),
        Err(OwnerProtocolError::Binding)
    );
}

#[test]
fn owner_data_events_use_zero_request_ids_and_enforce_chunk_limit() {
    let a = attachment();
    let channel = transport::channel_geometry::ChannelInstance::new(9).unwrap();
    let records = [
        ResumeData::Input {
            attachment: a,
            channel,
            epoch: InputEpoch::new([6; 16]).unwrap(),
            offset: 0,
            data: vec![7; 16384],
        },
        ResumeData::InputAck {
            attachment: a,
            channel,
            position: InputPosition {
                epoch: InputEpoch::new([6; 16]).unwrap(),
                accepted: 4,
                committed: 2,
            },
        },
        ResumeData::Output {
            attachment: a,
            channel,
            offset: 0,
            data: vec![8; 16384],
        },
        ResumeData::OutputAck {
            attachment: a,
            cursor: OutputCursor { channel, offset: 4 },
        },
    ];
    let mut p = peer();
    for record in records {
        let external = encode_data(&record, transport::Features::SESSION_RESUME).unwrap();
        let f = frame(OwnerRole::Owner, 0, OwnerMessage::Data(record.clone()));
        let bytes = encode(&f).unwrap();
        assert_eq!(&bytes[52..], &external[5..]);
        assert_eq!(
            OwnerDecoder::new().push(&bytes).unwrap().as_slice(),
            std::slice::from_ref(&f)
        );
        p.receive(&f).unwrap();
        assert_eq!(p.outstanding(), 0);
        assert_eq!(
            encode(&frame(OwnerRole::Owner, 1, OwnerMessage::Data(record))),
            Err(OwnerProtocolError::Binding)
        );
    }
    let too_big = ResumeData::Output {
        attachment: a,
        channel,
        offset: 0,
        data: vec![8; 16385],
    };
    assert_eq!(
        encode(&frame(OwnerRole::Owner, 0, OwnerMessage::Data(too_big))),
        Err(OwnerProtocolError::TooLarge)
    );
}

#[test]
fn owner_hostile_headers_fail_before_body_allocation_and_stay_failed() {
    let bytes = encode(&hello(OwnerRole::Frontend, 1)).unwrap();
    let mut cases = Vec::new();
    let mut wrong = bytes[..52].to_vec();
    wrong[0] = b'X';
    cases.push((wrong, OwnerProtocolError::Malformed));
    let mut wrong = bytes[..52].to_vec();
    wrong[5] = 2;
    cases.push((wrong, OwnerProtocolError::UnsupportedVersion));
    let mut wrong = bytes[..52].to_vec();
    wrong[6] = 9;
    cases.push((wrong, OwnerProtocolError::Malformed));
    let mut wrong = bytes[..52].to_vec();
    wrong[7] = 255;
    cases.push((wrong, OwnerProtocolError::UnknownKind(255)));
    let mut wrong = bytes[..52].to_vec();
    wrong[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push((wrong, OwnerProtocolError::TooLarge));
    let mut wrong = bytes[..52].to_vec();
    wrong[8..12].copy_from_slice(&65485_u32.to_be_bytes());
    cases.push((wrong, OwnerProtocolError::TooLarge));
    let mut wrong = bytes[..52].to_vec();
    wrong[12..28].fill(0);
    cases.push((wrong, OwnerProtocolError::Malformed));
    let mut wrong = bytes[..52].to_vec();
    wrong[28..44].fill(0);
    cases.push((wrong, OwnerProtocolError::Malformed));
    let mut wrong = bytes[..52].to_vec();
    wrong[44..52].fill(0);
    cases.push((wrong, OwnerProtocolError::Binding));
    for (header, error) in cases {
        let mut d = OwnerDecoder::new();
        assert_eq!(d.push(&header), Err(error));
        assert!(d.buffered_len() <= 52);
        assert!(d.buffer_capacity() <= 52);
        assert_eq!(d.push(&bytes), Err(error));
    }
    let mut maximum = bytes[..52].to_vec();
    maximum[8..12].copy_from_slice(&65484_u32.to_be_bytes());
    // The frame envelope fits, but the Hello kind has an exact four-byte body.
    assert_eq!(
        OwnerDecoder::new().push(&maximum),
        Err(OwnerProtocolError::Malformed)
    );
}

#[test]
fn owner_eof_rejects_every_truncated_frame_and_hello_range_is_strict() {
    let bytes = encode(&hello(OwnerRole::Frontend, 1)).unwrap();
    for end in 1..bytes.len() {
        let mut d = OwnerDecoder::new();
        d.push(&bytes[..end]).unwrap();
        assert_eq!(d.finish(), Err(OwnerProtocolError::Truncated));
    }
    OwnerDecoder::new().finish().unwrap();
    for (min_version, max_version) in [(0, 0), (2, 3), (2, 1)] {
        assert_eq!(
            encode(&frame(
                OwnerRole::Frontend,
                1,
                OwnerMessage::Hello {
                    min_version,
                    max_version
                }
            )),
            Err(OwnerProtocolError::UnsupportedVersion)
        );
    }
    assert_eq!(
        encode(&frame(
            OwnerRole::Owner,
            1,
            OwnerMessage::HelloAck {
                selected_version: 2
            }
        )),
        Err(OwnerProtocolError::UnsupportedVersion)
    );
    let mut bad = bytes;
    bad[54..56].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(
        OwnerDecoder::new().push(&bad),
        Err(OwnerProtocolError::UnsupportedVersion)
    );
}

#[test]
fn peer_requires_hello_and_rejects_wrong_roles_instances_and_duplicate_handshakes_without_mutation()
{
    let mut p = PeerState::new(OwnerRole::Frontend, OwnerRole::Owner, host(), owner());
    let before = p.clone();
    assert_eq!(
        p.send(&attach(OwnerRole::Frontend, 1)),
        Err(OwnerProtocolError::InvalidState)
    );
    assert_eq!(p, before);
    assert_eq!(
        p.receive(&attached(OwnerRole::Owner, 1)),
        Err(OwnerProtocolError::InvalidState)
    );
    assert_eq!(p, before);
    p.receive(&hello(OwnerRole::Owner, 1)).unwrap();
    p.send(&ack(OwnerRole::Frontend, 1)).unwrap();
    for wrong in [hello(OwnerRole::Owner, 2), hello(OwnerRole::Host, 2)] {
        let before = p.clone();
        assert!(p.receive(&wrong).is_err());
        assert_eq!(p, before);
    }
    let mut f = attach(OwnerRole::Owner, 2);
    f.header.host = HostInstance::new([9; 16]).unwrap();
    let before = p.clone();
    assert_eq!(p.receive(&f), Err(OwnerProtocolError::Binding));
    assert_eq!(p, before);
    let mut f = attach(OwnerRole::Owner, 2);
    f.header.owner = OwnerInstance::new([9; 16]).unwrap();
    let before = p.clone();
    assert_eq!(p.receive(&f), Err(OwnerProtocolError::Binding));
    assert_eq!(p, before);
}

#[test]
fn peer_bounds_requests_rejects_reuse_and_matches_exact_reply_kind() {
    let mut p = peer();
    for id in 2..=65 {
        p.send(&attach(OwnerRole::Frontend, id)).unwrap();
    }
    assert_eq!(p.outstanding(), 64);
    let before = p.clone();
    assert_eq!(
        p.send(&attach(OwnerRole::Frontend, 66)),
        Err(OwnerProtocolError::RequestLimit)
    );
    assert_eq!(p, before);
    let wrong = frame(
        OwnerRole::Owner,
        2,
        OwnerMessage::Control(ResumeControl::Fenced {
            request_id: RequestId::new(2).unwrap(),
            attachment: attachment(),
        }),
    );
    assert_eq!(p.receive(&wrong), Err(OwnerProtocolError::UnexpectedReply));
    assert_eq!(p, before);
    p.receive(&attached(OwnerRole::Owner, 2)).unwrap();
    assert_eq!(p.outstanding(), 63);
    let before = p.clone();
    assert_eq!(
        p.receive(&attached(OwnerRole::Owner, 2)),
        Err(OwnerProtocolError::UnexpectedReply)
    );
    assert_eq!(p, before);
    assert_eq!(
        p.send(&attach(OwnerRole::Frontend, 2)),
        Err(OwnerProtocolError::ReusedRequest)
    );
    assert_eq!(p, before);
    p.send(&attach(OwnerRole::Frontend, 66)).unwrap();
}

#[test]
fn peer_incoming_request_ids_are_independent_monotonic_and_bounded() {
    let mut p = peer();
    for id in 1..=64 {
        p.receive(&attach(OwnerRole::Owner, id)).unwrap();
    }
    assert_eq!(p.incoming(), 64);
    let before = p.clone();
    assert_eq!(
        p.receive(&attach(OwnerRole::Owner, 65)),
        Err(OwnerProtocolError::RequestLimit)
    );
    assert_eq!(p, before);
    assert_eq!(
        p.receive(&attach(OwnerRole::Owner, 64)),
        Err(OwnerProtocolError::ReusedRequest)
    );
    assert_eq!(p, before);
    p.send(&attached(OwnerRole::Frontend, 1)).unwrap();
    p.receive(&attach(OwnerRole::Owner, 65)).unwrap();
    let before = p.clone();
    assert_eq!(
        p.send(&attached(OwnerRole::Frontend, 1)),
        Err(OwnerProtocolError::UnexpectedReply)
    );
    assert_eq!(p, before);
}

#[test]
fn peer_counters_do_not_wrap_and_cross_peer_replies_never_complete_requests() {
    let mut p = peer();
    p.send(&attach(OwnerRole::Frontend, u64::MAX)).unwrap();
    assert_eq!(p.next_request_id(), Err(OwnerProtocolError::Exhausted));
    let mut wrong = attached(OwnerRole::Owner, u64::MAX);
    wrong.header.host = HostInstance::new([9; 16]).unwrap();
    let before = p.clone();
    assert_eq!(p.receive(&wrong), Err(OwnerProtocolError::Binding));
    assert_eq!(p, before);
    p.receive(&attached(OwnerRole::Owner, u64::MAX)).unwrap();
    assert_eq!(p.next_request_id(), Err(OwnerProtocolError::Exhausted));
}
