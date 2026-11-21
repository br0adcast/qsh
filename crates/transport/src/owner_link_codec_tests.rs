use super::codec::*;

fn ctx() -> Ctx {
    Ctx {
        generation: 7,
        session_id: 0x0102_0304_0506_0708,
        features: 0xdead_beef,
    }
}

fn geometry() -> GeometryWire {
    GeometryWire {
        instance: 11,
        request_id: 9,
        outcome: GeometryOutcomeWire::Refused(3),
        cols: 80,
        rows: 24,
    }
}

fn gate() -> GateWire {
    GateWire { id: 21, kind: 1 }
}

fn open() -> OpenWire {
    OpenWire {
        kind: 2,
        cols: 100,
        rows: 40,
        screen: true,
    }
}

fn all_records() -> Vec<OutRecord> {
    vec![
        OutRecord::RetirementReady {
            origin: ctx(),
            decisions_complete: true,
        },
        OutRecord::ReservedControl {
            id: 1,
            origin: ctx(),
            bytes: vec![1, 2, 3],
            charge: Some(gate()),
        },
        OutRecord::UpdateAccept {
            id: 2,
            origin: ctx(),
            bytes: vec![4],
            charge: None,
        },
        OutRecord::ReservedSessionControl {
            id: 3,
            bytes: vec![],
            charge: Some(gate()),
        },
        OutRecord::ResourceExhausted { origin: ctx() },
        OutRecord::CloseSession { origin: ctx() },
        OutRecord::RepaintBarrier {
            id: 4,
            generation: 5,
            sequence: 6,
        },
        OutRecord::ChannelClosed {
            id: 5,
            stream: 9,
            instance: 11,
            origin: ctx(),
        },
        OutRecord::ChannelOutput {
            id: 6,
            stream: 9,
            instance: 11,
            origin: ctx(),
            output: OutputBody::Data(vec![0xaa; 100]),
            gate: gate(),
            gap_reserve: true,
        },
        OutRecord::ChannelOutput {
            id: 7,
            stream: 9,
            instance: 11,
            origin: ctx(),
            output: OutputBody::Geometry(geometry()),
            gate: gate(),
            gap_reserve: false,
        },
        OutRecord::ChannelOutput {
            id: 8,
            stream: 9,
            instance: 11,
            origin: ctx(),
            output: OutputBody::EchoAck(77),
            gate: gate(),
            gap_reserve: false,
        },
        OutRecord::ChannelOutput {
            id: 9,
            stream: 9,
            instance: 11,
            origin: ctx(),
            output: OutputBody::OutputGap(2),
            gate: gate(),
            gap_reserve: false,
        },
        OutRecord::ChannelOutput {
            id: 10,
            stream: 9,
            instance: 11,
            origin: ctx(),
            output: OutputBody::DeliveryMarker { token: 55 },
            gate: gate(),
            gap_reserve: false,
        },
        OutRecord::ChannelExit {
            id: 11,
            stream: 9,
            instance: 11,
            origin: ctx(),
            code: Some(-1),
            open: open(),
            control_bytes: 10,
            charge: Some(gate()),
        },
        OutRecord::ChannelExit {
            id: 12,
            stream: 9,
            instance: 11,
            origin: ctx(),
            code: None,
            open: open(),
            control_bytes: 6,
            charge: None,
        },
        OutRecord::ProtocolFailure {
            origin: ctx(),
            code: Some(1),
        },
        OutRecord::ProtocolFailure {
            origin: ctx(),
            code: None,
        },
        OutRecord::Data {
            stream: 3,
            data: vec![5; 10],
        },
        OutRecord::Resyncable {
            stream: 3,
            resyncable: true,
        },
        OutRecord::StreamClass {
            stream: 3,
            bulk: true,
        },
        OutRecord::Consumed {
            stream: 3,
            n: u64::MAX,
        },
        OutRecord::NotifyDelivered {
            stream: 3,
            token: 8,
        },
        OutRecord::ChannelOpened {
            stream: 3,
            origin: ctx(),
        },
        OutRecord::ChannelRefused {
            stream: 3,
            origin: ctx(),
            reason: b"no".to_vec(),
        },
    ]
}

fn all_to_owner() -> Vec<ToOwner> {
    vec![
        ToOwner::Data {
            stream: 4,
            data: vec![1, 2, 3],
        },
        ToOwner::Live(ctx()),
        ToOwner::ResumeReset(ctx()),
        ToOwner::RepaintCutover {
            generation: 1,
            sequence: 2,
        },
        ToOwner::Repaint,
        ToOwner::DataPart(vec![3; 200]),
        ToOwner::Gate {
            gate: 4,
            op: GateOpWire::Admit(99),
        },
        ToOwner::Gate {
            gate: 4,
            op: GateOpWire::Withdraw(98),
        },
        ToOwner::Gate {
            gate: 4,
            op: GateOpWire::Transfer { n: 97, tail: 96 },
        },
        ToOwner::Gate {
            gate: 4,
            op: GateOpWire::Update {
                tail: 95,
                ready: Some((8, 2)),
            },
        },
        ToOwner::Gate {
            gate: 4,
            op: GateOpWire::Update {
                tail: 94,
                ready: None,
            },
        },
        ToOwner::Charge {
            id: 9,
            op: ChargeOp::Slice {
                n: 7,
                tail: 70,
                headers: 2,
            },
        },
        ToOwner::Charge {
            id: 1,
            op: ChargeOp::Transfer(5),
        },
        ToOwner::Charge {
            id: 3,
            op: ChargeOp::Withdraw,
        },
        ToOwner::Progress {
            stream: 4,
            instance: 8,
            generation: 2,
        },
        ToOwner::Admitted { id: 4 },
        ToOwner::Released { id: 5 },
        ToOwner::Retained {
            id: 6,
            kind: RetainedKind::Marker,
        },
        ToOwner::Retained {
            id: 7,
            kind: RetainedKind::Gap,
        },
        ToOwner::Committed { id: 8 },
        ToOwner::Frontier {
            stream: 4,
            instance: 8,
            geometry: geometry(),
        },
        ToOwner::Unconfirmed {
            stream: 4,
            instance: 1,
            unconfirmed: true,
        },
        ToOwner::MarkerDelivered {
            stream: 4,
            token: 3,
            generation: 2,
        },
        ToOwner::BudgetRetired { origin: ctx() },
        ToOwner::Liveness {
            last_client_recv: 123_456,
        },
        ToOwner::End(EndKind::Graceful),
        ToOwner::End(EndKind::Destroy),
        ToOwner::Retire,
    ]
}

fn all_to_frontend() -> Vec<ToFrontend> {
    let mut v: Vec<ToFrontend> = vec![
        ToFrontend::Grant { slots: 256 },
        ToFrontend::DataPart(vec![6; 300]),
        ToFrontend::Snapshot {
            id: 3,
            generation: 2,
            prefix: 10,
            dto: vec![9; 1000],
        },
        ToFrontend::Terminal {
            origin: ctx(),
            disposition: 2,
        },
        ToFrontend::ReplayFrontier {
            stream: 4,
            instance: 8,
            geometry: geometry(),
        },
        ToFrontend::ReplayUnconfirmed {
            stream: 4,
            unconfirmed: false,
        },
        ToFrontend::ReplayRetained {
            stream: 3,
            kind: RetainedKind::Gap,
        },
        ToFrontend::ReplayDone,
        ToFrontend::ReplayStart {
            last_generation: 7,
            live_seen: true,
            observed: 42,
        },
        ToFrontend::ReplayStream {
            stream: 4,
            instance: 8,
            reserve: 14,
            gate: GateWire { id: 2, kind: 1 },
        },
        ToFrontend::Finished,
    ];
    for r in all_records() {
        v.push(ToFrontend::Record(r.clone()));
        v.push(ToFrontend::ReplayItem(r));
    }
    v
}

fn decode_all<M: LinkMessage>(bytes: &[u8]) -> Result<Vec<M>, LinkError> {
    let mut reader = FrameReader::new();
    let mut out = Vec::new();
    let mut input = bytes;
    while let Some(frame) = reader.next(input)? {
        input = &[];
        out.push(M::decode(&frame)?);
    }
    reader.finish()?;
    Ok(out)
}

#[test]
fn owner_link_round_trips_every_kind() {
    let msgs = all_to_owner();
    let mut bytes = Vec::new();
    for m in &msgs {
        encode(m, &mut bytes).unwrap();
    }
    assert_eq!(decode_all::<ToOwner>(&bytes).unwrap(), msgs);

    let msgs = all_to_frontend();
    let mut bytes = Vec::new();
    for m in &msgs {
        encode(m, &mut bytes).unwrap();
    }
    assert_eq!(decode_all::<ToFrontend>(&bytes).unwrap(), msgs);
}

#[test]
fn owner_link_round_trips_when_fed_one_byte_at_a_time() {
    let msgs = all_to_frontend();
    let mut bytes = Vec::new();
    for m in &msgs {
        encode(m, &mut bytes).unwrap();
    }
    let mut reader = FrameReader::new();
    let mut got = Vec::new();
    for b in &bytes {
        let mut input: &[u8] = std::slice::from_ref(b);
        while let Some(f) = reader.next(input).unwrap() {
            input = &[];
            got.push(ToFrontend::decode(&f).unwrap());
        }
    }
    reader.finish().unwrap();
    assert_eq!(got, msgs);
}

fn header(version: u16, lane: u8, kind: u8, len: u32) -> Vec<u8> {
    let mut h = b"QSHL".to_vec();
    h.extend_from_slice(&version.to_be_bytes());
    h.push(lane);
    h.push(kind);
    h.extend_from_slice(&len.to_be_bytes());
    h
}

fn kind_of(msg: &ToOwner) -> u8 {
    let mut b = Vec::new();
    encode(msg, &mut b).unwrap();
    b[7]
}

#[test]
fn owner_link_rejects_oversized_frame_before_allocation() {
    let data_kind = kind_of(&ToOwner::Data {
        stream: 1,
        data: vec![],
    });
    let live_kind = kind_of(&ToOwner::End(EndKind::Graceful));
    let mut snap = Vec::new();
    encode(
        &ToFrontend::Snapshot {
            id: 0,
            generation: 0,
            prefix: 0,
            dto: vec![],
        },
        &mut snap,
    )
    .unwrap();
    let snap_kind = snap[7];
    let cases = [
        (data_kind, DATA_FRAME_MAX + FRAME_OVERHEAD),
        (live_kind, CONTROL_FRAME_MAX + FRAME_OVERHEAD),
        (snap_kind, SNAPSHOT_FRAME_MAX + FRAME_OVERHEAD),
    ];
    for (kind, max) in cases {
        let lane = 0;
        let mut over = header(LINK_VERSION, lane, kind, u32::try_from(max + 1).unwrap());
        // No body follows: the bound must be checked from the header alone.
        let mut reader = FrameReader::new();
        assert_eq!(reader.next(&over), Err(LinkError::TooLong));
        assert_eq!(reader.body_capacity(), 0);
        // Exactly at the bound the header is accepted and the frame is awaited.
        over = header(LINK_VERSION, lane, kind, u32::try_from(max).unwrap());
        let mut reader = FrameReader::new();
        assert_eq!(reader.next(&over), Ok(None));
    }
    assert_eq!(SNAPSHOT_FRAME_MAX, crate::channel::CHANNEL_SNAPSHOT_MAX);
    assert_eq!(CONTROL_FRAME_MAX, crate::shell_frame::CONTROL_RECORD_MAX);
    assert_eq!(DATA_FRAME_MAX, 64 * 1024);
}

fn ctx_max_records(n: usize) -> Vec<OutRecord> {
    vec![
        OutRecord::ReservedControl {
            id: u64::MAX,
            origin: ctx(),
            bytes: vec![1; n],
            charge: Some(gate()),
        },
        OutRecord::UpdateAccept {
            id: u64::MAX,
            origin: ctx(),
            bytes: vec![2; n],
            charge: Some(gate()),
        },
        OutRecord::ReservedSessionControl {
            id: u64::MAX,
            bytes: vec![3; n],
            charge: Some(gate()),
        },
        OutRecord::ChannelRefused {
            stream: 255,
            origin: ctx(),
            reason: vec![4; n],
        },
    ]
}

fn round_trip_to_frontend(msg: ToFrontend) {
    let mut bytes = Vec::new();
    encode(&msg, &mut bytes).unwrap();
    assert_eq!(decode_all::<ToFrontend>(&bytes).unwrap(), vec![msg]);
}

#[test]
fn owner_link_carries_maximum_content_of_every_class() {
    let data = ToOwner::Data {
        stream: 255,
        data: vec![7; DATA_FRAME_MAX],
    };
    let mut bytes = Vec::new();
    encode(&data, &mut bytes).unwrap();
    assert_eq!(decode_all::<ToOwner>(&bytes).unwrap(), vec![data]);
    round_trip_to_frontend(ToFrontend::Record(OutRecord::Data {
        stream: 255,
        data: vec![7; DATA_FRAME_MAX],
    }));
    round_trip_to_frontend(ToFrontend::DataPart(vec![7; DATA_FRAME_MAX]));
    round_trip_to_frontend(ToFrontend::ReplayItem(OutRecord::ChannelOutput {
        id: u64::MAX,
        stream: 255,
        instance: u64::MAX,
        origin: ctx(),
        output: OutputBody::Data(vec![7; DATA_FRAME_MAX]),
        gate: GateWire {
            id: u64::MAX,
            kind: 0,
        },
        gap_reserve: true,
    }));
    for r in ctx_max_records(CONTROL_FRAME_MAX) {
        round_trip_to_frontend(ToFrontend::Record(r.clone()));
        round_trip_to_frontend(ToFrontend::ReplayItem(r));
    }
    round_trip_to_frontend(ToFrontend::Snapshot {
        id: u64::MAX,
        generation: u64::MAX,
        prefix: u64::MAX,
        dto: vec![9; SNAPSHOT_FRAME_MAX],
    });
}

#[test]
fn owner_link_encode_refuses_content_one_over_the_limit() {
    let mut out = vec![1, 2, 3];
    let mut over: Vec<ToFrontend> = vec![
        ToFrontend::Record(OutRecord::Data {
            stream: 1,
            data: vec![0; DATA_FRAME_MAX + 1],
        }),
        ToFrontend::Snapshot {
            id: 0,
            generation: 0,
            prefix: 0,
            dto: vec![0; SNAPSHOT_FRAME_MAX + 1],
        },
        ToFrontend::DataPart(vec![0; DATA_FRAME_MAX + 1]),
    ];
    over.extend(
        ctx_max_records(CONTROL_FRAME_MAX + 1)
            .into_iter()
            .map(ToFrontend::Record),
    );
    for m in &over {
        assert_eq!(encode(m, &mut out), Err(LinkError::TooLong), "{m:?}");
        assert_eq!(out, [1, 2, 3]);
    }
    let msg = ToOwner::Data {
        stream: 1,
        data: vec![0; DATA_FRAME_MAX + 1],
    };
    assert_eq!(encode(&msg, &mut out), Err(LinkError::TooLong));
    assert_eq!(out, [1, 2, 3]);
}

#[test]
fn owner_link_decode_refuses_content_one_over_the_limit_within_frame_bound() {
    // A peer that stays inside the frame slack but declares content past the
    // class limit is refused at decode.
    let mut payload = vec![9];
    payload.extend_from_slice(&u32::try_from(DATA_FRAME_MAX + 1).unwrap().to_be_bytes());
    payload.extend(vec![0; DATA_FRAME_MAX + 1]);
    let mut bytes = header(
        LINK_VERSION,
        0,
        kind_of(&ToOwner::Data {
            stream: 0,
            data: vec![],
        }),
        u32::try_from(payload.len()).unwrap(),
    );
    bytes.extend(payload);
    let frame = FrameReader::new().next(&bytes).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::TooLong));
}

#[test]
fn owner_link_rejects_unknown_version_and_kind() {
    let mut reader = FrameReader::new();
    assert_eq!(
        reader.next(&header(LINK_VERSION + 1, 0, 1, 0)),
        Err(LinkError::UnknownVersion)
    );
    let mut reader = FrameReader::new();
    assert_eq!(
        reader.next(&header(LINK_VERSION, 0, 0xfe, 0)),
        Err(LinkError::UnknownKind)
    );
    let mut reader = FrameReader::new();
    assert_eq!(
        reader.next(&header(LINK_VERSION, 0, 0, 0)),
        Err(LinkError::UnknownKind)
    );
    let mut bad_magic = header(LINK_VERSION, 0, 1, 0);
    bad_magic[0] = b'X';
    assert_eq!(
        FrameReader::new().next(&bad_magic),
        Err(LinkError::BadMagic)
    );
    let bad_lane = header(LINK_VERSION, 9, 1, 0);
    assert_eq!(FrameReader::new().next(&bad_lane), Err(LinkError::BadLane));
    // A kind in the wrong lane is refused at decode.
    let mut term = Vec::new();
    encode(
        &ToFrontend::Terminal {
            origin: ctx(),
            disposition: 1,
        },
        &mut term,
    )
    .unwrap();
    term[6] = 0;
    assert_eq!(FrameReader::new().next(&term), Err(LinkError::BadLane));
    // A data-lane kind labelled priority is refused from its header, so
    // `next_priority` can never promote it past queued frames.
    let mut grant = Vec::new();
    encode(&ToFrontend::Grant { slots: 1 }, &mut grant).unwrap();
    grant[6] = 1;
    let mut reader = FrameReader::new();
    assert_eq!(reader.next_priority(&grant), Err(LinkError::BadLane));
    assert_eq!(reader.body_capacity(), 0);
    // A ToFrontend kind is not a ToOwner message.
    let mut grant = Vec::new();
    encode(&ToFrontend::Grant { slots: 1 }, &mut grant).unwrap();
    let frame = FrameReader::new().next(&grant).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::UnknownKind));
    // Invalid enum values inside a well-framed payload.
    let mut end = Vec::new();
    encode(&ToOwner::End(EndKind::Graceful), &mut end).unwrap();
    *end.last_mut().unwrap() = 9;
    let frame = FrameReader::new().next(&end).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::BadValue));
}

#[test]
fn owner_link_rejects_truncated_and_trailing_bytes() {
    let mut bytes = Vec::new();
    encode(&ToOwner::Released { id: 2 }, &mut bytes).unwrap();
    // Stream ends inside the header and inside the body.
    for cut in [3, HEADER_LEN, bytes.len() - 1] {
        let mut reader = FrameReader::new();
        assert_eq!(reader.next(&bytes[..cut]), Ok(None));
        assert_eq!(reader.finish(), Err(LinkError::Truncated));
    }
    // A payload shorter than its kind needs.
    let short = [header(LINK_VERSION, 0, bytes[7], 3), vec![0; 3]].concat();
    let frame = FrameReader::new().next(&short).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::Truncated));
    // A payload longer than its kind needs.
    let long = [header(LINK_VERSION, 0, bytes[7], 10), vec![0; 10]].concat();
    let frame = FrameReader::new().next(&long).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::Trailing));
    // A byte string whose declared length exceeds its payload.
    let mut data = Vec::new();
    encode(
        &ToOwner::Data {
            stream: 1,
            data: vec![1, 2],
        },
        &mut data,
    )
    .unwrap();
    let n = data.len();
    data[n - 6..n - 2].copy_from_slice(&1000u32.to_be_bytes());
    let frame = FrameReader::new().next(&data).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::Truncated));
    // ... and one past the class limit is refused as too long.
    data[n - 6..n - 2].copy_from_slice(&u32::MAX.to_be_bytes());
    let frame = FrameReader::new().next(&data).unwrap().unwrap();
    assert_eq!(ToOwner::decode(&frame), Err(LinkError::TooLong));
}

#[test]
fn owner_link_priority_lane_is_decoded_first() {
    let mut bytes = Vec::new();
    for i in 0..3u8 {
        encode(
            &ToFrontend::Record(OutRecord::Data {
                stream: i,
                data: vec![i],
            }),
            &mut bytes,
        )
        .unwrap();
    }
    let terminal = ToFrontend::Terminal {
        origin: ctx(),
        disposition: 1,
    };
    encode(&terminal, &mut bytes).unwrap();
    encode(&ToFrontend::Grant { slots: 1 }, &mut bytes).unwrap();

    let mut reader = FrameReader::new();
    let first = reader.next_priority(&bytes).unwrap().unwrap();
    assert_eq!(first.lane(), Lane::Priority);
    assert_eq!(ToFrontend::decode(&first).unwrap(), terminal);
    // The data frames keep their order afterwards.
    for i in 0..3u8 {
        let f = reader.next_priority(&[]).unwrap().unwrap();
        assert_eq!(
            ToFrontend::decode(&f).unwrap(),
            ToFrontend::Record(OutRecord::Data {
                stream: i,
                data: vec![i]
            })
        );
    }
    let f = reader.next_priority(&[]).unwrap().unwrap();
    assert_eq!(
        ToFrontend::decode(&f).unwrap(),
        ToFrontend::Grant { slots: 1 }
    );
    assert_eq!(reader.next_priority(&[]), Ok(None));
    reader.finish().unwrap();
}

#[test]
fn owner_link_error_is_sticky() {
    let mut reader = FrameReader::new();
    assert!(reader.next(&header(LINK_VERSION + 1, 0, 1, 0)).is_err());
    assert_eq!(reader.next(&[]), Err(LinkError::UnknownVersion));
}
