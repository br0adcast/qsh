use super::*;
use crate::qsh::QshSubstrate;
use transport::channel::{encode_server, CONTROL_STREAM};
use transport::channel_geometry::GeometryOutcome;
use transport::shell_frame::{encode_shell, ShellRecord, REC_DATA};

fn initial() -> GeometryRecord {
    GeometryRecord {
        instance: ChannelInstance::new(1).unwrap(),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 80,
        rows: 24,
    }
}
fn wire(record: ShellRecord) -> Vec<u8> {
    encode_shell(&record).unwrap()
}

#[test]
fn early_declared_data_over_cap_fails_from_header_before_payload() {
    let mut session = ChannelSession::new(QshSubstrate::new(|_, _| {}));
    let mut header = vec![REC_DATA];
    header.extend_from_slice(&(65537u32).to_be_bytes());
    assert_eq!(
        session.on_bytes(16, &header),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        )]
    );
    assert!(session
        .on_bytes(16, &wire(ShellRecord::Geometry(initial())))
        .is_empty());
}

#[test]
fn unknown_partial_records_share_declared_capacity_budget() {
    let mut session = ChannelSession::new(QshSubstrate::new(|_, _| {}));
    let mut header = vec![REC_DATA];
    header.extend_from_slice(&(65536u32).to_be_bytes());
    for ch in 16..23 {
        assert!(session.on_bytes(ch, &header).is_empty());
    }
    assert_eq!(
        session.on_bytes(23, &header),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        )]
    );
}

#[test]
fn geometry_before_opened_releases_geometry_ready_and_data_in_order() {
    let mut session = ChannelSession::new(QshSubstrate::new(|_, _| {}));
    let ch = session.open_shell(80, 24).unwrap();
    let mut batch = wire(ShellRecord::Geometry(initial()));
    batch.extend(wire(ShellRecord::Data(b"tail".to_vec())));
    assert!(session.on_bytes(ch, &batch).is_empty());
    assert_eq!(
        session.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Opened { stream: ch })
        ),
        vec![
            SessionEvent::Geometry {
                ch,
                record: initial()
            },
            SessionEvent::Ready(ch),
            SessionEvent::Data {
                ch,
                bytes: b"tail".to_vec()
            }
        ]
    );
}

use std::sync::{Arc, Mutex};
use transport::channel::{
    decode_client, ActiveChannel, ChannelSnapshot, ClientRecord, DrainingChannel,
    OpenClassification,
};
use transport::shell_frame::RecordDeframer;
type Sink = Box<dyn FnMut(u8, Vec<u8>) + Send>;
type Session = ChannelSession<QshSubstrate<Sink>>;
fn logged() -> (Session, Arc<Mutex<Vec<ClientRecord>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let seen = sent.clone();
    let sink: Sink = Box::new(move |stream, bytes| {
        if stream == CONTROL_STREAM {
            for raw in RecordDeframer::for_control().push(&bytes) {
                seen.lock().unwrap().push(decode_client(&raw).unwrap());
            }
        }
    });
    (ChannelSession::new(QshSubstrate::new(sink)), sent)
}
fn geometry(s: &mut Session, record: GeometryRecord) -> Vec<SessionEvent> {
    s.on_bytes(16, &wire(ShellRecord::Geometry(record)))
}
fn ready(s: &mut Session) {
    assert_eq!(s.open_shell(80, 24), Some(16));
    assert!(s
        .on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Opened { stream: 16 })
        )
        .is_empty());
    assert_eq!(
        geometry(s, initial()),
        vec![
            SessionEvent::Geometry {
                ch: 16,
                record: initial()
            },
            SessionEvent::Ready(16)
        ]
    );
}
fn applied(id: u64, cols: u16, rows: u16) -> GeometryRecord {
    GeometryRecord {
        request_id: id,
        outcome: GeometryOutcome::Applied,
        cols,
        rows,
        ..initial()
    }
}
fn request(cols: u16, rows: u16) -> OpenRequest {
    OpenRequest {
        stream: 16,
        kind: ChannelKind::Shell,
        cols,
        rows,
        screen: true,
        command: Vec::new(),
    }
}
fn snapshot(s: &mut Session, instance: u64, draining: bool) -> Vec<SessionEvent> {
    let req = request(80, 24);
    let instance = ChannelInstance::new(instance).unwrap();
    let list = if draining {
        ChannelSnapshot::new(
            vec![],
            vec![DrainingChannel {
                stream: 16,
                instance,
                open: OpenClassification::from_open(&req),
            }],
        )
    } else {
        ChannelSnapshot::new(
            vec![ActiveChannel {
                instance,
                request: req,
            }],
            vec![],
        )
    }
    .unwrap();
    s.on_bytes(CONTROL_STREAM, &list.encode_record())
}
fn resize_records(sent: &Arc<Mutex<Vec<ClientRecord>>>) -> Vec<(u64, u16, u16)> {
    sent.lock()
        .unwrap()
        .iter()
        .filter_map(|rec| {
            if let ClientRecord::ResizeRequest {
                request_id,
                cols,
                rows,
                ..
            } = rec
            {
                Some((request_id.get(), *cols, *rows))
            } else {
                None
            }
        })
        .collect()
}
#[test]
fn late_result_commits_a_then_sends_latest_b_and_duplicate_is_idempotent() {
    let (mut s, sent) = logged();
    ready(&mut s);
    assert_eq!(s.resize(16, 100, 30), ResizeDisposition::Sent);
    assert_eq!(s.resize(16, 120, 40), ResizeDisposition::Coalesced);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
    assert_eq!(
        geometry(&mut s, applied(1, 100, 30)),
        vec![SessionEvent::Geometry {
            ch: 16,
            record: applied(1, 100, 30)
        }]
    );
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (2, 120, 40)]);
    geometry(&mut s, applied(1, 100, 30));
    assert_eq!(resize_records(&sent).len(), 2);
    geometry(&mut s, applied(2, 120, 40));
    assert_eq!(s.committed_geometry(16), Some(applied(2, 120, 40)));
}
#[test]
fn return_to_old_desired_waits_for_inflight_result() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    s.resize(16, 80, 24);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
    geometry(&mut s, applied(1, 100, 30));
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (2, 80, 24)]);
}
#[test]
fn refusal_latch_transfers_same_instance_and_new_intent_can_retry() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    let refusal = GeometryRecord {
        request_id: 1,
        outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
        ..initial()
    };
    let events = geometry(&mut s, refusal);
    assert!(events
        .iter()
        .any(|e| matches!(e, SessionEvent::ResizeRefused { .. })));
    assert!(s.is_ready(16));
    assert_eq!(s.resize(16, 100, 30), ResizeDisposition::Unchanged);
    assert!(!geometry(&mut s, refusal)
        .iter()
        .any(|e| matches!(e, SessionEvent::ResizeRefused { .. })));
    geometry(&mut s, initial());
    assert_eq!(resize_records(&sent).len(), 1);
    let intent = s.into_attachment_intent();
    let (fresh, new_sent) = logged();
    let mut s = ChannelSession::with_attachment_intent(fresh.substrate, intent);
    snapshot(&mut s, 1, false);
    geometry(&mut s, initial());
    assert!(resize_records(&new_sent).is_empty());
    s.resize(16, 120, 40);
    s.resize(16, 100, 30);
    geometry(&mut s, applied(1, 120, 40));
    assert_eq!(resize_records(&new_sent), vec![(1, 120, 40), (2, 100, 30)]);
}
#[test]
fn early_exit_retains_partial_deframer_until_draining_tail_and_real_exit() {
    let (mut s, _) = logged();
    let data = wire(ShellRecord::Data(b"tail".to_vec()));
    assert!(geometry(&mut s, initial()).is_empty());
    assert!(s.on_bytes(16, &data[..6]).is_empty());
    assert!(s
        .on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Exit {
                stream: 16,
                code: 37
            })
        )
        .is_empty());
    assert_eq!(
        snapshot(&mut s, 1, true),
        vec![
            SessionEvent::Announced {
                active: vec![],
                draining: vec![16]
            },
            SessionEvent::Geometry {
                ch: 16,
                record: initial()
            },
            SessionEvent::DrainingReady(16)
        ]
    );
    assert!(!s.is_ready(16));
    assert_eq!(
        s.resize(16, 100, 30),
        ResizeDisposition::Rejected(ResizeRejection::Ended)
    );
    assert_eq!(
        s.on_bytes(16, &data[6..]),
        vec![
            SessionEvent::Data {
                ch: 16,
                bytes: b"tail".to_vec()
            },
            SessionEvent::Exit { ch: 16, code: 37 }
        ]
    );
    assert!(s
        .on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Exit {
                stream: 16,
                code: 37
            })
        )
        .is_empty());
}
#[test]
fn hot_reset_preserves_request_scope_and_replay_resolves_it() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    s.reset_stream(16);
    assert!(!s.is_ready(16));
    geometry(&mut s, initial());
    assert_eq!(resize_records(&sent).len(), 1);
    s.reset_stream(16);
    geometry(&mut s, applied(1, 100, 30));
    assert!(s.is_ready(16));
    assert_eq!(s.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (2, 120, 40)]);
}
#[test]
fn unknown_correlation_is_terminal_and_no_later_ready_or_data_escapes() {
    let (mut s, _) = logged();
    ready(&mut s);
    assert_eq!(
        geometry(&mut s, applied(1, 100, 30)),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::Correlation
        )]
    );
    assert!(geometry(&mut s, initial()).is_empty());
    assert!(!s.is_ready(16));
    assert!(s
        .on_bytes(16, &wire(ShellRecord::Data(b"no".to_vec())))
        .is_empty());
}
#[test]
fn repeated_snapshot_after_resize_does_not_reject_updated_effective_dimensions() {
    let (mut s, _) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    geometry(&mut s, applied(1, 100, 30));
    let list = ChannelSnapshot::new(
        vec![ActiveChannel {
            instance: initial().instance,
            request: request(100, 30),
        }],
        vec![],
    )
    .unwrap();
    assert_eq!(
        s.on_bytes(CONTROL_STREAM, &list.encode_record()),
        vec![SessionEvent::Announced {
            active: vec![16],
            draining: vec![]
        }]
    );
    assert_eq!(s.committed_geometry(16), Some(applied(1, 100, 30)));
}
#[test]
fn continuity_warning_survives_ready_and_real_exit() {
    let (mut s, _) = logged();
    ready(&mut s);
    let cause = OutputGapCause::PreviousConnectionOutputUnconfirmed;
    let mut batch = wire(ShellRecord::OutputGap {
        instance: initial().instance,
        cause,
    });
    batch.extend(wire(ShellRecord::Data(b"after-gap".to_vec())));
    assert_eq!(
        s.on_bytes(16, &batch),
        vec![
            SessionEvent::OutputContinuityLost {
                ch: 16,
                instance: initial().instance,
                cause
            },
            SessionEvent::Data {
                ch: 16,
                bytes: b"after-gap".to_vec()
            }
        ]
    );
    assert!(s.continuity_lost(16));
    geometry(&mut s, initial());
    assert_eq!(
        s.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Exit {
                stream: 16,
                code: 7
            })
        ),
        vec![SessionEvent::Exit { ch: 16, code: 7 }]
    );
    assert!(s.continuity_lost(16));
}
#[test]
fn control_exit_admission_includes_unknown_raw_reservations() {
    let (mut s, _) = logged();
    for ch in 16..23 {
        let mut header = vec![REC_DATA];
        header.extend_from_slice(&65536u32.to_be_bytes());
        assert!(s.on_bytes(ch, &header).is_empty());
    }
    // Fill all but nine aggregate bytes, including five framing bytes per record.
    let mut header = vec![REC_DATA];
    header.extend_from_slice(&65487u32.to_be_bytes());
    assert!(s.on_bytes(23, &header).is_empty());
    assert_eq!(
        s.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Exit {
                stream: 24,
                code: 0
            })
        ),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        )]
    );
}
#[test]
fn nine_draining_channels_are_classified_and_released_without_live_ready() {
    let (mut s, _) = logged();
    let mut draining = Vec::new();
    for ch in 16..25 {
        let geometry = GeometryRecord {
            instance: ChannelInstance::new(ch as u64).unwrap(),
            ..initial()
        };
        let mut bytes = wire(ShellRecord::Geometry(geometry));
        bytes.extend(wire(ShellRecord::Data(vec![ch])));
        assert!(s.on_bytes(ch, &bytes).is_empty());
        assert!(s
            .on_bytes(
                CONTROL_STREAM,
                &encode_server(&ServerRecord::Exit {
                    stream: ch,
                    code: ch as i32
                })
            )
            .is_empty());
        draining.push(DrainingChannel {
            stream: ch,
            instance: geometry.instance,
            open: OpenClassification::from_open(&request(80, 24)),
        });
    }
    let out = s.on_bytes(
        CONTROL_STREAM,
        &ChannelSnapshot::new(vec![], draining)
            .unwrap()
            .encode_record(),
    );
    assert_eq!(
        out.iter()
            .filter(|e| matches!(e, SessionEvent::DrainingReady(_)))
            .count(),
        9
    );
    assert_eq!(
        out.iter()
            .filter(|e| matches!(e, SessionEvent::Data { .. }))
            .count(),
        9
    );
    assert_eq!(
        out.iter()
            .filter(|e| matches!(e, SessionEvent::Exit { .. }))
            .count(),
        9
    );
    assert!(!out
        .iter()
        .any(|e| matches!(e, SessionEvent::Ready(_) | SessionEvent::ProtocolFailure(_))));
}
#[test]
fn unknown_event_limit_includes_empty_data_and_geometry() {
    let (mut s, _) = logged();
    for ch in 16..24 {
        let mut bytes = wire(ShellRecord::Geometry(GeometryRecord {
            instance: ChannelInstance::new(ch as u64).unwrap(),
            ..initial()
        }));
        for _ in 1..256 {
            bytes.extend(wire(ShellRecord::Data(vec![])));
        }
        assert!(s.on_bytes(ch, &bytes).is_empty());
    }
    assert_eq!(
        s.on_bytes(24, &wire(ShellRecord::Data(vec![]))),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        )]
    );
    assert!(snapshot(&mut s, 1, false).is_empty());
}
#[test]
fn no_pty_geometry_preserves_either_zero_open_exactly() {
    for (cols, rows) in [(0, 24), (80, 0), (0, 0)] {
        let (mut s, sent) = logged();
        let ch = s.open_command(b"cat", cols, rows).unwrap();
        s.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Opened { stream: ch }),
        );
        let record = GeometryRecord {
            cols,
            rows,
            ..initial()
        };
        assert_eq!(
            geometry(&mut s, record),
            vec![
                SessionEvent::Geometry { ch, record },
                SessionEvent::Ready(ch)
            ]
        );
        assert_eq!(
            s.resize(ch, 80, 24),
            ResizeDisposition::Rejected(ResizeRejection::NoPty)
        );
        assert!(resize_records(&sent).is_empty());
        let invalid = GeometryRecord {
            cols: 80,
            rows: 24,
            ..initial()
        };
        assert_eq!(
            geometry(&mut s, invalid),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::Metadata
            )]
        );
    }
}
#[test]
fn fresh_instance_does_not_inherit_predecessor_refusal() {
    let (mut s, _) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    geometry(
        &mut s,
        GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..initial()
        },
    );
    let intent = s.into_attachment_intent();
    let (fresh, sent) = logged();
    let mut s = ChannelSession::with_attachment_intent(fresh.substrate, intent);
    snapshot(&mut s, 2, false);
    geometry(
        &mut s,
        GeometryRecord {
            instance: ChannelInstance::new(2).unwrap(),
            ..initial()
        },
    );
    assert_eq!(s.resize(16, 100, 30), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
}
#[test]
fn ready_large_data_is_streamed_without_early_limit_or_lost_bytes() {
    let (mut s, _) = logged();
    ready(&mut s);
    let payload = vec![0x5a; 200_000];
    let events = s.on_bytes(16, &wire(ShellRecord::Data(payload.clone())));
    let mut received = Vec::new();
    for event in events {
        match event {
            SessionEvent::Data { bytes, .. } => {
                assert!(bytes.len() <= 65536);
                received.extend(bytes);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(received, payload);
}
#[test]
fn retired_stream_does_not_retain_new_partial_input() {
    let (mut s, _) = logged();
    ready(&mut s);
    s.on_bytes(
        CONTROL_STREAM,
        &encode_server(&ServerRecord::Exit {
            stream: 16,
            code: 0,
        }),
    );
    let frame = wire(ShellRecord::Data(vec![0; 65536]));
    assert!(s.on_bytes(16, &frame[..5]).is_empty());
    assert_eq!(s.substrate.input_usage(16).bytes, 0);
    assert_eq!(s.substrate.input_usage(16).events, 0);
}
#[test]
fn direct_decoder_batch_is_bounded_before_accumulating_output_events() {
    let mut sub = QshSubstrate::new(|_, _| {});
    let bytes = wire(ShellRecord::Data(vec![])).repeat(257);
    let events = sub.on_stream(16, &bytes);
    assert_eq!(
        events.last(),
        Some(&SubstrateEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        ))
    );
    assert!(events.len() <= 257);
}
#[test]
fn ordered_substrate_refuses_uncorrelated_resize_encoder() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sink = sent.clone();
    let mut sub = QshSubstrate::new(move |_, bytes| sink.lock().unwrap().push(bytes));
    sub.resize(16, 100, 30);
    assert!(sent.lock().unwrap().is_empty());
    assert_eq!(
        sub.protocol_error(),
        Some(ChannelProtocolError::UnsupportedProfile)
    );
}
#[test]
fn applied_result_must_match_the_correlated_requested_size() {
    let (mut s, _) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    assert_eq!(
        geometry(&mut s, applied(1, 120, 40)),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::Correlation
        )]
    );
}
#[test]
fn unknown_extension_body_is_skipped_without_early_payload_charge() {
    let mut sub = QshSubstrate::new(|_, _| {});
    let mut bytes = transport::shell_frame::encode_record(0x70, &vec![0; 600_000]);
    bytes.extend(wire(ShellRecord::Data(b"known".to_vec())));
    assert_eq!(
        sub.on_stream(16, &bytes),
        vec![SubstrateEvent::Data {
            ch: 16,
            bytes: b"known".to_vec()
        }]
    );
}
#[test]
fn same_refused_intent_survives_two_attachment_transitions_without_retry() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    geometry(
        &mut s,
        GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..initial()
        },
    );
    for _ in 0..2 {
        s.reset_attachment();
        snapshot(&mut s, 1, false);
        geometry(&mut s, initial());
        assert_eq!(s.resize(16, 100, 30), ResizeDisposition::Unchanged);
    }
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
}
#[test]
fn contradictory_duplicate_and_wrong_instance_are_terminal() {
    for instance in [1, 2] {
        let (mut s, _) = logged();
        ready(&mut s);
        s.resize(16, 100, 30);
        geometry(&mut s, applied(1, 100, 30));
        let record = GeometryRecord {
            instance: ChannelInstance::new(instance).unwrap(),
            ..applied(1, 120, 40)
        };
        let expected = if instance == 1 {
            ChannelProtocolError::Correlation
        } else {
            ChannelProtocolError::Instance
        };
        assert_eq!(
            geometry(&mut s, record),
            vec![SessionEvent::ProtocolFailure(expected)]
        );
    }
}
#[test]
fn locally_classified_opening_channels_use_per_channel_not_unknown_pool() {
    let (mut s, _) = logged();
    for _ in 0..8 {
        let ch = s.open_shell(80, 24).unwrap();
        let mut bytes = wire(ShellRecord::Geometry(GeometryRecord {
            instance: ChannelInstance::new(ch as u64).unwrap(),
            ..initial()
        }));
        bytes.extend(wire(ShellRecord::Data(vec![ch; 65536])));
        assert!(
            s.on_bytes(ch, &bytes).is_empty(),
            "known OPEN classification for {ch} has its own 64 KiB allowance"
        );
    }
}

#[test]
fn full_identity_namespace_retires_then_reuses_stream_without_old_state() {
    let (mut s, _) = logged();
    let mut draining = Vec::new();
    for ch in FIRST_CHANNEL_STREAM..=255 {
        let instance = ChannelInstance::new(ch as u64).unwrap();
        let record = GeometryRecord {
            instance,
            ..initial()
        };
        assert!(s
            .on_bytes(ch, &wire(ShellRecord::Geometry(record)))
            .is_empty());
        assert!(s
            .on_bytes(
                CONTROL_STREAM,
                &encode_server(&ServerRecord::Exit {
                    stream: ch,
                    code: 0
                })
            )
            .is_empty());
        draining.push(DrainingChannel {
            stream: ch,
            instance,
            open: OpenClassification::from_open(&request(80, 24)),
        });
    }
    let snapshot = ChannelSnapshot::new(vec![], draining).unwrap();
    let events = s.on_bytes(CONTROL_STREAM, &snapshot.encode_record());
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, SessionEvent::Exit { .. }))
            .count(),
        240
    );
    assert!(!events.iter().any(|event| matches!(
        event,
        SessionEvent::ProtocolFailure(_) | SessionEvent::Ready(_)
    )));
    assert_eq!(s.open_shell(80, 24), Some(16));
    assert!(s
        .on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Opened { stream: 16 })
        )
        .is_empty());
    let record = GeometryRecord {
        instance: ChannelInstance::new(1000).unwrap(),
        ..initial()
    };
    assert_eq!(
        geometry(&mut s, record),
        vec![
            SessionEvent::Geometry { ch: 16, record },
            SessionEvent::Ready(16)
        ]
    );
    assert!(!s.continuity_lost(16));
    assert!(s.is_ready(16));
}

#[test]
fn initial_not_ready_resize_is_rejected_without_retaining_a_hidden_request() {
    let (mut s, sent) = logged();
    assert_eq!(s.open_shell(80, 24), Some(16));
    assert_eq!(
        s.resize(16, 100, 30),
        ResizeDisposition::Rejected(ResizeRejection::NotReady)
    );
    s.on_bytes(
        CONTROL_STREAM,
        &encode_server(&ServerRecord::Opened { stream: 16 }),
    );
    geometry(&mut s, initial());
    assert!(resize_records(&sent).is_empty());
}
#[test]
fn resize_during_hot_reset_coalesces_behind_the_existing_pending_request() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    s.reset_stream(16);
    assert_eq!(s.resize(16, 120, 40), ResizeDisposition::Coalesced);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
    geometry(&mut s, applied(1, 100, 30));
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (2, 120, 40)]);
}

fn retired_draining_with_continuity_warning() -> Session {
    let (mut session, _) = logged();
    assert_eq!(
        snapshot(&mut session, 1, true),
        vec![SessionEvent::Announced {
            active: vec![],
            draining: vec![16],
        }]
    );
    assert_eq!(
        geometry(&mut session, initial()),
        vec![
            SessionEvent::Geometry {
                ch: 16,
                record: initial(),
            },
            SessionEvent::DrainingReady(16),
        ]
    );
    let cause = OutputGapCause::PreviousConnectionOutputUnconfirmed;
    assert_eq!(
        session.on_bytes(
            16,
            &wire(ShellRecord::OutputGap {
                instance: initial().instance,
                cause,
            }),
        ),
        vec![SessionEvent::OutputContinuityLost {
            ch: 16,
            instance: initial().instance,
            cause,
        }]
    );
    assert_eq!(
        session.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Exit {
                stream: 16,
                code: 42,
            }),
        ),
        vec![SessionEvent::Exit { ch: 16, code: 42 }]
    );
    assert!(!session.is_ready(16));
    assert!(session.continuity_lost(16));
    session
}

#[test]
fn repeated_same_instance_snapshot_cannot_reopen_draining_or_deliver_a_second_exit() {
    let mut session = retired_draining_with_continuity_warning();
    let mut replay = snapshot(&mut session, 1, true);
    replay.extend(geometry(&mut session, initial()));
    replay.extend(session.on_bytes(
        CONTROL_STREAM,
        &encode_server(&ServerRecord::Exit {
            stream: 16,
            code: 42,
        }),
    ));
    let repeated_lifecycle: Vec<_> = replay
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                SessionEvent::Ready(_) | SessionEvent::DrainingReady(_) | SessionEvent::Exit { .. }
            )
        })
        .collect();
    assert_eq!(
        repeated_lifecycle,
        vec![],
        "same-instance metadata cannot resurrect a retired output lifecycle"
    );
}

#[test]
fn repeated_same_instance_snapshot_preserves_retired_continuity_warning() {
    let mut session = retired_draining_with_continuity_warning();
    snapshot(&mut session, 1, true);
    assert!(
        session.continuity_lost(16),
        "same-instance metadata cannot clear an already disclosed output gap"
    );
}

#[test]
fn repeated_same_instance_snapshot_cannot_turn_retired_draining_into_live_ready() {
    let mut session = retired_draining_with_continuity_warning();
    let mut replay = snapshot(&mut session, 1, false);
    replay.extend(geometry(&mut session, initial()));
    assert!(
        !replay
            .iter()
            .any(|event| matches!(event, SessionEvent::Ready(_))),
        "an active projection cannot resurrect the same ended instance: {replay:?}"
    );
    assert!(!session.is_ready(16));
}

#[test]
fn newer_instance_snapshot_retires_old_partial_parser_before_new_geometry() {
    replacement_retires_partial_parser(8);
}

#[test]
fn newer_instance_snapshot_retires_old_partial_header_before_new_geometry() {
    replacement_retires_partial_parser(2);
}

fn replacement_retires_partial_parser(split: usize) {
    let (mut session, sent) = logged();
    ready(&mut session);
    assert_eq!(session.resize(16, 100, 30), ResizeDisposition::Sent);
    let old_data = wire(ShellRecord::Data(b"old partial body".to_vec()));
    assert!(session.on_bytes(16, &old_data[..split]).is_empty());
    assert!(session.substrate.has_partial_input(16));
    assert_eq!(
        snapshot(&mut session, 2, false),
        vec![SessionEvent::Announced {
            active: vec![16],
            draining: vec![],
        }]
    );
    assert!(
        !session.substrate.has_partial_input(16),
        "new instance must not inherit the predecessor's partial DATA frame"
    );
    let record = GeometryRecord {
        instance: ChannelInstance::new(2).unwrap(),
        ..initial()
    };
    assert_eq!(
        geometry(&mut session, record),
        vec![
            SessionEvent::Geometry { ch: 16, record },
            SessionEvent::Ready(16)
        ]
    );
    assert_eq!(
        session.on_bytes(16, &wire(ShellRecord::Data(b"new body".to_vec()))),
        vec![SessionEvent::Data {
            ch: 16,
            bytes: b"new body".to_vec()
        }]
    );
    assert_eq!(session.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (1, 120, 40)]);
}

#[test]
fn older_snapshot_cannot_roll_back_a_newer_admitted_instance() {
    let (mut session, _) = logged();
    ready(&mut session);
    snapshot(&mut session, 2, false);
    let record = GeometryRecord {
        instance: ChannelInstance::new(2).unwrap(),
        ..initial()
    };
    geometry(&mut session, record);
    assert_eq!(session.committed_geometry(16), Some(record));
    assert_eq!(
        snapshot(&mut session, 1, false),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::Instance
        )]
    );
    assert!(!session.is_ready(16));
}

#[test]
fn retired_same_instance_snapshot_is_absent_from_announced_projection() {
    let mut session = retired_draining_with_continuity_warning();
    assert_eq!(
        snapshot(&mut session, 1, true),
        vec![SessionEvent::Announced {
            active: vec![],
            draining: vec![],
        }]
    );
}

#[test]
fn close_and_vanished_preserve_retired_instance_and_continuity() {
    for local_close in [true, false] {
        let (mut session, _) = logged();
        ready(&mut session);
        session.on_bytes(
            16,
            &wire(ShellRecord::OutputGap {
                instance: initial().instance,
                cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
            }),
        );
        if local_close {
            session.close(16);
        } else {
            let empty = ChannelSnapshot::new(vec![], vec![]).unwrap();
            assert_eq!(
                session.on_bytes(CONTROL_STREAM, &empty.encode_record()),
                vec![
                    SessionEvent::Announced {
                        active: vec![],
                        draining: vec![]
                    },
                    SessionEvent::Vanished { ch: 16 },
                ]
            );
        }
        assert!(session.continuity_lost(16));
        assert_eq!(
            snapshot(&mut session, 1, false),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::Metadata
            ),]
        );
        assert!(!session.is_ready(16));
    }
}

#[test]
fn local_stream_reuse_keeps_retired_frontier_for_snapshot_and_geometry() {
    for metadata in [true, false] {
        let (mut session, _) = logged();
        ready(&mut session);
        session.close(16);
        // Occupy the remaining finite namespace so local OPEN reuses stream 16.
        for expected in 17..=255 {
            assert_eq!(session.open_shell(80, 24), Some(expected));
        }
        assert_eq!(session.open_shell(80, 24), Some(16));
        let events = if metadata {
            snapshot(&mut session, 1, false)
        } else {
            session.on_bytes(
                CONTROL_STREAM,
                &encode_server(&ServerRecord::Opened { stream: 16 }),
            );
            geometry(&mut session, initial())
        };
        assert_eq!(
            events,
            vec![SessionEvent::ProtocolFailure(if metadata {
                ChannelProtocolError::Metadata
            } else {
                ChannelProtocolError::Instance
            })]
        );
        assert!(!session.is_ready(16));
    }
}

#[test]
fn repeated_same_instance_snapshot_preserves_partial_header_and_exit_tail() {
    for split in [2, 8] {
        let (mut session, _) = logged();
        ready(&mut session);
        let data = wire(ShellRecord::Data(b"same instance tail".to_vec()));
        assert!(session.on_bytes(16, &data[..split]).is_empty());
        assert!(session
            .on_bytes(
                CONTROL_STREAM,
                &encode_server(&ServerRecord::Exit {
                    stream: 16,
                    code: 37,
                })
            )
            .is_empty());
        let usage = session.substrate.input_usage(16);
        for _ in 0..2 {
            assert_eq!(
                snapshot(&mut session, 1, true),
                vec![SessionEvent::Announced {
                    active: vec![],
                    draining: vec![16],
                }]
            );
            let retained = session.substrate.input_usage(16);
            assert_eq!(
                (retained.bytes, retained.events),
                (usage.bytes, usage.events)
            );
            assert!(session.substrate.has_partial_input(16));
        }
        assert_eq!(
            session.on_bytes(16, &data[split..]),
            vec![
                SessionEvent::Data {
                    ch: 16,
                    bytes: b"same instance tail".to_vec()
                },
                SessionEvent::Exit { ch: 16, code: 37 },
            ]
        );
        assert!(!session.substrate.has_partial_input(16));
    }
}

#[test]
fn newer_snapshot_clears_predecessor_continuity_refusal_and_ready_allocation() {
    let (mut session, sent) = logged();
    ready(&mut session);
    assert_eq!(session.resize(16, 100, 30), ResizeDisposition::Sent);
    geometry(
        &mut session,
        GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..initial()
        },
    );
    session.on_bytes(
        16,
        &wire(ShellRecord::OutputGap {
            instance: initial().instance,
            cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
        }),
    );
    assert!(session.continuity_lost(16));
    let mut header = vec![REC_DATA];
    header.extend_from_slice(&200_000u32.to_be_bytes());
    assert!(session.on_bytes(16, &header).is_empty());
    assert!(session.substrate.input_usage(16).bytes >= 65536);
    snapshot(&mut session, 2, false);
    let usage = session.substrate.input_usage(16);
    assert_eq!((usage.bytes, usage.events), (0, 0));
    assert!(!session.continuity_lost(16));
    geometry(
        &mut session,
        GeometryRecord {
            instance: ChannelInstance::new(2).unwrap(),
            ..initial()
        },
    );
    assert_eq!(session.resize(16, 100, 30), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (1, 100, 30)]);
}

#[test]
fn deferred_physical_intent_prevents_an_obsolete_coalesced_resize() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    s.resize(16, 120, 40);
    let before = sent.lock().unwrap().len();
    s.defer_resize(16, 140, 50);
    assert_eq!(sent.lock().unwrap().len(), before);
    geometry(&mut s, applied(1, 100, 30));
    assert_eq!(
        sent.lock().unwrap().len(),
        before,
        "C must wait for the owner's debounce; B must never go out"
    );
    assert_eq!(s.resize(16, 140, 50), ResizeDisposition::Sent);
    assert!(
        matches!(sent.lock().unwrap().last(), Some(ClientRecord::ResizeRequest { request_id, cols: 140, rows: 50, .. }) if request_id.get() == 2)
    );
}

#[test]
fn intent_import_rejects_a_started_attachment_including_partial_control() {
    for partial in [false, true] {
        let (mut s, _) = logged();
        if partial {
            s.on_bytes(CONTROL_STREAM, &[0x29]);
        } else {
            ready(&mut s);
        }
        assert_eq!(
            s.import_attachment_intent(AttachmentIntent::default()),
            Err(ChannelProtocolError::Metadata)
        );
    }
}

#[test]
fn intent_import_rejects_direct_lifecycle_admission() {
    let (mut s, _) = logged();
    s.on_event(SubstrateEvent::Snapshot(
        ChannelSnapshot::new(vec![], vec![]).unwrap(),
    ));
    assert_eq!(
        s.import_attachment_intent(AttachmentIntent::default()),
        Err(ChannelProtocolError::Metadata)
    );
}

#[test]
fn deferred_intent_transfers_before_metadata_and_preserves_offline_revisions() {
    let (mut s, _) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    geometry(
        &mut s,
        GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..initial()
        },
    );
    let mut intent = s.into_attachment_intent();
    intent.defer_resize(16, 120, 40);
    intent.defer_resize(16, 100, 30);
    let (mut fresh, sent) = logged();
    fresh.import_attachment_intent(intent).unwrap();
    snapshot(&mut fresh, 1, false);
    geometry(&mut fresh, initial());
    assert!(
        resize_records(&sent).is_empty(),
        "transferred physical intent is still debouncing"
    );
    assert_eq!(fresh.resize(16, 100, 30), ResizeDisposition::Sent);
    assert_eq!(
        resize_records(&sent),
        vec![(1, 100, 30)],
        "changed offline intent may retry, with a fresh request scope"
    );
}

#[test]
fn zero_viewport_suspends_coalesced_intent_across_a_result() {
    let (mut s, sent) = logged();
    ready(&mut s);
    s.resize(16, 100, 30);
    s.resize(16, 120, 40);
    assert_eq!(
        s.defer_resize(16, 0, 0),
        ResizeDisposition::Rejected(ResizeRejection::ZeroViewport)
    );
    geometry(&mut s, applied(1, 100, 30));
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
    assert_eq!(s.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30), (2, 120, 40)]);
}

#[test]
fn review_early_geometry_preserves_imported_away_and_back_refusal_revision() {
    let (mut old, _) = logged();
    ready(&mut old);
    assert_eq!(old.resize(16, 100, 30), ResizeDisposition::Sent);
    geometry(
        &mut old,
        GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..initial()
        },
    );
    let intent = old.into_attachment_intent();
    let (mut fresh, sent) = logged();
    fresh.import_attachment_intent(intent).unwrap();
    assert!(geometry(&mut fresh, initial()).is_empty());
    assert_eq!(
        fresh.defer_resize(16, 120, 40),
        ResizeDisposition::Coalesced
    );
    assert_eq!(
        fresh.defer_resize(16, 100, 30),
        ResizeDisposition::Coalesced
    );
    let events = snapshot(&mut fresh, 1, false);
    assert!(events.contains(&SessionEvent::Ready(16)));
    assert!(resize_records(&sent).is_empty());
    assert_eq!(
        fresh.resize(16, 100, 30),
        ResizeDisposition::Sent,
        "physical away/back after early Geometry is a new revision, not the old refusal"
    );
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
}

#[test]
fn review_early_geometry_keeps_latest_deferred_intent_ineligible_at_snapshot() {
    let (mut old, _) = logged();
    ready(&mut old);
    assert_eq!(old.resize(16, 100, 30), ResizeDisposition::Sent);
    let intent = old.into_attachment_intent();
    let (mut fresh, sent) = logged();
    fresh.import_attachment_intent(intent).unwrap();
    assert!(geometry(&mut fresh, initial()).is_empty());
    assert_eq!(
        fresh.defer_resize(16, 120, 40),
        ResizeDisposition::Coalesced
    );
    let events = snapshot(&mut fresh, 1, false);
    assert!(events.contains(&SessionEvent::Ready(16)));
    assert!(
        resize_records(&sent).is_empty(),
        "snapshot must not restore/send the older eligible size over the latest deferred intent"
    );
    assert_eq!(fresh.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 120, 40)]);
}

#[test]
fn review_early_geometry_preserves_zero_viewport_suspension() {
    let (mut old, _) = logged();
    ready(&mut old);
    old.resize(16, 100, 30);
    let (mut fresh, sent) = logged();
    fresh
        .import_attachment_intent(old.into_attachment_intent())
        .unwrap();
    assert!(geometry(&mut fresh, initial()).is_empty());
    assert_eq!(
        fresh.defer_resize(16, 0, 0),
        ResizeDisposition::Rejected(ResizeRejection::ZeroViewport)
    );
    snapshot(&mut fresh, 1, false);
    assert!(resize_records(&sent).is_empty());
    assert_eq!(fresh.resize(16, 100, 30), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 100, 30)]);
}

#[test]
fn review_early_geometry_preserves_latest_intent_across_another_transfer() {
    let (mut old, _) = logged();
    ready(&mut old);
    old.resize(16, 100, 30);
    let (mut middle, _) = logged();
    middle
        .import_attachment_intent(old.into_attachment_intent())
        .unwrap();
    assert!(geometry(&mut middle, initial()).is_empty());
    assert_eq!(
        middle.defer_resize(16, 120, 40),
        ResizeDisposition::Coalesced
    );
    let (mut fresh, sent) = logged();
    fresh
        .import_attachment_intent(middle.into_attachment_intent())
        .unwrap();
    snapshot(&mut fresh, 1, false);
    geometry(&mut fresh, initial());
    assert!(resize_records(&sent).is_empty());
    assert_eq!(fresh.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 120, 40)]);
}

#[test]
fn review_early_geometry_keeps_refusal_and_new_instance_fences() {
    for same_instance in [true, false] {
        let (mut old, _) = logged();
        ready(&mut old);
        old.resize(16, 100, 30);
        geometry(
            &mut old,
            GeometryRecord {
                request_id: 1,
                outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
                ..initial()
            },
        );
        let (mut fresh, sent) = logged();
        fresh
            .import_attachment_intent(old.into_attachment_intent())
            .unwrap();
        let instance = if same_instance { 1 } else { 2 };
        assert!(geometry(
            &mut fresh,
            GeometryRecord {
                instance: ChannelInstance::new(instance).unwrap(),
                ..initial()
            }
        )
        .is_empty());
        assert_eq!(
            fresh.defer_resize(16, 100, 30),
            ResizeDisposition::Coalesced
        );
        snapshot(&mut fresh, instance, false);
        assert!(resize_records(&sent).is_empty());
        assert_eq!(
            fresh.resize(16, 100, 30),
            if same_instance {
                ResizeDisposition::Unchanged
            } else {
                ResizeDisposition::Sent
            }
        );
    }
}

#[test]
fn review_early_geometry_keeps_a_new_local_open_intent_separate() {
    let (mut old, _) = logged();
    ready(&mut old);
    old.resize(16, 100, 30);
    let (mut fresh, sent) = logged();
    fresh
        .import_attachment_intent(old.into_attachment_intent())
        .unwrap();
    assert_eq!(fresh.open_shell(80, 24), Some(16));
    assert!(geometry(
        &mut fresh,
        GeometryRecord {
            instance: ChannelInstance::new(2).unwrap(),
            ..initial()
        }
    )
    .is_empty());
    assert_eq!(
        fresh.defer_resize(16, 120, 40),
        ResizeDisposition::Coalesced
    );
    fresh.on_bytes(
        CONTROL_STREAM,
        &encode_server(&ServerRecord::Opened { stream: 16 }),
    );
    assert!(fresh.is_ready(16));
    assert!(resize_records(&sent).is_empty());
    assert_eq!(fresh.resize(16, 120, 40), ResizeDisposition::Sent);
    assert_eq!(resize_records(&sent), vec![(1, 120, 40)]);
}

#[test]
fn unavailable_exit_waits_for_draining_geometry_and_partial_output() {
    let (mut s, _) = logged();
    let data = wire(ShellRecord::Data(b"final tail".to_vec()));
    assert!(geometry(&mut s, initial()).is_empty());
    assert!(s.on_bytes(16, &data[..6]).is_empty());
    let terminal = encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 });
    assert!(s.on_bytes(CONTROL_STREAM, &terminal).is_empty());
    assert!(s.on_bytes(CONTROL_STREAM, &terminal).is_empty());
    let announced = snapshot(&mut s, 1, true);
    assert!(announced.contains(&SessionEvent::DrainingReady(16)));
    assert!(!announced
        .iter()
        .any(|event| matches!(event, SessionEvent::ExitStatusUnavailable { .. })));
    assert_eq!(
        s.on_bytes(16, &data[6..]),
        vec![
            SessionEvent::Data {
                ch: 16,
                bytes: b"final tail".to_vec()
            },
            SessionEvent::ExitStatusUnavailable { ch: 16 },
        ]
    );
    assert!(s.on_bytes(CONTROL_STREAM, &terminal).is_empty());
    // Same-instance metadata cannot restore a terminal owner.
    assert!(!snapshot(&mut s, 1, true).iter().any(|event| matches!(
        event,
        SessionEvent::Ready(_)
            | SessionEvent::DrainingReady(_)
            | SessionEvent::ExitStatusUnavailable { .. }
    )));
}

#[test]
fn unavailable_exit_conflicts_with_a_different_terminal_outcome() {
    for unavailable_first in [true, false] {
        let (mut s, _) = logged();
        let unavailable = encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 });
        let known = encode_server(&ServerRecord::Exit {
            stream: 16,
            code: 7,
        });
        let (first, second) = if unavailable_first {
            (&unavailable, &known)
        } else {
            (&known, &unavailable)
        };
        assert!(s.on_bytes(CONTROL_STREAM, first).is_empty());
        assert_eq!(
            s.on_bytes(CONTROL_STREAM, second),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::Metadata
            )]
        );
        assert!(
            geometry(&mut s, initial()).is_empty(),
            "failure must stay sticky"
        );
    }
}

#[test]
fn unavailable_exit_leaves_a_healthy_sibling_writable() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let seen = sent.clone();
    let sink: Sink = Box::new(move |stream, bytes| {
        seen.lock().unwrap().push((stream, bytes));
    });
    let mut s = ChannelSession::new(QshSubstrate::new(sink));
    ready(&mut s);
    let sibling = s.open_shell(80, 24).unwrap();
    assert_ne!(sibling, 16);
    s.on_bytes(
        CONTROL_STREAM,
        &encode_server(&ServerRecord::Opened { stream: sibling }),
    );
    let sibling_geometry = GeometryRecord {
        instance: ChannelInstance::new(2).unwrap(),
        ..initial()
    };
    assert!(s
        .on_bytes(sibling, &wire(ShellRecord::Geometry(sibling_geometry)))
        .contains(&SessionEvent::Ready(sibling)));
    assert_eq!(
        s.on_bytes(
            CONTROL_STREAM,
            &encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 })
        ),
        vec![SessionEvent::ExitStatusUnavailable { ch: 16 }]
    );
    assert!(s.is_ready(sibling));
    assert_eq!(
        s.on_bytes(sibling, &wire(ShellRecord::Data(b"alive".to_vec()))),
        vec![SessionEvent::Data {
            ch: sibling,
            bytes: b"alive".to_vec()
        }]
    );
    s.send(sibling, b"still writable");
    assert!(sent
        .lock()
        .unwrap()
        .iter()
        .any(|(stream, bytes)| *stream == sibling && bytes == b"still writable"));
}

#[test]
fn unavailable_exit_malformed_wire_fails_sticky_at_the_client() {
    for payload in [vec![], vec![16, 0], vec![15]] {
        let (mut s, _) = logged();
        let bytes = transport::shell_frame::encode_record(0x2a, &payload);
        assert_eq!(
            s.on_bytes(CONTROL_STREAM, &bytes),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::UnexpectedRecord(0x2a)
            )]
        );
        assert!(s
            .on_bytes(
                CONTROL_STREAM,
                &encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 })
            )
            .is_empty());
    }
}

#[test]
fn unavailable_exit_occupies_one_early_terminal_slot_even_when_repeated() {
    let (mut s, _) = logged();
    let terminal = encode_server(&ServerRecord::ExitStatusUnavailable { stream: 16 });
    assert!(s.on_bytes(CONTROL_STREAM, &terminal).is_empty());
    assert!(s.on_bytes(CONTROL_STREAM, &terminal).is_empty());
    let mut batch = wire(ShellRecord::Geometry(initial()));
    for _ in 0..254 {
        batch.extend(wire(ShellRecord::Data(vec![])));
    }
    // One terminal + one geometry +254 DATA =256. Duplicate terminal is free.
    assert!(s.on_bytes(16, &batch).is_empty());
    assert_eq!(
        s.on_bytes(16, &wire(ShellRecord::Data(vec![]))),
        vec![SessionEvent::ProtocolFailure(
            ChannelProtocolError::EarlyOutputOverflow
        )]
    );
}
