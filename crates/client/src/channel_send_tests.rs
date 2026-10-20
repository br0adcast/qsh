use super::*;
use crate::qsh::QshSubstrate;
use std::sync::{Arc, Mutex};
use transport::channel::{decode_client, ClientRecord, CONTROL_STREAM};
use transport::channel_geometry::GeometryOutcome;
use transport::shell_frame::{encode_shell, RecordDeframer, ShellRecord};

fn initial() -> GeometryRecord {
    GeometryRecord {
        instance: ChannelInstance::new(1).unwrap(),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 80,
        rows: 24,
    }
}
fn shell(record: ShellRecord) -> Vec<u8> {
    encode_shell(&record).unwrap()
}

#[test]
fn all_five_qsh_producers_return_whole_local_refusal() {
    for error in [ChannelSendError::Full, ChannelSendError::Gone] {
        for producer in 0..5 {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let sent = seen.clone();
            let mut sub = QshSubstrate::new(move |stream, bytes| {
                sent.lock().unwrap().push((stream, bytes));
                Err(error)
            });
            let result = match producer {
                0 => sub.announce_term("xterm-256color"),
                1 => sub.open(&OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: Vec::new(),
                }),
                2 => sub.send(16, b"raw\x1b[A"),
                3 => sub.resize_correlated(
                    16,
                    initial().instance,
                    ResizeRequestId::new(1).unwrap(),
                    100,
                    30,
                ),
                _ => sub.close(16),
            };
            assert_eq!(result, Err(error));
            let sent = seen.lock().unwrap();
            assert_eq!(sent.len(), 1, "one complete attempt, no side queue/retry");
            assert_eq!(sent[0].0, if producer == 2 { 16 } else { CONTROL_STREAM });
            if producer == 2 {
                assert_eq!(sent[0].1, b"raw\x1b[A");
            } else {
                let raw = RecordDeframer::for_control().push(&sent[0].1);
                assert_eq!(raw.len(), 1);
                let record = decode_client(&raw[0]).unwrap();
                assert!(matches!(
                    (producer, record),
                    (0, ClientRecord::Term(_))
                        | (1, ClientRecord::Open(_))
                        | (3, ClientRecord::ResizeRequest { .. })
                        | (4, ClientRecord::Close { .. })
                ));
            }
            assert!(
                sub.protocol_error().is_none(),
                "local refusal is not remote protocol failure"
            );
        }
    }
}

#[test]
fn refused_open_close_and_resize_do_not_claim_publication() {
    for error in [ChannelSendError::Full, ChannelSendError::Gone] {
        let failure = Arc::new(Mutex::new(Some(error)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (flag, sent) = (failure.clone(), seen.clone());
        let mut session = ChannelSession::new(QshSubstrate::new(move |stream, bytes| {
            if let Some(error) = *flag.lock().unwrap() {
                return Err(error);
            }
            sent.lock().unwrap().push((stream, bytes));
            Ok(())
        }));
        assert_eq!(session.open_shell(80, 24), Err(error));
        *failure.lock().unwrap() = None;
        assert_eq!(
            session.open_shell(80, 24),
            Ok(16),
            "refusal consumed no identity"
        );
        session.on_event(SubstrateEvent::Opened(16));
        session.on_bytes(16, &shell(ShellRecord::Geometry(initial())));
        assert!(session.is_ready(16));
        *failure.lock().unwrap() = Some(error);
        assert_eq!(session.close(16), Err(error));
        assert!(
            session.is_ready(16),
            "failed Close must not retire live channel"
        );
        assert_eq!(session.resize(16, 100, 30), Err(error));
        *failure.lock().unwrap() = None;
        assert_eq!(session.resize(16, 100, 30), Ok(ResizeDisposition::Sent));
        let sent = seen.lock().unwrap();
        let raw = RecordDeframer::for_control().push(&sent.last().unwrap().1);
        assert!(
            matches!(decode_client(&raw[0]).unwrap(), ClientRecord::ResizeRequest { request_id, .. } if request_id.get() == 1)
        );
        drop(sent);
        session.close(16).unwrap();
        assert!(!session.is_ready(16));
        assert_eq!(session.send(16, b"no"), Err(ChannelSendError::NotReady));
    }
}

#[test]
fn deferred_resize_refusal_is_explicit_and_preserves_prior_output() {
    let failure = Arc::new(Mutex::new(None));
    let flag = failure.clone();
    let mut session = ChannelSession::new(QshSubstrate::new(move |_, _| {
        flag.lock().unwrap().map_or(Ok(()), Err)
    }));
    session.open_shell(80, 24).unwrap();
    session.on_event(SubstrateEvent::Opened(16));
    session.on_bytes(16, &shell(ShellRecord::Geometry(initial())));
    session.resize(16, 100, 30).unwrap();
    assert_eq!(
        session.resize(16, 120, 40),
        Ok(ResizeDisposition::Coalesced)
    );
    *failure.lock().unwrap() = Some(ChannelSendError::Full);
    let mut batch = shell(ShellRecord::Data(b"before".to_vec()));
    batch.extend(shell(ShellRecord::Geometry(GeometryRecord {
        request_id: 1,
        outcome: GeometryOutcome::Applied,
        cols: 100,
        rows: 30,
        ..initial()
    })));
    batch.extend(shell(ShellRecord::Data(b"after".to_vec())));
    let events = session.on_bytes(16, &batch);
    assert_eq!(
        events,
        vec![
            SessionEvent::Data {
                ch: 16,
                bytes: b"before".to_vec()
            },
            SessionEvent::SendFailure {
                ch: 16,
                error: ChannelSendError::Full
            }
        ]
    );
    assert!(!session.is_ready(16));
    assert!(
        session.on_bytes(16, &batch).is_empty(),
        "one terminal local failure, no replay"
    );
}

#[test]
fn optional_terminal_name_checks_maximum_before_encoding() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sent = seen.clone();
    let mut substrate = QshSubstrate::new(move |_, bytes| {
        sent.lock().unwrap().push(bytes);
        Ok(())
    });
    substrate
        .announce_term(&"x".repeat(transport::channel::MAX_TERM_LEN))
        .unwrap();
    substrate
        .announce_term(&"x".repeat(transport::channel::MAX_TERM_LEN + 1))
        .unwrap();
    let sent = seen.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "oversized optional name leaves the daemon default"
    );
    assert_eq!(sent[0].len(), transport::channel::MAX_TERM_LEN + 5);
}
