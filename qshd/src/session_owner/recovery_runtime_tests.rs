use super::super::{authorization_contract::*, resource_contract::*};
use super::*;
use std::{cell::Cell, sync::Mutex};
use transport::channel_geometry::GeometryOutcome;
struct Host {
    client: OwnerResourceClient,
    ledger: Arc<Mutex<ResourceLedger>>,
    next: Cell<u64>,
}
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
fn channel() -> ChannelInstance {
    ChannelInstance::new(1).unwrap()
}
fn geometry() -> GeometryRecord {
    GeometryRecord {
        instance: channel(),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 80,
        rows: 24,
    }
}
impl Host {
    fn new() -> Self {
        let p = AuthenticatedPrincipalRef::new([4; 16]).unwrap();
        let l = ByteLimits {
            channel_bytes: 1 << 20,
            session_bytes: 1 << 20,
            account_bytes: 1 << 20,
            global_bytes: 1 << 20,
        };
        let mut ledger = ResourceLedger::new(
            LedgerInstance::new([5; 16]).unwrap(),
            ResourceLimits {
                max_reservations: 16,
                screen: ScreenLimits {
                    global_cells: 0,
                    account_cells: 0,
                    global_rows: 0,
                    account_rows: 0,
                    global_models: 0,
                    account_models: 0,
                },
                snapshot_transfer: l,
                control_queue: l,
            },
        )
        .unwrap();
        let reg = ledger.register_fresh_principal(p, 1000).unwrap();
        let ledger = Arc::new(Mutex::new(ledger));
        Self {
            client: OwnerResourceClient::new(ledger.clone(), reg),
            ledger,
            next: Cell::new(0),
        }
    }
    fn grant(&self, retained: usize) -> TransferAllowance {
        let id = self.next.get() + 1;
        self.next.set(id);
        let r = Reservation {
            id: ReservationId::new(id).unwrap(),
            principal: self.client.principal(),
            locator: attachment().locator,
            channel: channel(),
            kind: ReservationKind::SnapshotTransfer,
            bytes: (retained.max(1) + CHUNK_BYTES + METADATA_BYTES) as u64,
            screen_charge: None,
        };
        TransferAllowance::admit(
            self.client.clone(),
            r,
            RequestId::new(id).unwrap(),
            retained,
        )
        .unwrap()
    }
    fn producer(&self, cursor: u64, bytes: &[u8]) -> RecoveryProducer {
        RecoveryProducer::new(
            RecoveryRequest {
                attachment: attachment(),
                channel: channel(),
                parser: ParserContinuity::DataCursor {
                    cursor: OutputCursor {
                        channel: channel(),
                        offset: cursor,
                    },
                },
            },
            RecoveryId::new([6; 16]).unwrap(),
            RequestId::new(10).unwrap(),
            geometry(),
            OutputCursor {
                channel: channel(),
                offset: cursor + bytes.len() as u64,
            },
            bytes,
            self.grant(bytes.len()),
        )
        .unwrap()
    }
}
#[test]
fn recovery_consumer_retains_real_partial_record_and_rejects_recreated_cursor() {
    let h = Host::new();
    let mut consumer = NoScreenConsumer::new(channel(), h.grant(64)).unwrap();
    consumer.consume_live(0, b"record:").unwrap();
    let cursor = consumer.cursor();
    assert_eq!(cursor.offset, 7);
    let mut producer = h.producer(cursor.offset, b"tail\n");
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: channel(),
        parser: ParserContinuity::DataCursor { cursor },
    };
    let mut recreated = NoScreenConsumer::new(channel(), h.grant(64)).unwrap();
    assert!(recreated
        .begin(RequestId::new(10).unwrap(), request, producer.start())
        .is_err());
    consumer
        .begin(RequestId::new(10).unwrap(), request, producer.start())
        .unwrap();
    let (end, ready) = (
        RecoveryEnd {
            attachment: attachment(),
            channel: channel(),
            recovery_id: producer.start().recovery_id,
            total_bytes: 5,
            boundary: producer.start().boundary,
        },
        ResumeControl::RecoveryReady {
            request_id: RequestId::new(10).unwrap(),
            attachment: attachment(),
        },
    );
    assert!(
        consumer.finish(end, ready).is_err(),
        "Ready bypassed actual chunk consumption"
    );
    let mut chunk = producer.next_chunk().unwrap().unwrap();
    let id = chunk.record().recovery_id;
    chunk.record.as_mut().unwrap().recovery_id = RecoveryId::new([8; 16]).unwrap();
    assert!(consumer.consume(&chunk).is_err());
    assert_eq!(consumer.cursor(), cursor);
    chunk.record.as_mut().unwrap().recovery_id = id;
    consumer.consume(&chunk).unwrap();
    drop(chunk);
    let (end, ready) = producer.end().unwrap();
    let _completed = consumer.finish(end, ready).unwrap();
    assert_eq!(consumer.bytes(), b"record:tail\n");
    consumer.consume_live(12, b"live").unwrap();
    assert_eq!(consumer.bytes(), b"record:tail\nlive");
    drop(producer);
    drop(consumer);
    drop(recreated);
    assert_eq!(h.ledger.lock().unwrap().reservations(), 0);
}
#[test]
fn recovery_chunk_is_single_bounded_copy_and_keeps_charge_after_producer_drop() {
    let h = Host::new();
    let data = vec![b'x'; 20000];
    let mut producer = h.producer(0, &data);
    let chunk = producer.next_chunk().unwrap().unwrap();
    assert_eq!(chunk.record().data.len(), 16384);
    assert!(matches!(producer.next_chunk(), Err(RecoveryError::Busy)));
    assert!(producer.end().is_err());
    assert_eq!(h.ledger.lock().unwrap().reservations(), 1);
    drop(producer);
    assert_eq!(h.ledger.lock().unwrap().reservations(), 1);
    drop(chunk);
    assert_eq!(h.ledger.lock().unwrap().reservations(), 0);
}
#[test]
fn recovery_zero_bytes_still_checks_real_cursor_end_and_ready_correlation() {
    let h = Host::new();
    let mut producer = h.producer(0, b"");
    let mut consumer = NoScreenConsumer::new(channel(), h.grant(8)).unwrap();
    let request = RecoveryRequest {
        attachment: attachment(),
        channel: channel(),
        parser: ParserContinuity::DataCursor {
            cursor: consumer.cursor(),
        },
    };
    consumer
        .begin(RequestId::new(10).unwrap(), request, producer.start())
        .unwrap();
    assert!(producer.next_chunk().unwrap().is_none());
    let (end, ready) = producer.end().unwrap();
    assert!(consumer
        .finish(
            end,
            ResumeControl::RecoveryReady {
                request_id: RequestId::new(11).unwrap(),
                attachment: attachment()
            }
        )
        .is_err());
    let _proof = consumer.finish(end, ready).unwrap();
    assert_eq!(consumer.cursor().offset, 0);
}
