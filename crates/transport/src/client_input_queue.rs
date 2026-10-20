//! Per-stream FIFO for admitted client commands and their ACK obligations.

use std::collections::{BTreeMap, LinkedList};
use std::time::Instant;

use crate::client_input_budget::{InputPermit, INPUT_BYTES};
use crate::conn::{Connection, Datagram, LinkState};
use crate::driver_std::InputFailure;
use crate::send_gate::{GateKind, GateTable};

pub(crate) const INPUT_TURN: usize = 16;
pub(crate) const INPUT_SLICE: usize = 4096;

#[derive(Debug)]
pub(crate) struct InputRecord {
    // Field order: source storage is destroyed before its permit refunds.
    bytes: Vec<u8>,
    copied: usize,
    end: Option<u64>,
    _permit: InputPermit,
}

impl InputRecord {
    pub(crate) fn new(bytes: Vec<u8>, permit: InputPermit) -> Self {
        assert!(!bytes.is_empty());
        assert_eq!(bytes.len(), permit.len());
        Self {
            bytes,
            copied: 0,
            end: None,
            _permit: permit,
        }
    }

    pub(crate) fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

#[derive(Default)]
pub(crate) struct InputQueue {
    streams: BTreeMap<u8, LinkedList<InputRecord>>,
    next_stream: u16,
    turn_full: bool,
}

impl InputQueue {
    pub(crate) fn push(&mut self, stream: u8, record: InputRecord) {
        self.streams.entry(stream).or_default().push_back(record);
    }

    /// Only the sender's actual validated cumulative base can settle records.
    /// NotLive/LinkDown is deliberately not a refund or a queue reset.
    pub(crate) fn acknowledge(&mut self, connection: &Connection) {
        self.streams.retain(|stream, records| {
            let progress = connection.stream_progress(*stream);
            let base = progress.queued - progress.unacked;
            while records
                .front()
                .is_some_and(|record| record.end.is_some_and(|end| end <= base))
            {
                records.pop_front();
            }
            !records.is_empty()
        });
    }

    /// A bounded turn may copy prefixes of a large accepted chunk as credit
    /// permits. Later records on the same stream never bypass that chunk.
    pub(crate) fn drain(
        &mut self,
        connection: &mut Connection,
        now: Instant,
        gates: &GateTable,
    ) -> Result<Vec<Datagram>, InputFailure> {
        self.turn_full = false;
        let mut out = Vec::new();
        if connection.state() != LinkState::Live {
            return Ok(out);
        }
        let mut idle = 0;
        let mut steps = 0;
        while steps < INPUT_TURN && idle < 256 {
            let stream = self.next_stream as u8;
            self.next_stream = (self.next_stream + 1) % 256;
            idle += 1;
            let Some(records) = self.streams.get_mut(&stream) else {
                continue;
            };
            let Some(record) = records.iter_mut().find(|record| record.end.is_none()) else {
                continue;
            };
            let remaining = record.bytes.len() - record.copied;
            if remaining as u64 > connection.stream_offset_room(stream) {
                return Err(InputFailure::OffsetSpaceExhausted { stream_id: stream });
            }
            let n = remaining
                .min(INPUT_SLICE)
                .min(connection.stream_write_room(stream, INPUT_BYTES));
            if n == 0 {
                continue;
            }
            out.extend(
                connection
                    .try_send_bounded(
                        now,
                        stream,
                        &record.bytes[record.copied..record.copied + n],
                        INPUT_BYTES,
                    )
                    .expect("exclusive connection room/offset preflight"),
            );
            record.copied += n;
            let progress = connection.stream_progress(stream);
            let _ = gates
                .gate(stream, GateKind::Pipe)
                .transfer(n as u64, progress.unacked);
            if record.copied == record.bytes.len() {
                record.end = Some(progress.queued);
                // Only the reliable copy remains; the complete obligation is
                // conservatively retained until the final whole-record ACK.
                record.bytes = Vec::new();
            }
            steps += 1;
            idle = 0;
        }
        self.turn_full = steps == INPUT_TURN;
        Ok(out)
    }

    pub(crate) fn turn_full(&self) -> bool {
        self.turn_full
    }
}

/// Field order is a teardown invariant: destroy the actual reliable sender
/// before refunding any of its retained record permits to another driver.
pub(crate) struct DriverConnection {
    pub(crate) connection: Connection,
    pub(crate) inputs: InputQueue,
}
