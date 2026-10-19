//! One envelope at a time. Fixed headers and checked declared reservations avoid
//! allocating a bulk deframer result before ChannelSession can admit its events.
use crate::channel::{ChannelProtocolError, InputLimits, InputUsage};
use transport::shell_frame::{RawRecord, CONTROL_RECORD_MAX, RECORD_MAX, REC_DATA};

const DATA_CHUNK: usize = 64 * 1024;
#[derive(Default)]
pub(super) struct Input {
    header: [u8; 5],
    header_len: usize,
    remaining: Option<usize>,
    payload: Vec<u8>,
    charge: usize,
}
impl Input {
    pub(super) fn usage(&self) -> InputUsage {
        InputUsage {
            bytes: self.charge,
            events: usize::from(self.header_len != 0),
        }
    }
    pub(super) fn partial(&self) -> bool {
        self.header_len != 0
    }
    pub(super) fn step(
        &mut self,
        input: &[u8],
        limits: InputLimits,
        control: bool,
    ) -> Result<(usize, Option<RawRecord>), ChannelProtocolError> {
        let mut consumed = 0;
        if self.header_len == 0 && !input.is_empty() {
            if limits.events == 0 || limits.bytes < 5 {
                return Err(ChannelProtocolError::EarlyOutputOverflow);
            }
            self.charge = 5;
        }
        if self.header_len < 5 {
            let n = (5 - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + n].copy_from_slice(&input[..n]);
            self.header_len += n;
            consumed += n;
            if self.header_len < 5 {
                return Ok((consumed, None));
            }
            let len = u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize;
            let max = if control {
                CONTROL_RECORD_MAX
            } else {
                RECORD_MAX
            };
            let skipped = !control && self.header[0] > 3;
            if len > max
                || (!skipped && len > limits.bytes.saturating_sub(5))
                || (!control && self.header[0] == REC_DATA && len > limits.payload)
            {
                return Err(ChannelProtocolError::EarlyOutputOverflow);
            }
            // Fixed-sized known shell records cannot justify arbitrary allocation.
            if !control && matches!(self.header[0], 1..=3) {
                let expected = match self.header[0] {
                    1 => 8,
                    2 => 22,
                    _ => 9,
                };
                if len != expected {
                    return Err(ChannelProtocolError::Shell(
                        transport::shell_frame::ShellCodecError::Malformed,
                    ));
                }
            }
            self.remaining = Some(len);
            let capacity = if !control && self.header[0] == REC_DATA {
                len.min(DATA_CHUNK)
            } else {
                len
            };
            // Unknown shell extensions are skipped without allocating their body.
            let capacity = if !control && self.header[0] > 3 {
                0
            } else {
                capacity
            };
            self.payload = Vec::with_capacity(capacity);
            self.charge = 5 + capacity;
        }
        let remaining = self.remaining.expect("complete header");
        let skipped = !control && self.header[0] > 3;
        let room = if skipped {
            remaining
        } else {
            self.payload.capacity() - self.payload.len()
        };
        let n = room.min(remaining).min(input.len() - consumed);
        if !skipped {
            self.payload
                .extend_from_slice(&input[consumed..consumed + n]);
        }
        consumed += n;
        let left = remaining - n;
        self.remaining = Some(left);
        if left != 0 && (skipped || self.payload.len() < self.payload.capacity()) {
            return Ok((consumed, None));
        }
        let record = RawRecord {
            kind: self.header[0],
            payload: std::mem::take(&mut self.payload),
        };
        if left == 0 {
            *self = Self::default();
        } else {
            self.payload = Vec::with_capacity(left.min(DATA_CHUNK));
            self.charge = 5 + self.payload.capacity();
        }
        Ok((consumed, Some(record)))
    }
}
