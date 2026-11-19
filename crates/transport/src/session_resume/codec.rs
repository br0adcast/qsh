//! Strict codecs for the reserved retained-session record ranges.
use super::*;
use crate::shell_frame::{encode_record, RawRecord};

fn enabled(features: Features) -> Result<(), ResumeError> {
    if features.contains(Features::SESSION_RESUME) {
        Ok(())
    } else {
        Err(ResumeError::FeatureRequired)
    }
}
pub(super) fn put_locator(out: &mut Vec<u8>, locator: SessionLocator) {
    out.extend_from_slice(locator.session.as_bytes());
    out.extend_from_slice(locator.owner.as_bytes());
}
pub(super) fn put_attachment(out: &mut Vec<u8>, attachment: Attachment) {
    put_locator(out, attachment.locator);
    out.extend_from_slice(attachment.frontend.as_bytes());
    out.extend_from_slice(&attachment.epoch.get().to_be_bytes());
}

pub fn encode_control(record: &ResumeControl, features: Features) -> Result<Vec<u8>, ResumeError> {
    enabled(features)?;
    if record.kind() >= 0x36 {
        return super::extension_codec::encode_control(record);
    }
    let mut out = Vec::with_capacity(64);
    match record {
        ResumeControl::Attach {
            request_id,
            locator,
            frontend,
            last_epoch,
        } => {
            out.extend_from_slice(&request_id.get().to_be_bytes());
            put_locator(&mut out, *locator);
            out.extend_from_slice(frontend.as_bytes());
            out.extend_from_slice(&last_epoch.to_be_bytes());
        }
        ResumeControl::Attached {
            request_id,
            attachment,
        }
        | ResumeControl::Fence {
            request_id,
            attachment,
        }
        | ResumeControl::Fenced {
            request_id,
            attachment,
        } => {
            out.extend_from_slice(&request_id.get().to_be_bytes());
            put_attachment(&mut out, *attachment);
        }
        ResumeControl::AttachRefused { request_id, reason } => {
            out.extend_from_slice(&request_id.get().to_be_bytes());
            out.push(reason.to_wire());
        }
        ResumeControl::Detach { attachment, reason } => {
            put_attachment(&mut out, *attachment);
            out.push(reason.to_wire());
        }
        _ => unreachable!("extension dispatched above"),
    }
    Ok(encode_record(record.kind(), &out))
}

pub fn decode_control(raw: RawRecord, features: Features) -> Result<ResumeControl, ResumeError> {
    decode_control_payload(raw.kind, &raw.payload, features)
}

pub fn decode_control_payload(
    kind: u8,
    payload: &[u8],
    features: Features,
) -> Result<ResumeControl, ResumeError> {
    enabled(features)?;
    if kind >= 0x36 {
        return super::extension_codec::decode_control(kind, payload);
    }
    let mut r = Reader::new(payload)?;
    let record = match kind {
        0x30 => ResumeControl::Attach {
            request_id: r.request()?,
            locator: r.locator()?,
            frontend: FrontendGeneration::new(r.array()?).ok_or(ResumeError::Malformed)?,
            last_epoch: r.u64()?,
        },
        0x31 => ResumeControl::Attached {
            request_id: r.request()?,
            attachment: r.attachment()?,
        },
        0x32 => ResumeControl::AttachRefused {
            request_id: r.request()?,
            reason: AttachRefusal::from_wire(r.byte()?).ok_or(ResumeError::Malformed)?,
        },
        0x33 => ResumeControl::Detach {
            attachment: r.attachment()?,
            reason: DetachReason::from_wire(r.byte()?).ok_or(ResumeError::Malformed)?,
        },
        0x34 => ResumeControl::Fence {
            request_id: r.request()?,
            attachment: r.attachment()?,
        },
        0x35 => ResumeControl::Fenced {
            request_id: r.request()?,
            attachment: r.attachment()?,
        },
        kind => return Err(ResumeError::UnknownKind(kind)),
    };
    r.finish()?;
    Ok(record)
}

pub fn encode_data(record: &ResumeData, features: Features) -> Result<Vec<u8>, ResumeError> {
    enabled(features)?;
    if record.kind() >= 0x44 {
        return super::extension_codec::encode_data(record);
    }
    let payload_len = match record {
        ResumeData::Input { data, offset, .. } | ResumeData::Output { data, offset, .. } => {
            if data.len() > MAX_RESUME_DATA {
                return Err(ResumeError::TooLarge);
            }
            checked_end(*offset, data.len())?;
            let fixed = if matches!(record, ResumeData::Input { .. }) {
                92
            } else {
                76
            };
            fixed + data.len()
        }
        ResumeData::InputAck { position, .. } => {
            position.validate()?;
            96
        }
        ResumeData::OutputAck { .. } => 72,
        _ => unreachable!("extension dispatched above"),
    };
    let mut out = Vec::with_capacity(payload_len);
    put_attachment(&mut out, record.attachment());
    match record {
        ResumeData::Input {
            channel,
            epoch,
            offset,
            data,
            ..
        } => {
            out.extend_from_slice(&channel.get().to_be_bytes());
            out.extend_from_slice(epoch.as_bytes());
            put_chunk(&mut out, *offset, data);
        }
        ResumeData::InputAck {
            channel, position, ..
        } => {
            out.extend_from_slice(&channel.get().to_be_bytes());
            out.extend_from_slice(position.epoch.as_bytes());
            out.extend_from_slice(&position.accepted.to_be_bytes());
            out.extend_from_slice(&position.committed.to_be_bytes());
        }
        ResumeData::Output {
            channel,
            offset,
            data,
            ..
        } => {
            out.extend_from_slice(&channel.get().to_be_bytes());
            put_chunk(&mut out, *offset, data);
        }
        ResumeData::OutputAck { cursor, .. } => {
            out.extend_from_slice(&cursor.channel.get().to_be_bytes());
            out.extend_from_slice(&cursor.offset.to_be_bytes());
        }
        _ => unreachable!("extension dispatched above"),
    }
    Ok(encode_record(record.kind(), &out))
}
fn put_chunk(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

pub fn decode_data(raw: RawRecord, features: Features) -> Result<ResumeData, ResumeError> {
    decode_data_payload(raw.kind, &raw.payload, features)
}

pub fn decode_data_payload(
    kind: u8,
    payload: &[u8],
    features: Features,
) -> Result<ResumeData, ResumeError> {
    enabled(features)?;
    if kind >= 0x44 {
        return super::extension_codec::decode_data(kind, payload);
    }
    let mut r = Reader::new(payload)?;
    if !matches!(kind, 0x40..=0x43) {
        return Err(ResumeError::UnknownKind(kind));
    }
    let attachment = r.attachment()?;
    let channel = ChannelInstance::new(r.u64()?).ok_or(ResumeError::Malformed)?;
    let record = match kind {
        0x40 => {
            let epoch = InputEpoch::new(r.array()?).ok_or(ResumeError::Malformed)?;
            let offset = r.u64()?;
            ResumeData::Input {
                attachment,
                channel,
                epoch,
                offset,
                data: r.chunk(offset)?,
            }
        }
        0x41 => {
            let position = InputPosition {
                epoch: InputEpoch::new(r.array()?).ok_or(ResumeError::Malformed)?,
                accepted: r.u64()?,
                committed: r.u64()?,
            };
            position.validate()?;
            ResumeData::InputAck {
                attachment,
                channel,
                position,
            }
        }
        0x42 => {
            let offset = r.u64()?;
            ResumeData::Output {
                attachment,
                channel,
                offset,
                data: r.chunk(offset)?,
            }
        }
        0x43 => ResumeData::OutputAck {
            attachment,
            cursor: OutputCursor {
                channel,
                offset: r.u64()?,
            },
        },
        _ => unreachable!("kind checked above"),
    };
    r.finish()?;
    Ok(record)
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self, ResumeError> {
        if bytes.len() > MAX_RESUME_PAYLOAD {
            return Err(ResumeError::TooLarge);
        }
        Ok(Self { bytes, pos: 0 })
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], ResumeError> {
        let end = self.pos.checked_add(N).ok_or(ResumeError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or(ResumeError::Malformed)?;
        self.pos = end;
        Ok(bytes.try_into().expect("fixed slice length"))
    }
    pub(super) fn byte(&mut self) -> Result<u8, ResumeError> {
        Ok(self.array::<1>()?[0])
    }
    pub(super) fn u64(&mut self) -> Result<u64, ResumeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub(super) fn request(&mut self) -> Result<RequestId, ResumeError> {
        RequestId::new(self.u64()?).ok_or(ResumeError::Malformed)
    }
    pub(super) fn locator(&mut self) -> Result<SessionLocator, ResumeError> {
        Ok(SessionLocator {
            session: RetainedSessionId::new(self.array()?).ok_or(ResumeError::Malformed)?,
            owner: OwnerInstance::new(self.array()?).ok_or(ResumeError::Malformed)?,
        })
    }
    pub(super) fn attachment(&mut self) -> Result<Attachment, ResumeError> {
        Ok(Attachment {
            locator: self.locator()?,
            frontend: FrontendGeneration::new(self.array()?).ok_or(ResumeError::Malformed)?,
            epoch: AttachEpoch::new(self.u64()?).ok_or(ResumeError::Malformed)?,
        })
    }
    pub(super) fn chunk(&mut self, offset: u64) -> Result<Vec<u8>, ResumeError> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > MAX_RESUME_DATA {
            return Err(ResumeError::TooLarge);
        }
        checked_end(offset, len)?;
        if self.bytes.len() - self.pos != len {
            return Err(ResumeError::Malformed);
        }
        let data = self.bytes[self.pos..].to_vec();
        self.pos = self.bytes.len();
        Ok(data)
    }
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], ResumeError> {
        let end = self.pos.checked_add(len).ok_or(ResumeError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or(ResumeError::Malformed)?;
        self.pos = end;
        Ok(bytes)
    }
    pub(super) fn finish(self) -> Result<(), ResumeError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ResumeError::Malformed)
        }
    }
}
