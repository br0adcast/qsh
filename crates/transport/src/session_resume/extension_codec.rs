use super::codec::{put_attachment, Reader};
use super::*;
use crate::channel::{ChannelSnapshot, CHANNEL_IDENTITIES, CHANNEL_SNAPSHOT_MAX};
use crate::channel_geometry::{GeometryOutcome, GeometryRecord, ResizeRefusal};
use crate::shell_frame::encode_record;
fn u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn channel(r: &mut Reader<'_>) -> Result<ChannelInstance, ResumeError> {
    ChannelInstance::new(r.u64()?).ok_or(ResumeError::Malformed)
}
fn cursor(r: &mut Reader<'_>) -> Result<OutputCursor, ResumeError> {
    Ok(OutputCursor {
        channel: channel(r)?,
        offset: r.u64()?,
    })
}
fn put_cursor(out: &mut Vec<u8>, c: OutputCursor) {
    u64(out, c.channel.get());
    u64(out, c.offset);
}
pub(super) fn put_geometry(out: &mut Vec<u8>, g: GeometryRecord) {
    u64(out, g.instance.get());
    u64(out, g.request_id);
    let (outcome, reason) = match g.outcome {
        GeometryOutcome::Established => (0, 0),
        GeometryOutcome::Applied => (1, 0),
        GeometryOutcome::Refused(r) => (2, r as u8),
    };
    out.push(outcome);
    out.push(reason);
    out.extend_from_slice(&g.cols.to_be_bytes());
    out.extend_from_slice(&g.rows.to_be_bytes());
}
pub(super) fn geometry(r: &mut Reader<'_>) -> Result<GeometryRecord, ResumeError> {
    let instance = channel(r)?;
    let request_id = r.u64()?;
    let outcome = r.byte()?;
    let reason = r.byte()?;
    let outcome = match (outcome, reason) {
        (0, 0) => GeometryOutcome::Established,
        (1, 0) => GeometryOutcome::Applied,
        (2, reason) => GeometryOutcome::Refused(
            ResizeRefusal::from_wire(reason).ok_or(ResumeError::Malformed)?,
        ),
        _ => return Err(ResumeError::Malformed),
    };
    let g = GeometryRecord {
        instance,
        request_id,
        outcome,
        cols: u16::from_be_bytes(r.array()?),
        rows: u16::from_be_bytes(r.array()?),
    };
    g.validate().map_err(|_| ResumeError::Malformed)?;
    Ok(g)
}
fn put_target(out: &mut Vec<u8>, target: CloseTarget) {
    match target {
        CloseTarget::Session => {
            out.push(0);
            u64(out, 0);
        }
        CloseTarget::Channel(c) => {
            out.push(1);
            u64(out, c.get());
        }
    }
}
fn target(r: &mut Reader<'_>) -> Result<CloseTarget, ResumeError> {
    let kind = r.byte()?;
    let id = r.u64()?;
    match (kind, id) {
        (0, 0) => Ok(CloseTarget::Session),
        (1, id) => Ok(CloseTarget::Channel(
            ChannelInstance::new(id).ok_or(ResumeError::Malformed)?,
        )),
        _ => Err(ResumeError::Malformed),
    }
}
pub(super) fn encode_control(c: &ResumeControl) -> Result<Vec<u8>, ResumeError> {
    let len = match c {
        ResumeControl::Catalog { catalog, .. } => {
            8 + 56 + 4 + catalog.channels().payload_len() + 2 + catalog.positions().len() * 79
        }
        ResumeControl::CatalogRequest { .. } | ResumeControl::RecoveryReady { .. } => 64,
        ResumeControl::RecoveryRequest { request, .. } => {
            64 + 8
                + match request.parser {
                    ParserContinuity::Recreated => 1,
                    ParserContinuity::DataCursor { cursor } => {
                        if cursor.channel != request.channel {
                            return Err(ResumeError::Malformed);
                        }
                        17
                    }
                    ParserContinuity::Retained {
                        parser_instance,
                        cursor,
                    } => {
                        if parser_instance == [0; 16] || cursor.channel != request.channel {
                            return Err(ResumeError::Malformed);
                        }
                        33
                    }
                }
        }
        ResumeControl::CloseChannel { .. } => 73,
        ResumeControl::CloseSession { .. } => 65,
        ResumeControl::CloseAccepted { .. } => 73,
        ResumeControl::ExitReceipt(_) => 77,
        _ => return Err(ResumeError::UnknownKind(c.kind())),
    };
    if len > MAX_RESUME_PAYLOAD {
        return Err(ResumeError::TooLarge);
    }
    let mut out = Vec::with_capacity(len);
    if let Some(id) = c.request_id() {
        u64(&mut out, id.get());
    }
    match c {
        ResumeControl::CatalogRequest { attachment, .. }
        | ResumeControl::RecoveryReady { attachment, .. } => put_attachment(&mut out, *attachment),
        ResumeControl::Catalog { catalog, .. } => {
            put_attachment(&mut out, catalog.attachment());
            let snapshot = catalog.channels().encode_record();
            out.extend_from_slice(&((snapshot.len() - 5) as u32).to_be_bytes());
            out.extend_from_slice(&snapshot[5..]);
            out.extend_from_slice(&(catalog.positions().len() as u16).to_be_bytes());
            for p in catalog.positions() {
                u64(&mut out, p.channel.get());
                out.extend_from_slice(p.input.epoch.as_bytes());
                u64(&mut out, p.input.accepted);
                u64(&mut out, p.input.committed);
                put_cursor(&mut out, p.output);
                put_geometry(&mut out, p.geometry);
                out.push(match p.lifecycle {
                    ChannelLifecycle::Active => 1,
                    ChannelLifecycle::Draining => 2,
                    ChannelLifecycle::Exited => 3,
                });
            }
        }
        ResumeControl::RecoveryRequest { request, .. } => {
            put_attachment(&mut out, request.attachment);
            u64(&mut out, request.channel.get());
            match request.parser {
                ParserContinuity::Recreated => out.push(0),
                ParserContinuity::DataCursor { cursor } => {
                    out.push(2);
                    put_cursor(&mut out, cursor);
                }
                ParserContinuity::Retained {
                    parser_instance,
                    cursor,
                } => {
                    if parser_instance == [0; 16] || cursor.channel != request.channel {
                        return Err(ResumeError::Malformed);
                    }
                    out.push(1);
                    out.extend_from_slice(&parser_instance);
                    put_cursor(&mut out, cursor);
                }
            }
        }
        ResumeControl::CloseChannel { close, .. } => {
            put_attachment(&mut out, close.attachment);
            u64(&mut out, close.channel.get());
            out.push(close.reason.to_wire());
        }
        ResumeControl::CloseSession { close, .. } => {
            put_attachment(&mut out, close.attachment);
            out.push(close.reason.to_wire());
        }
        ResumeControl::CloseAccepted { accepted, .. } => {
            put_attachment(&mut out, accepted.attachment);
            put_target(&mut out, accepted.target);
        }
        ResumeControl::ExitReceipt(receipt) => {
            put_attachment(&mut out, receipt.attachment);
            u64(&mut out, receipt.channel.get());
            u64(&mut out, receipt.receipt_id.get());
            let (fact, status) = match receipt.fact {
                ExitFact::Reaped { status } => (1, status),
                ExitFact::NoChild => (2, 0),
                ExitFact::StatusUnavailable => (3, 0),
            };
            out.push(fact);
            out.extend_from_slice(&status.to_be_bytes());
        }
        _ => return Err(ResumeError::UnknownKind(c.kind())),
    }
    Ok(encode_record(c.kind(), &out))
}
pub(super) fn decode_control(kind: u8, payload: &[u8]) -> Result<ResumeControl, ResumeError> {
    if !matches!(kind, 0x36..=0x3d) {
        return Err(ResumeError::UnknownKind(kind));
    }
    let mut r = Reader::new(payload)?;
    let id = if kind == 0x3d {
        None
    } else {
        Some(r.request()?)
    };
    let attachment = r.attachment()?;
    let record = match kind {
        0x36 => ResumeControl::CatalogRequest {
            request_id: id.unwrap(),
            attachment,
        },
        0x37 => {
            let len = u32::from_be_bytes(r.array()?) as usize;
            if len > CHANNEL_SNAPSHOT_MAX {
                return Err(ResumeError::TooLarge);
            }
            let snapshot = r.take(len)?;
            // Preflight position count and exact remaining size before nested allocation.
            let count = u16::from_be_bytes(r.array()?) as usize;
            if count > CHANNEL_IDENTITIES {
                return Err(ResumeError::TooLarge);
            }
            let positions_bytes = r.take(count.checked_mul(79).ok_or(ResumeError::Overflow)?)?;
            r.finish()?;
            let channels =
                ChannelSnapshot::decode_payload(snapshot).map_err(|_| ResumeError::Malformed)?;
            let mut positions = Vec::with_capacity(count);
            let mut p = Reader::new(positions_bytes)?;
            for _ in 0..count {
                let channel = channel(&mut p)?;
                let input = InputPosition {
                    epoch: InputEpoch::new(p.array()?).ok_or(ResumeError::Malformed)?,
                    accepted: p.u64()?,
                    committed: p.u64()?,
                };
                input.validate()?;
                let output = cursor(&mut p)?;
                let geometry = geometry(&mut p)?;
                let lifecycle = match p.byte()? {
                    1 => ChannelLifecycle::Active,
                    2 => ChannelLifecycle::Draining,
                    3 => ChannelLifecycle::Exited,
                    _ => return Err(ResumeError::Malformed),
                };
                positions.push(ChannelPosition {
                    channel,
                    input,
                    output,
                    geometry,
                    lifecycle,
                });
            }
            return Ok(ResumeControl::Catalog {
                request_id: id.unwrap(),
                catalog: RetainedCatalog::new(attachment, channels, positions)?,
            });
        }
        0x38 => {
            let channel = channel(&mut r)?;
            let parser = match r.byte()? {
                0 => ParserContinuity::Recreated,
                2 => {
                    let cursor = cursor(&mut r)?;
                    if cursor.channel != channel {
                        return Err(ResumeError::Malformed);
                    }
                    ParserContinuity::DataCursor { cursor }
                }
                1 => {
                    let parser_instance = r.array()?;
                    let cursor = cursor(&mut r)?;
                    if parser_instance == [0; 16] || cursor.channel != channel {
                        return Err(ResumeError::Malformed);
                    }
                    ParserContinuity::Retained {
                        parser_instance,
                        cursor,
                    }
                }
                _ => return Err(ResumeError::Malformed),
            };
            ResumeControl::RecoveryRequest {
                request_id: id.unwrap(),
                request: RecoveryRequest {
                    attachment,
                    channel,
                    parser,
                },
            }
        }
        0x39 => ResumeControl::RecoveryReady {
            request_id: id.unwrap(),
            attachment,
        },
        0x3a => ResumeControl::CloseChannel {
            request_id: id.unwrap(),
            close: OwnerCloseChannel {
                attachment,
                channel: channel(&mut r)?,
                reason: CloseReason::from_wire(r.byte()?).ok_or(ResumeError::Malformed)?,
            },
        },
        0x3b => ResumeControl::CloseSession {
            request_id: id.unwrap(),
            close: OwnerCloseSession {
                attachment,
                reason: CloseReason::from_wire(r.byte()?).ok_or(ResumeError::Malformed)?,
            },
        },
        0x3c => ResumeControl::CloseAccepted {
            request_id: id.unwrap(),
            accepted: CloseAccepted {
                attachment,
                target: target(&mut r)?,
            },
        },
        0x3d => {
            let channel = channel(&mut r)?;
            let receipt_id = r.request()?;
            let code = r.byte()?;
            let status = i32::from_be_bytes(r.array()?);
            let fact = match (code, status) {
                (1, status) => ExitFact::Reaped { status },
                (2, 0) => ExitFact::NoChild,
                (3, 0) => ExitFact::StatusUnavailable,
                _ => return Err(ResumeError::Malformed),
            };
            ResumeControl::ExitReceipt(ExitReceipt {
                attachment,
                channel,
                receipt_id,
                fact,
            })
        }
        other => return Err(ResumeError::UnknownKind(other)),
    };
    r.finish()?;
    Ok(record)
}
pub(super) fn encode_data(d: &ResumeData) -> Result<Vec<u8>, ResumeError> {
    let len = match d {
        ResumeData::RecoveryStart(s) => {
            s.validate()?;
            130
        }
        ResumeData::RecoveryChunk(c) => {
            if c.data.is_empty() || c.data.len() > MAX_RESUME_DATA {
                return Err(ResumeError::TooLarge);
            }
            checked_end(c.offset, c.data.len())?;
            92 + c.data.len()
        }
        ResumeData::RecoveryEnd(e) => {
            if e.channel != e.boundary.channel {
                return Err(ResumeError::Malformed);
            }
            104
        }
        ResumeData::RecoveryBlocked(b) => {
            if b.channel != b.boundary.channel {
                return Err(ResumeError::Malformed);
            }
            80
        }
        _ => return Err(ResumeError::UnknownKind(d.kind())),
    };
    let mut out = Vec::with_capacity(len);
    put_attachment(&mut out, d.attachment());
    match d {
        ResumeData::RecoveryStart(s) => {
            u64(&mut out, s.channel.get());
            out.extend_from_slice(s.recovery_id.as_bytes());
            out.push(match s.mode {
                RecoveryMode::Replay => 1,
                RecoveryMode::ScreenReset => 2,
            });
            put_cursor(&mut out, s.boundary);
            out.push(u8::from(s.gap));
            put_geometry(&mut out, s.geometry);
            u64(&mut out, s.total_bytes);
            out.extend_from_slice(&s.snapshot_version.to_be_bytes());
        }
        ResumeData::RecoveryChunk(c) => {
            u64(&mut out, c.channel.get());
            out.extend_from_slice(c.recovery_id.as_bytes());
            u64(&mut out, c.offset);
            out.extend_from_slice(&(c.data.len() as u32).to_be_bytes());
            out.extend_from_slice(&c.data);
        }
        ResumeData::RecoveryEnd(e) => {
            u64(&mut out, e.channel.get());
            out.extend_from_slice(e.recovery_id.as_bytes());
            u64(&mut out, e.total_bytes);
            put_cursor(&mut out, e.boundary);
        }
        ResumeData::RecoveryBlocked(b) => {
            u64(&mut out, b.channel.get());
            put_cursor(&mut out, b.boundary);
        }
        _ => unreachable!(),
    }
    Ok(encode_record(d.kind(), &out))
}
pub(super) fn decode_data(kind: u8, payload: &[u8]) -> Result<ResumeData, ResumeError> {
    if !matches!(kind, 0x44..=0x47) {
        return Err(ResumeError::UnknownKind(kind));
    }
    let mut r = Reader::new(payload)?;
    let attachment = r.attachment()?;
    let channel = channel(&mut r)?;
    let record = match kind {
        0x44 => {
            let recovery_id = RecoveryId::new(r.array()?).ok_or(ResumeError::Malformed)?;
            let mode = match r.byte()? {
                1 => RecoveryMode::Replay,
                2 => RecoveryMode::ScreenReset,
                _ => return Err(ResumeError::Malformed),
            };
            let boundary = cursor(&mut r)?;
            let gap = match r.byte()? {
                0 => false,
                1 => true,
                _ => return Err(ResumeError::Malformed),
            };
            let geometry = geometry(&mut r)?;
            let total_bytes = r.u64()?;
            let snapshot_version = u16::from_be_bytes(r.array()?);
            let start = RecoveryStart {
                attachment,
                channel,
                recovery_id,
                mode,
                boundary,
                gap,
                geometry,
                total_bytes,
                snapshot_version,
            };
            start.validate()?;
            ResumeData::RecoveryStart(start)
        }
        0x45 => {
            let recovery_id = RecoveryId::new(r.array()?).ok_or(ResumeError::Malformed)?;
            let offset = r.u64()?;
            let data = r.chunk(offset)?;
            if data.is_empty() {
                return Err(ResumeError::Malformed);
            }
            ResumeData::RecoveryChunk(RecoveryChunk {
                attachment,
                channel,
                recovery_id,
                offset,
                data,
            })
        }
        0x46 => {
            let recovery_id = RecoveryId::new(r.array()?).ok_or(ResumeError::Malformed)?;
            let total_bytes = r.u64()?;
            let boundary = cursor(&mut r)?;
            if channel != boundary.channel {
                return Err(ResumeError::Malformed);
            }
            ResumeData::RecoveryEnd(RecoveryEnd {
                attachment,
                channel,
                recovery_id,
                total_bytes,
                boundary,
            })
        }
        0x47 => {
            let boundary = cursor(&mut r)?;
            if channel != boundary.channel {
                return Err(ResumeError::Malformed);
            }
            ResumeData::RecoveryBlocked(RecoveryBlocked {
                attachment,
                channel,
                boundary,
            })
        }
        other => return Err(ResumeError::UnknownKind(other)),
    };
    r.finish()?;
    Ok(record)
}
