//! Bounded lifecycle discovery, including output still owed after process EOF.
use super::*;

pub const CHANNEL_IDENTITIES: usize = 256 - FIRST_CHANNEL_STREAM as usize;
pub const CHANNEL_SNAPSHOT_MAX: usize = 2
    + MAX_CHANNELS * (8 + OPEN_HEADER_LEN + MAX_COMMAND_LEN)
    + (CHANNEL_IDENTITIES - MAX_CHANNELS) * 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveChannel {
    pub instance: ChannelInstance,
    pub request: OpenRequest,
}

/// Immutable OPEN classification, not a resize result or an actual Screen claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenClassification {
    pub kind: ChannelKind,
    pub cols: u16,
    pub rows: u16,
    pub screen: bool,
}
impl OpenClassification {
    pub fn from_open(request: &OpenRequest) -> Self {
        Self {
            kind: request.kind,
            cols: request.cols,
            rows: request.rows,
            screen: request.screen,
        }
    }
    fn validate(self) -> Result<(), ChannelCodecError> {
        if self.cols != 0 && self.rows != 0 {
            terminal_size::TerminalSize::new(self.cols, self.rows)
                .map_err(|_| ChannelCodecError::Malformed)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainingChannel {
    pub stream: u8,
    pub instance: ChannelInstance,
    pub open: OpenClassification,
}

/// One atomic announcement. Ended channels are never writable active channels.
/// Boxed slices and normalized command capacities keep retained storage tied to
/// validated lengths, rather than the spare capacity of caller-owned vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSnapshot {
    active: Box<[ActiveChannel]>,
    draining: Box<[DrainingChannel]>,
}
impl ChannelSnapshot {
    pub fn new(
        mut active: Vec<ActiveChannel>,
        draining: Vec<DrainingChannel>,
    ) -> Result<Self, ChannelCodecError> {
        if active.len() > MAX_CHANNELS
            || draining.len() > CHANNEL_IDENTITIES.saturating_sub(active.len())
        {
            return Err(ChannelCodecError::Malformed);
        }
        let mut seen = [false; 256];
        for entry in &active {
            check_stream(&mut seen, entry.request.stream)?;
            OpenClassification::from_open(&entry.request).validate()?;
            if entry.request.command.len() > MAX_COMMAND_LEN
                || (entry.request.kind == ChannelKind::Shell && !entry.request.command.is_empty())
            {
                return Err(ChannelCodecError::Malformed);
            }
        }
        for entry in &draining {
            check_stream(&mut seen, entry.stream)?;
            entry.open.validate()?;
        }
        active.sort_unstable_by_key(|entry| entry.request.stream);
        for entry in &mut active {
            entry.request.command = std::mem::take(&mut entry.request.command)
                .into_boxed_slice()
                .into_vec();
        }
        let mut draining = draining.into_boxed_slice();
        draining.sort_unstable_by_key(|entry| entry.stream);
        Ok(Self {
            active: active.into_boxed_slice(),
            draining,
        })
    }
    pub fn active(&self) -> &[ActiveChannel] {
        &self.active
    }
    pub fn draining(&self) -> &[DrainingChannel] {
        &self.draining
    }
    pub fn into_parts(self) -> (Vec<ActiveChannel>, Vec<DrainingChannel>) {
        (self.active.into_vec(), self.draining.into_vec())
    }
    pub fn payload_len(&self) -> usize {
        2 + self
            .active
            .iter()
            .map(|entry| 8 + OPEN_HEADER_LEN + entry.request.command.len())
            .sum::<usize>()
            + self.draining.len() * 15
    }
    #[cfg(test)]
    fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(self.payload_len());
        self.append_payload(&mut payload);
        payload
    }
    pub fn encode_record(&self) -> Vec<u8> {
        // Write directly into the final frame: no simultaneous payload copy.
        let mut framed = Vec::with_capacity(5 + self.payload_len());
        framed.push(REC_CHANNEL_SNAPSHOT);
        framed.extend_from_slice(&(self.payload_len() as u32).to_be_bytes());
        self.append_payload(&mut framed);
        framed
    }
    fn append_payload(&self, payload: &mut Vec<u8>) {
        payload.push(self.active.len() as u8);
        for entry in &self.active {
            payload.extend_from_slice(&entry.instance.get().to_be_bytes());
            put_open(payload, &entry.request);
        }
        payload.push(self.draining.len() as u8);
        for entry in &self.draining {
            payload.push(entry.stream);
            payload.extend_from_slice(&entry.instance.get().to_be_bytes());
            payload.push(match entry.open.kind {
                ChannelKind::Shell => 0,
                ChannelKind::Command => 1,
            });
            payload.extend_from_slice(&entry.open.cols.to_be_bytes());
            payload.extend_from_slice(&entry.open.rows.to_be_bytes());
            payload.push(u8::from(entry.open.screen));
        }
    }
    pub(super) fn decode(payload: &[u8]) -> Result<Self, ChannelCodecError> {
        // Preflight the entire attacker-owned payload without allocations,
        // including counts, uniqueness, dimensions and command lengths.
        if payload.len() > CHANNEL_SNAPSHOT_MAX {
            return Err(ChannelCodecError::Malformed);
        }
        let mut cursor = Cursor {
            bytes: payload,
            pos: 0,
        };
        let active_count = cursor.take(1)?[0] as usize;
        if active_count > MAX_CHANNELS {
            return Err(ChannelCodecError::Malformed);
        }
        let mut seen = [false; 256];
        for _ in 0..active_count {
            cursor.instance()?;
            let header = cursor.take(OPEN_HEADER_LEN)?;
            check_stream(&mut seen, header[0])?;
            let open = classification(&header[1..7])?;
            let command_len = u16::from_be_bytes([header[7], header[8]]) as usize;
            if command_len > MAX_COMMAND_LEN
                || (open.kind == ChannelKind::Shell && command_len != 0)
            {
                return Err(ChannelCodecError::Malformed);
            }
            cursor.take(command_len)?;
        }
        let draining_offset = cursor.pos;
        let draining_count = cursor.take(1)?[0] as usize;
        if draining_count > CHANNEL_IDENTITIES - active_count {
            return Err(ChannelCodecError::Malformed);
        }
        for _ in 0..draining_count {
            let entry = cursor.draining()?;
            check_stream(&mut seen, entry.stream)?;
        }
        if cursor.pos != payload.len() {
            return Err(ChannelCodecError::Malformed);
        }
        cursor.pos = 1;
        let mut active = Vec::with_capacity(active_count);
        for _ in 0..active_count {
            let instance = cursor.instance()?;
            let request = take_open(payload, &mut cursor.pos)?;
            active.push(ActiveChannel { instance, request });
        }
        cursor.pos = draining_offset + 1;
        let mut draining = Vec::with_capacity(draining_count);
        for _ in 0..draining_count {
            draining.push(cursor.draining()?);
        }
        Self::new(active, draining)
    }
}

fn check_stream(seen: &mut [bool; 256], stream: u8) -> Result<(), ChannelCodecError> {
    if stream < FIRST_CHANNEL_STREAM || std::mem::replace(&mut seen[stream as usize], true) {
        return Err(ChannelCodecError::Malformed);
    }
    Ok(())
}
fn classification(bytes: &[u8]) -> Result<OpenClassification, ChannelCodecError> {
    let kind = match bytes[0] {
        0 => ChannelKind::Shell,
        1 => ChannelKind::Command,
        _ => return Err(ChannelCodecError::Malformed),
    };
    if bytes[5] & !FLAG_SCREEN != 0 {
        return Err(ChannelCodecError::Malformed);
    }
    let open = OpenClassification {
        kind,
        cols: u16::from_be_bytes([bytes[1], bytes[2]]),
        rows: u16::from_be_bytes([bytes[3], bytes[4]]),
        screen: bytes[5] != 0,
    };
    open.validate()?;
    Ok(open)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ChannelCodecError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ChannelCodecError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or(ChannelCodecError::Malformed)?;
        self.pos = end;
        Ok(bytes)
    }
    fn instance(&mut self) -> Result<ChannelInstance, ChannelCodecError> {
        ChannelInstance::new(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
            .ok_or(ChannelCodecError::Malformed)
    }
    fn draining(&mut self) -> Result<DrainingChannel, ChannelCodecError> {
        let stream = self.take(1)?[0];
        let instance = self.instance()?;
        let open = classification(self.take(6)?)?;
        Ok(DrainingChannel {
            stream,
            instance,
            open,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn active(stream: u8, command_len: usize) -> ActiveChannel {
        ActiveChannel {
            instance: ChannelInstance::new(stream as u64).unwrap(),
            request: OpenRequest {
                stream,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: vec![b'x'; command_len],
            },
        }
    }
    fn draining(stream: u8, cols: u16, rows: u16) -> DrainingChannel {
        DrainingChannel {
            stream,
            instance: ChannelInstance::new(stream as u64).unwrap(),
            open: OpenClassification {
                kind: ChannelKind::Command,
                cols,
                rows,
                screen: false,
            },
        }
    }
    #[test]
    fn snapshot_representation_inventory_is_separate_from_wire_allowances() {
        use std::mem::size_of;
        // These are actual Rust declarations, not the 15-byte wire descriptor
        // or the ten-byte Exit allowance in the shared timeline budget.
        assert!(size_of::<OpenClassification>() <= 8);
        assert!(size_of::<DrainingChannel>() <= 24);
        assert!(size_of::<ActiveChannel>() <= 48);
        assert!(size_of::<ChannelSnapshot>() <= 32);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            [
                size_of::<OpenClassification>(),
                size_of::<DrainingChannel>(),
                size_of::<ActiveChannel>(),
                size_of::<ChannelSnapshot>(),
            ],
            [6, 16, 40, 32]
        );
        assert_eq!(CHANNEL_IDENTITIES, 240);
        assert_eq!(CHANNEL_SNAPSHOT_MAX, 36_386);
    }

    #[test]
    fn maximal_snapshot_is_bounded_and_keeps_active_distinct_from_draining() {
        let snapshot = ChannelSnapshot::new(
            (16..24).map(|stream| active(stream, 4096)).collect(),
            (24..=255).map(|stream| draining(stream, 0, 24)).collect(),
        )
        .unwrap();
        assert_eq!(snapshot.payload_len(), 36_386);
        assert_eq!(snapshot.encode().len(), 36_386);
        assert_eq!(
            ChannelSnapshot::decode(&snapshot.encode()).unwrap(),
            snapshot
        );
        assert_eq!(snapshot.active().len(), 8);
        assert_eq!(snapshot.draining().len(), 232);
        assert!(snapshot
            .active()
            .iter()
            .all(|entry| entry.request.command.capacity() == 4096));
        let all_ended = ChannelSnapshot::new(
            Vec::new(),
            (16..=255).map(|stream| draining(stream, 0, 24)).collect(),
        )
        .unwrap();
        assert_eq!(all_ended.payload_len(), 3602);
        assert_eq!(
            ChannelSnapshot::decode(&all_ended.encode()).unwrap(),
            all_ended
        );
    }
    #[test]
    fn snapshot_no_pty_classification_is_exact() {
        for (cols, rows) in [(0, 24), (80, 0), (0, 0)] {
            let snapshot =
                ChannelSnapshot::new(Vec::new(), vec![draining(16, cols, rows)]).unwrap();
            let decoded = ChannelSnapshot::decode(&snapshot.encode()).unwrap();
            assert_eq!(decoded.draining()[0].open.cols, cols);
            assert_eq!(decoded.draining()[0].open.rows, rows);
        }
    }
    #[test]
    fn snapshot_wire_dictionary_round_trips_all_splits_without_changing_legacy_staging() {
        let snapshot =
            ChannelSnapshot::new(vec![active(16, 2)], vec![draining(17, 0, 24)]).unwrap();
        let framed = snapshot.encode_record();
        assert_eq!(framed[0], 0x29);
        assert_eq!(framed.len(), snapshot.payload_len() + 5);
        for split in 0..=framed.len() {
            let mut decoder = crate::shell_frame::RecordDeframer::for_control();
            let mut records = decoder.push(&framed[..split]);
            records.extend(decoder.push(&framed[split..]));
            assert_eq!(records.len(), 1);
            assert_eq!(
                decode_server(&records[0]),
                Ok(ServerRecord::ChannelSnapshot(snapshot.clone()))
            );
        }
        let maximal = ChannelSnapshot::new(
            (16..24).map(|s| active(s, 4096)).collect(),
            (24..=255).map(|s| draining(s, 0, 24)).collect(),
        )
        .unwrap()
        .encode_record();
        assert_eq!(maximal.len(), 36_391);
        assert!(maximal.len() - 5 < crate::shell_frame::CONTROL_RECORD_MAX * 3 / 4);
        assert_eq!(
            crate::shell_frame::RecordDeframer::for_control()
                .push(&maximal)
                .len(),
            1
        );
    }
    #[test]
    fn malformed_snapshot_is_rejected_before_any_codec_allocation() {
        let valid = ChannelSnapshot::new(vec![active(16, 2)], vec![draining(17, 0, 24)])
            .unwrap()
            .encode();
        let mut cases: Vec<Vec<u8>> = (0..valid.len()).map(|n| valid[..n].to_vec()).collect();
        cases.push(vec![9]);
        cases.push(vec![0, 241]);
        cases.push([valid.as_slice(), &[0]].concat());
        for (at, byte) in [
            (9, 15), // reserved active stream
            (10, 2), // invalid active kind
            (15, 2), // unknown active flag
            (16, 0x10),
            (17, 1),  // command length past the admitted payload
            (21, 16), // same stream in both lists
            (30, 2),  // invalid draining kind
            (35, 2),  // invalid draining flag
        ] {
            let mut bad = valid.clone();
            bad[at] = byte;
            cases.push(bad);
        }
        let mut zero_instance = valid.clone();
        zero_instance[1..9].fill(0);
        cases.push(zero_instance);
        for bad in cases {
            let allocations = crate::conn::tests::allocation_probe::measure(|| {
                assert_eq!(
                    ChannelSnapshot::decode(&bad),
                    Err(ChannelCodecError::Malformed)
                );
            });
            assert_eq!(allocations, 0);
        }
        assert!(
            ChannelSnapshot::new((16..25).map(|s| active(s, 0)).collect(), Vec::new()).is_err()
        );
        assert!(ChannelSnapshot::new(vec![active(16, 0)], vec![draining(16, 0, 24)]).is_err());
        assert!(ChannelSnapshot::new(Vec::new(), vec![draining(16, 1001, 24)]).is_err());
    }
}
