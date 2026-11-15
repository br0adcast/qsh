//! Fixed private setup data. Decoding this record never creates admission authority.
use super::super::local_channel::AdmissionError;
use nix::libc;
use std::time::{Duration, Instant};
use transport::session_resume::HostInstance;

pub(super) const RECORD_LEN: usize = 112;
#[derive(Debug)]
pub(in crate::session_owner) struct SetupRecord {
    pub(in crate::session_owner) host: HostInstance,
    pub(in crate::session_owner) channel: [u8; 16],
    pub(in crate::session_owner) challenge: [u8; 32],
    pub(in crate::session_owner) uid: u32,
    pub(in crate::session_owner) deadline: u64,
}
impl SetupRecord {
    pub(super) fn decode(bytes: &[u8], uid: u32, now: u64) -> Result<Self, AdmissionError> {
        if bytes.len() != RECORD_LEN
            || &bytes[..8] != b"QSHL5291"
            || bytes[8..12] != [0, 1, 0, 112]
            || bytes[80..88] != [2, 1, 0, 1, 0, 1, 0, 0]
            || bytes[96..104] != 1u64.to_be_bytes()
            || bytes[104..112] != [0; 8]
            || bytes[28..44] == [0; 16]
            || bytes[44..76] == [0; 32]
            || uid == 0
            || bytes[76..80] != uid.to_be_bytes()
        {
            return Err(AdmissionError::Refused);
        }
        let deadline = u64::from_be_bytes(bytes[88..96].try_into().unwrap());
        if deadline <= now {
            return Err(AdmissionError::Deadline);
        }
        Ok(Self {
            host: HostInstance::new(bytes[12..28].try_into().unwrap())
                .ok_or(AdmissionError::Refused)?,
            channel: bytes[28..44].try_into().unwrap(),
            challenge: bytes[44..76].try_into().unwrap(),
            uid,
            deadline,
        })
    }
    pub(super) fn prefix_deadline(
        prefix: &[u8],
        uid: u32,
        now: u64,
    ) -> Result<u64, AdmissionError> {
        if prefix.len() != 96 {
            return Err(AdmissionError::Refused);
        }
        let mut bytes = [0; RECORD_LEN];
        bytes[..96].copy_from_slice(prefix);
        bytes[96..104].copy_from_slice(&1u64.to_be_bytes());
        Self::decode(&bytes, uid, now).map(|record| record.deadline)
    }
    pub(super) fn encode(&self) -> [u8; RECORD_LEN] {
        let mut bytes = [0; RECORD_LEN];
        bytes[..8].copy_from_slice(b"QSHL5291");
        bytes[8..12].copy_from_slice(&[0, 1, 0, 112]);
        bytes[12..28].copy_from_slice(self.host.as_bytes());
        bytes[28..44].copy_from_slice(&self.channel);
        bytes[44..76].copy_from_slice(&self.challenge);
        bytes[76..80].copy_from_slice(&self.uid.to_be_bytes());
        bytes[80..88].copy_from_slice(&[2, 1, 0, 1, 0, 1, 0, 0]);
        bytes[88..96].copy_from_slice(&self.deadline.to_be_bytes());
        bytes[96..104].copy_from_slice(&1u64.to_be_bytes());
        bytes
    }
}

pub(super) fn monotonic_now() -> Result<u64, AdmissionError> {
    let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut sample) } != 0
        || sample.tv_sec < 0
        || !(0..1_000_000_000).contains(&sample.tv_nsec)
    {
        return Err(AdmissionError::Unavailable);
    }
    u64::try_from(sample.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|ns| ns.checked_add(sample.tv_nsec as u64))
        .ok_or(AdmissionError::Unavailable)
}

pub(super) struct LaunchDeadline {
    local: Instant,
    absolute: u64,
}
impl LaunchDeadline {
    pub(super) fn new(deadline: Instant) -> Result<Self, AdmissionError> {
        // Sampling monotonic first can shorten, but cannot extend, the deadline.
        let mono = monotonic_now()?;
        Self::from_samples(deadline, Instant::now(), mono)
    }
    pub(super) fn from_samples(
        deadline: Instant,
        now: Instant,
        mono: u64,
    ) -> Result<Self, AdmissionError> {
        let left = deadline
            .checked_duration_since(now)
            .filter(|d| !d.is_zero())
            .ok_or(AdmissionError::Deadline)?;
        let left = u64::try_from(left.as_nanos()).map_err(|_| AdmissionError::Deadline)?;
        Ok(Self {
            local: deadline,
            absolute: mono.checked_add(left).ok_or(AdmissionError::Deadline)?,
        })
    }
    pub(super) fn absolute(&self) -> u64 {
        self.absolute
    }
    pub(super) fn local(&self) -> Instant {
        self.local
    }
    pub(super) fn child_local(absolute: u64) -> Result<Instant, AdmissionError> {
        // Reverse sampling order also conservatively shortens the child limit.
        let now = Instant::now();
        Self::local_from_samples(absolute, monotonic_now()?, now)
    }
    pub(super) fn local_from_samples(
        absolute: u64,
        mono: u64,
        now: Instant,
    ) -> Result<Instant, AdmissionError> {
        let left = absolute
            .checked_sub(mono)
            .filter(|n| *n > 0)
            .ok_or(AdmissionError::Deadline)?;
        now.checked_add(Duration::from_nanos(left))
            .ok_or(AdmissionError::Deadline)
    }
}

pub(super) struct SetupReceiver {
    bytes: [u8; RECORD_LEN],
    used: usize,
    deadline: u64,
    retired: bool,
}
impl SetupReceiver {
    pub(super) fn new(deadline: u64) -> Self {
        Self {
            bytes: [0; RECORD_LEN],
            used: 0,
            deadline,
            retired: false,
        }
    }
    pub(super) fn push(
        &mut self,
        bytes: &[u8],
        now: u64,
        uid: u32,
    ) -> Result<Option<SetupRecord>, AdmissionError> {
        if self.retired || now >= self.deadline || bytes.len() > RECORD_LEN - self.used {
            self.retired = true;
            return Err(AdmissionError::Refused);
        }
        self.bytes[self.used..self.used + bytes.len()].copy_from_slice(bytes);
        self.used += bytes.len();
        if self.used != RECORD_LEN {
            return Ok(None);
        }
        self.retired = true;
        SetupRecord::decode(&self.bytes, uid, now).map(Some)
    }
}
