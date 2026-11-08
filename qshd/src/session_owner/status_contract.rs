//! Content-free executable identities, atomic administrative pages and facts.
use super::protocol::OwnerProtocolError as Error;
use super::wire::Reader;
use transport::session_resume::*;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    version: Box<str>,
    pub build: u64,
    pub checksum: [u8; 32],
}
impl BuildIdentity {
    pub fn new(version: &str, build: u64, checksum: [u8; 32]) -> Result<Self, Error> {
        // Same version/checksum validation as BusyDaemonIdentity, before copying.
        if version.is_empty()
            || version.len() > 128
            || !version.is_ascii()
            || version.bytes().any(|b| b.is_ascii_control())
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            version: version.into(),
            build,
            checksum,
        })
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub(super) fn len(&self) -> usize {
        1 + self.version.len() + 8 + 32
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        out.push(self.version.len() as u8);
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(&self.build.to_be_bytes());
        out.extend_from_slice(&self.checksum);
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let len = r.byte()? as usize;
        if len == 0 || len > 128 {
            return Err(Error::Malformed);
        }
        let version = std::str::from_utf8(r.take(len)?).map_err(|_| Error::Malformed)?;
        let build = r.u64()?;
        let checksum = r.array()?;
        Self::new(version, build, checksum)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendIdentity {
    pub generation: FrontendGeneration,
    pub build: BuildIdentity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcRange {
    min: u16,
    max: u16,
}
impl IpcRange {
    pub fn new(min: u16, max: u16) -> Result<Self, Error> {
        if min == 0 || min > max {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self { min, max })
    }
    pub fn min(self) -> u16 {
        self.min
    }
    pub fn max(self) -> u16 {
        self.max
    }
    pub fn select(self, other: Self) -> Result<u16, Error> {
        let chosen = self.max.min(other.max);
        if chosen < self.min.max(other.min) {
            Err(Error::UnsupportedVersion)
        } else {
            Ok(chosen)
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerStatus {
    pub locator: SessionLocator,
    pub build: BuildIdentity,
    pub ipc: IpcRange,
    pub active_channels: u8,
    pub total_channels: u16,
}
impl OwnerStatus {
    pub fn validate(&self) -> Result<(), Error> {
        if self.active_channels as usize > transport::channel::MAX_CHANNELS
            || self.total_channels as usize > transport::channel::CHANNEL_IDENTITIES
            || self.active_channels as u16 > self.total_channels
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        32 + self.build.len() + 4 + 1 + 2
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        super::wire::put_locator(out, self.locator);
        self.build.put(out);
        out.extend_from_slice(&self.ipc.min.to_be_bytes());
        out.extend_from_slice(&self.ipc.max.to_be_bytes());
        out.push(self.active_channels);
        out.extend_from_slice(&self.total_channels.to_be_bytes());
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let s = Self {
            locator: r.locator()?,
            build: BuildIdentity::read(r)?,
            ipc: IpcRange::new(r.u16()?, r.u16()?)?,
            active_channels: r.byte()?,
            total_channels: r.u16()?,
        };
        s.validate()?;
        Ok(s)
    }
}
macro_rules! identity {
    ($n:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $n([u8; 16]);
        impl $n {
            pub fn new(v: [u8; 16]) -> Option<Self> {
                (v != [0; 16]).then_some(Self(v))
            }
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}
identity!(StatusEpoch);
identity!(ReplacementId);
pub const MAX_STATUS_OWNERS: usize = 64;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCursor {
    pub epoch: StatusEpoch,
    pub index: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusPage {
    pub host: HostInstance,
    pub host_build: BuildIdentity,
    pub frontend: FrontendIdentity,
    pub epoch: StatusEpoch,
    pub cursor: u64,
    pub total: u64,
    pub owners: Vec<OwnerStatus>,
    pub next: Option<StatusCursor>,
}
impl StatusPage {
    pub fn validate(&self) -> Result<(), Error> {
        if self.owners.len() > MAX_STATUS_OWNERS {
            return Err(Error::TooLarge);
        }
        let end = self
            .cursor
            .checked_add(self.owners.len() as u64)
            .ok_or(Error::TooLarge)?;
        if end > self.total
            || ((end < self.total) != (self.next.is_some()))
            || self
                .next
                .is_some_and(|n| n.epoch != self.epoch || n.index != end)
            || self.owners.is_empty() && end < self.total
        {
            return Err(Error::Malformed);
        }
        for (i, o) in self.owners.iter().enumerate() {
            o.validate()?;
            if self.owners[..i]
                .iter()
                .any(|p| p.locator == o.locator || p.locator.owner == o.locator.owner)
            {
                return Err(Error::Binding);
            }
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        16 + self.host_build.len()
            + 16
            + self.frontend.build.len()
            + 16
            + 8
            + 8
            + 1
            + self.owners.iter().map(OwnerStatus::len).sum::<usize>()
            + 1
            + self.next.map_or(0, |_| 24)
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.host.as_bytes());
        self.host_build.put(out);
        out.extend_from_slice(self.frontend.generation.as_bytes());
        self.frontend.build.put(out);
        out.extend_from_slice(self.epoch.as_bytes());
        out.extend_from_slice(&self.cursor.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.push(self.owners.len() as u8);
        for o in &self.owners {
            o.put(out);
        }
        if let Some(n) = self.next {
            out.push(1);
            out.extend_from_slice(n.epoch.as_bytes());
            out.extend_from_slice(&n.index.to_be_bytes());
        } else {
            out.push(0);
        }
    }
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let host = HostInstance::new(r.array()?).ok_or(Error::Malformed)?;
        let host_build = BuildIdentity::read(r)?;
        let frontend = FrontendIdentity {
            generation: r.frontend()?,
            build: BuildIdentity::read(r)?,
        };
        let epoch = StatusEpoch::new(r.array()?).ok_or(Error::Malformed)?;
        let cursor = r.u64()?;
        let total = r.u64()?;
        let count = r.byte()? as usize;
        if count > MAX_STATUS_OWNERS {
            return Err(Error::TooLarge);
        }
        let mut owners = Vec::with_capacity(count);
        for _ in 0..count {
            owners.push(OwnerStatus::read(r)?);
        }
        let next = match r.byte()? {
            0 => None,
            1 => Some(StatusCursor {
                epoch: StatusEpoch::new(r.array()?).ok_or(Error::Malformed)?,
                index: r.u64()?,
            }),
            _ => return Err(Error::Malformed),
        };
        let p = Self {
            host,
            host_build,
            frontend,
            epoch,
            cursor,
            total,
            owners,
            next,
        };
        p.validate()?;
        Ok(p)
    }
}
/// Holds pages privately until exact completion; identity changes discard the
/// enumeration and require a new collector. Never merge partial status reports.
#[derive(Debug)]
pub struct StatusCollector {
    capacity: usize,
    first: Option<StatusPage>,
    owners: Vec<OwnerStatus>,
    next: u64,
    done: bool,
    failed: bool,
}
impl StatusCollector {
    pub fn new(capacity: usize) -> Result<Self, Error> {
        if capacity
            .checked_mul(std::mem::size_of::<OwnerStatus>())
            .is_none_or(|v| v > isize::MAX as usize)
        {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            capacity,
            first: None,
            owners: Vec::new(),
            next: 0,
            done: false,
            failed: false,
        })
    }
    pub fn accept(&mut self, page: StatusPage) -> Result<bool, Error> {
        let result = self.accept_page(page);
        if result.is_err() {
            self.failed = true;
            self.owners.clear();
            self.first = None;
        }
        result
    }
    fn accept_page(&mut self, mut page: StatusPage) -> Result<bool, Error> {
        page.validate()?;
        if self.done || self.failed || page.cursor != self.next || page.total > self.capacity as u64
        {
            return Err(Error::Binding);
        }
        if let Some(first) = &self.first {
            if page.host != first.host
                || page.host_build != first.host_build
                || page.frontend != first.frontend
                || page.epoch != first.epoch
                || page.total != first.total
            {
                return Err(Error::Binding);
            }
        }
        if page.owners.iter().any(|o| {
            self.owners
                .iter()
                .any(|p| p.locator == o.locator || p.locator.owner == o.locator.owner)
        }) {
            return Err(Error::Binding);
        }
        self.next = self
            .next
            .checked_add(page.owners.len() as u64)
            .ok_or(Error::TooLarge)?;
        self.done = page.next.is_none();
        self.owners.append(&mut page.owners);
        if self.first.is_none() {
            self.first = Some(page);
        }
        Ok(self.done)
    }
    pub fn finish(self) -> Result<Vec<OwnerStatus>, Error> {
        if !self.done || self.failed {
            return Err(Error::InvalidState);
        }
        Ok(self.owners)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplacementStatus {
    Prepared = 1,
    Fenced = 2,
    Retired = 3,
    Activated = 4,
    Recovered = 5,
    DetachedFailure = 6,
}
/// An untrusted report until checked against its transaction. Missing transaction
/// identity and missing/extra serving identities are explicit refusal cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementFact {
    pub transaction: Option<ReplacementId>,
    pub status: ReplacementStatus,
    pub serving: Option<FrontendIdentity>,
}
#[derive(Debug)]
pub struct ReplacementTransaction {
    id: ReplacementId,
    candidate: FrontendIdentity,
    status: Option<ReplacementStatus>,
    frontend_failed: bool,
    serving: Option<FrontendIdentity>,
}
impl ReplacementTransaction {
    pub fn new(id: ReplacementId, candidate: FrontendIdentity) -> Self {
        Self {
            id,
            candidate,
            status: None,
            frontend_failed: false,
            serving: None,
        }
    }
    /// Runtime caller must independently establish the actual frontend failure.
    pub fn record_frontend_failure(&mut self, transaction: ReplacementId) -> Result<(), Error> {
        if transaction != self.id {
            return Err(Error::Binding);
        }
        if matches!(
            self.status,
            Some(
                ReplacementStatus::Activated
                    | ReplacementStatus::Recovered
                    | ReplacementStatus::DetachedFailure
            )
        ) {
            return Err(Error::InvalidState);
        }
        self.frontend_failed = true;
        Ok(())
    }
    /// Record a transaction-bound fact only. This validates representation and
    /// order; the runtime must independently establish readiness/serving proof.
    pub fn record(&mut self, fact: ReplacementFact) -> Result<(), Error> {
        use ReplacementStatus::*;
        if fact.transaction != Some(self.id) {
            return Err(Error::Binding);
        }
        match (fact.status, &fact.serving) {
            (Activated, Some(actual)) if *actual == self.candidate => {}
            (Recovered, Some(_)) => {}
            (Prepared | Fenced | Retired | DetachedFailure, None) => {}
            _ => return Err(Error::Binding),
        }
        let next = fact.status;
        let allowed = matches!(
            (self.status, next),
            (None, Prepared)
                | (Some(Prepared), Fenced)
                | (Some(Fenced), Retired)
                | (Some(Retired), Activated)
        ) || next == Recovered
            && (self.status == Some(Retired) || self.frontend_failed)
            && !matches!(self.status, Some(Activated | Recovered | DetachedFailure))
            || next == DetachedFailure
                && (matches!(self.status, Some(Fenced | Retired))
                    || self.frontend_failed && self.status == Some(Prepared));
        if !allowed {
            return Err(Error::InvalidState);
        }
        self.status = Some(next);
        self.serving = fact.serving;
        Ok(())
    }
    pub fn serving(&self) -> Option<&FrontendIdentity> {
        self.serving.as_ref()
    }
    pub fn id(&self) -> ReplacementId {
        self.id
    }
    pub fn candidate(&self) -> &FrontendIdentity {
        &self.candidate
    }
    pub fn status(&self) -> Option<ReplacementStatus> {
        self.status
    }
}
