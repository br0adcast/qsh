//! Concrete installation custody for a session independent of network I/O.
use crate::channel_geometry::ChannelInstance;
use crate::channel_open::{
    ChannelOpenRegistry, IdleEpochGuard, InstalledSlot, OpenIdentity, OpenJob, OpenJobId,
    OpenRefusal, UninstalledChannel,
};
use crate::channel_server::{
    reaping::{PreparedActive, ReapSet},
    RestartSignal, SpawnedChannel,
};
use crate::session_manager::RetainedWorkerOwner;
use crate::shell_server::{ResizeHandle, SessionScreen};
use std::collections::{hash_map::VacantEntry, HashMap};
use std::io::{Read, Write};
use std::sync::Arc;

struct RetainedChannel {
    identity: OpenIdentity,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    _resize: Box<dyn ResizeHandle>,
    _screen: Box<dyn SessionScreen>,
    started: bool,
    receipts: Option<[crate::session_manager::WorkerReceipt; 2]>,
}
/// The frontend never owns this set. Only explicit close retires installed custody.
pub struct RetainedChannelSet {
    registry: Arc<ChannelOpenRegistry>,
    channels: HashMap<u8, RetainedChannel>,
    reaps: ReapSet,
    workers: RetainedWorkerOwner,
}
/// Constructed only by the exact reaper. The worker flag distinguishes
/// actual successful I/O joins from custody closed before workers were launched.
pub struct RetainedCleanup {
    stream: u8,
    instance: ChannelInstance,
    code: Option<i32>,
    workers_joined: bool,
}
impl RetainedCleanup {
    pub fn stream(&self) -> u8 {
        self.stream
    }
    pub fn instance(&self) -> ChannelInstance {
        self.instance
    }
    pub fn code(&self) -> Option<i32> {
        self.code
    }
    pub fn workers_joined(&self) -> bool {
        self.workers_joined
    }
}
pub(crate) struct PreparedRetainedInstallation<'a> {
    identity: OpenIdentity,
    registry: Arc<ChannelOpenRegistry>,
    job_id: OpenJobId,
    entry: VacantEntry<'a, u8, RetainedChannel>,
    reap: PreparedActive<'a>,
}
impl PreparedRetainedInstallation<'_> {
    pub(crate) fn matches(
        &self,
        identity: &OpenIdentity,
        registry: &Arc<ChannelOpenRegistry>,
        job_id: OpenJobId,
    ) -> bool {
        self.identity == *identity && self.job_id == job_id && Arc::ptr_eq(&self.registry, registry)
    }
    pub(crate) fn commit(self, spawned: SpawnedChannel, slot: InstalledSlot) {
        let SpawnedChannel {
            reader,
            writer,
            resize,
            screen,
            wait,
        } = spawned;
        // All storage already exists; these are concrete non-callback moves.
        self.reap.commit(wait, slot);
        self.entry.insert(RetainedChannel {
            identity: self.identity,
            reader: Some(reader),
            writer: Some(writer),
            _resize: resize,
            _screen: screen,
            started: false,
            receipts: None,
        });
    }
}
/// Concrete prepared target. Resources remain in registered custody until commit.
pub struct PreparedRetainedOpen<'a> {
    adopted: crate::channel_open::AdoptedOpen,
    identity: OpenIdentity,
    installation: PreparedRetainedInstallation<'a>,
}
impl PreparedRetainedOpen<'_> {
    pub fn commit(self, epoch: &IdleEpochGuard<'_>) -> Result<(), OpenRefusal> {
        self.adopted
            .commit_retained(epoch, &self.identity, self.installation)
            .ok_or(OpenRefusal::InvalidIdentity)
    }
}
/// An actual watch read guard, never an epoch value supplied by a caller.
pub fn installation_epoch(
    restart: &tokio::sync::watch::Receiver<RestartSignal>,
) -> Result<IdleEpochGuard<'_>, OpenRefusal> {
    IdleEpochGuard::from_signal(restart.borrow())
}
impl RetainedChannelSet {
    pub fn new(registry: Arc<ChannelOpenRegistry>) -> Self {
        Self {
            reaps: ReapSet::new(registry.clone()),
            registry,
            channels: HashMap::new(),
            workers: RetainedWorkerOwner::default(),
        }
    }
    pub fn channels(&self) -> usize {
        self.channels.len()
    }
    pub fn install(
        &mut self,
        job: OpenJob,
        channel: UninstalledChannel,
        identity: OpenIdentity,
        restart: &tokio::sync::watch::Receiver<RestartSignal>,
    ) -> Result<(), OpenRefusal> {
        let prepared = self.prepare(job, channel, identity)?;
        let epoch = installation_epoch(restart)?;
        prepared.commit(&epoch)
    }
    /// All allocations precede caller watch/origin guards. No resource extraction.
    pub fn prepare(
        &mut self,
        job: OpenJob,
        channel: UninstalledChannel,
        identity: OpenIdentity,
    ) -> Result<PreparedRetainedOpen<'_>, OpenRefusal> {
        let uid = job.request().owner.uid;
        let job_id = job.id();
        let adopted = job.try_adopt(channel).ok_or(OpenRefusal::InvalidIdentity)?;
        self.channels
            .try_reserve(1)
            .map_err(|_| OpenRefusal::Capacity)?;
        let std::collections::hash_map::Entry::Vacant(entry) = self.channels.entry(identity.stream)
        else {
            return Err(OpenRefusal::InvalidIdentity);
        };
        let reap = self
            .reaps
            .prepare_active(identity.stream, identity.instance.get(), uid)
            .ok_or(OpenRefusal::Capacity)?;
        let prepared = PreparedRetainedInstallation {
            identity,
            registry: self.registry.clone(),
            job_id,
            entry,
            reap,
        };
        Ok(PreparedRetainedOpen {
            adopted,
            identity,
            installation: prepared,
        })
    }
    /// Workers own descriptors and their supervisors retain actual JoinHandles.
    /// No caller can replace the child wait or manufacture a joined receipt.
    pub fn start_workers(
        &mut self,
        instance: ChannelInstance,
        reader: impl FnOnce(Box<dyn Read + Send>) + Send + 'static,
        writer: impl FnOnce(Box<dyn Write + Send>) + Send + 'static,
    ) -> Result<(), OpenRefusal> {
        let ch = self
            .channels
            .values_mut()
            .find(|c| c.identity.instance == instance)
            .ok_or(OpenRefusal::InvalidIdentity)?;
        if ch.started {
            return Err(OpenRefusal::InvalidIdentity);
        }
        let read = ch.reader.take().ok_or(OpenRefusal::InvalidIdentity)?;
        let write = ch.writer.take().ok_or(OpenRefusal::InvalidIdentity)?;
        let receipts = [
            crate::session_manager::WorkerReceipt::default(),
            crate::session_manager::WorkerReceipt::default(),
        ];
        self.reaps.attach_workers(instance.get(), receipts.clone());
        ch.receipts = Some(receipts.clone());
        self.workers
            .spawn_blocking(receipts[0].clone(), move || reader(read));
        self.workers
            .spawn_blocking(receipts[1].clone(), move || writer(write));
        ch.started = true;
        Ok(())
    }
    /// Publication is refused if an actual worker has already stopped or failed.
    pub fn ready_to_publish(&self, instance: ChannelInstance) -> bool {
        self.channels
            .values()
            .find(|c| c.identity.instance == instance)
            .and_then(|c| c.receipts.as_ref())
            .is_some_and(|rs| rs.iter().all(|r| r.joined().is_none()))
    }
    /// Only actual backend-observed running identity may enter an active catalog.
    pub fn catalog_active(&self, instance: ChannelInstance) -> bool {
        self.reaps.catalog_active(instance.get()) && self.ready_to_publish(instance)
    }
    pub fn close(&mut self, instance: ChannelInstance) -> bool {
        let Some(ch) = self
            .channels
            .values_mut()
            .find(|c| c.identity.instance == instance)
        else {
            return false;
        };
        // Unscheduled descriptors are still owned here and must close before wait.
        ch.reader.take();
        ch.writer.take();
        self.reaps.stop(instance.get());
        true
    }
    pub fn close_all(&mut self) {
        for ch in self.channels.values_mut() {
            ch.reader.take();
            ch.writer.take();
        }
        self.reaps.stop_all();
    }
    pub async fn next_cleanup(&mut self) -> RetainedCleanup {
        let done = self.reaps.next().await;
        let channel = self.channels.remove(&done.stream);
        let workers_joined = channel
            .as_ref()
            .and_then(|c| c.receipts.as_ref())
            .is_some_and(|rs| rs.iter().all(|r| matches!(r.joined(), Some(Ok(())))));
        RetainedCleanup {
            stream: done.stream,
            instance: ChannelInstance::new(done.instance).expect("installed nonzero instance"),
            code: done.code,
            workers_joined,
        }
    }
    pub async fn join_workers(&self) -> Result<(), crate::session_manager::ShutdownError> {
        self.workers.drain().await
    }
}
#[cfg(test)]
#[path = "channel_owner_tests.rs"]
mod tests;
