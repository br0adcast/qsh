//! The frontend upgrade transaction of a hosted daemon (#529 M2): a newer
//! image replaces the network frontend while the host keeps its own binary,
//! every owner keeps its own, and no session ends.
//!
//! **Prepare** ([`Upgrader`], `PREPARE-FRONTEND-UPGRADE`). The candidate is
//! opened and held by descriptor from then on; its size and sha256 are
//! checked through that descriptor, and its `self-check` runs on the held
//! image (`/proc/self/fd/N`), never on the path again. [`classify`] decides
//! what replacing the serving frontend with it comes to, from the catalog's
//! census. A silent replacement, or one the caller's consent covers, is held
//! under a one-use receipt good for [`RECEIPT_TTL`]; one prepared upgrade at
//! a time, the newest.
//!
//! **Commit** (`COMMIT-FRONTEND-UPGRADE`), under the exclusive control gate
//! and the replacement lease that also keeps a replacement of the whole
//! daemon out. Admission of new handshakes closes, the census is taken
//! again, and a receipt that no longer covers what the upgrade comes to now
//! is refused. Otherwise [`Host::replace_frontend`] hands the serve loop the
//! held image: it stops the running frontend in order (`Stop`, the pidfd
//! kill after `STOP_GRACE`; owners park as at any frontend death), reopens
//! admission and starts the candidate on the same sockets. Once that one
//! says it serves (`Ready`, within [`READY_BOUND`]) it is current, and the
//! commit -- still holding the gate -- makes it what every identity surface
//! describes. A candidate that exits or stays silent is killed through its
//! pidfd and the previous image started again at once; nothing that
//! describes the daemon changes. The commit runs on a task of its own, so a
//! caller that goes away never leaves it half done.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use daemon_bootstrap_protocol::CandidateImageIdentity;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use transport::session_manager::Shutdown;

use super::images::{FrontendImage, ImageIdentity, ImageInfo};
use super::{kill, FrontendChild, Host};
use crate::destructive_restart::{Actions, Rejected, ReplacementLease, RECEIPT_TTL};
use crate::frontend_upgrade::{
    classify, consented_case, receipt_covers, BoxFuture, CandidateFacts, CommitResponse,
    DaemonFacts, FrontendUpgrades, Outcome, PrepareRequest, PrepareResponse, Refusal, UpgradeCase,
};
use crate::owner_process::SelfImage;
use crate::server_info::{FrontendIdentity, Serving};

/// How long a new frontend may take from its start to its `Ready`.
pub(crate) const READY_BOUND: Duration = Duration::from_secs(10);
/// How long a commit waits for the control requests under way, each bounded
/// by [`crate::transport_daemon::CONTROL_REQUEST_TIMEOUT`], to let go of the
/// control gate.
const GATE_WAIT: Duration = crate::transport_daemon::CONTROL_REQUEST_TIMEOUT;
pub(super) const STOPPING: &str = "the daemon is stopping";
pub(super) const REPLACING: &str = "the daemon is replacing itself";

// ---- the serve loop's side ---------------------------------------------------

/// A replacement of the running frontend by `candidate`, for the serve loop;
/// `done` hears how it ended.
pub(crate) struct Replacement {
    pub(super) candidate: Arc<FrontendImage>,
    done: oneshot::Sender<Result<(), String>>,
}

/// The serve loop's end of [`Host::replace_frontend`].
pub(crate) type Replacements = mpsc::Receiver<Replacement>;

impl Replacement {
    /// Never started: `why`.
    pub(super) fn refuse(self, why: &str) {
        let _ = self.done.send(Err(why.into()));
    }

    /// Its candidate did not come up, for `reason`: answered once the
    /// previous image is started again.
    pub(super) fn failed(self, reason: String) -> RolledBack {
        RolledBack {
            done: self.done,
            reason,
        }
    }
}

/// A replacement whose candidate did not come up.
pub(super) struct RolledBack {
    done: oneshot::Sender<Result<(), String>>,
    reason: String,
}

impl RolledBack {
    pub(super) fn answer(self) {
        let _ = self.done.send(Err(self.reason));
    }
}

/// What became of one frontend's run, for the serve loop.
pub(super) struct Ran {
    /// A replacement stopped it: its candidate starts next.
    pub(super) replaced_by: Option<Replacement>,
    /// It was a candidate that did not come up.
    pub(super) rolled_back: Option<RolledBack>,
}

impl Host {
    /// Replace the running frontend with `candidate`: returns once the
    /// candidate's frontend serves and is current (`Ok`), or once it was
    /// given up on and the previous image started again (`Err`, why). A
    /// shutdown meanwhile is an `Err` too.
    pub(crate) async fn replace_frontend(&self, candidate: FrontendImage) -> Result<(), String> {
        let (done, answer) = oneshot::channel();
        let replacement = Replacement {
            candidate: Arc::new(candidate),
            done,
        };
        // Taken by `serve` when it starts, and dropped when it ends: no
        // replacement waits for a loop that is not there.
        if self
            .replacements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return Err("no frontend is served yet".into());
        }
        self.replace
            .try_send(replacement)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    "another frontend replacement is pending".into()
                }
                mpsc::error::TrySendError::Closed(_) => STOPPING.to_string(),
            })?;
        answer.await.unwrap_or_else(|_| Err(STOPPING.into()))
    }

    /// Run the candidate of `replacing` as `child` until it exits: current
    /// once it says it serves within [`READY_BOUND`], else killed and given
    /// up on.
    pub(super) async fn run_candidate(
        &self,
        child: FrontendChild,
        number: u64,
        shutdown: &Shutdown,
        replacements: &mut Replacements,
        replacing: Replacement,
    ) -> Ran {
        let (pid, ready, image) = (child.pid, child.ready.clone(), child.image.clone());
        // A descriptor of its own to kill it by: the run owns the child's.
        // Without one the candidate cannot be bounded, so it goes now.
        let killer = child.pidfd.try_clone();
        if killer.is_err() {
            kill(&child.pidfd);
        }
        let run = self.run_frontend(child, number, shutdown, replacements);
        tokio::pin!(run);
        let bound = tokio::time::sleep(READY_BOUND);
        tokio::pin!(bound);
        let mut ended = None;
        let verdict: Result<(), String> = tokio::select! {
            biased;
            _ = ready.reported() => Ok(()),
            replaced = &mut run => {
                ended = Some(replaced);
                if ready.has_reported() {
                    Ok(())
                } else {
                    Err("the new frontend exited before it was ready".into())
                }
            }
            _ = &mut bound => Err(format!(
                "the new frontend did not report ready within {} s",
                READY_BOUND.as_secs()
            )),
            _ = shutdown.requested() => Err(STOPPING.into()),
        };
        let mut rolled_back = None;
        match verdict {
            Ok(()) => {
                // From its first word on, the next frontend after a crash and
                // every new owner start from it. (A session it creates in the
                // moment before is recorded with the image its owner runs.)
                self.set_current(image);
                crate::log::info(
                    "qshd",
                    &format!("network frontend {number} pid={pid} is ready; the new image serves"),
                );
                let _ = replacing.done.send(Ok(()));
            }
            // Its waiter hears as it drops: the daemon is stopping, and the
            // run stops the candidate.
            Err(_) if shutdown.is_requested() => drop(replacing),
            Err(reason) => {
                crate::log::error(
                    "qshd",
                    &format!(
                        "network frontend {number} pid={pid}: {reason}; starting the previous image again"
                    ),
                );
                if ended.is_none() {
                    if let Ok(killer) = &killer {
                        kill(killer);
                    }
                }
                rolled_back = Some(replacing.failed(reason));
            }
        }
        let replaced_by = match ended {
            Some(replaced) => replaced,
            None => run.await,
        };
        Ran {
            replaced_by,
            rolled_back,
        }
    }
}

// ---- receipts ----------------------------------------------------------------

/// The candidate a prepare holds for its commit.
struct Held {
    receipt: [u8; 16],
    expires: Instant,
    image: FrontendImage,
    /// What the candidate's frontends will be described as.
    identity: FrontendIdentity,
    /// The disruption the caller agreed to, if any.
    consented: Option<UpgradeCase>,
}

/// One prepared upgrade at a time, and one commit. Held through a short
/// mutex guard: no I/O, wait or await under it.
#[derive(Default)]
struct Book {
    held: Option<Held>,
    /// A commit runs: no prepare, no other commit.
    committing: bool,
    /// The prepare begun last: only its candidate is held.
    latest: u64,
}

impl Book {
    /// A prepare begins: whatever was held is given up for it.
    fn begin(&mut self) -> Result<u64, Refusal> {
        if self.committing {
            return Err(Refusal::Busy);
        }
        self.held = None;
        self.latest += 1;
        Ok(self.latest)
    }

    /// Hold `held` for the prepare `seq`, unless a newer prepare or a
    /// commit began since.
    fn hold(&mut self, seq: u64, held: Held) -> Result<(), Refusal> {
        if self.committing || seq != self.latest {
            return Err(Refusal::Busy);
        }
        self.held = Some(held);
        Ok(())
    }

    /// Spend `receipt`: the candidate it holds, for a commit that runs from
    /// now on. Any other receipt leaves the held one as it is.
    fn take(&mut self, receipt: [u8; 16], now: Instant) -> Result<Held, Refusal> {
        if self.committing {
            return Err(Refusal::Busy);
        }
        if !self.held.as_ref().is_some_and(|h| h.receipt == receipt) {
            return Err(Refusal::Unknown);
        }
        let held = self.held.take().ok_or(Refusal::Unknown)?;
        if held.expires <= now {
            return Err(Refusal::Expired);
        }
        self.committing = true;
        Ok(held)
    }

    fn done(&mut self) {
        self.committing = false;
    }
}

// ---- the upgrader ------------------------------------------------------------

/// The frontend upgrades of one hosted daemon: what its control server
/// hands `PREPARE-FRONTEND-UPGRADE` and `COMMIT-FRONTEND-UPGRADE` to.
pub struct Upgrader(Arc<Inner>);

struct Inner {
    host: Arc<Host>,
    serving: Arc<Serving>,
    actions: Option<Arc<Actions>>,
    /// The gate every other control request holds for reading.
    gate: Arc<tokio::sync::RwLock<()>>,
    book: Mutex<Book>,
}

impl Upgrader {
    /// Upgrades of `host`'s frontend, which `serving` describes to every
    /// identity surface and `actions` names in its receipts.
    pub fn new(
        host: Arc<Host>,
        serving: Arc<Serving>,
        actions: Option<Arc<Actions>>,
    ) -> Arc<Upgrader> {
        let gate = actions
            .as_ref()
            .map_or_else(Default::default, |actions| actions.control_gate.clone());
        Arc::new(Upgrader(Arc::new(Inner {
            host,
            serving,
            actions,
            gate,
            book: Mutex::default(),
        })))
    }
}

impl FrontendUpgrades for Upgrader {
    fn prepare(&self, request: PrepareRequest) -> BoxFuture<'_, PrepareResponse> {
        Box::pin(self.0.clone().prepare(request))
    }

    fn commit(&self, receipt: [u8; 16]) -> BoxFuture<'_, CommitResponse> {
        let inner = self.0.clone();
        Box::pin(async move {
            // A task of its own: a caller that goes away, or a handler that
            // gives up, never leaves the transaction half done.
            tokio::spawn(inner.commit(receipt))
                .await
                .unwrap_or_else(|error| {
                    crate::log::error("qshd", &format!("the frontend upgrade failed: {error}"));
                    CommitResponse::RolledBack {
                        reason: format!("the upgrade failed: {error}"),
                    }
                })
        })
    }
}

/// What a prepare's checks found.
struct Checked {
    serving: FrontendIdentity,
    image: FrontendImage,
    identity: FrontendIdentity,
    facts: CandidateFacts,
    consented: Option<UpgradeCase>,
}

/// Cleared when the commit that set it ends, however it ends.
struct Committing<'a>(&'a Inner);
impl Drop for Committing<'_> {
    fn drop(&mut self) {
        self.0.book().done();
    }
}

/// The daemon's replacement lease, held for a commit: no update replaces the
/// daemon, and no destructive stop is committed, meanwhile.
struct Lease<'a> {
    actions: &'a Actions,
    lease: ReplacementLease,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.actions.state.lock() {
            state.finish_replacement(self.lease);
        }
    }
}

fn candidate(detail: impl Into<String>) -> Refusal {
    Refusal::Candidate {
        detail: detail.into(),
    }
}

/// What `classify` knows of a held image.
fn candidate_facts(info: &ImageInfo, identity: &FrontendIdentity) -> CandidateFacts {
    CandidateFacts {
        build: identity.build,
        checksum: identity.checksum.clone(),
        host_revision: Some(info.host_revision),
        link_versions: info.link_versions.clone(),
        session_profiles: info.profiles.clone(),
    }
}

/// sha256 of the held image, lower-case hex, read through its descriptor:
/// exactly `size` bytes, or it changed under the read.
fn sha256_of(image: &SelfImage, size: u64) -> Result<String, Refusal> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut at = 0u64;
    loop {
        let read = image
            .read_at(&mut buf, at)
            .map_err(|error| candidate(format!("cannot read it: {error}")))?;
        if read == 0 {
            break;
        }
        at += read as u64;
        if at > size {
            return Err(candidate("it grew while it was read"));
        }
        hasher.update(&buf[..read]);
    }
    if at != size {
        return Err(candidate("it shrank while it was read"));
    }
    Ok(hex::encode(hasher.finalize()))
}

impl Inner {
    fn book(&self) -> std::sync::MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What replacing `serving` with the candidate `facts` describes comes
    /// to, over every session the catalog has now.
    fn outcome(&self, serving: &FrontendIdentity, facts: &CandidateFacts) -> Outcome {
        classify(
            &DaemonFacts {
                host_revision: crate::state::HOST_REVISION,
                serving_build: serving.build,
                serving_checksum: serving.checksum.clone(),
                sessions: self.host.catalog.census(),
            },
            facts,
        )
    }

    async fn prepare(self: Arc<Self>, request: PrepareRequest) -> PrepareResponse {
        let refused = |reason| PrepareResponse::Refused { reason };
        let seq = match self.book().begin() {
            Ok(seq) => seq,
            Err(reason) => return refused(reason),
        };
        // Hashing and the self-check block: off the runtime.
        let inner = self.clone();
        let checked = match tokio::task::spawn_blocking(move || inner.check(request)).await {
            Ok(Ok(checked)) => checked,
            Ok(Err(reason)) => return refused(reason),
            Err(error) => return refused(candidate(format!("its checks failed: {error}"))),
        };
        let outcome = self.outcome(&checked.serving, &checked.facts);
        match outcome {
            Outcome::UpToDate => return PrepareResponse::UpToDate,
            Outcome::Older => return refused(Refusal::Older),
            Outcome::Destructive { .. } | Outcome::FullRestart => {
                return PrepareResponse::NotPreservable { outcome }
            }
            _ if !receipt_covers(checked.consented, &outcome) => {
                return PrepareResponse::NeedsConsent { outcome }
            }
            _ => {}
        }
        let mut receipt = [0u8; 16];
        if getrandom::fill(&mut receipt).is_err() {
            return refused(Refusal::Busy);
        }
        let held = Held {
            receipt,
            expires: Instant::now() + RECEIPT_TTL,
            image: checked.image,
            identity: checked.identity,
            consented: checked.consented,
        };
        match self.book().hold(seq, held) {
            Ok(()) => PrepareResponse::Ready {
                receipt: hex::encode(receipt),
                outcome,
            },
            Err(reason) => refused(reason),
        }
    }

    /// The checks of a prepare, blocking: the serving frontend is the one
    /// the request names, and the file at its path -- held from the open
    /// on -- is the candidate it describes and can serve.
    fn check(&self, request: PrepareRequest) -> Result<Checked, Refusal> {
        // Hashes this binary on the first ask: a blocking call.
        let serving = self.serving.identity().map_err(|_| Refusal::Mismatch)?;
        if serving.busy_identity() != request.identity {
            return Err(Refusal::Mismatch);
        }
        if request.size > crate::update::MAX_UPDATE_SIZE {
            return Err(candidate(format!(
                "{} bytes is more than {}",
                request.size,
                crate::update::MAX_UPDATE_SIZE
            )));
        }
        let image = SelfImage::open(Path::new(&request.path))
            .map_err(|error| candidate(format!("cannot open {}: {error}", request.path)))?;
        let size = image
            .size()
            .map_err(|error| candidate(format!("cannot read it: {error}")))?;
        if size != request.size {
            return Err(candidate(format!(
                "it is {size} bytes, not {}",
                request.size
            )));
        }
        let checksum = sha256_of(&image, size)?;
        if checksum != request.checksum {
            return Err(candidate(format!(
                "its sha256 is {checksum}, not {}",
                request.checksum
            )));
        }
        // The held image itself, through this process's descriptor of it.
        let check =
            crate::update::run_self_check(&image.proc_path(), crate::update::SELF_CHECK_TIMEOUT)
                .map_err(candidate)?;
        if check.build != request.build {
            return Err(candidate(format!(
                "it is build {}, not {}",
                check.build, request.build
            )));
        }
        let version = check
            .version
            .clone()
            .ok_or_else(|| candidate("its self-check names no version"))?;
        let profiles: Vec<transport::bootstrap::SessionProfile> = check
            .session_profiles
            .iter()
            .map(|p| transport::bootstrap::SessionProfile {
                wire: p[0],
                handshake: p[1],
                channel: p[2],
            })
            .collect();
        let mut generation = [0u8; 16];
        getrandom::fill(&mut generation).map_err(|_| candidate("no generation for it"))?;
        let identity = FrontendIdentity {
            version,
            build: check.build,
            checksum,
            profiles,
            generation,
        };
        // What its frontends would tell clients must fit the in-band
        // server information.
        transport::bootstrap::encode_server_info(&transport::bootstrap::ServerInfo {
            generation,
            core_version: identity.version.clone(),
            session_protocols: identity.profiles.clone(),
        })
        .map_err(|_| candidate("its version or session profiles exceed the server information"))?;
        let consented = consented_case(
            request.consent.as_ref(),
            &request.identity,
            &CandidateImageIdentity {
                build: identity.build,
                checksum: identity.checksum.clone(),
            },
        );
        let facts = CandidateFacts {
            build: identity.build,
            checksum: identity.checksum.clone(),
            host_revision: check.host_revision,
            link_versions: check.link_versions.clone(),
            session_profiles: check.session_profiles.clone(),
        };
        let image = FrontendImage {
            image,
            info: Arc::new(ImageInfo {
                identity: ImageIdentity::Known(identity.clone()),
                // None reported: such an image is never held (`classify`
                // leaves only a full restart for it).
                host_revision: check.host_revision.unwrap_or(0),
                link_versions: check.link_versions,
                profiles: check.session_profiles,
            }),
        };
        Ok(Checked {
            serving,
            image,
            identity,
            facts,
            consented,
        })
    }

    /// The daemon's replacement lease, if it has receipts at all.
    fn lease(&self) -> Result<Option<Lease<'_>>, Refusal> {
        let Some(actions) = &self.actions else {
            return Ok(None);
        };
        if actions.shutdown.is_requested() {
            return Err(Refusal::Stopping);
        }
        let mut state = actions.state.lock().map_err(|_| Refusal::Stopping)?;
        match state.begin_replacement() {
            Ok(lease) => Ok(Some(Lease { actions, lease })),
            Err(Rejected::ShutdownCommitted) => Err(Refusal::Stopping),
            Err(_) => Err(Refusal::Busy),
        }
    }

    async fn commit(self: Arc<Self>, receipt: [u8; 16]) -> CommitResponse {
        let refused = |reason| CommitResponse::Refused { reason };
        // Every control request under way finishes first, and none starts
        // until the commit is over: none sees two descriptions of the
        // daemon.
        let Ok(_gate) = tokio::time::timeout(GATE_WAIT, self.gate.clone().write_owned()).await
        else {
            return refused(Refusal::Busy);
        };
        let held = match self.book().take(receipt, Instant::now()) {
            Ok(held) => held,
            Err(reason) => return refused(reason),
        };
        let _committing = Committing(&self);
        let _lease = match self.lease() {
            Ok(lease) => lease,
            Err(reason) => return refused(reason),
        };
        let admission = &self.host.start.admission;
        admission.close();
        // What the upgrade comes to now, with no client arriving meanwhile.
        let Ok(serving) = self.serving.identity() else {
            admission.open();
            return refused(Refusal::Mismatch);
        };
        let outcome = self.outcome(&serving, &candidate_facts(&held.image.info, &held.identity));
        if !receipt_covers(held.consented, &outcome) {
            admission.open();
            return refused(Refusal::Changed { outcome });
        }
        crate::log::info(
            "qshd",
            &format!(
                "replacing the network frontend: build {} with build {} ({:?})",
                serving.build, held.identity.build, outcome
            ),
        );
        let identity = held.identity;
        // The serve loop reopens admission for the candidate.
        match self.host.replace_frontend(held.image).await {
            Ok(()) => {
                let busy = identity.busy_identity();
                self.serving.set(identity);
                if let Some(actions) = &self.actions {
                    actions.set_identity(busy.clone());
                }
                CommitResponse::Replaced { identity: busy }
            }
            Err(reason) => {
                // Open already if the serve loop got as far as a start; not
                // if it never took the replacement. A replacement of the
                // whole daemon, which keeps admission closed itself, cannot
                // run meanwhile (the lease), but its gate is left to it.
                if !self.host.control.is_closed() {
                    admission.open();
                }
                crate::log::warn(
                    "qshd",
                    &format!("the network frontend was not replaced: {reason}"),
                );
                CommitResponse::RolledBack { reason }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(receipt: u8, expires: Instant) -> Held {
        let identity = FrontendIdentity {
            version: "0.6.0".into(),
            build: 2,
            checksum: "ab".repeat(32),
            profiles: Vec::new(),
            generation: [2; 16],
        };
        Held {
            receipt: [receipt; 16],
            expires,
            image: FrontendImage {
                image: SelfImage::hold().unwrap(),
                info: Arc::new(ImageInfo {
                    identity: ImageIdentity::Known(identity.clone()),
                    host_revision: crate::state::HOST_REVISION,
                    link_versions: vec![1],
                    profiles: Vec::new(),
                }),
            },
            identity,
            consented: None,
        }
    }

    #[test]
    fn an_expired_receipt_is_refused_and_spent() {
        let now = Instant::now();
        let mut book = Book::default();
        let seq = book.begin().unwrap();
        book.hold(seq, held(1, now + RECEIPT_TTL)).unwrap();
        assert!(matches!(
            book.take([1; 16], now + RECEIPT_TTL),
            Err(Refusal::Expired)
        ));
        assert!(matches!(book.take([1; 16], now), Err(Refusal::Unknown)));
        assert!(!book.committing, "nothing runs");
    }

    #[test]
    fn a_receipt_is_good_once_and_only_the_newest_prepare_holds() {
        let now = Instant::now();
        let mut book = Book::default();
        let older = book.begin().unwrap();
        let newer = book.begin().unwrap();
        assert!(matches!(
            book.hold(older, held(1, now + RECEIPT_TTL)),
            Err(Refusal::Busy)
        ));
        book.hold(newer, held(2, now + RECEIPT_TTL)).unwrap();
        assert!(matches!(book.take([1; 16], now), Err(Refusal::Unknown)));
        let taken = book.take([2; 16], now).expect("the held one");
        assert_eq!(taken.receipt, [2; 16]);
        // While it commits, nothing else begins.
        assert!(matches!(book.begin(), Err(Refusal::Busy)));
        assert!(matches!(book.take([2; 16], now), Err(Refusal::Busy)));
        book.done();
        assert!(matches!(book.take([2; 16], now), Err(Refusal::Unknown)));
        // A new prepare gives up what was held.
        let seq = book.begin().unwrap();
        book.hold(seq, held(3, now + RECEIPT_TTL)).unwrap();
        book.begin().unwrap();
        assert!(matches!(book.take([3; 16], now), Err(Refusal::Unknown)));
    }

    #[test]
    fn a_held_image_is_hashed_through_its_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image");
        let bytes: Vec<u8> = (0..200_000u32).map(|n| n as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        let image = SelfImage::open(&path).unwrap();
        // The path changes; the held file does not.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"other").unwrap();
        assert_eq!(image.size().unwrap(), bytes.len() as u64);
        assert_eq!(
            sha256_of(&image, bytes.len() as u64).unwrap(),
            hex::encode(Sha256::digest(&bytes))
        );
        assert!(matches!(
            sha256_of(&image, 10),
            Err(Refusal::Candidate { .. })
        ));
        assert!(
            SelfImage::open(dir.path()).is_err(),
            "a directory is no image"
        );
    }
}
