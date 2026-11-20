//! Daemon-wide limits enforced once across session owners (#529 M1).
//!
//! Each simulated owner here is what an owner process is to its host: a
//! `HostClient` whose requests cross the real host channel codec to the
//! host's dispatch (`owner_process::serve_limits`) against that owner's
//! account, and whose replies cross back -- the same path a real owner's
//! frames take, minus the socket. An owner "exits" with its last frame,
//! `Drained`, after which its account is dropped, as the host drops it once
//! it has reaped the owner.

use std::sync::Arc;
use std::time::{Duration, Instant};

use terminal_size::TerminalSize;
use tokio::sync::mpsc;
use transport::channel_open::{
    ChannelOpenRegistry, OpenAdmission, OpenIdentity, OpenLimits, OpenRefusal, OpenRequestSnapshot,
    SessionOpenLedger, SpawnCleanup,
};
use transport::session_manager::{MAX_SESSIONS_PER_OWNER, MAX_SESSIONS_TOTAL};

use super::*;
use crate::owner_process::owner::{HostClient, RemoteLimits};
use crate::owner_process::serve_limits;
use crate::owner_process::wire::{ToHost, ToOwner};
use crate::screen_budget::{BackingSlots, ScreenBudget, ScreenPool, Usage};

const UID: u32 = 1000;

fn size() -> TerminalSize {
    TerminalSize::new(80, 24).unwrap()
}

/// Through the wire, as a frame would go.
fn crossed_to_host(msg: ToHost) -> ToHost {
    ToHost::decode(&msg.encode().unwrap()[4..]).unwrap()
}

fn crossed_to_owner(msg: ToOwner) -> ToOwner {
    ToOwner::decode(&msg.encode().unwrap()[4..]).unwrap()
}

/// One owner of `uid`'s session, served by its host's `services`.
struct TestOwner {
    client: Arc<HostClient>,
    limits: Arc<RemoteLimits>,
    host: Option<std::thread::JoinHandle<()>>,
}

impl TestOwner {
    fn start(services: &Arc<HostServices>, uid: u32) -> TestOwner {
        let account = services.admit(uid).expect("an envelope for the owner");
        let (out, mut frames) = mpsc::unbounded_channel();
        let client = HostClient::new(out);
        let replies = Arc::downgrade(&client);
        let host = std::thread::spawn(move || {
            while let Some(msg) = frames.blocking_recv() {
                let msg = crossed_to_host(msg);
                if matches!(msg, ToHost::Drained(_)) {
                    break;
                }
                if let Some(reply) = serve_limits(&account, msg, false).expect("a limit request") {
                    if let Some(client) = replies.upgrade() {
                        client.reply(crossed_to_owner(reply));
                    }
                }
            }
            // Reaped: everything the owner still held goes back.
            drop(account);
        });
        TestOwner {
            limits: Arc::new(RemoteLimits(client.clone())),
            client,
            host: Some(host),
        }
    }

    fn screens(&self) -> Arc<ScreenBudget> {
        Arc::new(ScreenBudget::remote(self.limits.clone()))
    }

    /// Wait until the host has served everything this owner sent so far:
    /// one more request, of nothing, and its answer (refunds are notices).
    fn sync(&self) {
        ScreenPool::acquire(&*self.limits, UID, BackingSlots::default(), 0).unwrap();
    }

    fn opens(&self) -> Arc<ChannelOpenRegistry> {
        ChannelOpenRegistry::with_admission(OpenLimits::default(), self.limits.clone())
    }

    /// The owner process ends -- whatever it still holds, as if it crashed
    /// -- and its host reaps it.
    fn exit(mut self) {
        self.client.notify(ToHost::Drained(Ok(())));
        self.host.take().unwrap().join().unwrap();
    }
}

fn open_request(session: &SessionOpenLedger, uid: u32, instance: u64) -> OpenRequestSnapshot {
    OpenRequestSnapshot {
        owner: transport::Principal {
            uid,
            name: "me".into(),
            identity: "fixture".into(),
            incarnation: 0,
        },
        login: [0; 16],
        request: transport::channel::OpenRequest {
            stream: 16,
            kind: transport::channel::ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        },
        term: None,
        identity: OpenIdentity {
            session: session.id(),
            stream: 16,
            instance: transport::channel_geometry::ChannelInstance::new(instance).unwrap(),
            generation: 0,
            invalidation_epoch: 0,
        },
    }
}

/// [RF 4] One uid's screens count once for the daemon however many owners
/// they are spread over: the 17th is refused, and everything comes back
/// when the owners exit, even with their leases never given back.
#[test]
fn screen_budget_is_shared_across_owners() {
    let services = HostServices::new(HostLimits::default());
    let owners: Vec<TestOwner> = (0..3).map(|_| TestOwner::start(&services, UID)).collect();
    let budgets: Vec<_> = owners.iter().map(TestOwner::screens).collect();
    let mut leases = Vec::new();
    for n in 0..16 {
        leases.push(
            budgets[n % budgets.len()]
                .reserve(UID, size())
                .unwrap_or_else(|e| panic!("screen {n}: {e}")),
        );
    }
    assert_eq!(services.in_use().screen.models, 16);
    for budget in &budgets {
        let refused = budget.reserve(UID, size()).err().expect("the 17th screen");
        assert!(
            refused.contains("owner terminal screen budget exhausted"),
            "{refused}"
        );
    }
    // A resize prepares against the same pool and gives its scratch back.
    // (The last lease is owner 0's.)
    {
        let mut lease = leases.pop().unwrap();
        let before = services.in_use().screen;
        let resize = lease
            .prepare(TerminalSize::new(100, 30).unwrap())
            .expect("a resize within the pool");
        assert!(services.in_use().screen.cells > before.cells);
        drop(resize);
        owners[0].sync();
        assert_eq!(services.in_use().screen, before);
        leases.push(lease);
    }
    // A lease given back is free for any owner.
    drop(leases.pop());
    owners[0].sync();
    leases.push(budgets[2].reserve(UID, size()).expect("room again"));
    assert_eq!(services.in_use().screen.models, 16);
    // The owners end with all 16 leases still held: the host frees them.
    for owner in owners {
        owner.exit();
    }
    assert_eq!(
        services.in_use(),
        InUse {
            envelopes: 0,
            opens: 0,
            screen: Usage::default(),
        }
    );
    // Their refunds now reach nobody, and change nothing.
    drop(leases);
    assert_eq!(services.in_use().screen, Usage::default());
}

/// One control budget envelope per owner, from a fixed number: owners of
/// one uid get at most `MAX_SESSIONS_PER_OWNER`, all owners together at
/// most `MAX_SESSIONS_TOTAL` -- one daemon's worth, each envelope one
/// session's share of it (`GlobalBudget::envelope`).
#[test]
fn global_control_budget_leases_do_not_multiply() {
    let services = HostServices::new(HostLimits::default());
    let mut held = Vec::new();
    for _ in 0..MAX_SESSIONS_PER_OWNER {
        held.push(services.admit(UID).unwrap());
    }
    let refused = services
        .admit(UID)
        .err()
        .expect("one uid's envelopes are taken");
    assert!(refused.contains("envelope"), "{refused}");
    let mut uid = UID + 1;
    while held.len() < MAX_SESSIONS_TOTAL {
        match services.admit(uid) {
            Ok(account) => held.push(account),
            Err(_) => uid += 1,
        }
    }
    assert_eq!(services.in_use().envelopes, MAX_SESSIONS_TOTAL);
    assert!(services.admit(uid + 1).is_err(), "every envelope is taken");
    // A draining owner keeps its envelope until it is reaped.
    drop(held.remove(0));
    assert_eq!(services.in_use().envelopes, MAX_SESSIONS_TOTAL - 1);
    let again = services.admit(UID).expect("the reaped owner's envelope");
    drop((held, again));
    assert_eq!(services.in_use().envelopes, 0);
}

/// Opens in flight count once for the daemon across owners' registries:
/// eight per uid, although each owner's registry alone would admit more.
#[test]
fn open_limits_hold_across_owners() {
    let services = HostServices::new(HostLimits::default());
    let owners: Vec<TestOwner> = (0..3).map(|_| TestOwner::start(&services, UID)).collect();
    let registries: Vec<_> = owners.iter().map(TestOwner::opens).collect();
    let sessions: Vec<_> = registries.iter().map(|r| r.session().unwrap()).collect();
    let per_uid = OpenLimits::default().per_uid;
    let mut jobs = Vec::new();
    for n in 0..per_uid {
        let i = n % registries.len();
        jobs.push(
            registries[i]
                .try_reserve(&sessions[i], open_request(&sessions[i], UID, n as u64 + 1))
                .unwrap_or_else(|e| panic!("open {n}: {e:?}")),
        );
    }
    assert_eq!(services.in_use().opens, per_uid);
    for (registry, session) in registries.iter().zip(&sessions) {
        assert!(registry.outstanding() < per_uid, "room in each registry");
        assert!(matches!(
            registry.try_reserve(session, open_request(session, UID, 99)),
            Err(OpenRefusal::Capacity)
        ));
    }
    // An open that is over goes back to the daemon-wide count.
    let job = jobs.remove(0);
    let failure = job.custody().refuse_before_creation("fixture".into());
    let SpawnCleanup::NoChild(proof) = failure.cleanup else {
        unreachable!()
    };
    assert!(registries[0].finish_cleanup(job.id(), &proof));
    owners[0].sync();
    assert_eq!(services.in_use().opens, per_uid - 1);
    jobs.push(
        registries[2]
            .try_reserve(&sessions[2], open_request(&sessions[2], UID, 50))
            .expect("room again"),
    );
    // Another uid is not this one's limit, but an owner speaks for its own.
    assert!(!OpenAdmission::acquire(&*owners[0].limits, UID + 1));
    for owner in owners {
        owner.exit();
    }
    assert_eq!(services.in_use().opens, 0);
}

/// An owner whose host does not answer in time takes it as a refusal; a
/// grant that still comes is given back, so nothing stays charged.
#[test]
fn host_timeout_refuses_reservation() {
    let services = HostServices::new(HostLimits::default());
    let account = services.admit(UID).unwrap();
    let (out, mut frames) = mpsc::unbounded_channel();
    let client = HostClient::new(out);
    let limits = Arc::new(RemoteLimits(client.clone()));
    let budget = Arc::new(ScreenBudget::remote(limits.clone()));

    let started = Instant::now();
    let refused = budget
        .reserve(UID, size())
        .err()
        .expect("no answer: refused");
    let waited = started.elapsed();
    assert!(refused.contains("unavailable"), "{refused}");
    assert!(
        waited >= HOST_SERVICE_TIMEOUT && waited < HOST_SERVICE_TIMEOUT + Duration::from_secs(1),
        "{waited:?}"
    );
    let started = Instant::now();
    assert!(
        !OpenAdmission::acquire(&*limits, UID),
        "an open without an answer is refused"
    );
    assert!(started.elapsed() >= HOST_SERVICE_TIMEOUT);

    // The host answers both late, granting them.
    for _ in 0..2 {
        let request = crossed_to_host(frames.try_recv().expect("the request"));
        let reply = serve_limits(&account, request, false)
            .unwrap()
            .expect("a reply");
        client.reply(crossed_to_owner(reply));
    }
    assert_ne!(services.in_use().screen, Usage::default());
    assert_eq!(services.in_use().opens, 1);
    // The owner gives both back.
    let mut undone = 0;
    while let Ok(msg) = frames.try_recv() {
        assert!(matches!(
            msg,
            ToHost::ScreenRelease { .. } | ToHost::OpenRelease { .. }
        ));
        assert_eq!(
            serve_limits(&account, crossed_to_host(msg), false),
            Ok(None)
        );
        undone += 1;
    }
    assert_eq!(undone, 2);
    assert_eq!(services.in_use().screen, Usage::default());
    assert_eq!(services.in_use().opens, 0);
}

/// The owner process's own backend (`owner_backend`, what `run_owner`
/// runs) charges the host: its screens and its opens count once across
/// owners, as the simulated ones above do.
#[test]
fn an_owner_process_backend_charges_the_shared_host_limits() {
    use crate::owner_process::owner::owner_backend;
    let services = HostServices::new(HostLimits::default());
    let owners: Vec<TestOwner> = (0..2).map(|_| TestOwner::start(&services, UID)).collect();
    let backends: Vec<_> = owners
        .iter()
        .map(|owner| owner_backend(&owner.client, false))
        .collect();
    let mut leases = Vec::new();
    for n in 0..16 {
        leases.push(
            backends[n % 2]
                .screens
                .reserve(UID, size())
                .unwrap_or_else(|e| panic!("screen {n}: {e}")),
        );
    }
    assert_eq!(services.in_use().screen.models, 16);
    assert!(
        backends[1].screens.reserve(UID, size()).is_err(),
        "the 17th"
    );
    let registries: Vec<_> = backends.iter().map(|b| b.backend.open_registry()).collect();
    let sessions: Vec<_> = registries.iter().map(|r| r.session().unwrap()).collect();
    let per_uid = OpenLimits::default().per_uid;
    let mut jobs = Vec::new();
    for n in 0..per_uid {
        let i = n % 2;
        jobs.push(
            registries[i]
                .try_reserve(&sessions[i], open_request(&sessions[i], UID, n as u64 + 1))
                .unwrap_or_else(|e| panic!("open {n}: {e:?}")),
        );
    }
    assert_eq!(services.in_use().opens, per_uid);
    assert!(matches!(
        registries[0].try_reserve(&sessions[0], open_request(&sessions[0], UID, 99)),
        Err(OpenRefusal::Capacity)
    ));
    drop((jobs, leases));
    for owner in owners {
        owner.exit();
    }
    assert_eq!(services.in_use().envelopes, 0);
}

/// A host that stalls past the owner's bound and then recovers leaves no
/// grant counted against the account once that owner is gone: the owner
/// ends its session when it takes the host for unreachable, and its late
/// grants go back when the host reaps it.
#[test]
fn a_stalled_host_that_recovers_leaves_no_grant_once_the_owner_is_gone() {
    use crate::owner_process::owner::ABANDONED_MAX;
    let services = HostServices::new(HostLimits::default());
    let account = services.admit(UID).unwrap();
    let (out, mut frames) = mpsc::unbounded_channel();
    let client = HostClient::new(out);
    let shutdown = transport::session_manager::Shutdown::default();
    client.end_session_on_unreachable(shutdown.clone());
    // The host stalls: every open times out.
    let callers: Vec<_> = (0..=ABANDONED_MAX)
        .map(|_| {
            let limits = RemoteLimits(client.clone());
            std::thread::spawn(move || OpenAdmission::acquire(&limits, UID))
        })
        .collect();
    for caller in callers {
        assert!(!caller.join().unwrap());
    }
    assert!(shutdown.is_requested(), "the owner ends its session");
    // The host recovers and answers every request late, granting.
    while let Ok(msg) = frames.try_recv() {
        if let Some(reply) = serve_limits(&account, crossed_to_host(msg), false).unwrap() {
            client.reply(crossed_to_owner(reply));
        }
    }
    while let Ok(msg) = frames.try_recv() {
        serve_limits(&account, crossed_to_host(msg), false).unwrap();
    }
    // Until then the late grants count (nobody is left to give them back).
    assert!(services.in_use().opens > 0);
    // Reaped: nothing is left counted against the account.
    drop(account);
    assert_eq!(services.in_use().opens, 0);
    assert_eq!(services.in_use().envelopes, 0);
}
