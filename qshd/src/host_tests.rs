use super::*;

fn descriptor() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").unwrap())
}

fn entry(owner_pid: u32, attached: bool) -> Entry {
    Entry {
        uid: 1000,
        owner_pid,
        pidfd: descriptor(),
        relink: descriptor(),
        last_client_recv: Instant::now(),
        state: SessionState::Live,
        attached,
        confirm_by: None,
        active: false,
        client_key: None,
        links: Arc::new([]),
        profiles: Arc::new([]),
    }
}

fn state_of(catalog: &Catalog, token: LoginId) -> SessionState {
    catalog.lock().get(&token).unwrap().state
}

/// 0.1 s doubling to 5 s, and from the start again after a frontend that
/// lived a minute.
#[test]
fn the_restart_backoff_doubles_to_its_cap_and_resets_after_a_healthy_run() {
    let crashed = Duration::from_millis(3);
    let mut backoff = BACKOFF_MIN;
    let mut waits = Vec::new();
    for _ in 0..8 {
        let (wait, next) = next_backoff(backoff, Attempt::Ran(crashed));
        waits.push(wait.as_millis());
        backoff = next;
    }
    assert_eq!(waits, [100, 200, 400, 800, 1600, 3200, 5000, 5000]);
    let (wait, next) = next_backoff(backoff, Attempt::Ran(HEALTHY_AFTER));
    assert_eq!((wait, next), (BACKOFF_MIN, BACKOFF_MIN * 2));
    let (wait, _) = next_backoff(
        backoff,
        Attempt::Ran(HEALTHY_AFTER - Duration::from_millis(1)),
    );
    assert_eq!(wait, BACKOFF_MAX, "not healthy yet");
}

/// A frontend's death changes nothing the catalog keeps of a session: not
/// when it was retained, not when its client was last heard. Only who holds
/// it and whether it counts as active.
#[test]
fn a_frontend_death_leaves_every_retention_time_as_it_was() {
    let active = Arc::new(AtomicUsize::new(0));
    let catalog = Catalog::new(active.clone());
    let (retained, live) = ([1; 16], [2; 16]);
    catalog.insert(retained, entry(11, true));
    catalog.insert(live, entry(12, true));
    catalog.traffic(live, Duration::from_secs(3), true);
    catalog.traffic(retained, Duration::from_secs(40), false);
    catalog.retained(retained);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    let SessionState::Retained { since } = state_of(&catalog, retained) else {
        panic!("retained")
    };
    // A second report of the same retention does not move it.
    catalog.retained(retained);
    assert_eq!(
        state_of(&catalog, retained),
        SessionState::Retained { since }
    );
    let heard = catalog.lock().get(&live).unwrap().last_client_recv;
    assert_eq!(
        catalog.next_deadline(),
        None,
        "the frontend's router decides"
    );

    catalog.detach_all();
    assert_eq!(active.load(Ordering::SeqCst), 0, "no client is being heard");
    assert_eq!(
        state_of(&catalog, retained),
        SessionState::Retained { since },
        "the retention did not start over"
    );
    assert_eq!(state_of(&catalog, live), SessionState::Live);
    assert_eq!(catalog.lock().get(&live).unwrap().last_client_recv, heard);
    // Each ends when a router would have ended it.
    assert_eq!(catalog.next_deadline(), Some(since + RETAIN_AFTER_DEATH));
    assert_eq!(
        catalog.lock().get(&live).unwrap().deadline(),
        Some(heard + SERVER_DEATH_AFTER + RETAIN_AFTER_DEATH)
    );

    assert!(catalog
        .take_expired(since + RETAIN_AFTER_DEATH - Duration::from_millis(1))
        .0
        .is_empty());
    assert_eq!(catalog.take_expired(since + RETAIN_AFTER_DEATH).0, [11]);
    assert_eq!(catalog.known(), [live]);
}

/// An owner that ended takes its login off the catalog -- but not a login
/// another owner has taken since (a cold start replaced the session).
#[test]
fn an_ended_owner_leaves_the_catalog_unless_its_login_was_replaced() {
    let catalog = Catalog::new(Arc::default());
    let token = [3; 16];
    catalog.insert(token, entry(21, true));
    catalog.insert(token, entry(22, true));
    catalog.owner_ended(21);
    assert_eq!(catalog.owner_of(token), Some((1000, 22)));
    catalog.owner_ended(22);
    assert_eq!(catalog.owner_of(token), None);
}

/// Only the session's own account is told it exists.
#[test]
fn a_lookup_from_another_account_is_foreign() {
    let catalog = Catalog::new(Arc::default());
    catalog.insert([4; 16], entry(31, false));
    assert!(matches!(catalog.lookup([4; 16], 1001, &[]), Found::Foreign));
    assert!(matches!(catalog.lookup([5; 16], 1000, &[]), Found::Unknown));
    // Its owner's relink channel leads nowhere here: the owner is gone.
    assert!(matches!(catalog.lookup([4; 16], 1000, &[]), Found::Unknown));
}

/// A replacement stops the frontend and waits until it is reaped; while it
/// stands no frontend starts, and afterwards one may again.
#[test]
fn a_closed_frontend_control_waits_for_the_reap_and_admits_none() {
    let control = Arc::new(FrontendControl::default());
    assert!(control.begin(), "a frontend runs");
    let soon = Instant::now() + Duration::from_millis(50);
    assert!(!control.close_until(soon), "it is not reaped yet");
    let reaper = {
        let control = control.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            control.reaped();
        })
    };
    assert!(control.close_until(Instant::now() + Duration::from_secs(10)));
    reaper.join().unwrap();
    assert!(!control.begin(), "closed: none starts");
    control.reopen();
    assert!(control.begin());
}

/// A start skipped because an exec window was open is no crash: the next
/// try comes after the shortest wait, and the backoff stays where it was.
#[test]
fn a_skipped_start_does_not_count_toward_the_backoff() {
    let grown = BACKOFF_MIN * 8;
    assert_eq!(
        next_backoff(grown, Attempt::Skipped),
        (BACKOFF_MIN, grown),
        "no doubling, no wait of its own"
    );
    let (wait, next) = next_backoff(BACKOFF_MIN, Attempt::Skipped);
    assert_eq!((wait, next), (BACKOFF_MIN, BACKOFF_MIN));
}

/// The expiry timer ends a session nobody holds exactly when a router
/// would have: not a moment before `since + RETAIN_AFTER_DEATH`, and then
/// through the host's stop (owner and key).
#[tokio::test(start_paused = true)]
async fn the_expiry_timer_stops_an_unheld_session_at_its_deadline() {
    let catalog = Catalog::new(Arc::default());
    let since = Instant::now();
    let mut retained = entry(41, false);
    retained.state = SessionState::Retained { since };
    retained.client_key = Some(([4; 32], 7));
    catalog.insert([4; 16], retained);
    let stopped = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Shutdown::default();
    let timer = {
        let stopped = stopped.clone();
        tokio::spawn(expire(
            catalog.clone(),
            shutdown.clone(),
            move |owners: &[u32], keys: &[([u8; 32], u64)]| {
                stopped
                    .lock()
                    .unwrap()
                    .push((owners.to_vec(), keys.to_vec()))
            },
        ))
    };
    tokio::time::sleep(RETAIN_AFTER_DEATH - Duration::from_secs(1)).await;
    assert!(
        stopped.lock().unwrap().is_empty(),
        "not before its deadline"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        *stopped.lock().unwrap(),
        [(vec![41], vec![([4; 32], 7)])],
        "stopped at its deadline, its key scrubbed"
    );
    assert_eq!(catalog.owner_of([4; 16]), None);
    shutdown.request();
    timer.await.unwrap();
}

fn relink_pair() -> (OwnedFd, OwnedFd) {
    socket_pair_of(nix::sys::socket::SockType::SeqPacket).unwrap()
}

/// A session the host hands a frontend (`Lookup`) is that frontend's only
/// once it says so: a takeover never confirmed lapses after
/// `TAKEOVER_CONFIRM`, and the host keeps the session's deadline again. A
/// report confirms it.
#[test]
fn a_takeover_nobody_confirms_lapses_back_to_the_host() {
    let catalog = Catalog::new(Arc::default());
    let (host_end, _owner_end) = relink_pair();
    let mut kept = entry(51, false);
    kept.relink = host_end;
    catalog.insert([5; 16], kept);
    assert!(matches!(
        catalog.lookup([5; 16], 1000, &[]),
        Found::Owner(..)
    ));
    let handed = Instant::now();
    let confirm_by = catalog.next_deadline().expect("a confirmation deadline");
    assert!(confirm_by >= handed + TAKEOVER_CONFIRM - Duration::from_secs(1));
    assert!(catalog
        .take_expired(confirm_by - Duration::from_millis(1))
        .0
        .is_empty());
    assert!(catalog.lock().get(&[5; 16]).unwrap().attached);
    let (stopped, _) = catalog.take_expired(confirm_by);
    assert!(stopped.is_empty(), "lapsed, not ended");
    {
        let entries = catalog.lock();
        let entry = entries.get(&[5; 16]).unwrap();
        assert!(!entry.attached && entry.confirm_by.is_none());
        assert!(
            entry.deadline().is_some_and(|at| at > confirm_by),
            "its own deadline again"
        );
    }

    // Confirmed by the frontend's first report: no lapse.
    assert!(matches!(
        catalog.lookup([5; 16], 1000, &[]),
        Found::Owner(..)
    ));
    catalog.traffic([5; 16], Duration::ZERO, true);
    assert_eq!(
        catalog.next_deadline(),
        None,
        "the frontend's router decides"
    );
}

/// A takeover that lapsed (its frontend's first report did not reach the
/// host within `TAKEOVER_CONFIRM`) is the frontend's again on its next
/// report: only the running frontend reports, and only for sessions its
/// router holds, so a report is proof enough. Without that the host would
/// keep the deadline of the `Lookup` time for good, and end a session in
/// use a day later.
#[test]
fn a_lapsed_takeover_is_held_again_on_the_frontends_next_report() {
    let catalog = Catalog::new(Arc::default());
    let (traffic, retained) = ([6; 16], [7; 16]);
    let mut owner_ends = Vec::new();
    for (token, pid) in [(traffic, 71), (retained, 72)] {
        let (host_end, owner_end) = relink_pair();
        owner_ends.push(owner_end);
        let mut kept = entry(pid, false);
        kept.relink = host_end;
        catalog.insert(token, kept);
        assert!(matches!(catalog.lookup(token, 1000, &[]), Found::Owner(..)));
    }
    let confirm_by = catalog.next_deadline().expect("a confirmation deadline");
    let (stopped, _) = catalog.take_expired(confirm_by + Duration::from_millis(1));
    assert!(stopped.is_empty(), "lapsed, not ended");
    assert!(catalog.lock().values().all(|entry| !entry.attached));

    catalog.traffic(traffic, Duration::from_secs(2), true);
    catalog.retained(retained);
    {
        let entries = catalog.lock();
        for token in [traffic, retained] {
            let entry = entries.get(&token).unwrap();
            assert!(entry.attached, "the frontend holds it again");
            assert_eq!(entry.deadline(), None, "no confirmation pending");
        }
    }
    assert_eq!(
        catalog.next_deadline(),
        None,
        "the frontend's router decides"
    );
    assert!(matches!(
        state_of(&catalog, retained),
        SessionState::Retained { .. }
    ));
    assert_eq!(state_of(&catalog, traffic), SessionState::Live);
}

/// An owner whose relink channel does not take a link just now is busy,
/// not gone: `Lookup` says `Unavailable` (never `Unknown`, which would
/// have a fresh session replace it) and `Relink` says so too. An owner
/// that closed its channel is gone.
#[test]
fn a_busy_owner_is_unavailable_and_a_closed_one_is_gone() {
    let catalog = Catalog::new(Arc::default());
    let (host_end, owner_end) = relink_pair();
    let mut busy = entry(61, false);
    busy.relink = host_end;
    catalog.insert([6; 16], busy);
    {
        let entries = catalog.lock();
        let channel = &entries.get(&[6; 16]).unwrap().relink;
        let mut filled = false;
        for _ in 0..100_000 {
            let (front, _) = socket_pair().unwrap();
            match send_descriptor(channel, &front) {
                Ok(()) => {}
                Err(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock, "{error}");
                    filled = true;
                    break;
                }
            }
        }
        assert!(filled, "the relink channel fills up");
    }
    assert!(matches!(
        catalog.lookup([6; 16], 1000, &[]),
        Found::Unavailable
    ));
    assert!(matches!(catalog.relink([6; 16]), Relinked::Unavailable));
    assert!(!catalog.lock().get(&[6; 16]).unwrap().attached);
    drop(owner_end);
    assert!(matches!(catalog.relink([6; 16]), Relinked::Gone));
    assert!(matches!(catalog.lookup([6; 16], 1000, &[]), Found::Unknown));
}

/// The keys of the sessions the host ends: scrubbed when no other session
/// has the same key.
#[test]
fn an_ended_session_leaves_its_key_unless_another_has_it() {
    let catalog = Catalog::new(Arc::default());
    let mut a = entry(71, true);
    a.client_key = Some(([7; 32], 1));
    let mut b = entry(72, true);
    b.client_key = Some(([7; 32], 1));
    let mut c = entry(73, true);
    c.client_key = Some(([8; 32], 2));
    catalog.insert([71; 16], a);
    catalog.insert([72; 16], b);
    catalog.insert([73; 16], c);
    assert!(catalog.owner_ended(71).is_empty(), "session 72 has the key");
    assert_eq!(catalog.owner_ended(72), [([7; 32], 1)]);
    assert_eq!(catalog.owner_ended(73), [([8; 32], 2)]);
    catalog.insert([74; 16], entry(74, true));
    catalog.client_key([74; 16], [9; 32], Some(5));
    assert_eq!(catalog.owner_ended(74), [([9; 32], 5)]);
}

/// Frontends are spawned from one thread that lives as long as the host,
/// never from the caller's (a runtime thread may end, and its children
/// would die with it, `PR_SET_PDEATHSIG`); a job that panics does not end
/// that thread.
#[test]
fn frontends_are_spawned_from_one_lasting_thread() {
    let first = on_spawner_thread(|| std::thread::current().id()).unwrap();
    let second = on_spawner_thread(|| std::thread::current().id()).unwrap();
    assert_eq!(first, second, "the same thread");
    assert_ne!(first, std::thread::current().id(), "not the caller's");
    let panicked = on_spawner_thread(|| -> u32 { panic!("a spawn job that panics") });
    assert!(panicked.is_err());
    let after = on_spawner_thread(|| std::thread::current().id()).unwrap();
    assert_eq!(after, first, "the thread survived the panic");
}

/// A fresh session's key, which its frontend's router reports ahead of
/// the `Create`, is the session's once it is created -- so the host scrubs
/// it when it ends that session itself. Reported for a session that was
/// never created (its frontend died first), it is dropped.
#[test]
fn a_key_reported_before_its_create_is_the_created_sessions() {
    let catalog = Catalog::new(Arc::default());
    catalog.client_key([81; 16], [8; 32], Some(4));
    assert_eq!(catalog.owner_of([81; 16]), None, "nothing created yet");
    catalog.created([81; 16], entry(81, true));
    assert_eq!(catalog.owner_ended(81), [([8; 32], 4)]);

    catalog.client_key([82; 16], [9; 32], Some(5));
    catalog.detach_all();
    catalog.created([82; 16], entry(82, true));
    assert!(
        catalog.owner_ended(82).is_empty(),
        "its frontend died first"
    );
}

/// What a full host gives up for a new session is what a router would:
/// the oldest retained session -- here among the sessions no frontend
/// holds, which no router knows of. At the account's own cap only its own;
/// otherwise anyone's. Never a live one, never one a frontend holds.
#[test]
fn a_full_host_gives_up_its_oldest_retained_unheld_session() {
    let catalog = Catalog::new(Arc::default());
    let at = Instant::now();
    let retained = |pid, uid, attached, ago: u64| {
        let mut entry = entry(pid, attached);
        entry.uid = uid;
        entry.state = SessionState::Retained {
            since: at - Duration::from_secs(ago),
        };
        entry
    };
    catalog.insert([1; 16], retained(51, 1000, false, 10));
    // Older, but held by the running frontend: its router's to evict.
    catalog.insert([2; 16], retained(52, 1000, true, 50));
    // Older, but another account's.
    catalog.insert([3; 16], retained(53, 2000, false, 40));
    catalog.insert([4; 16], entry(54, false));
    let mut key = retained(55, 1000, false, 5);
    key.client_key = Some(([5; 32], 9));
    catalog.insert([5; 16], key);

    // At its own cap, an account gives up only one of its own.
    assert_eq!(catalog.evict_retained(Some(1000)), Some((51, Vec::new())));
    assert_eq!(catalog.owner_of([1; 16]), None, "taken off");
    // At the daemon's cap, the oldest of anyone's.
    assert_eq!(catalog.evict_retained(None), Some((53, Vec::new())));
    assert_eq!(
        catalog.evict_retained(Some(1000)),
        Some((55, vec![([5; 32], 9)])),
        "with its key, which no other session has"
    );
    assert_eq!(
        catalog.evict_retained(None),
        None,
        "only live or held ones left"
    );
    // A live session nobody holds whose client has been silent past the
    // server's death timer is one a router holds retained by now -- since
    // that death.
    let mut silent = entry(56, false);
    silent.last_client_recv = at - SERVER_DEATH_AFTER - Duration::from_secs(1);
    catalog.insert([6; 16], silent);
    let mut later = retained(57, 1000, false, 0);
    later.state = SessionState::Retained {
        since: at - Duration::from_millis(1),
    };
    catalog.insert([7; 16], later);
    assert_eq!(
        catalog.evict_retained(None),
        Some((56, Vec::new())),
        "the older death"
    );
    assert_eq!(catalog.evict_retained(None), Some((57, Vec::new())));
    assert!(catalog.owner_of([2; 16]).is_some() && catalog.owner_of([4; 16]).is_some());
}

/// The running frontend's router ended a session (`Ended`): the host takes
/// it off the catalog at once and gives back its owner -- also one whose
/// link was lost, which no `End` from that router reaches. A frontend's
/// word about a session it does not hold changes nothing.
#[test]
fn a_session_the_router_ended_leaves_the_catalog_at_once() {
    let catalog = Catalog::new(Arc::default());
    catalog.insert([1; 16], entry(61, true));
    catalog.insert([2; 16], entry(62, false));
    assert_eq!(catalog.router_ended([1; 16]), Some(61));
    assert_eq!(catalog.owner_of([1; 16]), None);
    assert_eq!(catalog.router_ended([1; 16]), None, "once");
    assert_eq!(catalog.router_ended([2; 16]), None, "not the frontend's");
    assert!(catalog.owner_of([2; 16]).is_some());
}

/// A host whose frontends would start from `image`, with no frontend and
/// no owner running.
fn host_serving(image: FrontendImage) -> Arc<Host> {
    let owners = OwnerHost::new(
        SelfImage::hold().unwrap(),
        None,
        None,
        crate::owner_process::OwnerFleet::new(),
        crate::host_services::HostServices::new(Default::default()),
    );
    let host = Host::new(
        SelfImage::hold().unwrap(),
        owners,
        Catalog::new(Arc::default()),
        Arc::default(),
        HostStart {
            server_priv: [1; 32],
            server_pub: [2; 32],
            reset_secret: None,
            authorized_keys: None,
            account: "me".into(),
            allowlist: HostAllowlist::new(Arc::default()),
            admission: Arc::default(),
            runtime_threads: None,
        },
    );
    host.set_current(image);
    host
}

/// An image other than this binary, with its own links and profiles.
fn image(build: u64, links: Vec<u16>, profiles: Vec<[u8; 3]>) -> FrontendImage {
    FrontendImage {
        image: SelfImage::hold().unwrap(),
        info: Arc::new(ImageInfo {
            identity: ImageIdentity::Known(crate::server_info::FrontendIdentity {
                version: format!("0.{build}.0"),
                build,
                checksum: format!("{build:064x}"),
                profiles: Vec::new(),
                generation: [build as u8; 16],
            }),
            host_revision: crate::state::HOST_REVISION,
            link_versions: links,
            profiles,
        }),
    }
}

/// An owner as `start_raw` gives it, with `relink` as its relink channel.
fn raw_owner(pid: u32, relink: OwnedFd) -> crate::owner_process::RawOwner {
    crate::owner_process::RawOwner {
        pid,
        pidfd: descriptor(),
        link: descriptor(),
        relink,
    }
}

/// What the census says of a session: which links its owner speaks (those
/// of the image it was started from) and which profiles its client may
/// speak (those of the frontend it was last handed to). A switch of the
/// image changes a session's profiles only once a frontend of the new image
/// is handed the session, and never its links: its owner runs on.
#[test]
fn the_census_reports_each_sessions_owner_links_and_client_profiles() {
    let host = host_serving(image(1, vec![1], vec![[1, 1, 1]]));
    let (looked_up, kept) = ([1; 16], [2; 16]);
    let (relink, _owner_end) = relink_pair();
    let started = host.current();
    host.created(looked_up, 1000, raw_owner(91, relink), &started)
        .unwrap();
    host.created(kept, 1000, raw_owner(92, descriptor()), &started)
        .unwrap();
    host.catalog.traffic(kept, Duration::ZERO, true);

    host.set_current(image(2, vec![2], vec![[2, 2, 2]]));
    // The running frontend dies; the next one, started from B, is handed
    // one of the sessions.
    host.catalog.detach_all();
    assert!(matches!(host.lookup(looked_up, 1000), Found::Owner(..)));
    host.catalog.traffic(looked_up, Duration::ZERO, true);

    let mut facts = host.catalog.census();
    facts.sort_by_key(|f| f.profiles.clone());
    assert_eq!(
        facts,
        [
            crate::frontend_upgrade::SessionFacts {
                attached: false,
                profiles: vec![[1, 1, 1]],
                links: vec![1],
            },
            crate::frontend_upgrade::SessionFacts {
                attached: true,
                profiles: vec![[2, 2, 2]],
                links: vec![1],
            },
        ],
        "B's profiles, A's links; the frontend's death detached the other"
    );
}

/// A frontend's `Ready` is recorded for whoever waits for it, and is
/// otherwise just a packet that says the frontend is alive.
#[tokio::test]
async fn a_frontends_ready_is_recorded_for_whoever_waits() {
    let host = host_serving(image(1, vec![1], vec![[1, 1, 1]]));
    let (host_end, _front_end) = relink_pair();
    let channel = Channel::new(host_end).unwrap();
    let ready = Readiness::default();
    let wait = Duration::from_millis(50);
    assert!(
        tokio::time::timeout(wait, ready.reported()).await.is_err(),
        "not before it says so"
    );
    let alive = ToHost::Alive.encode().unwrap();
    assert!(
        host.serve_request(&channel, 7, &alive, &mut HashMap::new(), &ready)
            .await
    );
    assert!(tokio::time::timeout(wait, ready.reported()).await.is_err());
    let packet = ToHost::Ready.encode().unwrap();
    assert!(
        host.serve_request(&channel, 7, &packet, &mut HashMap::new(), &ready)
            .await
    );
    tokio::time::timeout(wait, ready.reported())
        .await
        .expect("reported");
}
