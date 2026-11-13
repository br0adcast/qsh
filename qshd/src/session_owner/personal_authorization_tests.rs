use super::*;
use crate::session_owner::host::{HostDecision, HostLimits, HostState};
use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};

fn host(mode: HostMode) -> HostState {
    let b = ByteLimits {
        channel_bytes: 1024,
        session_bytes: 2048,
        account_bytes: 4096,
        global_bytes: 8192,
    };
    HostState::new(
        mode,
        HostLimits::new(
            ResourceLimits {
                max_reservations: 128,
                screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                    .unwrap(),
                snapshot_transfer: b,
                control_queue: b,
            },
            4,
            4,
            4,
            4,
            1000,
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn personal529_host_system_mode_foreign_frontend_and_wrong_intent_refuse_before_transport() {
    let mut h = host(HostMode::System);
    let f = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap();
    assert!(PersonalAuthorization::new(
        h.instance(),
        f,
        HostMode::System,
        Arc::new(Mutex::new(vec![])),
        4,
        Arc::new(|| 0)
    )
    .is_err());
    let uid = nix::unistd::geteuid().as_raw();
    let mut h = host(HostMode::Personal { canonical_uid: uid });
    let f = h
        .admit_frontend(AuthenticatedPeer::for_test(
            h.instance(),
            HostMode::Personal { canonical_uid: uid },
        ))
        .unwrap();
    let adapter = PersonalAuthorization::new(
        h.instance(),
        f,
        HostMode::Personal { canonical_uid: uid },
        Arc::new(Mutex::new(vec![])),
        1,
        Arc::new(|| 0),
    )
    .unwrap();
    let mut other = host(HostMode::Personal { canonical_uid: uid });
    let foreign = other
        .admit_frontend(AuthenticatedPeer::for_test(
            other.instance(),
            HostMode::Personal { canonical_uid: uid },
        ))
        .unwrap();
    assert!(adapter
        .reserve(other.begin_authentication(foreign, 0, 100).unwrap(), 0)
        .is_err());
    let (observer, lease) = adapter
        .reserve(h.begin_authentication(f, 0, 100).unwrap(), 0)
        .unwrap();
    let refusal = adapter
        .reserve(h.begin_authentication(f, 0, 100).unwrap(), 0)
        .err()
        .unwrap();
    assert_eq!(refusal.reason, AuthorityError::Capacity);
    assert!(h.apply_policy_result(refusal.result, 1).is_err());
    drop(observer);
    assert!(lease.try_authenticate(&mut h, 1).is_err());
    drop(lease);
    assert_eq!(adapter.registrations(), 0);
}

use std::future::Future;
use std::pin::Pin;
use transport::{
    AuthPolicy, BackendFactory, Connection, ConnectionConfig, LoginEndedReports, Role,
    SessionBackend, SessionIo, SessionManager, Shutdown,
};
struct HoldingBackend;
impl SessionBackend for HoldingBackend {
    fn run(&self, mut io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move { while io.recv().await.is_some() {} })
    }
}
struct PersonalServer {
    public: [u8; 32],
    addr: std::net::SocketAddr,
    stop: Shutdown,
    task: tokio::task::JoinHandle<Result<(), transport::ShutdownError>>,
    allowlist: transport::SharedAllowlist,
}
impl PersonalServer {
    async fn start(
        observer: Arc<dyn PersonalAdmissionObserver>,
        allowlist: transport::SharedAllowlist,
    ) -> Self {
        let shared = allowlist.clone();
        let server = transport::generate_keypair();
        let server_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = server_socket.local_addr().unwrap();
        let shutdown = Shutdown::default();
        let auth = transport::ServerAuth {
            allowlist,
            server_pub: server.public,
            verifier: None,
            self_principal: transport::Principal {
                uid: nix::unistd::geteuid().as_raw(),
                name: "frontend-untrusted-name".into(),
                identity: "frontend untrusted label".into(),
                incarnation: transport::NO_INCARNATION,
            },
            nonces: Arc::new(transport::RandomNonces),
            logins: Arc::new(transport::ForgetNothing),
        };
        let task = tokio::spawn(SessionManager::serve_with_personal_admission(
            server_socket,
            server.private,
            auth,
            BackendFactory(Arc::new(HoldingBackend)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            LoginEndedReports::none(),
            shutdown.clone(),
            None,
            Some(observer),
        ));
        Self {
            public: server.public,
            addr,
            stop: shutdown,
            task,
            allowlist: shared,
        }
    }
    async fn prove(
        &self,
        slot: Arc<Slot>,
        key: &transport::handshake::Keypair,
        token: [u8; 16],
        start_kind: transport::StartKind,
    ) {
        {
            let mut list = self.allowlist.lock().unwrap();
            if !list.contains(&key.public) {
                list.push(key.public);
            }
        }
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Connection::new(ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(self.public),
            auth: AuthPolicy::Allowlist(vec![self.public]),
        });
        let payload = transport::encode_msg1(&transport::Msg1Payload {
            offered: transport::Features::SUPPORTED,
            start_kind,
            token,
            method: transport::AuthMethod::Allowlist,
        });
        for dg in client.start_with_payload(std::time::Instant::now(), self.addr, &payload) {
            socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        let mut buf = vec![0; 65536];
        let (n, src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        for dg in client.on_datagram(std::time::Instant::now(), src, &buf[..n]) {
            socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        client.request_ping(std::time::Instant::now());
        for dg in client.on_timeout(std::time::Instant::now()) {
            socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slot.delivery.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
async fn real_packets(
    observer: Arc<dyn PersonalAdmissionObserver>,
    slot: Arc<Slot>,
    allowlist: transport::SharedAllowlist,
) -> (
    Shutdown,
    tokio::task::JoinHandle<Result<(), transport::ShutdownError>>,
    [u8; 32],
) {
    let server = PersonalServer::start(observer, allowlist).await;
    let key = transport::generate_keypair();
    server
        .prove(slot, &key, [53; 16], transport::StartKind::Cold)
        .await;
    (server.stop, server.task, key.public)
}
async fn real_auth(
    adapter: &PersonalAuthorization,
    h: &mut HostState,
    f: FrontendAdmission,
    allowlist: transport::SharedAllowlist,
    now: u64,
) -> (
    PersonalAdmission,
    AuthenticationAttempt,
    Shutdown,
    tokio::task::JoinHandle<Result<(), transport::ShutdownError>>,
    [u8; 32],
) {
    let intent = h.begin_authentication(f, now, now + 10000).unwrap();
    let (observer, lease) = adapter.reserve(intent, now).unwrap();
    let (stop, task, key) = real_packets(observer, lease.slot.clone(), allowlist).await;
    let HostDecision::Authenticated(attempt) = lease.try_authenticate(h, now + 1).unwrap() else {
        panic!()
    };
    (lease, attempt, stop, task, key)
}
fn personal() -> (
    HostState,
    FrontendAdmission,
    PersonalAuthorization,
    transport::SharedAllowlist,
) {
    let uid = nix::unistd::geteuid().as_raw();
    let mode = HostMode::Personal { canonical_uid: uid };
    let mut h = host(mode);
    let f = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), mode))
        .unwrap();
    let list = Arc::new(Mutex::new(vec![]));
    let adapter =
        PersonalAuthorization::new(h.instance(), f, mode, list.clone(), 4, Arc::new(|| 0)).unwrap();
    (h, f, adapter, list)
}
#[tokio::test]
async fn personal529_real_noise_auth_then_distinct_fresh_issue_consume_and_key_revocation() {
    let (mut h, f, adapter, list) = personal();
    let (lease, a, stop, task, key) = real_auth(&adapter, &mut h, f, list.clone(), 0).await;
    assert!(
        lease.try_authenticate(&mut h, 2).is_err(),
        "completion is one-use"
    );
    let locator = h.create_session(a, 2).unwrap();
    let issue = h.begin_issue(a, locator, 3, 100).unwrap();
    let HostDecision::GrantIssued(g) = adapter.check_current(&lease, &mut h, issue, 4).unwrap()
    else {
        panic!()
    };
    list.lock().unwrap().retain(|k| *k != key);
    let consume = h.begin_consume(a, g.grant(), g.binding(), 5, 100).unwrap();
    assert!(adapter.check_current(&lease, &mut h, consume, 6).is_err());
    assert_eq!(h.catalog_len(), 1);
    stop.request();
    task.await.unwrap().unwrap();
    drop(lease);
    assert_eq!(adapter.registrations(), 0);
}
#[tokio::test]
async fn personal529_changed_canonical_mapping_and_known_cancel_refuse_without_catalog_loss() {
    let (mut h, f, mut adapter, list) = personal();
    let original = adapter.inner.account.clone();
    let current = Arc::new(Mutex::new(original));
    let copy = current.clone();
    Arc::get_mut(&mut adapter.inner).unwrap().resolve =
        Arc::new(move |_| copy.try_lock().ok().map(|a| a.clone()));
    let (lease, a, stop, task, _) = real_auth(&adapter, &mut h, f, list, 0).await;
    let locator = h.create_session(a, 2).unwrap();
    current.lock().unwrap().name.push_str("-changed");
    let issue = h.begin_issue(a, locator, 3, 100).unwrap();
    assert!(adapter.check_current(&lease, &mut h, issue, 4).is_err());
    assert_eq!(h.catalog_len(), 1);
    stop.request();
    task.await.unwrap().unwrap();
    drop(lease);
}
#[test]
fn personal529_unused_disconnected_and_expired_tickets_recover_bounded_capacity() {
    let (mut h, f, adapter, _) = personal();
    let mut identities = std::collections::HashSet::new();
    for i in 0..20 {
        let intent = h.begin_authentication(f, i * 2, i * 2 + 1).unwrap();
        assert!(identities.insert(intent.binding.attempt.identity));
        let (observer, lease) = adapter.reserve(intent, i * 2).unwrap();
        drop(observer);
        assert!(lease.try_authenticate(&mut h, i * 2 + 1).is_err());
        drop(lease);
        assert_eq!(adapter.registrations(), 0);
    }
    let (observer, lease) = adapter
        .reserve(h.begin_authentication(f, 100, 101).unwrap(), 100)
        .unwrap();
    lease.cancel(&mut h).unwrap();
    drop(observer);
    assert_eq!(adapter.registrations(), 0);
}

#[tokio::test]
async fn personal529_full_and_disconnected_result_sinks_refuse_actual_noise_completion() {
    for disconnected in [false, true] {
        let (mut h, f, adapter, list) = personal();
        let intent = h.begin_authentication(f, 0, 100).unwrap();
        let (observer, lease) = adapter.reserve_inner(intent, 0).unwrap();
        let slot = lease.slot.clone();
        if disconnected {
            // Fault injection disconnects the reserved consumer without changing
            // the actual Noise exchange or the attempt's active registration.
            let (_tx, rx) = sync_channel(1);
            let old = std::mem::replace(&mut *lease.reply.lock().unwrap(), rx);
            drop(old);
        } else {
            // A consumed one-use ticket cannot legitimately enqueue twice.
            observer
                .tickets
                .lock()
                .unwrap()
                .front()
                .unwrap()
                .reply
                .try_send(Completion::Refused)
                .ok()
                .unwrap();
        }
        let (stop, task, _) = real_packets(observer, slot.clone(), list).await;
        assert_eq!(
            slot.delivery.load(Ordering::Acquire),
            if disconnected { 4 } else { 3 }
        );
        assert!(lease.try_authenticate(&mut h, 1).is_err());
        stop.request();
        task.await.unwrap().unwrap();
        drop(lease);
        drop(slot);
        assert_eq!(adapter.registrations(), 0);
    }
}
#[tokio::test]
async fn personal529_host_cancel_retired_frontend_and_deadline_win_queued_real_completion() {
    for mode in 0..4 {
        let (mut h, f, adapter, list) = personal();
        let intent = h.begin_authentication(f, 0, 100).unwrap();
        let attempt = intent.binding.attempt;
        let (observer, lease) = adapter.reserve(intent, 0).unwrap();
        let (stop, task, _) = real_packets(observer, lease.slot.clone(), list).await;
        match mode {
            0 => h.cancel_attempt(attempt).unwrap(),
            1 => h.retire_frontend(f).unwrap(),
            3 => h.revoke_account(nix::unistd::geteuid().as_raw()).unwrap(),
            _ => {}
        }
        assert!(lease
            .try_authenticate(&mut h, if mode == 2 { 100 } else { 1 })
            .is_err());
        assert_eq!(h.catalog_len(), 0);
        stop.request();
        task.await.unwrap().unwrap();
        drop(lease);
        assert_eq!(adapter.registrations(), 0);
    }
}
#[tokio::test]
async fn personal529_fresh_consume_succeeds_and_wrong_lease_cannot_supply_policy() {
    let (mut h, f, adapter, list) = personal();
    let (lease, a, stop, task, key) = real_auth(&adapter, &mut h, f, list.clone(), 0).await;
    let locator = h.create_session(a, 2).unwrap();
    let issue = h.begin_issue(a, locator, 3, 100).unwrap();
    let HostDecision::GrantIssued(g) = adapter.check_current(&lease, &mut h, issue, 4).unwrap()
    else {
        panic!()
    };
    let consume = h.begin_consume(a, g.grant(), g.binding(), 5, 100).unwrap();
    assert!(matches!(
        adapter.check_current(&lease, &mut h, consume, 6),
        Ok(HostDecision::GrantConsumed(_))
    ));
    // A second attempt using the same registered key never owns the first
    // lease's authority, and dropping it never removes that allowlist entry.
    let (observer, other) = adapter
        .reserve(h.begin_authentication(f, 7, 100).unwrap(), 7)
        .unwrap();
    drop(observer);
    assert!(other.try_authenticate(&mut h, 8).is_err());
    let issue = h.begin_issue(a, locator, 9, 100).unwrap();
    assert!(
        adapter.check_current(&other, &mut h, issue, 10).is_err(),
        "a different attempt cannot supply policy"
    );
    drop(other);
    assert!(list.lock().unwrap().contains(&key));
    drop(lease);
    stop.request();
    task.await.unwrap().unwrap();
    assert_eq!(adapter.registrations(), 0);
}

#[tokio::test]
async fn personal529_policy_deadline_crossed_during_canonical_read_cannot_grant() {
    let (mut h, f, mut adapter, list) = personal();
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let expire = Arc::new(AtomicBool::new(false));
    let inner = Arc::get_mut(&mut adapter.inner).unwrap();
    let read_clock = clock.clone();
    inner.clock = Arc::new(move || read_clock.load(Ordering::Acquire));
    let account = inner.account.clone();
    let expire_read = expire.clone();
    let advance = clock.clone();
    inner.resolve = Arc::new(move |_| {
        if expire_read.load(Ordering::Acquire) {
            advance.store(200, Ordering::Release);
        }
        Some(account.clone())
    });
    let (lease, a, stop, task, _) = real_auth(&adapter, &mut h, f, list, 0).await;
    let locator = h.create_session(a, 2).unwrap();
    expire.store(true, Ordering::Release);
    let intent = h.begin_issue(a, locator, 3, 100).unwrap();
    let answer = adapter.check_current(&lease, &mut h, intent, 4);
    stop.request();
    task.await.unwrap().unwrap();
    assert!(
        answer.is_err(),
        "a slow current-policy read may not reuse the pre-read time"
    );
}

#[tokio::test]
async fn personal529_one_observer_handles_fresh_reconnect_and_old_cancel_keeps_new_key() {
    let (mut h, f, adapter, list) = personal();
    let (observer, old) = adapter
        .reserve(h.begin_authentication(f, 0, 100).unwrap(), 0)
        .unwrap();
    old.cancel(&mut h).unwrap();
    let (next, first) = adapter
        .reserve(h.begin_authentication(f, 1, 100).unwrap(), 1)
        .unwrap();
    assert!(Arc::ptr_eq(&observer, &next));
    let server = PersonalServer::start(observer, list.clone()).await;
    let key = transport::generate_keypair();
    server
        .prove(
            first.slot.clone(),
            &key,
            [71; 16],
            transport::StartKind::Cold,
        )
        .await;
    let HostDecision::Authenticated(a) = first.try_authenticate(&mut h, 2).unwrap() else {
        panic!()
    };
    let locator = h.create_session(a, 3).unwrap();
    let (next, second) = adapter
        .reserve(h.begin_authentication(f, 4, 100).unwrap(), 4)
        .unwrap();
    assert!(Arc::ptr_eq(
        &next,
        &(adapter.observer.clone() as Arc<dyn PersonalAdmissionObserver>)
    ));
    server
        .prove(
            second.slot.clone(),
            &key,
            [71; 16],
            transport::StartKind::Warm,
        )
        .await;
    let HostDecision::Authenticated(b) = second.try_authenticate(&mut h, 5).unwrap() else {
        panic!()
    };
    assert_ne!(a, b);
    first.cancel(&mut h).unwrap();
    assert!(list.lock().unwrap().contains(&key.public));
    let intent = h.begin_issue(b, locator, 6, 100).unwrap();
    assert!(matches!(
        adapter.check_current(&second, &mut h, intent, 7),
        Ok(HostDecision::GrantIssued(_))
    ));
    second.cancel(&mut h).unwrap();
    server.stop.request();
    server.task.await.unwrap().unwrap();
    assert_eq!(adapter.registrations(), 0);
}
#[test]
fn personal529_expired_queued_ticket_is_pruned_before_new_reservation() {
    let (mut h, f, adapter, _) = personal();
    let (observer, old) = adapter
        .reserve(h.begin_authentication(f, 0, 1).unwrap(), 0)
        .unwrap();
    h.sweep(2).unwrap();
    let (next, new) = adapter
        .reserve(h.begin_authentication(f, 2, 100).unwrap(), 2)
        .unwrap();
    assert!(Arc::ptr_eq(&observer, &next));
    assert_eq!(adapter.registrations(), 1);
    assert_eq!(adapter.observer.tickets.lock().unwrap().len(), 1);
    assert_eq!(old.delivery(), PersonalDelivery::Cancelled);
    assert!(old.try_authenticate(&mut h, 3).is_err());
    new.cancel(&mut h).unwrap();
    drop(old);
    assert_eq!(adapter.registrations(), 0);
}
