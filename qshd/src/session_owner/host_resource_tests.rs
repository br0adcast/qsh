use super::*;
use crate::session_owner::authorization::{
    local_peer,
    personal_authorization::{PersonalAdmission, PersonalAuthorization, PersonalDelivery},
};
use crate::session_owner::local_channel::{
    admit_channel, provision_pair, AdmissionBudget, TrustedChannelConfig,
};
use crate::session_owner::owner_resource_contract::OwnerResourceRequest;
use crate::session_owner::protocol::OwnerRole;
use crate::session_owner::resource_contract::{ByteLimits, ReservationKind, ScreenLimits};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use transport::personal_admission::PersonalAdmissionObserver;
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
        lease: &PersonalAdmission,
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
            while lease.delivery() == PersonalDelivery::Pending {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

async fn authenticated() -> (HostState, AuthenticationAttempt, PersonalAdmission) {
    let uid = nix::unistd::geteuid().as_raw();
    let mode = HostMode::Personal { canonical_uid: uid };
    let bytes = ByteLimits {
        channel_bytes: 64,
        session_bytes: 96,
        account_bytes: 128,
        global_bytes: 256,
    };
    let mut h = HostState::new(
        mode,
        HostLimits::new(
            ResourceLimits {
                max_reservations: 128,
                screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                    .unwrap(),
                snapshot_transfer: bytes,
                control_queue: bytes,
            },
            8,
            8,
            8,
            8,
            1000,
        )
        .unwrap(),
    )
    .unwrap();
    let budget = AdmissionBudget::new(1).unwrap();
    let (a, b) = provision_pair(
        TrustedChannelConfig {
            host: h.instance(),
            owner: None,
            requester: OwnerRole::Frontend,
            mode,
            system_uid: uid,
            min_version: 1,
            max_version: 1,
        },
        &budget,
    )
    .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let worker = std::thread::spawn(move || admit_channel(a, until));
    let mut host_channel = admit_channel(b, until).unwrap();
    let frontend_channel = worker.join().unwrap().unwrap();
    let peer = local_peer::authenticate_frontend(&mut host_channel, mode).unwrap();
    let f = h.admit_frontend(peer).unwrap();
    let list = Arc::new(Mutex::new(vec![]));
    let adapter =
        PersonalAuthorization::new(h.instance(), f, mode, list.clone(), 8, Arc::new(|| 0)).unwrap();
    let (observer, lease) = adapter
        .reserve(h.begin_authentication(f, 0, 10000).unwrap(), 0)
        .unwrap();
    let server = PersonalServer::start(observer, list).await;
    server
        .prove(
            &lease,
            &transport::generate_keypair(),
            [53; 16],
            transport::StartKind::Cold,
        )
        .await;
    let HostDecision::Authenticated(attempt) = lease.try_authenticate(&mut h, 1).unwrap() else {
        panic!("real proof refused")
    };
    server.stop.request();
    server.task.await.unwrap().unwrap();
    drop((frontend_channel, host_channel));
    assert_eq!(budget.in_use(), 0);
    (h, attempt, lease)
}
#[tokio::test]
async fn resources529_real_admission_provisions_and_drop_does_not_refund() {
    let (mut h, a, _lease) = authenticated().await;
    let (locator, owner) = h.create_session_provisioned(a, 2).unwrap();
    let request = OwnerResourceRequest {
        locator,
        channel: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 40,
        screen_charge: None,
    };
    let admitted = owner.reserve(request, RequestId::new(1).unwrap()).unwrap();
    assert_eq!(admitted.reservation().locator, locator);
    drop(admitted);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
}
fn request(locator: SessionLocator, channel: u64, bytes: u64) -> OwnerResourceRequest {
    OwnerResourceRequest {
        locator,
        channel: transport::channel_geometry::ChannelInstance::new(channel).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes,
        screen_charge: None,
    }
}
#[tokio::test]
async fn resources529_same_uid_sessions_share_debt_and_raw_receipts_are_not_cleanup() {
    use crate::session_owner::resource_contract::ReservationReceipt;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let (t, two) = h.create_session_provisioned(a, 3).unwrap();
    let x = one
        .reserve(request(s, 1, 64), RequestId::new(1).unwrap())
        .unwrap();
    let y = two
        .reserve(request(t, 1, 64), RequestId::new(2).unwrap())
        .unwrap();
    assert!(two
        .reserve(request(t, 2, 1), RequestId::new(3).unwrap())
        .is_err());
    assert!(one
        .reserve(request(t, 2, 1), RequestId::new(4).unwrap())
        .is_err());
    let receipt = ReservationReceipt {
        id: RequestId::new(1).unwrap(),
        reservation: x.reservation().id,
        locator: s,
        channel: x.reservation().channel,
    };
    assert!(one.client().release(&x, receipt).is_err());
    assert!(one.client().reserve(x.reservation(), receipt.id).is_err());
    drop((x, y));
    h.sweep(30_003).unwrap();
    assert_eq!(h.catalog_len(), 2);
    assert_eq!(h.resources.lock().unwrap().reservations(), 2);
}
#[tokio::test]
async fn resources529_host_bound_storage_final_reference_controls_refund() {
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let x = one
        .reserve(request(s, 1, 40), RequestId::new(1).unwrap())
        .unwrap();
    let charge = one.bind_storage(x).unwrap();
    let held = charge.clone();
    let backing = vec![0u8; charge.bytes() as usize];
    charge.allow_release();
    drop(charge);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    drop(backing);
    drop(held);
    assert_eq!(h.resources.lock().unwrap().reservations(), 0);
    h.sweep(30_002).unwrap();
    assert_eq!(h.catalog_len(), 0);
    assert!(one
        .reserve(request(s, 1, 1), RequestId::new(2).unwrap())
        .is_err());
}
#[tokio::test]
async fn resources529_cross_host_and_session_tokens_preserve_original_custody() {
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let (_, two) = h.create_session_provisioned(a, 3).unwrap();
    let (mut other, b, _lease2) = authenticated().await;
    let (_, foreign) = other.create_session_provisioned(b, 2).unwrap();
    let x = one
        .reserve(request(s, 1, 40), RequestId::new(1).unwrap())
        .unwrap();
    let (_, x) = *foreign.bind_storage(x).err().unwrap();
    let (_, x) = *two.bind_storage(x).err().unwrap();
    let c = one.bind_storage(x).unwrap();
    c.allow_release();
    drop(c);
    assert_eq!(h.resources.lock().unwrap().reservations(), 0);
    assert_eq!(other.resources.lock().unwrap().reservations(), 0);
}
#[tokio::test]
async fn resources529_malformed_requests_and_exhaustion_do_not_reconstruct_ids() {
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    assert!(one
        .reserve(request(s, 1, 0), RequestId::new(1).unwrap())
        .is_err());
    let mut ids = std::collections::HashSet::new();
    for n in 1..=128 {
        let mut r = request(s, n, 1);
        r.kind = ReservationKind::OutputHistory;
        let x = one.reserve(r, RequestId::new(n).unwrap()).unwrap();
        assert!(ids.insert(x.reservation().id.get()));
        drop(x);
    }
    let mut r = request(s, 129, 1);
    r.kind = ReservationKind::OutputHistory;
    assert!(one.reserve(r, RequestId::new(129).unwrap()).is_err());
    assert_eq!(h.resources.lock().unwrap().reservations(), 128);
}
fn screen_request(
    locator: SessionLocator,
    channel: u64,
    size: terminal_size::TerminalSize,
) -> OwnerResourceRequest {
    let slots = crate::screen_budget::ScreenEnvelope::new(size)
        .charge()
        .unwrap();
    OwnerResourceRequest {
        locator,
        channel: transport::channel_geometry::ChannelInstance::new(channel).unwrap(),
        kind: ReservationKind::ScreenModel,
        bytes: 0,
        screen_charge: Some(crate::session_owner::resource_contract::ScreenCharge {
            cells: slots.cells as u64,
            rows: slots.rows as u64,
            models: 1,
        }),
    }
}
#[tokio::test]
async fn resources529_reconstructed_client_cannot_bypass_bound_registration() {
    use crate::session_owner::{
        resource_contract::ReservationReceipt, resources::OwnerResourceClient,
    };
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let x = one
        .reserve(request(s, 1, 40), RequestId::new(1).unwrap())
        .unwrap();
    let registration = h
        .catalog
        .iter()
        .find(|e| e.locator == s)
        .unwrap()
        .resources
        .unwrap();
    let alias = OwnerResourceClient::new(h.resources.clone(), registration);
    assert!(alias
        .reserve(x.reservation(), RequestId::new(2).unwrap())
        .is_err());
    let v = x.reservation();
    assert!(alias
        .release(
            &x,
            ReservationReceipt {
                id: RequestId::new(1).unwrap(),
                reservation: v.id,
                locator: s,
                channel: v.channel
            }
        )
        .is_err());
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    drop(x);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
}
#[tokio::test]
async fn resources529_real_model_keeps_charge_until_final_reference_and_resize_settles() {
    use crate::session_owner::screen_owner::HostScreenLease;
    use transport::shell_server::SessionScreen;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let size = terminal_size::TerminalSize::new(2, 1).unwrap();
    let larger = terminal_size::TerminalSize::new(4, 2).unwrap();
    let token = one
        .reserve(screen_request(s, 1, size), RequestId::new(1).unwrap())
        .unwrap();
    let (_, token) = *HostScreenLease::admit_reserved(one.client(), token, larger)
        .err()
        .unwrap();
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    let lease = HostScreenLease::admit_reserved(one.client(), token, size).unwrap();
    let model = Arc::new(Mutex::new(crate::screen::PtyScreen::with_host_lease(lease)));
    let retained = model.clone();
    {
        let mut m = model.lock().unwrap();
        drop(m.prepare_resize(larger).unwrap());
    }
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    {
        let mut m = model.lock().unwrap();
        m.prepare_resize(larger).unwrap().commit();
        m.absorb(b"real backing").unwrap();
    }
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    drop(model);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    retained.lock().unwrap().absorb(b"still alive").unwrap();
    drop(retained);
    assert_eq!(h.resources.lock().unwrap().reservations(), 0);
}
#[tokio::test]
async fn resources529_concurrent_distinct_owners_and_resize_share_global_ids() {
    use crate::session_owner::screen_owner::HostScreenLease;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let (t, two) = h.create_session_provisioned(a, 3).unwrap();
    let size = terminal_size::TerminalSize::new(2, 1).unwrap();
    let token = one
        .reserve(screen_request(s, 1, size), RequestId::new(1).unwrap())
        .unwrap();
    let first = token.reservation().id.get();
    let mut screen = HostScreenLease::admit_reserved(one.client(), token, size).unwrap();
    let one = Arc::new(one);
    let two = Arc::new(two);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers = [(s, one), (t, two)]
        .into_iter()
        .map(|(s, o)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (2..=16)
                    .map(|n| {
                        o.reserve(request(s, n, 1), RequestId::new(n).unwrap())
                            .unwrap()
                            .reservation()
                            .id
                            .get()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let pending = screen
        .prepare(terminal_size::TerminalSize::new(4, 2).unwrap())
        .unwrap();
    pending.commit();
    let mut ids = std::collections::HashSet::from([first]);
    for worker in workers {
        for id in worker.join().unwrap() {
            assert!(ids.insert(id));
        }
    }
    assert_eq!(ids.len(), 31);
    let next = h
        .resources
        .lock()
        .unwrap()
        .next_reservation_id()
        .unwrap()
        .get();
    assert_eq!(next, 34);
    drop(screen);
    assert_eq!(h.resources.lock().unwrap().reservations(), 30);
}
#[tokio::test]
async fn resources529_poison_blocks_host_client_refunds_and_prepared_commit_without_panic() {
    use crate::session_owner::screen_owner::HostScreenLease;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let size = terminal_size::TerminalSize::new(2, 1).unwrap();
    let token = one
        .reserve(screen_request(s, 1, size), RequestId::new(1).unwrap())
        .unwrap();
    let lease = HostScreenLease::admit_reserved(one.client(), token, size).unwrap();
    use transport::shell_server::SessionScreen;
    let mut model = crate::screen::PtyScreen::with_host_lease(lease);
    let pending = model
        .prepare_resize(terminal_size::TerminalSize::new(4, 2).unwrap())
        .unwrap();
    let ledger = h.resources.clone();
    assert!(std::thread::spawn(move || {
        let _guard = ledger.lock().unwrap();
        panic!("fixture ledger poison");
    })
    .join()
    .is_err());
    pending.commit();
    model
        .absorb(b"actual resized backing survives poison")
        .unwrap();
    drop(model);
    assert!(one
        .reserve(request(s, 2, 1), RequestId::new(2).unwrap())
        .is_err());
    assert!(h.create_session_provisioned(a, 3).is_err());
    // Read-only poison inspection is not a recovery or refund.
    assert_eq!(h.resources.lock().unwrap_err().get_ref().reservations(), 2);
}
#[tokio::test]
async fn resources529_poisoned_prepared_rollback_retains_both_pinned_entries() {
    use crate::session_owner::screen_owner::HostScreenLease;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let size = terminal_size::TerminalSize::new(2, 1).unwrap();
    let token = one
        .reserve(screen_request(s, 1, size), RequestId::new(1).unwrap())
        .unwrap();
    let mut lease = HostScreenLease::admit_reserved(one.client(), token, size).unwrap();
    let pending = lease
        .prepare(terminal_size::TerminalSize::new(4, 2).unwrap())
        .unwrap();
    let ledger = h.resources.clone();
    assert!(std::thread::spawn(move || {
        let _guard = ledger.lock().unwrap();
        panic!("fixture ledger poison");
    })
    .join()
    .is_err());
    drop(pending);
    drop(lease);
    h.sweep(30_002).unwrap();
    assert_eq!(h.catalog_len(), 1);
    assert_eq!(h.resources.lock().unwrap_err().get_ref().reservations(), 2);
}

#[tokio::test]
async fn resources529_id_high_water_exhaustion_cannot_wrap_or_reconstruct() {
    use crate::session_owner::resource_contract::{Reservation, ReservationId};
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let x = one
        .reserve(request(s, 1, 1), RequestId::new(1).unwrap())
        .unwrap();
    let registration = h
        .catalog
        .iter()
        .find(|e| e.locator == s)
        .unwrap()
        .resources
        .unwrap();
    // Trusted pure-ledger setup uses the REAL catalog registration to reach
    // the integer boundary; no peer/client API can propose this identity.
    h.resources
        .lock()
        .unwrap()
        .reserve(
            registration,
            Reservation {
                id: ReservationId::new(u64::MAX).unwrap(),
                ..x.reservation()
            },
            RequestId::new(2).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        one.reserve(request(s, 2, 1), RequestId::new(3).unwrap()),
        Err(crate::session_owner::protocol::OwnerProtocolError::Exhausted)
    ));
    assert_eq!(h.resources.lock().unwrap().reservations(), 2);
}
#[tokio::test]
async fn resources529_preallocation_wrong_kind_returns_exact_token_without_refund() {
    use crate::session_owner::screen_owner::HostScreenLease;
    let (mut h, a, _lease) = authenticated().await;
    let (s, one) = h.create_session_provisioned(a, 2).unwrap();
    let token = one
        .reserve(request(s, 1, 40), RequestId::new(1).unwrap())
        .unwrap();
    let id = token.reservation().id;
    let (_, token) = *HostScreenLease::admit_reserved(
        one.client(),
        token,
        terminal_size::TerminalSize::new(2, 1).unwrap(),
    )
    .err()
    .unwrap();
    assert_eq!(token.reservation().id, id);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    let charge = one.bind_storage(token).unwrap();
    charge.allow_release();
    drop(charge);
    assert_eq!(h.resources.lock().unwrap().reservations(), 0);
}
