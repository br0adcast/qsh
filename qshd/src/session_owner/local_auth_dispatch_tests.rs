use super::*;
use crate::session_owner::authorization::personal_authorization::local_personal_dispatch::PersonalReportSource;
use crate::session_owner::authorization::HostMode;
use crate::session_owner::host::{HostLimits, HostState};
use crate::session_owner::host_auth_contract::{
    AuthMethod, AuthOutcome, AuthReference, HostAuthMessage,
};
use crate::session_owner::host_protocol::{HostDecoder, HostFrame, HostHeader, HostMessage};
use crate::session_owner::local_channel::{
    admit_channel, provision_pair, AdmissionBudget, AdmittedChannel, TrustedChannelConfig,
};
use crate::session_owner::protocol::OwnerRole;
use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport::personal_admission::PersonalAdmissionObserver;
use transport::{
    AuthPolicy, BackendFactory, Connection, ConnectionConfig, LoginEndedReports, Role,
    SessionBackend, SessionIo, SessionManager, Shutdown,
};

fn host(mode: HostMode, attempts: usize) -> HostState {
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
            8,
            attempts,
            attempts,
            8,
            1000,
        )
        .unwrap(),
    )
    .unwrap()
}
fn mode() -> HostMode {
    HostMode::Personal {
        canonical_uid: nix::unistd::geteuid().as_raw(),
    }
}
fn pair(
    h: &HostState,
    mode: HostMode,
    budget: &AdmissionBudget,
) -> (AdmittedChannel, AdmittedChannel) {
    let (a, b) = provision_pair(
        TrustedChannelConfig {
            host: h.instance(),
            owner: None,
            requester: OwnerRole::Frontend,
            mode,
            system_uid: nix::unistd::geteuid().as_raw(),
            min_version: 1,
            max_version: 1,
        },
        budget,
    )
    .unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    let worker = std::thread::spawn(move || admit_channel(a, until));
    let host = admit_channel(b, until).unwrap();
    (worker.join().unwrap().unwrap(), host)
}
struct Peer {
    channel: AdmittedChannel,
    host: transport::session_resume::HostInstance,
    decoder: HostDecoder,
}
impl Peer {
    fn send(&mut self, id: u64, message: HostAuthMessage) {
        let bytes = crate::session_owner::host_protocol::encode(&HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: self.host,
                request_id: id,
            },
            message: HostMessage::Authentication(message),
        })
        .unwrap();
        self.send_bytes(&bytes);
    }
    fn send_bytes(&mut self, bytes: &[u8]) {
        let mut offset = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while offset < bytes.len() {
            assert!(Instant::now() < deadline);
            match self
                .channel
                .frontend_write(self.host, mode(), &bytes[offset..])
            {
                Ok(0) => panic!("peer closed"),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(e) => panic!("{e}"),
            }
        }
    }
    fn receive(
        &mut self,
        dispatch: &mut PersonalAuthDispatch,
        host: &mut HostState,
    ) -> HostAuthMessage {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < deadline, "response deadline");
            dispatch.step(host).unwrap();
            let mut bytes = [0; 1]; // fixture consumes exactly one frame, preserving later replies
            match self.channel.frontend_read(self.host, mode(), &mut bytes) {
                Ok(0) => panic!("unexpected EOF"),
                Ok(n) => {
                    if let Some(frame) = self.decoder.push(&bytes[..n]).unwrap().pop() {
                        let HostMessage::Authentication(message) = frame.message else {
                            panic!("wrong reply")
                        };
                        return message;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(e) => panic!("{e}"),
            }
        }
    }
}
fn setup(
    h: &mut HostState,
    budget: &AdmissionBudget,
    allowlist: transport::SharedAllowlist,
    clock: Arc<AtomicU64>,
) -> (Peer, PersonalAuthDispatch) {
    let (peer, channel) = pair(h, mode(), budget);
    let instance = h.instance();
    let dispatch = PersonalAuthDispatch::new(
        channel,
        h,
        mode(),
        allowlist,
        Arc::new(move || clock.load(Ordering::Acquire)),
        100,
        1000,
    )
    .unwrap();
    (
        Peer {
            channel: peer,
            host: instance,
            decoder: HostDecoder::new(),
        },
        dispatch,
    )
}
fn challenge(
    peer: &mut Peer,
    dispatch: &mut PersonalAuthDispatch,
    host: &mut HostState,
    id: u64,
) -> AuthReference {
    peer.send(
        id,
        HostAuthMessage::Begin {
            method: AuthMethod::Personal,
        },
    );
    let HostAuthMessage::Challenge {
        method: AuthMethod::Personal,
        ticket,
        nonce: None,
        ..
    } = peer.receive(dispatch, host)
    else {
        panic!("expected charged challenge")
    };
    ticket
}
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
        reports: &PersonalReportSource,
        key: &transport::handshake::Keypair,
        token: [u8; 16],
        start_kind: transport::StartKind,
    ) -> HostAuthMessage {
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
            loop {
                if let Some(report) = reports.try_take_report().unwrap() {
                    break report;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }
}

async fn actual_report(
    observer: Arc<dyn PersonalAdmissionObserver>,
    reports: &PersonalReportSource,
    allowlist: transport::SharedAllowlist,
) -> HostAuthMessage {
    let key = transport::generate_keypair();
    allowlist.lock().unwrap().push(key.public);
    // Host policy and frontend transport state are independent. Joining the
    // frontend manager may scrub its own key; that must not mutate host policy.
    let frontend_allowlist = Arc::new(Mutex::new(vec![key.public]));
    let server = PersonalServer::start(observer, frontend_allowlist).await;
    let report = server
        .prove(reports, &key, [53; 16], transport::StartKind::Cold)
        .await;
    assert!(
        matches!(&report,HostAuthMessage::PersonalReport{key:reported,..}if *reported==key.public)
    );
    server.stop.request();
    server.task.await.unwrap().unwrap();
    report
}
#[tokio::test]
async fn authdispatch529_personal_real_noise_and_unix_report_mint_one_live_context() {
    let mut h = host(mode(), 4);
    let budget = AdmissionBudget::new(1).unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock);
    let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
    let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
    assert!(dispatch.take_reporter(ticket).is_err());
    let report = actual_report(observer, &reports, allowlist).await;
    peer.send(3, report);
    let HostAuthMessage::Result {
        ticket: echo,
        outcome: AuthOutcome::Accepted(context),
    } = peer.receive(&mut dispatch, &mut h)
    else {
        panic!("expected actual delegation acceptance")
    };
    assert_eq!(echo, ticket);
    assert_ne!(context, ticket);
    peer.send(4, HostAuthMessage::Cancel { ticket });
    assert_eq!(
        peer.receive(&mut dispatch, &mut h),
        HostAuthMessage::Cancelled { ticket }
    );
    challenge(&mut peer, &mut dispatch, &mut h, 5);
    dispatch.close(&mut h).unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}
#[tokio::test]
async fn authdispatch529_personal_revoked_key_refuses_actual_unix_report() {
    let mut h = host(mode(), 1);
    let budget = AdmissionBudget::new(1).unwrap();
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut peer, mut dispatch) = setup(
        &mut h,
        &budget,
        allowlist.clone(),
        Arc::new(AtomicU64::new(0)),
    );
    let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
    let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
    let report = actual_report(observer, &reports, allowlist.clone()).await;
    allowlist.lock().unwrap().clear();
    peer.send(3, report);
    assert!(matches!(
        peer.receive(&mut dispatch, &mut h),
        HostAuthMessage::Result {
            outcome: AuthOutcome::Refused(_),
            ..
        }
    ));
    challenge(&mut peer, &mut dispatch, &mut h, 4);
    dispatch.close(&mut h).unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}

#[tokio::test]
async fn authdispatch529_personal_changed_account_and_host_revocation_refuse_real_report() {
    for canonical_change in [false, true] {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let (mut peer, mut dispatch) = setup(
            &mut h,
            &budget,
            allowlist.clone(),
            Arc::new(AtomicU64::new(0)),
        );
        if canonical_change {
            // Negative-only resolver injection models a changed canonical NSS mapping;
            // it cannot supply successful identity or bypass the real Noise sender.
            Arc::get_mut(&mut dispatch.adapter.inner).unwrap().resolve = Arc::new(|uid| {
                Some(super::super::CanonicalAccount {
                    uid,
                    name: "changed-canonical-fixture".into(),
                })
            });
        }
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let report = actual_report(observer, &reports, allowlist).await;
        if !canonical_change {
            h.revoke_account(nix::unistd::geteuid().as_raw()).unwrap();
        }
        peer.send(3, report);
        assert!(matches!(
            peer.receive(&mut dispatch, &mut h),
            HostAuthMessage::Result {
                outcome: AuthOutcome::Refused(_),
                ..
            }
        ));
        challenge(&mut peer, &mut dispatch, &mut h, 4);
        dispatch.close(&mut h).unwrap();
        drop(peer);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
#[tokio::test]
async fn authdispatch529_personal_cancel_expiry_and_replay_cannot_apply_late_real_report() {
    for expire in [false, true] {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let clock = Arc::new(AtomicU64::new(0));
        let allowlist = Arc::new(Mutex::new(vec![]));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let report = actual_report(observer, &reports, allowlist.clone()).await;
        if expire {
            clock.store(100, Ordering::Release);
            dispatch.step(&mut h).unwrap();
        } else {
            peer.send(3, HostAuthMessage::Cancel { ticket });
            assert_eq!(
                peer.receive(&mut dispatch, &mut h),
                HostAuthMessage::Cancelled { ticket }
            );
        }
        peer.send(4, report);
        for _ in 0..4 {
            if dispatch.step(&mut h).is_err() {
                break;
            }
        }
        assert!(dispatch.channel.is_none());
        drop(peer);
        assert_eq!(budget.in_use(), 0);
        let (mut fresh, mut next) = setup(&mut h, &budget, allowlist, clock);
        challenge(&mut fresh, &mut next, &mut h, 2);
        next.close(&mut h).unwrap();
        drop(fresh);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
#[tokio::test]
async fn authdispatch529_personal_foreign_ticket_and_stolen_context_close_only_their_seam() {
    use transport::session_resume::{
        AttachRefusal, OwnerInstance, RetainedSessionId, SessionLocator,
    };
    for stolen_context in [false, true] {
        let mut h = host(mode(), 4);
        let budget = AdmissionBudget::new(2).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let clock = Arc::new(AtomicU64::new(0));
        let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let (mut b, mut db) = setup(&mut h, &budget, allowlist.clone(), clock);
        let ta = challenge(&mut a, &mut da, &mut h, 2);
        let (observer, reports) = da.take_reporter(ta).unwrap();
        let report = actual_report(observer, &reports, allowlist).await;
        a.send(3, report.clone());
        let HostAuthMessage::Result {
            outcome: AuthOutcome::Accepted(context),
            ..
        } = a.receive(&mut da, &mut h)
        else {
            panic!("expected proof-backed context")
        };
        challenge(&mut b, &mut db, &mut h, 2);
        let locator = SessionLocator {
            session: RetainedSessionId::new([8; 16]).unwrap(),
            owner: OwnerInstance::new([9; 16]).unwrap(),
        };
        if stolen_context {
            b.send(3, HostAuthMessage::AuthorizeAttach { context, locator });
        } else {
            b.send(3, report);
        }
        for _ in 0..4 {
            if db.step(&mut h).is_err() {
                break;
            }
        }
        assert!(db.channel.is_none());
        a.send(4, HostAuthMessage::AuthorizeAttach { context, locator });
        assert!(matches!(
            a.receive(&mut da, &mut h),
            HostAuthMessage::AttachResult {
                outcome: crate::session_owner::host_auth_contract::AttachOutcome::Refused(
                    AttachRefusal::Unsupported
                ),
                ..
            }
        ));
        a.send(5, HostAuthMessage::Cancel { ticket: ta });
        assert_eq!(
            a.receive(&mut da, &mut h),
            HostAuthMessage::Cancelled { ticket: ta }
        );
        da.close(&mut h).unwrap();
        drop((a, b));
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
#[test]
fn authdispatch529_personal_global_attempt_cap_cancel_and_eof_recover_without_other_seam_damage() {
    let mut h = host(mode(), 2);
    let budget = AdmissionBudget::new(2).unwrap();
    let allowlist = Arc::new(Mutex::new(vec![]));
    let clock = Arc::new(AtomicU64::new(0));
    let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
    let (mut b, mut db) = setup(&mut h, &budget, allowlist, clock);
    let ta = challenge(&mut a, &mut da, &mut h, 2);
    challenge(&mut b, &mut db, &mut h, 2);
    a.send(
        3,
        HostAuthMessage::Begin {
            method: AuthMethod::Personal,
        },
    );
    assert!(matches!(
        a.receive(&mut da, &mut h),
        HostAuthMessage::ChallengeRefused { .. }
    ));
    a.send(4, HostAuthMessage::Cancel { ticket: ta });
    assert_eq!(
        a.receive(&mut da, &mut h),
        HostAuthMessage::Cancelled { ticket: ta }
    );
    challenge(&mut a, &mut da, &mut h, 5);
    drop(a);
    da.step(&mut h).unwrap();
    assert!(da.channel.is_none());
    challenge(&mut b, &mut db, &mut h, 3);
    db.close(&mut h).unwrap();
    drop(b);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}
#[test]
fn authdispatch529_personal_system_constructor_and_wrong_method_never_create_account_authority() {
    let budget = AdmissionBudget::new(1).unwrap();
    let mut system = host(HostMode::System, 1);
    for _ in 0..9 {
        let (peer, channel) = pair(&system, HostMode::System, &budget);
        assert!(PersonalAuthDispatch::new(
            channel,
            &mut system,
            HostMode::System,
            Arc::new(Mutex::new(vec![])),
            Arc::new(|| 0),
            100,
            1000
        )
        .is_err());
        drop(peer);
        assert_eq!(budget.in_use(), 0);
    }
    let (peer, channel) = pair(&system, HostMode::System, &budget);
    channel
        .into_host_dispatch(&mut system, HostMode::System, 1)
        .unwrap()
        .retire(&mut system)
        .unwrap();
    drop(peer);
    let mut h = host(mode(), 1);
    let (mut peer, mut dispatch) = setup(
        &mut h,
        &budget,
        Arc::new(Mutex::new(vec![])),
        Arc::new(AtomicU64::new(0)),
    );
    peer.send(
        2,
        HostAuthMessage::Begin {
            method: AuthMethod::System,
        },
    );
    for _ in 0..4 {
        if dispatch.step(&mut h).is_err() {
            break;
        }
    }
    assert!(dispatch.channel.is_none());
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}

#[tokio::test]
async fn authdispatch529_personal_cancellation_or_deadline_during_policy_read_wins_before_host_apply(
) {
    for expire in [false, true] {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let clock = Arc::new(AtomicU64::new(0));
        let allowlist = Arc::new(Mutex::new(vec![]));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let cancelled: Arc<Mutex<Option<std::sync::Weak<super::super::Slot>>>> =
            Arc::new(Mutex::new(None));
        let target = cancelled.clone();
        let clock_in_read = clock.clone();
        Arc::get_mut(&mut dispatch.adapter.inner).unwrap().resolve = Arc::new(move |uid| {
            if expire {
                clock_in_read.store(100, Ordering::Release);
            } else if let Some(slot) = target.lock().unwrap().as_ref().and_then(|w| w.upgrade()) {
                slot.deactivate();
            }
            super::super::resolve(uid)
        });
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let slot = dispatch.slots[&ticket].lease.slot.clone();
        let attempt = slot.binding.attempt;
        let frontend = slot.binding.frontend;
        *cancelled.lock().unwrap() = Some(Arc::downgrade(&slot));
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let report = actual_report(observer, &reports, allowlist).await;
        peer.send(3, report);
        let result = dispatch.step(&mut h);
        assert!(
            !h.authentication_is_current(attempt, frontend),
            "logical cancellation/expiry must win before actual HostState policy application"
        );
        if expire {
            assert!(result.is_err());
            assert!(dispatch.channel.is_none());
        } else {
            result.unwrap();
            assert!(matches!(
                peer.receive(&mut dispatch, &mut h),
                HostAuthMessage::Result {
                    outcome: AuthOutcome::Refused(_),
                    ..
                }
            ));
        }
        dispatch.close(&mut h).unwrap();
        drop((slot, peer));
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}

#[tokio::test]
async fn authdispatch529_personal_cancellation_during_later_context_policy_read_is_inert() {
    use transport::session_resume::{
        AttachRefusal, OwnerInstance, RetainedSessionId, SessionLocator,
    };
    let mut h = host(mode(), 1);
    let budget = AdmissionBudget::new(1).unwrap();
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut peer, mut dispatch) = setup(
        &mut h,
        &budget,
        allowlist.clone(),
        Arc::new(AtomicU64::new(0)),
    );
    let revoke = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let weak: Arc<Mutex<Option<std::sync::Weak<super::super::Slot>>>> = Arc::new(Mutex::new(None));
    let trigger = revoke.clone();
    let target = weak.clone();
    Arc::get_mut(&mut dispatch.adapter.inner).unwrap().resolve = Arc::new(move |uid| {
        let account = super::super::resolve(uid);
        if trigger.load(Ordering::Acquire) {
            if let Some(slot) = target.lock().unwrap().as_ref().and_then(|w| w.upgrade()) {
                slot.deactivate();
            }
        }
        account
    });
    let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
    let slot = dispatch.slots[&ticket].lease.slot.clone();
    let attempt = slot.binding.attempt;
    let frontend = slot.binding.frontend;
    *weak.lock().unwrap() = Some(Arc::downgrade(&slot));
    let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
    let report = actual_report(observer, &reports, allowlist.clone()).await;
    peer.send(3, report);
    let HostAuthMessage::Result {
        outcome: AuthOutcome::Accepted(context),
        ..
    } = peer.receive(&mut dispatch, &mut h)
    else {
        panic!("actual context")
    };
    revoke.store(true, Ordering::Release);
    let locator = SessionLocator {
        session: RetainedSessionId::new([8; 16]).unwrap(),
        owner: OwnerInstance::new([9; 16]).unwrap(),
    };
    peer.send(4, HostAuthMessage::AuthorizeAttach { context, locator });
    dispatch.step(&mut h).unwrap();
    assert!(
        !h.authentication_is_current(attempt, frontend),
        "cancel during current-policy read must retire exact actual attempt before any later use"
    );
    assert!(matches!(
        peer.receive(&mut dispatch, &mut h),
        HostAuthMessage::AttachResult {
            outcome: crate::session_owner::host_auth_contract::AttachOutcome::Refused(
                AttachRefusal::Unauthorized
            ),
            ..
        }
    ));
    peer.send(5, HostAuthMessage::AuthorizeAttach { context, locator });
    assert!(dispatch.step(&mut h).is_err());
    assert!(dispatch.channel.is_none());
    drop((slot, peer));
    assert_eq!(budget.in_use(), 0);
    let (mut fresh, mut next) = setup(&mut h, &budget, allowlist, Arc::new(AtomicU64::new(0)));
    challenge(&mut fresh, &mut next, &mut h, 2);
    next.close(&mut h).unwrap();
    drop(fresh);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}

fn drain_fixture_occupancy(peer: &mut Peer, mut remaining: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = [0; 4096];
    while remaining > 0 {
        assert!(Instant::now() < deadline);
        let wanted = remaining.min(bytes.len());
        match peer
            .channel
            .frontend_read(peer.host, mode(), &mut bytes[..wanted])
        {
            Ok(0) => panic!("unexpected fixture EOF"),
            Ok(n) => {
                assert!(bytes[..n].iter().all(|b| *b == 0xa5));
                remaining -= n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => panic!("{e}"),
        }
    }
}
#[tokio::test]
async fn authdispatch529_personal_reserved_cancel_and_eof_progress_with_real_output_at_capacity() {
    for eof in [false, true] {
        let mut h = host(mode(), 4);
        let budget = AdmissionBudget::new(2).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let clock = Arc::new(AtomicU64::new(0));
        let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let (mut b, mut db) = setup(&mut h, &budget, allowlist.clone(), clock);
        let ta = challenge(&mut a, &mut da, &mut h, 2);
        let (observer, reports) = da.take_reporter(ta).unwrap();
        let report = actual_report(observer, &reports, allowlist).await;
        a.send(3, report);
        assert!(matches!(
            a.receive(&mut da, &mut h),
            HostAuthMessage::Result {
                outcome: AuthOutcome::Accepted(_),
                ..
            }
        ));
        // Three unrelated pending attempts occupy the remaining GLOBAL host budget.
        // New Begin requests on A produce bounded ordinary refusals, not more leases.
        for id in 2..5 {
            challenge(&mut b, &mut db, &mut h, id);
        }
        let occupied = crate::session_owner::local_channel::tests::fill_dispatch_output(
            da.channel.as_mut().unwrap(),
        );
        assert!(occupied > 0);
        for id in 4..67 {
            a.send(
                id,
                HostAuthMessage::Begin {
                    method: AuthMethod::Personal,
                },
            );
            da.step(&mut h).unwrap();
        }
        assert_eq!(
            da.ordinary_count(),
            63,
            "ordinary responses must leave the 64th lifecycle credit reserved"
        );
        if eof {
            drop(a);
            da.step(&mut h).unwrap();
            assert!(da.channel.is_none());
            challenge(&mut b, &mut db, &mut h, 5);
        } else {
            a.send(67, HostAuthMessage::Cancel { ticket: ta });
            da.step(&mut h).unwrap();
            assert!(!da.slots.contains_key(&ta)); // logical retirement precedes output drain
            assert!(da.lifecycle.is_some());
            drain_fixture_occupancy(&mut a, occupied);
            assert_eq!(
                a.receive(&mut da, &mut h),
                HostAuthMessage::Cancelled { ticket: ta }
            );
            for _ in 0..63 {
                assert!(matches!(
                    a.receive(&mut da, &mut h),
                    HostAuthMessage::ChallengeRefused { .. }
                ));
            }
            challenge(&mut a, &mut da, &mut h, 68);
            da.close(&mut h).unwrap();
            drop(a);
        }
        db.close(&mut h).unwrap();
        drop(b);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
#[tokio::test]
async fn authdispatch529_personal_partial_success_cancel_closes_only_its_seam_and_context_is_inert()
{
    let mut h = host(mode(), 2);
    let budget = AdmissionBudget::new(2).unwrap();
    let allowlist = Arc::new(Mutex::new(vec![]));
    let clock = Arc::new(AtomicU64::new(0));
    let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
    let (mut b, mut db) = setup(&mut h, &budget, allowlist.clone(), clock);
    let tb = challenge(&mut b, &mut db, &mut h, 2);
    let ta = challenge(&mut a, &mut da, &mut h, 2);
    let (observer, reports) = da.take_reporter(ta).unwrap();
    let report = actual_report(observer, &reports, allowlist.clone()).await;
    a.send(3, report);
    da.step(&mut h).unwrap();
    let slot = da.slots[&ta].lease.slot.clone();
    let attempt = slot.binding.attempt;
    let frontend = slot.binding.frontend;
    assert!(da.slots[&ta].context.is_some());
    a.send(4, HostAuthMessage::Cancel { ticket: ta });
    da.step(&mut h).unwrap();
    assert!(
        !h.authentication_is_current(attempt, frontend),
        "Cancel revokes host authority before any output settlement"
    );
    assert!(
        da.writing
            .as_ref()
            .is_some_and(|o| o.offset > 0 && o.offset < o.bytes.len()),
        "actual success frame must already be partial"
    );
    assert!(da.step(&mut h).is_err());
    assert!(da.channel.is_none());
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline);
        let mut bytes = [0; 128];
        match a.channel.frontend_read(a.host, mode(), &mut bytes) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&bytes[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => panic!("{e}"),
        }
    }
    let mut decoder = HostDecoder::new();
    assert!(decoder.push(&received).unwrap().is_empty());
    assert!(
        decoder.finish().is_err(),
        "partial success must end at EOF, with no interleaved Cancelled frame"
    );
    let (observer, reports) = db.take_reporter(tb).unwrap();
    let report = actual_report(observer, &reports, allowlist).await;
    b.send(3, report);
    assert!(matches!(
        b.receive(&mut db, &mut h),
        HostAuthMessage::Result {
            outcome: AuthOutcome::Accepted(_),
            ..
        }
    ));
    challenge(&mut b, &mut db, &mut h, 4);
    db.close(&mut h).unwrap();
    drop((slot, a, b));
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}
#[test]
fn authdispatch529_personal_partial_input_deadline_is_absolute_and_does_not_close_another_seam() {
    let mut h = host(mode(), 2);
    let budget = AdmissionBudget::new(2).unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
    let (mut b, mut db) = setup(&mut h, &budget, allowlist, clock.clone());
    let encoded = crate::session_owner::host_protocol::encode(&HostFrame {
        header: HostHeader {
            role: OwnerRole::Frontend,
            host: a.host,
            request_id: 2,
        },
        message: HostMessage::Authentication(HostAuthMessage::Begin {
            method: AuthMethod::Personal,
        }),
    })
    .unwrap();
    a.send_bytes(&encoded[..4]);
    da.step(&mut h).unwrap();
    clock.store(900, Ordering::Release);
    a.send_bytes(&encoded[4..5]);
    da.step(&mut h).unwrap();
    clock.store(1000, Ordering::Release);
    assert_eq!(da.step(&mut h), Err(DispatchError::Deadline));
    assert!(da.channel.is_none());
    challenge(&mut b, &mut db, &mut h, 2);
    db.close(&mut h).unwrap();
    drop((a, b));
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}
#[tokio::test]
async fn authdispatch529_personal_slow_reader_output_deadline_is_absolute() {
    use transport::session_resume::{OwnerInstance, RetainedSessionId, SessionLocator};
    let mut h = host(mode(), 2);
    let budget = AdmissionBudget::new(2).unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut a, mut da) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
    let (mut b, mut db) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
    let ta = challenge(&mut a, &mut da, &mut h, 2);
    let (observer, reports) = da.take_reporter(ta).unwrap();
    let report = actual_report(observer, &reports, allowlist).await;
    a.send(3, report);
    let HostAuthMessage::Result {
        outcome: AuthOutcome::Accepted(context),
        ..
    } = a.receive(&mut da, &mut h)
    else {
        panic!("actual context")
    };
    crate::session_owner::local_channel::tests::fill_dispatch_output(da.channel.as_mut().unwrap());
    let locator = SessionLocator {
        session: RetainedSessionId::new([8; 16]).unwrap(),
        owner: OwnerInstance::new([9; 16]).unwrap(),
    };
    a.send(4, HostAuthMessage::AuthorizeAttach { context, locator });
    da.step(&mut h).unwrap();
    clock.store(999, Ordering::Release);
    da.step(&mut h).unwrap();
    clock.store(1000, Ordering::Release);
    assert_eq!(da.step(&mut h), Err(DispatchError::Deadline));
    assert!(da.channel.is_none());
    challenge(&mut b, &mut db, &mut h, 2);
    db.close(&mut h).unwrap();
    drop((a, b));
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}

struct ProbationClient {
    socket: tokio::net::UdpSocket,
    connection: Connection,
    msg2: Vec<u8>,
    source: std::net::SocketAddr,
}
impl ProbationClient {
    async fn begin(server: &PersonalServer, key: &transport::handshake::Keypair) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut connection = Connection::new(ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(vec![server.public]),
        });
        let payload = transport::encode_msg1(&transport::Msg1Payload {
            offered: transport::Features::SUPPORTED,
            start_kind: transport::StartKind::Cold,
            token: [72; 16],
            method: transport::AuthMethod::Allowlist,
        });
        for dg in connection.start_with_payload(Instant::now(), server.addr, &payload) {
            socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        let mut bytes = vec![0; 65536];
        let (n, source) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        bytes.truncate(n);
        Self {
            socket,
            connection,
            msg2: bytes,
            source,
        }
    }
    async fn finish(mut self) {
        for dg in self
            .connection
            .on_datagram(Instant::now(), self.source, &self.msg2)
        {
            self.socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        self.connection.request_ping(Instant::now());
        for dg in self.connection.on_timeout(Instant::now()) {
            self.socket.send_to(&dg.bytes, dg.to).await.unwrap();
        }
        // Keep the client socket alive until this call's encrypted datagrams have
        // entered the kernel. The server's actual callback outcome is awaited below.
    }
}
#[tokio::test]
async fn authdispatch529_personal_eof_cancel_and_lost_report_consumer_refuse_late_actual_noise() {
    for action in 0..3 {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let clock = Arc::new(AtomicU64::new(0));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let slot = dispatch.slots[&ticket].lease.slot.clone();
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let mut reports = Some(reports);
        let key = transport::generate_keypair();
        allowlist.lock().unwrap().push(key.public);
        let frontend = Arc::new(Mutex::new(vec![key.public]));
        let server = PersonalServer::start(observer, frontend).await;
        let probation = ProbationClient::begin(&server, &key).await;
        assert_eq!(
            slot.delivery.load(Ordering::Acquire),
            0,
            "real msg2 must precede possession completion"
        );
        assert!(!server.task.is_finished());
        let mut peer = Some(peer);
        match action {
            0 => {
                drop(peer.take());
                dispatch.step(&mut h).unwrap();
            }
            1 => {
                drop(reports.take());
            }
            _ => {
                let peer = peer.as_mut().unwrap();
                peer.send(3, HostAuthMessage::Cancel { ticket });
                assert_eq!(
                    peer.receive(&mut dispatch, &mut h),
                    HostAuthMessage::Cancelled { ticket }
                );
            }
        }
        probation.finish().await;
        let outcome = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let value = slot.delivery.load(Ordering::Acquire);
                if value != 0 {
                    break value;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        // Logical capacity recovery is not physical cleanup: request and await the
        // existing manager's actual joined drain before asserting fixture completion.
        server.stop.request();
        server.task.await.unwrap().unwrap();
        assert_eq!(
            outcome.unwrap(),
            2,
            "actual observer must refuse completion after its channel/callback sink was lost"
        );
        assert!(!slot.active.load(Ordering::Acquire));
        dispatch.step(&mut h).unwrap();
        dispatch.close(&mut h).unwrap();
        drop((reports, slot, peer));
        assert_eq!(budget.in_use(), 0);
        let (mut fresh, mut next) = setup(&mut h, &budget, allowlist, clock);
        challenge(&mut fresh, &mut next, &mut h, 2);
        next.close(&mut h).unwrap();
        drop(fresh);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
#[tokio::test]
async fn authdispatch529_personal_forged_wire_key_and_duplicate_real_report_refuse() {
    for forged_key in [false, true] {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let clock = Arc::new(AtomicU64::new(0));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let mut report = actual_report(observer, &reports, allowlist.clone()).await;
        if forged_key {
            let HostAuthMessage::PersonalReport { key, .. } = &mut report else {
                unreachable!()
            };
            *key = [0; 32];
        }
        peer.send(3, report.clone());
        let result = peer.receive(&mut dispatch, &mut h);
        if forged_key {
            assert!(matches!(
                result,
                HostAuthMessage::Result {
                    outcome: AuthOutcome::Refused(_),
                    ..
                }
            ));
            dispatch.close(&mut h).unwrap();
        } else {
            assert!(matches!(
                result,
                HostAuthMessage::Result {
                    outcome: AuthOutcome::Accepted(_),
                    ..
                }
            ));
            peer.send(4, report);
            assert!(dispatch.step(&mut h).is_err());
            assert!(dispatch.channel.is_none());
        }
        drop(peer);
        assert_eq!(budget.in_use(), 0);
        let (mut fresh, mut next) = setup(&mut h, &budget, allowlist, clock);
        challenge(&mut fresh, &mut next, &mut h, 2);
        next.close(&mut h).unwrap();
        drop(fresh);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}

#[test]
fn authdispatch529_personal_unknown_method_wrong_host_role_magic_and_oversize_fail_before_authority(
) {
    for case in 0..5 {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let allowlist = Arc::new(Mutex::new(vec![]));
        let clock = Arc::new(AtomicU64::new(0));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let mut frame = crate::session_owner::host_protocol::encode(&HostFrame {
            header: HostHeader {
                role: OwnerRole::Frontend,
                host: peer.host,
                request_id: 2,
            },
            message: HostMessage::Authentication(HostAuthMessage::Begin {
                method: AuthMethod::Personal,
            }),
        })
        .unwrap();
        match case {
            0 => frame[36] = 99,
            1 => frame[12..28].copy_from_slice(&[0xee; 16]),
            2 => frame[6] = OwnerRole::Host.to_wire(),
            3 => frame[..4].copy_from_slice(b"QSHO"),
            _ => frame[8..12].copy_from_slice(&u32::MAX.to_be_bytes()),
        }
        peer.send_bytes(&frame);
        assert!(dispatch.step(&mut h).is_err());
        assert!(dispatch.channel.is_none());
        drop(peer);
        assert_eq!(budget.in_use(), 0);
        let (mut fresh, mut next) = setup(&mut h, &budget, allowlist, clock);
        challenge(&mut fresh, &mut next, &mut h, 2);
        next.close(&mut h).unwrap();
        drop(fresh);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
struct ObservedActualObserver {
    inner: Arc<dyn PersonalAdmissionObserver>,
    entered: Arc<std::sync::atomic::AtomicBool>,
}
impl PersonalAdmissionObserver for ObservedActualObserver {
    fn try_begin(
        &self,
        binding: transport::personal_admission::PersonalBinding,
    ) -> Result<
        Box<dyn transport::personal_admission::PersonalAdmissionAttempt>,
        transport::personal_admission::Refused,
    > {
        let outcome = self.inner.try_begin(binding);
        // Fixture synchronization only: delegate the real result unchanged; never
        // construct an attempt, completion or successful authority observation.
        self.entered.store(true, Ordering::Release);
        outcome
    }
}
#[tokio::test]
async fn authdispatch529_personal_twin_observer_cannot_claim_another_preassociated_ticket() {
    let mut h = host(mode(), 2);
    let budget = AdmissionBudget::new(1).unwrap();
    let allowlist = Arc::new(Mutex::new(vec![]));
    let (mut peer, mut dispatch) = setup(
        &mut h,
        &budget,
        allowlist.clone(),
        Arc::new(AtomicU64::new(0)),
    );
    let a = challenge(&mut peer, &mut dispatch, &mut h, 2);
    let b = challenge(&mut peer, &mut dispatch, &mut h, 3);
    let (observer_a, reports_a) = dispatch.take_reporter(a).unwrap();
    let (observer_b, reports_b) = dispatch.take_reporter(b).unwrap();
    let report_a = actual_report(observer_a.clone(), &reports_a, allowlist.clone()).await;
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = Arc::new(ObservedActualObserver {
        inner: observer_a,
        entered: entered.clone(),
    });
    let twin_key = transport::generate_keypair();
    let server = PersonalServer::start(observed, Arc::new(Mutex::new(vec![twin_key.public]))).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut connection = Connection::new(ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::SUPPORTED,
        role: Role::Client,
        local_static_priv: twin_key.private,
        remote_static_pub: Some(server.public),
        auth: AuthPolicy::Allowlist(vec![server.public]),
    });
    let payload = transport::encode_msg1(&transport::Msg1Payload {
        offered: transport::Features::SUPPORTED,
        start_kind: transport::StartKind::Cold,
        token: [53; 16],
        method: transport::AuthMethod::Allowlist,
    });
    for dg in connection.start_with_payload(Instant::now(), server.addr, &payload) {
        socket.send_to(&dg.bytes, dg.to).await.unwrap();
    }
    let synchronized = tokio::time::timeout(Duration::from_secs(2), async {
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let no_msg2 = tokio::time::timeout(
        Duration::from_millis(200),
        socket.recv_from(&mut [0; 65536]),
    )
    .await
    .is_err();
    server.stop.request();
    server.task.await.unwrap().unwrap();
    synchronized.unwrap();
    assert!(
        no_msg2,
        "consumed exact observer must refuse before probation msg2; never steal B's reservation"
    );
    assert!(reports_a.try_take_report().unwrap().is_none());
    assert!(reports_b.try_take_report().unwrap().is_none());
    peer.send(4, report_a);
    assert!(matches!(
        peer.receive(&mut dispatch, &mut h),
        HostAuthMessage::Result {
            outcome: AuthOutcome::Accepted(_),
            ..
        }
    ));
    let report_b = actual_report(observer_b, &reports_b, allowlist).await;
    peer.send(5, report_b);
    assert!(matches!(
        peer.receive(&mut dispatch, &mut h),
        HostAuthMessage::Result {
            outcome: AuthOutcome::Accepted(_),
            ..
        }
    ));
    dispatch.close(&mut h).unwrap();
    drop(peer);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(h.catalog_len(), 0);
}

#[tokio::test]
async fn authdispatch529_personal_queued_success_deadline_crossed_during_policy_read_emits_no_bytes(
) {
    for crossed in [100, 1000] {
        let mut h = host(mode(), 1);
        let budget = AdmissionBudget::new(1).unwrap();
        let clock = Arc::new(AtomicU64::new(0));
        let allowlist = Arc::new(Mutex::new(vec![]));
        let (mut peer, mut dispatch) = setup(&mut h, &budget, allowlist.clone(), clock.clone());
        let trigger = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trigger_in_read = trigger.clone();
        let clock_in_read = clock.clone();
        Arc::get_mut(&mut dispatch.adapter.inner).unwrap().resolve = Arc::new(move |uid| {
            let account = super::super::resolve(uid);
            if trigger_in_read.load(Ordering::Acquire) {
                clock_in_read.store(crossed, Ordering::Release);
            }
            account
        });
        let ticket = challenge(&mut peer, &mut dispatch, &mut h, 2);
        let attempt = dispatch.slots[&ticket].lease.slot.binding.attempt;
        let frontend = dispatch.slots[&ticket].lease.slot.binding.frontend;
        let (observer, reports) = dispatch.take_reporter(ticket).unwrap();
        let report = actual_report(observer, &reports, allowlist).await;
        peer.send(3, report);
        dispatch.step(&mut h).unwrap(); // Queues success without writing its bytes.
        assert!(h.authentication_is_current(attempt, frontend));
        trigger.store(true, Ordering::Release);
        assert_eq!(dispatch.step(&mut h), Err(DispatchError::Deadline));
        assert!(!h.authentication_is_current(attempt, frontend));
        assert!(dispatch.channel.is_none());
        let mut byte = [0; 1];
        assert_eq!(
            peer.channel
                .frontend_read(peer.host, mode(), &mut byte)
                .unwrap(),
            0
        );
        drop(peer);
        assert_eq!(budget.in_use(), 0);
        assert_eq!(h.catalog_len(), 0);
    }
}
