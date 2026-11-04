//! Source-bound compatibility fixtures. The six connected tests exist only in
//! the explicit Darwin fixture build; host controls never count as native runs.
pub(super) fn route_images(bytes: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut images = Vec::new();
    for line in text
        .lines()
        .filter(|line| line.starts_with("keeper223 route="))
    {
        let fields: Vec<_> = line.split(' ').collect();
        if fields.len() != 6
            || fields[0] != "keeper223"
            || fields[1] != "route=keeper"
            || fields[2] != "source=compiled-missing"
        {
            return None;
        }
        let image = fields[3].strip_prefix("image=")?;
        if image.len() != 64
            || !image
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let pid = fields[4].strip_prefix("pid=")?.parse::<u32>().ok()?;
        let stream = fields[5].strip_prefix("stream=")?.parse::<u8>().ok()?;
        if pid == 0 || stream < transport::channel::FIRST_CHANNEL_STREAM {
            return None;
        }
        images.push(image.to_owned());
    }
    Some(images)
}
#[test]
fn keeper_fixture_route_receipts_require_the_bound_image_and_compiled_route() {
    let hash = "a".repeat(64);
    let line =
        format!("keeper223 route=keeper source=compiled-missing image={hash} pid=71 stream=16\n");
    assert_eq!(route_images(line.as_bytes()), Some(vec![hash]));
    for invalid in [
        line.replace("image=", "image=wrong"),
        line.replace("route=keeper", "route=modern"),
        line.replace("compiled-missing", "environment-override"),
        line.replace("pid=71", "pid=0"),
        line.replace("stream=16", "stream=0"),
    ] {
        assert_eq!(route_images(invalid.as_bytes()), None);
    }
    assert_eq!(route_images(b"running 0 tests\n"), Some(vec![]));
}

fn delivered_eof(read_eof: bool, reader_drop: bool, retiring_poll_running: bool) -> bool {
    read_eof && reader_drop && retiring_poll_running
}

#[test]
fn keeper_fixture_eof_proof_requires_delivery_and_retiring_poll() {
    assert!(delivered_eof(true, true, true));
    // A real read paused before returning is not a delivered EOF.
    assert!(!delivered_eof(true, false, false));
    // Drop/queued None without the actual installed retiring poll is insufficient.
    assert!(!delivered_eof(true, true, false));
    // Active poll_leader_status/progress must not fabricate this marker.
    assert!(!delivered_eof(false, true, true));
}

#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
pub(super) mod native {
    use super::super::native_tests::{ConnectedBinder, ConnectedEvents};
    use super::super::{keeper_pty::KeeperFixture, native::NativeOps, Class, Ops};
    use std::{
        path::{Path, PathBuf},
        sync::{atomic::Ordering, Arc, Mutex},
        time::{Duration, Instant},
    };
    use transport::{
        channel::{
            encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, CONTROL_STREAM,
            FIRST_CHANNEL_STREAM,
        },
        channel_open::{
            ChannelOpenExecutor, ChannelOpenRegistry, CleanupStatus, OpenIdentity, OpenOutcome,
            OpenRequestSnapshot,
        },
        channel_server::ChannelSpawner,
        driver_std::StdClient,
    };
    pub(super) static SERIAL: Mutex<()> = Mutex::new(());
    pub(in crate::darwin_process_scope) fn fixture() -> KeeperFixture {
        use sha2::{Digest, Sha256};
        let path = PathBuf::from(
            std::env::var_os("QSH_DARWIN223_DAEMON")
                .expect("required Cargo JSON compatibility artifact"),
        );
        let hash = std::env::var("QSH_DARWIN223_DAEMON_SHA256")
            .expect("required exact Cargo artifact digest");
        assert!(path.is_absolute() && path.is_file());
        assert_eq!(
            hex::encode(Sha256::digest(std::fs::read(&path).unwrap())),
            hash
        );
        KeeperFixture::new(path, hash)
    }
    pub(in crate::darwin_process_scope) fn backend() -> (
        Arc<crate::channel_backend::ChannelSessionBackend>,
        KeeperFixture,
    ) {
        let fixture = fixture();
        let budget = Arc::new(crate::screen_budget::ScreenBudget::new(Default::default()));
        let spawner = Arc::new(
            crate::channel_backend::PtyChannelSpawner::new(budget)
                .with_keeper_fixture(fixture.clone()),
        );
        (
            Arc::new(crate::channel_backend::ChannelSessionBackend::with_spawner(
                spawner,
            )),
            fixture,
        )
    }
    pub(in crate::darwin_process_scope) fn assert_routes(bytes: &[u8], expected: usize) {
        let fixture = fixture();
        let images = super::route_images(bytes).expect("strict compiled keeper route receipt");
        assert_eq!(
            images.len(),
            expected,
            "every actual channel must select the fixture keeper"
        );
        assert!(images.iter().all(|image| *image == fixture.sha256));
        eprintln!(
            "keeper223 route_verified count={expected} image={} source=compiled-missing",
            fixture.sha256
        );
    }
    fn owner() -> transport::auth::Principal {
        transport::auth::Principal {
            uid: unsafe { nix::libc::geteuid() },
            name: "keeper-integrated".into(),
            identity: "keeper-integrated".into(),
            incarnation: 0,
        }
    }
    pub(super) struct Env(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Env {
        fn set(values: &[(&'static str, &std::ffi::OsStr)]) -> Self {
            let mut saved = Vec::new();
            for (key, value) in values {
                saved.push((*key, std::env::var_os(key)));
                std::env::set_var(key, value);
            }
            Self(saved)
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..).rev() {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }
    async fn until(mut check: impl FnMut() -> bool, end: Instant) {
        while !check() {
            assert!(Instant::now() < end, "original integrated fixture deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    fn exclusive(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    fn quoted(path: &Path) -> String {
        let s = path.to_str().unwrap();
        assert!(!s.contains('\''));
        format!("'{s}'")
    }
    struct Connected {
        client: Arc<StdClient>,
        events: Arc<ConnectedEvents>,
        registry: Arc<ChannelOpenRegistry>,
        fixture: KeeperFixture,
        budget: Arc<crate::screen_budget::ScreenBudget>,
        shutdown: transport::Shutdown,
        manager: tokio::task::JoinHandle<Result<(), String>>,
        end: Instant,
    }
    impl Connected {
        async fn new(fixture: KeeperFixture, end: Instant) -> Self {
            use transport::session_manager::{LoginEndedReports, ServerAuth};
            let server = transport::handshake::generate_keypair();
            let key = transport::handshake::generate_keypair();
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = udp.local_addr().unwrap();
            let budget = Arc::new(crate::screen_budget::ScreenBudget::new(Default::default()));
            let spawner = Arc::new(
                crate::channel_backend::PtyChannelSpawner::new(budget.clone())
                    .with_keeper_fixture(fixture.clone()),
            );
            let registry = spawner.open_registry();
            let backend = Arc::new(crate::channel_backend::ChannelSessionBackend::with_spawner(
                spawner,
            ));
            let auth = ServerAuth {
                allowlist: Arc::new(Mutex::new(vec![key.public])),
                verifier: None,
                server_pub: server.public,
                self_principal: owner(),
                nonces: Arc::new(crate::RandomNonces),
                logins: Arc::new(crate::ForgetNothing),
            };
            let shutdown = transport::Shutdown::default();
            let request = shutdown.clone();
            let manager = tokio::spawn(async move {
                crate::transport_daemon::run_serve_loop_until_shutdown(
                    udp,
                    server.private,
                    auth,
                    backend,
                    LoginEndedReports::none(),
                    request,
                )
                .await
                .map_err(|e| format!("{e:?}"))
            });
            let events = Arc::new(ConnectedEvents::default());
            let client = Arc::new(StdClient::connect(
                address,
                transport::ConnectionConfig {
                    required_features: transport::Features::CHANNEL_GEOMETRY
                        | transport::Features::AUTH_ACCEPTED,
                    features: transport::Features::SUPPORTED,
                    role: transport::Role::Client,
                    local_static_priv: key.private,
                    remote_static_pub: Some(server.public),
                    auth: transport::AuthPolicy::Allowlist(Vec::new()),
                },
                [1; 16],
                transport::StartKind::Cold,
                Arc::new(ConnectedBinder),
                events.clone(),
                None,
            ));
            let connected = Self {
                client,
                events,
                registry,
                fixture,
                budget,
                shutdown,
                manager,
                end,
            };
            while !connected.events.live.load(Ordering::SeqCst) {
                if Instant::now() >= end {
                    connected.finish(false).await;
                    panic!("connection deadline");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            connected
        }
        fn open(
            &self,
            kind: ChannelKind,
            command: Vec<u8>,
            screen: bool,
        ) -> Result<(), &'static str> {
            self.client
                .send_bytes(
                    CONTROL_STREAM,
                    encode_client(&ClientRecord::Term("xterm-keeper-fixture".into())),
                )
                .map_err(|_| "TERM enqueue")?;
            self.client
                .send_bytes(
                    CONTROL_STREAM,
                    encode_client(&ClientRecord::Open(OpenRequest {
                        stream: FIRST_CHANNEL_STREAM,
                        kind,
                        cols: 80,
                        rows: 24,
                        screen,
                        command,
                    })),
                )
                .map_err(|_| "OPEN enqueue")
        }
        async fn finish(mut self, body_ok: bool) {
            for i in 0..self.fixture.count() {
                let observation = self.fixture.observation(i).unwrap();
                observation.io.release_reader();
                if let Some(gate) = observation.gate {
                    gate.release();
                }
            }
            self.client.close();
            self.shutdown.request();
            let joined = tokio::time::timeout(
                self.end
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(30)),
                &mut self.manager,
            )
            .await;
            let normal = joined.is_ok();
            let result = match joined {
                Ok(v) => v,
                Err(_) => {
                    // Failure-only fixture cleanup; never a product-completion pass.
                    for i in 0..self.fixture.count() {
                        self.fixture
                            .observation(i)
                            .unwrap()
                            .authority
                            .rescue(Instant::now() + Duration::from_secs(10));
                    }
                    self.manager.await
                }
            };
            result.unwrap().unwrap();
            assert!(
                normal && body_ok,
                "fixture settled only after failure cleanup"
            );
            self.fixture.assert_settled(self.fixture.count());
            assert_eq!(self.registry.outstanding(), 0);
            assert_eq!(self.registry.retiring_count(), 0);
            assert_eq!(self.budget.used(), crate::screen_budget::Usage::default());
            eprintln!("keeper223 connected_join=normal registry=0 screen_credits=0 two_io_joins=terminal_certificate rescue=false");
        }
    }
    fn monotonic() -> u128 {
        let mut t: nix::libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut t) },
            0
        );
        t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
    }
    fn directory() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::Builder::new()
            .prefix("qsh-keeper-integrated-")
            .tempdir()
            .unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn nonce() -> String {
        use rand_core::RngCore;
        let mut b = [0; 16];
        rand_core::OsRng.fill_bytes(&mut b);
        hex::encode(b)
    }
    fn read_gate(path: &Path) -> Option<Vec<u8>> {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        let m = f.metadata().ok()?;
        if !m.is_file()
            || m.uid() != unsafe { nix::libc::geteuid() }
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || m.len() > 128
        {
            return None;
        }
        let mut b = Vec::new();
        f.take(129).read_to_end(&mut b).ok()?;
        Some(b)
    }
    struct Release {
        path: PathBuf,
        nonce: String,
    }
    impl Release {
        fn release(&self) {
            for name in ["release", "app-exit"] {
                if !self.path.join(name).exists() {
                    exclusive(&self.path.join(name), self.nonce.as_bytes());
                }
            }
        }
    }
    impl Drop for Release {
        fn drop(&mut self) {
            self.release();
        }
    }
    fn actor_command(mode: &str, path: &Path, nonce: &str, raw: u128, echo: bool) -> Vec<u8> {
        format!("/usr/bin/env QSH_KEEPER_TEST_MODE={mode} QSH_KEEPER_TEST_DIR={} QSH_KEEPER_TEST_NONCE={nonce} QSH_KEEPER_TEST_END={raw} QSH_KEEPER_TEST_ECHO={} {} --exact darwin_process_scope::keeper_integration_tests::keeper_owned_actor --nocapture",quoted(path),u8::from(echo),quoted(&std::env::current_exe().unwrap())).into_bytes()
    }
    pub(super) fn terminal() {
        let _serial = SERIAL.lock().unwrap();
        let end = Instant::now() + Duration::from_secs(60);
        let raw = monotonic() + 60_000_000_000;
        let _shell = Env::set(&[("SHELL", std::ffi::OsStr::new("/bin/sh"))]);
        runtime().block_on(async {
            for kind in [ChannelKind::Shell,ChannelKind::Command] {for screen in [false,true] {
                let d=directory();let nonce=nonce();let release=Release{path:d.path().to_path_buf(),nonce:nonce.clone()};
                let mut fixture=fixture();fixture.eof_deadline=Some(end);let c=Connected::new(fixture,end).await;
                let client=c.client.clone();let events=c.events.clone();let registry=c.registry.clone();let budget=c.budget.clone();let f=c.fixture.clone();let path=d.path().to_path_buf();
                let command=actor_command("terminal",&path,&nonce,raw,kind==ChannelKind::Shell);
                if c.open(kind,if kind==ChannelKind::Shell {vec![]}else{command.clone()},screen).is_err(){c.finish(false).await;panic!("OPEN enqueue failed");}
                let result=tokio::spawn(async move {
                    until(||events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Opened{stream} if *stream==FIRST_CHANNEL_STREAM)),end).await;
                    if kind==ChannelKind::Shell {let mut bytes=b"exec ".to_vec();bytes.extend_from_slice(&command);bytes.push(b'\n');client.send_bytes(FIRST_CHANNEL_STREAM,bytes).unwrap();}
                    until(||events.output.lock().unwrap().windows(b"KEEPER_READY".len()).any(|w|w==b"KEEPER_READY"),end).await;
                    if screen {assert_ne!(budget.used(),crate::screen_budget::Usage::default());}else{assert_eq!(budget.used(),crate::screen_budget::Usage::default());}
                    let instance=loop {let found=events.records.lock().unwrap().iter().find_map(|r|match r {ServerRecord::ChannelSnapshot(s)=>s.active().first().map(|a|a.instance),_=>None});if let Some(id)=found{break id;}assert!(Instant::now()<end);tokio::task::yield_now().await;};
                    client.send_bytes(CONTROL_STREAM,encode_client(&ClientRecord::ResizeRequest{stream:FIRST_CHANNEL_STREAM,instance,request_id:transport::channel_geometry::ResizeRequestId::new(1).unwrap(),cols:91,rows:31})).unwrap();
                    until(||events.geometries.lock().unwrap().iter().any(|g|g.instance==instance&&g.request_id==1&&g.outcome==transport::channel_geometry::GeometryOutcome::Applied&&g.cols==91&&g.rows==31),end).await;
                    client.send_bytes(FIRST_CHANNEL_STREAM,b"keeper-input-proof\n".to_vec()).unwrap();
                    until(||read_gate(&path.join("stdio-closed")).as_deref()==Some(nonce.as_bytes()),end).await;
                    let observation=f.observation(0).expect("actual factory child ran");
                    until(||super::delivered_eof(observation.io.eof.load(Ordering::SeqCst),observation.io.reader_drop.load(Ordering::SeqCst),observation.io.retiring_running.load(Ordering::SeqCst)),end).await;
                    assert!(Instant::now()<end&&!observation.io.reader_drop_finished.load(Ordering::SeqCst));
                    let snapshot=observation.authority.snapshot().unwrap();let app=snapshot.app.expect("real admitted A");assert!(matches!(NativeOps.classify(app).unwrap().class,Class::Session(_)));
                    assert!(snapshot.app_status.is_none()&&snapshot.session_wait.is_none());
                    assert!(registry.retiring_count()>0&&registry.try_cleanup_snapshot().unwrap().unique_cleanup_debt>0);
                    assert!(!events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Exit{stream,..}|ServerRecord::ExitStatusUnavailable{stream} if *stream==FIRST_CHANNEL_STREAM)));
                    // Screen memory follows Channel lifetime at consumed EOF;
                    // the OPEN/process slot follows the exact reaper/worker joins.
                    until(||budget.used()==crate::screen_budget::Usage::default(),end).await;
                    client.send_bytes(CONTROL_STREAM,encode_client(&ClientRecord::Open(OpenRequest{stream:FIRST_CHANNEL_STREAM+1,kind:ChannelKind::Command,cols:80,rows:24,screen:false,command:b"/usr/bin/true".to_vec()}))).unwrap();
                    until(||events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Exit{stream,code:0} if *stream==FIRST_CHANNEL_STREAM+1)),end).await;
                    assert_eq!(f.count(),2);assert!(observation.authority.snapshot().unwrap().app_status.is_none());
                    let output=events.output.lock().unwrap().clone();let echoed=output.windows(b"keeper-input-proof".len()).any(|w|w==b"keeper-input-proof");assert_eq!(echoed,kind==ChannelKind::Shell);
                    assert!(output.windows(b"KEEPER_RESIZED".len()).any(|w|w==b"KEEPER_RESIZED"));
                    exclusive(&path.join("release"),nonce.as_bytes());
                    until(||observation.authority.snapshot().is_some_and(|s|s.app_status==Some(37)&&s.session_wait==Some(0)&&s.drained&&s.broker_terminal&&s.census&&s.consumed),end).await;
                    assert!(registry.retiring_count()>0);
                    assert!(!events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Exit{stream,..}|ServerRecord::ExitStatusUnavailable{stream} if *stream==FIRST_CHANNEL_STREAM)));
                    assert!(Instant::now()<end&&!observation.io.reader_drop_finished.load(Ordering::SeqCst));
                    let fence=registry.begin_restart_fence().unwrap();assert!(fence.wait_until(Instant::now()).is_none(),"reader has not joined");
                    observation.io.release_reader();
                    until(||events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Exit{stream,code:37} if *stream==FIRST_CHANNEL_STREAM)),end).await;
                    until(||registry.outstanding()==0&&registry.retiring_count()==0,end).await;
                    assert!(fence.wait_until(Instant::now()).is_some());fence.reopen();f.assert_settled(2);
                }).await;
                release.release();c.finish(result.is_ok()).await;result.unwrap();
                eprintln!("keeper223 terminal kind={kind:?} screen={screen} real_eof_delivered_alive=true actual_retiring_poll=Running screen_lifetime=EOF process_slot=after_IO_joins terminal=37 session=0 rescue=false");
            }}
        });
    }
    pub(super) fn cancel_setup() {
        let _serial = SERIAL.lock().unwrap();
        let end = Instant::now() + Duration::from_secs(60);
        runtime().block_on(async {
            for mode in 0..4 {
                let mut fixture=fixture();if mode<2{fixture.pause_after_admit=Some(mode==1);}else{fixture.reader_failure=Some(mode==2);}
                let budget=Arc::new(crate::screen_budget::ScreenBudget::new(Default::default()));
                let spawner=Arc::new(crate::channel_backend::PtyChannelSpawner::new(budget.clone()).with_keeper_fixture(fixture.clone()));
                let registry=spawner.open_registry();let executor=ChannelOpenExecutor::new(spawner,registry.clone());let session=registry.session().unwrap();
                let d=directory();let marker=d.path().join("app-started");let script=d.path().join("application");exclusive(&script,format!("echo started > {}\nexec /bin/sleep 45\n",quoted(&marker)).as_bytes());
                let req=OpenRequest{stream:FIRST_CHANNEL_STREAM,kind:ChannelKind::Command,cols:80,rows:24,screen:true,command:format!("/bin/sh {}",quoted(&script)).into_bytes()};
                let job=Arc::new(registry.try_reserve(&session,OpenRequestSnapshot{owner:owner(),login:[0;16],request:req,term:Some("xterm-keeper-fixture".into()),identity:OpenIdentity{session:session.id(),instance:transport::channel_geometry::ChannelInstance::new(1).unwrap(),stream:FIRST_CHANNEL_STREAM,generation:0,invalidation_epoch:0}}).unwrap());
                executor.submit(&job).unwrap();let mut worker=job.take_worker().expect("actual owned OPEN worker");
                let body_job=job.clone();let body_fixture=fixture.clone();let body_registry=registry.clone();
                let result=tokio::spawn(async move {
                    until(||body_fixture.observation(0).is_some(),end).await;
                    let observation=body_fixture.observation(0).unwrap();
                    let fence=if mode<2 {
                        let gate=observation.gate.as_ref().unwrap();until(||gate.reached(),end).await;
                        if mode==1 {assert_eq!(observation.authority.snapshot().unwrap().decision,super::super::keeper::AdmissionDecision::Admit);}
                        body_job.cancel();let fence=body_registry.begin_restart_fence().unwrap();assert!(fence.wait_until(Instant::now()).is_none());gate.release();Some(fence)
                    }else{None};
                    let mut outcome=None;until(||{outcome=body_job.take_outcome();outcome.is_some()},end).await;
                    assert!(matches!(outcome,Some(OpenOutcome::Failed(_))));
                    until(||matches!(body_job.cleanup(),CleanupStatus::Confirmed(_)),end).await;
                    body_fixture.assert_settled(1);let proof=observation.authority.snapshot().unwrap();
                    if mode==0 {assert!(proof.not_started&&proof.app.is_none()&&proof.app_status.is_none());assert!(!marker.exists());}
                    else {assert!(!proof.not_started&&proof.app.is_some()&&proof.app_status.is_some());}
                    if let Some(fence)=fence {assert!(fence.wait_until(Instant::now()).is_some());fence.reopen();}
                }).await;
                // Always release scheduling gates before waiting the actual worker,
                // including an assertion-unwind path. Failed rescue never counts.
                job.cancel();for index in 0..fixture.count(){let observation=fixture.observation(index).unwrap();observation.io.release_reader();if let Some(gate)=observation.gate{gate.release();}}
                let joined=tokio::time::timeout(end.saturating_duration_since(Instant::now()),&mut worker).await;
                let normal=joined.is_ok();match joined {Ok(value)=>value.unwrap(),Err(_)=>{for index in 0..fixture.count(){fixture.observation(index).unwrap().authority.rescue(Instant::now()+Duration::from_secs(10));}worker.await.unwrap();}}
                assert!(normal,"OPEN worker settled only after failure rescue");result.unwrap();
                assert_eq!(registry.outstanding(),0);assert_eq!(registry.retiring_count(),0);assert_eq!(session.occupied(),0);assert_eq!(budget.used(),crate::screen_budget::Usage::default());
                eprintln!("keeper223 open_executor mode={mode} child=true registry=0 workers=joined rescue=false");
            }
        });
    }
    pub(super) fn foreign_sid() {
        let _serial = SERIAL.lock().unwrap();
        let end = Instant::now() + Duration::from_secs(60);
        let raw = monotonic() + 60_000_000_000;
        let d = directory();
        let nonce = nonce();
        let release = Release {
            path: d.path().to_path_buf(),
            nonce: nonce.clone(),
        };
        exclusive(&d.path().join("instance"), nonce.as_bytes());
        let _env = Env::set(&[("QSH_KEEPER_TEST_DEBT_DIRECTORY", d.path().as_os_str())]);
        runtime().block_on(async {
            let c=Connected::new(fixture(),end).await;
            if c.open(ChannelKind::Command,actor_command("foreign-parent",d.path(),&nonce,raw,false),true).is_err(){c.finish(false).await;panic!("OPEN enqueue failed");}
            let path=d.path().to_path_buf();let client=c.client.clone();let events=c.events.clone();let registry=c.registry.clone();let budget=c.budget.clone();let fixture=c.fixture.clone();
            let result=tokio::spawn(async move {
                until(||events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Opened{stream} if *stream==FIRST_CHANNEL_STREAM)),end).await;
                until(||match(read_gate(&path.join("escaped")),read_gate(&path.join("target")),read_gate(&path.join("ledger-recorded")),read_gate(&path.join("foreign-observed"))){
                    (Some(escaped),Some(target),Some(stored),Some(foreign))=>escaped==target&&stored==foreign&&super::super::keeper_helper::fixture_debt_request(&nonce,&stored).is_some(),_=>false
                },end).await;
                let target=read_gate(&path.join("target")).unwrap();let stored=read_gate(&path.join("ledger-recorded")).unwrap();assert_eq!(read_gate(&path.join("foreign-observed")).unwrap(),stored);
                let actual=super::super::keeper_helper::fixture_debt_request(&nonce,&target).unwrap();let recorded=super::super::keeper_helper::fixture_debt_request(&nonce,&stored).unwrap();assert!(recorded.same_process(actual));
                eprintln!("keeper223 debt stored_version={} current_version={} binding=pid_unique",recorded.version,actual.version);
                let text=std::str::from_utf8(&target).unwrap();let fields:Vec<_>=text.split_whitespace().collect();assert_eq!(fields[0],nonce);let pid:i32=fields[1].parse().unwrap();
                let observed=NativeOps.classify(pid).unwrap();assert_eq!(observed.identity,actual);let Class::Session(foreign)=observed.class else {panic!("escaped child must remain alive")};assert_eq!(foreign,pid);
                let observation=fixture.observation(0).unwrap();let original=observation.authority.snapshot().unwrap();assert_ne!(original.sid,foreign);
                exclusive(&path.join("app-exit"),nonce.as_bytes());until(||observation.authority.snapshot().is_some_and(|s|s.app_status==Some(37)),end).await;
                client.send_bytes(CONTROL_STREAM,encode_client(&ClientRecord::Close{stream:FIRST_CHANNEL_STREAM})).unwrap();until(||registry.retiring_count()>0,end).await;
                let fence=registry.begin_restart_fence().unwrap();assert!(fence.wait_until(Instant::now()).is_none());
                let snapshot=registry.try_cleanup_snapshot().unwrap();assert!(snapshot.unique_cleanup_debt>0 && snapshot.cleanup_unconfirmed);
                until(||budget.used()==crate::screen_budget::Usage::default(),end).await;
                assert!(!events.records.lock().unwrap().iter().any(|r|matches!(r,ServerRecord::Exit{..}|ServerRecord::ExitStatusUnavailable{..})));
                let debt=observation.authority.snapshot().unwrap();assert!(!debt.drained&&!debt.consumed&&debt.session_wait.is_none());
                assert_eq!(NativeOps.classify(pid).unwrap().identity,observed.identity);assert!(!path.join("foreign-signaled").exists());
                exclusive(&path.join("release"),nonce.as_bytes());until(||registry.retiring_count()==0&&registry.outstanding()==0,end).await;
                fixture.assert_settled(1);assert!(fence.wait_until(Instant::now()).is_some());fence.reopen();assert!(!path.join("foreign-signaled").exists());
                eprintln!("keeper223 foreign_sid ledger_before_setsid=true pending_interval=true refund=false replacement_refused=true foreign_signal=false voluntary_exit=true rescue=false");
            }).await;
            release.release();c.finish(result.is_ok()).await;result.unwrap();
        });
    }
    static FOREIGN_SIGNAL: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    extern "C" fn foreign_signal(_: i32) {
        FOREIGN_SIGNAL.store(true, Ordering::SeqCst);
    }
    pub(super) fn actor() {
        use std::io::{Read, Write};
        let Ok(mode) = std::env::var("QSH_KEEPER_TEST_MODE") else {
            return;
        };
        let path = PathBuf::from(std::env::var_os("QSH_KEEPER_TEST_DIR").unwrap());
        let nonce = std::env::var("QSH_KEEPER_TEST_NONCE").unwrap();
        let end: u128 = std::env::var("QSH_KEEPER_TEST_END")
            .unwrap()
            .parse()
            .unwrap();
        let wait = |name: &str| {
            while read_gate(&path.join(name)).as_deref() != Some(nonce.as_bytes()) {
                assert!(monotonic() < end, "original actor deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        if mode == "terminal" {
            assert_eq!(unsafe { nix::libc::isatty(0) }, 1);
            assert_eq!(unsafe { nix::libc::tcgetpgrp(0) }, unsafe {
                nix::libc::getpgrp()
            });
            assert_eq!(std::env::var("TERM").unwrap(), "xterm-keeper-fixture");
            let mut settings: nix::libc::termios = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { nix::libc::tcgetattr(0, &mut settings) }, 0);
            assert_eq!(
                settings.c_lflag & nix::libc::ECHO != 0,
                std::env::var("QSH_KEEPER_TEST_ECHO").unwrap() == "1"
            );
            let mut size: nix::libc::winsize = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { nix::libc::ioctl(0, nix::libc::TIOCGWINSZ, &mut size) },
                0
            );
            assert_eq!((size.ws_col, size.ws_row), (80, 24));
            println!("KEEPER_READY");
            std::io::stdout().flush().unwrap();
            let flags = unsafe { nix::libc::fcntl(0, nix::libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { nix::libc::fcntl(0, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) },
                0
            );
            let mut input = Vec::new();
            while !input.ends_with(b"\n") {
                assert!(monotonic() < end);
                let mut b = [0; 64];
                match std::io::stdin().read(&mut b) {
                    Ok(n) if n > 0 => input.extend_from_slice(&b[..n]),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    other => panic!("terminal input {other:?}"),
                };
                assert!(input.len() < 128);
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(input, b"keeper-input-proof\n");
            assert_eq!(
                unsafe { nix::libc::ioctl(0, nix::libc::TIOCGWINSZ, &mut size) },
                0
            );
            assert_eq!((size.ws_col, size.ws_row), (91, 31));
            println!("KEEPER_RESIZED");
            std::io::stdout().flush().unwrap();
            for fd in [0, 1, 2] {
                assert_eq!(unsafe { nix::libc::close(fd) }, 0);
            }
            exclusive(&path.join("stdio-closed"), nonce.as_bytes());
            wait("release");
            unsafe { nix::libc::_exit(37) };
        } else if mode == "foreign-parent" {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "darwin_process_scope::keeper_integration_tests::keeper_owned_actor",
                    "--nocapture",
                ])
                .env("QSH_KEEPER_TEST_MODE", "foreign-child")
                .spawn()
                .unwrap();
            while read_gate(&path.join("escaped")).is_none() {
                assert!(monotonic() < end);
                assert!(child.try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(5));
            }
            wait("app-exit");
            unsafe { nix::libc::_exit(37) };
        } else {
            assert_eq!(mode, "foreign-child");
            let identity = NativeOps.identity(std::process::id() as i32).unwrap();
            let record = format!(
                "{nonce} {} {} {}\n",
                identity.pid, identity.unique, identity.version
            );
            exclusive(&path.join("target"), record.as_bytes());
            loop {
                if let Some(bytes) = read_gate(&path.join("ledger-recorded")) {
                    if let Some(stored) =
                        super::super::keeper_helper::fixture_debt_request(&nonce, &bytes)
                    {
                        assert!(stored.same_process(identity));
                        break;
                    }
                }
                assert!(monotonic() < end);
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(unsafe { nix::libc::setsid() }, identity.pid);
            unsafe {
                nix::libc::signal(nix::libc::SIGHUP, foreign_signal as *const () as usize);
            }
            for fd in [0, 1, 2] {
                assert_eq!(unsafe { nix::libc::close(fd) }, 0);
            }
            exclusive(&path.join("escaped"), record.as_bytes());
            while read_gate(&path.join("release")).as_deref() != Some(nonce.as_bytes()) {
                assert!(monotonic() < end);
                if FOREIGN_SIGNAL.load(Ordering::SeqCst) && !path.join("foreign-signaled").exists()
                {
                    exclusive(&path.join("foreign-signaled"), nonce.as_bytes());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if FOREIGN_SIGNAL.load(Ordering::SeqCst) && !path.join("foreign-signaled").exists() {
                exclusive(&path.join("foreign-signaled"), nonce.as_bytes());
            }
            unsafe { nix::libc::_exit(0) };
        }
    }
}

#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_owned_actor() {
    native::actor();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_terminal_status_and_io() {
    native::terminal();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_open_cancel_and_setup_failure() {
    native::cancel_setup();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_close_stop_rebind_and_fresh_session() {
    let _serial = native::SERIAL.lock().unwrap();
    super::native_tests::keeper_connected_suite();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_term_interrupt_join() {
    let _serial = native::SERIAL.lock().unwrap();
    super::native_tests::keeper_signal_suite();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_actual_daemon_replacement() {
    let _serial = native::SERIAL.lock().unwrap();
    super::native_tests::keeper_replacement_suite();
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
#[test]
fn keeper_integrated_foreign_sid_retains_debt() {
    native::foreign_sid();
}
