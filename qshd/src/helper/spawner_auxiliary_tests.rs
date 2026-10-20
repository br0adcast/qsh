#[test]
fn auxiliary40_channel_drop_waits_for_actual_reader() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_channel_drop_waits_for_actual_reader_body",
    );
    assert!(
        status.success(),
        "owned reader join control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "runs only in the owned reader-join subprocess"]
fn auxiliary40_channel_drop_waits_for_actual_reader_body() {
    let (worker, helper) = channel::pair().unwrap();
    let (entered, entry) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let spawner = HelperChannelSpawner::with_login_ended_sink(
        worker,
        Box::new(move |_, _| {
            entered.send(()).unwrap();
            held.recv().unwrap();
        }),
    )
    .unwrap();
    channel::send(
        &helper,
        &encode(&Response::LoginEnded {
            login: [40; 16],
            incarnation: 1,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let (began, started) = mpsc::channel();
    let (done, completion) = mpsc::channel();
    let dropping = std::thread::spawn(move || {
        began.send(()).unwrap();
        drop(spawner);
        done.send(()).unwrap();
    });
    started.recv().unwrap();
    // This is a negative observation while a real reader callback is held,
    // not a timeout used as cleanup proof. Release and actual outer joins
    // precede every assertion. The subprocess bounds legacy detached cleanup.
    let early = completion.recv_timeout(Duration::from_millis(100)).is_ok();
    release.send(()).unwrap();
    dropping.join().unwrap();
    drop(helper);
    assert!(
        !early,
        "client drop returned before its actual reader joined"
    );
}

#[test]
fn auxiliary40_failed_auth_reader_spawn_joins_started_releaser() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_failed_auth_reader_spawn_joins_started_releaser_body",
    );
    assert!(
        status.success(),
        "owned partial-construction control failed ({status}):\n{stdout}\n{stderr}"
    );
}

// These test-only gates are initialized once inside their owned subprocess.
// No daemon-global status collector or parent test state is changed.
static AUXILIARY40_SPAWN_GATE: std::sync::OnceLock<Mutex<Option<mpsc::Receiver<()>>>> =
    std::sync::OnceLock::new();
static AUXILIARY40_SPAWN_STARTED: std::sync::OnceLock<mpsc::Sender<()>> =
    std::sync::OnceLock::new();

fn auxiliary40_fail_second_auth_spawn(
    name: &str,
    body: Box<dyn FnOnce() -> io::Result<()> + Send>,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
    if name == AUTH_READER_THREAD {
        return Err(io::Error::other("controlled second auth spawn failure"));
    }
    let gate = AUXILIARY40_SPAWN_GATE
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .take()
        .unwrap();
    spawn_auxiliary(
        name,
        Box::new(move || {
            AUXILIARY40_SPAWN_STARTED.get().unwrap().send(()).unwrap();
            gate.recv().unwrap();
            body()
        }),
    )
}

#[test]
#[ignore = "runs only in the owned partial-construction subprocess"]
fn auxiliary40_failed_auth_reader_spawn_joins_started_releaser_body() {
    let (worker, helper) = channel::pair().unwrap();
    let (release, held) = mpsc::channel();
    let (entered, entry) = mpsc::channel();
    AUXILIARY40_SPAWN_GATE.set(Mutex::new(Some(held))).unwrap();
    AUXILIARY40_SPAWN_STARTED.set(entered).unwrap();
    let (done, completion) = mpsc::channel();
    let constructor = std::thread::spawn(move || {
        let result = HelperAuth::build_with_spawn(
            worker,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Box::new(|| {}),
            ignore_the_end(),
            channel::recv,
            send_request,
            auxiliary40_fail_second_auth_spawn,
        );
        done.send(result.is_err()).unwrap();
    });
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let early = completion.recv_timeout(Duration::from_millis(100)).ok();
    release.send(()).unwrap();
    constructor.join().unwrap();
    let failed = early.unwrap_or_else(|| completion.recv().unwrap());
    drop(helper);
    assert!(failed, "preserve original spawn failure");
    assert!(
        early.is_none(),
        "construction returned before started releaser joined"
    );
}

#[test]
fn auxiliary40_auth_reader_finishes_late_nonce_before_write_shutdown() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_auth_reader_finishes_late_nonce_before_write_shutdown_body",
    );
    assert!(
        status.success(),
        "owned late-nonce teardown control failed ({status}):\n{stdout}\n{stderr}"
    );
}

static AUXILIARY40_RECV_GATE: std::sync::OnceLock<Mutex<Option<mpsc::Receiver<()>>>> =
    std::sync::OnceLock::new();
static AUXILIARY40_RECV_ENTERED: std::sync::OnceLock<mpsc::Sender<()>> = std::sync::OnceLock::new();
fn auxiliary40_held_auth_receive(
    sock: &UnixStream,
) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
    let message = channel::recv(sock)?;
    if message.is_some() {
        let gate = AUXILIARY40_RECV_GATE.get().unwrap().lock().unwrap().take();
        if let Some(gate) = gate {
            AUXILIARY40_RECV_ENTERED.get().unwrap().send(()).unwrap();
            gate.recv().unwrap();
        }
    }
    Ok(message)
}

#[test]
#[ignore = "runs only in the owned late-nonce teardown subprocess"]
fn auxiliary40_auth_reader_finishes_late_nonce_before_write_shutdown_body() {
    let (worker, helper) = channel::pair().unwrap();
    helper
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (release, held) = mpsc::channel();
    let (entered, entry) = mpsc::channel();
    AUXILIARY40_RECV_GATE.set(Mutex::new(Some(held))).unwrap();
    AUXILIARY40_RECV_ENTERED.set(entered).unwrap();
    let stub = std::thread::spawn(move || {
        let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
        let request: AuthRequest = decode(&bytes).unwrap();
        assert!(matches!(request.body, Request::Nonce));
        channel::send(
            &helper,
            &encode(&AuthResponse {
                id: request.id,
                body: Response::Nonce {
                    nonce: [61; transport::auth::AUTH_NONCE_LEN],
                },
            })
            .unwrap(),
            None,
        )
        .unwrap();
        match channel::recv(&helper).unwrap() {
            Some((bytes, _)) => {
                matches!(decode::<AuthRequest>(&bytes).unwrap().body, Request::ReleaseNonce { nonce } if nonce == [61; transport::auth::AUTH_NONCE_LEN])
            }
            None => false,
        }
    });
    let auth = HelperAuth::with_reader(
        worker,
        Duration::from_millis(30),
        Duration::from_millis(30),
        || {},
        auxiliary40_held_auth_receive,
    )
    .unwrap();
    let refused = auth.issue().is_err();
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let (done, completion) = mpsc::channel();
    let dropping = std::thread::spawn(move || {
        drop(auth);
        done.send(()).unwrap();
    });
    let early = completion.recv_timeout(Duration::from_millis(100)).is_ok();
    release.send(()).unwrap();
    dropping.join().unwrap();
    let released = stub.join().unwrap();
    assert!(
        refused,
        "controlled request expired while its actual reply was held"
    );
    assert!(
        !early,
        "auth client returned before its reader and releaser joined"
    );
    assert!(
        released,
        "late nonce release must precede writable-half shutdown"
    );
}

#[test]
fn auxiliary40_sealed_required_tell_latches_retained_failure_after_joins() {
    let (worker, helper) = channel::pair().unwrap();
    let mut auth = HelperAuth::with_timeout(worker, Duration::from_millis(100)).unwrap();
    let mut owner = auth.take_auxiliary();
    let joined = owner.stop_and_join();
    assert_eq!(joined.joined, 0b1100);
    assert_eq!(joined.failed, 0);
    auth.login_ended([40; 16]);
    let fault = owner.stop_and_join();
    assert_ne!(
        fault.failed & (1 << ThreadRole::TellReleaser as usize),
        0,
        "a required late producer must remain failed despite physical thread joins"
    );
    assert!(
        auth.seam.lock_tells().queue.is_empty(),
        "sealed queue cannot grow"
    );
    drop(auth);
    drop(helper);
}

fn auxiliary40_panicking_auth_receive(
    _: &UnixStream,
) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
    panic!("controlled actual auth reader panic");
}

#[test]
fn auxiliary40_actual_reader_panic_still_joins_releaser() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_actual_reader_panic_still_joins_releaser_body",
    );
    assert!(
        status.success(),
        "owned reader panic control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "runs only in the owned reader-panic subprocess"]
fn auxiliary40_actual_reader_panic_still_joins_releaser_body() {
    let (worker, helper) = channel::pair().unwrap();
    let (ended, end) = mpsc::channel();
    let mut auth = HelperAuth::with_reader(
        worker,
        Duration::from_millis(100),
        Duration::from_millis(100),
        move || {
            let _ = ended.send(());
        },
        auxiliary40_panicking_auth_receive,
    )
    .unwrap();
    end.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut owner = auth.take_auxiliary();
    let outcome = owner.stop_and_join();
    drop(auth);
    drop(helper);
    assert_eq!(outcome.joined, 0b1100);
    assert_eq!(outcome.panicked, 1 << ThreadRole::AuthReader as usize);
}

#[test]
fn auxiliary40_fixed_worker_owner_joins_roles_while_client_aliases_survive() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_fixed_worker_owner_joins_roles_while_client_aliases_survive_body",
    );
    assert!(
        status.success(),
        "owned four-role composition control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "runs only in the owned four-role composition subprocess"]
fn auxiliary40_fixed_worker_owner_joins_roles_while_client_aliases_survive_body() {
    let (channel_worker, channel_helper) = channel::pair().unwrap();
    let mut spawner = HelperChannelSpawner::new(channel_worker).unwrap();
    let local_close = spawner.disconnected_locally.clone();
    let (auth_worker, auth_helper) = channel::pair().unwrap();
    let stub = std::thread::spawn(move || {
        let mut issued = 0;
        let mut released = 0;
        while let Some((bytes, _)) = channel::recv(&auth_helper).unwrap() {
            let request: AuthRequest = decode(&bytes).unwrap();
            match request.body {
                Request::Nonce => {
                    issued += 1;
                    let mut nonce = [0; transport::AUTH_NONCE_LEN];
                    nonce[0] = issued as u8;
                    channel::send(
                        &auth_helper,
                        &encode(&AuthResponse {
                            id: request.id,
                            body: Response::Nonce { nonce },
                        })
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                }
                Request::ReleaseNonce { .. } => released += 1,
                _ => panic!("unexpected composed-worker auth request"),
            }
        }
        (issued, released)
    });
    let mut auth = HelperAuth::with_timeout(auth_worker, Duration::from_millis(100)).unwrap();
    let mut owner = WorkerThreads::default();
    owner.absorb(spawner.take_auxiliary());
    owner.absorb(auth.take_auxiliary());
    let auth = Arc::new(auth);
    let pool = crate::nonce_pool::PooledNonces::start_owned(auth.clone(), &mut owner).unwrap();
    drop(spawner);
    let early_close = local_close.load(Ordering::SeqCst);
    // This is physical auxiliary joining only. A retained client alias is not
    // proof of manager-producer settlement; exercise its late fault below.
    let joined = owner.stop_and_join();
    let no_new_nonce = transport::session_manager::NonceSource::issue(&*pool).is_err();
    auth.login_ended([40; 16]);
    let late = owner.stop_and_join();
    drop(pool);
    drop(auth);
    drop(channel_helper);
    let (issued, released) = stub.join().unwrap();
    assert!(
        !early_close,
        "client Drop cannot override transferred worker custody"
    );
    assert!(local_close.load(Ordering::SeqCst));
    assert_eq!(joined.started, 0b1111);
    assert_eq!(joined.joined, 0b1111);
    assert_eq!(joined.failed | joined.panicked, 0);
    assert_eq!(issued, crate::nonce_pool::POOL_TARGET);
    assert_eq!(released, issued);
    assert!(
        no_new_nonce,
        "retained pool aliases cannot issue after stop"
    );
    assert_ne!(late.failed & (1 << ThreadRole::TellReleaser as usize), 0);
}

#[test]
fn auxiliary40_returning_overflow_hook_cannot_enqueue_after_final_seal() {
    let (status, stdout, stderr) = run_isolated(
        "helper::spawner::tests::auxiliary40_returning_overflow_hook_cannot_enqueue_after_final_seal_body",
    );
    assert!(
        status.success(),
        "owned returning-hook seal control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "runs only in the owned returning-overflow-hook subprocess"]
fn auxiliary40_returning_overflow_hook_cannot_enqueue_after_final_seal_body() {
    let (worker, helper) = channel::pair().unwrap();
    let stub = std::thread::spawn(move || {
        let mut delivered = 0;
        while let Some((bytes, _)) = channel::recv(&helper).unwrap() {
            let request: AuthRequest = decode(&bytes).unwrap();
            assert!(matches!(request.body, Request::LoginEnded { .. }));
            delivered += 1;
        }
        delivered
    });
    let (entered, entry) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let held = Mutex::new(held);
    let mut auth = HelperAuth::with_end_worker(
        worker,
        Duration::from_secs(1),
        send_request,
        Arc::new(move |_| {
            entered.send(()).unwrap();
            held.lock().unwrap().recv().unwrap();
        }),
    )
    .unwrap();
    let mut owner = auth.take_auxiliary();
    let auth = Arc::new(auth);
    // Queue without waking the releaser, so the next real LoginSink producer
    // enters the supported overflow hook after releasing the tells mutex.
    for _ in 0..MAX_QUEUED_LOGIN_ENDS {
        auth.seam
            .queue_tell(Request::LoginEnded { login: [40; 16] });
    }
    let producer = {
        let auth = auth.clone();
        std::thread::spawn(move || auth.login_ended([41; 16]))
    };
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let joined = owner.stop_and_join(); // actual reader/releaser joins and final flush
    let sealed = auth.seam.lock_tells().sealed;
    release.send(()).unwrap();
    producer.join().unwrap();
    let queued = auth.seam.lock_tells().queue.len();
    let after = owner.stop_and_join();
    drop(auth);
    let delivered = stub.join().unwrap();
    assert_eq!(joined.joined, 0b1100);
    assert_eq!(joined.failed | joined.panicked, 0);
    assert!(sealed);
    assert_eq!(
        delivered, MAX_QUEUED_LOGIN_ENDS,
        "all pre-seal required tells reached the peer"
    );
    assert_eq!(
        queued, 0,
        "returning hook cannot append to the final sealed queue"
    );
    assert_ne!(
        after.failed & (1 << ThreadRole::TellReleaser as usize),
        0,
        "late required producer remains a retained owner failure after joins"
    );
}
