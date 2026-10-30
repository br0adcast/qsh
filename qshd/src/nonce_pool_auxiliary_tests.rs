#[test]
fn auxiliary40_pool_drop_waits_for_actual_refill_thread() {
    let (status, stdout, stderr) = crate::helper::spawner::tests::run_isolated(
        "nonce_pool::tests::auxiliary40_pool_drop_waits_for_actual_refill_thread_body",
    );
    assert!(
        status.success(),
        "owned pool join control failed ({status}):\n{stdout}\n{stderr}"
    );
}

static AUXILIARY40_POOL_GATE: std::sync::OnceLock<Mutex<Option<std::sync::mpsc::Receiver<()>>>> =
    std::sync::OnceLock::new();
static AUXILIARY40_POOL_ENTERED: std::sync::OnceLock<std::sync::mpsc::Sender<()>> =
    std::sync::OnceLock::new();
fn auxiliary40_held_pool_spawn(
    body: Box<dyn FnOnce() + Send>,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
    let gate = AUXILIARY40_POOL_GATE
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .take()
        .unwrap();
    std::thread::Builder::new()
        .name(AUTH_POOL_THREAD.into())
        .spawn(move || {
            AUXILIARY40_POOL_ENTERED.get().unwrap().send(()).unwrap();
            gate.recv().unwrap();
            body();
            Ok(())
        })
}

#[test]
#[ignore = "runs only in the owned pool-join subprocess"]
fn auxiliary40_pool_drop_waits_for_actual_refill_thread_body() {
    use std::sync::mpsc;
    let (worker, helper) = channel::pair().unwrap();
    let stub = std::thread::spawn(move || {
        let mut issued = 0;
        let mut released = 0;
        while let Some((bytes, _)) = channel::recv(&helper).unwrap() {
            let request: AuthRequest = decode(&bytes).unwrap();
            match request.body {
                Request::Nonce => {
                    issued += 1;
                    channel::send(
                        &helper,
                        &encode(&AuthResponse {
                            id: request.id,
                            body: Response::Nonce {
                                nonce: nonce_number(issued),
                            },
                        })
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                }
                Request::ReleaseNonce { .. } => released += 1,
                _ => panic!("unexpected controlled pool request"),
            }
        }
        (issued, released)
    });
    let (release, held) = mpsc::channel();
    let (entered, entry) = mpsc::channel();
    AUXILIARY40_POOL_GATE.set(Mutex::new(Some(held))).unwrap();
    AUXILIARY40_POOL_ENTERED.set(entered).unwrap();
    let pool = PooledNonces::with_spawn(client(worker), auxiliary40_held_pool_spawn).unwrap();
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    let (done, completion) = mpsc::channel();
    let dropping = std::thread::spawn(move || {
        drop(pool);
        done.send(()).unwrap();
    });
    let early = completion.recv_timeout(Duration::from_millis(100)).is_ok();
    release.send(()).unwrap();
    dropping.join().unwrap();
    let (issued, released) = stub.join().unwrap();
    assert_eq!(issued, POOL_TARGET);
    assert_eq!(
        released, issued,
        "final nonce returns precede auth shutdown"
    );
    assert!(
        !early,
        "pool Drop returned before its real refill thread joined"
    );
}

#[test]
fn panic_request_cannot_cross_the_checked_before_wait_boundary() {
    use std::sync::mpsc;
    let (worker, _stub) = helper_stub_answering_nonces_at_once();
    let (death, ended) = mpsc::channel();
    let end_worker: EndWorker = Arc::new(move |why| {
        let _ = death.send(why.to_owned());
    });
    let pool = PooledNonces::with_end_worker(client(worker), end_worker).expect("pool");
    wait_until_warm(&pool, POOL_TARGET, TEST_WAIT);
    let (checked, at_boundary) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    {
        let mut state = pool.shared.lock();
        state.before_wait = Some((checked, paused));
        pool.shared.wake.notify_one();
    }
    at_boundary
        .recv_timeout(TEST_WAIT)
        .expect("actual worker reached check-before-wait boundary");
    let (finished, completion) = mpsc::channel();
    let request_pool = Arc::clone(&pool);
    let requester = std::thread::spawn(move || {
        request_pool.panic_thread_for_test();
        finished.send(()).expect("panic request observer");
    });
    // The worker still owns the predicate mutex. A completed request here has
    // notified before the worker can atomically enter its condition wait.
    let crossed = completion.recv_timeout(Duration::from_millis(100)).is_ok();
    resume.send(()).expect("release actual worker to wait");
    if !crossed {
        completion
            .recv_timeout(TEST_WAIT)
            .expect("panic request completed after wait release");
    }
    requester.join().expect("panic requester joined");
    let actual = ended.recv_timeout(TEST_WAIT);
    // Release the real pool/thread/helper before either assertion can fail.
    drop(pool);
    eprintln!("SEEN panic boundary: notified_before_wait={crossed}, death={actual:?}");
    assert!(
        !crossed,
        "panic request notified across the checked-before-wait gap"
    );
    assert_eq!(
        actual,
        Ok(POOL_THREAD_GONE_REASON.to_owned()),
        "actual pool panic must report worker death"
    );
}
