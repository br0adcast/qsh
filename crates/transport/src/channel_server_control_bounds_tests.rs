// The provider is held independently of the async runner. Runtime destruction
// joins every blocking callback, including callbacks detached by the old source.
struct HeldAbout {
    inner: Arc<FakeDaemon>,
    entered: AtomicUsize,
    completed: AtomicUsize,
    changed: tokio::sync::Notify,
    released: (Mutex<bool>, std::sync::Condvar),
}

impl HeldAbout {
    fn release(&self) {
        *self.released.0.lock().unwrap() = true;
        self.released.1.notify_all();
    }
}

struct ReleaseAbout(Arc<HeldAbout>);

impl Drop for ReleaseAbout {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl DaemonUpdates for HeldAbout {
    fn about(&self) -> Option<About> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_one();
        let mut released = self.released.0.lock().unwrap();
        while !*released {
            released = self.released.1.wait(released).unwrap();
        }
        self.completed.fetch_add(1, Ordering::SeqCst);
        Some(fake_about())
    }

    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        self.inner.offer(from, offer)
    }

    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.inner.restart_signal()
    }

    fn restart_joined(&self, restart: u64) -> bool {
        self.inner.restart_joined(restart)
    }

    fn channels_released(&self, restart: u64) {
        self.inner.channels_released(restart);
    }
}

#[test]
fn about_burst_shares_one_held_provider_call() {
    const REQUESTS: usize = 8;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(REQUESTS)
        .build()
        .unwrap();
    let provider = Arc::new(HeldAbout {
        inner: FakeDaemon::new(),
        entered: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        changed: tokio::sync::Notify::new(),
        released: (Mutex::new(false), std::sync::Condvar::new()),
    });
    runtime.block_on(async {
        // This guard releases workers before runtime destruction on every exit,
        // including a failed fence or runner assertion.
        let release = ReleaseAbout(Arc::clone(&provider));
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            Some(Arc::clone(&provider) as Arc<dyn DaemonUpdates>),
        ));
        let request = encode_client(&ClientRecord::AboutRequest);
        let burst = request.repeat(REQUESTS);
        let bytes = burst.len();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: burst,
            }))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if matches!(outbound.recv().await,
                    Some(SessionOutbound::Consumed { stream_id: CONTROL_STREAM, n })
                    if n == bytes)
                {
                    break;
                }
            }
        })
        .await
        .expect("runner consumed the entire real control burst");
        // Correct code need only enter once. The consumed fence establishes
        // that the old source registered all eight jobs before cleanup.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let changed = provider.changed.notified();
                if provider.entered.load(Ordering::SeqCst) > 0 {
                    break;
                }
                changed.await;
            }
        })
        .await
        .expect("at least one real provider call enters");
        drop(release);
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("released runner terminates")
            .unwrap();
    });
    // Tokio's owned runtime waits for all blocking workers before returning.
    // Keep the final RED assertion after this join, never ahead of cleanup.
    drop(runtime);
    assert_eq!(
        provider.completed.load(Ordering::SeqCst),
        provider.entered.load(Ordering::SeqCst),
        "every entered callback returned before the runtime joined"
    );
    assert_eq!(
        provider.entered.load(Ordering::SeqCst),
        1,
        "one session should share its held About computation"
    );
}

struct ResetAdmissionHooks;
impl Drop for ResetAdmissionHooks {
    fn drop(&mut self) {
        CONTROL_REFUND_BEFORE_SELECT.with(|hook| drop(hook.borrow_mut().take()));
        CONTROL_FIRST_ACK_TICK.with(|slot| drop(slot.borrow_mut().take()));
    }
}

#[tokio::test(start_paused = true)]
async fn capacity_about_refund_between_admission_check_and_select_remains_ready() {
    let _reset = ResetAdmissionHooks;
    CONTROL_CAPACITY_WAKES.with(|count| count.set(0));
    let (io, inbound, mut outbound) = channel_pair();
    let held = io
        .control_budget()
        .reserve(crate::control_budget::Response::Ordinary(
            crate::control_budget::MAX_RECORD,
        ))
        .unwrap();
    let refunded = Arc::new(AtomicBool::new(false));
    let observed = refunded.clone();
    CONTROL_REFUND_BEFORE_SELECT.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            // Release real pre-existing response custody in the precise race
            // window. The hook changes no production admission decision.
            drop(held);
            observed.store(true, Ordering::SeqCst);
        }));
    });
    let first_tick = Arc::new(tokio::sync::Notify::new());
    CONTROL_FIRST_ACK_TICK.with(|slot| *slot.borrow_mut() = Some(first_tick.clone()));
    let runner = tokio::spawn(run_channel_session_with(
        io,
        FakeSpawner::new(),
        with_daemon(&FakeDaemon::new()),
    ));
    // Positively observe the real initial tick before submitting the request.
    // The paused clock then has no unrelated ready timer in the race window.
    tokio::time::timeout(std::time::Duration::from_secs(5), first_tick.notified())
        .await
        .unwrap();
    let request = encode_client(&ClientRecord::AboutRequest);
    let bytes = request.len();
    inbound
        .send(SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: request,
        }))
        .await
        .unwrap();
    let admitted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if matches!(outbound.recv().await.expect("runner alive until admission"), SessionOutbound::Consumed { stream_id: CONTROL_STREAM, n } if n == bytes) {
                break;
            }
        }
    }).await;
    let capacity_wakes = CONTROL_CAPACITY_WAKES.with(|count| count.get());
    drop(inbound);
    // No callback is held; the fixture driver joins its real worker before
    // returning. Assert only after that cleanup, including the RED outcome.
    runner.await.unwrap();
    assert!(admitted.is_ok(), "real pending record eventually admits");
    assert!(
        refunded.load(Ordering::SeqCst),
        "failed admission reached the refund fence"
    );
    assert_eq!(
        capacity_wakes, 1,
        "refund must wake select before the next actual ACK tick rescues progress"
    );
}
