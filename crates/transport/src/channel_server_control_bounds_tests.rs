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
