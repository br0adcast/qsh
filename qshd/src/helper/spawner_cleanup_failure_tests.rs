#[test]
fn selinux57_worker_failed_receipt_keeps_physical_kind_and_closes_reader() {
    use transport::channel_server::ChildStatus;
    for kind in [CleanupKind::NoChild, CleanupKind::Reaped] {
        let (worker, helper) = channel::pair().unwrap();
        let custody = transport::channel_open::OpenCustody::new();
        let receipt = Arc::new(Mutex::new(CleanupReceipt {
            kind: None,
            failure: None,
            cleanup_requested: false,
            notify: custody.cleanup_notifier(),
            reap_notify: None,
            leader_notified: false,
            connection_closed: false,
        }));
        let waiting = Arc::new(Mutex::new(HashMap::from([(
            5701,
            Pending {
                opened: None,
                exited: None,
                outcome: OpenOutcome::Failed,
                receipt: receipt.clone(),
            },
        )])));
        let disconnected = Arc::new(AtomicBool::new(false));
        let read_socket = worker.try_clone().unwrap();
        let reader_waiting = waiting.clone();
        let read_disconnected = disconnected.clone();
        let reader = std::thread::spawn(move || {
            read_loop(
                read_socket,
                reader_waiting,
                read_disconnected,
                || {},
                Box::new(|_, _| {}),
            )
        });
        let failure = CleanupFailure::PtyLabelRestore { errno: 5 };
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> std::io::Result<bool> {
                // Unrelated IDs and descriptor-bearing receipts cannot grant proof.
                channel::send(
                    &helper,
                    &encode(&Response::CleanupFailed {
                        id: 5702,
                        kind,
                        failure,
                    })
                    .unwrap(),
                    None,
                )?;
                channel::send(
                    &helper,
                    &encode(&Response::CleanupFailed {
                        id: 5701,
                        kind,
                        failure,
                    })
                    .unwrap(),
                    Some(worker.as_fd()),
                )?;
                channel::send(
                    &helper,
                    &encode(&Response::CleanupFailed {
                        id: 5701,
                        kind,
                        failure,
                    })
                    .unwrap(),
                    None,
                )?;
                // A duplicate clean receipt must not erase the original error.
                channel::send(
                    &helper,
                    &encode(&Response::CleanupComplete { id: 5701, kind }).unwrap(),
                    None,
                )?;
                let deadline = Instant::now() + TEST_RECV_TIMEOUT;
                while Instant::now() < deadline {
                    if receipt.lock().unwrap().kind.is_some() {
                        return Ok(true);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(false)
            }));
        drop(helper);
        let joined = reader.join();
        // All assertions follow actual reader settlement on success and failure.
        assert!(joined.is_ok());
        assert!(result.unwrap().unwrap());
        assert!(waiting.lock().unwrap().is_empty());
        assert_eq!(receipt.lock().unwrap().kind, Some(kind));
        assert_eq!(receipt.lock().unwrap().failure, Some(failure));
        if kind == CleanupKind::Reaped {
            let (_send, exits) = mpsc::channel();
            let mut wait = HelperWait {
                id: 5701,
                exits,
                leader_code: None,
                exits_closed: false,
                receipt,
                tx: worker,
                disconnected_locally: disconnected,
            };
            assert!(matches!(
                wait.poll_exit(),
                ChildStatus::Reaped { code: None }
            ));
        }
    }
}
