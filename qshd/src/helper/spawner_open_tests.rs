// Included in spawner::tests; use the real reader and typed custody registry.
mod open24_receipts {
    use super::*;
    use transport::channel_geometry::ChannelInstance;
    use transport::channel_open::{OpenIdentity, OpenRequestSnapshot};

    fn successful_early_receipt(receipt_first: bool) {
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::new(worker).unwrap();
        let registry = spawner.open_registry();
        let session = registry.session().unwrap();
        let request = shell_request();
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: anyone(),
                    login: any_login(),
                    request: request.clone(),
                    term: None,
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: ChannelInstance::new(1).unwrap(),
                        stream: request.stream,
                        generation: 1,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let (outcome, helper) = std::thread::scope(|scope| {
            let stub = scope.spawn(move || {
                let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                    panic!("Open")
                };
                let descriptor = tempfile::tempfile().unwrap();
                if receipt_first {
                    channel::send(
                        &helper,
                        &encode(&Response::CleanupComplete {
                            id,
                            kind: CleanupKind::Reaped,
                        })
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                }
                channel::send(
                    &helper,
                    &encode(&Response::Opened { id }).unwrap(),
                    Some(descriptor.as_fd()),
                )
                .unwrap();
                channel::send(
                    &helper,
                    &encode(&Response::Exited { id, code: 0 }).unwrap(),
                    None,
                )
                .unwrap();
                if !receipt_first {
                    channel::send(
                        &helper,
                        &encode(&Response::CleanupComplete {
                            id,
                            kind: CleanupKind::Reaped,
                        })
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                }
                helper
            });
            let outcome = ChannelSpawner::spawn(
                &spawner,
                &anyone(),
                any_login(),
                &request,
                None,
                job.custody(),
            );
            (outcome, stub.join().unwrap())
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !spawner.waiting.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            spawner.waiting.lock().unwrap().is_empty(),
            "reader must process the receipt"
        );
        assert!(
            !job.custody().is_cancelled(),
            "an early receipt is a fact, not cancellation"
        );
        let channel = match outcome {
            Ok(channel) => channel,
            Err(error) => panic!("{}", error.reason),
        };
        let (spawned, slot) = job
            .adopt(channel)
            .unwrap_or_else(|_| panic!("successful result must remain adoptable"));
        assert_eq!(spawned.wait.wait(), 0);
        drop(slot);
        drop(helper);
    }
    #[test]
    fn open24_early_reaped_receipt_does_not_cancel_a_successful_open() {
        successful_early_receipt(false);
    }

    #[test]
    fn open24_receipt_before_opened_keeps_the_result_adoptable() {
        successful_early_receipt(true);
    }
    #[test]
    fn open24_early_no_child_is_sticky_until_cleanup_is_requested() {
        use transport::channel_open::CleanupStatus;
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::new(worker).unwrap();
        let registry = spawner.open_registry();
        let session = registry.session().unwrap();
        let request = shell_request();
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: anyone(),
                    login: any_login(),
                    request: request.clone(),
                    term: None,
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: ChannelInstance::new(1).unwrap(),
                        stream: request.stream,
                        generation: 1,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let helper = std::thread::scope(|scope| {
            let stub = scope.spawn(move || {
                let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                    panic!("Open")
                };
                for response in [
                    Response::CleanupComplete {
                        id,
                        kind: CleanupKind::NoChild,
                    },
                    Response::Failed {
                        id,
                        reason: "fixture refusal".into(),
                    },
                ] {
                    channel::send(&helper, &encode(&response).unwrap(), None).unwrap();
                }
                helper
            });
            assert!(ChannelSpawner::spawn(
                &spawner,
                &anyone(),
                any_login(),
                &request,
                None,
                job.custody()
            )
            .is_err());
            stub.join().unwrap()
        });
        wait_for("receipt and outcome consumed", &|| {
            spawner.waiting.lock().unwrap().is_empty()
        });
        assert!(
            job.custody().is_cancelled(),
            "Failed marks cancellation, but is not cleanup proof"
        );
        assert_eq!(registry.outstanding(), 1);
        assert!(matches!(job.cleanup(), CleanupStatus::Confirmed(_)));
        assert_eq!(registry.outstanding(), 0);
        helper.set_nonblocking(true).unwrap();
        assert!(
            matches!(channel::recv(&helper), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "recorded proof cleanup performs no Close I/O"
        );
    }

    #[test]
    fn open24_identity_exhaustion_never_wraps_or_sends() {
        let (worker, helper) = channel::pair().unwrap();
        let spawner = HelperChannelSpawner::new(worker).unwrap();
        spawner.next_id.store(u64::MAX, Ordering::Relaxed);
        let result = spawner.spawn(&anyone(), any_login(), &shell_request(), None);
        assert!(result.err().unwrap().contains("identity exhausted"));
        assert_eq!(spawner.next_id.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(spawner.open_registry().outstanding(), 0);
        helper.set_nonblocking(true).unwrap();
        assert!(
            matches!(channel::recv(&helper), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }

    fn descriptor_failure_keeps_cleanup_custody(fail_at: usize) {
        use transport::channel_open::CleanupStatus;
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::new(worker).unwrap();
        let registry = spawner.open_registry();
        let session = registry.session().unwrap();
        let mut request = shell_request();
        request.screen = true;
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: anyone(),
                    login: any_login(),
                    request: request.clone(),
                    term: None,
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: ChannelInstance::new(1).unwrap(),
                        stream: request.stream,
                        generation: 1,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let (read_end, write_end) = nix::unistd::pipe().unwrap();
        let (helper, id) = std::thread::scope(|scope| {
            let stub = scope.spawn(move || {
                let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                    panic!("Open")
                };
                channel::send(
                    &helper,
                    &encode(&Response::Opened { id }).unwrap(),
                    Some(write_end.as_fd()),
                )
                .unwrap();
                drop(write_end);
                let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                assert_eq!(decode::<Request>(&bytes).unwrap(), Request::Close { id });
                (helper, id)
            });
            let mut calls = 0;
            let result = spawner.spawn_with_clone(
                &anyone(),
                any_login(),
                &request,
                None,
                job.custody(),
                |file| {
                    calls += 1;
                    if calls == fail_at {
                        Err(io::Error::other("fixture descriptor preparation failure"))
                    } else {
                        file.try_clone()
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(calls, fail_at);
            stub.join().unwrap()
        });
        // Every partially prepared descriptor must close on the failure path.
        nix::fcntl::fcntl(
            read_end.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
        )
        .unwrap();
        let mut byte = [0];
        assert_eq!(
            nix::unistd::read(read_end.as_raw_fd(), &mut byte).unwrap(),
            0
        );
        assert!(matches!(job.cleanup(), CleanupStatus::Unknown));
        assert_eq!(registry.outstanding(), 1);
        assert_eq!(session.occupied(), 1);
        assert_eq!(spawner.budget.used().models, 1);
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id,
                kind: CleanupKind::Reaped,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        wait_for(
            "preparation failure's exact receipt releases custody",
            &|| registry.outstanding() == 0,
        );
        assert_eq!(session.occupied(), 0);
        assert_eq!(spawner.budget.used().models, 0);
    }

    #[test]
    fn open24_reader_preparation_failure_keeps_custody_until_receipt() {
        descriptor_failure_keeps_cleanup_custody(1);
    }

    #[test]
    fn open24_writer_preparation_failure_keeps_custody_until_receipt() {
        descriptor_failure_keeps_cleanup_custody(2);
    }
    #[test]
    fn open24_same_numeric_id_on_another_connection_cannot_complete_custody() {
        let mut fixtures = Vec::new();
        for _ in 0..2 {
            let (worker, helper) = channel::pair().unwrap();
            helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
            let spawner = HelperChannelSpawner::new(worker).unwrap();
            let helper = std::thread::scope(|scope| {
                let stub = scope.spawn(move || {
                    let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                    let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                        panic!("Open")
                    };
                    assert_eq!(id, 1);
                    channel::send(
                        &helper,
                        &encode(&Response::Failed {
                            id,
                            reason: "fixture refusal".into(),
                        })
                        .unwrap(),
                        None,
                    )
                    .unwrap();
                    let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                    assert_eq!(decode::<Request>(&bytes).unwrap(), Request::Close { id });
                    helper
                });
                assert!(spawner
                    .spawn(&anyone(), any_login(), &shell_request(), None)
                    .is_err());
                stub.join().unwrap()
            });
            assert_eq!(spawner.open_registry().outstanding(), 1);
            fixtures.push((spawner, helper));
        }
        let receipt = encode(&Response::CleanupComplete {
            id: 1,
            kind: CleanupKind::NoChild,
        })
        .unwrap();
        channel::send(&fixtures[0].1, &receipt, None).unwrap();
        wait_for("first exact connection receipt", &|| {
            fixtures[0].0.open_registry().outstanding() == 0
        });
        assert_eq!(fixtures[1].0.open_registry().outstanding(), 1);
        channel::send(&fixtures[0].1, &receipt, None).unwrap(); // duplicate has no route
        assert_eq!(fixtures[1].0.open_registry().outstanding(), 1);
        channel::send(&fixtures[1].1, &receipt, None).unwrap();
        wait_for("second exact connection receipt", &|| {
            fixtures[1].0.open_registry().outstanding() == 0
        });
    }

    #[test]
    fn open24_concurrent_open_ids_follow_serialized_send_order() {
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::new(worker).unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let stub = scope.spawn(|| {
                for expected in 1..=8 {
                    loop {
                        let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                        match decode::<Request>(&bytes).unwrap() {
                            Request::Close { .. } => continue,
                            Request::Open { id, .. } => {
                                assert_eq!(id, expected, "allocation must match actual send order");
                                for response in [
                                    Response::Failed {
                                        id,
                                        reason: "fixture refusal".into(),
                                    },
                                    Response::CleanupComplete {
                                        id,
                                        kind: CleanupKind::NoChild,
                                    },
                                ] {
                                    channel::send(&helper, &encode(&response).unwrap(), None)
                                        .unwrap();
                                }
                                break;
                            }
                            other => panic!("unexpected request: {other:?}"),
                        }
                    }
                }
            });
            for _ in 0..8 {
                let spawner = &spawner;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    assert!(spawner
                        .spawn(&anyone(), any_login(), &shell_request(), None)
                        .is_err());
                });
            }
            stub.join().unwrap();
        });
        wait_for("all exact receipts retire their jobs", &|| {
            spawner.open_registry().outstanding() == 0
        });
    }
}
