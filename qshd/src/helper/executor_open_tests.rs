// Included in spawner::tests: real socket reader, executor and owned-child proof.
mod open24_executor_receipts {
    use super::*;
    use transport::channel_geometry::ChannelInstance;
    use transport::channel_open::{ChannelOpenExecutor, OpenIdentity, OpenRequestSnapshot};

    struct OwnedChild(Option<std::process::Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn open24_helper_executor_cancelled_delayed_success_keeps_lease_until_exact_reap_receipt()
    {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits {
            owner_models: 1,
            ..BudgetLimits::default()
        }));
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let (reader_done, reader_join) = mpsc::channel();
        let (reader_barrier, crossed_barrier) = mpsc::channel();
        let spawner = Arc::new(
            HelperChannelSpawner::with_budget_hook(
                worker,
                budget.clone(),
                move || {
                    let _ = reader_done.send(());
                },
                Box::new(move |login, incarnation| {
                    let _ = reader_barrier.send((login, incarnation));
                }),
            )
            .unwrap(),
        );
        let registry = spawner.open_registry();
        let session = registry.session().unwrap();
        let executor = ChannelOpenExecutor::new(spawner.clone(), registry.clone());
        let mut request = shell_request();
        request.cols = 2;
        request.rows = 1;
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
        executor.submit(&job).unwrap();
        let worker_join = job.take_worker().unwrap();
        let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
        let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
            panic!("exact admitted Open")
        };
        assert_eq!(budget.used().models, 1);
        // A fixture-owned real child represents the helper's side effect. Its
        // handle remains independent of product custody, including on panic.
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .env("HISTFILE", "/dev/null")
            .spawn()
            .unwrap();
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);
        let mut child = OwnedChild(Some(child));
        drop(job); // Receiver disappears while helper Open has no outcome yet.
        let descriptor = tempfile::tempfile().unwrap();
        channel::send(
            &helper,
            &encode(&Response::Opened { id }).unwrap(),
            Some(descriptor.as_fd()),
        )
        .unwrap();
        tokio::time::timeout(TEST_RECV_TIMEOUT, worker_join)
            .await
            .unwrap()
            .unwrap();
        let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
        assert!(
            matches!(decode::<Request>(&bytes).unwrap(), Request::Close { id: closed } if closed == id)
        );
        assert_eq!(
            (
                registry.outstanding(),
                session.occupied(),
                budget.used().models
            ),
            (1, 1, 1)
        );
        assert!(budget
            .reserve(
                anyone().uid,
                terminal_size::TerminalSize::new(2, 1).unwrap()
            )
            .is_err());
        let status = child.0.as_mut().unwrap().wait().unwrap();
        assert_eq!(status.code(), Some(7));
        child.0.take();
        assert!(matches!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        ));
        channel::send(
            &helper,
            &encode(&Response::Exited { id, code: 7 }).unwrap(),
            None,
        )
        .unwrap();
        // Actual independent wait and a bare Exited are still not the worker's
        // trusted receipt. Force a reader round trip with an unrelated ID; it
        // must not free this registration either.
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id: id + 1,
                kind: CleanupKind::Reaped,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        channel::send(
            &helper,
            &encode(&Response::LoginEnded {
                login: [9; 16],
                incarnation: 99,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            crossed_barrier.recv_timeout(TEST_RECV_TIMEOUT).unwrap(),
            ([9; 16], 99)
        );
        assert_eq!(
            (
                registry.outstanding(),
                session.occupied(),
                budget.used().models
            ),
            (1, 1, 1)
        );
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
        tokio::time::timeout(TEST_RECV_TIMEOUT, async {
            while registry.outstanding() != 0 {
                session.notified().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(session.occupied(), 0);
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
        let reused = budget
            .reserve(
                anyone().uid,
                terminal_size::TerminalSize::new(2, 1).unwrap(),
            )
            .unwrap();
        drop(reused);
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
        drop(helper);
        reader_join.recv_timeout(TEST_RECV_TIMEOUT).unwrap();
        drop(executor);
        drop(spawner);
    }
}
