// Included in server::tests; all fixtures exercise real lifecycle handlers.
mod open24_receipts {
    use super::*;
    use crate::helper::protocol::CleanupKind;

    fn pending_channel(state: &mut LoopState, owner: MonitorOwner, id: ChannelId) {
        state.live.insert(id, ChannelSlot::Starting(owner));
        state.highest_channel_id = state.highest_channel_id.max(id);
        state.pending.insert(Pending {
            deadline: Instant::now() + Duration::from_secs(10),
            what: PendingWhat::Channel {
                id,
                master: tempfile::tempfile().unwrap().into(),
                login: owner.login,
                uid: my_uid(),
                cancelled: false,
            },
        });
    }

    fn assert_quiet(sock: &UnixStream) {
        sock.set_nonblocking(true).unwrap();
        assert!(matches!(channel::recv(sock), Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock));
        sock.set_nonblocking(false).unwrap();
    }

    #[test]
    fn open24_receipt_retires_startup_before_a_late_started_event() {
        let login = [92; 16];
        let mut state = state_with_login(&my_account(), login);
        let owner = owner_for(&state, login);
        pending_channel(&mut state, owner, 101);
        let seam = DirectSeam::new();
        complete_cleanup(&seam.helper, &mut state, owner, 101, CleanupKind::Reaped);
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 101, .. }
        ));
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 101,
                kind: CleanupKind::Reaped
            }
        );
        assert!(!state.live.contains_key(&101));
        assert!(state.pending.take_channel(101).is_none());
        finish_channel(&seam.helper, &mut state, 101, StartupReport::Started);
        complete_cleanup(&seam.helper, &mut state, owner, 101, CleanupKind::Reaped);
        assert_quiet(&seam.worker);
    }

    #[test]
    fn open24_stale_incarnation_and_duplicate_ids_cannot_release_an_owner() {
        let login = [93; 16];
        let mut state = state_with_login(&my_account(), login);
        let old = owner_for(&state, login);
        state.next_incarnation = old.incarnation + 1;
        pending_channel(&mut state, old, 101);
        let seam = DirectSeam::new();
        forget_login(&seam.helper, &mut state, login);
        // Existing outcome order is separate from receipt proof.
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::LoginEnded { .. }
        ));
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 101, .. }
        ));
        assert_quiet(&seam.worker);
        let account = my_account();
        ensure_login(&mut state, login, &account, String::new()).unwrap();
        state.verified.insert(account.uid, account);
        let new = owner_for(&state, login);
        assert_ne!(old, new);
        pending_channel(&mut state, new, 102);
        complete_cleanup(&seam.helper, &mut state, old, 102, CleanupKind::Reaped);
        assert!(state.live.contains_key(&102));
        assert_quiet(&seam.worker);
        complete_cleanup(&seam.helper, &mut state, old, 101, CleanupKind::NoChild);
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 101,
                kind: CleanupKind::NoChild
            }
        );
        assert!(!state.retired.contains(&old));
        assert!(state.live.contains_key(&102));
        seam.serve(
            &mut state,
            &open_request(101, my_uid().as_raw(), login),
            &test_config(),
            keep_identity,
        );
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 101, .. }
        ));
        assert_quiet(&seam.worker); // refusing reuse cannot produce another proof
        assert!(!state.live.contains_key(&101));
    }

    #[test]
    fn open24_failed_channels_still_fill_all_sixteen_helper_slots() {
        let login = [94; 16];
        let mut state = state_with_login(&my_account(), login);
        let owner = owner_for(&state, login);
        let seam = DirectSeam::new();
        for id in 1..=MAX_CHANNELS_PER_LOGIN as u64 {
            pending_channel(&mut state, owner, id);
            finish_channel(
                &seam.helper,
                &mut state,
                id,
                StartupReport::Failed(nix::Error::ENOENT),
            );
            assert!(matches!(
                next_response(&seam.worker).0,
                Response::Failed { .. }
            ));
        }
        assert_eq!(state.live.len(), 16);
        seam.serve(
            &mut state,
            &open_request(17, my_uid().as_raw(), login),
            &test_config(),
            keep_identity,
        );
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 17, .. }
        ));
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 17,
                kind: CleanupKind::NoChild
            }
        );
        assert!(
            state.monitors.is_empty(),
            "capacity rejection must not create a monitor"
        );
        assert_eq!(state.live.len(), 16);
    }

    #[test]
    fn open24_retired_login_churn_preserves_the_256_owner_bound() {
        let account = my_account();
        let mut state = empty_state();
        let (helper, worker) = quiet_seam();
        // Drain notices synchronously; the fixed socket buffer is not the bound.
        worker.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        for n in 0..MAX_LOGINS {
            let login = login_token(n);
            ensure_login(&mut state, login, &account, String::new()).unwrap();
            let owner = owner_for(&state, login);
            for slot in 0..MAX_CHANNELS_PER_LOGIN {
                let id = (n * MAX_CHANNELS_PER_LOGIN + slot + 1) as u64;
                state.live.insert(id, ChannelSlot::Cleaning(owner));
            }
            forget_login(&helper, &mut state, login);
            assert!(matches!(
                next_response(&worker).0,
                Response::LoginEnded { .. }
            ));
        }
        assert!(state.logins.is_empty() && state.verified.is_empty());
        assert_eq!(state.retired.len(), 256);
        assert_eq!(state.live.len(), 4096);
        assert!(ensure_login(&mut state, [255; 16], &account, String::new()).is_err());
        let owner = state.live[&1].owner();
        for id in 1..=16 {
            complete_cleanup(&helper, &mut state, owner, id, CleanupKind::Reaped);
            assert!(matches!(
                next_response(&worker).0,
                Response::CleanupComplete { .. }
            ));
        }
        assert_eq!(state.retired.len(), 255);
        ensure_login(&mut state, [255; 16], &account, String::new()).unwrap();
        assert_eq!(state.logins.len() + state.retired.len(), 256);
    }

    #[test]
    fn open24_login_incarnation_exhaustion_refuses_without_wrap() {
        let mut state = empty_state();
        state.next_incarnation = u64::MAX;
        assert!(ensure_login(&mut state, [95; 16], &my_account(), String::new()).is_err());
        assert!(state.logins.is_empty());
        assert_eq!(state.next_incarnation, u64::MAX);
    }
    struct OwnedMonitor(Pid);
    impl Drop for OwnedMonitor {
        fn drop(&mut self) {
            use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
            if matches!(
                waitpid(self.0, Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::StillAlive)
            ) {
                let _ = nix::sys::signal::kill(self.0, nix::sys::signal::Signal::SIGKILL);
                while matches!(waitpid(self.0, None), Err(nix::Error::EINTR)) {}
            }
        }
    }

    #[test]
    fn open24_reaped_monitor_preserves_queued_exit_and_cleanup() {
        let login = [96; 16];
        let mut state = state_with_login(&my_account(), login);
        let owner = owner_for(&state, login);
        state.live.insert(101, ChannelSlot::Running(owner));
        let seam = DirectSeam::new();
        let (parent, monitor) = channel::pair().unwrap();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let _owned = OwnedMonitor(pid);
        state.monitors.insert(
            owner,
            Monitor {
                seam: parent,
                pid,
                reaped: false,
                write_closed: false,
                stop_attempted: false,
                completion: None,
                seam_closed: false,
                wait_lost: false,
                failure: None,
            },
        );
        for event in [
            MonitorEvent::Exited { id: 101, code: 7 },
            MonitorEvent::CleanupComplete {
                id: 101,
                kind: CleanupKind::Reaped,
            },
        ] {
            channel::send(&monitor, &encode(&event).unwrap(), None).unwrap();
        }
        drop(monitor);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state
            .monitors
            .get(&owner)
            .is_some_and(|monitor| monitor.reaped)
        {
            reap(&seam.helper, &mut state);
            assert!(Instant::now() < deadline, "owned monitor did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(nix::libc::ECHILD),
            "the helper already reaped the exact monitor"
        );
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::LoginEnded { .. }
        ));
        assert_quiet(&seam.worker); // monitor reap is not the shell's exit verdict
        serve_ready_monitors(seam.seams(), &mut state, &[owner]);
        assert_eq!(
            next_response(&seam.worker).0,
            Response::Exited { id: 101, code: 7 }
        );
        assert!(state.live.contains_key(&101));
        serve_ready_monitors(seam.seams(), &mut state, &[owner]);
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 101,
                kind: CleanupKind::Reaped
            }
        );
        assert!(state.live.is_empty() && state.retired.is_empty());
        assert!(state.monitors.is_empty());
    }

    #[test]
    fn open24_prefork_error_produces_exact_no_child_through_monitor() {
        let login = [97; 16];
        let mut state = state_with_login(&my_account(), login);
        let seam = DirectSeam::new();
        let mut request = open_request(101, my_uid().as_raw(), login);
        if let Request::Open { command, .. } = &mut request {
            *command = "bad\0command".into();
        }
        seam.serve(&mut state, &request, &test_config(), keep_identity);
        seam.settle(&mut state, &test_config());
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 101, .. }
        ));
        assert!(matches!(
            state.live.get(&101),
            Some(ChannelSlot::Cleaning(_))
        ));
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while state.live.contains_key(&101) {
            assert!(Instant::now() < deadline);
            seam.one_pass(&mut state, &test_config());
        }
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 101,
                kind: CleanupKind::NoChild
            }
        );
        assert!(
            state.logins.contains_key(&login),
            "one failed command does not end the login"
        );
        stop_monitors(&mut state);
    }

    #[test]
    fn open24_wrong_monitor_cannot_complete_another_incarnation() {
        let login = [98; 16];
        let mut state = state_with_login(&my_account(), login);
        let current = owner_for(&state, login);
        let stale = MonitorOwner {
            login,
            incarnation: current.incarnation + 1,
        };
        pending_channel(&mut state, current, 101);
        let seam = DirectSeam::new();
        let (parent, monitor) = channel::pair().unwrap();
        // Already-reaped synthetic owner avoids any signal/wait on a borrowed PID.
        state.monitors.insert(
            stale,
            Monitor {
                seam: parent,
                pid: Pid::from_raw(1),
                reaped: true,
                write_closed: false,
                stop_attempted: false,
                completion: None,
                seam_closed: false,
                wait_lost: false,
                failure: None,
            },
        );
        for event in [
            MonitorEvent::Started { id: 101 },
            MonitorEvent::CleanupComplete {
                id: 101,
                kind: CleanupKind::NoChild,
            },
        ] {
            channel::send(&monitor, &encode(&event).unwrap(), None).unwrap();
            serve_ready_monitors(seam.seams(), &mut state, &[stale]);
            assert!(
                matches!(state.live.get(&101), Some(ChannelSlot::Starting(owner)) if *owner == current)
            );
            assert_quiet(&seam.worker);
        }
    }
    #[test]
    fn open24_reaped_monitor_keeps_no_child_after_failed_first_read() {
        let login = [99; 16];
        let mut state = state_with_login(&my_account(), login);
        let owner = owner_for(&state, login);
        pending_channel(&mut state, owner, 101);
        let seam = DirectSeam::new();
        let (parent, monitor) = channel::pair().unwrap();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let _owned = OwnedMonitor(pid);
        state.monitors.insert(
            owner,
            Monitor {
                seam: parent,
                pid,
                reaped: false,
                write_closed: false,
                stop_attempted: false,
                completion: None,
                seam_closed: false,
                wait_lost: false,
                failure: None,
            },
        );
        for event in [
            MonitorEvent::Failed {
                id: 101,
                errno: nix::Error::EACCES as i32,
            },
            MonitorEvent::CleanupComplete {
                id: 101,
                kind: CleanupKind::NoChild,
            },
        ] {
            channel::send(&monitor, &encode(&event).unwrap(), None).unwrap();
        }
        drop(monitor);
        serve_ready_monitors(seam.seams(), &mut state, &[owner]);
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::Failed { id: 101, .. }
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !state
            .monitors
            .get(&owner)
            .is_some_and(|monitor| monitor.reaped)
        {
            reap(&seam.helper, &mut state);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            next_response(&seam.worker).0,
            Response::LoginEnded { .. }
        ));
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(nix::libc::ECHILD),
            "the helper already reaped the exact monitor"
        );
        assert!(matches!(
            state.live.get(&101),
            Some(ChannelSlot::Cleaning(_))
        ));
        serve_ready_monitors(seam.seams(), &mut state, &[owner]);
        assert_eq!(
            next_response(&seam.worker).0,
            Response::CleanupComplete {
                id: 101,
                kind: CleanupKind::NoChild
            }
        );
        assert!(state.live.is_empty() && state.retired.is_empty() && state.monitors.is_empty());
    }
}
