// Controlled socket seams exercise retirement without spawning or signalling.
#[test]
fn pam40_retirement_retains_readable_seam_and_admission_after_shell_cleanup() {
    use std::io::Read;
    let mut state = empty_state();
    let owner = MonitorOwner {
        login: [40; 16],
        incarnation: 1,
    };
    let (seam, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    // Already-reaped controlled monitor: no process authority is exercised.
    state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            #[cfg(target_os = "linux")]
            signal_failure: None,
            pid: Pid::this(),
            reaped: true,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: None,
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: false,
            failure: None,
        },
    );
    state.retired.insert(owner);
    finish_retired(&mut state, owner);
    let kept = state.monitors.contains_key(&owner);
    let charged = state.retired.contains(&owner);
    let mut byte = [0];
    let requested_end = peer.read(&mut byte).unwrap() == 0;
    let reverse_live = {
        use std::io::Write;
        peer.write_all(b"final cleanup result").is_ok()
    };
    let mut returned = [0; 20];
    if let Some(monitor) = state.monitors.get_mut(&owner) {
        monitor
            .seam()
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        monitor.seam().read_exact(&mut returned).unwrap();
    }
    assert_eq!(
        &returned, b"final cleanup result",
        "queued result remains readable after reap"
    );
    assert!(requested_end, "retirement must request monitor EOF");
    assert!(
        kept,
        "shell receipts cannot release the monitor awaiting PAM completion"
    );
    assert!(
        charged,
        "retiring PAM work retains its original admission charge"
    );
    assert!(
        reverse_live,
        "write-half shutdown must retain the final-result route"
    );
}

#[test]
fn pam40_retiring_pam_owner_cannot_admit_an_extra_login() {
    let account = my_account();
    let mut state = filled_state(&account, MAX_LOGINS - 1);
    let owner = MonitorOwner {
        login: [240; 16],
        incarnation: 500,
    };
    let (seam, _peer) = UnixStream::pair().unwrap();
    state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            #[cfg(target_os = "linux")]
            signal_failure: None,
            pid: Pid::this(),
            reaped: true,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: None,
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: false,
            failure: None,
        },
    );
    state.retired.insert(owner);
    finish_retired(&mut state, owner);
    let admitted = ensure_login(&mut state, [241; 16], &account, String::new());
    assert!(
        admitted.is_err(),
        "last shell receipt must not refund unfinished PAM admission"
    );
}
