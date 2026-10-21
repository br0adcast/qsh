fn invocation_setup(home: &std::path::Path) -> Setup {
    Setup::new(
        crate::args::parse_args(&["127.0.0.1:60001".into()]).unwrap(),
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(home.join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        Tty::at(home.join("no-tty")),
        KnownHosts::new(home.join("ssh_known_hosts"), None),
        None,
        None,
        [179; 16],
    )
}

// Constructor integration, not a primitive-handle test. All peers are actual
// authenticated sockets; source debt remains live across consented replacement.
fn check_invocation_replacement_constructors(shared: bool) {
    use std::sync::atomic::Ordering;
    use transport::driver_std::SendBlocked;
    let home = tempfile::tempdir().unwrap();
    let setup = invocation_setup(home.path());
    let (old, old_peer) = authenticated_startup_for(Some(&setup), false);
    assert_eq!(old.0.as_ref().unwrap().settle(), Verdict::Working);
    old_peer.hold.store(true, Ordering::SeqCst);
    old_peer
        .held
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    old.0
        .as_ref()
        .unwrap()
        .client
        .send_bytes(30, vec![b'a'; transport::client_input_budget::INPUT_BYTES])
        .unwrap();
    let replacement = setup.replacement([180; 16]);
    let (new, new_peer) = authenticated_startup_for(Some(&replacement), shared);
    assert_eq!(new.0.as_ref().unwrap().settle(), Verdict::Working);
    let candidate = vec![b'b'; 4096];
    let original = (candidate.as_ptr() as usize, candidate.capacity());
    let rejected = new
        .0
        .as_ref()
        .unwrap()
        .client
        .send_bytes(31, candidate)
        .err();
    let observed = rejected.as_ref().map(|r| {
        (
            r.reason,
            r.data.as_ptr() as usize,
            r.data.capacity(),
            r.data.len(),
        )
    });
    // Actual Connection teardown/join, not a link-down observer/refund.
    drop(old);
    drop(old_peer);
    let retried = rejected.map(|r| new.0.as_ref().unwrap().client.send_bytes(31, r.data));
    let delivered = if matches!(retried, Some(Ok(()))) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let bytes = new_peer.data.lock().unwrap().clone();
            if bytes.len() >= 4096 {
                break Some(bytes);
            }
            if new_peer
                .data_ready
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .is_err()
            {
                break None;
            }
        }
    } else {
        None
    };
    drop(new);
    drop(new_peer);
    assert_eq!(
        observed,
        Some((SendBlocked::Full, original.0, original.1, 4096)),
        "replacement constructor reset the invocation budget (shared={shared})"
    );
    assert!(
        matches!(retried, Some(Ok(()))),
        "actual old teardown must release the original whole candidate"
    );
    assert_eq!(
        delivered,
        Some(vec![b'b'; 4096]),
        "retry only wholly unaccepted candidate, actual peer bytes exactly once"
    );
}

#[test]
fn client179_invocation_single_constructor_retains_actual_old_driver_debt() {
    check_invocation_replacement_constructors(false);
}
#[test]
fn client179_invocation_shared_constructor_retains_actual_old_driver_debt() {
    check_invocation_replacement_constructors(true);
}

#[test]
fn client179_invocation_independent_setup_does_not_share_another_invocations_debt() {
    use std::sync::atomic::Ordering;
    let home = tempfile::tempdir().unwrap();
    let first_setup = invocation_setup(&home.path().join("first"));
    let second_setup = invocation_setup(&home.path().join("second"));
    let (first, first_peer) = authenticated_startup_for(Some(&first_setup), false);
    assert_eq!(first.0.as_ref().unwrap().settle(), Verdict::Working);
    first_peer.hold.store(true, Ordering::SeqCst);
    first_peer
        .held
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    first
        .0
        .as_ref()
        .unwrap()
        .client
        .send_bytes(30, vec![b'a'; transport::client_input_budget::INPUT_BYTES])
        .unwrap();
    let (second, second_peer) = authenticated_startup_for(Some(&second_setup), false);
    assert_eq!(second.0.as_ref().unwrap().settle(), Verdict::Working);
    let admitted = second.0.as_ref().unwrap().client.send_bytes(31, vec![b'b']);
    drop(first);
    drop(first_peer);
    drop(second);
    drop(second_peer);
    assert!(
        admitted.is_ok(),
        "separate invocation must have independent admission"
    );
}
