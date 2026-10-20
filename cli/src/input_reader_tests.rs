// Included in main::tests; every descriptor/thread is fixture-owned.
#[test]
fn client179_actual_reader_bounds_held_ingress_before_publication() {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut fds = [-1; 2];
    // SAFETY: fds contains space for both returned descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe produced two fresh, independently owned fds.
    let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    for fd in [read.as_raw_fd(), write.as_raw_fd()] {
        // SAFETY: both fixture-owned descriptors are live.
        assert!(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } >= 0);
    }
    let (tx, rx) = mpsc::channel();
    let budget = qsh::input_ingress::IngressBudget::default();
    let reader = InputReader::start_fd(tx, read.as_raw_fd(), budget.clone());
    let writer = std::thread::spawn(move || {
        for _ in 0..17 {
            write.write_all(&[b'a'; 4096])?;
        }
        Ok::<(), std::io::Error>(())
    });
    // Wait for actual reader EOF or explicit overflow termination. Receiving
    // channel disconnection is a positive completion fence, not a negative
    // sleep waiting for a correct implementation to exceed its own cap.
    let result = (|| -> Result<_, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut events = Vec::new();
        loop {
            match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
                Ok(event) => events.push(event),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(events),
                Err(error) => return Err(format!("reader completion: {error}")),
            }
        }
    })();
    reader.stop();
    drop(read);
    let written = writer.join();
    let events = result.expect("actual held-reader path completed");
    written
        .expect("fixture writer joined")
        .expect("finite fixture writes completed");
    let held_bytes: usize = events
        .iter()
        .filter_map(|event| match event {
            UiEvent::Stdin(bytes) => Some(bytes.len()),
            _ => None,
        })
        .sum();
    assert!(
        held_bytes <= 64 * 1024,
        "actual retained ingress {held_bytes} exceeds65536 before UI consumption"
    );
    assert_eq!(
        held_bytes,
        64 * 1024,
        "positive full admitted ingress prefix"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event,
                UiEvent::InputFailure(session::LocalInputFailure::IngressFull)
            ))
            .count(),
        1,
        "overflow must terminate explicitly exactly once"
    );
    assert_eq!(budget.usage(), (64 * 1024, 16, 64 * 1024));
    drop(events);
    assert_eq!(budget.usage(), (0, 0, 0));
}
