// Included in main::tests; every descriptor/thread is fixture-owned.
#[test]
fn client179_actual_reader_fences_pressure_and_resumes_or_stops_with_guards_held() {
    use std::os::fd::{AsRawFd, FromRawFd};
    for disposition in ["resume", "retained", "cancel"] {
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
            for _ in 0..16 {
                write.write_all(&[b'a'; 4096])?;
            }
            write.write_all(&[b'z'; 4096])
        });
        let result = (|| -> Result<_, String> {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut prefix = Vec::new();
            loop {
                let event = rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|e| format!("pressure fence: {e}"))?;
                match event {
                    UiEvent::IngressBlocked(blocked) => return Ok((prefix, blocked)),
                    UiEvent::Stdin(bytes) => prefix.push(bytes),
                    other => return Err(format!("unexpected reader event: {other:?}")),
                }
            }
        })();
        // On an early fixture error, cancellation precedes descriptor/guard
        // release and the writer is still joined before any outcome assertion.
        let Ok((prefix, blocked)) = result else {
            reader.stop();
            drop(read);
            let _ = writer.join();
            panic!("{}", result.unwrap_err());
        };
        let no_overtaking = matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty));
        let initial_usage = budget.usage();
        let prefix_bytes: usize = prefix.iter().map(qsh::input_ingress::InputBytes::len).sum();
        let mut resumed = Vec::new();
        let mut failure = false;
        let mut prefix_processed = true;
        let mut unexpected = None;
        let mut stopped_before_refund = true;
        if disposition == "cancel" {
            let (done_tx, done_rx) = mpsc::channel();
            let stop = std::thread::spawn(move || {
                reader.stop();
                let _ = done_tx.send(());
            });
            stopped_before_refund = done_rx.recv_timeout(Duration::from_secs(3)).is_ok();
            // Always release fixture obligations even if the stop contract failed.
            drop((prefix, blocked));
            stop.join().unwrap();
        } else {
            let mut session = geometry_session();
            if disposition == "retained" {
                session.assume_channel_opening();
                for input in prefix {
                    prefix_processed &= session.handle(UiEvent::Stdin(input), 0).is_empty();
                }
            } else {
                drop(prefix); // preceding UI actions actually consumed their input
            }
            let actions = session.handle(UiEvent::IngressBlocked(blocked), 1);
            failure = actions.iter().any(|a| matches!(a, Action::Exit(1)));
            let deadline = Instant::now() + Duration::from_secs(3);
            while let Ok(event) =
                rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                match event {
                    UiEvent::Stdin(bytes) => resumed.extend_from_slice(bytes.as_slice()),
                    other => {
                        unexpected = Some(other);
                        break;
                    }
                }
            }
            reader.stop();
            drop(session);
        }
        drop(read);
        let written = writer.join();
        assert!(
            prefix_processed,
            "Opening retained the complete preceding prefix"
        );
        assert!(
            unexpected.is_none(),
            "unexpected post-fence event: {unexpected:?}"
        );
        assert!(
            no_overtaking,
            "no newer event may pass an unacknowledged fence"
        );
        assert_eq!(prefix_bytes, 64 * 1024);
        assert_eq!(initial_usage, (64 * 1024, 16, 64 * 1024));
        written
            .expect("fixture writer joined")
            .expect("finite writes completed");
        assert!(
            stopped_before_refund,
            "stop must join while every guard remains held"
        );
        assert_eq!(failure, disposition == "retained");
        assert_eq!(
            resumed,
            if disposition == "resume" {
                vec![b'z'; 4096]
            } else {
                Vec::new()
            }
        );
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}
