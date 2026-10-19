mod owned_io {
    use super::*;
    #[tokio::test]
    async fn session_cleanup_waits_for_a_writer_after_exact_child_reap() {
        let spawner = FakeSpawner::new();
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        inbound
            .send(keystrokes(16, b"held owned write"))
            .await
            .unwrap();
        until(|| spawner.write_attempts.load(Ordering::SeqCst) != 0).await;
        // Independently end the reader/child. The held write is the only remaining
        // blocking operation, so a child receipt cannot stand in for its join.
        spawner.end_channel(16);
        until(|| spawner.waited.lock().unwrap().contains(&16)).await;
        drop(inbound);
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        // Release and join before asserting on RED as well as GREEN. The guard
        // also releases an owned fixture write on every earlier unwind path.
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("released writer allowed session cleanup")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "session cleanup completed while its PTY writer was still executing"
        );
    }

    #[tokio::test]
    async fn natural_exit_with_idle_writer_has_no_cleanup_cycle() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        spawner.end_channel(16);
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
        drop(inbound);
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("idle writer joins after EOF drops its sender")
            .unwrap();
        assert!(
            spawner.killed.lock().unwrap().is_empty(),
            "natural exit must not signal a reaped child"
        );
    }

    #[tokio::test]
    async fn session_cleanup_retains_a_reader_inside_read_after_child_reap() {
        let spawner = FakeSpawner::new();
        *spawner.held_reads.0.lock().unwrap() = true;
        let release = asynchronous_reaping::ReleaseWait(spawner.held_reads.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        until(|| spawner.reads.load(Ordering::SeqCst) != 0).await;
        drop(inbound);
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("released reader allowed session cleanup")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "child reap must not refund an executing read"
        );
    }

    #[tokio::test]
    async fn retired_writer_remains_owned_after_stream_reuse() {
        let spawner = FakeSpawner::new();
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        let (io, inbound, mut outbound) = channel_pair();
        let mut runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        inbound
            .send(keystrokes(16, b"old held write"))
            .await
            .unwrap();
        until(|| spawner.write_attempts.load(Ordering::SeqCst) != 0).await;
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        until(|| spawner.killed.lock().unwrap().contains(&16)).await;
        open_a_shell_channel(&inbound, &mut outbound).await;
        let _ = next_channel_data(&mut outbound, 16).await;
        drop(inbound);
        let returned_early =
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut runner)
                .await
                .ok();
        drop(release);
        if returned_early.is_none() {
            tokio::time::timeout(std::time::Duration::from_secs(5), runner)
                .await
                .expect("both exact instances joined after release")
                .unwrap();
        }
        assert!(
            returned_early.is_none(),
            "reusing a stream lost its retired writer owner"
        );
    }
}
