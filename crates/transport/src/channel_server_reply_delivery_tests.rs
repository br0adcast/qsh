// Included in channel_server::tests; drives actual writer and runner ownership.
mod reply_delivery_eof {
    use super::*;
    use crate::channel_geometry::OutputGapCause;

    async fn held_reply_at_eof(write_fails: bool) {
        let mut spawner = FakeSpawner::new();
        Arc::get_mut(&mut spawner).unwrap().exit_code = 23;
        spawner.reply_queries.store(true, Ordering::SeqCst);
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );

        spawner.hold_writes(true);
        // Installed before any assertion that could unwind with a blocked writer.
        let release = ReleaseHeldWrites(spawner.clone());
        spawner.feed(16, b"query");
        until(|| spawner.write_attempts.load(Ordering::SeqCst) == 1).await;
        assert!(spawner.written.lock().unwrap().is_empty());
        spawner.end_channel(16);
        until(|| spawner.waited.lock().unwrap().contains(&16)).await;

        // The process EOF/reap path has run, yet the required local reply is
        // still held inside write_all. Another channel remains responsive.
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 20).await,
            b"hello from the shell"
        );
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|(stream, _)| *stream != 16),
            "reader EOF cannot publish the final marker before local write completion"
        );
        assert!(!spawner.killed.lock().unwrap().contains(&20));

        if write_fails {
            spawner.break_writes();
        }
        drop(release);
        // No new inbound event is sent: actual write settlement must wake the
        // runner, disclose failure when necessary, then publish its marker.
        let gap_count = tokio::time::timeout(Duration::from_secs(5), async {
            let mut gaps = 0;
            loop {
                let msg = outbound.recv().await.expect("runner remains alive");
                match &msg {
                    SessionOutbound::ChannelOutput {
                        stream: 16,
                        output: ChannelOutput::OutputGap(cause, _),
                        ..
                    } => {
                        assert_eq!(*cause, OutputGapCause::TerminalReplyFailure);
                        gaps += 1;
                    }
                    SessionOutbound::ChannelExit { stream: 16, .. } => {
                        panic!("process exit overtook the final delivery proof");
                    }
                    _ => {}
                }
                if delivery_marker(&msg).is_some_and(|(stream, _, _)| stream == 16) {
                    break gaps;
                }
            }
        })
        .await
        .expect("writer settlement advances EOF without new input");
        assert_eq!(gap_count, usize::from(write_fails));
        let writes = spawner.written.lock().unwrap().clone();
        if write_fails {
            assert!(writes.is_empty(), "the controlled write actually failed");
        } else {
            assert_eq!(writes, vec![(16, b"reply".to_vec())]);
            assert!(!spawner.killed.lock().unwrap().contains(&16));
        }
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(stream, _)| *stream == 16)
                .count(),
            1
        );
        assert_no_control(&mut outbound).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: token_for(&requests, 16),
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 23
            }
        );

        assert!(!spawner.killed.lock().unwrap().contains(&20));
        spawner.feed(20, b"sibling output survives");
        assert_eq!(
            next_channel_data(&mut outbound, 20).await,
            b"sibling output survives"
        );
        spawner.end_channel(20);
        drop(inbound);
        tokio::time::timeout(Duration::from_secs(5), runner)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn reply_delivery44_successful_writer_settles_before_final_marker_after_eof() {
        held_reply_at_eof(false).await;
    }

    #[tokio::test]
    async fn reply_delivery44_failed_writer_discloses_gap_before_final_marker_after_eof() {
        held_reply_at_eof(true).await;
    }
}
