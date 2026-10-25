#[tokio::test(start_paused = true)]
async fn deadlines302_empty_runner_has_no_periodic_ack_wakeup() {
    let _reset = ResetAdmissionHooks;
    let first_tick = Arc::new(tokio::sync::Notify::new());
    SESSION_TIMER_WAKE.with(|slot| *slot.borrow_mut() = Some(first_tick.clone()));
    let (io, inbound, _outbound) = channel_pair();
    let runner = tokio::spawn(run_channel_session(io, FakeSpawner::new()));
    let ticked = tokio::time::timeout(std::time::Duration::from_secs(1), first_tick.notified())
        .await
        .is_ok();
    drop(inbound);
    runner.await.unwrap();
    assert!(
        !ticked,
        "an empty runner must not wake a periodic ACK timer"
    );
}

#[test]
fn deadlines302_denied_silent_ack_registers_scoped_capacity_wakeup() {
    let mut rig = ResizeRig::new(false, false);
    rig.channel.input_consumed = 1;
    let held = rig
        .channel
        .producer
        .timeline
        .try_reserve(
            EntryClass::Ordinary,
            crate::channel_timeline::ORDINARY_BYTES,
        )
        .unwrap();
    emit_ack(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.last_acked, 0);
    drop(held);
    assert!(
        rig.channel
            .producer
            .timeline
            .take_notification(ChannelInstance::new(1).unwrap(), 1),
        "capacity release must retry ACK without an idle interval"
    );
}

#[test]
fn deadlines302_echo_capacity_wait_does_not_replace_geometry_waiter() {
    let mut rig = ResizeRig::new(false, false);
    rig.channel.input_consumed = 4;
    let small = rig
        .channel
        .producer
        .timeline
        .try_reserve(EntryClass::Ordinary, 13)
        .unwrap();
    let rest = rig
        .channel
        .producer
        .timeline
        .try_reserve(
            EntryClass::Ordinary,
            crate::channel_timeline::ORDINARY_BYTES - 13,
        )
        .unwrap();
    let instance = ChannelInstance::new(1).unwrap();
    rig.channel.producer.deferred = Some(ResizeIntent {
        instance,
        request_id: ResizeRequestId::new(1).unwrap(),
        cols: 80,
        rows: 24,
        origin: rig.channel.producer.origin,
    });
    assert_eq!(
        rig.channel
            .producer
            .timeline
            .register_waiter_and_recheck(instance, 1),
        WaitRegistration::Waiting
    );
    emit_ack(&rig.io, &mut rig.channel);
    drop(small);
    assert!(
        !rig.channel.producer.timeline.take_notification(instance, 1),
        "13 bytes cannot wake a deferred geometry dependency"
    );
    drop(rest);
    assert!(rig.channel.producer.timeline.take_notification(instance, 1));
    resume_producer(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.last_acked, 4);
    assert!(rig.channel.producer.deferred.is_none());
}

#[test]
fn deadlines302_blocked_echo_retries_without_stale_output_or_another_input() {
    let mut rig = ResizeRig::new(false, false);
    let now = tokio::time::Instant::now().into_std();
    rig.channel.input_consumed = 9;
    rig.channel.echo.input(now);
    rig.channel.gate.set_metadata_blocked(true);
    retry_echo(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.echo.deadline(), None);
    assert_eq!(rig.channel.last_acked, 0);
    assert!(!rig.channel.stale);
    rig.channel.gate.set_metadata_blocked(false);
    retry_echo(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.last_acked, 9);
    assert_eq!(rig.channel.echo.deadline(), None);
    let held = rig
        .channel
        .producer
        .timeline
        .try_reserve(
            EntryClass::Ordinary,
            crate::channel_timeline::ORDINARY_BYTES - 13,
        )
        .unwrap();
    rig.channel.input_consumed = 10;
    rig.channel.echo.input(now);
    retry_echo(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.echo.deadline(), None);
    drop(held);
    assert!(rig
        .channel
        .producer
        .timeline
        .take_notification(ChannelInstance::new(1).unwrap(), 1));
    resume_producer(&rig.io, &mut rig.channel);
    assert_eq!(rig.channel.last_acked, 10);
}

struct DeadlineScreen {
    inner: Box<dyn SessionScreen>,
    due: Option<std::time::Instant>,
    calls: Arc<AtomicUsize>,
}
impl SessionScreen for DeadlineScreen {
    fn absorb(&mut self, bytes: &[u8]) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
        self.inner.absorb(bytes)
    }
    fn flush_pending_output(&mut self) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
        self.due = None;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
    fn sync_deadline(&self) -> Option<std::time::Instant> {
        self.due
    }
    fn repaint(
        &mut self,
    ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError> {
        self.inner.repaint()
    }
    fn prepare_resize(
        &mut self,
        size: TerminalSize,
    ) -> Result<
        Box<dyn crate::shell_server::PreparedScreenResize + '_>,
        crate::shell_server::ScreenPreparationError,
    > {
        self.inner.prepare_resize(size)
    }
}
#[test]
fn deadlines302_sync_deadline_is_gate_independent_and_cancels_after_flush_or_eof() {
    let mut rig = ResizeRig::new(false, false);
    let now = tokio::time::Instant::now().into_std();
    let due = now + std::time::Duration::from_millis(10);
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = std::mem::replace(
        &mut rig.channel.screen,
        Box::new(crate::shell_server::NoScreen),
    );
    rig.channel.screen = Box::new(DeadlineScreen {
        inner,
        due: Some(due),
        calls: calls.clone(),
    });
    rig.channel.gate.set_metadata_blocked(true);
    rig.channel.stale = true;
    assert_eq!(channel_deadline(&rig.channel), Some(due));
    flush_due_terminal_output(&rig.io, &mut rig.channel, due);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(channel_deadline(&rig.channel), None);
    rig.channel.echo.input(now);
    assert!(channel_deadline(&rig.channel).is_some());
    rig.channel.producer.eof = true;
    assert_eq!(channel_deadline(&rig.channel), None);
}

#[test]
fn deadlines302_ready_geometry_consumes_latch_but_blocked_ack_retries() {
    let mut rig = ResizeRig::new(false, false);
    rig.channel.input_consumed = 11;
    rig.channel
        .echo
        .input(tokio::time::Instant::now().into_std());
    let held = rig
        .channel
        .producer
        .timeline
        .try_reserve(
            EntryClass::Ordinary,
            crate::channel_timeline::ORDINARY_BYTES,
        )
        .unwrap();
    emit_ack(&rig.io, &mut rig.channel);
    drop(held);
    let instance = ChannelInstance::new(1).unwrap();
    assert_eq!(
        rig.channel
            .producer
            .timeline
            .register_waiter_and_recheck(instance, 1),
        WaitRegistration::Ready
    );
    assert!(
        !rig.channel.producer.timeline.take_notification(instance, 1),
        "a Ready producer can consume the coalesced notification latch"
    );
    let request = ResizeIntent {
        instance,
        request_id: ResizeRequestId::new(1).unwrap(),
        cols: 80,
        rows: 24,
        origin: rig.channel.producer.origin,
    };
    assert!(process_resize(&rig.io, &mut rig.channel, request));
    retry_blocked_echo(&rig.io, &mut rig.channel);
    assert_eq!(
        rig.channel.last_acked, 11,
        "producer progress must hand back ACK ownership without relying on the consumed callback"
    );
}

#[test]
fn deadlines302_forced_repaint_ack_survives_denial_even_at_unchanged_zero_offset() {
    let mut rig = ResizeRig::new(false, false);
    let held = rig.channel.producer.timeline.try_reserve(EntryClass::Ordinary, crate::channel_timeline::ORDINARY_BYTES).unwrap();
    emit_ack(&rig.io, &mut rig.channel); // Repaint owes an unconditional ACK0.
    let retained = rig.channel.echo.blocked();
    drop(held);
    resume_producer(&rig.io, &mut rig.channel);
    let mut acks = 0;
    while let Ok(event) = rig.outbound.try_recv() {
        if matches!(event, SessionOutbound::ChannelOutput { output: crate::session_manager::ChannelOutput::EchoAck(0, _), .. }) { acks += 1; }
    }
    assert!(retained, "forced ACK is an obligation even when the offset did not move");
    assert_eq!(acks, 1);
}
