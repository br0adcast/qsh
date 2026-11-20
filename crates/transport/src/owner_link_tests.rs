use super::*;
use crate::channel_timeline::{
    EntryClass, TimelineBudget, WaitRegistration, BRIDGE_LIFECYCLE_BYTES, GEOMETRY_BYTES,
};
use crate::control_budget::Response;
use crate::send_gate::{GateKind, SCREEN_HIGH};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// An owner backend that hands its io to the test and returns.
struct Capture(Mutex<Option<oneshot::Sender<SessionIo>>>);
impl SessionBackend for Capture {
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let tx = self.0.lock().unwrap().take();
        Box::pin(async move {
            if let Some(tx) = tx {
                let _ = tx.send(io);
            }
        })
    }
}

/// A frontend io (the test plays its bridge) linked to an owner io (the test
/// plays its backend) through the real codec over a loopback pipe.
struct Rig {
    owner: SessionIo,
    /// The bridge's inbound sender: the link's credit sender.
    front_in: Option<CreditSender>,
    front_out: mpsc::UnboundedReceiver<SessionOutbound>,
    front_control: Arc<SessionControl>,
    front_mailbox: channel_bridge::SnapshotMailbox,
    /// Stalls the frontend's writes to its owner while set.
    stalled: Arc<std::sync::atomic::AtomicBool>,
    waker: Arc<Mutex<Option<std::task::Waker>>>,
}

async fn rig() -> Rig {
    let (front, _unused_queue, front_out) = SessionIo::test_pair();
    let lifecycle = front.lifecycle.clone();
    let front_control = front.control().clone();
    let front_mailbox = front.resume_snapshots.clone();
    let (tx, rx) = oneshot::channel();
    let (front_end, owner_end) = loopback();
    let init = OwnerInit {
        principal: front.principal().clone(),
        login: front.login(),
        last_generation: 0,
        lifecycle: Some(lifecycle.clone()),
        relinks: OwnerRelink::default(),
    };
    let backend = Arc::new(Capture(Mutex::new(Some(tx))));
    lifecycle.spawn(async move {
        OwnerLink::run(owner_end, backend, init).await;
    });
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let front_end = Stall {
        inner: front_end,
        stalled: stalled.clone(),
        waker: waker.clone(),
    };
    lifecycle.spawn(start_frontend(front, Box::new(front_end), None, false));
    let front_in = front_control.remote.get().and_then(|r| r.take_inbound());
    assert!(front_in.is_some(), "the link installs the bridge's sender");
    let owner = rx.await.expect("owner io");
    Rig {
        owner,
        front_in,
        front_out,
        front_control,
        front_mailbox,
        stalled,
        waker,
    }
}

fn instance(n: u64) -> ChannelInstance {
    ChannelInstance::new(n).unwrap()
}

async fn eventually(what: &str, done: impl Fn() -> bool) {
    for _ in 0..2000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn next_out(rig: &mut Rig) -> SessionOutbound {
    tokio::time::timeout(Duration::from_secs(2), rig.front_out.recv())
        .await
        .expect("a frontend record")
        .expect("frontend queue open")
}

async fn next_in(owner: &mut SessionIo) -> Option<SessionInbound> {
    tokio::time::timeout(Duration::from_secs(2), owner.recv())
        .await
        .expect("an owner inbound event")
}

/// One screen-or-pipe output with its gap reserve, from the owner's runner.
fn send_output(rig: &Rig, gate: &Arc<SendGate>, budget: &TimelineBudget, output: ChannelOutput) {
    let reserve = budget
        .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
        .expect("gap reserve");
    rig.owner.send_channel_output(
        16,
        instance(1),
        rig.owner.processed_attachment(),
        gate.clone(),
        output,
        Some(reserve),
    );
}

#[tokio::test]
async fn remote_charge_drop_withdraws_on_owner_gate() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let before = gate.pending_for_test();
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![7; 100]));
    // A second outstanding charge on the same gate: a double withdraw of the
    // first would show, rather than saturate at zero.
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![8; 50]));
    assert_eq!(gate.pending_for_test(), before + 105 + 55);
    let SessionOutbound::ChannelOutput {
        position, charge, ..
    } = next_out(&mut rig).await
    else {
        panic!("typed output");
    };
    let other = next_out(&mut rig).await;
    assert_eq!(position, 1, "frontend positions follow the owner's queue");
    assert_eq!(other.channel_position(), Some(2));
    assert!(charge.remote.is_some(), "the frontend holds only a token");
    assert!(charge.gate().is_mirror());
    // The owner keeps the bytes charged while the frontend holds the token.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(gate.pending_for_test(), before + 105 + 55);
    drop(charge);
    eventually("the owner gate's charge to return", || {
        gate.pending_for_test() == before + 55
    })
    .await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        gate.pending_for_test(),
        before + 55,
        "withdrawn exactly once"
    );
    drop(other);
    eventually("the second charge to return", || {
        gate.pending_for_test() == before
    })
    .await;

    // A transferred token moves the owner's bytes to the tail instead.
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![7; 100]));
    let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    assert!(!charge.transfer(105));
    eventually("the transfer to apply", || {
        gate.pending_for_test() == before
    })
    .await;
}

#[tokio::test]
async fn remote_tail_opens_owner_screen_gate_and_injects_writable() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Screen);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    let mirror = charge.gate().clone();
    // The bridge admits the record into a connection whose tail closes it.
    charge.transfer(SCREEN_HIGH);
    eventually("the owner screen gate to close", || !gate.is_open()).await;
    // A mirror never reports an opening itself: its owner does.
    assert!(!mirror.update_scoped(0, Some((1, 0))));
    eventually("the owner screen gate to open", || gate.is_open()).await;
    match next_in(&mut rig.owner).await {
        Some(SessionInbound::Writable { stream: 16 }) => {}
        _ => panic!("the owner injects Writable for its screen gate"),
    }
}

#[tokio::test]
async fn remote_timeline_release_wakes_runner() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let woken = Arc::new(AtomicUsize::new(0));
    let counter = woken.clone();
    let budget = TimelineBudget::new(instance(1), 0, move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let reserve = budget
        .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
        .unwrap();
    let mut held = Vec::new();
    while let Some(permit) = budget.try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES) {
        held.push(permit);
    }
    assert_eq!(
        budget.register_waiter_and_recheck(instance(1), 0),
        WaitRegistration::Waiting
    );
    rig.owner.send_channel_output(
        16,
        instance(1),
        rig.owner.processed_attachment(),
        gate.clone(),
        ChannelOutput::EchoAck(5, held.pop().unwrap()),
        Some(reserve),
    );
    let record = next_out(&mut rig).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(woken.load(Ordering::SeqCst), 0, "the owner still holds it");
    // The bridge retires the item: its permit token releases the real one.
    drop(record);
    eventually("the runner's latched waiter to wake", || {
        woken.load(Ordering::SeqCst) == 1
    })
    .await;
}

#[tokio::test]
async fn remote_update_accept_commits_only_on_reliable_enqueue() {
    let mut rig = rig().await;
    let origin = rig.owner.processed_attachment();
    let part = |owner: &SessionIo| {
        owner
            .control_budget()
            .reserve(Response::Update)
            .ok()
            .map(|permit| permit.into_owner().take_record(6).unwrap())
    };
    let mut receipt = rig.owner.commit_update(origin, part(&rig.owner).unwrap());
    let SessionOutbound::UpdateAccept {
        committed,
        delivery,
        ..
    } = next_out(&mut rig).await
    else {
        panic!("update acceptance");
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        matches!(
            receipt.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "nothing is accepted before the bridge's whole reliable enqueue"
    );
    committed.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), &mut receipt)
        .await
        .expect("commit crosses")
        .expect("accepted");
    // Its reply reservation stays with the owner until the frontend's ledger
    // releases it.
    assert!(part(&rig.owner).is_none());
    drop(delivery);
    eventually("the acceptance part to be released", || {
        part(&rig.owner).is_some()
    })
    .await;

    // An acceptance the bridge drops unsent is not accepted.
    let receipt = rig.owner.commit_update(origin, part(&rig.owner).unwrap());
    drop(next_out(&mut rig).await);
    assert!(tokio::time::timeout(Duration::from_secs(2), receipt)
        .await
        .expect("refusal crosses")
        .is_err());
}

#[tokio::test]
async fn remote_terminal_request_bypasses_snapshot_fence() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let origin = rig.owner.processed_attachment();
    // Ordinary output queues ahead of the request, unread: a bridge fenced by
    // a pending snapshot does not read its backend queue.
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    rig.owner.close_session(origin);
    tokio::time::timeout(
        Duration::from_secs(2),
        rig.front_control.terminal_ready.notified(),
    )
    .await
    .expect("the terminal request reaches the frontend's fixed mailbox");
    assert_eq!(
        rig.front_control.take_priority_abort(),
        Some(TerminalRequest {
            origin,
            disposition: TerminalDisposition::Close,
        })
    );
    // The ordinary alias still waits behind the earlier output.
    assert!(matches!(
        next_out(&mut rig).await,
        SessionOutbound::ChannelOutput { .. }
    ));
    match next_out(&mut rig).await {
        SessionOutbound::CloseSession { origin: alias } => assert_eq!(alias, origin),
        _ => panic!("the alias follows in queue order"),
    }
}

#[tokio::test]
async fn remote_snapshot_never_overtakes_prior_output() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let origin = rig.owner.processed_attachment();
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    let reserve = budget
        .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
        .unwrap();
    rig.owner.send_channel_output(
        16,
        instance(1),
        origin,
        gate.clone(),
        ChannelOutput::EchoAck(1, reserve),
        None,
    );
    assert!(rig
        .owner
        .publish_resume_snapshot(origin, || crate::channel::ChannelSnapshot::new(
            Vec::new(),
            Vec::new()
        )));
    let mut positions = Vec::new();
    let mut records = Vec::new();
    for _ in 0..2 {
        let record = next_out(&mut rig).await;
        positions.push(record.channel_position().unwrap());
        records.push(record);
    }
    assert_eq!(positions, [1, 2]);
    assert!(matches!(
        next_out(&mut rig).await,
        SessionOutbound::ResumeSnapshotReady
    ));
    // The mirror slot holds the owner's prefix: nothing before both records.
    assert!(rig.front_mailbox.take(Some(0), true).is_none());
    rig.front_mailbox.observed(1);
    assert!(rig.front_mailbox.take(Some(0), false).is_none());
    rig.front_mailbox.observed(2);
    assert!(rig.front_mailbox.take(Some(0), false).is_some());
}

#[tokio::test]
async fn remote_latched_snapshot_ahead_of_its_prefix_waits_for_it() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let first = AttachmentContext {
        generation: 1,
        ..AttachmentContext::default()
    };
    let second = AttachmentContext {
        generation: 2,
        ..first
    };
    let empty = || crate::channel::ChannelSnapshot::new(Vec::new(), Vec::new());
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    // The wake queues here, behind one record...
    assert!(rig.owner.publish_resume_snapshot(first, empty));
    let echo = |n| {
        let permit = budget
            .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
            .unwrap();
        rig.owner.send_channel_output(
            16,
            instance(1),
            first,
            gate.clone(),
            ChannelOutput::EchoAck(n, permit),
            None,
        );
    };
    echo(1);
    echo(2);
    // ...and the latched second publication replaces the value with a
    // prefix of three records: its frame crosses before two of them.
    assert!(rig.owner.publish_resume_snapshot(second, empty));
    let mut order = Vec::new();
    for _ in 0..4 {
        order.push(next_out(&mut rig).await.channel_position());
    }
    assert_eq!(order, [Some(1), None, Some(2), Some(3)]);
    assert!(rig.front_mailbox.take(Some(2), true).is_none());
    rig.front_mailbox.observed(1);
    rig.front_mailbox.observed(2);
    assert!(
        rig.front_mailbox.take(Some(2), false).is_none(),
        "the snapshot never overtakes output produced before it"
    );
    rig.front_mailbox.observed(3);
    assert!(rig.front_mailbox.take(Some(2), false).is_some());
}

#[tokio::test]
async fn remote_inbound_crosses_in_order_and_ends_on_frontend_close() {
    let mut rig = rig().await;
    let context = AttachmentContext {
        generation: 3,
        session_id: 9,
        features: crate::Features::CHANNEL_GEOMETRY,
    };
    let big: Vec<u8> = (0..2 * DATA_FRAME_MAX + 10).map(|i| i as u8).collect();
    let sender = rig.front_in.as_ref().unwrap();
    for ev in [
        SessionInbound::Live(context),
        SessionInbound::Data(StreamData {
            stream_id: 16,
            data: big.clone(),
        }),
        SessionInbound::ResumeReset(context),
    ] {
        tokio::time::timeout(Duration::from_secs(2), sender.reserve())
            .await
            .expect("credit")
            .expect("link open")
            .send(ev);
    }
    assert!(matches!(
        next_in(&mut rig.owner).await,
        Some(SessionInbound::Live(c)) if c == context
    ));
    match next_in(&mut rig.owner).await {
        Some(SessionInbound::Data(data)) => {
            assert_eq!(data.stream_id, 16);
            assert_eq!(data.data, big, "one event, joined across frames");
        }
        _ => panic!("stream bytes"),
    }
    assert!(matches!(
        next_in(&mut rig.owner).await,
        Some(SessionInbound::ResumeReset(c)) if c == context
    ));
    assert_eq!(rig.owner.processed_attachment(), context);
    // The bridge dropping its sender ends the owner's backend.
    rig.front_in = None;
    assert!(next_in(&mut rig.owner).await.is_none());
}

#[tokio::test]
async fn remote_records_with_invalid_values_are_link_errors() {
    let (io, _in, _out) = SessionIo::test_pair();
    let (link, _queue) = LinkTx::new();
    let mut front = Frontend {
        io: &io,
        link,
        credits: Arc::new(Credits::default()),
        mirrors: HashMap::new(),
        mirrors_pruned_at: 0,
        data_parts: Vec::new(),
        awaits_replay: false,
        replaying: false,
        finished: false,
    };
    let origin = Ctx {
        generation: 0,
        session_id: 0,
        features: 0,
    };
    let gate = GateWire { id: 0, kind: 1 };
    let output = |output, gate: GateWire| OutRecord::ChannelOutput {
        id: 4,
        stream: 16,
        instance: 1,
        origin,
        output,
        gate,
        gap_reserve: true,
    };
    for record in [
        OutRecord::ChannelClosed {
            id: 0,
            stream: 16,
            instance: 0,
            origin,
        },
        output(OutputBody::OutputGap(9), gate),
        output(OutputBody::Data(vec![1]), GateWire { id: 0, kind: 7 }),
        output(
            OutputBody::Geometry(GeometryWire {
                instance: 1,
                request_id: 1,
                outcome: GeometryOutcomeWire::Refused(99),
                cols: 80,
                rows: 24,
            }),
            gate,
        ),
        OutRecord::ProtocolFailure {
            origin,
            code: Some(77),
        },
        OutRecord::ChannelRefused {
            stream: 16,
            origin,
            reason: vec![0xff, 0xfe],
        },
    ] {
        assert_eq!(front.on_record(record), Err(LinkError::BadValue));
    }
    let mut terminal = Vec::new();
    encode(
        &ToFrontend::Terminal {
            origin,
            disposition: 7,
        },
        &mut terminal,
    )
    .unwrap();
    let frame = FrameReader::new().next(&terminal).unwrap().unwrap();
    assert_eq!(front.on_frame(&frame), Err(LinkError::BadValue));
    // More credit than the owner's whole inbound queue is a protocol error.
    let mut grant = Vec::new();
    encode(
        &ToFrontend::Grant {
            slots: INBOUND_CAP as u32 + 1,
        },
        &mut grant,
    )
    .unwrap();
    let frame = FrameReader::new().next(&grant).unwrap().unwrap();
    assert_eq!(front.on_frame(&frame), Err(LinkError::BadValue));
}

#[tokio::test]
async fn remote_large_data_record_crosses_whole_with_its_charge() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Screen);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    // A screen repaint is one record, larger than one data frame.
    let repaint: Vec<u8> = (0..3 * DATA_FRAME_MAX + 17).map(|i| i as u8).collect();
    send_output(&rig, &gate, &budget, ChannelOutput::Data(repaint.clone()));
    let SessionOutbound::ChannelOutput { output, charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    let ChannelOutput::Data(data) = output else {
        panic!("data");
    };
    assert_eq!(data, repaint);
    assert_eq!(charge.bytes, 5 + repaint.len() as u64);
    // A slice the bridge sends moves those bytes; its next header is charged.
    let mut charge = charge;
    charge.transfer_slice(1000, 1000);
    eventually("the slice to apply", || {
        gate.pending_for_test() == 5 + repaint.len() as u64 - 1000 + 5
    })
    .await;
    drop(charge);
    eventually("the rest to be withdrawn", || gate.pending_for_test() == 0).await;
}

#[tokio::test]
async fn remote_bridge_charges_on_a_mirror_reach_the_owner_gate() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    let mirror = charge.gate().clone();
    drop(charge);
    eventually("the record charge to go", || gate.pending_for_test() == 0).await;
    // A gap record the bridge makes itself, as `channel_bridge::charge` does.
    mirror.admit(14);
    let gap = OutputCharge::admitted(mirror.clone(), 14);
    eventually("the gap charge to count", || gate.pending_for_test() == 14).await;
    assert!(!gap.transfer(300));
    eventually("the gap charge to transfer", || {
        gate.pending_for_test() == 0
    })
    .await;
    mirror.admit(27);
    drop(OutputCharge::admitted(mirror, 27));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        gate.pending_for_test(),
        0,
        "a dropped bridge charge withdraws"
    );
}

#[tokio::test]
async fn remote_progress_wakes_owner_output_ready_through_its_latch() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    let SessionOutbound::ChannelOutput {
        gap_reserve: Some(reserve),
        ..
    } = next_out(&mut rig).await
    else {
        panic!("typed output with its gap reserve");
    };
    // The bridge's stream budget is the owner's: progress crosses, and only
    // the owner's latch decides the wake.
    let remote = reserve.budget();
    assert!(!remote.mark_output_ready(instance(1), 0));
    assert!(!remote.mark_output_ready(instance(1), 0));
    match next_in(&mut rig.owner).await {
        Some(SessionInbound::OutputReady {
            stream: 16,
            instance: i,
            generation: 0,
        }) if i == instance(1) => {}
        _ => panic!("one OutputReady"),
    }
    assert!(budget.take_notification(instance(1), 0));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rig.owner.recv())
            .await
            .is_err(),
        "the latched second progress made no second wake"
    );
}

#[tokio::test]
async fn remote_oversized_admit_is_a_link_error_and_the_gate_survives() {
    for via_gate in [false, true] {
        let mut rig = rig().await;
        let gate = rig.owner.send_gate(16, GateKind::Pipe);
        let budget = TimelineBudget::new(instance(1), 0, |_| {});
        send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
        let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
            panic!("typed output");
        };
        if via_gate {
            // A bridge charge on the mirror: a gate admission by id.
            charge.gate().admit(u64::MAX);
        } else {
            let id = charge.remote.as_ref().unwrap().id;
            rig.front_control
                .remote
                .get()
                .unwrap()
                .send(ToOwner::Charge {
                    id,
                    op: ChargeOp::Slice {
                        n: 1,
                        tail: 0,
                        headers: u64::MAX,
                    },
                });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Nothing was added, the gate's lock is intact. The refused link is
        // a lost one: the output record that had crossed it is given up
        // (never sent twice), and its charge with it.
        assert_eq!(gate.pending_for_test(), 0);
        assert!(gate.is_open());
        // The owner refused the link and parked: later output stays with it.
        send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![2; 10]));
        // (The frontend sees the refused link end; no record crosses.)
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), rig.front_out.recv()).await,
                Ok(Some(_))
            ),
            "via_gate={via_gate}"
        );
        assert_eq!(
            gate.pending_for_test(),
            15,
            "output sent with no link up stays charged"
        );
        drop(charge);
    }
}

#[tokio::test]
async fn remote_link_queue_stays_bounded_when_the_owner_stalls() {
    let (tx, queue) = LinkTx::new();
    // Nothing drains the queue: the owner is not reading.
    for tail in 0..100_000u64 {
        tx.send(ToOwner::Gate {
            gate: 3,
            op: GateOpWire::Update { tail, ready: None },
        });
        tx.send(ToOwner::Progress {
            stream: 16,
            instance: 1,
            generation: tail % 3,
        });
        tx.send(ToOwner::Unconfirmed {
            stream: 16,
            instance: 1,
            unconfirmed: tail % 2 == 0,
        });
        tx.send(ToOwner::Charge {
            id: 8,
            op: ChargeOp::Slice {
                n: 6,
                tail,
                headers: 1,
            },
        });
    }
    let (live, entries) = queue.len();
    assert_eq!(live, 4, "repeated reports and slices fold into one each");
    assert!(entries <= 2 * live + 65, "{entries} entries");
    let mut batch = Vec::new();
    assert!(matches!(
        queue.next_batch(&mut batch).await,
        Batch::Messages
    ));
    assert!(batch.contains(&ToOwner::Gate {
        gate: 3,
        op: GateOpWire::Update {
            tail: 99_999,
            ready: None,
        },
    }));
    assert!(batch.contains(&ToOwner::Charge {
        id: 8,
        op: ChargeOp::Slice {
            n: 600_000,
            tail: 99_999,
            headers: 100_000,
        },
    }));
    // Releases are never dropped: one per custody object.
    for id in 0..100_000u64 {
        tx.send(ToOwner::Released { id });
    }
    tx.send(ToOwner::End(EndKind::Graceful));
    assert_eq!(queue.len().0, 100_001);
}

/// A link end whose writes wait while `stalled` is set.
struct Stall {
    inner: LinkEnd,
    stalled: Arc<std::sync::atomic::AtomicBool>,
    waker: Arc<Mutex<Option<std::task::Waker>>>,
}
impl Stall {
    fn resume(stalled: &std::sync::atomic::AtomicBool, waker: &Mutex<Option<std::task::Waker>>) {
        stalled.store(false, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
    }
    fn hold(&self, cx: &mut std::task::Context<'_>) -> bool {
        if !self.stalled.load(Ordering::SeqCst) {
            return false;
        }
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        // Recheck after registering: a resume in between is not lost.
        self.stalled.load(Ordering::SeqCst)
    }
}
impl AsyncRead for Stall {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stall {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.hold(cx) {
            return std::task::Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.hold(cx) {
            return std::task::Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.hold(cx) {
            return std::task::Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn remote_mass_release_behind_a_stalled_writer_refunds_everything_and_ends() {
    const TOKENS: usize = 70_000;
    let (front, _unused_queue, mut front_out) = SessionIo::test_pair();
    let lifecycle = front.lifecycle.clone();
    let front_control = front.control().clone();
    let (tx, rx) = oneshot::channel();
    let (front_end, owner_end) = loopback();
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let front_end = Stall {
        inner: front_end,
        stalled: stalled.clone(),
        waker: waker.clone(),
    };
    let init = OwnerInit {
        principal: front.principal().clone(),
        login: front.login(),
        last_generation: 0,
        lifecycle: Some(lifecycle.clone()),
        relinks: OwnerRelink::default(),
    };
    let backend = Arc::new(Capture(Mutex::new(Some(tx))));
    lifecycle.spawn(async move {
        OwnerLink::run(owner_end, backend, init).await;
    });
    lifecycle.spawn(start_frontend(front, Box::new(front_end), None, false));
    let sender = front_control.remote.get().unwrap().take_inbound().unwrap();
    let mut owner = rx.await.unwrap();
    let gate = owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    let reserve = budget
        .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
        .unwrap();
    let origin = owner.processed_attachment();
    let mut held = Vec::with_capacity(TOKENS);
    let mut reserve = Some(reserve);
    // Produce in rounds so the owner's queue to the frontend drains.
    for _ in 0..TOKENS / 1000 {
        for _ in 0..1000 {
            owner.send_channel_output(
                16,
                instance(1),
                origin,
                gate.clone(),
                ChannelOutput::Data(vec![1]),
                reserve.take(),
            );
        }
        for _ in 0..1000 {
            held.push(
                tokio::time::timeout(Duration::from_secs(5), front_out.recv())
                    .await
                    .expect("record")
                    .expect("open"),
            );
        }
    }
    assert_eq!(gate.pending_for_test(), 6 * TOKENS as u64);
    // The writer stalls; the bridge tears down at once: more releases than
    // any fixed bound, then the end of input, all in one synchronous burst.
    stalled.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(held);
    drop(sender);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        gate.pending_for_test(),
        6 * TOKENS as u64,
        "the owner waits"
    );
    Stall::resume(&stalled, &waker);
    eventually("every charge to be refunded", || {
        gate.pending_for_test() == 0
    })
    .await;
    // The queued end of input arrived: the session ends gracefully.
    assert!(next_in(&mut owner).await.is_none());
}

#[tokio::test]
async fn remote_owner_keeps_custody_after_its_backend_ends() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![2; 10]));
    let first = next_out(&mut rig).await;
    let second = next_out(&mut rig).await;
    // The backend ends; the frontend still holds both records.
    drop(rig.owner);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gate.pending_for_test(), 30, "custody outlives the backend");
    assert_eq!(budget.usage(EntryClass::Lifecycle).0, 2);
    // Each release still reaches the owner...
    drop(first);
    eventually("the first record's release", || {
        gate.pending_for_test() == 15
    })
    .await;
    assert_eq!(budget.usage(EntryClass::Lifecycle).0, 1);
    // ...and the link's end releases the rest.
    drop(second);
    drop(rig.front_in);
    drop(rig.front_control);
    drop(rig.front_mailbox);
    drop(rig.front_out);
    eventually("the link's end to release everything", || {
        gate.pending_for_test() == 0 && budget.usage(EntryClass::Lifecycle).0 == 0
    })
    .await;
}

#[tokio::test]
async fn remote_commit_for_another_custody_keeps_it() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Pipe);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    // A geometry record: unlike output bytes, it stays the owner's after
    // the link the bad frame costs.
    let permit = budget
        .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
        .unwrap();
    let geometry = GeometryRecord {
        instance: instance(1),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: 80,
        rows: 24,
    };
    send_output(
        &rig,
        &gate,
        &budget,
        ChannelOutput::Geometry(geometry, permit),
    );
    // The record's permits stay held: the bridge has not retired it.
    let SessionOutbound::ChannelOutput {
        charge,
        output: _output,
        gap_reserve: _reserve,
        ..
    } = next_out(&mut rig).await
    else {
        panic!("typed output");
    };
    let id = charge.remote.as_ref().unwrap().id;
    rig.front_control
        .remote
        .get()
        .unwrap()
        .send(ToOwner::Committed { id });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(gate.pending_for_test(), 27, "the charge was not dropped");
    drop(charge);
}

/// A link whose every write fails.
struct BrokenWrite;
impl AsyncWrite for BrokenWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn remote_write_failure_is_seen_and_ends_the_link() {
    let lifecycle = Arc::new(Lifecycle::default());
    let (tx, queue) = LinkTx::new();
    let failure = Arc::new(LinkFailure::default());
    tx.send(ToOwner::Released { id: 1 });
    frontend_write_loop(
        BrokenWrite,
        queue.clone(),
        failure.clone(),
        lifecycle.clone(),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), failure.failed())
        .await
        .expect("the frontend's reader hears of it");
    tx.send(ToOwner::Released { id: 2 });
    assert_eq!(queue.len(), (0, 0), "nothing queues into a failed link");

    let (data, data_rx) = mpsc::unbounded_channel();
    let (_priority, priority_rx) = mpsc::unbounded_channel();
    let failure = Arc::new(LinkFailure::default());
    data.send(ToFrontend::Grant { slots: 1 }).unwrap();
    owner_write_loop(
        BrokenWrite,
        data_rx,
        priority_rx,
        failure.clone(),
        lifecycle,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), failure.failed())
        .await
        .expect("the owner hears of it and parks");
}

#[tokio::test]
async fn remote_charge_transfer_refreshes_the_mirror_tail() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Screen);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 10]));
    let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    let mirror = charge.gate().clone();
    mirror.update_scoped(0, None);
    // The token's transfer moves the owner gate's tail, closing it...
    charge.transfer(SCREEN_HIGH);
    eventually("the owner screen gate to close", || !gate.is_open()).await;
    // ...so the same tail as before is news again, and must cross.
    mirror.update_scoped(0, None);
    eventually("the owner screen gate to open", || gate.is_open()).await;
}

/// Stall the rig's frontend writer with one frame in flight, so every later
/// message waits in (and folds within) the frontend's queue.
async fn stall_writer(rig: &Rig) {
    rig.stalled.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(20)).await;
    rig.front_control
        .remote
        .get()
        .unwrap()
        .send(ToOwner::Liveness {
            last_client_recv: 1,
        });
    tokio::time::sleep(Duration::from_millis(20)).await;
}

#[tokio::test]
async fn remote_merged_slices_apply_on_the_owner_and_refund_exactly() {
    let mut rig = rig().await;
    let gate = rig.owner.send_gate(16, GateKind::Screen);
    let budget = TimelineBudget::new(instance(1), 0, |_| {});
    // 20 payload bytes: a 25-byte charge on both sides.
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 20]));
    let SessionOutbound::ChannelOutput { mut charge, .. } = next_out(&mut rig).await else {
        panic!("typed output");
    };
    assert_eq!(gate.pending_for_test(), 25);
    stall_writer(&rig).await;
    // Three real slices (8, 8 and 3 payload bytes), each giving back a header:
    // the frontend's charge goes 25 -> 17 -> 9 -> 6, and they merge into one
    // Slice{n: 34, headers: 3}, more than the 25 bytes the owner charged.
    for n in [13, 13, 8] {
        charge.transfer_slice(n, 0);
    }
    assert_eq!(charge.bytes, 6);
    Stall::resume(&rig.stalled, &rig.waker);
    eventually("the merged slices to apply", || {
        gate.pending_for_test() == 6
    })
    .await;
    // The owner stayed linked: later output still crosses, and the final
    // transfer refunds exactly the rest.
    assert!(!charge.transfer(0));
    eventually("the final transfer", || gate.pending_for_test() == 0).await;
    send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![2; 10]));
    assert!(matches!(
        next_out(&mut rig).await,
        SessionOutbound::ChannelOutput { .. }
    ));
}

#[tokio::test]
async fn remote_inflating_slices_are_link_errors_and_the_gate_survives() {
    for (n, headers) in [(25, 25), (5, 1), (12, 3), (30, 1), (6, 0)] {
        let mut rig = rig().await;
        let gate = rig.owner.send_gate(16, GateKind::Pipe);
        let budget = TimelineBudget::new(instance(1), 0, |_| {});
        send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![1; 20]));
        let SessionOutbound::ChannelOutput { charge, .. } = next_out(&mut rig).await else {
            panic!("typed output");
        };
        let id = charge.remote.as_ref().unwrap().id;
        let link = rig.front_control.remote.get().unwrap().state().link.clone();
        // Repeated, an inflating slice would multiply the charge.
        for _ in 0..3 {
            link.send(ToOwner::Charge {
                id,
                op: ChargeOp::Slice {
                    n,
                    tail: 0,
                    headers,
                },
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Nothing was multiplied: the record that crossed the refused
        // (lost) link is given up, and its whole charge returns.
        assert_eq!(
            gate.pending_for_test(),
            0,
            "Slice{{n: {n}, headers: {headers}}}"
        );
        send_output(&rig, &gate, &budget, ChannelOutput::Data(vec![2; 10]));
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), rig.front_out.recv()).await,
                Ok(Some(_))
            ),
            "the owner parked on Slice{{n: {n}, headers: {headers}}}"
        );
        drop(charge);
    }
}

/// An owner process's session runs within one control budget envelope,
/// which its host leases to it, not a daemon's whole budget (#529).
#[tokio::test]
async fn an_owner_process_session_runs_within_one_envelope() {
    let (front, _queue, _out) = SessionIo::test_pair();
    let (tx, rx) = oneshot::channel();
    let (front_end, owner_end) = loopback();
    let shutdown = Shutdown::default();
    let run = tokio::spawn(OwnerLink::run_and_drain(
        owner_end,
        Arc::new(Capture(Mutex::new(Some(tx)))),
        OwnerInit::new(front.principal().clone(), front.login()),
        shutdown.clone(),
        Duration::from_secs(10),
    ));
    let owner = rx.await.expect("owner io");
    assert!(owner.global_control_budget().is_envelope_for_test());
    assert!(!front.global_control_budget().is_envelope_for_test());
    drop((owner, front_end));
    shutdown.request();
    run.await.unwrap();
}

/// A worker blocked for good does not hold an owner's drain forever: the
/// drain is given up on after its bound, as a failure (#529).
#[tokio::test]
async fn an_owner_drain_gives_up_on_a_worker_that_never_returns() {
    struct Blocked(Mutex<Option<std::sync::mpsc::Receiver<()>>>);
    impl SessionBackend for Blocked {
        fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            let held = self.0.lock().unwrap().take().unwrap();
            let _receipt = io.spawn_blocking_owned(move || {
                let _ = held.recv();
            });
            Box::pin(async move {
                std::future::pending::<()>().await;
                drop(io);
            })
        }
    }
    let (front, _queue, _out) = SessionIo::test_pair();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (_front_end, owner_end) = loopback();
    let shutdown = Shutdown::default();
    let run = tokio::spawn(OwnerLink::run_and_drain(
        owner_end,
        Arc::new(Blocked(Mutex::new(Some(held)))),
        OwnerInit::new(front.principal().clone(), front.login()),
        shutdown.clone(),
        Duration::from_millis(200),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown.request();
    let outcome = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .expect("the drain is bounded")
        .unwrap();
    assert_eq!(outcome.exit, OwnerExit::Shutdown);
    let error = outcome
        .drained
        .expect_err("an unjoined worker is a failed drain");
    assert!(error.to_string().contains("within"), "{error}");
    let _ = release.send(());
}
