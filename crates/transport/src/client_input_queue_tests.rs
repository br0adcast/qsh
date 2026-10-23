#[test]
fn client179_record_custody_waits_for_whole_validated_ack() {
    use crate::client_input_budget::ClientInputBudget;
    use crate::client_input_queue::{InputQueue, InputRecord};
    use crate::send_gate::{GateKind, GateTable};
    let (mut client, mut server, _, saddr) = established_pair();
    let budget = ClientInputBudget::default();
    let gates = GateTable::new();
    let mut inputs = InputQueue::default();
    inputs.push(
        30,
        InputRecord::new(b"accepted".to_vec(), budget.reserve(8).unwrap().unwrap()),
    );
    gates.gate(30, GateKind::Pipe).admit(8);
    let now = Instant::now();
    let sent = inputs.drain(&mut client, now, &gates).unwrap();
    assert!(!sent.is_empty());
    // The existing sender clamps an ahead ACK to its actual sent frontier.
    // Custody follows that validated base, never the unbounded claimed value.
    for (ack, still_held) in [(3, true), (3, true), (900, false), (8, false)] {
        let packet = server.packed_for_test(vec![StreamFrame::Ack {
            stream_id: 30,
            cum_ack: ack,
        }]);
        let _ = client.on_datagram(now, saddr, &packet.bytes);
        inputs.acknowledge(&client);
        assert_eq!(
            budget.usage(),
            if still_held { (8, 1, 16) } else { (0, 0, 0) }
        );
    }
}

#[test]
fn client179_unassigned_final_end_keeps_large_source_custody_after_prefix_ack() {
    use crate::client_input_budget::ClientInputBudget;
    use crate::client_input_queue::{InputQueue, InputRecord};
    use crate::send_gate::{GateKind, GateTable};
    let (mut client, mut server, _, saddr) = established_pair();
    let budget = ClientInputBudget::default();
    let gates = GateTable::new();
    let mut inputs = InputQueue::default();
    let length = STREAM_WINDOW as usize + 4096;
    inputs.push(
        30,
        InputRecord::new(vec![7; length], budget.reserve(length).unwrap().unwrap()),
    );
    gates.gate(30, GateKind::Pipe).admit(length as u64);
    let now = Instant::now();
    let sent = inputs.drain(&mut client, now, &gates).unwrap();
    assert!(!sent.is_empty());
    let prefix = client.stream_mut(30).sender.bytes_in_flight();
    assert!(prefix > 0 && prefix < length);
    let packet = server.packed_for_test(vec![StreamFrame::Ack {
        stream_id: 30,
        cum_ack: prefix as u32,
    }]);
    let _ = client.on_datagram(now, saddr, &packet.bytes);
    inputs.acknowledge(&client);
    assert_eq!(budget.usage(), (length, 1, 2 * length));
    // Drop of a real driver owner must destroy reliable storage first. This
    // test has no callback/worker whose completion could substitute for that.
    drop(crate::client_input_queue::DriverConnection {
        connection: client,
        inputs,
    });
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_large_chunks_drain_in_fifo_order_across_real_credit_windows() {
    use crate::client_input_budget::ClientInputBudget;
    use crate::client_input_queue::{DriverConnection, InputQueue, InputRecord};
    use crate::send_gate::{GateKind, GateTable};
    let (client, mut server, caddr, saddr) = established_pair();
    server.set_stream_consumption(30, Consumption::Explicit);
    let mut owner = DriverConnection {
        connection: client,
        inputs: InputQueue::default(),
    };
    let budget = ClientInputBudget::default();
    let gates = GateTable::new();
    let first = vec![1; STREAM_WINDOW as usize + 4096];
    let second = b"next generic/control producer on the same stream".to_vec();
    let expected = [first.as_slice(), second.as_slice()].concat();
    for bytes in [first, second] {
        gates.gate(30, GateKind::Pipe).admit(bytes.len() as u64);
        let permit = budget.reserve(bytes.len()).unwrap().unwrap();
        owner.inputs.push(30, InputRecord::new(bytes, permit));
    }
    let mut received = Vec::new();
    let start = Instant::now();
    for turn in 0..1000 {
        let now = start + Duration::from_millis(turn * 20);
        let mut packets = std::collections::VecDeque::new();
        packets.extend(
            owner
                .inputs
                .drain(&mut owner.connection, now, &gates)
                .unwrap()
                .into_iter()
                .map(|packet| (true, packet)),
        );
        packets.extend(
            owner
                .connection
                .on_timeout(now)
                .into_iter()
                .map(|packet| (true, packet)),
        );
        packets.extend(
            server
                .on_timeout(now)
                .into_iter()
                .map(|packet| (false, packet)),
        );
        let mut work = 0;
        while let Some((to_server, packet)) = packets.pop_front() {
            work += 1;
            assert!(
                work <= 10000,
                "bounded actual packet progress per virtual turn"
            );
            if to_server {
                packets.extend(
                    server
                        .on_datagram(now, caddr, &packet.bytes)
                        .into_iter()
                        .map(|packet| (false, packet)),
                );
                for event in server.poll_events() {
                    if let Event::StreamData {
                        stream_id: 30,
                        data,
                    } = event
                    {
                        received.extend_from_slice(&data);
                        packets.extend(
                            server
                                .on_consumed(now, 30, data.len())
                                .into_iter()
                                .map(|packet| (false, packet)),
                        );
                    }
                }
            } else {
                packets.extend(
                    owner
                        .connection
                        .on_datagram(now, saddr, &packet.bytes)
                        .into_iter()
                        .map(|packet| (true, packet)),
                );
            }
        }
        owner.inputs.acknowledge(&owner.connection);
        if budget.usage() == (0, 0, 0) {
            break;
        }
    }
    let final_usage = budget.usage();
    drop(owner); // actual connection destruction before outcome assertions
    assert_eq!(final_usage, (0, 0, 0), "whole records actually ACKed");
    assert_eq!(
        received, expected,
        "accepted chunks arrive exactly once and in order"
    );
}

#[test]
fn client179_async_offset_failure_is_reported_before_closed_and_teardown_refund() {
    use crate::client_input_budget::ClientInputBudget;
    use crate::client_input_queue::{DriverConnection, InputRecord};
    use crate::driver_std::{ClientEvents, InputFailure};
    use crate::send_gate::GateTable;
    struct Capture {
        budget: ClientInputBudget,
        seen: std::sync::Mutex<Vec<&'static str>>,
    }
    impl ClientEvents for Capture {
        fn on_input_failure(&self, failure: InputFailure) {
            assert_eq!(
                failure,
                InputFailure::OffsetSpaceExhausted { stream_id: 30 }
            );
            assert_eq!(self.budget.usage(), (8, 1, 16));
            self.seen.lock().unwrap().push("input failure");
        }
        fn on_state(&self, state: LinkState) {
            assert_eq!(state, LinkState::Closed);
            assert_eq!(self.budget.usage(), (8, 1, 16));
            self.seen.lock().unwrap().push("closed");
        }
        fn on_bytes(&self, _: u8, _: Vec<u8>) {
            panic!("no input replay");
        }
        fn on_stats(&self, _: Stats) {}
        fn on_reset(&self, _: u8) {}
    }
    let (client, _, _, _) = established_pair();
    let mut owner = DriverConnection {
        connection: client,
        inputs: Default::default(),
    };
    owner.connection.limit_channel_offset_for_test(30, 4);
    let budget = ClientInputBudget::default();
    owner.inputs.push(
        30,
        InputRecord::new(vec![1; 8], budget.reserve(8).unwrap().unwrap()),
    );
    let failure = owner
        .inputs
        .drain(&mut owner.connection, Instant::now(), &GateTable::new())
        .unwrap_err();
    let capture = Capture {
        budget: budget.clone(),
        seen: Default::default(),
    };
    let stop = std::sync::atomic::AtomicU8::new(0);
    crate::driver_std::report_input_failure(&mut owner.connection, &capture, &stop, failure);
    assert_eq!(stop.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(*capture.seen.lock().unwrap(), ["input failure", "closed"]);
    assert_eq!(budget.usage(), (8, 1, 16));
    drop(owner); // callback/Closed alone must not release the accepted debt
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_path_down_is_not_an_ack_refund_or_replay() {
    use crate::client_input_budget::ClientInputBudget;
    use crate::client_input_queue::{DriverConnection, InputRecord};
    use crate::send_gate::GateTable;
    let (client, _, _, _) = established_pair();
    let mut owner = DriverConnection {
        connection: client,
        inputs: Default::default(),
    };
    let budget = ClientInputBudget::with_limits(10, 2);
    owner.inputs.push(
        30,
        InputRecord::new(vec![1; 8], budget.reserve(8).unwrap().unwrap()),
    );
    let now = Instant::now();
    assert!(!owner
        .inputs
        .drain(&mut owner.connection, now, &GateTable::new())
        .unwrap()
        .is_empty());
    let _ = owner
        .connection
        .on_timeout(now + PATH_DOWN_AFTER + Duration::from_millis(1));
    assert_eq!(owner.connection.state(), LinkState::PathDown);
    owner.inputs.acknowledge(&owner.connection);
    assert_eq!(budget.usage(), (8, 1, 16));
    assert!(
        budget.reserve(3).is_err(),
        "replacement owner cannot spend old debt"
    );
    assert!(owner
        .inputs
        .drain(
            &mut owner.connection,
            now + PATH_DOWN_AFTER,
            &GateTable::new()
        )
        .unwrap()
        .is_empty());
    assert_eq!(owner.connection.stream_progress(30).queued, 8);
    drop(owner);
    assert_eq!(budget.usage(), (0, 0, 0));
}
