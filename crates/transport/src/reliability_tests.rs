use super::*;

fn both_wrapping() -> Features {
    Features::HEADER_AAD | Features::OFFSET_WRAP
}

#[test]
fn bounded_write_room_stops_at_full_offset_limit_and_counts_queued_credit() {
    let mut sender = StreamSender::new(16);
    sender.set_features(Features::OFFSET_WRAP);
    sender.base_offset = FULL_OFFSET_MAX - 7;
    sender.sent_up_to = sender.base_offset;
    assert_eq!(sender.write_room(100), 7);
    sender.push(b"123").unwrap();
    assert_eq!(sender.write_room(100), 4);
    sender.credit_limit = Some(FULL_OFFSET_MAX - 1);
    assert_eq!(sender.write_room(100), 3);
    assert_eq!(sender.write_room(5), 2);
    sender.credit_limit = Some(FULL_OFFSET_MAX - 10);
    assert_eq!(sender.write_room(100), 0);
    sender.mark_desynced();
    assert_eq!(sender.write_room(100), 0);
}

/// Spec §4.14: a 32-bit field names the full offset nearest where its
/// reader stands -- across 2^32 either way, never below zero -- and,
/// without `offset-wrap`, the field itself.
#[test]
fn a_wire_offset_names_the_nearest_full_offset() {
    const EDGE: u64 = 1 << 32;
    assert_eq!(expand(0, 5, true), Some(5));
    assert_eq!(
        expand(EDGE - 10, 3, true),
        Some(EDGE + 3),
        "just past the edge"
    );
    assert_eq!(
        expand(EDGE + 3, u32::MAX - 9, true),
        Some(EDGE - 10),
        "just behind it"
    );
    assert_eq!(expand(5, u32::MAX - 15, true), None, "below zero");
    let x = 3 * EDGE + 100;
    let ahead = (x as u32).wrapping_add((1 << 31) - 1);
    assert_eq!(expand(x, ahead, true), Some(x + (1 << 31) - 1));
    let halfway = (x as u32).wrapping_add(1 << 31);
    assert_eq!(
        expand(x, halfway, true),
        Some(x - (1 << 31)),
        "exactly 2^31 away reads as behind"
    );
    assert_eq!(expand(EDGE + 3, 7, false), Some(7), "without offset-wrap");
}

/// Spec §4.14: with `offset-wrap` a stream goes on past 2^32. The
/// sender's offsets are full ones, the wire carries their low 32 bits,
/// and the receiver and the sender's ACK handling read them back.
#[test]
fn a_stream_with_offset_wrap_crosses_2_pow_32() {
    let start = u32::MAX - 3 * 1024 + 1; // 3 KiB short of 2^32
    let mut tx = StreamSender::starting_at(7, start);
    let mut rx = StreamReceiver::starting_at(7, start);
    tx.set_features(both_wrapping());
    rx.set_features(both_wrapping());
    let data: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
    tx.push(&data).expect("no edge with offset-wrap");
    let mut got = Vec::new();
    for f in tx.frames_to_send(Instant::now(), Duration::from_secs(1)) {
        if let StreamFrame::Data { offset, data, .. } = f {
            got.extend(rx.on_data(offset, data));
        }
    }
    assert_eq!(got, data);
    assert_eq!(rx.next_offset(), u64::from(start) + data.len() as u64);
    assert!(rx.next_offset() > 1 << 32);
    assert!(
        tx.on_ack(rx.ack()),
        "the ACK's low 32 bits move the base across"
    );
    assert_eq!(tx.base_offset(), rx.next_offset());
    assert_eq!(tx.bytes_in_flight(), 0);
}

/// A `Reset` past 2^32 moves a receiver that still stands below it.
#[test]
fn a_reset_past_2_pow_32_moves_a_receiver_below_it() {
    let start = u32::MAX - 1023;
    let mut rx = StreamReceiver::starting_at(0, start);
    rx.set_features(both_wrapping());
    let target = u64::from(start) + 64 * 1024;
    assert!(rx.on_reset(target as u32));
    assert_eq!(rx.next_offset(), target);
    assert_eq!(rx.on_data(target as u32, b"after".to_vec()), b"after");
}

/// Spec §4.14: without `offset-wrap` -- a peer built before it -- the
/// edge stays where slice 1 put it.
#[test]
fn without_offset_wrap_the_limit_still_stands() {
    let mut tx = StreamSender::starting_at(0, OFFSET_LIMIT - 4);
    tx.set_features(Features::HEADER_AAD);
    assert_eq!(tx.push(b"abcde"), Err(OffsetSpaceExhausted));
    tx.set_features(both_wrapping());
    tx.push(b"abcde")
        .expect("with offset-wrap there is no limit");
}

/// Spec §4.14: with `offset-wrap` a `Reset` is taken as far as a field
/// can name -- the tails of several resyncs whose `Reset`s were lost add
/// up, and refusing one would stall the stream for good -- and crafted
/// ones of 2^31 - 1 each walk the point no farther than
/// `FULL_OFFSET_MAX`.
#[test]
fn with_offset_wrap_a_reset_as_far_as_a_field_names_is_taken() {
    let mut rx = StreamReceiver::new(20);
    rx.set_features(both_wrapping());
    assert_eq!(rx.on_data(0, vec![1u8; 10]).len(), 10);
    let farthest = (1u64 << 31) - 1;
    assert!(
        rx.on_reset((10 + farthest) as u32),
        "2^31 - 1 past the point"
    );
    assert_eq!(rx.next_offset(), 10 + farthest);
    rx.next_offset = FULL_OFFSET_MAX - 3 * farthest;
    let mut walked = 0;
    while rx.on_reset((rx.next_offset() + farthest) as u32) {
        walked += 1;
        assert!(walked <= 3, "past the last full offset");
    }
    assert_eq!(walked, 3);
    assert_eq!(rx.next_offset(), FULL_OFFSET_MAX);
    assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
}

/// Without `offset-wrap` a `Reset` jumps as far as it says, within the
/// 32-bit space.
#[test]
fn without_offset_wrap_a_reset_may_jump_as_far_as_it_says() {
    let mut rx = StreamReceiver::new(0);
    let far = 512 * 1024 * 1024;
    assert!(rx.on_reset(far as u32));
    assert_eq!(rx.next_offset(), far);
}

/// A `Reset` keeps exactly the chunks that start at or past its offset
/// -- one that starts below it and reaches past is dropped too -- and
/// gives back exactly what the dropped ones cost.
#[test]
fn a_reset_keeps_exactly_the_chunks_at_or_past_its_offset() {
    let mut rx = StreamReceiver::new(0);
    for (offset, len) in [
        (100u32, 50usize),
        (900, 200),
        (1000, 10),
        (1005, 1),
        (4000, 30),
    ] {
        let _ = rx.on_data(offset, vec![1u8; len]);
    }
    assert!(rx.on_reset(1000));
    let kept: Vec<(u64, usize)> = rx.buffered.iter().map(|(o, c)| (*o, c.len())).collect();
    assert_eq!(kept, vec![(1000, 10), (1005, 1), (4000, 30)]);
    assert_eq!(rx.buffered_cost(), 41 + 3 * CHUNK_COST);
    assert!(rx.on_reset(5000), "past every chunk");
    assert!(rx.buffered.is_empty());
    assert_eq!(rx.buffered_cost(), 0);
}

/// Spec §4.14: with `offset-wrap` a receiver takes nothing past
/// `FULL_OFFSET_MAX` -- neither a `Reset` nor `DATA` -- so every sum of an
/// offset and a length it forms stays far from the end of `u64`.
#[test]
fn with_offset_wrap_nothing_past_the_last_full_offset_is_taken() {
    let mut rx = StreamReceiver::new(20);
    rx.set_features(both_wrapping());
    rx.next_offset = FULL_OFFSET_MAX - 8;
    assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
    assert_eq!(rx.next_offset(), FULL_OFFSET_MAX - 8);
    assert_eq!(
        rx.on_data((FULL_OFFSET_MAX - 8) as u32, vec![1u8; 8]),
        vec![1u8; 8],
        "up to the last offset"
    );
    assert!(rx.on_data(FULL_OFFSET_MAX as u32, vec![1u8]).is_empty());
    assert!(rx
        .on_data((FULL_OFFSET_MAX + 1000) as u32, vec![1u8; 10])
        .is_empty());
    assert!(!rx.on_reset((FULL_OFFSET_MAX + 1) as u32));
    assert_eq!(rx.next_offset(), FULL_OFFSET_MAX);
    assert_eq!(
        rx.ack(),
        FULL_OFFSET_MAX as u32,
        "nothing past it acknowledged"
    );
    // The farthest a field can name, with the longest payload a frame
    // carries: dropped, and nothing overflows.
    let farthest = (FULL_OFFSET_MAX + (1 << 31) - 1) as u32;
    assert!(rx
        .on_data(farthest, vec![1u8; u16::MAX as usize])
        .is_empty());
}

/// The numbers themselves, pinned: `CHUNK_COST` is a measurement (see
/// its doc), and every test that exercises it scales by the constant.
/// A window of full segments is what a stream may hold.
#[test]
fn the_chunk_cost_is_the_measured_one_and_a_window_of_segments_fits() {
    assert_eq!(CHUNK_COST, 128);
    let rx = StreamReceiver::new(20);
    let segments = LEGACY_RECEIVE_WINDOW as usize / MAX_SEGMENT_SIZE;
    assert_eq!(rx.cost_cap(), segments * (MAX_SEGMENT_SIZE + CHUNK_COST));
}

/// Spec §4.16 (QSH-01): without credits a receiver keeps nothing past
/// the window every such sender stays in -- `LEGACY_RECEIVE_WINDOW` past
/// its cumulative point. Such DATA is neither kept nor acknowledged.
#[test]
fn data_past_the_legacy_window_is_neither_kept_nor_acknowledged() {
    let mut rx = StreamReceiver::new(20);
    assert!(rx
        .on_data(LEGACY_RECEIVE_WINDOW as u32, vec![1u8; 10])
        .is_empty());
    assert_eq!(rx.buffered_cost(), 0);
    assert_eq!(rx.ack(), 0);
}

/// The same with `offset-wrap`, as far ahead as a field can name.
#[test]
fn with_offset_wrap_data_as_far_ahead_as_a_field_names_is_dropped() {
    let mut rx = StreamReceiver::new(20);
    rx.set_features(both_wrapping());
    for offset in [LEGACY_RECEIVE_WINDOW as u32, 1 << 20, u32::MAX >> 1] {
        assert!(rx.on_data(offset, vec![1u8; u16::MAX as usize]).is_empty());
    }
    assert_eq!(rx.buffered_cost(), 0);
    assert_eq!(rx.ack(), 0);
}

/// A chunk across the window's edge keeps what lies inside it.
#[test]
fn a_chunk_across_the_window_keeps_what_fits() {
    let mut rx = StreamReceiver::new(20);
    let edge = LEGACY_RECEIVE_WINDOW as u32;
    assert!(
        rx.on_data(edge - 4, vec![7u8; 10]).is_empty(),
        "out of order"
    );
    assert_eq!(rx.buffered_cost(), 4 + CHUNK_COST);
    let mut got = Vec::new();
    let mut at = 0u32;
    while at < edge - 4 {
        let len = (edge - 4 - at).min(1024);
        got.extend(rx.on_data(at, vec![1u8; len as usize]));
        at += len;
    }
    assert_eq!(
        got.len() as u64,
        LEGACY_RECEIVE_WINDOW,
        "up to the edge, the kept tail included"
    );
    assert_eq!(rx.buffered_cost(), 0);
}

/// Spec §4.16: what a receiver keeps is counted by cost, not payload --
/// one-byte chunks at every other offset of the window cost no more
/// than `cost_cap`, and fewer than one chunk per `1 + CHUNK_COST` of it.
#[test]
fn one_byte_chunks_cost_no_more_than_the_cap() {
    let mut rx = StreamReceiver::new(20);
    for i in 0..40_000u32 {
        let _ = rx.on_data(1 + 2 * i, vec![0xEE]);
    }
    assert!(
        rx.buffered_cost() <= rx.cost_cap(),
        "{} > {}",
        rx.buffered_cost(),
        rx.cost_cap()
    );
    assert!(rx.buffered.len() <= rx.cost_cap() / (1 + CHUNK_COST));
    // The same chunks again, and longer ones on the same offsets: no growth past the cap.
    for i in 0..40_000u32 {
        let _ = rx.on_data(1 + 2 * i, vec![0xEE; 2]);
    }
    assert!(rx.buffered_cost() <= rx.cost_cap());
}

/// Spec §4.16: chunks that overlap one another -- a segment's length at
/// every offset -- cost no more than the cap either, and the bytes they
/// hold still assemble into the stream exactly.
#[test]
fn overlapping_chunks_cost_no_more_than_the_cap_and_assemble_exactly() {
    fn byte_at(offset: u32) -> u8 {
        (offset % 251) as u8
    }
    let mut rx = StreamReceiver::new(20);
    for offset in 1..5_000u32 {
        let chunk = (offset..offset + 1024).map(byte_at).collect();
        let _ = rx.on_data(offset, chunk);
    }
    assert!(rx.buffered_cost() <= rx.cost_cap());
    let kept = rx.buffered.len();
    assert_eq!(kept, rx.cost_cap() / (1024 + CHUNK_COST));
    let got = rx.on_data(0, vec![byte_at(0)]);
    let expected: Vec<u8> = (0..kept as u32 + 1024).map(byte_at).collect();
    assert_eq!(got, expected);
    assert_eq!(rx.buffered_cost(), 0);
}

/// In-order bytes are delivered whatever the buffer holds: a full buffer
/// never stalls the stream.
#[test]
fn in_order_bytes_are_delivered_even_with_the_buffer_full() {
    let mut rx = StreamReceiver::new(20);
    for i in 0..40_000u32 {
        let _ = rx.on_data(1 + 2 * i, vec![0xEE]);
    }
    let full = rx.buffered_cost();
    assert_eq!(
        rx.on_data(0, vec![0xAA]),
        vec![0xAA, 0xEE],
        "the hole and the byte kept after it"
    );
    assert!(rx.buffered_cost() < full);
}

/// The connection's room bounds what one stream may keep.
#[test]
fn the_connections_room_bounds_what_a_stream_keeps() {
    let mut rx = StreamReceiver::new(20);
    assert!(rx
        .on_data_within(1000, vec![1u8; 100], 100 + CHUNK_COST - 1)
        .is_empty());
    assert_eq!(rx.buffered_cost(), 0, "no room: dropped");
    assert!(rx
        .on_data_within(1000, vec![1u8; 100], 100 + CHUNK_COST)
        .is_empty());
    assert_eq!(rx.buffered_cost(), 100 + CHUNK_COST);
}

/// A chunk a `Reset` lands on is delivered with the next DATA, whatever
/// that DATA is -- as before the receiver had bounds.
#[test]
fn a_chunk_a_reset_lands_on_is_delivered_with_the_next_data() {
    let mut rx = StreamReceiver::new(0);
    assert!(rx.on_data(1000, b"abc".to_vec()).is_empty());
    assert!(rx.on_reset(1000));
    assert_eq!(rx.on_data(5000, b"x".to_vec()), b"abc", "out of order");
    assert_eq!(rx.buffered_cost(), 1 + CHUNK_COST);
    assert!(rx.on_data(3000, b"y".to_vec()).is_empty());
    assert!(rx.on_reset(3000));
    assert_eq!(rx.on_data(0, b"old".to_vec()), b"y", "a repeat");
    // With `offset-wrap`, even a field that names an offset below zero.
    let mut rx = StreamReceiver::new(0);
    rx.set_features(both_wrapping());
    assert!(rx.on_data(1000, b"abc".to_vec()).is_empty());
    assert!(rx.on_reset(1000));
    let below_zero = 1000u32.wrapping_sub(2000);
    assert_eq!(rx.on_data(below_zero, b"x".to_vec()), b"abc");
}

/// A `Reset` gives back the cost of what it drops.
#[test]
fn a_reset_gives_back_what_it_drops() {
    let mut rx = StreamReceiver::new(0);
    let _ = rx.on_data(100, vec![1u8; 50]);
    let _ = rx.on_data(5000, vec![1u8; 50]);
    assert!(rx.on_reset(1000));
    assert_eq!(
        rx.buffered_cost(),
        50 + CHUNK_COST,
        "the chunk past the new point stays"
    );
}

/// Spec §4.16 under any chunking a peer picks -- tiny, overlapping,
/// repeated, behind, ahead, past the window, `Reset`s among them, the
/// connection's room coming and going: what is kept costs exactly its
/// bytes plus `CHUNK_COST` a chunk, lies inside the window, never costs
/// more than the cap and never grows by more than the room; every byte
/// delivered is the stream's byte at its offset.
#[test]
fn under_any_chunking_the_cost_is_what_is_kept_and_delivery_is_exact() {
    fn byte_at(offset: u64) -> u8 {
        (offset % 251) as u8
    }
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for wrap in [false, true] {
        let mut rx = StreamReceiver::new(20);
        if wrap {
            rx.set_features(both_wrapping());
        }
        for _ in 0..20_000 {
            let point = rx.next_offset();
            let before = rx.buffered_cost();
            if next(20) == 0 {
                let to = point + next(4096);
                // What the chunks were before a `Reset` split them off:
                // exactly those at or past its offset stay.
                let mut expected = rx.buffered.clone();
                if to > point {
                    expected.retain(|off, _| *off >= to);
                }
                assert_eq!(rx.on_reset(to as u32), to > point);
                assert_eq!(rx.next_offset(), to.max(point));
                assert_eq!(rx.buffered, expected);
            } else {
                let start = (point + next(LEGACY_RECEIVE_WINDOW + 8192)).saturating_sub(4096);
                let longest = if next(2) == 0 { 8 } else { 1500 };
                let len = 1 + next(longest);
                let data = (start..start + len).map(byte_at).collect();
                let room = if next(4) == 0 {
                    next(4096) as usize
                } else {
                    usize::MAX
                };
                let got = rx.on_data_within(start as u32, data, room);
                for (i, b) in got.iter().enumerate() {
                    assert_eq!(*b, byte_at(point + i as u64), "byte {}", point + i as u64);
                }
                assert_eq!(rx.next_offset(), point + got.len() as u64);
                if rx.buffered_cost() > before {
                    assert!(rx.buffered_cost() - before <= room);
                }
            }
            let held: usize = rx.buffered.values().map(|c| c.len() + CHUNK_COST).sum();
            assert_eq!(rx.buffered_cost(), held);
            assert!(held <= rx.cost_cap());
            // A chunk may sit at the point itself: one a `Reset` landed
            // on waits for the next DATA to drain it.
            let (point, limit) = (rx.next_offset(), rx.accept_limit());
            assert!(rx
                .buffered
                .iter()
                .all(|(off, c)| *off >= point && off + c.len() as u64 <= limit));
        }
    }
}

#[test]
fn frames_codec_roundtrip() {
    let mut buf = Vec::new();
    StreamFrame::Data {
        stream_id: 0,
        offset: 4,
        data: vec![1, 2, 3],
    }
    .encode(&mut buf);
    StreamFrame::Ack {
        stream_id: 0,
        cum_ack: 7,
    }
    .encode(&mut buf);
    let out = StreamFrame::decode_all(&buf);
    assert_eq!(out.len(), 2);
}

#[test]
fn reliable_in_order_delivery() {
    let mut tx = StreamSender::new(0);
    let mut rx = StreamReceiver::new(0);
    tx.push(b"hello ").expect("room in the offset space");
    tx.push(b"world").expect("room in the offset space");
    let rto = Duration::from_millis(500);
    let now = Instant::now();
    let mut delivered = Vec::new();
    for f in tx.frames_to_send(now, rto) {
        if let StreamFrame::Data { offset, data, .. } = f {
            delivered.extend(rx.on_data(offset, data));
        }
    }
    assert_eq!(delivered, b"hello world");
    tx.on_ack(rx.ack());
    assert_eq!(tx.bytes_in_flight(), 0);
}

#[test]
fn retransmits_on_loss() {
    let mut tx = StreamSender::new(0);
    let mut rx = StreamReceiver::new(0);
    tx.push(b"abcdef").expect("room in the offset space");
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let first = tx.frames_to_send(t0, rto); // sent, "lost"
    assert!(!first.is_empty());
    // before RTO -- nothing new
    assert!(tx
        .frames_to_send(t0 + Duration::from_millis(100), rto)
        .is_empty());
    // after RTO -- retransmit
    let again = tx.frames_to_send(t0 + Duration::from_millis(600), rto);
    assert!(!again.is_empty());
    // deliver the retransmit -- data is intact, in order
    let mut got = Vec::new();
    for f in again {
        if let StreamFrame::Data { offset, data, .. } = f {
            got.extend(rx.on_data(offset, data));
        }
    }
    assert_eq!(got, b"abcdef");
}

#[test]
fn out_of_order_buffered() {
    let mut rx = StreamReceiver::new(0);
    assert_eq!(rx.on_data(3, vec![b'd']), Vec::<u8>::new()); // gap -- hold it
    assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), b"abcd");
    assert_eq!(rx.ack(), 4);
}

#[test]
fn codec_all_frame_kinds_roundtrip() {
    let mut buf = Vec::new();
    StreamFrame::Ack {
        stream_id: 1,
        cum_ack: 0xDEAD_BEEF,
    }
    .encode(&mut buf);
    StreamFrame::Data {
        stream_id: 2,
        offset: 9,
        data: vec![7, 8, 9, 10],
    }
    .encode(&mut buf);
    StreamFrame::Ping { token: 42 }.encode(&mut buf);
    StreamFrame::Pong { token: 42 }.encode(&mut buf);
    StreamFrame::Close { stream_id: 3 }.encode(&mut buf);
    let out = StreamFrame::decode_all(&buf);
    assert_eq!(
        out,
        vec![
            StreamFrame::Ack {
                stream_id: 1,
                cum_ack: 0xDEAD_BEEF,
            },
            StreamFrame::Data {
                stream_id: 2,
                offset: 9,
                data: vec![7, 8, 9, 10],
            },
            StreamFrame::Ping { token: 42 },
            StreamFrame::Pong { token: 42 },
            StreamFrame::Close { stream_id: 3 },
        ]
    );
}

#[test]
fn decode_stops_on_truncated_frame() {
    // A full ACK, then a truncated DATA (header promises 3 bytes, only 1 given).
    let mut buf = Vec::new();
    StreamFrame::Ack {
        stream_id: 0,
        cum_ack: 5,
    }
    .encode(&mut buf);
    buf.extend_from_slice(&[TYPE_DATA, 0, 0, 0, 0, 0, 0, 3, 0xAA]);
    let out = StreamFrame::decode_all(&buf);
    // Only the full ACK got parsed, the truncated DATA is dropped without a panic.
    assert_eq!(
        out,
        vec![StreamFrame::Ack {
            stream_id: 0,
            cum_ack: 5,
        }]
    );
}

#[test]
fn decode_stops_on_unknown_type() {
    let mut buf = Vec::new();
    StreamFrame::Ping { token: 1 }.encode(&mut buf);
    buf.push(0x7F); // unknown type -- parsing stops here
    buf.extend_from_slice(&[0, 0, 0, 0]);
    let out = StreamFrame::decode_all(&buf);
    assert_eq!(out, vec![StreamFrame::Ping { token: 1 }]);
}

#[test]
fn duplicate_and_overlapping_segments_do_not_regress() {
    let mut rx = StreamReceiver::new(0);
    assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), b"abc");
    assert_eq!(rx.ack(), 3);
    // A full repeat of already-delivered data -- nothing new, the point doesn't move back.
    assert_eq!(rx.on_data(0, vec![b'a', b'b', b'c']), Vec::<u8>::new());
    assert_eq!(rx.ack(), 3);
    // Partial overlap: part old, part new -- deliver only the new part.
    assert_eq!(rx.on_data(1, vec![b'b', b'c', b'd', b'e']), b"de");
    assert_eq!(rx.ack(), 5);
}

#[test]
fn ack_ignores_stale_and_never_regresses_base() {
    let mut tx = StreamSender::new(0);
    tx.push(b"abcdef").expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    assert_eq!(tx.bytes_in_flight(), 6);
    tx.on_ack(4);
    assert_eq!(tx.bytes_in_flight(), 2);
    // A stale ACK doesn't move the base backward.
    tx.on_ack(2);
    assert_eq!(tx.bytes_in_flight(), 2);
    // An ACK beyond what was sent is clamped to what was actually sent.
    tx.on_ack(999);
    assert_eq!(tx.bytes_in_flight(), 0);
}

#[test]
fn ack_does_not_drop_unsent_bytes() {
    // Regression: an ACK for bytes that are in the buffer but haven't
    // been sent yet via frames_to_send must be ignored -- otherwise the
    // bytes would be cut out of the buffer and never go out on the wire.
    let mut tx = StreamSender::new(0);
    tx.push(b"abcdef").expect("room in the offset space"); // nothing sent yet
    tx.on_ack(4); // acknowledging unsent bytes -- ignored
                  // all 6 bytes are still pending, starting from offset zero
    let mut rx = StreamReceiver::new(0);
    let mut got = Vec::new();
    for f in tx.frames_to_send(Instant::now(), Duration::from_millis(500)) {
        if let StreamFrame::Data { offset, data, .. } = f {
            got.extend(rx.on_data(offset, data));
        }
    }
    assert_eq!(got, b"abcdef");
    assert_eq!(rx.ack(), 6);
}

#[test]
fn window_limits_new_bytes_in_flight() {
    let mut tx = StreamSender::new(0);
    let big = vec![0u8; MAX_IN_FLIGHT + 4096];
    tx.push(&big).expect("room in the offset space");
    let frames = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    let sent: usize = frames
        .iter()
        .map(|f| match f {
            StreamFrame::Data { data, .. } => data.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(sent, MAX_IN_FLIGHT);
    assert_eq!(tx.bytes_in_flight(), MAX_IN_FLIGHT);
}

#[test]
fn reset_frame_roundtrip() {
    let mut buf = Vec::new();
    StreamFrame::Reset {
        stream_id: 0,
        new_offset: 12345,
    }
    .encode(&mut buf);
    assert_eq!(
        StreamFrame::decode_all(&buf),
        vec![StreamFrame::Reset {
            stream_id: 0,
            new_offset: 12345
        }]
    );
}

#[test]
fn receiver_on_reset_jumps_and_delivers_without_waiting_for_gap() {
    let mut rx = StreamReceiver::new(0);
    assert_eq!(rx.on_data(0, vec![b'a', b'b']), b"ab");
    assert_eq!(rx.ack(), 2);
    // Server dropped its backlog and restarted the stream far ahead.
    rx.on_reset(1000);
    assert_eq!(rx.ack(), 1000);
    // Data at the new base delivers immediately -- no stall waiting for 2..1000.
    assert_eq!(rx.on_data(1000, vec![b'X']), b"X");
    assert_eq!(rx.ack(), 1001);
}

#[test]
fn mark_desynced_drops_buffer_and_stops_buffering() {
    let mut tx = StreamSender::new(0);
    tx.push(b"hello").expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    tx.mark_desynced();
    assert!(tx.is_desynced());
    assert_eq!(tx.bytes_in_flight(), 0);
    // While desynced, new output is dropped (nothing to replay later).
    tx.push(b"world").expect("room in the offset space");
    let frames = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    assert!(frames
        .iter()
        .all(|f| !matches!(f, StreamFrame::Data { .. })));
}

#[test]
fn begin_resync_emits_reset_until_acked_then_streams_from_new_base() {
    let mut tx = StreamSender::new(0);
    tx.push(&[0u8; 100]).expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500)); // base advanced via send? no -- send only marks segments
    tx.mark_desynced(); // base jumps to write head (=100), buf empty
    let new_off = tx.begin_resync(); // pending reset at 100
    assert_eq!(new_off, 100);
    let now = Instant::now();
    // Reset is emitted while pending, even with no data.
    let f1 = tx.frames_to_send(now, Duration::from_millis(500));
    assert!(f1.iter().any(|f| matches!(
        f,
        StreamFrame::Reset {
            new_offset: 100,
            ..
        }
    )));
    // New (repaint) data streams from the new base.
    tx.push(b"NOW").expect("room in the offset space");
    let f2 = tx.frames_to_send(now, Duration::from_millis(500));
    assert!(f2
        .iter()
        .any(|f| matches!(f, StreamFrame::Data { offset: 100, .. })));
    // Once the receiver acks the reset point, Reset stops being sent.
    tx.on_ack(103);
    let f3 = tx.frames_to_send(now + Duration::from_millis(600), Duration::from_millis(500));
    assert!(f3.iter().all(|f| !matches!(f, StreamFrame::Reset { .. })));
}

#[test]
fn second_desync_clears_stale_pending_reset() {
    // Regression: resync once (arming a Reset at the old base), then go
    // desynced AGAIN before that Reset is acked. The second
    // `mark_desynced` must clear the stale `pending_reset`, or the sender
    // keeps emitting a Reset whose offset no longer matches its base.
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    tx.mark_desynced(); // base jumps to 4 (write head)
    let first = tx.begin_resync(); // pending_reset = Some(4)
    assert_eq!(first, 4);

    // More output queues before the Reset above is ever acked...
    tx.push(b"bb").expect("room in the offset space");
    // ...but the client goes silent again: desync a second time.
    tx.mark_desynced(); // base jumps to 6; must drop the stale pending_reset(4)
    assert!(tx.is_desynced());

    // No Reset should be emitted yet -- we haven't called begin_resync
    // again. A stale pending_reset(4) would wrongly emit one here, at an
    // offset that no longer matches the (new) base.
    let now = Instant::now();
    let frames = tx.frames_to_send(now, Duration::from_millis(500));
    assert!(
        frames
            .iter()
            .all(|f| !matches!(f, StreamFrame::Reset { .. })),
        "a stale pending_reset must not survive a second mark_desynced"
    );

    // The next real resync arms a Reset at the NEW base, not the old one.
    let second = tx.begin_resync();
    assert_eq!(
        second, 6,
        "begin_resync after a second desync must use the new base"
    );
    let frames2 = tx.frames_to_send(now, Duration::from_millis(500));
    assert!(frames2
        .iter()
        .any(|f| matches!(f, StreamFrame::Reset { new_offset: 6, .. })));
}

/// Feed a batch of `frames_to_send` output into a receiver, appending any
/// freshly delivered bytes to `delivered`. A small test-only helper
/// (`StreamFrame::Data`/`Reset` are the only kinds a sender's own
/// `frames_to_send` output ever contains) so the CRITICAL-1 regression
/// tests below read as a plain sender-to-receiver pipe.
fn apply_to_receiver(rx: &mut StreamReceiver, frames: Vec<StreamFrame>, delivered: &mut Vec<u8>) {
    for f in frames {
        match f {
            StreamFrame::Reset { new_offset, .. } => {
                rx.on_reset(new_offset);
            }
            StreamFrame::Data { offset, data, .. } => delivered.extend(rx.on_data(offset, data)),
            _ => {}
        }
    }
}

#[test]
fn pending_reset_is_paced_like_a_retransmit_not_resent_every_flush() {
    // CRITICAL-1 (source fix): before pacing, `frames_to_send` prepended
    // the armed Reset on EVERY call while it was pending, with no RTO
    // gating -- so several `Connection::send` flushes within one RTT (as
    // happens when a tmux repaint is chunked into multiple 8 KiB PTY
    // reads) each carried their OWN Reset, guaranteeing duplicates.
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    tx.mark_desynced();
    let _ = tx.begin_resync(); // pending_reset armed at the write head (4)

    let rto = Duration::from_millis(500);
    let now = Instant::now();

    // First flush: the Reset goes out -- it hasn't been sent before.
    let f1 = tx.frames_to_send(now, rto);
    assert!(
        f1.iter().any(|f| matches!(f, StreamFrame::Reset { .. })),
        "the Reset must go out immediately the first time"
    );

    // A SECOND flush at the SAME instant (e.g. the very next PTY chunk of
    // the same repaint, handled in the same wakeup) must NOT re-include
    // the Reset -- not a full RTO has passed since it last went out.
    tx.push(b"NOW").expect("room in the offset space");
    let f2 = tx.frames_to_send(now, rto);
    assert!(
        f2.iter().all(|f| !matches!(f, StreamFrame::Reset { .. })),
        "the Reset must be paced like a retransmit, not resent on every flush"
    );
    assert!(
        f2.iter().any(|f| matches!(f, StreamFrame::Data { .. })),
        "new data still goes out normally while the Reset is paced"
    );

    // Once RTO elapses with the Reset still unacked, it is resent.
    let f3 = tx.frames_to_send(now + rto, rto);
    assert!(
        f3.iter().any(|f| matches!(f, StreamFrame::Reset { .. })),
        "a still-unacked Reset must be resent after RTO, like a segment retransmit"
    );
}

#[test]
fn duplicate_reset_across_two_flushes_does_not_stall_or_duplicate_delivery() {
    // CRITICAL-1 repro (reviewer-verified): a big repaint chunked across
    // more than one `frames_to_send` batch, with the Reset still unacked
    // (and so re-armed/re-sent) on the second batch. The receiver must
    // treat the second Reset as a no-op and keep delivering forward --
    // not rewind and stall waiting for bytes the sender has already
    // dropped from its own buffer on the first batch's ack.
    let mut tx = StreamSender::new(0);
    tx.push(&[b'A'; 20]).expect("room in the offset space");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_millis(500));
    tx.mark_desynced(); // base jumps to the write head (20)
    let base = tx.begin_resync(); // pending_reset armed at 20
    assert_eq!(base, 20);

    let rto = Duration::from_millis(500);
    let t0 = Instant::now();

    // Batch 1: Reset(20) + the repaint's first chunk (8192 bytes, like a
    // full tmux PTY read).
    tx.push(&vec![b'B'; 8192])
        .expect("room in the offset space");
    let batch1 = tx.frames_to_send(t0, rto);
    assert!(batch1
        .iter()
        .any(|f| matches!(f, StreamFrame::Reset { new_offset: 20, .. })));

    let mut rx = StreamReceiver::new(0);
    let mut delivered = Vec::new();
    apply_to_receiver(&mut rx, batch1, &mut delivered);
    assert_eq!(rx.ack(), 20 + 8192);
    assert_eq!(delivered.len(), 8192);

    // Batch 2, issued past RTO with the Reset still unacked (the ack
    // hasn't made it back to the sender yet) -- a genuine paced resend of
    // the SAME Reset, plus newly queued repaint output "in between".
    tx.push(&vec![b'C'; 4096])
        .expect("room in the offset space");
    let batch2 = tx.frames_to_send(t0 + rto, rto);
    assert!(
        batch2
            .iter()
            .any(|f| matches!(f, StreamFrame::Reset { new_offset: 20, .. })),
        "the still-unacked Reset must be resent after RTO"
    );
    apply_to_receiver(&mut rx, batch2, &mut delivered);

    // The receiver ends exactly at the write head, and every byte arrived
    // exactly once: no stall (the bug), no duplication.
    assert_eq!(rx.ack(), 20 + 8192 + 4096);
    let mut expected = vec![b'B'; 8192];
    expected.extend(vec![b'C'; 4096]);
    assert_eq!(delivered, expected);
}

#[test]
fn on_reset_replayed_after_delivery_is_a_no_op() {
    // CRITICAL-1: a Reset that doesn't move the point FORWARD must be a
    // true no-op -- not just "doesn't crash", but leaves next_offset and
    // any already-buffered out-of-order data untouched.
    let mut rx = StreamReceiver::new(0);
    assert!(rx.on_reset(100));
    assert_eq!(rx.on_data(100, b"abc".to_vec()), b"abc");
    assert_eq!(rx.ack(), 103);

    // An out-of-order segment sits buffered ahead of the point.
    assert_eq!(rx.on_data(110, vec![b'z']), Vec::<u8>::new());

    // The SAME Reset replays (or an even older one would) -- it must
    // report false and touch nothing: the point stays put and the
    // buffered segment ahead of it survives (a rewind would have cleared it).
    assert!(
        !rx.on_reset(100),
        "on_reset must report false when it doesn't move the point"
    );
    assert_eq!(
        rx.ack(),
        103,
        "a stale/duplicate Reset must not rewind the point"
    );

    // Filling the gap up to the buffered segment now delivers it too --
    // proof the segment was never dropped by the no-op reset.
    let filled = rx.on_data(103, vec![b'd', b'e', b'f', b'g', b'h', b'i', b'j']);
    assert_eq!(
        filled, b"defghijz",
        "the buffered segment ahead of the point survived the no-op reset"
    );
}

/// The new frames survive the wire format, and their type codes do not
/// collide with the ones already spoken.
#[test]
fn path_probe_frames_round_trip() {
    let frames = vec![
        StreamFrame::PathProbe { token: 0xDEAD_BEEF },
        StreamFrame::PathProbeAck { token: 7 },
    ];
    for frame in frames {
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        assert_eq!(
            StreamFrame::decode_all(&buf),
            vec![frame.clone()],
            "a path frame must survive the round trip: {frame:?}"
        );
    }
}

/// A build that predates these frames stops at the unknown type instead
/// of reading its bytes as something else. That is what lets an older
/// daemon simply not answer a probe -- the path stays unverified -- while
/// everything else on the connection keeps working.
#[test]
fn an_older_peer_stops_at_the_unknown_frame_rather_than_misreading_it() {
    let mut buf = Vec::new();
    StreamFrame::PathProbe { token: 1 }.encode(&mut buf);
    // What an older `decode_all` would see: an unknown leading byte.
    assert_eq!(buf[0], TYPE_PATH_PROBE);
    let mut unknown = vec![0x7F_u8];
    unknown.extend_from_slice(&1u32.to_be_bytes());
    assert!(
        StreamFrame::decode_all(&unknown).is_empty(),
        "an unknown frame type yields nothing, and never a misparsed frame"
    );
}

/// Spec §4.2: the retransmit wake-up is per segment -- the oldest
/// unacknowledged segment's last send plus `rto` -- and an armed Reset
/// that has gone out is paced the same way.
#[test]
fn the_retransmit_deadline_is_the_oldest_unacked_segment_plus_rto() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_millis(100);
    let mut tx = StreamSender::new(0);
    assert_eq!(tx.retransmit_deadline(rto), None, "nothing sent");
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    tx.push(b"bb").expect("room in the offset space");
    let _ = tx.frames_to_send(t1, rto);
    assert_eq!(tx.retransmit_deadline(rto), Some(t0 + rto));
    assert!(tx.on_ack(4), "the ack moved the base");
    assert_eq!(tx.retransmit_deadline(rto), Some(t1 + rto));
    assert!(!tx.on_ack(4), "a repeated ack moves nothing");
    assert!(tx.on_ack(6));
    assert_eq!(tx.retransmit_deadline(rto), None, "everything acknowledged");

    tx.mark_desynced();
    let _ = tx.begin_resync();
    let t2 = t1 + Duration::from_millis(100);
    let _ = tx.frames_to_send(t2, rto);
    assert_eq!(
        tx.retransmit_deadline(rto),
        Some(t2 + rto),
        "a Reset that went out is due again rto later"
    );
}

/// Karn's rule for data (RFC 6298 §3): an ACK that newly covers segments
/// which all went out once times the newest of them from its send.
#[test]
fn an_ack_times_the_newest_segment_it_newly_covers() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_millis(10);
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    tx.push(b"bb").expect("room in the offset space");
    let _ = tx.frames_to_send(t1, rto);
    assert_eq!(tx.ack_timed_from(4), Some(t0));
    assert_eq!(tx.ack_timed_from(6), Some(t1), "the newest covered");
    assert!(tx.on_ack(4));
    assert_eq!(tx.ack_timed_from(4), None, "covers nothing new");
    assert_eq!(tx.ack_timed_from(6), Some(t1));
    assert_eq!(tx.ack_timed_from(5), None, "covers no whole segment");
}

/// An ACK that covers a retransmitted segment -- a hole filled, the
/// cumulative ACK jumping over segments that arrived long before -- says
/// nothing about any one send, so it times nothing.
#[test]
fn an_ack_covering_a_retransmitted_segment_times_nothing() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    tx.push(b"bb").expect("room in the offset space");
    let _ = tx.frames_to_send(t0 + Duration::from_millis(400), rto);
    let resent = tx.frames_to_send(t0 + rto, rto);
    assert_eq!(resent.len(), 1, "the first segment went out again");
    assert_eq!(tx.ack_timed_from(4), None);
    assert_eq!(
        tx.ack_timed_from(6),
        None,
        "the jump includes the resent one"
    );
    assert!(tx.on_ack(4));
    assert_eq!(
        tx.ack_timed_from(6),
        Some(t0 + Duration::from_millis(400)),
        "past the resent segment, timing resumes"
    );
}

/// After `forget_send_times` nothing already in flight times a round
/// trip; what is sent afterwards does again.
#[test]
fn forgotten_send_times_time_nothing_and_later_sends_time_again() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    tx.forget_send_times();
    assert_eq!(tx.ack_timed_from(4), None);
    let t1 = t0 + Duration::from_secs(600);
    tx.push(b"bb").expect("room in the offset space");
    let _ = tx.frames_to_send(t1, rto);
    assert_eq!(
        tx.ack_timed_from(6),
        None,
        "the ACK still covers a forgotten one"
    );
    assert!(tx.on_ack(4));
    assert_eq!(tx.ack_timed_from(6), Some(t1));
}

/// Final review, Important 1: the deadline that wakes the sender belongs
/// to the oldest segment, but a wake-up resends only the segments whose
/// OWN last send is `rto` old -- not the whole window with them.
#[test]
fn a_retransmit_wake_up_resends_only_the_segments_that_are_due() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let t1 = t0 + Duration::from_millis(400);
    let mut tx = StreamSender::new(0);
    tx.push(b"aaaa").expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    tx.push(b"bb").expect("room in the offset space");
    let _ = tx.frames_to_send(t1, rto);
    let due = tx.retransmit_deadline(rto).expect("both unacknowledged");
    assert_eq!(due, t0 + rto);
    let resent = tx.frames_to_send(due, rto);
    assert_eq!(
        resent,
        vec![StreamFrame::Data {
            stream_id: 0,
            offset: 0,
            data: b"aaaa".to_vec(),
        }],
        "the segment sent 100 ms ago waits for its own deadline"
    );
    assert_eq!(tx.retransmit_deadline(rto), Some(t1 + rto));
}

/// What `Connection::sendable_now` asks a sender: something that has no
/// deadline of its own -- unsent bytes with room in the window, a
/// segment taken for lost, an armed Reset that has not gone out yet.
/// A segment merely waiting for its ACK has a deadline instead.
#[test]
fn has_sendable_and_has_unsent_reset_count_what_has_no_deadline_of_its_own() {
    let rto = Duration::from_millis(500);
    let t0 = Instant::now();
    let mut tx = StreamSender::new(0);
    assert!(!tx.has_sendable(), "nothing queued");
    tx.push(b"abc").expect("room in the offset space");
    assert!(tx.has_sendable(), "queued, never sent");
    let _ = tx.frames_to_send(t0, rto);
    assert!(!tx.has_sendable(), "sent, waiting for its ACK");
    assert!(
        tx.mark_due_lost(t0 + rto, rto),
        "the oldest segment expired"
    );
    assert!(tx.has_sendable(), "a segment taken for lost");
    assert_eq!(tx.retransmit_deadline(rto), None, "and it has no deadline");
    let _ = tx.next_segment(t0 + rto).expect("the lost segment again");
    assert!(!tx.has_sendable(), "out again, waiting for its ACK");

    tx.push(&vec![b'x'; MAX_IN_FLIGHT])
        .expect("room in the offset space");
    let _ = tx.frames_to_send(t0, rto);
    assert!(tx.bytes_in_flight() >= MAX_IN_FLIGHT, "the window is full");
    assert!(
        !tx.has_sendable(),
        "bytes waiting for room in the window wait for an ACK, not a timer"
    );

    tx.mark_desynced();
    assert!(!tx.has_sendable(), "a desynced sender holds nothing");
    assert!(!tx.has_unsent_reset(), "and no Reset");
    let _ = tx.begin_resync();
    assert!(tx.has_unsent_reset(), "an armed Reset that never went out");
    let _ = tx.frames_to_send(t0, rto);
    assert!(!tx.has_unsent_reset(), "the Reset went out");
}

/// Spec §4.14 (legacy mode): a write that would reach past
/// `OFFSET_LIMIT` is refused whole, and nothing already queued is lost.
#[test]
fn a_write_past_the_offset_limit_is_refused_whole() {
    let mut tx = StreamSender::starting_at(0, OFFSET_LIMIT - 4);
    tx.push(b"abcd").expect("exactly up to the limit fits");
    assert_eq!(tx.push(b"e"), Err(OffsetSpaceExhausted));
    assert_eq!(tx.queued_total(), u64::from(OFFSET_LIMIT));
    assert_eq!(
        tx.unacked_len(),
        4,
        "the bytes before the limit are still there"
    );
}

/// A DATA frame that ends past `u32::MAX` is dropped, not wrapped: no
/// sender following this protocol writes there, and `drain`'s
/// `off + len` would overflow.
#[test]
fn a_data_frame_ending_past_u32_max_is_dropped_without_panic() {
    let mut rx = StreamReceiver::starting_at(0, u32::MAX - 100);
    assert!(rx.on_data(u32::MAX - 10, vec![1u8; 20]).is_empty());
    assert_eq!(rx.ack(), u32::MAX - 100, "nothing moved");
    assert_eq!(rx.on_data(u32::MAX - 100, vec![2u8; 100]), vec![2u8; 100]);
    assert_eq!(rx.ack(), u32::MAX, "up to the very last offset is fine");
}

/// Spec §9.2 (1a): an acknowledgement costs the same whatever lies
/// behind it. With a `Vec` every ACK moved the whole remaining backlog to
/// the front (`drain(0..n)`), so 32 MiB queued at once took 52 s. With a
/// ring only the head moves: the first byte still waiting after the ACK
/// sits at the very address it had before it.
#[test]
fn ack_cost_does_not_depend_on_backlog() {
    for backlog in [64 * 1024usize, 32 * 1024 * 1024] {
        let mut tx = StreamSender::new(1);
        tx.push(&vec![0xA5; backlog])
            .expect("room in the offset space");
        let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
        let acked = 4 * 1024;
        let before = tx.byte_address_for_test(acked);
        assert!(tx.on_ack(acked as u32));
        assert_eq!(
            tx.byte_address_for_test(0),
            before,
            "backlog {backlog}: the bytes behind the ACK were moved"
        );
        assert_eq!(tx.unacked_len(), backlog - acked);
    }
}

/// A burst past every send gate -- past `SEND_HARD_CAP` at worst, whose
/// data a stream nobody can rebuild keeps -- grows the ring to its size.
/// Once acknowledged, that memory comes back: a ring does not stay at
/// its peak for the rest of the connection. The move is made on a ring
/// that wraps, and the bytes still waiting come through it intact.
#[test]
fn a_ring_grown_by_a_burst_gives_its_memory_back_as_it_drains() {
    let rto = Duration::from_secs(1);
    let now = Instant::now();
    let all: Vec<u8> = (0..11 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let (first, second) = all.split_at(8 * 1024 * 1024);
    let mut tx = StreamSender::new(1);
    tx.push(first).expect("room");
    let grown = tx.buf.capacity();
    assert!(grown >= first.len());
    let mut acked = 0usize;
    let mut ack_up_to = |tx: &mut StreamSender, to: usize| {
        while acked < to {
            let _ = tx.frames_to_send(now, rto);
            let next = (tx.sent_up_to as usize).min(to);
            assert!(tx.on_ack(next as u32));
            acked = next;
        }
    };
    ack_up_to(&mut tx, 4 * 1024 * 1024);
    assert_eq!(tx.buf.capacity(), grown, "half full keeps its room");
    tx.push(second).expect("room");
    let (head, tail) = tx.buf.as_slices();
    assert!(!head.is_empty() && !tail.is_empty(), "the ring wraps");
    let left = 100 * 1024;
    ack_up_to(&mut tx, all.len() - left);
    assert!(
        tx.buf.capacity() <= RING_KEEP,
        "capacity {} after the burst drained",
        tx.buf.capacity()
    );
    assert_eq!(tx.copy_out(0, left), &all[all.len() - left..]);
}

/// A ring no bigger than what a send gate lets through (spec §4.7.2) is
/// never shrunk: a gated stream fills and drains it all the time, and
/// would pay for a reallocation on every burst.
#[test]
fn a_ring_within_what_a_gate_lets_through_keeps_its_capacity() {
    let rto = Duration::from_secs(1);
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    for _ in 0..80 {
        tx.push(&[0x5A; 8 * 1024]).expect("room");
    }
    let grown = tx.buf.capacity();
    assert!(
        grown <= RING_KEEP,
        "a 640 KiB tail grows the ring to {grown}"
    );
    while tx.unacked_len() > 0 {
        let _ = tx.frames_to_send(now, rto);
        assert!(tx.on_ack(tx.sent_up_to as u32));
    }
    assert_eq!(tx.buf.capacity(), grown);
}

/// The ring wraps: bytes pushed after an ACK freed its head come out of
/// `frames_to_send` intact and in order.
#[test]
fn segments_cut_across_the_rings_wrap_carry_the_right_bytes() {
    let rto = Duration::from_secs(1);
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    let first: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
    tx.push(&first).expect("room");
    let _ = tx.frames_to_send(now, rto);
    assert!(tx.on_ack(6 * 1024));
    let second: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 241) as u8).collect();
    tx.push(&second).expect("room");
    let mut rx = StreamReceiver::starting_at(1, 8 * 1024);
    for f in tx.frames_to_send(now, rto) {
        if let StreamFrame::Data { offset, data, .. } = f {
            let _ = rx.on_data(offset, data);
        }
    }
    let mut tail = Vec::new();
    for f in tx.frames_to_send(now + rto, rto) {
        if let StreamFrame::Data { offset, data, .. } = f {
            if (6 * 1024..8 * 1024).contains(&offset) {
                tail.extend_from_slice(&data);
            }
        }
    }
    assert_eq!(
        tail,
        &first[6 * 1024..],
        "the retransmitted head of the ring"
    );
    assert_eq!(rx.ack(), 16 * 1024, "the new bytes arrived whole");
}

/// `copy_out` across a ring that really is in two pieces: every range,
/// including the ones that straddle the split, comes out as the bytes a
/// flat copy of the backlog holds there. (The test above pins the
/// behaviour; its buffer grows in one piece and does not split.)
#[test]
fn copy_out_reads_across_the_split_of_the_ring() {
    let mut tx = StreamSender::new(1);
    let first: Vec<u8> = (0..8 * 1024u32).map(|i| (i % 251) as u8).collect();
    tx.push(&first).expect("room");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
    assert!(tx.on_ack(6 * 1024));
    let second: Vec<u8> = (0..4 * 1024u32).map(|i| (i % 241) as u8).collect();
    tx.push(&second).expect("room");
    let (head, tail) = tx.buf.as_slices();
    assert!(
        !head.is_empty() && !tail.is_empty(),
        "the ring holds the backlog in two pieces"
    );
    let split = head.len();
    let flat: Vec<u8> = tx.buf.iter().copied().collect();
    assert_eq!(&flat[..2 * 1024], &first[6 * 1024..]);
    assert_eq!(&flat[2 * 1024..], &second[..]);
    for from in [0, 1, split - 1, split, split + 1, flat.len() - 1] {
        for len in [0, 1, 7, split, flat.len() - from] {
            if from + len > flat.len() {
                continue;
            }
            assert_eq!(
                tx.copy_out(from, len),
                &flat[from..from + len],
                "from {from}, len {len}, split at {split}"
            );
        }
    }
}

/// RFC 5681 §3.2: an ACK that moves nothing while bytes are in flight is
/// a duplicate; the count restarts when one moves the base.
#[test]
fn duplicate_acks_are_counted_until_one_moves_the_base() {
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 4096]).expect("room");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
    assert_eq!(tx.on_ack_counting(0).duplicates, 1);
    assert_eq!(tx.on_ack_counting(0).duplicates, 2);
    assert_eq!(tx.on_ack_counting(0).duplicates, 3);
    let moved = tx.on_ack_counting(1024);
    assert_eq!((moved.acked, moved.duplicates), (1024, 0));
    assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
    let mut idle = StreamSender::new(2);
    assert_eq!(
        idle.on_ack_counting(0),
        AckEffect::default(),
        "nothing in flight"
    );
}

/// The urgent retransmit is the oldest segment and goes out first.
#[test]
fn an_urgent_segment_is_the_oldest_and_goes_out_before_anything_else() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[7u8; 3 * 1024]).expect("room");
    let _ = tx.frames_to_send(now, Duration::from_secs(1));
    assert!(tx.mark_oldest_urgent());
    assert!(tx.has_urgent());
    let seg = tx.next_urgent(now).expect("urgent");
    assert!(matches!(seg.frame, StreamFrame::Data { offset: 0, .. }) && seg.retransmit);
    assert!(!tx.has_urgent());
    assert_eq!(tx.pipe(), 3 * 1024, "back in the network");
}

/// An ACK below the base is a stale one overtaken on the way: neither a
/// duplicate nor the end of a run of them.
#[test]
fn a_stale_ack_is_not_a_duplicate_and_does_not_break_the_run() {
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 4096]).expect("room");
    let _ = tx.frames_to_send(Instant::now(), Duration::from_secs(1));
    let _ = tx.on_ack_counting(1024);
    assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
    assert_eq!(tx.on_ack_counting(0), AckEffect::default());
    assert_eq!(tx.on_ack_counting(1024).duplicates, 2);
}

/// An ACK that acknowledges an armed `Reset` moved something: it is the
/// answer to the `Reset`, not a sign of a hole in the DATA.
#[test]
fn the_ack_that_clears_a_reset_is_not_a_duplicate() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.mark_desynced();
    let base = tx.begin_resync();
    tx.push(&[0u8; 2048]).expect("room");
    let frames = tx.frames_to_send(now, Duration::from_secs(1));
    assert!(matches!(frames[0], StreamFrame::Reset { .. }));
    assert_eq!(tx.on_ack_counting(base as u32), AckEffect::default());
    assert!(!tx.has_unsent_reset() && tx.take_due_reset(now, Duration::ZERO).is_none());
    assert_eq!(
        tx.on_ack_counting(base as u32).duplicates,
        1,
        "the next one is"
    );
}

/// RFC 6582 §3.2 step 1: once held, a stream's fast retransmit waits
/// for an ACK past everything sent at the time -- one equal to it is
/// not enough: its copies may still draw ACKs of that base.
#[test]
fn a_held_fast_retransmit_waits_for_an_ack_past_what_was_sent() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 20 * 1024]).expect("room");
    for _ in 0..10 {
        let _ = tx.next_segment(now).expect("room");
    }
    assert!(tx.may_fast_retransmit());
    tx.hold_fast_retransmit();
    assert!(!tx.may_fast_retransmit());
    let _ = tx.on_ack_counting(10 * 1024);
    assert!(!tx.may_fast_retransmit(), "equal to it");
    let _ = tx.next_segment(now).expect("new data");
    let _ = tx.on_ack_counting(11 * 1024);
    assert!(tx.may_fast_retransmit());
}

/// RFC 3465 §2.3 (ruling R20): the round trip after a timeout lasts, for
/// a stream, until an ACK reaches where it had sent up to at the
/// timeout. The ACK that reaches it is still in it (asked before the ACK
/// is applied); the next is not. A stream with nothing in flight has no
/// such round trip.
#[test]
fn the_round_trip_after_a_timeout_lasts_until_its_flight_is_acknowledged() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 20 * 1024]).expect("room");
    tx.note_timeout_flight();
    assert!(!tx.acks_timeout_flight(), "nothing in flight");
    for _ in 0..10 {
        let _ = tx.next_segment(now).expect("room");
    }
    tx.note_timeout_flight();
    assert!(tx.acks_timeout_flight());
    let _ = tx.on_ack_counting(4 * 1024);
    assert!(tx.acks_timeout_flight(), "part of the flight");
    let _ = tx.next_segment(now).expect("new data");
    assert!(
        tx.acks_timeout_flight(),
        "what goes out since does not move it"
    );
    let _ = tx.on_ack_counting(10 * 1024);
    assert!(!tx.acks_timeout_flight(), "the flight acknowledged");
}

/// An undone timeout, a restart and a desync forget the round trip
/// after the timeout.
#[test]
fn an_undo_a_restart_and_a_desync_forget_the_timeouts_flight() {
    let now = Instant::now();
    let flying = || {
        let mut tx = StreamSender::new(1);
        tx.push(&[0u8; 4096]).expect("room");
        let _ = tx.next_segment(now).expect("room");
        tx.note_timeout_flight();
        assert!(tx.acks_timeout_flight());
        tx
    };
    let mut undone = flying();
    undone.forget_timeout_losses(now);
    assert!(!undone.acks_timeout_flight(), "undo");
    let mut restarted = flying();
    restarted.take_in_flight_for_lost();
    assert!(!restarted.acks_timeout_flight(), "restart");
    let mut desynced = flying();
    desynced.mark_desynced();
    assert!(!desynced.acks_timeout_flight(), "desync");
}

/// A restart resends everything in flight: those copies hold it.
#[test]
fn taking_the_flight_for_lost_holds_the_fast_retransmit() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 4096]).expect("room");
    let _ = tx.next_segment(now).expect("room");
    tx.take_in_flight_for_lost();
    assert!(!tx.may_fast_retransmit());
}

/// A recovery that ended with nothing past the base in flight still
/// holds: its repairs draw ACKs of that base, with new data behind them.
#[test]
fn a_hold_with_nothing_in_flight_waits_for_the_next_advance() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 4096]).expect("room");
    let _ = tx.next_segment(now).expect("room");
    let _ = tx.on_ack_counting(1024);
    tx.hold_fast_retransmit();
    let _ = tx.next_segment(now).expect("new data");
    assert_eq!(tx.on_ack_counting(1024).duplicates, 1);
    assert!(!tx.may_fast_retransmit());
    let _ = tx.on_ack_counting(2048);
    assert!(tx.may_fast_retransmit());
}

/// A desync drops everything the hold was about.
#[test]
fn a_desync_releases_the_hold() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 4096]).expect("room");
    let _ = tx.next_segment(now).expect("room");
    tx.hold_fast_retransmit();
    tx.mark_desynced();
    assert!(tx.may_fast_retransmit());
}

/// Review round 2 (Minor 1): the hold after a recovery runs to where the
/// recovery began (RFC 6582's `recover`), not to all the stream has sent
/// since -- and a full ACK already past that point holds nothing.
#[test]
fn a_hold_to_an_offset_waits_only_while_the_base_has_not_passed_it() {
    let now = Instant::now();
    let mut tx = StreamSender::new(1);
    tx.push(&[0u8; 20 * 1024]).expect("room");
    for _ in 0..14 {
        let _ = tx.next_segment(now).expect("room");
    }
    let _ = tx.on_ack_counting(10 * 1024);
    tx.hold_fast_retransmit_to(10 * 1024);
    assert!(!tx.may_fast_retransmit(), "the base is at it");
    let _ = tx.on_ack_counting(11 * 1024);
    assert!(
        tx.may_fast_retransmit(),
        "past it, not past all that was sent"
    );
    tx.hold_fast_retransmit_to(10 * 1024);
    assert!(tx.may_fast_retransmit(), "already past: nothing to hold");
}

fn with_credits() -> Features {
    Features::HEADER_AAD | Features::STREAM_CREDIT | Features::OFFSET_WRAP
}

fn crediting_sender(stream_id: u8) -> StreamSender {
    let mut tx = StreamSender::new(stream_id);
    tx.set_features(with_credits());
    tx
}

fn crediting_receiver(stream_id: u8) -> StreamReceiver {
    let mut rx = StreamReceiver::new(stream_id);
    rx.set_features(with_credits());
    rx
}

/// Send what `tx` may and acknowledge it at once, until it stops.
/// Returns how far it got.
fn send_and_ack_until_stopped(tx: &mut StreamSender, now: Instant) -> u64 {
    loop {
        if tx.frames_to_send(now, Duration::from_secs(1)).is_empty() {
            return tx.sent_up_to();
        }
        let _ = tx.on_ack(tx.sent_up_to() as u32);
    }
}

/// Deliver `n` bytes in order to `rx` from where it stands.
fn deliver_in_order(rx: &mut StreamReceiver, n: u64) {
    let mut left = n;
    while left > 0 {
        let len = left.min(MAX_SEGMENT_SIZE as u64);
        let at = rx.next_offset() as u32;
        assert_eq!(rx.on_data(at, vec![0u8; len as usize]).len() as u64, len);
        left -= len;
    }
}

/// Spec §6.1: `0x09 CREDIT stream_id(1) limit(u32, BE)`, six bytes.
#[test]
fn a_credit_frame_is_six_bytes_and_round_trips() {
    let mut buf = Vec::new();
    StreamFrame::Credit {
        stream_id: 20,
        limit: 0x0102_0304,
    }
    .encode(&mut buf);
    assert_eq!(buf, [0x09, 20, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        StreamFrame::decode_all(&buf),
        vec![StreamFrame::Credit {
            stream_id: 20,
            limit: 0x0102_0304
        }]
    );
    assert!(
        StreamFrame::decode_all(&buf[..5]).is_empty(),
        "a cut frame is dropped"
    );
}

/// Spec §6.2: with credits a sender puts out new bytes only below its
/// limit -- the implicit `STREAM_WINDOW` at first -- and goes on once a
/// `CREDIT` raises it; a stale or repeated one changes nothing. A sender
/// stopped at its limit has nothing to send and is not backlogged: the
/// reader sets the pace, not the network.
#[test]
fn a_sender_writes_new_bytes_only_below_its_limit() {
    let now = Instant::now();
    let mut tx = crediting_sender(20);
    tx.push(&vec![1u8; 600 * 1024]).expect("room");
    assert_eq!(tx.credit_limit(), Some(STREAM_WINDOW));
    assert_eq!(send_and_ack_until_stopped(&mut tx, now), STREAM_WINDOW);
    assert!(!tx.has_sendable());
    assert!(!tx.has_waiting());
    assert!(!tx.on_credit((STREAM_WINDOW - 1) as u32), "stale");
    assert!(!tx.on_credit(STREAM_WINDOW as u32), "the same again");
    assert!(tx.on_credit((STREAM_WINDOW + 64 * 1024) as u32));
    assert_eq!(
        send_and_ack_until_stopped(&mut tx, now),
        STREAM_WINDOW + 64 * 1024
    );
}

/// Spec §6.2, §6.5: a retransmit neither spends nor checks the credit.
#[test]
fn a_retransmit_goes_out_at_the_limit() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(500);
    let mut tx = crediting_sender(20);
    tx.push(&vec![2u8; STREAM_WINDOW as usize]).expect("room");
    let _ = tx.frames_to_send(t0, rto);
    assert!(tx.on_ack(tx.sent_up_to() as u32));
    let second = tx.frames_to_send(t0, rto);
    assert_eq!(tx.sent_up_to(), STREAM_WINDOW, "at the limit");
    let resent = tx.frames_to_send(t0 + rto, rto);
    assert_eq!(
        resent.len(),
        second.len(),
        "all of it again at its deadline"
    );
}

/// A `CREDIT` on a stream without credits -- a stray one -- is ignored.
#[test]
fn a_credit_without_credits_is_ignored() {
    let mut tx = StreamSender::new(20);
    assert_eq!(tx.credit_limit(), None);
    assert!(!tx.on_credit(1 << 30));
    assert_eq!(tx.credit_limit(), None);
}

/// Spec §6.5 (amended 2026-09-28, fix round 1): dropping a backlog that
/// still fit in the room the sender already had leaves its limit
/// standing -- there was nothing to wait for, so the repaint goes out
/// at once.
#[test]
fn a_desync_within_the_old_room_keeps_the_limit_and_the_repaint_goes_out_at_once() {
    let now = Instant::now();
    let mut tx = crediting_sender(0);
    tx.push(&vec![3u8; 300 * 1024]).expect("room");
    assert_eq!(send_and_ack_until_stopped(&mut tx, now), 300 * 1024);
    tx.push(&vec![4u8; 200 * 1024]).expect("room"); // queued, never sent -- head 500 KiB, inside 512 KiB
    tx.mark_desynced();
    assert_eq!(
        tx.credit_limit(),
        Some(STREAM_WINDOW),
        "the backlog fit -- the limit stands"
    );
    assert_eq!(tx.begin_resync(), 500 * 1024);
    tx.push(b"repaint").expect("room");
    let frames = tx.frames_to_send(now, Duration::from_secs(1));
    assert!(frames.iter().any(|f| matches!(
        f,
        StreamFrame::Data { offset, .. } if u64::from(*offset) == 500 * 1024
    )));
}

/// Spec §6.5 (amended 2026-09-28, fix round 1): dropping a backlog past
/// the room the sender already had takes the limit to exactly `q` --
/// not the plain `+= head - sent_up_to` shift, which would land it
/// strictly between the receiver's candidates (Important 1) -- and the
/// repaint then waits for the `CREDIT` that rides the `Reset`'s ACK.
#[test]
fn a_desync_past_the_old_room_takes_the_limit_to_q_and_the_repaint_waits_for_credit() {
    let now = Instant::now();
    let mut tx = crediting_sender(0);
    tx.push(&vec![3u8; 300 * 1024]).expect("room");
    assert_eq!(send_and_ack_until_stopped(&mut tx, now), 300 * 1024);
    tx.push(&vec![4u8; 300 * 1024]).expect("room"); // queued, never sent -- head 600 KiB, past 512 KiB
    tx.mark_desynced();
    assert_eq!(
        tx.credit_limit(),
        Some(600 * 1024),
        "past the room -- the limit takes q"
    );
    assert_eq!(tx.begin_resync(), 600 * 1024);
    tx.push(b"repaint").expect("room");
    let frames = tx.frames_to_send(now, Duration::from_secs(1));
    assert!(
        !frames.iter().any(|f| matches!(f, StreamFrame::Data { .. })),
        "no room yet -- the repaint waits for a CREDIT past q"
    );
    assert!(tx.on_credit((600 * 1024 + 64 * 1024) as u32));
    let frames = tx.frames_to_send(now, Duration::from_secs(1));
    assert!(frames.iter().any(|f| matches!(
        f,
        StreamFrame::Data { offset, .. } if u64::from(*offset) == 600 * 1024
    )));
}

/// Spec §6.2: a receiver with credits keeps nothing past its newest
/// limit -- DATA across it is cut there, the rest neither kept nor
/// acknowledged -- and its cost cap is the credit window's.
#[test]
fn data_past_the_announced_limit_is_cut_there() {
    let mut rx = crediting_receiver(20);
    assert_eq!(rx.credit_limit(), Some(STREAM_WINDOW));
    assert_eq!(
        rx.cost_cap(),
        STREAM_WINDOW as usize + STREAM_WINDOW as usize / MAX_SEGMENT_SIZE * CHUNK_COST
    );
    deliver_in_order(&mut rx, STREAM_WINDOW - 100);
    assert_eq!(
        rx.on_data((STREAM_WINDOW - 100) as u32, vec![5u8; 1000])
            .len(),
        100
    );
    assert!(rx.on_data(STREAM_WINDOW as u32, vec![5u8; 10]).is_empty());
    assert_eq!(rx.ack(), STREAM_WINDOW as u32);
}

/// Spec §6.4: a step of consumption is announced; less is not worth a
/// frame.
#[test]
fn a_step_of_consumption_is_announced_and_less_is_not() {
    let now = Instant::now();
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, 200 * 1024);
    rx.on_consumed(CREDIT_UPDATE_STEP - 1);
    assert_eq!(rx.credit_due(now, false), None);
    rx.on_consumed(1);
    let limit = STREAM_WINDOW + CREDIT_UPDATE_STEP;
    assert_eq!(
        rx.credit_due(now, false),
        Some(StreamFrame::Credit {
            stream_id: 20,
            limit: limit as u32
        })
    );
    assert_eq!(rx.credit_due(now, false), None, "said once");
    assert_eq!(rx.credit_limit(), Some(limit));
    assert_eq!(rx.unconsumed(), 200 * 1024 - CREDIT_UPDATE_STEP);
}

/// Spec §6.4 (amended fix round 3): a sender stopped at its limit hears
/// of room of `CREDIT_UPDATE_STEP` or more at once and three times more,
/// one rto apart; the PONGs carry it after that; once data goes past
/// the old limit nothing more is said. Before that much room there is
/// nothing to say: a stuck consumer costs no frames, and neither does a
/// growth too small to feed it -- a whole segment used to be enough
/// (fix round 2), but a sender stopped at `L = consumed_then + W` still
/// has about `W` unconsumed held for it, so a growth short of
/// `CREDIT_UPDATE_STEP` (a quarter of `W`) never actually frees the
/// consumer; measured (fix round 3 report), it only multiplied
/// `CREDIT`s for identical throughput.
#[test]
fn a_stopped_sender_hears_of_room_at_once_and_three_times_more() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, STREAM_WINDOW);
    assert_eq!(
        rx.credit_due(t0, false),
        None,
        "nothing taken, nothing to say"
    );
    assert_eq!(rx.credit_for_pong(t0, rto), None);
    assert_eq!(rx.credit_resend_deadline(rto), None);
    rx.on_consumed(CREDIT_UPDATE_STEP - 1);
    assert_eq!(
        rx.credit_due(t0, false),
        None,
        "less than a step frees nothing"
    );
    rx.on_consumed(1);
    let frame = StreamFrame::Credit {
        stream_id: 20,
        limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
    };
    assert_eq!(rx.credit_due(t0, false), Some(frame.clone()));
    let mut at = t0;
    for repeat in 0..CREDIT_RESENDS {
        let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
        assert_eq!(due, at + rto, "repeat {repeat}");
        assert_eq!(rx.credit_resend(due - Duration::from_millis(1), rto), None);
        assert_eq!(rx.credit_resend(due, rto), Some(frame.clone()));
        at = due;
    }
    assert_eq!(
        rx.credit_resend_deadline(rto),
        None,
        "three, then the PONGs"
    );
    assert_eq!(
        rx.credit_for_pong(at, rto),
        None,
        "the repeat just went: no PONG copy within an rto of it"
    );
    assert_eq!(rx.credit_for_pong(at + rto, rto), Some(frame.clone()));
    assert_eq!(rx.on_data(STREAM_WINDOW as u32, vec![0u8; 10]).len(), 10);
    assert_eq!(
        rx.credit_for_pong(at + rto, rto),
        None,
        "the sender has the new limit"
    );
    assert_eq!(rx.credit_resend_deadline(rto), None);
}

/// R9 (fix round 4, spec §6.4 amended), shaped like the review's probe
/// C: an `OnDelivery` stream whose data simply runs out 100 bytes short
/// of an older limit -- every byte delivered is taken at once, and
/// nothing more is coming -- is idle, not stopped. The earlier "within
/// a segment" rule (fix round 3) read that 100-byte gap (less than
/// `MAX_SEGMENT_SIZE`) as "possibly stopped" and kept the newest limit
/// riding every PONG for as long as the stream stayed idle there. This
/// test fails under that rule (the deadline and PONG assertions below
/// return `Some`, not `None`) and passes under the exact one.
#[test]
fn an_idle_stream_short_of_an_older_limit_draws_nothing_ever() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    // 100 bytes short of the implicit limit: the stream's data simply
    // ends there, and every byte delivered is taken at once.
    deliver_in_order(&mut rx, STREAM_WINDOW - 100);
    rx.on_consumed(STREAM_WINDOW - 100);
    // The growth announces a second, newer limit -- so there is now an
    // "older" one (the implicit first) to be wrongly judged against.
    assert!(rx.credit_due(t0, false).is_some(), "growth is announced");
    assert_eq!(
        rx.credit_resend_deadline(rto),
        None,
        "not armed -- idle, not stopped"
    );
    assert_eq!(
        rx.credit_for_pong(t0, rto),
        None,
        "not armed -- idle, not stopped"
    );

    // Many PING intervals pass with nothing more ever arriving: still
    // nothing, for as long as the stream stays idle.
    let mut now = t0;
    for _ in 0..5 {
        now += Duration::from_millis(1500);
        assert_eq!(rx.credit_resend(now, rto), None, "no timer repeat");
        assert_eq!(rx.credit_for_pong(now, rto), None, "no PONG-borne CREDIT");
    }
}

/// Spec §6.4 as this plan corrects it (Review Focus 1; fix round 4): a
/// `CREDIT` lost while the consumer stops at a step would, judged
/// against the newest limit, leave the sender stopped at the older one
/// for good -- nothing grows, no step fires. The receiver sees the
/// sender stopped at the older limit it may still hold, and arms a
/// repeat -- but does not send the newest again on the spot: it was
/// just sent (the announcement above), well under an `rto` ago, so
/// sending it again here would be a duplicate the sender cannot even
/// have missed yet. The repeat's own timing (fix round 4, spec §6.4
/// amended) is one `rto` after that announcement. A PONG in between
/// carries nothing either (ruling R15, spec §6.4 amended): a PONG copy
/// too waits an `rto` from the newest limit's last send. Once that
/// long has passed, a PONG does carry it and counts as a send: the
/// next repeat is then one `rto` after the PONG.
#[test]
fn a_lost_credit_is_repeated_once_the_sender_stops_at_the_older_limit() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, CREDIT_UPDATE_STEP);
    rx.on_consumed(CREDIT_UPDATE_STEP);
    let newer = StreamFrame::Credit {
        stream_id: 20,
        limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
    };
    assert_eq!(
        rx.credit_due(t0, false),
        Some(newer.clone()),
        "announced -- and lost"
    );
    // The sender, still at the implicit limit, stops there; the consumer
    // takes nothing more.
    deliver_in_order(&mut rx, STREAM_WINDOW - CREDIT_UPDATE_STEP);
    let t1 = t0 + Duration::from_millis(50);
    assert_eq!(
        rx.credit_due(t1, false),
        None,
        "armed, but the newest went out less than an rto ago"
    );
    assert_eq!(rx.credit_resend_deadline(rto), Some(t0 + rto));
    assert_eq!(
        rx.credit_for_pong(t1, rto),
        None,
        "a PONG within an rto of the announcement carries nothing"
    );
    assert_eq!(rx.credit_resend(t0 + rto, rto), Some(newer.clone()));
    let t2 = t0 + 2 * rto;
    assert_eq!(
        rx.credit_for_pong(t2, rto),
        Some(newer.clone()),
        "an rto after the repeat, a PONG carries it"
    );
    assert_eq!(
        rx.credit_resend_deadline(rto),
        Some(t2 + rto),
        "the PONG counts as a send too"
    );
    assert_eq!(rx.credit_resend(t2 + rto, rto), Some(newer));
}

/// Spec §6.5: a `Reset` counts what it skips as taken -- the delivered
/// bytes not taken yet stay owed -- and any room is announced at once.
#[test]
fn a_reset_counts_what_it_skips_as_taken_and_announces_at_once() {
    let now = Instant::now();
    let mut rx = crediting_receiver(0);
    deliver_in_order(&mut rx, 10 * 1024);
    rx.on_consumed(4 * 1024);
    assert!(rx.on_reset(20 * 1024));
    assert_eq!(rx.unconsumed(), 6 * 1024);
    assert_eq!(
        rx.credit_due(now, true),
        Some(StreamFrame::Credit {
            stream_id: 0,
            limit: (STREAM_WINDOW + 14 * 1024) as u32
        })
    );
}

/// Spec §4.10.1: what is consumed never passes what was delivered.
#[test]
fn consumption_stops_at_what_was_delivered() {
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, 1000);
    rx.on_consumed(5000);
    assert_eq!(rx.unconsumed(), 0);
    deliver_in_order(&mut rx, 1000);
    assert_eq!(rx.unconsumed(), 1000);
}

/// Spec §4.14 with §6: limits and `CREDIT`s cross 2^32 as offsets do.
#[test]
fn credit_limits_cross_2_pow_32() {
    let start = u32::MAX - 100 * 1024 + 1;
    let mut tx = StreamSender::starting_at(20, start);
    tx.set_features(with_credits());
    let mut rx = StreamReceiver::starting_at(20, start);
    rx.set_features(with_credits());
    assert_eq!(tx.credit_limit(), Some(u64::from(start) + STREAM_WINDOW));
    deliver_in_order(&mut rx, 200 * 1024);
    rx.on_consumed(200 * 1024);
    let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(Instant::now(), false) else {
        panic!("a step was taken");
    };
    assert!(tx.on_credit(limit));
    let full = u64::from(start) + 200 * 1024 + STREAM_WINDOW;
    assert_eq!(tx.credit_limit(), Some(full));
    assert!(full > 1 << 32);
}

/// Spec §6.2: without `offset-wrap` a limit never passes `OFFSET_LIMIT`.
#[test]
fn without_offset_wrap_a_limit_stops_at_offset_limit() {
    let mut rx = StreamReceiver::starting_at(20, OFFSET_LIMIT - 1024);
    rx.set_features(Features::STREAM_CREDIT);
    assert_eq!(rx.credit_limit(), Some(u64::from(OFFSET_LIMIT)));
    assert_eq!(rx.on_data(OFFSET_LIMIT - 1024, vec![0u8; 2048]).len(), 1024);
}

/// PROBE A (review, fix round 1): a sender stopped at the implicit first
/// limit, with several newer, unheard limits announced (every CREDIT
/// before the outage was lost), desyncs; the one CREDIT that rides the
/// Reset's ACK is lost too. §6.5's `on_reset` must still leave a live
/// limit the sender's own shift lands on, so the receiver keeps
/// repeating it -- under the plain `+=` shift this stalled for good.
#[test]
fn a_lost_post_reset_credit_is_still_repeated_past_unheard_limits() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut tx = crediting_sender(0);
    let mut rx = crediting_receiver(0);
    tx.push(&vec![1u8; 542 * 1024]).expect("room");
    // Delivered and consumed at once; every CREDIT the receiver computes
    // is lost -- the sender never learns of the room the receiver grants.
    loop {
        let frames = tx.frames_to_send(t0, rto);
        if frames.is_empty() {
            break;
        }
        for f in frames {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                let _ = rx.credit_due(t0, false); // lost
            }
        }
        let _ = tx.on_ack(rx.ack());
    }
    assert_eq!(
        tx.sent_up_to(),
        STREAM_WINDOW,
        "stopped at the implicit limit"
    );

    // A long outage: the sender drops its tail and resyncs at q; the
    // urgent CREDIT that rides the Reset's ACK is lost too.
    tx.mark_desynced();
    let q = tx.begin_resync();
    assert_eq!(q, 542 * 1024);
    tx.push(b"repaint").expect("room");
    let t1 = t0 + Duration::from_secs(12);
    assert!(rx.on_reset(q as u32));
    let _ = tx.on_ack(rx.ack());
    let lost = rx.credit_due(t1, true);
    assert!(lost.is_some(), "the urgent CREDIT is computed -- and lost");

    assert!(
        rx.credit_resend_deadline(rto).is_some() || rx.credit_for_pong(t1, rto).is_some(),
        "a lost post-Reset CREDIT must still be repeated: sender holds {:?}, receiver newest {:?}",
        tx.credit_limit(),
        rx.credit_limit()
    );
}

/// PROBE B (review, fix round 1): a stuck consumer (nothing taken) gets
/// a Reset past every limit it ever announced. The sender already holds
/// `q` after its own shift, so PONGs must not keep repeating a limit it
/// already has (§6.6: a stuck consumer costs no frames).
#[test]
fn a_reset_past_every_limit_of_a_stuck_consumer_is_quiet() {
    let t0 = Instant::now();
    let mut rx = crediting_receiver(0);
    deliver_in_order(&mut rx, STREAM_WINDOW); // nothing consumed
    let q = STREAM_WINDOW + 100 * 1024;
    assert!(rx.on_reset(q as u32));
    let _ = rx.credit_due(t0, true);
    assert_eq!(
        rx.credit_for_pong(t0 + Duration::from_secs(10), Duration::from_millis(300)),
        None,
        "the sender already holds q from its own shift -- nothing to repeat"
    );
}

/// PROBE C (review, fix round 1): the desynced sender's own room is
/// less than what the repaint needs, and the one urgent CREDIT that
/// rides the Reset's ACK is lost. Nothing goes out until a CREDIT past
/// `q` arrives; the receiver's later repeats and PONGs must still
/// deliver one, and the repaint must complete. The partial fix (only
/// `on_reset`'s drop-and-push-front, without correcting `mark_desynced`'s
/// shift) still stalls here (review's Important 1).
#[test]
fn a_repaint_longer_than_the_room_still_completes_after_a_lost_urgent_credit() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut tx = crediting_sender(0);
    let mut rx = crediting_receiver(0);
    tx.push(&vec![1u8; 500 * 1024]).expect("room");
    loop {
        let frames = tx.frames_to_send(t0, rto);
        if frames.is_empty() {
            break;
        }
        for f in frames {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                let _ = rx.credit_due(t0, false); // lost
            }
        }
        let _ = tx.on_ack(rx.ack());
    }
    assert_eq!(tx.sent_up_to(), 500 * 1024);
    tx.push(&vec![2u8; 100 * 1024]).expect("room"); // output during the outage
    tx.mark_desynced();
    let q = tx.begin_resync();
    tx.push(&vec![3u8; 20 * 1024]).expect("room"); // the repaint
    let t1 = t0 + Duration::from_secs(12);
    assert!(rx.on_reset(q as u32));
    let lost = rx.credit_due(t1, true);
    assert!(lost.is_some(), "the urgent CREDIT is computed -- and lost");

    // Nothing goes out at first: the repaint is longer than the room the
    // sender gave itself.
    assert!(
        tx.frames_to_send(t1, rto)
            .iter()
            .all(|f| !matches!(f, StreamFrame::Data { .. })),
        "no room yet -- waiting for a CREDIT"
    );

    // The repeats and PONGs eventually deliver a CREDIT past q, and the
    // repaint completes.
    let mut now = t1;
    for _ in 0..5 {
        for f in tx.frames_to_send(now, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, false) {
                    tx.on_credit(limit);
                }
            }
        }
        let _ = tx.on_ack(rx.ack());
        if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_resend(now, rto) {
            tx.on_credit(limit);
        }
        if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_for_pong(now, rto) {
            tx.on_credit(limit);
        }
        now += Duration::from_secs(2);
    }
    assert_eq!(tx.sent_up_to(), q + 20 * 1024, "the repaint completed");
}

/// Spec §6.4: once data passes the limit currently being repeated, a
/// sender that turns out stopped at the NEXT older limit gets its own
/// fresh cycle of repeats -- "once for each limit it may be stopped at".
/// (Fix round 3: each growth here is a full `CREDIT_UPDATE_STEP`, not a
/// segment -- that is the only immediacy rule left for a sender that
/// may be stopped.) Fresh does not mean immediate (fix round 4, spec
/// §6.4 amended): the second limit was just announced moments ago, so
/// arming its own cycle sends nothing on the spot -- its first repeat
/// waits the same one `rto` from that announcement everyone else's
/// does.
#[test]
fn a_second_older_limit_gets_its_own_fresh_repeats() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, STREAM_WINDOW);
    rx.on_consumed(CREDIT_UPDATE_STEP);
    let first = StreamFrame::Credit {
        stream_id: 20,
        limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
    };
    assert_eq!(rx.credit_due(t0, false), Some(first.clone()));
    let mut at = t0;
    for _ in 0..CREDIT_RESENDS {
        let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
        assert_eq!(rx.credit_resend(due, rto), Some(first.clone()));
        at = due;
    }
    assert_eq!(
        rx.credit_resend_deadline(rto),
        None,
        "the first limit's repeats are spent"
    );

    // A second CREDIT_UPDATE_STEP of consumption grows the newest
    // further, past a second, still-unheard limit.
    rx.on_consumed(CREDIT_UPDATE_STEP);
    let second = StreamFrame::Credit {
        stream_id: 20,
        limit: (STREAM_WINDOW + 2 * CREDIT_UPDATE_STEP) as u32,
    };
    assert_eq!(rx.credit_due(at, false), Some(second.clone()));

    // Data reaches exactly the first limit -- the sender had it after
    // all -- so the first entry pops and the second becomes the oldest,
    // with no room to spare: possibly stopped there at once.
    assert_eq!(
        rx.on_data(STREAM_WINDOW as u32, vec![0u8; CREDIT_UPDATE_STEP as usize])
            .len() as u64,
        CREDIT_UPDATE_STEP
    );

    // Stopped again, now at the first limit's own successor: a fresh
    // cycle of repeats arms, but `second` was announced only moments
    // ago (the `credit_due(at, false)` call above) -- well under an
    // `rto` -- so nothing new goes out on the spot.
    let t2 = at + Duration::from_millis(50);
    assert_eq!(
        rx.credit_due(t2, false),
        None,
        "armed, but the newest went out less than an rto ago"
    );
    let due2 = rx
        .credit_resend_deadline(rto)
        .expect("the second limit gets its own repeats");
    assert_eq!(
        due2,
        at + rto,
        "one rto after `second` was announced, not after t2"
    );
    assert_eq!(rx.credit_resend(due2, rto), Some(second));
}

/// Spec §6.4: `urgent` still needs some growth to say anything. Once a
/// limit has been announced, calling `credit_due` again with nothing
/// consumed since says nothing new, `urgent` or not.
#[test]
fn urgent_with_nothing_grown_since_the_last_announcement_says_nothing() {
    let now = Instant::now();
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, 10 * 1024);
    rx.on_consumed(10 * 1024);
    assert!(rx.credit_due(now, true).is_some(), "growth is announced");
    assert_eq!(
        rx.credit_due(now, true),
        None,
        "urgent alone announces nothing new"
    );
}

/// Spec §6.2, §6.4: `accept_limit` is always the NEWEST announced limit
/// -- data between an older one (where a sender may be stopped) and the
/// newest is still inside the window, and is kept.
#[test]
fn data_between_an_older_limit_and_the_newest_is_kept() {
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, STREAM_WINDOW);
    rx.on_consumed(CREDIT_UPDATE_STEP);
    let now = Instant::now();
    assert!(
        rx.credit_due(now, false).is_some(),
        "a newer limit is announced"
    );
    // The oldest announced limit (the implicit first one) is still
    // live -- the sender may be stopped there -- but data between it
    // and the newest limit is still accepted, only out of order.
    let past_the_old_limit = STREAM_WINDOW + 10 * 1024;
    assert_eq!(
        rx.on_data(past_the_old_limit as u32, vec![7u8; 1024]).len(),
        0,
        "out of order -- buffered, not yet delivered"
    );
    assert_eq!(rx.buffered_cost(), 1024 + CHUNK_COST, "kept, not dropped");
}

/// RE-REVIEW PROBE D (fix round 2): the repaint's DATA overtakes a lost
/// first copy of the Reset (a `Reset` and the repaint behind it can
/// travel in different datagrams). The receiver
/// then learns of `q` with data past `q` already in hand -- proof the
/// sender holds more than `q` -- and must not report "possibly stopped"
/// at `q` regardless.
#[test]
fn a_repaint_that_overtakes_the_reset_does_not_report_stopped_at_q() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut tx = crediting_sender(0);
    let mut rx = crediting_receiver(0);
    tx.push(&vec![1u8; 100 * 1024]).expect("room");
    loop {
        let frames = tx.frames_to_send(t0, rto);
        if frames.is_empty() {
            break;
        }
        for f in frames {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t0, false) {
                    tx.on_credit(limit);
                }
            }
        }
        let _ = tx.on_ack(rx.ack());
    }
    assert_eq!(tx.sent_up_to(), 100 * 1024);
    tx.push(&vec![2u8; 50 * 1024]).expect("room"); // during the outage
    tx.mark_desynced();
    let q = tx.begin_resync();
    tx.push(&vec![3u8; 20 * 1024]).expect("room"); // the repaint
    let t1 = t0 + Duration::from_secs(12);
    // The Reset's first copy is lost; the repaint's DATA arrives.
    for f in tx.frames_to_send(t1, rto) {
        if let StreamFrame::Data { offset, data, .. } = f {
            let n = rx.on_data(offset, data).len() as u64;
            rx.on_consumed(n);
            if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t1, false) {
                tx.on_credit(limit);
            }
        }
    }
    // The Reset's repeat arrives; its CREDIT reaches the sender.
    let t2 = t1 + rto;
    assert!(rx.on_reset(q as u32));
    if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(t2, true) {
        tx.on_credit(limit);
    }
    let _ = tx.on_ack(rx.ack());
    assert_eq!(
        tx.credit_limit(),
        rx.credit_limit(),
        "the sender already holds the newest"
    );
    assert_eq!(
        rx.credit_resend_deadline(rto),
        None,
        "not possibly stopped -- data past q proves it"
    );
    assert_eq!(rx.credit_for_pong(t2, rto), None);

    // An idle screen afterward draws nothing: no repeats, no PONG-borne
    // CREDITs, over many PING intervals.
    let mut now = t2;
    for _ in 0..40 {
        for f in tx.frames_to_send(now, rto) {
            if let StreamFrame::Data { offset, data, .. } = f {
                let n = rx.on_data(offset, data).len() as u64;
                rx.on_consumed(n);
                if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, false) {
                    tx.on_credit(limit);
                }
            }
        }
        let _ = tx.on_ack(rx.ack());
        assert_eq!(rx.credit_resend(now, rto), None, "no repeat");
        assert_eq!(rx.credit_for_pong(now, rto), None, "no PONG-borne CREDIT");
        now += Duration::from_millis(1500);
    }
}

/// Spec §6.4 (fix round 2): a hostile run of forward `Reset`s of one
/// byte each keeps `Credit::announced` at `CREDIT_ANNOUNCED_MAX + 1`
/// entries at most -- one live for `q` (`on_reset`'s own push, never
/// capped) plus `CREDIT_ANNOUNCED_MAX` from growth (`credit_due`'s
/// capped push) -- and the distinct limit values it ever puts in a
/// `CREDIT` frame stay bounded the same way: once growth is capped,
/// every further `CREDIT` repeats the same frozen newest, not a fresh
/// one. Without the cap both would grow by one per `Reset`, without
/// bound.
#[test]
fn a_hostile_run_of_one_byte_resets_keeps_the_announced_list_and_its_credits_capped() {
    let mut rx = crediting_receiver(0);
    let now = Instant::now();
    let mut distinct_limits = std::collections::BTreeSet::new();
    for offset in 1..=200u32 {
        assert!(rx.on_reset(offset));
        if let Some(StreamFrame::Credit { limit, .. }) = rx.credit_due(now, true) {
            distinct_limits.insert(limit);
        }
        let len = rx.credit.as_ref().unwrap().announced.len();
        assert!(
            len <= CREDIT_ANNOUNCED_MAX + 1,
            "announced grew past the cap after Reset {offset}: {len}"
        );
    }
    assert!(
        distinct_limits.len() <= CREDIT_ANNOUNCED_MAX + 1,
        "drew {} distinct CREDIT contents from 200 one-byte Resets",
        distinct_limits.len()
    );
}

/// Spec §6.4 (fix round 2; renamed and re-scoped by fix round 3's
/// re-review, Minor 1): consumption that happens to land in exact
/// `CREDIT_UPDATE_STEP` pieces never comes near `CREDIT_ANNOUNCED_MAX`
/// -- every step is announced at once. This pins step-sized growth
/// specifically, not every honest pattern: with the segment-while-
/// possibly-stopped immediacy this test's old name claimed for it,
/// smaller pieces filled the list instead (fix round 3's report, and
/// the re-review's Minor 1). Fix round 3 removed that rule, so the
/// bound now holds for any honest consumption pattern -- see
/// `a_small_piece_consumer_behind_a_stopped_sender_draws_credits_only_per_step`.
#[test]
fn step_sized_consumption_never_hits_the_announced_cap() {
    let mut rx = crediting_receiver(20);
    let now = Instant::now();
    let mut announcements = 0;
    for _ in 0..40 {
        deliver_in_order(&mut rx, CREDIT_UPDATE_STEP);
        rx.on_consumed(CREDIT_UPDATE_STEP);
        if rx.credit_due(now, false).is_some() {
            announcements += 1;
        }
        let len = rx.credit.as_ref().unwrap().announced.len();
        assert!(
            len < CREDIT_ANNOUNCED_MAX,
            "an honest flow should stay far short of the cap: {len}"
        );
    }
    assert_eq!(
        announcements, 40,
        "every 128 KiB step is announced, exactly as without the cap"
    );
}

/// Spec §6.4 (fix round 3): a small-piece `Explicit` consumer (1 KiB
/// pieces) behind a stopped sender draws a `CREDIT` only once per full
/// `CREDIT_UPDATE_STEP` of consumption -- not once a segment, which is
/// what let this family of scenarios draw 3.6x to 260x as many `CREDIT`s
/// before this fix (fix round 3 report) -- plus the ordinary repeats if
/// that one `CREDIT` is lost.
#[test]
fn a_small_piece_consumer_behind_a_stopped_sender_draws_credits_only_per_step() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, STREAM_WINDOW);
    let piece = 1024u64;
    let pieces_per_step = CREDIT_UPDATE_STEP / piece;
    let mut announced = 0u32;
    for _ in 0..pieces_per_step {
        rx.on_consumed(piece);
        if rx.credit_due(t0, false).is_some() {
            announced += 1;
        }
    }
    assert_eq!(
        announced, 1,
        "one CREDIT for the whole step, not one a piece"
    );
    let frame = StreamFrame::Credit {
        stream_id: 20,
        limit: (STREAM_WINDOW + CREDIT_UPDATE_STEP) as u32,
    };
    assert_eq!(rx.credit_limit(), Some(STREAM_WINDOW + CREDIT_UPDATE_STEP));

    // That one CREDIT, lost: the ordinary repeats still find it, one
    // rto apart, up to CREDIT_RESENDS times, then on the PONGs.
    let mut at = t0;
    for _ in 0..CREDIT_RESENDS {
        let due = rx.credit_resend_deadline(rto).expect("a repeat is due");
        assert_eq!(rx.credit_resend(due, rto), Some(frame.clone()));
        at = due;
    }
    assert_eq!(rx.credit_resend_deadline(rto), None, "repeats spent");
    assert_eq!(rx.credit_for_pong(at + rto, rto), Some(frame));
}

/// Spec §6.4 (fix round 2): a sender stopped at the oldest of a FULL
/// `announced` list still gets the newest repeated on schedule and on
/// PONGs -- the cap only defers growth, it never stalls a stopped
/// sender -- and once data passes the oldest entry, freeing a slot, the
/// deferred growth is announced at last.
#[test]
fn a_stopped_sender_with_a_full_list_still_gets_repeats_then_the_deferred_growth() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    // Exactly the implicit first limit: the sender may be stopped there
    // from the first byte past it.
    deliver_in_order(&mut rx, STREAM_WINDOW);
    // CREDIT_ANNOUNCED_MAX - 1 rounds of one-byte consumption, urgent so
    // each announces regardless of CREDIT_UPDATE_STEP: fills the list to
    // the cap without ever moving highest_end (no more data arrives),
    // so the sender reads as stopped at the very first (oldest) limit
    // throughout.
    for _ in 0..CREDIT_ANNOUNCED_MAX - 1 {
        rx.on_consumed(1);
        assert!(rx.credit_due(t0, true).is_some());
    }
    assert_eq!(
        rx.credit.as_ref().unwrap().announced.len(),
        CREDIT_ANNOUNCED_MAX,
        "the list is at the cap"
    );
    let newest_before = rx.credit_limit().unwrap();

    // One more round of growth: deferred by the cap, not announced.
    rx.on_consumed(1);
    assert_eq!(
        rx.credit_due(t0, true),
        None,
        "the list is full -- this growth waits"
    );
    assert_eq!(
        rx.credit.as_ref().unwrap().announced.len(),
        CREDIT_ANNOUNCED_MAX,
        "still capped"
    );
    assert_eq!(
        rx.credit_limit(),
        Some(newest_before),
        "newest did not move"
    );

    // Still not stalled: the repeat armed on the very first call is
    // due, and fires.
    let due = rx
        .credit_resend_deadline(rto)
        .expect("a repeat is still due");
    assert_eq!(due, t0 + rto);
    assert_eq!(
        rx.credit_resend(due, rto),
        Some(StreamFrame::Credit {
            stream_id: 20,
            limit: newest_before as u32
        })
    );
    assert_eq!(
        rx.credit_for_pong(due + rto, rto),
        Some(StreamFrame::Credit {
            stream_id: 20,
            limit: newest_before as u32
        })
    );

    // Data passes the oldest entry by a single byte -- just enough --
    // and a slot frees.
    assert_eq!(rx.on_data(STREAM_WINDOW as u32, vec![0u8; 1]).len(), 1);
    assert_eq!(
        rx.credit.as_ref().unwrap().announced.len(),
        CREDIT_ANNOUNCED_MAX - 1,
        "the oldest popped"
    );

    // The deferred growth is announced at once.
    assert_eq!(
        rx.credit_due(t0, true),
        Some(StreamFrame::Credit {
            stream_id: 20,
            limit: (STREAM_WINDOW + CREDIT_ANNOUNCED_MAX as u64) as u32
        }),
        "the deferred growth is announced now that there is room"
    );
}

/// Spec §6.2 (fix round 2): with credits and without `offset-wrap`, a
/// `Reset` past `OFFSET_LIMIT` is refused outright -- like one past
/// `FULL_OFFSET_MAX` with `offset-wrap` -- so a credited limit never
/// breaks the ceiling every credited limit keeps. A receiver without
/// credits keeps its wider rule (`offset_end`, `u32::MAX` there).
#[test]
fn without_offset_wrap_a_credited_reset_past_offset_limit_is_refused() {
    let mut rx = StreamReceiver::new(0);
    rx.set_features(Features::STREAM_CREDIT); // credits, no offset-wrap
    assert!(
        !rx.on_reset(OFFSET_LIMIT + 1),
        "past OFFSET_LIMIT -- refused"
    );
    assert_eq!(rx.next_offset(), 0, "nothing moved");
    assert!(
        rx.on_reset(OFFSET_LIMIT),
        "exactly at OFFSET_LIMIT -- allowed"
    );
    assert_eq!(rx.next_offset(), u64::from(OFFSET_LIMIT));

    // A legacy receiver (no credits) keeps the wider rule: up to
    // `offset_end` (`u32::MAX` without `offset-wrap`), past
    // `OFFSET_LIMIT`.
    let mut legacy = StreamReceiver::new(0);
    assert!(
        legacy.on_reset(OFFSET_LIMIT + 1),
        "legacy: past OFFSET_LIMIT is fine"
    );
    assert_eq!(legacy.next_offset(), u64::from(OFFSET_LIMIT) + 1);
}

/// Minor 2 (fix round 1), pinned by fix round 2: an announce of a newer
/// limit while a repeat cycle is still armed (`resends_left > 0`)
/// refreshes `sent_at` -- the next repeat is due one `rto` after THAT
/// announce, not after whenever the cycle was first armed.
#[test]
fn an_announce_during_an_armed_repeat_refreshes_the_next_deadline() {
    let t0 = Instant::now();
    let rto = Duration::from_millis(300);
    let mut rx = crediting_receiver(20);
    deliver_in_order(&mut rx, STREAM_WINDOW);
    rx.on_consumed(CREDIT_UPDATE_STEP);
    // Arms the repeat cycle for the implicit first limit.
    assert!(rx.credit_due(t0, false).is_some());
    assert_eq!(rx.credit_resend_deadline(rto), Some(t0 + rto));

    // Part way to the first repeat, a second CREDIT_UPDATE_STEP of
    // growth is announced -- a real transmission of the newest limit --
    // while the cycle is still armed (resends_left == CREDIT_RESENDS,
    // untouched).
    let t1 = t0 + Duration::from_millis(100);
    rx.on_consumed(CREDIT_UPDATE_STEP);
    assert!(
        rx.credit_due(t1, false).is_some(),
        "the growth is announced"
    );

    // The next repeat is due one rto after THAT announce, not after t0.
    assert_eq!(rx.credit_resend_deadline(rto), Some(t1 + rto));
}
#[test]
fn capacity_wire_abort_has_a_distinct_complete_two_byte_frame() {
    assert_eq!(StreamFrame::decode_all(&[0x0a, 1]).len(), 1);
    assert!(StreamFrame::decode_all(&[0x0a]).is_empty());
}

#[test]
fn capacity_wire_frame_allocation_is_unique_and_unknown_abort_reason_roundtrips() {
    let tags = [
        TYPE_ACK,
        TYPE_DATA,
        TYPE_PING,
        TYPE_PONG,
        TYPE_CLOSE,
        TYPE_RESET,
        TYPE_PATH_PROBE,
        TYPE_PATH_PROBE_ACK,
        TYPE_CREDIT,
        TYPE_SESSION_ABORT,
    ];
    assert_eq!(
        tags.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        tags.len()
    );
    assert_eq!(TYPE_SESSION_ABORT, 0x0a);
    for reason in [
        SessionAbortReason::ResourceExhausted,
        SessionAbortReason::Unknown(200),
    ] {
        let frame = StreamFrame::SessionAbort { reason };
        let mut bytes = Vec::new();
        frame.encode(&mut bytes);
        assert_eq!(bytes, vec![0x0a, reason.to_wire()]);
        assert_eq!(StreamFrame::decode_all(&bytes), vec![frame]);
    }
}
