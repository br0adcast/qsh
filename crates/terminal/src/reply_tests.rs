use super::*;

#[test]
fn fresh_queries_answer_once_in_parser_order_across_every_split() {
    let query = b"\x1b[c\x1b[5n\x1b[7;11H\x1b[6n";
    let expected = b"\x1b[?6c\x1b[0n\x1b[7;11R";
    for split in 0..=query.len() {
        let mut term = TerminalCore::new(80, 24);
        let mut replies = term.feed_with_replies(&query[..split]).unwrap();
        replies.extend(term.feed_with_replies(&query[split..]).unwrap());
        assert_eq!(replies, expected, "split {split}");
        assert!(term.feed_with_replies(b"").unwrap().is_empty());
    }
}

#[test]
fn character_size_uses_current_geometry_without_fabricated_pixels() {
    let mut term = TerminalCore::new(80, 24);
    assert_eq!(
        term.feed_with_replies(b"\x1b[18t").unwrap(),
        b"\x1b[8;24;80t"
    );
    term.resize(60, 20);
    assert_eq!(
        term.feed_with_replies(b"\x1b[14t\x1b[18t").unwrap(),
        b"\x1b[8;20;60t"
    );
}

#[test]
fn passive_feed_replay_and_pending_tail_do_not_queue_answers() {
    let mut authoritative = TerminalCore::with_replay(80, 24);
    assert_eq!(
        authoritative.feed_with_replies(b"\x1b[5n").unwrap(),
        b"\x1b[0n"
    );
    assert!(authoritative
        .feed_with_replies(b"\x1b[")
        .unwrap()
        .is_empty());
    let replay = authoritative.replay().unwrap();
    authoritative.snapshot().unwrap();
    let mut passive = TerminalCore::new(80, 24);
    passive.feed(&replay);
    passive.feed(b"6n");
    assert!(passive.feed_with_replies(b"").unwrap().is_empty());
    assert_eq!(
        authoritative.feed_with_replies(b"6n").unwrap(),
        b"\x1b[1;1R"
    );
    assert!(authoritative.feed_with_replies(b"").unwrap().is_empty());
}

#[test]
fn collection_cap_is_exact_and_never_returns_a_successful_prefix() {
    let mut term = TerminalCore::new(80, 24);
    let full = b"\x1b[5n".repeat(MAX_TERMINAL_REPLY_BYTES / 4);
    let replies = term.feed_with_replies(&full).unwrap();
    assert_eq!(replies.len(), MAX_TERMINAL_REPLY_BYTES);
    assert!(replies
        .as_chunks::<4>()
        .0
        .iter()
        .all(|reply| reply == b"\x1b[0n"));
    let mut too_many = full;
    too_many.extend_from_slice(b"\x1b[5n");
    assert_eq!(
        term.feed_with_replies(&too_many),
        Err(TerminalReplyError::Overflow)
    );
    term.feed(b"\x1b[5n");
    assert!(term.feed_with_replies(b"").unwrap().is_empty());
}

#[test]
fn synchronized_update_flush_is_bounded_even_with_a_tiny_final_feed() {
    let mut term = TerminalCore::new(80, 24);
    let mut burst = b"\x1b[?2026h".to_vec();
    burst.extend(b"\x1b[5n".repeat(MAX_TERMINAL_REPLY_BYTES / 4 + 1));
    assert!(term.feed_with_replies(&burst).unwrap().is_empty());
    assert_eq!(
        term.feed_with_replies(b"\x1b[?2026l"),
        Err(TerminalReplyError::Overflow)
    );
}

#[test]
fn secondary_attributes_and_mode_reports_use_upstream_answers() {
    let mut term = TerminalCore::new(80, 24);
    assert_eq!(
        term.feed_with_replies(b"\x1b[>c\x1b[4$p\x1b[?25$p")
            .unwrap(),
        b"\x1b[>0;2600;1c\x1b[4;2$y\x1b[?25;1$y"
    );
}

#[test]
fn authoritative_repaint_returns_buffered_fresh_query_replies_once() {
    let mut term = TerminalCore::with_replay(80, 24);
    assert!(term
        .feed_with_replies(b"\x1b[?2026h\x1b[5n")
        .unwrap()
        .is_empty());
    let repaint = term.replay_with_replies().unwrap().unwrap();
    assert_eq!(repaint.replies, b"\x1b[0n");
    assert!(term
        .replay_with_replies()
        .unwrap()
        .unwrap()
        .replies
        .is_empty());
    let mut passive = TerminalCore::new(80, 24);
    passive.feed(&repaint.bytes);
    assert!(passive.feed_with_replies(b"").unwrap().is_empty());
}

#[test]
fn authoritative_repaint_rejects_a_buffered_reply_overflow_without_a_prefix() {
    let mut term = TerminalCore::with_replay(80, 24);
    let mut burst = b"\x1b[?2026h".to_vec();
    burst.extend(b"\x1b[5n".repeat(MAX_TERMINAL_REPLY_BYTES / 4 + 1));
    assert!(term.feed_with_replies(&burst).unwrap().is_empty());
    assert!(matches!(
        term.replay_with_replies(),
        Err(TerminalReplyError::Overflow)
    ));
}

#[test]
fn authoritative_flush_answers_buffered_queries_at_the_old_geometry() {
    let mut term = TerminalCore::with_replay(80, 24);
    assert!(term
        .feed_with_replies(b"\x1b[?2026h\x1b[18t")
        .unwrap()
        .is_empty());
    assert_eq!(term.flush_with_replies().unwrap(), b"\x1b[8;24;80t");
    term.resize(60, 20);
    assert_eq!(
        term.feed_with_replies(b"\x1b[18t").unwrap(),
        b"\x1b[8;20;60t"
    );
    assert!(term.flush_with_replies().unwrap().is_empty());
}
