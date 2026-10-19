use super::*;
use std::time::Duration;

fn text(term: &TerminalCore) -> String {
    term.frame().cells.iter().map(|cell| cell.ch).collect()
}

#[test]
fn sync111_passive_flush_obeys_exact_deadline_once() {
    let mut term = TerminalCore::new(80, 24);
    term.feed(b"\x1b[?2026hDEADLINE\x1b[5n");
    let due = term.sync_deadline().unwrap();
    assert!(!term.flush_due_output(due - Duration::from_nanos(1)));
    assert!(!text(&term).contains("DEADLINE"));
    assert!(term.flush_due_output(due));
    assert!(text(&term).contains("DEADLINE"));
    assert_eq!(term.sync_deadline(), None);
    assert!(!term.flush_due_output(due + Duration::from_secs(1)));
    assert!(term.feed_with_replies(b"").unwrap().is_empty());
}

#[test]
fn sync111_authoritative_due_flush_answers_once_at_old_geometry() {
    let mut term = TerminalCore::new(80, 24);
    assert!(term
        .feed_with_replies(b"\x1b[?2026h\x1b[18t\x1b[7;11H\x1b[6n")
        .unwrap()
        .is_empty());
    let due = term.sync_deadline().unwrap();
    assert_eq!(
        term.flush_due_with_replies(due - Duration::from_nanos(1)),
        Ok(None)
    );
    assert_eq!(
        term.flush_due_with_replies(due),
        Ok(Some(b"\x1b[8;24;80t\x1b[7;11R".to_vec()))
    );
    assert_eq!(term.flush_due_with_replies(due), Ok(None));
    assert!(term.feed_with_replies(b"\x1b[?2026l").unwrap().is_empty());
}

#[test]
fn sync111_due_reply_overflow_rejects_the_whole_batch() {
    let mut term = TerminalCore::new(80, 24);
    let mut bytes = b"\x1b[?2026h".to_vec();
    bytes.extend(b"\x1b[5n".repeat(MAX_TERMINAL_REPLY_BYTES / 4 + 1));
    assert!(term.feed_with_replies(&bytes).unwrap().is_empty());
    let due = term.sync_deadline().unwrap();
    assert_eq!(
        term.flush_due_with_replies(due),
        Err(TerminalReplyError::Overflow)
    );
    assert_eq!(term.sync_deadline(), None);
}

#[test]
fn sync111_esu_manual_flush_and_restarted_bsu_replace_the_deadline() {
    let mut term = TerminalCore::new(80, 24);
    term.feed(b"\x1b[?2026hA");
    let first = term.sync_deadline().unwrap();
    term.feed(b"\x1b[?2026l");
    assert_eq!(term.sync_deadline(), None);
    assert!(!term.flush_due_output(first));
    term.feed(b"\x1b[?2026hB");
    term.flush_with_replies().unwrap();
    assert_eq!(term.sync_deadline(), None);
    term.feed(b"\x1b[?2026hC");
    let before_restart = term.sync_deadline().unwrap();
    term.feed(b"\x1b[?2026hD");
    let renewed = term.sync_deadline().unwrap();
    assert!(renewed >= before_restart);
    assert!(!term.flush_due_output(renewed - Duration::from_nanos(1)));
    assert!(term.flush_due_output(renewed));
    assert!(text(&term).contains("ABCD"));
}
