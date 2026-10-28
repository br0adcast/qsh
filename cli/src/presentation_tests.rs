use transport::shell_frame::{encode_record, REC_ECHO_ACK};
// Included in Session's private tests: real model and renderer, supplied clock.
#[test]
fn presentation304_burst_keeps_fixed_deadline_and_latest_quiet_frame() {
    let mut s = ready_session();
    let mut physical = terminal::TerminalCore::new(20, 5);
    physical.feed(&written(&s.handle(UiEvent::Stream0(record(b"\rA")), 100)));
    let projections = s.projections;
    for (at, byte) in [(101, b'B'), (105, b'C'), (115, b'D')] {
        let actions=s.handle(UiEvent::Stream0(record(&[b'\r',byte])),at);
        assert!(written(&actions).is_empty());
        assert_eq!(s.projections,projections,"no projection/composition while staging");
        assert_eq!(s.ui_deadlines().presentation_ms,Some(116));
    }
    assert!(written(&s.handle(UiEvent::Tick,115)).is_empty());
    physical.feed(&written(&s.handle(UiEvent::Tick,116)));
    assert_eq!(physical.frame().cell(0,0).ch,'D');
    assert_eq!(s.projections,projections+1);
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    assert!(!written(&s.handle(UiEvent::Stream0(record(b"\rE")),200)).is_empty());
}

#[test]
fn presentation304_equal_pending_evaluation_clears_without_sliding_commit() {
    let mut s=ready_session();
    s.handle(UiEvent::Stream0(record(b"\rA")),100);
    s.handle(UiEvent::Stream0(record(b"\rA")),101);
    assert_eq!(s.ui_deadlines().presentation_ms,Some(116));
    assert!(written(&s.handle(UiEvent::Tick,116)).is_empty());
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    assert!(!written(&s.handle(UiEvent::Stream0(record(b"\rB")),117)).is_empty(),"equal evaluation must not restart cooldown");
}

#[test]
fn presentation304_ack_mode_sync_and_input_supersede_pending_data() {
    for boundary in [record(b"\x1b[?1h"),record(b"\x1b[?2026hSYNC\x1b[?2026l"),encode_record(REC_ECHO_ACK,&0u64.to_be_bytes())] {
        let mut s=ready_session();
        s.handle(UiEvent::Stream0(record(b"A")),100);
        s.handle(UiEvent::Stream0(record(b"B")),101);
        s.handle(UiEvent::Stream0(boundary),102);
        assert_eq!(s.ui_deadlines().presentation_ms,None);
        assert_eq!(s.last_frame.as_ref().unwrap().cell(0,1).ch,'B');
    }
    let mut s=ready_session();
    s.handle(UiEvent::Stream0(record(b"A")),100);
    s.handle(UiEvent::Stream0(record(b"B")),101);
    let actions=s.handle(UiEvent::Stdin(ingress_input(b"x".to_vec())),102);
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    assert_eq!(sent(&actions),b"x");
    assert_eq!(s.last_frame.as_ref().unwrap().cell(0,1).ch,'B');
}

#[test]
fn presentation304_zero_extent_overflow_and_pending_storage_are_bounded() {
    let mut s=ready_session();
    s.handle(UiEvent::Stream0(record(b"A")),100);
    for at in 101..116 {
        s.handle(UiEvent::Stream0(record(b"B")),at);
        assert_eq!(s.pending_presentation.as_ref().unwrap().frame.cells.len(),100);
        assert!(s.shell.spare_capacities().count()<=client::SPARE_FRAMES);
    }
    s.on_resize(0,0,115);
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    assert!(written(&s.handle(UiEvent::Tick,116)).is_empty());
    s.on_resize(20,5,117);
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    s.last_presentation_ms=Some(i64::MAX-1);
    assert!(!written(&s.handle(UiEvent::Stream0(record(b"C")),i64::MAX-1)).is_empty());
    assert_eq!(s.ui_deadlines().presentation_ms,None);
}

#[test]
fn presentation304_normal_exit_suspend_and_draining_flush_before_finish() {
    let pair=|| {
        let mut s=ready_session();
        s.handle(UiEvent::Stream0(record(b"A")),100);
        s.handle(UiEvent::Stream0(record(b"\rLAST")),101);
        s
    };
    let mut pending=pair();
    let mut control=pair();
    let mut expected=written(&control.handle(UiEvent::Tick,116));
    expected.extend(written(&control.on_channel_exit(16,0,117)));
    assert_eq!(written(&pending.on_channel_exit(16,0,102)),expected);
    assert_eq!(pending.ui_deadlines().presentation_ms,None);
    let mut pending=pair();
    let mut control=pair();
    let mut expected=written(&control.handle(UiEvent::Tick,116));
    expected.extend(control.suspend(117));
    assert_eq!(pending.suspend(102),expected);
    assert_eq!(pending.ui_deadlines().presentation_ms,None);
    let mut pending=pair();
    assert!(!written(&pending.on_channel_draining(16,102)).is_empty());
    assert_eq!(pending.ui_deadlines().presentation_ms,None);
    assert!(!written(&pending.handle(UiEvent::Stream0(record(b"TAIL")),103)).is_empty(),"draining tail remains immediate until EOF");
}

#[test]
fn presentation304_independent_status_deadline_supersedes_before_presentation_deadline() {
    let mut s=ready_session();
    s.handle(UiEvent::Stream0(record(b"A")),100);
    s.handle(UiEvent::Stream0(record(b"B")),101);
    s.line_refreshed_ms=-898; // Existing independent status deadline is102.
    assert_eq!(s.ui_deadlines().status_ms,102);
    assert!(!written(&s.handle(UiEvent::Tick,102)).is_empty());
    assert_eq!(s.ui_deadlines().presentation_ms,None);
    assert_eq!(s.last_frame.as_ref().unwrap().cell(0,1).ch,'B');
}

#[test]
fn presentation304_all_input_modes_fence_against_actual_presented_state() {
    for (on,off) in [
        (&b"\x1b[?1h"[..],&b"\x1b[?1l"[..]),
        (b"\x1b=",b"\x1b>"),
        (b"\x1b[?1000h",b"\x1b[?1000l"),
        (b"\x1b[?1006h",b"\x1b[?1006l"),
        (b"\x1b[?2004h",b"\x1b[?2004l"),
        (b"\x1b[?6h",b"\x1b[?6l"),
        (b"\x1b[?1049h",b"\x1b[?1049l"),
    ] {
        let mut s=ready_session();
        s.handle(UiEvent::Stream0(record(b"A")),100);
        s.handle(UiEvent::Stream0(record(b"B")),101);
        let original=s.presented_modes.unwrap();
        s.handle(UiEvent::Stream0(record(on)),102);
        assert_eq!(s.ui_deadlines().presentation_ms,None,"{on:?}");
        assert_ne!(s.presented_modes.unwrap(),original,"{on:?}");
        s.handle(UiEvent::Stream0(record(off)),103);
        assert_eq!(s.ui_deadlines().presentation_ms,None,"{off:?}");
        assert_eq!(s.presented_modes.unwrap(),original,"{off:?}");
    }
}

#[test]
fn presentation304_reset_gap_and_fatal_failure_cannot_replay_old_candidate() {
    for kind in 0..3 {
        let mut s=ready_session();
        s.handle(UiEvent::Stream0(record(b"A")),100);
        s.handle(UiEvent::Stream0(record(b"OLD")),101);
        assert!(s.pending_presentation.is_some());
        match kind {
            0=>{s.handle(UiEvent::StreamReset,102);},
            1=>{s.on_output_gap(OutputGapCause::PreviousConnectionOutputUnconfirmed,102);},
            _=>{s.handle(UiEvent::InputFailure(LocalInputFailure::ReaderUnavailable),102);},
        }
        assert_eq!(s.ui_deadlines().presentation_ms,None);
        if kind!=1 { assert!(written(&s.handle(UiEvent::Tick,116)).is_empty()); }
    }
}
