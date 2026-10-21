// Included in session::tests. Uses the actual stdin/escape/mouse/Opening path.
#[test]
fn client179_opening_overflow_is_explicit_and_keeps_accepted_prefix() {
    let mut session = ready_session();
    session.shell_channel = ShellChannel::Opening {
        queued: VecDeque::new(),
    };
    for _ in 0..16 {
        let _ = session.handle(UiEvent::Stdin(ingress_input(vec![b'a'; 4096])), 0);
    }
    let prefix = match &session.shell_channel {
        ShellChannel::Opening { queued } => queued
            .iter()
            .flat_map(|input| input.as_slice())
            .copied()
            .collect::<Vec<_>>(),
        _ => panic!("fixture remains Opening"),
    };
    let actions = session.handle(UiEvent::Stdin(ingress_input(vec![b'z'; 4096])), 1);
    let retained = match &session.shell_channel {
        ShellChannel::Opening { queued } => queued
            .iter()
            .flat_map(|input| input.as_slice())
            .copied()
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    assert_eq!(prefix, vec![b'a'; 64 * 1024]);
    assert_eq!(
        retained, prefix,
        "no partial suffix or accepted-prefix mutation"
    );
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Notice(_))),
        "Opening overflow must report explicit local input failure"
    );
    assert!(matches!(actions.last(), Some(Action::Exit(1))));
}

#[test]
fn client179_opening_custody_moves_to_actions_and_refunds_on_final_drop() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    session.shell_channel = ShellChannel::Opening {
        queued: VecDeque::new(),
    };
    for _ in 0..16 {
        let input = budget.admit_slice(&[b'a'; 4096]).unwrap();
        assert!(session.handle(UiEvent::Stdin(input), 0).is_empty());
    }
    assert_eq!(budget.usage(), (64 * 1024, 16, 64 * 1024));
    assert!(budget.admit_slice(b"z").is_err());
    let actions = session.on_channel_ready(16, 1);
    assert_eq!(sent(&actions), vec![b'a'; 64 * 1024]);
    assert_eq!(
        budget.usage(),
        (64 * 1024, 16, 64 * 1024),
        "Ready is not action consumption"
    );
    drop(session);
    assert_eq!(budget.usage(), (64 * 1024, 16, 64 * 1024));
    drop(actions);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_opening_record_limit_is_independent_of_unique_read_count() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    session.shell_channel = ShellChannel::Opening {
        queued: VecDeque::new(),
    };
    // One read can contain ordered data fragments separated by local commands.
    let input = budget.admit_slice(&[b'x'; 17]).unwrap();
    let origin = input.origin();
    drop(input);
    for _ in 0..16 {
        assert!(session
            .queue_or_send(origin.derived(vec![b'x']), 0)
            .is_empty());
    }
    let overflow = session.queue_or_send(origin.derived(vec![b'z']), 1);
    assert!(matches!(overflow.last(), Some(Action::Exit(1))));
    assert_eq!(
        budget.usage(),
        (17, 1, 17),
        "fragments share one non-reissued read"
    );
    drop(origin);
    let actions = session.on_channel_ready(16, 2);
    assert_eq!(sent(&actions), vec![b'x'; 16]);
    drop((actions, session));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_draining_input_preserves_remote_exit_and_has_one_notice() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    let partial = budget.admit_slice(b"\x1b[<").unwrap();
    assert!(sent(&session.handle(UiEvent::Stdin(partial), 0)).is_empty());
    assert_eq!(budget.usage(), (3, 1, 3));
    session.on_channel_draining(16);
    assert_eq!(
        budget.usage(),
        (0, 0, 0),
        "retired remote parser tail releases custody"
    );
    let mut notices = 0;
    for now in 1..100 {
        session.on_channel_draining(16); // repeated snapshots must not rearm it
        let actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"no").unwrap()), now);
        assert!(sent(&actions).is_empty());
        assert!(!actions
            .iter()
            .any(|action| matches!(action, Action::Exit(_))));
        notices += actions
            .iter()
            .filter(|action| matches!(action, Action::Notice(_)))
            .count();
        assert_eq!(budget.usage(), (0, 0, 0));
        assert!(!session.shell.prediction_active());
    }
    assert_eq!(notices, 1);
    // Local status and quit remain local commands, outside remote admission.
    let status = session.handle(UiEvent::Stdin(budget.admit_slice(b"\x1dh").unwrap()), 100);
    assert!(!status
        .iter()
        .any(|action| matches!(action, Action::Exit(_))));
    assert!(session
        .on_channel_exit(16, 37, 101)
        .contains(&Action::Exit(37)));
    assert_eq!(budget.usage(), (0, 0, 0));
    let quit = session.handle(UiEvent::Stdin(budget.admit_slice(b"\x1d.").unwrap()), 102);
    assert!(quit.contains(&Action::Keep));
    assert!(quit.contains(&Action::Exit(1)));
}

#[test]
fn client179_parser_suffix_replaces_consumed_read_owners() {
    for local in [false, true] {
        let budget = crate::input_ingress::IngressBudget::default();
        let mut session = ready_session();
        if local {
            session.window = Some(Open::Roads(Roads::new()));
        }
        let first = if local {
            b"\x1b[1;".as_slice()
        } else {
            b"\x1b[<0;1;"
        };
        drop(session.handle(UiEvent::Stdin(budget.admit_slice(first).unwrap()), 0));
        assert_eq!(budget.usage(), (first.len(), 1, first.len()));
        let next = if local {
            b"2A\x1b[1;".as_slice()
        } else {
            b"1M\x1b[<0;1;"
        };
        for now in 1..65 {
            let actions = session.handle(UiEvent::Stdin(budget.admit_slice(next).unwrap()), now);
            if !local {
                assert_eq!(sent(&actions), b"\x1b[<0;1;1M");
            }
            drop(actions);
            assert_eq!(
                budget.usage(),
                (next.len(), 1, next.len()),
                "only newest suffix owner survives"
            );
        }
        drop(session);
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}

#[test]
fn client179_incomplete_mouse_tail_retains_all_unique_reads() {
    for local in [0, 1, 2] {
        let budget = crate::input_ingress::IngressBudget::default();
        let mut session = if local == 2 {
            session_with_history()
        } else {
            ready_session()
        };
        if local == 1 {
            session.window = Some(Open::Roads(Roads::new()));
        } else if local == 2 {
            drop(session.handle(UiEvent::Stdin(budget.admit_slice(b"\x1d[").unwrap()), 0));
            assert!(session.history_frame.is_some());
        }
        drop(session.handle(UiEvent::Stdin(budget.admit_slice(b"\x1b[<").unwrap()), 1));
        for now in 2..=16 {
            let actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"1").unwrap()), now);
            assert!(sent(&actions).is_empty());
            drop(actions);
        }
        assert_eq!(budget.usage(), (18, 16, 18));
        assert!(
            budget.admit_slice(b"1").is_err(),
            "unfinished tail cannot accumulate uncharged reads"
        );
        drop(session);
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}

#[test]
fn client179_local_tail_handback_retains_then_refunds_actual_owners() {
    for history in [false, true] {
        let budget = crate::input_ingress::IngressBudget::default();
        let mut session = if history {
            session_with_history()
        } else {
            ready_session()
        };
        if history {
            drop(session.handle(UiEvent::Stdin(budget.admit_slice(b"\x1d[").unwrap()), 0));
        } else {
            session.window = Some(Open::Roads(Roads::new()));
        }
        drop(session.handle(
            UiEvent::Stdin(budget.admit_slice(b"\x1b[<0;1;").unwrap()),
            1,
        ));
        assert_eq!(budget.usage(), (7, 1, 7));
        if history {
            session.close_history();
        } else {
            session.close_window();
        }
        assert_eq!(budget.usage(), (7, 1, 7), "handback is not consumption");
        let actions = session.handle(UiEvent::Stdin(budget.admit_slice(b"1M").unwrap()), 2);
        assert_eq!(sent(&actions), b"\x1b[<0;1;1M");
        assert_eq!(
            budget.usage(),
            (9, 2, 9),
            "action retains both actual read owners"
        );
        drop(actions);
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}

#[test]
fn client179_escape_fragments_keep_accepted_prefix_on_later_opening_failure() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    session.shell_channel = ShellChannel::Opening {
        queued: VecDeque::new(),
    };
    let mut read = Vec::new();
    for _ in 0..16 {
        read.extend_from_slice(b"a\x1dh"); // data, then an ordered local status toggle
    }
    read.push(b'z');
    let len = read.len();
    let actions = session.handle(UiEvent::Stdin(budget.admit_owned(read).unwrap()), 0);
    assert!(sent(&actions).is_empty());
    assert!(matches!(actions.last(), Some(Action::Exit(1))));
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, Action::Notice(_)))
            .count(),
        1
    );
    assert_eq!(budget.usage().0, len);
    assert_eq!(
        budget.usage().1,
        1,
        "fragments do not issue new read leases"
    );
    drop(actions);
    let accepted = session.on_channel_ready(16, 1);
    assert_eq!(
        sent(&accepted),
        vec![b'a'; 16],
        "rejected tail neither replaces nor replays accepted data"
    );
    drop((accepted, session));
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_mixed_escape_data_actions_keep_byte_order_and_custody() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    let actions = session.handle(
        UiEvent::Stdin(budget.admit_slice(b"a\x1dhb\x1d.c").unwrap()),
        0,
    );
    assert_eq!(
        sent(&actions),
        b"ab",
        "local quit consumes the later suffix"
    );
    let keep = actions
        .iter()
        .position(|action| matches!(action, Action::Keep))
        .unwrap();
    assert!(actions[..keep].iter().any(
        |action| matches!(action, Action::SendChannel { bytes, .. } if bytes.as_slice() == b"b")
    ));
    assert!(matches!(actions.last(), Some(Action::Exit(1))));
    assert_eq!(budget.usage(), (7, 1, 7));
    drop(actions);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_prediction_waits_for_actual_admission() {
    let mut session = Session::new(20, 5, TermCaps::truecolor(), PredictMode::Always, plain());
    session.on_link(LinkState::Live, 0);
    session.on_channel_ready(16, 0);
    let actions = session.handle(UiEvent::Stdin(ingress_input(b"prediction".to_vec())), 10);
    assert_eq!(sent(&actions), b"prediction");
    assert!(
        !session.shell.prediction_active(),
        "preparing a send is not actual admission"
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Write(_))),
        "no speculative paint before admission"
    );
}

#[test]
fn client179_reconnect_keeps_only_unaccepted_suffix_through_repeated_attach() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    let accepted = session.handle(UiEvent::Stdin(budget.admit_slice(b"old").unwrap()), 0);
    assert_eq!(sent(&accepted), b"old");
    drop(accepted); // canonical admission is the executor's separate boundary
    session.on_link_gone(1);
    let pending = session.handle(UiEvent::Stdin(budget.admit_slice(b"pending").unwrap()), 2);
    assert!(
        pending.is_empty(),
        "recoverable input is retained, not fatal"
    );
    assert_eq!(budget.usage(), (7, 1, 7));
    assert!(!session.shell.prediction_active());
    assert!(
        session.on_channel_ready(99, 3).is_empty(),
        "stale Ready cannot attach"
    );
    session.on_reattached(4);
    session.on_link_gone(5); // a failed replacement cannot drop the pending suffix
    session.on_reattached(6);
    assert!(session.on_announced(&[16], 7).is_empty());
    let ready = session.on_channel_ready(16, 8);
    assert_eq!(sent(&ready), b"pending");
    assert!(sent(&session.on_channel_ready(16, 9)).is_empty());
    drop(ready);
    assert_eq!(budget.usage(), (0, 0, 0));
}

#[test]
fn client179_confirmed_shell_loss_discards_pending_once_without_new_shell_replay() {
    let budget = crate::input_ingress::IngressBudget::default();
    let mut session = ready_session();
    session.on_link_gone(1);
    assert!(session
        .handle(
            UiEvent::Stdin(budget.admit_slice(b"old command").unwrap()),
            2
        )
        .is_empty());
    session.on_reattached(3);
    let lost = session.on_announced(&[], 4);
    assert!(lost.contains(&Action::ShellUnavailable));
    assert_eq!(budget.usage(), (0, 0, 0));
    assert_eq!(
        lost.iter()
            .filter(|a| matches!(a, Action::Notice(s) if s.contains("pending input")))
            .count(),
        1
    );
    let again = session.on_announced(&[], 5);
    assert!(!again
        .iter()
        .any(|a| matches!(a, Action::Notice(s) if s.contains("pending input"))));
    assert!(sent(&session.on_channel_ready(16, 6)).is_empty());
}
