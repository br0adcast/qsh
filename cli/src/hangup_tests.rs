// SIGHUP keeps the session: the turn's decision and the batch that carries
// it. A published but unadopted round's custody is tested in `background`.

#[test]
fn hangup_decision_keeps_only_when_no_close_was_observed() {
    use signals::{Leave, Pending};
    let hangup = Pending {
        hangup: true,
        ..Default::default()
    };
    for (pending, expected) in [
        (hangup, Some(Leave::Keep)),
        // A continue or resize observed with it changes nothing: the loop
        // measures nothing and does not reenter raw mode for a kept exit.
        (
            Pending {
                resumed: true,
                resized: true,
                ..hangup
            },
            Some(Leave::Keep),
        ),
        (
            Pending {
                terminate: true,
                ..hangup
            },
            Some(Leave::Close),
        ),
        (
            Pending {
                terminate: true,
                ..Default::default()
            },
            Some(Leave::Close),
        ),
        (
            Pending {
                suspend: true,
                resumed: true,
                ..Default::default()
            },
            None,
        ),
    ] {
        let (_home, mut links) = input_executor_links();
        assert_eq!(decide_leave(&pending, &mut links), expected, "{pending:?}");
        assert_eq!(links.keep, expected == Some(Leave::Keep), "{pending:?}");
    }
}

/// The loop puts the hangup's exit first in the batch and stops the batch
/// at the first exit, as this does: a `Terminate` queued behind it (a queue
/// disconnection) cannot turn the kept exit into a close.
#[test]
fn hangup_exit_commits_before_a_terminate_queued_behind_it() {
    let (_home, mut links) = input_executor_links();
    let mut sess = geometry_session();
    let hangup = signals::Pending {
        hangup: true,
        ..Default::default()
    };
    assert_eq!(
        decide_leave(&hangup, &mut links),
        Some(signals::Leave::Keep)
    );
    let mut stdout = Vec::new();
    let mut notices = Vec::new();
    let mut handled = Vec::new();
    let mut code = None;
    for event in [UiEvent::Hangup, UiEvent::Terminate] {
        handled.push(format!("{event:?}"));
        let actions = sess.handle(event, 0);
        code = apply_actions(actions, &mut stdout, &mut links, &mut sess, &mut notices, 0);
        if code.is_some() {
            break;
        }
    }
    assert_eq!(code, Some(1));
    assert_eq!(handled, ["Hangup"]);
    assert!(links.keep);
}
