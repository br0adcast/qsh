// SIGHUP keeps the session: the turn's decision and the batch that carries
// it. A published but unadopted round's custody is tested in `background`.

thread_local! {
    /// Fails `enter_raw_mode` before it touches the terminal, so a test
    /// reaches `interactive`'s actual setup exit.
    pub(crate) static FAIL_RAW_MODE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The terminal work a turn asked for, in order, with scripted answers.
#[derive(Default)]
struct ScriptedTerminal {
    calls: Vec<&'static str>,
    later: signals::Pending,
    stop_fails: bool,
}

impl SignalTerminal for ScriptedTerminal {
    fn stop(&mut self) -> Result<(), ()> {
        self.calls.push("stop");
        if self.stop_fails {
            Err(())
        } else {
            Ok(())
        }
    }
    fn later(&mut self) -> signals::Pending {
        self.calls.push("later");
        self.later
    }
    fn size(&mut self) -> (u16, u16) {
        self.calls.push("size");
        (90, 30)
    }
    fn reenter(&mut self) -> Result<(), ()> {
        self.calls.push("reenter");
        Ok(())
    }
}

/// The loop's own signal turn: a chosen exit skips every terminal
/// transition and goes first; only without one does a stop run, and what it
/// brings back is decided the same way.
#[test]
fn hangup_signal_turn_decides_before_any_terminal_transition() {
    use signals::Pending;
    let none = Pending::default();
    let everything = Pending {
        resized: true,
        resumed: true,
        terminate: true,
        hangup: true,
        suspend: true,
    };
    for (name, pending, later, calls, first, keep) in [
        (
            "close+hangup+suspend+continue+resize",
            everything,
            none,
            vec![],
            vec![UiEvent::Terminate],
            false,
        ),
        (
            "hangup+suspend+continue+resize",
            Pending {
                terminate: false,
                ..everything
            },
            none,
            vec![],
            vec![UiEvent::Hangup],
            true,
        ),
        (
            "suspend, then hangup+continue",
            Pending {
                suspend: true,
                ..none
            },
            Pending {
                hangup: true,
                resumed: true,
                ..none
            },
            vec!["stop", "later"],
            vec![UiEvent::Hangup],
            true,
        ),
        (
            "suspend, then close+hangup",
            Pending {
                suspend: true,
                ..none
            },
            Pending {
                terminate: true,
                hangup: true,
                ..none
            },
            vec!["stop", "later"],
            vec![UiEvent::Terminate],
            false,
        ),
        (
            "suspend, then continue",
            Pending {
                suspend: true,
                ..none
            },
            Pending {
                resumed: true,
                ..none
            },
            vec!["stop", "later", "reenter"],
            vec![UiEvent::Resumed],
            false,
        ),
        (
            "resize",
            Pending {
                resized: true,
                ..none
            },
            none,
            vec!["size"],
            vec![UiEvent::Resized { cols: 90, rows: 30 }],
            false,
        ),
    ] {
        let (_home, mut links) = input_executor_links();
        let mut terminal = ScriptedTerminal {
            later,
            ..Default::default()
        };
        let turn = signal_turn(pending, &mut links, &mut terminal);
        assert_eq!(turn, Ok(first), "{name}");
        assert_eq!(terminal.calls, calls, "{name}");
        assert_eq!(links.keep, keep, "{name}");
    }

    let (_home, mut links) = input_executor_links();
    let mut terminal = ScriptedTerminal {
        stop_fails: true,
        ..Default::default()
    };
    let suspend = Pending {
        suspend: true,
        ..none
    };
    assert_eq!(signal_turn(suspend, &mut links, &mut terminal), Err(1));
    assert_eq!(terminal.calls, ["stop"]);
}

/// `interactive`'s actual raw-mode setup exit, reached by an injected
/// failure with an admitted live login and the signals already observed. A
/// winning hangup keeps the session; a close with it, or no signal, leaves
/// the way a setup failure always has.
#[test]
fn hangup_seen_before_a_ui_setup_failure_keeps_the_session() {
    use nix::sys::signal::{raise, Signal};
    signals::install().unwrap();
    for (raised, keep) in [
        (&[Signal::SIGHUP][..], true),
        (&[Signal::SIGHUP, Signal::SIGTERM][..], false),
        (&[][..], false),
    ] {
        let _ = signals::take_pending();
        let sink: Sink = Box::new(|_, _| Ok(()));
        let mut executor = input_executor(sink, true);
        let (_home, idle) = input_executor_links();
        let links = std::mem::replace(&mut executor.links, idle);
        assert!(links.live.is_some(), "an admitted login");
        let mut inbox = UiInbox::new().unwrap();
        let tx = inbox.renew();
        let mut display = DisplaySize {
            physical: (20, 5),
            logical: (20, 5),
        };
        for signal in raised {
            raise(*signal).unwrap();
        }
        FAIL_RAW_MODE.with(|fail| fail.set(true));
        let (code, mut links) =
            interactive(links.setup.clone(), links, &mut display, tx, &mut inbox);
        FAIL_RAW_MODE.with(|fail| fail.set(false));
        let _ = signals::take_pending();
        assert_eq!((code, links.keep), (1, keep), "{raised:?}");
        if let Some(live) = links.live.take() {
            live.attempt.detach();
        }
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
