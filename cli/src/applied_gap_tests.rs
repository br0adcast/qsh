// Encoded wire records cross the actual current-link/CLI application boundary.
mod applied_gap_tests {
    use super::*;
    use transport::channel::{encode_server, ServerRecord, CONTROL_STREAM};
    use transport::channel_geometry::{
        ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause,
    };
    use transport::shell_frame::{encode_shell, ShellRecord};

    struct Rig {
        owner: InputExecutor,
        session: Session,
        pending: Vec<u8>,
        terminal: terminal::TerminalCore,
        now: i64,
    }
    impl Rig {
        fn new() -> Self {
            let owner = input_executor(Box::new(|_, _| Ok(())), false);
            let mut session = geometry_session_with_cols(20);
            session.handle(UiEvent::Link(LinkState::Live), 0);
            let mut rig = Self {
                owner,
                session,
                pending: Vec::new(),
                terminal: terminal::TerminalCore::new(20, 5),
                now: 1,
            };
            let opened = encode_server(&ServerRecord::Opened { stream: 16 });
            rig.wire(1, CONTROL_STREAM, &opened);
            rig.record(16, ShellRecord::Geometry(Self::geometry(1)));
            assert!(rig
                .owner
                .links
                .live
                .as_ref()
                .unwrap()
                .channel_session
                .is_ready(16));
            rig
        }
        fn geometry(instance: u64) -> GeometryRecord {
            GeometryRecord {
                instance: ChannelInstance::new(instance).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 20,
                rows: 5,
            }
        }
        fn paint(&mut self, actions: &[Action]) -> Vec<String> {
            let mut states = Vec::new();
            for action in actions {
                if let Action::Write(bytes) = action {
                    self.terminal.feed(bytes);
                    states.push(self.text());
                }
            }
            states
        }
        fn text(&self) -> String {
            self.terminal
                .frame()
                .cells
                .iter()
                .map(|cell| cell.ch)
                .collect()
        }
        fn event(&mut self, link: u64, event: UiEvent) -> (Vec<Action>, Vec<String>) {
            self.now += 1;
            let current = self.owner.links.current(UiEvent::FromLink {
                link,
                event: Box::new(event),
            });
            let actions = match current {
                Some(UiEvent::Wire { stream, bytes }) => on_wire(
                    stream,
                    &bytes,
                    &mut self.owner.links,
                    &mut self.session,
                    &mut self.pending,
                    &|| self.now,
                ),
                Some(UiEvent::WireReset(stream)) => on_wire_reset(
                    stream,
                    &mut self.owner.links,
                    &mut self.session,
                    &mut self.pending,
                    &|| self.now,
                ),
                None => Vec::new(),
                _ => panic!("fixture accepts only stamped wire/reset events"),
            };
            let states = self.paint(&actions);
            (actions, states)
        }
        fn wire(&mut self, link: u64, stream: u8, bytes: &[u8]) -> (Vec<Action>, Vec<String>) {
            self.event(
                link,
                UiEvent::Wire {
                    stream,
                    bytes: bytes.to_vec(),
                },
            )
        }
        fn record(&mut self, stream: u8, record: ShellRecord) -> (Vec<Action>, Vec<String>) {
            self.wire(1, stream, &encode_shell(&record).unwrap())
        }
        fn flush(&mut self) -> Vec<String> {
            let actions = flush_shell_bytes(&mut self.pending, &mut self.session, self.now);
            self.paint(&actions)
        }
        fn data(&mut self, text: &[u8]) {
            self.record(16, ShellRecord::Data(text.to_vec()));
            self.flush();
            // Existing assertions inspect a completed presentation. Service its
            // actual deadline; tests of a held candidate use record/flush directly.
            if let Some(at) = self.session.ui_deadlines().presentation_ms {
                self.now = at;
                let actions = self.session.handle(UiEvent::Tick, at);
                self.paint(&actions);
            }
        }
    }
    fn gap(instance: u64) -> ShellRecord {
        ShellRecord::OutputGap {
            instance: ChannelInstance::new(instance).unwrap(),
            cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
        }
    }

    #[test]
    fn presentation304_main_deadline_delivers_latest_snapshot_and_gap_cancels_it() {
        let mut rig = Rig::new();
        rig.now = 100;
        rig.data(b"A");
        rig.record(16, ShellRecord::Data(b"B".to_vec()));
        rig.flush();
        let due = rig.session.ui_deadlines().presentation_ms.unwrap();
        assert_eq!(due, 117);
        assert!(!rig.text().contains("AB"));
        let origin = Instant::now();
        assert_eq!(session_deadline(&rig.session, origin, None),
            Some(origin + Duration::from_millis(due as u64)));
        let inbox = UiInbox::new().unwrap();
        let mut events = Vec::new();
        collect_ui_turn(&inbox, &mut events, session_deadline(&rig.session, origin, None),
            origin + Duration::from_millis(due as u64));
        assert!(matches!(events.as_slice(), [UiEvent::Tick]));
        let actions = rig.session.handle(events.pop().unwrap(), due);
        rig.paint(&actions);
        rig.now = due;
        assert!(rig.text().contains("AB"));
        assert!(rig.session.ui_deadlines().presentation_ms.is_none());
        rig.record(16, ShellRecord::Data(b"C".to_vec()));
        rig.flush();
        assert!(rig.session.ui_deadlines().presentation_ms.is_some());
        let (_, states) = rig.record(16, gap(1));
        assert!(states.first().is_some_and(|frame| frame.contains("ABC")));
        assert!(rig.session.ui_deadlines().presentation_ms.is_none());
        assert!(rig.text().contains("Output continuity"));
    }

    #[test]
    fn applied_gap_selected_wire_flushes_prior_output_before_notice_and_keeps_current_state() {
        let mut rig = Rig::new();
        rig.record(16, ShellRecord::Data(b"PRIOR".to_vec()));
        assert!(!rig.pending.is_empty());
        assert!(!rig.text().contains("PRIOR"));
        let (actions, states) = rig.record(16, gap(1));
        assert!(
            rig.pending.is_empty(),
            "gap must flush the decoded prefix before application"
        );
        assert!(actions.iter().all(|a| !matches!(a, Action::Exit(_))));
        assert!(
            states.first().is_some_and(|state| state.contains("PRIOR")),
            "actual first paint must contain the queued prefix: {states:?}"
        );
        assert!(
            rig.text().contains("Output continuity"),
            "actual selected gap must reach visible Session continuity state: {:?}",
            rig.text()
        );
        // Reset retains the instance and its continuity warning; it must not
        // masquerade as replacement. Fresh repaint bytes still become current.
        rig.event(1, UiEvent::WireReset(16));
        rig.record(16, ShellRecord::Geometry(Rig::geometry(1)));
        rig.data(b"\x1b[2J\x1b[HFRESH");
        // The continuity overlay remains intentional for the same instance;
        // verify the actual model also retained newly applied lower rows.
        rig.data(b"\x1b[4;1HCURRENT");
        assert!(rig.text().contains("CURRENT"));
        rig.data(b"\x1b[4;1H\x1b[2KERASED");
        assert!(
            !rig.text().contains("CURRENT"),
            "past marker cannot certify the current terminal"
        );
        assert!(rig.text().contains("ERASED"));
    }

    #[test]
    fn applied_gap_wire_rejects_stale_link_and_ignores_other_selected_channel() {
        let mut rig = Rig::new();
        rig.data(b"KEEP");
        let before = rig.text();
        let stale = encode_shell(&gap(1)).unwrap();
        assert!(rig.wire(99, 16, &stale).0.is_empty());
        assert!(rig.event(99, UiEvent::WireReset(16)).0.is_empty());
        assert_eq!(rig.text(), before);
        // A genuinely opened second channel is parsed, but is not the CLI's
        // selected shell and therefore cannot apply its continuity notice.
        let other = rig
            .owner
            .links
            .live
            .as_mut()
            .unwrap()
            .channel_session
            .open_shell(20, 5)
            .unwrap();
        rig.wire(
            1,
            CONTROL_STREAM,
            &encode_server(&ServerRecord::Opened { stream: other }),
        );
        rig.record(other, ShellRecord::Geometry(Rig::geometry(2)));
        assert!(rig.record(other, gap(2)).0.is_empty());
        assert!(
            rig.owner
                .links
                .live
                .as_ref()
                .unwrap()
                .channel_session
                .continuity_lost(other),
            "a decoded other-channel gap is not a selected UI application"
        );
        assert_eq!(rig.text(), before);
        rig.event(1, UiEvent::WireReset(other));
        assert_eq!(rig.text(), before);
        assert_eq!(rig.owner.links.shell_channel, Some(16));
    }

    #[test]
    fn applied_gap_wrong_instance_fails_closed_before_notice_application() {
        let mut rig = Rig::new();
        rig.record(16, ShellRecord::Data(b"PREFIX".to_vec()));
        let (actions, states) = rig.record(16, gap(2));
        assert!(states.iter().any(|state| state.contains("PREFIX")));
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Notice(text) if text.contains("Instance"))));
        assert!(matches!(actions.last(), Some(Action::Exit(1))));
        assert!(!rig.text().contains("Output continuity"));
    }

    #[test]
    fn applied_gap_reset_drops_selected_partial_record_but_preserves_control_fragment() {
        let mut rig = Rig::new();
        rig.data(b"KEPTGRID");
        let stale = encode_shell(&ShellRecord::Data(b"STALE".to_vec())).unwrap();
        rig.wire(1, 16, &stale[..3]);
        // Preserve the control deframer across a reset of only channel16.
        let exit = encode_server(&ServerRecord::Exit {
            stream: 16,
            code: 0,
        });
        rig.wire(1, CONTROL_STREAM, &exit[..2]);
        let (actions, _) = rig.event(1, UiEvent::WireReset(16));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Write(bytes) if !bytes.is_empty())),
            "reset must invalidate rendered state and repaint"
        );
        assert!(
            rig.text().contains("KEPTGRID"),
            "reset does not clear the visible grid before repaint"
        );
        rig.record(16, ShellRecord::Geometry(Rig::geometry(1)));
        rig.data(b"\x1b[2J\x1b[HREPAINTED");
        assert!(rig.text().contains("REPAINTED"));
        assert!(!rig.text().contains("STALE"));
        let (actions, _) = rig.wire(1, CONTROL_STREAM, &exit[2..]);
        assert!(
            matches!(actions.last(), Some(Action::Exit(0))),
            "CONTROL partial frame survives selected reset: {actions:?}"
        );
        assert!(actions
            .iter()
            .all(|a| !matches!(a, Action::Notice(text) if text.contains("protocol failure"))));
    }
}
