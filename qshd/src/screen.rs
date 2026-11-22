//! The session's own model of the screen.
//!
//! The daemon runs a second emulator per shell session: PTY output goes both
//! to the wire and through this model. It costs memory and a second parse of
//! the output; it buys the behavior people keep mosh for -- the laptop wakes
//! up and the screen is right.
//!
//! After a long absence the transport stops hoarding output (`RESYNC_AFTER`
//! in `crates/transport/src/conn.rs`): replaying an hour of `htop` would be
//! worse than useless. What is dropped can only be recovered from a model of
//! the result, which is this. On the client's return the transport resets the
//! output stream and asks the backend to repaint; [`PtyScreen::repaint`] is
//! the answer.

//! Daemon models keep zero scrollback history: scrollback belongs to clients.
//! Content scrolled out or dropped by a smaller height does not return when
//! the model grows. Repaints describe the retained visible state at its size.

use crate::screen_budget::{ResizeReservation, ScreenBudget, ScreenLease};
use std::sync::Arc;
use terminal::{Frame, TerminalCore, TerminalOptions};
use terminal_size::TerminalSize;
use transport::shell_server::{
    PreparedScreenResize, ScreenPreparationError, ScreenRepaint, ScreenReplyError, SessionScreen,
};

/// A shell session's screen: the emulator that follows the output.
pub struct PtyScreen {
    term: TerminalCore,
    lease: ScreenLease,
}

impl PtyScreen {
    /// Reserve the shared daemon budget before allocating an emulator.
    pub fn try_new(
        size: TerminalSize,
        uid: u32,
        budget: Arc<ScreenBudget>,
    ) -> Result<Self, String> {
        let lease = budget.reserve(uid, size)?;
        Ok(Self {
            term: TerminalCore::with_options(
                size,
                TerminalOptions {
                    history_lines: 0,
                    replay: true,
                },
            ),
            lease,
        })
    }

    /// The screen as the model sees it. For tests and for callers that want
    /// to compare the two sides.
    pub fn frame(&self) -> Frame {
        self.term.frame()
    }

    /// Everything the repaint restores, to compare the two sides by.
    #[cfg(test)]
    pub fn snapshot(&mut self) -> terminal::StateSnapshot {
        self.term.snapshot().expect("the model is made to replay")
    }
}

struct ScreenResize<'a> {
    term: &'a mut TerminalCore,
    reservation: ResizeReservation<'a>,
    size: TerminalSize,
}

impl PreparedScreenResize for ScreenResize<'_> {
    fn commit(self: Box<Self>) {
        self.term.resize_to(self.size);
        self.reservation.commit();
    }
}

impl SessionScreen for PtyScreen {
    fn absorb(&mut self, bytes: &[u8]) -> Result<Vec<u8>, ScreenReplyError> {
        self.term
            .feed_with_replies(bytes)
            .map_err(|error| match error {
                terminal::TerminalReplyError::Overflow => ScreenReplyError::Overflow,
            })
    }

    fn flush_pending_output(&mut self) -> Result<Vec<u8>, ScreenReplyError> {
        self.term.flush_with_replies().map_err(|error| match error {
            terminal::TerminalReplyError::Overflow => ScreenReplyError::Overflow,
        })
    }

    fn sync_deadline(&self) -> Option<std::time::Instant> {
        self.term.sync_deadline()
    }

    fn flush_due_output(&mut self, now: std::time::Instant) -> Result<Vec<u8>, ScreenReplyError> {
        self.term
            .flush_due_with_replies(now)
            .map(|replies| replies.unwrap_or_default())
            .map_err(|error| match error {
                terminal::TerminalReplyError::Overflow => ScreenReplyError::Overflow,
            })
    }

    fn prepare_resize(
        &mut self,
        size: TerminalSize,
    ) -> Result<Box<dyn PreparedScreenResize + '_>, ScreenPreparationError> {
        let reservation = self
            .lease
            .prepare(size)
            .map_err(ScreenPreparationError::ResourceLimit)?;
        Ok(Box::new(ScreenResize {
            term: &mut self.term,
            reservation,
            size,
        }))
    }

    /// The model's replay (`TerminalCore::replay`): the client's emulator,
    /// having seen some prefix of this output and then nothing, ends in the
    /// model's state -- both screens, the cursor, the pen, the scroll region,
    /// the character sets, every mode, and the unfinished escape sequence the
    /// output stopped in -- so the live output after it lands the same on
    /// both. On the primary screen the rows are rewritten in place: nothing
    /// scrolls, and the client's scrollback keeps what it had. It starts
    /// with ESC, which ends any sequence the client was left inside.
    fn repaint(&mut self) -> Result<ScreenRepaint, ScreenReplyError> {
        let repaint = self
            .term
            .replay_with_replies()
            .map_err(|error| match error {
                terminal::TerminalReplyError::Overflow => ScreenReplyError::Overflow,
            })?
            .expect("the model is made to replay (`PtyScreen::try_new`)");
        Ok(ScreenRepaint {
            bytes: repaint.bytes,
            replies: repaint.replies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn screen(cols: u16, rows: u16) -> PtyScreen {
        PtyScreen::try_new(
            TerminalSize::new(cols, rows).unwrap(),
            1,
            Arc::new(ScreenBudget::new(
                crate::screen_budget::BudgetLimits::default(),
            )),
        )
        .unwrap()
    }

    fn resize(screen: &mut PtyScreen, cols: u16, rows: u16) {
        screen
            .prepare_resize(TerminalSize::new(cols, rows).unwrap())
            .unwrap()
            .commit();
    }

    #[test]
    fn replies_follow_committed_size_and_cancelled_resizes_stay_silent() {
        let budget = Arc::new(ScreenBudget::new(crate::screen_budget::BudgetLimits {
            global_cells: 100_000,
            owner_cells: 100_000,
            ..Default::default()
        }));
        let mut screen = PtyScreen::try_new(TerminalSize::new(80, 24).unwrap(), 1, budget).unwrap();
        assert!(screen
            .prepare_resize(TerminalSize::new(512, 256).unwrap())
            .is_err());
        drop(
            screen
                .prepare_resize(TerminalSize::new(60, 20).unwrap())
                .unwrap(),
        );
        assert_eq!(screen.absorb(b"\x1b[18t").unwrap(), b"\x1b[8;24;80t");
        resize(&mut screen, 60, 20);
        assert_eq!(
            screen.absorb(b"\x1b[18t\x1b[7;11H\x1b[6n").unwrap(),
            b"\x1b[8;20;60t\x1b[7;11R"
        );
        screen.repaint().unwrap();
        screen.snapshot();
        assert!(screen.absorb(b"").unwrap().is_empty());
    }

    #[test]
    fn repaint_flushes_buffered_fresh_queries_once() {
        let mut screen = screen(80, 24);
        assert!(screen.absorb(b"\x1b[?2026h\x1b[5n").unwrap().is_empty());
        let repaint = screen.repaint().unwrap();
        assert_eq!(repaint.replies, b"\x1b[0n");
        let mut passive = TerminalCore::new(80, 24);
        passive.feed(&repaint.bytes);
        assert!(passive.feed_with_replies(b"").unwrap().is_empty());
        assert!(screen.repaint().unwrap().replies.is_empty());
    }

    #[test]
    fn explicit_flush_answers_at_old_geometry_before_preparation() {
        let mut screen = screen(80, 24);
        assert!(screen.absorb(b"\x1b[?2026h\x1b[18t").unwrap().is_empty());
        assert_eq!(screen.flush_pending_output().unwrap(), b"\x1b[8;24;80t");
        resize(&mut screen, 60, 20);
        assert!(screen.repaint().unwrap().replies.is_empty());
        assert_eq!(screen.absorb(b"\x1b[18t").unwrap(), b"\x1b[8;20;60t");
    }

    #[test]
    fn reply_overflow_is_typed_and_raw_channels_have_no_hidden_responder() {
        let mut screen = screen(80, 24);
        let queries = b"\x1b[5n".repeat(terminal::MAX_TERMINAL_REPLY_BYTES / 4 + 1);
        assert_eq!(screen.absorb(&queries), Err(ScreenReplyError::Overflow));
        let mut raw = transport::shell_server::NoScreen;
        assert_eq!(raw.absorb(&queries), Ok(Vec::new()));
    }

    /// Cell equality for the round trip: every field. The replay makes a
    /// wide character's placeholder at the end of a row the way the model
    /// made it -- by printing the wide character there and letting it wrap --
    /// so even `FLAG_LEADING_WIDE_SPACER` comes back.
    fn cells_match_for_repaint(a: &terminal::Cell, b: &terminal::Cell) -> bool {
        a == b
    }

    /// Compare two frames and, on a mismatch, say WHERE -- a bare
    /// `assert_eq!` on ten thousand cells prints a wall nobody can read.
    ///
    /// Does not compare `Frame.palette`: nothing this encoder writes changes
    /// the palette, so there is nothing here that could make it diverge.
    fn assert_frames_match(want: &terminal::Frame, got: &terminal::Frame, case: &str) {
        assert_eq!(
            (want.cols, want.rows),
            (got.cols, got.rows),
            "[{case}] geometry"
        );
        for row in 0..want.rows {
            for col in 0..want.cols {
                let a = want.cell(row, col);
                let b = got.cell(row, col);
                assert!(
                    cells_match_for_repaint(a, b),
                    "[{case}] cell ({row},{col}) differs\n  server: {a:?}\n  client: {b:?}"
                );
            }
        }
        assert_eq!(
            (want.cursor_row, want.cursor_col),
            (got.cursor_row, got.cursor_col),
            "[{case}] cursor position"
        );
        assert_eq!(
            want.cursor_visible, got.cursor_visible,
            "[{case}] cursor visibility"
        );
        assert_eq!(want.app_cursor, got.app_cursor, "[{case}] DECCKM");
        assert_eq!(want.app_keypad, got.app_keypad, "[{case}] DECKPAM");
        assert_eq!(want.origin_mode, got.origin_mode, "[{case}] DECOM");
        assert_eq!(
            want.mouse_tracking, got.mouse_tracking,
            "[{case}] mouse tracking"
        );
        assert_eq!(want.mouse_sgr, got.mouse_sgr, "[{case}] SGR mouse");
        assert_eq!(
            want.bracketed_paste, got.bracketed_paste,
            "[{case}] bracketed paste"
        );
        assert_eq!(want.alt_screen, got.alt_screen, "[{case}] alternate screen");
    }

    /// Feed `script` into a server-side model, take its repaint, feed that
    /// into a FRESH client-side emulator, and require the two screens to be
    /// the same. This is the property the repaint mechanism rests on:
    /// whatever the shell did during the gap, the repaint reconstructs it.
    fn round_trip(case: &str, cols: u16, rows: u16, script: &[&[u8]]) {
        let mut screen = screen(cols, rows);
        for chunk in script {
            screen.absorb(chunk).unwrap();
        }
        let repaint = screen.repaint().unwrap().bytes;
        let mut client = terminal::TerminalCore::new(cols, rows);
        client.feed(&repaint);
        assert_frames_match(&screen.frame(), &client.frame(), case);
    }

    /// A PTY read can end inside a UTF-8 sequence. The model, and the
    /// repaint a reattaching client gets, must be those of the unsplit
    /// output, the character after the split included (#354).
    #[test]
    fn output_split_inside_a_utf8_sequence_models_and_repaints_unsplit() {
        let text = "д п р e\u{301}h\u{300}z ïcø".as_bytes();
        let mut whole = screen(30, 3);
        whole.absorb(text).unwrap();
        let expected = whole.repaint().unwrap().bytes;
        for at in 0..=text.len() {
            let mut split = screen(30, 3);
            split.absorb(&text[..at]).unwrap();
            split.absorb(&text[at..]).unwrap();
            assert_eq!(split.frame(), whole.frame(), "split at {at}");
            assert_eq!(split.repaint().unwrap().bytes, expected, "split at {at}");
        }
        assert_eq!(row_text(&whole.frame(), 0), "д п р ehz ïcø");
        round_trip("split utf-8", 30, 3, &[&text[..1], &text[1..]]);
    }

    #[test]
    fn zero_history_does_not_restore_scrolled_content_after_growth() {
        let mut screen = screen(8, 2);
        screen.absorb(b"LOST\r\nkept\r\nlast").unwrap();
        resize(&mut screen, 8, 4);
        assert!((0..screen.frame().rows).all(|r| row_text(&screen.frame(), r) != "LOST"));
        let mut client = TerminalCore::new(8, 4);
        client.feed(&screen.repaint().unwrap().bytes);
        assert_frames_match(&screen.frame(), &client.frame(), "zero history growth");
    }

    #[test]
    fn screen_budget_model_resize_cancellation_preserves_frame_and_credits() {
        let budget = Arc::new(ScreenBudget::new(
            crate::screen_budget::BudgetLimits::default(),
        ));
        let mut screen =
            PtyScreen::try_new(TerminalSize::new(2, 1).unwrap(), 1, budget.clone()).unwrap();
        screen.absorb(b"ok").unwrap();
        let before = budget.used();
        let frame = screen.frame();
        drop(
            screen
                .prepare_resize(TerminalSize::new(2, 2).unwrap())
                .unwrap(),
        );
        assert_eq!(budget.used(), before);
        assert_frames_match(&frame, &screen.frame(), "cancel resize");
        screen
            .prepare_resize(TerminalSize::new(2, 2).unwrap())
            .unwrap()
            .commit();
        assert_eq!((screen.frame().cols, screen.frame().rows), (2, 2));
        drop(screen);
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
    }

    #[test]
    fn plain_text_survives_a_repaint() {
        round_trip("plain", 40, 10, &[b"hello\r\nworld\r\n"]);
    }

    #[test]
    fn colors_survive_a_repaint() {
        round_trip(
            "colors",
            40,
            10,
            &[b"\x1b[31mred\x1b[0m \x1b[38;5;200mindexed\x1b[0m \x1b[38;2;10;20;30mrgb\x1b[0m"],
        );
    }

    #[test]
    fn attributes_survive_a_repaint() {
        round_trip(
            "attributes",
            40,
            10,
            &[b"\x1b[1mbold\x1b[0m \x1b[4munder\x1b[0m \x1b[7mrev\x1b[0m"],
        );
    }

    #[test]
    fn the_cursor_lands_where_it_was() {
        round_trip("cursor", 40, 10, &[b"\x1b[5;7Hx\x1b[3;2H"]);
    }

    #[test]
    fn a_hidden_cursor_stays_hidden() {
        round_trip("hidden cursor", 40, 10, &[b"text\x1b[?25l"]);
    }

    /// Origin mode reached the way an application actually reaches it: a
    /// scroll region, then `?6h`, then output and a cursor move -- not the
    /// bare toggle on its own, which would leave the cursor sitting right
    /// where the bug this test was written to catch would also put it. That
    /// bug: `repaint` turning `?6h` on as its trailing byte with nothing
    /// re-placing the cursor afterwards -- `alacritty_terminal`'s DECOM
    /// handler homes the cursor to the scroll region's start as a side
    /// effect of the mode toggle, so a client fed the naive byte order ends
    /// up with its cursor at the region's home instead of where the model's
    /// really is.
    #[test]
    fn origin_mode_keeps_the_cursor_in_place() {
        round_trip("origin mode", 40, 20, &[b"\x1b[5;15r\x1b[?6h\x1b[3;10Hhi"]);
    }

    /// The alternate screen, drawn in -- the vim case the module's own docs
    /// use as the motivating example for restoring `?1049` at all.
    #[test]
    fn alternate_screen_survives_a_repaint() {
        round_trip(
            "alt screen",
            40,
            10,
            &[b"\x1b[?1049hvim-like content\x1b[3;5H"],
        );
    }

    /// The client applies the repaint to a model that is NOT blank: this is
    /// the real shape of a resync, since `on_reset` clears the deframer and
    /// the prediction, not the screen.
    #[test]
    fn a_repaint_overwrites_a_stale_screen() {
        let mut screen = screen(40, 10);
        screen.absorb(b"\x1b[2J\x1b[HFRESH").unwrap();
        let repaint = screen.repaint().unwrap().bytes;

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[2J\x1b[HSTALE CONTENT FROM BEFORE THE GAP\r\nsecond line");
        client.feed(&repaint);

        assert_frames_match(&screen.frame(), &client.frame(), "stale overwrite");
    }

    /// Two resyncs in a row happen (the link flaps): the second repaint must
    /// leave the same screen, not double anything up.
    #[test]
    fn repainting_twice_is_stable() {
        let mut screen = screen(40, 10);
        screen.absorb(b"one\r\ntwo\r\nthree").unwrap();
        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(&screen.repaint().unwrap().bytes);
        let after_first = client.frame();
        client.feed(&screen.repaint().unwrap().bytes);
        assert_frames_match(&after_first, &client.frame(), "second repaint");
    }

    /// The model has to follow the size, or a repaint after a resize draws
    /// the old geometry -- and the repaint of a RESIZED model has to round
    /// trip just like any other.
    #[test]
    fn the_model_follows_a_resize() {
        let mut screen = screen(40, 10);
        resize(&mut screen, 100, 30);
        screen.absorb(b"wide after the resize").unwrap();
        let frame = screen.frame();
        assert_eq!((frame.cols, frame.rows), (100, 30));

        let repaint = screen.repaint().unwrap().bytes;
        let mut client = terminal::TerminalCore::new(100, 30);
        client.feed(&repaint);
        assert_frames_match(&screen.frame(), &client.frame(), "after resize");
    }

    /// Content laid out at the OLD geometry and then reflowed by the resize
    /// -- the path `the_model_follows_a_resize` above never takes, because
    /// it resizes an EMPTY screen and only then writes. Zero-history shrinking drops
    /// scrolled-out rows permanently; and a wide character or
    /// a raw `\t` cell can land anywhere in the reflowed grid; the round
    /// trip has to survive all of that, in both directions and in each
    /// dimension separately.
    #[test]
    fn content_laid_out_before_a_resize_still_round_trips() {
        // Newlines (so the zero-history screen scrolls), tabs (the
        // `\t` cell `repaint` recovers by hand), wide characters and color.
        let mut script = Vec::new();
        for i in 1..=14 {
            script.extend_from_slice(
                format!("row-{i}\tafter\ttab {i} 你好世界 🙂 end\r\n").as_bytes(),
            );
        }
        script.extend_from_slice(b"\x1b[31mtail with no newline\x1b[0m");

        for (cols, rows) in [(100u16, 30u16), (20, 5), (40, 30), (100, 6), (40, 10)] {
            let mut screen = screen(40, 10);
            screen.absorb(&script).unwrap();
            resize(&mut screen, cols, rows);

            let mut client = terminal::TerminalCore::new(cols, rows);
            client.feed(&screen.repaint().unwrap().bytes);
            assert_frames_match(
                &screen.frame(),
                &client.frame(),
                &format!("40x10 laid out, then resized to {cols}x{rows}"),
            );
        }
    }

    /// The text of one row, trimmed -- for assertions about WHAT is on the
    /// screen rather than about every attribute of every cell.
    fn row_text(frame: &terminal::Frame, row: u16) -> String {
        let raw: String = (0..frame.cols).map(|c| frame.cell(row, c).ch).collect();
        raw.trim_end().to_string()
    }

    /// Why the transport repaints a SECOND time once the client's resize
    /// record lands (`repainted_since_resize` in
    /// `crates/transport/src/shell_server.rs`). The encoder addresses rows and
    /// columns absolutely, so a repaint of an 80x24 model applied by a
    /// client that is now 60x20 cannot describe the rows past the client's
    /// bottom at all -- they collapse onto the last row and are gone for
    /// good, because an ordinary shell never redraws by itself. Once the
    /// model has been told the new size, the same round trip is exact again.
    #[test]
    fn a_repaint_at_the_wrong_geometry_loses_rows_and_a_resized_one_does_not() {
        let mut screen = screen(80, 24);
        let mut script = Vec::new();
        for line in 1..=24u16 {
            script.extend_from_slice(format!("\x1b[{line};1Hline-{line}").as_bytes());
        }
        screen.absorb(&script).unwrap();

        // The client came back smaller, and the repaint went out ahead of
        // its resize record.
        let mut small = terminal::TerminalCore::new(60, 20);
        small.feed(&screen.repaint().unwrap().bytes);
        let shown = small.frame();
        assert_eq!(
            row_text(&shown, 0),
            "line-1",
            "the repaint did arrive -- the loss below is about geometry, not about nothing being drawn"
        );
        for lost in [21u16, 22, 23] {
            let wanted = format!("line-{lost}");
            assert!(
                (0..shown.rows).all(|r| row_text(&shown, r) != wanted),
                "a repaint of an 80x24 model cannot put {wanted} on a 60x20 client"
            );
        }

        // ...and once the model follows the size, the client is exact again.
        resize(&mut screen, 60, 20);
        let mut small = terminal::TerminalCore::new(60, 20);
        small.feed(&screen.repaint().unwrap().bytes);
        assert_frames_match(&screen.frame(), &small.frame(), "repaint after the resize");
    }

    /// Every scenario worth doubting, in one table. A new case here is
    /// cheaper than a bug report from a laptop that woke up wrong.
    #[test]
    fn the_corpus_survives_a_repaint() {
        let cases: &[(&str, u16, u16, &[u8])] = &[
            ("cjk", 40, 10, "hello 你好世界 end".as_bytes()),
            // Precomposed Latin diacritics are 2-byte UTF-8 but only one
            // column wide, unlike CJK (3 bytes, width 2 above) and emoji (4
            // bytes, width 2 below). That is exactly the boundary where
            // byte offsets and column offsets are easiest to confuse, so
            // this case mixes both classes on one line rather than testing
            // them in isolation -- a byte/column mismatch that only shows
            // up once the running offsets from two different widths
            // interleave would pass either class alone.
            (
                "latin diacritics",
                40,
                10,
                "café 你好世界 señor end".as_bytes(),
            ),
            ("emoji", 40, 10, "start 🙂🙃 end".as_bytes()),
            ("cjk at the right edge", 10, 4, "aaaaaaaaa你".as_bytes()),
            (
                "alternate screen",
                40,
                10,
                b"before\x1b[?1049h\x1b[2J\x1b[Hinside the app",
            ),
            (
                "back from the alternate screen",
                40,
                10,
                b"before\x1b[?1049h\x1b[2Jinside\x1b[?1049l",
            ),
            ("app cursor and keypad", 40, 10, b"\x1b[?1h\x1b=text"),
            ("mouse tracking", 40, 10, b"\x1b[?1002h\x1b[?1006htext"),
            ("mouse off again", 40, 10, b"\x1b[?1002h\x1b[?1002ltext"),
            ("bracketed paste", 40, 10, b"\x1b[?2004htext"),
            (
                "origin mode with a region",
                40,
                10,
                b"\x1b[3;8r\x1b[?6h\x1b[2;3Hinside",
            ),
            (
                "scrolled past the bottom",
                20,
                5,
                b"1\r\n2\r\n3\r\n4\r\n5\r\n6\r\n7\r\n8\r\n9\r\n10",
            ),
            ("erase in line", 40, 10, b"abcdefgh\x1b[5D\x1b[K"),
            (
                "erase in display",
                40,
                10,
                b"one\r\ntwo\r\nthree\x1b[1;1H\x1b[J",
            ),
            ("tabs", 40, 10, b"a\tb\tc"),
            ("256-color background", 40, 10, b"\x1b[48;5;17mbg\x1b[0m"),
            ("truecolor background", 40, 10, b"\x1b[48;2;1;2;3mbg\x1b[0m"),
            ("blank screen", 40, 10, b""),
            ("only a cursor move", 40, 10, b"\x1b[7;13H"),
        ];
        for (name, cols, rows, script) in cases {
            round_trip(name, *cols, *rows, &[script]);
        }
    }

    /// The client may already be on the alternate screen when a repaint of a
    /// PRIMARY screen arrives (the app exited during the gap). The repaint
    /// has to bring it back, not draw the primary content into the alternate
    /// screen.
    #[test]
    fn a_repaint_pulls_the_client_out_of_the_alternate_screen() {
        let mut screen = screen(40, 10);
        screen.absorb(b"\x1b[2J\x1b[Hshell prompt").unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[?1049h\x1b[2J\x1b[Hvim was here");
        client.feed(&screen.repaint().unwrap().bytes);

        assert_frames_match(&screen.frame(), &client.frame(), "leaving the alt screen");
    }

    /// ...and the other way round: the client is on the primary screen and
    /// the app started during the gap.
    #[test]
    fn a_repaint_pushes_the_client_into_the_alternate_screen() {
        let mut screen = screen(40, 10);
        screen
            .absorb(b"\x1b[?1049h\x1b[2J\x1b[Hinside the app")
            .unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[2J\x1b[Hold shell output");
        client.feed(&screen.repaint().unwrap().bytes);

        assert_frames_match(&screen.frame(), &client.frame(), "entering the alt screen");
    }

    /// Both sides already on the alternate screen -- the flapping-link case,
    /// where a second resync repaints an alternate screen onto an alternate
    /// screen. A `?1049h` that re-saved the primary here would quietly lose
    /// the client's saved shell screen.
    #[test]
    fn a_repaint_of_the_alternate_screen_onto_the_alternate_screen_is_stable() {
        let mut screen = screen(40, 10);
        screen
            .absorb(b"\x1b[2J\x1b[Hshell\x1b[?1049h\x1b[2J\x1b[Happ")
            .unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[2J\x1b[Hshell\x1b[?1049h\x1b[2J\x1b[Hstale app");
        client.feed(&screen.repaint().unwrap().bytes);
        assert_frames_match(&screen.frame(), &client.frame(), "alt onto alt");

        // And leaving restores a primary screen with the shell on it, on both
        // sides, rather than a blank one on the client.
        screen.absorb(b"\x1b[?1049l").unwrap();
        client.feed(b"\x1b[?1049l");
        assert_frames_match(&screen.frame(), &client.frame(), "after leaving");
    }

    /// The client's scroll region can easily be something other than the
    /// full screen when a repaint arrives: its model persisted across the
    /// gap, so it still carries whatever DECSTBM the pre-gap screen last
    /// set. This is the ONLY case that actually exercises
    /// `RESET_SCROLL_REGION` -- every `round_trip` case above starts a FRESH
    /// client, whose region is already full-screen by construction, so
    /// deleting that line from `repaint` would not fail a single one of
    /// them. The script also puts the model in origin mode, which is where
    /// a stale region would actually bite: the cursor re-emission after
    /// `ORIGIN_ON` is only absolute because the region was reset first (see
    /// the comment on `ORIGIN_ON`).
    #[test]
    fn a_repaint_resets_a_stale_scroll_region_before_placing_the_cursor() {
        let mut screen = screen(40, 10);
        screen.absorb(b"\x1b[3;8r\x1b[?6h\x1b[2;3Hinside").unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[5;9rstale content left over in an old region");
        client.feed(&screen.repaint().unwrap().bytes);

        assert_frames_match(&screen.frame(), &client.frame(), "stale scroll region");
    }

    /// The scroll-region case with the alternate screen layered on top --
    /// what the review actually asked for. Content-staleness was never the
    /// gap (every alt-screen test above already starts from a non-blank
    /// client); the gap was that no client above ever carries a
    /// non-full-screen region into a repaint, which is the only condition
    /// under which `RESET_SCROLL_REGION` does anything at all. Both
    /// directions: the model also on the alternate screen, and the model
    /// back on the primary.
    ///
    /// `alacritty_terminal`'s `swap_alt` never touches the scroll region --
    /// it is a single `Term`-level field the alt/primary swap does not
    /// save or restore -- so this combination is not expected to reach a
    /// code path distinct from the two simpler cases above. That is a
    /// reason to expect green, not a reason to skip writing the case: the
    /// point of a property corpus is to let the round trip decide instead
    /// of reasoning about which combinations matter.
    #[test]
    fn a_repaint_resets_a_stale_scroll_region_on_the_alternate_screen() {
        let mut screen = screen(40, 10);
        screen
            .absorb(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[3;8r\x1b[?6h\x1b[2;3Hinside")
            .unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[?1049h\x1b[5;9rstale content left over in an old region");
        client.feed(&screen.repaint().unwrap().bytes);

        assert_frames_match(
            &screen.frame(),
            &client.frame(),
            "stale scroll region, alt onto alt",
        );
    }

    /// ...and the other direction: the client carries the same stale region
    /// and is on the alternate screen, but the repaint is of the PRIMARY
    /// screen -- the client has to leave the alternate screen AND drop the
    /// stale region in the same repaint.
    #[test]
    fn a_repaint_resets_a_stale_scroll_region_while_leaving_the_alternate_screen() {
        let mut screen = screen(40, 10);
        screen.absorb(b"\x1b[3;8r\x1b[?6h\x1b[2;3Hinside").unwrap();

        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(b"\x1b[?1049h\x1b[5;9rstale content left over in an old region");
        client.feed(&screen.repaint().unwrap().bytes);

        assert_frames_match(
            &screen.frame(),
            &client.frame(),
            "stale scroll region, leaving the alt screen",
        );
    }

    /// A wide character wrapping at the right edge with a non-default
    /// background: the placeholder it leaves keeps that background and its
    /// flag.
    #[test]
    fn a_wide_wrap_placeholder_with_a_non_default_background_survives_a_repaint() {
        round_trip(
            "cjk at the right edge, colored background",
            10,
            4,
            &[b"\x1b[41maaaaaaaaa\xe4\xbd\xa0"],
        );
    }

    /// Spec §12: a screen channel behind a closed gate drops whole chunks, so
    /// the last one the client saw may end inside an escape sequence. The
    /// repaint that follows starts with ESC, which aborts the unfinished CSI,
    /// and the client ends with exactly the model's screen -- including the
    /// red space the wrapped text leaves in the row's last column.
    #[test]
    fn a_repaint_after_output_cut_inside_an_escape_sequence_restores_the_screen() {
        let seen: &[u8] = b"\x1b[2J\x1b[Hbefore the gate closed\x1b[3";
        let mut screen = screen(40, 10);
        screen.absorb(seen).unwrap();
        screen
            .absorb(b"1mdropped while the gate was closed\x1b[0m")
            .unwrap();
        let repaint = screen.repaint().unwrap().bytes;
        assert_eq!(repaint.first(), Some(&0x1b), "a repaint starts with ESC");
        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(seen);
        client.feed(&repaint);
        assert_frames_match(&screen.frame(), &client.frame(), "cut inside a CSI");
    }

    /// The same inside a UTF-8 character: the stray lead bytes become one
    /// replacement character that the repaint overwrites.
    #[test]
    fn a_repaint_after_output_cut_inside_a_utf8_character_restores_the_screen() {
        let seen: &[u8] = b"\x1b[2J\x1b[Hprice: \xE2\x82";
        let mut screen = screen(40, 10);
        screen.absorb(seen).unwrap();
        screen.absorb(b"\xAC and more").unwrap();
        let repaint = screen.repaint().unwrap().bytes;
        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(seen);
        client.feed(&repaint);
        assert_frames_match(&screen.frame(), &client.frame(), "cut inside UTF-8");
    }

    /// The model gets `seen` and `dropped`, the client `seen` and the
    /// repaint; then both get `live`, and nothing tells them apart: not the
    /// screens, the cursor, the pen, the region, the character sets or the
    /// modes (`TerminalCore::snapshot`).
    fn live_after_repaint(case: &str, seen: &[u8], dropped: &[u8], live: &[u8]) {
        let mut screen = screen(40, 10);
        screen.absorb(seen).unwrap();
        screen.absorb(dropped).unwrap();
        let mut client = terminal::TerminalCore::with_replay(40, 10);
        client.feed(seen);
        client.feed(&screen.repaint().unwrap().bytes);
        screen.absorb(live).unwrap();
        client.feed(live);
        assert!(
            Some(screen.snapshot()) == client.snapshot(),
            "[{case}] the live output after the repaint lands differently"
        );
        assert_frames_match(&screen.frame(), &client.frame(), case);
    }

    /// Review, Important 1: tmux's pane region above its status line, its
    /// cached pen, and line drawing -- each cut where the repaint has to
    /// carry it into the live output.
    #[test]
    fn tmux_output_after_a_repaint_lands_as_on_the_model() {
        let setup: &[u8] =
            b"\x1b[?1049h\x1b[H\x1b[2J\x1b[10;1H\x1b[30;42m[0] 0:bash*\x1b[K\x1b[39;49m\x1b[1;9r";
        live_after_repaint(
            "a linefeed at the bottom of the pane's region",
            setup,
            b"\x1b[9;1Hlast pane line",
            b"\nscrolled inside the pane\n",
        );
        live_after_repaint(
            "the pen tmux left set",
            setup,
            b"\x1b[3;1H\x1b[44m",
            b"\x1b[Kblue to the end\x1b[49m",
        );
        live_after_repaint(
            "cut inside line drawing",
            setup,
            b"\x1b[2;1H\x1b(0lqq",
            b"qk\x1b(B text",
        );
        live_after_repaint(
            "cut inside an SGR",
            setup,
            b"\x1b[4;1Hplain \x1b[3",
            b"1mred\x1b[0m",
        );
        live_after_repaint("cut inside DECSTBM", setup, b"\x1b[2;", b"5r\x1b[5;1Hx\ny");
        live_after_repaint(
            "a line that ends at the last column, then more",
            setup,
            b"\x1b[6;1H0123456789012345678901234567890123456789",
            b"wrapped on",
        );
    }

    /// Review, Minor 5: on the primary screen the repaint rewrites the rows
    /// in place, so a shell's scrollback on the client gets no copy of its
    /// screen from it.
    #[test]
    fn a_repaint_on_the_primary_screen_adds_nothing_to_the_clients_history() {
        let lines: Vec<u8> = (0..30)
            .flat_map(|i| format!("line {i}\r\n").into_bytes())
            .collect();
        let mut screen = screen(40, 10);
        screen.absorb(&lines).unwrap();
        screen.absorb(b"dropped\r\n").unwrap();
        let mut client = terminal::TerminalCore::new(40, 10);
        client.feed(&lines);
        client.scroll(i32::MAX);
        let history = client.display_offset();
        client.scroll_to_bottom();
        client.feed(&screen.repaint().unwrap().bytes);
        client.scroll(i32::MAX);
        assert_eq!(
            client.display_offset(),
            history,
            "no line pushed into history"
        );
    }
    #[test]
    fn sync111_screen_due_flush_updates_model_and_answers_once() {
        let mut screen = screen(80, 24);
        assert!(screen
            .absorb(b"\x1b[?2026hDEADLINE\x1b[5n")
            .unwrap()
            .is_empty());
        let due = screen.sync_deadline().unwrap();
        assert!(screen
            .flush_due_output(due - std::time::Duration::from_nanos(1))
            .unwrap()
            .is_empty());
        assert_eq!(screen.frame().cell(0, 0).ch, ' ');
        assert_eq!(screen.flush_due_output(due).unwrap(), b"\x1b[0n");
        let frame = screen.frame();
        let text: String = frame.cells.iter().map(|cell| cell.ch).collect();
        assert!(text.contains("DEADLINE"));
        assert!(screen.flush_due_output(due).unwrap().is_empty());
        assert!(screen.absorb(b"\x1b[?2026l").unwrap().is_empty());
    }
}
