//! Client-side glue of a shell session: the core terminal, the prediction
//! engine and the stream-0 record deframer under one roof.
//!
//! Shared shell state without sockets or knowledge of the local terminal UI.

use transport::shell_frame::{ShellDeframer, ShellRecord};

pub mod channel;
pub mod qsh;

/// The "terminal + prediction + deframer" bundle under one lock: all mutable
/// state of the shell session, accessed both by the platform thread
/// (input/resize), the driver thread (receive), and the 50ms tick. Every
/// method returns a frame ready to render: overlaid with active predictions
/// at the live bottom, authoritative while viewing history.
///
/// Echo numeric contract: the engine stamps `expiration = local_frame_sent`
/// (no offset). So `on_input` first grows `input_bytes_sent` by the length of
/// the sent bytes and sets it via `set_local_frame_sent`, and the server's
/// echo_ack (`input_consumed` -- how many input bytes it has already echoed)
/// goes into `set_echo_ack`: a prediction is considered confirmed once
/// echo_ack catches up to the send offset.
pub struct ShellState {
    terminal: terminal::TerminalCore,
    prediction: prediction::PredictionEngine,
    deframer: ShellDeframer,
    /// Offset of input bytes sent to the shell -- the "send frame" number for
    /// the prediction engine (see the contract above).
    input_bytes_sent: u64,
    /// Explicit history mode suppresses prediction even at offset zero.
    history_view: bool,
}

impl ShellState {
    /// New bundle: terminal at `cols`/`rows`, prediction engine in mode
    /// `pref` with `predict_overwrite` applied, empty stream-0 deframer.
    pub fn new(
        cols: u16,
        rows: u16,
        pref: prediction::DisplayPreference,
        predict_overwrite: bool,
    ) -> Self {
        let size = terminal_size::TerminalSize::for_viewport(cols, rows);
        let mut prediction = prediction::PredictionEngine::new(pref);
        prediction.set_predict_overwrite(predict_overwrite);
        ShellState {
            terminal: terminal::TerminalCore::with_options(
                size,
                terminal::TerminalOptions::default(),
            ),
            prediction,
            deframer: ShellDeframer::new(),
            input_bytes_sent: 0,
            history_view: false,
        }
    }

    /// Whether the prediction engine shows anything right now -- for tests
    /// that a session predicts, or does not.
    pub fn prediction_active(&self) -> bool {
        self.prediction.active()
    }

    pub fn set_history_limit(&mut self, lines: usize) {
        self.terminal.set_history_limit(lines);
    }

    pub fn history_size(&self) -> usize {
        self.terminal.history_size()
    }

    /// Enters a local history view, or returns to the live bottom on exit.
    pub fn set_history_view(&mut self, enabled: bool) {
        self.history_view = enabled;
        if !enabled {
            self.terminal.scroll_to_bottom();
        }
    }

    /// Local input: raw bytes have ALREADY gone to stream 0 (outside the
    /// lock) -- only prediction happens here. Grow the send offset, stamp
    /// echo for each byte against the current authoritative frame, cull, and
    /// return the overlaid frame.
    pub fn on_input(&mut self, data: &[u8], now_ms: i64, rtt_ms: i64) -> terminal::Frame {
        // Printing always returns the view to the live bottom -- after this
        // line `display_offset() == 0`, and prediction can be overlaid as usual.
        self.terminal.scroll_to_bottom();
        self.input_bytes_sent += data.len() as u64;
        self.prediction
            .set_local_frame_sent(self.input_bytes_sent as i64);
        let auth = self.terminal.frame();
        for &b in data {
            self.prediction.new_user_byte(b, &auth, now_ms);
        }
        self.prediction.set_send_interval(rtt_ms);
        self.prediction.cull(&auth, now_ms);
        self.prediction.apply(&auth)
    }

    /// Framed stream 0 from the server: DATA records feed the terminal,
    /// ECHO_ACK advances echo confirmation. Then cull the prediction against
    /// the new authoritative frame and return the overlaid frame.
    pub fn on_stream0(&mut self, data: &[u8], now_ms: i64, rtt_ms: i64) -> terminal::Frame {
        let records = self.deframer.push(data);
        for rec in records {
            match rec {
                ShellRecord::Data(bytes) => {
                    // Alacritty anchors nonzero offsets as output scrolls.
                    // Borrow an offset while feeding at the live bottom so
                    // explicit history mode anchors that position as well.
                    let anchor = self.history_view
                        && self.terminal.display_offset() == 0
                        && self.terminal.history_size() > 0;
                    if anchor {
                        self.terminal.scroll(1);
                    }
                    self.terminal.feed(&bytes);
                    if anchor {
                        self.terminal.scroll(-1);
                    }
                }
                ShellRecord::EchoAck(k) => self.prediction.set_echo_ack(k as i64),
            }
        }
        let auth = self.terminal.frame();
        self.prediction.set_send_interval(rtt_ms);
        // In history (offset > 0) we don't overlay prediction -- its
        // coordinates are tied to the live bottom and no longer match in a scrolled frame.
        if !self.history_view && self.terminal.display_offset() == 0 {
            self.prediction.cull(&auth, now_ms);
            self.prediction.apply(&auth)
        } else {
            auth
        }
    }

    /// Resize: the terminal recalculates the grid immediately; a resize
    /// inside `cull` resets the prediction (it's tied to the previous grid).
    /// Return the overlaid frame at the new size (raw, without overlay, while
    /// in history -- for the same reason as in `on_stream0`).
    pub fn resize_frame(&mut self, cols: u16, rows: u16, now_ms: i64) -> terminal::Frame {
        self.terminal
            .resize_to(terminal_size::TerminalSize::for_viewport(cols, rows));
        let auth = self.terminal.frame();
        if !self.history_view && self.terminal.display_offset() == 0 {
            self.prediction.cull(&auth, now_ms);
            self.prediction.apply(&auth)
        } else {
            auth
        }
    }

    /// Shift the terminal history view by `delta_lines` lines (a positive
    /// value goes deeper into history) and return the frame: at the live
    /// bottom -- with prediction overlaid (as usual), in history -- the raw
    /// authoritative frame without overlay.
    pub fn scroll_frame(&mut self, delta_lines: i32, now_ms: i64, rtt_ms: i64) -> terminal::Frame {
        self.terminal.scroll(delta_lines);
        let auth = self.terminal.frame();
        self.prediction.set_send_interval(rtt_ms);
        if !self.history_view && self.terminal.display_offset() == 0 {
            self.prediction.cull(&auth, now_ms);
            self.prediction.apply(&auth)
        } else {
            auth
        }
    }

    /// The current frame with nothing else done: no input sent, no bytes fed,
    /// no view moved -- what a client redraws after `Renderer::invalidate`
    /// (a `SIGCONT`, a `SIGWINCH` that did not change the size) or wherever
    /// it needs the picture as it stands. Overlaid with the active
    /// predictions at the live bottom, the raw authoritative frame in
    /// history, by the same rule as `on_stream0`/`scroll_frame`. Unlike
    /// `tick` it always returns a frame: the caller asked for one.
    pub fn frame(&mut self, now_ms: i64, rtt_ms: i64) -> terminal::Frame {
        let auth = self.terminal.frame();
        self.prediction.set_send_interval(rtt_ms);
        if !self.history_view && self.terminal.display_offset() == 0 {
            self.prediction.cull(&auth, now_ms);
            self.prediction.apply(&auth)
        } else {
            auth
        }
    }

    /// Terminal history view offset (0 = live bottom). Internal methods read
    /// `self.terminal.display_offset()` directly; this accessor is for tests
    /// (and a placeholder for a future FFI-exposed offset query).
    pub fn display_offset(&self) -> usize {
        self.terminal.display_offset()
    }

    /// A stream reset arrived (the server dropped its output backlog after a
    /// long absence and is about to repaint the current screen): drop the
    /// deframer's partial `ShellRecord` bytes -- they belong to the pre-reset
    /// byte offset and are now meaningless, since the stream jumped -- and
    /// reset the prediction engine, whose overlays are tied to the pre-gap
    /// grid. History is discarded, but the visible grid is NOT cleared: the incoming repaint
    /// overwrites the visible screen, so clearing it first would just cause a
    /// blank flash.
    pub fn on_reset(&mut self) -> terminal::Frame {
        self.deframer = ShellDeframer::new();
        self.prediction.reset();
        self.history_view = false;
        self.terminal.clear_history();
        self.terminal.frame()
    }

    /// The session came back on a new connection (a warm reattach). The
    /// server counts consumed input from zero again, so this side counts
    /// sent input from zero too, or no prediction would ever be confirmed
    /// after the return; a partial record of the old connection means
    /// nothing on the new one; predictions belong to the screen as it was.
    /// The grid stays: the server repaints it.
    pub fn on_reattach(&mut self) -> terminal::Frame {
        self.deframer = ShellDeframer::new();
        self.prediction.reset();
        self.input_bytes_sent = 0;
        self.prediction.set_local_frame_sent(0);
        self.prediction.set_echo_ack(0);
        self.terminal.frame()
    }

    /// Timing-driven reveal without new input -- the 50ms tick. Returns an
    /// overlaid frame ONLY while the prediction engine has something active;
    /// `None` means the caller pushes no frame at all (that is exactly what
    /// the old inline tick loops did with `continue`).
    ///
    /// History views suppress predictions, including the timing-driven reveal.
    pub fn tick(&mut self, now_ms: i64, rtt_ms: i64) -> Option<terminal::Frame> {
        if self.history_view || self.terminal.display_offset() > 0 || !self.prediction.active() {
            return None;
        }
        self.prediction.set_send_interval(rtt_ms);
        let auth = self.terminal.frame();
        self.prediction.cull(&auth, now_ms);
        Some(self.prediction.apply(&auth))
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use transport::shell_frame::{encode_record, ShellRecord, REC_DATA, REC_ECHO_ACK};

    #[test]
    fn explicit_history_mode_suppresses_prediction_at_the_live_bottom() {
        let mut st = ShellState::new(20, 3, prediction::DisplayPreference::Always, false);
        st.on_input(b"h", 1000, 100);
        let mut ack = encode_record(REC_DATA, b"h");
        ack.extend(encode_record(REC_ECHO_ACK, &1u64.to_be_bytes()));
        st.on_stream0(&ack, 1050, 100);
        let predicted = st.on_input(b"i", 1100, 100);
        assert_ne!(predicted, st.terminal.frame());
        st.set_history_view(true);
        assert_eq!(st.frame(1150, 100), st.terminal.frame());
        assert!(st.tick(1200, 100).is_none());
        st.set_history_view(false);
        assert_ne!(st.frame(1250, 100), st.terminal.frame());
    }

    /// The "terminal + prediction + deframer" bundle without a network:
    /// `on_input` overlays echo instantly, receiving framed output with
    /// ECHO_ACK confirms the prediction.
    ///
    /// The warm-up order is mandatory: in a faithful mosh port, the FIRST
    /// prediction on a fresh engine is ambiguous (tentative) and HIDDEN until
    /// the epoch is confirmed (the first `cull` moves into a new epoch
    /// because of the grid resize 0 -> cols/rows, so the prediction sits in
    /// an unconfirmed epoch and `apply` skips it). So:
    ///   1. `on_input("h")` -- prediction is hidden (we don't check display);
    ///   2. `on_stream0(DATA "h" + ECHO_ACK 1)` -- the terminal draws 'h', the
    ///      epoch is confirmed (Correct);
    ///   3. `on_input("i")` -- steady state: 'i' is visible IMMEDIATELY in
    ///      the overlaid frame. `Always` mode, so the display gate doesn't depend on RTT.
    #[test]
    fn input_is_predicted_then_confirmed() {
        let mut st = ShellState::new(20, 1, prediction::DisplayPreference::Always, false);

        // (1) First input -- prediction is ambiguous and hidden: we don't
        // check display here, only track the bytes sent.
        let _hidden = st.on_input(b"h", 1000, 100);
        assert_eq!(st.input_bytes_sent, 1);

        // (2) The server sent framed output 'h' and echo_ack=1 -- the
        // terminal draws 'h', the epoch is confirmed (overlay cleared).
        let mut stream = encode_record(REC_DATA, b"h");
        stream.extend(encode_record(REC_ECHO_ACK, &1u64.to_be_bytes()));
        let after = st.on_stream0(&stream, 1050, 100);
        assert_eq!(after.cell(0, 0).ch, 'h');

        // (3) Steady state: the next input 'i' is visible instantly in the
        // overlaid frame, even before the server responds.
        let shown = st.on_input(b"i", 1100, 100);
        assert_eq!(shown.cell(0, 1).ch, 'i');
        assert_eq!(st.input_bytes_sent, 2);
    }

    /// `scroll_frame` while in history must return the RAW frame (no
    /// prediction overlay -- the prediction's coordinates are tied to the
    /// live bottom, they no longer match in history), and `on_input`
    /// (printing) must reset the view back to the live bottom.
    ///
    /// The warm-up is the same as in `input_is_predicted_then_confirmed`:
    /// first fill the history buffer with real lines via `on_stream0`, then
    /// go through the same "hidden prediction -> confirmed by echo -> steady
    /// state" cycle, so that by the time we scroll, a visible prediction is
    /// hanging in history and must be suppressed.
    #[test]
    fn scroll_frame_suppresses_prediction_in_history_and_input_returns_to_bottom() {
        let mut st = ShellState::new(6, 3, prediction::DisplayPreference::Always, false);

        // Fill the history buffer: 10 lines on a 6x3 grid -- old lines go
        // into history, so there's something to scroll through.
        for i in 0..10u32 {
            let line = encode_record(REC_DATA, format!("line{i}\r\n").as_bytes());
            st.on_stream0(&line, 1000, 100);
        }
        assert_eq!(
            st.display_offset(),
            0,
            "printing lines leaves the view at the live bottom"
        );

        // Prediction warm-up (see the comment above `input_is_predicted_then_confirmed`).
        let _hidden = st.on_input(b"h", 2000, 100);
        let mut ack = encode_record(REC_DATA, b"h");
        ack.extend(encode_record(
            REC_ECHO_ACK,
            &st.input_bytes_sent.to_be_bytes(),
        ));
        st.on_stream0(&ack, 2050, 100);

        // Steady state: the next byte is visible in the overlaid frame
        // immediately, before the server responds -- the overlaid frame must
        // differ from the raw one.
        let overlaid = st.on_input(b"i", 2100, 100);
        let raw_at_bottom = st.terminal.frame();
        assert_ne!(
            overlaid, raw_at_bottom,
            "at the live bottom (offset == 0) the prediction is overlaid on the frame"
        );

        // Scroll into history: offset > 0, overlay must be suppressed -- the
        // frame from `scroll_frame` matches the raw `terminal.frame()`.
        let scrolled = st.scroll_frame(3, 2200, 100);
        assert!(
            st.display_offset() > 0,
            "the display offset grew after scrolling"
        );
        let raw_in_history = st.terminal.frame();
        assert_eq!(
            scrolled, raw_in_history,
            "in history the frame carries no prediction overlay"
        );

        // Printing always returns the view to the live bottom.
        let _after_print = st.on_input(b"!", 2300, 100);
        assert_eq!(
            st.display_offset(),
            0,
            "on_input must bring the view back to the live bottom"
        );
    }

    /// `on_reset` must: drop the deframer's buffered partial `ShellRecord`,
    /// reset the prediction engine, and leave the visible terminal grid
    /// alone (the incoming repaint overwrites it -- clearing here would
    /// cause a blank flash before it arrives).
    #[test]
    fn on_reset_drops_partial_deframer_and_prediction_but_keeps_terminal_grid() {
        let mut st = ShellState::new(20, 1, prediction::DisplayPreference::Always, false);

        // Warm-up (see the comment on `input_is_predicted_then_confirmed`):
        // hidden prediction -> confirmed by echo -> a visible, active prediction.
        let _hidden = st.on_input(b"h", 1000, 100);
        let mut ack = encode_record(REC_DATA, b"h");
        ack.extend(encode_record(
            REC_ECHO_ACK,
            &st.input_bytes_sent.to_be_bytes(),
        ));
        st.on_stream0(&ack, 1050, 100);
        let overlaid = st.on_input(b"i", 1100, 100);
        let raw_before = st.terminal.frame();
        assert_ne!(
            overlaid, raw_before,
            "an active prediction must overlay the raw frame"
        );
        assert!(
            st.prediction.active(),
            "prediction must be active before the reset"
        );

        // Leave a genuinely partial ShellRecord buffered in the deframer:
        // only 3 of the 5 header bytes have arrived.
        let stray = encode_record(REC_DATA, b"stale-should-vanish");
        assert!(
            st.deframer.push(&stray[..3]).is_empty(),
            "only 3 of the header's 5 bytes arrived -- must stay buffered"
        );

        let reset_frame = st.on_reset();

        // Prediction is gone.
        assert!(
            !st.prediction.active(),
            "on_reset must clear the prediction engine"
        );
        // The visible grid is untouched -- the returned frame is the raw
        // one (nothing to overlay), and the printed 'h' survives.
        assert_eq!(reset_frame, st.terminal.frame());
        assert_eq!(
            reset_frame.cell(0, 0).ch,
            'h',
            "on_reset must not clear the visible grid"
        );

        // The stale partial bytes must be gone from the deframer:
        // completing a FRESH, unrelated record parses cleanly. A surviving
        // stale prefix would misalign the parse and this would fail.
        let fresh = encode_record(REC_DATA, b"fresh");
        let recs = st.deframer.push(&fresh);
        assert_eq!(recs.len(), 1);
        assert!(matches!(&recs[0], ShellRecord::Data(v) if v == b"fresh"));
    }

    /// `frame` hands out the current picture without doing anything else:
    /// the input offset does not move, and the rule of the other methods
    /// holds -- overlaid at the live bottom, raw in history.
    #[test]
    fn frame_is_overlaid_at_the_bottom_and_raw_in_history() {
        let mut st = ShellState::new(6, 3, prediction::DisplayPreference::Always, false);

        // History to scroll into, then the usual warm-up (see the comment on
        // `input_is_predicted_then_confirmed`) up to a visible prediction.
        for i in 0..10u32 {
            let line = encode_record(REC_DATA, format!("line{i}\r\n").as_bytes());
            st.on_stream0(&line, 1000, 100);
        }
        let _hidden = st.on_input(b"h", 2000, 100);
        let mut ack = encode_record(REC_DATA, b"h");
        ack.extend(encode_record(
            REC_ECHO_ACK,
            &st.input_bytes_sent.to_be_bytes(),
        ));
        st.on_stream0(&ack, 2050, 100);
        let overlaid = st.on_input(b"i", 2100, 100);
        assert_ne!(
            overlaid,
            st.terminal.frame(),
            "a prediction must be active and visible"
        );

        let sent_before = st.input_bytes_sent;
        let current = st.frame(2150, 100);
        assert_eq!(
            current, overlaid,
            "at the live bottom `frame` is the overlaid frame"
        );
        assert_eq!(
            current.cell(2, 1).ch,
            'i',
            "the predicted character is visible in it"
        );
        assert_eq!(
            st.input_bytes_sent, sent_before,
            "`frame` must not count as input"
        );

        st.scroll_frame(3, 2200, 100);
        assert!(st.display_offset() > 0, "the view is in history");
        assert_eq!(
            st.frame(2250, 100),
            st.terminal.frame(),
            "in history `frame` is the raw frame, without overlay"
        );
    }

    /// `tick` is the 50ms timer: it pushes a frame only while a prediction
    /// is outstanding. Nothing predicted -- nothing to push; a fresh
    /// prediction -- the overlaid frame with it visible; once the server has
    /// echoed it -- nothing again.
    #[test]
    fn tick_returns_a_frame_only_while_a_prediction_is_active() {
        let mut st = ShellState::new(20, 1, prediction::DisplayPreference::Always, false);
        assert!(
            st.tick(900, 100).is_none(),
            "nothing predicted, nothing to push"
        );

        // Warm-up (see the comment on `input_is_predicted_then_confirmed`).
        let _hidden = st.on_input(b"h", 1000, 100);
        let mut ack = encode_record(REC_DATA, b"h");
        ack.extend(encode_record(
            REC_ECHO_ACK,
            &st.input_bytes_sent.to_be_bytes(),
        ));
        st.on_stream0(&ack, 1050, 100);
        assert!(
            st.tick(1060, 100).is_none(),
            "a confirmed prediction is no longer outstanding"
        );

        let _ = st.on_input(b"i", 1100, 100);
        let ticked = st
            .tick(1150, 100)
            .expect("an outstanding prediction is pushed by the tick");
        assert_eq!(ticked.cell(0, 1).ch, 'i', "with the prediction visible");
        assert_ne!(
            st.terminal.frame().cell(0, 1).ch,
            'i',
            "while the terminal itself has not seen it yet"
        );

        // The server echoes 'i': confirmed, culled, nothing left to push.
        let mut ack = encode_record(REC_DATA, b"i");
        ack.extend(encode_record(
            REC_ECHO_ACK,
            &st.input_bytes_sent.to_be_bytes(),
        ));
        st.on_stream0(&ack, 1200, 100);
        assert!(
            st.tick(1250, 100).is_none(),
            "once echoed there is nothing left to push"
        );
    }

    /// A warm reattach is a new connection: the server counts consumed input
    /// from zero again, so this side must count sent input from zero too, or
    /// no prediction would ever be confirmed after the return.
    #[test]
    fn a_reattach_starts_the_input_count_over_and_keeps_the_screen() {
        let mut st = ShellState::new(20, 1, prediction::DisplayPreference::Always, false);
        st.on_stream0(&encode_record(REC_DATA, b"kept"), 1000, 100);
        st.on_input(b"abc", 1010, 100);
        assert_eq!(st.input_bytes_sent, 3);
        let frame = st.on_reattach();
        assert_eq!(st.input_bytes_sent, 0);
        assert!(
            !st.prediction_active(),
            "predictions belong to the old connection"
        );
        assert_eq!(
            frame.cell(0, 0).ch,
            'k',
            "the screen stays until the server repaints it"
        );
        // After the return: the first byte is acknowledged as byte 1.
        st.on_input(b"x", 1100, 100);
        assert_eq!(st.input_bytes_sent, 1);
    }
}
