//! Local echo prediction engine -- a port of mosh's `Overlay::PredictionEngine`
//! (`terminaloverlay.{h,cc}`). Consumes outgoing input bytes, builds prediction
//! overlays on top of the latest server frame; [`PredictionEngine::cull`]
//! checks them against incoming authoritative frames (via `echo_ack`) and
//! retires confirmed/incorrect ones; [`PredictionEngine::apply`] renders the
//! remaining ones onto a COPY of the frame. Epochs (`prediction_epoch`/
//! `confirmed_epoch`) hide predictions made after ambiguous input until the
//! server confirms them; the `srtt`/`glitch`/`flag` triggers decide whether to
//! show a prediction at all.
//!
//! Deviations from mosh:
//! - No `NotificationEngine`/`TitleEngine`/`OverlayManager` and no
//!   `Experimental` variant; the engine only does prediction.
//! - Time is injected (`now_ms: i64`) instead of `timestamp()`.
//! - Our frame number is the input byte offset, and `send_input` sends bytes
//!   SYNCHRONOUSLY before prediction; so every `.expire(...)` stamps
//!   `expiration_frame = self.local_frame_sent` (WITHOUT `+ 1`, unlike mosh).
//!   The `ConditionalCursorMove::new(local_frame_sent + 1, ...)` constructors
//!   still keep the `+ 1` as in mosh (the value gets overwritten by a
//!   subsequent `expire` on the common paths anyway). This is the only
//!   arithmetic deviation.

use crate::keystroke::{KeyAction, KeystrokeParser};
use crate::overlay::{
    ConditionalCursorMove, ConditionalOverlayCell, ConditionalOverlayRow, Validity,
};
use terminal::{Cell, Frame};
use unicode_width::UnicodeWidthChar;

/// SRTT threshold: `<=` ms clears the prediction-display trigger.
const SRTT_TRIGGER_LOW: i64 = 20;
/// SRTT threshold: `>` ms sets the prediction-display trigger.
const SRTT_TRIGGER_HIGH: i64 = 30;
/// Underline threshold: `<=` ms clears the underline.
const FLAG_TRIGGER_LOW: i64 = 50;
/// Underline threshold: `>` ms turns the underline on.
const FLAG_TRIGGER_HIGH: i64 = 80;
/// A prediction pending longer than this (ms) counts as a glitch.
const GLITCH_THRESHOLD: i64 = 250;
/// How many consecutive non-glitches are needed to clear the glitch trigger.
const GLITCH_REPAIR_COUNT: i64 = 10;
/// Minimum interval (ms) between counted non-glitches.
const GLITCH_REPAIR_MININTERVAL: i64 = 150;
/// A prediction pending longer than this (ms) turns the underline on.
const GLITCH_FLAG_THRESHOLD: i64 = 5000;

/// Prediction display mode (a port of `DisplayPreference` without `Experimental`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayPreference {
    /// Always show predictions.
    Always,
    /// Never show predictions.
    Never,
    /// Show depending on conditions (slow network / long server responses).
    Adaptive,
}

/// Input prediction engine. Holds overlays (`overlays`) and cursor predictions
/// (`cursors`), the sent/acked frame numbers, epochs, and triggers.
pub struct PredictionEngine {
    last_byte: u8,
    parser: KeystrokeParser,

    overlays: Vec<ConditionalOverlayRow>,
    cursors: Vec<ConditionalCursorMove>,

    local_frame_sent: i64,
    local_frame_acked: i64,
    local_frame_late_acked: i64,

    prediction_epoch: i64,
    confirmed_epoch: i64,

    flagging: bool,
    srtt_trigger: bool,
    glitch_trigger: i64,
    last_quick_confirmation: i64,

    send_interval: i64,

    last_height: u16,
    last_width: u16,

    display_preference: DisplayPreference,
    predict_overwrite: bool,
}

impl PredictionEngine {
    /// A new engine in the given display mode. Initial epochs/triggers match
    /// mosh (`prediction_epoch = 1`, `confirmed_epoch = 0`, `send_interval = 250`).
    pub fn new(pref: DisplayPreference) -> Self {
        PredictionEngine {
            last_byte: 0,
            parser: KeystrokeParser::new(),
            overlays: Vec::new(),
            cursors: Vec::new(),
            local_frame_sent: 0,
            local_frame_acked: 0,
            local_frame_late_acked: 0,
            prediction_epoch: 1,
            confirmed_epoch: 0,
            flagging: false,
            srtt_trigger: false,
            glitch_trigger: 0,
            last_quick_confirmation: 0,
            send_interval: 250,
            last_height: 0,
            last_width: 0,
            display_preference: pref,
            predict_overwrite: false,
        }
    }

    /// Change the display mode.
    pub fn set_display_preference(&mut self, pref: DisplayPreference) {
        self.display_preference = pref;
    }

    /// Change whether a printable prediction may overwrite existing (non-blank) terminal
    /// content, instead of skipping over cells that already hold a character (mosh's
    /// `predict_overwrite`). Off (`false`) by default -- unchanged for any existing caller
    /// that never calls this setter.
    pub fn set_predict_overwrite(&mut self, v: bool) {
        self.predict_overwrite = v;
    }

    /// Number of the last sent frame (for us -- the input byte offset after
    /// synchronously sending a keystroke).
    pub fn set_local_frame_sent(&mut self, x: i64) {
        self.local_frame_sent = x;
    }

    /// Set the echo-ack watermark: moves BOTH `local_frame_acked` AND
    /// `local_frame_late_acked` to `x` (how many input bytes the server has
    /// already echoed).
    pub fn set_echo_ack(&mut self, x: i64) {
        self.local_frame_acked = x;
        self.local_frame_late_acked = x;
    }

    /// Average send interval (ms) -- input for the srtt/flag triggers.
    pub fn set_send_interval(&mut self, ms: i64) {
        self.send_interval = ms;
    }

    // Topmost (latest) cursor prediction. Only called once `init_cursor` has
    // already guaranteed a non-empty list (a port of mosh's `cursor()`).
    fn cursor(&self) -> &ConditionalCursorMove {
        self.cursors.last().expect("cursors non-empty")
    }

    fn cursor_mut(&mut self) -> &mut ConditionalCursorMove {
        self.cursors.last_mut().expect("cursors non-empty")
    }

    // Whether there are any active predictions at all (a port of mosh's raw
    // `PredictionEngine::active`). Used inside `cull` for the srtt hysteresis.
    fn has_active_overlays(&self) -> bool {
        if !self.cursors.is_empty() {
            return true;
        }
        for row in &self.overlays {
            for cell in &row.overlay_cells {
                if cell.base.active {
                    return true;
                }
            }
        }
        false
    }

    // Condition for showing predictions (a port of the gate in mosh's `apply`):
    // not `Never`, and there's a reason to show -- `Always`, or the srtt/glitch
    // trigger is set.
    fn showing(&self) -> bool {
        self.display_preference != DisplayPreference::Never
            && (self.srtt_trigger
                || self.glitch_trigger != 0
                || self.display_preference == DisplayPreference::Always)
    }

    /// Whether predictions are currently shown: there are active overlays/cursors
    /// AND a display trigger has fired (a port of `active()` as interpreted by
    /// the display -- the display gate plus the presence of active predictions).
    pub fn active(&self) -> bool {
        self.showing() && self.has_active_overlays()
    }

    /// Overlay the active predictions onto a COPY of frame `fb` and return it.
    /// If there is nothing to show (`!active()`), return an unmodified copy
    /// (a port of mosh's display condition: `apply` is a no-op when prediction
    /// is inactive).
    pub fn apply(&self, fb: &Frame) -> Frame {
        let mut clone = fb.clone();
        if !self.active() {
            return clone;
        }
        for c in &self.cursors {
            c.apply(&mut clone, self.confirmed_epoch);
        }
        for row in &self.overlays {
            row.apply(&mut clone, self.confirmed_epoch, self.flagging);
        }
        clone
    }

    /// Reset all predictions (a port of `reset`): clear overlays/cursors and
    /// move to a new epoch.
    pub fn reset(&mut self) {
        self.cursors.clear();
        self.overlays.clear();
        self.become_tentative();
    }

    fn become_tentative(&mut self) {
        self.prediction_epoch += 1;
    }

    // Kill an ambiguous epoch: drop that epoch's predictions, recreate the
    // cursor from the actual position, and move to a new epoch (a port of
    // `kill_epoch`).
    fn kill_epoch(&mut self, epoch: i64, fb: &Frame) {
        self.cursors.retain(|c| !c.base.tentative(epoch - 1));
        // The constructor keeps the `+ 1` as in mosh (see the module doc comment).
        let exp = self.local_frame_sent + 1;
        let pe = self.prediction_epoch;
        self.cursors.push(ConditionalCursorMove::new(
            exp,
            fb.cursor_row as i32,
            fb.cursor_col as i32,
            pe,
        ));
        self.cursor_mut().base.active = true;
        for row in &mut self.overlays {
            for cell in &mut row.overlay_cells {
                if cell.base.tentative(epoch - 1) {
                    cell.reset();
                }
            }
        }
        self.become_tentative();
    }

    // Ensure a current-epoch cursor prediction exists (a port of `init_cursor`).
    // The constructors keep the `+ 1` as in mosh.
    fn init_cursor(&mut self, fb: &Frame) {
        let exp = self.local_frame_sent + 1;
        let pe = self.prediction_epoch;
        if self.cursors.is_empty() {
            self.cursors.push(ConditionalCursorMove::new(
                exp,
                fb.cursor_row as i32,
                fb.cursor_col as i32,
                pe,
            ));
            self.cursor_mut().base.active = true;
        } else if self.cursor().base.tentative_until_epoch != pe {
            let (r, c) = {
                let cu = self.cursor();
                (cu.row, cu.base.col)
            };
            self.cursors.push(ConditionalCursorMove::new(exp, r, c, pe));
            self.cursor_mut().base.active = true;
        }
    }

    // Find or create an overlay row for the given row number; return its index
    // in `overlays` (a port of `get_or_make_row`, but returning an index --
    // Rust's borrow checker).
    fn get_or_make_row(&mut self, row_num: i32, num_cols: i32) -> usize {
        if let Some(idx) = self.overlays.iter().position(|r| r.row_num == row_num) {
            return idx;
        }
        let mut r = ConditionalOverlayRow {
            row_num,
            overlay_cells: Vec::with_capacity(num_cols.max(0) as usize),
        };
        for i in 0..num_cols {
            r.overlay_cells
                .push(ConditionalOverlayCell::new(0, i, self.prediction_epoch));
        }
        self.overlays.push(r);
        self.overlays.len() - 1
    }

    /// Retire/confirm predictions against the authoritative frame `fb` (a port
    /// of `cull`). `now_ms` is the current time (ms) for glitch timing.
    pub fn cull(&mut self, fb: &Frame, now_ms: i64) {
        if self.display_preference == DisplayPreference::Never {
            return;
        }

        if self.last_height != fb.height() || self.last_width != fb.width() {
            self.last_height = fb.height();
            self.last_width = fb.width();
            self.reset();
        }

        let now = now_ms;

        // srtt_trigger with hysteresis.
        if self.send_interval > SRTT_TRIGGER_HIGH {
            self.srtt_trigger = true;
        } else if self.srtt_trigger
            && self.send_interval <= SRTT_TRIGGER_LOW
            && !self.has_active_overlays()
        {
            self.srtt_trigger = false;
        }

        // Underline with hysteresis.
        if self.send_interval > FLAG_TRIGGER_HIGH {
            self.flagging = true;
        } else if self.send_interval <= FLAG_TRIGGER_LOW {
            self.flagging = false;
        }

        // Very severe glitches also turn the underline on.
        if self.glitch_trigger > GLITCH_REPAIR_COUNT {
            self.flagging = true;
        }

        let early = self.local_frame_acked;
        let late = self.local_frame_late_acked;

        let mut row_i = 0;
        while row_i < self.overlays.len() {
            let row_num = self.overlays[row_i].row_num;
            if row_num < 0 || row_num >= fb.height() as i32 {
                self.overlays.remove(row_i);
                continue;
            }
            let ncells = self.overlays[row_i].overlay_cells.len();
            let mut j = 0;
            while j < ncells {
                let validity =
                    self.overlays[row_i].overlay_cells[j].get_validity(fb, row_num, early, late);
                match validity {
                    Validity::IncorrectOrExpired => {
                        if self.overlays[row_i].overlay_cells[j]
                            .base
                            .tentative(self.confirmed_epoch)
                        {
                            let tue = self.overlays[row_i].overlay_cells[j]
                                .base
                                .tentative_until_epoch;
                            self.kill_epoch(tue, fb);
                        } else {
                            self.reset();
                            return;
                        }
                    }
                    Validity::Correct => {
                        let tue = self.overlays[row_i].overlay_cells[j]
                            .base
                            .tentative_until_epoch;
                        if tue > self.confirmed_epoch {
                            self.confirmed_epoch = tue;
                        }
                        // On quick confirmations, gradually clear the glitch trigger.
                        let ptime = self.overlays[row_i].overlay_cells[j].base.prediction_time;
                        if now - ptime < GLITCH_THRESHOLD
                            && self.glitch_trigger > 0
                            && now - GLITCH_REPAIR_MININTERVAL >= self.last_quick_confirmation
                        {
                            self.glitch_trigger -= 1;
                            self.last_quick_confirmation = now;
                        }
                        // Match the rest of the row's renditions to the actual ones.
                        let col_j = self.overlays[row_i].overlay_cells[j].base.col;
                        let actual = *fb.cell(row_num as u16, col_j as u16);
                        for k in j..ncells {
                            let repl = &mut self.overlays[row_i].overlay_cells[k].replacement;
                            repl.fg = actual.fg;
                            repl.bg = actual.bg;
                            repl.flags = actual.flags;
                        }
                        self.overlays[row_i].overlay_cells[j].reset();
                    }
                    Validity::CorrectNoCredit => {
                        self.overlays[row_i].overlay_cells[j].reset();
                    }
                    Validity::Pending => {
                        // A long wait for confirmation activates display even at
                        // low SRTT.
                        let ptime = self.overlays[row_i].overlay_cells[j].base.prediction_time;
                        if now - ptime >= GLITCH_FLAG_THRESHOLD {
                            self.glitch_trigger = GLITCH_REPAIR_COUNT * 2; // show and underline
                        } else if now - ptime >= GLITCH_THRESHOLD
                            && self.glitch_trigger < GLITCH_REPAIR_COUNT
                        {
                            self.glitch_trigger = GLITCH_REPAIR_COUNT; // just show
                        }
                    }
                    Validity::Inactive => {}
                }
                j += 1;
            }
            row_i += 1;
        }

        // Cursor predictions.
        if !self.cursors.is_empty()
            && self.cursor().get_validity(fb, early, late) == Validity::IncorrectOrExpired
        {
            self.reset();
            return;
        }
        self.cursors
            .retain(|c| c.get_validity(fb, early, late) == Validity::Pending);
    }

    /// Spawn a prediction from a single input byte (a port of `new_user_byte`).
    /// `now_ms` is the current time (ms).
    pub fn new_user_byte(&mut self, byte: u8, fb: &Frame, now_ms: i64) {
        if self.display_preference == DisplayPreference::Never {
            return;
        }

        self.cull(fb, now_ms);

        let now = now_ms;

        let mut the_byte = byte;
        // Application-mode cursor function (ESC O ...) -> ANSI (ESC [ ...).
        if self.last_byte == 0x1b && the_byte == b'O' {
            the_byte = b'[';
        }
        self.last_byte = the_byte;

        let width = fb.width() as i32;

        for act in self.parser.input(the_byte) {
            match act {
                KeyAction::Print(ch) => {
                    self.init_cursor(fb);
                    if ch == '\u{7f}' {
                        // Backspace.
                        let cur_row = self.cursor().row;
                        let row_idx = self.get_or_make_row(cur_row, width);
                        if self.cursor().base.col > 0 {
                            self.cursor_mut().base.col -= 1;
                            let lfs = self.local_frame_sent;
                            self.cursor_mut().base.expire(lfs, now);
                            let col = self.cursor().base.col;
                            let epoch = self.prediction_epoch;
                            if self.predict_overwrite {
                                let orig = *fb.cell(fb.cursor_row, fb.cursor_col);
                                let cell = &mut self.overlays[row_idx].overlay_cells[col as usize];
                                cell.reset_with_orig();
                                cell.base.active = true;
                                cell.base.tentative_until_epoch = epoch;
                                cell.base.expire(lfs, now);
                                cell.original_contents.push(orig);
                                // replacement = orig, then clear()+append(' ').
                                cell.replacement = orig;
                                cell.replacement.ch = ' ';
                            } else {
                                for i in col..width {
                                    let orig = *fb.cell(cur_row as u16, i as u16);
                                    let (next_active, next_unknown, next_repl, next_actual) =
                                        if i + 2 < width {
                                            let nc = &self.overlays[row_idx].overlay_cells
                                                [(i + 1) as usize];
                                            (
                                                nc.base.active,
                                                nc.unknown,
                                                nc.replacement,
                                                *fb.cell(cur_row as u16, (i + 1) as u16),
                                            )
                                        } else {
                                            (false, false, Cell::blank(), Cell::blank())
                                        };
                                    let cell =
                                        &mut self.overlays[row_idx].overlay_cells[i as usize];
                                    cell.reset_with_orig();
                                    cell.base.active = true;
                                    cell.base.tentative_until_epoch = epoch;
                                    cell.base.expire(lfs, now);
                                    cell.original_contents.push(orig);
                                    if i + 2 < width {
                                        if next_active {
                                            if next_unknown {
                                                cell.unknown = true;
                                            } else {
                                                cell.unknown = false;
                                                cell.replacement = next_repl;
                                            }
                                        } else {
                                            cell.unknown = false;
                                            cell.replacement = next_actual;
                                        }
                                    } else {
                                        cell.unknown = true;
                                    }
                                }
                            }
                        }
                    } else if (ch as u32) < 0x20 || ch.width() != Some(1) {
                        // Control/wide/zero-width character -- unreliable to
                        // predict.
                        self.become_tentative();
                    } else {
                        let cur_row = self.cursor().row;
                        let cur_col = self.cursor().base.col;
                        let row_idx = self.get_or_make_row(cur_row, width);
                        if cur_col + 1 >= width {
                            // Prediction in the last column is unreliable.
                            self.become_tentative();
                        }
                        let epoch = self.prediction_epoch;
                        let lfs = self.local_frame_sent;

                        let rightmost = if self.predict_overwrite {
                            cur_col
                        } else {
                            width - 1
                        };
                        for i in (cur_col + 1..=rightmost).rev() {
                            let orig = *fb.cell(cur_row as u16, i as u16);
                            let (prev_active, prev_unknown, prev_repl) = {
                                let pc = &self.overlays[row_idx].overlay_cells[(i - 1) as usize];
                                (pc.base.active, pc.unknown, pc.replacement)
                            };
                            let prev_actual = *fb.cell(cur_row as u16, (i - 1) as u16);
                            let cell = &mut self.overlays[row_idx].overlay_cells[i as usize];
                            cell.reset_with_orig();
                            cell.base.active = true;
                            cell.base.tentative_until_epoch = epoch;
                            cell.base.expire(lfs, now);
                            cell.original_contents.push(orig);
                            if i == width - 1 {
                                cell.unknown = true;
                            } else if prev_active {
                                if prev_unknown {
                                    cell.unknown = true;
                                } else {
                                    cell.unknown = false;
                                    cell.replacement = prev_repl;
                                }
                            } else {
                                cell.unknown = false;
                                cell.replacement = prev_actual;
                            }
                        }

                        // The cell under the cursor -- the typed character itself.
                        let orig = *fb.cell(cur_row as u16, cur_col as u16);
                        // Default renditions (analogous to `fb.ds.renditions`),
                        // then a heuristic: take the styling from the character
                        // to the left.
                        let (mut rf, mut rb, mut rfl) =
                            (terminal::Color::Default, terminal::Color::Default, 0u16);
                        if cur_col > 0 {
                            let (pa, pu, prepl) = {
                                let pc =
                                    &self.overlays[row_idx].overlay_cells[(cur_col - 1) as usize];
                                (pc.base.active, pc.unknown, pc.replacement)
                            };
                            let pactual = *fb.cell(cur_row as u16, (cur_col - 1) as u16);
                            let src = if pa && !pu { prepl } else { pactual };
                            rf = src.fg;
                            rb = src.bg;
                            rfl = src.flags;
                        }
                        {
                            let cell = &mut self.overlays[row_idx].overlay_cells[cur_col as usize];
                            cell.reset_with_orig();
                            cell.base.active = true;
                            cell.base.tentative_until_epoch = epoch;
                            cell.base.expire(lfs, now);
                            cell.replacement = Cell {
                                ch,
                                fg: rf,
                                bg: rb,
                                flags: rfl,
                            };
                            cell.original_contents.push(orig);
                        }
                        self.cursor_mut().base.expire(lfs, now);
                        if self.cursor().base.col < width - 1 {
                            self.cursor_mut().base.col += 1;
                        } else {
                            self.become_tentative();
                            self.newline_carriage_return(fb, now);
                        }
                    }
                }
                KeyAction::Execute(ch) => {
                    if ch == '\r' {
                        self.become_tentative();
                        self.newline_carriage_return(fb, now);
                    } else {
                        self.become_tentative();
                    }
                }
                KeyAction::Esc => self.become_tentative(),
                KeyAction::Csi(ch) => {
                    if ch == 'C' {
                        // Right arrow.
                        self.init_cursor(fb);
                        if self.cursor().base.col < width - 1 {
                            self.cursor_mut().base.col += 1;
                            let lfs = self.local_frame_sent;
                            self.cursor_mut().base.expire(lfs, now);
                        }
                    } else if ch == 'D' {
                        // Left arrow.
                        self.init_cursor(fb);
                        if self.cursor().base.col > 0 {
                            self.cursor_mut().base.col -= 1;
                            let lfs = self.local_frame_sent;
                            self.cursor_mut().base.expire(lfs, now);
                        }
                    } else {
                        self.become_tentative();
                    }
                }
            }
        }
    }

    fn newline_carriage_return(&mut self, fb: &Frame, now: i64) {
        self.init_cursor(fb);
        self.cursor_mut().base.col = 0;
        if self.cursor().row == fb.height() as i32 - 1 {
            // We don't predict scrolling; use an empty prediction for the last
            // row instead.
            let cur_row = self.cursor().row;
            let width = fb.width() as i32;
            let epoch = self.prediction_epoch;
            let lfs = self.local_frame_sent;
            let row_idx = self.get_or_make_row(cur_row, width);
            for cell in &mut self.overlays[row_idx].overlay_cells {
                cell.base.active = true;
                cell.base.tentative_until_epoch = epoch;
                cell.base.expire(lfs, now);
                cell.replacement.ch = ' ';
            }
        } else {
            self.cursor_mut().row += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DisplayPreference, PredictionEngine};
    use terminal::{Cell, Color, Frame};

    fn frame(cols: u16, rows: u16) -> Frame {
        Frame::blank(cols, rows)
    }

    // Epoch warm-up. In mosh `prediction_epoch` starts at 1, `confirmed_epoch`
    // at 0, and the very first `cull` -- triggered by the size change
    // 0->(cols,rows) -- advances the epoch once more (`reset` -> `become_tentative`).
    // So the VERY FIRST prediction is always tentative and stays hidden until
    // the server confirms it. This helper types and confirms one character,
    // syncing `confirmed_epoch == prediction_epoch`; after that, subsequent
    // predictions are visible right away. A port of the technique from the
    // earlier validated Kotlin port (`PredictionEngineTest.warmUp`).
    fn warm_up(e: &mut PredictionEngine) {
        let blank = frame(20, 1);
        e.set_local_frame_sent(0); // 'a' -> expiration_frame = 0 (offset without +1)
        e.new_user_byte(b'a', &blank, 0);
        e.set_echo_ack(1); // late_ack = 1 >= expiration_frame 0 -> 'a' gets validated
        let mut server = frame(20, 1);
        *server.cell_mut(0, 0) = Cell {
            ch: 'a',
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        };
        server.cursor_col = 1;
        e.cull(&server, 0); // 'a' Correct -> confirmed_epoch == prediction_epoch
        e.set_local_frame_sent(1);
    }

    // Always: the typed character is visible in the overlaid frame immediately
    // (after the epoch warm-up -- mosh's first prediction is tentative, see
    // `warm_up`).
    #[test]
    fn always_shows_typed_char_before_echo() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        warm_up(&mut e);
        let fb = frame(20, 1);
        e.new_user_byte(b'h', &fb, 1000);
        let shown = e.apply(&fb);
        assert_eq!(shown.cell(0, 0).ch, 'h');
        assert_eq!(shown.cursor_col, 1);
    }

    // Confirmation: echo_ack has reached its deadline AND the frame shows 'h'
    // -- the overlay is retired.
    #[test]
    fn confirmed_prediction_is_retired() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        let fb0 = frame(20, 1);
        e.set_local_frame_sent(1);
        e.new_user_byte(b'h', &fb0, 1000);

        // The server echoed the input: the frame contains 'h', echo_ack has
        // reached its deadline.
        let mut fb1 = frame(20, 1);
        *fb1.cell_mut(0, 0) = Cell {
            ch: 'h',
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        };
        fb1.cursor_col = 1;
        e.set_echo_ack(1);
        e.cull(&fb1, 1050);

        // Overlaying adds nothing further: the frame is already correct.
        let shown = e.apply(&fb1);
        assert_eq!(shown.cell(0, 0).ch, 'h');
        assert!(
            !e.active(),
            "no active predictions remain after confirmation"
        );
    }

    // Never: show nothing.
    #[test]
    fn never_shows_nothing() {
        let mut e = PredictionEngine::new(DisplayPreference::Never);
        let fb = frame(20, 1);
        e.new_user_byte(b'h', &fb, 1000);
        let shown = e.apply(&fb);
        assert_eq!(shown.cell(0, 0).ch, ' ');
    }

    // Adaptive: on a fast link (small send_interval) we don't show the prediction.
    #[test]
    fn adaptive_hides_on_fast_link() {
        let mut e = PredictionEngine::new(DisplayPreference::Adaptive);
        let fb = frame(20, 1);
        e.set_send_interval(10); // faster than the SRTT threshold
        e.set_local_frame_sent(1);
        e.new_user_byte(b'h', &fb, 1000);
        assert!(!e.active());
        assert_eq!(e.apply(&fb).cell(0, 0).ch, ' ');
    }

    // Adaptive: on a slow link (large send_interval) we do show it (after the
    // epoch warm-up; culling during warm-up sets srtt_trigger).
    #[test]
    fn adaptive_shows_on_slow_link() {
        let mut e = PredictionEngine::new(DisplayPreference::Adaptive);
        e.set_send_interval(100); // above the SRTT_TRIGGER_HIGH threshold (30)
        warm_up(&mut e);
        let fb = frame(20, 1);
        e.new_user_byte(b'h', &fb, 1000);
        assert!(e.active());
        assert_eq!(e.apply(&fb).cell(0, 0).ch, 'h');
    }

    // predict_overwrite defaults to false (unset -- no caller ever touches
    // `set_predict_overwrite`): typing a character DOES change the cell under
    // the cursor, exactly like every other test above.
    #[test]
    fn predict_overwrite_defaults_to_false() {
        let e = PredictionEngine::new(DisplayPreference::Always);
        assert!(
            !e.predict_overwrite,
            "predict_overwrite must default to false"
        );
    }

    // The caller can change overwrite prediction after construction.
    #[test]
    fn set_predict_overwrite_changes_the_field() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        e.set_predict_overwrite(true);
        assert!(e.predict_overwrite);
        e.set_predict_overwrite(false);
        assert!(!e.predict_overwrite);
    }
}
