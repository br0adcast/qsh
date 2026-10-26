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

use crate::budget::{self, Budget, Exhausted};
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

#[cfg(test)]
#[derive(Default, Clone, Copy)]
struct ObservedWork {
    culls: u64,
    cells: u64,
    cursors: u64,
}

/// Input prediction engine with bounded speculative backing and work.
/// Input parsing and authoritative frame cloning remain independent of speculation.
pub struct PredictionEngine {
    budget: Budget,
    suppressed_until: Option<i64>,
    active_cells: usize,
    overlay_cells: usize,
    #[cfg(test)]
    observed_work: ObservedWork,
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
            budget: Budget::default(),
            suppressed_until: None,
            active_cells: 0,
            overlay_cells: 0,
            #[cfg(test)]
            observed_work: ObservedWork::default(),
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
        if pref == DisplayPreference::Never {
            if self.local_frame_sent > self.local_frame_late_acked {
                self.suppress();
            } else {
                self.release();
            }
        }
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
        if let Some(until) = &mut self.suppressed_until {
            *until = (*until).max(x);
        }
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

    /// The interval most recently supplied by any evaluation path.
    pub fn send_interval_ms(&self) -> i64 {
        self.send_interval
    }

    /// Glitch activation and quick repair happen after flagging in `cull`.
    /// Both can require a following evaluation, even without another timer.
    pub fn display_refresh_pending(&self) -> bool {
        self.active() && self.flagging_decision() != self.flagging
    }

    fn flagging_decision(&self) -> bool {
        let interval_flag = if self.send_interval > FLAG_TRIGGER_HIGH {
            true
        } else if self.send_interval <= FLAG_TRIGGER_LOW {
            false
        } else {
            self.flagging
        };
        interval_flag || self.glitch_trigger > GLITCH_REPAIR_COUNT
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
        !self.cursors.is_empty() || self.active_cells != 0
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
        self.suppressed_until.is_none() && self.showing() && self.has_active_overlays()
    }

    /// Earliest existing time-driven display transition for pending cells.
    /// Hidden adaptive predictions participate; ACK/frame validity and tentative
    /// epochs are still evaluated by `cull`, not changed by this query.
    pub fn next_display_deadline_ms(&self) -> Option<i64> {
        if self.display_preference == DisplayPreference::Never || self.suppressed_until.is_some() {
            return None;
        }
        let delay = if self.glitch_trigger < GLITCH_REPAIR_COUNT {
            GLITCH_THRESHOLD
        } else if self.glitch_trigger == GLITCH_REPAIR_COUNT {
            GLITCH_FLAG_THRESHOLD
        } else {
            return None;
        };
        self.overlays
            .iter()
            .flat_map(|row| &row.overlay_cells)
            .filter(|cell| {
                cell.base.active && self.local_frame_late_acked < cell.base.expiration_frame
            })
            .map(|cell| cell.base.prediction_time.saturating_add(delay))
            .min()
    }

    /// Overlay the active predictions onto a COPY of frame `fb` and return it.
    /// If there is nothing to show (`!active()`), return an unmodified copy
    /// (a port of mosh's display condition: `apply` is a no-op when prediction
    /// is inactive).
    pub fn apply(&mut self, fb: &Frame) -> Frame {
        self.apply_owned(fb.clone())
    }

    /// Apply predictions to an owned snapshot, retaining its cell allocation.
    /// The authoritative terminal model must not be mutated by presentation.
    pub fn apply_owned(&mut self, mut frame: Frame) -> Frame {
        if !self.active() {
            return frame;
        }
        if self
            .budget
            .work(self.cursors.len() + self.overlays.len() + self.overlay_cells)
            .is_err()
        {
            self.suppress();
            return frame;
        }
        for c in &self.cursors {
            c.apply(&mut frame, self.confirmed_epoch);
        }
        for row in &self.overlays {
            row.apply(&mut frame, self.confirmed_epoch, self.flagging);
        }
        frame
    }

    /// Reset all predictions (a port of `reset`): clear overlays/cursors and
    /// move to a new epoch.
    pub fn reset(&mut self) {
        self.release();
        self.become_tentative();
    }

    /// Start a new authenticated connection's input-offset scope. Visual resets,
    /// resizes and display preferences must keep using `reset` instead.
    /// The keystroke parser continues across the reconnect, as before.
    pub fn reset_connection(&mut self) {
        self.reset();
        self.suppressed_until = None;
        self.local_frame_sent = 0;
        self.local_frame_acked = 0;
        self.local_frame_late_acked = 0;
        self.budget.acknowledged();
    }

    fn release(&mut self) {
        // Cell is Copy; destroying a row visits only its bounded nested vectors.
        // Their cleanup was reserved when the row was created.
        self.overlays = Vec::new();
        self.cursors = Vec::new();
        self.active_cells = 0;
        self.overlay_cells = 0;
        self.budget.release_all();
    }

    fn suppress(&mut self) {
        self.suppressed_until = Some(
            self.local_frame_sent
                .max(self.suppressed_until.unwrap_or(0)),
        );
        self.release();
        self.become_tentative();
    }

    fn become_tentative(&mut self) {
        self.prediction_epoch += 1;
    }

    // Kill an ambiguous epoch: drop that epoch's predictions, recreate the
    // cursor from the actual position, and move to a new epoch (a port of
    // `kill_epoch`).
    fn kill_epoch(&mut self, epoch: i64, fb: &Frame) -> budget::Result {
        self.budget.work(self.cursors.len())?;
        self.cursors.retain(|c| !c.base.tentative(epoch - 1));
        // The constructor keeps the `+ 1` as in mosh (see the module doc comment).
        let exp = self.local_frame_sent + 1;
        let pe = self.prediction_epoch;
        if self.cursors.len() == self.budget.max_cursors() {
            return Err(Exhausted);
        }
        budget::push(
            &mut self.cursors,
            ConditionalCursorMove::new(exp, fb.cursor_row as i32, fb.cursor_col as i32, pe),
            &mut self.budget,
        )?;
        self.cursor_mut().base.active = true;
        for row in &mut self.overlays {
            self.budget.work(1)?;
            for cell in &mut row.overlay_cells {
                self.budget.work(1)?;
                if cell.base.tentative(epoch - 1) {
                    self.active_cells -= usize::from(cell.base.active);
                    cell.reset();
                }
            }
        }
        self.become_tentative();
        Ok(())
    }

    // Ensure a current-epoch cursor prediction exists (a port of `init_cursor`).
    // The constructors keep the `+ 1` as in mosh.
    fn init_cursor(&mut self, fb: &Frame) -> budget::Result {
        let exp = self.local_frame_sent + 1;
        let pe = self.prediction_epoch;
        if self.cursors.is_empty() {
            if self.cursors.len() == self.budget.max_cursors() {
                return Err(Exhausted);
            }
            budget::push(
                &mut self.cursors,
                ConditionalCursorMove::new(exp, fb.cursor_row as i32, fb.cursor_col as i32, pe),
                &mut self.budget,
            )?;
            self.cursor_mut().base.active = true;
        } else if self.cursor().base.tentative_until_epoch != pe {
            let (r, c) = {
                let cu = self.cursor();
                (cu.row, cu.base.col)
            };
            if self.cursors.len() == self.budget.max_cursors() {
                return Err(Exhausted);
            }
            budget::push(
                &mut self.cursors,
                ConditionalCursorMove::new(exp, r, c, pe),
                &mut self.budget,
            )?;
            self.cursor_mut().base.active = true;
        }
        Ok(())
    }

    // Find or create an overlay row for the given row number; return its index
    // in `overlays` (a port of `get_or_make_row`, but returning an index --
    // Rust's borrow checker).
    fn get_or_make_row(&mut self, row_num: i32, num_cols: i32) -> budget::Result<usize> {
        for (idx, row) in self.overlays.iter().enumerate() {
            self.budget.work(1)?;
            if row.row_num == row_num {
                return Ok(idx);
            }
        }
        let width = num_cols.max(0) as usize;
        self.budget.reserve_cleanup(2 * width + 1)?;
        let mut cells = Vec::new();
        budget::reserve(&mut cells, width, &mut self.budget)?;
        for i in 0..width {
            self.budget.work(1)?;
            cells.push(ConditionalOverlayCell::new(
                0,
                i as i32,
                self.prediction_epoch,
            ));
        }
        budget::push(
            &mut self.overlays,
            ConditionalOverlayRow {
                row_num,
                overlay_cells: cells,
            },
            &mut self.budget,
        )?;
        self.overlay_cells += width;
        Ok(self.overlays.len() - 1)
    }

    /// Retire/confirm predictions against the authoritative frame `fb` (a port
    /// of `cull`). `now_ms` is the current time (ms) for glitch timing.
    pub fn cull(&mut self, fb: &Frame, now_ms: i64) {
        // Only an ACK consumed together with an authoritative frame can open a
        // new episode. A setter, resize, mode switch or partial ACK cannot.
        if let Some(until) = self.suppressed_until {
            if self.local_frame_late_acked < until {
                return;
            }
            self.suppressed_until = None;
            self.budget.acknowledged();
        } else if self.local_frame_late_acked >= self.local_frame_sent {
            self.budget.acknowledged();
        }
        if self.cull_inner(fb, now_ms).is_err() {
            self.suppress();
            // This frame already consumed the complete ACK. Abandoning costly
            // validation must not leave an already-satisfied fence for the next
            // input setter to extend before another frame arrives.
            if self.local_frame_late_acked >= self.local_frame_sent {
                self.suppressed_until = None;
                self.budget.acknowledged();
            }
        }
    }

    fn cull_inner(&mut self, fb: &Frame, now_ms: i64) -> budget::Result {
        if self.display_preference == DisplayPreference::Never {
            return Ok(());
        }

        if self.last_height != fb.height() || self.last_width != fb.width() {
            self.last_height = fb.height();
            self.last_width = fb.width();
            self.reset();
        }

        #[cfg(test)]
        {
            self.observed_work.culls += 1;
        }
        self.budget.work(1)?;
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

        // Keep the display query and evaluation on the same hysteresis rule.
        self.flagging = self.flagging_decision();

        let early = self.local_frame_acked;
        let late = self.local_frame_late_acked;

        let mut row_i = 0;
        while row_i < self.overlays.len() {
            self.budget.work(1)?;
            let row_num = self.overlays[row_i].row_num;
            if row_num < 0 || row_num >= fb.height() as i32 {
                self.budget.work(self.overlays.len() - row_i)?;
                let row = self.overlays.remove(row_i);
                let mut bytes =
                    row.overlay_cells.capacity() * std::mem::size_of::<ConditionalOverlayCell>();
                for cell in &row.overlay_cells {
                    bytes += cell.original_contents.capacity() * std::mem::size_of::<Cell>();
                    self.active_cells -= usize::from(cell.base.active);
                }
                self.overlay_cells -= row.overlay_cells.len();
                self.budget.release_row(bytes, row.overlay_cells.len());
                continue;
            }
            let ncells = self.overlays[row_i].overlay_cells.len();
            let mut j = 0;
            while j < ncells {
                #[cfg(test)]
                {
                    self.observed_work.cells += 1;
                }
                self.budget.work(1)?;
                let validity = self.overlays[row_i].overlay_cells[j].validity_budgeted(
                    fb,
                    row_num,
                    early,
                    late,
                    &mut self.budget,
                )?;
                match validity {
                    Validity::IncorrectOrExpired => {
                        if self.overlays[row_i].overlay_cells[j]
                            .base
                            .tentative(self.confirmed_epoch)
                        {
                            let tue = self.overlays[row_i].overlay_cells[j]
                                .base
                                .tentative_until_epoch;
                            self.kill_epoch(tue, fb)?;
                        } else {
                            self.reset();
                            return Ok(());
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
                            self.budget.work(1)?;
                            let repl = &mut self.overlays[row_i].overlay_cells[k].replacement;
                            repl.fg = actual.fg;
                            repl.bg = actual.bg;
                            repl.flags = actual.flags;
                        }
                        self.active_cells -=
                            usize::from(self.overlays[row_i].overlay_cells[j].base.active);
                        self.overlays[row_i].overlay_cells[j].reset();
                    }
                    Validity::CorrectNoCredit => {
                        self.active_cells -=
                            usize::from(self.overlays[row_i].overlay_cells[j].base.active);
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
        #[cfg(test)]
        if !self.cursors.is_empty() {
            self.observed_work.cursors += 1;
        }
        self.budget.work(usize::from(!self.cursors.is_empty()))?;
        if !self.cursors.is_empty()
            && self.cursor().get_validity(fb, early, late) == Validity::IncorrectOrExpired
        {
            self.reset();
            return Ok(());
        }
        self.budget.work(self.cursors.len())?;
        #[cfg(test)]
        let observed_work = &mut self.observed_work;
        self.cursors.retain(|c| {
            #[cfg(test)]
            {
                observed_work.cursors += 1;
            }
            c.get_validity(fb, early, late) == Validity::Pending
        });
        Ok(())
    }

    /// Spawn a prediction from a single input byte (a port of `new_user_byte`).
    /// `now_ms` is the current time (ms).
    pub fn new_user_byte(&mut self, byte: u8, fb: &Frame, now_ms: i64) {
        self.cull(fb, now_ms);
        self.parse_byte(byte, fb, now_ms);
    }

    fn parse_byte(&mut self, byte: u8, fb: &Frame, now: i64) {
        let mut the_byte = byte;
        // Application-mode cursor function (ESC O ...) -> ANSI (ESC [ ...).
        if self.last_byte == 0x1b && the_byte == b'O' {
            the_byte = b'[';
        }
        self.last_byte = the_byte;

        for act in self.parser.input(the_byte) {
            if self.suppressed_until.is_some()
                || self.display_preference == DisplayPreference::Never
            {
                if self.display_preference == DisplayPreference::Never
                    && self.local_frame_sent > self.local_frame_late_acked
                {
                    self.suppressed_until = Some(self.local_frame_sent);
                }
                continue;
            }
            if self.predict_action(act, fb, now).is_err() {
                self.suppress();
            }
        }
    }

    fn predict_action(&mut self, act: KeyAction, fb: &Frame, now: i64) -> budget::Result {
        self.budget.work(1)?;
        let width = fb.width() as i32;
        match act {
            KeyAction::Print(ch) => {
                self.init_cursor(fb)?;
                if ch == '\u{7f}' {
                    // Backspace.
                    let cur_row = self.cursor().row;
                    let row_idx = self.get_or_make_row(cur_row, width)?;
                    if self.cursor().base.col > 0 {
                        self.cursor_mut().base.col -= 1;
                        let lfs = self.local_frame_sent;
                        self.cursor_mut().base.expire(lfs, now);
                        let col = self.cursor().base.col;
                        let epoch = self.prediction_epoch;
                        if self.predict_overwrite {
                            let orig = *fb.cell(fb.cursor_row, fb.cursor_col);
                            self.budget.work(1)?;
                            self.active_cells += usize::from(
                                !self.overlays[row_idx].overlay_cells[col as usize]
                                    .base
                                    .active,
                            );
                            let cell = &mut self.overlays[row_idx].overlay_cells[col as usize];
                            reset_cell_with_orig(cell, &mut self.budget)?;
                            cell.base.active = true;
                            cell.base.tentative_until_epoch = epoch;
                            cell.base.expire(lfs, now);
                            budget::push(&mut cell.original_contents, orig, &mut self.budget)?;
                            // replacement = orig, then clear()+append(' ').
                            cell.replacement = orig;
                            cell.replacement.set_char(' ');
                        } else {
                            for i in col..width {
                                self.budget.work(1)?;
                                self.active_cells += usize::from(
                                    !self.overlays[row_idx].overlay_cells[i as usize].base.active,
                                );
                                let orig = *fb.cell(cur_row as u16, i as u16);
                                let (next_active, next_unknown, next_repl, next_actual) =
                                    if i + 2 < width {
                                        let nc =
                                            &self.overlays[row_idx].overlay_cells[(i + 1) as usize];
                                        (
                                            nc.base.active,
                                            nc.unknown,
                                            nc.replacement,
                                            *fb.cell(cur_row as u16, (i + 1) as u16),
                                        )
                                    } else {
                                        (false, false, Cell::blank(), Cell::blank())
                                    };
                                let cell = &mut self.overlays[row_idx].overlay_cells[i as usize];
                                reset_cell_with_orig(cell, &mut self.budget)?;
                                cell.base.active = true;
                                cell.base.tentative_until_epoch = epoch;
                                cell.base.expire(lfs, now);
                                budget::push(&mut cell.original_contents, orig, &mut self.budget)?;
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
                    let row_idx = self.get_or_make_row(cur_row, width)?;
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
                        self.budget.work(1)?;
                        self.active_cells += usize::from(
                            !self.overlays[row_idx].overlay_cells[i as usize].base.active,
                        );
                        let orig = *fb.cell(cur_row as u16, i as u16);
                        let (prev_active, prev_unknown, prev_repl) = {
                            let pc = &self.overlays[row_idx].overlay_cells[(i - 1) as usize];
                            (pc.base.active, pc.unknown, pc.replacement)
                        };
                        let prev_actual = *fb.cell(cur_row as u16, (i - 1) as u16);
                        let cell = &mut self.overlays[row_idx].overlay_cells[i as usize];
                        reset_cell_with_orig(cell, &mut self.budget)?;
                        cell.base.active = true;
                        cell.base.tentative_until_epoch = epoch;
                        cell.base.expire(lfs, now);
                        budget::push(&mut cell.original_contents, orig, &mut self.budget)?;
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
                            let pc = &self.overlays[row_idx].overlay_cells[(cur_col - 1) as usize];
                            (pc.base.active, pc.unknown, pc.replacement)
                        };
                        let pactual = *fb.cell(cur_row as u16, (cur_col - 1) as u16);
                        let src = if pa && !pu { prepl } else { pactual };
                        rf = src.fg;
                        rb = src.bg;
                        rfl = src.flags;
                    }
                    {
                        self.budget.work(1)?;
                        self.active_cells += usize::from(
                            !self.overlays[row_idx].overlay_cells[cur_col as usize]
                                .base
                                .active,
                        );
                        let cell = &mut self.overlays[row_idx].overlay_cells[cur_col as usize];
                        reset_cell_with_orig(cell, &mut self.budget)?;
                        cell.base.active = true;
                        cell.base.tentative_until_epoch = epoch;
                        cell.base.expire(lfs, now);
                        cell.replacement = Cell {
                            ch,
                            fg: rf,
                            bg: rb,
                            combining: Default::default(),
                            flags: rfl,
                        };
                        budget::push(&mut cell.original_contents, orig, &mut self.budget)?;
                    }
                    self.cursor_mut().base.expire(lfs, now);
                    if self.cursor().base.col < width - 1 {
                        self.cursor_mut().base.col += 1;
                    } else {
                        self.become_tentative();
                        self.newline_carriage_return(fb, now)?;
                    }
                }
            }
            KeyAction::Execute(ch) => {
                if ch == '\r' {
                    self.become_tentative();
                    self.newline_carriage_return(fb, now)?;
                } else {
                    self.become_tentative();
                }
            }
            KeyAction::Esc => self.become_tentative(),
            KeyAction::Csi(ch) => {
                if ch == 'C' {
                    // Right arrow.
                    self.init_cursor(fb)?;
                    if self.cursor().base.col < width - 1 {
                        self.cursor_mut().base.col += 1;
                        let lfs = self.local_frame_sent;
                        self.cursor_mut().base.expire(lfs, now);
                    }
                } else if ch == 'D' {
                    // Left arrow.
                    self.init_cursor(fb)?;
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
        Ok(())
    }

    fn newline_carriage_return(&mut self, fb: &Frame, now: i64) -> budget::Result {
        self.init_cursor(fb)?;
        self.cursor_mut().base.col = 0;
        if self.cursor().row == fb.height() as i32 - 1 {
            // We don't predict scrolling; use an empty prediction for the last
            // row instead.
            let cur_row = self.cursor().row;
            let width = fb.width() as i32;
            let epoch = self.prediction_epoch;
            let lfs = self.local_frame_sent;
            let row_idx = self.get_or_make_row(cur_row, width)?;
            for cell in &mut self.overlays[row_idx].overlay_cells {
                self.budget.work(1)?;
                self.active_cells += usize::from(!cell.base.active);
                cell.base.active = true;
                cell.base.tentative_until_epoch = epoch;
                cell.base.expire(lfs, now);
                cell.replacement.set_char(' ');
            }
        } else {
            self.cursor_mut().row += 1;
        }
        Ok(())
    }
}

fn reset_cell_with_orig(cell: &mut ConditionalOverlayCell, budget: &mut Budget) -> budget::Result {
    if cell.base.active && !cell.unknown {
        budget.work(1)?;
        budget::reserve(&mut cell.original_contents, 1, budget)?;
    }
    // The existing operation cannot grow: its possible push was reserved above.
    cell.reset_with_orig();
    Ok(())
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
    pub(super) fn warm_up(e: &mut PredictionEngine) {
        let blank = frame(20, 1);
        e.set_local_frame_sent(0); // 'a' -> expiration_frame = 0 (offset without +1)
        e.new_user_byte(b'a', &blank, 0);
        e.set_echo_ack(1); // late_ack = 1 >= expiration_frame 0 -> 'a' gets validated
        let mut server = frame(20, 1);
        *server.cell_mut(0, 0) = Cell {
            ch: 'a',
            fg: Color::Default,
            bg: Color::Default,
            combining: Default::default(),
            flags: 0,
        };
        server.cursor_col = 1;
        e.cull(&server, 0); // 'a' Correct -> confirmed_epoch == prediction_epoch
        e.set_local_frame_sent(1);
    }

    #[test]
    fn complete_cell_overwrite_backspace_clears_marks() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        warm_up(&mut e);
        e.set_predict_overwrite(true);
        let mut fb = frame(20, 1);
        for cell in &mut fb.cells[..2] {
            cell.ch = 'e';
            cell.combining = terminal::CombiningMarks::from_slice(&['\u{301}']);
            cell.flags = terminal::FLAG_HIDDEN;
        }
        fb.cursor_col = 1;
        e.new_user_byte(0x7f, &fb, 1000);
        let shown = e.apply(&fb);
        assert_eq!(shown.cells[0].ch, ' ');
        assert!(shown.cells[0].combining.is_empty());
        assert_ne!(shown.cells[0].flags & terminal::FLAG_HIDDEN, 0);
    }

    #[test]
    fn complete_cell_delete_moves_marks_and_hidden_style() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        warm_up(&mut e);
        let mut fb = frame(20, 1);
        fb.cursor_col = 1;
        fb.cells[1].ch = 'e';
        fb.cells[1].combining = terminal::CombiningMarks::from_slice(&['\u{301}']);
        fb.cells[1].flags = terminal::FLAG_HIDDEN;
        e.new_user_byte(0x7f, &fb, 1000);
        let mut expected = fb.cells[1];
        expected.flags |= terminal::FLAG_UNDERLINE; // Existing prediction highlighting.
        assert_eq!(e.apply(&fb).cells[0], expected);
    }

    #[test]
    fn complete_cell_new_text_inherits_style_but_not_marks() {
        let mut e = PredictionEngine::new(DisplayPreference::Always);
        warm_up(&mut e);
        e.set_predict_overwrite(true);
        let mut fb = frame(20, 1);
        fb.cursor_col = 1;
        for cell in &mut fb.cells[..2] {
            cell.ch = 'e';
            cell.combining = terminal::CombiningMarks::from_slice(&['\u{301}']);
            cell.flags = terminal::FLAG_HIDDEN;
        }
        e.new_user_byte(b'x', &fb, 1000);
        let shown = e.apply(&fb);
        assert_eq!(shown.cells[1].ch, 'x');
        assert!(shown.cells[1].combining.is_empty());
        assert_ne!(shown.cells[1].flags & terminal::FLAG_HIDDEN, 0);
        assert_eq!(shown.cells[0], fb.cells[0]);
    }

    #[test]
    fn owned_apply_matches_borrowed_cells_and_budget_effects_without_replacing_storage() {
        for (preference, exhausted) in [
            (DisplayPreference::Never, false),
            (DisplayPreference::Always, false),
            (DisplayPreference::Always, true),
        ] {
            let mut borrowed = PredictionEngine::new(preference);
            let mut owned = PredictionEngine::new(preference);
            warm_up(&mut borrowed);
            warm_up(&mut owned);
            let mut core = terminal::TerminalCore::new(20, 1);
            core.feed("e\u{301}界\u{302}".as_bytes());
            let mut source = core.frame();
            source.cursor_col = 4;
            source.cells[4].flags = terminal::FLAG_HIDDEN;
            for engine in [&mut borrowed, &mut owned] {
                engine.new_user_byte(b'x', &source, 1000);
                if preference == DisplayPreference::Always {
                    assert!(engine.active());
                }
                if exhausted {
                    engine.budget.limits.work = 0;
                }
            }
            let expected = borrowed.apply(&source);
            let pointer = source.cells.as_ptr();
            let actual = owned.apply_owned(source);
            assert_eq!(actual, expected);
            assert_eq!(actual.cells.as_ptr(), pointer);
            assert_eq!(owned.budget.used, borrowed.budget.used);
            assert_eq!(owned.budget.bytes, borrowed.budget.bytes);
            assert_eq!(owned.suppressed_until, borrowed.suppressed_until);
            assert_eq!(owned.active(), borrowed.active());
            if exhausted {
                assert!(!owned.active());
            }
        }
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
            combining: Default::default(),
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

    #[test]
    fn eligibility_flagging_refresh_preserves_mid_interval_hysteresis() {
        let mut engine = PredictionEngine::new(DisplayPreference::Always);
        engine.set_local_frame_sent(1);
        engine.set_send_interval(60);
        engine.new_user_byte(b'h', &frame(20, 1), 1000);
        assert!(!engine.flagging);
        assert!(!engine.display_refresh_pending());
        engine.flagging = true;
        assert!(
            !engine.display_refresh_pending(),
            "mid interval retains underline"
        );
        engine.set_send_interval(50);
        assert!(
            engine.display_refresh_pending(),
            "low interval clears underline"
        );
        engine.set_send_interval(80);
        assert!(
            !engine.display_refresh_pending(),
            "upper boundary retains prior state"
        );
        engine.flagging = false;
        assert!(!engine.display_refresh_pending());
        engine.set_send_interval(81);
        assert!(
            engine.display_refresh_pending(),
            "above upper boundary enables underline"
        );
        engine.set_display_preference(DisplayPreference::Never);
        assert!(!engine.display_refresh_pending());
    }

    #[test]
    fn eligibility_severe_flagging_has_one_following_evaluation() {
        let mut engine = PredictionEngine::new(DisplayPreference::Adaptive);
        let fb = frame(20, 1);
        engine.set_send_interval(10);
        assert_eq!(engine.send_interval_ms(), 10);
        engine.set_local_frame_sent(1);
        engine.new_user_byte(b'h', &fb, 1000);
        assert!(!engine.display_refresh_pending());
        engine.cull(&fb, 6000);
        assert!(engine.display_refresh_pending());
        let work = engine.observed_work;
        assert!(engine.display_refresh_pending());
        assert_eq!(engine.next_display_deadline_ms(), None);
        assert_eq!(
            (work.culls, work.cells, work.cursors),
            (
                engine.observed_work.culls,
                engine.observed_work.cells,
                engine.observed_work.cursors
            )
        );
        engine.cull(&fb, 6020);
        assert!(!engine.display_refresh_pending());
        engine.suppress();
        assert!(!engine.display_refresh_pending());
    }

    #[test]
    fn hidden_display_deadlines_follow_pending_cells_and_policy() {
        let mut engine = PredictionEngine::new(DisplayPreference::Adaptive);
        let fb = frame(20, 1);
        engine.set_send_interval(10);
        engine.set_local_frame_sent(1);
        engine.new_user_byte(b'h', &fb, 1000);
        assert!(!engine.active());
        assert_eq!(engine.next_display_deadline_ms(), Some(1250));
        engine.cull(&fb, 1249);
        assert_eq!(engine.next_display_deadline_ms(), Some(1250));
        engine.cull(&fb, 1250);
        assert_eq!(engine.next_display_deadline_ms(), Some(6000));
        engine.cull(&fb, 6000);
        assert_eq!(engine.next_display_deadline_ms(), None);
        let mut acknowledged = PredictionEngine::new(DisplayPreference::Adaptive);
        acknowledged.set_local_frame_sent(2);
        acknowledged.new_user_byte(b'h', &fb, 1000);
        assert_eq!(acknowledged.next_display_deadline_ms(), Some(1250));
        acknowledged.set_echo_ack(1);
        assert_eq!(acknowledged.next_display_deadline_ms(), Some(1250));
        acknowledged.set_echo_ack(2);
        assert_eq!(acknowledged.next_display_deadline_ms(), None);

        let mut suppressed = PredictionEngine::new(DisplayPreference::Adaptive);
        suppressed.set_local_frame_sent(1);
        suppressed.new_user_byte(b'h', &fb, 1000);
        suppressed.suppress();
        assert_eq!(suppressed.next_display_deadline_ms(), None);
        let mut never = PredictionEngine::new(DisplayPreference::Never);
        never.set_local_frame_sent(1);
        never.new_user_byte(b'h', &fb, 1000);
        assert_eq!(never.next_display_deadline_ms(), None);
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

#[cfg(test)]
#[path = "engine_budget_tests.rs"]
mod budget_tests;
