//! Overlay types for prediction: a port of mosh's `terminaloverlay.{h,cc}`
//! (the `ConditionalOverlay`/`ConditionalCursorMove`/`ConditionalOverlayCell`/
//! `ConditionalOverlayRow` classes and the `Validity` enum). They operate on
//! a `terminal::Frame` grid snapshot -- overlaying a prediction onto a copy
//! of the frame and judging its correctness against the server. Composition
//! instead of C++/Kotlin inheritance: shared fields/methods are factored into
//! `ConditionalOverlay` and held in the `base` field.

use terminal::{Cell, Color, Frame, FLAG_UNDERLINE};

/// Validity of a prediction against the authoritative (server-provided) frame.
/// A port of `Overlay::Validity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Pending,
    Correct,
    CorrectNoCredit,
    IncorrectOrExpired,
    Inactive,
}

/// Base of a conditional overlay (a port of `ConditionalOverlay`): a prediction
/// valid up to frame `expiration_frame`, bound to column `col`; "tentative"
/// (not shown) while `tentative_until_epoch` is greater than the confirmed
/// epoch.
///
/// The `-1` sentinel after `reset` is a port of mosh's `uint64_t(-1)` (also
/// used as the sentinel for `prediction_time` before a prediction has been
/// stamped with `expire`). Frame/epoch numbers are typed as `i64` (as in the
/// earlier, reviewed Kotlin port) rather than `u64` as in the original.
#[derive(Debug, Clone, Copy)]
pub struct ConditionalOverlay {
    pub expiration_frame: i64,
    pub col: i32,
    /// Whether there is a prediction at all.
    pub active: bool,
    /// When the prediction becomes visible.
    pub tentative_until_epoch: i64,
    /// When the prediction was made (used to find long-pending ones). `-1`
    /// means not yet set.
    pub prediction_time: i64,
}

impl ConditionalOverlay {
    pub fn new(expiration_frame: i64, col: i32, tentative_until_epoch: i64) -> Self {
        ConditionalOverlay {
            expiration_frame,
            col,
            active: false,
            tentative_until_epoch,
            prediction_time: -1,
        }
    }

    pub fn tentative(&self, confirmed_epoch: i64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }

    pub fn reset(&mut self) {
        self.expiration_frame = -1;
        self.tentative_until_epoch = -1;
        self.active = false;
    }

    pub fn expire(&mut self, expiration_frame: i64, now: i64) {
        self.expiration_frame = expiration_frame;
        self.prediction_time = now;
    }
}

/// A cursor-movement prediction (a port of `ConditionalCursorMove`).
#[derive(Debug, Clone, Copy)]
pub struct ConditionalCursorMove {
    pub base: ConditionalOverlay,
    pub row: i32,
}

impl ConditionalCursorMove {
    pub fn new(expiration_frame: i64, row: i32, col: i32, tentative_until_epoch: i64) -> Self {
        ConditionalCursorMove {
            base: ConditionalOverlay::new(expiration_frame, col, tentative_until_epoch),
            row,
        }
    }

    pub fn apply(&self, fb: &mut Frame, confirmed_epoch: i64) {
        if !self.base.active {
            return;
        }
        if self.base.tentative(confirmed_epoch) {
            return;
        }
        // A port of mosh's assert (terminaloverlay.cc) as a safe early return:
        // in a release build this is a debug-only assert stripped from the
        // binary; the row/column is held by the caller (cull), and origin mode
        // isn't guaranteed for them -- in that mode the cursor prediction is
        // unreliable and gets skipped instead of crashing the terminal (see
        // fix cbd54cc in the earlier Kotlin port of this same logic).
        if self.row >= fb.height() as i32 || self.base.col >= fb.width() as i32 || fb.origin_mode {
            return;
        }
        fb.cursor_row = self.row as u16;
        fb.cursor_col = self.base.col as u16;
    }

    pub fn get_validity(&self, fb: &Frame, _early_ack: i64, late_ack: i64) -> Validity {
        if !self.base.active {
            return Validity::Inactive;
        }
        if self.row >= fb.height() as i32 || self.base.col >= fb.width() as i32 {
            return Validity::IncorrectOrExpired;
        }
        if late_ack >= self.base.expiration_frame {
            if fb.cursor_col == self.base.col as u16 && fb.cursor_row == self.row as u16 {
                Validity::Correct
            } else {
                Validity::IncorrectOrExpired
            }
        } else {
            Validity::Pending
        }
    }
}

/// A prediction of a single cell's contents (a port of `ConditionalOverlayCell`).
#[derive(Debug, Clone)]
pub struct ConditionalOverlayCell {
    pub base: ConditionalOverlay,
    /// What we predict for the cell. Colors/attributes (`fg`/`bg`/`flags`) are
    /// already set by the caller (the prediction engine) -- `apply`
    /// doesn't compute them, it only writes them and adds the underline flag
    /// when requested.
    pub replacement: Cell,
    /// Contents are unknown (a shift-right at the edge of the row -- what
    /// ends up there can't be predicted).
    pub unknown: bool,
    /// The cell's original values before predictions in this episode -- we
    /// don't give "credit" for a prediction matching them (a port of
    /// `original_contents`).
    pub original_contents: Vec<Cell>,
}

impl ConditionalOverlayCell {
    pub fn new(expiration_frame: i64, col: i32, tentative_until_epoch: i64) -> Self {
        ConditionalOverlayCell {
            base: ConditionalOverlay::new(expiration_frame, col, tentative_until_epoch),
            replacement: Cell {
                ch: '\0',
                fg: Color::Default,
                bg: Color::Default,
                flags: 0,
            },
            unknown: false,
            original_contents: Vec::new(),
        }
    }

    pub fn apply(&self, fb: &mut Frame, confirmed_epoch: i64, row: i32, mut flag: bool) {
        if !self.base.active || row >= fb.height() as i32 || self.base.col >= fb.width() as i32 {
            return;
        }
        if self.base.tentative(confirmed_epoch) {
            return;
        }

        let col = self.base.col as u16;
        if self.replacement.is_blank() && fb.cell(row as u16, col).is_blank() {
            // A blank prediction over an already-blank cell -- nothing to
            // underline.
            flag = false;
        }

        if self.unknown {
            if flag && self.base.col != fb.width() as i32 - 1 {
                fb.cell_mut(row as u16, col).flags |= FLAG_UNDERLINE;
            }
            return;
        }

        if *fb.cell(row as u16, col) != self.replacement {
            *fb.cell_mut(row as u16, col) = self.replacement;
            if flag {
                fb.cell_mut(row as u16, col).flags |= FLAG_UNDERLINE;
            }
        }
    }

    pub fn get_validity(&self, fb: &Frame, row: i32, _early_ack: i64, late_ack: i64) -> Validity {
        if !self.base.active {
            return Validity::Inactive;
        }
        if row >= fb.height() as i32 || self.base.col >= fb.width() as i32 {
            return Validity::IncorrectOrExpired;
        }
        let current = fb.cell(row as u16, self.base.col as u16);

        // The authoritative frame confirming or refuting the prediction hasn't
        // arrived yet -- too early to judge.
        if late_ack < self.base.expiration_frame {
            return Validity::Pending;
        }

        if self.unknown {
            return Validity::CorrectNoCredit;
        }
        // Too easy to false-positive on a blank cell -- no credit given.
        if self.replacement.is_blank() {
            return Validity::CorrectNoCredit;
        }

        if current.contents_match(&self.replacement) {
            let matches_original = self
                .original_contents
                .iter()
                .any(|cell| cell.contents_match(&self.replacement));
            if matches_original {
                Validity::CorrectNoCredit
            } else {
                Validity::Correct
            }
        } else {
            Validity::IncorrectOrExpired
        }
    }

    pub fn reset(&mut self) {
        self.unknown = false;
        self.original_contents.clear();
        self.base.reset();
    }

    pub fn reset_with_orig(&mut self) {
        if !self.base.active || self.unknown {
            self.reset();
            return;
        }
        self.original_contents.push(self.replacement);
        self.base.reset();
    }
}

/// A row of predicted cells (a port of `ConditionalOverlayRow`).
#[derive(Debug, Clone)]
pub struct ConditionalOverlayRow {
    pub row_num: i32,
    pub overlay_cells: Vec<ConditionalOverlayCell>,
}

impl ConditionalOverlayRow {
    pub fn apply(&self, fb: &mut Frame, confirmed_epoch: i64, flag: bool) {
        for cell in &self.overlay_cells {
            cell.apply(fb, confirmed_epoch, self.row_num, flag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terminal::{Cell, Frame};

    fn frame(cols: u16, rows: u16) -> Frame {
        // An empty frame of the given size: a grid of blanks, cursor at (0,0).
        Frame::blank(cols, rows)
    }

    fn cell_of(ch: char) -> Cell {
        Cell {
            ch,
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        }
    }

    #[test]
    fn cursor_move_applies_position() {
        let mut fb = frame(10, 3);
        let mut cur = ConditionalCursorMove::new(5, 1, 3, 0);
        cur.base.active = true;
        cur.apply(&mut fb, 0);
        assert_eq!((fb.cursor_col, fb.cursor_row), (3, 1));
    }

    #[test]
    fn cell_apply_writes_replacement() {
        let mut fb = frame(10, 1);
        let mut c = ConditionalOverlayCell::new(5, 2, 0);
        c.base.active = true;
        c.replacement = cell_of('x');
        c.apply(&mut fb, 0, 0, false);
        assert_eq!(fb.cell(0, 2).ch, 'x');
    }

    #[test]
    fn cell_validity_pending_before_late_ack() {
        let fb = frame(10, 1);
        let mut c = ConditionalOverlayCell::new(5, 0, 0);
        c.base.active = true;
        c.replacement = cell_of('a');
        // late_ack (4) < expiration_frame (5) -> still too early to judge.
        assert_eq!(c.get_validity(&fb, 0, 0, 4), Validity::Pending);
    }

    #[test]
    fn cell_validity_correct_on_match() {
        let mut fb = frame(10, 1);
        *fb.cell_mut(0, 0) = cell_of('a');
        let mut c = ConditionalOverlayCell::new(5, 0, 0);
        c.base.active = true;
        c.replacement = cell_of('a');
        assert_eq!(c.get_validity(&fb, 0, 0, 5), Validity::Correct);
    }

    #[test]
    fn cursor_move_skips_when_origin_mode_active() {
        // Regression for fix cbd54cc in the earlier Kotlin port: with
        // origin_mode=true the cursor prediction is unreliable and must be
        // skipped entirely rather than applied to an untrustworthy row/column.
        // Position and epoch are valid (row/col in bounds, epoch confirmed) --
        // the only reason to skip apply here is origin_mode itself.
        let mut fb = frame(10, 3);
        fb.origin_mode = true;
        let mut cur = ConditionalCursorMove::new(5, 1, 3, 0);
        cur.base.active = true;
        cur.apply(&mut fb, 0);
        assert_eq!((fb.cursor_col, fb.cursor_row), (0, 0));
    }

    #[test]
    fn cell_validity_incorrect_on_mismatch() {
        let mut fb = frame(10, 1);
        *fb.cell_mut(0, 0) = cell_of('b');
        let mut c = ConditionalOverlayCell::new(5, 0, 0);
        c.base.active = true;
        c.replacement = cell_of('a');
        assert_eq!(c.get_validity(&fb, 0, 0, 5), Validity::IncorrectOrExpired);
    }
}
