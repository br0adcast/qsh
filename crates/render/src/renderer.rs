//! The renderer itself: a frame in, bytes for the user's terminal out.
//!
//! It remembers what it has already drawn, so the next frame is sent as a
//! difference against it whenever the screen size did not change, falling
//! back to a full repaint otherwise. The scroll shortcut comes on top of
//! this.
//!
//! "The user's scrollback" below is the terminal's own history, which the
//! shortcut's newlines feed when the frames are drawn on its primary screen.
//! `qsh` draws them on the terminal's alternate screen, which keeps no
//! history: there the shortcut is only a cheaper way to move the screen,
//! and the history to scroll back through is the client's own.

use terminal::{
    Cell, Color, Frame, MouseTracking, FLAG_BOLD, FLAG_DIM, FLAG_HIDDEN, FLAG_ITALIC,
    FLAG_LEADING_WIDE_SPACER, FLAG_REVERSE, FLAG_UNDERLINE, FLAG_WIDE, FLAG_WIDE_SPACER,
};

use crate::caps::TermCaps;
use crate::sgr::{write_sgr, Style};

/// Restore every mode the renderer can enable when its current state is
/// unknown. Static bytes also let a panic hook write directly to its owned
/// terminal without allocating or acquiring a stdout lock. Screen switching
/// and the normal exit's trailing newline remain the caller's responsibility.
pub const RESET_TERMINAL_MODES: &[u8] =
    b"\x1b[0m\x1b[?1l\x1b>\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h";

/// The cell flags that actually change how a character looks. The width
/// flags live in the same word but carry no appearance, and letting them
/// into the style would force a full SGR reset at every wide-character
/// boundary.
const STYLE_FLAGS: u16 =
    FLAG_BOLD | FLAG_DIM | FLAG_ITALIC | FLAG_UNDERLINE | FLAG_REVERSE | FLAG_HIDDEN;

/// The input modes we mirror onto the user's terminal. Nothing about how the
/// screen LOOKS lives here -- only what makes the terminal encode keyboard
/// and mouse input the way the remote application asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Modes {
    app_cursor: bool,
    app_keypad: bool,
    tracking: MouseTracking,
    sgr_mouse: bool,
    bracketed_paste: bool,
}

impl Modes {
    /// The state a terminal is in before we touch it.
    fn initial() -> Modes {
        Modes {
            app_cursor: false,
            app_keypad: false,
            tracking: MouseTracking::Off,
            sgr_mouse: false,
            bracketed_paste: false,
        }
    }

    /// The modes a frame asks for.
    fn of(frame: &Frame) -> Modes {
        Modes {
            app_cursor: frame.app_cursor,
            app_keypad: frame.app_keypad,
            tracking: frame.mouse_tracking,
            sgr_mouse: frame.mouse_sgr,
            bracketed_paste: frame.bracketed_paste,
        }
    }
}

/// Draws frames into a terminal, remembering what is already on screen.
pub struct Renderer {
    caps: TermCaps,
    physical_scroll_eligible: bool,
    /// What the terminal is currently showing, as far as we know. `None`
    /// means "unknown" -- the next frame is painted from scratch.
    last: Option<Frame>,
    /// SGR state of the terminal after everything we have written so far.
    style: Style,
    /// Input modes the terminal is currently set to. `None` means "unknown"
    /// -- the next render emits the whole set rather than a difference. We do
    /// NOT reset to `Modes::initial()` instead: that would assert a state of
    /// the terminal we have no grounds to believe.
    modes: Option<Modes>,
}

impl Renderer {
    /// A renderer for a terminal with the given capabilities, assuming
    /// nothing about what is on screen or which input modes the terminal is
    /// in: the first `render` paints in full and emits every mirrored mode,
    /// exactly as after `invalidate`. We know no more about the user's shell
    /// at startup than after a SIGCONT.
    pub fn new(caps: TermCaps) -> Renderer {
        Renderer {
            caps,
            physical_scroll_eligible: true,
            last: None,
            style: Style::default_style(),
            modes: None,
        }
    }

    /// Permit physical scrolling only when the frame reaches the actual
    /// terminal bottom. Cropped viewports must redraw rows in place.
    pub fn set_physical_scroll_eligible(&mut self, eligible: bool) {
        self.physical_scroll_eligible = eligible;
    }

    /// Forget what is on screen: the next `render` repaints in full and
    /// re-emits the mirrored input modes. Used after the process is resumed
    /// from the background or anything else wrote to the terminal behind our
    /// back -- which is exactly when those modes are most likely to be gone
    /// too, since job control around SIGTSTP/SIGCONT typically clears
    /// bracketed paste and mouse tracking.
    pub fn invalidate(&mut self) {
        self.last = None;
        self.modes = None;
    }

    /// Bytes that bring `frame` onto the terminal: a difference against what
    /// is already there when possible, a full repaint otherwise.
    pub fn render(&mut self, frame: &Frame) -> Vec<u8> {
        let mut out = Vec::new();
        // The retained frame is diffed against, shifted in place, and then
        // overwritten with `frame`: its storage is reused rather than a new
        // copy made per render.
        let mut retained = self.last.take();
        let same_size = retained
            .as_mut()
            .filter(|p| p.cols == frame.cols && p.rows == frame.rows);
        if let Some(previous) = same_size {
            // The shortcut is only for the primary screen. The alternate one
            // has no scrollback to feed, and we do not mirror `?1049` onto
            // the user's terminal -- so a newline here would push the local
            // screen's content into the user's real scrollback. Scrolling a
            // line in `less` produces exactly the clean shift `scrolled_by`
            // detects, so this is normal use, not a corner case.
            //
            // BOTH frames have to be primary: on leaving the alternate screen
            // the previous frame is the application's last picture and the
            // new one is the restored shell -- unrelated content that can
            // still line up as a shift by coincidence (`cat file; less file`,
            // then `q`), and a newline here would feed that coincidence into
            // the user's scrollback.
            if self.physical_scroll_eligible && !frame.alt_screen && !previous.alt_screen {
                if let Some(lines) = scrolled_by(previous, frame) {
                    self.scroll_up(&mut out, lines, frame);
                    shift_up(previous, lines);
                }
            }
            self.diff_rows(&mut out, previous, frame);
        } else {
            self.full_repaint(&mut out, frame);
        }
        self.write_modes(&mut out, frame);
        self.place_cursor(&mut out, frame);
        match &mut retained {
            Some(last) => last.clone_from(frame),
            None => retained = Some(frame.clone()),
        }
        self.last = retained;
        out
    }

    /// Redraw only the rows that changed, and inside a row only the columns
    /// between the first and the last difference.
    fn diff_rows(&mut self, out: &mut Vec<u8>, previous: &Frame, frame: &Frame) {
        for row in 0..frame.rows {
            let Some((from, to)) = changed_span(previous, frame, row) else {
                continue;
            };
            move_to(out, row, from);
            // A tail that became blank is cleared with one escape instead of
            // a run of spaces -- but only when the blank carries the default
            // background, since `ESC [ K` erases with the current one.
            if tail_is_default_blank(frame, row, from) {
                // `ESC [ K` erases to end of line with the CURRENT background,
                // so the appearance has to be the default first.
                write_sgr(
                    out,
                    self.style,
                    Style::default_style(),
                    self.caps,
                    &frame.palette,
                );
                self.style = Style::default_style();
                out.extend_from_slice(b"\x1b[K");
            } else {
                self.put_span(out, frame, row, from, to);
            }
        }
    }

    /// Clear the screen and draw every row.
    fn full_repaint(&mut self, out: &mut Vec<u8>, frame: &Frame) {
        // Reset the appearance first: `ESC [ 2 J` erases with the CURRENT
        // background, so a leftover background color would paint the whole
        // screen.
        out.extend_from_slice(b"\x1b[0m\x1b[H\x1b[2J");
        self.style = Style::default_style();
        for row in 0..frame.rows {
            let end = through_wide_successor(frame, row, row_content_end(frame, row));
            if end == 0 {
                continue;
            }
            move_to(out, row, 0);
            self.put_span(out, frame, row, 0, end);
        }
    }

    /// Write cells `[from, to)` of `row`. The caller has put the cursor at
    /// `from`; from there the pen is tracked explicitly -- a printed wide
    /// character advances it by two columns, anything else by one -- and
    /// whenever the next cell to draw is not where the pen stands, the cursor
    /// is moved there first. Without that, the two damaged shapes the
    /// emulator can leave behind shift the rest of the row on screen while
    /// `last` believes it is right:
    ///   * `ESC [ K` on the second half of a wide character keeps the
    ///     `FLAG_WIDE` cell but replaces its spacer with an ordinary blank --
    ///     the glyph paints two columns, so the blank has to be repositioned
    ///     onto the second one rather than printed after it;
    ///   * `ESC [ P` on the wide character itself shifts its spacer left into
    ///     an ORPHAN -- a `FLAG_WIDE_SPACER` cell with no wide neighbor. It
    ///     is skipped only when the cell to its left really carries
    ///     `FLAG_WIDE` (that glyph painted it); an orphan is drawn as the
    ///     blank it is, with its own colours.
    ///
    /// The LEADING spacer (the placeholder left in the last column when a
    /// wide character did not fit and wrapped) is never skipped: no wide
    /// character stands to its left, so nothing else would ever paint it.
    fn put_span(&mut self, out: &mut Vec<u8>, frame: &Frame, row: u16, from: u16, to: u16) {
        let mut pen = from;
        for col in from..to {
            if painted_by_wide_neighbour(frame, row, col) {
                continue;
            }
            if pen != col {
                move_to(out, row, col);
                pen = col;
            }
            let cell = frame.cell(row, col);
            let style = Style {
                fg: cell.fg,
                bg: cell.bg,
                flags: cell.flags & STYLE_FLAGS,
            };
            write_sgr(out, self.style, style, self.caps, &frame.palette);
            self.style = style;
            // A wide character only fits when a second column follows. `ESC
            // [ @` can push one into the last column with its spacer shoved
            // off the row; printing the glyph there would make the terminal
            // wrap it onto the next row -- scrolling the whole screen when
            // this is the bottom one -- so that cell draws as a blank.
            let wide = cell.flags & FLAG_WIDE != 0 && col + 1 < frame.cols;
            // A control character has no glyph: alacritty records HT in the
            // cell it lands on, and an untouched cell holds NUL. Sent as a
            // byte, a tab would move the terminal's cursor to its own next
            // tab stop and shift everything after it.
            let ch = if cell.ch.is_control() || (cell.flags & FLAG_WIDE != 0 && !wide) {
                ' '
            } else {
                cell.ch
            };
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            if !cell.ch.is_control()
                && cell.flags & (FLAG_WIDE_SPACER | FLAG_LEADING_WIDE_SPACER) == 0
                && (cell.flags & FLAG_WIDE == 0 || wide)
            {
                for mark in cell.combining.as_slice() {
                    out.extend_from_slice(mark.encode_utf8(&mut buf).as_bytes());
                }
            }
            pen += if wide { 2 } else { 1 };
        }
    }

    /// Put the cursor where the frame wants it and match its visibility.
    fn place_cursor(&mut self, out: &mut Vec<u8>, frame: &Frame) {
        move_to(out, frame.cursor_row, frame.cursor_col);
        if frame.cursor_visible {
            out.extend_from_slice(b"\x1b[?25h");
        } else {
            out.extend_from_slice(b"\x1b[?25l");
        }
    }

    /// Push `lines` rows off the top by printing newlines at the bottom row:
    /// unlike an in-place scroll escape, this is what puts the lines into the
    /// user's own scrollback, where their terminal's search and mouse wheel
    /// can reach them.
    fn scroll_up(&mut self, out: &mut Vec<u8>, lines: u16, frame: &Frame) {
        // Newlines are erased with the CURRENT background, so reset first.
        write_sgr(
            out,
            self.style,
            Style::default_style(),
            self.caps,
            &frame.palette,
        );
        self.style = Style::default_style();
        move_to(out, frame.rows - 1, 0);
        for _ in 0..lines {
            out.push(b'\n');
        }
    }

    /// Emit the mode changes between what the terminal is set to and what the
    /// frame asks for.
    fn write_modes(&mut self, out: &mut Vec<u8>, frame: &Frame) {
        let want = Modes::of(frame);
        let have = self.modes;
        // With the terminal's state unknown every mode is emitted rather than
        // diffed: `None` cannot answer "does this already match?".
        let differs = |pick: fn(&Modes) -> bool| have.is_none_or(|h| pick(&h) != pick(&want));
        if differs(|m| m.app_cursor) {
            out.extend_from_slice(if want.app_cursor {
                b"\x1b[?1h"
            } else {
                b"\x1b[?1l"
            });
        }
        if differs(|m| m.app_keypad) {
            out.extend_from_slice(if want.app_keypad { b"\x1b=" } else { b"\x1b>" });
        }
        if have.is_none_or(|h| h.tracking != want.tracking) {
            // Turn the old level off explicitly: terminals track the three
            // modes separately, and leaving `?1002h` set while asking for
            // `?1000h` would keep sending drag events. When the old level is
            // unknown, turn all three off -- resetting a level that was never
            // on costs one escape and nothing else.
            for seq in have.map_or(ALL_TRACKING_OFF, |h| tracking_off(h.tracking)) {
                out.extend_from_slice(seq);
            }
            if let Some(seq) = tracking_on(want.tracking) {
                out.extend_from_slice(seq);
            }
        }
        if differs(|m| m.sgr_mouse) {
            out.extend_from_slice(if want.sgr_mouse {
                b"\x1b[?1006h"
            } else {
                b"\x1b[?1006l"
            });
        }
        if differs(|m| m.bracketed_paste) {
            out.extend_from_slice(if want.bracketed_paste {
                b"\x1b[?2004h"
            } else {
                b"\x1b[?2004l"
            });
        }
        self.modes = Some(want);
    }

    /// Bytes that hand the terminal back to the user: default appearance, no
    /// mirrored modes, a visible cursor and a fresh line to type on.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        self.style = Style::default_style();
        // Undo what we know is on. When the state is unknown, undo
        // everything: "we cannot tell" must not become "nothing to undo",
        // since mouse tracking or bracketed paste left behind would corrupt
        // the shell the user is handed back.
        if let Some(known) = self.modes {
            out.extend_from_slice(b"\x1b[0m");
            if known.app_cursor {
                out.extend_from_slice(b"\x1b[?1l");
            }
            if known.app_keypad {
                out.extend_from_slice(b"\x1b>");
            }
            for seq in tracking_off(known.tracking) {
                out.extend_from_slice(seq);
            }
            if known.sgr_mouse {
                out.extend_from_slice(b"\x1b[?1006l");
            }
            if known.bracketed_paste {
                out.extend_from_slice(b"\x1b[?2004l");
            }
            out.extend_from_slice(b"\x1b[?25h");
        } else {
            out.extend_from_slice(RESET_TERMINAL_MODES);
        }
        out.extend_from_slice(b"\r\n");
        self.modes = Some(Modes::initial());
        self.last = None;
        out
    }
}

/// One past the last column of `row` that has anything worth drawing: a
/// trailing run of blanks with default colors needs no output at all, since
/// the screen is already blank there.
fn row_content_end(frame: &Frame, row: u16) -> u16 {
    let mut end = 0;
    for col in 0..frame.cols {
        if !is_drawable_blank(frame.cell(row, col)) {
            end = col + 1;
        }
    }
    end
}

/// Whether a cell is indistinguishable from an untouched screen position.
/// Neither spacer flag counts as content: both mark cells the emulator filled
/// with a blank, so with the default background there is nothing to draw. A
/// control character (NUL in an untouched cell, HT where a tab landed) has
/// no glyph and is a blank too.
fn is_drawable_blank(cell: &Cell) -> bool {
    (cell.ch == ' ' || cell.ch.is_control())
        && cell.combining.is_empty()
        && cell.bg == Color::Default
        && cell.flags & !(FLAG_WIDE_SPACER | FLAG_LEADING_WIDE_SPACER) == 0
}

/// Whether the cell at `col` is the second column of a double-width
/// character that really stands to its left -- painted already by that
/// glyph, so nothing is printed for it. A `FLAG_WIDE_SPACER` cell with no
/// `FLAG_WIDE` neighbor (an orphan left by `ESC [ P` deleting the wide
/// character) is not covered by anything and draws as a blank.
fn painted_by_wide_neighbour(frame: &Frame, row: u16, col: u16) -> bool {
    frame.cell(row, col).flags & FLAG_WIDE_SPACER != 0
        && col > 0
        && frame.cell(row, col - 1).flags & FLAG_WIDE != 0
}

/// Absolute cursor positioning (1-based, as the escape wants it).
fn move_to(out: &mut Vec<u8>, row: u16, col: u16) {
    out.extend_from_slice(format!("\x1b[{};{}H", row + 1, col + 1).as_bytes());
}

/// First and last (exclusive) column where the two frames differ in `row`,
/// widened at both ends: a difference never starts on the trailing half of
/// a wide character, and never ends on a wide character that would paint
/// over an unchanged neighbor (see `through_wide_successor`).
fn changed_span(previous: &Frame, frame: &Frame, row: u16) -> Option<(u16, u16)> {
    let mut first = None;
    let mut last = 0u16;
    for col in 0..frame.cols {
        if !same_cell(previous.cell(row, col), frame.cell(row, col)) {
            if first.is_none() {
                first = Some(col);
            }
            last = col + 1;
        }
    }
    let mut first = first?;
    // Only a TRAILING spacer that is really covered by a wide character
    // needs this: it is drawn by that character, so the span has to start
    // there. A LEADING spacer, or an orphan trailing one with no wide
    // neighbor, is drawn on its own -- backing up over it would redraw an
    // untouched neighbor for nothing. Same rule as `put_span` skips by.
    if painted_by_wide_neighbour(frame, row, first) {
        first -= 1;
    }
    Some((first, through_wide_successor(frame, row, last)))
}

/// `end` (exclusive) pushed past every cell a damaged wide character at the
/// edge of the span would paint over. Printing the glyph of a `FLAG_WIDE`
/// cell paints the NEXT column too; when that column is not the spacer the
/// glyph owns (`ESC [ K` or `ESC [ X` on the second half leaves an ordinary
/// blank there), it comes out with the glyph's colours and attributes
/// instead of its own and has to be redrawn after the glyph -- so it joins
/// the span. Nothing else ever repairs it: its model value did not change,
/// so no later difference includes it, and even a full-line erase leaves it
/// out. The check repeats because the successor can itself be a damaged
/// wide character. The last column is left alone: a wide cell there draws
/// as a blank, and no column follows it.
fn through_wide_successor(frame: &Frame, row: u16, mut end: u16) -> u16 {
    while end > 0
        && end < frame.cols
        && frame.cell(row, end - 1).flags & FLAG_WIDE != 0
        && !painted_by_wide_neighbour(frame, row, end)
    {
        end += 1;
    }
    end
}

/// Cells are the same for drawing purposes when character, colors and
/// attributes match.
fn same_cell(a: &Cell, b: &Cell) -> bool {
    a == b
}

/// Whether everything from `from` to the end of `row` is blank with the
/// terminal's default background -- the case `ESC [ K` handles exactly.
fn tail_is_default_blank(frame: &Frame, row: u16, from: u16) -> bool {
    (from..frame.cols).all(|col| is_drawable_blank(frame.cell(row, col)))
}

/// How many rows the screen moved up, if the new frame is the old one shifted
/// (and only shifted) -- the rows that scrolled in at the bottom may differ.
///
/// Only the top `kept - 1` rows of the naive kept region (`kept = rows -
/// lines`) are trusted as evidence: the bottom kept row is written into
/// before the newline that triggers the scroll fires, so it rides the shift
/// already holding content the old frame never had, and can never match a
/// pure shift. That row is excluded from BOTH the `moved` and `shifted`
/// checks below -- judging `moved` on a row that is guaranteed to differ
/// would prove nothing about a real shift having happened. When no row is
/// left to confirm (`confirmed == 0`, i.e. `lines == rows - 1`), the shift is
/// skipped rather than accepted on zero evidence.
///
/// The `moved` check is not an optimization, it is what keeps the shortcut
/// honest: on a blank screen (or one with repeating rows) EVERY shift
/// "matches", and without it a bare cursor move -- or any frame whose only
/// change is unrelated to scrolling, such as a live clock in the top row --
/// would push blank or duplicated lines into the user's scrollback forever.
/// A shift is only real when the confirmed region does NOT already line up
/// unshifted.
///
/// `moved` alone is not enough, though: it only asks whether SOMETHING is
/// different, not whether what matched under the shift means anything. A
/// blank row matches a blank row under every possible shift -- it carries no
/// content to disagree with -- so `ESC [ J` erasing a mostly-blank screen, or
/// `ESC M` / `ESC [ L` inserting a line at the top (which moves content DOWN,
/// the opposite of what this function looks for), can leave the top row
/// changed (satisfying `moved`) while every row the shift would need to
/// confirm is blank on both sides (satisfying `shifted` vacuously). That
/// combination used to authorize a scroll that never happened, and since
/// `confirmed` shrinks as `lines` grows, a single such row could authorize
/// almost the whole screen. The rule applied below: a shift is corroborated
/// only when at least one of the confirmed rows is not blank -- real content
/// actually has to be seen riding the shift, not merely absent on both sides.
///
/// A stricter bar was considered -- requiring several matching rows, or a
/// fixed fraction of `confirmed` to be non-blank -- and rejected for two
/// reasons, not one. First, a fixed minimum count is simply wrong: a 3-row
/// screen scrolling by 1 has `confirmed == 1`, so any constant above 1 would
/// reject that ordinary scroll outright. A *proportional* minimum (say, half
/// of `confirmed`) survives that particular case -- one of one is still all
/// of them -- so it is not ruled out the same way. It was rejected on
/// balance instead: it would shrink a residual false positive this fix does
/// not fully close (a region-limited `Delete Line` with a blank margin can
/// still be authorized by one coincidentally-matching row, injecting a few
/// cosmetic blank lines -- annoying, not lossy), but at the direct cost of
/// rejecting more genuine sparse scrolls, which is the worse trade covered
/// next.
///
/// Requiring ANY non-blank confirmed row still has a cost, and it is not
/// tunable away: when the only content on screen scrolls off the top and
/// nothing new is printed at the bottom, the resulting frame is entirely
/// blank -- bit-identical to that same content having been erased in place.
/// `scrolled_by` sees only `(previous, frame)`, so nothing in that pair
/// distinguishes "scrolled away" from "erased", and this function declines
/// both alike: the vanished line is repainted rather than reaching the
/// user's real scrollback. That loss is accepted deliberately. The
/// alternative -- treating an all-blank result as a scroll on no evidence at
/// all -- is exactly the false positive this function exists to reject, and
/// a rare lost line is a smaller harm than a screenful of spurious blank
/// lines landing in every user's scrollback. See
/// `a_genuine_scroll_that_empties_the_screen_is_not_distinguishable_from_an_erase`
/// for the regression test pinning this trade-off's current shape.
fn scrolled_by(previous: &Frame, frame: &Frame) -> Option<u16> {
    // Every candidate's moved predicate examines a prefix of these rows.
    // Find its first difference once: moved is exactly first_changed <
    // confirmed. Neither excluded bottom row can establish that evidence.
    let first_changed =
        (0..frame.rows.saturating_sub(2)).find(|&row| !rows_equal(previous, frame, row, row))?;
    for lines in 1..frame.rows {
        let kept = frame.rows - lines;
        let confirmed = kept - 1;
        // confirmed only shrinks with ascending lines; no later candidate
        // can include the difference. Keep this order to choose the same
        // first accepted shift. Shifted/corroborated work is unchanged and
        // can still be quadratic on other inputs.
        if confirmed <= first_changed {
            break;
        }
        let shifted = (0..confirmed).all(|row| rows_equal(previous, frame, row + lines, row));
        if !shifted {
            continue;
        }
        let corroborated = (0..confirmed).any(|row| !row_is_blank(frame, row));
        if corroborated {
            return Some(lines);
        }
    }
    None
}

/// Whether every cell of `row` draws as blank. Used to keep `scrolled_by`
/// from treating two blank rows lining up as evidence of a scroll: a blank
/// matches a blank under any shift, so it proves nothing moved.
fn row_is_blank(frame: &Frame, row: u16) -> bool {
    (0..frame.cols).all(|col| is_drawable_blank(frame.cell(row, col)))
}

/// Whether row `a_row` of `a` draws the same as row `b_row` of `b`.
fn rows_equal(a: &Frame, b: &Frame, a_row: u16, b_row: u16) -> bool {
    #[cfg(test)]
    scroll_detection_tests::note_row();
    (0..b.cols).all(|col| {
        #[cfg(test)]
        scroll_detection_tests::note_cell();
        same_cell(a.cell(a_row, col), b.cell(b_row, col))
    })
}

/// The previous frame's cells as they look after scrolling `lines` rows off
/// the top: the vacated rows at the bottom become blank, which is exactly
/// what the terminal shows after the newlines. Only the cells change; the
/// diff that follows reads nothing else of the previous frame.
fn shift_up(previous: &mut Frame, lines: u16) {
    let start = usize::from(lines.min(previous.rows)) * usize::from(previous.cols);
    previous.cells.copy_within(start.., 0);
    let kept = previous.cells.len() - start;
    previous.cells[kept..].fill(Cell::blank());
}

/// Every tracking level turned off -- what to send when the level currently
/// set is unknown.
const ALL_TRACKING_OFF: &[&[u8]] = &[b"\x1b[?1000l", b"\x1b[?1002l", b"\x1b[?1003l"];

/// Escapes that turn a tracking level off (empty for `Off`).
fn tracking_off(tracking: MouseTracking) -> &'static [&'static [u8]] {
    match tracking {
        MouseTracking::Off => &[],
        MouseTracking::Click => &[b"\x1b[?1000l"],
        MouseTracking::Drag => &[b"\x1b[?1002l"],
        MouseTracking::Motion => &[b"\x1b[?1003l"],
    }
}

/// Escape that turns a tracking level on (`None` for `Off`).
fn tracking_on(tracking: MouseTracking) -> Option<&'static [u8]> {
    match tracking {
        MouseTracking::Off => None,
        MouseTracking::Click => Some(b"\x1b[?1000h"),
        MouseTracking::Drag => Some(b"\x1b[?1002h"),
        MouseTracking::Motion => Some(b"\x1b[?1003h"),
    }
}

#[cfg(test)]
#[path = "scroll_detection_tests.rs"]
mod scroll_detection_tests;
