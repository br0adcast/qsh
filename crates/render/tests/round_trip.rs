//! The renderer's core property: bytes it produces, fed to a clean emulator,
//! must reproduce the frame it was given. This is what makes the renderer
//! trustworthy -- it is checked against a real VT parser, not against our
//! own idea of what the escapes mean.

use std::ops::Range;

use render::{Renderer, TermCaps};
use terminal::{
    Cell, Color, Frame, TerminalCore, FLAG_BOLD, FLAG_ITALIC, FLAG_LEADING_WIDE_SPACER,
    FLAG_REVERSE, FLAG_UNDERLINE, FLAG_WIDE, FLAG_WIDE_SPACER,
};

/// The attributes that show even on a cell holding no character: reverse
/// video paints the foreground color as the background, and an underline is
/// drawn in the foreground color.
const VISIBLE_ATTRS: u16 = FLAG_BOLD | FLAG_ITALIC | FLAG_UNDERLINE | FLAG_REVERSE;

/// A cell reduced to what a viewer can actually SEE, as a comparable tuple.
///
/// Three normalizations, each about visibility rather than leniency:
///   * a cell the emulator never touched holds NUL, and the cell a tab
///     landed on holds HT, where a drawn one holds a space -- a control
///     character has no glyph, so all three are the same blank on screen;
///   * the LEADING spacer flag only records WHY a column holds a blank (a
///     wide character did not fit here and wrapped). The cell draws as that
///     blank with its own colours, and a terminal handed the blank has no
///     way to record the reason;
///   * the foreground of a blank cell on the default background with no
///     visible attribute cannot be seen at all, so the renderer rightly
///     spends no SGR on it.
fn visible(cell: &Cell) -> (char, terminal::CombiningMarks, Color, Color, u16) {
    let ch = if cell.ch.is_control() { ' ' } else { cell.ch };
    let flags = cell.flags & !FLAG_LEADING_WIDE_SPACER;
    let fg = if ch == ' '
        && cell.combining.is_empty()
        && cell.bg == Color::Default
        && flags & VISIBLE_ATTRS == 0
    {
        Color::Default
    } else {
        cell.fg
    };
    (ch, cell.combining, fg, cell.bg, flags)
}

/// Compare what matters for drawing: the grid and the cursor. Palette and
/// input modes are not part of the drawn content.
fn assert_same_screen(actual: &Frame, expected: &Frame) {
    assert_same_screen_except(actual, expected, 0, 0..0);
}

/// `assert_same_screen` with the cells `skip` of `row` exempt. For frames
/// holding a shape no terminal can be told about -- a wide character whose
/// spacer was erased, a spacer with no wide character beside it -- where
/// what matters is that everything AROUND it, above all the cells to its
/// right, lands where the frame has it.
fn assert_same_screen_except(actual: &Frame, expected: &Frame, row: u16, skip: Range<u16>) {
    assert_eq!(
        (actual.cols, actual.rows),
        (expected.cols, expected.rows),
        "size"
    );
    for r in 0..expected.rows {
        for col in 0..expected.cols {
            if r == row && skip.contains(&col) {
                continue;
            }
            assert_eq!(
                visible(actual.cell(r, col)),
                visible(expected.cell(r, col)),
                "cell at row {r}, col {col}"
            );
        }
    }
    assert_eq!(
        (actual.cursor_col, actual.cursor_row, actual.cursor_visible),
        (
            expected.cursor_col,
            expected.cursor_row,
            expected.cursor_visible
        ),
        "cursor"
    );
}

#[test]
fn full_repaint_reproduces_the_frame_in_a_clean_emulator() {
    let mut src = TerminalCore::new(20, 5);
    src.feed(b"\x1b[31mhello\x1b[0m\r\n");
    src.feed(b"\x1b[1;4mbold-under\x1b[0m\r\n");
    src.feed("\u{65e5}\u{672c} wide\r\n".as_bytes());
    src.feed(b"\x1b[38;2;10;20;30mrgb\x1b[48;5;200mbg\x1b[0m");
    let expected = src.frame();

    let mut r = Renderer::new(TermCaps::truecolor());
    let bytes = r.render(&expected);

    let mut dst = TerminalCore::new(20, 5);
    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &expected);
}

#[test]
fn full_repaint_restores_a_hidden_cursor() {
    let mut src = TerminalCore::new(10, 2);
    src.feed(b"\x1b[?25lhidden");
    let expected = src.frame();

    let mut r = Renderer::new(TermCaps::truecolor());
    let bytes = r.render(&expected);

    let mut dst = TerminalCore::new(10, 2);
    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &expected);
}

/// The renderer speaks to the terminal in escapes and, for the scroll
/// shortcut, newlines -- never in any other control byte. A tab or a
/// carriage return leaking out of a cell would move the terminal's cursor
/// on its own terms, which no emulator-based comparison would notice if the
/// oracle shared the renderer's blind spot; this check does not go through
/// the oracle.
fn assert_only_escapes_and_newlines(bytes: &[u8]) {
    if let Some(stray) = bytes
        .iter()
        .find(|b| b.is_ascii_control() && **b != 0x1b && **b != b'\n')
    {
        panic!(
            "control byte {stray:#04x} in the renderer's output: {:?}",
            String::from_utf8_lossy(bytes)
        );
    }
}

/// Feed a script of writes to a source terminal, render each step
/// incrementally into a destination terminal, and require the two to agree
/// after every step.
fn assert_incremental_matches(cols: u16, rows: u16, script: &[&[u8]]) {
    let mut src = TerminalCore::new(cols, rows);
    let mut dst = TerminalCore::new(cols, rows);
    let mut r = Renderer::new(TermCaps::truecolor());
    for chunk in script {
        src.feed(chunk);
        let frame = src.frame();
        let bytes = r.render(&frame);
        assert_only_escapes_and_newlines(&bytes);
        dst.feed(&bytes);
        assert_same_screen(&dst.frame(), &frame);
    }
}

#[test]
fn incremental_rendering_tracks_the_source_screen() {
    assert_incremental_matches(
        20,
        4,
        &[
            b"first line\r\n",
            b"\x1b[32msecond\x1b[0m\r\n",
            b"\x1b[1;1Hoverwrite",
            b"\x1b[2K",
            b"\x1b[4;1H\xe6\x97\xa5\xe6\x9c\xac wide tail",
            b"\x1b[2J\x1b[H",
            b"after clear",
        ],
    );
}

#[test]
fn an_unchanged_frame_produces_no_drawing() {
    let mut src = TerminalCore::new(10, 2);
    src.feed(b"stable");
    let frame = src.frame();
    let mut r = Renderer::new(TermCaps::truecolor());
    let _first = r.render(&frame);
    let second = r.render(&frame);
    let text = String::from_utf8_lossy(&second).to_string();
    assert!(
        !text.contains("\x1b[2J"),
        "an unchanged frame must not repaint the screen: {text:?}"
    );
    assert!(
        !text.contains("stable"),
        "an unchanged frame must not redraw its content: {text:?}"
    );
}

#[test]
fn a_resize_falls_back_to_a_full_repaint() {
    let mut src = TerminalCore::new(10, 2);
    src.feed(b"before");
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = r.render(&src.frame());

    src.resize(16, 3);
    src.feed(b"-after");
    let frame = src.frame();
    let bytes = r.render(&frame);
    assert!(
        String::from_utf8_lossy(&bytes).contains("\x1b[2J"),
        "a size change must repaint from scratch"
    );

    let mut dst = TerminalCore::new(16, 3);
    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn scrolling_uses_newlines_so_history_lands_in_the_users_terminal() {
    let mut src = TerminalCore::new(20, 3);
    let mut dst = TerminalCore::new(20, 3);
    let mut r = Renderer::new(TermCaps::truecolor());

    for i in 0..3 {
        src.feed(format!("line{i}\r\n").as_bytes());
        let frame = src.frame();
        dst.feed(&r.render(&frame));
    }

    // The third line already scrolled the screen once: it shows line1 and
    // line2 with a blank bottom row. One more line scrolls it again -- by
    // exactly one row, so exactly one newline.
    src.feed(b"line3\r\n");
    let frame = src.frame();
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert_eq!(
        text.matches('\n').count(),
        1,
        "a one-line scroll is exactly one newline: {text:?}"
    );
    assert!(
        !text.contains("\x1b[2J"),
        "a scroll must not repaint the screen: {text:?}"
    );
    // line2 is in both frames, one row higher in the new one: it rode the
    // shift and must not be redrawn. (line0 would prove nothing -- it is in
    // neither frame, so no path would ever print it.)
    assert!(
        !text.contains("line2"),
        "the row that only moved up must not be redrawn: {text:?}"
    );
    assert!(
        text.contains("line3"),
        "the row that scrolled in must be drawn: {text:?}"
    );

    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_blank_screen_with_a_moving_cursor_does_not_scroll() {
    let mut src = TerminalCore::new(10, 3);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = r.render(&src.frame());

    // Nothing is drawn, only the cursor moves: on an empty screen every
    // possible shift "matches", so a naive shortcut would push a blank line
    // into the scrollback here.
    src.feed(b"\x1b[2;5H");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "moving the cursor on a blank screen must not scroll"
    );
}

#[test]
fn a_frame_whose_top_row_changes_is_not_mistaken_for_a_scroll() {
    let mut src = TerminalCore::new(20, 4);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"alpha\r\nbravo\r\ncharlie\r\ndelta");
    let _ = r.render(&src.frame());

    // Only the top row is rewritten: nothing scrolled, so nothing may be
    // pushed into the user's scrollback.
    src.feed(b"\x1b[1;1Hoverwrite");
    let frame = src.frame();
    let bytes = r.render(&frame);
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "a top-row rewrite must not scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );

    // Check the frame's content independently of the incremental renderer's
    // own state, by painting it from scratch with a fresh renderer.
    let mut dst = TerminalCore::new(20, 4);
    dst.feed(&Renderer::new(TermCaps::truecolor()).render(&frame));
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn erasing_a_mostly_blank_screen_is_not_mistaken_for_a_scroll() {
    // Only the top row carries content; the other 23 are already blank.
    // `ESC [ J` wipes the rest of the screen from the cursor down, so the
    // whole frame ends up blank -- nothing scrolled, it was erased. Every
    // row the shortcut could point to as "shifted-in" evidence is blank on
    // both sides of the comparison, which is exactly the vacuous match the
    // shortcut must not accept.
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    let _ = r.render(&src.frame());

    src.feed(b"\x1b[H\x1b[J");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "erasing the screen must not scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn reverse_index_at_the_top_row_is_not_mistaken_for_a_scroll() {
    // `ESC M` at the top row scrolls the screen DOWN by one (a blank line
    // is inserted above the cursor), the opposite of what the shortcut
    // looks for. With only one row of content, most of the comparison is
    // blank-against-blank, which used to authorize an upward "shift" of up
    // to `rows - 2` lines that never happened.
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    let _ = r.render(&src.frame());

    src.feed(b"\x1b[H\x1bM");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "a reverse index must not be read as a forward scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn insert_line_at_the_top_row_is_not_mistaken_for_a_scroll() {
    // `ESC [ L` at the top row pushes every row below the cursor down by
    // one, dropping the bottom row -- again the opposite direction from the
    // shortcut, and again mostly blank rows lining up by coincidence.
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    let _ = r.render(&src.frame());

    src.feed(b"\x1b[H\x1b[L");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "an insert-line must not be read as a scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn a_scroll_still_fires_when_the_confirmed_rows_include_a_blank_one() {
    // The fix must not demand that EVERY confirmed row carry content --
    // only that at least one does. Row 1 here is blank in both frames
    // (matching vacuously), but row 2 ("beta") is real content that
    // genuinely rode the shift, which is enough to corroborate it.
    let mut src = TerminalCore::new(20, 5);
    let mut dst = TerminalCore::new(20, 5);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed(b"alpha\r\n\r\nbeta\r\ngamma\r\ndelta");
    dst.feed(&r.render(&src.frame()));

    // At the last row, one more newline scrolls the whole screen up by one.
    src.feed(b"\r\nepsilon");
    let frame = src.frame();
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert_eq!(
        text.matches('\n').count(),
        1,
        "a genuine scroll past a blank row is still one newline: {text:?}"
    );
    assert!(
        !text.contains("beta") && !text.contains("gamma") && !text.contains("delta"),
        "the rows that only moved up must not be redrawn: {text:?}"
    );

    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn erase_above_the_cursor_is_not_mistaken_for_a_scroll() {
    // `ESC [ 1 J` clears from the top-left corner through the cursor,
    // inclusive. Placing the cursor at the end of row 2 and erasing above it
    // wipes the only content on screen (row 0), leaving the frame entirely
    // blank -- the same blank-matches-blank shape as `ESC [ J`, reached
    // through the "erase above" variant instead of "erase below".
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    let _ = r.render(&src.frame());

    src.feed(b"\x1b[3;20H\x1b[1J");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "erasing above the cursor must not scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn erase_to_end_of_line_is_not_mistaken_for_a_scroll() {
    // `ESC [ K` with the cursor at the start of row 0 clears that whole row
    // -- the only content on screen -- leaving an all-blank frame. Same
    // shape again, reached through a single-line erase rather than a
    // whole-screen one.
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    let _ = r.render(&src.frame());

    src.feed(b"\x1b[H\x1b[K");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "erasing to end of line must not scroll: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn a_genuine_scroll_that_empties_the_screen_is_not_distinguishable_from_an_erase() {
    // Known, accepted limitation -- see the trade-off documented on
    // `scrolled_by`, not a bug this test is meant to catch. The only
    // content on a 24-row screen is on row 0; padding the cursor down to
    // the last row and feeding one more line feed there genuinely scrolls
    // that content off the top, and nothing new is printed at the bottom,
    // so the resulting frame is entirely blank -- bit-identical to
    // `erasing_a_mostly_blank_screen_is_not_mistaken_for_a_scroll`'s result.
    // No rule reading only the two frames can tell these two histories
    // apart, so the corroboration check declines this genuine scroll too:
    // the vanished line is repainted away rather than reaching the user's
    // real scrollback. This test PINS that current behavior, so a future
    // change to the rule cannot move the trade-off point without the
    // failure here making it obvious.
    let mut src = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"hello");
    for _ in 0..23 {
        src.feed(b"\r\n");
    }
    let _ = r.render(&src.frame());

    // The cursor is already on the last row: one more line feed scrolls the
    // whole screen up by one, carrying "hello" off the top.
    src.feed(b"\n");
    let bytes = r.render(&src.frame());
    assert!(
        !String::from_utf8_lossy(&bytes).contains('\n'),
        "pinning the accepted trade-off: a scroll that empties the screen \
         is currently repainted, not sent as a newline: {:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn a_scroll_still_fires_on_a_sparse_screen_with_content_scattered_among_blanks() {
    // The three pre-existing scroll tests all fill the screen edge to edge,
    // so the corroboration gate is trivially satisfied everywhere in them --
    // they would pass identically whether the gate were correct, inverted,
    // or missing. Here only every third row carries text among 24 rows, so
    // most of the confirmed region IS blank, and the gate has to find the
    // few real rows to accept the shift at all.
    let mut src = TerminalCore::new(20, 24);
    let mut dst = TerminalCore::new(20, 24);
    let mut r = Renderer::new(TermCaps::truecolor());

    for i in 0..24 {
        if i % 3 == 0 {
            src.feed(format!("row{i}").as_bytes());
        }
        if i < 23 {
            src.feed(b"\r\n");
        }
    }
    dst.feed(&r.render(&src.frame()));

    // The cursor sits on the blank last row: one more line feeds scrolls
    // the whole screen up by one and writes fresh content into the row
    // that scrolls in.
    src.feed(b"\r\nrowNew");
    let frame = src.frame();
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert_eq!(
        text.matches('\n').count(),
        1,
        "a sparse scroll is still exactly one newline: {text:?}"
    );
    assert!(
        text.contains("rowNew"),
        "the row that scrolled in must be drawn: {text:?}"
    );
    for surviving in ["row3", "row6", "row9", "row12", "row15", "row18", "row21"] {
        assert!(
            !text.contains(surviving),
            "a row that only moved up must not be redrawn: {text:?}"
        );
    }

    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_multi_line_scroll_is_expressed_as_that_many_newlines() {
    let mut src = TerminalCore::new(20, 5);
    let mut dst = TerminalCore::new(20, 5);
    let mut r = Renderer::new(TermCaps::truecolor());

    for i in 0..5 {
        src.feed(format!("line{i}\r\n").as_bytes());
        dst.feed(&r.render(&src.frame()));
    }

    // Two more lines scroll the full screen by 2 in a single step: two
    // newlines, not one newline plus a redraw of the rows that moved.
    src.feed(b"six\r\nseven\r\n");
    let frame = src.frame();
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert_eq!(
        text.matches('\n').count(),
        2,
        "a two-line scroll is exactly two newlines: {text:?}"
    );
    assert!(
        !text.contains("line3") && !text.contains("line4"),
        "rows that only moved up must not be redrawn: {text:?}"
    );
    assert!(
        !text.contains("\x1b[2J"),
        "a multi-line scroll must not repaint the screen: {text:?}"
    );

    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_row_filled_to_its_last_column_is_drawn_whole() {
    // Nothing may be dropped at the right edge: the last column is as much
    // part of the frame as any other, background included.
    let mut src = TerminalCore::new(8, 2);
    src.feed(b"\x1b[44mfilled--");
    let expected = src.frame();

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(8, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen(&dst.frame(), &expected);
}

#[test]
fn a_wide_character_that_does_not_fit_still_paints_its_placeholder() {
    // Six columns are taken and the wide character needs two, so the
    // emulator puts a placeholder (a LEADING spacer) in the last column and
    // wraps. Nothing above that cell ever prints, so a renderer that skips
    // it -- as it rightly skips the TRAILING spacer of a wide character --
    // never paints its background at all.
    let mut src = TerminalCore::new(7, 2);
    src.feed("\x1b[44mabcdef\u{65e5}".as_bytes());
    let expected = src.frame();

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(7, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen(&dst.frame(), &expected);
}

#[test]
fn the_placeholder_of_a_wrapped_wide_character_overwrites_the_previous_frame() {
    // The same placeholder, reached incrementally: the previous frame left a
    // conspicuous character in that column, and only the renderer can clear
    // it -- an artifact left here never heals, since no later frame prints
    // over the cell either.
    let mut src = TerminalCore::new(7, 2);
    let mut dst = TerminalCore::new(7, 2);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed(b"\x1b[41mXXXXXXX");
    dst.feed(&r.render(&src.frame()));

    src.feed("\x1b[H\x1b[44mabcdef\u{65e5}".as_bytes());
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn an_invisible_foreground_is_not_required_on_screen() {
    // A run of spaces written under a red foreground is invisible: the
    // renderer spends no escape on it, and the round-trip comparison must
    // agree that nothing is missing. Without this the helper would report a
    // mismatch on a non-defect for every line that does not reset SGR.
    let mut src = TerminalCore::new(10, 2);
    src.feed(b"\x1b[31mhi     ");
    let expected = src.frame();
    assert_eq!(
        expected.cell(0, 4).fg,
        terminal::Color::Indexed(1),
        "the blanks really do carry a non-default foreground"
    );

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(10, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen(&dst.frame(), &expected);
}

#[test]
fn the_scroll_shortcut_is_not_taken_on_the_alternate_screen() {
    // The alternate screen has no scrollback, and we deliberately do not
    // mirror `?1049` onto the user's terminal -- so a newline emitted here
    // would push the local screen's content into the user's real scrollback.
    // Scrolling one line in `less` produces exactly the clean shift the
    // shortcut looks for, so this is normal use, not a corner case.
    let mut src = TerminalCore::new(20, 3);
    let mut dst = TerminalCore::new(20, 3);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed(b"\x1b[?1049h");
    for i in 0..3 {
        src.feed(format!("line{i}\r\n").as_bytes());
        dst.feed(&r.render(&src.frame()));
    }

    // One more line shifts the whole alternate screen up by one.
    src.feed(b"line3\r\n");
    let frame = src.frame();
    assert!(
        frame.alt_screen,
        "the frame must be on the alternate screen"
    );
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        !text.contains('\n'),
        "a scroll on the alternate screen must not reach the user's scrollback: {text:?}"
    );

    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn tabs_are_drawn_as_the_blanks_they_occupy() {
    // alacritty records HT in the cell it lands on, so the frame carries a
    // literal '\t'. Sent as a byte it would move the terminal's cursor to
    // ITS next tab stop and shift the rest of the row -- permanently, since
    // the renderer would go on believing the screen is right. `cat
    // Makefile`, `git diff` and any TSV put one in nearly every line.
    let mut src = TerminalCore::new(20, 2);
    src.feed(b"a\tb\tc\r\n1\t2");
    let expected = src.frame();
    assert_eq!(expected.cell(0, 1).ch, '\t', "the model really holds a tab");

    let mut r = Renderer::new(TermCaps::truecolor());
    let bytes = r.render(&expected);
    assert_only_escapes_and_newlines(&bytes);
    let mut dst = TerminalCore::new(20, 2);
    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &expected);
}

#[test]
fn tabs_survive_the_incremental_path() {
    // Every branch of the difference meets a tab: a changed span that runs
    // across tab cells (row 0 rewritten with other letters at the same tab
    // stops), a tail of tab blanks erased with `ESC [ K`, a fresh tab in a
    // row the renderer already knows, and a write inside the blank run a
    // tab left behind.
    assert_incremental_matches(
        20,
        3,
        &[
            b"a\tb\tc\r\n1\t2\t3",
            b"\x1b[1;1HA\tB\tC",
            b"\x1b[2;3H\x1b[K",
            b"\x1b[3;1Hx\ty",
            b"\x1b[1;5Hmid",
        ],
    );
}

#[test]
fn erasing_the_second_half_of_a_wide_character_keeps_the_rest_of_the_row_aligned() {
    // `ESC [ K` with the cursor on the spacer leaves the model with a
    // FLAG_WIDE cell followed by an ordinary blank -- a shape no terminal
    // can hold, since the glyph paints two columns or none. The damaged pair
    // is therefore exempt from the comparison (the destination is free to
    // render it as two blanks); what must not happen is the row after it
    // shifting -- the blank has to be put ON the glyph's second column, not
    // after it.
    let mut src = TerminalCore::new(10, 2);
    src.feed("\u{65e5}xyz".as_bytes());
    src.feed(b"\x1b[1;2H\x1b[K\x1b[1;3Hxyz");
    let expected = src.frame();
    assert_eq!(expected.cell(0, 0).flags & FLAG_WIDE, FLAG_WIDE);
    assert_eq!(
        expected.cell(0, 1).flags & FLAG_WIDE_SPACER,
        0,
        "the spacer is gone"
    );

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(10, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen_except(&dst.frame(), &expected, 0, 0..2);
}

#[test]
fn a_damaged_wide_character_stays_aligned_through_the_incremental_path() {
    // The same shape reached through the difference: after the damage,
    // `ESC [ @` shifts the row right by one, so the changed span starts at
    // column 0 and runs across the FLAG_WIDE cell and the blank behind it.
    // As above, the damaged pair itself is exempt. The last step overwrites
    // the wide cell, after which the two screens must agree exactly: the
    // damage is confined and heals.
    let mut src = TerminalCore::new(10, 2);
    let mut dst = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed("\u{65e5}xyz".as_bytes());
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);

    src.feed(b"\x1b[1;2H\x1b[K\x1b[1;3Hxyz");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen_except(&dst.frame(), &frame, 0, 0..2);

    src.feed(b"\x1b[1;1H\x1b[@");
    let frame = src.frame();
    assert_eq!(
        frame.cell(0, 1).flags & FLAG_WIDE,
        FLAG_WIDE,
        "the damaged pair moved to columns 1..3"
    );
    dst.feed(&r.render(&frame));
    assert_same_screen_except(&dst.frame(), &frame, 0, 1..3);

    src.feed(b"\x1b[1;2HQ");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn deleting_a_wide_character_leaves_no_hole_where_its_orphan_spacer_is() {
    // `ESC [ P` on the wide character shifts its spacer one column left,
    // where it has no wide neighbor -- what every `delch()` in ncurses and
    // every line editor does. A renderer that skips every spacer as
    // "already painted" prints nothing for that column, and the rest of the
    // row lands one column too far left -- on a full repaint as much as in
    // the difference. The orphan is a blank either way; only its flag has no
    // counterpart on the destination, so that one cell is exempt.
    let mut src = TerminalCore::new(10, 2);
    src.feed("ab\u{65e5}cd".as_bytes());
    src.feed(b"\x1b[1;3H\x1b[P");
    let expected = src.frame();
    assert_eq!(
        expected.cell(0, 2).flags & FLAG_WIDE_SPACER,
        FLAG_WIDE_SPACER,
        "an orphan spacer"
    );
    assert_eq!(
        expected.cell(0, 1).flags & FLAG_WIDE,
        0,
        "with no wide character beside it"
    );

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(10, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen_except(&dst.frame(), &expected, 0, 2..3);
    assert_eq!(
        dst.frame().cell(0, 2).ch,
        ' ',
        "the orphan draws as a blank"
    );
}

#[test]
fn deleting_a_wide_character_stays_aligned_through_the_incremental_path() {
    // The same orphan through the difference: the changed span starts on it,
    // and it must be drawn rather than backed over or skipped. Overwriting
    // it afterwards brings the two screens back into exact agreement.
    let mut src = TerminalCore::new(10, 2);
    let mut dst = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed("ab\u{65e5}cd".as_bytes());
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);

    src.feed(b"\x1b[1;3H\x1b[P");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen_except(&dst.frame(), &frame, 0, 2..3);

    src.feed(b"\x1b[1;3HZ");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_wide_character_pushed_into_the_last_column_does_not_wrap_the_terminal() {
    // `ESC [ @` shifts the row right and can leave a FLAG_WIDE cell in the
    // last column with its spacer shoved off the row. Printing the glyph
    // there makes the terminal wrap it onto the next row -- and scroll the
    // whole screen when this is the bottom row. The cell has to draw as a
    // blank; the row above must still be where it was.
    let mut src = TerminalCore::new(6, 2);
    src.feed(b"row0\r\n");
    src.feed("abcd\u{65e5}".as_bytes());
    src.feed(b"\x1b[2;1H\x1b[@");
    let expected = src.frame();
    assert_eq!(
        expected.cell(1, 5).flags & FLAG_WIDE,
        FLAG_WIDE,
        "a wide cell in the last column"
    );

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(6, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen_except(&dst.frame(), &expected, 1, 5..6);
}

#[test]
fn leaving_the_alternate_screen_does_not_take_the_scroll_shortcut() {
    // On `?1049l` the previous frame is the application's last picture and
    // the new one is the restored shell: unrelated content that can still
    // line up as a shift by coincidence. Here the alternate screen's second
    // row equals the shell's first -- exactly the evidence `scrolled_by`
    // looks for -- and a newline would push a line of the application into
    // the user's real scrollback.
    let mut src = TerminalCore::new(20, 3);
    let mut dst = TerminalCore::new(20, 3);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed(b"line0\r\nline1\r\nline2");
    dst.feed(&r.render(&src.frame()));

    src.feed(b"\x1b[?1049h\x1b[Happ\r\nline0\r\nmore");
    let frame = src.frame();
    assert!(
        frame.alt_screen,
        "the application is on the alternate screen"
    );
    dst.feed(&r.render(&frame));

    src.feed(b"\x1b[?1049l");
    let frame = src.frame();
    assert!(!frame.alt_screen, "the shell is back on the primary screen");
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        !text.contains('\n'),
        "leaving the alternate screen must not scroll the user's terminal: {text:?}"
    );
    dst.feed(&bytes);
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_damaged_wide_character_does_not_leave_its_paint_on_an_unchanged_neighbour() {
    // Step 2 changes column 2 only: the wide character lands there, and
    // `ESC [ X` on its second half turns the spacer back into the cyan blank
    // column 3 already was -- so the model of column 3 is unchanged, and a
    // span that ends on the glyph leaves it out. Printing the glyph paints
    // column 3 on the terminal in the glyph's reverse red, and since the
    // model never changes there again, nothing would ever repair it: step 3
    // erases the whole row in cyan and still finds only column 2 different.
    // The span has to reach past the glyph onto its successor.
    let mut src = TerminalCore::new(8, 2);
    let mut dst = TerminalCore::new(8, 2);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed(b"\x1b[46m\x1b[2K");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);

    src.feed("\x1b[1;3H\x1b[7;31;46m\u{65e5}\x1b[1;4H\x1b[0;46m\x1b[X".as_bytes());
    let frame = src.frame();
    assert_eq!(frame.cell(0, 2).flags & FLAG_WIDE, FLAG_WIDE);
    assert_eq!(
        visible(frame.cell(0, 3)),
        (
            ' ',
            Default::default(),
            Color::Default,
            Color::Indexed(6),
            0
        ),
        "column 3 is the plain cyan blank it was before"
    );
    dst.feed(&r.render(&frame));
    // The damaged cell itself is ambiguous on a real terminal; its successor
    // is not, and has to show the model's plain cyan blank, not the glyph's
    // reverse red.
    assert_same_screen_except(&dst.frame(), &frame, 0, 2..3);

    src.feed(b"\x1b[1;1H\x1b[0;46m\x1b[2K");
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);
}

#[test]
fn a_damaged_wide_character_does_not_paint_past_the_row_content_on_a_full_repaint() {
    // The same shape on the full-repaint path: the glyph is the last thing
    // in the row and the erased second half behind it is a DEFAULT blank,
    // which the row's content end rightly excludes -- yet the glyph paints
    // it red, and no later frame changes that cell. The successor has to be
    // drawn as the blank it is.
    let mut src = TerminalCore::new(8, 2);
    src.feed("\x1b[41m\u{65e5}\x1b[1;2H\x1b[0m\x1b[K".as_bytes());
    let expected = src.frame();
    assert_eq!(expected.cell(0, 0).flags & FLAG_WIDE, FLAG_WIDE);
    assert_eq!(
        visible(expected.cell(0, 1)),
        (' ', Default::default(), Color::Default, Color::Default, 0),
        "the second half is a default blank"
    );

    let mut r = Renderer::new(TermCaps::truecolor());
    let mut dst = TerminalCore::new(8, 2);
    dst.feed(&r.render(&expected));
    assert_same_screen_except(&dst.frame(), &expected, 0, 0..1);
}

#[test]
fn an_orphan_spacer_is_drawn_when_its_row_moves_onto_other_text() {
    // The orphan-spacer rule -- a trailing spacer with no wide character to
    // its left is printed as the blank it is, not skipped -- is what keeps
    // this row right. The two orphan tests above pass even without it: the
    // destination's cell under the skipped orphan is the spacer of the very
    // character the emulator's own wide-character cleanup blanks out when
    // `c` is written beside it. Here the row with the orphan moves up (`ESC
    // [ M` deletes the row above) onto a row of plain letters, so the cell
    // under the orphan holds a `Z` that no cleanup ever touches: skipped, it
    // stays on screen as a glyph the model does not have.
    let mut src = TerminalCore::new(10, 2);
    let mut dst = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());

    src.feed("XYZWV\r\nab\u{65e5}cd".as_bytes());
    let frame = src.frame();
    dst.feed(&r.render(&frame));
    assert_same_screen(&dst.frame(), &frame);

    src.feed(b"\x1b[2;3H\x1b[P\x1b[1;1H\x1b[1M");
    let frame = src.frame();
    assert_eq!(
        frame.cell(0, 2).flags & FLAG_WIDE_SPACER,
        FLAG_WIDE_SPACER,
        "the orphan rode up to row 0"
    );
    let bytes = r.render(&frame);
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(
        text.contains("\x1b[1;1Hab cd"),
        "the orphan is printed as a blank in its place: {text:?}"
    );
    dst.feed(&bytes);
    let shown = dst.frame();
    for (col, ch) in "ab cd".chars().enumerate() {
        assert_eq!(
            *shown.cell(0, col as u16),
            Cell {
                ch,
                fg: Color::Default,
                bg: Color::Default,
                flags: 0,
                combining: Default::default(),
            },
            "row 0, col {col}"
        );
    }
    assert_same_screen_except(&shown, &frame, 0, 2..3);
}

#[test]
fn cropped_viewport_never_scrolls_the_physical_terminal() {
    let mut src = TerminalCore::new(20, 3);
    let mut dst = TerminalCore::new(20, 5);
    let mut r = Renderer::new(TermCaps::truecolor());
    r.set_physical_scroll_eligible(false);
    for i in 0..4 {
        src.feed(format!("line{i}\r\n").as_bytes());
        let frame = src.frame();
        let bytes = r.render(&frame);
        assert!(!bytes.contains(&b'\n'), "cropped view must use row diffs");
        dst.feed(&bytes);
        let actual = dst.frame();
        for row in 0..3 {
            for col in 0..20 {
                assert_eq!(
                    visible(actual.cell(row, col)),
                    visible(frame.cell(row, col))
                );
            }
        }
    }
}

/// This oracle reads Alacritty directly, without the public frame conversion
/// under test. Literal marks and attributes must survive the emitted bytes.
fn parse_complete_cells(
    bytes: &[u8],
) -> alacritty_terminal::term::Term<alacritty_terminal::event::VoidListener> {
    use alacritty_terminal::{
        event::VoidListener,
        term::{test::TermSize, Config, Term},
        vte::ansi::Processor,
    };
    let mut term = Term::new(Config::default(), &TermSize::new(12, 3), VoidListener);
    let mut parser: Processor = Processor::new();
    parser.advance(&mut term, bytes);
    term
}

#[test]
fn complete_cell_text_survives_frame_and_render() {
    use alacritty_terminal::index::{Column, Line};
    let mut source = TerminalCore::new(12, 3);
    // Split every UTF-8 sequence to exercise incremental input as well.
    for byte in "e\u{301}\u{302} \u{303}界\u{304}".as_bytes() {
        source.feed(&[*byte]);
    }
    let mut renderer = Renderer::new(TermCaps::truecolor());
    let term = parse_complete_cells(&renderer.render(&source.frame()));
    for (column, base, marks) in [
        (0, 'e', vec!['\u{301}', '\u{302}']),
        (1, ' ', vec!['\u{303}']),
        (2, '界', vec!['\u{304}']),
    ] {
        let cell = &term.grid()[Line(0)][Column(column)];
        assert_eq!(cell.c, base);
        assert_eq!(
            cell.zerowidth().unwrap_or_default(),
            marks,
            "column {column}"
        );
    }
    assert_eq!(term.grid().cursor.point.column, Column(4));
}

#[test]
fn complete_cell_concealment_survives_frame_and_render() {
    use alacritty_terminal::{
        index::{Column, Line},
        term::cell::Flags,
    };
    let mut source = TerminalCore::new(12, 3);
    source.feed(b"\x1b[1;8mH\x1b[28mV\x1b[8mX\x1b[0mY");
    for caps in [TermCaps::truecolor(), TermCaps::detect(Some("dumb"), None)] {
        let mut renderer = Renderer::new(caps);
        let term = parse_complete_cells(&renderer.render(&source.frame()));
        for (column, hidden) in [(0, true), (1, false), (2, true), (3, false)] {
            assert_eq!(
                term.grid()[Line(0)][Column(column)]
                    .flags
                    .contains(Flags::HIDDEN),
                hidden,
                "column {column}"
            );
            assert_eq!(
                term.grid()[Line(0)][Column(column)]
                    .flags
                    .contains(Flags::BOLD),
                column < 3
            );
        }
    }
}

#[test]
fn complete_cell_suffix_changes_and_removal_repaint_the_cluster() {
    use alacritty_terminal::index::{Column, Line};
    let mut source = TerminalCore::new(12, 3);
    let mut renderer = Renderer::new(TermCaps::truecolor());
    let mut output = Vec::new();
    for (text, marks) in [
        ("e\u{301}", vec!['\u{301}']),
        ("e\u{302}", vec!['\u{302}']),
        ("e", vec![]),
        (" \u{303}", vec!['\u{303}']),
        (" ", vec![]),
    ] {
        source.feed(b"\x1b[H");
        source.feed(text.as_bytes());
        output.extend(renderer.render(&source.frame()));
        let actual = parse_complete_cells(&output);
        assert_eq!(
            actual.grid()[Line(0)][Column(0)]
                .zerowidth()
                .unwrap_or_default(),
            marks
        );
        assert_eq!(actual.grid().cursor.point.column, Column(1));
    }
}

#[test]
fn complete_cell_replay_keeps_saturated_marks_and_concealment() {
    use alacritty_terminal::{
        index::{Column, Line},
        term::cell::Flags,
    };
    for alternate in [false, true] {
        let mut source = TerminalCore::with_replay(12, 3);
        if alternate {
            source.feed(b"\x1b[?1049h");
        }
        source.feed(format!("\x1b[8me{}", "\u{301}".repeat(100)).as_bytes());
        let mut restored = TerminalCore::new(12, 3);
        restored.feed(&source.replay().unwrap());
        let mut renderer = Renderer::new(TermCaps::truecolor());
        let actual = parse_complete_cells(&renderer.render(&restored.frame()));
        let cell = &actual.grid()[Line(0)][Column(0)];
        assert_eq!(cell.c, 'e');
        assert_eq!(
            cell.zerowidth().unwrap(),
            &['\u{301}'; terminal::MAX_COMBINING_MARKS]
        );
        assert!(cell.flags.contains(Flags::HIDDEN));
    }
}

#[test]
fn complete_cell_normalized_spacers_and_clipped_glyphs_emit_no_marks() {
    use alacritty_terminal::index::{Column, Line};
    for (col, ch, flags) in [
        (0, ' ', FLAG_WIDE_SPACER),
        (0, ' ', FLAG_LEADING_WIDE_SPACER),
        (0, '\t', 0),
        (11, '界', FLAG_WIDE),
    ] {
        let mut frame = Frame::blank(12, 3);
        let cell = frame.cell_mut(0, col);
        cell.ch = ch;
        cell.flags = flags;
        cell.combining = terminal::CombiningMarks::from_slice(&['\u{301}']);
        let bytes = Renderer::new(TermCaps::truecolor()).render(&frame);
        let actual = parse_complete_cells(&bytes);
        for column in 0..12 {
            assert!(actual.grid()[Line(0)][Column(column)]
                .zerowidth()
                .unwrap_or_default()
                .is_empty());
        }
    }
}

/// The renderer keeps one frame and rewrites it on every render, shifting
/// it in place for the scroll shortcut. Over a long script mixing scrolls of
/// several sizes, combining marks, wide characters, the alternate screen and
/// resizes, every step must still reproduce the source, and rendering the
/// same frame again must draw nothing: the kept frame is exactly what the
/// terminal shows, not a stale or shifted leftover.
#[test]
fn reused_renderer_storage_tracks_a_long_mixed_script() {
    fn check(r: &mut Renderer, src: &mut TerminalCore, dst: &mut TerminalCore, chunk: &[u8]) {
        src.feed(chunk);
        let frame = src.frame();
        let bytes = r.render(&frame);
        assert_only_escapes_and_newlines(&bytes);
        dst.feed(&bytes);
        assert_same_screen(&dst.frame(), &frame);
        let again = r.render(&frame);
        let cursor = format!(
            "\x1b[{};{}H\x1b[?25{}",
            frame.cursor_row + 1,
            frame.cursor_col + 1,
            if frame.cursor_visible { 'h' } else { 'l' }
        );
        assert_eq!(
            String::from_utf8_lossy(&again),
            cursor,
            "an unchanged frame drew more than the cursor after {chunk:?}"
        );
        dst.feed(&again);
        assert_same_screen(&dst.frame(), &frame);
    }
    let mut src = TerminalCore::new(24, 6);
    let mut dst = TerminalCore::new(24, 6);
    let mut r = Renderer::new(TermCaps::truecolor());
    for n in 0..30 {
        let lines = 1 + n % 3;
        let text: String = (0..lines)
            .map(|k| format!("{n:02}.{k} e\u{301}\u{302} 界 x\u{20dd}\r\n"))
            .collect();
        check(&mut r, &mut src, &mut dst, text.as_bytes());
    }
    check(
        &mut r,
        &mut src,
        &mut dst,
        b"\x1b[?1049h\x1b[2J\x1b[H\x1b[33mfull screen",
    );
    for n in 0..5 {
        let row = format!("\x1b[{};1H\x1b[4{}m界 a\u{301} {n}", 1 + n, n % 8);
        check(&mut r, &mut src, &mut dst, row.as_bytes());
    }
    check(&mut r, &mut src, &mut dst, b"\x1b[0m\x1b[?1049l");
    for n in 0..8 {
        let line = format!("after {n} o\u{308}\r\n");
        check(&mut r, &mut src, &mut dst, line.as_bytes());
    }
    for (cols, rows) in [(10, 3), (30, 8), (24, 6)] {
        src.resize(cols, rows);
        dst = TerminalCore::new(cols, rows);
        r.invalidate();
        check(&mut r, &mut src, &mut dst, b"");
        for n in 0..4 {
            let line = format!("{cols}x{rows} {n} 界\r\n");
            check(&mut r, &mut src, &mut dst, line.as_bytes());
        }
    }
}
