//! A replay: bytes that bring a client's emulator -- fed some prefix of this
//! model's input and then nothing, in whatever state that left it -- to
//! exactly this model's state. Not only the screen: everything the next
//! bytes are read against, so the output that follows lands on both sides
//! the same way.
//!
//! What it restores, in the order it does so:
//! 1. ends a synchronized update the client may be stuck in, and with the
//!    same ESC abandons any sequence it was in the middle of;
//! 2. the primary screen, row by row in place -- cursor addressing, no
//!    `ESC [ 2 J`, nothing that scrolls, so the client's scrollback gets no
//!    copy of its screen -- with soft wraps made the way the model made
//!    them (the next row is reached by wrapping, so the row carries the
//!    wrap flag a later resize reflows by);
//! 3. on the alternate screen, the primary screen's cursor first (it is what
//!    leaving the alternate screen returns to), then the alternate screen;
//! 4. tab characters the model recorded in cells, the saved cursor (DECSC),
//!    the palette (OSC 4/10/11/12), the tab stops, the last printed
//!    character (what `CSI b` repeats), every mode, the cursor style, the
//!    scroll region, origin mode, the cursor (a pending wrap at the last
//!    column included), insert mode and LNM, the character sets and which one
//!    is active, and the pen;
//! 5. the unfinished escape sequence the model's input ends in, if any, so
//!    both parsers stand in the same place.
//!
//! What it does not: hyperlinks (OSC 8), the window title, and -- while the
//! primary screen is shown -- the alternate screen's saved cursor, which only
//! a DECRC on the alternate screen before any DECSC would read. A row whose
//! wrap flag sits on the bottom row, and a wide-character placeholder that
//! no longer precedes a wrap, come back without that flag. Two cursor cases
//! need the saved cursor to stand where the cursor does (then DECRC carries
//! the cursor back, see `write`); otherwise the cursor is addressed, so
//! under origin mode one outside the region is clamped into it, and one
//! waiting to wrap over a cell that holds something other than the last
//! printed character makes that cell's character the one `CSI b` repeats.
//! (No input found reaches the latter: a wide character refused at the last
//! column and a resize that leaves the cursor waiting over a blank are both
//! restored.)

use std::fmt::Write as _;

use unicode_width::UnicodeWidthChar;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::{Cursor, Dimensions, Grid};
use alacritty_terminal::index::{Column, Line};
use alacritty_terminal::term::cell::{Cell as AlacrittyCell, Flags};
use alacritty_terminal::term::{Term, TermMode};
use alacritty_terminal::vte::ansi::{
    CharsetIndex, Color as AnsiColor, CursorShape, NamedColor, StandardCharset,
};

use crate::tracking::Tracked;

/// The flags an SGR sets: what a cell looks like, not what it is.
const SGR_FLAGS: Flags = Flags::BOLD
    .union(Flags::DIM)
    .union(Flags::ITALIC)
    .union(Flags::ALL_UNDERLINES)
    .union(Flags::INVERSE)
    .union(Flags::HIDDEN)
    .union(Flags::STRIKEOUT);

/// The last dynamic color an OSC can set: 256 foreground, 257 background,
/// 258 cursor.
const LAST_SETTABLE_COLOR: usize = NamedColor::Cursor as usize;

/// A cell's appearance, as an SGR carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Style {
    fg: AnsiColor,
    bg: AnsiColor,
    flags: Flags,
    underline: Option<AnsiColor>,
}

impl Style {
    fn default_style() -> Style {
        Style {
            fg: AnsiColor::Named(NamedColor::Foreground),
            bg: AnsiColor::Named(NamedColor::Background),
            flags: Flags::empty(),
            underline: None,
        }
    }

    fn of(cell: &AlacrittyCell) -> Style {
        Style {
            fg: cell.fg,
            bg: cell.bg,
            flags: cell.flags & SGR_FLAGS,
            underline: cell.underline_color(),
        }
    }

    /// A blank with only a background, as erasing with this pen leaves.
    fn background(bg: AnsiColor) -> Style {
        Style {
            bg,
            ..Style::default_style()
        }
    }
}

/// The replay being written, with what the client's pen is known to be.
struct Out {
    bytes: Vec<u8>,
    /// `None` until an SGR has set it, and again after a screen switch: the
    /// grid switched to brings its own pen.
    style: Option<Style>,
}

impl Out {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn push_str(&mut self, s: &str) {
        self.bytes.extend_from_slice(s.as_bytes());
    }

    fn print(&mut self, c: char) {
        let mut buf = [0u8; 4];
        self.push(c.encode_utf8(&mut buf).as_bytes());
    }

    /// CUP, 0-based `row` and `col` (origin-relative when DECOM is on).
    fn cup(&mut self, row: usize, col: usize) {
        let _ = write!(self, "\x1b[{};{}H", row + 1, col + 1);
    }

    /// Set the pen, from scratch: `0` first, then everything `style` has.
    fn sgr(&mut self, style: &Style) {
        if self.style.as_ref() == Some(style) {
            return;
        }
        let mut s = String::from("\x1b[0");
        let f = style.flags;
        if f.contains(Flags::BOLD) {
            s.push_str(";1");
        }
        if f.contains(Flags::DIM) {
            s.push_str(";2");
        }
        if f.contains(Flags::ITALIC) {
            s.push_str(";3");
        }
        // One underline style at a time, as `Term` keeps them; the styled
        // ones only exist as a colon sub-parameter.
        if f.contains(Flags::UNDERLINE) {
            s.push_str(";4");
        } else if f.contains(Flags::DOUBLE_UNDERLINE) {
            s.push_str(";4:2");
        } else if f.contains(Flags::UNDERCURL) {
            s.push_str(";4:3");
        } else if f.contains(Flags::DOTTED_UNDERLINE) {
            s.push_str(";4:4");
        } else if f.contains(Flags::DASHED_UNDERLINE) {
            s.push_str(";4:5");
        }
        if f.contains(Flags::INVERSE) {
            s.push_str(";7");
        }
        if f.contains(Flags::HIDDEN) {
            s.push_str(";8");
        }
        if f.contains(Flags::STRIKEOUT) {
            s.push_str(";9");
        }
        push_color(&mut s, style.fg, 30, 90, 38, NamedColor::Foreground);
        push_color(&mut s, style.bg, 40, 100, 48, NamedColor::Background);
        match style.underline {
            Some(AnsiColor::Indexed(i)) => {
                let _ = write!(s, ";58;5;{i}");
            }
            Some(AnsiColor::Spec(rgb)) => {
                let _ = write!(s, ";58;2;{};{};{}", rgb.r, rgb.g, rgb.b);
            }
            // An SGR sets an underline color only as an index or as RGB.
            Some(AnsiColor::Named(_)) | None => {}
        }
        s.push('m');
        self.push_str(&s);
        self.style = Some(style.clone());
    }

    /// Designate G0-G3 as `charsets` has them.
    fn designate(&mut self, charsets: &alacritty_terminal::grid::Charsets) {
        for (index, intermediate) in [
            (CharsetIndex::G0, b'('),
            (CharsetIndex::G1, b')'),
            (CharsetIndex::G2, b'*'),
            (CharsetIndex::G3, b'+'),
        ] {
            let final_byte = match charsets[index] {
                StandardCharset::Ascii => b'B',
                StandardCharset::SpecialCharacterAndLineDrawing => b'0',
            };
            self.push(&[0x1b, intermediate, final_byte]);
        }
    }
}

impl std::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

/// One SGR color: the default by its own code, the first sixteen named ones
/// by their short codes, an index or RGB by `38`/`48`.
fn push_color(
    s: &mut String,
    color: AnsiColor,
    base: u16,
    bright: u16,
    long: u16,
    default: NamedColor,
) {
    match color {
        AnsiColor::Named(named) if named == default => {
            let _ = write!(s, ";{}", base + 9);
        }
        AnsiColor::Named(named) if (named as usize) < 8 => {
            let _ = write!(s, ";{}", base + named as u16);
        }
        AnsiColor::Named(named) if (named as usize) < 16 => {
            let _ = write!(s, ";{}", bright + named as u16 - 8);
        }
        // No SGR sets any other named color on a cell.
        AnsiColor::Named(_) => {
            let _ = write!(s, ";{}", base + 9);
        }
        AnsiColor::Indexed(i) => {
            let _ = write!(s, ";{long};5;{i}");
        }
        AnsiColor::Spec(rgb) => {
            let _ = write!(s, ";{long};2;{};{};{}", rgb.r, rgb.g, rgb.b);
        }
    }
}

/// A cell no one has written to: what an erase with the default pen leaves.
fn is_untouched(cell: &AlacrittyCell) -> bool {
    cell.c == ' '
        && cell.fg == AnsiColor::Named(NamedColor::Foreground)
        && cell.bg == AnsiColor::Named(NamedColor::Background)
        && cell.flags.is_empty()
        && cell.zerowidth().is_none_or(|z| z.is_empty())
        && cell.underline_color().is_none()
}

/// A blank that holds nothing but a background, as an erase leaves.
fn is_plain_blank(cell: &AlacrittyCell) -> bool {
    cell.c == ' '
        && cell.fg == AnsiColor::Named(NamedColor::Foreground)
        && cell.flags.is_empty()
        && cell.zerowidth().is_none_or(|z| z.is_empty())
        && cell.underline_color().is_none()
}

/// One past the last cell of `row` anyone wrote to.
fn content_end(grid: &Grid<AlacrittyCell>, row: usize) -> usize {
    let cells = &grid[Line(row as i32)];
    (0..grid.columns())
        .rev()
        .find(|&col| !is_untouched(&cells[Column(col)]))
        .map_or(0, |col| col + 1)
}

/// Print the cell at `row`/`col` (the cursor is there) and return the column
/// after it. A spacer the wide character to its left already covered is
/// skipped; a wide character with no room for its second half, a control
/// character (a cell a tab landed on), an orphaned spacer and a placeholder
/// that no longer precedes a wrap all print as a blank.
fn put(out: &mut Out, grid: &Grid<AlacrittyCell>, row: usize, col: usize) -> usize {
    let cols = grid.columns();
    let cells = &grid[Line(row as i32)];
    let cell = &cells[Column(col)];
    if cell.flags.contains(Flags::WIDE_CHAR_SPACER)
        && col > 0
        && cells[Column(col - 1)].flags.contains(Flags::WIDE_CHAR)
    {
        return col + 1;
    }
    out.sgr(&Style::of(cell));
    let wide = cell.flags.contains(Flags::WIDE_CHAR) && col + 1 < cols;
    let ch = if cell.c.is_control() || (cell.flags.contains(Flags::WIDE_CHAR) && !wide) {
        ' '
    } else {
        cell.c
    };
    out.print(ch);
    for &z in cell.zerowidth().unwrap_or(&[]) {
        out.print(z);
    }
    col + if wide { 2 } else { 1 }
}

/// Paint `grid`'s screen in place. The client has origin mode off, the full
/// screen as its region, autowrap on, insert mode off and G0 as ASCII.
fn paint(out: &mut Out, grid: &Grid<AlacrittyCell>) {
    let rows = grid.screen_lines();
    let cols = grid.columns();
    // Where the cursor already stands on this row: the row above wrapped
    // into it.
    let mut resume: Option<usize> = None;
    for row in 0..rows {
        let cells = &grid[Line(row as i32)];
        let wraps = row + 1 < rows && cells[Column(cols - 1)].flags.contains(Flags::WRAPLINE);
        let mut col = match resume.take() {
            Some(col) => col,
            None => {
                out.cup(row, 0);
                0
            }
        };
        if !wraps {
            let end = content_end(grid, row);
            while col < end {
                col = put(out, grid, row, col);
            }
            if col < cols {
                out.sgr(&Style::default_style());
                out.push(b"\x1b[K");
            }
            continue;
        }
        while col < cols - 1 {
            col = put(out, grid, row, col);
        }
        let last = &cells[Column(cols - 1)];
        if col == cols - 1 && last.flags.contains(Flags::LEADING_WIDE_CHAR_SPACER) {
            // A wide character printed in the last column leaves this
            // placeholder and wraps: print the one that follows, or any, and
            // repaint the next row over it. Writing over a wide character at
            // the start of a row takes the placeholder's flag away from the
            // row above (`Term::write_at_cursor`), so the next row is erased
            // first, and again after a stand-in -- an erase only assigns.
            erase_row(out, row + 1);
            out.cup(row, cols - 1);
            out.sgr(&Style::of(last));
            let next = &grid[Line(row as i32 + 1)][Column(0)];
            if cols >= 2
                && next.flags.contains(Flags::WIDE_CHAR)
                && Style::of(next) == Style::of(last)
            {
                out.print(next.c);
                for &z in next.zerowidth().unwrap_or(&[]) {
                    out.print(z);
                }
                resume = Some(2);
            } else {
                out.print('\u{3000}');
                erase_row(out, row + 1);
                resume = Some(0);
            }
            continue;
        }
        if col == cols - 1 {
            col = put(out, grid, row, col);
        }
        debug_assert_eq!(col, cols);
        // The cursor waits at the last column; the next row's first cell
        // wraps it there, which is what marks this row as wrapped.
        resume = Some(put(out, grid, row + 1, 0));
    }
}

/// Erase `row` with the default background, leaving the cursor at its
/// start.
fn erase_row(out: &mut Out, row: usize) {
    out.cup(row, 0);
    out.sgr(&Style::default_style());
    out.push(b"\x1b[K");
}

/// A tab the model recorded in a cell (`put_tab` writes the character into
/// the blank cell it leaves): sent as a tab from that cell, it is recorded
/// the same way on the client.
fn fix_tabs(out: &mut Out, grid: &Grid<AlacrittyCell>) {
    for row in 0..grid.screen_lines() {
        let cells = &grid[Line(row as i32)];
        for col in 0..grid.columns() {
            if cells[Column(col)].c == '\t' {
                out.cup(row, col);
                out.push(b"\t");
            }
        }
    }
}

/// Which character set turns `p` into `c` when printed.
fn charset_for(p: char, c: char) -> Option<StandardCharset> {
    [
        StandardCharset::Ascii,
        StandardCharset::SpecialCharacterAndLineDrawing,
    ]
    .into_iter()
    .find(|cs| cs.map(p) == c)
}

/// Print the last-column cell of grid line `line` -- printing it is what
/// leaves a cursor waiting to wrap there. `address_row` is how the client
/// addresses that line: as is, or from the region's top under origin mode.
/// The cell is printed as the model's last printed character when that one
/// prints to it, so `CSI b` repeats the same character on both sides; the
/// answer is whether it did.
fn reprint_last_column(
    out: &mut Out,
    grid: &Grid<AlacrittyCell>,
    line: usize,
    address_row: usize,
    last_input: Option<char>,
) -> bool {
    let cols = grid.columns();
    let cells = &grid[Line(line as i32)];
    let mut col = cols - 1;
    if cols >= 2
        && cells[Column(col)].flags.contains(Flags::WIDE_CHAR_SPACER)
        && cells[Column(col - 1)].flags.contains(Flags::WIDE_CHAR)
    {
        col -= 1;
    }
    let cell = &cells[Column(col)];
    out.cup(address_row, col);
    out.sgr(&Style::of(cell));
    let base = if cell.c.is_control() { ' ' } else { cell.c };
    let zerowidth = cell.zerowidth().unwrap_or(&[]);
    let as_last = match last_input.and_then(|p| charset_for(p, base).map(|cs| (p, cs))) {
        Some((p, cs)) => {
            if cs != StandardCharset::Ascii {
                out.push(b"\x1b(0");
            }
            out.print(p);
            if cs != StandardCharset::Ascii {
                out.push(b"\x1b(B");
            }
            zerowidth.is_empty()
        }
        None => {
            out.print(base);
            false
        }
    };
    for &z in zerowidth {
        out.print(z);
    }
    if zerowidth.len() == 16 && last_input.is_some_and(|p| p.width() == Some(0)) {
        // The capped handler records this character for REP but drops its
        // addition to the already full target. Pending wrap remains intact.
        out.print(last_input.unwrap());
        return true;
    }
    as_last || (last_input.is_some() && zerowidth.last().copied() == last_input)
}

/// Put the client's cursor where and as `cursor` is: position, a pending
/// wrap, its character sets and its pen. Absolute addressing (origin mode is
/// off here).
fn place(out: &mut Out, grid: &Grid<AlacrittyCell>, cursor: &Cursor<AlacrittyCell>) {
    let line = cursor.point.line.0.max(0) as usize;
    let col = cursor.point.column.0;
    if cursor.input_needs_wrap && col + 1 == grid.columns() {
        let _ = reprint_last_column(out, grid, line, line, None);
    } else {
        out.cup(line, col);
    }
    out.designate(&cursor.charsets);
    out.sgr(&Style::of(&cursor.template));
}

/// Printing a cursor's pending wrap back (`reprint_last_column`) rewrites
/// the cell and so drops the wrap flag it has when the row did wrap
/// afterwards (DECSC over a pending wrap, then output went on). Wrapping out
/// of it again -- printing the next row's first cell, which is already
/// painted -- puts the flag back. The cursor moves: the caller has saved it
/// (DECSC) and brings it back.
fn rewrap(out: &mut Out, grid: &Grid<AlacrittyCell>, cursor: &Cursor<AlacrittyCell>) {
    if rewrap_would_print(grid, cursor) {
        let line = cursor.point.line.0.max(0) as usize;
        let _ = put(out, grid, line + 1, 0);
    }
}

fn rewrap_would_print(grid: &Grid<AlacrittyCell>, cursor: &Cursor<AlacrittyCell>) -> bool {
    let line = cursor.point.line.0.max(0) as usize;
    let cols = grid.columns();
    cursor.input_needs_wrap
        && cursor.point.column.0 + 1 == cols
        && line + 1 < grid.screen_lines()
        && grid[Line(line as i32)][Column(cols - 1)]
            .flags
            .contains(Flags::WRAPLINE)
}

/// Make `p` the last printed character -- the one `CSI b` repeats -- without
/// changing the screen: print it over a cell it would print to anyway, or,
/// failing that, into a blank inserted at the start of a row that ends in a
/// blank, then delete that blank again.
fn set_last_printed(out: &mut Out, grid: &Grid<AlacrittyCell>, p: char) {
    let rows = grid.screen_lines();
    let cols = grid.columns();
    // As `Term::input` measures it.
    let w = UnicodeWidthChar::width(p).unwrap_or(0);
    if p.width() == Some(0) {
        for row in 0..rows {
            for col in 0..cols {
                let cell = &grid[Line(row as i32)][Column(col)];
                if cell.zerowidth().is_some_and(|z| z.len() == 16) {
                    // At column zero, zero-width input targets column zero;
                    // otherwise place immediately after the target.
                    out.cup(row, (col + 1).min(cols - 1));
                    if col == cols - 1 {
                        // A wide input refused at the last column with wrap
                        // disabled sets pending wrap without rewriting the
                        // cell (or clearing its WRAPLINE flag). This makes
                        // zero-width input target this column. modes() below
                        // restores the model's wrap setting.
                        out.push(b"\x1b[?7l");
                        out.print('界');
                        out.print(p);
                    } else {
                        out.print(p);
                    }
                    return;
                }
            }
        }
    }
    if w > 0 {
        for row in 0..rows {
            let cells = &grid[Line(row as i32)];
            for col in 0..cols {
                let cell = &cells[Column(col)];
                let plain = !cell.flags.intersects(
                    Flags::WRAPLINE | Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER,
                ) && cell.zerowidth().is_none_or(|z| z.is_empty());
                if !plain {
                    continue;
                }
                // Writing over a wide character in the first two columns
                // takes the wrap placeholder's flag from the row above.
                let fits = if w == 1 {
                    !cell.flags.contains(Flags::WIDE_CHAR)
                } else {
                    col > 1
                        && cell.flags.contains(Flags::WIDE_CHAR)
                        && col + 1 < cols
                        && Style::of(&cells[Column(col + 1)]) == Style::of(cell)
                        && cells[Column(col + 1)]
                            .zerowidth()
                            .is_none_or(|z| z.is_empty())
                };
                let Some(cs) = charset_for(p, cell.c).filter(|_| fits) else {
                    continue;
                };
                out.cup(row, col);
                out.sgr(&Style::of(cell));
                if cs != StandardCharset::Ascii {
                    out.push(b"\x1b(0");
                }
                out.print(p);
                if cs != StandardCharset::Ascii {
                    out.push(b"\x1b(B");
                }
                return;
            }
        }
    }
    let n = w.max(1);
    for row in 0..rows {
        let cells = &grid[Line(row as i32)];
        if cols < n + 1 || !(cols - n..cols).all(|c| is_plain_blank(&cells[Column(c)])) {
            continue;
        }
        let bg = cells[Column(cols - 1)].bg;
        if (cols - n..cols).any(|c| cells[Column(c)].bg != bg) {
            continue;
        }
        // The blanks the insert pushes off the row come back from the
        // delete, erased with this background.
        out.cup(row, 0);
        out.sgr(&Style::background(bg));
        let _ = write!(out, "\x1b[{n}@");
        if w == 0 {
            // A zero-width character joins the cell before the cursor.
            out.push(b"\x1b[C");
        }
        out.print(p);
        out.cup(row, 0);
        out.sgr(&Style::background(bg));
        let _ = write!(out, "\x1b[{n}P");
        return;
    }
}

/// Every mode that changes how later bytes are read or input is encoded,
/// set or reset explicitly, and the cursor style. None of them moves the
/// cursor. Origin mode is left to the caller (it homes the cursor), and so
/// are insert mode and LNM (they would change the printing still to come).
fn modes(out: &mut Out, mode: TermMode, style: alacritty_terminal::vte::ansi::CursorStyle) {
    let flag = |out: &mut Out, on: bool, code: &str| {
        let _ = write!(out, "\x1b[?{code}{}", if on { 'h' } else { 'l' });
    };
    flag(out, mode.contains(TermMode::APP_CURSOR), "1");
    out.push(if mode.contains(TermMode::APP_KEYPAD) {
        b"\x1b="
    } else {
        b"\x1b>"
    });
    // The mouse levels and the two encodings exclude each other in `Term`:
    // all off, then the one that is on.
    out.push(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l");
    if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
        out.push(b"\x1b[?1000h");
    } else if mode.contains(TermMode::MOUSE_DRAG) {
        out.push(b"\x1b[?1002h");
    } else if mode.contains(TermMode::MOUSE_MOTION) {
        out.push(b"\x1b[?1003h");
    }
    out.push(b"\x1b[?1005l\x1b[?1006l");
    if mode.contains(TermMode::UTF8_MOUSE) {
        out.push(b"\x1b[?1005h");
    } else if mode.contains(TermMode::SGR_MOUSE) {
        out.push(b"\x1b[?1006h");
    }
    flag(out, mode.contains(TermMode::FOCUS_IN_OUT), "1004");
    flag(out, mode.contains(TermMode::ALTERNATE_SCROLL), "1007");
    flag(out, mode.contains(TermMode::URGENCY_HINTS), "1042");
    flag(out, mode.contains(TermMode::BRACKETED_PASTE), "2004");
    flag(out, mode.contains(TermMode::LINE_WRAP), "7");
    flag(out, mode.contains(TermMode::SHOW_CURSOR), "25");
    // DECSCUSR: `0` is "the default", which is what a style equal to the
    // default is on both sides.
    let default = alacritty_terminal::term::Config::default().default_cursor_style;
    let code = if style == default {
        0
    } else {
        let steady = u8::from(!style.blinking);
        match style.shape {
            CursorShape::Block | CursorShape::HollowBlock | CursorShape::Hidden => 1 + steady,
            CursorShape::Underline => 3 + steady,
            CursorShape::Beam => 5 + steady,
        }
    };
    let _ = write!(out, "\x1b[{code} q");
}

/// The palette: back to the defaults, then every color the model changed.
fn palette(out: &mut Out, term: &Term<VoidListener>) {
    out.push(b"\x1b]104\x07\x1b]110\x07\x1b]111\x07\x1b]112\x07");
    let colors = term.colors();
    for index in 0..=LAST_SETTABLE_COLOR {
        let Some(rgb) = colors[index] else {
            continue;
        };
        let spec = format!("rgb:{:02x}/{:02x}/{:02x}", rgb.r, rgb.g, rgb.b);
        match index {
            0..=255 => {
                let _ = write!(out, "\x1b]4;{index};{spec}\x07");
            }
            _ => {
                let code = 10 + index - NamedColor::Foreground as usize;
                let _ = write!(out, "\x1b]{code};{spec}\x07");
            }
        }
    }
}

/// The tab stops, all of them: whatever the client had is cleared first.
fn tabs(out: &mut Out, tabs: &[bool]) {
    out.push(b"\x1b[3g");
    for (col, _) in tabs.iter().enumerate().filter(|(_, on)| **on) {
        out.cup(0, col);
        out.push(b"\x1bH");
    }
}

/// While the alternate screen is shown, `f` gets the primary screen's grid.
///
/// `Term` keeps the inactive grid private, and `swap_alt` is the only way
/// to it: leaving the alternate screen is a plain swap, but coming back
/// clears the alternate grid, copies the primary cursor into it and sets
/// the primary's saved cursor to its cursor. So the alternate grid is
/// cloned before and put back after -- cells, cursor, saved cursor -- and
/// the primary's saved cursor ends as its cursor. It already was one unless
/// a resize moved the two apart (a resize reflows the cursor but only
/// clamps the saved one); either way the client, whose own entry sets the
/// same, agrees with the model after this.
pub(crate) fn with_primary<R>(
    term: &mut Term<VoidListener>,
    f: impl FnOnce(&Grid<AlacrittyCell>) -> R,
) -> R {
    debug_assert!(term.mode().contains(TermMode::ALT_SCREEN));
    let alternate = term.grid().clone();
    term.swap_alt();
    let result = f(term.grid());
    term.swap_alt();
    *term.grid_mut() = alternate;
    result
}

/// See the module docs.
pub(crate) fn write(term: &mut Term<VoidListener>, tracked: &Tracked, tail: &[u8]) -> Vec<u8> {
    let mut out = Out {
        bytes: Vec::new(),
        style: None,
    };
    // 1. The ESC of this ends whatever the client was in the middle of.
    out.push(b"\x1b[?2026l");
    // 2. The primary screen, prepared for painting: nothing that scrolls or
    // shifts, absolute addressing, G0 as ASCII and active.
    out.push(b"\x1b[?1049l");
    out.style = None;
    out.push(b"\x1b[4l\x1b[?6l\x1b[r\x1b[?7h\x1b(B\x0f");

    let mode = *term.mode();
    let on_alt = mode.contains(TermMode::ALT_SCREEN);
    if on_alt {
        // 3. The primary screen and its cursor, then the alternate screen:
        // entering it copies that cursor, as the model's entry did.
        with_primary(term, |primary| {
            paint(&mut out, primary);
            fix_tabs(&mut out, primary);
            place(&mut out, primary, &primary.cursor);
            // The primary's saved cursor is its cursor once the alternate
            // screen is entered (see `with_primary`), so the slot is free to
            // carry the cursor across a rewrap.
            out.push(b"\x1b7\x1b(B");
            rewrap(&mut out, primary, &primary.cursor);
            out.push(b"\x1b8");
        });
        out.push(b"\x1b[?1049h");
        out.style = None;
        out.push(b"\x1b(B");
    }
    let grid = term.grid();
    let rows = grid.screen_lines();
    let cols = grid.columns();
    paint(&mut out, grid);
    // 4.
    fix_tabs(&mut out, grid);
    let cursor = &grid.cursor;
    let saved = &grid.saved_cursor;
    let waits = cursor.input_needs_wrap && cursor.point.column.0 + 1 == cols;
    let line = cursor.point.line.0.max(0) as usize;
    // The cursor where the saved cursor is (DECSC then DECRC, and nothing
    // since that moved it): the saved cursor is set right there, and DECRC
    // brings the cursor back at the very end -- after the last printed
    // character is set elsewhere and after the region and origin mode have
    // homed it -- a pending wrap, and a place origin mode cannot address,
    // included. Otherwise the saved cursor is set first and the cursor
    // placed by addressing it.
    let shared = cursor.point == saved.point && cursor.input_needs_wrap == saved.input_needs_wrap;
    if !shared {
        place(&mut out, grid, saved);
        out.push(b"\x1b7\x1b(B");
        rewrap(&mut out, grid, saved);
    }
    palette(&mut out, term);
    tabs(&mut out, &tracked.tabs);
    let mut last_printed_set = false;
    if shared {
        if waits {
            last_printed_set = reprint_last_column(&mut out, grid, line, line, tracked.last_input);
        } else {
            out.cup(line, cursor.point.column.0);
        }
        out.designate(&saved.charsets);
        out.sgr(&Style::of(&saved.template));
        out.push(b"\x1b7\x1b(B");
        if rewrap_would_print(grid, saved) {
            rewrap(&mut out, grid, saved);
            last_printed_set = false;
        }
    }
    if !last_printed_set && (shared || !waits) {
        if let Some(p) = tracked.last_input {
            set_last_printed(&mut out, grid, p);
        }
    }
    modes(&mut out, mode, term.cursor_style());

    let region = &tracked.scroll_region;
    if region.start == 0 && region.end == rows as i32 {
        out.push(b"\x1b[r");
    } else {
        // A region the model got only by clamping (asked for past the
        // bottom: `CSI 10;40r` on 10 rows is lines 9..10, `CSI 30;40r` the
        // empty 10..10) would read back as top >= bottom, which a client
        // ignores. Such a region always ends at the screen's bottom, so a
        // bottom past it clamps back to the same one; a region no clamp
        // touched already spans two lines or more and is written as it is.
        let bottom = region.end.max(region.start + 2);
        let _ = write!(out, "\x1b[{};{}r", region.start + 1, bottom);
    }
    let origin = mode.contains(TermMode::ORIGIN);
    if origin {
        out.push(b"\x1b[?6h");
    }
    if shared {
        out.push(b"\x1b8");
    } else {
        let address_row = if origin {
            line.saturating_sub(region.start.max(0) as usize)
        } else {
            line
        };
        if !waits {
            out.cup(address_row, cursor.point.column.0);
        } else if !reprint_last_column(&mut out, grid, line, address_row, tracked.last_input) {
            // The last printed character is not the cell's.
            let last = &grid[Line(line as i32)][Column(cols - 1)];
            match tracked.last_input.map(|p| (p, p.width())) {
                // A wide one refused at the last column with autowrap off
                // leaves exactly this: the cursor waiting, the cell as it
                // was. Printing it there the same way does the same.
                Some((p, Some(2))) => {
                    out.cup(address_row, cols - 1);
                    out.push(b"\x1b[?7l");
                    out.print(p);
                    out.push(if mode.contains(TermMode::LINE_WRAP) {
                        b"\x1b[?7h"
                    } else {
                        b"\x1b[?7l"
                    });
                }
                // Over a blank (a resize left the cursor waiting there):
                // print it into the blank -- a zero-width one joins the
                // blank just printed -- and erase the cell back; an erase
                // does not end a pending wrap.
                Some((p, width)) if is_plain_blank(last) => {
                    if width != Some(0) {
                        out.cup(address_row, cols - 1);
                    }
                    out.print(p);
                    out.sgr(&Style::background(last.bg));
                    out.push(b"\x1b[X");
                }
                // Anything else keeps the cell's character (module docs).
                _ => {}
            }
        }
    }
    out.push(if mode.contains(TermMode::INSERT) {
        b"\x1b[4h"
    } else {
        b"\x1b[4l"
    });
    out.push(if mode.contains(TermMode::LINE_FEED_NEW_LINE) {
        b"\x1b[20h"
    } else {
        b"\x1b[20l"
    });
    out.designate(&cursor.charsets);
    out.push(match tracked.active_charset {
        CharsetIndex::G1 => b"\x0e",
        // Only SI and SO switch sets.
        _ => b"\x0f",
    });
    let pen = Style::of(&cursor.template);
    out.style = None;
    out.sgr(&pen);
    // 5.
    out.push(tail);
    out.bytes
}

/// Everything a replay restores, for comparing two emulators: the cells of
/// both screens (every attribute and zero-width character, hyperlinks
/// aside), the cursors, the saved cursor, the modes, the region, the
/// character sets, the tab stops, the cursor style, the palette and the
/// last printed character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSnapshot {
    active: GridState,
    /// While the alternate screen is shown: the primary screen and its
    /// cursor (its saved cursor is its cursor, see [`with_primary`]).
    primary: Option<GridState>,
    mode: u32,
    scroll_region: (i32, i32),
    active_charset: u8,
    tabs: Vec<bool>,
    cursor_style: (u8, bool),
    colors: Vec<Option<(u8, u8, u8)>>,
    last_input: Option<char>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GridState {
    rows: Vec<Vec<CellState>>,
    cursor: CursorState,
    saved: Option<CursorState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CellState {
    c: char,
    fg: AnsiColor,
    bg: AnsiColor,
    flags: u16,
    zerowidth: Vec<char>,
    underline: Option<AnsiColor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorState {
    line: i32,
    column: usize,
    waits_to_wrap: bool,
    pen: CellState,
    charsets: [bool; 4],
}

fn cell_state(cell: &AlacrittyCell) -> CellState {
    CellState {
        c: cell.c,
        fg: cell.fg,
        bg: cell.bg,
        flags: cell.flags.bits(),
        zerowidth: cell.zerowidth().unwrap_or(&[]).to_vec(),
        underline: cell.underline_color(),
    }
}

fn cursor_state(cursor: &Cursor<AlacrittyCell>) -> CursorState {
    let special = |i| cursor.charsets[i] == StandardCharset::SpecialCharacterAndLineDrawing;
    CursorState {
        line: cursor.point.line.0,
        column: cursor.point.column.0,
        waits_to_wrap: cursor.input_needs_wrap,
        pen: cell_state(&cursor.template),
        charsets: [
            special(CharsetIndex::G0),
            special(CharsetIndex::G1),
            special(CharsetIndex::G2),
            special(CharsetIndex::G3),
        ],
    }
}

fn grid_state(grid: &Grid<AlacrittyCell>, with_saved: bool) -> GridState {
    GridState {
        rows: (0..grid.screen_lines())
            .map(|row| {
                let cells = &grid[Line(row as i32)];
                (0..grid.columns())
                    .map(|col| cell_state(&cells[Column(col)]))
                    .collect()
            })
            .collect(),
        cursor: cursor_state(&grid.cursor),
        saved: with_saved.then(|| cursor_state(&grid.saved_cursor)),
    }
}

pub(crate) fn snapshot(term: &mut Term<VoidListener>, tracked: &Tracked) -> StateSnapshot {
    let primary = term
        .mode()
        .contains(TermMode::ALT_SCREEN)
        .then(|| with_primary(term, |g| grid_state(g, false)));
    let colors = term.colors();
    let style = term.cursor_style();
    StateSnapshot {
        active: grid_state(term.grid(), true),
        primary,
        mode: term.mode().bits(),
        scroll_region: (tracked.scroll_region.start, tracked.scroll_region.end),
        active_charset: tracked.active_charset as u8,
        tabs: tracked.tabs.clone(),
        cursor_style: (style.shape as u8, style.blinking),
        colors: (0..=LAST_SETTABLE_COLOR)
            .map(|i| colors[i].map(|c| (c.r, c.g, c.b)))
            .collect(),
        last_input: tracked.last_input,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TerminalCore;
    use alacritty_terminal::term::test::TermSize;
    use alacritty_terminal::term::Config;
    use alacritty_terminal::vte::ansi::Processor;

    /// The client's scrollback, oldest line first.
    fn history(t: &TerminalCore) -> Vec<String> {
        let grid = t.term.grid();
        let n = grid.history_size() as i32;
        (1..=n)
            .rev()
            .map(|k| {
                let row = &grid[Line(-k)];
                (0..grid.columns()).map(|c| row[Column(c)].c).collect()
            })
            .collect()
    }

    /// Name the first place two snapshots differ, instead of printing both.
    fn first_difference(want: &StateSnapshot, got: &StateSnapshot) -> Option<String> {
        fn grid(name: &str, a: &GridState, b: &GridState) -> Option<String> {
            for (r, (ra, rb)) in a.rows.iter().zip(&b.rows).enumerate() {
                for (c, (ca, cb)) in ra.iter().zip(rb).enumerate() {
                    if ca != cb {
                        return Some(format!(
                            "{name} cell ({r},{c}): model {ca:?}, client {cb:?}"
                        ));
                    }
                }
            }
            if a.cursor != b.cursor {
                return Some(format!(
                    "{name} cursor: model {:?}, client {:?}",
                    a.cursor, b.cursor
                ));
            }
            if a.saved != b.saved {
                return Some(format!(
                    "{name} saved cursor: model {:?}, client {:?}",
                    a.saved, b.saved
                ));
            }
            None
        }
        if let Some(d) = grid("active", &want.active, &got.active) {
            return Some(d);
        }
        match (&want.primary, &got.primary) {
            (Some(a), Some(b)) => {
                if let Some(d) = grid("primary", a, b) {
                    return Some(d);
                }
            }
            (None, None) => {}
            _ => return Some("one is on the alternate screen, the other is not".into()),
        }
        let fields: [(&str, String, String); 7] = [
            (
                "mode",
                format!("{:?}", TermMode::from_bits_truncate(want.mode)),
                format!("{:?}", TermMode::from_bits_truncate(got.mode)),
            ),
            (
                "scroll region",
                format!("{:?}", want.scroll_region),
                format!("{:?}", got.scroll_region),
            ),
            (
                "active charset",
                format!("{:?}", want.active_charset),
                format!("{:?}", got.active_charset),
            ),
            (
                "tabs",
                format!("{:?}", want.tabs),
                format!("{:?}", got.tabs),
            ),
            (
                "cursor style",
                format!("{:?}", want.cursor_style),
                format!("{:?}", got.cursor_style),
            ),
            (
                "colors",
                format!("{:?}", want.colors),
                format!("{:?}", got.colors),
            ),
            (
                "last printed",
                format!("{:?}", want.last_input),
                format!("{:?}", got.last_input),
            ),
        ];
        fields
            .into_iter()
            .find(|(_, a, b)| a != b)
            .map(|(name, a, b)| format!("{name}: model {a}, client {b}"))
    }

    fn assert_same(case: &str, when: &str, model: &mut TerminalCore, client: &mut TerminalCore) {
        let (want, got) = (
            model.snapshot().expect("made to replay"),
            client.snapshot().expect("made to replay"),
        );
        if let Some(d) = first_difference(&want, &got) {
            panic!("[{case}] {when}: {d}");
        }
    }

    /// The model gets `seen`, then `dropped`; the client gets `seen`, then
    /// the model's replay. Both are then the same, the client's scrollback
    /// is what it was, and the same `live` bytes keep them the same -- and
    /// keep the model where a twin that never replayed is.
    fn differential(case: &str, cols: u16, rows: u16, seen: &[u8], dropped: &[u8], live: &[u8]) {
        let mut model = TerminalCore::with_replay(cols, rows);
        let mut twin = TerminalCore::with_replay(cols, rows);
        let mut client = TerminalCore::with_replay(cols, rows);
        for t in [&mut model, &mut twin] {
            t.feed(seen);
            t.feed(dropped);
        }
        client.feed(seen);
        let scrollback = history(&client);
        let replay = model.replay().expect("made to replay");
        client.feed(&replay);
        assert_eq!(
            history(&client),
            scrollback,
            "[{case}] the replay put nothing into the client's scrollback"
        );
        assert_same(case, "right after the replay", &mut model, &mut client);
        for t in [&mut model, &mut twin, &mut client] {
            t.feed(live);
        }
        assert_same(case, "after the live output", &mut model, &mut client);
        if let Some(d) = first_difference(
            &twin.snapshot().expect("made to replay"),
            &model.snapshot().expect("made to replay"),
        ) {
            panic!("[{case}] the replay changed the model: {d}");
        }
    }

    /// `differential` at every byte of `script` as the point the live
    /// output resumes, with the dropped part starting at the same point (a
    /// repaint and nothing lost), halfway there, and at the start.
    fn every_cut(name: &str, cols: u16, rows: u16, script: &[u8]) {
        for b in 0..=script.len() {
            for a in [b, b / 2, 0] {
                let case = format!("{name}, dropped {a}..{b}");
                differential(&case, cols, rows, &script[..a], &script[a..b], &script[b..]);
            }
        }
    }

    /// tmux on its outer terminal: the alternate screen, a region above a
    /// coloured status line, linefeeds at the region's bottom, attributes
    /// that later erases and text rely on, line drawing, a line that ends
    /// at the last column and goes on, the saved cursor.
    const TMUX: &[u8] = b"\x1b[?1049h\x1b[H\x1b[2J\x1b[1;9r\
\x1b[10;1H\x1b[30;42m[0] 0:bash*\x1b[K\x1b[39;49m\
\x1b[1;1H$ ls\r\n\x1b[34mdir\x1b[39m  \x1b[32mrun.sh\x1b[39m\r\n\
\x1b[9;1Hbottom line\n\rscrolled\n\ragain\
\x1b(0lqqqk\x1b(B box\r\n\
\x1b[3;1H\x1b[44m\x1b[K\x1b[31mred on blue\x1b[1m bold\x1b[22m\x1b[39;49m\
\x1b7\x1b[5;38Hend\x1b8x\
\x1b[6;1H\x1b[4mul\x1b[24m\x1b[?25l\x1b[?2004h\x1b[?1000h\x1b[?1006h";

    #[test]
    fn a_tmux_screen_replays_at_every_cut() {
        every_cut("tmux", 40, 10, TMUX);
    }

    /// A shell on the primary screen: output that scrolls into history, a
    /// line longer than the screen, wide and combining characters, a wide
    /// character that no longer fits at the end of a row, tabs, REP.
    const SHELL: &[u8] = b"one\r\ntwo\r\nthree\r\nfour\r\nfive\r\nsix\r\n\
\x1b[1;32muser\x1b[0m:\x1b[34m~\x1b[0m$ \
a line that is longer than the twenty-four columns\r\n\
wide \xe4\xbd\xa0\xe5\xa5\xbd e\xcc\x81 done\r\n\
xxxxxxxxxxxxxxxxxxxxxxx\xe4\xbd\xa0 wrapped\r\n\
a\tb\tc\r\n\
-\x1b[9b\r\n\
\x1b[7mprompt\x1b[27m$ ";

    #[test]
    fn a_shell_on_the_primary_screen_replays_at_every_cut() {
        every_cut("shell", 24, 6, SHELL);
    }

    /// A full-screen program on the alternate screen over a shell, leaving
    /// it again: the primary screen and its cursor come back from under the
    /// alternate one.
    const VIM: &[u8] = b"$ cat notes\r\nfirst\r\nsecond\r\n$ vim\
\x1b[?1049h\x1b[?1h\x1b=\x1b[H\x1b[2J~\r\n~\r\n\x1b[1;1Hhello\x1b[4;1H\x1b[7m-- INSERT --\x1b[27m\
\x1b[1;6H there\
\x1b[?1l\x1b>\x1b[?1049l\r\n$ ";

    #[test]
    fn leaving_the_alternate_screen_after_a_replay_restores_the_shell() {
        every_cut("vim", 20, 5, VIM);
    }

    /// Everything else a later byte is read against: SO/SI with G1, the
    /// palette, tab stops, insert mode, LNM, autowrap off, origin mode in a
    /// region, the cursor style, a synchronized update, a title (an OSC the
    /// replay has to re-open when cut inside it).
    const MODES: &[u8] = b"\x1b)0\x0elqk\x0f text\r\n\
\x1b]4;1;rgb:12/34/56\x07\x1b]11;rgb:10/10/10\x07\x1b[31mred\x1b[0m\r\n\
\x1b[3g\x1b[1;5H\x1bH\x1b[1;11H\x1bH\r\ta\tb\r\n\
\x1b[4hins\x1b[4l \x1b[20hlnm\n\x1b[20l\
\x1b[?7lno wrap past the end of this row\x1b[?7h\r\n\
\x1b[2;4r\x1b[?6h\x1b[2;2Hin region\x1b[?6l\x1b[r\
\x1b[5 q\x1b[?2026hsync\x1b[?2026l\x1b]0;a title\x07\x1b[6 q";

    #[test]
    fn modes_charsets_palette_and_tabs_replay_at_every_cut() {
        every_cut("modes", 20, 5, MODES);
    }

    /// Spec §12: the cut in the middle of an escape sequence and of a UTF-8
    /// character, as the brief put them.
    #[test]
    fn a_cut_inside_a_sequence_or_a_character_replays() {
        differential(
            "cut inside a CSI",
            40,
            10,
            b"\x1b[2J\x1b[Hbefore the gate closed\x1b[3",
            b"1mdropped while the gate was closed\x1b[0m",
            b" and after",
        );
        differential(
            "cut inside UTF-8",
            40,
            10,
            b"\x1b[2J\x1b[Hprice: \xE2\x82",
            b"\xAC and more",
            b" after",
        );
        differential("repaint inside a CSI", 40, 10, b"a\x1b[3", b"", b"1mred");
        differential(
            "repaint inside DECSTBM",
            40,
            10,
            b"a\x1b[2;",
            b"",
            b"4r\x1b[4Hx\n\ny",
        );
        differential(
            "repaint inside a designation",
            40,
            10,
            b"a\x1b(",
            b"",
            b"0qqq\x1b(Bq",
        );
        differential("repaint inside UTF-8", 40, 10, b"a\xe4\xbd", b"", b"\xa0b");
    }

    /// Re-review, Minor 2: the last printed character (what `CSI b`
    /// repeats) when the cursor waits at the last column over a cell that
    /// is not it -- DECSC over a pending wrap, printing elsewhere, DECRC; and
    /// a wide character refused at the last column with autowrap off.
    #[test]
    fn the_last_printed_character_replays_when_the_cursor_waits_elsewhere() {
        let decrc: &[u8] = b"\x1b[2;1H01234567890123456789\x1b7\x1b[4;1Hy\x1b8";
        every_cut(
            "DECRC over a pending wrap",
            20,
            5,
            &[decrc, b"\x1b[2b z"].concat(),
        );
        let refused: &[u8] = b"ab\x1b[?7l\x1b[1;20H\xe4\xbd\xa0";
        every_cut(
            "a wide character refused at the last column",
            20,
            5,
            &[refused, b"\x1b[?7h\x1b[2b"].concat(),
        );
        let refused_then_on: &[u8] = b"ab\x1b[?7l\x1b[1;20H\xe4\xbd\xa0\x1b[?7h";
        differential(
            "refused, autowrap back on",
            20,
            5,
            refused_then_on,
            b"",
            b"\x1b[2b",
        );
    }

    /// A resize that leaves the cursor waiting at the last column over a
    /// blank -- `a`, the cursor moved to the last of 4 columns, 3 columns --
    /// keeps `a` as the character `CSI b` repeats; so does the client.
    #[test]
    fn a_cursor_a_resize_left_waiting_keeps_the_last_printed_character() {
        for zero_width in [false, true] {
            let prefix: &[u8] = if zero_width {
                b"a\xcc\x81\x1b[1;4H"
            } else {
                b"a\x1b[1;4H"
            };
            let mut model = TerminalCore::with_replay(4, 3);
            let mut client = TerminalCore::with_replay(4, 3);
            for t in [&mut model, &mut client] {
                t.feed(prefix);
                t.resize(3, 3);
            }
            assert!(
                model.term.grid().cursor.input_needs_wrap,
                "the case at hand"
            );
            client.feed(&model.replay().expect("made to replay"));
            assert_same("resize", "right after the replay", &mut model, &mut client);
            for t in [&mut model, &mut client] {
                t.feed(b"\x1b[2b");
            }
            assert_same("resize", "after REP", &mut model, &mut client);
        }
    }

    /// Re-review, Minor 1: a region only clamping made -- asked for past the
    /// screen's bottom -- is written in a form the client accepts and clamps
    /// to the same region, and linefeeds at the bottom scroll the same.
    #[test]
    fn a_region_reached_only_by_clamping_replays() {
        for (name, region) in [
            ("CSI 10;40r", b"\x1b[10;40r" as &[u8]),
            ("CSI 30;40r", b"\x1b[30;40r"),
        ] {
            let seen: &[u8] = b"first\r\nsecond\r\n";
            let live: &[u8] = b"\x1b[10;1Hbottom\nnext\n\x1b[9;1Hup\n\n";
            differential(name, 20, 10, seen, region, live);
            let script = [seen, region, live].concat();
            every_cut(name, 20, 10, &script);
        }
    }

    /// A core made the ordinary way tracks nothing and has no replay: the
    /// app and the console client feed the `Term` directly.
    #[test]
    fn only_a_core_made_to_replay_has_a_replay() {
        let mut plain = TerminalCore::new(10, 3);
        plain.feed(b"text\x1b[2;3r");
        assert!(plain.replay.is_none());
        assert!(plain.replay().is_none());
        assert!(plain.snapshot().is_none());
        assert!(TerminalCore::with_replay(10, 3).replay().is_some());
    }

    /// The tracking handler passes every call through: a `Term` fed through
    /// it and one fed directly end the same.
    #[test]
    fn the_tracking_handler_changes_nothing_the_term_does() {
        for script in [TMUX, SHELL, VIM, MODES] {
            let mut core = TerminalCore::with_replay(30, 8);
            core.feed(script);
            let mut term = Term::new(Config::default(), &TermSize::new(30, 8), VoidListener);
            Processor::<alacritty_terminal::vte::ansi::StdSyncHandler>::new()
                .advance(&mut term, script);
            assert_eq!(
                grid_state(core.term.grid(), true),
                grid_state(term.grid(), true)
            );
            assert_eq!(core.term.mode(), term.mode());
        }
    }

    /// Part 2 of the fix round: on the primary screen the replay rewrites
    /// the rows in place, so a client with scrollback keeps exactly the
    /// scrollback it had.
    #[test]
    fn a_replay_on_the_primary_screen_adds_no_scrollback() {
        let mut model = TerminalCore::with_replay(20, 4);
        let mut client = TerminalCore::with_replay(20, 4);
        let lines: Vec<u8> = (0..12)
            .flat_map(|i| format!("line {i}\r\n").into_bytes())
            .collect();
        model.feed(&lines);
        client.feed(&lines);
        model.feed(b"more\r\nand more\r\n");
        let before = history(&client);
        assert!(!before.is_empty());
        client.feed(&model.replay().expect("made to replay"));
        assert_eq!(history(&client), before);
        client.feed(&model.replay().expect("made to replay"));
        assert_eq!(history(&client), before, "a second replay neither");
    }
}
