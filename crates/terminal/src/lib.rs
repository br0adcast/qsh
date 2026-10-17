//! Terminal core built on `alacritty_terminal`.
//!
//! This module's job is to wrap a mature emulator: take a byte stream from
//! the remote shell, run it through the VT sequence parser, and update the
//! screen grid and cursor. What it exposes: `new`/`feed` (input), `resize`
//! (window size change), and `frame` (a snapshot of the visible grid for
//! rendering - characters, colors kept as the application meant them plus a
//! palette snapshot to resolve them, attributes, cursor).

use std::sync::Arc;

mod replay;
mod tracking;

pub use replay::StateSnapshot;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags as CellFlags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::test::TermSize;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color as AnsiColor, NamedColor, Processor, Rgb};

/// Cell flag: bold text.
pub const FLAG_BOLD: u16 = 0b0001;
/// Cell flag: underline (any of alacritty's variants - single, double,
/// curly, dotted, dashed).
pub const FLAG_UNDERLINE: u16 = 0b0010;
/// Cell flag: foreground/background color inversion (reverse video).
pub const FLAG_REVERSE: u16 = 0b0100;
/// Cell flag: italic.
pub const FLAG_ITALIC: u16 = 0b1000;
/// Cell flag: the leading cell of a double-width character. A renderer
/// prints it and then SKIPS the following spacer cell -- printing both would
/// shift the rest of the row one column to the right.
pub const FLAG_WIDE: u16 = 0b0001_0000;
/// Cell flag: the TRAILING spacer -- the second column occupied by a
/// double-width character. It carries no character of its own: the wide cell
/// to its left already painted both columns, so a renderer must skip it.
pub const FLAG_WIDE_SPACER: u16 = 0b0010_0000;
/// Cell flag: the LEADING spacer -- the placeholder the emulator puts in the
/// last column of a row when a double-width character does not fit there and
/// wraps to the next row.
///
/// It must NOT be confused with `FLAG_WIDE_SPACER`: no wide character stands
/// to its left, and nothing else ever paints this position. A renderer that
/// skips it (as it rightly skips the trailing spacer) never draws the cell at
/// all, so its background and attributes never reach the screen and whatever
/// was there before stays visible. Treat it as an ordinary one-column cell:
/// print its blank with its own colors.
pub const FLAG_LEADING_WIDE_SPACER: u16 = 0b0100_0000;

/// Faint (SGR 2). Set only by the console client's own chrome, never by the emulator.
pub const FLAG_DIM: u16 = 0b1000_0000;

/// A cell color exactly as the application asked for it. Resolving it into
/// concrete RGB is the consumer's job: a client that draws into SOMEONE
/// ELSE'S terminal must keep an indexed color indexed, otherwise it would
/// override the user's theme with our palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// The terminal's default foreground/background.
    Default,
    /// Palette entry `0..=255`.
    Indexed(u8),
    /// A direct 24-bit color, packed as `0x00RRGGBB`.
    Rgb(u32),
}

/// A snapshot of the emulator's palette, carried by every frame. Whoever
/// needs concrete RGB (such as a renderer behind the FFI) resolves through
/// it, so palette overrides (OSC 4) keep working exactly as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    /// 256 palette entries, `0x00RRGGBB` each.
    pub entries: [u32; 256],
    /// Default foreground and background of the terminal.
    pub default_fg: u32,
    pub default_bg: u32,
}

impl Palette {
    /// Resolve a color into `0x00RRGGBB`; `is_fg` picks which default applies.
    pub fn resolve(&self, color: Color, is_fg: bool) -> u32 {
        match color {
            Color::Default => {
                if is_fg {
                    self.default_fg
                } else {
                    self.default_bg
                }
            }
            Color::Indexed(i) => self.entries[i as usize],
            Color::Rgb(v) => v,
        }
    }

    /// The standard xterm palette with no terminal overrides -- for frames
    /// built by hand (tests, `Frame::blank`).
    pub fn xterm_default() -> Palette {
        let mut entries = [0u32; 256];
        for (i, slot) in entries.iter_mut().enumerate() {
            *slot = rgb_to_u32(default_indexed_rgb(i as u8));
        }
        Palette {
            entries,
            default_fg: rgb_to_u32(default_named_rgb(NamedColor::Foreground)),
            default_bg: rgb_to_u32(default_named_rgb(NamedColor::Background)),
        }
    }
}

/// Mouse tracking level the application asked for. The client mirrors this
/// onto the user's real terminal, so it must be the exact level: mirroring
/// "any tracking" as motion tracking would flood an application that only
/// asked for clicks with events it never requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MouseTracking {
    /// No tracking (`?1000l`/`?1002l`/`?1003l`).
    #[default]
    Off,
    /// Press/release only (`?1000h`).
    Click,
    /// Press/release plus motion while a button is held (`?1002h`).
    Drag,
    /// Any motion (`?1003h`).
    Motion,
}

/// One frame cell: a character, foreground/background colors (kept as the
/// application meant them -- see `Color`), and attributes (see the `FLAG_*`
/// constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
    pub flags: u16,
}

impl Cell {
    /// Blank cell: a space with default colors/attributes.
    pub fn blank() -> Cell {
        Cell {
            ch: ' ',
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        }
    }

    /// Whether the cell is blank (space or NUL). Port of mosh's
    /// `Cell::is_blank` - prediction gives no "credit" for matching a blank cell.
    pub fn is_blank(&self) -> bool {
        self.ch == ' ' || self.ch == '\0'
    }

    /// Whether the CONTENTS (character) of two cells match, ignoring
    /// colors/attributes. Port of mosh's `Cell::contents_match`: prediction
    /// validity is decided by the character, while colors are copied separately.
    pub fn contents_match(&self, other: &Cell) -> bool {
        self.ch == other.ch
    }
}

/// A snapshot of the terminal's visible grid: cells in row-major order (row
/// by row, left to right within a row) plus cursor position and visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub cols: u16,
    pub rows: u16,
    /// Length is always `cols * rows`.
    pub cells: Vec<Cell>,
    pub cursor_col: u16,
    pub cursor_row: u16,
    pub cursor_visible: bool,
    /// Application cursor key mode (DECCKM). When set (by vim, htop,
    /// ncurses, etc.), arrow keys must be encoded as SS3 (`ESC O A`) rather
    /// than CSI (`ESC [ A`) - the platform encodes input based on this flag.
    pub app_cursor: bool,
    /// Application keypad mode (DECKPAM). Affects how numeric keypad keys
    /// are encoded - the platform likewise uses it to encode input.
    pub app_keypad: bool,
    /// Origin mode (DECOM). When set, cursor prediction is unreliable (the
    /// coordinate system is offset by the scroll region) and is skipped.
    pub origin_mode: bool,
    /// Mouse tracking level requested by the application.
    pub mouse_tracking: MouseTracking,
    /// SGR-format mouse coordinate encoding (`ESC [ ? 1006 h`). Affects how
    /// the client encodes mouse events when `mouse_tracking` is on.
    pub mouse_sgr: bool,
    /// Bracketed paste (`ESC [ ? 2004 h`): the application wants pasted text
    /// wrapped in markers, so the client mirrors the mode onto the local
    /// terminal and the markers arrive from it for free.
    pub bracketed_paste: bool,
    /// Alternate screen (`ESC [ ? 1049 h`), used by full-screen applications
    /// (vim, less). Useful for deciding where to route scrolling.
    pub alt_screen: bool,
    /// Palette snapshot for consumers that need concrete RGB.
    pub palette: Arc<Palette>,
}

/// The emulator core: the `Term` screen grid plus the `Processor` control
/// sequence parser. We don't emit events outward - the `VoidListener`
/// listener swallows them (bell, title change, and the rest aren't needed yet).
pub struct TerminalCore {
    term: Term<VoidListener>,
    parser: Processor,
    /// Only in a core made to replay itself ([`TerminalCore::with_replay`]):
    /// the daemon's model of a screen. Everywhere else -- the app, the
    /// console client -- the parser drives the `Term` directly, as it always
    /// did, and pays nothing for it.
    replay: Option<ReplayState>,
    history_limit: usize,
}

/// What a replay needs on top of the `Term` (see `tracking`).
struct ReplayState {
    /// What `Term` and the parser keep privately and a replay restores.
    tracked: tracking::Tracked,
    /// The escape sequence the input has begun and not finished.
    pending: tracking::PendingSequence,
}

impl TerminalCore {
    /// Creates a terminal of size `cols` by `rows` (columns by rows).
    pub fn new(cols: u16, rows: u16) -> Self {
        // `TermSize` implements the `Dimensions` trait that `Term::new` expects.
        let size = TermSize::new(cols as usize, rows as usize);
        let term = Term::new(Config::default(), &size, VoidListener);
        Self {
            term,
            parser: Processor::new(),
            replay: None,
            history_limit: 10_000,
        }
    }

    /// Sets the primary screen's history capacity, including zero to disable it.
    pub fn set_history_limit(&mut self, lines: usize) {
        self.history_limit = lines;
        self.term.set_options(Config {
            scrolling_history: lines,
            ..Config::default()
        });
    }

    /// Discards history on both screens without blanking the visible grid.
    pub fn clear_history(&mut self) {
        let limit = self.history_limit;
        self.set_history_limit(0);
        self.set_history_limit(limit);
        self.scroll_to_bottom();
    }

    /// The number of retained lines above the visible screen.
    pub fn history_size(&self) -> usize {
        self.term.grid().history_size()
    }

    /// A terminal like [`TerminalCore::new`] that can also answer
    /// [`TerminalCore::replay`]: it tracks, alongside the `Term`, the state
    /// the `Term` keeps privately and the escape sequence its input stopped
    /// in. That costs some time on every `feed`, which only the daemon's
    /// model of a screen needs to pay.
    pub fn with_replay(cols: u16, rows: u16) -> Self {
        Self {
            replay: Some(ReplayState {
                tracked: tracking::Tracked::new(cols as usize, rows as usize),
                pending: tracking::PendingSequence::default(),
            }),
            ..Self::new(cols, rows)
        }
    }

    /// Feeds bytes to the parser: printable characters land in the grid,
    /// while control sequences move the cursor and change modes.
    pub fn feed(&mut self, bytes: &[u8]) {
        // In vte 0.15, `advance` takes the whole slice at once, not byte by byte.
        match &mut self.replay {
            None => self.parser.advance(&mut self.term, bytes),
            Some(replay) => {
                replay.pending.push(bytes);
                self.parser.advance(
                    &mut tracking::Tracking {
                        term: &mut self.term,
                        tracked: &mut replay.tracked,
                    },
                    bytes,
                );
            }
        }
    }

    /// Changes the terminal size (columns by rows), e.g. on screen rotation
    /// or a window resize on the client side.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let size = TermSize::new(cols as usize, rows as usize);
        match &mut self.replay {
            None => self.term.resize(size),
            Some(replay) => {
                let (old_cols, old_rows) = (self.term.columns(), self.term.screen_lines());
                self.term.resize(size);
                replay
                    .tracked
                    .resize(old_cols, old_rows, cols as usize, rows as usize);
            }
        }
    }

    /// Bytes that bring another emulator of the same size to this one's
    /// state: both screens, the cursor, the pen, every mode and the rest of
    /// what the bytes after them are read against -- and the escape sequence
    /// this one's input stopped in the middle of, if any, so the next bytes
    /// finish it on both sides. The other emulator may have seen any prefix
    /// of this one's input and nothing since; its scrollback is left as it
    /// was. See the `replay` module for what is restored and what is not.
    ///
    /// A synchronized update this emulator is holding back is applied first:
    /// its bytes are already part of the state the other one must reach.
    ///
    /// `None` from a core not made [`TerminalCore::with_replay`].
    pub fn replay(&mut self) -> Option<Vec<u8>> {
        let replay = self.replay.as_mut()?;
        if self.parser.sync_timeout().sync_timeout().is_some() {
            self.parser.stop_sync(&mut tracking::Tracking {
                term: &mut self.term,
                tracked: &mut replay.tracked,
            });
        }
        Some(replay::write(
            &mut self.term,
            &replay.tracked,
            replay.pending.tail(),
        ))
    }

    /// Everything [`TerminalCore::replay`] restores, to compare two
    /// emulators by; `None` from a core not made
    /// [`TerminalCore::with_replay`].
    pub fn snapshot(&mut self) -> Option<StateSnapshot> {
        let replay = self.replay.as_ref()?;
        Some(replay::snapshot(&mut self.term, &replay.tracked))
    }

    /// Shifts the history view by `delta_lines` lines. A positive `delta`
    /// goes into the past (older lines), a negative one goes back toward
    /// the live bottom. An empty history (little output) doesn't panic -
    /// `scroll_display` itself clamps the offset to the buffered range.
    pub fn scroll(&mut self, delta_lines: i32) {
        let target = self.display_offset() as i64 + i64::from(delta_lines);
        let scroll = if target <= 0 {
            Scroll::Bottom
        } else if target >= self.history_size() as i64 {
            Scroll::Top
        } else {
            Scroll::Delta(delta_lines)
        };
        self.term.scroll_display(scroll);
    }

    /// Returns the view to the live bottom (resets the history offset).
    pub fn scroll_to_bottom(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
    }

    /// Current history view offset (0 = live bottom, increasing towards the top of the buffer).
    pub fn display_offset(&self) -> usize {
        self.term.grid().display_offset()
    }

    /// Captures the current state of the visible grid: characters, colors
    /// (kept as the application meant them, see `Color`), attributes, and
    /// the cursor. A blank cell is a space with default colors (that's how
    /// `alacritty_terminal` itself reports them).
    ///
    /// Takes `display_offset` into account: when the view is scrolled into
    /// history, grid rows are read with an offset (`Line` goes negative -
    /// `Index<Line>` supports indexing into history), and the cursor is
    /// hidden, since it makes no sense in a historical frame (the cursor
    /// always lives at the live bottom).
    pub fn frame(&self) -> Frame {
        let cols = self.term.columns() as u16;
        let rows = self.term.screen_lines() as u16;
        let colors = self.term.colors();
        let offset = self.term.grid().display_offset();

        let mut cells = Vec::with_capacity(cols as usize * rows as usize);
        for row in 0..rows {
            for col in 0..cols {
                let point = Point::new(Line(row as i32 - offset as i32), Column(col as usize));
                let cell = &self.term.grid()[point];
                cells.push(Cell {
                    ch: cell.c,
                    fg: convert_color(cell.fg, colors),
                    bg: convert_color(cell.bg, colors),
                    flags: convert_flags(cell.flags),
                });
            }
        }

        // Input modes are read from the emulator's state: the platform
        // encodes keypresses based on them (see the `app_cursor`/`app_keypad` fields).
        let mode = self.term.mode();

        // The cursor is derived here rather than taken from
        // `renderable_content()`. alacritty's `RenderableCursor::new` does
        // the same two things -- backs the cursor off the trailing spacer of
        // a wide character onto the character itself, and reports it hidden
        // when DECTCEM turned it off -- but backs up without checking that a
        // column exists to back up to. `ESC [ P` on a wide character in
        // column 0 leaves its spacer orphaned there with the cursor on it:
        // an underflow (a panic in a debug build, column 65535 in a release
        // one). Vi mode, the only other input to that derivation, is never
        // enabled here, and no escape can set `CursorShape::Hidden` as a
        // style, so `Hidden` means exactly `!SHOW_CURSOR`.
        let mut cursor = self.term.grid().cursor.point;
        if cursor.column > 0
            && self.term.grid()[cursor]
                .flags
                .contains(CellFlags::WIDE_CHAR_SPACER)
        {
            cursor.column -= 1;
        }
        // On top of that the cursor is hidden while the view is scrolled
        // into history - there's nowhere to draw it there (mosh uses the
        // same logic: the cursor only lives at the bottom).
        let cursor_visible = offset == 0 && mode.contains(TermMode::SHOW_CURSOR);
        let cursor_col = cursor.column.0 as u16;
        let cursor_row = cursor.line.0 as u16;
        let app_cursor = mode.contains(TermMode::APP_CURSOR);
        let app_keypad = mode.contains(TermMode::APP_KEYPAD);
        let origin_mode = mode.contains(TermMode::ORIGIN);
        // The tracking level is a ladder: motion implies drag implies click,
        // so report the highest one the application turned on.
        let mouse_tracking = if mode.contains(TermMode::MOUSE_MOTION) {
            MouseTracking::Motion
        } else if mode.contains(TermMode::MOUSE_DRAG) {
            MouseTracking::Drag
        } else if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
            MouseTracking::Click
        } else {
            MouseTracking::Off
        };
        let bracketed_paste = mode.contains(TermMode::BRACKETED_PASTE);
        let mouse_sgr = mode.contains(TermMode::SGR_MOUSE);
        let alt_screen = mode.contains(TermMode::ALT_SCREEN);

        Frame {
            cols,
            rows,
            cells,
            cursor_col,
            cursor_row,
            cursor_visible,
            app_cursor,
            app_keypad,
            origin_mode,
            mouse_tracking,
            mouse_sgr,
            bracketed_paste,
            alt_screen,
            palette: Arc::new(snapshot_palette(colors)),
        }
    }
}

impl Frame {
    /// A blank frame of the given size: spaces with default colors, cursor at
    /// the top-left, every mode off, standard palette. Hand-built frames
    /// (tests, the renderer's "nothing drawn yet" state) start here, so
    /// adding a field to `Frame` doesn't ripple through every call site.
    pub fn blank(cols: u16, rows: u16) -> Frame {
        Frame {
            cols,
            rows,
            cells: vec![Cell::blank(); cols as usize * rows as usize],
            cursor_col: 0,
            cursor_row: 0,
            cursor_visible: true,
            app_cursor: false,
            app_keypad: false,
            origin_mode: false,
            mouse_tracking: MouseTracking::Off,
            mouse_sgr: false,
            bracketed_paste: false,
            alt_screen: false,
            palette: Arc::new(Palette::xterm_default()),
        }
    }

    /// Grid width in columns.
    pub fn width(&self) -> u16 {
        self.cols
    }

    /// Grid height in rows.
    pub fn height(&self) -> u16 {
        self.rows
    }

    /// The `(row, col)` cell of the visible grid (row-major). Indices must
    /// be within `height()`/`width()` - the caller (prediction) has already
    /// validated them.
    pub fn cell(&self, row: u16, col: u16) -> &Cell {
        &self.cells[row as usize * self.cols as usize + col as usize]
    }

    /// Mutable `(row, col)` cell - for overlaying a prediction onto a copy of the frame.
    pub fn cell_mut(&mut self, row: u16, col: u16) -> &mut Cell {
        &mut self.cells[row as usize * self.cols as usize + col as usize]
    }
}

/// Converts alacritty's cell flags into our compact outward bitflag. Combined
/// variants (`BOLD_ITALIC`, `ALL_UNDERLINES`) are checked bit by bit -
/// `contains`/`intersects` look at a specific bit, not an exact match of the
/// whole mask.
fn convert_flags(flags: CellFlags) -> u16 {
    let mut result = 0u16;
    if flags.contains(CellFlags::BOLD) {
        result |= FLAG_BOLD;
    }
    if flags.intersects(CellFlags::ALL_UNDERLINES) {
        result |= FLAG_UNDERLINE;
    }
    if flags.contains(CellFlags::INVERSE) {
        result |= FLAG_REVERSE;
    }
    if flags.contains(CellFlags::ITALIC) {
        result |= FLAG_ITALIC;
    }
    if flags.contains(CellFlags::WIDE_CHAR) {
        result |= FLAG_WIDE;
    }
    // The two spacers are kept apart on purpose: only the trailing one is
    // already painted by the wide character to its left. See the doc comment
    // on `FLAG_LEADING_WIDE_SPACER`.
    if flags.contains(CellFlags::WIDE_CHAR_SPACER) {
        result |= FLAG_WIDE_SPACER;
    }
    if flags.contains(CellFlags::LEADING_WIDE_CHAR_SPACER) {
        result |= FLAG_LEADING_WIDE_SPACER;
    }
    result
}

/// Convert a cell color into our `Color`, keeping the application's intent:
/// palette indices stay indices, the default stays the default. Named colors
/// with no palette slot of their own (cursor, dim/bright variants) are
/// resolved through the palette right here -- they are rare and have no
/// portable representation.
fn convert_color(color: AnsiColor, colors: &Colors) -> Color {
    match color {
        AnsiColor::Spec(rgb) => Color::Rgb(rgb_to_u32(rgb)),
        AnsiColor::Indexed(index) => Color::Indexed(index),
        AnsiColor::Named(NamedColor::Foreground) | AnsiColor::Named(NamedColor::Background) => {
            Color::Default
        }
        AnsiColor::Named(named) if (named as usize) < 16 => Color::Indexed(named as u8),
        AnsiColor::Named(named) => Color::Rgb(rgb_to_u32(
            colors[named].unwrap_or_else(|| default_named_rgb(named)),
        )),
    }
}

/// Snapshot the emulator's palette: every entry the terminal overrode
/// (OSC 4) wins, the rest fall back to the standard xterm values -- exactly
/// the resolution the FFI used to do inline.
fn snapshot_palette(colors: &Colors) -> Palette {
    let mut entries = [0u32; 256];
    for (i, slot) in entries.iter_mut().enumerate() {
        *slot = rgb_to_u32(colors[i].unwrap_or_else(|| default_indexed_rgb(i as u8)));
    }
    Palette {
        entries,
        default_fg: rgb_to_u32(
            colors[NamedColor::Foreground]
                .unwrap_or_else(|| default_named_rgb(NamedColor::Foreground)),
        ),
        default_bg: rgb_to_u32(
            colors[NamedColor::Background]
                .unwrap_or_else(|| default_named_rgb(NamedColor::Background)),
        ),
    }
}

/// Packs an `Rgb` into `0x00RRGGBB`.
fn rgb_to_u32(rgb: Rgb) -> u32 {
    (u32::from(rgb.r) << 16) | (u32::from(rgb.g) << 8) | u32::from(rgb.b)
}

/// Default RGB palette for the base 16 named colors and for the
/// background/foreground/cursor - modeled after the standard xterm palette.
fn default_named_rgb(named: NamedColor) -> Rgb {
    match named {
        NamedColor::Black => Rgb {
            r: 0x00,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::Red => Rgb {
            r: 0xcd,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::Green => Rgb {
            r: 0x00,
            g: 0xcd,
            b: 0x00,
        },
        NamedColor::Yellow => Rgb {
            r: 0xcd,
            g: 0xcd,
            b: 0x00,
        },
        NamedColor::Blue => Rgb {
            r: 0x00,
            g: 0x00,
            b: 0xee,
        },
        NamedColor::Magenta => Rgb {
            r: 0xcd,
            g: 0x00,
            b: 0xcd,
        },
        NamedColor::Cyan => Rgb {
            r: 0x00,
            g: 0xcd,
            b: 0xcd,
        },
        NamedColor::White => Rgb {
            r: 0xe5,
            g: 0xe5,
            b: 0xe5,
        },
        NamedColor::BrightBlack => Rgb {
            r: 0x7f,
            g: 0x7f,
            b: 0x7f,
        },
        NamedColor::BrightRed => Rgb {
            r: 0xff,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::BrightGreen => Rgb {
            r: 0x00,
            g: 0xff,
            b: 0x00,
        },
        NamedColor::BrightYellow => Rgb {
            r: 0xff,
            g: 0xff,
            b: 0x00,
        },
        NamedColor::BrightBlue => Rgb {
            r: 0x5c,
            g: 0x5c,
            b: 0xff,
        },
        NamedColor::BrightMagenta => Rgb {
            r: 0xff,
            g: 0x00,
            b: 0xff,
        },
        NamedColor::BrightCyan => Rgb {
            r: 0x00,
            g: 0xff,
            b: 0xff,
        },
        NamedColor::BrightWhite => Rgb {
            r: 0xff,
            g: 0xff,
            b: 0xff,
        },
        NamedColor::DimBlack => Rgb {
            r: 0x00,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::DimRed => Rgb {
            r: 0x86,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::DimGreen => Rgb {
            r: 0x00,
            g: 0x86,
            b: 0x00,
        },
        NamedColor::DimYellow => Rgb {
            r: 0x86,
            g: 0x86,
            b: 0x00,
        },
        NamedColor::DimBlue => Rgb {
            r: 0x00,
            g: 0x00,
            b: 0x86,
        },
        NamedColor::DimMagenta => Rgb {
            r: 0x86,
            g: 0x00,
            b: 0x86,
        },
        NamedColor::DimCyan => Rgb {
            r: 0x00,
            g: 0x86,
            b: 0x86,
        },
        NamedColor::DimWhite => Rgb {
            r: 0x82,
            g: 0x82,
            b: 0x82,
        },
        NamedColor::Foreground | NamedColor::BrightForeground => Rgb {
            r: 0xff,
            g: 0xff,
            b: 0xff,
        },
        NamedColor::DimForeground => Rgb {
            r: 0x82,
            g: 0x82,
            b: 0x82,
        },
        NamedColor::Background => Rgb {
            r: 0x00,
            g: 0x00,
            b: 0x00,
        },
        NamedColor::Cursor => Rgb {
            r: 0xff,
            g: 0xff,
            b: 0xff,
        },
    }
}

/// Default RGB palette for indexed colors (`0..256`): `0..16` are the base
/// named colors, `16..232` are the 6x6x6 color cube, `232..256` are the
/// grayscale ramp. This is the standard terminal scheme (xterm-256color).
fn default_indexed_rgb(index: u8) -> Rgb {
    match index {
        0..=15 => default_named_rgb(named_color_for_low_index(index)),
        16..=231 => {
            let value = index - 16;
            let r = value / 36;
            let g = (value / 6) % 6;
            let b = value % 6;
            Rgb {
                r: cube_component(r),
                g: cube_component(g),
                b: cube_component(b),
            }
        }
        // 232..=255
        _ => {
            let level = 8 + 10 * (index - 232);
            Rgb {
                r: level,
                g: level,
                b: level,
            }
        }
    }
}

/// Maps a palette index `0..16` to its corresponding named color.
fn named_color_for_low_index(index: u8) -> NamedColor {
    match index {
        0 => NamedColor::Black,
        1 => NamedColor::Red,
        2 => NamedColor::Green,
        3 => NamedColor::Yellow,
        4 => NamedColor::Blue,
        5 => NamedColor::Magenta,
        6 => NamedColor::Cyan,
        7 => NamedColor::White,
        8 => NamedColor::BrightBlack,
        9 => NamedColor::BrightRed,
        10 => NamedColor::BrightGreen,
        11 => NamedColor::BrightYellow,
        12 => NamedColor::BrightBlue,
        13 => NamedColor::BrightMagenta,
        14 => NamedColor::BrightCyan,
        _ => NamedColor::BrightWhite,
    }
}

/// One channel of the 6x6x6 color cube (level `0..6`) converted to an 8-bit value.
fn cube_component(level: u8) -> u8 {
    if level == 0 {
        0
    } else {
        55 + 40 * level
    }
}

#[cfg(test)]
impl TerminalCore {
    /// Character at cell `(col, row)` of the visible area - for use in test assertions.
    fn cell_char(&self, col: u16, row: u16) -> char {
        use alacritty_terminal::index::{Column, Line, Point};
        let point = Point::new(Line(row as i32), Column(col as usize));
        self.term.grid()[point].c
    }

    /// Cursor position as `(col, row)` - the order matches `cell_char`.
    fn cursor(&self) -> (u16, u16) {
        let point = self.term.grid().cursor.point;
        (point.column.0 as u16, point.line.0 as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_puts_char_into_grid() {
        let mut t = TerminalCore::new(80, 24);
        t.feed(b"\x1b[HAB"); // cursor home, print A and B
        assert_eq!(t.cell_char(0, 0), 'A');
        assert_eq!(t.cell_char(1, 0), 'B');
        assert_eq!(t.cursor(), (2, 0));
    }

    #[test]
    fn frame_reports_chars_colors_cursor() {
        let mut t = TerminalCore::new(10, 3);
        t.feed(b"\x1b[H\x1b[31mR\x1b[0mX"); // red R, reset, X
        let f = t.frame();
        assert_eq!(f.cols, 10);
        assert_eq!(f.rows, 3);
        assert_eq!(f.cells[0].ch, 'R');
        assert_ne!(f.cells[0].fg, f.cells[1].fg); // R is colored, X is default
        assert_eq!(f.cells[1].ch, 'X');
        assert_eq!((f.cursor_col, f.cursor_row), (2, 0));
    }

    #[test]
    fn resize_changes_dims() {
        let mut t = TerminalCore::new(80, 24);
        t.resize(100, 40);
        let f = t.frame();
        assert_eq!((f.cols, f.rows), (100, 40));
        assert_eq!(f.cells.len(), 100 * 40);
    }

    #[test]
    fn frame_reports_application_key_modes() {
        let mut t = TerminalCore::new(10, 3);
        // Both modes are off by default.
        let f = t.frame();
        assert!(!f.app_cursor);
        assert!(!f.app_keypad);

        // DECCKM (ESC [ ? 1 h) enables application cursor keys.
        t.feed(b"\x1b[?1h");
        assert!(t.frame().app_cursor);

        // DECKPAM (ESC =) enables the application keypad.
        t.feed(b"\x1b=");
        assert!(t.frame().app_keypad);

        // DECCKM reset (ESC [ ? 1 l) turns cursor key mode back off.
        t.feed(b"\x1b[?1l");
        assert!(!t.frame().app_cursor);
    }

    #[test]
    fn bold_and_reverse_flags_set() {
        let mut t = TerminalCore::new(5, 1);
        t.feed(b"\x1b[1mB\x1b[0m\x1b[7mI");
        let f = t.frame();
        assert_ne!(f.cells[0].flags & 0x1, 0); // bold on 'B'
        assert_ne!(f.cells[1].flags & 0x4, 0); // reverse on 'I'
    }

    #[test]
    fn wide_characters_are_flagged_together_with_their_spacer() {
        let mut t = TerminalCore::new(10, 1);
        t.feed("日本".as_bytes());
        let f = t.frame();
        assert_eq!(f.cells[0].ch, '日');
        assert_ne!(f.cells[0].flags & FLAG_WIDE, 0, "leading cell must be wide");
        assert_ne!(
            f.cells[1].flags & FLAG_WIDE_SPACER,
            0,
            "the cell a wide character occupies must be marked as a spacer"
        );
        assert_eq!(f.cells[2].ch, '本');
        assert_ne!(f.cells[2].flags & FLAG_WIDE, 0);
        assert_ne!(f.cells[3].flags & FLAG_WIDE_SPACER, 0);
        // A plain ASCII cell carries neither flag.
        assert_eq!(f.cells[4].flags & (FLAG_WIDE | FLAG_WIDE_SPACER), 0);
        // Mid-row there is no leading spacer anywhere.
        assert!(
            f.cells
                .iter()
                .all(|c| c.flags & FLAG_LEADING_WIDE_SPACER == 0),
            "a wide character that fits produces no leading spacer"
        );
    }

    #[test]
    fn a_wide_character_that_does_not_fit_leaves_a_leading_spacer_in_the_last_column() {
        // Six columns are taken, the wide character needs two: it cannot fit,
        // so the emulator marks the last column as a placeholder and wraps.
        let mut t = TerminalCore::new(7, 2);
        t.feed("\x1b[44mabcdef\u{65e5}".as_bytes());
        let f = t.frame();

        let placeholder = f.cell(0, 6);
        assert_eq!(placeholder.ch, ' ');
        assert_ne!(
            placeholder.flags & FLAG_LEADING_WIDE_SPACER,
            0,
            "the last column must be marked as a leading spacer"
        );
        assert_eq!(
            placeholder.flags & FLAG_WIDE_SPACER,
            0,
            "a leading spacer is not the trailing half of a wide character"
        );
        assert_eq!(
            placeholder.bg,
            Color::Indexed(4),
            "the placeholder carries the background in force when it was made"
        );

        // The wide character itself landed on the next row, with its own
        // TRAILING spacer beside it.
        assert_eq!(f.cell(1, 0).ch, '\u{65e5}');
        assert_ne!(f.cell(1, 0).flags & FLAG_WIDE, 0);
        assert_ne!(f.cell(1, 1).flags & FLAG_WIDE_SPACER, 0);
        assert_eq!(f.cell(1, 1).flags & FLAG_LEADING_WIDE_SPACER, 0);
    }

    #[test]
    fn frame_reports_origin_mode() {
        let mut t = TerminalCore::new(10, 3);
        assert!(!t.frame().origin_mode);
        // DECOM set (ESC [ ? 6 h) enables origin mode.
        t.feed(b"\x1b[?6h");
        assert!(t.frame().origin_mode);
        // DECOM reset (ESC [ ? 6 l) turns it back off.
        t.feed(b"\x1b[?6l");
        assert!(!t.frame().origin_mode);
    }

    #[test]
    fn frame_reports_mouse_and_alt_screen_modes() {
        let mut t = TerminalCore::new(10, 3);
        // All three modes are off by default.
        let f = t.frame();
        assert_eq!(f.mouse_tracking, MouseTracking::Off);
        assert!(!f.mouse_sgr);
        assert!(!f.alt_screen);

        // Mouse click mode (ESC [ ? 1000 h) enables mouse tracking.
        t.feed(b"\x1b[?1000h");
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Click);

        // SGR mouse encoding (ESC [ ? 1006 h) enables mouse_sgr.
        t.feed(b"\x1b[?1006h");
        assert!(t.frame().mouse_sgr);

        // Alternate screen (ESC [ ? 1049 h) enables alt_screen.
        t.feed(b"\x1b[?1049h");
        assert!(t.frame().alt_screen);

        // Resetting each mode (ESC [ ? N l) clears the corresponding flag.
        t.feed(b"\x1b[?1000l");
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Off);
        t.feed(b"\x1b[?1006l");
        assert!(!t.frame().mouse_sgr);
        t.feed(b"\x1b[?1049l");
        assert!(!t.frame().alt_screen);
    }

    #[test]
    fn frame_reports_the_exact_mouse_tracking_level() {
        let mut t = TerminalCore::new(10, 1);
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Off);
        t.feed(b"\x1b[?1000h");
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Click);
        t.feed(b"\x1b[?1002h");
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Drag);
        t.feed(b"\x1b[?1003h");
        assert_eq!(t.frame().mouse_tracking, MouseTracking::Motion);
    }

    #[test]
    fn frame_reports_bracketed_paste() {
        let mut t = TerminalCore::new(10, 1);
        assert!(!t.frame().bracketed_paste);
        t.feed(b"\x1b[?2004h");
        assert!(t.frame().bracketed_paste);
        t.feed(b"\x1b[?2004l");
        assert!(!t.frame().bracketed_paste);
    }

    #[test]
    fn frame_cell_accessor_and_dims() {
        let mut t = TerminalCore::new(10, 3);
        t.feed(b"\x1b[HAB");
        let f = t.frame();
        assert_eq!(f.width(), 10);
        assert_eq!(f.height(), 3);
        assert_eq!(f.cell(0, 0).ch, 'A');
        assert_eq!(f.cell(0, 1).ch, 'B');
    }

    #[test]
    fn history_scroll_round_trip_and_cursor() {
        let mut t = TerminalCore::new(6, 3);
        for i in 0..10 {
            t.feed(format!("line{i}\r\n").as_bytes());
        }
        let bottom = t.frame();
        assert_eq!(t.display_offset(), 0);
        assert!(bottom.cursor_visible);

        t.scroll(3);
        assert!(t.display_offset() > 0, "offset must have grown");
        let scrolled = t.frame();
        assert!(
            !scrolled.cursor_visible,
            "the cursor is hidden while scrolled into history"
        );
        assert_ne!(
            scrolled.cells, bottom.cells,
            "a different (historical) region is shown"
        );

        t.scroll_to_bottom();
        assert_eq!(t.display_offset(), 0);
        assert_eq!(t.frame(), bottom, "back to the same live frame");
    }

    #[test]
    fn history_limit_and_clear_preserve_the_live_screen() {
        let mut t = TerminalCore::new(20, 3);
        t.set_history_limit(7);
        for n in 0..40 {
            t.feed(format!("line{n}\r\n").as_bytes());
        }
        assert_eq!(t.history_size(), 7);
        let live = t.frame();
        t.scroll(3);
        t.clear_history();
        assert_eq!(t.history_size(), 0);
        assert_eq!(t.frame(), live);
        t.feed(b"more\r\n");
        assert_eq!(t.history_size(), 1);
        t.feed(b"\x1b[?1049h");
        t.clear_history();
        t.feed(b"\x1b[?1049l");
        assert_eq!(
            t.history_size(),
            0,
            "inactive primary history is cleared too"
        );
        t.set_history_limit(0);
        for _ in 0..40 {
            t.feed(b"no history\r\n");
        }
        assert_eq!(t.history_size(), 0);
    }

    #[test]
    fn frame_keeps_the_color_the_application_asked_for() {
        let mut t = TerminalCore::new(10, 1);
        // Red (indexed 1), default, palette entry 200, direct RGB.
        t.feed(b"\x1b[31mR\x1b[0mD\x1b[38;5;200mP\x1b[38;2;1;2;3mT");
        let f = t.frame();
        assert_eq!(f.cells[0].fg, Color::Indexed(1));
        assert_eq!(f.cells[1].fg, Color::Default);
        assert_eq!(f.cells[2].fg, Color::Indexed(200));
        assert_eq!(f.cells[3].fg, Color::Rgb(0x0001_0203));
        assert_eq!(f.cells[0].bg, Color::Default);
    }

    #[test]
    fn palette_resolves_like_the_previous_rgb_output() {
        let f = TerminalCore::new(4, 1).frame();
        // The values the FFI previously returned for these colors.
        assert_eq!(f.palette.resolve(Color::Indexed(1), true), 0x00cd_0000);
        assert_eq!(
            f.palette.resolve(Color::Rgb(0x0012_3456), true),
            0x0012_3456
        );
        assert_eq!(
            f.palette.resolve(Color::Default, true),
            f.palette.default_fg
        );
        assert_eq!(
            f.palette.resolve(Color::Default, false),
            f.palette.default_bg
        );
    }

    #[test]
    fn osc4_palette_override_reaches_the_frame_palette() {
        let mut t = TerminalCore::new(4, 1);
        let before = t.frame().palette.entries[1];
        // OSC 4: redefine palette entry 1 as pure blue. (If this exact
        // spelling is rejected by the parser, use the `#0000ff` form -- both
        // are standard; what matters is that the override reaches the frame.)
        t.feed(b"\x1b]4;1;rgb:00/00/ff\x1b\\");
        let after = t.frame().palette.entries[1];
        assert_ne!(before, after, "OSC 4 must change the snapshot palette");
        assert_eq!(after, 0x0000_00ff);
    }

    #[test]
    fn blank_frame_has_default_colors_everywhere() {
        let f = Frame::blank(3, 2);
        assert_eq!(f.cells.len(), 6);
        assert!(f
            .cells
            .iter()
            .all(|c| c.fg == Color::Default && c.bg == Color::Default));
        assert_eq!((f.cols, f.rows), (3, 2));
    }

    #[test]
    fn cell_blank_and_contents_match() {
        let blank = Cell::blank();
        assert!(blank.is_blank());
        assert_eq!(blank.ch, ' ');
        let a = Cell {
            ch: 'a',
            fg: Color::Indexed(1),
            bg: Color::Indexed(2),
            flags: 0,
        };
        let a2 = Cell {
            ch: 'a',
            fg: Color::Indexed(9),
            bg: Color::Indexed(9),
            flags: 4,
        };
        assert!(a.contents_match(&a2)); // compared by character, ignoring colors/attributes
        assert!(!a.contents_match(&blank));
        assert!(!a.is_blank());
    }
    #[test]
    fn frame_backs_the_cursor_off_the_spacer_of_a_wide_character() {
        // Placed on the second half of a wide character, the cursor is
        // reported on the character itself -- as alacritty's own renderer
        // does, so a cursor drawn there covers the glyph, not a blank.
        let mut t = TerminalCore::new(10, 2);
        t.feed("\u{65e5}ab\x1b[1;2H".as_bytes());
        assert_eq!(t.cursor(), (1, 0), "the emulator's cursor is on the spacer");
        let f = t.frame();
        assert_eq!(f.cells[1].flags & FLAG_WIDE_SPACER, FLAG_WIDE_SPACER);
        assert_eq!((f.cursor_col, f.cursor_row), (0, 0));
    }

    #[test]
    fn frame_reports_the_cursor_on_an_orphan_spacer_in_column_0() {
        // `ESC [ P` on a wide character in column 0 shifts its spacer into
        // column 0, with nothing to its left, and leaves the cursor on it.
        // Backing the cursor off a spacer unconditionally underflows here:
        // a panic in a debug build, column 65535 in a release one.
        let mut t = TerminalCore::new(10, 2);
        t.feed("\u{65e5}ab\x1b[1;1H\x1b[P".as_bytes());
        let f = t.frame();
        assert_eq!(
            f.cells[0].flags & FLAG_WIDE_SPACER,
            FLAG_WIDE_SPACER,
            "an orphan spacer in column 0"
        );
        assert_eq!((f.cursor_col, f.cursor_row), (0, 0));
        assert!(f.cursor_visible);
    }

    #[test]
    fn frame_hides_the_cursor_while_dectcem_is_off() {
        let mut t = TerminalCore::new(10, 2);
        t.feed(b"\x1b[?25l");
        assert!(!t.frame().cursor_visible);
        t.feed(b"\x1b[?25h");
        assert!(t.frame().cursor_visible);
    }
}
