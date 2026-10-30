#![forbid(unsafe_code)]

//! Terminal core built on `alacritty_terminal`.
//!
//! This module's job is to wrap a mature emulator: take a byte stream from
//! the remote shell, run it through the VT sequence parser, and update the
//! screen grid and cursor. What it exposes: `new`/`feed` (input), `resize`
//! (window size change), and `frame` (a snapshot of the visible grid for
//! rendering - characters, colors kept as the application meant them plus a
//! palette snapshot to resolve them, attributes, cursor).

use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
mod cached_frame_tests;
#[cfg(test)]
mod combining_equality_tests;
mod frame_cache;
#[cfg(test)]
mod frame_storage_tests;
mod limits;
mod replay;
mod replies;
#[cfg(test)]
mod reply_tests;
#[cfg(test)]
mod split_input_tests;
#[cfg(test)]
mod sync_deadline_tests;
mod tracking;

pub use limits::TerminalOptions;
pub use replay::StateSnapshot;
use replies::ReplyListener;
pub use replies::{TerminalRepaint, TerminalReplyError, MAX_TERMINAL_REPLY_BYTES};
use terminal_size::{TerminalSize, ViewportSize};

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

/// Concealed text (SGR 8). This affects display, not storage or confidentiality.
pub const FLAG_HIDDEN: u16 = 0b1_0000_0000;

/// Maximum accepted zero-width scalars following a cell's base character.
pub const MAX_COMBINING_MARKS: usize = 16;

/// Bounded inline zero-width suffix. Copying a cell never allocates.
///
/// Slots past `len` are always `'\0'`: the storage starts zeroed, `push`
/// writes only the slot at `len`, and nothing removes a mark in place.
/// Equality relies on this: it compares the length and only the slots that
/// can hold marks, so an empty suffix, the common case, compares one byte.
#[derive(Debug, Clone, Copy, Eq)]
pub struct CombiningMarks {
    chars: [char; MAX_COMBINING_MARKS],
    len: u8,
}

impl PartialEq for CombiningMarks {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Slots past `len` are zero in both, so the groups of four slots
        // that hold the marks compare as the marks themselves do. Each group
        // is a fixed-size comparison, which needs no call to `memcmp`.
        let groups = usize::from(self.len).div_ceil(4);
        let (ours, theirs) = (
            self.chars.as_chunks::<4>().0,
            other.chars.as_chunks::<4>().0,
        );
        self.len == other.len && ours.iter().zip(theirs).take(groups).all(|(a, b)| a == b)
    }
}

impl Default for CombiningMarks {
    fn default() -> Self {
        Self {
            chars: ['\0'; MAX_COMBINING_MARKS],
            len: 0,
        }
    }
}

impl CombiningMarks {
    /// Retain accepted zero-width scalars, dropping invalid or excess input.
    pub fn from_slice(marks: &[char]) -> Self {
        let mut result = Self::default();
        for &mark in marks {
            result.push(mark);
        }
        result
    }

    /// Append a non-control, zero-width scalar if capacity remains.
    /// Returns false when the scalar is invalid or the suffix is full.
    pub fn push(&mut self, mark: char) -> bool {
        use unicode_width::UnicodeWidthChar;
        if mark.is_control()
            || mark.width() != Some(0)
            || usize::from(self.len) == MAX_COMBINING_MARKS
        {
            return false;
        }
        self.chars[usize::from(self.len)] = mark;
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[char] {
        &self.chars[..usize::from(self.len)]
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

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

/// One frame cell: a base character with a bounded zero-width suffix,
/// foreground/background colors (kept as the
/// application meant them -- see `Color`), and attributes (see the `FLAG_*`
/// constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    /// Zero-width scalars attached to the base character.
    pub combining: CombiningMarks,
    pub fg: Color,
    pub bg: Color,
    pub flags: u16,
}

impl Cell {
    /// Blank cell: a space with default colors/attributes.
    pub fn blank() -> Cell {
        Cell {
            ch: ' ',
            combining: CombiningMarks::default(),
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        }
    }

    /// Replace the base text, clearing any suffix inherited from old content.
    pub fn set_char(&mut self, ch: char) {
        self.ch = ch;
        self.combining = CombiningMarks::default();
    }

    /// Whether the cell is blank (space or NUL). Port of mosh's
    /// `Cell::is_blank` - prediction gives no "credit" for matching a blank cell.
    pub fn is_blank(&self) -> bool {
        (self.ch == ' ' || self.ch == '\0') && self.combining.is_empty()
    }

    /// Whether the complete text of two cells matches, ignoring
    /// colors/attributes. Port of mosh's `Cell::contents_match`: prediction
    /// validity is decided by text, while colors are copied separately.
    pub fn contents_match(&self, other: &Cell) -> bool {
        self.ch == other.ch && self.combining == other.combining
    }
}

/// A snapshot of the terminal's visible grid: cells in row-major order (row
/// by row, left to right within a row) plus cursor position and visibility.
///
/// Every frame owns its cells: a copy never shares them with its source, so
/// changing the model or another frame leaves it as it was. Only the palette
/// is shared, and it is changed by copy-on-write (`Arc::make_mut`).
#[derive(Debug, PartialEq, Eq)]
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

/// `clone_from` copies into the destination's own cell storage, so a frame
/// kept from one presentation to the next takes the new picture without
/// allocating (see [`fit_cells`] for when the storage is replaced instead).
/// Both methods list every field: a field added to `Frame` fails to compile
/// here until it is copied.
impl Clone for Frame {
    fn clone(&self) -> Frame {
        let Frame {
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
            palette,
        } = self;
        Frame {
            cols: *cols,
            rows: *rows,
            cells: cells.clone(),
            cursor_col: *cursor_col,
            cursor_row: *cursor_row,
            cursor_visible: *cursor_visible,
            app_cursor: *app_cursor,
            app_keypad: *app_keypad,
            origin_mode: *origin_mode,
            mouse_tracking: *mouse_tracking,
            mouse_sgr: *mouse_sgr,
            bracketed_paste: *bracketed_paste,
            alt_screen: *alt_screen,
            palette: Arc::clone(palette),
        }
    }

    fn clone_from(&mut self, source: &Frame) {
        let Frame {
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
            palette,
        } = source;
        fit_cells(&mut self.cells, cells.len());
        self.cells.extend_from_slice(cells);
        self.cols = *cols;
        self.rows = *rows;
        self.cursor_col = *cursor_col;
        self.cursor_row = *cursor_row;
        self.cursor_visible = *cursor_visible;
        self.app_cursor = *app_cursor;
        self.app_keypad = *app_keypad;
        self.origin_mode = *origin_mode;
        self.mouse_tracking = *mouse_tracking;
        self.mouse_sgr = *mouse_sgr;
        self.bracketed_paste = *bracketed_paste;
        self.alt_screen = *alt_screen;
        if !Arc::ptr_eq(&self.palette, palette) {
            self.palette = Arc::clone(palette);
        }
    }
}

/// Empty `cells` for reuse with room for `needed` cells. Storage more than
/// twice as large as needed is replaced rather than kept, so a frame reused
/// after the screen shrank does not hold the larger grid indefinitely.
pub fn fit_cells(cells: &mut Vec<Cell>, needed: usize) {
    if cells.capacity() > needed.saturating_mul(2) {
        *cells = Vec::with_capacity(needed);
    } else {
        cells.clear();
        cells.reserve_exact(needed);
    }
}

/// The emulator core: the `Term` screen grid plus the `Processor` control
/// sequence parser. Ordinary feeds are passive; an explicit fresh-output feed
/// can collect bounded replies for the owner of the application input stream.
pub struct TerminalCore {
    term: Term<ReplyListener>,
    replies: ReplyListener,
    parser: Processor,
    /// Only in a core made to replay itself ([`TerminalCore::with_replay`]):
    /// the daemon's model of a screen. Everywhere else -- the app, the
    /// console client -- the parser drives the `Term` directly, as it always
    /// did, and pays nothing for it.
    replay: Option<ReplayState>,
    history_limit: usize,
    sync_boundary: bool,
    frame_cache: Option<Box<frame_cache::CachedFrame>>,
    #[cfg(test)]
    cache_counts: frame_cache::CacheCounts,
    #[cfg(test)]
    cache_omit_row: Option<usize>,
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
        Self::with_options(
            TerminalSize::for_viewport(cols, rows),
            TerminalOptions::default(),
        )
    }

    /// Creates a model with validated geometry and bounded history before allocation.
    pub fn with_options(size: TerminalSize, options: TerminalOptions) -> Self {
        let dimensions = TermSize::new(size.cols() as usize, size.rows() as usize);
        let replies = ReplyListener::default();
        let term = Term::new(
            Config {
                scrolling_history: limits::effective_history(options.history_lines, size),
                ..Config::default()
            },
            &dimensions,
            replies.clone(),
        );
        Self {
            term,
            replies,
            parser: Processor::new(),
            replay: options.replay.then(|| ReplayState {
                tracked: tracking::Tracked::new(size.cols() as usize, size.rows() as usize),
                pending: tracking::PendingSequence::default(),
            }),
            history_limit: options.history_lines,
            sync_boundary: false,
            frame_cache: None,
            #[cfg(test)]
            cache_counts: frame_cache::CacheCounts::default(),
            #[cfg(test)]
            cache_omit_row: None,
        }
    }

    /// Current validated model dimensions.
    pub fn size(&self) -> TerminalSize {
        TerminalSize::new(self.term.columns() as u16, self.term.screen_lines() as u16)
            .expect("terminal model geometry is bounded")
    }

    /// History rows allowed by the requested limit and current width.
    pub fn effective_history_limit(&self) -> usize {
        limits::effective_history(self.history_limit, self.size())
    }

    /// Sets the primary screen's history capacity, including zero to disable it.
    pub fn set_history_limit(&mut self, lines: usize) {
        self.invalidate_frame_cache();
        self.history_limit = lines;
        self.term.set_options(Config {
            scrolling_history: self.effective_history_limit(),
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
        Self::with_options(
            TerminalSize::for_viewport(cols, rows),
            TerminalOptions {
                replay: true,
                ..TerminalOptions::default()
            },
        )
    }

    /// Feeds bytes to the parser: printable characters land in the grid,
    /// while control sequences move the cursor and change modes.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.sync_boundary |= self.sync_deadline().is_some();
        for bytes in bytes.chunks(4096) {
            if let Some(replay) = &mut self.replay {
                replay.pending.push(bytes);
            }
            self.parser.advance(
                &mut tracking::Tracking {
                    term: &mut self.term,
                    tracked: self.replay.as_mut().map(|replay| &mut replay.tracked),
                    sync_boundary: &mut self.sync_boundary,
                },
                bytes,
            );
        }
    }

    /// Whether a synchronized-output boundary was encountered since the last observation.
    /// Independent of replay tracking; does not execute buffered output.
    pub fn take_sync_boundary(&mut self) -> bool {
        std::mem::take(&mut self.sync_boundary)
    }

    /// Feed fresh application output and return its ordered terminal replies.
    ///
    /// Only the authoritative owner of the application input stream may use
    /// this method. Display replicas, prediction and restored replay must use
    /// [`Self::feed`] instead. Pixel-size, clipboard and color requests remain
    /// unsupported because this model does not own those resources.
    ///
    /// An overflow returns no reply prefix. The owner must end the affected
    /// channel rather than continue after silently losing required responses.
    pub fn feed_with_replies(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TerminalReplyError> {
        let capture = self.replies.capture();
        self.feed(bytes);
        capture.finish()
    }

    /// Flush buffered fresh output before an authoritative geometry change.
    ///
    /// This executes pending synchronized-update bytes at the current geometry.
    /// It is an explicit flush boundary, not an operation to perform after every
    /// feed. The owner must admit the returned replies or end the channel.
    pub fn flush_with_replies(&mut self) -> Result<Vec<u8>, TerminalReplyError> {
        let capture = self.replies.capture();
        self.flush_pending_output();
        capture.finish()
    }

    /// Build a repaint while returning replies from buffered fresh output.
    ///
    /// The repaint bytes themselves never generate application replies here.
    /// Only previously buffered fresh bytes executed by the parser can do so.
    /// A passive replica must consume the repaint through ordinary [`Self::feed`].
    pub fn replay_with_replies(&mut self) -> Result<Option<TerminalRepaint>, TerminalReplyError> {
        let capture = self.replies.capture();
        let bytes = self.replay();
        let replies = capture.finish()?;
        Ok(bytes.map(|bytes| TerminalRepaint { bytes, replies }))
    }

    /// The parser's current synchronized-update deadline, if output is buffered.
    pub fn sync_deadline(&self) -> Option<Instant> {
        self.parser.sync_timeout().sync_timeout()
    }

    /// Apply due buffered output for a passive display replica.
    pub fn flush_due_output(&mut self, now: Instant) -> bool {
        if !self.sync_deadline().is_some_and(|deadline| now >= deadline) {
            return false;
        }
        self.flush_pending_output();
        true
    }

    /// Apply due fresh output for the authoritative application-input owner.
    pub fn flush_due_with_replies(
        &mut self,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TerminalReplyError> {
        if !self.sync_deadline().is_some_and(|deadline| now >= deadline) {
            return Ok(None);
        }
        self.flush_with_replies().map(Some)
    }

    /// Apply buffered output at an explicit passive display boundary.
    /// Authoritative owners must use [`Self::flush_with_replies`] instead.
    pub fn flush_pending_output(&mut self) {
        if self.parser.sync_timeout().sync_timeout().is_some() {
            self.parser.stop_sync(&mut tracking::Tracking {
                term: &mut self.term,
                tracked: self.replay.as_mut().map(|replay| &mut replay.tracked),
                sync_boundary: &mut self.sync_boundary,
            });
        }
    }

    /// Changes the terminal size (columns by rows), e.g. on screen rotation
    /// or a window resize on the client side.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        self.resize_to(TerminalSize::for_viewport(cols, rows));
    }

    /// Resizes the model, shrinking history before any width growth.
    pub fn resize_to(&mut self, size: TerminalSize) {
        let (old_cols, old_rows) = (self.term.columns(), self.term.screen_lines());
        if (old_cols, old_rows) != (usize::from(size.cols()), usize::from(size.rows())) {
            self.frame_cache = None;
        }
        // Alacritty set_options targets the primary grid even while it is inactive.
        self.term.set_options(Config {
            scrolling_history: limits::effective_history(self.history_limit, size),
            ..Config::default()
        });
        self.term
            .resize(TermSize::new(size.cols() as usize, size.rows() as usize));
        if let Some(replay) = &mut self.replay {
            replay.tracked.resize(
                old_cols,
                old_rows,
                size.cols() as usize,
                size.rows() as usize,
            );
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
    /// This is the passive form. An authoritative application-input owner must
    /// use [`Self::replay_with_replies`] to answer buffered fresh queries.
    ///
    /// `None` from a core not made [`TerminalCore::with_replay`].
    pub fn replay(&mut self) -> Option<Vec<u8>> {
        self.replay.as_ref()?;
        self.invalidate_frame_cache();
        self.flush_pending_output();
        let replay = self.replay.as_ref().expect("replay policy is unchanged");
        Some(replay::write(
            &mut self.term,
            &replay.tracked,
            &replay.pending.tail(),
        ))
    }

    /// Everything [`TerminalCore::replay`] restores, to compare two
    /// emulators by; `None` from a core not made
    /// [`TerminalCore::with_replay`].
    pub fn snapshot(&mut self) -> Option<StateSnapshot> {
        self.replay.as_ref()?;
        self.invalidate_frame_cache();
        let replay = self.replay.as_ref().expect("replay policy is unchanged");
        Some(replay::snapshot(&mut self.term, &replay.tracked))
    }

    /// Shifts the history view by `delta_lines` lines. A positive `delta`
    /// goes into the past (older lines), a negative one goes back toward
    /// the live bottom. An empty history (little output) doesn't panic -
    /// `scroll_display` itself clamps the offset to the buffered range.
    pub fn scroll(&mut self, delta_lines: i32) {
        let before = self.display_offset();
        let target = self.display_offset() as i64 + i64::from(delta_lines);
        let scroll = if target <= 0 {
            Scroll::Bottom
        } else if target >= self.history_size() as i64 {
            Scroll::Top
        } else {
            Scroll::Delta(delta_lines)
        };
        self.term.scroll_display(scroll);
        if self.display_offset() != before {
            self.invalidate_frame_cache();
        }
    }

    /// Returns the view to the live bottom (resets the history offset).
    pub fn scroll_to_bottom(&mut self) {
        let before = self.display_offset();
        self.term.scroll_display(Scroll::Bottom);
        if self.display_offset() != before {
            self.invalidate_frame_cache();
        }
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
        let mut frame = self.empty_frame();
        self.fill(&mut frame);
        frame
    }

    fn empty_frame(&self) -> Frame {
        Frame {
            cols: 0,
            rows: 0,
            cells: Vec::new(),
            cursor_col: 0,
            cursor_row: 0,
            cursor_visible: false,
            app_cursor: false,
            app_keypad: false,
            origin_mode: false,
            mouse_tracking: MouseTracking::Off,
            mouse_sgr: false,
            bracketed_paste: false,
            alt_screen: false,
            palette: Arc::new(snapshot_palette(self.term.colors())),
        }
    }

    /// [`TerminalCore::frame`] written over `frame`, reusing its cell storage
    /// and, when the colors did not change, its palette. Every field is
    /// replaced: nothing of what `frame` held before survives, whatever its
    /// size or content was. The result equals what `frame()` returns.
    pub fn frame_into(&self, frame: &mut Frame) {
        let palette = snapshot_palette(self.term.colors());
        if *frame.palette != palette {
            match Arc::get_mut(&mut frame.palette) {
                Some(owned) => *owned = palette,
                None => frame.palette = Arc::new(palette),
            }
        }
        self.fill(frame);
    }

    /// Every field of `frame` but the palette, from the current state.
    fn fill(&self, frame: &mut Frame) {
        let cols = self.term.columns() as u16;
        let rows = self.term.screen_lines() as u16;
        let colors = self.term.colors();
        let offset = self.term.grid().display_offset();

        let cells = &mut frame.cells;
        fit_cells(cells, cols as usize * rows as usize);
        for row in 0..rows {
            for col in 0..cols {
                let point = Point::new(Line(row as i32 - offset as i32), Column(col as usize));
                let cell = &self.term.grid()[point];
                cells.push(Cell {
                    ch: cell.c,
                    combining: CombiningMarks::from_slice(cell.zerowidth().unwrap_or_default()),
                    fg: convert_color(cell.fg, colors),
                    bg: convert_color(cell.bg, colors),
                    flags: convert_flags(cell.flags),
                });
            }
        }

        self.fill_metadata(frame);
    }

    fn fill_metadata(&self, frame: &mut Frame) {
        let cols = self.term.columns() as u16;
        let rows = self.term.screen_lines() as u16;
        let offset = self.term.grid().display_offset();
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

        frame.cols = cols;
        frame.rows = rows;
        frame.cursor_col = cursor_col;
        frame.cursor_row = cursor_row;
        frame.cursor_visible = cursor_visible;
        frame.app_cursor = app_cursor;
        frame.app_keypad = app_keypad;
        frame.origin_mode = origin_mode;
        frame.mouse_tracking = mouse_tracking;
        frame.mouse_sgr = mouse_sgr;
        frame.bracketed_paste = bracketed_paste;
        frame.alt_screen = alt_screen;
    }
}

impl Frame {
    /// A blank frame of the given size: spaces with default colors, cursor at
    /// the top-left, every mode off, standard palette. Hand-built frames
    /// (tests, the renderer's "nothing drawn yet" state) start here, so
    /// adding a field to `Frame` doesn't ripple through every call site.
    pub fn blank(cols: u16, rows: u16) -> Frame {
        let size = ViewportSize::new(cols, rows);
        let (cols, rows) = (size.cols(), size.rows());
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
    if flags.contains(CellFlags::HIDDEN) {
        result |= FLAG_HIDDEN;
    }
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
    fn minimum_geometry_wide_wrap_replay() {
        let mut source = TerminalCore::with_replay(0, 0);
        source.feed("日a日".as_bytes());
        let mut target = TerminalCore::with_replay(1, 0);
        target.feed(&source.replay().unwrap());
        assert_eq!(source.snapshot(), target.snapshot());
        assert_eq!((source.frame().cols, source.frame().rows), (2, 1));
    }

    #[test]
    fn history_cell_budget_tracks_width() {
        for alternate in [false, true] {
            let mut t = TerminalCore::new(2, 2);
            for _ in 0..5000 {
                t.feed(b"x\r\n");
            }
            if alternate {
                t.feed(b"\x1b[?1049h");
            }
            t.resize(512, 2);
            if alternate {
                t.feed(b"\x1b[?1049l");
            }
            assert_eq!(t.effective_history_limit(), 2048);
            assert!(t.history_size() <= 2048);
            let retained = t.history_size();
            t.resize(2, 2);
            assert_eq!(t.effective_history_limit(), 10000);
            assert!(t.history_size() <= retained);
            for _ in 0..11000 {
                t.feed(b"x\r\n");
            }
            assert_eq!(t.history_size(), 10000);
        }
    }

    #[test]
    fn history_zero_from_construction() {
        let mut t = TerminalCore::with_options(
            TerminalSize::new(512, 1).unwrap(),
            TerminalOptions {
                history_lines: 0,
                replay: true,
            },
        );
        assert_eq!(t.effective_history_limit(), 0);
        for _ in 0..3000 {
            t.feed(b"x\r\n");
        }
        assert_eq!(t.history_size(), 0);
        t.set_history_limit(usize::MAX);
        for _ in 0..3000 {
            t.feed(b"x\r\n");
        }
        assert!(t.history_size() <= 2048);
        t.set_history_limit(0);
        t.clear_history();
        t.feed(b"x\r\n");
        assert_eq!(t.history_size(), 0);
    }

    #[test]
    fn raw_geometry_adapters_are_bounded() {
        // Check the adapter before exercising maximum values to avoid a raw allocation.
        let mut t = TerminalCore::new(0, 0);
        assert_eq!((t.frame().cols, t.frame().rows), (2, 1));
        for replay in [false, true] {
            t = if replay {
                TerminalCore::with_replay(u16::MAX, u16::MAX)
            } else {
                TerminalCore::new(u16::MAX, u16::MAX)
            };
            assert_eq!((t.frame().cols, t.frame().rows), (512, 256));
            t.resize(u16::MAX, u16::MAX);
            assert_eq!((t.frame().cols, t.frame().rows), (512, 256));
        }
    }

    #[test]
    fn presentation_frame_accepts_one_and_zero() {
        for (cols, rows) in [(0, 0), (1, 1), (0, 257)] {
            let f = Frame::blank(cols, rows);
            assert_eq!((f.cols, f.rows), (cols, rows));
        }
        let f = Frame::blank(513, 258);
        assert_eq!((f.cols, f.rows), (512, 257));
    }

    // Damage consumers must observe cross-row flag changes, even though qsh currently
    // extracts complete frames rather than relying on the damage iterator.
    #[test]
    fn wide_spacer_damage_marks_previous_row_for_both_halves() {
        use alacritty_terminal::term::TermDamage;
        for col in [1, 2] {
            let mut t = TerminalCore::new(8, 4);
            t.feed("\x1b[1;8H界".as_bytes());
            t.feed(format!("\x1b[2;{col}H").as_bytes());
            let _ = t.term.damage();
            t.term.reset_damage();
            t.feed(b"x");
            assert!(!t.term.grid()[Point::new(Line(0), Column(7))]
                .flags
                .contains(CellFlags::LEADING_WIDE_CHAR_SPACER));
            let TermDamage::Partial(rows) = t.term.damage() else {
                panic!("expected partial damage")
            };
            assert!(
                rows.into_iter()
                    .any(|row| row.line == 0 && row.left <= 7 && row.right >= 7),
                "previous-row mutation was not damaged for column {col}"
            );
        }
    }

    #[test]
    fn wide_spacer_damage_does_not_mark_unchanged_previous_row() {
        use alacritty_terminal::term::TermDamage;
        let mut t = TerminalCore::new(8, 4);
        t.feed("\x1b[2;1H界\x1b[2;1H".as_bytes());
        let _ = t.term.damage();
        t.term.reset_damage();
        t.feed(b"x");
        let TermDamage::Partial(rows) = t.term.damage() else {
            panic!("expected partial damage")
        };
        assert!(!rows.into_iter().any(|row| row.line == 0));
    }

    #[test]
    fn wide_spacer_damage_history_boundary_keeps_full_invalidation() {
        use alacritty_terminal::term::TermDamage;
        let mut t = TerminalCore::new(8, 2);
        t.feed("\x1b[1;8H界\x1b[S\x1b[1;1H".as_bytes());
        assert_eq!(t.term.grid().history_size(), 1);
        assert!(t.term.grid()[Point::new(Line(-1), Column(7))]
            .flags
            .contains(CellFlags::LEADING_WIDE_CHAR_SPACER));
        t.scroll(1);
        assert!(matches!(t.term.damage(), TermDamage::Full));
        // Consume the scroll invalidation before fresh output changes the visible history row.
        t.term.reset_damage();
        t.feed(b"x");
        assert!(!t.term.grid()[Point::new(Line(-1), Column(7))]
            .flags
            .contains(CellFlags::LEADING_WIDE_CHAR_SPACER));
        assert!(matches!(t.term.damage(), TermDamage::Full));
    }

    #[test]
    fn wide_spacer_damage_offscreen_history_does_not_invalidate_viewport() {
        use alacritty_terminal::term::TermDamage;
        let mut t = TerminalCore::new(8, 2);
        t.feed("\x1b[1;8H界\x1b[S\x1b[1;1H".as_bytes());
        assert_eq!(t.term.grid().display_offset(), 0);
        assert!(t.term.grid()[Point::new(Line(-1), Column(7))]
            .flags
            .contains(CellFlags::LEADING_WIDE_CHAR_SPACER));
        let _ = t.term.damage();
        t.term.reset_damage();
        t.feed(b"x");
        assert!(!t.term.grid()[Point::new(Line(-1), Column(7))]
            .flags
            .contains(CellFlags::LEADING_WIDE_CHAR_SPACER));
        assert!(matches!(t.term.damage(), TermDamage::Partial(_)));
    }

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

    fn history_region_delete_fixture(offset: i32, positions: usize) -> (TerminalCore, Frame) {
        let mut terminal = TerminalCore::new(8, 7);
        terminal.feed(b"A\r\nB\r\nC\r\nD\r\nE\r\nF\r\nG");
        assert_eq!(terminal.history_size(), 0);
        terminal.feed(b"\x1b[6S");
        assert_eq!(terminal.history_size(), 6);
        terminal.scroll(offset);
        assert_eq!(terminal.display_offset(), offset as usize);
        let pinned = terminal.frame();
        assert_eq!(pinned.cell(0, 0).ch, (b'G' - offset as u8) as char);
        terminal.feed(format!("\x1b[2;2H\x1b[{positions}M").as_bytes());
        (terminal, pinned)
    }

    #[test]
    fn history_region_delete_keeps_offset_within_retained_history() {
        let (terminal, _) = history_region_delete_fixture(6, 2);
        assert_eq!(
            terminal.history_size(),
            6,
            "region deletion adds no history"
        );
        assert_eq!(
            terminal.display_offset(),
            6,
            "unchanged history remains pinned"
        );
    }

    #[test]
    fn history_region_delete_frame_keeps_pinned_rows() {
        let (terminal, pinned) = history_region_delete_fixture(6, 2);
        let frame = terminal.frame();
        assert_eq!(
            frame.cells, pinned.cells,
            "region deletion cannot move retained history"
        );
    }

    #[test]
    fn history_region_delete_keeps_partial_history_anchor() {
        let (terminal, pinned) = history_region_delete_fixture(3, 2);
        assert_eq!(terminal.history_size(), 6);
        let frame = terminal.frame();
        assert_eq!(
            (terminal.display_offset(), frame.cell(0, 0).ch),
            (3, pinned.cell(0, 0).ch),
            "a subregion scroll cannot move history even within its bounds"
        );
        let retained_cells = 3 * pinned.width() as usize;
        assert_eq!(
            &frame.cells[..retained_cells],
            &pinned.cells[..retained_cells]
        );
    }

    #[test]
    fn history_region_delete_full_clear_preserves_retained_prefix() {
        for offset in [3, 6] {
            let (terminal, pinned) = history_region_delete_fixture(offset, 99);
            assert_eq!(
                (terminal.history_size(), terminal.display_offset()),
                (6, offset as usize)
            );
            let frame = terminal.frame();
            let retained_cells = offset as usize * pinned.width() as usize;
            assert_eq!(
                &frame.cells[..retained_cells],
                &pinned.cells[..retained_cells]
            );
        }
    }

    #[test]
    fn history_region_scroll_from_top_keeps_anchor_until_evicted_at_cap() {
        let mut terminal = TerminalCore::new(8, 7);
        terminal.set_history_limit(8);
        terminal.feed(b"A\r\nB\r\nC\r\nD\r\nE\r\nF\r\nG\x1b[6S");
        terminal.scroll(3);
        assert_eq!(terminal.frame().cell(0, 0).ch, 'D');
        for offset in [5, 7] {
            terminal.feed(b"\x1b[2S");
            assert_eq!(
                (terminal.history_size(), terminal.display_offset()),
                (8, offset)
            );
            assert_eq!(terminal.frame().cell(0, 0).ch, 'D');
        }
        terminal.feed(b"\x1b[2S");
        assert_eq!((terminal.history_size(), terminal.display_offset()), (8, 8));
        assert_eq!(terminal.frame().cell(0, 0).ch, 'E');
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
            combining: Default::default(),
            flags: 0,
        };
        let a2 = Cell {
            ch: 'a',
            fg: Color::Indexed(9),
            bg: Color::Indexed(9),
            combining: Default::default(),
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

#[cfg(test)]
mod payload_tests {
    use super::*;
    use alacritty_terminal::index::{Column, Line};

    #[test]
    fn combining_payload_is_bounded_on_both_screens_and_replay() {
        for replay in [false, true] {
            let mut t = TerminalCore::with_options(
                TerminalSize::new(2, 1).unwrap(),
                TerminalOptions {
                    history_lines: 0,
                    replay,
                },
            );
            for switch in [b"".as_slice(), b"\x1b[?1049h".as_slice()] {
                t.feed(switch);
                t.feed("界".as_bytes());
                for _ in 0..100_000 {
                    t.feed("\u{301}".as_bytes());
                }
                t.feed("\u{302}".as_bytes());
                assert_eq!(
                    t.term.grid()[Line(0)][Column(0)].zerowidth().unwrap().len(),
                    16
                );
                if replay {
                    let mut other = TerminalCore::with_replay(2, 1);
                    other.feed(&t.replay().unwrap());
                    assert_eq!(t.snapshot(), other.snapshot());
                    t.feed(b"\x1b[3b");
                    other.feed(b"\x1b[3b");
                    assert_eq!(t.snapshot(), other.snapshot());
                }
            }
        }
    }

    #[test]
    fn combining_replay_preserves_cursor_saved_cursor_and_rep() {
        for alternate in [false, true] {
            for initial in ["abcd", "ab界", "界界"] {
                for cursor in [
                    "",
                    "\x1b[1;2H",
                    "\x1b[1;4H",
                    "\x1b[?7l",
                    "\x1b[2;2r\x1b[?6h",
                ] {
                    let mut t = TerminalCore::with_replay(4, 2);
                    if alternate {
                        t.feed(b"\x1b[?1049h");
                    }
                    t.feed(initial.as_bytes());
                    t.feed(cursor.as_bytes());
                    t.feed(b"\x1b7");
                    t.feed("\u{301}".repeat(16).as_bytes());
                    t.feed("\u{302}".as_bytes());
                    let mut other = TerminalCore::with_replay(4, 2);
                    other.feed(&t.replay().unwrap());
                    assert_eq!(t.snapshot(), other.snapshot(), "{initial:?} {cursor:?}");
                    for bytes in [
                        b"\x1b[3b".as_slice(),
                        b"\x1b8",
                        "z\u{303}".as_bytes(),
                        b"\x1b[2b",
                    ] {
                        t.feed(bytes);
                        other.feed(bytes);
                        assert_eq!(
                            t.snapshot(),
                            other.snapshot(),
                            "{initial:?} {cursor:?} {bytes:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dropped_combining_replay_preserves_wrapped_saturated_last_column() {
        let mut t = TerminalCore::with_replay(4, 2);
        t.feed(b"abcd");
        t.feed("\u{301}".repeat(16).as_bytes());
        t.feed(b"x");
        t.feed("\u{301}".repeat(16).as_bytes());
        t.feed("\u{302}".as_bytes());
        let mut other = TerminalCore::with_replay(4, 2);
        other.feed(&t.replay().unwrap());
        assert_eq!(t.snapshot(), other.snapshot());
        for bytes in [b"\x1b[3b".as_slice(), b"yz", b"\x1b[2b"] {
            t.feed(bytes);
            other.feed(bytes);
            assert_eq!(t.snapshot(), other.snapshot());
        }
    }

    #[test]
    fn dropped_combining_last_column_target_does_not_rewrite_cells() {
        for alternate in [false, true] {
            for wrapped in [false, true] {
                for wrap_enabled in [false, true] {
                    let mut t = TerminalCore::with_replay(4, 2);
                    if alternate {
                        t.feed(b"\x1b[?1049h");
                    }
                    t.feed(b"abcd");
                    t.feed("\u{301}".repeat(16).as_bytes());
                    if wrapped {
                        t.feed(b"x\x1b[1;4H\x1b[?7l");
                        // Refused wide input sets pending wrap without
                        // replacing the wrapped last-column cell.
                        t.feed("界".as_bytes());
                    }
                    t.feed("\u{302}".as_bytes());
                    t.feed(b"\x1b[2;2H\x1b7\x1b[2;3H");
                    t.feed(if wrap_enabled {
                        b"\x1b[?7h"
                    } else {
                        b"\x1b[?7l"
                    });
                    let mut other = TerminalCore::with_replay(4, 2);
                    other.feed(&t.replay().unwrap());
                    assert_eq!(
                        t.snapshot(),
                        other.snapshot(),
                        "alt={alternate} wrapped={wrapped} wrap={wrap_enabled}"
                    );
                    for bytes in [
                        b"\x1b[3b".as_slice(),
                        b"\x1b8",
                        "z界".as_bytes(),
                        b"\x1b[2b",
                    ] {
                        t.feed(bytes);
                        other.feed(bytes);
                        assert_eq!(t.snapshot(), other.snapshot());
                    }
                }
            }
        }
    }

    #[test]
    fn combining_caps_apply_to_split_utf8_and_synchronized_update_flush() {
        let mut t = TerminalCore::with_replay(2, 1);
        t.feed(b"\x1b[?2026h");
        t.feed(b"a");
        for byte in "\u{301}".repeat(100_000).as_bytes() {
            t.feed(&[*byte]);
        }
        let replay = t.replay().unwrap(); // stop_sync flushes the buffered input.
        assert_eq!(
            t.term.grid()[Line(0)][Column(0)].zerowidth().unwrap().len(),
            16
        );
        let mut other = TerminalCore::with_replay(2, 1);
        other.feed(&replay);
        assert_eq!(t.snapshot(), other.snapshot());
    }

    #[test]
    fn hyperlink_boundaries_and_malformed_chunks() {
        for (id, uri_len, accepted) in [
            ("id=x", 4095, true),
            ("id=x", 4096, false),
            ("", 4077, true),
            ("", 4078, false),
        ] {
            let mut t = TerminalCore::new(2, 1);
            let bytes = format!("\x1b]8;{id};{}\x07", "u".repeat(uri_len));
            for byte in bytes.as_bytes() {
                t.feed(&[*byte]);
            }
            let link = t.term.grid().cursor.template.hyperlink();
            assert_eq!(link.is_some(), accepted, "{id} {uri_len}");
            if let Some(link) = link {
                assert!(link.id().len() + link.uri().len() <= 4096);
            }
            t.feed(b"\x1b]8;id=bad;\xff\x07");
            t.feed(b"\x1b]8;;\x07");
            assert!(t.term.grid().cursor.template.hyperlink().is_none());
        }
    }

    #[test]
    fn oversized_hyperlink_clears_the_pen() {
        let mut t = TerminalCore::new(2, 1);
        t.feed(b"\x1b]8;id=ok;ok\x07");
        t.feed(format!("\x1b]8;id=x;{}\x07", "u".repeat(4096)).as_bytes());
        assert!(t.term.grid().cursor.template.hyperlink().is_none());
    }
}

#[cfg(test)]
mod complete_cell_tests {
    use super::*;
    #[test]
    fn complete_cell_suffix_is_bounded_validated_and_copyable() {
        let mut suffix = CombiningMarks::default();
        assert!(!suffix.push('x'));
        assert!(!suffix.push('\0'));
        for _ in 0..MAX_COMBINING_MARKS {
            assert!(suffix.push('\u{301}'));
        }
        assert!(!suffix.push('\u{302}'));
        assert_eq!(suffix.as_slice(), &['\u{301}'; MAX_COMBINING_MARKS]);
        let mut cell = Cell::blank();
        cell.combining = suffix;
        assert!(!cell.is_blank());
        assert!(!cell.contents_match(&Cell::blank()));
        let copied = cell;
        cell.set_char('x');
        assert!(cell.combining.is_empty());
        assert_eq!(copied.combining, suffix);
        let bytes = std::mem::size_of::<Cell>();
        eprintln!("public Cell={bytes}, inline suffix={}, frame cell backing: 80x24={}, 200x60={}, 512x256={}", std::mem::size_of::<CombiningMarks>(), bytes*80*24, bytes*200*60, bytes*512*256);
        assert!(!std::mem::needs_drop::<Cell>());
    }

    #[test]
    fn complete_cell_history_frame_retains_text_and_hidden() {
        let mut terminal = TerminalCore::with_replay(12, 3);
        terminal.feed("\x1b[8me\u{301}\x1b[0m\r\na\r\nb\r\nc".as_bytes());
        terminal.scroll(1);
        let frame = terminal.frame();
        assert_eq!(frame.cells[0].ch, 'e');
        assert_eq!(frame.cells[0].combining.as_slice(), &['\u{301}']);
        assert_ne!(frame.cells[0].flags & FLAG_HIDDEN, 0);
    }
}
