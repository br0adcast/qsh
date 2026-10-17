//! The emulator state a replay needs and `alacritty_terminal` keeps to itself.
//!
//! `Term` keeps the scroll region, the active character set and the tab
//! stops in private fields, and `vte`'s `Processor` keeps the last printed
//! character (what `CSI b`, REP, repeats) and its own parse state. Every byte
//! that reaches the emulator afterwards is read against that state, so a
//! replay that does not restore it leaves a client that draws the same
//! screen and then parses the next bytes differently. [`Tracking`] sits
//! between the parser and the `Term`: every call goes through to the `Term`
//! unchanged, and the few that touch private state are also recorded in
//! [`Tracked`], by the same rule the `Term` applies (`alacritty_terminal`
//! 0.26, pinned exactly). [`PendingSequence`] keeps the bytes of an escape
//! sequence (or UTF-8 character) the input has started and not finished.

use std::ops::Range;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::Term;
use alacritty_terminal::vte::ansi::cursor_icon::CursorIcon;
use alacritty_terminal::vte::ansi::{
    Attr, CharsetIndex, ClearMode, CursorShape, CursorStyle, Handler, Hyperlink, KeyboardModes,
    KeyboardModesApplyBehavior, LineClearMode, Mode, ModifyOtherKeys, NamedPrivateMode,
    PrivateMode, Rgb, ScpCharPath, ScpUpdateMode, StandardCharset, TabulationClearMode,
};
use alacritty_terminal::vte::{Params, Parser, Perform};

/// Where `Term` puts a tab stop by default: every eighth column, the first
/// one included (`INITIAL_TABSTOPS` in `alacritty_terminal`).
const TAB_INTERVAL: usize = 8;

/// State `Term` keeps privately, mirrored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tracked {
    /// DECSTBM: screen lines `[start, end)`, exactly as `Term::scroll_region`.
    pub scroll_region: Range<i32>,
    /// Which of G0-G3 printable ASCII is mapped through (SI/SO).
    pub active_charset: CharsetIndex,
    /// One flag per column.
    pub tabs: Vec<bool>,
    /// The last character handed to `Term::input` -- exactly what `vte`'s
    /// `Processor` repeats on `CSI b`: it records the printed character and
    /// nothing else ever changes it.
    pub last_input: Option<char>,
}

impl Tracked {
    pub fn new(columns: usize, lines: usize) -> Tracked {
        Tracked {
            scroll_region: 0..lines as i32,
            active_charset: CharsetIndex::G0,
            tabs: default_tabs(0, columns).collect(),
            last_input: None,
        }
    }

    /// `Term::resize` to `columns` x `lines` from `old_columns` x
    /// `old_lines`: the region goes back to the full screen, and the tab
    /// stops are cut, or extended by the default ones, only when the width
    /// changed. Nothing at all happens when neither did.
    pub fn resize(&mut self, old_columns: usize, old_lines: usize, columns: usize, lines: usize) {
        if old_columns == columns && old_lines == lines {
            return;
        }
        if old_columns != columns {
            let kept = self.tabs.len().min(columns);
            self.tabs.truncate(kept);
            self.tabs.extend(default_tabs(kept, columns));
        }
        self.scroll_region = 0..lines as i32;
    }

    fn reset(&mut self, columns: usize, lines: usize) {
        let last_input = self.last_input;
        *self = Tracked::new(columns, lines);
        self.last_input = last_input;
    }
}

/// The default tab stops of columns `from..to`.
fn default_tabs(from: usize, to: usize) -> impl Iterator<Item = bool> {
    (from..to).map(|i| i % TAB_INTERVAL == 0)
}

/// The `Handler` the parser drives: the `Term`, with [`Tracked`] kept up to
/// date alongside. Every method of the trait is forwarded -- a method the
/// trait gives a default body and this impl forgot would silently do nothing
/// -- so the list below is the trait's, in its order.
pub(crate) struct Tracking<'a> {
    pub term: &'a mut Term<VoidListener>,
    pub tracked: &'a mut Tracked,
}

impl Handler for Tracking<'_> {
    fn set_title(&mut self, title: Option<String>) {
        self.term.set_title(title)
    }
    fn set_cursor_style(&mut self, style: Option<CursorStyle>) {
        self.term.set_cursor_style(style)
    }
    fn set_cursor_shape(&mut self, shape: CursorShape) {
        self.term.set_cursor_shape(shape)
    }
    fn input(&mut self, c: char) {
        self.term.input(c);
        self.tracked.last_input = Some(c);
    }
    fn goto(&mut self, line: i32, col: usize) {
        self.term.goto(line, col)
    }
    fn goto_line(&mut self, line: i32) {
        self.term.goto_line(line)
    }
    fn goto_col(&mut self, col: usize) {
        self.term.goto_col(col)
    }
    fn insert_blank(&mut self, count: usize) {
        self.term.insert_blank(count)
    }
    fn move_up(&mut self, lines: usize) {
        self.term.move_up(lines)
    }
    fn move_down(&mut self, lines: usize) {
        self.term.move_down(lines)
    }
    fn identify_terminal(&mut self, intermediate: Option<char>) {
        self.term.identify_terminal(intermediate)
    }
    fn device_status(&mut self, arg: usize) {
        self.term.device_status(arg)
    }
    fn move_forward(&mut self, col: usize) {
        self.term.move_forward(col)
    }
    fn move_backward(&mut self, col: usize) {
        self.term.move_backward(col)
    }
    fn move_down_and_cr(&mut self, row: usize) {
        self.term.move_down_and_cr(row)
    }
    fn move_up_and_cr(&mut self, row: usize) {
        self.term.move_up_and_cr(row)
    }
    fn put_tab(&mut self, count: u16) {
        self.term.put_tab(count)
    }
    fn backspace(&mut self) {
        self.term.backspace()
    }
    fn carriage_return(&mut self) {
        self.term.carriage_return()
    }
    fn linefeed(&mut self) {
        self.term.linefeed()
    }
    fn bell(&mut self) {
        self.term.bell()
    }
    fn substitute(&mut self) {
        self.term.substitute()
    }
    fn newline(&mut self) {
        self.term.newline()
    }
    fn set_horizontal_tabstop(&mut self) {
        let column = self.term.grid().cursor.point.column.0;
        self.term.set_horizontal_tabstop();
        self.tracked.tabs[column] = true;
    }
    fn scroll_up(&mut self, lines: usize) {
        self.term.scroll_up(lines)
    }
    fn scroll_down(&mut self, lines: usize) {
        self.term.scroll_down(lines)
    }
    fn insert_blank_lines(&mut self, lines: usize) {
        self.term.insert_blank_lines(lines)
    }
    fn delete_lines(&mut self, lines: usize) {
        self.term.delete_lines(lines)
    }
    fn erase_chars(&mut self, count: usize) {
        self.term.erase_chars(count)
    }
    fn delete_chars(&mut self, count: usize) {
        self.term.delete_chars(count)
    }
    fn move_backward_tabs(&mut self, count: u16) {
        self.term.move_backward_tabs(count)
    }
    fn move_forward_tabs(&mut self, count: u16) {
        self.term.move_forward_tabs(count)
    }
    fn save_cursor_position(&mut self) {
        self.term.save_cursor_position()
    }
    fn restore_cursor_position(&mut self) {
        self.term.restore_cursor_position()
    }
    fn clear_line(&mut self, mode: LineClearMode) {
        self.term.clear_line(mode)
    }
    fn clear_screen(&mut self, mode: ClearMode) {
        self.term.clear_screen(mode)
    }
    fn clear_tabs(&mut self, mode: TabulationClearMode) {
        let column = self.term.grid().cursor.point.column.0;
        match mode {
            TabulationClearMode::Current => self.tracked.tabs[column] = false,
            TabulationClearMode::All => self.tracked.tabs.iter_mut().for_each(|t| *t = false),
        }
        self.term.clear_tabs(mode);
    }
    fn set_tabs(&mut self, interval: u16) {
        self.term.set_tabs(interval)
    }
    fn reset_state(&mut self) {
        self.term.reset_state();
        self.tracked
            .reset(self.term.columns(), self.term.screen_lines());
    }
    fn reverse_index(&mut self) {
        self.term.reverse_index()
    }
    fn terminal_attribute(&mut self, attr: Attr) {
        self.term.terminal_attribute(attr)
    }
    fn set_mode(&mut self, mode: Mode) {
        self.term.set_mode(mode)
    }
    fn unset_mode(&mut self, mode: Mode) {
        self.term.unset_mode(mode)
    }
    fn report_mode(&mut self, mode: Mode) {
        self.term.report_mode(mode)
    }
    fn set_private_mode(&mut self, mode: PrivateMode) {
        self.note_column_mode(mode);
        self.term.set_private_mode(mode)
    }
    fn unset_private_mode(&mut self, mode: PrivateMode) {
        self.note_column_mode(mode);
        self.term.unset_private_mode(mode)
    }
    fn report_private_mode(&mut self, mode: PrivateMode) {
        self.term.report_private_mode(mode)
    }
    fn set_scrolling_region(&mut self, top: usize, bottom: Option<usize>) {
        self.note_scrolling_region(top, bottom);
        self.term.set_scrolling_region(top, bottom)
    }
    fn set_keypad_application_mode(&mut self) {
        self.term.set_keypad_application_mode()
    }
    fn unset_keypad_application_mode(&mut self) {
        self.term.unset_keypad_application_mode()
    }
    fn set_active_charset(&mut self, index: CharsetIndex) {
        self.term.set_active_charset(index);
        self.tracked.active_charset = index;
    }
    fn configure_charset(&mut self, index: CharsetIndex, charset: StandardCharset) {
        self.term.configure_charset(index, charset)
    }
    fn set_color(&mut self, index: usize, color: Rgb) {
        self.term.set_color(index, color)
    }
    fn dynamic_color_sequence(&mut self, prefix: String, index: usize, terminator: &str) {
        self.term.dynamic_color_sequence(prefix, index, terminator)
    }
    fn reset_color(&mut self, index: usize) {
        self.term.reset_color(index)
    }
    fn clipboard_store(&mut self, clipboard: u8, base64: &[u8]) {
        self.term.clipboard_store(clipboard, base64)
    }
    fn clipboard_load(&mut self, clipboard: u8, terminator: &str) {
        self.term.clipboard_load(clipboard, terminator)
    }
    fn decaln(&mut self) {
        self.term.decaln()
    }
    fn push_title(&mut self) {
        self.term.push_title()
    }
    fn pop_title(&mut self) {
        self.term.pop_title()
    }
    fn text_area_size_pixels(&mut self) {
        self.term.text_area_size_pixels()
    }
    fn text_area_size_chars(&mut self) {
        self.term.text_area_size_chars()
    }
    fn set_hyperlink(&mut self, hyperlink: Option<Hyperlink>) {
        self.term.set_hyperlink(hyperlink)
    }
    fn set_mouse_cursor_icon(&mut self, icon: CursorIcon) {
        self.term.set_mouse_cursor_icon(icon)
    }
    fn report_keyboard_mode(&mut self) {
        self.term.report_keyboard_mode()
    }
    fn push_keyboard_mode(&mut self, mode: KeyboardModes) {
        self.term.push_keyboard_mode(mode)
    }
    fn pop_keyboard_modes(&mut self, to_pop: u16) {
        self.term.pop_keyboard_modes(to_pop)
    }
    fn set_keyboard_mode(&mut self, mode: KeyboardModes, behavior: KeyboardModesApplyBehavior) {
        Handler::set_keyboard_mode(self.term, mode, behavior)
    }
    fn set_modify_other_keys(&mut self, mode: ModifyOtherKeys) {
        self.term.set_modify_other_keys(mode)
    }
    fn report_modify_other_keys(&mut self) {
        self.term.report_modify_other_keys()
    }
    fn set_scp(&mut self, char_path: ScpCharPath, update_mode: ScpUpdateMode) {
        self.term.set_scp(char_path, update_mode)
    }
}

impl Tracking<'_> {
    /// `Term::set_scrolling_region`'s own rule: an empty or inverted region
    /// is ignored, both ends are clamped to the screen.
    fn note_scrolling_region(&mut self, top: usize, bottom: Option<usize>) {
        let lines = self.term.screen_lines();
        let bottom = bottom.unwrap_or(lines);
        if top >= bottom {
            return;
        }
        let lines = lines as i32;
        let start = (top as i32 - 1).min(lines);
        let end = (bottom as i32).min(lines);
        self.tracked.scroll_region = start..end;
    }

    /// DECCOLM (`?3`), set or reset: `Term` ignores the width but clears the
    /// screen and resets the region, which is what matters here.
    fn note_column_mode(&mut self, mode: PrivateMode) {
        if mode == PrivateMode::Named(NamedPrivateMode::ColumnMode) {
            self.tracked.scroll_region = 0..self.term.screen_lines() as i32;
        }
    }
}

/// The bytes of an escape sequence or UTF-8 character the input has begun
/// and not yet finished, so a replay can hand them to the client too and
/// leave its parser exactly where the model's is: the next bytes then finish
/// the same sequence on both.
///
/// Why "since the last ESC" is enough: `vte`'s parser enters the escape
/// state on ESC from every state (a string it was in ends, parameters are
/// reset), so from the last ESC on its path depends on nothing before it.
/// Whether it is still inside something at the end is asked of a fresh
/// parser fed the same bytes (see [`classify`]).
#[derive(Debug)]
pub(crate) struct PendingSequence {
    /// The input from its last ESC on -- or, when `ground`, at most the
    /// start of a UTF-8 character.
    bytes: Vec<u8>,
    /// The parser was found in its ground state and no ESC came since. Then
    /// it still is: only an ESC leads out of it (vte takes no 8-bit C1
    /// introducers), so all an ESC-free chunk can leave behind is the start
    /// of a UTF-8 character in its last three bytes -- no parse needed.
    ground: bool,
    /// When `bytes` grows past this, look again and drop what is finished.
    check_at: usize,
    /// A sequence ran past [`MAX_PENDING`]: what the parser is inside is not
    /// known any more, until the next ESC.
    lost: bool,
}

impl Default for PendingSequence {
    fn default() -> PendingSequence {
        PendingSequence {
            bytes: Vec::new(),
            // A new parser starts in its ground state.
            ground: true,
            check_at: CHECK_INTERVAL,
            lost: false,
        }
    }
}

/// A check is due when this much input has accumulated past the last one.
const CHECK_INTERVAL: usize = 4096;
/// The longest unfinished sequence kept. Only a string (OSC, DCS) gets this
/// long; a replay cut inside a longer one leaves the client outside it.
const MAX_PENDING: usize = 1 << 20;

impl PendingSequence {
    pub fn push(&mut self, chunk: &[u8]) {
        match memchr::memrchr(0x1b, chunk) {
            Some(at) => {
                self.bytes.clear();
                self.bytes.extend_from_slice(&chunk[at..]);
                self.lost = false;
                self.ground = false;
                self.check_at = CHECK_INTERVAL;
            }
            None if self.lost => return,
            None if self.ground => {
                if chunk.len() >= 3 {
                    self.bytes.clear();
                }
                self.bytes
                    .extend_from_slice(&chunk[chunk.len().saturating_sub(3)..]);
                let from = self.bytes.len() - unfinished_utf8(&self.bytes);
                self.bytes.drain(..from);
                return;
            }
            None => self.bytes.extend_from_slice(chunk),
        }
        if self.bytes.len() > self.check_at {
            self.trim();
        }
    }

    /// The unfinished part, possibly empty.
    pub fn tail(&self) -> &[u8] {
        if self.lost {
            return &[];
        }
        match classify(&self.bytes) {
            State::Ground => &[],
            State::InUtf8(n) => &self.bytes[self.bytes.len() - n..],
            State::InSequence => &self.bytes,
        }
    }

    fn trim(&mut self) {
        match classify(&self.bytes) {
            State::Ground => {
                self.bytes.clear();
                self.ground = true;
            }
            State::InUtf8(n) => {
                let from = self.bytes.len() - n;
                self.bytes.drain(..from);
                self.ground = true;
            }
            State::InSequence if self.bytes.len() > MAX_PENDING => {
                self.bytes = Vec::new();
                self.lost = true;
            }
            State::InSequence => {}
        }
        self.check_at = (self.bytes.len() * 2).max(CHECK_INTERVAL);
    }
}

/// Where a parser that started in its ground state stands after some bytes.
#[derive(Debug, PartialEq, Eq)]
enum State {
    Ground,
    /// In its ground state, but inside a UTF-8 character: this many of its
    /// bytes have come.
    InUtf8(usize),
    /// Inside an escape sequence or a string.
    InSequence,
}

/// Feed `bytes` to a fresh parser, then one `A`: in the ground state that
/// prints the `A` and nothing else; after the lead bytes of a UTF-8
/// character it prints a replacement character first; inside anything else
/// it prints nothing (it ends, extends or dispatches the sequence).
fn classify(bytes: &[u8]) -> State {
    let mut parser: Parser = Parser::new();
    let mut probe = Probe::default();
    parser.advance(&mut probe, bytes);
    probe.calls.clear();
    parser.advance(&mut probe, b"A");
    match probe.calls.as_slice() {
        [Call::Print('A')] => State::Ground,
        [Call::Print(char::REPLACEMENT_CHARACTER), Call::Print('A')] => {
            State::InUtf8(unfinished_utf8(bytes))
        }
        _ => State::InSequence,
    }
}

/// How many bytes at the end of `bytes` begin a UTF-8 character that has not
/// been finished (0 if none do).
fn unfinished_utf8(bytes: &[u8]) -> usize {
    for n in 1..=3.min(bytes.len()) {
        let tail = &bytes[bytes.len() - n..];
        if let Err(e) = std::str::from_utf8(tail) {
            if e.valid_up_to() == 0 && e.error_len().is_none() {
                return n;
            }
        }
    }
    0
}

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Print(char),
    Other,
}

#[derive(Default)]
struct Probe {
    calls: Vec<Call>,
}

impl Perform for Probe {
    fn print(&mut self, c: char) {
        self.calls.push(Call::Print(c));
    }
    fn execute(&mut self, _byte: u8) {
        self.calls.push(Call::Other);
    }
    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {
        self.calls.push(Call::Other);
    }
    fn put(&mut self, _byte: u8) {
        self.calls.push(Call::Other);
    }
    fn unhook(&mut self) {
        self.calls.push(Call::Other);
    }
    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {
        self.calls.push(Call::Other);
    }
    fn csi_dispatch(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _c: char) {
        self.calls.push(Call::Other);
    }
    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, _byte: u8) {
        self.calls.push(Call::Other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tail_after(chunks: &[&[u8]]) -> Vec<u8> {
        let mut p = PendingSequence::default();
        for c in chunks {
            p.push(c);
        }
        p.tail().to_vec()
    }

    #[test]
    fn nothing_is_pending_after_complete_sequences_and_text() {
        assert!(tail_after(&[b"abc\x1b[31mdef\x1b[0m"]).is_empty());
        assert!(tail_after(&[b"\x1b]0;title\x07after"]).is_empty());
        assert!(tail_after(&[b"\x1b(0lqqk\x1b(B"]).is_empty());
    }

    #[test]
    fn an_unfinished_escape_is_pending_across_chunks() {
        assert_eq!(tail_after(&[b"text\x1b[3"]), b"\x1b[3");
        assert_eq!(tail_after(&[b"text\x1b[", b"1;2"]), b"\x1b[1;2");
        assert_eq!(tail_after(&[b"text\x1b("]), b"\x1b(");
        assert_eq!(
            tail_after(&[b"\x1b]0;half a ti", b"tle"]),
            b"\x1b]0;half a title"
        );
        assert_eq!(tail_after(&[b"\x1b[3", b"1m"]), b"");
    }

    #[test]
    fn an_unfinished_utf8_character_is_pending() {
        assert_eq!(tail_after(&[b"price: \xE2\x82"]), b"\xE2\x82");
        assert_eq!(tail_after(&[b"\x1b[0mprice: \xE2"]), b"\xE2");
        assert!(tail_after(&[b"price: \xE2\x82\xAC"]).is_empty());
    }

    #[test]
    fn a_long_run_of_text_is_trimmed_away() {
        let mut p = PendingSequence::default();
        p.push(b"\x1b[0m");
        for _ in 0..100 {
            p.push(&[b'x'; 1000]);
        }
        assert!(p.bytes.len() < 2 * CHECK_INTERVAL, "{}", p.bytes.len());
        assert!(p.tail().is_empty());
    }

    /// In the ground state an ESC-free chunk costs no parse: what stays is
    /// at most the start of a UTF-8 character, carried across chunks.
    #[test]
    fn text_without_escapes_keeps_at_most_an_unfinished_character() {
        let mut p = PendingSequence::default();
        p.push(b"plain text \xe2");
        assert_eq!(p.bytes, b"\xe2");
        p.push(b"\x82");
        assert_eq!(p.tail(), b"\xe2\x82");
        p.push(b"\xac more");
        assert!(p.bytes.is_empty() && p.tail().is_empty());
        p.push(b"\x1b[0mback to text");
        for _ in 0..10 {
            p.push(&[b'x'; 1000]);
        }
        assert!(p.ground, "a check found the ground state again");
        p.push(&[b'y'; 100_000]);
        assert!(p.bytes.len() <= 3);
    }

    #[test]
    fn a_control_that_cancels_ends_the_sequence() {
        assert!(tail_after(&[b"\x1b[3\x18rest"]).is_empty());
    }
}
