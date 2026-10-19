//! The connection-state and help windows: pure rows, keys and cells.
//!
//! The rules mirror the app's `ConnectionStateDialog` (`roadRow`, `roadDot`,
//! `canSwitch`). Nothing here touches the session or the terminal; the
//! session paints a [`Boxed`] over a copy of the frame.

use std::net::SocketAddr;

use terminal::{Cell, Color, FLAG_BOLD, FLAG_DIM, FLAG_REVERSE};
use transport::paths::PathState;

use crate::escape;
use crate::statusline::{human_age, Link};

/// One road as the transport reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub addr: SocketAddr,
    pub label: String,
    pub in_use: bool,
    pub state: PathState,
    pub ewma_ms: Option<u32>,
    pub failed_ago_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dot {
    InUse,
    Spare,
    Silent,
}

/// One line of the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub in_use: bool,
    pub value: String,
    pub dot: Dot,
    pub can_switch: bool,
}

/// A road's row. The road in use is judged by the connection's own link (the
/// header, the overlay and this row turn over together); a road that stopped
/// answering shows its silence, not the stale round trip the table holds.
pub fn row(road: &Road, link: &Link) -> Row {
    let (value, dot) = match link {
        Link::Latency { ms } if road.in_use => (format!("{ms} ms"), Dot::InUse),
        Link::Silent { secs } if road.in_use => {
            (format!("silent {}", human_age(*secs)), Dot::Silent)
        }
        _ => match (road.state, road.ewma_ms) {
            (PathState::Dead, _) => (
                match road.failed_ago_ms {
                    Some(ms) => format!("silent {}", human_age(u64::from(ms / 1000))),
                    None => "silent".to_string(),
                },
                if road.in_use { Dot::InUse } else { Dot::Silent },
            ),
            (PathState::Verified, Some(ms)) => (
                format!("{ms} ms"),
                if road.in_use { Dot::InUse } else { Dot::Spare },
            ),
            _ => (
                "checking".to_string(),
                if road.in_use { Dot::InUse } else { Dot::Spare },
            ),
        },
    };
    Row {
        label: road.label.clone(),
        in_use: road.in_use,
        value,
        dot,
        can_switch: !road.in_use && road.state == PathState::Verified,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Pick(usize),
    Enter,
    Close,
    Other,
}

/// Splits a chunk of input into window keys, and says how many bytes at its
/// end are a key sequence cut off by the end of the chunk: those are not
/// read, for the caller to hand back in front of the next chunk.
pub fn keys(bytes: &[u8]) -> (Vec<Key>, usize) {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1b if matches!(bytes.get(i + 1), Some(b'[' | b'O')) => {
                // A key sequence is one key, whatever its length: the
                // digits of `ESC [ 1 5 ~` must not pick rows.
                let Some(len) = escape::sequence_len(&bytes[i..]) else {
                    return (out, bytes.len() - i);
                };
                out.push(match &bytes[i + 1..i + len] {
                    [b'[' | b'O', b'A'] => Key::Up,
                    [b'[' | b'O', b'B'] => Key::Down,
                    _ => Key::Other,
                });
                i += len;
            }
            // A lone ESC: the end of the chunk, or not a sequence start.
            0x1b => {
                out.push(Key::Close);
                i += 1;
            }
            b @ b'1'..=b'8' => {
                out.push(Key::Pick(usize::from(b - b'1')));
                i += 1;
            }
            b'\r' | b'\n' => {
                out.push(Key::Enter);
                i += 1;
            }
            b'q' => {
                out.push(Key::Close);
                i += 1;
            }
            _ => {
                out.push(Key::Other);
                i += 1;
            }
        }
    }
    (out, 0)
}

/// The window's state: the selected row and the switch under way, if any.
#[derive(Debug, Clone, Default)]
pub struct Roads {
    pub selected: usize,
    pub switching: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Stay,
    Close,
    Switch(usize),
}

impl Roads {
    pub fn new() -> Roads {
        Roads::default()
    }

    pub fn on_key(&mut self, key: Key, rows: &[Row]) -> Outcome {
        match key {
            Key::Up => {
                self.selected = self.selected.saturating_sub(1);
                Outcome::Stay
            }
            Key::Down => {
                if self.selected + 1 < rows.len() {
                    self.selected += 1;
                }
                Outcome::Stay
            }
            Key::Pick(n) => {
                if n < rows.len() {
                    self.selected = n;
                }
                Outcome::Stay
            }
            Key::Enter => match rows.get(self.selected) {
                Some(row) if self.switching.is_none() && row.can_switch => {
                    self.switching = Some(self.selected);
                    Outcome::Switch(self.selected)
                }
                _ => Outcome::Stay,
            },
            Key::Close => Outcome::Close,
            Key::Other => Outcome::Stay,
        }
    }
}

/// How the box is drawn.
#[derive(Debug, Clone, Copy)]
pub struct Glyphs {
    pub utf8: bool,
    pub colour: bool,
}

/// UTF-8 when the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG` says so.
pub fn utf8_locale(lc_all: Option<&str>, lc_ctype: Option<&str>, lang: Option<&str>) -> bool {
    [lc_all, lc_ctype, lang]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

/// A box to paint over the frame: `lines` start at (`top`, `left`).
#[derive(Debug, Clone)]
pub struct Boxed {
    pub top: u16,
    pub left: u16,
    pub lines: Vec<Vec<Cell>>,
}

const MIN_COLS: u16 = 8;
const MIN_HEIGHT: u16 = 3;

fn plain(ch: char) -> Cell {
    Cell {
        ch,
        fg: Color::Default,
        bg: Color::Default,
        combining: Default::default(),
        flags: 0,
    }
}

fn cells(text: &str) -> Vec<Cell> {
    crate::statusline::text_cells(text, true)
}

struct Frame {
    horizontal: char,
    vertical: char,
    corners: [char; 4],
}

impl Frame {
    fn of(g: Glyphs) -> Frame {
        if g.utf8 && g.colour {
            Frame {
                horizontal: '─',
                vertical: '│',
                corners: ['╭', '╮', '╰', '╯'],
            }
        } else if g.utf8 {
            Frame {
                horizontal: '═',
                vertical: '║',
                corners: ['╔', '╗', '╚', '╝'],
            }
        } else {
            Frame {
                horizontal: '=',
                vertical: '|',
                corners: ['+', '+', '+', '+'],
            }
        }
    }
}

fn vertical_padding(height: u16) -> usize {
    usize::from(height >= 5)
}

/// Number of visible road rows, after borders and vertical padding.
pub fn road_capacity(cols: u16, height: u16) -> usize {
    let size = terminal_size::ViewportSize::new(cols, height);
    let (cols, height) = (size.cols(), size.rows());
    if cols < MIN_COLS || height < MIN_HEIGHT {
        0
    } else {
        usize::from(height) - 2 - 2 * vertical_padding(height)
    }
}

/// Frames content with two columns of padding, clipped inside intact borders.
fn frame(
    title: &str,
    hint: &str,
    body: Vec<Vec<Cell>>,
    inner: usize,
    cols: u16,
    height: u16,
    g: Glyphs,
) -> Boxed {
    let f = Frame::of(g);
    let width = (inner + 6).max(44).min(usize::from(cols));
    let border_cell = |ch| Cell {
        fg: if g.colour {
            Color::Indexed(6)
        } else {
            Color::Default
        },
        ..plain(ch)
    };
    let border = |text: &str, lower: bool| {
        let mut line = vec![border_cell(f.horizontal); width];
        let corners = if lower { 2 } else { 0 };
        line[0] = border_cell(f.corners[corners]);
        line[width - 1] = border_cell(f.corners[corners + 1]);
        let text: Vec<char> = format!(" {text} ").chars().take(width - 4).collect();
        let start = if lower { width - 2 - text.len() } else { 2 };
        for (cell, ch) in line[start..].iter_mut().zip(text) {
            cell.ch = ch;
            if !lower {
                cell.flags |= FLAG_BOLD;
            }
        }
        line
    };
    let body_line = |content: &[Cell]| {
        let mut line = vec![plain(' '); width];
        line[0] = border_cell(f.vertical);
        line[width - 1] = border_cell(f.vertical);
        for (cell, source) in line[3..width - 3].iter_mut().zip(content) {
            *cell = *source;
        }
        line
    };
    let padding = vertical_padding(height);
    let mut lines = vec![border(title, false)];
    if padding > 0 {
        lines.push(body_line(&[]));
    }
    for content in body.into_iter().take(road_capacity(cols, height)) {
        lines.push(body_line(&content));
    }
    if padding > 0 {
        lines.push(body_line(&[]));
    }
    lines.push(border(hint, true));
    Boxed {
        top: (height - lines.len() as u16) / 2,
        left: (cols - width as u16) / 2,
        lines,
    }
}

fn dot_cell(dot: Dot, g: Glyphs) -> Cell {
    let ch = if g.utf8 { '●' } else { '*' };
    let mut cell = plain(ch);
    if g.colour {
        match dot {
            Dot::InUse => cell.fg = Color::Indexed(6),
            Dot::Spare => {
                cell.fg = Color::Indexed(6);
                cell.flags = FLAG_DIM;
            }
            Dot::Silent => cell.fg = Color::Indexed(1),
        }
    } else {
        match dot {
            Dot::InUse => cell.flags = FLAG_BOLD,
            Dot::Spare => cell.flags = FLAG_DIM,
            Dot::Silent => cell.ch = 'x',
        }
    }
    cell
}

/// The connection-state window, or `None` when the terminal is too small.
pub fn roads_box(rows: &[Row], state: &Roads, cols: u16, height: u16, g: Glyphs) -> Option<Boxed> {
    let size = terminal_size::ViewportSize::new(cols, height);
    let (cols, height) = (size.cols(), size.rows());
    if cols < MIN_COLS || height < MIN_HEIGHT {
        return None;
    }
    let shown = rows.len().min(road_capacity(cols, height));
    let rows = &rows[..shown];
    let value_of = |i: usize| -> &str {
        if state.switching == Some(i) {
            "switching"
        } else {
            rows[i].value.as_str()
        }
    };
    let value_width = (0..shown)
        .map(|i| value_of(i).chars().count())
        .max()
        .unwrap_or(0);
    let mut addr_width = rows
        .iter()
        .map(|r| crate::statusline::text_cells(&r.label, g.utf8).len())
        .max()
        .unwrap_or(0);
    // Dot, space, address, two spaces, "in use", two spaces, value.
    let inner_of = |a: usize| a + value_width + 12;
    while addr_width > 0 && inner_of(addr_width) + 6 > usize::from(cols) {
        addr_width -= 1;
    }
    let inner = inner_of(addr_width);
    let body = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut label = crate::statusline::text_cells(&r.label, g.utf8);
            label.truncate(addr_width);
            label.resize(addr_width, plain(' '));
            if let Some(last) = label.last_mut() {
                if last.flags & terminal::FLAG_WIDE != 0 {
                    *last = plain(' ');
                }
            }
            let mut line = vec![dot_cell(r.dot, g), plain(' ')];
            line.extend(label);
            let kind = if r.in_use { "in use" } else { "spare " };
            line.extend(cells(&format!("  {kind}  ")));
            let value = value_of(i);
            line.extend(cells(&format!("{value:>value_width$}")));
            if i == state.selected {
                for cell in &mut line {
                    cell.flags |= FLAG_REVERSE;
                }
            }
            line
        })
        .collect();
    let hint = if g.utf8 {
        "↑↓ choose · Enter use · Esc close"
    } else {
        "up/down choose | Enter use | Esc close"
    };
    Some(frame(
        "Connection state",
        hint,
        body,
        inner,
        cols,
        height,
        g,
    ))
}

/// Wrapped recovery details are read-only. Selection is a line viewport, not
/// an address index; Enter must never turn a diagnostic into a road switch.
pub fn recovery_lines(details: &[String], cols: u16, utf8: bool) -> Vec<Vec<Cell>> {
    let cols = terminal_size::ViewportSize::new(cols, 0).cols();
    let width = usize::from(cols.saturating_sub(6)).max(2);
    let mut rows = Vec::new();
    for text in details {
        let cells = crate::statusline::text_cells(text, utf8);
        let mut rest = cells.as_slice();
        if rest.is_empty() {
            rows.push(Vec::new());
        }
        while !rest.is_empty() {
            let mut end = rest.len().min(width);
            if rest[end - 1].flags & terminal::FLAG_WIDE != 0 {
                end -= 1;
            }
            rows.push(rest[..end].to_vec());
            rest = &rest[end..];
        }
    }
    rows
}

pub fn recovery_box(
    details: &[String],
    state: &Roads,
    cols: u16,
    height: u16,
    g: Glyphs,
) -> Option<Boxed> {
    if cols < MIN_COLS || height < MIN_HEIGHT {
        return None;
    }
    let size = terminal_size::ViewportSize::new(cols, height);
    let (cols, height) = (size.cols(), size.rows());
    let all = recovery_lines(details, cols, g.utf8);
    let capacity = road_capacity(cols, height);
    let start = state.selected.min(all.len().saturating_sub(capacity));
    let end = (start + capacity).min(all.len());
    let title = format!(
        "Recovery {}-{}/{}",
        start + usize::from(!all.is_empty()),
        end,
        all.len()
    );
    let hint = if g.utf8 {
        "↑↓ scroll · Esc close"
    } else {
        "up/down scroll | Esc close"
    };
    Some(frame(
        &title,
        hint,
        all[start..end].to_vec(),
        usize::from(cols) - 6,
        cols,
        height,
        g,
    ))
}

/// The help window, or `None` when the terminal is too small.
pub fn help_box(prefix_name: &str, cols: u16, height: u16, g: Glyphs) -> Option<Boxed> {
    let size = terminal_size::ViewportSize::new(cols, height);
    let (cols, height) = (size.cols(), size.rows());
    if cols < MIN_COLS || height < MIN_HEIGHT {
        return None;
    }
    let p = prefix_name;
    let entries = [
        (".", "leave; the session stays on the server".to_string()),
        ("s", "connection state".to_string()),
        ("h", "hide or show the status line".to_string()),
        ("r", "reconnect now".to_string()),
        ("[", "scroll history; q or Esc returns live".to_string()),
        ("?", "this help".to_string()),
        (p, format!("send {p} itself")),
    ];
    let key_width = p.chars().count() * 2 + 1;
    let body: Vec<Vec<Cell>> = entries
        .iter()
        .take(road_capacity(cols, height))
        .map(|(k, what)| {
            let mut line = cells(&format!("{:<key_width$}", format!("{p} {k}")));
            for c in &mut line {
                c.flags |= FLAG_BOLD;
            }
            line.extend(cells(&format!("  {what}")));
            line
        })
        .collect();
    let inner = body
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
        .max("Keys".chars().count() + 4);
    Some(frame("Keys", "Esc close", body, inner, cols, height, g))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statusline::Link;
    use transport::paths::PathState;

    fn road(
        label: &str,
        in_use: bool,
        state: PathState,
        ewma: Option<u32>,
        failed: Option<u32>,
    ) -> Road {
        Road {
            addr: "127.0.0.1:1".parse().unwrap(),
            label: label.into(),
            in_use,
            state,
            ewma_ms: ewma,
            failed_ago_ms: failed,
        }
    }

    #[test]
    fn oversized_layout_uses_bounded_top_left_viewport() {
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        for b in [
            help_box("Ctrl-]", 65535, 65535, g).unwrap(),
            recovery_box(&["details".into()], &Roads::new(), 65535, 65535, g).unwrap(),
        ] {
            assert!(usize::from(b.left) + b.lines[0].len() <= 512);
            assert!(usize::from(b.top) + b.lines.len() <= 257);
        }
    }

    #[test]
    fn recovery_details_scroll_past_the_visible_capacity() {
        let details: Vec<_> = (1..=20).map(|i| format!("target-{i}:60000")).collect();
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        let mut state = Roads::new();
        let first = recovery_box(&details, &state, 40, 8, g).unwrap();
        assert!(box_text(&first).join("\n").contains("target-1:"));
        state.selected = 19;
        let last = recovery_box(&details, &state, 40, 8, g).unwrap();
        assert!(box_text(&last).join("\n").contains("target-20:"));
        assert!(!box_text(&last).join("\n").contains("Enter use"));
        assert!(recovery_lines(&["界界界".into()], 8, true)
            .iter()
            .all(|line| line.len() <= 2));
    }

    #[test]
    fn rows_read_like_the_app_s() {
        let live = Link::Latency { ms: 42 };
        let r = row(
            &road("a:1", true, PathState::Verified, Some(99), None),
            &live,
        );
        assert_eq!(
            (r.value.as_str(), r.dot, r.can_switch),
            ("42 ms", Dot::InUse, false)
        );
        let r = row(
            &road("a:1", true, PathState::Verified, Some(99), None),
            &Link::Silent { secs: 7 },
        );
        assert_eq!((r.value.as_str(), r.dot), ("silent 7 s", Dot::Silent));
        let r = row(
            &road("b:1", false, PathState::Verified, Some(38), None),
            &live,
        );
        assert_eq!(
            (r.value.as_str(), r.dot, r.can_switch),
            ("38 ms", Dot::Spare, true)
        );
        let r = row(
            &road("c:1", false, PathState::Dead, Some(38), Some(125_000)),
            &live,
        );
        assert_eq!(
            (r.value.as_str(), r.dot, r.can_switch),
            ("silent 2 min", Dot::Silent, false)
        );
        let r = row(
            &road("d:1", false, PathState::Unverified, None, None),
            &live,
        );
        assert_eq!(
            (r.value.as_str(), r.dot, r.can_switch),
            ("checking", Dot::Spare, false)
        );
    }

    #[test]
    fn window_keys() {
        assert_eq!(
            keys(b"\x1b[A\x1bOB3\rq\x1b"),
            (
                vec![
                    Key::Up,
                    Key::Down,
                    Key::Pick(2),
                    Key::Enter,
                    Key::Close,
                    Key::Close
                ],
                0
            )
        );
        assert_eq!(keys(b"9x"), (vec![Key::Other, Key::Other], 0));
    }

    /// A key sequence is one key: its digits pick no row.
    #[test]
    fn a_long_key_sequence_is_one_key() {
        assert_eq!(
            keys(b"\x1b[1;5A\x1b[15~\x1b[1;2B2"),
            (vec![Key::Other, Key::Other, Key::Other, Key::Pick(1)], 0)
        );
    }

    /// A sequence cut off by the end of the chunk is left unread, whole.
    #[test]
    fn a_cut_sequence_is_left_for_the_next_chunk() {
        assert_eq!(keys(b"\x1b[A\x1b[1;5"), (vec![Key::Up], 5));
        assert_eq!(keys(b"\x1bO"), (vec![], 2));
        assert_eq!(keys(b"\x1b["), (vec![], 2));
    }

    fn rows() -> Vec<Row> {
        let live = Link::Latency { ms: 42 };
        vec![
            row(
                &road("a:1", true, PathState::Verified, Some(40), None),
                &live,
            ),
            row(
                &road("b:1", false, PathState::Verified, Some(38), None),
                &live,
            ),
            row(
                &road("c:1", false, PathState::Unverified, None, None),
                &live,
            ),
        ]
    }

    #[test]
    fn enter_switches_only_to_a_live_spare() {
        let rows = rows();
        let mut w = Roads::new();
        assert_eq!(
            w.on_key(Key::Enter, &rows),
            Outcome::Stay,
            "the road in use"
        );
        w.on_key(Key::Down, &rows);
        assert_eq!(w.on_key(Key::Enter, &rows), Outcome::Switch(1));
        assert_eq!(w.switching, Some(1));
        w.on_key(Key::Down, &rows);
        assert_eq!(
            w.on_key(Key::Enter, &rows),
            Outcome::Stay,
            "one switch at a time, and c is unchecked"
        );
        assert_eq!(w.on_key(Key::Pick(7), &rows), Outcome::Stay);
        assert_eq!(w.selected, 2, "no row 8");
        assert_eq!(w.on_key(Key::Close, &rows), Outcome::Close);
    }

    fn box_text(b: &Boxed) -> Vec<String> {
        b.lines
            .iter()
            .map(|l| l.iter().map(|c| c.ch).collect())
            .collect()
    }

    #[test]
    fn windows_have_padding_accent_borders_and_key_hints() {
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        let b = help_box("Ctrl-]", 80, 24, g).unwrap();
        let text = box_text(&b);
        let width = b.lines[0].len();
        assert!(width >= 44);
        assert_eq!(usize::from(b.left), (80 - width) / 2);
        assert!(text[0].starts_with("╭─ Keys"));
        assert!(text.last().unwrap().contains("Esc close"));
        for i in [1, text.len() - 2] {
            assert!(b.lines[i][1..width - 1].iter().all(|c| c.ch == ' '));
        }
        assert!(text[2].starts_with("│  Ctrl-] ."));
        assert!(b.lines[2][3..12].iter().all(|c| c.flags & FLAG_BOLD != 0));
        assert_eq!(b.lines[0][0].fg, Color::Indexed(6));
        assert!(b.lines[0]
            .iter()
            .filter(|c| c.ch.is_alphabetic())
            .all(|c| c.flags & FLAG_BOLD != 0));
        assert!(text.iter().any(|line| line.contains("Ctrl-] [")));
        let roads = roads_box(&rows(), &Roads::new(), 80, 24, g).unwrap();
        assert!(box_text(&roads).last().unwrap().contains("Enter use"));
        let mono = help_box("Ctrl-]", 80, 24, Glyphs { colour: false, ..g }).unwrap();
        assert_eq!(mono.lines[0][0].ch, '╔');
        let ascii = help_box("Ctrl-]", 80, 24, Glyphs { utf8: false, ..g }).unwrap();
        assert!(box_text(&ascii)[0].starts_with("+= Keys"));
        assert!(ascii.lines.iter().flatten().all(|cell| cell.ch.is_ascii()));
        let tiny = help_box("Ctrl-]", 20, 6, g).unwrap();
        assert_eq!(tiny.lines.len(), 6);
        assert!(tiny.lines.iter().all(|line| line.len() == 20));
        assert_eq!(tiny.lines[0].last().unwrap().ch, '╮');
    }

    #[test]
    fn the_roads_box_is_the_app_s_window() {
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        let b = roads_box(&rows(), &Roads::new(), 80, 24, g).expect("fits");
        let t = box_text(&b);
        assert!(t[0].starts_with("╭─ Connection state "), "{t:?}");
        assert!(
            t[2].contains("● a:1  in use")
                && t[2].trim_end_matches('│').trim_end().ends_with("42 ms"),
            "{t:?}"
        );
        assert!(t[3].contains("spare") && t[3].contains("38 ms"), "{t:?}");
        assert!(t[4].contains("checking"), "{t:?}");
        assert!(t[6].starts_with('╰'), "{t:?}");
        assert_eq!(b.top, (24 - 7) / 2);
        assert!(
            b.lines[2]
                .iter()
                .any(|c| c.flags & terminal::FLAG_REVERSE != 0),
            "the selected row"
        );
    }

    #[test]
    fn ascii_box_without_utf8() {
        let g = Glyphs {
            utf8: false,
            colour: true,
        };
        let t = box_text(&roads_box(&rows(), &Roads::new(), 80, 24, g).unwrap());
        assert!(t[0].starts_with("+= Connection state "), "{t:?}");
        assert!(t[2].starts_with("|  * a:1"), "{t:?}");
    }

    #[test]
    fn a_tiny_terminal_gets_a_clipped_box() {
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        let b = roads_box(&rows(), &Roads::new(), 22, 4, g).expect("some of it fits");
        assert_eq!(b.lines.len(), 4, "two borders and two rows");
        assert!(b.lines.iter().all(|l| l.len() <= 22));
        assert!(roads_box(&rows(), &Roads::new(), 7, 24, g).is_none());
        assert!(roads_box(&rows(), &Roads::new(), 80, 2, g).is_none());
    }

    #[test]
    fn the_help_box_names_the_prefix() {
        let g = Glyphs {
            utf8: true,
            colour: true,
        };
        let t = box_text(&help_box("Ctrl-]", 80, 24, g).unwrap());
        assert!(t.iter().any(
            |l| l.contains("Ctrl-] .") && l.contains("leave; the session stays on the server")
        ));
        assert!(t
            .iter()
            .any(|l| l.contains("Ctrl-] Ctrl-]") && l.contains("send Ctrl-] itself")));
    }

    #[test]
    fn the_locale_decides_the_glyphs() {
        assert!(utf8_locale(None, None, Some("en_US.UTF-8")));
        assert!(utf8_locale(Some("C.utf8"), None, Some("C")));
        assert!(
            !utf8_locale(Some("C"), None, Some("en_US.UTF-8")),
            "LC_ALL wins"
        );
        assert!(!utf8_locale(None, None, None));
    }
}
