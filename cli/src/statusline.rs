//! The status line: pure text and cells, no session and no I/O.
//!
//! The rules mirror the app's header (`headerStatus`): a latency, a silence
//! age, or a reconnect note on the right, the prefix hint on the left.

use terminal::{Cell, Color, FLAG_BOLD, FLAG_REVERSE};

/// Silence at or past this many seconds makes the link "quiet" (the app's
/// `QUIET_AFTER_SECONDS`, the transport's `PATH_DOWN_AFTER`).
pub const QUIET_AFTER_SECS: u64 = 3;

/// What the right part of the line reports about the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// Nothing measured yet.
    Unknown,
    Latency {
        ms: u32,
    },
    Silent {
        secs: u64,
    },
    Reconnecting {
        to: Option<String>,
    },
    Waiting {
        secs: u64,
        hint: Option<String>,
    },
}

/// Seconds under a minute, whole minutes past it.
pub fn human_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} s")
    } else {
        format!("{} min", secs / 60)
    }
}

/// Reads the transport's numbers like the app's header does. `Reconnecting`
/// and `Waiting` are set by the session itself.
pub fn link_of(rtt_ms: u32, silent_secs: u64, path_down: bool) -> Link {
    if path_down || silent_secs >= QUIET_AFTER_SECS {
        Link::Silent { secs: silent_secs }
    } else if rtt_ms == 0 {
        Link::Unknown
    } else {
        Link::Latency { ms: rtt_ms }
    }
}

/// The right part's text and whether it is an alarm.
pub fn right_part(road: Option<&str>, link: &Link) -> (String, bool) {
    let with_road = |value: String| match road {
        Some(road) => format!("{road}  {value}"),
        None => value,
    };
    match link {
        Link::Unknown => (String::new(), false),
        Link::Latency { ms } => (with_road(format!("{ms} ms")), false),
        Link::Silent { secs } => (with_road(human_age(*secs)), true),
        Link::Reconnecting { to: Some(to) } => (format!("reconnecting to {to}"), true),
        Link::Reconnecting { to: None } => ("reconnecting".to_string(), true),
        Link::Waiting { secs, hint: None } => (format!("next attempt in {secs} s"), true),
        Link::Waiting {
            secs,
            hint: Some(hint),
        } => (format!("next attempt in {secs} s -- {hint}"), true),
    }
}

/// The left part: the hint that opens the help, or nothing without a prefix.
pub fn left_part(prefix_name: Option<&str>) -> String {
    match prefix_name {
        Some(name) => format!(" {name} ? "),
        None => String::new(),
    }
}

pub fn scroll_part(offset: usize, total: usize) -> String {
    if total == 0 {
        "scroll: 0/0 -- no history".to_string()
    } else {
        format!("scroll: {offset}/{total}")
    }
}

/// Exactly `cols` cells, all reversed. The right part ends one column before
/// the edge; the left part is dropped when it does not fit beside it.
pub fn line(cols: u16, left: &str, right: &str, alarm: bool, colour: bool) -> Vec<Cell> {
    let cols = usize::from(terminal_size::ViewportSize::new(cols, 0).cols());
    let plain = Cell {
        ch: ' ',
        fg: Color::Default,
        bg: Color::Default,
        combining: Default::default(),
        flags: FLAG_REVERSE,
    };
    let mut cells = vec![plain; cols];
    if cols == 0 {
        return cells;
    }
    let right = text_cells(right, true);
    // The right part ends one column before the edge when it fits with that
    // margin; otherwise it starts at column 0 and is cut at the edge.
    let (start, shown) = if right.len() < cols {
        (cols - 1 - right.len(), right.len())
    } else {
        (0, cols)
    };
    for (i, source) in right.iter().take(shown).enumerate() {
        cells[start + i].ch = source.ch;
        cells[start + i].combining = source.combining;
        cells[start + i].flags |= source.flags;
    }
    if alarm {
        for cell in &mut cells {
            if colour {
                cell.fg = Color::Indexed(15);
                cell.bg = Color::Indexed(1);
                cell.flags &= terminal::FLAG_WIDE | terminal::FLAG_WIDE_SPACER;
            } else {
                cell.flags |= FLAG_REVERSE | FLAG_BOLD;
            }
        }
    }
    let left = text_cells(left, true);
    if !left.is_empty() && left.len() + 1 + shown < cols {
        for (i, source) in left.iter().enumerate() {
            cells[i].ch = source.ch;
            cells[i].combining = source.combining;
            cells[i].flags |= source.flags;
        }
    }
    if let Some(last) = cells.last_mut() {
        if last.flags & terminal::FLAG_WIDE != 0 {
            last.set_char(' ');
            last.flags &= !terminal::FLAG_WIDE;
        }
    }
    cells
}
/// Display cells with zero-width suffixes attached to their owning glyph.
/// Leading marks without an owner are omitted; wide spacers own no suffix.
pub(crate) fn text_cells(text: &str, utf8: bool) -> Vec<Cell> {
    use unicode_width::UnicodeWidthChar;
    let mut cells: Vec<Cell> = Vec::new();
    for ch in text.chars() {
        let ch = if ch.is_control() || (!utf8 && !ch.is_ascii()) {
            '?'
        } else {
            ch
        };
        let width = ch.width().unwrap_or(0);
        if width == 0 {
            if let Some(owner) = cells
                .iter_mut()
                .rev()
                .find(|cell| cell.flags & terminal::FLAG_WIDE_SPACER == 0)
            {
                owner.combining.push(ch);
            }
            continue;
        }
        let mut cell = Cell {
            ch,
            ..Cell::blank()
        };
        if width == 2 {
            cell.flags = terminal::FLAG_WIDE;
        }
        cells.push(cell);
        if width == 2 {
            cells.push(Cell {
                flags: terminal::FLAG_WIDE_SPACER,
                ..Cell::blank()
            });
        }
    }
    cells
}

/// Fixed left-aligned activity row: no pagination, no wrapping, and every
/// column (including padding) retains the outage alarm.
pub fn recovery_line(cols: u16, text: &str, colour: bool, utf8: bool) -> Vec<Cell> {
    recovery_spans(cols, &[(text.to_string(), true)], colour, utf8)
}

/// The usual left help slot, then recovery text anchored to the exact right
/// edge. Tiny rows omit the hint so at least the clipped recovery fits.
pub fn recovery_row(
    cols: u16,
    left: &str,
    spans: &[(String, bool)],
    colour: bool,
    utf8: bool,
) -> Vec<Cell> {
    let width = usize::from(cols);
    let left_width = text_cells(left, utf8).len();
    let ellipsis_width = if utf8 { 1 } else { 3 };
    let reserved = if left_width > 0 && left_width + 1 + ellipsis_width <= width {
        left_width + 1
    } else {
        0
    };
    let text_width: usize = spans.iter().map(|(s, _)| text_cells(s, utf8).len()).sum();
    let gap = (width - reserved).saturating_sub(text_width);
    let mut row = Vec::with_capacity(spans.len() + 2);
    if reserved > 0 {
        row.push((format!("{left} "), false));
    }
    row.push((" ".repeat(gap), false));
    row.extend_from_slice(spans);
    recovery_spans(cols, &row, colour, utf8)
}

pub fn recovery_spans(cols: u16, spans: &[(String, bool)], colour: bool, utf8: bool) -> Vec<Cell> {
    let width = usize::from(cols);
    let mut cells: Vec<_> = spans
        .iter()
        .flat_map(|(text, active)| {
            text_cells(text, utf8)
                .into_iter()
                .map(|cell| (cell, *active))
        })
        .collect();
    if cells.len() > width {
        let suffix = if utf8 { "…" } else { "..." };
        let suffix: Vec<_> = text_cells(suffix, utf8)
            .into_iter()
            .take(width)
            .map(|c| (c, false))
            .collect();
        cells.truncate(width - suffix.len());
        if cells
            .last()
            .is_some_and(|(c, _)| c.flags & terminal::FLAG_WIDE != 0)
        {
            *cells.last_mut().unwrap() = (Cell::blank(), false);
        }
        cells.extend(suffix);
    }
    cells.resize(width, (Cell::blank(), false));
    cells
        .into_iter()
        .map(|(mut cell, active)| {
            if colour {
                cell.fg = Color::Indexed(if active { 15 } else { 7 });
                cell.bg = Color::Indexed(1);
            } else {
                cell.flags |= FLAG_REVERSE;
                if active {
                    cell.flags |= FLAG_BOLD;
                }
            }
            cell
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use terminal::{Color, FLAG_BOLD, FLAG_REVERSE};

    fn text(cells: &[Cell]) -> String {
        cells.iter().map(|c| c.ch).collect()
    }

    #[test]
    fn the_link_is_read_like_the_app_s_header() {
        assert_eq!(link_of(0, 0, false), Link::Unknown);
        assert_eq!(link_of(42, 0, false), Link::Latency { ms: 42 });
        assert_eq!(link_of(42, 3, false), Link::Silent { secs: 3 });
        assert_eq!(link_of(42, 0, true), Link::Silent { secs: 0 });
    }

    #[test]
    fn the_right_part_says_what_the_app_says() {
        assert_eq!(right_part(None, &Link::Unknown), (String::new(), false));
        assert_eq!(
            right_part(None, &Link::Latency { ms: 42 }),
            ("42 ms".into(), false)
        );
        assert_eq!(
            right_part(Some("h:1"), &Link::Latency { ms: 42 }),
            ("h:1  42 ms".into(), false)
        );
        assert_eq!(
            right_part(Some("h:1"), &Link::Silent { secs: 7 }),
            ("h:1  7 s".into(), true)
        );
        assert_eq!(
            right_part(None, &Link::Silent { secs: 120 }),
            ("2 min".into(), true)
        );
        assert_eq!(
            right_part(
                Some("h:1"),
                &Link::Reconnecting {
                    to: Some("10.8.0.1".into())
                }
            ),
            ("reconnecting to 10.8.0.1".into(), true)
        );
        assert_eq!(
            right_part(
                None,
                &Link::Waiting {
                    secs: 8,
                    hint: None
                }
            ),
            ("next attempt in 8 s".into(), true)
        );
        assert_eq!(
            right_part(
                None,
                &Link::Waiting {
                    secs: 8,
                    hint: Some("x".into())
                }
            ),
            ("next attempt in 8 s -- x".into(), true)
        );
    }

    #[test]
    fn the_line_has_the_hint_left_and_the_state_right() {
        let cells = line(30, &left_part(Some("Ctrl-]")), "42 ms", false, true);
        assert_eq!(text(&cells), " Ctrl-] ?               42 ms ");
        assert!(cells.iter().all(|c| c.flags & FLAG_REVERSE != 0));
    }

    #[test]
    fn the_entire_alarm_row_including_padding_has_alarm_style() {
        for colour in [false, true] {
            let cells = line(40, " Ctrl-] ? ", "lost", true, colour);
            assert!(cells.iter().all(|c| if colour {
                c.bg == Color::Indexed(1)
            } else {
                c.flags & FLAG_BOLD != 0
            }));
        }
    }

    #[test]
    fn recovery_spans_change_only_brightness_not_text_or_positions() {
        let spans = vec![
            ("QSH".into(), true),
            ("/".into(), false),
            ("SSH".into(), false),
        ];
        let colour = recovery_spans(12, &spans, true, true);
        assert_eq!(text(&colour), "QSH/SSH     ");
        assert!(colour.iter().all(|c| c.bg == Color::Indexed(1)));
        assert!(colour[..3].iter().all(|c| c.fg == Color::Indexed(15)));
        assert!(colour[3..].iter().all(|c| c.fg == Color::Indexed(7)));
        let mono = recovery_spans(12, &spans, false, true);
        assert!(mono.iter().all(|c| c.flags & FLAG_REVERSE != 0));
        assert!(mono[..3].iter().all(|c| c.flags & FLAG_BOLD != 0));
        assert!(mono[3..].iter().all(|c| c.flags & FLAG_BOLD == 0));
    }

    #[test]
    fn recovery_row_anchors_text_at_the_right_edge_after_a_fixed_hint() {
        let spans = vec![("界 [QSH]".into(), true)];
        for width in [18, 30] {
            let row = recovery_row(width, " help ", &spans, true, true);
            assert_eq!(text(&row[..6]), " help ");
            assert_eq!(row[usize::from(width) - 8].ch, '界');
            assert_eq!(row.last().unwrap().ch, ']');
            assert!(row.iter().all(|c| c.bg == Color::Indexed(1)));
        }
        let disabled = recovery_row(12, "", &spans, false, true);
        assert_eq!(disabled[4].ch, '界');
        assert_eq!(disabled.last().unwrap().ch, ']');
        assert!(disabled.iter().all(|c| c.flags & FLAG_REVERSE != 0));
    }

    #[test]
    fn recovery_row_clips_only_within_the_available_area() {
        let spans = vec![("host.example [QSH]".into(), true)];
        assert_eq!(
            text(&recovery_row(12, " help ", &spans, true, true)),
            " help  host…"
        );
        assert_eq!(
            text(&recovery_row(12, " help ", &spans, true, false)),
            " help  ho..."
        );
        assert_eq!(
            text(&recovery_row(6, " help ", &spans, true, true)),
            "host.…"
        );
        assert_eq!(
            text(&recovery_row(8, " help ", &spans, true, false)),
            "host...."
        );
        assert_eq!(
            text(&recovery_row(9, " help ", &spans, true, false)),
            "host.e..."
        );
        assert!(recovery_row(0, " help ", &spans, true, true).is_empty());
        let wide = vec![("界界界".into(), true)];
        let clipped = recovery_row(4, "", &wide, true, true);
        assert_eq!(clipped[2].ch, ' ');
        assert_eq!(clipped[3].ch, '…', "clipping keeps the exact right anchor");
        let idle = recovery_row(12, " help ", &[(spans[0].0.clone(), false)], true, true);
        assert_eq!(
            text(&idle),
            text(&recovery_row(12, " help ", &spans, true, true))
        );
    }

    #[test]
    fn recovery_text_clips_by_cells_with_an_ellipsis() {
        let row = recovery_line(8, "QSH: 界界", true, true);
        assert_eq!(row.len(), 8);
        assert_eq!(row[5].ch, '界');
        assert_ne!(row[5].flags & terminal::FLAG_WIDE, 0);
        assert_ne!(row[6].flags & terminal::FLAG_WIDE_SPACER, 0);
        assert_eq!(row[7].ch, '…');
        assert_eq!(
            text(&recovery_line(8, "QSH: host:60000", true, false)),
            "QSH: ..."
        );
        assert_eq!(recovery_line(0, "QSH: x", true, true).len(), 0);
        assert_eq!(text(&recovery_line(1, "QSH: x", true, true)), "…");
    }

    #[test]
    fn an_alarm_is_red_with_colour() {
        let cells = line(20, "", "7 s", true, true);
        let start = 20 - 1 - 3;
        assert_eq!(cells[start].bg, Color::Indexed(1));
        assert_eq!(cells[start].fg, Color::Indexed(15));
        assert_eq!(cells[start].flags & FLAG_REVERSE, 0);
        assert_eq!(cells[0].bg, Color::Indexed(1));
    }

    #[test]
    fn a_mono_line_alarms_in_bold() {
        let cells = line(20, "", "7 s", true, false);
        let start = 20 - 1 - 3;
        assert_eq!(cells[start].bg, Color::Default);
        assert_ne!(cells[start].flags & FLAG_BOLD, 0);
        assert_ne!(cells[start].flags & FLAG_REVERSE, 0);
    }

    #[test]
    fn a_narrow_line_keeps_the_value_and_drops_the_rest() {
        assert_eq!(
            text(&line(12, " Ctrl-] ? ", "42 ms", false, true)),
            "      42 ms "
        );
        assert_eq!(text(&line(4, "", "reconnecting to x", true, true)), "reco");
        assert_eq!(line(0, " x ", "y", false, true).len(), 0);
    }

    #[test]
    fn no_prefix_no_hint() {
        assert_eq!(left_part(None), "");
    }
}

#[cfg(test)]
mod complete_cell_tests {
    use super::*;
    #[test]
    fn complete_cell_status_text_owns_marks_without_phantom_columns() {
        let cells = text_cells("\u{301}e\u{302}界\u{303}", true);
        assert_eq!(cells.len(), 3);
        assert_eq!(cells[0].combining.as_slice(), &['\u{302}']);
        assert_eq!(cells[1].combining.as_slice(), &['\u{303}']);
        assert!(cells[2].combining.is_empty());
        let row = line(12, "e\u{302}", "界\u{303}", false, true);
        assert_eq!(row[0].combining.as_slice(), &['\u{302}']);
        assert_eq!(row[9].combining.as_slice(), &['\u{303}']);
        let clipped = line(1, "", "界\u{303}", false, true);
        assert_eq!(clipped[0].ch, ' ');
        assert!(clipped[0].combining.is_empty());
        let capped = text_cells(&format!("e{}", "\u{301}".repeat(17)), true);
        assert_eq!(
            capped[0].combining.as_slice().len(),
            terminal::MAX_COMBINING_MARKS
        );
    }
}
