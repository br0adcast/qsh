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
    let cols = cols as usize;
    let plain = Cell {
        ch: ' ',
        fg: Color::Default,
        bg: Color::Default,
        flags: FLAG_REVERSE,
    };
    let mut cells = vec![plain; cols];
    if cols == 0 {
        return cells;
    }
    let right: Vec<char> = right.chars().collect();
    // The right part ends one column before the edge when it fits with that
    // margin; otherwise it starts at column 0 and is cut at the edge.
    let (start, shown) = if right.len() < cols {
        (cols - 1 - right.len(), right.len())
    } else {
        (0, cols)
    };
    for (i, ch) in right.iter().take(shown).enumerate() {
        cells[start + i].ch = *ch;
    }
    if alarm && shown > 0 {
        let from = start.saturating_sub(1);
        let to = (start + shown + 1).min(cols);
        for cell in &mut cells[from..to] {
            if colour {
                cell.fg = Color::Indexed(15);
                cell.bg = Color::Indexed(1);
                cell.flags = 0;
            } else {
                cell.flags = FLAG_REVERSE | FLAG_BOLD;
            }
        }
    }
    let left: Vec<char> = left.chars().collect();
    if !left.is_empty() && left.len() + 1 + shown < cols {
        for (i, ch) in left.iter().enumerate() {
            cells[i].ch = *ch;
        }
    }
    cells
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
    fn an_alarm_is_red_with_colour() {
        let cells = line(20, "", "7 s", true, true);
        let start = 20 - 1 - 3;
        assert_eq!(cells[start].bg, Color::Indexed(1));
        assert_eq!(cells[start].fg, Color::Indexed(15));
        assert_eq!(cells[start].flags & FLAG_REVERSE, 0);
        assert_eq!(cells[0].bg, Color::Default);
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
