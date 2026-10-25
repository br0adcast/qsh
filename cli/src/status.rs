//! The status line: a message painted over a COPY of the frame, never into
//! the frame itself. The screen model is what the renderer diffs against and
//! what prediction overlays; a status line written into it would look to
//! every later frame like output the server had sent, and would stay on
//! screen after the reason for it was gone.

use terminal::{Frame, FLAG_REVERSE};

/// What the user reads while the link is down. `<prefix> .` is the escape
/// from a server that is not coming back -- it is only useful if it is on
/// screen at the moment it is needed. `prefix` is the prefix's name
/// (`Ctrl-]`); without a prefix there are no keys to name.
pub fn lost_text(seconds: u64, prefix: Option<&str>) -> String {
    match prefix {
        Some(p) => format!("[qsh] link lost {seconds}s... {p} r -- reconnect, {p} . -- exit"),
        None => format!("[qsh] link lost {seconds}s..."),
    }
}

/// The top row while a reconnect round is under way: where it is trying (when
/// that is known yet), and the way out.
pub fn reconnecting_text(to: Option<&str>, prefix: Option<&str>) -> String {
    let head = match to {
        Some(to) => format!("[qsh] reconnecting to {to}..."),
        None => "[qsh] reconnecting...".to_string(),
    };
    match prefix {
        Some(p) => format!("{head} {p} . -- exit"),
        None => head,
    }
}

/// The top row between two reconnect rounds: when the next one starts, and
/// that the person may not want to wait for it. A `hint` (why every address
/// failed, and what to do) takes the place of the keys: it names its own
/// way out.
pub fn waiting_text(seconds: u64, prefix: Option<&str>, hint: Option<&str>) -> String {
    match (hint, prefix) {
        (Some(hint), _) => format!("[qsh] next attempt in {seconds} s -- {hint}"),
        (None, Some(p)) => {
            format!("[qsh] next attempt in {seconds} s... {p} r -- now, {p} . -- exit")
        }
        (None, None) => format!("[qsh] next attempt in {seconds} s..."),
    }
}

/// The hint between two rounds when every address was skipped because it
/// needed a question (a passphrase, a server key to trust): the background
/// asks nobody, so waiting will not help -- the way out is to leave and log
/// in again, where the question can be asked. `prefix` is the prefix's name;
/// without one there is no key to name.
pub fn needs_prompt_hint(prefix: Option<&str>) -> String {
    match prefix {
        Some(p) => format!("every address needs a question: {p} . and run qsh again"),
        None => "every address needs a question: leave and run qsh again".to_string(),
    }
}

/// Printed on the way out when the session came back but the shell in it did
/// not survive the time the link was down.
pub fn shell_ended_text() -> String {
    "qsh: the shell on the server ended while the link was down".to_string()
}

/// Printed on the way out when the server no longer knows the session and
/// there is nothing to return to. The server does not say why, so neither
/// does this: a restarted daemon and one that ended the session look alike.
pub fn session_gone_text(host: &str) -> String {
    format!(
        "qsh: the session on {host} is no longer on the server (the daemon restarted or ended it)"
    )
}

/// The line printed on the way out when the connection ended under the user
/// -- `link_closed` without the shell exiting or the user leaving first --
/// and not by a `Close` (`closed_gracefully`). That is a death (the link
/// stayed down past the death timer) or an abandonment (a stream reached the
/// end of its offset space): either way the server kept the session, and
/// the next run of the same command claims it back (the session is claimed
/// by the first address on the command line, so naming only the address in
/// use would send the person to another one). `None` otherwise:
/// a peer's `Close` means the session is gone, and an ordinary exit needs no
/// comment.
pub fn kept_session_notice(
    host: &str,
    link_closed: bool,
    closed_gracefully: bool,
) -> Option<String> {
    (link_closed && !closed_gracefully).then(|| lost_kept_notice(host))
}

/// The connection to `host` died and the server kept the session.
fn lost_kept_notice(host: &str) -> String {
    format!(
        "qsh: connection to {} lost; the session is kept on the server -- \
         run the same qsh command again to return to it",
        bracketed(host)
    )
}

/// The line printed on the way out when the person left with the prefix's
/// `.`: the link was let go quietly, and the next run of the same command
/// claims the session back. `host` is the address the link was on.
pub fn left_kept_notice(host: &str) -> String {
    format!(
        "qsh: left {}; the session is kept on the server -- \
         run the same qsh command again to return to it",
        bracketed(host)
    )
}

/// The line printed on the way out in the middle of a reconnect, when there
/// is no live link to ask: the old one was let go quietly, so the server
/// keeps the session either way. `left` is whether the person left with the
/// prefix's `.` -- then that is what they are told, not that the connection
/// was lost.
pub fn mid_reconnect_notice(host: &str, left: bool) -> String {
    if left {
        left_kept_notice(host)
    } else {
        lost_kept_notice(host)
    }
}

/// `host` the way it is typed: an IPv6 literal in brackets.
pub fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// `frame` with `text` painted across the top row, in reverse video, cut to
/// the width of the row.
pub fn overlay(frame: &Frame, text: &str) -> Frame {
    overlay_owned(frame.clone(), text)
}

/// Paint a plate on presentation storage supplied by the caller.
pub fn overlay_owned(mut out: Frame, text: &str) -> Frame {
    if out.cols == 0 || out.rows == 0 {
        return out;
    }
    for (cell, source) in out
        .cells
        .iter_mut()
        .take(usize::from(out.cols))
        .zip(crate::statusline::text_cells(text, true))
    {
        cell.ch = source.ch;
        cell.combining = source.combining;
        cell.flags &= !(terminal::FLAG_WIDE
            | terminal::FLAG_WIDE_SPACER
            | terminal::FLAG_LEADING_WIDE_SPACER
            | terminal::FLAG_HIDDEN);
        cell.flags |= FLAG_REVERSE | source.flags;
    }
    // Text and the surviving underlying cells can both end with half a pair.
    let size = terminal_size::ViewportSize::new(out.cols, out.rows);
    out = crate::viewport::project_owned(out, size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use terminal::{Frame, FLAG_REVERSE};

    fn row_text(frame: &Frame, row: u16) -> String {
        let start = row as usize * frame.cols as usize;
        frame.cells[start..start + frame.cols as usize]
            .iter()
            .map(|c| c.ch)
            .collect()
    }

    /// The overlay must not touch the caller's frame: the screen model is
    /// authoritative, and a status line written into it would be echoed back
    /// as if the server had sent it.
    #[test]
    fn the_source_frame_is_left_alone() {
        let frame = Frame::blank(20, 3);
        let painted = overlay(&frame, "abc");
        assert_eq!(
            row_text(&frame, 0),
            " ".repeat(20),
            "the original is untouched"
        );
        assert!(row_text(&painted, 0).starts_with("abc"));
    }

    /// Only the first row is an overlay; everything below is the frame.
    #[test]
    fn only_the_top_row_changes() {
        let mut frame = Frame::blank(10, 2);
        frame.cells[10].ch = 'x';
        let painted = overlay(&frame, "hi");
        assert_eq!(row_text(&painted, 1), row_text(&frame, 1));
    }

    /// Reverse video is what makes it read as an overlay rather than as
    /// output from the shell.
    #[test]
    fn the_overlay_is_reversed() {
        let painted = overlay(&Frame::blank(10, 1), "hi");
        assert_ne!(painted.cells[0].flags & FLAG_REVERSE, 0);
        assert_ne!(painted.cells[1].flags & FLAG_REVERSE, 0);
        assert_eq!(
            painted.cells[2].flags & FLAG_REVERSE,
            0,
            "the reverse run ends with the text -- the rest of the row is the frame"
        );
    }

    /// A narrow terminal must not corrupt the row: the text is cut, not
    /// wrapped, and never writes past `cols`.
    #[test]
    fn a_text_longer_than_the_row_is_cut() {
        let painted = overlay(&Frame::blank(4, 1), "abcdefgh");
        assert_eq!(row_text(&painted, 0), "abcd");
        assert_eq!(painted.cells.len(), 4);
    }

    /// A zero-sized frame is not a crash. It happens: a terminal reports
    /// 0x0 while a window manager is mid-resize.
    #[test]
    fn an_empty_frame_survives_an_overlay() {
        let painted = overlay(&Frame::blank(0, 0), "abc");
        assert_eq!(painted.cells.len(), 0);
    }

    /// The text the user actually reads, with the escape they need.
    #[test]
    fn the_lost_text_names_the_seconds_and_the_way_out() {
        let t = lost_text(7, Some("Ctrl-]"));
        assert!(t.contains('7'), "the elapsed seconds are the point: {t:?}");
        assert!(t.contains("Ctrl-]"), "the escape must be visible: {t:?}");
    }

    /// Spec §4.14: a console client whose connection died or was abandoned
    /// says the session is kept and how to return; a peer's `Close` and an
    /// ordinary exit say nothing.
    #[test]
    fn only_a_connection_lost_under_the_user_says_the_session_is_kept() {
        assert_eq!(
            kept_session_notice("box", true, false).as_deref(),
            Some(
                "qsh: connection to box lost; the session is kept on the server -- \
                 run the same qsh command again to return to it"
            ),
            "a death is reported"
        );
        assert_eq!(
            kept_session_notice("box", true, true),
            None,
            "the peer closed it"
        );
        assert_eq!(
            kept_session_notice("box", false, false),
            None,
            "the user left"
        );
    }

    /// Without a prefix there is no key to name: the texts say only what is
    /// going on.
    #[test]
    fn without_a_prefix_the_texts_name_no_keys() {
        assert_eq!(lost_text(7, None), "[qsh] link lost 7s...");
        assert_eq!(
            reconnecting_text(Some("h"), None),
            "[qsh] reconnecting to h..."
        );
        assert_eq!(reconnecting_text(None, None), "[qsh] reconnecting...");
        assert_eq!(waiting_text(8, None, None), "[qsh] next attempt in 8 s...");
        assert_eq!(
            waiting_text(8, None, Some("x")),
            "[qsh] next attempt in 8 s -- x"
        );
    }

    /// Leaving on purpose is not a loss: the notice says the person left.
    #[test]
    fn leaving_on_purpose_says_the_session_is_kept() {
        assert_eq!(
            left_kept_notice("box"),
            "qsh: left box; the session is kept on the server -- \
             run the same qsh command again to return to it"
        );
    }

    /// Leaving with `.` in the middle of a reconnect is still leaving on
    /// purpose; any other way out then is the connection lost.
    #[test]
    fn leaving_in_the_middle_of_a_reconnect_says_who_left() {
        assert_eq!(mid_reconnect_notice("box", true), left_kept_notice("box"));
        assert_eq!(
            Some(mid_reconnect_notice("box", false)),
            kept_session_notice("box", true, false)
        );
    }

    /// An IPv6 literal is named the way it is typed: in brackets.
    #[test]
    fn the_notices_bracket_an_ipv6_literal() {
        assert!(left_kept_notice("::1").starts_with("qsh: left [::1]; "));
        assert!(kept_session_notice("::1", true, false)
            .expect("a death is reported")
            .starts_with("qsh: connection to [::1] lost; "));
        assert_eq!(bracketed("box"), "box");
        assert_eq!(bracketed("2001:db8::1"), "[2001:db8::1]");
    }

    #[test]
    fn the_needs_a_question_hint_names_the_way_out() {
        assert_eq!(
            needs_prompt_hint(Some("Ctrl-]")),
            "every address needs a question: Ctrl-] . and run qsh again"
        );
        assert_eq!(
            needs_prompt_hint(None),
            "every address needs a question: leave and run qsh again"
        );
    }

    #[test]
    fn the_reconnect_texts_say_where_and_when() {
        let p = Some("Ctrl-]");
        assert_eq!(
            lost_text(7, p),
            "[qsh] link lost 7s... Ctrl-] r -- reconnect, Ctrl-] . -- exit"
        );
        assert_eq!(
            reconnecting_text(Some("h"), p),
            "[qsh] reconnecting to h... Ctrl-] . -- exit"
        );
        assert_eq!(
            reconnecting_text(None, p),
            "[qsh] reconnecting... Ctrl-] . -- exit"
        );
        assert_eq!(
            waiting_text(8, p, None),
            "[qsh] next attempt in 8 s... Ctrl-] r -- now, Ctrl-] . -- exit"
        );
        assert_eq!(
            waiting_text(8, p, Some("do this")),
            "[qsh] next attempt in 8 s -- do this"
        );
        assert_eq!(
            lost_text(7, Some("Ctrl-B")),
            "[qsh] link lost 7s... Ctrl-B r -- reconnect, Ctrl-B . -- exit",
            "the prefix in use, not a fixed one"
        );
        assert_eq!(
            session_gone_text("h"),
            "qsh: the session on h is no longer on the server (the daemon restarted or ended it)"
        );
        assert_eq!(
            shell_ended_text(),
            "qsh: the shell on the server ended while the link was down"
        );
    }
}

#[cfg(test)]
mod complete_cell_tests {
    #[test]
    fn complete_cell_status_replaces_hidden_marked_shell_text() {
        let mut source = terminal::TerminalCore::new(12, 2);
        source.feed("\x1b[8me\u{301}".as_bytes());
        let shown = super::overlay(&source.frame(), "O\u{302}K");
        assert_eq!(shown.cells[0].ch, 'O');
        assert_eq!(shown.cells[0].combining.as_slice(), &['\u{302}']);
        assert_eq!(shown.cells[0].flags & terminal::FLAG_HIDDEN, 0);
        assert!(shown.cells[1].combining.is_empty());
    }
}
