//! The renderer mirrors the application's INPUT modes onto the user's
//! terminal: arrow keys, the keypad, the mouse and bracketed paste must be
//! encoded the way the remote application expects, and the client passes
//! keyboard bytes through untouched.

use render::{Renderer, TermCaps};
use terminal::TerminalCore;

fn rendered(src: &mut TerminalCore, r: &mut Renderer) -> String {
    String::from_utf8_lossy(&r.render(&src.frame())).to_string()
}

#[test]
fn application_cursor_keys_are_mirrored() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = rendered(&mut src, &mut r);

    src.feed(b"\x1b[?1h");
    assert!(rendered(&mut src, &mut r).contains("\x1b[?1h"));

    src.feed(b"\x1b[?1l");
    assert!(rendered(&mut src, &mut r).contains("\x1b[?1l"));
}

#[test]
fn application_keypad_is_mirrored() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = rendered(&mut src, &mut r);

    // DECKPAM turns the application keypad on.
    src.feed(b"\x1b=");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b="), "keypad on: {out:?}");

    // DECKPNM turns it back off.
    src.feed(b"\x1b>");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b>"), "keypad off: {out:?}");
}

#[test]
fn mouse_tracking_is_mirrored_at_the_exact_level() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = rendered(&mut src, &mut r);

    src.feed(b"\x1b[?1000h\x1b[?1006h");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?1000h"), "click tracking: {out:?}");
    assert!(out.contains("\x1b[?1006h"), "SGR encoding: {out:?}");
    assert!(
        !out.contains("\x1b[?1003h"),
        "must not ask for motion: {out:?}"
    );

    src.feed(b"\x1b[?1003h");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?1003h"), "motion tracking: {out:?}");
}

#[test]
fn switching_tracking_level_turns_the_old_one_off_first() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = rendered(&mut src, &mut r);

    src.feed(b"\x1b[?1000h");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?1000h"), "click tracking: {out:?}");

    // Terminals track the three modes separately: leaving click tracking on
    // while asking for motion would keep both streams of events coming.
    src.feed(b"\x1b[?1003h");
    let out = rendered(&mut src, &mut r);
    let off = out
        .find("\x1b[?1000l")
        .unwrap_or_else(|| panic!("old level must be turned off: {out:?}"));
    let on = out
        .find("\x1b[?1003h")
        .unwrap_or_else(|| panic!("new level must be turned on: {out:?}"));
    assert!(off < on, "off must precede on: {out:?}");

    // Back to no tracking at all.
    src.feed(b"\x1b[?1003l\x1b[?1000l");
    let out = rendered(&mut src, &mut r);
    assert!(
        out.contains("\x1b[?1003l"),
        "motion tracking must be turned off: {out:?}"
    );
    assert!(
        !out.contains("\x1b[?1000h") && !out.contains("\x1b[?1003h"),
        "nothing may be re-enabled: {out:?}"
    );
}

#[test]
fn bracketed_paste_is_mirrored() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let _ = rendered(&mut src, &mut r);

    src.feed(b"\x1b[?2004h");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?2004h"), "paste on: {out:?}");

    src.feed(b"\x1b[?2004l");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?2004l"), "paste off: {out:?}");
}

#[test]
fn a_fresh_renderer_assumes_nothing_about_the_terminals_modes() {
    // Before the first frame we know no more about the user's shell than
    // after a SIGCONT: the previous program may have left mouse tracking or
    // bracketed paste on. So the first render states every mirrored mode
    // instead of diffing against an assumed "initial" state -- here all of
    // them off, since the frame asks for none.
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    let out = rendered(&mut src, &mut r);
    for expected in [
        "\x1b[?1l",
        "\x1b>",
        "\x1b[?1000l",
        "\x1b[?1002l",
        "\x1b[?1003l",
        "\x1b[?2004l",
    ] {
        assert!(
            out.contains(expected),
            "the first render must state {expected:?}: {out:?}"
        );
    }
    assert!(
        out.contains("\x1b[?1006l"),
        "the first render must state SGR mouse off: {out:?}"
    );

    // From then on the state is known: an unchanged frame repeats nothing.
    let out = rendered(&mut src, &mut r);
    assert!(
        !out.contains("\x1b[?2004l") && !out.contains("\x1b[?1000l"),
        "a known, unchanged state must not be restated: {out:?}"
    );
}

#[test]
fn finish_puts_the_terminal_back() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"\x1b[?1h\x1b=\x1b[?1003h\x1b[?1006h\x1b[?2004h\x1b[?25l\x1b[31mred");
    let _ = rendered(&mut src, &mut r);

    let out = String::from_utf8_lossy(&r.finish()).to_string();
    for expected in [
        "\x1b[0m",
        "\x1b[?1l",
        "\x1b>",
        "\x1b[?1003l",
        "\x1b[?1006l",
        "\x1b[?2004l",
        "\x1b[?25h",
    ] {
        assert!(
            out.contains(expected),
            "finish must emit {expected:?}: {out:?}"
        );
    }
}

#[test]
fn invalidate_forces_a_full_repaint() {
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"content");
    let _ = rendered(&mut src, &mut r);

    r.invalidate();
    let out = rendered(&mut src, &mut r);
    assert!(
        out.contains("\x1b[2J"),
        "must repaint after invalidate: {out:?}"
    );
    assert!(out.contains("content"), "must redraw the content: {out:?}");
}

#[test]
fn invalidate_re_emits_the_mirrored_modes() {
    // `invalidate` means "something else wrote to this terminal, or we were
    // resumed from the background" -- exactly the situation where job
    // control has most likely cleared bracketed paste and mouse tracking
    // behind our back. The next render has to put them back.
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"\x1b[?1h\x1b=\x1b[?1000h\x1b[?1006h\x1b[?2004h");
    let out = rendered(&mut src, &mut r);
    assert!(out.contains("\x1b[?1h"), "modes must be set first: {out:?}");

    r.invalidate();
    let out = rendered(&mut src, &mut r);
    for expected in [
        "\x1b[?1h",
        "\x1b=",
        "\x1b[?1000h",
        "\x1b[?1006h",
        "\x1b[?2004h",
    ] {
        assert!(
            out.contains(expected),
            "invalidate must re-emit {expected:?}: {out:?}"
        );
    }
}

#[test]
fn finish_after_invalidate_still_turns_every_mode_off() {
    // After `invalidate` the renderer knows nothing about the terminal, and
    // "nothing known" must not mean "nothing to undo": leaving mouse
    // tracking or bracketed paste on would corrupt the user's shell.
    let mut src = TerminalCore::new(10, 2);
    let mut r = Renderer::new(TermCaps::truecolor());
    src.feed(b"\x1b[?1h\x1b=\x1b[?1003h\x1b[?1006h\x1b[?2004h");
    let _ = rendered(&mut src, &mut r);

    r.invalidate();
    let out = String::from_utf8_lossy(&r.finish()).to_string();
    for expected in [
        "\x1b[?1l",
        "\x1b>",
        "\x1b[?1000l",
        "\x1b[?1002l",
        "\x1b[?1003l",
        "\x1b[?1006l",
        "\x1b[?2004l",
        "\x1b[?25h",
    ] {
        assert!(
            out.contains(expected),
            "finish must emit {expected:?}: {out:?}"
        );
    }
}
