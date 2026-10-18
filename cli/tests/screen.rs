//! The screen, end to end (spec §8): the status line on the top row, the
//! connection-state window over the frame, and the `Ctrl-]` prefix -- with a
//! real `qshd serve` and a real `qsh` on a pseudo-terminal that is its
//! controlling terminal.
//!
//! What is on screen is read through the terminal model ([`Screen::frame`]),
//! never from the raw bytes: the renderer repaints only the cells that
//! changed, so neither the line, the window nor a shell's answer is
//! necessarily contiguous in what the client wrote. Only the switches
//! between the terminal's own screen and its alternate one are looked for
//! in the raw bytes, where their order is the point. A shell's answer is a whole row of
//! the screen, with its marker split by quotes (`echo SW'IT'CHED`), so the
//! typed command -- which the screen echoes, and prediction may paint early
//! -- never reads as the answer.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::*;
use terminal::Color;

/// The client's terminal, as the tests spawn it.
const COLS: u16 = 80;
const ROWS: u16 = 24;

/// How the status line starts with the default prefix.
const LINE_HINT: &str = " Ctrl-] ?";

/// Everything the client has painted so far, collected on a background
/// thread.
struct Screen {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Screen {
    fn of(client: &Client) -> Screen {
        let seen = Arc::new(Mutex::new(Vec::new()));
        drain_into(
            client.master.try_clone().expect("clone master"),
            seen.clone(),
        );
        Screen { seen }
    }

    fn bytes(&self) -> Vec<u8> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The raw output: for what is printed after the terminal is restored
    /// (the notice on leaving), and for failure messages.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    fn has(&self, needle: &str) -> bool {
        self.text().contains(needle)
    }

    /// The screen as a person sees it now.
    fn frame(&self) -> terminal::Frame {
        let mut model = terminal::TerminalCore::new(COLS, ROWS);
        model.feed(&self.bytes());
        model.frame()
    }

    /// Every row of the screen, as text.
    fn rows(&self) -> Vec<String> {
        let frame = self.frame();
        (0..ROWS)
            .map(|row| (0..COLS).map(|col| frame.cell(row, col).ch).collect())
            .collect()
    }

    fn top(&self) -> String {
        self.rows().swap_remove(0)
    }

    /// Every line that scrolled off the top of the screen, oldest first: the
    /// terminal's own history, as its scroll wheel shows it (the view moved
    /// into it as `ShellState::scroll_frame` moves it).
    fn history(&self) -> Vec<String> {
        let mut model = terminal::TerminalCore::new(COLS, ROWS);
        model.feed(&self.bytes());
        model.scroll(i32::MAX);
        let mut lines = Vec::new();
        while model.display_offset() > 0 {
            let frame = model.frame();
            let row: String = (0..COLS).map(|col| frame.cell(0, col).ch).collect();
            lines.push(row.trim_end().to_string());
            model.scroll(-1);
        }
        lines
    }

    /// Whether some row reads exactly `text`, spaces around it aside: a
    /// shell's answer on its own line.
    fn has_row(&self, text: &str) -> bool {
        self.rows().iter().any(|row| row.trim() == text)
    }

    /// How many rows read exactly `text`.
    fn count_rows(&self, text: &str) -> usize {
        self.rows().iter().filter(|row| row.trim() == text).count()
    }

    /// Whether the connection-state window is on the screen.
    // Only the Linux-only window scenario reads the window.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn window_open(&self) -> bool {
        self.rows()
            .iter()
            .any(|row| row.contains("Connection state"))
    }

    /// The value the window shows for the road labelled `label`: what is
    /// right of `in use`/`spare`, the frame's right edge taken off.
    // Only the Linux-only window scenario reads the window.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn window_value(&self, label: &str) -> Option<String> {
        self.rows().iter().find_map(|row| {
            if !row.contains(label) {
                return None;
            }
            let after = row
                .split_once("spare")
                .or_else(|| row.split_once("in use"))?
                .1;
            let value = after.trim().trim_end_matches(['│', '|']).trim().to_string();
            Some(value)
        })
    }

    /// Whether the last character of the line's right part -- one column
    /// before the edge -- is on the alarm's red background.
    fn line_is_red(&self) -> bool {
        self.frame().cell(0, COLS - 2).bg == Color::Indexed(1)
    }

    /// For failure messages: the screen as rows.
    fn dump(&self) -> String {
        self.rows().join("\n")
    }
}

/// Waits up to `within` for `probe` to hold. For waits that are not
/// [`wait_until`]'s 20 s.
fn wait_for(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    probe()
}

/// Whether `text` ends with a latency: `... 42 ms`.
fn ends_with_latency(text: &str) -> bool {
    text.trim_end()
        .strip_suffix(" ms")
        .and_then(|head| head.rsplit(' ').next())
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `text` ends with a silence under a minute: `... 7 s`.
fn ends_with_silence(text: &str) -> bool {
    text.trim_end()
        .strip_suffix(" s")
        .and_then(|head| head.rsplit(' ').next())
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// First contact: the fingerprint is shown and trusted.
fn answer_yes(client: &mut Client, screen: &Screen, daemon: &Daemon) {
    assert!(
        wait_until(|| screen.has("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");
}

/// Waits for the session to run: the status line is on the top row.
fn wait_for_the_line(screen: &Screen, daemon: &Daemon) {
    assert!(
        wait_until(|| screen.top().starts_with(LINE_HINT)),
        "once the session runs, the top row is the status line; screen:\n{}\ndaemon: {}",
        screen.dump(),
        daemon.output_text()
    );
}

/// Types `command` and waits for a row that reads `answer`.
fn shell_answers(client: &mut Client, screen: &Screen, command: &str, answer: &str) {
    client.type_line(command);
    assert!(
        wait_until(|| screen.has_row(answer)),
        "the shell must answer {command:?} with a row {answer:?}; screen:\n{}",
        screen.dump()
    );
}

/// Types `stty size` once a second until a row reads `size`, or `within`
/// runs out. Retyped because a change of size reaches the shell a little
/// later than the key that asked for it.
fn the_shell_sees(client: &mut Client, screen: &Screen, size: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        client.type_line("stty size");
        if wait_for(Duration::from_secs(1), || screen.has_row(size)) {
            return true;
        }
    }
    screen.has_row(size)
}

/// `exit` ends the shell, and the run ends with it: code 0.
fn exit_cleanly(client: &mut Client, screen: &Screen, daemon: &Daemon) {
    client.type_line("exit");
    let status = wait_for_exit(&mut client.child).unwrap_or_else(|| {
        panic!(
            "the client must exit once its shell does; screen:\n{}\ndaemon: {}",
            screen.dump(),
            daemon.output_text()
        )
    });
    assert_eq!(
        status.code(),
        Some(0),
        "a shell that exited is not a failure; client saw: {}",
        screen.text()
    );
}

/// The status line takes the top row, starts with the prefix hint and ends
/// with the measured latency; the shell is given the rows below it only.
#[test]
fn the_line_shows_the_latency_and_the_shell_is_a_row_shorter() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    assert!(
        wait_for(Duration::from_secs(10), || ends_with_latency(&screen.top())),
        "the line must show the latency within 10 s; top row: {:?}",
        screen.top()
    );

    assert!(
        the_shell_sees(&mut client, &screen, "23 80", Duration::from_secs(20)),
        "with the line shown the shell gets 23 rows of 24; screen:\n{}",
        screen.dump()
    );
    assert!(
        !screen.has_row("24 80"),
        "the shell must never have been told the whole height; screen:\n{}",
        screen.dump()
    );

    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!("line_latency: whole test {:?}", started.elapsed());
}

/// `Ctrl-] h` hides the line: the shell is told the whole height, and the top
/// row is no longer the line.
#[test]
fn hiding_the_line_gives_the_row_back() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    assert!(
        the_shell_sees(&mut client, &screen, "23 80", Duration::from_secs(20)),
        "before hiding, the shell has 23 rows; screen:\n{}",
        screen.dump()
    );

    client.master.write_all(b"\x1dh").expect("type ctrl-] h");
    let pressed = Instant::now();
    assert!(
        the_shell_sees(&mut client, &screen, "24 80", Duration::from_secs(10)),
        "Ctrl-] h must give the shell the whole height within 10 s; screen:\n{}",
        screen.dump()
    );
    let resized_after = pressed.elapsed();
    let top = screen.top();
    assert!(
        !top.starts_with(LINE_HINT),
        "a hidden line is not on the top row: {top:?}"
    );

    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!(
        "hiding_the_line: 24 rows {resized_after:?} after Ctrl-] h; whole test {:?}",
        started.elapsed()
    );
}

#[test]
fn scroll_mode_shows_older_output_and_q_returns_to_the_live_screen() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    shell_answers(
        &mut client,
        &screen,
        "for n in $(seq 1 200); do printf 'row%03d\\n' $n; done; echo LI'VE'END",
        "LIVEEND",
    );
    client
        .master
        .write_all(b"\x1d[\x1b[5~")
        .expect("enter history and page up");
    assert!(
        wait_until(|| screen.top().contains("scroll:") && screen.has_row("row160")),
        "history shows a previous page; screen:\n{}",
        screen.dump()
    );
    assert!(!screen.has_row("LIVEEND"));
    client.master.write_all(b"q").expect("return live");
    assert!(
        wait_until(|| !screen.top().contains("scroll:") && screen.has_row("LIVEEND")),
        "q returns live; screen:\n{}",
        screen.dump()
    );
    shell_answers(&mut client, &screen, "echo AF'TER'HISTORY", "AFTERHISTORY");
    exit_cleanly(&mut client, &screen, &daemon);
}

/// With two addresses to one daemon, the window lists both; once the spare
/// has been checked, `2` and `Enter` move the session onto it: the window
/// closes and the line names the spare as the address in use.
#[test]
#[cfg(target_os = "linux")]
fn the_window_switches_to_a_live_spare() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    // `qshd serve` listens on every address, so both loopback addresses
    // reach the same daemon. Linux answers on all of 127.0.0.0/8; macOS
    // has only 127.0.0.1 on loopback by default, hence Linux only.
    let first = format!("127.0.0.1:{}", daemon.port);
    let spare = format!("127.0.0.2:{}", daemon.port);
    let mut client = spawn_qsh(
        &["-i", key_path.to_str().expect("utf-8"), &first, &spare],
        config.path(),
    );
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    assert!(
        wait_for(Duration::from_secs(10), || {
            let top = screen.top();
            top.contains(&first) && ends_with_latency(&top)
        }),
        "with several addresses, the line names the one in use and its latency; top row: {:?}",
        screen.top()
    );

    client.master.write_all(b"\x1ds").expect("type ctrl-] s");
    assert!(
        wait_until(|| screen.window_open()),
        "Ctrl-] s must open the connection-state window; screen:\n{}",
        screen.dump()
    );
    let opened = Instant::now();
    assert!(
        wait_for(Duration::from_secs(45), || screen
            .window_value(&spare)
            .is_some_and(|v| ends_with_latency(&v))),
        "the spare must be checked and show its round trip within 45 s; screen:\n{}",
        screen.dump()
    );
    let checked_after = opened.elapsed();

    client.master.write_all(b"2\r").expect("type 2 and enter");
    let pressed = Instant::now();
    assert!(
        wait_for(Duration::from_secs(5), || {
            !screen.window_open() && screen.top().contains(&spare)
        }),
        "Enter on a live spare must move the session there and close the window; screen:\n{}",
        screen.dump()
    );
    let switched_after = pressed.elapsed();
    assert!(
        !screen.top().contains(&first),
        "the line names only the address in use; top row: {:?}",
        screen.top()
    );

    shell_answers(&mut client, &screen, "echo SW'IT'CHED", "SWITCHED");
    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!(
        "window_switch: spare checked {checked_after:?} after opening, switched \
         {switched_after:?} after Enter; whole test {:?}",
        started.elapsed()
    );
}

/// `Ctrl-] .` leaves with exit code 1 and says the session is kept; the same
/// command run again lands in the same shell, which still knows a variable
/// set before leaving.
#[test]
fn ctrl_bracket_dot_leaves_and_the_next_run_comes_back() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    // The same config home for both runs: the pinned key and the session's
    // token are what make the second run a return.
    let config = tempfile::tempdir().expect("tempdir");
    let mut first = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&first);

    answer_yes(&mut first, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    first.type_line("export QSH_MARK=kept");
    shell_answers(&mut first, &screen, "echo BEFORE'LE'AVING", "BEFORELEAVING");

    first.master.write_all(b"\x1d.").expect("type ctrl-] .");
    let pressed = Instant::now();
    let mut status = None;
    while pressed.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(s)) = first.child.try_wait() {
            status = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let left_after = pressed.elapsed();
    let status = status.unwrap_or_else(|| {
        panic!(
            "Ctrl-] . must end the run within 5 s; screen:\n{}",
            screen.dump()
        )
    });
    assert_eq!(
        status.code(),
        Some(1),
        "leaving on the user's own instruction is exit 1; client saw: {}",
        screen.text()
    );
    assert!(
        wait_until(|| screen.has("qsh: left 127.0.0.1; the session is kept on the server")),
        "the way back must be printed on the way out; client saw: {}",
        screen.text()
    );

    let mut second = spawn_client(&daemon, &key_path, config.path());
    let screen2 = Screen::of(&second);
    // No question this time: the key is pinned, so the line is the first
    // thing that shows.
    wait_for_the_line(&screen2, &daemon);
    assert!(
        !screen2.has("Key fingerprint"),
        "the second run must not ask again; client saw: {}",
        screen2.text()
    );
    shell_answers(&mut second, &screen2, "echo M'AR'K$QSH_MARK", "MARKkept");

    exit_cleanly(&mut second, &screen2, &daemon);
    eprintln!(
        "leave_and_return: exit 1 {left_after:?} after Ctrl-] .; whole test {:?}",
        started.elapsed()
    );
}

/// `--escape none --status off`: no line, the shell has the whole height,
/// and `Ctrl-]` is an ordinary key that reaches the shell.
#[test]
fn escape_none_and_status_off() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client_with(
        &daemon,
        &key_path,
        config.path(),
        &["--escape", "none", "--status", "off"],
    );
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    assert!(
        the_shell_sees(&mut client, &screen, "24 80", Duration::from_secs(20)),
        "without the line the shell has all 24 rows; screen:\n{}\ndaemon: {}",
        screen.dump(),
        daemon.output_text()
    );
    assert!(
        !screen.has_row("23 80"),
        "the shell must never have been told a row less; screen:\n{}",
        screen.dump()
    );
    assert!(
        !screen.top().starts_with(LINE_HINT),
        "--status off shows no line; top row: {:?}",
        screen.top()
    );

    // Once the echo has run, the shell has handed the terminal to `cat`:
    // a Ctrl-] typed after that goes to `cat`, not to the line editor.
    shell_answers(
        &mut client,
        &screen,
        "echo CAT'ST'ARTS; cat -v",
        "CATSTARTS",
    );
    let before = screen.count_rows("^]");
    client
        .master
        .write_all(b"\x1d\r")
        .expect("type ctrl-] enter");
    assert!(
        wait_until(|| screen.count_rows("^]") > before),
        "with --escape none, Ctrl-] must reach the shell's program; screen:\n{}",
        screen.dump()
    );

    client.master.write_all(b"\x03").expect("type ctrl-c");
    // Typed until the run ends: a Ctrl-C makes the shell drop the keystrokes
    // right behind it. `exit 0`, not a bare `exit`: that one would hand on
    // the status of `cat`, which the Ctrl-C ended (130), and the run ends
    // with its shell's code.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut status = None;
    while Instant::now() < deadline && status.is_none() {
        client.type_line("exit 0");
        if wait_for(Duration::from_secs(1), || {
            matches!(client.child.try_wait(), Ok(Some(_)))
        }) {
            status = client.child.try_wait().ok().flatten();
        }
    }
    let status = status.unwrap_or_else(|| {
        panic!(
            "exit after Ctrl-C must end the run; screen:\n{}",
            screen.dump()
        )
    });
    assert_eq!(
        status.code(),
        Some(0),
        "a shell that exited is not a failure; client saw: {}",
        screen.text()
    );
    eprintln!("escape_none_status_off: whole test {:?}", started.elapsed());
}

/// A link that goes silent turns the line's right part red with the silence's
/// age; `Ctrl-] r` then says where it reconnects to, still on red; once the
/// network is back the line shows a latency again, off red, over the same
/// shell.
#[test]
fn a_silent_link_turns_the_line_red_and_the_reconnect_is_named() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_qsh(
        &[
            "--port",
            &relay.port.to_string(),
            "-i",
            key_path.to_str().expect("utf-8"),
            "127.0.0.1",
        ],
        config.path(),
    );
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    client.type_line("export QSH_MARK=kept");
    shell_answers(&mut client, &screen, "echo BEFORE'CU'T", "BEFORECUT");
    assert!(
        wait_for(Duration::from_secs(10), || ends_with_latency(&screen.top())),
        "a live link shows its latency; top row: {:?}",
        screen.top()
    );
    assert!(!screen.line_is_red(), "a live link is not an alarm");

    relay.cut();
    let cut = Instant::now();
    assert!(
        wait_for(Duration::from_secs(10), || {
            ends_with_silence(&screen.top()) && screen.line_is_red()
        }),
        "a silent link shows how long it has been silent, on red; top row: {:?}",
        screen.top()
    );
    let red_after = cut.elapsed();

    client.master.write_all(b"\x1dr").expect("type ctrl-] r");
    assert!(
        wait_until(|| {
            screen.top().contains("reconnecting to 127.0.0.1") && screen.line_is_red()
        }),
        "a reconnect names the address it tries, on red; top row: {:?}",
        screen.top()
    );

    relay.restore();
    let restored = Instant::now();
    let deadline = restored + Duration::from_secs(60);
    let mut back = false;
    while Instant::now() < deadline && !back {
        // Ctrl-U first: keystrokes typed while no link is live are dropped,
        // so an earlier attempt may have left half a line behind.
        client.master.write_all(b"\x15").expect("type ctrl-u");
        client.type_line("echo MA\\RK$QSH_MARK");
        back = wait_for(Duration::from_secs(1), || screen.has_row("MARKkept"));
    }
    assert!(
        back,
        "once the network is back the run returns to the same shell; screen:\n{}\ndaemon: {}",
        screen.dump(),
        daemon.output_text()
    );
    let back_after = restored.elapsed();
    assert!(
        wait_for(Duration::from_secs(10), || {
            ends_with_latency(&screen.top()) && !screen.line_is_red()
        }),
        "back on a live link, the line shows a latency off red; top row: {:?}",
        screen.top()
    );

    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!(
        "silent_red: red {red_after:?} after the cut, back {back_after:?} after the restore; \
         whole test {:?}",
        started.elapsed()
    );
}

/// The escape that switches the terminal to its alternate screen, and the
/// one that switches back.
const ALT_ON: &[u8] = b"\x1b[?1049h";
const ALT_OFF: &[u8] = b"\x1b[?1049l";
/// How every full repaint starts: the session's first frame is one, and so
/// is the frame after a return from the background.
const FULL_REPAINT: &[u8] = b"\x1b[0m\x1b[H\x1b[2J";

/// Every place `needle` starts in `hay`.
fn positions(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    (0..hay.len().saturating_sub(needle.len() - 1))
        .filter(|&i| hay[i..].starts_with(needle))
        .collect()
}

/// The switches between the screens, in the order they were written:
/// `true` onto the alternate screen, `false` back.
fn switches(bytes: &[u8]) -> Vec<bool> {
    let mut all: Vec<(usize, bool)> = positions(bytes, ALT_ON)
        .into_iter()
        .map(|at| (at, true))
        .chain(positions(bytes, ALT_OFF).into_iter().map(|at| (at, false)))
        .collect();
    all.sort_unstable();
    all.into_iter().map(|(_, on)| on).collect()
}

/// Whether the whole session was drawn on the alternate screen: the
/// fingerprint question, a line from before the session, comes before the
/// switch onto it, the first frame after it; and the last switch goes back
/// after the last frame. Returns where that last switch is.
fn drawn_on_the_alternate_screen(screen: &Screen) -> usize {
    let bytes = screen.bytes();
    let on = positions(&bytes, ALT_ON);
    let off = positions(&bytes, ALT_OFF);
    let repaints = positions(&bytes, FULL_REPAINT);
    let asked = screen
        .text()
        .find("Key fingerprint")
        .expect("the fingerprint was asked about");
    assert!(
        !on.is_empty() && !off.is_empty(),
        "the session must switch to the alternate screen and back; client saw: {:?}",
        screen.text()
    );
    assert!(
        asked < on[0],
        "the lines before the session stay on the terminal's own screen: the question at \
         {asked} must come before the switch at {}",
        on[0]
    );
    assert!(
        repaints.first().is_some_and(|&first| on[0] < first),
        "the switch must come before the first frame; switch at {}, repaints at {repaints:?}",
        on[0]
    );
    let last_off = *off.last().expect("checked above");
    assert!(
        repaints.last().is_some_and(|&last| last < last_off),
        "the switch back must come after the last frame; back at {last_off}, repaints at \
         {repaints:?}"
    );
    assert!(
        on.last().is_some_and(|&last| last < last_off),
        "the run must end on the terminal's own screen; client saw: {:?}",
        screen.text()
    );
    last_off
}

/// Sends `signal` to the client.
fn send(client: &Client, signal: nix::sys::signal::Signal) {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(client.pid() as i32), signal)
        .expect("send the signal");
}

/// `Ctrl-] .`: the session is drawn on the alternate screen, the switch back
/// comes before `qsh: left ...`, and what stays on the terminal is what was
/// there before the session and that line -- none of the shell's own.
#[test]
fn leaving_with_ctrl_bracket_dot_leaves_the_alternate_screen_first() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    shell_answers(
        &mut client,
        &screen,
        "for n in $(seq 1 60); do echo L$n; done; echo SEQ'DO'NE",
        "SEQDONE",
    );

    client.master.write_all(b"\x1d.").expect("type ctrl-] .");
    let status = wait_for_exit(&mut client.child).expect("Ctrl-] . ends the run");
    assert_eq!(status.code(), Some(1), "client saw: {}", screen.text());
    let left = "qsh: left 127.0.0.1; the session is kept on the server";
    assert!(
        wait_until(|| screen.has(left)),
        "the way back must be printed on the way out; client saw: {}",
        screen.text()
    );

    let back = drawn_on_the_alternate_screen(&screen);
    assert_eq!(
        switches(&screen.bytes()),
        vec![true, false],
        "onto the alternate screen once, back once"
    );
    let said = screen.text().find(left).expect("checked above");
    assert!(
        back < said,
        "`qsh: left` must be printed on the terminal's own screen, after the switch back"
    );

    // What the person sees now, and can scroll back to: the question, the
    // line on the way out -- and nothing of the shell's.
    let kept: Vec<String> = screen.history().into_iter().chain(screen.rows()).collect();
    let all = kept.join("\n");
    assert!(all.contains("Key fingerprint"), "kept:\n{all}");
    assert!(all.contains(left), "kept:\n{all}");
    assert!(
        !kept
            .iter()
            .any(|l| l.contains("SEQDONE") || l.trim() == "L30" || l.starts_with(LINE_HINT)),
        "none of the session's screen may stay behind; kept:\n{all}"
    );
    eprintln!("alt_screen_leave: whole test {:?}", started.elapsed());
}

/// Confirmed session loss restores the screen before its explanation/question;
/// declining the replacement then exits 13.
#[test]
fn a_lost_session_leaves_the_alternate_screen_before_saying_so() {
    let _serial = serialised();
    let started = Instant::now();
    let (mut daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    shell_answers(
        &mut client,
        &screen,
        "echo BEFORE'RE'START",
        "BEFORERESTART",
    );

    daemon.restart();
    client.master.write_all(b"\x1dr").expect("type ctrl-] r");
    assert!(
        wait_until(|| screen.has("Start a new session? [Y/n]")),
        "{}",
        screen.text()
    );
    let back = drawn_on_the_alternate_screen(&screen);
    let question = screen.text().find("Start a new session?").unwrap();
    assert!(back < question, "the question follows terminal restoration");
    client.master.write_all(b"no\n").unwrap();
    let status = wait_for_exit(&mut client.child).unwrap_or_else(|| {
        panic!(
            "a session the server no longer has must end the run; client saw: {}",
            screen.text()
        )
    });
    assert_eq!(status.code(), Some(13), "client saw: {}", screen.text());
    let says = "the session on 127.0.0.1 is no longer on the server";
    assert!(
        wait_until(|| screen.has(says)),
        "the reason must be printed on the way out; client saw: {}",
        screen.text()
    );

    let back = drawn_on_the_alternate_screen(&screen);
    assert_eq!(switches(&screen.bytes()), vec![true, false]);
    let said = screen.text().find(says).expect("checked above");
    assert!(back < said, "the reason is printed after the switch back");
    eprintln!("alt_screen_lost: whole test {:?}", started.elapsed());
}

/// SIGTERM: the run ends, and the terminal is back on its own screen.
#[test]
fn sigterm_leaves_the_alternate_screen() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    shell_answers(&mut client, &screen, "echo BEFORE'TE'RM", "BEFORETERM");

    send(&client, nix::sys::signal::Signal::SIGTERM);
    let status = wait_for_exit(&mut client.child).expect("SIGTERM ends the run");
    assert_eq!(status.code(), Some(0), "client saw: {}", screen.text());
    // The last of the output may still be on its way through the master.
    assert!(
        wait_until(|| switches(&screen.bytes()) == vec![true, false]),
        "onto the alternate screen once, back once; client saw: {:?}",
        screen.text()
    );
    drawn_on_the_alternate_screen(&screen);
    eprintln!("alt_screen_sigterm: whole test {:?}", started.elapsed());
}

/// SIGTSTP: the terminal goes back to its own screen before the client
/// stops, and after SIGCONT the session is back on the alternate screen and
/// drawn in full.
///
/// The client is its test terminal's session leader, so its process group is
/// orphaned and the kernel does not actually stop it on SIGTSTP -- it comes
/// straight back: what is checked is what it writes around the stop.
#[test]
fn sigtstp_leaves_the_alternate_screen_and_sigcont_comes_back_to_it() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    wait_for_the_line(&screen, &daemon);
    shell_answers(&mut client, &screen, "echo BEFORE'ST'OP", "BEFORESTOP");

    let before = screen.bytes().len();
    send(&client, nix::sys::signal::Signal::SIGTSTP);
    assert!(
        wait_until(|| switches(&screen.bytes()).starts_with(&[true, false])),
        "SIGTSTP must switch back to the terminal's own screen; client saw: {:?}",
        screen.text()
    );
    // What a shell's `fg` sends; here the client may already be back.
    send(&client, nix::sys::signal::Signal::SIGCONT);
    assert!(
        wait_until(|| switches(&screen.bytes()) == vec![true, false, true]),
        "after SIGCONT the session is back on the alternate screen; client saw: {:?}",
        screen.text()
    );
    let bytes = screen.bytes();
    let off = positions(&bytes, ALT_OFF)[0];
    let on_again = positions(&bytes, ALT_ON)[1];
    assert!(before <= off, "the switch back came with the stop");
    assert!(
        wait_until(|| positions(&screen.bytes(), FULL_REPAINT)
            .iter()
            .any(|&at| at > on_again)),
        "back on the alternate screen, the session is drawn in full"
    );
    wait_for_the_line(&screen, &daemon);
    shell_answers(&mut client, &screen, "echo AFTER'CO'NT", "AFTERCONT");

    exit_cleanly(&mut client, &screen, &daemon);
    assert!(wait_until(
        || switches(&screen.bytes()) == vec![true, false, true, false]
    ));
    drawn_on_the_alternate_screen(&screen);
    eprintln!("alt_screen_tstp: whole test {:?}", started.elapsed());
}
