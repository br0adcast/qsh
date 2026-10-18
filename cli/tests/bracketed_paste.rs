//! Local escape commands must not intercept bytes in an authenticated paste.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use support::*;

#[test]
fn pasted_leave_reaches_the_remote_shell_and_interactive_leave_still_works() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_client_with(&daemon, &key_path, config.path(), &["--predict", "never"]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    let text = || String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
    let preview = || format!("{:?}", text().chars().take(1024).collect::<String>());
    let screen_has = |needle: &str| {
        let mut model = terminal::TerminalCore::new(80, 24);
        model.feed(&seen.lock().unwrap());
        model
            .frame()
            .cells
            .iter()
            .map(|cell| cell.ch)
            .collect::<String>()
            .contains(needle)
    };
    assert!(
        wait_until(|| text().contains("Key fingerprint")),
        "{}",
        preview()
    );
    client.master.write_all(b"yes\n").unwrap();

    let paste = b"\x1b[200~\x1d.\x1ds\x1dh\x1dr\x1d?\x1d[\x1b[201~";
    let expected = [b"x".as_slice(), paste].concat();
    // The remote reader has a five-second idle timeout even if input is
    // lost. Its hex output proves the bytes reached the authenticated PTY;
    // a local echo or predicted rendering cannot manufacture this result.
    client.type_line(&format!(
        "stty raw -echo min 0 time 50; printf '\\033[?2004hREADY-%s\\n' \"$((6*7))\"; \
         dd bs=1 count={} 2>/dev/null | od -An -v -tx1 | tr -d ' \\n'; \
         stty sane; printf '\\033[?2004lDONE-%s\\n' \"$((6*7))\"",
        expected.len()
    ));
    assert!(wait_until(|| screen_has("READY-42")), "{}", preview());

    client.master.write_all(b"\x1d\x1b").unwrap();
    client.master.write_all(b"x").unwrap();
    // Separate writes exercise the actual stdin path; exhaustive and
    // byte-at-a-time split guarantees belong to the deterministic unit tests.
    for chunk in [
        &paste[..2],
        &paste[2..7],
        &paste[7..paste.len() - 2],
        &paste[paste.len() - 2..],
    ] {
        client.master.write_all(chunk).unwrap();
    }
    assert!(
        wait_until(|| screen_has("DONE-42") || client.child.try_wait().unwrap().is_some()),
        "{}",
        preview()
    );
    assert!(
        client.child.try_wait().unwrap().is_none(),
        "pasted Leave must not exit the client"
    );
    let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    assert!(screen_has(&hex), "remote capture mismatch: {}", preview());
    assert!(screen_has("DONE-42"), "{}", preview());

    client.master.write_all(b"\x1d.").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
}
