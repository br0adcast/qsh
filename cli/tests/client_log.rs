//! The client's log end to end: a real `qsh` on a pseudo-terminal, with a
//! temporary `HOME`/`XDG_CACHE_HOME` (`support::spawn_qsh`), writes its log
//! there without `--verbose`, one timestamped line per record.

mod support;

use std::path::{Path, PathBuf};

use support::{serialised, spawn_qsh, wait_for_exit};

/// A fresh ed25519 key for `qsh -i`, in `dir`.
fn client_key(dir: &Path) -> PathBuf {
    let key = ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate");
    let path = dir.join("id_test");
    std::fs::write(
        &path,
        key.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .as_bytes(),
    )
    .expect("write key");
    path
}

/// `YYYY-MM-DD HH:MM:SS.mmm UTC [pid] ` at the start of `line`.
fn has_header(line: &str, pid: u32) -> bool {
    let b = line.as_bytes();
    let digits = |r: std::ops::Range<usize>| {
        r.into_iter()
            .all(|i| b.get(i).is_some_and(u8::is_ascii_digit))
    };
    digits(0..4)
        && b.get(4) == Some(&b'-')
        && digits(5..7)
        && b.get(7) == Some(&b'-')
        && digits(8..10)
        && b.get(10) == Some(&b' ')
        && digits(11..13)
        && digits(14..16)
        && digits(17..19)
        && b.get(19) == Some(&b'.')
        && digits(20..23)
        && line
            .get(23..)
            .is_some_and(|rest| rest.starts_with(&format!(" UTC [{pid}] ")))
}

#[test]
fn a_run_on_a_silent_address_is_logged_without_verbose() {
    let _serial = serialised();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let silent = socket.local_addr().unwrap().port();
    let home = tempfile::tempdir().expect("tempdir");
    let key = client_key(home.path());
    let address = format!("127.0.0.1:{silent}");
    let mut client = spawn_qsh(&["-i", key.to_str().expect("utf-8"), &address], home.path());
    let pid = client.child.id();
    let status = wait_for_exit(&mut client.child);
    assert_eq!(status.and_then(|s| s.code()), Some(12));

    let log = std::fs::read_to_string(home.path().join("qsh").join("log")).expect("the log");
    // Shown with `--nocapture`: what a run like this leaves behind.
    println!("the log:\n{log}");
    let lines: Vec<&str> = log.lines().collect();
    assert!(!lines.is_empty(), "an empty log");
    for line in &lines {
        assert!(
            has_header(line, pid),
            "no header: {line:?}\nthe log:\n{log}"
        );
    }
    let start = format!("INFO  qsh: qsh {} (build ", env!("CARGO_PKG_VERSION"));
    assert!(lines[0].contains(&start), "the first line: {log}");
    assert!(lines[0].contains(") starting: "), "the first line: {log}");
    assert!(
        lines[0].contains(&format!("addresses: 127.0.0.1:{silent}")),
        "{log}"
    );
    let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let no_answer = at(&format!("127.0.0.1:{silent}: no answer"));
    let summary = at("could not connect");
    let exiting = at("INFO  qsh: qsh exiting with code 12");
    assert!(no_answer.is_some(), "no `no answer` line: {log}");
    assert!(summary.is_some(), "no exit-12 summary: {log}");
    assert_eq!(
        exiting,
        Some(lines.len() - 1),
        "the exit marker last: {log}"
    );
    assert!(summary < exiting, "{log}");
    // One prefix per line -- the component's -- and a failure at `warn`.
    assert!(!log.contains("qsh: qsh:"), "a doubled prefix: {log}");
    assert!(
        at(&format!(
            "WARN  qsh: could not get the server's key for 127.0.0.1:{silent}: "
        ))
        .is_some(),
        "the key request's failure at warn: {log}"
    );
}
