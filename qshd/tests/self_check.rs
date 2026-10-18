//! `qshd self-check` is what a running daemon asks of a staged binary before
//! it lets that binary replace it (spec §4.2): one JSON line, exit code 0.

use std::process::Command;

use qshd::state::{SelfCheck, TEST_BUILD_LABELS_ENV};
use sha2::{Digest, Sha256};

fn self_check(extra_env: Option<String>) -> SelfCheck {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qshd"));
    cmd.arg("self-check")
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .env_remove(TEST_BUILD_LABELS_ENV);
    if let Some(labels) = extra_env {
        cmd.env(TEST_BUILD_LABELS_ENV, labels);
    }
    let out = cmd.output().expect("qshd self-check runs");
    assert!(out.status.success(), "exit {:?}", out.status);
    let text = String::from_utf8(out.stdout).expect("utf-8");
    let first = text.lines().next().expect("one line");
    SelfCheck::from_line(first).expect("a self-check line")
}

#[test]
fn self_check_prints_its_build_architecture_and_protocol() {
    let check = self_check(None);
    assert_eq!(check.arch, std::env::consts::ARCH);
    assert_eq!(check.protocol, transport::channel::PROTOCOL_VERSION);
    assert_eq!(check.protocols, vec![2]);
    assert!(check
        .transport_features
        .iter()
        .any(|name| name == "channel-geometry"));
    assert!(!check
        .transport_features
        .iter()
        .any(|name| name == "auth-accepted"));
    assert!(check
        .handover_versions
        .contains(&qshd::state::HANDOVER_VERSION));
    assert_eq!(
        check.transport_features,
        transport::Features::SUPPORTED
            .names()
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>(),
        "what this build implements (spec §5.5)"
    );
    assert_eq!(
        check.build,
        qshd::state::build_label(),
        "the binary and the library are one build"
    );
}

/// The test hook: a debug build takes its label from the override keyed by
/// its own checksum -- and ignores entries for other checksums.
#[test]
fn a_debug_build_takes_its_label_from_the_override_keyed_by_its_checksum() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_qshd")).expect("read qshd");
    let sum = hex::encode(Sha256::digest(&bytes));
    let labels = format!("{}=1,{sum}=4242", "0".repeat(64));
    assert_eq!(self_check(Some(labels)).build, 4242);
}
