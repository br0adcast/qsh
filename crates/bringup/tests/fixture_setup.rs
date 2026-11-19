//! Constructor-only fixture preflight: no daemon/image/CLI entry point.
//! Local runs select constructor_sftp_ or subsystem_classification_ explicitly;
//! support_home also includes unrelated prebuilt-daemon tests for normal CI.
#![cfg(target_os = "linux")]

mod support_home;
use support_home::{Sandbox, VerificationFault};

#[test]
fn constructor_sftp_fail_verification() {
    constructor(VerificationFault::FailVerification);
}
#[test]
fn constructor_sftp_hold_uploaded_verification() {
    constructor(VerificationFault::HoldUploadedVerification);
}
fn constructor(fault: VerificationFault) {
    // This constructor only authenticates generated keys, inspects private
    // HOME and round-trips synthetic SFTP bytes. Do not add image/start calls.
    let sandbox = Sandbox::start_with_fault(&[], fault);
    assert_eq!(std::fs::read_dir(sandbox.cache()).unwrap().count(), 0);
    assert!(!sandbox.cache().join("control.sock").exists());
    assert!(!sandbox.home.path().join(".verification-held").exists());
    assert!(!sandbox
        .home
        .path()
        .join(".verification-hold-complete")
        .exists());
    drop(sandbox);
}

#[test]
fn subsystem_classification_trims_only_trailing_ascii_space_tab() {
    for (original, accepted) in [
        ("internal-sftp", true),
        ("internal-sftp ", true),
        ("internal-sftp\t", true),
        ("internal-sftp \t \t", true),
        ("internal-sftp-extra", false),
        ("internal-sftp -x", false),
        ("internal-sftp\t-x", false),
        (" internal-sftp", false),
        ("internal-sftp\n", false),
    ] {
        // Execute only the production classification builtins, never its
        // external-server route or arbitrary-command fallback.
        let script = format!(
            "{}printf '%s' \"$SSH_ORIGINAL_COMMAND\"; [ \"$subsystem\" = internal-sftp ]",
            support_home::SFTP_CLASSIFICATION
        );
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .env("SSH_ORIGINAL_COMMAND", original)
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap();
        assert_eq!(output.status.success(), accepted, "input {original:?}");
        assert_eq!(
            output.stdout,
            original.as_bytes(),
            "original command changed"
        );
    }
}
