//! Task 7 of the helper-process split: proof that a client sees nothing
//! different once `qshd serve --system` is the process actually answering.
//! Everything below the seam (`helper/mod.rs`, `helper/server.rs`,
//! `helper/spawner.rs`) is new; this is the one test that never looks at
//! any of it directly -- it only drives a real client against a real
//! `qshd serve --system` process and checks what comes back over the wire,
//! exactly as `serve_channels.rs`/`serve_terminal_type.rs` do for the
//! ordinary (non-system) daemon.
//!
//! `#![cfg(feature = "system")]`: without the feature `--system` is refused
//! outright (a plain CLI error, never a live daemon), so there is nothing
//! here worth compiling under the crate's default build.

#![cfg(feature = "system")]

mod common;

use ssh_key::{Algorithm, PrivateKey};

/// What this file's one test does to the machine it runs on, for the loud
/// `SKIPPED` line (see `common::on_a_disposable_host`): no account, but --
/// since Task 2 of slice 3 -- the machine's real `/etc/pam.d/qshd`,
/// installed so the real `qshd serve --system` it spawns can start at all.
const WHAT_THIS_TEST_DOES: &str =
    "starts a real `qshd serve --system` daemon, installing the machine's /etc/pam.d/qshd so it can";

/// The system mode serves a shell exactly as the personal mode does -- the
/// processes are split, the behaviour is not. Everything below the seam is
/// new; everything a client sees must be unchanged.
///
/// Needs root: since Task 1 of the system-mode-slice2b plan
/// (`qshd/src/serve.rs`), `--system` refuses to start at all otherwise -- see
/// `common::start_daemon`'s docs. And, since Task 2 of slice 3, it also
/// overwrites the machine's real `/etc/pam.d/qshd` (see
/// [`WHAT_THIS_TEST_DOES`]), the same write `system_mode_pam.rs` and
/// `system_mode_accounts.rs` already gate -- so this test runs through
/// `common::on_a_disposable_host` rather than a bare root check: root AND
/// `QSHD_TEST_DISPOSABLE_HOST=1`, or a loud `SKIPPED` line and nothing
/// touched. Run it like this, from the repository's root:
///
/// ```text
/// cargo test -p qshd --features system --test system_mode_shell --locked --no-run
/// docker run --rm --init -e QSHD_TEST_DISPOSABLE_HOST=1 \
///     -v "$PWD:$PWD:ro" -w "$PWD" ubuntu:24.04 \
///     "$PWD/target/debug/deps/system_mode_shell-<hash>" --nocapture
/// ```
#[test]
fn the_system_mode_serves_a_shell_over_the_seam() {
    common::on_a_disposable_host(
        "the_system_mode_serves_a_shell_over_the_seam",
        WHAT_THIS_TEST_DOES,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let key =
                PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");

            // The listed key, at the location `start_daemon` points `$HOME`
            // to.
            common::write_authorized_keys(dir.path(), &key);

            // `start_daemon` points `--host-key` at a file inside `dir`:
            // the system mode's real default is `/etc/qshd/host_key`, and
            // a test must never write there. It also proves the daemon is
            // genuinely alive (not just that it printed a banner right
            // before dying) by retrying on a fresh port rather than
            // accepting a process that never got that far -- see its own
            // docs in `tests/common/mod.rs`.
            //
            // Since the system-mode-slice3 plan's Task 2, the daemon also
            // refuses to start at all without its own PAM service file
            // (`refuse_without_pam_service` in `serve.rs`) -- a
            // container's `/etc/pam.d` has no reason to carry `qshd` on
            // its own, so this test installs the shipped one first, the
            // same way `system_mode_pam.rs` and `system_mode_accounts.rs`
            // do.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (mut daemon, server_pub, port) = common::start_daemon(dir.path());

            // Connect, prove the listed key (with the mandatory login the
            // server's nonce now requires -- see
            // `run_one_command_in_a_shell`'s docs), open a shell channel,
            // and run a command in it. The function waits for a sentinel
            // printed AFTER the command, not for a fixed delay or for the
            // command's own text, so a daemon that died right after its
            // banner (or a shell that never actually ran) shows up as a
            // loud, bounded timeout -- never a silent pass.
            //
            // The command is `printf`, not `echo split-works`, on
            // purpose: a pseudo-terminal echoes the typed line back
            // verbatim before the shell ever runs it, so a LITERAL
            // `split-works` in the command would let the assertion below
            // pass off nothing but that echo -- true even if the seam
            // this task exists to prove never actually delivered a
            // command to a real shell. `%s` means the substring the test
            // checks for exists only in `printf`'s OWN output, never in
            // what gets typed.
            let output = common::run_one_command_in_a_shell(
                port,
                server_pub,
                &key,
                &common::current_login(),
                "printf 'split-%s' works",
            );

            assert!(
                output.contains("split-works"),
                "the shell's output must come back across the seam, got {output:?}"
            );

            // `Daemon`'s own `Drop` would do this anyway (even if an
            // assertion above had panicked), but doing it here too lets
            // the process's exit be observed as part of this test rather
            // than only as background cleanup.
            let _ = daemon.child.kill();
            let _ = daemon.child.wait();
        },
    );
}
