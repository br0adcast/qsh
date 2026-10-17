//! Task 10 of the system-mode-slice2c plan: PAM decides who gets in, end to
//! end, with the real library, the real modules and the real
//! `/etc/pam.d/qshd`.
//!
//! Every other PAM test in this crate goes through `pam_start_confdir` with
//! a stack of its own (`helper::pam`'s and `helper::monitor`'s unit tests):
//! that needs no privileges and never touches `/etc/pam.d`, which is exactly
//! why it cannot show either of the two things this file exists for --
//!
//! - [`an_expired_account_is_refused`]: a real `pam_unix` account stack, a
//!   real expired account, and the refusal that follows. The only place in
//!   the slice where a stock module's verdict, rather than `pam_permit.so`
//!   or `pam_deny.so`, decides anything.
//! - [`the_service_file_in_etc_pam_d_is_what_decides`]: the daemon reads
//!   `/etc/pam.d/qshd` -- the file the package will ship -- and not some
//!   built-in default. `config::HelperConfig::pam_service` is `"qshd"` and
//!   no flag redirects it, so the only way to show this is to change the
//!   machine's own file and watch the verdict change with it.
//!
//! The third, [`a_session_is_closed_when_the_login_ends`], repeats what
//! `monitor`'s own `the_session_is_opened_and_closed_by_the_monitor` shows
//! in-process, over the wire: a login's PAM session is opened when it starts
//! and closed when it ends.
//!
//! Until these have run in a container, slice 2c is NOT verified, however
//! many green runs there are on a host -- on a host all three skip.
//!
//! Same conditions as `system_mode_accounts.rs`, and for the same reason
//! plus one: the tests create real accounts AND overwrite `/etc/pam.d/qshd`,
//! the file every `qshd` on the machine reads. Root, and
//! `QSHD_TEST_DISPOSABLE_HOST=1`, which only a disposable container may set;
//! loudly skipped otherwise. Run it like this, from the repository's root:
//!
//! ```text
//! cargo test -p qshd --features system --test system_mode_pam --locked --no-run
//! docker run --rm --init -e QSHD_TEST_DISPOSABLE_HOST=1 \
//!     -v "$PWD:$PWD:ro" -w "$PWD" ubuntu:24.04 sh -c \
//!     'apt-get update -qq && apt-get install -y -qq libpam-modules libpam-runtime >/dev/null && \
//!      "'"$PWD"'/target/debug/deps/system_mode_pam-<hash>" --test-threads=1 --nocapture'
//! ```
//!
//! - `libpam-modules` brings `pam_unix.so`, `pam_permit.so`, `pam_deny.so`
//!   and `pam_exec.so`; `libpam-runtime` generates the `common-account` and
//!   `common-session` the shipped service file includes. No `-dev` package:
//!   the test binary is built on the host and only loads what is there.
//! - Everything else -- the mount at its own absolute path, `--init`, the
//!   image's glibc -- is as `system_mode_accounts.rs` explains it.
//! - One test binary at a time, and a fresh container for each: the
//!   turn-taking that keeps these tests out of each other's accounts and out
//!   of each other's `/etc/pam.d/qshd` is per binary (see
//!   `common::on_a_disposable_host`), so `--test '*'`, which runs binaries
//!   in parallel, is not the way to run this and `system_mode_accounts.rs`
//!   on a disposable host. Nor is one container after the other: this suite
//!   leaves behind whichever stack it installed last -- a `pam_deny` account
//!   stack, as often as not -- and the next suite's logins would be decided
//!   by it. `--rm` and a new container is the whole cleanup.

#![cfg(feature = "system")]

mod common;

use std::path::PathBuf;

use common::run_account_command_or_panic;

/// What these tests do to the machine they run on, for the loud `SKIPPED`
/// line (see `common::on_a_disposable_host`). More than
/// `system_mode_accounts.rs` does: this suite also overwrites the file
/// every `qshd` on the machine reads.
const WHAT_THESE_TESTS_DO: &str =
    "creates real accounts and overwrites the machine's /etc/pam.d/qshd";

/// What a positive control asks the shell, and -- with
/// [`who_am_i_answer`] -- the only text that can prove the shell ran it.
///
/// NOT `id -un` checked with `output.contains(&account.name)`. A channel's
/// output carries three things besides what the command printed: the
/// pseudo-terminal's verbatim echo of the typed line, whatever the shell
/// prints as a prompt, and whatever a login banner adds -- and a prompt
/// commonly carries the account's own name, so a bare `contains(name)` can
/// be satisfied with `id -un` never having run at all. `system_mode_shell.rs`
/// carries the same scar for the same reason (`printf 'split-%s' works`
/// rather than `echo split-works`), and so does `system_mode_accounts.rs`'s
/// `WHO_AM_I`.
///
/// The echo of the typed line carries `qshd-pam-who=[%s]`, literally; only
/// `printf` actually running can put an account's name between those
/// brackets.
const WHO_AM_I: &str = r#"printf 'qshd-pam-who=[%s]\n' "$(id -un)""#;

/// The exact text [`WHO_AM_I`] prints for `account`.
fn who_am_i_answer(account: &str) -> String {
    format!("qshd-pam-who=[{account}]")
}

/// The needle the helper writes when a login's account stack refuses it
/// (`qshd/src/helper/server.rs`). The wire carries only the shared
/// `REFUSED_REASON`, so the log is the only place the real verdict appears.
const PAM_REFUSAL: &str = "the PAM stack refused login";

/// An expired account is refused -- and the SAME account got in a moment
/// earlier, which is what makes this about expiry rather than about a key
/// file, a home directory or a shell.
///
/// `chage -E` is the portable lever: `pam_unix`'s account stack returns
/// PAM_ACCT_EXPIRED for it on every distribution, where a locked password
/// (`usermod -L`) is read differently from one to the next.
///
/// Control run (see the task report): the monitor skips `pam_acct_mgmt`;
/// the expired account gets in, and this test fails on its own
/// `!expired.saw_opened()` -- not on the deadline -- while the positive
/// control above stays green.
#[test]
fn an_expired_account_is_refused() {
    common::on_a_disposable_host("an_expired_account_is_refused", WHAT_THESE_TESTS_DO, || {
        let dir = tempfile::tempdir().expect("tempdir");
        let bob = common::TestAccount::create("qshd-test-bob", "/bin/sh");
        common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
        let (mut daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());
        let log = common::daemon_log_path();

        // The positive control, on the account under test: before `chage`, bob
        // logs in and runs a command. The evidence is [`WHO_AM_I`]'s answer,
        // which no prompt, banner or echo of the typed line can produce.
        let before =
            common::run_one_command_in_a_shell(port, server_pub, &bob.key, &bob.name, WHO_AM_I);
        let answer = who_am_i_answer(&bob.name);
        assert!(
            before.contains(&answer),
            "the account must get in BEFORE it is expired -- otherwise the refusal below proves \
             nothing about expiry; {answer:?} is the shell's own answer and nothing else can print \
             it, yet the channel printed {before:?}"
        );

        run_account_command_or_panic("chage", &["-E", "1970-01-02", &bob.name]);

        // A refused login is never answered on the wire, so waiting for "no
        // answer" alone would be a timeout standing in for a verdict: either an
        // open channel or the helper's own line ends the wait.
        let refusals_before = common::log_mentions(&log, PAM_REFUSAL);
        let expired = common::Session::connect(port, server_pub, &bob.key, &bob.name);
        expired.request_channel(None);
        let settled = common::wait_until(|| {
            expired.saw_opened() || common::log_mentions(&log, PAM_REFUSAL) > refusals_before
        });
        assert!(
            !expired.saw_opened(),
            "an expired account must be refused by the account stack, yet {}'s channel opened; \
             control records: {:?}",
            bob.name,
            expired.control_records()
        );
        assert!(
            settled,
            "neither an open channel nor {PAM_REFUSAL:?} came within the deadline; the daemon's \
             log: {:?}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );

        daemon.child.kill().expect("stopping the daemon");
        daemon.child.wait().expect("reaping the daemon");
    });
}

/// The service file in /etc/pam.d is the one that decides: a `pam_deny`
/// account stack there refuses the very login the same daemon just
/// admitted, which proves the daemon reads the file rather than some
/// built-in default.
///
/// Control run (see the task report): the monitor starts its transaction
/// with `pam_start_confdir` over a stack of the test's own rather than with
/// `pam_start`; `/etc/pam.d/qshd` stops deciding anything, and this test
/// fails on its own `!refused.saw_opened()` while the admission above stays
/// green.
#[test]
fn the_service_file_in_etc_pam_d_is_what_decides() {
    common::on_a_disposable_host(
        "the_service_file_in_etc_pam_d_is_what_decides",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let alice = common::TestAccount::create("qshd-test-alice", "/bin/sh");
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (mut daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());
            let log = common::daemon_log_path();

            let admitted = common::run_one_command_in_a_shell(
                port,
                server_pub,
                &alice.key,
                &alice.name,
                WHO_AM_I,
            );
            let answer = who_am_i_answer(&alice.name);
            assert!(
            admitted.contains(&answer),
            "the shipped service file must admit a listed key: {answer:?} is the shell's own answer \
             and nothing else can print it, yet the channel printed {admitted:?}"
        );

            // Nothing changes but the file -- same daemon, same account, same key.
            // PAM reads it at every login.
            common::install_service_file(
                "auth required pam_permit.so\n\
             account required pam_deny.so\n\
             session required pam_permit.so\n",
            );
            let refusals_before = common::log_mentions(&log, PAM_REFUSAL);
            let refused = common::Session::connect(port, server_pub, &alice.key, &alice.name);
            refused.request_channel(None);
            let settled = common::wait_until(|| {
                refused.saw_opened() || common::log_mentions(&log, PAM_REFUSAL) > refusals_before
            });
            assert!(
            !refused.saw_opened(),
            "a pam_deny account stack in /etc/pam.d/qshd must refuse the login this daemon admitted \
             a moment ago -- the file is what decides; control records: {:?}",
            refused.control_records()
        );
            assert!(
            settled,
            "neither an open channel nor {PAM_REFUSAL:?} came within the deadline; the daemon's \
             log: {:?}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );

            daemon.child.kill().expect("stopping the daemon");
            daemon.child.wait().expect("reaping the daemon");
        },
    );
}

/// The session is opened and closed for the login as a whole: a marker file
/// written by `pam_exec.so` on open is gone once the client disconnects.
///
/// Control run (see the task report): the monitor does not call
/// `pam_close_session` when the login ends; the marker stays, and this test
/// fails on its second assertion while the first -- the session really was
/// opened -- stays green.
#[test]
fn a_session_is_closed_when_the_login_ends() {
    common::on_a_disposable_host(
        "a_session_is_closed_when_the_login_ends",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let alice = common::TestAccount::create("qshd-test-alice", "/bin/sh");
            let marker = PathBuf::from("/run/qshd-test-session");
            let _ = std::fs::remove_file(&marker);
            // A script file, not an inline `/bin/sh -c '...'`: Linux-PAM splits a
            // module's arguments on whitespace and does not understand quotes.
            let script = PathBuf::from("/run/qshd-test-session.sh");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\n\
                 if [ \"$PAM_TYPE\" = open_session ]; then : > {m}; else rm -f {m}; fi\n",
                    m = marker.display()
                ),
            )
            .expect("write the session script");
            std::fs::set_permissions(
                &script,
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
            )
            .expect("make the session script executable");
            common::install_service_file(&format!(
                "auth required pam_permit.so\n\
             account include common-account\n\
             session required pam_exec.so {s}\n\
             session include common-session\n",
                s = script.display()
            ));
            let (mut daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());

            let session = common::Session::connect(port, server_pub, &alice.key, &alice.name);
            session.open_shell();
            assert!(
                common::wait_until(|| marker.exists()),
                "the session stack must run at the login's open: {} never appeared",
                marker.display()
            );

            // Graceful, and it has to be: an ungraceful drop leaves a `Retained`
            // entry, and `forget_backend` -- the only thing that ends a login --
            // does not run for it until the GC passes RETAIN_AFTER_DEATH, which is
            // an hour (session_manager.rs:119). Only a graceful close ends the
            // login now.
            session.disconnect_gracefully();
            assert!(
            common::wait_until(|| !marker.exists()),
            "the PAM session must be closed when the login ends, not left open until the daemon \
             dies: {} is still there",
            marker.display()
        );

            daemon.child.kill().expect("stopping the daemon");
            daemon.child.wait().expect("reaping the daemon");
        },
    );
}
