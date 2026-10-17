//! Task 9 of the system-mode-slice2b plan: the acceptance test of the whole
//! slice. Real accounts -- `useradd`, a home, a key in that home's own
//! `~/.ssh/authorized_keys` -- on ONE `qshd serve --system` daemon, on one
//! port, driven by a real client over the wire:
//!
//! - two accounts each get a shell of their own, running as themselves;
//! - a uid 0 alias (`useradd --non-unique --uid 0`) is refused while
//!   `--permit-root` is off, whatever its name -- the end-to-end pin that
//!   the verification path (`verify_proof_after_nonce`) really calls
//!   `root_refused`, which that function's own unit test cannot show;
//! - an account whose passwd shell is `nologin` cannot run a command -- the
//!   end-to-end pin that commands go through the account's own shell, so a
//!   shell that confines key holders keeps confining them.
//!
//! And, since the final review of slice 2c, one test that creates no
//! account at all but belongs to the same tier because it needs root:
//! [`the_daemon_refuses_to_start_with_a_dangerous_securebit`], which pins
//! that the daemon ASKS about its securebits -- a call whose removal leaves
//! every unit test in this crate green, and which had been recorded as
//! needing a privileged runner it turns out not to need.
//!
//! Task 2 of the system-mode-slice3 plan adds a second such test, beside
//! it and creating no account either:
//! [`the_daemon_refuses_to_start_without_its_pam_service_file`], which pins
//! that `serve` actually CALLS `refuse_without_pam_service` -- its own unit
//! tests in `serve.rs` pin the rule but say nothing about the call site,
//! the same gap the securebit test above closes for
//! `refuse_dangerous_securebits`.
//!
//! Only real passwd entries can make these checks: the helper resolves the
//! login with `getpwnam`, reads `%h/.ssh/authorized_keys` as the account
//! itself, and execs the account's passwd shell. That is also why this
//! suite must never run on a machine anyone keeps: it creates accounts, a
//! second root among them, and a run killed half-way would leave them
//! there. It creates them only when it runs as root AND
//! `QSHD_TEST_DISPOSABLE_HOST=1` is set -- which only a disposable
//! container may set -- and skips loudly otherwise. Run it like this, from
//! the repository's root:
//!
//! ```text
//! cargo test -p qshd --features system --test system_mode_accounts --locked --no-run
//! docker run --rm --init -e QSHD_TEST_DISPOSABLE_HOST=1 \
//!     -v "$PWD:$PWD:ro" -w "$PWD" ubuntu:24.04 \
//!     "$PWD/target/debug/deps/system_mode_accounts-<hash>" --test-threads=1 --nocapture
//! ```
//!
//! - The image must carry `setpriv` (util-linux), which
//!   [`the_daemon_refuses_to_start_with_a_dangerous_securebit`] runs the
//!   daemon under. `ubuntu:24.04` does, in its base layer, which is why the
//!   command above installs nothing -- but a leaner image (`alpine`,
//!   `debian:*-slim` without util-linux) does not, and there that one test
//!   panics on `setpriv (util-linux) must be present in this container`
//!   rather than skipping. Named here because it is the command's
//!   dependency, not the test's alone.
//! - The repository is mounted at its own absolute path, because the test
//!   binary has `qshd`'s path baked in (`CARGO_BIN_EXE_qshd`), and
//!   read-only, so root in the container cannot leave anything behind in
//!   the tree; everything the test writes goes to the container's `/tmp`.
//! - `--init`, so something reaps what the killed daemon leaves behind:
//!   `userdel` refuses an account while any process of its uid -- a zombie
//!   included -- is still listed.
//! - The image's glibc must be at least the build host's: `ubuntu:24.04`
//!   for a binary built on Ubuntu 24.04 (glibc 2.39).
//!
//! Every test here takes its turn (see `common::on_a_disposable_host`), so
//! the command above works without `--test-threads=1` too; `--nocapture` is
//! what shows each account command this suite ran and each `SKIPPED` line.
//! One binary at a time, though: the turn-taking is per test binary, and
//! `system_mode_pam.rs` creates the same accounts.
//!
//! The account harness itself -- `TestAccount`, `run_account_command`, the
//! turn-taking, the skip -- lives in `common`, because `system_mode_pam.rs`
//! needs the same pieces and each file in `qshd/tests/` is its own crate.

#![cfg(feature = "system")]

mod common;

/// What MOST of the tests here do to the machine they run on, for the loud
/// `SKIPPED` line (see `common::on_a_disposable_host`) -- the three that
/// create real accounts and remove them again. `system_mode_pam.rs` is the
/// suite that overwrites `/etc/pam.d/qshd` to change what a login's account
/// stack decides; since Task 2 of slice 3, this suite also installs that
/// file and then removes it again, and leaves it removed -- see
/// [`WHAT_THE_PAM_SERVICE_FILE_TEST_DOES`], which is why that test, like
/// `system_mode_pam.rs`, must never run on a machine anyone keeps.
///
/// Not "what these tests do", however it reads: the skip line names ONE
/// test and has to describe that one, and
/// [`the_daemon_refuses_to_start_with_a_dangerous_securebit`] creates no
/// account at all. It passes [`WHAT_THE_SECUREBITS_TEST_DOES`] instead, and
/// a test added here has to decide which of the three `does` strings it is
/// rather than inherit this one by position.
const WHAT_THESE_TESTS_DO: &str = "creates real accounts (a uid 0 alias among them)";

/// What each shell is asked. The pseudo-terminal echoes the typed line
/// back verbatim, so the echo carries `%s` inside the brackets; a value
/// there that is anything but `%s` can only have come from the shell
/// actually running `id` (see `common`'s `octal_escape` for the same trap).
const WHO_AM_I: &str = r#"printf 'qshd-who=[%s] qshd-uid=[%s]\n' "$(id -un)" "$(id -u)""#;

/// Every value the shell printed after `<label>=[`, up to the next `]`,
/// skipping the `%s` the echo of the typed line carries.
fn reported(output: &str, label: &str) -> Vec<String> {
    let open = format!("{label}=[");
    output
        .match_indices(&open)
        .filter_map(|(at, _)| {
            let rest = &output[at + open.len()..];
            let value = &rest[..rest.find(']')?];
            (value != "%s").then(|| value.to_string())
        })
        .collect()
}

/// Asserts that `output` -- a shell's answer to [`WHO_AM_I`] -- names
/// `account`, by its name and by its uid from passwd, and nothing else.
/// Returns the uid the shell reported.
fn assert_shell_ran_as(account: &common::TestAccount, output: &str) -> String {
    assert_eq!(
        reported(output, "qshd-who"),
        std::slice::from_ref(&account.name),
        "{}'s shell must run as {}; its output: {output:?}",
        account.name,
        account.name
    );
    let uids = reported(output, "qshd-uid");
    assert_eq!(
        uids,
        [account.uid.to_string()],
        "{}'s shell must run with its own uid from passwd ({}); its output: {output:?}",
        account.name,
        account.uid
    );
    eprintln!(
        "SEEN {}'s shell: qshd-who=[{}] qshd-uid=[{}]",
        account.name, account.name, uids[0]
    );
    uids[0].clone()
}

/// Two accounts, one daemon, one port: each gets a shell of its own, and
/// `id` inside it says whose. The acceptance test of the whole slice --
/// everything else proves a piece.
///
/// Both sessions are logged in and both shells open at the SAME time: the
/// helper holds two verified accounts at once, and each channel must be
/// started as its own session's account -- not as whichever logged in
/// last.
///
/// Control run (see the task report): the child skips its `setuid`, with
/// the identity and capability checks that would catch that disabled too,
/// so the shells really run as root -- and this test fails on its own
/// assertion, `qshd-who=[root]`.
#[test]
fn two_accounts_each_get_their_own_shell() {
    common::on_a_disposable_host(
        "two_accounts_each_get_their_own_shell",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            // Declared before the daemon, so they are removed after it is gone.
            let alice = common::TestAccount::create("qshd-test-alice", "/bin/sh");
            let bob = common::TestAccount::create("qshd-test-bob", "/bin/sh");
            // Since Task 2 of slice 3, the daemon refuses to start at all
            // without its own PAM service file -- this suite must install
            // one before it expects the daemon to serve, the same way
            // `system_mode_pam.rs` always has.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (_daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());

            let alice_session = common::Session::connect(port, server_pub, &alice.key, &alice.name);
            alice_session.open_shell();
            let bob_session = common::Session::connect(port, server_pub, &bob.key, &bob.name);
            bob_session.open_shell();

            let alice_uid = assert_shell_ran_as(&alice, &alice_session.run_in_shell(WHO_AM_I));
            let bob_uid = assert_shell_ran_as(&bob, &bob_session.run_in_shell(WHO_AM_I));

            // And the point of the slice: two accounts, not one -- as the shells
            // themselves saw it, not merely as passwd lists them.
            assert_ne!(
                alice_uid, bob_uid,
                "the two shells must run under two different uids"
            );
        },
    );
}

/// The reason the helper (`qshd/src/helper/server.rs`) logs when
/// `verify_proof_after_nonce`'s uid 0 check refuses a login. The wire carries one fixed reason for every
/// refusal, so the helper's log is the only place that says WHICH check it
/// was.
const ROOT_REFUSAL: &str = "root login refused: permit_root is off";

/// `--permit-root` is about uid 0, not the name `root`: an alias with uid 0
/// under any other name is still root, and is refused while the flag is off.
///
/// Everything else about the alias is admissible -- its key is listed in
/// its own `authorized_keys`, which the helper can read -- so the uid 0
/// check is the only step that can turn it away; and the test asks the
/// helper's own log that it was that step. The positive control is on the
/// same daemon and the same path: alice, an ordinary account, gets in both
/// before and after.
///
/// Control run (see slice 2b's task 9 report): the verification path --
/// then `verify_proof`, now `verify_proof_after_nonce` -- compares the name
/// to `"root"` instead of calling `root_refused`; the alias gets in, and this
/// test fails on its own assertion. That closes, end to end, what the unit
/// test of `root_refused` alone could not: that the verification path calls
/// it.
#[test]
fn a_uid_0_alias_is_refused_while_permit_root_is_off() {
    common::on_a_disposable_host(
        "a_uid_0_alias_is_refused_while_permit_root_is_off",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let alice = common::TestAccount::create("qshd-test-alice", "/bin/sh");
            let toor = common::TestAccount::create_uid0_alias("qshd-test-toor");
            assert!(
                toor.uid.is_root(),
                "precondition: useradd --non-unique --uid 0 must make a uid 0 alias, got uid {}",
                toor.uid
            );
            // See `two_accounts_each_get_their_own_shell`: the daemon needs
            // its own PAM service file to start at all, since Task 2.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (_daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());
            let log = common::daemon_log_path();

            assert_shell_ran_as(
                &alice,
                &common::run_one_command_in_a_shell(
                    port,
                    server_pub,
                    &alice.key,
                    &alice.name,
                    WHO_AM_I,
                ),
            );

            let refusals_before = common::log_mentions(&log, ROOT_REFUSAL);
            let toor_session = common::Session::connect(port, server_pub, &toor.key, &toor.name);
            toor_session.request_channel(None);
            // Either answer ends the wait: an open channel (the alias got in) or the
            // helper's own record of refusing it for being uid 0. A refused login
            // is never answered on the wire, so waiting for "no answer" alone would
            // be a timeout standing in for a verdict.
            let settled = common::wait_until(|| {
                toor_session.saw_opened()
                    || common::log_mentions(&log, ROOT_REFUSAL) > refusals_before
            });
            assert!(
            !toor_session.saw_opened(),
            "a uid 0 alias must be refused while --permit-root is off, whatever its name -- but \
             {}'s shell channel opened; control records: {:?}",
            toor.name,
            toor_session.control_records()
        );
            assert!(
            settled,
            "{}'s login must be refused by the uid 0 check, which logs {ROOT_REFUSAL:?} -- neither \
             that nor an open channel came within the deadline; the daemon's log: {:?}",
            toor.name,
            std::fs::read_to_string(&log).unwrap_or_default()
        );
            for line in std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .filter(|line| line.contains(ROOT_REFUSAL))
            {
                eprintln!("SEEN in the daemon's log: {line}");
            }

            // The daemon still lets an ordinary account in after refusing the
            // alias: what turned it away was a verdict, not a daemon gone quiet.
            assert_shell_ran_as(
                &alice,
                &common::run_one_command_in_a_shell(
                    port,
                    server_pub,
                    &alice.key,
                    &alice.name,
                    WHO_AM_I,
                ),
            );
        },
    );
}

/// What util-linux's `nologin` prints when it refuses -- all it ever prints
/// while `/etc/nologin.txt` does not exist, which it does not in the
/// container this suite runs in.
const NOLOGIN_REFUSAL: &str = "This account is currently not available.";

/// An account whose passwd shell is `nologin` holds a listed key, logs in,
/// and asks for a command: the command goes to its shell (`nologin -c
/// ...`), which refuses it, so it never runs as that account. Commands run
/// the `sshd` way, through the account's own shell -- a server that ran
/// them any other way would let every key holder of a `nologin`,
/// `git-shell` or `scponly` account walk out of it.
///
/// The positive control is the same command, over the same kind of
/// channel, on the same daemon, for an account whose shell lets it run --
/// so what stops the second account can only be its shell.
///
/// Control run (see the task report): the helper execs the command
/// directly rather than through the account's shell -- the account's name
/// comes back, and this test fails on its own assertion.
#[test]
fn an_account_confined_by_its_shell_stays_confined() {
    common::on_a_disposable_host(
        "an_account_confined_by_its_shell_stays_confined",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let alice = common::TestAccount::create("qshd-test-alice", "/bin/sh");
            let git = common::TestAccount::create("qshd-test-git", "/usr/sbin/nologin");
            // See `two_accounts_each_get_their_own_shell`: the daemon needs
            // its own PAM service file to start at all, since Task 2.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let (_daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());

            let alice_run = common::Session::connect(port, server_pub, &alice.key, &alice.name);
            alice_run.request_channel(Some("id -un"));
            let alice_exit = alice_run.wait_for_exit();
            let alice_named = alice_run.wait_for_output(|output| output.contains(&alice.name));
            assert!(
                alice_named && alice_exit == 0,
                "the positive control: {}'s `id -un` must print its name and exit 0, got exit \
             {alice_exit} and output {:?}",
                alice.name,
                alice_run.output()
            );
            eprintln!(
                "SEEN {}'s `id -un`: exit {alice_exit}, output {:?}",
                alice.name,
                alice_run.output()
            );

            let git_run = common::Session::connect(port, server_pub, &git.key, &git.name);
            git_run.request_channel(Some("id -un"));
            let git_exit = git_run.wait_for_exit();
            // Either answer ends the wait: nologin's line -- all it ever prints, so
            // the output is complete once it is here -- or the account's name, the
            // command having run after all. Nothing else is waited for, so this
            // never stands in for a fixed delay.
            git_run.wait_for_output(|output| {
                output.contains(NOLOGIN_REFUSAL) || output.contains(&git.name)
            });
            let output = git_run.output();
            assert!(
            !output.contains(&git.name),
            "an account confined by its shell must stay confined: {}'s passwd shell is nologin, so \
             `id -un` must never run as it -- yet its name came back (exit {git_exit}): {output:?}",
            git.name
        );
            assert_ne!(
                git_exit, 0,
                "nologin refuses and exits non-zero; the channel exited 0 with output {output:?}"
            );
            assert!(
                output.contains(NOLOGIN_REFUSAL),
                "the account's own shell -- nologin -- must be what answered; got {output:?}"
            );
            eprintln!(
                "SEEN {}'s `id -un`: exit {git_exit}, output {output:?}",
                git.name
            );
        },
    );
}

/// What this one does, which is not what the rest of this suite does: it
/// starts a daemon under `setpriv`, and creates no account. Since Task 2 of
/// slice 3 it also installs `/etc/pam.d/qshd`, the same as every other test
/// here now does: without it the CONTROL run below could not start either,
/// and would prove nothing about the securebit.
const WHAT_THE_SECUREBITS_TEST_DOES: &str =
    "starts a daemon under `setpriv`, which needs root's CAP_SETPCAP (it creates no accounts, \
     but does install /etc/pam.d/qshd so its own control can start)";

/// The daemon REFUSES TO START with a securebit that would let a channel's
/// process keep root's capabilities across the drop to its account -- and
/// that it asks at all is what this pins.
///
/// `helper::refuse_dangerous_securebits` has had a unit test of its own
/// since it was written, and that test says nothing about whether the
/// daemon calls it: delete the call in `serve.rs` and every unit test in
/// this crate stays green, in both suites. It was recorded as needing a
/// privileged runner and pushed to the next slice. That was wrong. A
/// container gives `CAP_SETPCAP` in its default set, so `setpriv` can set
/// the bit here, and the daemon this suite already starts is the thing
/// under test.
///
/// Three runs, one variable each:
///
/// - control: the daemon, same binary and same arguments, starts and
///   prints its banner (`common::start_daemon`, which is what every other
///   test in this file relies on);
/// - this test: the same daemon under
///   `setpriv --securebits=+no_setuid_fixup` exits non-zero, before it
///   binds anything, naming the bit and what the operator should do;
/// - and, for whoever removes the call again: the daemon then prints its
///   banner and the worker dies on `the worker still holds capabilities
///   after the drop` -- a failure every login would suffer instead of one
///   the operator is told about at startup.
#[test]
fn the_daemon_refuses_to_start_with_a_dangerous_securebit() {
    common::on_a_disposable_host(
        "the_daemon_refuses_to_start_with_a_dangerous_securebit",
        WHAT_THE_SECUREBITS_TEST_DOES,
        || {
            // The control first, and it is the whole reason this proves
            // anything: a daemon that refused to start for some unrelated
            // reason of its own would satisfy the assertions below just as
            // well. Since Task 2, that includes having its own PAM service
            // file -- without it the control itself would refuse to start,
            // for a reason that has nothing to do with securebits.
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            let serving = tempfile::tempdir().expect("tempdir");
            let (daemon, _server_pub, _port) = common::start_daemon(serving.path());
            drop(daemon);

            let dir = tempfile::tempdir().expect("tempdir");
            let host_key = dir.path().join("host_key");
            let keys = dir.path().join("authorized_keys");
            // The port is never bound: the refusal happens before the host
            // key is created and long before anything listens, which is
            // itself the point -- an operator learns at startup rather than
            // at every login.
            let output = std::process::Command::new("setpriv")
                .arg("--securebits=+no_setuid_fixup")
                .arg(env!("CARGO_BIN_EXE_qshd"))
                .args([
                    "serve",
                    "--system",
                    "--port",
                    "61999",
                    "--host-key",
                    host_key.to_str().expect("utf-8 path"),
                    "--worker-user",
                    "nobody",
                    "--permit-root",
                    "--authorized-keys-template",
                    keys.to_str().expect("utf-8 path"),
                ])
                .env("XDG_CACHE_HOME", dir.path())
                .env("HOME", dir.path())
                .output()
                .expect("`setpriv` (util-linux) must be present in this container");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("SEEN under setpriv: {:?}\nstderr: {stderr}", output.status);
            assert!(
                !output.status.success(),
                "the daemon must REFUSE to start with SECBIT_NO_SETUID_FIXUP set; it exited \
                 {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            );
            assert!(
                !stdout.contains("server-pubkey: "),
                "and it must refuse BEFORE it has a host key and a port -- it printed its \
                 startup banner:\n{stdout}"
            );
            assert!(
                stderr.contains("SECBIT_NO_SETUID_FIXUP"),
                "the refusal must name the offending securebit, or an operator cannot act on \
                 it; stderr:\n{stderr}"
            );
            assert!(
                stderr.contains("Remove SecureBits="),
                "and must say what to do about it -- `SecureBits=` in the service unit is the \
                 one source this check exists for; stderr:\n{stderr}"
            );
        },
    );
}

/// What [`the_daemon_refuses_to_start_without_its_pam_service_file`] does to
/// the machine it runs on: no account, but the machine's real
/// `/etc/pam.d/qshd`, taken away and left that way -- like
/// `system_mode_pam.rs`, and unlike every other test in this file.
const WHAT_THE_PAM_SERVICE_FILE_TEST_DOES: &str =
    "takes /etc/pam.d/qshd away and expects the daemon to refuse";

/// The call site, witnessed where it can be: a container where
/// `/etc/pam.d` exists and our file can be taken away. The unit tests in
/// `serve.rs` (`a_missing_pam_service_file_refuses_the_start` and
/// `a_machine_without_a_pam_d_directory_is_not_refused`) pin the rule
/// itself; this pins that `serve` ASKS it at all -- the same gap
/// [`the_daemon_refuses_to_start_with_a_dangerous_securebit`] closes for
/// `refuse_dangerous_securebits`, and by the same argument: delete the call
/// in `serve.rs` and every unit test in this crate stays green, because
/// none of them starts the real `serve` command against the real
/// filesystem.
#[test]
fn the_daemon_refuses_to_start_without_its_pam_service_file() {
    common::on_a_disposable_host(
        "the_daemon_refuses_to_start_without_its_pam_service_file",
        WHAT_THE_PAM_SERVICE_FILE_TEST_DOES,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            common::install_service_file(include_str!("../../packaging/pam.d/qshd.debian"));
            // The positive control FIRST, on the same machine state:
            // with the file there, the daemon serves.
            let (mut daemon, _pub, _port) = common::start_daemon_for_accounts(dir.path());
            daemon.child.kill().expect("stopping the daemon");
            daemon.child.wait().expect("reaping the daemon");

            std::fs::remove_file("/etc/pam.d/qshd").expect("take the service file away");
            let output = common::start_daemon_expecting_refusal(dir.path());
            assert!(
                output.contains("/etc/pam.d/qshd"),
                "the refusal must name the missing file, got {output:?}"
            );
        },
    );
}
