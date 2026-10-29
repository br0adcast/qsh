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
const PAM_REFUSAL: &str = "login session setup failed";

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

const SENTINEL_GROUP: u32 = 61001;
const PAM_GROUP: u32 = 61002;
// Keep the first report separate from an interactive shell's pending prompt.
const GROUP_REPORT: &str = r#"printf '\n'; awk '/^(Uid|Gid|Groups|CapEff|CapPrm):/ {printf "qshd-proc-%s=[", $1; for(i=2;i<=NF;i++)printf "%s%s",i==2?"":" ",$i; print "]"}' /proc/self/status"#;

fn fixture_stack(record: &std::path::Path, options: &str) -> String {
    let module = std::env::var("QSHD_TEST_PAM_GROUP_MODULE")
        .expect("disposable tier must provide the built PAM group fixture");
    assert!(
        std::path::Path::new(&module).is_file(),
        "missing fixture {module}"
    );
    ["auth", "account", "session"]
        .map(|kind| {
            format!(
                "{kind} required {module} record={} {options}\n",
                record.display()
            )
        })
        .concat()
}

fn proc_values(output: &str, name: &str) -> Vec<u32> {
    let prefix = format!("qshd-proc-{name}:=[");
    let line = output
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing executed process report {name}: {output:?}"));
    line.trim_end_matches(']')
        .split_whitespace()
        .map(|n| n.parse().expect("numeric proc field"))
        .collect()
}

#[test]
fn process_report_starts_after_an_interactive_prompt() {
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("printf '$ '; {GROUP_REPORT}"))
        .env("HISTFILE", "/dev/null")
        .output()
        .expect("run the finite process-report producer");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let output = String::from_utf8(output.stdout).expect("ASCII process report");
    assert_eq!(
        proc_values(&output, "Uid"),
        vec![nix::unistd::getuid().as_raw(); 4]
    );
    for name in ["Gid", "Groups", "CapEff", "CapPrm"] {
        let prefix = format!("qshd-proc-{name}:=[");
        assert!(
            output.lines().any(|line| line.starts_with(&prefix)),
            "{output:?}"
        );
    }
}

#[test]
fn process_report_rejects_missing_field() {
    assert!(std::panic::catch_unwind(|| proc_values("qshd-proc-Groups:=[]\n", "Uid")).is_err());
}

#[test]
fn process_report_rejects_echo_only() {
    let echo = format!("$ {GROUP_REPORT}\r\n$ ");
    assert!(std::panic::catch_unwind(|| proc_values(&echo, "Uid")).is_err());
}

fn group_regression(test: &str, baseline_only: bool) {
    common::on_a_disposable_host(test, WHAT_THESE_TESTS_DO, || {
        let dir = tempfile::tempdir().expect("tempdir");
        let account = common::TestAccount::create("qshd-test-groups", "/bin/sh");
        let baseline = nix::unistd::getgrouplist(
            &std::ffi::CString::new(account.name.clone()).unwrap(),
            nix::unistd::User::from_uid(account.uid)
                .unwrap()
                .unwrap()
                .gid,
        )
        .unwrap();
        assert!(!baseline
            .iter()
            .any(|g| [SENTINEL_GROUP, PAM_GROUP].contains(&g.as_raw())));
        common::install_service_file("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n");
        let (_daemon, server_pub, port) = common::start_daemon_with_groups(
            dir.path(),
            &["--authorized-keys-template", "%h/.ssh/authorized_keys"],
            Some(vec![nix::unistd::Gid::from_raw(SENTINEL_GROUP)]),
        );
        let positive = common::run_one_command_in_a_shell(
            port,
            server_pub,
            &account.key,
            &account.name,
            WHO_AM_I,
        );
        assert!(
            positive.contains(&who_am_i_answer(&account.name)),
            "positive control: {positive}"
        );
        let record = dir.path().join("phases");
        common::install_service_file(&fixture_stack(&record, &format!("gid={PAM_GROUP}")));
        let output = common::run_one_command_in_a_shell(
            port,
            server_pub,
            &account.key,
            &account.name,
            GROUP_REPORT,
        );
        let records = std::fs::read_to_string(&record).expect("module records");
        if baseline_only {
            let first = records.lines().next().expect("account record");
            let before = first
                .split("before=")
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap();
            let mut actual: Vec<u32> = before
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|g| g.parse().unwrap())
                .collect();
            let mut expected: Vec<_> = baseline.iter().map(|g| g.as_raw()).collect();
            actual.sort_unstable();
            expected.sort_unstable();
            assert_eq!(
                actual, expected,
                "PAM must start with exactly the admitted NSS baseline"
            );
        } else {
            let groups = proc_values(&output, "Groups");
            assert!(
                groups.contains(&PAM_GROUP),
                "PAM-established group missing from actual child: {groups:?}"
            );
            assert!(!groups.contains(&SENTINEL_GROUP));
            for group in baseline {
                assert!(groups.contains(&group.as_raw()));
            }
        }
    });
}

#[test]
fn pam_receives_only_the_account_group_baseline() {
    group_regression("pam_receives_only_the_account_group_baseline", true);
}

#[test]
fn shell_keeps_groups_established_by_pam() {
    group_regression("shell_keeps_groups_established_by_pam", false);
}

fn group_case(
    test: &str,
    options: &str,
    check: impl FnOnce(&common::TestAccount, &str, &std::path::Path),
) {
    common::on_a_disposable_host(test, WHAT_THESE_TESTS_DO, || {
        let dir = tempfile::tempdir().expect("tempdir");
        let account = common::TestAccount::create("qshd-test-groups", "/bin/sh");
        let record = dir.path().join("phases");
        common::install_service_file(&fixture_stack(&record, options));
        let (_daemon, pubkey, port) = common::start_daemon_for_accounts(dir.path());
        let output = common::run_one_command_in_a_shell(
            port,
            pubkey,
            &account.key,
            &account.name,
            GROUP_REPORT,
        );
        check(&account, &output, &record);
    });
}

#[test]
fn pam_can_remove_all_supplementary_groups() {
    for options in [
        "phase=open action=empty",
        "phase=open action=replace gid=61002",
    ] {
        group_case(
            "pam_can_remove_all_supplementary_groups",
            options,
            |account, output, _| {
                let expected = if options.ends_with("empty") {
                    vec![]
                } else {
                    vec![PAM_GROUP]
                };
                assert_eq!(proc_values(output, "Groups"), expected);
                assert!(proc_values(output, "Uid")
                    .iter()
                    .all(|uid| *uid == account.uid.as_raw()));
                let gid = nix::unistd::User::from_uid(account.uid)
                    .unwrap()
                    .unwrap()
                    .gid
                    .as_raw();
                assert!(proc_values(output, "Gid")
                    .iter()
                    .all(|actual| *actual == gid));
            },
        );
    }
}

#[test]
fn pam_can_explicitly_grant_numeric_group_zero() {
    group_case(
        "pam_can_explicitly_grant_numeric_group_zero",
        "phase=open gid=0",
        |account, output, _| {
            assert!(proc_values(output, "Groups").contains(&0));
            assert!(proc_values(output, "Uid")
                .iter()
                .all(|uid| *uid == account.uid.as_raw() && *uid != 0));
            assert_eq!(proc_values(output, "CapEff"), vec![0]);
            assert_eq!(proc_values(output, "CapPrm"), vec![0]);
        },
    );
}

fn phase_records(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn pam_group_teardown_uses_the_opening_monitor() {
    group_case(
        "pam_group_teardown_uses_the_opening_monitor",
        "phase=open gid=61002",
        |_, output, record| {
            assert!(proc_values(output, "Groups").contains(&PAM_GROUP));
            assert!(common::wait_until(|| phase_records(record)
                .iter()
                .any(|line| line.contains(" end "))));
            let records = phase_records(record);
            let phases: Vec<_> = records
                .iter()
                .map(|line| line.split_whitespace().nth(1).unwrap())
                .collect();
            assert_eq!(
                phases,
                ["account", "establish", "open", "close", "delete", "end"]
            );
            let pid = records[0].split_whitespace().next().unwrap();
            assert!(records
                .iter()
                .all(|line| line.split_whitespace().next() == Some(pid)));
            assert!(
                records[3].contains("children=none"),
                "all shells must be reaped before PAM close: {:?}",
                records[3]
            );
            let opened_groups = records[2].split("after=").nth(1).unwrap();
            for line in &records[3..] {
                assert_eq!(
                    line.split("before=")
                        .nth(1)
                        .unwrap()
                        .split(' ')
                        .next()
                        .unwrap(),
                    opened_groups
                );
            }
        },
    );
}

#[test]
fn pam_groups_are_isolated_between_logins() {
    common::on_a_disposable_host(
        "pam_groups_are_isolated_between_logins",
        WHAT_THESE_TESTS_DO,
        || {
            let dir = tempfile::tempdir().expect("tempdir");
            let account = common::TestAccount::create("qshd-test-groups", "/bin/sh");
            let record = dir.path().join("phases");
            common::install_service_file(&fixture_stack(&record, "gid=61002"));
            let (daemon, pubkey, port) = common::start_daemon_with_groups(
                dir.path(),
                &["--authorized-keys-template", "%h/.ssh/authorized_keys"],
                Some(vec![nix::unistd::Gid::from_raw(SENTINEL_GROUP)]),
            );
            let helper_status = || {
                std::fs::read_to_string(format!("/proc/{}/status", daemon.child.id()))
                    .unwrap()
                    .lines()
                    .find(|line| line.starts_with("Groups:"))
                    .unwrap()
                    .to_owned()
            };
            let original = helper_status();
            let first = common::Session::connect(port, pubkey, &account.key, &account.name);
            first.open_shell();
            let a = proc_values(&first.run_in_shell(GROUP_REPORT), "Groups");
            common::install_service_file(&fixture_stack(&dir.path().join("other"), "gid=61003"));
            let second = common::Session::connect(port, pubkey, &account.key, &account.name);
            second.open_shell();
            let b = proc_values(&second.run_in_shell(GROUP_REPORT), "Groups");
            assert!(a.contains(&61002) && !a.contains(&61003) && !a.contains(&SENTINEL_GROUP));
            assert!(b.contains(&61003) && !b.contains(&61002) && !b.contains(&SENTINEL_GROUP));
            first.disconnect_gracefully();
            common::install_service_file("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n");
            let clean = common::run_one_command_in_a_shell(
                port,
                pubkey,
                &account.key,
                &account.name,
                GROUP_REPORT,
            );
            assert!(proc_values(&clean, "Groups")
                .iter()
                .all(|g| ![61002, 61003, SENTINEL_GROUP].contains(g)));
            assert_eq!(
                helper_status(),
                original,
                "the shared helper retains its own identity"
            );
            second.disconnect_gracefully();
        },
    );
}

#[test]
fn pam_session_open_groups_reach_every_channel() {
    common::on_a_disposable_host(
        "pam_session_open_groups_reach_every_channel",
        WHAT_THESE_TESTS_DO,
        || {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().expect("tempdir");
            let output_dir = dir.path().join("worker-output");
            std::fs::create_dir(&output_dir).unwrap();
            std::fs::set_permissions(&output_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
            let account = common::TestAccount::create("qshd-test-groups", "/bin/sh");
            let record = dir.path().join("phases");
            common::install_service_file(&fixture_stack(
                &record,
                "phase=open action=replace gid=61002",
            ));
            let (_daemon, pubkey, port) = common::start_daemon_for_accounts(dir.path());
            let session = common::Session::connect(port, pubkey, &account.key, &account.name);
            session.open_shell();
            let a = proc_values(&session.run_in_shell(GROUP_REPORT), "Groups");
            let second = output_dir.join("second-channel");
            session.run_another_command(&format!("{GROUP_REPORT} > {}", second.display()));
            let b = proc_values(&std::fs::read_to_string(second).unwrap(), "Groups");
            assert_eq!(a, vec![PAM_GROUP]);
            assert_eq!(b, a);
            let records = phase_records(&record);
            assert_eq!(
                records.iter().filter(|r| r.contains(" establish ")).count(),
                1
            );
            assert_eq!(records.iter().filter(|r| r.contains(" open ")).count(), 1);
            assert!(
                !records.iter().any(|r| r.contains(" close ")),
                "live first shell keeps session open"
            );
            session.disconnect_gracefully();
        },
    );
}
