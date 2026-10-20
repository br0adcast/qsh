//! Package PAM policy through a real daemon and executed account commands.
//! Run only in a fresh disposable container, one integration binary at a time.
//! QSHD_TEST_PAM_FAMILY selects the exact Debian or Fedora package profile.
#![cfg(feature = "system")]

mod common;

use common::{Session, TestAccount};
use std::path::Path;

const CHANGES: &str = "creates accounts and changes container PAM, nologin and limits files";
const REFUSAL: &str = "login session setup failed";
const REPORT: &str = r#"printf 'policy-uid=[%s] audit=[%s] soft=[%s] hard=[%s]\n' "$(id -u)" "$(cat /proc/self/loginuid)" "$(ulimit -Sn)" "$(ulimit -Hn)""#;

fn install_profile() {
    let profile = match std::env::var("QSHD_TEST_PAM_FAMILY").as_deref() {
        Ok("debian") => include_str!("../../packaging/pam.d/qshd.debian"),
        Ok("fedora") => include_str!("../../packaging/pam.d/qshd.fedora"),
        other => panic!("explicit QSHD_TEST_PAM_FAMILY=debian|fedora required: {other:?}"),
    };
    common::install_service_file(profile);
}

fn command(session: &Session, command: &str) -> String {
    session.request_channel(Some(command));
    session.wait_for_opened();
    assert_eq!(session.wait_for_exit(), 0);
    session.output()
}

fn policy_token() -> [u8; 16] {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    // The helper intentionally abbreviates tokens. Make those abbreviations unique
    // across this owned binary, so another login's diagnostic cannot satisfy a wait.
    let prefix = u16::try_from(NEXT.fetch_add(1, Ordering::Relaxed)).unwrap();
    let mut token = [0; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut token);
    token[..2].copy_from_slice(&prefix.to_be_bytes());
    token
}

fn connect(port: u16, public: [u8; 32], key: &ssh_key::PrivateKey, login: &str) -> Session {
    Session::connect_with_token(
        port,
        public,
        key,
        login,
        policy_token(),
        transport::handshake_payload::StartKind::Cold,
    )
}

fn require_refusal(session: &Session) {
    use transport::channel::{ServerRecord, FIRST_CHANNEL_STREAM};
    let refusal = || {
        session
            .control_records()
            .into_iter()
            .find_map(|record| match record {
                ServerRecord::Refused { stream, reason } if stream == FIRST_CHANNEL_STREAM => {
                    Some(reason)
                }
                _ => None,
            })
    };
    let log = common::daemon_log_path();
    let needle = format!("{REFUSAL} {}.. at channel ", session.login_log_prefix());
    let pam_refusal = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .any(|line| {
                line.contains(&needle)
                    && line.contains("; refusing the channel and ending the login")
            })
    };
    assert!(!pam_refusal(), "this token must have no prior refusal");
    session.request_channel(Some("printf 'should-not-%s' execute"));
    assert!(
        common::wait_until(|| session.saw_opened() || refusal().is_some() || pam_refusal()),
        "no verdict for this session's Open: {:?}; supplemental PAM log: {:?}",
        session.control_records(),
        std::fs::read_to_string(&log)
    );
    assert!(
        !session.saw_opened(),
        "new PAM session bypassed policy: {:?}",
        session.control_records()
    );
    if let Some(reason) = refusal() {
        assert!(
            !reason.is_empty() && reason.len() <= 1024,
            "bounded refusal reason: {reason:?}"
        );
    }
    // LoginEnded can retire the transport route before Refused is delivered.
    // This alternate proves this login's PAM verdict, not client-visible delivery.
    assert!(
        common::wait_until(pam_refusal),
        "this session must have an actual PAM refusal"
    );
    assert!(!session.saw_opened());
    assert!(!session.output().contains("should-not-execute"));
}

struct FixtureFile(&'static str);
impl FixtureFile {
    fn create(path: &'static str, contents: &str) -> Self {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap_or_else(|e| panic!("owned fixture collision at {path}: {e}"));
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }
}
impl Drop for FixtureFile {
    fn drop(&mut self) {
        std::fs::remove_file(self.0).expect("remove owned fixture");
    }
}

fn limits(account: &TestAccount, value: u32) -> String {
    format!(
        "{} soft nofile {value}\n{} hard nofile {value}\n",
        account.name, account.name
    )
}

#[test]
fn new_pam_sessions_obey_both_nologin_markers() {
    common::on_a_disposable_host(
        "new_pam_sessions_obey_both_nologin_markers",
        CHANGES,
        || {
            for marker in ["/etc/nologin", "/run/nologin"] {
                assert!(!Path::new(marker).exists());
            }
            let dir = tempfile::tempdir().unwrap();
            let account = TestAccount::create("qshd-test-policy", "/bin/sh");
            install_profile();
            let (_daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            let admitted = connect(port, public, &account.key, &account.name);
            admitted.open_shell();
            assert!(admitted
                .run_in_shell("printf 'admitted-%s' control")
                .contains("admitted-control"));
            for marker in ["/etc/nologin", "/run/nologin"] {
                // A completed signature proof without a first Open is not a PAM admission.
                let provisional = connect(port, public, &account.key, &account.name);
                let file = FixtureFile::create(marker, "Disposable policy test\n");
                let fresh = connect(port, public, &account.key, &account.name);
                require_refusal(&fresh);
                require_refusal(&provisional);
                drop(file);
                let restored = connect(port, public, &account.key, &account.name);
                assert!(
                    command(&restored, "printf 'restored-%s' control").contains("restored-control")
                );
            }
        },
    );
}

#[test]
fn executed_children_receive_account_audit_identity() {
    common::on_a_disposable_host(
        "executed_children_receive_account_audit_identity",
        CHANGES,
        || {
            // This tier requires ordinary audit support; absence is a qualification failure,
            // not a successful test of pam_loginuid assignment.
            let inherited =
                std::fs::read_to_string("/proc/self/loginuid").expect("audit-enabled kernel");
            let dir = tempfile::tempdir().unwrap();
            let alice = TestAccount::create("qshd-test-policy-a", "/bin/sh");
            let bob = TestAccount::create("qshd-test-policy-b", "/bin/sh");
            install_profile();
            let (daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            let a = connect(port, public, &alice.key, &alice.name);
            let b = connect(port, public, &bob.key, &bob.name);
            for (session, account) in [(&a, &alice), (&b, &bob)] {
                let output = command(session, REPORT);
                assert!(
                    output.contains(&format!(
                        "policy-uid=[{}] audit=[{}]",
                        account.uid, account.uid
                    )),
                    "executed account identity: {output:?}"
                );
            }
            assert_eq!(
                std::fs::read_to_string(format!("/proc/{}/loginuid", daemon.child.id())).unwrap(),
                inherited,
                "shared helper must retain its inherited audit identity"
            );
        },
    );
}

#[test]
fn executed_children_receive_per_account_limits() {
    common::on_a_disposable_host(
        "executed_children_receive_per_account_limits",
        CHANGES,
        || {
            let dir = tempfile::tempdir().unwrap();
            let account = TestAccount::create("qshd-test-policy", "/bin/sh");
            let other = TestAccount::create("qshd-test-policy-other", "/bin/sh");
            install_profile();
            let (_daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            let unaffected = connect(port, public, &other.key, &other.name);
            let other_before = command(&unaffected, REPORT);
            let before = connect(port, public, &account.key, &account.name);
            let baseline = command(&before, REPORT);
            assert!(
                !baseline.contains("soft=[73] hard=[73]"),
                "fixture must change inherited limits"
            );
            std::fs::create_dir_all("/etc/security/limits.d").unwrap();
            let _file = FixtureFile::create(
                "/etc/security/limits.d/99-qshd-policy-test.conf",
                &limits(&account, 73),
            );
            let after = connect(port, public, &account.key, &account.name);
            let output = command(&after, REPORT);
            assert!(
                output.contains("soft=[73] hard=[73]"),
                "executed limits: {output:?}"
            );
            let unaffected_after = connect(port, public, &other.key, &other.name);
            assert_eq!(
                command(&unaffected_after, REPORT),
                other_before,
                "a per-account rule must not change the other account"
            );
        },
    );
}

// Each report names the actual shell and its owning PAM monitor. A command's
// echoed input contains format placeholders, never these expanded values.
const CONTEXT: &str = r#"printf 'context=[%s %s %s %s %s]\n' "$$" "$PPID" "$POLICY_MARKER" "$(cat /proc/self/loginuid)" "$(ulimit -Hn)""#;

fn context(output: &str) -> Vec<String> {
    output
        .rmatch_indices("context=[")
        .find_map(|(at, _)| {
            let rest = &output[at + "context=[".len()..];
            let values = &rest[..rest.find(']')?];
            let fields: Vec<_> = values.split_whitespace().map(str::to_string).collect();
            (fields.len() == 5 && fields[0].parse::<u32>().is_ok()).then_some(fields)
        })
        .unwrap_or_else(|| panic!("missing executed context: {output:?}"))
}

fn other_channel(session: &Session, stream: u8, account: &TestAccount) -> Vec<String> {
    let path = format!("/home/{}/policy-report-{stream}", account.name);
    session.run_command_on_stream(stream, &format!("{CONTEXT} > {path}"));
    // A new shell does not inherit an environment variable set inside another shell.
    let output = std::fs::read_to_string(path).unwrap();
    let fields: Vec<_> = output
        .trim()
        .strip_prefix("context=[")
        .unwrap()
        .strip_suffix(']')
        .unwrap()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert_eq!(
        fields.len(),
        4,
        "new command has no shell-local marker: {output:?}"
    );
    fields
}

#[test]
fn retained_login_keeps_policy_until_a_new_incarnation() {
    use transport::handshake_payload::StartKind;
    common::on_a_disposable_host(
        "retained_login_keeps_policy_until_a_new_incarnation",
        CHANGES,
        || {
            let dir = tempfile::tempdir().unwrap();
            let account = TestAccount::create("qshd-test-policy", "/bin/sh");
            install_profile();
            std::fs::create_dir_all("/etc/security/limits.d").unwrap();
            let file = FixtureFile::create(
                "/etc/security/limits.d/99-qshd-policy-test.conf",
                &limits(&account, 73),
            );
            let (_daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            let token = policy_token();
            let original = Session::connect_with_token(
                port,
                public,
                &account.key,
                &account.name,
                token,
                StartKind::Cold,
            );
            original.open_shell();
            let marker = format!(
                "marker{:016x}",
                rand_core::RngCore::next_u64(&mut rand_core::OsRng)
            );
            let before =
                context(&original.run_in_shell(&format!("POLICY_MARKER={marker}; {CONTEXT}")));
            assert_eq!(
                &before[2..],
                &[marker, account.uid.to_string(), "73".to_string()]
            );
            std::fs::write(file.0, limits(&account, 64)).unwrap();
            let nologin = FixtureFile::create("/run/nologin", "Disposable policy test\n");

            original.detach();
            let warm = Session::connect_with_token(
                port,
                public,
                &account.key,
                &account.name,
                token,
                StartKind::Warm,
            );
            assert_eq!(
                context(&warm.run_in_shell(CONTEXT)),
                before,
                "warm attach preserves the actual shell and context"
            );
            let additional = other_channel(&warm, 17, &account);
            assert_eq!(
                &additional[1..],
                &[before[1].clone(), account.uid.to_string(), "73".to_string()]
            );
            warm.exit_shell();
            warm.wait_for_exit();
            let after_empty = other_channel(&warm, 18, &account);
            assert_eq!(
                &after_empty[1..],
                &additional[1..],
                "an empty channel set does not end PAM"
            );

            warm.detach();
            let cold = Session::connect_with_token(
                port,
                public,
                &account.key,
                &account.name,
                token,
                StartKind::Cold,
            );
            cold.open_shell();
            let replaced = context(&cold.run_in_shell(&format!("POLICY_MARKER=cold; {CONTEXT}")));
            assert_ne!(replaced[0], before[0], "Cold must execute a new shell");
            assert_eq!(replaced[1], before[1], "Cold retains the same PAM monitor");
            assert_eq!(&replaced[3..], &[account.uid.to_string(), "73".to_string()]);

            cold.disconnect_gracefully();
            assert!(
                common::wait_until(|| !Path::new(&format!("/proc/{}", before[1])).exists()),
                "original monitor must end before reusing token"
            );
            let denied = Session::connect_with_token(
                port,
                public,
                &account.key,
                &account.name,
                token,
                StartKind::Cold,
            );
            require_refusal(&denied);
            denied.disconnect_gracefully();
            drop(nologin);
            let fresh = Session::connect_with_token(
                port,
                public,
                &account.key,
                &account.name,
                token,
                StartKind::Cold,
            );
            fresh.open_shell();
            let renewed = context(&fresh.run_in_shell(&format!("POLICY_MARKER=new; {CONTEXT}")));
            assert_ne!(renewed[1], before[1], "new incarnation owns a new monitor");
            assert_eq!(&renewed[3..], &[account.uid.to_string(), "64".to_string()]);
        },
    );
}

#[test]
fn required_limits_failure_refuses_before_exec() {
    common::on_a_disposable_host(
        "required_limits_failure_refuses_before_exec",
        CHANGES,
        || {
            let dir = tempfile::tempdir().unwrap();
            let account = TestAccount::create("qshd-test-policy", "/bin/sh");
            install_profile();
            std::fs::create_dir_all("/etc/security/limits.d").unwrap();
            // maxlogins=0 is an explicit pam_limits refusal, independent of the
            // container's resource-raising privileges or module limit clamping.
            let _file = FixtureFile::create(
                "/etc/security/limits.d/99-qshd-policy-test.conf",
                &format!("{} - maxlogins 0\n", account.name),
            );
            let (_daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            let session = connect(port, public, &account.key, &account.name);
            require_refusal(&session);
        },
    );
}

#[test]
fn required_audit_failure_refuses_before_exec() {
    common::on_a_disposable_host(
        "required_audit_failure_refuses_before_exec",
        CHANGES,
        || {
            const CHILD: &str = "QSHD_TEST_AUDIT_FAILURE_CHILD";
            if std::env::var(CHILD).as_deref() != Ok("1") {
                // Own and reap a separate test process: assigning its audit identity must
                // not contaminate this binary's other tests or the container's PID 1.
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "required_audit_failure_refuses_before_exec",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .output()
                    .expect("owned audit fixture child");
                // Prefix nested libtest output so the outer suite's no-silent-skips
                // check measures its complete run, not the intentionally filtered child.
                for bytes in [&result.stdout, &result.stderr] {
                    for line in String::from_utf8_lossy(bytes).lines() {
                        eprintln!("audit child: {line}");
                    }
                }
                assert!(
                    result.status.success(),
                    "audit refusal fixture failed: {}",
                    result.status
                );
                return;
            }
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
            let caps = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:\t"))
                .unwrap();
            assert_eq!(u64::from_str_radix(caps, 16).unwrap() & (1 << 30), 0,
            "fixture requires no CAP_AUDIT_CONTROL, as in the default container filter/capability policy");
            let audit_path = "/proc/thread-self/loginuid";
            assert_eq!(
                std::fs::read_to_string(audit_path).unwrap().trim(),
                "4294967295",
                "fixture needs an initially unset audit identity"
            );
            std::fs::write(audit_path, "31416")
                .expect("qualify initial audit assignment in owned child");
            assert_eq!(std::fs::read_to_string(audit_path).unwrap().trim(), "31416");
            let dir = tempfile::tempdir().unwrap();
            let account = TestAccount::create("qshd-test-policy", "/bin/sh");
            assert_ne!(account.uid.as_raw(), 31416);
            install_profile();
            let (daemon, public, port) = common::start_daemon_for_accounts(dir.path());
            assert_eq!(
                std::fs::read_to_string(format!("/proc/{}/loginuid", daemon.child.id()))
                    .unwrap()
                    .trim(),
                "31416",
                "the actual helper must inherit the controlled identity"
            );
            let session = connect(port, public, &account.key, &account.name);
            require_refusal(&session);
        },
    );
}
