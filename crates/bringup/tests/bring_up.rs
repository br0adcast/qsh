mod support_home;

use std::sync::Arc;
use std::time::{Duration, Instant};
use support_home::*;

fn go(req: bringup::BringUpRequest) -> Result<bringup::Ready, bringup::BringUpError> {
    bringup::bring_up(req, Arc::new(knock::NoBind), &knock::Cancel::new())
}

/// The whole way: log in, find the cached qshd, start it with the client's
/// key, read where it listens.
#[test]
fn a_cached_qshd_is_started_and_says_where_it_listens() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _one = serialised();
    let mut sb = Sandbox::start();
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let port = free_udp_port();
    let ready = go(sb.request(port)).expect("bring up");
    assert_eq!(ready.ports, vec![port]);
    assert_eq!(ready.version, qshd::state::QSHD_VERSION);
    assert!(
        sb.cache().join("control.sock").exists(),
        "the daemon runs in the private cache"
    );
}

/// Nothing cached: the qshd on PATH is used.
#[test]
fn qshd_on_the_path_is_used_when_nothing_is_cached() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _one = serialised();
    let mut sb = Sandbox::start();
    std::fs::copy(qshd_path(), sb.home.path().join("bin/qshd")).unwrap();
    let port = free_udp_port();
    assert_eq!(go(sb.request(port)).expect("bring up").ports, vec![port]);
}

/// Personal mode installs qshd into `~/.local/bin`, which a
/// non-interactive session's PATH lacks (the sandbox's does too): it is
/// found there anyway.
#[test]
fn qshd_in_the_home_s_local_bin_is_found_off_the_path() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _one = serialised();
    let mut sb = Sandbox::start();
    let local_bin = sb.home.path().join(".local/bin");
    std::fs::create_dir_all(&local_bin).unwrap();
    std::fs::copy(qshd_path(), local_bin.join("qshd")).unwrap();
    let port = free_udp_port();
    let ready = go(sb.request(port)).expect("bring up");
    assert_eq!(ready.ports, vec![port]);
    assert_eq!(ready.version, qshd::state::QSHD_VERSION);
}

/// A `systemctl` in the sandbox PATH that says the unit is active only for
/// the given form; a qshd in the cache that would leave a mark if it ran.
/// Returns the marker's path.
fn service_sandbox(active_when_user: bool) -> (Sandbox, std::path::PathBuf) {
    let sb = Sandbox::start();
    let body = if active_when_user {
        "[ \"$1\" = --user ] && [ \"$2\" = is-active ] && [ \"$3\" = --quiet ] && [ \"$4\" = qshd.service ] && exit 0; exit 1"
    } else {
        "[ \"$1\" = is-active ] && [ \"$2\" = --quiet ] && [ \"$3\" = qshd.service ] && exit 0; exit 1"
    };
    sb.fake_qshd(&sb.home.path().join("bin/systemctl"), body);
    let marker = sb.home.path().join("ensure-ran");
    let fake = sb
        .cache()
        .join(format!("qshd-0.3.0-{}", std::env::consts::ARCH));
    sb.fake_qshd(&fake, "touch \"$HOME/ensure-ran\"; echo ran >&2; exit 9");
    (sb, marker)
}

/// A system unit is running: it is reported, and transport-ensure never runs.
#[test]
fn a_system_service_is_reported_and_nothing_is_started() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let (mut sb, marker) = service_sandbox(false);
    match go(sb.request(60022)) {
        Err(bringup::BringUpError::ServiceRunning(bringup::ServiceKind::System)) => {}
        other => panic!("expected ServiceRunning(System), got {other:?}"),
    }
    assert!(!marker.exists(), "transport-ensure ran");
}

/// Only the account's own service is running.
#[test]
fn a_user_service_is_reported_and_nothing_is_started() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let (mut sb, marker) = service_sandbox(true);
    match go(sb.request(60022)) {
        Err(bringup::BringUpError::ServiceRunning(bringup::ServiceKind::User)) => {}
        other => panic!("expected ServiceRunning(User), got {other:?}"),
    }
    assert!(!marker.exists(), "transport-ensure ran");
}

#[test]
fn no_qshd_anywhere_is_qshd_missing() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    for p in [
        "/usr/bin/qshd",
        "/bin/qshd",
        "/usr/local/bin/qshd",
        "/opt/homebrew/bin/qshd",
    ] {
        if std::path::Path::new(p).exists() {
            eprintln!("SKIPPED: {p} exists on this machine");
            return;
        }
    }
    let mut sb = Sandbox::start();
    match go(sb.request(60022)) {
        Err(bringup::BringUpError::QshdMissing) => {}
        other => panic!("expected QshdMissing, got {other:?}"),
    }
}

/// The SSH step's own refusal comes back as it is.
#[test]
fn a_refused_ssh_login_is_an_ssh_error() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let mut sb = Sandbox::start();
    let mut req = sb.request(60022);
    req.auth = ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(
        ssh_support::SoftSigner::random(),
    )));
    match go(req) {
        Err(bringup::BringUpError::Ssh(ssh::SshError::AuthFailed(_))) => {}
        other => panic!("expected an SSH refusal, got {other:?}"),
    }
}

/// transport-ensure hangs (a busy daemon); the person cancels. The fake
/// leaves a mark when it starts and the cancel waits for it, so the cancel
/// lands during transport-ensure -- not during the login or the lookup,
/// which end in `Cancelled` too.
#[test]
fn cancel_during_transport_ensure_returns_quickly() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let mut sb = Sandbox::start();
    let fake = sb
        .cache()
        .join(format!("qshd-0.3.0-{}", std::env::consts::ARCH));
    // Reads the channel until it closes, 30 s at most: a closed channel
    // or connection ends it, and it can never outlive its bound.
    sb.fake_qshd(
        &fake,
        "touch \"$HOME/ensure-started\"; timeout 30 cat >/dev/null",
    );
    let marker = sb.home.path().join("ensure-started");
    let cancel = knock::Cancel::new();
    let later = cancel.clone();
    let watch = marker.clone();
    let canceller = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !watch.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // Cancel either way, so a fake that never started cannot hold the
        // test for the whole ensure deadline; the marker assert below says
        // which it was.
        let seen = watch.exists();
        let at = Instant::now();
        later.cancel();
        (seen, at)
    });
    let result = bringup::bring_up(sb.request(60022), Arc::new(knock::NoBind), &cancel);
    let returned = Instant::now();
    let (seen, cancelled_at) = canceller.join().unwrap();
    assert!(
        seen,
        "transport-ensure never started (no {})",
        marker.display()
    );
    match result {
        Err(bringup::BringUpError::Ssh(ssh::SshError::Cancelled)) => {}
        other => panic!("expected Cancelled, got {other:?}"),
    }
    let took = returned.duration_since(cancelled_at);
    assert!(
        took < Duration::from_secs(1),
        "{took:?} from the cancel to the return"
    );
    // The fake ends with its channel: nothing from the sandbox is left.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut left = processes_under(sb.home.path());
    while !left.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        left = processes_under(sb.home.path());
    }
    assert!(
        left.is_empty(),
        "the fake qshd outlived its channel: {left:?}"
    );
}

/// Spec §6.3 end to end: the phone started the daemon on one port, the
/// console asks for another; the answer is the daemon's port, and
/// `port_for` picks it.
#[test]
fn a_live_daemon_on_another_port_is_reported_as_it_is() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _one = serialised();
    let mut sb = Sandbox::start();
    sb.cache_real_qshd(qshd::state::QSHD_VERSION);
    let first = free_udp_port();
    assert_eq!(go(sb.request(first)).expect("first").ports, vec![first]);
    let mut second = free_udp_port();
    while second == first {
        second = free_udp_port();
    }
    let ready = go(sb.request(second)).expect("second");
    assert_eq!(ready.ports, vec![first]);
    assert_eq!(ready.port_for(second), first);
}

/// A half-uploaded `.new` and a non-executable newer file are not chosen;
/// the newest runnable one is.
#[test]
fn the_newest_runnable_cached_qshd_is_chosen() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let _one = serialised();
    let mut sb = Sandbox::start();
    let arch = std::env::consts::ARCH;
    sb.fake_qshd(
        &sb.cache().join(format!("qshd-0.0.1-{arch}")),
        "echo 'the old one ran' >&2; exit 9",
    );
    sb.fake_qshd(
        &sb.cache().join(format!("qshd-99.0.0-{arch}.new")),
        "echo 'the upload ran' >&2; exit 9",
    );
    let stale = sb.cache().join(format!("qshd-98.0.0-{arch}"));
    std::fs::write(&stale, "#!/bin/sh\necho 'not runnable ran' >&2; exit 9\n").unwrap(); // 0644
    sb.cache_real_qshd("50.0.0");
    let port = free_udp_port();
    assert_eq!(go(sb.request(port)).expect("bring up").ports, vec![port]);
}

#[test]
fn a_failing_transport_ensure_says_why() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let mut sb = Sandbox::start();
    let fake = sb
        .cache()
        .join(format!("qshd-0.3.0-{}", std::env::consts::ARCH));
    sb.fake_qshd(
        &fake,
        "echo 'qshd: port 60022 is already taken' >&2; exit 3",
    );
    match go(sb.request(60022)) {
        Err(bringup::BringUpError::EnsureFailed(t)) => {
            assert!(t.contains("port 60022 is already taken"), "{t}")
        }
        other => panic!("expected EnsureFailed, got {other:?}"),
    }
}

#[test]
fn an_answer_without_the_ready_lines_is_bad_ready() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let mut sb = Sandbox::start();
    let fake = sb
        .cache()
        .join(format!("qshd-0.3.0-{}", std::env::consts::ARCH));
    sb.fake_qshd(&fake, "echo hello");
    assert!(matches!(
        go(sb.request(60022)),
        Err(bringup::BringUpError::BadReady(_))
    ));
}

/// Megabytes of output, then a failure: the error is short and nothing hangs.
#[test]
fn a_flood_of_output_is_bounded() {
    let Some(()) = ssh_support::sshd_or_skip() else {
        return;
    };
    let mut sb = Sandbox::start();
    let fake = sb
        .cache()
        .join(format!("qshd-0.3.0-{}", std::env::consts::ARCH));
    sb.fake_qshd(
        &fake,
        "head -c 4000000 /dev/zero | tr '\\000' x >&2; exit 1",
    );
    let started = Instant::now();
    match go(sb.request(60022)) {
        Err(bringup::BringUpError::EnsureFailed(t)) => {
            assert!(t.chars().count() < 1100, "{}", t.len())
        }
        other => panic!("expected EnsureFailed, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(20));
}
